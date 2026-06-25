#include "unix_socket_reader.hpp"

#include <logger.hpp>

#include <boost/asio.hpp>
#include <boost/system/error_code.hpp>

#include <filesystem>
#include <istream>
#include <utility>
#include <vector>

using namespace logcollector;
using boost::asio::local::datagram_protocol;
using boost::asio::local::stream_protocol;

namespace
{
    /// @brief Removes a trailing carriage return / line feed sequence from a message
    void TrimLineEnding(std::string& message)
    {
        while (!message.empty() && (message.back() == '\n' || message.back() == '\r'))
        {
            message.pop_back();
        }
    }
} // namespace

UnixSocketReader::UnixSocketReader(
    std::function<void(const std::string& location, const std::string& log, const std::string& collectorType)>
        pushMessageFunc,
    std::function<Awaitable(std::chrono::milliseconds)> waitFunc,
    std::function<void(boost::asio::awaitable<void>)> enqueueTaskFunc,
    UnixSocketType type,
    std::string path)
    : IReader(std::move(pushMessageFunc), std::move(waitFunc))
    , m_enqueueTask(std::move(enqueueTaskFunc))
    , m_type(type)
    , m_path(std::move(path))
{
}

std::string UnixSocketReader::TypeToString(UnixSocketType type)
{
    return type == UnixSocketType::Stream ? "unix_stream" : "unix_dgram";
}

std::string UnixSocketReader::ListenerId() const
{
    return TypeToString(m_type) + ":" + m_path;
}

void UnixSocketReader::RemoveSocketFile() const
{
    std::error_code fsEc;

    // Only remove a leftover socket file, never a regular file the user may own.
    if (std::filesystem::is_socket(m_path, fsEc))
    {
        std::filesystem::remove(m_path, fsEc);
    }
}

void UnixSocketReader::SetSocketPermissions() const
{
    namespace fs = std::filesystem;

    std::error_code fsEc;
    // 0660: owner and group read/write only. Keeps arbitrary local users from
    // writing to the socket (which would let them inject agent-attributed logs).
    const auto perms = fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read | fs::perms::group_write;
    fs::permissions(m_path, perms, fs::perm_options::replace, fsEc);

    if (fsEc)
    {
        LogWarn("Could not set permissions on unix socket {}: {}", m_path, fsEc.message());
    }
}

Awaitable UnixSocketReader::Run()
{
    const auto executor = co_await boost::asio::this_coro::executor;

    {
        const std::lock_guard<std::mutex> lock(m_socketMutex);
        m_executor = executor;
    }

    if (!m_keepRunning.load())
    {
        co_return;
    }

    if (m_type == UnixSocketType::Stream)
    {
        co_await RunStream();
    }
    else
    {
        co_await RunDatagram();
    }
}

void UnixSocketReader::Stop()
{
    m_keepRunning.store(false);

    const std::lock_guard<std::mutex> lock(m_socketMutex);

    if (!m_executor.has_value())
    {
        return;
    }

    // Sockets are not thread-safe: close them on the io_context thread.
    boost::asio::post(*m_executor,
                      [this]()
                      {
                          const std::lock_guard<std::mutex> innerLock(m_socketMutex);
                          boost::system::error_code ec;

                          // NOLINTBEGIN(bugprone-unused-return-value)
                          if (m_datagramSocket)
                          {
                              m_datagramSocket->close(ec);
                          }

                          if (m_acceptor)
                          {
                              m_acceptor->close(ec);
                          }

                          for (const auto& client : m_clients)
                          {
                              if (auto socket = client.lock())
                              {
                                  socket->close(ec);
                              }
                          }
                          // NOLINTEND(bugprone-unused-return-value)

                          RemoveSocketFile();
                      });
}

Awaitable UnixSocketReader::RunStream()
{
    const auto executor = co_await boost::asio::this_coro::executor;
    boost::system::error_code ec;

    // Remove a stale socket file from a previous run; otherwise bind fails with EADDRINUSE.
    RemoveSocketFile();

    const auto acceptor = std::make_shared<stream_protocol::acceptor>(executor);
    const stream_protocol::endpoint endpoint(m_path);

    // NOLINTBEGIN(bugprone-unused-return-value)
    acceptor->open(endpoint.protocol(), ec);
    if (!ec)
    {
        acceptor->bind(endpoint, ec);
    }
    if (!ec)
    {
        acceptor->listen(boost::asio::socket_base::max_listen_connections, ec);
    }
    // NOLINTEND(bugprone-unused-return-value)

    if (ec)
    {
        LogError("Failed to start agent-side unix_stream listener on {}: {}", m_path, ec.message());
        co_return;
    }

    SetSocketPermissions();

    {
        const std::lock_guard<std::mutex> lock(m_socketMutex);
        m_acceptor = acceptor;
    }

    if (!m_keepRunning.load())
    {
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        acceptor->close(ec);
        RemoveSocketFile();
        co_return;
    }

    LogInfo("Started agent-side unix_stream listener on {}", m_path);

    while (m_keepRunning.load())
    {
        const auto socket = std::make_shared<stream_protocol::socket>(executor);

        co_await acceptor->async_accept(*socket, boost::asio::redirect_error(boost::asio::use_awaitable, ec));

        if (ec)
        {
            if (ec == boost::asio::error::operation_aborted)
            {
                break;
            }

            LogDebug("unix_stream listener {} accept error: {}", ListenerId(), ec.message());
            continue;
        }

        {
            const std::lock_guard<std::mutex> lock(m_socketMutex);
            m_clients.remove_if([](const std::weak_ptr<stream_protocol::socket>& client) { return client.expired(); });
            m_clients.push_back(socket);
        }

        LogDebug("Accepted unix_stream client on {}", ListenerId());
        m_enqueueTask(HandleStreamClient(socket));
    }

    LogInfo("Stopped agent-side unix_stream listener on {}", m_path);
}

Awaitable UnixSocketReader::RunDatagram()
{
    const auto executor = co_await boost::asio::this_coro::executor;
    boost::system::error_code ec;

    RemoveSocketFile();

    const auto socket = std::make_shared<datagram_protocol::socket>(executor);
    const datagram_protocol::endpoint endpoint(m_path);

    // NOLINTBEGIN(bugprone-unused-return-value)
    socket->open(endpoint.protocol(), ec);
    if (!ec)
    {
        socket->bind(endpoint, ec);
    }
    // NOLINTEND(bugprone-unused-return-value)

    if (ec)
    {
        LogError("Failed to start agent-side unix_dgram listener on {}: {}", m_path, ec.message());
        co_return;
    }

    SetSocketPermissions();

    {
        const std::lock_guard<std::mutex> lock(m_socketMutex);
        m_datagramSocket = socket;
    }

    if (!m_keepRunning.load())
    {
        // NOLINTNEXTLINE(bugprone-unused-return-value)
        socket->close(ec);
        RemoveSocketFile();
        co_return;
    }

    LogInfo("Started agent-side unix_dgram listener on {}", m_path);

    std::vector<char> buffer(MAX_MESSAGE_SIZE);
    datagram_protocol::endpoint sender;

    while (m_keepRunning.load())
    {
        const std::size_t bytes = co_await socket->async_receive_from(
            boost::asio::buffer(buffer), sender, boost::asio::redirect_error(boost::asio::use_awaitable, ec));

        if (ec)
        {
            if (ec == boost::asio::error::operation_aborted)
            {
                break;
            }

            if (ec == boost::asio::error::message_size)
            {
                LogDebug("Dropped oversized unix_dgram message on {}", ListenerId());
                continue;
            }

            LogDebug("unix_dgram listener {} receive error: {}", ListenerId(), ec.message());
            continue;
        }

        ProcessMessage(std::string(buffer.data(), bytes));
    }

    LogInfo("Stopped agent-side unix_dgram listener on {}", m_path);
}

// Parameters are passed by value on purpose: a coroutine must own them so they
// remain valid across suspension points.
// NOLINTNEXTLINE(performance-unnecessary-value-param)
Awaitable UnixSocketReader::HandleStreamClient(std::shared_ptr<stream_protocol::socket> socket)
{
    boost::asio::streambuf buffer(MAX_MESSAGE_SIZE);
    boost::system::error_code ec;

    while (m_keepRunning.load())
    {
        co_await boost::asio::async_read_until(
            *socket, buffer, '\n', boost::asio::redirect_error(boost::asio::use_awaitable, ec));

        if (ec)
        {
            if (ec == boost::asio::error::not_found)
            {
                LogDebug("Dropped oversized unix_stream message on {}", ListenerId());
            }
            else if (ec != boost::asio::error::eof && ec != boost::asio::error::operation_aborted)
            {
                LogDebug("unix_stream client read error on {}: {}", ListenerId(), ec.message());
            }
            break;
        }

        std::istream stream(&buffer);
        std::string line;
        std::getline(stream, line);
        ProcessMessage(std::move(line));
    }

    boost::system::error_code closeEc;
    // NOLINTNEXTLINE(bugprone-unused-return-value)
    socket->close(closeEc);

    LogDebug("Closed unix_stream client on {}", ListenerId());
}

void UnixSocketReader::ProcessMessage(std::string message) const
{
    TrimLineEnding(message);

    if (message.empty())
    {
        return;
    }

    if (message.size() > MAX_MESSAGE_SIZE)
    {
        LogDebug("Dropped oversized unix socket message on {}", ListenerId());
        return;
    }

    m_pushMessage(ListenerId(), message, m_collectorType);
}
