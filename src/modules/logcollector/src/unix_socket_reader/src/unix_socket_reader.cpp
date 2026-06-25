#include "unix_socket_reader.hpp"

#include <logger.hpp>

#include <boost/asio/this_coro.hpp>

#include <utility>

using namespace logcollector;

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

// ----------------------------------------------------------------------------
// SCAFFOLD - not yet implemented (wazuh/wazuh#15178 follow-up).
//
// Planned design (mirrors src/syslog_reader for the UDP/TCP listeners):
//
//   Stream (SOCK_STREAM):
//     - boost::asio::local::stream_protocol::acceptor on m_path.
//     - Unlink any stale socket file before bind() (a leftover path makes bind
//       fail with EADDRINUSE); decide and document the file permissions/umask
//       for the created socket so only intended writers can connect.
//     - Accept loop -> per-connection coroutine reading newline-delimited
//       messages (reuse the framing logic from SyslogReader::HandleTcpClient).
//
//   Datagram (SOCK_DGRAM):
//     - boost::asio::local::datagram_protocol::socket bound to m_path.
//     - Receive loop -> one datagram == one message (as UDP).
//
//   Shared with SyslogReader:
//     - Push each message via m_pushMessage(ListenerId(), msg, m_collectorType).
//     - Close sockets on the io_context thread from Stop(); track client sockets
//       so they can be closed on shutdown; remove the socket file on stop.
//     - Validation/lifecycle/logging consistent with the syslog listeners.
//
// Wiring (later): add Logcollector::SetupUnixSocketReaders() parsing a config
// section (e.g. logcollector.unix_socket: [{ type, path }, ...]) and call it
// from Logcollector::Setup(), guarded by BOOST_ASIO_HAS_LOCAL_SOCKETS.
// ----------------------------------------------------------------------------

Awaitable UnixSocketReader::Run()
{
    const auto executor = co_await boost::asio::this_coro::executor;

    {
        const std::lock_guard<std::mutex> lock(m_socketMutex);
        m_executor = executor;
    }

    // TODO(#15178): implement the stream/datagram listener as described above.
    LogWarn("Agent-side UNIX socket listener is not implemented yet (scaffold): {}", ListenerId());
    co_return;
}

void UnixSocketReader::Stop()
{
    m_keepRunning.store(false);

    // TODO(#15178): post socket/acceptor close to the io_context executor and
    //               unlink the socket file, mirroring SyslogReader::Stop().
}
