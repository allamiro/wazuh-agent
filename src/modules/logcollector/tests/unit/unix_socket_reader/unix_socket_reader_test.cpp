#include <unix_socket_reader.hpp>

#include <boost/asio.hpp>
#include <gtest/gtest.h>

#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

using namespace logcollector;
using boost::asio::local::datagram_protocol;
using boost::asio::local::stream_protocol;

namespace
{
    constexpr auto POLL_INTERVAL = std::chrono::milliseconds(20);
    constexpr int MAX_ATTEMPTS = 100;

    /// @brief Thread-safe sink that records messages pushed by a reader
    class MessageSink
    {
    public:
        void Push(const std::string& location, const std::string& log, const std::string& collectorType)
        {
            const std::lock_guard<std::mutex> lock(m_mutex);
            m_messages.emplace_back(location, log, collectorType);
        }

        std::size_t Count() const
        {
            const std::lock_guard<std::mutex> lock(m_mutex);
            return m_messages.size();
        }

        std::vector<std::tuple<std::string, std::string, std::string>> Messages() const
        {
            const std::lock_guard<std::mutex> lock(m_mutex);
            return m_messages;
        }

    private:
        mutable std::mutex m_mutex;
        std::vector<std::tuple<std::string, std::string, std::string>> m_messages;
    };

    /// @brief Builds a unique temporary socket path for a test
    std::string TempSocketPath(const std::string& name)
    {
        return "/tmp/wazuh_ut_" + name + "_" + std::to_string(::getpid()) + ".sock";
    }

    std::shared_ptr<UnixSocketReader> MakeReader(boost::asio::io_context& io,
                                                 MessageSink& sink,
                                                 UnixSocketType type,
                                                 const std::string& path)
    {
        auto push = [&sink](const std::string& location, const std::string& log, const std::string& collectorType)
        { sink.Push(location, log, collectorType); };

        // NOLINTNEXTLINE(cppcoreguidelines-avoid-capturing-lambda-coroutines)
        auto wait = [](std::chrono::milliseconds) -> Awaitable { co_return; };

        auto enqueue = [&io](boost::asio::awaitable<void> task)
        { boost::asio::co_spawn(io, std::move(task), boost::asio::detached); };

        return std::make_shared<UnixSocketReader>(push, wait, enqueue, type, path);
    }

    void WaitForCount(const MessageSink& sink, std::size_t expected)
    {
        for (int attempt = 0; attempt < MAX_ATTEMPTS && sink.Count() < expected; ++attempt)
        {
            std::this_thread::sleep_for(POLL_INTERVAL);
        }
    }

    bool SendStream(const std::string& path, const std::string& message)
    {
        boost::asio::io_context io;
        stream_protocol::socket socket(io);
        const stream_protocol::endpoint endpoint(path);

        for (int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt)
        {
            boost::system::error_code ec;
            // NOLINTNEXTLINE(bugprone-unused-return-value)
            socket.connect(endpoint, ec);
            if (!ec)
            {
                boost::asio::write(socket, boost::asio::buffer(message), ec);
                socket.close();
                return !ec;
            }
            std::this_thread::sleep_for(POLL_INTERVAL);
        }
        return false;
    }

    bool SendDatagram(const std::string& path, const std::string& message)
    {
        boost::asio::io_context io;
        datagram_protocol::socket socket(io);
        socket.open();
        const datagram_protocol::endpoint endpoint(path);

        for (int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt)
        {
            boost::system::error_code ec;
            socket.send_to(boost::asio::buffer(message), endpoint, 0, ec);
            if (!ec)
            {
                socket.close();
                return true;
            }
            std::this_thread::sleep_for(POLL_INTERVAL);
        }
        return false;
    }

    void RemoveIfExists(const std::string& path)
    {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
} // namespace

TEST(UnixSocketReader, TypeToString)
{
    EXPECT_EQ(UnixSocketReader::TypeToString(UnixSocketType::Stream), "unix_stream");
    EXPECT_EQ(UnixSocketReader::TypeToString(UnixSocketType::Datagram), "unix_dgram");
}

TEST(UnixSocketReader, ListenerIdFormat)
{
    MessageSink sink;
    boost::asio::io_context io;
    auto reader = MakeReader(io, sink, UnixSocketType::Stream, "/var/run/test.sock");
    EXPECT_EQ(reader->ListenerId(), "unix_stream:/var/run/test.sock");
}

TEST(UnixSocketReader, SocketFilePermissionsAreRestricted)
{
    const auto path = TempSocketPath("perms");
    RemoveIfExists(path);
    MessageSink sink;
    boost::asio::io_context io;
    auto reader = MakeReader(io, sink, UnixSocketType::Stream, path);

    boost::asio::co_spawn(io, reader->Run(), boost::asio::detached);
    std::thread ioThread([&io]() { io.run(); });

    // Wait until the socket file exists and its permissions have been restricted.
    std::filesystem::perms perms = std::filesystem::perms::unknown;
    for (int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt)
    {
        std::error_code ec;
        if (std::filesystem::exists(path, ec))
        {
            perms = std::filesystem::status(path, ec).permissions();
            if ((perms & std::filesystem::perms::others_all) == std::filesystem::perms::none)
            {
                break;
            }
        }
        std::this_thread::sleep_for(POLL_INTERVAL);
    }

    reader->Stop();
    ioThread.join();

    // No access for "others", owner read/write present (0660).
    EXPECT_EQ(perms & std::filesystem::perms::others_all, std::filesystem::perms::none);
    EXPECT_NE(perms & std::filesystem::perms::owner_read, std::filesystem::perms::none);
    EXPECT_NE(perms & std::filesystem::perms::owner_write, std::filesystem::perms::none);
}

TEST(UnixSocketReader, StreamReceivesMessage)
{
    const auto path = TempSocketPath("stream");
    RemoveIfExists(path);
    MessageSink sink;
    boost::asio::io_context io;
    auto reader = MakeReader(io, sink, UnixSocketType::Stream, path);

    boost::asio::co_spawn(io, reader->Run(), boost::asio::detached);
    std::thread ioThread([&io]() { io.run(); });

    const bool sent = SendStream(path, "<13>unix stream listener test\n");
    WaitForCount(sink, 1);

    reader->Stop();
    ioThread.join();

    ASSERT_TRUE(sent);
    ASSERT_GE(sink.Count(), 1u);
    const auto messages = sink.Messages();
    EXPECT_EQ(std::get<1>(messages[0]), "<13>unix stream listener test");
    EXPECT_EQ(std::get<2>(messages[0]), UNIX_SOCKET_READER_TYPE);
    EXPECT_EQ(std::get<0>(messages[0]), reader->ListenerId());

    EXPECT_FALSE(std::filesystem::exists(path)); // socket file removed on stop
}

TEST(UnixSocketReader, DatagramReceivesMessage)
{
    const auto path = TempSocketPath("dgram");
    RemoveIfExists(path);
    MessageSink sink;
    boost::asio::io_context io;
    auto reader = MakeReader(io, sink, UnixSocketType::Datagram, path);

    boost::asio::co_spawn(io, reader->Run(), boost::asio::detached);
    std::thread ioThread([&io]() { io.run(); });

    const bool sent = SendDatagram(path, "<13>unix dgram listener test\n");
    WaitForCount(sink, 1);

    reader->Stop();
    ioThread.join();

    ASSERT_TRUE(sent);
    ASSERT_GE(sink.Count(), 1u);
    const auto messages = sink.Messages();
    EXPECT_EQ(std::get<1>(messages[0]), "<13>unix dgram listener test");
    EXPECT_EQ(std::get<2>(messages[0]), UNIX_SOCKET_READER_TYPE);
}

TEST(UnixSocketReader, StreamHandlesMultipleLines)
{
    const auto path = TempSocketPath("multiline");
    RemoveIfExists(path);
    MessageSink sink;
    boost::asio::io_context io;
    auto reader = MakeReader(io, sink, UnixSocketType::Stream, path);

    boost::asio::co_spawn(io, reader->Run(), boost::asio::detached);
    std::thread ioThread([&io]() { io.run(); });

    const bool sent = SendStream(path, "first\nsecond\nthird\n");
    WaitForCount(sink, 3);

    reader->Stop();
    ioThread.join();

    ASSERT_TRUE(sent);
    EXPECT_GE(sink.Count(), 3u);
}

TEST(UnixSocketReader, StaleSocketFileIsReplaced)
{
    const auto path = TempSocketPath("stale");
    RemoveIfExists(path);

    // Leave a stale socket file behind, as a previous crashed run would.
    {
        boost::asio::io_context staleIo;
        stream_protocol::acceptor stale(staleIo);
        stale.open();
        stale.bind(stream_protocol::endpoint(path));
        stale.close(); // closes the fd but leaves the socket file on disk
    }
    ASSERT_TRUE(std::filesystem::exists(path));

    MessageSink sink;
    boost::asio::io_context io;
    auto reader = MakeReader(io, sink, UnixSocketType::Stream, path);

    boost::asio::co_spawn(io, reader->Run(), boost::asio::detached);
    std::thread ioThread([&io]() { io.run(); });

    const bool sent = SendStream(path, "after stale cleanup\n");
    WaitForCount(sink, 1);

    reader->Stop();
    ioThread.join();

    ASSERT_TRUE(sent);
    EXPECT_GE(sink.Count(), 1u);
}

TEST(UnixSocketReader, MultipleListenersReceive)
{
    const auto streamPath = TempSocketPath("multi_stream");
    const auto dgramPath = TempSocketPath("multi_dgram");
    RemoveIfExists(streamPath);
    RemoveIfExists(dgramPath);
    MessageSink sink;
    boost::asio::io_context io;

    auto streamReader = MakeReader(io, sink, UnixSocketType::Stream, streamPath);
    auto dgramReader = MakeReader(io, sink, UnixSocketType::Datagram, dgramPath);

    boost::asio::co_spawn(io, streamReader->Run(), boost::asio::detached);
    boost::asio::co_spawn(io, dgramReader->Run(), boost::asio::detached);
    std::thread ioThread([&io]() { io.run(); });

    const bool streamSent = SendStream(streamPath, "stream message\n");
    const bool dgramSent = SendDatagram(dgramPath, "dgram message\n");
    WaitForCount(sink, 2);

    streamReader->Stop();
    dgramReader->Stop();
    ioThread.join();

    ASSERT_TRUE(streamSent);
    ASSERT_TRUE(dgramSent);
    EXPECT_GE(sink.Count(), 2u);
}
