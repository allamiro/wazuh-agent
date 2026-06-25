#pragma once

#include <reader.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/local/datagram_protocol.hpp>
#include <boost/asio/local/stream_protocol.hpp>

#include <cstddef>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

/// @brief Collector type reported for messages received by an agent-side UNIX socket listener
const std::string UNIX_SOCKET_READER_TYPE = "remote-unix";

namespace logcollector
{
    /// @brief UNIX domain socket type for a listener
    ///
    /// Mirrors the socket types discussed in wazuh/wazuh#15178:
    ///   - Stream:   SOCK_STREAM  (unix_stream)
    ///   - Datagram: SOCK_DGRAM   (unix_dgram)
    /// SOCK_SEQPACKET (unix_seq) may be added later.
    enum class UnixSocketType
    {
        Stream,
        Datagram
    };

    /// @brief Agent-side UNIX domain socket listener reader
    ///
    /// Creates and listens on a local UNIX domain socket (stream or datagram).
    /// A local service such as rsyslog (omuxsock) or syslog-ng writes to the
    /// socket and the agent ingests each message into the normal Logcollector
    /// processing path, keeping it associated with the receiving agent. This is
    /// the local-socket counterpart of the UDP/TCP SyslogReader.
    ///
    /// One reader handles one socket definition (one type, one path). Multiple
    /// sockets are represented by multiple reader instances.
    class UnixSocketReader : public IReader
    {
    public:
        /// @brief Constructor
        /// @param pushMessageFunc Push message function
        /// @param waitFunc Wait function
        /// @param enqueueTaskFunc Enqueue task function (used to spawn stream client handlers)
        /// @param type UNIX socket type (stream or datagram)
        /// @param path Filesystem path of the UNIX domain socket to create and listen on
        UnixSocketReader(
            std::function<void(const std::string& location, const std::string& log, const std::string& collectorType)>
                pushMessageFunc,
            std::function<Awaitable(std::chrono::milliseconds)> waitFunc,
            std::function<void(boost::asio::awaitable<void>)> enqueueTaskFunc,
            UnixSocketType type,
            std::string path);

        /// @copydoc IReader::Run
        Awaitable Run() override;

        /// @copydoc IReader::Stop
        void Stop() override;

        /// @brief Returns a human-readable identifier for this listener
        /// @return Identifier in the form "<type>:<path>"
        std::string ListenerId() const;

        /// @brief Converts a socket type to its lowercase string representation
        /// @param type Socket type to convert
        /// @return "unix_stream" or "unix_dgram"
        static std::string TypeToString(UnixSocketType type);

        /// @brief Maximum size in bytes of a single message accepted by a listener
        static constexpr std::size_t MAX_MESSAGE_SIZE = 65536;

        /// @brief Maximum length of a UNIX socket path (sun_path is 108 bytes including the null terminator)
        static constexpr std::size_t MAX_PATH_LENGTH = 107;

    private:
        /// @brief Runs the stream (SOCK_STREAM) accept loop
        Awaitable RunStream();

        /// @brief Runs the datagram (SOCK_DGRAM) receive loop
        Awaitable RunDatagram();

        /// @brief Handles a single accepted stream client connection
        /// @param socket Connected client socket
        Awaitable HandleStreamClient(std::shared_ptr<boost::asio::local::stream_protocol::socket> socket);

        /// @brief Normalizes and forwards a received message into the Logcollector path
        /// @param message Raw message received from the socket
        void ProcessMessage(std::string message) const;

        /// @brief Removes the socket file at m_path if it exists and is a socket
        void RemoveSocketFile() const;

        /// @brief Enqueue task function
        std::function<void(boost::asio::awaitable<void>)> m_enqueueTask;

        /// @brief Listener socket type
        UnixSocketType m_type;

        /// @brief Filesystem path of the UNIX domain socket
        std::string m_path;

        /// @brief Collector type reported to the Logcollector pipeline
        const std::string m_collectorType = UNIX_SOCKET_READER_TYPE;

        /// @brief Protects the executor and socket handles shared with Stop()
        std::mutex m_socketMutex;

        /// @brief Executor of the io_context the reader runs on (set when Run starts)
        std::optional<boost::asio::any_io_executor> m_executor;

        /// @brief Datagram socket (when type is Datagram)
        std::shared_ptr<boost::asio::local::datagram_protocol::socket> m_datagramSocket;

        /// @brief Stream acceptor (when type is Stream)
        std::shared_ptr<boost::asio::local::stream_protocol::acceptor> m_acceptor;

        /// @brief Active stream client sockets, tracked so they can be closed on shutdown
        std::list<std::weak_ptr<boost::asio::local::stream_protocol::socket>> m_clients;
    };

} // namespace logcollector
