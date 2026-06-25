#pragma once

#include <reader.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <functional>
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

    /// @brief Agent-side UNIX domain socket listener reader (SCAFFOLD - work in progress)
    ///
    /// This is the follow-up to the UDP/TCP SyslogReader, extending agent-side
    /// ingress to local UNIX domain sockets as requested in wazuh/wazuh#15178. A
    /// service such as rsyslog (omuxsock) or syslog-ng writes to the socket and the
    /// agent ingests the messages into the normal Logcollector processing path,
    /// keeping them associated with the receiving agent.
    ///
    /// @note Not yet wired into Logcollector::Setup and not yet functional. The
    ///       Run()/Stop() bodies are stubs; see the implementation file for the
    ///       planned design and the TODO markers that remain.
    class UnixSocketReader : public IReader
    {
    public:
        /// @brief Constructor
        /// @param pushMessageFunc Push message function
        /// @param waitFunc Wait function
        /// @param enqueueTaskFunc Enqueue task function (for per-connection handlers, stream type)
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

    private:
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

        // TODO(#15178): hold the boost::asio::local::stream_protocol::acceptor /
        //               datagram_protocol::socket and active client sockets here,
        //               mirroring SyslogReader, so Stop() can close them cleanly.
    };

} // namespace logcollector
