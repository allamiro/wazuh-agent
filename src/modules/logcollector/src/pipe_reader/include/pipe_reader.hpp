#pragma once

#include <reader.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <functional>
#include <mutex>
#include <optional>
#include <string>

/// @brief Collector type reported for messages received by an agent-side pipe listener
const std::string PIPE_READER_TYPE = "remote-pipe";

namespace logcollector
{
    /// @brief Agent-side named pipe (FIFO) reader (SCAFFOLD - work in progress)
    ///
    /// Reads newline-delimited messages from a local named pipe (FIFO) and ingests
    /// them into the normal Logcollector processing path. This is the third ingress
    /// type from wazuh/wazuh#15178 (after UDP/TCP syslog and UNIX domain sockets),
    /// equivalent to the legacy "syslog-pipe" log format. A service such as rsyslog
    /// (ompipe) writes to the FIFO and the agent drains it.
    ///
    /// Note: a FIFO cannot be read with the FileReader, which assumes seekable,
    /// sizeable, rotatable regular files (SeekEnd/Rotated/Reopen via seekg/tellg and
    /// std::filesystem::file_size). A FIFO is not seekable, reports size 0, blocks on
    /// open until a writer appears, and returns EOF when the writer closes. It
    /// therefore needs a dedicated streaming reader.
    ///
    /// @note Not yet wired into Logcollector::Setup and not yet functional. The
    ///       Run()/Stop() bodies are stubs; see the implementation file for the
    ///       planned design and the TODO markers that remain.
    class PipeReader : public IReader
    {
    public:
        /// @brief Constructor
        /// @param pushMessageFunc Push message function
        /// @param waitFunc Wait function
        /// @param path Filesystem path of the named pipe (FIFO) to read from
        PipeReader(
            std::function<void(const std::string& location, const std::string& log, const std::string& collectorType)>
                pushMessageFunc,
            std::function<Awaitable(std::chrono::milliseconds)> waitFunc,
            std::string path);

        /// @copydoc IReader::Run
        Awaitable Run() override;

        /// @copydoc IReader::Stop
        void Stop() override;

        /// @brief Returns a human-readable identifier for this reader
        /// @return Identifier in the form "pipe:<path>"
        std::string ListenerId() const;

        /// @brief Maximum size in bytes of a single message accepted by the reader
        static constexpr std::size_t MAX_MESSAGE_SIZE = 65536;

    private:
        /// @brief Filesystem path of the named pipe (FIFO)
        std::string m_path;

        /// @brief Collector type reported to the Logcollector pipeline
        const std::string m_collectorType = PIPE_READER_TYPE;

        /// @brief Protects the executor and pipe descriptor shared with Stop()
        std::mutex m_pipeMutex;

        /// @brief Executor of the io_context the reader runs on (set when Run starts)
        std::optional<boost::asio::any_io_executor> m_executor;

        // TODO(#15178): hold the boost::asio::posix::stream_descriptor wrapping the
        //               FIFO file descriptor here so Stop() can cancel/close it.
    };

} // namespace logcollector
