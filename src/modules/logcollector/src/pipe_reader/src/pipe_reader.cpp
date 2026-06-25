#include "pipe_reader.hpp"

#include <logger.hpp>

#include <boost/asio/this_coro.hpp>

#include <utility>

using namespace logcollector;

PipeReader::PipeReader(
    std::function<void(const std::string& location, const std::string& log, const std::string& collectorType)>
        pushMessageFunc,
    std::function<Awaitable(std::chrono::milliseconds)> waitFunc,
    std::string path)
    : IReader(std::move(pushMessageFunc), std::move(waitFunc))
    , m_path(std::move(path))
{
}

std::string PipeReader::ListenerId() const
{
    return "pipe:" + m_path;
}

// ----------------------------------------------------------------------------
// SCAFFOLD - not yet implemented (wazuh/wazuh#15178, phase 3).
//
// Planned design (reuses the framing/push logic from src/syslog_reader and
// src/unix_socket_reader, but reads from a FIFO instead of a socket):
//
//   - Open the FIFO at m_path O_RDONLY | O_NONBLOCK (create it with mkfifo first
//     if it does not exist; decide and document the file permissions).
//   - Wrap the file descriptor in boost::asio::posix::stream_descriptor and read
//     newline-delimited messages with async_read_until(fd, buf, '\n'), exactly as
//     UnixSocketReader::HandleStreamClient does.
//   - On EOF (the writer closed its end), reopen the FIFO and wait for the next
//     writer, rather than treating EOF as end-of-stream.
//   - Push each message via m_pushMessage(ListenerId(), msg, m_collectorType).
//   - Close/cancel the descriptor on the io_context thread from Stop().
//
// Validation/wiring (later): add Logcollector::SetupPipeReaders() parsing a config
// section (e.g. logcollector.pipe: [{ path }, ...]) and call it from
// Logcollector::Setup(), POSIX-only. Windows named pipes use a different API and
// are a separate follow-up. Pipe *write* mode (legacy pipe_write) is out of scope.
// ----------------------------------------------------------------------------

Awaitable PipeReader::Run()
{
    const auto executor = co_await boost::asio::this_coro::executor;

    {
        const std::lock_guard<std::mutex> lock(m_pipeMutex);
        m_executor = executor;
    }

    // TODO(#15178): implement the FIFO reader as described above.
    LogWarn("Agent-side pipe reader is not implemented yet (scaffold): {}", ListenerId());
    co_return;
}

void PipeReader::Stop()
{
    m_keepRunning.store(false);

    // TODO(#15178): post the descriptor close/cancel to the io_context executor.
}
