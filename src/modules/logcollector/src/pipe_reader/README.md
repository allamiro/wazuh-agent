# Pipe (FIFO) reader (scaffold)

Phase 3 of the agent-side ingress from
[wazuh/wazuh#15178](https://github.com/wazuh/wazuh/issues/15178), after the UDP/TCP
syslog listeners and the UNIX domain socket listeners.

**Status: scaffold only.** `PipeReader` is declared and compiles (POSIX), but
`Run()`/`Stop()` are stubs and it is **not** wired into `Logcollector::Setup`. It
does nothing at runtime yet.

## Why a dedicated reader (not the FileReader)

A FIFO is a filesystem path, but it cannot be read with the `FileReader`, which
assumes seekable, sizeable, rotatable regular files (`SeekEnd`, `Rotated` via
`std::filesystem::file_size`, `Reopen`, `seekg`/`tellg`). A FIFO is not seekable,
reports size 0, blocks on open until a writer appears, and returns EOF when the
writer closes — so it needs a streaming reader.

## Planned design (reuse `src/unix_socket_reader` / `src/syslog_reader`)

- Open the FIFO `O_RDONLY | O_NONBLOCK` (create with `mkfifo` if missing; decide
  and document permissions).
- Wrap the fd in `boost::asio::posix::stream_descriptor` and read newline-delimited
  messages with `async_read_until(fd, buf, '\n')` (same framing as the stream
  socket handler).
- On EOF (writer closed), reopen and wait for the next writer instead of stopping.
- Push via `m_pushMessage(ListenerId(), msg, m_collectorType)` (`remote-pipe`).
- Cancel/close the descriptor on the io_context thread from `Stop()`.

## Open decisions

- Whether the agent **creates** the FIFO (`mkfifo`) vs. expecting it to exist.
- FIFO **permissions** (who may write).
- Config shape, e.g. `logcollector.pipe: [{ path: /var/run/wazuh.pipe }]`, parsed by
  a new `Logcollector::SetupPipeReaders()` (POSIX-only).

## Out of scope for this phase

- **Windows named pipes** (different API).
- Pipe **write** mode (legacy `pipe_write`); this reader only consumes a FIFO.

## TODO checklist

- [ ] Open/create FIFO + reopen-on-EOF loop
- [ ] Framed read via `posix::stream_descriptor`
- [ ] Config parsing + validation + `Setup()` wiring
- [ ] Unit tests (config + runtime, mirroring the other readers)
- [ ] Docs in `docs/ref/modules/logcollector/README.md`
