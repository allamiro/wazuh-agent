# UNIX socket reader (scaffold)

Follow-up to the agent-side UDP/TCP syslog listeners (PR for `wazuh/wazuh-agent`,
related to [wazuh/wazuh#15178](https://github.com/wazuh/wazuh/issues/15178)).

**Status: scaffold only.** `UnixSocketReader` is declared and compiles (POSIX
platforms), but `Run()`/`Stop()` are stubs and it is **not** wired into
`Logcollector::Setup`. It does nothing at runtime yet.

## Goal

Let a local service (rsyslog `omuxsock`, syslog-ng, etc.) write to a UNIX domain
socket that the Wazuh agent listens on, ingesting messages through the normal
Logcollector path — the local-socket counterpart of the UDP/TCP listeners.

## Planned design (reuse `src/syslog_reader` patterns)

- **Stream (`unix_stream`, SOCK_STREAM):** `boost::asio::local::stream_protocol::acceptor`
  on the configured path; accept loop spawns a per-connection coroutine reading
  newline-delimited messages (same framing as `SyslogReader::HandleTcpClient`).
- **Datagram (`unix_dgram`, SOCK_DGRAM):** `boost::asio::local::datagram_protocol::socket`
  bound to the path; one datagram == one message (as UDP).
- Push via `m_pushMessage(ListenerId(), msg, m_collectorType)` (`remote-unix`).
- Close sockets on the io_context thread from `Stop()`; track client sockets;
  **unlink a stale socket file before bind** and remove it on shutdown.

## Open decisions

- Socket file **permissions / umask** (who may connect).
- Whether the agent **creates** the socket vs. expecting it to exist.
- Config shape, e.g. `logcollector.unix_socket: [{ type: unix_stream, path: /var/run/wazuh-syslog.sock }]`,
  parsed by a new `Logcollector::SetupUnixSocketReaders()` guarded by
  `BOOST_ASIO_HAS_LOCAL_SOCKETS`.
- `SOCK_SEQPACKET` (`unix_seq`) support.

## TODO checklist

- [ ] Implement stream listener (accept + framed read)
- [ ] Implement datagram listener
- [ ] Stale-socket unlink before bind + cleanup on stop
- [ ] Config parsing + validation + `Setup()` wiring
- [ ] Unit tests (config + runtime, mirroring `syslog_reader` tests)
- [ ] Docs in `docs/ref/modules/logcollector/README.md`
