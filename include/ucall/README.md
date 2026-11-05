# UCall Templates

`include/ucall/` holds the header-only templates UCall's servers and clients are built from, for advanced users who compose their own engines, kits or networks.
The public interface stays in `c/ucall/*.h`, and `src/` keeps the C entry points and the per-CPU instantiations.
Every subfolder `ucall/<dir>/` opens `unum::ucall::<dir>`, and every header is spelled `"ucall/<dir>/..."` in the tree and once installed.

## Stability

These headers carry no stability promise.
Their names, layouts and signatures change with the engines that instantiate them, in any release, and only the C ABI of `c/ucall/*.h` is versioned.
Pin a commit, not a version, when building on them.

## Folders

- `utilities/`, in `unum::ucall::utilities`:
  - `types.hpp`: platform and compiler detection, byte and text views, descriptors and polling threads, `allocated_ptr`, `highest_kit` and `successive_pools`, and the `fu`, `st` and `uc` aliases.
    The names every folder and the C entry points share are re-exported into `unum::ucall`.
  - `sockets.hpp`: the clock, socket and file calls each operating system spells its own way, from nonblocking sockets to unbuffered reads opened beneath a directory.
- `io/`, in `unum::ucall::io`:
  - `types.hpp`: `io_request_t` and the operations it asks for, `io_completion_t`, `io_statistics_t`, `wake_channel_t`, and the readiness helpers the polling engines share.
  - `posix_engine.hpp`: `posix_engine`, nonblocking POSIX syscalls completed through poll readiness.
  - `bsd_kqueue_engine.hpp`: `bsd_kqueue_engine` over `kqueue_readiness`, for Apple and FreeBSD.
  - `linux_epollaio_engine.hpp`: `epoll_readiness`, `linux_aio_t` and `linux_epollaio_engine`, with zero-copy sends released from the error queue.
  - `linux_uring612_engine.hpp`: the io_uring components both kernel versions compose, and `linux_uring612_engine` with single-shot buffer-select receives.
  - `linux_uring618_engine.hpp`: `linux_uring618_engine`, with multishot receive streams over the same components.
  - `windows_iocp_engine.hpp`: `windows_iocp_engine`, overlapped sockets and files on an I/O completion port.
- `http/`, in `unum::ucall::http`:
  - `messages.hpp`: the string kits and their ladders, incremental HTTP framing over borrowed views in `messages`, and the received response handle.
  - `routes.hpp`: immutable URI routing with literal, parameter and trailing wildcard precedence.
  - `multipart.hpp`: splitting `multipart/form-data` bodies into parts and the header fields each carries.
  - `percent.hpp`: `percent_codec` and `percent_kit`, decoding the `%XX` escapes of paths and queries through StringZilla's URL unescape helper over the class's byte-set search.
- `dns/`, in `unum::ucall::dns`:
  - `types.hpp`: the stub resolver's record types, answers, timing and size constants, and `resolver_options_t`.
  - `messages.hpp`: composing recursive queries and decoding their answers, bounded by the packet and refusing every malformed one.
  - `configuration.hpp`: reading the resolver settings and the hosts file the way each operating system spells them.
- `tunnel/`, in `unum::ucall::tunnel`:
  - `types.hpp`: Noise modes, roles, requests, states, faults and record kinds, the record geometry, the tunnel configuration, and the step and opened results.
  - `crypto.hpp`: the SHA-256 and AES-256-GCM kits and their ladders, and `secure_tunnel_crypto`, the Noise primitives and pattern state over them.
  - `secure_tunnel.hpp`: `secure_tunnel`, one connection's record layer, plaintext or a Noise handshake and its authenticated records.
  - `curve25519.hpp`: Curve25519 scalar multiplication for the Noise key exchange.
- `network/`, in `unum::ucall::network`, where every template takes the `network_variant` descriptor:
  - `types.hpp`: the server, client, request and batch handles the C faces cast to, with each handle's operation table, the connection, exchange, reply and file window enums, the linger and unsent limits, `reply_segment`, `file_segment`, `file_window_t`, and the event loop and interface statistics.
  - `transports.hpp`: `transport`, the record a server's and a client's connection share: one socket's receive and transmit state through handshakes, records, receives and sends.
  - `exchanges.hpp`: `endpoint`, `batch_endpoint` and its wake state, `exchange_release`, `replied_link` and `server_exchange`, one request and the reply it awaits.
  - `loops.hpp`: `network_interface`, `interface_acceptor`, `file_window_pool`, `loop_metrics` and `event_loop`, one thread's engine, connections and wakeups.
  - `formatting.hpp`: `formatting`, address and acceptor setup, status lines, dates, reply heads, log lines, record spreading and the range and part checks.
  - `replies.hpp`: `replies`, the reply segment and file segment lifecycle from claim and append through the replied queue to sends, file reads and releases.
  - `metrics.hpp`: `metrics`, the StatsD lines each event loop times and emits.
  - `serving.hpp`: `server_connection`, a transport with its exchanges, and `serving`, admission, dispatch to endpoints, streamed bodies, collected replies and each connection's progress through `server_progress`.
  - `server.hpp`: `server`, the server handle with its C entry points and `server_api_k`.
  - `resolving.hpp`: the client's asynchronous stub resolver, its lookups and questions on the client's engine, and the Happy Eyeballs order of the addresses they answer.
  - `client.hpp`: `response`, `response_pool`, `client_exchange`, `client_origin`, `client_connection`, a transport with its calls, and `client`, the client handle with its C entry points and `client_api_k`.

`network.hpp` is the umbrella, holding `network_variant`, the alias-only descriptor every `network/` template takes, and `serial_network`.

Outside `include/`, `cli/ucall.cpp` is the `ucall` command-line client, one HTTP or Noise call over the C ABI, and `test/properties.hpp` holds the oracles over these parsers that the seeded suite cases and the libFuzzer harnesses in `test/fuzz/` share.
