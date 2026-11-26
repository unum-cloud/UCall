# UCall Templates

`include/ucall/` holds the header-only templates UCall's servers and clients are built from, for advanced users who compose their own queues, kits or networks.
The public interface stays in `c/ucall/*.h`, and `src/` keeps the C entry points and the per-CPU instantiations.
Every subfolder `ucall/<dir>/` opens `unum::ucall::<dir>`, and every header is spelled `"ucall/<dir>/..."` in the tree and once installed.

## Stability

These headers make no stability promise.
Their names, layouts and signatures change with the queues that instantiate them, in any release, and only the C ABI of `c/ucall/*.h` is versioned.
Pin a commit, not a version, when building on them.

## Folders

- `utilities/`, in `unum::ucall::utilities`:
  - `types.hpp`: `publish` for outcomes, byte and text views, descriptors and polling threads, `allocated_ptr`, `highest_kit`, `cpu_ceiling_t`, and the `fu`, `st` and `uc` aliases.
    The names every folder and the C entry points share are re-exported into `unum::ucall`.
  - `sockets.hpp`: the clock, socket and file calls each operating system spells its own way, from nonblocking sockets to unbuffered reads opened beneath a directory.
- `io/`, in `unum::ucall::io`:
  - `types.hpp`: `io_request_t` and the operations it asks for, `io_completion_t`, `io_statistics_t`, `pollable_wakeup_t`, and the readiness helpers the polling queues share.
  - `posix_queue.hpp`: `posix_queue`, nonblocking POSIX syscalls completed through poll readiness.
  - `bsd_kqueue_queue.hpp`: `bsd_kqueue_queue` over `kqueue_readiness`, for Apple and FreeBSD.
  - `polled_file_reads.hpp`: `polled_file_reads`, POSIX AIO control blocks the poll thread reaps between waits, for macOS `kqueue`, which reports no AIO completion.
  - `linux_epollaio_queue.hpp`: `epoll_readiness`, `linux_aio_t` and `linux_epollaio_queue`, with zero-copy sends released from the error queue.
  - `linux_uring612_queue.hpp`: the io_uring components both kernel versions compose, and `linux_uring612_queue` with single-shot buffer-select receives.
  - `linux_uring618_queue.hpp`: `linux_uring618_queue`, with multishot receive streams over the same components.
  - `windows_iocp_queue.hpp`: `windows_iocp_queue`, overlapped sockets and files on an I/O completion port.
  - `windows_rio_queue.hpp`: `windows_rio_queue`, Registered I/O sockets beside overlapped accepts, connects and files on one port.
- `http/`, in `unum::ucall::http`:
  - `messages.hpp`: the string kits and their ladders, incremental HTTP framing over views into the caller's bytes in `messages`, and the received response handle.
  - `routes.hpp`: immutable URI routing with literal, parameter and trailing wildcard precedence.
  - `multipart.hpp`: splitting `multipart/form-data` bodies into parts and the header fields of each.
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
  - `loops.hpp`: `network_interface`, `interface_acceptor`, `file_window_pool`, `loop_metrics` and `event_loop`, one thread's queue, connections and wakeups.
  - `formatting.hpp`: `formatting`, address and acceptor setup, status lines, dates, reply heads, log lines, record spreading and the range and part checks.
  - `replies.hpp`: `replies`, the reply segment and file segment lifecycle from claim and append through the replied queue to sends, file reads and releases.
  - `metrics.hpp`: `metrics`, the StatsD lines each event loop times and emits.
  - `serving.hpp`: `server_connection`, a transport with its exchanges, and `serving`, admission, dispatch to endpoints, streamed bodies, collected replies and each connection's progress through `server_progress`.
  - `server.hpp`: `server`, the server handle with its C entry points and `server_api_k`.
  - `resolving.hpp`: the client's asynchronous stub resolver, its lookups and questions on the client's queue, and the Happy Eyeballs order of the addresses they answer.
  - `client.hpp`: `response`, `response_pool`, `client_exchange`, `client_origin`, `client_connection`, a transport with its calls, and `client`, the client handle with its C entry points and `client_api_k`.

`network.hpp` is the umbrella, holding `network_variant`, the alias-only descriptor every `network/` template takes, and `serial_network`.

Outside `include/`, `tools/ucall.cpp` is the `ucall` command-line client, one HTTP or Noise call over the C ABI, and `test/properties.hpp` holds the oracles over these parsers that the seeded suite cases and the libFuzzer harnesses in `test/fuzz/` share.

## I/O Queues

Every queue answers the same requests, and each spends what its kernel offers:

- __io_uring.__
  Both io_uring variants use registered files, direct descriptors, an incremental provided receive-buffer ring, a sparse table of registered buffers, `SEND_ZC` zero-copy sends of file windows and segments of a page or more, `SENDMSG` gathered sends of shorter ones, and `READ_FIXED` file reads.
  The 6.18 variant adds multishot receive and vectored `READV_FIXED` file reads.
- __Readiness and completion ports.__
  `linux-epollaio` reads files through Linux AIO completing into its epoll set, sends the same with `MSG_ZEROCOPY`, and refuses to start where `io_setup` is refused, naming `fs.aio-max-nr`.
  `posix` reads files blocking; FreeBSD `kqueue` reads them through `aio_read` landing as `EVFILT_AIO` events, and macOS `kqueue` through `aio_read`, a vectored read as `lio_listio` batches, polled with `aio_error` while its wait shrinks from 1 µs to 1 ms; IOCP reads through overlapped unbuffered reads. These send by copying, and a kernel refusing to queue a read has it read blocking.
  The readiness queues gather a `send_vectors_k` through `sendmsg`, while IOCP and Registered I/O, whose loops send one span at a time, refuse one.
- __Credit-limited accepts.__
  Accepts remain one-shot operations: multishot direct accept can consume more connections than a finite file table can install before userspace observes a completion.
