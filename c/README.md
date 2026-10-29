# UCall for C

Include `ucall/ucall.h` for the whole interface, or include `types.h`, `client.h`, and `server.h` separately beneath `ucall/`.
Every operation that can fail takes its named argument struct and writes a `ucall_outcome_t`.
Getters that cannot fail and handle release functions take their arguments directly.

Link `ucall::static` or `ucall::shared`, each a single library containing every enabled backend.
An installed tree or the SDK archive finds them through `find_package(ucall)`, and the shared library through `pkg-config --libs ucall` too.
Select `automatic`, `posix`, `linux-epollaio`, `linux-uring612`, `linux-uring618`, `macos-kqueue`, or `windows-iocp` in the server or client configuration.
Explicit unavailable selections fail.
CPU classes select compiled string, cryptographic, and atomic kernels once, at initialization, under the requested class or the initialization thread's capabilities.
The application keeps those threads on CPUs supporting the selected class; `serial` is the conservative choice for differing capabilities.
Server shutdown uses baseline atomics and native wakeups, so another thread can stop it without entering CPU-specific code.
UCall creates no threads.
All variants use the same HTTP/1.1 and Noise connection automata.
Both io_uring variants use registered files, direct descriptors, a provided receive-buffer ring, a sparse table of registered buffers, `SEND_ZC` zero-copy sends and `READ_FIXED` file reads.
The 6.18 variant adds multishot receive and vectored `READV_FIXED` file reads.
`linux-epollaio` reads files through Linux AIO completing into its epoll set, sends with `MSG_ZEROCOPY`, and refuses to start where `io_setup` is refused, naming `fs.aio-max-nr`.
`posix` and macOS `kqueue` read files blocking, FreeBSD `kqueue` through `aio_read`, and IOCP through overlapped unbuffered reads; these send by copying.
Accepts remain credit-limited one-shot operations: multishot direct accept can consume more connections than a finite file table can install before userspace observes a completion.

Initialize the server and register routes before polling.
`ucall_server_take_call()` drives one loop with a bounded wait; zero timeout performs one nonblocking progress round.
`ucall_server_take_calls()` drives it continuously until `ucall_server_stop()` or failure.
Each loop has one application polling owner, and endpoint callbacks execute synchronously on that caller.
Each batch endpoint has one draining owner, and its callbacks execute on the thread calling `ucall_server_take_batch()` or `ucall_server_take_batches()` with the handle its registration returned.
A deadline cannot preempt a callback.
Stop the server, join its polling threads, and finish application use of retained requests before freeing it.
Native I/O retirement during teardown can block.

Initialize, submit, poll, and free a client on the same owner thread.
`ucall_client_call()` returns a synchronous acceptance outcome; success guarantees one completion and refusal produces none.
Keep the borrowed URL, headers, body, and security-key inputs alive until completion retrieval.
`ucall_client_take_completed()` drives progress and retrieves a batch of records containing the caller cookie, final outcome, and response.
Retrieval returns each call's admission credit.
The connection budget must be positive; a zero call budget uses the connection budget times `max_pipelined_calls`.
Retrieved responses belong to the caller until `ucall_client_response_free()`; client teardown discards unretrieved results.
Response accessors take only the response, which stays readable after its client is freed.
Request handles own immutable received bytes and can outlive their callback until a reply consumes them or the server is freed.
Batch callbacks receive a counted array of retained request handles, followed by the registered context.
The array is borrowed only during the callback; copy its handles into application-owned storage to defer work without copying request bytes.
Each request can be replied to independently, including after the callback returns.
`ucall_server_request_path()` answers the request target without its query, still percent-encoded, beside the segment and parameter accessors.
`ucall_server_request_peer()` reports which configured interface a request arrived on and the peer's authenticated Noise static key, zero on plaintext interfaces, until its reply.
Every loop deposits into one queue per batch endpoint, so batches mix requests from all loops, and partial batches flush at their configured deadline.
A reply to a disconnected request reports connection closure and consumes the handle.
All byte views carry an explicit length, including empty and binary values.

HTTP calls support connection reuse, pipelining, chunked receive framing, redirects, and request deadlines.
A server interface's `max_pipelined_requests` and a client's `max_pipelined_calls` bound the requests one connection carries at once; zero means one, and replies leave in request order.
No call is pipelined behind one that is not idempotent or that sends `Connection: close`.
A pipelined connection lost mid-flight retries its unanswered idempotent calls and finishes the rest with `ucall_status_connection_closed_k`.
Calls a server left unread when it announced a close are sent again on a new connection.
Servers support immutable routes, size and latency based application batching, retained request views, and content, error, vectored and streamed replies.
A streamed reply is chunked for HTTP/1.1 peers, keeps identity framing when its headers declare `Content-Length`, and is delimited by the close for HTTP/1.0 peers; a chunk reports `ucall_status_would_block_k` while the socket lags too far behind.
Vectored replies and stream chunks take reply parts: bytes, a range of a file descriptor the caller keeps open until the outcome is final, or a range of a path opened beneath one of the interface's `reply_directories`.
The event loop opens files with `O_DIRECT`, refusing caller descriptors without it, and reads aligned extents itself before sending the requested slice.
Replies leave through zero-copy sends, so a connection closes only once the kernel let go of what it sent, and resets a peer that stops acknowledging by the linger deadline.
A reply with file or path parts publishes its outcome as `ucall_status_deferred_k`, then success once they are sent, or the cause; a refusal before the head becomes `404` or `416`, and a failure after it resets the connection.
XX and IK servers authenticate clients; KK clients can connect to a separately configured peer, while the server interface cannot specify KK's preknown initiator key.
`ucall_noise_key_generate()` draws a static keypair from the operating system's entropy, reporting `ucall_status_io_k` when it is refused, and `ucall_noise_key_derive()` recovers the public key of a stored private key.

WebSockets, multipart access, and metrics remain unsupported and return `ucall_status_unsupported_k` where an outcome is available.
Numeric addresses are handled directly, and reusing a connection does not resolve its host again.
A new connection to a hostname still uses the synchronous system resolver on the polling caller; request deadlines cannot interrupt that resolver.
The [Python](../python/README.md) and [Rust](../rust/README.md) bindings wrap this ABI and keep its polling model: the application starts every thread.
