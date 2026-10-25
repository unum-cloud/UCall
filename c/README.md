# UCall for C

Include `ucall/ucall.h` for the whole interface, or include `types.h`, `client.h`, and `server.h` separately beneath `ucall/`.
Every operation that can fail takes its named argument struct and writes a `ucall_outcome_t`.
Getters that cannot fail and handle release functions take their arguments directly.

Link `ucall::ucall` to use the single library containing every enabled backend.
Select `automatic`, `posix`, `linux-epoll`, `linux-uring612`, `linux-uring700`, `macos-kqueue`, or `windows-iocp` in the server or client configuration.
Explicit unavailable selections fail.
CPU classes select compiled string, cryptographic, and atomic kernels after checking the initialization thread's capabilities.
Baseline entry points check cached calling-thread capabilities before entering CPU-specific code.
The application keeps those threads on CPUs supporting the selected class; `serial` is the conservative choice for differing capabilities.
Server shutdown uses baseline atomics and native wakeups, so another thread can stop it without entering CPU-specific code.
UCall creates no threads.
All variants use the same HTTP/1.1 and Noise connection automata.
Both io_uring variants use registered files, direct descriptors, a provided receive-buffer ring, and registered transmission storage.
The 7.0 variant adds multishot receive, combined submit and wait, batched completion advancement, deferred task work, and packed SQ submission.
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
Request handles own immutable received bytes and can outlive their callback until a reply consumes them or the server is freed.
Batch callbacks receive a counted array of retained request handles, followed by the registered context.
The array is borrowed only during the callback; copy its handles into application-owned storage to defer work without copying request bytes.
Each request can be replied to independently, including after the callback returns.
`ucall_server_request_peer()` reports which configured interface a request arrived on and the peer's authenticated Noise static key, zero on plaintext interfaces, until its reply.
Every loop deposits into one queue per batch endpoint, so batches mix requests from all loops, and partial batches flush at their configured deadline.
A reply to a disconnected request reports connection closure and consumes the handle.
All byte views carry an explicit length, including empty and binary values.

HTTP calls support connection reuse, pipelining, chunked receive framing, redirects, and request deadlines.
A server interface's `max_pipelined_requests` and a client's `max_pipelined_calls` bound the requests one connection carries at once; zero means one, and replies leave in request order.
A pipelined connection lost mid-flight retries its unanswered idempotent calls and finishes the rest with `ucall_status_connection_closed_k`.
Servers support immutable routes, size and latency based application batching, retained request views, and content and error replies.
XX and IK servers authenticate clients; KK clients can connect to a separately configured peer, while the server interface cannot specify KK's preknown initiator key.

WebSockets, multipart access, streaming replies, file replies, and metrics remain unsupported and return `ucall_status_unsupported_k` where an outcome is available.
Numeric addresses are handled directly, and reusing a connection does not resolve its host again.
A new connection to a hostname still uses the synchronous system resolver on the polling caller; request deadlines cannot interrupt that resolver.
The Python and Rust SDKs await migration to this ABI.
