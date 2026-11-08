# UCall for C

Include `ucall/ucall.h` for the whole interface, or include `types.h`, `client.h`, and `server.h` separately beneath `ucall/`.
Every operation that can fail takes its named argument struct and writes a `ucall_outcome_t`.
Getters that cannot fail and handle release functions take their arguments directly.
The [Python](../python/README.md) and [Rust](../rust/README.md) bindings wrap this ABI and keep its polling model: the application starts every thread.

## Installation

Link `ucall::static` or `ucall::shared`, each a single library containing every enabled backend.
An installed tree or the SDK archive finds them through `find_package(ucall)`, and the shared library through `pkg-config --libs ucall` too.

## Quickstart

[`examples/hello.c`](../examples/hello.c) initializes a server on one interface, registers an echo route, and polls its event loop until stopped.

## Serving

Initialize the server and register routes before polling.
`ucall_server_take_call()` drives one loop with a bounded wait; zero timeout performs one nonblocking progress round.
`ucall_server_take_calls()` drives it continuously until `ucall_server_stop()` or failure.
An interface's `listen_descriptor` accepts on a listening socket the caller opened, such as one systemd passed in, instead of binding `address`; UCall accepts on duplicates and never closes it.
Routing is exact: empty segments are segments and a trailing slash is significant.
A path no route takes answers 404, other verbs' routes answer 405 with `allow`, GET routes serve HEAD, `OPTIONS` answers 204 with `allow`, and `Expect: 100-continue` gets its interim response once the request is next and its body is wanted.
An interface at its connection budget evicts its least recently progressed idle keep-alive connection for a new peer.
A server interface's `max_pipelined_requests` bounds the requests one connection carries at once; zero means one, and replies leave in request order.
Servers support immutable routes, size and latency based application batching, retained request views, and content, error, vectored and streamed replies.
The `metrics_*` configuration reports StatsD counters.
The first `ucall_server_stop()` drains: listeners and idle connections close, and every held request gets its reply before its connection closes; a second stop cuts what is still in flight.
Stop the server, join its polling threads, and finish application use of retained requests before freeing it.
Native I/O retirement during teardown can block.

## Requests

Request handles own immutable received bytes and can outlive their callback until a reply consumes them or the server is freed.
Each request can be replied to independently, including after the callback returns.
`ucall_server_request_path()` answers the request target without its query, still percent-encoded, beside the segment and parameter accessors, and `ucall_server_request_query()` answers the raw query after the first `?`.
`ucall_decode_percent()` decodes the `%XX` escapes of either, and `+` as a space in a query.
`ucall_server_request_fields_count()` and `ucall_server_request_field()` walk the header fields in arrival order, names lowercased and values trimmed, beside the by-name `ucall_server_request_header()`; responses offer the same pair.
`ucall_server_request_peer()` reports which configured interface a request arrived on, the peer's authenticated Noise static key, zero on plaintext interfaces, and its `ucall_peer_address_t`: IPv4, IPv6 with its scope, or AF_UNIX.
Multipart bodies are read part by part through `ucall_server_request_parts_count()` and `ucall_server_request_part()`.
A reply to a disconnected request reports connection closure and consumes the handle.
All byte views carry an explicit length, including empty and binary values.

## Files & Streams

A streamed reply is chunked for HTTP/1.1 peers, keeps identity framing when its headers declare `Content-Length`, and is delimited by the close for HTTP/1.0 peers; a chunk reports `ucall_status_would_block_k` while the socket lags too far behind.
Vectored replies and stream chunks take reply parts: bytes, a range of a file descriptor the caller keeps open until the outcome is final, or a range of a path opened beneath one of the interface's `reply_directories`.
The event loop opens files with `O_DIRECT`, refusing caller descriptors without it, and reads aligned extents itself before sending the requested slice.
Replies leave through zero-copy sends, so a connection closes only once the kernel let go of what it sent, and resets a peer that stops acknowledging by the linger deadline.
A reply with file or path parts publishes its outcome as `ucall_status_deferred_k`, then success once they are sent, or the cause; a refusal before the head becomes `404` or `416`, and a failure after it resets the connection.

## Batches

Batch callbacks receive a counted array of retained request handles, followed by the registered context.
The array is borrowed only during the callback; copy its handles into application-owned storage to defer work without copying request bytes.
Every loop deposits into one queue per batch endpoint, so batches mix requests from all loops, and partial batches flush at their configured deadline.

The batch endpoint's polling owner can also manage the engines the batch feeds, with no thread of its own per engine.
Each USearch, UStore and UForm executor runs one call at a time, and a deferred call on a caller-exclusive executor finishes on that executor's threads, so the owner submits one deferred call per executor and replies from the status words:

```c
ucall_server_take_batch(&take);                     // its callback copies the request handles out
search.completion = usearch_completion_deferred_k;  // every query of the batch, in one call
usearch_dense_search(&search);
read.completion = ustore_completion_deferred_k;     // every document of the batch, in one call
ustore_docs_read(&read);
while (usearch_outcome_status(search.outcome) == usearch_status_deferred_k ||
       ustore_outcome_status(read.outcome) == ustore_status_deferred_k)
    ucall_server_take_calls(&calls);                // keep serving the plain endpoints meanwhile
reply_to_each(requests, &search, &read);            // ucall_server_reply_content per request
```

## Calling

`ucall_client_call()` returns a synchronous acceptance outcome; success guarantees one completion and refusal produces none.
Keep the borrowed URL, headers, body, and security-key inputs alive until completion retrieval.
`ucall_client_take_completed()` drives progress and retrieves a batch of records containing the caller cookie, final outcome, and response.
Retrieval returns each call's admission credit.
The connection budget must be positive; a zero call budget uses the connection budget times `max_pipelined_calls`.
Retrieved responses belong to the caller until `ucall_client_response_free()`; client teardown discards unretrieved results.
Response accessors take only the response, which stays readable after its client is freed.
HTTP calls support connection reuse, pipelining, chunked receive framing, redirects, and request deadlines.
A client's `max_pipelined_calls` bounds the calls one connection carries at once, and no call is pipelined behind one that is not idempotent or that sends `Connection: close`.
A pipelined connection lost mid-flight retries its unanswered idempotent calls and finishes the rest with `ucall_status_connection_closed_k`.
Calls a server left unread when it announced a close are sent again on a new connection.
Host names go through a built-in stub resolver driven by the client's own engine: `/etc/resolv.conf` with `search` and `ndots` and `/etc/hosts` on POSIX, the adapters' settings on Windows, AAAA and A over UDP with TCP on truncation, CNAME chains, and answers cached for their TTL.
Connections race the answered addresses as RFC 8305's Happy Eyeballs does.
`max_response_bytes` caps what a call buffers, failing with `ucall_status_overflow_k` past it, and the client's `log` reports failed dials, refused handshakes and refused redirects.

## Noise Keys

XX and IK servers authenticate clients; KK clients connect to a separately configured peer, and a KK server interface names its preknown initiator in `noise_peer_key`.
`ucall_noise_key_generate()` draws a static keypair from the operating system's entropy, reporting `ucall_status_io_k` when it is refused, and `ucall_noise_key_derive()` recovers the public key of a stored private key.

## Threads & Polling

UCall creates no threads.
Each loop has one application polling owner, and endpoint callbacks execute synchronously on that caller.
Each batch endpoint has one polling owner, and its callbacks execute on the thread calling `ucall_server_take_batch()` or `ucall_server_take_batches()` with the handle its registration returned.
A deadline cannot preempt a callback.
One owner at a time may submit, poll, or free a client, on any thread.
CPU classes select compiled string, cryptographic, and atomic kernels once, at initialization, under the requested class or the initialization thread's capabilities.
The application keeps those threads on CPUs supporting the selected class; `serial` is the conservative choice for differing capabilities.
Server shutdown uses baseline atomics and native wakeups, so another thread can stop it without entering CPU-specific code.

## Design

- __Backends.__
  Select `automatic`, `posix`, `linux-epollaio`, `linux-uring612`, `linux-uring618`, `bsd-kqueue`, or `windows-iocp` in the server or client configuration; explicit unavailable selections fail.
  All variants use the same HTTP/1.1 and Noise connection automata.
- __io_uring.__
  Both io_uring variants use registered files, direct descriptors, an incremental provided receive-buffer ring, a sparse table of registered buffers, `SEND_ZC` zero-copy sends and `READ_FIXED` file reads.
  The 6.18 variant adds multishot receive and vectored `READV_FIXED` file reads.
- __Readiness and completion ports.__
  `linux-epollaio` reads files through Linux AIO completing into its epoll set, sends with `MSG_ZEROCOPY`, and refuses to start where `io_setup` is refused, naming `fs.aio-max-nr`.
  `posix` and macOS `kqueue` read files blocking, FreeBSD `kqueue` through `aio_read`, and IOCP through overlapped unbuffered reads; these send by copying.
- __Credit-limited accepts.__
  Accepts remain one-shot operations: multishot direct accept can consume more connections than a finite file table can install before userspace observes a completion.
