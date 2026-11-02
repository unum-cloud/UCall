<h1 align="center">UCall</h1>
<h3 align="center">
  Simple Secure Web Client and Server Framework<br />
  Caller-Owned Polling, SIMD Kernels, and Retained Request Batches<br />
</h3>
<br />

> What would a web framework look like built around Noise, io_uring, and SIMD?
> UCall keeps application handlers synchronous while its connection state machines overlap network I/O.

<p align="center">
  <a href="https://discord.gg/xuDmpbEDnQ"><img height="25" src="https://github.com/unum-cloud/.github/raw/main/assets/discord.svg" alt="Discord"></a>
  &nbsp;&nbsp;&nbsp;
  <a href="https://www.linkedin.com/company/unum-cloud/"><img height="25" src="https://github.com/unum-cloud/.github/raw/main/assets/linkedin.svg" alt="LinkedIn"></a>
  &nbsp;&nbsp;&nbsp;
  <a href="https://twitter.com/unum_cloud"><img height="25" src="https://github.com/unum-cloud/.github/raw/main/assets/twitter.svg" alt="Twitter"></a>
  &nbsp;&nbsp;&nbsp;
  <a href="https://unum.cloud/post"><img height="25" src="https://github.com/unum-cloud/.github/raw/main/assets/blog.svg" alt="Blog"></a>
  &nbsp;&nbsp;&nbsp;
  <a href="https://github.com/unum-cloud/UCall"><img height="25" src="https://github.com/unum-cloud/.github/raw/main/assets/github.svg" alt="GitHub"></a>
</p>

---

UCall is a ¹ performance-oriented, ² portable, and ³ compact HTTP/RPC framework, with a ⁴ twist!
How ¹ fast?
About 291,000 1 KiB echoes per second from one server thread natively, about 278,000 through its Rust bindings and about 268,000 through its Python bindings, against about 83,000 for gRPC on tonic, 21,000 for FastAPI and 15,000 for Python gRPC, in the [framework comparison](bench/README.md#framework-comparison).
How ² portable?
A C ABI fronts a C++20 core with POSIX, Linux epoll with AIO and io_uring, macOS/FreeBSD kqueue, and Windows IOCP backends.
Python and Rust bindings wrap that ABI directly, with the same caller-owned polling threads.
How ³ compact?
HTTP framing, routing, and transport state live in templated headers, with one native library exporting the C interface.
What's the ⁴ twist?
For encrypted native connections, it uses the Noise secure communication protocol instead of implementing TLS.

Moreover, it's easy to use synchronous handlers, even when the underlying backend uses asynchronous IO like Linux `io_uring`.
And it provides server-side batching for high-latency batch-processing endpoints, like GPU inference tasks and OLAP database queries.
The [native examples](examples/README.md) demonstrate binary echo, conditional key-value writes, atomic ledger transfers, and batched inference through the C ABI.

## 📊 FastAPI UX Comparison

Both columns serve the same typed endpoint; UCall's [Python bindings](python/README.md) bind its parameters in C and answer on the polling thread.

<table width="100%">
<tr>
<th width="50%">FastAPI</th><th width="50%">UCall</th>
</tr>
<tr>
<td>

```sh
pip install fastapi uvicorn
```

</td>
<td>

```sh
pip install ucall
```

</td>
</tr>
<tr>
<td>

```python
from fastapi import FastAPI

server = FastAPI()

@server.get('/sum')
def sum(a: int, b: int):
    return a + b

import uvicorn
uvicorn.run(server, host='0.0.0.0', port=8000)
```

</td>
<td>

```python
import ucall

server = ucall.Server(ucall.Interface('0.0.0.0:8000'))

@server.get('/sum')
def sum(a: int, b: int):
    return a + b

server.run()
```

</td>
</tr>
</table>

## 📈 Performance Metrics

The native [benchmark driver](bench/README.md) measures complete HTTP exchanges through the C ABI, including connection reuse, response validation, throughput, latency percentiles through p99.99, and client CPU time per request.
It runs closed-loop by default, or open-loop at a fixed arrival rate that charges each call its delay from the intended send time.
Each run records the selected backend, CPU kernel class, application polling threads, connection budget, and calls in flight.
On the server side, `ucall_server_event_loop_statistics()` counts each loop's submissions, completions, kernel enters, and copied bytes, which the echo example prints on exit to price one request.
The [framework comparison](bench/README.md#framework-comparison) serves a 1 KiB loopback echo and a typed sum through UCall natively and through its Rust and Python bindings, axum, actix-web, FastAPI and Python gRPC from the same cores.
The guide also measures pipelining depth, Noise against TLS 1.3 behind nginx, scaling across event loops, and 10,000 connections.
The [C ABI page](c/README.md) describes the implemented native surface; SDK, WebSocket, and authorization plans below are labeled as such.

## Design Principles

### Asynchronous Framework for Synchronous Applications

Talking to remote services over a network can cost much more than the local computation that handles a request.
Moreover, the packet exchange between the application and the network card involves multiple context switches and kernel calls.
To mitigate these latencies, UCall uses several asynchronous IO mechanisms under the hood, like `io_uring`.
Now the question is, how to expose this asynchrony to the user code?

The UCall way is to keep the application code synchronous.
No `async`/`await` keywords or `future`/`promise` handles.
For lightweight operations, a handler stays an ordinary synchronous function.
For heavy operations, there is no secret pill, but there is a common "latency hiding" trick - batching.

Batch endpoints group independent requests by their configured size and latency budgets.
Endpoint callbacks run synchronously on the application polling caller; a deadline cannot preempt a callback.
Registering a batch endpoint returns its `ucall_http_batch_endpoint_t` handle.
Each batch endpoint has one queue fed by every event loop and one application thread draining that handle through `ucall_server_take_batches()`, so its callback never runs on an event loop.
With `max_pipelined_requests` on an interface and `max_pipelined_calls` on a client, one connection carries several requests at once, so a single client can fill a batch; replies still leave in request order.

### Caller-Owned Polling

Select the backend and CPU class in the server or client configuration.
The polling threads must support the selected CPU class; `serial` is a conservative choice when their capabilities differ from the initialization thread's.
UCall creates no threads.

Register server routes before polling.
`ucall_server_take_call()` advances one loop with a bounded wait; a zero timeout performs one nonblocking progress round.
`ucall_server_take_calls()` drives that loop continuously until shutdown.
Each loop has one application owner, and `ucall_server_stop()` can wake it from another thread.

`ucall_client_call()` submits an exchange and returns its acceptance result.
Each accepted call produces one final record through `ucall_client_take_completed()`, which drives I/O and retrieves completion batches.
Initialize, submit, poll, and free a client on the same owner thread.
Keep borrowed request inputs alive until their completion is retrieved.
After retrieval, the caller owns each response until `ucall_client_response_free()`, even past client teardown.
Stop and join server polling threads before freeing the server.

### Encryption: From TLS to Noise

There is a good reason to implement TLS in a networking library - it's the most widespread encryption standard on the Internet.
There is also every reason not to - TLS is a massive and complex standard, with multiple versions, dozens of cipher suites, countless configuration options, error-prone details, and poor ergonomics.
Integrating TLS properly even using OpenSSL, BoringSSL, LibreSSL, and mbedTLS in a clean & performant way in line with principles of Unum - failed twice over two years.

Moreover, the certificate management, PKI, and trust chains are an absolute ergonomic nightmare.
There is a better way... that is broadly deployed, but little known.
The Noise Protocol Framework!

UCall uses a `protocol+transport` URL scheme convention (like Docker's `http+unix://`) to explicitly specify the transport: `http://` or `http+noise://`.
WebSocket transports are planned.
Noise uses a Diffie-Hellman __(DH)__ key exchange to establish a shared secret between the client and server, with the handshake pattern determining which keys each side must know.
Several handshake patterns are defined, each suitable for different use cases:

- __XX__: Full mutual authentication where both parties authenticate each other during the handshake.
  Best for peer-to-peer scenarios or when the server doesn't have a fixed identity known in advance.
- __IK__: Client knows the server's public key in advance (Identity Known).
  Provides faster handshakes and is ideal for typical client-server architectures, similar to TLS with certificate pinning.
- __KK__: Both parties know each other's public keys beforehand (Known Known).
  A server interface names the one initiator key it admits through `noise_peer_key`, and a client names the server's key per call.

`ucall_noise_key_generate()` draws static keys from the operating system's entropy, and `ucall_noise_key_derive()` recovers the public key that peers see from a stored private one.

Noise can be implemented in several ways, depending on the choice of three cryptographic primitives: Diffie-Hellman key exchange, symmetric cipher, and hash function.
Examples of primitive combinations are:

| Name                       | Key exchange |            Cipher |    Hash |
| :------------------------- | -----------: | ----------------: | ------: |
| `25519_AESGCM_SHA256`      |   Curve25519 |       AES-256-GCM | SHA-256 |
| `25519_ChaChaPoly_SHA256`  |   Curve25519 | ChaCha20-Poly1305 | SHA-256 |
| `25519_ChaChaPoly_BLAKE2s` |   Curve25519 | ChaCha20-Poly1305 | BLAKE2s |
| `448_ChaChaPoly_SHA512`    |     Curve448 | ChaCha20-Poly1305 | SHA-512 |

UCall implements exclusively the `25519_AESGCM_SHA256`.
First, it uses the [Curve25519](https://en.wikipedia.org/wiki/Curve25519) elliptic curve for the DH asymmetric key exchange to produce a shared secret.
Then, it uses the [AES-256-GCM](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) authenticated symmetric cipher for encrypting and decrypting the data.
Finally, it uses the [SHA-256](https://en.wikipedia.org/wiki/SHA-2) hash function for hashing operations during the handshake and key derivation.

Why choose AES-256-GCM and SHA-256?
Both primitives ship in [StringZilla][stringzilla], so the transport shares the framework's capability-selected kernels rather than maintaining a separate cryptographic backend.
The selected CPU class carries matching string searches, AES-GCM, SHA-256, and atomic operations together.
The implemented x86 and Arm kernels use the available cryptographic instruction paths, with serial fallbacks for the baseline class.

Noise itself sits __beneath__ HTTP, independently of the socket backend.
Payloads split into independently authenticated records, invisible to the protocol above.
The record bound comes from its two-byte length prefix and authentication overhead; it does not become an application message-size limit.

### Authentication: Macaroons, Biscuits, and Other Pastries

__Roadmap:__ Native Macaroon and Biscuit parsers are not implemented.
The following describes the authorization model being considered; current applications inspect headers and apply their own policy.

Traditional web authentication often combines OAuth2 flows, JWTs, and session cookies.
Delegating access to part of a service can require additional token issuance, scopes, and consent flows; capability tokens offer another way to express those restrictions.

There is a better way, pioneered by Google in 2014: [Macaroons][macaroons].
A Macaroon is a bearer token built on chained HMACs that supports __attenuation__ - anyone holding a token can add restrictions to it, but nobody can remove them.
No database lookup required for verification, just the server's secret key.

```
Original token:  user=alice, account=12345
                        ↓
Alice restricts: user=alice, account=12345, time < 2025-01-01, method = GET
                        ↓
Alice gives to Bob - Bob can only read, only until January
                        ↓
Bob restricts:   user=alice, account=12345, time < 2025-01-01, method = GET, path = /api/reports/*
                        ↓
Bob gives to Carol - Carol can only read reports, nothing else
```

The cryptography (HMAC chain) guarantees that restrictions can never be removed - only added.
The server verifies the signature, then evaluates each restriction against the current request.
No round-trip to a database, no OAuth dance for delegation.

[Biscuit][biscuit] is the modern successor, replacing free-form restriction strings with a proper [Datalog][datalog] query language and swapping HMAC (symmetric) for Ed25519 (asymmetric).
This means verification requires only the server's __public__ key - multiple services can verify tokens without sharing secrets.

```datalog
// Biscuit token with Datalog restrictions
user("alice");
role("viewer");
check if time($t), $t < 2025-01-01T00:00:00Z;
check if operation($op), ["read", "list"].contains($op);
check if resource($r), $r.starts_with("/api/");
```

The proposed integration would cover time bounds, path patterns, HTTP methods, IP ranges, and application-defined restrictions.
A possible `Authorization` header format is `Authorization: Macaroon <base64>` or `Authorization: Biscuit <base64>`; the current framework does not interpret either token.

Why "pastries"?
Because capability-based tokens are delicious - they're self-contained, offline-verifiable, and delegation-friendly.
Macaroons are used by the Lightning Network for Bitcoin payments.
Biscuits power Clever Cloud's infrastructure.
Both are battle-tested at scale.

[macaroons]: https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/
[biscuit]: https://biscuitsec.org
[datalog]: https://en.wikipedia.org/wiki/Datalog

### Protocol Identity: SPIFFE

__Roadmap:__ SPIFFE integration and SVID binding to Noise keys are not implemented.

Authentication tokens answer "what can this request do?" but not "who is making it?"
In traditional deployments, workloads authenticate using static credentials - API keys, service account tokens, or certificates manually provisioned by operators.
These secrets end up in config files, environment variables, and CI/CD pipelines, creating a sprawling attack surface.

[SPIFFE][spiffe] (Secure Production Identity Framework for Everyone) takes a different approach: workloads prove their identity through __attestation__, not secrets.
Instead of "here's my password", it's "here's cryptographic proof of what I am" - verified by inspecting process attributes, Kubernetes pod labels, AWS instance metadata, or other environmental signals.

A SPIFFE identity is a URI: `spiffe://example.com/service/api-server`.
The workload receives a short-lived identity document (SVID - SPIFFE Verifiable Identity Document), with its issuer and deployment policy controlling renewal.
No secrets in config files.
No manual certificate management.
If the workload dies and restarts, it re-attests and gets fresh credentials.

```
┌─────────────────────────────────────────────────────────────────┐
│  Traditional: Static secrets in config                          │
│  API_KEY=sk_live_abc123... ← Leaked? Game over.                 │
├─────────────────────────────────────────────────────────────────┤
│  SPIFFE: Identity from attestation                              │
│  Process starts → Agent inspects (PID, UID, k8s labels)         │
│                 → Issues a short-lived identity document        │
│                 → Renews before expiry                          │
│  No application API keys in config; workload attestation        │
│  provides the basis for issuing its identity.                   │
└─────────────────────────────────────────────────────────────────┘
```

A future integration would need to verify a binding between the SPIFFE identity and the Noise static key.
After an authenticated exchange, an application could authorize based on the client's SPIFFE ID pattern: `spiffe://prod.example.com/service/*` allows any production service, while `spiffe://prod.example.com/service/payment-*` restricts to payment services only.

The intended separation is Noise for channel encryption, SPIFFE for workload identity, and Macaroons or Biscuits for delegated capabilities.
Only the Noise transport and application peer-authorization callbacks are implemented today.

[spiffe]: https://spiffe.io

### Engineered for Performance

The shared connection automata consume completions and emit I/O requests for POSIX, Linux epoll with AIO, Linux io_uring 6.12 or 6.18, kqueue, and IOCP.
HTTP framing, routing, and Noise stay in templated headers under `include/ucall/`.
One library exposes the C ABI once; server and client configuration select the backend and a compiled CPU class.
Per-CPU instantiation units specialize every enabled native engine, while ordinary C calls use their handle's fixed operation table.

The implementation uses:

- [StringZilla](https://github.com/ashvardanian/StringZilla) for SIMD searches, header normalization, SHA-256, and AES-256-GCM.
- [ForkUnion](https://github.com/ashvardanian/ForkUnion) for capability checks and extended atomic references.
- [SmashTable](https://github.com/ashvardanian/SmashTable) for fallible containers and the examples' strictly serializable transactions.

There is no OpenSSL, no libsodium, and no third-party Noise implementation.
The Curve25519 implementation lives separately from StringZilla's symmetric cipher and hash kernels.

[stringzilla]: https://github.com/ashvardanian/StringZilla
[simdjson]: https://github.com/simdjson/simdjson
[simdutf]: https://github.com/simdutf/simdutf
[turbobase64]: https://github.com/powturbo/Turbo-Base64
[ada]: https://github.com/ada-url/ada

### Protocol Flexibility: REST and JSON-RPC

The current C ABI exposes path, query, header, and body views for REST-style APIs.
JSON-RPC conversion and higher-level parameter decoding are planned:

- __Path Parameters__: Extract from URL pattern, e.g., `/users/{user_id}/posts/{post_id}`
- __Query Parameters__: Extract from query string, e.g., `/search?q=rust&limit=10`
- __JSON Body__: Applications can parse raw body bytes, e.g., `{"temperature": 0.7, "max_tokens": 100}`; automatic decoding is planned
- __Multipart Body__: Planned support for files + metadata in one request

The routing and raw-body interface already lets an application implement either shape; the framework does not yet supply the JSON-RPC adapter.
Why support JSON-RPC?

- Broadly supported, especially in decentralized software.
- Human, machine, and LLM-friendly format with no vendor lock-in.
- Enables batch requests, allowing multiple calls in a single HTTP request.

### Multipart Data and Rich Types

__Roadmap:__ Python rich-type conversion and the following SDK example await implementation or migration.

A `multipart/form-data` body lets an application send files and metadata in a single HTTP request.
The client supplies the boundary parameter, and `ucall_server_request_parts_count()` and `ucall_server_request_part()` split the buffered body on it the first time a handler asks.
Each part keeps its own `Content-Disposition` name and `Content-Type`, and its payload is a view into the receive buffer, never copied, so an image or audio decoder reads it in place.
The intended Python SDK could decode `numpy.ndarray` and `PIL.Image` inputs and outputs.
The following is an illustrative design sketch, requiring future SDK support and application-provided model and index setup, for a multi-modal semantic search platform built on top of Unum's [UForm](https://github.com/unum-cloud/UForm) models and [USearch](https://github.com/unum-cloud/USearch) engine.

```python
from ucall import Server
from usearch import Index
from uform import get_model

server = Server()
model = get_model('unum-cloud/uform-vl-multilingual')

@server
def vectorize(description: str, photo: PIL.Image.Image) -> numpy.ndarray:
    image = model.preprocess_image(photo)
    tokens = model.preprocess_text(description)
    joint_embedding = model.encode_multimodal(image=image, text=tokens)

    return joint_embedding.cpu().detach().numpy()

@server
def search(vector: numpy.ndarray, top_k: int = 10):
    matches = index.search(vector, top_k)
    return matches.keys.tolist()
```

The intended wire interface could be called with standard tools like `curl`; this route is part of the sketch above:

```sh
curl -X POST http://localhost:8545/vectorize \
  -F "description=A cat in a hat" \
  -F "photo=@image.jpg"
```

### Client-Side Batching ≠ Server-Side Batching

When building high-throughput applications, it's common to batch multiple requests together on the client side to reduce network overhead.
For JSON-RPC, that's trivial - pack a JSON array of individual procedure calls:

```json
[
  { "id": 1, "method": "some-method", "params": "...", "jsonrpc": "2.0" },
  { "id": 2, "method": "another-method", "params": "...", "jsonrpc": "2.0" },
  { "id": 3, "method": "some-method", "params": "...", "jsonrpc": "2.0" }
]
```

A JSON-RPC adapter could regroup procedures by endpoint before assembling its response array; that adapter is planned.
The implemented server batching instead collects independent HTTP requests from every polling loop into each batch endpoint's queue and passes their retained handles as a counted array.
Each request keeps its own response and transaction boundary, as the [key-value and ledger examples](examples/README.md) demonstrate.

### Resumable Uploads & Downloads

__Roadmap:__ Resumable-transfer policies and streaming multipart access are not implemented.

There is no one unique way to deal with resumable or chunked uploads and downloads.
The most common approaches for uploads and downloads are sadly not symmetric.

|          | Upload                            | Download                                  |
| -------- | --------------------------------- | ----------------------------------------- |
| Standard | Tus.io                            | HTTP range requests (RFC 7233)            |
| State    | Stateful (server tracks progress) | Stateless (client decides ranges)         |
| Headers  | `Upload-Offset`, `Tus-Resumable`  | `Range`, `Accept-Ranges`, `Content-Range` |
| Methods  | `POST`, `PATCH`, `HEAD`           | `GET` with `Range` header                 |
| Usage    | Vimeo                             | Browsers and download clients             |

Streaming multipart is another upload design, but continuation after a failure requires an application-level protocol rather than multipart framing alone.

Replies can carry byte ranges of files, as descriptors or as paths beneath directories an interface registers, which is what a `Range` response needs.
The event loop reads them with `O_DIRECT`, past the page cache, into windows borrowed from its pool, reading the next window while the previous one sends.
Every reply leaves through zero-copy sends wherever the kernel offers them, and a window returns to the pool once the kernel let go of it.
Under Noise each read leaves a gap behind every record's payload for its tag and the next record's header, so records seal in place inside the window.

### Other Functional HTTP Headers

The C ABI exposes request headers and accepts application-supplied response headers.
The following are useful application-level conventions; they do not imply built-in rate limiting, caching, tracing, or security policies.

__Rate Limiting & Flow Control__ (Server → Client):

- `X-RateLimit-Limit`: Maximum requests allowed per time window
- `X-RateLimit-Remaining`: Remaining requests before hitting the limit
- `X-RateLimit-Reset`: Unix timestamp when the rate limit counter resets
- `Retry-After`: Seconds to wait before retrying (with 429/503 status codes)
- `X-Backoff-Ms`: Custom millisecond-precision backoff hint
- `X-Queue-Depth`: Current server queue depth for client-side load awareness

__Request Correlation & Tracing__ (Bidirectional):

- `X-Request-ID` / `X-Correlation-ID`: Unique identifier linking logs and metrics across services
- `X-Trace-ID` / `X-Span-ID`: Application-defined distributed tracing identifiers

__Caching & Validation__:

- `ETag` (Server → Client): Resource fingerprint for cache validation
- `If-None-Match` (Client → Server): Conditional request using ETag, returns 304 if unchanged
- `Last-Modified` (Server → Client): Resource modification timestamp
- `If-Modified-Since` (Client → Server): Conditional request using timestamp
- `Cache-Control`: Caching directives (`max-age`, `no-cache`, `no-store`, `private`, `public`)
- `Vary`: Indicates which request headers affect response caching

__Performance & Observability__ (Server → Client):

- `X-Response-Time`: Server-side processing time in milliseconds
- `Server`: Server software identification (e.g., `UCall/1.0`)

__Security__ (Server → Client):

- `X-Content-Type-Options: nosniff`: Prevents MIME-type sniffing attacks
- `X-Frame-Options`: Clickjacking protection (`DENY`, `SAMEORIGIN`)
- `Content-Security-Policy`: Controls resource loading to prevent XSS attacks

### WebSockets and Streaming

__Roadmap:__ The declared WebSocket operations currently return unsupported.
Streamed replies are implemented: `ucall_server_reply_begin()`, `ucall_server_reply_append()` and `ucall_server_reply_end()` send a chunked body from any thread, long after the callback returned.
Streamed request bodies are implemented too: an endpoint registered with `ucall_body_delivery_streamed_k` runs once the head parsed, and each `ucall_server_request_body_chunk()` takes every byte decoded since the last one, finishing later through its outcome when none arrived yet.
The Python and Rust bindings expose both through a detached request a worker finishes, described in their Files & Streams sections.
The connection reads on only as the handler pulls, so a slow handler slows its own peer and nobody else, and no request pipelined behind the body parses before the body ended.
Buffered requests are capped by `max_request_bytes`, which defaults to the largest receive buffer the kernel grants a socket; past it the reply is 413.

WebSockets have very different semantics from remaining request-response one-shot functionality.
Communication is bidirectional and long-lived, with messages flowing in both directions independently.
Often small, frequent messages, should be handled differently.

The planned WebSocket callbacks would deliver messages as they arrive.
An application would not be required to form one response for every message inside the callback.

### Observability & Metrics

Every event loop sends StatsD/DogStatsD datagrams to an explicitly configured endpoint, on a connected UDP socket of its own driven by the loop's I/O backend.
Metrics are __opt-in__: `metrics_address` names an endpoint such as `127.0.0.1:8125`, and an empty view sends nothing.
A server should never send packets to a port its operator didn't ask for.

Each `metrics_interval_microseconds`, one second by default, a loop reports the deltas of its counters since its last delivered datagram, its live connections per interface, and its refusals by status.
Loop zero also reports every batch endpoint's queue and counters.
Request latencies, sampled at `metrics_sample_rate`, ride the same datagrams, which never pass the path MTU:

```statsd
myapp.requests:1830|c|#env:prod,region:us-east,loop:0
myapp.connections:127|g|#env:prod,region:us-east,loop:0,interface:0
myapp.refused:4|c|#env:prod,region:us-east,loop:0,interface:0,status:413
myapp.latency:0.045|ms|@0.1|#env:prod,region:us-east,endpoint:/sum,method:POST,status:200
myapp.batch.queue:8|g|#env:prod,region:us-east,endpoint:/infer
```

```c
ucall_bytes_view_t const tags[] = {{(ucall_byte_t const*)"env:prod", 8}, {(ucall_byte_t const*)"region:us-east", 14}};
ucall_server_config_t config = {
    .metrics_address = {(ucall_byte_t const*)"127.0.0.1:8125", 14},
    .metrics_sample_rate = 0.1,                          // A latency line for one request in ten
    .metrics_prefix = {(ucall_byte_t const*)"myapp", 5}, // Metric names become "myapp.requests"
    .metrics_tags = tags,                                // Global tags for every line
    .metrics_tags_count = 2,
};
```

A datagram that fails to send is dropped, and the next one carries its counters, so collectors see every request counted once.

## Design Differences and Limitations

### Where Would You Prefer WebRTC?

WebRTC DataChannels offer message-oriented communication with configurable reliability.
That is a different tradeoff from UCall's TCP byte streams.

TCP's head-of-line blocking matters on lossy networks.
In TCP, if a packet is lost, all subsequent packets are held back until the lost packet is retransmitted and received.
On reliable networks, there should be no noticeable difference.
In the future, WebRTC DataChannels may be added.

### What About HTTP/2?

UCall currently supports HTTP/1.1; WebSocket upgrades are planned.
HTTP/2 adds several important features:

- Extended `CONNECT` for protocols that tunnel bidirectional traffic.
- Multiplexing multiple streams over a single TCP connection to improve resource utilization.
- Header compression using `HPACK` to reduce bandwidth usage for common and repetitive headers.

Those are all useful features.
Still, maintaining dynamic decompression tables for `HPACK` isn't trivial.
Moreover, the `CONNECT` has its own nested state machine inside each stream.
Many such streams can be active simultaneously within the same TCP connection.
All of that increases the attack surface and the potential for bugs and didn't align with UCall's design goals.

### Why not HTTP/3 and QUIC?

UCall currently only operates on top of TCP.
Building around UDP has been a long-standing ambition for Unum since inception in 2015, and a QUIC-like protocol with Noise encryption makes a lot of sense, but it's far less compatible with existing infrastructure.
So for now, UCall focuses on TCP-based communication and HTTP/1.1 interoperability.

### What Will You Miss From FastAPI?

FastAPI comes with a rich ecosystem of plugins and extensions for authentication, database integration, OpenAPI schema generation, and more.

UCall supports routes like `/users/{id}` natively, including named parameters and greedy suffixes.
The current gaps are higher-level SDK ergonomics, automatic schema generation, rich-type conversion, and the authentication integrations discussed above.

### What If You Love TLS?!

If you really need TLS, you can always deploy UCall behind a reverse proxy, like Nginx or Envoy.
They will handle all the TLS termination and forward decrypted HTTP traffic to UCall over a local network interface.
This is a common pattern in production deployments, as it allows to offload TLS processing from the application server.
The following deployment template assumes your application image binds plaintext HTTP on port 8080; replace the image and certificate paths for your deployment:

```yaml
services:
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - ucall

  ucall:
    image: your-ucall-application:latest
    expose:
      - "8080"
```

And the corresponding `nginx.conf`:

```nginx
upstream ucall_backend {
    server ucall:8080;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;

    location / {
        proxy_pass http://ucall_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name api.example.com;
    return 301 https://$server_name$request_uri;
}
```
