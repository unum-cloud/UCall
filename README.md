<h1 align="center">UCall</h1>
<h3 align="center">
Simple Secure Web Client and Server Framework<br/>
Up to 70x Higher Throughput and 50x Lower Latency than FastAPI and gRPC<br/>
</h3>
<br/>

<p align="center">
<a href="https://discord.gg/xuDmpbEDnQ"><img height="25" src="https://github.com/unum-cloud/.github/raw/main/assets/discord.svg" alt="Discord"></a>
&nbsp;&nbsp;&nbsp;
<a href="https://www.linkedin.com/company/unum-cloud/"><img height="25" src="https://github.com/unum-cloud/.github/raw/main/assets/linkedin.svg" alt="LinkedIn"></a>
&nbsp;&nbsp;&nbsp;
<a href="https://twitter.com/unum_cloud"><img height="25" src="https://github.com/unum-cloud/.github/raw/main/assets/twitter.svg" alt="Twitter"></a>
&nbsp;&nbsp;&nbsp;
<a href="https://unum.cloud/post"><img height="25" src="https://github.com/unum-cloud/.github/raw/main/assets/blog.svg" alt="Blog"></a>
&nbsp;&nbsp;&nbsp;
<a href="https://github.com/unum-cloud/ucall"><img height="25" src="https://github.com/unum-cloud/.github/raw/main/assets/github.svg" alt="GitHub"></a>
</p>

---

UCall is a very ¹ fast, ² portable, and ³ tiny HTTP/RPC framework supporting both REST, JSON-RPC, and WebSockets - with a ⁴ twist!
How ¹ fast?
10-70x faster than FastAPI and Google's gRPC.
How ² portable?
It powers applications in C 99, C++, Rust, Python, JavaScript, and Swift.
How ³ tiny?
10x shorter source code and smaller binary than FastAPI and gRPC.
What's the ⁴ twist?
For simplicity and robustness, it uses the Noise secure communication protocol instead of implementing the massive TLS standard.

Moreover, it's easy to use synchronously, even when the underlying backend uses asynchronous IO like Linux `io_uring`.
And provides transparent batching functionality for high-latency batch-processing endpoints, like on-GPU AI inference tasks and OLAP database queries.

## 📊 FastAPI UX Comparison

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
from ucall import Server

server = Server()

@server.get('/sum')
def sum(a: int, b: int):
    return a + b

server.run()    
```

</td>
</tr>
</table>

## 📈 Performance Metrics

It takes over a millisecond (1,203 μs) to handle a trivial FastAPI call on a recent 8-core CPU.
In that time, light could have traveled 300 km through optics to the neighboring city or country.
How does UCall compare to FastAPI and gRPC?

| Setup                   |   🔁   | Server | Protocol | Latency w 1 client | Throughput w 32 clients |
| :---------------------- | :---: | :----: | :------: | -----------------: | ----------------------: |
| Fast API over REST      |   ❌   |   🐍    |   REST   |           1'203 μs |               3'184 rps |
| Fast API over WebSocket |   ✅   |   🐍    |   REST   |              86 μs |            11'356 rps ¹ |
| gRPC ²                  |   ✅   |   🐍    |   gRPC   |             164 μs |               9'849 rps |
|                         |       |        |          |                    |                         |
| UCall with POSIX        |   ✅   |   C    |   HTTP   |              62 μs |              79'000 rps |
| UCall with io_uring     |   ✅   |   🐍    |   HTTP   |              40 μs |             210'000 rps |
| UCall with io_uring     |   ✅   |   C    |   HTTP   |              22 μs |             231'000 rps |

<details>
  <summary>Table legend</summary>

All benchmarks were conducted on AWS on general purpose instances with __Ubuntu 22.10 AMI__.
It is the first major AMI to come with __Linux Kernel 5.19__, featuring much wider `io_uring` support for networking operations.
These specific numbers were obtained on `c7g.metal` beefy instances with Graviton 3 chips.

- The 🔁 column marks, if the TCP/IP connection is being reused during subsequent requests.
- The "server" column defines the programming language in which the server was implemented.
- The "latency" column reports the amount of time between sending a request and receiving a response. μ (Greek letter mu) represents the prefix 'micro', so μs means microseconds.
- The "throughput" column reports the number of Requests Per Second when querying the same server application from multiple client processes running on the same machine.

> ¹ FastAPI couldn't process concurrent requests with WebSockets.

> ² We tried generating C++ backends with gRPC, but its numbers, suspiciously, weren't better.
> There is also an async gRPC option, that wasn't tried.

</details>

## Design Principles

### Asynchronous Framework for Synchronous Applications

It's clear that talking to remote services over a network is slower than any other operation in a computer.
Moreover, the packet exchange between the application and the network card involves multiple context switches and kernel calls.
To mitigate these latencies, UCall uses several asynchronous IO mechanisms under the hood, like `io_uring`.
Now the question is, how to expose this asynchrony to the user code?

The UCall way is to keep the application code synchronous.
No `async`/`await` keywords or `future`/`promise` handles.
For lightweight operations it's optimal - no additional bookkeeping overhead.
For heavy operations, there is no secret pill, but there is a common "latency hiding" trick - batching.

You can declare an endpoint as batchable, and UCall will accumulate requests for a short time window and deliver them to your function as a batch.
This is especially useful for GPU-backed AI inference endpoints, where the batch processing is much more efficient than single-item processing.
Another common use case is OLAP-style database queries or search queries, where multiple queries can be grouped and executed together.

> If you are triggering many async operations inside your batchable endpoint, UCall provides additional performance optimizing APIs to allow recursively calling `ucall_take_calls()` inside your endpoint handler to process pending requests while waiting for IO or other async operations to complete.

### Encryption: From TLS to Noise

There is a good reason to implement TLS in a networking library - it's the most widespread encryption standard on the Internet.
There is also every reason not to - TLS is a massive and complex standard, with multiple versions, dozens of cipher suites, countless configuration options, error-prone details, and poor ergonomics.
Integrating TLS properly even using OpenSSL, BoringSSL, LibreSSL, and mbedTLS in a clean & performant way in line with principles of Unum - failed twice over two years.

Moreover, the certificate management, PKI, and trust chains are an absolute ergonomic nightmare.
There is a better way... that is broadly deployed, but little known.
The Noise Protocol Framework!

It's used by WhatsApp, WireGuard VPN, and the Lightning Network for faster off-chain transactions on top of Bitcoin.
UCall uses a `protocol+transport` URL scheme convention (like Docker's `http+unix://`) to explicitly specify the transport: `http://`, `ws://`, `http+noise://`, and `ws+noise://`.
It also uses a Diffie-Hellman __(DH)__ key exchange to establish a shared secret between the client and server, but it's much simpler, easier to implement, audit, and reason about than TLS.
Several handshake patterns are defined, each suitable for different use cases:

- __XX__: Full mutual authentication where both parties authenticate each other during the handshake. Best for peer-to-peer scenarios or when the server doesn't have a fixed identity known in advance.
- __IK__: Client knows the server's public key in advance (Identity Known). Provides faster handshakes and is ideal for typical client-server architectures, similar to TLS with certificate pinning.
- __KK__: Both parties know each other's public keys beforehand (Known Known). Enables zero round-trip encryption for pre-configured systems with maximum performance.

Noise can be implemented in several ways, depending on the choice of three cryptographic primitives: Diffie-Hellman key exchange, symmetric cipher, and hash function.
The suite defines four standard combinations optimized for different use cases:

| Name                       | Key exchange |            Cipher |    Hash |
| :------------------------- | -----------: | ----------------: | ------: |
| `25519_ChaChaPoly_SHA256`  |   Curve25519 | ChaCha20-Poly1305 | SHA-256 |
| `25519_ChaChaPoly_BLAKE2s` |   Curve25519 | ChaCha20-Poly1305 | BLAKE2s |
| `25519_AESGCM_SHA256`      |   Curve25519 |       AES-256-GCM | SHA-256 |
| `448_ChaChaPoly_SHA512`    |     Curve448 | ChaCha20-Poly1305 | SHA-512 |

UCall implements the very first `25519_ChaChaPoly_SHA256`.
First, it uses the [Curve25519](https://en.wikipedia.org/wiki/Curve25519) elliptic curve for the DH asymmetric key exchange to produce a shared secret.
Then, it uses the [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) authenticated symmetric cipher for encrypting and decrypting the data.
Finally, it uses the [SHA-256](https://en.wikipedia.org/wiki/SHA-2) hash function for hashing operations during the handshake and key derivation.

### Engineered for Performance

UCall is pedantically designed from the ground up for high performance and so is its every dependency.
On the IO side, even on Linux, even just for `io_uring`, UCall ships different logic for different Linux kernel versions, as different features were added over time:

- `io_uring_prep_read_fixed` since kernel v5.1
- `io_uring_prep_accept_direct` since kernel v5.19
- `io_uring_register_files_sparse` since kernel v5.19
- `IORING_SETUP_COOP_TASKRUN` optional since kernel v5.19
- `IORING_SETUP_SINGLE_ISSUER` optional since kernel v6.0

Equally important, all of the packet encryption, decryption, serialization, and deserialization steps are powered by high-performance SIMD-accelerated libraries.
All of them come with "dynamic dispatch" logic to pick the best available CPU instructions at runtime, so that UCall can run blazingly fast on both old and new hardware.
Namely, UCall uses:

- [`libsodium`][libsodium] for cryptographic operations.
- [`stringzilla`][stringzilla] for string manipulations.
- [`simdjson`][simdjson] to parse JSON text faster than gRPC can load a binary `ProtoBuf`.
- [`simdutf`][simdutf] for fast UTF-8 validation and conversion.
- [`turbo-base64`][turbobase64] to decode binary values from Base64 form.
- [`ada`][ada] to parse URI endpoints.

[libsodium]: https://github.com/jedisct1/libsodium
[stringzilla]: https://github.com/ashvardanian/StringZilla
[simdjson]: https://github.com/simdjson/simdjson
[simdutf]: https://github.com/simdutf/simdutf
[turbobase64]: https://github.com/powturbo/Turbo-Base64
[ada]: https://github.com/ada-url/ada

### Protocol Flexibility: REST and JSON-RPC

UCall supports flexible parameter extraction for both REST-style APIs and JSON-RPC requests.
You can configure how  and where each parameter is extracted from:

- __Path Parameters__: Extract from URL pattern, e.g., `/users/{user_id}/posts/{post_id}`
- __Query Parameters__: Extract from query string, e.g., `/search?q=rust&limit=10`
- __JSON Body__: Extract from request body, e.g., `{"temperature": 0.7, "max_tokens": 100}`
- __Multipart Body__: Files + metadata in one request
  
This flexibility allows you to build both traditional REST APIs (using query params) and modern JSON-based APIs with the same codebase.
Why support JSON-RPC?

- Broadly supported, especially in decentralized software.
- Human, machine, and LLM-friendly format with no vendor lock-in.
- Enables batch requests, allowing multiple calls in a single HTTP request.

### Multipart Data and Rich Types

UCall supports `multipart/form-data` requests, allowing you to send files and metadata in a single HTTP request.
The `boundary=----WebKitFormBoundary` is injected by the client and respected by the server, making it compatible with most HTML `<form>` submissions and `fetch` API calls.
Each part gets its own `Content-Disposition` and `Content-Type` and can include rich data types, like images, audio, and binary blobs.
In Python, that allows us to transparently decode `numpy.ndarray` and `PIL.Image` inputs and outputs.
Here's what it would look like for building a multi-modal semantic search platform built on top of Unum's [UForm](https://github.com/unum-cloud/UForm) models and [USearch](https://github.com/unum-cloud/USearch) engine.

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

Now that server can be called with both standard tools like `curl` and with the UCall Python client:

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

It's important to remember that the batch sent from a user won't necessarily be processed at once.
All of the replies will be returned at once on completion, but under the hood, they may be regrouped, potentially invoking `"id": 1` and `"id": 3` together on a batch-capable callback, and the remaining task separately.

### Resumable Uploads & Downloads

There is no one unique way to deal with resumable or chunked uploads and downloads.
The most common approaches for uploads and downloads are sadly not symmetric.

|          | Upload                            | Download                                  |
| -------- | --------------------------------- | ----------------------------------------- |
| Standard | Tus.io                            | HTTP/1.1 RFC 7233 (1999)                  |
| State    | Stateful (server tracks progress) | Stateless (client decides ranges)         |
| Headers  | `Upload-Offset`, `Tus-Resumable`  | `Range`, `Accept-Ranges`, `Content-Range` |
| Methods  | `POST`, `PATCH`, `HEAD`           | `GET` with `Range` header                 |
| Usage    | Vimeo                             | Universal (all browsers since 1999)       |

The more popular alternative to Tus.io for resumable uploads is Streaming Multipart uploads.
Those are also natively supported by UCall, but not recommended for large files or unreliable connections, as they require re-sending all data after a failure - no continuation is possible.

When using `io_uring` as the backend, it's recommended to use large chunk sizes in multiples of default SSD page sizes.
In that case we can further reduce the number of transparent file copies in the OS and system calls by performing `O_DIRECT` zero-copy IO.

### Other Functional HTTP Headers

UCall supports standard HTTP headers for production deployments.

__Rate Limiting & Flow Control__ (Server → Client):

- `X-RateLimit-Limit`: Maximum requests allowed per time window
- `X-RateLimit-Remaining`: Remaining requests before hitting the limit
- `X-RateLimit-Reset`: Unix timestamp when the rate limit counter resets
- `Retry-After`: Seconds to wait before retrying (with 429/503 status codes)
- `X-Backoff-Ms`: Custom millisecond-precision backoff hint
- `X-Queue-Depth`: Current server queue depth for client-side load awareness

__Request Correlation & Tracing__ (Bidirectional):

- `X-Request-ID` / `X-Correlation-ID`: Unique identifier linking logs and metrics across services
- `X-Trace-ID` / `X-Span-ID`: OpenTelemetry-compatible distributed tracing identifiers

__Caching & Validation__:

- `ETag` (Server → Client): Resource fingerprint for cache validation
- `If-None-Match` (Client → Server): Conditional request using ETag, returns 304 if unchanged
- `Last-Modified` (Server → Client): Resource modification timestamp
- `If-Modified-Since` (Client → Server): Conditional request using timestamp
- `Cache-Control`: Caching directives (`max-age`, `no-cache`, `no-store`, `private`, `public`)
- `Vary`: Indicates which request headers affect response caching

__Performance & Observability__ (Server → Client):

- `X-Response-Time`: Server-side processing time in milliseconds
- `Server`: Server software identification (e.g., `UCall/2.0`)

__Security__ (Server → Client):

- `X-Content-Type-Options: nosniff`: Prevents MIME-type sniffing attacks
- `X-Frame-Options`: Clickjacking protection (`DENY`, `SAMEORIGIN`)
- `Content-Security-Policy`: Controls resource loading to prevent XSS attacks

### WebSockets and Streaming

WebSockets have very different semantics from remaining request-response one-shot functionality.
Communication is bidirectional and long-lived, with messages flowing in both directions independently.
Often small, frequent messages, should be handled differently.

We also provide callback handlers for WebSocket connections that let you handle messages as they arrive.
But you are not required or expected to form a response for each message inside the callback.


### Observability & Metrics

UCall provides minimal overhead observability out of the box, using the same kernel-bypass techniques to output metrics.
It sends metrics in StatsD/DogStatsD format over UDP to `localhost:8125` by default - enabled automatically with zero configuration.
This is the most lightweight approach for high-throughput servers: fire-and-forget UDP packets add ~100ns overhead per request.

Metrics are automatically tagged with endpoint, method, and status code for easy debugging:

```statsd
ucall.requests:1|c|#endpoint:/sum,method:POST,status:200
ucall.latency:45|ms|#endpoint:/sum,method:POST,status:200
ucall.connections.active:127|g
ucall.queue.depth:8|g|#endpoint:/inference
ucall.errors:1|c|#endpoint:/sum,error:timeout
```

For high-throughput scenarios (>500K rps), sampling can be configured to reduce UDP traffic:

```c
ucall_config_t config = {
    .metrics_sample_rate = 0.1,  // Sample 10% of requests, StatsD will multiply counts
    .metrics_prefix = "myapp",   // Metric names become "myapp.requests", etc.
    .metrics_tags = "env:prod,region:us-east"  // Global tags for all metrics
};
```
The StatsD format works universally with all major observability platforms via collectors: Datadog Agent, OTel Collector, Telegraf, and Prometheus StatsD Exporter.

## Design Differences and Limitations

### Where Would You Prefer WebRTC?

WebRTC is a separate protocol providing selective reliability in latency-critical applications.
Unlike most of UCall functionality, it builds on top of UDP, not TCP.
On top of that, it uses Sequence Numbers (TSN), Selective Acknowledgments (SACK), Retransmission Timers, and Congestion Control algorithms to emulate TCP-like behavior when needed.

This solves a few problems, most importantly - head of line blocking in lossy networks.
In TCP, if a packet is lost, all subsequent packets are held back until the lost packet is retransmitted and received.
On reliable networks, there should be no noticeable difference.
In the future, WebRTC DataChannels may be added.

### What About HTTP/2?

UCall currently only supports HTTP/1.1 with an upgrade path to WebSockets.
HTTP/2 adds several important features:

- `CONNECT` verb for tunneling in both directions to eliminate the need for traditional WebSockets.
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
So for now, UCall focuses on high-performance TCP-based communication and interoperability with existing HTTP/1.1 and WebSocket ecosystems.

### What Will You Miss From FastAPI?

FastAPI comes with a rich ecosystem of plugins and extensions for authentication, database integration, OpenAPI schema generation, and more.

First of all, UCall doesn't support endpoints like `/users/{id}` natively.

### What If You Love TLS?!

If you really need TLS, you can always deploy UCall behind a reverse proxy, like Nginx or Envoy.
They will handle all the TLS termination and forward decrypted HTTP traffic to UCall over a local network interface.
This is a common pattern in production deployments, as it allows to offload TLS processing from the application server.
Here's what your Docker Compose configuration may look like:

```yaml
version: '3.8'
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
    build: .
    ports:
      - "8080:8080"
    environment:
      - UCALL_HOSTNAME=0.0.0.0
      - UCALL_PORT=8080
      - UCALL_MAX_THREADS=4
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