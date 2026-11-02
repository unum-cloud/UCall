# UCall for Rust

## Installation

```sh
cargo add ucall
```

The crate links the UCall library, which its build script compiles through CMake, so building needs CMake and a C++20 compiler.
The library picks its I/O backend and CPU kernels when a server or client starts, so one build adapts to the kernel and CPU it runs on.

## Quickstart

A server answers on one or more interfaces, and a client calls it; neither starts a thread.

```rust
use ucall::*;

let mut server = Server::new(&[Interface::new("127.0.0.1:0")])?;
server.get("/hello/{name}", |request: Request| {
    let name = request.path_parameter("name").unwrap_or_default();
    let greeting = [b"Hello, ", name].concat();
    let _ = request.reply(HTTPStatus::OK, &["content-type: text/plain".into()], &greeting);
})?;
let address = server.address(0).unwrap().to_owned();

let mut client = Client::new(ClientOptions { connections: 1, ..Default::default() })?;
std::thread::scope(|scope| {
    scope.spawn(|| server.take_calls(0));
    let response = client.get(format!("http://{address}/hello/world"));
    server.stop();
    assert_eq!(response?.body(), b"Hello, world");
    Ok::<(), Error>(())
})?;
```

The polling thread runs the handler, the client blocks in `get` until its response arrives, and `stop` releases the polling thread so the scope can end.

## Serving

`Server::new` takes the interfaces to answer on, and `Server::with_options` also takes `ServerOptions`: the `Backend`, an optional `CPUClass` ceiling, a `Log` sink and a StatsD endpoint in `Metrics`.
It fails rather than substituting when the backend is unavailable or the CPU does not run the class.
An `Interface` is an address, optionally pinned to a Linux device, with its own security and admission limits, so one server answers plaintext on loopback and Noise on the wire at once.
It admits 1024 connections by default, reads one request per connection at a time unless `pipelined_requests` allows more, and replies still leave in request order.
`max_request_bytes` caps a request's head and buffered body, answering 413 past it, and `reply_directories` names the directories path replies resolve beneath.
Port zero binds a free port, which `Server::address` reports.

```rust
use std::sync::Arc;
use ucall::*;

let public = Interface::new("0.0.0.0:8545").event_loops(4).connections(16_384).pipelined_requests(16);
let health = Interface::new("127.0.0.1:8546").connections(4);
let log = Log { callback: Arc::new(|level: LogLevel, line: &[u8]| eprintln!("{level:?} {}", String::from_utf8_lossy(line))), format: LogFormat::Human, level: LogLevel::Warning };
let metrics = Metrics { address: "127.0.0.1:8125".into(), prefix: "rpc".into(), ..Default::default() };
let options = ServerOptions { cpu_class: Some(CPUClass::Serial), log: Some(log), metrics: Some(metrics), ..Default::default() };
let mut server = Server::with_options(&[public, health], options)?;
println!("{} event loops on {} with {} kernels", server.event_loops(), server.backend(), server.cpu_class());

server.get("/users/{user}/files/{*path}", |request: Request| {
    let user = request.path_parameter("user").unwrap_or_default();
    let path = request.path_parameter("path").unwrap_or_default();
    let listing = [user, b":".as_slice(), path].concat();
    let _ = request.reply(HTTPStatus::OK, &[], &listing);
})?;
server.route("/anything", Verb::Any, |request: Request| {
    let message = format!("{:?} is not served", request.verb());
    let _ = request.reply_error(HTTPStatus::NOT_IMPLEMENTED, &message);
})?;
```

Endpoints register through `&mut Server` before any loop is polled, with `route` taking any `Verb` and `get`, `post`, `put`, `delete` and `patch` naming one.
Templates capture `{name}` segments and a greedy `{*name}` tail, literal segments match before captures, and registering one template and verb twice fails with `Status::AlreadyExists`.
A path no endpoint matches answers 404, and a request that cannot be parsed answers 400, 413 or 501 before reaching any handler.

Log lines reach the callback on whichever thread produced them, and StatsD datagrams carry each loop's counters and sampled request latencies, every second unless `Metrics::interval` says otherwise.
`Server::event_loop_statistics` copies one loop's counters, from any thread while the loop runs: polls, system calls, submissions and completions, accepted connections, requests, and the bytes received, sent and copied.
Divided by `requests`, they price one call.

## Requests

A handler receives each `Request` by value.
Its reads borrow the received bytes: `verb`, `path`, `path_parameter`, `query`, `header` and `body`, with `peer` naming the interface it arrived on and the client's authenticated Noise key.
The path and query values stay percent-encoded as sent, header names match case-insensitively, and the body arrives whole, decoded from chunked framing if it was sent that way.
`path_segments_count` and `path_segment` read the path component by component, and `parts_count` and `part` read a `multipart/form-data` body as `RequestPart`s, each borrowing its name, content type and payload.

```rust
use ucall::*;

let mut server = Server::new(&[Interface::new("127.0.0.1:0")])?;
server.post("/orders/{order}", |request: Request| {
    let Some(token) = request.header("authorization") else {
        let _ = request.reply_error(HTTPStatus::UNAUTHORIZED, "sign in first");
        return;
    };
    let receipt = [request.path_parameter("order").unwrap_or_default(), b" by ", token].concat();
    let headers = ["content-type: text/plain".into(), "cache-control: no-store".into()];
    let _ = request.reply(HTTPStatus::CREATED, &headers, &receipt);
})?;
```

`reply` and `reply_error` consume the request, so a request is answered at most once, and Content-Length, Date and Server are generated.
A reply copies what it sends, and since it consumes the request, a body made of the request's bytes is assembled first, as `receipt` is above.
A request owns its received bytes and is `Send`, so a handler may hand it to a worker thread and return, and the worker replies whenever it is done.
A request dropped without a reply answers 500, as does one held by a handler that panics.
A reply to a closed connection still consumes the request and reports `Status::ConnectionClosed`; any other failed reply keeps it, and dropping it then answers 500.

## Files & Streams

Handlers run on the polling thread, so a reply or a pull that finishes later runs on a worker: `Request::detach` hands the request over as a `DetachedRequest`, which reads and replies like a `Request` and alone has the three verbs below.

| Verb                                   | Returns                                            | Final when                              |
| :------------------------------------- | :------------------------------------------------- | :-------------------------------------- |
| `reply_parts(status, headers, parts)`  | `None` for bytes alone, else a `Deferred`          | every part is sent                      |
| `reply_stream(status, headers)`        | a `ReplyStream` with `append(parts)` and `end()`   | `end()` returns `None` or a `Deferred`  |
| `body_chunk()`                         | the bytes decoded since the last pull              | an empty chunk once the body ended      |

### Serving a File

```rust
use std::sync::mpsc;
use ucall::*;

let (handed, received) = mpsc::channel::<DetachedRequest>();
let interface = Interface::new("0.0.0.0:8080").reply_directories(["/srv/videos"]);
let mut server = Server::new(&[interface])?;
server.get("/videos/{name}", move |request: Request| handed.send(request.detach()).unwrap())?;

std::thread::scope(|scope| {
    scope.spawn(|| server.take_calls(0));
    for detached in received {
        let name = detached.path_parameter("name").unwrap_or_default().to_vec();
        let path = PathRange { directory: 0, path: name.as_slice().into(), offset: 0, length: 0 };
        let parts = [ReplyPart::Path(path)];
        let replied = detached.reply_parts(HTTPStatus::OK, &[], &parts);
        if let Ok(Some(deferred)) = replied {
            let _ = deferred.wait(); // or: deferred.await
        }
    }
});
```

`reply_parts` concatenates `ReplyPart::Bytes`, `ReplyPart::Path` and `ReplyPart::File` parts into one body whose Content-Length is measured from the files.
A `Path` resolves beneath the interface's `reply_directories`, refusing absolute paths, `..` and links leading out, and the event loop opens, reads and closes it unbuffered.
A `File` borrows the caller's descriptor, opened with `O_DIRECT`, for the `Deferred`'s lifetime, while bytes and paths are copied before the call returns, so they may be dropped right after it.
A file that is missing, unreadable or too short replaces the reply with 404, 416 or 500 before its head leaves, and the `Deferred` reports the cause.
`Deferred::status` polls without blocking, `Deferred::wait` blocks until the reply is final, `.await` polls the status between other tasks, since the library has no wake-up, and dropping a `Deferred` waits for it, which is why only a detached request makes one.

### Streaming a Reply

```rust
fn send_rows(detached: DetachedRequest, rows: &[String]) -> Result<()> {
    let mut stream = detached.reply_stream(HTTPStatus::OK, &["content-type: text/csv".into()])?;
    for row in rows {
        stream.append(&[ReplyPart::Bytes(row.as_bytes().into())])?;
    }
    stream.end().map(|_| ())
}
```

The stream is chunked unless a Content-Length header declares the length; `append` refuses with `Status::WouldBlock`, queueing nothing, while the peer lags behind what is queued; `end` answers `None` or a `Deferred` like `reply_parts`, and dropping an unended stream ends it.

### Streaming an Upload

```rust
fn store(mut detached: DetachedRequest) -> Result<()> {
    let mut received_bytes = 0usize;
    loop {
        let chunk = detached.body_chunk()?;
        if chunk.is_empty() {
            break;
        }
        received_bytes += chunk.len();
    }
    let total = received_bytes.to_string();
    detached.reply_parts(HTTPStatus::OK, &[], &[ReplyPart::Bytes(total.as_bytes().into())]).map(|_| ())
}
```

An endpoint registered through `Server::route_with` with `BodyDelivery::Streamed` runs its handler once the headers arrive; the handler hands `request.detach()` to a worker as above, and `body_chunk` blocks for the bytes decoded since the last pull, empty once the body ended.
On the polling thread, where nothing arrives while the handler runs, a pull with nothing decoded refuses with `Status::WouldBlock` instead of waiting.

## Batches

A batch endpoint gathers matching requests from every event loop into one queue and hands them to its handler in batches, which suits work that is cheaper per request in bulk, like GPU inference.

```rust
use std::time::Duration;
use ucall::*;

let mut server = Server::new(&[Interface::new("127.0.0.1:0").pipelined_requests(8)])?;
let batching = Batching { min_size: 16, max_size: 64, max_latency: Duration::from_millis(2) };
let infer = server.batch("/infer", Verb::Post, batching, |batch: Batch| {
    let inputs: Vec<&[u8]> = batch.iter().map(Request::body).collect();
    let scores: Vec<String> = inputs.iter().map(|input| input.len().to_string()).collect();
    for (request, score) in batch.into_iter().zip(scores) {
        let _ = request.reply(HTTPStatus::OK, &[], score.as_bytes());
    }
})?;

std::thread::scope(|scope| {
    scope.spawn(|| server.take_calls(0));
    scope.spawn(|| infer.take_batches());
    scope.spawn(|| {
        std::thread::sleep(Duration::from_millis(100));
        println!("{:?}", infer.statistics());
        server.stop();
    });
});
```

`Batching` dispatches as soon as `min_size` requests wait, never more than `max_size` at once, and a smaller batch once its oldest request waited `max_latency`; zero fields mean 1, 32 and 10 milliseconds.
The handler runs on the thread draining the endpoint through `take_batch` or `take_batches`, never on an event loop, so a slow batch never stalls the network.
A `Batch` lends its requests in arrival order: `get` and `iter` borrow them, `take` moves one out, and iterating it by value takes them all, forwards or reversed.
Requests the handler neither replies to nor keeps answer 500 once it returns, and all of them do when it panics.
Taken requests may be replied to later, from any thread, while their responses still leave each connection in request order.

The queue holds as many requests as the interfaces admit at once, connections times pipelined requests, and refuses more with 503.
`Server::stop` releases the requests still queued without a reply, and a dropped `BatchEndpoint` leaves its queue unanswered until the server is freed.
`BatchEndpoint::statistics` counts batches and requests, and whether each batch was dispatched on reaching `max_size`, on reaching `min_size`, or once `max_latency` passed, from any thread while the endpoint drains.

## Calling

A `Client` submits calls without driving the network, and polls to drive them and collect what finished.
It holds up to `connections` connections, reusing them across calls, and carries up to `pipelined_calls` calls on each.

```rust
use std::time::Duration;
use ucall::*;

let mut client = Client::new(ClientOptions { connections: 4, pipelined_calls: 16, ..Default::default() })?;
for index in 0..64u64 {
    client.submit(CallRequest::post("http://127.0.0.1:8545/infer", vec![index as u8]), index)?;
}
let mut completed: [Completed; 16] = Default::default();
let mut remaining = 64;
while remaining != 0 {
    for done in client.take_completed(&mut completed, Duration::from_secs(1))? {
        match &done.response {
            Ok(response) => println!("call {} answered {}", done.context, response.status_code().0),
            Err(error) => println!("call {} failed: {error}", done.context),
        }
        remaining -= 1;
    }
}

let response = client.get("http://127.0.0.1:8545/health")?;
let keep = response.header("cache-control").map(<[u8]>::to_vec);
drop(client);
println!("{:?} {:?}", response.body(), keep);
```

`submit` takes a `CallRequest`, which owns its URL, header lines, body and security until the call completes, and tags it with a `u64` context.
A call admitted once completes exactly once, and a client already holding `calls` unretrieved calls refuses more with `Status::Contended`.
`take_completed` drives every admitted call and fills a caller-provided buffer with finished ones, waiting up to its timeout for the first, and a zero timeout performs one nonblocking round.
`get`, `post` and `call` submit one call and poll until it finishes, keeping the completions of other calls they retrieve meanwhile for the next `take_completed`, which hands those out first.
`CallRequest::options` carries the call's own `RequestOptions`: a timeout in place of the client's, retries, redirect hops, security, and the client and server keys.

Every received response is a `Response`, whatever its HTTP status, and only a failed exchange is an `Error`.
A `Response` owns its received bytes and is `Send`, so it stays readable after its `Client` is dropped and may move to another thread.
Dropping the client cancels the calls still in flight and discards completions not yet retrieved.

## Noise Keys

Interfaces and calls can run over the Noise protocol instead of plain TCP, authenticating both sides by 32-byte Curve25519 static keys.

```rust
use std::sync::Arc;
use ucall::*;

let (server_private_key, server_public_key) = generate_noise_keypair()?;
let (client_private_key, _) = generate_noise_keypair()?;
let client_public_key = derive_noise_public_key(&client_private_key);

let sealed = Interface::new("0.0.0.0:8546")
    .security(Security::NoiseXX, server_private_key)
    .peer_authorizer(move |key: &NoiseKey| *key == client_public_key);
let server = Server::new(&[sealed])?;

let client = Client::new(ClientOptions {
    connections: 1,
    private_key: Some(client_private_key),
    peer_authorizer: Some(Arc::new(move |key: &NoiseKey| *key == server_public_key)),
    ..Default::default()
})?;
```

`generate_noise_keypair` draws from the operating system's entropy and fails with `Status::IO` when it is refused.
`derive_noise_public_key` recovers the public half of a stored private key, which peers compare in their authorizers.
Under Noise XX both sides learn each other's key during the handshake, so both need an authorizer; Noise IK has the client name the server's key in advance through `RequestOptions::server_key`.
Noise KK has both sides know each other in advance: the interface admits the one key `Interface::noise_peer_key` names, and the call presents `RequestOptions::client_key` or the client's own key.
An `http+noise://` URL implies Noise XX, and a handler reads the client's authenticated key through `Request::peer`.

## Errors

Every fallible call answers `ucall::Result`, whose `Error` carries the `Status` the library reported and a static message beside it, so nothing allocates on the failure path.
A mistake the binding catches before calling the library, like polling an event loop the server lacks, reports the status the library would have used.
`Status` prints its stable spelling, such as "connection-failed", and a status a newer library added reads as `Status::Internal`.

```rust
use ucall::*;

let mut client = Client::new(ClientOptions { connections: 1, ..Default::default() })?;
match client.get("http://127.0.0.1:1/") {
    Ok(response) => println!("answered {}", response.status_code().0),
    Err(error) if error.status == Status::ConnectionFailed => println!("nobody listens: {error}"),
    Err(error) => return Err(error.into()),
}
```

A submitted call that fails completes with `Err` in `Completed::response`: `Status::ConnectionFailed`, `Status::ConnectionClosed`, `Status::Timeout`, `Status::HandshakeFailed` or `Status::PeerRejected`.
A request lookup that finds nothing answers `None`, and HTTP error statuses are ordinary responses.
`Backend` and `CPUClass` print and parse their stable names, like "linux-uring618" and "intel-icelake", failing with `Status::InvalidArgument` on a name no value has, and `ucall::version()` names the linked library.

## Threads & Polling

The crate starts no threads and needs no async runtime: every callback runs on a thread the application lent to a polling call.

- A route handler runs on the thread inside `take_call` or `take_calls` for the event loop that received the request.
- A batch handler runs on the thread inside `take_batch` or `take_batches` for its endpoint, never on an event loop.
- A server's peer authorizer runs on the polling thread completing the handshake, and a client's on the client's own thread inside `take_completed`, `call`, `get` or `post`.

Each event loop and each batch endpoint has one polling owner at a time, and a second thread polling it concurrently gets `Status::Contended`.
`take_calls` and `take_batches` run until `Server::stop`, while `take_call` and `take_batch` return after one round, waiting up to their timeout, so a loop of them interleaves polling with other work on the same thread.
`Server::stop` works from any thread, handlers included, wakes every polling and draining thread, and dropping the `Server` stops it too.
An interface accepts on its own number of event loops, one by default, and the server runs the largest of those counts.

Registration takes `&mut Server`, and polling, stopping and statistics take `&Server`, so the borrow checker orders setup before serving.
A `Request` and a `Response` move between threads, while a `Client` stays on the thread that created it.
Every thread that polls, replies or reads must run on a CPU supporting the CPU class the server or client resolved at start, so `CPUClass::Serial` is the safe choice on machines mixing CPU generations.

## What This Crate Does Not Expose

The crate leaves out WebSocket endpoints, connections and messages, on either side.

## Design

The crate is a thin layer over UCall's native library, and every rule below follows from that.

- __Verbs share one name across languages.__
  `take_call`, `take_calls`, `take_batch`, `take_batches`, `submit` and `take_completed` name the same calls in Python and Rust.
- __Blocking stays simple, deferring stays symmetric.__
  A reply that is final on return looks as it did before files and streams existed, a deferred one is a `Deferred` that `wait`s, `.await`s or waits as it drops, and nothing costs more until a `DetachedRequest` is used.
- __Ownership is a type, not a flag.__
  A reply consumes its `Request`, a dropped request answers 500, only a `DetachedRequest` hands back a `Deferred`, a `Response` frees itself, and a `Client` is neither `Send` nor `Sync`, so misuse does not compile.
- __Single owners are claimed, never assumed.__
  Event loops and batch endpoints take `&self`, and an atomic claim answers `Status::Contended` to a second poller instead of racing it.
- __Handlers are plain closures.__
  A panic inside a handler or an authorizer is caught at the boundary, answering 500 or rejecting the peer, and never unwinds through C.
- __Polling allocates nothing.__
  A client sizes its tables by its call budget once, and a batch endpoint reuses the slots it lends requests in.
- __No life of its own.__
  The crate starts no threads, keeps no global state and needs no async runtime, so it drops into any threading model.
