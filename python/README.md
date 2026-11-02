# UCall for Python

## Installation

```sh
pip install ucall
```

Wheels cover CPython 3.12 to 3.15 on Linux, macOS and Windows, and a source build needs CMake and a C++20 compiler.
The package picks its I/O backend and CPU kernels when a server or client starts, so one wheel adapts to the kernel and CPU it runs on.

## Quickstart

A server answers on one or more interfaces, and a client calls it; neither starts a thread.

```python
import threading

import ucall

server = ucall.Server(ucall.Interface("127.0.0.1:0"))


@server.get("/hello/{name}")
def hello(name: str, excited: bool = False):
    return f"Hello, {name}{'!' if excited else ''}"


runner = threading.Thread(target=server.run)
runner.start()
client = ucall.Client(connections=1)
response = client.get(f"http://{server.addresses[0]}/hello/world?excited=yes")
server.stop()
runner.join()
assert bytes(response.body) == b"Hello, world!"
```

`run` serves the one event loop on the thread the application lent it, the client blocks in `get` until its response arrives, and `stop` releases the serving thread.

## Serving

`ucall.Server` takes the interfaces to answer on, and `backend` and `cpu_class` keywords naming a `ucall.Backend` and a `ucall.CPUClass`, by member or by name such as "linux-epollaio".
Its `log=` callable receives each line the server writes as a `ucall.LogLevel` and a `str`, on whichever thread wrote it and holding the interpreter lock, and `metrics=ucall.Metrics(address, sample_rate, prefix, tags, interval_us)` sends StatsD datagrams from every event loop.
An `Interface` also takes `max_request_bytes=`, past which a request is answered 413, and `reply_directories=`, the directories a `ucall.Path` part names by position.
Without interfaces it answers on `ucall.DEFAULT_ADDRESS`, "127.0.0.1:8545".
An `Interface` is an address, optionally pinned to a Linux device, with its own security and admission limits, so one server answers plaintext on loopback and Noise on the wire at once.
It admits 1024 connections by default, reads one request per connection at a time unless `pipelined_requests` allows more, and replies still leave in request order.
Port zero binds a free port, which `server.addresses` reports.

```python
import ucall

public = ucall.Interface("0.0.0.0:0", event_loops=4, connections=16_384, pipelined_requests=16)
health = ucall.Interface("127.0.0.1:0", connections=4)
server = ucall.Server(public, health, backend="automatic", cpu_class=ucall.CPUClass.SERIAL)
print(f"{server.event_loops} event loops on {server.backend.name} with {server.cpu_class.name} kernels")


@server.get("/users/{user}/files/{*path}")
def listing(user: str, path: str, limit: int = 10, hidden: bool = False):
    return {"user": user, "path": path, "limit": limit, "hidden": hidden}


@server.post("/scale")
def scale(value: float, factor: float = 2.0):
    return value * factor


@server.route("/anything", ucall.Verb.ANY)
def anything(request: ucall.Request):
    request.reply_error(501, f"{request.verb.name} is not served\n")
```

Endpoints register before any loop is polled, with `route` taking any `Verb` and `get`, `post`, `put`, `delete` and `patch` naming one.
Each decorator registers the function through `add_endpoint` and returns it unchanged, so it stays callable from Python.
Templates capture `{name}` segments and a greedy `{*name}` tail, literal segments match before captures, and registering one template and verb twice raises `ucall.Error` with `Status.ALREADY_EXISTS`.
A path no endpoint matches answers 404, and a request that cannot be parsed answers 400, 413 or 501 before reaching any handler.

Registration reads a handler's signature once.
A handler taking one parameter annotated `ucall.Request` receives the request itself.
Any other handler takes parameters annotated `str`, `int`, `float`, `bool` or `bytes`, or left bare, and each binds by name from the first place that has it:

- a placeholder of the template, as sent;
- the query, percent-decoded with "+" as a space;
- a JSON object body, parsed once and only when an earlier place missed a parameter;
- the parameter's default.

Text converts as `int(text)` and `float(text)` do, `bool` reads "1", "true", "yes" and "on" or "0", "false", "no" and "off" in any case, and `bytes` takes the raw bytes.
A JSON value must already have the annotated type, except that an integer widens to `float` and a string encodes to `bytes`.
A missing or malformed value answers 400 with the reason as plain text, such as "missing parameter 'limit'", without calling the handler.
Registration raises `TypeError` for `*args`, `**kwargs`, more than 16 parameters, or an annotation outside that list.

What a handler returns becomes the reply: `bytes`, `bytearray` and `memoryview` as application/octet-stream, `str` as UTF-8 text/plain, and anything else through `json.dumps` as application/json.
None from a typed handler answers 204, and None from a handler taking the request means it replies itself.
A handler's exception reaches `sys.unraisablehook` and answers 500, and the loop keeps serving.

`server.event_loop_statistics(loop)` copies one loop's counters as a dict, from any thread while the loop runs: polls, system calls, submissions and completions, accepted connections, requests, and the bytes received, sent and copied.
Divided by `requests`, they price one call.

## Requests

A `Request` is what a handler annotated to take one receives.
Its reads copy out of the received bytes: `verb`, `path`, `path_parameter(name)`, `query(name)` and `header(name)`, with `peer` naming the interface it arrived on and the client's authenticated Noise key.
`path`, path parameters and query values stay percent-encoded as sent, header names match case-insensitively, a lookup that finds nothing answers None, and the body arrives whole, decoded from chunked framing if it was sent that way.
`peer` is a tuple of the interface's index in the server's arguments and the client's 32-byte static key, 32 zero bytes on a plaintext interface.

```python
import ucall

server = ucall.Server(ucall.Interface("127.0.0.1:0"))


@server.post("/orders/{order}")
def order(request: ucall.Request):
    token = request.header("authorization")
    if token is None:
        request.reply_error(401, "sign in first\n")
        return
    receipt = f"{request.path_parameter('order')} by {token}".encode()
    request.reply(receipt, status=201, headers=("content-type: text/plain", "cache-control: no-store"))
```

`request.body` is a read-only `memoryview` over the received bytes, and the request itself supports the buffer protocol, so `bytes(request)` copies the body and `numpy.frombuffer(request, numpy.int8)` views it without a copy.
Both views stay valid until the reply, which frees those bytes, so a reply is refused with `BufferError` while any of them is alive.
The one view a reply accepts is `request.body` itself passed as the reply body, which it releases first, so `request.reply(request.body)` echoes without a copy.

`reply(body, status, headers)` sends any bytes-like body, copied before it returns, with "name: value" header lines, and Content-Length, Date and Server are generated; `reply_error(status, message)` sends a plain-text error.
Either consumes the request, so a second reply raises `ucall.Error` with `Status.ALREADY_EXISTS`, and later reads raise `ucall.Error` or, for the body, `BufferError`.
A request may be kept past its handler and answered later, from any thread, once, while responses still leave each connection in request order.
A request released without a reply answers 500.
A reply to a closed connection still consumes the request silently; any other failed reply raises `ucall.Error` and keeps it.

`request.path_segments` is a tuple of the path's components as `bytes`, and `request.parts` a tuple of `ucall.RequestPart(name, content_type, data)` for a `multipart/form-data` body.
Each part's `data` views the received bytes like `body` does, and keeps the request alive and unanswered until every such view is gone.

## Files & Streams

Handlers run on the polling thread, so a reply or a pull that finishes later runs on a worker: `request.detach()` hands the request over as a `ucall.DetachedRequest`, which reads and replies like a `Request` and alone has the three verbs below.

| Verb                                  | Returns                                             | Final when                             |
| :------------------------------------ | :-------------------------------------------------- | :------------------------------------- |
| `reply_parts(parts, status, headers)` | `None` for bytes alone, else a `ucall.Deferred`     | every part is sent                     |
| `reply_stream(status, headers)`       | a `ucall.ReplyStream` with `append(parts)`, `end()` | `end()` returns `None` or a `Deferred` |
| `body_chunks()`                       | an iterator of `memoryview` chunks                  | the body ended                         |

### Serving a File

```python
import concurrent.futures

import ucall

workers = concurrent.futures.ThreadPoolExecutor()
server = ucall.Server(ucall.Interface("0.0.0.0:8080", reply_directories=["/srv/videos"]))


def send_video(detached: ucall.DetachedRequest, name: str):
    deferred = detached.reply_parts([ucall.Path(0, name)])
    deferred.wait()  # or: await deferred


@server.get("/videos/{name}")
def video(request: ucall.Request):
    workers.submit(send_video, request.detach(), request.path_parameter("name"))
```

`reply_parts` concatenates bytes-like objects, `ucall.Path(directory, path, offset=0, length=0)` and `ucall.File(descriptor, offset=0, length=0)` into one body whose Content-Length is measured from the files.
A `Path` resolves beneath the named `reply_directories` entry, and the event loop opens, reads and closes it unbuffered.
A `File` is the caller's regular file opened with `os.O_DIRECT`, or an object whose `fileno()` answers one; UCall never closes it, and the `Deferred` keeps it open until the reply is final.
`deferred.status()` reads the outcome without waiting, `deferred.wait()` blocks without the interpreter lock and raises the failure, such as `Status.NOT_FOUND` after a 404, and `await deferred` runs that wait on the running loop's default executor.
Releasing an unfinished `Deferred` waits for it, which is why only a detached request makes one.

### Streaming a Reply

```python
def send_rows(detached: ucall.DetachedRequest, rows):
    stream = detached.reply_stream(headers=("content-type: text/csv",))
    for row in rows:
        stream.append([row.encode()])
    stream.end()
```

`append` queues more parts and raises `ucall.Error` with `Status.WOULD_BLOCK` while the peer lags behind what is queued; `end()` answers `None` or a `Deferred` as `reply_parts` does, and a stream released without `end()` ends itself.

### Streaming an Upload

```python
import hashlib


def store(detached: ucall.DetachedRequest):
    digest = hashlib.sha256()
    for chunk in detached.body_chunks():
        digest.update(chunk)
    detached.reply(digest.hexdigest().encode())


@server.post("/uploads", body=ucall.BodyDelivery.STREAMED)
def upload(request: ucall.Request):
    workers.submit(store, request.detach())
```

An endpoint registered with `body=ucall.BodyDelivery.STREAMED`, on `add_endpoint`, `route` and every verb decorator, runs its handler once the headers arrived.
`body_chunks()` yields each chunk as a `memoryview` valid until the next pull, which releases it, and waits for bytes without the interpreter lock.

## Batches

A batch endpoint gathers matching requests from every event loop into one queue and hands them to its handler in batches, which suits work that is cheaper per request in bulk, like GPU inference.

```python
import threading
import time

import ucall

server = ucall.Server(ucall.Interface("127.0.0.1:0", pipelined_requests=8))


@server.batch("/infer", min_size=16, max_size=64, max_latency_us=2_000)
def infer(requests: list[ucall.Request]):
    scores = [str(len(request.body)).encode() for request in requests]
    for request, score in zip(requests, scores, strict=True):
        request.reply(score)


threads = [threading.Thread(target=server.take_calls), threading.Thread(target=infer.take_batches)]
for thread in threads:
    thread.start()
time.sleep(0.1)
print(infer.statistics())
server.stop()
for thread in threads:
    thread.join()
```

`server.batch` registers the function through `add_batch_endpoint` and replaces it with its `BatchEndpoint`, which `server.batch_endpoints` lists too.
A batch is due as soon as `min_size` requests wait, holds at most `max_size`, and goes smaller once its oldest request waited `max_latency_us`; zeros mean 1, 32 and 10 milliseconds.
The handler runs on the thread draining the endpoint through `take_batch` or `take_batches`, never on an event loop, so a slow batch never stalls the network.
It receives a list of `Request` objects in arrival order, and may reply in any order or keep requests to answer later from any thread.
When the handler raises, every request it left unanswered answers 500.

The queue holds as many requests as the interfaces admit at once, connections times pipelined requests, and refuses more with 503.
`server.stop()` releases the requests still queued without a reply.
`endpoint.statistics()` counts `batches` and `requests`, and how many batches were `filled_batches` on reaching `max_size`, `ready_batches` on reaching `min_size`, or `expired_batches` once `max_latency_us` passed, from any thread while the endpoint drains.

## Calling

A `Client` submits calls without driving the network, and polls to drive them and collect what finished.
It holds up to `connections` connections, reusing them across calls, and carries up to `pipelined_calls` calls on each.

```python
import threading

import ucall

server = ucall.Server(ucall.Interface("127.0.0.1:0", pipelined_requests=16))


@server.post("/echo")
def echo(request: ucall.Request):
    return request.body


@server.post("/sum")
def total(a: int, b: int):
    return a + b


runner = threading.Thread(target=server.run)
runner.start()
base = f"http://{server.addresses[0]}"

client = ucall.Client(connections=4, pipelined_calls=16)
for index in range(64):
    client.submit("POST", f"{base}/echo", bytes([index]), context=index)
remaining = 64
while remaining:
    for completed in client.take_completed(timeout_us=1_000_000):
        assert completed.status == ucall.Status.SUCCESS
        assert bytes(completed.response.body) == bytes([completed.context])
        remaining -= 1

response = client.post(f"{base}/sum", json={"a": 1, "b": 2})
print(response.status_code, response.header("content-type"), bytes(response.body))
server.stop()
runner.join()
```

`submit(verb, url, body, headers, security=..., server_key=..., context=...)` borrows its URL, header lines, body and key until the call completes, and tags it with any `context` object.
A call admitted once completes exactly once, and a client already holding `calls` unretrieved calls refuses more with `ucall.Error` and `Status.CONTENDED`; `calls` defaults to `connections` times `pipelined_calls`.
`take_completed(timeout_us, capacity)` drives every admitted call and returns up to `capacity` finished ones as `Completed` objects, waiting up to its timeout for the first, and a zero timeout performs one nonblocking round.
A `Completed` carries the `context`, the final `status`, a `message` on failure, and the `response`, None on failure.

`request`, `get`, `post`, `put`, `delete` and `patch` submit one call and poll until it finishes, keeping the completions of other calls they retrieve meanwhile for the next `take_completed`, which hands those out first.
They take `json=` to send a value as JSON with its content type, and raise `ucall.Error` when the exchange fails.
Every calling method also takes this call's `timeout_us=`, `max_retries=` and `max_redirects=` in place of the client's, and a `client_key=` private key in place of its own.

Every received response is a `Response`, whatever its HTTP status, and only a failed exchange is an error.
A `Response` owns its received bytes, so it stays readable after its `Client` is gone, and supports the buffer protocol as a request does: `bytes(response)` copies its body and `response.body` views it.
Releasing the client cancels the calls still in flight and discards completions not yet retrieved.

## Noise Keys

Interfaces and calls can run over the Noise protocol instead of plain TCP, authenticating both sides by 32-byte Curve25519 static keys.

```python
import threading

import ucall

server_private_key, server_public_key = ucall.generate_noise_keypair()
client_private_key, _ = ucall.generate_noise_keypair()
client_public_key = ucall.derive_noise_public_key(client_private_key)

sealed = ucall.Interface(
    "127.0.0.1:0",
    security=ucall.Security.NOISE_XX,
    private_key=server_private_key,
    peer_authorizer=lambda key: key == client_public_key,
)
server = ucall.Server(sealed)


@server.get("/whoami")
def whoami(request: ucall.Request):
    _, static_key = request.peer
    return static_key


runner = threading.Thread(target=server.run)
runner.start()
client = ucall.Client(
    connections=1,
    private_key=client_private_key,
    peer_authorizer=lambda key: key == server_public_key,
)
response = client.get(f"http+noise://{server.addresses[0]}/whoami")
server.stop()
runner.join()
assert bytes(response.body) == client_public_key
```

`generate_noise_keypair` draws from the operating system's entropy and raises `ucall.Error` with `Status.IO` when it is refused.
`derive_noise_public_key` recovers the public half of a stored private key, which peers compare in their authorizers.
Under Noise XX both sides learn each other's key during the handshake, so both need an authorizer; Noise IK has the client name the server's key in advance through `server_key=`.
Noise KK has both sides name each other in advance: the interface admits one caller through `noise_peer_key=`, and the call names its own private key with `client_key=` and the server's with `server_key=`.
An `http+noise://` URL implies Noise XX, and a handler reads the client's authenticated key through `request.peer`.

## Errors

A failed operation raises `ucall.Error`, a `RuntimeError` whose `status` is the `ucall.Status` it reported and whose `message` is a static detail beside it.
`str(error)` joins the two, as in "CONNECTION_FAILED: connection-failed".
Arguments of the wrong type raise `TypeError`, a key of the wrong length or an unknown enum name raises `ValueError`, and a reply while views over the body are alive raises `BufferError`.

```python
import ucall

client = ucall.Client(connections=1)
try:
    response = client.get("http://127.0.0.1:1/")
    print("answered", response.status_code)
except ucall.Error as error:
    assert error.status == ucall.Status.CONNECTION_FAILED
    print("nobody listens:", error)
```

`ucall.Status`, `Backend`, `CPUClass`, `Security`, `Verb`, `BodyDelivery` and `LogLevel` are `enum.IntEnum` classes, and every argument taking one also takes its name in any case, with "-" or "_" between words.
A submitted call that fails completes with that status in `Completed.status`, such as `CONNECTION_FAILED`, `CONNECTION_CLOSED`, `TIMEOUT`, `HANDSHAKE_FAILED` or `PEER_REJECTED`, and HTTP error statuses are ordinary responses.
On the serving side, failures become replies rather than exceptions: 400 for parameters that do not bind, 500 for a handler that raised or a request released unanswered.

## Threads & Polling

The package starts no threads and needs no event loop of its own: every handler runs on a thread the application lent to a polling call.

- A route handler runs on the thread inside `take_call`, `take_calls` or `run` for the event loop that received the request.
- A batch handler runs on the thread inside `take_batch` or `take_batches` for its endpoint, never on an event loop.
- A server's peer authorizer runs on the polling thread completing the handshake, and a client's on the client's own thread inside `take_completed` or a blocking call.

Each event loop and each batch endpoint has one polling owner at a time.
`take_calls` and `take_batches` run until `server.stop()`, while `take_call` and `take_batch` return after one round, waiting up to their timeout, so a loop of them interleaves polling with other work on the same thread.
`server.stop()` works from any thread, handlers included, and wakes every polling and draining thread; join them before releasing the server.
An interface accepts on its own number of event loops, one by default, and `server.event_loops` reports the largest of those counts.

```python
import threading

import ucall

server = ucall.Server(ucall.Interface("127.0.0.1:0", event_loops=4))
threads = [threading.Thread(target=server.take_calls, args=(loop,)) for loop in range(server.event_loops)]
threads += [threading.Thread(target=endpoint.take_batches) for endpoint in server.batch_endpoints]
for thread in threads:
    thread.start()
server.stop()
for thread in threads:
    thread.join()
```

Every polling call releases the interpreter lock while it waits on the network and takes it back only to run a Python handler, authorizer or batch handler.
So loops parse, route and send in parallel, while Python handlers on several loops take turns on the lock unless they release it themselves, as NumPy does in its kernels.
Signals reach Python only on the main thread between calls, so `take_calls` and `take_batches` belong on other threads.

`server.run()` covers the simplest server, one event loop and no batch endpoints, on the calling thread, and raises `RuntimeError` for anything larger.
It polls in slices of 100 milliseconds and checks for signals between them, so Ctrl+C raises `KeyboardInterrupt` from it, and once stopped it lets the loop finish the requests in flight before returning.
The blocking client calls wait in the same slices, so Ctrl+C interrupts them too, and the interrupted call completes later through `take_completed`.

A `Client` belongs to the thread that created it, and any other thread calling it gets `ucall.Error` with `Status.INVALID_ARGUMENT`, so a program calling from several threads makes one client per thread.
A `Request` and a `Response` move freely between threads.
Every thread that polls, replies or reads must run on a CPU supporting the CPU class the server or client resolved at start, so `CPUClass.SERIAL` is the safe choice on machines mixing CPU generations.

## What This Binding Does Not Expose

The binding leaves these out:

- WebSocket endpoints, connections and messages, on either side.

## Design

The binding is a thin native layer, and every rule below follows from that.

- __Processing stays native.__
  Parameter binding, percent-decoding, conversion, reply serialization and the blocking client calls run in the extension, and `ucall/__init__.py` only re-exports it.
  A handler's signature is resolved once at registration, so a request costs a table walk and one call, and a typed handler never sees a `Request` object at all.
- __Verbs share one name across languages.__
  `take_call`, `take_calls`, `take_batch`, `take_batches`, `submit` and `take_completed` name the same calls in Python and Rust.
- __Ownership follows the request.__
  A reply consumes its `Request`, a released request answers 500, views over a body pin it until released, and a `Response` frees itself.
- __Handlers never stop a loop.__
  An exception inside a handler or an authorizer reaches `sys.unraisablehook` and answers 500 or rejects the peer, and Ctrl+C raised inside one is re-armed for the main thread.
- __Blocking stays simple.__
  Every method looks as it would without asynchrony, and only a reply with file or path parts answers a `Deferred`.
- __Deferred replies are symmetric through language idioms.__
  A `Deferred` owns its outcome: `wait()` blocks, `await` borrows the running loop's executor, and releasing it waits, as releasing any owner does.
  The verbs that may defer exist only on a `DetachedRequest`, so by type no polling thread waits on its own loop.
- __No extra cost until used.__
  Bytes-only replies keep their outcome on the stack, up to sixteen reply parts lay out on the stack, and a `Deferred` is the one allocation a file reply adds.
- __No life of its own.__
  The binding starts no threads, keeps no global state beyond imported helpers, and needs no async runtime, so it drops into any threading model.
- __Statuses and modes are enums.__
  `ucall.Status`, `Backend`, `CPUClass`, `Security`, `Verb`, `BodyDelivery` and `LogLevel` are `enum.IntEnum` classes, so nothing is ever compared as a string.
