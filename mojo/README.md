# UCall for Mojo

The Mojo package binds the C ABI in `c/ucall/`, opening the library's shared object with `dlopen` rather than linking it, so a consumer builds with no linker flags of its own.
It needs Mojo 1.2 through pixi, on Linux x86-64, Linux AArch64 or macOS on Apple silicon, and glibc 2.39 or newer on Linux.
It exposes servers with their routes, batch endpoints and replies, and clients with their calls and responses.

## Installation

Let Pixi build the package from source, with no channel to add and no linker flag to pass; the library arrives as its run dependency, in the environment prefix `mojo build` bakes as runpath.

```toml
[workspace]
preview = ["pixi-build"]

[dependencies]
ucall_mojo = { git = "https://github.com/unum-cloud/UCall", subdirectory = "mojo", tag = "v1.0.0-rc.1" }
```

From a checkout, `pixi run test` builds the library through the tree's own CMake and runs `mojo/test.mojo` against it.

## Quickstart

A server on a free loopback port greets the name `GET /hello/{name}` captures, and a client bound to the server's event loop calls `/hello/world` on the same thread.
Each `take_call` round advances both, until the completion arrives.
`Library()` opens the shared object once, and every server, client and response created through it keeps it mapped.

```mojo
from std.testing import assert_equal

from ucall import Client, ClientCall, ClientOptions, Completed, HTTPStatus, Interface, Library, Request, Server


def say_hello(var request: Request) raises:
    var greeting = List[Byte](capacity=64)
    greeting.extend("Hello, ".as_bytes())
    greeting.extend(request.path_parameter("name").value())  # copied, as the reply consumes the request
    request^.reply(HTTPStatus.OK, greeting)


def main() raises:
    var server = Server(Library(), [Interface("127.0.0.1:0")])
    server.get["/hello/{name}", say_hello]()
    var client = Client(server, ClientOptions(connections=1))  # advanced by the server's event loop
    client.submit(ClientCall.get(String("http://", server.address(0).value(), "/hello/world")))
    var completed = List[Completed]()
    while len(completed) == 0:
        _ = server.take_call(0, 1_000)
        client.take_completed(completed)
    var body = String(unsafe_from_utf8=completed[0].response.value().body())
    print(body)
    assert_equal(body, "Hello, world")
    _ = completed^
    _ = client^  # a bound client goes before its server
    server.stop()
```

## Serving

A server takes the interfaces it answers on and its `ServerOptions`; each `Interface` carries its own security and admission limits, so one server answers plaintext on loopback and Noise on the wire at once.

```mojo
def listing(var request: Request) raises:
    var user = String(unsafe_from_utf8=request.path_parameter("user").value())
    var path = String(unsafe_from_utf8=request.path_parameter("path").value())
    request^.reply(HTTPStatus.OK, String(user, ":", path).as_bytes())


def anything(var request: Request) raises:
    request^.reply_error(HTTPStatus.NOT_IMPLEMENTED, "not served")


def main() raises:
    var library = Library()
    var public = Interface("0.0.0.0:0", connections=16_384, event_loops=4)
    public.pipelined_requests = 16
    var health = Interface("127.0.0.1:0", connections=4)
    var options = ServerOptions()
    options.cpu_class_ceiling = CPUClass.SERIAL
    var server = Server(library, [public^, health^], options)
    print(server.event_loops(), "event loops on", library.io_backend_name(server.backend()))
    server.get["/users/{user}/files/{*path}", listing]()
    server.route["/anything", anything](Verb.ANY)
```

A handler is a compile-time parameter of its route, `server.get["/users/{name}", handler]()` and likewise `post`, `put`, `delete` and `patch`, or `route[path, handler](verb)` and `route_with[path, handler](verb, delivery)` for any other.
Templates capture `{name}` segments and a greedy `{*name}` tail, literal segments match before captures, and port zero binds a free port, which `server.address` reports.

UCall writes nothing on its own; a server's or a client's `log` option hands every line to a handler, with state of your own that must outlive the server or client:

```mojo
def count(level: LogLevel, line: StringSlice[ImmUntrackedOrigin], mut lines: Int):
    lines += 1

var options = ServerOptions()
options.log = Log.to[count](lines, level=LogLevel.INFO)
```

## Requests

Each handler runs on the thread polling the event loop and owns its `Request`:

```mojo
def greet(var request: Request) raises:
    var verbose = request.query("verbose")          # Optional[Span[Byte, ...]], still percent-encoded
    var agent = request.header("user-agent")        # case-insensitive
    if not request.path_parameter("name"):          # case-sensitive
        request^.reply_error(HTTPStatus.BAD_REQUEST, "no name")
        return
    request^.reply(HTTPStatus.OK, [BytesView.of("content-type: text/plain")], "Hello!".as_bytes())
```

Every read borrows the received bytes with the request's origin.
`fields_count` and `field` walk every header line in arrival order, `path_segments_count` and `path_segment` walk the path, `parts_count` and `part` walk a `multipart/form-data` body, and `peer` reports the interface, the authenticated Noise key and the socket address.
`reply`, `reply_error` and `detach` consume the request, and a request dropped without them answers 500, which is also what a handler raising past it answers.

## Files & Streams

`request^.detach()` hands the request to a `DetachedRequest`, which reads the same way, moves to any thread, and answers 500 when dropped unreplied.
It alone offers the replies that may finish later, such as a stream of rows:

```mojo
def rows(var request: Request) raises:
    var stream = request^.detach().reply_stream(HTTPStatus.OK, [BytesView.of("content-type: text/csv")])
    for row in range(3):
        var line = String(row, ",", row * row, "\n")
        stream.append([ReplyPart.bytes(line.as_bytes())])
    _ = stream^.end()  # `None`, as no file or path part is left to send
```

A reply with a path part resolves it beneath the interface's `reply_directories`, and is sent by the polling thread, so a worker thread waits for it:

```mojo
def send_clip(var detached: DetachedRequest) raises:
    var no_headers = List[BytesView[ImmUntrackedOrigin]]()
    var parts = [ReplyPart.bytes("frame:".as_bytes()), ReplyPart.path(0, "clip.bin")]
    var deferred = detached^.reply_parts(HTTPStatus.OK, no_headers, parts)
    if deferred:
        deferred.take().wait()  # raises the reply's failure, such as `NOT_FOUND` after a 404
```

`ReplyPart.file` takes a `FileRange` of a descriptor the caller opened with `O_DIRECT` and keeps open until the reply is final.
`append` raises `WOULD_BLOCK`, queueing nothing, while the peer lags behind what is queued, and a stream dropped without `end` ends itself.
`body_chunk` pulls a streamed body, waiting for the next bytes; on a buffered route the first pull is the whole body.
A `Deferred` reads `DEFERRED` from `status` until the reply is final, and dropping an unfinished one waits for it.

## Batches

```mojo
def score(batch: Batch) raises:
    for index in range(len(batch)):
        var request = batch.take(index)
        var length = String(len(request.body()))
        request^.reply(HTTPStatus.OK, length.as_bytes())


def main() raises:
    var server = Server(Library(), [Interface("127.0.0.1:0")])
    var scores = server.batch["/score", score](Verb.POST, Batching(16, 64, 2_000))
    scores.take_batches()  # on its own thread, until server.stop()
```

`Batching(min_size, max_size, max_latency_microseconds)` dispatches as soon as `min_size` requests wait, never more than `max_size` at once, and a smaller batch once the oldest waited the latency; zeros mean 1, 32 and 10 milliseconds.
Requests from every event loop share one queue per endpoint, drained by whichever thread polls it through `take_batch` or `take_batches`; requests the handler does not take answer 500 once it returns.
`scores.statistics()` counts the batches and requests it handed out.

## Calling

```mojo
def main() raises:
    var client = Client(Library(), ClientOptions(connections=2))
    var response = client.get("http://127.0.0.1:8545/hello/world")
    print(response.status_code().code, String(unsafe_from_utf8=response.body()))

    for index in range(8):
        client.submit(ClientCall.post("http://127.0.0.1:8545/echo", "ping".as_bytes()), UInt64(index))
    var completed = List[Completed]()
    var remaining = 8
    while remaining > 0:
        client.take_completed(completed, timeout_microseconds=1_000_000)
        for position in range(len(completed)):
            ref done = completed[position]  # `Completed` is not `Copyable`, so it is read in place
            if done.error:
                print(done.context, "failed:", done.error.value())
            else:
                print(done.context, "answered", done.response.value().status_code().code)
            remaining -= 1
```

`submit` admits a call without driving the network, `take_completed` drives every admitted call and hands back what finished, and `call`, with `get`, `post`, `put`, `delete` and `patch`, submits one and polls until its own response arrives.
A client owns every input until its call completes, in slots sized once by the resolved call budget, and a `Response` stays readable after its client is dropped.
`Client(server, options, event_loop=0)` binds the client to a server's event loop instead, so that loop's `take_call` drives both, as the Quickstart does.

### Streamed Response Bodies

```mojo
def download(mut client: Client) raises:
    var call = ClientCall.get("http://127.0.0.1:8545/dataset.bin")
    call.options.body_delivery = BodyDelivery.STREAMED
    var response = client.call(call^)
    var received_bytes = 0
    while True:
        var chunk = response.body_chunk()
        if len(chunk) == 0:
            break
        received_bytes += len(chunk)
```

A call whose `ClientCallOptions.body_delivery` is `BodyDelivery.STREAMED` completes once its head arrived, so a download larger than `max_response_bytes` is pulled through `Response.body_chunk` as it lands, while `Response.body` raises `INVALID_ARGUMENT`.
Each chunk borrows the response until the next pull, and the bytes decoded before a failure come out before the failure is raised.
Pulls run on the client's thread and never wait in the library: `body_chunk` advances the client while nothing was decoded.
A client bound to a server advances only as that server's loop polls, so there `body_chunk` raises `WOULD_BLOCK`, to be pulled again after the next `take_call`.
Every streamed response is pulled to its end or dropped, bodiless ones too, as its connection carries no other call meanwhile; dropping it early closes that connection and fails the calls pipelined behind it with `CONNECTION_CLOSED`.
Redirects stay buffered so they can be followed, and only the final response streams.

## Noise Keys

An interface with `Security.NOISE_XX` learns client keys during the handshake, so it vets them through a `PeerAuthorizer`, and a client calling an "http+noise://" URL vets the server's the same way:

```mojo
def admit(peer_static_key: NoiseKey) -> Bool:
    return peer_static_key == trusted_key

var keys = library.generate_noise_keypair()
var sealed = Interface("0.0.0.0:8546")
sealed.security = Security.NOISE_XX
sealed.noise_private_key = keys[0]
sealed.peer_authorizer = PeerAuthorizer.to[admit]()
var server = Server(library, [sealed^])

var client_keys = library.generate_noise_keypair()
var options = ClientOptions(connections=1)
options.noise_private_key = client_keys[0]
options.peer_authorizer = PeerAuthorizer.to[admit]()
var client = Client(server, options)
client.submit(ClientCall.get(String("http+noise://", server.address(0).value(), "/hello")))
```

`generate_noise_keypair` draws a private and public key from the operating system's entropy, and `derive_noise_public_key` recovers the public half of a stored private key, which is what a peer's authorizer compares.
Noise IK has the client name the server's key in advance through the call's options, and Noise KK has both sides name each other, the interface through `noise_peer_key`.

The authorizer returns a value through the C calling convention, which Mojo 1.2 was confirmed to lower correctly on Linux x86-64; the CI matrix confirms Linux AArch64 and macOS.

## Errors

Every fallible entry point raises `Error` and nothing else, carrying a `Status` shared with the C interface:

```mojo
try:
    server.get["/hello", hello]()
except error:
    if error.status == Status.ALREADY_EXISTS:
        pass  # the template and verb were registered before
    print(error)  # UCall: already-exists [ucall_server_add_http_endpoint]: ...
```

## Threads & Polling

The binding starts no threads and keeps no queues; the application polls every event loop, batch endpoint and client on threads it owns.
A route handler runs on the thread inside `take_call` or `take_calls` for its event loop, and a batch handler on the thread inside `take_batches` for its endpoint.
On the polling thread nothing arrives while a handler runs, so a pull finding nothing there raises `WOULD_BLOCK` instead of waiting, and a streamed body is read from another thread.
`take_calls` runs until `server.stop()`, while `take_call` returns after one round, so a thread interleaves polling with its other work:

```mojo
while server.take_call(0, 100_000) != Polling.RETIRED:
    pass  # this thread's other work goes between rounds, until server.stop()
```

`take_call` answers `Polling.RETIRED` once the loop drained or cut everything after a stop; the first stop drains the requests already held, and a second cuts the replies still in flight.
A client bound to a server's event loop is used only on that loop's polling thread, and is dropped before its server.

## Design

- __A thin layer over the C ABI.__
  Every name follows `c/ucall/`, and enums mirror C enums, never strings.
  Every one of the 55 exported functions is bound, and so are both callback types, the log sink and the peer authorizer; typed JSON handlers stay Python's, and Mojo handlers read and write bytes.
- __Handlers are compile-time parameters.__
  One `thin abi("C")` trampoline is instantiated per handler, and the context the library passes back addresses the `Server`, which is not `Movable` for that reason.
- __Pointers keep their types and their borrows.__
  A C pointer that may be null is an `Optional[Pointer]`, a view carries the origin of what it borrows, and only opaque handles and `void *` state cross as an integer `Address`.
