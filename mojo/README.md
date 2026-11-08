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

```mojo
from ucall import HTTPStatus, Interface, Library, Request, Server

def hello(var request: Request) raises:
    request^.reply(HTTPStatus.OK, "Hello!".as_bytes())

def echo(var request: Request) raises:
    var body = List[Byte](capacity=len(request.body()))
    body.extend(request.body())  # a reply consumes the request its body borrows from
    request^.reply(HTTPStatus.OK, body)

def main() raises:
    var server = Server(Library(), [Interface("127.0.0.1:8545")])
    server.get["/hello", hello]()
    server.post["/echo", echo]()
    server.take_calls(0)  # until server.stop() from a handler or another thread
```

`Library()` opens the shared object once, and every server, client and response created through it keeps it mapped.

## Serving

A handler is a compile-time parameter of its route, `server.get["/users/{name}", handler]()` and likewise `post`, `put`, `delete` and `patch`, or `route[path, handler](verb)` and `route_with[path, handler](verb, delivery)` for any other.

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
It alone offers the replies that may finish later:

```mojo
var detached = request^.detach()
var parts = [ReplyPart.bytes(header), ReplyPart.bytes(payload)]
if case .Some(deferred) = detached^.reply_parts(HTTPStatus.OK, no_headers, parts):
    deferred^.wait()  # off the polling thread, which is the one sending the file parts

var stream = other^.reply_stream(HTTPStatus.OK, no_headers)
stream.append(parts)
_ = stream^.end()  # Optional[Deferred] while file or path parts still send
```

`body_chunk` pulls a streamed body, waiting for the next bytes; on a buffered route the first pull is the whole body.
A `Deferred` reads `DEFERRED` from `status` until the reply is final, and `wait` blocks through `ucall_outcome_wait` and raises the reply's failure.
Dropping an unfinished `Deferred` waits for it.

## Batches

```mojo
def score(batch: Batch) raises:
    for index in range(len(batch)):
        var request = batch.take(index)
        var length = String(len(request.body()))
        request^.reply(HTTPStatus.OK, length.as_bytes())

var scores = server.batch["/score", score](Verb.POST, Batching(2, 32, 10_000))
scores.take_batches()  # on its own thread, until server.stop()
```

Requests from every event loop share one queue per endpoint, drained by whichever thread polls it; requests the handler does not take answer 500 once it returns.

## Calling

```mojo
var client = Client(library, ClientOptions(connections=2))
var response = client.get("http://127.0.0.1:8545/hello")
print(response.status_code().code, response.header("content-length").value())

client.submit(ClientCall.post("http://127.0.0.1:8545/echo", "ping".as_bytes()), 7)
var completed = List[Completed]()
client.take_completed(completed, timeout_microseconds=1_000_000)
for position in range(len(completed)):  # `Completed` is not `Copyable`, so it is read in place
    ref done = completed[position]
    print(done.context, done.response.value().body())
```

`submit` admits a call without driving the network, `take_completed` drives every admitted call and hands back what finished, and `call`, with `get`, `post`, `put`, `delete` and `patch`, submits one and polls until its own response arrives.
A client owns every input until its call completes, in slots sized once by the resolved call budget.
`Client(server, options, event_loop=0)` binds the client to a server's event loop instead, so that loop's `take_call` drives both, which is how `mojo/test.mojo` serves and calls on one thread.

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
```

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

## Design

- __A thin layer over the C ABI.__
  Every name follows `c/ucall/`, and enums mirror C enums, never strings.
  Every one of the 55 exported functions is bound, and so are both callback types, the log sink and the peer authorizer; typed JSON handlers stay Python's, and Mojo handlers read and write bytes.
- __Handlers are compile-time parameters.__
  One `thin abi("C")` trampoline is instantiated per handler, and the context the library passes back addresses the `Server`, which is not `Movable` for that reason.
- __Pointers keep their types and their borrows.__
  A C pointer that may be null is an `Optional[Pointer]`, a view carries the origin of what it borrows, and only opaque handles and `void *` state cross as an integer `Address`.
