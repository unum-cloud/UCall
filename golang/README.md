# UCall for Go

## Installation

```sh
go get github.com/unum-cloud/ucall/golang@main
```

The package binds the C interface in `c/ucall/` through cgo and links the `ucall_static` archive, so building needs Go 1.24 or newer with cgo enabled and a C toolchain.
Build the archive from a checkout and point cgo at it for the current shell, or install it where the linker looks:

```sh
cmake -B build_release -D CMAKE_BUILD_TYPE=Release
cmake --build build_release --target ucall_static
export CGO_LDFLAGS="-L$PWD/build_release"
```

On Linux the archive's io_uring backends also link the `liburing` archive the same build leaves beside it.
Pin a branch or a commit, as in `@main` or `@<commit>`, which `go.sum` records as a pseudo-version.
The library picks its I/O backend and CPU kernels when a server or client starts, so one build adapts to the kernel and CPU it runs on.

## Quickstart

A server answers on one or more interfaces, and a client calls it; neither starts a goroutine.

```go
package main

import (
	"fmt"
	"log"

	ucall "github.com/unum-cloud/ucall/golang"
)

func main() {
	server, err := ucall.NewServer([]ucall.Interface{ucall.NewInterface("127.0.0.1:0")}, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()
	err = server.Get("/hello/{name}", func(request *ucall.Request) {
		name, _ := request.PathParameter("name")
		greeting := append([]byte("Hello, "), name...)
		_ = request.Reply(ucall.HTTPStatusOK, []string{"content-type: text/plain"}, greeting)
	})
	if err != nil {
		log.Fatal(err)
	}
	address, _ := server.Address(0)
	polled := make(chan error)
	go func() { polled <- server.TakeCalls(0) }()

	client, err := ucall.NewClient(&ucall.ClientOptions{Connections: 1})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	response, err := client.Get("http://" + address + "/hello/world")
	server.Stop()
	if err := <-polled; err != nil {
		log.Fatal(err)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer response.Close()
	body, err := response.Body()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(body))
}
```

The polling goroutine runs the handler, the client blocks in `Get` until its response arrives, and `Stop` releases the polling goroutine.
`golang/example_test.go` compiles and runs this Quickstart.

## Serving

`NewServer` takes the interfaces to answer on and optional `ServerOptions`: the `Backend`, a `CPUClass` ceiling that caps the picked class rather than demanding one the machine lacks, a `Log` sink and a StatsD endpoint in `Metrics`.
It fails rather than substituting when the backend is unavailable or the CPU does not run the class.
An `Interface` is an address, optionally pinned to a Linux device, with its own security and admission limits, so one server answers plaintext on loopback and Noise on the wire at once.
`Server.MemoryDomain` reports the NUMA node the kernel ties an interface's device to, or -1, so the application inits and polls from goroutines locked to threads there; UCall places nothing by it.
`NewInterface` admits 1024 connections, reads one request per connection at a time unless `PipelinedRequests` allows more, and replies still leave in request order.
`MaxRequestBytes` caps a request's head and buffered body, answering 413 past it, and `ReplyDirectories` names the directories path replies resolve beneath.
`ListenDescriptor` accepts on a listener another owner opened instead of binding an address, and never closes it.
Port zero binds a free port, which `Server.Address` reports.

```go
public := ucall.NewInterface("0.0.0.0:8545")
public.EventLoops, public.Connections, public.PipelinedRequests = 4, 16_384, 16
health := ucall.NewInterface("127.0.0.1:8546")
health.Connections = 4
sink := &ucall.Log{
	Callback: func(level ucall.LogLevel, line []byte) { fmt.Fprintf(os.Stderr, "%d %s\n", level, line) },
	Format:   ucall.LogHuman,
	Level:    ucall.LogWarning,
}
options := &ucall.ServerOptions{
	CPUClassCeiling: ucall.CPUClassSerial,
	Log:             sink,
	Metrics:         &ucall.Metrics{Address: "127.0.0.1:8125", Prefix: "myapp"},
}
server, err := ucall.NewServer([]ucall.Interface{public, health}, options)
if err != nil {
	return err
}
fmt.Println(server.EventLoops(), "event loops on", server.Backend(), "with", server.CPUClassCeiling(), "kernels")

err = server.Get("/users/{user}/files/{*path}", func(request *ucall.Request) {
	user, _ := request.PathParameter("user")
	path, _ := request.PathParameter("path")
	_ = request.Reply(ucall.HTTPStatusOK, nil, append(append(user, ':'), path...))
})
err = server.Route("/anything", ucall.VerbAny, func(request *ucall.Request) {
	_ = request.ReplyError(ucall.HTTPStatusNotImplemented, "This method is not served")
})
```

Routes register before any loop is polled, with `Route` taking any `Verb` and `Get`, `Post`, `Put`, `Delete` and `Patch` naming one, while `RouteWith` also names the `BodyDelivery`.
Templates capture `{name}` segments and a greedy `{*name}` tail, literal segments match before captures, and registering one template and verb twice fails with `StatusAlreadyExists`.
Routing is exact: an empty segment is a segment, so `/users` and `/users/` are different paths.
A path no route matches answers 404, one whose routes take other verbs answers 405 with an `allow` header, a GET route also serves HEAD, and `OPTIONS` answers 204 with the same `allow` list.

Log lines reach the callback on whichever goroutine produced them, and StatsD datagrams carry each loop's counters and sampled request latencies, every second unless `Metrics.Interval` says otherwise.
`Server.EventLoopStatistics` copies one loop's counters, from any goroutine while the loop runs; divided by `Requests`, they price one call.

## Requests

A handler receives each `*Request`.
Its reads view the received bytes until the reply: `Verb`, `Path`, `QueryString`, `PathParameter`, `Query`, `Header` and `Body`, with `Peer` naming the interface it arrived on, the client's authenticated Noise key and its `PeerAddress`.
Every read that can fail answers its value beside an error, so a missing header or parameter reports `StatusNotFound` and a body read on a streamed route `StatusInvalidArgument`.
The path and query values stay percent-encoded as sent, which `ucall.DecodePercent` decodes, header names match case-insensitively, and the body arrives whole, decoded from chunked framing if it was sent that way.
`Fields` yields every header field in arrival order as a name and a value, names lowercased and values trimmed, as a proxy forwards a head.
`PathSegmentsCount` and `PathSegment` read the path component by component, and `PartsCount` and `Part` read a `multipart/form-data` body as `RequestPart`s.

```go
err = server.Post("/orders/{order}", func(request *ucall.Request) {
	token, err := request.Header("authorization")
	if err != nil {
		_ = request.ReplyError(ucall.HTTPStatusUnauthorized, "sign in first")
		return
	}
	order, _ := request.PathParameter("order")
	receipt := append(append(append([]byte{}, order...), " by "...), token...)
	headers := []string{"content-type: text/plain", "cache-control: no-store"}
	_ = request.Reply(ucall.HTTPStatusCreated, headers, receipt)
})
```

`Reply` and `ReplyError` take the request, so a request is answered at most once, and Content-Length, Date and Server are generated.
A reply copies what it sends before it returns, so a body may view the request's bytes.
A handler that neither replies nor detaches its request answers 500 once it returns, and a handler that panics crashes the process, as a panic cannot unwind through the library.
The library clears the request's handle once a reply took it, a closed connection included, which reports `StatusConnectionClosed`; a reply it refused keeps the handle, and the handler's return then answers 500.

## Files & Streams

Handlers run on the polling goroutine, so a reply or a pull that finishes later runs on a worker: `Request.Detach` hands the request over as a `*DetachedRequest`, which reads and replies like a `Request` and alone has the verbs below.

| Verb                                  | Returns                               | Final when                         |
| :------------------------------------ | :------------------------------------ | :--------------------------------- |
| `ReplyParts(status, headers, parts)`  | `*Deferred[struct{}]`                 | every part is sent                 |
| `ReplyStream(status, headers)`        | `*ReplyStream` with `Append` and `End` | `End` answers a `*Deferred`        |
| `BodyChunk()`                         | `*Deferred[BodyChunk]`                | the next bytes arrived             |

### Serving a File

```go
handed := make(chan *ucall.DetachedRequest, 16)
videos := ucall.NewInterface("0.0.0.0:8080")
videos.ReplyDirectories = []string{"/srv/videos"}
server, err := ucall.NewServer([]ucall.Interface{videos}, nil)
if err != nil {
	return err
}
err = server.Get("/videos/{name}", func(request *ucall.Request) { handed <- request.Detach() })
go server.TakeCalls(0)
for detached := range handed {
	name, _ := detached.PathParameter("name")
	parts := []ucall.ReplyPart{ucall.PathPart(ucall.PathRange{Directory: 0, Path: string(name)})}
	if sent, err := detached.ReplyParts(ucall.HTTPStatusOK, nil, parts); err == nil {
		_, _ = sent.Wait()
	}
}
```

`ReplyParts` concatenates `BytesPart`, `PathPart` and `FilePart` parts into one body whose Content-Length is measured from the files.
A path part resolves beneath the interface's `ReplyDirectories`, refusing absolute paths, `..` and links leading out, and a file part names the caller's unbuffered descriptor until the reply is final, while bytes and paths are copied before the call returns.
A missing, unreadable or too short file replaces the reply with 404, 416 or 500 before its head leaves, and the `Deferred` reports the cause.
`Deferred.Status` polls, `Deferred.Wait` parks the goroutine in the library until the call is final, `Deferred.Close` waits and drops it, and a `Deferred` dropped without either is released by the collector once final.
A refusal comes back as the error beside a nil `Deferred`, before anything is submitted.

### Streaming a Reply

```go
func sendRows(detached *ucall.DetachedRequest, rows []string) error {
	stream, err := detached.ReplyStream(ucall.HTTPStatusOK, []string{"content-type: text/csv"})
	if err != nil {
		return err
	}
	for _, row := range rows {
		if err := stream.Append([]ucall.ReplyPart{ucall.BytesPart([]byte(row))}); err != nil {
			return err
		}
	}
	ended, err := stream.End()
	if err != nil {
		return err
	}
	_, err = ended.Wait()
	return err
}
```

The stream is chunked unless a Content-Length header declares the length, `Append` refuses with `StatusWouldBlock`, queueing nothing, while the peer lags behind, and `ReplyStream.Close` ends a stream not yet ended.

### Streaming an Upload

```go
func store(detached *ucall.DetachedRequest) error {
	receivedBytes := 0
	for {
		pulled, err := detached.BodyChunk()
		if err != nil {
			return err
		}
		chunk, err := pulled.Wait()
		if err != nil {
			return err
		}
		if len(chunk.Bytes()) == 0 {
			break
		}
		receivedBytes += len(chunk.Bytes())
	}
	return detached.Reply(ucall.HTTPStatusOK, nil, []byte(strconv.Itoa(receivedBytes)))
}
```

A route registered through `Server.RouteWith` with `BodyStreamed` runs its handler once the headers arrive and hands `request.Detach()` to a worker, whose pulls wait for the next bytes, each valid until the next pull.
On the polling goroutine a pull with nothing decoded fails with `StatusWouldBlock` instead, as nothing arrives while it runs.

## Batches

A batch endpoint gathers matching requests from every event loop into one queue and hands them to its handler in batches, which suits work that is cheaper per request in bulk, like GPU inference.

```go
network := ucall.NewInterface("127.0.0.1:0")
network.PipelinedRequests = 8
server, err := ucall.NewServer([]ucall.Interface{network}, nil)
if err != nil {
	return err
}
batching := ucall.Batching{MinSize: 16, MaxSize: 64, MaxLatency: 2 * time.Millisecond}
infer, err := server.Batch("/infer", ucall.VerbPost, batching, func(batch ucall.Batch) {
	for index := range batch.Len() {
		request := batch.Take(index)
		body, err := request.Body()
		if err != nil {
			_ = request.ReplyError(ucall.HTTPStatusBadRequest, err.Error())
			continue
		}
		_ = request.Reply(ucall.HTTPStatusOK, nil, []byte(strconv.Itoa(len(body))))
	}
})
if err != nil {
	return err
}
go server.TakeCalls(0)
go infer.TakeBatches()
```

`Batching` dispatches as soon as `MinSize` requests wait, never more than `MaxSize` at once, and a smaller batch once its oldest request waited `MaxLatency`; zero fields mean 1, 32 and 10 milliseconds.
The handler runs on the goroutine polling the endpoint through `TakeBatch` or `TakeBatches`, never on an event loop, so a slow batch never stalls the network.
A `Batch` holds its requests in arrival order, and `Take` hands one over, to be replied to then or later from any goroutine; a request never taken stays unanswered until the server closes.
The queue holds as many requests as the interfaces admit at once, connections times pipelined requests, and refuses more with 503.
`BatchEndpoint.Statistics` counts batches and requests, and whether each was dispatched on reaching `MaxSize`, on reaching `MinSize`, or once `MaxLatency` passed.

## Calling

A `Client` submits calls without driving the network, and polls to drive them and collect what finished.
It holds up to `Connections` connections, reusing them across calls, and carries up to `PipelinedCalls` calls on each.

```go
client, err := ucall.NewClient(&ucall.ClientOptions{Connections: 4, PipelinedCalls: 16})
if err != nil {
	return err
}
defer client.Close()
for index := range uint64(64) {
	call := ucall.ClientCall{Verb: ucall.VerbPost, URL: "http://127.0.0.1:8545/infer", Body: []byte{byte(index)}}
	if err := client.Submit(call, index); err != nil {
		return err
	}
}
completed := make([]ucall.Completed, 16)
for remaining := 64; remaining != 0; {
	finished, err := client.TakeCompleted(completed, time.Second)
	if err != nil {
		return err
	}
	for _, done := range finished {
		if done.Err != nil {
			fmt.Println("call", done.Context, "failed:", done.Err)
			continue
		}
		fmt.Println("call", done.Context, "answered", done.Response.StatusCode())
		_ = done.Response.Close()
	}
	remaining -= len(finished)
}

health, err := client.Get("http://127.0.0.1:8545/health")
if err != nil {
	return err
}
defer health.Close()
cacheControl, _ := health.Header("cache-control")
```

`Submit` takes a `ClientCall`, whose URL, header lines and body the client pins until the call completes, and tags it with a `uint64` context.
A call admitted once completes exactly once, and a client already holding `Calls` unretrieved calls refuses more with `StatusContended`.
`TakeCompleted` drives every admitted call and fills a caller-provided slice with finished ones, waiting up to its timeout for the first, and a zero timeout performs one nonblocking round.
`Get`, `Post`, `Put`, `Delete`, `Patch` and `Call` submit one call and poll until it finishes, while the library keeps the completions of other calls queued for the next `TakeCompleted`.
`ClientCall.Options` carries the call's own `ClientCallOptions`: a timeout in place of the client's, retries, redirect hops, security, and the client and server keys.

Every received response is a `*Response`, whatever its HTTP status, and only a failed exchange is an error.
A `Response` owns its received bytes, stays readable after its `Client` is closed and may move to another goroutine; `Close` frees it, and the collector frees one dropped.
Closing the client cancels the calls still in flight and discards completions not yet retrieved.

### Streamed Response Bodies

```go
call := ucall.ClientCall{Verb: ucall.VerbGet, URL: "http://127.0.0.1:8545/dataset.bin"}
call.Options.BodyDelivery = ucall.BodyStreamed
response, err := client.Call(call)
if err != nil {
	return err
}
defer response.Close()
receivedBytes := 0
for {
	chunk, err := response.BodyChunk()
	if errors.Is(err, ucall.StatusWouldBlock) {
		_, _ = client.TakeCompleted(nil, time.Millisecond)
		continue
	}
	if err != nil {
		return err
	}
	if len(chunk) == 0 {
		break
	}
	receivedBytes += len(chunk)
}
```

A call whose `BodyDelivery` is `BodyStreamed` completes once its head arrived, so a download larger than `MaxResponseBytes` is pulled through `Response.BodyChunk` as it lands, while `Response.Body` reads empty.
A pull never waits: with nothing decoded yet it fails with `StatusWouldBlock`, and an empty `TakeCompleted` advances the client, moving the next bytes in.
Every streamed response is pulled to its end or closed, as its connection carries no other call meanwhile; closing it early closes that connection and fails the calls pipelined behind it.

## Noise Keys

Interfaces and calls can run over the Noise protocol instead of plain TCP, authenticating both sides by 32-byte Curve25519 static keys.

```go
serverPrivateKey, serverPublicKey, err := ucall.GenerateNoiseKeypair()
if err != nil {
	return err
}
clientPrivateKey, _, err := ucall.GenerateNoiseKeypair()
if err != nil {
	return err
}
clientPublicKey, err := ucall.DeriveNoisePublicKey(clientPrivateKey)
if err != nil {
	return err
}

sealed := ucall.NewInterface("0.0.0.0:8546")
sealed.Security, sealed.NoisePrivateKey = ucall.SecurityNoiseXX, &serverPrivateKey
sealed.PeerAuthorizer = func(key ucall.NoiseKey) bool { return key == clientPublicKey }
server, err := ucall.NewServer([]ucall.Interface{sealed}, nil)
if err != nil {
	return err
}

client, err := ucall.NewClient(&ucall.ClientOptions{
	Connections:     1,
	NoisePrivateKey: &clientPrivateKey,
	PeerAuthorizer:  func(key ucall.NoiseKey) bool { return key == serverPublicKey },
})
```

`GenerateNoiseKeypair` draws from the operating system's entropy and fails with `StatusIO` when it is refused.
`DeriveNoisePublicKey` recovers the public half of a stored private key, which peers compare in their authorizers.
Under Noise XX both sides learn each other's key during the handshake, so both need an authorizer; Noise IK has the client name the server's key in advance through `ClientCallOptions.NoisePeerKey`.
Noise KK has both sides know each other in advance: the interface admits the one key `Interface.NoisePeerKey` names, and the call presents `ClientCallOptions.NoisePrivateKey` or the client's own key.
An `http+noise://` URL implies Noise XX, and a handler reads the client's authenticated key through `Request.Peer`.

## Errors

Every fallible call answers an `error`, an `*ucall.Error` carrying the `Status` the library reported and its static message, which `errors.Is` matches against a bare `Status`.
A mistake the binding catches before calling the library, like a client closed before a call, reports the status the library would have used.
`Status` prints its stable spelling, such as "connection-failed".

```go
client, err := ucall.NewClient(&ucall.ClientOptions{Connections: 1})
if err != nil {
	return err
}
defer client.Close()
response, err := client.Get("http://127.0.0.1:1/")
switch {
case errors.Is(err, ucall.StatusConnectionFailed):
	fmt.Println("nobody listens:", err)
case err != nil:
	return err
default:
	defer response.Close()
	fmt.Println("answered", response.StatusCode())
}
```

A submitted call that fails completes with `Completed.Err`: `StatusConnectionFailed`, `StatusConnectionClosed`, `StatusTimeout`, `StatusHandshakeFailed` or `StatusPeerRejected`.
A request or response lookup that finds nothing fails with `StatusNotFound` beside an empty value, and HTTP error statuses are ordinary responses.
`Backend`, `CPUClass` and `Status` print their stable names, like "linux-uring618" and "intel-icelake", and `BackendFromName`, `CPUClassFromName` and `StatusFromName` parse them back, failing with `StatusInvalidArgument` on a name no value has.
`ucall.Version()` spells the linked library's version, candidate suffix included, and `ucall.DecodePercent` decodes a path or a query value, which requests hold still percent-encoded.

## Threads & Polling

The package starts no goroutines: every callback runs on a goroutine the application gave to a polling call, which stays on one thread for that call.

- A route handler runs on the goroutine inside `TakeCall` or `TakeCalls` for the event loop that received the request.
- A batch handler runs on the goroutine inside `TakeBatch` or `TakeBatches` for its endpoint, never on an event loop.
- A server's peer authorizer runs on the polling goroutine completing the handshake, and a client's on the goroutine inside `TakeCompleted` or a blocking call.

Each event loop and each batch endpoint has one polling owner at a time.
`TakeCalls` and `TakeBatches` run until `Server.Stop`, while `TakeCall` and `TakeBatch` return after one round, waiting up to their timeout, so a loop of them interleaves polling with other work; `TakeCall` answers `PollingRetired` once the loop drained after a stop.
`Server.Stop` works from any goroutine, handlers included, and wakes every polling goroutine; `Server.Close` frees the server once they returned.
The first stop drains, answering every request already held before its connection closes, and a second one cuts the replies still in flight.
A `Request` and a `Response` move between goroutines, while a `Client` is used by one goroutine at a time.
Every thread that polls, replies or reads must run on a CPU supporting the CPU class the server or client resolved at start, so `CPUClassSerial` is the safe choice on machines mixing CPU generations.

## Design

The package is a thin layer over UCall's native library, and every rule below follows from that.

- __Verbs share one name across languages.__
  `TakeCall`, `TakeCalls`, `TakeBatch`, `TakeBatches`, `Submit` and `TakeCompleted` name the same calls as `take_call` and its siblings in C++, Python and Rust.
- __Blocking stays simple, deferring stays symmetric.__
  A reply that is final on return answers an `error`, and one that may finish later answers `(*Deferred[T], error)`, as Rust's `Deferring::answer` hands back its refusal before submitting anything.
- __Ownership is a type, not a flag.__
  A reply takes its `Request`, which the library clears once taken, only a `DetachedRequest` hands back a `Deferred`, and a `Response` is freed by `Close` or the collector.
- __Callbacks cross as handles.__
  Routes, batch endpoints, log sinks and authorizers reach C as `cgo.Handle`s the server or client deletes when closed, never as Go pointers; a route's handle holds its handler alone, as each callback receives its server from the library.
- __One pinned frame per call.__
  Each call pins one allocation holding its outcome, its argument structure and its result, polls included, and a refusal the binding catches allocates only its `Error`, before anything is pinned.
- __No life of its own.__
  The package starts no goroutines, keeps no locks or counters, and recovers no panics, so it drops into any concurrency model.

| Path | Go | Rust |
|---|---|---|
| Blocking call | 1 frame | 0 |
| Refusal before the call | 1 `Error` | 1 error |
| Deferred submit and wait | 4: frame, `Deferred`, 2 in `AddCleanup` | 0 |
| Each callback | 1 `Request` | 0 |

A completion `TakeCompleted` lifts adds its `Response` and that response's cleanup, and header lines or reply parts add the one array they cross as.
`TestCallsAllocateOnlyTheirFrames` holds the first three rows.
