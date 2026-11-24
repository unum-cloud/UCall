# UCall for C++

## Installation

```sh
cmake -B build_release -D CMAKE_BUILD_TYPE=Release
cmake --build build_release --target ucall_static
```

The C++ interface is header-only over the C one: `cpp/ucall/*.hpp` include only `c/ucall/*.h` and the standard library, and a program links `ucall_static`.
In CMake, link `ucall::cpp`, which carries the C headers of `ucall::abi` and the archive `ucall::static`, and which `find_package(ucall)` names once installed, or add the repository as a subdirectory.
It needs C++20, for concepts, designated initializers and coroutines, and it throws nothing.
The library picks its I/O backend and CPU kernels when a server or client starts, so one build adapts to the kernel and CPU it runs on.

## Quickstart

A server answers on one or more interfaces, and a client calls it; neither starts a thread.

```cpp
#include <thread>

#include <ucall/ucall.hpp>

namespace uc = unum::ucall;

void greet(uc::request_t request) noexcept {
    auto [name, name_status] = request.path_parameter("name");
    if (name_status.failed()) return;
    ucall_reply_part_t const parts[] {uc::bytes_part("Hello, "), uc::bytes_part(name)};
    ucall_bytes_view_t const headers[] {uc::bytes_view("content-type: text/plain")};
    uc::deferred<> sent; // final on return, as the parts are bytes alone
    [[maybe_unused]] uc::status_t const replied =
        std::move(request).reply_parts(ucall_http_status_ok_k, headers, parts, sent);
}

int main() {
    uc::interface_t const interfaces[] {{.address = "127.0.0.1:0"}};
    auto [server, server_status] = uc::server_t::make(interfaces);
    if (server_status.failed()) return 1;
    uc::status_t const routed = server.get<greet>("/hello/{name}");
    if (routed.failed()) return 1;
    auto [address, address_status] = server.address(0);

    auto [client, client_status] = uc::client_t::make({.max_concurrent_connections = 1});
    std::thread polling([&server] { [[maybe_unused]] uc::status_t const polled = server.take_calls(0); });
    char url[128];
    std::snprintf(url, sizeof url, "http://%.*s/hello/world", int(address.size()), address.data());
    auto [response, response_status] = client.get(url);
    server.stop();
    polling.join();
    auto [body, body_status] = response.body();
    return response_status.failed() || body_status.failed() || body != "Hello, world";
}
```

The polling thread runs the handler, the client blocks in `get` until its response arrives, and `stop` releases the polling thread so it can be joined.
Every fallible verb answers a `status_t` or an `expected<T>`, unpacked as `auto [value, status]`.

## Serving

`server_t::make` takes the interfaces to answer on, as an array whose size the compiler knows, and optionally `server_options_t`: the backend, a CPU class ceiling that caps the picked class rather than demanding one the machine lacks, a `log_t` sink and a StatsD endpoint.
It fails rather than substituting when the backend is unavailable or the CPU does not run the class.
An `interface_t` is an address, optionally pinned to a Linux device, with its own security and admission limits, so one server answers plaintext on loopback and Noise on the wire at once.
`server_t::memory_domain` reports the NUMA node the kernel ties an interface's device to, or -1, so the application inits and polls from threads there; UCall places nothing by it.
It admits 1024 connections by default, reads one request per connection at a time unless `max_pipelined_requests` allows more, and replies still leave in request order.
`max_request_bytes` caps a request's head and buffered body, answering 413 past it, and `reply_directories` names the directories path replies resolve beneath.
`listen_descriptor` accepts on a listener another owner opened instead of binding an address, and never closes it.
Port zero binds a free port, which `server_t::address` reports.

```cpp
void list_files(uc::request_t request) noexcept {
    auto [user, user_status] = request.path_parameter("user");
    auto [path, path_status] = request.path_parameter("path");
    ucall_reply_part_t const parts[] {uc::bytes_part(user), uc::bytes_part(":"), uc::bytes_part(path)};
    uc::deferred<> sent;
    [[maybe_unused]] uc::status_t const replied =
        std::move(request).reply_parts(ucall_http_status_ok_k, {}, parts, sent);
}

void not_served(uc::request_t request) noexcept {
    [[maybe_unused]] uc::status_t const replied =
        std::move(request).reply_error(ucall_http_status_not_implemented_k, "This method is not served");
}

auto log_line = [](ucall_log_level_t level, std::string_view line) noexcept {
    std::fprintf(stderr, "%d %.*s\n", int(level), int(line.size()), line.data());
};
uc::interface_t const interfaces[] {
    {.address = "0.0.0.0:8545", .event_loops = 4, .max_concurrent_connections = 16'384, .max_pipelined_requests = 16},
    {.address = "127.0.0.1:8546", .max_concurrent_connections = 4},
};
uc::server_options_t const options {
    .log = {log_line, ucall_log_format_human_k, ucall_log_level_warning_k},
    .metrics_address = "127.0.0.1:8125",
    .metrics_prefix = "myapp",
    .cpu_class_ceiling = ucall_cpu_class_serial_k,
};
auto [server, server_status] = uc::server_t::make(interfaces, options);
std::printf("%zu event loops on %.*s\n", server.event_loops(), int(uc::io_backend_name(server.backend()).size()),
            uc::io_backend_name(server.backend()).data());

uc::status_t const listed = server.get<list_files>("/users/{user}/files/{*path}");
uc::status_t const fallback = server.route<not_served>("/anything", ucall_verb_any_k);
```

Routes register before any loop is polled, with `route` taking any verb and `get`, `post`, `put`, `delete_` and `patch` naming one; `delete_` carries an underscore, as `delete` is a keyword.
A handler is a `noexcept` function taking `request_t` by value, named as a template argument, as in `server.get<greet>(path)`; a member function named the same way with its object, as in `server.post<&service_t::echo>(path, service)`; or a callable with state, such as a lambda with captures, passed as an argument.
The server refers to a member's object or a callable, which the caller keeps until the server is destroyed, and keeps no record of a route; log sinks and peer authorizers are callables the caller keeps alike.
Every polling loop may run a route at once, so a callable, a log sink and a peer authorizer are called through a const call operator, and a member's object must be safe to call from several threads, like an internally synchronized store.
Templates capture `{name}` segments and a greedy `{*name}` tail, literal segments match before captures, and registering one template and verb twice fails with `status_code_t::already_exists_k`.
Routing is exact: an empty segment is a segment, so `/users` and `/users/` are different paths.
A path no route matches answers 404, one whose routes take other verbs answers 405 with an `allow` header, a GET route also serves HEAD, and `OPTIONS` answers 204 with the same `allow` list.

Log lines reach the handler on whichever thread produced them, and StatsD datagrams carry each loop's counters and sampled request latencies, every second unless `metrics_interval` says otherwise.
`server_t::event_loop_statistics` copies one loop's counters, from any thread while the loop runs; divided by `requests`, they price one call.

## Requests

A handler receives each `request_t` by value, owning it.
Its reads view the received bytes: `verb`, `path`, `query_string`, `path_parameter`, `query`, `header` and `body`, with `peer` naming the interface it arrived on, the client's authenticated Noise key and its socket address.
Every read that can fail answers an `expected`, so a missing header answers `status_code_t::not_found_k` and a body read on a streamed route `status_code_t::invalid_argument_k`, while the counts answer plain numbers.
The path and query values stay percent-encoded as sent, which `uc::decode_percent` decodes, header names match case-insensitively, and the body arrives whole, decoded from chunked framing if it was sent that way.
`fields_count` and `field` read every header field in arrival order, names lowercased and values trimmed, as a proxy forwards a head.
`path_segments_count` and `path_segment` read the path component by component, and `parts_count` and `part` read a `multipart/form-data` body as `request_part_t`s.

```cpp
void order(uc::request_t request) noexcept {
    auto [token, token_status] = request.header("authorization");
    if (token_status.failed()) {
        [[maybe_unused]] uc::status_t const refused =
            std::move(request).reply_error(ucall_http_status_unauthorized_k, "sign in first");
        return;
    }
    auto [order_id, order_status] = request.path_parameter("order");
    ucall_bytes_view_t const headers[] {uc::bytes_view("content-type: text/plain"),
                                        uc::bytes_view("cache-control: no-store")};
    ucall_reply_part_t const parts[] {uc::bytes_part(order_id), uc::bytes_part(" by "), uc::bytes_part(token)};
    uc::deferred<> sent;
    [[maybe_unused]] uc::status_t const replied =
        std::move(request).reply_parts(ucall_http_status_created_k, headers, parts, sent);
}
```

`reply`, `reply_error`, `reply_parts` and `reply_stream` take the request, spelled `std::move(request).reply(...)`, and Content-Length, Date and Server are generated.
A reply copies the bytes it sends before it returns, so a body made of the request's bytes needs no copy of its own.
A request moves to any thread, so a handler may hand it to a worker and return, and the worker replies whenever it is done.
A request destroyed without a reply answers 500.
The library clears the request's handle once a reply took it, a closed connection included, which reports `status_code_t::connection_closed_k`; a reply it refused keeps the handle, and destroying the request then answers 500.

## Files & Streams

Handlers run on the polling thread, so a reply or a pull that finishes later runs in a `deferred` slot the caller keeps, which the polling thread finishes as it keeps polling.
Await it on the polling thread through a scheduler, or wait on it from another thread; waiting on the polling thread itself never ends.
A verb taking a slot answers a refusal at once, or success while the call runs, and the slot reports the final status.
A slot is reused for the next call, waiting first only if its previous call still runs, so a server keeps a ring of slots rather than one per request.

| Verb                                        | Returns                    | Final when                     |
| :------------------------------------------ | :------------------------- | :----------------------------- |
| `reply_parts(status, headers, parts, into)` | `status_t`                 | every part is sent             |
| `reply_stream(status, headers)`             | `expected<reply_stream_t>` | `end()` answers a `deferred<>` |
| `body_chunk(into)`                          | `status_t`                 | the next bytes arrived         |

A scheduler is any type with `post(void (*poll)(void*) noexcept, void* state)`, which runs `poll(state)` later on its own loop and stores those two words, so awaiting allocates nothing in the binding.

### Serving a File

```cpp
task_t send_video(uc::request_t request, loop_t& loop) {
    auto [name, name_status] = request.path_parameter("name");
    ucall_reply_part_t const parts[] {uc::path_part({.directory_index = 0, .relative_path = uc::bytes_view(name)})};
    uc::deferred<> sent;
    if (std::move(request).reply_parts(ucall_http_status_ok_k, {}, parts, sent).failed()) co_return;
    uc::status_t const sent_status = co_await sent.wait(loop); // or: sent.wait()
}

ucall_bytes_view_t const directories[] {uc::bytes_view("/srv/videos")};
uc::interface_t const interfaces[] {{.address = "0.0.0.0:8080", .reply_directories = directories}};
auto [server, server_status] = uc::server_t::make(interfaces);
auto serve = [&loop](uc::request_t request) noexcept { send_video(std::move(request), loop); };
uc::status_t const routed = server.get("/videos/{name}", serve); // the caller keeps `serve` until the server is destroyed
for (;;) {
    uc::status_t const polled = server.take_call(0, std::chrono::milliseconds(1));
    if (polled == uc::status_code_t::connection_closed_k) break;
    loop.run();
}
```

`reply_parts` concatenates `bytes_part`, `path_part` and `file_part` parts into one body whose Content-Length is measured from the files.
A path part resolves beneath the interface's `reply_directories`, refusing absolute paths, `..` and links leading out, and a file part names the caller's unbuffered descriptor until the reply is final, while bytes and paths are copied before the call returns.
A missing, unreadable or too short file replaces the reply with 404, 416 or 500 before its head leaves, and the awaited status reports the cause.
`deferred::status` polls, `deferred::wait()` blocks, `co_await deferred.wait(loop)` re-polls through the loop between other tasks, and a `deferred` waits as it is destroyed, so the coroutine frame, the stack or the ring holding it must outlive the call.

### Streaming a Reply

```cpp
uc::status_t send_rows(uc::request_t request, std::span<std::string_view const> rows) noexcept {
    ucall_bytes_view_t const headers[] {uc::bytes_view("content-type: text/csv")};
    auto [stream, stream_status] = std::move(request).reply_stream(ucall_http_status_ok_k, headers);
    if (stream_status.failed()) return stream_status;
    for (std::string_view row : rows) {
        ucall_reply_part_t const parts[] {uc::bytes_part(row)};
        if (uc::status_t const appended = stream.append(parts); appended.failed()) return appended;
    }
    return std::move(stream).end().wait();
}
```

The stream is chunked unless a Content-Length header declares the length, `append` refuses with `status_code_t::would_block_k`, queueing nothing, while the peer lags behind, and destroying an unended stream ends it.

### Streaming an Upload

```cpp
task_t store(uc::request_t request, loop_t& loop) {
    std::size_t received_bytes = 0;
    uc::deferred<std::string_view> pulled;
    for (;;) {
        if (request.body_chunk(pulled).failed()) break;
        auto [chunk, chunk_status] = co_await pulled.wait(loop); // or: pulled.wait()
        if (chunk_status.failed() || chunk.empty()) break;
        received_bytes += chunk.size();
    }
    std::array<char, 24> total {};
    int const length = std::snprintf(total.data(), total.size(), "%zu", received_bytes);
    ucall_reply_part_t const parts[] {uc::bytes_part({total.data(), std::size_t(length)})};
    uc::deferred<> sent;
    if (std::move(request).reply_parts(ucall_http_status_ok_k, {}, parts, sent).failed()) co_return;
    uc::status_t const replied = co_await sent.wait(loop);
}
```

A route registered with `ucall_body_delivery_streamed_k` runs its handler once the headers arrive, and each `body_chunk` takes the bytes decoded since the last pull, valid until the next one.
A pull from another thread blocks in `wait()` until the bytes arrive; on the polling thread a pull with nothing decoded answers `status_code_t::would_block_k` instead, as nothing arrives while it runs.

## Batches

A batch endpoint gathers matching requests from every event loop into one queue and hands them to its handler in batches, which suits work that is cheaper per request in bulk, like GPU inference.

```cpp
void infer(uc::batch_t batch) noexcept {
    for (uc::request_t request : batch) {
        auto [body, body_status] = request.body();
        std::array<char, 24> score {};
        int const length = std::snprintf(score.data(), score.size(), "%zu", body.size());
        [[maybe_unused]] uc::status_t const replied =
            std::move(request).reply(ucall_http_status_ok_k, {}, {score.data(), std::size_t(length)});
    }
}

uc::interface_t const interfaces[] {{.address = "127.0.0.1:0", .max_pipelined_requests = 8}};
auto [server, server_status] = uc::server_t::make(interfaces);
uc::batching_t const batching {.min_batch_size = 16, .max_batch_size = 64, .max_latency = std::chrono::milliseconds(2)};
auto [endpoint, endpoint_status] = server.batch<infer>("/infer", ucall_verb_post_k, batching);
std::thread polling([&server] { [[maybe_unused]] uc::status_t const polled = server.take_calls(0); });
std::thread batching_thread([&endpoint] { [[maybe_unused]] uc::status_t const taken = endpoint.take_batches(); });
```

`batching_t` dispatches as soon as `min_batch_size` requests wait, never more than `max_batch_size` at once, and a smaller batch once its oldest request waited `max_latency`; zero fields mean 1, 32 and 10 milliseconds.
The handler runs on the thread polling the endpoint through `take_batch` or `take_batches`, never on an event loop, so a slow batch never stalls the network.
A `batch_t` holds its requests in arrival order: `take(index)` hands one over, and iterating it hands over each in turn, once, answering 500 for one passed without being taken.
A request never taken stays unanswered until the server is destroyed, so take every one; a taken request answers 500 if it is destroyed unreplied.
The queue holds as many requests as the interfaces admit at once, connections times pipelined requests, and refuses more with 503.
`batch_endpoint_t::statistics` counts batches and requests, and whether each was dispatched on reaching the maximum size, the minimum size, or the latency.

## Calling

A `client_t` submits calls without driving the network, and polls to drive them and collect what finished.
It holds up to `max_concurrent_connections` connections, reusing them across calls, and carries up to `max_pipelined_calls` calls on each.

```cpp
auto [client, client_status] = uc::client_t::make({.max_concurrent_connections = 4, .max_pipelined_calls = 16});
std::array<std::uint64_t, 64> contexts {};
std::array<char, 64> bodies {};
for (std::size_t index = 0; index != contexts.size(); ++index) {
    contexts[index] = index, bodies[index] = char(index);
    uc::client_call_t const call {.verb = ucall_verb_post_k, .url = "http://127.0.0.1:8545/infer",
                                  .body = {&bodies[index], 1}};
    uc::status_t const submitted = client.submit(call, &contexts[index]);
}
std::array<ucall_completed_call_t, 16> storage {};
for (std::size_t remaining = contexts.size(); remaining != 0;) {
    auto [finished, finished_status] = client.take_completed(storage, std::chrono::seconds(1));
    for (uc::completed_t done : finished) {
        auto [response, response_status] = std::move(done.response);
        std::printf("call %llu answered %u\n", *static_cast<unsigned long long*>(done.context),
                    response_status.failed() ? 0u : unsigned(response.status_code()));
    }
    remaining -= finished.size();
}

auto [health, health_status] = client.get("http://127.0.0.1:8545/health");
auto [cache_control, cache_control_status] = health.header("cache-control");
```

`submit` takes a `client_call_t`, whose URL, header lines and body the caller keeps until the call completes, and tags it with a `void*` context.
A call admitted once completes exactly once, and a client already holding its call budget of unretrieved calls refuses more with `status_code_t::contended_k`.
`take_completed` drives every admitted call and fills the front of the storage the caller passes with finished ones, waiting up to its timeout for the first, and a zero timeout performs one nonblocking round.
It answers a `completed_view_t`, which hands each `completed_t` over once by `take` or by iterating and frees the responses never taken.
`get`, `post`, `put`, `delete_`, `patch` and `call` submit one call and wait for it alone, while the library keeps the completions of other calls queued for the next `take_completed`.
`client_call_t::options` carries the call's own `client_call_options_t`: a timeout in place of the client's, retries, redirect hops, security, and the client and server keys.

Every received response is a `response_t`, whatever its HTTP status, and only a failed exchange is a failed status.
A `response_t` owns its received bytes, frees them when destroyed, stays readable after its `client_t` is destroyed and may move to another thread.
Destroying the client cancels the calls still in flight and discards completions not yet retrieved.

### Streamed Response Bodies

```cpp
uc::client_call_t const call {.url = "http://127.0.0.1:8545/dataset.bin",
                              .options = {.body_delivery = ucall_body_delivery_streamed_k}};
auto [response, response_status] = client.call(call);
std::size_t received_bytes = 0;
for (;;) {
    auto [chunk, chunk_status] = response.body_chunk();
    if (chunk_status == uc::status_code_t::would_block_k) {
        auto [advanced, advanced_status] = client.take_completed({}, std::chrono::milliseconds(1));
        continue;
    }
    if (chunk_status.failed() || chunk.empty()) break;
    received_bytes += chunk.size();
}
```

A call whose `body_delivery` is `ucall_body_delivery_streamed_k` completes once its head arrived, so a download larger than `max_response_bytes` is pulled through `response_t::body_chunk` as it lands, while `response_t::body` reads empty.
A pull never waits: with nothing decoded yet it answers `status_code_t::would_block_k`, and an empty `take_completed` advances the client, moving the next bytes in.
Every streamed response is pulled to its end or destroyed, as its connection carries no other call meanwhile; destroying it early closes that connection and fails the calls pipelined behind it.

## Noise Keys

Interfaces and calls can run over the Noise protocol instead of plain TCP, authenticating both sides by 32-byte Curve25519 static keys.

```cpp
auto [server_keys, server_keys_status] = uc::noise_key_generate();
auto [client_keys, client_keys_status] = uc::noise_key_generate();

auto admit_client = [&client_keys](ucall_noise_key_t const& key) noexcept {
    return uc::noise_keys_equal(key, client_keys.public_key);
};
uc::interface_t const interfaces[] {{.address = "0.0.0.0:8546",
                                     .security = ucall_security_noise_xx_k,
                                     .noise_private_key = &server_keys.private_key,
                                     .peer_authorizer = admit_client}};
auto [server, server_status] = uc::server_t::make(interfaces);

auto admit_server = [&server_keys](ucall_noise_key_t const& key) noexcept {
    return uc::noise_keys_equal(key, server_keys.public_key);
};
auto [client, client_status] = uc::client_t::make(
    {.max_concurrent_connections = 1, .noise_private_key = &client_keys.private_key, .peer_authorizer = admit_server});
```

`noise_key_generate` draws from the operating system's entropy and fails with `status_code_t::io_k` when it is refused.
`noise_key_derive` recovers the public half of a stored private key, which peers compare in their authorizers.
Under Noise XX both sides learn each other's key during the handshake, so both need an authorizer; Noise IK has the client name the server's key in advance through `client_call_options_t::noise_peer_key`.
Noise KK has both sides know each other in advance: the interface admits the one key `interface_t::noise_peer_key` names, and the call presents its own key or the client's.
An `http+noise://` URL implies Noise XX, and a handler reads the client's authenticated key through `request_t::peer`.

## Errors

Every fallible verb answers a `status_t`, or an `expected<T>`, a plain pair of a value and its `status_t` unpacked as `auto [value, status]`, whose value is default-constructed on failure.
A `status_t` carries a `status_code_t` and an optional static `note` beside it, so nothing allocates on the failure path, and `status == status_code_t::timeout_k` compares the code.
Recovery branches on the code, while the note names the broken step or resource for logs, falling back to the status name.
A mistake the binding catches before calling the library, like asking for an interface the server lacks, reports the status the library would have used.

```cpp
auto [client, client_status] = uc::client_t::make({.max_concurrent_connections = 1});
auto [response, status] = client.get("http://127.0.0.1:1/");
if (status == uc::status_code_t::connection_failed_k) fmt::println(stderr, "nobody listens: {}", status.note);

```

A submitted call that fails completes with a failed `completed_t::response`: `connection_failed_k`, `connection_closed_k`, `timeout_k`, `handshake_failed_k` or `peer_rejected_k`.
HTTP error statuses are ordinary responses.
`status_name`, `io_backend_name` and `cpu_class_name` spell stable names, like "linux-uring618" and "intel-icelake", and their `_from_name` twins parse them back, failing with `status_code_t::invalid_argument_k` on a name no value has.
`version_name()` spells the linked library's version, candidate suffix included, and `decode_percent` decodes a path or a query value, which requests hold still percent-encoded.

## Threads & Polling

The interface starts no threads and needs no runtime: every callback runs on a thread the application gave to a polling call.

- A route handler runs on the thread inside `take_call` or `take_calls` for the event loop that received the request.
- A batch handler runs on the thread inside `take_batch` or `take_batches` for its endpoint, never on an event loop.
- A server's peer authorizer runs on the polling thread completing the handshake, and a client's on the client's own thread inside `take_completed` or a blocking call.
- A deferred reply or pull finishes as its event loop polls, so its awaiter re-polls through the caller's scheduler on that same thread.

Each event loop and each batch endpoint has one polling owner at a time.
`take_calls` and `take_batches` run until `server_t::stop`, while `take_call` and `take_batch` return after one round, waiting up to their timeout, so a loop of them interleaves polling with other work, such as a scheduler's posted polls.
`server_t::stop` works from any thread, handlers included, and wakes every polling thread.
The first stop drains, answering every request already held before its connection closes, and a second one cuts the replies still in flight.
A client bound to a server through `client_options_t::server` advances only as that loop polls, so it is used on that loop's thread, and its blocking calls would wait forever there.
Every thread that polls, replies or reads must run on a CPU supporting the CPU class the server or client resolved at start, so `ucall_cpu_class_serial_k` is the safe choice on machines mixing CPU generations.

## Design

The interface is a thin layer over UCall's native library, and every rule below follows from that.

- __Verbs share one name across languages.__
  `take_call`, `take_calls`, `take_batch`, `take_batches`, `submit` and `take_completed` name the same calls in C++, Go, Python and Rust.
- __Blocking stays simple, deferring stays symmetric.__
  A reply that is final on return answers a `status_t`, and one that may finish later answers a `deferred` that `wait`s, is awaited through `co_await call.wait(loop)`, or waits as it is destroyed, as Rust's `Deferred` does when dropped.
- __Ownership is a type, not a flag.__
  A reply takes its `request_t`, a destroyed request answers 500, a `response_t` frees itself, and a `deferred` never moves, so the stack or the coroutine frame holding it outlives the call.
- __Handlers stay the caller's, never boxed.__
  A function or a member is a template argument and an object or a callable with state stays the caller's until the server or client is destroyed, so registration copies no closure, and every handler is `noexcept`, as no fault can unwind through the library.
- __Polling allocates nothing.__
  Blocking verbs keep their outcome on the stack, a deferred call keeps it inside itself, and an awaiter posts two words, a function and its own address, into the caller's scheduler, as Rust's waker does.
  A server and a client hold their handles alone: the library hands each callback its server, and a blocking call takes its own completion out of the library's queue.
- __No life of its own.__
  The interface starts no threads, keeps no global state and needs no runtime, so it drops into any threading model.

| Path                       | Rust          | C++                                   |
| :------------------------- | :------------ | :------------------------------------ |
| Blocking verb              | 0             | 0                                     |
| Each handler call          | 0             | 0                                     |
| Deferred reply or pull     | 0             | 0, the `deferred` lives in the caller |
| Await                      | 0             | 0 in the binding                      |
| Route registration         | 1 `Box`       | 0                                     |
| Client start               | call tables   | 0                                     |
