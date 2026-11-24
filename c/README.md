# UCall for C

Include `ucall/ucall.h` for the whole interface, or include `types.h`, `client.h`, and `server.h` separately beneath `ucall/`.
Every operation that can fail takes its named argument struct and writes a `ucall_outcome_t`.
Getters that cannot fail and handle release functions take their arguments directly.
The [Python](../python/README.md) and [Rust](../rust/README.md) bindings wrap this ABI and keep its polling model: the application starts every thread.

## Installation

Link `ucall::static` or `ucall::shared`, each a single library containing every enabled backend.
An installed tree or the SDK archive finds them through `find_package(ucall)`, and the shared library through `pkg-config --libs ucall` too.

```sh
cmake -B build -D UCALL_BUILD_TEST=ON -D UCALL_BUILD_EXAMPLES=ON && cmake --build build
build/ucall_test_c && build/ucall_example_hello
```

## Quickstart

A server on a free loopback port greets whoever `GET /hello/{name}` names, and a client bound to the server's event loop calls `/hello/world` on the same thread.
Each `ucall_server_take_call()` round advances both, until the completion arrives.
The program prints the body and exits nonzero unless it reads "Hello, world"; it is [`examples/hello.c`](../examples/hello.c).

```c
#include <stdio.h>
#include <string.h>

#include "ucall/ucall.h"

static int failed(ucall_outcome_t const* outcome) {
    if (outcome->status == ucall_status_success_k) return 0;
    fprintf(stderr, "%s: %s\n", ucall_status_name(outcome->status), outcome->message);
    return 1;
}

static void hello(ucall_server_t server, ucall_received_http_request_t request, void* context) {
    char const* greeting = (char const*)context;
    ucall_outcome_t outcome = {0};
    ucall_bytes_view_t name = {0};
    ucall_server_request_path_parameter_t parameter = {.server = server,
                                                       .outcome = &outcome,
                                                       .request = request,
                                                       .name = {(ucall_byte_t const*)"name", 4},
                                                       .value = &name};
    ucall_server_request_path_parameter(&parameter);
    ucall_reply_part_t parts[2] = {
        {.kind = ucall_reply_part_bytes_k, .data.bytes = {(ucall_byte_t const*)greeting, strlen(greeting)}},
        {.kind = ucall_reply_part_bytes_k, .data.bytes = name}};
    ucall_server_reply_vectored_t reply = {.server = server,
                                           .outcome = &outcome,
                                           .request = &request,
                                           .parts = parts,
                                           .parts_count = 2};
    ucall_server_reply_vectored(&reply);
}

static char greeting[] = "Hello, ";

int main(void) {
    ucall_network_interface_t listener = {.address = {(ucall_byte_t const*)"127.0.0.1:0", 11},
                                          .max_concurrent_connections = 1};
    ucall_server_options_t options = {.interfaces = &listener, .interfaces_count = 1}, resolved = {0};
    ucall_server_t server = NULL;
    ucall_outcome_t outcome = {0};
    ucall_server_init_t init = {.server = &server, .outcome = &outcome, .options = &options, .resolved = &resolved};
    ucall_server_init(&init);
    if (failed(&outcome)) return 1;
    ucall_server_add_http_endpoint_t route = {.server = server,
                                              .outcome = &outcome,
                                              .uri_template = {(ucall_byte_t const*)"/hello/{name}", 13},
                                              .verb = ucall_verb_get_k,
                                              .callback = hello,
                                              .context = greeting};
    ucall_server_add_http_endpoint(&route);
    if (failed(&outcome)) return 1;

    // A client bound to the server's event loop advances whenever that loop is polled.
    ucall_client_options_t client_options = {.max_concurrent_connections = 1, .server = server};
    ucall_client_t client = NULL;
    ucall_client_init_t client_init = {.client = &client, .outcome = &outcome, .options = &client_options};
    ucall_client_init(&client_init);
    if (failed(&outcome)) return 1;
    char url[128];
    ucall_bytes_view_t address = resolved.interfaces[0].address;
    snprintf(url, sizeof url, "http://%.*s/hello/world", (int)address.length, (char const*)address.data);
    ucall_client_call_t call = {.client = client,
                                .outcome = &outcome,
                                .url = {(ucall_byte_t const*)url, strlen(url)},
                                .verb = ucall_verb_get_k};
    ucall_client_call(&call);
    if (failed(&outcome)) return 1;

    ucall_completed_call_t completed = {0};
    ucall_server_take_call_t poll = {.server = server, .outcome = &outcome, .timeout_microseconds = 1000};
    ucall_client_take_completed_call_t take = {.client = client, .outcome = &outcome, .call = &completed};
    do {
        ucall_server_take_call(&poll);
        if (failed(&outcome)) return 1;
        ucall_client_take_completed_call(&take);
    } while (outcome.status == ucall_status_would_block_k);
    if (failed(&outcome) || failed(&completed.outcome)) return 1;
    ucall_bytes_view_t body = {0};
    ucall_client_response_body_t body_read = {.response = completed.response, .outcome = &outcome, .body = &body};
    ucall_client_response_body(&body_read);
    printf("%.*s\n", (int)body.length, (char const*)body.data);
    int greeted = body.length == 12 && memcmp(body.data, "Hello, world", 12) == 0;

    ucall_client_response_free(completed.response);
    ucall_client_free(client);
    ucall_server_stop(server);
    ucall_server_free(server);
    return greeted ? 0 : 1;
}
```

## Serving

Initialize the server and register routes before polling.
`ucall_server_take_call()` drives one loop with a bounded wait; zero timeout performs one nonblocking progress round.
`ucall_server_take_calls()` drives it continuously until `ucall_server_stop()` or failure.
An interface's `listen_descriptor` accepts on a listening socket the caller opened, such as one systemd passed in, instead of binding `address`; UCall accepts on duplicates and never closes it.
The resolved options fill each interface's `memory_domain` with the NUMA node the kernel ties its device to, or -1, so the application inits and polls from threads there; UCall places nothing by it.
Routing is exact: empty segments are segments and a trailing slash is significant.
A path no route takes answers 404, other verbs' routes answer 405 with `allow`, GET routes serve HEAD, `OPTIONS` answers 204 with `allow`, and `Expect: 100-continue` gets its interim response once the request is next and its body is wanted.
An interface at its connection budget evicts its least recently progressed idle keep-alive connection for a new peer.
A server interface's `max_pipelined_requests` bounds the requests one connection holds at once; zero means one, and replies leave in request order.
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
Every reply takes a pointer to the request handle and clears it once it took the request, on success, on connection closure, or with a reply left deferred, so a caller holding a non-null handle knows it still owes a reply.
All byte views have an explicit length, including empty and binary values.

## Files & Streams

A streamed reply opens with `ucall_server_reply_begin()`, takes any number of `ucall_server_reply_append()` calls, and closes with exactly one `ucall_server_reply_end()`:

```c
static void rows(ucall_server_t server, ucall_received_http_request_t request, void* context) {
    ucall_outcome_t outcome = {0};
    ucall_bytes_view_t headers[1] = {{(ucall_byte_t const*)"content-type: text/csv", 22}};
    ucall_server_reply_begin_t begin = {
        .server = server, .outcome = &outcome, .request = &request, .headers = headers, .headers_count = 1};
    ucall_server_reply_begin(&begin);
    if (outcome.status != ucall_status_success_k) return; // a closed connection already ended the reply
    for (int row = 0; row != 3 && outcome.status == ucall_status_success_k; ++row) {
        char line[32];
        int length = snprintf(line, sizeof line, "%d,%d\n", row, row * row);
        ucall_reply_part_t part = {.kind = ucall_reply_part_bytes_k,
                                   .data.bytes = {(ucall_byte_t const*)line, (size_t)length}};
        ucall_server_reply_append_t append = {
            .server = server, .outcome = &outcome, .request = request, .parts = &part, .parts_count = 1};
        ucall_server_reply_append(&append);
    }
    ucall_server_reply_end_t end = {.server = server, .outcome = &outcome, .request = &request};
    ucall_server_reply_end(&end);
}
```

The stream is chunked for HTTP/1.1 peers, keeps identity framing when its headers declare `Content-Length`, and is delimited by the close for HTTP/1.0 peers.
An append reports `ucall_status_would_block_k`, queueing nothing, while the socket lags too far behind; retry once the peer catches up.

Vectored replies and stream chunks take reply parts: bytes, a range of a file descriptor the caller keeps open until the outcome is final, or a range of a path opened beneath one of the interface's `reply_directories`.
A worker thread holding a retained request answers with a header and a file, while another thread polls the loop that sends it:

```c
ucall_outcome_t sent = {0}; // kept alive until it leaves ucall_status_deferred_k
ucall_reply_part_t parts[2] = {
    {.kind = ucall_reply_part_bytes_k, .data.bytes = {(ucall_byte_t const*)"frame:", 6}},
    {.kind = ucall_reply_part_path_k, .data.path = {.directory_index = 0, .relative_path = name}},
};
ucall_server_reply_vectored_t reply = {
    .server = server, .outcome = &sent, .request = &request, .parts = parts, .parts_count = 2};
ucall_server_reply_vectored(&reply);
if (ucall_outcome_wait(&sent) != ucall_status_success_k)
    fprintf(stderr, "%s: %s\n", ucall_status_name(sent.status), sent.message);
```

The event loop opens files with `O_DIRECT`, refusing caller descriptors without it, and reads aligned extents itself before sending the requested slice.
Paths are copied before the call returns, and empty or absolute paths, `..` components and any resolution leaving the directory are refused.
A reply with file or path parts publishes its outcome as `ucall_status_deferred_k`, then success once they are sent, or the cause; a refusal before the head becomes `404` or `416`, and a failure after it resets the connection.
Replies leave through zero-copy sends where the backend has them, so a connection closes only once the kernel let go of what it sent, and resets a peer that stops acknowledging by the linger deadline.

## Batches

Batch callbacks receive the server, a counted array of retained request handles, and the registered context, as request callbacks receive the server, one request and the context.
The array is valid only during the callback; copy its handles into application-owned storage to defer work without copying request bytes.
Every loop deposits into one queue per batch endpoint, so batches mix requests from all loops, and partial batches flush at their configured deadline.

The batch endpoint's polling owner can also manage the queues the batch feeds, with no thread of its own per queue.
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

`ucall_client_call()` submits without driving the network, and `ucall_client_take_completed()` drives every accepted call and retrieves a batch of finished ones:

```c
ucall_client_options_t options = {.max_concurrent_connections = 4, .max_pipelined_calls = 16};
ucall_client_t client = NULL;
ucall_outcome_t outcome = {0};
ucall_client_init_t init = {.client = &client, .outcome = &outcome, .options = &options};
ucall_client_init(&init);

static char const url[] = "http://127.0.0.1:8545/echo";
static ucall_byte_t const bodies[64] = {0};
size_t accepted = 0;
for (size_t index = 0; index != 64; ++index) {
    ucall_client_call_t call = {.client = client,
                                .outcome = &outcome,
                                .url = {(ucall_byte_t const*)url, sizeof url - 1},
                                .verb = ucall_verb_post_k,
                                .body = {bodies + index, 1},
                                .context = (void*)index};
    ucall_client_call(&call);
    accepted += outcome.status == ucall_status_success_k; // a refusal produces no completion
}

ucall_completed_call_t completed[16];
size_t count = 0;
ucall_client_take_completed_t take = {.client = client,
                                      .outcome = &outcome,
                                      .calls = completed,
                                      .capacity = 16,
                                      .count = &count,
                                      .timeout_microseconds = 1000000};
for (; accepted != 0; accepted -= count) {
    ucall_client_take_completed(&take);
    for (size_t index = 0; index != count; ++index) {
        ucall_completed_call_t* done = &completed[index];
        printf("call %zu: %s, HTTP %u\n", (size_t)done->context, ucall_status_name(done->outcome.status),
               (unsigned)ucall_client_response_status(done->response));
        ucall_client_response_free(done->response);
    }
}
ucall_client_free(client);
```

Success of `ucall_client_call()` guarantees exactly one completion, and refusal produces none.
`ucall_client_take_completed_call()` waits for the one call submitted with a given context, as a blocking call does, leaving every other completion queued for the next `ucall_client_take_completed()`.
Keep the URL, headers, body, and security-key inputs allocated and unchanged until completion retrieval, which also returns the call's admission credit.
The connection budget must be positive; a zero call budget uses the connection budget times `max_pipelined_calls`.
Retrieved responses belong to the caller until `ucall_client_response_free()`, and stay readable after the client is freed; client teardown discards unretrieved results.
A client whose `server` option names a server shares that server's event loop, as the Quickstart's does, and its `ucall_client_take_completed()` only pops what that loop finished.
HTTP calls support connection reuse, pipelining, chunked receive framing, redirects, and request deadlines.
A client's `max_pipelined_calls` bounds the calls one connection holds at once, and no call is pipelined behind one that is not idempotent or that sends `Connection: close`.
A pipelined connection lost mid-flight retries its unanswered idempotent calls and finishes the rest with `ucall_status_connection_closed_k`.
Calls a server left unread when it announced a close are sent again on a new connection.
Host names go through a built-in stub resolver driven by the client's own queue: `/etc/resolv.conf` with `search` and `ndots` and `/etc/hosts` on POSIX, the adapters' settings on Windows, AAAA and A over UDP with TCP on truncation, CNAME chains, and answers cached for their TTL.
Connections race the answered addresses as RFC 8305's Happy Eyeballs does.
`max_response_bytes` caps what a call buffers, failing with `ucall_status_overflow_k` past it, and the client's `log` reports failed dials, refused handshakes and refused redirects.

### Streamed Response Bodies

A call whose options set `body_delivery` to `ucall_body_delivery_streamed_k` completes once its head arrived, so a download larger than `max_response_bytes` is pulled through `ucall_client_response_body_chunk()` as it lands:

```c
ucall_bytes_view_t data = {0};
ucall_client_response_body_chunk_t pull = {
    .client = client, .outcome = &outcome, .response = completed[0].response, .data = &data};
size_t polled = 0;
ucall_client_take_completed_t advance = {.client = client, .outcome = &outcome, .count = &polled};
for (;;) {
    ucall_client_response_body_chunk(&pull);
    if (outcome.status == ucall_status_would_block_k) {
        ucall_client_take_completed(&advance); // moves the bytes, retrieving nothing
        continue;
    }
    if (outcome.status != ucall_status_success_k || !data.length) break; // a failure, or the end
    fwrite(data.data, 1, data.length, stdout);
}
ucall_client_response_free(completed[0].response);
```

Each pull hands every byte decoded since the last one, valid until the next pull or the response's free, and an empty view once the body ended; bytes decoded before a failure come out before it.
A pull never blocks: it runs on the client's owner thread, the one polling `ucall_client_take_completed()`, and answers `ucall_status_would_block_k` while nothing new arrived.
The connection reads on only once the previous bytes were pulled, so the cap bounds the head and each framing line rather than the body, and a body has no deadline once its head arrived.
A streamed body is a barrier: the connection takes no new call and answers none pipelined behind it until the body ended.
Redirects stay buffered so they can be followed, and a body already whole with its head, as with bodiless statuses, `HEAD` and small bodies, comes whole from the first pull, then the end.
`ucall_client_response_body()` refuses a streamed response with `ucall_status_invalid_argument_k`, and the pull refuses a buffered one the same way.
Bad chunk framing answers `ucall_status_malformed_k`, and a connection closing early `ucall_status_connection_closed_k`.
The response may be freed on any thread; freeing it before its body ended closes its connection and ends the calls pipelined behind it with `ucall_status_connection_closed_k`, never sending them again.
Freeing the client drops the unpulled bytes of a body still arriving, whose next pull answers `ucall_status_connection_closed_k`.

## Noise Keys

`ucall_noise_key_generate()` draws a static keypair from the operating system's entropy, reporting `ucall_status_io_k` when it is refused, and `ucall_noise_key_derive()` recovers the public key of a stored private key.
An XX interface and an XX client each vet the other's key through a `ucall_peer_authorizer_t`:

```c
static ucall_status_t admit(ucall_noise_key_t const* peer_static_key, void* expected_key) {
    return memcmp(*peer_static_key, expected_key, sizeof(ucall_noise_key_t)) == 0 ? ucall_status_success_k
                                                                                    : ucall_status_peer_rejected_k;
}

ucall_noise_key_t server_private_key, server_public_key, client_private_key, client_public_key;
ucall_outcome_t outcome = {0};
ucall_noise_key_generate_t server_keys = {
    .outcome = &outcome, .private_key = &server_private_key, .public_key = &server_public_key};
ucall_noise_key_generate(&server_keys);
ucall_noise_key_generate_t client_keys = {
    .outcome = &outcome, .private_key = &client_private_key, .public_key = &client_public_key};
ucall_noise_key_generate(&client_keys);
ucall_noise_key_derive_t derive = {.outcome = &outcome, .private_key = &server_private_key, .public_key = &server_public_key};
ucall_noise_key_derive(&derive); // what a restarted server does with its stored private key

ucall_network_interface_t sealed = {.address = {(ucall_byte_t const*)"0.0.0.0:8546", 12},
                                    .max_concurrent_connections = 1024,
                                    .security = ucall_security_noise_xx_k,
                                    .noise_private_key = &server_private_key,
                                    .peer_authorizer = admit,
                                    .peer_authorizer_context = client_public_key};
ucall_client_options_t client_options = {.max_concurrent_connections = 1,
                                         .noise_private_key = &client_private_key,
                                         .peer_authorizer = admit,
                                         .peer_authorizer_context = server_public_key};
```

The client calls `http+noise://` URLs, which imply Noise XX, and a handler reads the client's authenticated key through `ucall_server_request_peer()`.
IK clients name the server's key in advance through the call's `noise_peer_key`.
KK clients connect to a separately configured peer, and a KK server interface names its preknown initiator in `noise_peer_key`.
An authorizer returning any status but success refuses the peer, and that status becomes the connection's outcome.

## Errors

Every verb that can fail writes a `ucall_outcome_t`: a `ucall_status_t` to branch on, and a static `message` naming what broke, else the status's own name, never freed and `NULL` exactly on success.
Statuses 0 to 19 are numbered as in every Unum library, and 20 up are UCall's own, from `ucall_status_connection_failed_k` to `ucall_status_would_block_k`.
`ucall_status_name()` spells a status in lowercase with dashes, as in "already-exists", and `ucall_status_from_name()` reads it back.

```c
ucall_server_add_http_endpoint(&route);
if (outcome.status == ucall_status_already_exists_k)
    fprintf(stderr, "registered twice: %s\n", outcome.message);
else if (outcome.status != ucall_status_success_k)
    fprintf(stderr, "%s: %s\n", ucall_status_name(outcome.status), outcome.message);
```

A verb answers `ucall_status_uninitialized_k` for a `NULL` handle before it reads anything else, then checks its arguments and the state they meet, as each verb's documented statuses list them.
A refusal leaves the server, client and request as they were: a refused reply keeps its request, except one to a closed connection, and a refused call produces no completion.
A deferred outcome reads `ucall_status_deferred_k` until the event loop publishes its final status; poll it with `ucall_outcome_status()` or block with `ucall_outcome_wait()`, never by reading the field.
A completed client call has its own outcome, independent of the acceptance one, and HTTP error statuses are ordinary responses.

## Threads & Polling

UCall creates no threads.
Each loop has one application polling owner, and endpoint callbacks execute synchronously on that caller.
Each batch endpoint has one polling owner, and its callbacks execute on the thread calling `ucall_server_take_batch()` or `ucall_server_take_batches()` with the handle its registration returned.
A deadline cannot preempt a callback.
One owner at a time may submit, poll, or free a client, on any thread.
CPU classes select compiled string, cryptographic, and atomic kernels once, at initialization, under the `cpu_class_ceiling` intersected with the initialization thread's capabilities.
The application keeps those threads on CPUs supporting the picked class; `serial` is the conservative choice for differing capabilities.
Server shutdown uses baseline atomics and native wakeups, so another thread can stop it without entering CPU-specific code.

## Design

- __Backends.__
  Select `automatic`, `posix`, `linux-epollaio`, `linux-uring612`, `linux-uring618`, `bsd-kqueue`, `windows-iocp`, or `windows-rio` in the server or client configuration; explicit unavailable selections fail.
  All variants use the same HTTP/1.1 and Noise connection automata.
- __Zero-copy where the kernel offers it.__
  Both io_uring variants and `linux-epollaio` send without copying and read files unbuffered on the event loop, while `posix`, `kqueue` and IOCP send by copying.
- __One argument struct per verb.__
  Fields are named at the call site, zeroed fields take their documented defaults, and every fallible verb reports through the outcome its struct points at.
- __Bound clients.__
  A client made with a server's handle runs on that server's event loop, so one thread serves and calls without a second queue.
