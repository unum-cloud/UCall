/**
 *  @file c/ucall/server.h
 *  @author Ash Vardanian
 *  @date Feb 3, 2023
 *  @brief The server lifecycle and HTTP and WebSocket operations of the UCall C interface.
 */
#ifndef UNUM_UCALL_SERVER_H
#define UNUM_UCALL_SERVER_H

#include "ucall/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/** One virtualized network interface, and every policy applying to what arrives on it.
 *
 *  An interface is an address the server answers on, together with the security posture and
 *  admission limits for the connections it accepts. Several of them live under one server, which
 *  is what lets a single server answer VPN-internal Noise traffic and public plaintext at once,
 *  across as many physical devices as the machine has.
 *
 *  Encryption and admission live on the interface rather than on the server, so one server
 *  serves plaintext on loopback for health checks while requiring Noise on the wire - without
 *  standing up a second server to do it. */
typedef struct ucall_network_interface_t {

    /** Listening address in "host:port" form. Required. */
    char const* address;

    /** Physical device to pin this interface to with @c SO_BINDTODEVICE, such as "eth0", or @c
     *  NULL to bind by address alone.
     *
     *  Several interfaces may name one device, and one interface bound to @c 0.0.0.0 spans every
     *  device the machine has - which is why the two are separate fields rather than one. */
    char const* device_name;

    /**
     *  Encryption for connections accepted here. Default: ucall_security_mode_none_k.
     *  @note Server-side @c ucall_security_mode_noise_kk_k is rejected, since an interface cannot
     *      name the initiator static key that pattern hashes before the first message.
     */
    ucall_security_mode_t security_mode;

    /** Server identity for handshakes. Required when @c security_mode is not none. */
    ucall_noise_key_t const* noise_private_key;

    /** Vets client static keys. Required for XX. Default: NULL. */
    ucall_peer_authorizer_t peer_authorizer;

    /** Passed verbatim to @c peer_authorizer. */
    void* peer_authorizer_context;

    /**
     *  Event loops accepting on this interface. Zero uses one loop for an address, or the
     *  receive-queue count for a named Linux device, bounded by the connection budget.
     *
     *  Each loop has one application polling owner; UCall creates no threads.
     *  POSIX readiness backends and io_uring share one listen queue through a descriptor per loop.
     *  IOCP currently accepts one loop per interface because a socket belongs to one completion
     *  port; requesting more returns @c ucall_status_unsupported_k.
     *  @sa @c ucall_server_init_t::resolved reports the chosen counts.
     */
    size_t event_loops;

    /** Required open-connection budget across this interface's loops.
     *  Accept operations reserve this budget before submission; releasing a connection wakes
     *  the other loops to resume admission. The OS separately bounds the listen backlog and
     *  descriptor resources. Receive storage grows with the actual framed message. */
    size_t max_concurrent_connections;

    /** Requests one connection may have in flight before UCall stops reading from it; zero means
     *  one. Replies leave in request order. Batch rings hold @c max_concurrent_connections times
     *  this many requests. */
    size_t max_pipelined_requests;

} ucall_network_interface_t;

/**
 *  @brief Configuration parameters for the UCall server.
 *  @sa Initialize with @c ucall_server_init().
 */
typedef struct ucall_server_config_t {

    /** Interfaces to answer on. At least one is required.
     *
     *  Configuration and identity keys are copied during initialization. Callback contexts must
     *  outlive the server. Parallelism is the largest @c event_loops among the resolved
     *  interfaces, not this count. */
    ucall_network_interface_t const* interfaces;

    /** Entries in @c interfaces. At least one; zero fails with @c
     *  ucall_status_invalid_argument_k. */
    size_t interfaces_count;

    /** Where log lines go. Default: nowhere. */
    ucall_log_t log;

    /** StatsD UDP endpoint "host:port". NULL = disabled. Default: NULL. */
    char const* metrics_address;

    /** Sampling rate [0.0, 1.0]. Default: 1.0. */
    float metrics_sample_rate;

    /** Metric name prefix. Default: "ucall". */
    char const* metrics_prefix;

    /** Global tags "key:val,key:val". Default: NULL. */
    char const* metrics_tags;

    /** Requested I/O backend; automatic chooses an available native backend. */
    ucall_io_backend_t backend;

    /** Requested CPU class; unknown selects from the initialization thread's capabilities.
     *  Callers must stay on compatible CPUs after first use. Serial is the conservative choice. */
    ucall_cpu_class_t cpu_class;

} ucall_server_config_t;

/** Arguments of @c ucall_server_init(). */
typedef struct ucall_server_init_t {

    /** Output for the new server. Free with @c ucall_server_free() at the end. */
    ucall_server_t* server;

    /** Synchronous initialization result. */
    ucall_outcome_t* outcome;

    /** Requested configuration. Zeroed fields take their documented defaults. */
    ucall_server_config_t const* config;

    /** Optional output for @c config with every default filled in, including each interface's @c
     *  event_loops. The arrays and strings it points at belong to the server until @c
     *  ucall_server_free(). */
    ucall_server_config_t* resolved;

} ucall_server_init_t;

/**
 *  @brief Initializes the server state.
 *  @note Call during setup only, before any loop is polled.
 */
UCALL_EXPORT void ucall_server_init(ucall_server_init_t* arguments);

/**
 *  @brief Frees the server state after its polling callers have returned. Does nothing for @c NULL.
 *  @param[in] server Server from @c ucall_server_init(), or @c NULL.
 *
 *  @note Stop and join polling threads, and finish application use of retained requests before
 *      teardown. Remaining request handles become invalid. Native I/O retirement can block.
 */
UCALL_EXPORT void ucall_server_free(ucall_server_t server);

/** Requests shutdown and wakes blocked polling and draining callers.
 *  Safe from an endpoint callback or a separate thread. */
UCALL_EXPORT void ucall_server_stop(ucall_server_t server);

/** Arguments of @c ucall_server_take_call(). */
typedef struct ucall_server_take_call_t {

    /** Initialized server whose routes are ready. */
    ucall_server_t server;

    /** Outcome of this polling round. */
    ucall_outcome_t* outcome;

    /** Zero-based loop index; each loop has one polling owner. */
    size_t event_loop_index;

    /** Maximum wait; zero performs one bounded nonblocking progress round. */
    size_t timeout_microseconds;

} ucall_server_take_call_t;

/** Advances one server loop and invokes ready callbacks on the calling thread.
 *  Callbacks run synchronously; the timeout cannot preempt them. */
UCALL_EXPORT void ucall_server_take_call(ucall_server_take_call_t* arguments);

/** Arguments of @c ucall_server_take_calls(). */
typedef struct ucall_server_take_calls_t {

    /** Initialized server whose routes are ready. */
    ucall_server_t server;

    /** Final outcome after polling stops or fails. */
    ucall_outcome_t* outcome;

    /** Zero-based loop index; each loop has one polling owner. */
    size_t event_loop_index;

} ucall_server_take_calls_t;

/** Drives one server loop until @c ucall_server_stop() or an I/O failure. */
UCALL_EXPORT void ucall_server_take_calls(ucall_server_take_calls_t* arguments);

/** Counters of one event loop since initialization; divided by @c requests, they price one call.
 *
 *  Only the loop's polling owner advances them. Byte counters cover the bytes UCall itself moves,
 *  never the copies the kernel makes between socket buffers and user memory. */
typedef struct ucall_event_loop_statistics_t {

    /** Engine polls the loop issued, each taking zero or more completions. */
    uint64_t polls;

    /** Engine polls that took no completion. */
    uint64_t empty_polls;

    /** System calls: io_uring enters, or other backends' waits, registrations and socket calls. */
    uint64_t kernel_enters;

    /** Operations queued: io_uring submission entries, or requests another backend accepted. */
    uint64_t submissions;

    /** Results taken: io_uring completion entries, or operations another backend finished. */
    uint64_t completions;

    /** Pending operations, or io_uring multishot receives, the engine asked to cancel. */
    uint64_t cancellations;

    /** Connections accepted and handed to this loop. */
    uint64_t accepts;

    /** HTTP requests parsed and dispatched to an endpoint or an error reply. */
    uint64_t requests;

    /** Multishot receives armed again on a socket that already streamed, only on io_uring 7.0. */
    uint64_t receive_rearms;

    /** Bytes the kernel reported received on this loop's connections, ciphertext under Noise. */
    uint64_t bytes_received;

    /** Bytes the kernel reported sent from this loop's connections, ciphertext under Noise. */
    uint64_t bytes_sent;

    /** Bytes UCall copied: receive appends, reply bodies, Noise records and parked receives. */
    uint64_t bytes_copied;

} ucall_event_loop_statistics_t;

/** Arguments of @c ucall_server_event_loop_statistics(). */
typedef struct ucall_server_event_loop_statistics_t {

    /** Initialized server. */
    ucall_server_t server;

    /** Receives @c ucall_status_invalid_argument_k for an index past the last loop. */
    ucall_outcome_t* outcome;

    /** Zero-based loop index. */
    size_t event_loop_index;

    /** Output for a snapshot of the loop's counters, zeroed on failure. */
    ucall_event_loop_statistics_t* statistics;

} ucall_server_event_loop_statistics_t;

/** Copies one loop's counters, from any thread whose CPU runs the server's CPU class.
 *  Each counter is read on its own, so a snapshot of a running loop is not one instant. */
UCALL_EXPORT void ucall_server_event_loop_statistics(ucall_server_event_loop_statistics_t* arguments);

/** Arguments of @c ucall_server_take_batch(). */
typedef struct ucall_server_take_batch_t {

    /** Initialized server that registered @c endpoint. */
    ucall_server_t server;

    /** Outcome of this draining round; @c ucall_status_invalid_argument_k for a NULL endpoint. */
    ucall_outcome_t* outcome;

    /** Endpoint from @c ucall_server_add_http_batch_endpoint(); each has one draining owner. */
    ucall_http_batch_endpoint_t endpoint;

    /** Maximum wait for a due batch; zero performs one nonblocking round. */
    size_t timeout_microseconds;

} ucall_server_take_batch_t;

/** Invokes one batch endpoint's callback if a batch is due, with requests from every event loop,
 *  on the calling thread. UCall creates no thread; a bounded wait sleeps until a deposit, the
 *  partial batch's deadline, or the timeout, without polling any event loop. */
UCALL_EXPORT void ucall_server_take_batch(ucall_server_take_batch_t* arguments);

/** Arguments of @c ucall_server_take_batches(). */
typedef struct ucall_server_take_batches_t {

    /** Initialized server that registered @c endpoint. */
    ucall_server_t server;

    /** Final outcome after draining stops; @c ucall_status_invalid_argument_k for a NULL
     *  endpoint. */
    ucall_outcome_t* outcome;

    /** Endpoint from @c ucall_server_add_http_batch_endpoint(); each has one draining owner. */
    ucall_http_batch_endpoint_t endpoint;

} ucall_server_take_batches_t;

/** Invokes one batch endpoint's due callbacks on the calling thread, sleeping in between, until
 *  @c ucall_server_stop(). Requests still queued then are released without a callback. */
UCALL_EXPORT void ucall_server_take_batches(ucall_server_take_batches_t* arguments);

/**
 *  @brief Callback type for handling incoming requests on the server side.
 *  @param[in] request Retained until a reply consumes it or the server is freed.
 *  @param[in] context User-supplied context pointer from the endpoint registration.
 */
typedef void (*ucall_received_http_request_callback_t)(ucall_received_http_request_t request, void* context);

/** Arguments of @c ucall_server_add_http_endpoint(). */
typedef struct ucall_server_add_http_endpoint_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Receives a failure for a duplicate endpoint, an invalid template, or a lack of memory. */
    ucall_outcome_t* outcome;

    /** URI template, with an explicit byte length. */
    ucall_bytes_view_t uri_template;

    /** HTTP method for this endpoint. */
    ucall_verb_t verb;

    /** Function pointer to the callback. */
    ucall_received_http_request_callback_t callback;

    /** Optional payload/tag for metadata (e.g., for CPython runtime). */
    void* context;

} ucall_server_add_http_endpoint_t;

/**
 *  @brief Registers a function callback to be triggered when a matching request arrives.
 *
 *  The @c uri_template field supports URI template syntax (RFC 6570 subset):
 *  - @c "/users/{id}" matches @c "/users/123" or @c "/users/abc"
 *  - @c "/posts/{year}/{month}" matches @c "/posts/2024/03"
 *  - @c "/files/{*path}" matches @c "/files/a/b/c.txt" (greedy, captures @c "a/b/c.txt")
 *
 *  Routing precedence: Literals match before template variables, before greedy wildcards.
 *
 *  @see RFC 6570 Section 3.2.2 for simple string expansion specification.
 *
 *  @note Call during setup only, before any loop is polled.
 */
UCALL_EXPORT void ucall_server_add_http_endpoint(ucall_server_add_http_endpoint_t* arguments);

/**
 *  @brief Callback type for handling batched requests on the server side.
 *  @param[in] requests Borrowed array of retained request handles; copy the handles to defer work.
 *  @param[in] count Number of requests in the array; always positive.
 *  @param[in] context User-defined context pointer.
 *  @note The array is valid only during the callback. Each request stays valid until a reply
 *      consumes it or the server is freed, independently of the array and the other requests.
 */
typedef void (*ucall_received_http_batch_callback_t)( //
    ucall_received_http_request_t const* requests, size_t count, void* context);

/** Arguments of @c ucall_server_add_http_batch_endpoint().
 *
 *  Batching improves throughput for high-latency operations (e.g., GPU inference) by
 *  accumulating multiple requests and processing them together. */
typedef struct ucall_server_add_http_batch_endpoint_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Receives a failure for a NULL @c endpoint, a duplicate endpoint, an invalid template, or a
     *  lack of memory. */
    ucall_outcome_t* outcome;

    /** URI template, with an explicit byte length. */
    ucall_bytes_view_t uri_template;

    /** HTTP method for this endpoint. */
    ucall_verb_t verb;

    /** Function pointer to the batch callback. */
    ucall_received_http_batch_callback_t callback;

    /** Optional payload/tag for metadata (e.g., for CPython runtime). */
    void* context;

    /** Optimal batch size. Dispatch immediately when reached. Default: 1. */
    size_t min_batch_size;

    /** Maximum requests per batch. Force dispatch when reached. Default: 32. */
    size_t max_batch_size;

    /** Maximum wait time for partial batches. Default: 10'000, i.e. 10 milliseconds. */
    size_t max_latency_microseconds;

    /** Receives the endpoint that @c ucall_server_take_batch() and @c ucall_server_take_batches()
     *  drain; required. */
    ucall_http_batch_endpoint_t* endpoint;

} ucall_server_add_http_batch_endpoint_t;

/**
 *  @brief Registers a batching callback to collect multiple requests and process them together.
 *      Very handy for batch-processing and high-latency operations (e.g., GPU inference).
 *
 *  This differs from JSON-RPC batching: here the server aggregates requests from different sources
 *  and dispatches them together, rather than the client batching into a JSON array.
 *
 *  Batching behavior:
 *  - Batch size < @c min_batch_size: Wait for more requests (up to @c max_latency_microseconds).
 *  - Batch size >= @c min_batch_size: Dispatch immediately (optimal utilization).
 *  - Batch size >= @c max_batch_size: Force dispatch (prevent unbounded growth).
 *
 *  Requests from every event loop share one queue per batch endpoint. The callback receives a
 *  counted array of request handles on the thread draining that endpoint through
 *  @c ucall_server_take_batch() or @c ucall_server_take_batches(), never on an event loop.
 *  Registration returns the endpoint's handle, so each endpoint can have its own draining thread.
 *  Copy the request handles into application-owned storage to process them later; received bytes
 *  need no copy.
 *
 *  @note Call during setup only, before any loop is polled.
 */
UCALL_EXPORT void ucall_server_add_http_batch_endpoint(ucall_server_add_http_batch_endpoint_t* arguments);

/** Arguments of @c ucall_server_add_websocket_endpoint(). */
typedef struct ucall_server_add_websocket_endpoint_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Receives a failure for a duplicate endpoint, an invalid template, or a lack of memory. */
    ucall_outcome_t* outcome;

    /** URI template, with an explicit byte length. */
    ucall_bytes_view_t uri_template;

    /** Function pointer to handle WebSocket events. */
    ucall_websocket_callback_t callback;

    /** Optional user-defined context pointer passed to all event callbacks. */
    void* context;

} ucall_server_add_websocket_endpoint_t;

/**
 *  @brief Registers a WebSocket endpoint to accept incoming connections.
 *
 *  On HTTP Upgrade request, establishes a WebSocket connection and invokes @c callback for all
 *  events (open, message, error, close) on the application polling caller.
 *
 *  @note Call during setup only, before any loop is polled.
 */
UCALL_EXPORT void ucall_server_add_websocket_endpoint(ucall_server_add_websocket_endpoint_t* arguments);

/**
 *  @brief Returns the HTTP method of the received request. Never @c ucall_verb_any_k.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request inside the @c ucall_received_http_request_callback_t.
 *
 *  Needed by endpoints registered with @c ucall_verb_any_k, which match every method.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @p request
 *      concurrently.
 */
UCALL_EXPORT ucall_verb_t ucall_server_request_verb(ucall_server_t server, ucall_received_http_request_t request);

/**
 *  @brief Returns the number of path components of the received request.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request inside the @c ucall_received_http_request_callback_t.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @p request
 *      concurrently.
 */
UCALL_EXPORT size_t ucall_server_request_path_segments_count(ucall_server_t server,
                                                             ucall_received_http_request_t request);

/** Arguments of @c ucall_server_request_path_segment(). */
typedef struct ucall_server_request_path_segment_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Receives @c ucall_status_not_found_k when @c index is past the last segment. */
    ucall_outcome_t* outcome;

    /** The received request inside the @c ucall_received_http_request_callback_t. */
    ucall_received_http_request_t request;

    /** The zero-based index of the path component to extract. */
    size_t index;

    /** Output for a borrowed view of the path component. */
    ucall_bytes_view_t* segment;

} ucall_server_request_path_segment_t;

/**
 *  @brief Extracts an indexed path component from the received request.
 *
 *  Useful for RESTful APIs with path parameters, e.g., "/users/{id}/posts/{postId}".
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_request_path_segment(ucall_server_request_path_segment_t* arguments);

/** Arguments of @c ucall_server_request_path_parameter(). */
typedef struct ucall_server_request_path_parameter_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Receives @c ucall_status_not_found_k when the template has no such placeholder. */
    ucall_outcome_t* outcome;

    /** The received request inside the @c ucall_received_http_request_callback_t. */
    ucall_received_http_request_t request;

    /** The @b case-sensitive placeholder name, without braces. */
    ucall_bytes_view_t name;

    /** Output for a borrowed view of the captured value. */
    ucall_bytes_view_t* value;

} ucall_server_request_path_parameter_t;

/**
 *  @brief Extracts a named path parameter captured by the endpoint's URI template.
 *
 *  For an endpoint registered as @c "/users/{id}/posts/{post_id}" receiving @c "/users/7/posts/3",
 *  a @c name of @c "id" yields @c "7". A greedy wildcard @c {*path} captures the remaining segments
 *  including separators.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_request_path_parameter(ucall_server_request_path_parameter_t* arguments);

/** Arguments of @c ucall_server_request_query_parameter(). */
typedef struct ucall_server_request_query_parameter_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Receives @c ucall_status_not_found_k when the query has no such parameter. */
    ucall_outcome_t* outcome;

    /** The received request inside the @c ucall_received_http_request_callback_t. */
    ucall_received_http_request_t request;

    /** The @b case-sensitive name of the parameter to extract. */
    ucall_bytes_view_t name;

    /** Output for a borrowed view of the parameter value. */
    ucall_bytes_view_t* value;

} ucall_server_request_query_parameter_t;

/**
 *  @brief Extracts the named string parameter from the received request.
 *
 *  Unlike HTTP headers, query parameters are case-sensitive by specification, but server-dependent
 *  in practice. An example would be ASP.NET / IIS, which treats "?id" and "?ID" as same parameters.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_request_query_parameter(ucall_server_request_query_parameter_t* arguments);

/** Arguments of @c ucall_server_request_header(). */
typedef struct ucall_server_request_header_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Receives @c ucall_status_not_found_k when the request has no such header. */
    ucall_outcome_t* outcome;

    /** The received request inside the @c ucall_received_http_request_callback_t. */
    ucall_received_http_request_t request;

    /** The name of the HTTP header to extract (case-insensitive). */
    ucall_bytes_view_t name;

    /** Output for a borrowed view of the header value. */
    ucall_bytes_view_t* value;

} ucall_server_request_header_t;

/**
 *  @brief Extracts the named string header from the received request.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_request_header(ucall_server_request_header_t* arguments);

/** Arguments of @c ucall_server_request_peer(). */
typedef struct ucall_server_request_peer_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome. */
    ucall_outcome_t* outcome;

    /** A request from any endpoint, plain or batch, until its reply. */
    ucall_received_http_request_t request;

    /** Output for the position of its interface in @c ucall_server_config_t::interfaces. */
    size_t* network_interface_index;

    /** Output for the peer's authenticated Noise static key; zeroed on plaintext interfaces. */
    ucall_noise_key_t* static_key;

} ucall_server_request_peer_t;

/**
 *  @brief Reports which interface a request arrived on and which authenticated key sent it.
 *
 *  Both facts are copied when the request is received, so they remain readable after its
 *  connection closes, as batched requests often outlive theirs.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_request_peer(ucall_server_request_peer_t* arguments);

/** Arguments of @c ucall_server_request_body(). */
typedef struct ucall_server_request_body_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** The received request inside the @c ucall_received_http_request_callback_t. */
    ucall_received_http_request_t request;

    /** Output for a borrowed view of the body. */
    ucall_bytes_view_t* body;

} ucall_server_request_body_t;

/**
 *  @brief Extracts the body content from the received request.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_request_body(ucall_server_request_body_t* arguments);

/** Arguments of @c ucall_server_request_body_chunk(). */
typedef struct ucall_server_request_body_chunk_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Receives @c ucall_status_would_block_k if more data is expected but none has arrived. */
    ucall_outcome_t* outcome;

    /** The received request inside the @c ucall_received_http_request_callback_t. */
    ucall_received_http_request_t request;

    /** Output for a borrowed view of the next body bytes, empty once the body is complete. */
    ucall_bytes_view_t* data;

} ucall_server_request_body_chunk_t;

/**
 *  @brief Pulls the next chunk of a request body that is still arriving.
 *
 *  Endpoints registered as streaming are invoked as soon as headers are parsed, before the body is
 *  complete. Without this, a multi-gigabyte upload must be buffered in full before the handler
 *  runs, which is both a memory hazard and a denial-of-service vector.
 *
 *  @warning The returned @c data is valid only until the next call on this @c request.
 *  @sa Use @c ucall_server_request_body() for endpoints that are not registered as streaming.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_request_body_chunk(ucall_server_request_body_chunk_t* arguments);

/**
 *  @brief Returns the number of parts in a @c multipart/form-data request body. Zero if it is not
 *      multipart.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request inside the @c ucall_received_http_request_callback_t.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @p request
 *      concurrently.
 */
UCALL_EXPORT size_t ucall_server_request_parts_count(ucall_server_t server, ucall_received_http_request_t request);

/** Arguments of @c ucall_server_request_part(). */
typedef struct ucall_server_request_part_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** The received request inside the @c ucall_received_http_request_callback_t. */
    ucall_received_http_request_t request;

    /** Zero-based index of the part, below @c ucall_server_request_parts_count(). */
    size_t index;

    /** Output for the part name from @c Content-Disposition. */
    ucall_bytes_view_t* name;

    /** Output for the part's @c Content-Type. Empty if absent. */
    ucall_bytes_view_t* content_type;

    /** Output for the part payload. Aliases the receive buffer, never copied. */
    ucall_bytes_view_t* data;

} ucall_server_request_part_t;

/**
 *  @brief Extracts one part of a @c multipart/form-data request body by index.
 *
 *  The payload is handed over without decoding. Media formats are the application's concern - pass
 *  @c data straight to an image or video decoder to keep the path copy-free.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_request_part(ucall_server_request_part_t* arguments);

/** Arguments of @c ucall_server_reply_content(). */
typedef struct ucall_server_reply_content_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** The received request to reply to. */
    ucall_received_http_request_t request;

    /** Every HTTP header line, each as a counted byte view. */
    ucall_bytes_view_t const* headers;

    /** Number of counted header lines. */
    size_t headers_count;

    /** Response body content. Can be NULL for empty body. */
    ucall_bytes_view_t body;

    /** Response status. Zero sends @c ucall_http_status_ok_k. */
    ucall_http_status_t http_status;

} ucall_server_reply_content_t;

/**
 *  @brief Sends an HTTP response with custom headers and body.
 *
 *  Automatically sets standard headers: @c Content-Length, @c Date, @c Server.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_reply_content(ucall_server_reply_content_t* arguments);

/** Arguments of @c ucall_server_reply_error(). */
typedef struct ucall_server_reply_error_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** The received request to reply to. */
    ucall_received_http_request_t request;

    /** HTTP error status code (400, 404, 500, etc.). */
    ucall_http_status_t http_status;

    /** Error message text. */
    ucall_bytes_view_t message;

} ucall_server_reply_error_t;

/**
 *  @brief Sends an error response with plain text message.
 *
 *  Automatically sets @c Content-Type: @c text/plain. For errors requiring custom headers, use @c
 *  ucall_server_reply_content() instead.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_reply_error(ucall_server_reply_error_t* arguments);

/** Arguments of @c ucall_server_reply_vectored(). */
typedef struct ucall_server_reply_vectored_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** The received request to reply to. */
    ucall_received_http_request_t request;

    /** Every HTTP header line, each as a counted byte view. */
    ucall_bytes_view_t const* headers;

    /** Number of counted header lines. */
    size_t headers_count;

    /** Array of buffers concatenated, in order, to form the body. */
    ucall_bytes_view_t const* parts;

    /** Number of entries in @c parts. */
    size_t parts_count;

} ucall_server_reply_vectored_t;

/**
 *  @brief Sends a response assembled from several non-contiguous buffers.
 *
 *  Lets a handler reply with a header, a tensor, and a trailer without concatenating them into a
 *  staging buffer first.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_reply_vectored(ucall_server_reply_vectored_t* arguments);

/** Arguments of @c ucall_server_reply_begin(). */
typedef struct ucall_server_reply_begin_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** The received request to reply to. */
    ucall_received_http_request_t request;

    /** HTTP status code for the response. */
    ucall_http_status_t http_status;

    /** Every HTTP header line, each as a counted byte view. */
    ucall_bytes_view_t const* headers;

    /** Number of counted header lines. */
    size_t headers_count;

} ucall_server_reply_begin_t;

/**
 *  @brief Begins a streamed response, emitting the status line and headers.
 *
 *  Must be followed by zero or more @c ucall_server_reply_chunk() calls and exactly one @c
 *  ucall_server_reply_end(). Supplying @c Content-Length switches to identity encoding, which is
 *  what @c Range responses need.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_reply_begin(ucall_server_reply_begin_t* arguments);

/** Arguments of @c ucall_server_reply_chunk(). */
typedef struct ucall_server_reply_chunk_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** The received request being replied to. */
    ucall_received_http_request_t request;

    /** Chunk payload. Copied before returning. */
    ucall_bytes_view_t data;

} ucall_server_reply_chunk_t;

/**
 *  @brief Appends one chunk to a response opened with @c ucall_server_reply_begin().
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_reply_chunk(ucall_server_reply_chunk_t* arguments);

/** Arguments of @c ucall_server_reply_end(). */
typedef struct ucall_server_reply_end_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** The received request being replied to. Invalid once the call returns. */
    ucall_received_http_request_t request;

} ucall_server_reply_end_t;

/**
 *  @brief Completes a response opened with @c ucall_server_reply_begin().
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_reply_end(ucall_server_reply_end_t* arguments);

/** Arguments of @c ucall_server_reply_file(). */
typedef struct ucall_server_reply_file_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** The received request to reply to. */
    ucall_received_http_request_t request;

    /** An open, readable, seekable descriptor. @b Ownership transfers to UCall. */
    int file_descriptor;

    /** Byte offset within the file at which to start. */
    uint64_t offset;

    /** Number of bytes to send. Zero sends through end of file. */
    uint64_t length;

} ucall_server_reply_file_t;

/**
 *  @brief Replies with a byte range of an open file, bypassing user space entirely.
 *
 *  On the @c io_uring backend this splices the file straight into the socket, so payload bytes
 *  never enter user space. UCall closes @c file_descriptor once the reply completes or fails,
 *  because the caller cannot otherwise know when the asynchronous send is done.
 *
 *  @warning Mutually exclusive with Noise. Encryption requires the payload in user space, so
 *      connections using @c ucall_security_noise_* fall back to a buffered copy.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_reply_file(ucall_server_reply_file_t* arguments);

/** Arguments of @c ucall_server_reply_path(). */
typedef struct ucall_server_reply_path_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** The received request to reply to. */
    ucall_received_http_request_t request;

    /** An open directory acting as the containment root. */
    int directory_descriptor;

    /** Path resolved beneath @c directory_descriptor. */
    ucall_bytes_view_t relative_path;

    /** Byte offset within the file at which to start. */
    uint64_t offset;

    /** Number of bytes to send. Zero sends through end of file. */
    uint64_t length;

} ucall_server_reply_path_t;

/**
 *  @brief Replies with a byte range of a file named relative to a directory descriptor.
 *
 *  Preferred over @c ucall_server_reply_file() on the @c io_uring backend, where the open, splice,
 *  and close are chained into one submission and the handler thread issues no syscalls. Resolution
 *  is confined beneath @c directory_descriptor, so a @c "../" in @c relative_path fails rather than
 *  escaping. UCall retains no reference to @c directory_descriptor.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_reply_path(ucall_server_reply_path_t* arguments);

/** Arguments of @c ucall_server_websocket_send(). */
typedef struct ucall_server_websocket_send_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** WebSocket connection handle from the callback. */
    ucall_websocket_t websocket;

    /** Message type (text, binary, ping, pong). */
    ucall_websocket_opcode_t opcode;

    /** Message payload. */
    ucall_bytes_view_t data;

} ucall_server_websocket_send_t;

/**
 *  @brief Sends a message to a connected WebSocket client.
 *
 *  Thread-safe, can be called from any thread including from within the callback itself.
 *
 *  @note @b Thread-safe.
 */
UCALL_EXPORT void ucall_server_websocket_send(ucall_server_websocket_send_t* arguments);

/** Arguments of @c ucall_server_websocket_close(). */
typedef struct ucall_server_websocket_close_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** WebSocket connection handle from the callback. Invalid once this call returns. */
    ucall_websocket_t websocket;

} ucall_server_websocket_close_t;

/**
 *  @brief Closes a WebSocket connection.
 *
 *  Thread-safe, can be called from any thread including from within the callback itself.
 *
 *  @note @b Thread-safe.
 */
UCALL_EXPORT void ucall_server_websocket_close(ucall_server_websocket_close_t* arguments);

#ifdef __cplusplus
}
#endif

#endif // UNUM_UCALL_SERVER_H
