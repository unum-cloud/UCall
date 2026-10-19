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
     *  How many event loops accept on this interface. Default: inferred from the hardware.
     *
     *  Zero means @c min(receive queues on @c device_name, physical cores on its memory domain).
     *  Physical, not logical: hyperthread siblings measure at roughly a third of a core each for
     *  this workload, not a full one.
     *
     *  The server creates the @b maximum across interfaces, never the sum, and clamps it to the
     *  machine's core count so threads cannot be oversubscribed. Two interfaces on two devices each
     *  asking for sixteen loops on a sixteen-core host therefore yield sixteen threads holding
     *  thirty-two listening sockets, not thirty-two threads. An interface asking for fewer loops
     *  than the server ends up with is served by the first that many; the rest never accept on it.
     *  Each participating loop gets its own socket in this address's @c SO_REUSEPORT group, so no
     *  listening socket is ever shared between threads.
     *
     *  @sa @c ucall_server_init_t::resolved reports what the server settled on.
     */
    size_t event_loops;

    /** Submission queue entries this interface needs, on each loop that serves it. Default: @c
     *  max_concurrent_connections.
     *
     *  A loop's ring is sized to the @b sum over the interfaces it serves, because one loop has
     *  one ring and must hold every outstanding operation across all of them. Sizing it here
     *  rather than server-wide is what lets an interface hosting thousands of connections ask
     *  for a deeper ring than one hosting a handful.
     *
     *  Meaningful only on backends built around a submission ring, and each imposes its own
     *  ceiling
     *  - Linux @c io_uring allows 32'768 entries and allocates a completion queue of twice that,
     *    so a sum exceeding it fails @c ucall_server_init() with @c
     *    ucall_status_connection_failed_k. Below @c max_concurrent_connections the ring merely
     *    flushes early, costing a system call per burst rather than failing, which is why the
     *    library raises it to that floor rather than refusing. Backends without a ring ignore
     *    this field. */
    size_t queue_depth;

    /**
     *  Connections this interface may hold open at once, so one cannot starve another. Default:
     *  1024.
     *
     *  The one independent size on this struct: @c queue_depth and the kernel's listen backlog are
     *  both derived from it unless overridden. Each connection costs one file descriptor and two
     *  pages of buffer, so 65'536 connections is roughly half a gigabyte of arena, and the
     *  descriptor total across every interface and event loop must stay under @c RLIMIT_NOFILE -
     *  commonly 1024 unraised, 1'048'576 tuned. Exhausting it does not fail the server; the
     *  interface simply stops accepting until a connection is released, and pending handshakes
     *  queue in the kernel's backlog behind it.
     *
     *  @note The backlog handed to @c listen() is this value, which the operating system then
     *      clamps to its own ceiling - @c net.core.somaxconn on Linux, 4096 on a modern kernel and
     *      128 on an old one. That clamp is silent rather than reported, and once the queue
     *      overflows a completed handshake is dropped and the client retransmits.
     */
    size_t max_concurrent_connections;

} ucall_network_interface_t;

/**
 *  @brief Configuration parameters for the UCall server.
 *  @sa Initialize with @c ucall_server_init().
 */
typedef struct ucall_server_config_t {

    /** Interfaces to answer on. At least one is required.
     *
     *  The array and every string it points at must outlive the server. Parallelism is the
     *  largest @c event_loops among the resolved interfaces, not this count. */
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

} ucall_server_config_t;

/** Arguments of @c ucall_server_init(). */
typedef struct ucall_server_init_t {

    /** Output for the new server. Free with @c ucall_server_free() at the end. */
    ucall_server_t* server;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
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
 *  @note Call during setup only, before any thread enters @c ucall_server_take_calls().
 */
UCALL_EXPORT void ucall_server_init(ucall_server_init_t* arguments);

/**
 *  @brief Frees the server state. Does nothing for @c NULL.
 *  @param[in] server Server from @c ucall_server_init(), or @c NULL.
 *
 *  @note Call during setup only, before any thread enters @c ucall_server_take_calls().
 */
UCALL_EXPORT void ucall_server_free(ucall_server_t server);

/**
 *  @brief Callback type for handling incoming requests on the server side.
 *  @param[in] request The received request handle.
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
 *  @note Call during setup only, before any thread enters @c ucall_server_take_calls().
 */
UCALL_EXPORT void ucall_server_add_http_endpoint(ucall_server_add_http_endpoint_t* arguments);

/**
 *  @brief Callback type for handling batched requests on the server side.
 *  @param[in] batch The batched request handle.
 *  @param[in] context User-defined context pointer.
 */
typedef void (*ucall_received_batch_http_request_callback_t)( //
    ucall_received_batch_http_request_t batch, void* context);

/** Arguments of @c ucall_server_add_batch_endpoint().
 *
 *  Batching improves throughput for high-latency operations (e.g., GPU inference) by
 *  accumulating multiple requests and processing them together. */
typedef struct ucall_server_add_batch_endpoint_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Receives a failure for a duplicate endpoint, an invalid template, or a lack of memory. */
    ucall_outcome_t* outcome;

    /** URI template, with an explicit byte length. */
    ucall_bytes_view_t uri_template;

    /** HTTP method for this endpoint. */
    ucall_verb_t verb;

    /** Function pointer to the batch callback. */
    ucall_received_batch_http_request_callback_t callback;

    /** Optional payload/tag for metadata (e.g., for CPython runtime). */
    void* context;

    /** Optimal batch size. Dispatch immediately when reached. Default: 1. */
    size_t min_batch_size;

    /** Maximum requests per batch. Force dispatch when reached. Default: 32. */
    size_t max_batch_size;

    /** Maximum wait time for partial batches. Default: 10'000, i.e. 10 milliseconds. */
    size_t max_latency_microseconds;

} ucall_server_add_batch_endpoint_t;

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
 *
 *  @sa To extract the number of calls in the batch - @c ucall_server_batch_size().
 *  @sa To enumerate separate calls from within the batch - @c ucall_server_batch_unpack().
 *
 *  @note Call during setup only, before any thread enters @c ucall_server_take_calls().
 */
UCALL_EXPORT void ucall_server_add_batch_endpoint(ucall_server_add_batch_endpoint_t* arguments);

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
 *  events (open, message, error, close) on a server worker thread.
 *
 *  @note Call during setup only, before any thread enters @c ucall_server_take_calls().
 */
UCALL_EXPORT void ucall_server_add_websocket_endpoint(ucall_server_add_websocket_endpoint_t* arguments);

/** Arguments of @c ucall_server_take_call. */
typedef struct ucall_server_take_call_t {

    /** The server whose connections are advanced. */
    ucall_server_t server;

    /** Output for the outcome of this poll. */
    ucall_outcome_t* outcome;

    /** The event loop reserved for this thread, below the largest resolved interface loop count. */
    size_t event_loop_index;

} ucall_server_take_call_t;

/** Advances one event loop through a blocking round of polling. Each loop has one owner thread;
 *  two threads must not advance the same loop concurrently. */
UCALL_EXPORT void ucall_server_take_call(ucall_server_take_call_t* arguments);

/** Arguments of @c ucall_server_take_calls. */
typedef struct ucall_server_take_calls_t {

    /** The server whose connections are advanced. */
    ucall_server_t server;

    /** Output for the outcome if the loop stops on a failure. */
    ucall_outcome_t* outcome;

    /** The event loop reserved for this thread, below the largest resolved interface loop count. */
    size_t event_loop_index;

} ucall_server_take_calls_t;

/** Advances one event loop continuously on its owner thread until an I/O failure stops it. */
UCALL_EXPORT void ucall_server_take_calls(ucall_server_take_calls_t* arguments);

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

    /** Output for a borrowed view of the chunk. Aliases the receive buffer. */
    ucall_bytes_view_t* chunk;

    /** Output flag, false once the final chunk has been delivered. */
    bool* has_more;

} ucall_server_request_body_chunk_t;

/**
 *  @brief Pulls the next chunk of a request body that is still arriving.
 *
 *  Endpoints registered as streaming are invoked as soon as headers are parsed, before the body is
 *  complete. Without this, a multi-gigabyte upload must be buffered in full before the handler
 *  runs, which is both a memory hazard and a denial-of-service vector.
 *
 *  @warning The returned @c chunk is valid only until the next call on this @c request.
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
UCALL_EXPORT size_t ucall_server_request_part_count(ucall_server_t server, ucall_received_http_request_t request);

/** Arguments of @c ucall_server_request_part_at(). */
typedef struct ucall_server_request_part_at_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** The received request inside the @c ucall_received_http_request_callback_t. */
    ucall_received_http_request_t request;

    /** Zero-based index of the part, below @c ucall_server_request_part_count(). */
    size_t index;

    /** Output for the part name from @c Content-Disposition. */
    ucall_bytes_view_t* name;

    /** Output for the part's @c Content-Type. Empty if absent. */
    ucall_bytes_view_t* content_type;

    /** Output for the part payload. Aliases the receive buffer, never copied. */
    ucall_bytes_view_t* data;

} ucall_server_request_part_at_t;

/**
 *  @brief Extracts one part of a @c multipart/form-data request body by index.
 *
 *  The payload is handed over without decoding. Media formats are the application's concern - pass
 *  @c data straight to an image or video decoder to keep the path copy-free.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_request_part_at(ucall_server_request_part_at_t* arguments);

/**
 *  @brief Returns the number of individual requests in a batch.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] batch Batch request handle from batch callback.
 *  @return Number of requests in the batch (always >= 1).
 *
 *  @note @b Thread-safe across batches. Two threads must not operate on the @b same @p batch
 *      concurrently.
 */
UCALL_EXPORT size_t ucall_server_batch_size(ucall_server_t server, ucall_received_batch_http_request_t batch);

/** Arguments of @c ucall_server_batch_unpack(). */
typedef struct ucall_server_batch_unpack_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Receives @c ucall_status_invalid_argument_k when @c index is not below the batch size. */
    ucall_outcome_t* outcome;

    /** Batch request handle from batch callback. */
    ucall_received_batch_http_request_t batch;

    /** Zero-based index of the request to extract. */
    size_t index;

    /** Output for the extracted request handle. */
    ucall_received_http_request_t* request;

} ucall_server_batch_unpack_t;

/**
 *  @brief Unpacks an individual request from a batch by index.
 *
 *  @note @b Thread-safe across batches. Two threads must not operate on the @b same @c batch
 *      concurrently.
 */
UCALL_EXPORT void ucall_server_batch_unpack(ucall_server_batch_unpack_t* arguments);

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

    /** Number of header name-value pairs (total strings / 2). */
    size_t headers_count;

    /** Response body content. Can be NULL for empty body. */
    ucall_bytes_view_t body;

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

    /** Number of header name-value pairs (total strings / 2). */
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

    /** Number of header name-value pairs (total strings / 2). */
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

/**
 *  @brief Closes a WebSocket connection.
 *
 *  This function is thread-safe and can be called from any thread. After calling this, the @p
 *  websocket handle becomes invalid.
 *
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] websocket WebSocket connection handle to close.
 *
 *  @note @b Thread-safe.
 */
UCALL_EXPORT void ucall_server_websocket_close(ucall_server_t server, ucall_websocket_t websocket);

#ifdef __cplusplus
}
#endif

#endif // UNUM_UCALL_SERVER_H
