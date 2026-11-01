/**
 *  @file c/ucall/server.h
 *  @author Ash Vardanian
 *  @date February 3, 2023
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
    ucall_bytes_view_t address;

    /** Physical device to pin this interface to with @c SO_BINDTODEVICE, such as "eth0", or empty
     *  to bind by address alone.
     *
     *  Several interfaces may name one device, and one interface bound to @c 0.0.0.0 spans every
     *  device the machine has - which is why the two are separate fields rather than one. */
    ucall_bytes_view_t device_name;

    /** Encryption for connections accepted here. Default: ucall_security_mode_none_k. */
    ucall_security_mode_t security_mode;

    /** Server identity for handshakes. Required when @c security_mode is not none. */
    ucall_noise_key_t const* noise_private_key;

    /** The initiator's static public key, which KK hashes before the first message. Required for
     *  KK, copied during initialization. Default: NULL. */
    ucall_noise_key_t const* noise_peer_key;

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

    /** Largest request head and buffered body; past it the reply is 413 and the connection
     *  lingers closed. Zero takes the largest receive buffer the kernel grants a socket. Streamed
     *  bodies are bounded by the application's pulls instead. */
    size_t max_request_bytes;

    /** Directories that path parts of replies to this interface's requests resolve beneath, by
     *  position, each copied during @c ucall_server_init(). UCall opens each then and closes it in
     *  @c ucall_server_free(); one that cannot be opened fails initialization. Default: NULL. */
    ucall_bytes_view_t const* reply_directories;

    /** Entries in @c reply_directories. */
    size_t reply_directories_count;

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

    /** StatsD UDP endpoint "host:port"; empty disables emission. */
    ucall_bytes_view_t metrics_address;

    /** Fraction of finished requests whose latency is reported, in (0.0, 1.0]. Zero takes 1.0. */
    float metrics_sample_rate;

    /** Metric name prefix; empty takes "ucall". */
    ucall_bytes_view_t metrics_prefix;

    /** Global tags, each "key:value". Default: none. */
    ucall_bytes_view_t const* metrics_tags;

    /** Entries in @c metrics_tags. */
    size_t metrics_tags_count;

    /** Microseconds between one event loop's datagrams. Zero takes one second. */
    size_t metrics_interval_microseconds;

    /** Requested I/O backend; automatic chooses an available native backend. */
    ucall_io_backend_t backend;

    /** Ceiling on the CPU class: the newest compiled class under it runs, and unknown takes the
     *  initialization thread's capabilities. Callers must stay on compatible CPUs after first use.
     *  Serial is the conservative choice. */
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
 *
 *  @par Statuses:
 *  - @c ucall_status_invalid_argument_k An output, the configuration or its interfaces are missing,
 *    or a metrics setting, an address, a device name, a security mode with the key or authorizer it
 *    needs, a connection budget or the reply directories are unusable.
 *  - @c ucall_status_unsupported_k This machine does not run the requested CPU class, no I/O
 *    backend serves the configuration on it, a device is named outside Linux, or an interface asks
 *    Windows for several loops.
 *  - @c ucall_status_connection_failed_k The metrics address or a listening address does not
 *    resolve, or no socket binds to it.
 *  - @c ucall_status_not_found_k A reply directory does not exist.
 *  - @c ucall_status_overflow_k The connection and pipelining budgets overflow their counters.
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

/**
 *  Advances one server loop and invokes ready callbacks on the calling thread.
 *  Callbacks run synchronously; the timeout cannot preempt them.
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_unsupported_k The kernel refuses the loop's I/O ring on its first poll.
 *  - @c ucall_status_invalid_argument_k The @c event_loop_index is past the last loop.
 *  - @c ucall_status_overflow_k The loop's connections, acceptors or pipelined requests overflow
 *    the counters its first poll sizes.
 */
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

/**
 *  Drives one server loop until @c ucall_server_stop() or an I/O failure.
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_unsupported_k The kernel refuses the loop's I/O ring on its first poll.
 *  - @c ucall_status_invalid_argument_k The @c event_loop_index is past the last loop.
 *  - @c ucall_status_overflow_k The loop's connections, acceptors or pipelined requests overflow
 *    the counters its first poll sizes.
 */
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

    /** Multishot receives armed again on a socket that already streamed, only on io_uring 6.18. */
    uint64_t receive_rearms;

    /** Bytes the kernel reported received on this loop's connections, ciphertext under Noise. */
    uint64_t bytes_received;

    /** Bytes the kernel reported sent from this loop's connections, ciphertext under Noise. */
    uint64_t bytes_sent;

    /** Bytes UCall copied: receive appends, reply bodies, Noise records and parked receives. */
    uint64_t bytes_copied;

    /** Sends that left without copying: reply segments and file windows. */
    uint64_t zero_copy_sends;

    /** Zero-copy sends the kernel copied anyway or refused to pin, as loopback always does. */
    uint64_t zero_copy_fallbacks;

    /** Sends that copied instead of pinning: the socket was demoted or refused zero-copy. */
    uint64_t copying_sends;

    /** File reads the kernel finishes later: io_uring, Linux or FreeBSD AIO, or overlapped I/O. */
    uint64_t file_reads_asynchronous;

    /** File reads the loop issued itself and blocked on, as the posix backend and macOS do. */
    uint64_t file_reads_blocking;

    /** Bytes the kernel reported read from files into the loop's file windows. */
    uint64_t bytes_read;

    /** File reads submitted while an earlier window of the same stream waited to send or sent. */
    uint64_t file_window_overlaps;

    /** Lingering closes reset at their deadline because the kernel still held what they sent. */
    uint64_t linger_resets;

    /** Passes the loop made over a ready connection, each advancing it as far as it goes. */
    uint64_t ready_passes;

    /** Replied exchanges the loop took from its queue to adopt their reply segments. */
    uint64_t replied_dequeues;

    /** Requests the loop answered itself with 400, 404, 413, 501 or 503. */
    uint64_t refused_requests;

    /** Connections whose Noise handshake failed. */
    uint64_t handshake_failures;

    /** Connections whose authenticated peer key the interface's authorizer refused. */
    uint64_t authorizer_refusals;

} ucall_event_loop_statistics_t;

/** Arguments of @c ucall_server_event_loop_statistics(). */
typedef struct ucall_server_event_loop_statistics_t {

    /** Initialized server. */
    ucall_server_t server;

    /** The verb's status, listed on the verb. */
    ucall_outcome_t* outcome;

    /** Zero-based loop index. */
    size_t event_loop_index;

    /** Output for a snapshot of the loop's counters, zeroed on failure. */
    ucall_event_loop_statistics_t* statistics;

} ucall_server_event_loop_statistics_t;

/**
 *  Copies one loop's counters, from any thread whose CPU runs the server's CPU class.
 *  Each counter is read on its own, so a snapshot of a running loop is not one instant.
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c statistics output is @c NULL, or the loop index is
 *    past the last loop.
 */
UCALL_EXPORT void ucall_server_event_loop_statistics(ucall_server_event_loop_statistics_t* arguments);

/** Arguments of @c ucall_server_take_batch(). */
typedef struct ucall_server_take_batch_t {

    /** Initialized server that registered @c endpoint. */
    ucall_server_t server;

    /** Outcome of this draining round. */
    ucall_outcome_t* outcome;

    /** Endpoint from @c ucall_server_add_http_batch_endpoint(); each has one draining owner. */
    ucall_http_batch_endpoint_t endpoint;

    /** Maximum wait for a due batch; zero performs one nonblocking round. */
    size_t timeout_microseconds;

} ucall_server_take_batch_t;

/**
 *  Invokes one batch endpoint's callback if a batch is due, with requests from every event loop,
 *  on the calling thread. UCall creates no thread; a bounded wait sleeps until a deposit, the
 *  partial batch's deadline, or the timeout, without polling any event loop.
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c endpoint is @c NULL.
 */
UCALL_EXPORT void ucall_server_take_batch(ucall_server_take_batch_t* arguments);

/** Arguments of @c ucall_server_take_batches(). */
typedef struct ucall_server_take_batches_t {

    /** Initialized server that registered @c endpoint. */
    ucall_server_t server;

    /** Final outcome after draining stops. */
    ucall_outcome_t* outcome;

    /** Endpoint from @c ucall_server_add_http_batch_endpoint(); each has one draining owner. */
    ucall_http_batch_endpoint_t endpoint;

} ucall_server_take_batches_t;

/**
 *  Invokes one batch endpoint's due callbacks on the calling thread, sleeping in between, until
 *  @c ucall_server_stop(). Requests still queued then are released without a callback.
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c endpoint is @c NULL.
 */
UCALL_EXPORT void ucall_server_take_batches(ucall_server_take_batches_t* arguments);

/** Counters of one batch endpoint since registration; they say how large its batches were and
 *  why each fired.
 *
 *  Only the endpoint's draining owner advances them. Batches released by a stop fire no callback
 *  and count nowhere. */
typedef struct ucall_batch_endpoint_statistics_t {

    /** Callbacks invoked. */
    uint64_t batches;

    /** Requests delivered across those callbacks. */
    uint64_t requests;

    /** Batches that fired on reaching @c max_batch_size. */
    uint64_t filled_batches;

    /** Batches that fired on reaching @c min_batch_size below the maximum. */
    uint64_t ready_batches;

    /** Batches that fired below @c min_batch_size once @c max_latency_microseconds passed. */
    uint64_t expired_batches;

} ucall_batch_endpoint_statistics_t;

/** Arguments of @c ucall_server_batch_endpoint_statistics(). */
typedef struct ucall_server_batch_endpoint_statistics_t {

    /** Initialized server that registered @c endpoint. */
    ucall_server_t server;

    /** The verb's status, listed on the verb. */
    ucall_outcome_t* outcome;

    /** Endpoint from @c ucall_server_add_http_batch_endpoint(). */
    ucall_http_batch_endpoint_t endpoint;

    /** Output for a snapshot of the endpoint's counters, zeroed on failure. */
    ucall_batch_endpoint_statistics_t* statistics;

} ucall_server_batch_endpoint_statistics_t;

/**
 *  Copies one batch endpoint's counters, from any thread whose CPU runs the server's CPU class.
 *  Each counter is read on its own, so a snapshot of a draining endpoint is not one instant.
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c endpoint or the @c statistics output is @c NULL.
 */
UCALL_EXPORT void ucall_server_batch_endpoint_statistics(ucall_server_batch_endpoint_statistics_t* arguments);

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

    /** The verb's status, listed on the verb. */
    ucall_outcome_t* outcome;

    /** URI template, with an explicit byte length. */
    ucall_bytes_view_t uri_template;

    /** HTTP method for this endpoint. */
    ucall_verb_t verb;

    /** Function pointer to the callback. */
    ucall_received_http_request_callback_t callback;

    /** Optional payload/tag for metadata (e.g., for CPython runtime). */
    void* context;

    /** Whether the callback runs once the body is buffered, or at headers time with the body
     *  pulled through ucall_server_request_body_chunk(). Default: buffered. */
    ucall_body_delivery_t body_delivery;

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
 *  @see RFC 6570 Section 3.2.2, simple string expansion: https://www.rfc-editor.org/rfc/rfc6570#section-3.2.2
 *
 *  @note Call during setup only, before any loop is polled.
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c callback is @c NULL, the @c verb is unknown, or
 *    the template is empty, lacks its leading slash, carries a query, a fragment or a malformed
 *    segment, or names a placeholder another template names differently at the same position.
 *  - @c ucall_status_contended_k A loop of the server was already polled.
 *  - @c ucall_status_already_exists_k An endpoint of the same @c verb has the same or an equivalent
 *    template.
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

    /** The verb's status, listed on the verb. */
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
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c endpoint output or the @c callback is @c NULL, the
 *    minimum batch size exceeds the maximum, the @c verb is unknown, or the template is empty,
 *    lacks its leading slash, carries a query, a fragment or a malformed segment, or names a
 *    placeholder another template names differently at the same position.
 *  - @c ucall_status_contended_k A loop of the server was already polled.
 *  - @c ucall_status_already_exists_k An endpoint of the same @c verb has the same or an equivalent
 *    template.
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

/** Arguments of @c ucall_server_request_path(). */
typedef struct ucall_server_request_path_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome. */
    ucall_outcome_t* outcome;

    /** The received request inside the @c ucall_received_http_request_callback_t. */
    ucall_received_http_request_t request;

    /** Output for a borrowed view of the path. */
    ucall_bytes_view_t* path;

} ucall_server_request_path_t;

/**
 *  @brief Extracts the path of the received request: its target without the query.
 *
 *  The path stays as the peer sent it, percent-encoded and with repeated slashes, which the
 *  segment and parameter accessors skip.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c request or the @c path output is @c NULL.
 */
UCALL_EXPORT void ucall_server_request_path(ucall_server_request_path_t* arguments);

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

    /** The verb's status, listed on the verb. */
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
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c request or the @c segment output is @c NULL.
 *  - @c ucall_status_not_found_k The @c index is past the last segment.
 */
UCALL_EXPORT void ucall_server_request_path_segment(ucall_server_request_path_segment_t* arguments);

/** Arguments of @c ucall_server_request_path_parameter(). */
typedef struct ucall_server_request_path_parameter_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** The verb's status, listed on the verb. */
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
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c request or the @c value output is @c NULL, or the
 *    placeholder name is not a valid view.
 *  - @c ucall_status_not_found_k The template has no such placeholder, or the path ends before it.
 */
UCALL_EXPORT void ucall_server_request_path_parameter(ucall_server_request_path_parameter_t* arguments);

/** Arguments of @c ucall_server_request_query_parameter(). */
typedef struct ucall_server_request_query_parameter_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** The verb's status, listed on the verb. */
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
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c request or the @c value output is @c NULL, or the
 *    parameter name is not a valid view.
 *  - @c ucall_status_not_found_k The query has no such parameter.
 */
UCALL_EXPORT void ucall_server_request_query_parameter(ucall_server_request_query_parameter_t* arguments);

/** Arguments of @c ucall_server_request_header(). */
typedef struct ucall_server_request_header_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** The verb's status, listed on the verb. */
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
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c request or the @c value output is @c NULL, or the
 *    header name is not an HTTP token.
 *  - @c ucall_status_not_found_k The request has no such header.
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
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c request or an output is @c NULL.
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
 *  A streamed endpoint's body is pulled through @c ucall_server_request_body_chunk() instead.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c request or the @c body output is @c NULL, or the
 *    endpoint is streamed.
 */
UCALL_EXPORT void ucall_server_request_body(ucall_server_request_body_t* arguments);

/** Arguments of @c ucall_server_request_body_chunk(). */
typedef struct ucall_server_request_body_chunk_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Final with the next bytes, or deferred until they arrive; a deferred pull finishes on the
     *  request's polling thread, so a pull from that thread with nothing decoded yet answers
     *  @c ucall_status_would_block_k instead and keeps no outcome. */
    ucall_outcome_t* outcome;

    /** The received request inside the @c ucall_received_http_request_callback_t. */
    ucall_received_http_request_t request;

    /** Output for a borrowed view of the bytes decoded since the last pull, valid until the next
     *  pull and written once the outcome is final; empty once the body ended. */
    ucall_bytes_view_t* data;

} ucall_server_request_body_chunk_t;

/**
 *  @brief Pulls the next chunk of a request body that is still arriving.
 *
 *  Endpoints registered with @c ucall_body_delivery_streamed_k are invoked as soon as headers are
 *  parsed, before the body is complete. Without this, a multi-gigabyte upload must be buffered in
 *  full before the handler runs, which is both a memory hazard and a denial-of-service vector.
 *  Each pull takes every byte decoded since the last one; the connection reads on only once the
 *  previous bytes were pulled, and parses no pipelined request until the body ended. On a buffered
 *  endpoint the first pull answers the whole body and the next one empty.
 *
 *  @warning The returned @c data is valid only until the next call on this @c request.
 *  @sa Use @c ucall_server_request_body() for endpoints that are not registered as streaming.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c request or the @c data output is @c NULL.
 *  - @c ucall_status_malformed_k The streamed body's framing is malformed.
 *  - @c ucall_status_connection_closed_k The connection closed before the streamed body ended.
 *  - @c ucall_status_would_block_k Called on the request's polling thread with nothing decoded
 *    yet; the next pull takes what arrives by then.
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
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c request or an output is @c NULL, or the @c index is
 *    past the last part.
 *  - @c ucall_status_malformed_k The body is not a well-formed @c multipart/form-data body, or the
 *    part has no blank line closing its headers.
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
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c request is @c NULL, a view is invalid, a status of
 *    204 or 304 carries a body, the @c http_status is outside 200 to 599, or a header line is
 *    malformed or sets @c Content-Length, @c Transfer-Encoding, @c Date or @c Server.
 *  - @c ucall_status_already_exists_k The request was already answered.
 *  - @c ucall_status_connection_closed_k The peer left or the server stops.
 *  - @c ucall_status_overflow_k The reply's length overflows its counter.
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
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c request is @c NULL, the @c message is not a valid
 *    view, or the @c http_status is outside 400 to 599.
 *  - @c ucall_status_already_exists_k The request was already answered.
 *  - @c ucall_status_connection_closed_k The peer left or the server stops.
 *  - @c ucall_status_overflow_k The reply's length overflows its counter.
 */
UCALL_EXPORT void ucall_server_reply_error(ucall_server_reply_error_t* arguments);

/** What one part of a reply body holds. */
typedef enum ucall_reply_part_kind_t {

    /** @c data.bytes, copied before the call returns. */
    ucall_reply_part_bytes_k = 0,

    /** @c data.file, a range of a descriptor the event loop reads unbuffered and sends without
     *  copying where the kernel allows. */
    ucall_reply_part_file_k = 1,

    /** @c data.path, a range of a file the event loop opens beneath a registered directory. */
    ucall_reply_part_path_k = 2,

} ucall_reply_part_kind_t;

/** A byte range of a file the caller opened. UCall never closes the descriptor: the caller keeps
 *  it open until the reply's outcome leaves @c ucall_status_deferred_k, and may close it right
 *  after any synchronous refusal. */
typedef struct ucall_file_range_t {

    /** A regular file opened with @c O_DIRECT, borrowed; a descriptor without it is refused with
     *  @c ucall_status_invalid_argument_k. */
    int file_descriptor;

    /** The range's first byte. */
    uint64_t offset;

    /** The range's byte count; zero sends through the end of the file. */
    uint64_t length;

} ucall_file_range_t;

/** A byte range of a file UCall opens unbuffered beneath a registered directory, and closes once
 *  the part is sent or dropped. Empty, absolute paths, @c ".." components and NUL bytes are
 *  refused, and so is any resolution leaving the directory, symbolic links included. */
typedef struct ucall_path_range_t {

    /** A position below the @c reply_directories_count of the interface the request arrived on. */
    size_t directory_index;

    /** The file beneath that directory, copied before the call returns. */
    ucall_bytes_view_t relative_path;

    /** The range's first byte. */
    uint64_t offset;

    /** The range's byte count; zero sends through the end of the file. */
    uint64_t length;

} ucall_path_range_t;

/** One part of a reply body: bytes in memory, or a byte range of a file, which the event loop
 *  reads after the call returns. */
typedef struct ucall_reply_part_t {

    /** Which member of @c data the part uses. */
    ucall_reply_part_kind_t kind;

    /** The part's content, as @c kind selects. */
    union {

        /** Content of a @c ucall_reply_part_bytes_k part. */
        ucall_bytes_view_t bytes;

        /** Range of a @c ucall_reply_part_file_k part. */
        ucall_file_range_t file;

        /** Range of a @c ucall_reply_part_path_k part. */
        ucall_path_range_t path;

    } data;

} ucall_reply_part_t;

/** Arguments of @c ucall_server_reply_vectored(). */
typedef struct ucall_server_reply_vectored_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. Kept alive by
     *  the caller until then. */
    ucall_outcome_t* outcome;

    /** The received request to reply to. */
    ucall_received_http_request_t request;

    /** Response status. Zero sends @c ucall_http_status_ok_k. */
    ucall_http_status_t http_status;

    /** Every HTTP header line, each as a counted byte view. */
    ucall_bytes_view_t const* headers;

    /** Number of counted header lines. */
    size_t headers_count;

    /** Parts concatenated, in order, into the body. */
    ucall_reply_part_t const* parts;

    /** Number of entries in @c parts. Empty parts are allowed. */
    size_t parts_count;

} ucall_server_reply_vectored_t;

/**
 *  @brief Sends a response assembled from several non-contiguous buffers and file ranges.
 *
 *  Lets a handler reply with a header, a tensor, and a file without concatenating them into a
 *  staging buffer first. Sets @c Content-Length to the sum of the parts, and sends no body to a
 *  @c HEAD request.
 *
 *  Memory-only replies are final on return. With any file or path part, the outcome reads
 *  @c ucall_status_deferred_k on return: the event loop opens and sizes every part before it sends
 *  the head, so @c Content-Length is measured, then publishes success once every part is sent, or
 *  the cause of a failure. A part failing before the head replaces the whole reply: @c 404 for a
 *  missing, unreadable or irregular file, @c 416 for a range past its end, @c 500 otherwise. A part
 *  failing after the head resets the connection.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c request is @c NULL, a part or a view is invalid, a
 *    file descriptor reads buffered, a path leaves its directories, a status of 204 or 304 carries
 *    a body, the @c http_status is outside 200 to 599, or a header line is malformed or sets a
 *    length, a transfer encoding, a date or a server name.
 *  - @c ucall_status_overflow_k A range's end or the reply's length overflows its counter, or a
 *    range runs past the end of its file.
 *  - @c ucall_status_already_exists_k The request was already answered.
 *  - @c ucall_status_connection_closed_k The peer left or the server stops.
 *  - @c ucall_status_not_found_k A file is missing, unreadable or irregular.
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

    /** Response status. Zero sends @c ucall_http_status_ok_k. */
    ucall_http_status_t http_status;

    /** Every HTTP header line, each as a counted byte view. May include @c Content-Length. */
    ucall_bytes_view_t const* headers;

    /** Number of counted header lines. */
    size_t headers_count;

} ucall_server_reply_begin_t;

/**
 *  @brief Begins a streamed response, emitting the status line and headers.
 *
 *  Must be followed by zero or more @c ucall_server_reply_append() calls and exactly one @c
 *  ucall_server_reply_end() once this call reports success or @c ucall_status_connection_closed_k;
 *  any other failure leaves the request unanswered. The body is chunked for HTTP/1.1 peers.
 *  Supplying @c Content-Length switches to identity encoding, which is what @c Range responses
 *  need, and @c ucall_server_reply_end() checks the chunks summed to it. An HTTP/1.0 peer without
 *  it gets a body delimited by closing the connection. A @c HEAD request, @c 204 and @c 304 carry
 *  no body: chunks for a @c HEAD request are accepted and dropped.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c request is @c NULL, the @c http_status is outside
 *    200 to 599, a header line is malformed or sets @c Transfer-Encoding, @c Date or @c Server, the
 *    declared @c Content-Length is no decimal number, or a status of 204 or 304 declares one.
 *  - @c ucall_status_already_exists_k The request was already answered.
 *  - @c ucall_status_connection_closed_k The peer left or the server stops.
 *  - @c ucall_status_overflow_k The head's length overflows its counter.
 */
UCALL_EXPORT void ucall_server_reply_begin(ucall_server_reply_begin_t* arguments);

/** Arguments of @c ucall_server_reply_append(). */
typedef struct ucall_server_reply_append_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** The received request being replied to. */
    ucall_received_http_request_t request;

    /** Parts appended, in order, to the body: queued together or not at all. */
    ucall_reply_part_t const* parts;

    /** Number of entries in @c parts. */
    size_t parts_count;

} ucall_server_reply_append_t;

/**
 *  @brief Appends parts to a response opened with @c ucall_server_reply_begin().
 *
 *  Can be called from any thread, long after the request callback returned. Empty bytes parts send
 *  nothing, and so do file ranges of zero bytes.
 *
 *  A file or path part that fails once the head left resets the connection.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c request is @c NULL, its reply was not begun or
 *    already ended, a part or a view is invalid, a file descriptor reads buffered, a path leaves
 *    its directories, a file or path part of zero length comes on a stream with a declared length,
 *    as their size is unknown, a status of 204 or 304 gets a body, or one call brings more file and
 *    path parts than may wait.
 *  - @c ucall_status_overflow_k A range's end overflows its counter, or parts would run past a
 *    declared @c Content-Length.
 *  - @c ucall_status_connection_closed_k The peer left or the server stops.
 *  - @c ucall_status_would_block_k Nothing was queued, as the bytes parts already queued for this
 *    request and not yet taken by the socket exceed the bytes a reading peer takes per round trip,
 *    or too many file and path parts wait; retry once the peer catches up.
 */
UCALL_EXPORT void ucall_server_reply_append(ucall_server_reply_append_t* arguments);

/** Arguments of @c ucall_server_reply_end(). */
typedef struct ucall_server_reply_end_t {

    /** The server this call operates on. */
    ucall_server_t server;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. Kept alive by
     *  the caller until then. */
    ucall_outcome_t* outcome;

    /** The received request being replied to. Invalid once the call returns. */
    ucall_received_http_request_t request;

} ucall_server_reply_end_t;

/**
 *  @brief Completes a response opened with @c ucall_server_reply_begin().
 *
 *  Consumes the request handle on every outcome. A response whose chunks fell short of a declared
 *  @c Content-Length closes the connection after the bytes already sent, so the peer cannot
 *  mistake the truncated body for a whole one.
 *
 *  While file or path parts are still unsent, the outcome reads @c ucall_status_deferred_k on
 *  return, and the event loop publishes success once they are sent, or the cause of a failure.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the @b same @c request
 *      concurrently.
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c server is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c request is @c NULL, or its reply was not begun or
 *    already ended.
 *  - @c ucall_status_connection_closed_k The peer left or the server stops.
 *  - @c ucall_status_malformed_k The chunks fell short of a declared @c Content-Length.
 *  - @c ucall_status_overflow_k The last chunk's length overflows its counter, or a file part's
 *    range runs past the end of its file.
 *  - @c ucall_status_not_found_k A file part's file is missing, unreadable or irregular.
 */
UCALL_EXPORT void ucall_server_reply_end(ucall_server_reply_end_t* arguments);

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
