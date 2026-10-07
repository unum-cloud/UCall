/**
 *  @brief UCall is a fast HTTP+Noise client & server web framework leveraging
 *    @b io_uring & SIMD across x86 & Arm for high-performance packet processing.
 *
 *  @file ucall.h
 *  @date Feb 3, 2023
 *  @author Ash Vardanian
 *
 *  Every verb that can fail takes one argument struct named after it, as @c ucall_client_call() takes
 *  @c ucall_client_call_t, and returns nothing. Each struct opens with its handle, then @c outcome, then
 *  inputs, outputs, and knobs. Initialize them with designated initializers, so fields added later stay
 *  zero. Getters that cannot fail and @c *_free() stay positional.
 *
 *  Synchronous and asynchronous calls share one shape. A client call carries a @c ucall_completion_t:
 *  zero blocks until the response arrives, and @c ucall_completion_deferred_k returns once the call is
 *  queued, so no verb has an asynchronous twin. The outcome's status is the one word both sides
 *  synchronize on:
 *
 *  - For a deferred call the library stores @c ucall_status_pending_k, then the message and the final
 *    status with release ordering, even for a call refused at submission, and touches nothing the struct
 *    names after that store.
 *  - The caller reads the status with acquire ordering, by waiting or by polling, and may reuse the
 *    struct or free its buffers only once the status is final.
 *  - A client tracks a fixed number of deferred calls in flight, and a submission that finds the table
 *    full finishes at once with @c ucall_status_contended_k instead of queueing.
 *
 *  Server verbs called from an endpoint callback finish before they return. Received bytes live in
 *  memory the library owns, a server's receive pool or a client's response, so no allocator, alignment
 *  or memory kind crosses this interface.
 */

#ifndef UCALL_H_
#define UCALL_H_

#include <stdbool.h> // bool
#include <stddef.h>  // size_t
#include <stdint.h>  // uint32_t, int32_t

#define UCALL_VERSION_MAJOR 1
#define UCALL_VERSION_MINOR 0
#define UCALL_VERSION_PATCH 0

/**
 *  @brief Marks exported functions. Define @c UCALL_BUILDING while compiling UCall itself,
 *    or predefine @c UCALL_EXPORT as empty to link it statically on Windows.
 */
#ifndef UCALL_EXPORT
#if defined(_WIN32) || defined(__CYGWIN__)
#if defined(UCALL_BUILDING)
#define UCALL_EXPORT __declspec(dllexport)
#else
#define UCALL_EXPORT __declspec(dllimport)
#endif
#else
#define UCALL_EXPORT __attribute__((visibility("default")))
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

#pragma region Basic Types

/** @brief Type alias for immutable strings. */
typedef char const* ucall_string_t;

/**
 *  @brief A non-owning view of a contiguous byte range.
 *
 *  Used for scatter-gather replies, avoiding a dependency on POSIX @c iovec,
 *  which is unavailable on Windows.
 */
typedef struct ucall_buffer_t {
    void const* data;
    size_t length;
} ucall_buffer_t;

/**
 *  @brief Opaque server handle.
 *  @sa Deals with @c ucall_received_http_request_t and @c ucall_received_batch_http_request_t.
 *  @sa Use with @c ucall_server_init() and @c ucall_server_free() for lifetime.
 *  @sa Use @c ucall_server_add_http_endpoint() and @c ucall_server_take_calls() for logic.
 */
typedef struct ucall_server_handle_t* ucall_server_t;

/**
 *  @brief Opaque client handle.
 *  @sa Deals with @c ucall_received_http_response_t.
 *  @sa Use with @c ucall_client_init() and @c ucall_client_free() for lifetime.
 *  @sa Use @c ucall_client_call() for logic.
 *
 *  At a high level, a @b client is responsible for:
 *
 *  - Establishing connections to one or more servers, reusing encryption keys between requests.
 *  - Following redirects chains automatically, unless disabled.
 *  - Driving every submitted call on a connection thread it owns.
 */
typedef struct ucall_client_handle_t* ucall_client_t;

/** @brief Opaque handle for a single Remote Procedure Call on the @b server side. */
typedef struct ucall_received_http_request_handle_t* ucall_received_http_request_t;

/** @brief Opaque handle for several batched Remote Procedure Calls on the @b server side. */
typedef struct ucall_received_batch_http_request_handle_t* ucall_received_batch_http_request_t;

/** @brief Opaque handle for a single Remote Procedure Call reply on the @b client side. */
typedef struct ucall_received_http_response_handle_t* ucall_received_http_response_t;

/**
 *  @brief Security modes for UCall server and client.
 *
 *  Noise protocol pattern to use for handshake. Supported values:
 *  - @c XX: Full mutual authentication (both parties authenticate during handshake).
 *  - @c IK: Client knows server's public key in advance (Identity Known).
 *  - @c KK: Both parties know each other's public keys (Known Known).
 *
 *  @note Use @c http+noise:// or @c ws+noise:// URL schemes to enable Noise transport.
 *  @see https://noiseprotocol.org/noise.html for pattern specifications.
 */
typedef enum ucall_security_mode_t {
    /** @brief No encryption, plain TCP/IP. */
    ucall_security_none_k,
    /** @brief Trust on first use - no pre-shared keys needed. */
    ucall_security_noise_xx_k,
    /** @brief Client knows server's public key in advance. */
    ucall_security_noise_ik_k,
    /** @brief Both know each other's public keys in advance. */
    ucall_security_noise_kk_k
} ucall_security_mode_t;

/**
 *  @brief Noise protocol key (32 bytes for Curve25519).
 */
typedef uint8_t ucall_noise_key_t[32];

/**
 *  @brief Decides whether a peer presenting a given static key may proceed past the handshake.
 *  @param[in] peer_static_key The remote party's 32-byte Curve25519 static public key.
 *  @param[in] context User-supplied context from the server or client configuration.
 *  @return True to accept the peer, false to abort with @c ucall_status_peer_rejected_k.
 *
 *  Required for @c ucall_security_noise_xx_k, where keys are learned during the handshake
 *  rather than known in advance. Called after the key is authenticated, before any payload.
 */
typedef bool (*ucall_peer_authorizer_t)(ucall_noise_key_t const* peer_static_key, void* context);

/**
 *  @brief HTTP request methods/verbs for endpoint routing.
 *
 *  For JSON-RPC all requests are typically sent via HTTP @c POST.
 */
typedef enum ucall_verb_t {
    /** @brief Unrecognized or not yet parsed. The zero-initialized default. */
    ucall_verb_unknown_k = 0,
    /** @brief HTTP "GET" method for retrieving resources. */
    ucall_verb_get_k,
    /** @brief HTTP "POST" method for creating resources. */
    ucall_verb_post_k,
    /** @brief HTTP "PUT" method for updating resources. */
    ucall_verb_put_k,
    /** @brief HTTP "DELETE" method for removing resources. */
    ucall_verb_delete_k,
    /** @brief HTTP "PATCH" method for partial updates. */
    ucall_verb_patch_k,
    /** @brief HTTP "HEAD" method for retrieving headers only. */
    ucall_verb_head_k,
    /** @brief HTTP "OPTIONS" method for retrieving supported methods. */
    ucall_verb_options_k,
    /** @brief Matches every method. Valid only when registering an endpoint. */
    ucall_verb_any_k
} ucall_verb_t;

/**
 *  @brief Library-level status codes for UCall operations.
 *
 *  These codes represent library/transport-level outcomes.
 *  For HTTP-specific status codes (200, 404, 500), use @c ucall_http_status_t.
 */
typedef enum ucall_status_t {
    /** @brief Operation completed successfully. */
    ucall_status_success_k = 0,
    /** @brief The call was submitted and has not finished; never a final status. */
    ucall_status_pending_k = 1,

    /** @brief Invalid function parameters - NULL pointers or out-of-range values. */
    ucall_status_invalid_argument_k = 2,
    /** @brief Memory allocation failed. */
    ucall_status_out_of_memory_k = 3,
    /** @brief Failed to establish connection at the DNS, TCP, or Noise handshake stage. */
    ucall_status_connection_failed_k = 4,
    /** @brief Connection closed unexpectedly. */
    ucall_status_connection_closed_k = 5,
    /** @brief Operation exceeded configured timeout. */
    ucall_status_timeout_k = 6,

    /** @brief Requested resource/header/parameter not found. */
    ucall_status_not_found_k = 7,
    /** @brief Malformed or invalid protocol data. */
    ucall_status_malformed_k = 8,

    /** @brief Noise handshake failed - key mismatch, bad pattern, or bad tag. */
    ucall_status_handshake_failed_k = 9,
    /** @brief Peer static key declined by @c ucall_peer_authorizer_t. */
    ucall_status_peer_rejected_k = 10,
    /** @brief Non-blocking operation had no progress to report. */
    ucall_status_would_block_k = 11,
    /** @brief Requested memory kind or feature is not available on this backend or machine. */
    ucall_status_unsupported_k = 12,
    /** @brief Every slot of the client's in-flight table is taken; the call was refused, not queued. */
    ucall_status_contended_k = 13,

} ucall_status_t;

/**
 *  @brief Outcome of one call: a status to branch on, and a static message with the detail it cannot carry.
 *
 *  The message has static storage, is never freed, and is @c NULL exactly when the status is
 *  @c ucall_status_success_k. Every verb struct points at one.
 */
typedef struct ucall_outcome_t {
    ucall_status_t status;
    char const* message;
} ucall_outcome_t;

/**
 *  @brief Blocks until @p outcome is final, without spinning, and with acquire ordering.
 *  @param[in] outcome An outcome passed to a call, read until its status leaves @c ucall_status_pending_k.
 *  @return The final status; @c ucall_status_pending_k at once when called from a thread the client drives the
 *    call on, rather than waiting on itself.
 *
 *  @par Example
 *  @code{.c}
 *  ucall_outcome_t outcomes[4] = {{0}};
 *  for (size_t i = 0; i != 4; ++i) {
 *      calls[i].outcome = &outcomes[i];
 *      calls[i].completion = ucall_completion_deferred_k;
 *      ucall_client_call(&calls[i]);
 *  }
 *  for (size_t i = 0; i != 4; ++i) ucall_outcome_wait(&outcomes[i]);
 *  @endcode
 *
 *  @note @b Thread-safe. Any number of threads may wait on one outcome.
 */
UCALL_EXPORT ucall_status_t ucall_outcome_wait(ucall_outcome_t const* outcome);

/** @brief Whether a call returns once its work is done, or once it is queued on the client. */
typedef enum ucall_completion_t {
    /** @brief Return with the final status stored and the response readable; the default. */
    ucall_completion_blocking_k = 0,
    /** @brief Return once queued, with the status pending until the call ends; the caller waits or polls. */
    ucall_completion_deferred_k = 1,
} ucall_completion_t;

/**
 *  @brief HTTP status codes for server responses and client results.
 *
 *  Use these when you need HTTP-specific semantics (400, 404, 500, etc.).
 *  For library-level operations, use @c ucall_status_t instead.
 */
typedef enum ucall_http_status_t {
    /** @brief Request succeeded. */
    ucall_http_ok_k = 200,
    /** @brief Resource created. */
    ucall_http_created_k = 201,
    /** @brief Success with an empty body. */
    ucall_http_no_content_k = 204,
    /** @brief Success with the requested @c Range of the body. */
    ucall_http_partial_content_k = 206,

    /** @brief Resource has a new permanent URL. */
    ucall_http_moved_permanently_k = 301,
    /** @brief Resource is temporarily at a different URL. */
    ucall_http_found_k = 302,
    /** @brief Cached copy is still fresh. */
    ucall_http_not_modified_k = 304,

    /** @brief Malformed request syntax. */
    ucall_http_bad_request_k = 400,
    /** @brief Authentication required or failed. */
    ucall_http_unauthorized_k = 401,
    /** @brief Authenticated, but not permitted. */
    ucall_http_forbidden_k = 403,
    /** @brief No endpoint matches the request path. */
    ucall_http_not_found_k = 404,
    /** @brief Endpoint exists, but not for this verb. */
    ucall_http_method_not_allowed_k = 405,
    /** @brief Client took too long to send the request. */
    ucall_http_timeout_k = 408,
    /** @brief Request conflicts with current resource state. */
    ucall_http_conflict_k = 409,
    /** @brief Request body exceeds the configured limit. */
    ucall_http_payload_too_large_k = 413,
    /** @brief Rate limit exceeded. */
    ucall_http_too_many_requests_k = 429,

    /** @brief Unhandled failure inside an endpoint. */
    ucall_http_internal_error_k = 500,
    /** @brief Verb or feature not supported. */
    ucall_http_not_implemented_k = 501,
    /** @brief Server is overloaded or shutting down. */
    ucall_http_service_unavailable_k = 503,
    /** @brief Upstream dependency timed out. */
    ucall_http_gateway_timeout_k = 504,
} ucall_http_status_t;

/** @brief Severity of a log line, from the most verbose up. */
typedef enum ucall_log_level_t {
    ucall_log_level_debug_k,
    ucall_log_level_info_k,
    ucall_log_level_warning_k,
    ucall_log_level_error_k,
    ucall_log_level_fatal_k
} ucall_log_level_t;

/** @brief Shape of each log line. */
typedef enum ucall_log_format_t {
    /** @brief Human-readable unit-normalized lines. */
    ucall_log_format_human_k,
    /** @brief Newline-delimited JSONs documents. */
    ucall_log_format_json_k,
} ucall_log_format_t;

/**
 *  @brief Receives one formatted log line, without a trailing newline.
 *  @param[in] level Severity of the line.
 *  @param[in] line The formatted line. Valid only for the duration of the call.
 *  @param[in] line_length Length of @p line in bytes.
 *  @param[in] context User-supplied context from @c ucall_log_t.
 *
 *  Called on whichever thread produced the line, including event loops and the client's
 *  connection thread, so it must be thread-safe and return quickly.
 */
typedef void (*ucall_log_callback_t)(ucall_log_level_t level, ucall_string_t line, size_t line_length, void* context);

/**
 *  @brief The single log sink of a client or a server.
 *
 *  UCall writes nothing anywhere on its own: every line goes to @c callback, and without one
 *  the library stays silent.
 */
typedef struct ucall_log_t {
    /** @brief Receives every line at or above @c level. Default: NULL, logging nothing. */
    ucall_log_callback_t callback;
    /** @brief Passed verbatim to @c callback. */
    void* context;
    /** @brief Line format. Default: ucall_log_format_human_k. */
    ucall_log_format_t format;
    /** @brief Lines below this severity are never formatted. Default: ucall_log_level_debug_k. */
    ucall_log_level_t level;
} ucall_log_t;

/**
 *  @brief WebSocket event types, shared between client and server.
 */
typedef enum ucall_websocket_event_t {
    /** @brief Connection established. */
    ucall_websocket_open_k,
    /** @brief Message received. */
    ucall_websocket_message_k,
    /** @brief Error occurred. */
    ucall_websocket_error_k,
    /** @brief Connection closed. */
    ucall_websocket_close_k
} ucall_websocket_event_t;

/**
 * @brief WebSocket message types (RFC 6455).
 */
typedef enum ucall_websocket_opcode_t {
    ucall_websocket_text_k = 0x1,
    ucall_websocket_binary_k = 0x2,
    ucall_websocket_ping_k = 0x9,
    ucall_websocket_pong_k = 0xA
} ucall_websocket_opcode_t;

/**
 *  @brief Opaque handle to a WebSocket connection.
 *
 *  Valid from @c ucall_websocket_open_k event until @c ucall_websocket_close_k event.
 */
typedef struct ucall_websocket_handle_t* ucall_websocket_t;

/**
 *  @brief Callback for WebSocket events on both client and server sides.
 *  @param[in] websocket WebSocket connection handle.
 *  @param[in] event Type of event.
 *  @param[in] opcode Message opcode (only valid for @c ucall_websocket_message_k event).
 *  @param[in] data Event data. Message payload for @c ucall_websocket_message_k.
 *    Error description for @c ucall_websocket_error_k. Otherwise - @c NULL.
 *  @param[in] data_length Length of data.
 *  @param[in] context User-supplied context pointer from the WebSocket initialization.
 */
typedef void (*ucall_websocket_callback_t)(                                                      //
    ucall_websocket_t websocket, ucall_websocket_event_t event, ucall_websocket_opcode_t opcode, //
    ucall_string_t data, size_t data_length, void* context);

#pragma endregion Basic Types

#pragma region Clients

/**
 *  @brief Configuration parameters for the UCall client.
 *  @sa Initialize with @c ucall_client_init().
 */
typedef struct ucall_client_config_t {

    /** @brief Maximum simultaneously open connections. Default: 100. */
    uint32_t max_concurrent_connections;
    /** @brief Time budget for establishing a connection. Default: 5'000'000. */
    uint32_t connect_timeout_micro_seconds;
    /** @brief Time budget for a full request-response exchange. Default: 30'000'000. */
    uint32_t request_timeout_micro_seconds;

    /** @brief Client identity for handshakes. Optional, needed only when the server authenticates clients. */
    ucall_noise_key_t const* noise_private_key;

    /** @brief Vets server static keys. Required for XX. Default: NULL. */
    ucall_peer_authorizer_t peer_authorizer;
    /** @brief Passed verbatim to @c peer_authorizer. */
    void* peer_authorizer_context;

    /** @brief Where log lines go. Default: nowhere. */
    ucall_log_t log;

    /** @brief Depth of the submission queue backing the client. Default: 128. */
    uint16_t queue_depth;
} ucall_client_config_t;

/** @brief Arguments of @c ucall_client_init(). */
typedef struct ucall_client_init_t {
    ucall_outcome_t* outcome;
    /** @brief Requested configuration. Zeroed fields take their documented defaults. */
    ucall_client_config_t const* config;
    /** @brief Optional output for @c config with every default filled in. */
    ucall_client_config_t* resolved;
    /** @brief Output for the new client. Free with @c ucall_client_free() at the end. */
    ucall_client_t* client;
    /**
     *  @brief Slots of the fixed in-flight table, one per deferred call not yet final. A deferred call
     *    finding it full stores @c ucall_status_contended_k as its final status. Zero means a default.
     */
    size_t in_flight_limit;
} ucall_client_init_t;

/**
 *  @brief Initializes the client state.
 *  @note Call during setup only, before any thread enters @c ucall_client_call().
 */
UCALL_EXPORT void ucall_client_init(ucall_client_init_t* arguments);

/**
 *  @brief Frees the client state. Does nothing for @c NULL.
 *  @param[in] client Client from @c ucall_client_init(), or @c NULL.
 *
 *  @note Call during setup only, before any thread enters @c ucall_client_call(),
 *    and only once the outcome of every call submitted to it is final.
 */
UCALL_EXPORT void ucall_client_free(ucall_client_t client);

/**
 *  @brief Options for individual UCall client requests and connections.
 *
 *  All of them control the library behavior on a per-request basis, but don't affect the HTTP
 *  headers of individual requests.
 */
typedef struct ucall_request_options_t {
    /** @brief Time budget for this call. Default: 5'000'000. */
    uint32_t timeout_micro_seconds;
    /** @brief Retries attempted on transport failure. Default: 3. */
    uint8_t max_retries;
    /** @brief Redirect hops followed before failing. Default: 5. */
    uint8_t max_redirects;

    /** @brief Transport security for this call. Default: ucall_security_none_k. */
    ucall_security_mode_t security;
    /** @brief Needed for KK security mode. */
    ucall_noise_key_t const* client_key;
    /** @brief Needed for IK and KK security modes. */
    ucall_noise_key_t const* server_key;
} ucall_request_options_t;

/** @brief Arguments of @c ucall_client_call(). */
typedef struct ucall_client_call_t {
    ucall_client_t client;
    /** @brief Output for the outcome, final once its status leaves @c ucall_status_pending_k. */
    ucall_outcome_t* outcome;
    /** @brief Whether the call blocks or returns once queued; zero blocks. */
    ucall_completion_t completion;

    /**
     *  @brief Full URL with scheme: @c http://, @c ws://, @c http+noise://, or @c ws+noise://.
     *    Example: "http://localhost:8080/sum?a=1&b=2" or "http+noise://api.example.com/rpc".
     */
    ucall_string_t url;
    /** @brief HTTP method, like @c ucall_verb_get_k or @c ucall_verb_post_k, etc. */
    ucall_verb_t verb;
    /** @brief Array of @b non-system headers to include in the request. */
    ucall_string_t const* headers;
    /** @brief Optional array of lengths for each string (NULL if terminated). */
    size_t const* headers_lengths;
    /** @brief Number of strings in the @c headers array. */
    size_t headers_count;
    /** @brief Request body, can be @c NULL for @c GET, @c HEAD, or @c DELETE. */
    ucall_string_t body;
    /** @brief Length of @c body in bytes. */
    size_t body_length;

    /** @brief Output for the received response, which owns its headers and body. Free with
     *    @c ucall_received_http_response_free() once done. */
    ucall_received_http_response_t* response;

    /** @brief Per-request timeouts, retries, redirects, and security. Zeroed fields take their defaults. */
    ucall_request_options_t options;
} ucall_client_call_t;

/**
 *  @brief Makes a single HTTP call, blocking until the response arrives or returning once queued.
 *
 *  @note @b Thread-safe. A blocking call holds its calling thread; deferred calls let one thread keep
 *    any number in flight, each with its own outcome.
 *
 *  @par Blocking and Asynchronous Calls
 *
 *  A blocking call, the default, returns with @c response written and the final status in @c outcome.
 *  A deferred one, with @c completion set to @c ucall_completion_deferred_k, returns at once and the
 *  client's own connection thread drives the exchange: it writes @c response, then stores the final
 *  status in @c outcome. Until then @c outcome->status reads @c ucall_status_pending_k, and the caller
 *  waits with @c ucall_outcome_wait() or polls.
 *
 *  When calling out to another service from @b inside a server endpoint, blocking holds the worker
 *  thread. To keep serving other requests while waiting, re-enter the server loop by calling
 *  @c ucall_server_take_calls() from within the handler.
 *
 *  @par Headers
 *
 *  Some of the standard HTTP headers are automatically managed by UCall, such as:
 *  - @c Host: Set from the @c url field.
 *  - @c Content-Length: Set based on the @c body_length field.
 *  - @c User-Agent: Set to a default value identifying the UCall client.
 *
 *  Those shouldn't be included in the @c headers array.
 *  All header names will be normalized to lower-case before sending.
 *
 *  @par Redirects
 *
 *  HTTP redirects are a two-step protocol mechanism: the server responds with a 3xx status code
 *  and @c Location header, and the client automatically follows by making a new request.
 *
 *  Common redirect codes:
 *  - @b 301/308: Permanent redirects (domain changes, HTTPS migration). Client may cache.
 *  - @b 302/307: Temporary redirects (maintenance, A/B testing). Client shouldn't cache.
 *  - @b 303: After @c POST submission - redirect to result page via @c GET (prevents duplicate submissions).
 *  - @b 304: Not Modified - cached version is still fresh, saves bandwidth.
 *
 *  Redirect chains occur when multiple redirects happen in sequence, for example
 *  http://site.com → https://site.com → https://www.site.com. Chains longer than
 *  @c ucall_request_options_t::max_redirects fail with @c ucall_status_malformed_k.
 *
 *  @par Example
 *
 *  @code{.c}
 *  ucall_outcome_t outcome;
 *  ucall_client_t client;
 *  ucall_client_config_t config = {0};
 *  ucall_client_init(&(ucall_client_init_t){.outcome = &outcome, .config = &config, .client = &client});
 *
 *  ucall_received_http_response_t response;
 *  ucall_client_call(&(ucall_client_call_t){.client = client, .outcome = &outcome,
 *      .url = "http://localhost:8080/sum?a=1&b=2", .verb = ucall_verb_get_k, .response = &response});
 *
 *  if (outcome.status == ucall_status_success_k) {
 *      ucall_string_t body;
 *      size_t body_length;
 *      ucall_received_http_response_body(&(ucall_received_http_response_body_t){.client = client,
 *          .outcome = &outcome, .response = response, .body = &body, .body_length = &body_length});
 *      // process `body`...
 *      ucall_received_http_response_free(response);
 *  }
 *  ucall_client_free(client);
 *  @endcode
 */
UCALL_EXPORT void ucall_client_call(ucall_client_call_t* arguments);

/** @brief Arguments of @c ucall_client_websocket_connect(). */
typedef struct ucall_client_websocket_connect_t {
    ucall_client_t client;
    ucall_outcome_t* outcome;
    /** @brief WebSocket URL with scheme: @c ws:// or @c ws+noise://. */
    ucall_string_t url;
    /** @brief Output for the WebSocket handle. */
    ucall_websocket_t* websocket;
    /** @brief Timeouts, retries, and security for the handshake. Zeroed fields take their defaults. */
    ucall_request_options_t options;
} ucall_client_websocket_connect_t;

/**
 *  @brief Establishes a WebSocket connection and blocks until the handshake completes.
 *  @note @b Thread-safe.
 */
UCALL_EXPORT void ucall_client_websocket_connect(ucall_client_websocket_connect_t* arguments);

/** @brief Arguments of @c ucall_client_websocket_receive(). */
typedef struct ucall_client_websocket_receive_t {
    ucall_client_t client;
    /** @brief Receives @c ucall_status_timeout_k if no message arrived, @c ucall_status_connection_closed_k
     *    once the peer closes the connection. */
    ucall_outcome_t* outcome;
    /** @brief WebSocket handle from @c ucall_client_websocket_connect(). */
    ucall_websocket_t websocket;
    /** @brief Output for the received message type. */
    ucall_websocket_opcode_t* opcode;
    /** @brief Output for the message payload. Valid until the next call. */
    ucall_string_t* data;
    /** @brief Output for the length of the message payload. */
    size_t* data_length;
    /** @brief Maximum time to block. Zero returns immediately. */
    uint32_t timeout_micro_seconds;
} ucall_client_websocket_receive_t;

/**
 *  @brief Blocks until a message arrives on an established WebSocket connection.
 *
 *  @note @b Thread-safe against @c ucall_client_websocket_send() on the same @c websocket,
 *    so one thread may receive while another sends. Two threads must not receive concurrently.
 *
 *  Unlike the server side, which dispatches to @c ucall_websocket_callback_t from within its
 *  own loop, the client receives on a loop the application owns.
 */
UCALL_EXPORT void ucall_client_websocket_receive(ucall_client_websocket_receive_t* arguments);

/** @brief Arguments of @c ucall_received_http_response_header(). */
typedef struct ucall_received_http_response_header_t {
    ucall_client_t client;
    /** @brief Receives @c ucall_status_not_found_k if the response has no such header. */
    ucall_outcome_t* outcome;
    /** @brief The received response from @c ucall_client_call(). */
    ucall_received_http_response_t response;
    /** @brief The name of the HTTP header to extract (case-insensitive). */
    ucall_string_t name;
    /** @brief The length of the @c name string. */
    size_t name_length;
    /** @brief Output for the start of the header value string. */
    ucall_string_t* value;
    /** @brief Output for the length of the header value string. */
    size_t* value_length;
} ucall_received_http_response_header_t;

/**
 *  @brief Extracts the named string header from the received response.
 *
 *  Header name matching is case-insensitive per RFC 7230.
 *
 *  @note @b Thread-safe across responses. Two threads must not operate on the
 *    @b same @c response concurrently.
 */
UCALL_EXPORT void ucall_received_http_response_header(ucall_received_http_response_header_t* arguments);

/** @brief Arguments of @c ucall_received_http_response_body(). */
typedef struct ucall_received_http_response_body_t {
    ucall_client_t client;
    ucall_outcome_t* outcome;
    /** @brief The received response from @c ucall_client_call(). */
    ucall_received_http_response_t response;
    /** @brief Output for the start of the body content. */
    ucall_string_t* body;
    /** @brief Output for the length of the body content. */
    size_t* body_length;
} ucall_received_http_response_body_t;

/**
 *  @brief Extracts the body content from the received response.
 *
 *  @note @b Thread-safe across responses. Two threads must not operate on the
 *    @b same @c response concurrently.
 */
UCALL_EXPORT void ucall_received_http_response_body(ucall_received_http_response_body_t* arguments);

/**
 *  @brief Frees the received response handle. Does nothing for @c NULL.
 *  @param[in] response The received response from @c ucall_client_call(), or @c NULL.
 *
 *  @note @b Thread-safe across responses. Two threads must not operate on the
 *    @b same @p response concurrently.
 */
UCALL_EXPORT void ucall_received_http_response_free(ucall_received_http_response_t response);

/** @brief Arguments of @c ucall_client_websocket_send(). */
typedef struct ucall_client_websocket_send_t {
    ucall_client_t client;
    ucall_outcome_t* outcome;
    /** @brief WebSocket connection handle from @c ucall_client_websocket_connect(). */
    ucall_websocket_t websocket;
    /** @brief Message type (text, binary, ping, pong). */
    ucall_websocket_opcode_t opcode;
    /** @brief Message payload. */
    ucall_string_t data;
    /** @brief Length of the message payload in bytes. */
    size_t data_length;
} ucall_client_websocket_send_t;

/**
 *  @brief Sends a message over an established WebSocket connection.
 *  @note @b Thread-safe.
 */
UCALL_EXPORT void ucall_client_websocket_send(ucall_client_websocket_send_t* arguments);

/**
 *  @brief Closes a WebSocket connection.
 *  @param[in] client Client handle from @c ucall_client_init().
 *  @param[in] websocket WebSocket connection handle to close.
 *
 *  @note @b Thread-safe.
 */
UCALL_EXPORT void ucall_client_websocket_close(ucall_client_t client, ucall_websocket_t websocket);

#pragma endregion Clients

#pragma region Servers

/**
 *  @brief One virtualized network interface, and every policy applying to what arrives on it.
 *
 *  An interface is an address the server answers on, together with the security posture and
 *  admission limits for the connections it accepts. Several of them live under one server, which
 *  is what lets a single server answer VPN-internal Noise traffic and public plaintext at once,
 *  across as many physical devices as the machine has.
 *
 *  Encryption and admission live on the interface rather than on the server, so one server
 *  serves plaintext on loopback for health checks while requiring Noise on the wire - without
 *  standing up a second server to do it.
 *
 *  @par Example
 *  @code{.c}
 *  ucall_network_interface_t interfaces[] = {
 *      {.address = "127.0.0.1:8545"},
 *      {.address = "0.0.0.0:8546", .device_name = "eth0",
 *       .security_mode = ucall_security_noise_xx_k, .noise_private_key = &key},
 *  };
 *  ucall_server_config_t config = {.interfaces = interfaces, .interfaces_count = 2};
 *  @endcode
 */
typedef struct ucall_network_interface_t {
    /** @brief Listening address in "host:port" form. Required. */
    char const* address;
    /**
     *  @brief Physical device to pin this interface to with @c SO_BINDTODEVICE, such as "eth0",
     *    or @c NULL to bind by address alone.
     *
     *  Several interfaces may name one device, and one interface bound to @c 0.0.0.0 spans every
     *  device the machine has - which is why the two are separate fields rather than one.
     */
    char const* device_name;

    /**
     *  @brief Encryption for connections accepted here. Default: ucall_security_none_k.
     *  @note Server-side @c ucall_security_noise_kk_k is rejected, since an interface cannot name
     *    the initiator static key that pattern hashes before the first message.
     */
    ucall_security_mode_t security_mode;
    /** @brief Server identity for handshakes. Required when @c security_mode is not none. */
    ucall_noise_key_t const* noise_private_key;
    /** @brief Vets client static keys. Required for XX. Default: NULL. */
    ucall_peer_authorizer_t peer_authorizer;
    /** @brief Passed verbatim to @c peer_authorizer. */
    void* peer_authorizer_context;

    /**
     *  @brief How many event loops accept on this interface. Default: inferred from the hardware.
     *
     *  Zero means @c min(receive queues on @c device_name, physical cores on its memory domain).
     *  Physical, not logical: hyperthread siblings measure at roughly a third of a core each for
     *  this workload, not a full one.
     *
     *  The server creates the @b maximum across interfaces, never the sum, and clamps it to the
     *  machine's core count so threads cannot be oversubscribed. Two interfaces on two devices
     *  each asking for sixteen loops on a sixteen-core host therefore yield sixteen threads
     *  holding thirty-two listening sockets, not thirty-two threads. An interface asking for
     *  fewer loops than the server ends up with is served by the first that many; the rest never
     *  accept on it. Each participating loop gets its own socket in this address's
     *  @c SO_REUSEPORT group, so no listening socket is ever shared between threads.
     *
     *  @sa @c ucall_server_init_t::resolved reports what the server settled on.
     */
    size_t event_loops;

    /**
     *  @brief Submission queue entries this interface needs, on each loop that serves it.
     *    Default: @c max_concurrent_connections.
     *
     *  A loop's ring is sized to the @b sum over the interfaces it serves, because one loop has
     *  one ring and must hold every outstanding operation across all of them. Sizing it here
     *  rather than server-wide is what lets an interface hosting thousands of connections ask
     *  for a deeper ring than one hosting a handful.
     *
     *  Meaningful only on backends built around a submission ring, and each imposes its own
     *  ceiling - Linux @c io_uring allows 32'768 entries and allocates a completion queue of
     *  twice that, so a sum exceeding it fails @c ucall_server_init() with
     *  @c ucall_status_connection_failed_k. Below @c max_concurrent_connections the ring merely
     *  flushes early, costing a system call per burst rather than failing, which is why the
     *  library raises it to that floor rather than refusing. Backends without a ring ignore
     *  this field.
     */
    size_t queue_depth;

    /**
     *  @brief Connections this interface may hold open at once, so one cannot starve another.
     *    Default: 1024.
     *
     *  The one independent size on this struct: @c queue_depth and the kernel's listen backlog
     *  are both derived from it unless overridden. Each connection costs one file descriptor
     *  and two pages of buffer, so 65'536 connections is roughly half a gigabyte of arena, and
     *  the descriptor total across every interface and event loop must stay under
     *  @c RLIMIT_NOFILE - commonly 1024 unraised, 1'048'576 tuned. Exhausting it does not fail
     *  the server; the interface simply stops accepting until a connection is released, and
     *  pending handshakes queue in the kernel's backlog behind it.
     *
     *  @note The backlog handed to @c listen() is this value, which the operating system then
     *    clamps to its own ceiling - @c net.core.somaxconn on Linux, 4096 on a modern kernel
     *    and 128 on an old one. That clamp is silent rather than reported, and once the queue
     *    overflows a completed handshake is dropped and the client retransmits.
     */
    size_t max_concurrent_connections;
} ucall_network_interface_t;

/**
 *  @brief Configuration parameters for the UCall server.
 *  @sa Initialize with @c ucall_server_init().
 *
 *  @par Example
 *  @code{.c}
 *  ucall_network_interface_t interfaces[] = {{.address = "0.0.0.0:8080", .queue_depth = 512}};
 *  ucall_server_config_t config = {
 *      .interfaces = interfaces,
 *      .interfaces_count = 1,
 *      .log = {.callback = write_log_line, .format = ucall_log_format_json_k},
 *      .metrics_address = "127.0.0.1:8125",
 *      .metrics_sample_rate = 1.0f,
 *      .metrics_prefix = "myapp",
 *      .metrics_tags = "env:prod,region:us-east"
 *  };
 *  @endcode
 */
typedef struct ucall_server_config_t {
    /**
     *  @brief Interfaces to answer on. At least one is required.
     *
     *  The array and every string it points at must outlive the server. Parallelism is the
     *  largest @c event_loops among the resolved interfaces, not this count.
     */
    ucall_network_interface_t const* interfaces;
    /** @brief Entries in @c interfaces. At least one; zero fails with @c ucall_status_invalid_argument_k. */
    size_t interfaces_count;

    /** @brief Where log lines go. Default: nowhere. */
    ucall_log_t log;

    /** @brief StatsD UDP endpoint "host:port". NULL = disabled. Default: NULL. */
    char const* metrics_address;
    /** @brief Sampling rate [0.0, 1.0]. Default: 1.0. */
    float metrics_sample_rate;
    /** @brief Metric name prefix. Default: "ucall". */
    char const* metrics_prefix;
    /** @brief Global tags "key:val,key:val". Default: NULL. */
    char const* metrics_tags;
} ucall_server_config_t;

/** @brief Arguments of @c ucall_server_init(). */
typedef struct ucall_server_init_t {
    ucall_outcome_t* outcome;
    /** @brief Requested configuration. Zeroed fields take their documented defaults. */
    ucall_server_config_t const* config;
    /**
     *  @brief Optional output for @c config with every default filled in, including each interface's
     *    @c event_loops. The arrays and strings it points at belong to the server until @c ucall_server_free().
     */
    ucall_server_config_t* resolved;
    /** @brief Output for the new server. Free with @c ucall_server_free() at the end. */
    ucall_server_t* server;
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

#pragma region Endpoint Registration

/**
 *  @brief Callback type for handling incoming requests on the server side.
 *  @param[in] request The received request handle.
 *  @param[in] context User-supplied context pointer from the endpoint registration.
 */
typedef void (*ucall_received_http_request_callback_t)(ucall_received_http_request_t request, void* context);

/** @brief Arguments of @c ucall_server_add_http_endpoint(). */
typedef struct ucall_server_add_http_endpoint_t {
    ucall_server_t server;
    /** @brief Receives a failure for a duplicate endpoint, an invalid template, or a lack of memory. */
    ucall_outcome_t* outcome;
    /**
     *  @brief URI template string with optional @c {variable} placeholders.
     *    Must be @b unique across all registered endpoints.
     */
    ucall_string_t uri_template;
    /** @brief HTTP method for this endpoint. */
    ucall_verb_t verb;
    /** @brief Function pointer to the callback. */
    ucall_received_http_request_callback_t callback;
    /** @brief Optional payload/tag for metadata (e.g., for CPython runtime). */
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

/**
 *  @brief Arguments of @c ucall_server_add_batch_endpoint().
 *
 *  Batching improves throughput for high-latency operations (e.g., GPU inference)
 *  by accumulating multiple requests and processing them together.
 */
typedef struct ucall_server_add_batch_endpoint_t {
    ucall_server_t server;
    /** @brief Receives a failure for a duplicate endpoint, an invalid template, or a lack of memory. */
    ucall_outcome_t* outcome;
    /**
     *  @brief URI template string with optional @c {variable} placeholders.
     *    Must be @b unique across all registered endpoints.
     */
    ucall_string_t uri_template;
    /** @brief HTTP method for this endpoint. */
    ucall_verb_t verb;
    /** @brief Function pointer to the batch callback. */
    ucall_received_batch_http_request_callback_t callback;
    /** @brief Optional payload/tag for metadata (e.g., for CPython runtime). */
    void* context;

    /** @brief Optimal batch size. Dispatch immediately when reached. Default: 1. */
    size_t min_batch_size;
    /** @brief Maximum requests per batch. Force dispatch when reached. Default: 32. */
    size_t max_batch_size;
    /** @brief Maximum wait time for partial batches. Default: 10'000, i.e. 10 milliseconds. */
    size_t max_latency_micro_seconds;
} ucall_server_add_batch_endpoint_t;

/**
 *  @brief Registers a batching callback to collect multiple requests and process them together.
 *    Very handy for batch-processing and high-latency operations (e.g., GPU inference).
 *
 *  This differs from JSON-RPC batching: here the server aggregates requests from different
 *  sources and dispatches them together, rather than the client batching into a JSON array.
 *
 *  Batching behavior:
 *  - Batch size < @c min_batch_size: Wait for more requests (up to @c max_latency_micro_seconds).
 *  - Batch size >= @c min_batch_size: Dispatch immediately (optimal utilization).
 *  - Batch size >= @c max_batch_size: Force dispatch (prevent unbounded growth).
 *
 *  @par Example
 *  @code{.c}
 *  void inference_batch(ucall_received_batch_http_request_t batch, void* context) {
 *      ucall_server_t server = (ucall_server_t)context;
 *      size_t count = ucall_server_batch_size(server, batch);
 *      float* inputs = malloc(count * INPUT_DIM * sizeof(float));
 *      ucall_received_http_request_t request;
 *      ucall_string_t body;
 *      size_t body_length;
 *
 *      // Unpack all requests and prepare batch input
 *      for (size_t i = 0; i < count; i++) {
 *          ucall_server_batch_unpack(&(ucall_server_batch_unpack_t){
 *              .server = server, .batch = batch, .index = i, .request = &request});
 *          ucall_server_request_body(&(ucall_server_request_body_t){
 *              .server = server, .request = request, .body = &body, .body_length = &body_length});
 *          memcpy(&inputs[i * INPUT_DIM], body, INPUT_DIM * sizeof(float));
 *      }
 *
 *      // Single GPU kernel call for entire batch
 *      float* outputs = run_gpu_inference(inputs, count);
 *
 *      // Reply to each request individually
 *      for (size_t i = 0; i < count; i++) {
 *          ucall_server_batch_unpack(&(ucall_server_batch_unpack_t){
 *              .server = server, .batch = batch, .index = i, .request = &request});
 *          ucall_server_reply_content(&(ucall_server_reply_content_t){.server = server, .request = request,
 *              .body = (char const*)&outputs[i * OUTPUT_DIM], .body_length = OUTPUT_DIM * sizeof(float)});
 *      }
 *      free(inputs); free(outputs);
 *  }
 *
 *  ucall_server_add_batch_endpoint(&(ucall_server_add_batch_endpoint_t){
 *      .server = server, .outcome = &outcome,
 *      .uri_template = "/inference", .verb = ucall_verb_post_k,
 *      .callback = inference_batch, .context = server,
 *      .min_batch_size = 8,                 // Wait for at least 8 requests
 *      .max_batch_size = 64,                // Process max 64 at once
 *      .max_latency_micro_seconds = 5000}); // Wait max 5ms
 *  @endcode
 *
 *  @sa To extract the number of calls in the batch - @c ucall_server_batch_size().
 *  @sa To enumerate separate calls from within the batch - @c ucall_server_batch_unpack().
 *
 *  @note Call during setup only, before any thread enters @c ucall_server_take_calls().
 */
UCALL_EXPORT void ucall_server_add_batch_endpoint(ucall_server_add_batch_endpoint_t* arguments);

/** @brief Arguments of @c ucall_server_add_websocket_endpoint(). */
typedef struct ucall_server_add_websocket_endpoint_t {
    ucall_server_t server;
    /** @brief Receives a failure for a duplicate endpoint, an invalid template, or a lack of memory. */
    ucall_outcome_t* outcome;
    /**
     *  @brief URI template string with optional @c {variable} placeholders.
     *    Must be @b unique across all registered endpoints.
     */
    ucall_string_t uri_template;
    /** @brief Function pointer to handle WebSocket events. */
    ucall_websocket_callback_t callback;
    /** @brief Optional user-defined context pointer passed to all event callbacks. */
    void* context;
} ucall_server_add_websocket_endpoint_t;

/**
 *  @brief Registers a WebSocket endpoint to accept incoming connections.
 *
 *  On HTTP Upgrade request, establishes a WebSocket connection and invokes @c callback for
 *  all events (open, message, error, close) on a server worker thread.
 *
 *  @note Call during setup only, before any thread enters @c ucall_server_take_calls().
 */
UCALL_EXPORT void ucall_server_add_websocket_endpoint(ucall_server_add_websocket_endpoint_t* arguments);

#pragma endregion Endpoint Registration

#pragma region Event Loop

/**
 *  @brief Performs a single blocking round of polling on the current calling thread.
 *  @param[in] server Must be pre-initialized with @c ucall_server_init().
 *  @param[in] thread_index Unique thread identifier, below the largest @c event_loops among the
 *    interfaces of the resolved configuration. Each index is one event loop.
 *
 *  @note @b Thread-safe when every caller passes a distinct @p thread_index.
 *    Reusing an index corrupts server state.
 */
UCALL_EXPORT void ucall_server_take_call(ucall_server_t server, uint16_t thread_index);

/**
 *  @brief Blocks current thread, more efficient than a @c while loop with @c ucall_server_take_call().
 *
 *  @param[in] server Must be pre-initialized with @c ucall_server_init().
 *  @param[in] thread_index Unique thread identifier, below the largest @c event_loops among the
 *    interfaces of the resolved configuration. Each index is one event loop.
 *
 *  @note @b Thread-safe when every caller passes a distinct @p thread_index.
 *    Reusing an index corrupts server state.
 */
UCALL_EXPORT void ucall_server_take_calls(ucall_server_t server, uint16_t thread_index);

#pragma endregion Event Loop

#pragma region Received Requests

/**
 *  @brief Returns the HTTP method of the received request. Never @c ucall_verb_any_k.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request inside the @c ucall_received_http_request_callback_t.
 *
 *  Needed by endpoints registered with @c ucall_verb_any_k, which match every method.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
UCALL_EXPORT ucall_verb_t ucall_server_request_verb(ucall_server_t server, ucall_received_http_request_t request);

/**
 *  @brief Returns the number of path components of the received request.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request inside the @c ucall_received_http_request_callback_t.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
UCALL_EXPORT size_t ucall_server_request_path_segments_count(ucall_server_t server,
                                                             ucall_received_http_request_t request);

/** @brief Arguments of @c ucall_server_request_path_segment(). */
typedef struct ucall_server_request_path_segment_t {
    ucall_server_t server;
    /** @brief Receives @c ucall_status_not_found_k when @c index is past the last segment. */
    ucall_outcome_t* outcome;
    /** @brief The received request inside the @c ucall_received_http_request_callback_t. */
    ucall_received_http_request_t request;
    /** @brief The zero-based index of the path component to extract. */
    size_t index;
    /** @brief Output for the start of the path component string. */
    ucall_string_t* segment;
    /** @brief Output for the length of the path component string. */
    size_t* segment_length;
} ucall_server_request_path_segment_t;

/**
 *  @brief Extracts an indexed path component from the received request.
 *
 *  Useful for RESTful APIs with path parameters, e.g., "/users/{id}/posts/{postId}".
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @c request concurrently.
 */
UCALL_EXPORT void ucall_server_request_path_segment(ucall_server_request_path_segment_t* arguments);

/** @brief Arguments of @c ucall_server_request_path_parameter(). */
typedef struct ucall_server_request_path_parameter_t {
    ucall_server_t server;
    /** @brief Receives @c ucall_status_not_found_k when the template has no such placeholder. */
    ucall_outcome_t* outcome;
    /** @brief The received request inside the @c ucall_received_http_request_callback_t. */
    ucall_received_http_request_t request;
    /** @brief The @b case-sensitive placeholder name, without braces. */
    ucall_string_t name;
    /** @brief The length of the @c name string. */
    size_t name_length;
    /** @brief Output for the start of the captured value. */
    ucall_string_t* value;
    /** @brief Output for the length of the captured value. */
    size_t* value_length;
} ucall_server_request_path_parameter_t;

/**
 *  @brief Extracts a named path parameter captured by the endpoint's URI template.
 *
 *  For an endpoint registered as @c "/users/{id}/posts/{post_id}" receiving @c "/users/7/posts/3",
 *  a @c name of @c "id" yields @c "7". A greedy wildcard @c {*path} captures the remaining segments
 *  including separators.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @c request concurrently.
 */
UCALL_EXPORT void ucall_server_request_path_parameter(ucall_server_request_path_parameter_t* arguments);

/** @brief Arguments of @c ucall_server_request_query_parameter(). */
typedef struct ucall_server_request_query_parameter_t {
    ucall_server_t server;
    /** @brief Receives @c ucall_status_not_found_k when the query has no such parameter. */
    ucall_outcome_t* outcome;
    /** @brief The received request inside the @c ucall_received_http_request_callback_t. */
    ucall_received_http_request_t request;
    /** @brief The @b case-sensitive name of the parameter to extract. */
    ucall_string_t name;
    /** @brief The length of the @c name string. */
    size_t name_length;
    /** @brief Output for the start of the parameter value string. */
    ucall_string_t* value;
    /** @brief Output for the length of the parameter value string. */
    size_t* value_length;
} ucall_server_request_query_parameter_t;

/**
 *  @brief Extracts the named string parameter from the received request.
 *
 *  Unlike HTTP headers, query parameters are case-sensitive by specification, but server-dependent
 *  in practice. An example would be ASP.NET / IIS, which treats "?id" and "?ID" as same parameters.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @c request concurrently.
 */
UCALL_EXPORT void ucall_server_request_query_parameter(ucall_server_request_query_parameter_t* arguments);

/** @brief Arguments of @c ucall_server_request_header(). */
typedef struct ucall_server_request_header_t {
    ucall_server_t server;
    /** @brief Receives @c ucall_status_not_found_k when the request has no such header. */
    ucall_outcome_t* outcome;
    /** @brief The received request inside the @c ucall_received_http_request_callback_t. */
    ucall_received_http_request_t request;
    /** @brief The name of the HTTP header to extract (case-insensitive). */
    ucall_string_t name;
    /** @brief The length of the @c name string. */
    size_t name_length;
    /** @brief Output for the start of the header value string. */
    ucall_string_t* value;
    /** @brief Output for the length of the header value string. */
    size_t* value_length;
} ucall_server_request_header_t;

/**
 *  @brief Extracts the named string header from the received request.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @c request concurrently.
 */
UCALL_EXPORT void ucall_server_request_header(ucall_server_request_header_t* arguments);

/** @brief Arguments of @c ucall_server_request_body(). */
typedef struct ucall_server_request_body_t {
    ucall_server_t server;
    ucall_outcome_t* outcome;
    /** @brief The received request inside the @c ucall_received_http_request_callback_t. */
    ucall_received_http_request_t request;
    /** @brief Output for the start of the body content. */
    ucall_string_t* body;
    /** @brief Output for the length of the body content. */
    size_t* body_length;
} ucall_server_request_body_t;

/**
 *  @brief Extracts the body content from the received request.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @c request concurrently.
 */
UCALL_EXPORT void ucall_server_request_body(ucall_server_request_body_t* arguments);

/** @brief Arguments of @c ucall_server_request_body_chunk(). */
typedef struct ucall_server_request_body_chunk_t {
    ucall_server_t server;
    /** @brief Receives @c ucall_status_would_block_k if more data is expected but none has arrived. */
    ucall_outcome_t* outcome;
    /** @brief The received request inside the @c ucall_received_http_request_callback_t. */
    ucall_received_http_request_t request;
    /** @brief Output for the start of the chunk. Aliases the receive buffer. */
    ucall_string_t* chunk;
    /** @brief Output for the length of the chunk. Zero when no data is available yet. */
    size_t* chunk_length;
    /** @brief Output flag, false once the final chunk has been delivered. */
    bool* has_more;
} ucall_server_request_body_chunk_t;

/**
 *  @brief Pulls the next chunk of a request body that is still arriving.
 *
 *  Endpoints registered as streaming are invoked as soon as headers are parsed, before the body
 *  is complete. Without this, a multi-gigabyte upload must be buffered in full before the handler
 *  runs, which is both a memory hazard and a denial-of-service vector.
 *
 *  @warning The returned @c chunk is valid only until the next call on this @c request.
 *  @sa Use @c ucall_server_request_body() for endpoints that are not registered as streaming.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @c request concurrently.
 */
UCALL_EXPORT void ucall_server_request_body_chunk(ucall_server_request_body_chunk_t* arguments);

/**
 *  @brief Returns the number of parts in a @c multipart/form-data request body. Zero if it is not multipart.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request inside the @c ucall_received_http_request_callback_t.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
UCALL_EXPORT size_t ucall_server_request_part_count(ucall_server_t server, ucall_received_http_request_t request);

/** @brief Arguments of @c ucall_server_request_part_at(). */
typedef struct ucall_server_request_part_at_t {
    ucall_server_t server;
    ucall_outcome_t* outcome;
    /** @brief The received request inside the @c ucall_received_http_request_callback_t. */
    ucall_received_http_request_t request;
    /** @brief Zero-based index of the part, below @c ucall_server_request_part_count(). */
    size_t index;
    /** @brief Output for the part name from @c Content-Disposition. */
    ucall_string_t* name;
    /** @brief Output for the length of the part name. */
    size_t* name_length;
    /** @brief Output for the part's @c Content-Type. Empty if absent. */
    ucall_string_t* content_type;
    /** @brief Output for the length of the content type. */
    size_t* content_type_length;
    /** @brief Output for the part payload. Aliases the receive buffer, never copied. */
    ucall_string_t* data;
    /** @brief Output for the length of the part payload. */
    size_t* data_length;
} ucall_server_request_part_at_t;

/**
 *  @brief Extracts one part of a @c multipart/form-data request body by index.
 *
 *  The payload is handed over without decoding. Media formats are the application's concern -
 *  pass @c data straight to an image or video decoder to keep the path copy-free.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @c request concurrently.
 */
UCALL_EXPORT void ucall_server_request_part_at(ucall_server_request_part_at_t* arguments);

/**
 *  @brief Returns the number of individual requests in a batch.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] batch Batch request handle from batch callback.
 *  @return Number of requests in the batch (always >= 1).
 *
 *  @note @b Thread-safe across batches. Two threads must not operate on the
 *    @b same @p batch concurrently.
 */
UCALL_EXPORT size_t ucall_server_batch_size(ucall_server_t server, ucall_received_batch_http_request_t batch);

/** @brief Arguments of @c ucall_server_batch_unpack(). */
typedef struct ucall_server_batch_unpack_t {
    ucall_server_t server;
    /** @brief Receives @c ucall_status_invalid_argument_k when @c index is not below the batch size. */
    ucall_outcome_t* outcome;
    /** @brief Batch request handle from batch callback. */
    ucall_received_batch_http_request_t batch;
    /** @brief Zero-based index of the request to extract. */
    size_t index;
    /** @brief Output for the extracted request handle. */
    ucall_received_http_request_t* request;
} ucall_server_batch_unpack_t;

/**
 *  @brief Unpacks an individual request from a batch by index.
 *
 *  @note @b Thread-safe across batches. Two threads must not operate on the
 *    @b same @c batch concurrently.
 */
UCALL_EXPORT void ucall_server_batch_unpack(ucall_server_batch_unpack_t* arguments);

#pragma endregion Received Requests

#pragma region Planned Replies

/** @brief Arguments of @c ucall_server_reply_content(). */
typedef struct ucall_server_reply_content_t {
    ucall_server_t server;
    ucall_outcome_t* outcome;
    /** @brief The received request to reply to. */
    ucall_received_http_request_t request;
    /** @brief Array of custom headers ("Content-Type", "application/json", "X-Foo", "bar"). */
    ucall_string_t const* headers;
    /** @brief Optional array of lengths (NULL = use strlen). */
    size_t const* headers_lengths;
    /** @brief Number of header name-value pairs (total strings / 2). */
    size_t headers_count;
    /** @brief Response body content. Can be NULL for empty body. */
    ucall_string_t body;
    /** @brief Length of body in bytes. */
    size_t body_length;
} ucall_server_reply_content_t;

/**
 *  @brief Sends an HTTP response with custom headers and body.
 *
 *  Automatically sets standard headers: @c Content-Length, @c Date, @c Server.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @c request concurrently.
 */
UCALL_EXPORT void ucall_server_reply_content(ucall_server_reply_content_t* arguments);

/** @brief Arguments of @c ucall_server_reply_error(). */
typedef struct ucall_server_reply_error_t {
    ucall_server_t server;
    ucall_outcome_t* outcome;
    /** @brief The received request to reply to. */
    ucall_received_http_request_t request;
    /** @brief HTTP error status code (400, 404, 500, etc.). */
    ucall_http_status_t http_status;
    /** @brief Error message text. */
    ucall_string_t message;
    /** @brief Length of message in bytes. */
    size_t message_length;
} ucall_server_reply_error_t;

/**
 *  @brief Sends an error response with plain text message.
 *
 *  Automatically sets @c Content-Type: @c text/plain.
 *  For errors requiring custom headers, use @c ucall_server_reply_content() instead.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @c request concurrently.
 */
UCALL_EXPORT void ucall_server_reply_error(ucall_server_reply_error_t* arguments);

/** @brief Arguments of @c ucall_server_reply_vectored(). */
typedef struct ucall_server_reply_vectored_t {
    ucall_server_t server;
    ucall_outcome_t* outcome;
    /** @brief The received request to reply to. */
    ucall_received_http_request_t request;
    /** @brief Array of custom headers ("Content-Type", "application/json"). */
    ucall_string_t const* headers;
    /** @brief Optional array of lengths (NULL = use strlen). */
    size_t const* headers_lengths;
    /** @brief Number of header name-value pairs (total strings / 2). */
    size_t headers_count;
    /** @brief Array of buffers concatenated, in order, to form the body. */
    ucall_buffer_t const* parts;
    /** @brief Number of entries in @c parts. */
    size_t parts_count;
} ucall_server_reply_vectored_t;

/**
 *  @brief Sends a response assembled from several non-contiguous buffers.
 *
 *  Lets a handler reply with a header, a tensor, and a trailer without concatenating them
 *  into a staging buffer first.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @c request concurrently.
 */
UCALL_EXPORT void ucall_server_reply_vectored(ucall_server_reply_vectored_t* arguments);

#pragma region Streaming and Zero Copy Replies

/** @brief Arguments of @c ucall_server_reply_begin(). */
typedef struct ucall_server_reply_begin_t {
    ucall_server_t server;
    ucall_outcome_t* outcome;
    /** @brief The received request to reply to. */
    ucall_received_http_request_t request;
    /** @brief HTTP status code for the response. */
    ucall_http_status_t http_status;
    /** @brief Array of custom headers. Omit @c Content-Length to use chunked encoding. */
    ucall_string_t const* headers;
    /** @brief Optional array of lengths (NULL = use strlen). */
    size_t const* headers_lengths;
    /** @brief Number of header name-value pairs (total strings / 2). */
    size_t headers_count;
} ucall_server_reply_begin_t;

/**
 *  @brief Begins a streamed response, emitting the status line and headers.
 *
 *  Must be followed by zero or more @c ucall_server_reply_chunk() calls and exactly one
 *  @c ucall_server_reply_end(). Supplying @c Content-Length switches to identity encoding,
 *  which is what @c Range responses need.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @c request concurrently.
 */
UCALL_EXPORT void ucall_server_reply_begin(ucall_server_reply_begin_t* arguments);

/** @brief Arguments of @c ucall_server_reply_chunk(). */
typedef struct ucall_server_reply_chunk_t {
    ucall_server_t server;
    ucall_outcome_t* outcome;
    /** @brief The received request being replied to. */
    ucall_received_http_request_t request;
    /** @brief Chunk payload. Copied before returning. */
    ucall_string_t data;
    /** @brief Length of the chunk in bytes. */
    size_t data_length;
} ucall_server_reply_chunk_t;

/**
 *  @brief Appends one chunk to a response opened with @c ucall_server_reply_begin().
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @c request concurrently.
 */
UCALL_EXPORT void ucall_server_reply_chunk(ucall_server_reply_chunk_t* arguments);

/** @brief Arguments of @c ucall_server_reply_end(). */
typedef struct ucall_server_reply_end_t {
    ucall_server_t server;
    ucall_outcome_t* outcome;
    /** @brief The received request being replied to. Invalid once the call returns. */
    ucall_received_http_request_t request;
} ucall_server_reply_end_t;

/**
 *  @brief Completes a response opened with @c ucall_server_reply_begin().
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @c request concurrently.
 */
UCALL_EXPORT void ucall_server_reply_end(ucall_server_reply_end_t* arguments);

/** @brief Arguments of @c ucall_server_reply_file(). */
typedef struct ucall_server_reply_file_t {
    ucall_server_t server;
    ucall_outcome_t* outcome;
    /** @brief The received request to reply to. */
    ucall_received_http_request_t request;
    /** @brief An open, readable, seekable descriptor. @b Ownership transfers to UCall. */
    int file_descriptor;
    /** @brief Byte offset within the file at which to start. */
    uint64_t offset;
    /** @brief Number of bytes to send. Zero sends through end of file. */
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
 *    connections using @c ucall_security_noise_* fall back to a buffered copy.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @c request concurrently.
 */
UCALL_EXPORT void ucall_server_reply_file(ucall_server_reply_file_t* arguments);

/** @brief Arguments of @c ucall_server_reply_path(). */
typedef struct ucall_server_reply_path_t {
    ucall_server_t server;
    ucall_outcome_t* outcome;
    /** @brief The received request to reply to. */
    ucall_received_http_request_t request;
    /** @brief An open directory acting as the containment root. */
    int directory_descriptor;
    /** @brief Path resolved beneath @c directory_descriptor. */
    ucall_string_t relative_path;
    /** @brief Length of @c relative_path. */
    size_t relative_path_length;
    /** @brief Byte offset within the file at which to start. */
    uint64_t offset;
    /** @brief Number of bytes to send. Zero sends through end of file. */
    uint64_t length;
} ucall_server_reply_path_t;

/**
 *  @brief Replies with a byte range of a file named relative to a directory descriptor.
 *
 *  Preferred over @c ucall_server_reply_file() on the @c io_uring backend, where the open,
 *  splice, and close are chained into one submission and the handler thread issues no syscalls.
 *  Resolution is confined beneath @c directory_descriptor, so a @c "../" in @c relative_path
 *  fails rather than escaping. UCall retains no reference to @c directory_descriptor.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @c request concurrently.
 */
UCALL_EXPORT void ucall_server_reply_path(ucall_server_reply_path_t* arguments);

#pragma endregion Streaming and Zero Copy Replies

#pragma endregion Planned Replies

#pragma region WebSockets

/** @brief Arguments of @c ucall_server_websocket_send(). */
typedef struct ucall_server_websocket_send_t {
    ucall_server_t server;
    ucall_outcome_t* outcome;
    /** @brief WebSocket connection handle from the callback. */
    ucall_websocket_t websocket;
    /** @brief Message type (text, binary, ping, pong). */
    ucall_websocket_opcode_t opcode;
    /** @brief Message payload. */
    ucall_string_t data;
    /** @brief Length of the message payload. */
    size_t data_length;
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
 *  This function is thread-safe and can be called from any thread.
 *  After calling this, the @p websocket handle becomes invalid.
 *
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] websocket WebSocket connection handle to close.
 *
 *  @note @b Thread-safe.
 */
UCALL_EXPORT void ucall_server_websocket_close(ucall_server_t server, ucall_websocket_t websocket);

#pragma endregion WebSockets

#pragma endregion Servers

#pragma region Diagnostics

/**
 *  @brief Returns the canonical lowercase, dash-separated spelling of a status, as
 *    @c ucall_status_out_of_memory_k spells "out-of-memory".
 *  @param[in] status The status code to name.
 *  @return A @c NULL -terminated string with static storage duration. Never @c NULL.
 *
 *  @note @b Thread-safe.
 */
UCALL_EXPORT ucall_string_t ucall_status_name(ucall_status_t status);

/**
 *  @brief Reads a status back from its canonical spelling.
 *  @param[in] name The spelling @c ucall_status_name() returns.
 *  @param[in] name_length Length of @p name in bytes.
 *  @return The named status, or @c ucall_status_invalid_argument_k for an unrecognized name.
 *
 *  @note @b Thread-safe.
 */
UCALL_EXPORT ucall_status_t ucall_status_from_name(ucall_string_t name, size_t name_length);

/**
 *  @brief Reports the version of the linked library, which may differ from @c UCALL_VERSION_* in the header.
 *  @param[out] major Output for the major version.
 *  @param[out] minor Output for the minor version.
 *  @param[out] patch Output for the patch version.
 */
UCALL_EXPORT void ucall_version(int* major, int* minor, int* patch);

#pragma endregion Diagnostics

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif
