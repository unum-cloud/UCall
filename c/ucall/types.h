/**
 *  @file c/ucall/types.h
 *  @author Ash Vardanian
 *  @date Feb 3, 2023
 *  @brief Shared handles, counted byte views, statuses, and deferred outcomes.
 *
 *  Every verb that can fail takes one argument struct named after it, as @c ucall_client_call()
 *  takes @c ucall_client_call_t, and returns nothing. Each struct opens with its handle, then @c
 *  outcome, then inputs, outputs, and knobs. Initialize them with designated initializers, so
 *  fields added later stay zero. Getters that cannot fail and @c *_free() stay positional.
 *
 *  Synchronous and asynchronous calls share one shape. A client call carries a @c
 *  ucall_completion_t: zero blocks until the response arrives, and @c ucall_completion_deferred_k
 *  returns once the call is queued, so no verb has an asynchronous twin. The outcome's status is
 *  the one word both sides synchronize on:
 *
 *  - For a deferred call the library stores @c ucall_status_deferred_k, then the message and the
 *    final status with release ordering, even for a call refused at submission, and touches nothing
 *    the struct names after that store.
 *  - The caller reads through @c ucall_outcome_status or @c ucall_outcome_wait, and may reuse the
 *    struct or free its buffers only once the status is final.
 *  - A client tracks a fixed number of deferred calls in flight, and a submission that finds the
 *    table full finishes at once with @c ucall_status_contended_k instead of queueing.
 *
 *  Server verbs called from an endpoint callback finish before they return. Received bytes live in
 *  memory the library owns, a server's receive pool or a client's response, so no allocator,
 *  alignment or memory kind crosses this interface.
 */

#ifndef UNUM_UCALL_TYPES_H
#define UNUM_UCALL_TYPES_H

#include <stdbool.h> // bool
#include <stddef.h>  // size_t
#include <stdint.h>  // uint32_t, int32_t

#define UCALL_VERSION_MAJOR 1
#define UCALL_VERSION_MINOR 0
#define UCALL_VERSION_PATCH 0

#ifdef __cplusplus
extern "C" {
#endif

/** Marks exported functions. Define @c UCALL_BUILDING while compiling UCall itself, or predefine
 *  @c UCALL_EXPORT as empty to link it statically on Windows. */
#ifndef UCALL_EXPORT
#if (defined(_WIN32) || defined(__CYGWIN__)) && defined(UCALL_BUILDING)
#define UCALL_EXPORT __declspec(dllexport)
#elif defined(_WIN32) || defined(__CYGWIN__)
#define UCALL_EXPORT __declspec(dllimport)
#else
#define UCALL_EXPORT __attribute__((visibility("default")))
#endif // Windows import or export
#endif // !defined(UCALL_EXPORT)

/** A borrowed run of bytes; text is bytes that happen to decode.
 *
 *  Empty is {NULL, 0}. Length never requests a null-terminator lookup. */
typedef struct ucall_bytes_view_t {

    /** First byte of the run. */
    uint8_t const* data;

    /** Bytes the run spans, with no terminator assumed or written. */
    size_t length;

} ucall_bytes_view_t;

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

/** Opaque handle for a single Remote Procedure Call on the @b server side. */
typedef struct ucall_received_http_request_handle_t* ucall_received_http_request_t;

/** Opaque handle for several batched Remote Procedure Calls on the @b server side. */
typedef struct ucall_received_batch_http_request_handle_t* ucall_received_batch_http_request_t;

/** Opaque handle for a single Remote Procedure Call reply on the @b client side. */
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

    /** No encryption, plain TCP/IP. */
    ucall_security_mode_none_k,

    /** Trust on first use - no pre-shared keys needed. */
    ucall_security_mode_noise_xx_k,

    /** Client knows server's public key in advance. */
    ucall_security_mode_noise_ik_k,

    /** Both know each other's public keys in advance. */
    ucall_security_mode_noise_kk_k
} ucall_security_mode_t;

/** Noise protocol key (32 bytes for Curve25519). */
typedef uint8_t ucall_noise_key_t[32];

/**
 *  @brief Decides whether a peer presenting a given static key may proceed past the handshake.
 *  @param[in] peer_static_key The remote party's 32-byte Curve25519 static public key.
 *  @param[in] context User-supplied context from the server or client configuration.
 *  @return True to accept the peer, false to abort with @c ucall_status_peer_rejected_k.
 *
 *  Required for @c ucall_security_mode_noise_xx_k, where keys are learned during the handshake
 *  rather than known in advance. Called after the key is authenticated, before any payload.
 */
typedef bool (*ucall_peer_authorizer_t)(ucall_noise_key_t const* peer_static_key, void* context);

/** HTTP request methods/verbs for endpoint routing.
 *
 *  For JSON-RPC all requests are typically sent via HTTP @c POST. */
typedef enum ucall_verb_t {

    /** Unrecognized or not yet parsed. The zero-initialized default. */
    ucall_verb_unknown_k = 0,

    /** HTTP "GET" method for retrieving resources. */
    ucall_verb_get_k,

    /** HTTP "POST" method for creating resources. */
    ucall_verb_post_k,

    /** HTTP "PUT" method for updating resources. */
    ucall_verb_put_k,

    /** HTTP "DELETE" method for removing resources. */
    ucall_verb_delete_k,

    /** HTTP "PATCH" method for partial updates. */
    ucall_verb_patch_k,

    /** HTTP "HEAD" method for retrieving headers only. */
    ucall_verb_head_k,

    /** HTTP "OPTIONS" method for retrieving supported methods. */
    ucall_verb_options_k,

    /** Matches every method. Valid only when registering an endpoint. */
    ucall_verb_any_k
} ucall_verb_t;

/** Library-level outcomes, preserving USearch numbers for shared statuses.
 *
 *  These codes represent library/transport-level outcomes. For HTTP-specific status codes (200,
 *  404, 500), use @c ucall_http_status_t. */
typedef enum ucall_status_t {

    /** The call succeeded; the outcome message is NULL. */
    ucall_status_success_k = 0,

    /** A submitted call has not finished; the only status that is never final. */
    ucall_status_deferred_k = 1,

    /** An allocation or reservation could not be satisfied. */
    ucall_status_out_of_memory_k = 2,

    /** A socket or file could not be opened, read, written, or closed. */
    ucall_status_io_k = 7,

    /** The peer supplied bytes that cannot be decoded as the expected protocol. */
    ucall_status_malformed_k = 9,

    /** The engine violated its contract, which points at a defect. */
    ucall_status_internal_k = 10,

    /** A hard design ceiling was reached. */
    ucall_status_overflow_k = 11,

    /** The call needs a handle that was never initialized. */
    ucall_status_uninitialized_k = 12,

    /** The call was refused rather than waited for, such as submission to a full deferred table. */
    ucall_status_contended_k = 14,

    /** The build, backend, or machine does not implement the requested feature. */
    ucall_status_unsupported_k = 16,

    /** An argument is null, out of range, or contradicts another argument. */
    ucall_status_invalid_argument_k = 17,

    /** The requested endpoint, header, or parameter does not exist. */
    ucall_status_not_found_k = 18,

    /** An endpoint with the same template and method is already registered. */
    ucall_status_already_exists_k = 19,

    /** DNS lookup or connection establishment failed. */
    ucall_status_connection_failed_k = 20,

    /** The connection closed before the exchange completed. */
    ucall_status_connection_closed_k = 21,

    /** The operation exceeded its time budget. */
    ucall_status_timeout_k = 22,

    /** The Noise handshake failed to authenticate or agree on keys. */
    ucall_status_handshake_failed_k = 23,

    /** The peer authorizer declined the authenticated static key. */
    ucall_status_peer_rejected_k = 24,

    /** A nonblocking poll had no progress to report. */
    ucall_status_would_block_k = 25,

} ucall_status_t;

/** Outcome of one call: a status to branch on, and a static message with the detail it cannot
 *  carry.
 *
 *  The message has static storage, is never freed, and is @c NULL exactly when the status is @c
 *  ucall_status_success_k. Every verb struct points at one. */
typedef struct ucall_outcome_t {

    /** The final status, or ucall_status_deferred_k while a submitted call is unfinished. */
    ucall_status_t status;

    /** Static detail, never freed; NULL exactly on success. */
    char const* message;

} ucall_outcome_t;

/**
 *  @brief Blocks until @p outcome is final, without spinning, and with acquire ordering.
 *  @param[in] outcome An outcome passed to a call, read until its status leaves @c
 *      ucall_status_deferred_k.
 *  @return The final status.
 *
 *  Producers publish the final status with a release store and notify all waiters on that word.
 *  Never wait from a callback that the call itself must finish before it can complete.
 *
 *
 *  @note @b Thread-safe. Any number of threads may wait on one outcome.
 */
UCALL_EXPORT ucall_status_t ucall_outcome_wait(ucall_outcome_t* outcome);

/**
 *  @brief Reads the outcome without waiting, with acquire ordering, so a final status publishes
 *      every output.
 *  @param[in] outcome An outcome passed to a call.
 *  @return @c ucall_status_deferred_k until final, then the final status.
 *
 *  Poll through this function; directly reading the field during a deferred call is not an atomic
 *  load.
 */
UCALL_EXPORT ucall_status_t ucall_outcome_status(ucall_outcome_t* outcome);

/** Whether a call returns once its work is done, or once it is queued on the client. */
typedef enum ucall_completion_t {

    /** Return with the final status stored and the response readable; the default. */
    ucall_completion_blocking_k = 0,

    /** Return once queued, with the status pending until the call ends; the caller waits or
     *  polls. */
    ucall_completion_deferred_k = 1,
} ucall_completion_t;

/** HTTP status codes for server responses and client results.
 *
 *  Use these when you need HTTP-specific semantics (400, 404, 500, etc.). For library-level
 *  operations, use @c ucall_status_t instead. */
typedef enum ucall_http_status_t {

    /** Request succeeded. */
    ucall_http_status_ok_k = 200,

    /** Resource created. */
    ucall_http_status_created_k = 201,

    /** Success with an empty body. */
    ucall_http_status_no_content_k = 204,

    /** Success with the requested @c Range of the body. */
    ucall_http_status_partial_content_k = 206,

    /** Resource has a new permanent URL. */
    ucall_http_status_moved_permanently_k = 301,

    /** Resource is temporarily at a different URL. */
    ucall_http_status_found_k = 302,

    /** Cached copy is still fresh. */
    ucall_http_status_not_modified_k = 304,

    /** Malformed request syntax. */
    ucall_http_status_bad_request_k = 400,

    /** Authentication required or failed. */
    ucall_http_status_unauthorized_k = 401,

    /** Authenticated, but not permitted. */
    ucall_http_status_forbidden_k = 403,

    /** No endpoint matches the request path. */
    ucall_http_status_not_found_k = 404,

    /** Endpoint exists, but not for this verb. */
    ucall_http_status_method_not_allowed_k = 405,

    /** Client took too long to send the request. */
    ucall_http_status_timeout_k = 408,

    /** Request conflicts with current resource state. */
    ucall_http_status_conflict_k = 409,

    /** Request body exceeds the configured limit. */
    ucall_http_status_payload_too_large_k = 413,

    /** Rate limit exceeded. */
    ucall_http_status_too_many_requests_k = 429,

    /** Unhandled failure inside an endpoint. */
    ucall_http_status_internal_error_k = 500,

    /** Verb or feature not supported. */
    ucall_http_status_not_implemented_k = 501,

    /** Server is overloaded or shutting down. */
    ucall_http_status_service_unavailable_k = 503,

    /** Upstream dependency timed out. */
    ucall_http_status_gateway_timeout_k = 504,
} ucall_http_status_t;

/** Severity of a log line, from the most verbose up. */
typedef enum ucall_log_level_t {
    ucall_log_level_debug_k,
    ucall_log_level_info_k,
    ucall_log_level_warning_k,
    ucall_log_level_error_k,
    ucall_log_level_fatal_k
} ucall_log_level_t;

/** Shape of each log line. */
typedef enum ucall_log_format_t {

    /** Human-readable unit-normalized lines. */
    ucall_log_format_human_k,

    /** Newline-delimited JSONs documents. */
    ucall_log_format_json_k,
} ucall_log_format_t;

/**
 *  @brief Receives one formatted log line, without a trailing newline.
 *  @param[in] level Severity of the line.
 *  @param[in] line The formatted line. Valid only for the duration of the call.
 *  @param[in] context User-supplied context from @c ucall_log_t.
 *
 *  Called on whichever thread produced the line, including event loops and the client's connection
 *  thread, so it must be thread-safe and return quickly.
 */
typedef void (*ucall_log_callback_t)(ucall_log_level_t level, ucall_bytes_view_t line, void* context);

/** The single log sink of a client or a server.
 *
 *  UCall writes nothing anywhere on its own: every line goes to @c callback, and without one the
 *  library stays silent. */
typedef struct ucall_log_t {

    /** Receives every line at or above @c level. Default: NULL, logging nothing. */
    ucall_log_callback_t callback;

    /** Passed verbatim to @c callback. */
    void* context;

    /** Line format. Default: ucall_log_format_human_k. */
    ucall_log_format_t format;

    /** Lines below this severity are never formatted. Default: ucall_log_level_debug_k. */
    ucall_log_level_t level;

} ucall_log_t;

/** WebSocket event types, shared between client and server. */
typedef enum ucall_websocket_event_t {

    /** Connection established. */
    ucall_websocket_event_open_k,

    /** Message received. */
    ucall_websocket_event_message_k,

    /** Error occurred. */
    ucall_websocket_event_error_k,

    /** Connection closed. */
    ucall_websocket_event_close_k
} ucall_websocket_event_t;

/** WebSocket message types (RFC 6455). */
typedef enum ucall_websocket_opcode_t {
    ucall_websocket_opcode_text_k = 0x1,
    ucall_websocket_opcode_binary_k = 0x2,
    ucall_websocket_opcode_ping_k = 0x9,
    ucall_websocket_opcode_pong_k = 0xA
} ucall_websocket_opcode_t;

/** Opaque handle to a WebSocket connection.
 *
 *  Valid from @c ucall_websocket_event_open_k event until @c ucall_websocket_event_close_k
 *  event. */
typedef struct ucall_websocket_handle_t* ucall_websocket_t;

/**
 *  @brief Callback for WebSocket events on both client and server sides.
 *  @param[in] websocket WebSocket connection handle.
 *  @param[in] event Type of event.
 *  @param[in] opcode Message opcode (only valid for @c ucall_websocket_event_message_k event).
 *  @param[in] data Event data. Message payload for @c ucall_websocket_event_message_k. Error
 *      description for @c ucall_websocket_event_error_k. Otherwise an empty view.
 *  @param[in] context User-supplied context pointer from the WebSocket initialization.
 */
typedef void (*ucall_websocket_callback_t)(                                                      //
    ucall_websocket_t websocket, ucall_websocket_event_t event, ucall_websocket_opcode_t opcode, //
    ucall_bytes_view_t data, void* context);

/**
 *  @brief Returns the canonical lowercase, dash-separated spelling of a status, as @c
 *      ucall_status_out_of_memory_k spells "out-of-memory".
 *  @param[in] status The status code to name.
 *  @return A @c NULL -terminated string with static storage duration. Never @c NULL.
 *
 *  @note @b Thread-safe.
 */
UCALL_EXPORT char const* ucall_status_name(ucall_status_t status);

/**
 *  @brief Reads a status back from its canonical spelling.
 *  @param[in] name The counted spelling @c ucall_status_name() returns.
 *  @return The named status, or @c ucall_status_invalid_argument_k for an unrecognized name.
 *
 *  @note @b Thread-safe.
 */
UCALL_EXPORT ucall_status_t ucall_status_from_name(ucall_bytes_view_t name);

/**
 *  @brief Reports the version of the linked library, which may differ from @c UCALL_VERSION_* in
 *      the header.
 *  @param[out] major Output for the major version.
 *  @param[out] minor Output for the minor version.
 *  @param[out] patch Output for the patch version.
 */
UCALL_EXPORT void ucall_version(int* major, int* minor, int* patch);

/** The linked library's version, including a release-candidate suffix, in static storage. */
UCALL_EXPORT char const* ucall_version_name(void);

#ifdef __cplusplus
}
#endif

#endif // UNUM_UCALL_TYPES_H
