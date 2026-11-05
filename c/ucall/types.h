/**
 *  @file c/ucall/types.h
 *  @author Ash Vardanian
 *  @date February 3, 2023
 *  @brief Shared handles, counted byte views, statuses, and outcomes.
 */

#ifndef UNUM_UCALL_TYPES_H
#define UNUM_UCALL_TYPES_H

#include <stddef.h> // size_t
#include <stdint.h> // uint32_t, int32_t

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

/** One byte of raw storage shared by views and cryptographic keys. */
typedef uint8_t ucall_byte_t;

/** A borrowed run of bytes; text is bytes that happen to decode.
 *
 *  Empty is {NULL, 0}. Length never requests a null-terminator lookup. */
typedef struct ucall_bytes_view_t {

    /** First byte of the run. */
    ucall_byte_t const* data;

    /** Bytes the run spans, with no terminator assumed or written. */
    size_t length;

} ucall_bytes_view_t;

/** A concrete I/O implementation; automatic chooses an available native implementation. */
typedef enum ucall_io_backend_t {
    ucall_io_backend_automatic_k = 0,
    ucall_io_backend_posix_k,
    ucall_io_backend_linux_epollaio_k,
    ucall_io_backend_linux_uring612_k,
    ucall_io_backend_linux_uring618_k,
    ucall_io_backend_bsd_kqueue_k,
    ucall_io_backend_windows_iocp_k
} ucall_io_backend_t;

/** A CPU kernel bundle, named with the same native classes as the sibling libraries. */
typedef enum ucall_cpu_class_t {
    ucall_cpu_class_unknown_k = 0,
    ucall_cpu_class_serial_k,
    ucall_cpu_class_intel_haswell_k,
    ucall_cpu_class_intel_skylake_k,
    ucall_cpu_class_intel_icelake_k,
    ucall_cpu_class_intel_alder_k,
    ucall_cpu_class_aws_g2_k,
    ucall_cpu_class_aws_g5_k,
    ucall_cpu_class_monoversioned_k
} ucall_cpu_class_t;

/** Returns the stable name of an I/O backend. */
UCALL_EXPORT char const* ucall_io_backend_name(ucall_io_backend_t backend);

/** Returns the stable name of a CPU kernel class. */
UCALL_EXPORT char const* ucall_cpu_class_name(ucall_cpu_class_t cpu_class);

/**
 *  @brief Reads an I/O backend back from its stable name.
 *  @param[in] name The counted spelling @c ucall_io_backend_name() returns.
 *  @return The named backend, or @c ucall_io_backend_automatic_k for an unrecognized name, which
 *      callers tell from "automatic" by naming the result back.
 *
 *  @note @b Thread-safe.
 */
UCALL_EXPORT ucall_io_backend_t ucall_io_backend_from_name(ucall_bytes_view_t name);

/**
 *  @brief Reads a CPU kernel class back from its stable name.
 *  @param[in] name The counted spelling @c ucall_cpu_class_name() returns.
 *  @return The named class, or @c ucall_cpu_class_unknown_k for an unrecognized name.
 *
 *  @note @b Thread-safe.
 */
UCALL_EXPORT ucall_cpu_class_t ucall_cpu_class_from_name(ucall_bytes_view_t name);

/**
 *  @brief Opaque server handle.
 *  @sa Deals with @c ucall_received_http_request_t, individually or in counted arrays.
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
 *  - Driving accepted calls when the application polls for completions.
 */
typedef struct ucall_client_handle_t* ucall_client_t;

/** Opaque handle for a single Remote Procedure Call on the @b server side. */
typedef struct ucall_received_http_request_handle_t* ucall_received_http_request_t;

/** One batch endpoint of a server, drained by one application thread; lives until
 *  @c ucall_server_free(). */
typedef struct ucall_http_batch_endpoint_handle_t* ucall_http_batch_endpoint_t;

/** Opaque handle for a single Remote Procedure Call reply on the @b client side. */
typedef struct ucall_received_http_response_handle_t* ucall_received_http_response_t;

/** When an endpoint's callback runs: once the body is buffered, or at headers time with the body
 *  pulled through ucall_server_request_body_chunk(). */
typedef enum ucall_body_delivery_t {
    ucall_body_delivery_buffered_k = 0,
    ucall_body_delivery_streamed_k = 1,
} ucall_body_delivery_t;

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
typedef enum ucall_security_t {

    /** No encryption, plain TCP/IP. */
    ucall_security_none_k,

    /** Trust on first use - no pre-shared keys needed. */
    ucall_security_noise_xx_k,

    /** Client knows server's public key in advance. */
    ucall_security_noise_ik_k,

    /** Both know each other's public keys in advance. */
    ucall_security_noise_kk_k
} ucall_security_t;

/** Noise protocol key (32 bytes for Curve25519). */
typedef ucall_byte_t ucall_noise_key_t[32];

/** HTTP request methods/verbs for endpoint routing. */
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
 *  404, 500), use @c ucall_http_status_t.
 *
 *  Statuses fall into five categories. Resources: @c ucall_status_out_of_memory_k,
 *  @c ucall_status_io_k, @c ucall_status_connection_failed_k and
 *  @c ucall_status_connection_closed_k. Input: @c ucall_status_invalid_argument_k,
 *  @c ucall_status_malformed_k, @c ucall_status_handshake_failed_k and
 *  @c ucall_status_peer_rejected_k. State: @c ucall_status_uninitialized_k,
 *  @c ucall_status_unsupported_k, @c ucall_status_not_found_k, @c ucall_status_already_exists_k,
 *  @c ucall_status_overflow_k and @c ucall_status_contended_k. Interruptions:
 *  @c ucall_status_deferred_k, @c ucall_status_would_block_k and @c ucall_status_timeout_k.
 *  Defects: @c ucall_status_internal_k. Any verb that allocates, binds a device or touches a file
 *  or a socket may also return a Resources status. A verb's own block lists only what its contract
 *  adds. */
typedef uint32_t ucall_status_t;
enum {

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

    /** The requested size exceeds the representable range. */
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

};

/**
 *  @brief Decides whether a peer presenting a given static key may proceed past the handshake.
 *  @param[in] peer_static_key The remote party's 32-byte Curve25519 static public key.
 *  @param[in] context User-supplied context from the server or client configuration.
 *
 *  Required for @c ucall_security_noise_xx_k, where keys are learned during the handshake
 *  rather than known in advance. Called after the key is authenticated, before any payload.
 *  Returning @c ucall_status_success_k admits the peer.
 *
 *  @par Statuses:
 *  - @c ucall_status_peer_rejected_k The plain refusal. Any other status refuses the peer too, and
 *    becomes the connection's outcome.
 */
typedef ucall_status_t (*ucall_peer_authorizer_t)(ucall_noise_key_t const* peer_static_key, void* context);

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
 *  @return The final status once the call is final.
 *
 *  Poll through this function; directly reading the field during a deferred call is not an atomic
 *  load.
 *
 *  @par Statuses:
 *  - @c ucall_status_deferred_k The call is not final.
 */
UCALL_EXPORT ucall_status_t ucall_outcome_status(ucall_outcome_t* outcome);

/** Arguments of @c ucall_noise_key_generate(). */
typedef struct ucall_noise_key_generate_t {

    /** The verb's status, listed on the verb. */
    ucall_outcome_t* outcome;

    /** Output for the secret scalar, drawn from the operating system's entropy. */
    ucall_noise_key_t* private_key;

    /** Output for the Curve25519 public key matching @c private_key. */
    ucall_noise_key_t* public_key;

} ucall_noise_key_generate_t;

/**
 *  @brief Draws a fresh static keypair for @c noise_private_key fields and peer authorizers.
 *
 *  Both outputs are zeroed unless the call succeeds.
 *
 *  @note @b Thread-safe.
 *
 *  @par Statuses:
 *  - @c ucall_status_invalid_argument_k An output is @c NULL.
 */
UCALL_EXPORT void ucall_noise_key_generate(ucall_noise_key_generate_t* arguments);

/** Arguments of @c ucall_noise_key_derive(). */
typedef struct ucall_noise_key_derive_t {

    /** Output for the outcome. */
    ucall_outcome_t* outcome;

    /** The secret scalar, as @c noise_private_key fields take it. */
    ucall_noise_key_t const* private_key;

    /** Output for the Curve25519 public key, which peers see during the handshake. */
    ucall_noise_key_t* public_key;

} ucall_noise_key_derive_t;

/**
 *  @brief Derives the public key of a stored private key, as peer authorizers compare it.
 *
 *  @note @b Thread-safe.
 *
 *  @par Statuses:
 *  - @c ucall_status_invalid_argument_k The @c private_key or the @c public_key output is @c NULL.
 */
UCALL_EXPORT void ucall_noise_key_derive(ucall_noise_key_derive_t* arguments);

/** The family of a peer's socket address. */
typedef enum ucall_address_family_t {
    ucall_address_family_unknown_k = 0,
    ucall_address_family_ipv4_k = 1,
    ucall_address_family_ipv6_k = 2,
    ucall_address_family_unix_k = 3,
} ucall_address_family_t;

/** A peer's socket address: IPv4 in the first 4 @c bytes, IPv6 in all 16, both in network order,
 *  the port in host order and the IPv6 scope; AF_UNIX peers carry only the family. */
typedef struct ucall_peer_address_t {
    ucall_byte_t bytes[16];
    uint32_t scope;
    uint16_t port;

    /** A @c ucall_address_family_t, one byte wide. */
    uint8_t family;
    uint8_t reserved;
} ucall_peer_address_t;

/** HTTP status codes for server responses and client results.
 *
 *  Numeric codes also represent responses absent from the named constants below.
 *  For library outcomes, use @c ucall_status_t instead. */
typedef uint32_t ucall_http_status_t;
enum {

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

    /** A request condition does not match the current resource. */
    ucall_http_status_precondition_failed_k = 412,

    /** Request body is too large. */
    ucall_http_status_payload_too_large_k = 413,

    /** A requested byte range starts or ends past the end of the resource. */
    ucall_http_status_range_not_satisfiable_k = 416,

    /** Rate limit exceeded. */
    ucall_http_status_too_many_requests_k = 429,

    /** Unhandled failure inside an endpoint. */
    ucall_http_status_internal_error_k = 500,

    /** Verb or feature not supported. */
    ucall_http_status_not_implemented_k = 501,

    /** An upstream answered with something no HTTP peer would send. */
    ucall_http_status_bad_gateway_k = 502,

    /** Server is overloaded or shutting down. */
    ucall_http_status_service_unavailable_k = 503,

    /** Upstream dependency timed out. */
    ucall_http_status_gateway_timeout_k = 504,

    /** Request names an HTTP version the server does not speak. */
    ucall_http_status_version_not_supported_k = 505,
};

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
 *  Called on whichever thread produced the line, including application polling threads.
 *  The callback must be thread-safe and return quickly.
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
 *  @return The named status.
 *
 *  @note @b Thread-safe.
 *
 *  @par Statuses:
 *  - @c ucall_status_invalid_argument_k An unrecognized name.
 */
UCALL_EXPORT ucall_status_t ucall_status_from_name(ucall_bytes_view_t name);

/** Which part of a URL @c ucall_decode_percent() reads, as only a query spells a space '+'. */
typedef enum ucall_percent_mode_t {

    /** A path, where '+' stays itself. */
    ucall_percent_path_k = 0,

    /** A query, where '+' is a space. */
    ucall_percent_query_k = 1
} ucall_percent_mode_t;

/**
 *  @brief Decodes the %XX escapes of @p encoded, and '+' as a space in query mode.
 *  @param[in] encoded A path or a query value, as a request lends it.
 *  @param[out] decoded At least @c encoded.length bytes; may alias @c encoded.data.
 *  @param[out] length The decoded length.
 *  @param[in] mode Whether a '+' is itself or a space.
 *  @return The decoding's status.
 *
 *  @note @b Thread-safe.
 *
 *  @par Statuses:
 *  - @c ucall_status_invalid_argument_k A '%' without two hexadecimal digits, an unknown @p mode,
 *    or a missing @p length, @p decoded or @c encoded.data while @c encoded.length is not zero.
 */
UCALL_EXPORT ucall_status_t ucall_decode_percent(ucall_bytes_view_t encoded, ucall_byte_t* decoded, size_t* length,
                                                 ucall_percent_mode_t mode);

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
