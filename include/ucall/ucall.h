/**
 *  @brief UCall is a fast HTTP+Noise client & server web framework leveraging
 *    @b io_uring & SIMD across x86 & Arm for high-performance packet processing.
 *
 *  @file ucall.h
 *  @date Feb 3, 2023
 *  @author Ash Vardanian
 */

#ifndef UCALL_H_
#define UCALL_H_

#define UCALL_VERSION_MAJOR 1
#define UCALL_VERSION_MINOR 0
#define UCALL_VERSION_PATCH 0

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h> // bool
#include <stddef.h>  // size_t
#include <stdint.h>  // int64_t

#pragma region Basic Types

/** @brief Type alias for immutable strings. */
typedef char const *ucall_string_t;

/**
 *  @brief A non-owning view of a contiguous byte range.
 *
 *  Used for scatter-gather replies, avoiding a dependency on POSIX @c iovec,
 *  which is unavailable on Windows.
 */
typedef struct ucall_buffer_t {
    void const *data;
    size_t length;
} ucall_buffer_t;

/**
 *  @brief Opaque type-punned server handle.
 *  @sa Deals with @c ucall_received_http_request_t and @c ucall_received_batch_http_request_t.
 *  @sa Use with @c ucall_server_init() and @c ucall_server_free() for lifetime.
 *  @sa Use @c ucall_server_add_http_endpoint() and @c ucall_server_take_calls() for logic.
 */
typedef void *ucall_server_t;

/**
 *  @brief Opaque type-punned client handle.
 *  @sa Deals with @c ucall_received_http_response_t.
 *  @sa Use with @c ucall_client_init() and @c ucall_client_free() for lifetime.
 *  @sa Use @c ucall_client_call() for logic.
 *
 *  At a high level, a @b client is responsible for:
 *
 *  - Establishing connections to one or more servers, reusing encryption keys between requests.
 *  - Following redirects chains automatically, unless disabled.
 */
typedef void *ucall_client_t;

/** @brief Opaque type-punned handle for a single Remote Procedure Call on the @b server side. */
typedef void *ucall_received_http_request_t;

/** @brief Opaque type-punned handle for several batched Remote Procedure Calls on the @b server side. */
typedef void *ucall_received_batch_http_request_t;

/** @brief Opaque type-punned handle for a single Remote Procedure Call reply on the @b client side. */
typedef void *ucall_received_http_response_t;

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
typedef bool (*ucall_peer_authorizer_t)(ucall_noise_key_t const *peer_static_key, void *context);

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
    ucall_status_ok_k = 0,
    /** @brief Async operation still in progress. */
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
    ucall_status_invalid_data_k = 8,

    /** @brief Noise handshake failed - key mismatch, bad pattern, or bad tag. */
    ucall_status_handshake_failed_k = 9,
    /** @brief Peer static key declined by @c ucall_peer_authorizer_t. */
    ucall_status_peer_rejected_k = 10,
    /** @brief Non-blocking operation had no progress to report. */
    ucall_status_would_block_k = 11,

} ucall_status_t;

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
typedef void *ucall_websocket_t;

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
    ucall_string_t data, size_t data_length, void *context);

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
    ucall_noise_key_t const *noise_private_key;

    /** @brief Vets server static keys. Required for XX. Default: NULL. */
    ucall_peer_authorizer_t peer_authorizer;
    /** @brief Passed verbatim to @c peer_authorizer. */
    void *peer_authorizer_context;

    /** @brief Descriptor receiving log output. Default: STDERR_FILENO. */
    int32_t logs_file_descriptor;
    /** @brief Log format name. Default: "human". */
    char const *logs_format;

    /** @brief Depth of the submission queue backing the client. Default: 128. */
    uint16_t queue_depth;
} ucall_client_config_t;

/**
 *  @brief Initializes the client state.
 *  @param[inout] config Input/output argument updated to export the final configuration.
 *  @param[out] client Output variable, which on success will be an initialized client.
 *    Free with @c ucall_client_free() at the end.
 *
 *  @note Call during setup only, before any thread enters @c ucall_client_call().
 */
ucall_status_t ucall_client_init(ucall_client_config_t *config, ucall_client_t *client);

/**
 *  @brief Frees the client state.
 *  @param[in] client Must be pre-initialized with @c ucall_client_init().
 *
 *  @note Call during setup only, before any thread enters @c ucall_client_call().
 */
void ucall_client_free(ucall_client_t client);

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
    ucall_noise_key_t const *client_key;
    /** @brief Needed for IK and KK security modes. */
    ucall_noise_key_t const *server_key;
} ucall_request_options_t;

/**
 *  @brief Makes a single HTTP call and blocks until the response arrives.
 *  @param[in] client Pre-initialized client handle.
 *  @param[in] url Full URL with scheme: @c http://, @c ws://, @c http+noise://, or @c ws+noise://.
 *    Example: "http://localhost:8080/sum?a=1&b=2" or "http+noise://api.example.com/rpc".
 *  @param[in] verb HTTP method, like @c ucall_verb_get_k or @c ucall_verb_post_k, etc.
 *  @param[in] headers Array of @b non-system headers to include in the request.
 *  @param[in] headers_lengths Optional array of lengths for each string (NULL if terminated).
 *  @param[in] headers_count Number of headers in the @p headers array.
 *  @param[in] body Request body, can be @c NULL for @c GET, @c HEAD, or @c DELETE.
 *  @param[in] body_length Length of @p body in bytes.
 *  @param[in] options Per-request options for timeouts, retries, redirects, and security.
 *  @param[out] response Output handle for the received response.
 *    Free with @c ucall_received_http_response_free() once done.
 *  @return Status code indicating success or failure.
 *
 *  @note @b Thread-safe. One call is in flight per calling thread.
 *
 *  @par Synchronous by Design
 *
 *  One call at a time, blocking until it completes. There are no futures, promises, or
 *  polling loops - concurrency comes from running more threads, each with its own call
 *  in flight. This mirrors @c ucall_server_take_calls() on the server side, where
 *  asynchrony lives inside the library and never in the application's control flow.
 *
 *  When calling out to another service from @b inside a server endpoint, this blocks the
 *  worker thread. To keep serving other requests while waiting, re-enter the server loop
 *  by calling @c ucall_server_take_calls() from within the handler.
 *
 *  @par Headers
 *
 *  Some of the standard HTTP headers are automatically managed by UCall, such as:
 *  - @c Host: Set from the @p url function argument.
 *  - @c Content-Length: Set based on the @p body_length function argument.
 *  - @c User-Agent: Set to a default value identifying the UCall client.
 *
 *  Those shouldn't be included in the @p headers array.
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
 *  @c ucall_request_options_t::max_redirects fail with @c ucall_status_invalid_data_k.
 *
 *  @par Example
 *
 *  @code{.c}
 *  ucall_client_t client;
 *  ucall_client_config_t config = {0};
 *  ucall_client_init(&config, &client);
 *
 *  ucall_received_http_response_t response;
 *  ucall_request_options_t options = {0};
 *  ucall_status_t status = ucall_client_call(client,
 *      "http://localhost:8080/sum?a=1&b=2", ucall_verb_get_k,
 *      NULL, NULL, 0,          // ! no custom headers
 *      NULL, 0,                // ! no body
 *      &options, &response);
 *
 *  if (status == ucall_status_ok_k) {
 *      ucall_string_t body;
 *      size_t body_length;
 *      ucall_received_http_response_body(client, response, &body, &body_length);
 *      // process `body`...
 *      ucall_received_http_response_free(client, response);
 *  }
 *  ucall_client_free(client);
 *  @endcode
 */
ucall_status_t ucall_client_call(                                                       //
    ucall_client_t client, ucall_string_t url, ucall_verb_t verb,                       //
    ucall_string_t const *headers, size_t const *headers_lengths, size_t headers_count, //
    ucall_string_t body, size_t body_length,                                            //
    ucall_request_options_t const *options,                                             //
    ucall_received_http_response_t *response);

/**
 *  @brief Establishes a WebSocket connection and blocks until the handshake completes.
 *  @param[in] client Pre-initialized client handle.
 *  @param[in] url WebSocket URL with scheme: @c ws:// or @c ws+noise://.
 *  @param[in] options Optional request options.
 *  @param[out] websocket Output variable to hold the WebSocket handle.
 *
 *  @note @b Thread-safe.
 */
ucall_status_t ucall_client_websocket_connect( //
    ucall_client_t client, ucall_string_t url, //
    ucall_request_options_t const *options,    //
    ucall_websocket_t *websocket);

/**
 *  @brief Blocks until a message arrives on an established WebSocket connection.
 *  @param[in] client Client handle from @c ucall_client_init().
 *  @param[in] websocket WebSocket handle from @c ucall_client_websocket_connect().
 *  @param[out] opcode Output variable for the received message type.
 *  @param[out] data Output pointer for the message payload. Valid until the next call.
 *  @param[out] data_length Output length of the message payload.
 *  @param[in] timeout_micro_seconds Maximum time to block. Zero returns immediately.
 *  @return @c ucall_status_timeout_k if no message arrived, @c ucall_status_connection_closed_k
 *    once the peer closes the connection.
 *
 *  @note @b Thread-safe against @c ucall_client_websocket_send() on the same @p websocket,
 *    so one thread may receive while another sends. Two threads must not receive concurrently.
 *
 *  Unlike the server side, which dispatches to @c ucall_websocket_callback_t from within its
 *  own loop, the client receives on a loop the application owns.
 */
ucall_status_t ucall_client_websocket_receive(          //
    ucall_client_t client, ucall_websocket_t websocket, //
    ucall_websocket_opcode_t *opcode,                   //
    ucall_string_t *data, size_t *data_length,          //
    uint32_t timeout_micro_seconds);

/**
 *  @brief Extracts the named string header from the received response.
 *
 *  Header name matching is case-insensitive per RFC 7230.
 *
 *  @param[in] client Client handle from @c ucall_client_init().
 *  @param[in] response The received response from @c ucall_client_call().
 *  @param[in] header_name The name of the HTTP header to extract (case-insensitive).
 *  @param[in] header_name_length The length of the @p header_name string.
 *  @param[out] output Output pointer for the start of the header value string.
 *  @param[out] output_length Output length of the header value string.
 *  @return Status code indicating success or failure (header not found).
 *
 *  @note @b Thread-safe across responses. Two threads must not operate on the
 *    @b same @p response concurrently.
 */
ucall_status_t ucall_received_http_response_header(                 //
    ucall_client_t client, ucall_received_http_response_t response, //
    ucall_string_t header_name, size_t header_name_length,          //
    ucall_string_t *output, size_t *output_length);

/**
 *  @brief Extracts the body content from the received response.
 *  @param[in] client Client handle from @c ucall_client_init().
 *  @param[in] response The received response from @c ucall_client_call().
 *  @param[out] output Output pointer for the start of the body content.
 *  @param[out] output_length Output length of the body content.
 *  @return Status code indicating success or failure.
 *
 *  @note @b Thread-safe across responses. Two threads must not operate on the
 *    @b same @p response concurrently.
 */
ucall_status_t ucall_received_http_response_body(                   //
    ucall_client_t client, ucall_received_http_response_t response, //
    ucall_string_t *output, size_t *output_length);

/**
 *  @brief Frees the received response handle.
 *  @param[in] client Client handle from @c ucall_client_init().
 *  @param[in] response The received response from @c ucall_client_call().
 *
 *  @note @b Thread-safe across responses. Two threads must not operate on the
 *    @b same @p response concurrently.
 */
void ucall_received_http_response_free(ucall_client_t client, ucall_received_http_response_t response);

/**
 *  @brief Sends a message over an established WebSocket connection.
 *  @param[in] client Client handle from @c ucall_client_init().
 *  @param[in] websocket WebSocket connection handle from @c ucall_client_websocket_connect().
 *  @param[in] opcode Message type (text, binary, ping, pong).
 *  @param[in] data Message payload.
 *  @param[in] data_length Length of the message payload in bytes.
 *  @return Status code indicating success or failure.
 *
 *  @note @b Thread-safe.
 */
ucall_status_t ucall_client_websocket_send(             //
    ucall_client_t client, ucall_websocket_t websocket, //
    ucall_websocket_opcode_t opcode, ucall_string_t data, size_t data_length);

/**
 *  @brief Closes a WebSocket connection.
 *  @param[in] client Client handle from @c ucall_client_init().
 *  @param[in] websocket WebSocket connection handle to close.
 *
 *  @note @b Thread-safe.
 */
void ucall_client_websocket_close(ucall_client_t client, ucall_websocket_t websocket);

#pragma endregion Clients

#pragma region Servers

typedef enum ucall_log_level_t {
    ucall_log_level_debug_k,
    ucall_log_level_info_k,
    ucall_log_level_warning_k,
    ucall_log_level_error_k,
    ucall_log_level_fatal_k
} ucall_log_level_t;

typedef enum ucall_log_mode_t {
    /** @brief Human-readable unit-normalized lines. */
    ucall_log_mode_human_k,
    /** @brief Newline-delimited JSONs documents. */
    ucall_log_mode_json_k,
} ucall_log_mode_t;

/**
 *  @brief Notifies the application that the shared receive buffer pool has been mapped.
 *  @param[in] base Start of the pool. Page-aligned and contiguous for the server's lifetime.
 *  @param[in] length Size of the pool in bytes.
 *  @param[in] context User-supplied context from the server configuration.
 *  @return True to proceed with startup, false to abort @c ucall_server_init().
 *
 *  Invoked once during @c ucall_server_init(). Lets an application page-lock the pool for
 *  accelerator transfers - by calling @c cudaHostRegister() or an equivalent - without UCall
 *  itself depending on any accelerator runtime.
 */
typedef bool (*ucall_buffer_pool_callback_t)(void *base, size_t length, void *context);

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
    char const *address;
    /**
     *  @brief Physical device to pin this interface to with @c SO_BINDTODEVICE, such as "eth0",
     *    or @c NULL to bind by address alone.
     *
     *  Several interfaces may name one device, and one interface bound to @c 0.0.0.0 spans every
     *  device the machine has - which is why the two are separate fields rather than one.
     */
    char const *device_name;

    /**
     *  @brief Encryption for connections accepted here. Default: ucall_security_none_k.
     *  @note Server-side @c ucall_security_noise_kk_k is rejected, since an interface cannot name
     *    the initiator static key that pattern hashes before the first message.
     */
    ucall_security_mode_t security_mode;
    /** @brief Server identity for handshakes. Required when @c security_mode is not none. */
    ucall_noise_key_t const *noise_private_key;
    /** @brief Vets client static keys. Required for XX. Default: NULL. */
    ucall_peer_authorizer_t peer_authorizer;
    /** @brief Passed verbatim to @c peer_authorizer. */
    void *peer_authorizer_context;

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
     *  @sa @c ucall_server_event_loops_count() reports what the server settled on.
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
 *      .logs_output_path = NULL,  // stderr
 *      .log_mode = ucall_log_mode_json_k,
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
     *  The array and every string it points at must outlive the server. Parallelism is
     *  @c ucall_server_event_loops_count(), not this count.
     */
    ucall_network_interface_t const *interfaces;
    /** @brief Entries in @c interfaces. At least one; zero fails with @c ucall_status_invalid_argument_k. */
    size_t interfaces_count;

    /** @brief Notified once the pool is mapped. Default: NULL. */
    ucall_buffer_pool_callback_t buffer_pool_callback;
    /** @brief Passed verbatim to @c buffer_pool_callback. */
    void *buffer_pool_context;

    /** @brief Log file path. NULL redirects to stderr. Default: NULL. */
    char const *logs_output_path;
    /** @brief Log format. Default: ucall_log_mode_human_k. */
    ucall_log_mode_t log_mode;

    /** @brief StatsD UDP endpoint "host:port". NULL = disabled. Default: NULL. */
    char const *metrics_address;
    /** @brief Sampling rate [0.0, 1.0]. Default: 1.0. */
    float metrics_sample_rate;
    /** @brief Metric name prefix. Default: "ucall". */
    char const *metrics_prefix;
    /** @brief Global tags "key:val,key:val". Default: NULL. */
    char const *metrics_tags;
} ucall_server_config_t;

/**
 *  @brief Initializes the server state.
 *  @param[inout] config Input/output argument updated to export the final configuration.
 *  @param[out] server Output variable, which on success will be an initialized server.
 *    Free with @c ucall_server_free() at the end.
 *  @return Status code indicating success or failure.
 *
 *  @note Call during setup only, before any thread enters @c ucall_server_take_calls().
 */
ucall_status_t ucall_server_init(ucall_server_config_t *config, ucall_server_t *server);

/**
 *  @brief Frees the server state.
 *  @param[in] server Must be pre-initialized with @c ucall_server_init().
 *
 *  @note Call during setup only, before any thread enters @c ucall_server_take_calls().
 */
void ucall_server_free(ucall_server_t server);

#pragma region Endpoint Registration

/**
 *  @brief Callback type for handling incoming requests on the server side.
 *  @param[in] request The received request handle.
 *  @param[in] context User-supplied context pointer from the endpoint registration.
 */
typedef void (*ucall_received_http_request_callback_t)(ucall_received_http_request_t request, void *context);

/**
 *  @brief Registers a function callback to be triggered when a matching request arrives.
 *
 *  The @p template argument supports URI template syntax (RFC 6570 subset):
 *  - @c "/users/{id}" matches @c "/users/123" or @c "/users/abc"
 *  - @c "/posts/{year}/{month}" matches @c "/posts/2024/03"
 *  - @c "/files/{*path}" matches @c "/files/a/b/c.txt" (greedy, captures @c "a/b/c.txt")
 *
 *  Routing precedence: Literals match before template variables, before greedy wildcards.
 *
 *  @param[in] server Must be pre-initialized with @c ucall_server_init().
 *  @param[in] template URI template string with optional @c {variable} placeholders.
 *    Must be @b unique across all registered endpoints.
 *  @param[in] verb HTTP method for this endpoint.
 *  @param[in] callback Function pointer to the callback.
 *  @param[in] context Optional payload/tag for metadata (e.g., for CPython runtime).
 *  @return Status code (duplicate endpoint, invalid template, out of memory).
 *
 *  @see RFC 6570 Section 3.2.2 for simple string expansion specification.
 *
 *  @note Call during setup only, before any thread enters @c ucall_server_take_calls().
 */
ucall_status_t ucall_server_add_http_endpoint(                             //
    ucall_server_t server, ucall_string_t uri_template, ucall_verb_t verb, //
    ucall_received_http_request_callback_t callback, void *context);

/**
 *  @brief Callback type for handling batched requests on the server side.
 *  @param[in] batch The batched request handle.
 *  @param[in] context User-defined context pointer.
 */
typedef void (*ucall_received_batch_http_request_callback_t)( //
    ucall_received_batch_http_request_t batch, void *context);

/**
 *  @brief Options for server-side request batching.
 *
 *  Batching improves throughput for high-latency operations (e.g., GPU inference)
 *  by accumulating multiple requests and processing them together.
 */
typedef struct ucall_server_batch_endpoint_options_t {
    /** @brief Optimal batch size. Dispatch immediately when reached. Default: 1. */
    size_t min_batch_size;
    /** @brief Maximum requests per batch. Force dispatch when reached. Default: 32. */
    size_t max_batch_size;
    /** @brief Maximum wait time for partial batches. Default: 10'000, i.e. 10 milliseconds. */
    size_t max_latency_micro_seconds;
} ucall_server_batch_endpoint_options_t;

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
 *  @param[in] server Must be pre-initialized with @c ucall_server_init().
 *  @param[in] template URI template string with optional @c {variable} placeholders.
 *    Must be @b unique across all registered endpoints.
 *  @param[in] verb HTTP method for this endpoint.
 *  @param[in] options Batching configuration. If @c NULL, uses defaults (min=1, max=32, latency=10ms).
 *  @param[in] callback Function pointer to the batch callback.
 *  @param[in] context Optional payload/tag for metadata (e.g., for CPython runtime).
 *  @return Status code (duplicate endpoint, invalid template, out of memory).
 *
 *  @par Example
 *  @code{.c}
 *  void inference_batch(ucall_received_batch_http_request_t batch, void *context) {
 *      size_t count = ucall_server_batch_size(server, batch);
 *      float *inputs = malloc(count * INPUT_DIM * sizeof(float));
 *
 *      // Unpack all requests and prepare batch input
 *      for (size_t i = 0; i < count; i++) {
 *          ucall_received_http_request_t request;
 *          ucall_server_batch_unpack(server, batch, i, &request);
 *
 *          ucall_string_t body;
 *          size_t body_len;
 *          ucall_server_request_body(server, request, &body, &body_len);
 *          memcpy(&inputs[i * INPUT_DIM], body, INPUT_DIM * sizeof(float));
 *      }
 *
 *      // Single GPU kernel call for entire batch
 *      float *outputs = run_gpu_inference(inputs, count);
 *
 *      // Reply to each request individually
 *      for (size_t i = 0; i < count; i++) {
 *          ucall_received_http_request_t request;
 *          ucall_server_batch_unpack(server, batch, i, &request);
 *          ucall_server_reply_content(server, request, NULL, NULL, 0,
 *            (char*)&outputs[i * OUTPUT_DIM], OUTPUT_DIM * sizeof(float));
 *      }
 *      free(inputs); free(outputs);
 *  }
 *
 *  ucall_server_batch_endpoint_options_t opts = {
 *      .min_batch_size = 8,      // Wait for at least 8 requests
 *      .max_batch_size = 64,     // Process max 64 at once
 *      .max_latency_micro_seconds = 5000  // Wait max 5ms
 *  };
 *  ucall_server_add_batch_endpoint(server, "/inference", ucall_verb_post_k,
 *    &opts, inference_batch, NULL);
 *  @endcode
 *
 *  @sa To extract the number of calls in the batch - @c ucall_server_batch_size().
 *  @sa To enumerate separate calls from within the batch - @c ucall_server_batch_unpack().
 *
 *  @note Call during setup only, before any thread enters @c ucall_server_take_calls().
 */
ucall_status_t ucall_server_add_batch_endpoint(            //
    ucall_server_t server,                                 //
    ucall_string_t uri_template, ucall_verb_t verb,        //
    ucall_server_batch_endpoint_options_t const *options,  //
    ucall_received_batch_http_request_callback_t callback, //
    void *context);

/**
 *  @brief Registers a WebSocket endpoint to accept incoming connections.
 *
 *  On HTTP Upgrade request, establishes a WebSocket connection and invokes @p callback for
 *  all events (open, message, error, close) on a server worker thread.
 *
 *  @param[in] server Must be pre-initialized with @c ucall_server_init().
 *  @param[in] template URI template string with optional @c {variable} placeholders.
 *    Must be @b unique across all registered endpoints.
 *  @param[in] callback Function pointer to handle WebSocket events.
 *  @param[in] context Optional user-defined context pointer passed to all event callbacks.
 *  @return Status code (duplicate endpoint, invalid template, out of memory).
 *
 *  @note Call during setup only, before any thread enters @c ucall_server_take_calls().
 */
ucall_status_t ucall_server_add_websocket_endpoint(     //
    ucall_server_t server, ucall_string_t uri_template, //
    ucall_websocket_callback_t callback, void *context);

#pragma endregion Endpoint Registration

#pragma region Event Loop

/**
 *  @brief Performs a single blocking round of polling on the current calling thread.
 *  @param[in] server Must be pre-initialized with @c ucall_server_init().
 *  @param[in] thread_index Unique thread identifier within @c ucall_server_config_t::max_threads.
 *
 *  @note @b Thread-safe when every caller passes a distinct @p thread_index below
 *    @c ucall_server_config_t::max_threads. Reusing an index corrupts server state.
 */
void ucall_server_take_call(ucall_server_t server, uint16_t thread_index);

/**
 *  @brief Blocks current thread, more efficient than a @c while loop with @c ucall_server_take_call().
 *
 *  @param[in] server Must be pre-initialized with @c ucall_server_init().
 *  @param[in] thread_index Unique thread identifier within @c ucall_server_config_t::max_threads.
 *
 *  @note @b Thread-safe when every caller passes a distinct @p thread_index below
 *    @c ucall_server_config_t::max_threads. Reusing an index corrupts server state.
 */
void ucall_server_take_calls(ucall_server_t server, uint16_t thread_index);

#pragma endregion Event Loop

#pragma region Received Requests

/**
 *  @brief Extracts the HTTP method of the received request.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request inside the @c ucall_received_http_request_callback_t.
 *  @param[out] verb Output pointer for the method. Never @c ucall_verb_any_k.
 *
 *  Needed by endpoints registered with @c ucall_verb_any_k, which match every method.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_request_verb(                         //
    ucall_server_t server, ucall_received_http_request_t request, //
    ucall_verb_t *verb);

/**
 *  @brief Extracts the number of path components from the received request.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request inside the @c ucall_received_http_request_callback_t.
 *  @param[out] count Output pointer for the number of path components.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_request_path_segments_count(          //
    ucall_server_t server, ucall_received_http_request_t request, //
    size_t *count);

/**
 *  @brief Extracts an indexed path component from the received request.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request inside the @c ucall_received_http_request_callback_t.
 *  @param[in] index The zero-based index of the path component to extract.
 *  @param[out] output Output pointer for the start of the path component string.
 *  @param[out] output_length Output length of the path component string.
 *
 *  Useful for RESTful APIs with path parameters, e.g., "/users/{id}/posts/{postId}".
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_request_path_segment(                               //
    ucall_server_t server, ucall_received_http_request_t request, size_t index, //
    ucall_string_t *output, size_t *output_length);

/**
 *  @brief Extracts a named path parameter captured by the endpoint's URI template.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request inside the @c ucall_received_http_request_callback_t.
 *  @param[in] name The @b case-sensitive placeholder name, without braces.
 *  @param[in] name_length The length of the @p name string.
 *  @param[out] output Output pointer for the start of the captured value.
 *  @param[out] output_length Output length of the captured value.
 *
 *  For an endpoint registered as @c "/users/{id}/posts/{post_id}" receiving @c "/users/7/posts/3",
 *  a @p name of @c "id" yields @c "7". A greedy wildcard @c {*path} captures the remaining segments
 *  including separators.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_request_path_parameter(               //
    ucall_server_t server, ucall_received_http_request_t request, //
    ucall_string_t name, size_t name_length,                      //
    ucall_string_t *output, size_t *output_length);

/**
 *  @brief Extracts the named string parameter from the received request.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request inside the @c ucall_received_http_request_callback_t.
 *  @param[in] param_name The @b case-sensitive name of the parameter to extract.
 *  @param[in] param_name_length The length of the @p param_name string.
 *  @param[out] output Output pointer for the start of the parameter value string.
 *  @param[out] output_length Output length of the parameter value string.
 *
 *  Unlike HTTP headers, query parameters are case-sensitive by specification, but server-dependent
 *  in practice. An example would be ASP.NET / IIS, which treats "?id" and "?ID" as same parameters.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_request_query_parameter(              //
    ucall_server_t server, ucall_received_http_request_t request, //
    ucall_string_t param_name, size_t param_name_length,          //
    ucall_string_t *output, size_t *output_length);

/**
 *  @brief Extracts the named string header from the received request.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request inside the @c ucall_received_http_request_callback_t callback.
 *  @param[in] header_name The name of the HTTP header to extract (case-insensitive).
 *  @param[in] header_name_length The length of the @p header_name string.
 *  @param[out] output Output pointer for the start of the header value string.
 *  @param[out] output_length Output length of the header value string.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_request_header(                       //
    ucall_server_t server, ucall_received_http_request_t request, //
    ucall_string_t header_name, size_t header_name_length,        //
    ucall_string_t *output, size_t *output_length);

/**
 *  @brief Extracts the body content from the received request.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request inside the @c ucall_received_http_request_callback_t.
 *  @param[out] output Output pointer for the start of the body content.
 *  @param[out] output_length Output length of the body content.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_request_body(                         //
    ucall_server_t server, ucall_received_http_request_t request, //
    ucall_string_t *output, size_t *output_length);

/**
 *  @brief Pulls the next chunk of a request body that is still arriving.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request inside the @c ucall_received_http_request_callback_t.
 *  @param[out] chunk Output pointer for the start of the chunk. Aliases the receive buffer.
 *  @param[out] chunk_length Output length of the chunk. Zero when no data is available yet.
 *  @param[out] has_more Output flag, false once the final chunk has been delivered.
 *  @return @c ucall_status_would_block_k if more data is expected but none has arrived.
 *
 *  Endpoints registered as streaming are invoked as soon as headers are parsed, before the body
 *  is complete. Without this, a multi-gigabyte upload must be buffered in full before the handler
 *  runs, which is both a memory hazard and a denial-of-service vector.
 *
 *  @warning The returned @p chunk is valid only until the next call on this @p request.
 *  @sa Use @c ucall_server_request_body() for endpoints that are not registered as streaming.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_request_body_chunk(                   //
    ucall_server_t server, ucall_received_http_request_t request, //
    ucall_string_t *chunk, size_t *chunk_length, bool *has_more);

/**
 *  @brief Returns the number of parts in a @c multipart/form-data request body.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request inside the @c ucall_received_http_request_callback_t.
 *  @param[out] count Output pointer for the number of parts. Zero if the body is not multipart.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_request_part_count(                   //
    ucall_server_t server, ucall_received_http_request_t request, //
    size_t *count);

/**
 *  @brief Extracts one part of a @c multipart/form-data request body by index.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request inside the @c ucall_received_http_request_callback_t.
 *  @param[in] index Zero-based index of the part, below @c ucall_server_request_part_count().
 *  @param[out] name Output pointer for the part name from @c Content-Disposition.
 *  @param[out] name_length Output length of the part name.
 *  @param[out] content_type Output pointer for the part's @c Content-Type. Empty if absent.
 *  @param[out] content_type_length Output length of the content type.
 *  @param[out] data Output pointer for the part payload. Aliases the receive buffer, never copied.
 *  @param[out] data_length Output length of the part payload.
 *
 *  The payload is handed over without decoding. Media formats are the application's concern -
 *  pass @p data straight to an image or video decoder to keep the path copy-free.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_request_part_at(                                    //
    ucall_server_t server, ucall_received_http_request_t request, size_t index, //
    ucall_string_t *name, size_t *name_length,                                  //
    ucall_string_t *content_type, size_t *content_type_length,                  //
    ucall_string_t *data, size_t *data_length);

/**
 *  @brief Returns the number of individual requests in a batch.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] batch Batch request handle from batch callback.
 *  @return Number of requests in the batch (always >= 1).
 *
 *  @note @b Thread-safe across batches. Two threads must not operate on the
 *    @b same @p batch concurrently.
 */
size_t ucall_server_batch_size(ucall_server_t server, ucall_received_batch_http_request_t batch);

/**
 *  @brief Unpacks an individual request from a batch by index.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] batch Batch request handle from batch callback.
 *  @param[in] index Zero-based index of the request to extract (must be < batch size).
 *  @param[out] call Output variable to hold the extracted request handle.
 *  @return Status code indicating success or failure (invalid index).
 *
 *  @note @b Thread-safe across batches. Two threads must not operate on the
 *    @b same @p batch concurrently.
 */
ucall_status_t ucall_server_batch_unpack(                             //
    ucall_server_t server, ucall_received_batch_http_request_t batch, //
    size_t index, ucall_received_http_request_t *call);

#pragma endregion Received Requests

#pragma region Planned Replies

/**
 *  @brief Sends an HTTP response with custom headers and body.
 *
 *  Automatically sets standard headers: @c Content-Length, @c Date, @c Server.
 *
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request to reply to.
 *  @param[in] headers Array of custom headers ("Content-Type", "application/json", "X-Foo", "bar").
 *  @param[in] headers_lengths Optional array of lengths (NULL = use strlen).
 *  @param[in] headers_count Number of header name-value pairs (total strings / 2).
 *  @param[in] body Response body content. Can be NULL for empty body.
 *  @param[in] body_length Length of body in bytes.
 *  @return Status code indicating success or failure.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_reply_content(                                              //
    ucall_server_t server, ucall_received_http_request_t request,                       //
    ucall_string_t const *headers, size_t const *headers_lengths, size_t headers_count, //
    ucall_string_t body, size_t body_length);

/**
 *  @brief Sends an error response with plain text message.
 *
 *  Automatically sets @c Content-Type: @c text/plain.
 *  For errors requiring custom headers, use @c ucall_server_reply_content() instead.
 *
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request to reply to.
 *  @param[in] status_code HTTP error status code (400, 404, 500, etc.).
 *  @param[in] message Error message text.
 *  @param[in] message_length Length of message in bytes.
 *  @return Status code indicating success or failure.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_reply_error(                          //
    ucall_server_t server, ucall_received_http_request_t request, //
    int status_code, ucall_string_t message, size_t message_length);

/**
 *  @brief Sends a response assembled from several non-contiguous buffers.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request to reply to.
 *  @param[in] headers Array of custom headers ("Content-Type", "application/json").
 *  @param[in] headers_lengths Optional array of lengths (NULL = use strlen).
 *  @param[in] headers_count Number of header name-value pairs (total strings / 2).
 *  @param[in] parts Array of buffers concatenated, in order, to form the body.
 *  @param[in] parts_count Number of entries in @p parts.
 *
 *  Lets a handler reply with a header, a tensor, and a trailer without concatenating them
 *  into a staging buffer first.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_reply_vectored(                                             //
    ucall_server_t server, ucall_received_http_request_t request,                       //
    ucall_string_t const *headers, size_t const *headers_lengths, size_t headers_count, //
    ucall_buffer_t const *parts, size_t parts_count);

#pragma region Streaming and Zero Copy Replies

/**
 *  @brief Begins a streamed response, emitting the status line and headers.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request to reply to.
 *  @param[in] status_code HTTP status code for the response.
 *  @param[in] headers Array of custom headers. Omit @c Content-Length to use chunked encoding.
 *  @param[in] headers_lengths Optional array of lengths (NULL = use strlen).
 *  @param[in] headers_count Number of header name-value pairs (total strings / 2).
 *
 *  Must be followed by zero or more @c ucall_server_reply_chunk() calls and exactly one
 *  @c ucall_server_reply_end(). Supplying @c Content-Length switches to identity encoding,
 *  which is what @c Range responses need.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_reply_begin(                          //
    ucall_server_t server, ucall_received_http_request_t request, //
    int status_code,                                              //
    ucall_string_t const *headers, size_t const *headers_lengths, size_t headers_count);

/**
 *  @brief Appends one chunk to a response opened with @c ucall_server_reply_begin().
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request being replied to.
 *  @param[in] data Chunk payload. Copied before returning.
 *  @param[in] data_length Length of the chunk in bytes.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_reply_chunk(                          //
    ucall_server_t server, ucall_received_http_request_t request, //
    ucall_string_t data, size_t data_length);

/**
 *  @brief Completes a response opened with @c ucall_server_reply_begin().
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request being replied to. Invalid once this returns.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_reply_end(ucall_server_t server, ucall_received_http_request_t request);

/**
 *  @brief Replies with a byte range of an open file, bypassing user space entirely.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request to reply to.
 *  @param[in] file_descriptor An open, readable, seekable descriptor. @b Ownership transfers to UCall.
 *  @param[in] offset Byte offset within the file at which to start.
 *  @param[in] length Number of bytes to send. Zero sends through end of file.
 *
 *  On the @c io_uring backend this splices the file straight into the socket, so payload bytes
 *  never enter user space. UCall closes @p file_descriptor once the reply completes or fails,
 *  because the caller cannot otherwise know when the asynchronous send is done.
 *
 *  @warning Mutually exclusive with Noise. Encryption requires the payload in user space, so
 *    connections using @c ucall_security_noise_* fall back to a buffered copy.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_reply_file(                           //
    ucall_server_t server, ucall_received_http_request_t request, //
    int file_descriptor, uint64_t offset, uint64_t length);

/**
 *  @brief Replies with a byte range of a file named relative to a directory descriptor.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request to reply to.
 *  @param[in] directory_descriptor An open directory acting as the containment root.
 *  @param[in] relative_path Path resolved beneath @p directory_descriptor.
 *  @param[in] relative_path_length Length of @p relative_path.
 *  @param[in] offset Byte offset within the file at which to start.
 *  @param[in] length Number of bytes to send. Zero sends through end of file.
 *
 *  Preferred over @c ucall_server_reply_file() on the @c io_uring backend, where the open,
 *  splice, and close are chained into one submission and the handler thread issues no syscalls.
 *  Resolution is confined beneath @p directory_descriptor, so a @c "../" in @p relative_path
 *  fails rather than escaping. UCall retains no reference to @p directory_descriptor.
 *
 *  @note @b Thread-safe across requests. Two threads must not operate on the
 *    @b same @p request concurrently.
 */
ucall_status_t ucall_server_reply_path(                           //
    ucall_server_t server, ucall_received_http_request_t request, //
    int directory_descriptor,                                     //
    ucall_string_t relative_path, size_t relative_path_length,    //
    uint64_t offset, uint64_t length);

#pragma endregion Streaming and Zero Copy Replies

#pragma endregion Planned Replies

#pragma region WebSockets

/**
 *  @brief Sends a message to a connected WebSocket client.
 *
 *  Thread-safe, can be called from any thread including from within the callback itself.
 *
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] websocket WebSocket connection handle from the callback.
 *  @param[in] opcode Message type (text, binary, ping, pong).
 *  @param[in] data Message payload.
 *  @param[in] data_length Length of the message payload.
 *  @return Status code indicating success or failure.
 *
 *  @note @b Thread-safe.
 */
ucall_status_t ucall_server_websocket_send(             //
    ucall_server_t server, ucall_websocket_t websocket, //
    ucall_websocket_opcode_t opcode, ucall_string_t data, size_t data_length);

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
void ucall_server_websocket_close(ucall_server_t server, ucall_websocket_t websocket);

#pragma endregion WebSockets

#pragma endregion Servers

#pragma region Diagnostics

/**
 *  @brief Returns a static human-readable description of a status code.
 *  @param[in] status The status code to describe.
 *  @return A @c NULL -terminated string with static storage duration. Never @c NULL.
 *
 *  @note @b Thread-safe.
 */
ucall_string_t ucall_status_description(ucall_status_t status);

#pragma endregion Diagnostics

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif
