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
 *  @brief Opaque type-punned server handle.
 *  @sa Deals with @c ucall_received_http_request_t, @c ucall_received_batch_http_request_t,
 *    @c ucall_planned_http_response_t.
 *  @sa Use with @c ucall_server_init() and @c ucall_server_free() for lifetime.
 *  @sa Use @c ucall_server_add_http_endpoint() and @c ucall_server_take_calls() for logic.
 */
typedef void *ucall_server_t;

/**
 *  @brief Opaque type-punned client handle.
 *  @sa Deals with @c ucall_planned_http_request_t, @c ucall_received_http_response_t.
 *  @sa Use with @c ucall_client_init() and @c ucall_client_free() for lifetime.
 *  @sa Use @c ucall_client_send_request() for logic.
 *
 *  At a high level, a @b client is responsible for:
 *
 *  - Establishing connections to one or more servers, reusing encryption keys between requests.
 *  - Following redirects chains automatically, unless disabled.
 */
typedef void *ucall_client_t;

/**
 *  @brief Opaque type-punned handle for a planned Remote Procedure Call on the @b client side.
 *  @sa Created by @c ucall_client_request() and polled with @c ucall_planned_http_request_ready().
 */
typedef void *ucall_planned_http_request_t;

/** @brief Opaque type-punned handle for a single Remote Procedure Call on the @b server side. */
typedef void *ucall_received_http_request_t;

/** @brief Opaque type-punned handle for several batched Remote Procedure Calls on the @b server side. */
typedef void *ucall_received_batch_http_request_t;

/** @brief Opaque type-punned handle for a single Remote Procedure Call reply on the @b server side. */
typedef void *ucall_planned_http_response_t;

/** @brief Opaque type-punned handle for a single Remote Procedure Call reply on the @b client side. */
typedef void *ucall_received_http_response_t;

/** @brief Opaque type-punned handle for a message (same as call for server context). */
typedef void *ucall_message_t;

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
    ucall_security_none_k,     // ? No encryption, plain TCP/IP.
    ucall_security_noise_xx_k, // ? Trust on first use - no pre-shared keys needed.
    ucall_security_noise_ik_k, // ? Client knows server's public key in advance.
    ucall_security_noise_kk_k  // ? Both know each other's public keys in advance.
} ucall_security_mode_t;

/**
 *  @brief Noise protocol key (32 bytes for Curve25519).
 */
typedef uint8_t ucall_noise_key_t[32];

/**
 *  @brief HTTP request methods/verbs for endpoint routing.
 *
 *  For JSON-RPC all requests are typically sent via HTTP @c POST.
 */
typedef enum ucall_verb_t {
    ucall_verb_get_k,    // ? HTTP "GET" method for retrieving resources.
    ucall_verb_post_k,   // ? HTTP "POST" method for creating resources.
    ucall_verb_put_k,    // ? HTTP "PUT" method for updating resources.
    ucall_verb_delete_k, // ? HTTP "DELETE" method for removing resources.
    ucall_verb_patch_k,  // ? HTTP "PATCH" method for partial updates.
    ucall_verb_head_k,   // ? HTTP "HEAD" method for retrieving headers only.
    ucall_verb_options_k // ? HTTP "OPTIONS" method for retrieving supported methods.
} ucall_verb_t;

/**
 *  @brief Parameter parsing mode for HTTP requests.
 *
 *  Determines how the server extracts parameters from incoming HTTP requests.
 *  Can be configured per-endpoint or globally.
 */
typedef enum ucall_params_source_t {
    ucall_params_from_uri_k,  // ? Parse parameters from URL query string (e.g., /sum?a=10&b=20).
    ucall_params_from_path_k, // ? Parse parameters from URL path (e.g., /sum/{10}/{20}).
    ucall_params_from_json_k  // ? Parse parameters from JSON body payload (e.g., {"a": 10, "b": 20}).
} ucall_params_source_t;

/**
 *  @brief Library-level status codes for UCall operations.
 *
 *  These codes represent library/transport-level outcomes.
 *  For HTTP-specific status codes (200, 404, 500), use @c ucall_http_status_t.
 */
typedef enum ucall_status_t {
    ucall_status_ok_k = 0,      // ? Operation completed successfully
    ucall_status_pending_k = 1, // ? Async operation still in progress

    ucall_status_invalid_argument_k = 2,  // ? Invalid function parameters (NULL pointers, invalid values)
    ucall_status_out_of_memory_k = 3,     // ? Memory allocation failed
    ucall_status_connection_failed_k = 4, // ? Failed to establish connection (DNS, TCP, or Noise handshake)
    ucall_status_connection_closed_k = 5, // ? Connection closed unexpectedly
    ucall_status_timeout_k = 6,           // ? Operation exceeded configured timeout

    ucall_status_not_found_k = 7,    // ? Requested resource/header/parameter not found
    ucall_status_invalid_data_k = 8, // ? Malformed or invalid protocol data

} ucall_status_t;

/**
 *  @brief HTTP status codes for server responses and client results.
 *
 *  Use these when you need HTTP-specific semantics (400, 404, 500, etc.).
 *  For library-level operations, use @c ucall_status_t instead.
 */
typedef enum ucall_http_status_t {
    // 2xx Success
    ucall_http_ok_k = 200,
    ucall_http_created_k = 201,
    ucall_http_no_content_k = 204,

    // 3xx Redirection
    ucall_http_moved_permanently_k = 301,
    ucall_http_found_k = 302,
    ucall_http_not_modified_k = 304,

    // 4xx Client errors
    ucall_http_bad_request_k = 400,
    ucall_http_unauthorized_k = 401,
    ucall_http_forbidden_k = 403,
    ucall_http_not_found_k = 404,
    ucall_http_method_not_allowed_k = 405,
    ucall_http_timeout_k = 408,
    ucall_http_conflict_k = 409,
    ucall_http_payload_too_large_k = 413,
    ucall_http_too_many_requests_k = 429,

    // 5xx Server errors
    ucall_http_internal_error_k = 500,
    ucall_http_not_implemented_k = 501,
    ucall_http_service_unavailable_k = 503,
    ucall_http_gateway_timeout_k = 504,
} ucall_http_status_t;

/**
 *  @brief WebSocket event types, shared between client and server.
 */
typedef enum ucall_websocket_event_t {
    ucall_websocket_open_k,    // ? Connection established.
    ucall_websocket_message_k, // ? Message received.
    ucall_websocket_error_k,   // ? Error occurred.
    ucall_websocket_close_k    // ? Connection closed.
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

    uint32_t max_concurrent_connections;    // ? Default: 100
    uint32_t connect_timeout_micro_seconds; // ? Default: 5'000'000
    uint32_t request_timeout_micro_seconds; // ? Default: 30'000'000

    ucall_noise_key_t const *noise_private_key; // ? Optional for client auth

    int32_t logs_file_descriptor; // ? Default: STDERR_FILENO
    char const *logs_format;      // ? Default: "human"

    uint16_t queue_depth; // ? Default: 128
} ucall_client_config_t;

/**
 *  @brief Initializes the client state.
 *  @param[inout] config Input/output argument updated to export the final configuration.
 *  @param[out] client Output variable, which on success will be an initialized client.
 *    Free with @c ucall_client_free() at the end.
 */
ucall_status_t ucall_client_init(ucall_client_config_t *config, ucall_client_t *client);

/**
 *  @brief Frees the client state.
 *  @param[in] client Must be pre-initialized with @c ucall_client_init().
 */
void ucall_client_free(ucall_client_t client);

/**
 *  @brief Options for individual UCall client requests and connections.
 *
 *  All of them control the library behavior on a per-request basis, but don't affect the HTTP
 *  headers of individual requests.
 */
typedef struct ucall_request_options_t {
    uint32_t timeout_micro_seconds; // ? Default: 5'000'000
    uint8_t max_retries;            // ? Default: 3
    uint8_t max_redirects;          // ? Default: 5

    ucall_security_mode_t security;      // ? Default: ucall_security_none_k
    ucall_noise_key_t const *client_key; // ? Needed for KK security mode
    ucall_noise_key_t const *server_key; // ? Needed for IK and KK security modes
} ucall_request_options_t;

/**
 *  @brief Performs an asynchronous HTTP request.
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
 *  @param[out] planned_http_request Output handle for the planned request.
 *  @return Status code indicating success or failure.
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
 *  Redirect chains occur when multiple redirects happen in sequence (e.g., http://site.com →
 *  https://site.com → https://www.site.com). Most browsers follow up to 20-30 redirects before
 *  stopping. Googlebot stops after 5 hops, treating longer chains as soft 404s.
 *
 *  @par Minimal Blocking Example
 *
 *  There are several ways to use this function, depending on the efficiency/complexity constraints.
 *  The simplest way is to call it, then immediately poll for readiness of the response:
 *
 *  @code{.c}
 *  ucall_client_t client;
 *  ucall_client_config_t config = {0};
 *  ucall_client_init(&config, &client);
 *
 *  ucall_planned_http_request_t request;
 *  ucall_request_options_t options = {0};
 *  ucall_client_request(client, "http://localhost:8080/sum?a=1&b=2", ucall_verb_get_k,
 *      NULL, NULL, 0,          // ! no custom headers
 *      NULL, 0,                // ! no body
 *      &options, &request);
 *
 *  ucall_received_http_response_t response;
 *  ucall_status_t status;
 *  do { status = ucall_planned_http_request_ready(request, &response); }
 *  while (status == ucall_status_pending_k);
 *  // process `response`...
 *  ucall_received_http_response_free(response);
 *  ucall_client_free(client);
 *  @endcode
 *
 *  @par Futures & Promises API
 *
 *  Unlike the server-side and WebSocket APIs, the client-side API is designed around
 *  a "Futures & Promises" asynchronous programming model. The reason is that clients
 *  often need to issue many concurrent requests to different servers, generally expecting
 *  high and non-uniform latencies from each.
 *
 *  @par Complex Batch Asynchronous Example
 *
 *  Using the Futures & Promises model, we can issue multiple requests concurrently, potentially
 *  with different security constraints, and then wait for each to complete as needed:
 *
 *  @code{.c}
 *  ucall_client_t client;
 *  ucall_client_config_t config = {0};
 *  ucall_client_init(&config, &client);
 *
 *  ucall_planned_http_request_t requests[3];
 *  ucall_request_options_t options = {0};
 *  ucall_client_request(client, "https://api.github.com/users/unum-cloud", ucall_verb_get_k,
 *      NULL, NULL, 0, NULL, 0, &options, &requests[0]);
 *  ucall_client_request(client, "https://api.weather.com/forecast", ucall_verb_post_k,
 *      NULL, NULL, 0, "{\"city\":\"New York\"}", 20, &options, &requests[1]);
 *  ucall_client_request(client, "https://localhost:8080/sum?a=1&b=2", ucall_verb_get_k,
 *      NULL, NULL, 0, NULL, 0, &options, &requests[2]);
 *
 *  size_t requests_remaining = 3;
 *  while (requests_remaining > 0) {
 *      for (size_t i = 0; i < 3; i++) {
 *          ucall_received_http_response_t response;
 *          ucall_status_t status = ucall_planned_http_request_ready(requests[i], &response);
 *          if (status == ucall_status_pending_k) continue;
 *          // process `response`...
 *          ucall_received_http_response_free(response);
 *          requests_remaining--;
 *      }
 *  }
 *  ucall_client_free(client);
 *  @endcode
 */
ucall_status_t ucall_client_request(                                                    //
    ucall_client_t client, ucall_string_t url, ucall_verb_t verb,                       //
    ucall_string_t const *headers, size_t const *headers_lengths, size_t headers_count, //
    ucall_string_t body, size_t body_length,                                            //
    ucall_request_options_t const *options,                                             //
    ucall_planned_http_request_t *planned_http_request);

/**
 *  @brief Establishes a WebSocket connection to the specified URL.
 *  @param[in] client Pre-initialized client handle.
 *  @param[in] url WebSocket URL with scheme: @c ws:// or @c ws+noise://.
 *  @param[in] options Optional request options.
 *  @param[in] callback Callback function to handle WebSocket events (receiving messages).
 *  @param[in] context User-defined context pointer for the @p callback.
 *  @param[out] websocket Output variable to hold the WebSocket handle (sending messages).
 */
ucall_status_t ucall_client_websocket(                  //
    ucall_client_t client, ucall_string_t url,          //
    ucall_request_options_t const *options,             //
    ucall_websocket_callback_t callback, void *context, //
    ucall_websocket_t *websocket);

/**
 *  @brief Non-blocking thread-safe check if the planned request is ready.
 *  @param[in] request The planned request from @c ucall_client_request() to check.
 *  @param[out] response Output variable to hold the received response handle.
 *
 *  Once complete, @p request becomes invalid. All context transfers to @p response.
 */
ucall_status_t ucall_planned_http_request_ready(ucall_planned_http_request_t request,
                                                ucall_received_http_response_t *response);

/**
 *  @brief Extracts the named string header from the received response.
 *
 *  Header name matching is case-insensitive per RFC 7230.
 *
 *  @param[in] client Client handle from @c ucall_client_init().
 *  @param[in] response The received response from @c ucall_planned_http_request_ready().
 *  @param[in] header_name The name of the HTTP header to extract (case-insensitive).
 *  @param[in] header_name_length The length of the @p header_name string.
 *  @param[out] output Output pointer for the start of the header value string.
 *  @param[out] output_length Output length of the header value string.
 *  @return Status code indicating success or failure (header not found).
 */
ucall_status_t ucall_received_http_response_header(                 //
    ucall_client_t client, ucall_received_http_response_t response, //
    ucall_string_t header_name, size_t header_name_length,          //
    ucall_string_t *output, size_t *output_length);

/**
 *  @brief Extracts the body content from the received response.
 *  @param[in] client Client handle from @c ucall_client_init().
 *  @param[in] response The received response from @c ucall_planned_http_request_ready().
 *  @param[out] output Output pointer for the start of the body content.
 *  @param[out] output_length Output length of the body content.
 *  @return Status code indicating success or failure.
 */
ucall_status_t ucall_received_http_response_body(                   //
    ucall_client_t client, ucall_received_http_response_t response, //
    ucall_string_t *output, size_t *output_length);

/**
 *  @brief Frees the received response handle.
 *  @param[in] client Client handle from @c ucall_client_init().
 *  @param[in] response The received response from @c ucall_planned_http_request_ready().
 */
void ucall_received_http_response_free(ucall_client_t client, ucall_received_http_response_t response);

/**
 *  @brief Sends a message over an established WebSocket connection.
 *  @param[in] client Client handle from @c ucall_client_init().
 *  @param[in] websocket WebSocket connection handle from @c ucall_client_websocket().
 *  @param[in] opcode Message type (text, binary, ping, pong).
 *  @param[in] data Message payload.
 *  @param[in] data_length Length of the message payload in bytes.
 *  @return Status code indicating success or failure.
 */
ucall_status_t ucall_client_websocket_send(             //
    ucall_client_t client, ucall_websocket_t websocket, //
    ucall_websocket_opcode_t opcode, ucall_string_t data, size_t data_length);

/**
 *  @brief Closes a WebSocket connection.
 *  @param[in] client Client handle from @c ucall_client_init().
 *  @param[in] websocket WebSocket connection handle to close.
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
    ucall_log_mode_human_k, // ? Human-readable unit-normalized lines
    ucall_log_mode_json_k,  // ? Newline-delimited JSONs documents
} ucall_log_mode_t;

/**
 *  @brief Configuration parameters for the UCall server.
 *  @sa Initialize with @c ucall_server_init().
 *
 *  @par Example
 *  @code{.c}
 *  ucall_server_config_t config = {
 *      .bind_address = "0.0.0.0:8080",
 *      .security_mode = ucall_security_none_k,
 *      .max_threads = 8,
 *      .max_concurrent_connections = 1000,
 *      .queue_depth = 512,
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
    char const *bind_address;                   // ? Server address in "host:port" format. Default: "0.0.0.0:8545"
    ucall_security_mode_t security_mode;        // ? Encryption mode for all connections. Default: ucall_security_none_k
    ucall_noise_key_t const *noise_private_key; // ? Server identity for handshakes. Required for secure connections.

    uint16_t max_threads;                // ? Thread pool size. Default: CPU count.
    uint16_t max_concurrent_connections; // ? Connection limit. Default: 1024.
    uint16_t queue_depth;                // ? Pending connections queue. Default: 128.

    char const *logs_output_path; // ? Log file path. NULL redirects to stderr. Default: NULL.
    ucall_log_mode_t log_mode;    // ? Log format. Default: ucall_log_mode_human_k.

    char const *metrics_address; // ? StatsD UDP endpoint "host:port". NULL = disabled. Default: NULL.
    float metrics_sample_rate;   // ? Sampling rate [0.0, 1.0]. Default: 1.0.
    char const *metrics_prefix;  // ? Metric name prefix. Default: "ucall".
    char const *metrics_tags;    // ? Global tags "key:val,key:val". Default: NULL.
} ucall_server_config_t;

/**
 *  @brief Initializes the server state.
 *  @param[inout] config Input/output argument updated to export the final configuration.
 *  @param[out] server Output variable, which on success will be an initialized server.
 *    Free with @c ucall_server_free() at the end.
 *  @return Status code indicating success or failure.
 */
ucall_status_t ucall_server_init(ucall_server_config_t *config, ucall_server_t *server);

/**
 *  @brief Frees the server state.
 *  @param[in] server Must be pre-initialized with @c ucall_server_init().
 */
void ucall_server_free(ucall_server_t server);

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
 */
ucall_status_t ucall_server_add_http_endpoint(                         //
    ucall_server_t server, ucall_string_t template, ucall_verb_t verb, //
    ucall_received_http_request_callback_t callback, void *context);

/**
 *  @brief Performs a single blocking round of polling on the current calling thread.
 *  @param[in] server Must be pre-initialized with @c ucall_server_init().
 *  @param[in] thread_index Unique thread identifier within @c ucall_server_config_t::max_threads.
 */
void ucall_server_take_call(ucall_server_t server, uint16_t thread_index);

/**
 *  @brief Blocks current thread, more efficient than a @c while loop with @c ucall_server_take_call().
 *
 *  @param[in] server Must be pre-initialized with @c ucall_server_init().
 *  @param[in] thread_index Unique thread identifier within @c ucall_server_config_t::max_threads.
 */
void ucall_server_take_calls(ucall_server_t server, uint16_t thread_index);

/**
 *  @brief Extracts the number of path components from the received request.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] request The received request inside the @c ucall_received_http_request_callback_t.
 *  @param[in] index The zero-based index of the path component to extract.
 *  @param[out] count Output pointer for the number of path components.
 */
ucall_status_t ucall_server_request_path_components_count(                      //
    ucall_server_t server, ucall_received_http_request_t request, size_t index, //
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
 */
ucall_status_t ucall_server_request_path_component(                             //
    ucall_server_t server, ucall_received_http_request_t request, size_t index, //
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
 */
ucall_status_t ucall_server_request_parameter(                    //
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
 */
ucall_status_t ucall_server_request_body(                         //
    ucall_server_t server, ucall_received_http_request_t request, //
    ucall_string_t *output, size_t *output_length);

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
 */
ucall_status_t ucall_server_reply_error(                          //
    ucall_server_t server, ucall_received_http_request_t request, //
    int status_code, ucall_string_t message, size_t message_length);

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
    size_t min_batch_size;            // ? Optimal batch size. Dispatch immediately when reached. Default: 1.
    size_t max_batch_size;            // ? Maximum requests per batch. Force dispatch when reached. Default: 32.
    size_t max_latency_micro_seconds; // ? Maximum wait time for partial batches. Default: 10'000 (10ms).
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
 */
ucall_status_t ucall_server_add_batch_endpoint(            //
    ucall_server_t server,                                 //
    ucall_string_t template, ucall_verb_t verb,            //
    ucall_server_batch_endpoint_options_t const *options,  //
    ucall_received_batch_http_request_callback_t callback, //
    void *context);

/**
 *  @brief Returns the number of individual requests in a batch.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] batch Batch request handle from batch callback.
 *  @return Number of requests in the batch (always >= 1).
 */
size_t ucall_server_batch_size(ucall_server_t server, ucall_received_batch_http_request_t batch);

/**
 *  @brief Unpacks an individual request from a batch by index.
 *  @param[in] server Server handle from @c ucall_server_init().
 *  @param[in] batch Batch request handle from batch callback.
 *  @param[in] index Zero-based index of the request to extract (must be < batch size).
 *  @param[out] call Output variable to hold the extracted request handle.
 *  @return Status code indicating success or failure (invalid index).
 */
ucall_status_t ucall_server_batch_unpack(                             //
    ucall_server_t server, ucall_received_batch_http_request_t batch, //
    size_t index, ucall_received_http_request_t *call);

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
 */
ucall_status_t ucall_server_add_websocket_endpoint( //
    ucall_server_t server, ucall_string_t template, //
    ucall_websocket_callback_t callback, void *context);

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
 */
void ucall_server_websocket_close(ucall_server_t server, ucall_websocket_t websocket);

#pragma endregion Servers

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif