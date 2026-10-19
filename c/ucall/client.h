/**
 *  @file c/ucall/client.h
 *  @author Ash Vardanian
 *  @date Feb 3, 2023
 *  @brief The client lifecycle and HTTP and WebSocket operations of the UCall C interface.
 */
#ifndef UNUM_UCALL_CLIENT_H
#define UNUM_UCALL_CLIENT_H

#include "ucall/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  @brief Configuration parameters for the UCall client.
 *  @sa Initialize with @c ucall_client_init().
 */
typedef struct ucall_client_config_t {

    /** Maximum simultaneously open connections. Default: 100. */
    size_t max_concurrent_connections;

    /** Time budget for establishing a connection. Default: 5'000'000. */
    size_t connect_timeout_microseconds;

    /** Time budget for a full request-response exchange. Default: 30'000'000. */
    size_t request_timeout_microseconds;

    /** Client identity for handshakes. Required for Noise; unused on plaintext connections. */
    ucall_noise_key_t const* noise_private_key;

    /** Vets server static keys. Required for XX. Default: NULL. */
    ucall_peer_authorizer_t peer_authorizer;

    /** Passed verbatim to @c peer_authorizer. */
    void* peer_authorizer_context;

    /** Where log lines go. Default: nowhere. */
    ucall_log_t log;

    /** Depth of the submission queue backing the client. Default: 128. */
    size_t queue_depth;

} ucall_client_config_t;

/** Arguments of @c ucall_client_init(). */
typedef struct ucall_client_init_t {

    /** Output for the new client. Free with @c ucall_client_free() at the end. */
    ucall_client_t* client;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** Requested configuration. Zeroed fields take their documented defaults. */
    ucall_client_config_t const* config;

    /** Optional output for @c config with every default filled in. */
    ucall_client_config_t* resolved;

    /** Slots of the fixed in-flight table, one per deferred call not yet final. A deferred call
     *  finding it full stores @c ucall_status_contended_k as its final status. Zero means a
     *  default. */
    size_t deferred_limit;

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
 *  @note Call during setup only, before any thread enters @c ucall_client_call(), and only once the
 *      outcome of every call submitted to it is final.
 */
UCALL_EXPORT void ucall_client_free(ucall_client_t client);

/** Options for individual UCall client requests and connections.
 *
 *  All of them control the library behavior on a per-request basis, but don't affect the HTTP
 *  headers of individual requests. */
typedef struct ucall_request_options_t {

    /** Time budget for this call. Default: 5'000'000. */
    size_t timeout_microseconds;

    /** Retries attempted on transport failure. Default: 3. */
    size_t max_retries;

    /** Redirect hops followed before failing. Default: 5. */
    size_t max_redirects;

    /** Transport security for this call. Default: ucall_security_mode_none_k. */
    ucall_security_mode_t security;

    /** Needed for KK security mode. */
    ucall_noise_key_t const* client_key;

    /** Needed for IK and KK security modes. */
    ucall_noise_key_t const* server_key;

} ucall_request_options_t;

/** Arguments of @c ucall_client_call(). */
typedef struct ucall_client_call_t {

    /** The client this call operates on. */
    ucall_client_t client;

    /** Output for the outcome, final once its status leaves @c ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** Whether the call blocks or returns once queued; zero blocks. */
    ucall_completion_t completion;

    /** Full URL, with an explicit byte length. */
    ucall_bytes_view_t url;

    /** HTTP method, like @c ucall_verb_get_k or @c ucall_verb_post_k, etc. */
    ucall_verb_t verb;

    /** Every HTTP header line, each as a counted byte view. */
    ucall_bytes_view_t const* headers;

    /** Number of strings in the @c headers array. */
    size_t headers_count;

    /** Request body; an empty view sends no payload. */
    ucall_bytes_view_t body;

    /** Output for the received response, which owns its headers and body. Free with @c
     *  ucall_received_http_response_free() once done. */
    ucall_received_http_response_t* response;

    /** Per-request timeouts, retries, redirects, and security. Zeroed fields take their
     *  defaults. */
    ucall_request_options_t options;

} ucall_client_call_t;

/**
 *  @brief Makes a single HTTP call, blocking until the response arrives or returning once queued.
 *
 *  @note @b Thread-safe. A blocking call holds its calling thread; deferred calls let one thread
 *      keep any number in flight, each with its own outcome.
 *
 *  @par Blocking and Asynchronous Calls
 *
 *  A blocking call, the default, returns with @c response written and the final status in @c
 *  outcome. A deferred one, with @c completion set to @c ucall_completion_deferred_k, returns at
 *  once and the client's own connection thread drives the exchange: it writes @c response, then
 *  stores the final status in @c outcome. Until then @c outcome->status reads @c
 *  ucall_status_deferred_k, and the caller waits with @c ucall_outcome_wait() or polls with @c
 *  ucall_outcome_status().
 *
 *  A blocking call made inside a server endpoint holds its worker thread until the call finishes.
 *
 *  @par Headers
 *
 *  Some of the standard HTTP headers are automatically managed by UCall, such as:
 *  - @c Host: Set from the @c url field.
 *  - @c Content-Length: Set based on the @c body.length field.
 *  - @c User-Agent: Set to a default value identifying the UCall client.
 *
 *  Those shouldn't be included in the @c headers array. All header names will be normalized to
 *  lower-case before sending.
 *
 *  @par Redirects
 *
 *  HTTP redirects are a two-step protocol mechanism: the server responds with a 3xx status code and
 *  @c Location header, and the client automatically follows by making a new request.
 *
 *  Common redirect codes:
 *  - @b 301/308: Permanent redirects (domain changes, HTTPS migration). Client may cache.
 *  - @b 302/307: Temporary redirects (maintenance, A/B testing). Client shouldn't cache.
 *  - @b 303: After @c POST submission - redirect to result page via @c GET (prevents duplicate
 *    submissions).
 *  - @b 304: Not Modified - cached version is still fresh, saves bandwidth.
 *
 *  Redirect chains occur when multiple redirects happen in sequence, for example
 *      http://site.com → https://site.com → https://www.site.com. Chains longer than
 *  @c ucall_request_options_t::max_redirects fail with @c ucall_status_malformed_k.
 */
UCALL_EXPORT void ucall_client_call(ucall_client_call_t* arguments);

/** Arguments of @c ucall_client_websocket_connect(). */
typedef struct ucall_client_websocket_connect_t {

    /** The client this call operates on. */
    ucall_client_t client;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** Full URL, with an explicit byte length. */
    ucall_bytes_view_t url;

    /** Output for the WebSocket handle. */
    ucall_websocket_t* websocket;

    /** Timeouts, retries, and security for the handshake. Zeroed fields take their defaults. */
    ucall_request_options_t options;

} ucall_client_websocket_connect_t;

/**
 *  @brief Establishes a WebSocket connection and blocks until the handshake completes.
 *  @note @b Thread-safe.
 */
UCALL_EXPORT void ucall_client_websocket_connect(ucall_client_websocket_connect_t* arguments);

/** Arguments of @c ucall_client_websocket_receive(). */
typedef struct ucall_client_websocket_receive_t {

    /** The client this call operates on. */
    ucall_client_t client;

    /** Receives @c ucall_status_timeout_k if no message arrived, @c
     *  ucall_status_connection_closed_k once the peer closes the connection. */
    ucall_outcome_t* outcome;

    /** WebSocket handle from @c ucall_client_websocket_connect(). */
    ucall_websocket_t websocket;

    /** Output for the received message type. */
    ucall_websocket_opcode_t* opcode;

    /** Output for the message payload. Valid until the next call. */
    ucall_bytes_view_t* data;

    /** Maximum time to block. Zero returns immediately. */
    size_t timeout_microseconds;

} ucall_client_websocket_receive_t;

/**
 *  @brief Blocks until a message arrives on an established WebSocket connection.
 *
 *  @note @b Thread-safe against @c ucall_client_websocket_send() on the same @c websocket, so one
 *      thread may receive while another sends. Two threads must not receive concurrently.
 *
 *  Unlike the server side, which dispatches to @c ucall_websocket_callback_t from within its own
 *  loop, the client receives on a loop the application owns.
 */
UCALL_EXPORT void ucall_client_websocket_receive(ucall_client_websocket_receive_t* arguments);

/** Arguments of @c ucall_received_http_response_header(). */
typedef struct ucall_received_http_response_header_t {

    /** The client this call operates on. */
    ucall_client_t client;

    /** Receives @c ucall_status_not_found_k if the response has no such header. */
    ucall_outcome_t* outcome;

    /** The received response from @c ucall_client_call(). */
    ucall_received_http_response_t response;

    /** The name of the HTTP header to extract (case-insensitive). */
    ucall_bytes_view_t name;

    /** Output for a borrowed view of the header value. */
    ucall_bytes_view_t* value;

} ucall_received_http_response_header_t;

/**
 *  @brief Extracts the named string header from the received response.
 *
 *  Header name matching is case-insensitive per RFC 7230.
 *
 *  @note @b Thread-safe across responses. Two threads must not operate on the @b same @c response
 *      concurrently.
 */
UCALL_EXPORT void ucall_received_http_response_header(ucall_received_http_response_header_t* arguments);

/** Arguments of @c ucall_received_http_response_body(). */
typedef struct ucall_received_http_response_body_t {

    /** The client this call operates on. */
    ucall_client_t client;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** The received response from @c ucall_client_call(). */
    ucall_received_http_response_t response;

    /** Output for a borrowed view of the body. */
    ucall_bytes_view_t* body;

} ucall_received_http_response_body_t;

/**
 *  @brief Extracts the body content from the received response.
 *
 *  @note @b Thread-safe across responses. Two threads must not operate on the @b same @c response
 *      concurrently.
 */
UCALL_EXPORT void ucall_received_http_response_body(ucall_received_http_response_body_t* arguments);

/**
 *  @brief Frees the received response handle. Does nothing for @c NULL.
 *  @param[in] response The received response from @c ucall_client_call(), or @c NULL.
 *
 *  @note @b Thread-safe across responses. Two threads must not operate on the @b same @p response
 *      concurrently.
 */
UCALL_EXPORT void ucall_received_http_response_free(ucall_received_http_response_t response);

/** Arguments of @c ucall_client_websocket_send(). */
typedef struct ucall_client_websocket_send_t {

    /** The client this call operates on. */
    ucall_client_t client;

    /** Output for the outcome, final once its status leaves ucall_status_deferred_k. */
    ucall_outcome_t* outcome;

    /** WebSocket connection handle from @c ucall_client_websocket_connect(). */
    ucall_websocket_t websocket;

    /** Message type (text, binary, ping, pong). */
    ucall_websocket_opcode_t opcode;

    /** Message payload. */
    ucall_bytes_view_t data;

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

#ifdef __cplusplus
}
#endif

#endif // UNUM_UCALL_CLIENT_H
