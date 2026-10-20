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

    /** Required positive budget for simultaneously open connections. */
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

    /** Accepted calls, including unretrieved completions; zero uses the connection budget. */
    size_t max_concurrent_calls;

    /** Requested I/O backend; automatic chooses an available native backend. */
    ucall_io_backend_t backend;

    /** Requested CPU class; unknown selects from the initialization thread's capabilities.
     *  Callers must stay on compatible CPUs after first use. Serial is the conservative choice. */
    ucall_cpu_class_t cpu_class;

} ucall_client_config_t;

/** Arguments of @c ucall_client_init(). */
typedef struct ucall_client_init_t {

    /** Output for the new client. Free with @c ucall_client_free() at the end. */
    ucall_client_t* client;

    /** Synchronous initialization result. */
    ucall_outcome_t* outcome;

    /** Requested configuration. Zeroed fields take their documented defaults. */
    ucall_client_config_t const* config;

    /** Optional output for @c config with every default filled in. */
    ucall_client_config_t* resolved;

} ucall_client_init_t;

/**
 *  @brief Initializes the client state.
 *  @note Initialize, submit, poll, and free the client on the same owner thread.
 */
UCALL_EXPORT void ucall_client_init(ucall_client_init_t* arguments);

/**
 *  @brief Frees the client state. Does nothing for @c NULL.
 *  @param[in] client Client from @c ucall_client_init(), or @c NULL.
 *
 *  @note Cancels accepted calls and discards unretrieved completions. Retrieved responses remain
 *      caller-owned. Do not submit or poll concurrently with teardown.
 */
UCALL_EXPORT void ucall_client_free(ucall_client_t client);

/** Options for individual UCall client requests and connections.
 *
 *  All of them control the library behavior on a per-request basis, but don't affect the HTTP
 *  headers of individual requests. */
typedef struct ucall_request_options_t {

    /** Time budget including queueing and redirects. Zero uses the client request timeout. */
    size_t timeout_microseconds;

    /** Additional connection attempts before sending the request. Default: 3. */
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

    /** Synchronous acceptance result. Success guarantees one completion; refusal produces none. */
    ucall_outcome_t* outcome;

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

    /** Per-request timeouts, retries, redirects, and security. Zeroed fields take their
     *  defaults. */
    ucall_request_options_t options;

    /** Caller cookie returned with the final completion. */
    void* context;

} ucall_client_call_t;

/**
 *  @brief Submits one HTTP exchange without driving network progress.
 *  @note Success guarantees exactly one record from @c ucall_client_take_completed(). Keep URL,
 *      headers, body, and security-key inputs alive until that completion is retrieved. The
 *      argument struct and acceptance outcome may be reused after submission returns.
 *      One owner submits and polls this client; calls are not internally synchronized.
 *  @note Host, Content-Length, and User-Agent are generated by the client. Do not supply them in
 *      the header array. Redirects obey @c ucall_request_options_t::max_redirects.
 */
UCALL_EXPORT void ucall_client_call(ucall_client_call_t* arguments);

/** A final result for one accepted client call. */
typedef struct ucall_completed_call_t {

    /** Cookie supplied when the call was submitted. */
    void* context;

    /** Final network or protocol outcome, independent of the acceptance result. */
    ucall_outcome_t outcome;

    /** Received response, or NULL on failure. Free with @c ucall_received_http_response_free(). */
    ucall_received_http_response_t response;

} ucall_completed_call_t;

/** Arguments of @c ucall_client_take_completed(). */
typedef struct ucall_client_take_completed_t {

    /** Client whose accepted calls to advance. */
    ucall_client_t client;

    /** Outcome of polling, independently of the completed calls' outcomes. */
    ucall_outcome_t* outcome;

    /** Caller-owned completion storage. */
    ucall_completed_call_t* calls;

    /** Entries available in @c calls; zero advances I/O without retrieving completions. */
    size_t capacity;

    /** Output for the number of retrieved entries. */
    size_t* count;

    /** Maximum wait for completions; zero performs one bounded nonblocking progress round. */
    size_t timeout_microseconds;

} ucall_client_take_completed_t;

/**
 *  @brief Drives client I/O and retrieves a batch of final call results on the calling thread.
 *  @note Retrieving a completion returns its admission credit. Free its response after use.
 *      Only one owner may submit or poll this client at a time.
 */
UCALL_EXPORT void ucall_client_take_completed(ucall_client_take_completed_t* arguments);

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
 *  @note Call on the client owner thread.
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
 *  @note Call on the client owner thread.
 *
 *  Unlike the server side, which dispatches to @c ucall_websocket_callback_t from within its own
 *  loop, the client receives on a loop the application owns.
 */
UCALL_EXPORT void ucall_client_websocket_receive(ucall_client_websocket_receive_t* arguments);

/**
 *  @brief Returns the HTTP status of a received response.
 *  @param[in] client Client that received the response.
 *  @param[in] response Response from ucall_client_take_completed().
 *  @return The peer's status code, or zero for a null response.
 */
UCALL_EXPORT ucall_http_status_t ucall_received_http_response_status(ucall_client_t client,
                                                                     ucall_received_http_response_t response);

/** Arguments of @c ucall_received_http_response_header(). */
typedef struct ucall_received_http_response_header_t {

    /** The client this call operates on. */
    ucall_client_t client;

    /** Receives @c ucall_status_not_found_k if the response has no such header. */
    ucall_outcome_t* outcome;

    /** The received response from @c ucall_client_take_completed(). */
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

    /** The received response from @c ucall_client_take_completed(). */
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
 *  @param[in] response The received response from @c ucall_client_take_completed(), or @c NULL.
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
 *  @note Call on the client owner thread.
 */
UCALL_EXPORT void ucall_client_websocket_send(ucall_client_websocket_send_t* arguments);

/**
 *  @brief Closes a WebSocket connection.
 *  @param[in] client Client handle from @c ucall_client_init().
 *  @param[in] websocket WebSocket connection handle to close.
 *
 *  @note Call on the client owner thread.
 */
UCALL_EXPORT void ucall_client_websocket_close(ucall_client_t client, ucall_websocket_t websocket);

#ifdef __cplusplus
}
#endif

#endif // UNUM_UCALL_CLIENT_H
