/**
 *  @file c/ucall/client.h
 *  @author Ash Vardanian
 *  @date February 3, 2023
 *  @brief The client lifecycle and HTTP operations of the UCall C interface.
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
typedef struct ucall_client_options_t {

    /** Required positive budget for simultaneously open connections. */
    size_t max_concurrent_connections;

    /** Calls one connection may hold before the next call opens or waits for another; zero means
     *  one. No call follows one that is not idempotent or that asks to close the connection. A
     *  connection lost mid-pipeline retries its unanswered idempotent calls and fails the rest with
     *  @c ucall_status_connection_closed_k. Calls a closing server never read are sent again. */
    size_t max_pipelined_calls;

    /** Time budget for establishing a connection. Default: 5'000'000. */
    size_t connect_timeout_microseconds;

    /** Time budget for a full request-response exchange. Default: 30'000'000. */
    size_t call_timeout_microseconds;

    /** Client identity for handshakes. Required for Noise; unused on plaintext connections. */
    ucall_noise_key_t const* noise_private_key;

    /** Vets server static keys. Required for XX. Default: NULL. */
    ucall_peer_authorizer_t peer_authorizer;

    /** Passed verbatim to @c peer_authorizer. */
    void* peer_authorizer_context;

    /** Where log lines go. Default: nowhere. */
    ucall_log_t log;

    /** Accepted calls, including unretrieved completions; zero uses the connection budget times
     *  @c max_pipelined_calls. */
    size_t max_concurrent_calls;

    /** Requested I/O backend; automatic chooses an available native backend. */
    ucall_io_backend_t backend;

    /** Ceiling on the CPU class, intersected with the initialization thread's capabilities: the
     *  newest compiled class fitting both runs, and unknown sets no ceiling. A class this machine
     *  lacks still caps it, so serial is the conservative choice. Resolved options report the class
     *  picked, and callers must stay on CPUs running it after first use. */
    ucall_cpu_class_t cpu_class_ceiling;

    /** Largest response a call buffers, head and body, past which it fails with
     *  @c ucall_status_overflow_k, as @c max_request_bytes bounds a server's requests. A streamed
     *  call's cap bounds its head and each framing line of its body instead. Zero takes the largest
     *  receive buffer the kernel grants a socket. */
    size_t max_response_bytes;

    /** A server whose event loop drives this client, or NULL for a client with its own queue. A
     *  bound client shares that loop's queue, backend and CPU class, so a @c backend naming
     *  another or a @c cpu_class_ceiling picking another is an invalid argument; it is made before
     *  the loop's first poll, and is used only on its polling thread, whose take_call advances it;
     *  its take_completed only pops finished calls. @c ucall_server_free() returns without freeing
     *  while one lives. */
    ucall_server_t server;

    /** Which of @c server's event loops; ignored without @c server. */
    size_t event_loop;

} ucall_client_options_t;

/** Arguments of @c ucall_client_init(). */
typedef struct ucall_client_init_t {

    /** Output for the new client. Free with @c ucall_client_free() at the end. */
    ucall_client_t* client;

    /** Synchronous initialization result. */
    ucall_outcome_t* outcome;

    /** Requested configuration. Zeroed fields take their documented defaults. */
    ucall_client_options_t const* options;

    /** Optional output for @c options with every default filled in. */
    ucall_client_options_t* resolved;

} ucall_client_init_t;

/**
 *  @brief Initializes the client state.
 *  @note One owner at a time may submit, poll, or free the client, on any thread.
 *
 *  @par Statuses:
 *  - @c ucall_status_invalid_argument_k An output or the configuration is missing, the CPU class
 *    ceiling is a value no class takes, the connection budget is zero, or the default call budget
 *    overflows.
 *  - @c ucall_status_unsupported_k No compiled CPU class fits under the ceiling on this machine,
 *    as when a monoversioned build targets a newer CPU, or no I/O backend serves the
 *    configuration on it.
 *  - @c ucall_status_overflow_k The connection, pipelining and call budgets overflow a counter.
 */
UCALL_EXPORT void ucall_client_init(ucall_client_init_t* arguments);

/**
 *  @brief Frees the client state. Does nothing for @c NULL.
 *  @param[in] client Client from @c ucall_client_init(), or @c NULL.
 *
 *  @note Cancels accepted calls and discards unretrieved completions. Retrieved responses remain
 *      caller-owned and readable, though a streamed body that had not ended is cut short: its
 *      unpulled bytes are dropped and its next pull answers @c ucall_status_connection_closed_k.
 *      Do not submit or poll concurrently with teardown.
 */
UCALL_EXPORT void ucall_client_free(ucall_client_t client);

/** Options of one client call: time budget, retries, redirects, security and body delivery. */
typedef struct ucall_client_call_options_t {

    /** Time budget including queueing and redirects. Zero uses the client's call timeout. */
    size_t timeout_microseconds;

    /** Additional connection attempts before sending the request. Default: 3. */
    size_t max_retries;

    /** Redirect hops followed before failing. Default: 5. */
    size_t max_redirects;

    /** Transport security for this call. Default: ucall_security_none_k. */
    ucall_security_t security;

    /** The client's identity; needed for KK. */
    ucall_noise_key_t const* noise_private_key;

    /** The server's expected key; needed for IK and KK. */
    ucall_noise_key_t const* noise_peer_key;

    /** When the call completes: once the whole response is buffered, or once its head arrived, with
     *  the body pulled through @c ucall_client_response_body_chunk(). Redirects stay buffered, and
     *  only the final response streams. A streamed body has no deadline once its head arrived;
     *  freeing its response stops it. Default: buffered. */
    ucall_body_delivery_t body_delivery;

} ucall_client_call_options_t;

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
    ucall_client_call_options_t options;

    /** Caller cookie returned with the final completion. */
    void* context;

} ucall_client_call_t;

/**
 *  @brief Submits one HTTP exchange without driving network progress.
 *  @note Success guarantees exactly one record from @c ucall_client_take_completed() or
 *      @c ucall_client_take_completed_call(). Keep URL, headers, body, and security-key inputs
 *      alive until that completion is retrieved. The argument struct and acceptance outcome may
 *      be reused after submission returns. One owner submits and polls this client; calls are
 *      not internally synchronized.
 *  @note Host, Content-Length, and User-Agent are generated by the client. Do not supply them in
 *      the header array. Redirects obey @c ucall_client_call_options_t::max_redirects.
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c client is @c NULL.
 *  - @c ucall_status_unsupported_k The @c url names a scheme other than @c http and @c http+noise.
 *  - @c ucall_status_invalid_argument_k A view, the @c verb, the security mode or the body delivery
 *    is invalid, the mode lacks the key or authorizer it needs, or the @c url has no scheme or a
 *    malformed authority.
 *  - @c ucall_status_contended_k Every call the client admits is taken.
 *  - @c ucall_status_overflow_k The @c url's length overflows its counter.
 */
UCALL_EXPORT void ucall_client_call(ucall_client_call_t* arguments);

/** A final result for one accepted client call. */
typedef struct ucall_completed_call_t {

    /** Cookie supplied when the call was submitted. */
    void* context;

    /** Final network or protocol outcome, independent of the acceptance result. */
    ucall_outcome_t outcome;

    /** Received response, or NULL on failure. Free with @c ucall_client_response_free(). */
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
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c client is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c count output is @c NULL, or @c calls is @c NULL
 *    with a nonzero @c capacity.
 */
UCALL_EXPORT void ucall_client_take_completed(ucall_client_take_completed_t* arguments);

/** Arguments of @c ucall_client_take_completed_call(). */
typedef struct ucall_client_take_completed_call_t {

    /** Client whose accepted calls to advance. */
    ucall_client_t client;

    /** Outcome of the wait, independently of the completed call's own outcome. */
    ucall_outcome_t* outcome;

    /** Cookie the wanted call was submitted with; the oldest such call is taken. */
    void* context;

    /** Output for that call's completion, zeroed until it is taken. */
    ucall_completed_call_t* call;

    /** Maximum wait; zero waits until the call finishes, which its own time budget bounds. */
    size_t timeout_microseconds;

} ucall_client_take_completed_call_t;

/**
 *  @brief Drives client I/O on the calling thread until the call submitted with @c context
 *      finishes, and retrieves its result alone, leaving every other completion queued in order
 *      for @c ucall_client_take_completed().
 *  @note Retrieving the completion returns its admission credit. Free its response after use.
 *      Only one owner may submit or poll this client at a time. A client bound to a server only
 *      takes what that loop finished, as its polling thread alone drives it.
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c client is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c call output is @c NULL.
 *  - @c ucall_status_would_block_k The call is still running once the timeout passed, or on a
 *    bound client whose loop has not finished it.
 *  - @c ucall_status_not_found_k No call admitted with @c context runs or waits to be taken.
 */
UCALL_EXPORT void ucall_client_take_completed_call(ucall_client_take_completed_call_t* arguments);

/**
 *  @brief Returns the HTTP status of a received response.
 *  @param[in] response Response from ucall_client_take_completed().
 *  @return The peer's status code, or zero for a null response.
 */
UCALL_EXPORT ucall_http_status_t ucall_client_response_status(ucall_received_http_response_t response);

/** Arguments of @c ucall_client_response_header(). */
typedef struct ucall_client_response_header_t {

    /** The received response from @c ucall_client_take_completed(), readable after its client is
     *  freed. */
    ucall_received_http_response_t response;

    /** The verb's status, listed on the verb. */
    ucall_outcome_t* outcome;

    /** The name of the HTTP header to extract (case-insensitive). */
    ucall_bytes_view_t name;

    /** Output for a view into the response's bytes holding the header value, valid until the
     *  response is freed. */
    ucall_bytes_view_t* value;

} ucall_client_response_header_t;

/**
 *  @brief Extracts the named string header from the received response.
 *
 *  Header name matching is case-insensitive per RFC 7230.
 *
 *  @note @b Thread-safe across responses, though two threads must not use one @c response at once.
 *
 *  @par Statuses:
 *  - @c ucall_status_invalid_argument_k The @c response or the @c value output is @c NULL, or the
 *    header name is not an HTTP token.
 *  - @c ucall_status_not_found_k The response has no such header.
 */
UCALL_EXPORT void ucall_client_response_header(ucall_client_response_header_t* arguments);

/**
 *  @brief Returns the number of header field lines of the received response, repeated names
 *      included, or zero for a @c NULL @p response.
 *  @param[in] response The received response from @c ucall_client_take_completed(), readable
 *      after its client is freed.
 *
 *  @note @b Thread-safe across responses, though two threads must not use one @p response at once.
 */
UCALL_EXPORT size_t ucall_client_response_fields_count(ucall_received_http_response_t response);

/** Arguments of @c ucall_client_response_field(). */
typedef struct ucall_client_response_field_t {

    /** The received response from @c ucall_client_take_completed(), readable after its client is
     *  freed. */
    ucall_received_http_response_t response;

    /** The verb's status, listed on the verb. */
    ucall_outcome_t* outcome;

    /** Which field line, below @c ucall_client_response_fields_count(). */
    size_t index;

    /** Output for a view into the response's bytes holding its name, lowercased as the parser keeps
     *  every field name, valid until the response is freed. */
    ucall_bytes_view_t* name;

    /** Output for a view into the response's bytes holding its value, without surrounding
     *  whitespace, valid until the response is freed. */
    ucall_bytes_view_t* value;

} ucall_client_response_field_t;

/**
 *  @brief Extracts one header field line of the received response by its arrival order.
 *
 *  @note @b Thread-safe across responses, though two threads must not use one @c response at once.
 *
 *  @par Statuses:
 *  - @c ucall_status_invalid_argument_k The @c response, the @c name or the @c value output
 *    is @c NULL.
 *  - @c ucall_status_not_found_k The @c index is past the last field line.
 */
UCALL_EXPORT void ucall_client_response_field(ucall_client_response_field_t* arguments);

/** Arguments of @c ucall_client_response_body(). */
typedef struct ucall_client_response_body_t {

    /** The received response from @c ucall_client_take_completed(), readable after its client is
     *  freed. */
    ucall_received_http_response_t response;

    /** The verb's status, listed on the verb. */
    ucall_outcome_t* outcome;

    /** Output for a view into the response's bytes holding the body, valid until the response is
     *  freed. */
    ucall_bytes_view_t* body;

} ucall_client_response_body_t;

/**
 *  @brief Extracts the body content from the received response.
 *
 *  A streamed call's response is pulled through @c ucall_client_response_body_chunk() instead.
 *
 *  @note @b Thread-safe across responses, though two threads must not use one @c response at once.
 *
 *  @par Statuses:
 *  - @c ucall_status_invalid_argument_k The @c response or the @c body output is @c NULL, or the
 *    response is streamed.
 */
UCALL_EXPORT void ucall_client_response_body(ucall_client_response_body_t* arguments);

/** Arguments of @c ucall_client_response_body_chunk(). */
typedef struct ucall_client_response_body_chunk_t {

    /** The client the response came from. */
    ucall_client_t client;

    /** The verb's status, final on return: the next bytes, the end, or nothing decoded yet. */
    ucall_outcome_t* outcome;

    /** A response of a call submitted with @c ucall_body_delivery_streamed_k. */
    ucall_received_http_response_t response;

    /** Output for a view into the response's bytes decoded since the last pull, valid until the
     *  next pull or the response's free; empty once the body ended. */
    ucall_bytes_view_t* data;

} ucall_client_response_body_chunk_t;

/**
 *  @brief Pulls the next chunk of a response body that is still arriving.
 *
 *  A call submitted with @c ucall_body_delivery_streamed_k completes once its head arrived, so a
 *  download larger than @c max_response_bytes streams through its owner. Each pull takes every
 *  byte decoded since the last one; the connection reads on only once the previous bytes were
 *  pulled, and answers no call pipelined behind it until the body ended. A pull never blocks: the
 *  client's polling moves the bytes, so a pull with nothing decoded yet answers
 *  @c ucall_status_would_block_k. A body already whole when its head arrived, as with bodiless
 *  statuses, @c HEAD and small bodies, comes whole from the first pull, and the next one answers
 *  empty. Bytes decoded before a failure are handed out before the failure is.
 *
 *  Freeing the response before its body ended closes its connection, and the calls pipelined
 *  behind it end with @c ucall_status_connection_closed_k, never sent again. Once the client is
 *  freed, a body that had not ended drops its unpulled bytes and answers
 *  @c ucall_status_connection_closed_k.
 *
 *  @warning The returned @c data is valid only until the next pull or the response's free.
 *  @sa Use @c ucall_client_response_body() for responses that are not streamed.
 *
 *  @note Pulls run on the client's owner thread, the one polling @c ucall_client_take_completed(),
 *      while the response may be freed on any thread.
 *
 *  @par Statuses:
 *  - @c ucall_status_uninitialized_k The @c client is @c NULL.
 *  - @c ucall_status_invalid_argument_k The @c response or the @c data output is @c NULL, or the
 *    response is not streamed.
 *  - @c ucall_status_malformed_k The body's framing is malformed, or a framing line runs past
 *    @c max_response_bytes.
 *  - @c ucall_status_connection_closed_k The connection closed, or the client was freed, before the
 *    body ended.
 *  - @c ucall_status_would_block_k Nothing was decoded since the last pull, so poll the client
 *    before pulling again.
 */
UCALL_EXPORT void ucall_client_response_body_chunk(ucall_client_response_body_chunk_t* arguments);

/**
 *  @brief Frees the received response handle. Does nothing for @c NULL.
 *  @param[in] response The received response from @c ucall_client_take_completed(), or @c NULL.
 *
 *  @note @b Thread-safe across responses. Two threads must not operate on the @b same @p response
 *      concurrently.
 */
UCALL_EXPORT void ucall_client_response_free(ucall_received_http_response_t response);

#ifdef __cplusplus
}
#endif

#endif // UNUM_UCALL_CLIENT_H
