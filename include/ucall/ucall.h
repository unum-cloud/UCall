/**
 *   @file        ucall.h
 *   @author      Ash Vardanian
 *   @date        Feb 3, 2023
 *
 *   @addtogroup C
 *
 *   @brief Binary C99 interface for UCall.
 *
 *   For basic usage you are gonna need:
 *
 *   - `ucall_init()` - to start a server.
 *   - `ucall_add_endpoint()` - to register a callback.
 *   - `ucall_reply_content()` - to submit a reply from inside the callback.
 *   - `ucall_take_calls()` - to run the polling loop, or manually repeat `ucall_take_call()`.
 *   - `ucall_free()` - to shut down.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h> // `bool`
#include <stddef.h>  // `size_t`
#include <stdint.h>  // `int64_t`

/**
 * @brief A handle to the UCall server instance.
 */
typedef void* ucall_server_t;

/**
 * @brief A handle to a message instance processed by the UCall server.
 */
typedef void* ucall_message_t;

/**
 * @brief A handle to an endpoint tag which may contain additional metadata for the callback.
 */
typedef void* ucall_endpoint_tag_t;

/**
 * @brief A type alias for a constant string.
 */
typedef char const* ucall_string_t;

/**
 * @brief A function pointer type for callback functions to be registered with the UCall server.
 *
 * Most callbacks are expected to be synchronous ~ blocking. So by the time their scope is finished,
 * the server will automatically send the response back to the client. So, in most cases, the
 * callback will trigger `ucall_reply_content` or `ucall_reply_error`.
 *
 * Alternatively, for async or batch execution, you should notify the server using `ucall_reply_async`.
 * This will preserve the context, allowing you to return to the callback later, and submit the response.
 *
 * @param call The message being processed.
 * @param endpoint_tag An optional tag containing additional metadata for the callback.
 */
typedef void (*ucall_callback_t)(ucall_message_t call, ucall_endpoint_tag_t);

/**
 * @brief Enumeration representing the types of HTTP requests that can be processed.
 */
typedef enum ucall_verb_t {
    get_k,   ///< Represents an HTTP GET request.
    put_k,   ///< Represents an HTTP PUT request.
    post_k,  ///< Represents an HTTP POST request.
    delete_k ///< Represents an HTTP DELETE request.
} ucall_verb_t;

/**
 * @brief Struct containing configuration parameters for initializing a UCall server instance.
 */
typedef struct ucall_config_t {
    char const* hostname;   ///< The hostname on which the server will run.
    uint16_t port;          ///< The port on which the server will listen for incoming connections.
    uint16_t queue_depth;   ///< The depth of the queue for pending connections.
    uint16_t max_callbacks; ///< The maximum number of callbacks that can be registered with the server.
    uint16_t max_threads;   ///< The maximum number of threads that can be spawned by the server.

    /// @brief The file descriptor to which logs will be written.
    /// Common choices, aside from a TCP socket are:
    /// > STDOUT_FILENO: for console output.
    /// > STDERR_FILENO: for error output.
    int32_t logs_file_descriptor;

    /// @brief The format in which logs will be written.
    /// Can be:
    /// > "human": will print human-readable unit-normalized lines.
    /// > "json": will output newline-delimited JSON documents.
    char const* logs_format;

    uint16_t max_batch_size;             ///< The maximum batch size for processing requests.
    uint32_t max_concurrent_connections; ///< The maximum number of concurrent connections the server can handle.
    uint32_t max_lifetime_micro_seconds; ///< The maximum lifetime of a connection in microseconds.
    uint32_t max_lifetime_exchanges;     ///< The maximum number of exchanges allowed for a connection.

    /// @brief The path to the private key file required for SSL.
    char const* ssl_private_key_path;

    /// @brief An array of paths to certificate files required for SSL.
    char const** ssl_certificates_paths;

    /// @brief The count of certificates provided in `ssl_certificates_paths`.
    size_t ssl_certificates_count;
} ucall_config_t;

#pragma region Setup

/**
 *   @param config Input and output argument, that will be updated to export set configuration.
 *   @param server Output variable, which, on success, will be an initialized server.
 *   Don't forget to free its memory with `ucall_free()` at the end.
 */
void ucall_init(ucall_config_t* config, ucall_server_t* server);

void ucall_free(ucall_server_t);

/**
 *   @brief Registers a function callback to be triggered by the server,
 *   when a matching request arrives.
 *
 *   @param server Must be pre-initialized with `ucall_init()`.
 *   @param name The string to be matched against "method" in every JSON request.
 *   @param verb Type of the request the callback is registered for.
 *   @param callback Function pointer to the callback.
 *   @param endpoint_tag Optional payload/tag, often pointing to metadata about
 *   expected "params", mostly used for higher-level runtimes, like CPython.
 */
void ucall_add_endpoint(ucall_server_t server, ucall_string_t name, ucall_verb_t verb, ucall_callback_t callback,
                        ucall_endpoint_tag_t endpoint_tag);

#pragma endregion

#pragma region Event Loop

/**
 *   @brief Perform a single blocking round of polling on the current calling thread.
 *
 *   @param thread_idx Assuming that the `::server` itself has memory reserves for every
 *   thread, the caller must provide a `::thread_idx` uniquely identifying current thread
 *   with a number from zero to `::ucall_config_t::max_threads`.
 */
void ucall_take_call(ucall_server_t server, uint16_t thread_idx);

/**
 *   @brief Blocks current thread, replying to requests in a potentially more efficient
 *   way, than just a `while` loop calling `ucall_take_call()`.
 *
 *   @param thread_idx Assuming that the `::server` itself has memory reserves for every
 *   thread, the caller must provide a `::thread_idx` uniquely identifying current thread
 *   with a number from zero to `::ucall_config_t::max_threads`.
 */
void ucall_take_calls(ucall_server_t server, uint16_t thread_idx);

#pragma endregion

#pragma region Inspecting Requests

/**
 *  @brief Retrieves the decrypted version of the message from the specified call.
 *
 *  @param call The message whose decrypted version is to be retrieved.
 *  @param output The buffer where the decrypted message will be stored.
 *  @param output_length The length of the decrypted message.
 *  @return true on success, false on failure.
 */
bool ucall_request_decrypted(ucall_message_t call, ucall_string_t* output, size_t* output_length);

/**
 *  @brief Retrieves the value of a specified header from the message of the specified call.
 *
 *  @param call The call whose message's header value is to be retrieved.
 *  @param header_name The name of the header to retrieve.
 *  @param header_name_length The length of the header name string.
 *  @param output The buffer where the header value will be stored.
 *  @param output_length The length of the header value.
 *  @return true on success, false on failure.
 */
bool ucall_request_header(ucall_message_t call, ucall_string_t header_name, size_t header_name_length,
                          ucall_string_t* output, size_t* output_length);

/**
 *  @brief Retrieves the body of the message from the specified call.
 *
 *  @param call The call whose message body is to be retrieved.
 *  @param output The buffer where the body will be stored.
 *  @param output_length The length of the body.
 *  @return true on success, false on failure.
 */
bool ucall_request_body(ucall_message_t call, ucall_string_t* output, size_t* output_length);

/**
 *  @brief Retrieves the value of a specified parameter from the message of the specified call.
 *
 *  @param call The call whose message's parameter value is to be retrieved.
 *  @param param_name The name of the parameter to retrieve.
 *  @param param_name_length The length of the parameter name string.
 *  @param output The buffer where the parameter value will be stored.
 *  @param output_length The length of the parameter value.
 *  @return true on success, false on failure.
 */
bool ucall_request_param(ucall_message_t call, ucall_string_t param_name, size_t param_name_length,
                         ucall_string_t* output, size_t* output_length);

#pragma endregion

#pragma region Submitting Responses

/**
 *  @brief Sends a response message to the specified call.
 *
 *  @param call The call to respond to.
 *  @param reply The content of the response message.
 *  @param reply_length The length of the response message.
 *  @param content_type The MIME type of the content being sent.
 *  @param content_type_length The length of the content_type string.
 */
void ucall_reply_content(ucall_message_t call, ucall_string_t reply, size_t reply_length, ucall_string_t content_type,
                         size_t content_type_length);

/**
 *  @brief Sends an error response to the specified call.
 *
 *  @param call The call to respond to.
 *  @param error_code The error code to be sent.
 *  @param error_message The error message to be sent.
 *  @param error_message_length The length of the error message.
 */
void ucall_reply_error(ucall_message_t call, int error_code, ucall_string_t error_message, size_t error_message_length);

/**
 *  @brief Notifies the server, that a long-running task was started, and emits an async execution token.
 *
 *  @param call The call to respond to.
 */
void ucall_reply_async(ucall_message_t call);

void ucall_reply_error_invalid_params(ucall_message_t);
void ucall_reply_error_out_of_memory(ucall_message_t);
void ucall_reply_error_unknown(ucall_message_t);

#pragma endregion

#ifdef __cplusplus
} /*   end extern "C" */
#endif