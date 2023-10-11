/**
 * @file        ucall.h
 * @author      Ash Vardanian
 * @date        Feb 3, 2023
 *
 * @addtogroup C
 *
 * @brief Binary Interface for UCall.
 *
 * ## Basic Usage
 *
 * To use UCall, at the very least you need the following few functions:
 *
 * - `ucall_init()` - to start a server,
 * - `ucall_add_procedure()` - to register a callback,
 * - `ucall_call_reply_content()` - to submit a reply from inside the callback,
 * - `ucall_take_calls()` - to run the polling loop,
 * - `ucall_free()` - to shut down.
 *
 * Assuming the C language has no reflection, and we want to avoid dynamic
 * memory allocations, there are a few functions to fetch the function arguments
 * from inside the callback. For named arguments those are:
 *
 * - `ucall_param_named_bool()`.
 * - `ucall_param_named_i64()`.
 * - `ucall_param_named_f64()`.
 * - `ucall_param_named_str()`.
 *
 * Similarly there is a `positional` counterpart to every `named` function.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h> // `bool`
#include <stddef.h>  // `size_t`
#include <stdint.h>  // `int64_t`

typedef void* ucall_server_t;
typedef void* ucall_call_t;
typedef void* ucall_callback_tag_t;
typedef char const* ucall_str_t;

typedef void (*ucall_callback_t)(ucall_call_t, ucall_callback_tag_t);

/**
 * @brief Represents the types of protocols that can be used.
 */
typedef enum protocol_type_t {
    tcp_k,          ///< Raw Transmission Control Protocol (TCP)
    http_k,         ///< Raw Hypertext Transfer Protocol (HTTP)
    jsonrpc_tcp_k,  ///< JSON-RPC over TCP
    jsonrpc_http_k, ///< JSON-RPC over HTTP
    rest_k          ///< REST over HTTP
} protocol_type_t;

/**
 * @brief Represents the types of callbacks/Requests.
 */
typedef enum request_type_t {
    get_k,   ///< GET Request
    put_k,   ///< PUT Request
    post_k,  ///< POST Request
    delete_k ///< DELETE Request
} request_type_t;

/**
 * @brief Configuration parameters for `ucall_init()`.
 */
typedef struct ucall_config_t {
    char const* hostname;
    uint16_t port;
    uint16_t queue_depth;
    uint16_t max_callbacks;
    uint16_t max_threads;

    /// @brief Common choices, aside from a TCP socket are:
    /// > STDOUT_FILENO: console output.
    /// > STDERR_FILENO: errors.
    int32_t logs_file_descriptor;
    /// @brief Can be:
    /// > "human" will print human-readable unit-normalized lines.
    /// > "json" will output newline-delimited JSONs documents.
    char const* logs_format;

    uint16_t max_batch_size;
    uint32_t max_concurrent_connections;
    uint32_t max_lifetime_micro_seconds;
    uint32_t max_lifetime_exchanges;

    /// @brief Connection Protocol.
    protocol_type_t protocol;

    /// @brief Private Key required for SSL.
    char const* ssl_private_key_path;
    /// @brief At least one certificate is required for SSL.
    char const** ssl_certificates_paths;
    /// @brief Certificates count.
    size_t ssl_certificates_count;
} ucall_config_t;

/**
 * @param config Input and output argument, that will be updated to export set configuration.
 * @param server Output variable, which, on success, will be an initialized server.
 * Don't forget to free its memory with `ucall_free()` at the end.
 */
void ucall_init(ucall_config_t* config, ucall_server_t* server);

void ucall_free(ucall_server_t);

/**
 * @brief Registers a function callback to be triggered by the server,
 * when a matching request arrives.
 *
 * @param server Must be pre-initialized with `ucall_init()`.
 * @param name The string to be matched against "method" in every JSON request.
 * @param callback Function pointer to the callback.
 * @param callback_type Type of the request the callback is registered for.
 * @param callback_tag Optional payload/tag, often pointing to metadata about
 * expected "params", mostly used for higher-level runtimes, like CPython.
 */
void ucall_add_procedure(         //
    ucall_server_t server,        //
    ucall_str_t name,             //
    ucall_callback_t callback,    //
    request_type_t callback_type, //
    ucall_callback_tag_t callback_tag);

/**
 * @brief Perform a single blocking round of polling on the current calling thread.
 *
 * @param thread_idx Assuming that the `::server` itself has memory reserves for every
 * thread, the caller must provide a `::thread_idx` uniquely identifying current thread
 * with a number from zero to `::ucall_config_t::max_threads`.
 */
void ucall_take_call(ucall_server_t server, uint16_t thread_idx);

/**
 * @brief Blocks current thread, replying to requests in a potentially more efficient
 * way, than just a `while` loop calling `ucall_take_call()`.
 *
 * @param thread_idx Assuming that the `::server` itself has memory reserves for every
 * thread, the caller must provide a `::thread_idx` uniquely identifying current thread
 * with a number from zero to `::ucall_config_t::max_threads`.
 */
void ucall_take_calls(ucall_server_t server, uint16_t thread_idx);

bool ucall_param_named_bool(  //
    ucall_call_t call,        //
    ucall_str_t param_name,   //
    size_t param_name_length, //
    bool* output);

bool ucall_param_named_i64(   //
    ucall_call_t call,        //
    ucall_str_t param_name,   //
    size_t param_name_length, //
    int64_t* output);

bool ucall_param_named_f64(   //
    ucall_call_t call,        //
    ucall_str_t param_name,   //
    size_t param_name_length, //
    double* output);

bool ucall_param_named_str(   //
    ucall_call_t call,        //
    ucall_str_t param_name,   //
    size_t param_name_length, //
    ucall_str_t* output, size_t* output_length);

bool ucall_param_positional_bool(ucall_call_t, size_t, bool*);
bool ucall_param_positional_i64(ucall_call_t, size_t, int64_t*);
bool ucall_param_positional_f64(ucall_call_t, size_t, double*);
bool ucall_param_positional_str(ucall_call_t, size_t, ucall_str_t*, size_t*);

bool ucall_get_request_header(ucall_call_t call,         //
                              ucall_str_t header_name,   //
                              size_t header_name_length, //
                              ucall_str_t* output, size_t* output_length);

bool ucall_get_request_body(ucall_call_t call, //
                            ucall_str_t* output, size_t* output_length);

/**
 * @param call Encapsulates the context and the arguments of the current request.
 * @param json_reply The response to send, which must be a valid JSON string.
 * @param json_reply_length An option length of `::json_reply`.
 */
void ucall_call_reply_content(ucall_call_t call, ucall_str_t json_reply, size_t json_reply_length);

/**
 * @param call Encapsulates the context and the arguments of the current request.
 * @param error_message An optional string.
 * @param error_message_length An option length of `::json_reply`.
 */
void ucall_call_reply_error(ucall_call_t call, int error_code, ucall_str_t error_message, size_t error_message_length);

void ucall_call_reply_error_invalid_params(ucall_call_t);
void ucall_call_reply_error_out_of_memory(ucall_call_t);
void ucall_call_reply_error_unknown(ucall_call_t);

bool ucall_param_named_json(ucall_call_t, ucall_str_t, size_t, ucall_str_t*, size_t*); // TODO
bool ucall_param_positional_json(ucall_call_t, size_t, ucall_str_t*, size_t*);         // TODO

#ifdef __cplusplus
} /* end extern "C" */
#endif