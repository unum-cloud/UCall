/**
 *  @file   ucall.h
 *  @author Ash Vardanian
 *  @date   Feb 3, 2023
 *
 *  @addtogroup C
 *
 *  @brief UCall is fast JSON-RPC implementation using `io_uring` and SIMD on x86 and Arm.
 *
 *  ## Basic Usage
 *
 *  To use UCall, at the very least you need the following few functions:
 *
 *  - `ucall_init()` - to start a server,
 *  - `ucall_add_procedure()` - to register a callback,
 *  - `ucall_call_reply_content()` - to submit a reply from inside the callback,
 *  - `ucall_take_calls()` - to run the polling loop,
 *  - `ucall_free()` - to shut down.
 *
 *  Assuming the C language has no reflection, and we want to avoid dynamic
 *  memory allocations, there are a few functions to fetch the function arguments
 *  from inside the callback. For named arguments those are:
 *
 *  - `ucall_param_named_bool()`.
 *  - `ucall_param_named_i64()`.
 *  - `ucall_param_named_f64()`.
 *  - `ucall_param_named_str()`.
 *
 *  Similarly there is a `positional` counterpart to every `named` function.
 */

#ifndef UCALL_H_
#define UCALL_H_

#define UCALL_VERSION_MAJOR 0
#define UCALL_VERSION_MINOR 5
#define UCALL_VERSION_PATCH 8

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h> // `bool`
#include <stddef.h>  // `size_t`
#include <stdint.h>  // `int64_t`

/// @brief Opaque type-punned server handle.
typedef void* ucall_server_t;

/// @brief Opaque type-punned handle for a single Remote Procedure Call.
typedef void* ucall_call_t;

/// @brief Opaque type-punned handle for several batched Remote Procedure Calls.
typedef void* ucall_batch_call_t;

/// @brief Opaque type-punned handle to identify dynamically defined endpoints.
typedef void* ucall_callback_tag_t;

/// @brief Type alias for immutable strings.
typedef char const* ucall_str_t;

typedef void (*ucall_callback_t)(ucall_call_t, ucall_callback_tag_t);

typedef void (*ucall_batch_callback_t)(ucall_batch_call_t, ucall_callback_tag_t);

/**
 *  @brief Configuration parameters for the UCall server.
 *  @see `ucall_init()` to initialize the server.
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

} ucall_config_t;

/**
 *  @brief  Initializes the server state.
 *
 *  @param config   Input and output argument, that will be updated to export set configuration.
 *  @param server   Output variable, which, on success, will be an initialized server.
 *                  Don't forget to free its memory with `ucall_free()` at the end.
 */
void ucall_init(ucall_config_t* config, ucall_server_t* server);

void ucall_free(ucall_server_t);

/**
 *  @brief  Registers a function callback to be triggered by the server,
 *          when a matching request arrives.
 *
 *  @param server           Must be pre-initialized with `ucall_init()`.
 *  @param name             The string to be matched against "method" in every JSON request.
 *                          Must be @b unique, and can't be reused in `ucall_add_batched_procedure`.
 *  @param callback         Function pointer to the callback.
 *  @param callback_tag     Optional payload/tag, often pointing to metadata about
 *                          expected "params", mostly used for higher-level runtimes, like CPython.
 */
void ucall_add_procedure(      //
    ucall_server_t server,     //
    ucall_str_t name,          //
    ucall_callback_t callback, //
    ucall_callback_tag_t callback_tag);

/**
 *  @brief  Perform a single blocking round of polling on the current calling thread.
 *
 *  @param thread_idx   Assuming that the `::server` itself has memory reserves for every
 *                      thread, the caller must provide a `::thread_idx` uniquely identifying
 *                      current thread with a number from zero to `::ucall_config_t::max_threads`.
 */
void ucall_take_call(ucall_server_t server, uint16_t thread_idx);

/**
 *  @brief Blocks current thread, replying to requests in a potentially more efficient
 *          way, than just a `while` loop calling `ucall_take_call()`.
 *
 *  @param thread_idx   Assuming that the `::server` itself has memory reserves for every
 *                      thread, the caller must provide a `::thread_idx` uniquely identifying current
 *                      thread with a number from zero to `::ucall_config_t::max_threads`.
 */
void ucall_take_calls(ucall_server_t server, uint16_t thread_idx);

/**
 *  @brief Extracts the named @b boolean parameter from the current request (call).
 *  @param call Encapsulates the context and the arguments of the current request.
 *  @param json_pointer A JSON Pointer to the parameter.
 *  @param json_pointer_length The length of the `::json_pointer`.
 *  @param output The output boolean.
 *  @return `true` if the parameter was found and successfully extracted.
 */
bool ucall_param_named_bool(    //
    ucall_call_t call,          //
    ucall_str_t json_pointer,   //
    size_t json_pointer_length, //
    bool* output);

/**
 *  @brief Extracts the named @b integral parameter from the current request (call).
 *  @param call Encapsulates the context and the arguments of the current request.
 *  @param json_pointer A JSON Pointer to the parameter.
 *  @param json_pointer_length The length of the `::json_pointer`.
 *  @param output The output 64-bit signed integer.
 *  @return `true` if the parameter was found and successfully extracted.
 */
bool ucall_param_named_i64(     //
    ucall_call_t call,          //
    ucall_str_t json_pointer,   //
    size_t json_pointer_length, //
    int64_t* output);

/**
 *  @brief Extracts the named @b floating-point parameter from the current request (call).
 *  @param call Encapsulates the context and the arguments of the current request.
 *  @param json_pointer A JSON Pointer to the parameter.
 *  @param json_pointer_length The length of the `::json_pointer`.
 *  @param output The output 64-bit double-precision float.
 *  @return `true` if the parameter was found and successfully extracted.
 */
bool ucall_param_named_f64(     //
    ucall_call_t call,          //
    ucall_str_t json_pointer,   //
    size_t json_pointer_length, //
    double* output);

/**
 *  @brief Extracts the named @b string parameter from the current request (call).
 *  @param call Encapsulates the context and the arguments of the current request.
 *  @param json_pointer A JSON Pointer to the parameter.
 *  @param json_pointer_length The length of the `::json_pointer`.
 *  @param output The output pointer for the string start.
 *  @param output_length The output length of the string.
 *  @return `true` if the parameter was found and successfully extracted.
 */
bool ucall_param_named_str(     //
    ucall_call_t call,          //
    ucall_str_t json_pointer,   //
    size_t json_pointer_length, //
    ucall_str_t* output, size_t* output_length);

bool ucall_param_positional_bool(ucall_call_t, size_t, bool*);
bool ucall_param_positional_i64(ucall_call_t, size_t, int64_t*);
bool ucall_param_positional_f64(ucall_call_t, size_t, double*);
bool ucall_param_positional_str(ucall_call_t, size_t, ucall_str_t*, size_t*);

/**
 *  @param call Encapsulates the context and the arguments of the current request.
 *  @param json_reply The response to send, which must be a valid JSON string.
 *  @param json_reply_length An option length of `::json_reply`.
 */
void ucall_call_reply_content(ucall_call_t call, ucall_str_t json_reply, size_t json_reply_length);

/**
 *  @param call Encapsulates the context and the arguments of the current request.
 *  @param error_message An optional string.
 *  @param error_message_length An option length of `::json_reply`.
 */
void ucall_call_reply_error(ucall_call_t call, int error_code, ucall_str_t error_message, size_t error_message_length);

void ucall_call_reply_error_invalid_params(ucall_call_t);
void ucall_call_reply_error_out_of_memory(ucall_call_t);
void ucall_call_reply_error_unknown(ucall_call_t);

/**
 *  @brief Extract the entire nested @b JSON object from the current request (call).
 *  @param call Encapsulates the context and the arguments of the current request.
 *  @param output The output buffer.
 *  @param output_length The length of the `::output`.
 *  @return `true` if the parameter was found and successfully extracted.
 */
bool ucall_param_named_json(ucall_call_t, ucall_str_t, size_t, ucall_str_t*, size_t*);

/**
 *  @brief Extract the entire nested @b JSON object from the current request (call).
 *  @param call Encapsulates the context and the arguments of the current request.
 *  @param output The output buffer.
 *  @param output_length The length of the `::output`.
 *  @return `true` if the parameter was found and successfully extracted.
 */
bool ucall_param_positional_json(ucall_call_t, size_t, ucall_str_t*, size_t*);

/**
 *  @brief  Registers a function callback to be triggered by the server, adding an additional batching
 *          layer, which allows the server to collect multiple requests and process them in a single
 *          callback. Very handy for @b batch-processing, and high-latency opeations, like dispatching
 *          a GPU kernel for @b AI-inference.
 *
 *  This function is different from the inherent ability of JSON-RPS to handle batched requests.
 *  In one case, the client is responsible for batching multiple requests into a single JSON array,
 *  and sending to the server. In this case, however, single or batch requests from different sources
 *  are packed together by the server, and dispatched to the callback when the batch is full.
 *
 *  @param server           Must be pre-initialized with `ucall_init()`.
 *  @param name             The string to be matched against "method" in every JSON request.
 *                          Must be @b unique, and can't be reused in `ucall_add_batched_procedure`.
 *  @param max_batch_size   The maximum number of requests to batch together.
 *  @param max_latency_micro_seconds The maximum time to wait for the batch to fill up.
 *                              If the batch is not full, the server will dispatch the callback after this time.
 *
 *  @param callback         Function pointer to the callback.
 *  @param callback_tag     Optional payload/tag, often pointing to metadata about
 *                          expected "params", mostly used for higher-level runtimes, like CPython.
 *
 *  @see `ucall_batch_size` to extract the number of calls in the batch.
 *  @see `ucall_batch_unpack` to enumerate separate calls from within the batch.
 */
void ucall_batch_add_procedure(       //
    ucall_server_t server,            //
    ucall_str_t name,                 //
    size_t max_batch_size,            //
    size_t max_latency_micro_seconds, //
    ucall_batch_callback_t callback,  //
    ucall_callback_tag_t callback_tag);

/**
 *  @brief  Introspects the structure of the batch request.
 */
size_t ucall_batch_size(ucall_batch_call_t batch);

void ucall_batch_unpack(ucall_batch_call_t batch, ucall_call_t* call);

#ifdef __cplusplus
} /* end extern "C" */
#endif

#endif