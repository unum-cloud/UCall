/**
 *  @file src/server_shared.cpp
 *  @author Ash Vardanian
 *  @date August 15, 2023
 *  @brief Request access and response operations shared by the server backends.
 */
#include <ucall/ucall.h>

#include "automata.hpp"
#include "containers.hpp"
#include "network.hpp"
#include "server.hpp"
#include "shared.hpp"

unum::ucall::any_param_t param_at(ucall_message_t call, ucall_string_t name, size_t name_len) noexcept {
    automata_t& automata = *reinterpret_cast<automata_t*>(call);
    name_len = unum::ucall::string_length(name, name_len);
    return automata.get_protocol().get_param({name, name_len});
}

unum::ucall::any_param_t param_at(ucall_message_t call, size_t position) noexcept {
    automata_t& automata = *reinterpret_cast<automata_t*>(call);
    return automata.get_protocol().get_param(position);
}

#pragma region C Interface Implementation

void ucall_add_endpoint(ucall_server_t punned_server, ucall_string_t name, ucall_callback_t callback,
                        ucall_verb_t callback_type, ucall_endpoint_tag_t endpoint_tag) {
    server_state_t& server = *reinterpret_cast<server_state_t*>(punned_server);
    server.engine.try_add_callback({{name, strlen(name)}, callback, callback_type, endpoint_tag});
}

void ucall_take_calls(ucall_server_t punned_server, uint16_t thread_idx) {
    server_state_t* server = reinterpret_cast<server_state_t*>(punned_server);
    if (!thread_idx && server->logs_file_descriptor > 0) server->submit_stats_heartbeat();
    while (true) { ucall_take_call(punned_server, thread_idx); }
}

void ucall_take_call(ucall_server_t punned_server, uint16_t thread_idx) {
    // Submitted buffers must remain alive until their completion is observed.
    server_state_t* server = reinterpret_cast<server_state_t*>(punned_server);
    if (thread_idx == 0) server->consider_accepting_new_connection();

    constexpr std::size_t completed_max_k {16};
    completed_event_t completed_events[completed_max_k] {};

    std::size_t completed_count = server->network_engine.pop_completed_events<completed_max_k>(completed_events);

    for (std::size_t i = 0; i != completed_count; ++i) {
        completed_event_t& completed = completed_events[i];

        automata_t automata {
            *server, //
            *completed.connection_ptr,
            completed.result,
        };

        // If everything is fine, let automata work in its normal regime.
        automata();
    }
}

void ucall_reply_content(ucall_message_t call, ucall_string_t body, size_t body_len) {
    automata_t& automata = *reinterpret_cast<automata_t*>(call);
    connection_t& connection = automata.connection;

    body_len = unum::ucall::string_length(body, body_len);
    connection.protocol.append_response(connection.pipes, std::string_view(body, body_len));
}

void ucall_reply_error(ucall_message_t call, int code_int, ucall_string_t note, size_t note_len) {
    automata_t& automata = *reinterpret_cast<automata_t*>(call);
    connection_t& connection = automata.connection;

    note_len = unum::ucall::string_length(note, note_len);
    char code[unum::ucall::max_integer_length_k] {};
    std::to_chars_result res = std::to_chars(code, code + unum::ucall::max_integer_length_k, code_int);
    auto code_len = res.ptr - code;
    if (res.ec != std::error_code()) return ucall_reply_error_unknown(call);

    if (!connection.protocol.append_error(connection.pipes, std::string_view(code, code_len),
                                          std::string_view(note, note_len)))
        return ucall_reply_error_out_of_memory(call);
}

// TODO Abstract out errors to protocols
void ucall_reply_error_invalid_params(ucall_message_t call) {
    return ucall_reply_error(call, -32602, "Invalid method param(s).", 24);
}

void ucall_reply_error_unknown(ucall_message_t call) { return ucall_reply_error(call, -32603, "Unknown error.", 14); }

void ucall_reply_error_out_of_memory(ucall_message_t call) {
    return ucall_reply_error(call, -32000, "Out of memory.", 14);
}

bool ucall_param_named_bool(ucall_message_t call, ucall_string_t name, size_t name_len, bool* result_ptr) {
    if (auto value = param_at(call, name, name_len); std::holds_alternative<bool>(value)) {
        *result_ptr = std::get<bool>(value);
        return true;
    }
    else return false;
}

bool ucall_param_named_i64(ucall_message_t call, ucall_string_t name, size_t name_len, int64_t* result_ptr) {
    if (auto value = param_at(call, name, name_len); std::holds_alternative<int64_t>(value)) {
        *result_ptr = std::get<int64_t>(value);
        return true;
    }
    else return false;
}

bool ucall_param_named_f64(ucall_message_t call, ucall_string_t name, size_t name_len, double* result_ptr) {
    if (auto value = param_at(call, name, name_len); std::holds_alternative<double>(value)) {
        *result_ptr = std::get<double>(value);
        return true;
    }
    else return false;
}

bool ucall_request_param(ucall_message_t call, ucall_string_t name, size_t name_len, ucall_string_t* result_ptr,
                         size_t* result_len_ptr) {
    if (auto value = param_at(call, name, name_len); std::holds_alternative<std::string_view>(value)) {
        std::string_view val = std::get<std::string_view>(value);
        *result_ptr = val.data();
        *result_len_ptr = val.size();
        return true;
    }
    else return false;
}

bool ucall_param_positional_bool(ucall_message_t call, size_t position, bool* result_ptr) {
    if (auto value = param_at(call, position); std::holds_alternative<bool>(value)) {
        *result_ptr = std::get<bool>(value);
        return true;
    }
    else return false;
}

bool ucall_param_positional_i64(ucall_message_t call, size_t position, int64_t* result_ptr) {
    if (auto value = param_at(call, position); std::holds_alternative<int64_t>(value)) {
        *result_ptr = std::get<int64_t>(value);
        return true;
    }
    else return false;
}

bool ucall_param_positional_f64(ucall_message_t call, size_t position, double* result_ptr) {
    if (auto value = param_at(call, position); std::holds_alternative<double>(value)) {
        *result_ptr = std::get<double>(value);
        return true;
    }
    else return false;
}

bool ucall_param_positional_str(ucall_message_t call, size_t position, ucall_string_t* result_ptr,
                                size_t* result_len_ptr) {
    if (auto value = param_at(call, position); std::holds_alternative<std::string_view>(value)) {
        std::string_view val = std::get<std::string_view>(value);
        *result_ptr = val.data();
        *result_len_ptr = val.size();
        return true;
    }
    else return false;
}

bool ucall_request_header(ucall_message_t call, ucall_string_t header_name, size_t header_name_length,
                          ucall_string_t* output, size_t* output_length) {
    automata_t& automata = *reinterpret_cast<automata_t*>(call);
    size_t name_len = unum::ucall::string_length(header_name, header_name_length);
    std::string_view res = automata.get_protocol().get_header({header_name, name_len});
    if (res.size() == 0) return false;
    *output = res.data();
    *output_length = res.size();
    return true;
}

bool ucall_request_body(ucall_message_t call, ucall_string_t* output, size_t* output_length) {
    automata_t& automata = *reinterpret_cast<automata_t*>(call);
    std::string_view body = automata.get_protocol().get_content();
    *output = body.data();
    *output_length = body.size();
    return true;
}

#pragma endregion
