/**
 *  @file src/lib.cpp
 *  @author Ash Vardanian
 *  @date August 15, 2023
 *  @brief C entry points over each handle's initialization-selected operations, the outcome
 *      word and the percent codec through the host class's rows, and the Noise key and
 *      received response verbs.
 */
#include <cstdint>
#include <cstring> // `std::memset`

#include <span>        // `std::as_bytes`, `std::as_writable_bytes`
#include <string_view> // `std::string_view`

#include "ucall/http/messages.hpp" // `messages`, `received_response_t`, the serial kits
#include "ucall/network/types.hpp" // `ucall_server_handle_t`, `ucall_client_handle_t`
#include "lib.hpp"

using namespace unum::ucall;

static_assert(sizeof(void*) != 8 || sizeof(ucall_reply_part_t) == 48, "a reply part is 48 bytes on 64-bit targets");

namespace unum::ucall {

using http::received_response_t;
using http::serial_byteset_kit_t;
using http::serial_compare_kit_t;
using http::serial_find_kit_t;
using http::serial_fold_kit_t;
using http::serial_hash_kit_t;
using tunnel::secure_tunnel_fault_t;
using tunnel::secure_tunnel_generate_keypair;

/** Responses outlive their client and its CPU class, so reading one takes the serial kits. */
using response_http_t =
    http::messages<serial_compare_kit_t, serial_find_kit_t, serial_byteset_kit_t, serial_hash_kit_t, serial_fold_kit_t>;

template <typename handle_type_>
[[nodiscard]] static ucall_status_t admit(handle_type_ const* handle, ucall_outcome_t* outcome) noexcept {
    if (handle) return ucall_status_success_k;
    publish(outcome, ucall_status_uninitialized_k);
    return ucall_status_uninitialized_k;
}

template <typename init_type_>
static void init_network(init_type_* arguments) noexcept {
    cpu_ceiling_t ceiling;
    if (ucall_status_t const picked = pick_cpu_ceiling(arguments->options->cpu_class, ceiling);
        picked != ucall_status_success_k) {
        publish(arguments->outcome, picked);
        return;
    }
    auto options = *arguments->options;
    auto request = *arguments;
    request.options = &options;
    auto try_backend = [&](ucall_io_backend_t backend) {
        options.backend = backend;
        make_network(cpu_ladder_t {}, &request, ceiling);
        auto status = request.outcome->status;
        return status != ucall_status_unsupported_k && status != ucall_status_io_k;
    };
    if (options.backend != ucall_io_backend_automatic_k) make_network(cpu_ladder_t {}, &request, ceiling);
    else {
        bool finished = false;
#if UCALL_WITH_LINUX_URING
        finished = try_backend(ucall_io_backend_linux_uring618_k);
        if (!finished) finished = try_backend(ucall_io_backend_linux_uring612_k);
#endif
#if UCALL_WITH_LINUX_EPOLLAIO
        if (!finished) finished = try_backend(ucall_io_backend_linux_epollaio_k);
#endif
#if UCALL_WITH_KQUEUE
        if (!finished) finished = try_backend(ucall_io_backend_bsd_kqueue_k);
#endif
#if UCALL_WITH_IOCP
        if (!finished) finished = try_backend(ucall_io_backend_windows_iocp_k);
#endif
#if UCALL_WITH_POSIX
        if (!finished) finished = try_backend(ucall_io_backend_posix_k);
#endif
        if (!finished) publish(arguments->outcome, ucall_status_unsupported_k);
    }
}

} // namespace unum::ucall

extern "C" {

ucall_status_t ucall_outcome_status(ucall_outcome_t* outcome) { return host_verbs().load(outcome); }

ucall_status_t ucall_outcome_wait(ucall_outcome_t* outcome) { return host_verbs().wait(outcome); }

ucall_status_t ucall_decode_percent(ucall_bytes_view_t encoded, ucall_byte_t* decoded, size_t* length,
                                    ucall_percent_mode_t mode) {
    if (!length || mode > ucall_percent_query_k || (encoded.length && (!encoded.data || !decoded)))
        return ucall_status_invalid_argument_k;
    return host_verbs().decode_percent(encoded, decoded, length, mode);
}

void ucall_noise_key_generate(ucall_noise_key_generate_t* arguments) {
    if (!arguments) return;
    if (arguments->private_key) std::memset(*arguments->private_key, 0, sizeof(ucall_noise_key_t));
    if (arguments->public_key) std::memset(*arguments->public_key, 0, sizeof(ucall_noise_key_t));
    if (!arguments->private_key || !arguments->public_key) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    // Entropy the platform refused is an I/O failure at the ABI, which names no tunnel faults.
    if (secure_tunnel_generate_keypair(std::as_writable_bytes(std::span {*arguments->private_key}),
                                       std::as_writable_bytes(std::span {*arguments->public_key})) !=
        secure_tunnel_fault_t::none_k) {
        std::memset(*arguments->private_key, 0, sizeof(ucall_noise_key_t));
        publish(arguments->outcome, ucall_status_io_k);
        return;
    }
    publish(arguments->outcome, ucall_status_success_k);
}

void ucall_noise_key_derive(ucall_noise_key_derive_t* arguments) {
    if (!arguments) return;
    if (arguments->public_key) std::memset(*arguments->public_key, 0, sizeof(ucall_noise_key_t));
    if (!arguments->private_key || !arguments->public_key) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    host_verbs().derive_public(std::as_writable_bytes(std::span {*arguments->public_key}),
                               std::as_bytes(std::span {*arguments->private_key}));
    publish(arguments->outcome, ucall_status_success_k);
}

void ucall_server_init(ucall_server_init_t* arguments) {
    if (!arguments) return;
    if (arguments->server) *arguments->server = nullptr;
    if (!arguments->server || !arguments->outcome || !arguments->options) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    init_network(arguments);
}

void ucall_client_init(ucall_client_init_t* arguments) {
    if (!arguments) return;
    if (arguments->client) *arguments->client = nullptr;
    if (!arguments->client || !arguments->outcome || !arguments->options) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    // A bound client takes its server's network, whose engine it shares.
    if (arguments->options->server) return arguments->options->server->api->bind_client(arguments);
    init_network(arguments);
}

void ucall_server_take_call(ucall_server_take_call_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->take_call(arguments);
}

void ucall_server_take_calls(ucall_server_take_calls_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->take_calls(arguments);
}

void ucall_server_event_loop_statistics(ucall_server_event_loop_statistics_t* arguments) {
    if (!arguments) return;
    if (arguments->statistics) *arguments->statistics = {};
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->event_loop_statistics(arguments);
}

void ucall_server_take_batch(ucall_server_take_batch_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->take_batch(arguments);
}

void ucall_server_take_batches(ucall_server_take_batches_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->take_batches(arguments);
}

void ucall_server_batch_endpoint_statistics(ucall_server_batch_endpoint_statistics_t* arguments) {
    if (!arguments) return;
    if (arguments->statistics) *arguments->statistics = {};
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->batch_endpoint_statistics(arguments);
}

void ucall_client_take_completed(ucall_client_take_completed_t* arguments) {
    if (!arguments) return;
    if (arguments->count) *arguments->count = 0;
    if (admit(arguments->client, arguments->outcome) != ucall_status_success_k) return;
    arguments->client->api->take_completed(arguments);
}

void ucall_server_free(ucall_server_t server) {
    if (!server) return;
    server->api->free(server);
}
void ucall_server_stop(ucall_server_t server) {
    if (!server) return;
    server->api->stop(server);
}
void ucall_client_free(ucall_client_t client) {
    if (!client) return;
    client->api->free(client);
}

void ucall_server_add_http_endpoint(ucall_server_add_http_endpoint_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->add_http_endpoint(arguments);
}
void ucall_server_request_path(ucall_server_request_path_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->request_path(arguments);
}
void ucall_server_request_path_segment(ucall_server_request_path_segment_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->request_path_segment(arguments);
}
void ucall_server_request_path_parameter(ucall_server_request_path_parameter_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->request_path_parameter(arguments);
}
void ucall_server_request_query_parameter(ucall_server_request_query_parameter_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->request_query_parameter(arguments);
}
void ucall_server_request_header(ucall_server_request_header_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->request_header(arguments);
}
void ucall_server_request_fields_count(ucall_server_request_fields_count_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->request_fields_count(arguments);
}
void ucall_server_request_field(ucall_server_request_field_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->request_field(arguments);
}
void ucall_server_request_query(ucall_server_request_query_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->request_query(arguments);
}
void ucall_server_request_peer(ucall_server_request_peer_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->request_peer(arguments);
}
void ucall_server_request_body(ucall_server_request_body_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->request_body(arguments);
}
void ucall_server_reply_content(ucall_server_reply_content_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->reply_content(arguments);
}
void ucall_server_reply_error(ucall_server_reply_error_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->reply_error(arguments);
}
void ucall_client_call(ucall_client_call_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->client, arguments->outcome) != ucall_status_success_k) return;
    arguments->client->api->call(arguments);
}
void ucall_client_response_header(ucall_client_response_header_t* arguments) {
    if (!arguments) return;
    if (arguments->value) *arguments->value = {};
    if (!arguments->response || !arguments->value || !response_http_t::valid_view(arguments->name) ||
        !response_http_t::http_token(text_view(arguments->name))) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    auto& response = *static_cast<received_response_t*>(arguments->response);
    response_http_t::http_message_t message {};
    message.headers_length = response.headers_length;
    auto value = message.header(text_view(response.bytes()), text_view(arguments->name));
    *arguments->value = bytes_view(value);
    publish(arguments->outcome, value.data() ? ucall_status_success_k : ucall_status_not_found_k);
}
void ucall_client_response_fields_count(ucall_client_response_fields_count_t* arguments) {
    if (!arguments) return;
    if (arguments->count) *arguments->count = 0;
    if (!arguments->response || !arguments->count) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    auto& response = *static_cast<received_response_t*>(arguments->response);
    response_http_t::http_message_t message {};
    message.headers_length = response.headers_length;
    *arguments->count = message.fields_count(text_view(response.bytes()));
    publish(arguments->outcome, ucall_status_success_k);
}
void ucall_client_response_field(ucall_client_response_field_t* arguments) {
    if (!arguments) return;
    if (arguments->name) *arguments->name = {};
    if (arguments->value) *arguments->value = {};
    if (!arguments->response || !arguments->name || !arguments->value) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    auto& response = *static_cast<received_response_t*>(arguments->response);
    response_http_t::http_message_t message {};
    message.headers_length = response.headers_length;
    std::string_view name, value;
    if (!message.field(text_view(response.bytes()), arguments->index, name, value)) {
        publish(arguments->outcome, ucall_status_not_found_k);
        return;
    }
    *arguments->name = bytes_view(name);
    *arguments->value = bytes_view(value);
    publish(arguments->outcome, ucall_status_success_k);
}
void ucall_client_response_body(ucall_client_response_body_t* arguments) {
    if (!arguments) return;
    if (arguments->body) *arguments->body = {};
    if (!arguments->response || !arguments->body) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    auto& response = *static_cast<received_response_t*>(arguments->response);
    auto bytes = text_view(response.bytes());
    *arguments->body = bytes_view(bytes.substr(response.headers_length, response.body_length));
    publish(arguments->outcome, ucall_status_success_k);
}

ucall_verb_t ucall_server_request_verb(ucall_server_t server, ucall_received_http_request_t request) {
    return server ? server->api->request_verb(server, request) : ucall_verb_unknown_k;
}
size_t ucall_server_request_path_segments_count(ucall_server_t server, ucall_received_http_request_t request) {
    return server ? server->api->request_path_segments_count(server, request) : 0;
}
ucall_http_status_t ucall_client_response_status(ucall_received_http_response_t response) {
    return response ? static_cast<received_response_t*>(response)->status : 0;
}
void ucall_client_response_free(ucall_received_http_response_t response) {
    if (!response) return;
    auto* received = static_cast<received_response_t*>(response);
    received->destroy(received);
}

void ucall_server_add_http_batch_endpoint(ucall_server_add_http_batch_endpoint_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->add_http_batch_endpoint(arguments);
}

void ucall_server_request_body_chunk(ucall_server_request_body_chunk_t* arguments) {
    if (!arguments) return;
    if (arguments->data) *arguments->data = {};
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->request_body_chunk(arguments);
}

size_t ucall_server_request_parts_count(ucall_server_t server, ucall_received_http_request_t request) {
    return server ? server->api->request_parts_count(server, request) : 0;
}

void ucall_server_request_part(ucall_server_request_part_t* arguments) {
    if (!arguments) return;
    if (arguments->name) *arguments->name = {};
    if (arguments->content_type) *arguments->content_type = {};
    if (arguments->data) *arguments->data = {};
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->request_part(arguments);
}

void ucall_server_reply_vectored(ucall_server_reply_vectored_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->reply_vectored(arguments);
}

void ucall_server_reply_begin(ucall_server_reply_begin_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->reply_begin(arguments);
}

void ucall_server_reply_append(ucall_server_reply_append_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->reply_append(arguments);
}

void ucall_server_reply_end(ucall_server_reply_end_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->reply_end(arguments);
}

} // extern "C"
