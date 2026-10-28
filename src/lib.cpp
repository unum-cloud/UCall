/**
 *  @file src/lib.cpp
 *  @author Ash Vardanian
 *  @date August 15, 2023
 *  @brief C entry points over each handle's initialization-selected operations, and the Noise key
 *      and received response verbs, which need no CPU-specific code.
 */
#include <cstdint>
#include <cstring> // `std::memset`

#include <span>        // `std::as_bytes`, `std::as_writable_bytes`
#include <string_view> // `std::string_view`

#include "ucall/http.hpp"
#include "ucall/io.hpp"
#include "lib.hpp"

using namespace unum::ucall;

static_assert(sizeof(void*) != 8 || sizeof(ucall_reply_part_t) == 48, "a reply part is 48 bytes on 64-bit targets");

namespace unum::ucall {

template struct received_response<st::default_allocator<byte_t>>;

/** Responses outlive their client and its CPU class, so reading one takes the serial kits. */
using response_http_t =
    http<serial_compare_kit_t, serial_find_kit_t, serial_byteset_kit_t, serial_hash_kit_t, serial_fold_kit_t>;

template <typename handle_type_>
[[nodiscard]] static ucall_status_t admit(handle_type_ const* handle, ucall_outcome_t* outcome) noexcept {
    if (handle) return ucall_status_success_k;
    publish(outcome, ucall_status_uninitialized_k);
    return ucall_status_uninitialized_k;
}

static bool named(std::string_view spelling, ucall_bytes_view_t name) noexcept { return spelling == text_view(name); }

template <typename init_type_>
static void init_network(init_type_* arguments) noexcept {
    cpu_ceiling_t ceiling;
    if (ucall_status_t const picked = pick_cpu_ceiling(arguments->config->cpu_class, ceiling);
        picked != ucall_status_success_k) {
        publish(arguments->outcome, picked);
        return;
    }
    auto config = *arguments->config;
    auto request = *arguments;
    request.config = &config;
    auto try_backend = [&](ucall_io_backend_t backend) {
        config.backend = backend;
        make_network(cpu_ladder_t {}, &request, ceiling);
        auto status = request.outcome->status;
        return status != ucall_status_unsupported_k && status != ucall_status_io_k;
    };
    if (config.backend != ucall_io_backend_automatic_k) make_network(cpu_ladder_t {}, &request, ceiling);
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
        if (!finished) finished = try_backend(ucall_io_backend_macos_kqueue_k);
#endif
#if UCALL_WITH_IOCP
        if (!finished) finished = try_backend(ucall_io_backend_windows_iocp_k);
#endif
#if UCALL_WITH_POSIX
        if (!finished) finished = try_backend(ucall_io_backend_posix_k);
#endif
        if (!finished) publish(arguments->outcome, ucall_status_unsupported_k);
    }
    if (arguments->outcome->status != ucall_status_success_k) return;
    if constexpr (std::is_same_v<init_type_, ucall_server_init_t>) (*arguments->server)->ceiling = ceiling;
    else (*arguments->client)->ceiling = ceiling;
}

} // namespace unum::ucall

extern "C" {

char const* ucall_io_backend_name(ucall_io_backend_t backend) {
    switch (backend) {
    case ucall_io_backend_automatic_k: return "automatic";
    case ucall_io_backend_posix_k: return "posix";
    case ucall_io_backend_linux_epollaio_k: return "linux-epollaio";
    case ucall_io_backend_linux_uring612_k: return "linux-uring612";
    case ucall_io_backend_linux_uring618_k: return "linux-uring618";
    case ucall_io_backend_macos_kqueue_k: return "macos-kqueue";
    case ucall_io_backend_windows_iocp_k: return "windows-iocp";
    }
    return "unknown";
}

char const* ucall_cpu_class_name(ucall_cpu_class_t cpu_class) {
    switch (cpu_class) {
    case ucall_cpu_class_unknown_k: return "automatic";
    case ucall_cpu_class_serial_k: return "serial";
    case ucall_cpu_class_intel_haswell_k: return "intel-haswell";
    case ucall_cpu_class_intel_skylake_k: return "intel-skylake";
    case ucall_cpu_class_intel_icelake_k: return "intel-icelake";
    case ucall_cpu_class_intel_alder_k: return "intel-alder";
    case ucall_cpu_class_intel_sierra_k: return "intel-sierra";
    case ucall_cpu_class_aws_g2_k: return "aws-g2";
    case ucall_cpu_class_apple_m2_k: return "apple-m2";
    case ucall_cpu_class_aws_g5_k: return "aws-g5";
    case ucall_cpu_class_monoversioned_k: return "monoversioned";
    }
    return "unknown";
}

ucall_io_backend_t ucall_io_backend_from_name(ucall_bytes_view_t name) {
    for (auto backend = ucall_io_backend_posix_k; backend <= ucall_io_backend_windows_iocp_k;
         backend = static_cast<ucall_io_backend_t>(backend + 1))
        if (named(ucall_io_backend_name(backend), name)) return backend;
    return ucall_io_backend_automatic_k;
}

ucall_cpu_class_t ucall_cpu_class_from_name(ucall_bytes_view_t name) {
    for (auto cpu_class = ucall_cpu_class_serial_k; cpu_class <= ucall_cpu_class_monoversioned_k;
         cpu_class = static_cast<ucall_cpu_class_t>(cpu_class + 1))
        if (named(ucall_cpu_class_name(cpu_class), name)) return cpu_class;
    return ucall_cpu_class_unknown_k;
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
    x25519_derive_public(std::as_writable_bytes(std::span {*arguments->public_key}),
                         std::as_bytes(std::span {*arguments->private_key}));
    publish(arguments->outcome, ucall_status_success_k);
}

void ucall_server_init(ucall_server_init_t* arguments) {
    if (!arguments) return;
    if (arguments->server) *arguments->server = nullptr;
    if (!arguments->server || !arguments->outcome || !arguments->config) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    init_network(arguments);
}

void ucall_client_init(ucall_client_init_t* arguments) {
    if (!arguments) return;
    if (arguments->client) *arguments->client = nullptr;
    if (!arguments->client || !arguments->outcome || !arguments->config) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
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
    std::atomic_ref<std::uint32_t> {server->stopped}.store(1, std::memory_order_release);
    for (auto* wake : server->wakeups) wake->notify();
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

void ucall_client_websocket_connect(ucall_client_websocket_connect_t* arguments) {
    if (!arguments) return;
    if (arguments->websocket) *arguments->websocket = {};
    publish(arguments->outcome, ucall_status_unsupported_k);
}

void ucall_client_websocket_receive(ucall_client_websocket_receive_t* arguments) {
    if (!arguments) return;
    if (arguments->opcode) *arguments->opcode = {};
    if (arguments->data) *arguments->data = {};
    publish(arguments->outcome, ucall_status_unsupported_k);
}

void ucall_client_websocket_send(ucall_client_websocket_send_t* arguments) {
    if (!arguments) return;
    publish(arguments->outcome, ucall_status_unsupported_k);
}

void ucall_client_websocket_close(ucall_client_websocket_close_t* arguments) {
    if (!arguments) return;
    publish(arguments->outcome, ucall_status_unsupported_k);
}

void ucall_server_add_http_batch_endpoint(ucall_server_add_http_batch_endpoint_t* arguments) {
    if (!arguments) return;
    if (admit(arguments->server, arguments->outcome) != ucall_status_success_k) return;
    arguments->server->api->add_http_batch_endpoint(arguments);
}

void ucall_server_add_websocket_endpoint(ucall_server_add_websocket_endpoint_t* arguments) {
    if (!arguments) return;
    publish(arguments->outcome, ucall_status_unsupported_k);
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

void ucall_server_websocket_send(ucall_server_websocket_send_t* arguments) {
    if (!arguments) return;
    publish(arguments->outcome, ucall_status_unsupported_k);
}

void ucall_server_websocket_close(ucall_server_websocket_close_t* arguments) {
    if (!arguments) return;
    publish(arguments->outcome, ucall_status_unsupported_k);
}

} // extern "C"
