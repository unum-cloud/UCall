/**
 *  @file src/lib.cpp
 *  @author Ash Vardanian
 *  @date August 15, 2023
 *  @brief C entry points over each handle's initialization-selected operations.
 */
#include <cassert>
#include <cstdint>
#include <cstring> // `std::strlen`, `std::memcmp`

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

#include "ucall/http.hpp"
#include "ucall/io.hpp"
#include "lib.hpp"

using namespace unum::ucall;

namespace unum::ucall {

template struct received_response<st::default_allocator<byte_t>>;

struct thread_capabilities_t {
    std::uint64_t strings, atomics;
};

static thread_capabilities_t const& thread_capabilities() noexcept {
    static thread_local thread_capabilities_t const capabilities {sz_capabilities_detected_cpu_(),
                                                                  static_cast<std::uint64_t>(fu::cpu_capabilities())};
    return capabilities;
}

template <typename handle_type_>
static bool compatible(handle_type_ const* handle) noexcept {
    auto const& capabilities = thread_capabilities();
    return (capabilities.strings & handle->string_capabilities) == handle->string_capabilities &&
           (capabilities.atomics & handle->atomic_capabilities) == handle->atomic_capabilities;
}

template <typename handle_type_>
static bool admit(handle_type_ const* handle, ucall_outcome_t* outcome) noexcept {
    if (!handle) {
        publish(outcome, ucall_status_uninitialized_k);
        return false;
    }
    if (!compatible(handle)) {
        publish(outcome, ucall_status_unsupported_k);
        return false;
    }
    return true;
}

static bool named(char const* spelling, ucall_bytes_view_t name) noexcept {
    return std::strlen(spelling) == name.length && std::memcmp(spelling, name.data, name.length) == 0;
}

template <typename init_type_>
static void init_network(init_type_* arguments) noexcept {
    auto config = *arguments->config;
    auto request = *arguments;
    request.config = &config;
    auto const& capabilities = thread_capabilities();
    auto strings = static_cast<sz_capability_t>(capabilities.strings);
    auto atomics = static_cast<fu::capabilities_t>(capabilities.atomics);
    auto try_backend = [&](ucall_io_backend_t backend) {
        config.backend = backend;
        make_network(&request, strings, atomics);
        auto status = request.outcome->status;
        return status != ucall_status_unsupported_k && status != ucall_status_io_k;
    };
    if (config.backend != ucall_io_backend_automatic_k) make_network(&request, strings, atomics);
    else {
        bool finished = false;
#if UCALL_WITH_LINUX_URING
        finished = try_backend(ucall_io_backend_linux_uring700_k);
        if (!finished) finished = try_backend(ucall_io_backend_linux_uring612_k);
#endif
#if UCALL_WITH_LINUX_EPOLL
        if (!finished) finished = try_backend(ucall_io_backend_linux_epoll_k);
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
}

} // namespace unum::ucall

extern "C" {

char const* ucall_io_backend_name(ucall_io_backend_t backend) {
    switch (backend) {
    case ucall_io_backend_automatic_k: return "automatic";
    case ucall_io_backend_posix_k: return "posix";
    case ucall_io_backend_linux_epoll_k: return "linux-epoll";
    case ucall_io_backend_linux_uring612_k: return "linux-uring612";
    case ucall_io_backend_linux_uring700_k: return "linux-uring700";
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
    for (auto cpu_class = ucall_cpu_class_serial_k; cpu_class <= ucall_cpu_class_aws_g5_k;
         cpu_class = static_cast<ucall_cpu_class_t>(cpu_class + 1))
        if (named(ucall_cpu_class_name(cpu_class), name)) return cpu_class;
    return ucall_cpu_class_unknown_k;
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
    if (!admit(arguments->server, arguments->outcome)) return;
    arguments->server->api->take_call(arguments);
}

void ucall_server_take_calls(ucall_server_take_calls_t* arguments) {
    if (!arguments) return;
    if (!admit(arguments->server, arguments->outcome)) return;
    arguments->server->api->take_calls(arguments);
}

void ucall_server_event_loop_statistics(ucall_server_event_loop_statistics_t* arguments) {
    if (!arguments) return;
    if (arguments->statistics) *arguments->statistics = {};
    if (!admit(arguments->server, arguments->outcome)) return;
    arguments->server->api->event_loop_statistics(arguments);
}

void ucall_server_take_batch(ucall_server_take_batch_t* arguments) {
    if (!arguments) return;
    if (!admit(arguments->server, arguments->outcome)) return;
    arguments->server->api->take_batch(arguments);
}

void ucall_server_take_batches(ucall_server_take_batches_t* arguments) {
    if (!arguments) return;
    if (!admit(arguments->server, arguments->outcome)) return;
    arguments->server->api->take_batches(arguments);
}

void ucall_client_take_completed(ucall_client_take_completed_t* arguments) {
    if (!arguments) return;
    if (arguments->count) *arguments->count = 0;
    if (!admit(arguments->client, arguments->outcome)) return;
    arguments->client->api->take_completed(arguments);
}

void ucall_server_free(ucall_server_t server) {
    if (!server) return;
    assert(compatible(server));
    server->api->free(server);
}
void ucall_server_stop(ucall_server_t server) {
    if (!server) return;
    std::atomic_ref<std::uint32_t> {server->stopped}.store(1, std::memory_order_release);
    for (auto* wake : server->wakeups) wake->notify();
    if (!server->batch_tail) return;
    std::atomic_ref<std::uint64_t> {*server->batch_tail}.fetch_or(ucall_server_handle_t::batch_signal_k,
                                                                  std::memory_order_release);
    std::atomic_ref<std::uint64_t> {*server->batch_tail}.notify_one();
}
void ucall_client_free(ucall_client_t client) {
    if (!client) return;
    assert(compatible(client));
    client->api->free(client);
}

void ucall_server_add_http_endpoint(ucall_server_add_http_endpoint_t* arguments) {
    if (!arguments) return;
    if (!admit(arguments->server, arguments->outcome)) return;
    arguments->server->api->add_http_endpoint(arguments);
}
void ucall_server_request_path_segment(ucall_server_request_path_segment_t* arguments) {
    if (!arguments) return;
    if (!admit(arguments->server, arguments->outcome)) return;
    arguments->server->api->request_path_segment(arguments);
}
void ucall_server_request_path_parameter(ucall_server_request_path_parameter_t* arguments) {
    if (!arguments) return;
    if (!admit(arguments->server, arguments->outcome)) return;
    arguments->server->api->request_path_parameter(arguments);
}
void ucall_server_request_query_parameter(ucall_server_request_query_parameter_t* arguments) {
    if (!arguments) return;
    if (!admit(arguments->server, arguments->outcome)) return;
    arguments->server->api->request_query_parameter(arguments);
}
void ucall_server_request_header(ucall_server_request_header_t* arguments) {
    if (!arguments) return;
    if (!admit(arguments->server, arguments->outcome)) return;
    arguments->server->api->request_header(arguments);
}
void ucall_server_request_body(ucall_server_request_body_t* arguments) {
    if (!arguments) return;
    if (!admit(arguments->server, arguments->outcome)) return;
    arguments->server->api->request_body(arguments);
}
void ucall_server_reply_content(ucall_server_reply_content_t* arguments) {
    if (!arguments) return;
    if (!admit(arguments->server, arguments->outcome)) return;
    arguments->server->api->reply_content(arguments);
}
void ucall_server_reply_error(ucall_server_reply_error_t* arguments) {
    if (!arguments) return;
    if (!admit(arguments->server, arguments->outcome)) return;
    arguments->server->api->reply_error(arguments);
}
void ucall_client_call(ucall_client_call_t* arguments) {
    if (!arguments) return;
    if (!admit(arguments->client, arguments->outcome)) return;
    arguments->client->api->call(arguments);
}
void ucall_client_response_header(ucall_client_response_header_t* arguments) {
    if (!arguments) return;
    if (!admit(arguments->client, arguments->outcome)) return;
    arguments->client->api->response_header(arguments);
}
void ucall_client_response_body(ucall_client_response_body_t* arguments) {
    if (!arguments) return;
    if (!admit(arguments->client, arguments->outcome)) return;
    arguments->client->api->response_body(arguments);
}

ucall_verb_t ucall_server_request_verb(ucall_server_t server, ucall_received_http_request_t request) {
    return server && compatible(server) ? server->api->request_verb(server, request) : ucall_verb_unknown_k;
}
size_t ucall_server_request_path_segments_count(ucall_server_t server, ucall_received_http_request_t request) {
    return server && compatible(server) ? server->api->request_path_segments_count(server, request) : 0;
}
ucall_http_status_t ucall_client_response_status(ucall_client_t, ucall_received_http_response_t response) {
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

void ucall_server_add_batch_endpoint(ucall_server_add_batch_endpoint_t* arguments) {
    if (!arguments) return;
    if (!admit(arguments->server, arguments->outcome)) return;
    arguments->server->api->add_batch_endpoint(arguments);
}

void ucall_server_add_websocket_endpoint(ucall_server_add_websocket_endpoint_t* arguments) {
    if (!arguments) return;
    publish(arguments->outcome, ucall_status_unsupported_k);
}

void ucall_server_request_body_chunk(ucall_server_request_body_chunk_t* arguments) {
    if (!arguments) return;
    if (arguments->data) *arguments->data = {};
    publish(arguments->outcome, ucall_status_unsupported_k);
}

size_t ucall_server_request_parts_count(ucall_server_t server, ucall_received_http_request_t request) { return 0; }

void ucall_server_request_part(ucall_server_request_part_t* arguments) {
    if (!arguments) return;
    if (arguments->name) *arguments->name = {};
    if (arguments->content_type) *arguments->content_type = {};
    if (arguments->data) *arguments->data = {};
    publish(arguments->outcome, ucall_status_unsupported_k);
}

void ucall_server_reply_vectored(ucall_server_reply_vectored_t* arguments) {
    if (!arguments) return;
    publish(arguments->outcome, ucall_status_unsupported_k);
}

void ucall_server_reply_begin(ucall_server_reply_begin_t* arguments) {
    if (!arguments) return;
    publish(arguments->outcome, ucall_status_unsupported_k);
}

void ucall_server_reply_chunk(ucall_server_reply_chunk_t* arguments) {
    if (!arguments) return;
    publish(arguments->outcome, ucall_status_unsupported_k);
}

void ucall_server_reply_end(ucall_server_reply_end_t* arguments) {
    if (!arguments) return;
    publish(arguments->outcome, ucall_status_unsupported_k);
}

void ucall_server_reply_file(ucall_server_reply_file_t* arguments) {
    if (!arguments) return;
    if (arguments->file_descriptor >= 0) {
#if UCALL_OS_WINDOWS_
        _close(arguments->file_descriptor);
#else
        close(arguments->file_descriptor);
#endif
    }
    publish(arguments->outcome, ucall_status_unsupported_k);
}

void ucall_server_reply_path(ucall_server_reply_path_t* arguments) {
    if (!arguments) return;
    publish(arguments->outcome, ucall_status_unsupported_k);
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
