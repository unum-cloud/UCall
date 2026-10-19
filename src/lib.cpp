/**
 *  @file src/lib.cpp
 *  @author Ash Vardanian
 *  @date August 15, 2023
 *  @brief C entry points over each handle's initialization-selected operations.
 */
#include <cstdint>

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

#include "ucall/http.hpp"
#include "lib.hpp"

using namespace unum::ucall;

namespace unum::ucall {

template <typename init_type_>
static void init_network(init_type_* arguments) noexcept {
    auto config = *arguments->config;
    auto request = *arguments;
    request.config = &config;
    auto strings = sz_capabilities_detected_cpu_();
    auto atomics = fu::cpu_capabilities();
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
    if (!arguments->server) {
        publish(arguments->outcome, ucall_status_uninitialized_k);
        return;
    }
    arguments->server->api->take_call(arguments);
}

void ucall_server_take_calls(ucall_server_take_calls_t* arguments) {
    if (!arguments) return;
    if (!arguments->server) {
        publish(arguments->outcome, ucall_status_uninitialized_k);
        return;
    }
    arguments->server->api->take_calls(arguments);
}

void ucall_client_take_completed(ucall_client_take_completed_t* arguments) {
    if (!arguments) return;
    if (arguments->count) *arguments->count = 0;
    if (!arguments->client) {
        publish(arguments->outcome, ucall_status_uninitialized_k);
        return;
    }
    arguments->client->api->take_completed(arguments);
}

void ucall_server_free(ucall_server_t server) {
    if (server) server->api->free(server);
}
void ucall_server_stop(ucall_server_t server) {
    if (server) server->api->stop(server);
}
void ucall_client_free(ucall_client_t client) {
    if (client) client->api->free(client);
}

void ucall_server_add_http_endpoint(ucall_server_add_http_endpoint_t* arguments) {
    if (!arguments) return;
    if (!arguments->server) {
        publish(arguments->outcome, ucall_status_uninitialized_k);
        return;
    }
    arguments->server->api->add_http_endpoint(arguments);
}
void ucall_server_request_path_segment(ucall_server_request_path_segment_t* arguments) {
    if (!arguments) return;
    if (!arguments->server) {
        publish(arguments->outcome, ucall_status_uninitialized_k);
        return;
    }
    arguments->server->api->request_path_segment(arguments);
}
void ucall_server_request_path_parameter(ucall_server_request_path_parameter_t* arguments) {
    if (!arguments) return;
    if (!arguments->server) {
        publish(arguments->outcome, ucall_status_uninitialized_k);
        return;
    }
    arguments->server->api->request_path_parameter(arguments);
}
void ucall_server_request_query_parameter(ucall_server_request_query_parameter_t* arguments) {
    if (!arguments) return;
    if (!arguments->server) {
        publish(arguments->outcome, ucall_status_uninitialized_k);
        return;
    }
    arguments->server->api->request_query_parameter(arguments);
}
void ucall_server_request_header(ucall_server_request_header_t* arguments) {
    if (!arguments) return;
    if (!arguments->server) {
        publish(arguments->outcome, ucall_status_uninitialized_k);
        return;
    }
    arguments->server->api->request_header(arguments);
}
void ucall_server_request_body(ucall_server_request_body_t* arguments) {
    if (!arguments) return;
    if (!arguments->server) {
        publish(arguments->outcome, ucall_status_uninitialized_k);
        return;
    }
    arguments->server->api->request_body(arguments);
}
void ucall_server_reply_content(ucall_server_reply_content_t* arguments) {
    if (!arguments) return;
    if (!arguments->server) {
        publish(arguments->outcome, ucall_status_uninitialized_k);
        return;
    }
    arguments->server->api->reply_content(arguments);
}
void ucall_server_reply_error(ucall_server_reply_error_t* arguments) {
    if (!arguments) return;
    if (!arguments->server) {
        publish(arguments->outcome, ucall_status_uninitialized_k);
        return;
    }
    arguments->server->api->reply_error(arguments);
}
void ucall_client_call(ucall_client_call_t* arguments) {
    if (!arguments) return;
    if (!arguments->client) {
        publish(arguments->outcome, ucall_status_uninitialized_k);
        return;
    }
    arguments->client->api->call(arguments);
}
void ucall_received_http_response_header(ucall_received_http_response_header_t* arguments) {
    if (!arguments) return;
    if (!arguments->client) {
        publish(arguments->outcome, ucall_status_uninitialized_k);
        return;
    }
    arguments->client->api->response_header(arguments);
}
void ucall_received_http_response_body(ucall_received_http_response_body_t* arguments) {
    if (!arguments) return;
    if (!arguments->client) {
        publish(arguments->outcome, ucall_status_uninitialized_k);
        return;
    }
    arguments->client->api->response_body(arguments);
}

ucall_verb_t ucall_server_request_verb(ucall_server_t server, ucall_received_http_request_t request) {
    return server ? server->api->request_verb(server, request) : ucall_verb_unknown_k;
}
size_t ucall_server_request_path_segments_count(ucall_server_t server, ucall_received_http_request_t request) {
    return server ? server->api->request_path_segments_count(server, request) : 0;
}
ucall_http_status_t ucall_received_http_response_status(ucall_client_t, ucall_received_http_response_t response) {
    return response ? static_cast<received_response_t*>(response)->status : 0;
}
void ucall_received_http_response_free(ucall_received_http_response_t response) {
    delete static_cast<received_response_t*>(response);
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

void ucall_client_websocket_close(ucall_client_t client, ucall_websocket_t websocket) {}

void ucall_server_add_batch_endpoint(ucall_server_add_batch_endpoint_t* arguments) {
    if (!arguments) return;
    if (!arguments->server) {
        publish(arguments->outcome, ucall_status_uninitialized_k);
        return;
    }
    arguments->server->api->add_batch_endpoint(arguments);
}

void ucall_server_add_websocket_endpoint(ucall_server_add_websocket_endpoint_t* arguments) {
    if (!arguments) return;
    publish(arguments->outcome, ucall_status_unsupported_k);
}

void ucall_server_request_body_chunk(ucall_server_request_body_chunk_t* arguments) {
    if (!arguments) return;
    if (arguments->chunk) *arguments->chunk = {};
    if (arguments->has_more) *arguments->has_more = {};
    publish(arguments->outcome, ucall_status_unsupported_k);
}

size_t ucall_server_request_part_count(ucall_server_t server, ucall_received_http_request_t request) { return 0; }

void ucall_server_request_part_at(ucall_server_request_part_at_t* arguments) {
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

void ucall_server_websocket_close(ucall_server_t server, ucall_websocket_t websocket) {}

} // extern "C"
