/**
 *  @file src_stub/client.cpp
 *  @author Ash Vardanian
 *  @date November 16, 2026
 *  @brief The stand-in's client: a configuration check, calls refused once valid, and no responses.
 *
 *  A call passes every check the engine makes before it would dial, then answers
 *  @c ucall_status_unsupported_k, so nothing is admitted and no completion or response ever exists.
 */
#include "lib.hpp"

namespace util = unum::ucall::utilities;

using namespace unum::ucall;
using namespace unum::ucall::stub;

using util::allocate_unique;
using util::allocator_delete;
using util::text_view;

/** Whether @p url names a scheme and an authority the engine would parse; @p known reports whether
 *  the scheme is one it speaks. */
static bool url_valid(std::string_view url, bool& known) noexcept {
    std::size_t const scheme = http_t::find(url, "://");
    if (scheme == std::string_view::npos) return false;
    std::string_view const protocol = url.substr(0, scheme);
    known = protocol == "http" || protocol == "http+noise";
    std::string_view const rest = url.substr(scheme + 3);
    std::size_t const boundary = fu::min_of(http_t::find(rest, '/'),
                                            fu::min_of(http_t::find(rest, '?'), http_t::find(rest, '#')));
    std::string_view const authority = rest.substr(0, boundary);
    if (authority.empty() || http_t::find(authority, '@') != std::string_view::npos || !http_t::http_value(authority) ||
        http_t::find(authority, ' ') != std::string_view::npos ||
        http_t::find(authority, '\t') != std::string_view::npos ||
        http_t::find(authority, '\0') != std::string_view::npos)
        return false;
    std::string_view host = authority, port = "80";
    if (host.front() == '[') {
        std::size_t const end = http_t::find(host, ']');
        if (end == std::string_view::npos) return false;
        if (end + 1 < host.size()) {
            if (host[end + 1] != ':') return false;
            port = host.substr(end + 2);
        }
        host = host.substr(1, end - 1);
    }
    else if (std::size_t const colon = http_t::find(host, ':'); colon != std::string_view::npos) {
        port = host.substr(colon + 1);
        host = host.substr(0, colon);
    }
    unsigned number = 0;
    auto const parsed = std::from_chars(port.data(), port.data() + port.size(), number);
    return parsed.ec == std::errc {} && parsed.ptr == port.data() + port.size() && number &&
           number <= (std::numeric_limits<std::uint16_t>::max)() && !host.empty();
}

extern "C" {

void ucall_client_init(ucall_client_init_t* arguments) {
    if (!arguments) return;
    if (arguments->client) *arguments->client = nullptr;
    ucall_client_options_t const* options = arguments->options;
    if (!arguments->client || !arguments->outcome || !options || !options->max_concurrent_connections ||
        unrecognized(ucall_cpu_class_name(options->cpu_class_ceiling))) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    std::size_t const pipelined = fu::max_of<std::size_t>(options->max_pipelined_calls, 1);
    std::size_t const connections = options->max_concurrent_connections;
    if (!options->max_concurrent_calls && connections > (std::numeric_limits<std::size_t>::max)() / pipelined) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    // A bound client runs on its loop's backend, so one naming another is refused; every
    // ceiling picks serial, as its server does.
    ucall_server_t const server = options->server;
    if (server && (options->event_loop >= server->event_loops ||
                   (options->backend != ucall_io_backend_automatic_k && options->backend != server->config.backend))) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    if (!backend_offered(options->backend)) {
        publish(arguments->outcome, ucall_status_unsupported_k);
        return;
    }
    std::size_t const calls = options->max_concurrent_calls ? options->max_concurrent_calls : connections * pipelined;
    std::size_t const counted_limit = (std::numeric_limits<std::uint32_t>::max)() / 4;
    if (pipelined > (std::numeric_limits<std::uint32_t>::max)() || connections > counted_limit ||
        calls > counted_limit) {
        publish(arguments->outcome, ucall_status_overflow_k);
        return;
    }
    auto client = allocate_unique<ucall_client_handle_t>(allocator_t {});
    if (!client) {
        publish(arguments->outcome, ucall_status_out_of_memory_k);
        return;
    }
    auto& config = client->config;
    config = *options;
    if (!config.connect_timeout_microseconds) config.connect_timeout_microseconds = 5'000'000;
    if (!config.call_timeout_microseconds) config.call_timeout_microseconds = 30'000'000;
    config.max_pipelined_calls = pipelined;
    config.max_concurrent_calls = calls;
    config.cpu_class_ceiling = ucall_cpu_class_serial_k;
    if (server) config.backend = server->config.backend;
    else config.event_loop = 0;
    if (config.noise_private_key) {
        std::memcpy(client->private_key, *config.noise_private_key, sizeof(ucall_noise_key_t));
        config.noise_private_key = &client->private_key;
    }
    if (server) atomic_ref<std::size_t> {server->bound_clients}.fetch_add(1, std::memory_order_acq_rel);
    if (arguments->resolved) *arguments->resolved = config;
    *arguments->client = client.release();
    publish(arguments->outcome, ucall_status_success_k);
}

void ucall_client_free(ucall_client_t client) {
    if (!client) return;
    if (ucall_server_t const server = client->config.server)
        atomic_ref<std::size_t> {server->bound_clients}.fetch_sub(1, std::memory_order_acq_rel);
    allocator_delete<ucall_client_handle_t, allocator_t> {client->allocator}(client);
}

void ucall_client_call(ucall_client_call_t* arguments) {
    if (!arguments || !admit(arguments->client, arguments->outcome)) return;
    ucall_client_handle_t const& client = *arguments->client;
    ucall_client_call_options_t const& options = arguments->options;
    if (!http_t::valid_view(arguments->url) || !http_t::valid_view(arguments->body) ||
        !http_t::http_verb_name(arguments->verb) || !security_valid(options.security) ||
        (arguments->headers_count && !arguments->headers)) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    std::string_view const url = text_view(arguments->url);
    ucall_security_t security = options.security;
    if (url.starts_with("http+noise://") && security == ucall_security_none_k) security = ucall_security_noise_xx_k;
    bool known = false;
    if ((options.body_delivery != ucall_body_delivery_buffered_k &&
         options.body_delivery != ucall_body_delivery_streamed_k) ||
        (security != ucall_security_none_k && !options.noise_private_key && !client.config.noise_private_key) ||
        (security == ucall_security_noise_xx_k && !client.config.peer_authorizer) ||
        ((security == ucall_security_noise_ik_k || security == ucall_security_noise_kk_k) && !options.noise_peer_key) ||
        !url_valid(url, known)) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    // Nothing is ever admitted, so the admission budget never runs out and no call is contended.
    if (!known) publish(arguments->outcome, ucall_status_unsupported_k);
    else publish(arguments->outcome, ucall_status_unsupported_k, no_network_k);
}

void ucall_client_take_completed(ucall_client_take_completed_t* arguments) {
    if (!arguments) return;
    if (arguments->count) *arguments->count = 0;
    if (!admit(arguments->client, arguments->outcome)) return;
    if (!arguments->count || (arguments->capacity && !arguments->calls))
        publish(arguments->outcome, ucall_status_invalid_argument_k);
    else publish(arguments->outcome, ucall_status_success_k);
}

void ucall_client_take_completed_call(ucall_client_take_completed_call_t* arguments) {
    if (!arguments) return;
    if (arguments->call) *arguments->call = {};
    if (!admit(arguments->client, arguments->outcome)) return;
    // No call is ever admitted, so none runs or waits under any context.
    if (!arguments->call) publish(arguments->outcome, ucall_status_invalid_argument_k);
    else publish(arguments->outcome, ucall_status_not_found_k);
}

/*  No call is admitted, so no response exists: past their documented checks, the accessors below
 *  refuse any response handle with @c ucall_status_invalid_argument_k. */

ucall_http_status_t ucall_client_response_status(ucall_received_http_response_t) { return 0; }

void ucall_client_response_header(ucall_client_response_header_t* arguments) {
    if (!arguments) return;
    if (arguments->value) *arguments->value = {};
    bool const valid = arguments->value && http_t::valid_view(arguments->name) &&
                       http_t::http_token(text_view(arguments->name));
    refuse_exchange(valid ? arguments->response : nullptr, arguments->outcome);
}

size_t ucall_client_response_fields_count(ucall_received_http_response_t) { return 0; }

void ucall_client_response_field(ucall_client_response_field_t* arguments) {
    if (!arguments) return;
    if (arguments->name) *arguments->name = {};
    if (arguments->value) *arguments->value = {};
    refuse_exchange(arguments->name && arguments->value ? arguments->response : nullptr, arguments->outcome);
}

void ucall_client_response_body(ucall_client_response_body_t* arguments) {
    if (!arguments) return;
    if (arguments->body) *arguments->body = {};
    refuse_exchange(arguments->body ? arguments->response : nullptr, arguments->outcome);
}

void ucall_client_response_body_chunk(ucall_client_response_body_chunk_t* arguments) {
    if (!arguments) return;
    if (arguments->data) *arguments->data = {};
    if (!admit(arguments->client, arguments->outcome)) return;
    refuse_exchange(arguments->data ? arguments->response : nullptr, arguments->outcome);
}

void ucall_client_response_free(ucall_received_http_response_t) {}

} // extern "C"
