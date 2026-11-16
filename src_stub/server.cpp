/**
 *  @file src_stub/server.cpp
 *  @author Ash Vardanian
 *  @date November 16, 2026
 *  @brief The stand-in's server: a whole-configuration check, real routes, and no network.
 *
 *  Initialization refuses what the engine refuses before it binds a socket, in the ruled order:
 *  invalid arguments, then what this build cannot run, then counters that overflow, then reply
 *  directories missing from the file system. It then returns a socketless handle whose resolved
 *  configuration the caller may read. Endpoints register into the route trie the engine uses, so
 *  the template refusals are the engine's. Polling answers @c ucall_status_unsupported_k, so no
 *  request ever exists, and every request accessor and reply verb refuses its handle.
 */
#include <cerrno> // `ENOENT`, `ENOTDIR`

#include <sys/stat.h> // `stat`, `S_IFDIR`

#include "lib.hpp"

using namespace unum::ucall;
using namespace unum::ucall::stub;

using utilities::allocate_unique;
using utilities::allocator_delete;

/** Whether @p text may stand in a metric name or tag: no separator StatsD lines use. */
static bool metrics_text_valid(std::string_view text, std::string_view banned) noexcept {
    for (char separator : banned)
        if (http_t::find(text, separator) != std::string_view::npos) return false;
    return !text.empty();
}

/** The loops one interface resolves to, zero for a device this machine lacks. */
static std::size_t interface_event_loops(ucall_network_interface_t const& network_interface) noexcept {
    std::size_t const loops = network_interface.event_loops ? network_interface.event_loops
                              : network_interface.device_name.length
                                  ? utilities::receive_queues_count(text_view(network_interface.device_name))
                                  : 1;
    return fu::min_of(loops, network_interface.max_concurrent_connections);
}

/** Whether @p descriptor is a listening stream socket, as the engine vets a borrowed listener. */
static bool listener_valid(std::intptr_t descriptor) noexcept {
    descriptor_t const duplicate = utilities::socket_duplicate_listener(descriptor);
    if (duplicate < 0) return false;
    utilities::socket_close(duplicate);
    return true;
}

/** The metrics settings, as the engine checks them before resolving the StatsD address. */
static bool metrics_valid(ucall_server_options_t const& options) noexcept {
    float const rate = options.metrics_sample_rate;
    if (!(rate >= 0.f && rate <= 1.f) || !http_t::valid_view(options.metrics_address) ||
        !http_t::valid_view(options.metrics_prefix) || (options.metrics_tags_count && !options.metrics_tags))
        return false;
    std::string_view const prefix = options.metrics_prefix.length ? text_view(options.metrics_prefix) : "ucall";
    if (!metrics_text_valid(prefix, ":|#,@\r\n")) return false;
    for (std::size_t i = 0; i != options.metrics_tags_count; ++i)
        if (!http_t::valid_view(options.metrics_tags[i]) ||
            !metrics_text_valid(text_view(options.metrics_tags[i]), "|#,@\r\n"))
            return false;
    return !options.metrics_address.length || address_valid(text_view(options.metrics_address));
}

/** One interface's own arguments, apart from the CPU class and the backend its server names. */
static bool interface_valid(ucall_network_interface_t const& network_interface) noexcept {
    auto const& settings = network_interface;
    if (!http_t::valid_view(settings.address) || !http_t::valid_view(settings.device_name) ||
        http_t::find(text_view(settings.device_name), '\0') != std::string_view::npos)
        return false;
    if ((!settings.address.length && !settings.listen_descriptor) || !security_valid(settings.security) ||
        (settings.security != ucall_security_none_k && !settings.noise_private_key) ||
        (settings.security == ucall_security_noise_xx_k && !settings.peer_authorizer) ||
        (settings.security == ucall_security_noise_kk_k && !settings.noise_peer_key))
        return false;
    if (!settings.max_concurrent_connections) return false;
    if (settings.reply_directories_count && !settings.reply_directories) return false;
    for (std::size_t i = 0; i != settings.reply_directories_count; ++i) {
        ucall_bytes_view_t const directory = settings.reply_directories[i];
        if (!directory.data || !directory.length || http_t::find(text_view(directory), '\0') != std::string_view::npos)
            return false;
    }
    // A device named outside Linux is unsupported rather than missing, which a later check says.
    if (UCALL_OS_LINUX_ && !interface_event_loops(settings)) return false;
    if (settings.listen_descriptor) return listener_valid(*settings.listen_descriptor);
    return address_valid(text_view(settings.address));
}

/** What this build cannot serve: a device outside Linux, several loops on Windows, or a borrowed
 *  listener under Registered I/O. */
static bool interface_supported(ucall_network_interface_t const& network_interface,
                                ucall_io_backend_t backend) noexcept {
    if (!UCALL_OS_LINUX_ && network_interface.device_name.length) return false;
    if (UCALL_OS_WINDOWS_ && interface_event_loops(network_interface) > 1) return false;
    return !(network_interface.listen_descriptor && backend == ucall_io_backend_windows_rio_k);
}

/** Sums the interfaces' request budgets, and the busiest loop's connections and exchanges, against
 *  the counters the engine sizes them in. */
static bool budgets_fit(ucall_server_options_t const& options) noexcept {
    constexpr std::size_t size_max_k = (std::numeric_limits<std::size_t>::max)();
    constexpr std::size_t counted_limit_k = (std::numeric_limits<std::uint32_t>::max)() / 8;
    std::size_t requests = 0, connections = 0, exchanges = 0, acceptors = 0;
    for (std::size_t i = 0; i != options.interfaces_count; ++i) {
        auto const& network_interface = options.interfaces[i];
        std::size_t const pipelined = fu::max_of<std::size_t>(network_interface.max_pipelined_requests, 1);
        std::size_t const budget = network_interface.max_concurrent_connections;
        if (pipelined > (std::numeric_limits<std::uint32_t>::max)() || budget > size_max_k / pipelined ||
            budget * pipelined > size_max_k - requests)
            return false;
        requests += budget * pipelined;
        // Loop zero takes the rounded-up share, so it is the busiest.
        std::size_t const loops = interface_event_loops(network_interface);
        std::size_t const quota = budget / loops + (budget % loops != 0);
        connections += quota, exchanges += quota * pipelined, ++acceptors;
    }
    return connections <= counted_limit_k && acceptors <= counted_limit_k && exchanges <= counted_limit_k;
}

/** Bytes of text the resolved configuration copies, each reply directory with its NUL. */
static std::size_t copied_text_bytes(ucall_server_options_t const& options) noexcept {
    std::size_t bytes = options.metrics_prefix.length ? options.metrics_prefix.length : 5;
    for (std::size_t i = 0; i != options.metrics_tags_count; ++i) bytes += options.metrics_tags[i].length;
    for (std::size_t i = 0; i != options.interfaces_count; ++i) {
        auto const& network_interface = options.interfaces[i];
        bytes += network_interface.address.length + network_interface.device_name.length;
        for (std::size_t j = 0; j != network_interface.reply_directories_count; ++j)
            bytes += network_interface.reply_directories[j].length + 1;
    }
    return bytes;
}

/** Appends @p text to @p server's copied text, sized beforehand, and views the copy. */
static ucall_bytes_view_t keep_text(ucall_server_handle_t& server, std::size_t& offset, std::string_view text,
                                    bool terminated = false) noexcept {
    if (!text.empty()) std::memcpy(server.text.data() + offset, text.data(), text.size());
    ucall_bytes_view_t const kept {reinterpret_cast<ucall_byte_t const*>(server.text.data() + offset), text.size()};
    offset += text.size();
    if (terminated) server.text[offset++] = '\0';
    return text.empty() ? ucall_bytes_view_t {} : kept;
}

/** Whether the NUL-terminated @p name is a directory: a missing path, or one that is not a
 *  directory, is not found, and any other failure is an I/O one, as opening it would answer. */
static ucall_status_t directory_status(char const* name) noexcept {
    struct stat information {};
    if (::stat(name, &information) != 0)
        return errno == ENOENT || errno == ENOTDIR ? ucall_status_not_found_k : ucall_status_io_k;
    return (information.st_mode & S_IFMT) == S_IFDIR ? ucall_status_success_k : ucall_status_not_found_k;
}

/** Copies @p options into @p server with every default the stand-in can fill: the serial class, the
 *  backend as requested, since it opens none, and each interface's loops and pipelining. */
static ucall_status_t resolve(ucall_server_handle_t& server, ucall_server_options_t const& options) noexcept {
    std::size_t views = options.metrics_tags_count;
    for (std::size_t i = 0; i != options.interfaces_count; ++i) views += options.interfaces[i].reply_directories_count;
    if (st::failed(server.interfaces.resize(options.interfaces_count)) ||
        st::failed(server.keys.resize(options.interfaces_count)) || st::failed(server.views.resize(views)) ||
        st::failed(server.text.resize(copied_text_bytes(options))))
        return ucall_status_out_of_memory_k;
    if (ucall_status_t const routed = server.routes.init(); routed != ucall_status_success_k) return routed;
    std::size_t offset = 0, view = 0;
    for (std::size_t i = 0; i != options.interfaces_count; ++i) {
        auto& network_interface = server.interfaces[i];
        network_interface = options.interfaces[i];
        network_interface.address = keep_text(server, offset, text_view(network_interface.address));
        network_interface.device_name = keep_text(server, offset, text_view(network_interface.device_name));
        network_interface.event_loops = interface_event_loops(options.interfaces[i]);
        // The engine reports a borrowed listener only through the call's own copy of the options.
        network_interface.listen_descriptor = nullptr;
        network_interface.max_pipelined_requests = fu::max_of<std::size_t>(network_interface.max_pipelined_requests, 1);
        if (network_interface.noise_private_key) {
            std::memcpy(server.keys[i].private_key, *network_interface.noise_private_key, sizeof(ucall_noise_key_t));
            network_interface.noise_private_key = &server.keys[i].private_key;
        }
        if (network_interface.noise_peer_key) {
            std::memcpy(server.keys[i].peer_key, *network_interface.noise_peer_key, sizeof(ucall_noise_key_t));
            network_interface.noise_peer_key = &server.keys[i].peer_key;
        }
        ucall_bytes_view_t* directories = network_interface.reply_directories_count ? &server.views[view] : nullptr;
        for (std::size_t j = 0; j != network_interface.reply_directories_count; ++j) {
            server.views[view++] = keep_text(server, offset, text_view(network_interface.reply_directories[j]), true);
            if (ucall_status_t const found = directory_status(
                    reinterpret_cast<char const*>(server.views[view - 1].data));
                found != ucall_status_success_k)
                return found;
        }
        network_interface.reply_directories = directories;
        server.event_loops = fu::max_of(server.event_loops, network_interface.event_loops);
    }
    server.config = options;
    server.config.interfaces = server.interfaces.data();
    server.config.metrics_prefix = keep_text(
        server, offset, options.metrics_prefix.length ? text_view(options.metrics_prefix) : "ucall");
    server.config.metrics_tags = options.metrics_tags_count ? &server.views[view] : nullptr;
    for (std::size_t i = 0; i != options.metrics_tags_count; ++i)
        server.views[view++] = keep_text(server, offset, text_view(options.metrics_tags[i]));
    if (!server.config.metrics_sample_rate) server.config.metrics_sample_rate = 1.f;
    if (!server.config.metrics_interval_microseconds) server.config.metrics_interval_microseconds = 1'000'000;
    server.config.cpu_class_ceiling = ucall_cpu_class_serial_k;
    return ucall_status_success_k;
}

/** Registers a plain or batch endpoint, after the checks both share, into the engine's trie. */
template <typename arguments_type_>
static void add_endpoint(arguments_type_* arguments, ucall_http_batch_endpoint_t* batch_endpoint) noexcept {
    auto& server = *arguments->server;
    std::string_view const path = text_view(arguments->uri_template);
    if (!arguments->callback || !http_t::valid_view(arguments->uri_template) ||
        (!http_t::http_verb_name(arguments->verb) && arguments->verb != ucall_verb_any_k) || path.empty() ||
        path.front() != '/' || http_t::find(path, '?') != std::string_view::npos ||
        http_t::find(path, '#') != std::string_view::npos) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    // No loop is ever polled, so registration is never contended.
    auto kept = allocate_unique<ucall_stub_template_t>(server.allocator);
    if (!kept || st::failed(kept->text.resize(path.size()))) {
        publish(arguments->outcome, ucall_status_out_of_memory_k);
        return;
    }
    std::memcpy(kept->text.data(), path.data(), path.size());
    decltype(allocate_unique<ucall_http_batch_endpoint_handle_t>(server.allocator)) batch;
    if (batch_endpoint && !(batch = allocate_unique<ucall_http_batch_endpoint_handle_t>(server.allocator))) {
        publish(arguments->outcome, ucall_status_out_of_memory_k);
        return;
    }
    // The trie may borrow segments of a template it then refuses, so the copy stays either way.
    ucall_stub_template_t* const copy = kept.release();
    copy->next = std::exchange(server.templates, copy);
    ucall_status_t const inserted = server.routes.insert(http::text_view(copy->text), arguments->verb, copy);
    if (inserted != ucall_status_success_k) {
        publish(arguments->outcome, inserted);
        return;
    }
    if (batch) {
        batch->server = &server;
        batch->next = server.batch_endpoints;
        server.batch_endpoints = batch.get();
        *batch_endpoint = batch.release();
    }
    publish(arguments->outcome, ucall_status_success_k);
}

extern "C" {

void ucall_server_init(ucall_server_init_t* arguments) {
    if (!arguments) return;
    if (arguments->server) *arguments->server = nullptr;
    ucall_server_options_t const* options = arguments->options;
    if (!arguments->server || !arguments->outcome || !options || !options->interfaces || !options->interfaces_count ||
        !metrics_valid(*options) || unrecognized(ucall_cpu_class_name(options->cpu_class_ceiling))) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    for (std::size_t i = 0; i != options->interfaces_count; ++i)
        if (!interface_valid(options->interfaces[i])) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
    if (!backend_offered(options->backend)) {
        publish(arguments->outcome, ucall_status_unsupported_k);
        return;
    }
    for (std::size_t i = 0; i != options->interfaces_count; ++i)
        if (!interface_supported(options->interfaces[i], options->backend)) {
            publish(arguments->outcome, ucall_status_unsupported_k);
            return;
        }
    if (!budgets_fit(*options)) {
        publish(arguments->outcome, ucall_status_overflow_k);
        return;
    }
    auto server = allocate_unique<ucall_server_handle_t>(allocator_t {});
    if (!server) {
        publish(arguments->outcome, ucall_status_out_of_memory_k);
        return;
    }
    if (ucall_status_t const resolved = resolve(*server, *options); resolved != ucall_status_success_k) {
        publish(arguments->outcome, resolved);
        return;
    }
    if (arguments->resolved) *arguments->resolved = server->config;
    // The caller's own views end with this call, so the kept configuration lets go of them.
    server->config.metrics_address = {};
    *arguments->server = server.release();
    publish(arguments->outcome, ucall_status_success_k);
}

void ucall_server_free(ucall_server_t server) {
    if (!server) return;
    // A bound client keeps its server, as the engine shares a loop's engine with it.
    if (atomic_ref<std::size_t> {server->bound_clients}.load(std::memory_order_acquire)) return;
    allocator_delete<ucall_server_handle_t, allocator_t> {server->allocator}(server);
}

/** No loop runs and none waits, so a stop has nothing to drain or wake. */
void ucall_server_stop(ucall_server_t) {}

void ucall_server_take_call(ucall_server_take_call_t* arguments) {
    if (!arguments || !admit(arguments->server, arguments->outcome)) return;
    if (arguments->event_loop_index >= arguments->server->event_loops)
        publish(arguments->outcome, ucall_status_invalid_argument_k);
    else publish(arguments->outcome, ucall_status_unsupported_k, no_network_k);
}

void ucall_server_take_calls(ucall_server_take_calls_t* arguments) {
    if (!arguments || !admit(arguments->server, arguments->outcome)) return;
    if (arguments->event_loop_index >= arguments->server->event_loops)
        publish(arguments->outcome, ucall_status_invalid_argument_k);
    else publish(arguments->outcome, ucall_status_unsupported_k, no_network_k);
}

void ucall_server_event_loop_statistics(ucall_server_event_loop_statistics_t* arguments) {
    if (!arguments) return;
    if (arguments->statistics) *arguments->statistics = {};
    if (!admit(arguments->server, arguments->outcome)) return;
    if (!arguments->statistics || arguments->event_loop_index >= arguments->server->event_loops)
        publish(arguments->outcome, ucall_status_invalid_argument_k);
    else publish(arguments->outcome, ucall_status_success_k);
}

void ucall_server_take_batch(ucall_server_take_batch_t* arguments) {
    if (!arguments || !admit(arguments->server, arguments->outcome)) return;
    if (!arguments->endpoint) publish(arguments->outcome, ucall_status_invalid_argument_k);
    else publish(arguments->outcome, ucall_status_unsupported_k, no_network_k);
}

void ucall_server_take_batches(ucall_server_take_batches_t* arguments) {
    if (!arguments || !admit(arguments->server, arguments->outcome)) return;
    if (!arguments->endpoint) publish(arguments->outcome, ucall_status_invalid_argument_k);
    else publish(arguments->outcome, ucall_status_unsupported_k, no_network_k);
}

void ucall_server_batch_endpoint_statistics(ucall_server_batch_endpoint_statistics_t* arguments) {
    if (!arguments) return;
    if (arguments->statistics) *arguments->statistics = {};
    if (!admit(arguments->server, arguments->outcome)) return;
    if (!arguments->endpoint || !arguments->statistics) publish(arguments->outcome, ucall_status_invalid_argument_k);
    else publish(arguments->outcome, ucall_status_success_k);
}

void ucall_server_add_http_endpoint(ucall_server_add_http_endpoint_t* arguments) {
    if (!arguments || !admit(arguments->server, arguments->outcome)) return;
    add_endpoint(arguments, nullptr);
}

void ucall_server_add_http_batch_endpoint(ucall_server_add_http_batch_endpoint_t* arguments) {
    if (!arguments || !admit(arguments->server, arguments->outcome)) return;
    std::size_t const minimum = arguments->min_batch_size ? arguments->min_batch_size : 1;
    std::size_t const maximum = arguments->max_batch_size ? arguments->max_batch_size : 32;
    if (!arguments->endpoint || minimum > maximum) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    add_endpoint(arguments, arguments->endpoint);
}

/*  No loop is polled, so no request exists: past their documented checks, the accessors and reply
 *  verbs below refuse any request handle with @c ucall_status_invalid_argument_k. */

ucall_verb_t ucall_server_request_verb(ucall_server_t, ucall_received_http_request_t) { return ucall_verb_unknown_k; }

size_t ucall_server_request_path_segments_count(ucall_server_t, ucall_received_http_request_t) { return 0; }

size_t ucall_server_request_parts_count(ucall_server_t, ucall_received_http_request_t) { return 0; }

void ucall_server_request_path(ucall_server_request_path_t* arguments) {
    if (!arguments) return;
    if (arguments->path) *arguments->path = {};
    if (!admit(arguments->server, arguments->outcome)) return;
    refuse_exchange(arguments->path ? arguments->request : nullptr, arguments->outcome);
}

void ucall_server_request_query(ucall_server_request_query_t* arguments) {
    if (!arguments) return;
    if (arguments->query) *arguments->query = {};
    if (!admit(arguments->server, arguments->outcome)) return;
    refuse_exchange(arguments->query ? arguments->request : nullptr, arguments->outcome);
}

void ucall_server_request_path_segment(ucall_server_request_path_segment_t* arguments) {
    if (!arguments) return;
    if (arguments->segment) *arguments->segment = {};
    if (!admit(arguments->server, arguments->outcome)) return;
    refuse_exchange(arguments->segment ? arguments->request : nullptr, arguments->outcome);
}

void ucall_server_request_path_parameter(ucall_server_request_path_parameter_t* arguments) {
    if (!arguments) return;
    if (arguments->value) *arguments->value = {};
    if (!admit(arguments->server, arguments->outcome)) return;
    bool const valid = arguments->value && http_t::valid_view(arguments->name);
    refuse_exchange(valid ? arguments->request : nullptr, arguments->outcome);
}

void ucall_server_request_query_parameter(ucall_server_request_query_parameter_t* arguments) {
    if (!arguments) return;
    if (arguments->value) *arguments->value = {};
    if (!admit(arguments->server, arguments->outcome)) return;
    bool const valid = arguments->value && http_t::valid_view(arguments->name);
    refuse_exchange(valid ? arguments->request : nullptr, arguments->outcome);
}

void ucall_server_request_header(ucall_server_request_header_t* arguments) {
    if (!arguments) return;
    if (arguments->value) *arguments->value = {};
    if (!admit(arguments->server, arguments->outcome)) return;
    bool const valid = arguments->value && http_t::valid_view(arguments->name) &&
                       http_t::http_token(text_view(arguments->name));
    refuse_exchange(valid ? arguments->request : nullptr, arguments->outcome);
}

void ucall_server_request_fields_count(ucall_server_request_fields_count_t* arguments) {
    if (!arguments) return;
    if (arguments->count) *arguments->count = 0;
    if (!admit(arguments->server, arguments->outcome)) return;
    refuse_exchange(arguments->count ? arguments->request : nullptr, arguments->outcome);
}

void ucall_server_request_field(ucall_server_request_field_t* arguments) {
    if (!arguments) return;
    if (arguments->name) *arguments->name = {};
    if (arguments->value) *arguments->value = {};
    if (!admit(arguments->server, arguments->outcome)) return;
    refuse_exchange(arguments->name && arguments->value ? arguments->request : nullptr, arguments->outcome);
}

void ucall_server_request_peer(ucall_server_request_peer_t* arguments) {
    if (!arguments) return;
    if (arguments->network_interface_index) *arguments->network_interface_index = 0;
    if (arguments->static_key) std::memset(*arguments->static_key, 0, sizeof(ucall_noise_key_t));
    if (arguments->address) *arguments->address = {};
    if (!admit(arguments->server, arguments->outcome)) return;
    bool const valid = arguments->network_interface_index && arguments->static_key && arguments->address;
    refuse_exchange(valid ? arguments->request : nullptr, arguments->outcome);
}

void ucall_server_request_body(ucall_server_request_body_t* arguments) {
    if (!arguments) return;
    if (arguments->body) *arguments->body = {};
    if (!admit(arguments->server, arguments->outcome)) return;
    refuse_exchange(arguments->body ? arguments->request : nullptr, arguments->outcome);
}

void ucall_server_request_body_chunk(ucall_server_request_body_chunk_t* arguments) {
    if (!arguments) return;
    if (arguments->data) *arguments->data = {};
    if (!admit(arguments->server, arguments->outcome)) return;
    refuse_exchange(arguments->data ? arguments->request : nullptr, arguments->outcome);
}

void ucall_server_request_part(ucall_server_request_part_t* arguments) {
    if (!arguments) return;
    if (arguments->name) *arguments->name = {};
    if (arguments->content_type) *arguments->content_type = {};
    if (arguments->data) *arguments->data = {};
    if (!admit(arguments->server, arguments->outcome)) return;
    bool const valid = arguments->name && arguments->content_type && arguments->data;
    refuse_exchange(valid ? arguments->request : nullptr, arguments->outcome);
}

void ucall_server_reply_content(ucall_server_reply_content_t* arguments) {
    if (!arguments || !admit(arguments->server, arguments->outcome)) return;
    refuse_exchange(arguments->request, arguments->outcome);
}

void ucall_server_reply_error(ucall_server_reply_error_t* arguments) {
    if (!arguments || !admit(arguments->server, arguments->outcome)) return;
    refuse_exchange(arguments->request, arguments->outcome);
}

void ucall_server_reply_vectored(ucall_server_reply_vectored_t* arguments) {
    if (!arguments || !admit(arguments->server, arguments->outcome)) return;
    refuse_exchange(arguments->request, arguments->outcome);
}

void ucall_server_reply_begin(ucall_server_reply_begin_t* arguments) {
    if (!arguments || !admit(arguments->server, arguments->outcome)) return;
    refuse_exchange(arguments->request, arguments->outcome);
}

void ucall_server_reply_append(ucall_server_reply_append_t* arguments) {
    if (!arguments || !admit(arguments->server, arguments->outcome)) return;
    refuse_exchange(arguments->request, arguments->outcome);
}

void ucall_server_reply_end(ucall_server_reply_end_t* arguments) {
    if (!arguments || !admit(arguments->server, arguments->outcome)) return;
    refuse_exchange(arguments->request, arguments->outcome);
}

} // extern "C"
