/**
 *  @file include/ucall/network/server.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief A server's interfaces, event loops and endpoints, with the entry points over them.
 */
#pragma once

#include <bit> // `std::bit_ceil`, `std::bit_cast`

#include "ucall/http/multipart.hpp" // `split_multipart`, `header_parameter`, `part_header`
#include "ucall/http/routes.hpp" // `count_path_segments`, `extract_path_component`, `parse_segment`, `parsed_segment_t`
#include "ucall/io/types.hpp"    // `io_completion_t`, `io_operation_t`, `io_wait_t`
#include "ucall/network/exchanges.hpp" // `claimed_k`, `replied_k`, `detached_k`
#include "ucall/network/loops.hpp"     // `event_loop_stage_t`, `wake_state_t`, `metrics_state_t`
#include "ucall/network/types.hpp"     // `server_stage_t`, `transport_stage_t`, `body_stage_t`, `parts_state_t`
#include "ucall/tunnel/curve25519.hpp" // `x25519_derive_public`
#include "ucall/utilities/sockets.hpp" // `datagram_open`, `deadline_after`, `directory_open`, `monotonic_ns`
#include "ucall/utilities/types.hpp"   // `text_view`, `allocator_delete`, `current_polling_thread`, `polling_thread_t`

namespace unum::ucall::network {

using http::count_path_segments;
using http::extract_path_component;
using http::parse_segment;
using http::parsed_segment_t;
using http::path_cursor;
using http::route_trie;
using http::segment_type_t;
using io::io_completion_t;
using io::io_operation_t;
using io::io_wait_t;
using io::tally;
using tunnel::x25519_derive_public;
using utilities::allocate_unique;
using utilities::allocator_delete;
using utilities::bytes_view;
using utilities::current_polling_thread;
using utilities::datagram_open;
using utilities::deadline_after;
using utilities::descriptor_t;
using utilities::directory_open;
using utilities::monotonic_ns;
using utilities::polling_thread_t;
using utilities::publish;
using utilities::socket_close;
using utilities::socket_length_t;
using utilities::sockets_start;
using utilities::span;
using utilities::text_view;

template <typename network_type_>
struct server : ucall_server_handle_t {
    using network_t = network_type_;
    using http_t = typename network_t::http_t;
    using crypto_t = typename network_t::crypto_t;
    using waiter_t = typename network_t::waiter_t;
    using allocator_t = typename network_t::allocator_t;
    using engine_t = typename network_t::engine_t;
    using connection_t = typename network_t::server_connection_t;
    using batch_endpoint_t = typename network_t::batch_endpoint_t;
    using endpoint_t = typename network_t::endpoint_t;
    using server_exchange_t = typename network_t::server_exchange_t;
    using network_interface_t = typename network_t::network_interface_t;
    using interface_acceptor_t = typename network_t::interface_acceptor_t;
    using event_loop_t = typename network_t::event_loop_t;
    using server_t = typename network_t::server_t;
    using formatting_t = typename network_t::formatting_t;
    using replies_t = typename network_t::replies_t;
    using metrics_t = typename network_t::metrics_t;
    using serving_t = typename network_t::serving_t;
    using client_t = typename network_t::client_t;
    using client_connection_t = typename network_t::client_connection_t;
    using transport_t = typename network_t::transport_t;
    using resolving_t = typename network_t::resolving_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;
    template <typename value_type_>
    using owner = typename network_t::template owner<value_type_>;
    template <typename value_type_>
    using atomic_ref = typename network_t::template atomic_ref<value_type_>;

    allocator_t allocator;
    explicit server(allocator_t const& allocator = {}) noexcept
        : allocator(allocator), resolved(rebound_allocator<ucall_network_interface_t> {allocator}),
          event_loops(rebound_allocator<owner<event_loop_t>> {allocator}), routes(allocator),
          batch_endpoints(rebound_allocator<batch_endpoint_t*> {allocator}),
          metrics_text(rebound_allocator<char> {allocator}),
          metrics_tag_views(rebound_allocator<ucall_bytes_view_t> {allocator}) {}
    server(server const&) = delete;
    server& operator=(server const&) = delete;
    server(server&&) = delete;
    server& operator=(server&&) = delete;

    ucall_status_t failure {ucall_status_success_k};
    ucall_server_options_t config {};
    span<network_interface_t> network_interfaces {};
    vector<ucall_network_interface_t> resolved {};
    vector<owner<event_loop_t>> event_loops {};
    route_trie<http_t, allocator_t> routes {};
    endpoint_t* endpoints {};

    /** Every batch endpoint, whose polling owner @c server_stop must wake. */
    vector<batch_endpoint_t*> batch_endpoints;
    std::size_t requests_budget {};

    /** Event loops retired for good; once all are, a drained server takes no more deposits. */
    std::uint32_t retired_event_loops {};

    /** Read by registrations, apart from what dispatch reads. */
    alignas(fu::default_alignment_k) std::uint32_t polling_started {};

    /** The metric prefix then every tag, back to back, as the resolved configuration views. */
    vector<char> metrics_text {};
    vector<ucall_bytes_view_t> metrics_tag_views {};
    ucall_bytes_view_t metrics_prefix {};
    sockaddr_storage metrics_destination {};

    /** Zero when metrics are off. */
    socket_length_t metrics_destination_length {};

    /** The path MTU less the IP and UDP headers. */
    std::size_t metrics_datagram_bytes {};
    ~server() noexcept {
        event_loops.clear();
        for (auto& network_interface : network_interfaces) {
            crypto_t::secure_zero(network_interface.private_key);
            std::destroy_at(&network_interface);
        }
        if (!network_interfaces.empty())
            rebound_allocator<network_interface_t> {allocator}.deallocate(network_interfaces.data(),
                                                                          network_interfaces.size());
        while (endpoints) {
            auto* next = endpoints->next;
            allocator_delete<endpoint_t, allocator_t> {allocator}(endpoints);
            endpoints = next;
        }
    }

    /** Opens the interface's reply directories, and points its configuration at copies of their
     *  names, which the resolved configuration reports. */
    static ucall_status_t open_reply_directories(network_interface_t& network_interface) noexcept {
        auto& settings = network_interface.config;
        if (!settings.reply_directories_count) {
            settings.reply_directories = nullptr;
            return ucall_status_success_k;
        }
        if (!settings.reply_directories) return ucall_status_invalid_argument_k;
        auto& names = network_interface.reply_directory_names;
        for (std::size_t i = 0; i != settings.reply_directories_count; ++i) {
            ucall_bytes_view_t const directory = settings.reply_directories[i];
            if (!directory.data || !directory.length ||
                http_t::find(text_view(directory), '\0') != std::string_view::npos)
                return ucall_status_invalid_argument_k;
            if (ucall_status_t const copied = http_t::append_text(names,
                                                                  {text_view(directory), std::string_view {"\0", 1}});
                copied != ucall_status_success_k)
                return copied;
        }
        if (st::failed(network_interface.reply_directory_descriptors.reserve(settings.reply_directories_count)) ||
            st::failed(network_interface.reply_directory_views.resize(settings.reply_directories_count)))
            return ucall_status_out_of_memory_k;
        char const* name = names.data();
        for (std::size_t i = 0; i != settings.reply_directories_count; ++i) {
            descriptor_t const directory = directory_open(name);
            if (directory < 0)
                return directory == -ENOENT || directory == -ENOTDIR ? ucall_status_not_found_k : ucall_status_io_k;
            [[maybe_unused]] st::status_t const kept = network_interface.reply_directory_descriptors.push_back(
                st::assume_reserved, std::bit_cast<native_file_t>(directory));
            std::size_t const length = settings.reply_directories[i].length;
            network_interface.reply_directory_views[i] = {reinterpret_cast<ucall_byte_t const*>(name), length};
            name += length + 1;
        }
        settings.reply_directories = network_interface.reply_directory_views.data();
        return ucall_status_success_k;
    }

    /** Whether @p text may stand in a metric name or tag: no separator StatsD lines use. */
    static bool metrics_text_valid(std::string_view text, std::string_view banned) noexcept {
        for (char separator : banned)
            if (http_t::find(text, separator) != std::string_view::npos) return false;
        return !text.empty();
    }

    /** Copies the metric prefix and tags into @p server, resolves the StatsD address, and measures
     *  the datagram its path carries, on a socket of its own. */
    static ucall_status_t resolve_metrics(server_t& server, ucall_server_options_t const& config) noexcept {
        float const rate = config.metrics_sample_rate;
        if (!(rate >= 0.f && rate <= 1.f) || !http_t::valid_view(config.metrics_address) ||
            !http_t::valid_view(config.metrics_prefix) || (config.metrics_tags_count && !config.metrics_tags))
            return ucall_status_invalid_argument_k;
        std::string_view const prefix = config.metrics_prefix.length ? text_view(config.metrics_prefix) : "ucall";
        if (!metrics_text_valid(prefix, ":|#,@\r\n")) return ucall_status_invalid_argument_k;
        auto& text = server.metrics_text;
        if (ucall_status_t const copied = http_t::append_text(text, {prefix}); copied != ucall_status_success_k)
            return copied;
        for (std::size_t i = 0; i != config.metrics_tags_count; ++i) {
            ucall_bytes_view_t const tag = config.metrics_tags[i];
            if (!http_t::valid_view(tag) || !metrics_text_valid(text_view(tag), "|#,@\r\n"))
                return ucall_status_invalid_argument_k;
            if (ucall_status_t const copied = http_t::append_text(text, {text_view(tag)});
                copied != ucall_status_success_k)
                return copied;
        }
        if (st::failed(server.metrics_tag_views.resize(config.metrics_tags_count))) return ucall_status_out_of_memory_k;
        server.metrics_prefix = bytes_view({text.data(), prefix.size()});
        std::size_t offset = prefix.size();
        for (std::size_t i = 0; i != config.metrics_tags_count; ++i) {
            server.metrics_tag_views[i] = bytes_view({text.data() + offset, config.metrics_tags[i].length});
            offset += config.metrics_tags[i].length;
        }
        if (!config.metrics_address.length) return ucall_status_success_k;
        vector<char> host {rebound_allocator<char> {server.allocator}}, service {host.get_allocator()};
        if (ucall_status_t const started = sockets_start(); started != ucall_status_success_k) return started;
        if (auto status = formatting_t::split_address(text_view(config.metrics_address), host, service);
            status != ucall_status_success_k)
            return status;
        addrinfo hints {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        addrinfo* addresses = nullptr;
        if (getaddrinfo(host.data(), service.data(), &hints, &addresses) != 0 || !addresses)
            return ucall_status_connection_failed_k;
        std::memcpy(&server.metrics_destination, addresses->ai_addr, addresses->ai_addrlen);
        server.metrics_destination_length = static_cast<socket_length_t>(addresses->ai_addrlen);
        freeaddrinfo(addresses);
        descriptor_t const probe = datagram_open(reinterpret_cast<sockaddr const*>(&server.metrics_destination),
                                                 server.metrics_destination_length);
        if (probe < 0) return ucall_status_connection_failed_k;
        [[maybe_unused]] bool const inet6 = server.metrics_destination.ss_family == AF_INET6;
        // The IPv4 minimum reassembly size, less its headers, wherever the path MTU is unknown.
        server.metrics_datagram_bytes = 576 - 28;
#if UCALL_OS_LINUX_
        int mtu = 0;
        socket_length_t length = sizeof(mtu);
        if (getsockopt(probe, inet6 ? IPPROTO_IPV6 : IPPROTO_IP, inet6 ? IPV6_MTU : IP_MTU, &mtu, &length) == 0 &&
            mtu > (inet6 ? 48 : 28))
            server.metrics_datagram_bytes = static_cast<std::size_t>(mtu) - (inet6 ? 48 : 28);
#endif // UCALL_OS_LINUX_
        socket_close(probe);
        return ucall_status_success_k;
    }
    static void server_init(ucall_server_init_t* arguments, allocator_t const& allocator = {}) noexcept {
        if (!arguments) return;
        if (arguments->server) *arguments->server = nullptr;
        auto* config = arguments->options;
        if (!arguments->outcome || !arguments->server || !config || !config->interfaces || !config->interfaces_count) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto server = allocate_unique<server_t>(allocator, allocator);
        if (!server || st::failed(server->resolved.resize(config->interfaces_count))) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        if (ucall_status_t const resolved = resolve_metrics(*server, *config); resolved != ucall_status_success_k) {
            publish(arguments->outcome, resolved);
            return;
        }
        if (ucall_status_t const routed = server->routes.init(); routed != ucall_status_success_k) {
            publish(arguments->outcome, routed);
            return;
        }
        rebound_allocator<network_interface_t> network_interface_allocator {allocator};
        auto* network_interfaces = network_interface_allocator.allocate(config->interfaces_count);
        if (!network_interfaces) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        for (std::size_t i = 0; i != config->interfaces_count; ++i)
            std::construct_at(network_interfaces + i, allocator);
        server->network_interfaces = {network_interfaces, config->interfaces_count};
        std::size_t event_loops_count = 1;
        io::io_listeners_t listeners = io::io_listeners_t::created_k;
        for (std::size_t i = 0; i != config->interfaces_count; ++i) {
            auto& network_interface = server->network_interfaces[i];
            network_interface.config = config->interfaces[i];
            if (network_interface.config.noise_private_key) {
                std::memcpy(network_interface.private_key, *network_interface.config.noise_private_key,
                            sizeof(network_interface.private_key));
                network_interface.config.noise_private_key = &network_interface.private_key;
            }
            if (network_interface.config.noise_peer_key) {
                std::memcpy(network_interface.peer_key, *network_interface.config.noise_peer_key,
                            sizeof(network_interface.peer_key));
                network_interface.config.noise_peer_key = &network_interface.peer_key;
            }
            auto& settings = network_interface.config;
            std::string_view const device = text_view(settings.device_name);
            if (!http_t::valid_view(settings.address) || !http_t::valid_view(settings.device_name) ||
                http_t::find(device, '\0') != std::string_view::npos) {
                publish(arguments->outcome, ucall_status_invalid_argument_k);
                return;
            }
            if (!device.empty()) {
                if (ucall_status_t const copied = formatting_t::copy_text(network_interface.device, device);
                    copied != ucall_status_success_k) {
                    publish(arguments->outcome, copied);
                    return;
                }
                settings.device_name = bytes_view({network_interface.device.data(), device.size()});
            }
            if ((!settings.address.length && !settings.listen_descriptor) ||
                !formatting_t::security_valid(settings.security) ||
                (settings.security != ucall_security_none_k && !settings.noise_private_key) ||
                (settings.security == ucall_security_noise_xx_k && !settings.peer_authorizer) ||
                (settings.security == ucall_security_noise_kk_k && !settings.noise_peer_key)) {
                publish(arguments->outcome, ucall_status_invalid_argument_k);
                return;
            }
#if !UCALL_OS_LINUX_
            if (settings.device_name.length) {
                publish(arguments->outcome, ucall_status_unsupported_k);
                return;
            }
#endif
            if (!settings.max_concurrent_connections) {
                publish(arguments->outcome, ucall_status_invalid_argument_k);
                return;
            }
            if (ucall_status_t const opened = open_reply_directories(network_interface);
                opened != ucall_status_success_k) {
                publish(arguments->outcome, opened);
                return;
            }
            if (!settings.event_loops) settings.event_loops = formatting_t::interface_event_loops(device);
            if (!settings.event_loops) {
                publish(arguments->outcome, ucall_status_invalid_argument_k);
                return;
            }
            if (settings.event_loops > settings.max_concurrent_connections)
                settings.event_loops = settings.max_concurrent_connections;
            if (!settings.max_pipelined_requests) settings.max_pipelined_requests = 1;
            if (settings.max_pipelined_requests > (std::numeric_limits<std::uint32_t>::max)() ||
                settings.max_concurrent_connections >
                    (std::numeric_limits<std::size_t>::max)() / settings.max_pipelined_requests ||
                settings.max_concurrent_connections * settings.max_pipelined_requests >
                    (std::numeric_limits<std::size_t>::max)() - server->requests_budget) {
                publish(arguments->outcome, ucall_status_overflow_k);
                return;
            }
            server->requests_budget += settings.max_concurrent_connections * settings.max_pipelined_requests;
#if UCALL_OS_WINDOWS_
            if (settings.event_loops > 1) {
                publish(arguments->outcome, ucall_status_unsupported_k);
                return;
            }
#endif
            event_loops_count = fu::max_of(event_loops_count, settings.event_loops);
            if (settings.listen_descriptor) listeners = io::io_listeners_t::borrowed_k;
            network_interface.send_buffer_bytes = formatting_t::listener_send_buffer(network_interface);
            if (settings.noise_private_key)
                x25519_derive_public<typename crypto_t::x25519_kit_t>(
                    network_interface.public_key, std::as_bytes(std::span {*settings.noise_private_key}));
        }
        if (st::failed(server->event_loops.resize(event_loops_count))) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        for (std::size_t event_loop_index = 0; event_loop_index != event_loops_count; ++event_loop_index) {
            server->event_loops[event_loop_index] = allocate_unique<event_loop_t>(allocator, allocator);
            if (!server->event_loops[event_loop_index]) {
                publish(arguments->outcome, ucall_status_out_of_memory_k);
                return;
            }
            auto& event_loop = *server->event_loops[event_loop_index];
            event_loop.server = server.get();
            event_loop.index = static_cast<std::uint32_t>(event_loop_index);
            if (st::failed(event_loop.interface_statistics.resize(config->interfaces_count)) ||
                st::failed(event_loop.interface_orders.resize(config->interfaces_count))) {
                publish(arguments->outcome, ucall_status_out_of_memory_k);
                return;
            }
            if (ucall_status_t const opened = event_loop.wake.open(); opened != ucall_status_success_k) {
                publish(arguments->outcome, opened);
                return;
            }
            std::size_t connections_count = 0, acceptors_count = 0;
            for (auto& network_interface : server->network_interfaces)
                if (event_loop_index < network_interface.config.event_loops) {
                    std::size_t const quota = network_interface.quota(event_loop_index);
                    if (quota > (std::numeric_limits<std::size_t>::max)() - connections_count) {
                        publish(arguments->outcome, ucall_status_overflow_k);
                        return;
                    }
                    connections_count += quota;
                    event_loop.max_exchanges += quota * network_interface.config.max_pipelined_requests;
                    ++acceptors_count;
                }
            if (st::failed(event_loop.connections.resize(connections_count))) {
                publish(arguments->outcome, ucall_status_out_of_memory_k);
                return;
            }
            rebound_allocator<interface_acceptor_t> acceptor_allocator {allocator};
            auto* acceptors = acceptor_allocator.allocate(acceptors_count);
            if (!acceptors) {
                publish(arguments->outcome, ucall_status_out_of_memory_k);
                return;
            }
            for (std::size_t i = 0; i != acceptors_count; ++i) std::construct_at(acceptors + i, allocator);
            event_loop.interface_acceptors = {acceptors, acceptors_count};
            for (auto& connection : event_loop.connections) {
                connection = allocate_unique<connection_t>(allocator, allocator);
                if (!connection) {
                    publish(arguments->outcome, ucall_status_out_of_memory_k);
                    return;
                }
                connection->index = static_cast<std::uint32_t>(&connection - event_loop.connections.data());
                connection->transport.statistics = &event_loop.statistics;
                connection->next = event_loop.idle;
                event_loop.idle = connection.get();
            }
            std::size_t acceptor_index = 0;
            for (auto& network_interface : server->network_interfaces)
                if (event_loop_index < network_interface.config.event_loops) {
                    auto& acceptor = event_loop.interface_acceptors[acceptor_index++];
                    acceptor.event_loop = &event_loop;
                    acceptor.network_interface = &network_interface;
                    if (st::failed(acceptor.peer_addresses.resize(
                            fu::max_of<std::size_t>(network_interface.quota(event_loop_index), 1)))) {
                        publish(arguments->outcome, ucall_status_out_of_memory_k);
                        return;
                    }
                }
        }
        // Each engine opens before its loop's listeners, the later loops on the backend the first
        // one resolved, so loop zero's listeners and the sockets they accept carry its engine's
        // flags, and the later loops accept on duplicates of them; a ring serves the thread that
        // first polls it.
        ucall_io_backend_t backend = config->backend;
        for (auto& event_loop : server->event_loops) {
            std::size_t windows = 0, slots = 0;
            ucall_status_t status = event_loop_slots(*event_loop, windows, slots);
            if (status == ucall_status_success_k)
                status = event_loop->engine.open(backend, slots, slots, io::io_issuer_scope_t::one_thread_k, listeners);
            if (status != ucall_status_success_k) {
                // An engine refused by a host setting or a borrowed listener names what to change.
                char const* refusal = event_loop->engine.refusal();
                publish(arguments->outcome, status, refusal ? refusal : ucall_status_name(status));
                return;
            }
            reserve_releases(*event_loop, windows);
            backend = event_loop->engine.backend();
            for (auto& acceptor : event_loop->interface_acceptors) {
                ucall_status_t result;
                if (!event_loop->index) result = formatting_t::bind_acceptor(acceptor, event_loop->engine);
#if UCALL_OS_POSIX_
                else {
                    auto network_interface_index = static_cast<std::size_t>(acceptor.network_interface -
                                                                            server->network_interfaces.data());
                    auto& first = server->event_loops[0]->interface_acceptors[network_interface_index];
                    int descriptor = fcntl(static_cast<int>(first.request.descriptor), F_DUPFD_CLOEXEC, 0);
                    result = descriptor >= 0 ? ucall_status_success_k : ucall_status_io_k;
                    acceptor.request = {.operation = io_operation_t::accept_k,
                                        .descriptor = descriptor,
                                        .context = &acceptor};
                }
#else
                else result = ucall_status_unsupported_k;
#endif
                if (result != ucall_status_success_k) {
                    publish(arguments->outcome, result);
                    return;
                }
                acceptor.descriptor = acceptor.request.descriptor;
            }
        }
        server->config = *config;
        server->config.backend = backend;
        for (std::size_t i = 0; i != config->interfaces_count; ++i)
            server->resolved[i] = server->network_interfaces[i].config;
        server->config.interfaces = server->resolved.data();
        server->config.metrics_prefix = server->metrics_prefix;
        server->config.metrics_tags = server->metrics_tag_views.data();
        if (!server->config.metrics_sample_rate) server->config.metrics_sample_rate = 1.f;
        if (!server->config.metrics_interval_microseconds) server->config.metrics_interval_microseconds = 1'000'000;
        if (arguments->resolved) *arguments->resolved = server->config;
        server->api = &server_api_k;
        char digits[std::numeric_limits<std::size_t>::digits10 + 1];
        for (auto const& network_interface : server->network_interfaces)
            formatting_t::log_line(server->config.log, ucall_log_level_info_k, "serving",
                                   {{"address", text_view(network_interface.config.address)},
                                    {"backend", ucall_io_backend_name(server->config.backend)},
                                    {"event_loops", formatting_t::format_decimal(digits, server->event_loops.size())}});
        *arguments->server = server.release();
        publish(arguments->outcome, ucall_status_success_k);
    }

    /** The first stop drains, letting the replies in flight finish; any later one cuts them. */
    static void server_stop(ucall_server_t handle) noexcept {
        if (!handle) return;
        auto& server = *static_cast<server_t*>(handle);
        atomic_ref<std::uint32_t> {server.stage}.fetch_add_if_at_most(
            1, static_cast<std::uint32_t>(server_stage_t::cutting_k), std::memory_order_release);
        for (auto& event_loop : server.event_loops) event_loop->notify();
        for (auto* endpoint : server.batch_endpoints) endpoint->wake.notify();
    }

    /** Stops at once, cutting the replies in flight, as a failure or a free must. */
    static void server_cut(server_t& server) noexcept {
        atomic_ref<std::uint32_t> {server.stage}.store(static_cast<std::uint32_t>(server_stage_t::cutting_k),
                                                       std::memory_order_release);
        server_stop(&server);
    }

    /** Opens the loop's StatsD socket through its engine, with every buffer a datagram needs. */
    static ucall_status_t open_metrics(server_t& server, event_loop_t& event_loop) noexcept {
        if (!server.metrics_destination_length) return ucall_status_success_k;
        auto& metrics = event_loop.metrics;
        std::size_t const interfaces = event_loop.interface_statistics.size();
        std::size_t const batches = event_loop.index ? 0 : server.batch_endpoints.size();
        if (st::failed(metrics.composing.reserve(server.metrics_datagram_bytes)) ||
            st::failed(metrics.sending.reserve(server.metrics_datagram_bytes)) ||
            st::failed(metrics.interfaces_reported.resize(interfaces)) ||
            st::failed(metrics.interfaces_reporting.resize(interfaces)) ||
            st::failed(metrics.batches_reported.resize(batches)) ||
            st::failed(metrics.batches_reporting.resize(batches)))
            return ucall_status_out_of_memory_k;
        descriptor_t const opened = datagram_open(reinterpret_cast<sockaddr const*>(&server.metrics_destination),
                                                  server.metrics_destination_length);
        descriptor_t const descriptor = opened < 0 ? opened : event_loop.engine.import_socket(opened);
        if (descriptor < 0) return ucall_status_connection_failed_k;
        metrics.send_request = {.operation = io_operation_t::send_k, .descriptor = descriptor, .context = &metrics};
        metrics.state = metrics_state_t::idle_k;
        metrics.due = deadline_after(server.config.metrics_interval_microseconds);
        return ucall_status_success_k;
    }

    /** The file windows @p event_loop may hold and the engine slots it opens: each connection one
     *  operation per direction and one for files, each acceptor one, as its accept and the refusal
     *  of a peer it sheds never overlap, each window one release, each pipelined exchange two, and
     *  the wakeup and the metrics socket one each. */
    static ucall_status_t event_loop_slots(event_loop_t const& event_loop, std::size_t& windows,
                                           std::size_t& slots) noexcept {
        auto connections = event_loop.connections.size(), acceptors = event_loop.interface_acceptors.size();
        std::size_t const counted_limit = (std::numeric_limits<std::uint32_t>::max)() / 8;
        if (connections > counted_limit || acceptors > counted_limit || event_loop.max_exchanges > counted_limit)
            return ucall_status_overflow_k;
        // Every stream holds at most its socket's send buffer in windows, so the pool sums them.
        windows = 0;
        for (auto const& acceptor : event_loop.interface_acceptors)
            windows += acceptor.network_interface->quota(event_loop.index) *
                       replies_t::stream_windows_limit(acceptor.network_interface->send_buffer_bytes);
        if (windows > counted_limit) return ucall_status_overflow_k;
        slots = 3 * connections + acceptors + 2 + windows + 2 * event_loop.max_exchanges + event_loop.bound_slots;
        return ucall_status_success_k;
    }

    /** Grows @p event_loop's engine to its present size, as only a loop not yet polled may: a ring
     *  keeps the size and the locked memory initialization proved, and other engines lock none. */
    static ucall_status_t grow_engine(event_loop_t& event_loop) noexcept {
        std::size_t windows = 0, slots = 0;
        if (ucall_status_t const sized = event_loop_slots(event_loop, windows, slots); sized != ucall_status_success_k)
            return sized;
        ucall_status_t const grown = event_loop.engine.grow(slots);
        if (grown == ucall_status_success_k) reserve_releases(event_loop, windows);
        return grown;
    }

    /** Sets aside what the windows and exchanges of @p event_loop can name, within its slots. */
    static void reserve_releases(event_loop_t& event_loop, std::size_t windows) noexcept {
        event_loop.engine.reserve_releases(windows + 2 * event_loop.max_exchanges);
    }

    /** Makes a client of @c options->server's loop @c options->event_loop, sharing its engine,
     *  whose tables grow by the client's slots, which only a loop not yet polled allows. */
    static void bind_client(ucall_client_init_t* arguments) noexcept {
        auto options = *arguments->options;
        auto& server = *static_cast<server_t*>(options.server);
        if (options.event_loop >= server.event_loops.size() ||
            server.event_loops[options.event_loop]->stage != event_loop_stage_t::unopened_k) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& event_loop = *server.event_loops[options.event_loop];
        options.backend = server.config.backend;
        options.cpu_class = server.config.cpu_class;
        ucall_client_init_t bound = *arguments;
        bound.options = &options;
        client_t::client_init(&bound, server.allocator, &event_loop.engine);
        if (ucall_status_t const made = arguments->outcome->status; made != ucall_status_success_k) return;
        auto* client = static_cast<client_t*>(*arguments->client);
        std::size_t const slots = client_t::engine_slots(client->config);
        event_loop.bound_slots += slots;
        if (ucall_status_t const grown = grow_engine(event_loop); grown != ucall_status_success_k) {
            event_loop.bound_slots -= slots;
            allocator_delete<client_t, allocator_t> {client->allocator}(client);
            *arguments->client = nullptr;
            // The loop keeps serving at its former size, or reports why not from its first poll.
            event_loop.setup_status = grow_engine(event_loop);
            char const* refusal = event_loop.engine.refusal();
            publish(arguments->outcome, grown, refusal ? refusal : ucall_status_name(grown));
            return;
        }
        client->next_bound = std::exchange(event_loop.bound_clients, client);
    }

    /** The bound client a completion belongs to, or null for the loop's own requests. */
    static client_t* bound_client(event_loop_t const& event_loop, io_completion_t const& completion) noexcept {
        if (!event_loop.bound_clients) return nullptr;
        for (client_t* client = event_loop.bound_clients; client; client = client->next_bound)
            if (resolving_t::owns(*client, completion.request)) return client;
        // Both roles hold their transport first, so its role tells which record the context names.
        void* const context = completion.request->context;
        return static_cast<transport_t*>(context)->role == transport_role_t::client_k
                   ? static_cast<client_connection_t*>(context)->client
                   : nullptr;
    }

    /** Steps the loop's bound clients, deleting those freed once nothing of them is left in flight,
     *  and answers when the earliest of the rest next needs a step, or zero. */
    static std::uint64_t bound_progress(event_loop_t& event_loop) noexcept {
        std::uint64_t deadline = 0;
        for (client_t** link = &event_loop.bound_clients; *link;) {
            client_t& client = **link;
            std::uint64_t const due = client_t::client_progress(client);
            if (client.binding == client_binding_t::retiring_k && client_t::retired(client)) {
                *link = client.next_bound;
                allocator_delete<client_t, allocator_t> {client.allocator}(&client);
                continue;
            }
            if (due && (!deadline || due < deadline)) deadline = due;
            link = &client.next_bound;
        }
        return deadline;
    }
    static ucall_status_t open_event_loop(event_loop_t& event_loop) noexcept {
        if (event_loop.stage != event_loop_stage_t::unopened_k) return event_loop.setup_status;
        std::size_t windows = 0, slots = 0;
        if (ucall_status_t const sized = event_loop_slots(event_loop, windows, slots); sized != ucall_status_success_k)
            return sized;
        auto& pool = event_loop.file_windows;
        pool.max_windows = static_cast<std::uint32_t>(windows);
        if (st::failed(pool.window_runs.reserve(pool.max_windows)) ||
            st::failed(pool.window_memory.reserve(pool.max_windows)) ||
            st::failed(pool.windows.reserve(pool.max_windows)) ||
            st::failed(pool.release_requests.reserve(pool.max_windows)))
            return ucall_status_out_of_memory_k;
        event_loop.stage = event_loop_stage_t::serving_k;
        if (st::failed(event_loop.completions.resize(slots))) return ucall_status_out_of_memory_k;
        auto descriptor = event_loop.engine.import_socket(event_loop.wake.descriptors[0]);
        if (descriptor < 0) return ucall_status_io_k;
        event_loop.wake.descriptors[0] = -1;
        event_loop.wake.request.descriptor = descriptor;
        if (event_loop.engine.submit(event_loop.wake.request) != ucall_status_success_k) return ucall_status_io_k;
        if (ucall_status_t const opened = open_metrics(*event_loop.server, event_loop);
            opened != ucall_status_success_k)
            return opened;
        for (auto& acceptor : event_loop.interface_acceptors) {
            auto imported = event_loop.engine.import_socket(acceptor.request.descriptor);
            if (imported < 0) return ucall_status_io_k;
            acceptor.request.descriptor = imported;
            acceptor.descriptor = -1;
            acceptor.reserve_descriptor = socket_open(acceptor.network_interface->family);
            if (acceptor.reserve_descriptor < 0) return ucall_status_io_k;
        }
        return ucall_status_success_k;
    }
    static void advance_completion(engine_t& engine, io_completion_t const& completion) noexcept {
        if (completion.request->operation == io_operation_t::accept_k) serving_t::accepted(completion);
        else static_cast<connection_t*>(completion.request->context)->complete(completion);
        engine.release(completion);
    }
    static ucall_status_t server_poll(server_t& server, event_loop_t& event_loop, io_wait_t wait,
                                      std::uint64_t deadline = 0) noexcept {
        if (event_loop.setup_status != ucall_status_success_k) return event_loop.setup_status;
        if (event_loop.stage == event_loop_stage_t::retired_k)
            return atomic_ref<ucall_status_t> {server.failure}.load(std::memory_order_acquire);
        event_loop.setup_status = open_event_loop(event_loop);
        if (event_loop.setup_status != ucall_status_success_k) {
            // A loop that never opened deposits nothing, so batch owners must not wait for it.
            serving_t::retire_event_loop(server, event_loop);
            return event_loop.setup_status;
        }
        // Stored once, so polling never dirties the line registrations read.
        if (auto polling_started = atomic_ref<std::uint32_t> {server.polling_started};
            !polling_started.load(std::memory_order_relaxed))
            polling_started.store(1, std::memory_order_release);
        serving_t::server_progress(server, event_loop);
        if (event_loop.stage == event_loop_stage_t::retired_k)
            return atomic_ref<ucall_status_t> {server.failure}.load(std::memory_order_acquire);
        // A close waiting for the kernel's releases resets at its deadline, metrics go out at
        // theirs, reserves the residue held closed reopen at theirs, and bound clients step at
        // theirs, with nothing to poll.
        for (std::uint64_t const due : {serving_t::release_deadline(event_loop), event_loop.metrics.due,
                                        event_loop.accept_deadline, bound_progress(event_loop)})
            if (due && (!deadline || due < deadline)) deadline = due;
        // A notify that landed while the loop ran may have listed what the rounds above missed.
        auto wake_state = atomic_ref<wake_state_t> {event_loop.wake_state};
        if (wait == io_wait_t::blocking_k &&
            wake_state.exchange(wake_state_t::sleeping_k, std::memory_order_acq_rel) == wake_state_t::notified_k)
            serving_t::server_progress(server, event_loop);
        int count = event_loop.engine.poll(span<io_completion_t> {event_loop.completions}, wait, deadline);
        // Acquiring, so the listings of notifies that found the channel already written are seen.
        if (wait == io_wait_t::blocking_k) {
            [[maybe_unused]] wake_state_t const slept = wake_state.exchange(wake_state_t::awake_k,
                                                                            std::memory_order_acq_rel);
        }
        if (count < 0) {
            atomic_ref<ucall_status_t> {server.failure}.store(ucall_status_io_k, std::memory_order_release);
            server_cut(server);
            serving_t::retire_event_loop(server, event_loop);
            return ucall_status_io_k;
        }
        tally<atomic_ref>(event_loop.statistics.polls);
        if (!count) tally<atomic_ref>(event_loop.statistics.empty_polls);
        for (int i = 0; i != count; ++i) {
            auto& completion = event_loop.completions[static_cast<std::size_t>(i)];
            if (completion.request == &event_loop.wake.request) {
                event_loop.engine.release(completion);
                if (event_loop.engine.submit(event_loop.wake.request) != ucall_status_success_k) {
                    atomic_ref<ucall_status_t> {server.failure}.store(ucall_status_io_k, std::memory_order_release);
                    server_cut(server);
                }
            }
            else if (completion.request == &event_loop.metrics.send_request) {
                metrics_t::complete_metrics(event_loop, completion);
                event_loop.engine.release(completion);
            }
            else if (completion.request->operation == io_operation_t::accept_k)
                advance_completion(event_loop.engine, completion);
            else if (completion.request->operation == io_operation_t::zero_copy_release_k) {
                replies_t::complete_release(event_loop, completion);
                event_loop.engine.release(completion);
            }
            else if (auto* const acceptor = serving_t::shedding_acceptor(event_loop, completion.request)) {
                serving_t::shed_sent(event_loop, *acceptor);
                event_loop.engine.release(completion);
            }
            else if (client_t* const client = bound_client(event_loop, completion))
                client_t::step_completion(*client, completion);
            else {
                auto& connection = *static_cast<connection_t*>(completion.request->context);
                advance_completion(event_loop.engine, completion);
                if (completion.request != &connection.file_read_request) {
                    if (completion.request->operation == io_operation_t::send_zero_copy_k)
                        replies_t::complete_zero_copy_send(event_loop, connection, completion);
                }
                else if (completion.request->operation == io_operation_t::file_open_k)
                    replies_t::complete_file_open(connection, completion);
                else replies_t::complete_file_read(event_loop, connection, completion);
                serving_t::mark_ready(event_loop, connection);
            }
        }
        serving_t::server_progress(server, event_loop);
        // Handlers just called out, and answers just arrived, so bound clients step before the
        // caller reads them.
        bound_progress(event_loop);
        return atomic_ref<ucall_status_t> {server.failure}.load(std::memory_order_acquire);
    }
    static void server_take_call(ucall_server_take_call_t* arguments) noexcept {
        auto& server = *static_cast<server_t*>(arguments->server);
        if (arguments->event_loop_index >= server.event_loops.size()) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto wait = arguments->timeout_microseconds ? io_wait_t::blocking_k : io_wait_t::nonblocking_k;
        auto deadline = arguments->timeout_microseconds ? deadline_after(arguments->timeout_microseconds) : 0;
        auto& event_loop = *server.event_loops[arguments->event_loop_index];
        auto polling_thread = atomic_ref<polling_thread_t> {event_loop.polling_thread};
        polling_thread.store(current_polling_thread(), std::memory_order_relaxed);
        ucall_status_t status = server_poll(server, event_loop, wait, deadline);
        // A caller polling in slices learns here that the loop has nothing left to take.
        if (status == ucall_status_success_k && event_loop.stage == event_loop_stage_t::retired_k)
            status = ucall_status_connection_closed_k;
        polling_thread.store({}, std::memory_order_relaxed);
        publish(arguments->outcome, status);
    }
    static void server_take_calls(ucall_server_take_calls_t* arguments) noexcept {
        auto& server = *static_cast<server_t*>(arguments->server);
        if (arguments->event_loop_index >= server.event_loops.size()) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& event_loop = *server.event_loops[arguments->event_loop_index];
        ucall_status_t status = ucall_status_success_k;
        auto polling_thread = atomic_ref<polling_thread_t> {event_loop.polling_thread};
        polling_thread.store(current_polling_thread(), std::memory_order_relaxed);
        while (event_loop.stage != event_loop_stage_t::retired_k && status == ucall_status_success_k)
            status = server_poll(server, event_loop, io_wait_t::blocking_k);
        polling_thread.store({}, std::memory_order_relaxed);
        publish(arguments->outcome, status);
    }

    /** Every counter of @p event_loop, as any thread may read them while the loop runs. */
    static ucall_event_loop_statistics_t loop_totals(event_loop_t& event_loop) noexcept {
        auto& loop = event_loop.statistics;
        auto& engine = event_loop.engine.statistics();
        auto read = [](std::uint64_t& counter) noexcept {
            return atomic_ref<std::uint64_t> {counter}.load(std::memory_order_relaxed);
        };
        ucall_event_loop_statistics_t totals {.polls = read(loop.polls),
                                              .empty_polls = read(loop.empty_polls),
                                              .kernel_enters = read(engine.kernel_enters),
                                              .submissions = read(engine.submissions),
                                              .completions = read(engine.completions),
                                              .cancellations = read(engine.cancellations),
                                              .accepts = read(loop.accepts),
                                              .requests = read(loop.requests),
                                              .receive_rearms = read(engine.receive_rearms),
                                              .bytes_received = read(loop.bytes_received),
                                              .bytes_sent = read(loop.bytes_sent),
                                              .bytes_copied = read(loop.bytes_copied) + read(engine.bytes_copied),
                                              .zero_copy_sends = read(engine.zero_copy_sends),
                                              .zero_copy_fallbacks = read(engine.zero_copy_fallbacks),
                                              .copying_sends = read(engine.copying_sends),
                                              .file_reads_asynchronous = read(engine.file_reads_asynchronous),
                                              .file_reads_blocking = read(engine.file_reads_blocking),
                                              .bytes_read = read(loop.bytes_read),
                                              .file_window_overlaps = read(loop.file_window_overlaps),
                                              .linger_resets = read(loop.linger_resets),
                                              .ready_passes = read(loop.ready_passes),
                                              .replied_dequeues = read(loop.replied_dequeues),
                                              .shed_connections = read(loop.shed_connections),
                                              .windows_unpinned = read(loop.windows_unpinned)};
        for (auto& counters : event_loop.interface_statistics) {
            for (auto& refused : counters.refused) totals.refused_requests += read(refused);
            totals.handshake_failures += read(counters.handshake_failures);
            totals.authorizer_refusals += read(counters.authorizer_refusals);
        }
        return totals;
    }
    static void server_event_loop_statistics(ucall_server_event_loop_statistics_t* arguments) noexcept {
        auto& server = *static_cast<server_t*>(arguments->server);
        if (!arguments->statistics || arguments->event_loop_index >= server.event_loops.size()) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        *arguments->statistics = loop_totals(*server.event_loops[arguments->event_loop_index]);
        publish(arguments->outcome, ucall_status_success_k);
    }

    /** Hands the pending batch to its callback and counts it under @p trigger, the counter of why
     *  it fired, or detaches it while stopping, firing and counting nothing. */
    static ucall_status_t flush_collected(batch_endpoint_t& endpoint, server_stage_t stage,
                                          std::uint64_t& trigger) noexcept {
        if (endpoint.collected.empty()) return ucall_status_would_block_k;
        if (stage == server_stage_t::cutting_k)
            for (auto handle : endpoint.collected) {
                auto& exchange = *static_cast<server_exchange_t*>(handle);
                atomic_ref<std::uint32_t> {exchange.shared.state}.set_bits(claimed_k | replied_k | detached_k,
                                                                           std::memory_order_release);
                replies_t::abandon_reply(exchange);
            }
        else {
            tally<atomic_ref>(endpoint.statistics.batches);
            tally<atomic_ref>(endpoint.statistics.requests, endpoint.collected.size());
            tally<atomic_ref>(trigger);
            endpoint.callback(endpoint.collected.data(), endpoint.collected.size(), endpoint.context);
        }
        endpoint.collected.clear();
        return stage != server_stage_t::cutting_k ? ucall_status_success_k : ucall_status_would_block_k;
    }

    /** One round of one batch endpoint: moves its deposits to @c collected, invokes the batch
     *  if due, and sets @p expiry to when the waiting remainder falls due, or zero when nothing
     *  waits. Succeeds when the callback fired, or reports @c ucall_status_would_block_k. */
    static ucall_status_t collect_deposits(batch_endpoint_t& endpoint, server_stage_t stage,
                                           std::uint64_t& expiry) noexcept {
        auto tail = atomic_ref<std::uint64_t> {endpoint.tail}.load(std::memory_order_acquire);
        ucall_status_t flushed = ucall_status_would_block_k;
        auto head = endpoint.head;
        for (; head != tail; ++head) {
            server_exchange_t*& word = endpoint.slots[head & (endpoint.slots.size() - 1)];
            auto slot = atomic_ref<server_exchange_t*> {word};
            auto* exchange = slot.load(std::memory_order_acquire);
            // The depositor has claimed this index and stores into it right after.
            while (!exchange) {
                waiter_t {}(&word, exchange, 0);
                exchange = slot.load(std::memory_order_acquire);
            }
            slot.store(nullptr, std::memory_order_relaxed);
            [[maybe_unused]] st::status_t const queued = endpoint.collected.push_back(st::assume_reserved, exchange);
            if (endpoint.collected.size() == endpoint.max_batch_size &&
                flush_collected(endpoint, stage, endpoint.statistics.filled_batches) == ucall_status_success_k)
                flushed = ucall_status_success_k;
        }
        atomic_ref<std::uint64_t> {endpoint.head}.store(head, std::memory_order_release);
        expiry = 0;
        if (endpoint.collected.empty()) return flushed;
        auto arrived = static_cast<server_exchange_t*>(endpoint.collected.front())->arrived;
        auto maximum = (std::numeric_limits<std::uint64_t>::max)();
        auto due = endpoint.max_latency_microseconds > (maximum - arrived) / 1000
                       ? maximum
                       : arrived + endpoint.max_latency_microseconds * 1000;
        auto ready = endpoint.collected.size() >= endpoint.min_batch_size;
        if (stage != server_stage_t::serving_k || ready || monotonic_ns() >= due) {
            auto& trigger = ready ? endpoint.statistics.ready_batches : endpoint.statistics.expired_batches;
            if (flush_collected(endpoint, stage, trigger) == ucall_status_success_k) flushed = ucall_status_success_k;
        }
        else expiry = due;
        return flushed;
    }

    /** Whether batch rounds are done: the server cuts, or drains with every loop retired, and a
     *  loop retires only once each deposit it made was answered. */
    static bool batches_ended(server_t& server, server_stage_t stage) noexcept {
        if (stage != server_stage_t::draining_k) return stage == server_stage_t::cutting_k;
        auto const retired = atomic_ref<std::uint32_t> {server.retired_event_loops}.load(std::memory_order_acquire);
        return retired == server.event_loops.size();
    }

    /** Sleeps on the endpoint's wake channel until a deposit, a stop, or @p deadline, zero meaning
     *  none. Depositors wake only a sleeping polling owner, so it announces sleep before its last
     *  look at the queue. */
    static void wait_for_deposits(server_t& server, batch_endpoint_t& endpoint, std::uint64_t deadline) noexcept {
        auto wake_state = atomic_ref<wake_state_t> {endpoint.wake_state};
        wake_state.store(wake_state_t::sleeping_k, std::memory_order_seq_cst);
        if (atomic_ref<std::uint64_t> {endpoint.tail}.load(std::memory_order_seq_cst) == endpoint.head &&
            !batches_ended(server, serving_t::server_stage(server)))
            endpoint.wake.wait(deadline);
        wake_state.store(wake_state_t::awake_k, std::memory_order_seq_cst);
    }
    static void server_take_batch(ucall_server_take_batch_t* arguments) noexcept {
        if (!arguments->endpoint) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& server = *static_cast<server_t*>(arguments->server);
        auto& endpoint = *static_cast<batch_endpoint_t*>(arguments->endpoint);
        auto deadline = arguments->timeout_microseconds ? deadline_after(arguments->timeout_microseconds) : 0;
        for (;;) {
            std::uint64_t expiry {};
            auto stage = serving_t::server_stage(server);
            if (collect_deposits(endpoint, stage, expiry) == ucall_status_success_k || batches_ended(server, stage) ||
                monotonic_ns() >= deadline)
                break;
            wait_for_deposits(server, endpoint, expiry ? fu::min_of(expiry, deadline) : deadline);
        }
        publish(arguments->outcome, atomic_ref<ucall_status_t> {server.failure}.load(std::memory_order_acquire));
    }
    static void server_take_batches(ucall_server_take_batches_t* arguments) noexcept {
        if (!arguments->endpoint) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& server = *static_cast<server_t*>(arguments->server);
        auto& endpoint = *static_cast<batch_endpoint_t*>(arguments->endpoint);
        for (;;) {
            std::uint64_t expiry {};
            auto stage = serving_t::server_stage(server);
            collect_deposits(endpoint, stage, expiry);
            if (batches_ended(server, stage)) break;
            wait_for_deposits(server, endpoint, expiry);
        }
        publish(arguments->outcome, atomic_ref<ucall_status_t> {server.failure}.load(std::memory_order_acquire));
    }
    static void server_batch_endpoint_statistics(ucall_server_batch_endpoint_statistics_t* arguments) noexcept {
        if (!arguments->endpoint || !arguments->statistics) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& counters = static_cast<batch_endpoint_t*>(arguments->endpoint)->statistics;
        auto read = [](std::uint64_t& counter) noexcept {
            return atomic_ref<std::uint64_t> {counter}.load(std::memory_order_relaxed);
        };
        *arguments->statistics = {.batches = read(counters.batches),
                                  .requests = read(counters.requests),
                                  .filled_batches = read(counters.filled_batches),
                                  .ready_batches = read(counters.ready_batches),
                                  .expired_batches = read(counters.expired_batches)};
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void server_free(ucall_server_t handle) noexcept {
        if (!handle) return;
        auto& server = *static_cast<server_t*>(handle);
        // A bound client still in use shares a loop's engine, so the server outlives it.
        for (auto& event_loop : server.event_loops)
            for (client_t* client = event_loop->bound_clients; client; client = client->next_bound)
                if (client->binding == client_binding_t::bound_k) return;
        server_cut(server);
        for (auto& event_loop : server.event_loops)
            while (event_loop->stage != event_loop_stage_t::unopened_k &&
                   event_loop->stage != event_loop_stage_t::retired_k &&
                   event_loop->setup_status == ucall_status_success_k)
                if (server_poll(server, *event_loop, io_wait_t::blocking_k) != ucall_status_success_k) break;
        // Freed clients the loops did not finish are deleted once their engines hold
        // nothing of them.
        for (auto& event_loop : server.event_loops) {
            event_loop->engine.stop();
            while (client_t* const client = event_loop->bound_clients) {
                event_loop->bound_clients = client->next_bound;
                allocator_delete<client_t, allocator_t> {client->allocator}(client);
            }
        }
        allocator_delete<server_t, allocator_t> {server.allocator}(&server);
    }
    template <typename arguments_type_>
    static void add_endpoint(arguments_type_* arguments) noexcept {
        if (!arguments->callback || !http_t::valid_view(arguments->uri_template) ||
            (!http_t::http_verb_name(arguments->verb) && arguments->verb != ucall_verb_any_k)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& server = *static_cast<server_t*>(arguments->server);
        if (atomic_ref<std::uint32_t> {server.polling_started}.load(std::memory_order_acquire)) {
            publish(arguments->outcome, ucall_status_contended_k);
            return;
        }
        auto path = text_view(arguments->uri_template);
        if (path.empty() || path.front() != '/' || http_t::find(path, '?') != std::string_view::npos ||
            http_t::find(path, '#') != std::string_view::npos) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        for (auto* existing = server.endpoints; existing; existing = existing->next)
            if ((existing->callback || (existing->batch && existing->batch->callback)) &&
                existing->verb == arguments->verb && http_t::equal(existing->path, path)) {
                publish(arguments->outcome, ucall_status_already_exists_k);
                return;
            }
        auto* endpoint = allocate_unique<endpoint_t>(server.allocator, server.allocator).release();
        ucall_status_t const copied = endpoint ? formatting_t::copy_text(endpoint->storage, path)
                                               : ucall_status_out_of_memory_k;
        if (copied != ucall_status_success_k) {
            allocator_delete<endpoint_t, allocator_t> {server.allocator}(endpoint);
            publish(arguments->outcome, copied);
            return;
        }
        endpoint->path = {endpoint->storage.data(), path.size()};
        endpoint->verb = arguments->verb;
        if constexpr (requires { arguments->min_batch_size; }) {
            endpoint->batch = allocate_unique<batch_endpoint_t>(server.allocator, server.allocator);
            auto* batch = endpoint->batch.get();
            auto slots = server.requests_budget + server.event_loops.size();
            auto max_batch_size = arguments->max_batch_size ? arguments->max_batch_size : 32;
            ucall_status_t prepared = ucall_status_out_of_memory_k;
            if (batch && !st::failed(batch->collected.reserve(max_batch_size)) &&
                !st::failed(batch->slots.resize(std::bit_ceil(slots))) &&
                !st::failed(server.batch_endpoints.reserve(server.batch_endpoints.size() + 1)))
                prepared = batch->wake.open();
            if (prepared != ucall_status_success_k) {
                allocator_delete<endpoint_t, allocator_t> {server.allocator}(endpoint);
                publish(arguments->outcome, prepared);
                return;
            }
            batch->min_batch_size = arguments->min_batch_size ? arguments->min_batch_size : 1;
            batch->max_batch_size = max_batch_size;
            batch->max_latency_microseconds = arguments->max_latency_microseconds ? arguments->max_latency_microseconds
                                                                                  : 10'000;
            batch->context = arguments->context;
        }
        endpoint->next = server.endpoints;
        server.endpoints = endpoint;
        // Trie edges may already borrow template segments when an allocation fails.
        if (auto status = server.routes.insert(endpoint->path, endpoint->verb, endpoint);
            status != ucall_status_success_k) {
            publish(arguments->outcome, status);
            return;
        }
        if constexpr (requires { arguments->min_batch_size; }) {
            auto& batch = *endpoint->batch;
            batch.callback = arguments->callback;
            [[maybe_unused]] st::status_t const listed = server.batch_endpoints.emplace_back(st::assume_reserved,
                                                                                             &batch);
            *arguments->endpoint = &batch;
        }
        else {
            endpoint->callback = arguments->callback;
            endpoint->body_delivery = arguments->body_delivery;
            endpoint->context = arguments->context;
        }
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void server_add_http_endpoint(ucall_server_add_http_endpoint_t* arguments) noexcept {
        add_endpoint(arguments);
    }
    static void server_add_http_batch_endpoint(ucall_server_add_http_batch_endpoint_t* arguments) noexcept {
        auto minimum = arguments->min_batch_size ? arguments->min_batch_size : 1;
        auto maximum = arguments->max_batch_size ? arguments->max_batch_size : 32;
        if (!arguments->endpoint || minimum > maximum) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        add_endpoint(arguments);
    }
    static ucall_verb_t server_request_verb(ucall_server_t, ucall_received_http_request_t request) noexcept {
        return request ? static_cast<server_exchange_t*>(request)->message.verb : ucall_verb_unknown_k;
    }
    static void server_request_path(ucall_server_request_path_t* arguments) noexcept {
        if (arguments->path) *arguments->path = {};
        if (!arguments->request || !arguments->path) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        *arguments->path = bytes_view(extract_path_component<http_t>(exchange.message.target(exchange.text())));
        publish(arguments->outcome, ucall_status_success_k);
    }
    static std::string_view path_segment(std::string_view path, std::size_t index) noexcept {
        path_cursor<http_t> cursor {path};
        for (auto segment = cursor.next(); segment.data(); segment = cursor.next())
            if (!index--) return segment;
        return {};
    }
    static std::size_t server_request_path_segments_count(ucall_server_t,
                                                          ucall_received_http_request_t request) noexcept {
        if (!request) return 0;
        auto& exchange = *static_cast<server_exchange_t*>(request);
        return count_path_segments<http_t>(extract_path_component<http_t>(exchange.message.target(exchange.text())));
    }
    static void server_request_path_segment(ucall_server_request_path_segment_t* arguments) noexcept {
        if (arguments->segment) *arguments->segment = {};
        if (!arguments->request || !arguments->segment) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        auto value = path_segment(extract_path_component<http_t>(exchange.message.target(exchange.text())),
                                  arguments->index);
        *arguments->segment = bytes_view(value);
        publish(arguments->outcome, value.data() ? ucall_status_success_k : ucall_status_not_found_k);
    }
    static void server_request_path_parameter(ucall_server_request_path_parameter_t* arguments) noexcept {
        if (arguments->value) *arguments->value = {};
        if (!arguments->request || !arguments->value || !http_t::valid_view(arguments->name)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        auto* endpoint = exchange.endpoint;
        auto name = text_view(arguments->name);
        auto pattern = endpoint ? endpoint->path : std::string_view {};
        auto path = extract_path_component<http_t>(exchange.message.target(exchange.text()));
        path_cursor<http_t> patterns {pattern}, values {path};
        for (auto segment = patterns.next(); segment.data(); segment = patterns.next()) {
            if (values.ended()) break;
            auto value = values.next();
            parsed_segment_t parsed {};
            if (!parse_segment<http_t>(segment, parsed)) break;
            if (parsed.type != segment_type_t::literal_k && http_t::equal(parsed.content, name)) {
                if (parsed.type == segment_type_t::wildcard_k)
                    value = path.substr(static_cast<std::size_t>(value.data() - path.data()));
                *arguments->value = bytes_view(value);
                publish(arguments->outcome, ucall_status_success_k);
                return;
            }
        }
        publish(arguments->outcome, ucall_status_not_found_k);
    }
    static void server_request_query_parameter(ucall_server_request_query_parameter_t* arguments) noexcept {
        if (arguments->value) *arguments->value = {};
        if (!arguments->request || !arguments->value || !http_t::valid_view(arguments->name)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        auto target = exchange.message.target(exchange.text());
        auto query_at = http_t::find(target, '?');
        auto query = query_at == std::string_view::npos ? std::string_view {} : target.substr(query_at + 1);
        while (!query.empty()) {
            auto end = http_t::find(query, '&');
            auto field = query.substr(0, end);
            auto equals = http_t::find(field, '=');
            if (http_t::equal(field.substr(0, equals), text_view(arguments->name))) {
                *arguments->value = bytes_view(equals == std::string_view::npos ? std::string_view {}
                                                                                : field.substr(equals + 1));
                publish(arguments->outcome, ucall_status_success_k);
                return;
            }
            if (end == std::string_view::npos) break;
            query.remove_prefix(end + 1);
        }
        publish(arguments->outcome, ucall_status_not_found_k);
    }
    static void server_request_header(ucall_server_request_header_t* arguments) noexcept {
        if (arguments->value) *arguments->value = {};
        if (!arguments->request || !arguments->value || !http_t::valid_view(arguments->name) ||
            !http_t::http_token(text_view(arguments->name))) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        auto value = exchange.message.header(exchange.text(), text_view(arguments->name));
        *arguments->value = bytes_view(value);
        publish(arguments->outcome, value.data() ? ucall_status_success_k : ucall_status_not_found_k);
    }
    static void server_request_fields_count(ucall_server_request_fields_count_t* arguments) noexcept {
        if (arguments->count) *arguments->count = 0;
        if (!arguments->request || !arguments->count) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        *arguments->count = exchange.message.fields_count(exchange.text());
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void server_request_field(ucall_server_request_field_t* arguments) noexcept {
        if (arguments->name) *arguments->name = {};
        if (arguments->value) *arguments->value = {};
        if (!arguments->request || !arguments->name || !arguments->value) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        std::string_view name, value;
        if (!exchange.message.field(exchange.text(), arguments->index, name, value)) {
            publish(arguments->outcome, ucall_status_not_found_k);
            return;
        }
        *arguments->name = bytes_view(name);
        *arguments->value = bytes_view(value);
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void server_request_query(ucall_server_request_query_t* arguments) noexcept {
        if (arguments->query) *arguments->query = {};
        if (!arguments->request || !arguments->query) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        auto target = exchange.message.target(exchange.text());
        auto query_at = http_t::find(target, '?');
        if (query_at != std::string_view::npos) *arguments->query = bytes_view(target.substr(query_at + 1));
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void server_request_peer(ucall_server_request_peer_t* arguments) noexcept {
        if (arguments->network_interface_index) *arguments->network_interface_index = 0;
        if (arguments->static_key) std::memset(*arguments->static_key, 0, sizeof(ucall_noise_key_t));
        if (arguments->address) *arguments->address = {};
        if (!arguments->request || !arguments->network_interface_index || !arguments->static_key ||
            !arguments->address) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& server = *static_cast<server_t*>(arguments->server);
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        *arguments->network_interface_index = static_cast<std::size_t>(exchange.network_interface -
                                                                       server.network_interfaces.data());
        std::memcpy(*arguments->static_key, exchange.peer_static_key, sizeof(ucall_noise_key_t));
        *arguments->address = exchange.peer_address;
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void server_request_body(ucall_server_request_body_t* arguments) noexcept {
        if (arguments->body) *arguments->body = {};
        if (!arguments->request || !arguments->body) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        if (streams(exchange)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        *arguments->body = bytes_view(exchange.message.body(exchange.text()));
        publish(arguments->outcome, ucall_status_success_k);
    }

    /** Whether @p exchange's body streams in through pulls, as its endpoint fixed at dispatch, so
     *  any thread holding the request may ask, unlike its loop-written @c body_stage. */
    static bool streams(server_exchange_t const& exchange) noexcept {
        return exchange.endpoint && exchange.endpoint->body_delivery == ucall_body_delivery_streamed_k;
    }

    /** Locates a buffered request's multipart parts once, from its own bytes. */
    static void locate_parts(server_exchange_t& exchange) noexcept {
        if (exchange.parts_state != parts_state_t::unlocated_k) return;
        exchange.parts.clear();
        auto const text = exchange.text();
        auto const body = exchange.message.body(text);
        bool const located = !streams(exchange) &&
                             http::split_multipart<http_t>(exchange.message.header(text, "content-type"), body,
                                                           static_cast<std::uint64_t>(body.data() - text.data()),
                                                           exchange.parts);
        exchange.parts_state = located ? parts_state_t::located_k : parts_state_t::malformed_k;
    }
    static std::size_t server_request_parts_count(ucall_server_t, ucall_received_http_request_t request) noexcept {
        if (!request) return 0;
        auto& exchange = *static_cast<server_exchange_t*>(request);
        locate_parts(exchange);
        return exchange.parts_state == parts_state_t::located_k ? exchange.parts.size() : 0;
    }
    static void server_request_part(ucall_server_request_part_t* arguments) noexcept {
        for (ucall_bytes_view_t* output : {arguments->name, arguments->content_type, arguments->data})
            if (output) *output = {};
        if (!arguments->request || !arguments->name || !arguments->content_type || !arguments->data) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        locate_parts(exchange);
        if (exchange.parts_state != parts_state_t::located_k) {
            publish(arguments->outcome, ucall_status_malformed_k);
            return;
        }
        if (arguments->index >= exchange.parts.size()) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto const& located = exchange.parts[arguments->index];
        auto const part = exchange.text().substr(located.offset, located.length);
        // A part without headers opens with the CRLF that ends its empty header block.
        std::size_t const blank = part.substr(0, 2) == "\r\n" ? 0 : http_t::find(part, "\r\n\r\n");
        if (blank == std::string_view::npos) {
            publish(arguments->outcome, ucall_status_malformed_k);
            return;
        }
        auto const block = part.substr(0, blank);
        *arguments->name = bytes_view(
            http::header_parameter<http_t>(http::part_header<http_t>(block, "content-disposition"), "name"));
        *arguments->content_type = bytes_view(http::part_header<http_t>(block, "content-type"));
        *arguments->data = bytes_view(part.substr(blank ? blank + 4 : 2));
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void server_request_body_chunk(ucall_server_request_body_chunk_t* arguments) noexcept {
        if (arguments->data) *arguments->data = {};
        if (!arguments->request || !arguments->data) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        if (!streams(exchange)) {
            // The whole body once, then the end; `pulled_view` remembers that it was pulled.
            if (!exchange.pulled_view) *arguments->data = bytes_view(exchange.message.body(exchange.text()));
            exchange.pulled_view = arguments->data;
            publish(arguments->outcome, ucall_status_success_k);
            return;
        }
        exchange.pulled_view = arguments->data;
        exchange.pull_outcome = arguments->outcome;
        publish(arguments->outcome, ucall_status_deferred_k);
        // Only the loop touches the chunks, so a pull on the polling thread can finish at once.
        if (exchange.event_loop->polled_by_this_thread()) {
            auto requested = atomic_ref<std::uint32_t> {exchange.shared.pull_requested};
            if (!exchange.body_chunk.empty() || exchange.body_stage == body_stage_t::ended_k) {
                requested.store(pull_waiting_k, std::memory_order_relaxed);
                return serving_t::finish_pull(exchange, ucall_status_success_k);
            }
            // Nothing arrives until this thread polls again, so the pull keeps no outcome or view.
            exchange.pull_outcome = nullptr;
            exchange.pulled_view = nullptr;
            requested.store(pull_more_k, std::memory_order_relaxed);
            if (auto* connection = exchange.connection) serving_t::mark_ready(*exchange.event_loop, *connection);
            return publish(arguments->outcome, ucall_status_would_block_k);
        }
        atomic_ref<std::uint32_t> {exchange.shared.pull_requested}.store(pull_waiting_k, std::memory_order_release);
        // The loop reads on and finishes the pull as bytes arrive.
        replies_t::list_replied(exchange);
    }
    static void server_reply_content(ucall_server_reply_content_t* arguments) noexcept {
        if (!arguments->request || !http_t::valid_view(arguments->body) ||
            (arguments->headers_count && !arguments->headers)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        ucall_reply_part_t part {};
        part.data.bytes = arguments->body;
        publish(arguments->outcome, replies_t::reply(*static_cast<server_exchange_t*>(arguments->request), nullptr,
                                                     arguments->http_status ? arguments->http_status : 200,
                                                     {arguments->headers, arguments->headers_count}, {&part, 1}));
    }
    static void server_reply_error(ucall_server_reply_error_t* arguments) noexcept {
        if (!arguments->request || !http_t::valid_view(arguments->message) || arguments->http_status < 400) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        ucall_bytes_view_t const header = bytes_view("content-type: text/plain");
        ucall_reply_part_t part {};
        part.data.bytes = arguments->message;
        publish(arguments->outcome, replies_t::reply(*static_cast<server_exchange_t*>(arguments->request), nullptr,
                                                     arguments->http_status, {&header, 1}, {&part, 1}));
    }
    static void server_reply_vectored(ucall_server_reply_vectored_t* arguments) noexcept {
        if (!arguments->request || (arguments->headers_count && !arguments->headers) ||
            (arguments->parts_count && !arguments->parts)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        // A deferred outcome was published before the loop could see the reply, which owns it now.
        ucall_status_t const status = replies_t::reply(
            *static_cast<server_exchange_t*>(arguments->request), arguments->outcome,
            arguments->http_status ? arguments->http_status : 200, {arguments->headers, arguments->headers_count},
            {arguments->parts, arguments->parts_count});
        if (status != ucall_status_deferred_k) publish(arguments->outcome, status);
    }
    static void server_reply_begin(ucall_server_reply_begin_t* arguments) noexcept {
        if (!arguments->request || (arguments->headers_count && !arguments->headers)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        publish(arguments->outcome, replies_t::begin_reply(*static_cast<server_exchange_t*>(arguments->request),
                                                           arguments->http_status ? arguments->http_status : 200,
                                                           {arguments->headers, arguments->headers_count}));
    }
    static void server_reply_append(ucall_server_reply_append_t* arguments) noexcept {
        if (!arguments->request || (arguments->parts_count && !arguments->parts)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        publish(arguments->outcome, replies_t::append_reply_parts(*static_cast<server_exchange_t*>(arguments->request),
                                                                  {arguments->parts, arguments->parts_count}));
    }
    static void server_reply_end(ucall_server_reply_end_t* arguments) noexcept {
        if (!arguments->request) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        ucall_status_t const status = replies_t::end_reply(*static_cast<server_exchange_t*>(arguments->request),
                                                           arguments->outcome);
        if (status != ucall_status_deferred_k) publish(arguments->outcome, status);
    }

    inline static server_api_t const server_api_k {&server_free,
                                                   &server_stop,
                                                   &server_take_call,
                                                   &server_take_calls,
                                                   &server_event_loop_statistics,
                                                   &server_take_batch,
                                                   &server_take_batches,
                                                   &server_batch_endpoint_statistics,
                                                   &server_add_http_endpoint,
                                                   &server_request_verb,
                                                   &server_request_path,
                                                   &server_request_path_segments_count,
                                                   &server_request_path_segment,
                                                   &server_request_path_parameter,
                                                   &server_request_query_parameter,
                                                   &server_request_header,
                                                   &server_request_fields_count,
                                                   &server_request_field,
                                                   &server_request_query,
                                                   &server_request_peer,
                                                   &server_request_body,
                                                   &server_reply_content,
                                                   &server_reply_error,
                                                   &server_add_http_batch_endpoint,
                                                   &server_reply_vectored,
                                                   &server_reply_begin,
                                                   &server_reply_append,
                                                   &server_reply_end,
                                                   &server_request_body_chunk,
                                                   &server_request_parts_count,
                                                   &server_request_part,
                                                   &bind_client};
};

} // namespace unum::ucall::network
