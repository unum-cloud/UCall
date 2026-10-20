/**
 *  @file include/ucall/network.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Client and server composites over an I/O engine, string kernels, and atomic references.
 */
#pragma once

#include <cstdio>

#include <atomic> // `std::atomic_ref::wait`
#include <bit>    // `std::bit_ceil`

#if defined(__linux__)
#include <dirent.h>
#endif

#include "ucall/capabilities.hpp"
#include "ucall/http.hpp"
#include "ucall/io.hpp"
#include "ucall/routes.hpp"
#include "ucall/tunnel.hpp"
#include "ucall/curve25519.hpp"

namespace unum::ucall {

template <typename engine_type_, cpu_class_t cpu_class_, typename allocator_type_ = st::default_allocator<byte_t>>
struct network_variant : http<cpu_traits<cpu_class_>::stringzilla_capabilities_k> {
    static constexpr sz_capability_t capabilities_k = cpu_traits<cpu_class_>::stringzilla_capabilities_k;
    using http_t = http<capabilities_k>;
    using allocator_t = allocator_type_;
    using engine_t = typename engine_type_::template rebind_allocator<allocator_t>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    template <typename value_type_>
    using vector = st::basic_vector<value_type_, rebound_allocator<value_type_>>;
    template <typename value_type_>
    using owner = allocated_ptr<value_type_, allocator_t>;
    template <typename value_type_>
    using atomic_ref = typename cpu_traits<cpu_class_>::template atomic_ref<value_type_>;
    using http_message_t = typename http_t::http_message_t;
    using http_t::append_text;
    using http_t::c_view;
    using http_t::drop_bytes;
    using http_t::equal;
    using http_t::find;
    using http_t::http_decode_chunks;
    using http_t::http_has_token;
    using http_t::http_parse;
    using http_t::http_token;
    using http_t::http_value;
    using http_t::http_verb;
    using http_t::http_verb_name;
    using http_t::lowercase_ascii;
    using http_t::text_view;
    using http_t::trim_http;
    using http_t::valid_view;
    enum class connection_role_t { client_k, server_k };
    enum class connection_stage_t {
        idle_k,
        connecting_k,
        handshake_k,
        receiving_k,
        transmitting_k,
        received_k,
        sent_k,
        closing_k,
        closed_k
    };

    enum connection_flags_t : std::uint8_t {
        connection_none_k = 0,
        connection_authorized_k = 1,
        connection_pending_k = 2,
        connection_peer_closed_k = 4,
        connection_ready_k = 8
    };
    struct server_t;
    struct client_t;
    struct loop_t;
    struct binding_t;
    struct client_peer_t;
    struct endpoint_t;
    struct request_t;
    inline static thread_local loop_t* polling_loop {};

    /** Set in a batch queue's tail by event loops to wake the drain without a deposit. */
    static constexpr std::uint64_t batch_signal_k = ucall_server_handle_t::batch_signal_k;

    /** Drives accepted and dialed sockets through partial handshakes, records, and writes. */
    struct connection_t {
        explicit connection_t(allocator_t const& allocator = {}) noexcept
            : input(rebound_allocator<byte_t> {allocator}), encrypted(rebound_allocator<byte_t> {allocator}),
              output(rebound_allocator<byte_t> {allocator}), received(rebound_allocator<byte_t> {allocator}),
              record(rebound_allocator<byte_t> {allocator}) {}
        connection_t(connection_t const&) = delete;
        connection_t& operator=(connection_t const&) = delete;
        connection_t(connection_t&&) = delete;
        connection_t& operator=(connection_t&&) = delete;

        io_request_t request {};
        descriptor_t descriptor {-1};
        connection_role_t role {connection_role_t::server_k};
        connection_stage_t stage {connection_stage_t::idle_k};
        ucall_status_t status {ucall_status_success_k};
        std::uint64_t deadline {};
        secure_tunnel<capabilities_k> tunnel {};
        vector<byte_t> input {}, encrypted {}, output {};
        http_message_t message {};
        ucall_verb_t verb {ucall_verb_get_k};
        ucall_peer_authorizer_t authorizer {};
        void* authorizer_context {};
        connection_flags_t flags {connection_none_k};
        vector<byte_t> received {}, record {};
        byte_t* sending {};
        std::size_t sending_length {}, sending_offset {}, output_offset {}, payload_length {};
        binding_t* binding {};
        client_peer_t* peer {};
        endpoint_t* endpoint {};
        request_t* exchange {};
        connection_t* next {}; // Links the loop's idle list or its ready queue, never both.

        ucall_status_t configure(secure_tunnel_config_t const& config) noexcept {
            request = {};
            message = {};
            input.clear();
            encrypted.clear();
            sending = nullptr;
            sending_length = sending_offset = output_offset = payload_length = 0;
            deadline = 0;
            flags = connection_none_k;
            auto fault = tunnel.make(config);
            if (fault != secure_tunnel_fault_t::none_k) return ucall_status_handshake_failed_k;
            auto page = page_size();
            if (page <= 0) return ucall_status_io_k;
            if (st::failed(received.resize(static_cast<std::size_t>(page))) ||
                st::failed(record.resize(tunnel.encrypts() ? tunnel.geometry().record_size() : 0)))
                return ucall_status_out_of_memory_k;
            request.context = this;
            flags = config.mode == secure_tunnel_mode_t::plain_k ? connection_authorized_k : connection_none_k;
            return ucall_status_success_k;
        }
        io_request_t* advance(io_completion_t const* completion = nullptr) noexcept {
            if (completion) {
                flags = static_cast<connection_flags_t>(flags & ~connection_pending_k);
                auto result = completion->result;
                if (request.operation == io_operation_t::close_k) {
                    descriptor = -1;
                    stage = connection_stage_t::closed_k;
                    return nullptr;
                }
                if (result < 0)
                    fail(result == -ETIMEDOUT                        ? ucall_status_timeout_k
                         : stage == connection_stage_t::connecting_k ? ucall_status_connection_failed_k
                                                                     : ucall_status_io_k);
                else if (request.operation == io_operation_t::connect_k) stage = connection_stage_t::handshake_k;
                else if (request.operation == io_operation_t::send_k) {
                    if (!result) fail(ucall_status_connection_closed_k);
                    else sending_offset += static_cast<std::size_t>(result);
                }
                else if (request.operation == io_operation_t::receive_k) {
                    if (!result) {
                        flags = static_cast<connection_flags_t>(flags | connection_peer_closed_k);
                        if (!tunnel.encrypts() && role == connection_role_t::client_k && message.headers_length &&
                            message.framing == http_framing_t::until_close_k) {
                            message.body_length = input.size() - message.headers_length;
                            message.wire_length = input.size();
                            stage = connection_stage_t::received_k;
                        }
                        else fail(ucall_status_connection_closed_k);
                    }
                    else {
                        auto& destination = tunnel.encrypts() ? encrypted : input;
                        auto limit = std::numeric_limits<std::size_t>::max();
                        if (static_cast<std::size_t>(result) > limit - destination.size())
                            fail(ucall_status_overflow_k);
                        else if (!append_text(destination, {reinterpret_cast<char const*>(
                                                                completion->data ? completion->data : received.data()),
                                                            static_cast<std::size_t>(result)}))
                            fail(ucall_status_out_of_memory_k);
                    }
                }
            }
            auto emit = [&](io_operation_t operation, byte_t* data, std::size_t length) -> io_request_t* {
                request = {operation, descriptor, data, length, operation == io_operation_t::close_k ? 0 : deadline,
                           this};
                return &request;
            };
            for (;;) {
                if (stage == connection_stage_t::closing_k) {
                    if (descriptor < 0) {
                        stage = connection_stage_t::closed_k;
                        return nullptr;
                    }
                    return emit(io_operation_t::close_k, nullptr, 0);
                }
                if (stage == connection_stage_t::closed_k || stage == connection_stage_t::idle_k ||
                    stage == connection_stage_t::received_k || stage == connection_stage_t::sent_k)
                    return nullptr;
                if (stage == connection_stage_t::connecting_k) return &request;
                if (sending && sending_offset < sending_length)
                    return emit(io_operation_t::send_k, sending + sending_offset, sending_length - sending_offset);
                if (sending) {
                    sending = nullptr;
                    if (stage == connection_stage_t::transmitting_k) output_offset += payload_length;
                }
                if (stage == connection_stage_t::handshake_k) {
                    auto step = tunnel.advance({encrypted.data(), encrypted.data() + encrypted.size()});
                    drop_bytes(encrypted, step.consumed);
                    if (step.state == secure_tunnel_state_t::broken_k ||
                        step.state == secure_tunnel_state_t::closed_k) {
                        fail(ucall_status_handshake_failed_k);
                        continue;
                    }
                    if (step.outbound.size()) {
                        if (step.outbound.size() > record.size() && st::failed(record.resize(step.outbound.size()))) {
                            fail(ucall_status_overflow_k);
                            continue;
                        }
                        std::memcpy(record.data(), step.outbound.data(), step.outbound.size());
                        sending = record.data();
                        sending_length = step.outbound.size();
                        sending_offset = 0;
                        continue;
                    }
                    if (step.state != secure_tunnel_state_t::ready_k)
                        return emit(io_operation_t::receive_k, received.data(), received.size());
                    if (!(flags & connection_authorized_k)) {
                        ucall_noise_key_t key {};
                        if (!tunnel.peer_key(std::as_writable_bytes(std::span {key}).data())) {
                            fail(ucall_status_handshake_failed_k);
                            continue;
                        }
                        if (authorizer && !authorizer(&key, authorizer_context)) {
                            fail(ucall_status_peer_rejected_k);
                            continue;
                        }
                        flags = static_cast<connection_flags_t>(flags | connection_authorized_k);
                    }
                    stage = role == connection_role_t::client_k ? connection_stage_t::transmitting_k
                                                                : connection_stage_t::receiving_k;
                }
                if (stage == connection_stage_t::transmitting_k) {
                    if (output_offset == output.size()) {
                        if (role == connection_role_t::server_k) {
                            stage = connection_stage_t::sent_k;
                            return nullptr;
                        }
                        receive();
                        continue;
                    }
                    sending_offset = 0;
                    payload_length = output.size() - output_offset;
                    if (tunnel.encrypts()) {
                        auto window = tunnel.payload_window({record.data(), record.data() + record.size()});
                        payload_length = std::min(payload_length, window.size());
                        if (!payload_length) {
                            fail(ucall_status_handshake_failed_k);
                            continue;
                        }
                        std::memcpy(window.data(), output.data() + output_offset, payload_length);
                        auto sealed = tunnel.seal({record.data(), record.data() + record.size()}, payload_length);
                        if (!sealed.size()) {
                            fail(ucall_status_handshake_failed_k);
                            continue;
                        }
                        sending = record.data();
                        sending_length = sealed.size();
                    }
                    else {
                        sending = output.data() + output_offset;
                        sending_length = payload_length;
                    }
                    continue;
                }
                if (stage == connection_stage_t::receiving_k) {
                    while (tunnel.encrypts() && encrypted.size() &&
                           !tunnel.bytes_until_boundary({encrypted.data(), encrypted.data() + encrypted.size()})) {
                        auto opened = tunnel.open({encrypted.data(), encrypted.data() + encrypted.size()});
                        if (!opened.consumed) {
                            fail(ucall_status_handshake_failed_k);
                            break;
                        }
                        if (opened.payload.size() > std::numeric_limits<std::size_t>::max() - input.size()) {
                            fail(ucall_status_overflow_k);
                            break;
                        }
                        if (!append_text(input, text_view(opened.payload))) {
                            fail(ucall_status_out_of_memory_k);
                            break;
                        }
                        drop_bytes(encrypted, opened.consumed);
                        if (opened.kind == secure_tunnel_record_t::close_k)
                            flags = static_cast<connection_flags_t>(flags | connection_peer_closed_k);
                    }
                    if (stage == connection_stage_t::closing_k) continue;
                    auto http_role = role == connection_role_t::server_k ? http_role_t::request_k
                                     : verb == ucall_verb_head_k         ? http_role_t::head_response_k
                                                                         : http_role_t::response_k;
                    auto parsed = http_parse({input.data(), input.data() + input.size()}, message, http_role);
                    if (parsed == http_parse_t::complete_k) {
                        if (role == connection_role_t::client_k && message.status < 200) {
                            if (message.status == 101) {
                                fail(ucall_status_unsupported_k);
                                continue;
                            }
                            drop_bytes(input, message.wire_length);
                            message = {};
                            continue;
                        }
                        http_decode_chunks({input.data(), input.data() + input.size()}, message);
                        stage = connection_stage_t::received_k;
                        return nullptr;
                    }
                    if (parsed != http_parse_t::incomplete_k) {
                        fail(parsed == http_parse_t::overflow_k      ? ucall_status_overflow_k
                             : parsed == http_parse_t::unsupported_k ? ucall_status_unsupported_k
                                                                     : ucall_status_malformed_k);
                        continue;
                    }
                    if (flags & connection_peer_closed_k) {
                        if (role == connection_role_t::client_k && message.headers_length &&
                            message.framing == http_framing_t::until_close_k) {
                            message.body_length = input.size() - message.headers_length;
                            message.wire_length = input.size();
                            stage = connection_stage_t::received_k;
                            return nullptr;
                        }
                        fail(ucall_status_connection_closed_k);
                        continue;
                    }
                    return emit(io_operation_t::receive_k, received.data(), received.size());
                }
            }
        }
        void fail(ucall_status_t error) noexcept {
            status = error;
            stage = connection_stage_t::closing_k;
        }
        void transmit() noexcept {
            stage = connection_stage_t::transmitting_k;
            sending = nullptr;
            output_offset = 0;
        }
        void receive() noexcept {
            stage = connection_stage_t::receiving_k;
            message = {};
        }
        std::string_view text() const noexcept { return http_t::text_view(input); }
    };

    struct endpoint_t {
        explicit endpoint_t(allocator_t const& allocator = {}) noexcept
            : storage(rebound_allocator<char> {allocator}),
              pending(rebound_allocator<ucall_received_http_request_t> {allocator}) {}
        endpoint_t(endpoint_t const&) = delete;
        endpoint_t& operator=(endpoint_t const&) = delete;
        endpoint_t(endpoint_t&&) = delete;
        endpoint_t& operator=(endpoint_t&&) = delete;

        vector<char> storage {};
        std::string_view path {};
        ucall_verb_t verb {};
        ucall_received_http_request_callback_t callback {};
        ucall_received_batch_http_request_callback_t batch_callback {};
        std::size_t min_batch_size {}, max_batch_size {}, batch_latency {};
        vector<ucall_received_http_request_t> pending {}; // Owned by the drain, reserved to `max_batch_size`.
        void* context {};
        endpoint_t* next {};
    };
    enum request_state_t : std::uint32_t { claimed_k = 1, ready_k = 2, detached_k = 4 };
    struct request_t : ucall_received_http_request_handle_t {
        explicit request_t(allocator_t const& allocator = {}) noexcept
            : input(rebound_allocator<byte_t> {allocator}), output(rebound_allocator<byte_t> {allocator}) {}
        request_t(request_t const&) = delete;
        request_t& operator=(request_t const&) = delete;
        request_t(request_t&&) = delete;
        request_t& operator=(request_t&&) = delete;

        loop_t* loop {};
        connection_t* connection {};
        endpoint_t* endpoint {};
        request_t* next {};         // Links every request the loop owns, until the loop is freed.
        request_t* replied_next {}; // Links the loop's replied list, then its free list once recycled.
        http_message_t message {};
        vector<byte_t> input {}, output {};
        std::uint32_t state {};
        std::uint64_t deposited {};
        std::string_view text() const noexcept { return http_t::text_view(input); }
    };

    /** Batch requests from every event loop on their way to the one draining thread. */
    struct batch_queue_t {
        explicit batch_queue_t(allocator_t const& allocator = {}) noexcept
            : slots(rebound_allocator<request_t*> {allocator}) {}
        batch_queue_t(batch_queue_t const&) = delete;
        batch_queue_t& operator=(batch_queue_t const&) = delete;
        batch_queue_t(batch_queue_t&&) = delete;
        batch_queue_t& operator=(batch_queue_t&&) = delete;

        vector<request_t*> slots {}; // A power of two above the connection budget plus one per loop.
        std::uint64_t tail {};       // Event loops `fetch_add`, the drain waits on it.
        std::uint64_t head {};       // Written by the drain only.
    };
    struct binding_t {
        explicit binding_t(allocator_t const& allocator = {}) noexcept
            : address(rebound_allocator<char> {allocator}), device(rebound_allocator<char> {allocator}) {}
        binding_t(binding_t const&) = delete;
        binding_t& operator=(binding_t const&) = delete;
        binding_t(binding_t&&) = delete;
        binding_t& operator=(binding_t&&) = delete;

        ucall_network_interface_t config {};
        vector<char> address {}, device {};
        byte_t public_key[32] {};
        ucall_noise_key_t private_key {};
        std::size_t active {};
    };
    using wake_t = wake_channel_t;
    struct listener_t {
        listener_t() noexcept = default;
        listener_t(listener_t const&) = delete;
        listener_t& operator=(listener_t const&) = delete;
        listener_t(listener_t&&) = delete;
        listener_t& operator=(listener_t&&) = delete;
        io_request_t request {};
        binding_t* binding {};
        loop_t* loop {};
        enum class stage_t { idle_k, pending_k };
        stage_t stage {stage_t::idle_k};
        descriptor_t descriptor {-1};
    };
    enum class loop_stage_t { unopened_k, ready_k, quiesced_k };
    struct loop_t {
        allocator_t allocator;
        explicit loop_t(allocator_t const& allocator = {}) noexcept
            : allocator(allocator), engine(allocator), completions(rebound_allocator<io_completion_t> {allocator}),
              connections(rebound_allocator<owner<connection_t>> {allocator}) {}
        loop_t(loop_t const&) = delete;
        loop_t& operator=(loop_t const&) = delete;
        loop_t(loop_t&&) = delete;
        loop_t& operator=(loop_t&&) = delete;

        engine_t engine {};
        wake_t wake {};
        vector<io_completion_t> completions {};
        server_t* server {};
        std::uint32_t wake_pending {};
        loop_stage_t stage {loop_stage_t::unopened_k};
        vector<owner<connection_t>> connections {};
        span<listener_t> listeners {};
        connection_t* idle {};
        connection_t* ready {};
        request_t* requests {};
        request_t* free_requests {};
        request_t* replied {}; // Pushed from any replying thread, taken whole by the loop.
        ucall_status_t setup_status {ucall_status_success_k};
        void notify() noexcept {
            if (polling_loop == this) return;
            if (!atomic_ref<std::uint32_t> {wake_pending}.exchange(1, std::memory_order_release)) wake.notify();
        }
        ~loop_t() noexcept {
            engine.stop();
            if (wake.descriptors[0] < 0 && wake.request.descriptor >= 0) engine.close_socket(wake.request.descriptor);
            for (auto& connection : connections)
                if (connection && connection->descriptor >= 0 &&
                    !((connection->flags & connection_pending_k) &&
                      connection->request.operation == io_operation_t::close_k && connection->request.descriptor < 0))
                    engine.close_socket(connection->descriptor);
            while (requests) {
                auto* next = requests->next;
                allocator_delete<request_t, allocator_t> {allocator}(requests);
                requests = next;
            }
            for (auto& listener : listeners) {
                if (listener.request.descriptor >= 0) {
                    if (listener.descriptor >= 0) socket_close(listener.descriptor);
                    else engine.close_socket(listener.request.descriptor);
                }
                std::destroy_at(&listener);
            }
            if (!listeners.empty())
                rebound_allocator<listener_t> {allocator}.deallocate(listeners.data(), listeners.size());
        }
    };
    struct server_t : ucall_server_handle_t {
        allocator_t allocator;
        explicit server_t(allocator_t const& allocator = {}) noexcept
            : allocator(allocator), resolved(rebound_allocator<ucall_network_interface_t> {allocator}),
              loops(rebound_allocator<owner<loop_t>> {allocator}), routes(allocator),
              owned_wakeups(rebound_allocator<wake_t*> {allocator}), batches(allocator) {}
        server_t(server_t const&) = delete;
        server_t& operator=(server_t const&) = delete;
        server_t(server_t&&) = delete;
        server_t& operator=(server_t&&) = delete;

        ucall_status_t failure {ucall_status_success_k};
        ucall_server_config_t config {};
        span<binding_t> bindings {};
        vector<ucall_network_interface_t> resolved {};
        vector<owner<loop_t>> loops {};
        route_trie<http_t, allocator_t> routes {};
        vector<wake_t*> owned_wakeups;
        endpoint_t* endpoints {};
        batch_queue_t batches;
        std::uint64_t batch_deadline {}; // The drain's earliest pending expiry, which event loops poll toward.
        std::size_t connections_budget {};
        std::uint32_t serving {};
        ~server_t() noexcept {
            loops.clear();
            for (auto& binding : bindings) {
                secure_tunnel_crypto<capabilities_k>::secure_zero(binding.private_key);
                std::destroy_at(&binding);
            }
            if (!bindings.empty())
                rebound_allocator<binding_t> {allocator}.deallocate(bindings.data(), bindings.size());
            while (endpoints) {
                auto* next = endpoints->next;
                allocator_delete<endpoint_t, allocator_t> {allocator}(endpoints);
                endpoints = next;
            }
        }
    };
    using response_t = received_response<allocator_t>;

    static secure_tunnel_mode_t tunnel_mode(ucall_security_mode_t mode) noexcept {
        return static_cast<secure_tunnel_mode_t>(mode);
    }
    static bool security_valid(ucall_security_mode_t mode) noexcept {
        return mode >= ucall_security_mode_none_k && mode <= ucall_security_mode_noise_kk_k;
    }
    static secure_tunnel_config_t tunnel_config(ucall_security_mode_t mode, secure_tunnel_role_t role,
                                                ucall_noise_key_t const* private_key, byte_t const* public_key,
                                                ucall_noise_key_t const* peer_key) noexcept {
        secure_tunnel_config_t config {};
        config.mode = tunnel_mode(mode);
        config.role = role;
        if (private_key) config.local_private = std::as_bytes(std::span {*private_key});
        if (public_key) config.local_public = {public_key, public_key + 32};
        if (peer_key) config.remote_public = std::as_bytes(std::span {*peer_key});
        return config;
    }
    static bool copy_text(vector<char>& destination, std::string_view text) noexcept {
        destination.clear();
        return append_text(destination, text) && append_text(destination, std::string_view {"\0", 1});
    }
    static bool split_address(std::string_view address, vector<char>& host, vector<char>& service) noexcept {
        auto colon = http_t::rfind(address, ':');
        if (colon == std::string_view::npos || !colon || colon + 1 == address.size()) return false;
        auto name = address.substr(0, colon), port = address.substr(colon + 1);
        if (name.front() == '[' && name.back() == ']') {
            name.remove_prefix(1);
            name.remove_suffix(1);
        }
        else if (find(name, ':') != std::string_view::npos) return false;
        unsigned number = 0;
        auto parsed = std::from_chars(port.data(), port.data() + port.size(), number);
        if (parsed.ec != std::errc {} || parsed.ptr != port.data() + port.size() || number > 65535 || name.empty() ||
            find(name, '\0') != std::string_view::npos)
            return false;
        return copy_text(host, name) && copy_text(service, port);
    }
    static std::size_t interface_loops(char const* device) noexcept {
        if (!device) return 1;
#if UCALL_OS_LINUX_
        char path[256];
        if (std::strchr(device, '/') ||
            std::snprintf(path, sizeof(path), "/sys/class/net/%s/queues", device) >= static_cast<int>(sizeof(path)))
            return 0;
        DIR* directory = opendir(path);
        if (!directory) return 0;
        std::size_t queues = 0;
        while (auto* entry = readdir(directory))
            if (std::strncmp(entry->d_name, "rx-", 3) == 0) ++queues;
        closedir(directory);
        return queues ? queues : 1;
#else
        return 0;
#endif // UCALL_OS_LINUX_
    }
    static ucall_status_t bind_listener(binding_t& binding, listener_t& listener) noexcept {
        vector<char> host {rebound_allocator<char> {binding.address.get_allocator()}}, service {host.get_allocator()};
        if (!sockets_start()) return ucall_status_io_k;
        if (!split_address(binding.config.address, host, service)) return ucall_status_invalid_argument_k;
        addrinfo hints {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        addrinfo* addresses = nullptr;
        if (getaddrinfo(host.data(), service.data(), &hints, &addresses) != 0) return ucall_status_connection_failed_k;
        descriptor_t descriptor = -1;
        for (auto* address = addresses; address; address = address->ai_next) {
            descriptor = socket_open(address->ai_family);
            if (descriptor < 0) continue;
            int enabled = 1;
#if UCALL_OS_WINDOWS_
            bool configured = socket_option(descriptor, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &enabled, sizeof(enabled)) ==
                              0;
#else
            bool configured = socket_option(descriptor, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) == 0;
#endif
#if UCALL_OS_LINUX_
            if (binding.config.device_name)
                configured = configured &&
                             socket_option(descriptor, SOL_SOCKET, SO_BINDTODEVICE, binding.config.device_name,
                                           static_cast<socket_length_t>(std::strlen(binding.config.device_name) + 1)) ==
                                 0;
#endif // UCALL_OS_LINUX_
            if (configured && bind(descriptor, address->ai_addr, address->ai_addrlen) == 0 &&
                listen(descriptor, static_cast<int>(std::min<std::size_t>(binding.config.max_concurrent_connections,
                                                                          std::numeric_limits<int>::max()))) == 0)
                break;
            socket_close(descriptor);
            descriptor = -1;
        }
        freeaddrinfo(addresses);
        if (descriptor < 0) return ucall_status_connection_failed_k;
        sockaddr_storage bound {};
        socket_length_t length = sizeof(bound);
        char numeric_host[NI_MAXHOST], numeric_service[NI_MAXSERV], text[NI_MAXHOST + NI_MAXSERV + 4];
        if (getsockname(descriptor, reinterpret_cast<sockaddr*>(&bound), &length) != 0 ||
            getnameinfo(reinterpret_cast<sockaddr*>(&bound), length, numeric_host, sizeof(numeric_host),
                        numeric_service, sizeof(numeric_service), NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
            socket_close(descriptor);
            return ucall_status_io_k;
        }
        std::snprintf(text, sizeof(text), bound.ss_family == AF_INET6 ? "[%s]:%s" : "%s:%s", numeric_host,
                      numeric_service);
        if (!copy_text(binding.address, text)) {
            socket_close(descriptor);
            return ucall_status_out_of_memory_k;
        }
        binding.config.address = binding.address.data();
        listener.binding = &binding;
        listener.request = {io_operation_t::accept_k, descriptor, nullptr, 0, 0, &listener};
        return ucall_status_success_k;
    }

    /** The status line of every named @c ucall_http_status_t, with its RFC 9110 reason phrase. */
    static std::string_view status_line(unsigned status) noexcept {
        switch (status) {
        case ucall_http_status_ok_k: return "HTTP/1.1 200 OK\r\n";
        case ucall_http_status_created_k: return "HTTP/1.1 201 Created\r\n";
        case ucall_http_status_no_content_k: return "HTTP/1.1 204 No Content\r\n";
        case ucall_http_status_partial_content_k: return "HTTP/1.1 206 Partial Content\r\n";
        case ucall_http_status_moved_permanently_k: return "HTTP/1.1 301 Moved Permanently\r\n";
        case ucall_http_status_found_k: return "HTTP/1.1 302 Found\r\n";
        case ucall_http_status_not_modified_k: return "HTTP/1.1 304 Not Modified\r\n";
        case ucall_http_status_bad_request_k: return "HTTP/1.1 400 Bad Request\r\n";
        case ucall_http_status_unauthorized_k: return "HTTP/1.1 401 Unauthorized\r\n";
        case ucall_http_status_forbidden_k: return "HTTP/1.1 403 Forbidden\r\n";
        case ucall_http_status_not_found_k: return "HTTP/1.1 404 Not Found\r\n";
        case ucall_http_status_method_not_allowed_k: return "HTTP/1.1 405 Method Not Allowed\r\n";
        case ucall_http_status_timeout_k: return "HTTP/1.1 408 Request Timeout\r\n";
        case ucall_http_status_conflict_k: return "HTTP/1.1 409 Conflict\r\n";
        case ucall_http_status_precondition_failed_k: return "HTTP/1.1 412 Precondition Failed\r\n";
        case ucall_http_status_payload_too_large_k: return "HTTP/1.1 413 Content Too Large\r\n";
        case ucall_http_status_too_many_requests_k: return "HTTP/1.1 429 Too Many Requests\r\n";
        case ucall_http_status_internal_error_k: return "HTTP/1.1 500 Internal Server Error\r\n";
        case ucall_http_status_not_implemented_k: return "HTTP/1.1 501 Not Implemented\r\n";
        case ucall_http_status_service_unavailable_k: return "HTTP/1.1 503 Service Unavailable\r\n";
        case ucall_http_status_gateway_timeout_k: return "HTTP/1.1 504 Gateway Timeout\r\n";
        }
        return {};
    }
    template <std::size_t capacity_>
    static std::string_view format_decimal(char (&output)[capacity_], std::size_t value) noexcept {
        auto written = std::to_chars(output, output + capacity_, value);
        return {output, static_cast<std::size_t>(written.ptr - output)};
    }
    static constexpr std::size_t http_date_length_k = sizeof("Sun, 06 Nov 1994 08:49:37 GMT") - 1;

    /** Formats the RFC 9110 IMF-fixdate with Howard Hinnant's civil-from-days arithmetic. */
    static std::string_view format_date(char (&output)[http_date_length_k], std::time_t now) noexcept {
        static constexpr char weekdays_k[] = "ThuFriSatSunMonTueWed",
                              months_k[] = "MarAprMayJunJulAugSepOctNovDecJanFeb";
        auto seconds = static_cast<std::uint64_t>(std::max<std::time_t>(now, 0));
        auto days = seconds / 86400, time = seconds % 86400;
        auto shifted = days + 719468, era = shifted / 146097, day_of_era = shifted % 146097;
        auto year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
        auto day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        auto month_from_march = (5 * day_of_year + 2) / 153;
        auto day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
        auto year = year_of_era + era * 400 + (month_from_march >= 10);
        auto put = [&](std::size_t offset, std::uint64_t value, std::size_t width) {
            for (auto position = offset + width; position != offset; value /= 10)
                output[--position] = static_cast<char>('0' + value % 10);
        };
        std::memcpy(output, weekdays_k + days % 7 * 3, 3);
        std::memcpy(output + 3, ", ", 2);
        put(5, day, 2);
        output[7] = ' ';
        std::memcpy(output + 8, months_k + month_from_march * 3, 3);
        output[11] = ' ';
        put(12, year, 4);
        output[16] = ' ';
        put(17, time / 3600, 2);
        output[19] = ':';
        put(20, time / 60 % 60, 2);
        output[22] = ':';
        put(23, time % 60, 2);
        std::memcpy(output + 25, " GMT", 4);
        return {output, http_date_length_k};
    }

    static ucall_status_t append_headers(vector<byte_t>& output, ucall_bytes_view_t const* headers, std::size_t count,
                                         http_role_t role) noexcept {
        if (count && !headers) return ucall_status_invalid_argument_k;
        for (std::size_t i = 0; i != count; ++i) {
            if (!valid_view(headers[i])) return ucall_status_invalid_argument_k;
            auto line = text_view(headers[i]);
            auto colon = find(line, ':');
            if (colon == std::string_view::npos || !http_token(line.substr(0, colon)) ||
                !http_value(line.substr(colon + 1)))
                return ucall_status_invalid_argument_k;
            auto previous = output.size();
            if (!append_text(output, line.substr(0, colon))) return ucall_status_out_of_memory_k;
            lowercase_ascii(reinterpret_cast<char*>(output.data()) + previous, colon);
            std::string_view name {reinterpret_cast<char const*>(output.data()) + previous, colon};
            if (equal(name, "content-length") || equal(name, "transfer-encoding") ||
                (role == http_role_t::request_k && (equal(name, "host") || equal(name, "user-agent"))) ||
                (role != http_role_t::request_k && (equal(name, "date") || equal(name, "server"))))
                return ucall_status_invalid_argument_k;
            if (!append_text(output, ": ") || !append_text(output, trim_http(line.substr(colon + 1))) ||
                !append_text(output, "\r\n"))
                return ucall_status_out_of_memory_k;
        }
        return ucall_status_success_k;
    }
    static ucall_status_t serialize_reply(request_t& request, unsigned status, ucall_bytes_view_t const* headers,
                                          std::size_t count, std::string_view body) noexcept {
        if (!request.output.empty()) return ucall_status_already_exists_k;
        if (status < 200 || status > 599 || ((status == 204 || status == 304) && !body.empty()))
            return ucall_status_invalid_argument_k;
        static constexpr std::string_view classes_k[] {"Successful", "Redirection", "Client Error", "Server Error"};
        char digits[std::numeric_limits<std::size_t>::digits10 + 1], date[http_date_length_k];
        auto line = status_line(status);
        bool appended = line.empty() ? append_text(request.output, "HTTP/1.1 ") &&
                                           append_text(request.output, format_decimal(digits, status)) &&
                                           append_text(request.output, " ") &&
                                           append_text(request.output, classes_k[status / 100 - 2]) &&
                                           append_text(request.output, "\r\n")
                                     : append_text(request.output, line);
        if (!appended || !append_text(request.output, "server: UCall\r\ndate: ") ||
            !append_text(request.output, format_date(date, std::time(nullptr))) ||
            !append_text(request.output, "\r\n")) {
            request.output.clear();
            return ucall_status_out_of_memory_k;
        }
        auto result = append_headers(request.output, headers, count, http_role_t::response_k);
        if (result != ucall_status_success_k) {
            request.output.clear();
            return result;
        }
        if ((status != 204 && status != 304 &&
             (!append_text(request.output, "content-length: ") ||
              !append_text(request.output, format_decimal(digits, body.size())) ||
              !append_text(request.output, "\r\n"))) ||
            !append_text(request.output, request.message.keep_alive() ? "connection: keep-alive\r\n\r\n"
                                                                      : "connection: close\r\n\r\n") ||
            (request.message.verb != ucall_verb_head_k && !append_text(request.output, body))) {
            request.output.clear();
            return ucall_status_out_of_memory_k;
        }
        return ucall_status_success_k;
    }
    static ucall_status_t reply(request_t& request, unsigned status, ucall_bytes_view_t const* headers,
                                std::size_t count, std::string_view body) noexcept {
        auto state = atomic_ref<std::uint32_t> {request.state};
        auto previous = state.fetch_or(claimed_k, std::memory_order_acq_rel);
        if (previous & claimed_k) return ucall_status_already_exists_k;
        if ((previous & detached_k) ||
            atomic_ref<std::uint32_t> {request.loop->server->stopped}.load(std::memory_order_acquire)) {
            state.fetch_or(detached_k | ready_k, std::memory_order_release);
            push_replied(request);
            return ucall_status_connection_closed_k;
        }
        auto result = serialize_reply(request, status, headers, count, body);
        if (result != ucall_status_success_k) {
            request.output.clear();
            state.fetch_and(~std::uint32_t {claimed_k}, std::memory_order_release);
            return result;
        }
        previous = state.fetch_or(ready_k, std::memory_order_release);
        push_replied(request);
        return previous & detached_k ? ucall_status_connection_closed_k : ucall_status_success_k;
    }

    /** Hands a finished request back to its loop from any thread; only that loop recycles it. */
    static void push_replied(request_t& request) noexcept {
        auto* loop = request.loop;
        request.replied_next = atomic_ref<request_t*> {loop->replied}.exchange(&request, std::memory_order_acq_rel);
        loop->notify();
    }
    static void detach(connection_t& connection) noexcept {
        if (!connection.exchange) return;
        connection.exchange->connection = nullptr;
        atomic_ref<std::uint32_t> {connection.exchange->state}.fetch_or(detached_k, std::memory_order_release);
        connection.exchange = nullptr;
    }
    static void recycle_request(loop_t& loop, request_t& request) noexcept {
        request.input.clear();
        request.output.clear();
        request.replied_next = loop.free_requests;
        loop.free_requests = &request;
    }
    static void mark_ready(loop_t& loop, connection_t& connection) noexcept {
        if (connection.flags & connection_ready_k) return;
        connection.flags = static_cast<connection_flags_t>(connection.flags | connection_ready_k);
        connection.next = loop.ready;
        loop.ready = &connection;
    }
    static bool collect_replies(loop_t& loop) noexcept {
        auto* request = atomic_ref<request_t*> {loop.replied}.exchange(nullptr, std::memory_order_acq_rel);
        if (!request) return false;
        while (request) {
            auto* next = request->replied_next;
            if (auto* connection = request->connection) {
                request->connection = nullptr;
                connection->exchange = nullptr;
                if (atomic_ref<std::uint32_t> {request->state}.load(std::memory_order_acquire) & detached_k)
                    connection->fail(ucall_status_connection_closed_k);
                else if (connection->stage == connection_stage_t::received_k) {
                    std::swap(connection->output, request->output);
                    connection->transmit();
                }
                mark_ready(loop, *connection);
            }
            recycle_request(loop, *request);
            request = next;
        }
        return true;
    }

    /** Answers on the loop itself, recycling the request when no reply was queued. */
    static void refuse(loop_t& loop, connection_t& connection, request_t& request, unsigned status,
                       std::string_view body) noexcept {
        auto result = reply(request, status, nullptr, 0, body);
        if (result == ucall_status_success_k || result == ucall_status_connection_closed_k) return;
        request.connection = nullptr;
        connection.exchange = nullptr;
        recycle_request(loop, request);
        connection.fail(ucall_status_out_of_memory_k);
    }
    static void signal_batches(server_t& server) noexcept {
        if (server.batches.slots.empty()) return;
        atomic_ref<std::uint64_t> {server.batches.tail}.fetch_or(batch_signal_k, std::memory_order_release);
        std::atomic_ref<std::uint64_t> {server.batches.tail}.notify_one();
    }
    static void dispatch(server_t& server, loop_t& loop, connection_t& connection) noexcept {
        auto* request = loop.free_requests;
        if (request) loop.free_requests = request->replied_next;
        else if ((request = allocate_unique<request_t>(loop.allocator, loop.allocator).release())) {
            request->next = loop.requests;
            loop.requests = request;
        }
        if (!request) {
            connection.fail(ucall_status_out_of_memory_k);
            return;
        }
        request->state = 0;
        request->loop = &loop;
        request->connection = &connection;
        request->message = connection.message;
        std::swap(request->input, connection.input);
        connection.input.clear();
        auto wire = request->message.wire_length;
        if (wire < request->input.size() && !append_text(connection.input, text_view(request->input).substr(wire))) {
            std::swap(request->input, connection.input);
            recycle_request(loop, *request);
            connection.fail(ucall_status_out_of_memory_k);
            return;
        }
        if (wire < request->input.size()) request->input.erase(wire, request->input.size() - wire);
        auto path = extract_path_component<http_t>(request->message.target(request->text()));
        auto* endpoint = static_cast<endpoint_t*>(server.routes.match(path, request->message.verb));
        request->endpoint = endpoint;
        connection.exchange = request;
        if (!endpoint) return refuse(loop, connection, *request, 404, "Not found");
        if (endpoint->callback) return endpoint->callback(request, endpoint->context);
        auto& queue = server.batches;
        auto tail = atomic_ref<std::uint64_t> {queue.tail};
        // Requests of closed connections outlive their admission, so this check alone bounds it.
        if ((tail.load(std::memory_order_relaxed) & ~batch_signal_k) -
                atomic_ref<std::uint64_t> {queue.head}.load(std::memory_order_acquire) >=
            server.connections_budget)
            return refuse(loop, connection, *request, 503, "Batch queue full");
        request->deposited = monotonic_ns();
        auto index = tail.fetch_add(1, std::memory_order_relaxed) & ~batch_signal_k;
        atomic_ref<request_t*> {queue.slots[index & (queue.slots.size() - 1)]}.store(request,
                                                                                     std::memory_order_release);
        std::atomic_ref<std::uint64_t> {queue.tail}.notify_one();
    }
    static void release_admission(server_t& server, binding_t& binding) noexcept {
        auto before = atomic_ref<std::size_t> {binding.active}.fetch_sub(1, std::memory_order_relaxed);
        if (before == binding.config.max_concurrent_connections)
            for (auto& loop : server.loops) loop->notify();
    }
    static void advance_connection(server_t& server, loop_t& loop, connection_t& connection, bool stopping) noexcept {
        auto& engine = loop.engine;
        if (connection.stage == connection_stage_t::idle_k) return;
        if (stopping && (connection.flags & connection_pending_k)) {
            if (connection.request.operation != io_operation_t::close_k) engine.cancel(connection.request);
            return;
        }
        if (connection.flags & connection_pending_k) return;
        if (stopping && connection.stage != connection_stage_t::closed_k)
            connection.fail(ucall_status_connection_closed_k);
        for (;;) {
            if (connection.stage == connection_stage_t::received_k) {
                if (connection.exchange) return;
                dispatch(server, loop, connection);
                if (connection.stage == connection_stage_t::received_k) return;
            }
            if (connection.stage == connection_stage_t::sent_k) {
                if (!connection.message.keep_alive() || (connection.flags & connection_peer_closed_k))
                    connection.fail(ucall_status_success_k);
                else {
                    connection.output.clear();
                    connection.endpoint = nullptr;
                    connection.receive();
                }
            }
            auto* next = connection.advance();
            if (next) {
                // A failed submission is retried on the loop's next round rather than this one.
                if (engine.submit(*next))
                    connection.flags = static_cast<connection_flags_t>(connection.flags | connection_pending_k);
                else mark_ready(loop, connection);
                return;
            }
            if (connection.stage == connection_stage_t::closed_k) {
                detach(connection);
                release_admission(server, *connection.binding);
                connection.tunnel.reset();
                connection.input.clear();
                connection.encrypted.clear();
                connection.output.clear();
                connection.sending = nullptr;
                connection.flags = static_cast<connection_flags_t>(connection.flags & ~connection_peer_closed_k);
                connection.endpoint = nullptr;
                connection.stage = connection_stage_t::idle_k;
                connection.next = loop.idle;
                loop.idle = &connection;
                return;
            }
            if (connection.stage != connection_stage_t::received_k) return;
        }
    }
    static ucall_status_t server_progress(server_t& server, loop_t& loop) noexcept {
        auto& engine = loop.engine;
        bool stopping = atomic_ref<std::uint32_t> {server.stopped}.load(std::memory_order_acquire);
        for (auto& listener : loop.listeners) {
            if (stopping) {
                if (listener.stage == listener_t::stage_t::pending_k) { engine.cancel(listener.request); }
                continue;
            }
            if (listener.stage == listener_t::stage_t::pending_k || !loop.idle) continue;
            auto& binding = *listener.binding;
            auto active = atomic_ref<std::size_t> {binding.active};
            auto before = active.fetch_add_if_at_most(1, binding.config.max_concurrent_connections,
                                                      std::memory_order_relaxed);
            if (before >= binding.config.max_concurrent_connections) continue;
            if (engine.submit(listener.request)) listener.stage = listener_t::stage_t::pending_k;
            else active.fetch_sub(1, std::memory_order_relaxed);
        }
        collect_replies(loop);
        if (stopping) {
            for (; loop.ready; loop.ready = loop.ready->next)
                loop.ready->flags = static_cast<connection_flags_t>(loop.ready->flags & ~connection_ready_k);
            for (auto& connection : loop.connections) advance_connection(server, loop, *connection, stopping);
        }
        else do {
                for (auto* connection = std::exchange(loop.ready, nullptr); connection;) {
                    auto& current = *connection;
                    connection = current.next;
                    current.flags = static_cast<connection_flags_t>(current.flags & ~connection_ready_k);
                    advance_connection(server, loop, current, stopping);
                }
            } while (collect_replies(loop));
        auto batch_deadline = atomic_ref<std::uint64_t> {server.batch_deadline};
        auto expiry = batch_deadline.load(std::memory_order_acquire);
        if (stopping ||
            (expiry && monotonic_ns() >= expiry &&
             batch_deadline.compare_exchange_strong(expiry, 0, std::memory_order_acq_rel, std::memory_order_relaxed)))
            signal_batches(server);
        if (stopping) {
            bool busy = false;
            for (auto& listener : loop.listeners) busy |= (listener.stage == listener_t::stage_t::pending_k);
            for (auto& connection : loop.connections) busy |= connection->stage != connection_stage_t::idle_k;
            if (!busy) {
                for (auto& listener : loop.listeners)
                    if (listener.request.descriptor >= 0) {
                        engine.close_socket(listener.request.descriptor);
                        listener.request.descriptor = -1;
                    }
                loop.stage = loop_stage_t::quiesced_k;
            }
        }
        return ucall_status_success_k;
    }
    static void accepted(io_completion_t const& completion) noexcept {
        auto& listener = *static_cast<listener_t*>(completion.request->context);
        auto& loop = *listener.loop;
        auto& server = *loop.server;
        auto& binding = *listener.binding;
        listener.stage = listener_t::stage_t::idle_k;
        if (completion.result < 0) {
            release_admission(server, binding);
            if (completion.result != -ECONNABORTED && completion.result != -ECANCELED) {
                atomic_ref<ucall_status_t> {server.failure}.store(ucall_status_io_k, std::memory_order_release);
                server_stop(&server);
            }
            return;
        }
        auto* chosen = loop.idle;
        if (!chosen || atomic_ref<std::uint32_t> {server.stopped}.load(std::memory_order_acquire)) {
            loop.engine.close_socket(completion.result);
            release_admission(server, binding);
            return;
        }
        loop.idle = chosen->next;
        chosen->descriptor = completion.result;
        chosen->binding = &binding;
        chosen->role = connection_role_t::server_k;
        chosen->stage = connection_stage_t::handshake_k;
        chosen->status = ucall_status_success_k;
        chosen->authorizer = binding.config.peer_authorizer;
        chosen->authorizer_context = binding.config.peer_authorizer_context;
        auto result = chosen->configure(tunnel_config(binding.config.security_mode, secure_tunnel_role_t::responder_k,
                                                      binding.config.noise_private_key, binding.public_key, nullptr));
        if (result != ucall_status_success_k) chosen->fail(result);
        mark_ready(loop, *chosen);
    }
    static void server_init(ucall_server_init_t* arguments, allocator_t const& allocator = {}) noexcept {
        if (!arguments) return;
        if (arguments->server) *arguments->server = nullptr;
        auto* config = arguments->config;
        if (!arguments->outcome || !arguments->server || !config || !config->interfaces || !config->interfaces_count) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        if (config->metrics_address) {
            publish(arguments->outcome, ucall_status_unsupported_k);
            return;
        }
        auto server = allocate_unique<server_t>(allocator, allocator);
        if (!server || st::failed(server->resolved.resize(config->interfaces_count)) || !server->routes.init()) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        rebound_allocator<binding_t> binding_allocator {allocator};
        auto* bindings = binding_allocator.allocate(config->interfaces_count);
        if (!bindings) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        for (std::size_t i = 0; i != config->interfaces_count; ++i) std::construct_at(bindings + i, allocator);
        server->bindings = {bindings, config->interfaces_count};
        std::size_t loops_count = 1;
        for (std::size_t i = 0; i != config->interfaces_count; ++i) {
            auto& binding = server->bindings[i];
            binding.config = config->interfaces[i];
            if (binding.config.noise_private_key) {
                std::memcpy(binding.private_key, *binding.config.noise_private_key, sizeof(binding.private_key));
                binding.config.noise_private_key = &binding.private_key;
            }
            auto& interface = binding.config;
            if (interface.device_name) {
                if (!copy_text(binding.device, interface.device_name)) {
                    publish(arguments->outcome, ucall_status_out_of_memory_k);
                    return;
                }
                interface.device_name = binding.device.data();
            }
            if (!interface.address || !security_valid(interface.security_mode) ||
                (interface.security_mode != ucall_security_mode_none_k && !interface.noise_private_key) ||
                (interface.security_mode == ucall_security_mode_noise_xx_k && !interface.peer_authorizer) ||
                interface.security_mode == ucall_security_mode_noise_kk_k) {
                publish(arguments->outcome, ucall_status_invalid_argument_k);
                return;
            }
#if !UCALL_OS_LINUX_
            if (interface.device_name) {
                publish(arguments->outcome, ucall_status_unsupported_k);
                return;
            }
#endif
            if (!interface.max_concurrent_connections) {
                publish(arguments->outcome, ucall_status_invalid_argument_k);
                return;
            }
            if (!interface.event_loops) interface.event_loops = interface_loops(interface.device_name);
            if (!interface.event_loops) {
                publish(arguments->outcome, ucall_status_invalid_argument_k);
                return;
            }
            if (interface.event_loops > interface.max_concurrent_connections)
                interface.event_loops = interface.max_concurrent_connections;
#if UCALL_OS_WINDOWS_
            if (interface.event_loops > 1) {
                publish(arguments->outcome, ucall_status_unsupported_k);
                return;
            }
#endif
            loops_count = std::max(loops_count, interface.event_loops);
            if (interface.noise_private_key)
                x25519_derive_public(binding.public_key,
                                     std::as_bytes(std::span {*interface.noise_private_key}).data());
        }
        {
            engine_t probe {allocator};
            auto status = probe.open(1, 1);
            if (status != ucall_status_success_k) {
                publish(arguments->outcome, status);
                return;
            }
        }
        if (st::failed(server->loops.resize(loops_count)) || st::failed(server->owned_wakeups.resize(loops_count))) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        for (std::size_t loop_index = 0; loop_index != loops_count; ++loop_index) {
            server->loops[loop_index] = allocate_unique<loop_t>(allocator, allocator);
            if (!server->loops[loop_index]) {
                publish(arguments->outcome, ucall_status_out_of_memory_k);
                return;
            }
            auto& loop = *server->loops[loop_index];
            loop.server = server.get();
            server->owned_wakeups[loop_index] = &loop.wake;
            if (!loop.wake.open()) {
                publish(arguments->outcome, ucall_status_out_of_memory_k);
                return;
            }
            std::size_t connections_count = 0, listeners_count = 0;
            for (auto& binding : server->bindings)
                if (loop_index < binding.config.event_loops) {
                    auto quota = binding.config.max_concurrent_connections / binding.config.event_loops +
                                 (loop_index < binding.config.max_concurrent_connections % binding.config.event_loops);
                    if (quota > std::numeric_limits<std::size_t>::max() - connections_count) {
                        publish(arguments->outcome, ucall_status_overflow_k);
                        return;
                    }
                    connections_count += quota;
                    ++listeners_count;
                }
            if (connections_count > std::numeric_limits<std::size_t>::max() - server->connections_budget) {
                publish(arguments->outcome, ucall_status_overflow_k);
                return;
            }
            server->connections_budget += connections_count;
            if (st::failed(loop.connections.resize(connections_count))) {
                publish(arguments->outcome, ucall_status_out_of_memory_k);
                return;
            }
            rebound_allocator<listener_t> listener_allocator {allocator};
            auto* listeners = listener_allocator.allocate(listeners_count);
            if (!listeners) {
                publish(arguments->outcome, ucall_status_out_of_memory_k);
                return;
            }
            for (std::size_t i = 0; i != listeners_count; ++i) std::construct_at(listeners + i);
            loop.listeners = {listeners, listeners_count};
            for (auto& connection : loop.connections) {
                connection = allocate_unique<connection_t>(allocator, allocator);
                if (!connection) {
                    publish(arguments->outcome, ucall_status_out_of_memory_k);
                    return;
                }
                connection->next = loop.idle;
                loop.idle = connection.get();
            }
            std::size_t listener_index = 0;
            for (auto& binding : server->bindings)
                if (loop_index < binding.config.event_loops) {
                    auto& listener = loop.listeners[listener_index++];
                    listener.loop = &loop;
                    ucall_status_t result;
                    if (!loop_index) result = bind_listener(binding, listener);
#if UCALL_OS_POSIX_
                    else {
                        auto binding_index = static_cast<std::size_t>(&binding - server->bindings.data());
                        auto& first = server->loops[0]->listeners[binding_index];
                        int descriptor = fcntl(static_cast<int>(first.request.descriptor), F_DUPFD_CLOEXEC, 0);
                        result = descriptor >= 0 ? ucall_status_success_k : ucall_status_io_k;
                        listener.binding = &binding;
                        listener.request = {io_operation_t::accept_k, descriptor, nullptr, 0, 0, &listener};
                    }
#else
                    else result = ucall_status_unsupported_k;
#endif
                    if (result != ucall_status_success_k) {
                        publish(arguments->outcome, result);
                        return;
                    }
                    listener.descriptor = listener.request.descriptor;
                }
        }
        server->wakeups = server->owned_wakeups;
        server->batch_tail = &server->batches.tail;
        server->config = *config;
        server->config.cpu_class = static_cast<ucall_cpu_class_t>(cpu_class_);
        for (std::size_t i = 0; i != config->interfaces_count; ++i) server->resolved[i] = server->bindings[i].config;
        server->config.interfaces = server->resolved.data();
        if (arguments->resolved) *arguments->resolved = server->config;
        server->string_capabilities = capabilities_k;
        server->atomic_capabilities = static_cast<std::uint64_t>(cpu_traits<cpu_class_>::forkunion_capabilities_k);
        server->api = &server_api_k;
        *arguments->server = server.release();
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void server_stop(ucall_server_t handle) noexcept {
        if (!handle) return;
        auto& server = *static_cast<server_t*>(handle);
        atomic_ref<std::uint32_t> {server.stopped}.store(1, std::memory_order_release);
        for (auto& loop : server.loops) loop->notify();
        signal_batches(server);
    }
    static ucall_status_t open_loop(loop_t& loop) noexcept {
        if (loop.stage != loop_stage_t::unopened_k) return loop.setup_status;
        auto slots = loop.connections.size() + loop.listeners.size();
        if (slots == std::numeric_limits<std::size_t>::max()) return ucall_status_overflow_k;
        ++slots; // The wakeup occupies one operation slot beside listeners and connections.
        auto status = loop.engine.open(slots, slots);
        if (status != ucall_status_success_k) return status;
        loop.stage = loop_stage_t::ready_k;
        if (st::failed(loop.completions.resize(slots))) return ucall_status_out_of_memory_k;
        auto descriptor = loop.engine.import_socket(loop.wake.descriptors[0]);
        if (descriptor < 0) return ucall_status_io_k;
        loop.wake.descriptors[0] = -1;
        loop.wake.request.descriptor = descriptor;
        if (!loop.engine.submit(loop.wake.request)) return ucall_status_io_k;
        for (auto& listener : loop.listeners) {
            auto imported = loop.engine.import_socket(listener.request.descriptor);
            if (imported < 0) return ucall_status_io_k;
            listener.request.descriptor = imported;
            listener.descriptor = -1;
        }
        return ucall_status_success_k;
    }
    static void advance_completion(engine_t& engine, io_completion_t const& completion) noexcept {
        if (completion.request->operation == io_operation_t::accept_k) accepted(completion);
        else {
            auto& connection = *static_cast<connection_t*>(completion.request->context);
            bool connected = connection.stage == connection_stage_t::connecting_k && completion.result >= 0;
            connection.advance(&completion);
            if (connected && connection.peer && connection.peer->job)
                connection.deadline = connection.peer->job->deadline;
        }
        engine.release(completion);
    }
    static ucall_status_t server_poll(server_t& server, loop_t& loop, io_wait_t wait,
                                      std::uint64_t deadline = 0) noexcept {
        if (loop.stage == loop_stage_t::quiesced_k)
            return atomic_ref<ucall_status_t> {server.failure}.load(std::memory_order_acquire);
        if (loop.setup_status != ucall_status_success_k) return loop.setup_status;
        loop.setup_status = open_loop(loop);
        if (loop.setup_status != ucall_status_success_k) return loop.setup_status;
        atomic_ref<std::uint32_t> {server.serving}.store(1, std::memory_order_release);
        atomic_ref<std::uint32_t> {loop.wake_pending}.store(0, std::memory_order_release);
        server_progress(server, loop);
        if (loop.stage == loop_stage_t::quiesced_k)
            return atomic_ref<ucall_status_t> {server.failure}.load(std::memory_order_acquire);
        auto batch_deadline = atomic_ref<std::uint64_t> {server.batch_deadline}.load(std::memory_order_acquire);
        if (batch_deadline) deadline = deadline ? std::min(deadline, batch_deadline) : batch_deadline;
        int count = loop.engine.poll(span<io_completion_t> {loop.completions}, wait, deadline);
        if (count < 0) {
            atomic_ref<ucall_status_t> {server.failure}.store(ucall_status_io_k, std::memory_order_release);
            server_stop(&server);
            loop.engine.stop();
            loop.stage = loop_stage_t::quiesced_k;
            return ucall_status_io_k;
        }
        for (int i = 0; i != count; ++i) {
            auto& completion = loop.completions[static_cast<std::size_t>(i)];
            if (completion.request == &loop.wake.request) {
                loop.engine.release(completion);
                if (!loop.engine.submit(loop.wake.request)) {
                    atomic_ref<ucall_status_t> {server.failure}.store(ucall_status_io_k, std::memory_order_release);
                    server_stop(&server);
                }
            }
            else if (completion.request->operation == io_operation_t::accept_k)
                advance_completion(loop.engine, completion);
            else {
                auto& connection = *static_cast<connection_t*>(completion.request->context);
                advance_completion(loop.engine, completion);
                mark_ready(loop, connection);
            }
        }
        server_progress(server, loop);
        return atomic_ref<ucall_status_t> {server.failure}.load(std::memory_order_acquire);
    }
    static void server_take_call(ucall_server_take_call_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server) {
            publish(arguments->outcome, ucall_status_uninitialized_k);
            return;
        }
        auto& server = *static_cast<server_t*>(arguments->server);
        if (arguments->event_loop_index >= server.loops.size()) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto wait = arguments->timeout_microseconds ? io_wait_t::blocking_k : io_wait_t::nonblocking_k;
        auto deadline = arguments->timeout_microseconds ? deadline_after(arguments->timeout_microseconds) : 0;
        auto& loop = *server.loops[arguments->event_loop_index];
        auto* previous = std::exchange(polling_loop, &loop);
        auto status = server_poll(server, loop, wait, deadline);
        polling_loop = previous;
        publish(arguments->outcome, status);
    }
    static void server_take_calls(ucall_server_take_calls_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server) {
            publish(arguments->outcome, ucall_status_uninitialized_k);
            return;
        }
        auto& server = *static_cast<server_t*>(arguments->server);
        if (arguments->event_loop_index >= server.loops.size()) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& loop = *server.loops[arguments->event_loop_index];
        ucall_status_t status = ucall_status_success_k;
        auto* previous = std::exchange(polling_loop, &loop);
        while (loop.stage != loop_stage_t::quiesced_k && status == ucall_status_success_k)
            status = server_poll(server, loop, io_wait_t::blocking_k);
        polling_loop = previous;
        publish(arguments->outcome, status);
    }
    static bool flush_pending(endpoint_t& endpoint, bool stopping) noexcept {
        if (endpoint.pending.empty()) return false;
        if (stopping)
            for (auto handle : endpoint.pending) {
                auto& request = *static_cast<request_t*>(handle);
                atomic_ref<std::uint32_t> {request.state}.fetch_or(claimed_k | ready_k | detached_k,
                                                                   std::memory_order_release);
                push_replied(request);
            }
        else endpoint.batch_callback(endpoint.pending.data(), endpoint.pending.size(), endpoint.context);
        endpoint.pending.clear();
        return !stopping;
    }

    /** One drain round: moves deposits to their endpoints, invokes due batches, and publishes the
     *  next expiry. */
    static bool drain_batches(server_t& server, bool stopping, std::uint64_t& observed) noexcept {
        auto& queue = server.batches;
        observed = atomic_ref<std::uint64_t> {queue.tail}.fetch_and(~batch_signal_k, std::memory_order_acq_rel) &
                   ~batch_signal_k;
        bool fired = false;
        auto head = queue.head;
        for (; head != observed; ++head) {
            auto slot = atomic_ref<request_t*> {queue.slots[head & (queue.slots.size() - 1)]};
            auto* request = slot.load(std::memory_order_acquire);
            // The depositor has claimed this index and stores into it right after.
            while (!request) {
                fu::standard_yield_t {}(slot, request, 0);
                request = slot.load(std::memory_order_acquire);
            }
            slot.store(nullptr, std::memory_order_relaxed);
            auto& endpoint = *request->endpoint;
            (void)endpoint.pending.push_back(st::assume_reserved, request);
            if (endpoint.pending.size() == endpoint.max_batch_size) fired |= flush_pending(endpoint, stopping);
        }
        atomic_ref<std::uint64_t> {queue.head}.store(head, std::memory_order_release);
        auto now = monotonic_ns();
        std::uint64_t deadline = 0;
        for (auto* endpoint = server.endpoints; endpoint; endpoint = endpoint->next) {
            if (endpoint->pending.empty()) continue;
            auto deposited = static_cast<request_t*>(endpoint->pending.front())->deposited;
            auto maximum = std::numeric_limits<std::uint64_t>::max();
            auto expiry = endpoint->batch_latency > (maximum - deposited) / 1000
                              ? maximum
                              : deposited + endpoint->batch_latency * 1000;
            if (stopping || endpoint->pending.size() >= endpoint->min_batch_size || now >= expiry)
                fired |= flush_pending(*endpoint, stopping);
            else deadline = deadline ? std::min(deadline, expiry) : expiry;
        }
        auto previous = atomic_ref<std::uint64_t> {server.batch_deadline}.exchange(deadline, std::memory_order_acq_rel);
        if (deadline && (!previous || deadline < previous)) server.loops.front()->notify();
        return fired;
    }
    static void server_take_batch(ucall_server_take_batch_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server) {
            publish(arguments->outcome, ucall_status_uninitialized_k);
            return;
        }
        auto& server = *static_cast<server_t*>(arguments->server);
        if (server.batches.slots.empty()) {
            publish(arguments->outcome, ucall_status_not_found_k);
            return;
        }
        auto deadline = arguments->timeout_microseconds ? deadline_after(arguments->timeout_microseconds) : 0;
        auto tail = atomic_ref<std::uint64_t> {server.batches.tail};
        for (;;) {
            std::uint64_t observed {};
            bool stopping = atomic_ref<std::uint32_t> {server.stopped}.load(std::memory_order_acquire);
            if (drain_batches(server, stopping, observed) || stopping || monotonic_ns() >= deadline) break;
            // The portable wait has no timeout, so a bounded call yields until a deposit or signal.
            while (tail.load(std::memory_order_acquire) == observed && monotonic_ns() < deadline)
                fu::standard_yield_t {}(tail, observed, 0);
        }
        publish(arguments->outcome, atomic_ref<ucall_status_t> {server.failure}.load(std::memory_order_acquire));
    }
    static void server_take_batches(ucall_server_take_batches_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server) {
            publish(arguments->outcome, ucall_status_uninitialized_k);
            return;
        }
        auto& server = *static_cast<server_t*>(arguments->server);
        if (server.batches.slots.empty()) {
            publish(arguments->outcome, ucall_status_not_found_k);
            return;
        }
        for (;;) {
            std::uint64_t observed {};
            bool stopping = atomic_ref<std::uint32_t> {server.stopped}.load(std::memory_order_acquire);
            drain_batches(server, stopping, observed);
            if (stopping) break;
            std::atomic_ref<std::uint64_t> {server.batches.tail}.wait(observed, std::memory_order_acquire);
        }
        publish(arguments->outcome, atomic_ref<ucall_status_t> {server.failure}.load(std::memory_order_acquire));
    }
    static void server_free(ucall_server_t handle) noexcept {
        if (!handle) return;
        auto& server = *static_cast<server_t*>(handle);
        server_stop(handle);
        for (auto& loop : server.loops)
            while (loop->stage == loop_stage_t::ready_k && loop->setup_status == ucall_status_success_k)
                if (server_poll(server, *loop, io_wait_t::blocking_k) != ucall_status_success_k) break;
        allocator_delete<server_t, allocator_t> {server.allocator}(&server);
    }
    template <typename arguments_type_>
    static void add_endpoint(arguments_type_* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server || !arguments->callback || !valid_view(arguments->uri_template) ||
            (!http_verb_name(arguments->verb) && arguments->verb != ucall_verb_any_k)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& server = *static_cast<server_t*>(arguments->server);
        if (atomic_ref<std::uint32_t> {server.serving}.load(std::memory_order_acquire)) {
            publish(arguments->outcome, ucall_status_contended_k);
            return;
        }
        auto path = text_view(arguments->uri_template);
        if (path.empty() || path.front() != '/' || find(path, '?') != std::string_view::npos ||
            find(path, '#') != std::string_view::npos) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        for (auto* existing = server.endpoints; existing; existing = existing->next)
            if ((existing->callback || existing->batch_callback) && existing->verb == arguments->verb &&
                equal(existing->path, path)) {
                publish(arguments->outcome, ucall_status_already_exists_k);
                return;
            }
        auto* endpoint = allocate_unique<endpoint_t>(server.allocator, server.allocator).release();
        if (!endpoint || !copy_text(endpoint->storage, path)) {
            allocator_delete<endpoint_t, allocator_t> {server.allocator}(endpoint);
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        endpoint->path = {endpoint->storage.data(), path.size()};
        endpoint->verb = arguments->verb;
        endpoint->context = arguments->context;
        if constexpr (requires { arguments->min_batch_size; }) {
            endpoint->min_batch_size = arguments->min_batch_size ? arguments->min_batch_size : 1;
            endpoint->max_batch_size = arguments->max_batch_size ? arguments->max_batch_size : 32;
            endpoint->batch_latency = arguments->max_latency_microseconds ? arguments->max_latency_microseconds
                                                                          : 10'000;
            auto slots = server.connections_budget + server.loops.size();
            if (st::failed(endpoint->pending.reserve(endpoint->max_batch_size)) ||
                (server.batches.slots.empty() && st::failed(server.batches.slots.resize(std::bit_ceil(slots))))) {
                allocator_delete<endpoint_t, allocator_t> {server.allocator}(endpoint);
                publish(arguments->outcome, ucall_status_out_of_memory_k);
                return;
            }
        }
        endpoint->next = server.endpoints;
        server.endpoints = endpoint;
        // Trie edges may already borrow template segments when an allocation fails.
        if (!server.routes.insert(endpoint->path, endpoint->verb, endpoint)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        if constexpr (requires { arguments->min_batch_size; }) endpoint->batch_callback = arguments->callback;
        else endpoint->callback = arguments->callback;
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void server_add_http_endpoint(ucall_server_add_http_endpoint_t* arguments) noexcept {
        add_endpoint(arguments);
    }
    static void server_add_batch_endpoint(ucall_server_add_batch_endpoint_t* arguments) noexcept {
        if (!arguments) return;
        auto minimum = arguments->min_batch_size ? arguments->min_batch_size : 1;
        auto maximum = arguments->max_batch_size ? arguments->max_batch_size : 32;
        if (minimum > maximum) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        add_endpoint(arguments);
    }
    static ucall_verb_t server_request_verb(ucall_server_t, ucall_received_http_request_t request) noexcept {
        return request ? static_cast<request_t*>(request)->message.verb : ucall_verb_unknown_k;
    }
    static std::string_view path_segment(std::string_view path, std::size_t index) noexcept {
        path_cursor<http_t> cursor {path};
        for (auto segment = cursor.next(); !segment.empty(); segment = cursor.next())
            if (!index--) return segment;
        return {};
    }
    static std::size_t server_request_path_segments_count(ucall_server_t,
                                                          ucall_received_http_request_t request) noexcept {
        if (!request) return 0;
        auto& exchange = *static_cast<request_t*>(request);
        return count_path_segments<http_t>(extract_path_component<http_t>(exchange.message.target(exchange.text())));
    }
    static void server_request_path_segment(ucall_server_request_path_segment_t* arguments) noexcept {
        if (!arguments) return;
        if (arguments->segment) *arguments->segment = {};
        if (!arguments->server || !arguments->request || !arguments->segment) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<request_t*>(arguments->request);
        auto value = path_segment(extract_path_component<http_t>(exchange.message.target(exchange.text())),
                                  arguments->index);
        *arguments->segment = c_view(value);
        publish(arguments->outcome, value.empty() ? ucall_status_not_found_k : ucall_status_success_k);
    }
    static void server_request_path_parameter(ucall_server_request_path_parameter_t* arguments) noexcept {
        if (!arguments) return;
        if (arguments->value) *arguments->value = {};
        if (!arguments->server || !arguments->request || !arguments->value || !valid_view(arguments->name)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<request_t*>(arguments->request);
        auto* endpoint = exchange.endpoint;
        auto name = text_view(arguments->name);
        auto pattern = endpoint ? endpoint->path : std::string_view {};
        auto path = extract_path_component<http_t>(exchange.message.target(exchange.text()));
        path_cursor<http_t> patterns {pattern}, values {path};
        for (auto segment = patterns.next(); !segment.empty(); segment = patterns.next()) {
            auto value = values.next();
            if (value.empty()) break;
            parsed_segment_t parsed {};
            if (!parse_segment<http_t>(segment, parsed)) break;
            if (parsed.type != segment_type_t::literal_k && equal(parsed.content, name)) {
                if (parsed.type == segment_type_t::wildcard_k)
                    value = path.substr(static_cast<std::size_t>(value.data() - path.data()));
                *arguments->value = c_view(value);
                publish(arguments->outcome, ucall_status_success_k);
                return;
            }
        }
        publish(arguments->outcome, ucall_status_not_found_k);
    }
    static void server_request_query_parameter(ucall_server_request_query_parameter_t* arguments) noexcept {
        if (!arguments) return;
        if (arguments->value) *arguments->value = {};
        if (!arguments->server || !arguments->request || !arguments->value || !valid_view(arguments->name)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<request_t*>(arguments->request);
        auto target = exchange.message.target(exchange.text());
        auto query_at = find(target, '?');
        auto query = query_at == std::string_view::npos ? std::string_view {} : target.substr(query_at + 1);
        while (!query.empty()) {
            auto end = find(query, '&');
            auto field = query.substr(0, end);
            auto equals = find(field, '=');
            if (equal(field.substr(0, equals), text_view(arguments->name))) {
                *arguments->value = c_view(equals == std::string_view::npos ? std::string_view {}
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
        if (!arguments) return;
        if (arguments->value) *arguments->value = {};
        if (!arguments->server || !arguments->request || !arguments->value || !valid_view(arguments->name) ||
            !http_token(text_view(arguments->name))) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<request_t*>(arguments->request);
        auto value = exchange.message.header(exchange.text(), text_view(arguments->name));
        *arguments->value = c_view(value);
        publish(arguments->outcome, value.data() ? ucall_status_success_k : ucall_status_not_found_k);
    }
    static void server_request_body(ucall_server_request_body_t* arguments) noexcept {
        if (!arguments) return;
        if (arguments->body) *arguments->body = {};
        if (!arguments->server || !arguments->request || !arguments->body) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<request_t*>(arguments->request);
        *arguments->body = c_view(exchange.message.body(exchange.text()));
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void server_reply_content(ucall_server_reply_content_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server || !arguments->request || !valid_view(arguments->body)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        publish(arguments->outcome, reply(*static_cast<request_t*>(arguments->request),
                                          arguments->http_status ? arguments->http_status : 200, arguments->headers,
                                          arguments->headers_count, text_view(arguments->body)));
    }
    static void server_reply_error(ucall_server_reply_error_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server || !arguments->request || !valid_view(arguments->message) ||
            arguments->http_status < 400) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        ucall_bytes_view_t header = c_view("content-type: text/plain");
        publish(arguments->outcome, reply(*static_cast<request_t*>(arguments->request), arguments->http_status, &header,
                                          1, text_view(arguments->message)));
    }
    struct client_job_t {
        explicit client_job_t(allocator_t const& allocator = {}) noexcept
            : authority(rebound_allocator<char> {allocator}), target(rebound_allocator<char> {allocator}),
              host(rebound_allocator<char> {allocator}), service(rebound_allocator<char> {allocator}),
              redirect(rebound_allocator<char> {allocator}),
              redirect_headers(rebound_allocator<ucall_bytes_view_t> {allocator}) {}
        client_job_t(client_job_t const&) = delete;
        client_job_t& operator=(client_job_t const&) = delete;
        client_job_t(client_job_t&&) = delete;
        client_job_t& operator=(client_job_t&&) = delete;

        ucall_client_call_t arguments {};
        enum class stage_t { idle_k, queued_k, active_k };
        stage_t stage {};
        std::uint64_t deadline {};
        std::unique_ptr<addrinfo, void (*)(addrinfo*)> addresses {nullptr, &freeaddrinfo};
        addrinfo* address {};
        addrinfo numeric_address {};
        sockaddr_storage numeric_socket {};
        std::uint16_t port {};
        addrinfo* first_address() noexcept { return numeric_address.ai_addr ? &numeric_address : addresses.get(); }
        vector<char> authority {}, target {}, host {}, service {}, redirect {};
        vector<ucall_bytes_view_t> redirect_headers {};
        std::size_t attempts {}, redirects {};
        std::uint64_t authority_hash {};
    };
    struct client_peer_t {
        explicit client_peer_t(allocator_t const& allocator = {}) noexcept
            : connection(allocator), authority(rebound_allocator<char> {allocator}) {}
        client_peer_t(client_peer_t const&) = delete;
        client_peer_t& operator=(client_peer_t const&) = delete;
        client_peer_t(client_peer_t&&) = delete;
        client_peer_t& operator=(client_peer_t&&) = delete;

        connection_t connection {};
        client_job_t* job {};
        vector<char> authority {};
        ucall_security_mode_t security {};
        std::uint64_t authority_hash {};
        ucall_noise_key_t private_key {}, remote_key {};
    };
    struct client_t : ucall_client_handle_t {
        allocator_t allocator;
        explicit client_t(allocator_t const& allocator = {}) noexcept
            : allocator(allocator), engine(allocator), completions(rebound_allocator<io_completion_t> {allocator}),
              completed(rebound_allocator<ucall_completed_call_t> {allocator}),
              peers(rebound_allocator<owner<client_peer_t>> {allocator}) {}
        client_t(client_t const&) = delete;
        client_t& operator=(client_t const&) = delete;
        client_t(client_t&&) = delete;
        client_t& operator=(client_t&&) = delete;

        engine_t engine {};
        vector<io_completion_t> completions {};
        vector<ucall_completed_call_t> completed {};
        ucall_status_t failure {ucall_status_success_k};
        ucall_client_config_t config {};
        ucall_noise_key_t private_key {};
        vector<owner<client_peer_t>> peers {};
        span<client_job_t> jobs {};
        std::size_t next_job {}, admitted {}, completed_head {}, completed_count {};
        ~client_t() noexcept {
            engine.stop();
            secure_tunnel_crypto<capabilities_k>::secure_zero(private_key);
            for (auto& peer : peers)
                if (peer) {
                    auto& connection = peer->connection;
                    if (connection.descriptor >= 0 &&
                        !((connection.flags & connection_pending_k) &&
                          connection.request.operation == io_operation_t::close_k && connection.request.descriptor < 0))
                        engine.close_socket(connection.descriptor);
                    secure_tunnel_crypto<capabilities_k>::secure_zero(peer->private_key);
                }
            for (std::size_t i = 0; i != completed_count; ++i)
                ucall_received_http_response_free(completed[(completed_head + i) % completed.size()].response);
            peers.clear();
            for (auto& job : jobs) std::destroy_at(&job);
            if (!jobs.empty()) rebound_allocator<client_job_t> {allocator}.deallocate(jobs.data(), jobs.size());
        }
    };
    static ucall_status_t parse_url(client_job_t& job) noexcept {
        auto url = text_view(job.arguments.url);
        auto scheme = find(url, "://");
        if (scheme == std::string_view::npos) return ucall_status_invalid_argument_k;
        auto protocol = url.substr(0, scheme);
        if (protocol != "http" && protocol != "http+noise") return ucall_status_unsupported_k;
        if (protocol == "http+noise" && job.arguments.options.security == ucall_security_mode_none_k)
            job.arguments.options.security = ucall_security_mode_noise_xx_k;
        auto rest = url.substr(scheme + 3);
        auto slash = find(rest, '/'), query = find(rest, '?'), fragment = find(rest, '#');
        auto boundary = std::min(slash, std::min(query, fragment));
        auto authority = rest.substr(0, boundary);
        if (authority.empty() || find(authority, '@') != std::string_view::npos || !http_value(authority) ||
            find(authority, ' ') != std::string_view::npos || find(authority, '\t') != std::string_view::npos ||
            find(authority, '\0') != std::string_view::npos)
            return ucall_status_invalid_argument_k;
        if (!copy_text(job.authority, authority)) return ucall_status_out_of_memory_k;
        job.authority_hash = http_t::hash(authority);
        auto tail = boundary == std::string_view::npos ? std::string_view {} : rest.substr(boundary);
        fragment = find(tail, '#');
        tail = tail.substr(0, fragment);
        job.target.clear();
        if ((tail.empty() || tail.front() != '/') && !append_text(job.target, "/")) return ucall_status_out_of_memory_k;
        if (!append_text(job.target, tail)) return ucall_status_out_of_memory_k;
        auto host = authority;
        std::string_view port = "80";
        if (host.front() == '[') {
            auto end = find(host, ']');
            if (end == std::string_view::npos) return ucall_status_invalid_argument_k;
            if (end + 1 < host.size()) {
                if (host[end + 1] != ':') return ucall_status_invalid_argument_k;
                port = host.substr(end + 2);
            }
            host = host.substr(1, end - 1);
        }
        else {
            auto colon = find(host, ':');
            if (colon != std::string_view::npos) {
                port = host.substr(colon + 1);
                host = host.substr(0, colon);
            }
        }
        unsigned number = 0;
        auto parsed = std::from_chars(port.data(), port.data() + port.size(), number);
        if (parsed.ec != std::errc {} || parsed.ptr != port.data() + port.size() || !number ||
            number > std::numeric_limits<std::uint16_t>::max() || host.empty())
            return ucall_status_invalid_argument_k;
        if (!copy_text(job.host, host) || !copy_text(job.service, port)) return ucall_status_out_of_memory_k;
        job.addresses.reset();
        job.numeric_address = {};
        job.address = nullptr;
        job.port = static_cast<std::uint16_t>(number);
        return ucall_status_success_k;
    }
    static ucall_status_t resolve_job(client_job_t& job) noexcept {
        sockaddr_in ipv4 {};
        sockaddr_in6 ipv6 {};
        if (!sockets_start()) return ucall_status_io_k;
        if (inet_pton(AF_INET, job.host.data(), &ipv4.sin_addr) == 1) {
            ipv4.sin_family = AF_INET;
            ipv4.sin_port = htons(job.port);
            std::memcpy(&job.numeric_socket, &ipv4, sizeof(ipv4));
            job.numeric_address.ai_family = AF_INET;
            job.numeric_address.ai_addrlen = sizeof(ipv4);
        }
        else if (inet_pton(AF_INET6, job.host.data(), &ipv6.sin6_addr) == 1) {
            ipv6.sin6_family = AF_INET6;
            ipv6.sin6_port = htons(job.port);
            std::memcpy(&job.numeric_socket, &ipv6, sizeof(ipv6));
            job.numeric_address.ai_family = AF_INET6;
            job.numeric_address.ai_addrlen = sizeof(ipv6);
        }
        if (job.numeric_address.ai_addrlen) {
            job.numeric_address.ai_socktype = SOCK_STREAM;
            job.numeric_address.ai_addr = reinterpret_cast<sockaddr*>(&job.numeric_socket);
            job.address = &job.numeric_address;
            return ucall_status_success_k;
        }
        addrinfo hints {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* resolved = nullptr;
        if (getaddrinfo(job.host.data(), job.service.data(), &hints, &resolved) != 0)
            return ucall_status_connection_failed_k;
        job.addresses.reset(resolved);
        job.address = job.addresses.get();
        return ucall_status_success_k;
    }
    static ucall_status_t compose_request(connection_t& connection, client_job_t const& job) noexcept {
        connection.output.clear();
        auto& arguments = job.arguments;
        auto target = text_view(job.target);
        if (!http_value(target) || find(target, ' ') != std::string_view::npos ||
            find(target, '\t') != std::string_view::npos)
            return ucall_status_invalid_argument_k;
        if (!append_text(connection.output, http_verb_name(arguments.verb)) || !append_text(connection.output, " ") ||
            !append_text(connection.output, target) || !append_text(connection.output, " HTTP/1.1\r\nhost: ") ||
            !append_text(connection.output, {job.authority.data(), job.authority.size() - 1}) ||
            !append_text(connection.output, "\r\nuser-agent: UCall\r\n"))
            return ucall_status_out_of_memory_k;
        auto result = append_headers(connection.output, arguments.headers, arguments.headers_count,
                                     http_role_t::request_k);
        if (result != ucall_status_success_k) return result;
        char digits[std::numeric_limits<std::size_t>::digits10 + 1];
        if (!append_text(connection.output, "content-length: ") ||
            !append_text(connection.output, format_decimal(digits, arguments.body.length)) ||
            !append_text(connection.output, "\r\n\r\n") || !append_text(connection.output, text_view(arguments.body)))
            return ucall_status_out_of_memory_k;
        connection.verb = arguments.verb;
        return ucall_status_success_k;
    }
    static void finish_job(client_t& client, client_job_t& job, ucall_status_t status,
                           response_t* response = nullptr) noexcept {
        auto& completed = client.completed[(client.completed_head + client.completed_count) % client.completed.size()];
        completed.context = job.arguments.context;
        completed.response = response;
        completed.outcome = {status, status == ucall_status_success_k ? nullptr : ucall_status_name(status)};
        ++client.completed_count;
        job.addresses.reset();
        job.address = nullptr;
        job.redirect.clear();
        job.redirect_headers.clear();
        job.stage = client_job_t::stage_t::idle_k;
    }
    static bool same_peer(client_t const& client, client_peer_t const& peer, client_job_t const& job) noexcept {
        auto& options = job.arguments.options;
        auto* private_key = options.client_key ? options.client_key : client.config.noise_private_key;
        if (peer.security != options.security || peer.authority_hash != job.authority_hash ||
            peer.authority.size() != job.authority.size() ||
            !equal(text_view(peer.authority), text_view(job.authority)))
            return false;
        if (options.security == ucall_security_mode_none_k) return true;
        return private_key && std::memcmp(peer.private_key, *private_key, sizeof(peer.private_key)) == 0 &&
               (!options.server_key || std::memcmp(peer.remote_key, *options.server_key, sizeof(peer.remote_key)) == 0);
    }
    static ucall_status_t dial_peer(client_t& client, client_peer_t& peer) noexcept {
        auto& job = *peer.job;
        auto& connection = peer.connection;
        if (!copy_text(peer.authority, {job.authority.data(), job.authority.size() - 1}))
            return ucall_status_out_of_memory_k;
        peer.authority_hash = job.authority_hash;
        while (job.address) {
            auto descriptor = client.engine.open_socket(job.address->ai_family);
            if (descriptor < 0) {
                job.address = job.address->ai_next;
                continue;
            }
            auto& options = job.arguments.options;
            auto* key = options.client_key ? options.client_key : client.config.noise_private_key;
            auto config = tunnel_config(options.security, secure_tunnel_role_t::initiator_k, key, nullptr,
                                        options.server_key);
            auto result = connection.configure(config);
            if (result != ucall_status_success_k) {
                client.engine.close_socket(descriptor);
                return result;
            }
            connection.descriptor = descriptor;
            connection.output_offset = 0;
            connection.sending = nullptr;
            connection.message = {};
            connection.flags = static_cast<connection_flags_t>(connection.flags & ~connection_peer_closed_k);
            connection.role = connection_role_t::client_k;
            connection.stage = connection_stage_t::connecting_k;
            connection.status = ucall_status_success_k;
            connection.flags = static_cast<connection_flags_t>(connection.flags & ~connection_pending_k);
            connection.authorizer = client.config.peer_authorizer;
            connection.authorizer_context = client.config.peer_authorizer_context;
            connection.deadline = std::min(job.deadline, deadline_after(client.config.connect_timeout_microseconds));
            connection.request = {
                io_operation_t::connect_k, descriptor,          reinterpret_cast<byte_t*>(job.address->ai_addr),
                job.address->ai_addrlen,   connection.deadline, &connection};
            peer.security = options.security;
            if (key) std::memcpy(peer.private_key, *key, sizeof(peer.private_key));
            if (options.server_key) std::memcpy(peer.remote_key, *options.server_key, sizeof(peer.remote_key));
            return ucall_status_success_k;
        }
        return ucall_status_connection_failed_k;
    }
    static ucall_status_t redirect_job(client_job_t& job, connection_t const& connection) noexcept {
        auto location = connection.message.header(connection.text(), "location");
        if (location.empty()) return ucall_status_not_found_k;
        auto maximum = job.arguments.options.max_redirects ? job.arguments.options.max_redirects : 5;
        if (job.redirects++ >= maximum) return ucall_status_malformed_k;
        auto previous = text_view(job.arguments.url);
        auto scheme = find(previous, "://");
        auto origin_end = scheme + 3 + job.authority.size() - 1;
        vector<char> next {job.redirect.get_allocator()};
        if (find(location, "://") != std::string_view::npos) {
            if (!append_text(next, location)) return ucall_status_out_of_memory_k;
        }
        else if (location.starts_with("//")) {
            if (!append_text(next, previous.substr(0, scheme + 1)) || !append_text(next, location))
                return ucall_status_out_of_memory_k;
        }
        else {
            if (!append_text(next, previous.substr(0, origin_end))) return ucall_status_out_of_memory_k;
            if (location.front() != '/') {
                auto path = text_view(job.target);
                path = path.substr(0, find(path, '?'));
                auto last = http_t::rfind(path, '/');
                if (!append_text(next, last != path.npos ? path.substr(0, last + 1) : "/"))
                    return ucall_status_out_of_memory_k;
            }
            if (!append_text(next, location)) return ucall_status_out_of_memory_k;
        }
        if (job.arguments.options.security != ucall_security_mode_none_k &&
            !text_view(next).starts_with("http+noise://"))
            return ucall_status_peer_rejected_k;
        job.redirect = std::move(next);
        job.arguments.url = c_view(text_view(job.redirect));
        if (connection.message.status == 303 ||
            ((connection.message.status == 301 || connection.message.status == 302) &&
             job.arguments.verb == ucall_verb_post_k)) {
            if (job.arguments.verb != ucall_verb_head_k) job.arguments.verb = ucall_verb_get_k;
            job.arguments.body = {};
        }
        // Credentials belong to the caller's original origin, never to a redirect target.
        vector<ucall_bytes_view_t> safe_headers {job.redirect_headers.get_allocator()};
        for (std::size_t i = 0; i != job.arguments.headers_count; ++i) {
            auto header = job.arguments.headers[i];
            auto name = text_view(header).substr(0, find(text_view(header), ':'));
            if (http_t::equal_ascii_uncased(name, "authorization") ||
                http_t::equal_ascii_uncased(name, "proxy-authorization") || http_t::equal_ascii_uncased(name, "cookie"))
                continue;
            if (st::failed(safe_headers.push_back(std::move(header)))) return ucall_status_out_of_memory_k;
        }
        job.redirect_headers = std::move(safe_headers);
        job.arguments.headers = job.redirect_headers.data();
        job.arguments.headers_count = job.redirect_headers.size();
        auto result = parse_url(job);
        return result == ucall_status_success_k ? resolve_job(job) : result;
    }
    static void client_completed(client_t& client, client_peer_t& peer) noexcept {
        auto& connection = peer.connection;
        auto& job = *peer.job;
        if (connection.stage == connection_stage_t::closed_k) {
            bool retry = connection.status == ucall_status_connection_failed_k && monotonic_ns() < job.deadline;
            if (retry) {
                job.address = job.address ? job.address->ai_next : nullptr;
                auto maximum = job.arguments.options.max_retries ? job.arguments.options.max_retries : 3;
                if (!job.address && job.attempts++ < maximum) job.address = job.first_address();
                if (job.address) {
                    connection.input.clear();
                    connection.encrypted.clear();
                    connection.sending = nullptr;
                    connection.output_offset = 0;
                    connection.flags = static_cast<connection_flags_t>(connection.flags & ~connection_peer_closed_k);
                    auto result = compose_request(connection, job);
                    if (result == ucall_status_success_k) result = dial_peer(client, peer);
                    if (result == ucall_status_success_k) return;
                    connection.status = result;
                }
            }
            auto status = connection.status;
            connection.stage = connection_stage_t::idle_k;
            peer.job = nullptr;
            finish_job(client, job, status);
            return;
        }
        if (connection.stage != connection_stage_t::received_k) return;
        auto code = connection.message.status;
        if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
            auto result = redirect_job(job, connection);
            if (result != ucall_status_not_found_k) {
                if (result != ucall_status_success_k) {
                    connection.fail(result);
                    return;
                }
                connection.fail(ucall_status_connection_failed_k);
                // A redirect is a new exchange; the close completion is consumed before dialing it.
                job.address = nullptr;
                job.attempts = 0;
                return;
            }
        }
        auto* response = allocate_unique<response_t>(client.allocator, client.allocator).release();
        if (!response) {
            connection.fail(ucall_status_out_of_memory_k);
            return;
        }
        response->headers_length = connection.message.headers_length;
        response->body_length = connection.message.body_length;
        response->status = code;
        bool keep_alive = connection.message.keep_alive() && !(connection.flags & connection_peer_closed_k) &&
                          connection.input.size() == connection.message.wire_length && connection.encrypted.empty();
        response->storage = std::move(connection.input);
        response->content = response->storage;
        connection.input.clear();
        connection.output.clear();
        connection.message = {};
        connection.sending = nullptr;
        peer.job = nullptr;
        if (!keep_alive) connection.fail(ucall_status_success_k);
        else connection.stage = connection_stage_t::idle_k;
        finish_job(client, job, ucall_status_success_k, response);
    }
    static std::uint64_t client_progress(client_t& client) noexcept {
        auto& engine = client.engine;
        auto now = monotonic_ns();
        std::uint64_t deadline = 0;
        std::size_t available = 0;
        for (auto& peer : client.peers) {
            auto& connection = peer->connection;
            if (!(connection.flags & connection_pending_k) && peer->job) client_completed(client, *peer);
            available += !peer->job && !(connection.flags & connection_pending_k) &&
                         (connection.stage == connection_stage_t::idle_k ||
                          connection.stage == connection_stage_t::closed_k);
        }
        auto first = client.next_job;
        bool assigned = false;
        for (unsigned pass = 0; pass != 2; ++pass) {
            for (std::size_t offset = 0; offset != client.jobs.size(); ++offset) {
                auto index = offset < client.jobs.size() - first ? first + offset
                                                                 : offset - (client.jobs.size() - first);
                auto& job = client.jobs[index];
                if (job.stage == client_job_t::stage_t::idle_k) continue;
                if (!pass) {
                    if (now >= job.deadline && job.stage == client_job_t::stage_t::queued_k) {
                        finish_job(client, job, ucall_status_timeout_k);
                        continue;
                    }
                    deadline = !deadline ? job.deadline : std::min(deadline, job.deadline);
                }
                if (job.stage != client_job_t::stage_t::queued_k) continue;
                if (!available) continue;
                client_peer_t* chosen = nullptr;
                for (auto& peer : client.peers)
                    if (!peer->job && !(peer->connection.flags & connection_pending_k) &&
                        (peer->connection.stage == connection_stage_t::idle_k ||
                         peer->connection.stage == connection_stage_t::closed_k)) {
                        bool same = peer->connection.descriptor >= 0 && same_peer(client, *peer, job);
                        if (!pass && assigned && peer->connection.descriptor >= 0 && !same) continue;
                        if (!chosen || same || (chosen->connection.descriptor >= 0 && peer->connection.descriptor < 0))
                            chosen = peer.get();
                        if (same) break;
                    }
                if (!chosen) continue;
                --available;
                if (!assigned) {
                    client.next_job = index + 1 == client.jobs.size() ? 0 : index + 1;
                    assigned = true;
                }
                job.stage = client_job_t::stage_t::active_k;
                chosen->job = &job;
                auto& connection = chosen->connection;
                ucall_status_t result = ucall_status_success_k;
                bool reuse = connection.descriptor >= 0 && same_peer(client, *chosen, job);
                if (result == ucall_status_success_k && !reuse) result = resolve_job(job);
                if (result == ucall_status_success_k) result = compose_request(connection, job);
                if (result != ucall_status_success_k) {
                    chosen->job = nullptr;
                    ++available;
                    finish_job(client, job, result);
                    continue;
                }
                connection.deadline = job.deadline;
                if (reuse) connection.transmit();
                else if (connection.descriptor >= 0) {
                    connection.fail(ucall_status_connection_failed_k);
                    job.address = nullptr;
                }
                else {
                    result = dial_peer(client, *chosen);
                    if (result != ucall_status_success_k) {
                        chosen->job = nullptr;
                        ++available;
                        finish_job(client, job, result);
                    }
                }
            }
            if (!available) break;
        }
        for (auto& peer : client.peers) {
            auto& connection = peer->connection;
            if (connection.flags & connection_pending_k) continue;
            auto* request = connection.advance();
            if (request && engine.submit(*request))
                connection.flags = static_cast<connection_flags_t>(connection.flags | connection_pending_k);
        }
        return deadline;
    }
    static void client_init(ucall_client_init_t* arguments, allocator_t const& allocator = {}) noexcept {
        if (!arguments) return;
        if (arguments->client) *arguments->client = nullptr;
        if (!arguments->client || !arguments->outcome || !arguments->config ||
            !arguments->config->max_concurrent_connections) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto client = allocate_unique<client_t>(allocator, allocator);
        if (!client) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        client->config = *arguments->config;
        auto& config = client->config;
        config.cpu_class = static_cast<ucall_cpu_class_t>(cpu_class_);
        if (!config.connect_timeout_microseconds) config.connect_timeout_microseconds = 5'000'000;
        if (!config.request_timeout_microseconds) config.request_timeout_microseconds = 30'000'000;
        if (!config.max_concurrent_calls) config.max_concurrent_calls = config.max_concurrent_connections;
        if (config.noise_private_key) {
            std::memcpy(client->private_key, *config.noise_private_key, sizeof(client->private_key));
            config.noise_private_key = &client->private_key;
        }
        if (st::failed(client->completed.resize(config.max_concurrent_calls)) ||
            st::failed(client->completions.resize(config.max_concurrent_connections)) ||
            st::failed(client->peers.resize(config.max_concurrent_connections))) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        rebound_allocator<client_job_t> job_allocator {allocator};
        auto* jobs = job_allocator.allocate(config.max_concurrent_calls);
        if (!jobs) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        for (std::size_t i = 0; i != config.max_concurrent_calls; ++i) std::construct_at(jobs + i, allocator);
        client->jobs = {jobs, config.max_concurrent_calls};
        auto status = client->engine.open(config.max_concurrent_connections, config.max_concurrent_connections);
        if (status != ucall_status_success_k) {
            publish(arguments->outcome, status);
            return;
        }
        for (auto& peer : client->peers) {
            peer = allocate_unique<client_peer_t>(allocator, allocator);
            if (!peer) {
                publish(arguments->outcome, ucall_status_out_of_memory_k);
                return;
            }
            peer->connection.role = connection_role_t::client_k;
            peer->connection.peer = peer.get();
        }
        if (arguments->resolved) *arguments->resolved = config;
        client->string_capabilities = capabilities_k;
        client->atomic_capabilities = static_cast<std::uint64_t>(cpu_traits<cpu_class_>::forkunion_capabilities_k);
        client->api = &client_api_k;
        *arguments->client = client.release();
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void client_free(ucall_client_t handle) noexcept {
        auto* client = static_cast<client_t*>(handle);
        allocator_delete<client_t, allocator_t> {client->allocator}(client);
    }
    static void client_call(ucall_client_call_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->client || !arguments->outcome || !valid_view(arguments->url) || !valid_view(arguments->body) ||
            !http_verb_name(arguments->verb) || !security_valid(arguments->options.security) ||
            (arguments->headers_count && !arguments->headers)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& client = *static_cast<client_t*>(arguments->client);
        auto options = arguments->options;
        auto mode = options.security;
        if (text_view(arguments->url).starts_with("http+noise://") && mode == ucall_security_mode_none_k)
            mode = ucall_security_mode_noise_xx_k;
        if ((mode != ucall_security_mode_none_k && !options.client_key && !client.config.noise_private_key) ||
            (mode == ucall_security_mode_noise_xx_k && !client.config.peer_authorizer) ||
            ((mode == ucall_security_mode_noise_ik_k || mode == ucall_security_mode_noise_kk_k) &&
             !options.server_key)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        if (client.failure != ucall_status_success_k) {
            publish(arguments->outcome, client.failure);
            return;
        }
        if (client.admitted == client.jobs.size()) {
            publish(arguments->outcome, ucall_status_contended_k);
            return;
        }
        auto timeout = options.timeout_microseconds ? options.timeout_microseconds
                                                    : client.config.request_timeout_microseconds;
        for (auto& job : client.jobs)
            if (job.stage == client_job_t::stage_t::idle_k) {
                job.arguments = *arguments;
                job.arguments.outcome = nullptr;
                auto result = parse_url(job);
                if (result != ucall_status_success_k) {
                    publish(arguments->outcome, result);
                    return;
                }
                job.deadline = deadline_after(timeout);
                job.attempts = job.redirects = 0;
                job.stage = client_job_t::stage_t::queued_k;
                ++client.admitted;
                publish(arguments->outcome, ucall_status_success_k);
                return;
            }
        publish(arguments->outcome, ucall_status_contended_k);
    }
    static void client_take_completed(ucall_client_take_completed_t* arguments) noexcept {
        if (!arguments) return;
        if (arguments->count) *arguments->count = 0;
        if (!arguments->client || !arguments->count || (arguments->capacity && !arguments->calls)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& client = *static_cast<client_t*>(arguments->client);
        auto deadline = arguments->timeout_microseconds ? deadline_after(arguments->timeout_microseconds) : 0;
        if (client.failure == ucall_status_success_k) {
            auto next_deadline = client_progress(client);
            do {
                auto round_deadline = deadline && next_deadline ? std::min(next_deadline, deadline)
                                      : deadline                ? deadline
                                                                : next_deadline;
                auto wait = arguments->timeout_microseconds && client.admitted && !client.completed_count
                                ? io_wait_t::blocking_k
                                : io_wait_t::nonblocking_k;
                int count = client.engine.poll(span<io_completion_t> {client.completions}, wait, round_deadline);
                if (count < 0) {
                    client.failure = ucall_status_io_k;
                    client.engine.stop();
                    for (auto& job : client.jobs)
                        if (job.stage != client_job_t::stage_t::idle_k) finish_job(client, job, client.failure);
                    break;
                }
                for (int i = 0; i != count; ++i)
                    advance_completion(client.engine, client.completions[static_cast<std::size_t>(i)]);
                next_deadline = client_progress(client);
            } while (!client.completed_count && client.admitted && arguments->timeout_microseconds &&
                     monotonic_ns() < deadline);
        }
        auto count = std::min(arguments->capacity, client.completed_count);
        for (std::size_t i = 0; i != count; ++i) {
            arguments->calls[i] = client.completed[client.completed_head];
            client.completed_head = (client.completed_head + 1) % client.completed.size();
        }
        client.completed_count -= count;
        client.admitted -= count;
        *arguments->count = count;
        publish(arguments->outcome, count ? ucall_status_success_k : client.failure);
    }
    static void received_http_response_header(ucall_received_http_response_header_t* arguments) noexcept {
        if (!arguments) return;
        if (arguments->value) *arguments->value = {};
        if (!arguments->client || !arguments->response || !arguments->value || !valid_view(arguments->name) ||
            !http_token(text_view(arguments->name))) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& response = *static_cast<received_response_t*>(arguments->response);
        http_message_t message {};
        message.headers_length = response.headers_length;
        auto value = message.header(text_view(response.bytes()), text_view(arguments->name));
        *arguments->value = c_view(value);
        publish(arguments->outcome, value.data() ? ucall_status_success_k : ucall_status_not_found_k);
    }
    static void received_http_response_body(ucall_received_http_response_body_t* arguments) noexcept {
        if (!arguments) return;
        if (arguments->body) *arguments->body = {};
        if (!arguments->client || !arguments->response || !arguments->body) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& response = *static_cast<received_response_t*>(arguments->response);
        *arguments->body = c_view(text_view(response.bytes()).substr(response.headers_length, response.body_length));
        publish(arguments->outcome, ucall_status_success_k);
    }

    inline static server_api_t const server_api_k {&server_free,
                                                   &server_take_call,
                                                   &server_take_calls,
                                                   &server_take_batch,
                                                   &server_take_batches,
                                                   &server_add_http_endpoint,
                                                   &server_request_verb,
                                                   &server_request_path_segments_count,
                                                   &server_request_path_segment,
                                                   &server_request_path_parameter,
                                                   &server_request_query_parameter,
                                                   &server_request_header,
                                                   &server_request_body,
                                                   &server_reply_content,
                                                   &server_reply_error,
                                                   &server_add_batch_endpoint};
    inline static client_api_t const client_api_k {&client_free, &client_call, &client_take_completed,
                                                   &received_http_response_header, &received_http_response_body};
};

} // namespace unum::ucall
