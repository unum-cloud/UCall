/**
 *  @file include/ucall/network.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Client and server composites over an I/O engine, string kernels, and atomic references.
 */
#pragma once

#include <cstdio>

#include <atomic> // `std::atomic_ref`
#include <bit>    // `std::bit_ceil`
#include <chrono> // `std::chrono::year_month_day`, `std::chrono::hh_mm_ss`, `std::chrono::weekday`

#include "ucall/http.hpp"
#include "ucall/io.hpp"
#include "ucall/routes.hpp"
#include "ucall/tunnel.hpp"
#include "ucall/curve25519.hpp"

#if UCALL_OS_LINUX_
#include <dirent.h> // `opendir`, `readdir`, `closedir`
#endif

namespace unum::ucall {

template <typename engine_type_, template <typename> class atomic_ref_template_, typename compare_kit_type_,
          typename find_kit_type_, typename byteset_kit_type_, typename hash_kit_type_, typename fold_kit_type_,
          typename sha256_kit_type_, typename aes256_gcm_kit_type_,
          typename allocator_type_ = st::default_allocator<byte_t>>
struct network_variant : http<compare_kit_type_, find_kit_type_, byteset_kit_type_, hash_kit_type_, fold_kit_type_> {
    using http_t = http<compare_kit_type_, find_kit_type_, byteset_kit_type_, hash_kit_type_, fold_kit_type_>;
    using tunnel_t = secure_tunnel<sha256_kit_type_, aes256_gcm_kit_type_>;
    using crypto_t = secure_tunnel_crypto<sha256_kit_type_, aes256_gcm_kit_type_>;
    static constexpr sz_capability_t capabilities_k = http_t::capabilities_k | sha256_kit_type_::capability_k |
                                                      aes256_gcm_kit_type_::capability_k;
    using allocator_t = allocator_type_;
    using engine_t = typename engine_type_::template rebind_allocator<allocator_t>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    template <typename value_type_>
    using vector = st::basic_vector<value_type_, rebound_allocator<value_type_>>;
    template <typename value_type_>
    using owner = allocated_ptr<value_type_, allocator_t>;
    template <typename value_type_>
    using atomic_ref = atomic_ref_template_<value_type_>;
    using http_message_t = typename http_t::http_message_t;
    using http_t::append_text;
    using http_t::drop_bytes;
    using http_t::equal;
    using http_t::find;
    using http_t::http_decode_chunks;
    using http_t::http_has_token;
    using http_t::http_parse;
    using http_t::http_token;
    using http_t::http_value;
    using http_t::http_verb_name;
    using http_t::lowercase_ascii;
    using http_t::trim_http;
    using http_t::valid_view;
    enum class server_mode_t { serving_k, stopping_k };
    enum class connection_stage_t : std::uint8_t {
        idle_k,
        connecting_k,
        handshake_k,
        open_k,
        lingering_k, // Half-closed after the last reply, discarding what the peer still sends.
        closing_k,
        closed_k
    };

    /** RFC 6298's initial retransmission timeout bounds the round trip a peer's last bytes take. */
    static constexpr std::size_t linger_microseconds_k = 1'000'000;

    /** Linux's default receive buffer, `tcp_rmem`, bounds what a peer has in flight at our FIN. */
    static constexpr std::size_t linger_bytes_k = 128 * 1024;

    /** Whether a direction's one engine request is in flight; only submission and completion
     *  write it. */
    enum class operation_state_t : std::uint8_t { idle_k, pending_k };

    /** The receive side: reading, full while it holds as many parsed messages as its consumer
     *  accepts now, or ended by `connection: close`, a peer close, or an unparsable request. */
    enum class receive_state_t : std::uint8_t { reading_k, full_k, ended_k };

    /** The transmit side: idle, or sending the oldest reply or a client's newest request. */
    enum class transmit_state_t : std::uint8_t { idle_k, sending_k };

    /** Whether an exchange's reply was collected from the replied list; only its event loop
     *  writes this. */
    enum class exchange_stage_t : std::uint8_t { dispatched_k, collected_k };

    enum connection_flags_t : std::uint8_t {
        connection_none_k = 0,
        connection_authorized_k = 1,
        connection_peer_closed_k = 4,
        connection_ready_k = 8
    };
    struct server_t;
    struct client_t;
    struct event_loop_t;
    struct network_interface_t;
    struct client_peer_t;
    struct endpoint_t;
    struct server_exchange_t;
    inline static thread_local event_loop_t* polling_event_loop {};

    /** The event loop's own counters beside its engine's, on lines no other thread writes. */
    struct alignas(false_sharing_bytes_k) event_loop_statistics_t {
        std::uint64_t polls {}, empty_polls {}, accepts {}, requests {}, bytes_received {}, bytes_sent {},
            bytes_copied {};
    };

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

        io_request_t receive_request {}, transmit_request {}; // One engine request per direction; closes receive.
        operation_state_t receive_operation {}, transmit_operation {};
        descriptor_t descriptor {-1};
        connection_stage_t stage {connection_stage_t::idle_k};
        receive_state_t receiving {};
        transmit_state_t transmitting {};
        ucall_status_t status {ucall_status_success_k};
        std::uint64_t deadline {};
        tunnel_t tunnel {};
        vector<byte_t> input {}, encrypted {}, output {};
        http_message_t message {};
        ucall_peer_authorizer_t authorizer {};
        void* authorizer_context {};
        ucall_noise_key_t peer_static_key {}; // Authenticated at handshake; zero on plaintext connections.
        connection_flags_t flags {connection_none_k};
        vector<byte_t> received {}, record {}; // `record` holds handshake messages only.
        byte_t* sending {};
        std::size_t sending_length {}, sending_offset {};
        std::size_t output_offset {}, output_advance {}; // The next send's start, and how far its completion moves it.
        std::size_t discarded {};                        // Bytes read and dropped while lingering.
        byte_t stash[secure_tunnel_tailroom_k] {};       // What a record sealed in place wrote its framing over.
        network_interface_t* network_interface {};
        client_peer_t* peer {};
        server_exchange_t* oldest_exchange {}; // Replies leave in this order.
        server_exchange_t* newest_exchange {};
        std::uint32_t exchanges_in_flight {};
        connection_t* next {}; // Links the event loop's idle list or its ready queue, never both.

        /** The owning event loop's counters; null on client connections, which have no loop. */
        event_loop_statistics_t* statistics {};

        ucall_status_t configure(secure_tunnel_config_t const& config) noexcept {
            receive_request = transmit_request = {};
            receive_operation = transmit_operation = operation_state_t::idle_k;
            receiving = receive_state_t::reading_k;
            transmitting = transmit_state_t::idle_k;
            message = {};
            input.clear();
            encrypted.clear();
            sending = nullptr;
            sending_length = sending_offset = output_offset = output_advance = discarded = 0;
            deadline = 0;
            flags = connection_none_k;
            crypto_t::secure_zero(peer_static_key);
            auto fault = tunnel.make(config);
            if (fault != secure_tunnel_fault_t::none_k) return ucall_status_handshake_failed_k;
            auto page = page_size();
            if (page <= 0) return ucall_status_io_k;
            if (st::failed(received.resize(static_cast<std::size_t>(page)))) return ucall_status_out_of_memory_k;
            receive_request.context = transmit_request.context = this;
            flags = config.mode == secure_tunnel_mode_t::plain_k ? connection_authorized_k : connection_none_k;
            return ucall_status_success_k;
        }

        /** Records what one completion did to bytes and operation states,
         *  deciding nothing for the protocol. */
        void complete(io_completion_t const& completion) noexcept {
            auto& completed = *completion.request;
            (&completed == &receive_request ? receive_operation : transmit_operation) = operation_state_t::idle_k;
            auto result = completion.result;
            if (completed.operation == io_operation_t::close_k) {
                descriptor = -1;
                stage = connection_stage_t::closed_k;
            }
            else if (result < 0)
                fail(result == -ETIMEDOUT                        ? ucall_status_timeout_k
                     : stage == connection_stage_t::connecting_k ? ucall_status_connection_failed_k
                                                                 : ucall_status_io_k);
            else if (completed.operation == io_operation_t::connect_k) stage = connection_stage_t::handshake_k;
            else if (completed.operation == io_operation_t::send_k) {
                if (!result) return fail(ucall_status_connection_closed_k);
                sending_offset += static_cast<std::size_t>(result);
                if (statistics) tally(statistics->bytes_sent, static_cast<std::uint64_t>(result));
                if (sending_offset != sending_length) return;
                if (stage == connection_stage_t::open_k) {
                    output_offset += output_advance;
                    if (tunnel.encrypts())
                        std::memcpy(sending + sending_length - secure_tunnel_tailroom_k, stash,
                                    secure_tunnel_tailroom_k);
                }
                sending = nullptr;
            }
            else if (stage == connection_stage_t::lingering_k) {
                if (completed.operation == io_operation_t::shutdown_k) return;
                discarded += static_cast<std::size_t>(result);
                if (statistics) tally(statistics->bytes_received, static_cast<std::uint64_t>(result));
                if (!result || discarded >= linger_bytes_k) fail(ucall_status_success_k);
            }
            else if (!result) flags = static_cast<connection_flags_t>(flags | connection_peer_closed_k);
            else {
                auto& destination = tunnel.encrypts() ? encrypted : input;
                std::string_view const arrived {
                    reinterpret_cast<char const*>(completion.data ? completion.data : received.data()),
                    static_cast<std::size_t>(result)};
                if (ucall_status_t const appended = append_text(destination, {arrived});
                    appended != ucall_status_success_k)
                    fail(appended);
                else if (statistics) {
                    tally(statistics->bytes_received, static_cast<std::uint64_t>(result));
                    tally(statistics->bytes_copied, static_cast<std::uint64_t>(result));
                }
            }
        }

        /** The next engine request of every stage but open,
         *  which `serve_open` and `call_open` step. */
        io_request_t* advance() noexcept {
            for (;;) {
                if (stage == connection_stage_t::closing_k) {
                    if (in_flight()) return nullptr;
                    if (descriptor < 0) {
                        stage = connection_stage_t::closed_k;
                        return nullptr;
                    }
                    return emit(receive_request, io_operation_t::close_k, {});
                }
                if (stage == connection_stage_t::closed_k || stage == connection_stage_t::idle_k ||
                    stage == connection_stage_t::open_k)
                    return nullptr;
                // The handshake takes turns between the two directions, and so does lingering.
                if (in_flight()) return nullptr;
                if (stage == connection_stage_t::connecting_k) return &transmit_request;
                if (sending)
                    return emit(transmit_request, io_operation_t::send_k,
                                {sending + sending_offset, sending_length - sending_offset});
                secure_tunnel_request_t const tunnel_request = stage == connection_stage_t::lingering_k
                                                                   ? secure_tunnel_request_t::close_k
                                                                   : secure_tunnel_request_t::proceed_k;
                auto step = tunnel.advance({encrypted.data(), encrypted.data() + encrypted.size()}, tunnel_request);
                drop_bytes(encrypted, step.consumed);
                if (step.state == secure_tunnel_state_t::broken_k ||
                    (step.state == secure_tunnel_state_t::closed_k &&
                     tunnel_request == secure_tunnel_request_t::proceed_k)) {
                    fail(ucall_status_handshake_failed_k);
                    continue;
                }
                if (step.outbound.size()) {
                    if (step.outbound.size() > record.size() && st::failed(record.resize(step.outbound.size()))) {
                        fail(ucall_status_overflow_k);
                        continue;
                    }
                    std::memcpy(record.data(), step.outbound.data(), step.outbound.size());
                    if (statistics) tally(statistics->bytes_copied, step.outbound.size());
                    sending = record.data();
                    sending_length = step.outbound.size();
                    sending_offset = 0;
                    continue;
                }
                // The FIN follows any Noise close record, then receives drain the peer.
                if (stage == connection_stage_t::lingering_k)
                    return transmit_request.operation == io_operation_t::shutdown_k
                               ? emit(receive_request, io_operation_t::receive_k, received)
                               : emit(transmit_request, io_operation_t::shutdown_k, {});
                if (step.state != secure_tunnel_state_t::ready_k) {
                    if (flags & connection_peer_closed_k) {
                        fail(ucall_status_connection_closed_k);
                        continue;
                    }
                    return emit(receive_request, io_operation_t::receive_k, received);
                }
                if (!(flags & connection_authorized_k)) {
                    if (!tunnel.peer_key(std::as_writable_bytes(std::span {peer_static_key}))) {
                        fail(ucall_status_handshake_failed_k);
                        continue;
                    }
                    auto verdict = authorizer ? authorizer(&peer_static_key, authorizer_context)
                                              : ucall_status_success_k;
                    if (verdict != ucall_status_success_k) {
                        fail(verdict);
                        continue;
                    }
                    flags = static_cast<connection_flags_t>(flags | connection_authorized_k);
                }
                stage = connection_stage_t::open_k;
                return nullptr;
            }
        }
        io_request_t* emit(io_request_t& request, io_operation_t operation, span<byte_t> bytes) noexcept {
            request = {
                operation, descriptor, bytes.data(), bytes.size(), operation == io_operation_t::close_k ? 0 : deadline,
                this};
            return &request;
        }

        /** Marks @p request, one of this connection's two,
         *  in flight once the engine accepted it. */
        void submitted(io_request_t const& request) noexcept {
            (&request == &receive_request ? receive_operation : transmit_operation) = operation_state_t::pending_k;
        }
        bool in_flight() const noexcept {
            return receive_operation == operation_state_t::pending_k ||
                   transmit_operation == operation_state_t::pending_k;
        }

        /** The next send of @p source: the rest of the chunk in flight, or its next slice, sealed
         *  in place when the tunnel encrypts, as its producer reserved the tunnel's headroom and
         *  tailroom around the payload.
         *  Null once @p source is all sent, or when sealing failed the connection. */
        io_request_t* transmit_from(vector<byte_t>& source) noexcept {
            if (sending)
                return emit(transmit_request, io_operation_t::send_k,
                            {sending + sending_offset, sending_length - sending_offset});
            if (output_offset == source.size()) return nullptr;
            sending_offset = 0;
            sending = source.data() + output_offset;
            if (!tunnel.encrypts()) {
                sending_length = output_advance = source.size() - output_offset;
                return emit(transmit_request, io_operation_t::send_k, {sending, sending_length});
            }
            // A later record's prefix lands on the last two payload bytes
            // of the one already sent before it.
            std::size_t const payload_length = std::min(source.size() - output_offset - secure_tunnel_overhead_k,
                                                        tunnel.geometry().max_payload);
            std::memcpy(stash, sending + secure_tunnel_headroom_k + payload_length, secure_tunnel_tailroom_k);
            auto sealed = tunnel.seal({sending, sending + secure_tunnel_overhead_k + payload_length}, payload_length);
            if (!sealed.size()) {
                sending = nullptr;
                fail(ucall_status_handshake_failed_k);
                return nullptr;
            }
            sending_length = sealed.size();
            output_advance = output_offset + sending_length == source.size() ? sending_length : payload_length;
            return emit(transmit_request, io_operation_t::send_k, {sending, sending_length});
        }

        /** Opens every whole record waiting in `encrypted` straight into the tail of `input`,
         *  failing the connection on a broken one. */
        void open_records() noexcept {
            if (!tunnel.encrypts()) return;
            std::size_t consumed = 0;
            for (;;) {
                span<byte_t> pending {encrypted.data() + consumed, encrypted.data() + encrypted.size()};
                if (pending.empty() || tunnel.bytes_until_boundary(pending)) break;
                std::size_t const declared = tunnel.bytes_until_boundary(pending.first(secure_tunnel_headroom_k));
                std::size_t const previous = input.size();
                if (st::failed(input.resize(previous + declared))) return fail(ucall_status_out_of_memory_k);
                auto opened = tunnel.open(pending, {input.data() + previous, input.data() + previous + declared});
                if (!opened.consumed) return fail(ucall_status_handshake_failed_k);
                input.erase(previous + opened.payload.size(), declared - opened.payload.size());
                consumed += opened.consumed;
                if (opened.kind == secure_tunnel_record_t::close_k)
                    flags = static_cast<connection_flags_t>(flags | connection_peer_closed_k);
            }
            drop_bytes(encrypted, consumed);
        }
        void fail(ucall_status_t error) noexcept {
            status = error;
            stage = connection_stage_t::closing_k;
            crypto_t::secure_zero(peer_static_key);
        }
        std::string_view text() const noexcept { return text_view(input); }
    };

    enum class drain_state_t : std::uint32_t { draining_k, sleeping_k };

    /** One batch endpoint: the ring every event loop deposits into
     *  and the state its one drain owns. */
    struct batch_endpoint_t : ucall_http_batch_endpoint_handle_t {
        explicit batch_endpoint_t(allocator_t const& allocator = {}) noexcept
            : slots(rebound_allocator<server_exchange_t*> {allocator}),
              pending(rebound_allocator<ucall_received_http_request_t> {allocator}) {}
        batch_endpoint_t(batch_endpoint_t const&) = delete;
        batch_endpoint_t& operator=(batch_endpoint_t const&) = delete;
        batch_endpoint_t(batch_endpoint_t&&) = delete;
        batch_endpoint_t& operator=(batch_endpoint_t&&) = delete;

        vector<server_exchange_t*> slots {}; // A power of two above the request budget plus one per event loop.
        std::uint64_t tail {};               // Event loops `fetch_add`.
        std::uint64_t head {};               // Written by the drain only.
        drain_state_t drain {};
        wake_channel_t wake {};
        ucall_received_http_batch_callback_t callback {};
        std::size_t min_batch_size {}, max_batch_size {}, max_latency_microseconds {};
        vector<ucall_received_http_request_t> pending {}; // Owned by the drain, reserved to `max_batch_size`.
        void* context {};
        ucall_batch_endpoint_statistics_t statistics {}; // Advanced by the drain, loaded relaxed by any thread.
    };

    struct endpoint_t {
        explicit endpoint_t(allocator_t const& allocator = {}) noexcept
            : storage(rebound_allocator<char> {allocator}) {}
        endpoint_t(endpoint_t const&) = delete;
        endpoint_t& operator=(endpoint_t const&) = delete;
        endpoint_t(endpoint_t&&) = delete;
        endpoint_t& operator=(endpoint_t&&) = delete;

        vector<char> storage {};
        std::string_view path {};
        ucall_verb_t verb {};
        ucall_received_http_request_callback_t callback {};
        owner<batch_endpoint_t> batch {}; // Apart, so deposits never contend with routing reads of this endpoint.
        void* context {};
        endpoint_t* next {};
    };
    enum exchange_state_t : std::uint32_t { claimed_k = 1, ready_k = 2, detached_k = 4 };
    struct server_exchange_t : ucall_received_http_request_handle_t {
        explicit server_exchange_t(allocator_t const& allocator = {}) noexcept
            : input(rebound_allocator<byte_t> {allocator}), output(rebound_allocator<byte_t> {allocator}) {}
        server_exchange_t(server_exchange_t const&) = delete;
        server_exchange_t& operator=(server_exchange_t const&) = delete;
        server_exchange_t(server_exchange_t&&) = delete;
        server_exchange_t& operator=(server_exchange_t&&) = delete;

        event_loop_t* event_loop {};
        connection_t* connection {};
        endpoint_t* endpoint {};
        network_interface_t* network_interface {}; // Copied at dispatch, as a batch can outlive its connection.
        ucall_noise_key_t peer_static_key {};
        secure_tunnel_geometry_t geometry {};  // Copied at dispatch; zero headroom and tailroom for plaintext.
        server_exchange_t* next {};            // Links every exchange the event loop owns, until the loop is freed.
        server_exchange_t* replied_next {};    // Links the event loop's replied list, then its free list once recycled.
        server_exchange_t* connection_next {}; // Links its connection's exchanges in request order.
        exchange_stage_t stage {};
        http_message_t message {};
        vector<byte_t> input {}, output {};
        std::uint32_t state {};
        std::uint64_t deposited {};
        std::size_t copied {}; // Reply body bytes, counted later by the event loop, as any thread may reply.
        std::string_view text() const noexcept { return text_view(input); }
    };
    struct network_interface_t {
        explicit network_interface_t(allocator_t const& allocator = {}) noexcept
            : address(rebound_allocator<char> {allocator}), device(rebound_allocator<char> {allocator}) {}
        network_interface_t(network_interface_t const&) = delete;
        network_interface_t& operator=(network_interface_t const&) = delete;
        network_interface_t(network_interface_t&&) = delete;
        network_interface_t& operator=(network_interface_t&&) = delete;

        ucall_network_interface_t config {};
        vector<char> address {}, device {};
        byte_t public_key[32] {};
        ucall_noise_key_t private_key {};
        std::size_t active {};
    };
    using wake_t = wake_channel_t;
    struct interface_acceptor_t {
        interface_acceptor_t() noexcept = default;
        interface_acceptor_t(interface_acceptor_t const&) = delete;
        interface_acceptor_t& operator=(interface_acceptor_t const&) = delete;
        interface_acceptor_t(interface_acceptor_t&&) = delete;
        interface_acceptor_t& operator=(interface_acceptor_t&&) = delete;
        io_request_t request {};
        network_interface_t* network_interface {};
        event_loop_t* event_loop {};
        enum class stage_t { idle_k, pending_k };
        stage_t stage {stage_t::idle_k};
        descriptor_t descriptor {-1};
    };
    enum class event_loop_stage_t { unopened_k, ready_k, quiesced_k };
    struct event_loop_t {
        allocator_t allocator;
        explicit event_loop_t(allocator_t const& allocator = {}) noexcept
            : allocator(allocator), engine(allocator), completions(rebound_allocator<io_completion_t> {allocator}),
              connections(rebound_allocator<owner<connection_t>> {allocator}) {}
        event_loop_t(event_loop_t const&) = delete;
        event_loop_t& operator=(event_loop_t const&) = delete;
        event_loop_t(event_loop_t&&) = delete;
        event_loop_t& operator=(event_loop_t&&) = delete;

        engine_t engine {};
        wake_t wake {};
        vector<io_completion_t> completions {};
        server_t* server {};
        std::uint32_t wake_pending {};
        event_loop_stage_t stage {event_loop_stage_t::unopened_k};
        vector<owner<connection_t>> connections {};
        span<interface_acceptor_t> interface_acceptors {};
        connection_t* idle {};
        connection_t* ready {};
        server_exchange_t* exchanges {};
        server_exchange_t* free_exchanges {};
        server_exchange_t* replied {}; // Pushed from any replying thread, taken whole by the event loop.
        ucall_status_t setup_status {ucall_status_success_k};
        event_loop_statistics_t statistics {};
        void notify() noexcept {
            if (polling_event_loop == this) return;
            if (!atomic_ref<std::uint32_t> {wake_pending}.exchange(1, std::memory_order_release)) wake.notify();
        }
        ~event_loop_t() noexcept {
            engine.stop();
            if (wake.descriptors[0] < 0 && wake.request.descriptor >= 0) engine.close_socket(wake.request.descriptor);
            for (auto& connection : connections)
                if (connection && connection->descriptor >= 0 &&
                    !(connection->receive_operation == operation_state_t::pending_k &&
                      connection->receive_request.operation == io_operation_t::close_k &&
                      connection->receive_request.descriptor < 0))
                    engine.close_socket(connection->descriptor);
            while (exchanges) {
                auto* next = exchanges->next;
                allocator_delete<server_exchange_t, allocator_t> {allocator}(exchanges);
                exchanges = next;
            }
            for (auto& acceptor : interface_acceptors) {
                if (acceptor.request.descriptor >= 0) {
                    if (acceptor.descriptor >= 0) socket_close(acceptor.descriptor);
                    else engine.close_socket(acceptor.request.descriptor);
                }
                std::destroy_at(&acceptor);
            }
            if (!interface_acceptors.empty())
                rebound_allocator<interface_acceptor_t> {allocator}.deallocate(interface_acceptors.data(),
                                                                               interface_acceptors.size());
        }
    };
    struct server_t : ucall_server_handle_t {
        allocator_t allocator;
        explicit server_t(allocator_t const& allocator = {}) noexcept
            : allocator(allocator), resolved(rebound_allocator<ucall_network_interface_t> {allocator}),
              event_loops(rebound_allocator<owner<event_loop_t>> {allocator}), routes(allocator),
              owned_wakeups(rebound_allocator<wake_t*> {allocator}),
              batch_endpoints(rebound_allocator<batch_endpoint_t*> {allocator}) {}
        server_t(server_t const&) = delete;
        server_t& operator=(server_t const&) = delete;
        server_t(server_t&&) = delete;
        server_t& operator=(server_t&&) = delete;

        ucall_status_t failure {ucall_status_success_k};
        ucall_server_config_t config {};
        span<network_interface_t> network_interfaces {};
        vector<ucall_network_interface_t> resolved {};
        vector<owner<event_loop_t>> event_loops {};
        route_trie<http_t, allocator_t> routes {};
        vector<wake_t*> owned_wakeups;
        endpoint_t* endpoints {};
        vector<batch_endpoint_t*> batch_endpoints; // Every drain that `server_stop` must wake.
        std::size_t requests_budget {};
        std::uint32_t serving {};
        ~server_t() noexcept {
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
    [[nodiscard]] static ucall_status_t copy_text(vector<char>& destination, std::string_view text) noexcept {
        destination.clear();
        return append_text(destination, {text, std::string_view {"\0", 1}});
    }
    static ucall_status_t split_address(std::string_view address, vector<char>& host, vector<char>& service) noexcept {
        auto colon = http_t::rfind(address, ':');
        if (colon == std::string_view::npos || !colon || colon + 1 == address.size())
            return ucall_status_invalid_argument_k;
        auto name = address.substr(0, colon), port = address.substr(colon + 1);
        if (name.front() == '[' && name.back() == ']') {
            name.remove_prefix(1);
            name.remove_suffix(1);
        }
        else if (find(name, ':') != std::string_view::npos) return ucall_status_invalid_argument_k;
        unsigned number = 0;
        auto parsed = std::from_chars(port.data(), port.data() + port.size(), number);
        if (parsed.ec != std::errc {} || parsed.ptr != port.data() + port.size() || number > 65535 || name.empty() ||
            find(name, '\0') != std::string_view::npos)
            return ucall_status_invalid_argument_k;
        if (ucall_status_t const copied = copy_text(host, name); copied != ucall_status_success_k) return copied;
        return copy_text(service, port);
    }
    static std::size_t interface_event_loops(char const* device) noexcept {
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
    static ucall_status_t bind_acceptor(network_interface_t& network_interface,
                                        interface_acceptor_t& acceptor) noexcept {
        vector<char> host {rebound_allocator<char> {network_interface.address.get_allocator()}},
            service {host.get_allocator()};
        if (ucall_status_t const started = sockets_start(); started != ucall_status_success_k) return started;
        if (auto status = split_address(network_interface.config.address, host, service);
            status != ucall_status_success_k)
            return status;
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
            if (network_interface.config.device_name)
                configured = configured &&
                             socket_option(
                                 descriptor, SOL_SOCKET, SO_BINDTODEVICE, network_interface.config.device_name,
                                 static_cast<socket_length_t>(std::strlen(network_interface.config.device_name) + 1)) ==
                                 0;
#endif // UCALL_OS_LINUX_
            if (configured && bind(descriptor, address->ai_addr, address->ai_addrlen) == 0 &&
                listen(descriptor,
                       static_cast<int>(std::min<std::size_t>(network_interface.config.max_concurrent_connections,
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
        if (ucall_status_t const copied = copy_text(network_interface.address, text);
            copied != ucall_status_success_k) {
            socket_close(descriptor);
            return copied;
        }
        network_interface.config.address = network_interface.address.data();
        acceptor.network_interface = &network_interface;
        acceptor.request = {io_operation_t::accept_k, descriptor, nullptr, 0, 0, &acceptor};
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

    /** Formats the RFC 9110 IMF-fixdate through the calendar types, without allocating. */
    static std::string_view format_date(char (&output)[http_date_length_k], std::time_t now) noexcept {
        static constexpr char weekdays_k[] = "SunMonTueWedThuFriSat",
                              months_k[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
        std::chrono::sys_seconds const seconds {std::chrono::seconds {std::max<std::time_t>(now, 0)}};
        std::chrono::sys_days const days = std::chrono::floor<std::chrono::days>(seconds);
        std::chrono::year_month_day const date {days};
        std::chrono::hh_mm_ss<std::chrono::seconds> const time {seconds - days};
        auto put = [&](std::size_t offset, std::uint64_t value, std::size_t width) {
            for (auto position = offset + width; position != offset; value /= 10)
                output[--position] = static_cast<char>('0' + value % 10);
        };
        std::memcpy(output, weekdays_k + std::chrono::weekday {days}.c_encoding() * 3, 3);
        std::memcpy(output + 3, ", ", 2);
        put(5, static_cast<unsigned>(date.day()), 2);
        output[7] = ' ';
        std::memcpy(output + 8, months_k + (static_cast<unsigned>(date.month()) - 1) * 3, 3);
        output[11] = ' ';
        put(12, static_cast<std::uint64_t>(static_cast<int>(date.year())), 4);
        output[16] = ' ';
        put(17, static_cast<std::uint64_t>(time.hours().count()), 2);
        output[19] = ':';
        put(20, static_cast<std::uint64_t>(time.minutes().count()), 2);
        output[22] = ':';
        put(23, static_cast<std::uint64_t>(time.seconds().count()), 2);
        std::memcpy(output + 25, " GMT", 4);
        return {output, http_date_length_k};
    }

    static ucall_status_t append_headers(vector<byte_t>& output, span<ucall_bytes_view_t const> headers,
                                         http_role_t role) noexcept {
        for (ucall_bytes_view_t const header : headers) {
            if (!valid_view(header)) return ucall_status_invalid_argument_k;
            auto line = text_view(header);
            auto colon = find(line, ':');
            if (colon == std::string_view::npos || !http_token(line.substr(0, colon)) ||
                !http_value(line.substr(colon + 1)))
                return ucall_status_invalid_argument_k;
            auto previous = output.size();
            if (ucall_status_t const appended = append_text(output, {line.substr(0, colon)});
                appended != ucall_status_success_k)
                return appended;
            lowercase_ascii({reinterpret_cast<char*>(output.data()) + previous, colon});
            std::string_view name {reinterpret_cast<char const*>(output.data()) + previous, colon};
            if (equal(name, "content-length") || equal(name, "transfer-encoding") ||
                (role == http_role_t::request_k && (equal(name, "host") || equal(name, "user-agent"))) ||
                (role != http_role_t::request_k && (equal(name, "date") || equal(name, "server"))))
                return ucall_status_invalid_argument_k;
            if (ucall_status_t const appended = append_text(output, {": ", trim_http(line.substr(colon + 1)), "\r\n"});
                appended != ucall_status_success_k)
                return appended;
        }
        return ucall_status_success_k;
    }
    static ucall_status_t serialize_reply(server_exchange_t& exchange, unsigned status,
                                          span<ucall_bytes_view_t const> headers, std::string_view body) noexcept {
        if (!exchange.output.empty()) return ucall_status_already_exists_k;
        if (status < 200 || status > 599 || ((status == 204 || status == 304) && !body.empty()))
            return ucall_status_invalid_argument_k;
        static constexpr std::string_view classes_k[] {"Successful", "Redirection", "Client Error", "Server Error"};
        char digits[std::numeric_limits<std::size_t>::digits10 + 1], date[http_date_length_k];
        if (st::failed(exchange.output.resize(exchange.geometry.headroom))) return ucall_status_out_of_memory_k;
        auto line = status_line(status);
        ucall_status_t result = line.empty()
                                    ? append_text(exchange.output, {"HTTP/1.1 ", format_decimal(digits, status), " ",
                                                                    classes_k[status / 100 - 2], "\r\n"})
                                    : append_text(exchange.output, {line});
        if (result == ucall_status_success_k)
            result = append_text(exchange.output,
                                 {"server: UCall\r\ndate: ", format_date(date, std::time(nullptr)), "\r\n"});
        if (result == ucall_status_success_k)
            result = append_headers(exchange.output, headers, http_role_t::response_k);
        if (result == ucall_status_success_k && status != 204 && status != 304)
            result = append_text(exchange.output, {"content-length: ", format_decimal(digits, body.size()), "\r\n"});
        if (result == ucall_status_success_k)
            result = append_text(
                exchange.output,
                {exchange.message.keep_alive() ? "connection: keep-alive\r\n\r\n" : "connection: close\r\n\r\n",
                 exchange.message.verb != ucall_verb_head_k ? body : std::string_view {}});
        if (result == ucall_status_success_k &&
            st::failed(exchange.output.resize(exchange.output.size() + exchange.geometry.tailroom)))
            result = ucall_status_out_of_memory_k;
        if (result != ucall_status_success_k) {
            exchange.output.clear();
            return result;
        }
        exchange.copied = exchange.message.verb != ucall_verb_head_k ? body.size() : 0;
        return ucall_status_success_k;
    }
    static ucall_status_t reply(server_exchange_t& exchange, unsigned status, span<ucall_bytes_view_t const> headers,
                                std::string_view body) noexcept {
        auto state = atomic_ref<std::uint32_t> {exchange.state};
        auto previous = state.fetch_or(claimed_k, std::memory_order_acq_rel);
        if (previous & claimed_k) return ucall_status_already_exists_k;
        if ((previous & detached_k) ||
            atomic_ref<std::uint32_t> {exchange.event_loop->server->stopped}.load(std::memory_order_acquire)) {
            state.fetch_or(detached_k | ready_k, std::memory_order_release);
            push_replied(exchange);
            return ucall_status_connection_closed_k;
        }
        auto result = serialize_reply(exchange, status, headers, body);
        if (result != ucall_status_success_k) {
            exchange.output.clear();
            state.fetch_and(~std::uint32_t {claimed_k}, std::memory_order_release);
            return result;
        }
        previous = state.fetch_or(ready_k, std::memory_order_release);
        push_replied(exchange);
        return previous & detached_k ? ucall_status_connection_closed_k : ucall_status_success_k;
    }

    /** Hands a finished exchange back to its event loop from any thread; only it recycles one. */
    static void push_replied(server_exchange_t& exchange) noexcept {
        auto* event_loop = exchange.event_loop;
        auto head = atomic_ref<server_exchange_t*> {event_loop->replied};
        auto* next = head.load(std::memory_order_relaxed);
        // The link is written before publishing, so the loop never follows a stale `replied_next`.
        do {
            exchange.replied_next = next;
        } while (!head.compare_exchange_weak(next, &exchange, std::memory_order_release, std::memory_order_relaxed));
        event_loop->notify();
    }

    /** Unlinks every exchange of a closed connection: collected ones recycle now, the rest once
     *  their reply or the stop path returns them. */
    static void detach(event_loop_t& event_loop, connection_t& connection) noexcept {
        for (auto* exchange = connection.oldest_exchange; exchange;) {
            auto* next = std::exchange(exchange->connection_next, nullptr);
            exchange->connection = nullptr;
            if (exchange->stage == exchange_stage_t::collected_k) recycle_exchange(event_loop, *exchange);
            else atomic_ref<std::uint32_t> {exchange->state}.fetch_or(detached_k, std::memory_order_release);
            exchange = next;
        }
        connection.oldest_exchange = connection.newest_exchange = nullptr;
        connection.exchanges_in_flight = 0;
    }
    static void recycle_exchange(event_loop_t& event_loop, server_exchange_t& exchange) noexcept {
        tally(event_loop.statistics.bytes_copied, std::exchange(exchange.copied, 0));
        exchange.input.clear();
        exchange.output.clear();
        crypto_t::secure_zero(exchange.peer_static_key);
        exchange.replied_next = event_loop.free_exchanges;
        event_loop.free_exchanges = &exchange;
    }
    static void mark_ready(event_loop_t& event_loop, connection_t& connection) noexcept {
        if (connection.flags & connection_ready_k) return;
        connection.flags = static_cast<connection_flags_t>(connection.flags | connection_ready_k);
        connection.next = event_loop.ready;
        event_loop.ready = &connection;
    }

    /** Takes the replied list whole; a reply stays on its connection until sent,
     *  and only orphans recycle here. */
    static ucall_status_t collect_replies(event_loop_t& event_loop) noexcept {
        auto* exchange = atomic_ref<server_exchange_t*> {event_loop.replied}.exchange(nullptr,
                                                                                      std::memory_order_acq_rel);
        if (!exchange) return ucall_status_would_block_k;
        while (exchange) {
            auto* next = exchange->replied_next;
            if (auto* connection = exchange->connection) {
                exchange->stage = exchange_stage_t::collected_k;
                if (atomic_ref<std::uint32_t> {exchange->state}.load(std::memory_order_acquire) & detached_k)
                    connection->fail(ucall_status_connection_closed_k);
                mark_ready(event_loop, *connection);
            }
            else recycle_exchange(event_loop, *exchange);
            exchange = next;
        }
        return ucall_status_success_k;
    }

    /** Answers on the event loop itself, failing the connection when no reply was queued. */
    static void refuse(connection_t& connection, server_exchange_t& exchange, unsigned status,
                       std::string_view body) noexcept {
        auto result = reply(exchange, status, {}, body);
        if (result == ucall_status_success_k || result == ucall_status_connection_closed_k) return;
        exchange.stage = exchange_stage_t::collected_k; // Never pushed, so the close recycles it.
        connection.fail(ucall_status_out_of_memory_k);
    }

    /** A fresh exchange at the back of @p connection's FIFO,
     *  or null once the connection failed for memory. */
    static server_exchange_t* enqueue_exchange(event_loop_t& event_loop, connection_t& connection) noexcept {
        auto* exchange = event_loop.free_exchanges;
        if (exchange) event_loop.free_exchanges = exchange->replied_next;
        else if ((exchange =
                      allocate_unique<server_exchange_t>(event_loop.allocator, event_loop.allocator).release())) {
            exchange->next = event_loop.exchanges;
            event_loop.exchanges = exchange;
        }
        if (!exchange) {
            connection.fail(ucall_status_out_of_memory_k);
            return nullptr;
        }
        exchange->state = 0;
        exchange->stage = exchange_stage_t::dispatched_k;
        exchange->event_loop = &event_loop;
        exchange->connection = &connection;
        exchange->endpoint = nullptr;
        exchange->network_interface = connection.network_interface;
        exchange->geometry = connection.tunnel.geometry();
        std::memcpy(exchange->peer_static_key, connection.peer_static_key, sizeof(exchange->peer_static_key));
        if (connection.newest_exchange) connection.newest_exchange->connection_next = exchange;
        else connection.oldest_exchange = exchange;
        connection.newest_exchange = exchange;
        ++connection.exchanges_in_flight;
        return exchange;
    }

    /** Moves the request parsed at @p offset of `input` into a fresh exchange, and routes it. */
    static void dispatch(server_t& server, event_loop_t& event_loop, connection_t& connection,
                         std::size_t offset) noexcept {
        auto* exchange = enqueue_exchange(event_loop, connection);
        if (!exchange) return;
        auto wire = connection.message.wire_length;
        if (!offset && wire == connection.input.size()) std::swap(exchange->input, connection.input);
        else if (ucall_status_t const appended = append_text(exchange->input,
                                                             {text_view(connection.input).substr(offset, wire)});
                 appended == ucall_status_success_k)
            tally(event_loop.statistics.bytes_copied, wire);
        else {
            exchange->stage = exchange_stage_t::collected_k; // Never handed out, so the close recycles it.
            return connection.fail(appended);
        }
        tally(event_loop.statistics.requests);
        exchange->message = std::exchange(connection.message, http_message_t {});
        auto path = extract_path_component<http_t>(exchange->message.target(exchange->text()));
        auto* endpoint = static_cast<endpoint_t*>(server.routes.match(path, exchange->message.verb));
        exchange->endpoint = endpoint;
        if (!endpoint) return refuse(connection, *exchange, 404, "Not found");
        if (endpoint->callback) return endpoint->callback(exchange, endpoint->context);
        auto& batch = *endpoint->batch;
        auto tail = atomic_ref<std::uint64_t> {batch.tail};
        // Exchanges of closed connections outlive their admission, so this check alone bounds it.
        if (tail.load(std::memory_order_relaxed) -
                atomic_ref<std::uint64_t> {batch.head}.load(std::memory_order_acquire) >=
            server.requests_budget)
            return refuse(connection, *exchange, 503, "Batch queue full");
        exchange->deposited = monotonic_ns();
        auto index = tail.fetch_add(1, std::memory_order_seq_cst);
        atomic_ref<server_exchange_t*> {batch.slots[index & (batch.slots.size() - 1)]}.store(exchange,
                                                                                             std::memory_order_release);
        auto drain = atomic_ref<drain_state_t> {batch.drain};
        if (drain.load(std::memory_order_seq_cst) == drain_state_t::sleeping_k &&
            drain.exchange(drain_state_t::draining_k, std::memory_order_seq_cst) == drain_state_t::sleeping_k)
            batch.wake.notify();
    }

    /** Queues the refusal of a request that cannot be parsed behind every earlier reply. */
    static void refuse_unparsable(event_loop_t& event_loop, connection_t& connection, http_parse_t parsed) noexcept {
        connection.input.clear();
        connection.message = {};
        auto* exchange = enqueue_exchange(event_loop, connection);
        if (!exchange) return;
        exchange->message = {}; // A default message never keeps the connection alive.
        refuse(connection, *exchange,
               parsed == http_parse_t::unsupported_k ? 501
               : parsed == http_parse_t::overflow_k  ? 413
                                                     : 400,
               {});
    }

    /** Steps an open server connection, answering its next engine request or null, by these rules
     *  in order:
     *  R1 reply finished: the oldest reply is all sent, so pop and recycle it, and a full receive
     *     side reads again.
     *  R2 requests: while reading, dispatch each complete request; the depth makes the side full,
     *     and `connection: close`, a peer close, or an unparsable request, refused in its turn,
     *     ends it.
     *  R3 next reply: an idle transmit side starts on the oldest exchange once its reply is
     *     collected.
     *  R4 emit: the next chunk of that reply while its send is idle, else a receive while reading.
     *  R5 done: ended with every reply sent, the connection lingers half-closed until the peer
     *     closes, so request bytes it never read cannot turn the close into a reset. */
    static io_request_t* serve_open(server_t& server, event_loop_t& event_loop, connection_t& connection) noexcept {
        auto* oldest = connection.oldest_exchange;
        if (connection.transmitting == transmit_state_t::sending_k &&
            connection.transmit_operation == operation_state_t::idle_k && !connection.sending &&
            connection.output_offset == oldest->output.size()) {
            connection.oldest_exchange = std::exchange(oldest->connection_next, nullptr);
            if (!connection.oldest_exchange) connection.newest_exchange = nullptr;
            --connection.exchanges_in_flight;
            oldest->connection = nullptr;
            recycle_exchange(event_loop, *oldest);
            connection.transmitting = transmit_state_t::idle_k;
            connection.output_offset = 0;
            if (connection.receiving == receive_state_t::full_k) connection.receiving = receive_state_t::reading_k;
        }
        connection.open_records();
        auto depth = connection.network_interface->config.max_pipelined_requests;
        // Requests dispatched this round, erased from `input` once after it rather than one by one.
        std::size_t consumed = 0;
        while (connection.stage == connection_stage_t::open_k && connection.receiving == receive_state_t::reading_k) {
            if (connection.exchanges_in_flight == depth) {
                connection.receiving = receive_state_t::full_k;
                break;
            }
            span<byte_t> unparsed {connection.input.data() + consumed,
                                   connection.input.data() + connection.input.size()};
            auto parsed = http_parse(unparsed, connection.message, http_role_t::request_k);
            if (parsed == http_parse_t::incomplete_k) {
                if (connection.flags & connection_peer_closed_k) connection.receiving = receive_state_t::ended_k;
                break;
            }
            if (parsed != http_parse_t::complete_k) {
                connection.receiving = receive_state_t::ended_k;
                refuse_unparsable(event_loop, connection, parsed);
                consumed = 0;
                break;
            }
            http_decode_chunks(unparsed, connection.message);
            if (!connection.message.keep_alive()) connection.receiving = receive_state_t::ended_k;
            auto wire = connection.message.wire_length;
            dispatch(server, event_loop, connection, consumed);
            consumed = connection.input.empty() ? 0 : consumed + wire;
        }
        if (consumed) drop_bytes(connection.input, consumed);
        if (connection.stage != connection_stage_t::open_k) return connection.advance();
        oldest = connection.oldest_exchange;
        if (connection.transmitting == transmit_state_t::idle_k && oldest &&
            oldest->stage == exchange_stage_t::collected_k)
            connection.transmitting = transmit_state_t::sending_k;
        if (connection.transmitting == transmit_state_t::sending_k &&
            connection.transmit_operation == operation_state_t::idle_k) {
            if (auto* next = connection.transmit_from(oldest->output)) return next;
            return connection.advance(); // Sealing failed the connection.
        }
        if (connection.receiving == receive_state_t::reading_k &&
            connection.receive_operation == operation_state_t::idle_k)
            return connection.emit(connection.receive_request, io_operation_t::receive_k, connection.received);
        if (connection.receiving == receive_state_t::ended_k && !oldest &&
            connection.transmitting == transmit_state_t::idle_k) {
            // A peer that closed left nothing unread, so only a live receive side lingers.
            if (connection.flags & connection_peer_closed_k) connection.fail(ucall_status_success_k);
            else {
                connection.stage = connection_stage_t::lingering_k;
                connection.deadline = deadline_after(linger_microseconds_k);
            }
            return connection.advance();
        }
        return nullptr;
    }
    static void release_admission(server_t& server, network_interface_t& network_interface) noexcept {
        auto before = atomic_ref<std::size_t> {network_interface.active}.fetch_sub(1, std::memory_order_relaxed);
        if (before == network_interface.config.max_concurrent_connections)
            for (auto& event_loop : server.event_loops) event_loop->notify();
    }
    static server_mode_t server_mode(server_t& server) noexcept {
        return atomic_ref<std::uint32_t> {server.stopped}.load(std::memory_order_acquire) ? server_mode_t::stopping_k
                                                                                          : server_mode_t::serving_k;
    }
    static void advance_connection(server_t& server, event_loop_t& event_loop, connection_t& connection,
                                   server_mode_t mode) noexcept {
        auto& engine = event_loop.engine;
        if (connection.stage == connection_stage_t::idle_k) return;
        if (mode == server_mode_t::stopping_k && connection.stage != connection_stage_t::closing_k &&
            connection.stage != connection_stage_t::closed_k)
            connection.fail(ucall_status_connection_closed_k);
        for (;;) {
            auto* next = connection.advance();
            if (!next && connection.stage == connection_stage_t::open_k)
                next = serve_open(server, event_loop, connection);
            if (!next) break;
            // A failed submission is retried on the loop's next round rather than this one.
            if (engine.submit(*next) != ucall_status_success_k) {
                mark_ready(event_loop, connection);
                return;
            }
            connection.submitted(*next);
        }
        // The close waits until the other direction's operation completes or is cancelled.
        if (connection.stage == connection_stage_t::closing_k) {
            if (connection.receive_operation == operation_state_t::pending_k &&
                connection.receive_request.operation != io_operation_t::close_k)
                engine.cancel(connection.receive_request);
            if (connection.transmit_operation == operation_state_t::pending_k)
                engine.cancel(connection.transmit_request);
        }
        if (connection.stage == connection_stage_t::closed_k) {
            detach(event_loop, connection);
            release_admission(server, *connection.network_interface);
            connection.tunnel.reset();
            connection.input.clear();
            connection.encrypted.clear();
            connection.output.clear();
            connection.sending = nullptr;
            connection.output_offset = 0;
            connection.flags = static_cast<connection_flags_t>(connection.flags & ~connection_peer_closed_k);
            connection.stage = connection_stage_t::idle_k;
            connection.next = event_loop.idle;
            event_loop.idle = &connection;
        }
    }
    static ucall_status_t server_progress(server_t& server, event_loop_t& event_loop) noexcept {
        auto& engine = event_loop.engine;
        auto mode = server_mode(server);
        for (auto& acceptor : event_loop.interface_acceptors) {
            if (mode == server_mode_t::stopping_k) {
                if (acceptor.stage == interface_acceptor_t::stage_t::pending_k) { engine.cancel(acceptor.request); }
                continue;
            }
            if (acceptor.stage == interface_acceptor_t::stage_t::pending_k || !event_loop.idle) continue;
            auto& network_interface = *acceptor.network_interface;
            auto active = atomic_ref<std::size_t> {network_interface.active};
            auto before = active.fetch_add_if_at_most(1, network_interface.config.max_concurrent_connections,
                                                      std::memory_order_relaxed);
            if (before >= network_interface.config.max_concurrent_connections) continue;
            if (engine.submit(acceptor.request) == ucall_status_success_k)
                acceptor.stage = interface_acceptor_t::stage_t::pending_k;
            else active.fetch_sub(1, std::memory_order_relaxed);
        }
        collect_replies(event_loop);
        if (mode == server_mode_t::stopping_k) {
            for (; event_loop.ready; event_loop.ready = event_loop.ready->next)
                event_loop.ready->flags = static_cast<connection_flags_t>(event_loop.ready->flags &
                                                                          ~connection_ready_k);
            for (auto& connection : event_loop.connections) advance_connection(server, event_loop, *connection, mode);
        }
        else do {
                for (auto* connection = std::exchange(event_loop.ready, nullptr); connection;) {
                    auto& current = *connection;
                    connection = current.next;
                    current.flags = static_cast<connection_flags_t>(current.flags & ~connection_ready_k);
                    advance_connection(server, event_loop, current, mode);
                }
            } while (collect_replies(event_loop) == ucall_status_success_k);
        if (mode == server_mode_t::stopping_k) {
            bool busy = false;
            for (auto& acceptor : event_loop.interface_acceptors)
                busy |= acceptor.stage == interface_acceptor_t::stage_t::pending_k;
            for (auto& connection : event_loop.connections) busy |= connection->stage != connection_stage_t::idle_k;
            if (!busy) {
                for (auto& acceptor : event_loop.interface_acceptors)
                    if (acceptor.request.descriptor >= 0) {
                        engine.close_socket(acceptor.request.descriptor);
                        acceptor.request.descriptor = -1;
                    }
                // Retire the engine on its polling owner, as a single-issuer ring completes
                // nothing for another thread.
                engine.stop();
                event_loop.stage = event_loop_stage_t::quiesced_k;
            }
        }
        return ucall_status_success_k;
    }
    static void accepted(io_completion_t const& completion) noexcept {
        auto& acceptor = *static_cast<interface_acceptor_t*>(completion.request->context);
        auto& event_loop = *acceptor.event_loop;
        auto& server = *event_loop.server;
        auto& network_interface = *acceptor.network_interface;
        acceptor.stage = interface_acceptor_t::stage_t::idle_k;
        if (completion.result < 0) {
            release_admission(server, network_interface);
            if (completion.result != -ECONNABORTED && completion.result != -ECANCELED) {
                atomic_ref<ucall_status_t> {server.failure}.store(ucall_status_io_k, std::memory_order_release);
                server_stop(&server);
            }
            return;
        }
        auto* chosen = event_loop.idle;
        if (!chosen || atomic_ref<std::uint32_t> {server.stopped}.load(std::memory_order_acquire)) {
            event_loop.engine.close_socket(completion.result);
            release_admission(server, network_interface);
            return;
        }
        tally(event_loop.statistics.accepts);
        event_loop.idle = chosen->next;
        chosen->descriptor = completion.result;
        chosen->network_interface = &network_interface;
        chosen->stage = connection_stage_t::handshake_k;
        chosen->status = ucall_status_success_k;
        chosen->authorizer = network_interface.config.peer_authorizer;
        chosen->authorizer_context = network_interface.config.peer_authorizer_context;
        auto result = chosen->configure(
            tunnel_config(network_interface.config.security_mode, secure_tunnel_role_t::responder_k,
                          network_interface.config.noise_private_key, network_interface.public_key, nullptr));
        if (result != ucall_status_success_k) chosen->fail(result);
        mark_ready(event_loop, *chosen);
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
        if (!server || st::failed(server->resolved.resize(config->interfaces_count))) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
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
        for (std::size_t i = 0; i != config->interfaces_count; ++i) {
            auto& network_interface = server->network_interfaces[i];
            network_interface.config = config->interfaces[i];
            if (network_interface.config.noise_private_key) {
                std::memcpy(network_interface.private_key, *network_interface.config.noise_private_key,
                            sizeof(network_interface.private_key));
                network_interface.config.noise_private_key = &network_interface.private_key;
            }
            auto& settings = network_interface.config;
            if (settings.device_name) {
                if (ucall_status_t const copied = copy_text(network_interface.device, settings.device_name);
                    copied != ucall_status_success_k) {
                    publish(arguments->outcome, copied);
                    return;
                }
                settings.device_name = network_interface.device.data();
            }
            if (!settings.address || !security_valid(settings.security_mode) ||
                (settings.security_mode != ucall_security_mode_none_k && !settings.noise_private_key) ||
                (settings.security_mode == ucall_security_mode_noise_xx_k && !settings.peer_authorizer) ||
                settings.security_mode == ucall_security_mode_noise_kk_k) {
                publish(arguments->outcome, ucall_status_invalid_argument_k);
                return;
            }
#if !UCALL_OS_LINUX_
            if (settings.device_name) {
                publish(arguments->outcome, ucall_status_unsupported_k);
                return;
            }
#endif
            if (!settings.max_concurrent_connections) {
                publish(arguments->outcome, ucall_status_invalid_argument_k);
                return;
            }
            if (!settings.event_loops) settings.event_loops = interface_event_loops(settings.device_name);
            if (!settings.event_loops) {
                publish(arguments->outcome, ucall_status_invalid_argument_k);
                return;
            }
            if (settings.event_loops > settings.max_concurrent_connections)
                settings.event_loops = settings.max_concurrent_connections;
            if (!settings.max_pipelined_requests) settings.max_pipelined_requests = 1;
            if (settings.max_pipelined_requests > std::numeric_limits<std::uint32_t>::max() ||
                settings.max_concurrent_connections >
                    std::numeric_limits<std::size_t>::max() / settings.max_pipelined_requests ||
                settings.max_concurrent_connections * settings.max_pipelined_requests >
                    std::numeric_limits<std::size_t>::max() - server->requests_budget) {
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
            event_loops_count = std::max(event_loops_count, settings.event_loops);
            if (settings.noise_private_key)
                x25519_derive_public(network_interface.public_key,
                                     std::as_bytes(std::span {*settings.noise_private_key}));
        }
        {
            engine_t probe {allocator};
            auto status = probe.open(1, 1);
            if (status != ucall_status_success_k) {
                publish(arguments->outcome, status);
                return;
            }
        }
        if (st::failed(server->event_loops.resize(event_loops_count)) ||
            st::failed(server->owned_wakeups.resize(event_loops_count))) {
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
            server->owned_wakeups[event_loop_index] = &event_loop.wake;
            if (ucall_status_t const opened = event_loop.wake.open(); opened != ucall_status_success_k) {
                publish(arguments->outcome, opened);
                return;
            }
            std::size_t connections_count = 0, acceptors_count = 0;
            for (auto& network_interface : server->network_interfaces)
                if (event_loop_index < network_interface.config.event_loops) {
                    auto quota = network_interface.config.max_concurrent_connections /
                                     network_interface.config.event_loops +
                                 (event_loop_index < network_interface.config.max_concurrent_connections %
                                                         network_interface.config.event_loops);
                    if (quota > std::numeric_limits<std::size_t>::max() - connections_count) {
                        publish(arguments->outcome, ucall_status_overflow_k);
                        return;
                    }
                    connections_count += quota;
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
            for (std::size_t i = 0; i != acceptors_count; ++i) std::construct_at(acceptors + i);
            event_loop.interface_acceptors = {acceptors, acceptors_count};
            for (auto& connection : event_loop.connections) {
                connection = allocate_unique<connection_t>(allocator, allocator);
                if (!connection) {
                    publish(arguments->outcome, ucall_status_out_of_memory_k);
                    return;
                }
                connection->statistics = &event_loop.statistics;
                connection->next = event_loop.idle;
                event_loop.idle = connection.get();
            }
            std::size_t acceptor_index = 0;
            for (auto& network_interface : server->network_interfaces)
                if (event_loop_index < network_interface.config.event_loops) {
                    auto& acceptor = event_loop.interface_acceptors[acceptor_index++];
                    acceptor.event_loop = &event_loop;
                    ucall_status_t result;
                    if (!event_loop_index) result = bind_acceptor(network_interface, acceptor);
#if UCALL_OS_POSIX_
                    else {
                        auto network_interface_index = static_cast<std::size_t>(&network_interface -
                                                                                server->network_interfaces.data());
                        auto& first = server->event_loops[0]->interface_acceptors[network_interface_index];
                        int descriptor = fcntl(static_cast<int>(first.request.descriptor), F_DUPFD_CLOEXEC, 0);
                        result = descriptor >= 0 ? ucall_status_success_k : ucall_status_io_k;
                        acceptor.network_interface = &network_interface;
                        acceptor.request = {io_operation_t::accept_k, descriptor, nullptr, 0, 0, &acceptor};
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
        server->wakeups = server->owned_wakeups;
        server->config = *config;
        for (std::size_t i = 0; i != config->interfaces_count; ++i)
            server->resolved[i] = server->network_interfaces[i].config;
        server->config.interfaces = server->resolved.data();
        if (arguments->resolved) *arguments->resolved = server->config;
        server->string_capabilities = capabilities_k;
        server->atomic_capabilities = static_cast<std::uint64_t>(atomic_ref<std::uint32_t>::capabilities_k);
        server->api = &server_api_k;
        *arguments->server = server.release();
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void server_stop(ucall_server_t handle) noexcept {
        if (!handle) return;
        auto& server = *static_cast<server_t*>(handle);
        atomic_ref<std::uint32_t> {server.stopped}.store(1, std::memory_order_release);
        for (auto& event_loop : server.event_loops) event_loop->notify();
        for (auto* endpoint : server.batch_endpoints) endpoint->wake.notify();
    }
    static ucall_status_t open_event_loop(event_loop_t& event_loop) noexcept {
        if (event_loop.stage != event_loop_stage_t::unopened_k) return event_loop.setup_status;
        // Each connection keeps one operation per direction; the wakeup occupies one more slot.
        auto connections = event_loop.connections.size(), acceptors = event_loop.interface_acceptors.size();
        if (connections > (std::numeric_limits<std::size_t>::max() - acceptors - 1) / 2) return ucall_status_overflow_k;
        auto slots = 2 * connections + acceptors + 1;
        auto status = event_loop.engine.open(slots, slots);
        if (status != ucall_status_success_k) return status;
        event_loop.stage = event_loop_stage_t::ready_k;
        if (st::failed(event_loop.completions.resize(slots))) return ucall_status_out_of_memory_k;
        auto descriptor = event_loop.engine.import_socket(event_loop.wake.descriptors[0]);
        if (descriptor < 0) return ucall_status_io_k;
        event_loop.wake.descriptors[0] = -1;
        event_loop.wake.request.descriptor = descriptor;
        if (event_loop.engine.submit(event_loop.wake.request) != ucall_status_success_k) return ucall_status_io_k;
        for (auto& acceptor : event_loop.interface_acceptors) {
            auto imported = event_loop.engine.import_socket(acceptor.request.descriptor);
            if (imported < 0) return ucall_status_io_k;
            acceptor.request.descriptor = imported;
            acceptor.descriptor = -1;
        }
        return ucall_status_success_k;
    }
    static void advance_completion(engine_t& engine, io_completion_t const& completion) noexcept {
        if (completion.request->operation == io_operation_t::accept_k) accepted(completion);
        else {
            auto& connection = *static_cast<connection_t*>(completion.request->context);
            bool connected = connection.stage == connection_stage_t::connecting_k && completion.result >= 0;
            connection.complete(completion);
            if (connected && connection.peer && connection.peer->oldest_exchange)
                connection.deadline = connection.peer->oldest_exchange->deadline;
        }
        engine.release(completion);
    }
    static ucall_status_t server_poll(server_t& server, event_loop_t& event_loop, io_wait_t wait,
                                      std::uint64_t deadline = 0) noexcept {
        if (event_loop.stage == event_loop_stage_t::quiesced_k)
            return atomic_ref<ucall_status_t> {server.failure}.load(std::memory_order_acquire);
        if (event_loop.setup_status != ucall_status_success_k) return event_loop.setup_status;
        event_loop.setup_status = open_event_loop(event_loop);
        if (event_loop.setup_status != ucall_status_success_k) return event_loop.setup_status;
        atomic_ref<std::uint32_t> {server.serving}.store(1, std::memory_order_release);
        atomic_ref<std::uint32_t> {event_loop.wake_pending}.store(0, std::memory_order_release);
        server_progress(server, event_loop);
        if (event_loop.stage == event_loop_stage_t::quiesced_k)
            return atomic_ref<ucall_status_t> {server.failure}.load(std::memory_order_acquire);
        int count = event_loop.engine.poll(span<io_completion_t> {event_loop.completions}, wait, deadline);
        if (count < 0) {
            atomic_ref<ucall_status_t> {server.failure}.store(ucall_status_io_k, std::memory_order_release);
            server_stop(&server);
            event_loop.engine.stop();
            event_loop.stage = event_loop_stage_t::quiesced_k;
            return ucall_status_io_k;
        }
        tally(event_loop.statistics.polls);
        if (!count) tally(event_loop.statistics.empty_polls);
        for (int i = 0; i != count; ++i) {
            auto& completion = event_loop.completions[static_cast<std::size_t>(i)];
            if (completion.request == &event_loop.wake.request) {
                event_loop.engine.release(completion);
                if (event_loop.engine.submit(event_loop.wake.request) != ucall_status_success_k) {
                    atomic_ref<ucall_status_t> {server.failure}.store(ucall_status_io_k, std::memory_order_release);
                    server_stop(&server);
                }
            }
            else if (completion.request->operation == io_operation_t::accept_k)
                advance_completion(event_loop.engine, completion);
            else {
                auto& connection = *static_cast<connection_t*>(completion.request->context);
                advance_completion(event_loop.engine, completion);
                mark_ready(event_loop, connection);
            }
        }
        server_progress(server, event_loop);
        return atomic_ref<ucall_status_t> {server.failure}.load(std::memory_order_acquire);
    }
    static void server_take_call(ucall_server_take_call_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server) {
            publish(arguments->outcome, ucall_status_uninitialized_k);
            return;
        }
        auto& server = *static_cast<server_t*>(arguments->server);
        if (arguments->event_loop_index >= server.event_loops.size()) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto wait = arguments->timeout_microseconds ? io_wait_t::blocking_k : io_wait_t::nonblocking_k;
        auto deadline = arguments->timeout_microseconds ? deadline_after(arguments->timeout_microseconds) : 0;
        auto& event_loop = *server.event_loops[arguments->event_loop_index];
        auto* previous = std::exchange(polling_event_loop, &event_loop);
        auto status = server_poll(server, event_loop, wait, deadline);
        polling_event_loop = previous;
        publish(arguments->outcome, status);
    }
    static void server_take_calls(ucall_server_take_calls_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server) {
            publish(arguments->outcome, ucall_status_uninitialized_k);
            return;
        }
        auto& server = *static_cast<server_t*>(arguments->server);
        if (arguments->event_loop_index >= server.event_loops.size()) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& event_loop = *server.event_loops[arguments->event_loop_index];
        ucall_status_t status = ucall_status_success_k;
        auto* previous = std::exchange(polling_event_loop, &event_loop);
        while (event_loop.stage != event_loop_stage_t::quiesced_k && status == ucall_status_success_k)
            status = server_poll(server, event_loop, io_wait_t::blocking_k);
        polling_event_loop = previous;
        publish(arguments->outcome, status);
    }
    static void server_event_loop_statistics(ucall_server_event_loop_statistics_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server) {
            publish(arguments->outcome, ucall_status_uninitialized_k);
            return;
        }
        auto& server = *static_cast<server_t*>(arguments->server);
        if (!arguments->statistics || arguments->event_loop_index >= server.event_loops.size()) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& event_loop = *server.event_loops[arguments->event_loop_index];
        auto& loop = event_loop.statistics;
        auto& engine = event_loop.engine.statistics;
        auto read = [](std::uint64_t& counter) noexcept {
            return std::atomic_ref<std::uint64_t> {counter}.load(std::memory_order_relaxed);
        };
        *arguments->statistics = {.polls = read(loop.polls),
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
                                  .bytes_copied = read(loop.bytes_copied) + read(engine.bytes_copied)};
        publish(arguments->outcome, ucall_status_success_k);
    }

    /** Hands the pending batch to its callback and counts it under @p trigger, the counter of why
     *  it fired, or detaches it while stopping, firing and counting nothing. */
    static ucall_status_t flush_pending(batch_endpoint_t& endpoint, server_mode_t mode,
                                        std::uint64_t& trigger) noexcept {
        if (endpoint.pending.empty()) return ucall_status_would_block_k;
        if (mode == server_mode_t::stopping_k)
            for (auto handle : endpoint.pending) {
                auto& exchange = *static_cast<server_exchange_t*>(handle);
                atomic_ref<std::uint32_t> {exchange.state}.fetch_or(claimed_k | ready_k | detached_k,
                                                                    std::memory_order_release);
                push_replied(exchange);
            }
        else {
            tally(endpoint.statistics.batches);
            tally(endpoint.statistics.requests, endpoint.pending.size());
            tally(trigger);
            endpoint.callback(endpoint.pending.data(), endpoint.pending.size(), endpoint.context);
        }
        endpoint.pending.clear();
        return mode == server_mode_t::serving_k ? ucall_status_success_k : ucall_status_would_block_k;
    }

    /** One drain round of one batch endpoint: moves its deposits to `pending`, invokes the batch
     *  if due, and sets @p expiry to when the waiting remainder falls due, or zero when nothing
     *  waits. Succeeds when the callback fired, or reports @c ucall_status_would_block_k. */
    static ucall_status_t drain_batch(batch_endpoint_t& endpoint, server_mode_t mode, std::uint64_t& expiry) noexcept {
        auto tail = atomic_ref<std::uint64_t> {endpoint.tail}.load(std::memory_order_acquire);
        ucall_status_t drained = ucall_status_would_block_k;
        auto head = endpoint.head;
        for (; head != tail; ++head) {
            auto slot = atomic_ref<server_exchange_t*> {endpoint.slots[head & (endpoint.slots.size() - 1)]};
            auto* exchange = slot.load(std::memory_order_acquire);
            // The depositor has claimed this index and stores into it right after.
            while (!exchange) {
                fu::standard_yield_t {}(slot, exchange, 0);
                exchange = slot.load(std::memory_order_acquire);
            }
            slot.store(nullptr, std::memory_order_relaxed);
            [[maybe_unused]] st::status_t const queued = endpoint.pending.push_back(st::assume_reserved, exchange);
            if (endpoint.pending.size() == endpoint.max_batch_size &&
                flush_pending(endpoint, mode, endpoint.statistics.filled_batches) == ucall_status_success_k)
                drained = ucall_status_success_k;
        }
        atomic_ref<std::uint64_t> {endpoint.head}.store(head, std::memory_order_release);
        expiry = 0;
        if (endpoint.pending.empty()) return drained;
        auto deposited = static_cast<server_exchange_t*>(endpoint.pending.front())->deposited;
        auto maximum = std::numeric_limits<std::uint64_t>::max();
        auto due = endpoint.max_latency_microseconds > (maximum - deposited) / 1000
                       ? maximum
                       : deposited + endpoint.max_latency_microseconds * 1000;
        auto ready = endpoint.pending.size() >= endpoint.min_batch_size;
        if (mode == server_mode_t::stopping_k || ready || monotonic_ns() >= due) {
            auto& trigger = ready ? endpoint.statistics.ready_batches : endpoint.statistics.expired_batches;
            if (flush_pending(endpoint, mode, trigger) == ucall_status_success_k) drained = ucall_status_success_k;
        }
        else expiry = due;
        return drained;
    }

    /** Sleeps on the endpoint's wake channel until a deposit, a stop, or @p deadline, zero meaning
     *  none. Depositors wake only a sleeping drain, so it announces sleep before its last look at
     *  the queue. */
    static void await_deposits(server_t& server, batch_endpoint_t& endpoint, std::uint64_t deadline) noexcept {
        auto drain = atomic_ref<drain_state_t> {endpoint.drain};
        drain.store(drain_state_t::sleeping_k, std::memory_order_seq_cst);
        if (atomic_ref<std::uint64_t> {endpoint.tail}.load(std::memory_order_seq_cst) == endpoint.head &&
            server_mode(server) == server_mode_t::serving_k)
            endpoint.wake.wait(deadline);
        drain.store(drain_state_t::draining_k, std::memory_order_seq_cst);
    }
    static void server_take_batch(ucall_server_take_batch_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server) {
            publish(arguments->outcome, ucall_status_uninitialized_k);
            return;
        }
        if (!arguments->endpoint) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& server = *static_cast<server_t*>(arguments->server);
        auto& endpoint = *static_cast<batch_endpoint_t*>(arguments->endpoint);
        auto deadline = arguments->timeout_microseconds ? deadline_after(arguments->timeout_microseconds) : 0;
        for (;;) {
            std::uint64_t expiry {};
            auto mode = server_mode(server);
            if (drain_batch(endpoint, mode, expiry) == ucall_status_success_k || mode == server_mode_t::stopping_k ||
                monotonic_ns() >= deadline)
                break;
            await_deposits(server, endpoint, expiry ? std::min(expiry, deadline) : deadline);
        }
        publish(arguments->outcome, atomic_ref<ucall_status_t> {server.failure}.load(std::memory_order_acquire));
    }
    static void server_take_batches(ucall_server_take_batches_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server) {
            publish(arguments->outcome, ucall_status_uninitialized_k);
            return;
        }
        if (!arguments->endpoint) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& server = *static_cast<server_t*>(arguments->server);
        auto& endpoint = *static_cast<batch_endpoint_t*>(arguments->endpoint);
        for (;;) {
            std::uint64_t expiry {};
            auto mode = server_mode(server);
            drain_batch(endpoint, mode, expiry);
            if (mode == server_mode_t::stopping_k) break;
            await_deposits(server, endpoint, expiry);
        }
        publish(arguments->outcome, atomic_ref<ucall_status_t> {server.failure}.load(std::memory_order_acquire));
    }
    static void server_batch_endpoint_statistics(ucall_server_batch_endpoint_statistics_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server) {
            publish(arguments->outcome, ucall_status_uninitialized_k);
            return;
        }
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
        server_stop(handle);
        for (auto& event_loop : server.event_loops)
            while (event_loop->stage == event_loop_stage_t::ready_k &&
                   event_loop->setup_status == ucall_status_success_k)
                if (server_poll(server, *event_loop, io_wait_t::blocking_k) != ucall_status_success_k) break;
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
            if ((existing->callback || (existing->batch && existing->batch->callback)) &&
                existing->verb == arguments->verb && equal(existing->path, path)) {
                publish(arguments->outcome, ucall_status_already_exists_k);
                return;
            }
        auto* endpoint = allocate_unique<endpoint_t>(server.allocator, server.allocator).release();
        ucall_status_t const copied = endpoint ? copy_text(endpoint->storage, path) : ucall_status_out_of_memory_k;
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
            if (batch && !st::failed(batch->pending.reserve(max_batch_size)) &&
                !st::failed(batch->slots.resize(std::bit_ceil(slots))) &&
                !st::failed(server.batch_endpoints.reserve(server.batch_endpoints.size() + 1)) &&
                !st::failed(server.owned_wakeups.reserve(server.owned_wakeups.size() + 1)))
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
            [[maybe_unused]] st::status_t const woken = server.owned_wakeups.push_back(st::assume_reserved,
                                                                                       &batch.wake);
            server.wakeups = server.owned_wakeups;
            *arguments->endpoint = &batch;
        }
        else {
            endpoint->callback = arguments->callback;
            endpoint->context = arguments->context;
        }
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void server_add_http_endpoint(ucall_server_add_http_endpoint_t* arguments) noexcept {
        add_endpoint(arguments);
    }
    static void server_add_http_batch_endpoint(ucall_server_add_http_batch_endpoint_t* arguments) noexcept {
        if (!arguments) return;
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
        if (!arguments) return;
        if (arguments->path) *arguments->path = {};
        if (!arguments->server || !arguments->request || !arguments->path) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        *arguments->path = bytes_view(extract_path_component<http_t>(exchange.message.target(exchange.text())));
        publish(arguments->outcome, ucall_status_success_k);
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
        auto& exchange = *static_cast<server_exchange_t*>(request);
        return count_path_segments<http_t>(extract_path_component<http_t>(exchange.message.target(exchange.text())));
    }
    static void server_request_path_segment(ucall_server_request_path_segment_t* arguments) noexcept {
        if (!arguments) return;
        if (arguments->segment) *arguments->segment = {};
        if (!arguments->server || !arguments->request || !arguments->segment) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        auto value = path_segment(extract_path_component<http_t>(exchange.message.target(exchange.text())),
                                  arguments->index);
        *arguments->segment = bytes_view(value);
        publish(arguments->outcome, value.empty() ? ucall_status_not_found_k : ucall_status_success_k);
    }
    static void server_request_path_parameter(ucall_server_request_path_parameter_t* arguments) noexcept {
        if (!arguments) return;
        if (arguments->value) *arguments->value = {};
        if (!arguments->server || !arguments->request || !arguments->value || !valid_view(arguments->name)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
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
                *arguments->value = bytes_view(value);
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
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        auto target = exchange.message.target(exchange.text());
        auto query_at = find(target, '?');
        auto query = query_at == std::string_view::npos ? std::string_view {} : target.substr(query_at + 1);
        while (!query.empty()) {
            auto end = find(query, '&');
            auto field = query.substr(0, end);
            auto equals = find(field, '=');
            if (equal(field.substr(0, equals), text_view(arguments->name))) {
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
        if (!arguments) return;
        if (arguments->value) *arguments->value = {};
        if (!arguments->server || !arguments->request || !arguments->value || !valid_view(arguments->name) ||
            !http_token(text_view(arguments->name))) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        auto value = exchange.message.header(exchange.text(), text_view(arguments->name));
        *arguments->value = bytes_view(value);
        publish(arguments->outcome, value.data() ? ucall_status_success_k : ucall_status_not_found_k);
    }
    static void server_request_peer(ucall_server_request_peer_t* arguments) noexcept {
        if (!arguments) return;
        if (arguments->network_interface_index) *arguments->network_interface_index = 0;
        if (arguments->static_key) std::memset(*arguments->static_key, 0, sizeof(ucall_noise_key_t));
        if (!arguments->server || !arguments->request || !arguments->network_interface_index ||
            !arguments->static_key) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& server = *static_cast<server_t*>(arguments->server);
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        *arguments->network_interface_index = static_cast<std::size_t>(exchange.network_interface -
                                                                       server.network_interfaces.data());
        std::memcpy(*arguments->static_key, exchange.peer_static_key, sizeof(ucall_noise_key_t));
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void server_request_body(ucall_server_request_body_t* arguments) noexcept {
        if (!arguments) return;
        if (arguments->body) *arguments->body = {};
        if (!arguments->server || !arguments->request || !arguments->body) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& exchange = *static_cast<server_exchange_t*>(arguments->request);
        *arguments->body = bytes_view(exchange.message.body(exchange.text()));
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void server_reply_content(ucall_server_reply_content_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server || !arguments->request || !valid_view(arguments->body) ||
            (arguments->headers_count && !arguments->headers)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        publish(arguments->outcome, reply(*static_cast<server_exchange_t*>(arguments->request),
                                          arguments->http_status ? arguments->http_status : 200,
                                          {arguments->headers, arguments->headers_count}, text_view(arguments->body)));
    }
    static void server_reply_error(ucall_server_reply_error_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server || !arguments->request || !valid_view(arguments->message) ||
            arguments->http_status < 400) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        ucall_bytes_view_t const header = bytes_view("content-type: text/plain");
        publish(arguments->outcome, reply(*static_cast<server_exchange_t*>(arguments->request), arguments->http_status,
                                          {&header, 1}, text_view(arguments->message)));
    }
    struct client_exchange_t {
        explicit client_exchange_t(allocator_t const& allocator = {}) noexcept
            : authority(rebound_allocator<char> {allocator}), target(rebound_allocator<char> {allocator}),
              host(rebound_allocator<char> {allocator}), service(rebound_allocator<char> {allocator}),
              redirect(rebound_allocator<char> {allocator}),
              redirect_headers(rebound_allocator<ucall_bytes_view_t> {allocator}) {}
        client_exchange_t(client_exchange_t const&) = delete;
        client_exchange_t& operator=(client_exchange_t const&) = delete;
        client_exchange_t(client_exchange_t&&) = delete;
        client_exchange_t& operator=(client_exchange_t&&) = delete;

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
        http_connection_t connection_intent {}; // Close, when the caller's own `connection` header asks to.
        client_exchange_t* next {};             // Idle or waiting calls of the client, or a peer's calls in order.
    };
    struct client_peer_t {
        explicit client_peer_t(allocator_t const& allocator = {}) noexcept
            : connection(allocator), authority(rebound_allocator<char> {allocator}) {}
        client_peer_t(client_peer_t const&) = delete;
        client_peer_t& operator=(client_peer_t const&) = delete;
        client_peer_t(client_peer_t&&) = delete;
        client_peer_t& operator=(client_peer_t&&) = delete;

        connection_t connection {};
        client_exchange_t* oldest_exchange {}; // Responses arrive in this order.
        client_exchange_t* newest_exchange {}; // While sending, its request is the one in `connection.output`.
        std::uint32_t exchanges_in_flight {};
        std::size_t answered_calls {}; // Since the dial, telling a reused connection from a fresh one.
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
        span<client_exchange_t> exchanges {};
        client_exchange_t* idle {};                           // Calls free to submit.
        client_exchange_t *waiting_head {}, *waiting_tail {}; // Queued calls, earliest deadline first.
        std::size_t admitted {}, completed_head {}, completed_count {};
        ~client_t() noexcept {
            engine.stop();
            crypto_t::secure_zero(private_key);
            for (auto& peer : peers)
                if (peer) {
                    auto& connection = peer->connection;
                    if (connection.descriptor >= 0 &&
                        !(connection.receive_operation == operation_state_t::pending_k &&
                          connection.receive_request.operation == io_operation_t::close_k &&
                          connection.receive_request.descriptor < 0))
                        engine.close_socket(connection.descriptor);
                    crypto_t::secure_zero(peer->private_key);
                }
            for (std::size_t i = 0; i != completed_count; ++i)
                ucall_client_response_free(completed[(completed_head + i) % completed.size()].response);
            peers.clear();
            for (auto& exchange : exchanges) std::destroy_at(&exchange);
            if (!exchanges.empty())
                rebound_allocator<client_exchange_t> {allocator}.deallocate(exchanges.data(), exchanges.size());
        }
    };
    static ucall_status_t parse_url(client_exchange_t& exchange) noexcept {
        auto url = text_view(exchange.arguments.url);
        auto scheme = find(url, "://");
        if (scheme == std::string_view::npos) return ucall_status_invalid_argument_k;
        auto protocol = url.substr(0, scheme);
        if (protocol != "http" && protocol != "http+noise") return ucall_status_unsupported_k;
        if (protocol == "http+noise" && exchange.arguments.options.security == ucall_security_mode_none_k)
            exchange.arguments.options.security = ucall_security_mode_noise_xx_k;
        auto rest = url.substr(scheme + 3);
        auto slash = find(rest, '/'), query = find(rest, '?'), fragment = find(rest, '#');
        auto boundary = std::min(slash, std::min(query, fragment));
        auto authority = rest.substr(0, boundary);
        if (authority.empty() || find(authority, '@') != std::string_view::npos || !http_value(authority) ||
            find(authority, ' ') != std::string_view::npos || find(authority, '\t') != std::string_view::npos ||
            find(authority, '\0') != std::string_view::npos)
            return ucall_status_invalid_argument_k;
        if (ucall_status_t const copied = copy_text(exchange.authority, authority); copied != ucall_status_success_k)
            return copied;
        exchange.authority_hash = http_t::hash(authority);
        auto tail = boundary == std::string_view::npos ? std::string_view {} : rest.substr(boundary);
        fragment = find(tail, '#');
        tail = tail.substr(0, fragment);
        exchange.target.clear();
        std::string_view const root = tail.empty() || tail.front() != '/' ? "/" : "";
        if (ucall_status_t const appended = append_text(exchange.target, {root, tail});
            appended != ucall_status_success_k)
            return appended;
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
        if (ucall_status_t const copied = copy_text(exchange.host, host); copied != ucall_status_success_k)
            return copied;
        if (ucall_status_t const copied = copy_text(exchange.service, port); copied != ucall_status_success_k)
            return copied;
        exchange.addresses.reset();
        exchange.numeric_address = {};
        exchange.address = nullptr;
        exchange.port = static_cast<std::uint16_t>(number);
        return ucall_status_success_k;
    }
    static ucall_status_t resolve_exchange(client_exchange_t& exchange) noexcept {
        sockaddr_in ipv4 {};
        sockaddr_in6 ipv6 {};
        if (ucall_status_t const started = sockets_start(); started != ucall_status_success_k) return started;
        if (inet_pton(AF_INET, exchange.host.data(), &ipv4.sin_addr) == 1) {
            ipv4.sin_family = AF_INET;
            ipv4.sin_port = htons(exchange.port);
            std::memcpy(&exchange.numeric_socket, &ipv4, sizeof(ipv4));
            exchange.numeric_address.ai_family = AF_INET;
            exchange.numeric_address.ai_addrlen = sizeof(ipv4);
        }
        else if (inet_pton(AF_INET6, exchange.host.data(), &ipv6.sin6_addr) == 1) {
            ipv6.sin6_family = AF_INET6;
            ipv6.sin6_port = htons(exchange.port);
            std::memcpy(&exchange.numeric_socket, &ipv6, sizeof(ipv6));
            exchange.numeric_address.ai_family = AF_INET6;
            exchange.numeric_address.ai_addrlen = sizeof(ipv6);
        }
        if (exchange.numeric_address.ai_addrlen) {
            exchange.numeric_address.ai_socktype = SOCK_STREAM;
            exchange.numeric_address.ai_addr = reinterpret_cast<sockaddr*>(&exchange.numeric_socket);
            exchange.address = &exchange.numeric_address;
            return ucall_status_success_k;
        }
        addrinfo hints {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* resolved = nullptr;
        if (getaddrinfo(exchange.host.data(), exchange.service.data(), &hints, &resolved) != 0)
            return ucall_status_connection_failed_k;
        exchange.addresses.reset(resolved);
        exchange.address = exchange.addresses.get();
        return ucall_status_success_k;
    }
    static ucall_status_t compose_request(connection_t& connection, client_exchange_t const& exchange) noexcept {
        connection.output.clear();
        auto& arguments = exchange.arguments;
        auto target = text_view(exchange.target);
        if (!http_value(target) || find(target, ' ') != std::string_view::npos ||
            find(target, '\t') != std::string_view::npos)
            return ucall_status_invalid_argument_k;
        // A dial composes before it configures the tunnel,
        // so the call's own security sizes the framing.
        bool const framed = secure_tunnel_mode_encrypts(tunnel_mode(arguments.options.security));
        if (st::failed(connection.output.resize(framed ? secure_tunnel_headroom_k : 0)))
            return ucall_status_out_of_memory_k;
        ucall_status_t result = append_text(connection.output,
                                            {http_verb_name(arguments.verb),
                                             " ",
                                             target,
                                             " HTTP/1.1\r\nhost: ",
                                             {exchange.authority.data(), exchange.authority.size() - 1},
                                             "\r\nuser-agent: UCall\r\n"});
        if (result == ucall_status_success_k)
            result = append_headers(connection.output, {arguments.headers, arguments.headers_count},
                                    http_role_t::request_k);
        char digits[std::numeric_limits<std::size_t>::digits10 + 1];
        if (result == ucall_status_success_k)
            result = append_text(connection.output, {"content-length: ", format_decimal(digits, arguments.body.length),
                                                     "\r\n\r\n", text_view(arguments.body)});
        if (result == ucall_status_success_k &&
            st::failed(connection.output.resize(connection.output.size() + (framed ? secure_tunnel_tailroom_k : 0))))
            result = ucall_status_out_of_memory_k;
        return result;
    }
    static void finish_exchange(client_t& client, client_exchange_t& exchange, ucall_status_t status,
                                response_t* response = nullptr) noexcept {
        auto& completed = client.completed[(client.completed_head + client.completed_count) % client.completed.size()];
        completed.context = exchange.arguments.context;
        completed.response = response;
        completed.outcome = {status, status == ucall_status_success_k ? nullptr : ucall_status_name(status)};
        ++client.completed_count;
        exchange.addresses.reset();
        exchange.address = nullptr;
        exchange.redirect.clear();
        exchange.redirect_headers.clear();
        exchange.stage = client_exchange_t::stage_t::idle_k;
        exchange.next = std::exchange(client.idle, &exchange);
    }
    static bool same_peer(client_t const& client, client_peer_t const& peer,
                          client_exchange_t const& exchange) noexcept {
        auto& options = exchange.arguments.options;
        auto* private_key = options.client_key ? options.client_key : client.config.noise_private_key;
        if (peer.security != options.security || peer.authority_hash != exchange.authority_hash ||
            peer.authority.size() != exchange.authority.size() ||
            !equal(text_view(peer.authority), text_view(exchange.authority)))
            return false;
        if (options.security == ucall_security_mode_none_k) return true;
        return private_key && std::memcmp(peer.private_key, *private_key, sizeof(peer.private_key)) == 0 &&
               (!options.server_key || std::memcmp(peer.remote_key, *options.server_key, sizeof(peer.remote_key)) == 0);
    }

    /** Dials the address of @p peer's one call, whose request `output` already holds. */
    static ucall_status_t dial_peer(client_t& client, client_peer_t& peer) noexcept {
        auto& exchange = *peer.oldest_exchange;
        auto& connection = peer.connection;
        if (ucall_status_t const copied = copy_text(peer.authority,
                                                    {exchange.authority.data(), exchange.authority.size() - 1});
            copied != ucall_status_success_k)
            return copied;
        peer.authority_hash = exchange.authority_hash;
        while (exchange.address) {
            auto descriptor = client.engine.open_socket(exchange.address->ai_family);
            if (descriptor < 0) {
                exchange.address = exchange.address->ai_next;
                continue;
            }
            auto& options = exchange.arguments.options;
            auto* key = options.client_key ? options.client_key : client.config.noise_private_key;
            auto config = tunnel_config(options.security, secure_tunnel_role_t::initiator_k, key, nullptr,
                                        options.server_key);
            auto result = connection.configure(config);
            if (result != ucall_status_success_k) {
                client.engine.close_socket(descriptor);
                return result;
            }
            connection.descriptor = descriptor;
            peer.answered_calls = 0;
            connection.output_offset = 0;
            connection.sending = nullptr;
            connection.message = {};
            connection.flags = static_cast<connection_flags_t>(connection.flags & ~connection_peer_closed_k);
            connection.stage = connection_stage_t::connecting_k;
            connection.transmitting = transmit_state_t::sending_k;
            connection.status = ucall_status_success_k;
            connection.authorizer = client.config.peer_authorizer;
            connection.authorizer_context = client.config.peer_authorizer_context;
            connection.deadline = std::min(exchange.deadline,
                                           deadline_after(client.config.connect_timeout_microseconds));
            connection.transmit_request = {
                io_operation_t::connect_k,    descriptor,          reinterpret_cast<byte_t*>(exchange.address->ai_addr),
                exchange.address->ai_addrlen, connection.deadline, &connection};
            peer.security = options.security;
            if (key) std::memcpy(peer.private_key, *key, sizeof(peer.private_key));
            if (options.server_key) std::memcpy(peer.remote_key, *options.server_key, sizeof(peer.remote_key));
            return ucall_status_success_k;
        }
        return ucall_status_connection_failed_k;
    }
    static ucall_status_t redirect_exchange(client_exchange_t& exchange, http_message_t const& message,
                                            std::string_view text) noexcept {
        auto location = message.header(text, "location");
        if (location.empty()) return ucall_status_not_found_k;
        auto maximum = exchange.arguments.options.max_redirects ? exchange.arguments.options.max_redirects : 5;
        if (exchange.redirects++ >= maximum) return ucall_status_malformed_k;
        auto previous = text_view(exchange.arguments.url);
        auto scheme = find(previous, "://");
        auto origin_end = scheme + 3 + exchange.authority.size() - 1;
        vector<char> next {exchange.redirect.get_allocator()};
        ucall_status_t appended = ucall_status_success_k;
        if (find(location, "://") != std::string_view::npos) appended = append_text(next, {location});
        else if (location.starts_with("//")) appended = append_text(next, {previous.substr(0, scheme + 1), location});
        else {
            std::string_view directory {};
            if (location.front() != '/') {
                auto path = text_view(exchange.target);
                path = path.substr(0, find(path, '?'));
                auto last = http_t::rfind(path, '/');
                directory = last != path.npos ? path.substr(0, last + 1) : "/";
            }
            appended = append_text(next, {previous.substr(0, origin_end), directory, location});
        }
        if (appended != ucall_status_success_k) return appended;
        if (exchange.arguments.options.security != ucall_security_mode_none_k &&
            !text_view(next).starts_with("http+noise://"))
            return ucall_status_peer_rejected_k;
        exchange.redirect = std::move(next);
        exchange.arguments.url = bytes_view(text_view(exchange.redirect));
        if (message.status == 303 ||
            ((message.status == 301 || message.status == 302) && exchange.arguments.verb == ucall_verb_post_k)) {
            if (exchange.arguments.verb != ucall_verb_head_k) exchange.arguments.verb = ucall_verb_get_k;
            exchange.arguments.body = {};
        }
        // Credentials belong to the caller's original origin, never to a redirect target.
        vector<ucall_bytes_view_t> safe_headers {exchange.redirect_headers.get_allocator()};
        for (std::size_t i = 0; i != exchange.arguments.headers_count; ++i) {
            auto header = exchange.arguments.headers[i];
            auto name = text_view(header).substr(0, find(text_view(header), ':'));
            if (http_t::equal_ascii_uncased(name, "authorization") ||
                http_t::equal_ascii_uncased(name, "proxy-authorization") || http_t::equal_ascii_uncased(name, "cookie"))
                continue;
            if (st::failed(safe_headers.push_back(std::move(header)))) return ucall_status_out_of_memory_k;
        }
        exchange.redirect_headers = std::move(safe_headers);
        exchange.arguments.headers = exchange.redirect_headers.data();
        exchange.arguments.headers_count = exchange.redirect_headers.size();
        auto result = parse_url(exchange);
        return result == ucall_status_success_k ? resolve_exchange(exchange) : result;
    }

    /** Appends @p exchange to @p peer's calls, whose earliest deadline becomes the connection's;
     *  its request is composed into `output` before it starts sending. */
    static void push_call(client_peer_t& peer, client_exchange_t& exchange) noexcept {
        exchange.stage = client_exchange_t::stage_t::active_k;
        std::uint64_t& deadline = peer.connection.deadline;
        deadline = peer.oldest_exchange ? std::min(deadline, exchange.deadline) : exchange.deadline;
        if (peer.newest_exchange) peer.newest_exchange->next = &exchange;
        else peer.oldest_exchange = &exchange;
        peer.newest_exchange = &exchange;
        ++peer.exchanges_in_flight;
    }

    /** Unlinks @p peer's oldest call, and moves the connection's deadline to the earliest of the
     *  calls left, a walk over at most `max_pipelined_calls` of them. */
    static client_exchange_t& pop_call(client_peer_t& peer) noexcept {
        auto& exchange = *peer.oldest_exchange;
        peer.oldest_exchange = std::exchange(exchange.next, nullptr);
        if (!peer.oldest_exchange) peer.newest_exchange = nullptr;
        --peer.exchanges_in_flight;
        std::uint64_t deadline = 0;
        for (client_exchange_t const* left = peer.oldest_exchange; left; left = left->next)
            deadline = deadline ? std::min(deadline, left->deadline) : left->deadline;
        peer.connection.deadline = deadline;
        return exchange;
    }

    /** Queues @p exchange by deadline, behind every waiting call due no later, for the next
     *  connection of its origin. Equal timeouts append every new call at once. */
    static void queue_call(client_t& client, client_exchange_t& exchange) noexcept {
        exchange.stage = client_exchange_t::stage_t::queued_k;
        client_exchange_t* previous = nullptr;
        if (client.waiting_tail && client.waiting_tail->deadline <= exchange.deadline) previous = client.waiting_tail;
        else
            for (auto* waiting = client.waiting_head; waiting && waiting->deadline <= exchange.deadline;
                 waiting = waiting->next)
                previous = waiting;
        exchange.next = previous ? previous->next : client.waiting_head;
        (previous ? previous->next : client.waiting_head) = &exchange;
        if (!exchange.next) client.waiting_tail = &exchange;
    }

    /** Unlinks the waiting @p exchange, which follows @p previous or, when that is null, leads. */
    static void unqueue_call(client_t& client, client_exchange_t& exchange, client_exchange_t* previous) noexcept {
        (previous ? previous->next : client.waiting_head) = exchange.next;
        if (client.waiting_tail == &exchange) client.waiting_tail = previous;
        exchange.next = nullptr;
    }
    static std::size_t retry_budget(client_exchange_t const& exchange) noexcept {
        return exchange.arguments.options.max_retries ? exchange.arguments.options.max_retries : 3;
    }

    /** Whether the server may act on @p exchange twice to the same effect, per RFC 9110 §9.2.2. */
    static bool idempotent(client_exchange_t const& exchange) noexcept {
        ucall_verb_t verb = exchange.arguments.verb;
        return verb == ucall_verb_get_k || verb == ucall_verb_head_k || verb == ucall_verb_put_k ||
               verb == ucall_verb_delete_k || verb == ucall_verb_options_k;
    }

    /** Whether the caller's own @p headers ask to close the connection after the call. */
    static http_connection_t connection_intent(span<ucall_bytes_view_t const> headers) noexcept {
        for (ucall_bytes_view_t const header : headers) {
            if (!valid_view(header)) continue;
            std::string_view line = text_view(header);
            std::size_t colon = find(line, ':');
            if (colon != std::string_view::npos && http_t::equal_ascii_uncased(line.substr(0, colon), "connection") &&
                http_has_token(line.substr(colon + 1), "close"))
                return http_connection_t::close_k;
        }
        return http_connection_t::keep_alive_k;
    }

    /** Whether @p peer may pipeline one more call: below the depth, and behind no call that closes
     *  the connection or, per RFC 9112 §9.3.2, cannot be replayed. */
    static bool accepts_another_call(client_t const& client, client_peer_t const& peer) noexcept {
        client_exchange_t const* newest = peer.newest_exchange;
        return peer.exchanges_in_flight < client.config.max_pipelined_calls &&
               (!newest || (newest->connection_intent == http_connection_t::keep_alive_k && idempotent(*newest)));
    }

    /** Whether a call older than the one being sent waits for its response. */
    static bool awaits_response(client_peer_t const& peer) noexcept {
        return peer.exchanges_in_flight > (peer.connection.transmitting == transmit_state_t::sending_k ? 1u : 0u);
    }

    /** Whether @p peer carries no call, so a call of any origin may take it,
     *  though an open connection keeps a receive posted meanwhile. */
    static bool vacant(client_peer_t const& peer) noexcept {
        auto stage = peer.connection.stage;
        return !peer.oldest_exchange && (stage == connection_stage_t::idle_k || stage == connection_stage_t::open_k ||
                                         stage == connection_stage_t::closed_k);
    }

    /** Takes the waiting call due first that @p peer's connection can carry. */
    static client_exchange_t* take_waiting_call(client_t& client, client_peer_t const& peer) noexcept {
        client_exchange_t* previous = nullptr;
        for (auto* exchange = client.waiting_head; exchange; previous = exchange, exchange = exchange->next)
            if (same_peer(client, peer, *exchange)) {
                unqueue_call(client, *exchange, previous);
                return exchange;
            }
        return nullptr;
    }

    /** Answers @p peer's oldest call with the whole response at @p offset of `input`:
     *  a redirect queues the call again as a fresh one, and any other response completes it. */
    static void answer_call(client_t& client, client_peer_t& peer, std::size_t offset) noexcept {
        auto& connection = peer.connection;
        auto& message = connection.message;
        auto& exchange = *peer.oldest_exchange;
        auto code = message.status;
        ucall_status_t status = ucall_status_not_found_k;
        if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308)
            status = redirect_exchange(exchange, message, connection.text().substr(offset));
        response_t* response = nullptr;
        if (status == ucall_status_not_found_k) {
            response = allocate_unique<response_t>(client.allocator, client.allocator).release();
            if (!response) return connection.fail(ucall_status_out_of_memory_k);
            if (!offset && message.wire_length == connection.input.size()) {
                response->storage = std::move(connection.input);
                connection.input.clear();
            }
            else if (ucall_status_t const appended = append_text(
                         response->storage, {text_view(connection.input).substr(offset, message.wire_length)});
                     appended != ucall_status_success_k) {
                response_t::release(response);
                return connection.fail(appended);
            }
            response->headers_length = message.headers_length;
            response->body_length = message.body_length;
            response->status = code;
            response->content = response->storage;
            status = ucall_status_success_k;
        }
        ++peer.answered_calls;
        if (!message.keep_alive() || exchange.connection_intent == http_connection_t::close_k)
            connection.fail(ucall_status_success_k);
        message = {};
        pop_call(peer);
        if (status != ucall_status_success_k || response) return finish_exchange(client, exchange, status, response);
        exchange.attempts = 0;
        queue_call(client, exchange);
    }

    /** Steps an open client connection, answering its next engine request or null, by these rules
     *  in order:
     *  C1 responses: while reading and a sent call awaits, each whole response answers the oldest
     *     call, a redirect queueing it again as a fresh call; a response without keep-alive, or to
     *     a call that asked to close, closes the connection.
     *  C2 requests: while reading, an idle transmit side composes the next queued call this peer
     *     can carry into `output` and appends it to the FIFO, if `accepts_another_call` allows.
     *  C3 emit: while reading, the next chunk of that request while its send is idle, else a
     *     receive, posted even with no call so a peer close is seen before reuse.
     *  C4 done: a peer close, or bytes no call asked for, close the connection, losing any call
     *     still on the FIFO; with the FIFO empty and the side reading, the peer stays open.
     *  C5 loss: `call_lost` settles the calls of the closed connection. */
    static io_request_t* call_open(client_t& client, client_peer_t& peer) noexcept {
        auto& connection = peer.connection;
        auto& input = connection.input;
        if (connection.transmitting == transmit_state_t::sending_k &&
            connection.transmit_operation == operation_state_t::idle_k && !connection.sending &&
            connection.output_offset == connection.output.size())
            connection.transmitting = transmit_state_t::idle_k;
        connection.open_records();
        // Responses answered this round, erased from `input` once after it rather than one by one.
        std::size_t consumed = 0;
        while (connection.stage == connection_stage_t::open_k && connection.receiving == receive_state_t::reading_k &&
               awaits_response(peer)) {
            auto role = peer.oldest_exchange->arguments.verb == ucall_verb_head_k ? http_role_t::head_response_k
                                                                                  : http_role_t::response_k;
            span<byte_t> unparsed {input.data() + consumed, input.data() + input.size()};
            auto parsed = http_parse(unparsed, connection.message, role);
            if (parsed == http_parse_t::incomplete_k && (connection.flags & connection_peer_closed_k)) {
                // Over Noise only a close record, never a bare end of stream, may end a response.
                if (!connection.message.headers_length || connection.message.framing != http_framing_t::until_close_k ||
                    (connection.tunnel.encrypts() && connection.tunnel.may_open())) {
                    connection.fail(ucall_status_connection_closed_k);
                    break;
                }
                connection.message.body_length = unparsed.size() - connection.message.headers_length;
                connection.message.wire_length = unparsed.size();
                parsed = http_parse_t::complete_k;
            }
            if (parsed == http_parse_t::incomplete_k) break;
            if (parsed != http_parse_t::complete_k || connection.message.status == 101) {
                connection.fail(parsed == http_parse_t::overflow_k ? ucall_status_overflow_k
                                : parsed == http_parse_t::unsupported_k || parsed == http_parse_t::complete_k
                                    ? ucall_status_unsupported_k
                                    : ucall_status_malformed_k);
                break;
            }
            if (connection.message.status < 200) {
                consumed += connection.message.wire_length;
                connection.message = {};
                continue;
            }
            http_decode_chunks(unparsed, connection.message);
            auto wire = connection.message.wire_length;
            answer_call(client, peer, consumed);
            consumed = input.empty() ? 0 : consumed + wire;
        }
        if (consumed) drop_bytes(input, consumed);
        if (connection.stage != connection_stage_t::open_k) return connection.advance();
        if ((connection.flags & connection_peer_closed_k) || (!peer.oldest_exchange && !input.empty()))
            connection.receiving = receive_state_t::ended_k;
        if (connection.receiving == receive_state_t::reading_k) {
            if (connection.transmitting == transmit_state_t::idle_k && accepts_another_call(client, peer))
                if (auto* exchange = take_waiting_call(client, peer)) {
                    auto result = compose_request(connection, *exchange);
                    if (result != ucall_status_success_k) finish_exchange(client, *exchange, result);
                    else {
                        push_call(peer, *exchange);
                        connection.transmitting = transmit_state_t::sending_k;
                        connection.output_offset = 0;
                    }
                }
            if (connection.transmitting == transmit_state_t::sending_k &&
                connection.transmit_operation == operation_state_t::idle_k) {
                if (auto* next = connection.transmit_from(connection.output)) return next;
                return connection.advance(); // Sealing failed the connection.
            }
            if (connection.receive_operation == operation_state_t::idle_k)
                return connection.emit(connection.receive_request, io_operation_t::receive_k, connection.received);
            return nullptr;
        }
        connection.fail(peer.oldest_exchange ? ucall_status_connection_closed_k : ucall_status_success_k);
        return connection.advance();
    }

    /** Settles the calls of @p peer's closed connection at @p now, rule C5 of `call_open`:
     *  - a failed connect queues its one call again on the next address or attempt;
     *  - a call past its deadline finishes with @c ucall_status_timeout_k;
     *  - after a close the server announced, every unread call queues again, as RFC 9112 §9.6 bars
     *    the server from processing it;
     *  - a lost connection, or one dropped for a later call's deadline, queues its idempotent calls
     *    again within their retry budget, and its oldest call too when a reused connection read no
     *    byte of its response, as the server had closed before the request reached it;
     *  - the oldest of the rest finishes with the connection's failure, and the others with
     *    @c ucall_status_connection_closed_k. */
    static void call_lost(client_t& client, client_peer_t& peer, std::uint64_t now) noexcept {
        connection_t& connection = peer.connection;
        ucall_status_t status = connection.status;
        // A timeout with several calls aboard expired one of them and dropped the rest with it.
        bool const lost = status == ucall_status_connection_closed_k || status == ucall_status_io_k ||
                          (status == ucall_status_timeout_k && peer.oldest_exchange != peer.newest_exchange);
        bool const unread = lost && peer.answered_calls && connection.input.empty() && connection.encrypted.empty();
        for (bool oldest = true; peer.oldest_exchange; oldest = false) {
            auto& exchange = pop_call(peer);
            ucall_status_t outcome = oldest ? status : ucall_status_connection_closed_k;
            if (status == ucall_status_connection_failed_k) {
                // A connection carries no second call before it opens, so this request never left.
                exchange.address = exchange.address ? exchange.address->ai_next : nullptr;
                if (!exchange.address && exchange.attempts++ < retry_budget(exchange))
                    exchange.address = exchange.first_address();
                if (exchange.address) queue_call(client, exchange);
            }
            else if (now >= exchange.deadline) outcome = ucall_status_timeout_k;
            else if (status == ucall_status_success_k ||
                     ((lost || !oldest) && (idempotent(exchange) || (oldest && unread)) &&
                      exchange.attempts++ < retry_budget(exchange))) {
                exchange.address = exchange.first_address(); // Null for a call that rode a connection it never dialed.
                queue_call(client, exchange);
            }
            if (exchange.stage != client_exchange_t::stage_t::queued_k) finish_exchange(client, exchange, outcome);
        }
    }

    /** Advances one client peer as `advance_connection` advances a server's,
     *  submitting each request it asks for. */
    static void step_peer(client_t& client, client_peer_t& peer, std::uint64_t now) noexcept {
        auto& connection = peer.connection;
        // A pending receive keeps the deadline it was posted with, which a later call may undercut.
        if (connection.stage == connection_stage_t::open_k && peer.oldest_exchange && now >= connection.deadline)
            connection.fail(ucall_status_timeout_k);
        for (;;) {
            auto* next = connection.advance();
            if (!next && connection.stage == connection_stage_t::open_k) next = call_open(client, peer);
            if (!next) break;
            // A failed submission is retried on the next round rather than this one.
            if (client.engine.submit(*next) != ucall_status_success_k) break;
            connection.submitted(*next);
        }
        // The close waits until the other direction's operation completes or is cancelled.
        if (connection.stage == connection_stage_t::closing_k) {
            if (connection.receive_operation == operation_state_t::pending_k &&
                connection.receive_request.operation != io_operation_t::close_k)
                client.engine.cancel(connection.receive_request);
            if (connection.transmit_operation == operation_state_t::pending_k)
                client.engine.cancel(connection.transmit_request);
        }
        if (connection.stage == connection_stage_t::closed_k && peer.oldest_exchange) call_lost(client, peer, now);
    }
    static std::uint64_t client_progress(client_t& client) noexcept {
        auto now = monotonic_ns();
        std::uint64_t deadline = 0;
        std::size_t vacancies = 0;
        // Completions only record bytes, so peers answer and take calls
        // before the rest look for peers.
        for (auto& peer : client.peers) {
            step_peer(client, *peer, now);
            vacancies += vacant(*peer);
        }
        // The queue runs by deadline, so expiry and the next wake-up read only its front.
        while (client.waiting_head && now >= client.waiting_head->deadline) {
            auto& expired = *client.waiting_head;
            unqueue_call(client, expired, nullptr);
            finish_exchange(client, expired, ucall_status_timeout_k);
        }
        if (client.waiting_head) deadline = client.waiting_head->deadline;
        bool assigned = false;
        for (unsigned pass = 0; pass != 2 && vacancies; ++pass) {
            client_exchange_t* previous = nullptr;
            for (auto* waiting = client.waiting_head; waiting && vacancies;) {
                auto& exchange = *waiting;
                waiting = exchange.next;
                // A connection of the same origin below the depth takes the call
                // by `call_open` rule C2.
                client_peer_t* chosen = nullptr;
                bool carried = false;
                for (auto& peer : client.peers) {
                    auto& connection = peer->connection;
                    if (connection.descriptor >= 0 && connection.receiving == receive_state_t::reading_k &&
                        (connection.stage == connection_stage_t::connecting_k ||
                         connection.stage == connection_stage_t::handshake_k ||
                         connection.stage == connection_stage_t::open_k) &&
                        accepts_another_call(client, *peer) && same_peer(client, *peer, exchange)) {
                        carried = true;
                        break;
                    }
                    if (!vacant(*peer) || (!pass && assigned && connection.descriptor >= 0)) continue;
                    if (!chosen || (chosen->connection.descriptor >= 0 && connection.descriptor < 0))
                        chosen = peer.get();
                }
                if (carried || !chosen) {
                    previous = &exchange;
                    continue;
                }
                --vacancies;
                assigned = true;
                auto& connection = chosen->connection;
                // An idle connection to another origin closes first; the call dials once it has.
                if (connection.descriptor >= 0) {
                    connection.fail(ucall_status_success_k);
                    previous = &exchange;
                    continue;
                }
                unqueue_call(client, exchange, previous);
                auto result = exchange.address ? ucall_status_success_k : resolve_exchange(exchange);
                if (result == ucall_status_success_k) result = compose_request(connection, exchange);
                if (result == ucall_status_success_k) {
                    push_call(*chosen, exchange);
                    result = dial_peer(client, *chosen);
                    if (result != ucall_status_success_k) pop_call(*chosen);
                }
                if (result != ucall_status_success_k) {
                    ++vacancies;
                    finish_exchange(client, exchange, result);
                }
            }
        }
        // Calls in flight time out through their connection's deadline, the earliest of its calls'.
        for (auto& peer : client.peers)
            if (peer->oldest_exchange)
                deadline = !deadline ? peer->connection.deadline : std::min(deadline, peer->connection.deadline);
        for (auto& peer : client.peers) step_peer(client, *peer, now);
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
        if (!config.connect_timeout_microseconds) config.connect_timeout_microseconds = 5'000'000;
        if (!config.request_timeout_microseconds) config.request_timeout_microseconds = 30'000'000;
        if (!config.max_pipelined_calls) config.max_pipelined_calls = 1;
        if (!config.max_concurrent_calls) {
            // Every connection may carry its full pipeline at once.
            if (config.max_concurrent_connections >
                std::numeric_limits<std::size_t>::max() / config.max_pipelined_calls) {
                publish(arguments->outcome, ucall_status_invalid_argument_k);
                return;
            }
            config.max_concurrent_calls = config.max_concurrent_connections * config.max_pipelined_calls;
        }
        // Each connection keeps one operation per direction.
        if (config.max_pipelined_calls > std::numeric_limits<std::uint32_t>::max() ||
            config.max_concurrent_connections > std::numeric_limits<std::size_t>::max() / 2) {
            publish(arguments->outcome, ucall_status_overflow_k);
            return;
        }
        auto slots = 2 * config.max_concurrent_connections;
        if (config.noise_private_key) {
            std::memcpy(client->private_key, *config.noise_private_key, sizeof(client->private_key));
            config.noise_private_key = &client->private_key;
        }
        if (st::failed(client->completed.resize(config.max_concurrent_calls)) ||
            st::failed(client->completions.resize(slots)) ||
            st::failed(client->peers.resize(config.max_concurrent_connections))) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        rebound_allocator<client_exchange_t> exchange_allocator {allocator};
        auto* exchanges = exchange_allocator.allocate(config.max_concurrent_calls);
        if (!exchanges) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        for (std::size_t i = config.max_concurrent_calls; i != 0; --i)
            std::construct_at(exchanges + i - 1, allocator)->next = std::exchange(client->idle, exchanges + i - 1);
        client->exchanges = {exchanges, config.max_concurrent_calls};
        auto status = client->engine.open(slots, slots);
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
            peer->connection.peer = peer.get();
        }
        if (arguments->resolved) *arguments->resolved = config;
        client->string_capabilities = capabilities_k;
        client->atomic_capabilities = static_cast<std::uint64_t>(atomic_ref<std::uint32_t>::capabilities_k);
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
        if (client.admitted == client.exchanges.size()) {
            publish(arguments->outcome, ucall_status_contended_k);
            return;
        }
        auto timeout = options.timeout_microseconds ? options.timeout_microseconds
                                                    : client.config.request_timeout_microseconds;
        auto& exchange = *client.idle; // Admission keeps one idle call for every call not admitted.
        exchange.arguments = *arguments;
        exchange.arguments.outcome = nullptr;
        auto result = parse_url(exchange);
        if (result != ucall_status_success_k) {
            publish(arguments->outcome, result);
            return;
        }
        client.idle = exchange.next;
        exchange.deadline = deadline_after(timeout);
        exchange.connection_intent = connection_intent({arguments->headers, arguments->headers_count});
        exchange.attempts = exchange.redirects = 0;
        queue_call(client, exchange);
        ++client.admitted;
        publish(arguments->outcome, ucall_status_success_k);
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
                    client.waiting_head = client.waiting_tail = nullptr;
                    for (auto& peer : client.peers) {
                        peer->oldest_exchange = peer->newest_exchange = nullptr;
                        peer->exchanges_in_flight = 0;
                    }
                    for (auto& exchange : client.exchanges)
                        if (exchange.stage != client_exchange_t::stage_t::idle_k)
                            finish_exchange(client, exchange, client.failure);
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

    inline static server_api_t const server_api_k {&server_free,
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
                                                   &server_request_peer,
                                                   &server_request_body,
                                                   &server_reply_content,
                                                   &server_reply_error,
                                                   &server_add_http_batch_endpoint};
    inline static client_api_t const client_api_k {&client_free, &client_call, &client_take_completed};
};

/** Portable network over the serial kits, for callers without a CPU dispatch point. */
template <typename engine_type_, typename allocator_type_ = st::default_allocator<byte_t>>
using serial_network = network_variant<engine_type_, fu::standard_atomic_ref, serial_compare_kit_t, serial_find_kit_t,
                                       serial_byteset_kit_t, serial_hash_kit_t, serial_fold_kit_t, serial_sha256_kit_t,
                                       serial_aes256_gcm_kit_t, allocator_type_>;

} // namespace unum::ucall
