/**
 *  @file include/ucall/network/transports.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief A socket of a server or a client through handshakes, records, receives and sends.
 */
#pragma once

#include "ucall/io/types.hpp"      // `io_completion_t`, `io_operation_t`, `io_request_t`, `registered_memory_t`
#include "ucall/network/types.hpp" // `transport_stage_t`, `linger_bytes_k`, `operation_state_t`
#include "ucall/tunnel/types.hpp" // `secure_tunnel_config_t`, `secure_tunnel_fault_t`, `secure_tunnel_headroom_k`, `secure_tunnel_mode_t`
#include "ucall/utilities/sockets.hpp" // `page_size`
#include "ucall/utilities/types.hpp"   // `text_view`, `byte_t`, `descriptor_t`, `span`

namespace unum::ucall::network {

using io::io_completion_t;
using io::io_operation_t;
using io::io_receive_memory_t;
using io::io_request_t;
using io::registered_memory_t;
using io::tally;
using tunnel::secure_tunnel_config_t;
using tunnel::secure_tunnel_fault_t;
using tunnel::secure_tunnel_headroom_k;
using tunnel::secure_tunnel_mode_t;
using tunnel::secure_tunnel_overhead_k;
using tunnel::secure_tunnel_record_t;
using tunnel::secure_tunnel_request_t;
using tunnel::secure_tunnel_state_t;
using utilities::byte_t;
using utilities::descriptor_t;
using utilities::io_vector_t;
using utilities::page_size;
using utilities::span;
using utilities::text_view;

/** A socket's engine requests, tunnel, buffers and send cursor, shared by both roles. */
template <typename network_type_>
struct transport {
    using network_t = network_type_;
    using http_t = typename network_t::http_t;
    using tunnel_t = typename network_t::tunnel_t;
    using crypto_t = typename network_t::crypto_t;
    using allocator_t = typename network_t::allocator_t;
    using engine_t = typename network_t::engine_t;
    using http_message_t = typename network_t::http_message_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;
    template <typename value_type_>
    using atomic_ref = typename network_t::template atomic_ref<value_type_>;

    explicit transport(allocator_t const& allocator = {}) noexcept
        : input(rebound_allocator<byte_t> {allocator}), encrypted(rebound_allocator<byte_t> {allocator}),
          output(rebound_allocator<byte_t> {allocator}), record(rebound_allocator<byte_t> {allocator}) {
        // Measured on Linux AArch64 LP64 with a stateless allocator; other targets go unmeasured.
        if constexpr (UCALL_OS_LINUX_ && UCALL_ARCH_ARM64_ && std::is_empty_v<allocator_t>)
            static_assert(sizeof(transport) == 2160);
    }
    transport(transport const&) = delete;
    transport& operator=(transport const&) = delete;
    transport(transport&&) = delete;
    transport& operator=(transport&&) = delete;

    /** One engine request per direction; @c receive_request also closes. */
    io_request_t receive_request {}, transmit_request {};
    operation_state_t receive_operation {}, transmit_operation {};
    descriptor_t descriptor {-1};
    transport_stage_t stage {transport_stage_t::idle_k};
    receive_state_t receiving {};
    transmit_state_t transmitting {};
    close_mode_t close_mode {};
    ucall_status_t status {ucall_status_success_k};
    std::uint64_t deadline {};
    tunnel_t tunnel {};
    vector<byte_t> input {}, encrypted {}, output {};
    http_message_t message {};
    ucall_peer_authorizer_t authorizer {};
    void* authorizer_context {};

    /** Authenticated at handshake; zero on plaintext connections. */
    ucall_noise_key_t peer_static_key {};

    /** As accepted; unknown on client connections. */
    ucall_peer_address_t peer_address {};
    peer_verdict_t peer_verdict {};
    peer_stream_t peer_stream {};
    listing_t readiness {};
    transport_role_t role {};

    /** The tail of the receive's destination, which @c receive_request names. */
    io_vector_t receive_vector {};

    /** @c record holds handshake messages only. */
    vector<byte_t> record {};
    byte_t* sending {};
    std::size_t sending_length {}, sending_offset {};

    /** Bytes of the segment in front that sends took. */
    std::size_t output_offset {};

    /** Bytes read and dropped while lingering. */
    std::size_t lingered_bytes {};

    /** The owning event loop's counters; null on client connections, which have no loop. */
    event_loop_statistics_t* statistics {};

    /** The counters of its interface on its event loop; null on client connections. */
    interface_statistics_t* interface_statistics {};

    /** Resets it for a new socket whose requests name @p role, the record holding it. */
    ucall_status_t configure(secure_tunnel_config_t const& config, void* role) noexcept {
        receive_request = transmit_request = {};
        receive_request.context = transmit_request.context = role;
        receive_operation = transmit_operation = operation_state_t::idle_k;
        receiving = receive_state_t::reading_k;
        transmitting = transmit_state_t::idle_k;
        close_mode = close_mode_t::orderly_k;
        message = {};
        input.clear();
        encrypted.clear();
        sending = nullptr;
        sending_length = sending_offset = output_offset = lingered_bytes = 0;
        deadline = 0;
        peer_verdict = peer_verdict_t::unverified_k;
        peer_stream = peer_stream_t::writing_k;
        crypto_t::secure_zero(peer_static_key);
        auto fault = tunnel.make(config);
        if (fault != secure_tunnel_fault_t::none_k) return ucall_status_handshake_failed_k;
        if (!page_size()) return ucall_status_io_k;
        peer_verdict = config.mode == secure_tunnel_mode_t::plain_k ? peer_verdict_t::authorized_k
                                                                    : peer_verdict_t::unverified_k;
        return ucall_status_success_k;
    }

    /** Records what one completion did to bytes and operation states, deciding nothing for the
     *  protocol; a receive that filled its room doubles it, while under @p limit bytes. */
    void complete(io_completion_t const& completion, std::size_t limit) noexcept {
        auto& completed = *completion.request;
        (&completed == &receive_request ? receive_operation : transmit_operation) = operation_state_t::idle_k;
        auto result = completion.result;
        if (completed.operation == io_operation_t::close_k) {
            descriptor = -1;
            stage = transport_stage_t::closed_k;
        }
        else if (result < 0)
            fail(result == -ETIMEDOUT                       ? ucall_status_timeout_k
                 : stage == transport_stage_t::connecting_k ? ucall_status_connection_failed_k
                                                            : ucall_status_io_k);
        else if (completed.operation == io_operation_t::connect_k) stage = transport_stage_t::handshake_k;
        else if (completed.operation == io_operation_t::send_k ||
                 completed.operation == io_operation_t::send_zero_copy_k) {
            if (!result) return fail(ucall_status_connection_closed_k);
            sending_offset += static_cast<std::size_t>(result);
            if (statistics) tally<atomic_ref>(statistics->bytes_sent, static_cast<std::uint64_t>(result));
            if (sending_offset != sending_length) return;
            // A server credits its zero-copy sends itself, as a window's slice is no segment.
            if (completed.operation == io_operation_t::send_k && stage == transport_stage_t::open_k &&
                transmitting == transmit_state_t::sending_k)
                output_offset += sending_length;
            sending = nullptr;
        }
        else if (stage == transport_stage_t::lingering_k) {
            if (completed.operation == io_operation_t::shutdown_k) return;
            lingered_bytes += static_cast<std::size_t>(result);
            if (statistics) tally<atomic_ref>(statistics->bytes_received, static_cast<std::uint64_t>(result));
            if (!result || lingered_bytes >= linger_bytes_k) fail(ucall_status_success_k);
        }
        else if (!result) peer_stream = peer_stream_t::closed_k;
        else {
            vector<byte_t>& destination = tunnel.encrypts() ? encrypted : input;
            std::size_t const arrived = static_cast<std::size_t>(result);
            std::size_t const previous = destination.size();
            if (st::failed(destination.resize(st::assume_uninitialized, previous + arrived)))
                return fail(ucall_status_out_of_memory_k);
            if constexpr (engine_t::receive_memory_k == io_receive_memory_t::engine_k) {
                std::memcpy(destination.data() + previous, completion.data, arrived);
                if (statistics) tally<atomic_ref>(statistics->bytes_copied, arrived);
            }
            // A failed reservation only leaves the room as it was.
            else if (arrived >= receive_vector.iov_len && destination.capacity() < limit) {
                [[maybe_unused]] st::status_t const grown = destination.reserve(destination.capacity() + 1);
            }
            if (statistics) tally<atomic_ref>(statistics->bytes_received, arrived);
        }
    }

    /** The next engine request of every stage but open,
     *  which @c serve_open and @c call_open step. */
    io_request_t* advance() noexcept {
        for (;;) {
            if (stage == transport_stage_t::closing_k) {
                if (in_flight()) return nullptr;
                if (descriptor < 0) {
                    stage = transport_stage_t::closed_k;
                    return nullptr;
                }
                return emit(receive_request, io_operation_t::close_k, {});
            }
            if (stage == transport_stage_t::closed_k || stage == transport_stage_t::idle_k ||
                stage == transport_stage_t::open_k || stage == transport_stage_t::releasing_k)
                return nullptr;
            // The handshake takes turns between the two directions, and so does lingering.
            if (in_flight()) return nullptr;
            if (stage == transport_stage_t::connecting_k) return &transmit_request;
            if (sending)
                return emit(transmit_request, io_operation_t::send_k,
                            {sending + sending_offset, sending_length - sending_offset});
            secure_tunnel_request_t const tunnel_request = stage == transport_stage_t::lingering_k
                                                               ? secure_tunnel_request_t::close_k
                                                               : secure_tunnel_request_t::proceed_k;
            auto step = tunnel.advance({encrypted.data(), encrypted.data() + encrypted.size()}, tunnel_request);
            http_t::drop_bytes(encrypted, step.consumed);
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
                if (statistics) tally<atomic_ref>(statistics->bytes_copied, step.outbound.size());
                sending = record.data();
                sending_length = step.outbound.size();
                sending_offset = 0;
                continue;
            }
            // The FIN follows any Noise close record, then receives drain the peer.
            if (stage == transport_stage_t::lingering_k)
                return transmit_request.operation == io_operation_t::shutdown_k
                           ? emit_receive()
                           : emit(transmit_request, io_operation_t::shutdown_k, {});
            if (step.state != secure_tunnel_state_t::ready_k) {
                if (peer_stream == peer_stream_t::closed_k) {
                    fail(ucall_status_connection_closed_k);
                    continue;
                }
                return emit_receive();
            }
            if (peer_verdict == peer_verdict_t::unverified_k) {
                if (!tunnel.peer_key(std::as_writable_bytes(std::span {peer_static_key}))) {
                    fail(ucall_status_handshake_failed_k);
                    continue;
                }
                auto verdict = authorizer ? authorizer(&peer_static_key, authorizer_context) : ucall_status_success_k;
                if (verdict != ucall_status_success_k) {
                    if (interface_statistics) tally<atomic_ref>(interface_statistics->authorizer_refusals);
                    fail(verdict);
                    continue;
                }
                peer_verdict = peer_verdict_t::authorized_k;
            }
            stage = transport_stage_t::open_k;
            return nullptr;
        }
    }
    io_request_t* emit(io_request_t& request, io_operation_t operation, span<byte_t> bytes) noexcept {
        request = {.operation = operation,
                   .descriptor = descriptor,
                   .data = bytes.data(),
                   .length = bytes.size(),
                   .deadline = operation == io_operation_t::close_k ? 0 : deadline,
                   .context = request.context};
        return &request;
    }

    /** Points the receive at the tail of its destination, moved or not, so an armed one follows. */
    void aim_receive() noexcept {
        if constexpr (engine_t::receive_memory_k == io_receive_memory_t::submitter_k) {
            vector<byte_t>& destination = tunnel.encrypts() ? encrypted : input;
            // A receive of no bytes would read as a peer close.
            if (destination.size() == destination.capacity() &&
                st::failed(destination.reserve(destination.size() + page_size())))
                return fail(ucall_status_out_of_memory_k);
            receive_vector = {destination.data() + destination.size(), destination.capacity() - destination.size()};
        }
    }

    /** Starts a receive, or steps the close of a transport that could not grow its room. */
    io_request_t* emit_receive() noexcept {
        aim_receive();
        if (stage == transport_stage_t::closing_k) return advance();
        return emit(receive_request, io_operation_t::receive_k, {reinterpret_cast<byte_t*>(&receive_vector), 1});
    }

    /** Starts sending @p bytes, which lie in engine memory @p registered_memory, without copying
     *  them; @p release_request collects the kernel's hold on them once its last send is done. */
    io_request_t* emit_zero_copy(span<byte_t> bytes, io_request_t& release_request,
                                 registered_memory_t registered_memory) noexcept {
        emit_send(bytes);
        transmit_request.operation = io_operation_t::send_zero_copy_k;
        transmit_request.registered_memory = registered_memory;
        transmit_request.release_request = &release_request;
        return &transmit_request;
    }

    /** Starts sending @p bytes, which the socket copies. */
    io_request_t* emit_send(span<byte_t> bytes) noexcept {
        sending = bytes.data();
        sending_length = bytes.size();
        sending_offset = 0;
        return emit(transmit_request, io_operation_t::send_k, bytes);
    }

    /** The rest of the send the socket took only part of, with its operation, memory and
     *  release. */
    io_request_t* resume_send() noexcept {
        transmit_request.data = sending + sending_offset;
        transmit_request.length = sending_length - sending_offset;
        transmit_request.deadline = deadline;
        return &transmit_request;
    }

    /** Marks @p request, one of its two, in flight once the engine took it. */
    void submitted(io_request_t const& request) noexcept {
        (&request == &receive_request ? receive_operation : transmit_operation) = operation_state_t::submitted_k;
    }
    bool in_flight() const noexcept {
        return receive_operation == operation_state_t::submitted_k ||
               transmit_operation == operation_state_t::submitted_k;
    }

    /** Seals in place every record of @p bytes, laid out as whole records from its start. */
    [[nodiscard]] ucall_status_t seal_records(span<byte_t> bytes) noexcept {
        if (!tunnel.encrypts()) return ucall_status_success_k;
        std::size_t const stride = tunnel.geometry().record_size();
        for (std::size_t start = 0; start < bytes.size(); start += stride) {
            std::size_t const length = std::min(stride, bytes.size() - start);
            if (tunnel.seal(bytes.subspan(start, length), length - secure_tunnel_overhead_k).empty())
                return ucall_status_handshake_failed_k;
        }
        return ucall_status_success_k;
    }

    /** The next send of @p bytes, laid out as whole records: the rest of the send in flight, or
     *  all of them, sealed in place first when the tunnel encrypts. Null once @p bytes are all
     *  sent, or when sealing failed the connection. */
    io_request_t* transmit_from(span<byte_t> bytes) noexcept {
        if (sending) return resume_send();
        if (output_offset == bytes.size()) return nullptr;
        if (ucall_status_t const sealed = seal_records(bytes); sealed != ucall_status_success_k) {
            fail(sealed);
            return nullptr;
        }
        return emit_send(bytes);
    }

    /** Opens every whole record waiting in @c encrypted straight into the tail of @c input,
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
            if (opened.kind == secure_tunnel_record_t::close_k) peer_stream = peer_stream_t::closed_k;
        }
        http_t::drop_bytes(encrypted, consumed);
    }
    void fail(ucall_status_t error) noexcept {
        if (interface_statistics && error == ucall_status_handshake_failed_k)
            tally<atomic_ref>(interface_statistics->handshake_failures);
        status = error;
        stage = transport_stage_t::closing_k;
        crypto_t::secure_zero(peer_static_key);
    }
    std::string_view text() const noexcept { return text_view(input); }

    /** Whether @c input may leave with the @p wire bytes it holds, as room that outgrew them would
     *  stay pinned in whatever pool keeps them next. */
    bool input_may_leave(std::size_t wire) const noexcept {
        return input.capacity() / 2 <= wire || input.capacity() <= page_size();
    }
};

} // namespace unum::ucall::network
