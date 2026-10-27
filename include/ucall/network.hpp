/**
 *  @file include/ucall/network.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Client and server composites over an I/O engine, string kernels, and atomic references.
 */
#pragma once

#include <cstdio>

#include <atomic>   // `std::atomic_ref`
#include <bit>      // `std::bit_ceil`
#include <chrono>   // `std::chrono::year_month_day`, `std::chrono::hh_mm_ss`, `std::chrono::weekday`
#include <optional> // `std::optional`

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
    using http_t::http_stream_body;
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
        releasing_k, // Closing once the kernel lets go of zero-copy sends, or resetting at the linger deadline.
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

    /** The transmit side: idle, or sending a reply's segment, a window's slice, or a client's
     *  newest request. */
    enum class transmit_state_t : std::uint8_t { idle_k, sending_k };

    /** How a connection's close ends its stream: in order, or with a reset once a reply broke off
     *  past its head, so the peer cannot take the truncated body for a whole one. */
    enum class close_mode_t : std::uint8_t { orderly_close_k, reset_close_k };

    /** Whether the event loop adopted any segment of an exchange's reply yet, whether the last one,
     *  and whether its connection let go of it while the kernel still holds its segments; only the
     *  loop writes this. */
    enum class exchange_stage_t : std::uint8_t { dispatched_k, collected_k, ended_k, releasing_k };

    /** Whether a request's body was buffered before dispatch, is still streaming in through
     *  pulls, or streamed to its end; only the loop writes this once dispatched. */
    enum class body_stage_t : std::uint8_t { buffered_k, streaming_k, ended_k };

    /** Whether a request's multipart parts were looked for yet, and whether its body held them. */
    enum class parts_state_t : std::uint8_t { unlocated_k, located_k, malformed_k };

    /** One multipart part's headers and payload, `offset` to `offset + length` of its input. */
    struct request_part_t {
        std::uint64_t offset {}, length {};
    };

    /** Whether zero-copy sends named a release request since it last completed, and whether it is
     *  in flight; segments it covers return to their free lists only once it completes. */
    enum class release_state_t : std::uint8_t { idle_k, named_k, releasing_k };

    /** How a streamed reply delimits its body: by a declared length, in chunks, by the close, or
     *  not at all, as for @c HEAD, @c 204 and @c 304. */
    enum class reply_framing_t : std::uint8_t { length_k, chunked_k, until_close_k, bodiless_k };

    /** Whether a reply's head already left, or waits until the loop sized every file segment. */
    enum class reply_head_t : std::uint8_t { queued_k, deferred_k };

    /** A reading peer takes Linux's default `tcp_rmem` per round trip, so more unsent chunk bytes
     *  only queue. */
    static constexpr std::size_t max_unsent_bytes_k = 128 * 1024;

    /** Each unsent file segment pins a descriptor, so a stream outrunning its peer pins at most
     *  this many. */
    static constexpr std::size_t max_unsent_file_segments_k = 64;

    /** One slice of a reply, linked into its exchange's pushed stack, its send queue, or a free
     *  list; never moved while linked, so the event loop sends from it in place. Under Noise its
     *  bytes are whole records, each payload followed by a gap for its tag and the next header. */
    struct reply_segment_t {
        explicit reply_segment_t(allocator_t const& allocator = {}) noexcept
            : bytes(rebound_allocator<byte_t> {allocator}) {}
        reply_segment_t(reply_segment_t const&) = delete;
        reply_segment_t& operator=(reply_segment_t const&) = delete;
        reply_segment_t(reply_segment_t&&) = delete;
        reply_segment_t& operator=(reply_segment_t&&) = delete;

        vector<byte_t> bytes {}; // Framed bytes between the tunnel's headroom and tailroom.
        reply_segment_t* next {};
    };

    /** How far a file segment got: a path to open, a descriptor to measure, a range ready to read,
     *  or why it cannot be sent. */
    enum class file_segment_stage_t : std::uint8_t {
        unopened_k,
        opened_k,
        measured_k,
        not_found_k,
        out_of_range_k,
        failed_k
    };

    /** Whether a file segment reads the caller's descriptor, or one the loop opened from a path
     *  and closes. */
    enum class file_origin_t : std::uint8_t { caller_descriptor_k, opened_path_k };

    /** A file or path range of a reply, cold beside the memory segments. Its segment links it into
     *  the send queue, holding the path until it opens, then the chunk framing around its range. */
    struct file_segment_t {
        explicit file_segment_t(allocator_t const& allocator = {}) noexcept : segment(allocator) {}
        file_segment_t(file_segment_t const&) = delete;
        file_segment_t& operator=(file_segment_t const&) = delete;
        file_segment_t(file_segment_t&&) = delete;
        file_segment_t& operator=(file_segment_t&&) = delete;

        reply_segment_t segment;
        file_segment_t* next {};
        std::uint64_t file_offset {};     // The next byte to read.
        std::uint64_t remaining_bytes {}; // Still unread; the file's size, once out of range.
        int file_descriptor {-1};         // The directory while unopened, then the file.
        file_segment_stage_t stage {};
        file_origin_t file_origin {};
        std::uint8_t chunk_prefix_bytes {}; // Framing bytes of `segment` ahead of the range.
        std::uint8_t alignment_log2 {};     // Of the file's unbuffered reads, once measured.
    };
    static_assert(sizeof(file_segment_t) == sizeof(reply_segment_t) + 32);
    static_assert(!std::is_empty_v<allocator_t> || sizeof(reply_segment_t) == 32,
                  "a stateless allocator keeps reply segments at 32 bytes and file segments at 64");

    /** Whether @p file_segment holds a file the loop opened from its path, which only the loop
     *  closes. */
    static bool owns_file_descriptor(file_segment_t const& file_segment) noexcept {
        return file_segment.file_origin == file_origin_t::opened_path_k &&
               file_segment.stage != file_segment_stage_t::unopened_k && file_segment.file_descriptor >= 0;
    }

    /** Records one window reads at once: 256 KiB, one or two device commands. */
    static constexpr std::size_t file_window_records_k = 4;

    /** The span of one record's payload slot and its gap, as P + A is 65536 for every alignment A
     *  from 512 to 32768. */
    static constexpr std::size_t file_record_stride_k = 64 * 1024;

    /** A window's headroom, which holds its first record's header and keeps its reads aligned. */
    static constexpr std::size_t page_bytes_k = 4096;

    /** The largest unbuffered alignment a window serves: past it, no record payload fits a slot. */
    static constexpr std::size_t file_max_alignment_k = 32768;

    /** No index, as `file_window_t` links and borrowers spell it. */
    static constexpr std::uint32_t absent_k = std::numeric_limits<std::uint32_t>::max();

    /** Where a pooled window is: free, read into, holding read bytes, being sent, or waiting for
     *  the kernel to let go of it. */
    enum class file_window_stage_t : std::uint8_t { vacant_k, reading_k, filled_k, sending_k, releasing_k };

    /** What a connection's file side does: nothing, open a path, read a window, or wait for one. */
    enum class file_read_state_t : std::uint8_t { idle_k, opening_file_k, reading_file_k, waiting_window_k };

    /** One window of an event loop's pool: an aligned read of a file segment and its slice. */
    struct file_window_t {
        std::uint64_t extent_offset {};      // Aligned file offset the read started at.
        std::uint32_t slice_bytes {};        // Bytes of the requested range in this window.
        std::uint32_t sent_bytes {};         // Of those, taken by the socket.
        std::uint32_t next {absent_k};       // The stream's next window, or the next free one.
        std::uint32_t connection {absent_k}; // The borrower, until the window is vacant again.
        std::uint16_t skipped {};            // Read ahead of the range, below the alignment.
        file_window_stage_t stage {};
    };
    static_assert(sizeof(file_window_t) == 32);

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
            bytes_copied {}, file_window_overlaps {};
    };

    /** The statuses the loop answers itself with, in `interface_statistics_t::refused` order. */
    static constexpr unsigned refused_statuses_k[] {400, 404, 413, 501, 503};

    /** One event loop's refusals, handshake failures and live connections on one interface. */
    struct interface_statistics_t {
        std::uint64_t refused[std::size(refused_statuses_k)] {};
        std::uint64_t handshake_failures {}, authorizer_refusals {}, connections {};
    };
    static_assert(sizeof(interface_statistics_t) == 64);

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

        /** One engine request per direction and one for files; `receive_request` also closes. */
        io_request_t receive_request {}, transmit_request {}, file_read_request {};
        operation_state_t receive_operation {}, transmit_operation {}, file_read_operation {};
        file_read_state_t file_reading {};
        descriptor_t descriptor {-1};
        connection_stage_t stage {connection_stage_t::idle_k};
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
        ucall_noise_key_t peer_static_key {}; // Authenticated at handshake; zero on plaintext connections.
        connection_flags_t flags {connection_none_k};
        vector<byte_t> received {}, record {}; // `record` holds handshake messages only.
        byte_t* sending {};
        std::size_t sending_length {}, sending_offset {};
        std::size_t output_offset {};     // Bytes of the segment in front that sends took.
        std::size_t lingered_bytes {};    // Bytes read and dropped while lingering.
        std::size_t send_buffer_bytes {}; // `SO_SNDBUF` read once, bounding what the kernel holds for it.
        std::uint32_t oldest_window {absent_k}, newest_window {absent_k}; // The stream's windows in file order.
        std::uint32_t releasing_windows {}, releasing_exchanges {};       // Releases the close waits for.
        std::uint32_t index {}; // In its event loop's connections, as windows name their borrower.
        io_vector_t file_read_vectors[file_window_records_k] {};
        connection_t* next_waiting_connection {}; // Links the loop's FIFO of streams waiting for a window.
        network_interface_t* network_interface {};
        client_peer_t* peer {};
        endpoint_t* routed {};                 // Matched once the head of the request being parsed arrived.
        server_exchange_t* streaming {};       // The exchange whose body is arriving; nothing parses behind it.
        server_exchange_t* oldest_exchange {}; // Replies leave in this order.
        server_exchange_t* newest_exchange {};
        std::uint32_t exchanges_in_flight {};
        connection_t* next {}; // Links the event loop's idle list or its ready queue, never both.

        /** The owning event loop's counters; null on client connections, which have no loop. */
        event_loop_statistics_t* statistics {};

        /** The counters of its interface on its event loop; null on client connections. */
        interface_statistics_t* interface_statistics {};

        ucall_status_t configure(secure_tunnel_config_t const& config) noexcept {
            receive_request = transmit_request = file_read_request = {};
            receive_operation = transmit_operation = file_read_operation = operation_state_t::idle_k;
            file_reading = file_read_state_t::idle_k;
            receiving = receive_state_t::reading_k;
            transmitting = transmit_state_t::idle_k;
            close_mode = close_mode_t::orderly_close_k;
            message = {};
            routed = nullptr;
            streaming = nullptr;
            input.clear();
            encrypted.clear();
            sending = nullptr;
            sending_length = sending_offset = output_offset = lingered_bytes = 0;
            deadline = 0;
            flags = connection_none_k;
            crypto_t::secure_zero(peer_static_key);
            auto fault = tunnel.make(config);
            if (fault != secure_tunnel_fault_t::none_k) return ucall_status_handshake_failed_k;
            auto page = page_size();
            if (page <= 0) return ucall_status_io_k;
            if (st::failed(received.resize(static_cast<std::size_t>(page)))) return ucall_status_out_of_memory_k;
            receive_request.context = transmit_request.context = file_read_request.context = this;
            flags = config.mode == secure_tunnel_mode_t::plain_k ? connection_authorized_k : connection_none_k;
            return ucall_status_success_k;
        }

        /** Records what one completion did to bytes and operation states,
         *  deciding nothing for the protocol. */
        void complete(io_completion_t const& completion) noexcept {
            auto& completed = *completion.request;
            // A file operation's outcome belongs to the segment it served, which the server lands.
            if (&completed == &file_read_request) {
                file_read_operation = operation_state_t::idle_k;
                return;
            }
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
            else if (completed.operation == io_operation_t::send_k ||
                     completed.operation == io_operation_t::send_zero_copy_k) {
                if (!result) return fail(ucall_status_connection_closed_k);
                sending_offset += static_cast<std::size_t>(result);
                if (statistics) tally(statistics->bytes_sent, static_cast<std::uint64_t>(result));
                if (sending_offset != sending_length) return;
                // A server credits its zero-copy sends itself, as a window's slice is no segment.
                if (completed.operation == io_operation_t::send_k && stage == connection_stage_t::open_k &&
                    transmitting == transmit_state_t::sending_k)
                    output_offset += sending_length;
                sending = nullptr;
            }
            else if (stage == connection_stage_t::lingering_k) {
                if (completed.operation == io_operation_t::shutdown_k) return;
                lingered_bytes += static_cast<std::size_t>(result);
                if (statistics) tally(statistics->bytes_received, static_cast<std::uint64_t>(result));
                if (!result || lingered_bytes >= linger_bytes_k) fail(ucall_status_success_k);
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
                    // A close sends what the kernel still holds, unless it resets, which purges it.
                    if (releases_pending() && close_mode == close_mode_t::orderly_close_k) {
                        stage = connection_stage_t::releasing_k;
                        deadline = deadline_after(linger_microseconds_k);
                        return nullptr;
                    }
                    return emit(receive_request, io_operation_t::close_k, {});
                }
                if (stage == connection_stage_t::closed_k || stage == connection_stage_t::idle_k ||
                    stage == connection_stage_t::open_k || stage == connection_stage_t::releasing_k)
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
                        if (interface_statistics) tally(interface_statistics->authorizer_refusals);
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
            request = {.operation = operation,
                       .descriptor = descriptor,
                       .data = bytes.data(),
                       .length = bytes.size(),
                       .deadline = operation == io_operation_t::close_k ? 0 : deadline,
                       .context = this};
            return &request;
        }

        /** Starts sending @p bytes, which lie in engine memory @p registered_memory, without
         *  copying them; @p release_request collects the kernel's hold on them once its last send
         *  is done. */
        io_request_t* emit_zero_copy(span<byte_t> bytes, io_request_t& release_request,
                                     registered_memory_t registered_memory) noexcept {
            sending = bytes.data();
            sending_length = bytes.size();
            sending_offset = 0;
            emit(transmit_request, io_operation_t::send_zero_copy_k, bytes);
            transmit_request.registered_memory = registered_memory;
            transmit_request.release_request = &release_request;
            return &transmit_request;
        }

        /** The rest of the send the socket took only part of, with its operation, memory and
         *  release. */
        io_request_t* resume_send() noexcept {
            transmit_request.data = sending + sending_offset;
            transmit_request.length = sending_length - sending_offset;
            transmit_request.deadline = deadline;
            return &transmit_request;
        }

        /** Marks @p request, one of this connection's three, in flight once the engine took it. */
        void submitted(io_request_t const& request) noexcept {
            (&request == &receive_request    ? receive_operation
             : &request == &transmit_request ? transmit_operation
                                             : file_read_operation) = operation_state_t::pending_k;
        }
        bool in_flight() const noexcept {
            return receive_operation == operation_state_t::pending_k ||
                   transmit_operation == operation_state_t::pending_k ||
                   file_read_operation == operation_state_t::pending_k;
        }

        /** Whether the kernel still holds memory this connection sent without copying. */
        bool releases_pending() const noexcept { return releasing_windows || releasing_exchanges; }

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
            sending = bytes.data();
            sending_length = bytes.size();
            sending_offset = 0;
            return emit(transmit_request, io_operation_t::send_k, bytes);
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
            if (interface_statistics && error == ucall_status_handshake_failed_k)
                tally(interface_statistics->handshake_failures);
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
        ucall_body_delivery_t body_delivery {};
        owner<batch_endpoint_t> batch {}; // Apart, so deposits never contend with routing reads of this endpoint.
        void* context {};
        endpoint_t* next {};
    };

    /** Set once a reply began and once it ended, so a claimed reply short of ready is an open
     *  stream, and once the connection left. */
    enum exchange_state_t : std::uint32_t { claimed_k = 1, ready_k = 2, detached_k = 4, listed_k = 8 };

    /** The bit index of one @p state flag, as the single-bit test-and-set takes it. */
    static constexpr unsigned bit_of(exchange_state_t state) noexcept {
        return static_cast<unsigned>(std::countr_zero(static_cast<std::uint32_t>(state)));
    }

    /** One of an exchange's two zero-copy releases: what the sends naming it hold, and the
     *  segments they sent, which return to their free lists once it completes. */
    struct exchange_release_t {
        io_request_t request {};
        reply_segment_t* sent_segments {};
        file_segment_t* sent_file_segments {};
        std::size_t held_bytes {};
        release_state_t state {};
    };

    /** A link of an event loop's replied queue, naming the exchange it carries, or none for the
     *  loop's own stub. */
    struct replied_link_t {
        replied_link_t* next {};
        server_exchange_t* exchange {};
    };

    struct server_exchange_t : ucall_received_http_request_handle_t {
        explicit server_exchange_t(allocator_t const& allocator = {}) noexcept
            : input(rebound_allocator<byte_t> {allocator}), head_segment(allocator), end_segment(allocator),
              body_chunk(rebound_allocator<byte_t> {allocator}), pulled_chunk(rebound_allocator<byte_t> {allocator}),
              parts(rebound_allocator<request_part_t> {allocator}) {
            replied_link.exchange = this;
        }
        server_exchange_t(server_exchange_t const&) = delete;
        server_exchange_t& operator=(server_exchange_t const&) = delete;
        server_exchange_t(server_exchange_t&&) = delete;
        server_exchange_t& operator=(server_exchange_t&&) = delete;
        ~server_exchange_t() noexcept {
            for (reply_segment_t* segment : {free_segments, returned_segments, queued_segments(),
                                             releases[0].sent_segments, releases[1].sent_segments})
                while (segment) {
                    reply_segment_t* next = segment->next;
                    if (segment != &head_segment && segment != &end_segment && !holds_file_segment(segment))
                        allocator_delete<reply_segment_t, allocator_t> {event_loop->allocator}(segment);
                    segment = next;
                }
            for (file_segment_t* file_segment : {free_file_segments, returned_file_segments, queued_file_segments(),
                                                 releases[0].sent_file_segments, releases[1].sent_file_segments})
                while (file_segment) {
                    file_segment_t* next = file_segment->next;
                    if (owns_file_descriptor(*file_segment)) file_close(file_segment->file_descriptor);
                    allocator_delete<file_segment_t, allocator_t> {event_loop->allocator}(file_segment);
                    file_segment = next;
                }
            // The server is going away, so a reply still in flight never reaches its peer.
            if (outcome) publish(outcome, ucall_status_connection_closed_k);
            if (pull_outcome) publish(pull_outcome, ucall_status_connection_closed_k);
        }

        /** The first segment not handed back: parked, adopted unsent, or linked past a cursor that
         *  stays embedded; a retired cursor that was handed back links nothing further. */
        reply_segment_t* queued_segments() noexcept {
            if (parked_segment) return parked_segment;
            if (oldest_segment) return oldest_segment;
            if (!newest_segment) return pushed_segments;
            return newest_segment == &head_segment || newest_segment == &end_segment ? newest_segment->next : nullptr;
        }
        file_segment_t* queued_file_segments() const noexcept {
            if (parked_file_segment) return parked_file_segment;
            if (oldest_file_segment) return oldest_file_segment;
            return newest_file_segment ? nullptr : pushed_file_segments;
        }

        /** Whether @p segment is embedded in one of the file segments queued to send. */
        bool holds_file_segment(reply_segment_t const* segment) const noexcept {
            for (file_segment_t* file_segment = queued_file_segments(); file_segment; file_segment = file_segment->next)
                if (&file_segment->segment == segment) return true;
            return false;
        }

        event_loop_t* event_loop {};
        connection_t* connection {}; // Kept while the kernel holds its segments, past its reply.
        endpoint_t* endpoint {};
        network_interface_t* network_interface {}; // Copied at dispatch, as a batch can outlive its connection.
        ucall_noise_key_t peer_static_key {};
        secure_tunnel_geometry_t geometry {};  // Copied at dispatch; zero headroom and tailroom for plaintext.
        server_exchange_t* next {};            // Links every exchange the event loop owns, until the loop is freed.
        server_exchange_t* replied_next {};    // Links the event loop's free list once recycled.
        replied_link_t replied_link {};        // Queues it for its event loop while listed.
        server_exchange_t* connection_next {}; // Links its connection's exchanges in request order.
        exchange_stage_t stage {};
        http_message_t message {};
        vector<byte_t> input {};
        std::uint32_t state {};
        std::uint64_t arrived {};      // When the request was dispatched, for batch expiry and latency lines.
        std::uint16_t reply_status {}; // The status its reply began with, zero before one did.
        std::size_t copied {};         // Reply body bytes, counted later by the event loop, as any thread may reply.

        /** A stream's status line and headers, and the segment ending every reply: a whole one, or
         *  a stream's last chunk. The loop learns a reply ended by adopting `end_segment`, and only
         *  the chunks between the two ever allocate. */
        reply_segment_t head_segment, end_segment;
        reply_segment_t* pushed_segments {};   // The reply's first segment, which the replier links once.
        reply_segment_t* pushed_tail {};       // The replier's newest, whose `next` the next chain lands in.
        reply_segment_t* returned_segments {}; // Released chunks the loop pushes back; taken whole by the replier.
        reply_segment_t* free_segments {};     // Free chunks only the replier touches.
        reply_segment_t* oldest_segment {};    // The adopted segments the loop sends, in order.
        reply_segment_t* newest_segment {};    // The loop's cursor, whose `next` the replier may still link.
        reply_segment_t* parked_segment {};    // Retired at the cursor, so handed back only once it moves.

        /** File segments, whose own segments sit in the same stacks and queue: the replier
         *  pushes each ahead of its segment, the loop adopts them after the segments, and
         *  recognizes one by its segment reaching the front of the queue. */
        file_segment_t* pushed_file_segments {};   // The reply's first file segment, linked once.
        file_segment_t* pushed_file_tail {};       // The replier's newest file segment.
        file_segment_t* returned_file_segments {}; // Released ones the loop pushes back; taken whole by the replier.
        file_segment_t* free_file_segments {};     // Free ones only the replier touches.
        file_segment_t* oldest_file_segment {};    // The adopted ones, in order.
        file_segment_t* newest_file_segment {};    // The loop's cursor over file segments.
        file_segment_t* parked_file_segment {};    // Retired at either cursor, handed back once both moved.
        std::uint32_t unsent_file_segments {};     // Queued ones the loop has not retired; any thread.
        ucall_outcome_t* outcome {};               // A reply's deferred outcome, which the loop makes final.
        std::size_t unsent_bytes {};               // Queued chunk bytes the socket has not taken; any thread.
        std::uint64_t declared {}, streamed {};    // A streamed body's `content-length` and bytes so far.
        reply_framing_t framing {};                // How the replier frames its chunks.
        reply_head_t reply_head {};                // Whether the loop completes the head once it sized every file.

        /** Sends name `releases[naming]`, each release holding at most half the socket's send
         *  buffer, so the next one fills while the other is in the kernel's hands. */
        exchange_release_t releases[2] {};
        std::uint8_t naming {};
        bool releasing() const noexcept {
            return releases[0].state == release_state_t::releasing_k ||
                   releases[1].state == release_state_t::releasing_k;
        }

        /** The release @p request is, among the two of this exchange. */
        exchange_release_t& release_of(io_request_t const* request) noexcept {
            return releases[request == &releases[1].request];
        }

        /** A streamed request body: the loop decodes into `body_chunk`, and a pull swaps it with
         *  `pulled_chunk`, which the application views until its next pull. Only the loop touches
         *  either; a pull from another thread only raises `pull_requested`. */
        vector<byte_t> body_chunk {}, pulled_chunk {};
        ucall_bytes_view_t* pulled_view {}; // A waiting pull's output, written as the loop finishes it.
        ucall_outcome_t* pull_outcome {};   // A waiting pull's outcome, which the loop makes final.
        std::uint32_t pull_requested {};    // Raised by a pull from any thread, lowered by the loop.
        body_stage_t body_stage {};
        ucall_status_t body_status {};   // How a streamed body ended, which pulls past its bytes report.
        vector<request_part_t> parts {}; // Located on the first lookup, kept for the request's life.
        parts_state_t parts_state {};    // Written only by the one thread operating on the request.
        std::string_view text() const noexcept { return text_view(input); }
    };
    struct network_interface_t {
        explicit network_interface_t(allocator_t const& allocator = {}) noexcept
            : address(rebound_allocator<char> {allocator}), device(rebound_allocator<char> {allocator}),
              reply_directory_descriptors(rebound_allocator<int> {allocator}),
              reply_directory_names(rebound_allocator<char> {allocator}),
              reply_directory_views(rebound_allocator<ucall_bytes_view_t> {allocator}) {}
        network_interface_t(network_interface_t const&) = delete;
        network_interface_t& operator=(network_interface_t const&) = delete;
        network_interface_t(network_interface_t&&) = delete;
        network_interface_t& operator=(network_interface_t&&) = delete;

        ~network_interface_t() noexcept {
            for (int directory : reply_directory_descriptors) file_close(directory);
        }

        ucall_network_interface_t config {};
        vector<char> address {}, device {};
        byte_t public_key[32] {};
        ucall_noise_key_t private_key {}, peer_key {};
        std::size_t active {};
        vector<int>
            reply_directory_descriptors {};    // Opened from `reply_directories`, which path parts resolve beneath.
        std::size_t send_buffer_bytes {};      // The listener's `SO_SNDBUF`, which every accepted socket inherits.
        vector<char> reply_directory_names {}; // Every reply directory, NUL-terminated, back to back.

        /** Views into `reply_directory_names`, as the resolved configuration reports them. */
        vector<ucall_bytes_view_t> reply_directory_views {};
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

    /** One event loop's windows, after UStore's `registered_memory_arena`: each a slab of a page of
     *  headroom and four record strides, registered with the engine at its index while the engine
     *  pins them, grown on demand up to `buffers_limit` and never shrunk. Streams borrow windows in
     *  file order, and each returns once the kernel let go of it, serving the oldest waiting
     *  stream. */
    struct file_window_pool_t {
        static constexpr std::size_t buffer_bytes = page_bytes_k + file_window_records_k * file_record_stride_k;
        struct alignas(page_bytes_k) page_t {
            byte_t bytes[page_bytes_k];
        };
        explicit file_window_pool_t(allocator_t const& allocator = {}) noexcept
            : slabs(rebound_allocator<byte_t*> {allocator}), windows(rebound_allocator<file_window_t> {allocator}),
              release_requests(rebound_allocator<io_request_t> {allocator}) {}
        file_window_pool_t(file_window_pool_t const&) = delete;
        file_window_pool_t& operator=(file_window_pool_t const&) = delete;
        file_window_pool_t(file_window_pool_t&&) = delete;
        file_window_pool_t& operator=(file_window_pool_t&&) = delete;

        vector<byte_t*> slabs {};         // One window each.
        vector<file_window_t> windows {}; // Reserved to `buffers_limit` at open, never moved.

        /** Parallel to `windows`, and engines hold pointers into it; each names the engine buffer
         *  its window's sends lie in as its `registered_memory`. */
        vector<io_request_t> release_requests {};
        std::uint32_t free_windows {absent_k}, buffers_count {}, buffers_limit {}, releasing_count {};
        connection_t *oldest_waiting_connection {}, *newest_waiting_connection {};
        range_pinning_t pinning {range_pinning_t::pinned_k};

        /** The window whose release @p request is, or `absent_k` for an exchange's. */
        std::uint32_t window_of(io_request_t const* request) const noexcept {
            std::size_t const index = static_cast<std::size_t>(request - release_requests.data());
            return request >= release_requests.data() && index < buffers_count ? static_cast<std::uint32_t>(index)
                                                                               : absent_k;
        }
        registered_memory_t registered_memory(std::uint32_t window) const noexcept {
            return release_requests[window].registered_memory;
        }
    };
    enum class event_loop_stage_t { unopened_k, ready_k, quiesced_k };

    /** Whether a loop's StatsD socket is absent, free to send, or sending a datagram. */
    enum class metrics_stage_t : std::uint8_t { closed_k, idle_k, sending_k };

    /** One loop's StatsD socket, what its datagrams last reported, and two datagram buffers: one
     *  composing while the other sends. */
    struct loop_metrics_t {
        explicit loop_metrics_t(allocator_t const& allocator = {}) noexcept
            : composing(rebound_allocator<byte_t> {allocator}), sending(rebound_allocator<byte_t> {allocator}),
              interfaces_reported(rebound_allocator<interface_statistics_t> {allocator}),
              interfaces_pending(rebound_allocator<interface_statistics_t> {allocator}),
              batches_reported(rebound_allocator<ucall_batch_endpoint_statistics_t> {allocator}),
              batches_pending(rebound_allocator<ucall_batch_endpoint_statistics_t> {allocator}) {}
        io_request_t send_request {};
        metrics_stage_t stage {};
        std::uint64_t due {};           // Folded into the poll deadline, as `release_deadline` is.
        float sample_credit {};         // Gains the sample rate per finished request; a latency line spends one.
        std::uint64_t dropped_lines {}; // Latency lines that found both buffers taken.
        vector<byte_t> composing {}, sending {};

        /** What the last delivered datagram reported, and what the one in flight will. */
        ucall_event_loop_statistics_t reported {}, pending {};
        vector<interface_statistics_t> interfaces_reported {}, interfaces_pending {};
        vector<ucall_batch_endpoint_statistics_t> batches_reported {}, batches_pending {}; // Loop zero only.
    };

    struct event_loop_t {
        allocator_t allocator;
        explicit event_loop_t(allocator_t const& allocator = {}) noexcept
            : allocator(allocator), engine(allocator), completions(rebound_allocator<io_completion_t> {allocator}),
              connections(rebound_allocator<owner<connection_t>> {allocator}),
              interface_statistics(rebound_allocator<interface_statistics_t> {allocator}), metrics(allocator),
              file_windows(allocator) {}
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

        /** Vyukov's intrusive queue of listed exchanges: any replying thread exchanges the tail,
         *  and the loop alone walks from the head, which starts at the stub. */
        replied_link_t replied_stub {};
        replied_link_t* replied_head {&replied_stub};
        replied_link_t* replied_tail {&replied_stub};
        ucall_status_t setup_status {ucall_status_success_k};
        event_loop_statistics_t statistics {};
        std::uint32_t index {};
        vector<interface_statistics_t> interface_statistics {}; // One per interface, by its index.
        loop_metrics_t metrics;
        file_window_pool_t file_windows;
        std::size_t max_exchanges {};      // Pipelined requests its connections may hold at once.
        std::uint64_t release_deadline {}; // The earliest linger deadline of a close waiting for releases.
        void notify() noexcept {
            if (polling_event_loop == this) return;
            if (!atomic_ref<std::uint32_t> {wake_pending}.exchange(1, std::memory_order_release)) wake.notify();
        }
        ~event_loop_t() noexcept {
            engine.stop();
            if (wake.descriptors[0] < 0 && wake.request.descriptor >= 0) engine.close_socket(wake.request.descriptor);
            if (metrics.stage != metrics_stage_t::closed_k) engine.close_socket(metrics.send_request.descriptor);
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
            for (byte_t* slab : file_windows.slabs)
                rebound_allocator<typename file_window_pool_t::page_t> {allocator}.deallocate(
                    reinterpret_cast<typename file_window_pool_t::page_t*>(slab),
                    file_window_pool_t::buffer_bytes / page_bytes_k);
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
              batch_endpoints(rebound_allocator<batch_endpoint_t*> {allocator}),
              metrics_text(rebound_allocator<char> {allocator}),
              metrics_tag_views(rebound_allocator<ucall_bytes_view_t> {allocator}) {}
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
        alignas(
            false_sharing_bytes_k) std::uint32_t serving {}; // Read by registrations, apart from what dispatch reads.

        /** The metric prefix then every tag, back to back, as the resolved configuration views. */
        vector<char> metrics_text {};
        vector<ucall_bytes_view_t> metrics_tag_views {};
        ucall_bytes_view_t metrics_prefix {};
        sockaddr_storage metrics_peer {};
        socket_length_t metrics_peer_length {}; // Zero when metrics are off.
        std::size_t metrics_datagram_bytes {};  // The path MTU less the IP and UDP headers.
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
    static std::size_t interface_event_loops(std::string_view device) noexcept {
        if (device.empty()) return 1;
#if UCALL_OS_LINUX_
        char path[256];
        if (find(device, '/') != std::string_view::npos ||
            std::snprintf(path, sizeof(path), "/sys/class/net/%.*s/queues", static_cast<int>(device.size()),
                          device.data()) >= static_cast<int>(sizeof(path)))
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

    /** The largest `SO_RCVBUF` the kernel grants, probed on a socket of its own, since setting it
     *  on the listener would pin every accepted socket's buffer and stop receive autotuning. */
    static std::size_t largest_receive_buffer(int family) noexcept {
        descriptor_t const probe = socket_open(family);
        if (probe < 0) return max_unsent_bytes_k;
        int granted = std::numeric_limits<int>::max();
        socket_length_t length = sizeof(granted);
        if (socket_option(probe, SOL_SOCKET, SO_RCVBUF, &granted, sizeof(granted)) != 0 ||
            getsockopt(probe, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<char*>(&granted), &length) != 0 || granted <= 0)
            granted = static_cast<int>(max_unsent_bytes_k);
        socket_close(probe);
        return static_cast<std::size_t>(granted);
    }
    static ucall_status_t bind_acceptor(network_interface_t& network_interface,
                                        interface_acceptor_t& acceptor) noexcept {
        vector<char> host {rebound_allocator<char> {network_interface.address.get_allocator()}},
            service {host.get_allocator()};
        if (ucall_status_t const started = sockets_start(); started != ucall_status_success_k) return started;
        if (auto status = split_address(text_view(network_interface.config.address), host, service);
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
            if (network_interface.config.device_name.length)
                configured = configured &&
                             socket_option(descriptor, SOL_SOCKET, SO_BINDTODEVICE, network_interface.device.data(),
                                           static_cast<socket_length_t>(network_interface.device.size())) == 0;
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
        network_interface.config.address = bytes_view(
            {network_interface.address.data(), network_interface.address.size() - 1});
        int send_buffer = 0;
        socket_length_t send_buffer_length = sizeof(send_buffer);
        if (getsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<char*>(&send_buffer), &send_buffer_length) !=
                0 ||
            send_buffer <= 0)
            send_buffer = static_cast<int>(max_unsent_bytes_k);
        network_interface.send_buffer_bytes = static_cast<std::size_t>(send_buffer);
        if (!network_interface.config.max_request_bytes)
            network_interface.config.max_request_bytes = largest_receive_buffer(bound.ss_family);
        acceptor.network_interface = &network_interface;
        acceptor.request = {.operation = io_operation_t::accept_k, .descriptor = descriptor, .context = &acceptor};
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
        case ucall_http_status_range_not_satisfiable_k: return "HTTP/1.1 416 Range Not Satisfiable\r\n";
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

    /** Appends validated, lowercased @p headers. A `content-length` is refused, unless @p declared
     *  takes its value instead, as a streamed reply's framing. */
    static ucall_status_t append_headers(vector<byte_t>& output, span<ucall_bytes_view_t const> headers,
                                         http_role_t role, std::optional<std::uint64_t>* declared = nullptr) noexcept {
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
            if (declared && !*declared && equal(name, "content-length")) {
                std::string_view const value = trim_http(line.substr(colon + 1));
                std::uint64_t length {};
                auto parsed = std::from_chars(value.data(), value.data() + value.size(), length);
                if (value.empty() || parsed.ec != std::errc {} || parsed.ptr != value.data() + value.size())
                    return ucall_status_invalid_argument_k;
                *declared = length;
                [[maybe_unused]] st::status_t const dropped = output.resize(previous);
                continue;
            }
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

    /** Starts a reply head after the tunnel's headroom: the status line, `server` and `date`. */
    static ucall_status_t write_reply_head(vector<byte_t>& output, secure_tunnel_geometry_t const& geometry,
                                           unsigned status) noexcept {
        if (status < 200 || status > 599) return ucall_status_invalid_argument_k;
        static constexpr std::string_view classes_k[] {"Successful", "Redirection", "Client Error", "Server Error"};
        char digits[std::numeric_limits<std::size_t>::digits10 + 1], date[http_date_length_k];
        output.clear();
        if (st::failed(output.resize(geometry.headroom))) return ucall_status_out_of_memory_k;
        auto line = status_line(status);
        ucall_status_t result = line.empty() ? append_text(output, {"HTTP/1.1 ", format_decimal(digits, status), " ",
                                                                    classes_k[status / 100 - 2], "\r\n"})
                                             : append_text(output, {line});
        if (result != ucall_status_success_k) return result;
        return append_text(output, {"server: UCall\r\ndate: ", format_date(date, std::time(nullptr)), "\r\n"});
    }

    /** Ends a reply head with the field @p framing announces, `connection`, and the blank line. */
    static ucall_status_t finish_reply_head(vector<byte_t>& output, server_exchange_t const& exchange,
                                            reply_framing_t framing, std::uint64_t length) noexcept {
        char digits[std::numeric_limits<std::uint64_t>::digits10 + 1];
        std::string_view const connection = exchange.message.keep_alive() ? "connection: keep-alive\r\n\r\n"
                                                                          : "connection: close\r\n\r\n";
        switch (framing) {
        case reply_framing_t::length_k:
            return append_text(output, {"content-length: ", format_decimal(digits, length), "\r\n", connection});
        case reply_framing_t::chunked_k: return append_text(output, {"transfer-encoding: chunked\r\n", connection});
        case reply_framing_t::until_close_k:
        case reply_framing_t::bodiless_k: break;
        }
        return append_text(output, {connection});
    }

    /** Appends @p texts to @p bytes, a segment laid out as whole records of @p geometry from its
     *  start: once a record's payload is full, a gap for its tag and the next record's header
     *  follows, so every record seals in place and a send takes them back to back. */
    static ucall_status_t append_records(vector<byte_t>& bytes, secure_tunnel_geometry_t const& geometry,
                                         std::initializer_list<std::string_view> texts) noexcept {
        if (!geometry.tailroom) return append_text(bytes, texts);
        std::size_t total = 0;
        for (std::string_view const text : texts) total += text.size();
        std::size_t const stride = geometry.record_size(), payload_end = geometry.headroom + geometry.max_payload,
                          overhead = stride - geometry.max_payload;
        if (st::failed(bytes.reserve(bytes.size() + total + (total / geometry.max_payload + 1) * overhead)))
            return ucall_status_out_of_memory_k;
        for (std::string_view text : texts)
            while (!text.empty()) {
                std::size_t position = bytes.size() % stride;
                if (position == payload_end) {
                    [[maybe_unused]] st::status_t const gap = bytes.resize(bytes.size() + overhead);
                    position = geometry.headroom;
                }
                std::size_t const taken = std::min(text.size(), payload_end - position), end = bytes.size();
                [[maybe_unused]] st::status_t const grown = bytes.resize(end + taken);
                std::memcpy(bytes.data() + end, text.data(), taken);
                text.remove_prefix(taken);
            }
        return ucall_status_success_k;
    }

    /** Spreads a head written contiguously after one headroom into whole records, which only a head
     *  longer than one record's payload needs. */
    static ucall_status_t spread_records(vector<byte_t>& bytes, secure_tunnel_geometry_t const& geometry) noexcept {
        std::size_t const payload_limit = geometry.max_payload;
        if (!geometry.tailroom || bytes.size() <= geometry.headroom + payload_limit) return ucall_status_success_k;
        std::size_t const payload = bytes.size() - geometry.headroom, stride = geometry.record_size(),
                          records = (payload + payload_limit - 1) / payload_limit;
        if (st::failed(bytes.resize(bytes.size() + (records - 1) * (stride - payload_limit))))
            return ucall_status_out_of_memory_k;
        for (std::size_t record = records - 1; record; --record)
            std::memmove(bytes.data() + record * stride + geometry.headroom,
                         bytes.data() + geometry.headroom + record * payload_limit,
                         std::min(payload_limit, payload - record * payload_limit));
        return ucall_status_success_k;
    }

    /** Lays @p texts out as whole records between the tunnel's headroom and tailroom, ready to seal
     *  in place. */
    static ucall_status_t frame_segment(vector<byte_t>& bytes, secure_tunnel_geometry_t const& geometry,
                                        std::initializer_list<std::string_view> texts) noexcept {
        bytes.clear();
        if (st::failed(bytes.resize(geometry.headroom))) return ucall_status_out_of_memory_k;
        if (ucall_status_t const appended = append_records(bytes, geometry, texts); appended != ucall_status_success_k)
            return appended;
        return st::failed(bytes.resize(bytes.size() + geometry.tailroom)) ? ucall_status_out_of_memory_k
                                                                          : ucall_status_success_k;
    }

    /** Serializes a whole reply of bytes parts into the end segment, its body the parts
     *  concatenated. */
    static ucall_status_t serialize_reply(server_exchange_t& exchange, unsigned status,
                                          span<ucall_bytes_view_t const> headers,
                                          span<ucall_reply_part_t const> parts) noexcept {
        auto& output = exchange.end_segment.bytes;
        if (!output.empty()) return ucall_status_already_exists_k;
        std::size_t length = 0;
        for (ucall_reply_part_t const& part : parts) {
            if (part.data.bytes.length > std::numeric_limits<std::size_t>::max() - length)
                return ucall_status_overflow_k;
            length += part.data.bytes.length;
        }
        bool const bodiless = status == 204 || status == 304;
        if (bodiless && length) return ucall_status_invalid_argument_k;
        std::size_t const sent = exchange.message.verb != ucall_verb_head_k ? length : 0;
        ucall_status_t result = write_reply_head(output, exchange.geometry, status);
        if (result == ucall_status_success_k) result = append_headers(output, headers, http_role_t::response_k);
        if (result == ucall_status_success_k)
            result = finish_reply_head(output, exchange,
                                       bodiless ? reply_framing_t::bodiless_k : reply_framing_t::length_k, length);
        if (result == ucall_status_success_k) result = spread_records(output, exchange.geometry);
        if (sent)
            for (ucall_reply_part_t const& part : parts)
                if (result == ucall_status_success_k)
                    result = append_records(output, exchange.geometry, {text_view(part.data.bytes)});
        if (result == ucall_status_success_k && st::failed(output.resize(output.size() + exchange.geometry.tailroom)))
            result = ucall_status_out_of_memory_k;
        if (result != ucall_status_success_k) {
            output.clear();
            return result;
        }
        exchange.copied = sent;
        return ucall_status_success_k;
    }
    static bool server_stopping(server_exchange_t const& exchange) noexcept {
        return atomic_ref<std::uint32_t> {exchange.event_loop->server->stopped}.load(std::memory_order_acquire);
    }

    /** Whether the request line names HTTP/1.0, whose peers take no chunked body. */
    static bool requests_http_1_0(server_exchange_t const& exchange) noexcept {
        std::string_view const text = exchange.text();
        std::size_t const end = find(text, "\r\n");
        return end != std::string_view::npos && end >= 8 && equal(text.substr(end - 8, 8), "HTTP/1.0");
    }

    /** Whether @p path names a file beneath a directory: not empty, not absolute, and free of NUL
     *  bytes and `..` components. */
    static bool stays_beneath_directory(std::string_view path) noexcept {
        if (path.empty() || path.front() == '/' || find(path, '\0') != std::string_view::npos) return false;
        for (std::size_t start = 0; start <= path.size();) {
            std::size_t const slash = find(path, '/', start);
            std::size_t const end = slash == std::string_view::npos ? path.size() : slash;
            if (equal(path.substr(start, end - start), "..")) return false;
            start = end + 1;
        }
        return true;
    }

    /** Refuses a range whose end overflows. */
    static ucall_status_t check_range(std::uint64_t offset, std::uint64_t length) noexcept {
        return length > std::numeric_limits<std::uint64_t>::max() - offset ? ucall_status_overflow_k
                                                                           : ucall_status_success_k;
    }

    /** Checks one part against @p exchange's interface, answering why it cannot be queued. A
     *  caller's descriptor must read unbuffered, as the loop reads files only that way. */
    static ucall_status_t check_part(server_exchange_t const& exchange, ucall_reply_part_t const& part) noexcept {
        switch (part.kind) {
        case ucall_reply_part_bytes_k:
            return valid_view(part.data.bytes) ? ucall_status_success_k : ucall_status_invalid_argument_k;
        case ucall_reply_part_file_k: {
            ucall_file_range_t const& file = part.data.file;
            if (file.file_descriptor < 0 || file_direct_check(file.file_descriptor) != ucall_status_success_k)
                return ucall_status_invalid_argument_k;
            return check_range(file.offset, file.length);
        }
        case ucall_reply_part_path_k: {
            ucall_path_range_t const& path = part.data.path;
            if (!valid_view(path.relative_path) ||
                path.directory_index >= exchange.network_interface->reply_directory_descriptors.size() ||
                !stays_beneath_directory(text_view(path.relative_path)))
                return ucall_status_invalid_argument_k;
            return check_range(path.offset, path.length);
        }
        default: return ucall_status_invalid_argument_k;
        }
    }

    /** Checks every one of @p parts, counting the file and path parts into @p files. */
    static ucall_status_t check_parts(server_exchange_t const& exchange, span<ucall_reply_part_t const> parts,
                                      std::size_t& files) noexcept {
        files = 0;
        for (ucall_reply_part_t const& part : parts) {
            if (ucall_status_t const checked = check_part(exchange, part); checked != ucall_status_success_k)
                return checked;
            files += part.kind != ucall_reply_part_bytes_k;
        }
        return ucall_status_success_k;
    }

    /** The records one call queues, each list newest first as the pushed stacks hold them, so they
     *  are published together or handed back together. */
    struct reply_batch_t {
        reply_segment_t *newest_segment {}, *oldest_segment {};
        file_segment_t *newest_file_segment {}, *oldest_file_segment {};
        std::size_t bytes {}, copied {}; // Framed bytes the socket will take, and body bytes copied.
        std::uint32_t file_segments {};
    };

    /** A free file segment for @p exchange's replier: its own, then those the loop released, else
     *  one it allocates. */
    static file_segment_t* take_file_segment(server_exchange_t& exchange) noexcept {
        if (!exchange.free_file_segments)
            exchange.free_file_segments = atomic_ref<file_segment_t*> {exchange.returned_file_segments}.exchange(
                nullptr, std::memory_order_acquire);
        if (file_segment_t* file_segment = exchange.free_file_segments) {
            exchange.free_file_segments = file_segment->next;
            return file_segment;
        }
        return allocate_unique<file_segment_t>(exchange.event_loop->allocator, exchange.event_loop->allocator)
            .release();
    }

    /** Frames @p parts into fresh records held in @p batch: bytes parts copied as the exchange's
     *  framing asks, unless it is bodiless, and file and path parts as file segments. Adds the
     *  bytes to `streamed`, and the ranges too unless the loop measures them for a deferred
     *  head. */
    static ucall_status_t build_reply_batch(server_exchange_t& exchange, span<ucall_reply_part_t const> parts,
                                            reply_batch_t& batch) noexcept {
        for (ucall_reply_part_t const& part : parts) {
            if (part.kind == ucall_reply_part_bytes_k) {
                std::string_view const data = text_view(part.data.bytes);
                exchange.streamed += data.size();
                if (data.empty() || exchange.framing == reply_framing_t::bodiless_k) continue;
                reply_segment_t* segment = take_segment(exchange);
                if (!segment) return ucall_status_out_of_memory_k;
                segment->next = batch.newest_segment;
                batch.newest_segment = segment;
                if (!batch.oldest_segment) batch.oldest_segment = segment;
                char digits[sizeof(std::size_t) * 2];
                auto written = std::to_chars(digits, digits + sizeof(digits), data.size(), 16);
                std::string_view const size {digits, static_cast<std::size_t>(written.ptr - digits)};
                ucall_status_t const framed = exchange.framing == reply_framing_t::chunked_k
                                                  ? frame_segment(segment->bytes, exchange.geometry,
                                                                  {size, "\r\n", data, "\r\n"})
                                                  : frame_segment(segment->bytes, exchange.geometry, {data});
                if (framed != ucall_status_success_k) return framed;
                batch.bytes += segment->bytes.size();
                batch.copied += data.size();
                continue;
            }
            file_segment_t* record = take_file_segment(exchange);
            if (!record) return ucall_status_out_of_memory_k;
            record->next = batch.newest_file_segment;
            batch.newest_file_segment = record;
            if (!batch.oldest_file_segment) batch.oldest_file_segment = record;
            record->segment.bytes.clear();
            record->segment.next = batch.newest_segment;
            batch.newest_segment = &record->segment;
            if (!batch.oldest_segment) batch.oldest_segment = &record->segment;
            record->chunk_prefix_bytes = 0;
            record->alignment_log2 = 0;
            ++batch.file_segments;
            if (part.kind == ucall_reply_part_file_k) {
                ucall_file_range_t const& file = part.data.file;
                record->file_offset = file.offset;
                record->remaining_bytes = file.length;
                record->file_descriptor = file.file_descriptor;
                record->stage = file_segment_stage_t::opened_k;
                record->file_origin = file_origin_t::caller_descriptor_k;
            }
            else {
                ucall_path_range_t const& path = part.data.path;
                record->file_offset = path.offset;
                record->remaining_bytes = path.length;
                record->file_descriptor = exchange.network_interface->reply_directory_descriptors[path.directory_index];
                record->stage = file_segment_stage_t::unopened_k;
                record->file_origin = file_origin_t::opened_path_k;
                if (ucall_status_t const copied = append_text(
                        record->segment.bytes, {text_view(path.relative_path), std::string_view {"\0", 1}});
                    copied != ucall_status_success_k)
                    return copied;
            }
            if (exchange.reply_head == reply_head_t::queued_k) exchange.streamed += record->remaining_bytes;
        }
        return ucall_status_success_k;
    }

    /** Hands every record of @p batch back to the replier's free lists, unpublished. */
    static void discard_reply_batch(server_exchange_t& exchange, reply_batch_t& batch) noexcept {
        for (reply_segment_t* segment = batch.newest_segment; segment;) {
            reply_segment_t* next = segment->next;
            file_segment_t* owner = batch.newest_file_segment;
            while (owner && &owner->segment != segment) owner = owner->next;
            if (!owner) {
                segment->next = exchange.free_segments;
                exchange.free_segments = segment;
            }
            segment = next;
        }
        for (file_segment_t* file_segment = batch.newest_file_segment; file_segment;) {
            file_segment_t* next = file_segment->next;
            file_segment->segment.bytes.clear();
            file_segment->next = exchange.free_file_segments;
            exchange.free_file_segments = file_segment;
            file_segment = next;
        }
        batch = {};
    }

    /** Publishes @p batch: its file segments ahead of their segments, then the segments between
     *  @p first and @p last when given, so the loop never meets a file segment's own segment before
     *  the file segment. */
    static void push_reply_batch(server_exchange_t& exchange, reply_batch_t& batch, reply_segment_t* first = nullptr,
                                 reply_segment_t* last = nullptr) noexcept {
        exchange.copied += batch.copied;
        atomic_ref<std::size_t> {exchange.unsent_bytes}.add(batch.bytes, std::memory_order_relaxed);
        atomic_ref<std::uint32_t> {exchange.unsent_file_segments}.add(batch.file_segments, std::memory_order_relaxed);
        if (batch.newest_file_segment)
            link_chain(exchange.pushed_file_segments, exchange.pushed_file_tail, *batch.newest_file_segment,
                       *batch.oldest_file_segment);
        reply_segment_t* newest = batch.newest_segment;
        reply_segment_t* oldest = batch.oldest_segment;
        if (first) {
            if (oldest) oldest->next = first;
            else newest = first;
            oldest = first;
        }
        if (last) {
            last->next = newest;
            newest = last;
            if (!oldest) oldest = last;
        }
        if (newest) push_segments(exchange, *newest, *oldest);
    }

    /** Queues a reply whose file segments the loop must measure before its head: the head without
     *  its framing in `head_segment`, the parts, and an empty `end_segment`. The outcome reads
     *  deferred before the loop can see the reply, which then makes it final. */
    static ucall_status_t queue_measured_reply(server_exchange_t& exchange, ucall_outcome_t* outcome, unsigned status,
                                               span<ucall_bytes_view_t const> headers,
                                               span<ucall_reply_part_t const> parts) noexcept {
        exchange.framing = exchange.message.verb == ucall_verb_head_k ? reply_framing_t::bodiless_k
                                                                      : reply_framing_t::length_k;
        exchange.reply_head = reply_head_t::deferred_k;
        exchange.streamed = exchange.declared = 0;
        reply_batch_t batch {};
        auto& head = exchange.head_segment.bytes;
        ucall_status_t result = build_reply_batch(exchange, parts, batch);
        if (result == ucall_status_success_k) result = write_reply_head(head, exchange.geometry, status);
        if (result == ucall_status_success_k) result = append_headers(head, headers, http_role_t::response_k);
        if (result != ucall_status_success_k) {
            head.clear();
            discard_reply_batch(exchange, batch);
            return result;
        }
        publish(outcome, ucall_status_deferred_k);
        exchange.outcome = outcome;
        exchange.end_segment.bytes.clear();
        atomic_ref<std::uint32_t> {exchange.state}.set_bits(ready_k, std::memory_order_release);
        push_reply_batch(exchange, batch, &exchange.head_segment, &exchange.end_segment);
        return ucall_status_deferred_k;
    }

    /** Answers @p exchange with @p parts. Bytes alone are serialized whole and final on return;
     *  with any file or path part the reply is queued, and the outcome reads deferred until the
     *  loop sent every part. */
    static ucall_status_t reply(server_exchange_t& exchange, ucall_outcome_t* outcome, unsigned status,
                                span<ucall_bytes_view_t const> headers, span<ucall_reply_part_t const> parts) noexcept {
        std::size_t files = 0;
        if (ucall_status_t const checked = check_parts(exchange, parts, files); checked != ucall_status_success_k)
            return checked;
        if (files && (status == 204 || status == 304)) return ucall_status_invalid_argument_k;
        auto state = atomic_ref<std::uint32_t> {exchange.state};
        if (state.fetch_test_and_set_bit(bit_of(claimed_k), std::memory_order_acq_rel))
            return ucall_status_already_exists_k;
        exchange.reply_status = static_cast<std::uint16_t>(status);
        if ((state.load(std::memory_order_acquire) & detached_k) || server_stopping(exchange)) {
            state.set_bits(detached_k | ready_k, std::memory_order_release);
            abandon_reply(exchange);
            return ucall_status_connection_closed_k;
        }
        auto result = files ? queue_measured_reply(exchange, outcome, status, headers, parts)
                            : serialize_reply(exchange, status, headers, parts);
        if (result == ucall_status_deferred_k) return result;
        if (result != ucall_status_success_k) {
            state.clear_bits(claimed_k, std::memory_order_release);
            return result;
        }
        auto const previous = state.fetch_or(ready_k, std::memory_order_release);
        push_segment(exchange, exchange.end_segment);
        return previous & detached_k ? ucall_status_connection_closed_k : ucall_status_success_k;
    }

    /** Ends a reply with an empty end segment, so its exchange recycles whether the connection
     *  lives or not. */
    static void abandon_reply(server_exchange_t& exchange) noexcept {
        exchange.end_segment.bytes.clear();
        push_segment(exchange, exchange.end_segment);
    }

    /** Opens a streamed reply: claims the exchange, picks its body's framing, queues the head. */
    static ucall_status_t begin_reply(server_exchange_t& exchange, unsigned status,
                                      span<ucall_bytes_view_t const> headers) noexcept {
        auto state = atomic_ref<std::uint32_t> {exchange.state};
        if (state.fetch_test_and_set_bit(bit_of(claimed_k), std::memory_order_acq_rel))
            return ucall_status_already_exists_k;
        exchange.reply_status = static_cast<std::uint16_t>(status);
        exchange.declared = exchange.streamed = 0;
        exchange.framing = reply_framing_t::bodiless_k;
        exchange.reply_head = reply_head_t::queued_k;
        if ((state.load(std::memory_order_acquire) & detached_k) || server_stopping(exchange)) {
            state.set_bits(detached_k, std::memory_order_release);
            return ucall_status_connection_closed_k;
        }
        std::optional<std::uint64_t> declared;
        auto& output = exchange.head_segment.bytes;
        ucall_status_t result = write_reply_head(output, exchange.geometry, status);
        if (result == ucall_status_success_k)
            result = append_headers(output, headers, http_role_t::response_k, &declared);
        bool const head_request = exchange.message.verb == ucall_verb_head_k;
        reply_framing_t framing = declared                       ? reply_framing_t::length_k
                                  : !requests_http_1_0(exchange) ? reply_framing_t::chunked_k
                                  : head_request                 ? reply_framing_t::bodiless_k
                                                                 : reply_framing_t::until_close_k;
        if (status == 204 || status == 304) {
            if (declared) result = ucall_status_invalid_argument_k;
            framing = reply_framing_t::bodiless_k;
        }
        if (framing == reply_framing_t::until_close_k) exchange.message.connection = http_connection_t::close_k;
        if (result == ucall_status_success_k)
            result = finish_reply_head(output, exchange, framing, declared.value_or(0));
        if (result == ucall_status_success_k) result = spread_records(output, exchange.geometry);
        if (result == ucall_status_success_k && st::failed(output.resize(output.size() + exchange.geometry.tailroom)))
            result = ucall_status_out_of_memory_k;
        if (result != ucall_status_success_k) {
            output.clear();
            state.clear_bits(claimed_k, std::memory_order_release);
            return result;
        }
        exchange.framing = head_request ? reply_framing_t::bodiless_k : framing;
        exchange.declared = declared.value_or(0);
        push_segment(exchange, exchange.head_segment);
        return ucall_status_success_k;
    }

    /** A free chunk segment for @p exchange's replier: its own, then those the loop released, else
     *  one it allocates. */
    static reply_segment_t* take_segment(server_exchange_t& exchange) noexcept {
        if (!exchange.free_segments)
            exchange.free_segments = atomic_ref<reply_segment_t*> {exchange.returned_segments}.exchange(
                nullptr, std::memory_order_acquire);
        if (reply_segment_t* segment = exchange.free_segments) {
            exchange.free_segments = segment->next;
            return segment;
        }
        return allocate_unique<reply_segment_t>(exchange.event_loop->allocator, exchange.event_loop->allocator)
            .release();
    }

    /** Queues @p parts on the open reply together, unless the socket lags behind its bytes or too
     *  many file segments wait. */
    static ucall_status_t append_reply_parts(server_exchange_t& exchange,
                                             span<ucall_reply_part_t const> parts) noexcept {
        std::uint32_t const state = atomic_ref<std::uint32_t> {exchange.state}.load(std::memory_order_acquire);
        if (!(state & claimed_k) || (state & ready_k)) return ucall_status_invalid_argument_k;
        std::size_t files = 0;
        if (ucall_status_t const checked = check_parts(exchange, parts, files); checked != ucall_status_success_k)
            return checked;
        if ((state & detached_k) || server_stopping(exchange)) return ucall_status_connection_closed_k;
        std::uint64_t length = 0;
        for (ucall_reply_part_t const& part : parts) {
            std::uint64_t const size = part.kind == ucall_reply_part_bytes_k  ? part.data.bytes.length
                                       : part.kind == ucall_reply_part_file_k ? part.data.file.length
                                                                              : part.data.path.length;
            if (part.kind != ucall_reply_part_bytes_k && !size && exchange.framing == reply_framing_t::length_k)
                return ucall_status_invalid_argument_k;
            if (size > std::numeric_limits<std::uint64_t>::max() - length) return ucall_status_overflow_k;
            length += size;
        }
        if (exchange.framing == reply_framing_t::bodiless_k) {
            if (exchange.message.verb != ucall_verb_head_k && (length || files)) return ucall_status_invalid_argument_k;
            return ucall_status_success_k;
        }
        if (exchange.framing == reply_framing_t::length_k && length > exchange.declared - exchange.streamed)
            return ucall_status_overflow_k;
        if (files > max_unsent_file_segments_k) return ucall_status_invalid_argument_k;
        if (atomic_ref<std::size_t> {exchange.unsent_bytes}.load(std::memory_order_relaxed) > max_unsent_bytes_k ||
            atomic_ref<std::uint32_t> {exchange.unsent_file_segments}.load(std::memory_order_relaxed) + files >
                max_unsent_file_segments_k)
            return ucall_status_would_block_k;
        std::uint64_t const streamed = exchange.streamed;
        reply_batch_t batch {};
        if (ucall_status_t const built = build_reply_batch(exchange, parts, batch); built != ucall_status_success_k) {
            discard_reply_batch(exchange, batch);
            exchange.streamed = streamed;
            return built;
        }
        push_reply_batch(exchange, batch);
        return ucall_status_success_k;
    }

    /** Closes the open reply with its last chunk, closing the connection after a body cut short of
     *  its declared length. With file segments still unsent, @p outcome reads deferred until the
     *  loop sent them, then reports what the call would have. */
    static ucall_status_t end_reply(server_exchange_t& exchange, ucall_outcome_t* outcome) noexcept {
        auto state = atomic_ref<std::uint32_t> {exchange.state};
        std::uint32_t const current = state.load(std::memory_order_acquire);
        if (!(current & claimed_k) || (current & ready_k)) return ucall_status_invalid_argument_k;
        auto& end_segment = exchange.end_segment;
        end_segment.bytes.clear();
        ucall_status_t result = ucall_status_success_k;
        if ((current & detached_k) || server_stopping(exchange)) result = ucall_status_connection_closed_k;
        else if (exchange.framing == reply_framing_t::length_k && exchange.streamed != exchange.declared)
            result = ucall_status_malformed_k;
        else if (exchange.framing == reply_framing_t::chunked_k)
            result = frame_segment(end_segment.bytes, exchange.geometry, {"0\r\n\r\n"});
        if (result != ucall_status_success_k && result != ucall_status_connection_closed_k) {
            end_segment.bytes.clear();
            exchange.message.connection = http_connection_t::close_k;
        }
        // The loop may still read a borrowed descriptor, so the loop reports how the reply ended.
        if (atomic_ref<std::uint32_t> {exchange.unsent_file_segments}.load(std::memory_order_acquire)) {
            publish(outcome, ucall_status_deferred_k);
            exchange.outcome = outcome;
            result = ucall_status_deferred_k;
        }
        if ((state.fetch_or(ready_k, std::memory_order_release) & detached_k) && result != ucall_status_deferred_k)
            result = ucall_status_connection_closed_k;
        push_segment(exchange, end_segment);
        return result;
    }

    /** Turns the chain from @p newest down to @p oldest around and links it behind @p tail, or as
     *  @p first when nothing was linked yet, publishing it to the loop with one release store. */
    template <typename record_type_>
    static void link_chain(record_type_*& first, record_type_*& tail, record_type_& newest,
                           record_type_& oldest) noexcept {
        record_type_* forward = nullptr;
        for (record_type_* record = &newest; record;) {
            record_type_* older = record == &oldest ? nullptr : record->next;
            record->next = forward;
            forward = record;
            record = older;
        }
        atomic_ref<record_type_*> {tail ? tail->next : first}.store(&oldest, std::memory_order_release);
        tail = &newest;
    }

    /** Moves the chain linked after @p newest, or from @p first, into the loop's queue; false when
     *  the replier linked nothing new. */
    template <typename record_type_>
    static bool adopt_chain(record_type_*& first, record_type_*& oldest, record_type_*& newest) noexcept {
        record_type_* next = atomic_ref<record_type_*> {newest ? newest->next : first}.load(std::memory_order_acquire);
        if (!next) return false;
        if (!oldest) oldest = next;
        for (; next; next = atomic_ref<record_type_*> {next->next}.load(std::memory_order_acquire)) newest = next;
        return true;
    }

    /** Links the chain from @p newest down to @p oldest behind the exchange's earlier segments and
     *  lists the exchange for its event loop. Only the one replier of an exchange calls it. */
    static void push_segments(server_exchange_t& exchange, reply_segment_t& newest, reply_segment_t& oldest) noexcept {
        link_chain(exchange.pushed_segments, exchange.pushed_tail, newest, oldest);
        list_replied(exchange);
    }

    /** Lists @p exchange for its event loop once, however many pushes and pulls raced to. */
    static void list_replied(server_exchange_t& exchange) noexcept {
        if (!atomic_ref<std::uint32_t> {exchange.state}.fetch_test_and_set_bit(bit_of(listed_k),
                                                                               std::memory_order_acq_rel))
            push_replied(exchange);
    }
    static void push_segment(server_exchange_t& exchange, reply_segment_t& segment) noexcept {
        push_segments(exchange, segment, segment);
    }

    /** Hands an exchange with more reply segments to its event loop from any thread; only it
     *  recycles one. */
    static void push_replied(server_exchange_t& exchange) noexcept {
        auto* event_loop = exchange.event_loop;
        enqueue_replied(*event_loop, exchange.replied_link);
        event_loop->notify();
    }

    /** Appends @p link with one exchange of the tail; until the pusher links its predecessor to it,
     *  the loop stops short of it, and the pusher's notify brings the loop back. */
    static void enqueue_replied(event_loop_t& event_loop, replied_link_t& link) noexcept {
        atomic_ref<replied_link_t*> {link.next}.store(nullptr, std::memory_order_relaxed);
        auto* previous = atomic_ref<replied_link_t*> {event_loop.replied_tail}.exchange(&link,
                                                                                        std::memory_order_acq_rel);
        atomic_ref<replied_link_t*> {previous->next}.store(&link, std::memory_order_release);
    }

    /** The next listed exchange, or null when none is linked yet; only the loop calls it. */
    static server_exchange_t* dequeue_replied(event_loop_t& event_loop) noexcept {
        auto next_of = [](replied_link_t* link) noexcept {
            return atomic_ref<replied_link_t*> {link->next}.load(std::memory_order_acquire);
        };
        replied_link_t* head = event_loop.replied_head;
        replied_link_t* next = next_of(head);
        if (head == &event_loop.replied_stub) {
            if (!next) return nullptr;
            event_loop.replied_head = head = next;
            next = next_of(head);
        }
        if (!next) {
            // The last link stays until the stub is queued behind it, so the tail never dangles.
            if (head != atomic_ref<replied_link_t*> {event_loop.replied_tail}.load(std::memory_order_acquire))
                return nullptr;
            enqueue_replied(event_loop, event_loop.replied_stub);
            next = next_of(head);
            if (!next) return nullptr;
        }
        event_loop.replied_head = next;
        return head->exchange;
    }

    /** Moves the pushed stack to the back of the send queue in push order, noting whether the
     *  reply ended, then the file segments published ahead of those segments. */
    static void adopt_segments(server_exchange_t& exchange) noexcept {
        if (!adopt_chain(exchange.pushed_segments, exchange.oldest_segment, exchange.newest_segment)) return;
        exchange.stage = exchange.newest_segment == &exchange.end_segment ? exchange_stage_t::ended_k
                                                                          : exchange_stage_t::collected_k;
        // File segments are linked ahead of their own segments, so this meets each adopted above.
        adopt_chain(exchange.pushed_file_segments, exchange.oldest_file_segment, exchange.newest_file_segment);
        return_parked(exchange);
    }

    /** Pushes the chain from @p newest down to @p oldest onto the stack at @p head, which a
     *  replier takes whole. */
    template <typename record_type_>
    static void push_returned(record_type_*& head, record_type_& newest, record_type_& oldest) noexcept {
        auto stack = atomic_ref<record_type_*> {head};
        auto* next = stack.load(std::memory_order_relaxed);
        do {
            oldest.next = next;
        } while (!stack.compare_exchange_weak(next, &newest, std::memory_order_release, std::memory_order_relaxed));
    }

    /** Hands a sent or abandoned chunk back to its replier, or keeps it while sends of the exchange
     *  named a release the kernel has not completed. */
    static void retire_segment(server_exchange_t& exchange, reply_segment_t& segment) noexcept {
        if (&segment == &exchange.head_segment || &segment == &exchange.end_segment) return;
        atomic_ref<std::size_t> {exchange.unsent_bytes}.sub(segment.bytes.size(), std::memory_order_relaxed);
        if (&segment == exchange.newest_segment && replier_links(exchange)) {
            exchange.parked_segment = &segment;
            return;
        }
        return_segment(exchange, segment);
    }

    /** Hands a retired chunk back, or keeps it while the kernel may hold it. */
    static void return_segment(server_exchange_t& exchange, reply_segment_t& segment) noexcept {
        // A segment retires before the next send, so the release its send named is still named.
        exchange_release_t& release = exchange.releases[exchange.naming];
        if (release.state != release_state_t::idle_k) {
            segment.next = release.sent_segments;
            release.sent_segments = &segment;
        }
        else push_returned(exchange.returned_segments, segment, segment);
    }

    /** The file segment whose own segment leads @p exchange's queue, or null when a memory segment
     *  does. */
    static file_segment_t* front_file_segment(server_exchange_t const& exchange) noexcept {
        file_segment_t* file_segment = exchange.oldest_file_segment;
        return file_segment && &file_segment->segment == exchange.oldest_segment ? file_segment : nullptr;
    }

    /** Closes the file the oldest file segment opened from a path, and hands its record back to
     *  the replier, or keeps it while the kernel may hold its framing. */
    static void retire_file_segment(server_exchange_t& exchange, file_segment_t& file_segment) noexcept {
        exchange.oldest_file_segment = &file_segment == exchange.newest_file_segment ? nullptr : file_segment.next;
        if (owns_file_descriptor(file_segment)) file_close(file_segment.file_descriptor);
        file_segment.file_descriptor = -1;
        // Releasing orders the last use of a borrowed descriptor before a replier sees none unsent.
        atomic_ref<std::uint32_t> {exchange.unsent_file_segments}.sub(1, std::memory_order_release);
        if ((&file_segment == exchange.newest_file_segment || &file_segment.segment == exchange.newest_segment) &&
            replier_links(exchange)) {
            exchange.parked_file_segment = &file_segment;
            return;
        }
        return_file_segment(exchange, file_segment);
    }

    /** Hands a retired file segment back, or keeps it while the kernel may hold its framing. */
    static void return_file_segment(server_exchange_t& exchange, file_segment_t& file_segment) noexcept {
        exchange_release_t& release = exchange.releases[exchange.naming];
        if (release.state != release_state_t::idle_k) {
            file_segment.next = release.sent_file_segments;
            release.sent_file_segments = &file_segment;
            return;
        }
        file_segment.segment.bytes.clear();
        push_returned(exchange.returned_file_segments, file_segment, file_segment);
    }

    /** Retires the front of @p exchange's queue, a file or memory segment, sent or not. */
    static void retire_oldest_segment(server_exchange_t& exchange) noexcept {
        reply_segment_t& segment = *exchange.oldest_segment;
        file_segment_t* file_segment = front_file_segment(exchange);
        exchange.oldest_segment = &segment == exchange.newest_segment ? nullptr : segment.next;
        if (file_segment) retire_file_segment(exchange, *file_segment);
        else retire_segment(exchange, segment);
    }

    /** Whether the replier may still link records behind the cursors, until the end is adopted. */
    static bool replier_links(server_exchange_t const& exchange) noexcept {
        return exchange.stage == exchange_stage_t::dispatched_k || exchange.stage == exchange_stage_t::collected_k;
    }

    /** Hands back the records parked at the cursors once the cursors moved past them, or the reply
     *  ended, after which the replier links nothing more. */
    static void return_parked(server_exchange_t& exchange) noexcept {
        bool const ended = !replier_links(exchange);
        if (auto* parked = exchange.parked_segment; parked && (ended || parked != exchange.newest_segment)) {
            exchange.parked_segment = nullptr;
            return_segment(exchange, *parked);
        }
        if (auto* parked = exchange.parked_file_segment;
            parked &&
            (ended || (parked != exchange.newest_file_segment && &parked->segment != exchange.newest_segment))) {
            exchange.parked_file_segment = nullptr;
            return_file_segment(exchange, *parked);
        }
    }

    /** Retires every adopted segment and file segment of @p exchange, sent or not. */
    static void release_all_segments(server_exchange_t& exchange) noexcept {
        while (exchange.oldest_segment) retire_oldest_segment(exchange);
    }

    /** Hands back every segment the release of @p exchange covered, once the kernel let go. */
    static void return_released_segments(server_exchange_t& exchange, exchange_release_t& release) noexcept {
        if (reply_segment_t* newest = std::exchange(release.sent_segments, nullptr)) {
            reply_segment_t* oldest = newest;
            while (oldest->next) oldest = oldest->next;
            push_returned(exchange.returned_segments, *newest, *oldest);
        }
        if (file_segment_t* newest = std::exchange(release.sent_file_segments, nullptr)) {
            file_segment_t* oldest = newest;
            for (;; oldest = oldest->next) {
                oldest->segment.bytes.clear();
                if (!oldest->next) break;
            }
            push_returned(exchange.returned_file_segments, *newest, *oldest);
        }
        release.state = release_state_t::idle_k;
        release.held_bytes = 0;
    }

    /** Makes a reply's deferred outcome final with @p status, once. */
    static void publish_reply_outcome(server_exchange_t& exchange, ucall_status_t status) noexcept {
        if (exchange.outcome) publish(std::exchange(exchange.outcome, nullptr), status);
    }

    /** Unlinks every exchange of a closed connection: ended ones recycle now, the rest once their
     *  reply or the stop path ends them. */
    static void detach(event_loop_t& event_loop, connection_t& connection) noexcept {
        for (auto* exchange = connection.oldest_exchange; exchange;) {
            auto* next = std::exchange(exchange->connection_next, nullptr);
            exchange->connection = nullptr;
            if (exchange->body_stage == body_stage_t::streaming_k) {
                exchange->body_stage = body_stage_t::ended_k;
                exchange->body_status = ucall_status_connection_closed_k;
            }
            finish_pull(*exchange, ucall_status_connection_closed_k);
            if (exchange->stage == exchange_stage_t::ended_k)
                recycle_exchange(event_loop, *exchange, ucall_status_connection_closed_k);
            else {
                atomic_ref<std::uint32_t> {exchange->state}.set_bits(detached_k, std::memory_order_release);
                release_all_segments(*exchange);
            }
            exchange = next;
        }
        connection.oldest_exchange = connection.newest_exchange = nullptr;
        connection.streaming = nullptr;
        connection.routed = nullptr;
        connection.exchanges_in_flight = 0;
    }

    /** @p key followed by the decimal @p value, written into @p output. */
    template <std::size_t capacity_>
    static std::string_view tag_text(char (&output)[capacity_], std::string_view key, std::uint64_t value) noexcept {
        std::memcpy(output, key.data(), key.size());
        auto written = std::to_chars(output + key.size(), output + capacity_, value);
        return {output, static_cast<std::size_t>(written.ptr - output)};
    }

    /** @p key followed by as much of @p value as @p output holds. */
    template <std::size_t capacity_>
    static std::string_view tag_text(char (&output)[capacity_], std::string_view key, std::string_view value) noexcept {
        std::size_t const length = std::min(value.size(), capacity_ - key.size());
        std::memcpy(output, key.data(), key.size());
        std::memcpy(output + key.size(), value.data(), length);
        return {output, key.size() + length};
    }

    /** Appends one StatsD line, `prefix.name:value|type` with the global tags and @p tags, or
     *  leaves @p datagram as it was with overflow when the line would pass the datagram's bound. */
    static ucall_status_t append_metric(server_t const& server, vector<byte_t>& datagram, std::string_view name,
                                        std::string_view value, std::string_view type,
                                        std::initializer_list<std::string_view> tags) noexcept {
        std::size_t const before = datagram.size();
        ucall_status_t status = append_text(
            datagram, {before ? "\n" : "", text_view(server.metrics_prefix), ".", name, ":", value, "|", type});
        std::string_view separator = "|#";
        for (ucall_bytes_view_t tag : server.metrics_tag_views) {
            if (status == ucall_status_success_k) status = append_text(datagram, {separator, text_view(tag)});
            separator = ",";
        }
        for (std::string_view tag : tags) {
            if (status == ucall_status_success_k) status = append_text(datagram, {separator, tag});
            separator = ",";
        }
        if (status == ucall_status_success_k && datagram.size() > server.metrics_datagram_bytes)
            status = ucall_status_overflow_k;
        if (status != ucall_status_success_k) {
            [[maybe_unused]] st::status_t const shrunk = datagram.resize(before); // Never grows.
        }
        return status;
    }

    /** Hands the composing datagram to the engine, when the previous one left. */
    static void send_metrics(event_loop_t& event_loop) noexcept {
        auto& metrics = event_loop.metrics;
        if (metrics.stage != metrics_stage_t::idle_k || metrics.composing.empty()) return;
        std::swap(metrics.composing, metrics.sending);
        metrics.composing.clear();
        metrics.send_request.data = metrics.sending.data();
        metrics.send_request.length = metrics.sending.size();
        if (event_loop.engine.submit(metrics.send_request) == ucall_status_success_k)
            metrics.stage = metrics_stage_t::sending_k;
        else metrics.sending.clear();
    }

    /** Starts the next datagram's counters from what the last delivered one reported. */
    static void restart_pending(loop_metrics_t& metrics) noexcept {
        metrics.pending = metrics.reported;
        std::memcpy(metrics.interfaces_pending.data(), metrics.interfaces_reported.data(),
                    metrics.interfaces_reported.size() * sizeof(interface_statistics_t));
        std::memcpy(metrics.batches_pending.data(), metrics.batches_reported.data(),
                    metrics.batches_reported.size() * sizeof(ucall_batch_endpoint_statistics_t));
    }

    /** Settles a sent datagram: delivered counters become the base of the next deltas, and a failed
     *  one leaves them to the next datagram. */
    static void complete_metrics(event_loop_t& event_loop, io_completion_t const& completion) noexcept {
        auto& metrics = event_loop.metrics;
        metrics.stage = metrics_stage_t::idle_k;
        metrics.sending.clear();
        if (completion.result < 0) return;
        metrics.reported = metrics.pending;
        std::memcpy(metrics.interfaces_reported.data(), metrics.interfaces_pending.data(),
                    metrics.interfaces_pending.size() * sizeof(interface_statistics_t));
        std::memcpy(metrics.batches_reported.data(), metrics.batches_pending.data(),
                    metrics.batches_pending.size() * sizeof(ucall_batch_endpoint_statistics_t));
    }

    /** Writes a latency line for one in every `1 / metrics_sample_rate` finished requests, sending
     *  early when it would not fit, and dropping it when both datagrams are taken. */
    static void time_request(server_t& server, event_loop_t& event_loop, server_exchange_t const& exchange) noexcept {
        auto& metrics = event_loop.metrics;
        if (metrics.stage == metrics_stage_t::closed_k || !exchange.endpoint || !exchange.reply_status) return;
        float const rate = server.config.metrics_sample_rate;
        metrics.sample_credit += rate;
        if (metrics.sample_credit < 1.f) return;
        metrics.sample_credit -= 1.f;
        std::uint64_t const micros = (monotonic_ns() - exchange.arrived) / 1000;
        char value[32], type[24], endpoint_text[256], method_text[32], status_text[24];
        char* const point = std::to_chars(value, value + sizeof(value) - 4, micros / 1000).ptr;
        point[0] = '.';
        point[1] = static_cast<char>('0' + micros / 100 % 10);
        point[2] = static_cast<char>('0' + micros / 10 % 10);
        point[3] = static_cast<char>('0' + micros % 10);
        std::memcpy(type, "ms|@", 4);
        std::size_t const type_length =
            rate < 1.f ? static_cast<std::size_t>(std::to_chars(type + 4, type + sizeof(type), rate).ptr - type) : 2;
        char const* const verb = http_verb_name(exchange.message.verb);
        std::initializer_list<std::string_view> const tags {
            tag_text(endpoint_text, "endpoint:", exchange.endpoint->path),
            tag_text(method_text, "method:", verb ? std::string_view {verb} : std::string_view {}),
            tag_text(status_text, "status:", exchange.reply_status)};
        std::string_view const text {value, static_cast<std::size_t>(point + 4 - value)}, kind {type, type_length};
        if (append_metric(server, metrics.composing, "latency", text, kind, tags) == ucall_status_success_k) return;
        if (metrics.stage == metrics_stage_t::idle_k) {
            restart_pending(metrics);
            send_metrics(event_loop);
            if (append_metric(server, metrics.composing, "latency", text, kind, tags) == ucall_status_success_k) return;
        }
        ++metrics.dropped_lines;
    }

    /** Once due, writes the loop's counter deltas and gauges behind the latency lines waiting, and
     *  sends them; a datagram still sending leaves its window's deltas to the next one. */
    static void emit_metrics(server_t& server, event_loop_t& event_loop) noexcept {
        auto& metrics = event_loop.metrics;
        if (metrics.stage == metrics_stage_t::closed_k || monotonic_ns() < metrics.due) return;
        metrics.due = deadline_after(server.config.metrics_interval_microseconds);
        if (metrics.stage != metrics_stage_t::idle_k) return;
        restart_pending(metrics);
        auto& datagram = metrics.composing;
        char digits[24], loop_text[32], interface_text[32], status_text[32];
        std::string_view const loop = tag_text(loop_text, "loop:", event_loop.index);
        using counter_t = std::uint64_t ucall_event_loop_statistics_t::*;
        static constexpr std::pair<std::string_view, counter_t> counters_k[] {
            {"polls", &ucall_event_loop_statistics_t::polls},
            {"empty_polls", &ucall_event_loop_statistics_t::empty_polls},
            {"kernel_enters", &ucall_event_loop_statistics_t::kernel_enters},
            {"submissions", &ucall_event_loop_statistics_t::submissions},
            {"completions", &ucall_event_loop_statistics_t::completions},
            {"cancellations", &ucall_event_loop_statistics_t::cancellations},
            {"accepts", &ucall_event_loop_statistics_t::accepts},
            {"requests", &ucall_event_loop_statistics_t::requests},
            {"receive_rearms", &ucall_event_loop_statistics_t::receive_rearms},
            {"bytes_received", &ucall_event_loop_statistics_t::bytes_received},
            {"bytes_sent", &ucall_event_loop_statistics_t::bytes_sent},
            {"bytes_copied", &ucall_event_loop_statistics_t::bytes_copied},
            {"zero_copy_sends", &ucall_event_loop_statistics_t::zero_copy_sends},
            {"zero_copy_fallbacks", &ucall_event_loop_statistics_t::zero_copy_fallbacks},
            {"file_window_overlaps", &ucall_event_loop_statistics_t::file_window_overlaps}};
        ucall_event_loop_statistics_t const totals = loop_totals(event_loop);
        ucall_status_t fitted = ucall_status_success_k;
        for (auto [name, counter] : counters_k) {
            std::uint64_t const delta = totals.*counter - metrics.reported.*counter;
            if (!delta || fitted != ucall_status_success_k) continue;
            fitted = append_metric(server, datagram, name, format_decimal(digits, delta), "c", {loop});
            if (fitted == ucall_status_success_k) metrics.pending.*counter = totals.*counter;
        }
        for (std::size_t i = 0; i != event_loop.interface_statistics.size() && fitted == ucall_status_success_k; ++i) {
            auto const& live = event_loop.interface_statistics[i];
            auto const& reported = metrics.interfaces_reported[i];
            auto& pending = metrics.interfaces_pending[i];
            std::string_view const interface = tag_text(interface_text, "interface:", i);
            fitted = append_metric(server, datagram, "connections", format_decimal(digits, live.connections), "g",
                                   {loop, interface});
            for (std::size_t j = 0; j != std::size(refused_statuses_k) && fitted == ucall_status_success_k; ++j) {
                if (live.refused[j] == reported.refused[j]) continue;
                fitted = append_metric(server, datagram, "refused",
                                       format_decimal(digits, live.refused[j] - reported.refused[j]), "c",
                                       {loop, interface, tag_text(status_text, "status:", refused_statuses_k[j])});
                if (fitted == ucall_status_success_k) pending.refused[j] = live.refused[j];
            }
            using failure_t = std::uint64_t interface_statistics_t::*;
            for (auto [name, failure] : {std::pair<std::string_view, failure_t> {
                                             "handshake_failures", &interface_statistics_t::handshake_failures},
                                         std::pair<std::string_view, failure_t> {
                                             "authorizer_refusals", &interface_statistics_t::authorizer_refusals}}) {
                if (live.*failure == reported.*failure || fitted != ucall_status_success_k) continue;
                fitted = append_metric(server, datagram, name,
                                       format_decimal(digits, live.*failure - reported.*failure), "c",
                                       {loop, interface});
                if (fitted == ucall_status_success_k) pending.*failure = live.*failure;
            }
        }
        std::size_t batch_index = 0;
        for (auto* endpoint = server.endpoints; endpoint && !event_loop.index && fitted == ucall_status_success_k;
             endpoint = endpoint->next) {
            if (!endpoint->batch) continue;
            auto& batch = *endpoint->batch;
            auto& reported = metrics.batches_reported[batch_index];
            auto& pending = metrics.batches_pending[batch_index++];
            char endpoint_text[256];
            std::string_view const tag = tag_text(endpoint_text, "endpoint:", endpoint->path);
            std::uint64_t const queued = atomic_ref<std::uint64_t> {batch.tail}.load(std::memory_order_relaxed) -
                                         atomic_ref<std::uint64_t> {batch.head}.load(std::memory_order_relaxed);
            fitted = append_metric(server, datagram, "batch.queue", format_decimal(digits, queued), "g", {tag});
            using batch_counter_t = std::uint64_t ucall_batch_endpoint_statistics_t::*;
            static constexpr std::pair<std::string_view, batch_counter_t> batch_counters_k[] {
                {"batch.batches", &ucall_batch_endpoint_statistics_t::batches},
                {"batch.requests", &ucall_batch_endpoint_statistics_t::requests},
                {"batch.filled", &ucall_batch_endpoint_statistics_t::filled_batches},
                {"batch.ready", &ucall_batch_endpoint_statistics_t::ready_batches},
                {"batch.expired", &ucall_batch_endpoint_statistics_t::expired_batches}};
            for (auto [name, counter] : batch_counters_k) {
                std::uint64_t const total = atomic_ref<std::uint64_t> {batch.statistics.*counter}.load(
                    std::memory_order_relaxed);
                if (total == reported.*counter || fitted != ucall_status_success_k) continue;
                fitted = append_metric(server, datagram, name, format_decimal(digits, total - reported.*counter), "c",
                                       {tag});
                if (fitted == ucall_status_success_k) pending.*counter = total;
            }
        }
        if (metrics.dropped_lines &&
            append_metric(server, datagram, "metrics_dropped", format_decimal(digits, metrics.dropped_lines), "c",
                          {loop}) == ucall_status_success_k)
            metrics.dropped_lines = 0;
        send_metrics(event_loop);
    }

    /** Frees @p exchange for the next request once its reply ended, making a deferred outcome final
     *  with @p status after the loop let go of every file segment. While the kernel still holds its
     *  sent segments, it waits as `releasing_k` for the release to complete. */
    static void recycle_exchange(event_loop_t& event_loop, server_exchange_t& exchange,
                                 ucall_status_t status) noexcept {
        if (status == ucall_status_success_k) time_request(*event_loop.server, event_loop, exchange);
        tally(event_loop.statistics.bytes_copied, std::exchange(exchange.copied, 0));
        exchange.input.clear();
        release_all_segments(exchange);
        publish_reply_outcome(exchange, status);
        if (exchange.releasing()) {
            exchange.stage = exchange_stage_t::releasing_k;
            return;
        }
        free_exchange(event_loop, exchange);
    }

    /** Lists @p exchange, whose segments nothing holds any longer, among the free ones. */
    static void free_exchange(event_loop_t& event_loop, server_exchange_t& exchange) noexcept {
        exchange.head_segment.bytes.clear();
        exchange.end_segment.bytes.clear();
        exchange.connection = nullptr;
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

    /** Drains the replied queue and adopts each exchange's pushed segments; a reply stays on its
     *  connection until sent, and only orphans release theirs here, recycling once ended. */
    static ucall_status_t collect_replies(event_loop_t& event_loop) noexcept {
        auto* exchange = dequeue_replied(event_loop);
        if (!exchange) return ucall_status_would_block_k;
        for (; exchange; exchange = dequeue_replied(event_loop)) {
            // Unlisting before adopting makes a later push list the exchange again.
            atomic_ref<std::uint32_t> {exchange->state}.fetch_and(~std::uint32_t {listed_k}, std::memory_order_acq_rel);
            adopt_segments(*exchange);
            if (pull_ready(*exchange)) finish_pull(*exchange, ucall_status_success_k);
            if (auto* connection = exchange->connection) {
                if (atomic_ref<std::uint32_t> {exchange->state}.load(std::memory_order_acquire) & detached_k)
                    connection->fail(ucall_status_connection_closed_k);
                mark_ready(event_loop, *connection);
            }
            else {
                release_all_segments(*exchange);
                if (exchange->stage == exchange_stage_t::ended_k)
                    recycle_exchange(event_loop, *exchange, ucall_status_connection_closed_k);
            }
        }
        return ucall_status_success_k;
    }

    /** Answers on the event loop itself, failing the connection when no reply was queued. */
    static void refuse(connection_t& connection, server_exchange_t& exchange, unsigned status,
                       std::string_view body) noexcept {
        if (auto* counters = connection.interface_statistics)
            for (std::size_t i = 0; i != std::size(refused_statuses_k); ++i)
                if (refused_statuses_k[i] == status) tally(counters->refused[i]);
        ucall_reply_part_t part {};
        part.data.bytes = bytes_view(body);
        auto result = reply(exchange, nullptr, status, {}, {&part, 1});
        if (result == ucall_status_success_k || result == ucall_status_connection_closed_k) return;
        exchange.stage = exchange_stage_t::ended_k; // Never pushed, so the close recycles it.
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
        exchange->unsent_bytes = 0;
        exchange->unsent_file_segments = 0;
        exchange->reply_head = reply_head_t::queued_k;
        exchange->declared = exchange->streamed = 0;
        exchange->outcome = nullptr;
        exchange->pull_outcome = nullptr;
        exchange->pulled_view = nullptr;
        exchange->pushed_segments = exchange->pushed_tail = exchange->newest_segment = nullptr;
        exchange->pushed_file_segments = exchange->pushed_file_tail = exchange->newest_file_segment = nullptr;
        exchange->parts_state = parts_state_t::unlocated_k;
        exchange->pull_requested = 0;
        exchange->body_stage = body_stage_t::buffered_k;
        exchange->body_status = ucall_status_success_k;
        exchange->reply_status = 0;
        exchange->arrived = monotonic_ns();
        exchange->body_chunk.clear();
        exchange->pulled_chunk.clear();
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
            exchange->stage = exchange_stage_t::ended_k; // Never handed out, so the close recycles it.
            return connection.fail(appended);
        }
        tally(event_loop.statistics.requests);
        exchange->message = std::exchange(connection.message, http_message_t {});
        auto* endpoint = std::exchange(connection.routed, nullptr);
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
        auto index = tail.fetch_add(1, std::memory_order_seq_cst);
        atomic_ref<server_exchange_t*> {batch.slots[index & (batch.slots.size() - 1)]}.store(exchange,
                                                                                             std::memory_order_release);
        auto drain = atomic_ref<drain_state_t> {batch.drain};
        if (drain.load(std::memory_order_seq_cst) == drain_state_t::sleeping_k &&
            drain.exchange(drain_state_t::draining_k, std::memory_order_seq_cst) == drain_state_t::sleeping_k)
            batch.wake.notify();
    }

    /** The endpoint the request whose head parsed at the front of @p unparsed goes to, or null. */
    static endpoint_t* route(server_t& server, connection_t& connection, span<byte_t> unparsed) noexcept {
        auto path = extract_path_component<http_t>(connection.message.target(text_view(unparsed)));
        return static_cast<endpoint_t*>(server.routes.match(path, connection.message.verb));
    }

    /** Hands a streamed request to its callback once its head parsed at @p offset of `input`:
     *  the head moves to the exchange, and the body behind it stays in `input` to stream. */
    static void dispatch_streamed(event_loop_t& event_loop, connection_t& connection, std::size_t offset) noexcept {
        auto* exchange = enqueue_exchange(event_loop, connection);
        if (!exchange) return;
        auto const head = connection.message.headers_length;
        if (ucall_status_t const appended = append_text(exchange->input,
                                                        {text_view(connection.input).substr(offset, head)});
            appended != ucall_status_success_k) {
            exchange->stage = exchange_stage_t::ended_k; // Never handed out, so the close recycles it.
            return connection.fail(appended);
        }
        tally(event_loop.statistics.bytes_copied, head);
        tally(event_loop.statistics.requests);
        drop_bytes(connection.input, offset + head);
        exchange->message = connection.message;
        exchange->message.body_length = 0;
        // The connection keeps the framing and decodes the body from the front of what remains.
        connection.message.decoded_length = connection.message.chunk_remaining = 0;
        connection.message.chunk_state = http_chunk_state_t::size_k;
        auto* endpoint = std::exchange(connection.routed, nullptr);
        exchange->endpoint = endpoint;
        exchange->body_stage = body_stage_t::streaming_k;
        connection.streaming = exchange;
        endpoint->callback(exchange, endpoint->context);
    }

    /** Hands a waiting pull `body_chunk`, or the end of the body, and makes its outcome final. */
    static void finish_pull(server_exchange_t& exchange, ucall_status_t status) noexcept {
        // Acquiring the request orders the puller's outcome and view before these reads.
        auto requested = atomic_ref<std::uint32_t> {exchange.pull_requested};
        if (!requested.load(std::memory_order_acquire)) return;
        requested.store(0, std::memory_order_relaxed);
        auto* outcome = std::exchange(exchange.pull_outcome, nullptr);
        *exchange.pulled_view = {};
        if (status == ucall_status_success_k && exchange.body_chunk.empty()) status = exchange.body_status;
        if (status == ucall_status_success_k) {
            std::swap(exchange.pulled_chunk, exchange.body_chunk);
            exchange.body_chunk.clear();
            *exchange.pulled_view = bytes_view(text_view(exchange.pulled_chunk));
        }
        publish(outcome, status);
    }

    /** Whether a waiting pull of @p exchange can take bytes or the end now. */
    static bool pull_ready(server_exchange_t& exchange) noexcept {
        return atomic_ref<std::uint32_t> {exchange.pull_requested}.load(std::memory_order_acquire) &&
               (!exchange.body_chunk.empty() || exchange.body_stage == body_stage_t::ended_k);
    }

    /** Decodes what `input` holds of the streamed body in place and, once the last chunk was
     *  pulled, rotates `input` into `body_chunk` and finishes a waiting pull; complete once the
     *  body ended, leaving the bytes behind it in `input`. */
    static http_parse_t stream_body(connection_t& connection) noexcept {
        auto& exchange = *connection.streaming;
        // A reply that ended before its body drains the rest, so nothing behind it stalls.
        bool const draining = exchange.stage == exchange_stage_t::ended_k;
        if (draining) exchange.body_chunk.clear();
        if (!exchange.body_chunk.empty()) return http_parse_t::incomplete_k;
        std::size_t payload = 0, consumed = 0;
        auto parsed = http_stream_body(connection.input, connection.message, payload, consumed);
        if (parsed != http_parse_t::complete_k && parsed != http_parse_t::incomplete_k) {
            exchange.body_status = ucall_status_malformed_k;
            finish_pull(exchange, ucall_status_malformed_k);
            exchange.body_stage = body_stage_t::ended_k;
            connection.streaming = nullptr;
            connection.receiving = receive_state_t::ended_k;
            connection.fail(ucall_status_malformed_k);
            return parsed;
        }
        if (payload && !draining) {
            // Rotating buffers hands the payload over where it was decoded, never copying it.
            std::swap(exchange.body_chunk, connection.input);
            connection.input.clear();
            ucall_status_t const kept = append_text(connection.input,
                                                    {text_view(exchange.body_chunk).substr(consumed)});
            if (kept != ucall_status_success_k) connection.fail(kept);
            [[maybe_unused]] st::status_t const shrunk = exchange.body_chunk.resize(payload); // Never grows.
        }
        else drop_bytes(connection.input, consumed);
        if (parsed == http_parse_t::complete_k) {
            exchange.body_stage = body_stage_t::ended_k;
            connection.streaming = nullptr;
            bool const closes = !connection.message.keep_alive();
            connection.message = {};
            if (closes) connection.receiving = receive_state_t::ended_k;
        }
        else if (connection.flags & connection_peer_closed_k) {
            exchange.body_status = ucall_status_connection_closed_k;
            finish_pull(exchange, ucall_status_connection_closed_k);
            exchange.body_stage = body_stage_t::ended_k;
            connection.streaming = nullptr;
            connection.receiving = receive_state_t::ended_k;
        }
        if (pull_ready(exchange)) finish_pull(exchange, ucall_status_success_k);
        return parsed;
    }

    /** Queues the refusal of a request that cannot be parsed behind every earlier reply. */
    static void refuse_unparsable(event_loop_t& event_loop, connection_t& connection, http_parse_t parsed) noexcept {
        connection.input.clear();
        connection.message = {};
        connection.routed = nullptr;
        auto* exchange = enqueue_exchange(event_loop, connection);
        if (!exchange) return;
        exchange->message = {}; // A default message never keeps the connection alive.
        refuse(connection, *exchange,
               parsed == http_parse_t::unsupported_k ? 501
               : parsed == http_parse_t::overflow_k  ? 413
                                                     : 400,
               {});
    }

    /** Whether the segment leading @p exchange's queue is all sent: a memory segment once sends
     *  took its bytes, a file segment once its framing and every window of its range did. */
    static bool front_segment_sent(connection_t const& connection, server_exchange_t const& exchange) noexcept {
        std::size_t const size = exchange.oldest_segment->bytes.size();
        file_segment_t const* file_segment = front_file_segment(exchange);
        if (!file_segment) return connection.output_offset == size;
        return file_segment->stage == file_segment_stage_t::measured_k && !file_segment->remaining_bytes &&
               connection.oldest_window == absent_k && connection.output_offset == size;
    }

    /** Readies the release of @p exchange's segment sends on @p connection's socket. */
    static io_request_t& name_exchange_release(connection_t& connection, server_exchange_t& exchange) noexcept {
        exchange_release_t& release = exchange.releases[exchange.naming];
        if (release.state == release_state_t::idle_k) {
            release.request = {.operation = io_operation_t::zero_copy_release_k,
                               .descriptor = connection.descriptor,
                               .context = &exchange};
            release.state = release_state_t::named_k;
        }
        return release.request;
    }

    /** Retires the oldest replies' sent segments, then each exchange whose reply ended with nothing
     *  left to send, reading again on a full receive side, and answers the release such an exchange
     *  must submit first. A reply delimited by the close, or cut short of its length, ends the
     *  connection after it. */
    static io_request_t* retire_sent_segments(event_loop_t& event_loop, connection_t& connection) noexcept {
        while (auto* oldest = connection.oldest_exchange) {
            if (oldest->oldest_segment) {
                if (!front_segment_sent(connection, *oldest)) return nullptr;
                connection.output_offset = 0;
                retire_oldest_segment(*oldest);
                continue;
            }
            connection.transmitting = transmit_state_t::idle_k;
            if (oldest->stage != exchange_stage_t::ended_k || oldest == connection.streaming) return nullptr;
            for (exchange_release_t& release : oldest->releases)
                if (release.state == release_state_t::named_k) return &release.request;
            connection.oldest_exchange = std::exchange(oldest->connection_next, nullptr);
            if (!connection.oldest_exchange) connection.newest_exchange = nullptr;
            --connection.exchanges_in_flight;
            bool const closes = !oldest->message.keep_alive();
            // A stream ending short of its declared length reports so once its parts are sent.
            bool const cut = oldest->framing == reply_framing_t::length_k && oldest->streamed != oldest->declared;
            recycle_exchange(event_loop, *oldest, cut ? ucall_status_malformed_k : ucall_status_success_k);
            if (connection.receiving == receive_state_t::full_k) connection.receiving = receive_state_t::reading_k;
            if (closes) {
                connection.receiving = receive_state_t::ended_k;
                if (connection.oldest_exchange) connection.fail(ucall_status_connection_closed_k);
                return nullptr;
            }
        }
        return nullptr;
    }

    /** The outcome a file segment that cannot be sent reports: missing, past its range, or
     *  failing. */
    static ucall_status_t file_segment_status(file_segment_stage_t stage) noexcept {
        return stage == file_segment_stage_t::not_found_k      ? ucall_status_not_found_k
               : stage == file_segment_stage_t::out_of_range_k ? ucall_status_overflow_k
                                                               : ucall_status_io_k;
    }

    /** Checks a file segment's range against its file's @p size, then frames it as a chunk when
     *  its reply is chunked, as two records: the size line ahead of the range, and the line break
     *  behind it. A range of zero bytes sends nothing, framing included. */
    static void frame_file_segment(server_exchange_t const& exchange, file_segment_t& file_segment,
                                   std::uint64_t size) noexcept {
        if (file_segment.file_offset > size || file_segment.remaining_bytes > size - file_segment.file_offset) {
            file_segment.stage = file_segment_stage_t::out_of_range_k;
            file_segment.remaining_bytes = size;
            return;
        }
        if (!file_segment.remaining_bytes) file_segment.remaining_bytes = size - file_segment.file_offset;
        file_segment.stage = file_segment_stage_t::measured_k;
        if (exchange.framing != reply_framing_t::chunked_k || !file_segment.remaining_bytes) return;
        char digits[sizeof(std::uint64_t) * 2];
        auto written = std::to_chars(digits, digits + sizeof(digits), file_segment.remaining_bytes, 16);
        auto& bytes = file_segment.segment.bytes;
        ucall_status_t framed = frame_segment(
            bytes, exchange.geometry,
            {std::string_view {digits, static_cast<std::size_t>(written.ptr - digits)}, "\r\n"});
        std::size_t const prefix = bytes.size();
        if (framed == ucall_status_success_k && st::failed(bytes.resize(prefix + exchange.geometry.headroom)))
            framed = ucall_status_out_of_memory_k;
        if (framed == ucall_status_success_k) framed = append_text(bytes, {"\r\n"});
        if (framed == ucall_status_success_k && st::failed(bytes.resize(bytes.size() + exchange.geometry.tailroom)))
            framed = ucall_status_out_of_memory_k;
        if (framed != ucall_status_success_k) {
            bytes.clear();
            file_segment.stage = file_segment_stage_t::failed_k;
            return;
        }
        file_segment.chunk_prefix_bytes = static_cast<std::uint8_t>(prefix);
    }

    /** Measures a file segment's file on the loop, as a `statx` never waits on a peer: its size,
     *  and the alignment its unbuffered reads keep. */
    static void stat_file_segment(server_exchange_t const& exchange, file_segment_t& file_segment) noexcept {
        file_geometry_t const geometry = file_direct_alignment(file_segment.file_descriptor);
        std::size_t const alignment = std::max<std::size_t>(geometry.alignment, 512);
        if (geometry.error == -ENXIO) file_segment.stage = file_segment_stage_t::not_found_k;
        else if (geometry.error || alignment > file_max_alignment_k || !std::has_single_bit(alignment))
            file_segment.stage = file_segment_stage_t::failed_k;
        else {
            file_segment.alignment_log2 = static_cast<std::uint8_t>(std::countr_zero(alignment));
            frame_file_segment(exchange, file_segment, geometry.size);
        }
    }

    /** Lands an open's result on the first file segment still unopened, which owns the descriptor
     *  from now on, whatever the connection's stage. Every refusal a peer's path can provoke reads
     *  as missing, so permissions are never revealed. */
    static void complete_file_open(connection_t& connection, io_completion_t const& completion) noexcept {
        connection.file_reading = file_read_state_t::idle_k;
        file_segment_t* file_segment = connection.oldest_exchange->oldest_file_segment;
        while (file_segment->stage != file_segment_stage_t::unopened_k) file_segment = file_segment->next;
        file_segment->segment.bytes.clear();
        descriptor_t const result = completion.result;
        file_segment->file_descriptor = result >= 0 ? static_cast<int>(result) : -1;
        if (result >= 0) {
            file_segment->stage = file_segment_stage_t::opened_k;
            return;
        }
        switch (-result) {
        case ENOENT:
        case ENOTDIR:
        case ELOOP:
        case EXDEV:
        case EACCES:
        case EPERM:
        case ENXIO:
        case EISDIR:
        case EINVAL:
        case ENAMETOOLONG: file_segment->stage = file_segment_stage_t::not_found_k; break;
        default: file_segment->stage = file_segment_stage_t::failed_k; break;
        }
    }

    /** Asks the engine to open @p file_segment's path beneath its directory. */
    static io_request_t* submit_file_open(connection_t& connection, file_segment_t& file_segment) noexcept {
        connection.file_reading = file_read_state_t::opening_file_k;
        io_request_t* request = connection.emit(connection.file_read_request, io_operation_t::file_open_k,
                                                file_segment.segment.bytes);
        request->deadline = 0;
        request->file = {.directory_descriptor = file_segment.file_descriptor};
        return request;
    }

    /** Breaks off a reply whose head already left: the close resets the connection, so the peer
     *  never takes the truncated body for a whole one, and the reply's outcome reports @p cause. */
    static void fail_reply(connection_t& connection, server_exchange_t& exchange, ucall_status_t cause) noexcept {
        publish_reply_outcome(exchange, cause);
        connection.close_mode = close_mode_t::reset_close_k;
        connection.fail(cause);
    }

    /** Retires every body segment and file segment of a measured reply nothing of which was sent,
     *  keeping its head and end segments. */
    static void drop_reply_body(server_exchange_t& exchange) noexcept {
        reply_segment_t& head = *exchange.oldest_segment;
        exchange.oldest_segment = head.next;
        while (exchange.oldest_segment != &exchange.end_segment) retire_oldest_segment(exchange);
        head.next = &exchange.end_segment;
        exchange.oldest_segment = &head;
    }

    /** Replaces a measured reply, a file segment of which cannot be sent, with the refusal it
     *  earns: @c 404, @c 416 naming the file's size, or @c 500. Its outcome reports why. */
    static void replace_reply_with_refusal(connection_t& connection, server_exchange_t& exchange,
                                           file_segment_stage_t refusal, std::uint64_t size) noexcept {
        unsigned status = ucall_http_status_internal_error_k;
        std::string_view body = "Internal error", range {};
        char digits[std::numeric_limits<std::uint64_t>::digits10 + 1];
        if (refusal == file_segment_stage_t::not_found_k) {
            status = ucall_http_status_not_found_k;
            body = "Not found";
        }
        else if (refusal == file_segment_stage_t::out_of_range_k) {
            status = ucall_http_status_range_not_satisfiable_k;
            body = "Range not satisfiable";
            auto written = std::to_chars(digits, digits + sizeof(digits), size);
            range = {digits, static_cast<std::size_t>(written.ptr - digits)};
        }
        drop_reply_body(exchange);
        auto& head = exchange.head_segment.bytes;
        ucall_status_t result = write_reply_head(head, exchange.geometry, status);
        if (result == ucall_status_success_k && !range.empty())
            result = append_text(head, {"content-range: bytes */", range, "\r\n"});
        if (result == ucall_status_success_k) result = append_text(head, {"content-type: text/plain\r\n"});
        if (result == ucall_status_success_k)
            result = finish_reply_head(head, exchange, reply_framing_t::length_k, body.size());
        if (result == ucall_status_success_k && exchange.message.verb != ucall_verb_head_k)
            result = append_text(head, {body});
        if (result == ucall_status_success_k) result = spread_records(head, exchange.geometry);
        if (result == ucall_status_success_k && st::failed(head.resize(head.size() + exchange.geometry.tailroom)))
            result = ucall_status_out_of_memory_k;
        publish_reply_outcome(exchange, file_segment_status(refusal));
        if (result != ucall_status_success_k) connection.fail(result);
    }

    /** Completes a measured reply's head with the measured `content-length` once every file
     *  segment is measured, or replaces the whole reply on the first that cannot be sent; a
     *  @c HEAD request then drops the body. Either way the head is no longer deferred. */
    static void complete_deferred_head(connection_t& connection, server_exchange_t& exchange) noexcept {
        exchange.reply_head = reply_head_t::queued_k;
        std::uint64_t length = exchange.streamed;
        file_segment_t* refused = nullptr;
        for (file_segment_t* file_segment = exchange.oldest_file_segment; file_segment && !refused;
             file_segment = file_segment->next) {
            if (file_segment->stage != file_segment_stage_t::measured_k) refused = file_segment;
            else if (file_segment->remaining_bytes > std::numeric_limits<std::uint64_t>::max() - length) {
                file_segment->stage = file_segment_stage_t::failed_k;
                refused = file_segment;
            }
            else length += file_segment->remaining_bytes;
        }
        if (refused) return replace_reply_with_refusal(connection, exchange, refused->stage, refused->remaining_bytes);
        exchange.declared = exchange.streamed = length;
        auto& head = exchange.head_segment.bytes;
        ucall_status_t result = finish_reply_head(head, exchange, reply_framing_t::length_k, length);
        if (result == ucall_status_success_k) result = spread_records(head, exchange.geometry);
        if (result == ucall_status_success_k && st::failed(head.resize(head.size() + exchange.geometry.tailroom)))
            result = ucall_status_out_of_memory_k;
        if (result != ucall_status_success_k) {
            publish_reply_outcome(exchange, result);
            return connection.fail(result);
        }
        if (exchange.message.verb == ucall_verb_head_k) drop_reply_body(exchange);
    }

    /** Payload bytes each record slot of a window holds under Noise: whole alignments, leaving at
     *  least one alignment of gap in the slot for the tag and the next record's header. */
    static std::size_t window_record_payload(secure_tunnel_geometry_t const& geometry,
                                             file_segment_t const& file_segment) noexcept {
        std::size_t const alignment = std::size_t {1} << file_segment.alignment_log2;
        return geometry.max_payload / alignment * alignment;
    }

    /** Whether the oldest waiting stream may read again, now that a window is vacant. */
    static void wake_waiting_connection(event_loop_t& event_loop) noexcept {
        auto& pool = event_loop.file_windows;
        connection_t* connection = pool.oldest_waiting_connection;
        if (!connection) return;
        pool.oldest_waiting_connection = std::exchange(connection->next_waiting_connection, nullptr);
        if (!pool.oldest_waiting_connection) pool.newest_waiting_connection = nullptr;
        connection->file_reading = file_read_state_t::idle_k;
        mark_ready(event_loop, *connection);
    }

    /** Returns @p window to the free list and serves the oldest waiting stream. */
    static void vacate_window(event_loop_t& event_loop, std::uint32_t window) noexcept {
        auto& pool = event_loop.file_windows;
        file_window_t& record = pool.windows[window];
        record.stage = file_window_stage_t::vacant_k;
        record.connection = absent_k;
        record.next = std::exchange(pool.free_windows, window);
        wake_waiting_connection(event_loop);
    }

    /** Unlinks @p connection's newest window, the one a read targets. */
    static std::uint32_t unlink_newest_window(event_loop_t& event_loop, connection_t& connection) noexcept {
        auto& windows = event_loop.file_windows.windows;
        std::uint32_t const newest = connection.newest_window;
        if (connection.oldest_window == newest) connection.oldest_window = connection.newest_window = absent_k;
        else {
            std::uint32_t previous = connection.oldest_window;
            while (windows[previous].next != newest) previous = windows[previous].next;
            windows[previous].next = absent_k;
            connection.newest_window = previous;
        }
        return newest;
    }

    /** Unlinks @p connection's oldest window, the one sends drain first. */
    static std::uint32_t unlink_oldest_window(event_loop_t& event_loop, connection_t& connection) noexcept {
        std::uint32_t const oldest = connection.oldest_window;
        connection.oldest_window = std::exchange(event_loop.file_windows.windows[oldest].next, absent_k);
        if (connection.oldest_window == absent_k) connection.newest_window = absent_k;
        return oldest;
    }

    /** A vacant window for @p connection's stream: a free one, a slab the pool grows by while below
     *  its limit, else none, queuing the stream for the next release. */
    static std::uint32_t borrow_window(event_loop_t& event_loop, connection_t& connection) noexcept {
        auto& pool = event_loop.file_windows;
        std::uint32_t window = pool.free_windows;
        if (window != absent_k) pool.free_windows = pool.windows[window].next;
        else if (pool.buffers_count != pool.buffers_limit) {
            using page_t = typename file_window_pool_t::page_t;
            auto* slab = rebound_allocator<page_t> {event_loop.allocator}.allocate(file_window_pool_t::buffer_bytes /
                                                                                   page_bytes_k);
            if (!slab) return absent_k;
            window = pool.buffers_count++;
            [[maybe_unused]] st::status_t const listed = pool.slabs.push_back(st::assume_reserved,
                                                                              reinterpret_cast<byte_t*>(slab));
            [[maybe_unused]] st::status_t const added = pool.windows.push_back(st::assume_reserved, file_window_t {});
            io_request_t release {.operation = io_operation_t::zero_copy_release_k, .context = &pool};
            // Past the engine's table or its locked-memory cap, sends pin each window themselves.
            if (pool.pinning == range_pinning_t::pinned_k) {
                memory_registration_t const registration = event_loop.engine.register_memory(
                    {reinterpret_cast<byte_t*>(slab), file_window_pool_t::buffer_bytes});
                pool.pinning = registration.pinning;
                if (registration.pinning == range_pinning_t::pinned_k) release.registered_memory = registration.index;
            }
            [[maybe_unused]] st::status_t const named = pool.release_requests.push_back(st::assume_reserved,
                                                                                        io_request_t {release});
        }
        else {
            connection.file_reading = file_read_state_t::waiting_window_k;
            if (pool.newest_waiting_connection) pool.newest_waiting_connection->next_waiting_connection = &connection;
            else pool.oldest_waiting_connection = &connection;
            pool.newest_waiting_connection = &connection;
            return absent_k;
        }
        file_window_t& record = pool.windows[window];
        record = {};
        record.connection = connection.index;
        pool.release_requests[window].descriptor = connection.descriptor;
        if (connection.newest_window != absent_k) pool.windows[connection.newest_window].next = window;
        else connection.oldest_window = window;
        connection.newest_window = window;
        return window;
    }

    /** Reads the next slice of @p file_segment into @p window: aligned extents covering it, one
     *  contiguous span in plaintext, or one payload slot per record under Noise. */
    static io_request_t* submit_file_read(event_loop_t& event_loop, connection_t& connection,
                                          file_segment_t& file_segment, std::uint32_t window) noexcept {
        auto& pool = event_loop.file_windows;
        file_window_t& record = pool.windows[window];
        if (connection.oldest_window != window) tally(event_loop.statistics.file_window_overlaps);
        std::uint64_t const alignment = std::uint64_t {1} << file_segment.alignment_log2;
        bool const sealed = connection.tunnel.encrypts();
        std::size_t const payload = sealed ? window_record_payload(connection.tunnel.geometry(), file_segment)
                                           : file_record_stride_k;
        record.extent_offset = file_segment.file_offset / alignment * alignment;
        record.skipped = static_cast<std::uint16_t>(file_segment.file_offset - record.extent_offset);
        record.slice_bytes = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(file_segment.remaining_bytes, file_window_records_k * payload - record.skipped));
        record.sent_bytes = 0;
        record.stage = file_window_stage_t::reading_k;
        file_segment.file_offset += record.slice_bytes;
        file_segment.remaining_bytes -= record.slice_bytes;
        std::size_t const length = (record.skipped + record.slice_bytes + alignment - 1) / alignment * alignment;
        byte_t* const base = pool.slabs[window] + page_bytes_k;
        connection.file_reading = file_read_state_t::reading_file_k;
        io_request_t* request;
        if (!sealed)
            request = connection.emit(connection.file_read_request, io_operation_t::file_read_k, {base, length});
        else {
            std::size_t const slots = (length + payload - 1) / payload;
            for (std::size_t slot = 0; slot != slots; ++slot)
                connection.file_read_vectors[slot] = {base + slot * file_record_stride_k,
                                                      std::min(payload, length - slot * payload)};
            request = connection.emit(connection.file_read_request, io_operation_t::file_read_vectors_k,
                                      {reinterpret_cast<byte_t*>(connection.file_read_vectors), slots});
        }
        request->deadline = 0;
        request->registered_memory = pool.registered_memory(window);
        request->file = {.offset = record.extent_offset, .file_descriptor = file_segment.file_descriptor};
        return request;
    }

    /** Lands a read on the stream's newest window: filled once it covers the slice, else the file
     *  ended short of the size it was measured at, failing the reply. A connection already closing
     *  vacates the window. */
    static void complete_file_read(event_loop_t& event_loop, connection_t& connection,
                                   io_completion_t const& completion) noexcept {
        connection.file_reading = file_read_state_t::idle_k;
        file_window_t& record = event_loop.file_windows.windows[connection.newest_window];
        bool const covered = completion.result >= 0 &&
                             static_cast<std::uint64_t>(completion.result) >= record.skipped + record.slice_bytes;
        if (connection.stage == connection_stage_t::open_k && covered) {
            record.stage = file_window_stage_t::filled_k;
            return;
        }
        vacate_window(event_loop, unlink_newest_window(event_loop, connection));
        if (connection.stage == connection_stage_t::open_k)
            fail_reply(connection, *connection.oldest_exchange, ucall_status_io_k);
    }

    /** Windows @p connection's stream may hold at once: one reading, one sending, and as many more
     *  as its socket's send buffer, so zero-copy never holds more than a copying send would. */
    static std::uint32_t stream_windows_limit(connection_t const& connection) noexcept {
        std::size_t const buffer = file_window_pool_t::buffer_bytes;
        return static_cast<std::uint32_t>(
            std::max<std::size_t>(2, (connection.send_buffer_bytes + buffer - 1) / buffer));
    }

    /** The next file request of the oldest reply: open and measure every file segment of a deferred
     *  head, then complete it; open and measure the oldest file segment; or read its next slice
     *  into a borrowed window, while the socket side sends the earlier ones. Null once nothing can
     *  proceed. */
    static io_request_t* read_reply(event_loop_t& event_loop, connection_t& connection) noexcept {
        auto* exchange = connection.oldest_exchange;
        // Until the loop adopted a segment of the reply, its replier may still be writing the head.
        if (!exchange || exchange->stage == exchange_stage_t::dispatched_k ||
            connection.file_reading == file_read_state_t::waiting_window_k)
            return nullptr;
        if (exchange->reply_head == reply_head_t::deferred_k) {
            if (exchange->stage != exchange_stage_t::ended_k) return nullptr;
            for (file_segment_t* file_segment = exchange->oldest_file_segment; file_segment;
                 file_segment = file_segment->next) {
                if (file_segment->stage == file_segment_stage_t::unopened_k)
                    return submit_file_open(connection, *file_segment);
                if (file_segment->stage == file_segment_stage_t::opened_k) stat_file_segment(*exchange, *file_segment);
            }
            complete_deferred_head(connection, *exchange);
            if (connection.stage != connection_stage_t::open_k) return nullptr;
        }
        file_segment_t* file_segment = exchange->oldest_file_segment;
        if (!file_segment) return nullptr;
        if (file_segment->stage == file_segment_stage_t::unopened_k) return submit_file_open(connection, *file_segment);
        if (file_segment->stage == file_segment_stage_t::opened_k) stat_file_segment(*exchange, *file_segment);
        if (file_segment->stage != file_segment_stage_t::measured_k || !file_segment->remaining_bytes) return nullptr;
        std::uint32_t held = connection.releasing_windows;
        for (std::uint32_t window = connection.oldest_window; window != absent_k;
             window = event_loop.file_windows.windows[window].next)
            ++held;
        if (held >= stream_windows_limit(connection)) return nullptr;
        std::uint32_t const window = borrow_window(event_loop, connection);
        if (window == absent_k) {
            if (connection.file_reading != file_read_state_t::waiting_window_k)
                fail_reply(connection, *exchange, ucall_status_out_of_memory_k);
            return nullptr;
        }
        return submit_file_read(event_loop, connection, *file_segment, window);
    }

    /** Starts sending @p bytes of @p exchange's front segment, sealing its records first; every
     *  segment send names the exchange's release. A stream whose sends hold its socket's send
     *  buffer submits that release first, and sends on once it completes. */
    static io_request_t* send_segment(connection_t& connection, server_exchange_t& exchange,
                                      span<byte_t> bytes) noexcept {
        // A release holding half the buffer goes to the kernel, and sends name the other, waiting
        // only while that one is still released, so both together hold what a copying send would.
        exchange_release_t& named = exchange.releases[exchange.naming];
        exchange_release_t& other = exchange.releases[exchange.naming ^ 1];
        // A full release whose submission failed is offered again before anything else is sent.
        if (other.state == release_state_t::named_k) return &other.request;
        if (named.state == release_state_t::named_k && named.held_bytes >= connection.send_buffer_bytes / 2) {
            if (other.state == release_state_t::releasing_k) return nullptr;
            exchange.naming ^= 1;
            return &named.request;
        }
        if (ucall_status_t const sealed = connection.seal_records(bytes); sealed != ucall_status_success_k) {
            connection.fail(sealed);
            return nullptr;
        }
        return connection.emit_zero_copy(bytes, name_exchange_release(connection, exchange), io_unregistered_k);
    }

    /** The next send of the stream's oldest window: its release once its slice is all sent, else
     *  the rest of its slice in plaintext, or its next record under Noise, sealed in place between
     *  the slot's gaps. Null while it is still read into. */
    static io_request_t* transmit_window(event_loop_t& event_loop, connection_t& connection,
                                         file_segment_t const& file_segment) noexcept {
        auto& pool = event_loop.file_windows;
        std::uint32_t const window = connection.oldest_window;
        file_window_t& record = pool.windows[window];
        if (record.stage == file_window_stage_t::reading_k) return nullptr;
        if (record.sent_bytes == record.slice_bytes) return &pool.release_requests[window];
        byte_t* const base = pool.slabs[window] + page_bytes_k;
        span<byte_t> bytes {base + record.skipped + record.sent_bytes, record.slice_bytes - record.sent_bytes};
        if (connection.tunnel.encrypts()) {
            secure_tunnel_geometry_t const geometry = connection.tunnel.geometry();
            std::size_t const payload = window_record_payload(geometry, file_segment),
                              position = record.skipped + record.sent_bytes, slot = position / payload,
                              end = std::min<std::size_t>(record.skipped + record.slice_bytes, (slot + 1) * payload);
            byte_t* const start = base + slot * file_record_stride_k + (position - slot * payload);
            bytes = {start - geometry.headroom, end - position + secure_tunnel_overhead_k};
            if (connection.tunnel.seal(bytes, end - position).empty()) {
                connection.fail(ucall_status_handshake_failed_k);
                return nullptr;
            }
        }
        record.stage = file_window_stage_t::sending_k;
        return connection.emit_zero_copy(bytes, pool.release_requests[window], pool.registered_memory(window));
    }

    /** The next socket request of the oldest reply, taking these steps in turn: finish a partial
     *  send; retire what was sent; wait for a deferred head or a stream's release; send the front
     *  memory segment; or, for a file segment, send its chunk framing, its windows in file order,
     *  each followed by its release, and its closing framing. Null once nothing can proceed, or
     *  the connection failed. */
    static io_request_t* transmit_reply(event_loop_t& event_loop, connection_t& connection) noexcept {
        for (;;) {
            if (connection.sending) return connection.resume_send();
            if (io_request_t* release = retire_sent_segments(event_loop, connection)) return release;
            auto* exchange = connection.oldest_exchange;
            if (connection.stage != connection_stage_t::open_k || !exchange || !exchange->oldest_segment ||
                exchange->reply_head == reply_head_t::deferred_k ||
                exchange->releases[exchange->naming].state == release_state_t::releasing_k)
                return nullptr;
            connection.transmitting = transmit_state_t::sending_k;
            auto& bytes = exchange->oldest_segment->bytes;
            file_segment_t* file_segment = front_file_segment(*exchange);
            if (!file_segment) return send_segment(connection, *exchange, bytes);
            switch (file_segment->stage) {
            case file_segment_stage_t::measured_k: break;
            case file_segment_stage_t::not_found_k:
            case file_segment_stage_t::out_of_range_k:
            case file_segment_stage_t::failed_k:
                fail_reply(connection, *exchange, file_segment_status(file_segment->stage));
                return nullptr;
            default: return nullptr;
            }
            std::size_t const prefix = file_segment->chunk_prefix_bytes;
            if (connection.output_offset < prefix) return send_segment(connection, *exchange, {bytes.data(), prefix});
            if (connection.oldest_window != absent_k) return transmit_window(event_loop, connection, *file_segment);
            if (file_segment->remaining_bytes) return nullptr;
            if (connection.output_offset == bytes.size()) continue;
            return send_segment(connection, *exchange, {bytes.data() + prefix, bytes.size() - prefix});
        }
    }

    /** Credits a zero-copy send the socket took: a window's slice once a whole send of it is done,
     *  or a segment's bytes, which also count against its exchange's hold. */
    static void complete_zero_copy_send(event_loop_t& event_loop, connection_t& connection,
                                        io_completion_t const& completion) noexcept {
        if (completion.result <= 0) return;
        io_request_t const* release = completion.request->release_request;
        std::uint32_t const window = event_loop.file_windows.window_of(release);
        if (window == absent_k)
            static_cast<server_exchange_t*>(release->context)->release_of(release).held_bytes +=
                static_cast<std::size_t>(completion.result);
        if (connection.sending) return;
        if (window == absent_k) connection.output_offset += connection.sending_length;
        else
            event_loop.file_windows.windows[window].sent_bytes += static_cast<std::uint32_t>(
                connection.sending_length - (connection.tunnel.encrypts() ? secure_tunnel_overhead_k : 0));
    }

    /** Marks a release @p request in flight once the engine took it: a window leaves its stream for
     *  the pool, and an exchange's segments wait for the kernel. */
    static void release_submitted(event_loop_t& event_loop, connection_t& connection,
                                  io_request_t const& request) noexcept {
        auto& pool = event_loop.file_windows;
        std::uint32_t const window = pool.window_of(&request);
        if (window == absent_k) {
            static_cast<server_exchange_t*>(request.context)->release_of(&request).state = release_state_t::releasing_k;
            ++connection.releasing_exchanges;
            return;
        }
        [[maybe_unused]] std::uint32_t const oldest = unlink_oldest_window(event_loop, connection);
        pool.windows[window].stage = file_window_stage_t::releasing_k;
        ++pool.releasing_count;
        ++connection.releasing_windows;
    }

    /** Lands a completed release: a window returns to the pool, waking the oldest waiting stream,
     *  and an exchange hands its segments back, recycling once its connection let go of it. A
     *  close waiting for the last release goes on. */
    static void complete_release(event_loop_t& event_loop, io_completion_t const& completion) noexcept {
        auto& pool = event_loop.file_windows;
        std::uint32_t const window = pool.window_of(completion.request);
        connection_t* connection;
        if (window != absent_k) {
            connection = event_loop.connections[pool.windows[window].connection].get();
            --pool.releasing_count;
            --connection->releasing_windows;
            vacate_window(event_loop, window);
        }
        else {
            auto& exchange = *static_cast<server_exchange_t*>(completion.request->context);
            connection = exchange.connection;
            --connection->releasing_exchanges;
            return_released_segments(exchange, exchange.release_of(completion.request));
            if (exchange.stage == exchange_stage_t::releasing_k && !exchange.releasing())
                free_exchange(event_loop, exchange);
        }
        if (connection->stage == connection_stage_t::releasing_k && !connection->releases_pending())
            connection->stage = connection_stage_t::closing_k;
        mark_ready(event_loop, *connection);
    }

    /** The next release a closing connection owes the kernel, once no send or read is in flight:
     *  windows it sent from leave for the pool, the rest return vacant, and exchanges whose sends
     *  named a release submit it. Null once nothing is left to release. */
    static io_request_t* drain_releases(event_loop_t& event_loop, connection_t& connection) noexcept {
        if (connection.transmit_operation == operation_state_t::pending_k ||
            connection.file_read_operation == operation_state_t::pending_k)
            return nullptr;
        auto& pool = event_loop.file_windows;
        while (connection.oldest_window != absent_k) {
            std::uint32_t const window = connection.oldest_window;
            if (pool.windows[window].stage == file_window_stage_t::sending_k) return &pool.release_requests[window];
            vacate_window(event_loop, unlink_oldest_window(event_loop, connection));
        }
        for (auto* exchange = connection.oldest_exchange; exchange; exchange = exchange->connection_next)
            for (exchange_release_t& release : exchange->releases)
                if (release.state == release_state_t::named_k) return &release.request;
        return nullptr;
    }

    /** Steps an open server connection, answering its next engine request or null, by these rules
     *  in order:
     *  R1 replies sent: with the transmit side free, retire the oldest replies' sent segments, then
     *     each exchange whose reply ended, submitting its release first, and a full receive side
     *     reads again.
     *  R2 requests: while reading, dispatch each complete request; the depth makes the side full,
     *     and `connection: close`, a peer close, or an unparsable request, refused in its turn,
     *     ends it.
     *  R3 file side: a free file request advances the oldest reply's files, as `read_reply` steps
     *     them, measuring every file of a deferred head before completing it.
     *  R4 socket side: a free transmit side advances the oldest reply once adopted, as
     *     `transmit_reply` steps it.
     *  R5 receive: a receive while reading.
     *  R6 done: ended with every reply sent, the connection lingers half-closed until the peer
     *     closes, so request bytes it never read cannot turn the close into a reset. */
    static io_request_t* serve_open(server_t& server, event_loop_t& event_loop, connection_t& connection) noexcept {
        if (connection.transmit_operation == operation_state_t::idle_k && !connection.sending)
            if (io_request_t* release = retire_sent_segments(event_loop, connection)) return release;
        if (connection.stage != connection_stage_t::open_k) return connection.advance();
        connection.open_records();
        auto depth = connection.network_interface->config.max_pipelined_requests;
        auto const cap = connection.network_interface->config.max_request_bytes;
        // Requests dispatched this round, erased from `input` once after it rather than one by one.
        std::size_t consumed = 0;
        while (connection.stage == connection_stage_t::open_k && connection.receiving == receive_state_t::reading_k) {
            // A streamed body is a barrier: nothing behind it parses until it ended.
            if (connection.streaming) {
                if (stream_body(connection) == http_parse_t::complete_k) continue;
                // An engine prefetching into a shared ring parks what an unpulled body holds there.
                if constexpr (requires { event_loop.engine.receive_pause(connection.descriptor); })
                    if (connection.streaming && !connection.streaming->body_chunk.empty())
                        event_loop.engine.receive_pause(connection.descriptor);
                break;
            }
            if (connection.exchanges_in_flight == depth) {
                connection.receiving = receive_state_t::full_k;
                break;
            }
            span<byte_t> unparsed {connection.input.data() + consumed,
                                   connection.input.data() + connection.input.size()};
            bool const headless = !connection.message.headers_length;
            auto parsed = http_parse(unparsed, connection.message, http_role_t::request_k);
            auto const& message = connection.message;
            auto const head = message.headers_length;
            if (headless && head) connection.routed = route(server, connection, unparsed);
            bool const head_fits = head ? head <= cap : unparsed.size() <= cap;
            // A parsed head is valid, so what the body holds is the stream's to report.
            if (head && head_fits && connection.routed &&
                connection.routed->body_delivery == ucall_body_delivery_streamed_k) {
                dispatch_streamed(event_loop, connection, consumed);
                consumed = 0;
                continue;
            }
            bool const body_fits = message.framing != http_framing_t::length_k
                                       ? (parsed == http_parse_t::complete_k ? message.wire_length : unparsed.size()) <=
                                             cap
                                       : message.content_length <= cap - std::min(cap, head);
            if ((!head_fits || (head && !body_fits)) &&
                (parsed == http_parse_t::incomplete_k || parsed == http_parse_t::complete_k))
                parsed = http_parse_t::overflow_k;
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
        if (connection.file_read_operation == operation_state_t::idle_k) {
            if (auto* next = read_reply(event_loop, connection)) return next;
            if (connection.stage != connection_stage_t::open_k) return connection.advance();
        }
        if (connection.transmit_operation == operation_state_t::idle_k) {
            if (auto* next = transmit_reply(event_loop, connection)) return next;
            if (connection.stage != connection_stage_t::open_k) return connection.advance();
        }
        // A streamed body reads on only once its last chunk was pulled.
        if (connection.receiving == receive_state_t::reading_k &&
            connection.receive_operation == operation_state_t::idle_k &&
            (!connection.streaming || connection.streaming->body_chunk.empty()))
            return connection.emit(connection.receive_request, io_operation_t::receive_k, connection.received);
        if (connection.receiving == receive_state_t::ended_k && !connection.oldest_exchange &&
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

    /** Takes @p connection off its loop's queue of streams waiting for a window. */
    static void leave_window_queue(event_loop_t& event_loop, connection_t& connection) noexcept {
        auto& pool = event_loop.file_windows;
        connection.file_reading = file_read_state_t::idle_k;
        connection_t* previous = nullptr;
        for (connection_t* waiting = pool.oldest_waiting_connection; waiting != &connection;
             waiting = waiting->next_waiting_connection)
            previous = waiting;
        connection_t* next = std::exchange(connection.next_waiting_connection, nullptr);
        (previous ? previous->next_waiting_connection : pool.oldest_waiting_connection) = next;
        if (pool.newest_waiting_connection == &connection) pool.newest_waiting_connection = previous;
    }
    static void advance_connection(server_t& server, event_loop_t& event_loop, connection_t& connection,
                                   server_mode_t mode) noexcept {
        auto& engine = event_loop.engine;
        if (connection.stage == connection_stage_t::idle_k) return;
        if (mode == server_mode_t::stopping_k && connection.stage != connection_stage_t::closing_k &&
            connection.stage != connection_stage_t::releasing_k && connection.stage != connection_stage_t::closed_k)
            connection.fail(ucall_status_connection_closed_k);
        if (connection.stage == connection_stage_t::closing_k &&
            connection.file_reading == file_read_state_t::waiting_window_k)
            leave_window_queue(event_loop, connection);
        for (;;) {
            io_request_t* next = connection.stage == connection_stage_t::closing_k
                                     ? drain_releases(event_loop, connection)
                                     : nullptr;
            if (!next) next = connection.advance();
            if (!next && connection.stage == connection_stage_t::open_k)
                next = serve_open(server, event_loop, connection);
            if (!next) break;
            if (next->operation == io_operation_t::close_k && connection.close_mode == close_mode_t::reset_close_k) {
                [[maybe_unused]] ucall_status_t const reset = engine.reset_on_close(connection.descriptor);
                connection.close_mode = close_mode_t::orderly_close_k;
            }
            // A failed submission is retried on the loop's next round rather than this one.
            if (engine.submit(*next) != ucall_status_success_k) {
                mark_ready(event_loop, connection);
                return;
            }
            if (next->operation == io_operation_t::zero_copy_release_k)
                release_submitted(event_loop, connection, *next);
            else connection.submitted(*next);
        }
        if (connection.stage == connection_stage_t::releasing_k &&
            (!event_loop.release_deadline || connection.deadline < event_loop.release_deadline))
            event_loop.release_deadline = connection.deadline;
        // The close waits until the other operations complete or are cancelled.
        if (connection.stage == connection_stage_t::closing_k) {
            if (connection.receive_operation == operation_state_t::pending_k &&
                connection.receive_request.operation != io_operation_t::close_k)
                engine.cancel(connection.receive_request);
            if (connection.transmit_operation == operation_state_t::pending_k)
                engine.cancel(connection.transmit_request);
            if (connection.file_read_operation == operation_state_t::pending_k)
                engine.cancel(connection.file_read_request);
        }
        // A reset close purges what the kernel held, whose releases still arrive after it.
        if (connection.stage == connection_stage_t::closed_k && !connection.releases_pending()) {
            detach(event_loop, connection);
            release_admission(server, *connection.network_interface);
            if (auto* counters = connection.interface_statistics)
                atomic_ref<std::uint64_t> {counters->connections}.store(counters->connections - 1,
                                                                        std::memory_order_relaxed);
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

    /** Resets every close whose linger deadline passed while the kernel still held what it sent,
     *  and notes the next such deadline. */
    static void expire_releases(event_loop_t& event_loop) noexcept {
        std::uint64_t const now = monotonic_ns();
        if (!event_loop.release_deadline || now < event_loop.release_deadline) return;
        event_loop.release_deadline = 0;
        for (auto& connection : event_loop.connections) {
            if (connection->stage != connection_stage_t::releasing_k) continue;
            if (connection->deadline <= now) {
                connection->close_mode = close_mode_t::reset_close_k;
                connection->stage = connection_stage_t::closing_k;
                mark_ready(event_loop, *connection);
            }
            else if (!event_loop.release_deadline || connection->deadline < event_loop.release_deadline)
                event_loop.release_deadline = connection->deadline;
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
            else active.sub(1, std::memory_order_relaxed);
        }
        collect_replies(event_loop);
        expire_releases(event_loop);
        if (mode == server_mode_t::serving_k) emit_metrics(server, event_loop);
        else if (event_loop.metrics.stage == metrics_stage_t::sending_k) engine.cancel(event_loop.metrics.send_request);
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
            busy |= event_loop.metrics.stage == metrics_stage_t::sending_k;
            if (!busy) {
                if (event_loop.metrics.stage != metrics_stage_t::closed_k) {
                    engine.close_socket(event_loop.metrics.send_request.descriptor);
                    event_loop.metrics.stage = metrics_stage_t::closed_k;
                }
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
        chosen->send_buffer_bytes = network_interface.send_buffer_bytes;
        chosen->stage = connection_stage_t::handshake_k;
        chosen->status = ucall_status_success_k;
        chosen->authorizer = network_interface.config.peer_authorizer;
        chosen->interface_statistics =
            &event_loop
                 .interface_statistics[static_cast<std::size_t>(&network_interface - server.network_interfaces.data())];
        tally(chosen->interface_statistics->connections);
        chosen->authorizer_context = network_interface.config.peer_authorizer_context;
        auto result = chosen->configure(
            tunnel_config(network_interface.config.security_mode, secure_tunnel_role_t::responder_k,
                          network_interface.config.noise_private_key, network_interface.public_key,
                          network_interface.config.noise_peer_key));
        if (result != ucall_status_success_k) chosen->fail(result);
        mark_ready(event_loop, *chosen);
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
            if (!directory.data || !directory.length || find(text_view(directory), '\0') != std::string_view::npos)
                return ucall_status_invalid_argument_k;
            if (ucall_status_t const copied = append_text(names, {text_view(directory), std::string_view {"\0", 1}});
                copied != ucall_status_success_k)
                return copied;
        }
        if (st::failed(network_interface.reply_directory_descriptors.reserve(settings.reply_directories_count)) ||
            st::failed(network_interface.reply_directory_views.resize(settings.reply_directories_count)))
            return ucall_status_out_of_memory_k;
        char const* name = names.data();
        for (std::size_t i = 0; i != settings.reply_directories_count; ++i) {
            int const directory = directory_open(name);
            if (directory < 0)
                return directory == -ENOENT || directory == -ENOTDIR ? ucall_status_not_found_k : ucall_status_io_k;
            [[maybe_unused]] st::status_t const kept = network_interface.reply_directory_descriptors.push_back(
                st::assume_reserved, int {directory});
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
            if (find(text, separator) != std::string_view::npos) return false;
        return !text.empty();
    }

    /** Copies the metric prefix and tags into @p server, resolves the StatsD address, and measures
     *  the datagram its path carries, on a socket of its own. */
    static ucall_status_t resolve_metrics(server_t& server, ucall_server_config_t const& config) noexcept {
        float const rate = config.metrics_sample_rate;
        if (!(rate >= 0.f && rate <= 1.f) || !valid_view(config.metrics_address) ||
            !valid_view(config.metrics_prefix) || (config.metrics_tags_count && !config.metrics_tags))
            return ucall_status_invalid_argument_k;
        std::string_view const prefix = config.metrics_prefix.length ? text_view(config.metrics_prefix) : "ucall";
        if (!metrics_text_valid(prefix, ":|#,@\r\n")) return ucall_status_invalid_argument_k;
        auto& text = server.metrics_text;
        if (ucall_status_t const copied = append_text(text, {prefix}); copied != ucall_status_success_k) return copied;
        for (std::size_t i = 0; i != config.metrics_tags_count; ++i) {
            ucall_bytes_view_t const tag = config.metrics_tags[i];
            if (!valid_view(tag) || !metrics_text_valid(text_view(tag), "|#,@\r\n"))
                return ucall_status_invalid_argument_k;
            if (ucall_status_t const copied = append_text(text, {text_view(tag)}); copied != ucall_status_success_k)
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
        if (auto status = split_address(text_view(config.metrics_address), host, service);
            status != ucall_status_success_k)
            return status;
        addrinfo hints {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        addrinfo* addresses = nullptr;
        if (getaddrinfo(host.data(), service.data(), &hints, &addresses) != 0 || !addresses)
            return ucall_status_connection_failed_k;
        std::memcpy(&server.metrics_peer, addresses->ai_addr, addresses->ai_addrlen);
        server.metrics_peer_length = static_cast<socket_length_t>(addresses->ai_addrlen);
        freeaddrinfo(addresses);
        descriptor_t const probe = datagram_open(reinterpret_cast<sockaddr const*>(&server.metrics_peer),
                                                 server.metrics_peer_length);
        if (probe < 0) return ucall_status_connection_failed_k;
        bool const inet6 = server.metrics_peer.ss_family == AF_INET6;
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
        auto* config = arguments->config;
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
            if (!valid_view(settings.address) || !valid_view(settings.device_name) ||
                find(device, '\0') != std::string_view::npos) {
                publish(arguments->outcome, ucall_status_invalid_argument_k);
                return;
            }
            if (!device.empty()) {
                if (ucall_status_t const copied = copy_text(network_interface.device, device);
                    copied != ucall_status_success_k) {
                    publish(arguments->outcome, copied);
                    return;
                }
                settings.device_name = bytes_view({network_interface.device.data(), device.size()});
            }
            if (!settings.address.length || !security_valid(settings.security_mode) ||
                (settings.security_mode != ucall_security_mode_none_k && !settings.noise_private_key) ||
                (settings.security_mode == ucall_security_mode_noise_xx_k && !settings.peer_authorizer) ||
                (settings.security_mode == ucall_security_mode_noise_kk_k && !settings.noise_peer_key)) {
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
            if (!settings.event_loops) settings.event_loops = interface_event_loops(device);
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
                char const* message = ucall_status_name(status);
                // An engine refused by a host setting names the setting to raise.
                if constexpr (requires { probe.refusal; })
                    if (probe.refusal) message = probe.refusal;
                publish(arguments->outcome, status, message);
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
            event_loop.index = static_cast<std::uint32_t>(event_loop_index);
            if (st::failed(event_loop.interface_statistics.resize(config->interfaces_count))) {
                publish(arguments->outcome, ucall_status_out_of_memory_k);
                return;
            }
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
            for (std::size_t i = 0; i != acceptors_count; ++i) std::construct_at(acceptors + i);
            event_loop.interface_acceptors = {acceptors, acceptors_count};
            for (auto& connection : event_loop.connections) {
                connection = allocate_unique<connection_t>(allocator, allocator);
                if (!connection) {
                    publish(arguments->outcome, ucall_status_out_of_memory_k);
                    return;
                }
                connection->index = static_cast<std::uint32_t>(&connection - event_loop.connections.data());
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
        server->wakeups = server->owned_wakeups;
        server->config = *config;
        for (std::size_t i = 0; i != config->interfaces_count; ++i)
            server->resolved[i] = server->network_interfaces[i].config;
        server->config.interfaces = server->resolved.data();
        server->config.metrics_prefix = server->metrics_prefix;
        server->config.metrics_tags = server->metrics_tag_views.data();
        if (!server->config.metrics_sample_rate) server->config.metrics_sample_rate = 1.f;
        if (!server->config.metrics_interval_microseconds) server->config.metrics_interval_microseconds = 1'000'000;
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

    /** Opens the loop's StatsD socket through its engine, with every buffer a datagram needs. */
    static ucall_status_t open_metrics(server_t& server, event_loop_t& event_loop) noexcept {
        if (!server.metrics_peer_length) return ucall_status_success_k;
        auto& metrics = event_loop.metrics;
        std::size_t const interfaces = event_loop.interface_statistics.size();
        std::size_t const batches = event_loop.index ? 0 : server.batch_endpoints.size();
        if (st::failed(metrics.composing.reserve(server.metrics_datagram_bytes)) ||
            st::failed(metrics.sending.reserve(server.metrics_datagram_bytes)) ||
            st::failed(metrics.interfaces_reported.resize(interfaces)) ||
            st::failed(metrics.interfaces_pending.resize(interfaces)) ||
            st::failed(metrics.batches_reported.resize(batches)) || st::failed(metrics.batches_pending.resize(batches)))
            return ucall_status_out_of_memory_k;
        descriptor_t const opened = datagram_open(reinterpret_cast<sockaddr const*>(&server.metrics_peer),
                                                  server.metrics_peer_length);
        descriptor_t const descriptor = opened < 0 ? opened : event_loop.engine.import_socket(opened);
        if (descriptor < 0) return ucall_status_connection_failed_k;
        metrics.send_request = {.operation = io_operation_t::send_k, .descriptor = descriptor, .context = &metrics};
        metrics.stage = metrics_stage_t::idle_k;
        metrics.due = deadline_after(server.config.metrics_interval_microseconds);
        return ucall_status_success_k;
    }
    static ucall_status_t open_event_loop(event_loop_t& event_loop) noexcept {
        if (event_loop.stage != event_loop_stage_t::unopened_k) return event_loop.setup_status;
        // Each connection keeps one operation per direction and one for files, each window one
        // release, each pipelined exchange two, and the wakeup and the metrics socket one each.
        auto connections = event_loop.connections.size(), acceptors = event_loop.interface_acceptors.size();
        std::size_t const counted_limit = std::numeric_limits<std::uint32_t>::max() / 8;
        if (connections > counted_limit || acceptors > counted_limit || event_loop.max_exchanges > counted_limit)
            return ucall_status_overflow_k;
        auto& pool = event_loop.file_windows;
        pool.buffers_limit = static_cast<std::uint32_t>(2 * connections);
        auto slots = 3 * connections + acceptors + 2 + pool.buffers_limit + 2 * event_loop.max_exchanges;
        if (st::failed(pool.slabs.reserve(pool.buffers_limit)) ||
            st::failed(pool.windows.reserve(pool.buffers_limit)) ||
            st::failed(pool.release_requests.reserve(pool.buffers_limit)))
            return ucall_status_out_of_memory_k;
        auto status = event_loop.engine.open(slots, slots);
        if (status != ucall_status_success_k) return status;
        event_loop.stage = event_loop_stage_t::ready_k;
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
        // Stored once, so polling never dirties the line registrations read.
        if (auto serving = atomic_ref<std::uint32_t> {server.serving}; !serving.load(std::memory_order_relaxed))
            serving.store(1, std::memory_order_release);
        atomic_ref<std::uint32_t> {event_loop.wake_pending}.store(0, std::memory_order_release);
        server_progress(server, event_loop);
        if (event_loop.stage == event_loop_stage_t::quiesced_k)
            return atomic_ref<ucall_status_t> {server.failure}.load(std::memory_order_acquire);
        // A close waiting for the kernel's releases resets at its deadline, and metrics go out at
        // theirs, with nothing to poll.
        for (std::uint64_t const due : {event_loop.release_deadline, event_loop.metrics.due})
            if (due && (!deadline || due < deadline)) deadline = due;
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
            else if (completion.request == &event_loop.metrics.send_request) {
                complete_metrics(event_loop, completion);
                event_loop.engine.release(completion);
            }
            else if (completion.request->operation == io_operation_t::accept_k)
                advance_completion(event_loop.engine, completion);
            else if (completion.request->operation == io_operation_t::zero_copy_release_k) {
                complete_release(event_loop, completion);
                event_loop.engine.release(completion);
            }
            else {
                auto& connection = *static_cast<connection_t*>(completion.request->context);
                advance_completion(event_loop.engine, completion);
                if (completion.request != &connection.file_read_request) {
                    if (completion.request->operation == io_operation_t::send_zero_copy_k)
                        complete_zero_copy_send(event_loop, connection, completion);
                }
                else if (completion.request->operation == io_operation_t::file_open_k)
                    complete_file_open(connection, completion);
                else complete_file_read(event_loop, connection, completion);
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

    /** Every counter of @p event_loop, as any thread may read them while the loop runs. */
    static ucall_event_loop_statistics_t loop_totals(event_loop_t& event_loop) noexcept {
        auto& loop = event_loop.statistics;
        auto& engine = event_loop.engine.statistics;
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
                                              .file_window_overlaps = read(loop.file_window_overlaps)};
        for (auto& counters : event_loop.interface_statistics) {
            for (auto& refused : counters.refused) totals.refused_requests += read(refused);
            totals.handshake_failures += read(counters.handshake_failures);
            totals.authorizer_refusals += read(counters.authorizer_refusals);
        }
        return totals;
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
        *arguments->statistics = loop_totals(*server.event_loops[arguments->event_loop_index]);
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
                atomic_ref<std::uint32_t> {exchange.state}.set_bits(claimed_k | ready_k | detached_k,
                                                                    std::memory_order_release);
                abandon_reply(exchange);
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
        auto arrived = static_cast<server_exchange_t*>(endpoint.pending.front())->arrived;
        auto maximum = std::numeric_limits<std::uint64_t>::max();
        auto due = endpoint.max_latency_microseconds > (maximum - arrived) / 1000
                       ? maximum
                       : arrived + endpoint.max_latency_microseconds * 1000;
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
            endpoint->body_delivery = arguments->body_delivery;
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
        if (streams(exchange)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        *arguments->body = bytes_view(exchange.message.body(exchange.text()));
        publish(arguments->outcome, ucall_status_success_k);
    }

    /** Whether @p exchange's body streams in through pulls, as its endpoint fixed at dispatch, so
     *  any thread holding the request may ask, unlike its loop-written `body_stage`. */
    static bool streams(server_exchange_t const& exchange) noexcept {
        return exchange.endpoint && exchange.endpoint->body_delivery == ucall_body_delivery_streamed_k;
    }

    /** The value of parameter @p name in a header value such as `form-data; name="x"`, unquoted but
     *  not unescaped, or an empty dataless view. */
    static std::string_view header_parameter(std::string_view value, std::string_view name) noexcept {
        for (std::size_t cursor = find(value, ';'); cursor != std::string_view::npos;) {
            auto rest = value.substr(cursor + 1);
            auto const equals = find(rest, '=');
            if (equals == std::string_view::npos) return {};
            auto const key = trim_http(rest.substr(0, equals));
            rest = trim_http(rest.substr(equals + 1));
            std::string_view found;
            std::size_t next = 0;
            if (!rest.empty() && rest.front() == '"') {
                std::size_t end = 1;
                while (end < rest.size() && rest[end] != '"') end += rest[end] == '\\' ? 2 : 1;
                if (end >= rest.size()) return {};
                found = rest.substr(1, end - 1);
                next = find(rest, ';', end);
            }
            else {
                next = find(rest, ';');
                found = trim_http(rest.substr(0, next));
            }
            if (http_t::equal_ascii_uncased(key, name)) return found;
            if (next == std::string_view::npos) return {};
            cursor = static_cast<std::size_t>(rest.data() - value.data()) + next;
        }
        return {};
    }

    /** The first field named @p name in a multipart part's header @p block, trimmed, or empty. */
    static std::string_view part_header(std::string_view block, std::string_view name) noexcept {
        for (std::size_t start = 0; start < block.size();) {
            auto end = std::min(find(block, "\r\n", start), block.size());
            auto const colon = find(block, ':', start);
            if (colon < end && http_t::equal_ascii_uncased(block.substr(start, colon - start), name))
                return trim_http(block.substr(colon + 1, end - colon - 1));
            start = end + 2;
        }
        return {};
    }

    /** Splits a buffered `multipart/form-data` body on its boundary into `parts`, once: a delimiter
     *  is `--` and the boundary at the body's start or after a CRLF, and the one followed by `--`
     *  closes; a body without it is malformed. */
    static void locate_parts(server_exchange_t& exchange) noexcept {
        if (exchange.parts_state != parts_state_t::unlocated_k) return;
        exchange.parts_state = parts_state_t::malformed_k;
        exchange.parts.clear();
        if (streams(exchange)) return;
        auto const text = exchange.text();
        auto const type = exchange.message.header(text, "content-type");
        auto const media = trim_http(type.substr(0, find(type, ';')));
        auto const boundary = header_parameter(type, "boundary");
        if (!http_t::equal_ascii_uncased(media, "multipart/form-data") || boundary.empty() || boundary.size() > 70)
            return;
        auto const body = exchange.message.body(text);
        auto const body_offset = static_cast<std::uint64_t>(body.data() - text.data());
        std::size_t start = std::string_view::npos;
        for (std::size_t cursor = 0;;) {
            auto const match = find(body, boundary, cursor);
            if (match == std::string_view::npos) return;
            cursor = match + boundary.size();
            bool const leads = match == 2 && body.substr(0, 2) == "--";
            bool const follows = match >= 4 && body.substr(match - 4, 4) == "\r\n--";
            if (!leads && !follows) continue;
            std::size_t const delimiter = leads ? 0 : match - 4;
            if (start != std::string_view::npos &&
                st::failed(exchange.parts.push_back(
                    request_part_t {body_offset + start, static_cast<std::uint64_t>(delimiter - start)})))
                return;
            if (body.substr(cursor, 2) == "--") {
                exchange.parts_state = parts_state_t::located_k;
                return;
            }
            auto const line_end = find(body, "\r\n", cursor);
            if (line_end == std::string_view::npos) return;
            start = cursor = line_end + 2;
        }
    }
    static std::size_t server_request_parts_count(ucall_server_t, ucall_received_http_request_t request) noexcept {
        if (!request) return 0;
        auto& exchange = *static_cast<server_exchange_t*>(request);
        locate_parts(exchange);
        return exchange.parts_state == parts_state_t::located_k ? exchange.parts.size() : 0;
    }
    static void server_request_part(ucall_server_request_part_t* arguments) noexcept {
        if (!arguments) return;
        for (ucall_bytes_view_t* output : {arguments->name, arguments->content_type, arguments->data})
            if (output) *output = {};
        if (!arguments->server || !arguments->request || !arguments->name || !arguments->content_type ||
            !arguments->data) {
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
        std::size_t const blank = part.substr(0, 2) == "\r\n" ? 0 : find(part, "\r\n\r\n");
        if (blank == std::string_view::npos) {
            publish(arguments->outcome, ucall_status_malformed_k);
            return;
        }
        auto const block = part.substr(0, blank);
        *arguments->name = bytes_view(header_parameter(part_header(block, "content-disposition"), "name"));
        *arguments->content_type = bytes_view(part_header(block, "content-type"));
        *arguments->data = bytes_view(part.substr(blank ? blank + 4 : 2));
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void server_request_body_chunk(ucall_server_request_body_chunk_t* arguments) noexcept {
        if (!arguments) return;
        if (arguments->data) *arguments->data = {};
        if (!arguments->server || !arguments->request || !arguments->data) {
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
        if (polling_event_loop == exchange.event_loop) {
            atomic_ref<std::uint32_t> {exchange.pull_requested}.store(1, std::memory_order_relaxed);
            if (!exchange.body_chunk.empty() || exchange.body_stage == body_stage_t::ended_k)
                return finish_pull(exchange, ucall_status_success_k);
            if (auto* connection = exchange.connection) mark_ready(*exchange.event_loop, *connection);
            return;
        }
        atomic_ref<std::uint32_t> {exchange.pull_requested}.store(1, std::memory_order_release);
        list_replied(exchange); // The loop reads on and finishes the pull as bytes arrive.
    }
    static void server_reply_content(ucall_server_reply_content_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server || !arguments->request || !valid_view(arguments->body) ||
            (arguments->headers_count && !arguments->headers)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        ucall_reply_part_t part {};
        part.data.bytes = arguments->body;
        publish(arguments->outcome, reply(*static_cast<server_exchange_t*>(arguments->request), nullptr,
                                          arguments->http_status ? arguments->http_status : 200,
                                          {arguments->headers, arguments->headers_count}, {&part, 1}));
    }
    static void server_reply_error(ucall_server_reply_error_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server || !arguments->request || !valid_view(arguments->message) ||
            arguments->http_status < 400) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        ucall_bytes_view_t const header = bytes_view("content-type: text/plain");
        ucall_reply_part_t part {};
        part.data.bytes = arguments->message;
        publish(arguments->outcome, reply(*static_cast<server_exchange_t*>(arguments->request), nullptr,
                                          arguments->http_status, {&header, 1}, {&part, 1}));
    }
    static void server_reply_vectored(ucall_server_reply_vectored_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server || !arguments->request || (arguments->headers_count && !arguments->headers) ||
            (arguments->parts_count && !arguments->parts)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        // A deferred outcome was published before the loop could see the reply, which owns it now.
        ucall_status_t const status = reply(*static_cast<server_exchange_t*>(arguments->request), arguments->outcome,
                                            arguments->http_status ? arguments->http_status : 200,
                                            {arguments->headers, arguments->headers_count},
                                            {arguments->parts, arguments->parts_count});
        if (status != ucall_status_deferred_k) publish(arguments->outcome, status);
    }
    static void server_reply_begin(ucall_server_reply_begin_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server || !arguments->request || (arguments->headers_count && !arguments->headers)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        publish(arguments->outcome, begin_reply(*static_cast<server_exchange_t*>(arguments->request),
                                                arguments->http_status ? arguments->http_status : 200,
                                                {arguments->headers, arguments->headers_count}));
    }
    static void server_reply_append(ucall_server_reply_append_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server || !arguments->request || (arguments->parts_count && !arguments->parts)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        publish(arguments->outcome, append_reply_parts(*static_cast<server_exchange_t*>(arguments->request),
                                                       {arguments->parts, arguments->parts_count}));
    }
    static void server_reply_end(ucall_server_reply_end_t* arguments) noexcept {
        if (!arguments) return;
        if (!arguments->server || !arguments->request) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        ucall_status_t const status = end_reply(*static_cast<server_exchange_t*>(arguments->request),
                                                arguments->outcome);
        if (status != ucall_status_deferred_k) publish(arguments->outcome, status);
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
        std::size_t answered_exchanges {}; // Since the dial, telling a reused connection from a fresh one.
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
        secure_tunnel_geometry_t const geometry {.headroom = framed ? secure_tunnel_headroom_k : 0,
                                                 .tailroom = framed ? secure_tunnel_tailroom_k : 0,
                                                 .max_payload = secure_tunnel_default_payload_k};
        if (st::failed(connection.output.resize(geometry.headroom))) return ucall_status_out_of_memory_k;
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
            result = append_text(connection.output,
                                 {"content-length: ", format_decimal(digits, arguments.body.length), "\r\n\r\n"});
        if (result == ucall_status_success_k) result = spread_records(connection.output, geometry);
        if (result == ucall_status_success_k)
            result = append_records(connection.output, geometry, {text_view(arguments.body)});
        if (result == ucall_status_success_k &&
            st::failed(connection.output.resize(connection.output.size() + geometry.tailroom)))
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
            peer.answered_exchanges = 0;
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
            connection.transmit_request = {.operation = io_operation_t::connect_k,
                                           .descriptor = descriptor,
                                           .data = reinterpret_cast<byte_t*>(exchange.address->ai_addr),
                                           .length = exchange.address->ai_addrlen,
                                           .deadline = connection.deadline,
                                           .context = &connection};
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
    static http_connection_t parse_connection_intent(span<ucall_bytes_view_t const> headers) noexcept {
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
    static bool accepts_another_exchange(client_t const& client, client_peer_t const& peer) noexcept {
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
        ++peer.answered_exchanges;
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
     *     can carry into `output` and appends it to the FIFO, if `accepts_another_exchange` allows.
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
            if (connection.transmitting == transmit_state_t::idle_k && accepts_another_exchange(client, peer))
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
        bool const unread = lost && peer.answered_exchanges && connection.input.empty() && connection.encrypted.empty();
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
                        accepts_another_exchange(client, *peer) && same_peer(client, *peer, exchange)) {
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
        exchange.connection_intent = parse_connection_intent({arguments->headers, arguments->headers_count});
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
                                                   &server_add_http_batch_endpoint,
                                                   &server_reply_vectored,
                                                   &server_reply_begin,
                                                   &server_reply_append,
                                                   &server_reply_end,
                                                   &server_request_body_chunk,
                                                   &server_request_parts_count,
                                                   &server_request_part};
    inline static client_api_t const client_api_k {&client_free, &client_call, &client_take_completed};
};

/** Portable network over the serial kits, for callers without a CPU dispatch point. */
template <typename engine_type_, typename allocator_type_ = st::default_allocator<byte_t>>
using serial_network = network_variant<engine_type_, fu::standard_atomic_ref, serial_compare_kit_t, serial_find_kit_t,
                                       serial_byteset_kit_t, serial_hash_kit_t, serial_fold_kit_t, serial_sha256_kit_t,
                                       serial_aes256_gcm_kit_t, allocator_type_>;

} // namespace unum::ucall
