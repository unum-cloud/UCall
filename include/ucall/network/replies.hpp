/**
 *  @file include/ucall/network/replies.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Queuing, framing, sending and releasing the segments of server replies.
 */
#pragma once

#include <bit>      // `std::bit_cast`, `std::countr_zero`, `std::has_single_bit`
#include <optional> // `std::optional`

#include "ucall/http/messages.hpp"     // `http_connection_t`, `http_role_t`
#include "ucall/io/types.hpp"          // `io_completion_t`, `io_operation_t`, `io_request_t`, `io_unregistered_k`
#include "ucall/network/exchanges.hpp" // `bit_of`, `claimed_k`, `replied_k`, `detached_k`
#include "ucall/network/types.hpp" // `transport_stage_t`, `operation_state_t`, `receive_state_t`, `transmit_state_t`
#include "ucall/tunnel/types.hpp"  // `secure_tunnel_geometry_t`, `secure_tunnel_overhead_k`
#include "ucall/utilities/sockets.hpp" // `close_native_file`, `direct_alignment_of`, `native_file_of`
#include "ucall/utilities/types.hpp"   // `text_view`, `byte_t`, `descriptor_t`, `publish`

namespace unum::ucall::network {

using http::http_connection_t;
using http::http_role_t;
using io::io_completion_t;
using io::io_operation_t;
using io::io_request_t;
using io::io_unregistered_k;
using io::memory_registration_t;
using io::range_pinning_t;
using io::tally;
using tunnel::secure_tunnel_geometry_t;
using tunnel::secure_tunnel_overhead_k;
using utilities::allocate_unique;
using utilities::byte_t;
using utilities::close_native_file;
using utilities::descriptor_t;
using utilities::direct_alignment_of;
using utilities::file_geometry_t;
using utilities::invalid_native_file_k;
using utilities::native_file_of;
using utilities::native_file_t;
using utilities::publish;
using utilities::span;
using utilities::text_view;

/** Queues, frames, sends and releases the segments of server replies. */
template <typename network_type_>
struct replies {
    using network_t = network_type_;
    using http_t = typename network_t::http_t;
    using reply_segment_t = typename network_t::reply_segment_t;
    using file_segment_t = typename network_t::file_segment_t;
    using connection_t = typename network_t::server_connection_t;
    using exchange_release_t = typename network_t::exchange_release_t;
    using replied_link_t = typename network_t::replied_link_t;
    using server_exchange_t = typename network_t::server_exchange_t;
    using file_window_pool_t = typename network_t::file_window_pool_t;
    using event_loop_t = typename network_t::event_loop_t;
    using formatting_t = typename network_t::formatting_t;
    using serving_t = typename network_t::serving_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using atomic_ref = typename network_t::template atomic_ref<value_type_>;

    /** The records one call queues, each list newest first as the pushed stacks hold them, so they
     *  are published together or handed back together. */
    struct reply_batch_t {
        reply_segment_t *newest_segment {}, *oldest_segment {};
        file_segment_t *newest_file_segment {}, *oldest_file_segment {};

        /** Framed bytes the socket will take, and body bytes copied. */
        std::size_t bytes {}, copied {};
        std::uint32_t file_segments {};
    };

    /** Whether @p file_segment holds a file the loop opened from its path, which only the loop
     *  closes. */
    static bool owns_file(file_segment_t const& file_segment) noexcept {
        return file_segment.file_origin == file_origin_t::opened_path_k &&
               file_segment.stage != file_segment_stage_t::unopened_k && file_segment.file != invalid_native_file_k;
    }

    /** A free file segment for @p exchange's replier: its own, then those the loop released, else
     *  one it allocates. */
    static file_segment_t* take_file_segment(server_exchange_t& exchange) noexcept {
        if (!exchange.free_file_segments)
            exchange.free_file_segments = exchange.shared.returned_file_segments.take_all();
        if (file_segment_t* file_segment = exchange.free_file_segments) {
            exchange.free_file_segments = file_segment->next;
            return file_segment;
        }
        return allocate_unique<file_segment_t>(exchange.event_loop->allocator, exchange.event_loop->allocator)
            .release();
    }

    /** Frames @p parts into fresh records held in @p batch: bytes parts copied as the
     *  exchange's framing asks, unless it is bodiless, and file and path parts as file
     *  segments. Adds the bytes to @c streamed, and the ranges too unless the loop measures
     *  them for a deferred head. */
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
                ucall_status_t const framed =
                    exchange.framing == reply_framing_t::chunked_k
                        ? formatting_t::frame_segment(segment->bytes, exchange.geometry, {size, "\r\n", data, "\r\n"})
                        : formatting_t::frame_segment(segment->bytes, exchange.geometry, {data});
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
                record->file = native_file_of(file.file_descriptor);
                record->stage = file_segment_stage_t::opened_k;
                record->file_origin = file_origin_t::caller_descriptor_k;
                // Windows reads through a handle its loop reopens beneath the caller's, owning it.
                if constexpr (UCALL_OS_WINDOWS_) {
                    record->stage = file_segment_stage_t::unopened_k;
                    record->file_origin = file_origin_t::opened_path_k;
                    if (ucall_status_t const named = http_t::append_text(record->segment.bytes,
                                                                         {std::string_view {"\0", 1}});
                        named != ucall_status_success_k)
                        return named;
                }
            }
            else {
                ucall_path_range_t const& path = part.data.path;
                record->file_offset = path.offset;
                record->remaining_bytes = path.length;
                record->file = exchange.network_interface->reply_directory_descriptors[path.directory_index];
                record->stage = file_segment_stage_t::unopened_k;
                record->file_origin = file_origin_t::opened_path_k;
                if (ucall_status_t const copied = http_t::append_text(
                        record->segment.bytes, {text_view(path.relative_path), std::string_view {"\0", 1}});
                    copied != ucall_status_success_k)
                    return copied;
            }
            if (exchange.reply_head == reply_head_t::pushed_k) exchange.streamed += record->remaining_bytes;
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
        atomic_ref<std::size_t> {exchange.shared.unsent_bytes}.add(batch.bytes, std::memory_order_relaxed);
        atomic_ref<std::uint32_t> {exchange.shared.unsent_file_segments}.add(batch.file_segments,
                                                                             std::memory_order_relaxed);
        if (batch.newest_file_segment)
            link_chain(exchange.shared.pushed_file_segments, exchange.pushed_file_tail, *batch.newest_file_segment,
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
     *  its framing in @c head_segment, the parts, and an empty @c end_segment. The outcome reads
     *  deferred before the loop can see the reply, which then makes it final. */
    static ucall_status_t queue_measured_reply(server_exchange_t& exchange, ucall_outcome_t* outcome, unsigned status,
                                               span<ucall_bytes_view_t const> headers,
                                               span<ucall_reply_part_t const> parts) noexcept {
        exchange.framing = exchange.message.verb == ucall_verb_head_k ? reply_framing_t::bodiless_k
                                                                      : reply_framing_t::length_k;
        exchange.reply_head = reply_head_t::held_k;
        exchange.streamed = exchange.declared = 0;
        reply_batch_t batch {};
        auto& head = exchange.head_segment.bytes;
        ucall_status_t result = build_reply_batch(exchange, parts, batch);
        if (result == ucall_status_success_k) result = formatting_t::write_reply_head(head, exchange.geometry, status);
        if (result == ucall_status_success_k)
            result = formatting_t::append_headers(head, headers, http_role_t::response_k);
        if (result != ucall_status_success_k) {
            head.clear();
            discard_reply_batch(exchange, batch);
            return result;
        }
        publish(outcome, ucall_status_deferred_k);
        exchange.outcome = outcome;
        exchange.end_segment.bytes.clear();
        atomic_ref<std::uint32_t> {exchange.shared.state}.set_bits(replied_k, std::memory_order_release);
        push_reply_batch(exchange, batch, &exchange.head_segment, &exchange.end_segment);
        return ucall_status_deferred_k;
    }

    /** Answers @p exchange with @p parts. Bytes alone are serialized whole and final on return;
     *  with any file or path part the reply is queued, and the outcome reads deferred until the
     *  loop sent every part. */
    static ucall_status_t reply(server_exchange_t& exchange, ucall_outcome_t* outcome, unsigned status,
                                span<ucall_bytes_view_t const> headers, span<ucall_reply_part_t const> parts) noexcept {
        std::size_t files = 0;
        if (ucall_status_t const checked = formatting_t::check_parts(exchange, parts, files);
            checked != ucall_status_success_k)
            return checked;
        if (files && (status == 204 || status == 304)) return ucall_status_invalid_argument_k;
        auto state = atomic_ref<std::uint32_t> {exchange.shared.state};
        if (state.fetch_test_and_set_bit(bit_of(claimed_k), std::memory_order_acq_rel))
            return ucall_status_already_exists_k;
        exchange.reply_status = static_cast<std::uint16_t>(status);
        if ((state.load(std::memory_order_acquire) & detached_k) ||
            formatting_t::server_stage(exchange) == server_stage_t::cutting_k) {
            state.set_bits(detached_k | replied_k, std::memory_order_release);
            abandon_reply(exchange);
            return ucall_status_connection_closed_k;
        }
        auto result = files ? queue_measured_reply(exchange, outcome, status, headers, parts)
                            : formatting_t::serialize_reply(exchange, status, headers, parts);
        if (result == ucall_status_deferred_k) return result;
        if (result != ucall_status_success_k) {
            state.clear_bits(claimed_k, std::memory_order_release);
            return result;
        }
        auto const previous = state.fetch_or(replied_k, std::memory_order_release);
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
        auto state = atomic_ref<std::uint32_t> {exchange.shared.state};
        if (state.fetch_test_and_set_bit(bit_of(claimed_k), std::memory_order_acq_rel))
            return ucall_status_already_exists_k;
        exchange.reply_status = static_cast<std::uint16_t>(status);
        exchange.declared = exchange.streamed = 0;
        exchange.framing = reply_framing_t::bodiless_k;
        exchange.reply_head = reply_head_t::pushed_k;
        if ((state.load(std::memory_order_acquire) & detached_k) ||
            formatting_t::server_stage(exchange) == server_stage_t::cutting_k) {
            state.set_bits(detached_k, std::memory_order_release);
            return ucall_status_connection_closed_k;
        }
        std::optional<std::uint64_t> declared;
        auto& output = exchange.head_segment.bytes;
        ucall_status_t result = formatting_t::write_reply_head(output, exchange.geometry, status);
        if (result == ucall_status_success_k)
            result = formatting_t::append_headers(output, headers, http_role_t::response_k, &declared);
        bool const head_request = exchange.message.verb == ucall_verb_head_k;
        reply_framing_t framing = declared                                     ? reply_framing_t::length_k
                                  : !formatting_t::requests_http_1_0(exchange) ? reply_framing_t::chunked_k
                                  : head_request                               ? reply_framing_t::bodiless_k
                                                                               : reply_framing_t::until_close_k;
        if (status == 204 || status == 304) {
            if (declared) result = ucall_status_invalid_argument_k;
            framing = reply_framing_t::bodiless_k;
        }
        if (framing == reply_framing_t::until_close_k) exchange.message.connection = http_connection_t::close_k;
        if (result == ucall_status_success_k)
            result = formatting_t::finish_reply_head(output, exchange, framing, declared.value_or(0));
        if (result == ucall_status_success_k) result = formatting_t::spread_records(output, exchange.geometry);
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
        if (!exchange.free_segments) exchange.free_segments = exchange.shared.returned_segments.take_all();
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
        std::uint32_t const state = atomic_ref<std::uint32_t> {exchange.shared.state}.load(std::memory_order_acquire);
        if (!(state & claimed_k) || (state & replied_k)) return ucall_status_invalid_argument_k;
        std::size_t files = 0;
        if (ucall_status_t const checked = formatting_t::check_parts(exchange, parts, files);
            checked != ucall_status_success_k)
            return checked;
        if ((state & detached_k) || formatting_t::server_stage(exchange) == server_stage_t::cutting_k)
            return ucall_status_connection_closed_k;
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
        if (atomic_ref<std::size_t> {exchange.shared.unsent_bytes}.load(std::memory_order_relaxed) >
                max_unsent_bytes_k ||
            atomic_ref<std::uint32_t> {exchange.shared.unsent_file_segments}.load(std::memory_order_relaxed) + files >
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
        auto state = atomic_ref<std::uint32_t> {exchange.shared.state};
        std::uint32_t const current = state.load(std::memory_order_acquire);
        if (!(current & claimed_k) || (current & replied_k)) return ucall_status_invalid_argument_k;
        auto& end_segment = exchange.end_segment;
        end_segment.bytes.clear();
        ucall_status_t result = ucall_status_success_k;
        if ((current & detached_k) || formatting_t::server_stage(exchange) == server_stage_t::cutting_k)
            result = ucall_status_connection_closed_k;
        else if (exchange.framing == reply_framing_t::length_k && exchange.streamed != exchange.declared)
            result = ucall_status_malformed_k;
        else if (exchange.framing == reply_framing_t::chunked_k)
            result = formatting_t::frame_segment(end_segment.bytes, exchange.geometry, {"0\r\n\r\n"});
        if (result != ucall_status_success_k && result != ucall_status_connection_closed_k) {
            end_segment.bytes.clear();
            exchange.message.connection = http_connection_t::close_k;
        }
        // The loop may still read a borrowed descriptor, so the loop reports how the reply ended.
        if (atomic_ref<std::uint32_t> {exchange.shared.unsent_file_segments}.load(std::memory_order_acquire)) {
            publish(outcome, ucall_status_deferred_k);
            exchange.outcome = outcome;
            result = ucall_status_deferred_k;
        }
        if ((state.fetch_or(replied_k, std::memory_order_release) & detached_k) && result != ucall_status_deferred_k)
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
        link_chain(exchange.shared.pushed_segments, exchange.pushed_tail, newest, oldest);
        list_replied(exchange);
    }

    /** Lists @p exchange for its event loop once, however many pushes and pulls raced to. */
    static void list_replied(server_exchange_t& exchange) noexcept {
        if (!atomic_ref<std::uint32_t> {exchange.shared.state}.fetch_test_and_set_bit(bit_of(listed_k),
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
        enqueue_replied(*event_loop, exchange.shared.replied_link);
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
     *  reply ended, then the file segments published ahead of those segments; false when the
     *  replier pushed nothing since the last adoption. */
    static bool adopt_segments(server_exchange_t& exchange) noexcept {
        if (!adopt_chain(exchange.shared.pushed_segments, exchange.oldest_segment, exchange.newest_segment))
            return false;
        exchange.stage = exchange.newest_segment == &exchange.end_segment ? exchange_stage_t::ended_k
                                                                          : exchange_stage_t::collected_k;
        // File segments are linked ahead of their own segments, so this meets each adopted above.
        adopt_chain(exchange.shared.pushed_file_segments, exchange.oldest_file_segment, exchange.newest_file_segment);
        return_parked(exchange);
        return true;
    }

    /** Hands a sent or abandoned chunk back to its replier, or keeps it while sends of the exchange
     *  named a release the kernel has not completed. */
    static void retire_segment(server_exchange_t& exchange, reply_segment_t& segment) noexcept {
        if (&segment == &exchange.head_segment || &segment == &exchange.end_segment) return;
        atomic_ref<std::size_t> {exchange.shared.unsent_bytes}.sub(segment.bytes.size(), std::memory_order_relaxed);
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
        else exchange.shared.returned_segments.push(segment);
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
        if (owns_file(file_segment)) close_native_file(file_segment.file);
        file_segment.file = invalid_native_file_k;
        // Releasing orders the last use of a borrowed descriptor before a replier sees none unsent.
        atomic_ref<std::uint32_t> {exchange.shared.unsent_file_segments}.sub(1, std::memory_order_release);
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
        exchange.shared.returned_file_segments.push(file_segment);
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
            exchange.shared.returned_segments.push_chain(*newest, *oldest);
        }
        if (file_segment_t* newest = std::exchange(release.sent_file_segments, nullptr)) {
            file_segment_t* oldest = newest;
            for (;; oldest = oldest->next) {
                oldest->segment.bytes.clear();
                if (!oldest->next) break;
            }
            exchange.shared.returned_file_segments.push_chain(*newest, *oldest);
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
            serving_t::finish_pull(*exchange, ucall_status_connection_closed_k);
            if (exchange->stage == exchange_stage_t::ended_k)
                serving_t::recycle_exchange(event_loop, *exchange, ucall_status_connection_closed_k);
            else {
                ++event_loop.orphaned_exchanges;
                atomic_ref<std::uint32_t> {exchange->shared.state}.set_bits(detached_k, std::memory_order_release);
                release_all_segments(*exchange);
            }
            exchange = next;
        }
        connection.oldest_exchange = connection.newest_exchange = nullptr;
        connection.streaming = nullptr;
        connection.routed = nullptr;
        connection.outstanding_exchanges = 0;
    }

    /** Whether the segment leading @p exchange's queue is all sent: a memory segment once sends
     *  took its bytes, a file segment once its framing and every window of its range did. */
    static bool front_segment_sent(connection_t const& connection, server_exchange_t const& exchange) noexcept {
        std::size_t const size = exchange.oldest_segment->bytes.size();
        file_segment_t const* file_segment = front_file_segment(exchange);
        if (!file_segment) return connection.transport.output_offset == size;
        return file_segment->stage == file_segment_stage_t::measured_k && !file_segment->remaining_bytes &&
               connection.oldest_window == absent_k && connection.transport.output_offset == size;
    }

    /** Readies the release of @p exchange's segment sends on @p connection's socket. */
    static io_request_t& name_exchange_release(connection_t& connection, server_exchange_t& exchange) noexcept {
        exchange_release_t& release = exchange.releases[exchange.naming];
        if (release.state == release_state_t::idle_k) {
            release.request = {.operation = io_operation_t::zero_copy_release_k,
                               .descriptor = connection.transport.descriptor,
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
                connection.transport.output_offset = 0;
                retire_oldest_segment(*oldest);
                continue;
            }
            connection.transport.transmitting = transmit_state_t::idle_k;
            if (oldest->stage != exchange_stage_t::ended_k || oldest == connection.streaming) return nullptr;
            for (exchange_release_t& release : oldest->releases)
                if (release.state == release_state_t::named_k) return &release.request;
            connection.oldest_exchange = std::exchange(oldest->connection_next, nullptr);
            if (!connection.oldest_exchange) connection.newest_exchange = nullptr;
            --connection.outstanding_exchanges;
            bool const closes = !oldest->message.keep_alive();
            // A stream ending short of its declared length reports so once its parts are sent.
            bool const cut = oldest->framing == reply_framing_t::length_k && oldest->streamed != oldest->declared;
            serving_t::recycle_exchange(event_loop, *oldest, cut ? ucall_status_malformed_k : ucall_status_success_k);
            if (connection.transport.receiving == receive_state_t::full_k)
                connection.transport.receiving = receive_state_t::reading_k;
            if (closes) {
                connection.transport.receiving = receive_state_t::ended_k;
                if (connection.oldest_exchange) connection.transport.fail(ucall_status_connection_closed_k);
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
        ucall_status_t framed = formatting_t::frame_segment(
            bytes, exchange.geometry,
            {std::string_view {digits, static_cast<std::size_t>(written.ptr - digits)}, "\r\n"});
        std::size_t const prefix = bytes.size();
        if (framed == ucall_status_success_k && st::failed(bytes.resize(prefix + exchange.geometry.headroom)))
            framed = ucall_status_out_of_memory_k;
        if (framed == ucall_status_success_k) framed = http_t::append_text(bytes, {"\r\n"});
        if (framed == ucall_status_success_k && st::failed(bytes.resize(bytes.size() + exchange.geometry.tailroom)))
            framed = ucall_status_out_of_memory_k;
        if (framed != ucall_status_success_k) {
            bytes.clear();
            file_segment.stage = file_segment_stage_t::failed_k;
            return;
        }
        file_segment.chunk_prefix_bytes = static_cast<std::uint8_t>(prefix);
    }

    /** Measures a file segment's file on the loop, as a @c statx never waits on a peer: its size,
     *  and the alignment its unbuffered reads keep in offset and length. */
    static void stat_file_segment(server_exchange_t const& exchange, file_segment_t& file_segment) noexcept {
        file_geometry_t const geometry = direct_alignment_of(file_segment.file);
        std::size_t const alignment = std::max<std::size_t>(geometry.offset_alignment, 512);
        // Reads land on whole pages of a window, so a file wanting more of memory fails here.
        if (geometry.error == -ENXIO) file_segment.stage = file_segment_stage_t::not_found_k;
        else if (geometry.error || geometry.memory_alignment > page_bytes_k || alignment > file_max_alignment_k ||
                 !std::has_single_bit(alignment))
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
        file_segment->file = result >= 0 ? std::bit_cast<native_file_t>(result) : invalid_native_file_k;
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
        io_request_t* request = connection.transport.emit(connection.file_read_request, io_operation_t::file_open_k,
                                                          file_segment.segment.bytes);
        request->deadline = 0;
        request->file = {.file = file_segment.file};
        return request;
    }

    /** Breaks off a reply whose head already left: the close resets the connection, so the peer
     *  never takes the truncated body for a whole one, and the reply's outcome reports @p cause. */
    static void fail_reply(connection_t& connection, server_exchange_t& exchange, ucall_status_t cause) noexcept {
        publish_reply_outcome(exchange, cause);
        connection.transport.close_mode = close_mode_t::reset_k;
        connection.transport.fail(cause);
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
        ucall_status_t result = formatting_t::write_reply_head(head, exchange.geometry, status);
        if (result == ucall_status_success_k && !range.empty())
            result = http_t::append_text(head, {"content-range: bytes */", range, "\r\n"});
        if (result == ucall_status_success_k) result = http_t::append_text(head, {"content-type: text/plain\r\n"});
        if (result == ucall_status_success_k)
            result = formatting_t::finish_reply_head(head, exchange, reply_framing_t::length_k, body.size());
        if (result == ucall_status_success_k && exchange.message.verb != ucall_verb_head_k)
            result = http_t::append_text(head, {body});
        if (result == ucall_status_success_k) result = formatting_t::spread_records(head, exchange.geometry);
        if (result == ucall_status_success_k && st::failed(head.resize(head.size() + exchange.geometry.tailroom)))
            result = ucall_status_out_of_memory_k;
        publish_reply_outcome(exchange, file_segment_status(refusal));
        if (result != ucall_status_success_k) connection.transport.fail(result);
    }

    /** Completes a measured reply's head with the measured @c content-length once every file
     *  segment is measured, or replaces the whole reply on the first that cannot be sent; a
     *  @c HEAD request then drops the body. Either way its head becomes @c pushed_k. */
    static void complete_deferred_head(connection_t& connection, server_exchange_t& exchange) noexcept {
        exchange.reply_head = reply_head_t::pushed_k;
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
        ucall_status_t result = formatting_t::finish_reply_head(head, exchange, reply_framing_t::length_k, length);
        if (result == ucall_status_success_k) result = formatting_t::spread_records(head, exchange.geometry);
        if (result == ucall_status_success_k && st::failed(head.resize(head.size() + exchange.geometry.tailroom)))
            result = ucall_status_out_of_memory_k;
        if (result != ucall_status_success_k) {
            publish_reply_outcome(exchange, result);
            return connection.transport.fail(result);
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
        serving_t::mark_ready(event_loop, *connection);
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

    /** Grows the pool by one run of windows in one allocation, registered with the engine once: as
     *  many windows as fill the allocator's page, at least one and at most the pool's limit, so a
     *  huge page holds many. A run the engine fails to register, rather than declining to pin it,
     *  adds no window. */
    static ucall_status_t grow_windows(event_loop_t& event_loop) noexcept {
        auto& pool = event_loop.file_windows;
        using page_t = typename file_window_pool_t::page_t;
        rebound_allocator<page_t> pages {event_loop.allocator};
        std::size_t granularity = page_bytes_k;
        if constexpr (requires { pages.default_page_size(); })
            granularity = std::max<std::size_t>(pages.default_page_size(), page_bytes_k);
        std::size_t const window_bytes = file_window_pool_t::window_bytes;
        std::size_t const run_windows = std::min<std::size_t>(std::max<std::size_t>(granularity / window_bytes, 1),
                                                              pool.max_windows - pool.allocated_windows);
        std::size_t const run_bytes = (run_windows * window_bytes + granularity - 1) / granularity * granularity;
        page_t* const run = pages.allocate(run_bytes / page_bytes_k);
        if (!run) return ucall_status_out_of_memory_k;
        byte_t* const base = reinterpret_cast<byte_t*>(run);
        io_request_t release {.operation = io_operation_t::zero_copy_release_k, .context = &pool};
        // Past the engine's table or its locked-memory cap, sends pin each window themselves.
        if (pool.pinning == range_pinning_t::pinned_k) {
            memory_registration_t const registration = event_loop.engine.register_memory(
                {base, run_windows * window_bytes});
            if (registration.status != ucall_status_success_k) {
                pages.deallocate(run, run_bytes / page_bytes_k);
                return registration.status;
            }
            pool.pinning = registration.pinning;
            if (registration.pinning == range_pinning_t::pinned_k) release.registered_memory = registration.index;
        }
        if (release.registered_memory == io_unregistered_k)
            tally<atomic_ref>(event_loop.statistics.windows_unpinned, run_windows);
        [[maybe_unused]] st::status_t const kept = pool.window_runs.push_back(st::assume_reserved,
                                                                              span<byte_t> {base, run_bytes});
        for (std::size_t offset = run_windows * window_bytes; offset;) {
            offset -= window_bytes;
            [[maybe_unused]] st::status_t const listed = pool.window_memory.push_back(st::assume_reserved,
                                                                                      base + offset);
            [[maybe_unused]] st::status_t const added = pool.windows.push_back(
                st::assume_reserved, file_window_t {.next = std::exchange(pool.free_windows, pool.allocated_windows)});
            [[maybe_unused]] st::status_t const named = pool.release_requests.push_back(st::assume_reserved,
                                                                                        io_request_t {release});
            ++pool.allocated_windows;
        }
        return ucall_status_success_k;
    }

    /** A vacant window for @p connection's stream: a free one, one of a run the pool grows by while
     *  below its limit, else none, queuing the stream for the next release. */
    static std::uint32_t borrow_window(event_loop_t& event_loop, connection_t& connection) noexcept {
        auto& pool = event_loop.file_windows;
        if (pool.free_windows == absent_k && pool.allocated_windows != pool.max_windows &&
            grow_windows(event_loop) != ucall_status_success_k)
            return absent_k;
        std::uint32_t const window = pool.free_windows;
        if (window != absent_k) pool.free_windows = pool.windows[window].next;
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
        pool.release_requests[window].descriptor = connection.transport.descriptor;
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
        if (connection.oldest_window != window) tally<atomic_ref>(event_loop.statistics.file_window_overlaps);
        std::uint64_t const alignment = std::uint64_t {1} << file_segment.alignment_log2;
        bool const sealed = connection.transport.tunnel.encrypts();
        std::size_t const payload = sealed ? window_record_payload(connection.transport.tunnel.geometry(), file_segment)
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
        byte_t* const base = pool.window_memory[window] + page_bytes_k;
        connection.file_reading = file_read_state_t::reading_file_k;
        io_request_t* request;
        if (!sealed)
            request = connection.transport.emit(connection.file_read_request, io_operation_t::file_read_k,
                                                {base, length});
        else {
            std::size_t const slots = (length + payload - 1) / payload;
            for (std::size_t slot = 0; slot != slots; ++slot)
                connection.file_read_vectors[slot] = {base + slot * file_record_stride_k,
                                                      std::min(payload, length - slot * payload)};
            request = connection.transport.emit(connection.file_read_request, io_operation_t::file_read_vectors_k,
                                                {reinterpret_cast<byte_t*>(connection.file_read_vectors), slots});
        }
        request->deadline = 0;
        request->registered_memory = pool.registered_memory(window);
        request->file = {.offset = record.extent_offset, .file = file_segment.file};
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
        if (connection.transport.stage == transport_stage_t::open_k && covered) {
            record.stage = file_window_stage_t::filled_k;
            return;
        }
        vacate_window(event_loop, unlink_newest_window(event_loop, connection));
        if (connection.transport.stage == transport_stage_t::open_k)
            fail_reply(connection, *connection.oldest_exchange, ucall_status_io_k);
    }

    /** Windows a stream may hold at once: one reading, one sending, and as many more as its
     *  socket's @p send_buffer_bytes, so zero-copy never holds more than a copying send would. */
    static std::uint32_t stream_windows_limit(std::size_t send_buffer_bytes) noexcept {
        std::size_t const buffer = file_window_pool_t::window_bytes;
        return static_cast<std::uint32_t>(std::max<std::size_t>(2, (send_buffer_bytes + buffer - 1) / buffer));
    }

    /** The next file request of the oldest reply: open and measure every file segment of a
     *  deferred head, then complete it; open and measure the oldest file segment; or read its next
     *  slice into a borrowed window, while the socket side sends the earlier ones. Null once
     *  nothing can proceed. */
    static io_request_t* read_reply(event_loop_t& event_loop, connection_t& connection) noexcept {
        auto* exchange = connection.oldest_exchange;
        // Until the loop adopted a segment of the reply, its replier may still be writing the head.
        if (!exchange || exchange->stage == exchange_stage_t::dispatched_k ||
            connection.file_reading == file_read_state_t::waiting_window_k)
            return nullptr;
        if (exchange->reply_head == reply_head_t::held_k) {
            if (exchange->stage != exchange_stage_t::ended_k) return nullptr;
            for (file_segment_t* file_segment = exchange->oldest_file_segment; file_segment;
                 file_segment = file_segment->next) {
                if (file_segment->stage == file_segment_stage_t::unopened_k)
                    return submit_file_open(connection, *file_segment);
                if (file_segment->stage == file_segment_stage_t::opened_k) stat_file_segment(*exchange, *file_segment);
            }
            complete_deferred_head(connection, *exchange);
            if (connection.transport.stage != transport_stage_t::open_k) return nullptr;
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
        if (held >= stream_windows_limit(connection.send_buffer_bytes)) return nullptr;
        std::uint32_t const window = borrow_window(event_loop, connection);
        if (window == absent_k) {
            if (connection.file_reading != file_read_state_t::waiting_window_k)
                fail_reply(connection, *exchange, ucall_status_out_of_memory_k);
            return nullptr;
        }
        return submit_file_read(event_loop, connection, *file_segment, window);
    }

    /** Starts sending @p bytes of @p exchange's front segment, sealing its records first; every
     *  segment send names the exchange's release until the socket is demoted to copying. A
     *  stream whose sends hold its socket's send buffer submits that release first, and sends
     *  on once it completes. */
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
        if (ucall_status_t const sealed = connection.transport.seal_records(bytes); sealed != ucall_status_success_k) {
            connection.transport.fail(sealed);
            return nullptr;
        }
        if (connection.send_mode == send_mode_t::copying_k) return connection.transport.emit_send(bytes);
        return connection.transport.emit_zero_copy(bytes, name_exchange_release(connection, exchange),
                                                   io_unregistered_k);
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
        byte_t* const base = pool.window_memory[window] + page_bytes_k;
        span<byte_t> bytes {base + record.skipped + record.sent_bytes, record.slice_bytes - record.sent_bytes};
        if (connection.transport.tunnel.encrypts()) {
            secure_tunnel_geometry_t const geometry = connection.transport.tunnel.geometry();
            std::size_t const payload = window_record_payload(geometry, file_segment),
                              position = record.skipped + record.sent_bytes, slot = position / payload,
                              end = std::min<std::size_t>(record.skipped + record.slice_bytes, (slot + 1) * payload);
            byte_t* const start = base + slot * file_record_stride_k + (position - slot * payload);
            bytes = {start - geometry.headroom, end - position + secure_tunnel_overhead_k};
            if (connection.transport.tunnel.seal(bytes, end - position).empty()) {
                connection.transport.fail(ucall_status_handshake_failed_k);
                return nullptr;
            }
        }
        record.stage = file_window_stage_t::sending_k;
        return connection.transport.emit_zero_copy(bytes, pool.release_requests[window],
                                                   pool.registered_memory(window));
    }

    /** The next socket request of the oldest reply, taking these steps in turn: finish a partial
     *  send; retire what was sent; wait for a deferred head or a stream's release; send the front
     *  memory segment; or, for a file segment, send its chunk framing, its windows in file order,
     *  each followed by its release, and its closing framing. Null once nothing can proceed, or
     *  the connection failed. */
    static io_request_t* transmit_reply(event_loop_t& event_loop, connection_t& connection) noexcept {
        for (;;) {
            if (connection.transport.sending) return connection.transport.resume_send();
            if (io_request_t* release = retire_sent_segments(event_loop, connection)) return release;
            auto* exchange = connection.oldest_exchange;
            if (connection.transport.stage != transport_stage_t::open_k || !exchange || !exchange->oldest_segment ||
                exchange->reply_head == reply_head_t::held_k ||
                exchange->releases[exchange->naming].state == release_state_t::releasing_k)
                return nullptr;
            connection.transport.transmitting = transmit_state_t::sending_k;
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
            if (connection.transport.output_offset < prefix)
                return send_segment(connection, *exchange, {bytes.data(), prefix});
            if (connection.oldest_window != absent_k) return transmit_window(event_loop, connection, *file_segment);
            if (file_segment->remaining_bytes) return nullptr;
            if (connection.transport.output_offset == bytes.size()) continue;
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
        if (connection.transport.sending) return;
        if (window == absent_k) connection.transport.output_offset += connection.transport.sending_length;
        else
            event_loop.file_windows.windows[window].sent_bytes += static_cast<std::uint32_t>(
                connection.transport.sending_length -
                (connection.transport.tunnel.encrypts() ? secure_tunnel_overhead_k : 0));
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
        ++pool.releasing_windows;
        ++connection.releasing_windows;
    }

    /** Lands a completed release: a window returns to the pool, waking the oldest waiting stream,
     *  and an exchange hands its segments back, recycling once its connection let go of it. A
     *  release the engine reports copying demotes the connection's sends, and a close waiting for
     *  the last release goes on. */
    static void complete_release(event_loop_t& event_loop, io_completion_t const& completion) noexcept {
        auto& pool = event_loop.file_windows;
        std::uint32_t const window = pool.window_of(completion.request);
        connection_t* connection;
        if (window != absent_k) {
            connection = event_loop.connections[pool.windows[window].connection].get();
            --pool.releasing_windows;
            --connection->releasing_windows;
            vacate_window(event_loop, window);
        }
        else {
            auto& exchange = *static_cast<server_exchange_t*>(completion.request->context);
            connection = exchange.connection;
            --connection->releasing_exchanges;
            return_released_segments(exchange, exchange.release_of(completion.request));
            if (exchange.stage == exchange_stage_t::releasing_k && !exchange.releasing())
                serving_t::free_exchange(event_loop, exchange);
        }
        if (completion.result > 0) connection->send_mode = send_mode_t::copying_k;
        if (connection->transport.stage == transport_stage_t::releasing_k && !connection->outstanding_releases())
            connection->transport.stage = transport_stage_t::closing_k;
        serving_t::mark_ready(event_loop, *connection);
    }

    /** The next release a closing connection owes the kernel, once no send or read is in flight:
     *  windows it sent from leave for the pool, the rest return vacant, and exchanges whose sends
     *  named a release submit it. Null once nothing is left to release. */
    static io_request_t* drain_releases(event_loop_t& event_loop, connection_t& connection) noexcept {
        if (connection.transport.transmit_operation == operation_state_t::submitted_k ||
            connection.file_read_operation == operation_state_t::submitted_k)
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
};

} // namespace unum::ucall::network
