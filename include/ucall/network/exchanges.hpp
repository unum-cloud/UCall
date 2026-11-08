/**
 *  @file include/ucall/network/exchanges.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Endpoints, batch endpoints, and the server exchanges carrying a request and its reply.
 */
#pragma once

#include <bit> // `std::countr_zero`

#include <smashtable/atomic_intrusive_stack.hpp> // `atomic_intrusive_stack`

#include "ucall/io/types.hpp"          // `io_request_t`, `wake_channel_t`
#include "ucall/network/types.hpp"     // `exchange_stage_t`, `body_stage_t`, `parts_state_t`, `request_part_t`
#include "ucall/tunnel/types.hpp"      // `secure_tunnel_geometry_t`
#include "ucall/utilities/sockets.hpp" // `file_close`
#include "ucall/utilities/types.hpp"   // `text_view`, `allocator_delete`, `byte_t`, `publish`

namespace unum::ucall::network {

using io::io_request_t;
using io::wake_channel_t;
using tunnel::secure_tunnel_geometry_t;
using utilities::allocator_delete;
using utilities::byte_t;
using utilities::file_close;
using utilities::publish;
using utilities::text_view;

/** One batch endpoint: the ring every event loop deposits into, and the state its one polling
 *  owner keeps. */
template <typename network_type_>
struct batch_endpoint : ucall_http_batch_endpoint_handle_t {
    using network_t = network_type_;
    using allocator_t = typename network_t::allocator_t;
    using server_exchange_t = typename network_t::server_exchange_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;

    explicit batch_endpoint(allocator_t const& allocator = {}) noexcept
        : slots(rebound_allocator<server_exchange_t*> {allocator}),
          collected(rebound_allocator<ucall_received_http_request_t> {allocator}) {}
    batch_endpoint(batch_endpoint const&) = delete;
    batch_endpoint& operator=(batch_endpoint const&) = delete;
    batch_endpoint(batch_endpoint&&) = delete;
    batch_endpoint& operator=(batch_endpoint&&) = delete;

    /** A power of two above the request budget plus one per event loop. */
    vector<server_exchange_t*> slots {};

    /** Event loops @c fetch_add it. */
    alignas(fu::default_alignment_k) std::uint64_t tail {};

    /** Written by the polling owner only. */
    alignas(fu::default_alignment_k) std::uint64_t head {};
    wake_state_t wake_state {wake_state_t::awake_k};
    wake_channel_t wake {};
    ucall_received_http_batch_callback_t callback {};
    std::size_t min_batch_size {}, max_batch_size {}, max_latency_microseconds {};

    /** Owned by the polling owner, reserved to @c max_batch_size. */
    vector<ucall_received_http_request_t> collected {};
    void* context {};

    /** Advanced by the polling owner, loaded relaxed by any thread. */
    ucall_batch_endpoint_statistics_t statistics {};
};

template <typename network_type_>
struct endpoint {
    using network_t = network_type_;
    using allocator_t = typename network_t::allocator_t;
    using batch_endpoint_t = typename network_t::batch_endpoint_t;
    using endpoint_t = typename network_t::endpoint_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;
    template <typename value_type_>
    using owner = typename network_t::template owner<value_type_>;

    explicit endpoint(allocator_t const& allocator = {}) noexcept : storage(rebound_allocator<char> {allocator}) {}
    endpoint(endpoint const&) = delete;
    endpoint& operator=(endpoint const&) = delete;
    endpoint(endpoint&&) = delete;
    endpoint& operator=(endpoint&&) = delete;

    vector<char> storage {};
    std::string_view path {};
    ucall_verb_t verb {};
    ucall_received_http_request_callback_t callback {};
    ucall_body_delivery_t body_delivery {};

    /** Apart, so deposits never contend with routing reads of this endpoint. */
    owner<batch_endpoint_t> batch {};
    void* context {};
    endpoint_t* next {};
};

/** Set once a reply began and once it ended, so a claimed reply not yet replied is an open
 *  stream, and once the connection left. A listing is the loop's promise to look at the
 *  exchange once, and survives the exchange's recycling. */
enum exchange_state_t : std::uint32_t { claimed_k = 1, replied_k = 2, detached_k = 4, listed_k = 8 };

/** What a streamed body's reader asked of the loop: nothing, to read on with no pull left behind,
 *  or to finish a pull whose view and outcome it published. */
enum pull_request_t : std::uint32_t { pull_unrequested_k, pull_more_k, pull_waiting_k };

/** The bit index of one @p state flag, as the single-bit test-and-set takes it. */
constexpr unsigned bit_of(exchange_state_t state) noexcept {
    return static_cast<unsigned>(std::countr_zero(static_cast<std::uint32_t>(state)));
}

/** One of an exchange's two zero-copy releases: what the sends naming it hold, and the
 *  segments they sent, which return to their free lists once it completes. */
template <typename network_type_>
struct exchange_release {
    using network_t = network_type_;
    using reply_segment_t = typename network_t::reply_segment_t;
    using file_segment_t = typename network_t::file_segment_t;

    io_request_t request {};
    reply_segment_t* sent_segments {};
    file_segment_t* sent_file_segments {};
    std::size_t held_bytes {};
    release_state_t state {};
};

/** A link of an event loop's replied queue, naming the exchange it carries, or none for the
 *  loop's own stub. */
template <typename network_type_>
struct replied_link {
    using network_t = network_type_;
    using replied_link_t = typename network_t::replied_link_t;
    using server_exchange_t = typename network_t::server_exchange_t;

    replied_link_t* next {};
    server_exchange_t* exchange {};
};

template <typename network_type_>
struct server_exchange : ucall_received_http_request_handle_t {
    using network_t = network_type_;
    using allocator_t = typename network_t::allocator_t;
    using http_message_t = typename network_t::http_message_t;
    using reply_segment_t = typename network_t::reply_segment_t;
    using file_segment_t = typename network_t::file_segment_t;
    using connection_t = typename network_t::server_connection_t;
    using endpoint_t = typename network_t::endpoint_t;
    using exchange_release_t = typename network_t::exchange_release_t;
    using replied_link_t = typename network_t::replied_link_t;
    using server_exchange_t = typename network_t::server_exchange_t;
    using network_interface_t = typename network_t::network_interface_t;
    using event_loop_t = typename network_t::event_loop_t;
    using replies_t = typename network_t::replies_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;
    template <typename value_type_>
    using atomic_ref = typename network_t::template atomic_ref<value_type_>;

    explicit server_exchange(allocator_t const& allocator = {}) noexcept
        : input(rebound_allocator<byte_t> {allocator}), head_segment(allocator), end_segment(allocator),
          body_chunk(rebound_allocator<byte_t> {allocator}), pulled_chunk(rebound_allocator<byte_t> {allocator}),
          parts(rebound_allocator<request_part_t> {allocator}) {
        shared.replied_link.exchange = this;
    }
    server_exchange(server_exchange const&) = delete;
    server_exchange& operator=(server_exchange const&) = delete;
    server_exchange(server_exchange&&) = delete;
    server_exchange& operator=(server_exchange&&) = delete;
    ~server_exchange() noexcept {
        for (reply_segment_t* segment : {free_segments, shared.returned_segments.take_all(), queued_segments(),
                                         releases[0].sent_segments, releases[1].sent_segments})
            while (segment) {
                reply_segment_t* next = segment->next;
                if (segment != &head_segment && segment != &end_segment && !holds_file_segment(segment))
                    allocator_delete<reply_segment_t, allocator_t> {event_loop->allocator}(segment);
                segment = next;
            }
        for (file_segment_t* file_segment :
             {free_file_segments, shared.returned_file_segments.take_all(), queued_file_segments(),
              releases[0].sent_file_segments, releases[1].sent_file_segments})
            while (file_segment) {
                file_segment_t* next = file_segment->next;
                if (replies_t::owns_file_descriptor(*file_segment)) file_close(file_segment->file_descriptor);
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
        if (!newest_segment) return shared.pushed_segments;
        return newest_segment == &head_segment || newest_segment == &end_segment ? newest_segment->next : nullptr;
    }
    file_segment_t* queued_file_segments() const noexcept {
        if (parked_file_segment) return parked_file_segment;
        if (oldest_file_segment) return oldest_file_segment;
        return newest_file_segment ? nullptr : shared.pushed_file_segments;
    }

    /** Whether @p segment is embedded in one of the file segments queued to send. */
    bool holds_file_segment(reply_segment_t const* segment) const noexcept {
        for (file_segment_t* file_segment = queued_file_segments(); file_segment; file_segment = file_segment->next)
            if (&file_segment->segment == segment) return true;
        return false;
    }

    event_loop_t* event_loop {};

    /** Kept while the kernel holds its segments, past its reply. */
    connection_t* connection {};
    endpoint_t* endpoint {};

    /** Copied at dispatch, as a batch can outlive its connection. */
    network_interface_t* network_interface {};
    ucall_noise_key_t peer_static_key {};
    ucall_peer_address_t peer_address {};

    /** Copied at dispatch; zero headroom and tailroom for plaintext. */
    secure_tunnel_geometry_t geometry {};

    /** Links every exchange the event loop owns, until the loop is freed. */
    server_exchange_t* next {};

    /** Links the event loop's free list once recycled. */
    server_exchange_t* replied_next {};

    /** Links its connection's exchanges in request order. */
    server_exchange_t* connection_next {};
    exchange_stage_t stage {};
    http_message_t message {};
    vector<byte_t> input {};

    /** When the request was dispatched, for batch expiry and latency lines. */
    std::uint64_t arrived {};

    /** The status its reply began with, zero before one did. */
    std::uint16_t reply_status {};

    /** Reply body bytes, counted later by the event loop, as any thread may reply. */
    std::size_t copied {};

    /** A stream's status line and headers, and the segment ending every reply: a whole one, or
     *  a stream's last chunk. The loop learns a reply ended by adopting @c end_segment, and
     *  only the chunks between the two ever allocate. */
    reply_segment_t head_segment, end_segment;

    /** The replier's newest, whose @c next the next chain lands in. */
    reply_segment_t* pushed_tail {};

    /** Free chunks only the replier touches. */
    reply_segment_t* free_segments {};

    /** The adopted segments the loop sends, in order. */
    reply_segment_t* oldest_segment {};

    /** The loop's cursor, whose @c next the replier may still link. */
    reply_segment_t* newest_segment {};

    /** Retired at the cursor, so handed back only once it moves. */
    reply_segment_t* parked_segment {};

    /** The replier's newest file segment. File segments' own segments sit in the same stacks
     *  and queue: the replier pushes each ahead of its segment, the loop adopts them after the
     *  segments, and recognizes one by its segment reaching the front of the queue. */
    file_segment_t* pushed_file_tail {};

    /** Free ones only the replier touches. */
    file_segment_t* free_file_segments {};

    /** The adopted ones, in order. */
    file_segment_t* oldest_file_segment {};

    /** The loop's cursor over file segments. */
    file_segment_t* newest_file_segment {};

    /** Retired at either cursor, handed back once both moved. */
    file_segment_t* parked_file_segment {};

    /** A reply's deferred outcome, which the loop makes final. */
    ucall_outcome_t* outcome {};

    /** A streamed body's @c content-length and bytes so far. */
    std::uint64_t declared {}, streamed {};

    /** How the replier frames its chunks. */
    reply_framing_t framing {};

    /** Whether the loop completes the head once it sized every file. */
    reply_head_t reply_head {};

    /** Sends name <tt>releases[naming]</tt>, each release holding at most half the socket's
     *  send buffer, so the next one fills while the other is in the kernel's hands. */
    exchange_release_t releases[2] {};
    std::uint8_t naming {};
    bool releasing() const noexcept {
        return releases[0].state == release_state_t::releasing_k || releases[1].state == release_state_t::releasing_k;
    }

    /** The release @p request is, among the two of this exchange. */
    exchange_release_t& release_of(io_request_t const* request) noexcept {
        return releases[request == &releases[1].request];
    }

    /** A streamed request body: the loop decodes into @c body_chunk, and a pull swaps it with
     *  @c pulled_chunk, which the application views until its next pull. Only the loop touches
     *  either; a pull from another thread only raises @c shared.pull_requested. */
    vector<byte_t> body_chunk {}, pulled_chunk {};

    /** A waiting pull's output, written as the loop finishes it. */
    ucall_bytes_view_t* pulled_view {};

    /** A waiting pull's outcome, which the loop makes final. */
    ucall_outcome_t* pull_outcome {};
    body_stage_t body_stage {};

    /** How a streamed body ended, which pulls past its bytes report. */
    ucall_status_t body_status {};

    /** Located on the first lookup, kept for the request's life. */
    vector<request_part_t> parts {};

    /** Written only by the one thread operating on the request. */
    parts_state_t parts_state {};
    std::string_view text() const noexcept { return text_view(input); }

    /** Words a replier or puller writes while the loop reads the cursors above, on lines of
     *  their own: the reply's state bits, its hold on the socket, and the stacks both link. */
    struct alignas(fu::default_alignment_k) shared_t {
        std::uint32_t state {};

        /** A @c pull_request_t, raised by a pull from any thread, lowered by the loop. */
        std::uint32_t pull_requested {pull_unrequested_k};

        /** Queued ones the loop has not retired. */
        std::uint32_t unsent_file_segments {};

        /** Queued chunk bytes the socket has not taken. */
        std::size_t unsent_bytes {};

        /** The reply's first segment, which the replier links once. */
        reply_segment_t* pushed_segments {};

        /** Released chunks the loop pushes back; taken whole by the replier. */
        st::atomic_intrusive_stack<reply_segment_t, atomic_ref> returned_segments {};

        /** The reply's first file segment, linked once. */
        file_segment_t* pushed_file_segments {};

        /** Released ones the loop pushes back for the replier. */
        st::atomic_intrusive_stack<file_segment_t, atomic_ref> returned_file_segments {};

        /** Queues it for its event loop while listed. */
        replied_link_t replied_link {};
    } shared;
    static_assert(sizeof(shared_t) == fu::default_alignment_k);
};

} // namespace unum::ucall::network
