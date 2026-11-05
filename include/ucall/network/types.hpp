/**
 *  @file include/ucall/network/types.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The handles the C faces cast to, and the stages, limits and segment records a network
 *      shares across its files.
 */
#pragma once

#include "ucall/io/types.hpp"        // `close_mode_t`, `listing_t`
#include "ucall/utilities/types.hpp" // `byte_t`

struct ucall_received_http_request_handle_t {};
struct ucall_http_batch_endpoint_handle_t {};

struct ucall_server_handle_t {
    ucall_server_handle_t() noexcept = default;
    ucall_server_handle_t(ucall_server_handle_t const&) = delete;
    ucall_server_handle_t& operator=(ucall_server_handle_t const&) = delete;
    ucall_server_handle_t(ucall_server_handle_t&&) = delete;
    ucall_server_handle_t& operator=(ucall_server_handle_t&&) = delete;

    /** Stopping runs on any thread, so it touches only this CPU-independent word. */
    std::uint32_t stage {};

    struct api_t {
        void (*free)(ucall_server_t);
        void (*stop)(ucall_server_t);
        void (*take_call)(ucall_server_take_call_t*);
        void (*take_calls)(ucall_server_take_calls_t*);
        void (*event_loop_statistics)(ucall_server_event_loop_statistics_t*);
        void (*take_batch)(ucall_server_take_batch_t*);
        void (*take_batches)(ucall_server_take_batches_t*);
        void (*batch_endpoint_statistics)(ucall_server_batch_endpoint_statistics_t*);
        void (*add_http_endpoint)(ucall_server_add_http_endpoint_t*);
        ucall_verb_t (*request_verb)(ucall_server_t, ucall_received_http_request_t);
        void (*request_path)(ucall_server_request_path_t*);
        std::size_t (*request_path_segments_count)(ucall_server_t, ucall_received_http_request_t);
        void (*request_path_segment)(ucall_server_request_path_segment_t*);
        void (*request_path_parameter)(ucall_server_request_path_parameter_t*);
        void (*request_query_parameter)(ucall_server_request_query_parameter_t*);
        void (*request_header)(ucall_server_request_header_t*);
        void (*request_fields_count)(ucall_server_request_fields_count_t*);
        void (*request_field)(ucall_server_request_field_t*);
        void (*request_query)(ucall_server_request_query_t*);
        void (*request_peer)(ucall_server_request_peer_t*);
        void (*request_body)(ucall_server_request_body_t*);
        void (*reply_content)(ucall_server_reply_content_t*);
        void (*reply_error)(ucall_server_reply_error_t*);
        void (*add_http_batch_endpoint)(ucall_server_add_http_batch_endpoint_t*);
        void (*reply_vectored)(ucall_server_reply_vectored_t*);
        void (*reply_begin)(ucall_server_reply_begin_t*);
        void (*reply_append)(ucall_server_reply_append_t*);
        void (*reply_end)(ucall_server_reply_end_t*);
        void (*request_body_chunk)(ucall_server_request_body_chunk_t*);
        std::size_t (*request_parts_count)(ucall_server_t, ucall_received_http_request_t);
        void (*request_part)(ucall_server_request_part_t*);
        void (*bind_client)(ucall_client_init_t*);
    };
    api_t const* api {};
};
struct ucall_client_handle_t {
    ucall_client_handle_t() noexcept = default;
    ucall_client_handle_t(ucall_client_handle_t const&) = delete;
    ucall_client_handle_t& operator=(ucall_client_handle_t const&) = delete;
    ucall_client_handle_t(ucall_client_handle_t&&) = delete;
    ucall_client_handle_t& operator=(ucall_client_handle_t&&) = delete;

    struct api_t {
        void (*free)(ucall_client_t);
        void (*call)(ucall_client_call_t*);
        void (*take_completed)(ucall_client_take_completed_t*);
    };
    api_t const* api {};
};

namespace unum::ucall::network {

using io::close_mode_t;
using io::listing_t;
using utilities::byte_t;
using server_api_t = ucall_server_handle_t::api_t;
using client_api_t = ucall_client_handle_t::api_t;

/** Serving until the first stop, draining the replies in flight after it, and cutting them after
 *  any later stop; the server's @c stage word holds it. */
enum class server_stage_t : std::uint32_t { serving_k, draining_k, cutting_k };
enum class transport_stage_t : std::uint8_t {
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
inline constexpr std::size_t linger_microseconds_k = 1'000'000;

/** Linux's default receive buffer, @c tcp_rmem, bounds what a peer has in flight at our FIN. */
inline constexpr std::size_t linger_bytes_k = 128 * 1024;

/** Whether a direction's one engine request is in flight; only submission and completion
 *  write it. */
enum class operation_state_t : std::uint8_t { idle_k, submitted_k };

/** The receive side: reading, full while it holds as many parsed messages as its consumer accepts
 *  now, or ended by <tt>connection: close</tt>, a peer close, or an unparsable request. */
enum class receive_state_t : std::uint8_t { reading_k, full_k, ended_k };

/** The transmit side: idle, or sending a reply's segment, a window's slice, or a client's
 *  newest request. */
enum class transmit_state_t : std::uint8_t { idle_k, sending_k };

/** How the socket's sends reach the wire: pinned until the kernel reports a copied send, which
 *  demotes the socket for good, as the rulings say; a demoted socket names no releases. */
enum class send_mode_t : std::uint8_t { zero_copy_k, copying_k };

/** Whether a request expecting <tt>100-continue</tt> is still owed its interim response. */
enum class continue_state_t : std::uint8_t { none_k, owed_k };

/** Whether the event loop adopted any segment of an exchange's reply yet, whether the last one,
 *  and whether its connection let go of it while the kernel still holds its segments; only the
 *  loop writes this. */
enum class exchange_stage_t : std::uint8_t { dispatched_k, collected_k, ended_k, releasing_k };

/** Whether a request's body was buffered before dispatch, is still streaming in through
 *  pulls, or streamed to its end; only the loop writes this once dispatched. */
enum class body_stage_t : std::uint8_t { buffered_k, streaming_k, ended_k };

/** Whether a request's multipart parts were looked for yet, and whether its body held them. */
enum class parts_state_t : std::uint8_t { unlocated_k, located_k, malformed_k };

/** One multipart part's headers and payload, @c offset to <tt>offset + length</tt> of its
 *  input. */
struct request_part_t {
    std::uint64_t offset {}, length {};
};

/** Whether zero-copy sends named a release request since it last completed, and whether it is
 *  in flight; segments it covers return to their free lists only once it completes. */
enum class release_state_t : std::uint8_t { idle_k, named_k, releasing_k };

/** How a streamed reply delimits its body: by a declared length, in chunks, by the close, or
 *  not at all, as for @c HEAD, @c 204 and @c 304. */
enum class reply_framing_t : std::uint8_t { length_k, chunked_k, until_close_k, bodiless_k };

/** Whether a reply's head was pushed, or is held until the loop sized every file segment. */
enum class reply_head_t : std::uint8_t { pushed_k, held_k };

/** A reading peer takes Linux's default @c tcp_rmem per round trip, so more unsent chunk bytes
 *  only queue. */
inline constexpr std::size_t max_unsent_bytes_k = 128 * 1024;

/** Each unsent file segment pins a descriptor, so a stream outrunning its peer pins at most
 *  this many. */
inline constexpr std::size_t max_unsent_file_segments_k = 64;

/** One slice of a reply, linked into its exchange's pushed stack, its send queue, or a free
 *  list; never moved while linked, so the event loop sends from it in place. Under Noise its
 *  bytes are whole records, each payload followed by a gap for its tag and the next header. */
template <typename network_type_>
struct reply_segment {
    using network_t = network_type_;
    using allocator_t = typename network_t::allocator_t;
    using reply_segment_t = typename network_t::reply_segment_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;

    explicit reply_segment(allocator_t const& allocator = {}) noexcept : bytes(rebound_allocator<byte_t> {allocator}) {}
    reply_segment(reply_segment const&) = delete;
    reply_segment& operator=(reply_segment const&) = delete;
    reply_segment(reply_segment&&) = delete;
    reply_segment& operator=(reply_segment&&) = delete;

    /** Framed bytes between the tunnel's headroom and tailroom. */
    vector<byte_t> bytes {};
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
template <typename network_type_>
struct file_segment {
    using network_t = network_type_;
    using allocator_t = typename network_t::allocator_t;
    using reply_segment_t = typename network_t::reply_segment_t;
    using file_segment_t = typename network_t::file_segment_t;

    explicit file_segment(allocator_t const& allocator = {}) noexcept : segment(allocator) {
        static_assert(sizeof(file_segment_t) == sizeof(reply_segment_t) + 32);
        static_assert(!std::is_empty_v<allocator_t> || sizeof(reply_segment_t) == 32,
                      "a stateless allocator keeps reply segments at 32 bytes and file segments at 64");
    }
    file_segment(file_segment const&) = delete;
    file_segment& operator=(file_segment const&) = delete;
    file_segment(file_segment&&) = delete;
    file_segment& operator=(file_segment&&) = delete;

    reply_segment_t segment;
    file_segment_t* next {};

    /** The next byte to read. */
    std::uint64_t file_offset {};

    /** Still unread; the file's size, once out of range. */
    std::uint64_t remaining_bytes {};

    /** The directory while unopened, then the file. */
    int file_descriptor {-1};
    file_segment_stage_t stage {};
    file_origin_t file_origin {};

    /** Framing bytes of @c segment ahead of the range. */
    std::uint8_t chunk_prefix_bytes {};

    /** Of the file's unbuffered reads, once measured. */
    std::uint8_t alignment_log2 {};
};

/** Records one window reads at once: 256 KiB, one or two device commands. */
inline constexpr std::size_t file_window_records_k = 4;

/** The span of one record's payload slot and its gap, as P + A is 65536 for every alignment A
 *  from 512 to 32768. */
inline constexpr std::size_t file_record_stride_k = 64 * 1024;

/** A window's headroom, which holds its first record's header and keeps its reads aligned. */
inline constexpr std::size_t page_bytes_k = 4096;

/** The largest unbuffered alignment a window serves: past it, no record payload fits a slot. */
inline constexpr std::size_t file_max_alignment_k = 32768;

/** No index, as @c file_window_t links and borrowers spell it. */
inline constexpr std::uint32_t absent_k = std::numeric_limits<std::uint32_t>::max();

/** Where a pooled window is: free, read into, holding read bytes, being sent, or waiting for
 *  the kernel to let go of it. */
enum class file_window_stage_t : std::uint8_t { vacant_k, reading_k, filled_k, sending_k, releasing_k };

/** What a connection's file side does: nothing, open a path, read a window, or wait for one. */
enum class file_read_state_t : std::uint8_t { idle_k, opening_file_k, reading_file_k, waiting_window_k };

/** One window of an event loop's pool: an aligned read of a file segment and its slice. */
struct file_window_t {

    /** Aligned file offset the read started at. */
    std::uint64_t extent_offset {};

    /** Bytes of the requested range in this window. */
    std::uint32_t slice_bytes {};

    /** Of those, taken by the socket. */
    std::uint32_t sent_bytes {};

    /** The stream's next window, or the next free one. */
    std::uint32_t next {absent_k};

    /** The borrower, until the window is vacant again. */
    std::uint32_t connection {absent_k};

    /** Read ahead of the range, below the alignment. */
    std::uint16_t skipped {};
    file_window_stage_t stage {};
};
static_assert(sizeof(file_window_t) == 32);

/** Whether the peer's static key passed the authorizer, once, before the connection opens. */
enum class peer_verdict_t : std::uint8_t { unverified_k, authorized_k };

/** Whether the peer still writes, or sent its FIN or Noise close record. */
enum class peer_stream_t : std::uint8_t { writing_k, closed_k };

/** Whether a client polls its own engine, is advanced by the server event loop it is bound to, or
 *  was freed while bound and waits for that loop to end its connections. */
enum class client_binding_t : std::uint8_t { owned_k, bound_k, retiring_k };

/** Whether an event loop, or a batch endpoint's polling owner, runs, sleeps on its wake channel,
 *  or was notified since it last did either; only waking a sleeper writes the channel. */
enum class wake_state_t : std::uint32_t { awake_k, sleeping_k, notified_k };

/** Whether a client call is free, waits on its origin for a connection, or rides one's pipeline. */
enum class client_exchange_stage_t : std::uint8_t { idle_k, waiting_k, pipelined_k };

/** Which record holds a transport, so a loop routes a bound client's completions to it. */
enum class transport_role_t : std::uint8_t { server_k, client_k };

/** Which of its loop's orders a server connection sits on: none, the idle ones saturation evicts
 *  oldest first, or the lingers and releases waiting for their deadlines. */
enum class connection_order_t : std::uint8_t { unlisted_k, keepalive_k, expiring_k };

/** A connection's place on its order, by indices into its loop's connections. */
struct order_link_t {
    std::uint32_t next {absent_k}, previous {absent_k};
};

/** The event loop's own counters beside its engine's, on lines no other thread writes. */
struct alignas(fu::default_alignment_k) event_loop_statistics_t {
    std::uint64_t polls {}, empty_polls {}, accepts {}, requests {}, bytes_received {}, bytes_sent {}, bytes_copied {},
        bytes_read {}, file_window_overlaps {}, linger_resets {}, ready_passes {}, replied_dequeues {};
};

/** The statuses the loop answers itself with, in @c interface_statistics_t::refused order. */
inline constexpr unsigned refused_statuses_k[] {400, 404, 405, 413, 501, 503, 505};

/** One event loop's refusals, handshake failures and live connections on one interface, in whole
 *  lines so neighbours in the loop's vector never share one. */
struct alignas(fu::default_alignment_k) interface_statistics_t {
    std::uint64_t refused[std::size(refused_statuses_k)] {};
    std::uint64_t handshake_failures {}, authorizer_refusals {}, connections {};
};
static_assert(sizeof(interface_statistics_t) % fu::default_alignment_k == 0);

} // namespace unum::ucall::network
