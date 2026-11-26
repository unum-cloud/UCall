/**
 *  @file include/ucall/io/linux_uring618_queue.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Registered sockets and multishot receive streams for Linux 6.18 io_uring.
 */
#pragma once

#include <smashtable/basic_vector.hpp> // `vector`
#include <smashtable/row_search.hpp>   // `serial_row_kit_t`

#include "ucall/io/linux_uring612_queue.hpp" // `uring_operation`, `registered_socket_t`
#include "ucall/io/types.hpp"          // `operation_list_t`, `zero_copy_stage_t`, `io_statistics_t`, `io_completion_t`
#include "ucall/utilities/sockets.hpp" // `monotonic_ns`
#include "ucall/utilities/types.hpp"   // `byte_t`, `descriptor_t`, `span`

namespace unum::ucall::io {

using utilities::byte_t;
using utilities::descriptor_t;
using utilities::monotonic_ns;
using utilities::span;

/** One-shot requests and multishot streams share the same registered socket slot lifetimes. */
template <typename allocator_type_ = st::default_allocator<byte_t>,
          template <typename> class atomic_ref_template_ = fu::standard_atomic_ref,
          typename row_kit_type_ = st::serial_row_kit_t>
struct linux_uring618_queue {
    using allocator_t = allocator_type_;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    template <typename value_type_>
    using vector = st::vector<value_type_, rebound_allocator<value_type_>>;
    template <typename other_allocator_type_, template <typename> class other_atomic_ref_, typename other_row_kit_>
    using rebind = linux_uring618_queue<other_allocator_type_, other_atomic_ref_, other_row_kit_>;

    enum class receive_stage_t : std::uint8_t {

        /** No stream is armed. */
        idle_k,

        /** A multishot receive the kernel holds. */
        submitted_k,

        /** A stream the kernel holds and was asked to cancel. */
        cancelling_k,

        /** The stream ended with @c terminal, which a receive answers once the backlog is empty. */
        ended_k,
    };

    /** Whether the socket's stream may prefetch, or stays cancelled while nobody pulls bytes or
     *  receives land in place. */
    enum class receive_flow_t : std::uint8_t {

        /** The stream re-arms whenever it ends. */
        flowing_k,

        /** The stream stays cancelled until the next receive is submitted. */
        paused_k,

        /** The stream stays cancelled while receives land in the room their requests name. */
        in_place_k,
    };

    /** Whether the socket's next stream is its first, or a re-arm the statistics count. */
    enum class stream_start_t : std::uint8_t {

        /** The socket never streamed. */
        first_k,

        /** The socket streamed before, so its next start counts in @c receive_rearms. */
        rearm_k,
    };
    struct alignas(8) socket_slot_t {

        /** The slot's index in the registered file table, which its handle holds. */
        unsigned index {};

        /** The next vacant slot while vacant, or the next on @c rearming_socket_slots. */
        unsigned next {operation_list_t::absent_k};

        /** The newest record the slot owns, linked through @c owned_next, or @c absent_k. */
        unsigned owned_head {operation_list_t::absent_k};

        /** The close request waiting for the slot to close, or @c absent_k. */
        unsigned close_operation {operation_list_t::absent_k};

        /** The receive waiting for the socket's bytes, or @c absent_k. */
        unsigned receive_operation {operation_list_t::absent_k};

        /** Unique per socket the slot held, so a late notification never demotes its successor. */
        std::uint64_t serial {};

        /** Received bytes no receive took yet, copied out of the pool. */
        vector<byte_t> backlog;

        /** Where the bytes of @c backlog not yet delivered start. */
        std::size_t backlog_offset {};

        /** The backlog a receive delivered, set apart until every holder released it, so bytes
         *  arriving behind it go to @c backlog and never move it. */
        vector<byte_t> delivered;

        /** Where the bytes @c delivered was delivered from start. */
        std::size_t delivered_offset {};

        /** Holders of @c delivered beyond the first, each releasing its own part of it. */
        std::uint32_t delivered_shares {};

        /** The result that ended the stream, valid while @c receive_stage is @c ended_k. */
        descriptor_t terminal {};

        /** Where the slot's registered descriptor stands. */
        uring_socket_stage_t stage {uring_socket_stage_t::vacant_k};

        /** Untried, or copying once the kernel refused zero-copy for the socket or for one send. */
        zero_copy_stage_t zero_copy {zero_copy_stage_t::untried_k};

        /** Whether the close sends a FIN or a reset. */
        close_mode_t close {close_mode_t::orderly_k};

        /** Where the socket's multishot receive stream stands. */
        receive_stage_t receive_stage {receive_stage_t::idle_k};

        /** Whether the stream may prefetch, or stays cancelled while nobody receives or receives
         *  land in place. */
        receive_flow_t receive_flow {receive_flow_t::flowing_k};

        /** Whether the next stream is the socket's first, or a re-arm. */
        stream_start_t stream_start {stream_start_t::first_k};

        /** Whether a completion named @c delivered from @c delivered_offset on and @c release has
         *  not run for it. */
        receive_slice_state_t backlog_slice_state {receive_slice_state_t::released_k};

        /** Whether the slot is on @c rearming_socket_slots, linked through @c next. */
        listing_t rearm_listing {listing_t::unlisted_k};

        /** Whether the slot is on @c waiting_socket_slots, linked through @c next_waiting. */
        listing_t waiting_listing {listing_t::unlisted_k};

        /** One slice waiting for a receive, uncopied for a poll round, or while its socket paused
         *  and the pool spares a buffer for the kernel; it implies an empty backlog. */
        span<byte_t> waiting_slice {};

        /** The next slot on @c waiting_socket_slots, or @c absent_k. */
        unsigned next_waiting {operation_list_t::absent_k};

        /** The header of the socket's gathered send, which names the request's vectors. */
        msghdr message {};
        explicit socket_slot_t(allocator_t const& allocator) noexcept : backlog(allocator), delivered(allocator) {}
        bool receive_in_flight() const noexcept {
            return receive_stage == receive_stage_t::submitted_k || receive_stage == receive_stage_t::cancelling_k;
        }
    };
    using state_t = uring_state<allocator_t, atomic_ref_template_>;
    using socket_slots_t = uring_socket_slots<socket_slot_t, allocator_t>;
    using operations_t = uring_operations<socket_slot_t, allocator_t>;
    using zero_copy_t = uring_zero_copy<socket_slot_t, allocator_t, atomic_ref_template_>;
    using operation_t = typename operations_t::operation_t;
    static_assert(sizeof(operation_t) == 56);
    static constexpr io_uring_op opcodes_k[] {
        IORING_OP_SOCKET,      IORING_OP_ACCEPT,   IORING_OP_CONNECT, IORING_OP_RECV,         IORING_OP_SEND,
        IORING_OP_READ,        IORING_OP_SHUTDOWN, IORING_OP_CLOSE,   IORING_OP_ASYNC_CANCEL, IORING_OP_LINK_TIMEOUT,
        IORING_OP_URING_CMD,   IORING_OP_OPENAT2,  IORING_OP_SEND_ZC, IORING_OP_READ_FIXED,   IORING_OP_READV,
        IORING_OP_READV_FIXED, IORING_OP_SENDMSG};
    static constexpr ucall_io_backend_t backend_k = ucall_io_backend_linux_uring618_k;
    static constexpr io_receive_memory_t receive_memory_k = io_receive_memory_t::queue_unless_room_k;

    /** The counters the queue and its components advance for its polling owner. */
    io_statistics_t statistics {};

    /** The ring, its registered tables and its receive pool. */
    state_t state;

    /** The registered sockets, each with its receive stream and backlog. */
    socket_slots_t socket_slots;

    /** The operation records and the lists they wait on. */
    operations_t operations;

    /** The releases sends name and the notifications still due. */
    zero_copy_t zero_copy;

    /** Receives with a deadline, which @c maintain expires. */
    operation_list_t timed_operations;

    /** The first slot whose stream re-arms at the next @c maintain, linked through @c next. */
    unsigned rearming_socket_slots {absent_k};

    /** The first slot whose slice waits a poll round for a receive, linked by @c next_waiting. */
    unsigned waiting_socket_slots {absent_k};

    /** Sockets whose stream is submitted or cancelling, which the kernel still holds. */
    unsigned receiving_socket_slots {};

    /** At most every timed deadline while @c timed_operations is not empty. */
    std::uint64_t earliest_timed {};

    /** Why @c open answered @c ucall_status_unsupported_k, naming the setting to raise. */
    char const* refusal {};

    explicit linux_uring618_queue(allocator_t const& instance = {}) noexcept
        : state(instance, statistics), socket_slots(instance), operations(instance), zero_copy(statistics) {}
    linux_uring618_queue(linux_uring618_queue const&) = delete;
    linux_uring618_queue& operator=(linux_uring618_queue const&) = delete;
    linux_uring618_queue(linux_uring618_queue&&) = delete;
    linux_uring618_queue& operator=(linux_uring618_queue&&) = delete;
    ~linux_uring618_queue() noexcept { stop(); }

    bool is_open() const noexcept { return state.is_open(); }
    bool has_kernel_work() const noexcept {
        return !state.control.result || operations.outstanding_operations || zero_copy.outstanding_notifications ||
               socket_slots.closing() || receiving_socket_slots != 0;
    }

    ucall_status_t open(std::size_t depth, std::size_t capacity,
                        io_issuer_scope_t scope = io_issuer_scope_t::one_thread_k) noexcept {
        if (!depth || !capacity) return ucall_status_invalid_argument_k;
        if (capacity > static_cast<std::size_t>(registered_socket_t::tag_k)) return ucall_status_overflow_k;
        if (state.stage != uring_queue_stage_t::idle_k) return ucall_status_invalid_argument_k;
        // Releases take no file, and the kernel registers no more files than descriptors.
        std::size_t const sockets = uring_socket_capacity(capacity);
        if (ucall_status_t const reserved = state.reserve(capacity); reserved != ucall_status_success_k)
            return reserved;
        if (operations.open(capacity) != ucall_status_success_k ||
            socket_slots.open(sockets, state.allocator) != ucall_status_success_k)
            return ucall_status_out_of_memory_k;
        ucall_status_t const opened = state.open(depth, sockets, opcodes_k, scope);
        if (opened == ucall_status_success_k) return opened;
        // Only ring setup fails before the ring opens.
        if (state.is_open()) stop();
        else refusal = uring_setup_refusal_k;
        return opened;
    }
    void rearm(socket_slot_t& owner) noexcept {
        if (owner.rearm_listing == listing_t::listed_k) return;
        owner.rearm_listing = listing_t::listed_k;
        owner.next = rearming_socket_slots;
        rearming_socket_slots = owner.index;
    }
    int wait_control() noexcept { return uring_wait_control(*this); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept {
        return socket_slots.import_socket(descriptor, state);
    }
    descriptor_t open_socket(int family) noexcept { return uring_open_socket(*this, family); }

    /** Releases what @p completion named: a slice of the pool, or a socket's backlog past it. */
    void release(io_completion_t const& completion) noexcept {
        if (!state.is_open() || !completion.release_token) return;
        std::size_t const pool = state.provided.memory.size();
        if (completion.release_token <= pool)
            return state.provided.release_slice({completion.data, static_cast<std::size_t>(completion.result)});
        socket_slot_t& owner = socket_slots.records[completion.release_token - pool - 1];
        if (owner.backlog_slice_state != receive_slice_state_t::awaiting_release_k) return;
        if (owner.delivered_shares) {
            --owner.delivered_shares;
            return;
        }
        owner.backlog_slice_state = receive_slice_state_t::released_k;
        owner.delivered.clear();
        owner.delivered_offset = 0;
        if (owner.receive_flow == receive_flow_t::paused_k) park_receive(owner);
        if (uring_serves(owner.stage)) deliver_receive(owner);
        else retire(owner);
    }

    /** Whether the bytes @p completion names may be kept past their round: a pool slice while the
     *  pool spares a buffer for the kernel, or a delivered backlog, which arrivals never move. */
    bool retains(io_completion_t const& completion) const noexcept {
        return completion.release_token &&
               (completion.release_token > state.provided.memory.size() || state.provided.spares_a_buffer());
    }

    /** Counts one more holder of the bytes @p completion names, each releasing its own part. */
    void share(io_completion_t const& completion) noexcept {
        std::size_t const pool = state.provided.memory.size();
        if (completion.release_token <= pool)
            return state.provided.share_slice({completion.data, static_cast<std::size_t>(completion.result)});
        ++socket_slots.records[completion.release_token - pool - 1].delivered_shares;
    }

    /** Extends @p completion, a pool slice the reader of @p descriptor keeps, by the bytes that
     *  landed right behind it in its buffer and wait for a receive, so the reader takes them in the
     *  same view rather than a round later. */
    void extend(descriptor_t descriptor, io_completion_t& completion) noexcept {
        if (!completion.release_token || completion.release_token > state.provided.memory.size()) return;
        auto* owner = socket_slots.find(descriptor);
        if (!owner || owner->backlog_offset != owner->backlog.size() ||
            !state.provided.adjoins({completion.data, static_cast<std::size_t>(completion.result)},
                                    owner->waiting_slice))
            return;
        completion.result += static_cast<decltype(completion.result)>(owner->waiting_slice.size());
        state.provided.release_slice(std::exchange(owner->waiting_slice, {}));
    }

    /** Slides what a paused socket still holds to the front of its backlog, unless a completion
     *  still names it. */
    void park_receive(socket_slot_t& owner) noexcept {
        if (owner.backlog_slice_state == receive_slice_state_t::awaiting_release_k || !owner.backlog_offset) return;
        auto remaining = owner.backlog.size() - owner.backlog_offset;
        if (remaining) std::memmove(owner.backlog.data(), owner.backlog.data() + owner.backlog_offset, remaining);
        tally<atomic_ref_template_>(statistics.bytes_copied, remaining);
        [[maybe_unused]] st::status_t const shrunk = owner.backlog.resize(remaining);
        owner.backlog_offset = 0;
    }

    /** Pauses the reader of @p descriptor, whose peer still owes it @p rest bytes: what arrives
     *  waits in the paused socket's slice or backlog, and a rest one buffer carries keeps the
     *  stream armed, as re-arming it costs a round trip, while a longer one ends it until the next
     *  receive. A backlog past the socket's fair share ends it either way. */
    void receive_pause(descriptor_t descriptor, std::size_t rest = (std::numeric_limits<std::size_t>::max)()) noexcept {
        auto* owner = socket_slots.find(descriptor);
        if (!owner || !uring_serves(owner->stage) || owner->receive_operation != absent_k) return;
        owner->receive_flow = receive_flow_t::paused_k;
        if (!keeps_paused(*owner)) spill_slice(*owner);
        park_receive(*owner);
        if (owner->receive_stage == receive_stage_t::submitted_k && rest >= state.provided.buffer_bytes()) {
            if (cancel_stream(*owner) != ucall_status_success_k) state.fault = -EIO;
            else owner->receive_stage = receive_stage_t::cancelling_k;
        }
    }

    /** Copies @p slice to the end of @p owner's backlog and gives the pool its bytes back,
     *  cancelling the stream of a socket past its fair share of the pool. */
    void append_backlog(socket_slot_t& owner, span<byte_t> slice) noexcept {
        uring_provided_buffers<allocator_t>& provided = state.provided;
        std::size_t const previous = owner.backlog.size();
        if (st::failed(owner.backlog.resize(st::assume_uninitialized, previous + slice.size()))) state.fault = -ENOMEM;
        else std::memcpy(owner.backlog.data() + previous, slice.data(), slice.size());
        tally<atomic_ref_template_>(statistics.bytes_copied, slice.size());
        provided.release_slice(slice);
        assert(socket_slots.records.size() > socket_slots.vacant_socket_slots);
        std::size_t const share = fu::min_of(
            provided.buffer_bytes(),
            provided.memory.size() / (socket_slots.records.size() - socket_slots.vacant_socket_slots));
        if (owner.backlog.size() - owner.backlog_offset >= share &&
            owner.receive_stage == receive_stage_t::submitted_k) {
            if (cancel_stream(owner) != ucall_status_success_k) state.fault = -EIO;
            else owner.receive_stage = receive_stage_t::cancelling_k;
        }
    }

    /** Whether @p owner paused with a waiting slice worth keeping uncopied: one of a page or more,
     *  where keeping beats copying as for sends, while the pool spares a buffer for the kernel. */
    bool keeps_paused(socket_slot_t const& owner) const noexcept {
        return owner.receive_flow == receive_flow_t::paused_k && !owner.waiting_slice.empty() &&
               owner.waiting_slice.size() >= state.page_bytes && state.provided.spares_a_buffer();
    }
    void spill_slice(socket_slot_t& owner) noexcept {
        if (!owner.waiting_slice.empty()) append_backlog(owner, std::exchange(owner.waiting_slice, {}));
    }

    /** Ends a poll round for the slices waiting on their receives: one whose socket paused, as its
     *  reader pulls at its own pace, stays uncopied while the pool spares a buffer for the kernel;
     *  the others move to their backlogs, so no waiting slice starves the pool. */
    void spill_waiting_slices() noexcept {
        unsigned waiting = std::exchange(waiting_socket_slots, absent_k);
        while (waiting != absent_k) {
            socket_slot_t& owner = socket_slots.records[waiting];
            waiting = std::exchange(owner.next_waiting, absent_k);
            if (keeps_paused(owner)) {
                owner.next_waiting = std::exchange(waiting_socket_slots, owner.index);
                continue;
            }
            owner.waiting_listing = listing_t::unlisted_k;
            spill_slice(owner);
        }
    }

    /** Hands @p slice straight to the receive waiting on @p owner. */
    void deliver_slice(socket_slot_t& owner, span<byte_t> slice) noexcept {
        operation_t& operation = operations[std::exchange(owner.receive_operation, absent_k)];
        operation.buffer = static_cast<unsigned>(state.provided.offset_of(slice));
        operation.result = static_cast<descriptor_t>(slice.size());
        unlist_timed(operation);
        operations.complete(operation);
    }
    void deliver_receive(socket_slot_t& owner) noexcept {
        if (owner.receive_operation == absent_k) return;
        if (!owner.waiting_slice.empty()) return deliver_slice(owner, std::exchange(owner.waiting_slice, {}));
        auto& operation = operations[owner.receive_operation];
        if (owner.backlog_offset != owner.backlog.size()) {
            if (owner.backlog_slice_state == receive_slice_state_t::awaiting_release_k) return;
            // The backlog moves apart whole, so bytes arriving behind it never move what it named.
            std::swap(owner.delivered, owner.backlog);
            owner.delivered_offset = std::exchange(owner.backlog_offset, 0);
            assert(owner.delivered.size() - owner.delivered_offset <=
                       static_cast<std::size_t>((std::numeric_limits<descriptor_t>::max)()) &&
                   "a backlog stays within a fair share of the pool");
            operation.receive_source = uring_receive_source_t::backlog_k;
            operation.result = static_cast<descriptor_t>(owner.delivered.size() - owner.delivered_offset);
            owner.backlog_slice_state = receive_slice_state_t::awaiting_release_k;
        }
        else if (owner.receive_stage == receive_stage_t::ended_k) operation.result = owner.terminal;
        else return;
        owner.receive_operation = absent_k;
        unlist_timed(operation);
        operations.complete(operation);
    }
    void unlist_timed(operation_t& operation) noexcept {
        if (operation.timed_listing == listing_t::unlisted_k) return;
        operations.unlink(timed_operations, operation);
        operation.timed_listing = listing_t::unlisted_k;
    }

    /** Arms the stream of @p owner where it needs one, or starts the receive in place it waits
     *  for, failing only once the ring refuses an entry, which @c maintain then offers again. */
    ucall_status_t start_receive(socket_slot_t& owner) noexcept {
        if (owner.receive_flow == receive_flow_t::in_place_k) return start_in_place(owner);
        if (owner.receive_stage != receive_stage_t::idle_k || owner.receive_flow != receive_flow_t::flowing_k ||
            !uring_serves(owner.stage) || state.stage != uring_queue_stage_t::running_k ||
            !state.provided.available_buffers)
            return ucall_status_success_k;
        auto* submission = state.entry();
        if (!submission) return ucall_status_io_k;
        io_uring_prep_recv_multishot(submission, static_cast<int>(owner.index), nullptr, 0, 0);
        submission->flags |= IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
        submission->buf_group = 0;
        io_uring_sqe_set_data64(submission, state.tag(&owner, uring_receive_tag_k));
        owner.receive_stage = receive_stage_t::submitted_k;
        ++receiving_socket_slots;
        if (owner.stream_start == stream_start_t::rearm_k) tally<atomic_ref_template_>(statistics.receive_rearms);
        owner.stream_start = stream_start_t::rearm_k;
        return ucall_status_success_k;
    }

    /** Hands the receive @p owner waits on to the kernel to fill the room it names, once the
     *  stream that would race it ended and the queue holds none of the socket's bytes, which
     *  @c deliver_receive answers first; an armed stream is cancelled, and its last completion
     *  offers this again. */
    ucall_status_t start_in_place(socket_slot_t& owner) noexcept {
        if (owner.receive_operation == absent_k || !uring_serves(owner.stage) ||
            state.stage != uring_queue_stage_t::running_k || owner.backlog_offset != owner.backlog.size())
            return ucall_status_success_k;
        if (owner.receive_stage == receive_stage_t::submitted_k) {
            if (ucall_status_t const cancelled = cancel_stream(owner); cancelled != ucall_status_success_k)
                return cancelled;
            owner.receive_stage = receive_stage_t::cancelling_k;
        }
        if (owner.receive_stage != receive_stage_t::idle_k) return ucall_status_success_k;
        operation_t& operation = operations[owner.receive_operation];
        auto* submission = operations.entry(operation, state);
        if (!submission) return ucall_status_io_k;
        owner.receive_operation = absent_k;
        unlist_timed(operation);
        uring_prepare(submission, operation, state, operations, zero_copy);
        operations.submit(submission, operation, state);
        return ucall_status_success_k;
    }
    ucall_status_t cancel_stream(socket_slot_t& owner) noexcept {
        auto* submission = state.entry();
        if (!submission) return ucall_status_io_k;
        io_uring_prep_cancel64(submission, state.tag(&owner, uring_receive_tag_k), 0);
        io_uring_sqe_set_data64(submission, uring_cancel_tag_k);
        tally<atomic_ref_template_>(statistics.cancellations);
        return ucall_status_success_k;
    }

    memory_registration_t register_memory(span<byte_t> memory) noexcept { return state.register_memory(memory); }
    void submit(io_request_t& request) noexcept {
        tally<atomic_ref_template_>(statistics.submissions);
        if (request.operation == io_operation_t::zero_copy_release_k) {
            if (!zero_copy.submit_release(request, operations, socket_slots)) state.fault = -ENOBUFS;
            return;
        }
        auto* operation = uring_take(*this, request);
        if (!operation) return;
        if (request.operation != io_operation_t::receive_k) return start_operation(*operation);
        auto& owner = *operation->socket_slot;
        bool const in_place = io_receive_names_room(request);
        owner.receive_flow = in_place ? receive_flow_t::in_place_k : receive_flow_t::flowing_k;
        owner.receive_operation = operations.index_of(*operation);
        deliver_receive(owner);
        if (operation->stage == uring_operation_stage_t::completed_k) return;
        // A stream's last completion offers a receive in place again, as `maintain` does.
        if (start_receive(owner) != ucall_status_success_k || (!in_place && !owner.receive_in_flight())) rearm(owner);
        if (request.deadline && owner.receive_operation == operations.index_of(*operation)) {
            if (timed_operations.empty() || request.deadline < earliest_timed) earliest_timed = request.deadline;
            operation->timed_listing = listing_t::listed_k;
            operations.push(timed_operations, *operation);
        }
    }

    /** Starts @p operation, which waits for the next poll while the ring refuses an entry. */
    void start_operation(operation_t& operation) noexcept {
        auto& request = *operation.request;
        if (request.operation == io_operation_t::accept_k)
            return operations.arm_accepts(operation, state, socket_slots);
        auto* submission = operations.entry(operation, state);
        if (!submission) return operations.push(operations.waiting_operations, operation);
        if (request.operation == io_operation_t::file_read_vectors_k) {
            if (request.registered_memory != io_unregistered_k)
                io_uring_prep_readv_fixed(submission, request.file.handle, io_vectors(request).data(),
                                          static_cast<unsigned>(request.length), request.file.offset, 0,
                                          static_cast<int>(request.registered_memory));
            else
                io_uring_prep_readv(submission, request.file.handle, io_vectors(request).data(),
                                    static_cast<unsigned>(request.length), request.file.offset);
            tally<atomic_ref_template_>(statistics.file_reads_asynchronous);
        }
        else uring_prepare(submission, operation, state, operations, zero_copy);
        operations.submit(submission, operation, state);
    }

    /** Marks the close of @p descriptor to send a reset rather than a FIN, without a round trip. */
    [[nodiscard]] ucall_status_t reset_on_close(descriptor_t descriptor) noexcept {
        return uring_reset_on_close(*this, descriptor);
    }
    void copy_sends(descriptor_t descriptor) noexcept { uring_copy_sends(*this, descriptor); }
    ucall_status_t cancel(io_request_t& request) noexcept { return uring_cancel(*this, request); }
    ucall_status_t cancel(operation_t& operation) noexcept {
        if (operation.answered() || operation.stage == uring_operation_stage_t::cancelling_k)
            return ucall_status_success_k;
        tally<atomic_ref_template_>(statistics.cancellations);
        if (operations.carrying(*operation.request) == &operation &&
            operation.request->operation == io_operation_t::accept_k)
            return operations.end_accepts(operation, state);
        if (operation.in_flight()) return operations.cancel_in_flight(operation, state);
        auto& owner = *operation.socket_slot;
        if (owner.receive_operation != operations.index_of(operation))
            operations.unlink(operations.waiting_operations, operation);
        else {
            owner.receive_operation = absent_k;
            unlist_timed(operation);
        }
        operation.result = -ECANCELED;
        operations.complete(operation);
        if (operation.request->operation == io_operation_t::receive_k) receive_pause(operation.request->descriptor);
        return ucall_status_success_k;
    }
    void retire(socket_slot_t& owner) noexcept {
        if (state.stage == uring_queue_stage_t::recovering_k) return;
        if (uring_serves(owner.stage)) {
            uring_abandon(*this, owner);
            if (owner.receive_stage == receive_stage_t::submitted_k) {
                if (cancel_stream(owner) != ucall_status_success_k) state.fault = -EIO;
                else owner.receive_stage = receive_stage_t::cancelling_k;
            }
        }
        if (owner.stage == uring_socket_stage_t::abandoned_k || owner.receive_in_flight() ||
            owner.stage == uring_socket_stage_t::closing_k || operations.owns_in_flight(owner))
            return;
        if (owner.stage != uring_socket_stage_t::closed_k) socket_slots.submit_close(owner, state);
        else if (owner.backlog_slice_state == receive_slice_state_t::released_k) finish_close(owner);
    }
    int close_socket(descriptor_t descriptor) noexcept { return uring_close_socket(*this, descriptor); }
    void finish_close(socket_slot_t& owner) noexcept {
        // A socket can close before maintain() drains the re-arm list that shares its link.
        if (owner.rearm_listing == listing_t::listed_k)
            for (auto* link = &rearming_socket_slots; *link != absent_k; link = &socket_slots.records[*link].next)
                if (*link == owner.index) {
                    *link = owner.next;
                    break;
                }
        owner.receive_operation = absent_k;
        if (!owner.waiting_slice.empty()) state.provided.release_slice(std::exchange(owner.waiting_slice, {}));
        owner.backlog.clear();
        if (owner.backlog.capacity() > state.page_bytes) owner.backlog = vector<byte_t> {state.allocator};
        owner.backlog_offset = 0;
        owner.delivered.clear();
        if (owner.delivered.capacity() > state.page_bytes) owner.delivered = vector<byte_t> {state.allocator};
        owner.delivered_offset = 0;
        owner.delivered_shares = 0;
        owner.terminal = 0;
        owner.receive_stage = receive_stage_t::idle_k;
        owner.receive_flow = receive_flow_t::flowing_k;
        owner.stream_start = stream_start_t::first_k;
        owner.rearm_listing = listing_t::unlisted_k;
        operations.finish_close(owner, socket_slots);
    }
    void completion(io_uring_cqe const& completion) noexcept {
        auto kind = static_cast<std::uintptr_t>(completion.user_data) & 7;
        auto* pointer = reinterpret_cast<void*>(static_cast<std::uintptr_t>(completion.user_data) &
                                                ~std::uintptr_t {7});
        if (kind == uring_cancel_tag_k) return;
        if (kind == uring_control_tag_k) {
            state.control.result = completion.res;
            return;
        }
        if (kind == uring_close_tag_k) {
            if (auto* closed = socket_slots.settle_close(*static_cast<socket_slot_t*>(pointer), completion.res, state))
                retire(*closed);
            return;
        }
        if (kind == uring_receive_tag_k) {
            settle_receive(*static_cast<socket_slot_t*>(pointer), completion);
            return;
        }
        if (kind == uring_release_tag_k) {
            auto* settled = zero_copy.settle(*static_cast<operation_t*>(pointer), completion, operations, socket_slots);
            if (settled && !uring_serves(settled->stage)) retire(*settled);
            return;
        }
        auto& operation = *static_cast<operation_t*>(pointer);
        if (auto* accepted = operations.settle(operation, completion, state, socket_slots)) retire(*accepted);
        if (!uring_serves(operation.socket_slot->stage)) retire(*operation.socket_slot);
    }
    void settle_receive(socket_slot_t& owner, io_uring_cqe const& completion) noexcept {
        if (!(completion.flags & IORING_CQE_F_MORE)) {
            if (owner.receive_in_flight()) --receiving_socket_slots;
            owner.receive_stage = receive_stage_t::idle_k;
        }
        uring_provided_buffers<allocator_t>& provided = state.provided;
        if (completion.res > 0 && (completion.flags & IORING_CQE_F_BUFFER)) {
            span<byte_t> const slice = provided.take_received_slice(completion.flags >> IORING_CQE_BUFFER_SHIFT,
                                                                    static_cast<std::size_t>(completion.res));
            if (!uring_serves(owner.stage) || state.stage != uring_queue_stage_t::running_k)
                provided.release_slice(slice);
            else if (owner.receive_operation != absent_k && owner.backlog_offset == owner.backlog.size())
                deliver_slice(owner, slice);
            else if (owner.waiting_slice.empty() && owner.backlog_offset == owner.backlog.size() &&
                     (owner.receive_flow == receive_flow_t::flowing_k ||
                      (owner.receive_flow == receive_flow_t::paused_k && provided.spares_a_buffer()))) {
                // The next bytes often land before their receive, so they wait uncopied a while.
                owner.waiting_slice = slice;
                if (owner.waiting_listing == listing_t::unlisted_k) {
                    owner.waiting_listing = listing_t::listed_k;
                    owner.next_waiting = std::exchange(waiting_socket_slots, owner.index);
                }
            }
            // Bytes continuing the waiting slice in its buffer join it, still uncopied.
            else if (owner.backlog_offset == owner.backlog.size() && provided.adjoins(owner.waiting_slice, slice)) {
                owner.waiting_slice = {owner.waiting_slice.data(), owner.waiting_slice.size() + slice.size()};
                provided.release_slice(slice);
            }
            else {
                spill_slice(owner);
                append_backlog(owner, slice);
            }
        }
        else if (completion.res != -ENOBUFS && completion.res != -ECANCELED) {
            if (owner.receive_in_flight()) --receiving_socket_slots;
            owner.receive_stage = receive_stage_t::ended_k;
            owner.terminal = completion.res;
            deliver_receive(owner);
        }
        if (!uring_serves(owner.stage)) retire(owner);
        else if (owner.receive_stage == receive_stage_t::idle_k) rearm(owner);
    }
    void reap() noexcept { uring_reap(*this); }
    int collect(span<io_completion_t> output) noexcept {
        std::size_t count {};
        while (count != output.size()) {
            auto* operation = operations.pop(operations.completed_operations);
            if (!operation) break;
            io_completion_t completed = operations.completion_of(*operation, state, socket_slots);
            if (operation->receive_source == uring_receive_source_t::backlog_k) {
                auto& owner = *operation->socket_slot;
                completed.data = owner.delivered.data() + owner.delivered_offset;
                completed.release_token = static_cast<std::uint32_t>(state.provided.memory.size() + 1 + owner.index);
            }
            output[count++] = completed;
            operations.vacate(*operation);
        }
        tally<atomic_ref_template_>(statistics.completions, count);
        return static_cast<int>(count);
    }
    void maintain() noexcept {
        if (state.fault) return;
        if (!timed_operations.empty() && monotonic_ns() >= earliest_timed) {
            auto now = monotonic_ns();
            earliest_timed = 0;
            for (auto index = timed_operations.oldest; index != absent_k;) {
                auto& operation = operations[index];
                index = operation.next;
                std::uint64_t const expiry = operation.request->deadline;
                if (expiry > now) {
                    earliest_timed = earliest_timed ? fu::min_of(earliest_timed, expiry) : expiry;
                    continue;
                }
                operation.expiry = uring_expiry_t::expired_k;
                [[maybe_unused]] ucall_status_t const cancelled = cancel(operation);
            }
        }
        for (auto retry = std::exchange(operations.waiting_operations, {}); auto* operation = operations.pop(retry);)
            start_operation(*operation);
        for (auto index = std::exchange(rearming_socket_slots, absent_k); index != absent_k;) {
            auto& owner = socket_slots.records[index];
            index = owner.next;
            owner.rearm_listing = listing_t::unlisted_k;
            if (owner.receive_operation == absent_k || owner.receive_in_flight()) continue;
            if (start_receive(owner) != ucall_status_success_k ||
                (owner.receive_flow == receive_flow_t::flowing_k && !state.provided.available_buffers))
                rearm(owner);
        }
    }
    int poll(span<io_completion_t> output, io_wait_t policy, std::uint64_t deadline = 0) noexcept {
        if (!state.is_open()) return -EBADF;
        for (;;) {
            spill_waiting_slices();
            reap();
            maintain();
            if (state.fault) return state.fault;
            int count = collect(output);
            if (count) return count;
            spill_waiting_slices();
            auto now = monotonic_ns();
            auto wait_deadline = deadline;
            if (!timed_operations.empty())
                wait_deadline = !wait_deadline ? earliest_timed : fu::min_of(wait_deadline, earliest_timed);
            unsigned wait = policy == io_wait_t::blocking_k && (!wait_deadline || now < wait_deadline) ? 1 : 0;
            int result = state.enter(wait, wait_deadline);
            // A kernel short of request memory took nothing; the submissions wait in the ring.
            if (result < 0 && result != -EAGAIN) return result;
            reap();
            maintain();
            count = collect(output);
            if (count || result < 0 || policy == io_wait_t::nonblocking_k || (deadline && monotonic_ns() >= deadline))
                return count;
        }
    }
    void discard(std::uint64_t user_data) noexcept {
        if ((static_cast<std::uintptr_t>(user_data) & 7) != uring_receive_tag_k)
            return uring_discard(user_data, state, operations, socket_slots, zero_copy);
        auto& owner = *reinterpret_cast<socket_slot_t*>(static_cast<std::uintptr_t>(user_data) & ~std::uintptr_t {7});
        if (owner.receive_in_flight()) {
            owner.receive_stage = receive_stage_t::idle_k;
            --receiving_socket_slots;
        }
    }
    void discard_unsubmitted() noexcept { uring_discard_unsubmitted(*this); }
    [[nodiscard]] ucall_status_t drain_after_fault() noexcept { return uring_drain_after_fault(*this); }
    void reserve_releases(std::size_t count) noexcept { operations.reserve_releases(count); }
    [[nodiscard]] ucall_status_t grow(std::size_t capacity) noexcept {
        return uring_grow(*this, capacity, state.allocator);
    }
    void stop() noexcept { uring_stop(*this); }
};

using linux_uring618_queue_t = linux_uring618_queue<>;

} // namespace unum::ucall::io
