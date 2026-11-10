/**
 *  @file include/ucall/io/linux_uring618_engine.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Registered sockets and multishot receive streams for Linux 6.18 io_uring.
 */
#pragma once

#include <smashtable/basic_vector.hpp> // `vector`
#include <smashtable/row_search.hpp>   // `serial_row_kit_t`

#include "ucall/io/linux_uring612_engine.hpp" // `uring_operation`, `registered_socket_t`
#include "ucall/io/types.hpp"          // `operation_list_t`, `zero_copy_stage_t`, `io_statistics_t`, `io_completion_t`
#include "ucall/utilities/sockets.hpp" // `open_files_limit`, `monotonic_ns`
#include "ucall/utilities/types.hpp"   // `byte_t`, `descriptor_t`, `span`

namespace unum::ucall::io {

using utilities::byte_t;
using utilities::descriptor_t;
using utilities::monotonic_ns;
using utilities::open_files_limit;
using utilities::span;

/** One-shot requests and multishot streams share the same registered socket slot lifetimes. */
template <typename allocator_type_ = st::default_allocator<byte_t>,
          template <typename> class atomic_ref_template_ = fu::standard_atomic_ref,
          typename row_kit_type_ = st::serial_row_kit_t>
struct linux_uring618_engine {
    using allocator_t = allocator_type_;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    template <typename value_type_>
    using vector = st::vector<value_type_, rebound_allocator<value_type_>>;
    template <typename other_allocator_type_, template <typename> class other_atomic_ref_, typename other_row_kit_>
    using rebind = linux_uring618_engine<other_allocator_type_, other_atomic_ref_, other_row_kit_>;
    static constexpr unsigned absent_k = operation_list_t::absent_k;

    enum class receive_stage_t : std::uint8_t { idle_k, submitted_k, cancelling_k, ended_k };

    /** Whether the socket's stream may prefetch, or stays cancelled while nobody pulls bytes. */
    enum class receive_flow_t : std::uint8_t { flowing_k, paused_k };

    /** Whether the socket's next stream is its first, or a re-arm the statistics count. */
    enum class stream_start_t : std::uint8_t { first_k, rearm_k };
    struct alignas(8) socket_slot_t {
        unsigned index {}, next {operation_list_t::absent_k}, owned_head {operation_list_t::absent_k};
        unsigned close_operation {operation_list_t::absent_k}, receive_operation {operation_list_t::absent_k};
        std::uint64_t serial {};
        vector<byte_t> backlog;
        std::size_t backlog_offset {};
        descriptor_t terminal {};
        uring_socket_stage_t stage {uring_socket_stage_t::vacant_k};
        zero_copy_stage_t zero_copy {zero_copy_stage_t::untried_k};
        uring_retirement_t retirement {uring_retirement_t::serving_k};
        close_mode_t close {close_mode_t::orderly_k};
        receive_stage_t receive_stage {receive_stage_t::idle_k};
        receive_flow_t receive_flow {receive_flow_t::flowing_k};
        stream_start_t stream_start {stream_start_t::first_k};
        uring_lease_t backlog_lease {uring_lease_t::returned_k};
        listing_t rearm_listing {listing_t::unlisted_k};
        listing_t waiting_listing {listing_t::unlisted_k};

        /** One slice waiting a poll round for a receive, implying an empty backlog. */
        span<byte_t> waiting_slice {};
        unsigned next_waiting {operation_list_t::absent_k};
        explicit socket_slot_t(allocator_t const& allocator) noexcept : backlog(allocator) {}
        bool receive_in_flight() const noexcept {
            return receive_stage == receive_stage_t::submitted_k || receive_stage == receive_stage_t::cancelling_k;
        }
    };
    using queue_t = uring_queue<allocator_t, atomic_ref_template_>;
    using socket_slots_t = uring_socket_slots<socket_slot_t, allocator_t>;
    using operations_t = uring_operations<socket_slot_t, allocator_t>;
    using zero_copy_t = uring_zero_copy<socket_slot_t, allocator_t, atomic_ref_template_>;
    using operation_t = typename operations_t::operation_t;
    static_assert(sizeof(operation_t) == 64);
    static constexpr io_uring_op opcodes_k[] {
        IORING_OP_SOCKET,       IORING_OP_ACCEPT,       IORING_OP_CONNECT,   IORING_OP_RECV,
        IORING_OP_SEND,         IORING_OP_READ,         IORING_OP_SHUTDOWN,  IORING_OP_CLOSE,
        IORING_OP_ASYNC_CANCEL, IORING_OP_LINK_TIMEOUT, IORING_OP_URING_CMD, IORING_OP_OPENAT2,
        IORING_OP_SEND_ZC,      IORING_OP_READ_FIXED,   IORING_OP_READV,     IORING_OP_READV_FIXED};
    static constexpr ucall_io_backend_t backend_k = ucall_io_backend_linux_uring618_k;
    static constexpr io_receive_memory_t receive_memory_k = io_receive_memory_t::engine_k;

    io_statistics_t statistics {};
    queue_t queue;
    socket_slots_t socket_slots;
    operations_t operations;
    zero_copy_t zero_copy;

    /** Receives with a deadline, and the sockets whose stream re-arms as receive credits allow. */
    operation_list_t timed_operations;
    unsigned rearming_socket_slots {absent_k};
    unsigned waiting_socket_slots {absent_k};

    /** Sockets whose stream is submitted or cancelling, which the kernel still holds. */
    unsigned receiving_socket_slots {};

    /** At most every timed deadline while @c timed_operations is not empty. */
    std::uint64_t earliest_timed {};

    /** Why @c open answered @c ucall_status_unsupported_k, naming the setting to raise. */
    char const* refusal {};

    explicit linux_uring618_engine(allocator_t const& instance = {}) noexcept
        : queue(instance, statistics), socket_slots(instance), operations(instance), zero_copy(statistics) {}
    linux_uring618_engine(linux_uring618_engine const&) = delete;
    linux_uring618_engine& operator=(linux_uring618_engine const&) = delete;
    linux_uring618_engine(linux_uring618_engine&&) = delete;
    linux_uring618_engine& operator=(linux_uring618_engine&&) = delete;
    ~linux_uring618_engine() noexcept { stop(); }

    bool is_open() const noexcept { return queue.is_open(); }
    bool has_kernel_work() const noexcept {
        return !queue.control.result || operations.outstanding_operations || zero_copy.outstanding_notifications ||
               socket_slots.closing() || receiving_socket_slots != 0;
    }

    ucall_status_t open(std::size_t depth, std::size_t capacity,
                        io_issuer_scope_t scope = io_issuer_scope_t::one_thread_k) noexcept {
        if (!depth || !capacity) return ucall_status_invalid_argument_k;
        if (capacity > static_cast<std::size_t>(registered_socket_t::tag_k)) return ucall_status_overflow_k;
        if (queue.stage != uring_engine_stage_t::idle_k) return ucall_status_invalid_argument_k;
        // Releases take no file, and the kernel registers no more files than descriptors.
        std::size_t const sockets = fu::min_of(capacity, open_files_limit() - 1);
        if (ucall_status_t const reserved = queue.reserve(capacity); reserved != ucall_status_success_k)
            return reserved;
        if (operations.open(capacity) != ucall_status_success_k ||
            socket_slots.open(sockets, queue.allocator) != ucall_status_success_k)
            return ucall_status_out_of_memory_k;
        ucall_status_t const opened = queue.open(depth, sockets, opcodes_k, scope);
        if (opened == ucall_status_success_k) return opened;
        // Only ring setup fails before the ring opens.
        if (queue.is_open()) stop();
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
        return socket_slots.import_socket(descriptor, queue);
    }
    descriptor_t open_socket(int family) noexcept { return uring_open_socket(*this, family); }

    /** Takes back what @p completion lent: a slice of the pool, or a socket's backlog past it. */
    void release(io_completion_t const& completion) noexcept {
        if (!queue.is_open() || !completion.lease) return;
        std::size_t const pool = queue.provided.memory.size();
        if (completion.lease <= pool)
            return queue.provided.return_slice({completion.data, static_cast<std::size_t>(completion.result)});
        socket_slot_t& owner = socket_slots.records[completion.lease - pool - 1];
        if (owner.backlog_lease != uring_lease_t::leased_k) return;
        owner.backlog_lease = uring_lease_t::returned_k;
        owner.backlog_offset += static_cast<std::size_t>(completion.result);
        if (owner.backlog_offset == owner.backlog.size()) {
            owner.backlog.clear();
            owner.backlog_offset = 0;
        }
        if (owner.receive_flow == receive_flow_t::paused_k) park_receive(owner);
        if (owner.retirement == uring_retirement_t::serving_k) deliver_receive(owner);
        else retire(owner);
    }

    /** Slides what a paused socket still holds to the front of its backlog, unless it is lent. */
    void park_receive(socket_slot_t& owner) noexcept {
        if (owner.backlog_lease == uring_lease_t::leased_k || !owner.backlog_offset) return;
        auto remaining = owner.backlog.size() - owner.backlog_offset;
        if (remaining) std::memmove(owner.backlog.data(), owner.backlog.data() + owner.backlog_offset, remaining);
        tally<atomic_ref_template_>(statistics.bytes_copied, remaining);
        [[maybe_unused]] st::status_t const shrunk = owner.backlog.resize(remaining);
        owner.backlog_offset = 0;
    }
    void receive_pause(descriptor_t descriptor) noexcept {
        auto* owner = socket_slots.find(descriptor);
        if (!owner || owner->retirement == uring_retirement_t::retiring_k || owner->receive_operation != absent_k)
            return;
        owner->receive_flow = receive_flow_t::paused_k;
        spill_slice(*owner);
        park_receive(*owner);
        if (owner->receive_stage == receive_stage_t::submitted_k) {
            if (cancel_stream(*owner) != ucall_status_success_k) queue.fault = -EIO;
            else owner->receive_stage = receive_stage_t::cancelling_k;
        }
    }

    /** Copies @p slice to the end of @p owner's backlog and gives the pool its bytes back,
     *  cancelling the stream of a socket past its fair share of the pool. */
    void append_backlog(socket_slot_t& owner, span<byte_t> slice) noexcept {
        uring_provided_buffers<allocator_t>& provided = queue.provided;
        std::size_t const previous = owner.backlog.size();
        if (st::failed(owner.backlog.resize(st::assume_uninitialized, previous + slice.size()))) queue.fault = -ENOMEM;
        else std::memcpy(owner.backlog.data() + previous, slice.data(), slice.size());
        tally<atomic_ref_template_>(statistics.bytes_copied, slice.size());
        provided.return_slice(slice);
        assert(socket_slots.records.size() > socket_slots.vacant_socket_slots);
        std::size_t const share = fu::min_of(
            provided.buffer_bytes,
            provided.memory.size() / (socket_slots.records.size() - socket_slots.vacant_socket_slots));
        if (owner.backlog.size() - owner.backlog_offset >= share &&
            owner.receive_stage == receive_stage_t::submitted_k) {
            if (cancel_stream(owner) != ucall_status_success_k) queue.fault = -EIO;
            else owner.receive_stage = receive_stage_t::cancelling_k;
        }
    }
    void spill_slice(socket_slot_t& owner) noexcept {
        if (!owner.waiting_slice.empty()) append_backlog(owner, std::exchange(owner.waiting_slice, {}));
    }

    /** Ends the round slices waited for their receives, so none pins a buffer past it. */
    void spill_waiting_slices() noexcept {
        while (waiting_socket_slots != absent_k) {
            socket_slot_t& owner = socket_slots.records[waiting_socket_slots];
            waiting_socket_slots = std::exchange(owner.next_waiting, absent_k);
            owner.waiting_listing = listing_t::unlisted_k;
            spill_slice(owner);
        }
    }

    /** Hands @p slice straight to the receive waiting on @p owner. */
    void deliver_slice(socket_slot_t& owner, span<byte_t> slice) noexcept {
        operation_t& operation = operations[std::exchange(owner.receive_operation, absent_k)];
        operation.buffer = static_cast<unsigned>(queue.provided.offset_of(slice));
        operation.result = static_cast<descriptor_t>(slice.size());
        unlist_timed(operation);
        operations.complete(operation);
    }
    void deliver_receive(socket_slot_t& owner) noexcept {
        if (owner.receive_operation == absent_k) return;
        if (!owner.waiting_slice.empty()) return deliver_slice(owner, std::exchange(owner.waiting_slice, {}));
        auto& operation = operations[owner.receive_operation];
        if (owner.backlog_offset != owner.backlog.size()) {
            if (owner.backlog_lease == uring_lease_t::leased_k) return;
            operation.receive_source = uring_receive_source_t::backlog_k;
            operation.result = static_cast<descriptor_t>(fu::min_of<std::size_t>(
                owner.backlog.size() - owner.backlog_offset, (std::numeric_limits<descriptor_t>::max)()));
            owner.backlog_lease = uring_lease_t::leased_k;
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
    ucall_status_t start_receive(socket_slot_t& owner) noexcept {
        if (owner.receive_stage != receive_stage_t::idle_k || owner.receive_flow == receive_flow_t::paused_k ||
            owner.retirement == uring_retirement_t::retiring_k || queue.stage != uring_engine_stage_t::running_k ||
            !queue.provided.available_buffers)
            return ucall_status_success_k;
        auto* submission = queue.entry();
        if (!submission) return ucall_status_io_k;
        io_uring_prep_recv_multishot(submission, static_cast<int>(owner.index), nullptr, 0, 0);
        submission->flags |= IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
        submission->buf_group = 0;
        io_uring_sqe_set_data64(submission, queue.tag(&owner, uring_receive_tag_k));
        owner.receive_stage = receive_stage_t::submitted_k;
        ++receiving_socket_slots;
        if (owner.stream_start == stream_start_t::rearm_k) tally<atomic_ref_template_>(statistics.receive_rearms);
        owner.stream_start = stream_start_t::rearm_k;
        return ucall_status_success_k;
    }
    ucall_status_t cancel_stream(socket_slot_t& owner) noexcept {
        auto* submission = queue.entry();
        if (!submission) return ucall_status_io_k;
        io_uring_prep_cancel64(submission, queue.tag(&owner, uring_receive_tag_k), 0);
        io_uring_sqe_set_data64(submission, uring_cancel_tag_k);
        tally<atomic_ref_template_>(statistics.cancellations);
        return ucall_status_success_k;
    }

    memory_registration_t register_memory(span<byte_t> memory) noexcept { return queue.register_memory(memory); }
    ucall_status_t submit(io_request_t& request) noexcept {
        if (request.operation == io_operation_t::zero_copy_release_k)
            return zero_copy.submit_release(request, operations, socket_slots);
        auto* owner = socket_slots.find(request.descriptor);
        if (!owner) return ucall_status_invalid_argument_k;
        if (owner->retirement == uring_retirement_t::retiring_k) return ucall_status_connection_closed_k;
        auto* operation = operations.take(request, owner);
        if (!operation) return ucall_status_contended_k;
        if (request.operation == io_operation_t::close_k) {
            owner->close_operation = operations.index_of(*operation);
            retire(*owner);
            return ucall_status_success_k;
        }
        if (request.operation == io_operation_t::receive_k) {
            owner->receive_flow = receive_flow_t::flowing_k;
            owner->receive_operation = operations.index_of(*operation);
            deliver_receive(*owner);
            if (operation->stage == uring_operation_stage_t::completed_k) return ucall_status_success_k;
            if (auto status = start_receive(*owner); status != ucall_status_success_k) {
                owner->receive_operation = absent_k;
                operations.vacate(*operation);
                return status;
            }
            if (!owner->receive_in_flight()) rearm(*owner);
            if (request.deadline) {
                if (timed_operations.empty() || request.deadline < earliest_timed) earliest_timed = request.deadline;
                operation->timed_listing = listing_t::listed_k;
                operations.push(timed_operations, *operation);
            }
            return ucall_status_success_k;
        }
        auto status = start_operation(*operation);
        if (status != ucall_status_success_k) operations.vacate(*operation);
        return status;
    }
    ucall_status_t start_operation(operation_t& operation) noexcept {
        auto& request = *operation.request;
        if (request.operation == io_operation_t::accept_k)
            return operations.arm_accepts(operation, queue, socket_slots);
        auto* submission = operations.entry(operation, queue);
        if (!submission) return ucall_status_io_k;
        if (request.operation == io_operation_t::file_read_vectors_k) {
            if (request.registered_memory != io_unregistered_k)
                io_uring_prep_readv_fixed(submission, request.file.file, io_vectors(request).data(),
                                          static_cast<unsigned>(request.length), request.file.offset, 0,
                                          static_cast<int>(request.registered_memory));
            else
                io_uring_prep_readv(submission, request.file.file, io_vectors(request).data(),
                                    static_cast<unsigned>(request.length), request.file.offset);
            tally<atomic_ref_template_>(statistics.file_reads_asynchronous);
        }
        else uring_prepare(submission, operation, queue, operations, zero_copy);
        operations.submit(submission, operation, queue);
        return ucall_status_success_k;
    }

    /** Marks the close of @p descriptor to send a reset rather than a FIN, without a round trip. */
    [[nodiscard]] ucall_status_t reset_on_close(descriptor_t descriptor) noexcept {
        return uring_reset_on_close(*this, descriptor);
    }
    ucall_status_t cancel(io_request_t& request) noexcept { return uring_cancel(*this, request); }
    ucall_status_t cancel(operation_t& operation) noexcept {
        if (operation.stage == uring_operation_stage_t::completed_k ||
            operation.stage == uring_operation_stage_t::cancelling_k)
            return ucall_status_success_k;
        tally<atomic_ref_template_>(statistics.cancellations);
        if (operations.carrying(*operation.request) == &operation &&
            operation.request->operation == io_operation_t::accept_k)
            return operations.end_accepts(operation, queue);
        if (operation.in_flight()) return operations.cancel_in_flight(operation, queue);
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
        if (queue.stage == uring_engine_stage_t::recovering_k) return;
        if (owner.retirement == uring_retirement_t::serving_k) {
            owner.retirement = uring_retirement_t::retiring_k;
            for (unsigned index = owner.owned_head; index != absent_k; index = operations[index].owned_next) {
                auto& operation = operations[index];
                if (operation.stage != uring_operation_stage_t::completed_k &&
                    operation.request->operation != io_operation_t::close_k)
                    if (cancel(operation) != ucall_status_success_k) queue.fault = -EIO;
            }
            if (owner.receive_stage == receive_stage_t::submitted_k) {
                if (cancel_stream(owner) != ucall_status_success_k) queue.fault = -EIO;
                else owner.receive_stage = receive_stage_t::cancelling_k;
            }
        }
        if (owner.stage == uring_socket_stage_t::installing_k || owner.receive_in_flight() ||
            owner.stage == uring_socket_stage_t::closing_k || operations.owns_in_flight(owner))
            return;
        if (owner.stage != uring_socket_stage_t::closed_k) socket_slots.submit_close(owner, queue);
        else if (owner.backlog_lease == uring_lease_t::returned_k) finish_close(owner);
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
        if (!owner.waiting_slice.empty()) queue.provided.return_slice(std::exchange(owner.waiting_slice, {}));
        owner.backlog.clear();
        if (owner.backlog.capacity() > queue.page) owner.backlog = vector<byte_t> {queue.allocator};
        owner.backlog_offset = 0;
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
            queue.control.result = completion.res;
            return;
        }
        if (kind == uring_close_tag_k) {
            if (auto* closed = socket_slots.settle_close(*static_cast<socket_slot_t*>(pointer), completion.res, queue))
                retire(*closed);
            return;
        }
        if (kind == uring_receive_tag_k) {
            settle_receive(*static_cast<socket_slot_t*>(pointer), completion);
            return;
        }
        if (kind == uring_release_tag_k) {
            auto* settled = zero_copy.settle(*static_cast<operation_t*>(pointer), completion, operations, socket_slots);
            if (settled && settled->retirement == uring_retirement_t::retiring_k) retire(*settled);
            return;
        }
        auto& operation = *static_cast<operation_t*>(pointer);
        if (auto* accepted = operations.settle(operation, completion, queue, socket_slots)) retire(*accepted);
        if (operation.socket_slot->retirement == uring_retirement_t::retiring_k) retire(*operation.socket_slot);
    }
    void settle_receive(socket_slot_t& owner, io_uring_cqe const& completion) noexcept {
        if (!(completion.flags & IORING_CQE_F_MORE)) {
            if (owner.receive_in_flight()) --receiving_socket_slots;
            owner.receive_stage = receive_stage_t::idle_k;
        }
        uring_provided_buffers<allocator_t>& provided = queue.provided;
        if (completion.res > 0 && (completion.flags & IORING_CQE_F_BUFFER)) {
            span<byte_t> const slice = provided.lease_slice(completion.flags >> IORING_CQE_BUFFER_SHIFT,
                                                            static_cast<std::size_t>(completion.res));
            if (owner.retirement == uring_retirement_t::retiring_k || queue.stage != uring_engine_stage_t::running_k)
                provided.return_slice(slice);
            else if (owner.receive_operation != absent_k && owner.backlog_offset == owner.backlog.size())
                deliver_slice(owner, slice);
            else if (owner.waiting_slice.empty() && owner.backlog_offset == owner.backlog.size() &&
                     owner.receive_flow == receive_flow_t::flowing_k) {
                // The next request often lands before its receive, so it waits a round.
                owner.waiting_slice = slice;
                if (owner.waiting_listing == listing_t::unlisted_k) {
                    owner.waiting_listing = listing_t::listed_k;
                    owner.next_waiting = std::exchange(waiting_socket_slots, owner.index);
                }
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
        if (owner.retirement == uring_retirement_t::retiring_k) retire(owner);
        else if (owner.receive_stage == receive_stage_t::idle_k) rearm(owner);
    }
    void reap() noexcept { uring_reap(*this); }
    int collect(span<io_completion_t> output) noexcept {
        std::size_t count {};
        while (count != output.size()) {
            auto* operation = operations.pop(operations.completed_operations);
            if (!operation) break;
            io_completion_t completed = operations.completion_of(*operation, queue, socket_slots);
            if (operation->receive_source == uring_receive_source_t::backlog_k) {
                auto& owner = *operation->socket_slot;
                completed.data = owner.backlog.data() + owner.backlog_offset;
                completed.lease = queue.provided.memory.size() + 1 + owner.index;
            }
            output[count++] = completed;
            operations.vacate(*operation);
        }
        return static_cast<int>(count);
    }
    void maintain() noexcept {
        if (queue.fault) return;
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
            if (start_operation(*operation) != ucall_status_success_k) queue.fault = -EIO;
        for (auto index = std::exchange(rearming_socket_slots, absent_k); index != absent_k;) {
            auto& owner = socket_slots.records[index];
            index = owner.next;
            owner.rearm_listing = listing_t::unlisted_k;
            if (owner.receive_operation == absent_k || owner.receive_in_flight()) continue;
            if (start_receive(owner) != ucall_status_success_k) queue.fault = -EIO;
            else if (!queue.provided.available_buffers) rearm(owner);
        }
    }
    int poll(span<io_completion_t> output, io_wait_t policy, std::uint64_t deadline = 0) noexcept {
        if (!queue.is_open()) return -EBADF;
        for (;;) {
            spill_waiting_slices();
            reap();
            maintain();
            if (queue.fault) return queue.fault;
            int count = collect(output);
            if (count) return count;
            spill_waiting_slices();
            auto now = monotonic_ns();
            auto wait_deadline = deadline;
            if (!timed_operations.empty())
                wait_deadline = !wait_deadline ? earliest_timed : fu::min_of(wait_deadline, earliest_timed);
            unsigned wait = policy == io_wait_t::blocking_k && (!wait_deadline || now < wait_deadline) ? 1 : 0;
            int result = queue.enter(wait, wait_deadline);
            if (result < 0) return result;
            reap();
            maintain();
            count = collect(output);
            if (count || policy == io_wait_t::nonblocking_k || (deadline && monotonic_ns() >= deadline)) return count;
        }
    }
    void discard(std::uint64_t user_data) noexcept {
        if ((static_cast<std::uintptr_t>(user_data) & 7) != uring_receive_tag_k)
            return uring_discard(user_data, queue, operations, socket_slots, zero_copy);
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
        return uring_grow(*this, capacity, queue.allocator);
    }
    void stop() noexcept { uring_stop(*this); }
};

using linux_uring618_engine_t = linux_uring618_engine<>;

} // namespace unum::ucall::io
