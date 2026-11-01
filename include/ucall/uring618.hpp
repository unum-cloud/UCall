/**
 *  @file include/ucall/uring618.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Registered sockets and multishot receive streams for Linux 6.18 io_uring.
 */
#pragma once

#include "ucall/uring612.hpp"

namespace unum::ucall {

/** One-shot requests and multishot streams share the same registered socket slot lifetimes. */
template <typename allocator_type_ = st::default_allocator<byte_t>,
          template <typename> class atomic_ref_template_ = fu::standard_atomic_ref>
struct linux_uring618_engine {
    using allocator_t = allocator_type_;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    template <typename value_type_>
    using vector = st::vector<value_type_, rebound_allocator<value_type_>>;
    template <typename other_allocator_type_, template <typename> class other_atomic_ref_>
    using rebind = linux_uring618_engine<other_allocator_type_, other_atomic_ref_>;
    static constexpr unsigned absent_k = operation_list_t::absent_k;

    enum class receive_stage_t : std::uint8_t { idle_k, submitted_k, cancelling_k, ended_k };

    /** Whether the socket's stream may prefetch, or stays cancelled while nobody pulls bytes. */
    enum class receive_flow_t : std::uint8_t { flowing_k, paused_k };

    /** Whether the socket's next stream is its first, or a re-arm the statistics count. */
    enum class stream_start_t : std::uint8_t { first_k, rearm_k };
    struct alignas(8) socket_slot_t {
        unsigned index {}, next {operation_list_t::absent_k}, owned_head {operation_list_t::absent_k};
        unsigned close_operation {operation_list_t::absent_k}, receive_operation {operation_list_t::absent_k};
        unsigned receive_head {operation_list_t::absent_k}, receive_tail {operation_list_t::absent_k};
        unsigned queued_buffers {};
        std::uint64_t serial {};
        vector<byte_t> backlog;
        std::size_t backlog_offset {};
        descriptor_t terminal {};
        uring_socket_stage_t stage {uring_socket_stage_t::vacant_k};
        zero_copy_stage_t zero_copy {zero_copy_stage_t::untried_k};
        uring_retirement_t retirement {uring_retirement_t::serving_k};
        receive_stage_t receive_stage {receive_stage_t::idle_k};
        receive_flow_t receive_flow {receive_flow_t::flowing_k};
        stream_start_t stream_start {stream_start_t::first_k};
        uring_lease_t backlog_lease {uring_lease_t::returned_k};
        uring_listing_t rearm_listing {uring_listing_t::unlisted_k};
        explicit socket_slot_t(allocator_t const& allocator) noexcept : backlog(allocator) {}
        bool receive_in_flight() const noexcept {
            return receive_stage == receive_stage_t::submitted_k || receive_stage == receive_stage_t::cancelling_k;
        }
    };
    struct buffer_t {
        unsigned next {operation_list_t::absent_k};
        int length {};
        uring_lease_t lease {uring_lease_t::returned_k};
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

    io_statistics_t statistics {};
    queue_t queue;
    socket_slots_t socket_slots;
    operations_t operations;
    zero_copy_t zero_copy;
    vector<buffer_t> buffers;

    /** Receives with a deadline, and the sockets whose stream re-arms as receive credits allow. */
    operation_list_t timed_operations;
    unsigned rearming_socket_slots {absent_k};

    /** At most every timed deadline while @c timed_operations is not empty. */
    std::uint64_t earliest_timed {};

    explicit linux_uring618_engine(allocator_t const& instance = {}) noexcept
        : queue(instance, statistics), socket_slots(instance), operations(instance), zero_copy(instance, statistics),
          buffers(rebound_allocator<buffer_t> {instance}) {}
    linux_uring618_engine(linux_uring618_engine const&) = delete;
    linux_uring618_engine& operator=(linux_uring618_engine const&) = delete;
    linux_uring618_engine(linux_uring618_engine&&) = delete;
    linux_uring618_engine& operator=(linux_uring618_engine&&) = delete;
    ~linux_uring618_engine() noexcept { stop(); }

    bool is_open() const noexcept { return queue.is_open(); }
    bool has_kernel_work() const noexcept {
        if (!queue.control.result || operations.in_flight_operations || zero_copy.pending_notifications ||
            socket_slots.closing())
            return true;
        for (auto const& owner : socket_slots.records)
            if (owner.receive_in_flight()) return true;
        return false;
    }

    ucall_status_t open(std::size_t depth, std::size_t capacity) noexcept {
        if (!depth || !capacity) return ucall_status_invalid_argument_k;
        if (capacity > static_cast<std::size_t>(registered_socket_t::tag_k)) return ucall_status_overflow_k;
        if (queue.stage != uring_engine_stage_t::idle_k) return ucall_status_invalid_argument_k;
        // Releases take no file, and the kernel registers no more files than descriptors.
        std::size_t const sockets = std::min(capacity, open_files_limit());
        if (ucall_status_t const reserved = queue.reserve(capacity); reserved != ucall_status_success_k)
            return reserved;
        if (operations.open(capacity) != ucall_status_success_k ||
            socket_slots.open(sockets, queue.allocator) != ucall_status_success_k ||
            zero_copy.releases.open(capacity) != ucall_status_success_k ||
            st::failed(buffers.resize(queue.buffer_count)))
            return ucall_status_out_of_memory_k;
        ucall_status_t const opened = queue.open(depth, sockets, opcodes_k);
        if (opened != ucall_status_success_k && queue.is_open()) stop();
        return opened;
    }
    void rearm(socket_slot_t& owner) noexcept {
        if (owner.rearm_listing == uring_listing_t::listed_k) return;
        owner.rearm_listing = uring_listing_t::listed_k;
        owner.next = rearming_socket_slots;
        rearming_socket_slots = owner.index;
    }
    int wait_control() noexcept {
        while (!queue.control.result.has_value() && !queue.fault) {
            int result = queue.enter(1, 0);
            if (result < 0) {
                queue.fault = result;
                break;
            }
            reap();
        }
        return queue.fault ? queue.fault : *queue.control.result;
    }
    descriptor_t import_socket(descriptor_t descriptor) noexcept {
        return socket_slots.import_socket(descriptor, queue);
    }
    descriptor_t open_socket(int family) noexcept {
        if (queue.fault) return queue.fault;
        auto* target = socket_slots.reserve();
        if (!target) return -ENFILE;
        auto* submission = queue.entry();
        if (!submission) {
            socket_slots.vacate(*target);
            return -EIO;
        }
        queue.control = {};
        io_uring_prep_socket_direct(submission, family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP, target->index, 0);
        queue.command(submission);
        int result = wait_control();
        if (result < 0) {
            if (queue.control.result) socket_slots.vacate(*target);
            return result;
        }
        target->stage = uring_socket_stage_t::open_k;
        auto handle = registered_socket_t {target->index}.handle();
        submission = queue.entry();
        if (!submission) {
            [[maybe_unused]] int const closed = close_socket(handle);
            return -EIO;
        }
        queue.storage->socket_option_value = 1;
        io_uring_prep_cmd_sock(submission, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(target->index), IPPROTO_TCP,
                               TCP_NODELAY, &queue.storage->socket_option_value,
                               sizeof(queue.storage->socket_option_value));
        submission->flags |= IOSQE_FIXED_FILE;
        queue.command(submission);
        result = wait_control();
        if (result < 0) {
            [[maybe_unused]] int const closed = close_socket(handle);
            return result;
        }
        return handle;
    }
    void recycle(unsigned index) noexcept {
        buffers[index] = {};
        queue.return_buffer(index);
    }
    void release(io_completion_t const& completion) noexcept {
        if (!queue.is_open() || !completion.lease) return;
        if (completion.lease >= static_cast<std::uintptr_t>(registered_socket_t::tag_k)) {
            auto* owner = socket_slots.find(static_cast<descriptor_t>(completion.lease));
            if (!owner || owner->backlog_lease != uring_lease_t::leased_k) return;
            owner->backlog_lease = uring_lease_t::returned_k;
            owner->backlog_offset += static_cast<std::size_t>(completion.result);
            if (owner->backlog_offset == owner->backlog.size()) {
                owner->backlog.clear();
                owner->backlog_offset = 0;
            }
            if (owner->receive_flow == receive_flow_t::paused_k) park_receive(*owner);
            if (owner->retirement == uring_retirement_t::serving_k) deliver_receive(*owner);
            else retire(*owner);
            return;
        }
        auto index = static_cast<unsigned>(completion.lease - 1);
        if (index < buffers.size() && buffers[index].lease == uring_lease_t::leased_k) {
            if (queue.receive_ring) recycle(index);
            else buffers[index].lease = uring_lease_t::returned_k;
        }
    }
    void park_receive(socket_slot_t& owner) noexcept {
        // Late CQEs keep their finite ring credits until cancellation stops prefetch.
        if (owner.backlog_lease == uring_lease_t::leased_k || owner.receive_stage == receive_stage_t::cancelling_k)
            return;
        if (owner.backlog_offset) {
            auto remaining = owner.backlog.size() - owner.backlog_offset;
            if (remaining) std::memmove(owner.backlog.data(), owner.backlog.data() + owner.backlog_offset, remaining);
            tally<atomic_ref_template_>(statistics.bytes_copied, remaining);
            [[maybe_unused]] st::status_t const shrunk = owner.backlog.resize(remaining);
            owner.backlog_offset = 0;
        }
        while (owner.receive_head != absent_k) {
            auto index = owner.receive_head;
            auto& buffer = buffers[index];
            if (buffer.length > 0) {
                auto previous = owner.backlog.size();
                auto length = static_cast<std::size_t>(buffer.length);
                if (length > std::numeric_limits<std::size_t>::max() - previous) {
                    queue.fault = -EOVERFLOW;
                    return;
                }
                if (st::failed(owner.backlog.resize(previous + length))) {
                    queue.fault = -ENOMEM;
                    return;
                }
                std::memcpy(owner.backlog.data() + previous, queue.receive_data(index).data(), length);
                tally<atomic_ref_template_>(statistics.bytes_copied, length);
            }
            else {
                owner.receive_stage = receive_stage_t::ended_k;
                owner.terminal = buffer.length;
            }
            owner.receive_head = buffer.next;
            --owner.queued_buffers;
            recycle(index);
        }
        owner.receive_tail = absent_k;
    }
    void receive_pause(descriptor_t descriptor) noexcept {
        auto* owner = socket_slots.find(descriptor);
        if (!owner || owner->retirement == uring_retirement_t::retiring_k || owner->receive_operation != absent_k)
            return;
        owner->receive_flow = receive_flow_t::paused_k;
        park_receive(*owner);
        if (owner->receive_stage == receive_stage_t::submitted_k) {
            if (cancel_stream(*owner) != ucall_status_success_k) queue.fault = -EIO;
            else owner->receive_stage = receive_stage_t::cancelling_k;
        }
    }
    void queue_buffer(socket_slot_t& owner, unsigned index, int length) noexcept {
        auto& buffer = buffers[index];
        buffer.length = length;
        buffer.next = absent_k;
        if (owner.receive_tail != absent_k) buffers[owner.receive_tail].next = index;
        else owner.receive_head = index;
        owner.receive_tail = index;
        ++owner.queued_buffers;
    }
    void deliver_receive(socket_slot_t& owner) noexcept {
        if (owner.receive_operation == absent_k) return;
        auto& operation = operations[owner.receive_operation];
        if (owner.backlog_offset != owner.backlog.size()) {
            if (owner.backlog_lease == uring_lease_t::leased_k) return;
            operation.receive_source = uring_receive_source_t::backlog_k;
            operation.result = static_cast<descriptor_t>(
                std::min(owner.backlog.size() - owner.backlog_offset, std::min(operation.request->length, queue.page)));
            owner.backlog_lease = uring_lease_t::leased_k;
        }
        else if (owner.receive_head != absent_k) {
            auto index = owner.receive_head;
            owner.receive_head = buffers[index].next;
            if (owner.receive_head == absent_k) owner.receive_tail = absent_k;
            --owner.queued_buffers;
            buffers[index].lease = uring_lease_t::leased_k;
            operation.buffer = index;
            operation.result = buffers[index].length;
        }
        else if (owner.receive_stage == receive_stage_t::ended_k) operation.result = owner.terminal;
        else return;
        owner.receive_operation = absent_k;
        unlist_timed(operation);
        operations.complete(operation);
    }
    void unlist_timed(operation_t& operation) noexcept {
        if (operation.timed_listing == uring_listing_t::unlisted_k) return;
        operations.unlink(timed_operations, operation);
        operation.timed_listing = uring_listing_t::unlisted_k;
    }
    ucall_status_t start_receive(socket_slot_t& owner) noexcept {
        if (owner.receive_stage != receive_stage_t::idle_k || owner.receive_flow == receive_flow_t::paused_k ||
            owner.retirement == uring_retirement_t::retiring_k || queue.stage != uring_engine_stage_t::running_k ||
            !queue.available_buffers)
            return ucall_status_success_k;
        auto* submission = queue.entry();
        if (!submission) return ucall_status_io_k;
        io_uring_prep_recv_multishot(submission, static_cast<int>(owner.index), nullptr, 0, 0);
        submission->flags |= IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
        submission->buf_group = 0;
        io_uring_sqe_set_data64(submission, queue.tag(&owner, uring_receive_tag_k));
        owner.receive_stage = receive_stage_t::submitted_k;
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
                if (timed_operations.head == absent_k || request.deadline < earliest_timed)
                    earliest_timed = request.deadline;
                operation->timed_listing = uring_listing_t::listed_k;
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
        ucall_status_t status;
        auto* submission = operations.entry(operation, queue, socket_slots, status);
        if (!submission) return status;
        if (request.operation == io_operation_t::file_read_vectors_k) {
            if (request.registered_memory != io_unregistered_k)
                io_uring_prep_readv_fixed(submission, request.file.file_descriptor, io_vectors(request).data(),
                                          static_cast<unsigned>(request.length), request.file.offset, 0,
                                          static_cast<int>(request.registered_memory));
            else
                io_uring_prep_readv(submission, request.file.file_descriptor, io_vectors(request).data(),
                                    static_cast<unsigned>(request.length), request.file.offset);
            tally<atomic_ref_template_>(statistics.file_reads_asynchronous);
        }
        else uring_prepare(submission, operation, queue, operations, zero_copy);
        operations.submit(submission, operation, queue);
        return ucall_status_success_k;
    }

    /** Makes the close of @p descriptor send a reset rather than a FIN, waiting on the ring. */
    [[nodiscard]] ucall_status_t reset_on_close(descriptor_t descriptor) noexcept {
        auto* owner = socket_slots.find(descriptor);
        if (!owner || queue.fault) return ucall_status_io_k;
        auto* submission = queue.entry();
        if (!submission) return ucall_status_io_k;
        io_uring_prep_cmd_sock(submission, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(owner->index), SOL_SOCKET,
                               SO_LINGER, &queue.storage->reset_linger, sizeof(queue.storage->reset_linger));
        submission->flags |= IOSQE_FIXED_FILE;
        queue.command(submission);
        return wait_control() < 0 ? ucall_status_io_k : ucall_status_success_k;
    }
    ucall_status_t cancel(io_request_t& request) noexcept {
        // A release ends on its notifications, a close on its last socket operation, never sooner.
        if (request.operation == io_operation_t::close_k || request.operation == io_operation_t::zero_copy_release_k)
            return ucall_status_success_k;
        auto* owner = socket_slots.find(request.descriptor);
        auto* operation = owner ? operations.owned(*owner, request) : nullptr;
        return operation ? cancel(*operation) : ucall_status_not_found_k;
    }
    ucall_status_t cancel(operation_t& operation) noexcept {
        if (operation.stage == uring_operation_stage_t::completed_k ||
            operation.stage == uring_operation_stage_t::cancelling_k)
            return ucall_status_success_k;
        tally<atomic_ref_template_>(statistics.cancellations);
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
            while (owner.receive_head != absent_k) {
                auto index = owner.receive_head;
                owner.receive_head = buffers[index].next;
                --owner.queued_buffers;
                recycle(index);
            }
            owner.receive_tail = absent_k;
        }
        if (owner.stage == uring_socket_stage_t::installing_k || owner.receive_in_flight() ||
            owner.stage == uring_socket_stage_t::closing_k || operations.owns_in_flight(owner))
            return;
        if (owner.stage != uring_socket_stage_t::closed_k) socket_slots.submit_close(owner, queue);
        else if (owner.backlog_lease == uring_lease_t::returned_k) finish_close(owner);
    }
    int close_socket(descriptor_t descriptor) noexcept {
        if (!queue.is_open()) return 0;
        auto* owner = socket_slots.find(descriptor);
        if (!owner) return 0;
        auto serial = owner->serial;
        retire(*owner);
        while (owner->stage != uring_socket_stage_t::vacant_k && owner->serial == serial && !queue.fault) {
            int result = queue.enter(1, 0);
            if (result < 0) {
                queue.fault = result;
                break;
            }
            reap();
        }
        return queue.fault;
    }
    void finish_close(socket_slot_t& owner) noexcept {
        // A socket can close before maintain() drains the re-arm list that shares its link.
        if (owner.rearm_listing == uring_listing_t::listed_k)
            for (auto* link = &rearming_socket_slots; *link != absent_k; link = &socket_slots.records[*link].next)
                if (*link == owner.index) {
                    *link = owner.next;
                    break;
                }
        owner.receive_operation = owner.receive_head = owner.receive_tail = absent_k;
        owner.queued_buffers = 0;
        owner.backlog.clear();
        owner.backlog_offset = 0;
        owner.terminal = 0;
        owner.receive_stage = receive_stage_t::idle_k;
        owner.receive_flow = receive_flow_t::flowing_k;
        owner.stream_start = stream_start_t::first_k;
        owner.rearm_listing = uring_listing_t::unlisted_k;
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
        if (!(completion.flags & IORING_CQE_F_MORE)) owner.receive_stage = receive_stage_t::idle_k;
        if (completion.flags & IORING_CQE_F_BUFFER) {
            --queue.available_buffers;
            unsigned index = completion.flags >> IORING_CQE_BUFFER_SHIFT;
            if (owner.retirement == uring_retirement_t::retiring_k || queue.stage != uring_engine_stage_t::running_k)
                recycle(index);
            else {
                queue_buffer(owner, index, completion.res);
                if (owner.receive_flow == receive_flow_t::paused_k) park_receive(owner);
                else deliver_receive(owner);
                // One open socket may hold at most its fair share of the shared receive ring.
                assert(socket_slots.records.size() > socket_slots.vacant_socket_slots);
                if (owner.queued_buffers >=
                        queue.buffer_count / (socket_slots.records.size() - socket_slots.vacant_socket_slots) &&
                    owner.receive_stage == receive_stage_t::submitted_k) {
                    if (cancel_stream(owner) != ucall_status_success_k) queue.fault = -EIO;
                    else owner.receive_stage = receive_stage_t::cancelling_k;
                }
            }
        }
        else if (completion.res != -ENOBUFS && completion.res != -ECANCELED) {
            owner.receive_stage = receive_stage_t::ended_k;
            owner.terminal = completion.res;
            deliver_receive(owner);
        }
        if (owner.receive_flow == receive_flow_t::paused_k && !owner.receive_in_flight()) park_receive(owner);
        if (owner.retirement == uring_retirement_t::retiring_k) retire(owner);
        else if (owner.receive_stage == receive_stage_t::idle_k) rearm(owner);
    }
    void reap() noexcept {
        unsigned head {}, count {};
        io_uring_cqe* current {};
        io_uring_for_each_cqe(&queue.ring, head, current) {
            completion(*current);
            ++count;
        }
        if (!count) return;
        io_uring_cq_advance(&queue.ring, count);
        tally<atomic_ref_template_>(statistics.completions, count);
    }
    int collect(span<io_completion_t> output) noexcept {
        std::size_t count {};
        while (count != output.size()) {
            auto* operation = operations.pop(operations.completed_operations);
            if (!operation) break;
            io_completion_t completed = operations.completion_of(*operation, queue);
            if (operation->receive_source == uring_receive_source_t::backlog_k) {
                auto& owner = *operation->socket_slot;
                completed.data = owner.backlog.data() + owner.backlog_offset;
                completed.lease = static_cast<std::uintptr_t>(registered_socket_t {owner.index}.handle());
            }
            output[count++] = completed;
            operations.vacate(*operation);
        }
        return static_cast<int>(count);
    }
    void maintain() noexcept {
        if (queue.fault) return;
        if (timed_operations.head != absent_k && monotonic_ns() >= earliest_timed) {
            auto now = monotonic_ns();
            earliest_timed = 0;
            for (auto index = timed_operations.head; index != absent_k;) {
                auto& operation = operations[index];
                index = operation.next;
                std::uint64_t const expiry = operation.request->deadline;
                if (expiry > now) {
                    earliest_timed = earliest_timed ? std::min(earliest_timed, expiry) : expiry;
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
            owner.rearm_listing = uring_listing_t::unlisted_k;
            if (owner.receive_operation == absent_k || owner.receive_in_flight()) continue;
            if (start_receive(owner) != ucall_status_success_k) queue.fault = -EIO;
            else if (!queue.available_buffers) rearm(owner);
        }
    }
    int poll(span<io_completion_t> output, io_wait_t policy, std::uint64_t deadline = 0) noexcept {
        if (!queue.is_open()) return -EBADF;
        for (;;) {
            reap();
            maintain();
            if (queue.fault) return queue.fault;
            int count = collect(output);
            if (count) return count;
            auto now = monotonic_ns();
            auto wait_deadline = deadline;
            if (timed_operations.head != absent_k)
                wait_deadline = !wait_deadline ? earliest_timed : std::min(wait_deadline, earliest_timed);
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
        if (owner.receive_in_flight()) owner.receive_stage = receive_stage_t::idle_k;
    }
    void discard_unsubmitted() noexcept {
        auto head = io_uring_smp_load_acquire(queue.ring.sq.khead);
        for (auto i = head; i != queue.ring.sq.sqe_tail; ++i)
            discard(queue.ring.sq.sqes[i & queue.ring.sq.ring_mask].user_data);
        queue.ring.sq.sqe_head = queue.ring.sq.sqe_tail = head;
        io_uring_smp_store_release(queue.ring.sq.ktail, head);
    }
    [[nodiscard]] ucall_status_t drain_after_fault() noexcept {
        queue.stage = uring_engine_stage_t::recovering_k;
        discard_unsubmitted();
        if (ucall_status_t const cancelled = queue.cancel_synchronously(); cancelled != ucall_status_success_k)
            return cancelled;
        if (ucall_status_t const unregistered = queue.unregister_files(); unregistered != ucall_status_success_k)
            return unregistered;
        reap();
        while (has_kernel_work()) {
            int result = queue.retry_interrupted(
                [&] { return io_uring_enter(queue.ring.ring_fd, 0, 1, IORING_ENTER_GETEVENTS, nullptr); });
            if (result < 0) {
                queue.fault = result;
                return ucall_status_io_k;
            }
            reap();
        }
        return ucall_status_success_k;
    }
    void stop() noexcept {
        if (!queue.is_open()) return;
        queue.stage = uring_engine_stage_t::stopping_k;
        if (!queue.fault) {
            for (auto& owner : socket_slots.records)
                if (owner.stage != uring_socket_stage_t::vacant_k) retire(owner);
            while (has_kernel_work() && !queue.fault) {
                int result = queue.enter(1, 0);
                if (result < 0) {
                    queue.fault = result;
                    break;
                }
                reap();
            }
        }
        // Failed submission must not bypass terminal CQEs that still reference caller memory.
        ucall_status_t const retirement = queue.fault ? drain_after_fault() : queue.unregister_files();
        operations.close_uncollected_files();
        queue.close(retirement);
        for (auto& owner : socket_slots.records) owner.stage = uring_socket_stage_t::vacant_k;
    }
};

using linux_uring618_engine_t = linux_uring618_engine<>;

} // namespace unum::ucall
