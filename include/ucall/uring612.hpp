/**
 *  @file include/ucall/uring612.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Registered sockets and single-shot buffer-select receives for Linux 6.12 io_uring.
 */
#pragma once

#include <optional>

#include "ucall/io.hpp"

namespace unum::ucall {

/** One-shot requests over registered sockets, submitted through the liburing SQ. */
template <typename allocator_type_ = st::default_allocator<byte_t>>
struct linux_uring612_engine {
    using allocator_t = allocator_type_;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    template <typename value_type_>
    using vector = st::basic_vector<value_type_, rebound_allocator<value_type_>>;
    template <typename other_allocator_type_>
    using rebind_allocator = linux_uring612_engine<other_allocator_type_>;

    /** The high bit separates registered transport handles from process file descriptors. */
    struct registered_socket_t {
        unsigned index {};
        static constexpr descriptor_t tag_k = descriptor_t {1} << (sizeof(descriptor_t) * CHAR_BIT - 2);
        descriptor_t handle() const noexcept { return tag_k | static_cast<descriptor_t>(index); }
        static bool contains(descriptor_t handle) noexcept { return handle >= tag_k; }
        static unsigned index_of(descriptor_t handle) noexcept { return static_cast<unsigned>(handle & ~tag_k); }
    };

    enum class engine_stage_t : std::uint8_t { idle_k, running_k, stopping_k, recovering_k, stopped_k };
    enum class operation_stage_t : std::uint8_t { waiting_k, submitted_k, cancelling_k, completed_k };
    enum class socket_stage_t : std::uint8_t { vacant_k, installing_k, open_k, closing_k, closed_k };
    enum operation_flags_t : std::uint8_t { operation_none_k = 0, operation_expired_k = 1 };
    enum socket_flags_t : std::uint8_t { socket_none_k = 0, socket_retiring_k = 1 };
    enum registration_flags_t : std::uint8_t { registration_none_k = 0, registration_files_k = 1 };
    enum buffer_flags_t : std::uint8_t { buffer_none_k = 0, buffer_leased_k = 1 };
    static constexpr unsigned absent_k = std::numeric_limits<unsigned>::max();
    static constexpr std::uintptr_t operation_tag_k = 0, control_tag_k = 1, close_tag_k = 4, cancel_tag_k = 7;
    struct socket_slot_t;
    struct alignas(8) operation_t {
        io_request_t* request {};
        socket_slot_t* socket_slot {};
        descriptor_t result {};
        __kernel_timespec expiry {};
        unsigned accepted {absent_k}, buffer {absent_k}, next {absent_k};
        operation_stage_t stage {operation_stage_t::waiting_k};
        operation_flags_t flags {operation_none_k};
        bool in_flight() const noexcept {
            return stage == operation_stage_t::submitted_k || stage == operation_stage_t::cancelling_k;
        }
    };
    struct operation_list_t {
        unsigned head {absent_k}, tail {absent_k};
    };
    struct alignas(8) socket_slot_t {
        unsigned index {}, next {absent_k};
        operation_t* close_request {};
        std::uint64_t serial {};
        socket_stage_t stage {socket_stage_t::vacant_k};
        socket_flags_t flags {socket_none_k};
    };
    struct buffer_t {
        buffer_flags_t flags {buffer_none_k};
    };
    struct alignas(8) control_t {
        std::optional<int> result {0};
    };

    struct storage_t {
        vector<byte_t> receive;
        int socket_option_value {1};
        explicit storage_t(allocator_t const& allocator) noexcept : receive(allocator) {}
        storage_t(storage_t const&) = delete;
        storage_t& operator=(storage_t const&) = delete;
        storage_t(storage_t&&) = delete;
        storage_t& operator=(storage_t&&) = delete;
    };
    io_uring ring {};
    io_uring_buf_ring* receive_ring {};
    allocator_t allocator;
    vector<operation_t> operations;
    vector<socket_slot_t> socket_slots;
    vector<buffer_t> buffers;
    allocated_ptr<storage_t, allocator_t> storage;
    operation_list_t free_operations, completed_operations, waiting_operations;
    unsigned free_socket_slots {absent_k};
    unsigned buffer_count {}, buffer_mask {}, available_buffers {};
    std::size_t page {};
    control_t control {};
    std::uint64_t next_serial {};
    engine_stage_t stage {engine_stage_t::idle_k};
    registration_flags_t registrations {registration_none_k};
    int fault {};
    io_statistics_t statistics {};

    explicit linux_uring612_engine(allocator_t const& instance = {}) noexcept
        : allocator(instance), operations(rebound_allocator<operation_t> {instance}),
          socket_slots(rebound_allocator<socket_slot_t> {instance}), buffers(rebound_allocator<buffer_t> {instance}),
          storage(nullptr, allocator_delete<storage_t, allocator_t> {instance}) {}
    linux_uring612_engine(linux_uring612_engine const&) = delete;
    linux_uring612_engine& operator=(linux_uring612_engine const&) = delete;
    linux_uring612_engine(linux_uring612_engine&&) = delete;
    linux_uring612_engine& operator=(linux_uring612_engine&&) = delete;
    ~linux_uring612_engine() noexcept { stop(); }

    bool is_open() const noexcept { return stage != engine_stage_t::idle_k && stage != engine_stage_t::stopped_k; }
    bool has_kernel_work() const noexcept {
        if (!control.result) return true;
        for (auto const& operation : operations)
            if (operation.in_flight()) return true;
        for (auto const& owner : socket_slots)
            if (owner.stage == socket_stage_t::closing_k) return true;
        return false;
    }

    static std::uintptr_t tag(void* pointer, std::uintptr_t kind) noexcept {
        return reinterpret_cast<std::uintptr_t>(pointer) | kind;
    }
    socket_slot_t* socket_slot(descriptor_t handle) noexcept {
        if (!registered_socket_t::contains(handle)) return nullptr;
        auto index = registered_socket_t::index_of(handle);
        return index < socket_slots.size() && (socket_slots[index].stage != socket_stage_t::vacant_k)
                   ? &socket_slots[index]
                   : nullptr;
    }
    span<byte_t> receive_data(unsigned index) noexcept {
        return span<byte_t> {storage->receive}.subspan(static_cast<std::size_t>(index) * page, page);
    }
    unsigned index_of(operation_t const& operation) const noexcept {
        return static_cast<unsigned>(&operation - operations.data());
    }
    void push(operation_list_t& list, operation_t& operation) noexcept {
        operation.next = absent_k;
        if (list.tail != absent_k) operations[list.tail].next = index_of(operation);
        else list.head = index_of(operation);
        list.tail = index_of(operation);
    }
    operation_t* pop(operation_list_t& list) noexcept {
        if (list.head == absent_k) return nullptr;
        auto& operation = operations[list.head];
        list.head = operation.next;
        if (list.head == absent_k) list.tail = absent_k;
        return &operation;
    }
    void unlink(operation_list_t& list, operation_t& operation) noexcept {
        auto index = index_of(operation);
        for (unsigned previous = absent_k, current = list.head; current != absent_k;
             previous = current, current = operations[current].next) {
            if (current != index) continue;
            if (previous != absent_k) operations[previous].next = operation.next;
            else list.head = operation.next;
            if (list.tail == index) list.tail = previous;
            return;
        }
    }
    void complete(operation_t& operation) noexcept {
        operation.stage = operation_stage_t::completed_k;
        push(completed_operations, operation);
    }
    void vacate(operation_t& operation) noexcept {
        operation.request = nullptr;
        push(free_operations, operation);
    }
    void vacate(socket_slot_t& owner) noexcept {
        owner.stage = socket_stage_t::vacant_k;
        owner.next = free_socket_slots;
        free_socket_slots = owner.index;
    }
    static __kernel_timespec timespec_of(std::uint64_t nanoseconds) noexcept {
        return {static_cast<__kernel_time64_t>(nanoseconds / 1'000'000'000),
                static_cast<long long>(nanoseconds % 1'000'000'000)};
    }
    io_uring_sqe* entry(unsigned count = 1) noexcept {
        if (io_uring_sq_space_left(&ring) < count) {
            tally(statistics.kernel_enters);
            if (io_uring_submit(&ring) < 0) return nullptr;
        }
        if (io_uring_sq_space_left(&ring) < count) return nullptr;
        tally(statistics.submissions);
        return io_uring_get_sqe(&ring);
    }
    int enter(unsigned wait, std::uint64_t deadline) noexcept {
        tally(statistics.kernel_enters);
        // Deferred task work only runs inside an enter that asks for events.
        if (!wait) return io_uring_submit_and_get_events(&ring);
        auto now = deadline ? monotonic_ns() : 0;
        auto timeout = timespec_of(deadline > now ? deadline - now : 0);
        io_uring_cqe* completion {};
        int result = deadline ? io_uring_submit_and_wait_timeout(&ring, &completion, wait, &timeout, nullptr)
                              : io_uring_submit_and_wait(&ring, wait);
        return result == -ETIME || result == -EINTR ? 0 : result;
    }
    ucall_status_t open(std::size_t depth, std::size_t capacity) noexcept {
        if (!depth || !capacity) return ucall_status_invalid_argument_k;
        if (capacity > static_cast<std::size_t>(registered_socket_t::tag_k)) return ucall_status_overflow_k;
        if (stage != engine_stage_t::idle_k) return ucall_status_invalid_argument_k;
        storage = allocate_unique<storage_t>(allocator, allocator);
        if (!storage) return ucall_status_out_of_memory_k;
        page = page_size();
        if (!page || capacity > std::numeric_limits<std::size_t>::max() / page) return ucall_status_overflow_k;
        // Pbuf ring IDs and head distances are 16-bit; the kernel permits 32768 entries.
        buffer_count = 1;
        while (buffer_count < capacity && buffer_count < 32768) buffer_count *= 2;
        buffer_mask = buffer_count - 1;
        available_buffers = buffer_count;
        if (st::failed(operations.resize(capacity)) || st::failed(socket_slots.resize(capacity)) ||
            st::failed(buffers.resize(buffer_count)) ||
            st::failed(storage->receive.resize(static_cast<std::size_t>(buffer_count) * page)))
            return ucall_status_out_of_memory_k;
        for (auto& operation : operations) push(free_operations, operation);
        for (auto i = socket_slots.size(); i--;) {
            socket_slots[i].index = static_cast<unsigned>(i);
            vacate(socket_slots[i]);
        }
        io_uring_params parameters {};
        parameters.flags = IORING_SETUP_CLAMP | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_SINGLE_ISSUER |
                           IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_NO_SQARRAY;
        // Each one-shot operation may carry a linked timeout.
        auto entries = static_cast<unsigned>(
            std::min(depth, static_cast<std::size_t>(std::numeric_limits<unsigned>::max() / 2)) * 2);
        int result = io_uring_queue_init_params(entries, &ring, &parameters);
        if (result < 0) return result == -ENOMEM ? ucall_status_out_of_memory_k : ucall_status_unsupported_k;
        [[maybe_unused]] int const registered = io_uring_register_ring_fd(&ring);
        stage = engine_stage_t::running_k;
        constexpr auto probe_length = unsigned {std::numeric_limits<decltype(io_uring_probe_op::op)>::max()} + 1;
        struct alignas(io_uring_probe) probe_scratch_t {
            byte_t bytes[sizeof(io_uring_probe) + probe_length * sizeof(io_uring_probe_op)] {};
        };
        auto scratch = allocate_unique<probe_scratch_t>(allocator);
        if (!scratch) {
            stop();
            return ucall_status_out_of_memory_k;
        }
        auto* probe = std::construct_at(reinterpret_cast<io_uring_probe*>(scratch->bytes));
        bool supported = io_uring_register_probe(&ring, probe, probe_length) == 0 &&
                         (parameters.features & IORING_FEAT_NODROP) && (parameters.features & IORING_FEAT_EXT_ARG);
        for (auto opcode :
             {IORING_OP_SOCKET, IORING_OP_ACCEPT, IORING_OP_CONNECT, IORING_OP_RECV, IORING_OP_SEND, IORING_OP_READ,
              IORING_OP_CLOSE, IORING_OP_ASYNC_CANCEL, IORING_OP_LINK_TIMEOUT, IORING_OP_URING_CMD})
            supported = supported && io_uring_opcode_supported(probe, opcode);
        scratch.reset();
        if (!supported) {
            stop();
            return ucall_status_unsupported_k;
        }
        result = io_uring_register_files_sparse(&ring, static_cast<unsigned>(socket_slots.size()));
        if (result < 0) {
            stop();
            return ucall_status_unsupported_k;
        }
        registrations = static_cast<registration_flags_t>(registrations | registration_files_k);
        receive_ring = io_uring_setup_buf_ring(&ring, buffer_count, 0, 0, &result);
        if (!receive_ring) {
            stop();
            return ucall_status_unsupported_k;
        }
        for (unsigned i = 0; i != buffer_count; ++i)
            io_uring_buf_ring_add(receive_ring, receive_data(i).data(), static_cast<unsigned>(page),
                                  static_cast<unsigned short>(i), buffer_mask, i);
        io_uring_buf_ring_advance(receive_ring, buffer_count);
        return ucall_status_success_k;
    }
    socket_slot_t* reserve() noexcept {
        if (free_socket_slots == absent_k) return nullptr;
        auto index = free_socket_slots;
        auto& result = socket_slots[index];
        free_socket_slots = result.next;
        result = {};
        result.index = index;
        result.stage = socket_stage_t::installing_k;
        result.serial = ++next_serial;
        return &result;
    }
    int wait_control() noexcept {
        while (!control.result.has_value() && !fault) {
            int result = enter(1, 0);
            if (result < 0) {
                fault = result;
                break;
            }
            reap();
        }
        return fault ? fault : *control.result;
    }
    descriptor_t import_socket(descriptor_t descriptor) noexcept {
        if (fault) return fault;
        if (descriptor < 0 || descriptor > std::numeric_limits<int>::max()) return -EINVAL;
        int protocol {}, enabled = 1;
        socklen_t length = sizeof(protocol);
        if (getsockopt(static_cast<int>(descriptor), SOL_SOCKET, SO_PROTOCOL, &protocol, &length) == 0 &&
            protocol == IPPROTO_TCP &&
            socket_option(descriptor, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) != 0)
            return -errno;
        auto* target = reserve();
        if (!target) return -ENFILE;
        int raw = static_cast<int>(descriptor);
        int result = io_uring_register_files_update(&ring, target->index, &raw, 1);
        if (result != 1) {
            vacate(*target);
            return result < 0 ? result : -EIO;
        }
        socket_close(descriptor);
        target->stage = socket_stage_t::open_k;
        return registered_socket_t {target->index}.handle();
    }
    descriptor_t open_socket(int family) noexcept {
        if (fault) return fault;
        auto* target = reserve();
        if (!target) return -ENFILE;
        auto* submission = entry();
        if (!submission) {
            vacate(*target);
            return -EIO;
        }
        control = {};
        control.result.reset();
        io_uring_prep_socket_direct(submission, family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP, target->index, 0);
        io_uring_sqe_set_data64(submission, tag(&control, control_tag_k));
        int result = wait_control();
        if (result < 0) {
            if (control.result) vacate(*target);
            return result;
        }
        target->stage = socket_stage_t::open_k;
        auto handle = registered_socket_t {target->index}.handle();
        submission = entry();
        if (!submission) {
            [[maybe_unused]] int const closed = close_socket(handle);
            return -EIO;
        }
        storage->socket_option_value = 1;
        control.result.reset();
        io_uring_prep_cmd_sock(submission, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(target->index), IPPROTO_TCP,
                               TCP_NODELAY, &storage->socket_option_value, sizeof(storage->socket_option_value));
        submission->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(submission, tag(&control, control_tag_k));
        result = wait_control();
        if (result < 0) {
            [[maybe_unused]] int const closed = close_socket(handle);
            return result;
        }
        return handle;
    }
    void recycle(unsigned index) noexcept {
        buffers[index] = {};
        ++available_buffers;
        io_uring_buf_ring_add(receive_ring, receive_data(index).data(), static_cast<unsigned>(page),
                              static_cast<unsigned short>(index), buffer_mask, 0);
        io_uring_buf_ring_advance(receive_ring, 1);
    }
    void release(io_completion_t const& completion) noexcept {
        if (!is_open() || !completion.lease) return;
        auto index = static_cast<unsigned>(completion.lease - 1);
        if (index < buffers.size() && (buffers[index].flags & buffer_leased_k)) {
            if (receive_ring) recycle(index);
            else buffers[index].flags = buffer_none_k;
        }
    }
    ucall_status_t submit(io_request_t& request) noexcept {
        auto* owner = socket_slot(request.descriptor);
        if (!owner) return ucall_status_invalid_argument_k;
        if (owner->flags & socket_retiring_k) return ucall_status_connection_closed_k;
        auto* operation = pop(free_operations);
        if (!operation) return ucall_status_contended_k;
        *operation = {};
        operation->request = &request;
        operation->socket_slot = owner;
        if (request.operation == io_operation_t::close_k) {
            owner->close_request = operation;
            retire(*owner);
            return ucall_status_success_k;
        }
        auto status = start_operation(*operation);
        if (status != ucall_status_success_k) vacate(*operation);
        return status;
    }
    ucall_status_t start_operation(operation_t& operation) noexcept {
        auto& request = *operation.request;
        auto* owner = operation.socket_slot;
        if (request.operation == io_operation_t::accept_k && operation.accepted == absent_k) {
            auto* accepted = reserve();
            if (!accepted) {
                push(waiting_operations, operation);
                return ucall_status_success_k;
            }
            operation.accepted = accepted->index;
        }
        if (request.operation == io_operation_t::receive_k && !available_buffers) {
            push(waiting_operations, operation);
            return ucall_status_success_k;
        }
        auto* submission = entry(request.deadline ? 2 : 1);
        if (!submission) {
            if (operation.accepted != absent_k) vacate(socket_slots[operation.accepted]);
            return ucall_status_io_k;
        }
        auto length = static_cast<unsigned>(std::min(request.length, page));
        switch (request.operation) {
        case io_operation_t::accept_k:
            // A full fixed table can make multishot accept drop a peer; reserve one credit.
            io_uring_prep_accept_direct(submission, static_cast<int>(owner->index), nullptr, nullptr, SOCK_NONBLOCK,
                                        operation.accepted);
            break;
        case io_operation_t::connect_k:
            io_uring_prep_connect(submission, static_cast<int>(owner->index), reinterpret_cast<sockaddr*>(request.data),
                                  static_cast<socklen_t>(request.length));
            break;
        case io_operation_t::receive_k:
            io_uring_prep_recv(submission, static_cast<int>(owner->index), nullptr, length, 0);
            submission->flags |= IOSQE_BUFFER_SELECT;
            submission->buf_group = 0;
            break;
        case io_operation_t::send_k:
            // The submission length field is 32 bits wide.
            io_uring_prep_send(submission, static_cast<int>(owner->index), request.data,
                               std::min(request.length, std::size_t {std::numeric_limits<unsigned>::max()}),
                               MSG_NOSIGNAL);
            break;
        case io_operation_t::read_k:
            io_uring_prep_read(submission, static_cast<int>(owner->index), request.data, length, -1);
            break;
        case io_operation_t::close_k: break;
        }
        submission->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(submission, tag(&operation, operation_tag_k));
        if (request.deadline) {
            submission->flags |= IOSQE_IO_LINK;
            operation.expiry = timespec_of(request.deadline);
            auto* timeout = entry();
            io_uring_prep_link_timeout(timeout, &operation.expiry, IORING_TIMEOUT_ABS);
            io_uring_sqe_set_data64(timeout, cancel_tag_k);
        }
        operation.stage = operation_stage_t::submitted_k;
        return ucall_status_success_k;
    }
    ucall_status_t cancel(io_request_t& request) noexcept {
        for (auto& operation : operations)
            if (operation.request == &request) {
                if (request.operation == io_operation_t::close_k) return ucall_status_success_k;
                if ((operation.stage == operation_stage_t::completed_k) ||
                    (operation.stage == operation_stage_t::cancelling_k))
                    return ucall_status_success_k;
                tally(statistics.cancellations);
                if (!operation.in_flight()) {
                    unlink(waiting_operations, operation);
                    operation.result = -ECANCELED;
                    complete(operation);
                    return ucall_status_success_k;
                }
                operation.stage = operation_stage_t::cancelling_k;
                auto* submission = entry();
                if (!submission) {
                    operation.stage = operation_stage_t::submitted_k;
                    return ucall_status_io_k;
                }
                io_uring_prep_cancel64(submission, tag(&operation, operation_tag_k), 0);
                io_uring_sqe_set_data64(submission, cancel_tag_k);
                return ucall_status_success_k;
            }
        return ucall_status_not_found_k;
    }
    void retire(socket_slot_t& owner) noexcept {
        if (stage == engine_stage_t::recovering_k) return;
        if (!(owner.flags & socket_retiring_k)) {
            owner.flags = static_cast<socket_flags_t>(owner.flags | socket_retiring_k);
            for (auto& operation : operations)
                if (operation.request && operation.socket_slot == &owner &&
                    operation.stage != operation_stage_t::completed_k &&
                    operation.request->operation != io_operation_t::close_k)
                    if (cancel(*operation.request) != ucall_status_success_k) fault = -EIO;
        }
        if (owner.stage == socket_stage_t::installing_k || owner.stage == socket_stage_t::closing_k) return;
        for (auto const& operation : operations)
            if (operation.in_flight() && operation.socket_slot == &owner) return;
        if (owner.stage == socket_stage_t::closed_k) {
            finish_close(owner);
            return;
        }
        auto* submission = entry();
        if (!submission) {
            fault = -EIO;
            return;
        }
        io_uring_prep_close_direct(submission, owner.index);
        io_uring_sqe_set_data64(submission, tag(&owner, close_tag_k));
        owner.stage = socket_stage_t::closing_k;
    }
    int close_socket(descriptor_t descriptor) noexcept {
        if (!is_open()) return 0;
        auto* owner = socket_slot(descriptor);
        if (!owner) return 0;
        auto serial = owner->serial;
        retire(*owner);
        while ((owner->stage != socket_stage_t::vacant_k) && owner->serial == serial && !fault) {
            int result = enter(1, 0);
            if (result < 0) {
                fault = result;
                break;
            }
            reap();
        }
        return fault;
    }
    void finish_close(socket_slot_t& owner) noexcept {
        if (owner.close_request) {
            owner.close_request->result = 0;
            owner.close_request->request->descriptor = -1;
            complete(*owner.close_request);
            owner.close_request = nullptr;
        }
        vacate(owner);
    }
    void completion(io_uring_cqe const& completion) noexcept {
        auto kind = static_cast<std::uintptr_t>(completion.user_data) & 7;
        auto* pointer = reinterpret_cast<void*>(static_cast<std::uintptr_t>(completion.user_data) &
                                                ~std::uintptr_t {7});
        if (kind == cancel_tag_k) return;
        if (kind == control_tag_k) {
            control.result = completion.res;
            return;
        }
        if (kind == close_tag_k) {
            auto& owner = *static_cast<socket_slot_t*>(pointer);
            owner.stage = socket_stage_t::open_k;
            if (completion.res < 0) {
                fault = completion.res;
                return;
            }
            owner.stage = socket_stage_t::closed_k;
            retire(owner);
            return;
        }
        auto& operation = *static_cast<operation_t*>(pointer);
        operation.result = completion.res;
        // Only the linked timeout cancels an operation that was not asked to cancel.
        if (completion.res == -ECANCELED && operation.stage != operation_stage_t::cancelling_k &&
            operation.request->deadline)
            operation.flags = static_cast<operation_flags_t>(operation.flags | operation_expired_k);
        if (operation.accepted != absent_k) {
            auto& accepted = socket_slots[operation.accepted];
            accepted.stage = socket_stage_t::open_k;
            if (completion.res >= 0) {
                operation.result = registered_socket_t {operation.accepted}.handle();
                if (stage != engine_stage_t::running_k || (operation.socket_slot->flags & socket_retiring_k))
                    retire(accepted);
            }
            else vacate(accepted);
        }
        if (completion.flags & IORING_CQE_F_BUFFER) {
            --available_buffers;
            operation.buffer = completion.flags >> IORING_CQE_BUFFER_SHIFT;
            buffers[operation.buffer].flags = buffer_leased_k;
        }
        if (completion.res != -ENOBUFS || operation.stage == operation_stage_t::cancelling_k ||
            stage != engine_stage_t::running_k)
            complete(operation);
        else {
            operation.stage = operation_stage_t::waiting_k;
            push(waiting_operations, operation);
        }
        if (operation.socket_slot->flags & socket_retiring_k) retire(*operation.socket_slot);
    }
    void reap() noexcept {
        unsigned head {}, count {};
        io_uring_cqe* current {};
        io_uring_for_each_cqe(&ring, head, current) {
            completion(*current);
            ++count;
        }
        if (!count) return;
        io_uring_cq_advance(&ring, count);
        tally(statistics.completions, count);
    }
    int collect(span<io_completion_t> output) noexcept {
        std::size_t count {};
        while (count != output.size()) {
            auto* operation = pop(completed_operations);
            if (!operation) break;
            auto result = (operation->flags & operation_expired_k) && operation->result == -ECANCELED
                              ? -ETIMEDOUT
                              : operation->result;
            auto index = operation->buffer;
            byte_t* data = index != absent_k ? receive_data(index).data() : nullptr;
            std::uintptr_t lease = index != absent_k ? static_cast<std::uintptr_t>(index) + 1 : 0;
            output[count++] = {operation->request, result, data,
                               data && result >= 0 ? static_cast<std::size_t>(result) : 0, lease};
            vacate(*operation);
        }
        return static_cast<int>(count);
    }
    void maintain() noexcept {
        if (fault) return;
        for (auto retry = std::exchange(waiting_operations, {}); auto* operation = pop(retry);)
            if (start_operation(*operation) != ucall_status_success_k) fault = -EIO;
    }
    int poll(span<io_completion_t> output, io_wait_t policy, std::uint64_t deadline = 0) noexcept {
        if (!is_open()) return -EBADF;
        for (;;) {
            reap();
            maintain();
            if (fault) return fault;
            int count = collect(output);
            if (count) return count;
            unsigned wait = policy == io_wait_t::blocking_k && (!deadline || monotonic_ns() < deadline) ? 1 : 0;
            int result = enter(wait, deadline);
            if (result < 0) return result;
            reap();
            maintain();
            count = collect(output);
            if (count || policy == io_wait_t::nonblocking_k || (deadline && monotonic_ns() >= deadline)) return count;
        }
    }
    template <typename function_type_>
    static int retry_interrupted(function_type_ function) noexcept {
        int result;
        do { result = function(); } while (result == -EINTR);
        return result;
    }
    bool unregister_files() noexcept {
        if (!(registrations & registration_files_k)) return true;
        int result = retry_interrupted([&] { return io_uring_unregister_files(&ring); });
        if (result && result != -ENXIO) {
            fault = result;
            return false;
        }
        registrations = static_cast<registration_flags_t>(registrations & ~registration_files_k);
        return true;
    }
    void discard(std::uint64_t user_data) noexcept {
        auto kind = static_cast<std::uintptr_t>(user_data) & 7;
        auto* pointer = reinterpret_cast<void*>(static_cast<std::uintptr_t>(user_data) & ~std::uintptr_t {7});
        if (kind == operation_tag_k) {
            auto& operation = *static_cast<operation_t*>(pointer);
            operation.result = -ECANCELED;
            complete(operation);
            if (operation.accepted != absent_k) vacate(socket_slots[operation.accepted]);
        }
        else if (kind == control_tag_k) control.result = -ECANCELED;
        else if (kind == close_tag_k) {
            auto& owner = *static_cast<socket_slot_t*>(pointer);
            if (owner.stage == socket_stage_t::closing_k) owner.stage = socket_stage_t::open_k;
        }
    }
    void discard_unsubmitted() noexcept {
        auto head = io_uring_smp_load_acquire(ring.sq.khead);
        for (auto i = head; i != ring.sq.sqe_tail; ++i) discard(ring.sq.sqes[i & ring.sq.ring_mask].user_data);
        ring.sq.sqe_head = ring.sq.sqe_tail = head;
        io_uring_smp_store_release(ring.sq.ktail, head);
    }
    bool drain_after_fault() noexcept {
        stage = engine_stage_t::recovering_k;
        discard_unsubmitted();
        if (!cancel_synchronously() || !unregister_files()) return false;
        reap();
        while (has_kernel_work()) {
            int result = retry_interrupted(
                [&] { return io_uring_enter(ring.ring_fd, 0, 1, IORING_ENTER_GETEVENTS, nullptr); });
            if (result < 0) {
                fault = result;
                return false;
            }
            reap();
        }
        return true;
    }
    bool cancel_synchronously() noexcept {
        io_uring_sync_cancel_reg cancellation {};
        cancellation.flags = IORING_ASYNC_CANCEL_ANY | IORING_ASYNC_CANCEL_ALL;
        cancellation.timeout.tv_sec = -1;
        cancellation.timeout.tv_nsec = -1;
        int result = retry_interrupted([&] { return io_uring_register_sync_cancel(&ring, &cancellation); });
        if (result >= 0 || result == -ENOENT) return true;
        fault = result;
        return false;
    }
    void stop() noexcept {
        if (!is_open()) return;
        stage = engine_stage_t::stopping_k;
        if (!fault) {
            for (auto& operation : operations)
                if (operation.request && operation.stage != operation_stage_t::completed_k &&
                    operation.request->operation != io_operation_t::close_k) {
                    [[maybe_unused]] ucall_status_t const cancelled = cancel(*operation.request);
                }
            for (auto& owner : socket_slots)
                if (owner.stage != socket_stage_t::vacant_k) retire(owner);
            while (has_kernel_work() && !fault) {
                int result = enter(1, 0);
                if (result < 0) {
                    fault = result;
                    break;
                }
                reap();
            }
        }
        // Failed submission must not bypass terminal CQEs that still reference caller memory.
        bool retired = fault ? drain_after_fault() : unregister_files();
        if (receive_ring && retired) {
            int result = retry_interrupted(
                [&] { return io_uring_free_buf_ring(&ring, receive_ring, buffer_count, 0); });
            if (result) {
                fault = result;
                retired = false;
            }
            else receive_ring = nullptr;
        }
        if (!retired) {
            // A failed retirement barrier must not make registered memory reusable.
            [[maybe_unused]] storage_t* const leaked = storage.release();
        }
        io_uring_queue_exit(&ring);
        stage = engine_stage_t::stopped_k;
        for (auto& owner : socket_slots) owner.stage = socket_stage_t::vacant_k;
    }
};

using linux_uring612_engine_t = linux_uring612_engine<>;

} // namespace unum::ucall
