/**
 *  @file include/ucall/uring.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Registered socket and receive ownership for the Linux completion engines.
 */
#pragma once

#include <optional>

#include "ucall/io.hpp"

namespace unum::ucall {

/** The high bit separates registered transport handles from process file descriptors. */
struct registered_socket_t {
    unsigned index {};
    static constexpr descriptor_t tag_k = descriptor_t {1} << (sizeof(descriptor_t) * CHAR_BIT - 2);
    descriptor_t handle() const noexcept { return tag_k | static_cast<descriptor_t>(index); }
    static bool contains(descriptor_t handle) noexcept { return handle >= tag_k; }
    static unsigned index_of(descriptor_t handle) noexcept { return static_cast<unsigned>(handle & ~tag_k); }
};

/** One-shot requests and multishot streams share the same registered resource lifetimes. */
template <ucall_io_backend_t backend_, typename allocator_type_ = st::default_allocator<byte_t>>
struct linux_uring_engine {
    static_assert(backend_ == ucall_io_backend_linux_uring612_k || backend_ == ucall_io_backend_linux_uring700_k);
    using allocator_t = allocator_type_;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    template <typename value_type_>
    using vector = st::basic_vector<value_type_, rebound_allocator<value_type_>>;
    template <typename other_allocator_type_>
    using rebind_allocator = linux_uring_engine<backend_, other_allocator_type_>;
    enum class engine_stage_t : std::uint8_t { idle_k, running_k, stopping_k, recovering_k, stopped_k };
    enum class operation_stage_t : std::uint8_t { waiting_k, submitted_k, cancelling_k, completed_k };
    enum class resource_stage_t : std::uint8_t { vacant_k, installing_k, open_k, closing_k, closed_k };
    enum class receive_stage_t : std::uint8_t { idle_k, submitted_k, cancelling_k, ended_k };
    enum operation_flags_t : std::uint8_t {
        operation_none_k = 0,
        operation_expired_k = 1,
        operation_backlog_k = 2,
        operation_timed_k = 4
    };
    enum resource_flags_t : std::uint8_t {
        resource_none_k = 0,
        resource_retiring_k = 1,
        resource_paused_k = 2,
        resource_leased_k = 4,
        resource_rearming_k = 8
    };
    enum registration_flags_t : std::uint8_t { registration_none_k = 0, registration_files_k = 1 };
    enum buffer_flags_t : std::uint8_t { buffer_none_k = 0, buffer_leased_k = 1 };
    static constexpr unsigned absent_k = std::numeric_limits<unsigned>::max();
    static constexpr std::uintptr_t operation_tag_k = 0, control_tag_k = 1, receive_tag_k = 3, close_tag_k = 4,
                                    cancel_tag_k = 7;
    struct resource_t;
    struct alignas(8) operation_t {
        io_request_t* request {};
        resource_t* resource {};
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
    struct alignas(8) resource_t {
        unsigned index {}, next {absent_k}, queued_buffers {};
        unsigned receive_head {absent_k}, receive_tail {absent_k};
        operation_t* receive_request {};
        operation_t* close_request {};
        std::uint64_t serial {};
        vector<byte_t> backlog;
        std::size_t backlog_offset {};
        descriptor_t terminal {};
        resource_stage_t stage {resource_stage_t::vacant_k};
        receive_stage_t receive_stage {receive_stage_t::idle_k};
        resource_flags_t flags {resource_none_k};
        explicit resource_t(allocator_t const& allocator) noexcept : backlog(allocator) {}
        bool receive_in_flight() const noexcept {
            return receive_stage == receive_stage_t::submitted_k || receive_stage == receive_stage_t::cancelling_k;
        }
    };
    struct buffer_t {
        unsigned next {absent_k};
        int length {};
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
    vector<resource_t> resources;
    vector<buffer_t> buffers;
    allocated_ptr<storage_t, allocator_t> storage;
    operation_list_t free_operations, completed_operations, waiting_operations, timed_operations;
    unsigned free_resources {absent_k}, vacant_resources {}, rearming_resources {absent_k};
    unsigned buffer_count {}, buffer_mask {}, pending_sqes {}, available_buffers {};
    std::size_t page {};
    control_t control {};
    std::uint64_t next_serial {};
    engine_stage_t stage {engine_stage_t::idle_k};
    registration_flags_t registrations {registration_none_k};
    int fault {};

    explicit linux_uring_engine(allocator_t const& instance = {}) noexcept
        : allocator(instance), operations(rebound_allocator<operation_t> {instance}),
          resources(rebound_allocator<resource_t> {instance}), buffers(rebound_allocator<buffer_t> {instance}),
          storage(nullptr, allocator_delete<storage_t, allocator_t> {instance}) {}
    linux_uring_engine(linux_uring_engine const&) = delete;
    linux_uring_engine& operator=(linux_uring_engine const&) = delete;
    linux_uring_engine(linux_uring_engine&&) = delete;
    linux_uring_engine& operator=(linux_uring_engine&&) = delete;
    ~linux_uring_engine() noexcept { stop(); }

    bool is_open() const noexcept { return stage != engine_stage_t::idle_k && stage != engine_stage_t::stopped_k; }
    bool has_kernel_work() const noexcept {
        if (!control.result) return true;
        for (auto const& operation : operations)
            if (operation.in_flight()) return true;
        for (auto const& owner : resources)
            if (owner.receive_in_flight() || owner.stage == resource_stage_t::closing_k) return true;
        return false;
    }

    static std::uintptr_t tag(void* pointer, std::uintptr_t kind) noexcept {
        return reinterpret_cast<std::uintptr_t>(pointer) | kind;
    }
    resource_t* resource(descriptor_t handle) noexcept {
        if (!registered_socket_t::contains(handle)) return nullptr;
        auto index = registered_socket_t::index_of(handle);
        return index < resources.size() && (resources[index].stage != resource_stage_t::vacant_k) ? &resources[index]
                                                                                                  : nullptr;
    }
    byte_t* receive_data(unsigned index) noexcept {
        return storage->receive.data() + static_cast<std::size_t>(index) * page;
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
    void vacate(resource_t& owner) noexcept {
        // A socket can close before maintain() drains the re-arm list that shares its link.
        if (owner.flags & resource_rearming_k)
            for (auto* link = &rearming_resources; *link != absent_k; link = &resources[*link].next)
                if (*link == owner.index) {
                    *link = owner.next;
                    break;
                }
        owner.stage = resource_stage_t::vacant_k;
        owner.next = free_resources;
        free_resources = owner.index;
        ++vacant_resources;
    }
    void rearm(resource_t& owner) noexcept {
        if (owner.flags & resource_rearming_k) return;
        owner.flags = static_cast<resource_flags_t>(owner.flags | resource_rearming_k);
        owner.next = rearming_resources;
        rearming_resources = owner.index;
    }
    static __kernel_timespec timespec_of(std::uint64_t nanoseconds) noexcept {
        return {static_cast<__kernel_time64_t>(nanoseconds / 1'000'000'000),
                static_cast<long long>(nanoseconds % 1'000'000'000)};
    }
    io_uring_sqe* entry(unsigned count = 1) noexcept {
        if constexpr (backend_ == ucall_io_backend_linux_uring700_k) {
            if (pending_sqes + count > ring.sq.ring_entries && enter(0, 0) < 0) return nullptr;
            if (pending_sqes + count > ring.sq.ring_entries) return nullptr;
            auto* result = &ring.sq.sqes[pending_sqes++];
            io_uring_initialize_sqe(result);
            return result;
        }
        else {
            if (io_uring_sq_space_left(&ring) < count && io_uring_submit(&ring) < 0) return nullptr;
            return io_uring_sq_space_left(&ring) < count ? nullptr : io_uring_get_sqe(&ring);
        }
    }
    int enter(unsigned wait, std::uint64_t deadline) noexcept {
        if constexpr (backend_ == ucall_io_backend_linux_uring700_k) {
            auto timeout = timespec_of(deadline);
            io_uring_getevents_arg arguments {};
            arguments.ts = deadline ? reinterpret_cast<std::uintptr_t>(&timeout) : 0;
            unsigned flags = IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG | IORING_ENTER_ABS_TIMER |
                             (ring.int_flags & IORING_ENTER_REGISTERED_RING);
            int result = io_uring_enter2(ring.enter_ring_fd, pending_sqes, wait, flags, &arguments, sizeof(arguments));
            if (result >= 0) {
                auto submitted = static_cast<unsigned>(result);
                pending_sqes -= submitted;
                if (pending_sqes)
                    std::memmove(ring.sq.sqes, ring.sq.sqes + submitted, pending_sqes * sizeof(io_uring_sqe));
            }
            return result == -ETIME || result == -EINTR ? 0 : result;
        }
        else {
            // Deferred task work only runs inside an enter that asks for events.
            if (!wait) return io_uring_submit_and_get_events(&ring);
            auto now = deadline ? monotonic_ns() : 0;
            auto timeout = timespec_of(deadline > now ? deadline - now : 0);
            io_uring_cqe* completion {};
            int result = deadline ? io_uring_submit_and_wait_timeout(&ring, &completion, wait, &timeout, nullptr)
                                  : io_uring_submit_and_wait(&ring, wait);
            return result == -ETIME || result == -EINTR ? 0 : result;
        }
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
        if (st::failed(operations.resize(capacity)) || st::failed(resources.reserve(capacity)) ||
            st::failed(buffers.resize(buffer_count)) ||
            st::failed(storage->receive.resize(static_cast<std::size_t>(buffer_count) * page)))
            return ucall_status_out_of_memory_k;
        for (auto& operation : operations) push(free_operations, operation);
        resources.clear();
        for (std::size_t i = 0; i != capacity; ++i) {
            if (st::failed(resources.emplace_back(allocator))) return ucall_status_out_of_memory_k;
            resources[i].index = static_cast<unsigned>(i);
        }
        for (auto i = resources.size(); i--;) vacate(resources[i]);
        io_uring_params parameters {};
        parameters.flags = IORING_SETUP_CLAMP | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_SINGLE_ISSUER |
                           IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_NO_SQARRAY;
        if constexpr (backend_ == ucall_io_backend_linux_uring700_k) parameters.flags |= IORING_SETUP_SQ_REWIND;
        // Each one-shot operation may carry a linked timeout.
        auto entries = static_cast<unsigned>(
            std::min(depth, static_cast<std::size_t>(std::numeric_limits<unsigned>::max() / 2)) * 2);
        int result = io_uring_queue_init_params(entries, &ring, &parameters);
        if (result < 0) return result == -ENOMEM ? ucall_status_out_of_memory_k : ucall_status_unsupported_k;
        (void)io_uring_register_ring_fd(&ring);
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
        result = io_uring_register_files_sparse(&ring, static_cast<unsigned>(resources.size()));
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
            io_uring_buf_ring_add(receive_ring, receive_data(i), static_cast<unsigned>(page),
                                  static_cast<unsigned short>(i), buffer_mask, i);
        io_uring_buf_ring_advance(receive_ring, buffer_count);
        return ucall_status_success_k;
    }
    resource_t* reserve() noexcept {
        if (free_resources == absent_k) return nullptr;
        auto index = free_resources;
        auto& result = resources[index];
        free_resources = result.next;
        --vacant_resources;
        auto backlog = std::move(result.backlog);
        result = resource_t {allocator};
        result.backlog = std::move(backlog);
        result.backlog.clear();
        result.index = index;
        result.stage = resource_stage_t::installing_k;
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
        target->stage = resource_stage_t::open_k;
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
        target->stage = resource_stage_t::open_k;
        auto handle = registered_socket_t {target->index}.handle();
        submission = entry();
        if (!submission) {
            (void)close_socket(handle);
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
            (void)close_socket(handle);
            return result;
        }
        return handle;
    }
    void recycle(unsigned index) noexcept {
        auto& buffer = buffers[index];
        buffer = {};
        ++available_buffers;
        io_uring_buf_ring_add(receive_ring, receive_data(index), static_cast<unsigned>(page),
                              static_cast<unsigned short>(index), buffer_mask, 0);
        io_uring_buf_ring_advance(receive_ring, 1);
    }
    void release(io_completion_t const& completion) noexcept {
        if (!is_open() || !completion.lease) return;
        if (completion.lease >= static_cast<std::uintptr_t>(registered_socket_t::tag_k)) {
            auto* owner = resource(static_cast<descriptor_t>(completion.lease));
            if (!owner || !(owner->flags & resource_leased_k)) return;
            owner->flags = static_cast<resource_flags_t>(owner->flags & ~resource_leased_k);
            owner->backlog_offset += completion.length;
            if (owner->backlog_offset == owner->backlog.size()) {
                owner->backlog.clear();
                owner->backlog_offset = 0;
            }
            if ((owner->flags & resource_paused_k)) park_receive(*owner);
            if (!(owner->flags & resource_retiring_k)) deliver_receive(*owner);
            if ((owner->flags & resource_retiring_k)) retire(*owner);
            return;
        }
        auto index = static_cast<unsigned>(completion.lease - 1);
        if (index < buffers.size() && (buffers[index].flags & buffer_leased_k)) {
            if (receive_ring) recycle(index);
            else buffers[index].flags = buffer_none_k;
        }
    }
    void park_receive(resource_t& owner) noexcept {
        // Late CQEs keep their finite ring credits until cancellation stops prefetch.
        if ((owner.flags & resource_leased_k) || owner.receive_stage == receive_stage_t::cancelling_k) return;
        if (owner.backlog_offset) {
            auto remaining = owner.backlog.size() - owner.backlog_offset;
            if (remaining) std::memmove(owner.backlog.data(), owner.backlog.data() + owner.backlog_offset, remaining);
            (void)owner.backlog.resize(remaining);
            owner.backlog_offset = 0;
        }
        while (owner.receive_head != absent_k) {
            auto index = owner.receive_head;
            auto& buffer = buffers[index];
            if (buffer.length > 0) {
                auto previous = owner.backlog.size();
                auto length = static_cast<std::size_t>(buffer.length);
                if (length > std::numeric_limits<std::size_t>::max() - previous) {
                    fault = -EOVERFLOW;
                    return;
                }
                if (st::failed(owner.backlog.resize(previous + length))) {
                    fault = -ENOMEM;
                    return;
                }
                std::memcpy(owner.backlog.data() + previous, receive_data(index), length);
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
        if constexpr (backend_ == ucall_io_backend_linux_uring700_k) {
            auto* owner = resource(descriptor);
            if (!owner || (owner->flags & resource_retiring_k) || owner->receive_request) return;
            owner->flags = static_cast<resource_flags_t>(owner->flags | resource_paused_k);
            park_receive(*owner);
            if (owner->receive_stage == receive_stage_t::submitted_k) {
                if (!cancel_stream(*owner, receive_tag_k)) fault = -EIO;
                else owner->receive_stage = receive_stage_t::cancelling_k;
            }
        }
    }
    void queue_buffer(resource_t& owner, unsigned index, int length) noexcept {
        auto& buffer = buffers[index];

        buffer.length = length;
        buffer.next = absent_k;
        if (owner.receive_tail != absent_k) buffers[owner.receive_tail].next = index;
        else owner.receive_head = index;
        owner.receive_tail = index;
        ++owner.queued_buffers;
    }
    void deliver_receive(resource_t& owner) noexcept {
        auto* operation = owner.receive_request;
        if (!operation) return;
        if (owner.backlog_offset != owner.backlog.size()) {
            if (owner.flags & resource_leased_k) return;
            operation->flags = static_cast<operation_flags_t>(operation->flags | operation_backlog_k);
            operation->result = static_cast<descriptor_t>(
                std::min(owner.backlog.size() - owner.backlog_offset, std::min(operation->request->length, page)));
            owner.flags = static_cast<resource_flags_t>(owner.flags | resource_leased_k);
        }
        else if (owner.receive_head != absent_k) {
            auto index = owner.receive_head;
            owner.receive_head = buffers[index].next;
            if (owner.receive_head == absent_k) owner.receive_tail = absent_k;
            --owner.queued_buffers;
            buffers[index].flags = buffer_leased_k;
            operation->buffer = index;
            operation->result = buffers[index].length;
        }
        else if (owner.receive_stage == receive_stage_t::ended_k) operation->result = owner.terminal;
        else return;
        owner.receive_request = nullptr;
        if (operation->flags & operation_timed_k) unlink(timed_operations, *operation);
        complete(*operation);
    }
    bool start_receive(resource_t& owner) noexcept {
        if (owner.receive_stage != receive_stage_t::idle_k || (owner.flags & resource_paused_k) ||
            (owner.flags & resource_retiring_k) || (stage != engine_stage_t::running_k) || !available_buffers)
            return true;
        auto* submission = entry();
        if (!submission) return false;
        io_uring_prep_recv_multishot(submission, static_cast<int>(owner.index), nullptr, 0, 0);
        submission->flags |= IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
        submission->buf_group = 0;
        io_uring_sqe_set_data64(submission, tag(&owner, receive_tag_k));
        owner.receive_stage = receive_stage_t::submitted_k;

        return true;
    }
    bool submit(io_request_t& request) noexcept {
        auto* owner = resource(request.descriptor);
        if (!owner || (owner->flags & resource_retiring_k)) return false;
        auto* operation = pop(free_operations);
        if (!operation) return false;
        *operation = {};
        operation->request = &request;
        operation->resource = owner;
        if (request.operation == io_operation_t::close_k) {
            owner->close_request = operation;
            retire(*owner);
            return true;
        }
        if constexpr (backend_ == ucall_io_backend_linux_uring700_k) {
            if (request.operation == io_operation_t::receive_k) {
                owner->flags = static_cast<resource_flags_t>(owner->flags & ~resource_paused_k);
                owner->receive_request = operation;
                deliver_receive(*owner);
                if (operation->stage == operation_stage_t::completed_k) return true;
                if (!start_receive(*owner)) {
                    owner->receive_request = nullptr;
                    vacate(*operation);
                    return false;
                }
                if (!owner->receive_in_flight()) rearm(*owner);
                if (request.deadline) {
                    operation->flags = static_cast<operation_flags_t>(operation->flags | operation_timed_k);
                    push(timed_operations, *operation);
                }
                return true;
            }
        }
        if (start_operation(*operation)) return true;
        vacate(*operation);
        return false;
    }
    bool start_operation(operation_t& operation) noexcept {
        auto& request = *operation.request;
        auto* owner = operation.resource;
        if (request.operation == io_operation_t::accept_k && operation.accepted == absent_k) {
            auto* accepted = reserve();
            if (!accepted) {
                push(waiting_operations, operation);
                return true;
            }
            operation.accepted = accepted->index;
        }
        if (request.operation == io_operation_t::receive_k && !available_buffers) {
            push(waiting_operations, operation);
            return true;
        }
        auto* submission = entry(request.deadline ? 2 : 1);
        if (!submission) {
            if (operation.accepted != absent_k) vacate(resources[operation.accepted]);
            return false;
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

        return true;
    }
    bool cancel_stream(resource_t& owner, std::uintptr_t kind) noexcept {
        auto* submission = entry();
        if (!submission) return false;
        io_uring_prep_cancel64(submission, tag(&owner, kind), 0);
        io_uring_sqe_set_data64(submission, cancel_tag_k);
        return true;
    }
    bool cancel(io_request_t& request) noexcept {
        for (auto& operation : operations)
            if (operation.request == &request) {
                if (request.operation == io_operation_t::close_k) return true;
                if ((operation.stage == operation_stage_t::completed_k) ||
                    (operation.stage == operation_stage_t::cancelling_k))
                    return true;
                if (!operation.in_flight()) {
                    if (operation.resource->receive_request != &operation) unlink(waiting_operations, operation);
                    else {
                        operation.resource->receive_request = nullptr;
                        if (operation.flags & operation_timed_k) unlink(timed_operations, operation);
                    }
                    operation.result = -ECANCELED;
                    complete(operation);
                    if constexpr (backend_ == ucall_io_backend_linux_uring700_k)
                        if (request.operation == io_operation_t::receive_k) receive_pause(request.descriptor);
                    return true;
                }
                operation.stage = operation_stage_t::cancelling_k;
                auto* submission = entry();
                if (!submission) {
                    operation.stage = operation_stage_t::submitted_k;
                    return false;
                }
                io_uring_prep_cancel64(submission, tag(&operation, operation_tag_k), 0);
                io_uring_sqe_set_data64(submission, cancel_tag_k);
                return true;
            }
        return false;
    }
    void retire(resource_t& owner) noexcept {
        if (stage == engine_stage_t::recovering_k) return;
        if (!(owner.flags & resource_retiring_k)) {
            owner.flags = static_cast<resource_flags_t>(owner.flags | resource_retiring_k);
            for (auto& operation : operations)
                if (operation.request && operation.resource == &owner &&
                    operation.stage != operation_stage_t::completed_k &&
                    operation.request->operation != io_operation_t::close_k)
                    if (!cancel(*operation.request)) fault = -EIO;
            if (owner.receive_stage == receive_stage_t::submitted_k) {
                if (!cancel_stream(owner, receive_tag_k)) fault = -EIO;
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
        if (owner.stage == resource_stage_t::installing_k || owner.receive_in_flight() ||
            owner.stage == resource_stage_t::closing_k)
            return;
        for (auto const& operation : operations)
            if (operation.in_flight() && operation.resource == &owner) return;
        if (owner.stage == resource_stage_t::closed_k) {
            if (!(owner.flags & resource_leased_k)) finish_close(owner);
            return;
        }
        auto* submission = entry();
        if (!submission) {
            fault = -EIO;
            return;
        }
        io_uring_prep_close_direct(submission, owner.index);
        io_uring_sqe_set_data64(submission, tag(&owner, close_tag_k));
        owner.stage = resource_stage_t::closing_k;
    }
    int close_socket(descriptor_t descriptor) noexcept {
        if (!is_open()) return 0;
        auto* owner = resource(descriptor);
        if (!owner) return 0;
        auto serial = owner->serial;
        retire(*owner);
        while ((owner->stage != resource_stage_t::vacant_k) && owner->serial == serial && !fault) {
            int result = enter(1, 0);
            if (result < 0) {
                fault = result;
                break;
            }
            reap();
        }
        return fault;
    }
    void finish_close(resource_t& owner) noexcept {
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
            auto& owner = *static_cast<resource_t*>(pointer);

            owner.stage = resource_stage_t::open_k;
            if (completion.res < 0) {
                fault = completion.res;
                return;
            }
            owner.stage = resource_stage_t::closed_k;

            retire(owner);
            return;
        }
        if (kind == receive_tag_k) {
            auto& owner = *static_cast<resource_t*>(pointer);
            if (!(completion.flags & IORING_CQE_F_MORE)) { owner.receive_stage = receive_stage_t::idle_k; }
            if (completion.flags & IORING_CQE_F_BUFFER) {
                --available_buffers;
                unsigned index = completion.flags >> IORING_CQE_BUFFER_SHIFT;
                if ((owner.flags & resource_retiring_k) || (stage != engine_stage_t::running_k)) recycle(index);
                else {
                    queue_buffer(owner, index, completion.res);
                    if (owner.flags & resource_paused_k) park_receive(owner);
                    else deliver_receive(owner);
                    // One open socket may hold at most its fair share of the shared receive ring.
                    assert(resources.size() > vacant_resources);
                    if (owner.queued_buffers >= buffer_count / (resources.size() - vacant_resources) &&
                        owner.receive_stage == receive_stage_t::submitted_k) {
                        if (!cancel_stream(owner, receive_tag_k)) fault = -EIO;
                        else owner.receive_stage = receive_stage_t::cancelling_k;
                    }
                }
            }
            else if (completion.res != -ENOBUFS && completion.res != -ECANCELED) {
                owner.receive_stage = receive_stage_t::ended_k;
                owner.terminal = completion.res;
                deliver_receive(owner);
            }
            if ((owner.flags & resource_paused_k) && !owner.receive_in_flight()) park_receive(owner);
            if (owner.flags & resource_retiring_k) retire(owner);
            else if (owner.receive_stage == receive_stage_t::idle_k) rearm(owner);
            return;
        }
        auto& operation = *static_cast<operation_t*>(pointer);
        operation.result = completion.res;
        // Only the linked timeout cancels an operation that was not asked to cancel.
        if (completion.res == -ECANCELED && operation.stage != operation_stage_t::cancelling_k &&
            operation.request->deadline)
            operation.flags = static_cast<operation_flags_t>(operation.flags | operation_expired_k);
        if (operation.accepted != absent_k) {
            auto& accepted = resources[operation.accepted];
            accepted.stage = resource_stage_t::open_k;
            if (completion.res >= 0) {
                operation.result = registered_socket_t {operation.accepted}.handle();
                if (stage != engine_stage_t::running_k || (operation.resource->flags & resource_retiring_k))
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
        if (operation.resource->flags & resource_retiring_k) retire(*operation.resource);
    }
    void reap() noexcept {
        unsigned head {}, count {};
        io_uring_cqe* current {};
        io_uring_for_each_cqe(&ring, head, current) {
            completion(*current);
            ++count;
        }
        if (count) io_uring_cq_advance(&ring, count);
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
            byte_t* data {};
            std::uintptr_t lease {};
            if (operation->flags & operation_backlog_k) {
                data = operation->resource->backlog.data() + operation->resource->backlog_offset;
                lease = static_cast<std::uintptr_t>(registered_socket_t {operation->resource->index}.handle());
            }
            else if (index != absent_k) {
                data = receive_data(index);
                lease = static_cast<std::uintptr_t>(index) + 1;
            }
            output[count++] = {operation->request, result, data,
                               data && result >= 0 ? static_cast<std::size_t>(result) : 0, lease};
            vacate(*operation);
        }
        return static_cast<int>(count);
    }
    void maintain() noexcept {
        if (fault) return;
        if (timed_operations.head != absent_k) {
            auto now = monotonic_ns();
            for (auto index = timed_operations.head; index != absent_k;) {
                auto& operation = operations[index];
                index = operation.next;
                if (operation.request->deadline > now) continue;
                operation.flags = static_cast<operation_flags_t>(operation.flags | operation_expired_k);
                (void)cancel(*operation.request);
            }
        }
        for (auto retry = std::exchange(waiting_operations, {}); auto* operation = pop(retry);)
            if (!start_operation(*operation)) fault = -EIO;
        for (auto index = std::exchange(rearming_resources, absent_k); index != absent_k;) {
            auto& owner = resources[index];
            index = owner.next;
            owner.flags = static_cast<resource_flags_t>(owner.flags & ~resource_rearming_k);
            if (!owner.receive_request || owner.receive_in_flight()) continue;
            if (!start_receive(owner)) fault = -EIO;
            else if (!available_buffers) rearm(owner);
        }
    }
    int poll(span<io_completion_t> output, io_wait_t policy, std::uint64_t deadline = 0) noexcept {
        if (!is_open()) return -EBADF;
        for (;;) {
            reap();
            maintain();
            if (fault) return fault;
            int count = collect(output);
            if (count) return count;
            auto now = monotonic_ns();
            auto wait_deadline = deadline;
            for (auto index = timed_operations.head; index != absent_k; index = operations[index].next) {
                auto expiry = operations[index].request->deadline;
                wait_deadline = !wait_deadline ? expiry : std::min(wait_deadline, expiry);
            }
            unsigned wait = policy == io_wait_t::blocking_k && (!wait_deadline || now < wait_deadline) ? 1 : 0;
            int result = enter(wait, wait_deadline);
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
            if (operation.accepted != absent_k) vacate(resources[operation.accepted]);
        }
        else if (kind == control_tag_k) control.result = -ECANCELED;
        else if (kind == receive_tag_k) {
            auto& owner = *static_cast<resource_t*>(pointer);
            if (owner.receive_in_flight()) { owner.receive_stage = receive_stage_t::idle_k; }
        }
        else if (kind == close_tag_k) {
            auto& owner = *static_cast<resource_t*>(pointer);
            if (owner.stage == resource_stage_t::closing_k) { owner.stage = resource_stage_t::open_k; }
        }
    }
    void discard_unsubmitted() noexcept {
        if constexpr (backend_ == ucall_io_backend_linux_uring700_k) {
            for (unsigned i = 0; i != pending_sqes; ++i) discard(ring.sq.sqes[i].user_data);
            pending_sqes = 0;
        }
        else {
            auto head = io_uring_smp_load_acquire(ring.sq.khead);
            for (auto i = head; i != ring.sq.sqe_tail; ++i) discard(ring.sq.sqes[i & ring.sq.ring_mask].user_data);
            ring.sq.sqe_head = ring.sq.sqe_tail = head;
            io_uring_smp_store_release(ring.sq.ktail, head);
        }
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
                    operation.request->operation != io_operation_t::close_k)
                    (void)cancel(*operation.request);
            for (auto& owner : resources)
                if (owner.stage != resource_stage_t::vacant_k) retire(owner);
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
            (void)storage.release();
        }
        io_uring_queue_exit(&ring);
        stage = engine_stage_t::stopped_k;
        for (auto& owner : resources) owner.stage = resource_stage_t::vacant_k;
    }
};

using linux_uring612_engine_t = linux_uring_engine<ucall_io_backend_linux_uring612_k>;
using linux_uring700_engine_t = linux_uring_engine<ucall_io_backend_linux_uring700_k>;

} // namespace unum::ucall
