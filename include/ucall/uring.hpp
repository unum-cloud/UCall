/**
 *  @file include/ucall/uring.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Registered socket, transmit, and receive ownership for the Linux completion engines.
 */
#pragma once

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
template <bool advanced_>
struct linux_uring_engine {
    static constexpr unsigned absent_k = std::numeric_limits<unsigned>::max();
    static constexpr std::uintptr_t operation_tag_k = 0, control_tag_k = 1, transmit_tag_k = 2, receive_tag_k = 3,
                                    close_tag_k = 4, cancel_tag_k = 7;
    struct resource_t;
    struct transmit_t;
    struct alignas(8) operation_t {
        io_request_t* request {};
        resource_t* resource {};
        transmit_t* transmit {};
        descriptor_t result {};
        unsigned accepted {absent_k}, buffer {absent_k};
        bool live {}, done {}, cancelling {}, timed_out {};
    };
    struct alignas(8) transmit_t {
        operation_t* operation {};
        resource_t* resource {};
        bool live {};
    };
    struct alignas(8) resource_t {
        unsigned index {};
        unsigned receive_head {absent_k}, receive_tail {absent_k};
        operation_t* receive_request {};
        operation_t* close_request {};
        std::uint64_t serial {};
        descriptor_t terminal {};
        int close_result {};
        bool occupied {}, installing {}, retiring {}, receive_live {}, receive_ended {}, close_live {}, file_closed {};
    };
    struct buffer_t {
        unsigned next {absent_k}, owner {absent_k};
        int length {};
        bool leased {};
    };
    struct alignas(8) control_t {
        int result {};
        bool live {};
    };

    struct storage_t {
        st::basic_vector<byte_t> transmit {}, receive {};
    };
    io_uring ring {};
    io_uring_buf_ring* receive_ring {};
    st::basic_vector<operation_t> operations {};
    st::basic_vector<transmit_t> transmissions {};
    st::basic_vector<resource_t> resources {};
    st::basic_vector<buffer_t> buffers {};
    std::unique_ptr<storage_t> storage {};
    unsigned buffer_count {}, buffer_mask {}, pending_sqes {}, available_buffers {};
    std::size_t page {}, live_operations {}, live_transmissions {}, live_streams {};
    control_t control {};
    std::uint64_t next_serial {};
    bool opened {}, buffers_registered {}, files_registered {}, stopping {}, recovering {};
    int fault {};

    linux_uring_engine() noexcept = default;
    linux_uring_engine(linux_uring_engine const&) = delete;
    ~linux_uring_engine() noexcept { stop(); }

    static std::uintptr_t tag(void* pointer, std::uintptr_t kind) noexcept {
        return reinterpret_cast<std::uintptr_t>(pointer) | kind;
    }
    resource_t* resource(descriptor_t handle) noexcept {
        if (!registered_socket_t::contains(handle)) return nullptr;
        auto index = registered_socket_t::index_of(handle);
        return index < resources.size() && resources[index].occupied ? &resources[index] : nullptr;
    }
    byte_t* receive_data(unsigned index) noexcept {
        return storage->receive.data() + static_cast<std::size_t>(index) * page;
    }
    byte_t* transmit_data(transmit_t& transmission) noexcept {
        return storage->transmit.data() + static_cast<std::size_t>(&transmission - transmissions.data()) * page;
    }
    io_uring_sqe* entry() noexcept {
        if constexpr (advanced_) {
            if (pending_sqes == ring.sq.ring_entries && enter(0, 0) < 0) return nullptr;
            if (pending_sqes == ring.sq.ring_entries) return nullptr;
            auto* result = &ring.sq.sqes[pending_sqes++];
            io_uring_initialize_sqe(result);
            return result;
        }
        else {
            auto* result = io_uring_get_sqe(&ring);
            if (!result) {
                if (io_uring_submit(&ring) < 0) return nullptr;
                result = io_uring_get_sqe(&ring);
            }
            return result;
        }
    }
    int enter(unsigned wait, std::uint64_t deadline) noexcept {
        __kernel_timespec timeout {};
        if (deadline) {
            auto now = monotonic_ns();
            auto duration = deadline > now ? deadline - now : 0;
            timeout.tv_sec = static_cast<__kernel_time64_t>(duration / 1'000'000'000);
            timeout.tv_nsec = static_cast<long long>(duration % 1'000'000'000);
        }
        if constexpr (advanced_) {
            io_uring_getevents_arg arguments {};
            arguments.ts = deadline ? reinterpret_cast<std::uintptr_t>(&timeout) : 0;
            unsigned flags = IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG;
            int result = io_uring_enter2(ring.ring_fd, pending_sqes, wait, flags, &arguments, sizeof(arguments));
            if (result >= 0) {
                auto submitted = static_cast<unsigned>(result);
                pending_sqes -= submitted;
                if (pending_sqes)
                    std::memmove(ring.sq.sqes, ring.sq.sqes + submitted, pending_sqes * sizeof(io_uring_sqe));
            }
            return result == -ETIME || result == -EINTR ? 0 : result;
        }
        else {
            int submitted = io_uring_submit(&ring);
            if (submitted < 0 || !wait) return submitted;
            io_uring_cqe* completion {};
            int result = deadline ? io_uring_wait_cqe_timeout(&ring, &completion, &timeout)
                                  : io_uring_wait_cqe(&ring, &completion);
            return result == -ETIME || result == -EINTR ? 0 : result;
        }
    }
    ucall_status_t open(std::size_t depth, std::size_t capacity) noexcept {
        if (!depth || !capacity) return ucall_status_invalid_argument_k;
        if (capacity > static_cast<std::size_t>(registered_socket_t::tag_k)) return ucall_status_overflow_k;
        if (opened || stopping) return ucall_status_invalid_argument_k;
        storage.reset(new (std::nothrow) storage_t);
        if (!storage) return ucall_status_out_of_memory_k;
        page = page_size();
        if (!page || capacity > std::numeric_limits<std::size_t>::max() / page) return ucall_status_overflow_k;
        // Pbuf ring IDs and head distances are 16-bit; the kernel permits 32768 entries.
        buffer_count = 1;
        while (buffer_count < capacity && buffer_count < 32768) buffer_count *= 2;
        buffer_mask = buffer_count - 1;
        available_buffers = buffer_count;
        if (st::failed(operations.resize(capacity)) || st::failed(transmissions.resize(capacity)) ||
            st::failed(resources.resize(capacity)) || st::failed(buffers.resize(buffer_count)) ||
            st::failed(storage->transmit.resize(capacity * page)) ||
            st::failed(storage->receive.resize(static_cast<std::size_t>(buffer_count) * page)))
            return ucall_status_out_of_memory_k;
        for (unsigned i = 0; i != resources.size(); ++i) resources[i].index = i;
        io_uring_params parameters {};
        parameters.flags = IORING_SETUP_CLAMP;
        if constexpr (advanced_)
            parameters.flags |= IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_NO_SQARRAY |
                                IORING_SETUP_SQ_REWIND;
        auto entries = static_cast<unsigned>(
            std::min(depth, static_cast<std::size_t>(std::numeric_limits<unsigned>::max())));
        int result = io_uring_queue_init_params(entries, &ring, &parameters);
        if (result < 0) return result == -ENOMEM ? ucall_status_out_of_memory_k : ucall_status_unsupported_k;
        opened = true;
        auto* probe = io_uring_get_probe_ring(&ring);
        bool supported = probe && (parameters.features & IORING_FEAT_NODROP) &&
                         (parameters.features & IORING_FEAT_EXT_ARG);
        for (auto opcode : {IORING_OP_SOCKET, IORING_OP_ACCEPT, IORING_OP_CONNECT, IORING_OP_RECV, IORING_OP_SEND_ZC,
                            IORING_OP_READ, IORING_OP_CLOSE, IORING_OP_ASYNC_CANCEL})
            supported = supported && io_uring_opcode_supported(probe, opcode);
        if (probe) io_uring_free_probe(probe);
        if (!supported) {
            stop();
            return ucall_status_unsupported_k;
        }
        result = io_uring_register_files_sparse(&ring, static_cast<unsigned>(resources.size()));
        if (result < 0) {
            stop();
            return ucall_status_unsupported_k;
        }
        files_registered = true;
        iovec transmit {};
        transmit.iov_base = storage->transmit.data();
        transmit.iov_len = storage->transmit.size();
        result = io_uring_register_buffers(&ring, &transmit, 1);
        if (result < 0) {
            stop();
            return result == -ENOMEM ? ucall_status_out_of_memory_k : ucall_status_unsupported_k;
        }
        buffers_registered = true;
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
        for (unsigned i = 0; i != resources.size(); ++i)
            if (!resources[i].occupied) {
                auto& result = resources[i];
                result = {};
                result.index = i;
                result.occupied = true;
                result.serial = ++next_serial;
                return &result;
            }
        return nullptr;
    }
    int wait_control() noexcept {
        while (control.live && !fault) {
            int result = enter(1, 0);
            if (result < 0) {
                fault = result;
                break;
            }
            reap();
        }
        return fault ? fault : control.result;
    }
    descriptor_t import_socket(descriptor_t descriptor) noexcept {
        if (descriptor < 0 || descriptor > std::numeric_limits<int>::max()) return -EINVAL;
        auto* target = reserve();
        if (!target) return -ENFILE;
        int raw = static_cast<int>(descriptor);
        int result = io_uring_register_files_update(&ring, target->index, &raw, 1);
        if (result != 1) {
            target->occupied = false;
            return result < 0 ? result : -EIO;
        }
        socket_close(descriptor);
        return registered_socket_t {target->index}.handle();
    }
    descriptor_t open_socket(int family) noexcept {
        auto* target = reserve();
        if (!target) return -ENFILE;
        auto* submission = entry();
        if (!submission) {
            target->occupied = false;
            return -EIO;
        }
        control = {};
        control.live = true;
        io_uring_prep_socket_direct(submission, family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP, target->index, 0);
        io_uring_sqe_set_data64(submission, tag(&control, control_tag_k));
        int result = wait_control();
        if (result < 0) {
            target->occupied = false;
            return result;
        }
        return registered_socket_t {target->index}.handle();
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
        if (!completion.lease) return;
        auto index = static_cast<unsigned>(completion.lease - 1);
        if (index < buffers.size() && buffers[index].leased) {
            if (receive_ring) recycle(index);
            else buffers[index].leased = false;
        }
    }
    void queue_buffer(resource_t& owner, unsigned index, int length) noexcept {
        auto& buffer = buffers[index];
        buffer.owner = owner.index;
        buffer.length = length;
        buffer.next = absent_k;
        if (owner.receive_tail != absent_k) buffers[owner.receive_tail].next = index;
        else owner.receive_head = index;
        owner.receive_tail = index;
    }
    void deliver_receive(resource_t& owner) noexcept {
        auto* operation = owner.receive_request;
        if (!operation) return;
        if (owner.receive_head != absent_k) {
            auto index = owner.receive_head;
            owner.receive_head = buffers[index].next;
            if (owner.receive_head == absent_k) owner.receive_tail = absent_k;
            buffers[index].leased = true;
            operation->buffer = index;
            operation->result = buffers[index].length;
            operation->done = true;
            owner.receive_request = nullptr;
        }
        else if (owner.receive_ended) {
            operation->result = owner.terminal;
            operation->done = true;
            owner.receive_request = nullptr;
        }
    }
    bool start_receive(resource_t& owner) noexcept {
        if (owner.receive_live || owner.receive_ended || owner.retiring || stopping || !available_buffers) return true;
        auto* submission = entry();
        if (!submission) return false;
        io_uring_prep_recv_multishot(submission, static_cast<int>(owner.index), nullptr, 0, 0);
        submission->flags |= IOSQE_FIXED_FILE | IOSQE_BUFFER_SELECT;
        submission->buf_group = 0;
        io_uring_sqe_set_data64(submission, tag(&owner, receive_tag_k));
        owner.receive_live = true;
        ++live_streams;
        return true;
    }
    bool submit(io_request_t& request) noexcept {
        auto* owner = resource(request.descriptor);
        if (!owner || owner->retiring) return false;
        operation_t* operation {};
        for (auto& candidate : operations)
            if (!candidate.request) {
                operation = &candidate;
                break;
            }
        if (!operation) return false;
        *operation = {};
        operation->request = &request;
        operation->resource = owner;
        if (request.operation == io_operation_t::close_k) {
            owner->close_request = operation;
            retire(*owner);
            return true;
        }
        if constexpr (advanced_) {
            if (request.operation == io_operation_t::receive_k) {
                owner->receive_request = operation;
                deliver_receive(*owner);
                if (!operation->done && !start_receive(*owner)) {
                    owner->receive_request = nullptr;
                    operation->request = nullptr;
                    return false;
                }
                return true;
            }
        }
        if (start_operation(*operation)) return true;
        operation->request = nullptr;
        return false;
    }
    bool start_operation(operation_t& operation) noexcept {
        auto& request = *operation.request;
        auto* owner = operation.resource;
        if (request.operation == io_operation_t::accept_k && operation.accepted == absent_k) {
            auto* accepted = reserve();
            if (!accepted) return true;
            accepted->installing = true;
            operation.accepted = accepted->index;
        }
        if (request.operation == io_operation_t::receive_k && !available_buffers) return true;
        if (request.operation == io_operation_t::send_k) {
            for (auto& transmission : transmissions)
                if (!transmission.live) {
                    operation.transmit = &transmission;
                    transmission = {&operation, owner, true};
                    break;
                }
            if (!operation.transmit) return true;
        }
        auto* submission = entry();
        if (!submission) {
            if (operation.transmit) operation.transmit->live = false;
            if (operation.accepted != absent_k) resources[operation.accepted].occupied = false;
            operation.request = nullptr;
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
            if (length) std::memcpy(transmit_data(*operation.transmit), request.data, length);
            io_uring_prep_send_zc_fixed(submission, static_cast<int>(owner->index), transmit_data(*operation.transmit),
                                        length, MSG_NOSIGNAL, 0, 0);
            ++live_transmissions;
            break;
        case io_operation_t::read_k:
            io_uring_prep_read(submission, static_cast<int>(owner->index), request.data, length, -1);
            break;
        case io_operation_t::close_k: break;
        }
        submission->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(submission, operation.transmit ? tag(operation.transmit, transmit_tag_k)
                                                               : tag(&operation, operation_tag_k));
        operation.live = true;
        ++live_operations;
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
                if (operation.done || operation.cancelling) return true;
                operation.cancelling = true;
                if (!operation.live) {
                    if (operation.resource->receive_request == &operation)
                        operation.resource->receive_request = nullptr;
                    operation.result = -ECANCELED;
                    operation.done = true;
                    return true;
                }
                auto* submission = entry();
                if (!submission) {
                    operation.cancelling = false;
                    return false;
                }
                io_uring_prep_cancel64(
                    submission,
                    operation.transmit ? tag(operation.transmit, transmit_tag_k) : tag(&operation, operation_tag_k), 0);
                io_uring_sqe_set_data64(submission, cancel_tag_k);
                return true;
            }
        return false;
    }
    void retire(resource_t& owner) noexcept {
        if (recovering) return;
        if (!owner.retiring) {
            owner.retiring = true;
            if (owner.receive_live && !cancel_stream(owner, receive_tag_k)) fault = -EIO;
            while (owner.receive_head != absent_k) {
                auto index = owner.receive_head;
                owner.receive_head = buffers[index].next;
                recycle(index);
            }
            owner.receive_tail = absent_k;
        }
        if (owner.installing || owner.receive_live || owner.close_live) return;
        bool notifications = false;
        for (auto const& operation : operations)
            if (operation.live && operation.resource == &owner) return;
        for (auto const& transmission : transmissions)
            if (transmission.live && transmission.resource == &owner) notifications = true;
        if (owner.file_closed) {
            if (!notifications) finish_close(owner);
            return;
        }
        auto* submission = entry();
        if (!submission) {
            fault = -EIO;
            return;
        }
        io_uring_prep_close_direct(submission, owner.index);
        io_uring_sqe_set_data64(submission, tag(&owner, close_tag_k));
        owner.close_live = true;
        ++live_streams;
    }
    int close_socket(descriptor_t descriptor) noexcept {
        if (!opened) return 0;
        auto* owner = resource(descriptor);
        if (!owner) return 0;
        auto serial = owner->serial;
        retire(*owner);
        while (owner->occupied && owner->serial == serial && !fault) {
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
            owner.close_request->result = owner.close_result;
            owner.close_request->done = true;
            if (owner.close_result >= 0) owner.close_request->request->descriptor = -1;
            owner.close_request = nullptr;
        }
        owner.occupied = false;
    }
    void completion(io_uring_cqe const& completion) noexcept {
        auto kind = static_cast<std::uintptr_t>(completion.user_data) & 7;
        auto* pointer = reinterpret_cast<void*>(static_cast<std::uintptr_t>(completion.user_data) &
                                                ~std::uintptr_t {7});
        if (kind == cancel_tag_k) return;
        if (kind == control_tag_k) {
            control.result = completion.res;
            control.live = false;
            return;
        }
        if (kind == transmit_tag_k) {
            auto& transmission = *static_cast<transmit_t*>(pointer);
            if (!(completion.flags & IORING_CQE_F_NOTIF)) {
                auto& operation = *transmission.operation;
                operation.result = completion.res;
                operation.done = true;
                operation.live = false;
                operation.transmit = nullptr;
                transmission.operation = nullptr;
                --live_operations;
            }
            if (!(completion.flags & IORING_CQE_F_MORE)) {
                transmission.live = false;
                --live_transmissions;
            }
            if (transmission.resource->retiring) retire(*transmission.resource);
            return;
        }
        if (kind == close_tag_k) {
            auto& owner = *static_cast<resource_t*>(pointer);
            --live_streams;
            owner.close_live = false;
            owner.file_closed = true;
            owner.close_result = completion.res;
            retire(owner);
            return;
        }
        if (kind == receive_tag_k) {
            auto& owner = *static_cast<resource_t*>(pointer);
            if (!(completion.flags & IORING_CQE_F_MORE)) {
                owner.receive_live = false;
                --live_streams;
            }
            if (completion.flags & IORING_CQE_F_BUFFER) {
                --available_buffers;
                unsigned index = completion.flags >> IORING_CQE_BUFFER_SHIFT;
                if (owner.retiring || stopping) recycle(index);
                else {
                    queue_buffer(owner, index, completion.res);
                    deliver_receive(owner);
                }
            }
            else if (completion.res != -ENOBUFS && completion.res != -ECANCELED) {
                owner.receive_ended = true;
                owner.terminal = completion.res;
                deliver_receive(owner);
            }
            if (owner.retiring) retire(owner);
            return;
        }
        auto& operation = *static_cast<operation_t*>(pointer);
        operation.result = completion.res;
        if (operation.accepted != absent_k) {
            auto& accepted = resources[operation.accepted];
            accepted.installing = false;
            if (completion.res >= 0) {
                operation.result = registered_socket_t {operation.accepted}.handle();
                if (stopping || operation.resource->retiring) retire(accepted);
            }
            else accepted.occupied = false;
        }
        if (completion.flags & IORING_CQE_F_BUFFER) {
            --available_buffers;
            operation.buffer = completion.flags >> IORING_CQE_BUFFER_SHIFT;
            buffers[operation.buffer].leased = true;
        }
        if (!(completion.flags & IORING_CQE_F_MORE)) {
            operation.live = false;
            operation.done = completion.res != -ENOBUFS || operation.cancelling || stopping;
            --live_operations;
            if (operation.resource->retiring) retire(*operation.resource);
        }
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
        for (auto& operation : operations)
            if (operation.request && operation.done && count != output.size()) {
                auto result = operation.timed_out && operation.result == -ECANCELED ? -ETIMEDOUT : operation.result;
                auto index = operation.buffer;
                output[count++] = {operation.request, result, index == absent_k ? nullptr : receive_data(index),
                                   index == absent_k || result < 0 ? 0 : static_cast<std::size_t>(result),
                                   index == absent_k ? 0 : static_cast<std::uintptr_t>(index) + 1};
                operation.request = nullptr;
            }
        return static_cast<int>(count);
    }
    void maintain() noexcept {
        auto now = monotonic_ns();
        for (auto& operation : operations)
            if (operation.request && !operation.done && operation.request->deadline &&
                operation.request->deadline <= now && operation.request->operation != io_operation_t::close_k) {
                operation.timed_out = true;
                (void)cancel(*operation.request);
            }
        for (auto& operation : operations)
            if (operation.request && !operation.live && !operation.done && !operation.cancelling &&
                operation.request->operation != io_operation_t::close_k &&
                (operation.request->operation == io_operation_t::accept_k ||
                 operation.request->operation == io_operation_t::send_k || !advanced_))
                if (!start_operation(operation)) fault = -EIO;
        if constexpr (advanced_)
            for (auto& owner : resources)
                if (owner.occupied && !owner.retiring) {
                    if (owner.receive_request && !owner.receive_live) (void)start_receive(owner);
                }
    }
    int poll(span<io_completion_t> output, io_wait_t policy, std::uint64_t deadline = 0) noexcept {
        if (!opened) return -EBADF;
        for (;;) {
            reap();
            maintain();
            if (fault) return fault;
            int count = collect(output);
            if (count) return count;
            auto now = monotonic_ns();
            auto wait_deadline = deadline;
            for (auto const& operation : operations)
                if (operation.request && !operation.done && !operation.cancelling && operation.request->deadline)
                    wait_deadline = !wait_deadline ? operation.request->deadline
                                                   : std::min(wait_deadline, operation.request->deadline);
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
        if (!files_registered) return true;
        int result = retry_interrupted([&] { return io_uring_unregister_files(&ring); });
        if (result && result != -ENXIO) {
            fault = result;
            return false;
        }
        files_registered = false;
        return true;
    }
    bool unregister_transmit() noexcept {
        if (!buffers_registered) return true;
        int result = retry_interrupted([&] { return io_uring_unregister_buffers(&ring); });
        if (result && result != -ENXIO) {
            fault = result;
            return false;
        }
        buffers_registered = false;
        return true;
    }
    void discard(std::uint64_t user_data) noexcept {
        auto kind = static_cast<std::uintptr_t>(user_data) & 7;
        auto* pointer = reinterpret_cast<void*>(static_cast<std::uintptr_t>(user_data) & ~std::uintptr_t {7});
        if (kind == operation_tag_k) {
            auto& operation = *static_cast<operation_t*>(pointer);
            if (operation.live) {
                operation.live = false;
                --live_operations;
            }
            operation.done = true;
            operation.result = -ECANCELED;
            if (operation.accepted != absent_k) resources[operation.accepted].occupied = false;
        }
        else if (kind == transmit_tag_k) {
            auto& transmission = *static_cast<transmit_t*>(pointer);
            auto& operation = *transmission.operation;
            operation.live = false;
            operation.done = true;
            operation.result = -ECANCELED;
            operation.transmit = nullptr;
            --live_operations;
            transmission.live = false;
            transmission.operation = nullptr;
            --live_transmissions;
        }
        else if (kind == control_tag_k) control.live = false;
        else if (kind == receive_tag_k) {
            auto& owner = *static_cast<resource_t*>(pointer);
            if (owner.receive_live) {
                owner.receive_live = false;
                --live_streams;
            }
        }
        else if (kind == close_tag_k) {
            auto& owner = *static_cast<resource_t*>(pointer);
            if (owner.close_live) {
                owner.close_live = false;
                --live_streams;
            }
        }
    }
    void discard_unsubmitted() noexcept {
        if constexpr (advanced_) {
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
        recovering = true;
        discard_unsubmitted();
        if (!cancel_synchronously() || !unregister_files()) return false;
        reap();
        while (live_operations || live_transmissions || live_streams || control.live) {
            int result = retry_interrupted(
                [&] { return io_uring_enter(ring.ring_fd, 0, 1, IORING_ENTER_GETEVENTS, nullptr); });
            if (result < 0) {
                fault = result;
                return false;
            }
            reap();
        }
        return unregister_transmit();
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
        if (!opened) return;
        stopping = true;
        if (!fault) {
            for (auto& operation : operations)
                if (operation.request && !operation.done && operation.request->operation != io_operation_t::close_k)
                    (void)cancel(*operation.request);
            for (auto& owner : resources)
                if (owner.occupied) retire(owner);
            while ((live_operations || live_transmissions || live_streams || control.live) && !fault) {
                int result = enter(1, 0);
                if (result < 0) {
                    fault = result;
                    break;
                }
                reap();
            }
        }
        bool retired = true;
        if (fault) {
            // Failed submission must not bypass terminal CQEs or fixed-buffer TX notifications.
            retired = drain_after_fault();
        }
        else {
            retired = unregister_files();
            retired = unregister_transmit() && retired;
        }
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
        opened = false;
        if (retired) {
            live_operations = live_transmissions = live_streams = 0;
            control.live = false;
        }
        for (auto& owner : resources) owner.occupied = false;
    }
};

using linux_uring612_engine_t = linux_uring_engine<false>;
using linux_uring700_engine_t = linux_uring_engine<true>;

} // namespace unum::ucall
