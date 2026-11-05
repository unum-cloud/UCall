/**
 *  @file include/ucall/io/linux_uring612_engine.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Registered sockets and single-shot buffer-select receives for Linux 6.12 io_uring,
 *      and the ring components the 6.18 engine composes too.
 */
#pragma once

#include <optional>

#include <liburing.h>

#include <smashtable/basic_hash_index.hpp> // `basic_hash_index`
#include <smashtable/basic_vector.hpp>     // `vector`
#include <smashtable/row_search.hpp>       // `serial_row_kit_t`

#include "ucall/io/types.hpp"          // `operation_list_t`, `io_request_t`, `io_statistics_t`, `tally`
#include "ucall/utilities/sockets.hpp" // `socket_reset_linger_k`, `monotonic_ns`, `page_size`, `file_open_flags_k`
#include "ucall/utilities/types.hpp"   // `descriptor_t`, `byte_t`, `allocated_ptr`, `allocator_delete`

namespace unum::ucall::io {

using utilities::allocate_unique;
using utilities::allocated_ptr;
using utilities::allocator_delete;
using utilities::byte_t;
using utilities::descriptor_t;
using utilities::file_close;
using utilities::file_open_finish;
using utilities::file_open_flags_k;
using utilities::monotonic_ns;
using utilities::open_files_limit;
using utilities::page_size;
using utilities::socket_close;
using utilities::socket_option;
using utilities::socket_reset_linger_k;
using utilities::span;

/** Slots in an io_uring registered-buffer table, the kernel's @c IORING_MAX_REG_BUFFERS. */
inline constexpr unsigned uring_registered_buffers_limit_k = 16384;

/** Why an engine's @c open answered @c ucall_status_unsupported_k before its ring existed. */
inline constexpr char const* uring_setup_refusal_k =
    "io_uring ring setup failed: raise `ulimit -l` or pick linux-epollaio";

/** The high bit separates registered transport handles from process file descriptors. */
struct registered_socket_t {
    unsigned index {};
    static constexpr descriptor_t tag_k = descriptor_t {1} << (sizeof(descriptor_t) * CHAR_BIT - 2);
    descriptor_t handle() const noexcept { return tag_k | static_cast<descriptor_t>(index); }
    static bool contains(descriptor_t handle) noexcept { return handle >= tag_k; }
    static unsigned index_of(descriptor_t handle) noexcept { return static_cast<unsigned>(handle & ~tag_k); }
};

enum class uring_engine_stage_t : std::uint8_t { idle_k, running_k, stopping_k, recovering_k, stopped_k };

/** Whether a thread entered the ring yet, becoming its one issuer. */
enum class uring_issuer_t : std::uint8_t { unclaimed_k, claimed_k };

/** @c collecting_k is a release some zero-copy send named before its request was submitted, and
 *  @c releasing_k one submitted, waiting for the notifications still due. */
enum class uring_operation_stage_t : std::uint8_t {
    waiting_k,
    submitted_k,
    cancelling_k,
    completed_k,
    collecting_k,
    releasing_k
};
enum class uring_socket_stage_t : std::uint8_t { vacant_k, installing_k, open_k, closing_k, closed_k };

/** Whether a socket still takes operations, or cancels them on its way to the close. */
enum class uring_retirement_t : std::uint8_t { serving_k, retiring_k };

/** Whether an operation's deadline passed, so its cancellation completes as a timeout. */
enum class uring_expiry_t : std::uint8_t { waiting_k, expired_k };

/** Where a receive's bytes wait for the caller: an engine buffer, or its socket's backlog. */
enum class uring_receive_source_t : std::uint8_t { buffer_k, backlog_k };

/** Whether a table is registered with the ring. */
enum class uring_registration_t : std::uint8_t { unregistered_k, registered_k };

/** Whether received bytes are lent to the caller until @c release returns them. */
enum class uring_lease_t : std::uint8_t { returned_k, leased_k };

/** Tags in the low bits of a submission's user data, naming what its completion settles. */
inline constexpr std::uintptr_t uring_operation_tag_k = 0, uring_control_tag_k = 1, uring_release_tag_k = 2,
                                uring_receive_tag_k = 3, uring_close_tag_k = 4, uring_cancel_tag_k = 7;

/** One request on a registered socket, or the zero-copy release its sends name. */
template <typename socket_slot_type_>
struct alignas(8) uring_operation {
    static constexpr unsigned absent_k = operation_list_t::absent_k;
    io_request_t* request {};
    socket_slot_type_* socket_slot {};
    descriptor_t result {};
    unsigned previous {absent_k};
    std::uint64_t zero_copy_serial {}; // The serial `zero_copy_socket` had when the send left.
    unsigned accepted {absent_k}, buffer {absent_k}, next {absent_k};
    unsigned owned_next {absent_k};             // The next operation of the same socket slot.
    unsigned paired_operation {absent_k};       // A zero-copy send's release, or a release's send in flight.
    std::uint32_t outstanding_notifications {}; // A release's zero-copy sends whose notification is due.
    unsigned zero_copy_socket {absent_k};       // The socket slot a release's latest send left through.
    uring_operation_stage_t stage {uring_operation_stage_t::waiting_k};
    uring_expiry_t expiry {uring_expiry_t::waiting_k};
    uring_receive_source_t receive_source {uring_receive_source_t::buffer_k};
    listing_t timed_listing {listing_t::unlisted_k};
    bool in_flight() const noexcept {
        return stage == uring_operation_stage_t::submitted_k || stage == uring_operation_stage_t::cancelling_k;
    }
};

/** The ring, its registered tables and receive buffers, and the control word its synchronous
 *  commands complete into. */
template <typename allocator_type_, template <typename> class atomic_ref_template_>
struct uring_queue {
    using allocator_t = allocator_type_;
    template <typename value_type_>
    using atomic_ref = atomic_ref_template_<value_type_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;

    struct alignas(8) control_t {
        std::optional<int> result {0};
    };
    struct storage_t {
        st::vector<byte_t, rebound_allocator<byte_t>> receive;
        int socket_option_value {1};
        linger reset_linger {socket_reset_linger_k};
        open_how open_resolution {}; // Read by the kernel as an `IORING_OP_OPENAT2` is submitted.
        explicit storage_t(allocator_t const& allocator) noexcept : receive(allocator) {}
        storage_t(storage_t const&) = delete;
        storage_t& operator=(storage_t const&) = delete;
        storage_t(storage_t&&) = delete;
        storage_t& operator=(storage_t&&) = delete;
    };

    io_uring ring {};
    io_uring_buf_ring* receive_ring {};
    allocator_t allocator;

    /** The owning engine's counters. */
    io_statistics_t& statistics;
    allocated_ptr<storage_t, allocator_t> storage;
    control_t control {};
    unsigned registered_buffers {}, buffer_count {}, buffer_mask {}, available_buffers {};
    std::size_t page {};
    uring_engine_stage_t stage {uring_engine_stage_t::idle_k};
    uring_registration_t file_registration {uring_registration_t::unregistered_k};
    uring_registration_t buffer_registration {uring_registration_t::unregistered_k};
    uring_issuer_t issuer {uring_issuer_t::unclaimed_k};
    int fault {};

    uring_queue(allocator_t const& instance, io_statistics_t& counters) noexcept
        : allocator(instance), statistics(counters),
          storage(nullptr, allocator_delete<storage_t, allocator_t> {instance}) {}
    uring_queue(uring_queue const&) = delete;
    uring_queue& operator=(uring_queue const&) = delete;
    uring_queue(uring_queue&&) = delete;
    uring_queue& operator=(uring_queue&&) = delete;

    bool is_open() const noexcept {
        return stage != uring_engine_stage_t::idle_k && stage != uring_engine_stage_t::stopped_k;
    }
    static std::uintptr_t tag(void* pointer, std::uintptr_t kind) noexcept {
        return reinterpret_cast<std::uintptr_t>(pointer) | kind;
    }
    span<byte_t> receive_data(unsigned index) noexcept {
        return span<byte_t> {storage->receive}.subspan(static_cast<std::size_t>(index) * page, page);
    }
    static __kernel_timespec timespec_of(std::uint64_t nanoseconds) noexcept {
        return {static_cast<__kernel_time64_t>(nanoseconds / 1'000'000'000),
                static_cast<long long>(nanoseconds % 1'000'000'000)};
    }

    /** Enables the ring for the calling thread at its first enter, making it the one issuer, as
     *  rings open disabled on the thread that sizes them. */
    int claim() noexcept {
        if (issuer == uring_issuer_t::claimed_k) return 0;
        int const enabled = io_uring_enable_rings(&ring);
        if (enabled == 0) issuer = uring_issuer_t::claimed_k;
        return enabled;
    }
    io_uring_sqe* entry(unsigned count = 1) noexcept {
        if (io_uring_sq_space_left(&ring) < count) {
            tally<atomic_ref_template_>(statistics.kernel_enters);
            if (claim() < 0 || io_uring_submit(&ring) < 0) return nullptr;
        }
        if (io_uring_sq_space_left(&ring) < count) return nullptr;
        tally<atomic_ref_template_>(statistics.submissions);
        return io_uring_get_sqe(&ring);
    }
    int enter(unsigned wait, std::uint64_t deadline) noexcept {
        tally<atomic_ref_template_>(statistics.kernel_enters);
        if (int const claimed = claim(); claimed < 0) return claimed;
        // Deferred task work only runs inside an enter that asks for events.
        if (!wait) return io_uring_submit_and_get_events(&ring);
        auto now = deadline ? monotonic_ns() : 0;
        auto timeout = timespec_of(deadline > now ? deadline - now : 0);
        io_uring_cqe* completion {};
        int result = deadline ? io_uring_submit_and_wait_timeout(&ring, &completion, wait, &timeout, nullptr)
                              : io_uring_submit_and_wait(&ring, wait);
        return result == -ETIME || result == -EINTR ? 0 : result;
    }

    /** Sizes the receive buffers for @p capacity operations, one page each up to the kernel's
     *  limit, before the ring opens. */
    ucall_status_t reserve(std::size_t capacity) noexcept {
        storage = allocate_unique<storage_t>(allocator, allocator);
        if (!storage) return ucall_status_out_of_memory_k;
        page = page_size();
        if (!page || capacity > std::numeric_limits<std::size_t>::max() / page) return ucall_status_overflow_k;
        // Pbuf ring IDs and head distances are 16-bit; the kernel permits 32768 entries.
        buffer_count = 1;
        while (buffer_count < capacity && buffer_count < 32768) buffer_count *= 2;
        buffer_mask = buffer_count - 1;
        available_buffers = buffer_count;
        // Untouched pages stay unbacked until a receive lands in them.
        if (st::failed(
                storage->receive.resize(st::assume_uninitialized, static_cast<std::size_t>(buffer_count) * page)))
            return ucall_status_out_of_memory_k;
        return ucall_status_success_k;
    }

    /** Opens the ring with room for @p files registered sockets, refusing a kernel lacking any of
     *  @p opcodes. */
    ucall_status_t open(std::size_t depth, std::size_t files, span<io_uring_op const> opcodes) noexcept {
        io_uring_params parameters {};
        parameters.flags = IORING_SETUP_CLAMP | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_SINGLE_ISSUER |
                           IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_NO_SQARRAY | IORING_SETUP_R_DISABLED;
        // Each one-shot operation may carry a linked timeout.
        auto entries = static_cast<unsigned>(
            std::min(depth, static_cast<std::size_t>(std::numeric_limits<unsigned>::max() / 2)) * 2);
        // io_uring bills rings to the locked-memory limit, so ENOMEM points at it, not the heap.
        int result = io_uring_queue_init_params(entries, &ring, &parameters);
        if (result < 0) return ucall_status_unsupported_k;
        stage = uring_engine_stage_t::running_k;
        constexpr auto probe_length = unsigned {std::numeric_limits<decltype(io_uring_probe_op::op)>::max()} + 1;
        struct alignas(io_uring_probe) probe_scratch_t {
            byte_t bytes[sizeof(io_uring_probe) + probe_length * sizeof(io_uring_probe_op)] {};
        };
        auto scratch = allocate_unique<probe_scratch_t>(allocator);
        if (!scratch) return ucall_status_out_of_memory_k;
        auto* probe = std::construct_at(reinterpret_cast<io_uring_probe*>(scratch->bytes));
        bool supported = io_uring_register_probe(&ring, probe, probe_length) == 0 &&
                         (parameters.features & IORING_FEAT_NODROP) && (parameters.features & IORING_FEAT_EXT_ARG);
        for (io_uring_op const opcode : opcodes) supported = supported && io_uring_opcode_supported(probe, opcode);
        scratch.reset();
        if (!supported) return ucall_status_unsupported_k;
        storage->open_resolution.flags = file_open_flags_k;
        storage->open_resolution.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
        if (io_uring_register_files_sparse(&ring, static_cast<unsigned>(files)) < 0) return ucall_status_unsupported_k;
        file_registration = uring_registration_t::registered_k;
        // An empty table locks no memory; `register_memory` pins one range per slot as it fills.
        if (io_uring_register_buffers_sparse(&ring, uring_registered_buffers_limit_k) == 0)
            buffer_registration = uring_registration_t::registered_k;
        receive_ring = io_uring_setup_buf_ring(&ring, buffer_count, 0, 0, &result);
        if (!receive_ring) return ucall_status_unsupported_k;
        for (unsigned i = 0; i != buffer_count; ++i)
            io_uring_buf_ring_add(receive_ring, receive_data(i).data(), static_cast<unsigned>(page),
                                  static_cast<unsigned short>(i), buffer_mask, i);
        io_uring_buf_ring_advance(receive_ring, buffer_count);
        return ucall_status_success_k;
    }

    /** Hands receive buffer @p index back to the kernel. */
    void return_buffer(unsigned index) noexcept {
        ++available_buffers;
        io_uring_buf_ring_add(receive_ring, receive_data(index).data(), static_cast<unsigned>(page),
                              static_cast<unsigned short>(index), buffer_mask, 0);
        io_uring_buf_ring_advance(receive_ring, 1);
    }

    /** Pins @p memory into the next slot of the sparse buffer table, answering @c unpinned_k once
     *  the locked-memory cap refuses or the table is full. */
    memory_registration_t register_memory(span<byte_t> memory) noexcept {
        if (buffer_registration != uring_registration_t::registered_k ||
            registered_buffers == uring_registered_buffers_limit_k)
            return {};
        iovec range {};
        range.iov_base = memory.data();
        range.iov_len = memory.size();
        if (io_uring_register_buffers_update_tag(&ring, registered_buffers, &range, nullptr, 1) != 1) return {};
        return {static_cast<registered_memory_t>(registered_buffers++), range_pinning_t::pinned_k};
    }

    /** Tags @p submission as a synchronous command whose result lands in @c control. */
    void command(io_uring_sqe* submission) noexcept {
        control.result.reset();
        io_uring_sqe_set_data64(submission, tag(&control, uring_control_tag_k));
    }

    template <typename function_type_>
    static int retry_interrupted(function_type_ function) noexcept {
        int result;
        do { result = function(); } while (result == -EINTR);
        return result;
    }
    [[nodiscard]] ucall_status_t unregister_files() noexcept {
        if (file_registration != uring_registration_t::registered_k) return ucall_status_success_k;
        int result = retry_interrupted([&] { return io_uring_unregister_files(&ring); });
        if (result && result != -ENXIO) {
            fault = result;
            return ucall_status_io_k;
        }
        file_registration = uring_registration_t::unregistered_k;
        return ucall_status_success_k;
    }
    [[nodiscard]] ucall_status_t cancel_synchronously() noexcept {
        io_uring_sync_cancel_reg cancellation {};
        cancellation.flags = IORING_ASYNC_CANCEL_ANY | IORING_ASYNC_CANCEL_ALL;
        cancellation.timeout.tv_sec = -1;
        cancellation.timeout.tv_nsec = -1;
        int result = retry_interrupted([&] { return io_uring_register_sync_cancel(&ring, &cancellation); });
        if (result >= 0 || result == -ENOENT) return ucall_status_success_k;
        fault = result;
        return ucall_status_io_k;
    }

    /** Ends the ring once the kernel holds nothing, or, after a failed @p retirement, leaks the
     *  registered memory rather than make it reusable. */
    void close(ucall_status_t retirement) noexcept {
        if (buffer_registration == uring_registration_t::registered_k) {
            [[maybe_unused]] int const unregistered = io_uring_unregister_buffers(&ring);
            buffer_registration = uring_registration_t::unregistered_k;
            registered_buffers = 0;
        }
        if (receive_ring && retirement == ucall_status_success_k) {
            int result = retry_interrupted(
                [&] { return io_uring_free_buf_ring(&ring, receive_ring, buffer_count, 0); });
            if (result) {
                fault = result;
                retirement = ucall_status_io_k;
            }
            else receive_ring = nullptr;
        }
        if (retirement != ucall_status_success_k) {
            // A failed retirement barrier must not make registered memory reusable.
            [[maybe_unused]] storage_t* const leaked = storage.release();
        }
        io_uring_queue_exit(&ring);
        stage = uring_engine_stage_t::stopped_k;
    }
};

/** The registered socket slots, free-listed; @p socket_slot_type_ carries @c index, @c next,
 *  @c serial, @c owned_head, @c close_operation, @c stage, @c zero_copy, @c retirement and
 *  @c close, as both engines' slot types do. */
template <typename socket_slot_type_, typename allocator_type_>
struct uring_socket_slots {
    using socket_slot_t = socket_slot_type_;
    using allocator_t = allocator_type_;
    static constexpr unsigned absent_k = operation_list_t::absent_k;

    st::vector<socket_slot_t, typename std::allocator_traits<allocator_t>::template rebind_alloc<socket_slot_t>>
        records;
    unsigned free_socket_slots {absent_k}, vacant_socket_slots {}, closing_socket_slots {};
    std::uint64_t next_serial {};

    explicit uring_socket_slots(allocator_t const& allocator) noexcept : records(allocator) {}

    /** Builds @p count vacant slots from @p slot_arguments. */
    template <typename... slot_arguments_type_>
    ucall_status_t open(std::size_t count, slot_arguments_type_ const&... slot_arguments) noexcept {
        if (st::failed(records.reserve(count))) return ucall_status_out_of_memory_k;
        records.clear();
        for (std::size_t i = 0; i != count; ++i) {
            if (st::failed(records.emplace_back(slot_arguments...))) return ucall_status_out_of_memory_k;
            records[i].index = static_cast<unsigned>(i);
        }
        for (auto i = records.size(); i--;) vacate(records[i]);
        return ucall_status_success_k;
    }
    socket_slot_t* find(descriptor_t handle) noexcept {
        if (!registered_socket_t::contains(handle)) return nullptr;
        auto index = registered_socket_t::index_of(handle);
        return index < records.size() && records[index].stage != uring_socket_stage_t::vacant_k ? &records[index]
                                                                                                : nullptr;
    }

    /** Takes a vacant slot for a socket being installed, with a serial no earlier socket had. */
    socket_slot_t* reserve() noexcept {
        if (free_socket_slots == absent_k) return nullptr;
        auto& result = records[free_socket_slots];
        free_socket_slots = result.next;
        --vacant_socket_slots;
        result.next = absent_k;
        result.owned_head = absent_k;
        result.close_operation = absent_k;
        result.zero_copy = zero_copy_stage_t::untried_k;
        result.retirement = uring_retirement_t::serving_k;
        result.close = close_mode_t::orderly_k;
        result.stage = uring_socket_stage_t::installing_k;
        result.serial = ++next_serial;
        return &result;
    }
    void vacate(socket_slot_t& owner) noexcept {
        owner.stage = uring_socket_stage_t::vacant_k;
        owner.next = free_socket_slots;
        free_socket_slots = owner.index;
        ++vacant_socket_slots;
    }
    bool closing() const noexcept { return closing_socket_slots != 0; }

    template <typename queue_type_>
    descriptor_t import_socket(descriptor_t descriptor, queue_type_& queue) noexcept {
        if (queue.fault) return queue.fault;
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
        int result = io_uring_register_files_update(&queue.ring, target->index, &raw, 1);
        if (result != 1) {
            vacate(*target);
            return result < 0 ? result : -EIO;
        }
        socket_close(descriptor);
        target->stage = uring_socket_stage_t::open_k;
        return registered_socket_t {target->index}.handle();
    }

    /** Submits the close of @p owner's registered descriptor, behind a linked @c SO_LINGER that
     *  turns it into a reset where @p owner was marked so. */
    template <typename queue_type_>
    void submit_close(socket_slot_t& owner, queue_type_& queue) noexcept {
        auto* submission = queue.entry(owner.close == close_mode_t::reset_k ? 2 : 1);
        if (!submission) {
            queue.fault = -EIO;
            return;
        }
        if (owner.close == close_mode_t::reset_k) {
            // Hard-linked, so a refused option still closes, in order; its failure lands untracked.
            io_uring_prep_cmd_sock(submission, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(owner.index), SOL_SOCKET,
                                   SO_LINGER, &queue.storage->reset_linger, sizeof(queue.storage->reset_linger));
            submission->flags |= IOSQE_FIXED_FILE | IOSQE_IO_HARDLINK | IOSQE_CQE_SKIP_SUCCESS;
            io_uring_sqe_set_data64(submission, uring_cancel_tag_k);
            submission = queue.entry();
        }
        io_uring_prep_close_direct(submission, owner.index);
        io_uring_sqe_set_data64(submission, queue.tag(&owner, uring_close_tag_k));
        owner.stage = uring_socket_stage_t::closing_k;
        ++closing_socket_slots;
    }

    /** Settles the close of @p owner's descriptor, answering the slot when it closed. */
    template <typename queue_type_>
    socket_slot_t* settle_close(socket_slot_t& owner, int result, queue_type_& queue) noexcept {
        owner.stage = uring_socket_stage_t::open_k;
        --closing_socket_slots;
        if (result < 0) {
            queue.fault = result;
            return nullptr;
        }
        owner.stage = uring_socket_stage_t::closed_k;
        return &owner;
    }
};

/** The operation records and the lists they wait on; each socket slot owns the ones it submitted
 *  until they are collected. */
template <typename socket_slot_type_, typename allocator_type_>
struct uring_operations {
    using socket_slot_t = socket_slot_type_;
    using allocator_t = allocator_type_;
    using operation_t = uring_operation<socket_slot_t>;
    using socket_slots_t = uring_socket_slots<socket_slot_t, allocator_t>;
    template <typename value_type_>
    using vector =
        st::vector<value_type_, typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>>;
    static constexpr unsigned absent_k = operation_list_t::absent_k;

    vector<operation_t> records;

    /** Each operation's linked timeout, read by the kernel at submission. */
    vector<__kernel_timespec> expiries;
    operation_list_t free_operations, completed_operations, waiting_operations;
    unsigned outstanding_operations {};

    explicit uring_operations(allocator_t const& allocator) noexcept : records(allocator), expiries(allocator) {}

    ucall_status_t open(std::size_t capacity) noexcept {
        if (st::failed(records.resize(capacity)) || st::failed(expiries.resize(capacity)))
            return ucall_status_out_of_memory_k;
        for (unsigned i = 0; i != records.size(); ++i) free_operations.push(records, i);
        return ucall_status_success_k;
    }
    operation_t& operator[](unsigned index) noexcept { return records[index]; }
    operation_t const& operator[](unsigned index) const noexcept { return records[index]; }
    unsigned index_of(operation_t const& operation) const noexcept {
        return static_cast<unsigned>(&operation - records.data());
    }
    void push(operation_list_t& list, operation_t& operation) noexcept { list.push(records, index_of(operation)); }
    operation_t* pop(operation_list_t& list) noexcept {
        unsigned const index = list.pop(records);
        return index != absent_k ? &records[index] : nullptr;
    }
    void unlink(operation_list_t& list, operation_t& operation) noexcept {
        [[maybe_unused]] st::status_t const removed = list.erase(records, index_of(operation));
    }

    /** Takes a free operation for @p request, owned by @p owner when it names a socket. */
    operation_t* take(io_request_t& request, socket_slot_t* owner = nullptr) noexcept {
        auto* operation = pop(free_operations);
        if (!operation) return nullptr;
        *operation = {};
        operation->request = &request;
        if (!owner) return operation;
        operation->socket_slot = owner;
        operation->owned_next = owner->owned_head;
        owner->owned_head = index_of(*operation);
        return operation;
    }
    void complete(operation_t& operation) noexcept {
        if (operation.in_flight()) --outstanding_operations;
        operation.stage = uring_operation_stage_t::completed_k;
        push(completed_operations, operation);
    }
    void vacate(operation_t& operation) noexcept {
        if (operation.socket_slot)
            for (unsigned* link = &operation.socket_slot->owned_head; *link != absent_k;
                 link = &records[*link].owned_next)
                if (*link == index_of(operation)) {
                    *link = operation.owned_next;
                    break;
                }
        operation.request = nullptr;
        push(free_operations, operation);
    }

    /** The operation of @p owner submitted for @p request, or @c nullptr. */
    operation_t* owned(socket_slot_t& owner, io_request_t const& request) noexcept {
        for (unsigned index = owner.owned_head; index != absent_k; index = records[index].owned_next)
            if (records[index].request == &request) return &records[index];
        return nullptr;
    }
    bool owns_in_flight(socket_slot_t const& owner) const noexcept {
        for (unsigned index = owner.owned_head; index != absent_k; index = records[index].owned_next)
            if (records[index].in_flight()) return true;
        return false;
    }

    /** The entry @p operation starts with, and one for its linked timeout; an accept first takes
     *  the slot it accepts into, waiting while none is vacant. @c nullptr with @p status success
     *  means the operation waits. */
    template <typename queue_type_>
    io_uring_sqe* entry(operation_t& operation, queue_type_& queue, socket_slots_t& socket_slots,
                        ucall_status_t& status) noexcept {
        auto& request = *operation.request;
        status = ucall_status_success_k;
        if (request.operation == io_operation_t::accept_k && operation.accepted == absent_k) {
            auto* accepted = socket_slots.reserve();
            if (!accepted) {
                push(waiting_operations, operation);
                return nullptr;
            }
            operation.accepted = accepted->index;
        }
        auto* submission = queue.entry(request.deadline ? 2 : 1);
        if (submission) return submission;
        if (operation.accepted != absent_k) socket_slots.vacate(socket_slots.records[operation.accepted]);
        status = ucall_status_io_k;
        return nullptr;
    }

    /** Tags a prepared entry, links its timeout, and counts the operation in flight. */
    template <typename queue_type_>
    void submit(io_uring_sqe* submission, operation_t& operation, queue_type_& queue) noexcept {
        auto& request = *operation.request;
        // A file or a directory is a process descriptor, never a registered socket.
        if (request.operation != io_operation_t::file_open_k && request.operation != io_operation_t::file_read_k &&
            request.operation != io_operation_t::file_read_vectors_k)
            submission->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(submission, operation.paired_operation != absent_k
                                                ? queue.tag(&records[operation.paired_operation], uring_release_tag_k)
                                                : queue.tag(&operation, uring_operation_tag_k));
        if (request.deadline) {
            submission->flags |= IOSQE_IO_LINK;
            auto& expiry = expiries[index_of(operation)];
            expiry = queue.timespec_of(request.deadline);
            auto* timeout = queue.entry();
            io_uring_prep_link_timeout(timeout, &expiry, IORING_TIMEOUT_ABS);
            io_uring_sqe_set_data64(timeout, uring_cancel_tag_k);
        }
        operation.stage = uring_operation_stage_t::submitted_k;
        ++outstanding_operations;
    }

    /** Asks the kernel to cancel an operation in flight. */
    template <typename queue_type_>
    ucall_status_t cancel_in_flight(operation_t& operation, queue_type_& queue) noexcept {
        operation.stage = uring_operation_stage_t::cancelling_k;
        auto* submission = queue.entry();
        if (!submission) {
            operation.stage = uring_operation_stage_t::submitted_k;
            return ucall_status_io_k;
        }
        io_uring_prep_cancel64(submission,
                               operation.paired_operation != absent_k
                                   ? queue.tag(&records[operation.paired_operation], uring_release_tag_k)
                                   : queue.tag(&operation, uring_operation_tag_k),
                               0);
        io_uring_sqe_set_data64(submission, uring_cancel_tag_k);
        return ucall_status_success_k;
    }

    /** Settles the completion of a one-shot operation, answering a slot it accepted that must be
     *  retired at once because the engine or the listener is retiring. */
    template <typename queue_type_>
    socket_slot_t* settle(operation_t& operation, io_uring_cqe const& completion, queue_type_& queue,
                          socket_slots_t& socket_slots) noexcept {
        socket_slot_t* retired {};
        operation.result = completion.res;
        if (operation.request->operation == io_operation_t::file_open_k && completion.res >= 0)
            operation.result = file_open_finish(completion.res);
        // Only the linked timeout cancels an operation that was not asked to cancel.
        if (completion.res == -ECANCELED && operation.stage != uring_operation_stage_t::cancelling_k &&
            operation.request->deadline)
            operation.expiry = uring_expiry_t::expired_k;
        if (operation.accepted != absent_k) {
            auto& accepted = socket_slots.records[operation.accepted];
            accepted.stage = uring_socket_stage_t::open_k;
            if (completion.res < 0) socket_slots.vacate(accepted);
            else {
                operation.result = registered_socket_t {operation.accepted}.handle();
                if (queue.stage != uring_engine_stage_t::running_k ||
                    operation.socket_slot->retirement == uring_retirement_t::retiring_k)
                    retired = &accepted;
            }
        }
        if (completion.res != -ENOBUFS || operation.stage == uring_operation_stage_t::cancelling_k ||
            queue.stage != uring_engine_stage_t::running_k)
            complete(operation);
        else {
            --outstanding_operations;
            operation.stage = uring_operation_stage_t::waiting_k;
            push(waiting_operations, operation);
        }
        return retired;
    }

    /** Completes the close request of a closed @p owner and frees its slot. */
    void finish_close(socket_slot_t& owner, socket_slots_t& socket_slots) noexcept {
        if (owner.close_operation != absent_k) {
            auto& closing = records[owner.close_operation];
            closing.result = 0;
            closing.request->descriptor = -1;
            complete(closing);
            owner.close_operation = absent_k;
        }
        socket_slots.vacate(owner);
    }

    /** What a completed @p operation reports, naming the engine buffer a receive filled and the
     *  lease that returns it. */
    template <typename queue_type_>
    io_completion_t completion_of(operation_t& operation, queue_type_& queue) noexcept {
        auto result = operation.expiry == uring_expiry_t::expired_k && operation.result == -ECANCELED
                          ? -ETIMEDOUT
                          : operation.result;
        auto index = operation.buffer;
        byte_t* data = index != absent_k ? queue.receive_data(index).data() : nullptr;
        std::uintptr_t lease = index != absent_k ? static_cast<std::uintptr_t>(index) + 1 : 0;
        return {operation.request, result, data, lease};
    }

    /** Opens completed but never collected hand their descriptors to no one. */
    void close_uncollected_files() noexcept {
        for (unsigned index = completed_operations.oldest; index != absent_k; index = records[index].next)
            if (records[index].request->operation == io_operation_t::file_open_k && records[index].result >= 0)
                file_close(records[index].result);
    }
};

/** The zero-copy releases sends name, found through their index, and the notifications the kernel
 *  still owes them. */
template <typename socket_slot_type_, typename allocator_type_, template <typename> class atomic_ref_template_,
          typename row_kit_type_>
struct uring_zero_copy {
    using socket_slot_t = socket_slot_type_;
    using allocator_t = allocator_type_;
    using operations_t = uring_operations<socket_slot_t, allocator_t>;
    using socket_slots_t = uring_socket_slots<socket_slot_t, allocator_t>;
    using operation_t = typename operations_t::operation_t;
    using release_index_t =
        st::basic_hash_index<std::uint64_t, std::uint32_t, st::default_hash_t,
                             typename std::allocator_traits<allocator_t>::template rebind_alloc<byte_t>, row_kit_type_>;
    static constexpr unsigned absent_k = operation_list_t::absent_k;

    release_index_t releases;

    /** Summed over every release. */
    std::uint32_t outstanding_notifications {};

    /** The owning engine's counters. */
    io_statistics_t& statistics;

    explicit uring_zero_copy(io_statistics_t& counters) noexcept : statistics(counters) {}

    /** Builds the release index for up to @p capacity releases, dropping any it held. */
    ucall_status_t open(std::size_t capacity, allocator_t const& allocator) noexcept {
        st::expected<release_index_t> made = release_index_t::make(capacity, {}, allocator);
        if (!made) return ucall_status_out_of_memory_k;
        releases = std::move(*made);
        return ucall_status_success_k;
    }

    /** The release a zero-copy send counts against, taking an operation for it on the first send
     *  naming it; @c absent_k when the send copies instead: its socket was reported copying, or
     *  no operation is free, or another send naming the release is still in flight. */
    unsigned pair_release(operation_t& operation, operations_t& operations) noexcept {
        io_request_t* const named = operation.request->release_request;
        if (operation.socket_slot->zero_copy == zero_copy_stage_t::copying_k || !named) return absent_k;
        unsigned release = releases.find(release_key(named));
        if (release == absent_k) {
            auto* taken = operations.take(*named);
            if (!taken) return absent_k;
            taken->stage = uring_operation_stage_t::collecting_k;
            release = operations.index_of(*taken);
            [[maybe_unused]] st::status_t const indexed = releases.insert(release_key(named), release,
                                                                          st::assume_unique);
        }
        else if (operations[release].paired_operation != absent_k) return absent_k;
        return release;
    }

    /** Prepares a @c SEND_ZC whose result and notification both name @p release, from a registered
     *  buffer where the request names one. */
    void prepare_send(io_uring_sqe* submission, operation_t& operation, operation_t& release,
                      operations_t& operations) noexcept {
        auto const& request = *operation.request;
        auto* owner = operation.socket_slot;
        auto const length = std::min(request.length, std::size_t {std::numeric_limits<unsigned>::max()});
        if (request.registered_memory != io_unregistered_k)
            io_uring_prep_send_zc_fixed(submission, static_cast<int>(owner->index), request.data, length, MSG_NOSIGNAL,
                                        IORING_SEND_ZC_REPORT_USAGE, static_cast<int>(request.registered_memory));
        else
            io_uring_prep_send_zc(submission, static_cast<int>(owner->index), request.data, length, MSG_NOSIGNAL,
                                  IORING_SEND_ZC_REPORT_USAGE);
        ++release.outstanding_notifications;
        ++outstanding_notifications;
        release.paired_operation = operations.index_of(operation);
        release.zero_copy_socket = owner->index;
        release.zero_copy_serial = owner->serial;
        operation.paired_operation = operations.index_of(release);
        tally<atomic_ref_template_>(statistics.zero_copy_sends);
    }

    /** Completes a submitted release once no notification it counts is due; one no zero-copy send
     *  named completes at once. */
    ucall_status_t submit_release(io_request_t& request, operations_t& operations,
                                  socket_slots_t& socket_slots) noexcept {
        unsigned index = releases.find(release_key(&request));
        if (index != absent_k) {
            [[maybe_unused]] st::status_t const unindexed = releases.erase(release_key(&request), index);
        }
        else {
            auto* taken = operations.take(request);
            if (!taken) return ucall_status_contended_k;
            index = operations.index_of(*taken);
        }
        auto& release = operations[index];
        release.stage = uring_operation_stage_t::releasing_k;
        if (!release.outstanding_notifications) complete_release(release, operations, socket_slots);
        return ucall_status_success_k;
    }

    /** Completes @p release with 1 once its socket sends by copying for its lifetime, else 0. */
    void complete_release(operation_t& release, operations_t& operations, socket_slots_t& socket_slots) noexcept {
        socket_slot_t const* owner = socket_slots.find(release.request->descriptor);
        release.result = owner && owner->zero_copy == zero_copy_stage_t::copying_k ? 1 : 0;
        operations.complete(release);
    }

    /** Settles one completion of a zero-copy send naming @p release: the send's result, or one of
     *  its notifications, which demotes the socket when the kernel reports it copied. Answers the
     *  slot of a send that completed, whose retirement may now advance. */
    socket_slot_t* settle(operation_t& release, io_uring_cqe const& completion, operations_t& operations,
                          socket_slots_t& socket_slots) noexcept {
        socket_slot_t* settled {};
        if (completion.flags & IORING_CQE_F_NOTIF) {
            if (static_cast<std::uint32_t>(completion.res) & IORING_NOTIF_USAGE_ZC_COPIED) {
                tally<atomic_ref_template_>(statistics.zero_copy_fallbacks);
                // A notification after the close must not demote whichever socket reuses the slot.
                if (release.zero_copy_socket != absent_k &&
                    socket_slots.records[release.zero_copy_socket].serial == release.zero_copy_serial)
                    socket_slots.records[release.zero_copy_socket].zero_copy = zero_copy_stage_t::copying_k;
            }
            --release.outstanding_notifications;
            --outstanding_notifications;
        }
        else {
            auto& send = operations[std::exchange(release.paired_operation, absent_k)];
            send.paired_operation = absent_k;
            send.result = completion.res;
            if (!(completion.flags & IORING_CQE_F_MORE)) {
                --release.outstanding_notifications;
                --outstanding_notifications;
            }
            // The kernel refuses zero-copy with no notification to demote the socket: AF_UNIX has
            // none, and pinning past the user's locked-memory limit fails with ENOMEM.
            if ((completion.res == -EOPNOTSUPP || completion.res == -ENOMEM) &&
                send.stage != uring_operation_stage_t::cancelling_k) {
                send.socket_slot->zero_copy = zero_copy_stage_t::copying_k;
                tally<atomic_ref_template_>(statistics.zero_copy_fallbacks);
                // The retry counts itself in flight again once submitted.
                --operations.outstanding_operations;
                send.stage = uring_operation_stage_t::waiting_k;
                operations.push(operations.waiting_operations, send);
            }
            else {
                // Only the linked timeout cancels a send that was not asked to cancel.
                if (completion.res == -ECANCELED && send.stage != uring_operation_stage_t::cancelling_k &&
                    send.request->deadline)
                    send.expiry = uring_expiry_t::expired_k;
                operations.complete(send);
                settled = send.socket_slot;
            }
        }
        if (release.stage == uring_operation_stage_t::releasing_k && !release.outstanding_notifications)
            complete_release(release, operations, socket_slots);
        return settled;
    }
};

/** Prepares every operation both io_uring engines submit alike: all but receives and vectored
 *  reads. */
template <typename queue_type_, typename operations_type_, typename zero_copy_type_>
void uring_prepare(io_uring_sqe* submission, typename operations_type_::operation_t& operation, queue_type_& queue,
                   operations_type_& operations, zero_copy_type_& zero_copy) noexcept {
    auto& request = *operation.request;
    auto const socket = static_cast<int>(operation.socket_slot->index);
    // The submission length field is 32 bits wide.
    auto const sent = std::min(request.length, std::size_t {std::numeric_limits<unsigned>::max()});
    switch (request.operation) {
    case io_operation_t::accept_k: {
        auto* peer = reinterpret_cast<io_peer_address_t*>(request.data);
        if (peer) peer->length = sizeof(peer->address);
        // A full fixed table can make multishot accept drop a peer; reserve one credit.
        io_uring_prep_accept_direct(submission, socket, peer ? reinterpret_cast<sockaddr*>(&peer->address) : nullptr,
                                    peer ? &peer->length : nullptr, SOCK_NONBLOCK, operation.accepted);
        break;
    }
    case io_operation_t::connect_k:
        io_uring_prep_connect(submission, socket, reinterpret_cast<sockaddr*>(request.data),
                              static_cast<socklen_t>(request.length));
        break;
    case io_operation_t::send_k:
        io_uring_prep_send(submission, socket, request.data, sent, MSG_NOSIGNAL);
        tally<queue_type_::template atomic_ref>(queue.statistics.copying_sends);
        break;
    case io_operation_t::send_zero_copy_k:
        if (unsigned const release = zero_copy.pair_release(operation, operations);
            release != operation_list_t::absent_k) {
            zero_copy.prepare_send(submission, operation, operations[release], operations);
            break;
        }
        io_uring_prep_send(submission, socket, request.data, sent, MSG_NOSIGNAL);
        tally<queue_type_::template atomic_ref>(queue.statistics.copying_sends);
        break;
    case io_operation_t::read_k:
        io_uring_prep_read(submission, socket, request.data,
                           static_cast<unsigned>(std::min(request.length, queue.page)), -1);
        break;
    case io_operation_t::file_read_k: {
        auto const bytes = static_cast<unsigned>(
            std::min<std::size_t>(request.length, std::numeric_limits<unsigned>::max()));
        if (request.registered_memory != io_unregistered_k)
            io_uring_prep_read_fixed(submission, request.file.file_descriptor, request.data, bytes, request.file.offset,
                                     static_cast<int>(request.registered_memory));
        else io_uring_prep_read(submission, request.file.file_descriptor, request.data, bytes, request.file.offset);
        tally<queue_type_::template atomic_ref>(queue.statistics.file_reads_asynchronous);
        break;
    }
    case io_operation_t::file_open_k:
        io_uring_prep_openat2(submission, request.file.directory_descriptor,
                              reinterpret_cast<char const*>(request.data), &queue.storage->open_resolution);
        break;
    case io_operation_t::shutdown_k: io_uring_prep_shutdown(submission, socket, SHUT_WR); break;
    case io_operation_t::receive_k:
    case io_operation_t::file_read_vectors_k:
    case io_operation_t::zero_copy_release_k:
    case io_operation_t::close_k: break;
    }
}

/** Settles an entry the kernel never saw, of a kind both io_uring engines submit. */
template <typename queue_type_, typename operations_type_, typename socket_slots_type_, typename zero_copy_type_>
void uring_discard(std::uint64_t user_data, queue_type_& queue, operations_type_& operations,
                   socket_slots_type_& socket_slots, zero_copy_type_& zero_copy) noexcept {
    using operation_t = typename operations_type_::operation_t;
    using socket_slot_t = typename socket_slots_type_::socket_slot_t;
    auto kind = static_cast<std::uintptr_t>(user_data) & 7;
    auto* pointer = reinterpret_cast<void*>(static_cast<std::uintptr_t>(user_data) & ~std::uintptr_t {7});
    if (kind == uring_operation_tag_k) {
        auto& operation = *static_cast<operation_t*>(pointer);
        operation.result = -ECANCELED;
        operations.complete(operation);
        if (operation.accepted != operation_list_t::absent_k)
            socket_slots.vacate(socket_slots.records[operation.accepted]);
    }
    else if (kind == uring_release_tag_k) {
        // The send never reached the kernel, so neither its result nor its notification will.
        io_uring_cqe unsent {};
        unsent.res = -ECANCELED;
        [[maybe_unused]] socket_slot_t* const settled = zero_copy.settle(*static_cast<operation_t*>(pointer), unsent,
                                                                         operations, socket_slots);
    }
    else if (kind == uring_control_tag_k) queue.control.result = -ECANCELED;
    else if (kind == uring_close_tag_k) {
        auto& owner = *static_cast<socket_slot_t*>(pointer);
        if (owner.stage == uring_socket_stage_t::closing_k) {
            owner.stage = uring_socket_stage_t::open_k;
            --socket_slots.closing_socket_slots;
        }
    }
}

/** Reaps every ready completion through @p engine's own dispatch. */
template <typename engine_type_>
void uring_reap(engine_type_& engine) noexcept {
    unsigned head {}, count {};
    io_uring_cqe* current {};
    io_uring_for_each_cqe(&engine.queue.ring, head, current) {
        engine.completion(*current);
        ++count;
    }
    if (!count) return;
    io_uring_cq_advance(&engine.queue.ring, count);
    tally<engine_type_::queue_t::template atomic_ref>(engine.statistics.completions, count);
}

/** Waits for the one control command in flight, or the ring's fault. */
template <typename engine_type_>
int uring_wait_control(engine_type_& engine) noexcept {
    auto& queue = engine.queue;
    while (!queue.control.result.has_value() && !queue.fault) {
        int result = queue.enter(1, 0);
        if (result < 0) {
            queue.fault = result;
            break;
        }
        uring_reap(engine);
    }
    return queue.fault ? queue.fault : *queue.control.result;
}

/** Retires the socket behind @p descriptor and waits until its slot is vacant. */
template <typename engine_type_>
int uring_close_socket(engine_type_& engine, descriptor_t descriptor) noexcept {
    auto& queue = engine.queue;
    if (!queue.is_open()) return 0;
    auto* owner = engine.socket_slots.find(descriptor);
    if (!owner) return 0;
    auto serial = owner->serial;
    engine.retire(*owner);
    while (owner->stage != uring_socket_stage_t::vacant_k && owner->serial == serial && !queue.fault) {
        int result = queue.enter(1, 0);
        if (result < 0) {
            queue.fault = result;
            break;
        }
        uring_reap(engine);
    }
    return queue.fault;
}

/** Opens a registered TCP socket with Nagle off, through two control commands. */
template <typename engine_type_>
descriptor_t uring_open_socket(engine_type_& engine, int family) noexcept {
    auto& queue = engine.queue;
    auto& socket_slots = engine.socket_slots;
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
    int result = uring_wait_control(engine);
    if (result < 0) {
        if (queue.control.result) socket_slots.vacate(*target);
        return result;
    }
    target->stage = uring_socket_stage_t::open_k;
    auto handle = registered_socket_t {target->index}.handle();
    submission = queue.entry();
    if (!submission) {
        [[maybe_unused]] int const closed = uring_close_socket(engine, handle);
        return -EIO;
    }
    queue.storage->socket_option_value = 1;
    io_uring_prep_cmd_sock(submission, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(target->index), IPPROTO_TCP,
                           TCP_NODELAY, &queue.storage->socket_option_value,
                           sizeof(queue.storage->socket_option_value));
    submission->flags |= IOSQE_FIXED_FILE;
    queue.command(submission);
    result = uring_wait_control(engine);
    if (result < 0) {
        [[maybe_unused]] int const closed = uring_close_socket(engine, handle);
        return result;
    }
    return handle;
}

/** Hands receive buffer @p index back to the kernel's ring, unleased. */
template <typename engine_type_>
void uring_recycle(engine_type_& engine, unsigned index) noexcept {
    engine.buffers[index] = {};
    engine.queue.return_buffer(index);
}

/** Cancels the operation carrying @p request, if its socket still owns one. */
template <typename engine_type_>
ucall_status_t uring_cancel(engine_type_& engine, io_request_t& request) noexcept {
    // A release ends on its notifications, a close on its last socket operation, never sooner.
    if (request.operation == io_operation_t::close_k || request.operation == io_operation_t::zero_copy_release_k)
        return ucall_status_success_k;
    auto* owner = engine.socket_slots.find(request.descriptor);
    auto* operation = owner ? engine.operations.owned(*owner, request) : nullptr;
    return operation ? engine.cancel(*operation) : ucall_status_not_found_k;
}

/** Settles every entry queued since the last submission as if the kernel cancelled it. */
template <typename engine_type_>
void uring_discard_unsubmitted(engine_type_& engine) noexcept {
    auto& ring = engine.queue.ring;
    auto head = io_uring_smp_load_acquire(ring.sq.khead);
    for (auto i = head; i != ring.sq.sqe_tail; ++i) engine.discard(ring.sq.sqes[i & ring.sq.ring_mask].user_data);
    ring.sq.sqe_head = ring.sq.sqe_tail = head;
    io_uring_smp_store_release(ring.sq.ktail, head);
}

/** Cancels and reaps everything the kernel still holds once a submission faulted. */
template <typename engine_type_>
[[nodiscard]] ucall_status_t uring_drain_after_fault(engine_type_& engine) noexcept {
    auto& queue = engine.queue;
    queue.stage = uring_engine_stage_t::recovering_k;
    uring_discard_unsubmitted(engine);
    if (ucall_status_t const cancelled = queue.cancel_synchronously(); cancelled != ucall_status_success_k)
        return cancelled;
    if (ucall_status_t const unregistered = queue.unregister_files(); unregistered != ucall_status_success_k)
        return unregistered;
    uring_reap(engine);
    while (engine.has_kernel_work()) {
        int result = queue.retry_interrupted(
            [&] { return io_uring_enter(queue.ring.ring_fd, 0, 1, IORING_ENTER_GETEVENTS, nullptr); });
        if (result < 0) {
            queue.fault = result;
            return ucall_status_io_k;
        }
        uring_reap(engine);
    }
    return ucall_status_success_k;
}

/** Grows @p engine's operation records, socket slots and registered table to @p capacity before
 *  any thread entered its ring, which keeps the size and locked memory its open proved; each
 *  slot takes @p slot_arguments, as in @c open. */
template <typename engine_type_, typename... slot_arguments_type_>
[[nodiscard]] ucall_status_t uring_grow(engine_type_& engine, std::size_t capacity,
                                        slot_arguments_type_ const&... slot_arguments) noexcept {
    auto& queue = engine.queue;
    if (queue.stage != uring_engine_stage_t::running_k || queue.issuer != uring_issuer_t::unclaimed_k)
        return ucall_status_invalid_argument_k;
    if (capacity > static_cast<std::size_t>(registered_socket_t::tag_k)) return ucall_status_overflow_k;
    std::size_t const sockets = std::min(capacity, open_files_limit());
    std::destroy_at(&engine.operations);
    std::construct_at(&engine.operations, queue.allocator);
    std::destroy_at(&engine.socket_slots);
    std::construct_at(&engine.socket_slots, queue.allocator);
    if (engine.operations.open(capacity) != ucall_status_success_k ||
        engine.socket_slots.open(sockets, slot_arguments...) != ucall_status_success_k ||
        engine.zero_copy.open(capacity, queue.allocator) != ucall_status_success_k)
        return ucall_status_out_of_memory_k;
    if (ucall_status_t const unregistered = queue.unregister_files(); unregistered != ucall_status_success_k)
        return unregistered;
    if (io_uring_register_files_sparse(&queue.ring, static_cast<unsigned>(sockets)) < 0) return ucall_status_io_k;
    queue.file_registration = uring_registration_t::registered_k;
    return ucall_status_success_k;
}

/** Retires every socket, reaps what the kernel still holds, then closes the ring. */
template <typename engine_type_>
void uring_stop(engine_type_& engine) noexcept {
    auto& queue = engine.queue;
    if (!queue.is_open()) return;
    queue.stage = uring_engine_stage_t::stopping_k;
    if (!queue.fault) {
        for (auto& owner : engine.socket_slots.records)
            if (owner.stage != uring_socket_stage_t::vacant_k) engine.retire(owner);
        while (engine.has_kernel_work() && !queue.fault) {
            int result = queue.enter(1, 0);
            if (result < 0) {
                queue.fault = result;
                break;
            }
            uring_reap(engine);
        }
    }
    // Failed submission must not bypass terminal CQEs that still reference caller memory.
    ucall_status_t const retirement = queue.fault ? uring_drain_after_fault(engine) : queue.unregister_files();
    engine.operations.close_uncollected_files();
    queue.close(retirement);
    for (auto& owner : engine.socket_slots.records) owner.stage = uring_socket_stage_t::vacant_k;
}

/** Marks the close of @p descriptor to send a reset rather than a FIN, without a round trip. */
template <typename engine_type_>
[[nodiscard]] ucall_status_t uring_reset_on_close(engine_type_& engine, descriptor_t descriptor) noexcept {
    auto* owner = engine.socket_slots.find(descriptor);
    if (!owner) return ucall_status_io_k;
    owner->close = close_mode_t::reset_k;
    return ucall_status_success_k;
}

/** One-shot requests over registered sockets, submitted through the liburing SQ. */
template <typename allocator_type_ = st::default_allocator<byte_t>,
          template <typename> class atomic_ref_template_ = fu::standard_atomic_ref,
          typename row_kit_type_ = st::serial_row_kit_t>
struct linux_uring612_engine {
    using allocator_t = allocator_type_;
    template <typename other_allocator_type_, template <typename> class other_atomic_ref_, typename other_row_kit_>
    using rebind = linux_uring612_engine<other_allocator_type_, other_atomic_ref_, other_row_kit_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    template <typename value_type_>
    using vector = st::vector<value_type_, rebound_allocator<value_type_>>;
    static constexpr unsigned absent_k = operation_list_t::absent_k;

    struct alignas(8) socket_slot_t {
        unsigned index {}, next {absent_k}, owned_head {absent_k}, close_operation {absent_k};
        std::uint64_t serial {};
        uring_socket_stage_t stage {uring_socket_stage_t::vacant_k};
        zero_copy_stage_t zero_copy {zero_copy_stage_t::untried_k};
        uring_retirement_t retirement {uring_retirement_t::serving_k};
        close_mode_t close {close_mode_t::orderly_k};
    };
    static_assert(sizeof(socket_slot_t) == 32);
    struct buffer_t {
        uring_lease_t lease {uring_lease_t::returned_k};
    };
    using queue_t = uring_queue<allocator_t, atomic_ref_template_>;
    using socket_slots_t = uring_socket_slots<socket_slot_t, allocator_t>;
    using operations_t = uring_operations<socket_slot_t, allocator_t>;
    using zero_copy_t = uring_zero_copy<socket_slot_t, allocator_t, atomic_ref_template_, row_kit_type_>;
    using operation_t = typename operations_t::operation_t;
    static_assert(sizeof(operation_t) == 64);
    static constexpr io_uring_op opcodes_k[] {
        IORING_OP_SOCKET,    IORING_OP_ACCEPT,   IORING_OP_CONNECT, IORING_OP_RECV,         IORING_OP_SEND,
        IORING_OP_READ,      IORING_OP_SHUTDOWN, IORING_OP_CLOSE,   IORING_OP_ASYNC_CANCEL, IORING_OP_LINK_TIMEOUT,
        IORING_OP_URING_CMD, IORING_OP_OPENAT2,  IORING_OP_SEND_ZC, IORING_OP_READ_FIXED,   IORING_OP_READV};

    io_statistics_t statistics {};
    queue_t queue;
    socket_slots_t socket_slots;
    operations_t operations;
    zero_copy_t zero_copy;
    vector<buffer_t> buffers;

    /** Why @c open answered @c ucall_status_unsupported_k, naming the setting to raise. */
    char const* refusal {};

    explicit linux_uring612_engine(allocator_t const& instance = {}) noexcept
        : queue(instance, statistics), socket_slots(instance), operations(instance), zero_copy(statistics),
          buffers(rebound_allocator<buffer_t> {instance}) {}
    linux_uring612_engine(linux_uring612_engine const&) = delete;
    linux_uring612_engine& operator=(linux_uring612_engine const&) = delete;
    linux_uring612_engine(linux_uring612_engine&&) = delete;
    linux_uring612_engine& operator=(linux_uring612_engine&&) = delete;
    ~linux_uring612_engine() noexcept { stop(); }

    bool is_open() const noexcept { return queue.is_open(); }
    bool has_kernel_work() const noexcept {
        return !queue.control.result || operations.outstanding_operations || zero_copy.outstanding_notifications ||
               socket_slots.closing();
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
            socket_slots.open(sockets) != ucall_status_success_k ||
            zero_copy.open(capacity, queue.allocator) != ucall_status_success_k ||
            st::failed(buffers.resize(queue.buffer_count)))
            return ucall_status_out_of_memory_k;
        ucall_status_t const opened = queue.open(depth, sockets, opcodes_k);
        if (opened == ucall_status_success_k) return opened;
        // Only ring setup fails before the ring opens.
        if (queue.is_open()) stop();
        else refusal = uring_setup_refusal_k;
        return opened;
    }
    int wait_control() noexcept { return uring_wait_control(*this); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept {
        return socket_slots.import_socket(descriptor, queue);
    }
    descriptor_t open_socket(int family) noexcept { return uring_open_socket(*this, family); }
    void recycle(unsigned index) noexcept { uring_recycle(*this, index); }
    void release(io_completion_t const& completion) noexcept {
        if (!queue.is_open() || !completion.lease) return;
        auto index = static_cast<unsigned>(completion.lease - 1);
        if (index < buffers.size() && buffers[index].lease == uring_lease_t::leased_k) {
            if (queue.receive_ring) recycle(index);
            else buffers[index] = {};
        }
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
        auto status = start_operation(*operation);
        if (status != ucall_status_success_k) operations.vacate(*operation);
        return status;
    }
    ucall_status_t start_operation(operation_t& operation) noexcept {
        auto& request = *operation.request;
        if (request.operation == io_operation_t::receive_k && !queue.available_buffers) {
            operations.push(operations.waiting_operations, operation);
            return ucall_status_success_k;
        }
        ucall_status_t status;
        auto* submission = operations.entry(operation, queue, socket_slots, status);
        if (!submission) return status;
        if (request.operation == io_operation_t::receive_k) {
            io_uring_prep_recv(submission, static_cast<int>(operation.socket_slot->index), nullptr,
                               static_cast<unsigned>(std::min(request.length, queue.page)), 0);
            submission->flags |= IOSQE_BUFFER_SELECT;
            submission->buf_group = 0;
        }
        else if (request.operation == io_operation_t::file_read_vectors_k) {
            io_uring_prep_readv(submission, request.file.file_descriptor, io_vectors(request).data(),
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
        if (operation.in_flight()) return operations.cancel_in_flight(operation, queue);
        operations.unlink(operations.waiting_operations, operation);
        operation.result = -ECANCELED;
        operations.complete(operation);
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
        }
        if (owner.stage == uring_socket_stage_t::installing_k || owner.stage == uring_socket_stage_t::closing_k ||
            operations.owns_in_flight(owner))
            return;
        if (owner.stage == uring_socket_stage_t::closed_k) operations.finish_close(owner, socket_slots);
        else socket_slots.submit_close(owner, queue);
    }
    int close_socket(descriptor_t descriptor) noexcept { return uring_close_socket(*this, descriptor); }
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
        if (kind == uring_release_tag_k) {
            auto* settled = zero_copy.settle(*static_cast<operation_t*>(pointer), completion, operations, socket_slots);
            if (settled && settled->retirement == uring_retirement_t::retiring_k) retire(*settled);
            return;
        }
        auto& operation = *static_cast<operation_t*>(pointer);
        if (completion.flags & IORING_CQE_F_BUFFER) {
            --queue.available_buffers;
            operation.buffer = completion.flags >> IORING_CQE_BUFFER_SHIFT;
            buffers[operation.buffer].lease = uring_lease_t::leased_k;
        }
        if (auto* accepted = operations.settle(operation, completion, queue, socket_slots)) retire(*accepted);
        if (operation.socket_slot->retirement == uring_retirement_t::retiring_k) retire(*operation.socket_slot);
    }
    void reap() noexcept { uring_reap(*this); }
    int collect(span<io_completion_t> output) noexcept {
        std::size_t count {};
        while (count != output.size()) {
            auto* operation = operations.pop(operations.completed_operations);
            if (!operation) break;
            output[count++] = operations.completion_of(*operation, queue);
            operations.vacate(*operation);
        }
        return static_cast<int>(count);
    }
    void maintain() noexcept {
        if (queue.fault) return;
        for (auto retry = std::exchange(operations.waiting_operations, {}); auto* operation = operations.pop(retry);)
            if (start_operation(*operation) != ucall_status_success_k) queue.fault = -EIO;
    }
    int poll(span<io_completion_t> output, io_wait_t policy, std::uint64_t deadline = 0) noexcept {
        if (!queue.is_open()) return -EBADF;
        for (;;) {
            reap();
            maintain();
            if (queue.fault) return queue.fault;
            int count = collect(output);
            if (count) return count;
            unsigned wait = policy == io_wait_t::blocking_k && (!deadline || monotonic_ns() < deadline) ? 1 : 0;
            int result = queue.enter(wait, deadline);
            if (result < 0) return result;
            reap();
            maintain();
            count = collect(output);
            if (count || policy == io_wait_t::nonblocking_k || (deadline && monotonic_ns() >= deadline)) return count;
        }
    }
    void discard(std::uint64_t user_data) noexcept {
        uring_discard(user_data, queue, operations, socket_slots, zero_copy);
    }
    void discard_unsubmitted() noexcept { uring_discard_unsubmitted(*this); }
    [[nodiscard]] ucall_status_t drain_after_fault() noexcept { return uring_drain_after_fault(*this); }
    [[nodiscard]] ucall_status_t grow(std::size_t capacity) noexcept { return uring_grow(*this, capacity); }
    void stop() noexcept { uring_stop(*this); }
};

using linux_uring612_engine_t = linux_uring612_engine<>;

} // namespace unum::ucall::io
