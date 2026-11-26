/**
 *  @file include/ucall/io/linux_uring612_queue.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Registered sockets and single-shot buffer-select receives for Linux 6.12 io_uring,
 *      and the ring components the 6.18 queue composes too.
 */
#pragma once

#include <algorithm> // `std::clamp`
#include <bit>       // `std::bit_ceil`, `std::bit_floor`, `std::countr_zero`
#include <optional>

#include <liburing.h>

#include <smashtable/basic_vector.hpp> // `vector`
#include <smashtable/row_search.hpp>   // `serial_row_kit_t`

#include "ucall/io/types.hpp"          // `operation_list_t`, `io_request_t`, `io_statistics_t`, `tally`
#include "ucall/utilities/sockets.hpp" // `socket_reset_linger_k`, `page_size`, `native_file_open_flags_k`
#include "ucall/utilities/types.hpp"   // `descriptor_t`, `byte_t`, `allocated_ptr`, `allocator_delete`

namespace unum::ucall::io {

using utilities::allocate_unique;
using utilities::allocated_ptr;
using utilities::allocator_delete;
using utilities::byte_t;
using utilities::bytes_of;
using utilities::close_native_file;
using utilities::descriptor_t;
using utilities::largest_receive_buffer;
using utilities::monotonic_ns;
using utilities::native_file_open_flags_k;
using utilities::open_files_limit;
using utilities::open_native_file_finish;
using utilities::page_size;
using utilities::socket_close;
using utilities::socket_option;
using utilities::socket_reset_linger_k;
using utilities::span;

/** Slots in an io_uring registered-buffer table, the kernel's @c IORING_MAX_REG_BUFFERS. */
inline constexpr unsigned uring_registered_buffers_limit_k = 16384;

/** Slots in an io_uring registered-file table, the kernel's @c IORING_MAX_FIXED_FILES. */
inline constexpr std::size_t uring_registered_files_limit_k = std::size_t {1} << 20;

/** Registered sockets a queue of @p capacity operations holds: one per operation, within the open
 *  files the process may hold and the kernel's file table, both less the exit signal's slot, as a
 *  table refused would refuse the ring. */
inline std::size_t uring_socket_capacity(std::size_t capacity) noexcept {
    return fu::min_of(fu::min_of(capacity, open_files_limit() - 1), uring_registered_files_limit_k - 1);
}

/** Why a queue's @c open answered @c ucall_status_unsupported_k before its ring existed. */
inline constexpr char const* uring_setup_refusal_k =
    "io_uring ring setup failed: raise `ulimit -l`, free contiguous memory or pick linux-epollaio";

enum class uring_queue_stage_t : std::uint8_t {

    /** Never opened. */
    idle_k,

    /** The ring is open and serving. */
    running_k,

    /** Retiring every socket and reaping what the kernel holds, inside @c stop. */
    stopping_k,

    /** Cancelling and reaping what the kernel holds after a fault. */
    recovering_k,

    /** The ring is closed, and the queue never opens again. */
    stopped_k,
};

/** Whether a thread entered the ring yet, becoming its one issuer. */
enum class uring_issuer_t : std::uint8_t {

    /** No thread entered the ring, so it is still disabled and may grow. */
    unclaimed_k,

    /** A thread enabled the ring and became its issuer. */
    claimed_k,
};

/** Where an operation record stands between the request that takes it and its collection. */
enum class uring_operation_stage_t : std::uint8_t {

    /** Not yet submitted, or waiting for a buffer, a slot or a retry. */
    waiting_k,

    /** Held by the kernel. */
    submitted_k,

    /** Held by the kernel, which was asked to cancel it. */
    cancelling_k,

    /** Answered, waiting for its collection. */
    completed_k,

    /** Answered like @c completed_k, by an accept whose request stays submitted for more. */
    yielded_k,

    /** A release some zero-copy send named before its request was submitted. */
    collecting_k,

    /** A release submitted, waiting for the notifications still due. */
    releasing_k,

    /** An accept's anchor while the kernel holds its accepts on records of their own. */
    accepting_k,

    /** An accept's anchor waiting for the last of them, after a cancel or its length ran out. */
    ending_k
};
enum class uring_socket_stage_t : std::uint8_t {

    /** Free, holding no descriptor. */
    vacant_k,

    /** Reserved while a socket or an accept installs a descriptor into it. */
    installing_k,

    /** Still installing, and retired meanwhile, so it closes once the descriptor is in. */
    abandoned_k,

    /** Holding an open registered descriptor and taking operations. */
    open_k,

    /** Open, cancelling what it owns, and closing once the kernel holds none of it. */
    retiring_k,

    /** Its close is in the kernel. */
    closing_k,

    /** Closed, waiting for whatever still refers to the slot. */
    closed_k,
};

/** Whether a socket slot in @p stage still takes operations. */
constexpr bool uring_serves(uring_socket_stage_t stage) noexcept {
    return stage == uring_socket_stage_t::installing_k || stage == uring_socket_stage_t::open_k;
}

/** The stage a slot enters once its descriptor is installed: open, or retiring if abandoned. */
constexpr uring_socket_stage_t uring_installed(uring_socket_stage_t stage) noexcept {
    return stage == uring_socket_stage_t::abandoned_k ? uring_socket_stage_t::retiring_k : uring_socket_stage_t::open_k;
}

/** Whether an operation's deadline passed, so its cancellation completes as a timeout. */
enum class uring_expiry_t : std::uint8_t {

    /** No deadline passed yet, or none was set. */
    waiting_k,

    /** The deadline passed, so a cancelled completion reports @c -ETIMEDOUT. */
    expired_k,
};

/** Where a receive's bytes wait for the caller: a queue buffer, or its socket's backlog. */
enum class uring_receive_source_t : std::uint8_t {

    /** A slice of the provided pool, named by the record's @c buffer. */
    buffer_k,

    /** The socket's backlog, from its @c backlog_offset on. */
    backlog_k,
};

/** Whether a table is registered with the ring. */
enum class uring_registration_t : std::uint8_t {

    /** Not registered, so no submission may name its slots. */
    unregistered_k,

    /** Registered, so submissions name its slots. */
    registered_k,
};

/** Whether a received slice is still in the caller's hands, from the completion that
 *  names it until @c release. */
enum class receive_slice_state_t : std::uint8_t {

    /** No slice awaits @c release. */
    released_k,

    /** A completion named the slice, and @c release has not run for it. */
    awaiting_release_k,
};

/** Tags in the low bits of a submission's user data, naming what its completion settles. */
inline constexpr std::uintptr_t uring_operation_tag_k = 0, uring_control_tag_k = 1, uring_release_tag_k = 2,
                                uring_receive_tag_k = 3, uring_close_tag_k = 4, uring_cancel_tag_k = 7;

/** One request on a registered socket, the zero-copy release its sends name, or one connection
 *  an accept takes, which shares the request with the accept's anchor, the record it names. */
template <typename socket_slot_type_>
struct alignas(8) uring_operation {

    /** The request the record holds, or null while it is free; an accept's records share one. */
    io_request_t* request {};

    /** The socket owning the record, or null for a release or a request no serving socket took. */
    socket_slot_type_* socket_slot {};

    /** What the operation completes with, set as its completion settles. */
    descriptor_t result {};

    /** The record before this one on the list holding it, so a list unlinks it in place. */
    unsigned previous {absent_k};

    /** For one connection of an accept, the slot it accepts into; else @c absent_k. */
    unsigned accepted {absent_k};

    /** The pool offset of the slice a receive filled, or @c absent_k while it holds none. */
    unsigned buffer {absent_k};

    /** The record after this one on the free, completed, waiting or timed list holding it. */
    unsigned next {absent_k};

    /** The next operation of the same socket slot. */
    unsigned owned_next {absent_k};

    /** A zero-copy send's release, or a release's send in flight. */
    unsigned paired_operation {absent_k};
    union {

        /** A release's zero-copy sends whose notification is due. */
        std::uint32_t outstanding_notifications {};

        /** An accept anchor's accepts the kernel holds. */
        std::uint32_t accepting;
    };

    /** Where the record stands, from the request taking it to its collection. */
    uring_operation_stage_t stage {uring_operation_stage_t::waiting_k};

    /** Whether the deadline passed, so a cancelled completion reports @c -ETIMEDOUT. */
    uring_expiry_t expiry {uring_expiry_t::waiting_k};

    /** Where a 6.18 receive's bytes wait: a pool slice, or its socket's backlog. */
    uring_receive_source_t receive_source {uring_receive_source_t::buffer_k};

    /** Whether a 6.18 receive with a deadline is on the queue's @c timed_operations. */
    listing_t timed_listing {listing_t::unlisted_k};
    bool in_flight() const noexcept {
        return stage == uring_operation_stage_t::submitted_k || stage == uring_operation_stage_t::cancelling_k;
    }

    /** Whether its completion already waits for collection. */
    bool answered() const noexcept {
        return stage == uring_operation_stage_t::completed_k || stage == uring_operation_stage_t::yielded_k;
    }
};

/** The receive pool the kernel consumes by bytes, and each buffer's cursor; two buffers are
 *  provided at first, doubling only once the kernel runs out, so that resident memory follows
 *  the peak batch of receives. */
template <typename allocator_type_>
struct uring_provided_buffers {
    using allocator_t = allocator_type_;
    template <typename value_type_>
    using vector =
        st::vector<value_type_, typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>>;

    /** How far the kernel filled a buffer, and how many of its slices await @c release. */
    struct record_t {

        /** Bytes the kernel filled, or the whole buffer once it moved past it. */
        std::uint32_t consumed_bytes {};

        /** Slices of the buffer that completions named and @c release has not run for. */
        std::uint32_t slices_awaiting_release {};
    };
    static_assert(sizeof(record_t) == 8);

    /** The pool, a power of two of equal buffers, backed only as receives touch it. */
    vector<byte_t> memory;

    /** Each buffer's fill and its slices awaiting @c release. */
    vector<record_t> records;

    /** The buffer ring the kernel picks from, null before the ring opens or once it is freed. */
    io_uring_buf_ring* receive_ring {};

    /** Buffers ever handed to the kernel, the pool's first ones. */
    unsigned provided_buffers {};

    /** Buffers the kernel can still pick. */
    unsigned available_buffers {};

    /** The buffer the kernel consumes, unknown until its first slice. */
    unsigned newest_buffer {absent_k};

    /** The base-2 logarithm of one buffer's bytes, which maps offsets to buffers. */
    std::size_t buffer_bytes_log2 {};

    /** Bytes of one buffer. */
    std::size_t buffer_bytes() const noexcept { return std::size_t {1} << buffer_bytes_log2; }

    /** Buffers in the pool, a power of two. */
    unsigned buffer_count() const noexcept { return static_cast<unsigned>(records.size()); }

    explicit uring_provided_buffers(allocator_t const& allocator) noexcept : memory(allocator), records(allocator) {}

    /** Sizes the pool for @p capacity operations of @p page bytes each, up to the kernel's limit of
     *  entries; a buffer as large as a socket's receive buffer spans one kernel read. */
    ucall_status_t reserve(std::size_t capacity, std::size_t page) noexcept {
        std::size_t const pool = std::bit_ceil(std::clamp<std::size_t>(capacity, 2, 32768)) * page;
        buffer_bytes_log2 = static_cast<std::size_t>(
            std::countr_zero(std::bit_floor(std::clamp(largest_receive_buffer(AF_INET, page), page, pool / 2))));
        // Untouched pages stay unbacked until a receive lands in them.
        if (st::failed(memory.resize(st::assume_uninitialized, pool)) ||
            st::failed(records.resize(pool >> buffer_bytes_log2)))
            return ucall_status_out_of_memory_k;
        return ucall_status_success_k;
    }

    /** Takes the next @p length bytes of buffer @p index, which the kernel just filled, as a slice
     * that stays valid until @c release_slice; only a positive receive advances the cursor, as an
     * end of stream names a buffer it left unused. */
    span<byte_t> take_received_slice(unsigned index, std::size_t length) noexcept {
        // Consumption is FIFO, so a new buffer means the previous one was left, even if short.
        if (newest_buffer != index && newest_buffer != absent_k) leave_buffer(newest_buffer);
        newest_buffer = index;
        record_t& record = records[index];
        std::size_t const start = record.consumed_bytes;
        record.consumed_bytes += static_cast<std::uint32_t>(length);
        ++record.slices_awaiting_release;
        if (record.consumed_bytes == buffer_bytes()) {
            newest_buffer = absent_k;
            leave_buffer(index);
        }
        return span<byte_t> {memory}.subspan((std::size_t {index} << buffer_bytes_log2) + start, length);
    }

    /** Releases @p slice, providing its buffer again once the kernel left it and no
     *  slice awaits release. */
    void release_slice(span<byte_t const> slice) noexcept {
        unsigned const index = static_cast<unsigned>(offset_of(slice) >> buffer_bytes_log2);
        record_t& record = records[index];
        if (--record.slices_awaiting_release || record.consumed_bytes != buffer_bytes()) return;
        record = {};
        provide(index);
    }

    /** The mapping @c io_uring_setup_buf_ring made for the ring's entries. */
    std::size_t receive_ring_bytes() const noexcept {
        return std::size_t {buffer_count()} * sizeof(*receive_ring->bufs);
    }

    /** Doubles the buffers handed to the kernel, once it has none left to pick. */
    void provide_more() noexcept {
        unsigned const target = fu::min_of(fu::max_of(provided_buffers * 2, 2u), buffer_count());
        for (; provided_buffers != target; ++provided_buffers) provide(provided_buffers);
    }

    /** Where @p slice starts in the pool. */
    std::size_t offset_of(span<byte_t const> slice) const noexcept {
        return static_cast<std::size_t>(slice.data() - memory.data());
    }

  private:
    /** Marks buffer @p index as left by the kernel, however much of it was filled. */
    void leave_buffer(unsigned index) noexcept {
        record_t& record = records[index];
        record.consumed_bytes = static_cast<std::uint32_t>(buffer_bytes());
        --available_buffers;
        if (!record.slices_awaiting_release) {
            record = {};
            provide(index);
        }
        if (!available_buffers) provide_more();
    }

    /** Adds buffer @p index whole, as the kernel rewrites an entry's address and length. */
    void provide(unsigned index) noexcept {
        ++available_buffers;
        io_uring_buf_ring_add(receive_ring, memory.data() + (std::size_t {index} << buffer_bytes_log2),
                              static_cast<unsigned>(buffer_bytes()), static_cast<unsigned short>(index),
                              buffer_count() - 1, 0);
        io_uring_buf_ring_advance(receive_ring, 1);
    }
};

/** The ring, its registered tables and receive buffers, and the control word its synchronous
 *  commands complete into. */
template <typename allocator_type_, template <typename> class atomic_ref_template_>
struct uring_state {
    using allocator_t = allocator_type_;
    template <typename value_type_>
    using atomic_ref = atomic_ref_template_<value_type_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;

    struct alignas(8) control_t {

        /** The command's result, or empty while it is in flight. */
        std::optional<int> result {0};
    };
    struct storage_t {

        /** The @c TCP_NODELAY value a socket command passes, read by the kernel at submission. */
        int socket_option_value {1};

        /** The @c SO_LINGER a close marked to reset sets first, read by the kernel then. */
        linger reset_linger {socket_reset_linger_k};
        open_how open_resolution {}; // Read by the kernel as an `IORING_OP_OPENAT2` is submitted.
        storage_t() noexcept = default;
        storage_t(storage_t const&) = delete;
        storage_t& operator=(storage_t const&) = delete;
        storage_t(storage_t&&) = delete;
        storage_t& operator=(storage_t&&) = delete;
    };

    /** The ring, valid while @c is_open holds. */
    io_uring ring {};

    /** What the pool, the storage and the queue's grown records allocate from. */
    [[no_unique_address]] allocator_t allocator;

    /** The receive pool the kernel picks buffers from. */
    uring_provided_buffers<allocator_t> provided;

    /** The owning queue's counters. */
    io_statistics_t& statistics;

    /** What the kernel reads at submission, kept at one address; null before @c reserve. */
    allocated_ptr<storage_t, allocator_t> storage;

    /** Where the one synchronous command in flight lands. */
    control_t control {};

    /** Slots of the sparse buffer table @c register_memory filled, the next one's index. */
    unsigned registered_buffers {};

    /** The system page size, which caps a @c read_k and the backlog a closed socket keeps. */
    std::size_t page_bytes {};

    /** Where the ring stands, from idle through running to stopped. */
    uring_queue_stage_t stage {uring_queue_stage_t::idle_k};

    /** Whether the sparse file table of sockets and the exit signal is registered. */
    uring_registration_t file_registration {uring_registration_t::unregistered_k};

    /** Whether the sparse buffer table is registered, so @c register_memory may pin ranges. */
    uring_registration_t buffer_registration {uring_registration_t::unregistered_k};

    /** Whether a thread enabled the ring yet. */
    uring_issuer_t issuer {uring_issuer_t::unclaimed_k};

    /** The error that ended the ring's use, which every poll then answers, or zero. */
    int fault {};

    /** The read end of a pipe whose only write end sits in the file table, armed at @c claim. */
    descriptor_t exit_descriptor {-1};

    /** Completions reaped since the last enter returned, which the next waiting one waits for as
     *  many of. */
    unsigned reaped_since_enter {};

    /** When the last enter returned, waiting or not, so the next waiting one waits at most as long
     *  as the loop since spent handling what it reaped; zero before the first. */
    std::uint64_t enter_returned_ns {};

    /** The file-table slot past the sockets', holding the exit pipe's write end. */
    unsigned exit_slot {};

    uring_state(allocator_t const& instance, io_statistics_t& counters) noexcept
        : allocator(instance), provided(instance), statistics(counters),
          storage(nullptr, allocator_delete<storage_t, allocator_t> {instance}) {}
    uring_state(uring_state const&) = delete;
    uring_state& operator=(uring_state const&) = delete;
    uring_state(uring_state&&) = delete;
    uring_state& operator=(uring_state&&) = delete;

    bool is_open() const noexcept {
        return stage != uring_queue_stage_t::idle_k && stage != uring_queue_stage_t::stopped_k;
    }
    static std::uintptr_t tag(void* pointer, std::uintptr_t kind) noexcept {
        return reinterpret_cast<std::uintptr_t>(pointer) | kind;
    }
    static __kernel_timespec timespec_of(std::uint64_t nanoseconds) noexcept {
        return {static_cast<__kernel_time64_t>(nanoseconds / 1'000'000'000),
                static_cast<long long>(nanoseconds % 1'000'000'000)};
    }

    /** Hands the ring the only write end of a pipe, so end of file means it released its table,
     *  which it does once every request ended. */
    int arm_exit_signal() noexcept {
        if (exit_descriptor >= 0) return 0;
        int ends[2];
        if (pipe2(ends, O_CLOEXEC) != 0) return -errno;
        int const installed = io_uring_register_files_update(&ring, exit_slot, &ends[1], 1);
        close_native_file(ends[1]);
        if (installed != 1) {
            close_native_file(ends[0]);
            return installed < 0 ? installed : -EIO;
        }
        exit_descriptor = ends[0];
        return 0;
    }

    /** Enables the ring for the calling thread at its first enter, as rings open disabled on the
     *  thread that sizes them, making that thread the one issuer of a single-issuer ring. */
    int claim() noexcept {
        if (issuer == uring_issuer_t::claimed_k) return 0;
        if (int const armed = arm_exit_signal(); armed < 0) return armed;
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
        tally<atomic_ref_template_>(statistics.kernel_entries);
        return io_uring_get_sqe(&ring);
    }
    int enter(unsigned wait, std::uint64_t deadline) noexcept {
        tally<atomic_ref_template_>(statistics.kernel_enters);
        if (int const claimed = claim(); claimed < 0) return claimed;
        // Every enter ends a round, so the count and the time a waiting one sizes itself from never
        // span the rounds of nonblocking polls before it.
        unsigned const reaped = std::exchange(reaped_since_enter, 0);
        // Deferred task work only runs inside an enter that asks for events.
        if (!wait) {
            int const result = io_uring_submit_and_get_events(&ring);
            enter_returned_ns = monotonic_ns();
            return result;
        }
        // A loop that reaped several completions last round waits for as many again, for at most as
        // long as it spent handling them, so one enter takes a round's worth while the added wait
        // stays within the loop's own recent service time. With deferred task work the kernel wakes
        // the loop only once that many are ready. A round of one, or an empty one, waits for one.
        auto now = monotonic_ns();
        std::uint64_t const handling = enter_returned_ns && now > enter_returned_ns ? now - enter_returned_ns : 0;
        if (reaped > wait && handling && (!deadline || now + handling < deadline)) {
            wait = reaped;
            deadline = now + handling;
        }
        auto timeout = timespec_of(deadline > now ? deadline - now : 0);
        io_uring_cqe* completion {};
        int result = deadline ? io_uring_submit_and_wait_timeout(&ring, &completion, wait, &timeout, nullptr)
                              : io_uring_submit_and_wait(&ring, wait);
        enter_returned_ns = monotonic_ns();
        // A signal, the deadline, or a full queue's overflow ends it empty; reaping makes room.
        return result == -ETIME || result == -EINTR || result == -EBUSY ? 0 : result;
    }

    /** Sizes the receive pool for @p capacity operations before the ring opens. */
    ucall_status_t reserve(std::size_t capacity) noexcept {
        storage = allocate_unique<storage_t>(allocator);
        if (!storage) return ucall_status_out_of_memory_k;
        page_bytes = page_size();
        if (!page_bytes || capacity > (std::numeric_limits<std::size_t>::max)() / page_bytes)
            return ucall_status_overflow_k;
        return provided.reserve(capacity, page_bytes);
    }

    /** Opens the ring with room for @p files registered sockets and the exit signal, refusing a
     *  kernel lacking any of @p opcodes. */
    ucall_status_t open(std::size_t depth, std::size_t files, span<io_uring_op const> opcodes,
                        io_issuer_scope_t scope) noexcept {
        io_uring_params parameters {};
        parameters.flags = IORING_SETUP_CLAMP | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_NO_SQARRAY |
                           IORING_SETUP_R_DISABLED;
        // A foreign free still progresses: task work runs at the issuer's next kernel entry.
        parameters.flags |= scope == io_issuer_scope_t::one_thread_k
                                ? IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN
                                : IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG;
        // Each one-shot operation may hold a linked timeout.
        auto entries = static_cast<unsigned>(
            fu::min_of(depth, static_cast<std::size_t>((std::numeric_limits<unsigned>::max)() / 2)) * 2);
        // io_uring bills rings to the locked-memory limit, so ENOMEM points at it, not the heap.
        int result = io_uring_queue_init_params(entries, &ring, &parameters);
        if (result < 0) return ucall_status_unsupported_k;
        stage = uring_queue_stage_t::running_k;
        constexpr auto probe_length = unsigned {(std::numeric_limits<decltype(io_uring_probe_op::op)>::max)()} + 1;
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
        storage->open_resolution.flags = native_file_open_flags_k;
        storage->open_resolution.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
        if (register_table(files) != ucall_status_success_k) return ucall_status_unsupported_k;
        // An empty table locks no memory; `register_memory` pins one range per slot as it fills.
        if (io_uring_register_buffers_sparse(&ring, uring_registered_buffers_limit_k) == 0)
            buffer_registration = uring_registration_t::registered_k;
        provided.receive_ring = io_uring_setup_buf_ring(&ring, provided.buffer_count(), 0, IOU_PBUF_RING_INC, &result);
        if (!provided.receive_ring) return ucall_status_unsupported_k;
        provided.provide_more();
        return ucall_status_success_k;
    }

    /** Pins @p memory into the next slot of the sparse buffer table: @c unpinned_k once the
     *  locked-memory cap refuses or the table is full, and @c ucall_status_io_k on any other
     *  refusal of the kernel's. */
    memory_registration_t register_memory(span<byte_t> memory) noexcept {
        if (buffer_registration != uring_registration_t::registered_k ||
            registered_buffers == uring_registered_buffers_limit_k)
            return {};
        iovec range {};
        range.iov_base = memory.data();
        range.iov_len = memory.size();
        int const registered = io_uring_register_buffers_update_tag(&ring, registered_buffers, &range, nullptr, 1);
        if (registered == 1) return {static_cast<registered_memory_t>(registered_buffers++)};
        if (registered == -ENOMEM) return {};
        return {io_unregistered_k, ucall_status_io_k};
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

    /** Registers an empty table of @p files sockets, with the exit signal's slot after them. */
    [[nodiscard]] ucall_status_t register_table(std::size_t files) noexcept {
        if (io_uring_register_files_sparse(&ring, static_cast<unsigned>(files) + 1) < 0) return ucall_status_io_k;
        exit_slot = static_cast<unsigned>(files);
        file_registration = uring_registration_t::registered_k;
        return ucall_status_success_k;
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

    /** Blocks until the ring released its table, proving every request ended, then unmaps the
     *  buffer ring a failed retirement could not free. */
    void await_ring_exit() noexcept {
        byte_t ignored;
        ssize_t received;
        do { received = ::read(exit_descriptor, &ignored, 1); } while (received < 0 && errno == EINTR);
        if (provided.receive_ring) munmap(provided.receive_ring, provided.receive_ring_bytes());
        provided.receive_ring = nullptr;
    }

    /** Ends the ring, and after a failed @p retirement waits for the kernel to let go, as requests
     *  may outlive the ring's descriptor. */
    void close(ucall_status_t retirement) noexcept {
        if (buffer_registration == uring_registration_t::registered_k) {
            [[maybe_unused]] int const unregistered = io_uring_unregister_buffers(&ring);
            buffer_registration = uring_registration_t::unregistered_k;
            registered_buffers = 0;
        }
        if (provided.receive_ring && retirement == ucall_status_success_k) {
            int result = retry_interrupted(
                [&] { return io_uring_free_buf_ring(&ring, provided.receive_ring, provided.buffer_count(), 0); });
            if (result) {
                fault = result;
                retirement = ucall_status_io_k;
            }
            else provided.receive_ring = nullptr;
        }
        io_uring_queue_exit(&ring);
        file_registration = uring_registration_t::unregistered_k;
        // An unclaimed ring never held a request, so it has no signal to wait on.
        if (retirement != ucall_status_success_k && exit_descriptor >= 0) await_ring_exit();
        if (exit_descriptor >= 0) close_native_file(std::exchange(exit_descriptor, -1));
        stage = uring_queue_stage_t::stopped_k;
    }
};

/** The registered socket slots, free-listed, and the peer of each; @p socket_slot_type_ holds
 *  @c index, @c next, @c serial, @c owned_head, @c close_operation, @c stage, @c zero_copy,
 *  @c retirement and @c close, as every queue's slot type does. */
template <typename socket_slot_type_, typename allocator_type_>
struct uring_socket_slots {
    using socket_slot_t = socket_slot_type_;
    using allocator_t = allocator_type_;
    template <typename value_type_>
    using vector =
        st::vector<value_type_, typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>>;

    /** One slot per index of the registered file table. */
    vector<socket_slot_t> records;

    /** Where an accept writes the peer of the socket each slot holds, which stays until the slot
     *  holds another. */
    vector<io_peer_address_t> peers;

    /** The first vacant slot, linked through @c next, or @c absent_k. */
    unsigned free_socket_slots {absent_k};

    /** Vacant slots, counted down as @c reserve takes them. */
    unsigned vacant_socket_slots {};

    /** Slots whose close the kernel holds. */
    unsigned closing_socket_slots {};

    /** The serial the latest reserved slot took. */
    std::uint64_t next_serial {};

    explicit uring_socket_slots(allocator_t const& allocator) noexcept : records(allocator), peers(allocator) {}

    /** Empties the sockets' table slots, leaving the rest of @p state's table in place. */
    template <typename state_type_>
    [[nodiscard]] ucall_status_t clear_files(state_type_& state) noexcept {
        int const empty = -1;
        for (unsigned index = 0; index != records.size(); ++index) {
            int const cleared = state.retry_interrupted(
                [&] { return io_uring_register_files_update(&state.ring, index, &empty, 1); });
            if (cleared < 0) {
                state.fault = cleared;
                return ucall_status_io_k;
            }
        }
        return ucall_status_success_k;
    }

    /** Builds @p count vacant slots from @p slot_arguments. */
    template <typename... slot_arguments_type_>
    ucall_status_t open(std::size_t count, slot_arguments_type_ const&... slot_arguments) noexcept {
        if (st::failed(records.reserve(count)) || st::failed(peers.resize(count))) return ucall_status_out_of_memory_k;
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

    /** Takes @p descriptor from its caller, whether or not a slot then registers it. */
    template <typename state_type_>
    descriptor_t import_socket(descriptor_t descriptor, state_type_& state) noexcept {
        descriptor_t const registered = register_socket(descriptor, state);
        if (descriptor >= 0) socket_close(descriptor);
        return registered;
    }
    template <typename state_type_>
    descriptor_t register_socket(descriptor_t descriptor, state_type_& state) noexcept {
        if (state.fault) return state.fault;
        if (descriptor < 0 || descriptor > (std::numeric_limits<int>::max)()) return -EINVAL;
        int protocol {}, enabled = 1;
        socklen_t length = sizeof(protocol);
        if (getsockopt(static_cast<int>(descriptor), SOL_SOCKET, SO_PROTOCOL, &protocol, &length) == 0 &&
            protocol == IPPROTO_TCP &&
            socket_option(descriptor, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) != 0)
            return -errno;
        auto* target = reserve();
        if (!target) return -ENFILE;
        int raw = static_cast<int>(descriptor);
        int result = io_uring_register_files_update(&state.ring, target->index, &raw, 1);
        if (result != 1) {
            vacate(*target);
            return result < 0 ? result : -EIO;
        }
        target->stage = uring_installed(target->stage);
        return registered_socket_t {target->index}.handle();
    }

    /** Submits the close of @p owner's registered descriptor, behind a linked @c SO_LINGER that
     *  turns it into a reset where @p owner was marked so. */
    template <typename state_type_>
    void submit_close(socket_slot_t& owner, state_type_& state) noexcept {
        auto* submission = state.entry(owner.close == close_mode_t::reset_k ? 2 : 1);
        if (!submission) {
            state.fault = -EIO;
            return;
        }
        if (owner.close == close_mode_t::reset_k) {
            // Hard-linked, so a refused option still closes, in order; its failure lands untracked.
            io_uring_prep_cmd_sock(submission, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(owner.index), SOL_SOCKET,
                                   SO_LINGER, &state.storage->reset_linger, sizeof(state.storage->reset_linger));
            submission->flags |= IOSQE_FIXED_FILE | IOSQE_IO_HARDLINK | IOSQE_CQE_SKIP_SUCCESS;
            io_uring_sqe_set_data64(submission, uring_cancel_tag_k);
            submission = state.entry();
        }
        io_uring_prep_close_direct(submission, owner.index);
        io_uring_sqe_set_data64(submission, state.tag(&owner, uring_close_tag_k));
        owner.stage = uring_socket_stage_t::closing_k;
        ++closing_socket_slots;
    }

    /** Settles the close of @p owner's descriptor, answering the slot when it closed. */
    template <typename state_type_>
    socket_slot_t* settle_close(socket_slot_t& owner, int result, state_type_& state) noexcept {
        owner.stage = uring_socket_stage_t::retiring_k;
        --closing_socket_slots;
        if (result < 0) {
            state.fault = result;
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

    /** One record per operation; those from @c first_release on serve named releases. */
    vector<operation_t> records;

    /** Each operation's linked timeout, read by the kernel at submission. */
    vector<__kernel_timespec> expiries;

    /** Free records before @c first_release, for any request. */
    operation_list_t free_operations;

    /** Free records from @c first_release on, for releases a send names. */
    operation_list_t free_releases;

    /** Records answered and awaiting collection. */
    operation_list_t completed_operations;

    /** Records waiting for a buffer, a slot, an entry or a retry, which the next poll restarts. */
    operation_list_t waiting_operations;

    /** Records the kernel holds, submitted or cancelling. */
    unsigned outstanding_operations {};

    /** Records from here on serve releases a send named, so the kernel holding those for as long
     *  as it likes never drains what connections need. */
    unsigned first_release {};

    explicit uring_operations(allocator_t const& allocator) noexcept : records(allocator), expiries(allocator) {}

    ucall_status_t open(std::size_t capacity) noexcept {
        if (st::failed(records.resize(capacity)) || st::failed(expiries.resize(capacity)))
            return ucall_status_out_of_memory_k;
        reserve_releases(0);
        return ucall_status_success_k;
    }

    /** Splits the free records before any is taken: the last @p count serve named releases. */
    void reserve_releases(std::size_t count) noexcept {
        first_release = static_cast<unsigned>(records.size() - count);
        free_operations = free_releases = {};
        for (unsigned i = 0; i != first_release; ++i) free_operations.push(records, i);
        for (unsigned i = first_release; i != records.size(); ++i) free_releases.push(records, i);
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
        request.operation_index = index_of(*operation);
        if (!owner) return operation;
        operation->socket_slot = owner;
        operation->owned_next = owner->owned_head;
        owner->owned_head = index_of(*operation);
        return operation;
    }

    /** Takes a free record for a release a send named, or @c nullptr so the send copies. */
    operation_t* take_release(io_request_t& request) noexcept {
        auto* operation = pop(free_releases);
        if (!operation) return nullptr;
        *operation = {};
        operation->request = &request;
        request.operation_index = index_of(*operation);
        return operation;
    }
    void complete(operation_t& operation,
                  uring_operation_stage_t answered = uring_operation_stage_t::completed_k) noexcept {
        if (operation.in_flight()) --outstanding_operations;
        operation.stage = answered;
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
        // A connection an accept took leaves its request named by the accept's anchor.
        if (operation.request && operation.request->operation_index == index_of(operation))
            operation.request->operation_index = absent_k;
        operation.request = nullptr;
        push(index_of(operation) < first_release ? free_operations : free_releases, operation);
    }

    /** The operation carrying @p request, or @c nullptr. */
    operation_t* carrying(io_request_t const& request) noexcept {
        unsigned const index = request.operation_index;
        return index < records.size() && records[index].request == &request ? &records[index] : nullptr;
    }
    bool owns_in_flight(socket_slot_t const& owner) const noexcept {
        for (unsigned index = owner.owned_head; index != absent_k; index = records[index].owned_next)
            if (records[index].in_flight()) return true;
        return false;
    }

    /** The entry @p operation starts with, and one for its linked timeout, or @c nullptr once the
     *  ring refused to submit. */
    template <typename state_type_>
    io_uring_sqe* entry(operation_t& operation, state_type_& state) noexcept {
        return state.entry(operation.request->deadline ? 2 : 1);
    }

    /** Tags a prepared entry, links its timeout, and counts the operation in flight. */
    template <typename state_type_>
    void submit(io_uring_sqe* submission, operation_t& operation, state_type_& state) noexcept {
        auto& request = *operation.request;
        // A file or a directory is a process descriptor, never a registered socket.
        if (request.operation != io_operation_t::file_open_k && request.operation != io_operation_t::file_read_k &&
            request.operation != io_operation_t::file_read_vectors_k)
            submission->flags |= IOSQE_FIXED_FILE;
        io_uring_sqe_set_data64(submission, operation.paired_operation != absent_k
                                                ? state.tag(&records[operation.paired_operation], uring_release_tag_k)
                                                : state.tag(&operation, uring_operation_tag_k));
        if (request.deadline) {
            submission->flags |= IOSQE_IO_LINK;
            auto& expiry = expiries[index_of(operation)];
            expiry = state.timespec_of(request.deadline);
            auto* timeout = state.entry();
            io_uring_prep_link_timeout(timeout, &expiry, IORING_TIMEOUT_ABS);
            io_uring_sqe_set_data64(timeout, uring_cancel_tag_k);
        }
        operation.stage = uring_operation_stage_t::submitted_k;
        ++outstanding_operations;
    }

    /** Asks the kernel to cancel an operation in flight. */
    template <typename state_type_>
    ucall_status_t cancel_in_flight(operation_t& operation, state_type_& state) noexcept {
        operation.stage = uring_operation_stage_t::cancelling_k;
        auto* submission = state.entry();
        if (!submission) {
            operation.stage = uring_operation_stage_t::submitted_k;
            return ucall_status_io_k;
        }
        io_uring_prep_cancel64(submission,
                               operation.paired_operation != absent_k
                                   ? state.tag(&records[operation.paired_operation], uring_release_tag_k)
                                   : state.tag(&operation, uring_operation_tag_k),
                               0);
        io_uring_sqe_set_data64(submission, uring_cancel_tag_k);
        return ucall_status_success_k;
    }

    /** Settles the completion of a one-shot operation, or of an accept, answering a slot it
     *  accepted that must be retired at once. */
    template <typename state_type_>
    socket_slot_t* settle(operation_t& operation, io_uring_cqe const& completion, state_type_& state,
                          socket_slots_t& socket_slots) noexcept {
        if (operation.request->operation == io_operation_t::accept_k)
            return settle_accept(operation, completion, state, socket_slots);
        operation.result = completion.res;
        if (operation.request->operation == io_operation_t::file_open_k && completion.res >= 0)
            operation.result = open_native_file_finish(completion.res);
        expire(operation, completion.res);
        if (completion.res != -ENOBUFS || operation.stage == uring_operation_stage_t::cancelling_k ||
            state.stage != uring_queue_stage_t::running_k)
            complete(operation);
        else {
            --outstanding_operations;
            operation.stage = uring_operation_stage_t::waiting_k;
            push(waiting_operations, operation);
        }
        return nullptr;
    }

    /** Marks @p operation timed out where its linked timeout, not a cancel it asked for, ended it
     *  with @p result. */
    void expire(operation_t& operation, int result) noexcept {
        if (result == -ECANCELED && operation.stage != uring_operation_stage_t::cancelling_k &&
            operation.request->deadline)
            operation.expiry = uring_expiry_t::expired_k;
    }

    /**
     *  @brief Arms the accept @p anchor holds: one-shot accepts until @c length are held, each
     *      into a slot, an address and a record of its own.
     *
     *  An anchor arming none waits for a slot, a record or a ring entry.
     */
    template <typename state_type_>
    void arm_accepts(operation_t& anchor, state_type_& state, socket_slots_t& socket_slots) noexcept {
        io_request_t& request = *anchor.request;
        int const listener = static_cast<int>(anchor.socket_slot->index);
        unsigned const anchored = index_of(anchor);
        anchor.stage = uring_operation_stage_t::accepting_k;
        while (anchor.accepting < fu::max_of<std::size_t>(request.length, 1)) {
            operation_t* accept = take(request, anchor.socket_slot);
            request.operation_index = anchored;
            socket_slot_t* accepted = accept ? socket_slots.reserve() : nullptr;
            io_uring_sqe* submission = accepted ? entry(*accept, state) : nullptr;
            if (!submission) {
                if (accepted) socket_slots.vacate(*accepted);
                if (accept) vacate(*accept);
                break;
            }
            accept->accepted = accepted->index;
            io_peer_address_t& peer = socket_slots.peers[accepted->index];
            peer.length = sizeof(peer.address);
            io_uring_prep_accept_direct(submission, listener, reinterpret_cast<sockaddr*>(&peer.address), &peer.length,
                                        SOCK_NONBLOCK, accepted->index);
            submit(submission, *accept, state);
            ++anchor.accepting;
        }
        if (anchor.accepting) return;
        anchor.stage = uring_operation_stage_t::waiting_k;
        push(waiting_operations, anchor);
    }

    /** Ends the accept @p anchor holds: one still waiting completes cancelled at once, and an
     *  armed one cancels what the kernel holds for it, the last of which then ends the request. */
    template <typename state_type_>
    ucall_status_t end_accepts(operation_t& anchor, state_type_& state) noexcept {
        if (anchor.stage == uring_operation_stage_t::waiting_k) {
            unlink(waiting_operations, anchor);
            anchor.request->length = 0;
            anchor.result = -ECANCELED;
            complete(anchor);
            return ucall_status_success_k;
        }
        if (anchor.stage != uring_operation_stage_t::accepting_k) return ucall_status_success_k;
        anchor.stage = uring_operation_stage_t::ending_k;
        for (unsigned index = anchor.socket_slot->owned_head; index != absent_k; index = records[index].owned_next)
            if (records[index].request == anchor.request &&
                records[index].stage == uring_operation_stage_t::submitted_k)
                if (ucall_status_t const cancelled = cancel_in_flight(records[index], state);
                    cancelled != ucall_status_success_k)
                    return cancelled;
        return ucall_status_success_k;
    }

    /**
     *  @brief Settles a completion of an accept, answering a slot to retire.
     *
     *  Each one-shot accept answers its connection at once, taking one from the request's
     *  @c length, and the one spending its last ends the accept. Whichever completion leaves the
     *  anchor holding nothing in the kernel ends the request, unless its connection may still go
     *  on; a refused record answers nothing while others are held.
     */
    template <typename state_type_>
    socket_slot_t* settle_accept(operation_t& operation, io_uring_cqe const& completion, state_type_& state,
                                 socket_slots_t& socket_slots) noexcept {
        io_request_t& request = *operation.request;
        operation_t& anchor = records[request.operation_index];
        bool const running = state.stage == uring_queue_stage_t::running_k;
        --anchor.accepting;
        socket_slot_t& accepted = socket_slots.records[operation.accepted];
        socket_slot_t* retired {};
        bool const connected = completion.res >= 0;
        if (connected) {
            accepted.stage = uring_installed(accepted.stage);
            operation.result = registered_socket_t {operation.accepted}.handle();
            if (!running || !uring_serves(operation.socket_slot->stage)) retired = &accepted;
        }
        else {
            operation.result = completion.res;
            expire(operation, completion.res);
            socket_slots.vacate(accepted);
        }
        bool const flowing = anchor.stage == uring_operation_stage_t::accepting_k;
        if (anchor.accepting || (connected && flowing && request.length > 1)) {
            if (!connected) {
                --outstanding_operations;
                vacate(operation);
                return retired;
            }
            if (request.length > 1) --request.length;
            else if (running && end_accepts(anchor, state) != ucall_status_success_k) state.fault = -EIO;
            complete(operation, uring_operation_stage_t::yielded_k);
            if (anchor.stage == uring_operation_stage_t::accepting_k && running)
                arm_accepts(anchor, state, socket_slots);
            return retired;
        }
        request.length = 0;
        vacate(anchor);
        complete(operation);
        return retired;
    }

    /** Completes the close request of a closed @p owner and frees its slot. */
    void finish_close(socket_slot_t& owner, socket_slots_t& socket_slots) noexcept {
        if (owner.close_operation != absent_k) {
            auto& closing = records[owner.close_operation];
            closing.result = 0;
            complete(closing);
            owner.close_operation = absent_k;
        }
        socket_slots.vacate(owner);
    }

    /** What a completed @p operation reports, naming the slice a receive filled and the
     *  release token that frees it, one past the slice's offset in the pool, or the peer of
     *  a socket accepted. */
    template <typename state_type_>
    io_completion_t completion_of(operation_t& operation, state_type_& state, socket_slots_t& socket_slots) noexcept {
        auto result = operation.expiry == uring_expiry_t::expired_k && operation.result == -ECANCELED
                          ? -ETIMEDOUT
                          : operation.result;
        if (operation.request->operation == io_operation_t::accept_k && result >= 0)
            return {operation.request, result, bytes_of(&socket_slots.peers[operation.accepted], 1).data(), 0,
                    operation.stage == uring_operation_stage_t::yielded_k ? io_continuation_t::pending_k
                                                                          : io_continuation_t::ended_k};
        unsigned const offset = operation.buffer;
        if (offset == absent_k) return {operation.request, result};
        return {operation.request, result, state.provided.memory.data() + offset, offset + 1};
    }

    /** Opens completed but never collected hand their descriptors to no one. */
    void close_uncollected_files() noexcept {
        for (unsigned index = completed_operations.oldest; index != absent_k; index = records[index].next)
            if (records[index].request->operation == io_operation_t::file_open_k && records[index].result >= 0)
                close_native_file(records[index].result);
    }
};

/** The zero-copy releases sends name, each found through the record its request names, and the
 *  notifications the kernel still owes them. */
template <typename socket_slot_type_, typename allocator_type_, template <typename> class atomic_ref_template_>
struct uring_zero_copy {
    using socket_slot_t = socket_slot_type_;
    using allocator_t = allocator_type_;
    using operations_t = uring_operations<socket_slot_t, allocator_t>;
    using socket_slots_t = uring_socket_slots<socket_slot_t, allocator_t>;
    using operation_t = typename operations_t::operation_t;

    /** Summed over every release. */
    std::uint32_t outstanding_notifications {};

    /** The owning queue's counters. */
    io_statistics_t& statistics;

    explicit uring_zero_copy(io_statistics_t& counters) noexcept : statistics(counters) {}

    /** The record collecting the notifications of the release @p request, from the first send
     *  naming it until its submission, or @c absent_k. */
    static unsigned collecting(io_request_t const& request, operations_t& operations) noexcept {
        operation_t const* const held = operations.carrying(request);
        return held && held->stage == uring_operation_stage_t::collecting_k ? operations.index_of(*held) : absent_k;
    }

    /** The release a zero-copy send counts against, taking an operation for it on the first send
     *  naming it; @c absent_k when the send copies instead: its socket was reported copying, or
     *  no release record is free, or another send naming the release is still in flight. */
    unsigned pair_release(operation_t& operation, operations_t& operations) noexcept {
        io_request_t* const named = operation.request->release_request;
        zero_copy_stage_t const stage = operation.socket_slot->zero_copy;
        if (stage == zero_copy_stage_t::copying_k || stage == zero_copy_stage_t::refused_k || !named) return absent_k;
        unsigned release = collecting(*named, operations);
        if (release == absent_k) {
            auto* taken = operations.take_release(*named);
            if (!taken) return absent_k;
            taken->stage = uring_operation_stage_t::collecting_k;
            release = operations.index_of(*taken);
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
        auto const length = fu::min_of(request.length, std::size_t {(std::numeric_limits<unsigned>::max)()});
        if (request.registered_memory != io_unregistered_k)
            io_uring_prep_send_zc_fixed(submission, static_cast<int>(owner->index), request.data, length, MSG_NOSIGNAL,
                                        IORING_SEND_ZC_REPORT_USAGE, static_cast<int>(request.registered_memory));
        else
            io_uring_prep_send_zc(submission, static_cast<int>(owner->index), request.data, length, MSG_NOSIGNAL,
                                  IORING_SEND_ZC_REPORT_USAGE);
        ++release.outstanding_notifications;
        ++outstanding_notifications;
        release.paired_operation = operations.index_of(operation);
        operation.paired_operation = operations.index_of(release);
        tally<atomic_ref_template_>(statistics.zero_copy_sends);
    }

    /** Completes a submitted release once no notification it counts is due; one no zero-copy send
     *  named completes at once, and answers false where no record is free to hold it. */
    [[nodiscard]] bool submit_release(io_request_t& request, operations_t& operations,
                                      socket_slots_t& socket_slots) noexcept {
        unsigned index = collecting(request, operations);
        if (index == absent_k) {
            auto* taken = operations.take(request);
            if (!taken) return false;
            index = operations.index_of(*taken);
        }
        auto& release = operations[index];
        release.stage = uring_operation_stage_t::releasing_k;
        if (!release.outstanding_notifications) complete_release(release, operations, socket_slots);
        return true;
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
            if (static_cast<std::uint32_t>(completion.res) & IORING_NOTIF_USAGE_ZC_COPIED)
                tally<atomic_ref_template_>(statistics.zero_copy_fallbacks);
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
            // The kernel refuses zero-copy with no notification: AF_UNIX has none, so its socket
            // copies for good, while pinning past the locked-memory limit fails one send with
            // ENOMEM, whose retry copies.
            if ((completion.res == -EOPNOTSUPP || completion.res == -ENOMEM) &&
                send.stage != uring_operation_stage_t::cancelling_k) {
                send.socket_slot->zero_copy = completion.res == -ENOMEM ? zero_copy_stage_t::refused_k
                                                                        : zero_copy_stage_t::copying_k;
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

/** Prepares every operation the io_uring queues submit alike: all but accepts, receives and
 *  vectored reads. */
template <typename state_type_, typename operations_type_, typename zero_copy_type_>
void uring_prepare(io_uring_sqe* submission, typename operations_type_::operation_t& operation, state_type_& state,
                   operations_type_& operations, zero_copy_type_& zero_copy) noexcept {
    auto& request = *operation.request;
    auto const socket = static_cast<int>(operation.socket_slot->index);
    // The submission length field is 32 bits wide.
    auto const sent = fu::min_of(request.length, std::size_t {(std::numeric_limits<unsigned>::max)()});
    switch (request.operation) {
    case io_operation_t::connect_k:
        io_uring_prep_connect(submission, socket, reinterpret_cast<sockaddr*>(request.data),
                              static_cast<socklen_t>(request.length));
        break;
    case io_operation_t::send_k:
        io_uring_prep_send(submission, socket, request.data, sent, MSG_NOSIGNAL);
        tally<state_type_::template atomic_ref>(state.statistics.copying_sends);
        break;
    case io_operation_t::send_zero_copy_k:
        if (unsigned const release = zero_copy.pair_release(operation, operations);
            release != operation_list_t::absent_k) {
            zero_copy.prepare_send(submission, operation, operations[release], operations);
            break;
        }
        io_uring_prep_send(submission, socket, request.data, sent, MSG_NOSIGNAL);
        tally<state_type_::template atomic_ref>(state.statistics.copying_sends);
        // A send the kernel refused to pin copies once, and the socket's next send pins again.
        if (operation.socket_slot->zero_copy == zero_copy_stage_t::refused_k)
            operation.socket_slot->zero_copy = zero_copy_stage_t::untried_k;
        break;
    case io_operation_t::send_vectors_k: {
        // A socket keeps one send pending, so its slot holds the header the kernel reads.
        msghdr& message = operation.socket_slot->message;
        message = {};
        message.msg_iov = io_vectors(request).data();
        message.msg_iovlen = static_cast<decltype(message.msg_iovlen)>(
            fu::min_of<std::size_t>(request.length, io_send_vectors_limit_k));
        io_uring_prep_sendmsg(submission, socket, &message, MSG_NOSIGNAL);
        tally<state_type_::template atomic_ref>(state.statistics.copying_sends);
        break;
    }
    case io_operation_t::read_k:
        io_uring_prep_read(submission, socket, request.data,
                           static_cast<unsigned>(fu::min_of(request.length, state.page_bytes)), -1);
        break;
    case io_operation_t::file_read_k: {
        auto const bytes = static_cast<unsigned>(
            fu::min_of<std::size_t>(request.length, (std::numeric_limits<unsigned>::max)()));
        if (request.registered_memory != io_unregistered_k)
            io_uring_prep_read_fixed(submission, request.file.handle, request.data, bytes, request.file.offset,
                                     static_cast<int>(request.registered_memory));
        else io_uring_prep_read(submission, request.file.handle, request.data, bytes, request.file.offset);
        tally<state_type_::template atomic_ref>(state.statistics.file_reads_asynchronous);
        break;
    }
    case io_operation_t::file_open_k:
        io_uring_prep_openat2(submission, request.file.handle, reinterpret_cast<char const*>(request.data),
                              &state.storage->open_resolution);
        break;
    case io_operation_t::shutdown_k: io_uring_prep_shutdown(submission, socket, SHUT_WR); break;
    case io_operation_t::accept_k:
    case io_operation_t::receive_k:
    case io_operation_t::file_read_vectors_k:
    case io_operation_t::zero_copy_release_k:
    case io_operation_t::close_k: break;
    }
}

/** Settles an entry the kernel never saw, of a kind both io_uring queues submit. */
template <typename state_type_, typename operations_type_, typename socket_slots_type_, typename zero_copy_type_>
void uring_discard(std::uint64_t user_data, state_type_& state, operations_type_& operations,
                   socket_slots_type_& socket_slots, zero_copy_type_& zero_copy) noexcept {
    using operation_t = typename operations_type_::operation_t;
    using socket_slot_t = typename socket_slots_type_::socket_slot_t;
    auto kind = static_cast<std::uintptr_t>(user_data) & 7;
    auto* pointer = reinterpret_cast<void*>(static_cast<std::uintptr_t>(user_data) & ~std::uintptr_t {7});
    if (kind == uring_operation_tag_k) {
        auto& operation = *static_cast<operation_t*>(pointer);
        io_uring_cqe unsent {};
        unsent.res = -ECANCELED;
        if (operation.request->operation == io_operation_t::accept_k) {
            [[maybe_unused]] socket_slot_t* const retired = operations.settle_accept(operation, unsent, state,
                                                                                     socket_slots);
        }
        else {
            operation.result = unsent.res;
            operations.complete(operation);
        }
    }
    else if (kind == uring_release_tag_k) {
        // The send never reached the kernel, so neither its result nor its notification will.
        io_uring_cqe unsent {};
        unsent.res = -ECANCELED;
        [[maybe_unused]] socket_slot_t* const settled = zero_copy.settle(*static_cast<operation_t*>(pointer), unsent,
                                                                         operations, socket_slots);
    }
    else if (kind == uring_control_tag_k) state.control.result = -ECANCELED;
    else if (kind == uring_close_tag_k) {
        auto& owner = *static_cast<socket_slot_t*>(pointer);
        if (owner.stage == uring_socket_stage_t::closing_k) {
            owner.stage = uring_socket_stage_t::retiring_k;
            --socket_slots.closing_socket_slots;
        }
    }
}

/** Reaps every ready completion through @p queue's own dispatch. */
template <typename queue_type_>
void uring_reap(queue_type_& queue) noexcept {
    unsigned head {}, count {};
    io_uring_cqe* current {};
    io_uring_for_each_cqe(&queue.state.ring, head, current) {
        queue.completion(*current);
        ++count;
    }
    if (!count) return;
    io_uring_cq_advance(&queue.state.ring, count);
    queue.state.reaped_since_enter += count;
    tally<queue_type_::state_t::template atomic_ref>(queue.statistics.kernel_entries, count);
}

/** Waits for the one control command in flight, or the ring's fault. */
template <typename queue_type_>
int uring_wait_control(queue_type_& queue) noexcept {
    auto& state = queue.state;
    while (!state.control.result.has_value() && !state.fault) {
        int result = state.enter(1, 0);
        if (result < 0) {
            state.fault = result;
            break;
        }
        uring_reap(queue);
    }
    return state.fault ? state.fault : *state.control.result;
}

/** Retires the socket behind @p descriptor and waits until its slot is vacant. */
template <typename queue_type_>
int uring_close_socket(queue_type_& queue, descriptor_t descriptor) noexcept {
    auto& state = queue.state;
    if (!state.is_open()) return 0;
    auto* owner = queue.socket_slots.find(descriptor);
    if (!owner) return 0;
    auto serial = owner->serial;
    queue.retire(*owner);
    while (owner->stage != uring_socket_stage_t::vacant_k && owner->serial == serial && !state.fault) {
        int result = state.enter(1, 0);
        if (result < 0) {
            state.fault = result;
            break;
        }
        uring_reap(queue);
    }
    return state.fault;
}

/** Opens a registered TCP socket with Nagle off, through two control commands. */
template <typename queue_type_>
descriptor_t uring_open_socket(queue_type_& queue, int family) noexcept {
    auto& state = queue.state;
    auto& socket_slots = queue.socket_slots;
    if (state.fault) return state.fault;
    auto* target = socket_slots.reserve();
    if (!target) return -ENFILE;
    auto* submission = state.entry();
    if (!submission) {
        socket_slots.vacate(*target);
        return -EIO;
    }
    state.control = {};
    io_uring_prep_socket_direct(submission, family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP, target->index, 0);
    state.command(submission);
    int result = uring_wait_control(queue);
    if (result < 0) {
        if (state.control.result) socket_slots.vacate(*target);
        return result;
    }
    target->stage = uring_installed(target->stage);
    auto handle = registered_socket_t {target->index}.handle();
    submission = state.entry();
    if (!submission) {
        [[maybe_unused]] int const closed = uring_close_socket(queue, handle);
        return -EIO;
    }
    state.storage->socket_option_value = 1;
    io_uring_prep_cmd_sock(submission, SOCKET_URING_OP_SETSOCKOPT, static_cast<int>(target->index), IPPROTO_TCP,
                           TCP_NODELAY, &state.storage->socket_option_value,
                           sizeof(state.storage->socket_option_value));
    submission->flags |= IOSQE_FIXED_FILE;
    state.command(submission);
    result = uring_wait_control(queue);
    if (result < 0) {
        [[maybe_unused]] int const closed = uring_close_socket(queue, handle);
        return result;
    }
    return handle;
}

/** Cancels the operation carrying @p request, if its socket still owns one. */
template <typename queue_type_>
ucall_status_t uring_cancel(queue_type_& queue, io_request_t& request) noexcept {
    // A release ends on its notifications, a close on its last socket operation, never sooner.
    if (request.operation == io_operation_t::close_k || request.operation == io_operation_t::zero_copy_release_k)
        return ucall_status_success_k;
    auto* operation = queue.operations.carrying(request);
    return operation ? queue.cancel(*operation) : ucall_status_not_found_k;
}

/** Settles every entry queued since the last submission as if the kernel cancelled it. */
template <typename queue_type_>
void uring_discard_unsubmitted(queue_type_& queue) noexcept {
    auto& ring = queue.state.ring;
    auto head = io_uring_smp_load_acquire(ring.sq.khead);
    for (auto i = head; i != ring.sq.sqe_tail; ++i) queue.discard(ring.sq.sqes[i & ring.sq.ring_mask].user_data);
    ring.sq.sqe_head = ring.sq.sqe_tail = head;
    io_uring_smp_store_release(ring.sq.ktail, head);
}

/** Cancels and reaps everything the kernel still holds once a submission faulted. */
template <typename queue_type_>
[[nodiscard]] ucall_status_t uring_drain_after_fault(queue_type_& queue) noexcept {
    auto& state = queue.state;
    state.stage = uring_queue_stage_t::recovering_k;
    uring_discard_unsubmitted(queue);
    if (ucall_status_t const cancelled = state.cancel_synchronously(); cancelled != ucall_status_success_k)
        return cancelled;
    // Sockets go and the exit signal stays, or end of file would arrive before the ring ended.
    if (ucall_status_t const cleared = queue.socket_slots.clear_files(state); cleared != ucall_status_success_k)
        return cleared;
    uring_reap(queue);
    while (queue.has_kernel_work()) {
        int result = state.retry_interrupted(
            [&] { return io_uring_enter(state.ring.ring_fd, 0, 1, IORING_ENTER_GETEVENTS, nullptr); });
        if (result < 0) {
            state.fault = result;
            return ucall_status_io_k;
        }
        uring_reap(queue);
    }
    return ucall_status_success_k;
}

/** Grows @p queue's operation records, socket slots and registered table to @p capacity before
 *  any thread entered its ring, which keeps the size and locked memory its open proved; each
 *  slot takes @p slot_arguments, as in @c open. */
template <typename queue_type_, typename... slot_arguments_type_>
[[nodiscard]] ucall_status_t uring_grow(queue_type_& queue, std::size_t capacity,
                                        slot_arguments_type_ const&... slot_arguments) noexcept {
    auto& state = queue.state;
    if (state.stage != uring_queue_stage_t::running_k || state.issuer != uring_issuer_t::unclaimed_k)
        return ucall_status_invalid_argument_k;
    if (capacity > static_cast<std::size_t>(registered_socket_t::tag_k)) return ucall_status_overflow_k;
    std::size_t const sockets = uring_socket_capacity(capacity);
    std::destroy_at(&queue.operations);
    std::construct_at(&queue.operations, state.allocator);
    std::destroy_at(&queue.socket_slots);
    std::construct_at(&queue.socket_slots, state.allocator);
    if (queue.operations.open(capacity) != ucall_status_success_k ||
        queue.socket_slots.open(sockets, slot_arguments...) != ucall_status_success_k)
        return ucall_status_out_of_memory_k;
    if (ucall_status_t const unregistered = state.unregister_files(); unregistered != ucall_status_success_k)
        return unregistered;
    return state.register_table(sockets);
}

/** Retires every socket, reaps what the kernel still holds, then closes the ring. */
template <typename queue_type_>
void uring_stop(queue_type_& queue) noexcept {
    auto& state = queue.state;
    if (!state.is_open()) return;
    state.stage = uring_queue_stage_t::stopping_k;
    if (!state.fault) {
        for (auto& owner : queue.socket_slots.records)
            if (owner.stage != uring_socket_stage_t::vacant_k) queue.retire(owner);
    }
    while (!state.fault && queue.has_kernel_work()) {
        int result = state.enter(1, 0);
        if (result < 0) {
            state.fault = result;
            break;
        }
        uring_reap(queue);
    }
    // Failed submission must not bypass terminal CQEs that still reference caller memory.
    ucall_status_t const retirement = state.fault ? uring_drain_after_fault(queue) : state.unregister_files();
    queue.operations.close_uncollected_files();
    state.close(retirement);
    for (auto& owner : queue.socket_slots.records) owner.stage = uring_socket_stage_t::vacant_k;
}

/** Marks the close of @p descriptor to send a reset rather than a FIN, without a round trip. */
template <typename queue_type_>
[[nodiscard]] ucall_status_t uring_reset_on_close(queue_type_& queue, descriptor_t descriptor) noexcept {
    auto* owner = queue.socket_slots.find(descriptor);
    if (!owner) return ucall_status_io_k;
    owner->close = close_mode_t::reset_k;
    return ucall_status_success_k;
}

/** Makes every later zero-copy send of @p descriptor copy, as delivery to a peer on this host
 *  copies anyway; its releases then complete as soon as their sends do. */
template <typename queue_type_>
void uring_copy_sends(queue_type_& queue, descriptor_t descriptor) noexcept {
    if (auto* owner = queue.socket_slots.find(descriptor)) owner->zero_copy = zero_copy_stage_t::copying_k;
}

/** Stops @p owner taking operations and cancels every unanswered one it owns but its close. */
template <typename queue_type_>
void uring_abandon(queue_type_& queue, typename queue_type_::socket_slot_t& owner) noexcept {
    owner.stage = owner.stage == uring_socket_stage_t::installing_k ? uring_socket_stage_t::abandoned_k
                                                                    : uring_socket_stage_t::retiring_k;
    for (unsigned index = owner.owned_head; index != absent_k; index = queue.operations[index].owned_next) {
        auto& operation = queue.operations[index];
        if (!operation.answered() && operation.request->operation != io_operation_t::close_k)
            if (queue.cancel(operation) != ucall_status_success_k) queue.state.fault = -EIO;
    }
}

/** Takes the record carrying @p request on either io_uring queue, or @c nullptr once the request
 *  needs no start: a close retires its socket, and a request naming no socket or one already
 *  retiring completes with the error a kernel would report. */
template <typename queue_type_>
typename queue_type_::operation_t* uring_take(queue_type_& queue, io_request_t& request) noexcept {
    auto* owner = queue.socket_slots.find(request.descriptor);
    bool const serving = owner && uring_serves(owner->stage);
    auto* operation = queue.operations.take(request, serving ? owner : nullptr);
    // The records cover what the loops hold at once, so only a miscount ends the queue here.
    if (!operation) {
        queue.state.fault = -ENOBUFS;
        return nullptr;
    }
    if (!serving) {
        operation->result = owner ? -ECONNABORTED : -EBADF;
        queue.operations.complete(*operation);
        return nullptr;
    }
    if (request.operation != io_operation_t::close_k) return operation;
    owner->close_operation = queue.operations.index_of(*operation);
    queue.retire(*owner);
    return nullptr;
}

/** One-shot requests over registered sockets, submitted through the liburing SQ. */
template <typename allocator_type_ = st::default_allocator<byte_t>,
          template <typename> class atomic_ref_template_ = fu::standard_atomic_ref,
          typename row_kit_type_ = st::serial_row_kit_t>
struct linux_uring612_queue {
    using allocator_t = allocator_type_;
    template <typename other_allocator_type_, template <typename> class other_atomic_ref_, typename other_row_kit_>
    using rebind = linux_uring612_queue<other_allocator_type_, other_atomic_ref_, other_row_kit_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    template <typename value_type_>
    using vector = st::vector<value_type_, rebound_allocator<value_type_>>;

    struct alignas(8) socket_slot_t {

        /** The slot's index in the registered file table, which its handle holds. */
        unsigned index {};

        /** The next vacant slot while this one is vacant. */
        unsigned next {absent_k};

        /** The newest record the slot owns, linked through @c owned_next, or @c absent_k. */
        unsigned owned_head {absent_k};

        /** The close request waiting for the slot to close, or @c absent_k. */
        unsigned close_operation {absent_k};

        /** Unique per socket the slot held, so a late notification never demotes its successor. */
        std::uint64_t serial {};

        /** Where the slot's registered descriptor stands. */
        uring_socket_stage_t stage {uring_socket_stage_t::vacant_k};

        /** Untried, or copying once the kernel refused zero-copy for the socket or for one send. */
        zero_copy_stage_t zero_copy {zero_copy_stage_t::untried_k};

        /** Whether the close sends a FIN or a reset. */
        close_mode_t close {close_mode_t::orderly_k};

        /** The header of the socket's gathered send, which names the request's vectors. */
        msghdr message {};
    };
    static_assert(sizeof(socket_slot_t) == 88);
    using state_t = uring_state<allocator_t, atomic_ref_template_>;
    using socket_slots_t = uring_socket_slots<socket_slot_t, allocator_t>;
    using operations_t = uring_operations<socket_slot_t, allocator_t>;
    using zero_copy_t = uring_zero_copy<socket_slot_t, allocator_t, atomic_ref_template_>;
    using operation_t = typename operations_t::operation_t;
    static_assert(sizeof(operation_t) == 56);
    static constexpr io_uring_op opcodes_k[] {
        IORING_OP_SOCKET,       IORING_OP_ACCEPT,       IORING_OP_CONNECT,   IORING_OP_RECV,
        IORING_OP_SEND,         IORING_OP_READ,         IORING_OP_SHUTDOWN,  IORING_OP_CLOSE,
        IORING_OP_ASYNC_CANCEL, IORING_OP_LINK_TIMEOUT, IORING_OP_URING_CMD, IORING_OP_OPENAT2,
        IORING_OP_SEND_ZC,      IORING_OP_READ_FIXED,   IORING_OP_READV,     IORING_OP_SENDMSG};
    static constexpr ucall_io_backend_t backend_k = ucall_io_backend_linux_uring612_k;
    static constexpr io_receive_memory_t receive_memory_k = io_receive_memory_t::queue_k;

    /** The counters the queue and its components advance for its polling owner. */
    io_statistics_t statistics {};

    /** The ring, its registered tables and its receive pool. */
    state_t state;

    /** The registered sockets. */
    socket_slots_t socket_slots;

    /** The operation records and the lists they wait on. */
    operations_t operations;

    /** The releases sends name and the notifications still due. */
    zero_copy_t zero_copy;

    /** Why @c open answered @c ucall_status_unsupported_k, naming the setting to raise. */
    char const* refusal {};

    explicit linux_uring612_queue(allocator_t const& instance = {}) noexcept
        : state(instance, statistics), socket_slots(instance), operations(instance), zero_copy(statistics) {}
    linux_uring612_queue(linux_uring612_queue const&) = delete;
    linux_uring612_queue& operator=(linux_uring612_queue const&) = delete;
    linux_uring612_queue(linux_uring612_queue&&) = delete;
    linux_uring612_queue& operator=(linux_uring612_queue&&) = delete;
    ~linux_uring612_queue() noexcept { stop(); }

    bool is_open() const noexcept { return state.is_open(); }
    bool has_kernel_work() const noexcept {
        return !state.control.result || operations.outstanding_operations || zero_copy.outstanding_notifications ||
               socket_slots.closing();
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
        if (operations.open(capacity) != ucall_status_success_k || socket_slots.open(sockets) != ucall_status_success_k)
            return ucall_status_out_of_memory_k;
        ucall_status_t const opened = state.open(depth, sockets, opcodes_k, scope);
        if (opened == ucall_status_success_k) return opened;
        // Only ring setup fails before the ring opens.
        if (state.is_open()) stop();
        else refusal = uring_setup_refusal_k;
        return opened;
    }
    int wait_control() noexcept { return uring_wait_control(*this); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept {
        return socket_slots.import_socket(descriptor, state);
    }
    descriptor_t open_socket(int family) noexcept { return uring_open_socket(*this, family); }
    void release(io_completion_t const& completion) noexcept {
        if (!state.is_open() || !completion.release_token) return;
        state.provided.release_slice({completion.data, static_cast<std::size_t>(completion.result)});
    }
    memory_registration_t register_memory(span<byte_t> memory) noexcept { return state.register_memory(memory); }
    void submit(io_request_t& request) noexcept {
        tally<atomic_ref_template_>(statistics.submissions);
        if (request.operation == io_operation_t::zero_copy_release_k) {
            if (!zero_copy.submit_release(request, operations, socket_slots)) state.fault = -ENOBUFS;
            return;
        }
        if (auto* operation = uring_take(*this, request)) start_operation(*operation);
    }

    /** Starts @p operation, which waits for the next poll while it lacks a buffer or the ring
     *  refuses an entry. */
    void start_operation(operation_t& operation) noexcept {
        auto& request = *operation.request;
        if (request.operation == io_operation_t::accept_k)
            return operations.arm_accepts(operation, state, socket_slots);
        auto* submission = request.operation == io_operation_t::receive_k && !state.provided.available_buffers
                               ? nullptr
                               : operations.entry(operation, state);
        if (!submission) return operations.push(operations.waiting_operations, operation);
        if (request.operation == io_operation_t::receive_k) {
            // A length would cut the buffer short of what the cursor expects.
            io_uring_prep_recv(submission, static_cast<int>(operation.socket_slot->index), nullptr, 0, 0);
            submission->flags |= IOSQE_BUFFER_SELECT;
            submission->buf_group = 0;
        }
        else if (request.operation == io_operation_t::file_read_vectors_k) {
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
        operations.unlink(operations.waiting_operations, operation);
        operation.result = -ECANCELED;
        operations.complete(operation);
        return ucall_status_success_k;
    }
    void retire(socket_slot_t& owner) noexcept {
        if (state.stage == uring_queue_stage_t::recovering_k) return;
        if (uring_serves(owner.stage)) { uring_abandon(*this, owner); }
        if (owner.stage == uring_socket_stage_t::abandoned_k || owner.stage == uring_socket_stage_t::closing_k ||
            operations.owns_in_flight(owner))
            return;
        if (owner.stage == uring_socket_stage_t::closed_k) operations.finish_close(owner, socket_slots);
        else socket_slots.submit_close(owner, state);
    }
    int close_socket(descriptor_t descriptor) noexcept { return uring_close_socket(*this, descriptor); }
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
        if (kind == uring_release_tag_k) {
            auto* settled = zero_copy.settle(*static_cast<operation_t*>(pointer), completion, operations, socket_slots);
            if (settled && !uring_serves(settled->stage)) retire(*settled);
            return;
        }
        auto& operation = *static_cast<operation_t*>(pointer);
        if (completion.res > 0 && (completion.flags & IORING_CQE_F_BUFFER))
            operation.buffer = static_cast<unsigned>(state.provided.offset_of(state.provided.take_received_slice(
                completion.flags >> IORING_CQE_BUFFER_SHIFT, static_cast<std::size_t>(completion.res))));
        if (auto* accepted = operations.settle(operation, completion, state, socket_slots)) retire(*accepted);
        if (!uring_serves(operation.socket_slot->stage)) retire(*operation.socket_slot);
    }
    void reap() noexcept { uring_reap(*this); }
    int collect(span<io_completion_t> output) noexcept {
        std::size_t count {};
        while (count != output.size()) {
            auto* operation = operations.pop(operations.completed_operations);
            if (!operation) break;
            output[count++] = operations.completion_of(*operation, state, socket_slots);
            operations.vacate(*operation);
        }
        tally<atomic_ref_template_>(statistics.completions, count);
        return static_cast<int>(count);
    }
    void maintain() noexcept {
        if (state.fault) return;
        for (auto retry = std::exchange(operations.waiting_operations, {}); auto* operation = operations.pop(retry);)
            start_operation(*operation);
    }
    int poll(span<io_completion_t> output, io_wait_t policy, std::uint64_t deadline = 0) noexcept {
        if (!state.is_open()) return -EBADF;
        for (;;) {
            reap();
            maintain();
            if (state.fault) return state.fault;
            int count = collect(output);
            if (count) return count;
            unsigned wait = policy == io_wait_t::blocking_k && (!deadline || monotonic_ns() < deadline) ? 1 : 0;
            int result = state.enter(wait, deadline);
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
        uring_discard(user_data, state, operations, socket_slots, zero_copy);
    }
    void discard_unsubmitted() noexcept { uring_discard_unsubmitted(*this); }
    [[nodiscard]] ucall_status_t drain_after_fault() noexcept { return uring_drain_after_fault(*this); }
    void reserve_releases(std::size_t count) noexcept { operations.reserve_releases(count); }
    [[nodiscard]] ucall_status_t grow(std::size_t capacity) noexcept { return uring_grow(*this, capacity); }
    void stop() noexcept { uring_stop(*this); }
};

using linux_uring612_queue_t = linux_uring612_queue<>;

} // namespace unum::ucall::io
