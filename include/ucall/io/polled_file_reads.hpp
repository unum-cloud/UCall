/**
 *  @file include/ucall/io/polled_file_reads.hpp
 *  @author Ash Vardanian
 *  @date November 16, 2026
 *  @brief File reads through POSIX AIO, whose landing the poll thread checks between waits, for a
 *      readiness engine whose kernel queue can't report AIO completions, as macOS kqueue can't.
 *
 *  A single read is one @c aio_read; a vectored read is one @c lio_listio batch of @c aio_read
 *  control blocks, one per vector, chunked by the batch limit. Nothing is notified: the owner
 *  shortens its wait while reads are in flight, with a backoff from 1 µs to 1 ms, and reaps what
 *  @c aio_error reports done. Only a refusal to queue, @c EAGAIN, or a pool with no room left
 *  reads blocking, on the poll thread.
 */
#pragma once

#include <cerrno>  // `EINPROGRESS`, `EAGAIN`
#include <cstddef> // `std::size_t`
#include <cstdint> // `std::uint64_t`

#include <aio.h>    // `aiocb`, `aio_read`, `lio_listio`, `aio_error`, `aio_return`, `aio_suspend`
#include <limits.h> // `AIO_LISTIO_MAX`, `IOV_MAX`

#include "ucall/utilities/sockets.hpp" // `io_vector_t`, `read_native_file_vectors`, `native_file_t`
#include "ucall/utilities/types.hpp"   // `st::vector`, `span`, `descriptor_t`

namespace unum::ucall::io {

#if UCALL_OS_POSIX_

/** The longest batch one @c lio_listio takes, where the platform names none. */
#if defined(AIO_LISTIO_MAX)
inline constexpr std::size_t aio_batch_limit_k = AIO_LISTIO_MAX;
#else
inline constexpr std::size_t aio_batch_limit_k = 16;
#endif

/** Marks a block or a read that links to nothing. */
inline constexpr unsigned aio_absent_k = ~0u;

/** The shortest and longest wait while reads are in flight, in nanoseconds. */
inline constexpr std::uint64_t aio_backoff_floor_ns_k = 1'000, aio_backoff_ceiling_ns_k = 1'000'000;

/**
 *  @brief A pool of AIO control blocks, each owned by one engine operation while its read is in
 *      flight; an operation's vectored read links several blocks, landing once the last lands.
 *
 *  Every call runs on the engine's polling thread. The pool never allocates after @c reserve.
 */
template <typename allocator_type_ = st::default_allocator<byte_t>>
struct polled_file_reads {
    using allocator_t = allocator_type_;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;

    /** One control block, the operation it reads for, and where the operation's next block is. */
    struct block_t {
        aiocb control {};
        utilities::io_vector_t vector {};
        unsigned owner {aio_absent_k};
        unsigned next {aio_absent_k};
        descriptor_t landed {};
        bool in_flight {};
    };

    /** An operation's read: its first block, the blocks still in flight, and how many it spans. */
    struct read_t {
        unsigned first {aio_absent_k};
        unsigned pending {};
    };

    explicit polled_file_reads(allocator_t const& allocator = {}) noexcept
        : blocks(rebound_allocator<block_t> {allocator}), free_blocks(rebound_allocator<unsigned> {allocator}),
          flying(rebound_allocator<unsigned> {allocator}), reads(rebound_allocator<read_t> {allocator}) {}
    polled_file_reads(polled_file_reads const&) = delete;
    polled_file_reads& operator=(polled_file_reads const&) = delete;

    st::vector<block_t, rebound_allocator<block_t>> blocks {};
    st::vector<unsigned, rebound_allocator<unsigned>> free_blocks {};

    /** The blocks in flight, which every reap walks. */
    st::vector<unsigned, rebound_allocator<unsigned>> flying {};

    /** One per engine operation, indexed as the engine indexes them. */
    st::vector<read_t, rebound_allocator<read_t>> reads {};

    /** How long the owner's next wait may last while reads are in flight. */
    std::uint64_t backoff_ns {aio_backoff_floor_ns_k};

    /** Sizes the pool for @p operations, one block each, as vectored reads borrow the idle ones. */
    ucall_status_t reserve(std::size_t operations) noexcept {
        if (st::failed(blocks.resize(operations)) || st::failed(free_blocks.reserve(operations)) ||
            st::failed(flying.reserve(operations)) || st::failed(reads.resize(operations)))
            return ucall_status_out_of_memory_k;
        free_blocks.clear();
        for (std::size_t index = operations; index != 0; --index) [[maybe_unused]]
            st::status_t const kept = free_blocks.push_back(st::assume_reserved, static_cast<unsigned>(index - 1));
        return ucall_status_success_k;
    }

    [[nodiscard]] bool in_flight() const noexcept { return !flying.empty(); }

    /** The wait the owner may take, shortened to the backoff while reads are in flight. */
    [[nodiscard]] std::uint64_t cap_wait(std::uint64_t nanoseconds) const noexcept {
        return in_flight() && nanoseconds > backoff_ns ? backoff_ns : nanoseconds;
    }

    /**
     *  @brief Starts reading @p vectors of @p file from @p offset for operation @p owner.
     *  @return True once in flight, landing through @c reap; false with @p result holding the bytes
     *      read or a negated errno, read at once because the pool or the kernel had no room.
     */
    bool start(unsigned owner, native_file_t file, span<utilities::io_vector_t const> vectors, std::uint64_t offset,
               descriptor_t& result) noexcept {
        std::size_t const count = vectors.size() < IOV_MAX ? vectors.size() : IOV_MAX;
        if (!count || count > free_blocks.size()) {
            result = utilities::read_native_file_vectors(file, vectors, offset);
            return false;
        }
        read_t& read = reads[owner];
        read = {};
        unsigned* link = &read.first;
        aiocb* batch[aio_batch_limit_k];
        unsigned slots[aio_batch_limit_k];
        for (std::size_t first = 0; first < count; first += aio_batch_limit_k) {
            std::size_t const size = count - first < aio_batch_limit_k ? count - first : aio_batch_limit_k;
            for (std::size_t index = 0; index != size; ++index) {
                unsigned const slot = free_blocks.back();
                free_blocks.pop_back();
                block_t& block = blocks[slot];
                block = {};
                block.owner = owner;
                block.control.aio_fildes = file;
                block.control.aio_offset = static_cast<off_t>(offset);
                block.vector = vectors[first + index];
                block.control.aio_buf = block.vector.iov_base;
                block.control.aio_nbytes = vectors[first + index].iov_len;
                block.control.aio_lio_opcode = LIO_READ;
                block.control.aio_sigevent.sigev_notify = SIGEV_NONE;
                offset += vectors[first + index].iov_len;
                *link = slot;
                link = &block.next;
                batch[index] = &block.control;
                slots[index] = slot;
                ++read.pending;
            }
            bool const single = size == 1;
            int const listed = single ? aio_read(batch[0])
                                      : lio_listio(LIO_NOWAIT, batch, static_cast<int>(size), nullptr);
            int const refusal = listed == 0 ? 0 : errno;
            // A partly queued batch tells its blocks apart through `aio_error`; a refusal of any
            // other kind queued none of them.
            bool const partly = !single && (refusal == EAGAIN || refusal == EINTR || refusal == EIO);
            for (std::size_t index = 0; index != size; ++index) {
                int const state = listed == 0 ? EINPROGRESS : partly ? aio_error(batch[index]) : refusal;
                settle(slots[index], state);
            }
        }
        if (read.pending) return true;
        result = finish(owner);
        return false;
    }

    /** Hands @p landed the operation and result of every read whose last block landed. */
    template <typename landed_type_>
    void reap(landed_type_&& landed) noexcept {
        bool reaped = false;
        for (std::size_t position = 0; position != flying.size();) {
            block_t& block = blocks[flying[position]];
            int const error = aio_error(&block.control);
            if (error == EINPROGRESS) {
                ++position;
                continue;
            }
            ssize_t const returned = aio_return(&block.control);
            block.landed = returned >= 0 ? static_cast<descriptor_t>(returned) : -(error ? error : EIO);
            block.in_flight = false;
            flying[position] = flying.back();
            flying.pop_back();
            reaped = true;
            if (--reads[block.owner].pending == 0) landed(block.owner, finish(block.owner));
        }
        backoff_ns = reaped                                      ? aio_backoff_floor_ns_k
                     : backoff_ns * 2 > aio_backoff_ceiling_ns_k ? aio_backoff_ceiling_ns_k
                                                                 : backoff_ns * 2;
    }

    /** Waits until every read in flight landed, handing each to @p landed, as a stop must. */
    template <typename landed_type_>
    void drain(landed_type_&& landed) noexcept {
        aiocb const* waited[aio_batch_limit_k];
        while (in_flight()) {
            std::size_t const size = flying.size() < aio_batch_limit_k ? flying.size() : aio_batch_limit_k;
            for (std::size_t index = 0; index != size; ++index) waited[index] = &blocks[flying[index]].control;
            [[maybe_unused]] int const suspended = aio_suspend(waited, static_cast<int>(size), nullptr);
            reap(landed);
        }
    }

  private:
    /** Records block @p slot by its @p state: in flight while the kernel queued it, its result once
     *  it landed already, and read blocking into its buffer when the kernel had no room for it. */
    void settle(unsigned slot, int state) noexcept {
        block_t& block = blocks[slot];
        if (state == EINPROGRESS) {
            block.in_flight = true;
            [[maybe_unused]] st::status_t const kept = flying.push_back(st::assume_reserved, unsigned {slot});
            return;
        }
        if (state == 0) block.landed = static_cast<descriptor_t>(aio_return(&block.control));
        else if (state == EAGAIN || state == EINTR) {
            block.landed = utilities::read_native_file_vectors(block.control.aio_fildes, {&block.vector, 1},
                                                               static_cast<std::uint64_t>(block.control.aio_offset));
        }
        else block.landed = -state;
        --reads[block.owner].pending;
    }

    /** Sums the landed blocks of @p owner in order up to the first short or failed one, as
     *  @c preadv would answer, and returns them to the pool. */
    descriptor_t finish(unsigned owner) noexcept {
        descriptor_t total = 0;
        bool ended = false;
        for (unsigned slot = reads[owner].first; slot != aio_absent_k; slot = blocks[slot].next) {
            block_t const& block = blocks[slot];
            if (ended) continue;
            if (block.landed < 0) {
                if (!total) total = block.landed;
                ended = true;
                continue;
            }
            total += block.landed;
            ended = static_cast<std::size_t>(block.landed) < block.control.aio_nbytes;
        }
        release(owner);
        return total;
    }

    void release(unsigned owner) noexcept {
        for (unsigned slot = reads[owner].first; slot != aio_absent_k;) {
            unsigned const next = blocks[slot].next;
            blocks[slot].owner = aio_absent_k;
            [[maybe_unused]] st::status_t const kept = free_blocks.push_back(st::assume_reserved, unsigned {slot});
            slot = next;
        }
        reads[owner] = {};
    }
};

#endif // UCALL_OS_POSIX_

} // namespace unum::ucall::io
