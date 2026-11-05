/**
 *  @file include/ucall/io/bsd_kqueue_engine.hpp
 *  @author Ash Vardanian
 *  @date January 13, 2025
 *  @brief kqueue readiness for Apple and FreeBSD sockets, with FreeBSD file reads through AIO.
 */
#pragma once

#include <smashtable/basic_vector.hpp> // `vector`
#include <smashtable/row_search.hpp>   // `serial_row_kit_t`

#include "ucall/io/types.hpp"          // `operation_list_t`, `io_request_t`, `operation_stage_t`, `io_interest_t`
#include "ucall/utilities/sockets.hpp" // `socket_open`, `socket_close`, `socket_reset_on_close`, `monotonic_ns`
#include "ucall/utilities/types.hpp"   // `byte_t`, `descriptor_t`, `span`

#if UCALL_OS_APPLE_ || UCALL_OS_FREEBSD_

#include <sys/event.h> // `kevent`, `EVFILT_READ`
#if UCALL_OS_FREEBSD_
#include <aio.h> // `aio_read`, `aiocb`
#endif

namespace unum::ucall::io {

using utilities::byte_t;
using utilities::descriptor_t;
using utilities::monotonic_ns;
using utilities::socket_close;
using utilities::socket_open;
using utilities::socket_reset_on_close;
using utilities::span;

/** Each descriptor stays registered edge-triggered until @c close_socket or a close request, aimed
 *  at its latest operation in each direction; file reads land through the readiness queue where
 *  the kernel offers asynchronous reads, and zero-copy sends copy, so their releases complete as
 *  soon as they are submitted. */
template <typename allocator_type_, template <typename> class atomic_ref_template_, typename row_kit_type_>
struct kqueue_readiness;

template <typename allocator_type_ = st::default_allocator<byte_t>,
          template <typename> class atomic_ref_template_ = fu::standard_atomic_ref,
          typename row_kit_type_ = st::serial_row_kit_t>
struct bsd_kqueue_engine {
    using allocator_t = allocator_type_;
    template <typename other_allocator_, template <typename> class other_atomic_ref_, typename other_row_kit_>
    using rebind = bsd_kqueue_engine<other_allocator_, other_atomic_ref_, other_row_kit_>;
    static constexpr unsigned absent_k = operation_list_t::absent_k;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    struct operation_t {
        io_request_t* request {};
        unsigned next {absent_k}, timed {absent_k};

        /** What a landed file read completes with. */
        descriptor_t result {};

        operation_stage_t stage {operation_stage_t::fresh_k};
        io_interest_t interest {io_interest_t::unarmed_k};
    };
    descriptor_t open_socket(int family) noexcept { return socket_open(family); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept { return descriptor; }
    int close_socket(descriptor_t descriptor) noexcept {
        readiness.remove(descriptor);
        return socket_close(descriptor);
    }
    [[nodiscard]] ucall_status_t reset_on_close(descriptor_t descriptor) noexcept {
        return socket_reset_on_close(descriptor);
    }
    memory_registration_t register_memory(span<byte_t>) noexcept { return {}; }
    void release(io_completion_t const&) noexcept {}
    ucall_status_t cancel(io_request_t& request) noexcept {
        for (unsigned i = 0; i != operations.size(); ++i)
            if (operations[i].request == &request) {
                tally<atomic_ref_template_>(statistics.cancellations);
                // A landing file read keeps its buffer until the kernel answers, then reports it.
                operations[i].stage = operation_stage_t::cancelled_k;
                if (operations[i].interest == io_interest_t::armed_k) wake(i);
                return ucall_status_success_k;
            }
        return ucall_status_not_found_k;
    }
    explicit bsd_kqueue_engine(allocator_t const& allocator = {}) noexcept
        : operations(rebound_allocator<operation_t> {allocator}), timed(rebound_allocator<unsigned> {allocator}),
          readiness(allocator) {}
    bsd_kqueue_engine(bsd_kqueue_engine const&) = delete;
    bsd_kqueue_engine& operator=(bsd_kqueue_engine const&) = delete;
    bsd_kqueue_engine(bsd_kqueue_engine&&) = delete;
    bsd_kqueue_engine& operator=(bsd_kqueue_engine&&) = delete;
    st::vector<operation_t, rebound_allocator<operation_t>> operations {};
    st::vector<unsigned, rebound_allocator<unsigned>> timed {};
    kqueue_readiness<allocator_t, atomic_ref_template_, row_kit_type_> readiness {};
    operation_list_t free_operations, fresh_operations, ready_operations, landed_operations;
    std::size_t active {};
    io_statistics_t statistics {};
    ucall_status_t open(std::size_t, std::size_t capacity) noexcept {
        if (st::failed(operations.resize(capacity)) || st::failed(timed.reserve(capacity)))
            return ucall_status_out_of_memory_k;
        stop();
        return readiness.open(capacity);
    }
    ucall_status_t submit(io_request_t& request) noexcept {
        auto index = free_operations.pop(operations);
        if (index == absent_k) return ucall_status_contended_k;
        auto& operation = operations[index];
        operation = {};
        operation.request = &request;
        fresh_operations.push(operations, index);
        if (request.deadline) {
            operation.timed = static_cast<unsigned>(timed.size());
            [[maybe_unused]] st::status_t const tracked = timed.push_back(st::assume_reserved, unsigned {index});
        }
        ++active;
        tally<atomic_ref_template_>(statistics.submissions);
        return ucall_status_success_k;
    }
    void wake(unsigned index) noexcept { readiness_wake(*this, index); }
    void land(unsigned index, descriptor_t result) noexcept { readiness_land(*this, index, result); }
    io_completion_t finish(unsigned index, descriptor_t result) noexcept {
        return readiness_finish<atomic_ref_template_>(*this, index, result);
    }
    std::size_t progress(operation_list_t& list, span<io_completion_t> completions, std::size_t count,
                         std::uint64_t now) noexcept {
        while (count != completions.size()) {
            auto index = list.pop(operations);
            if (index == absent_k) break;
            auto& operation = operations[index];
            auto& request = *operation.request;
            bool fired = operation.interest == io_interest_t::ready_k;
            descriptor_t result = -ETIMEDOUT;
            // An edge-triggered operation hears nothing more until its syscall reports EAGAIN.
            if (!request.deadline || request.deadline > now) {
                if (request.operation == io_operation_t::close_k) readiness.remove(request.descriptor);
                do {
                    result = readiness.attempt(index, request, operation.stage, operation.interest, statistics);
                } while (fired && result == -EINTR);
            }
            if (operation.interest == io_interest_t::landing_k) continue;
            if (io_pending(result) && !fired) {
                io_direction_t direction = io_direction(request.operation);
                if (int armed = readiness.arm(request.descriptor, direction, index, statistics); armed < 0)
                    result = armed;
            }
            if (io_pending(result)) operation.interest = io_interest_t::armed_k;
            else completions[count++] = finish(index, result);
        }
        return count;
    }
    std::size_t collect(span<io_completion_t> completions, std::size_t count) noexcept {
        return readiness_collect<atomic_ref_template_>(*this, completions, count);
    }
    int poll(span<io_completion_t> completions, io_wait_t wait_policy, std::uint64_t deadline = 0) noexcept {
        if (!completions.size()) return 0;
        std::size_t count {};
        for (unsigned round = 0; round != 2; ++round) {
            auto now = monotonic_ns();
            auto wait = wait_policy == io_wait_t::blocking_k ? std::numeric_limits<std::uint64_t>::max() : 0;
            if (deadline) wait = std::min(wait, deadline > now ? deadline - now : 0);
            for (auto index : timed) {
                auto expiry = operations[index].request->deadline;
                if (expiry > now) wait = std::min(wait, expiry - now);
                else if (operations[index].interest == io_interest_t::armed_k) wake(index);
            }
            count = collect(completions, count);
            count = progress(fresh_operations, completions, count, now);
            count = progress(ready_operations, completions, count, now);
            if (count || round || !active) break;
            int timeout = wait == std::numeric_limits<std::uint64_t>::max()
                              ? -1
                              : static_cast<int>(std::min<std::uint64_t>(wait / 1'000'000 + (wait % 1'000'000 != 0),
                                                                         std::numeric_limits<int>::max()));
            tally<atomic_ref_template_>(statistics.kernel_enters);
            int result = readiness.wait(
                timeout,
                [&](unsigned index, descriptor_t descriptor, short events) noexcept {
                    auto& operation = operations[index];
                    if (operation.interest == io_interest_t::armed_k && operation.request->descriptor == descriptor &&
                        (events & io_events(operation.request->operation)))
                        wake(index);
                },
                [&](unsigned index, descriptor_t result) noexcept { land(index, result); });
            if (result < 0 && result != -EINTR) return result;
        }
        return static_cast<int>(count);
    }
    void stop() noexcept {
        // File reads still in the kernel write into their buffers until they land.
        readiness.drain_files([&](unsigned, descriptor_t) noexcept {});
        free_operations = fresh_operations = ready_operations = landed_operations = {};
        timed.clear();
        active = 0;
        for (unsigned i = 0; i != operations.size(); ++i) {
            operations[i] = {};
            free_operations.push(operations, i);
        }
    }
    ~bsd_kqueue_engine() noexcept { stop(); }
};

/** kqueue readiness; FreeBSD reads files through @c aio_read completing as @c EVFILT_AIO events,
 *  while macOS, lacking kernel file AIO for this, reads them blocking and uncached. */
template <typename allocator_type_ = st::default_allocator<byte_t>,
          template <typename> class atomic_ref_template_ = fu::standard_atomic_ref,
          typename row_kit_type_ = st::serial_row_kit_t>
struct kqueue_readiness {
    using allocator_t = allocator_type_;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
#if UCALL_OS_FREEBSD_
    explicit kqueue_readiness(allocator_t const& allocator = {}) noexcept
        : events(rebound_allocator<struct kevent> {allocator}), file_reads(rebound_allocator<aiocb> {allocator}) {}
#else
    explicit kqueue_readiness(allocator_t const& allocator = {}) noexcept
        : events(rebound_allocator<struct kevent> {allocator}) {}
#endif
    kqueue_readiness(kqueue_readiness const&) = delete;
    kqueue_readiness& operator=(kqueue_readiness const&) = delete;
    kqueue_readiness(kqueue_readiness&&) = delete;
    kqueue_readiness& operator=(kqueue_readiness&&) = delete;
    int descriptor {-1};
    st::vector<struct kevent, rebound_allocator<struct kevent>> events {};
#if UCALL_OS_FREEBSD_

    /** One per operation, read by the kernel. */
    st::vector<aiocb, rebound_allocator<aiocb>> file_reads {};
    std::size_t file_reads_in_flight {};
#endif
    ucall_status_t open(std::size_t capacity) noexcept {
        if (st::failed(events.resize(capacity)) || reserve_file_reads(capacity) != ucall_status_success_k)
            return ucall_status_out_of_memory_k;
        descriptor = kqueue();
        if (descriptor >= 0 && fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0) return ucall_status_success_k;
        return ucall_status_io_k;
    }

    /** Points the @p direction filter of the descriptor at operation @p index,
     *  adding it on first use. */
    int arm(descriptor_t watched, io_direction_t direction, unsigned index, io_statistics_t& statistics) noexcept {
        struct kevent change {};
        short filter = direction == io_direction_t::receive_k ? EVFILT_READ : EVFILT_WRITE;
        EV_SET(&change, static_cast<std::uintptr_t>(watched), filter, EV_ADD | EV_CLEAR, 0, 0,
               reinterpret_cast<void*>(static_cast<std::uintptr_t>(index)));
        tally<atomic_ref_template_>(statistics.kernel_enters);
        return kevent(descriptor, &change, 1, nullptr, 0, nullptr) == 0 ? 0 : -errno;
    }
    // Closing a descriptor drops its knotes.
    void remove(descriptor_t) noexcept {}

#if UCALL_OS_FREEBSD_
    ucall_status_t reserve_file_reads(std::size_t capacity) noexcept {
        return st::failed(file_reads.resize(capacity)) ? ucall_status_out_of_memory_k : ucall_status_success_k;
    }

    /** Starts a file read as operation @p index, landing it through @c EVFILT_AIO; a full AIO queue
     *  reads blocking instead. Everything else is a plain syscall. */
    descriptor_t attempt(unsigned index, io_request_t& request, operation_stage_t& stage, io_interest_t& interest,
                         io_statistics_t& statistics) noexcept {
        if (request.operation != io_operation_t::file_read_k &&
            request.operation != io_operation_t::file_read_vectors_k)
            return attempt_io<atomic_ref_template_>(request, stage, interest, statistics);
        if (stage == operation_stage_t::cancelled_k) return -ECANCELED;
        aiocb& block = file_reads[index];
        block = {};
        block.aio_fildes = request.file.file_descriptor;
        block.aio_offset = static_cast<off_t>(request.file.offset);
        block.aio_sigevent.sigev_notify = SIGEV_KEVENT;
        block.aio_sigevent.sigev_notify_kqueue = descriptor;
        block.aio_sigevent.sigev_value.sival_ptr = reinterpret_cast<void*>(static_cast<std::uintptr_t>(index));
        int started;
        tally<atomic_ref_template_>(statistics.kernel_enters);
        if (request.operation == io_operation_t::file_read_k) {
            block.aio_buf = request.data;
            block.aio_nbytes = request.length;
            started = aio_read(&block);
        }
        else {
            block.aio_iov = io_vectors(request).data();
            block.aio_iovcnt = static_cast<int>(request.length);
            started = aio_readv(&block);
        }
        if (started == 0) {
            ++file_reads_in_flight;
            tally<atomic_ref_template_>(statistics.file_reads_asynchronous);
            interest = io_interest_t::landing_k;
            return 0;
        }
        if (errno != EAGAIN) return -errno;
        return attempt_io<atomic_ref_template_>(request, stage, interest, statistics);
    }
#else
    ucall_status_t reserve_file_reads(std::size_t) noexcept { return ucall_status_success_k; }
    descriptor_t attempt(unsigned, io_request_t& request, operation_stage_t& stage, io_interest_t& interest,
                         io_statistics_t& statistics) noexcept {
        return attempt_io<atomic_ref_template_>(request, stage, interest, statistics);
    }
#endif // UCALL_OS_FREEBSD_

    template <typename fired_type_, typename landed_type_>
    int wait(int timeout, fired_type_&& fired, landed_type_&& landed) noexcept {
        timespec duration {timeout / 1000, (timeout % 1000) * 1'000'000L};
        int count = kevent(descriptor, nullptr, 0, events.data(),
                           static_cast<int>(std::min<std::size_t>(events.size(), std::numeric_limits<int>::max())),
                           timeout < 0 ? nullptr : &duration);
        if (count < 0) return -errno;
        for (int i = 0; i != count; ++i) {
            if (events[i].flags & EV_ERROR) return -static_cast<int>(events[i].data);
            auto const index = static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(events[i].udata));
            if (events[i].filter == EVFILT_READ || events[i].filter == EVFILT_WRITE)
                fired(index, static_cast<descriptor_t>(events[i].ident),
                      static_cast<short>(events[i].filter == EVFILT_READ ? POLLIN : POLLOUT));
            else land_file_read(index, landed);
        }
        return count;
    }
#if UCALL_OS_FREEBSD_
    template <typename landed_type_>
    void land_file_read(unsigned index, landed_type_& landed) noexcept {
        aiocb& block = file_reads[index];
        ssize_t const result = aio_return(&block);
        --file_reads_in_flight;
        landed(index, result >= 0 ? static_cast<descriptor_t>(result) : -errno);
    }

    /** Waits for every file read still in the kernel, handing each to @p landed. */
    template <typename landed_type_>
    void drain_files(landed_type_&& landed) noexcept {
        while (file_reads_in_flight) {
            struct kevent event {};
            if (kevent(descriptor, nullptr, 0, &event, 1, nullptr) == 1 && event.filter == EVFILT_AIO)
                land_file_read(static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(event.udata)), landed);
        }
    }
#else
    template <typename landed_type_>
    void land_file_read(unsigned, landed_type_&) noexcept {}
    template <typename landed_type_>
    void drain_files(landed_type_&&) noexcept {}
#endif // UCALL_OS_FREEBSD_
    ~kqueue_readiness() noexcept {
        if (descriptor >= 0) close(descriptor);
    }
};
using kqueue_readiness_t = kqueue_readiness<>;
using bsd_kqueue_engine_t = bsd_kqueue_engine<>;

} // namespace unum::ucall::io

#endif // UCALL_OS_APPLE_ || UCALL_OS_FREEBSD_
