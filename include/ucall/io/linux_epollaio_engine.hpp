/**
 *  @file include/ucall/io/linux_epollaio_engine.hpp
 *  @author Ash Vardanian
 *  @date January 13, 2025
 *  @brief epoll readiness for sockets and Linux AIO for files, completing in one epoll set.
 */
#pragma once

#include <bit> // `std::bit_cast`

#include <smashtable/basic_hash_index.hpp> // `basic_hash_index`
#include <smashtable/basic_vector.hpp>     // `vector`
#include <smashtable/row_search.hpp>       // `serial_row_kit_t`

#include "ucall/io/types.hpp"          // `operation_list_t`, `zero_copy_stage_t`, `io_statistics_t`, `tally`
#include "ucall/utilities/sockets.hpp" // `socket_reset_on_close`, `socket_open`, `socket_option`, `socket_close`
#include "ucall/utilities/types.hpp"   // `descriptor_t`, `byte_t`, `span`

#if UCALL_OS_LINUX_

#include <linux/aio_abi.h>  // `aio_context_t`, `iocb`, `io_event`
#include <linux/errqueue.h> // `sock_extended_err`, `SO_EE_ORIGIN_ZEROCOPY`
#include <sys/epoll.h>
#include <sys/eventfd.h> // `eventfd`
#include <sys/syscall.h> // `SYS_io_setup`

namespace unum::ucall::io {

using utilities::byte_t;
using utilities::descriptor_t;
using utilities::monotonic_ns;
using utilities::socket_close;
using utilities::socket_open;
using utilities::socket_option;
using utilities::socket_reset_on_close;
using utilities::span;

/** Resets @p descriptor's connection now while keeping the descriptor, so its error queue stays
 *  readable; the kernel purges what it still meant to send. */
[[nodiscard]] inline ucall_status_t socket_disconnect_with_reset(descriptor_t descriptor) noexcept {
    sockaddr unspecified {};
    unspecified.sa_family = AF_UNSPEC;
    return socket_reset_on_close(descriptor) == ucall_status_success_k &&
                   connect(static_cast<int>(descriptor), &unspecified, sizeof(unspecified)) == 0
               ? ucall_status_success_k
               : ucall_status_io_k;
}

/** Whether a watched socket is open, or closed by its owner and kept until the kernel let go of its
 *  zero-copy bytes. */
enum class watch_stage_t : std::uint8_t { open_k, closing_k };

/** One registered descriptor, the operation waiting in each direction, and its zero-copy sends
 *  whose notifications are still due, as runs in send order. */
struct readiness_watch_t {
    std::int32_t descriptor {-1};

    /** Rides in the event, so stale events never wake a reused watch. */
    std::uint32_t generation {};

    std::uint32_t receive_operation {operation_list_t::absent_k};

    /** Or the close of a closing watch. */
    std::uint32_t transmit_operation {operation_list_t::absent_k};

    std::uint32_t next_zero_copy_id {};
    std::uint32_t oldest_run {operation_list_t::absent_k}, newest_run {operation_list_t::absent_k};
    zero_copy_stage_t zero_copy {zero_copy_stage_t::untried_k};
    watch_stage_t stage {watch_stage_t::open_k};
};
static_assert(sizeof(readiness_watch_t) == 32);

/** Consecutive zero-copy sends of one socket naming one release, by their notification IDs. */
struct zero_copy_run_t {
    std::uint32_t first_id {};
    std::uint32_t release_operation {operation_list_t::absent_k};
    std::uint32_t next {operation_list_t::absent_k};
    std::uint16_t sends {};
    std::uint16_t notified {};
};
static_assert(sizeof(zero_copy_run_t) == 16);

/** Registers each descriptor once; a descriptor-addressed index finds its watch,
 *  at most half full. */
template <typename allocator_type_ = st::default_allocator<byte_t>,
          template <typename> class atomic_ref_template_ = fu::standard_atomic_ref,
          typename row_kit_type_ = st::serial_row_kit_t>
struct epoll_readiness {
    using allocator_t = allocator_type_;
    static constexpr std::uint32_t absent_k = operation_list_t::absent_k;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;

    /** The event data of the one descriptor that is no watch, the AIO completion counter. */
    static constexpr std::uint64_t signal_k = std::numeric_limits<std::uint64_t>::max();
    using watches_t = st::basic_fixed_pool<readiness_watch_t, std::uint32_t, rebound_allocator<byte_t>>;
    using watch_index_t =
        st::basic_hash_index<std::int32_t, std::uint32_t, st::default_hash_t, rebound_allocator<byte_t>, row_kit_type_>;
    explicit epoll_readiness(allocator_t const& allocator = {}) noexcept
        : events(rebound_allocator<epoll_event> {allocator}) {}
    epoll_readiness(epoll_readiness const&) = delete;
    epoll_readiness& operator=(epoll_readiness const&) = delete;
    epoll_readiness(epoll_readiness&&) = delete;
    epoll_readiness& operator=(epoll_readiness&&) = delete;
    int descriptor {-1};
    st::vector<epoll_event, rebound_allocator<epoll_event>> events {};
    watches_t watches {};
    watch_index_t watch_index {};
    ucall_status_t open(std::size_t capacity) noexcept {
        if (st::failed(events.resize(capacity))) return ucall_status_out_of_memory_k;
        rebound_allocator<byte_t> const allocator {events.get_allocator()};
        st::expected<watches_t> made_watches = watches_t::make(capacity, allocator);
        st::expected<watch_index_t> made_index = watch_index_t::make(capacity, {}, allocator);
        if (!made_watches || !made_index) return ucall_status_out_of_memory_k;
        watches = std::move(*made_watches);
        watch_index = std::move(*made_index);
        if (descriptor < 0) descriptor = epoll_create1(EPOLL_CLOEXEC);
        return descriptor < 0 ? ucall_status_io_k : ucall_status_success_k;
    }

    /** Watches @p signalled, reported apart from every watch. */
    [[nodiscard]] ucall_status_t watch_signal(int signalled) noexcept {
        epoll_event event {};
        event.events = EPOLLIN | EPOLLET;
        event.data.u64 = signal_k;
        return epoll_ctl(descriptor, EPOLL_CTL_ADD, signalled, &event) == 0 ? ucall_status_success_k
                                                                            : ucall_status_io_k;
    }

    /** The watch of @p watched, or @c absent_k. */
    std::uint32_t find(descriptor_t watched) const noexcept {
        return watch_index.find(static_cast<std::int32_t>(watched));
    }

    /** The watch of @p watched, registering it on first use: its index, or a negated errno. */
    std::int64_t watch(descriptor_t watched, io_statistics_t& statistics) noexcept {
        if (std::uint32_t const found = find(watched); found != absent_k) return found;
        std::uint32_t const chosen = watches.take();
        if (chosen == watches_t::absent_k) return -ENOBUFS;
        epoll_event event {};
        event.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET;
        event.data.u64 = std::bit_cast<std::uint64_t>(watches.handle_of(chosen));
        tally<atomic_ref_template_>(statistics.kernel_enters);
        if (epoll_ctl(descriptor, EPOLL_CTL_ADD, static_cast<int>(watched), &event) != 0) {
            int const error = errno;
            watches.vacate(chosen);
            return -error;
        }
        watches[chosen].descriptor = static_cast<std::int32_t>(watched);
        [[maybe_unused]] st::status_t const indexed = watch_index.insert(static_cast<std::int32_t>(watched), chosen,
                                                                         st::assume_unique);
        return chosen;
    }

    /** Points @p direction of the descriptor's watch at operation @p index,
     *  registering it on first use. */
    int arm(descriptor_t watched, io_direction_t direction, unsigned index, io_statistics_t& statistics) noexcept {
        std::int64_t const chosen = watch(watched, statistics);
        if (chosen < 0) return static_cast<int>(chosen);
        readiness_watch_t& found = watches[static_cast<std::uint32_t>(chosen)];
        (direction == io_direction_t::receive_k ? found.receive_operation : found.transmit_operation) = index;
        return 0;
    }

    /** Unregisters @p watched and frees its watch; events still queued for it find nothing. */
    void remove(descriptor_t watched) noexcept {
        std::uint32_t const chosen = find(watched);
        if (chosen == absent_k) return;
        epoll_ctl(descriptor, EPOLL_CTL_DEL, static_cast<int>(watched), nullptr);
        [[maybe_unused]] st::status_t const unindexed = watch_index.erase(static_cast<std::int32_t>(watched), chosen);
        watches[chosen] = {-1, watches[chosen].generation};
        watches.vacate(chosen);
    }

    /** Waits up to @p timeout milliseconds, reporting readiness to @p fired, the error queues of
     *  watches awaiting notifications to @p errored, and the signal descriptor to @p signalled. */
    template <typename fired_type_, typename errored_type_, typename signalled_type_>
    int wait(int timeout, fired_type_&& fired, errored_type_&& errored, signalled_type_&& signalled) noexcept {
        int count = epoll_wait(descriptor, events.data(),
                               static_cast<int>(std::min<std::size_t>(events.size(), std::numeric_limits<int>::max())),
                               timeout);
        if (count < 0) return -errno;
        for (int i = 0; i != count; ++i) {
            auto flags = events[i].events;
            if (events[i].data.u64 == signal_k) {
                signalled();
                continue;
            }
            auto const handle = std::bit_cast<typename watches_t::handle_t>(events[i].data.u64);
            readiness_watch_t const* watch = watches.at(handle);
            if (!watch) continue;
            if ((flags & EPOLLERR) && (watch->oldest_run != absent_k || watch->stage == watch_stage_t::closing_k))
                errored(handle.index);
            // The error queue may have closed and freed the watch.
            watch = watches.at(handle);
            if (!watch || watch->stage == watch_stage_t::closing_k) continue;
            if ((flags & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)) && watch->receive_operation != absent_k)
                fired(watch->receive_operation, watch->descriptor, short {POLLIN});
            if ((flags & (EPOLLOUT | EPOLLHUP | EPOLLERR)) && watch->transmit_operation != absent_k)
                fired(watch->transmit_operation, watch->descriptor, short {POLLOUT});
        }
        return count;
    }
    ~epoll_readiness() noexcept {
        if (descriptor >= 0) close(descriptor);
    }
};
using epoll_readiness_t = epoll_readiness<>;

/** AIO events one engine keeps in flight; <tt>fs.aio-max-nr</tt>, 65536 by default, bounds the sum
 *  on a host, so a 64-loop server reserves 4096 of them. */
inline constexpr std::uint32_t linux_aio_depth_k = 64;

/** One Linux AIO context, through raw syscalls, completing into an eventfd an epoll set watches. */
struct linux_aio_t {
    aio_context_t context {};
    int signal_descriptor {-1};

    /** The first @c open tries, halved while the host limit refuses. */
    std::uint32_t depth {linux_aio_depth_k};

    std::uint32_t in_flight {};
    linux_aio_t() noexcept = default;
    linux_aio_t(linux_aio_t const&) = delete;
    linux_aio_t& operator=(linux_aio_t const&) = delete;
    ~linux_aio_t() noexcept { close(); }

    /** Sets up the context, answering @c ucall_status_unsupported_k when the kernel or the host's
     *  <tt>fs.aio-max-nr</tt> refuses even one event. */
    [[nodiscard]] ucall_status_t open() noexcept {
        if (context) return ucall_status_success_k;
        while (depth && syscall(SYS_io_setup, depth, &context) != 0) depth = errno == EAGAIN ? depth / 2 : 0;
        if (!depth) {
            context = 0;
            return ucall_status_unsupported_k;
        }
        signal_descriptor = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (signal_descriptor >= 0) return ucall_status_success_k;
        close();
        return ucall_status_io_k;
    }

    /** Destroys the context, which waits for every read in flight, so their buffers are free. */
    void close() noexcept {
        if (context) syscall(SYS_io_destroy, context);
        if (signal_descriptor >= 0) ::close(signal_descriptor);
        context = 0;
        signal_descriptor = -1;
        in_flight = 0;
    }

    /** Starts @p request's file read as operation @p index: zero, or a negated errno, @c -EAGAIN
     *  while every event is taken. */
    int submit(unsigned index, io_request_t const& request) noexcept {
        if (in_flight == depth) return -EAGAIN;
        iocb block {};
        block.aio_data = index;
        block.aio_lio_opcode = request.operation == io_operation_t::file_read_k ? IOCB_CMD_PREAD : IOCB_CMD_PREADV;
        block.aio_fildes = static_cast<std::uint32_t>(request.file.file_descriptor);
        block.aio_buf = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(request.data));
        block.aio_nbytes = request.length;
        block.aio_offset = static_cast<std::int64_t>(request.file.offset);
        block.aio_flags = IOCB_FLAG_RESFD;
        block.aio_resfd = static_cast<std::uint32_t>(signal_descriptor);
        iocb* blocks[1] {&block};
        long const submitted = syscall(SYS_io_submit, context, 1, blocks);
        if (submitted == 1) {
            ++in_flight;
            return 0;
        }
        return submitted < 0 ? -errno : -EAGAIN;
    }

    /** Empties the counter, then hands every landed read to @p landed. */
    template <typename landed_type_>
    void drain(landed_type_&& landed) noexcept {
        std::uint64_t signalled {};
        while (::read(signal_descriptor, &signalled, sizeof(signalled)) < 0 && errno == EINTR) {}
        io_event landed_events[linux_aio_depth_k];
        for (long count = linux_aio_depth_k; count == linux_aio_depth_k;) {
            timespec none {};
            count = syscall(SYS_io_getevents, context, 0, long {linux_aio_depth_k}, landed_events, &none);
            for (long i = 0; i < count; ++i) {
                --in_flight;
                landed(static_cast<unsigned>(landed_events[i].data), static_cast<descriptor_t>(landed_events[i].res));
            }
        }
    }
};

/**
 *  @brief epoll readiness for sockets with Linux AIO for files, both completing in one epoll set,
 *      and @c MSG_ZEROCOPY sends whose releases land from the error queue.
 *
 *  - A file read lands from the AIO eventfd and cannot be cancelled: a cancel completes it with
 *    @c -ECANCELED once the kernel answered, keeping its buffer until then.
 *  - A zero-copy send takes the next notification ID of its socket; a socket whose notification
 *    reports a copy, or that refuses @c SO_ZEROCOPY, copies from then on, and @c ENOBUFS copies
 *    once.
 *  - A close with notifications still due keeps the descriptor until they all arrived, resetting
 *    first if the socket was set to reset on close.
 */
template <typename allocator_type_ = st::default_allocator<byte_t>,
          template <typename> class atomic_ref_template_ = fu::standard_atomic_ref,
          typename row_kit_type_ = st::serial_row_kit_t>
struct linux_epollaio_engine {
    using allocator_t = allocator_type_;
    template <typename other_allocator_, template <typename> class other_atomic_ref_, typename other_row_kit_>
    using rebind = linux_epollaio_engine<other_allocator_, other_atomic_ref_, other_row_kit_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    template <typename value_type_>
    using vector = st::vector<value_type_, rebound_allocator<value_type_>>;
    static constexpr unsigned absent_k = operation_list_t::absent_k;
    struct operation_t {
        io_request_t* request {};
        unsigned next {absent_k}, timed {absent_k};

        /** A release's zero-copy sends not yet notified. */
        std::uint32_t outstanding_notifications {};

        /** What a landed operation completes with. */
        descriptor_t result {};

        operation_stage_t stage {operation_stage_t::fresh_k};
        io_interest_t interest {io_interest_t::unarmed_k};
    };
    static_assert(sizeof(operation_t) == 32);
    using release_index_t = st::basic_hash_index<std::uint64_t, std::uint32_t, st::default_hash_t,
                                                 rebound_allocator<byte_t>, row_kit_type_>;

    vector<operation_t> operations;
    vector<unsigned> timed;
    vector<zero_copy_run_t> runs;
    epoll_readiness<allocator_t, atomic_ref_template_, row_kit_type_> readiness;
    release_index_t releases;
    linux_aio_t files;
    operation_list_t free_operations, fresh_operations, ready_operations, landed_operations, waiting_files;
    unsigned free_runs {absent_k};
    std::size_t active {};

    /** Why @c open answered @c ucall_status_unsupported_k, naming the setting to raise. */
    char const* refusal {};

    io_statistics_t statistics {};

    explicit linux_epollaio_engine(allocator_t const& allocator = {}) noexcept
        : operations(rebound_allocator<operation_t> {allocator}), timed(rebound_allocator<unsigned> {allocator}),
          runs(rebound_allocator<zero_copy_run_t> {allocator}), readiness(allocator) {}
    linux_epollaio_engine(linux_epollaio_engine const&) = delete;
    linux_epollaio_engine& operator=(linux_epollaio_engine const&) = delete;
    linux_epollaio_engine(linux_epollaio_engine&&) = delete;
    linux_epollaio_engine& operator=(linux_epollaio_engine&&) = delete;
    ~linux_epollaio_engine() noexcept { stop(); }

    descriptor_t open_socket(int family) noexcept { return socket_open(family); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept { return descriptor; }
    [[nodiscard]] ucall_status_t reset_on_close(descriptor_t descriptor) noexcept {
        return socket_reset_on_close(descriptor);
    }
    memory_registration_t register_memory(span<byte_t>) noexcept { return {}; }
    void release(io_completion_t const&) noexcept {}

    ucall_status_t open(std::size_t, std::size_t capacity) noexcept {
        if (st::failed(operations.resize(capacity)) || st::failed(timed.reserve(capacity)) ||
            st::failed(runs.resize(capacity)))
            return ucall_status_out_of_memory_k;
        stop();
        if (ucall_status_t const opened = readiness.open(capacity); opened != ucall_status_success_k) return opened;
        st::expected<release_index_t> made = release_index_t::make(
            capacity, {}, rebound_allocator<byte_t> {operations.get_allocator()});
        if (!made) return ucall_status_out_of_memory_k;
        releases = std::move(*made);
        if (ucall_status_t const opened = files.open(); opened != ucall_status_success_k) {
            if (opened == ucall_status_unsupported_k)
                refusal = "Linux AIO refused a context: raise `fs.aio-max-nr`, as `sysctl -w fs.aio-max-nr=1048576`";
            return opened;
        }
        return readiness.watch_signal(files.signal_descriptor);
    }

    ucall_status_t submit(io_request_t& request) noexcept {
        unsigned index = absent_k;
        // A release some send already named exists since that send; it now leaves the index.
        if (request.operation == io_operation_t::zero_copy_release_k) index = releases.find(release_key(&request));
        if (index != absent_k) {
            [[maybe_unused]] st::status_t const unindexed = releases.erase(release_key(&request), index);
        }
        else {
            index = free_operations.pop(operations);
            if (index == absent_k) return ucall_status_contended_k;
            operations[index] = {};
            operations[index].request = &request;
        }
        auto& operation = operations[index];
        fresh_operations.push(operations, index);
        bool const lands = request.operation == io_operation_t::zero_copy_release_k ||
                           request.operation == io_operation_t::file_read_k ||
                           request.operation == io_operation_t::file_read_vectors_k;
        if (request.deadline && !lands) {
            operation.timed = static_cast<unsigned>(timed.size());
            [[maybe_unused]] st::status_t const tracked = timed.push_back(st::assume_reserved, unsigned {index});
        }
        ++active;
        tally<atomic_ref_template_>(statistics.submissions);
        return ucall_status_success_k;
    }

    ucall_status_t cancel(io_request_t& request) noexcept {
        for (unsigned i = 0; i != operations.size(); ++i) {
            auto& operation = operations[i];
            if (operation.request != &request) continue;
            // A release ends on its notifications, a closing socket on its last one, never sooner.
            if (request.operation == io_operation_t::zero_copy_release_k ||
                (request.operation == io_operation_t::close_k && operation.interest == io_interest_t::landing_k))
                return ucall_status_success_k;
            tally<atomic_ref_template_>(statistics.cancellations);
            operation.stage = operation_stage_t::cancelled_k;
            if (operation.interest == io_interest_t::armed_k) wake(i);
            else if (operation.interest == io_interest_t::landing_k &&
                     waiting_files.erase(operations, i) == st::success_k) {
                operation.interest = io_interest_t::unarmed_k;
                fresh_operations.push(operations, i);
            }
            return ucall_status_success_k;
        }
        return ucall_status_not_found_k;
    }

    void wake(unsigned index) noexcept { readiness_wake(*this, index); }
    void land(unsigned index, descriptor_t result) noexcept { readiness_land(*this, index, result); }
    io_completion_t finish(unsigned index, descriptor_t result) noexcept {
        return readiness_finish<atomic_ref_template_>(*this, index, result);
    }

    /** Starts a file read, or queues it for an AIO event; it lands through @c files.drain. */
    descriptor_t read_file(unsigned index) noexcept {
        auto& operation = operations[index];
        if (operation.stage == operation_stage_t::cancelled_k) return -ECANCELED;
        tally<atomic_ref_template_>(statistics.kernel_enters);
        int const started = files.submit(index, *operation.request);
        if (started == -EAGAIN) waiting_files.push(operations, index);
        else if (started < 0) return started;
        else tally<atomic_ref_template_>(statistics.file_reads_asynchronous);
        operation.interest = io_interest_t::landing_k;
        return 0;
    }

    /** Sends copying, as a socket does once zero-copy is refused or reported copied. */
    descriptor_t send_copying(io_request_t const& request) noexcept {
        auto const length = std::min<std::size_t>(request.length, std::numeric_limits<int>::max());
        tally<atomic_ref_template_>(statistics.copying_sends);
        ssize_t const sent = send(static_cast<int>(request.descriptor), request.data, length, MSG_NOSIGNAL);
        return sent >= 0 ? static_cast<descriptor_t>(sent) : -errno;
    }

    /** Sends with @c MSG_ZEROCOPY, counting the send against its release under the socket's next
     *  notification ID; without room to count it, the send copies. */
    descriptor_t send_zero_copy(unsigned index) noexcept {
        auto& operation = operations[index];
        if (operation.stage == operation_stage_t::cancelled_k) return -ECANCELED;
        io_request_t const& request = *operation.request;
        tally<atomic_ref_template_>(statistics.kernel_enters);
        std::int64_t const chosen = readiness.watch(request.descriptor, statistics);
        if (chosen < 0) return send_copying(request);
        readiness_watch_t& watch = readiness.watches[static_cast<std::uint32_t>(chosen)];
        if (watch.zero_copy == zero_copy_stage_t::untried_k) {
            int enabled = 1;
            watch.zero_copy = socket_option(request.descriptor, SOL_SOCKET, SO_ZEROCOPY, &enabled, sizeof(enabled)) == 0
                                  ? zero_copy_stage_t::enabled_k
                                  : zero_copy_stage_t::copying_k;
        }
        if (watch.zero_copy == zero_copy_stage_t::copying_k) return send_copying(request);
        unsigned release = releases.find(release_key(request.release_request));
        zero_copy_run_t* extended = watch.newest_run != absent_k ? &runs[watch.newest_run] : nullptr;
        if (extended && (extended->release_operation != release || release == absent_k ||
                         extended->sends == std::numeric_limits<std::uint16_t>::max() ||
                         extended->first_id + extended->sends != watch.next_zero_copy_id))
            extended = nullptr;
        if ((release == absent_k && free_operations.empty()) || (!extended && free_runs == absent_k))
            return send_copying(request);
        auto const length = std::min<std::size_t>(request.length, std::numeric_limits<int>::max());
        ssize_t const sent = send(static_cast<int>(request.descriptor), request.data, length,
                                  MSG_NOSIGNAL | MSG_ZEROCOPY);
        if (sent < 0 && errno == ENOBUFS) {
            tally<atomic_ref_template_>(statistics.zero_copy_fallbacks);
            return send_copying(request);
        }
        if (sent <= 0) return sent < 0 ? -errno : 0;
        tally<atomic_ref_template_>(statistics.zero_copy_sends);
        if (release == absent_k) {
            release = free_operations.pop(operations);
            operations[release] = {};
            operations[release].request = request.release_request;
            [[maybe_unused]] st::status_t const indexed = releases.insert(release_key(request.release_request), release,
                                                                          st::assume_unique);
        }
        ++operations[release].outstanding_notifications;
        if (extended) ++extended->sends;
        else {
            unsigned const run = free_runs;
            free_runs = runs[run].next;
            runs[run] = {watch.next_zero_copy_id, release, absent_k, 1, 0};
            if (watch.newest_run != absent_k) runs[watch.newest_run].next = run;
            else watch.oldest_run = run;
            watch.newest_run = run;
        }
        ++watch.next_zero_copy_id;
        return static_cast<descriptor_t>(sent);
    }

    /** Lands a release once no send it counts awaits a notification. */
    descriptor_t release_zero_copy(unsigned index) noexcept {
        auto& operation = operations[index];
        if (operation.outstanding_notifications) {
            operation.interest = io_interest_t::landing_k;
            return 0;
        }
        return release_verdict(*operation.request);
    }

    /** What @p release completes with: 1 once its socket copies its sends for good, else 0. */
    descriptor_t release_verdict(io_request_t const& release) const noexcept {
        std::uint32_t const chosen = readiness.find(release.descriptor);
        return chosen != absent_k && readiness.watches[chosen].zero_copy == zero_copy_stage_t::copying_k ? 1 : 0;
    }

    /** Closes a socket, or keeps it while notifications are due, resetting it first when it was set
     *  to reset on close, so the kernel purges and notifies at once. Answers through @p closing,
     *  the operation it lands, or @c absent_k. */
    descriptor_t close_watched(descriptor_t descriptor, unsigned closing) noexcept {
        std::uint32_t const chosen = readiness.find(descriptor);
        if (chosen == absent_k || readiness.watches[chosen].oldest_run == absent_k) {
            readiness.remove(descriptor);
            return socket_close(descriptor) == 0 || errno == EINTR ? 0 : -errno;
        }
        readiness_watch_t& watch = readiness.watches[chosen];
        linger lingering {};
        socklen_t length = sizeof(lingering);
        if (getsockopt(static_cast<int>(descriptor), SOL_SOCKET, SO_LINGER, &lingering, &length) == 0 &&
            lingering.l_onoff && !lingering.l_linger) {
            [[maybe_unused]] ucall_status_t const reset = socket_disconnect_with_reset(descriptor);
        }
        watch.stage = watch_stage_t::closing_k;
        watch.receive_operation = absent_k;
        watch.transmit_operation = closing;
        if (closing != absent_k) operations[closing].interest = io_interest_t::landing_k;
        return 0;
    }
    int close_socket(descriptor_t descriptor) noexcept { return close_watched(descriptor, absent_k); }

    /** Counts the notification IDs @p lowest through @p highest of watch @p chosen against the
     *  releases of its runs, overlaps taken modulo 2^32, landing each release they complete. */
    void notified(std::uint32_t chosen, std::uint32_t lowest, std::uint32_t highest,
                  zero_copy_stage_t reported) noexcept {
        readiness_watch_t& watch = readiness.watches[chosen];
        std::uint32_t const span = highest - lowest + 1;
        if (reported == zero_copy_stage_t::copying_k) {
            watch.zero_copy = zero_copy_stage_t::copying_k;
            tally<atomic_ref_template_>(statistics.zero_copy_fallbacks, span);
        }
        for (unsigned previous = absent_k, current = watch.oldest_run; current != absent_k;) {
            zero_copy_run_t& run = runs[current];
            unsigned const next = run.next;
            std::uint32_t const into_run = lowest - run.first_id, into_span = run.first_id - lowest;
            std::uint32_t overlap = 0;
            if (into_run < run.sends) overlap = std::min<std::uint32_t>(run.sends - into_run, span);
            else if (into_span < span) overlap = std::min<std::uint32_t>(span - into_span, run.sends);
            if (overlap) {
                run.notified = static_cast<std::uint16_t>(run.notified + overlap);
                auto& release = operations[run.release_operation];
                release.outstanding_notifications -= overlap;
                if (!release.outstanding_notifications && release.interest == io_interest_t::landing_k)
                    land(run.release_operation, release_verdict(*release.request));
            }
            if (run.notified == run.sends) {
                if (previous != absent_k) runs[previous].next = next;
                else watch.oldest_run = next;
                if (watch.newest_run == current) watch.newest_run = previous;
                run.next = free_runs;
                free_runs = current;
            }
            else previous = current;
            current = next;
        }
    }

    /** Reads the error queue of watch @p chosen dry, closing it once a closing watch is done. */
    void drain_error_queue(std::uint32_t chosen) noexcept {
        int const descriptor = readiness.watches[chosen].descriptor;
        for (;;) {
            alignas(cmsghdr) byte_t control[CMSG_SPACE(sizeof(sock_extended_err) + sizeof(sockaddr_in6))];
            msghdr message {};
            message.msg_control = control;
            message.msg_controllen = sizeof(control);
            tally<atomic_ref_template_>(statistics.kernel_enters);
            if (recvmsg(descriptor, &message, MSG_ERRQUEUE) < 0) break;
            for (cmsghdr* header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header)) {
                if (!((header->cmsg_level == SOL_IP && header->cmsg_type == IP_RECVERR) ||
                      (header->cmsg_level == SOL_IPV6 && header->cmsg_type == IPV6_RECVERR)))
                    continue;
                sock_extended_err error {};
                std::memcpy(&error, CMSG_DATA(header), sizeof(error));
                if (error.ee_errno || error.ee_origin != SO_EE_ORIGIN_ZEROCOPY) continue;
                notified(chosen, error.ee_info, error.ee_data,
                         error.ee_code & SO_EE_CODE_ZEROCOPY_COPIED ? zero_copy_stage_t::copying_k
                                                                    : zero_copy_stage_t::enabled_k);
            }
        }
        readiness_watch_t const& watch = readiness.watches[chosen];
        if (watch.stage != watch_stage_t::closing_k || watch.oldest_run != absent_k) return;
        unsigned const closing = watch.transmit_operation;
        readiness.remove(descriptor);
        descriptor_t const closed = socket_close(descriptor) == 0 || errno == EINTR ? 0 : -errno;
        if (closing != absent_k) land(closing, closed);
    }

    /** Hands landed AIO reads on, then starts the reads that waited for their events. */
    void drain_files() noexcept {
        files.drain([&](unsigned index, descriptor_t result) noexcept { land(index, result); });
        while (files.in_flight != files.depth) {
            unsigned const index = waiting_files.pop(operations);
            if (index == absent_k) break;
            operations[index].interest = io_interest_t::unarmed_k;
            fresh_operations.push(operations, index);
        }
    }

    descriptor_t attempt(unsigned index) noexcept {
        auto& operation = operations[index];
        auto& request = *operation.request;
        switch (request.operation) {
        case io_operation_t::file_read_k:
        case io_operation_t::file_read_vectors_k: return read_file(index);
        case io_operation_t::send_zero_copy_k: return send_zero_copy(index);
        case io_operation_t::zero_copy_release_k: return release_zero_copy(index);
        case io_operation_t::close_k: return close_watched(request.descriptor, index);
        case io_operation_t::send_k: tally<atomic_ref_template_>(statistics.copying_sends); [[fallthrough]];
        default: return attempt_io<atomic_ref_template_>(request, operation.stage, operation.interest, statistics);
        }
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
            if (!request.deadline || request.deadline > now || operation.timed == absent_k) {
                do { result = attempt(index); } while (fired && result == -EINTR);
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
    int wait(int timeout) noexcept {
        tally<atomic_ref_template_>(statistics.kernel_enters);
        return readiness.wait(
            timeout,
            [&](unsigned index, descriptor_t descriptor, short events) noexcept {
                auto& operation = operations[index];
                if (operation.interest == io_interest_t::armed_k && operation.request->descriptor == descriptor &&
                    (events & io_events(operation.request->operation)))
                    wake(index);
            },
            [&](std::uint32_t chosen) noexcept { drain_error_queue(chosen); }, [&]() noexcept { drain_files(); });
    }
    int poll(span<io_completion_t> completions, io_wait_t wait_policy, std::uint64_t deadline = 0) noexcept {
        if (!completions.size()) return 0;
        std::size_t count {};
        for (unsigned round = 0; round != 2; ++round) {
            auto now = monotonic_ns();
            auto wait_for = wait_policy == io_wait_t::blocking_k ? std::numeric_limits<std::uint64_t>::max() : 0;
            if (deadline) wait_for = std::min(wait_for, deadline > now ? deadline - now : 0);
            for (auto index : timed) {
                auto expiry = operations[index].request->deadline;
                if (expiry > now) wait_for = std::min(wait_for, expiry - now);
                else if (operations[index].interest == io_interest_t::armed_k) wake(index);
            }
            count = collect(completions, count);
            count = progress(fresh_operations, completions, count, now);
            count = progress(ready_operations, completions, count, now);
            if (count || round || !active) break;
            int timeout = wait_for == std::numeric_limits<std::uint64_t>::max()
                              ? -1
                              : static_cast<int>(
                                    std::min<std::uint64_t>(wait_for / 1'000'000 + (wait_for % 1'000'000 != 0),
                                                            std::numeric_limits<int>::max()));
            int result = wait(timeout);
            if (result < 0 && result != -EINTR) return result;
        }
        return static_cast<int>(count);
    }

    /** Waits for every AIO read, then resets each socket the kernel still sends zero-copy bytes
     *  from and waits for its notifications, so no buffer stays in the kernel's hands. */
    void stop() noexcept {
        files.close();
        for (auto const& watch : readiness.watches.records())
            if (watch.oldest_run != absent_k) {
                [[maybe_unused]] ucall_status_t const reset = socket_disconnect_with_reset(watch.descriptor);
            }
        for (;;) {
            std::uint32_t due = absent_k;
            for (std::uint32_t i = 0; i != readiness.watches.capacity() && due == absent_k; ++i)
                if (readiness.watches[i].oldest_run != absent_k) due = i;
            if (due == absent_k) break;
            drain_error_queue(due);
            if (readiness.watches[due].oldest_run == absent_k) continue;
            pollfd polled {readiness.watches[due].descriptor, 0, 0};
            ::poll(&polled, 1, -1);
        }
        for (auto& watch : readiness.watches.records())
            if (watch.stage == watch_stage_t::closing_k) {
                int const descriptor = watch.descriptor;
                readiness.remove(descriptor);
                socket_close(descriptor);
            }
        free_operations = fresh_operations = ready_operations = landed_operations = waiting_files = {};
        timed.clear();
        active = 0;
        refusal = nullptr;
        for (unsigned i = 0; i != operations.size(); ++i) {
            operations[i] = {};
            free_operations.push(operations, i);
        }
        free_runs = absent_k;
        for (unsigned i = static_cast<unsigned>(runs.size()); i--;) {
            runs[i] = {};
            runs[i].next = free_runs;
            free_runs = i;
        }
        releases.clear();
    }
};
using linux_epollaio_engine_t = linux_epollaio_engine<>;

} // namespace unum::ucall::io

#endif // UCALL_OS_LINUX_
