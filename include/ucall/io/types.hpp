/**
 *  @file include/ucall/io/types.hpp
 *  @author Ash Vardanian
 *  @date January 13, 2025
 *  @brief Requests, completions, statistics and wakeups every I/O queue shares.
 */
#pragma once

#include <cassert> // `assert`
#include <cerrno>
#include <climits> // `CHAR_BIT`

#include <atomic>   // `std::memory_order_relaxed`
#include <concepts> // `std::convertible_to`, `std::same_as`
#include <limits>   // `std::numeric_limits`
#include <variant>  // `std::variant`, `std::visit`

#include <smashtable/intrusive_list.hpp> // `intrusive_list`

#include "ucall/utilities/sockets.hpp" // `socket_close`, `socket_open`, `nonblocking`, `socket_option`
#include "ucall/utilities/types.hpp"   // `descriptor_t`, `byte_t`, `span`

namespace unum::ucall::io {

using utilities::absent_k;
using utilities::accepted_socket;
using utilities::byte_t;
using utilities::descriptor_t;
using utilities::invalid_native_file_k;
using utilities::io_vector_t;
using utilities::monotonic_ns;
using utilities::native_file_t;
using utilities::nonblocking;
using utilities::open_native_file_beneath;
using utilities::socket_close;
using utilities::socket_length_t;
using utilities::socket_open;
using utilities::socket_option;
using utilities::span;

enum class io_wait_t {

    /** Waits for a completion, the deadline or a wakeup when none is ready. */
    blocking_k,

    /** Answers what already completed and returns at once. */
    nonblocking_k,
};

/** How a socket's close ends its stream: a FIN after what it sent, or a reset that purges what the
 *  kernel still holds, as a connection whose reply broke off past its head needs. */
enum class close_mode_t : std::uint8_t {

    /** Ends the stream with a FIN after the bytes it sent. */
    orderly_k,

    /** Ends the stream with a reset, purging what the kernel still holds. */
    reset_k,
};

/** Whether a record is linked on a list that steps or reaps it, such as a ready queue. */
enum class listing_t : std::uint8_t {

    /** On no list of that kind. */
    unlisted_k,

    /** Linked on the list the member names. */
    listed_k,
};

/** Which threads may enter a queue: the first one for good, or one at a time in any order, so
 *  a runtime's collector may free what another thread polled. */
enum class io_issuer_scope_t : std::uint8_t {

    /** The first thread to enter stays the only one. */
    one_thread_k,

    /** Any thread may enter, one at a time. */
    any_thread_k,
};

/** Where a server's listeners come from: created through its queues, or handed over by the caller
 *  as some are. */
enum class io_listeners_t : std::uint8_t {

    /** Every listener is created through the server's queues. */
    created_k,

    /** Some listeners are sockets the caller created and owns. */
    caller_k,
};

/** What a request asks of its socket or of a file; file operations keep @c descriptor as the
 *  socket they serve, so its close waits for them, and their offsets, lengths and buffers meet the
 *  file's @c direct_alignment_of. */
enum class io_operation_t : std::uint8_t {

    /** Accepts up to @c length connections on a listening socket, at least one, completing once
     *  per connection with the descriptor it opened and the peer's address written into the
     *  @c io_peer_address_t at @c data when that names an array of them, which a completion's own
     *  @c data names where it differs. Each connection takes one from @c length, and the request
     *  stays pending while some is left: a readiness queue takes as many as are queued, and a
     *  port or a ring arms one accept per socket for as many as it admits at once. A ring names a
     *  peer it keeps until the socket closes, and a connection its accepts already took past the
     *  last of @c length still completes before the request ends. Both are read at each attempt,
     *  so a submitter may renew them. */
    accept_k,

    /** Connects to the address of @c length bytes in @c data. */
    connect_k,

    /** Receives into the vector @c data names, read at each attempt so its owner may move it, or
     *  into queue memory where the queue's @c receive_memory_k says so. */
    receive_k,

    /** Sends @c data by copying. */
    send_k,

    /** Completes once the socket took bytes of @c data, and names the @c release_request whose
     *  @c zero_copy_release_k completes once the kernel let go of them; the submitter submits the
     *  release after the last send naming it completed. */
    send_zero_copy_k,

    /** Reads into @c data, never into queue memory, for a wakeup or a datagram that must stay
     *  whole. */
    read_k,

    /** Shuts the sending direction of the socket down. */
    shutdown_k,

    /** Closes the socket. */
    close_k,

    /** Opens the NUL-terminated path in @c data beneath the directory @c file.handle for unbuffered
     *  reads, completing with a descriptor the submitter owns even after a cancel. */
    file_open_k,

    /** Reads @c length bytes of @c file.handle at @c file.offset into @c data. */
    file_read_k,

    /** Scatters the bytes @c file_read_k would read into the @c length vectors in @c data. */
    file_read_vectors_k,

    /** Completes with 0 while the socket still pins its sends, and with 1 once the socket sends by
     *  copying for its lifetime, as the kernel reported a send it counts copied or the queue never
     *  pins its sends at all. */
    zero_copy_release_k,
};

/** Where a queue lands a receive: the submitter's vector, or memory of its own that it owns. */
enum class io_receive_memory_t : std::uint8_t {

    /** Into the vector the request's @c data names. */
    submitter_k,

    /** Into the queue's own buffers; the completion's bytes stay valid until the caller passes them
     *  to @c release. */
    queue_k,
};

/** The queue buffer index a request's memory lies in, scoped so no descriptor binds to it. */
enum class registered_memory_t : std::uint16_t {};

/** The @c registered_memory of a request whose buffer lies in no queue-registered range. */
inline constexpr registered_memory_t io_unregistered_k {(std::numeric_limits<std::uint16_t>::max)()};

/** The file a read reads, or the directory a @c file_open_k opens beneath, owned by the
 *  submitter until the request completes. */
struct io_file_t {

    /** Where in the file a read starts; an open ignores it. */
    std::uint64_t offset {};

    /** The file a read reads, or the directory an open resolves its path beneath. */
    native_file_t handle {invalid_native_file_k};
};
static_assert(sizeof(io_file_t) == 16);

/** Where an accept writes its peer's address, kept by the submitter with the request. */
struct io_peer_address_t {

    /** The peer's address, once the accept's connection completed. */
    sockaddr_storage address {};

    /** Bytes of @c address the accept wrote. */
    socket_length_t length {};
};

/** The submitter keeps this request, its buffers and the requests it names alive until its
 *  completion is polled. */
struct io_request_t {

    /** What the queue does; it stays as set after the completion, so the submitter may read it. */
    io_operation_t operation {io_operation_t::receive_k};

    /** The registered range @c data lies in, as sends and file reads may name, or unregistered. */
    registered_memory_t registered_memory {io_unregistered_k};

    /** The queue record carrying this request while it is submitted, which the queue sets, so a
     *  cancel or a release finds it without a search; @c absent_k otherwise. */
    std::uint32_t operation_index {absent_k};

    /** The socket, the listener of an accept, or for a file operation the socket it serves; a
     *  successful close sets it to -1. */
    descriptor_t descriptor {-1};

    /** Bytes of a send or a read, the vectors of a receive, the address of a connect, the peer
     *  addresses of an accept, which the queue walks, or the path of a file open. */
    byte_t* data {};

    /** Bytes, vectors or address bytes of @c data; the connections an accept still takes, which the
     *  queue counts down. */
    std::size_t length {};

    /** The monotonic nanosecond the operation times out at, or zero for none. */
    std::uint64_t deadline {};

    /** The submitter's own; queues never read it. */
    void* context {};
    union {

        /** What a file operation reads or opens beneath. */
        io_file_t file {};

        /** The release a @c send_zero_copy_k names. */
        io_request_t* release_request;
    };
};
static_assert(sizeof(io_request_t) == 64);

/** Whether a queue holds a registered range pinned, sparing each request in it the pinning. */
enum class range_pinning_t : std::uint8_t {
    pinned_k,   // Registered at `index`; requests pass it as `registered_memory`.
    unpinned_k, // Refused, by the locked-memory cap or a full table; requests pass `io_unregistered_k`.
};

/** What @c register_memory made of a range. */
struct memory_registration_t {

    /** What requests in the range pass as @c registered_memory once pinned, or unregistered. */
    registered_memory_t index {io_unregistered_k};

    /** Success for a pinned range or a soft refusal, else why the queue failed the range. */
    ucall_status_t status {ucall_status_success_k};

    /** Whether the queue holds the range pinned, as a range with an index is. */
    range_pinning_t pinning() const noexcept {
        return index == io_unregistered_k ? range_pinning_t::unpinned_k : range_pinning_t::pinned_k;
    }
};
static_assert(sizeof(memory_registration_t) == 8);

/** The readiness an operation waits for; a socket keeps at most one pending operation per
 *  direction, and file operations wait on no socket at all. */
enum class io_direction_t : std::uint8_t {

    /** Readable, for every operation but connects, sends and shutdowns. */
    receive_k,

    /** Writable, for connects, sends and shutdowns. */
    transmit_k,
};
inline io_direction_t io_direction(io_operation_t operation) noexcept {
    return operation == io_operation_t::connect_k || operation == io_operation_t::send_k ||
                   operation == io_operation_t::send_zero_copy_k || operation == io_operation_t::shutdown_k
               ? io_direction_t::transmit_k
               : io_direction_t::receive_k;
}

/** Whether the request a completion answers stays submitted, as an accept taking more does. */
enum class io_continuation_t : std::uint8_t {

    /** The request ended with this completion and is the submitter's again. */
    ended_k,

    /** The request stays submitted, as an accept taking more connections does. */
    pending_k,
};

/** A byte count, accepted descriptor, or negated errno for one submitted request, or for one
 *  connection of an accept that takes several. */
struct io_completion_t {

    /** The request this answers. */
    io_request_t* request {};

    /** Bytes moved, an accepted or opened descriptor, a release's verdict, or a negated errno. */
    descriptor_t result {};

    /** The peer address an accept wrote, or the slice a receive into queue memory filled. */
    byte_t* data {};

    /** What @c release takes back for a receive into queue memory; zero when the completion holds
     *  no queue buffer. */
    std::uint32_t release_token {};

    /** Whether the request stays submitted, read here as an accept's @c length keeps moving while
     *  later ones land. */
    io_continuation_t continuation {io_continuation_t::ended_k};
};
static_assert(sizeof(io_completion_t) == 32);

/** Counters a queue advances for its one polling owner, on lines no other thread writes. Every
 *  queue counts a request at its submit and an answer when the submitter collects it, and every
 *  send that left in exactly one of @c zero_copy_sends and @c copying_sends. */
struct alignas(fu::default_alignment_k) io_statistics_t {

    /** Requests the queue took. */
    std::uint64_t submissions {};

    /** Completions the submitter collected, an accept's every connection among them. */
    std::uint64_t completions {};

    /** Submission entries io_uring filled and completion entries it reaped; zero elsewhere. */
    std::uint64_t kernel_entries {};

    /** System calls: ring enters, waits, registrations and the socket and file calls themselves. */
    std::uint64_t kernel_enters {};

    /** Cancels asked of pending operations, and on io_uring 6.18 of receive streams. */
    std::uint64_t cancellations {};

    /** Receive streams armed again on a socket that already streamed, only on io_uring 6.18. */
    std::uint64_t receive_rearms {};

    /** Bytes io_uring 6.18 copied into socket backlogs or slid within them. */
    std::uint64_t bytes_copied {};

    /** Sends that left without a copy: @c MSG_ZEROCOPY, @c SEND_ZC, or a registered RIO range. */
    std::uint64_t zero_copy_sends {};

    /** Zero-copy sends the kernel reported copied, refused to pin, or ran out of buffers for. */
    std::uint64_t zero_copy_fallbacks {};

    /** Sends that copied on epoll, io_uring and Registered I/O, demoted zero-copy ones included. */
    std::uint64_t copying_sends {};

    /** File reads the kernel finishes later: io_uring, Linux or FreeBSD AIO, or overlapped I/O. */
    std::uint64_t file_reads_asynchronous {};

    /** File reads the queue issued itself and blocked on: posix, macOS, or a full AIO queue. */
    std::uint64_t file_reads_blocking {};
};

/** Advances a counter only its owner writes, through @p atomic_ref_template_, so other threads may
 *  load it relaxed. */
template <template <typename> class atomic_ref_template_>
inline void tally(std::uint64_t& counter, std::uint64_t amount = 1) noexcept {
    atomic_ref_template_<std::uint64_t> word {counter};
    word.store(word.load(std::memory_order_relaxed) + amount, std::memory_order_relaxed);
}

/** A pollable wakeup with the same request lifetime as socket operations. */
struct pollable_wakeup_t {
    pollable_wakeup_t() noexcept = default;
    pollable_wakeup_t(pollable_wakeup_t const&) = delete;
    pollable_wakeup_t& operator=(pollable_wakeup_t const&) = delete;
    pollable_wakeup_t(pollable_wakeup_t&&) = delete;
    pollable_wakeup_t& operator=(pollable_wakeup_t&&) = delete;

    /** The read end, -1 once a queue imported it, and the write end @c notify sends on. */
    descriptor_t descriptors[2] {-1, -1};

    /** Where the read request lands notifications, and where @c wait drains them. */
    byte_t bytes[sizeof(std::uint64_t)] {};

    /** The read of the read end, or of the queue's handle for it once imported, resubmitted after
     *  each completion. */
    io_request_t request {};
#if UCALL_OS_APPLE_

    /** A kqueue watching the read end, as Darwin's @c poll waits in whole milliseconds. */
    int queue {-1};
#elif UCALL_OS_WINDOWS_

    /** An event the read end signals, as @c WSAPoll waits in whole scheduler ticks. */
    HANDLE readable {};

    /** A high-resolution timer that ends a @c wait at its deadline. */
    HANDLE timer {};
#endif // UCALL_OS_APPLE_
    ~pollable_wakeup_t() noexcept {
        for (auto descriptor : descriptors)
            if (descriptor >= 0) socket_close(descriptor);
#if UCALL_OS_APPLE_
        if (queue >= 0) ::close(queue);
#elif UCALL_OS_WINDOWS_
        if (readable) CloseHandle(readable);
        if (timer) CloseHandle(timer);
#endif // UCALL_OS_APPLE_
    }
    [[nodiscard]] ucall_status_t open() noexcept {
#if UCALL_OS_WINDOWS_
        auto listener = socket_open(AF_INET);
        if (listener < 0) return ucall_status_io_k;
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bool ready = bind(static_cast<SOCKET>(listener), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 &&
                     listen(static_cast<SOCKET>(listener), 1) == 0;
        int length = sizeof(address);
        ready = ready &&
                getsockname(static_cast<SOCKET>(listener), reinterpret_cast<sockaddr*>(&address), &length) == 0;
        if (ready) {
            descriptors[1] = static_cast<descriptor_t>(
                WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED));
            ready = descriptors[1] >= 0 && connect(static_cast<SOCKET>(descriptors[1]),
                                                   reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
        }
        if (ready) descriptors[0] = static_cast<descriptor_t>(accept(static_cast<SOCKET>(listener), nullptr, nullptr));
        socket_close(listener);
        if (!ready || descriptors[0] < 0) return ucall_status_io_k;
#else
        int sockets[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return ucall_status_io_k;
        descriptors[0] = sockets[0];
        descriptors[1] = sockets[1];
#endif // UCALL_OS_WINDOWS_
#if UCALL_OS_APPLE_
        struct kevent change {};
        EV_SET(&change, descriptors[0], EVFILT_READ, EV_ADD, 0, 0, nullptr);
        queue = kqueue();
        if (queue < 0 || kevent(queue, &change, 1, nullptr, 0, nullptr) != 0) return ucall_status_io_k;
#endif // UCALL_OS_APPLE_
        if (nonblocking(descriptors[0]) != ucall_status_success_k ||
            nonblocking(descriptors[1]) != ucall_status_success_k)
            return ucall_status_io_k;
#if UCALL_OS_WINDOWS_
        readable = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        timer = CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
        if (!readable || !timer || WSAEventSelect(static_cast<SOCKET>(descriptors[0]), readable, FD_READ) != 0)
            return ucall_status_io_k;
#endif // UCALL_OS_WINDOWS_
        request = {.operation = io_operation_t::read_k,
                   .descriptor = descriptors[0],
                   .data = bytes,
                   .length = sizeof(bytes)};
        return ucall_status_success_k;
    }
    void notify() noexcept {
        char value = 1;
#if UCALL_OS_WINDOWS_
        while (send(static_cast<SOCKET>(descriptors[1]), &value, 1, 0) == SOCKET_ERROR &&
               WSAGetLastError() == WSAEINTR) {}
#else
        while (send(static_cast<int>(descriptors[1]), &value, 1, MSG_NOSIGNAL) < 0 && errno == EINTR) {}
#endif // UCALL_OS_WINDOWS_
    }

    /** Blocks until a notification or the monotonic @p deadline, zero meaning none, then empties a
     *  channel whose read end no queue imported. */
    void wait(std::uint64_t deadline) noexcept {
        std::uint64_t const now = monotonic_ns();
        std::uint64_t const remaining = !deadline        ? (std::numeric_limits<std::uint64_t>::max)()
                                        : deadline > now ? deadline - now
                                                         : 0;
#if UCALL_OS_WINDOWS_
        // Relative, in 100 ns ticks rounded up, so the wait never ends early.
        LARGE_INTEGER due {};
        due.QuadPart = -static_cast<LONGLONG>(remaining / 100 + (remaining % 100 != 0));
        HANDLE const handles[] {readable, timer};
        if (!deadline || SetWaitableTimer(timer, &due, 0, nullptr, nullptr, FALSE))
            WaitForMultipleObjects(deadline ? 2 : 1, handles, FALSE, INFINITE);
        while (recv(static_cast<SOCKET>(descriptors[0]), reinterpret_cast<char*>(bytes), sizeof(bytes), 0) > 0) {}
#elif UCALL_OS_APPLE_
        timespec const timeout {static_cast<time_t>(remaining / 1'000'000'000),
                                static_cast<long>(remaining % 1'000'000'000)};
        struct kevent event {};
        kevent(queue, nullptr, 0, &event, 1, deadline ? &timeout : nullptr);
        while (recv(static_cast<int>(descriptors[0]), bytes, sizeof(bytes), 0) > 0) {}
#else
        pollfd polled {static_cast<int>(descriptors[0]), POLLIN, 0};
        utilities::socket_poll(&polled, 1, remaining);
        while (recv(static_cast<int>(descriptors[0]), bytes, sizeof(bytes), 0) > 0) {}
#endif // UCALL_OS_WINDOWS_
    }
};

/** A socket a queue registered in a table of its own, named by its index under a high bit that
 *  separates it from process descriptors and socket handles. */
struct registered_socket_t {

    /** The queue's table index the handle holds. */
    unsigned index {};
    static constexpr descriptor_t tag_k = descriptor_t {1} << (sizeof(descriptor_t) * CHAR_BIT - 2);
    descriptor_t handle() const noexcept { return tag_k | static_cast<descriptor_t>(index); }
    static bool contains(descriptor_t handle) noexcept { return handle >= tag_k; }
    static unsigned index_of(descriptor_t handle) noexcept { return static_cast<unsigned>(handle & ~tag_k); }
};

/** An intrusive FIFO of queue operations, linked through their @c next indices. */
using operation_list_t = st::intrusive_list<unsigned>;
static_assert(operation_list_t::absent_k == absent_k);

/** The vectors a @c file_read_vectors_k or @c receive_k request fills, named by its @c data. */
inline span<io_vector_t> io_vectors(io_request_t const& request) noexcept {
    return {reinterpret_cast<io_vector_t*>(request.data), request.length};
}

/** Whether a polled operation is untouched, has started connecting, or was cancelled. */
enum class operation_stage_t : std::uint8_t {

    /** Never attempted. */
    fresh_k,

    /** A connect already issued, whose outcome the next attempt reads. */
    started_k,

    /** Cancelled, completing with @c -ECANCELED at its next attempt or collection. */
    cancelled_k,
};

#if UCALL_OS_POSIX_
inline short io_events(io_operation_t operation) noexcept {
    return io_direction(operation) == io_direction_t::transmit_k ? POLLOUT : POLLIN;
}

/** Where an operation waits: nowhere yet, on its socket's readiness, retrying once that fired, in
 *  a kernel queue that completes it without readiness, or on the queue's list for a place. */
enum class io_interest_t : std::uint8_t {

    /** Waiting on nothing yet. */
    unarmed_k,

    /** Waiting for its socket's readiness in its direction. */
    armed_k,

    /** Woken by readiness, a cancel or a deadline, so the next progress pass retries it. */
    ready_k,

    /** Handed to a kernel queue or held back by the queue, which lands its result. */
    landing_k,

    /** On the queue's list until a kernel queue has room, then attempted again. */
    queued_k,
};

/** Performs the request's syscall, blocking for file work and copying for zero-copy sends, and
 *  probes a pending connect only once @p interest reports readiness. */
template <template <typename> class atomic_ref_template_>
inline descriptor_t attempt_io(io_request_t& request, operation_stage_t& stage, io_interest_t interest,
                               io_statistics_t& statistics) noexcept {
    if (stage == operation_stage_t::cancelled_k) return -ECANCELED;
    if (request.operation == io_operation_t::connect_k && stage != operation_stage_t::fresh_k &&
        interest != io_interest_t::ready_k)
        return -EAGAIN;
    tally<atomic_ref_template_>(statistics.kernel_enters);
    auto descriptor = static_cast<int>(request.descriptor);
    ssize_t result = -1;
    auto length = fu::min_of<std::size_t>(request.length, (std::numeric_limits<int>::max)());
    switch (request.operation) {
    case io_operation_t::accept_k: {
        io_peer_address_t unnamed {};
        auto& peer = request.data ? *reinterpret_cast<io_peer_address_t*>(request.data) : unnamed;
        peer.length = sizeof(peer.address);
        return accepted_socket(accept(descriptor, reinterpret_cast<sockaddr*>(&peer.address), &peer.length),
                               peer.address.ss_family);
    }
    case io_operation_t::connect_k:
        if (stage == operation_stage_t::fresh_k) {
            stage = operation_stage_t::started_k;
            if (connect(descriptor, reinterpret_cast<sockaddr*>(request.data),
                        static_cast<socklen_t>(request.length)) == 0)
                return 0;
            return -errno;
        }
        {
            int error {};
            socklen_t size = sizeof(error);
            return getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &size) == 0 ? -error : -errno;
        }
    case io_operation_t::receive_k: {
        io_vector_t const& room = io_vectors(request).front();
        result = recv(descriptor, room.iov_base,
                      fu::min_of<std::size_t>(room.iov_len, (std::numeric_limits<int>::max)()), 0);
        break;
    }
    case io_operation_t::send_k:
    case io_operation_t::send_zero_copy_k: result = send(descriptor, request.data, length, MSG_NOSIGNAL); break;
    case io_operation_t::read_k: result = read(descriptor, request.data, length); break;
    case io_operation_t::shutdown_k: return ::shutdown(descriptor, SHUT_WR) == 0 ? 0 : -errno;
    case io_operation_t::close_k: return socket_close(request.descriptor) == 0 || errno == EINTR ? 0 : -errno;
    case io_operation_t::file_open_k:
        return open_native_file_beneath(request.file.handle, reinterpret_cast<char const*>(request.data));
    case io_operation_t::file_read_k:
        tally<atomic_ref_template_>(statistics.file_reads_blocking);
        return utilities::read_native_file(request.file.handle, {request.data, request.length}, request.file.offset);
    case io_operation_t::file_read_vectors_k:
        tally<atomic_ref_template_>(statistics.file_reads_blocking);
        return utilities::read_native_file_vectors(request.file.handle, io_vectors(request), request.file.offset);
    case io_operation_t::zero_copy_release_k: return 1;
    }
    return result >= 0 ? static_cast<descriptor_t>(result) : -errno;
}

inline bool io_pending(descriptor_t result) noexcept {
    return result == -EAGAIN || result == -EWOULDBLOCK || result == -EINPROGRESS || result == -EINTR;
}

/** A readiness queue whose level-triggered set keeps polling what nothing waits on, so it must
 *  hear of each operation's end. */
template <typename queue_type_>
concept a_readiness_disarming_queue = requires(queue_type_& queue, descriptor_t descriptor, unsigned index) {
    queue.readiness.disarm(descriptor, io_direction_t::receive_k, index);
};

/** Marks an armed operation ready, for the next progress pass of a readiness queue. */
template <typename queue_type_>
void readiness_wake(queue_type_& queue, unsigned index) noexcept {
    queue.operations[index].interest = io_interest_t::ready_k;
    queue.ready_operations.push(queue.operations, index);
}

/** Parks a finished operation's result until the next collect of a readiness queue. */
template <typename queue_type_>
void readiness_land(queue_type_& queue, unsigned index, descriptor_t result) noexcept {
    queue.cold_fields(index).result = result;
    queue.completed_operations.push(queue.operations, index);
}

/** Wakes operation @p index of a readiness queue for @p events that @p descriptor reported, unless
 *  the operation stopped waiting on it, or waits in the other direction. */
template <typename queue_type_>
void readiness_fire(queue_type_& queue, unsigned index, descriptor_t descriptor, short events) noexcept {
    auto& operation = queue.operations[index];
    if (operation.interest == io_interest_t::armed_k && operation.request->descriptor == descriptor &&
        (events & io_events(operation.request->operation)))
        readiness_wake(queue, index);
}

/** Closes the sockets of closes a readiness queue took but never attempted, as its stop owes
 *  their submitters. */
template <typename queue_type_>
void readiness_close_unattempted(queue_type_& queue) noexcept {
    for (unsigned index = queue.fresh_operations.oldest; index != operation_list_t::absent_k;
         index = queue.operations[index].next)
        if (queue.operations[index].request->operation == io_operation_t::close_k)
            socket_close(queue.operations[index].request->descriptor);
}

/** Empties a stopped readiness queue's lists and frees every operation record. */
template <typename queue_type_>
void readiness_reset(queue_type_& queue) noexcept {
    queue.free_operations = queue.fresh_operations = queue.ready_operations = queue.completed_operations = {};
    queue.timed.clear();
    queue.taken_operations = 0;
    for (unsigned index = 0; index != queue.operations.size(); ++index) {
        queue.operations[index] = {};
        queue.cold[index] = {};
        queue.free_operations.push(queue.operations, index);
    }
}

/** Returns a readiness queue's operation to its free list, answering its completion; an accept
 *  ends with nothing left of its @c length. */
template <template <typename> class atomic_ref_template_, typename queue_type_>
io_completion_t readiness_finish(queue_type_& queue, unsigned index, descriptor_t result) noexcept {
    auto& operation = queue.operations[index];
    auto& request = *operation.request;
    typename queue_type_::operation_cold_t& cold = queue.cold_fields(index);
    if (cold.timed != absent_k) {
        queue.timed[cold.timed] = queue.timed.back();
        queue.cold_fields(queue.timed.back()).timed = cold.timed;
        queue.timed.pop_back();
    }
    // Only a level-triggered set keeps polling what nothing waits on, so only it hears of the end.
    if constexpr (a_readiness_disarming_queue<queue_type_>)
        if (operation.interest == io_interest_t::armed_k || operation.interest == io_interest_t::ready_k)
            queue.readiness.disarm(request.descriptor, io_direction(request.operation), index);
    if (request.operation == io_operation_t::accept_k) request.length = 0;
    request.operation_index = absent_k;
    operation = {};
    cold = {};
    queue.free_list(index).push(queue.operations, index);
    --queue.taken_operations;
    tally<atomic_ref_template_>(queue.statistics.completions);
    if (request.operation == io_operation_t::send_k && result >= 0)
        tally<atomic_ref_template_>(queue.statistics.copying_sends);
    return {&request, result};
}

/** Answers one connection an accept took while its request stays pending, naming the peer address
 *  it wrote, the next of which goes past it. */
template <template <typename> class atomic_ref_template_, typename queue_type_>
io_completion_t readiness_yield(queue_type_& queue, io_request_t& request, descriptor_t accepted) noexcept {
    byte_t* const peer = request.data;
    if (peer) request.data = peer + sizeof(io_peer_address_t);
    --request.length;
    tally<atomic_ref_template_>(queue.statistics.completions);
    return {&request, accepted, peer, 0, io_continuation_t::pending_k};
}

/** Answers the landed operations of a readiness queue into @p completions from @p count on. */
template <template <typename> class atomic_ref_template_, typename queue_type_>
std::size_t readiness_collect(queue_type_& queue, span<io_completion_t> completions, std::size_t count) noexcept {
    while (count != completions.size()) {
        auto index = queue.completed_operations.pop(queue.operations);
        if (index == absent_k) break;
        descriptor_t const result = queue.operations[index].stage == operation_stage_t::cancelled_k
                                        ? -ECANCELED
                                        : queue.cold_fields(index).result;
        completions[count++] = readiness_finish<atomic_ref_template_>(queue, index, result);
    }
    return count;
}

/** Attempts each operation on @p list, arming those the socket is not ready for, answering the rest
 *  into @p completions from @p count on; an accept takes connections while its @c length lasts. */
template <template <typename> class atomic_ref_template_, typename queue_type_>
std::size_t readiness_progress(queue_type_& queue, operation_list_t& list, span<io_completion_t> completions,
                               std::size_t count, std::uint64_t now) noexcept {
    while (count != completions.size()) {
        unsigned const index = list.pop(queue.operations);
        if (index == absent_k) break;
        auto& operation = queue.operations[index];
        io_request_t& request = *operation.request;
        bool const fired = operation.interest == io_interest_t::ready_k;
        descriptor_t result = -ETIMEDOUT;
        // An edge-triggered operation hears nothing more until its syscall reports EAGAIN.
        if (queue.cold_fields(index).timed == absent_k || request.deadline > now) {
            do result = queue.attempt(index);
            while (fired && result == -EINTR);
        }
        if (operation.interest == io_interest_t::landing_k || operation.interest == io_interest_t::queued_k) continue;
        while (request.operation == io_operation_t::accept_k && result >= 0 && request.length > 1 &&
               count + 1 != completions.size()) {
            completions[count++] = readiness_yield<atomic_ref_template_>(queue, request, result);
            do result = queue.attempt(index);
            while (result == -EINTR);
        }
        if (io_pending(result) && !fired) {
            io_direction_t const direction = io_direction(request.operation);
            if (int const armed = queue.readiness.arm(request.descriptor, direction, index, queue.statistics);
                armed < 0)
                result = armed;
        }
        if (io_pending(result)) operation.interest = io_interest_t::armed_k;
        else completions[count++] = readiness_finish<atomic_ref_template_>(queue, index, result);
    }
    return count;
}

/** Collects, progresses and, finding nothing, waits once through the queue's @c wait, which takes
 *  nanoseconds, the maximum meaning forever, until @p deadline or the earliest operation's. */
template <template <typename> class atomic_ref_template_, typename queue_type_>
int readiness_poll(queue_type_& queue, span<io_completion_t> completions, io_wait_t wait_policy,
                   std::uint64_t deadline) noexcept {
    if (queue.fault) return queue.fault;
    if (!completions.size()) return 0;
    std::size_t count {};
    for (unsigned round = 0; round != 2; ++round) {
        std::uint64_t const now = monotonic_ns();
        std::uint64_t wait = wait_policy == io_wait_t::blocking_k ? (std::numeric_limits<std::uint64_t>::max)() : 0;
        if (deadline) wait = fu::min_of(wait, deadline > now ? deadline - now : 0);
        for (unsigned index : queue.timed) {
            std::uint64_t const expiry = queue.operations[index].request->deadline;
            if (expiry > now) wait = fu::min_of(wait, expiry - now);
            else if (queue.operations[index].interest == io_interest_t::armed_k) readiness_wake(queue, index);
        }
        count = readiness_collect<atomic_ref_template_>(queue, completions, count);
        count = readiness_progress<atomic_ref_template_>(queue, queue.fresh_operations, completions, count, now);
        count = readiness_progress<atomic_ref_template_>(queue, queue.ready_operations, completions, count, now);
        if (count || round || !queue.taken_operations) break;
        int const result = queue.wait(wait);
        // A signal, or poll(2) short of kernel memory, ends the wait with nothing landed.
        if (result < 0 && result != -EINTR && result != -EAGAIN && result != -ENOMEM) return result;
    }
    return static_cast<int>(count);
}

#endif // UCALL_OS_POSIX_

/** Whether a socket's sends still try zero-copy, which ends once the kernel reports it copied. */
enum class zero_copy_stage_t : std::uint8_t {

    /** No zero-copy send tried yet, or not yet reported copied. */
    untried_k,

    /** The socket took @c SO_ZEROCOPY, so its sends pin their bytes. */
    enabled_k,

    /** Sends copy for the socket's lifetime. */
    copying_k,
};

/** A queue that names the host setting its refused setup needs raised. */
template <typename queue_type_>
concept a_refusal_naming_queue = requires(queue_type_ const& queue) {
    { queue.refusal } -> std::convertible_to<char const*>;
};

/** A queue that grows its capacity in place, keeping the setup it proved. */
template <typename queue_type_>
concept an_in_place_growing_queue = requires(queue_type_& queue, std::size_t capacity) {
    { queue.grow(capacity) } -> std::same_as<ucall_status_t>;
};

/** A queue that keeps the records sends' releases name apart from the rest. */
template <typename queue_type_>
concept a_release_reserving_queue = requires(queue_type_& queue, std::size_t count) { queue.reserve_releases(count); };

/** A queue that prefetches a stream's bytes, and so can pause while nobody pulls them. */
template <typename queue_type_>
concept a_prefetching_queue = requires(queue_type_& queue, descriptor_t descriptor) {
    queue.receive_pause(descriptor);
};

/** A queue whose accepted sockets share flags its listener must be created with. */
template <typename queue_type_>
concept a_listener_creating_queue = requires(queue_type_& queue, int family) {
    { queue.open_listener(family) } -> std::same_as<descriptor_t>;
};

/** A queue that accepts only from listeners it creates, naming why it refuses a caller's. */
template <typename queue_type_>
concept a_caller_listener_refusing_queue = requires {
    { queue_type_::caller_listener_refusal_k } -> std::convertible_to<char const*>;
};

/**
 *  @brief Several queues behind one type: @c open picks one at runtime, and every queue verb
 *      forwards to it through one @c std::visit, a predictable switch per call.
 *
 *  Under @c ucall_io_backend_automatic_k it tries the queues in declaration order, so a ring a
 *  seccomp profile or the locked-memory cap refuses falls to the next. Any other backend opens
 *  exactly its own queue or answers why it could not. A queue that accepts only from listeners it
 *  creates declares @c caller_listener_refusal_k, and a server with a caller-owned listener passes
 *  over it, or is refused where it names it.
 */
template <typename... queue_types_>
class io_queue_variant {
  public:
    using queues_t = std::variant<queue_types_...>;
    using allocator_t = typename std::variant_alternative_t<0, queues_t>::allocator_t;
    template <typename other_allocator_, template <typename> class other_atomic_ref_, typename other_row_kit_>
    using rebind = io_queue_variant<
        typename queue_types_::template rebind<other_allocator_, other_atomic_ref_, other_row_kit_>...>;

    static_assert((std::is_same_v<typename queue_types_::allocator_t, allocator_t> && ...),
                  "Every queue of a set places its records through one allocator");

    explicit io_queue_variant(allocator_t const& allocator = {}) noexcept
        : queues_(std::in_place_index<0>, allocator), allocator_(allocator) {}
    io_queue_variant(io_queue_variant const&) = delete;
    io_queue_variant& operator=(io_queue_variant const&) = delete;
    io_queue_variant(io_queue_variant&&) = delete;
    io_queue_variant& operator=(io_queue_variant&&) = delete;

    /**
     *  @brief Opens the queue of @p backend, or under @c ucall_io_backend_automatic_k the first
     *      one whose setup the host admits, for @p capacity operations.
     *
     *  @par Statuses:
     *  - @c unsupported_k The set has no queue for @p backend, the named one's kernel lacks it, or
     *    it cannot accept from caller-owned @p listeners.
     *  - @c io_k The setup was refused, or under automatic every queue's was, the last one's
     *    status answering for all of them.
     *  - @c out_of_memory_k The setup ran short of memory, which under automatic passes on to the
     *    next queue like a refusal.
     */
    ucall_status_t open(ucall_io_backend_t backend, std::size_t depth, std::size_t capacity,
                        io_issuer_scope_t scope = io_issuer_scope_t::one_thread_k,
                        io_listeners_t listeners = io_listeners_t::created_k) noexcept {
        depth_ = depth, scope_ = scope, listeners_ = listeners;
        return open_<0>(backend, depth, capacity, scope, listeners, ucall_status_unsupported_k);
    }

    /** The backend of the queue @c open picked, or tried last. */
    ucall_io_backend_t backend() const noexcept { return backends_k[queues_.index()]; }

    /** Where the open queue lands receives. */
    io_receive_memory_t receive_memory() const noexcept { return receive_memories_k[queues_.index()]; }

    /** Why the queue refused its setup, naming the host setting to raise, or null. */
    char const* refusal() const noexcept {
        return std::visit(
            [](auto const& queue) noexcept -> char const* {
                if constexpr (a_refusal_naming_queue<decltype(queue)>) return queue.refusal;
                else return nullptr;
            },
            queues_);
    }

    io_statistics_t& statistics() noexcept {
        return std::visit([](auto& queue) noexcept -> io_statistics_t& { return queue.statistics; }, queues_);
    }

    /** Grows the open queue to @p capacity, as only one not yet polled may: a ring in place,
     *  keeping the size and locked memory its setup proved, any other reopened. */
    ucall_status_t grow(std::size_t capacity) noexcept {
        ucall_status_t grown = ucall_status_success_k;
        bool const in_place = std::visit(
            [&](auto& queue) noexcept {
                if constexpr (an_in_place_growing_queue<decltype(queue)>) {
                    grown = queue.grow(capacity);
                    return true;
                }
                else return false;
            },
            queues_);
        return in_place ? grown : open(backend(), depth_, capacity, scope_, listeners_);
    }

    /** Sets aside the last @p count records for the releases sends name, where the queue keeps
     *  them apart. */
    void reserve_releases(std::size_t count) noexcept {
        std::visit(
            [&](auto& queue) noexcept {
                if constexpr (a_release_reserving_queue<decltype(queue)>) queue.reserve_releases(count);
            },
            queues_);
    }

    /** Stops prefetching into @p descriptor's stream while nobody pulls its bytes, where the queue
     *  prefetches at all. */
    void receive_pause(descriptor_t descriptor) noexcept {
        std::visit(
            [&](auto& queue) noexcept {
                if constexpr (a_prefetching_queue<decltype(queue)>) queue.receive_pause(descriptor);
            },
            queues_);
    }

    void submit(io_request_t& request) noexcept {
        std::visit([&](auto& queue) noexcept { queue.submit(request); }, queues_);
    }
    int poll(span<io_completion_t> completions, io_wait_t wait_policy, std::uint64_t deadline = 0) noexcept {
        return std::visit([&](auto& queue) noexcept { return queue.poll(completions, wait_policy, deadline); },
                          queues_);
    }
    ucall_status_t cancel(io_request_t& request) noexcept {
        return std::visit([&](auto& queue) noexcept { return queue.cancel(request); }, queues_);
    }
    descriptor_t open_socket(int family) noexcept {
        return std::visit([&](auto& queue) noexcept { return queue.open_socket(family); }, queues_);
    }

    /** A stream socket of @p family for a listener to bind, which the loop imports once it listens:
     *  created with the queue's flags where its accepted sockets must share them. */
    descriptor_t open_listener(int family) noexcept {
        return std::visit(
            [&](auto& queue) noexcept {
                if constexpr (a_listener_creating_queue<decltype(queue)>) return queue.open_listener(family);
                else return socket_open(family);
            },
            queues_);
    }
    descriptor_t import_socket(descriptor_t descriptor) noexcept {
        return std::visit([&](auto& queue) noexcept { return queue.import_socket(descriptor); }, queues_);
    }
    int close_socket(descriptor_t descriptor) noexcept {
        return std::visit([&](auto& queue) noexcept { return queue.close_socket(descriptor); }, queues_);
    }
    [[nodiscard]] ucall_status_t reset_on_close(descriptor_t descriptor) noexcept {
        return std::visit([&](auto& queue) noexcept { return queue.reset_on_close(descriptor); }, queues_);
    }
    memory_registration_t register_memory(span<byte_t> memory) noexcept {
        return std::visit([&](auto& queue) noexcept { return queue.register_memory(memory); }, queues_);
    }
    void release(io_completion_t const& completion) noexcept {
        std::visit([&](auto& queue) noexcept { queue.release(completion); }, queues_);
    }
    void stop() noexcept {
        std::visit([](auto& queue) noexcept { queue.stop(); }, queues_);
    }

  private:
    static constexpr ucall_io_backend_t backends_k[] {queue_types_::backend_k...};
    static constexpr io_receive_memory_t receive_memories_k[] {queue_types_::receive_memory_k...};

    /** Past the last queue, the ladder answers why the last one tried refused. */
    template <std::size_t index_>
        requires(index_ == sizeof...(queue_types_))
    ucall_status_t open_(ucall_io_backend_t, std::size_t, std::size_t, io_issuer_scope_t, io_listeners_t,
                         ucall_status_t refused) noexcept {
        return refused;
    }

    template <std::size_t index_>
    ucall_status_t open_(ucall_io_backend_t backend, std::size_t depth, std::size_t capacity, io_issuer_scope_t scope,
                         io_listeners_t listeners, ucall_status_t refused) noexcept {
        using queue_t = std::variant_alternative_t<index_, queues_t>;
        bool const automatic = backend == ucall_io_backend_automatic_k;
        if (!automatic && backend != backends_k[index_])
            return open_<index_ + 1>(backend, depth, capacity, scope, listeners, refused);
        if constexpr (a_caller_listener_refusing_queue<queue_t>)
            if (listeners == io_listeners_t::caller_k) {
                if (automatic) return open_<index_ + 1>(backend, depth, capacity, scope, listeners, refused);
                queues_.template emplace<index_>(allocator_).refusal = queue_t::caller_listener_refusal_k;
                return ucall_status_unsupported_k;
            }
        ucall_status_t const opened = queues_.template emplace<index_>(allocator_).open(depth, capacity, scope);
        // Only the automatic ladder passes on, and only past a host refusing a queue's setup.
        if (!automatic || (opened != ucall_status_unsupported_k && opened != ucall_status_io_k &&
                           opened != ucall_status_out_of_memory_k))
            return opened;
        return open_<index_ + 1>(backend, depth, capacity, scope, listeners, opened);
    }

    /** The queue @c open picked, or the one it tried last. */
    queues_t queues_;

    /** What every queue @c open emplaces is constructed with. */
    [[no_unique_address]] allocator_t allocator_;

    /** The depth @c open was last given, which a reopen in @c grow repeats. */
    std::size_t depth_ {};

    /** The issuer scope @c open was last given, which a reopen in @c grow repeats. */
    io_issuer_scope_t scope_ {io_issuer_scope_t::one_thread_k};

    /** The listeners' origin @c open was last given, which a reopen in @c grow repeats. */
    io_listeners_t listeners_ {io_listeners_t::created_k};
};

} // namespace unum::ucall::io
