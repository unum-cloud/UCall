/**
 *  @file include/ucall/io/types.hpp
 *  @author Ash Vardanian
 *  @date January 13, 2025
 *  @brief Requests, completions, statistics and wakeups every I/O engine shares.
 */
#pragma once

#include <cerrno>
#include <climits> // `CHAR_BIT`

#include <atomic>  // `std::memory_order_relaxed`
#include <limits>  // `std::numeric_limits`
#include <variant> // `std::variant`, `std::visit`

#include <smashtable/intrusive_list.hpp> // `intrusive_list`

#include "ucall/utilities/sockets.hpp" // `socket_close`, `socket_open`, `nonblocking`, `socket_option`
#include "ucall/utilities/types.hpp"   // `descriptor_t`, `byte_t`, `span`

namespace unum::ucall::io {

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

enum class io_wait_t { blocking_k, nonblocking_k };

/** How a socket's close ends its stream: a FIN after what it sent, or a reset that purges what the
 *  kernel still holds, as a connection whose reply broke off past its head needs. */
enum class close_mode_t : std::uint8_t { orderly_k, reset_k };

/** Whether a record is linked on a list that steps or reaps it, such as a ready queue. */
enum class listing_t : std::uint8_t { unlisted_k, listed_k };

/** Which threads may enter an engine: the first one for good, or one at a time in any order, so
 *  a runtime's collector may free what another thread polled. */
enum class io_issuer_scope_t : std::uint8_t { one_thread_k, any_thread_k };

/** Where a server's listeners come from: created through its engines, or handed over by the caller
 *  as some are. */
enum class io_listeners_t : std::uint8_t { created_k, borrowed_k };

/** What a request asks of its socket or of a file; file operations keep @c descriptor as the
 *  socket they serve, so its close waits for them, and their offsets, lengths and buffers meet the
 *  file's @c direct_alignment_of. */
enum class io_operation_t : std::uint8_t {

    /** Accepts up to @c length connections on a listening socket, at least one, completing once
     *  per connection with the descriptor it opened and the peer's address written into the
     *  @c io_peer_address_t at @c data when that names an array of them, which a completion's own
     *  @c data names where it differs. Each connection takes one from @c length, and the request
     *  stays pending while some is left: a readiness engine takes as many as are queued, and a
     *  port or a ring arms one accept per socket for as many as it admits at once. A ring names a
     *  peer it keeps until the socket closes, and a connection its accepts already took past the
     *  last of @c length still completes before the request ends. Both are read at each attempt,
     *  so a submitter may renew them. */
    accept_k,

    /** Connects to the address of @c length bytes in @c data. */
    connect_k,

    /** Receives into the vector @c data names, read at each attempt so its owner may move it, or
     *  into engine memory where the engine's @c receive_memory_k says so. */
    receive_k,

    /** Sends @c data by copying. */
    send_k,

    /** Completes once the socket took bytes of @c data, and names the @c release_request whose
     *  @c zero_copy_release_k completes once the kernel let go of them; the submitter submits the
     *  release after the last send naming it completed. */
    send_zero_copy_k,

    /** Reads into @c data, never into engine memory, for a wakeup or a datagram that must stay
     *  whole. */
    read_k,

    /** Shuts the sending direction of the socket down. */
    shutdown_k,

    /** Closes the socket. */
    close_k,

    /** Opens the NUL-terminated path in @c data beneath the directory @c file.file for unbuffered
     *  reads, completing with a descriptor the submitter owns even after a cancel. */
    file_open_k,

    /** Reads @c length bytes of @c file.file at @c file.offset into @c data. */
    file_read_k,

    /** Scatters the bytes @c file_read_k would read into the @c length vectors in @c data. */
    file_read_vectors_k,

    /** Completes with 0 while the socket still pins its sends, and with 1 once the socket sends by
     *  copying for its lifetime, as the kernel reported a send it counts copied or the engine never
     *  pins its sends at all. */
    zero_copy_release_k,
};

/** Where an engine lands a receive: the submitter's vector, or memory of its own it lends. */
enum class io_receive_memory_t : std::uint8_t { submitter_k, engine_k };

/** The engine buffer index a request's memory lies in, scoped so no descriptor binds to it. */
enum class registered_memory_t : std::uint16_t {};

/** The @c registered_memory of a request whose buffer lies in no engine-registered range. */
inline constexpr registered_memory_t io_unregistered_k {(std::numeric_limits<std::uint16_t>::max)()};

/** The @c operation_index of a request no engine record carries. */
inline constexpr std::uint32_t io_unindexed_k = (std::numeric_limits<std::uint32_t>::max)();

/** The file a read reads, or the directory a @c file_open_k opens beneath, borrowed from the
 *  submitter. */
struct io_file_t {
    std::uint64_t offset {};
    native_file_t file {invalid_native_file_k};
};
static_assert(sizeof(io_file_t) == 16);

/** Where an accept writes its peer's address, kept by the submitter with the request. */
struct io_peer_address_t {
    sockaddr_storage address {};
    socket_length_t length {};
};

/** The submitter keeps this request, its buffers and the requests it names alive until its
 *  completion is polled. */
struct io_request_t {
    io_operation_t operation {io_operation_t::receive_k};
    registered_memory_t registered_memory {io_unregistered_k};

    /** The engine record carrying this request while it is submitted, which the engine sets, so a
     *  cancel or a release finds it without a search; @c io_unindexed_k otherwise. */
    std::uint32_t operation_index {io_unindexed_k};

    descriptor_t descriptor {-1};
    byte_t* data {};
    std::size_t length {};
    std::uint64_t deadline {};
    void* context {};
    union {

        /** What a file operation reads or opens beneath. */
        io_file_t file {};

        /** The release a @c send_zero_copy_k names. */
        io_request_t* release_request;
    };
};
static_assert(sizeof(io_request_t) == 64);

/** Whether an engine holds a registered range pinned, sparing each request in it the pinning. */
enum class range_pinning_t : std::uint8_t {
    pinned_k,   // Registered at `index`; requests pass it as `registered_memory`.
    unpinned_k, // Refused, by the locked-memory cap or a full table; requests pass `io_unregistered_k`.
};

/** What @c register_memory made of a range. */
struct memory_registration_t {
    registered_memory_t index {io_unregistered_k};
    range_pinning_t pinning {range_pinning_t::unpinned_k};
    ucall_status_t status {ucall_status_success_k};
};
static_assert(sizeof(memory_registration_t) == 8);

/** The readiness an operation waits for; a socket keeps at most one pending operation per
 *  direction, and file operations wait on no socket at all. */
enum class io_direction_t : std::uint8_t { receive_k, transmit_k };
inline io_direction_t io_direction(io_operation_t operation) noexcept {
    return operation == io_operation_t::connect_k || operation == io_operation_t::send_k ||
                   operation == io_operation_t::send_zero_copy_k || operation == io_operation_t::shutdown_k
               ? io_direction_t::transmit_k
               : io_direction_t::receive_k;
}

/** A byte count, accepted descriptor, or negated errno for exactly one submitted request; a receive
 *  into engine memory names the @c data it filled and the @c lease that @c release returns. */
struct io_completion_t {
    io_request_t* request {};
    descriptor_t result {};
    byte_t* data {};
    std::uintptr_t lease {};
};
static_assert(sizeof(io_completion_t) == 32);

/** Counters an engine advances for its one polling owner, on lines no other thread writes.
 *  @c zero_copy_fallbacks counts sends the kernel copied anyway or refused to pin, and
 *  @c zero_copy_sends plus @c copying_sends is every send. */
struct alignas(fu::default_alignment_k) io_statistics_t {
    std::uint64_t submissions {}, completions {}, kernel_enters {}, cancellations {}, receive_rearms {},
        bytes_copied {}, zero_copy_sends {}, zero_copy_fallbacks {}, copying_sends {}, file_reads_asynchronous {},
        file_reads_blocking {};
};

/** Advances a counter only its owner writes, through @p atomic_ref_template_, so other threads may
 *  load it relaxed. */
template <template <typename> class atomic_ref_template_>
inline void tally(std::uint64_t& counter, std::uint64_t amount = 1) noexcept {
    atomic_ref_template_<std::uint64_t> word {counter};
    word.store(word.load(std::memory_order_relaxed) + amount, std::memory_order_relaxed);
}

/** A pollable wakeup with the same request lifetime as socket operations. */
struct wake_channel_t {
    wake_channel_t() noexcept = default;
    wake_channel_t(wake_channel_t const&) = delete;
    wake_channel_t& operator=(wake_channel_t const&) = delete;
    wake_channel_t(wake_channel_t&&) = delete;
    wake_channel_t& operator=(wake_channel_t&&) = delete;
    descriptor_t descriptors[2] {-1, -1};
    byte_t bytes[sizeof(std::uint64_t)] {};
    io_request_t request {};
#if UCALL_OS_APPLE_

    /** A kqueue watching the read end, as Darwin's @c poll waits in whole milliseconds. */
    int queue {-1};
#elif UCALL_OS_WINDOWS_

    /** An event the read end signals and a high-resolution timer, as @c WSAPoll waits in whole
     *  scheduler ticks. */
    HANDLE readable {}, timer {};
#endif // UCALL_OS_APPLE_
    ~wake_channel_t() noexcept {
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
     *  channel whose read end no engine imported. */
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

/** A socket an engine registered in a table of its own, named by its index under a high bit that
 *  separates it from process descriptors and socket handles. */
struct registered_socket_t {
    unsigned index {};
    static constexpr descriptor_t tag_k = descriptor_t {1} << (sizeof(descriptor_t) * CHAR_BIT - 2);
    descriptor_t handle() const noexcept { return tag_k | static_cast<descriptor_t>(index); }
    static bool contains(descriptor_t handle) noexcept { return handle >= tag_k; }
    static unsigned index_of(descriptor_t handle) noexcept { return static_cast<unsigned>(handle & ~tag_k); }
};

/** An intrusive FIFO of engine operations, linked through their @c next indices. */
using operation_list_t = st::intrusive_list<unsigned>;

/** The vectors a @c file_read_vectors_k or @c receive_k request fills, named by its @c data. */
inline span<io_vector_t> io_vectors(io_request_t const& request) noexcept {
    return {reinterpret_cast<io_vector_t*>(request.data), request.length};
}

/** Whether a polled operation is untouched, has started connecting, or was cancelled. */
enum class operation_stage_t : std::uint8_t { fresh_k, started_k, cancelled_k };

#if UCALL_OS_POSIX_
inline short io_events(io_operation_t operation) noexcept {
    return io_direction(operation) == io_direction_t::transmit_k ? POLLOUT : POLLIN;
}

/** Where an operation waits: nowhere yet, on its socket's readiness, retrying once that fired, or
 *  in a kernel queue that completes it without readiness. */
enum class io_interest_t : std::uint8_t { unarmed_k, armed_k, ready_k, landing_k };

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
        return open_native_file_beneath(request.file.file, reinterpret_cast<char const*>(request.data));
    case io_operation_t::file_read_k:
        tally<atomic_ref_template_>(statistics.file_reads_blocking);
        return utilities::read_native_file(request.file.file, {request.data, request.length}, request.file.offset);
    case io_operation_t::file_read_vectors_k:
        tally<atomic_ref_template_>(statistics.file_reads_blocking);
        return utilities::read_native_file_vectors(request.file.file, io_vectors(request), request.file.offset);
    case io_operation_t::zero_copy_release_k: return 1;
    }
    return result >= 0 ? static_cast<descriptor_t>(result) : -errno;
}

inline bool io_pending(descriptor_t result) noexcept {
    return result == -EAGAIN || result == -EWOULDBLOCK || result == -EINPROGRESS || result == -EINTR;
}

/** Marks an armed operation ready, for the next progress pass of a readiness engine. */
template <typename engine_type_>
void readiness_wake(engine_type_& engine, unsigned index) noexcept {
    engine.operations[index].interest = io_interest_t::ready_k;
    engine.ready_operations.push(engine.operations, index);
}

/** Parks a finished operation's result until the next collect of a readiness engine. */
template <typename engine_type_>
void readiness_land(engine_type_& engine, unsigned index, descriptor_t result) noexcept {
    engine.cold_fields(index).result = result;
    engine.landed_operations.push(engine.operations, index);
}

/** Wakes operation @p index of a readiness engine for @p events that @p descriptor reported, unless
 *  the operation stopped waiting on it, or waits in the other direction. */
template <typename engine_type_>
void readiness_fire(engine_type_& engine, unsigned index, descriptor_t descriptor, short events) noexcept {
    auto& operation = engine.operations[index];
    if (operation.interest == io_interest_t::armed_k && operation.request->descriptor == descriptor &&
        (events & io_events(operation.request->operation)))
        readiness_wake(engine, index);
}

/** Returns a readiness engine's operation to its free list, answering its completion; an accept
 *  ends with nothing left of its @c length. */
template <template <typename> class atomic_ref_template_, typename engine_type_>
io_completion_t readiness_finish(engine_type_& engine, unsigned index, descriptor_t result) noexcept {
    auto& operation = engine.operations[index];
    auto& request = *operation.request;
    typename engine_type_::operation_cold_t& cold = engine.cold_fields(index);
    if (cold.timed != engine_type_::absent_k) {
        engine.timed[cold.timed] = engine.timed.back();
        engine.cold_fields(engine.timed.back()).timed = cold.timed;
        engine.timed.pop_back();
    }
    // Only a level-triggered set keeps polling what nothing waits on, so only it hears of the end.
    if constexpr (requires { engine.readiness.disarm(request.descriptor, io_direction_t::receive_k, index); })
        if (operation.interest == io_interest_t::armed_k || operation.interest == io_interest_t::ready_k)
            engine.readiness.disarm(request.descriptor, io_direction(request.operation), index);
    if (request.operation == io_operation_t::close_k && result >= 0) request.descriptor = -1;
    if (request.operation == io_operation_t::accept_k) request.length = 0;
    request.operation_index = io_unindexed_k;
    operation = {};
    cold = {};
    engine.free_list(index).push(engine.operations, index);
    --engine.active;
    tally<atomic_ref_template_>(engine.statistics.completions);
    return {&request, result};
}

/** Answers one connection an accept took while its request stays pending, naming the peer address
 *  it wrote, the next of which goes past it. */
template <template <typename> class atomic_ref_template_, typename engine_type_>
io_completion_t readiness_yield(engine_type_& engine, io_request_t& request, descriptor_t accepted) noexcept {
    byte_t* const peer = request.data;
    if (peer) request.data = peer + sizeof(io_peer_address_t);
    --request.length;
    tally<atomic_ref_template_>(engine.statistics.completions);
    return {&request, accepted, peer};
}

/** Answers the landed operations of a readiness engine into @p completions from @p count on. */
template <template <typename> class atomic_ref_template_, typename engine_type_>
std::size_t readiness_collect(engine_type_& engine, span<io_completion_t> completions, std::size_t count) noexcept {
    while (count != completions.size()) {
        auto index = engine.landed_operations.pop(engine.operations);
        if (index == engine_type_::absent_k) break;
        descriptor_t const result = engine.operations[index].stage == operation_stage_t::cancelled_k
                                        ? -ECANCELED
                                        : engine.cold_fields(index).result;
        completions[count++] = readiness_finish<atomic_ref_template_>(engine, index, result);
    }
    return count;
}

/** Attempts each operation on @p list, arming those the socket is not ready for, answering the rest
 *  into @p completions from @p count on; an accept takes connections while its @c length lasts. */
template <template <typename> class atomic_ref_template_, typename engine_type_>
std::size_t readiness_progress(engine_type_& engine, operation_list_t& list, span<io_completion_t> completions,
                               std::size_t count, std::uint64_t now) noexcept {
    while (count != completions.size()) {
        unsigned const index = list.pop(engine.operations);
        if (index == engine_type_::absent_k) break;
        auto& operation = engine.operations[index];
        io_request_t& request = *operation.request;
        bool const fired = operation.interest == io_interest_t::ready_k;
        descriptor_t result = -ETIMEDOUT;
        // An edge-triggered operation hears nothing more until its syscall reports EAGAIN.
        if (engine.cold_fields(index).timed == engine_type_::absent_k || request.deadline > now) {
            do result = engine.attempt(index);
            while (fired && result == -EINTR);
        }
        if (operation.interest == io_interest_t::landing_k) continue;
        while (request.operation == io_operation_t::accept_k && result >= 0 && request.length > 1 &&
               count + 1 != completions.size()) {
            completions[count++] = readiness_yield<atomic_ref_template_>(engine, request, result);
            do result = engine.attempt(index);
            while (result == -EINTR);
        }
        if (io_pending(result) && !fired) {
            io_direction_t const direction = io_direction(request.operation);
            if (int const armed = engine.readiness.arm(request.descriptor, direction, index, engine.statistics);
                armed < 0)
                result = armed;
        }
        if (io_pending(result)) operation.interest = io_interest_t::armed_k;
        else completions[count++] = readiness_finish<atomic_ref_template_>(engine, index, result);
    }
    return count;
}

/** Collects, progresses and, finding nothing, waits once through the engine's @c wait, which takes
 *  nanoseconds, the maximum meaning forever, until @p deadline or the earliest operation's. */
template <template <typename> class atomic_ref_template_, typename engine_type_>
int readiness_poll(engine_type_& engine, span<io_completion_t> completions, io_wait_t wait_policy,
                   std::uint64_t deadline) noexcept {
    if (!completions.size()) return 0;
    std::size_t count {};
    for (unsigned round = 0; round != 2; ++round) {
        std::uint64_t const now = monotonic_ns();
        std::uint64_t wait = wait_policy == io_wait_t::blocking_k ? (std::numeric_limits<std::uint64_t>::max)() : 0;
        if (deadline) wait = fu::min_of(wait, deadline > now ? deadline - now : 0);
        for (unsigned index : engine.timed) {
            std::uint64_t const expiry = engine.operations[index].request->deadline;
            if (expiry > now) wait = fu::min_of(wait, expiry - now);
            else if (engine.operations[index].interest == io_interest_t::armed_k) readiness_wake(engine, index);
        }
        count = readiness_collect<atomic_ref_template_>(engine, completions, count);
        count = readiness_progress<atomic_ref_template_>(engine, engine.fresh_operations, completions, count, now);
        count = readiness_progress<atomic_ref_template_>(engine, engine.ready_operations, completions, count, now);
        if (count || round || !engine.active) break;
        int const result = engine.wait(wait);
        if (result < 0 && result != -EINTR) return result;
    }
    return static_cast<int>(count);
}

#endif // UCALL_OS_POSIX_

/** Whether a socket's sends still try zero-copy, which ends once the kernel reports it copied. */
enum class zero_copy_stage_t : std::uint8_t { untried_k, enabled_k, copying_k };

/**
 *  @brief Several engines behind one type: @c open picks one at runtime, and every engine verb
 *      forwards to it through one @c std::visit, a predictable switch per call.
 *
 *  Under @c ucall_io_backend_automatic_k it tries the engines in declaration order, so a ring a
 *  seccomp profile or the locked-memory cap refuses falls to the next. Any other backend opens
 *  exactly its own engine or answers why it could not. An engine that accepts only from listeners
 *  it creates declares @c borrowed_listener_refusal_k, and a server with a borrowed listener passes
 *  over it, or is refused where it names it.
 */
template <typename... engine_types_>
class io_engine_variant {
  public:
    using engines_t = std::variant<engine_types_...>;
    using allocator_t = typename std::variant_alternative_t<0, engines_t>::allocator_t;
    template <typename other_allocator_, template <typename> class other_atomic_ref_, typename other_row_kit_>
    using rebind = io_engine_variant<
        typename engine_types_::template rebind<other_allocator_, other_atomic_ref_, other_row_kit_>...>;

    static_assert((std::is_same_v<typename engine_types_::allocator_t, allocator_t> && ...),
                  "Every engine of a set places its records through one allocator");

    explicit io_engine_variant(allocator_t const& allocator = {}) noexcept
        : engines_(std::in_place_index<0>, allocator), allocator_(allocator) {}
    io_engine_variant(io_engine_variant const&) = delete;
    io_engine_variant& operator=(io_engine_variant const&) = delete;
    io_engine_variant(io_engine_variant&&) = delete;
    io_engine_variant& operator=(io_engine_variant&&) = delete;

    /**
     *  @brief Opens the engine of @p backend, or under @c ucall_io_backend_automatic_k the first
     *      one whose setup the host admits, for @p capacity operations.
     *
     *  @par Statuses:
     *  - @c unsupported_k The set has no engine for @p backend, the named one's kernel lacks it, or
     *    it cannot accept from borrowed @p listeners.
     *  - @c io_k The setup was refused, or under automatic every engine's was, the last one's
     *    status answering for all of them.
     */
    ucall_status_t open(ucall_io_backend_t backend, std::size_t depth, std::size_t capacity,
                        io_issuer_scope_t scope = io_issuer_scope_t::one_thread_k,
                        io_listeners_t listeners = io_listeners_t::created_k) noexcept {
        return open_<0>(backend, depth, capacity, scope, listeners, ucall_status_unsupported_k);
    }

    /** The backend of the engine @c open picked, or tried last. */
    ucall_io_backend_t backend() const noexcept { return backends_k[engines_.index()]; }

    /** Where the open engine lands receives. */
    io_receive_memory_t receive_memory() const noexcept { return receive_memories_k[engines_.index()]; }

    /** Why the engine refused its setup, naming the host setting to raise, or null. */
    char const* refusal() const noexcept {
        return std::visit(
            [](auto const& engine) noexcept -> char const* {
                if constexpr (requires { engine.refusal; }) return engine.refusal;
                else return nullptr;
            },
            engines_);
    }

    io_statistics_t& statistics() noexcept {
        return std::visit([](auto& engine) noexcept -> io_statistics_t& { return engine.statistics; }, engines_);
    }

    /** Grows the open engine to @p capacity, as only one not yet polled may: a ring in place,
     *  keeping the size and locked memory its setup proved, any other reopened. */
    ucall_status_t grow(std::size_t capacity) noexcept {
        ucall_status_t grown = ucall_status_success_k;
        bool const in_place = std::visit(
            [&](auto& engine) noexcept {
                if constexpr (requires { engine.grow(capacity); }) {
                    grown = engine.grow(capacity);
                    return true;
                }
                else return false;
            },
            engines_);
        return in_place ? grown : open(backend(), capacity, capacity);
    }

    /** Sets aside the last @p count records for the releases sends name, where the engine keeps
     *  them apart. */
    void reserve_releases(std::size_t count) noexcept {
        std::visit(
            [&](auto& engine) noexcept {
                if constexpr (requires { engine.reserve_releases(count); }) engine.reserve_releases(count);
            },
            engines_);
    }

    /** Stops prefetching into @p descriptor's stream while nobody pulls its bytes, where the engine
     *  prefetches at all. */
    void receive_pause(descriptor_t descriptor) noexcept {
        std::visit(
            [&](auto& engine) noexcept {
                if constexpr (requires { engine.receive_pause(descriptor); }) engine.receive_pause(descriptor);
            },
            engines_);
    }

    ucall_status_t submit(io_request_t& request) noexcept {
        return std::visit([&](auto& engine) noexcept { return engine.submit(request); }, engines_);
    }
    int poll(span<io_completion_t> completions, io_wait_t wait_policy, std::uint64_t deadline = 0) noexcept {
        return std::visit([&](auto& engine) noexcept { return engine.poll(completions, wait_policy, deadline); },
                          engines_);
    }
    ucall_status_t cancel(io_request_t& request) noexcept {
        return std::visit([&](auto& engine) noexcept { return engine.cancel(request); }, engines_);
    }
    descriptor_t open_socket(int family) noexcept {
        return std::visit([&](auto& engine) noexcept { return engine.open_socket(family); }, engines_);
    }

    /** A stream socket of @p family for a listener to bind, which the loop imports once it listens:
     *  created with the engine's flags where its accepted sockets must share them. */
    descriptor_t open_listener(int family) noexcept {
        return std::visit(
            [&](auto& engine) noexcept {
                if constexpr (requires { engine.open_listener(family); }) return engine.open_listener(family);
                else return socket_open(family);
            },
            engines_);
    }
    descriptor_t import_socket(descriptor_t descriptor) noexcept {
        return std::visit([&](auto& engine) noexcept { return engine.import_socket(descriptor); }, engines_);
    }
    int close_socket(descriptor_t descriptor) noexcept {
        return std::visit([&](auto& engine) noexcept { return engine.close_socket(descriptor); }, engines_);
    }
    [[nodiscard]] ucall_status_t reset_on_close(descriptor_t descriptor) noexcept {
        return std::visit([&](auto& engine) noexcept { return engine.reset_on_close(descriptor); }, engines_);
    }
    memory_registration_t register_memory(span<byte_t> memory) noexcept {
        return std::visit([&](auto& engine) noexcept { return engine.register_memory(memory); }, engines_);
    }
    void release(io_completion_t const& completion) noexcept {
        std::visit([&](auto& engine) noexcept { engine.release(completion); }, engines_);
    }
    void stop() noexcept {
        std::visit([](auto& engine) noexcept { engine.stop(); }, engines_);
    }

  private:
    static constexpr ucall_io_backend_t backends_k[] {engine_types_::backend_k...};
    static constexpr io_receive_memory_t receive_memories_k[] {engine_types_::receive_memory_k...};

    template <std::size_t index_>
    ucall_status_t open_(ucall_io_backend_t backend, std::size_t depth, std::size_t capacity, io_issuer_scope_t scope,
                         io_listeners_t listeners, ucall_status_t refused) noexcept {
        if constexpr (index_ == sizeof...(engine_types_)) return refused;
        else {
            using engine_t = std::variant_alternative_t<index_, engines_t>;
            bool const automatic = backend == ucall_io_backend_automatic_k;
            if (!automatic && backend != backends_k[index_])
                return open_<index_ + 1>(backend, depth, capacity, scope, listeners, refused);
            if constexpr (requires { engine_t::borrowed_listener_refusal_k; })
                if (listeners == io_listeners_t::borrowed_k) {
                    if (automatic) return open_<index_ + 1>(backend, depth, capacity, scope, listeners, refused);
                    engines_.template emplace<index_>(allocator_).refusal = engine_t::borrowed_listener_refusal_k;
                    return ucall_status_unsupported_k;
                }
            ucall_status_t const opened = engines_.template emplace<index_>(allocator_).open(depth, capacity, scope);
            // Only the automatic ladder passes on, and only past a host refusing an engine's setup.
            if (!automatic || (opened != ucall_status_unsupported_k && opened != ucall_status_io_k &&
                               opened != ucall_status_out_of_memory_k))
                return opened;
            return open_<index_ + 1>(backend, depth, capacity, scope, listeners, opened);
        }
    }

    engines_t engines_;
    [[no_unique_address]] allocator_t allocator_;
};

} // namespace unum::ucall::io
