/**
 *  @file include/ucall/io/types.hpp
 *  @author Ash Vardanian
 *  @date January 13, 2025
 *  @brief Requests, completions, statistics and wakeups every I/O engine shares.
 */
#pragma once

#include <cerrno>
#include <ctime> // `timespec`

#include <atomic> // `std::memory_order_relaxed`
#include <limits> // `std::numeric_limits`

#include <smashtable/intrusive_list.hpp> // `intrusive_list`

#include "ucall/utilities/sockets.hpp" // `socket_close`, `socket_open`, `nonblocking`, `socket_option`
#include "ucall/utilities/types.hpp"   // `descriptor_t`, `byte_t`, `span`

namespace unum::ucall::io {

using utilities::accepted_socket;
using utilities::byte_t;
using utilities::descriptor_t;
using utilities::file_open_beneath;
using utilities::io_vector_t;
using utilities::monotonic_ns;
using utilities::nonblocking;
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

/** What a request asks of its socket or of a file; file operations keep @c descriptor as the
 *  socket they serve, so its close waits for them, and their offsets, lengths and buffers meet the
 *  file's @c file_direct_alignment. */
enum class io_operation_t : std::uint8_t {

    /** Accepts a connection on a listening socket, completing with the descriptor it opened, and
     *  writes the peer's address into the @c io_peer_address_t at @c data when it names one. */
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

    /** Opens the NUL-terminated path in @c data beneath @c file.directory_descriptor for unbuffered
     *  reads, completing with a descriptor the submitter owns even after a cancel. */
    file_open_k,

    /** Reads @c length bytes of @c file.file_descriptor at @c file.offset into @c data. */
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
inline constexpr registered_memory_t io_unregistered_k {std::numeric_limits<std::uint16_t>::max()};

/** The file a file operation reads or opens beneath, borrowed from the submitter. */
struct io_file_t {
    std::uint64_t offset {};
    int file_descriptor {-1};
    int directory_descriptor {-1};
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
static_assert(sizeof(io_request_t) == (UCALL_OS_WINDOWS_ ? 64 : 56));

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
    ~wake_channel_t() noexcept {
        for (auto descriptor : descriptors)
            if (descriptor >= 0) socket_close(descriptor);
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
        if (nonblocking(descriptors[0]) != ucall_status_success_k ||
            nonblocking(descriptors[1]) != ucall_status_success_k)
            return ucall_status_io_k;
#if defined(SO_NOSIGPIPE)
        int enabled = 1;
        if (socket_option(descriptors[1], SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0)
            return ucall_status_io_k;
#endif // defined(SO_NOSIGPIPE)
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
#if defined(MSG_NOSIGNAL)
        constexpr int flags = MSG_NOSIGNAL;
#else
        constexpr int flags = 0;
#endif
        while (send(static_cast<int>(descriptors[1]), &value, 1, flags) < 0 && errno == EINTR) {}
#endif // UCALL_OS_WINDOWS_
    }

    /** Blocks until a notification or the monotonic @p deadline, zero meaning none, then empties a
     *  channel whose read end no engine imported. */
    void wait(std::uint64_t deadline) noexcept {
        auto now = monotonic_ns();
        auto remaining = deadline > now ? deadline - now : 0;
#if UCALL_OS_LINUX_ || UCALL_OS_FREEBSD_
        timespec timeout {static_cast<time_t>(remaining / 1000000000), static_cast<long>(remaining % 1000000000)};
        pollfd polled {static_cast<int>(descriptors[0]), POLLIN, 0};
        ::ppoll(&polled, 1, deadline ? &timeout : nullptr, nullptr);
        while (recv(static_cast<int>(descriptors[0]), bytes, sizeof(bytes), 0) > 0) {}
#else
        int timeout = -1;
        if (deadline)
            timeout = static_cast<int>(std::min<std::uint64_t>(remaining / 1000000 + (remaining % 1000000 != 0),
                                                               std::numeric_limits<int>::max()));
#if UCALL_OS_WINDOWS_
        WSAPOLLFD polled {static_cast<SOCKET>(descriptors[0]), POLLRDNORM, 0};
        WSAPoll(&polled, 1, timeout);
        while (recv(static_cast<SOCKET>(descriptors[0]), reinterpret_cast<char*>(bytes), sizeof(bytes), 0) > 0) {}
#else
        pollfd polled {static_cast<int>(descriptors[0]), POLLIN, 0};
        ::poll(&polled, 1, timeout);
        while (recv(static_cast<int>(descriptors[0]), bytes, sizeof(bytes), 0) > 0) {}
#endif // UCALL_OS_WINDOWS_
#endif // UCALL_OS_LINUX_
    }
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

/** The flags a copying send takes so a vanished peer never raises @c SIGPIPE; Apple sockets carry
 *  @c SO_NOSIGPIPE instead. */
#if UCALL_OS_APPLE_
inline constexpr int socket_send_flags_k = 0;
#else
inline constexpr int socket_send_flags_k = MSG_NOSIGNAL;
#endif

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
    auto length = std::min<std::size_t>(request.length, std::numeric_limits<int>::max());
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
        result = recv(descriptor, room.iov_base, std::min<std::size_t>(room.iov_len, std::numeric_limits<int>::max()),
                      0);
        break;
    }
    case io_operation_t::send_k:
    case io_operation_t::send_zero_copy_k: result = send(descriptor, request.data, length, socket_send_flags_k); break;
    case io_operation_t::read_k: result = read(descriptor, request.data, length); break;
    case io_operation_t::shutdown_k: return ::shutdown(descriptor, SHUT_WR) == 0 ? 0 : -errno;
    case io_operation_t::close_k: return socket_close(request.descriptor) == 0 || errno == EINTR ? 0 : -errno;
    case io_operation_t::file_open_k:
        return file_open_beneath(request.file.directory_descriptor, reinterpret_cast<char const*>(request.data));
    case io_operation_t::file_read_k:
        tally<atomic_ref_template_>(statistics.file_reads_blocking);
        return utilities::file_read(request.file.file_descriptor, {request.data, request.length}, request.file.offset);
    case io_operation_t::file_read_vectors_k:
        tally<atomic_ref_template_>(statistics.file_reads_blocking);
        return utilities::file_read_vectors(request.file.file_descriptor, io_vectors(request), request.file.offset);
    case io_operation_t::zero_copy_release_k: return 1;
    }
    return result >= 0 ? static_cast<descriptor_t>(result) : -errno;
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

/** Returns a readiness engine's operation to its free list, answering its completion. */
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
    if (request.operation == io_operation_t::close_k && result >= 0) request.descriptor = -1;
    operation = {};
    cold = {};
    engine.free_list(index).push(engine.operations, index);
    --engine.active;
    tally<atomic_ref_template_>(engine.statistics.completions);
    return {&request, result};
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
inline bool io_pending(descriptor_t result) noexcept {
    return result == -EAGAIN || result == -EWOULDBLOCK || result == -EINPROGRESS || result == -EINTR;
}

#endif // UCALL_OS_POSIX_

/** Whether a socket's sends still try zero-copy, which ends once the kernel reports it copied. */
enum class zero_copy_stage_t : std::uint8_t { untried_k, enabled_k, copying_k };

/** The key an engine indexes a zero-copy release by, the address of the request its sends name. */
inline std::uint64_t release_key(io_request_t const* request) noexcept {
    return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(request));
}

} // namespace unum::ucall::io
