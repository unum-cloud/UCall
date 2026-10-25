/**
 *  @file include/ucall/io.hpp
 *  @author Ash Vardanian
 *  @date January 13, 2025
 *  @brief Durable I/O requests and connection transitions shared by socket backends.
 */
#pragma once

#include <cerrno>
#include <climits>
#include <ctime>

#include <atomic>
#include <bit>
#include <chrono>
#include <new>

#include "ucall/types.hpp"

#if UCALL_OS_WINDOWS_
#include <mswsock.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#if UCALL_OS_LINUX_
#include <sys/epoll.h>
#endif
#if UCALL_OS_APPLE_ || UCALL_OS_FREEBSD_
#include <sys/event.h>
#endif

#if !defined(UCALL_WITH_LINUX_URING)
#define UCALL_WITH_LINUX_URING 0
#endif // !defined(UCALL_WITH_LINUX_URING)
#if UCALL_WITH_LINUX_URING
#include <liburing.h>
#endif // UCALL_WITH_LINUX_URING

namespace unum::ucall {

inline std::uint64_t monotonic_ns() noexcept {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
        .count();
}
inline std::uint64_t deadline_after(std::size_t microseconds) noexcept {
    auto now = monotonic_ns();
    auto maximum = std::numeric_limits<std::uint64_t>::max();
    return microseconds > (maximum - now) / 1000 ? maximum : now + microseconds * 1000;
}

#if UCALL_OS_WINDOWS_
using socket_length_t = int;
inline int socket_error(int error) noexcept {
    switch (error) {
    case WSAEWOULDBLOCK: return EAGAIN;
    case WSAEINPROGRESS: return EINPROGRESS;
    case WSAEINTR: return EINTR;
    case WSAECONNRESET:
    case ERROR_NETNAME_DELETED: return ECONNRESET;
    case WSAECONNREFUSED: return ECONNREFUSED;
    case WSAETIMEDOUT: return ETIMEDOUT;
    case ERROR_OPERATION_ABORTED: return ECANCELED;
    default: return EIO;
    }
}
inline int socket_last_error() noexcept { return socket_error(WSAGetLastError()); }
inline bool start_windows_sockets() noexcept {
    WSADATA data {};
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
}
inline bool sockets_start() noexcept {
    static bool const ready = start_windows_sockets();
    return ready;
}
inline int socket_close(descriptor_t descriptor) noexcept { return closesocket(static_cast<SOCKET>(descriptor)); }
inline bool nonblocking(descriptor_t descriptor) noexcept {
    u_long enabled = 1;
    return ioctlsocket(static_cast<SOCKET>(descriptor), FIONBIO, &enabled) == 0 &&
           SetHandleInformation(reinterpret_cast<HANDLE>(descriptor), HANDLE_FLAG_INHERIT, 0);
}
inline std::size_t page_size() noexcept {
    SYSTEM_INFO info {};
    GetSystemInfo(&info);
    return info.dwPageSize;
}
#else
using socket_length_t = socklen_t;
inline int socket_last_error() noexcept { return errno; }
inline bool sockets_start() noexcept { return true; }
inline int socket_close(descriptor_t descriptor) noexcept { return close(static_cast<int>(descriptor)); }
inline bool nonblocking(descriptor_t descriptor) noexcept {
    int flags = fcntl(static_cast<int>(descriptor), F_GETFL, 0);
    return flags != -1 && fcntl(static_cast<int>(descriptor), F_SETFL, flags | O_NONBLOCK) != -1 &&
           fcntl(static_cast<int>(descriptor), F_SETFD, FD_CLOEXEC) != -1;
}
inline std::size_t page_size() noexcept {
    long result = sysconf(_SC_PAGESIZE);
    return result > 0 ? static_cast<std::size_t>(result) : 0;
}
#endif
inline int socket_option(descriptor_t descriptor, int level, int name, void const* value, std::size_t length) noexcept {
#if UCALL_OS_WINDOWS_
    return setsockopt(static_cast<SOCKET>(descriptor), level, name, static_cast<char const*>(value),
                      static_cast<int>(length));
#else
    return setsockopt(static_cast<int>(descriptor), level, name, value, static_cast<socklen_t>(length));
#endif
}
inline descriptor_t socket_open(int family) noexcept {
    if (!sockets_start()) return -1;
#if UCALL_OS_WINDOWS_
    descriptor_t descriptor = static_cast<descriptor_t>(
        WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED));
#else
    descriptor_t descriptor = socket(family, SOCK_STREAM, 0);
#endif
    if (descriptor == -1) return -1;
    if (!nonblocking(descriptor)) {
        socket_close(descriptor);
        return -1;
    }
    int enabled = 1;
    // Fragmented RPC writes must not wait for delayed ACKs before releasing TX credits.
    if ((family == AF_INET || family == AF_INET6) &&
        socket_option(descriptor, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) != 0) {
        socket_close(descriptor);
        return -1;
    }
#if UCALL_OS_APPLE_
    if (setsockopt(static_cast<int>(descriptor), SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
        socket_close(descriptor);
        return -1;
    }
#endif
    return descriptor;
}
inline descriptor_t accepted_socket(descriptor_t descriptor) noexcept {
    if (descriptor == -1) return -socket_last_error();
    if (!nonblocking(descriptor)) {
        int error = socket_last_error();
        socket_close(descriptor);
        return -error;
    }
    int enabled = 1;
    if (socket_option(descriptor, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) != 0) {
        int error = socket_last_error();
        socket_close(descriptor);
        return -error;
    }
#if UCALL_OS_APPLE_
    if (setsockopt(static_cast<int>(descriptor), SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
        int error = errno;
        socket_close(descriptor);
        return -error;
    }
#endif
    return descriptor;
}

enum class io_wait_t { blocking_k, nonblocking_k };

enum class io_operation_t { accept_k, connect_k, receive_k, send_k, read_k, close_k };

/** The readiness an operation waits for; a socket keeps at most one pending operation per
 *  direction. */
enum class io_direction_t : std::uint8_t { receive_k, transmit_k };
inline io_direction_t io_direction(io_operation_t operation) noexcept {
    return operation == io_operation_t::connect_k || operation == io_operation_t::send_k ? io_direction_t::transmit_k
                                                                                         : io_direction_t::receive_k;
}

/** The submitter keeps this request and its buffer alive until its completion is polled. */
struct io_request_t {
    io_operation_t operation {io_operation_t::receive_k};
    descriptor_t descriptor {-1};
    byte_t* data {};
    std::size_t length {};
    std::uint64_t deadline {};
    void* context {};
};

/** A byte count, accepted descriptor, or negated errno for exactly one submitted request. */
struct io_completion_t {
    io_request_t* request {};
    descriptor_t result {};
    byte_t* data {};
    std::size_t length {};
    std::uintptr_t lease {};
};

/** Counters an engine advances for its one polling owner, on lines no other thread writes. */
struct alignas(false_sharing_bytes_k) io_statistics_t {
    std::uint64_t submissions {}, completions {}, kernel_enters {}, cancellations {}, receive_rearms {},
        bytes_copied {};
};

/** Advances a counter only its owner writes, atomically so other threads may load it relaxed. */
inline void tally(std::uint64_t& counter, std::uint64_t amount = 1) noexcept {
    std::atomic_ref<std::uint64_t> word {counter};
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
    bool open() noexcept {
#if UCALL_OS_WINDOWS_
        auto listener = socket_open(AF_INET);
        if (listener < 0) return false;
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
        if (!ready || descriptors[0] < 0 || !nonblocking(descriptors[0]) || !nonblocking(descriptors[1])) return false;
#else
        int sockets[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return false;
        descriptors[0] = sockets[0];
        descriptors[1] = sockets[1];
        if (!nonblocking(descriptors[0]) || !nonblocking(descriptors[1])) return false;
#if defined(SO_NOSIGPIPE)
        int enabled = 1;
        if (socket_option(descriptors[1], SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) return false;
#endif // defined(SO_NOSIGPIPE)
#endif // UCALL_OS_WINDOWS_
        request = {io_operation_t::read_k, descriptors[0], bytes, sizeof(bytes), 0, nullptr};
        return true;
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
#if UCALL_OS_LINUX_
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

/** An intrusive FIFO of engine operations, linked through their `next` indices. */
struct operation_list_t {
    static constexpr unsigned absent_k = std::numeric_limits<unsigned>::max();
    unsigned head {absent_k}, tail {absent_k};
    template <typename operations_type_>
    void push(operations_type_& operations, unsigned index) noexcept {
        operations[index].next = absent_k;
        if (tail != absent_k) operations[tail].next = index;
        else head = index;
        tail = index;
    }
    template <typename operations_type_>
    unsigned pop(operations_type_& operations) noexcept {
        auto index = head;
        if (index == absent_k) return index;
        head = operations[index].next;
        if (head == absent_k) tail = absent_k;
        return index;
    }
};

/** Readiness operations retain connect progress and cancellation beside the durable request. */
enum class operation_stage_t { fresh_k, started_k, cancelled_k };
struct readiness_operation_t {
    io_request_t* request {};
    operation_stage_t stage {operation_stage_t::fresh_k};
    unsigned next {operation_list_t::absent_k};
};

#if UCALL_OS_POSIX_
inline short io_events(io_operation_t operation) noexcept {
    return io_direction(operation) == io_direction_t::transmit_k ? POLLOUT : POLLIN;
}
enum class io_interest_t { unarmed_k, armed_k, ready_k };

/** Performs the syscall, probing a pending connect only once @p interest reports readiness. */
inline descriptor_t attempt_io(readiness_operation_t& operation, io_interest_t interest,
                               io_statistics_t& statistics) noexcept {
    if (operation.stage == operation_stage_t::cancelled_k) return -ECANCELED;
    auto& request = *operation.request;
    if (request.operation == io_operation_t::connect_k && operation.stage != operation_stage_t::fresh_k &&
        interest != io_interest_t::ready_k)
        return -EAGAIN;
    tally(statistics.kernel_enters);
    auto descriptor = static_cast<int>(request.descriptor);
    ssize_t result = -1;
    auto length = std::min<std::size_t>(request.length, std::numeric_limits<int>::max());
    switch (request.operation) {
    case io_operation_t::accept_k: return accepted_socket(accept(descriptor, nullptr, nullptr));
    case io_operation_t::connect_k:
        if (operation.stage == operation_stage_t::fresh_k) {
            operation.stage = operation_stage_t::started_k;
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
    case io_operation_t::receive_k: result = recv(descriptor, request.data, length, 0); break;
    case io_operation_t::send_k:
#if UCALL_OS_LINUX_ || UCALL_OS_FREEBSD_
        result = send(descriptor, request.data, length, MSG_NOSIGNAL);
        break;
#else
        result = send(descriptor, request.data, length, 0);
        break;
#endif
    case io_operation_t::read_k: result = read(descriptor, request.data, length); break;
    case io_operation_t::close_k: return socket_close(request.descriptor) == 0 || errno == EINTR ? 0 : -errno;
    }
    return result >= 0 ? static_cast<descriptor_t>(result) : -errno;
}
inline bool io_pending(descriptor_t result) noexcept {
    return result == -EAGAIN || result == -EWOULDBLOCK || result == -EINPROGRESS || result == -EINTR;
}

#endif // UCALL_OS_POSIX_

#if UCALL_OS_POSIX_

/** Nonblocking POSIX syscalls, completed through poll readiness. */
template <typename allocator_type_ = st::default_allocator<byte_t>>
struct posix_engine {
    using allocator_t = allocator_type_;
    template <typename other_allocator_>
    using rebind_allocator = posix_engine<other_allocator_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    static constexpr unsigned absent_k = operation_list_t::absent_k;
    struct operation_t : readiness_operation_t {
        unsigned polled {absent_k};
    };
    st::basic_vector<operation_t, rebound_allocator<operation_t>> operations {};
    st::basic_vector<pollfd, rebound_allocator<pollfd>> polling {};
    st::basic_vector<unsigned, rebound_allocator<unsigned>> polled {};
    operation_list_t free_operations, fresh_operations;
    unsigned waiting {};
    io_statistics_t statistics {};
    descriptor_t open_socket(int family) noexcept { return socket_open(family); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept { return descriptor; }
    int close_socket(descriptor_t descriptor) noexcept { return socket_close(descriptor); }
    void release(io_completion_t const&) noexcept {}
    ucall_status_t cancel(io_request_t& request) noexcept {
        for (unsigned i = 0; i != operations.size(); ++i)
            if (operations[i].request == &request) {
                tally(statistics.cancellations);
                operations[i].stage = operation_stage_t::cancelled_k;
                if (operations[i].polled != absent_k) {
                    unpoll(operations[i]);
                    fresh_operations.push(operations, i);
                }
                return ucall_status_success_k;
            }
        return ucall_status_not_found_k;
    }
    explicit posix_engine(allocator_t const& allocator = {}) noexcept
        : operations(rebound_allocator<operation_t> {allocator}), polling(rebound_allocator<pollfd> {allocator}),
          polled(rebound_allocator<unsigned> {allocator}) {}
    posix_engine(posix_engine const&) = delete;
    posix_engine& operator=(posix_engine const&) = delete;
    posix_engine(posix_engine&&) = delete;
    posix_engine& operator=(posix_engine&&) = delete;
    ~posix_engine() noexcept { stop(); }
    ucall_status_t open(std::size_t, std::size_t capacity) noexcept {
        if (st::failed(operations.resize(capacity)) || st::failed(polling.resize(capacity)) ||
            st::failed(polled.resize(capacity)))
            return ucall_status_out_of_memory_k;
        stop();
        return ucall_status_success_k;
    }
    void stop() noexcept {
        free_operations = fresh_operations = {};
        waiting = 0;
        for (unsigned i = 0; i != operations.size(); ++i) {
            operations[i] = {};
            free_operations.push(operations, i);
        }
    }
    ucall_status_t submit(io_request_t& request) noexcept {
        auto index = free_operations.pop(operations);
        if (index == absent_k) return ucall_status_contended_k;
        operations[index] = {};
        operations[index].request = &request;
        fresh_operations.push(operations, index);
        tally(statistics.submissions);
        return ucall_status_success_k;
    }
    void unpoll(operation_t& operation) noexcept {
        auto position = operation.polled;
        --waiting;
        polling[position] = polling[waiting];
        polled[position] = polled[waiting];
        operations[polled[position]].polled = position;
        operation.polled = absent_k;
    }
    io_completion_t finish(unsigned index, descriptor_t result) noexcept {
        auto& operation = operations[index];
        auto& request = *operation.request;
        if (operation.polled != absent_k) unpoll(operation);
        if (request.operation == io_operation_t::close_k && result >= 0) request.descriptor = -1;
        operation.request = nullptr;
        free_operations.push(operations, index);
        tally(statistics.completions);
        return {&request, result};
    }
    int poll(span<io_completion_t> completions, io_wait_t wait_policy, std::uint64_t deadline = 0) noexcept {
        std::size_t count = 0;
        for (unsigned round = 0; round != 2; ++round) {
            auto now = monotonic_ns();
            auto wait = wait_policy == io_wait_t::blocking_k ? std::numeric_limits<std::uint64_t>::max() : 0;
            if (deadline)
                wait = std::min(wait, deadline > now ? (deadline - now) / 1000 + ((deadline - now) % 1000 != 0) : 0);
            while (count != completions.size()) {
                auto index = fresh_operations.pop(operations);
                if (index == absent_k) break;
                auto& operation = operations[index];
                auto& request = *operation.request;
                auto result = request.deadline && now >= request.deadline
                                  ? -ETIMEDOUT
                                  : attempt_io(operation, io_interest_t::unarmed_k, statistics);
                if (!io_pending(result)) {
                    completions[count++] = finish(index, result);
                    continue;
                }
                operation.polled = waiting;
                polling[waiting] = {static_cast<int>(request.descriptor), io_events(request.operation), 0};
                polled[waiting++] = index;
            }
            for (unsigned i = 0; i != waiting && count != completions.size();) {
                auto& operation = operations[polled[i]];
                auto& request = *operation.request;
                bool expired = request.deadline && now >= request.deadline;
                if (expired || polling[i].revents) {
                    auto result = expired ? -ETIMEDOUT : attempt_io(operation, io_interest_t::ready_k, statistics);
                    polling[i].revents = 0;
                    if (!io_pending(result)) {
                        completions[count++] = finish(polled[i], result);
                        continue;
                    }
                }
                if (request.deadline) wait = std::min(wait, (request.deadline - now + 999) / 1000);
                ++i;
            }
            if (count || round || !waiting) break;
            int timeout = wait == std::numeric_limits<std::uint64_t>::max()
                              ? -1
                              : static_cast<int>(std::min<std::uint64_t>(wait / 1000 + (wait % 1000 != 0),
                                                                         std::numeric_limits<int>::max()));
            tally(statistics.kernel_enters);
            int result = ::poll(polling.data(), static_cast<nfds_t>(waiting), timeout);
            if (result < 0 && errno != EINTR) return -errno;
        }
        return static_cast<int>(count);
    }
};

using posix_engine_t = posix_engine<>;

#endif // UCALL_OS_POSIX_

#if UCALL_OS_POSIX_

/** Each descriptor stays registered edge-triggered until `close_socket` or a close request, aimed
 *  at its latest operation in each direction. */
template <typename readiness_type_, typename allocator_type_ = st::default_allocator<byte_t>>
struct readiness_engine {
    using allocator_t = allocator_type_;
    template <typename other_allocator_>
    using rebind_allocator =
        readiness_engine<typename readiness_type_::template rebind_allocator<other_allocator_>, other_allocator_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    static constexpr unsigned absent_k = operation_list_t::absent_k;
    struct operation_t : readiness_operation_t {
        io_interest_t interest {io_interest_t::unarmed_k};
        unsigned timed {absent_k};
    };
    descriptor_t open_socket(int family) noexcept { return socket_open(family); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept { return descriptor; }
    int close_socket(descriptor_t descriptor) noexcept {
        readiness.remove(descriptor);
        return socket_close(descriptor);
    }
    void release(io_completion_t const&) noexcept {}
    ucall_status_t cancel(io_request_t& request) noexcept {
        for (unsigned i = 0; i != operations.size(); ++i)
            if (operations[i].request == &request) {
                tally(statistics.cancellations);
                operations[i].stage = operation_stage_t::cancelled_k;
                if (operations[i].interest == io_interest_t::armed_k) wake(i);
                return ucall_status_success_k;
            }
        return ucall_status_not_found_k;
    }
    explicit readiness_engine(allocator_t const& allocator = {}) noexcept
        : operations(rebound_allocator<operation_t> {allocator}), timed(rebound_allocator<unsigned> {allocator}),
          readiness(allocator) {}
    readiness_engine(readiness_engine const&) = delete;
    readiness_engine& operator=(readiness_engine const&) = delete;
    readiness_engine(readiness_engine&&) = delete;
    readiness_engine& operator=(readiness_engine&&) = delete;
    st::basic_vector<operation_t, rebound_allocator<operation_t>> operations {};
    st::basic_vector<unsigned, rebound_allocator<unsigned>> timed {};
    readiness_type_ readiness {};
    operation_list_t free_operations, fresh_operations, ready_operations;
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
        tally(statistics.submissions);
        return ucall_status_success_k;
    }
    void wake(unsigned index) noexcept {
        operations[index].interest = io_interest_t::ready_k;
        ready_operations.push(operations, index);
    }
    io_completion_t finish(unsigned index, descriptor_t result) noexcept {
        auto& operation = operations[index];
        auto& request = *operation.request;
        if (operation.timed != absent_k) {
            timed[operation.timed] = timed.back();
            operations[timed.back()].timed = operation.timed;
            timed.pop_back();
        }
        if (request.operation == io_operation_t::close_k && result >= 0) request.descriptor = -1;
        operation = {};
        free_operations.push(operations, index);
        --active;
        tally(statistics.completions);
        return {&request, result};
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
                    result = attempt_io(operation, operation.interest, statistics);
                } while (fired && result == -EINTR);
            }
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
            count = progress(fresh_operations, completions, count, now);
            count = progress(ready_operations, completions, count, now);
            if (count || round || !active) break;
            int timeout = wait == std::numeric_limits<std::uint64_t>::max()
                              ? -1
                              : static_cast<int>(std::min<std::uint64_t>(wait / 1'000'000 + (wait % 1'000'000 != 0),
                                                                         std::numeric_limits<int>::max()));
            tally(statistics.kernel_enters);
            int result = readiness.wait(timeout, [&](unsigned index, descriptor_t descriptor, short events) noexcept {
                auto& operation = operations[index];
                if (operation.interest == io_interest_t::armed_k && operation.request->descriptor == descriptor &&
                    (events & io_events(operation.request->operation)))
                    wake(index);
            });
            if (result < 0 && result != -EINTR) return result;
        }
        return static_cast<int>(count);
    }
    void stop() noexcept {
        free_operations = fresh_operations = ready_operations = {};
        timed.clear();
        active = 0;
        for (unsigned i = 0; i != operations.size(); ++i) {
            operations[i] = {};
            free_operations.push(operations, i);
        }
    }
    ~readiness_engine() noexcept { stop(); }
};
#endif

#if UCALL_OS_LINUX_

/** One registered descriptor and the operation waiting in each direction. */
struct readiness_watch_t {
    std::int32_t descriptor {-1};
    std::uint32_t generation {}; // Rides in the event, so stale events never wake a reused watch.
    std::uint32_t receive_operation {operation_list_t::absent_k};
    std::uint32_t transmit_operation {operation_list_t::absent_k};
};
static_assert(sizeof(readiness_watch_t) == 16);

/** Registers each descriptor once; a descriptor-addressed index finds its watch,
 *  at most half full. */
template <typename allocator_type_ = st::default_allocator<byte_t>>
struct epoll_readiness {
    using allocator_t = allocator_type_;
    template <typename other_allocator_>
    using rebind_allocator = epoll_readiness<other_allocator_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    static constexpr std::uint32_t absent_k = operation_list_t::absent_k;
    explicit epoll_readiness(allocator_t const& allocator = {}) noexcept
        : events(rebound_allocator<epoll_event> {allocator}), watches(rebound_allocator<readiness_watch_t> {allocator}),
          watch_slots(rebound_allocator<std::uint32_t> {allocator}),
          free_watches(rebound_allocator<std::uint32_t> {allocator}) {}
    epoll_readiness(epoll_readiness const&) = delete;
    epoll_readiness& operator=(epoll_readiness const&) = delete;
    epoll_readiness(epoll_readiness&&) = delete;
    epoll_readiness& operator=(epoll_readiness&&) = delete;
    int descriptor {-1};
    st::basic_vector<epoll_event, rebound_allocator<epoll_event>> events {};
    st::basic_vector<readiness_watch_t, rebound_allocator<readiness_watch_t>> watches {};
    st::basic_vector<std::uint32_t, rebound_allocator<std::uint32_t>> watch_slots {}, free_watches {};
    ucall_status_t open(std::size_t capacity) noexcept {
        if (st::failed(events.resize(capacity)) || st::failed(watches.resize(capacity)) ||
            st::failed(watch_slots.resize(std::bit_ceil(capacity * 2))) || st::failed(free_watches.reserve(capacity)))
            return ucall_status_out_of_memory_k;
        free_watches.clear();
        for (std::size_t index = 0; index != capacity; ++index) {
            watches[index] = {};
            [[maybe_unused]] st::status_t const freed = free_watches.push_back(st::assume_reserved,
                                                                               static_cast<std::uint32_t>(index));
        }
        for (auto& slot : watch_slots) slot = absent_k;
        descriptor = epoll_create1(EPOLL_CLOEXEC);
        return descriptor < 0 ? ucall_status_io_k : ucall_status_success_k;
    }

    /** The slot naming the watch of @p watched, or the vacant slot that ends its probe. */
    std::size_t slot_of(descriptor_t watched) const noexcept {
        std::size_t mask = watch_slots.size() - 1;
        std::size_t slot = static_cast<std::size_t>(watched) & mask;
        while (watch_slots[slot] != absent_k && watches[watch_slots[slot]].descriptor != watched)
            slot = (slot + 1) & mask;
        return slot;
    }

    /** Points @p direction of the descriptor's watch at operation @p index,
     *  registering it on first use. */
    int arm(descriptor_t watched, io_direction_t direction, unsigned index, io_statistics_t& statistics) noexcept {
        std::size_t slot = slot_of(watched);
        if (watch_slots[slot] == absent_k) {
            if (free_watches.empty()) return -ENOBUFS;
            std::uint32_t chosen = free_watches.back();
            epoll_event event {};
            event.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET;
            event.data.u64 = std::uint64_t {chosen} << 32 | watches[chosen].generation;
            tally(statistics.kernel_enters);
            if (epoll_ctl(descriptor, EPOLL_CTL_ADD, static_cast<int>(watched), &event) != 0) return -errno;
            free_watches.pop_back();
            watches[chosen].descriptor = static_cast<std::int32_t>(watched);
            watch_slots[slot] = chosen;
        }
        readiness_watch_t& watch = watches[watch_slots[slot]];
        (direction == io_direction_t::receive_k ? watch.receive_operation : watch.transmit_operation) = index;
        return 0;
    }

    /** Unregisters @p watched and frees its watch, shifting back the probe run behind it. */
    void remove(descriptor_t watched) noexcept {
        std::size_t slot = slot_of(watched);
        std::uint32_t chosen = watch_slots[slot];
        if (chosen == absent_k) return;
        epoll_ctl(descriptor, EPOLL_CTL_DEL, static_cast<int>(watched), nullptr);
        watches[chosen] = {-1, watches[chosen].generation + 1};
        [[maybe_unused]] st::status_t const freed = free_watches.push_back(st::assume_reserved, std::uint32_t {chosen});
        std::size_t mask = watch_slots.size() - 1;
        for (std::size_t next = (slot + 1) & mask; watch_slots[next] != absent_k; next = (next + 1) & mask) {
            std::size_t home = static_cast<std::size_t>(watches[watch_slots[next]].descriptor) & mask;
            // Linear probing finds an entry only while no vacancy lies
            // between its home and its slot.
            if (((next - home) & mask) >= ((next - slot) & mask)) {
                watch_slots[slot] = watch_slots[next];
                slot = next;
            }
        }
        watch_slots[slot] = absent_k;
    }
    template <typename callback_type_>
    int wait(int timeout, callback_type_&& fired) noexcept {
        int count = epoll_wait(descriptor, events.data(),
                               static_cast<int>(std::min<std::size_t>(events.size(), std::numeric_limits<int>::max())),
                               timeout);
        if (count < 0) return -errno;
        for (int i = 0; i != count; ++i) {
            auto flags = events[i].events;
            readiness_watch_t const& watch = watches[static_cast<std::size_t>(events[i].data.u64 >> 32)];
            if (watch.generation != static_cast<std::uint32_t>(events[i].data.u64)) continue;
            if ((flags & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)) && watch.receive_operation != absent_k)
                fired(watch.receive_operation, watch.descriptor, short {POLLIN});
            if ((flags & (EPOLLOUT | EPOLLHUP | EPOLLERR)) && watch.transmit_operation != absent_k)
                fired(watch.transmit_operation, watch.descriptor, short {POLLOUT});
        }
        return count;
    }
    ~epoll_readiness() noexcept {
        if (descriptor >= 0) close(descriptor);
    }
};
using epoll_readiness_t = epoll_readiness<>;
using linux_epoll_engine_t = readiness_engine<epoll_readiness_t>;
#endif

#if UCALL_OS_APPLE_ || UCALL_OS_FREEBSD_
template <typename allocator_type_ = st::default_allocator<byte_t>>
struct kqueue_readiness {
    using allocator_t = allocator_type_;
    template <typename other_allocator_>
    using rebind_allocator = kqueue_readiness<other_allocator_>;
    using events_allocator_t = typename std::allocator_traits<allocator_t>::template rebind_alloc<struct kevent>;
    explicit kqueue_readiness(allocator_t const& allocator = {}) noexcept : events(events_allocator_t {allocator}) {}
    kqueue_readiness(kqueue_readiness const&) = delete;
    kqueue_readiness& operator=(kqueue_readiness const&) = delete;
    kqueue_readiness(kqueue_readiness&&) = delete;
    kqueue_readiness& operator=(kqueue_readiness&&) = delete;
    int descriptor {-1};
    st::basic_vector<struct kevent, events_allocator_t> events {};
    ucall_status_t open(std::size_t capacity) noexcept {
        if (st::failed(events.resize(capacity))) return ucall_status_out_of_memory_k;
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
        tally(statistics.kernel_enters);
        return kevent(descriptor, &change, 1, nullptr, 0, nullptr) == 0 ? 0 : -errno;
    }
    // Closing a descriptor drops its knotes.
    void remove(descriptor_t) noexcept {}
    template <typename callback_type_>
    int wait(int timeout, callback_type_&& fired) noexcept {
        timespec duration {timeout / 1000, (timeout % 1000) * 1'000'000L};
        int count = kevent(descriptor, nullptr, 0, events.data(),
                           static_cast<int>(std::min<std::size_t>(events.size(), std::numeric_limits<int>::max())),
                           timeout < 0 ? nullptr : &duration);
        if (count < 0) return -errno;
        for (int i = 0; i != count; ++i) {
            if (events[i].flags & EV_ERROR) return -static_cast<int>(events[i].data);
            fired(static_cast<unsigned>(reinterpret_cast<std::uintptr_t>(events[i].udata)),
                  static_cast<descriptor_t>(events[i].ident),
                  static_cast<short>(events[i].filter == EVFILT_READ ? POLLIN : POLLOUT));
        }
        return count;
    }
    ~kqueue_readiness() noexcept {
        if (descriptor >= 0) close(descriptor);
    }
};
using kqueue_readiness_t = kqueue_readiness<>;
using kqueue_engine_t = readiness_engine<kqueue_readiness_t>;
#endif

#if UCALL_OS_WINDOWS_

/** Overlapped socket operations retain their storage through cancellation completion. */
template <typename allocator_type_ = st::default_allocator<byte_t>>
struct windows_iocp_engine {
    using allocator_t = allocator_type_;
    template <typename other_allocator_>
    using rebind_allocator = windows_iocp_engine<other_allocator_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    enum class operation_stage_t { pending_k, immediate_k, cancelling_k, timing_out_k };
    static constexpr unsigned absent_k = operation_list_t::absent_k;
    struct operation_t {
        OVERLAPPED overlapped {};
        io_request_t* request {};
        SOCKET accepted {INVALID_SOCKET};
        descriptor_t immediate {};
        operation_stage_t stage {operation_stage_t::pending_k};
        unsigned next {absent_k}, timed {absent_k};
        byte_t addresses[2 * (sizeof(sockaddr_storage) + 16)] {};
    };
    descriptor_t open_socket(int family) noexcept { return socket_open(family); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept { return descriptor; }
    int close_socket(descriptor_t descriptor) noexcept { return socket_close(descriptor); }
    void release(io_completion_t const&) noexcept {}
    ucall_status_t cancel(io_request_t& request) noexcept {
        for (auto& operation : operations)
            if (operation.request == &request) {
                if (operation.stage == operation_stage_t::pending_k) {
                    tally(statistics.cancellations);
                    operation.stage = operation_stage_t::cancelling_k;
                    CancelIoEx(reinterpret_cast<HANDLE>(request.descriptor), &operation.overlapped);
                }
                return ucall_status_success_k;
            }
        return ucall_status_not_found_k;
    }
    explicit windows_iocp_engine(allocator_t const& allocator = {}) noexcept
        : operations(rebound_allocator<operation_t> {allocator}), timed(rebound_allocator<unsigned> {allocator}),
          entries(rebound_allocator<OVERLAPPED_ENTRY> {allocator}) {}
    windows_iocp_engine(windows_iocp_engine const&) = delete;
    windows_iocp_engine& operator=(windows_iocp_engine const&) = delete;
    windows_iocp_engine(windows_iocp_engine&&) = delete;
    windows_iocp_engine& operator=(windows_iocp_engine&&) = delete;
    HANDLE port {};
    st::basic_vector<operation_t, rebound_allocator<operation_t>> operations {};
    st::basic_vector<unsigned, rebound_allocator<unsigned>> timed {};
    st::basic_vector<OVERLAPPED_ENTRY, rebound_allocator<OVERLAPPED_ENTRY>> entries {};
    operation_list_t free_operations, immediate_operations;
    std::size_t active {};
    io_statistics_t statistics {};
    ucall_status_t open(std::size_t, std::size_t capacity) noexcept {
        if (!sockets_start()) return ucall_status_io_k;
        if (st::failed(operations.resize(capacity)) || st::failed(timed.reserve(capacity)) ||
            st::failed(entries.resize(capacity)))
            return ucall_status_out_of_memory_k;
        for (unsigned i = 0; i != operations.size(); ++i) free_operations.push(operations, i);
        port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
        return port ? ucall_status_success_k : ucall_status_io_k;
    }
    void untime(operation_t& operation) noexcept {
        timed[operation.timed] = timed.back();
        operations[timed.back()].timed = operation.timed;
        timed.pop_back();
        operation.timed = absent_k;
    }
    template <typename function_type_>
    bool extension(SOCKET socket, GUID id, function_type_& function) noexcept {
        DWORD bytes {};
        return WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id), &function, sizeof(function),
                        &bytes, nullptr, nullptr) == 0;
    }
    ucall_status_t submit(io_request_t& request) noexcept {
        auto index = free_operations.pop(operations);
        if (index == absent_k) return ucall_status_contended_k;
        auto* operation = &operations[index];
        *operation = {};
        operation->request = &request;
        tally(statistics.submissions);
        auto socket = static_cast<SOCKET>(request.descriptor);
        auto complete_immediately = [&](descriptor_t result) noexcept {
            operation->immediate = result;
            operation->stage = operation_stage_t::immediate_k;
            immediate_operations.push(operations, index);
            ++active;
            return ucall_status_success_k;
        };
        if (request.operation == io_operation_t::close_k)
            return complete_immediately(socket_close(request.descriptor) == 0 ? 0 : -socket_last_error());
        if (!CreateIoCompletionPort(reinterpret_cast<HANDLE>(socket), port, 0, 0)) return complete_immediately(-EIO);
        DWORD bytes {}, flags {};
        int result = SOCKET_ERROR;
        switch (request.operation) {
        case io_operation_t::accept_k: {
            LPFN_ACCEPTEX accept_ex {};
            sockaddr_storage address {};
            int length = sizeof(address);
            if (!extension(socket, WSAID_ACCEPTEX, accept_ex) ||
                getsockname(socket, reinterpret_cast<sockaddr*>(&address), &length) != 0)
                return complete_immediately(-socket_last_error());
            operation->accepted = static_cast<SOCKET>(socket_open(address.ss_family));
            if (operation->accepted == INVALID_SOCKET) return complete_immediately(-socket_last_error());
            result = accept_ex(socket, operation->accepted, operation->addresses, 0, sizeof(sockaddr_storage) + 16,
                               sizeof(sockaddr_storage) + 16, &bytes, &operation->overlapped)
                         ? 0
                         : SOCKET_ERROR;
            break;
        }
        case io_operation_t::connect_k: {
            LPFN_CONNECTEX connect_ex {};
            if (!extension(socket, WSAID_CONNECTEX, connect_ex)) return complete_immediately(-socket_last_error());
            auto remote = reinterpret_cast<sockaddr*>(request.data);
            sockaddr_storage local {};
            local.ss_family = remote->sa_family;
            int length = local.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
            if (bind(socket, reinterpret_cast<sockaddr*>(&local), length) != 0)
                return complete_immediately(-socket_last_error());
            result = connect_ex(socket, remote, static_cast<int>(request.length), nullptr, 0, &bytes,
                                &operation->overlapped)
                         ? 0
                         : SOCKET_ERROR;
            break;
        }
        case io_operation_t::receive_k:
        case io_operation_t::read_k: {
            WSABUF buffer {static_cast<ULONG>(std::min<std::size_t>(request.length, std::numeric_limits<int>::max())),
                           reinterpret_cast<char*>(request.data)};
            result = WSARecv(socket, &buffer, 1, &bytes, &flags, &operation->overlapped, nullptr);
            break;
        }
        case io_operation_t::send_k: {
            WSABUF buffer {static_cast<ULONG>(std::min<std::size_t>(request.length, std::numeric_limits<int>::max())),
                           reinterpret_cast<char*>(request.data)};
            result = WSASend(socket, &buffer, 1, &bytes, 0, &operation->overlapped, nullptr);
            break;
        }
        case io_operation_t::close_k: break;
        }
        tally(statistics.kernel_enters);
        if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
            auto error = socket_last_error();
            if (operation->accepted != INVALID_SOCKET) {
                closesocket(operation->accepted);
                operation->accepted = INVALID_SOCKET;
            }
            return complete_immediately(-error);
        }
        if (request.deadline) {
            operation->timed = static_cast<unsigned>(timed.size());
            [[maybe_unused]] st::status_t const tracked = timed.push_back(st::assume_reserved, unsigned {index});
        }
        ++active;
        return ucall_status_success_k;
    }
    io_completion_t finish(operation_t& operation, descriptor_t result) noexcept {
        auto& request = *operation.request;
        if (operation.timed != absent_k) untime(operation);
        if (operation.stage == operation_stage_t::timing_out_k && result == -ECANCELED) result = -ETIMEDOUT;
        if (request.operation == io_operation_t::accept_k && operation.accepted != INVALID_SOCKET) {
            if (result >= 0) {
                auto listener = static_cast<SOCKET>(request.descriptor);
                if (setsockopt(operation.accepted, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                               reinterpret_cast<char const*>(&listener), sizeof(listener)) == 0)
                    result = static_cast<descriptor_t>(operation.accepted);
                else result = -socket_last_error();
            }
            if (result < 0) closesocket(operation.accepted);
        }
        else if (request.operation == io_operation_t::connect_k && result >= 0 &&
                 setsockopt(static_cast<SOCKET>(request.descriptor), SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, nullptr,
                            0) != 0)
            result = -socket_last_error();
        if (request.operation == io_operation_t::close_k && result >= 0) request.descriptor = -1;
        operation.request = nullptr;
        free_operations.push(operations, static_cast<unsigned>(&operation - operations.data()));
        --active;
        tally(statistics.completions);
        return {&request, result};
    }
    int poll(span<io_completion_t> completions, io_wait_t wait_policy, std::uint64_t deadline = 0) noexcept {
        std::size_t count {};
        while (count < completions.size() && active) {
            auto now = monotonic_ns();
            auto wait = wait_policy == io_wait_t::blocking_k && !count ? INFINITE : DWORD {0};
            if (deadline) {
                auto duration = deadline > now ? deadline - now : 0;
                wait = std::min<DWORD>(wait, static_cast<DWORD>(std::min<std::uint64_t>(
                                                 duration / 1'000'000 + (duration % 1'000'000 != 0), INFINITE - 1)));
            }
            for (std::size_t i = 0; i != timed.size();) {
                auto& operation = operations[timed[i]];
                auto expiry = operation.request->deadline;
                if (expiry > now) {
                    wait = std::min<DWORD>(
                        wait, static_cast<DWORD>(std::min<std::uint64_t>(
                                  (expiry - now) / 1'000'000 + ((expiry - now) % 1'000'000 != 0), INFINITE - 1)));
                    ++i;
                    continue;
                }
                if (operation.stage == operation_stage_t::pending_k) {
                    operation.stage = operation_stage_t::timing_out_k;
                    CancelIoEx(reinterpret_cast<HANDLE>(operation.request->descriptor), &operation.overlapped);
                }
                untime(operation);
            }
            if (auto index = immediate_operations.pop(operations); index != absent_k) {
                completions[count++] = finish(operations[index], operations[index].immediate);
                continue;
            }
            ULONG dequeued {};
            auto limit = static_cast<ULONG>(std::min(completions.size() - count, entries.size()));
            tally(statistics.kernel_enters);
            if (!GetQueuedCompletionStatusEx(port, entries.data(), limit, &dequeued, wait, FALSE)) {
                if (GetLastError() == WAIT_TIMEOUT) {
                    if (wait_policy == io_wait_t::blocking_k && !count && (!deadline || monotonic_ns() < deadline))
                        continue;
                    break;
                }
                return -EIO;
            }
            for (ULONG i = 0; i != dequeued; ++i) {
                auto& operation = *reinterpret_cast<operation_t*>(entries[i].lpOverlapped);
                DWORD bytes {}, flags {};
                // The per-packet status lives in the OVERLAPPED; this reads it without waiting.
                descriptor_t result = WSAGetOverlappedResult(static_cast<SOCKET>(operation.request->descriptor),
                                                             &operation.overlapped, &bytes, FALSE, &flags)
                                          ? static_cast<descriptor_t>(bytes)
                                          : -socket_last_error();
                completions[count++] = finish(operation, result);
            }
        }
        return static_cast<int>(count);
    }
    void stop() noexcept {
        for (auto& operation : operations)
            if (operation.request && operation.stage != operation_stage_t::immediate_k) {
                if (operation.stage == operation_stage_t::pending_k) operation.stage = operation_stage_t::cancelling_k;
                CancelIoEx(reinterpret_cast<HANDLE>(operation.request->descriptor), &operation.overlapped);
            }
        io_completion_t discarded[32];
        while (active) {
            int count = poll(discarded, io_wait_t::blocking_k);
            if (count < 0) break;
            for (int i = 0; i != count; ++i)
                if (discarded[i].request->operation == io_operation_t::accept_k && discarded[i].result >= 0)
                    socket_close(discarded[i].result);
        }
    }
    ~windows_iocp_engine() noexcept {
        stop();
        if (port) CloseHandle(port);
    }
};
using windows_iocp_engine_t = windows_iocp_engine<>;
#endif

} // namespace unum::ucall

#if UCALL_WITH_LINUX_URING
#include "ucall/uring612.hpp"
#include "ucall/uring700.hpp"
#endif
