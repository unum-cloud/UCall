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
#include <chrono>
#include <new>

#include "ucall/types.hpp"

#if UCALL_OS_WINDOWS_
#include <mswsock.h>
#include <ws2tcpip.h>
#else
#include <fcntl.h>
#include <netdb.h>
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
inline bool sockets_start() noexcept {
    static bool ready = [] {
        WSADATA data {};
        return WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }();
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
#if UCALL_OS_APPLE_
    int enabled = 1;
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
#if UCALL_OS_APPLE_
    int enabled = 1;
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

/** A pollable wakeup with the same request lifetime as socket operations. */
struct wake_channel_t {
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
};

/** Readiness slots retain connect progress and cancellation beside the durable request. */
struct io_slot_t {
    io_request_t* request {};
    bool started {}, cancelled {};
};

#if UCALL_OS_POSIX_
inline descriptor_t attempt_io(io_slot_t& slot, bool ready) noexcept {
    if (slot.cancelled) return -ECANCELED;
    auto& request = *slot.request;
    auto descriptor = static_cast<int>(request.descriptor);
    ssize_t result = -1;
    auto length = std::min<std::size_t>(request.length, std::numeric_limits<int>::max());
    switch (request.operation) {
    case io_operation_t::accept_k: return accepted_socket(accept(descriptor, nullptr, nullptr));
    case io_operation_t::connect_k:
        if (!slot.started) {
            slot.started = true;
            if (connect(descriptor, reinterpret_cast<sockaddr*>(request.data),
                        static_cast<socklen_t>(request.length)) == 0)
                return 0;
            return -errno;
        }
        if (ready) {
            int error {};
            socklen_t size = sizeof(error);
            return getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &size) == 0 ? -error : -errno;
        }
        return -EAGAIN;
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
struct posix_engine_t {
    st::basic_vector<io_slot_t> slots {};
    st::basic_vector<pollfd> polling {};
    std::size_t active {};
    descriptor_t open_socket(int family) noexcept { return socket_open(family); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept { return descriptor; }
    int close_socket(descriptor_t descriptor) noexcept { return socket_close(descriptor); }
    void release(io_completion_t const&) noexcept {}
    bool cancel(io_request_t& request) noexcept {
        for (auto& slot : slots)
            if (slot.request == &request) {
                slot.cancelled = true;
                return true;
            }
        return false;
    }
    posix_engine_t() noexcept = default;
    posix_engine_t(posix_engine_t const&) = delete;
    ~posix_engine_t() noexcept;
    ucall_status_t open(std::size_t depth, std::size_t capacity) noexcept;
    bool submit(io_request_t& request) noexcept;
    int poll(span<io_completion_t> completions, io_wait_t wait_policy, std::uint64_t deadline = 0) noexcept;
    void stop() noexcept;
};
inline ucall_status_t posix_engine_t::open(std::size_t, std::size_t capacity) noexcept {
    return st::succeeded(slots.resize(capacity)) && st::succeeded(polling.resize(capacity))
               ? ucall_status_success_k
               : ucall_status_out_of_memory_k;
}
inline posix_engine_t::~posix_engine_t() noexcept { stop(); }
inline void posix_engine_t::stop() noexcept {
    for (auto& slot : slots) slot.request = nullptr;
    active = 0;
}
inline bool posix_engine_t::submit(io_request_t& request) noexcept {
    for (auto& slot : slots)
        if (!slot.request) {
            slot = {};
            slot.request = &request;
            ++active;
            return true;
        }
    return false;
}
inline int posix_engine_t::poll(span<io_completion_t> completions, io_wait_t wait_policy,
                                std::uint64_t deadline) noexcept {
    std::size_t count = 0;
    for (unsigned round = 0; round != 2; ++round) {
        auto now = monotonic_ns();
        auto wait = wait_policy == io_wait_t::blocking_k ? std::numeric_limits<std::uint64_t>::max() : 0;
        if (deadline)
            wait = std::min(wait, deadline > now ? (deadline - now) / 1000 + ((deadline - now) % 1000 != 0) : 0);
        std::size_t polling_count = 0, ready_index = 0;
        for (std::size_t i = 0; i != slots.size() && count < completions.size(); ++i) {
            auto& slot = slots[i];
            if (!slot.request) continue;
            bool ready = round && polling[ready_index++].revents;
            auto& request = *slot.request;
            descriptor_t result = -EAGAIN;
            if (request.deadline && now >= request.deadline) result = -ETIMEDOUT;
            else result = attempt_io(slot, ready);
            if (!io_pending(result)) {
                if (request.operation == io_operation_t::close_k && result >= 0) request.descriptor = -1;
                completions[count++] = {&request, result};
                slot.request = nullptr;
                --active;
                continue;
            }
            short events = request.operation == io_operation_t::connect_k || request.operation == io_operation_t::send_k
                               ? POLLOUT
                               : POLLIN;
            polling[polling_count++] = {static_cast<int>(request.descriptor), events, 0};
            if (request.deadline && request.deadline > now) {
                auto remaining = (request.deadline - now + 999) / 1000;
                if (remaining < wait) wait = remaining;
            }
        }
        if (count || round || !active) break;
        int timeout = wait == std::numeric_limits<std::uint64_t>::max()
                          ? -1
                          : static_cast<int>(std::min<std::uint64_t>(wait / 1000 + (wait % 1000 != 0),
                                                                     std::numeric_limits<int>::max()));
        int result = ::poll(polling.data(), static_cast<nfds_t>(polling_count), timeout);
        if (result < 0 && errno != EINTR) return -errno;
    }
    return static_cast<int>(count);
}

#endif // UCALL_OS_POSIX_

#if UCALL_OS_POSIX_

/** Readiness engines retain stable slots until their one-shot interest is removed. */
template <typename readiness_type_>
struct readiness_engine {
    struct slot_t : io_slot_t {
        bool armed {}, ready {};
    };
    descriptor_t open_socket(int family) noexcept { return socket_open(family); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept { return descriptor; }
    int close_socket(descriptor_t descriptor) noexcept { return socket_close(descriptor); }
    void release(io_completion_t const&) noexcept {}
    bool cancel(io_request_t& request) noexcept {
        for (auto& slot : slots)
            if (slot.request == &request) {
                slot.cancelled = true;
                return true;
            }
        return false;
    }
    readiness_engine() noexcept = default;
    readiness_engine(readiness_engine const&) = delete;
    st::basic_vector<slot_t> slots {};
    readiness_type_ readiness {};
    std::size_t active {};
    ucall_status_t open(std::size_t, std::size_t capacity) noexcept {
        if (st::failed(slots.resize(capacity))) return ucall_status_out_of_memory_k;
        return readiness.open(capacity);
    }
    bool submit(io_request_t& request) noexcept {
        for (auto& slot : slots)
            if (!slot.request) {
                slot = {};
                slot.request = &request;
                ++active;
                return true;
            }
        return false;
    }
    int poll(span<io_completion_t> completions, io_wait_t wait_policy, std::uint64_t deadline = 0) noexcept {
        if (!completions.size()) return 0;
        std::size_t count {};
        for (unsigned round = 0; round != 2; ++round) {
            auto now = monotonic_ns();
            auto wait = wait_policy == io_wait_t::blocking_k ? std::numeric_limits<std::uint64_t>::max() : 0;
            if (deadline) wait = std::min(wait, deadline > now ? deadline - now : 0);
            for (auto& slot : slots) {
                if (!slot.request || count == completions.size()) continue;
                auto& request = *slot.request;
                bool expired = request.deadline && request.deadline <= now;
                if (!slot.armed || slot.ready || expired || slot.cancelled) {
                    auto result = expired ? -ETIMEDOUT : attempt_io(slot, slot.ready);
                    slot.ready = false;
                    if (!io_pending(result)) {
                        if (slot.armed) readiness.remove(slot);
                        if (request.operation == io_operation_t::close_k && result >= 0) request.descriptor = -1;
                        completions[count++] = {&request, result};
                        slot = {};
                        --active;
                        continue;
                    }
                    int result_arm = readiness.arm(slot);
                    if (result_arm < 0) return result_arm;
                    slot.armed = true;
                }
                if (request.deadline && request.deadline > now) wait = std::min(wait, request.deadline - now);
            }
            if (count || round || !active) break;
            int timeout = wait == std::numeric_limits<std::uint64_t>::max()
                              ? -1
                              : static_cast<int>(std::min<std::uint64_t>(wait / 1'000'000 + (wait % 1'000'000 != 0),
                                                                         std::numeric_limits<int>::max()));
            int result = readiness.wait(timeout);
            if (result < 0 && result != -EINTR) return result;
        }
        return static_cast<int>(count);
    }
    void stop() noexcept {
        for (auto& slot : slots)
            if (slot.request) {
                if (slot.armed) readiness.remove(slot);
                slot = {};
            }
        active = 0;
    }
    ~readiness_engine() noexcept { stop(); }
};
#endif

#if UCALL_OS_LINUX_
struct epoll_readiness_t {
    int descriptor {-1};
    st::basic_vector<epoll_event> events {};
    ucall_status_t open(std::size_t capacity) noexcept {
        if (st::failed(events.resize(capacity))) return ucall_status_out_of_memory_k;
        descriptor = epoll_create1(EPOLL_CLOEXEC);
        return descriptor < 0 ? ucall_status_io_k : ucall_status_success_k;
    }
    template <typename slot_type_>
    int arm(slot_type_& slot) noexcept {
        auto operation = slot.request->operation;
        epoll_event event {};
        event.events = EPOLLONESHOT |
                       (operation == io_operation_t::connect_k || operation == io_operation_t::send_k ? EPOLLOUT
                                                                                                      : EPOLLIN);
        event.data.ptr = &slot;
        int action = slot.armed ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
        return epoll_ctl(descriptor, action, static_cast<int>(slot.request->descriptor), &event) == 0 ? 0 : -errno;
    }
    template <typename slot_type_>
    void remove(slot_type_& slot) noexcept {
        epoll_ctl(descriptor, EPOLL_CTL_DEL, static_cast<int>(slot.request->descriptor), nullptr);
    }
    int wait(int timeout) noexcept;
    ~epoll_readiness_t() noexcept {
        if (descriptor >= 0) close(descriptor);
    }
};
using linux_epoll_engine_t = readiness_engine<epoll_readiness_t>;
inline int epoll_readiness_t::wait(int timeout) noexcept {
    int count = epoll_wait(descriptor, events.data(),
                           static_cast<int>(std::min<std::size_t>(events.size(), std::numeric_limits<int>::max())),
                           timeout);
    if (count < 0) return -errno;
    for (int i = 0; i != count; ++i) static_cast<linux_epoll_engine_t::slot_t*>(events[i].data.ptr)->ready = true;
    return count;
}
#endif

#if UCALL_OS_APPLE_ || UCALL_OS_FREEBSD_
struct kqueue_readiness_t {
    int descriptor {-1};
    st::basic_vector<struct kevent> events {};
    ucall_status_t open(std::size_t capacity) noexcept {
        if (st::failed(events.resize(capacity))) return ucall_status_out_of_memory_k;
        descriptor = kqueue();
        if (descriptor >= 0 && fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0) return ucall_status_success_k;
        return ucall_status_io_k;
    }
    template <typename slot_type_>
    int arm(slot_type_& slot) noexcept {
        auto operation = slot.request->operation;
        struct kevent event {};
        EV_SET(
            &event, static_cast<std::uintptr_t>(slot.request->descriptor),
            operation == io_operation_t::connect_k || operation == io_operation_t::send_k ? EVFILT_WRITE : EVFILT_READ,
            EV_ADD | EV_ONESHOT, 0, 0, &slot);
        return kevent(descriptor, &event, 1, nullptr, 0, nullptr) == 0 ? 0 : -errno;
    }
    template <typename slot_type_>
    void remove(slot_type_& slot) noexcept {
        auto operation = slot.request->operation;
        struct kevent event {};
        EV_SET(
            &event, static_cast<std::uintptr_t>(slot.request->descriptor),
            operation == io_operation_t::connect_k || operation == io_operation_t::send_k ? EVFILT_WRITE : EVFILT_READ,
            EV_DELETE, 0, 0, nullptr);
        kevent(descriptor, &event, 1, nullptr, 0, nullptr);
    }
    int wait(int timeout) noexcept;
    ~kqueue_readiness_t() noexcept {
        if (descriptor >= 0) close(descriptor);
    }
};
using kqueue_engine_t = readiness_engine<kqueue_readiness_t>;
inline int kqueue_readiness_t::wait(int timeout) noexcept {
    timespec duration {timeout / 1000, (timeout % 1000) * 1'000'000L};
    int count = kevent(descriptor, nullptr, 0, events.data(),
                       static_cast<int>(std::min<std::size_t>(events.size(), std::numeric_limits<int>::max())),
                       timeout < 0 ? nullptr : &duration);
    if (count < 0) return -errno;
    for (int i = 0; i != count; ++i) {
        if (events[i].flags & EV_ERROR) return -static_cast<int>(events[i].data);
        static_cast<kqueue_engine_t::slot_t*>(events[i].udata)->ready = true;
    }
    return count;
}
#endif

#if UCALL_OS_WINDOWS_

/** Overlapped socket operations retain their storage through cancellation completion. */
struct windows_iocp_engine_t {
    struct slot_t {
        OVERLAPPED overlapped {};
        io_request_t* request {};
        SOCKET accepted {INVALID_SOCKET};
        descriptor_t immediate {};
        bool posted {}, timed_out {}, cancelling {};
        byte_t addresses[2 * (sizeof(sockaddr_storage) + 16)] {};
    };
    descriptor_t open_socket(int family) noexcept { return socket_open(family); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept { return descriptor; }
    int close_socket(descriptor_t descriptor) noexcept { return socket_close(descriptor); }
    void release(io_completion_t const&) noexcept {}
    bool cancel(io_request_t& request) noexcept {
        for (auto& slot : slots)
            if (slot.request == &request) {
                if (!slot.posted && !slot.cancelling) {
                    slot.cancelling = true;
                    CancelIoEx(reinterpret_cast<HANDLE>(request.descriptor), &slot.overlapped);
                }
                return true;
            }
        return false;
    }
    windows_iocp_engine_t() noexcept = default;
    windows_iocp_engine_t(windows_iocp_engine_t const&) = delete;
    HANDLE port {};
    st::basic_vector<slot_t> slots {};
    std::size_t active {};
    ucall_status_t open(std::size_t, std::size_t capacity) noexcept {
        if (!sockets_start()) return ucall_status_io_k;
        if (st::failed(slots.resize(capacity))) return ucall_status_out_of_memory_k;
        port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
        return port ? ucall_status_success_k : ucall_status_io_k;
    }
    template <typename function_type_>
    bool extension(SOCKET socket, GUID id, function_type_& function) noexcept {
        DWORD bytes {};
        return WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id), &function, sizeof(function),
                        &bytes, nullptr, nullptr) == 0;
    }
    bool submit(io_request_t& request) noexcept {
        slot_t* slot {};
        for (auto& candidate : slots)
            if (!candidate.request) {
                slot = &candidate;
                break;
            }
        if (!slot) return false;
        *slot = {};
        slot->accepted = INVALID_SOCKET;
        slot->request = &request;
        auto socket = static_cast<SOCKET>(request.descriptor);
        auto complete_immediately = [&](descriptor_t result) noexcept {
            slot->immediate = result;
            slot->posted = true;
            if (!PostQueuedCompletionStatus(port, 0, 0, &slot->overlapped)) {
                slot->request = nullptr;
                return false;
            }
            ++active;
            return true;
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
            slot->accepted = static_cast<SOCKET>(socket_open(address.ss_family));
            if (slot->accepted == INVALID_SOCKET) return complete_immediately(-socket_last_error());
            result = accept_ex(socket, slot->accepted, slot->addresses, 0, sizeof(sockaddr_storage) + 16,
                               sizeof(sockaddr_storage) + 16, &bytes, &slot->overlapped)
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
            result = connect_ex(socket, remote, static_cast<int>(request.length), nullptr, 0, &bytes, &slot->overlapped)
                         ? 0
                         : SOCKET_ERROR;
            break;
        }
        case io_operation_t::receive_k:
        case io_operation_t::read_k: {
            WSABUF buffer {static_cast<ULONG>(std::min<std::size_t>(request.length, std::numeric_limits<int>::max())),
                           reinterpret_cast<char*>(request.data)};
            result = WSARecv(socket, &buffer, 1, &bytes, &flags, &slot->overlapped, nullptr);
            break;
        }
        case io_operation_t::send_k: {
            WSABUF buffer {static_cast<ULONG>(std::min<std::size_t>(request.length, std::numeric_limits<int>::max())),
                           reinterpret_cast<char*>(request.data)};
            result = WSASend(socket, &buffer, 1, &bytes, 0, &slot->overlapped, nullptr);
            break;
        }
        case io_operation_t::close_k: break;
        }
        if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
            auto error = socket_last_error();
            if (slot->accepted != INVALID_SOCKET) {
                closesocket(slot->accepted);
                slot->accepted = INVALID_SOCKET;
            }
            return complete_immediately(-error);
        }
        ++active;
        return true;
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
            for (auto& slot : slots)
                if (slot.request && slot.request->deadline && !slot.cancelling) {
                    auto deadline = slot.request->deadline;
                    if (deadline <= now) {
                        slot.timed_out = true;
                        slot.cancelling = true;
                        CancelIoEx(reinterpret_cast<HANDLE>(slot.request->descriptor), &slot.overlapped);
                    }
                    else
                        wait = std::min<DWORD>(
                            wait,
                            static_cast<DWORD>(std::min<std::uint64_t>(
                                (deadline - now) / 1'000'000 + ((deadline - now) % 1'000'000 != 0), INFINITE - 1)));
                }
            DWORD bytes {};
            ULONG_PTR key {};
            OVERLAPPED* overlapped {};
            BOOL success = GetQueuedCompletionStatus(port, &bytes, &key, &overlapped, wait);
            DWORD error = success ? ERROR_SUCCESS : GetLastError();
            if (!overlapped) {
                if (!success && error == WAIT_TIMEOUT) {
                    if (wait_policy == io_wait_t::blocking_k && !count && (!deadline || monotonic_ns() < deadline))
                        continue;
                    break;
                }
                return -EIO;
            }
            auto& slot = *reinterpret_cast<slot_t*>(overlapped);
            auto& request = *slot.request;
            descriptor_t result = slot.posted ? slot.immediate
                                  : success   ? static_cast<descriptor_t>(bytes)
                                              : -socket_error(static_cast<int>(error));
            if (!success && slot.timed_out && result == -ECANCELED) result = -ETIMEDOUT;
            if (request.operation == io_operation_t::accept_k && slot.accepted != INVALID_SOCKET) {
                if (result >= 0) {
                    auto listener = static_cast<SOCKET>(request.descriptor);
                    if (setsockopt(slot.accepted, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                                   reinterpret_cast<char const*>(&listener), sizeof(listener)) == 0)
                        result = static_cast<descriptor_t>(slot.accepted);
                    else result = -socket_last_error();
                }
                if (result < 0) closesocket(slot.accepted);
            }
            else if (request.operation == io_operation_t::connect_k && result >= 0 &&
                     setsockopt(static_cast<SOCKET>(request.descriptor), SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, nullptr,
                                0) != 0)
                result = -socket_last_error();
            if (request.operation == io_operation_t::close_k && result >= 0) request.descriptor = -1;
            completions[count++] = {&request, result};
            slot.request = nullptr;
            --active;
        }
        return static_cast<int>(count);
    }
    void stop() noexcept {
        for (auto& slot : slots)
            if (slot.request && !slot.posted) {
                slot.cancelling = true;
                CancelIoEx(reinterpret_cast<HANDLE>(slot.request->descriptor), &slot.overlapped);
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
    ~windows_iocp_engine_t() noexcept {
        stop();
        if (port) CloseHandle(port);
    }
};
#endif

} // namespace unum::ucall

#if UCALL_WITH_LINUX_URING
#include "ucall/uring.hpp"
#endif
