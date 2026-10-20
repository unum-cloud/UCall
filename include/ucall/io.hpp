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
};

/** An intrusive FIFO of engine slots, linked through their `next` indices. */
struct io_slot_list_t {
    static constexpr unsigned absent_k = std::numeric_limits<unsigned>::max();
    unsigned head {absent_k}, tail {absent_k};
    template <typename slots_type_>
    void push(slots_type_& slots, unsigned index) noexcept {
        slots[index].next = absent_k;
        if (tail != absent_k) slots[tail].next = index;
        else head = index;
        tail = index;
    }
    template <typename slots_type_>
    unsigned pop(slots_type_& slots) noexcept {
        auto index = head;
        if (index == absent_k) return index;
        head = slots[index].next;
        if (head == absent_k) tail = absent_k;
        return index;
    }
};

/** Readiness slots retain connect progress and cancellation beside the durable request. */
enum class io_phase_t { fresh_k, started_k, cancelled_k };
struct io_slot_t {
    io_request_t* request {};
    io_phase_t phase {io_phase_t::fresh_k};
    unsigned next {io_slot_list_t::absent_k};
};

#if UCALL_OS_POSIX_
inline short io_events(io_operation_t operation) noexcept {
    return operation == io_operation_t::connect_k || operation == io_operation_t::send_k ? POLLOUT : POLLIN;
}
inline descriptor_t attempt_io(io_slot_t& slot, bool ready) noexcept {
    if (slot.phase == io_phase_t::cancelled_k) return -ECANCELED;
    auto& request = *slot.request;
    auto descriptor = static_cast<int>(request.descriptor);
    ssize_t result = -1;
    auto length = std::min<std::size_t>(request.length, std::numeric_limits<int>::max());
    switch (request.operation) {
    case io_operation_t::accept_k: return accepted_socket(accept(descriptor, nullptr, nullptr));
    case io_operation_t::connect_k:
        if (slot.phase == io_phase_t::fresh_k) {
            slot.phase = io_phase_t::started_k;
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
template <typename allocator_type_ = st::default_allocator<byte_t>>
struct posix_engine {
    using allocator_t = allocator_type_;
    template <typename other_allocator_>
    using rebind_allocator = posix_engine<other_allocator_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    static constexpr unsigned absent_k = io_slot_list_t::absent_k;
    struct slot_t : io_slot_t {
        unsigned polled {absent_k};
    };
    st::basic_vector<slot_t, rebound_allocator<slot_t>> slots {};
    st::basic_vector<pollfd, rebound_allocator<pollfd>> polling {};
    st::basic_vector<unsigned, rebound_allocator<unsigned>> polled {};
    io_slot_list_t free_slots, fresh_slots;
    unsigned waiting {};
    descriptor_t open_socket(int family) noexcept { return socket_open(family); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept { return descriptor; }
    int close_socket(descriptor_t descriptor) noexcept { return socket_close(descriptor); }
    void release(io_completion_t const&) noexcept {}
    bool cancel(io_request_t& request) noexcept {
        for (unsigned i = 0; i != slots.size(); ++i)
            if (slots[i].request == &request) {
                slots[i].phase = io_phase_t::cancelled_k;
                if (slots[i].polled != absent_k) {
                    unpoll(slots[i]);
                    fresh_slots.push(slots, i);
                }
                return true;
            }
        return false;
    }
    explicit posix_engine(allocator_t const& allocator = {}) noexcept
        : slots(rebound_allocator<slot_t> {allocator}), polling(rebound_allocator<pollfd> {allocator}),
          polled(rebound_allocator<unsigned> {allocator}) {}
    posix_engine(posix_engine const&) = delete;
    posix_engine& operator=(posix_engine const&) = delete;
    posix_engine(posix_engine&&) = delete;
    posix_engine& operator=(posix_engine&&) = delete;
    ~posix_engine() noexcept { stop(); }
    ucall_status_t open(std::size_t, std::size_t capacity) noexcept {
        if (st::failed(slots.resize(capacity)) || st::failed(polling.resize(capacity)) ||
            st::failed(polled.resize(capacity)))
            return ucall_status_out_of_memory_k;
        stop();
        return ucall_status_success_k;
    }
    void stop() noexcept {
        free_slots = fresh_slots = {};
        waiting = 0;
        for (unsigned i = 0; i != slots.size(); ++i) {
            slots[i] = {};
            free_slots.push(slots, i);
        }
    }
    bool submit(io_request_t& request) noexcept {
        auto index = free_slots.pop(slots);
        if (index == absent_k) return false;
        slots[index] = {};
        slots[index].request = &request;
        fresh_slots.push(slots, index);
        return true;
    }
    void unpoll(slot_t& slot) noexcept {
        auto position = slot.polled;
        --waiting;
        polling[position] = polling[waiting];
        polled[position] = polled[waiting];
        slots[polled[position]].polled = position;
        slot.polled = absent_k;
    }
    io_completion_t finish(unsigned index, descriptor_t result) noexcept {
        auto& slot = slots[index];
        auto& request = *slot.request;
        if (slot.polled != absent_k) unpoll(slot);
        if (request.operation == io_operation_t::close_k && result >= 0) request.descriptor = -1;
        slot.request = nullptr;
        free_slots.push(slots, index);
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
                auto index = fresh_slots.pop(slots);
                if (index == absent_k) break;
                auto& slot = slots[index];
                auto& request = *slot.request;
                auto result = request.deadline && now >= request.deadline ? -ETIMEDOUT : attempt_io(slot, false);
                if (!io_pending(result)) {
                    completions[count++] = finish(index, result);
                    continue;
                }
                slot.polled = waiting;
                polling[waiting] = {static_cast<int>(request.descriptor), io_events(request.operation), 0};
                polled[waiting++] = index;
            }
            for (unsigned i = 0; i != waiting && count != completions.size();) {
                auto& slot = slots[polled[i]];
                auto& request = *slot.request;
                bool expired = request.deadline && now >= request.deadline;
                if (expired || polling[i].revents) {
                    auto result = expired ? -ETIMEDOUT : attempt_io(slot, true);
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
            int result = ::poll(polling.data(), static_cast<nfds_t>(waiting), timeout);
            if (result < 0 && errno != EINTR) return -errno;
        }
        return static_cast<int>(count);
    }
};

using posix_engine_t = posix_engine<>;

#endif // UCALL_OS_POSIX_

#if UCALL_OS_POSIX_

enum class io_interest_t { unarmed_k, armed_k, ready_k };

/** Each descriptor stays registered edge-triggered until closed, pointing at its latest slot. */
template <typename readiness_type_, typename allocator_type_ = st::default_allocator<byte_t>>
struct readiness_engine {
    using allocator_t = allocator_type_;
    template <typename other_allocator_>
    using rebind_allocator =
        readiness_engine<typename readiness_type_::template rebind_allocator<other_allocator_>, other_allocator_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    static constexpr unsigned absent_k = io_slot_list_t::absent_k;
    struct slot_t : io_slot_t {
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
    bool cancel(io_request_t& request) noexcept {
        for (unsigned i = 0; i != slots.size(); ++i)
            if (slots[i].request == &request) {
                slots[i].phase = io_phase_t::cancelled_k;
                if (slots[i].interest == io_interest_t::armed_k) wake(i);
                return true;
            }
        return false;
    }
    explicit readiness_engine(allocator_t const& allocator = {}) noexcept
        : slots(rebound_allocator<slot_t> {allocator}), timed(rebound_allocator<unsigned> {allocator}),
          readiness(allocator) {}
    readiness_engine(readiness_engine const&) = delete;
    readiness_engine& operator=(readiness_engine const&) = delete;
    readiness_engine(readiness_engine&&) = delete;
    readiness_engine& operator=(readiness_engine&&) = delete;
    st::basic_vector<slot_t, rebound_allocator<slot_t>> slots {};
    st::basic_vector<unsigned, rebound_allocator<unsigned>> timed {};
    readiness_type_ readiness {};
    io_slot_list_t free_slots, fresh_slots, ready_slots;
    std::size_t active {};
    ucall_status_t open(std::size_t, std::size_t capacity) noexcept {
        if (st::failed(slots.resize(capacity)) || st::failed(timed.reserve(capacity)))
            return ucall_status_out_of_memory_k;
        stop();
        return readiness.open(capacity);
    }
    bool submit(io_request_t& request) noexcept {
        auto index = free_slots.pop(slots);
        if (index == absent_k) return false;
        auto& slot = slots[index];
        slot = {};
        slot.request = &request;
        fresh_slots.push(slots, index);
        if (request.deadline) {
            slot.timed = static_cast<unsigned>(timed.size());
            (void)timed.push_back(st::assume_reserved, unsigned {index});
        }
        ++active;
        return true;
    }
    void wake(unsigned index) noexcept {
        slots[index].interest = io_interest_t::ready_k;
        ready_slots.push(slots, index);
    }
    io_completion_t finish(unsigned index, descriptor_t result) noexcept {
        auto& slot = slots[index];
        auto& request = *slot.request;
        if (slot.timed != absent_k) {
            timed[slot.timed] = timed.back();
            slots[timed.back()].timed = slot.timed;
            timed.pop_back();
        }
        if (request.operation == io_operation_t::close_k && result >= 0) request.descriptor = -1;
        slot = {};
        free_slots.push(slots, index);
        --active;
        return {&request, result};
    }
    std::size_t progress(io_slot_list_t& list, span<io_completion_t> completions, std::size_t count,
                         std::uint64_t now) noexcept {
        while (count != completions.size()) {
            auto index = list.pop(slots);
            if (index == absent_k) break;
            auto& slot = slots[index];
            auto& request = *slot.request;
            bool fired = slot.interest == io_interest_t::ready_k;
            descriptor_t result = -ETIMEDOUT;
            // An edge-triggered slot hears nothing more until its syscall reports EAGAIN.
            if (!request.deadline || request.deadline > now) {
                if (request.operation == io_operation_t::close_k) readiness.remove(request.descriptor);
                do { result = attempt_io(slot, fired); } while (fired && result == -EINTR);
            }
            if (io_pending(result) && !fired)
                if (int armed = readiness.arm(request.descriptor, index); armed < 0) result = armed;
            if (io_pending(result)) slot.interest = io_interest_t::armed_k;
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
                auto expiry = slots[index].request->deadline;
                if (expiry > now) wait = std::min(wait, expiry - now);
                else if (slots[index].interest == io_interest_t::armed_k) wake(index);
            }
            count = progress(fresh_slots, completions, count, now);
            count = progress(ready_slots, completions, count, now);
            if (count || round || !active) break;
            int timeout = wait == std::numeric_limits<std::uint64_t>::max()
                              ? -1
                              : static_cast<int>(std::min<std::uint64_t>(wait / 1'000'000 + (wait % 1'000'000 != 0),
                                                                         std::numeric_limits<int>::max()));
            int result = readiness.wait(timeout, [&](unsigned index, descriptor_t descriptor, short events) noexcept {
                auto& slot = slots[index];
                if (slot.interest == io_interest_t::armed_k && slot.request->descriptor == descriptor &&
                    (events & io_events(slot.request->operation)))
                    wake(index);
            });
            if (result < 0 && result != -EINTR) return result;
        }
        return static_cast<int>(count);
    }
    void stop() noexcept {
        free_slots = fresh_slots = ready_slots = {};
        timed.clear();
        active = 0;
        for (unsigned i = 0; i != slots.size(); ++i) {
            slots[i] = {};
            free_slots.push(slots, i);
        }
    }
    ~readiness_engine() noexcept { stop(); }
};
#endif

#if UCALL_OS_LINUX_
template <typename allocator_type_ = st::default_allocator<byte_t>>
struct epoll_readiness {
    using allocator_t = allocator_type_;
    template <typename other_allocator_>
    using rebind_allocator = epoll_readiness<other_allocator_>;
    using events_allocator_t = typename std::allocator_traits<allocator_t>::template rebind_alloc<epoll_event>;
    explicit epoll_readiness(allocator_t const& allocator = {}) noexcept : events(events_allocator_t {allocator}) {}
    epoll_readiness(epoll_readiness const&) = delete;
    epoll_readiness& operator=(epoll_readiness const&) = delete;
    epoll_readiness(epoll_readiness&&) = delete;
    epoll_readiness& operator=(epoll_readiness&&) = delete;
    int descriptor {-1};
    st::basic_vector<epoll_event, events_allocator_t> events {};
    ucall_status_t open(std::size_t capacity) noexcept {
        if (st::failed(events.resize(capacity))) return ucall_status_out_of_memory_k;
        descriptor = epoll_create1(EPOLL_CLOEXEC);
        return descriptor < 0 ? ucall_status_io_k : ucall_status_success_k;
    }

    /** Re-points the descriptor's registration at @p slot, adding it on first use. */
    int arm(descriptor_t watched, unsigned slot) noexcept {
        epoll_event event {};
        event.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET;
        // The descriptor rides beside the slot, so its stale events never wake a reused slot.
        event.data.u64 = std::uint64_t {slot} << 32 | static_cast<std::uint32_t>(watched);
        if (epoll_ctl(descriptor, EPOLL_CTL_MOD, static_cast<int>(watched), &event) == 0) return 0;
        if (errno != ENOENT) return -errno;
        return epoll_ctl(descriptor, EPOLL_CTL_ADD, static_cast<int>(watched), &event) == 0 ? 0 : -errno;
    }
    void remove(descriptor_t watched) noexcept {
        epoll_ctl(descriptor, EPOLL_CTL_DEL, static_cast<int>(watched), nullptr);
    }
    template <typename callback_type_>
    int wait(int timeout, callback_type_&& fired) noexcept {
        int count = epoll_wait(descriptor, events.data(),
                               static_cast<int>(std::min<std::size_t>(events.size(), std::numeric_limits<int>::max())),
                               timeout);
        if (count < 0) return -errno;
        for (int i = 0; i != count; ++i) {
            auto flags = events[i].events;
            short directions = (flags & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR) ? POLLIN : 0) |
                               (flags & (EPOLLOUT | EPOLLHUP | EPOLLERR) ? POLLOUT : 0);
            fired(static_cast<unsigned>(events[i].data.u64 >> 32),
                  static_cast<descriptor_t>(static_cast<std::uint32_t>(events[i].data.u64)), directions);
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

    /** Re-points both filters of the descriptor at @p slot, adding them on first use. */
    int arm(descriptor_t watched, unsigned slot) noexcept {
        struct kevent changes[2] {};
        auto* context = reinterpret_cast<void*>(static_cast<std::uintptr_t>(slot));
        EV_SET(&changes[0], static_cast<std::uintptr_t>(watched), EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, context);
        EV_SET(&changes[1], static_cast<std::uintptr_t>(watched), EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, context);
        return kevent(descriptor, changes, 2, nullptr, 0, nullptr) == 0 ? 0 : -errno;
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
    enum class phase_t { pending_k, immediate_k, cancelling_k, timing_out_k };
    static constexpr unsigned absent_k = io_slot_list_t::absent_k;
    struct slot_t {
        OVERLAPPED overlapped {};
        io_request_t* request {};
        SOCKET accepted {INVALID_SOCKET};
        descriptor_t immediate {};
        phase_t phase {phase_t::pending_k};
        unsigned next {absent_k}, timed {absent_k};
        byte_t addresses[2 * (sizeof(sockaddr_storage) + 16)] {};
    };
    descriptor_t open_socket(int family) noexcept { return socket_open(family); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept { return descriptor; }
    int close_socket(descriptor_t descriptor) noexcept { return socket_close(descriptor); }
    void release(io_completion_t const&) noexcept {}
    bool cancel(io_request_t& request) noexcept {
        for (auto& slot : slots)
            if (slot.request == &request) {
                if (slot.phase == phase_t::pending_k) {
                    slot.phase = phase_t::cancelling_k;
                    CancelIoEx(reinterpret_cast<HANDLE>(request.descriptor), &slot.overlapped);
                }
                return true;
            }
        return false;
    }
    explicit windows_iocp_engine(allocator_t const& allocator = {}) noexcept
        : slots(rebound_allocator<slot_t> {allocator}), timed(rebound_allocator<unsigned> {allocator}),
          entries(rebound_allocator<OVERLAPPED_ENTRY> {allocator}) {}
    windows_iocp_engine(windows_iocp_engine const&) = delete;
    windows_iocp_engine& operator=(windows_iocp_engine const&) = delete;
    windows_iocp_engine(windows_iocp_engine&&) = delete;
    windows_iocp_engine& operator=(windows_iocp_engine&&) = delete;
    HANDLE port {};
    st::basic_vector<slot_t, rebound_allocator<slot_t>> slots {};
    st::basic_vector<unsigned, rebound_allocator<unsigned>> timed {};
    st::basic_vector<OVERLAPPED_ENTRY, rebound_allocator<OVERLAPPED_ENTRY>> entries {};
    io_slot_list_t free_slots, immediate_slots;
    std::size_t active {};
    ucall_status_t open(std::size_t, std::size_t capacity) noexcept {
        if (!sockets_start()) return ucall_status_io_k;
        if (st::failed(slots.resize(capacity)) || st::failed(timed.reserve(capacity)) ||
            st::failed(entries.resize(capacity)))
            return ucall_status_out_of_memory_k;
        for (unsigned i = 0; i != slots.size(); ++i) free_slots.push(slots, i);
        port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
        return port ? ucall_status_success_k : ucall_status_io_k;
    }
    void untime(slot_t& slot) noexcept {
        timed[slot.timed] = timed.back();
        slots[timed.back()].timed = slot.timed;
        timed.pop_back();
        slot.timed = absent_k;
    }
    template <typename function_type_>
    bool extension(SOCKET socket, GUID id, function_type_& function) noexcept {
        DWORD bytes {};
        return WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id), &function, sizeof(function),
                        &bytes, nullptr, nullptr) == 0;
    }
    bool submit(io_request_t& request) noexcept {
        auto index = free_slots.pop(slots);
        if (index == absent_k) return false;
        auto* slot = &slots[index];
        *slot = {};
        slot->request = &request;
        auto socket = static_cast<SOCKET>(request.descriptor);
        auto complete_immediately = [&](descriptor_t result) noexcept {
            slot->immediate = result;
            slot->phase = phase_t::immediate_k;
            immediate_slots.push(slots, index);
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
        if (request.deadline) {
            slot->timed = static_cast<unsigned>(timed.size());
            (void)timed.push_back(st::assume_reserved, unsigned {index});
        }
        ++active;
        return true;
    }
    io_completion_t finish(slot_t& slot, descriptor_t result) noexcept {
        auto& request = *slot.request;
        if (slot.timed != absent_k) untime(slot);
        if (slot.phase == phase_t::timing_out_k && result == -ECANCELED) result = -ETIMEDOUT;
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
        slot.request = nullptr;
        free_slots.push(slots, static_cast<unsigned>(&slot - slots.data()));
        --active;
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
                auto& slot = slots[timed[i]];
                auto expiry = slot.request->deadline;
                if (expiry > now) {
                    wait = std::min<DWORD>(
                        wait, static_cast<DWORD>(std::min<std::uint64_t>(
                                  (expiry - now) / 1'000'000 + ((expiry - now) % 1'000'000 != 0), INFINITE - 1)));
                    ++i;
                    continue;
                }
                if (slot.phase == phase_t::pending_k) {
                    slot.phase = phase_t::timing_out_k;
                    CancelIoEx(reinterpret_cast<HANDLE>(slot.request->descriptor), &slot.overlapped);
                }
                untime(slot);
            }
            if (auto index = immediate_slots.pop(slots); index != absent_k) {
                completions[count++] = finish(slots[index], slots[index].immediate);
                continue;
            }
            ULONG dequeued {};
            auto limit = static_cast<ULONG>(std::min(completions.size() - count, entries.size()));
            if (!GetQueuedCompletionStatusEx(port, entries.data(), limit, &dequeued, wait, FALSE)) {
                if (GetLastError() == WAIT_TIMEOUT) {
                    if (wait_policy == io_wait_t::blocking_k && !count && (!deadline || monotonic_ns() < deadline))
                        continue;
                    break;
                }
                return -EIO;
            }
            for (ULONG i = 0; i != dequeued; ++i) {
                auto& slot = *reinterpret_cast<slot_t*>(entries[i].lpOverlapped);
                DWORD bytes {}, flags {};
                // The per-packet status lives in the OVERLAPPED; this reads it without waiting.
                descriptor_t result = WSAGetOverlappedResult(static_cast<SOCKET>(slot.request->descriptor),
                                                             &slot.overlapped, &bytes, FALSE, &flags)
                                          ? static_cast<descriptor_t>(bytes)
                                          : -socket_last_error();
                completions[count++] = finish(slot, result);
            }
        }
        return static_cast<int>(count);
    }
    void stop() noexcept {
        for (auto& slot : slots)
            if (slot.request && slot.phase != phase_t::immediate_k) {
                if (slot.phase == phase_t::pending_k) slot.phase = phase_t::cancelling_k;
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
