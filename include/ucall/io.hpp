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
#include <io.h> // `_get_osfhandle`
#include <mswsock.h>
#include <sys/stat.h> // `_fstat64`
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h> // `fstat`, `statx`
#include <sys/uio.h>  // `iovec`, `preadv`
#include <unistd.h>
#endif
#if UCALL_OS_LINUX_
#include <linux/aio_abi.h>  // `aio_context_t`, `iocb`, `io_event`
#include <linux/errqueue.h> // `sock_extended_err`, `SO_EE_ORIGIN_ZEROCOPY`
#include <linux/openat2.h>  // `open_how`, `RESOLVE_BENEATH`
#include <sys/epoll.h>
#include <sys/eventfd.h> // `eventfd`
#include <sys/syscall.h> // `SYS_openat2`, `SYS_io_setup`
#endif
#if UCALL_OS_APPLE_ || UCALL_OS_FREEBSD_
#include <sys/event.h>
#endif
#if UCALL_OS_FREEBSD_
#include <aio.h> // `aio_read`, `aiocb`
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
inline ucall_status_t start_windows_sockets() noexcept {
    WSADATA data {};
    return WSAStartup(MAKEWORD(2, 2), &data) == 0 ? ucall_status_success_k : ucall_status_io_k;
}
[[nodiscard]] inline ucall_status_t sockets_start() noexcept {
    static ucall_status_t const started = start_windows_sockets();
    return started;
}
inline int socket_close(descriptor_t descriptor) noexcept { return closesocket(static_cast<SOCKET>(descriptor)); }
[[nodiscard]] inline ucall_status_t nonblocking(descriptor_t descriptor) noexcept {
    u_long enabled = 1;
    return ioctlsocket(static_cast<SOCKET>(descriptor), FIONBIO, &enabled) == 0 &&
                   SetHandleInformation(reinterpret_cast<HANDLE>(descriptor), HANDLE_FLAG_INHERIT, 0)
               ? ucall_status_success_k
               : ucall_status_io_k;
}
inline std::size_t page_size() noexcept {
    SYSTEM_INFO info {};
    GetSystemInfo(&info);
    return info.dwPageSize;
}
#else
using socket_length_t = socklen_t;
inline int socket_last_error() noexcept { return errno; }
[[nodiscard]] inline ucall_status_t sockets_start() noexcept { return ucall_status_success_k; }
inline int socket_close(descriptor_t descriptor) noexcept { return close(static_cast<int>(descriptor)); }
[[nodiscard]] inline ucall_status_t nonblocking(descriptor_t descriptor) noexcept {
    int flags = fcntl(static_cast<int>(descriptor), F_GETFL, 0);
    return flags != -1 && fcntl(static_cast<int>(descriptor), F_SETFL, flags | O_NONBLOCK) != -1 &&
                   fcntl(static_cast<int>(descriptor), F_SETFD, FD_CLOEXEC) != -1
               ? ucall_status_success_k
               : ucall_status_io_k;
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

/** The `SO_LINGER` setting that makes a close send a reset rather than a FIN. */
inline constexpr linger socket_reset_linger_k {1, 0};

/** Makes the close of @p descriptor send a reset rather than a FIN. */
[[nodiscard]] inline ucall_status_t socket_reset_on_close(descriptor_t descriptor) noexcept {
    return socket_option(descriptor, SOL_SOCKET, SO_LINGER, &socket_reset_linger_k, sizeof(socket_reset_linger_k)) == 0
               ? ucall_status_success_k
               : ucall_status_io_k;
}
inline descriptor_t socket_open(int family) noexcept {
    if (sockets_start() != ucall_status_success_k) return -1;
#if UCALL_OS_WINDOWS_
    descriptor_t descriptor = static_cast<descriptor_t>(
        WSASocketW(family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED));
#else
    descriptor_t descriptor = socket(family, SOCK_STREAM, 0);
#endif
    if (descriptor == -1) return -1;
    if (nonblocking(descriptor) != ucall_status_success_k) {
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

/** A nonblocking UDP socket connected to @p address, so sends need no destination, or -1. */
inline descriptor_t datagram_open(sockaddr const* address, socket_length_t length) noexcept {
    if (sockets_start() != ucall_status_success_k) return -1;
#if UCALL_OS_WINDOWS_
    descriptor_t descriptor = static_cast<descriptor_t>(
        WSASocketW(address->sa_family, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED));
    if (descriptor == -1) return -1;
    bool const connected = connect(static_cast<SOCKET>(descriptor), address, length) == 0;
#else
    descriptor_t descriptor = socket(address->sa_family, SOCK_DGRAM, 0);
    if (descriptor == -1) return -1;
    bool const connected = connect(static_cast<int>(descriptor), address, length) == 0;
#endif
    if (!connected || nonblocking(descriptor) != ucall_status_success_k) {
        socket_close(descriptor);
        return -1;
    }
    return descriptor;
}
inline descriptor_t accepted_socket(descriptor_t descriptor) noexcept {
    if (descriptor == -1) return -socket_last_error();
    if (nonblocking(descriptor) != ucall_status_success_k) {
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

/** What a request asks of its socket or of a file. File operations keep `descriptor` as the socket
 *  they serve, so its close waits for them.
 *
 *  - `send_zero_copy_k` completes once the socket took bytes of `data`, and names the
 *    `release_request` whose `zero_copy_release_k` completes once the kernel let go of them; the
 *    submitter submits the release after the last send naming it completed.
 *  - `file_open_k` opens the NUL-terminated path in `data` beneath `file.directory_descriptor` for
 *    unbuffered reads, completing with a descriptor the submitter owns even after a cancel.
 *  - `file_read_k` reads `length` bytes of `file.file_descriptor` at `file.offset` into `data`;
 *    `file_read_vectors_k` scatters them into the `length` vectors that `data` points at. Offsets,
 *    lengths and buffers meet the file's `file_direct_alignment`. */
enum class io_operation_t : std::uint8_t {
    accept_k,
    connect_k,
    receive_k,
    send_k,
    send_zero_copy_k,
    read_k,
    shutdown_k,
    close_k,
    file_open_k,
    file_read_k,
    file_read_vectors_k,
    zero_copy_release_k,
};

/** The engine buffer index a request's memory lies in, scoped so no descriptor binds to it. */
enum class registered_memory_t : std::uint16_t {};

/** The `registered_memory` of a request whose buffer lies in no engine-registered range. */
inline constexpr registered_memory_t io_unregistered_k {std::numeric_limits<std::uint16_t>::max()};

/** The file a file operation reads or opens beneath, borrowed from the submitter. */
struct io_file_t {
    std::uint64_t offset {};
    int file_descriptor {-1};
    int directory_descriptor {-1};
};
static_assert(sizeof(io_file_t) == 16);

/** One destination of a `file_read_vectors_k`, the platform's own scatter element, braced as
 *  `{data, length}`. */
#if UCALL_OS_WINDOWS_
struct io_vector_t {
    void* iov_base {};
    std::size_t iov_len {};
};
#else
using io_vector_t = iovec;
#endif
static_assert(sizeof(io_vector_t) == 16);

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
        io_file_t file {};             // File operations.
        io_request_t* release_request; // `send_zero_copy_k`.
    };
};
static_assert(sizeof(io_request_t) == (UCALL_OS_WINDOWS_ ? 64 : 56));

/** Whether an engine holds a registered range pinned, sparing each request in it the pinning. */
enum class range_pinning_t : std::uint8_t {
    pinned_k,   // Registered at `index`; requests pass it as `registered_memory`.
    unpinned_k, // Refused, by the locked-memory cap or a full table; requests pass `io_unregistered_k`.
};

/** What `register_memory` made of a range. */
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

/** Closes a file or directory descriptor, as opposed to a socket. */
inline void file_close(int file) noexcept {
#if UCALL_OS_WINDOWS_
    _close(file);
#else
    close(file);
#endif
}

/** What `file_direct_alignment` learned of an open file: its size and the alignment its unbuffered
 *  reads meet in offset, length and memory, or a negated errno, `-ENXIO` for anything but a
 *  regular file. */
struct file_geometry_t {
    std::uint64_t size {};
    std::uint32_t alignment {};
    std::int32_t error {};
};
static_assert(sizeof(file_geometry_t) == 16);

/** The alignment unbuffered reads assume where the filesystem cannot say, a page everywhere. */
inline constexpr std::uint32_t file_portable_alignment_k = 4096;

#if UCALL_OS_WINDOWS_

/** Measures the open regular @p file; unbuffered handles want sector alignment, which no volume
 *  sets above a page. */
inline file_geometry_t file_direct_alignment(int file) noexcept {
    struct _stat64 status {};
    if (_fstat64(file, &status) != 0) return {0, 0, -errno};
    if (!(status.st_mode & _S_IFREG)) return {0, 0, -ENXIO};
    return {static_cast<std::uint64_t>(status.st_size), file_portable_alignment_k, 0};
}

/** Accepts any descriptor, since the IOCP engine reopens each file unbuffered for its reads. */
inline ucall_status_t file_direct_check(int) noexcept { return ucall_status_success_k; }

#else

#if UCALL_OS_LINUX_

/** Measures the open regular @p file and asks its filesystem what unbuffered reads demand. */
inline file_geometry_t file_direct_alignment(int file) noexcept {
    struct statx status {};
    if (statx(file, "", AT_EMPTY_PATH, STATX_TYPE | STATX_SIZE | STATX_DIOALIGN, &status) != 0) return {0, 0, -errno};
    if (!S_ISREG(status.stx_mode)) return {0, 0, -ENXIO};
    std::uint32_t alignment = file_portable_alignment_k;
    if ((status.stx_mask & STATX_DIOALIGN) && status.stx_dio_mem_align && status.stx_dio_offset_align)
        alignment = std::max(status.stx_dio_mem_align, status.stx_dio_offset_align);
    return {status.stx_size, alignment, 0};
}

#else

/** Measures the open regular @p file; these kernels report no unbuffered alignment, so a page. */
inline file_geometry_t file_direct_alignment(int file) noexcept {
    struct stat status {};
    if (fstat(file, &status) != 0) return {0, 0, -errno};
    if (!S_ISREG(status.st_mode)) return {0, 0, -ENXIO};
    return {static_cast<std::uint64_t>(status.st_size), file_portable_alignment_k, 0};
}

#endif // UCALL_OS_LINUX_

#if UCALL_OS_APPLE_

/** Switches the borrowed @p file to uncached reads, as Darwin keeps no flag to check instead. */
inline ucall_status_t file_direct_check(int file) noexcept {
    return fcntl(file, F_NOCACHE, 1) == 0 ? ucall_status_success_k : ucall_status_invalid_argument_k;
}

/** The flags every file open beneath a directory takes; a FIFO opens without waiting for a writer,
 *  and `file_open_finish` drops the nonblocking flag from what opened. */
inline constexpr int file_open_flags_k = O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK;

/** Readies a @p file just opened with `file_open_flags_k` for blocking uncached reads: the
 *  descriptor, or a negated errno with the file closed. */
inline int file_open_finish(int file) noexcept {
    int const flags = fcntl(file, F_GETFL);
    if (flags != -1 && fcntl(file, F_SETFL, flags & ~O_NONBLOCK) == 0 && fcntl(file, F_NOCACHE, 1) == 0) return file;
    int const error = errno;
    close(file);
    return -error;
}

#else

/** Refuses a borrowed @p file opened without `O_DIRECT`, whose reads would go through the cache. */
inline ucall_status_t file_direct_check(int file) noexcept {
    int const flags = fcntl(file, F_GETFL);
    return flags != -1 && (flags & O_DIRECT) ? ucall_status_success_k : ucall_status_invalid_argument_k;
}

/** The flags every file open beneath a directory takes; a FIFO opens without waiting for a writer,
 *  then fails the direct check, and `file_open_finish` drops the nonblocking flag from a file, as
 *  io_uring answers a nonblocking file's blocked read with `-EAGAIN` instead of a worker. */
inline constexpr int file_open_flags_k = O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK | O_DIRECT;

/** Readies a @p file just opened with `file_open_flags_k` for blocking unbuffered reads: the
 *  descriptor, or a negated errno with the file closed. */
inline int file_open_finish(int file) noexcept {
    int const flags = fcntl(file, F_GETFL);
    if (flags != -1 && fcntl(file, F_SETFL, flags & ~O_NONBLOCK) == 0) return file;
    int const error = errno;
    close(file);
    return -error;
}

#endif // UCALL_OS_APPLE_

/** Reads @p file at @p offset into @p bytes, blocking: a count, or a negated errno. */
inline descriptor_t file_read(int file, span<byte_t> bytes, std::uint64_t offset) noexcept {
    ssize_t read;
    do
        read = pread(file, bytes.data(), std::min<std::size_t>(bytes.size(), std::numeric_limits<int>::max()),
                     static_cast<off_t>(offset));
    while (read < 0 && errno == EINTR);
    return read >= 0 ? static_cast<descriptor_t>(read) : -errno;
}

/** Scatters @p file from @p offset into @p vectors, blocking: a count, or a negated errno. */
inline descriptor_t file_read_vectors(int file, span<io_vector_t const> vectors, std::uint64_t offset) noexcept {
    ssize_t read;
    do
        read = preadv(file, vectors.data(), static_cast<int>(std::min<std::size_t>(vectors.size(), IOV_MAX)),
                      static_cast<off_t>(offset));
    while (read < 0 && errno == EINTR);
    return read >= 0 ? static_cast<descriptor_t>(read) : -errno;
}

/** Opens @p path for unbuffered reads strictly beneath @p directory: a descriptor, or a negated
 *  errno. */
inline int file_open_beneath(int directory, char const* path) noexcept {
#if UCALL_OS_LINUX_
    open_how how {};
    how.flags = file_open_flags_k;
    how.resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS;
    long const opened = syscall(SYS_openat2, directory, path, &how, sizeof(how));
    int file = opened >= 0 ? static_cast<int>(opened) : -errno;
#elif UCALL_OS_FREEBSD_
    int file = openat(directory, path, file_open_flags_k | O_RESOLVE_BENEATH);
    if (file < 0) file = -errno;
#else
    // Lacking a beneath resolution, a walk that takes no `..` and follows no link stays inside.
    int file = directory;
    char name[NAME_MAX + 1];
    for (char const* cursor = path; file >= 0 && *cursor;) {
        char const* end = std::strchr(cursor, '/');
        if (!end) end = cursor + std::strlen(cursor);
        auto const length = static_cast<std::size_t>(end - cursor);
        int next = -EXDEV;
        if (length && length <= NAME_MAX && !(length == 2 && cursor[0] == '.' && cursor[1] == '.')) {
            std::memcpy(name, cursor, length);
            name[length] = '\0';
            next = openat(file, name, (*end ? O_RDONLY | O_DIRECTORY | O_CLOEXEC : file_open_flags_k) | O_NOFOLLOW);
            if (next < 0) next = -errno;
        }
        if (file != directory) close(file);
        file = next;
        cursor = *end ? end + 1 : end;
    }
    if (file == directory) file = -EISDIR;
#endif // UCALL_OS_LINUX_
    return file < 0 ? file : file_open_finish(file);
}

#endif // UCALL_OS_WINDOWS_

/** A byte count, accepted descriptor, or negated errno for exactly one submitted request; a receive
 *  into engine memory names the `data` it filled and the `lease` that `release` returns. */
struct io_completion_t {
    io_request_t* request {};
    descriptor_t result {};
    byte_t* data {};
    std::uintptr_t lease {};
};
static_assert(sizeof(io_completion_t) == 32);

/** Counters an engine advances for its one polling owner, on lines no other thread writes.
 *  `zero_copy_fallbacks` counts sends the kernel copied anyway or refused to pin. */
struct alignas(false_sharing_bytes_k) io_statistics_t {
    std::uint64_t submissions {}, completions {}, kernel_enters {}, cancellations {}, receive_rearms {},
        bytes_copied {}, zero_copy_sends {}, zero_copy_fallbacks {}, file_reads_asynchronous {}, file_reads_blocking {};
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

    /** Unlinks operation @p index, or answers `ucall_status_not_found_k` when it is not queued. */
    template <typename operations_type_>
    ucall_status_t remove(operations_type_& operations, unsigned index) noexcept {
        for (unsigned previous = absent_k, current = head; current != absent_k;
             previous = current, current = operations[current].next) {
            if (current != index) continue;
            if (previous != absent_k) operations[previous].next = operations[current].next;
            else head = operations[current].next;
            if (tail == index) tail = previous;
            return ucall_status_success_k;
        }
        return ucall_status_not_found_k;
    }
};

/** The vectors a `file_read_vectors_k` request scatters into, which its `data` points at. */
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

/** The flags a copying send takes so a vanished peer never raises `SIGPIPE`; Apple sockets carry
 *  `SO_NOSIGPIPE` instead. */
#if UCALL_OS_APPLE_
inline constexpr int socket_send_flags_k = 0;
#else
inline constexpr int socket_send_flags_k = MSG_NOSIGNAL;
#endif

/** Performs the request's syscall, blocking for file work and copying for zero-copy sends, and
 *  probes a pending connect only once @p interest reports readiness. */
inline descriptor_t attempt_io(io_request_t& request, operation_stage_t& stage, io_interest_t interest,
                               io_statistics_t& statistics) noexcept {
    if (stage == operation_stage_t::cancelled_k) return -ECANCELED;
    if (request.operation == io_operation_t::connect_k && stage != operation_stage_t::fresh_k &&
        interest != io_interest_t::ready_k)
        return -EAGAIN;
    tally(statistics.kernel_enters);
    auto descriptor = static_cast<int>(request.descriptor);
    ssize_t result = -1;
    auto length = std::min<std::size_t>(request.length, std::numeric_limits<int>::max());
    switch (request.operation) {
    case io_operation_t::accept_k: return accepted_socket(accept(descriptor, nullptr, nullptr));
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
    case io_operation_t::receive_k: result = recv(descriptor, request.data, length, 0); break;
    case io_operation_t::send_k:
    case io_operation_t::send_zero_copy_k: result = send(descriptor, request.data, length, socket_send_flags_k); break;
    case io_operation_t::read_k: result = read(descriptor, request.data, length); break;
    case io_operation_t::shutdown_k: return ::shutdown(descriptor, SHUT_WR) == 0 ? 0 : -errno;
    case io_operation_t::close_k: return socket_close(request.descriptor) == 0 || errno == EINTR ? 0 : -errno;
    case io_operation_t::file_open_k:
        return file_open_beneath(request.file.directory_descriptor, reinterpret_cast<char const*>(request.data));
    case io_operation_t::file_read_k:
        tally(statistics.file_reads_blocking);
        return file_read(request.file.file_descriptor, {request.data, request.length}, request.file.offset);
    case io_operation_t::file_read_vectors_k:
        tally(statistics.file_reads_blocking);
        return file_read_vectors(request.file.file_descriptor, io_vectors(request), request.file.offset);
    case io_operation_t::zero_copy_release_k: return 0;
    }
    return result >= 0 ? static_cast<descriptor_t>(result) : -errno;
}
inline bool io_pending(descriptor_t result) noexcept {
    return result == -EAGAIN || result == -EWOULDBLOCK || result == -EINPROGRESS || result == -EINTR;
}

#endif // UCALL_OS_POSIX_

#if UCALL_OS_POSIX_

/** Nonblocking POSIX syscalls, completed through poll readiness; files are read blocking, and
 *  zero-copy sends copy, so their releases complete as submitted. */
template <typename allocator_type_ = st::default_allocator<byte_t>>
struct posix_engine {
    using allocator_t = allocator_type_;
    template <typename other_allocator_>
    using rebind_allocator = posix_engine<other_allocator_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    static constexpr unsigned absent_k = operation_list_t::absent_k;
    struct operation_t {
        io_request_t* request {};
        unsigned polled {absent_k}, next {absent_k};
        operation_stage_t stage {operation_stage_t::fresh_k};
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
    [[nodiscard]] ucall_status_t reset_on_close(descriptor_t descriptor) noexcept {
        return socket_reset_on_close(descriptor);
    }
    memory_registration_t register_memory(span<byte_t>) noexcept { return {}; }
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
                                  : attempt_io(request, operation.stage, io_interest_t::unarmed_k, statistics);
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
                    auto result = expired ? -ETIMEDOUT
                                          : attempt_io(request, operation.stage, io_interest_t::ready_k, statistics);
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

#if UCALL_OS_APPLE_ || UCALL_OS_FREEBSD_

/** Each descriptor stays registered edge-triggered until `close_socket` or a close request, aimed
 *  at its latest operation in each direction; file reads land through the readiness queue where
 *  the kernel offers asynchronous reads, and zero-copy sends copy, so their releases complete as
 *  submitted. */
template <typename readiness_type_, typename allocator_type_ = st::default_allocator<byte_t>>
struct readiness_engine {
    using allocator_t = allocator_type_;
    template <typename other_allocator_>
    using rebind_allocator =
        readiness_engine<typename readiness_type_::template rebind_allocator<other_allocator_>, other_allocator_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    static constexpr unsigned absent_k = operation_list_t::absent_k;
    struct operation_t {
        io_request_t* request {};
        unsigned next {absent_k}, timed {absent_k};
        descriptor_t result {}; // What a landed file read completes with.
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
                tally(statistics.cancellations);
                // A landing file read keeps its buffer until the kernel answers, then reports it.
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
        tally(statistics.submissions);
        return ucall_status_success_k;
    }
    void wake(unsigned index) noexcept {
        operations[index].interest = io_interest_t::ready_k;
        ready_operations.push(operations, index);
    }
    void land(unsigned index, descriptor_t result) noexcept {
        operations[index].result = result;
        landed_operations.push(operations, index);
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
        while (count != completions.size()) {
            auto index = landed_operations.pop(operations);
            if (index == absent_k) break;
            auto const& operation = operations[index];
            descriptor_t const result = operation.stage == operation_stage_t::cancelled_k ? -ECANCELED
                                                                                          : operation.result;
            completions[count++] = finish(index, result);
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
            count = collect(completions, count);
            count = progress(fresh_operations, completions, count, now);
            count = progress(ready_operations, completions, count, now);
            if (count || round || !active) break;
            int timeout = wait == std::numeric_limits<std::uint64_t>::max()
                              ? -1
                              : static_cast<int>(std::min<std::uint64_t>(wait / 1'000'000 + (wait % 1'000'000 != 0),
                                                                         std::numeric_limits<int>::max()));
            tally(statistics.kernel_enters);
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
    ~readiness_engine() noexcept { stop(); }
};

/** kqueue readiness; FreeBSD reads files through `aio_read` completing as `EVFILT_AIO` events,
 *  while macOS, lacking kernel file AIO for this, reads them blocking and uncached. */
template <typename allocator_type_ = st::default_allocator<byte_t>>
struct kqueue_readiness {
    using allocator_t = allocator_type_;
    template <typename other_allocator_>
    using rebind_allocator = kqueue_readiness<other_allocator_>;
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
    st::basic_vector<struct kevent, rebound_allocator<struct kevent>> events {};
#if UCALL_OS_FREEBSD_
    st::basic_vector<aiocb, rebound_allocator<aiocb>> file_reads {}; // One per operation, read by the kernel.
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
        tally(statistics.kernel_enters);
        return kevent(descriptor, &change, 1, nullptr, 0, nullptr) == 0 ? 0 : -errno;
    }
    // Closing a descriptor drops its knotes.
    void remove(descriptor_t) noexcept {}

#if UCALL_OS_FREEBSD_
    ucall_status_t reserve_file_reads(std::size_t capacity) noexcept {
        return st::failed(file_reads.resize(capacity)) ? ucall_status_out_of_memory_k : ucall_status_success_k;
    }

    /** Starts a file read as operation @p index, landing it through `EVFILT_AIO`; a full AIO queue
     *  reads blocking instead. Everything else is a plain syscall. */
    descriptor_t attempt(unsigned index, io_request_t& request, operation_stage_t& stage, io_interest_t& interest,
                         io_statistics_t& statistics) noexcept {
        if (request.operation != io_operation_t::file_read_k &&
            request.operation != io_operation_t::file_read_vectors_k)
            return attempt_io(request, stage, interest, statistics);
        if (stage == operation_stage_t::cancelled_k) return -ECANCELED;
        aiocb& block = file_reads[index];
        block = {};
        block.aio_fildes = request.file.file_descriptor;
        block.aio_offset = static_cast<off_t>(request.file.offset);
        block.aio_sigevent.sigev_notify = SIGEV_KEVENT;
        block.aio_sigevent.sigev_notify_kqueue = descriptor;
        block.aio_sigevent.sigev_value.sival_ptr = reinterpret_cast<void*>(static_cast<std::uintptr_t>(index));
        int started;
        tally(statistics.kernel_enters);
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
            tally(statistics.file_reads_asynchronous);
            interest = io_interest_t::landing_k;
            return 0;
        }
        if (errno != EAGAIN) return -errno;
        return attempt_io(request, stage, interest, statistics);
    }
#else
    ucall_status_t reserve_file_reads(std::size_t) noexcept { return ucall_status_success_k; }
    descriptor_t attempt(unsigned, io_request_t& request, operation_stage_t& stage, io_interest_t& interest,
                         io_statistics_t& statistics) noexcept {
        return attempt_io(request, stage, interest, statistics);
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
using kqueue_engine_t = readiness_engine<kqueue_readiness_t>;

#endif // UCALL_OS_APPLE_ || UCALL_OS_FREEBSD_

#if UCALL_OS_LINUX_

/** Whether a socket's sends still try zero-copy, which ends once the kernel reports it copied. */
enum class zero_copy_stage_t : std::uint8_t { untried_k, enabled_k, copying_k };

/** Slots in an io_uring registered-buffer table, the kernel's `IORING_MAX_REG_BUFFERS`. */
inline constexpr unsigned uring_registered_buffers_limit_k = 16384;

/** Finds an engine's zero-copy release operations by the request their sends name, open addressed
 *  and at most half full. */
template <typename allocator_type_ = st::default_allocator<byte_t>>
struct release_table {
    using allocator_t = allocator_type_;
    using slots_allocator_t = typename std::allocator_traits<allocator_t>::template rebind_alloc<std::uint32_t>;
    static constexpr std::uint32_t absent_k = operation_list_t::absent_k;
    st::basic_vector<std::uint32_t, slots_allocator_t> slots;
    explicit release_table(allocator_t const& allocator = {}) noexcept : slots(slots_allocator_t {allocator}) {}
    ucall_status_t open(std::size_t capacity) noexcept {
        if (st::failed(slots.resize(std::bit_ceil(capacity * 2)))) return ucall_status_out_of_memory_k;
        for (auto& slot : slots) slot = absent_k;
        return ucall_status_success_k;
    }
    std::size_t home(io_request_t const* request) const noexcept {
        auto const key = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(request));
        std::uint64_t mixed = (key >> 3) * 0x9E3779B97F4A7C15ull;
        return static_cast<std::size_t>(mixed ^ mixed >> 32) & (slots.size() - 1);
    }
    template <typename operations_type_>
    std::size_t slot_of(operations_type_ const& operations, io_request_t const* request) const noexcept {
        std::size_t mask = slots.size() - 1, slot = home(request);
        while (slots[slot] != absent_k && operations[slots[slot]].request != request) slot = (slot + 1) & mask;
        return slot;
    }
    template <typename operations_type_>
    unsigned find(operations_type_ const& operations, io_request_t const* request) const noexcept {
        return slots.empty() ? absent_k : slots[slot_of(operations, request)];
    }
    template <typename operations_type_>
    void insert(operations_type_ const& operations, unsigned index) noexcept {
        slots[slot_of(operations, operations[index].request)] = index;
    }
    template <typename operations_type_>
    void erase(operations_type_ const& operations, unsigned index) noexcept {
        std::size_t mask = slots.size() - 1, slot = slot_of(operations, operations[index].request);
        if (slots[slot] != index) return;
        for (std::size_t next = (slot + 1) & mask; slots[next] != absent_k; next = (next + 1) & mask) {
            std::size_t const next_home = home(operations[slots[next]].request);
            // Linear probing finds an entry only while no vacancy lies between its home and slot.
            if (((next - next_home) & mask) >= ((next - slot) & mask)) {
                slots[slot] = slots[next];
                slot = next;
            }
        }
        slots[slot] = absent_k;
    }
};

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
    std::uint32_t generation {}; // Rides in the event, so stale events never wake a reused watch.
    std::uint32_t receive_operation {operation_list_t::absent_k};
    std::uint32_t transmit_operation {operation_list_t::absent_k}; // Or the close of a closing watch.
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
template <typename allocator_type_ = st::default_allocator<byte_t>>
struct epoll_readiness {
    using allocator_t = allocator_type_;
    template <typename other_allocator_>
    using rebind_allocator = epoll_readiness<other_allocator_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    static constexpr std::uint32_t absent_k = operation_list_t::absent_k;

    /** The event data of the one descriptor that is no watch, the AIO completion counter. */
    static constexpr std::uint64_t signal_k = std::numeric_limits<std::uint64_t>::max();
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

    /** The slot naming the watch of @p watched, or the vacant slot that ends its probe. */
    std::size_t slot_of(descriptor_t watched) const noexcept {
        std::size_t mask = watch_slots.size() - 1;
        std::size_t slot = static_cast<std::size_t>(watched) & mask;
        while (watch_slots[slot] != absent_k && watches[watch_slots[slot]].descriptor != watched)
            slot = (slot + 1) & mask;
        return slot;
    }

    /** The watch of @p watched, or `absent_k`. */
    std::uint32_t find(descriptor_t watched) const noexcept {
        return watch_slots.empty() ? absent_k : watch_slots[slot_of(watched)];
    }

    /** The watch of @p watched, registering it on first use: its index, or a negated errno. */
    std::int64_t watch(descriptor_t watched, io_statistics_t& statistics) noexcept {
        std::size_t slot = slot_of(watched);
        if (watch_slots[slot] != absent_k) return watch_slots[slot];
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
        return chosen;
    }

    /** Points @p direction of the descriptor's watch at operation @p index,
     *  registering it on first use. */
    int arm(descriptor_t watched, io_direction_t direction, unsigned index, io_statistics_t& statistics) noexcept {
        std::int64_t const chosen = watch(watched, statistics);
        if (chosen < 0) return static_cast<int>(chosen);
        readiness_watch_t& found = watches[static_cast<std::size_t>(chosen)];
        (direction == io_direction_t::receive_k ? found.receive_operation : found.transmit_operation) = index;
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
            auto const chosen = static_cast<std::uint32_t>(events[i].data.u64 >> 32);
            if (watches[chosen].generation != static_cast<std::uint32_t>(events[i].data.u64)) continue;
            if ((flags & EPOLLERR) &&
                (watches[chosen].oldest_run != absent_k || watches[chosen].stage == watch_stage_t::closing_k))
                errored(chosen);
            // The error queue may have closed and freed the watch.
            readiness_watch_t const& watch = watches[chosen];
            if (watch.generation != static_cast<std::uint32_t>(events[i].data.u64) ||
                watch.stage == watch_stage_t::closing_k)
                continue;
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

/** AIO events one engine keeps in flight; `fs.aio-max-nr`, 65536 by default, bounds the sum on a
 *  host, so a 64-loop server reserves 4096 of them. */
inline constexpr std::uint32_t linux_aio_depth_k = 64;

/** One Linux AIO context, through raw syscalls, completing into an eventfd an epoll set watches. */
struct linux_aio_t {
    aio_context_t context {};
    int signal_descriptor {-1};
    std::uint32_t depth {linux_aio_depth_k}; // The first `open` tries, halved while the host limit refuses.
    std::uint32_t in_flight {};
    linux_aio_t() noexcept = default;
    linux_aio_t(linux_aio_t const&) = delete;
    linux_aio_t& operator=(linux_aio_t const&) = delete;
    ~linux_aio_t() noexcept { close(); }

    /** Sets up the context, answering `ucall_status_unsupported_k` when the kernel or the host's
     *  `fs.aio-max-nr` refuses even one event. */
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

    /** Starts @p request's file read as operation @p index: zero, or a negated errno, `-EAGAIN`
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

/** epoll readiness for sockets with Linux AIO for files, both completing in one epoll set, and
 *  `MSG_ZEROCOPY` sends whose releases land from the error queue.
 *
 *  - A file read lands from the AIO eventfd and cannot be cancelled: a cancel completes it with
 *    `-ECANCELED` once the kernel answered, keeping its buffer until then.
 *  - A zero-copy send takes the next notification ID of its socket; a socket whose notification
 *    reports a copy, or that refuses `SO_ZEROCOPY`, copies from then on, and `ENOBUFS` copies once.
 *  - A close with notifications still due keeps the descriptor until they all arrived, resetting
 *    first if the socket was set to reset on close. */
template <typename allocator_type_ = st::default_allocator<byte_t>>
struct linux_epollaio_engine {
    using allocator_t = allocator_type_;
    template <typename other_allocator_>
    using rebind_allocator = linux_epollaio_engine<other_allocator_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    template <typename value_type_>
    using vector = st::basic_vector<value_type_, rebound_allocator<value_type_>>;
    static constexpr unsigned absent_k = operation_list_t::absent_k;
    struct operation_t {
        io_request_t* request {};
        unsigned next {absent_k}, timed {absent_k};
        std::uint32_t pending_notifications {}; // A release's zero-copy sends not yet notified.
        descriptor_t result {};                 // What a landed operation completes with.
        operation_stage_t stage {operation_stage_t::fresh_k};
        io_interest_t interest {io_interest_t::unarmed_k};
    };
    static_assert(sizeof(operation_t) == 32);

    vector<operation_t> operations;
    vector<unsigned> timed;
    vector<zero_copy_run_t> runs;
    epoll_readiness<allocator_t> readiness;
    release_table<allocator_t> releases;
    linux_aio_t files;
    operation_list_t free_operations, fresh_operations, ready_operations, landed_operations, waiting_files;
    unsigned free_runs {absent_k};
    std::size_t active {};
    char const* refusal {}; // Why `open` answered `ucall_status_unsupported_k`, naming the setting to raise.
    io_statistics_t statistics {};

    explicit linux_epollaio_engine(allocator_t const& allocator = {}) noexcept
        : operations(rebound_allocator<operation_t> {allocator}), timed(rebound_allocator<unsigned> {allocator}),
          runs(rebound_allocator<zero_copy_run_t> {allocator}), readiness(allocator), releases(allocator) {}
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
        if (ucall_status_t const opened = releases.open(capacity); opened != ucall_status_success_k) return opened;
        if (ucall_status_t const opened = files.open(); opened != ucall_status_success_k) {
            if (opened == ucall_status_unsupported_k)
                refusal = "Linux AIO refused a context: raise `fs.aio-max-nr`, as `sysctl -w fs.aio-max-nr=1048576`";
            return opened;
        }
        return readiness.watch_signal(files.signal_descriptor);
    }

    ucall_status_t submit(io_request_t& request) noexcept {
        unsigned index = absent_k;
        // A release some send already named exists since that send; it now leaves the table.
        if (request.operation == io_operation_t::zero_copy_release_k) index = releases.find(operations, &request);
        if (index != absent_k) releases.erase(operations, index);
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
        tally(statistics.submissions);
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
            tally(statistics.cancellations);
            operation.stage = operation_stage_t::cancelled_k;
            if (operation.interest == io_interest_t::armed_k) wake(i);
            else if (operation.interest == io_interest_t::landing_k &&
                     waiting_files.remove(operations, i) == ucall_status_success_k) {
                operation.interest = io_interest_t::unarmed_k;
                fresh_operations.push(operations, i);
            }
            return ucall_status_success_k;
        }
        return ucall_status_not_found_k;
    }

    void wake(unsigned index) noexcept {
        operations[index].interest = io_interest_t::ready_k;
        ready_operations.push(operations, index);
    }
    void land(unsigned index, descriptor_t result) noexcept {
        operations[index].result = result;
        landed_operations.push(operations, index);
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

    /** Starts a file read, or queues it for an AIO event; it lands through `files.drain`. */
    descriptor_t read_file(unsigned index) noexcept {
        auto& operation = operations[index];
        if (operation.stage == operation_stage_t::cancelled_k) return -ECANCELED;
        tally(statistics.kernel_enters);
        int const started = files.submit(index, *operation.request);
        if (started == -EAGAIN) waiting_files.push(operations, index);
        else if (started < 0) return started;
        else tally(statistics.file_reads_asynchronous);
        operation.interest = io_interest_t::landing_k;
        return 0;
    }

    /** Sends copying, as a socket does once zero-copy is refused or reported copied. */
    descriptor_t send_copying(io_request_t const& request) noexcept {
        auto const length = std::min<std::size_t>(request.length, std::numeric_limits<int>::max());
        ssize_t const sent = send(static_cast<int>(request.descriptor), request.data, length, MSG_NOSIGNAL);
        return sent >= 0 ? static_cast<descriptor_t>(sent) : -errno;
    }

    /** Sends with `MSG_ZEROCOPY`, counting the send against its release under the socket's next
     *  notification ID; without room to count it, the send copies. */
    descriptor_t send_zero_copy(unsigned index) noexcept {
        auto& operation = operations[index];
        if (operation.stage == operation_stage_t::cancelled_k) return -ECANCELED;
        io_request_t const& request = *operation.request;
        tally(statistics.kernel_enters);
        std::int64_t const chosen = readiness.watch(request.descriptor, statistics);
        if (chosen < 0) return send_copying(request);
        readiness_watch_t& watch = readiness.watches[static_cast<std::size_t>(chosen)];
        if (watch.zero_copy == zero_copy_stage_t::untried_k) {
            int enabled = 1;
            watch.zero_copy = socket_option(request.descriptor, SOL_SOCKET, SO_ZEROCOPY, &enabled, sizeof(enabled)) == 0
                                  ? zero_copy_stage_t::enabled_k
                                  : zero_copy_stage_t::copying_k;
        }
        if (watch.zero_copy == zero_copy_stage_t::copying_k) return send_copying(request);
        unsigned release = releases.find(operations, request.release_request);
        zero_copy_run_t* extended = watch.newest_run != absent_k ? &runs[watch.newest_run] : nullptr;
        if (extended && (extended->release_operation != release || release == absent_k ||
                         extended->sends == std::numeric_limits<std::uint16_t>::max() ||
                         extended->first_id + extended->sends != watch.next_zero_copy_id))
            extended = nullptr;
        if ((release == absent_k && free_operations.head == absent_k) || (!extended && free_runs == absent_k)) {
            tally(statistics.zero_copy_fallbacks);
            return send_copying(request);
        }
        auto const length = std::min<std::size_t>(request.length, std::numeric_limits<int>::max());
        ssize_t const sent = send(static_cast<int>(request.descriptor), request.data, length,
                                  MSG_NOSIGNAL | MSG_ZEROCOPY);
        if (sent < 0 && errno == ENOBUFS) {
            tally(statistics.zero_copy_fallbacks);
            return send_copying(request);
        }
        if (sent <= 0) return sent < 0 ? -errno : 0;
        tally(statistics.zero_copy_sends);
        if (release == absent_k) {
            release = free_operations.pop(operations);
            operations[release] = {};
            operations[release].request = request.release_request;
            releases.insert(operations, release);
        }
        ++operations[release].pending_notifications;
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
        if (operation.pending_notifications) operation.interest = io_interest_t::landing_k;
        return 0;
    }

    /** Closes a socket, or keeps it while notifications are due, resetting it first when it was set
     *  to reset on close, so the kernel purges and notifies at once. Answers through @p closing,
     *  the operation it lands, or `absent_k`. */
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
            tally(statistics.zero_copy_fallbacks, span);
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
                release.pending_notifications -= overlap;
                if (!release.pending_notifications && release.interest == io_interest_t::landing_k)
                    land(run.release_operation, 0);
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
            tally(statistics.kernel_enters);
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
        default: return attempt_io(request, operation.stage, operation.interest, statistics);
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
        while (count != completions.size()) {
            auto index = landed_operations.pop(operations);
            if (index == absent_k) break;
            auto const& operation = operations[index];
            descriptor_t const result = operation.stage == operation_stage_t::cancelled_k ? -ECANCELED
                                                                                          : operation.result;
            completions[count++] = finish(index, result);
        }
        return count;
    }
    int wait(int timeout) noexcept {
        tally(statistics.kernel_enters);
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
        for (auto const& watch : readiness.watches)
            if (watch.oldest_run != absent_k) {
                [[maybe_unused]] ucall_status_t const reset = socket_disconnect_with_reset(watch.descriptor);
            }
        for (;;) {
            std::uint32_t due = absent_k;
            for (std::uint32_t i = 0; i != readiness.watches.size() && due == absent_k; ++i)
                if (readiness.watches[i].oldest_run != absent_k) due = i;
            if (due == absent_k) break;
            drain_error_queue(due);
            if (readiness.watches[due].oldest_run == absent_k) continue;
            pollfd polled {readiness.watches[due].descriptor, 0, 0};
            ::poll(&polled, 1, -1);
        }
        for (auto& watch : readiness.watches)
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
        for (auto& slot : releases.slots) slot = release_table<allocator_t>::absent_k;
    }
};
using linux_epollaio_engine_t = linux_epollaio_engine<>;

#endif // UCALL_OS_LINUX_

#if UCALL_OS_WINDOWS_

/** Overlapped socket operations retain their storage through cancellation completion.
 *
 *  A file read reopens its file unbuffered and overlapped on the port for its own lifetime; path
 *  opens and vectored reads answer `-ENOSYS`, and zero-copy sends copy, so their releases complete
 *  as submitted. */
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
        HANDLE file {}; // A file read's own unbuffered handle, closed as it finishes.
        descriptor_t immediate {};
        operation_stage_t stage {operation_stage_t::pending_k};
        unsigned next {absent_k}, timed {absent_k};
        byte_t addresses[2 * (sizeof(sockaddr_storage) + 16)] {};
    };
    descriptor_t open_socket(int family) noexcept { return socket_open(family); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept { return descriptor; }
    int close_socket(descriptor_t descriptor) noexcept { return socket_close(descriptor); }
    [[nodiscard]] ucall_status_t reset_on_close(descriptor_t descriptor) noexcept {
        return socket_reset_on_close(descriptor);
    }
    memory_registration_t register_memory(span<byte_t>) noexcept { return {}; }
    void release(io_completion_t const&) noexcept {}
    static HANDLE handle_of(operation_t const& operation) noexcept {
        return operation.file ? operation.file : reinterpret_cast<HANDLE>(operation.request->descriptor);
    }
    ucall_status_t cancel(io_request_t& request) noexcept {
        for (auto& operation : operations)
            if (operation.request == &request) {
                if (operation.stage == operation_stage_t::pending_k) {
                    tally(statistics.cancellations);
                    operation.stage = operation_stage_t::cancelling_k;
                    CancelIoEx(handle_of(operation), &operation.overlapped);
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
        if (ucall_status_t const started = sockets_start(); started != ucall_status_success_k) return started;
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
    [[nodiscard]] ucall_status_t extension(SOCKET socket, GUID id, function_type_& function) noexcept {
        DWORD bytes {};
        return WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id), &function, sizeof(function),
                        &bytes, nullptr, nullptr) == 0
                   ? ucall_status_success_k
                   : ucall_status_io_k;
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
        if (request.operation == io_operation_t::shutdown_k)
            return complete_immediately(shutdown(socket, SD_SEND) == 0 ? 0 : -socket_last_error());
        if (request.operation == io_operation_t::zero_copy_release_k) return complete_immediately(0);
        // Directories cannot be registered on Windows, so no path ever reaches an open.
        if (request.operation == io_operation_t::file_open_k ||
            request.operation == io_operation_t::file_read_vectors_k)
            return complete_immediately(-ENOSYS);
        if (request.operation == io_operation_t::file_read_k) return submit_file_read(index);
        if (!CreateIoCompletionPort(reinterpret_cast<HANDLE>(socket), port, 0, 0)) return complete_immediately(-EIO);
        DWORD bytes {}, flags {};
        int result = SOCKET_ERROR;
        switch (request.operation) {
        case io_operation_t::accept_k: {
            LPFN_ACCEPTEX accept_ex {};
            sockaddr_storage address {};
            int length = sizeof(address);
            if (extension(socket, WSAID_ACCEPTEX, accept_ex) != ucall_status_success_k ||
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
            if (extension(socket, WSAID_CONNECTEX, connect_ex) != ucall_status_success_k)
                return complete_immediately(-socket_last_error());
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
        case io_operation_t::send_k:
        case io_operation_t::send_zero_copy_k: {
            WSABUF buffer {static_cast<ULONG>(std::min<std::size_t>(request.length, std::numeric_limits<int>::max())),
                           reinterpret_cast<char*>(request.data)};
            result = WSASend(socket, &buffer, 1, &bytes, 0, &operation->overlapped, nullptr);
            break;
        }
        case io_operation_t::shutdown_k:
        case io_operation_t::close_k:
        case io_operation_t::file_open_k:
        case io_operation_t::file_read_k:
        case io_operation_t::file_read_vectors_k:
        case io_operation_t::zero_copy_release_k: break;
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

    /** Reads through a handle reopened unbuffered and overlapped, associated with the port. */
    ucall_status_t submit_file_read(unsigned index) noexcept {
        auto& operation = operations[index];
        auto& request = *operation.request;
        ++active;
        if (request.deadline) {
            operation.timed = static_cast<unsigned>(timed.size());
            [[maybe_unused]] st::status_t const tracked = timed.push_back(st::assume_reserved, unsigned {index});
        }
        tally(statistics.kernel_enters);
        HANDLE const file = ReOpenFile(reinterpret_cast<HANDLE>(_get_osfhandle(request.file.file_descriptor)),
                                       GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                       FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED);
        descriptor_t failure = -EIO;
        if (file != INVALID_HANDLE_VALUE) {
            operation.file = file;
            operation.overlapped.Offset = static_cast<DWORD>(request.file.offset);
            operation.overlapped.OffsetHigh = static_cast<DWORD>(request.file.offset >> 32);
            auto const length = static_cast<DWORD>(
                std::min<std::size_t>(request.length, std::numeric_limits<DWORD>::max()));
            if (CreateIoCompletionPort(file, port, 0, 0) &&
                (ReadFile(file, request.data, length, nullptr, &operation.overlapped) ||
                 GetLastError() == ERROR_IO_PENDING)) {
                tally(statistics.file_reads_asynchronous);
                return ucall_status_success_k;
            }
            failure = GetLastError() == ERROR_HANDLE_EOF ? 0 : -EIO;
        }
        operation.immediate = failure;
        operation.stage = operation_stage_t::immediate_k;
        immediate_operations.push(operations, index);
        return ucall_status_success_k;
    }
    io_completion_t finish(operation_t& operation, descriptor_t result) noexcept {
        auto& request = *operation.request;
        if (operation.file) {
            CloseHandle(operation.file);
            operation.file = {};
        }
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
                    CancelIoEx(handle_of(operation), &operation.overlapped);
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
                descriptor_t result {};
                if (operation.file)
                    result = GetOverlappedResult(operation.file, &operation.overlapped, &bytes, FALSE)
                                 ? static_cast<descriptor_t>(bytes)
                             : GetLastError() == ERROR_HANDLE_EOF ? 0
                                                                  : -socket_error(static_cast<int>(GetLastError()));
                else
                    result = WSAGetOverlappedResult(static_cast<SOCKET>(operation.request->descriptor),
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
                CancelIoEx(handle_of(operation), &operation.overlapped);
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
#include "ucall/uring618.hpp"
#endif
