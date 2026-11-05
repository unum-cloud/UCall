/**
 *  @file include/ucall/utilities/sockets.hpp
 *  @author Ash Vardanian
 *  @date January 13, 2025
 *  @brief The clock, socket and file calls each operating system spells its own way.
 */
#pragma once

#include <cerrno>
#include <climits>
#include <cstdio>  // `std::snprintf`
#include <cstring> // `std::strchr`, `std::memcpy`

#include <algorithm> // `std::min`, `std::max`
#include <chrono>    // `std::chrono::steady_clock`
#include <limits>    // `std::numeric_limits`
#include <string_view>

#include "ucall/utilities/types.hpp" // `descriptor_t`, `span`, `byte_t`

#if UCALL_OS_WINDOWS_
#include <fcntl.h>    // `_O_RDONLY`
#include <io.h>       // `_get_osfhandle`, `_open_osfhandle`
#include <winternl.h> // `NtCreateFile`, `OBJECT_ATTRIBUTES`
#include <sys/stat.h> // `_fstat64`
#include <ws2tcpip.h>
#include <afunix.h> // `sockaddr_un`
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h> // `IPPROTO_TCP`, `sockaddr_in6`, which glibc alone pulls in through `<arpa/inet.h>`
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/resource.h> // `getrlimit`
#include <sys/socket.h>
#include <sys/stat.h> // `fstat`, `statx`
#include <sys/uio.h>  // `iovec`, `preadv`
#include <sys/un.h>   // `sockaddr_un`
#include <unistd.h>
#endif
#if UCALL_OS_LINUX_
#include <dirent.h>        // `opendir`, `readdir`, `closedir`
#include <linux/openat2.h> // `open_how`, `RESOLVE_BENEATH`
#include <sys/syscall.h>   // `SYS_openat2`
#endif                     // UCALL_OS_LINUX_

namespace unum::ucall::utilities {

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
    case WSAECONNABORTED: return ECONNABORTED;
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

/** The most descriptors the process may hold, which also bounds a registered file table. */
inline std::size_t open_files_limit() noexcept {
    rlimit files {};
    return getrlimit(RLIMIT_NOFILE, &files) == 0 ? static_cast<std::size_t>(files.rlim_cur)
                                                 : std::numeric_limits<std::size_t>::max();
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

/** The @c SO_LINGER setting that makes a close send a reset rather than a FIN. */
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
        WSASocketW(family, SOCK_STREAM, family == AF_UNIX ? 0 : IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED));
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

/** The receive queues the network device @p device_name has, one or more, or zero when it names
 *  no device or the platform exposes no queues. */
inline std::size_t receive_queues_count([[maybe_unused]] std::string_view device_name) noexcept {
#if UCALL_OS_LINUX_
    char path[256];
    if (std::memchr(device_name.data(), '/', device_name.size()) ||
        std::snprintf(path, sizeof(path), "/sys/class/net/%.*s/queues", static_cast<int>(device_name.size()),
                      device_name.data()) >= static_cast<int>(sizeof(path)))
        return 0;
    DIR* directory = opendir(path);
    if (!directory) return 0;
    std::size_t queues = 0;
    while (auto* entry = readdir(directory))
        if (std::strncmp(entry->d_name, "rx-", 3) == 0) ++queues;
    closedir(directory);
    return queues ? queues : 1;
#else
    return 0;
#endif // UCALL_OS_LINUX_
}

/** A nonblocking duplicate of @p handed, a listening stream socket a caller passed in, or -1 when
 *  it is none; the caller's own descriptor stays open and shares the nonblocking flag. */
inline descriptor_t socket_duplicate_listener(std::intptr_t handed) noexcept {
#if UCALL_OS_WINDOWS_
    WSAPROTOCOL_INFOW information {};
    if (WSADuplicateSocketW(static_cast<SOCKET>(handed), GetCurrentProcessId(), &information) != 0) return -1;
    auto descriptor = static_cast<descriptor_t>(
        WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &information, 0, WSA_FLAG_OVERLAPPED));
#else
    if (handed < 0 || handed > std::numeric_limits<int>::max()) return -1;
    descriptor_t descriptor = fcntl(static_cast<int>(handed), F_DUPFD_CLOEXEC, 0);
#endif
    if (descriptor == -1) return -1;
    int listening = 0, type = 0;
    socket_length_t listening_length = sizeof(listening), type_length = sizeof(type);
    if (getsockopt(descriptor, SOL_SOCKET, SO_ACCEPTCONN, reinterpret_cast<char*>(&listening), &listening_length) ==
            0 &&
        getsockopt(descriptor, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&type), &type_length) == 0 && listening &&
        type == SOCK_STREAM && nonblocking(descriptor) == ucall_status_success_k)
        return descriptor;
    socket_close(descriptor);
    return -1;
}

/** An accepted socket set up for the loop, or a negated error; the accepted socket's own setup
 *  failures report @c ECONNABORTED, so they never read as the listener's. */
inline descriptor_t accepted_socket(descriptor_t descriptor, int family) noexcept {
    if (descriptor == -1) return -socket_last_error();
    if (nonblocking(descriptor) != ucall_status_success_k) {
        socket_close(descriptor);
        return -ECONNABORTED;
    }
    int enabled = 1;
    // Unix-domain sockets have no TCP options to set.
    if ((family == AF_INET || family == AF_INET6) &&
        socket_option(descriptor, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) != 0) {
        socket_close(descriptor);
        return -ECONNABORTED;
    }
#if UCALL_OS_APPLE_
    if (setsockopt(static_cast<int>(descriptor), SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
        socket_close(descriptor);
        return -ECONNABORTED;
    }
#endif
    return descriptor;
}

/** What a failed accept means: its peer or route failed, the host ran short, or
 * its listener broke. */
enum class accept_failure_t : std::uint8_t { peer_k, exhausted_k, broken_k };
inline accept_failure_t accept_failure(int error) noexcept {
    switch (error) {
    case EMFILE:
    case ENFILE:
    case ENOBUFS:
    case ENOMEM: return accept_failure_t::exhausted_k;
    case ECONNABORTED:
    case ECANCELED:
    case ECONNRESET: // AcceptEx reports a peer that reset before acceptance as ERROR_NETNAME_DELETED.
    case EINTR:
    case EAGAIN:
    case EPERM:
    case EPROTO:
    case ENOPROTOOPT:
    case ENETDOWN:
    case ENETUNREACH:
    case EHOSTUNREACH:
    case EOPNOTSUPP:
#if UCALL_OS_POSIX_
    case EHOSTDOWN:
#endif
#if UCALL_OS_LINUX_
    case ENONET:
#endif
        return accept_failure_t::peer_k;
    default: return accept_failure_t::broken_k;
    }
}

/** One destination of a @c file_read_vectors_k, the platform's own scatter element, braced as
 *  <tt>{data, length}</tt>. */
#if UCALL_OS_WINDOWS_
struct io_vector_t {
    void* iov_base {};
    std::size_t iov_len {};
};
#else
using io_vector_t = iovec;
#endif
static_assert(sizeof(io_vector_t) == 16);

/** Closes a file or directory descriptor, as opposed to a socket. */
inline void file_close(int file) noexcept {
#if UCALL_OS_WINDOWS_
    _close(file);
#else
    close(file);
#endif
}

/** What @c file_direct_alignment learned of an open file: its size and the alignment its unbuffered
 *  reads meet in offset, length and memory, or a negated errno, which is @c -ENXIO for anything but
 *  a regular file. */
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

/** @p path as UTF-16 with backslashes, in @p wide of @p capacity characters: its length, or zero
 *  when it does not convert or fit. */
inline int file_path_wide(char const* path, wchar_t* wide, int capacity) noexcept {
    int const length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, capacity);
    for (int i = 0; i < length; ++i)
        if (wide[i] == L'/') wide[i] = L'\\';
    return length > 1 ? length - 1 : 0;
}

/** Opens the directory @p path as a CRT descriptor whose handle path parts open beneath. */
inline int directory_open(char const* path) noexcept {
    wchar_t wide[MAX_PATH];
    if (!file_path_wide(path, wide, MAX_PATH)) return -ENOENT;
    HANDLE const directory = CreateFileW(wide, FILE_LIST_DIRECTORY,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                         FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (directory == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND ? -ENOENT : -EIO;
    int const descriptor = _open_osfhandle(reinterpret_cast<intptr_t>(directory), _O_RDONLY);
    if (descriptor < 0) CloseHandle(directory);
    return descriptor < 0 ? -EIO : descriptor;
}

/** Whether @p path names something beneath its directory: relative, without a drive, a <tt>..</tt>
 *  segment or a <tt>:</tt> stream. */
inline bool file_path_beneath(std::string_view path) noexcept {
    if (path.empty() || path.front() == '/' || path.front() == '\\' || path.find(':') != std::string_view::npos)
        return false;
    for (std::size_t start = 0; start <= path.size();) {
        std::size_t end = path.find_first_of("/\\", start);
        if (end == std::string_view::npos) end = path.size();
        if (path.substr(start, end - start) == "..") return false;
        start = end + 1;
    }
    return true;
}

/** Opens @p path for reads strictly beneath the descriptor @p directory names, following no
 *  reparse point on the way, as @c RESOLVE_BENEATH does on Linux: a descriptor, or a negated
 *  errno; every refusal reads as missing, so permissions are never revealed. */
inline int file_open_beneath(int directory, char const* path) noexcept {
    wchar_t wide[MAX_PATH];
    int const length = file_path_beneath(path) ? file_path_wide(path, wide, MAX_PATH) : 0;
    if (!length) return -ENOENT;
    UNICODE_STRING name {static_cast<USHORT>(length * sizeof(wchar_t)),
                         static_cast<USHORT>((length + 1) * sizeof(wchar_t)), wide};
    OBJECT_ATTRIBUTES attributes {};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = reinterpret_cast<HANDLE>(_get_osfhandle(directory));
    attributes.ObjectName = &name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE;
    IO_STATUS_BLOCK status {};
    HANDLE file {};
    NTSTATUS const opened = NtCreateFile(&file, FILE_GENERIC_READ, &attributes, &status, nullptr, 0,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
                                         FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
    if (opened < 0) return -ENOENT;
    int const descriptor = _open_osfhandle(reinterpret_cast<intptr_t>(file), _O_RDONLY);
    if (descriptor < 0) CloseHandle(file);
    return descriptor < 0 ? -EIO : descriptor;
}

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
 *  and @c file_open_finish drops the nonblocking flag from what opened. */
inline constexpr int file_open_flags_k = O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK;

/** Readies a @p file just opened with @c file_open_flags_k for blocking uncached reads: the
 *  descriptor, or a negated errno with the file closed. */
inline int file_open_finish(int file) noexcept {
    int const flags = fcntl(file, F_GETFL);
    if (flags != -1 && fcntl(file, F_SETFL, flags & ~O_NONBLOCK) == 0 && fcntl(file, F_NOCACHE, 1) == 0) return file;
    int const error = errno;
    close(file);
    return -error;
}

#else

/** Refuses a borrowed @p file opened without @c O_DIRECT, whose reads would go through the
 *  cache. */
inline ucall_status_t file_direct_check(int file) noexcept {
    int const flags = fcntl(file, F_GETFL);
    return flags != -1 && (flags & O_DIRECT) ? ucall_status_success_k : ucall_status_invalid_argument_k;
}

/** The flags every file open beneath a directory takes; a FIFO opens without waiting for a writer,
 *  then fails the direct check, and @c file_open_finish drops the nonblocking flag from a file, as
 *  io_uring answers a nonblocking file's blocked read with @c -EAGAIN instead of a worker. */
inline constexpr int file_open_flags_k = O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK | O_DIRECT;

/** Readies a @p file just opened with @c file_open_flags_k for blocking unbuffered reads: the
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

/** Opens the directory @p path as a descriptor path parts open beneath, or a negated errno. */
inline int directory_open(char const* path) noexcept {
#if UCALL_OS_LINUX_
    int const directory = ::open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
#else
    int const directory = ::open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
#endif
    return directory >= 0 ? directory : -errno;
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
    // FreeBSD refuses an escape with ENOTCAPABLE where Linux's beneath resolution answers EXDEV.
    if (file < 0) file = errno == ENOTCAPABLE ? -EXDEV : -errno;
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
    if (file < 0) return file;
    // FreeBSD opens directories and FIFOs under these flags, and a FIFO read would block the loop.
    struct stat status {};
    if (fstat(file, &status) != 0 || !S_ISREG(status.st_mode)) {
        close(file);
        return -ENXIO;
    }
    return file_open_finish(file);
}

#endif // UCALL_OS_WINDOWS_

} // namespace unum::ucall::utilities
