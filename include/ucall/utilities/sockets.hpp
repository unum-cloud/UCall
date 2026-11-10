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
#include <ctime>   // `timespec`

#include <bit>       // `std::bit_cast`
#include <chrono>    // `std::chrono::steady_clock`
#include <limits>    // `std::numeric_limits`
#include <string_view>

#include "ucall/utilities/types.hpp" // `descriptor_t`, `span`, `byte_t`

#if UCALL_OS_WINDOWS_
#include <io.h>       // `_get_osfhandle`
#include <winternl.h> // `NtCreateFile`, `OBJECT_ATTRIBUTES`
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
#include <dirent.h>      // `opendir`, `readdir`, `closedir`
#include <sys/syscall.h> // `SYS_statx`
#endif
#if UCALL_OS_APPLE_
#include <libproc.h>   // `proc_pidfdinfo`, `socket_fdinfo`
#include <sys/event.h> // `kqueue`, `kevent`
#endif

namespace unum::ucall::utilities {

#pragma region Kernel

/** @c open_how, the arguments of @c openat2, from Linux 5.6. */
struct linux_open_how_t {
    std::uint64_t flags;
    std::uint64_t mode;
    std::uint64_t resolve;
};
static_assert(sizeof(linux_open_how_t) == 24, "the kernel reads a 24-byte open_how");

/** @c statx_timestamp. */
struct linux_statx_timestamp_t {
    std::int64_t tv_sec;
    std::uint32_t tv_nsec;
    std::int32_t reserved;
};

/** @c statx, with the unbuffered-read alignments Linux 6.1 added. */
struct linux_statx_t {
    std::uint32_t mask;
    std::uint32_t blksize;
    std::uint64_t attributes;
    std::uint32_t nlink;
    std::uint32_t uid;
    std::uint32_t gid;
    std::uint16_t mode;
    std::uint16_t spare0;
    std::uint64_t ino;
    std::uint64_t size;
    std::uint64_t blocks;
    std::uint64_t attributes_mask;
    linux_statx_timestamp_t atime;
    linux_statx_timestamp_t btime;
    linux_statx_timestamp_t ctime;
    linux_statx_timestamp_t mtime;
    std::uint32_t rdev_major;
    std::uint32_t rdev_minor;
    std::uint32_t dev_major;
    std::uint32_t dev_minor;
    std::uint64_t mnt_id;
    std::uint32_t dio_mem_align;
    std::uint32_t dio_offset_align;
    std::uint64_t spare3[12];
};
static_assert(sizeof(linux_statx_t) == 256, "the kernel writes a 256-byte statx");

#pragma endregion Kernel

inline std::uint64_t monotonic_ns() noexcept {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
        .count();
}
inline std::uint64_t deadline_after(std::size_t microseconds) noexcept {
    auto now = monotonic_ns();
    auto maximum = (std::numeric_limits<std::uint64_t>::max)();
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
    case WSAEMFILE: return EMFILE;
    case WSAENOBUFS: return ENOBUFS;
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
    // A Registered I/O socket refuses the flag, and no call it governs ever reaches one.
    return (ioctlsocket(static_cast<SOCKET>(descriptor), FIONBIO, &enabled) == 0 ||
            WSAGetLastError() == WSAEOPNOTSUPP) &&
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
                                                 : (std::numeric_limits<std::size_t>::max)();
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

/** Waits up to @p nanoseconds, the maximum meaning forever, for any of the @p count descriptors in
 *  @p polled: how many reported, or a negated errno. Linux and FreeBSD wait to the nanosecond, and
 *  the rest to the millisecond, rounded up so a wait never ends early. */
inline int socket_poll(pollfd* polled, std::size_t count, std::uint64_t nanoseconds) noexcept {
    bool const forever = nanoseconds == (std::numeric_limits<std::uint64_t>::max)();
    [[maybe_unused]] int const milliseconds = forever ? -1
                                                      : static_cast<int>(fu::min_of<std::uint64_t>(
                                                            nanoseconds / 1'000'000 + (nanoseconds % 1'000'000 != 0),
                                                            (std::numeric_limits<int>::max)()));
#if UCALL_OS_LINUX_ || UCALL_OS_FREEBSD_
    timespec const timeout {static_cast<time_t>(nanoseconds / 1'000'000'000),
                            static_cast<long>(nanoseconds % 1'000'000'000)};
    int const result = ::ppoll(polled, static_cast<nfds_t>(count), forever ? nullptr : &timeout, nullptr);
#elif UCALL_OS_WINDOWS_
    int const result = WSAPoll(polled, static_cast<ULONG>(count), milliseconds);
#else
    int const result = ::poll(polled, static_cast<nfds_t>(count), milliseconds);
#endif // UCALL_OS_LINUX_ || UCALL_OS_FREEBSD_
    return result < 0 ? -socket_last_error() : result;
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

/** The largest @c SO_RCVBUF the kernel grants, or @p fallback, probed on a socket of its own, since
 *  setting it on a listener would pin every accepted socket's buffer and stop autotuning. */
inline std::size_t largest_receive_buffer(int family, std::size_t fallback) noexcept {
    descriptor_t const probe = socket_open(family);
    if (probe < 0) return fallback;
    // Linux clamps an oversized request where FreeBSD and macOS refuse it, so refusals bisect.
    int accepted = 0, refused = (std::numeric_limits<int>::max)();
    if (socket_option(probe, SOL_SOCKET, SO_RCVBUF, &refused, sizeof(refused)) == 0) accepted = refused;
    while (refused - accepted > 1) {
        int const requested = accepted + (refused - accepted) / 2;
        if (socket_option(probe, SOL_SOCKET, SO_RCVBUF, &requested, sizeof(requested)) == 0) accepted = requested;
        else refused = requested;
    }
    int granted = 0;
    socket_length_t length = sizeof(granted);
    bool const measured = accepted &&
                          getsockopt(probe, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<char*>(&granted), &length) == 0 &&
                          granted > 0;
    socket_close(probe);
    return measured ? static_cast<std::size_t>(granted) : fallback;
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

/** Whether @p descriptor listens for connections; Darwin answers only through @c proc_pidfdinfo, as
 *  its @c getsockopt refuses @c SO_ACCEPTCONN with @c ENOPROTOOPT. */
inline bool socket_listening(descriptor_t descriptor) noexcept {
#if UCALL_OS_APPLE_
    socket_fdinfo information {};
    return proc_pidfdinfo(getpid(), static_cast<int>(descriptor), PROC_PIDFDSOCKETINFO, &information,
                          sizeof(information)) == static_cast<int>(sizeof(information)) &&
           (information.psi.soi_options & SO_ACCEPTCONN);
#else
    int listening = 0;
    socket_length_t length = sizeof(listening);
    return getsockopt(descriptor, SOL_SOCKET, SO_ACCEPTCONN, reinterpret_cast<char*>(&listening), &length) == 0 &&
           listening;
#endif // UCALL_OS_APPLE_
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
    if (handed < 0 || handed > (std::numeric_limits<int>::max)()) return -1;
    descriptor_t descriptor = fcntl(static_cast<int>(handed), F_DUPFD_CLOEXEC, 0);
#endif
    if (descriptor == -1) return -1;
    int type = 0;
    socket_length_t type_length = sizeof(type);
    if (getsockopt(descriptor, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&type), &type_length) == 0 &&
        type == SOCK_STREAM && socket_listening(descriptor) && nonblocking(descriptor) == ucall_status_success_k)
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

/** Closes a file or directory, as opposed to a socket. */
inline void close_native_file(native_file_t file) noexcept {
#if UCALL_OS_WINDOWS_
    CloseHandle(file);
#else
    close(file);
#endif
}

/** What @c direct_alignment_of learned of an open file: its size, the alignment its unbuffered
 *  reads keep in memory and the one they keep in offset and length, or a negated errno, which is
 *  @c -ENXIO for anything but a regular file. */
struct file_geometry_t {
    std::uint64_t size {};
    std::uint32_t memory_alignment {}, offset_alignment {};
    std::int32_t error {};
};
static_assert(sizeof(file_geometry_t) == 24);

/** The alignment unbuffered reads assume where the filesystem cannot say, a page everywhere. */
inline constexpr std::uint32_t file_portable_alignment_k = 4096;

/** Whether @p path names something beneath its directory: relative, and free of NUL bytes,
 *  backslashes, <tt>:</tt> drives or streams, and <tt>..</tt> segments, alike on every platform. */
inline bool file_path_beneath(std::string_view path) noexcept {
    if (path.empty() || path.front() == '/' ||
        path.find_first_of(std::string_view {"\\:\0", 3}) != std::string_view::npos)
        return false;
    for (std::size_t start = 0; start <= path.size();) {
        std::size_t end = path.find('/', start);
        if (end == std::string_view::npos) end = path.size();
        if (path.substr(start, end - start) == "..") return false;
        start = end + 1;
    }
    return true;
}

#if UCALL_OS_WINDOWS_

/** Measures the open regular @p file; unbuffered handles want sector alignment, which no volume
 *  sets above a page. */
inline file_geometry_t direct_alignment_of(native_file_t file) noexcept {
    if (GetFileType(file) != FILE_TYPE_DISK) return {0, 0, 0, -ENXIO};
    FILE_STANDARD_INFO standard {};
    if (!GetFileInformationByHandleEx(file, FileStandardInfo, &standard, sizeof(standard))) return {0, 0, 0, -EIO};
    if (standard.Directory) return {0, 0, 0, -ENXIO};
    return {static_cast<std::uint64_t>(standard.EndOfFile.QuadPart), file_portable_alignment_k,
            file_portable_alignment_k, 0};
}

/** Checks that the borrowed @p file reads a disk file. The loop reads it through a handle it
 *  reopens once beneath @p file with an empty name, since only its engine binds to its port. */
inline ucall_status_t file_direct_switch(native_file_t& file) noexcept {
    return GetFileType(file) == FILE_TYPE_DISK ? ucall_status_success_k : ucall_status_invalid_argument_k;
}

/** The handle the C interface's CRT descriptor @p file reads through, which stays the caller's. */
inline native_file_t native_file_of(int file) noexcept { return reinterpret_cast<HANDLE>(_get_osfhandle(file)); }

/** @p path as UTF-16 with backslashes, in @p wide of @p capacity characters: its length, or zero
 *  when it does not convert or fit. */
inline int file_path_wide(char const* path, wchar_t* wide, int capacity) noexcept {
    int const length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, capacity);
    for (int i = 0; i < length; ++i)
        if (wide[i] == L'/') wide[i] = L'\\';
    return length > 1 ? length - 1 : 0;
}

/** Opens the directory @p path as a handle path parts open beneath: its value, or a negated
 *  errno. */
inline descriptor_t directory_open(char const* path) noexcept {
    wchar_t wide[MAX_PATH];
    if (!file_path_wide(path, wide, MAX_PATH)) return -ENOENT;
    HANDLE const directory = CreateFileW(wide, FILE_LIST_DIRECTORY,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                         FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (directory != INVALID_HANDLE_VALUE) return std::bit_cast<descriptor_t>(directory);
    return GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND ? -ENOENT : -EIO;
}

/** Opens @p path for unbuffered, overlapped reads strictly beneath the handle @p directory,
 *  following no reparse point on the way, as @c RESOLVE_BENEATH does on Linux; an empty @p path
 *  reopens the file @p directory names that way. Answers the handle's value, or a negated errno;
 *  every refusal reads as missing, so permissions are never revealed. */
inline descriptor_t open_native_file_beneath(native_file_t directory, char const* path) noexcept {
    wchar_t wide[MAX_PATH];
    int const length = *path && file_path_beneath(path) ? file_path_wide(path, wide, MAX_PATH) : 0;
    if (*path && !length) return -ENOENT;
    UNICODE_STRING name {static_cast<USHORT>(length * sizeof(wchar_t)),
                         static_cast<USHORT>((length + 1) * sizeof(wchar_t)), wide};
    OBJECT_ATTRIBUTES attributes {};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = directory;
    attributes.ObjectName = &name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE;
    IO_STATUS_BLOCK status {};
    HANDLE file {};
    NTSTATUS const opened = NtCreateFile(&file, FILE_GENERIC_READ, &attributes, &status, nullptr, 0,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
                                         FILE_NON_DIRECTORY_FILE | FILE_NO_INTERMEDIATE_BUFFERING, nullptr, 0);
    return opened < 0 ? -ENOENT : std::bit_cast<descriptor_t>(file);
}

#else

#if UCALL_OS_LINUX_

/** Measures the open regular @p file and asks its filesystem what unbuffered reads demand; the
 *  alignments need Linux 6.1. */
inline file_geometry_t direct_alignment_of(native_file_t file) noexcept {
    std::uint32_t const dioalign = 0x2000; // STATX_DIOALIGN
    linux_statx_t status {};
    if (syscall(SYS_statx, file, "", AT_EMPTY_PATH, STATX_TYPE | STATX_SIZE | dioalign, &status) != 0)
        return {0, 0, 0, -errno};
    if (!S_ISREG(status.mode)) return {0, 0, 0, -ENXIO};
    if ((status.mask & dioalign) && status.dio_mem_align && status.dio_offset_align)
        return {status.size, status.dio_mem_align, status.dio_offset_align, 0};
    return {status.size, file_portable_alignment_k, file_portable_alignment_k, 0};
}

#else

/** Measures the open regular @p file; these kernels report no unbuffered alignment, so a page. */
inline file_geometry_t direct_alignment_of(native_file_t file) noexcept {
    struct stat status {};
    if (fstat(file, &status) != 0) return {0, 0, 0, -errno};
    if (!S_ISREG(status.st_mode)) return {0, 0, 0, -ENXIO};
    return {static_cast<std::uint64_t>(status.st_size), file_portable_alignment_k, file_portable_alignment_k, 0};
}

#endif // UCALL_OS_LINUX_

#if UCALL_OS_APPLE_

/** Adopts the borrowed @p file for uncached reads; the switch is shared with the caller's open file
 *  description, and Darwin names no flag to read it back by. */
inline ucall_status_t file_direct_switch(native_file_t& file) noexcept {
    return fcntl(file, F_NOCACHE, 1) == 0 ? ucall_status_success_k : ucall_status_invalid_argument_k;
}

/** The flags every file open beneath a directory takes; a FIFO opens without waiting for a writer,
 *  and @c open_native_file_finish drops the nonblocking flag from what opened. */
inline constexpr int native_file_open_flags_k = O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK;

/** Readies a @p file just opened with @c native_file_open_flags_k for blocking uncached reads: the
 *  descriptor, or a negated errno with the file closed. */
inline native_file_t open_native_file_finish(native_file_t file) noexcept {
    int const flags = fcntl(file, F_GETFL);
    if (flags != -1 && fcntl(file, F_SETFL, flags & ~O_NONBLOCK) == 0 && fcntl(file, F_NOCACHE, 1) == 0) return file;
    int const error = errno;
    close(file);
    return -error;
}

#else

/** Adopts the borrowed @p file for unbuffered, blocking reads; the switch is shared with the
 *  caller's open file description, and a no-op once switched. */
inline ucall_status_t file_direct_switch(native_file_t& file) noexcept {
    int const flags = fcntl(file, F_GETFL);
    int const wanted = (flags | O_DIRECT) & ~O_NONBLOCK;
    return flags != -1 && (wanted == flags || fcntl(file, F_SETFL, wanted) == 0) ? ucall_status_success_k
                                                                                 : ucall_status_invalid_argument_k;
}

/** The flags every file open beneath a directory takes; a FIFO opens without waiting for a writer,
 *  then fails the direct check, and @c open_native_file_finish drops the nonblocking flag from a
 *  file, as io_uring answers a nonblocking file's blocked read with @c -EAGAIN, not a worker. */
inline constexpr int native_file_open_flags_k = O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NONBLOCK | O_DIRECT;

/** Readies a @p file just opened with @c native_file_open_flags_k for blocking unbuffered reads:
 *  the descriptor, or a negated errno with the file closed. */
inline native_file_t open_native_file_finish(native_file_t file) noexcept {
    int const flags = fcntl(file, F_GETFL);
    if (flags != -1 && fcntl(file, F_SETFL, flags & ~O_NONBLOCK) == 0) return file;
    int const error = errno;
    close(file);
    return -error;
}

#endif // UCALL_OS_APPLE_

/** The descriptor @p file reads through, itself. */
inline native_file_t native_file_of(int file) noexcept { return file; }

/** Reads @p file at @p offset into @p bytes, blocking: a count, or a negated errno. */
inline descriptor_t read_native_file(native_file_t file, span<byte_t> bytes, std::uint64_t offset) noexcept {
    ssize_t read;
    do
        read = pread(file, bytes.data(), fu::min_of<std::size_t>(bytes.size(), (std::numeric_limits<int>::max)()),
                     static_cast<off_t>(offset));
    while (read < 0 && errno == EINTR);
    return read >= 0 ? static_cast<descriptor_t>(read) : -errno;
}

/** Scatters @p file from @p offset into @p vectors, blocking: a count, or a negated errno. */
inline descriptor_t read_native_file_vectors(native_file_t file, span<io_vector_t const> vectors,
                                             std::uint64_t offset) noexcept {
    ssize_t read;
    do
        read = preadv(file, vectors.data(), static_cast<int>(fu::min_of<std::size_t>(vectors.size(), IOV_MAX)),
                      static_cast<off_t>(offset));
    while (read < 0 && errno == EINTR);
    return read >= 0 ? static_cast<descriptor_t>(read) : -errno;
}

/** Opens the directory @p path as a descriptor path parts open beneath, or a negated errno. */
inline descriptor_t directory_open(char const* path) noexcept {
#if UCALL_OS_LINUX_
    int const directory = ::open(path, O_PATH | O_DIRECTORY | O_CLOEXEC);
#else
    int const directory = ::open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
#endif
    return directory >= 0 ? directory : -errno;
}

/** Opens @p path with @c native_file_open_flags_k beneath @p directory one name at a time, taking
 *  no <tt>..</tt> and following no link, so it stays inside: a descriptor, or a negated errno. */
inline native_file_t open_native_file_beneath_walk(native_file_t directory, char const* path) noexcept {
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
            next = openat(file, name,
                          (*end ? O_RDONLY | O_DIRECTORY | O_CLOEXEC : native_file_open_flags_k) | O_NOFOLLOW);
            if (next < 0) next = -errno;
        }
        if (file != directory) close(file);
        file = next;
        cursor = *end ? end + 1 : end;
    }
    return file == directory ? -EISDIR : file;
}

/** Opens @p path for unbuffered reads strictly beneath @p directory: a descriptor, or a negated
 *  errno. */
inline native_file_t open_native_file_beneath(native_file_t directory, char const* path) noexcept {
#if UCALL_OS_LINUX_
    long const openat2 = 437 + linux_syscall_offset_k; // SYS_openat2, mirrored for headers older than 5.6

    std::uint64_t const no_magiclinks = 0x02; // RESOLVE_NO_MAGICLINKS
    std::uint64_t const beneath = 0x08;       // RESOLVE_BENEATH
    linux_open_how_t how {};
    how.flags = native_file_open_flags_k;
    how.resolve = beneath | no_magiclinks;
    long const opened = syscall(openat2, directory, path, &how, sizeof(how));
    int file = opened >= 0 ? static_cast<int>(opened) : -errno;
    // A kernel older than 5.6 has no beneath resolution, so the walk stands in for it.
    if (file == -ENOSYS) file = open_native_file_beneath_walk(directory, path);
#elif UCALL_OS_FREEBSD_
    int file = openat(directory, path, native_file_open_flags_k | O_RESOLVE_BENEATH);
    // FreeBSD refuses an escape with ENOTCAPABLE where Linux's beneath resolution answers EXDEV.
    if (file < 0) file = errno == ENOTCAPABLE ? -EXDEV : -errno;
#else
    int file = open_native_file_beneath_walk(directory, path);
#endif // UCALL_OS_LINUX_
    if (file < 0) return file;
    // FreeBSD opens directories and FIFOs under these flags, and a FIFO read would block the loop.
    struct stat status {};
    if (fstat(file, &status) != 0 || !S_ISREG(status.st_mode)) {
        close(file);
        return -ENXIO;
    }
    return open_native_file_finish(file);
}

#endif // UCALL_OS_WINDOWS_

} // namespace unum::ucall::utilities
