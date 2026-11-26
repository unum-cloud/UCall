/**
 *  @file bench/zero_copy_sends.cpp
 *  @author Ash Vardanian
 *  @date November 25, 2026
 *  @brief The sender's cost of copying, zero-copy and registered zero-copy sends, per send size.
 *
 *  One connection sends one buffer back to back through io_uring, one send in flight at a time, as
 *  UCall's ring queues send a reply segment: @c IORING_OP_SEND copies into the socket, while
 *  @c IORING_OP_SEND_ZC pins the pages and notifies once the kernel let go of them, and its
 *  fixed-buffer form sends from memory registered once. Sizes double from @c --minimum-bytes up to
 *  @c --maximum-bytes, which defaults to the largest send buffer @c tcp_wmem grows a socket to.
 *
 *  Without @c --address the receiver is a thread of this process on loopback, pinned to the second
 *  CPU the process may use while the sender takes the first. Loopback delivers by copying, so a
 *  zero-copy send there pays its pinning, its notification and the copy together, and the sender's
 *  thread runs the receiving softirq as well. @c --listen runs that receiver alone, for a sender
 *  on another machine to name in @c --address, so the rows price sends through a real NIC.
 *
 *  Each row also reports every CPU's busy time from @c /proc/stat, interrupt and softirq cores
 *  included, and @c --repetitions repeats the whole sweep. Each flag overrides the variable of the
 *  same name, so @c --time-limit overrides @c UCALL_TIME_LIMIT.
 */
#include <cerrno>  // `errno`
#include <cstdint> // `std::uint64_t`
#include <cstdio>  // `std::fopen`, `std::fscanf`
#include <cstring> // `std::memset`, `std::strerror`

#include <netinet/in.h>  // `IPPROTO_TCP`
#include <netinet/tcp.h> // `TCP_NODELAY`
#include <pthread.h>     // `pthread_setaffinity_np`
#include <sched.h>       // `sched_getaffinity`, `CPU_SET`
#include <sys/mman.h>    // `mmap`, `munmap`
#include <sys/socket.h>  // `socket`, `connect`, `recv`, `MSG_TRUNC`
#include <time.h>        // `clock_gettime`, `CLOCK_THREAD_CPUTIME_ID`
#include <unistd.h>      // `close`, `sysconf`

#include <chrono>      // `std::chrono::steady_clock`
#include <limits>      // `std::numeric_limits`
#include <span>        // `std::span`
#include <string>      // `std::string`
#include <string_view> // `std::string_view`
#include <thread>      // `std::thread`

#include <fmt/format.h> // `fmt::println`
#include <liburing.h>   // `io_uring_prep_send_zc`, `io_uring_prep_send_zc_fixed`
#include <netdb.h>      // `getaddrinfo`, `freeaddrinfo`

#include "ucall/utilities/sockets.hpp" // `largest_send_buffer_bytes`

#include "arguments.hpp" // `exit_unparsed`, `parse_count`, `parse_duration`, `process_cpu_seconds`, `setting_text`

namespace unum::ucall::bench {

using tools::exit_unparsed;
using tools::parse_count;
using tools::parse_duration;
using tools::process_cpu_seconds;
using tools::setting_text;
using utilities::largest_send_buffer_bytes;

/** How one row's sends reach the socket. */
enum class send_kind_t { copying_k, zero_copy_k, registered_zero_copy_k };

inline constexpr send_kind_t send_kinds_k[] {send_kind_t::copying_k, send_kind_t::zero_copy_k,
                                             send_kind_t::registered_zero_copy_k};

inline char const* send_kind_name(send_kind_t kind) noexcept {
    switch (kind) {
    case send_kind_t::copying_k: return "copying";
    case send_kind_t::zero_copy_k: return "zero-copy";
    default: return "registered zero-copy";
    }
}

/** What one run sends and where. */
struct sweep_settings_t {

    /** The smallest send, doubled per row until it passes @c maximum_bytes. */
    std::size_t minimum_bytes {1};

    /** The largest send, the third @c tcp_wmem value unless set. */
    std::size_t maximum_bytes {};

    /** How long each row sends. */
    std::chrono::nanoseconds time_limit {std::chrono::seconds {1}};

    /** How many times the whole sweep runs, each repetition printing its own rows. */
    std::size_t repetitions {1};

    /** The receiver's @c host:port, or null for a loopback receiver of this process. */
    char const* address {};

    /** The @c host:port to receive on, which makes this process only a receiver. */
    char const* listen {};
};

/** Reads every setting, each flag over its variable. */
inline sweep_settings_t read_settings(int argc, char** argv) noexcept {
    sweep_settings_t settings;
    settings.maximum_bytes = largest_send_buffer_bytes();
    if (char const* text = setting_text(argc, argv, "UCALL_MINIMUM_BYTES", "--minimum-bytes"))
        if (!parse_count(text, settings.minimum_bytes, 1)) exit_unparsed("UCALL_MINIMUM_BYTES", text, "a count");
    if (char const* text = setting_text(argc, argv, "UCALL_MAXIMUM_BYTES", "--maximum-bytes"))
        if (!parse_count(text, settings.maximum_bytes, 1)) exit_unparsed("UCALL_MAXIMUM_BYTES", text, "a count");
    if (char const* text = setting_text(argc, argv, "UCALL_REPETITIONS", "--repetitions"))
        if (!parse_count(text, settings.repetitions, 1)) exit_unparsed("UCALL_REPETITIONS", text, "a count");
    if (char const* text = setting_text(argc, argv, "UCALL_TIME_LIMIT", "--time-limit"))
        if (!parse_duration(text, settings.time_limit)) exit_unparsed("UCALL_TIME_LIMIT", text, "a duration");
    settings.address = setting_text(argc, argv, "UCALL_ADDRESS", "--address");
    settings.listen = setting_text(argc, argv, "UCALL_LISTEN", "--listen");
    if (!settings.maximum_bytes) exit_unparsed("UCALL_MAXIMUM_BYTES", "", "a count, as tcp_wmem is unreadable");
    return settings;
}

/** The first address @p text, spelled @c host:port, resolves to under @c getaddrinfo's
 *  @p resolution_flags, or null. */
inline addrinfo* resolve(char const* text, int resolution_flags) noexcept {
    std::string_view const spelled {text};
    std::size_t const colon = spelled.rfind(':');
    if (colon == std::string_view::npos) return nullptr;
    std::string const host {spelled.substr(0, colon)}, port {spelled.substr(colon + 1)};
    addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = resolution_flags;
    addrinfo* resolved = nullptr;
    return getaddrinfo(host.c_str(), port.c_str(), &hints, &resolved) == 0 ? resolved : nullptr;
}

/** Pins the calling thread to the @p ordinal -th CPU the process may use, if there is one. */
inline void pin_to_allowed_cpu(unsigned ordinal) noexcept {
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) return;
    for (unsigned cpu = 0, seen = 0; cpu != CPU_SETSIZE; ++cpu) {
        if (!CPU_ISSET(cpu, &allowed) || seen++ != ordinal) continue;
        cpu_set_t chosen;
        CPU_ZERO(&chosen);
        CPU_SET(cpu, &chosen);
        pthread_setaffinity_np(pthread_self(), sizeof(chosen), &chosen);
        return;
    }
}

/** Takes the next connection on @p listener and discards what it sends, without copying it, until
 *  it ends; false once the listener takes none. */
inline bool drain_connection(int listener) noexcept {
    int const connection = accept(listener, nullptr, nullptr);
    if (connection < 0) return false;
    while (recv(connection, nullptr, (std::numeric_limits<int>::max)(), MSG_TRUNC) > 0) {}
    close(connection);
    return true;
}

/** A listening socket bound to @p resolved, or -1. */
inline int listen_on(addrinfo const& resolved) noexcept {
    int const listener = socket(resolved.ai_family, SOCK_STREAM, 0);
    int const enabled = 1;
    if (listener < 0) return -1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    if (bind(listener, resolved.ai_addr, resolved.ai_addrlen) != 0 || ::listen(listener, 1) != 0) {
        close(listener);
        return -1;
    }
    return listener;
}

/** A connected socket with @c TCP_NODELAY, as UCall's are, or -1. */
inline int connect_to(sockaddr const* address, socklen_t length) noexcept {
    int const sender = socket(address->sa_family, SOCK_STREAM, 0);
    int const enabled = 1;
    if (sender < 0) return -1;
    setsockopt(sender, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
    if (connect(sender, address, length) != 0) {
        close(sender);
        return -1;
    }
    return sender;
}

/** CPU seconds the calling thread spent so far. */
inline double thread_cpu_seconds() noexcept {
    timespec spent {};
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &spent);
    return static_cast<double>(spent.tv_sec) + static_cast<double>(spent.tv_nsec) * 1e-9;
}

/** Seconds every CPU of the machine spent busy so far, interrupts and softirqs included, from the
 *  aggregate line of @c /proc/stat; zero where it is unreadable. */
inline double machine_busy_seconds() noexcept {
    std::FILE* file = std::fopen("/proc/stat", "r");
    if (!file) return 0;
    unsigned long long user = 0, nice = 0, system = 0, idle = 0, waiting = 0, interrupts = 0, softirqs = 0, stolen = 0;
    int const read = std::fscanf(file, "cpu %llu %llu %llu %llu %llu %llu %llu %llu", &user, &nice, &system, &idle,
                                 &waiting, &interrupts, &softirqs, &stolen);
    std::fclose(file);
    if (read != 8) return 0;
    return static_cast<double>(user + nice + system + interrupts + softirqs + stolen) /
           static_cast<double>(sysconf(_SC_CLK_TCK));
}

/** What one row measured. */
struct row_t {
    std::uint64_t sends {}, bytes {}, notifications {}, copied_notifications {};
    double wall_seconds {}, sender_cpu_seconds {}, process_cpu_seconds {}, machine_busy_seconds {};
    int error {};
};

/** Queues one send of @p bytes from @p data on @p socket the way @p kind asks. */
inline void prepare_send(io_uring& ring, send_kind_t kind, int socket, std::byte const* data,
                         std::size_t bytes) noexcept {
    io_uring_sqe* submission = io_uring_get_sqe(&ring);
    if (kind == send_kind_t::copying_k) io_uring_prep_send(submission, socket, data, bytes, MSG_NOSIGNAL);
    else if (kind == send_kind_t::zero_copy_k)
        io_uring_prep_send_zc(submission, socket, data, bytes, MSG_NOSIGNAL, IORING_SEND_ZC_REPORT_USAGE);
    else io_uring_prep_send_zc_fixed(submission, socket, data, bytes, MSG_NOSIGNAL, IORING_SEND_ZC_REPORT_USAGE, 0);
}

/** Sends whole sends of @p bytes from @p buffer until @p time_limit passed, one in flight, then
 *  waits for every notification the kernel still owes. */
inline row_t run_row(io_uring& ring, int socket, std::byte const* buffer, std::size_t bytes, send_kind_t kind,
                     std::chrono::nanoseconds time_limit) noexcept {
    row_t row;
    auto const started = std::chrono::steady_clock::now();
    double const sender_started = thread_cpu_seconds(), process_started = process_cpu_seconds(),
                 machine_started = machine_busy_seconds();
    std::size_t offset = 0;
    std::uint64_t owed_notifications = 0;
    bool sending = false;
    for (;;) {
        if (!sending && !offset && std::chrono::steady_clock::now() - started >= time_limit) break;
        if (!sending) prepare_send(ring, kind, socket, buffer + offset, bytes - offset);
        sending = true;
        io_uring_submit_and_wait(&ring, 1);
        unsigned head, seen = 0;
        io_uring_cqe* completion;
        io_uring_for_each_cqe(&ring, head, completion) {
            ++seen;
            if (completion->flags & IORING_CQE_F_NOTIF) {
                --owed_notifications;
                ++row.notifications;
                row.copied_notifications += (static_cast<std::uint32_t>(completion->res) &
                                             IORING_NOTIF_USAGE_ZC_COPIED) != 0;
                continue;
            }
            owed_notifications += (completion->flags & IORING_CQE_F_MORE) != 0;
            sending = false;
            if (completion->res < 0) row.error = -completion->res;
            if (completion->res <= 0) continue;
            offset += static_cast<std::size_t>(completion->res);
            row.bytes += static_cast<std::uint64_t>(completion->res);
            if (offset != bytes) continue;
            offset = 0;
            ++row.sends;
        }
        io_uring_cq_advance(&ring, seen);
        if (row.error) return row;
    }
    while (owed_notifications) {
        io_uring_cqe* completion;
        if (io_uring_wait_cqe(&ring, &completion) != 0) break;
        --owed_notifications;
        ++row.notifications;
        row.copied_notifications += (static_cast<std::uint32_t>(completion->res) & IORING_NOTIF_USAGE_ZC_COPIED) != 0;
        io_uring_cqe_seen(&ring, completion);
    }
    row.wall_seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    row.sender_cpu_seconds = thread_cpu_seconds() - sender_started;
    row.process_cpu_seconds = process_cpu_seconds() - process_started;
    row.machine_busy_seconds = machine_busy_seconds() - machine_started;
    return row;
}

/** A byte count in powers of two: B, KB, MB or GB. */
inline std::string format_bytes(std::size_t bytes) noexcept {
    char const* units[] {"B", "KB", "MB", "GB"};
    std::size_t unit = 0;
    while (unit + 1 != std::size(units) && bytes >= 1024 && bytes % 1024 == 0) bytes /= 1024, ++unit;
    return fmt::format("{} {}", bytes, units[unit]);
}

/** Sends @p bytes from @p buffer in each of @p kinds, printing one row of repetition @p repetition
 *  each; nonzero once a send failed. */
inline int sweep_send_kinds(io_uring& ring, int sender, std::byte const* buffer, std::size_t bytes,
                            std::span<send_kind_t const> kinds, std::size_t repetition,
                            sweep_settings_t const& settings) noexcept {
    for (send_kind_t const kind : kinds) {
        row_t const row = run_row(ring, sender, buffer, bytes, kind, settings.time_limit);
        if (row.error) {
            fmt::println(stderr, "{} sends of {} failed: {}", send_kind_name(kind), format_bytes(bytes),
                         std::strerror(row.error));
            return 1;
        }
        double const kilobytes = static_cast<double>(row.bytes) / 1024;
        double const copied = row.notifications ? 100.0 * static_cast<double>(row.copied_notifications) /
                                                      static_cast<double>(row.notifications)
                                                : 0.0;
        fmt::println(
            "| {:>10} | {:<20} | {:>8} | {:>9} | {:>7.2f} | {:>14.3f} | {:>12.1f} | {:>13.1f} | {:>13.1f} | " //
            "{:>7.1f}% |",
            repetition + 1, send_kind_name(kind), format_bytes(bytes), row.sends,
            static_cast<double>(row.bytes) * 8 / row.wall_seconds / 1e9,
            row.sender_cpu_seconds * 1e6 / static_cast<double>(row.sends), row.sender_cpu_seconds * 1e9 / kilobytes,
            row.process_cpu_seconds * 1e9 / kilobytes, row.machine_busy_seconds * 1e9 / kilobytes, copied);
        std::fflush(stdout);
    }
    return 0;
}

/** Sweeps every send size and kind against the receiver @p settings name, one row each. */
inline int sweep_send_sizes(sweep_settings_t const& settings) noexcept {
    fmt::println("- Receiver: {}", settings.address ? settings.address : "loopback thread");
    fmt::println("- Sizes: {} to {}", format_bytes(settings.minimum_bytes), format_bytes(settings.maximum_bytes));
    fmt::println("- Time limit per row: {} ms",
                 std::chrono::duration_cast<std::chrono::milliseconds>(settings.time_limit).count());
    fmt::println("- Repetitions: {}", settings.repetitions);
    std::thread receiver;
    int sender = -1;
    if (settings.address) {
        addrinfo* resolved = resolve(settings.address, 0);
        if (resolved) sender = connect_to(resolved->ai_addr, resolved->ai_addrlen);
        if (resolved) freeaddrinfo(resolved);
    }
    else {
        addrinfo* resolved = resolve("127.0.0.1:0", AI_PASSIVE);
        int const listener = resolved ? listen_on(*resolved) : -1;
        if (resolved) freeaddrinfo(resolved);
        sockaddr_storage bound {};
        socklen_t length = sizeof(bound);
        if (listener >= 0 && getsockname(listener, reinterpret_cast<sockaddr*>(&bound), &length) == 0) {
            receiver = std::thread([listener] {
                pin_to_allowed_cpu(1);
                drain_connection(listener);
                close(listener);
            });
            sender = connect_to(reinterpret_cast<sockaddr*>(&bound), length);
        }
    }
    if (sender < 0) {
        fmt::println(stderr, "connecting failed: {}", std::strerror(errno));
        if (receiver.joinable()) receiver.detach();
        return 1;
    }
    pin_to_allowed_cpu(0);
    void* const mapped = mmap(nullptr, settings.maximum_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
                              0);
    // One send is in flight, so one submission entry, while each send the kernel still holds owes
    // a notification: as many as the smallest sends the largest buffer holds, plus the result,
    // clamped to the kernel's own limit.
    io_uring_params parameters {};
    parameters.flags = IORING_SETUP_CQSIZE | IORING_SETUP_CLAMP;
    parameters.cq_entries = static_cast<unsigned>(fu::min_of<std::size_t>(
        settings.maximum_bytes / settings.minimum_bytes + 2, (std::numeric_limits<unsigned>::max)()));
    io_uring ring {};
    if (mapped == MAP_FAILED || io_uring_queue_init_params(1, &ring, &parameters) != 0) {
        fmt::println(stderr, "setting up failed: {}", std::strerror(errno));
        return 1;
    }
    auto* const buffer = static_cast<std::byte*>(mapped);
    std::memset(buffer, 0x55, settings.maximum_bytes);
    iovec const registered {buffer, settings.maximum_bytes};
    // Registered zero-copy sends come last, so a kernel refusing the registration drops only them.
    std::span<send_kind_t const> kinds {send_kinds_k};
    if (io_uring_register_buffers(&ring, &registered, 1) != 0) kinds = kinds.first(kinds.size() - 1);
    fmt::println("| {:>10} | {:<20} | {:>8} | {:>9} | {:>7} | {:>14} | {:>12} | {:>13} | {:>13} | {:>8} |",
                 "Repetition", "Send", "Bytes", "Sends", "Gbit/s", "Sender µs/send", "Sender ns/KB", "Process ns/KB",
                 "Machine ns/KB", "Copied");
    int status = 0;
    for (std::size_t repetition = 0; repetition != settings.repetitions && !status; ++repetition)
        for (std::size_t bytes = settings.minimum_bytes; bytes <= settings.maximum_bytes && !status; bytes *= 2)
            status = sweep_send_kinds(ring, sender, buffer, bytes, kinds, repetition, settings);
    io_uring_queue_exit(&ring);
    shutdown(sender, SHUT_WR);
    close(sender);
    if (receiver.joinable()) receiver.join();
    munmap(mapped, settings.maximum_bytes);
    return status;
}

} // namespace unum::ucall::bench

int main(int argc, char** argv) {
    using namespace unum::ucall::bench;
    sweep_settings_t const settings = read_settings(argc, argv);
    if (!settings.listen) return sweep_send_sizes(settings);
    addrinfo* resolved = resolve(settings.listen, AI_PASSIVE);
    int const listener = resolved ? listen_on(*resolved) : -1;
    if (resolved) freeaddrinfo(resolved);
    if (listener < 0) {
        fmt::println(stderr, "listening on {} failed: {}", settings.listen, std::strerror(errno));
        return 1;
    }
    while (drain_connection(listener)) {}
    return 0;
}
