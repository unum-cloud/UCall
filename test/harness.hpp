/**
 *  @file test/harness.hpp
 *  @author Ash Vardanian
 *  @date August 9, 2026
 *  @brief Harness for the C++ test suites: the run, its checks, the sweep and byte diagnostics.
 *
 *  A failed check counts into @c test_run and lets the case go on, so one run lists every mismatch
 *  it reaches. @c run_test_case diffs that count around each case and prints its verdict, which a
 *  failure follows with the command that reruns only that case, under the same seed. Where the next
 *  line would dereference what a check guarded, the case returns on the check's answer instead.
 *
 *  @section harness_settings Settings
 *
 *  Each reads <tt>UCALL_&lt;NAME&gt;</tt>, and a <tt>--name</tt> flag of the same name overrides it.
 *
 *  - <tt>UCALL_SEED</tt> : Seed every case's streams derive from, or <tt>random</tt>. Defaults to 42,
 *    and is always printed at startup, so a run reproduces without being told.
 *  - <tt>UCALL_SCALE</tt> : Scales every sweep and iteration count. Defaults to 1. Use 0.1 for a
 *    quick run, 10 for a thorough one.
 *  - <tt>UCALL_FILTER</tt> : Case labels to run, as a regex or else a substring; unset runs every
 *    case, and a filter selecting none fails the run.
 *  - <tt>UCALL_TRAP_ON_FAILURE</tt> : Traps on the first failed check, to stop there under a
 *    debugger.
 *  - <tt>UCALL_NO_SKIPS</tt> : Exits with 3 when any case skipped.
 *  - <tt>UCALL_BACKEND</tt> : The one queue a sweep keeps; unset keeps every compiled one.
 *  - <tt>UCALL_CPU_CLASS_CEILING</tt> : The one CPU class ceiling a sweep keeps; unset keeps every
 *    class this machine runs.
 *  - <tt>UCALL_TEST_DIRECT_DIRECTORY</tt> : Where cases reading files with @c O_DIRECT make their
 *    directories; the working directory when unset, which CTest sets to the build tree.
 *
 *  @section Example Usage
 *
 *  @code{.sh}
 *  # Only the 6.18 ring's network cells, at a tenth of the usual depth.
 *  UCALL_FILTER='^network\.linux_uring618\.' UCALL_SCALE=0.1 build_debug_siblings/ucall_test
 *
 *  # A thorough sweep, reproducible from a named seed.
 *  build_debug_siblings/ucall_test --seed 12345 --scale 10
 *  @endcode
 */
#pragma once
#include <cerrno>  // `errno`, `EAGAIN`, `EINTR`
#include <cctype>  // `std::tolower`
#include <cmath>   // `std::llround`, `std::isfinite`
#include <csignal> // `std::signal`, `std::raise`, `SIGABRT`, `SIGSEGV`, `SIGTRAP`
#include <cstddef> // `std::size_t`
#include <cstdint> // `std::uint64_t`, `std::uint_least32_t`
#include <cstdio>  // `std::FILE`, `std::fflush`, `stderr`
#include <cstdlib> // `std::abort`, `std::exit`, `std::getenv`, `std::strtod`
#include <cstring> // `std::strcmp`, `std::strncmp`, `std::memcmp`

#include <algorithm>       // `std::max`, `std::replace`
#include <atomic>          // `std::atomic`
#include <charconv>        // `std::from_chars`
#include <chrono>          // `std::chrono::steady_clock`
#include <filesystem>      // `std::filesystem::remove_all`
#include <functional>      // `std::invoke`
#include <limits>          // `std::numeric_limits`
#include <random>          // `std::random_device`, `std::uniform_random_bit_generator`
#include <regex>           // `std::regex`, `std::regex_search`
#include <source_location> // `std::source_location`
#include <string>          // `std::string`
#include <string_view>     // `std::string_view`
#include <system_error>    // `std::errc`
#include <thread>          // `std::this_thread::yield`
#include <type_traits>     // `std::true_type`, `std::invoke_result_t`, `std::type_identity_t`
#include <utility>         // `std::forward`, `std::exchange`

#include <fmt/base.h>   // `fmt::print`, `fmt::format_string`
#include <fmt/format.h> // `fmt::formatter`, `fmt::format_to`

#include <forkunion/types.hpp>         // `fu::max_of`
#include <stringzilla/stringzilla.hpp> // `sz::string_t`

#include "ucall/ucall.h"             // `ucall_client_init`, `ucall_io_backend_name`
#include "ucall/utilities/types.hpp" // `byte_t`, `span`

#include "arguments.hpp" // `exit_stopped_k`, `parse_backend`, `parse_cpu_class`
#include "lib.hpp"       // `cpu_classes_k`

#if UCALL_OS_LINUX_ || UCALL_OS_APPLE_
#include <unistd.h> // `write`, `STDERR_FILENO`
#endif
#if (defined(__GLIBC__) || UCALL_OS_APPLE_) && __has_include(<execinfo.h>)
#include <execinfo.h> // `backtrace`, `backtrace_symbols_fd`
#endif
#if UCALL_OS_POSIX_
#include <arpa/inet.h>   // `inet_pton`, `htons`
#include <netinet/in.h>  // `sockaddr_in`
#include <netinet/tcp.h> // `TCP_NODELAY`
#include <fcntl.h>       // `fcntl`
#include <poll.h>        // `poll`
#include <sys/socket.h>  // `socket`, `connect`, `send`, `recv`, `accept`
#include <sys/stat.h>    // `statx`, `STATX_DIOALIGN`
#include <unistd.h>      // `close`
#endif
#if UCALL_OS_LINUX_
#include <linux/magic.h> // `TMPFS_MAGIC`
#include <sys/vfs.h>     // `statfs`
#endif

namespace sz = ashvardanian::stringzilla;
namespace uc = unum::ucall;

/** Prints an owning StringZilla string as the text it holds, never as a range of characters. */
template <>
struct fmt::formatter<sz::string_t> : fmt::formatter<std::string_view> {
    fmt::format_context::iterator format(sz::string_t const& text, fmt::format_context& context) const {
        return fmt::formatter<std::string_view>::format(std::string_view {text}, context);
    }
};

namespace unum::ucall::test {

using tools::exit_stopped_k;
using util::byte_span;
using util::byte_t;
using util::bytes_view;
using util::descriptor_t;
using util::span;
using util::text_view;

/** Stops in an attached debugger, or dumps core without one; SIGTRAP skips the crash handlers. */
inline void trap_into_debugger() noexcept {
#if UCALL_OS_WINDOWS_
    __debugbreak();
#else
    std::raise(SIGTRAP);
#endif
}

/** Names the fatal signal and the case in progress, then backtraces; defined after the run. */
inline void install_test_signal_handlers() noexcept;

/** What this build compiled and this machine runs, printed above the settings line. */
struct machine_t {
    char const* version = "";
    st::vector<ucall_cpu_class_t> admitted_classes;
    st::vector<ucall_io_backend_t> compiled_backends;
};

/** Probes the classes this machine admits and the queues this build compiled; defined later. */
inline machine_t probe_machine() noexcept;

/** Prints the version line, the classes admitted and the backends compiled. */
inline void print(machine_t const& machine) noexcept;

/** Writes one line to @p stream, formatted from @p format and @p args, then its newline. */
template <typename... args_types_>
void print_line(std::FILE* stream, fmt::format_string<args_types_...> format, args_types_&&... args) {
    fmt::println(stream, format, std::forward<args_types_>(args)...);
}

#pragma region Shared Settings

/** Exits with one line naming a setting that does not parse, so a bad value never runs anything. */
[[noreturn]] inline void exit_unparsed(char const* variable, char const* text, char const* expected) noexcept {
    print_line(stderr, "{}=\"{}\" does not parse, expected {}", variable, text, expected);
    std::exit(1);
}

/** The text of a setting: its @p flag when given, else its environment @p variable , else null. */
inline char const* setting_text(int argc, char** argv, char const* variable, std::string_view flag) noexcept {
    for (int index = 1; index < argc; ++index) {
        std::string_view const argument {argv[index]};
        if (argument == flag)
            return index + 1 < argc && std::strncmp(argv[index + 1], "--", 2) != 0 ? argv[index + 1] : "1";
        if (argument.size() > flag.size() && argument.starts_with(flag) && argument[flag.size()] == '=')
            return argv[index] + flag.size() + 1;
    }
    char const* text = std::getenv(variable);
    return text && *text ? text : nullptr;
}

/** A switch, @p fallback when unset: 0, false, off and no turn it off, anything else on. */
inline bool read_flag_setting(int argc, char** argv, char const* variable, std::string_view flag,
                              bool fallback = false) noexcept {
    char const* text = setting_text(argc, argv, variable, flag);
    if (!text) return fallback;
    for (char const* off : {"0", "false", "off", "no"})
        if (std::strcmp(text, off) == 0) return false;
    return true;
}

/** A whole number, @p fallback when unset. */
inline std::size_t read_count_setting(int argc, char** argv, char const* variable, std::string_view flag,
                                      std::size_t fallback) noexcept {
    char const* text = setting_text(argc, argv, variable, flag);
    if (!text) return fallback;
    std::string_view const spelled {text};
    std::size_t count = 0;
    auto const [end, parse_status] = std::from_chars(spelled.data(), spelled.data() + spelled.size(), count);
    if (parse_status != std::errc {} || end != spelled.data() + spelled.size())
        exit_unparsed(variable, text, "a whole number");
    return count;
}

/** A positive real, @p fallback when unset. */
inline double read_real_setting(int argc, char** argv, char const* variable, std::string_view flag,
                                double fallback) noexcept {
    char const* text = setting_text(argc, argv, variable, flag);
    if (!text) return fallback;
    char* end = nullptr;
    double const value = std::strtod(text, &end);
    if (*end != '\0' || !(value > 0) || !std::isfinite(value))
        exit_unparsed(variable, text, "a positive number like 0.1 or 10");
    return value;
}

/** A positive duration such as 200ms, 10s or 2m, @p fallback when unset. */
inline std::chrono::milliseconds read_duration_setting(int argc, char** argv, char const* variable,
                                                       std::string_view flag,
                                                       std::chrono::milliseconds fallback) noexcept {
    char const* text = setting_text(argc, argv, variable, flag);
    if (!text) return fallback;
    std::string_view const spelled {text};
    std::uint32_t count = 0;
    auto const [end, parse_status] = std::from_chars(spelled.data(), spelled.data() + spelled.size(), count);
    std::string_view const unit = spelled.substr(static_cast<std::size_t>(end - spelled.data()));
    if (parse_status == std::errc {} && count != 0) {
        if (unit == "ms") return std::chrono::milliseconds(count);
        if (unit == "s") return std::chrono::seconds(count);
        if (unit == "m") return std::chrono::minutes(count);
    }
    exit_unparsed(variable, text, "a duration like 200ms, 10s or 2m");
}

/** The run's seed: 42 when unset, drawn afresh for @c random , else any unsigned 64-bit value. */
inline std::uint64_t read_seed_setting(int argc, char** argv, char const* variable, std::string_view flag) noexcept {
    char const* text = setting_text(argc, argv, variable, flag);
    if (!text) return 42;
    std::string_view const spelled {text};
    if (spelled == "random") {
        std::random_device device;
        return (static_cast<std::uint64_t>(device()) << 32) ^ device();
    }
    std::uint64_t seed = 0;
    auto const [end, parse_status] = std::from_chars(spelled.data(), spelled.data() + spelled.size(), seed);
    if (parse_status != std::errc {} || end != spelled.data() + spelled.size())
        exit_unparsed(variable, text, "an unsigned integer or random");
    return seed;
}

/** Which labels a run selects: those its regex matches somewhere, every label while unset. */
struct regex_filter_t {
    std::string_view text;
    std::regex regex {""};

    bool selects(std::string_view label) const noexcept { return std::regex_search(label.begin(), label.end(), regex); }
};

/** The filter a setting spells, compiled once; one that does not compile exits as a bad setting. */
inline regex_filter_t read_regex_filter_setting(int argc, char** argv, char const* variable,
                                                std::string_view flag) noexcept {
    regex_filter_t filter;
    char const* text = setting_text(argc, argv, variable, flag);
    if (!text) return filter;
    filter.text = text;
#if defined(__cpp_exceptions) && __cpp_exceptions
    try {
        filter.regex.assign(filter.text.begin(), filter.text.end());
    }
    catch (std::regex_error const&) {
        exit_unparsed(variable, text, "a regular expression");
    }
#else
    filter.regex.assign(filter.text.begin(), filter.text.end());
#endif
    return filter;
}

/** What every suite and bench reads before its own settings; @c program starts the rerun lines. */
struct common_settings_t {
    std::uint64_t seed = 42;
    regex_filter_t regex_filter;
    char const* program = "";
};

/** SplitMix64's finalizer, a bijection that spreads every input bit over all 64 output bits. */
constexpr std::uint64_t split_mix_bits(std::uint64_t value) noexcept {
    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
    value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
    return value ^ (value >> 31);
}

/** The @p index -th stream of the family @p name under @p seed , identical in every language. */
constexpr std::uint64_t stream_key(std::uint64_t seed, std::string_view name, std::uint64_t index = 0) noexcept {
    std::uint64_t hashed = 0xCBF29CE484222325ull;
    for (char const character : name) hashed = (hashed ^ static_cast<std::uint8_t>(character)) * 0x100000001B3ull;
    return split_mix_bits(split_mix_bits(seed ^ hashed) + index);
}

/**
 *  @brief SplitMix64 over one 64-bit counter, seeded by a @ref stream_key , bit-identical to the
 *      JavaScript generator NumKong ships.
 *
 *  Distributions are not specified to draw the same sequence on every standard library, so a
 *  failure would stop reproducing from its seed when the toolchain changed; @ref below is the
 *  portable bounded draw.
 */
struct split_mix_generator_t {
    using result_type = std::uint64_t;
    std::uint64_t counter = 0;

    explicit split_mix_generator_t(std::uint64_t key) noexcept : counter(key) {}
    static constexpr result_type(min)() noexcept { return 0; }
    static constexpr result_type(max)() noexcept { return ~result_type {0}; }
    result_type operator()() noexcept { return split_mix_bits(counter += 0x9E3779B97F4A7C15ull); }

    /** A uniform draw below @p bound , zero for an empty bound, without the bias of a modulo. */
    std::uint64_t below(std::uint64_t bound) noexcept {
        if (bound == 0) return 0;
        std::uint64_t const rejection_floor = (0u - bound) % bound;
        std::uint64_t draw = (*this)();
        while (draw < rejection_floor) draw = (*this)();
        return draw % bound;
    }
};

#pragma endregion Shared Settings

/** What the suites read: the run's settings, then the queue and class a sweep keeps and where
 *  unbuffered file cases make their directories. */
struct test_settings_t : common_settings_t {
    double scale = 1.0;
    bool trap_on_failure = false;
    bool refuse_skips = false;
    ucall_io_backend_t backend = ucall_io_backend_automatic_k;
    ucall_cpu_class_t cpu_class_ceiling = ucall_cpu_class_unknown_k;
    char const* direct_directory = ".";
};

/** Reads every @c test_settings_t field, each from its flag or else its variable. */
inline test_settings_t read_test_settings(int argc, char** argv) noexcept {
    test_settings_t settings;
    settings.seed = read_seed_setting(argc, argv, "UCALL_SEED", "--seed");
    settings.regex_filter = read_regex_filter_setting(argc, argv, "UCALL_FILTER", "--filter");
    settings.scale = read_real_setting(argc, argv, "UCALL_SCALE", "--scale", 1.0);
    settings.trap_on_failure = read_flag_setting(argc, argv, "UCALL_TRAP_ON_FAILURE", "--trap-on-failure");
    settings.refuse_skips = read_flag_setting(argc, argv, "UCALL_NO_SKIPS", "--no-skips");
    settings.program = argc != 0 ? argv[0] : "";
    if (char const* text = setting_text(argc, argv, "UCALL_BACKEND", "--backend");
        text && !tools::parse_backend(text, settings.backend))
        exit_unparsed("UCALL_BACKEND", text, "a queue name such as posix or linux-uring618");
    if (char const* text = setting_text(argc, argv, "UCALL_CPU_CLASS_CEILING", "--cpu-class-ceiling");
        text && !tools::parse_cpu_class(text, settings.cpu_class_ceiling))
        exit_unparsed("UCALL_CPU_CLASS_CEILING", text, "a CPU class name such as serial or aws-g2");
    if (char const* text = setting_text(argc, argv, "UCALL_TEST_DIRECT_DIRECTORY", "--test-direct-directory"))
        settings.direct_directory = text;
    return settings;
}

#pragma region Shared Run

/** What a case reports beyond its checks: that it ran, or why it skipped. */
struct case_result_t {
    char const* skip_reason = nullptr;

    [[nodiscard]] static constexpr case_result_t skipped(char const* reason) noexcept { return {reason}; }
};

/**
 *  @brief The run in progress: the harness's one sanctioned mutable global.
 *
 *  Checks fire on worker threads and inside helpers as well as in a case's own body, so the run
 *  counts failed checks in one place and @ref run_test_case diffs that count around each case,
 *  rather than threading a tally through every call. After a crash, printing @c test_run from a
 *  core dump names the case in progress and the last failed check, and the signal handlers print
 *  the case too.
 */
struct test_run_t {
    test_settings_t settings {};
    char const* current_case = nullptr;
    std::atomic<std::size_t> failed_checks {0};
    std::atomic<char const*> last_failed_file {nullptr};
    std::atomic<std::uint_least32_t> last_failed_line {0};
    std::size_t passed_cases = 0;
    std::size_t failed_cases = 0;
    std::size_t skipped_cases = 0;
};

inline test_run_t test_run;

/** How long any wait in a test may take; a passing case never waits it out, so it bounds hangs. */
inline constexpr std::chrono::seconds wait_limit_k {120};

/** Yields until @p predicate holds; false when @ref wait_limit_k passed first. */
template <typename predicate_type_>
bool spin_until(predicate_type_&& predicate) noexcept {
    auto const deadline = std::chrono::steady_clock::now() + wait_limit_k;
    while (!predicate()) {
        if (std::chrono::steady_clock::now() > deadline) return false;
        std::this_thread::yield();
    }
    return true;
}

/** @p baseline iterations under the @c SCALE setting, never fewer than one. */
inline std::size_t scaled_iterations(std::size_t baseline) noexcept {
    double const scaled = static_cast<double>(baseline) * test_run.settings.scale;
    return scaled < 1 ? 1 : static_cast<std::size_t>(std::llround(scaled));
}

/** The step that visits a @p coverage fraction of a sweep, at least one. */
inline std::size_t sweep_stride(double coverage) noexcept {
    double const stride = 1.0 / coverage;
    return stride < 1 ? 1 : static_cast<std::size_t>(std::llround(stride));
}

/** The @p index -th stream of the case in progress, so a filtered run draws what a full one did. */
inline std::uint64_t case_stream_key(std::uint64_t index = 0) noexcept {
    return stream_key(test_run.settings.seed, test_run.current_case ? test_run.current_case : "", index);
}

/** Line-buffers stdout, prints the machine, reads the settings, arms the crash handlers and
 *  prints the settings line, before the first case. */
inline void start_test_run(int argc, char** argv) noexcept {
    std::setvbuf(stdout, nullptr, _IOLBF, BUFSIZ); // before any output, or the C library keeps its buffering
    print(probe_machine());
    test_run.settings = read_test_settings(argc, argv);
    install_test_signal_handlers();
    print_line(stdout, "- Seed: {}, scale: {}", test_run.settings.seed, test_run.settings.scale);
    print_line(
        stdout, "- Filter: {}",
        test_run.settings.regex_filter.text.empty() ? std::string_view("none") : test_run.settings.regex_filter.text);
}

/** Counts one failed check at @p where , and traps when the run asked to stop at the first. */
inline void record_failed_check(std::source_location where) noexcept {
    std::fflush(stdout); // so a log that merges both streams keeps the failure under its case
    print_line(stderr, "  check failed at {}:{}", where.file_name(), where.line());
    test_run.last_failed_file.store(where.file_name(), std::memory_order_relaxed);
    test_run.last_failed_line.store(where.line(), std::memory_order_relaxed);
    test_run.failed_checks.fetch_add(1, std::memory_order_relaxed);
    if (test_run.settings.trap_on_failure) trap_into_debugger();
}

/** Holds when @p is_satisfied does; otherwise counts a failed check at the caller's line. */
inline bool expect_true(bool is_satisfied, std::source_location where = std::source_location::current()) noexcept {
    if (!is_satisfied) record_failed_check(where);
    return is_satisfied;
}

/** A case label spelled as a regex that matches only itself, every metacharacter escaped. */
struct regex_escaped_t {
    std::string_view label;
};

} // namespace unum::ucall::test

/** Writes a @ref regex_escaped_t straight to the output, a backslash before each metacharacter. */
template <>
struct fmt::formatter<unum::ucall::test::regex_escaped_t> {
    constexpr auto parse(fmt::format_parse_context& context) { return context.begin(); }
    template <typename context_type_>
    auto format(unum::ucall::test::regex_escaped_t const& escaped, context_type_& context) const {
        auto output = context.out();
        for (char const character : escaped.label) {
            if (std::string_view {"\\^$.|?*+()[]{}"}.find(character) != std::string_view::npos) *output++ = '\\';
            *output++ = character;
        }
        return output;
    }
};

namespace unum::ucall::test {

/** Prints one case's verdict, and the line that reruns it alone when it failed. */
inline void report_test_case(char const* label, std::size_t failed_checks, char const* skip_reason,
                             double seconds) noexcept {
    if (skip_reason) {
        print_line(stdout, "- {} ... skipped: {}", label, skip_reason);
        return;
    }
    if (failed_checks == 0) {
        print_line(stdout, "- {} ... ok ({:.2f} s)", label, seconds);
        return;
    }
    std::fflush(stdout);
    print_line(stderr, "- {} ... FAILED: {} failed check(s)", label, failed_checks);
    print_line(stderr, "  rerun: {} --seed {} --filter '^{}$'", test_run.settings.program, test_run.settings.seed,
               regex_escaped_t {label});
}

/** Runs one case unless the filter leaves it out, and records whether it passed or skipped. */
template <typename case_function_type_, typename... argument_types_>
void run_test_case(char const* label, case_function_type_&& case_function, argument_types_&&... arguments) noexcept {
    if (!test_run.settings.regex_filter.selects(label)) return;
    test_run.current_case = label;
    std::size_t const failed_before = test_run.failed_checks.load();
    auto const started = std::chrono::steady_clock::now();
    case_result_t result {};
    using returned_type = std::invoke_result_t<case_function_type_, argument_types_...>;
    if constexpr (std::is_void_v<returned_type>)
        std::invoke(case_function, std::forward<argument_types_>(arguments)...);
    else result = std::invoke(case_function, std::forward<argument_types_>(arguments)...);
    std::chrono::duration<double> const elapsed = std::chrono::steady_clock::now() - started;
    std::size_t const failed_checks = test_run.failed_checks.load() - failed_before;
    if (result.skip_reason) ++test_run.skipped_cases;
    else if (failed_checks != 0) ++test_run.failed_cases;
    else ++test_run.passed_cases;
    report_test_case(label, failed_checks, result.skip_reason, elapsed.count());
    test_run.current_case = nullptr;
}

/** The exit code: 1 when a case or a check outside any case failed, or nothing ran; 3 when
 *  skips are refused and one happened; else 0. */
inline int finish_test_run() noexcept {
    print_line(stdout, "{} passed, {} failed, {} skipped, seed {}", test_run.passed_cases, test_run.failed_cases,
               test_run.skipped_cases, test_run.settings.seed);
    bool const failed = test_run.failed_cases != 0 || test_run.failed_checks.load() != 0;
    if (failed || test_run.passed_cases + test_run.skipped_cases == 0) return 1;
    if (test_run.skipped_cases != 0 && test_run.settings.refuse_skips) return 3;
    return 0;
}

#pragma endregion Shared Run

#pragma region Crash Localization

/**
 *  @brief Names the signal and the case in progress, prints a backtrace, then re-raises the signal,
 *      so a crash self-localizes rather than dying silently under CI's output redirection.
 *
 *  Writes through a raw @c write, since the crashing thread may already hold the stdio lock that
 *  @c std::fprintf takes.
 */
inline void test_fatal_signal_handler(int signal_number) noexcept {
    auto const write_text = [](std::string_view text) noexcept {
#if UCALL_OS_POSIX_
        [[maybe_unused]] auto const written = ::write(STDERR_FILENO, text.data(), text.size());
#else
        std::fwrite(text.data(), 1, text.size(), stderr);
#endif
    };
    std::string_view signal_name = "SIGSEGV";
    if (signal_number == SIGABRT) signal_name = "SIGABRT";
    else if (signal_number == SIGILL) signal_name = "SIGILL";
    else if (signal_number == SIGFPE) signal_name = "SIGFPE";
#if defined(SIGBUS)
    else if (signal_number == SIGBUS) signal_name = "SIGBUS";
#endif
    write_text("\n*** ");
    write_text(signal_name);
    write_text(" in case '");
    write_text(test_run.current_case ? test_run.current_case : "none");
    write_text("' - backtrace follows ***\n");
#if (defined(__GLIBC__) || UCALL_OS_APPLE_) && __has_include(<execinfo.h>)
    void* frames[64];
    int const frames_count = backtrace(frames, sizeof(frames) / sizeof(frames[0]));
    // The `_fd` form writes without allocating, which is what makes it usable from a handler.
    backtrace_symbols_fd(frames, frames_count, STDERR_FILENO);
#endif
    std::signal(signal_number, SIG_DFL);
    std::raise(signal_number);
}

inline void install_test_signal_handlers() noexcept {
    for (int signal_number : {SIGSEGV, SIGABRT, SIGILL, SIGFPE}) std::signal(signal_number, test_fatal_signal_handler);
#if defined(SIGBUS)
    std::signal(SIGBUS, test_fatal_signal_handler);
#endif
}

#pragma endregion Crash Localization

#pragma region Byte Ranges

/** Scratch extent shared by buffer and record fixtures. */
inline constexpr std::size_t fixture_buffer_bytes_k = 4096;

/** Fills a range with one repeated value, keeping its pointer and length together. */
inline void fill_with(span<byte_t> bytes, byte_t value) noexcept {
    // `memset` with a null destination is undefined even when it writes no bytes, and an empty
    // span may have one - the same hazard `array::append_n` guards against.
    if (bytes.size()) std::memset(bytes.data(), std::to_integer<int>(value), bytes.size());
}

/** Whether two byte ranges have the same length and the same contents. */
[[nodiscard]] inline bool bytes_equal(span<byte_t const> left, span<byte_t const> right) noexcept {
    if (left.size() != right.size()) return false;
    if (!left.size()) return true;
    return std::memcmp(left.data(), right.data(), left.size()) == 0;
}

/** Whether every byte in the range equals @p value. */
[[nodiscard]] inline bool all_equal_to(span<byte_t const> bytes, byte_t value) noexcept {
    for (std::size_t index = 0; index != bytes.size(); ++index)
        if (bytes[index] != value) return false;
    return true;
}

/** Whether every byte in the range is zero, which is how a wiped secret is recognised. */
[[nodiscard]] inline bool all_zero(span<byte_t const> bytes) noexcept { return all_equal_to(bytes, byte_t {}); }

/*  Published cryptographic vectors arrive as hex, so two of the four suites speak it. Names ending
 *  in an underscore are this header's own workings and have no callers outside it. */

/**
 *  @brief Decodes one hex digit into @p value.
 *  @return False when @p character is not a hex digit, leaving @p value untouched.
 */
[[nodiscard]] inline bool parse_hex_nibble_(char character, byte_t& value) noexcept {
    if (character >= '0' && character <= '9') value = static_cast<byte_t>(character - '0');
    else if (character >= 'a' && character <= 'f') value = static_cast<byte_t>(character - 'a' + 10);
    else if (character >= 'A' && character <= 'F') value = static_cast<byte_t>(character - 'A' + 10);
    else return false;
    return true;
}

/**
 *  @brief Parses `2 × size` hex characters from @p text into @p bytes.
 *  @return False when the literal is not hex, or its length disagrees with the range.
 */
[[nodiscard]] inline bool from_hex(char const* text, span<byte_t> bytes) noexcept {
    for (std::size_t index = 0; index != bytes.size(); ++index) {
        byte_t high {}, low {};
        if (!parse_hex_nibble_(text[index * 2], high)) return false;
        if (!parse_hex_nibble_(text[index * 2 + 1], low)) return false;
        bytes[index] = static_cast<byte_t>((high << 4) | low);
    }
    return text[bytes.size() * 2] == '\0';
}

/** How a byte range compared against a hex literal, which one @c bool could not say. */
enum class hex_match_t : std::uint8_t {
    matched_k,
    differed_k,

    /** The literal is not hex, or its length disagrees with the range - a typo in a table. */
    malformed_literal_k,
};

/** Compares @p bytes against the value the hex literal @p text names. */
[[nodiscard]] inline hex_match_t bytes_match_hex_(span<byte_t const> bytes, char const* text) noexcept {
    hex_match_t answer = hex_match_t::matched_k;
    for (std::size_t index = 0; index != bytes.size(); ++index) {
        byte_t high {}, low {};
        if (!parse_hex_nibble_(text[index * 2], high)) return hex_match_t::malformed_literal_k;
        if (!parse_hex_nibble_(text[index * 2 + 1], low)) return hex_match_t::malformed_literal_k;
        if (bytes[index] != static_cast<byte_t>((high << 4) | low)) answer = hex_match_t::differed_k;
    }
    if (text[bytes.size() * 2] != '\0') return hex_match_t::malformed_literal_k;
    return answer;
}

/**
 *  @brief Prints up to @p limit bytes as hex, noting the total when it truncates.
 *
 *  A record can be sixty-five thousand bytes wide, so an untruncated dump would bury the answer.
 *  Printing straight to the stream is what keeps a caller from having to size a buffer for it.
 */
inline void print_hex_(span<byte_t const> bytes, std::size_t limit = 32) {
    static char const digits[] = "0123456789abcdef";
    std::size_t const shown = bytes.size() < limit ? bytes.size() : limit;
    for (std::size_t index = 0; index != shown; ++index)
        fmt::print(stderr, "{}{}", digits[std::to_integer<unsigned>(bytes[index]) >> 4],
                   digits[std::to_integer<unsigned>(bytes[index]) & 0x0Fu]);
    if (shown < bytes.size()) fmt::print(stderr, "... ({} bytes total)", bytes.size());
}

/** The byte at @p offset of the patterned files the file cases read. */
[[nodiscard]] inline byte_t file_byte(std::uint64_t offset) noexcept {
    return static_cast<byte_t>((offset * 2654435761u) >> 13);
}

#pragma endregion Byte Ranges

#pragma region Checks

/**
 *  @brief A format string bundled with the @c std::source_location of the call that spelled it.
 *
 *  The implicit conversion from a string literal captures the caller's line behind the variadic
 *  arguments of a check's context, where a defaulted trailing parameter cannot go, and checks the
 *  pattern against those arguments at compile time, as @c fmt::format_string does.
 */
template <typename... args_types_>
struct located_format {
    fmt::format_string<args_types_...> format;
    std::source_location location;

    template <typename text_type_>
    consteval located_format(text_type_ const& text,
                             std::source_location location = std::source_location::current()) noexcept
        : format(text), location(location) {}
};

/** Prints @p context formatted with @p args , indented under a failed check's location line. */
template <typename... args_types_>
void print_context_(located_format<std::type_identity_t<args_types_>...> context, args_types_ const&... args) noexcept {
    fmt::print(stderr, "    ");
    fmt::vprint(stderr, context.format.get(), fmt::make_format_args(args...));
    fmt::print(stderr, "\n");
}

/** Holds when @p is_satisfied does; otherwise counts a failed check at the caller's line and prints
 *  @p context formatted with @p args beneath it. */
template <typename... args_types_>
bool expect_true(bool is_satisfied, located_format<std::type_identity_t<args_types_>...> context,
                 args_types_ const&... args) noexcept {
    if (is_satisfied) return true;
    record_failed_check(context.location);
    print_context_<args_types_...>(context, args...);
    return false;
}

/** Holds when two byte ranges match; otherwise counts a failed check at the caller's line and
 *  prints the first differing offset, with a window of both in hex from a little before it. */
inline bool expect_equal_bytes(span<byte_t const> actual, span<byte_t const> wanted,
                               std::source_location where = std::source_location::current()) noexcept {
    if (bytes_equal(actual, wanted)) return true;
    record_failed_check(where);
    fmt::print(stderr, "    expected {} bytes, got {}\n", wanted.size(), actual.size());
    std::size_t const shared = actual.size() < wanted.size() ? actual.size() : wanted.size();
    std::size_t offset = 0;
    while (offset != shared && actual[offset] == wanted[offset]) ++offset;
    if (offset != shared)
        fmt::print(stderr, "    first difference at offset {}: expected {:#04x}, got {:#04x}\n", offset,
                   static_cast<unsigned>(wanted[offset]), static_cast<unsigned>(actual[offset]));
    else fmt::print(stderr, "    the shorter range is a prefix of the longer one\n");
    std::size_t const start = offset > 8 ? offset - 8 : 0;
    auto from_start = [start](span<byte_t const> side) {
        return side.size() > start ? span<byte_t const> {side.data() + start, side.data() + side.size()}
                                   : span<byte_t const> {};
    };
    fmt::print(stderr, "    expected from {}: ", start);
    print_hex_(from_start(wanted));
    fmt::print(stderr, "\n    got from {}:      ", start);
    print_hex_(from_start(actual));
    fmt::print(stderr, "\n");
    return false;
}

/** The same against bytes @p wanted_hex spells in hex, as published vectors do, without decoding
 *  them into a buffer first; a malformed literal fails the check too. */
inline bool expect_equal_bytes(span<byte_t const> actual, char const* wanted_hex,
                               std::source_location where = std::source_location::current()) noexcept {
    hex_match_t const answer = bytes_match_hex_(actual, wanted_hex);
    if (answer == hex_match_t::matched_k) return true;
    record_failed_check(where);
    if (answer == hex_match_t::malformed_literal_k)
        fmt::print(stderr, "    the hex literal is malformed for {} bytes\n", actual.size());
    fmt::print(stderr, "    expected {}\n    got      ", wanted_hex);
    print_hex_(actual, 64);
    fmt::print(stderr, "\n");
    return false;
}

/** @p text with up to three seeded edits: a byte replaced, inserted, erased or a run repeated. */
inline std::string mutate(std::string text, split_mix_generator_t& generator) {
    static constexpr std::string_view alphabet_k = "\r\n:;0123456789abcdefABCDEF -\t\x00\x7f\xff";
    for (std::size_t edits = generator.below(4); edits; --edits) {
        std::size_t const at = generator.below(text.size() + 1);
        switch (generator.below(4)) {
        case 0:
            if (at < text.size()) text[at] = alphabet_k[generator.below(alphabet_k.size())];
            break;
        case 1: text.insert(at, 1, alphabet_k[generator.below(alphabet_k.size())]); break;
        case 2:
            if (at < text.size()) text.erase(at, 1 + generator.below(4));
            break;
        default: text.insert(at, text.substr(generator.below(text.size() + 1), generator.below(8))); break;
        }
    }
    return text;
}

#pragma endregion Checks

#pragma region Allocators

/** What a @c counting_allocator saw, and the attempt from which it refuses. */
struct allocation_ledger_t {
    std::atomic<std::size_t> allocations {}, deallocations {}, live_bytes {}, refusals {};

    /** Every attempt from this one onward fails, so a case can starve setup at any step. */
    std::atomic<std::size_t> refuse_from {(std::numeric_limits<std::size_t>::max)()};

    [[nodiscard]] std::size_t live() const noexcept { return allocations - deallocations; }
};

/** Counts every allocation into an @c allocation_ledger_t, and refuses them on request. */
template <typename value_type_>
struct counting_allocator {
    using value_type = value_type_;
    using propagate_on_container_move_assignment = std::true_type;
    allocation_ledger_t* ledger {};
    counting_allocator() noexcept = default;
    explicit counting_allocator(allocation_ledger_t& state) noexcept : ledger(&state) {}
    template <typename other_type_>
    counting_allocator(counting_allocator<other_type_> const& other) noexcept : ledger(other.ledger) {}
    value_type_* allocate(std::size_t count) noexcept {
        if (ledger->allocations + ledger->refusals >= ledger->refuse_from) {
            ++ledger->refusals;
            return nullptr;
        }
        value_type_* const result = st::default_allocator<value_type_> {}.allocate(count);
        if (result) {
            ++ledger->allocations;
            ledger->live_bytes += count * sizeof(value_type_);
        }
        return result;
    }
    void deallocate(value_type_* pointer, std::size_t count) noexcept {
        ++ledger->deallocations;
        ledger->live_bytes -= count * sizeof(value_type_);
        st::default_allocator<value_type_> {}.deallocate(pointer, count);
    }
    template <typename other_type_>
    bool operator==(counting_allocator<other_type_> const& other) const noexcept {
        return ledger == other.ledger;
    }
};

#pragma endregion Allocators

#pragma region Scratch Files
#if UCALL_OS_POSIX_

/** Open descriptors of this process, which every file case leaves as it found them. */
[[nodiscard]] inline std::size_t open_descriptors() noexcept {
    std::size_t count = 0;
    for (int descriptor = 0; descriptor != 4096; ++descriptor) count += fcntl(descriptor, F_GETFD) != -1;
    return count;
}

/** What @p case_function answers, checking it left every descriptor as it found them. */
template <typename case_type_>
case_result_t keeping_descriptors(case_type_&& case_function) {
    std::size_t const before = open_descriptors();
    case_result_t result {};
    if constexpr (std::is_void_v<std::invoke_result_t<case_type_>>) case_function();
    else result = case_function();
    std::size_t const after = open_descriptors();
    expect_true(after == before, "{} descriptors open before the case, {} after", before, after);
    return result;
}

/** A fresh directory under `/tmp` for cases that read files, removed with everything in it. */
struct scratch_directory_t {
    std::string path;

    scratch_directory_t() {
        char pattern[] = "/tmp/ucall-test-XXXXXX";
        if (mkdtemp(pattern)) path = pattern;
    }
    scratch_directory_t(scratch_directory_t const&) = delete;
    scratch_directory_t& operator=(scratch_directory_t const&) = delete;
    ~scratch_directory_t() {
        std::error_code ignored;
        if (!path.empty()) std::filesystem::remove_all(path, ignored);
    }

    [[nodiscard]] bool ready() const noexcept { return !path.empty(); }
    [[nodiscard]] std::string name(std::string_view relative) const { return fmt::format("{}/{}", path, relative); }

    /** Writes @p content to the file @p relative names, answering whether all of it landed. */
    [[nodiscard]] bool write(std::string_view relative, std::string_view content) const {
        std::FILE* file = std::fopen(name(relative).c_str(), "wb");
        if (!file) return false;
        bool const written = std::fwrite(content.data(), 1, content.size(), file) == content.size();
        return std::fclose(file) == 0 && written;
    }
};

/** A fresh directory whose filesystem serves unbuffered reads, for cases that read files with
 *  @c O_DIRECT: under @c UCALL_TEST_DIRECT_DIRECTORY, else the working directory, which CTest sets
 *  to the build tree, since @c /tmp is often tmpfs. It probes with one aligned read, and @c reason
 *  says why a filesystem cannot serve, naming the path and the filesystem. */
struct direct_directory_t {
    std::string path;
    std::string reason;
    int descriptor = -1;
    std::uint32_t alignment = 0;

    direct_directory_t() {
        std::string pattern = fmt::format("{}/ucall-direct-XXXXXX", test_run.settings.direct_directory);
        if (!mkdtemp(pattern.data())) {
            reason = fmt::format("no directory could be made as {}", pattern);
            return;
        }
        path = pattern;
        descriptor = ::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        reason = probe();
    }
    direct_directory_t(direct_directory_t const&) = delete;
    direct_directory_t& operator=(direct_directory_t const&) = delete;
    ~direct_directory_t() {
        if (descriptor >= 0) ::close(descriptor);
        std::error_code ignored;
        if (!path.empty()) std::filesystem::remove_all(path, ignored);
    }

    [[nodiscard]] bool ready() const noexcept { return reason.empty(); }
    [[nodiscard]] std::string name(std::string_view relative) const { return fmt::format("{}/{}", path, relative); }

    /** Why a case needing this directory skips, kept past the case so its verdict can print it, or
     *  null once the directory serves. */
    [[nodiscard]] char const* unusable() const {
        if (ready()) return nullptr;
        static std::string kept;
        kept = fmt::format("needs a directory serving O_DIRECT, as {}", reason);
        return kept.c_str();
    }

    /** Writes @p content to the file @p relative names, answering whether all of it landed. */
    [[nodiscard]] bool write(std::string_view relative, std::string_view content) const {
        std::FILE* file = std::fopen(name(relative).c_str(), "wb");
        if (!file) return false;
        bool const written = std::fwrite(content.data(), 1, content.size(), file) == content.size();
        return std::fclose(file) == 0 && written;
    }

#if UCALL_OS_LINUX_

    /** Why this directory cannot serve unbuffered reads, or nothing. */
    std::string probe() {
        struct statfs filesystem {};
        if (descriptor < 0 || fstatfs(descriptor, &filesystem) != 0) return fmt::format("{} cannot be opened", path);
        if (static_cast<unsigned long>(filesystem.f_type) == TMPFS_MAGIC)
            return fmt::format("{} is on tmpfs; set UCALL_TEST_DIRECT_DIRECTORY to a disk-backed directory", path);
        std::string const content(1 << 16, 'x');
        if (!write("probe.bin", content)) return fmt::format("{} takes no writes", path);
        int const file = ::open(name("probe.bin").c_str(), O_RDONLY | O_DIRECT | O_CLOEXEC);
        if (file < 0)
            return fmt::format("{} on filesystem {:#x} refuses O_DIRECT: {}", path,
                               static_cast<unsigned long>(filesystem.f_type), std::strerror(errno));
        struct statx status {};
        bool const answered = statx(file, "", AT_EMPTY_PATH, STATX_DIOALIGN, &status) == 0 &&
                              (status.stx_mask & STATX_DIOALIGN) && status.stx_dio_offset_align;
        alignment = answered ? fu::max_of(status.stx_dio_mem_align, status.stx_dio_offset_align) : 0;
        void* block = nullptr;
        bool const read = alignment && posix_memalign(&block, alignment, alignment) == 0 &&
                          ::pread(file, block, alignment, 0) == static_cast<ssize_t>(alignment);
        std::free(block);
        ::close(file);
        std::remove(name("probe.bin").c_str());
        if (!answered)
            return fmt::format("{} on filesystem {:#x} reports no STATX_DIOALIGN", path,
                               static_cast<unsigned long>(filesystem.f_type));
        if (!read)
            return fmt::format("{} on filesystem {:#x} failed an aligned unbuffered read", path,
                               static_cast<unsigned long>(filesystem.f_type));
        return {};
    }
#else

    /** Darwin and FreeBSD report no unbuffered alignment, so a page serves. */
    std::string probe() {
        alignment = 4096;
        return descriptor < 0 ? fmt::format("{} cannot be opened", path) : std::string {};
    }
#endif
};

/** Bytes aligned to a page, as unbuffered reads and registered buffers want them. */
struct aligned_bytes_t {
    byte_t* data = nullptr;
    std::size_t size = 0;

    explicit aligned_bytes_t(std::size_t bytes) noexcept {
        void* allocated = nullptr;
        if (posix_memalign(&allocated, 4096, bytes) != 0) return;
        data = static_cast<byte_t*>(allocated);
        size = bytes;
    }
    aligned_bytes_t(aligned_bytes_t const&) = delete;
    aligned_bytes_t& operator=(aligned_bytes_t const&) = delete;
    ~aligned_bytes_t() noexcept { std::free(data); }

    [[nodiscard]] span<byte_t> bytes() const noexcept { return {data, size}; }
};
#else

/** Where descriptors cannot be counted, every case reads as leaving them as it found them. */
template <typename case_type_>
case_result_t keeping_descriptors(case_type_&& case_function) {
    case_result_t result {};
    if constexpr (std::is_void_v<std::invoke_result_t<case_type_>>) case_function();
    else result = case_function();
    return result;
}

#endif // UCALL_OS_POSIX_
#pragma endregion Scratch Files

#pragma region Raw Sockets
#if UCALL_OS_POSIX_

/** How a @c raw_client_t read ended. */
enum class read_end_t : std::uint8_t {

    /** The peer closed its side in order. */
    closed_k,

    /** The requested byte count arrived first. */
    filled_k,

    /** The deadline passed first. */
    timed_out_k,

    /** The socket reported an error, such as a reset. */
    failed_k,
};

/**
 *  @brief A blocking loopback TCP client that writes exact bytes and reads what comes back.
 *
 *  Library clients frame what they send, so a malformed, fragmented, or pipelined request needs
 *  this instead. Every wait is bounded by a deadline, so a server that stalls fails a case rather
 *  than hanging the suite.
 */
struct raw_client_t {
    using deadline_t = std::chrono::steady_clock::time_point;

    int descriptor = -1;

    /** Every byte read so far, across calls to @c read. */
    std::string received;

    raw_client_t() noexcept = default;
    raw_client_t(raw_client_t const&) = delete;
    raw_client_t& operator=(raw_client_t const&) = delete;
    ~raw_client_t() noexcept { close(); }

    /** Connects to a numeric IPv4 @p address in `host:port` form, without Nagle's delay. */
    [[nodiscard]] bool connect(std::string_view address) noexcept {
        close();
        auto const colon = address.rfind(':');
        if (colon == std::string_view::npos || colon >= 16) return false;
        char host[16] {};
        std::memcpy(host, address.data(), colon);
        std::uint16_t port = 0;
        auto const [end, error] = std::from_chars(address.data() + colon + 1, address.data() + address.size(), port);
        if (error != std::errc {} || end != address.data() + address.size()) return false;
        sockaddr_in target {};
        target.sin_family = AF_INET;
        target.sin_port = htons(port);
        if (inet_pton(AF_INET, host, &target.sin_addr) != 1) return false;
        descriptor = ::socket(AF_INET, SOCK_STREAM, 0);
        if (descriptor < 0) return false;
        int enabled = 1;
        ::setsockopt(descriptor, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
#if defined(SO_NOSIGPIPE)
        ::setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
#endif
        if (::connect(descriptor, reinterpret_cast<sockaddr const*>(&target), sizeof(target)) == 0) return true;
        close();
        return false;
    }

    /**
     *  @brief Writes all of @p bytes in chunks of one to @p max_chunk bytes, drawn from
     *      @p generator, so a seed reproduces the fragmentation.
     *  @return False when the peer stopped taking bytes or the deadline passed.
     */
    [[nodiscard]] bool write(span<byte_t const> bytes, std::size_t max_chunk, split_mix_generator_t& generator,
                             deadline_t deadline) noexcept {
        constexpr int flags = MSG_NOSIGNAL | MSG_DONTWAIT;
        std::size_t offset = 0;
        while (offset != bytes.size()) {
            std::size_t const remaining = bytes.size() - offset;
            std::size_t chunk = 1 + generator.below(max_chunk);
            if (chunk > remaining) chunk = remaining;
            std::size_t sent = 0;
            while (sent != chunk) {
                if (!wait_for_(POLLOUT, deadline)) return false;
                auto const count = ::send(descriptor, bytes.data() + offset + sent, chunk - sent, flags);
                if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue;
                if (count <= 0) return false;
                sent += static_cast<std::size_t>(count);
            }
            offset += chunk;
        }
        return true;
    }

    /** Reads until @c received holds @p size bytes, the peer closes, or @p deadline passes. */
    [[nodiscard]] read_end_t read(std::size_t size, deadline_t deadline) {
        char buffer[16384];
        while (received.size() < size) {
            if (!wait_for_(POLLIN, deadline)) return read_end_t::timed_out_k;
            auto const count = ::recv(descriptor, buffer, sizeof(buffer), MSG_DONTWAIT);
            if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue;
            if (count < 0) return read_end_t::failed_k;
            if (count == 0) return read_end_t::closed_k;
            received.append(buffer, static_cast<std::size_t>(count));
        }
        return read_end_t::filled_k;
    }

    /** Reads until the peer closes, or @p deadline passes. */
    [[nodiscard]] read_end_t read_until_close(deadline_t deadline) { return read(std::string::npos, deadline); }

    void close() noexcept {
        if (descriptor >= 0) ::close(descriptor);
        descriptor = -1;
    }

    /** Waits for @p events on the socket until @p deadline, answering whether they arrived. */
    [[nodiscard]] bool wait_for_(short events, deadline_t deadline) const noexcept {
        for (;;) {
            auto const now = std::chrono::steady_clock::now();
            auto const left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
            if (left.count() < 0) return false;
            pollfd watched {descriptor, events, 0};
            int const ready = ::poll(&watched, 1, static_cast<int>(left.count()) + 1);
            if (ready > 0) return true;
            if (ready == 0 || errno != EINTR) return false;
        }
    }
};

/** The first response on the wire, with zero @c length while it is still incomplete. */
struct wire_response_t {
    unsigned status = 0;
    std::string_view body {};
    std::size_t length = 0;
};

inline wire_response_t parse_response(std::string_view wire) {
    wire_response_t response;
    auto const headers_end = wire.find("\r\n\r\n");
    if (headers_end == std::string_view::npos || headers_end < 12) return response;
    auto const headers = wire.substr(0, headers_end + 2);
    std::size_t body_length = 0;
    if (auto field = headers.find("\r\ncontent-length: "); field != std::string_view::npos)
        std::from_chars(headers.data() + field + 18, headers.data() + headers.size(), body_length);
    if (wire.size() - headers_end - 4 < body_length) return response;
    std::from_chars(wire.data() + 9, wire.data() + 12, response.status);
    response.body = wire.substr(headers_end + 4, body_length);
    response.length = headers_end + 4 + body_length;
    return response;
}

/** Reads until a whole response follows @p offset, or answers a partial one on close or timeout. */
inline wire_response_t read_response(raw_client_t& client, std::size_t offset) {
    auto const deadline = std::chrono::steady_clock::now() + wait_limit_k;
    for (;;) {
        auto response = parse_response(std::string_view {client.received}.substr(offset));
        if (response.length) return response;
        if (client.read(client.received.size() + 1, deadline) != read_end_t::filled_k) return response;
    }
}

/** A loopback TCP listener on an ephemeral port, for cases that script a server's bytes. */
struct raw_listener_t {
    int descriptor = -1;

    /** The bound `127.0.0.1:port`, empty when listening failed. */
    std::string address;

    raw_listener_t() {
        descriptor = ::socket(AF_INET, SOCK_STREAM, 0);
        if (descriptor < 0) return;
        sockaddr_in bound {};
        bound.sin_family = AF_INET;
        bound.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t bound_length = sizeof(bound);
        if (::bind(descriptor, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) == 0 &&
            ::getsockname(descriptor, reinterpret_cast<sockaddr*>(&bound), &bound_length) == 0 &&
            ::listen(descriptor, 4) == 0)
            address = fmt::format("127.0.0.1:{}", ntohs(bound.sin_port));
    }
    raw_listener_t(raw_listener_t const&) = delete;
    raw_listener_t& operator=(raw_listener_t const&) = delete;
    ~raw_listener_t() noexcept {
        if (descriptor >= 0) ::close(descriptor);
    }

    /** Accepts the next connection into @p client without Nagle's delay, or answers false once
     *  @p deadline passes. */
    [[nodiscard]] bool accept(raw_client_t& client, raw_client_t::deadline_t deadline) noexcept {
        client.close();
        auto const left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline -
                                                                                std::chrono::steady_clock::now());
        pollfd watched {descriptor, POLLIN, 0};
        if (left.count() < 0 || ::poll(&watched, 1, static_cast<int>(left.count()) + 1) <= 0) return false;
        client.descriptor = ::accept(descriptor, nullptr, nullptr);
        int enabled = 1;
        if (client.descriptor >= 0)
            ::setsockopt(client.descriptor, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
        return client.descriptor >= 0;
    }
};

/** Both ends of a loopback TCP connection, closed with the pair unless a case takes one. */
struct loopback_pair_t {
    int client = -1, peer = -1;

    loopback_pair_t() noexcept = default;
    loopback_pair_t(loopback_pair_t&& other) noexcept
        : client(std::exchange(other.client, -1)), peer(std::exchange(other.peer, -1)) {}
    loopback_pair_t& operator=(loopback_pair_t&&) = delete;
    ~loopback_pair_t() noexcept {
        if (client >= 0) ::close(client);
        if (peer >= 0) ::close(peer);
    }

    [[nodiscard]] bool connected() const noexcept { return client >= 0 && peer >= 0; }
};

/** Connects a fresh loopback TCP pair without Nagle's delay, or answers one not @c connected. */
[[nodiscard]] inline loopback_pair_t loopback_pair() noexcept {
    loopback_pair_t pair;
    int const listener = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) return pair;
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t address_length = sizeof(address);
    int enabled = 1;
    if (::setsockopt(listener, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) == 0 &&
        ::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 &&
        ::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_length) == 0 &&
        ::listen(listener, 1) == 0)
        pair.client = ::socket(AF_INET, SOCK_STREAM, 0);
    if (pair.client >= 0 && ::connect(pair.client, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0)
        pair.peer = ::accept(listener, nullptr, nullptr);
    ::close(listener);
    return pair;
}

#endif // UCALL_OS_POSIX_
#pragma endregion Raw Sockets

#pragma region Sweep

/** @p format over @p arguments as an owning string, aborting when it cannot be allocated. */
template <typename... argument_types_>
sz::string_t formatted(fmt::format_string<argument_types_ const&...> format,
                       argument_types_ const&... arguments) noexcept {
    sz::string_t text;
    if (text.resize(fmt::formatted_size(format, arguments...)) != sz::status_t::success_k) std::abort();
    fmt::format_to(text.data(), format, arguments...);
    return text;
}

/** The case label for @p function called over @p arguments, like <tt>test_exchanges(posix_k)</tt>. */
[[nodiscard]] inline sz::string_t called(char const* function, std::string_view arguments) noexcept {
    return formatted("{}({})", function, arguments);
}

/** Runs @p test over @p arguments as the case <tt>stem(cell_arguments)</tt>, apart from its cell's
 *  case as it may skip, checking it leaves every descriptor as it found them. */
template <typename test_type_, typename... argument_types_>
void run_cell_case(sz::string_t const& cell_arguments, char const* stem, test_type_&& test,
                   argument_types_ const&... arguments) {
    sz::string_t const label = called(stem, cell_arguments);
    run_test_case(label.c_str(), [&] { return keeping_descriptors([&] { return test(arguments...); }); });
}

/** One cell of a suite's sweep: the queue it runs on, the CPU class ceiling, how it encrypts. */
struct sweep_cell_t {
    ucall_io_backend_t backend = ucall_io_backend_automatic_k;
    ucall_cpu_class_t cpu_class_ceiling = ucall_cpu_class_unknown_k;
    ucall_security_t security = ucall_security_none_k;
};

/** Whether a client of @p cell 's backend under its ceiling initializes on this host and runs the
 *  class the ceiling names, as a ceiling above what the machine runs resolves lower and would
 *  sweep that lower class again under another name. */
[[nodiscard]] inline bool opens(sweep_cell_t const& cell) noexcept {
    ucall_client_t client {};
    ucall_outcome_t outcome {};
    ucall_client_options_t config {}, resolved {};
    config.max_concurrent_connections = 1;
    config.backend = cell.backend;
    config.cpu_class_ceiling = cell.cpu_class_ceiling;
    ucall_client_init_t init {&client, &outcome, &config, &resolved};
    ucall_client_init(&init);
    ucall_client_free(client);
    return outcome.status == ucall_status_success_k && (cell.cpu_class_ceiling == ucall_cpu_class_unknown_k ||
                                                        resolved.cpu_class_ceiling == cell.cpu_class_ceiling);
}

/** The queues this build compiled, in the order of @c ucall_io_backend_t. */
[[nodiscard]] inline st::vector<ucall_io_backend_t> compiled_backends() noexcept {
    struct queue_t {
        ucall_io_backend_t backend;
        bool compiled;
    };
    queue_t const queues[] {
        {ucall_io_backend_posix_k, UCALL_WITH_POSIX},
        {ucall_io_backend_linux_epollaio_k, UCALL_WITH_LINUX_EPOLLAIO},
        {ucall_io_backend_linux_uring612_k, UCALL_WITH_LINUX_URING},
        {ucall_io_backend_linux_uring618_k, UCALL_WITH_LINUX_URING},
        {ucall_io_backend_bsd_kqueue_k, UCALL_WITH_BSD_KQUEUE},
        {ucall_io_backend_windows_iocp_k, UCALL_WITH_WINDOWS_IOCP},
        {ucall_io_backend_windows_rio_k, UCALL_WITH_WINDOWS_RIO},
    };
    st::vector<ucall_io_backend_t> backends;
    for (queue_t const& queue : queues)
        if (queue.compiled && st::failed(backends.push_back(ucall_io_backend_t {queue.backend}))) std::abort();
    return backends;
}

/** The CPU classes this machine runs under a ceiling naming each, from the portable floor up. */
[[nodiscard]] inline st::vector<ucall_cpu_class_t> admitted_classes() noexcept {
    st::vector<ucall_cpu_class_t> classes;
    for (ucall_cpu_class_t const cpu_class : uc::cpu_classes_k)
        if (opens({.cpu_class_ceiling = cpu_class}) && st::failed(classes.push_back(ucall_cpu_class_t {cpu_class})))
            std::abort();
    return classes;
}

/** The diagonal a suite sweeps rather than the full product: every compiled backend at the best
 *  class in plaintext, every admitted class on the first backend, and every Noise pattern on the
 *  first backend, each narrowed by the run's backend and ceiling. */
[[nodiscard]] inline st::vector<sweep_cell_t> diagonal_sweep() noexcept {
    test_settings_t const& settings = test_run.settings;
    st::vector<sweep_cell_t> cells;
    auto add = [&](sweep_cell_t const& cell) noexcept {
        if (st::failed(cells.push_back(sweep_cell_t {cell}))) std::abort();
    };
    ucall_io_backend_t first = ucall_io_backend_automatic_k;
    for (ucall_io_backend_t const backend : compiled_backends()) {
        if (settings.backend != ucall_io_backend_automatic_k && settings.backend != backend) continue;
        if (first == ucall_io_backend_automatic_k) first = backend;
        add({backend, settings.cpu_class_ceiling, ucall_security_none_k});
    }
    if (first == ucall_io_backend_automatic_k) return cells;
    if (settings.cpu_class_ceiling == ucall_cpu_class_unknown_k)
        for (ucall_cpu_class_t const cpu_class : admitted_classes()) add({first, cpu_class, ucall_security_none_k});
    for (ucall_security_t const security :
         {ucall_security_noise_xx_k, ucall_security_noise_ik_k, ucall_security_noise_kk_k})
        add({first, settings.cpu_class_ceiling, security});
    return cells;
}

/** The exact spelling of @p backend, as the label of a cell names it. */
[[nodiscard]] inline char const* backend_constant(ucall_io_backend_t backend) noexcept {
    struct entry_t {
        ucall_io_backend_t value;
        char const* spelling;
    };
    static constexpr entry_t entries[] {
        {ucall_io_backend_automatic_k, "ucall_io_backend_automatic_k"},
        {ucall_io_backend_posix_k, "ucall_io_backend_posix_k"},
        {ucall_io_backend_linux_epollaio_k, "ucall_io_backend_linux_epollaio_k"},
        {ucall_io_backend_linux_uring612_k, "ucall_io_backend_linux_uring612_k"},
        {ucall_io_backend_linux_uring618_k, "ucall_io_backend_linux_uring618_k"},
        {ucall_io_backend_bsd_kqueue_k, "ucall_io_backend_bsd_kqueue_k"},
        {ucall_io_backend_windows_iocp_k, "ucall_io_backend_windows_iocp_k"},
        {ucall_io_backend_windows_rio_k, "ucall_io_backend_windows_rio_k"},
    };
    for (entry_t const& entry : entries)
        if (entry.value == backend) return entry.spelling;
    return "ucall_io_backend_automatic_k";
}

/** The exact spelling of @p cpu_class, as the label of a cell names it. */
[[nodiscard]] inline char const* cpu_class_constant(ucall_cpu_class_t cpu_class) noexcept {
    struct entry_t {
        ucall_cpu_class_t value;
        char const* spelling;
    };
    static constexpr entry_t entries[] {
        {ucall_cpu_class_unknown_k, "ucall_cpu_class_unknown_k"},
        {ucall_cpu_class_serial_k, "ucall_cpu_class_serial_k"},
        {ucall_cpu_class_monoversioned_k, "ucall_cpu_class_monoversioned_k"},
        {ucall_cpu_class_intel_haswell_k, "ucall_cpu_class_intel_haswell_k"},
        {ucall_cpu_class_intel_skylake_k, "ucall_cpu_class_intel_skylake_k"},
        {ucall_cpu_class_intel_icelake_k, "ucall_cpu_class_intel_icelake_k"},
        {ucall_cpu_class_intel_alder_k, "ucall_cpu_class_intel_alder_k"},
        {ucall_cpu_class_aws_g2_k, "ucall_cpu_class_aws_g2_k"},
        {ucall_cpu_class_apple_m4_k, "ucall_cpu_class_apple_m4_k"},
        {ucall_cpu_class_aws_g5_k, "ucall_cpu_class_aws_g5_k"},
        {ucall_cpu_class_alibaba_c930_k, "ucall_cpu_class_alibaba_c930_k"},
        {ucall_cpu_class_ibm_power10_k, "ucall_cpu_class_ibm_power10_k"},
    };
    for (entry_t const& entry : entries)
        if (entry.value == cpu_class) return entry.spelling;
    return "ucall_cpu_class_unknown_k";
}

/** The exact spelling of @p security, as the label of a cell names it. */
[[nodiscard]] inline char const* security_constant(ucall_security_t security) noexcept {
    switch (security) {
    case ucall_security_noise_xx_k: return "ucall_security_noise_xx_k";
    case ucall_security_noise_ik_k: return "ucall_security_noise_ik_k";
    case ucall_security_noise_kk_k: return "ucall_security_noise_kk_k";
    default: return "ucall_security_none_k";
    }
}

/** The arguments of a call to the case of @p cell , like "posix_k, aws_g2_k". */
[[nodiscard]] inline sz::string_t cell_arguments(sweep_cell_t const& cell) noexcept {
    return formatted("{}, {}, {}", backend_constant(cell.backend), cpu_class_constant(cell.cpu_class_ceiling),
                     security_constant(cell.security));
}

inline machine_t probe_machine() noexcept { return {ucall_version_name(), admitted_classes(), compiled_backends()}; }

inline void print(machine_t const& machine) noexcept {
    fmt::println("UCall {}", machine.version);
    fmt::print("- CPU classes admitted:");
    for (ucall_cpu_class_t const cpu_class : machine.admitted_classes)
        fmt::print(" {}", ucall_cpu_class_name(cpu_class));
    fmt::print("\n- Backends compiled:");
    for (ucall_io_backend_t const backend : machine.compiled_backends)
        fmt::print(" {}", ucall_io_backend_name(backend));
    fmt::print("\n");
    std::fflush(stdout);
}

#pragma endregion Sweep

namespace utilities {
void run_utilities_cases();
} // namespace utilities

namespace io {
void run_io_cases();
} // namespace io

namespace http {
void run_http_messages_cases();
void run_routes_cases();
void run_percent_cases();
void run_multipart_cases();
} // namespace http

namespace dns {
void run_dns_messages_cases();
void run_dns_configuration_cases();
} // namespace dns

namespace tunnel {
void run_crypto_cases();
void run_secure_tunnel_cases();
} // namespace tunnel

} // namespace unum::ucall::test
