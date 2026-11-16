/**
 *  @file tools/arguments.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Command-line values shared by the native examples, servers and benchmark driver.
 */
#pragma once

#include <cstddef> // `std::size_t`
#include <cstdint> // `std::uint32_t`, `std::uint64_t`
#include <cstdio>  // `std::FILE`, `stderr`
#include <cstdlib> // `std::exit`, `std::getenv`, `std::strtod`

#include <charconv>     // `std::from_chars`
#include <chrono>       // `std::chrono::nanoseconds`
#include <optional>     // `std::optional`
#include <random>       // `std::random_device`
#include <regex>        // `std::regex`, `std::regex_search`
#include <string_view>  // `std::string_view`
#include <system_error> // `std::errc`

#include <fmt/format.h> // `fmt::print`
#include <fmt/ranges.h> // `fmt::join`

#include "ucall/utilities/types.hpp" // `UCALL_OS_WINDOWS_`
#include "ucall/ucall.h"             // `ucall_noise_key_t`, `ucall_status_t`

#if !UCALL_OS_WINDOWS_
#include <sys/resource.h> // `getrusage`
#endif

namespace unum::ucall::tools {

/** A whole decimal @p text of at least @p minimum, left unchanged in @p value when it fails. */
inline bool parse_count(std::string_view text, std::size_t& value, std::size_t minimum = 0) noexcept {
    std::size_t parsed {};
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (error != std::errc {} || end != text.data() + text.size() || parsed < minimum) return false;
    value = parsed;
    return true;
}

/** A duration like "1s", "500ms" or "250us". */
inline bool parse_duration(std::string_view text, std::chrono::nanoseconds& value) noexcept {
    std::uint32_t count {};
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), count);
    if (error != std::errc {} || end == text.data()) return false;
    std::string_view const unit = text.substr(static_cast<std::size_t>(end - text.data()));
    if (unit == "s") value = std::chrono::seconds(count);
    else if (unit == "ms") value = std::chrono::milliseconds(count);
    else if (unit == "us") value = std::chrono::microseconds(count);
    else return false;
    return true;
}

/** A SplitMix64 seed, any unsigned 64-bit decimal. */
inline bool parse_seed(std::string_view text, std::uint64_t& value) noexcept {
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    return error == std::errc {} && end == text.data() + text.size();
}

/** A Noise key spelled as 64 hexadecimal digits. */
inline bool parse_key(std::string_view text, ucall_noise_key_t& key) noexcept {
    if (text.size() != 2 * sizeof(key)) return false;
    for (std::size_t i = 0; i != sizeof(key); ++i) {
        char const* digits = text.data() + 2 * i;
        auto [end, error] = std::from_chars(digits, digits + 2, key[i], 16);
        if (error != std::errc {} || end != digits + 2) return false;
    }
    return true;
}

/** Prints @p key to @p file as the 64 hexadecimal digits @ref parse_key reads, then a newline. */
inline void print_key(std::FILE* file, ucall_noise_key_t const& key) noexcept {
    fmt::print(file, "{:02x}\n", fmt::join(key, ""));
}

/** An engine name as @c ucall_io_backend_name spells it, left untouched when it names none. */
inline bool parse_backend(std::string_view text, ucall_io_backend_t& backend) noexcept {
    return ucall_io_backend_from_name(bytes_view(text), &backend) == ucall_status_success_k;
}

/** A CPU class name as @c ucall_cpu_class_name spells it, left untouched when it names none. */
inline bool parse_cpu_class(std::string_view text, ucall_cpu_class_t& cpu_class) noexcept {
    return ucall_cpu_class_from_name(bytes_view(text), &cpu_class) == ucall_status_success_k;
}

/** Which named checks run: every one for an empty pattern, else those the pattern finds as an
 *  ECMAScript regex, or as a substring when it is no valid regex. */
struct filter_t {
    std::string_view pattern;
    std::optional<std::regex> regex;

    /** Whether @p name passes the filter. */
    bool selects(std::string_view name) const noexcept {
        if (pattern.empty()) return true;
        if (regex) return std::regex_search(name.begin(), name.end(), *regex);
        return name.find(pattern) != std::string_view::npos;
    }
};

/** The filter @p pattern spells, compiled once. */
inline filter_t filter_of(std::string_view pattern) {
    filter_t filter {pattern, std::nullopt};
    if (pattern.empty()) return filter;
#if defined(__cpp_exceptions) && __cpp_exceptions
    try {
        filter.regex.emplace(pattern.begin(), pattern.end());
    }
    catch (std::regex_error const&) {
    }
#else
    filter.regex.emplace(pattern.begin(), pattern.end());
#endif
    return filter;
}

/** Every setting the suites, the benchmarks and the tools share, its default as the initializer,
 *  filled once by @ref read_settings. */
struct settings_t {

    /** Seed every case's generator derives from. Override: @c UCALL_SEED, a number or random. */
    std::uint64_t seed = 42;

    /** Scales every sweep and iteration count. Override: @c UCALL_MULTIPLIER. */
    double multiplier = 1.0;

    /** Checks to run. Override: @c UCALL_FILTER. */
    filter_t filter;

    /** The one engine a sweep keeps; automatic keeps every compiled one. Override: @c --backend. */
    ucall_io_backend_t backend = ucall_io_backend_automatic_k;

    /** The one CPU class a sweep keeps; unknown keeps all admitted. Override: @c --cpu-class. */
    ucall_cpu_class_t cpu_class = ucall_cpu_class_unknown_k;
};

/** Prints why @p value of @p name does not parse, then exits with status 1. */
[[noreturn]] inline void exit_unparsed(std::string_view name, std::string_view value, char const* expected) noexcept {
    fmt::print(stderr, "{}=\"{}\" does not parse, expected {}\n", name, value, expected);
    std::exit(1);
}

/** Reads the environment, then the @c --backend and @c --cpu-class pins of @p argv, leaving every
 *  argument without a leading dash to the binary. On @c --help prints the usage and exits with
 *  status 0; on a setting that does not parse prints one line and exits with 1. */
inline settings_t read_settings(int argc, char const* const* argv, std::string_view synopsis) {
    settings_t settings;
    auto environment = [](char const* name) noexcept {
        char const* text = std::getenv(name);
        return std::string_view {text ? text : ""};
    };
    settings.filter = filter_of(environment("UCALL_FILTER"));
    if (std::string_view const text = environment("UCALL_SEED"); text == "random")
        settings.seed = std::random_device {}();
    else if (!text.empty() && !parse_seed(text, settings.seed))
        exit_unparsed("UCALL_SEED", text, "an unsigned integer or random");
    if (std::string_view const text = environment("UCALL_MULTIPLIER"); !text.empty()) {
        char* end = nullptr;
        settings.multiplier = std::strtod(text.data(), &end);
        if (end != text.data() + text.size() || !(settings.multiplier > 0.0))
            exit_unparsed("UCALL_MULTIPLIER", text, "a positive number");
    }
    for (int index = 1; index < argc; ++index) {
        std::string_view const flag = argv[index];
        // What follows `--` belongs to the program, never to these flags.
        if (flag == "--") break;
        if (flag.empty() || flag[0] != '-') continue;
        std::string_view const value = index + 1 < argc ? argv[index + 1] : "";
        bool const parsed = flag == "--backend"     ? parse_backend(value, settings.backend)
                            : flag == "--cpu-class" ? parse_cpu_class(value, settings.cpu_class)
                                                    : false;
        if (parsed) {
            ++index;
            continue;
        }
        if (flag != "--help") exit_unparsed(flag, value, "a flag of the usage below");
        fmt::print("Usage: {} [--backend name] [--cpu-class name]\n", synopsis);
        std::exit(0);
    }
    return settings;
}

/** User plus system seconds this process spent so far, read through the platform's accounting. */
inline double process_cpu_seconds() noexcept {
#if UCALL_OS_WINDOWS_
    FILETIME created, exited, kernel, user;
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return 0;
    auto ticks = [](FILETIME t) { return (std::uint64_t {t.dwHighDateTime} << 32 | t.dwLowDateTime) * 1e-7; };
    return ticks(kernel) + ticks(user);
#else
    rusage usage {};
    getrusage(RUSAGE_SELF, &usage);
    auto seconds = [](timeval t) { return t.tv_sec + t.tv_usec * 1e-6; };
    return seconds(usage.ru_utime) + seconds(usage.ru_stime);
#endif
}

/** Wall and process CPU seconds read together, so one span reports both from one pair of
 *  readings: the driver's measured phase, or a server's whole life. */
struct process_clocks_t {
    double wall_seconds {}, cpu_seconds {};
    static process_clocks_t now() noexcept {
        return {std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count(),
                process_cpu_seconds()};
    }
    process_clocks_t operator-(process_clocks_t const& since) const noexcept {
        return {wall_seconds - since.wall_seconds, cpu_seconds - since.cpu_seconds};
    }
};

/** XX learns the peer's key during the handshake, and these tools admit whichever it shows. */
inline ucall_status_t admit_any_peer(ucall_noise_key_t const*, void*) noexcept { return ucall_status_success_k; }

} // namespace unum::ucall::tools
