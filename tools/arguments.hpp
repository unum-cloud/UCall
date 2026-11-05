/**
 *  @file tools/arguments.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Command-line values shared by the native examples, servers and benchmark driver.
 */
#pragma once

#include <cstddef> // `std::size_t`
#include <cstdint> // `std::uint32_t`, `std::uint64_t`

#include <charconv>     // `std::from_chars`
#include <chrono>       // `std::chrono::nanoseconds`
#include <string_view>  // `std::string_view`
#include <system_error> // `std::errc`

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
