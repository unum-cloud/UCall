/**
 *  @file test/harness.hpp
 *  @author Ash Vardanian
 *  @date August 9, 2026
 *  @brief Shared harness for the C++ test suites: counted checks, scaling, and byte diagnostics.
 *
 *  Every check answers its own failure count, a case adds them up and returns a @c case_result_t,
 *  and @c run_test rolls each result into the @c suite_totals_t the suite's @c main owns, so counts
 *  reach @c suite_exit_code without global mutable state. A failed case prints the command that
 *  reruns only it, under the same seed and multiplier.
 *
 *  A failed @c expect lets the case go on. Where the next line would dereference what the check
 *  guarded, @c require returns from the case instead, with the failures counted so far.
 *
 *  `-fno-exceptions` rules out a `try` around a test body, and makes `UCALL_FILTER` a substring
 *  rather than a regular expression.
 *
 *  @section Environment Variables
 *
 *  - `UCALL_SEED` : Seed for the deterministic generator. Defaults to a fixed value, and is always
 *    printed at startup, so a run reproduces without being told.
 *  - `UCALL_MULTIPLIER` : Scales every sweep and iteration count. Defaults to 1.0. Use 0.1 for a
 *    quick smoke run, 10 for a thorough one.
 *  - `UCALL_FILTER` : Substring matched against test names; only matching tests run. Unset or empty
 *    runs everything. Honored by @c run_test.
 *
 *  @section Example Usage
 *
 *  @code{.sh}
 * # Only the record-layer tests, at a tenth of the usual depth.
 * UCALL_FILTER=records UCALL_MULTIPLIER=0.1 ./build_test/test_noise
 *
 * # A thorough sweep, reproducible from a named seed.
 * UCALL_SEED=12345 UCALL_MULTIPLIER=10 ./build_test/test_noise
 *  @endcode
 */
#pragma once
#include <cerrno>  // `errno`, `EAGAIN`, `EINTR`
#include <csignal> // `std::signal`, `std::raise`, `SIGABRT`, `SIGSEGV`
#include <cstddef> // `std::size_t`
#include <cstdint> // `std::uint64_t`
#include <cstdio>  // `stderr`, `stdout`, `std::fflush`
#include <cstdlib> // `std::abort`, `std::getenv`, `std::strtod`, `std::strtoull`
#include <cstring> // `std::strstr`, `std::memcmp`

#include <charconv>    // `std::from_chars`
#include <chrono>      // `std::chrono::steady_clock`
#include <limits>      // `std::numeric_limits`
#include <random>      // `std::uniform_random_bit_generator`
#include <string>      // `std::string`
#include <type_traits> // `std::true_type`, `std::is_invocable_v`
#include <utility>     // `std::forward`, `std::exchange`

#include <fmt/base.h>   // `fmt::print`, `fmt::format_string`
#include <fmt/color.h>  // `fmt::text_style`, `fmt::fg`, `fmt::emphasis`
#include <fmt/format.h> // `fmt::formatter`, `fmt::format_to`

#include <forkunion/types.hpp> // `fu::split_mix`

#include "ucall/types.hpp" // `byte_t`, `span`

#if UCALL_OS_LINUX_ || UCALL_OS_APPLE_
#include <unistd.h> // `isatty`, `STDERR_FILENO`
#endif
#if UCALL_OS_LINUX_ && defined(__GLIBC__)
#include <execinfo.h> // `backtrace`, `backtrace_symbols_fd`
#endif
#if UCALL_OS_POSIX_
#include <arpa/inet.h>   // `inet_pton`, `htons`
#include <netinet/in.h>  // `sockaddr_in`
#include <netinet/tcp.h> // `TCP_NODELAY`
#include <poll.h>        // `poll`
#include <sys/socket.h>  // `socket`, `connect`, `send`, `recv`, `accept`
#include <unistd.h>      // `close`
#endif

namespace unum::ucall::test {

/** Scratch extent shared by buffer and record fixtures. */
inline constexpr std::size_t fixture_buffer_bytes_k = 4096;

#pragma region Byte Ranges

/** Fills a range with one repeated value, keeping its pointer and length together. */
inline void fill_with(span<byte_t> bytes, byte_t value) noexcept {
    // `memset` with a null destination is undefined even when it writes no bytes, and an empty
    // span carries one - the same hazard `array::append_n` guards against.
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

#pragma endregion Byte Ranges

#pragma region Diagnostics

/** Whether diagnostics may use colour: only when standard error is a terminal. */
[[nodiscard]] inline bool diagnostics_are_styled_() noexcept {
#if UCALL_OS_LINUX_ || UCALL_OS_APPLE_
    static bool const styled = isatty(STDERR_FILENO) != 0;
    return styled;
#else
    return false;
#endif
}

[[nodiscard]] inline fmt::text_style failure_style_() {
    return diagnostics_are_styled_() ? fmt::fg(fmt::color::crimson) | fmt::emphasis::bold : fmt::text_style {};
}

[[nodiscard]] inline fmt::text_style detail_style_() {
    return diagnostics_are_styled_() ? fmt::fg(fmt::color::dim_gray) : fmt::text_style {};
}

/** Prints the header line every failed check shares, before any context the caller adds. */
inline void report_failure(char const* expression, char const* file, int line) {
    fmt::print(stderr, failure_style_(), "Test verification failed: {}, {}:{}\n", expression, file, line);
}

/** Backs @c expect: counts one failure when @p holds is false, printing it with its location. */
[[nodiscard]] inline std::size_t expect_(bool holds, char const* expression, char const* file, int line) {
    if (holds) return 0;
    report_failure(expression, file, line);
    return 1;
}

/** Backs @c expect with context: counts like the plain overload, then prints the context. */
template <typename... argument_types_>
[[nodiscard]] std::size_t expect_(bool holds, char const* expression, char const* file, int line,
                                  fmt::format_string<argument_types_...> format, argument_types_&&... arguments) {
    if (holds) return 0;
    report_failure(expression, file, line);
    fmt::print(stderr, "  ");
    fmt::print(stderr, format, std::forward<argument_types_>(arguments)...);
    fmt::print(stderr, "\n");
    return 1;
}

/** Backs @c expect_bytes: reports a mismatch and counts it as one failure. */
[[nodiscard]] inline std::size_t expect_bytes_(span<byte_t const> actual, span<byte_t const> expected,
                                               char const* actual_text, char const* expected_text, char const* file,
                                               int line) {
    if (bytes_equal(actual, expected)) return 0;

    fmt::print(stderr, failure_style_(), "Test verification failed: bytes differ, {}:{}\n", file, line);
    fmt::print(stderr, detail_style_(), "  actual   `{}` holds {} bytes\n", actual_text, actual.size());
    fmt::print(stderr, detail_style_(), "  expected `{}` holds {} bytes\n", expected_text, expected.size());

    std::size_t const shared = actual.size() < expected.size() ? actual.size() : expected.size();
    std::size_t offset = 0;
    while (offset != shared && actual[offset] == expected[offset]) ++offset;
    if (offset != shared)
        fmt::print(stderr, "  first difference at offset {}: {:#04x} against {:#04x}\n", offset,
                   static_cast<unsigned>(actual[offset]), static_cast<unsigned>(expected[offset]));
    else fmt::print(stderr, "  the shorter range is a prefix of the longer one\n");

    // A window anchored a little before the difference, so its neighbours are visible too.
    std::size_t const start = offset > 8 ? offset - 8 : 0;
    auto from_start = [start](span<byte_t const> side) {
        return side.size() > start ? span<byte_t const> {side.data() + start, side.data() + side.size()}
                                   : span<byte_t const> {};
    };
    fmt::print(stderr, "  actual   from {}: ", start);
    print_hex_(from_start(actual));
    fmt::print(stderr, "\n  expected from {}: ", start);
    print_hex_(from_start(expected));
    fmt::print(stderr, "\n");
    return 1;
}

/** Backs @c expect_hex: reports a mismatch against the literal and counts it as one failure. */
[[nodiscard]] inline std::size_t expect_hex_(span<byte_t const> actual, char const* expected_hex,
                                             char const* actual_text, char const* file, int line) {
    hex_match_t const answer = bytes_match_hex_(actual, expected_hex);
    if (answer == hex_match_t::matched_k) return 0;

    fmt::print(stderr, failure_style_(), "Test verification failed: {}, {}:{}\n",
               answer == hex_match_t::malformed_literal_k ? "the hex literal is malformed" : "bytes do not match hex",
               file, line);
    fmt::print(stderr, detail_style_(), "  actual   `{}` holds {} bytes\n", actual_text, actual.size());
    fmt::print(stderr, "  actual   ");
    print_hex_(actual, 64);
    fmt::print(stderr, "\n  expected {}\n", expected_hex);
    return 1;
}

/** Announces the step about to run, so the failures printed after it read as that step's. */
template <typename... argument_types_>
inline void announce(fmt::format_string<argument_types_...> format, argument_types_&&... arguments) {
    fmt::print("  - ");
    fmt::print(format, std::forward<argument_types_>(arguments)...);
    fmt::print("\n");
    std::fflush(stdout);
}

#pragma endregion Diagnostics

#pragma region Environment

/**
 *  @brief A counter over ForkUnion's SplitMix64 avalanche, modelling
 *      @c std::uniform_random_bit_generator.
 *
 *  Deliberately independent of the library's own entropy, so a bug in @c secure_random_bytes can
 *  never shape the inputs the tests run against.
 *
 *  Satisfying the concept is what lets @c std::shuffle and @c std::sample take it. Do not reach for
 *  @c std::uniform_int_distribution with it: distributions are not specified to yield the same
 *  sequence across standard libraries, so a failure would stop reproducing from @c UCALL_SEED the
 *  moment the toolchain changed. That is what @c below is for.
 */
struct random_generator_t {
    using result_type = std::uint64_t;

    /** The next draw's input, starting at the seed. */
    result_type counter {};

    explicit random_generator_t(result_type seed) noexcept : counter(seed) {}

    [[nodiscard]] static constexpr result_type min() noexcept { return 0; }
    [[nodiscard]] static constexpr result_type max() noexcept { return ~result_type {0}; }

    [[nodiscard]] result_type operator()() noexcept { return fu::split_mix(counter++); }

    /**
     *  @brief The next value in `[0, bound)`, or zero when the bound is empty.
     *
     *  Rejects the tail that `%` alone would make likelier, which costs an almost-never-taken
     *  branch and buys a draw that is uniform and identical on every standard library.
     */
    [[nodiscard]] std::size_t below(std::size_t bound) noexcept {
        if (!bound) return 0;
        result_type const rejection_floor = (0u - static_cast<result_type>(bound)) % bound;
        result_type draw = (*this)();
        while (draw < rejection_floor) draw = (*this)();
        return static_cast<std::size_t>(draw % bound);
    }
};

static_assert(std::uniform_random_bit_generator<random_generator_t>,
              "the generator must be usable with `std::shuffle` and friends");

/** Everything the environment configures, established once before any test runs. */
struct test_environment_t {

    /** `UCALL_SEED`. Fixed by default, so a run reproduces without being told. */
    std::uint64_t seed {42};

    /** `UCALL_MULTIPLIER`. Scales every sweep and iteration count. */
    double multiplier {1.0};

    /** `UCALL_FILTER`. Null or empty runs everything. */
    char const* filter {nullptr};
};

/*  Constant-initialized, so it carries no thread-safe-static guard on every read and takes no part
 *  in the initialization order across the translation units that include this header. `constinit`
 *  is what makes the compiler enforce both rather than leave them to inspection. */
constinit inline test_environment_t test_environment {};

/** Aborts with a message, for a malformed environment that no case could run under. */
[[noreturn]] inline void abort_with_(char const* what, char const* file, int line) {
    report_failure(what, file, line);
    std::abort();
}

/**
 *  @brief Reads and announces the run's configuration. Call once from @c main, before any test.
 *
 *  Reading eagerly and in one place is what lets a malformed value abort here rather than silently
 *  become a zero seed or an unscaled sweep, either of which a run would then report as deliberate.
 */
inline void configure_tests() {
    if (char const* const text = std::getenv("UCALL_SEED"); text && text[0] != '\0') {
        if (std::strcmp(text, "random") == 0) test_environment.seed = std::random_device {}();
        else {
            std::uint32_t parsed = 0;
            auto const [end, error] = std::from_chars(text, text + std::strlen(text), parsed);
            if (error != std::errc {} || *end != '\0')
                abort_with_("UCALL_SEED expects an unsigned 32-bit integer or random", __FILE__, __LINE__);
            test_environment.seed = parsed;
        }
    }
    if (char const* const text = std::getenv("UCALL_MULTIPLIER"); text && text[0] != '\0') {
        char* end = nullptr;
        double const parsed = std::strtod(text, &end);
        if (!end || *end != '\0' || !(parsed > 0.0))
            abort_with_("UCALL_MULTIPLIER is not a positive number", __FILE__, __LINE__);
        test_environment.multiplier = parsed;
    }
    if (char const* const text = std::getenv("UCALL_FILTER"); text && text[0] != '\0') test_environment.filter = text;

    fmt::print("  UCALL_SEED       {}\n", test_environment.seed);
    fmt::print("  UCALL_MULTIPLIER {:.2f}\n", test_environment.multiplier);
    fmt::print("  UCALL_FILTER     {}\n", test_environment.filter ? test_environment.filter : "(none)");
    std::fflush(stdout);
}

/** A test's seed, from the run's and the name, so a filtered run reproduces an unfiltered one. */
[[nodiscard]] inline std::uint64_t test_seed_(char const* name) noexcept {
    std::uint64_t hashed = 0xCBF29CE484222325ull;
    for (char const* character = name; *character; ++character) {
        hashed ^= static_cast<std::uint64_t>(static_cast<unsigned char>(*character));
        hashed *= 0x100000001B3ull;
    }
    return test_environment.seed ^ hashed;
}

/**
 *  @brief Scales a baseline iteration count by the run's multiplier, never below one.
 *
 *  Wrapping every hardcoded trip count is what makes depth an environment variable, not an edit.
 */
[[nodiscard]] inline std::size_t scale_iterations(std::size_t baseline) noexcept {
    double const scaled = static_cast<double>(baseline) * test_environment.multiplier;
    return scaled < 1.0 ? 1u : static_cast<std::size_t>(scaled);
}

/**
 *  @brief Step for walking an exhaustive space, so the multiplier dials sweeps as well as loops.
 *
 *  Striding rather than truncating keeps the far end reachable at a low multiplier, which matters
 *  where the interesting offsets sit at the end of a record. Complete at the ten-times point.
 */
[[nodiscard]] inline std::size_t sweep_stride(std::size_t complete) noexcept {
    double const coverage = test_environment.multiplier / 10.0;
    if (coverage >= 1.0 || complete == 0) return 1;
    std::size_t const stride = static_cast<std::size_t>(1.0 / coverage);
    return stride ? stride : 1;
}

#pragma endregion Environment

#pragma region Allocators

/** What a @c counting_allocator saw, and the attempt from which it refuses. */
struct allocation_counts_t {
    std::size_t attempts {}, allocations {}, deallocations {}, bytes {};

    /** Every attempt from this one onward fails, so a case can starve setup at any step. */
    std::size_t fail_from {std::numeric_limits<std::size_t>::max()};

    [[nodiscard]] std::size_t live() const noexcept { return allocations - deallocations; }
};

/** Counts every allocation through @c allocation_counts_t, and fails them on request. */
template <typename value_type_>
struct counting_allocator {
    using value_type = value_type_;
    using propagate_on_container_move_assignment = std::true_type;
    allocation_counts_t* counts {};
    counting_allocator() noexcept = default;
    explicit counting_allocator(allocation_counts_t& state) noexcept : counts(&state) {}
    template <typename other_type_>
    counting_allocator(counting_allocator<other_type_> const& other) noexcept : counts(other.counts) {}
    value_type_* allocate(std::size_t count) noexcept {
        if (counts->attempts++ >= counts->fail_from) return nullptr;
        value_type_* const result = st::default_allocator<value_type_> {}.allocate(count);
        if (result) {
            ++counts->allocations;
            counts->bytes += count * sizeof(value_type_);
        }
        return result;
    }
    void deallocate(value_type_* pointer, std::size_t count) noexcept {
        ++counts->deallocations;
        counts->bytes -= count * sizeof(value_type_);
        st::default_allocator<value_type_> {}.deallocate(pointer, count);
    }
    template <typename other_type_>
    bool operator==(counting_allocator<other_type_> const& other) const noexcept {
        return counts == other.counts;
    }
};

#pragma endregion Allocators

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
    [[nodiscard]] bool write(span<byte_t const> bytes, std::size_t max_chunk, random_generator_t& generator,
                             deadline_t deadline) noexcept {
#if defined(MSG_NOSIGNAL)
        constexpr int flags = MSG_NOSIGNAL | MSG_DONTWAIT;
#else
        constexpr int flags = MSG_DONTWAIT;
#endif
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
    auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds {5};
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

#pragma region Test Runner

/**
 *  @brief Prints a backtrace on abort or a segmentation fault, then re-raises the default action.
 *
 *  A failed check is counted and located by its own message, so this is for the crash a check did
 *  not see coming, which the last announced case and step then name.
 */
inline void install_test_signal_handlers() noexcept {
    auto report = [](int signal_number) noexcept {
#if UCALL_OS_LINUX_ && defined(__GLIBC__)
        void* frames[32];
        int const depth = backtrace(frames, 32);
        fmt::print(stderr, "Caught signal {}, backtrace follows:\n", signal_number);
        std::fflush(stderr);
        backtrace_symbols_fd(frames, depth, STDERR_FILENO);
#else
        fmt::print(stderr, "Caught signal {}\n", signal_number);
        std::fflush(stderr);
#endif
        std::signal(signal_number, SIG_DFL);
        std::raise(signal_number);
    };
    std::signal(SIGABRT, report);
    std::signal(SIGSEGV, report);
}

/** Whether a test named @p name should run, honoring the run's filter. */
[[nodiscard]] inline bool test_should_run_(char const* name) noexcept {
    if (!test_environment.filter) return true;
    return std::strstr(name, test_environment.filter) != nullptr;
}

/** What one case answers: its failures, and the reason it could not run when it skipped. */
struct case_result_t {

    /** Checks that failed, which a case skipping past its gate still carries from before it. */
    std::size_t failures = 0;

    /** Why the case did not run, or null when it ran. */
    char const* skip_reason = nullptr;

    /** A result of @p counted failures, so a case answering its count reads as one. */
    constexpr case_result_t(std::size_t counted) noexcept : failures(counted) {}

    /** A result that did not run for @p reason, carrying the @p counted failures from before it. */
    [[nodiscard]] static constexpr case_result_t skipped(char const* reason, std::size_t counted = 0) noexcept {
        case_result_t result {counted};
        result.skip_reason = reason;
        return result;
    }
};

/** The counts one suite's @c main owns and every @c run_test rolls into. */
struct suite_totals_t {

    /** Cases that ran without a failure. */
    std::size_t passed = 0;

    /** Cases that did not run. */
    std::size_t skipped = 0;

    /** Cases with at least one failure. */
    std::size_t failed = 0;

    /** Failed checks across every case. */
    std::size_t failures = 0;

    /** The binary's @c argv[0], which turns a rerun line into a command. */
    char const* program = "";
};

/**
 *  @brief Runs the case @p name unless the filter leaves it out: seeds, times it, and rolls its
 *      result into @p totals.
 *
 *  A case that takes a @c random_generator_t gets one seeded from its name, owned by this call. A
 *  failed case also prints the command that reruns only it, under the same seed and multiplier.
 */
template <typename case_function_type_>
inline void run_test(suite_totals_t& totals, char const* name, case_function_type_ case_function) {
    if (!test_should_run_(name)) {
        fmt::print("- {} ... skipped (UCALL_FILTER)\n", name);
        std::fflush(stdout);
        return;
    }
    fmt::print("- {} ...\n", name);
    std::fflush(stdout);
    random_generator_t generator {test_seed_(name)};
    auto const start = std::chrono::steady_clock::now();
    case_result_t result {0};
    if constexpr (std::is_invocable_v<case_function_type_&, random_generator_t&>) result = case_function(generator);
    else result = case_function();
    double const seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();

    totals.failures += result.failures;
    if (result.failures) {
        ++totals.failed;
        fmt::print("- {} ... FAILED with {} failures ({:.2f} s)\n", name, result.failures, seconds);
        std::fflush(stdout);
        fmt::print(stderr, "  rerun: UCALL_SEED={} UCALL_MULTIPLIER={} UCALL_FILTER={} {}\n", test_environment.seed,
                   test_environment.multiplier, name, totals.program);
    }
    else if (result.skip_reason) {
        ++totals.skipped;
        fmt::print("- {} ... skipped: {}\n", name, result.skip_reason);
    }
    else {
        ++totals.passed;
        fmt::print("- {} ... ok ({:.2f} s)\n", name, seconds);
    }
    std::fflush(stdout);
}

/**
 *  @brief Prints the totals and answers the exit code: 1 on any failure or on a filter that matched
 *      no case, 77 when every case that ran skipped, 0 otherwise.
 *
 *  A filter that selected nothing fails, since a mistyped one would otherwise read like a green
 *  suite. 77 is the code CTest's `SKIP_RETURN_CODE` names.
 */
[[nodiscard]] inline int suite_exit_code(suite_totals_t const& totals) {
    fmt::print("Totals: {} passed, {} skipped, {} failed with {} failures, seed {}\n", totals.passed, totals.skipped,
               totals.failed, totals.failures, test_environment.seed);
    std::fflush(stdout);
    if (totals.failures) return 1;
    if (test_environment.filter && totals.passed + totals.skipped == 0) {
        fmt::print(stderr, "UCALL_FILTER={} matched no case, so nothing ran\n", test_environment.filter);
        return 1;
    }
    if (totals.skipped && !totals.passed) return 77;
    return 0;
}

#pragma endregion Test Runner

} // namespace unum::ucall::test

/*  Defined after the namespace because a macro is text: nothing above needs them, and putting them
 *  last is what lets every helper live in one namespace block rather than two split around them. */

#pragma region Assertion Helpers

/**
 *  @brief Counts one failure when @p condition is false - always active, regardless of `NDEBUG`.
 *
 *  Optional trailing arguments are an @c fmt format string and its operands:
 *  @code{.cpp}
 * failures += expect(outcome == handshake_outcome_t::settled_k, "{} handshake {}", mode, outcome);
 *  @endcode
 */
#define expect(condition, ...)                                                       \
    ::unum::ucall::test::expect_(static_cast<bool>(condition), #condition, __FILE__, \
                                 __LINE__ __VA_OPT__(, ) __VA_ARGS__)

/**
 *  @brief Like @c expect, but a failure returns from the enclosing case with @p failures plus one.
 *
 *  For the checks whose failure would make the next line unsafe, such as a null about to be read.
 */
#define require(failures, condition, ...)                                        \
    do {                                                                         \
        if (expect(condition __VA_OPT__(, ) __VA_ARGS__)) return (failures) + 1; \
    } while (0)

/** Compares two byte ranges, naming the first differing offset, and counts a mismatch. */
#define expect_bytes(actual, expected) \
    ::unum::ucall::test::expect_bytes_((actual), (expected), #actual, #expected, __FILE__, __LINE__)

/** Compares a byte range against a hex literal, without materialising either as a string. */
#define expect_hex(actual, expected_hex) \
    ::unum::ucall::test::expect_hex_((actual), (expected_hex), #actual, __FILE__, __LINE__)

#pragma endregion Assertion Helpers
