/**
 *  @file test/harness.hpp
 *  @author Ash Vardanian
 *  @date August 9, 2026
 *  @brief Shared harness for the C++ test suites: verification, scaling, and byte diagnostics.
 *
 *  A failing check aborts, so a check is a statement rather than an expression callers accumulate.
 *  The first failure stops the run, which is why every case announces itself first - the last line
 *  on standard output names whatever the abort landed on.
 *
 *  `-fno-exceptions` rules out a `throws_verify` and a `try` around a test body, and makes
 *  `UCALL_FILTER` a substring rather than a regular expression.
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
#include <csignal> // `std::signal`, `std::raise`, `SIGABRT`, `SIGSEGV`
#include <cstddef> // `std::size_t`
#include <cstdint> // `std::uint64_t`
#include <cstdio>  // `stderr`, `stdout`, `std::fflush`
#include <cstdlib> // `std::abort`, `std::getenv`, `std::strtod`, `std::strtoull`
#include <cstring> // `std::strstr`, `std::memcmp`

#include <charconv> // `std::from_chars`
#include <chrono>   // `std::chrono::steady_clock`
#include <random>   // `std::uniform_random_bit_generator`
#include <utility>  // `std::forward`

#include <fmt/base.h>   // `fmt::print`, `fmt::format_string`
#include <fmt/color.h>  // `fmt::text_style`, `fmt::fg`, `fmt::emphasis`
#include <fmt/format.h> // `fmt::formatter`, `fmt::format_to`

#include "shared.hpp" // `byte_t`, `span`

#if defined(UCALL_OS_LINUX_) || defined(UCALL_OS_MACOS_)
#include <unistd.h> // `isatty`, `STDERR_FILENO`
#endif
#if defined(UCALL_OS_LINUX_) && defined(__GLIBC__)
#include <execinfo.h> // `backtrace`, `backtrace_symbols_fd`
#endif

namespace unum::ucall::test {

#pragma region Spans

/** Views a string literal as bytes, without its terminating zero. */
template <std::size_t length_>
[[nodiscard]] inline span<byte_t const> ascii_bytes(char const (&text)[length_]) noexcept {
    byte_t const* const begin = reinterpret_cast<byte_t const*>(text);
    return {begin, begin + length_ - 1};
}

/** Views a counted run of characters as bytes. */
[[nodiscard]] inline span<byte_t const> ascii_bytes(char const* text, std::size_t length) noexcept {
    byte_t const* const begin = reinterpret_cast<byte_t const*>(text);
    return {begin, begin + length};
}

/** Fills a range with one repeated value, keeping its pointer and length together. */
inline void fill_with(span<byte_t> bytes, byte_t value) noexcept {
    // `memset` with a null destination is undefined even when it writes no bytes, and an empty
    // span carries one - the same hazard `array::append_n` guards against.
    if (bytes.size()) std::memset(bytes.data(), value, bytes.size());
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
[[nodiscard]] inline bool all_zero(span<byte_t const> bytes) noexcept { return all_equal_to(bytes, 0); }

#pragma endregion Spans

/*  Published cryptographic vectors arrive as hex, so two of the four suites speak it. Names ending
 *  in an underscore are this header's own workings and have no callers outside it. */

#pragma region Hexadecimal

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
        byte_t high = 0, low = 0;
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
        byte_t high = 0, low = 0;
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
        fmt::print(stderr, "{}{}", digits[bytes[index] >> 4], digits[bytes[index] & 0x0Fu]);
    if (shown < bytes.size()) fmt::print(stderr, "... ({} bytes total)", bytes.size());
}

#pragma endregion Hexadecimal

#pragma region Diagnostics

/** Whether diagnostics may use colour: only when standard error is a terminal. */
[[nodiscard]] inline bool diagnostics_are_styled_() noexcept {
#if defined(UCALL_OS_LINUX_) || defined(UCALL_OS_MACOS_)
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

/** Backs @c verify_bytes: reports a mismatch and answers whether the ranges agreed. */
[[nodiscard]] inline bool report_unequal_bytes(span<byte_t const> actual, span<byte_t const> expected,
                                               char const* actual_text, char const* expected_text, char const* file,
                                               int line) {
    if (bytes_equal(actual, expected)) return true;

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
    return false;
}

/** Backs @c verify_hex: reports a mismatch and answers whether the range matched the literal. */
[[nodiscard]] inline bool report_unmatched_hex(span<byte_t const> actual, char const* expected_hex,
                                               char const* actual_text, char const* file, int line) {
    hex_match_t const answer = bytes_match_hex_(actual, expected_hex);
    if (answer == hex_match_t::matched_k) return true;

    fmt::print(stderr, failure_style_(), "Test verification failed: {}, {}:{}\n",
               answer == hex_match_t::malformed_literal_k ? "the hex literal is malformed" : "bytes do not match hex",
               file, line);
    fmt::print(stderr, detail_style_(), "  actual   `{}` holds {} bytes\n", actual_text, actual.size());
    fmt::print(stderr, "  actual   ");
    print_hex_(actual, 64);
    fmt::print(stderr, "\n  expected {}\n", expected_hex);
    return false;
}

/** Announces the case about to run, so an aborting harness names what it was attempting. */
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
 *  @brief Minimal SplitMix64 generator, modelling @c std::uniform_random_bit_generator.
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

    result_type state {};

    explicit random_generator_t(result_type seed) noexcept : state(seed) {}

    [[nodiscard]] static constexpr result_type min() noexcept { return 0; }
    [[nodiscard]] static constexpr result_type max() noexcept { return ~result_type {0}; }

    [[nodiscard]] result_type operator()() noexcept {
        result_type mixed = (state += 0x9E3779B97F4A7C15ull);
        mixed = (mixed ^ (mixed >> 30)) * 0xBF58476D1CE4E5B9ull;
        mixed = (mixed ^ (mixed >> 27)) * 0x94D049BB133111EBull;
        return mixed ^ (mixed >> 31);
    }

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

/** Aborts with a message, for the checks that run before the `verify` macro is in scope. */
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

/** The shared generator. Reseeded per test, so a filtered run reproduces an unfiltered one. */
[[nodiscard]] inline random_generator_t& global_random_generator() noexcept {
    static random_generator_t generator(test_environment.seed);
    return generator;
}

/** Reseeds the shared generator from the run's seed and a test's name. */
inline void seed_generator_for_test_(char const* name) noexcept {
    std::uint64_t hashed = 0xCBF29CE484222325ull;
    for (char const* character = name; *character; ++character) {
        hashed ^= static_cast<std::uint64_t>(static_cast<unsigned char>(*character));
        hashed *= 0x100000001B3ull;
    }
    global_random_generator().state = test_environment.seed ^ hashed;
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

#pragma region Test Runner

/**
 *  @brief Prints a backtrace on abort or a segmentation fault, then re-raises the default action.
 *
 *  Load-bearing where a counting harness would not need it: @c verify aborts, so this is what turns
 *  a failure into a located one.
 */
inline void install_test_signal_handlers() noexcept {
    auto report = [](int signal_number) noexcept {
#if defined(UCALL_OS_LINUX_) && defined(__GLIBC__)
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

/**
 *  @brief Runs one named test: honors the filter, reseeds, times it, reports the outcome.
 *
 *  Reaching the end is the pass; a @c verify inside aborts, and the name printed before it started
 *  is what says which one.
 */
inline void run_test(char const* name, void (*test_function)()) {
    if (!test_should_run_(name)) {
        fmt::print("- {} ... skipped (UCALL_FILTER)\n", name);
        std::fflush(stdout);
        return;
    }
    fmt::print("- {} ...\n", name);
    std::fflush(stdout);
    seed_generator_for_test_(name);
    auto const start = std::chrono::steady_clock::now();
    test_function();
    double const seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
    fmt::print("- {} ... ok ({:.2f} s)\n", name, seconds);
    std::fflush(stdout);
}

#pragma endregion Test Runner

} // namespace unum::ucall::test

/*  Defined after the namespace because a macro is text: nothing above needs them, and putting them
 *  last is what lets every helper live in one namespace block rather than two split around them. */

#pragma region Assertion Helpers

/**
 *  @brief Test-suite verification - always active, regardless of `NDEBUG`.
 *
 *  Optional trailing arguments are an @c fmt format string and its operands:
 *  @code{.cpp}
 * verify(outcome == handshake_outcome_t::settled_k, "{} handshake {}", mode, outcome);
 *  @endcode
 */
#define verify(condition, ...)                                                          \
    do {                                                                                \
        if (!(condition)) {                                                             \
            ::unum::ucall::test::report_failure(#condition, __FILE__, __LINE__);        \
            __VA_OPT__(fmt::print(stderr, "  " __VA_ARGS__); fmt::print(stderr, "\n");) \
            std::abort();                                                               \
        }                                                                               \
    } while (0)

/** Compares two byte ranges, naming the first differing offset before aborting. */
#define verify_bytes(actual, expected)                                                                                \
    do {                                                                                                              \
        if (!::unum::ucall::test::report_unequal_bytes((actual), (expected), #actual, #expected, __FILE__, __LINE__)) \
            std::abort();                                                                                             \
    } while (0)

/** Compares a byte range against a hex literal, without materialising either as a string. */
#define verify_hex(actual, expected_hex)                                                                       \
    do {                                                                                                       \
        if (!::unum::ucall::test::report_unmatched_hex((actual), (expected_hex), #actual, __FILE__, __LINE__)) \
            std::abort();                                                                                      \
    } while (0)

#pragma endregion Assertion Helpers
