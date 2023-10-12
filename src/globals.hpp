#pragma once

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#define UCALL_IS_WINDOWS
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

#if defined(__linux__)
#define UCALL_IS_LINUX
#endif

#include <cstddef>

namespace unum::ucall {

using descriptor_t = ssize_t;
using connectino_data_t = void*;
using network_data_t = void*;

/// @brief To avoid dynamic memory allocations on tiny requests,
/// for every connection we keep a tiny embedded buffer of this capacity.
static constexpr std::size_t ram_page_size_k = 4096;

/// @brief The maximum length of JSON-Pointer, we will use
/// to lookup parameters in heavily nested requests.
/// A performance-oriented API will have maximum depth of 1 token.
/// Some may go as far as 5 token, or roughly 50 character.
static constexpr std::size_t json_pointer_capacity_k = 256;
/// @brief Number of bytes in a printed integer.
/// Used either for error codes, or for request IDs.
static constexpr std::size_t max_integer_length_k = 32;
/// @brief Needed for largest-register-aligned memory addressing.
static constexpr std::size_t align_k = 64;
/// @brief Accessing real time from user-space is very expensive.
/// To approximate we can use CPU cycle counters.
constexpr std::size_t cpu_cycles_per_micro_second_k = 3'000;

// /// @brief As we use SIMDJSON, we don't want to fill our message buffers entirely.
// /// If there is a @b padding at the end, matching the size of the largest CPU register
// /// on the machine, we would avoid copies.
// static constexpr std::size_t max_embedded_length_k{ram_page_size_k - sj::SIMDJSON_PADDING};

static constexpr descriptor_t invalid_descriptor_k{-1};
static constexpr std::size_t max_inactive_duration_ns_k{10'000'000'000}; // 10 sec
static constexpr std::size_t wakeup_initial_frequency_ns_k{100};
static constexpr std::size_t sleep_growth_factor_k{2};

static constexpr descriptor_t bad_descriptor_k{-1};

} // namespace unum::ucall
