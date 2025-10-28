#pragma once

#if defined(__linux__) // iovec required only for uring
#define UCALL_IS_LINUX
#include <sys/uio.h> // `struct iovec`
#endif

#include <memory>      // `std::malloc`
#include <numeric>     // `std::iota`
#include <string_view> // `std::string_view`

#if defined(__x86_64__)
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
#endif

#include "ucall/ucall.h" // `ucall_callback_t`

namespace unum::ucall {

/// @brief To avoid dynamic memory allocations on tiny requests,
/// for every connection we keep a tiny embedded buffer of this capacity.
static constexpr std::size_t ram_page_size_k = 4096;
/// @brief  Expected max length of http headers
static constexpr std::size_t http_head_max_size_k = 1024;
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

enum descriptor_t : int {};
static constexpr descriptor_t bad_descriptor_k{-1};

struct named_callback_t {
    ucall_str_t name{};
    ucall_callback_t callback{};
    ucall_callback_tag_t callback_tag{};
};

using timestamp_t = std::uint64_t;

inline timestamp_t cpu_cycle() noexcept {
    timestamp_t result;
#ifdef __aarch64__
    /*
     * According to ARM DDI 0487F.c, from Armv8.0 to Armv8.5 inclusive, the
     * system counter is at least 56 bits wide; from Armv8.6, the counter
     * must be 64 bits wide.  So the system counter could be less than 64
     * bits wide and it is attributed with the flag 'cap_user_time_short'
     * is true.
     */
    asm volatile("mrs %0, cntvct_el0" : "=r"(result));
#else
    unsigned int low, high;
    asm volatile("rdtsc" : "=a"(low), "=d"(high));
    result = ((timestamp_t)high << 32) | low;
#endif
    return result;
}

std::size_t string_length(char const* c_str, std::size_t optional_length) noexcept {
    return c_str && !optional_length ? std::strlen(c_str) : optional_length;
}

/**
 * @brief Round-Robin construct for reusable connection states.
 */
template <typename element_at> class round_robin_gt {

    element_at* circle_{};
    std::size_t count_{};
    std::size_t capacity_{};
    std::size_t idx_newest_{};
    std::size_t idx_oldest_{};
    /// @brief Follows the tail (oldest), or races forward
    /// and cycles around all the active connections, if all
    /// of them are long-livers,
    std::size_t idx_to_poll_{};

  public:
    inline round_robin_gt& operator=(round_robin_gt&& other) noexcept {
        std::swap(circle_, other.circle_);
        std::swap(count_, other.count_);
        std::swap(capacity_, other.capacity_);
        std::swap(idx_newest_, other.idx_newest_);
        std::swap(idx_oldest_, other.idx_oldest_);
        std::swap(idx_to_poll_, other.idx_to_poll_);
        return *this;
    }

    inline bool alloc(std::size_t n) noexcept {

        auto cons = (element_at*)std::malloc(sizeof(element_at) * n);
        if (!cons)
            return false;
        circle_ = cons;
        capacity_ = n;
        return true;
    }

    inline descriptor_t drop_tail() noexcept {
        descriptor_t old = std::exchange(circle_[idx_oldest_].descriptor, bad_descriptor_k);
        idx_to_poll_ = idx_to_poll_ == idx_oldest_ ? (idx_to_poll_ + 1) % capacity_ : idx_to_poll_;
        idx_oldest_ = (idx_oldest_ + 1) % capacity_;
        count_--;
        return old;
    }

    inline void push_ahead(descriptor_t new_) noexcept {
        circle_[idx_newest_].descriptor = new_;
        circle_[idx_newest_].skipped_cycles = 0;
        circle_[idx_newest_].response.copies_count = 0;
        circle_[idx_newest_].response.iovecs_count = 0;
        idx_newest_ = (idx_newest_ + 1) % capacity_;
        count_++;
    }

    inline element_at& poll() noexcept {
        auto connection_ptr = &circle_[idx_to_poll_];
        auto idx_to_poll_following = (idx_to_poll_ + 1) % count_;
        idx_to_poll_ = idx_to_poll_following == idx_newest_ ? idx_oldest_ : idx_to_poll_following;
        return circle_[idx_to_poll_];
    }

    inline element_at& tail() noexcept { return circle_[idx_oldest_]; }
    inline element_at& head() noexcept { return circle_[idx_newest_ - 1]; }
    inline std::size_t size() const noexcept { return count_; }
    inline std::size_t capacity() const noexcept { return capacity_; }
};

} // namespace unum::ucall
