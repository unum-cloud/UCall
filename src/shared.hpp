/**
 *  @brief Trivial utility types, functions, and containers shared across protocols.
 *
 *  The containers replace STL counterparts to avoid dynamic memory allocations and provide
 *  safe error handling - as opposed to exceptions on resize/reserve failures.
 *
 *  @file shared.hpp
 *  @author Ash Vardanian
 *  @date January 18, 2023
 */
#pragma once
#include <cstdlib>     // `std::malloc`, `std::free`, `std::realloc`
#include <cstring>     // `std::strlen`, `std::memset`, `std::memcpy`
#include <memory>      // `std::uninitialized_default_construct`, `std::destroy_n`
#include <numeric>     // `std::iota`
#include <string_view> // `std::string_view`

#if defined(__linux__)
#define UCALL_OS_LINUX_
#elif defined(__APPLE__)
#define UCALL_OS_MACOS_
#elif defined(_WIN32) || defined(_WIN64)
#define UCALL_OS_WINDOWS_
#endif

#if defined(_MSC_VER)
#define UCALL_COMPILER_MSVC_
#elif defined(__GNUC__)
#define UCALL_COMPILER_GCC_
#elif defined(__clang__)
#define UCALL_COMPILER_CLANG_
#endif

#if defined(__x86_64__) || defined(_M_X64)
#define UCALL_ARCH_X86_64_
#elif defined(__aarch64__)
#define UCALL_ARCH_ARM64_
#endif

#if defined(UCALL_OS_LINUX_)
#include <sys/uio.h>  // `struct iovec`
#include <sys/mman.h> // `mmap`, `munmap`
#endif

#if defined(UCALL_OS_MACOS_)
#include <sys/mman.h> // `mmap`, `munmap`, `PROT_*`, `MAP_*`
#endif

#include "ucall/ucall.h" // `ucall_callback_t`

namespace unum::ucall {

using byte_t = unsigned char;

/** @brief Embedded buffer size for tiny requests, avoiding dynamic allocations. */
static constexpr std::size_t ram_page_size_k = 4096;

/** @brief Expected maximum length of HTTP headers. */
static constexpr std::size_t http_head_max_size_k = 1024;

/**
 *  @brief Maximum length of JSON-Pointer for parameter lookup in nested requests.
 *
 *  Performance-oriented APIs have maximum depth of 1 token. Some may use up to 5 tokens,
 *  or roughly 50 characters.
 */
static constexpr std::size_t json_pointer_capacity_k = 256;

/** @brief Number of bytes in a printed integer (for error codes or request IDs). */
static constexpr std::size_t max_integer_length_k = 32;

/** @brief Alignment for largest-register-aligned memory addressing. */
static constexpr std::size_t align_k = 64;

/** @brief Approximate CPU cycles per microsecond (real-time access is expensive). */
constexpr std::size_t cpu_cycles_per_micro_second_k = 3'000;

/** @brief File descriptor type-safe wrapper. */
enum descriptor_t : ssize_t {};

/** @brief Invalid file descriptor constant. */
static constexpr descriptor_t bad_descriptor_k {-1};

/** @brief Groups server-side endpoint information needed to register a callback. */
struct named_callback_t {
    ucall_string_t name_template {};
    void (*callback)(void *) {};
    void *callback_tag {};
};

/** @brief Timestamp in CPU cycles for low-overhead time measurements. */
using timestamp_t = std::uint64_t;

/**
 *  @brief Reads CPU cycle counter for high-resolution timestamps.
 *  @return Current CPU cycle count.
 *
 *  On ARM (Armv8.0-8.5), the system counter is at least 56 bits wide.
 *  From Armv8.6 onward, it must be 64 bits wide. On x86/x64, uses RDTSC instruction.
 */
inline timestamp_t cpu_cycle() noexcept {
    timestamp_t result;
#ifdef __aarch64__
    asm volatile("mrs %0, cntvct_el0" : "=r"(result));
#else
    unsigned int low, high;
    asm volatile("rdtsc" : "=a"(low), "=d"(high));
    result = ((timestamp_t)high << 32) | low;
#endif
    return result;
}

/**
 *  @brief Returns string length, using provided length or computing with strlen.
 *  @param[in] c_str The C string to measure.
 *  @param[in] optional_length Pre-computed length, or 0 to compute with strlen.
 *  @return Length of the string.
 */
inline std::size_t string_length(char const *c_str, std::size_t optional_length) noexcept {
    return c_str && !optional_length ? std::strlen(c_str) : optional_length;
}

/**
 *  @brief Round-robin circular buffer for managing reusable connection states.
 *
 *  Maintains a circular queue with oldest/newest tracking and polling support for
 *  fair connection scheduling.
 */
template <typename element_type_>
class round_robin {

    element_type_ *circle_ {};
    std::size_t count_ {};
    std::size_t capacity_ {};
    std::size_t idx_newest_ {};
    std::size_t idx_oldest_ {};
    /** @brief Polling index that follows the tail or races forward through active connections. */
    std::size_t idx_to_poll_ {};

  public:
    using element_t = element_type_;
    using value_type = element_t;

    round_robin() = default;
    round_robin(round_robin &&) = delete;
    round_robin(round_robin const &) = delete;
    round_robin &operator=(round_robin const &) = delete;

    inline ~round_robin() noexcept {
        if (circle_) {
            if constexpr (!std::is_trivially_destructible<element_t>()) std::destroy_n(circle_, capacity_);
            std::free(circle_);
        }
    }

    inline round_robin &operator=(round_robin &&other) noexcept {
        std::swap(circle_, other.circle_);
        std::swap(count_, other.count_);
        std::swap(capacity_, other.capacity_);
        std::swap(idx_newest_, other.idx_newest_);
        std::swap(idx_oldest_, other.idx_oldest_);
        std::swap(idx_to_poll_, other.idx_to_poll_);
        return *this;
    }

    inline bool alloc(std::size_t n) noexcept {
        auto cons = (element_t *)std::malloc(sizeof(element_t) * n);
        if (!cons) return false;
        circle_ = cons;
        capacity_ = n;
        // Default-construct all elements
        std::uninitialized_default_construct(circle_, circle_ + capacity_);
        return true;
    }

    inline element_t &drop_tail() noexcept {
        element_t &dropped = circle_[idx_oldest_];
        idx_to_poll_ = idx_to_poll_ == idx_oldest_ ? (idx_to_poll_ + 1) % capacity_ : idx_to_poll_;
        idx_oldest_ = (idx_oldest_ + 1) % capacity_;
        count_--;
        return dropped;
    }

    inline element_t &push_ahead() noexcept {
        element_t &added = circle_[idx_newest_];
        idx_newest_ = (idx_newest_ + 1) % capacity_;
        count_++;
        return added;
    }

    inline element_t &poll() noexcept {
        element_t &result = circle_[idx_to_poll_];
        auto idx_to_poll_following = (idx_to_poll_ + 1) % capacity_;
        idx_to_poll_ = idx_to_poll_following == idx_newest_ ? idx_oldest_ : idx_to_poll_following;
        return result;
    }

    inline element_t &tail() noexcept { return circle_[idx_oldest_]; }
    inline element_t &head() noexcept { return circle_[idx_newest_ > 0 ? idx_newest_ - 1 : capacity_ - 1]; }
    inline std::size_t size() const noexcept { return count_; }
    inline std::size_t capacity() const noexcept { return capacity_; }
};

/**
 *  @brief Lightweight spinlock mutex alternative to @c std::mutex.
 *
 *  Non-recursive, non-reentrant spinlock optimized for low thread contention.
 *  Uses a test-and-test-and-set pattern to reduce cache coherency traffic.
 *  For high contention scenarios, consider using @c std::mutex instead.
 */
class alignas(align_k) mutex_t {
    std::atomic<bool> flag {false};

  public:
    inline void lock() noexcept {
        while (flag.exchange(true, std::memory_order_relaxed))
            // Yield to avoid burning CPU in tight loop
            while (flag.load(std::memory_order_relaxed));

        std::atomic_thread_fence(std::memory_order_acquire);
    }

    inline void unlock() noexcept {
        std::atomic_thread_fence(std::memory_order_release);
        flag.store(false, std::memory_order_relaxed);
    }
};

/**
 *  @brief RAII wrapper for memory-mapped pages, portable between UNIX and Windows.
 *
 *  Uses @c mmap on POSIX systems and @c MapViewOfFile on Windows for anonymous memory mapping.
 *  Automatically unmaps on destruction.
 */
class memory_map_t {
    byte_t *data_ {};
    std::size_t size_ {};
#if defined(UCALL_OS_WINDOWS_)
    HANDLE mapping_handle_ {};
#endif

  public:
    memory_map_t() = default;
    memory_map_t(memory_map_t const &) = delete;
    memory_map_t &operator=(memory_map_t const &) = delete;
    ~memory_map_t() noexcept { reset(); }

#if defined(UCALL_OS_WINDOWS_)
    inline memory_map_t(memory_map_t &&other) noexcept
        : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)),
          mapping_handle_(std::exchange(other.mapping_handle_, nullptr)) {}
#else
    inline memory_map_t(memory_map_t &&other) noexcept
        : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)) {}
#endif

    inline memory_map_t &operator=(memory_map_t &&other) noexcept {
        if (this == &other) return *this;
        reset();
        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0);
#if defined(UCALL_OS_WINDOWS_)
        mapping_handle_ = std::exchange(other.mapping_handle_, nullptr);
#endif
        return *this;
    }

    inline byte_t *data() const noexcept { return data_; }
    inline std::size_t size() const noexcept { return size_; }

    void reset() noexcept {
        if (!data_) return;

#if defined(UCALL_OS_WINDOWS_)
        UnmapViewOfFile(data_);
        if (mapping_handle_) CloseHandle(mapping_handle_);
        mapping_handle_ = nullptr;
#else
        munmap(data_, size_);
#endif
        data_ = nullptr;
        size_ = 0;
    }

    bool remap(std::size_t size) noexcept {
        reset();

#if defined(UCALL_OS_WINDOWS_)
        HANDLE file_handle = INVALID_HANDLE_VALUE;
        mapping_handle_ = CreateFileMapping(file_handle, nullptr, PAGE_READWRITE, 0, size, nullptr);
        if (mapping_handle_ == nullptr) return false;

        byte_t *new_ptr = (byte_t *)MapViewOfFile(mapping_handle_, FILE_MAP_ALL_ACCESS, 0, 0, size);
        if (new_ptr == nullptr) {
            CloseHandle(mapping_handle_);
            mapping_handle_ = nullptr;
            return false;
        }
#else
        // Use `mmap` for Linux and other POSIX systems
        byte_t *new_ptr = (byte_t *)mmap(nullptr, size, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (new_ptr == MAP_FAILED) return false;
#endif
        std::memset(new_ptr, 0, size);
        data_ = new_ptr;
        size_ = size;
        return true;
    }
};

/**
 *  @brief Fixed-size buffer with manual memory management.
 *
 *  Non-resizable buffer allocated once with @c resize(). Does not support reallocation.
 *  Elements must be nothrow default-constructible.
 */
template <typename element_type_>
class buffer {
    element_type_ *elements_ {};
    std::size_t capacity_ {};
    static_assert(std::is_nothrow_default_constructible<element_type_>());

  public:
    using element_t = element_type_;
    using value_type = element_t;

    buffer() noexcept = default;
    buffer(buffer &&) = delete;
    buffer(buffer const &) = delete;
    buffer &operator=(buffer const &) = delete;

    buffer &operator=(buffer &&other) noexcept {
        std::swap(elements_, other.elements_);
        std::swap(capacity_, other.capacity_);
        return *this;
    }
    [[nodiscard]] bool resize(std::size_t n) noexcept {
        if (elements_) {
            if constexpr (!std::is_trivially_destructible<element_t>()) std::destroy_n(elements_, capacity_);
            std::free(elements_);
        }
        elements_ = (element_t *)std::malloc(sizeof(element_t) * n);
        if (!elements_) {
            capacity_ = 0;
            return false;
        }
        capacity_ = n;
        std::uninitialized_default_construct(elements_, elements_ + capacity_);
        return true;
    }
    ~buffer() noexcept {
        if constexpr (!std::is_trivially_destructible<element_t>()) std::destroy_n(elements_, capacity_);
        std::free(elements_);
        elements_ = nullptr;
    }
    [[nodiscard]] element_t const *data() const noexcept { return elements_; }
    [[nodiscard]] element_t *data() noexcept { return elements_; }
    [[nodiscard]] element_t *begin() noexcept { return elements_; }
    [[nodiscard]] element_t *end() noexcept { return elements_ + capacity_; }
    [[nodiscard]] std::size_t size() const noexcept { return capacity_; }
    [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
    [[nodiscard]] element_t &operator[](std::size_t i) noexcept { return elements_[i]; }
    [[nodiscard]] element_t const &operator[](std::size_t i) const noexcept { return elements_[i]; }
};

/**
 *  @brief Object pool for efficient allocation/deallocation of fixed-size elements.
 *
 *  Maintains a free list of element indices for O(1) allocation and deallocation.
 *  All elements are default-constructed on @c reserve(). Elements must be nothrow
 *  default-constructible.
 */
template <typename element_type_>
class pool {
    std::size_t capacity_ {};
    std::size_t free_count_ {};
    element_type_ *elements_ {};
    std::size_t *free_offsets_ {};
    static_assert(std::is_nothrow_default_constructible<element_type_>());

  public:
    using element_t = element_type_;
    using value_type = element_t;

    pool() = default;
    pool(pool &&) = delete;
    pool(pool const &) = delete;
    pool &operator=(pool const &) = delete;

    pool &operator=(pool &&other) noexcept {
        std::swap(capacity_, other.capacity_);
        std::swap(free_count_, other.free_count_);
        std::swap(elements_, other.elements_);
        std::swap(free_offsets_, other.free_offsets_);
        return *this;
    }

    [[nodiscard]] bool reserve(std::size_t n) noexcept {
        auto mem = std::malloc((sizeof(element_t) + sizeof(std::size_t)) * n);
        if (!mem) return false;
        elements_ = (element_t *)mem;
        free_offsets_ = (std::size_t *)(elements_ + n);
        free_count_ = capacity_ = n;
        std::uninitialized_default_construct(elements_, elements_ + capacity_);
        std::iota(free_offsets_, free_offsets_ + n, 0ul);
        return true;
    }

    ~pool() noexcept {
        if constexpr (!std::is_trivially_destructible<element_t>()) std::destroy_n(elements_, capacity_);
        std::free(elements_);
        elements_ = nullptr;
    }
    [[nodiscard]] element_t *alloc() noexcept {
        return free_count_ ? elements_ + free_offsets_[--free_count_] : nullptr;
    }
    void release(element_t *released) noexcept { free_offsets_[free_count_++] = released - elements_; }
    [[nodiscard]] std::size_t offset_of(element_t &element) const noexcept { return &element - elements_; }
    [[nodiscard]] element_t &at_offset(std::size_t i) const noexcept { return elements_[i]; }
};

/**
 *  @brief Non-owning view over a contiguous sequence of elements.
 *
 *  Similar to @c std::span (C++20) but simplified. Does not own the memory.
 */
template <typename element_type_>
class span {
    element_type_ *begin_ {};
    element_type_ *end_ {};

  public:
    using element_t = element_type_;
    using value_type = element_t;

    span(element_t *b, element_t *e) noexcept : begin_(b), end_(e) {}

    [[nodiscard]] element_t const *data() const noexcept { return begin_; }
    [[nodiscard]] element_t *data() noexcept { return begin_; }
    [[nodiscard]] element_t *begin() noexcept { return begin_; }
    [[nodiscard]] element_t *end() noexcept { return end_; }
    [[nodiscard]] std::size_t size() const noexcept { return end_ - begin_; }
    [[nodiscard]] element_t &operator[](std::size_t i) noexcept { return begin_[i]; }
    [[nodiscard]] element_t const &operator[](std::size_t i) const noexcept { return begin_[i]; }
    operator std::basic_string_view<element_t>() const noexcept { return {data(), size()}; }
};

/**
 *  @brief Dynamic array with manual memory management.
 *
 *  Similar to @c std::vector but uses @c malloc / @c realloc instead of allocators. Supports
 *  growing with @c reserve(). Elements must be nothrow default-constructible and trivially
 *  copy-constructible (to allow @c realloc and @c memcpy).
 */
template <typename element_type_>
class array {
    element_type_ *elements_ {};
    std::size_t count_ {};
    std::size_t capacity_ {};
    static_assert(std::is_nothrow_default_constructible<element_type_>());
    static_assert(std::is_trivially_copyable<element_type_>(),
                  "Elements must be trivially copyable for realloc and memcpy");

  public:
    using element_t = element_type_;
    using value_type = element_t;

    array() = default;
    array(array &&) = delete;
    array(array const &) = delete;
    array &operator=(array const &) = delete;

    array &operator=(array &&other) noexcept {
        std::swap(elements_, other.elements_);
        std::swap(count_, other.count_);
        std::swap(capacity_, other.capacity_);
        return *this;
    }
    [[nodiscard]] bool reserve(std::size_t n) noexcept {
        if (n <= capacity_) return true;
        if (!elements_) {
            auto ptr = (element_t *)std::malloc(sizeof(element_t) * n);
            if (!ptr) return false;
            elements_ = ptr;
        }
        else {
            auto ptr = (element_t *)std::realloc(elements_, sizeof(element_t) * n);
            if (!ptr) return false;
            elements_ = ptr;
        }
        std::uninitialized_default_construct(elements_ + capacity_, elements_ + n);
        capacity_ = n;
        return true;
    }
    ~array() noexcept { reset(); }
    void reset() noexcept {
        if constexpr (!std::is_trivially_destructible<element_t>()) std::destroy_n(elements_, count_);
        std::free(elements_);
        elements_ = nullptr;
        capacity_ = count_ = 0;
    }
    [[nodiscard]] element_t const *data() const noexcept { return elements_; }
    [[nodiscard]] element_t *data() noexcept { return elements_; }
    [[nodiscard]] element_t *begin() noexcept { return elements_; }
    [[nodiscard]] element_t *end() noexcept { return elements_ + count_; }
    [[nodiscard]] std::size_t size() const noexcept { return count_; }
    [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
    [[nodiscard]] element_t &operator[](std::size_t i) noexcept { return elements_[i]; }

    void push_back_reserved(element_t element) noexcept { new (elements_ + count_++) element_t(std::move(element)); }
    void pop_back(std::size_t n = 1) noexcept { count_ -= n; }
    [[nodiscard]] bool append_n(element_t const *elements, std::size_t n) noexcept {
        if (!reserve(size() + n)) return false;
        std::memcpy(end(), elements, n * sizeof(element_t));
        count_ += n;
        return true;
    }
};

} // namespace unum::ucall
