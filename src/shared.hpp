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
#include <cassert>     // `assert`
#include <cstdlib>     // `std::malloc`, `std::free`, `std::realloc`
#include <cstring>     // `std::strlen`, `std::memset`, `std::memcpy`
#include <memory>      // `std::uninitialized_default_construct`, `std::destroy_n`
#include <numeric>     // `std::iota`
#include <string_view> // `std::string_view`
#include <utility>     // `std::exchange`, `std::swap`

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
 *  @return Length of the string, or 0 if c_str is null.
 */
inline std::size_t string_length(char const *c_str, std::size_t optional_length) noexcept {
    if (!c_str) return 0;
    return optional_length ? optional_length : std::strlen(c_str);
}

/**
 *  @brief Round-robin circular buffer for managing reusable connection states.
 *
 *  Maintains a circular queue with oldest/newest tracking and polling support for
 *  fair connection scheduling.
 *
 *  @tparam element_type_ Type of elements stored. Must be nothrow default-constructible.
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
    round_robin(round_robin const &) = delete;
    round_robin &operator=(round_robin const &) = delete;

    inline round_robin(round_robin &&other) noexcept
        : circle_(std::exchange(other.circle_, nullptr)), count_(std::exchange(other.count_, 0)),
          capacity_(std::exchange(other.capacity_, 0)), idx_newest_(std::exchange(other.idx_newest_, 0)),
          idx_oldest_(std::exchange(other.idx_oldest_, 0)), idx_to_poll_(std::exchange(other.idx_to_poll_, 0)) {}

    void reset() noexcept {
        if (!circle_) return;
        if constexpr (!std::is_trivially_destructible<element_t>()) std::destroy_n(circle_, capacity_);
        std::free(circle_);
        circle_ = nullptr;
        count_ = capacity_ = 0;
        idx_newest_ = idx_oldest_ = idx_to_poll_ = 0;
    }

    inline ~round_robin() noexcept { reset(); }

    inline round_robin &operator=(round_robin &&other) noexcept {
        if (this == &other) return *this;
        reset();
        circle_ = std::exchange(other.circle_, nullptr);
        count_ = std::exchange(other.count_, 0);
        capacity_ = std::exchange(other.capacity_, 0);
        idx_newest_ = std::exchange(other.idx_newest_, 0);
        idx_oldest_ = std::exchange(other.idx_oldest_, 0);
        idx_to_poll_ = std::exchange(other.idx_to_poll_, 0);
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

    /** @brief Removes and returns oldest element. Requires non-empty buffer. */
    inline element_t &drop_tail() noexcept {
        assert(count_ > 0 && "drop_tail() called on empty round_robin");
        element_t &dropped = circle_[idx_oldest_];
        idx_to_poll_ = idx_to_poll_ == idx_oldest_ ? (idx_to_poll_ + 1) % capacity_ : idx_to_poll_;
        idx_oldest_ = (idx_oldest_ + 1) % capacity_;
        count_--;
        return dropped;
    }

    /** @brief Adds element at head position. Requires non-full buffer. */
    inline element_t &push_ahead() noexcept {
        assert(count_ < capacity_ && "push_ahead() called on full round_robin");
        element_t &added = circle_[idx_newest_];
        idx_newest_ = (idx_newest_ + 1) % capacity_;
        count_++;
        return added;
    }

    /** @brief Returns current element and advances polling index for fair round-robin iteration. */
    inline element_t &poll() noexcept {
        assert(capacity_ > 0 && "poll() called on unallocated round_robin");
        element_t &result = circle_[idx_to_poll_];
        auto idx_to_poll_following = (idx_to_poll_ + 1) % capacity_;
        idx_to_poll_ = idx_to_poll_following == idx_newest_ ? idx_oldest_ : idx_to_poll_following;
        return result;
    }

    /** @brief Returns oldest element. Requires non-empty buffer. */
    inline element_t &tail() noexcept {
        assert(count_ > 0 && "tail() called on empty round_robin");
        return circle_[idx_oldest_];
    }
    /** @brief Returns newest element. Requires non-empty buffer. */
    inline element_t &head() noexcept {
        assert(count_ > 0 && "head() called on empty round_robin");
        return circle_[idx_newest_ > 0 ? idx_newest_ - 1 : capacity_ - 1];
    }
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
 *  Automatically unmaps on destruction. Provides zero-initialized memory pages suitable for
 *  large allocations that benefit from virtual memory backing.
 *
 *  Platform Differences:
 *  - On POSIX - uses @c mmap with @c MAP_ANONYMOUS flag.
 *  - On Windows - uses @c CreateFileMapping / @c MapViewOfFile with page file backing.
 *  Both provide similar semantics: zero-initialized, anonymous memory regions.
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
 *  Simple buffer container that allocates a fixed number of elements via @c resize(). Unlike
 *  @c array, does not support growing or partial filling - capacity is always equal to the
 *  number of constructed elements. Suitable for fixed-size working buffers.
 *
 *  @tparam element_type_ Type of elements stored. Must be nothrow default-constructible.
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
    buffer(buffer const &) = delete;
    buffer &operator=(buffer const &) = delete;

    buffer(buffer &&other) noexcept
        : elements_(std::exchange(other.elements_, nullptr)), capacity_(std::exchange(other.capacity_, 0)) {}

    buffer &operator=(buffer &&other) noexcept {
        if (this == &other) return *this;
        reset();
        elements_ = std::exchange(other.elements_, nullptr);
        capacity_ = std::exchange(other.capacity_, 0);
        return *this;
    }

    void reset() noexcept {
        if constexpr (!std::is_trivially_destructible<element_t>()) std::destroy_n(elements_, capacity_);
        std::free(elements_);
        elements_ = nullptr;
        capacity_ = 0;
    }

    [[nodiscard]] bool resize(std::size_t n) noexcept {
        reset();
        elements_ = (element_t *)std::malloc(sizeof(element_t) * n);
        if (!elements_) {
            capacity_ = 0;
            return false;
        }
        capacity_ = n;
        std::uninitialized_default_construct(elements_, elements_ + capacity_);
        return true;
    }
    ~buffer() noexcept { reset(); }
    [[nodiscard]] element_t const *data() const noexcept { return elements_; }
    [[nodiscard]] element_t *data() noexcept { return elements_; }
    [[nodiscard]] element_t *begin() noexcept { return elements_; }
    [[nodiscard]] element_t *end() noexcept { return elements_ + capacity_; }
    [[nodiscard]] std::size_t size() const noexcept { return capacity_; }
    [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
    [[nodiscard]] element_t &operator[](std::size_t i) noexcept {
        assert(i < capacity_ && "buffer::operator[] index out of bounds");
        return elements_[i];
    }
    [[nodiscard]] element_t const &operator[](std::size_t i) const noexcept {
        assert(i < capacity_ && "buffer::operator[] index out of bounds");
        return elements_[i];
    }
};

/**
 *  @brief Object pool for efficient allocation/deallocation of fixed-size elements.
 *
 *  Maintains a free list for O(1) operations. All elements remain constructed for the pool's
 *  lifetime, enabling fast reuse without construction overhead.
 *
 *  @tparam element_type_ Type of pooled elements. Must be nothrow default-constructible.
 *
 *  @code
 *  pool<connection_t> conn_pool;
 *  conn_pool.reserve(100);
 *  connection_t* conn = conn_pool.alloc();
 *  if (conn) { conn->reset(); conn_pool.release(conn); }
 *  @endcode
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
    pool(pool const &) = delete;
    pool &operator=(pool const &) = delete;

    pool(pool &&other) noexcept
        : capacity_(std::exchange(other.capacity_, 0)), free_count_(std::exchange(other.free_count_, 0)),
          elements_(std::exchange(other.elements_, nullptr)),
          free_offsets_(std::exchange(other.free_offsets_, nullptr)) {}

    pool &operator=(pool &&other) noexcept {
        if (this == &other) return *this;
        reset();
        capacity_ = std::exchange(other.capacity_, 0);
        free_count_ = std::exchange(other.free_count_, 0);
        elements_ = std::exchange(other.elements_, nullptr);
        free_offsets_ = std::exchange(other.free_offsets_, nullptr);
        return *this;
    }

    void reset() noexcept {
        if (!elements_) return;
        if constexpr (!std::is_trivially_destructible<element_t>()) std::destroy_n(elements_, capacity_);
        std::free(elements_);
        elements_ = nullptr;
        free_offsets_ = nullptr;
        capacity_ = free_count_ = 0;
    }

    /** @brief Initializes pool with n elements. Can only be called once. */
    [[nodiscard]] bool reserve(std::size_t n) noexcept {
        assert(!elements_ && "pool::reserve() called on already-initialized pool");
        auto mem = std::malloc((sizeof(element_t) + sizeof(std::size_t)) * n);
        if (!mem) return false;
        elements_ = (element_t *)mem;
        free_offsets_ = (std::size_t *)(elements_ + n);
        free_count_ = capacity_ = n;
        std::uninitialized_default_construct(elements_, elements_ + capacity_);
        std::iota(free_offsets_, free_offsets_ + n, 0ul);
        return true;
    }

    ~pool() noexcept { reset(); }

    /** @brief Returns pointer to available element, or nullptr if pool exhausted. */
    [[nodiscard]] element_t *alloc() noexcept {
        return free_count_ ? elements_ + free_offsets_[--free_count_] : nullptr;
    }

    /** @brief Returns element to pool. Pointer must be valid, within bounds, and not double-freed. */
    void release(element_t *released) noexcept {
        assert(released && "pool::release() called with null pointer");
        assert(released >= elements_ && released < elements_ + capacity_ && "pool::release() pointer out of bounds");
        assert(free_count_ < capacity_ && "pool::release() called too many times (double-free?)");
        free_offsets_[free_count_++] = released - elements_;
    }

    [[nodiscard]] std::size_t offset_of(element_t &element) const noexcept { return &element - elements_; }
    [[nodiscard]] element_t &at_offset(std::size_t i) const noexcept { return elements_[i]; }
    [[nodiscard]] element_t const *data() const noexcept { return elements_; }

    /** @brief Checks if pointer is within this pool's allocated range. */
    [[nodiscard]] bool contains(element_t const *ptr) const noexcept {
        return ptr >= elements_ && ptr < elements_ + capacity_;
    }
};

/**
 *  @brief Growable pool allocator with pointer stability guarantee.
 *
 *  Manages a linked list of fixed-size pools. When a pool is exhausted, allocates
 *  a new pool at 2x the previous capacity. Pointers remain valid for the lifetime
 *  of the successive_pools instance since individual pools are never reallocated.
 *
 *  Allocation strategy:
 *  - Tries to allocate from newest (largest) pool first for better cache locality
 *  - Falls back to older pools if newest is exhausted
 *  - Allocates new pool (2x previous size) if all pools are full
 *
 *  Memory overhead:
 *  - Each pool stores a linked-list pointer (8 bytes per pool)
 *  - With exponential growth, total overhead is ~2x the final capacity
 *
 *  Example growth pattern (initial_capacity = 100):
 *  - Pool 0: 100 elements
 *  - Pool 1: 200 elements (if pool 0 fills)
 *  - Pool 2: 400 elements (if pool 1 fills)
 *  - Pool 3: 800 elements ...
 *
 *  @tparam element_type_ Type of pooled elements. Must be nothrow default-constructible.
 *
 *  @code
 *  successive_pools<connection_t> conn_pools(100);
 *  connection_t* conn = conn_pools.alloc();  // Auto-grows if needed
 *  if (conn) { conn->reset(); conn_pools.release(conn); }
 *  @endcode
 */
template <typename element_type_>
class successive_pools {
    struct pool_node {
        pool<element_type_> pool_ {};
        std::size_t capacity_ {};
        pool_node *next_ {}; // Singly linked list, newer pools first

        pool_node(std::size_t cap) noexcept : capacity_(cap), next_(nullptr) {}
    };

    pool_node *head_ {}; // Newest pool (tried first)
    std::size_t initial_capacity_ {};
    std::size_t total_capacity_ {};
    std::size_t allocated_count_ {}; // Track total allocations for statistics

  public:
    using element_t = element_type_;
    using value_type = element_t;

    /**
     *  @brief Constructs with initial pool capacity.
     *  @param initial_capacity Number of elements in first pool (default 100).
     */
    explicit successive_pools(std::size_t initial_capacity = 100) noexcept
        : head_(nullptr), initial_capacity_(initial_capacity), total_capacity_(0), allocated_count_(0) {}

    // Disable copying, allow moving
    successive_pools(successive_pools const &) = delete;
    successive_pools &operator=(successive_pools const &) = delete;

    successive_pools(successive_pools &&other) noexcept
        : head_(std::exchange(other.head_, nullptr)), initial_capacity_(std::exchange(other.initial_capacity_, 0)),
          total_capacity_(std::exchange(other.total_capacity_, 0)),
          allocated_count_(std::exchange(other.allocated_count_, 0)) {}

    successive_pools &operator=(successive_pools &&other) noexcept {
        if (this == &other) return *this;
        reset();
        head_ = std::exchange(other.head_, nullptr);
        initial_capacity_ = std::exchange(other.initial_capacity_, 0);
        total_capacity_ = std::exchange(other.total_capacity_, 0);
        allocated_count_ = std::exchange(other.allocated_count_, 0);
        return *this;
    }

    ~successive_pools() noexcept { reset(); }

    /**
     *  @brief Allocates an element from the pool, growing if necessary.
     *  @return Pointer to element, or nullptr on allocation failure (OOM).
     *
     *  Tries pools in reverse order (newest first) for better cache locality.
     *  If all pools exhausted, allocates new pool at 2x the previous capacity.
     */
    [[nodiscard]] element_t *alloc() noexcept {
        // Try existing pools (newest to oldest)
        for (pool_node *node = head_; node != nullptr; node = node->next_) {
            element_t *elem = node->pool_.alloc();
            if (elem) {
                ++allocated_count_;
                return elem;
            }
        }

        // All pools exhausted - grow
        std::size_t new_capacity = head_ ? head_->capacity_ * 2 : initial_capacity_;
        if (!grow(new_capacity)) return nullptr;

        // Try allocation from newly created pool
        element_t *elem = head_->pool_.alloc();
        if (elem) ++allocated_count_;
        return elem;
    }

    /**
     *  @brief Returns element to its pool for reuse.
     *  @param released Pointer to element (must be from this successive_pools instance).
     *
     *  Automatically determines which pool owns the pointer based on address range.
     */
    void release(element_t *released) noexcept {
        if (!released) return;

        // Find which pool owns this pointer
        for (pool_node *node = head_; node != nullptr; node = node->next_) {
            if (node->pool_.contains(released)) {
                node->pool_.release(released);
                --allocated_count_;
                return;
            }
        }

        assert(false && "successive_pools::release() pointer not from this pool");
    }

    /** @brief Returns total capacity across all pools. */
    [[nodiscard]] std::size_t capacity() const noexcept { return total_capacity_; }

    /** @brief Returns number of currently allocated elements. */
    [[nodiscard]] std::size_t allocated() const noexcept { return allocated_count_; }

    /** @brief Returns number of pools currently allocated. */
    [[nodiscard]] std::size_t pool_count() const noexcept {
        std::size_t count = 0;
        for (pool_node *node = head_; node != nullptr; node = node->next_) ++count;
        return count;
    }

    /** @brief Releases all pools and resets to empty state. */
    void reset() noexcept {
        pool_node *current = head_;
        while (current) {
            pool_node *next = current->next_;
            delete current;
            current = next;
        }
        head_ = nullptr;
        total_capacity_ = 0;
        allocated_count_ = 0;
    }

  private:
    /**
     *  @brief Grows pool list by adding a new pool at the head.
     *  @param capacity Capacity for the new pool.
     *  @return True on success, false on allocation failure.
     */
    [[nodiscard]] bool grow(std::size_t capacity) noexcept {
        pool_node *new_node = new (std::nothrow) pool_node(capacity);
        if (!new_node) return false;

        // Reserve the pool capacity
        if (!new_node->pool_.reserve(capacity)) {
            delete new_node;
            return false;
        }

        // Prepend to linked list (newest first)
        new_node->next_ = head_;
        head_ = new_node;
        total_capacity_ += capacity;

        return true;
    }
};

/**
 *  @brief Non-owning view over a contiguous sequence of elements.
 *
 *  Similar to @c std::span (C++20) but simplified. Provides a lightweight reference to a
 *  contiguous memory region without ownership. Does not allocate, deallocate, or manage
 *  the referenced memory in any way.
 *
 *  @tparam element_type_ Type of elements in the view. Can be const-qualified for read-only views.
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
    [[nodiscard]] element_t &operator[](std::size_t i) noexcept {
        assert(i < size() && "span::operator[] index out of bounds");
        return begin_[i];
    }
    [[nodiscard]] element_t const &operator[](std::size_t i) const noexcept {
        assert(i < size() && "span::operator[] index out of bounds");
        return begin_[i];
    }
    operator std::basic_string_view<element_t>() const noexcept { return {data(), size()}; }
};

/**
 *  @brief Dynamic array with manual memory management.
 *
 *  Similar to @c std::vector but uses @c malloc / @c realloc for amortized O(1) growth.
 *  Maintains both capacity (allocated) and count (active) for efficient growing.
 *
 *  @tparam element_type_ Type of elements stored. Must be nothrow default-constructible and
 *    trivially copyable (required for @c realloc and @c memcpy to work correctly).
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
    array(array const &) = delete;
    array &operator=(array const &) = delete;

    array(array &&other) noexcept
        : elements_(std::exchange(other.elements_, nullptr)), count_(std::exchange(other.count_, 0)),
          capacity_(std::exchange(other.capacity_, 0)) {}

    array &operator=(array &&other) noexcept {
        if (this == &other) return *this;
        reset();
        elements_ = std::exchange(other.elements_, nullptr);
        count_ = std::exchange(other.count_, 0);
        capacity_ = std::exchange(other.capacity_, 0);
        return *this;
    }
    /** @brief Grows capacity to at least n elements. Never shrinks. Preserves existing elements. */
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
        if (!elements_) return;
        if constexpr (!std::is_trivially_destructible<element_t>()) std::destroy_n(elements_, capacity_);
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
    [[nodiscard]] element_t &operator[](std::size_t i) noexcept {
        assert(i < count_ && "array::operator[] index out of bounds");
        return elements_[i];
    }

    /** @brief Adds element to pre-allocated space. Requires capacity > count. */
    void push_back_reserved(element_t element) noexcept {
        assert(count_ < capacity_ && "push_back_reserved() called on full array");
        elements_[count_++] = std::move(element);
    }
    /** @brief Decrements count by n. Does not destroy elements or deallocate. */
    void pop_back(std::size_t n = 1) noexcept {
        assert(count_ >= n && "pop_back() would underflow array");
        count_ -= n;
    }
    [[nodiscard]] bool append_n(element_t const *elements, std::size_t n) noexcept {
        if (!reserve(size() + n)) return false;
        std::memcpy(end(), elements, n * sizeof(element_t));
        count_ += n;
        return true;
    }
};

struct number_and_suffix_t {
    float number {};
    char suffix {};
};

inline number_and_suffix_t printable(std::size_t n) noexcept {
    if (n > 1'000'000'000) return {n / 1'000'000'000.0f, 'G'};
    if (n > 1'000'000) return {n / 1'000'000.0f, 'M'};
    if (n > 1'000) return {n / 1'000.0f, 'K'};
    return {n + 0.0f, ' '};
}

/**
 *  @brief Tracks aggregate network traffic (connections, bytes, packets) for periodic logging.
 */
struct traffic_stats_t {

    static constexpr std::size_t default_frequency_secs_k {5};

    std::atomic<std::size_t> added_connections {};
    std::atomic<std::size_t> closed_connections {};
    std::atomic<std::size_t> bytes_received {};
    std::atomic<std::size_t> bytes_sent {};
    std::atomic<std::size_t> packets_received {};
    std::atomic<std::size_t> packets_sent {};

    /**
     *  @brief Logs statistical data in a human-readable format, normalized for a time period.
     *
     *  @param[in] buffer Pointer to the buffer where the log string will be written.
     *  @param[in] buffer_capacity Size of the buffer.
     *  @param[in] seconds Time span over which the statistics were collected.
     *  @return The number of characters written to the buffer.
     */
    inline std::size_t log_human_readable(char *buffer, std::size_t buffer_capacity, std::size_t seconds) noexcept {
        if (seconds == 0) seconds = 1; // Prevent division by zero
        auto &s = *this;
        auto printable_normalized = [=](std::atomic<std::size_t> &i) noexcept {
            return printable(double(i.exchange(0, std::memory_order_relaxed)) / seconds);
        };
        auto added_connections = printable_normalized(s.added_connections);
        auto closed_connections = printable_normalized(s.closed_connections);
        auto bytes_received = printable_normalized(s.bytes_received);
        auto bytes_sent = printable_normalized(s.bytes_sent);
        auto packets_received = printable_normalized(s.packets_received);
        auto packets_sent = printable_normalized(s.packets_sent);
        auto len = snprintf( //
            buffer, buffer_capacity,
            "connections: +%.1f %c/s, "
            "-%.1f %c/s, "
            "RX: %.1f %c msgs/s, "
            "%.1f %cb/s, "
            "TX: %.1f %c msgs/s, "
            "%.1f %cb/s. \n",
            added_connections.number, added_connections.suffix,   //
            closed_connections.number, closed_connections.suffix, //
            packets_received.number, packets_received.suffix,     //
            bytes_received.number, bytes_received.suffix,         //
            packets_sent.number, packets_sent.suffix,             //
            bytes_sent.number, bytes_sent.suffix                  //
        );
        return static_cast<std::size_t>(len);
    }

    /**
     *  @brief Logs statistical data in a JSON format.
     *
     *  @param[in] buffer Pointer to the buffer where the log string will be written.
     *  @param[in] buffer_capacity Size of the buffer.
     *  @return The number of characters written to the buffer.
     */
    inline std::size_t log_json(char *buffer, std::size_t buffer_capacity) noexcept {
        auto &s = *this;
        auto added_connections = s.added_connections.exchange(0, std::memory_order_relaxed);
        auto closed_connections = s.closed_connections.exchange(0, std::memory_order_relaxed);
        auto bytes_received = s.bytes_received.exchange(0, std::memory_order_relaxed);
        auto bytes_sent = s.bytes_sent.exchange(0, std::memory_order_relaxed);
        auto packets_received = s.packets_received.exchange(0, std::memory_order_relaxed);
        auto packets_sent = s.packets_sent.exchange(0, std::memory_order_relaxed);
        auto format =
            R"( {"add":%zu,"close":%zu,"recv_bytes":%zu,"sent_bytes":%zu,"recv_packs":%zu,"sent_packs":%zu} \n )";
        auto len = snprintf(         //
            buffer, buffer_capacity, //
            format,                  //
            added_connections,       //
            closed_connections,      //
            bytes_received,          //
            bytes_sent,              //
            packets_received,        //
            packets_sent             //
        );
        return static_cast<std::size_t>(len);
    }
};

} // namespace unum::ucall
