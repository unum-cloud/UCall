/**
 *  @file include/ucall/types.hpp
 *  @author Ash Vardanian
 *  @date January 18, 2023
 *  @brief Shared ABI handles, platform identities, byte views, and fallible storage primitives.
 */
#pragma once
#include <cstddef> // `std::byte`
#include <cstdint> // `std::intptr_t`
#include <cassert> // `assert`
#include <cstring> // `std::strlen`, `std::memset`, `std::memcpy`

#include <atomic>    // `std::atomic`
#include <algorithm> // `std::max`
#include <limits>    // `std::numeric_limits`
#include <memory>    // `std::uninitialized_default_construct`, `std::destroy_n`
#include <span>
#include <numeric>     // `std::iota`
#include <string_view> // `std::string_view`
#include <type_traits> // `std::is_convertible_v`
#include <utility>     // `std::exchange`, `std::swap`

#if !defined(UCALL_OS_LINUX_)
#if defined(__linux__)
#define UCALL_OS_LINUX_ 1
#else
#define UCALL_OS_LINUX_ 0
#endif // defined(__linux__)
#endif // !defined(UCALL_OS_LINUX_)

#if !defined(UCALL_OS_APPLE_)
#if defined(__APPLE__)
#define UCALL_OS_APPLE_ 1
#else
#define UCALL_OS_APPLE_ 0
#endif // defined(__APPLE__)
#endif // !defined(UCALL_OS_APPLE_)

#if !defined(UCALL_OS_WINDOWS_)
#if defined(_WIN32)
#define UCALL_OS_WINDOWS_ 1
#else
#define UCALL_OS_WINDOWS_ 0
#endif // defined(_WIN32)
#endif // !defined(UCALL_OS_WINDOWS_)

#if !defined(UCALL_OS_FREEBSD_)
#if defined(__FreeBSD__)
#define UCALL_OS_FREEBSD_ 1
#else
#define UCALL_OS_FREEBSD_ 0
#endif // defined(__FreeBSD__)
#endif // !defined(UCALL_OS_FREEBSD_)

#if !defined(UCALL_ARCH_X8664_)
#if defined(__x86_64__) || defined(_M_X64)
#define UCALL_ARCH_X8664_ 1
#else
#define UCALL_ARCH_X8664_ 0
#endif // defined(__x86_64__) || defined(_M_X64)
#endif // !defined(UCALL_ARCH_X8664_)

#if !defined(UCALL_ARCH_ARM64_)
#if defined(__aarch64__) || defined(_M_ARM64)
#define UCALL_ARCH_ARM64_ 1
#else
#define UCALL_ARCH_ARM64_ 0
#endif // defined(__aarch64__) || defined(_M_ARM64)
#endif // !defined(UCALL_ARCH_ARM64_)

#if !defined(UCALL_COMPILER_CLANG_)
#if defined(__clang__)
#define UCALL_COMPILER_CLANG_ 1
#else
#define UCALL_COMPILER_CLANG_ 0
#endif // defined(__clang__)
#endif // !defined(UCALL_COMPILER_CLANG_)

#if !defined(UCALL_COMPILER_MSVC_)
#if defined(_MSC_VER) && !defined(__clang__)
#define UCALL_COMPILER_MSVC_ 1
#else
#define UCALL_COMPILER_MSVC_ 0
#endif // defined(_MSC_VER) && !defined(__clang__)
#endif // !defined(UCALL_COMPILER_MSVC_)

#if !defined(UCALL_COMPILER_GCC_)
#if defined(__GNUC__) && !defined(__clang__)
#define UCALL_COMPILER_GCC_ 1
#else
#define UCALL_COMPILER_GCC_ 0
#endif // defined(__GNUC__) && !defined(__clang__)
#endif // !defined(UCALL_COMPILER_GCC_)

#define UCALL_OS_POSIX_ (UCALL_OS_LINUX_ || UCALL_OS_APPLE_ || UCALL_OS_FREEBSD_)

#if UCALL_OS_LINUX_ || UCALL_OS_FREEBSD_
#include <sys/mman.h> // `mmap`, `munmap`
#include <unistd.h>   // `sysconf`, `_SC_LEVEL1_DCACHE_LINESIZE`
#endif

#if UCALL_OS_APPLE_
#include <sys/mman.h>   // `mmap`, `munmap`, `PROT_*`, `MAP_*`
#include <sys/sysctl.h> // `sysctlbyname`
#endif

/*  `<winsock2.h>` has to precede `<windows.h>`, which otherwise drags in the Winsock 1.1
 *  declarations and leaves the socket backends with two incompatible definitions of each. */
#if UCALL_OS_WINDOWS_
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h> // `HANDLE`, `CreateFileMapping`, `MapViewOfFile`
#endif

#include <forkunion/atomics.hpp>
#include <forkunion/capabilities.hpp>
#include <smashtable/basic_vector.hpp>

#include "ucall/ucall.h" // `ucall_callback_t`

namespace unum::ucall {
struct wake_channel_t;
}
namespace uc = unum::ucall;

struct ucall_server_handle_t {
    ucall_server_handle_t() noexcept = default;
    ucall_server_handle_t(ucall_server_handle_t const&) = delete;
    ucall_server_handle_t& operator=(ucall_server_handle_t const&) = delete;
    ucall_server_handle_t(ucall_server_handle_t&&) = delete;
    ucall_server_handle_t& operator=(ucall_server_handle_t&&) = delete;

    /** Set in the batch queue's tail to wake its drain without publishing a request. */
    static constexpr std::uint64_t batch_signal_k = std::uint64_t {1} << 63;

    /** Stopping runs on any thread, so it touches only these CPU-independent words. */
    std::uint32_t stopped {};
    std::span<uc::wake_channel_t*> wakeups {};
    std::uint64_t* batch_tail {};
    struct api_t {
        void (*free)(ucall_server_t);
        void (*take_call)(ucall_server_take_call_t*);
        void (*take_calls)(ucall_server_take_calls_t*);
        void (*event_loop_statistics)(ucall_server_event_loop_statistics_t*);
        void (*take_batch)(ucall_server_take_batch_t*);
        void (*take_batches)(ucall_server_take_batches_t*);
        void (*add_http_endpoint)(ucall_server_add_http_endpoint_t*);
        ucall_verb_t (*request_verb)(ucall_server_t, ucall_received_http_request_t);
        std::size_t (*request_path_segments_count)(ucall_server_t, ucall_received_http_request_t);
        void (*request_path_segment)(ucall_server_request_path_segment_t*);
        void (*request_path_parameter)(ucall_server_request_path_parameter_t*);
        void (*request_query_parameter)(ucall_server_request_query_parameter_t*);
        void (*request_header)(ucall_server_request_header_t*);
        void (*request_body)(ucall_server_request_body_t*);
        void (*reply_content)(ucall_server_reply_content_t*);
        void (*reply_error)(ucall_server_reply_error_t*);
        void (*add_batch_endpoint)(ucall_server_add_batch_endpoint_t*);
    };
    api_t const* api {};
    std::uint64_t string_capabilities {}, atomic_capabilities {};
};
struct ucall_client_handle_t {
    ucall_client_handle_t() noexcept = default;
    ucall_client_handle_t(ucall_client_handle_t const&) = delete;
    ucall_client_handle_t& operator=(ucall_client_handle_t const&) = delete;
    ucall_client_handle_t(ucall_client_handle_t&&) = delete;
    ucall_client_handle_t& operator=(ucall_client_handle_t&&) = delete;

    struct api_t {
        void (*free)(ucall_client_t);
        void (*call)(ucall_client_call_t*);
        void (*take_completed)(ucall_client_take_completed_t*);
        void (*response_header)(ucall_client_response_header_t*);
        void (*response_body)(ucall_client_response_body_t*);
    };
    api_t const* api {};
    std::uint64_t string_capabilities {}, atomic_capabilities {};
};
struct ucall_received_http_request_handle_t {};
struct ucall_received_http_response_handle_t {};

namespace unum::ucall {
using server_api_t = ucall_server_handle_t::api_t;
using client_api_t = ucall_client_handle_t::api_t;

inline void publish(ucall_outcome_t* outcome, ucall_status_t status) noexcept {
    if (!outcome) return;
    outcome->message = status == ucall_status_success_k ? nullptr : ucall_status_name(status);
    std::atomic_ref<ucall_status_t> word {outcome->status};
    word.store(status, std::memory_order_release);
    word.notify_all();
}
namespace fu = ashvardanian::forkunion;
namespace st = ashvardanian::smashtable;

/** Raw storage, with the same width as the C interface's ucall_byte_t. */
using byte_t = std::byte;
static_assert(sizeof(byte_t) == sizeof(ucall_byte_t));

template <typename value_type_, typename allocator_type_>
struct allocator_delete {
    using allocator_t = typename std::allocator_traits<allocator_type_>::template rebind_alloc<value_type_>;
    allocator_t allocator {};

    void operator()(value_type_* pointer) const noexcept {
        if (!pointer) return;
        auto owner = allocator;
        std::destroy_at(pointer);
        owner.deallocate(pointer, 1);
    }
};

template <typename value_type_, typename allocator_type_>
using allocated_ptr = std::unique_ptr<value_type_, allocator_delete<value_type_, allocator_type_>>;

template <typename value_type_, typename allocator_type_, typename... arguments_types_>
allocated_ptr<value_type_, allocator_type_> allocate_unique(allocator_type_ const& allocator,
                                                            arguments_types_&&... arguments) noexcept {
    static_assert(std::is_nothrow_constructible_v<value_type_, arguments_types_...>);
    using deleter_t = allocator_delete<value_type_, allocator_type_>;
    typename deleter_t::allocator_t owner {allocator};
    auto* pointer = owner.allocate(1);
    if (pointer) std::construct_at(pointer, std::forward<arguments_types_>(arguments)...);
    return {pointer, deleter_t {owner}};
}

/**
 *  @brief Picks the first of @p kits_ this build compiled and @p caps_ runs, else @p floor_ - a
 *      ladder's one closing @c >::type, with no nested @c std::conditional_t pile.
 *
 *  Every kit states its own needs: @c capability_k, the capability it runs under, and
 *  @c compiled_k, whether this build carries its body. A kit whose target this build cannot carry
 *  is a stub of those two members alone, so naming it in a ladder never needs its body.
 */
template <auto caps_, typename floor_, typename... kits_>
struct highest_kit {
    using type = floor_;
};

template <auto caps_, typename floor_, typename head_, typename... tail_>
struct highest_kit<caps_, floor_, head_, tail_...> {
    using type = std::conditional_t<head_::compiled_k && (caps_ & head_::capability_k) != 0, head_,
                                    typename highest_kit<caps_, floor_, tail_...>::type>;
};

/**
 *  @brief Bytes to keep between things two threads write, so neither steals the other's line.
 *
 *  Not 64. Apple's arm64 cores use 128-byte lines, and x86 pulls adjacent lines in pairs for the
 *  prefetcher, so 64 leaves two hot fields sharing a fetch on both of the architectures we target.
 *  `alignas` needs a constant expression, so this is the conservative upper bound rather than
 *  whatever the machine in front of you reports.
 *
 *  Deliberately not @c std::hardware_destructive_interference_size: libstdc++ reports 64 for
 *  x86-64, which is the number this exists to correct, and GCC warns on its use in any layout that
 *  crosses a translation unit.
 */
static constexpr std::size_t false_sharing_bytes_k = 128;

/** A native socket descriptor; Winsock handles require pointer width. */
#if UCALL_OS_WINDOWS_
using descriptor_t = std::intptr_t;
#else
using descriptor_t = int;
#endif

/** Invalid file descriptor constant. */
static constexpr descriptor_t bad_descriptor_k {-1};

/**
 *  @brief Returns string length, using provided length or computing with strlen.
 *  @param[in] c_str The C string to measure.
 *  @param[in] optional_length Pre-computed length, or 0 to compute with strlen.
 *  @return Length of the string, or 0 if c_str is null.
 */
inline std::size_t string_length(char const* c_str, std::size_t optional_length) noexcept {
    if (!c_str) return 0;
    return optional_length ? optional_length : std::strlen(c_str);
}

/**
 *  @brief RAII wrapper for memory-mapped pages, portable between UNIX and Windows.
 *
 *  Uses @c mmap on POSIX systems and @c MapViewOfFile on Windows for anonymous memory mapping.
 *  Automatically unmaps on destruction. Provides zero-initialized memory pages suitable for large
 *  allocations that benefit from virtual memory backing.
 *
 *  Platform Differences:
 *  - On POSIX - uses @c mmap with @c MAP_ANONYMOUS flag.
 *  - On Windows - uses @c CreateFileMapping / @c MapViewOfFile with page file backing. Both provide
 *    similar semantics: zero-initialized, anonymous memory regions.
 */
class memory_map_t {
    byte_t* data_ {};
    std::size_t size_ {};
#if UCALL_OS_WINDOWS_
    HANDLE mapping_handle_ {};
#endif

  public:
    memory_map_t() = default;
    memory_map_t(memory_map_t const&) = delete;
    memory_map_t& operator=(memory_map_t const&) = delete;
    ~memory_map_t() noexcept { reset(); }

#if UCALL_OS_WINDOWS_
    inline memory_map_t(memory_map_t&& other) noexcept
        : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)),
          mapping_handle_(std::exchange(other.mapping_handle_, nullptr)) {}
#else
    inline memory_map_t(memory_map_t&& other) noexcept
        : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)) {}
#endif

    inline memory_map_t& operator=(memory_map_t&& other) noexcept {
        if (this == &other) return *this;
        reset();
        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0);
#if UCALL_OS_WINDOWS_
        mapping_handle_ = std::exchange(other.mapping_handle_, nullptr);
#endif
        return *this;
    }

    inline byte_t* data() const noexcept { return data_; }
    inline std::size_t size() const noexcept { return size_; }

    void reset() noexcept {
        if (!data_) return;

#if UCALL_OS_WINDOWS_
        UnmapViewOfFile(data_);
        if (mapping_handle_) CloseHandle(mapping_handle_);
        mapping_handle_ = nullptr;
#else
        munmap(data_, size_);
#endif
        data_ = nullptr;
        size_ = 0;
    }

    /**
     *  @brief Reserves @p size bytes of anonymous, zeroed address space.
     *  @return False when the kernel refuses the mapping.
     *
     *  Reserves rather than commits: neither backend is asked to touch a page here, so the physical
     *  page behind an address is allocated by the thread that first writes to it and lands on that
     *  thread's NUMA node. Committing from the builder thread instead - which is what an eager @c
     *  memset does - places every worker's buffers on whichever node ran @c ucall_server_init. Both
     *  @c mmap and @c CreateFileMapping already guarantee the pages read as zero, so nothing is
     *  lost by not writing them.
     */
    [[nodiscard]] bool remap(std::size_t size) noexcept {
        reset();

#if UCALL_OS_WINDOWS_
        HANDLE file_handle = INVALID_HANDLE_VALUE;
        auto mapping_size = static_cast<std::uint64_t>(size);
        mapping_handle_ = CreateFileMapping(file_handle, nullptr, PAGE_READWRITE,
                                            static_cast<DWORD>(mapping_size >> 32), static_cast<DWORD>(mapping_size),
                                            nullptr);
        if (mapping_handle_ == nullptr) return false;

        byte_t* new_ptr = static_cast<byte_t*>(MapViewOfFile(mapping_handle_, FILE_MAP_ALL_ACCESS, 0, 0, size));
        if (new_ptr == nullptr) {
            CloseHandle(mapping_handle_);
            mapping_handle_ = nullptr;
            return false;
        }
#else
        byte_t* new_ptr = static_cast<byte_t*>(
            mmap(nullptr, size, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
        if (new_ptr == MAP_FAILED) return false;
#endif
        data_ = new_ptr;
        size_ = size;
        return true;
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
 * pool<connection_t> conn_pool;
 * conn_pool.reserve(100);
 * connection_t* conn = conn_pool.alloc();
 * if (conn) { conn->reset(); conn_pool.release(conn); }
 *  @endcode
 */
template <typename element_type_, typename allocator_type_ = st::default_allocator<element_type_>>
class pool {
    using offsets_allocator_t = typename std::allocator_traits<allocator_type_>::template rebind_alloc<std::size_t>;
    st::basic_vector<element_type_, allocator_type_> elements_;
    st::basic_vector<std::size_t, offsets_allocator_t> free_offsets_;
    std::size_t free_count_ {};

  public:
    using element_t = element_type_;
    using value_type = element_t;
    using allocator_t = allocator_type_;

    explicit pool(allocator_t const& allocator = {}) noexcept
        : elements_(allocator), free_offsets_(offsets_allocator_t {allocator}) {}
    pool(pool const&) = delete;
    pool& operator=(pool const&) = delete;
    pool(pool&& other) noexcept
        : elements_(std::move(other.elements_)), free_offsets_(std::move(other.free_offsets_)),
          free_count_(std::exchange(other.free_count_, 0)) {}
    pool& operator=(pool&& other) noexcept {
        if (this == &other) return *this;
        elements_ = std::move(other.elements_);
        free_offsets_ = std::move(other.free_offsets_);
        free_count_ = std::exchange(other.free_count_, 0);
        return *this;
    }
    ~pool() noexcept = default;

    void reset() noexcept {
        elements_ = decltype(elements_) {elements_.get_allocator()};
        free_offsets_ = decltype(free_offsets_) {free_offsets_.get_allocator()};
        free_count_ = 0;
    }
    bool reserve(std::size_t count) noexcept {
        assert(elements_.empty());
        decltype(elements_) elements {elements_.get_allocator()};
        decltype(free_offsets_) offsets {free_offsets_.get_allocator()};
        if (st::failed(elements.resize(count)) || st::failed(offsets.resize(count))) return false;
        std::iota(offsets.begin(), offsets.end(), std::size_t {0});
        elements_ = std::move(elements);
        free_offsets_ = std::move(offsets);
        free_count_ = count;
        return true;
    }
    element_t* alloc() noexcept { return free_count_ ? elements_.data() + free_offsets_[--free_count_] : nullptr; }
    void release(element_t* released) noexcept {
        assert(contains(released) && free_count_ < elements_.size());
        free_offsets_[free_count_++] = static_cast<std::size_t>(released - elements_.data());
    }
    std::size_t offset_of(element_t& element) const noexcept {
        return static_cast<std::size_t>(&element - elements_.data());
    }
    element_t& at_offset(std::size_t index) noexcept { return elements_[index]; }
    element_t const& at_offset(std::size_t index) const noexcept { return elements_[index]; }
    element_t const* data() const noexcept { return elements_.data(); }
    std::size_t capacity() const noexcept { return elements_.size(); }
    bool contains(element_t const* pointer) const noexcept {
        return !elements_.empty() && pointer >= elements_.data() && pointer < elements_.data() + elements_.size();
    }
};

/**
 *  @brief Growable pool allocator with pointer stability guarantee.
 *
 *  Manages a linked list of fixed-size pools. When a pool is exhausted, allocates a new pool at 2x
 *  the previous capacity. Pointers remain valid for the lifetime of the successive_pools instance
 *  since individual pools are never reallocated.
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
 * successive_pools<connection_t> conn_pools(100);
 * connection_t* conn = conn_pools.alloc();  // Auto-grows if needed
 * if (conn) { conn->reset(); conn_pools.release(conn); }
 *  @endcode
 */
template <typename element_type_, typename allocator_type_ = st::default_allocator<element_type_>>
class successive_pools {
    struct pool_node_t {
        pool<element_type_, allocator_type_> pool_;
        std::size_t capacity_ {};

        /** Singly linked list, newer pools first. */
        pool_node_t* next_ {};

        pool_node_t(std::size_t capacity, allocator_type_ const& allocator) noexcept
            : pool_(allocator), capacity_(capacity) {}
    };

    allocator_type_ allocator_ {};

    /** Newest pool, tried first. */
    pool_node_t* head_ {};
    std::size_t initial_capacity_ {};
    std::size_t total_capacity_ {};

    /** Tracks total allocations for statistics. */
    std::size_t allocated_count_ {};

  public:
    using element_t = element_type_;
    using value_type = element_t;

    /**
     *  @brief Constructs with initial pool capacity.
     *  @param[in] initial_capacity Number of elements in first pool (default 100).
     */
    explicit successive_pools(std::size_t initial_capacity = 100, allocator_type_ const& allocator = {}) noexcept
        : allocator_(allocator), initial_capacity_(initial_capacity) {}

    // Disable copying, allow moving
    successive_pools(successive_pools const&) = delete;
    successive_pools& operator=(successive_pools const&) = delete;

    successive_pools(successive_pools&& other) noexcept
        : allocator_(std::move(other.allocator_)), head_(std::exchange(other.head_, nullptr)),
          initial_capacity_(std::exchange(other.initial_capacity_, 0)),
          total_capacity_(std::exchange(other.total_capacity_, 0)),
          allocated_count_(std::exchange(other.allocated_count_, 0)) {}

    successive_pools& operator=(successive_pools&& other) noexcept {
        if (this == &other) return *this;
        reset();
        allocator_ = std::move(other.allocator_);
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
     *  Tries pools in reverse order (newest first) for better cache locality. If all pools
     *  exhausted, allocates new pool at 2x the previous capacity.
     */
    [[nodiscard]] element_t* alloc() noexcept {
        // Try existing pools (newest to oldest)
        for (pool_node_t* node = head_; node != nullptr; node = node->next_) {
            element_t* elem = node->pool_.alloc();
            if (elem) {
                ++allocated_count_;
                return elem;
            }
        }

        // All pools exhausted - grow
        std::size_t new_capacity = head_ ? head_->capacity_ * 2 : initial_capacity_;
        if (!grow(new_capacity)) return nullptr;

        // Try allocation from newly created pool
        element_t* elem = head_->pool_.alloc();
        if (elem) ++allocated_count_;
        return elem;
    }

    /**
     *  @brief Returns element to its pool for reuse.
     *  @param[in] released Pointer to element (must be from this successive_pools instance).
     *
     *  Automatically determines which pool owns the pointer based on address range.
     */
    void release(element_t* released) noexcept {
        if (!released) return;

        // Find which pool owns this pointer
        for (pool_node_t* node = head_; node != nullptr; node = node->next_) {
            if (node->pool_.contains(released)) {
                node->pool_.release(released);
                --allocated_count_;
                return;
            }
        }

        assert(false && "successive_pools::release() pointer not from this pool");
    }

    /** Returns total capacity across all pools. */
    [[nodiscard]] std::size_t capacity() const noexcept { return total_capacity_; }

    /** Returns number of currently allocated elements. */
    [[nodiscard]] std::size_t allocated() const noexcept { return allocated_count_; }

    /** Returns number of pools currently allocated. */
    [[nodiscard]] std::size_t pool_count() const noexcept {
        std::size_t count = 0;
        for (pool_node_t* node = head_; node != nullptr; node = node->next_) ++count;
        return count;
    }

    /** Releases all pools and resets to empty state. */
    void reset() noexcept {
        pool_node_t* current = head_;
        while (current) {
            pool_node_t* next = current->next_;
            allocator_delete<pool_node_t, allocator_type_> {allocator_}(current);
            current = next;
        }
        head_ = nullptr;
        total_capacity_ = 0;
        allocated_count_ = 0;
    }

  private:

    /**
     *  @brief Grows pool list by adding a new pool at the head.
     *  @param[in] capacity Capacity for the new pool.
     *  @return True on success, false on allocation failure.
     */
    [[nodiscard]] bool grow(std::size_t capacity) noexcept {
        auto owned = allocate_unique<pool_node_t>(allocator_, capacity, allocator_);
        auto* new_node = owned.get();
        if (!new_node) return false;

        // Reserve the pool capacity
        if (!new_node->pool_.reserve(capacity)) return false;

        // Prepend to linked list (newest first)
        new_node->next_ = head_;
        head_ = owned.release();
        total_capacity_ += capacity;

        return true;
    }
};

template <typename element_type_>
using span = std::span<element_type_>;

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
 *  @brief Aggregate network traffic, for periodic logging.
 *
 *  Atomic because the logging thread drains these while the engines keep counting. Nothing on the
 *  request path touches it.
 */
struct alignas(false_sharing_bytes_k) traffic_stats_t {

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
    inline std::size_t log_human_readable(char* buffer, std::size_t buffer_capacity, std::size_t seconds) noexcept {
        if (seconds == 0) seconds = 1; // Prevent division by zero
        auto& s = *this;
        auto printable_normalized = [=](std::atomic<std::size_t>& i) noexcept {
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
    inline std::size_t log_json(char* buffer, std::size_t buffer_capacity) noexcept {
        auto& s = *this;
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
