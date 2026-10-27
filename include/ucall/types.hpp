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
#include <cstring> // `std::memset`, `std::memcpy`

#include <atomic>      // `std::atomic`
#include <algorithm>   // `std::max`
#include <limits>      // `std::numeric_limits`
#include <memory>      // `std::uninitialized_default_construct`, `std::destroy_n`
#include <span>        // `std::span`, `std::as_bytes`
#include <numeric>     // `std::iota`
#include <string_view> // `std::string_view`
#include <type_traits> // `std::is_convertible_v`
#include <utility>     // `std::move`

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

/*  `<winsock2.h>` has to precede `<windows.h>`, which otherwise drags in the Winsock 1.1
 *  declarations and leaves the socket backends with two incompatible definitions of each. */
#if UCALL_OS_WINDOWS_
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#endif // UCALL_OS_WINDOWS_

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

    /** Stopping runs on any thread, so it touches only these CPU-independent words. */
    std::uint32_t stopped {};
    std::span<uc::wake_channel_t*> wakeups {}; // Every event loop's, then every batch endpoint's.
    struct api_t {
        void (*free)(ucall_server_t);
        void (*take_call)(ucall_server_take_call_t*);
        void (*take_calls)(ucall_server_take_calls_t*);
        void (*event_loop_statistics)(ucall_server_event_loop_statistics_t*);
        void (*take_batch)(ucall_server_take_batch_t*);
        void (*take_batches)(ucall_server_take_batches_t*);
        void (*batch_endpoint_statistics)(ucall_server_batch_endpoint_statistics_t*);
        void (*add_http_endpoint)(ucall_server_add_http_endpoint_t*);
        ucall_verb_t (*request_verb)(ucall_server_t, ucall_received_http_request_t);
        void (*request_path)(ucall_server_request_path_t*);
        std::size_t (*request_path_segments_count)(ucall_server_t, ucall_received_http_request_t);
        void (*request_path_segment)(ucall_server_request_path_segment_t*);
        void (*request_path_parameter)(ucall_server_request_path_parameter_t*);
        void (*request_query_parameter)(ucall_server_request_query_parameter_t*);
        void (*request_header)(ucall_server_request_header_t*);
        void (*request_peer)(ucall_server_request_peer_t*);
        void (*request_body)(ucall_server_request_body_t*);
        void (*reply_content)(ucall_server_reply_content_t*);
        void (*reply_error)(ucall_server_reply_error_t*);
        void (*add_http_batch_endpoint)(ucall_server_add_http_batch_endpoint_t*);
        void (*reply_vectored)(ucall_server_reply_vectored_t*);
        void (*reply_begin)(ucall_server_reply_begin_t*);
        void (*reply_append)(ucall_server_reply_append_t*);
        void (*reply_end)(ucall_server_reply_end_t*);
        void (*request_body_chunk)(ucall_server_request_body_chunk_t*);
        std::size_t (*request_parts_count)(ucall_server_t, ucall_received_http_request_t);
        void (*request_part)(ucall_server_request_part_t*);
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
    };
    api_t const* api {};
    std::uint64_t string_capabilities {}, atomic_capabilities {};
};
struct ucall_received_http_request_handle_t {};
struct ucall_http_batch_endpoint_handle_t {};
struct ucall_received_http_response_handle_t {};

namespace unum::ucall {
using server_api_t = ucall_server_handle_t::api_t;
using client_api_t = ucall_client_handle_t::api_t;

inline void publish(ucall_outcome_t* outcome, ucall_status_t status, char const* message) noexcept {
    if (!outcome) return;
    outcome->message = status == ucall_status_success_k ? nullptr : message;
    std::atomic_ref<ucall_status_t> word {outcome->status};
    word.store(status, std::memory_order_release);
    word.notify_all();
}
inline void publish(ucall_outcome_t* outcome, ucall_status_t status) noexcept {
    publish(outcome, status, ucall_status_name(status));
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
    ~pool() noexcept = default;

    [[nodiscard]] ucall_status_t reserve(std::size_t count) noexcept {
        assert(elements_.empty());
        decltype(elements_) elements {elements_.get_allocator()};
        decltype(free_offsets_) offsets {free_offsets_.get_allocator()};
        if (st::failed(elements.resize(count)) || st::failed(offsets.resize(count)))
            return ucall_status_out_of_memory_k;
        std::iota(offsets.begin(), offsets.end(), std::size_t {0});
        elements_ = std::move(elements);
        free_offsets_ = std::move(offsets);
        free_count_ = count;
        return ucall_status_success_k;
    }
    element_t* alloc() noexcept { return free_count_ ? elements_.data() + free_offsets_[--free_count_] : nullptr; }
    void release(element_t* released) noexcept {
        assert(contains(released) && free_count_ < elements_.size());
        free_offsets_[free_count_++] = static_cast<std::size_t>(released - elements_.data());
    }
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

  public:
    using element_t = element_type_;
    using value_type = element_t;

    /**
     *  @brief Constructs with initial pool capacity.
     *  @param[in] initial_capacity Number of elements in first pool (default 100).
     */
    explicit successive_pools(std::size_t initial_capacity = 100, allocator_type_ const& allocator = {}) noexcept
        : allocator_(allocator), initial_capacity_(initial_capacity) {}

    successive_pools(successive_pools const&) = delete;
    successive_pools& operator=(successive_pools const&) = delete;

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
            if (elem) return elem;
        }

        // All pools exhausted - grow
        std::size_t new_capacity = head_ ? head_->capacity_ * 2 : initial_capacity_;
        if (grow(new_capacity) != ucall_status_success_k) return nullptr;

        // Try allocation from newly created pool
        return head_->pool_.alloc();
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
                return;
            }
        }

        assert(false && "successive_pools::release() pointer not from this pool");
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
    }

  private:

    /**
     *  @brief Grows pool list by adding a new pool at the head.
     *  @param[in] capacity Capacity for the new pool.
     *  @return @c ucall_status_out_of_memory_k when the pool or its storage cannot be allocated.
     */
    [[nodiscard]] ucall_status_t grow(std::size_t capacity) noexcept {
        auto owned = allocate_unique<pool_node_t>(allocator_, capacity, allocator_);
        auto* new_node = owned.get();
        if (!new_node) return ucall_status_out_of_memory_k;

        // Reserve the pool capacity
        if (ucall_status_t const reserved = new_node->pool_.reserve(capacity); reserved != ucall_status_success_k)
            return reserved;

        // Prepend to linked list (newest first)
        new_node->next_ = head_;
        head_ = owned.release();

        return ucall_status_success_k;
    }
};

template <typename element_type_, std::size_t extent_ = std::dynamic_extent>
using span = std::span<element_type_, extent_>;

/** The C view of @p text, borrowing its bytes. */
inline ucall_bytes_view_t bytes_view(std::string_view text) noexcept {
    return {reinterpret_cast<ucall_byte_t const*>(text.data()), text.size()};
}

/** The text a C view holds, borrowing its bytes; empty for a null view. */
inline std::string_view text_view(ucall_bytes_view_t bytes) noexcept {
    return bytes.length ? std::string_view {reinterpret_cast<char const*>(bytes.data), bytes.length}
                        : std::string_view {};
}

/** The text @p bytes spell, borrowing them. */
inline std::string_view text_view(span<byte_t const> bytes) noexcept {
    return {reinterpret_cast<char const*>(bytes.data()), bytes.size()};
}

/** The bytes of @p text, as engines and tunnels take their input. */
inline span<byte_t const> byte_span(std::string_view text) noexcept { return std::as_bytes(std::span {text}); }

} // namespace unum::ucall
