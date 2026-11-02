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
#else
#include <pthread.h>
#endif // UCALL_OS_WINDOWS_

#include <forkunion/atomics.hpp>
#include <forkunion/capabilities.hpp>
#include <smashtable/basic_slot_pool.hpp>
#include <smashtable/basic_vector.hpp>
#include <stringzilla/capabilities.h>

#include "ucall/ucall.h" // `ucall_callback_t`

namespace unum::ucall {
namespace fu = ashvardanian::forkunion;
struct wake_channel_t;

/** What one server or client may use: the StringZilla kernels its kits run and the ForkUnion
 *  atomics it synchronizes with, picked once at init. */
struct cpu_ceiling_t {
    sz_capability_t compute = sz_cap_serial_k;
    fu::capabilities_t sync = fu::capabilities_unknown_k;
};
} // namespace unum::ucall
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
    uc::cpu_ceiling_t ceiling;
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
    uc::cpu_ceiling_t ceiling;
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

static_assert(st::cache_line_bytes_k == fu::default_alignment_k,
              "SMASHTABLE_DEFAULT_ALIGNMENT and FORKUNION_DEFAULT_ALIGNMENT disagree");

/** A native socket descriptor; Winsock handles require pointer width. A polling thread names
 *  itself by the identity its platform reads without entering the kernel; zero names no thread. */
#if UCALL_OS_WINDOWS_
using descriptor_t = std::intptr_t;
using polling_thread_t = DWORD;
inline polling_thread_t current_polling_thread() noexcept { return GetCurrentThreadId(); }
inline bool is_current_thread(polling_thread_t thread) noexcept { return thread == GetCurrentThreadId(); }
#else
using descriptor_t = int;
using polling_thread_t = pthread_t;
inline polling_thread_t current_polling_thread() noexcept { return pthread_self(); }
inline bool is_current_thread(polling_thread_t thread) noexcept { return pthread_equal(thread, pthread_self()); }
#endif

/**
 *  @brief Growable pool allocator with pointer stability guarantee.
 *
 *  Manages a linked list of fixed-size slot pools. When a pool is exhausted, allocates a new pool
 *  at 2x the previous capacity. Pointers remain valid for the lifetime of the successive_pools
 *  instance since individual pools are never reallocated.
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
 *  @code{.cpp}
 * successive_pools<connection_t> conn_pools(100);
 * connection_t* conn = conn_pools.alloc();  // Auto-grows if needed
 * if (conn) { conn->reset(); conn_pools.release(conn); }
 *  @endcode
 */
template <typename element_type_, typename allocator_type_ = st::default_allocator<element_type_>>
class successive_pools {
    using bytes_allocator_t = typename std::allocator_traits<allocator_type_>::template rebind_alloc<byte_t>;
    using slot_pool_t = st::basic_slot_pool<element_type_, std::uint32_t, bytes_allocator_t>;

    struct pool_node_t {
        slot_pool_t pool_;

        /** Singly linked list, newer pools first. */
        pool_node_t* next_ {};

        explicit pool_node_t(slot_pool_t&& pool) noexcept : pool_(std::move(pool)) {}
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
     *  @param[in] allocator Allocator the pools draw from.
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
        for (pool_node_t* node = head_; node != nullptr; node = node->next_)
            if (std::uint32_t const index = node->pool_.take(); index != slot_pool_t::absent_k)
                return &node->pool_[index];

        // All pools exhausted - grow
        std::size_t new_capacity = head_ ? head_->pool_.capacity() * 2 : initial_capacity_;
        if (grow(new_capacity) != ucall_status_success_k) return nullptr;

        // Try allocation from newly created pool
        std::uint32_t const index = head_->pool_.take();
        return index != slot_pool_t::absent_k ? &head_->pool_[index] : nullptr;
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
            std::span<element_t const> const records = node->pool_.records();
            if (released >= records.data() && released < records.data() + records.size()) {
                node->pool_.vacate(node->pool_.index_of(*released));
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
        st::expected<slot_pool_t> made = slot_pool_t::make(capacity, bytes_allocator_t {allocator_});
        if (!made) return ucall_status_out_of_memory_k;
        auto owned = allocate_unique<pool_node_t>(allocator_, std::move(*made));
        auto* new_node = owned.get();
        if (!new_node) return ucall_status_out_of_memory_k;

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
