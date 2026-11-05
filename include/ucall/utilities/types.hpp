/**
 *  @file include/ucall/utilities/types.hpp
 *  @author Ash Vardanian
 *  @date January 18, 2023
 *  @brief Platform identities, byte views, and fallible storage primitives.
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

/*  128-bit products for radix-51 limbs; MSVC has no `__int128`. */
#if !defined(UCALL_COMPILER_INT128_)
#if defined(__SIZEOF_INT128__)
#define UCALL_COMPILER_INT128_ 1
#else
#define UCALL_COMPILER_INT128_ 0
#endif // defined(__SIZEOF_INT128__)
#endif // !defined(UCALL_COMPILER_INT128_)

/*  ADX and BMI2 recompiles need the target attribute GCC and Clang accept. */
#if !defined(UCALL_ARCH_X8664_ADX_)
#if (UCALL_COMPILER_GCC_ || UCALL_COMPILER_CLANG_) && UCALL_ARCH_X8664_
#define UCALL_ARCH_X8664_ADX_ 1
#else
#define UCALL_ARCH_X8664_ADX_ 0
#endif // (UCALL_COMPILER_GCC_ || UCALL_COMPILER_CLANG_) && UCALL_ARCH_X8664_
#endif // !defined(UCALL_ARCH_X8664_ADX_)

#define UCALL_OS_POSIX_ (UCALL_OS_LINUX_ || UCALL_OS_APPLE_ || UCALL_OS_FREEBSD_)

#if !defined(UCALL_WITH_LINUX_URING)
#define UCALL_WITH_LINUX_URING 0
#endif // !defined(UCALL_WITH_LINUX_URING)

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
#include <smashtable/basic_fixed_pool.hpp>
#include <smashtable/basic_vector.hpp>
#include <stringzilla/capabilities.h>

#include "ucall/ucall.h" // `ucall_callback_t`

namespace unum::ucall {
namespace fu = ashvardanian::forkunion;
namespace st = ashvardanian::smashtable;
} // namespace unum::ucall
namespace uc = unum::ucall;

namespace unum::ucall::utilities {

/** What one server or client may use: the StringZilla kernels its kits run and the ForkUnion
 *  atomics it synchronizes with, picked once at init. */
struct cpu_ceiling_t {
    sz_capability_t compute = sz_cap_serial_k;
    fu::capabilities_t sync = fu::capabilities_unknown_k;
};

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

/** The one final write to @p outcome: the message, then the status its waiters acquire; waiters
 *  watch the address, so the store notifies nothing. */
template <template <typename> class atomic_ref_template_>
inline void publish(ucall_outcome_t* outcome, ucall_status_t status, char const* message) noexcept {
    if (!outcome) return;
    outcome->message = status == ucall_status_success_k ? nullptr : message;
    atomic_ref_template_<ucall_status_t> {outcome->status}.store(status, std::memory_order_release);
}
template <template <typename> class atomic_ref_template_>
inline void publish(ucall_outcome_t* outcome, ucall_status_t status) noexcept {
    publish<atomic_ref_template_>(outcome, status, ucall_status_name(status));
}

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

} // namespace unum::ucall::utilities

namespace unum::ucall {

/*  The views, descriptors, outcomes, allocations and CPU ceilings every folder and the entry
 *  points share. */
using utilities::byte_span;
using utilities::byte_t;
using utilities::bytes_view;
using utilities::cpu_ceiling_t;
using utilities::descriptor_t;
using utilities::span;
using utilities::text_view;

} // namespace unum::ucall
