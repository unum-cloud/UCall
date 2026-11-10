/**
 *  @file src/variants.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief CPU-specific server and client construction over the enabled native I/O engines.
 */
#pragma once

#include "ucall/io/bsd_kqueue_engine.hpp"     // `bsd_kqueue_engine_t`
#include "ucall/io/linux_epollaio_engine.hpp" // `linux_epollaio_engine_t`
#include "ucall/io/posix_engine.hpp"          // `posix_engine_t`
#include "ucall/io/types.hpp"                 // `io_engine_variant`
#include "ucall/io/windows_iocp_engine.hpp"   // `windows_iocp_engine_t`
#include "ucall/io/windows_rio_engine.hpp"    // `windows_rio_engine_t`
#include "ucall/network.hpp"                  // `network_variant`
#if UCALL_WITH_LINUX_URING
#include "ucall/io/linux_uring612_engine.hpp" // `linux_uring612_engine_t`
#include "ucall/io/linux_uring618_engine.hpp" // `linux_uring618_engine_t`
#endif
#include "lib.hpp"

namespace unum::ucall {

/** The engines of every set in @p sets_, in order, as one @c io_engine_variant. */
template <typename... sets_>
struct joined_engines;

template <typename... engine_types_>
struct joined_engines<io::io_engine_variant<engine_types_...>> {
    using type = io::io_engine_variant<engine_types_...>;
};

template <typename... first_types_, typename... second_types_, typename... sets_>
struct joined_engines<io::io_engine_variant<first_types_...>, io::io_engine_variant<second_types_...>, sets_...> {
    using type = typename joined_engines<io::io_engine_variant<first_types_..., second_types_...>, sets_...>::type;
};

/*  Each facility contributes its engines, or none where the build leaves it out. */
#if UCALL_WITH_LINUX_URING
using uring_engines_t = io::io_engine_variant<io::linux_uring618_engine_t, io::linux_uring612_engine_t>;
#else
using uring_engines_t = io::io_engine_variant<>;
#endif // UCALL_WITH_LINUX_URING
#if UCALL_WITH_LINUX_EPOLLAIO
using epollaio_engines_t = io::io_engine_variant<io::linux_epollaio_engine_t>;
#else
using epollaio_engines_t = io::io_engine_variant<>;
#endif // UCALL_WITH_LINUX_EPOLLAIO
#if UCALL_WITH_BSD_KQUEUE
using kqueue_engines_t = io::io_engine_variant<io::bsd_kqueue_engine_t>;
#else
using kqueue_engines_t = io::io_engine_variant<>;
#endif // UCALL_WITH_BSD_KQUEUE
#if UCALL_WITH_WINDOWS_RIO
using rio_engines_t = io::io_engine_variant<io::windows_rio_engine_t>;
#else
using rio_engines_t = io::io_engine_variant<>;
#endif // UCALL_WITH_WINDOWS_RIO
#if UCALL_WITH_WINDOWS_IOCP
using iocp_engines_t = io::io_engine_variant<io::windows_iocp_engine_t>;
#else
using iocp_engines_t = io::io_engine_variant<>;
#endif // UCALL_WITH_WINDOWS_IOCP
#if UCALL_WITH_POSIX
using posix_engines_t = io::io_engine_variant<io::posix_engine_t>;
#else
using posix_engines_t = io::io_engine_variant<>;
#endif // UCALL_WITH_POSIX

/** Every engine this build compiled, in the order an automatic open tries them: the 6.18 ring
 *  first, the portable engine last. */
using io_engines_t = typename joined_engines<uring_engines_t, epollaio_engines_t, kqueue_engines_t, rio_engines_t,
                                             iocp_engines_t, posix_engines_t>::type;

template <cpu_class_t cpu_class_, typename init_type_>
void make_network_variant(init_type_* arguments) noexcept {
    using traits_t = cpu_traits<cpu_class_>;
    using network_t = network::network_variant<
        io_engines_t, atomic_ref_for_cpu_class<cpu_class_>::template type, typename traits_t::waiter_t,
        typename traits_t::compare_kit_t, typename traits_t::find_kit_t, typename traits_t::byteset_kit_t,
        typename traits_t::hash_kit_t, typename traits_t::fold_kit_t, typename traits_t::sha256_kit_t,
        typename traits_t::aes256_gcm_kit_t, typename traits_t::x25519_kit_t, typename traits_t::row_search_kit_t>;
    // The network reports the class it was built for, which only this layer names.
    auto options = *arguments->options;
    options.cpu_class = static_cast<ucall_cpu_class_t>(cpu_class_);
    auto forwarded = *arguments;
    forwarded.options = &options;
    if constexpr (std::is_same_v<init_type_, ucall_server_init_t>) network_t::server_t::server_init(&forwarded);
    else network_t::client_t::client_init(&forwarded);
}

} // namespace unum::ucall
