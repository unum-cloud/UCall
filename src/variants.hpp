/**
 *  @file src/variants.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief CPU-specific server and client construction over the enabled native I/O queues.
 */
#pragma once

#include "ucall/io/bsd_kqueue_queue.hpp"     // `bsd_kqueue_queue_t`
#include "ucall/io/linux_epollaio_queue.hpp" // `linux_epollaio_queue_t`
#include "ucall/io/posix_queue.hpp"          // `posix_queue_t`
#include "ucall/io/types.hpp"                // `io_queue_variant`
#include "ucall/io/windows_iocp_queue.hpp"   // `windows_iocp_queue_t`
#include "ucall/io/windows_rio_queue.hpp"    // `windows_rio_queue_t`
#include "ucall/network.hpp"                 // `network_variant`
#if UCALL_WITH_LINUX_URING
#include "ucall/io/linux_uring612_queue.hpp" // `linux_uring612_queue_t`
#include "ucall/io/linux_uring618_queue.hpp" // `linux_uring618_queue_t`
#endif
#include "lib.hpp"

namespace unum::ucall {

/** The queues of every set in @p sets_, in order, as one @c io_queue_variant. */
template <typename... sets_>
struct joined_queues;

template <typename... queue_types_>
struct joined_queues<io::io_queue_variant<queue_types_...>> {
    using type = io::io_queue_variant<queue_types_...>;
};

template <typename... first_types_, typename... second_types_, typename... sets_>
struct joined_queues<io::io_queue_variant<first_types_...>, io::io_queue_variant<second_types_...>, sets_...> {
    using type = typename joined_queues<io::io_queue_variant<first_types_..., second_types_...>, sets_...>::type;
};

/*  Each facility contributes its queues, or none where the build leaves it out. */
#if UCALL_WITH_LINUX_URING
using uring_queues_t = io::io_queue_variant<io::linux_uring618_queue_t, io::linux_uring612_queue_t>;
#else
using uring_queues_t = io::io_queue_variant<>;
#endif // UCALL_WITH_LINUX_URING
#if UCALL_WITH_LINUX_EPOLLAIO
using epollaio_queues_t = io::io_queue_variant<io::linux_epollaio_queue_t>;
#else
using epollaio_queues_t = io::io_queue_variant<>;
#endif // UCALL_WITH_LINUX_EPOLLAIO
#if UCALL_WITH_BSD_KQUEUE
using kqueue_queues_t = io::io_queue_variant<io::bsd_kqueue_queue_t>;
#else
using kqueue_queues_t = io::io_queue_variant<>;
#endif // UCALL_WITH_BSD_KQUEUE
#if UCALL_WITH_WINDOWS_RIO
using rio_queues_t = io::io_queue_variant<io::windows_rio_queue_t>;
#else
using rio_queues_t = io::io_queue_variant<>;
#endif // UCALL_WITH_WINDOWS_RIO
#if UCALL_WITH_WINDOWS_IOCP
using iocp_queues_t = io::io_queue_variant<io::windows_iocp_queue_t>;
#else
using iocp_queues_t = io::io_queue_variant<>;
#endif // UCALL_WITH_WINDOWS_IOCP
#if UCALL_WITH_POSIX
using posix_queues_t = io::io_queue_variant<io::posix_queue_t>;
#else
using posix_queues_t = io::io_queue_variant<>;
#endif // UCALL_WITH_POSIX

/** Every queue this build compiled, in the order an automatic open tries them: the 6.18 ring
 *  first, the portable queue last. */
using io_queues_t = typename joined_queues<uring_queues_t, epollaio_queues_t, kqueue_queues_t, rio_queues_t,
                                           iocp_queues_t, posix_queues_t>::type;

template <cpu_class_t cpu_class_, typename init_type_>
void make_network_variant(init_type_* arguments) noexcept {
    using traits_t = cpu_traits<cpu_class_>;
    using network_t = network::network_variant<
        io_queues_t, atomic_ref_for_cpu_class<cpu_class_>::template type, typename traits_t::waiter_t,
        typename traits_t::compare_kit_t, typename traits_t::find_kit_t, typename traits_t::byteset_kit_t,
        typename traits_t::hash_kit_t, typename traits_t::fold_kit_t, typename traits_t::sha256_kit_t,
        typename traits_t::aes256_gcm_kit_t, typename traits_t::x25519_kit_t, typename traits_t::row_search_kit_t>;
    // The network reports the class it was built for, which only this layer names.
    auto options = *arguments->options;
    options.cpu_class_ceiling = static_cast<ucall_cpu_class_t>(cpu_class_);
    auto forwarded = *arguments;
    forwarded.options = &options;
    if constexpr (std::is_same_v<init_type_, ucall_server_init_t>) network_t::server_t::server_init(&forwarded);
    else network_t::client_t::client_init(&forwarded);
}

} // namespace unum::ucall
