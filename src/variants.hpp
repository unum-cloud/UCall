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
#include "ucall/io/windows_iocp_engine.hpp"   // `windows_iocp_engine_t`
#include "ucall/network.hpp"                  // `network_variant`
#if UCALL_WITH_LINUX_URING
#include "ucall/io/linux_uring612_engine.hpp" // `linux_uring612_engine_t`
#include "ucall/io/linux_uring618_engine.hpp" // `linux_uring618_engine_t`
#endif
#include "lib.hpp"

namespace unum::ucall {

template <typename engine_type_, cpu_class_t cpu_class_, typename init_type_>
void make_network_for_engine(init_type_* arguments) noexcept {
    using traits_t = cpu_traits<cpu_class_>;
    using network_t = network::network_variant<
        engine_type_, atomic_ref_for_cpu_class<cpu_class_>::template type, typename traits_t::waiter_t,
        typename traits_t::compare_kit_t, typename traits_t::find_kit_t, typename traits_t::byteset_kit_t,
        typename traits_t::hash_kit_t, typename traits_t::fold_kit_t, typename traits_t::sha256_kit_t,
        typename traits_t::aes256_gcm_kit_t, typename traits_t::row_search_kit_t>;
    // The network reports the class it was built for, which only this layer names.
    auto options = *arguments->options;
    options.cpu_class = static_cast<ucall_cpu_class_t>(cpu_class_);
    auto forwarded = *arguments;
    forwarded.options = &options;
    if constexpr (std::is_same_v<init_type_, ucall_server_init_t>) network_t::server_t::server_init(&forwarded);
    else network_t::client_t::client_init(&forwarded);
}

template <cpu_class_t cpu_class_, typename init_type_>
void make_network_variant(init_type_* arguments) noexcept {
    switch (arguments->options->backend) {
#if UCALL_WITH_POSIX
    case ucall_io_backend_posix_k: return make_network_for_engine<io::posix_engine_t, cpu_class_>(arguments);
#endif
#if UCALL_WITH_LINUX_EPOLLAIO
    case ucall_io_backend_linux_epollaio_k:
        return make_network_for_engine<io::linux_epollaio_engine_t, cpu_class_>(arguments);
#endif
#if UCALL_WITH_LINUX_URING
    case ucall_io_backend_linux_uring612_k:
        return make_network_for_engine<io::linux_uring612_engine_t, cpu_class_>(arguments);
#endif
#if UCALL_WITH_LINUX_URING
    case ucall_io_backend_linux_uring618_k:
        return make_network_for_engine<io::linux_uring618_engine_t, cpu_class_>(arguments);
#endif
#if UCALL_WITH_KQUEUE
    case ucall_io_backend_bsd_kqueue_k: return make_network_for_engine<io::bsd_kqueue_engine_t, cpu_class_>(arguments);
#endif
#if UCALL_WITH_IOCP
    case ucall_io_backend_windows_iocp_k:
        return make_network_for_engine<io::windows_iocp_engine_t, cpu_class_>(arguments);
#endif
    default: publish(arguments->outcome, ucall_status_unsupported_k); return;
    }
}

} // namespace unum::ucall
