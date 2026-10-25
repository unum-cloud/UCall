/**
 *  @file src/variants.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief CPU-specific server and client construction over the enabled native I/O engines.
 */
#pragma once

#include "ucall/network.hpp"
#include "lib.hpp"

namespace unum::ucall {

template <typename engine_type_, cpu_class_t cpu_class_, typename init_type_>
void make_network_for_engine(init_type_* arguments) noexcept {
    using traits_t = cpu_traits<cpu_class_>;
    using network_t =
        network_variant<engine_type_, atomic_ref_for_cpu_class<cpu_class_>::template type,
                        typename traits_t::compare_kit_t, typename traits_t::find_kit_t,
                        typename traits_t::byteset_kit_t, typename traits_t::hash_kit_t, typename traits_t::fold_kit_t,
                        typename traits_t::sha256_kit_t, typename traits_t::aes256_gcm_kit_t>;
    // The network reports the class it was built for, which only this layer names.
    auto config = *arguments->config;
    config.cpu_class = static_cast<ucall_cpu_class_t>(cpu_class_);
    auto forwarded = *arguments;
    forwarded.config = &config;
    if constexpr (std::is_same_v<init_type_, ucall_server_init_t>) network_t::server_init(&forwarded);
    else network_t::client_init(&forwarded);
}

template <cpu_class_t cpu_class_, typename init_type_>
void make_network_variant(init_type_* arguments) noexcept {
    switch (arguments->config->backend) {
#if UCALL_WITH_POSIX
    case ucall_io_backend_posix_k: return make_network_for_engine<posix_engine_t, cpu_class_>(arguments);
#endif
#if UCALL_WITH_LINUX_EPOLL
    case ucall_io_backend_linux_epoll_k: return make_network_for_engine<linux_epoll_engine_t, cpu_class_>(arguments);
#endif
#if UCALL_WITH_LINUX_URING
    case ucall_io_backend_linux_uring612_k:
        return make_network_for_engine<linux_uring612_engine_t, cpu_class_>(arguments);
#endif
#if UCALL_WITH_LINUX_URING
    case ucall_io_backend_linux_uring700_k:
        return make_network_for_engine<linux_uring700_engine_t, cpu_class_>(arguments);
#endif
#if UCALL_WITH_KQUEUE
    case ucall_io_backend_macos_kqueue_k: return make_network_for_engine<kqueue_engine_t, cpu_class_>(arguments);
#endif
#if UCALL_WITH_IOCP
    case ucall_io_backend_windows_iocp_k: return make_network_for_engine<windows_iocp_engine_t, cpu_class_>(arguments);
#endif
    default: publish(arguments->outcome, ucall_status_unsupported_k); return;
    }
}

} // namespace unum::ucall
