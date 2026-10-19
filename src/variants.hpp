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
    if constexpr (std::is_same_v<init_type_, ucall_server_init_t>)
        network_variant<engine_type_, cpu_class_>::server_init(arguments);
    else network_variant<engine_type_, cpu_class_>::client_init(arguments);
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
