/**
 *  @file src/lib.hpp
 *  @author Ash Vardanian
 *  @date August 15, 2023
 *  @brief Descends the compiled CPU ladder once while constructing a server or client.
 */
#pragma once

#include "ucall/ucall.h"
#include "ucall/capabilities.hpp"
#include "ucall/types.hpp"

namespace unum::ucall {

template <cpu_class_t cpu_class_, typename init_type_>
void make_network_variant(init_type_* arguments) noexcept;

extern template void make_network_variant<cpu_class_t::serial_k>(ucall_server_init_t*) noexcept;
extern template void make_network_variant<cpu_class_t::serial_k>(ucall_client_init_t*) noexcept;
#if UCALL_TARGET_INTEL_HASWELL
extern template void make_network_variant<cpu_class_t::intel_haswell_k>(ucall_server_init_t*) noexcept;
extern template void make_network_variant<cpu_class_t::intel_haswell_k>(ucall_client_init_t*) noexcept;
#endif
#if UCALL_TARGET_INTEL_SKYLAKE
extern template void make_network_variant<cpu_class_t::intel_skylake_k>(ucall_server_init_t*) noexcept;
extern template void make_network_variant<cpu_class_t::intel_skylake_k>(ucall_client_init_t*) noexcept;
#endif
#if UCALL_TARGET_INTEL_ICELAKE
extern template void make_network_variant<cpu_class_t::intel_icelake_k>(ucall_server_init_t*) noexcept;
extern template void make_network_variant<cpu_class_t::intel_icelake_k>(ucall_client_init_t*) noexcept;
#endif
#if UCALL_TARGET_INTEL_ALDER
extern template void make_network_variant<cpu_class_t::intel_alder_k>(ucall_server_init_t*) noexcept;
extern template void make_network_variant<cpu_class_t::intel_alder_k>(ucall_client_init_t*) noexcept;
#endif
#if UCALL_TARGET_INTEL_SIERRA
extern template void make_network_variant<cpu_class_t::intel_sierra_k>(ucall_server_init_t*) noexcept;
extern template void make_network_variant<cpu_class_t::intel_sierra_k>(ucall_client_init_t*) noexcept;
#endif
#if UCALL_TARGET_AWS_G2
extern template void make_network_variant<cpu_class_t::aws_g2_k>(ucall_server_init_t*) noexcept;
extern template void make_network_variant<cpu_class_t::aws_g2_k>(ucall_client_init_t*) noexcept;
#endif
#if UCALL_TARGET_APPLE_M2
extern template void make_network_variant<cpu_class_t::apple_m2_k>(ucall_server_init_t*) noexcept;
extern template void make_network_variant<cpu_class_t::apple_m2_k>(ucall_client_init_t*) noexcept;
#endif
#if UCALL_TARGET_AWS_G5
extern template void make_network_variant<cpu_class_t::aws_g5_k>(ucall_server_init_t*) noexcept;
extern template void make_network_variant<cpu_class_t::aws_g5_k>(ucall_client_init_t*) noexcept;
#endif

template <cpu_class_t cpu_class_, typename init_type_>
bool make_network_for_cpu(init_type_* arguments, sz_capability_t strings, fu::capabilities_t atomics) noexcept {
    if constexpr (cpu_class_compiled(cpu_class_) && rung_advances<cpu_class_>()) {
        if (cpu_class_admits<cpu_class_>(strings, atomics)) {
            make_network_variant<cpu_class_>(arguments);
            return true;
        }
    }
    return false;
}

template <cpu_class_t head_, cpu_class_t... tail_, typename init_type_>
void descend_network_ladder(init_type_* arguments, sz_capability_t strings, fu::capabilities_t atomics) noexcept {
    if (make_network_for_cpu<head_>(arguments, strings, atomics)) return;
    if constexpr (sizeof...(tail_)) descend_network_ladder<tail_...>(arguments, strings, atomics);
    else publish(arguments->outcome, ucall_status_unsupported_k);
}

template <typename init_type_>
void descend_x86_ladder(init_type_* arguments, sz_capability_t strings, fu::capabilities_t atomics) noexcept {
    descend_network_ladder<cpu_class_t::intel_sierra_k, cpu_class_t::intel_icelake_k, cpu_class_t::intel_skylake_k,
                           cpu_class_t::intel_alder_k, cpu_class_t::intel_haswell_k, cpu_class_t::serial_k>(
        arguments, strings, atomics);
}

template <typename init_type_>
void descend_arm_ladder(init_type_* arguments, sz_capability_t strings, fu::capabilities_t atomics) noexcept {
    descend_network_ladder<cpu_class_t::aws_g5_k, cpu_class_t::apple_m2_k, cpu_class_t::aws_g2_k,
                           cpu_class_t::serial_k>(arguments, strings, atomics);
}

template <typename init_type_>
void make_network(init_type_* arguments, sz_capability_t strings, fu::capabilities_t atomics) noexcept {
    if (!arguments) return;
    strings &= sz_capabilities_compiled_cpu_();
    if (arguments->config->cpu_class == ucall_cpu_class_unknown_k) {
#if STRINGZILLA_ARCH_X8664_
        descend_x86_ladder(arguments, strings, atomics);
#elif STRINGZILLA_ARCH_ARM64_
        descend_arm_ladder(arguments, strings, atomics);
#else
        descend_network_ladder<cpu_class_t::serial_k>(arguments, strings, atomics);
#endif
        return;
    }
    switch (static_cast<cpu_class_t>(arguments->config->cpu_class)) {
    case cpu_class_t::serial_k:
        if (make_network_for_cpu<cpu_class_t::serial_k>(arguments, strings, atomics)) return;
        break;
    case cpu_class_t::intel_haswell_k:
        if (make_network_for_cpu<cpu_class_t::intel_haswell_k>(arguments, strings, atomics)) return;
        break;
    case cpu_class_t::intel_skylake_k:
        if (make_network_for_cpu<cpu_class_t::intel_skylake_k>(arguments, strings, atomics)) return;
        break;
    case cpu_class_t::intel_icelake_k:
        if (make_network_for_cpu<cpu_class_t::intel_icelake_k>(arguments, strings, atomics)) return;
        break;
    case cpu_class_t::intel_alder_k:
        if (make_network_for_cpu<cpu_class_t::intel_alder_k>(arguments, strings, atomics)) return;
        break;
    case cpu_class_t::intel_sierra_k:
        if (make_network_for_cpu<cpu_class_t::intel_sierra_k>(arguments, strings, atomics)) return;
        break;
    case cpu_class_t::aws_g2_k:
        if (make_network_for_cpu<cpu_class_t::aws_g2_k>(arguments, strings, atomics)) return;
        break;
    case cpu_class_t::apple_m2_k:
        if (make_network_for_cpu<cpu_class_t::apple_m2_k>(arguments, strings, atomics)) return;
        break;
    case cpu_class_t::aws_g5_k:
        if (make_network_for_cpu<cpu_class_t::aws_g5_k>(arguments, strings, atomics)) return;
        break;
    default: break;
    }
    publish(arguments->outcome, ucall_status_unsupported_k);
}

} // namespace unum::ucall
