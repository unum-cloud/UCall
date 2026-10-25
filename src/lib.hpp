/**
 *  @file src/lib.hpp
 *  @author Ash Vardanian
 *  @date August 15, 2023
 *  @brief CPU classes, the kits and atomic references each one picks, and the ladder descended once
 *      while constructing a server or client.
 */
#pragma once

#include <type_traits>

#include "ucall/ucall.h"
#include "ucall/types.hpp"
#include "ucall/http.hpp"
#include "ucall/tunnel.hpp"

namespace unum::ucall {

/** Classes name distinct kernel bundles rather than every combination of feature flags. */
enum class cpu_class_t : std::uint32_t {
    unknown_k,
    serial_k,
    intel_haswell_k,
    intel_skylake_k,
    intel_icelake_k,
    intel_alder_k,
    intel_sierra_k,
    aws_g2_k,
    apple_m2_k,
    aws_g5_k,
};

constexpr cpu_class_t parent_class_of(cpu_class_t cpu) noexcept {
    switch (cpu) {
    case cpu_class_t::intel_sierra_k: return cpu_class_t::intel_alder_k;
    case cpu_class_t::intel_alder_k: return cpu_class_t::intel_haswell_k;
    case cpu_class_t::intel_icelake_k: return cpu_class_t::intel_skylake_k;
    case cpu_class_t::intel_skylake_k: return cpu_class_t::intel_haswell_k;
    case cpu_class_t::aws_g5_k: return cpu_class_t::apple_m2_k;
    case cpu_class_t::apple_m2_k: return cpu_class_t::aws_g2_k;
    default: return cpu_class_t::serial_k;
    }
}

constexpr sz_capability_t stringzilla_capabilities_of(cpu_class_t cpu) noexcept {
    switch (cpu) {
    case cpu_class_t::intel_haswell_k: return sz_cap_serial_k | sz_cap_haswell_k | sz_cap_westmere_k;
    case cpu_class_t::intel_skylake_k:
        return stringzilla_capabilities_of(cpu_class_t::intel_haswell_k) | sz_cap_skylake_k;
    case cpu_class_t::intel_icelake_k:
        return stringzilla_capabilities_of(cpu_class_t::intel_skylake_k) | sz_cap_icelake_k | sz_cap_goldmont_k;
    case cpu_class_t::intel_alder_k:
    case cpu_class_t::intel_sierra_k:
        return stringzilla_capabilities_of(cpu_class_t::intel_haswell_k) | sz_cap_goldmont_k;
    case cpu_class_t::aws_g2_k:
    case cpu_class_t::apple_m2_k: return sz_cap_serial_k | sz_cap_neon_k | sz_cap_neonaes_k | sz_cap_neonsha_k;
    case cpu_class_t::aws_g5_k:
        return stringzilla_capabilities_of(cpu_class_t::apple_m2_k) | sz_cap_sve_k | sz_cap_sve2_k | sz_cap_sve2aes_k;
    default: return sz_cap_serial_k;
    }
}

template <cpu_class_t cpu_class_>
struct atomic_ref_for_cpu_class {
    template <typename value_type_>
    using type = fu::standard_atomic_ref<value_type_>;
};
#if FORKUNION_TARGET_X86_CMPCCXADD
template <>
struct atomic_ref_for_cpu_class<cpu_class_t::intel_sierra_k> {
    template <typename value_type_>
    using type = fu::x86_cmpccxadd_atomic_ref<value_type_>;
};
#endif
#if FORKUNION_TARGET_ARM64_LSE
template <>
struct atomic_ref_for_cpu_class<cpu_class_t::aws_g2_k> {
    template <typename value_type_>
    using type = fu::arm64_lse_atomic_ref<value_type_>;
};
#endif
#if FORKUNION_TARGET_ARM64_RCPC
template <>
struct atomic_ref_for_cpu_class<cpu_class_t::apple_m2_k> {
    template <typename value_type_>
    using type = fu::arm64_rcpc_atomic_ref<value_type_>;
};
#else
template <>
struct atomic_ref_for_cpu_class<cpu_class_t::apple_m2_k> : atomic_ref_for_cpu_class<cpu_class_t::aws_g2_k> {};
#endif
template <>
struct atomic_ref_for_cpu_class<cpu_class_t::aws_g5_k> : atomic_ref_for_cpu_class<cpu_class_t::apple_m2_k> {};

/** The kits and atomic reference one CPU class builds its network from, each picked once here. */
template <cpu_class_t cpu_class_>
struct cpu_traits {
    static constexpr sz_capability_t stringzilla_capabilities_k = stringzilla_capabilities_of(cpu_class_) &
                                                                  sz_capabilities_compiled_cpu_();
    using compare_kit_t = compare_kit<stringzilla_capabilities_k>;
    using find_kit_t = find_kit<stringzilla_capabilities_k>;
    using byteset_kit_t = byteset_kit<stringzilla_capabilities_k>;
    using hash_kit_t = hash_kit<stringzilla_capabilities_k>;
    using fold_kit_t = fold_kit<stringzilla_capabilities_k>;
    using sha256_kit_t = sha256_kit<stringzilla_capabilities_k>;
    using aes256_gcm_kit_t = aes256_gcm_kit<stringzilla_capabilities_k>;

    template <typename value_type_>
    using atomic_ref = typename atomic_ref_for_cpu_class<cpu_class_>::template type<value_type_>;

    static constexpr fu::capabilities_t forkunion_capabilities_k = atomic_ref<std::uint32_t>::capabilities_k;
};

template <cpu_class_t cpu_class_>
constexpr fu::capabilities_t forkunion_capabilities_of() noexcept {
    return cpu_traits<cpu_class_>::forkunion_capabilities_k;
}

/** Only a different picked kit or atomic reference earns another instantiation. */
template <cpu_class_t cpu_class_>
constexpr bool rung_advances() noexcept {
    using own_t = cpu_traits<cpu_class_>;
    using parent_t = cpu_traits<parent_class_of(cpu_class_)>;
    return cpu_class_ == cpu_class_t::serial_k ||
           !std::is_same_v<typename own_t::compare_kit_t, typename parent_t::compare_kit_t> ||
           !std::is_same_v<typename own_t::find_kit_t, typename parent_t::find_kit_t> ||
           !std::is_same_v<typename own_t::byteset_kit_t, typename parent_t::byteset_kit_t> ||
           !std::is_same_v<typename own_t::hash_kit_t, typename parent_t::hash_kit_t> ||
           !std::is_same_v<typename own_t::fold_kit_t, typename parent_t::fold_kit_t> ||
           !std::is_same_v<typename own_t::sha256_kit_t, typename parent_t::sha256_kit_t> ||
           !std::is_same_v<typename own_t::aes256_gcm_kit_t, typename parent_t::aes256_gcm_kit_t> ||
           !std::is_same_v<typename own_t::template atomic_ref<std::uint32_t>,
                           typename parent_t::template atomic_ref<std::uint32_t>>;
}

constexpr bool cpu_class_compiled(cpu_class_t cpu) noexcept {
    switch (cpu) {
    case cpu_class_t::serial_k: return true;
#if UCALL_TARGET_INTEL_HASWELL
    case cpu_class_t::intel_haswell_k: return true;
#endif
#if UCALL_TARGET_INTEL_SKYLAKE
    case cpu_class_t::intel_skylake_k: return true;
#endif
#if UCALL_TARGET_INTEL_ICELAKE
    case cpu_class_t::intel_icelake_k: return true;
#endif
#if UCALL_TARGET_INTEL_ALDER
    case cpu_class_t::intel_alder_k: return true;
#endif
#if UCALL_TARGET_INTEL_SIERRA
    case cpu_class_t::intel_sierra_k: return true;
#endif
#if UCALL_TARGET_AWS_G2
    case cpu_class_t::aws_g2_k: return true;
#endif
#if UCALL_TARGET_APPLE_M2
    case cpu_class_t::apple_m2_k: return true;
#endif
#if UCALL_TARGET_AWS_G5
    case cpu_class_t::aws_g5_k: return true;
#endif
    default: return false;
    }
}

/** Reads the reference's entire mask, so RCpc also requires LSE. */
template <cpu_class_t cpu_class_>
constexpr bool cpu_class_admits(sz_capability_t strings, fu::capabilities_t atomics) noexcept {
    constexpr auto string_mask = cpu_traits<cpu_class_>::stringzilla_capabilities_k;
    constexpr auto atomic_mask = forkunion_capabilities_of<cpu_class_>();
    return (strings & string_mask) == string_mask && (atomics & atomic_mask) == atomic_mask;
}

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
