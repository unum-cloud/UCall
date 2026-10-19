/**
 *  @file include/ucall/capabilities.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief CPU classes and the string, cryptographic, and atomic kernels each class can use.
 */
#pragma once

#include <cstdint>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#endif // defined(_WIN32)

#include <type_traits>

#include <forkunion/atomics.hpp>
#include <forkunion/capabilities.hpp>
#include <stringzilla/capabilities.h>

namespace unum::ucall {

namespace fu = ashvardanian::forkunion;

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

template <cpu_class_t cpu_class_>
struct cpu_traits {
    static constexpr sz_capability_t stringzilla_capabilities_k = stringzilla_capabilities_of(cpu_class_) &
                                                                  sz_capabilities_compiled_cpu_();

    template <typename value_type_>
    using atomic_ref = typename atomic_ref_for_cpu_class<cpu_class_>::template type<value_type_>;

    static constexpr fu::capabilities_t forkunion_capabilities_k = atomic_ref<std::uint32_t>::capabilities_k;
};

template <cpu_class_t cpu_class_>
constexpr fu::capabilities_t forkunion_capabilities_of() noexcept {
    return cpu_traits<cpu_class_>::forkunion_capabilities_k;
}

/** Only a different compiled kernel or atomic reference earns another instantiation. */
template <cpu_class_t cpu_class_>
constexpr bool rung_advances() noexcept {
    constexpr auto parent = parent_class_of(cpu_class_);
    return cpu_class_ == cpu_class_t::serial_k ||
           cpu_traits<cpu_class_>::stringzilla_capabilities_k != cpu_traits<parent>::stringzilla_capabilities_k ||
           !std::is_same_v<typename cpu_traits<cpu_class_>::template atomic_ref<std::uint32_t>,
                           typename cpu_traits<parent>::template atomic_ref<std::uint32_t>>;
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

} // namespace unum::ucall
