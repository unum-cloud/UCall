/**
 *  @file src/lib.hpp
 *  @author Ash Vardanian
 *  @date August 15, 2023
 *  @brief CPU classes, the kits and atomic references each one picks, and the ladder descended once
 *      while constructing a server or client.
 */
#pragma once

#include <type_traits>

#include <smashtable/row_search.hpp>

#include "ucall/ucall.h"
#include "ucall/utilities/types.hpp" // `cpu_ceiling_t`, `publish`
#include "ucall/http/messages.hpp"   // `compare_kit`, `find_kit`, `byteset_kit`, `hash_kit`, `fold_kit`
#include "ucall/http/percent.hpp"    // `percent_kit`
#include "ucall/tunnel/crypto.hpp"   // `sha256_kit`, `aes256_gcm_kit`

namespace unum::ucall {

/** Classes name distinct kernel bundles rather than every combination of feature flags. */
enum class cpu_class_t : std::uint32_t {
    unknown_k,
    serial_k,
    intel_haswell_k,
    intel_skylake_k,
    intel_icelake_k,
    intel_alder_k,
    aws_g2_k,
    aws_g5_k,
    monoversioned_k,
};

constexpr cpu_class_t parent_class_of(cpu_class_t cpu) noexcept {
    switch (cpu) {
    case cpu_class_t::intel_alder_k: return cpu_class_t::intel_haswell_k;
    case cpu_class_t::intel_icelake_k: return cpu_class_t::intel_skylake_k;
    case cpu_class_t::intel_skylake_k: return cpu_class_t::intel_haswell_k;
    case cpu_class_t::aws_g5_k: return cpu_class_t::aws_g2_k;
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
        return stringzilla_capabilities_of(cpu_class_t::intel_haswell_k) | sz_cap_goldmont_k;
    case cpu_class_t::aws_g2_k:
    case cpu_class_t::aws_g5_k: return sz_cap_serial_k | sz_cap_neon_k | sz_cap_neonaes_k | sz_cap_neonsha_k;
    case cpu_class_t::monoversioned_k: return sz_capabilities_compiled_cpu_mask();
    default: return sz_cap_serial_k;
    }
}

template <cpu_class_t cpu_class_>
struct atomic_ref_for_cpu_class {
    template <typename value_type_>
    using type = fu::standard_atomic_ref<value_type_>;
};
#if FORKUNION_TARGET_ARM64_LSE
template <>
struct atomic_ref_for_cpu_class<cpu_class_t::aws_g2_k> {
    template <typename value_type_>
    using type = fu::arm64_lse_atomic_ref<value_type_>;
};
#endif
#if FORKUNION_TARGET_ARM64_RCPC
template <>
struct atomic_ref_for_cpu_class<cpu_class_t::aws_g5_k> {
    template <typename value_type_>
    using type = fu::arm64_rcpc_atomic_ref<value_type_>;
};
#elif FORKUNION_TARGET_ARM64_LSE
template <>
struct atomic_ref_for_cpu_class<cpu_class_t::aws_g5_k> {
    template <typename value_type_>
    using type = fu::arm64_lse_atomic_ref<value_type_>;
};
#endif
#if UCALL_TARGET_MONOVERSIONED
template <>
struct atomic_ref_for_cpu_class<cpu_class_t::monoversioned_k> {
    template <typename value_type_>
    using type = fu::preferred_atomic_ref<value_type_>;
};
#endif

/** The row kit one CPU class compares index keys with, serial wherever its
 *  @c SMASHTABLE_TARGET_<KIT> is off. */
template <cpu_class_t cpu_class_>
struct row_kit_for_cpu_class {
    using type = st::serial_row_kit_t;
};
#if SMASHTABLE_TARGET_HASWELL
template <>
struct row_kit_for_cpu_class<cpu_class_t::intel_haswell_k> {
    using type = st::haswell_row_kit_t;
};
template <>
struct row_kit_for_cpu_class<cpu_class_t::intel_alder_k> {
    using type = st::haswell_row_kit_t;
};
#endif
#if SMASHTABLE_TARGET_SKYLAKE
template <>
struct row_kit_for_cpu_class<cpu_class_t::intel_skylake_k> {
    using type = st::skylake_row_kit_t;
};
#endif
#if SMASHTABLE_TARGET_ICELAKE
template <>
struct row_kit_for_cpu_class<cpu_class_t::intel_icelake_k> {
    using type = st::icelake_row_kit_t;
};
#endif
#if SMASHTABLE_TARGET_NEON
template <>
struct row_kit_for_cpu_class<cpu_class_t::aws_g2_k> {
    using type = st::neon_row_kit_t;
};
template <>
struct row_kit_for_cpu_class<cpu_class_t::aws_g5_k> {
    using type = st::neon_row_kit_t;
};
#endif
#if UCALL_TARGET_MONOVERSIONED
template <>
struct row_kit_for_cpu_class<cpu_class_t::monoversioned_k> {
    using type = st::native_row_kit_t;
};
#endif

/** The wait instruction one CPU class pairs: x86 spins on PAUSE, the Graviton2 class spins on YIELD
 *  and the Graviton5 class sleeps in WFE, a monoversioned build takes its target's pick, and
 *  everything else yields, as does any class whose @c FORKUNION_TARGET_<BIT> is off, such as in
 *  builds under ThreadSanitizer. */
template <cpu_class_t cpu_class_>
struct waiter_for_cpu_class {
    using type = fu::standard_yield_t;
};
#if FORKUNION_TARGET_X86_PAUSE
template <>
struct waiter_for_cpu_class<cpu_class_t::intel_haswell_k> {
    using type = fu::x86_pause_t;
};
template <>
struct waiter_for_cpu_class<cpu_class_t::intel_skylake_k> {
    using type = fu::x86_pause_t;
};
template <>
struct waiter_for_cpu_class<cpu_class_t::intel_icelake_k> {
    using type = fu::x86_pause_t;
};
template <>
struct waiter_for_cpu_class<cpu_class_t::intel_alder_k> {
    using type = fu::x86_pause_t;
};
#endif
#if FORKUNION_TARGET_ARM64_YIELD
template <>
struct waiter_for_cpu_class<cpu_class_t::aws_g2_k> {
    using type = fu::arm64_yield_t;
};
#endif
#if FORKUNION_TARGET_ARM64_WFE
template <>
struct waiter_for_cpu_class<cpu_class_t::aws_g5_k> {
    using type = fu::arm64_wfe_t;
};
#endif
#if UCALL_TARGET_MONOVERSIONED
template <>
struct waiter_for_cpu_class<cpu_class_t::monoversioned_k> {
    using type = fu::preferred_yield_t;
};
#endif

/** The kits, atomic reference and waiter one CPU class builds its network from. */
template <cpu_class_t cpu_class_>
struct cpu_traits {
    static constexpr sz_capability_t stringzilla_capabilities_k = stringzilla_capabilities_of(cpu_class_) &
                                                                  sz_capabilities_compiled_cpu_mask();
    using compare_kit_t = http::compare_kit<stringzilla_capabilities_k>;
    using find_kit_t = http::find_kit<stringzilla_capabilities_k>;
    using byteset_kit_t = http::byteset_kit<stringzilla_capabilities_k>;
    using hash_kit_t = http::hash_kit<stringzilla_capabilities_k>;
    using fold_kit_t = http::fold_kit<stringzilla_capabilities_k>;
    using percent_kit_t = http::percent_kit<stringzilla_capabilities_k>;
    using sha256_kit_t = tunnel::sha256_kit<stringzilla_capabilities_k>;
    using aes256_gcm_kit_t = tunnel::aes256_gcm_kit<stringzilla_capabilities_k>;
    using row_search_kit_t = typename row_kit_for_cpu_class<cpu_class_>::type;
    using waiter_t = typename waiter_for_cpu_class<cpu_class_>::type;

    template <typename value_type_>
    using atomic_ref = typename atomic_ref_for_cpu_class<cpu_class_>::template type<value_type_>;

    static constexpr fu::capabilities_t forkunion_capabilities_k = atomic_ref<std::uint32_t>::capabilities_k;
};

template <cpu_class_t cpu_class_>
constexpr fu::capabilities_t forkunion_capabilities_of() noexcept {
    return cpu_traits<cpu_class_>::forkunion_capabilities_k;
}

constexpr bool cpu_class_compiled(cpu_class_t cpu) noexcept {
    switch (cpu) {
#if UCALL_TARGET_SERIAL
    case cpu_class_t::serial_k: return true;
#endif
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
#if UCALL_TARGET_AWS_G2
    case cpu_class_t::aws_g2_k: return true;
#endif
#if UCALL_TARGET_AWS_G5
    case cpu_class_t::aws_g5_k: return true;
#endif
#if UCALL_TARGET_MONOVERSIONED
    case cpu_class_t::monoversioned_k: return true;
#endif
    default: return false;
    }
}

/** Only a different picked kit, atomic reference or waiter earns another instantiation, or a parent
 *  the build left out, as a monoversioned build leaves serial. */
template <cpu_class_t cpu_class_>
constexpr bool rung_advances() noexcept {
    using own_t = cpu_traits<cpu_class_>;
    using parent_t = cpu_traits<parent_class_of(cpu_class_)>;
    return cpu_class_ == cpu_class_t::serial_k || !cpu_class_compiled(parent_class_of(cpu_class_)) ||
           !std::is_same_v<typename own_t::compare_kit_t, typename parent_t::compare_kit_t> ||
           !std::is_same_v<typename own_t::find_kit_t, typename parent_t::find_kit_t> ||
           !std::is_same_v<typename own_t::byteset_kit_t, typename parent_t::byteset_kit_t> ||
           !std::is_same_v<typename own_t::hash_kit_t, typename parent_t::hash_kit_t> ||
           !std::is_same_v<typename own_t::fold_kit_t, typename parent_t::fold_kit_t> ||
           !std::is_same_v<typename own_t::sha256_kit_t, typename parent_t::sha256_kit_t> ||
           !std::is_same_v<typename own_t::aes256_gcm_kit_t, typename parent_t::aes256_gcm_kit_t> ||
           !std::is_same_v<typename own_t::row_search_kit_t, typename parent_t::row_search_kit_t> ||
           !std::is_same_v<typename own_t::waiter_t, typename parent_t::waiter_t> ||
           !std::is_same_v<typename own_t::template atomic_ref<std::uint32_t>,
                           typename parent_t::template atomic_ref<std::uint32_t>>;
}

/** ForkUnion's mask for a class named at run time, as a pinned class names it. */
constexpr fu::capabilities_t forkunion_capabilities_of(cpu_class_t cpu) noexcept {
    switch (cpu) {
    case cpu_class_t::intel_haswell_k: return forkunion_capabilities_of<cpu_class_t::intel_haswell_k>();
    case cpu_class_t::intel_skylake_k: return forkunion_capabilities_of<cpu_class_t::intel_skylake_k>();
    case cpu_class_t::intel_icelake_k: return forkunion_capabilities_of<cpu_class_t::intel_icelake_k>();
    case cpu_class_t::intel_alder_k: return forkunion_capabilities_of<cpu_class_t::intel_alder_k>();
    case cpu_class_t::aws_g2_k: return forkunion_capabilities_of<cpu_class_t::aws_g2_k>();
    case cpu_class_t::aws_g5_k: return forkunion_capabilities_of<cpu_class_t::aws_g5_k>();
    case cpu_class_t::monoversioned_k: return forkunion_capabilities_of<cpu_class_t::monoversioned_k>();
    default: return forkunion_capabilities_of<cpu_class_t::serial_k>();
    }
}

/** Whether @p rung fits under @p ceiling: its compiled string kernels and its atomic reference's
 *  entire mask, so RCpc with LSE, need nothing the ceiling lacks. */
constexpr bool cpu_rung_fits(cpu_class_t rung, cpu_ceiling_t ceiling) noexcept {
    sz_capability_t const strings = stringzilla_capabilities_of(rung) & sz_capabilities_compiled_cpu_mask();
    return (strings & ~ceiling.compute) == 0 && (forkunion_capabilities_of(rung) & ~ceiling.sync) == 0;
}

/** What one server or client may use: the masks this machine runs when nothing is pinned, the
 *  pinned class's masks when it runs them, refusing a class it does not and a ceiling no compiled
 *  class fits, like one below a monoversioned build's masks. The one caller of StringZilla's and
 *  ForkUnion's detection. */
inline ucall_status_t pick_cpu_ceiling(ucall_cpu_class_t pinned, cpu_ceiling_t& ceiling) noexcept {
    cpu_ceiling_t picked;
    if (sz_capabilities_detected_cpu(&picked.compute) != sz_success_k) picked.compute = sz_cap_serial_k;
    picked.sync = fu::cpu_capabilities();
    if (pinned != ucall_cpu_class_unknown_k) {
        if (pinned > ucall_cpu_class_monoversioned_k) return ucall_status_unsupported_k;
        cpu_class_t const pinned_class = static_cast<cpu_class_t>(pinned);
        cpu_ceiling_t const wanted {stringzilla_capabilities_of(pinned_class), forkunion_capabilities_of(pinned_class)};
        if ((picked.compute & wanted.compute) != wanted.compute || (picked.sync & wanted.sync) != wanted.sync)
            return ucall_status_unsupported_k;
        picked = wanted;
    }
    for (auto rung = ucall_cpu_class_serial_k; rung <= ucall_cpu_class_monoversioned_k;
         rung = static_cast<ucall_cpu_class_t>(rung + 1))
        if (cpu_class_compiled(static_cast<cpu_class_t>(rung)) &&
            cpu_rung_fits(static_cast<cpu_class_t>(rung), picked)) {
            ceiling = picked;
            return ucall_status_success_k;
        }
    return ucall_status_unsupported_k;
}

template <cpu_class_t cpu_class_, typename init_type_>
void make_network_variant(init_type_* arguments) noexcept;

/** CPU classes newest first, the order a ladder tries them in. */
template <cpu_class_t... classes_>
struct cpu_ladder {};

/** The classes carrying variants, each lineage newest first and the serial floor last; a rung the
 *  build left out is skipped by the walk, never by the list. A monoversioned build carries one. */
#if UCALL_TARGET_MONOVERSIONED
using cpu_ladder_t = cpu_ladder<cpu_class_t::monoversioned_k>;
#else
using cpu_ladder_t =
    cpu_ladder<cpu_class_t::intel_icelake_k, cpu_class_t::intel_skylake_k, cpu_class_t::intel_alder_k,
               cpu_class_t::intel_haswell_k, cpu_class_t::aws_g5_k, cpu_class_t::aws_g2_k, cpu_class_t::serial_k>;
#endif

/** Builds the network on the newest rung of @p ladder the build compiled and @p ceiling fits, one
 *  of which @ref pick_cpu_ceiling made sure of, and a class picking its parent's kits and atomics
 *  is skipped without instantiating its variant. */
template <cpu_class_t... classes_, typename init_type_>
void make_network(cpu_ladder<classes_...>, init_type_* arguments, cpu_ceiling_t ceiling) noexcept {
    bool picked = false;
    auto rung = [&]<cpu_class_t class_>() noexcept {
        if constexpr (cpu_class_compiled(class_) && rung_advances<class_>())
            if (!picked && cpu_rung_fits(class_, ceiling)) picked = true, make_network_variant<class_>(arguments);
    };
    (rung.template operator()<classes_>(), ...);
}

/** The class-free entry points' verbs, lowered onto one CPU class: the outcome word through its
 *  reference and waiter, and the percent codec through its kit. */
struct host_verbs_t {
    void (*publish)(ucall_outcome_t*, ucall_status_t, char const*) noexcept;
    ucall_status_t (*load)(ucall_outcome_t const*) noexcept;

    /** Loops on the class waiter while the status reads deferred. */
    ucall_status_t (*wait)(ucall_outcome_t const*) noexcept;

    ucall_status_t (*decode_percent)(ucall_bytes_view_t, ucall_byte_t*, std::size_t*, ucall_percent_mode_t) noexcept;
};

template <cpu_class_t cpu_class_>
host_verbs_t host_verbs_of() noexcept {
    using traits_t = cpu_traits<cpu_class_>;
    using status_reader_t = typename traits_t::template atomic_ref<ucall_status_t const>;
    using wait_t = typename traits_t::waiter_t;
    return {
        [](ucall_outcome_t* outcome, ucall_status_t status, char const* message) noexcept {
            utilities::publish<traits_t::template atomic_ref>(outcome, status, message);
        },
        [](ucall_outcome_t const* outcome) noexcept {
            return status_reader_t {outcome->status}.load(std::memory_order_acquire);
        },
        [](ucall_outcome_t const* outcome) noexcept {
            status_reader_t const status {outcome->status};
            ucall_status_t seen = status.load(std::memory_order_acquire);
            // One word wakes the monitor, so the wait needs no timeout to notice the publish.
            for (; seen == ucall_status_deferred_k; seen = status.load(std::memory_order_acquire))
                wait_t {}(&outcome->status, seen, 0u, fu::wait_uncapped_k);
            return seen;
        },
        &traits_t::percent_kit_t::decode,
    };
}

/** The row of the newest class this machine admits, picked once by the ladder walk. */
inline host_verbs_t const& host_verbs() noexcept {
    static host_verbs_t const picked = []<cpu_class_t... classes_>(cpu_ladder<classes_...>) noexcept {
        cpu_ceiling_t ceiling {};
        if (pick_cpu_ceiling(ucall_cpu_class_unknown_k, ceiling) != ucall_status_success_k) ceiling = {};
        host_verbs_t row = host_verbs_of<cpu_class_t::serial_k>();
        bool found = false;
        auto rung = [&]<cpu_class_t class_>() noexcept {
            if constexpr (cpu_class_compiled(class_))
                if (!found && cpu_rung_fits(class_, ceiling)) row = host_verbs_of<class_>(), found = true;
        };
        (rung.template operator()<classes_>(), ...);
        return row;
    }(cpu_ladder_t {});
    return picked;
}

/** Publishes from the class-free entry points through the host's row. */
inline void publish(ucall_outcome_t* outcome, ucall_status_t status) noexcept {
    host_verbs().publish(outcome, status, ucall_status_name(status));
}

} // namespace unum::ucall
