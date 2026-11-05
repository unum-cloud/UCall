/**
 *  @file include/ucall/tunnel/curve25519.hpp
 *  @author Ash Vardanian
 *  @date August 4, 2026
 *  @brief Curve25519 scalar multiplication, the one Noise primitive with no home elsewhere.
 *
 *  @section Why Vendored
 *
 *  AES-256-GCM and SHA-256 belong in StringZilla - they are byte-stream transforms with the same
 *  hardware-dispatch story as everything else there. Curve25519 is not. A field element is one
 *  255-bit number spread across five or four limbs with carries flowing between them, which is a
 *  serial dependency chain rather than the lane-parallel work a string library is built for. It is
 *  also the one primitive where the compiler must be held back rather than let loose: a
 *  secret-dependent branch or table index here is a key-recovery bug, so the implementation needs
 *  constant-time discipline that sits badly beside code compiled for maximum throughput.
 *
 *  So it lives in one translation unit rather than a dependency, with the field arithmetic
 *  transcribed from a machine-verified implementation - fiat-crypto's generated C carries a proof
 *  of both functional correctness and constant-time behaviour, and is what BoringSSL and NSS ship.
 *  A subtly wrong field multiply still produces a shared secret that looks random.
 *
 *  @section Tiers
 *
 *  Three field backends, chosen at runtime. @c saturated is four saturated limbs in plain C++ and
 *  runs wherever this file compiles; @c radix51 is five limbs over 128-bit products, so it needs @c
 *  __int128 ; @c adx is @c saturated recompiled with @c target("adx,bmi2") , which lets the
 *  compiler emit @c MULX and makes it illegal on x86-64 without BMI2.
 *
 *  @c saturated is the baseline and carries no switch: one that can be compiled out is not a
 *  baseline. The two switches follow StringZilla's @c SZ_USE_* - always defined to 1 or 0, so @c
 *  \#if never reads an undefined identifier as zero and silently drops a tier.
 *
 *  @section Cost
 *
 *  One scalar multiplication is on the order of 100'000 cycles, and a Noise XX handshake needs four
 *  per side. That cost is @b per @b handshake, unlike AES-GCM which is per byte, so it disappears
 *  entirely under connection reuse and dominates under connection churn. An x86-64 path compiled to
 *  @c MULX carry chains ships as @c x25519_scalar_multiply_adx, selected at runtime. The remaining
 *  levers, worth measuring before pulling: the hand-scheduled @c ADCX / @c ADOX dual-chain assembly
 *  BoringSSL ships, which no compiler synthesizes from C, then batching independent handshakes
 *  across AVX-512IFMA lanes.
 */
#pragma once

#include <cstdint> // `std::uint8_t`

#include "ucall/utilities/types.hpp" // `span`, `byte_t`

namespace unum::ucall::tunnel {

using utilities::byte_t;
using utilities::span;

/** Length of a Curve25519 scalar, public key, or shared secret, in bytes. */
static constexpr std::size_t x25519_key_size_k = 32;

/**
 *  @brief Bitmask over the field-arithmetic tiers this library knows about.
 *
 *  A bitmask rather than one enumerator per tier because the useful questions are about sets: which
 *  tiers a build contains, which this machine favours, and which one it therefore picked.
 */
enum class x25519_tiers_t : std::uint8_t {
    none_k = 0,

    /** Four limbs over a multiply built from 32-bit products. Always compiled, always runs. */
    serial_k = 1u << 0,

    /** Five limbs over 128-bit products. Faster than @c serial_k wherever it compiles. */
    radix51_k = 1u << 1,

    /** Four limbs built for ADX and BMI2, so it runs only where CPUID reports them. */
    adx_k = 1u << 2,
};

[[nodiscard]] constexpr x25519_tiers_t operator&(x25519_tiers_t left, x25519_tiers_t right) noexcept {
    return static_cast<x25519_tiers_t>(static_cast<std::uint8_t>(left) & static_cast<std::uint8_t>(right));
}

/** Whether @p available contains every tier in @p wanted. */
[[nodiscard]] constexpr bool x25519_has_tiers(x25519_tiers_t available, x25519_tiers_t wanted) noexcept {
    return (available & wanted) == wanted;
}

/** The tiers this build compiled in. @c serial_k carries no switch and is always among them. */
[[nodiscard]] constexpr x25519_tiers_t x25519_tiers_compiled() noexcept {
    return static_cast<x25519_tiers_t>(static_cast<std::uint8_t>(x25519_tiers_t::serial_k) |
                                       static_cast<std::uint8_t>(x25519_tiers_t::radix51_k) * UCALL_COMPILER_INT128_ |
                                       static_cast<std::uint8_t>(x25519_tiers_t::adx_k) * UCALL_ARCH_X8664_ADX_);
}

/**
 *  @brief The tiers this machine can execute, whatever was compiled.
 *
 *  Only @c adx_k is conditional. The other two hold no instruction a supported CPU can lack.
 */
[[nodiscard]] x25519_tiers_t x25519_tiers_runtime() noexcept;

/** The tiers both compiled in and runnable here. Never empty: @c saturated_k is in both. */
[[nodiscard]] inline x25519_tiers_t x25519_tiers() noexcept { return x25519_tiers_compiled() & x25519_tiers_runtime(); }

/**
 *  @brief The single tier @c x25519_scalar_multiply dispatches to on this machine.
 *
 *  Exposed because a benchmark that does not name the tier it measured is unreadable, and a test
 *  cross-checking tiers has to know which one the dispatcher already covered.
 */
[[nodiscard]] x25519_tiers_t x25519_tier_preferred() noexcept;

/** Names one tier, for diagnostics. Answers @c "none" for a mask with no bits set. */
[[nodiscard]] char const* x25519_tier_name(x25519_tiers_t tier) noexcept;

/**
 *  @brief Computes @p out = @p scalar * @p point on Curve25519, per RFC 7748 §5.
 *  @param[out] out The 32-byte result. For key generation this is a public key; for Diffie-Hellman
 *      it is the shared secret.
 *  @param[in] scalar The 32-byte secret scalar. Clamped internally, so callers may pass raw random
 *      bytes.
 *  @param[in] point The 32-byte u-coordinate of the peer's point.
 *  @return False when the result is the all-zero value, which indicates a small-order input point
 *      and must abort the handshake rather than continue with a known secret.
 *
 *  @warning Must execute in time independent of @p scalar. Any implementation swapped in here has
 *      to preserve that - it is the whole reason this primitive is isolated.
 */
[[nodiscard]] bool x25519_scalar_multiply(        //
    span<byte_t, x25519_key_size_k> out,          //
    span<byte_t const, x25519_key_size_k> scalar, //
    span<byte_t const, x25519_key_size_k> point) noexcept;

/** Baseline tier of @c x25519_scalar_multiply. Always built, and runs on any supported CPU. */
[[nodiscard]] bool x25519_scalar_multiply_serial( //
    span<byte_t, x25519_key_size_k> out,          //
    span<byte_t const, x25519_key_size_k> scalar, //
    span<byte_t const, x25519_key_size_k> point) noexcept;

#if UCALL_COMPILER_INT128_

/** Radix-51 tier of @c x25519_scalar_multiply. Needs 128-bit integers, so absent under MSVC. */
[[nodiscard]] bool x25519_scalar_multiply_radix51( //
    span<byte_t, x25519_key_size_k> out,           //
    span<byte_t const, x25519_key_size_k> scalar,  //
    span<byte_t const, x25519_key_size_k> point) noexcept;
#endif

#if UCALL_ARCH_X8664_ADX_

/** ADX tier of @c x25519_scalar_multiply. Faults where @c x25519_tiers_runtime omits it. */
[[nodiscard]] bool x25519_scalar_multiply_adx(    //
    span<byte_t, x25519_key_size_k> out,          //
    span<byte_t const, x25519_key_size_k> scalar, //
    span<byte_t const, x25519_key_size_k> point) noexcept;
#endif

/**
 *  @brief Derives the public key matching @p scalar, multiplying by the standard base point.
 *  @param[out] out The 32-byte public key.
 *  @param[in] scalar The 32-byte secret scalar.
 */
void x25519_derive_public(               //
    span<byte_t, x25519_key_size_k> out, //
    span<byte_t const, x25519_key_size_k> scalar) noexcept;

} // namespace unum::ucall::tunnel
