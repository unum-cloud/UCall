/**
 *  @brief Curve25519 scalar multiplication, the one Noise primitive with no home elsewhere.
 *
 *  @section Why Vendored
 *
 *  AES-256-GCM and SHA-256 belong in StringZilla - they are byte-stream transforms with the
 *  same hardware-dispatch story as everything else there. Curve25519 is not. A field element
 *  is one 255-bit number spread across five or four limbs with carries flowing between them,
 *  which is a serial dependency chain rather than the lane-parallel work a string library is
 *  built for. It is also the one primitive where the compiler must be held back rather than
 *  let loose: a secret-dependent branch or table index here is a key-recovery bug, so the
 *  implementation needs constant-time discipline that sits badly beside code compiled for
 *  maximum throughput.
 *
 *  So it lives in one translation unit rather than a dependency, with the field arithmetic
 *  transcribed from a machine-verified implementation - fiat-crypto's generated C carries a
 *  proof of both functional correctness and constant-time behaviour, and is what BoringSSL
 *  and NSS ship. A subtly wrong field multiply still produces a shared secret that looks
 *  random.
 *
 *  @section Cost
 *
 *  One scalar multiplication is on the order of 100'000 cycles, and a Noise XX handshake
 *  needs four per side. That cost is @b per @b handshake, unlike AES-GCM which is per byte,
 *  so it disappears entirely under connection reuse and dominates under connection churn.
 *  An x86-64 path compiled to @c MULX carry chains ships as @c x25519_scalar_multiply_adx,
 *  selected at runtime. The remaining levers, worth measuring before pulling: the
 *  hand-scheduled @c ADCX / @c ADOX dual-chain assembly BoringSSL ships, which no compiler
 *  synthesizes from C, then batching independent handshakes across AVX-512IFMA lanes.
 *
 *  @file src/crypto_x25519.hpp
 *  @author Ash Vardanian
 */
#pragma once

#include <cstdint> // `std::uint8_t`

namespace unum::ucall {

/** @brief Length of a Curve25519 scalar, public key, or shared secret, in bytes. */
static constexpr std::size_t x25519_key_size_k = 32;

/**
 *  @brief Computes @p out = @p scalar * @p point on Curve25519, per RFC 7748 §5.
 *  @param[out] out The 32-byte result. For key generation this is a public key; for
 *    Diffie-Hellman it is the shared secret.
 *  @param[in] scalar The 32-byte secret scalar. Clamped internally, so callers may pass
 *    raw random bytes.
 *  @param[in] point The 32-byte u-coordinate of the peer's point.
 *  @return False when the result is the all-zero value, which indicates a small-order
 *    input point and must abort the handshake rather than continue with a known secret.
 *
 *  @warning Must execute in time independent of @p scalar. Any implementation swapped in
 *    here has to preserve that - it is the whole reason this primitive is isolated.
 */
[[nodiscard]] bool x25519_scalar_multiply(        //
    std::uint8_t out[x25519_key_size_k],          //
    std::uint8_t const scalar[x25519_key_size_k], //
    std::uint8_t const point[x25519_key_size_k]) noexcept;

/** @brief Radix-51 tier of @c x25519_scalar_multiply. Needs 128-bit integers, so absent under MSVC. */
[[nodiscard]] bool x25519_scalar_multiply_serial( //
    std::uint8_t out[x25519_key_size_k],          //
    std::uint8_t const scalar[x25519_key_size_k], //
    std::uint8_t const point[x25519_key_size_k]) noexcept;

/** @brief Saturated 4-limb tier of @c x25519_scalar_multiply, compiled to MULX carry chains on x86-64. */
[[nodiscard]] bool x25519_scalar_multiply_adx(    //
    std::uint8_t out[x25519_key_size_k],          //
    std::uint8_t const scalar[x25519_key_size_k], //
    std::uint8_t const point[x25519_key_size_k]) noexcept;

/**
 *  @brief Derives the public key matching @p scalar, multiplying by the standard base point.
 *  @param[out] out The 32-byte public key.
 *  @param[in] scalar The 32-byte secret scalar.
 */
void x25519_derive_public(               //
    std::uint8_t out[x25519_key_size_k], //
    std::uint8_t const scalar[x25519_key_size_k]) noexcept;

} // namespace unum::ucall
