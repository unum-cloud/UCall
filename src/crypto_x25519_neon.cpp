/**
 *  @file src/crypto_x25519_neon.cpp
 *  @author Ash Vardanian
 *  @date August 4, 2026
 *  @brief The Arm X25519 kit: saturated limbs over @c UMULH with @c ADCS chains.
 *
 *  It runs no vector instruction. It sits on the NEON rung because that rung is every Arm64 core,
 *  and its flags reach this unit alone. Four 64-bit limbs take 16 partial products per multiply
 *  against radix-51's 25, and Clang fuses the carries below into flag chains.
 *
 *  GCC 15 does not: it materializes every carry with @c CSET, which costs more than the products
 *  saved, so under GCC this unit keeps the radix-51 field, whose carries are shifts.
 */
#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h> // `__umulh`
#endif

#include "crypto_x25519_radix51.hpp" // `field_radix51`, which includes the saturated field

namespace unum::ucall {

bool tunnel::x25519_multiply_neon(span<byte_t, x25519_key_size_k> out, span<byte_t const, x25519_key_size_k> scalar,
                                  span<byte_t const, x25519_key_size_k> point) noexcept {
    struct neon_words_t {
        [[gnu::always_inline]] static void fiat_mulx_u64(std::uint64_t* out1, std::uint64_t* out2, std::uint64_t arg1,
                                                         std::uint64_t arg2) noexcept {
#if defined(_MSC_VER) && !defined(__clang__)
            *out1 = arg1 * arg2, *out2 = __umulh(arg1, arg2);
#else
            *out1 = arg1 * arg2;
            __asm__("umulh %x0, %x1, %x2" : "=r"(*out2) : "r"(arg1), "r"(arg2));
#endif
        }

        /** Two adds and two compares, which Clang fuses into one @c ADCS on the chain's flags. */
        [[gnu::always_inline]] static void fiat_addcarryx_u64(std::uint64_t* out1, fiat_25519_uint1_t* out2,
                                                              fiat_25519_uint1_t arg1, std::uint64_t arg2,
                                                              std::uint64_t arg3) noexcept {
            std::uint64_t const summed = arg2 + arg3, carried_in = summed + arg1;
            *out1 = carried_in, *out2 = (summed < arg2) | (carried_in < summed);
        }

        /** The subtracting twin, fused into one @c SBCS. */
        [[gnu::always_inline]] static void fiat_subborrowx_u64(std::uint64_t* out1, fiat_25519_uint1_t* out2,
                                                               fiat_25519_uint1_t arg1, std::uint64_t arg2,
                                                               std::uint64_t arg3) noexcept {
            std::uint64_t const differenced = arg2 - arg3, carried_in = differenced - arg1;
            *out1 = carried_in, *out2 = (arg2 < arg3) | (differenced < arg1);
        }
    };
#if defined(__GNUC__) && !defined(__clang__)
    return scalar_multiply_through<field_radix51<neon_words_t>>(out, scalar, point);
#else
    return scalar_multiply_through<field_saturated<neon_words_t>>(out, scalar, point);
#endif
}

} // namespace unum::ucall
