/**
 *  @file src/crypto_x25519_neon.cpp
 *  @author Ash Vardanian
 *  @date August 4, 2026
 *  @brief The NEON X25519 kit: radix-51 limbs over @c UMULH.
 */
#include "crypto_x25519_radix51.hpp"

namespace unum::ucall {

bool tunnel::x25519_multiply_neon(span<byte_t, x25519_key_size_k> out, span<byte_t const, x25519_key_size_k> scalar,
                                  span<byte_t const, x25519_key_size_k> point) noexcept {
    struct unit_t {};
    struct neon_words_t {
        static void fiat_mulx_u64(std::uint64_t* out1, std::uint64_t* out2, std::uint64_t arg1,
                                  std::uint64_t arg2) noexcept {
            *out1 = arg1 * arg2;
#if UCALL_COMPILER_MSVC_
            *out2 = __umulh(arg1, arg2);
#else
            __asm__("umulh %x0, %x1, %x2" : "=r"(*out2) : "r"(arg1), "r"(arg2));
#endif
        }

        static void fiat_addcarryx_u64(std::uint64_t* out1, fiat_25519_uint1_t* out2, fiat_25519_uint1_t arg1,
                                       std::uint64_t arg2, std::uint64_t arg3) noexcept {
            // Stays C: AArch64 flags cannot cross separate statements.
            serial_words<unit_t>::fiat_addcarryx_u64(out1, out2, arg1, arg2, arg3);
        }
    };
    return scalar_multiply_through<field_radix51<neon_words_t>>(out, scalar, point);
}

} // namespace unum::ucall
