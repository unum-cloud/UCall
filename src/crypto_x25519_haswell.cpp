/**
 *  @file src/crypto_x25519_haswell.cpp
 *  @author Ash Vardanian
 *  @date August 4, 2026
 *  @brief The Haswell X25519 kit: saturated limbs over @c MULX with @c ADC and @c SBB chains.
 *
 *  @c _addcarry_u64 lowers to @c ADC, so this kit needs no ADX, which Haswell lacks. Neither
 *  compiler interleaves the @c ADCX / @c ADOX dual carry chains from C - that is what BoringSSL's
 *  hand-scheduled assembly buys, and it remains the measured follow-up.
 */
#include <immintrin.h> // `_mulx_u64`, `_addcarry_u64`, `_subborrow_u64`

#include "crypto_x25519.hpp"

namespace unum::ucall {

bool tunnel::x25519_multiply_haswell(span<byte_t, x25519_key_size_k> out, span<byte_t const, x25519_key_size_k> scalar,
                                     span<byte_t const, x25519_key_size_k> point) noexcept {
    struct haswell_words_t {
        static void fiat_mulx_u64(std::uint64_t* out1, std::uint64_t* out2, std::uint64_t arg1,
                                  std::uint64_t arg2) noexcept {
            unsigned long long high;
            *out1 = _mulx_u64(arg1, arg2, &high), *out2 = high;
        }

        static void fiat_addcarryx_u64(std::uint64_t* out1, fiat_25519_uint1_t* out2, fiat_25519_uint1_t arg1,
                                       std::uint64_t arg2, std::uint64_t arg3) noexcept {
            unsigned long long summed;
            *out2 = _addcarry_u64(arg1, arg2, arg3, &summed), *out1 = summed;
        }

        static void fiat_subborrowx_u64(std::uint64_t* out1, fiat_25519_uint1_t* out2, fiat_25519_uint1_t arg1,
                                        std::uint64_t arg2, std::uint64_t arg3) noexcept {
            unsigned long long differenced;
            *out2 = _subborrow_u64(arg1, arg2, arg3, &differenced), *out1 = differenced;
        }
    };
    return scalar_multiply_through<field_saturated<haswell_words_t>>(out, scalar, point);
}

} // namespace unum::ucall
