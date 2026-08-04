/**
 *  @brief Curve25519 scalar multiplication per RFC 7748 §5, in two field-arithmetic tiers.
 *
 *  @section Tiers
 *
 *  - @c x25519_scalar_multiply_serial - radix-51 limbs over 128-bit products. The portable
 *    tier for any GCC- or Clang-compatible compiler, and the faster one on machines without
 *    ADX carry chains.
 *  - @c x25519_scalar_multiply_adx - saturated 4-limb arithmetic, compiled to @c MULX carry
 *    chains under x86-64 GCC and Clang, and the only tier MSVC builds, where it lowers to
 *    plain @c MUL and @c ADC through @c _umul128 and @c _addcarry_u64. Neither compiler
 *    interleaves the @c ADCX / @c ADOX dual carry chains from C - that is what BoringSSL's
 *    hand-scheduled assembly buys, and it remains the measured follow-up.
 *
 *  @c x25519_scalar_multiply picks between them once per process from CPUID.
 *
 *  @section Provenance
 *
 *  Every @c fiat_25519_*, @c fiat_*_u64, and @c fe4_* kernel below is a mechanical,
 *  statement-preserving transcription of fiat-crypto's machine-verified output, whose Coq
 *  proofs cover functional correctness and constant-time execution. Only surface syntax
 *  differs: type spellings, grouped declarations, comma-collapsed assignment runs. The
 *  transcription is held to the RFC 7748 and Wycheproof vectors plus a serial-versus-adx
 *  differential suite in `scripts/test_x25519.cpp`, so regenerate a kernel from the pinned
 *  sources below rather than hand-editing its body.
 *
 *  @see Fiat Cryptography origin v0.1.6+137, the radix-51 `fiat_25519_*` kernels:
 *    https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c
 *  @see Fiat Cryptography origin v0.1.6+137, the saturated `fiat_25519_solinas_*` pair:
 *    https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_solinas_64.c
 *  @see BoringSSL origin, main of 2026-08-04, the `fe4_*` family and the carry shims:
 *    https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_adx.h
 *  @see BoringSSL origin, main of 2026-08-04, the inversion chain's shape - forced by the
 *    exponent p-2 = 2^255-21 itself, so any correct Fermat inversion for this prime performs
 *    the same squarings in the same order:
 *    https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/crypto/curve25519/curve25519.cc#L311-L367
 *
 *  The ladder in @c montgomery_ladder, the clamping, and the small-order check are
 *  transcribed from RFC 7748 §5's pseudocode with the specification's own variable names,
 *  and are shared by both tiers through the field-backend template parameter.
 *
 *  @file src/crypto_x25519.cpp
 *  @author Ash Vardanian
 */
#include <cstdint> // `std::uint64_t`
#include <cstring> // `std::memcpy`

#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h> // `_umul128`, `__umulh`, `_addcarry_u64`, `_subborrow_u64`
#endif
#if (defined(__GNUC__) || defined(__clang__)) && defined(__x86_64__)
#include <cpuid.h> // `__get_cpuid_count`
#endif

#include "crypto_x25519.hpp"

/*
 *  A function attribute cannot hide behind a `using` alias or a template, so this one macro
 *  is unavoidable: it lets GCC and Clang emit MULX/ADCX/ADOX in the saturated kernels while
 *  expanding to nothing under MSVC and on non-x86 targets. It is #undef-ed at end of file.
 */
#if (defined(__GNUC__) || defined(__clang__)) && defined(__x86_64__)
#define UCALL_X25519_TARGET_ADX __attribute__((target("adx,bmi2")))
#else
#define UCALL_X25519_TARGET_ADX
#endif

namespace unum::ucall {
namespace {

#pragma region Compiler Shims

using fiat_25519_uint1_t = unsigned char;
using fiat_25519_int1_t = signed char;
#if defined(__SIZEOF_INT128__)
// A typedef rather than a `using` alias because only the former accepts `__extension__`,
// which silences the pedantic warning about `__int128` being a language extension.
__extension__ typedef unsigned __int128 fiat_25519_uint128_t;
#endif

/**
 *  @brief Returns @p value while hiding everything the optimizer knows about it.
 *
 *  Without this, a compiler that can prove the mask in @c fiat_25519_cmovznz_u64 is 0 or ~0
 *  may rewrite the masked select into a branch, turning a constant-time kernel into a
 *  key-dependent one. MSVC has no empty-asm barrier and no equivalent intrinsic -
 *  @c _ReadWriteBarrier is a deprecated memory-ordering fence that does not hide a register
 *  value's range - so the conforming substitute is a volatile round-trip: the load cannot be
 *  folded, and no range fact survives it. fiat-crypto and BoringSSL both compile this
 *  barrier to a plain identity under MSVC, so the round-trip is strictly stronger.
 */
[[nodiscard]] inline std::uint64_t value_barrier(std::uint64_t value) noexcept {
#if defined(__GNUC__) || defined(__clang__)
    __asm__("" : "+r"(value));
    return value;
#else
    volatile std::uint64_t laundered = value;
    return laundered;
#endif
}

/**
 *  @brief Full 64x64->128 multiply: @p out1 receives the low half, @p out2 the high.
 *  @see BoringSSL origin, main of 2026-08-04:
 *    https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_adx.h#L44
 */
inline void fiat_mulx_u64(std::uint64_t *out1, std::uint64_t *out2, std::uint64_t arg1, std::uint64_t arg2) noexcept {
#if defined(__SIZEOF_INT128__)
    fiat_25519_uint128_t const product = (fiat_25519_uint128_t)arg1 * arg2;
    *out1 = (std::uint64_t)product, *out2 = (std::uint64_t)(product >> 64);
#elif defined(_M_X64)
    *out1 = _umul128(arg1, arg2, out2);
#elif defined(_M_ARM64)
    *out1 = arg1 * arg2, *out2 = __umulh(arg1, arg2);
#else
#error "No 128-bit multiply available: need __int128, _umul128, or __umulh."
#endif
}

/**
 *  @brief 64-bit add with carry: @p out1 = @p arg2 + @p arg3 + @p arg1, @p out2 the carry-out.
 *  @see BoringSSL origin, main of 2026-08-04:
 *    https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_adx.h#L76
 */
inline void fiat_addcarryx_u64(std::uint64_t *out1, fiat_25519_uint1_t *out2, fiat_25519_uint1_t arg1,
                               std::uint64_t arg2, std::uint64_t arg3) noexcept {
#if defined(_MSC_VER) && !defined(__clang__) && defined(_M_X64)
    unsigned long long summed;
    *out2 = _addcarry_u64(arg1, arg2, arg3, &summed), *out1 = summed;
#else
    // GCC and Clang pattern-match this into ADC, and into ADCX/ADOX under the target above.
    arg2 += arg1;
    fiat_25519_uint1_t carried = arg2 < arg1;
    std::uint64_t const summed = arg2 + arg3;
    carried += summed < arg2;
    *out1 = summed, *out2 = carried;
#endif
}

/**
 *  @brief 64-bit subtract with borrow: @p out1 = @p arg2 - @p arg3 - @p arg1, @p out2 the borrow-out.
 *  @see BoringSSL origin, main of 2026-08-04:
 *    https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_adx.h#L116
 */
inline void fiat_subborrowx_u64(std::uint64_t *out1, fiat_25519_uint1_t *out2, fiat_25519_uint1_t arg1,
                                std::uint64_t arg2, std::uint64_t arg3) noexcept {
#if defined(_MSC_VER) && !defined(__clang__) && defined(_M_X64)
    unsigned long long differenced;
    *out2 = _subborrow_u64(arg1, arg2, arg3, &differenced), *out1 = differenced;
#else
    *out1 = arg2 - arg3 - arg1;
    *out2 = (arg2 < arg3) | ((arg2 == arg3) & arg1);
#endif
}

/**
 *  @brief Constant-time select: @p out1 = @p arg1 ? @p arg3 : @p arg2, masked rather than branched. Both tiers use it.
 *  @see Fiat Cryptography origin v0.1.6+137:
 *    https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c#L116
 */
inline void fiat_25519_cmovznz_u64(std::uint64_t *out1, fiat_25519_uint1_t arg1, std::uint64_t arg2,
                                   std::uint64_t arg3) noexcept {
    fiat_25519_uint1_t x1;
    std::uint64_t x2, x3;
    x1 = (!(!arg1)), x2 = ((fiat_25519_int1_t)(0x0 - x1) & 0xffffffffffffffffULL),
    x3 = ((value_barrier(x2) & arg3) | (value_barrier((~x2)) & arg2)), *out1 = x3;
}

/** @brief True when the CPU executes the ADX and BMI2 instruction sets the saturated tier is compiled for. */
[[nodiscard]] inline bool cpu_supports_adx_and_bmi2() noexcept {
#if (defined(__GNUC__) || defined(__clang__)) && defined(__x86_64__)
    unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) return false;
    bool const has_bmi2 = (ebx >> 8) & 1u;
    bool const has_adx = (ebx >> 19) & 1u;
    return has_bmi2 && has_adx;
#else
    return false;
#endif
}

#pragma endregion Compiler Shims

#if defined(__SIZEOF_INT128__)

#pragma region Radix 51 Field Arithmetic

/**
 *  @brief Adds @p arg2, @p arg3, and carry-in @p arg1 within a 51-bit limb, splitting sum and carry-out.
 *  @see Fiat Cryptography origin v0.1.6+137:
 *    https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c#L66
 */
inline void fiat_25519_addcarryx_u51(std::uint64_t *out1, fiat_25519_uint1_t *out2, fiat_25519_uint1_t arg1,
                                     std::uint64_t arg2, std::uint64_t arg3) noexcept {
    std::uint64_t x1, x2;
    fiat_25519_uint1_t x3;
    x1 = ((arg1 + arg2) + arg3), x2 = (x1 & 0x7ffffffffffffULL), x3 = (fiat_25519_uint1_t)(x1 >> 51), *out1 = x2,
    *out2 = x3;
}

/**
 *  @brief Subtracts @p arg3 and borrow-in @p arg1 from @p arg2 within a 51-bit limb, splitting difference and
 * borrow-out.
 *  @see Fiat Cryptography origin v0.1.6+137:
 *    https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c#L92
 */
inline void fiat_25519_subborrowx_u51(std::uint64_t *out1, fiat_25519_uint1_t *out2, fiat_25519_uint1_t arg1,
                                      std::uint64_t arg2, std::uint64_t arg3) noexcept {
    std::int64_t x1;
    fiat_25519_int1_t x2;
    std::uint64_t x3;
    x1 = ((std::int64_t)(arg2 - (std::int64_t)arg1) - (std::int64_t)arg3), x2 = (fiat_25519_int1_t)(x1 >> 51),
    x3 = (x1 & 0x7ffffffffffffULL), *out1 = x3, *out2 = (fiat_25519_uint1_t)(0x0 - x2);
}

/**
 *  @brief Multiplies two radix-51 elements and reduces mod 2^255-19 into tight bounds.
 *  @see Fiat Cryptography origin v0.1.6+137:
 *    https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c#L133
 */
inline void fiat_25519_carry_mul(std::uint64_t out1[5], std::uint64_t const arg1[5],
                                 std::uint64_t const arg2[5]) noexcept {
    fiat_25519_uint128_t x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21,
        x22, x23, x24, x25, x26, x29, x30, x31, x32, x33, x36, x39, x42;
    std::uint64_t x27, x28, x34, x35, x37, x38, x40, x41, x43, x44, x45, x46, x47, x48, x49, x51, x52;
    fiat_25519_uint1_t x50;
    x1 = ((fiat_25519_uint128_t)(arg1[4]) * ((arg2[4]) * 0x13)),
    x2 = ((fiat_25519_uint128_t)(arg1[4]) * ((arg2[3]) * 0x13)),
    x3 = ((fiat_25519_uint128_t)(arg1[4]) * ((arg2[2]) * 0x13)),
    x4 = ((fiat_25519_uint128_t)(arg1[4]) * ((arg2[1]) * 0x13)),
    x5 = ((fiat_25519_uint128_t)(arg1[3]) * ((arg2[4]) * 0x13)),
    x6 = ((fiat_25519_uint128_t)(arg1[3]) * ((arg2[3]) * 0x13)),
    x7 = ((fiat_25519_uint128_t)(arg1[3]) * ((arg2[2]) * 0x13)),
    x8 = ((fiat_25519_uint128_t)(arg1[2]) * ((arg2[4]) * 0x13)),
    x9 = ((fiat_25519_uint128_t)(arg1[2]) * ((arg2[3]) * 0x13)),
    x10 = ((fiat_25519_uint128_t)(arg1[1]) * ((arg2[4]) * 0x13)), x11 = ((fiat_25519_uint128_t)(arg1[4]) * (arg2[0])),
    x12 = ((fiat_25519_uint128_t)(arg1[3]) * (arg2[1])), x13 = ((fiat_25519_uint128_t)(arg1[3]) * (arg2[0])),
    x14 = ((fiat_25519_uint128_t)(arg1[2]) * (arg2[2])), x15 = ((fiat_25519_uint128_t)(arg1[2]) * (arg2[1])),
    x16 = ((fiat_25519_uint128_t)(arg1[2]) * (arg2[0])), x17 = ((fiat_25519_uint128_t)(arg1[1]) * (arg2[3])),
    x18 = ((fiat_25519_uint128_t)(arg1[1]) * (arg2[2])), x19 = ((fiat_25519_uint128_t)(arg1[1]) * (arg2[1])),
    x20 = ((fiat_25519_uint128_t)(arg1[1]) * (arg2[0])), x21 = ((fiat_25519_uint128_t)(arg1[0]) * (arg2[4])),
    x22 = ((fiat_25519_uint128_t)(arg1[0]) * (arg2[3])), x23 = ((fiat_25519_uint128_t)(arg1[0]) * (arg2[2])),
    x24 = ((fiat_25519_uint128_t)(arg1[0]) * (arg2[1])), x25 = ((fiat_25519_uint128_t)(arg1[0]) * (arg2[0])),
    x26 = (x25 + (x10 + (x9 + (x7 + x4)))), x27 = (std::uint64_t)(x26 >> 51),
    x28 = (std::uint64_t)(x26 & 0x7ffffffffffffULL), x29 = (x21 + (x17 + (x14 + (x12 + x11)))),
    x30 = (x22 + (x18 + (x15 + (x13 + x1)))), x31 = (x23 + (x19 + (x16 + (x5 + x2)))),
    x32 = (x24 + (x20 + (x8 + (x6 + x3)))), x33 = (x27 + x32), x34 = (std::uint64_t)(x33 >> 51),
    x35 = (std::uint64_t)(x33 & 0x7ffffffffffffULL), x36 = (x34 + x31), x37 = (std::uint64_t)(x36 >> 51),
    x38 = (std::uint64_t)(x36 & 0x7ffffffffffffULL), x39 = (x37 + x30), x40 = (std::uint64_t)(x39 >> 51),
    x41 = (std::uint64_t)(x39 & 0x7ffffffffffffULL), x42 = (x40 + x29), x43 = (std::uint64_t)(x42 >> 51),
    x44 = (std::uint64_t)(x42 & 0x7ffffffffffffULL), x45 = (x43 * 0x13), x46 = (x28 + x45), x47 = (x46 >> 51),
    x48 = (x46 & 0x7ffffffffffffULL), x49 = (x47 + x35), x50 = (fiat_25519_uint1_t)(x49 >> 51),
    x51 = (x49 & 0x7ffffffffffffULL), x52 = (x50 + x38), out1[0] = x48, out1[1] = x51, out1[2] = x52, out1[3] = x41,
    out1[4] = x44;
}

/**
 *  @brief Carries a loose radix-51 element back into tight bounds.
 *  @see Fiat Cryptography origin v0.1.6+137:
 *    https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c#L367
 */
inline void fiat_25519_carry(std::uint64_t out1[5], std::uint64_t const arg1[5]) noexcept {
    std::uint64_t x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12;
    x1 = (arg1[0]), x2 = ((x1 >> 51) + (arg1[1])), x3 = ((x2 >> 51) + (arg1[2])), x4 = ((x3 >> 51) + (arg1[3])),
    x5 = ((x4 >> 51) + (arg1[4])), x6 = ((x1 & 0x7ffffffffffffULL) + ((x5 >> 51) * 0x13)),
    x7 = ((fiat_25519_uint1_t)(x6 >> 51) + (x2 & 0x7ffffffffffffULL)), x8 = (x6 & 0x7ffffffffffffULL),
    x9 = (x7 & 0x7ffffffffffffULL), x10 = ((fiat_25519_uint1_t)(x7 >> 51) + (x3 & 0x7ffffffffffffULL)),
    x11 = (x4 & 0x7ffffffffffffULL), x12 = (x5 & 0x7ffffffffffffULL), out1[0] = x8, out1[1] = x9, out1[2] = x10,
    out1[3] = x11, out1[4] = x12;
}

/**
 *  @brief Adds tight radix-51 elements into a loose result awaiting @c fiat_25519_carry.
 *  @see Fiat Cryptography origin v0.1.6+137:
 *    https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c#L406
 */
inline void fiat_25519_add(std::uint64_t out1[5], std::uint64_t const arg1[5], std::uint64_t const arg2[5]) noexcept {
    std::uint64_t x1, x2, x3, x4, x5;
    x1 = ((arg1[0]) + (arg2[0])), x2 = ((arg1[1]) + (arg2[1])), x3 = ((arg1[2]) + (arg2[2])),
    x4 = ((arg1[3]) + (arg2[3])), x5 = ((arg1[4]) + (arg2[4])), out1[0] = x1, out1[1] = x2, out1[2] = x3, out1[3] = x4,
    out1[4] = x5;
}

/**
 *  @brief Subtracts tight radix-51 elements into a loose result awaiting @c fiat_25519_carry.
 *  @see Fiat Cryptography origin v0.1.6+137:
 *    https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c#L431
 */
inline void fiat_25519_sub(std::uint64_t out1[5], std::uint64_t const arg1[5], std::uint64_t const arg2[5]) noexcept {
    std::uint64_t x1, x2, x3, x4, x5;
    x1 = ((0xfffffffffffdaULL + (arg1[0])) - (arg2[0])), x2 = ((0xffffffffffffeULL + (arg1[1])) - (arg2[1])),
    x3 = ((0xffffffffffffeULL + (arg1[2])) - (arg2[2])), x4 = ((0xffffffffffffeULL + (arg1[3])) - (arg2[3])),
    x5 = ((0xffffffffffffeULL + (arg1[4])) - (arg2[4])), out1[0] = x1, out1[1] = x2, out1[2] = x3, out1[3] = x4,
    out1[4] = x5;
}

/**
 *  @brief Serializes a tight radix-51 element to 32 canonical little-endian bytes.
 *  @see Fiat Cryptography origin v0.1.6+137:
 *    https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c#L514
 */
inline void fiat_25519_to_bytes(std::uint8_t out1[32], std::uint64_t const arg1[5]) noexcept {
    std::uint64_t x1, x3, x5, x7, x9, x11, x12, x14, x16, x18, x20, x22, x23, x24, x25, x27, x29, x31, x33, x35, x38,
        x40, x42, x44, x46, x48, x51, x53, x55, x57, x59, x61, x63, x66, x68, x70, x72, x74, x76, x79, x81, x83, x85,
        x87, x89;
    fiat_25519_uint1_t x2, x4, x6, x8, x10, x13, x15, x17, x19, x21, x65;
    std::uint8_t x26, x28, x30, x32, x34, x36, x37, x39, x41, x43, x45, x47, x49, x50, x52, x54, x56, x58, x60, x62,
        x64, x67, x69, x71, x73, x75, x77, x78, x80, x82, x84, x86, x88, x90, x91;
    fiat_25519_subborrowx_u51(&x1, &x2, 0x0, (arg1[0]), 0x7ffffffffffedULL);
    fiat_25519_subborrowx_u51(&x3, &x4, x2, (arg1[1]), 0x7ffffffffffffULL);
    fiat_25519_subborrowx_u51(&x5, &x6, x4, (arg1[2]), 0x7ffffffffffffULL);
    fiat_25519_subborrowx_u51(&x7, &x8, x6, (arg1[3]), 0x7ffffffffffffULL);
    fiat_25519_subborrowx_u51(&x9, &x10, x8, (arg1[4]), 0x7ffffffffffffULL);
    fiat_25519_cmovznz_u64(&x11, x10, 0x0, 0xffffffffffffffffULL);
    fiat_25519_addcarryx_u51(&x12, &x13, 0x0, x1, (x11 & 0x7ffffffffffedULL));
    fiat_25519_addcarryx_u51(&x14, &x15, x13, x3, (x11 & 0x7ffffffffffffULL));
    fiat_25519_addcarryx_u51(&x16, &x17, x15, x5, (x11 & 0x7ffffffffffffULL));
    fiat_25519_addcarryx_u51(&x18, &x19, x17, x7, (x11 & 0x7ffffffffffffULL));
    fiat_25519_addcarryx_u51(&x20, &x21, x19, x9, (x11 & 0x7ffffffffffffULL));
    x22 = (x20 << 4), x23 = (x18 * (std::uint64_t)0x2), x24 = (x16 << 6), x25 = (x14 << 3),
    x26 = (std::uint8_t)(x12 & 0xff), x27 = (x12 >> 8), x28 = (std::uint8_t)(x27 & 0xff), x29 = (x27 >> 8),
    x30 = (std::uint8_t)(x29 & 0xff), x31 = (x29 >> 8), x32 = (std::uint8_t)(x31 & 0xff), x33 = (x31 >> 8),
    x34 = (std::uint8_t)(x33 & 0xff), x35 = (x33 >> 8), x36 = (std::uint8_t)(x35 & 0xff),
    x37 = (std::uint8_t)(x35 >> 8), x38 = (x25 + (std::uint64_t)x37), x39 = (std::uint8_t)(x38 & 0xff),
    x40 = (x38 >> 8), x41 = (std::uint8_t)(x40 & 0xff), x42 = (x40 >> 8), x43 = (std::uint8_t)(x42 & 0xff),
    x44 = (x42 >> 8), x45 = (std::uint8_t)(x44 & 0xff), x46 = (x44 >> 8), x47 = (std::uint8_t)(x46 & 0xff),
    x48 = (x46 >> 8), x49 = (std::uint8_t)(x48 & 0xff), x50 = (std::uint8_t)(x48 >> 8),
    x51 = (x24 + (std::uint64_t)x50), x52 = (std::uint8_t)(x51 & 0xff), x53 = (x51 >> 8),
    x54 = (std::uint8_t)(x53 & 0xff), x55 = (x53 >> 8), x56 = (std::uint8_t)(x55 & 0xff), x57 = (x55 >> 8),
    x58 = (std::uint8_t)(x57 & 0xff), x59 = (x57 >> 8), x60 = (std::uint8_t)(x59 & 0xff), x61 = (x59 >> 8),
    x62 = (std::uint8_t)(x61 & 0xff), x63 = (x61 >> 8), x64 = (std::uint8_t)(x63 & 0xff),
    x65 = (fiat_25519_uint1_t)(x63 >> 8), x66 = (x23 + (std::uint64_t)x65), x67 = (std::uint8_t)(x66 & 0xff),
    x68 = (x66 >> 8), x69 = (std::uint8_t)(x68 & 0xff), x70 = (x68 >> 8), x71 = (std::uint8_t)(x70 & 0xff),
    x72 = (x70 >> 8), x73 = (std::uint8_t)(x72 & 0xff), x74 = (x72 >> 8), x75 = (std::uint8_t)(x74 & 0xff),
    x76 = (x74 >> 8), x77 = (std::uint8_t)(x76 & 0xff), x78 = (std::uint8_t)(x76 >> 8),
    x79 = (x22 + (std::uint64_t)x78), x80 = (std::uint8_t)(x79 & 0xff), x81 = (x79 >> 8),
    x82 = (std::uint8_t)(x81 & 0xff), x83 = (x81 >> 8), x84 = (std::uint8_t)(x83 & 0xff), x85 = (x83 >> 8),
    x86 = (std::uint8_t)(x85 & 0xff), x87 = (x85 >> 8), x88 = (std::uint8_t)(x87 & 0xff), x89 = (x87 >> 8),
    x90 = (std::uint8_t)(x89 & 0xff), x91 = (std::uint8_t)(x89 >> 8), out1[0] = x26, out1[1] = x28, out1[2] = x30,
    out1[3] = x32, out1[4] = x34, out1[5] = x36, out1[6] = x39, out1[7] = x41, out1[8] = x43, out1[9] = x45,
    out1[10] = x47, out1[11] = x49, out1[12] = x52, out1[13] = x54, out1[14] = x56, out1[15] = x58, out1[16] = x60,
    out1[17] = x62, out1[18] = x64, out1[19] = x67, out1[20] = x69, out1[21] = x71, out1[22] = x73, out1[23] = x75,
    out1[24] = x77, out1[25] = x80, out1[26] = x82, out1[27] = x84, out1[28] = x86, out1[29] = x88, out1[30] = x90,
    out1[31] = x91;
}

/**
 *  @brief Deserializes 32 little-endian bytes, bit 255 pre-cleared, into a tight radix-51 element.
 *  @see Fiat Cryptography origin v0.1.6+137:
 *    https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c#L730
 */
inline void fiat_25519_from_bytes(std::uint64_t out1[5], std::uint8_t const arg1[32]) noexcept {
    std::uint64_t x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22,
        x23, x24, x25, x26, x27, x28, x29, x30, x31, x33, x34, x35, x36, x37, x38, x39, x41, x42, x43, x44, x45, x46,
        x47, x49, x50, x51, x52, x53, x54, x55, x56, x58, x59, x60, x61, x62, x63, x64, x66, x67, x68, x69, x70, x71;
    std::uint8_t x32, x40, x48, x57, x65;
    x1 = ((std::uint64_t)(arg1[31]) << 44), x2 = ((std::uint64_t)(arg1[30]) << 36),
    x3 = ((std::uint64_t)(arg1[29]) << 28), x4 = ((std::uint64_t)(arg1[28]) << 20),
    x5 = ((std::uint64_t)(arg1[27]) << 12), x6 = ((std::uint64_t)(arg1[26]) << 4),
    x7 = ((std::uint64_t)(arg1[25]) << 47), x8 = ((std::uint64_t)(arg1[24]) << 39),
    x9 = ((std::uint64_t)(arg1[23]) << 31), x10 = ((std::uint64_t)(arg1[22]) << 23),
    x11 = ((std::uint64_t)(arg1[21]) << 15), x12 = ((std::uint64_t)(arg1[20]) << 7),
    x13 = ((std::uint64_t)(arg1[19]) << 50), x14 = ((std::uint64_t)(arg1[18]) << 42),
    x15 = ((std::uint64_t)(arg1[17]) << 34), x16 = ((std::uint64_t)(arg1[16]) << 26),
    x17 = ((std::uint64_t)(arg1[15]) << 18), x18 = ((std::uint64_t)(arg1[14]) << 10),
    x19 = ((std::uint64_t)(arg1[13]) << 2), x20 = ((std::uint64_t)(arg1[12]) << 45),
    x21 = ((std::uint64_t)(arg1[11]) << 37), x22 = ((std::uint64_t)(arg1[10]) << 29),
    x23 = ((std::uint64_t)(arg1[9]) << 21), x24 = ((std::uint64_t)(arg1[8]) << 13),
    x25 = ((std::uint64_t)(arg1[7]) << 5), x26 = ((std::uint64_t)(arg1[6]) << 48),
    x27 = ((std::uint64_t)(arg1[5]) << 40), x28 = ((std::uint64_t)(arg1[4]) << 32),
    x29 = ((std::uint64_t)(arg1[3]) << 24), x30 = ((std::uint64_t)(arg1[2]) << 16),
    x31 = ((std::uint64_t)(arg1[1]) << 8), x32 = (arg1[0]), x33 = (x31 + (std::uint64_t)x32), x34 = (x30 + x33),
    x35 = (x29 + x34), x36 = (x28 + x35), x37 = (x27 + x36), x38 = (x26 + x37), x39 = (x38 & 0x7ffffffffffffULL),
    x40 = (std::uint8_t)(x38 >> 51), x41 = (x25 + (std::uint64_t)x40), x42 = (x24 + x41), x43 = (x23 + x42),
    x44 = (x22 + x43), x45 = (x21 + x44), x46 = (x20 + x45), x47 = (x46 & 0x7ffffffffffffULL),
    x48 = (std::uint8_t)(x46 >> 51), x49 = (x19 + (std::uint64_t)x48), x50 = (x18 + x49), x51 = (x17 + x50),
    x52 = (x16 + x51), x53 = (x15 + x52), x54 = (x14 + x53), x55 = (x13 + x54), x56 = (x55 & 0x7ffffffffffffULL),
    x57 = (std::uint8_t)(x55 >> 51), x58 = (x12 + (std::uint64_t)x57), x59 = (x11 + x58), x60 = (x10 + x59),
    x61 = (x9 + x60), x62 = (x8 + x61), x63 = (x7 + x62), x64 = (x63 & 0x7ffffffffffffULL),
    x65 = (std::uint8_t)(x63 >> 51), x66 = (x6 + (std::uint64_t)x65), x67 = (x5 + x66), x68 = (x4 + x67),
    x69 = (x3 + x68), x70 = (x2 + x69), x71 = (x1 + x70), out1[0] = x39, out1[1] = x47, out1[2] = x56, out1[3] = x64,
    out1[4] = x71;
}

/**
 *  @brief The radix-51 field backend: five 51-bit limbs, little-endian, 128-bit products.
 *
 *  fiat-crypto distinguishes "tight" (freshly carried) from "loose" (freshly added or
 *  subtracted, wider) limb bounds so a caller can skip a carry between them. That
 *  distinction buys throughput, and throughput is not the concern of a primitive that runs
 *  four times per handshake rather than once per byte, so every sum and difference is
 *  carried back to tight bounds before reuse. A tight value always satisfies a loose
 *  precondition, so this is never unsafe, only slower.
 */
struct field_serial_t {
    struct element_t {
        std::uint64_t limb[5];
    };

    static element_t zero() noexcept { return {{0, 0, 0, 0, 0}}; }
    static element_t one() noexcept { return {{1, 0, 0, 0, 0}}; }

    static void add(element_t &out, element_t const &first, element_t const &second) noexcept {
        element_t loose;
        fiat_25519_add(loose.limb, first.limb, second.limb);
        fiat_25519_carry(out.limb, loose.limb);
    }

    static void subtract(element_t &out, element_t const &first, element_t const &second) noexcept {
        element_t loose;
        fiat_25519_sub(loose.limb, first.limb, second.limb);
        fiat_25519_carry(out.limb, loose.limb);
    }

    /** @brief May alias @p out with either input - fiat kernels read everything before writing. */
    static void multiply(element_t &out, element_t const &first, element_t const &second) noexcept {
        fiat_25519_carry_mul(out.limb, first.limb, second.limb);
    }

    static void square(element_t &out, element_t const &value) noexcept { multiply(out, value, value); }

    static void multiply_small(element_t &out, element_t const &value, std::uint64_t small) noexcept {
        element_t const factor {{small, 0, 0, 0, 0}};
        fiat_25519_carry_mul(out.limb, value.limb, factor.limb);
    }

    /** @brief Constant-time swap when @p bit is 1: a barriered mask select, never a branch. */
    static void conditional_swap(element_t &first, element_t &second, std::uint64_t bit) noexcept {
        std::uint64_t const mask = value_barrier(0 - bit);
        for (std::size_t index = 0; index != 5; ++index) {
            std::uint64_t const difference = (first.limb[index] ^ second.limb[index]) & mask;
            first.limb[index] ^= difference;
            second.limb[index] ^= difference;
        }
    }

    /** @brief Precondition: bit 255 of @p bytes is already clear - the caller masks it per RFC 7748 §5. */
    static void from_bytes(element_t &out, std::uint8_t const bytes[x25519_key_size_k]) noexcept {
        fiat_25519_from_bytes(out.limb, bytes);
    }

    static void to_bytes(std::uint8_t bytes[x25519_key_size_k], element_t const &value) noexcept {
        fiat_25519_to_bytes(bytes, value.limb);
    }
};

#pragma endregion Radix 51 Field Arithmetic

#endif // defined(__SIZEOF_INT128__)

#pragma region Saturated Field Arithmetic

/**
 *  @brief Multiplies two saturated 4-limb elements mod 2^255-19.
 *  @see Fiat Cryptography origin v0.1.6+137:
 *    https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_solinas_64.c#L150
 */
UCALL_X25519_TARGET_ADX inline void fiat_25519_solinas_mul(std::uint64_t out1[4], std::uint64_t const arg1[4],
                                                           std::uint64_t const arg2[4]) noexcept {
    std::uint64_t x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22,
        x23, x24, x25, x26, x27, x28, x29, x30, x31, x32, x33, x35, x37, x38, x40, x42, x44, x45, x47, x49, x51, x53,
        x55, x56, x58, x60, x62, x64, x66, x68, x70, x72, x74, x76, x78, x80, x82, x84, x86, x88, x90, x92, x94, x96,
        x97, x98, x99, x100, x101, x102, x103, x104, x106, x108, x110, x111, x113, x115, x117, x119, x120, x121, x122,
        x124, x126, x128, x130, x131;
    fiat_25519_uint1_t x34, x36, x39, x41, x43, x46, x48, x50, x52, x54, x57, x59, x61, x63, x65, x67, x69, x71, x73,
        x75, x77, x79, x81, x83, x85, x87, x89, x91, x93, x95, x105, x107, x109, x112, x114, x116, x118, x123, x125,
        x127, x129, x132;
    fiat_mulx_u64(&x1, &x2, (arg1[3]), (arg2[3]));
    fiat_mulx_u64(&x3, &x4, (arg1[3]), (arg2[2]));
    fiat_mulx_u64(&x5, &x6, (arg1[3]), (arg2[1]));
    fiat_mulx_u64(&x7, &x8, (arg1[3]), (arg2[0]));
    fiat_mulx_u64(&x9, &x10, (arg1[2]), (arg2[3]));
    fiat_mulx_u64(&x11, &x12, (arg1[2]), (arg2[2]));
    fiat_mulx_u64(&x13, &x14, (arg1[2]), (arg2[1]));
    fiat_mulx_u64(&x15, &x16, (arg1[2]), (arg2[0]));
    fiat_mulx_u64(&x17, &x18, (arg1[1]), (arg2[3]));
    fiat_mulx_u64(&x19, &x20, (arg1[1]), (arg2[2]));
    fiat_mulx_u64(&x21, &x22, (arg1[1]), (arg2[1]));
    fiat_mulx_u64(&x23, &x24, (arg1[1]), (arg2[0]));
    fiat_mulx_u64(&x25, &x26, (arg1[0]), (arg2[3]));
    fiat_mulx_u64(&x27, &x28, (arg1[0]), (arg2[2]));
    fiat_mulx_u64(&x29, &x30, (arg1[0]), (arg2[1]));
    fiat_mulx_u64(&x31, &x32, (arg1[0]), (arg2[0]));
    fiat_addcarryx_u64(&x33, &x34, 0x0, x28, x7);
    fiat_addcarryx_u64(&x35, &x36, x34, x26, x5);
    x37 = (x36 + x18);
    fiat_addcarryx_u64(&x38, &x39, 0x0, x33, x13);
    fiat_addcarryx_u64(&x40, &x41, x39, x35, x8);
    fiat_addcarryx_u64(&x42, &x43, x41, x37, 0x0);
    x44 = (x43 + x10);
    fiat_addcarryx_u64(&x45, &x46, 0x0, x30, x15);
    fiat_addcarryx_u64(&x47, &x48, x46, x38, x16);
    fiat_addcarryx_u64(&x49, &x50, x48, x40, x11);
    fiat_addcarryx_u64(&x51, &x52, x50, x42, x3);
    fiat_addcarryx_u64(&x53, &x54, x52, x44, 0x0);
    x55 = (x54 + x2);
    fiat_addcarryx_u64(&x56, &x57, 0x0, x45, x21);
    fiat_addcarryx_u64(&x58, &x59, x57, x47, x19);
    fiat_addcarryx_u64(&x60, &x61, x59, x49, x14);
    fiat_addcarryx_u64(&x62, &x63, x61, x51, x6);
    fiat_addcarryx_u64(&x64, &x65, x63, x53, 0x0);
    fiat_addcarryx_u64(&x66, &x67, x65, x55, 0x0);
    fiat_addcarryx_u64(&x68, &x69, 0x0, x32, x23);
    fiat_addcarryx_u64(&x70, &x71, x69, x56, x24);
    fiat_addcarryx_u64(&x72, &x73, x71, x58, x22);
    fiat_addcarryx_u64(&x74, &x75, x73, x60, x17);
    fiat_addcarryx_u64(&x76, &x77, x75, x62, x9);
    fiat_addcarryx_u64(&x78, &x79, x77, x64, x1);
    fiat_addcarryx_u64(&x80, &x81, x79, x66, 0x0);
    fiat_addcarryx_u64(&x82, &x83, 0x0, x68, x29);
    fiat_addcarryx_u64(&x84, &x85, x83, x70, x27);
    fiat_addcarryx_u64(&x86, &x87, x85, x72, x25);
    fiat_addcarryx_u64(&x88, &x89, x87, x74, x20);
    fiat_addcarryx_u64(&x90, &x91, x89, x76, x12);
    fiat_addcarryx_u64(&x92, &x93, x91, x78, x4);
    fiat_addcarryx_u64(&x94, &x95, x93, x80, 0x0);
    fiat_mulx_u64(&x96, &x97, 0x26, x94);
    fiat_mulx_u64(&x98, &x99, 0x26, x92);
    fiat_mulx_u64(&x100, &x101, 0x26, x90);
    fiat_mulx_u64(&x102, &x103, 0x26, x88);
    fiat_addcarryx_u64(&x104, &x105, 0x0, x82, x100);
    fiat_addcarryx_u64(&x106, &x107, x105, x84, x98);
    fiat_addcarryx_u64(&x108, &x109, x107, x86, x96);
    x110 = (x109 + x97);
    fiat_addcarryx_u64(&x111, &x112, 0x0, x31, x102);
    fiat_addcarryx_u64(&x113, &x114, x112, x104, x103);
    fiat_addcarryx_u64(&x115, &x116, x114, x106, x101);
    fiat_addcarryx_u64(&x117, &x118, x116, x108, x99);
    x119 = (x118 + x110);
    fiat_mulx_u64(&x120, &x121, 0x26, x119);
    fiat_addcarryx_u64(&x122, &x123, 0x0, x111, x120);
    fiat_addcarryx_u64(&x124, &x125, x123, x113, 0x0);
    fiat_addcarryx_u64(&x126, &x127, x125, x115, 0x0);
    fiat_addcarryx_u64(&x128, &x129, x127, x117, 0x0);
    fiat_25519_cmovznz_u64(&x130, x129, 0x0, 0x26);
    fiat_addcarryx_u64(&x131, &x132, 0x0, x130, x122);
    out1[0] = x131, out1[1] = x124, out1[2] = x126, out1[3] = x128;
}

/**
 *  @brief Squares a saturated 4-limb element mod 2^255-19.
 *  @see Fiat Cryptography origin v0.1.6+137:
 *    https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_solinas_64.c#L369
 */
UCALL_X25519_TARGET_ADX inline void fiat_25519_solinas_square(std::uint64_t out1[4],
                                                              std::uint64_t const arg1[4]) noexcept {
    std::uint64_t x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x13, x15, x17, x19, x20, x21, x22, x24, x26, x28, x30,
        x32, x34, x36, x38, x40, x42, x43, x44, x45, x46, x47, x48, x49, x50, x51, x53, x55, x57, x59, x61, x63, x65,
        x66, x67, x68, x69, x70, x71, x72, x73, x75, x77, x79, x80, x82, x84, x86, x88, x89, x90, x91, x93, x95, x97,
        x99, x100;
    fiat_25519_uint1_t x12, x14, x16, x18, x23, x25, x27, x29, x31, x33, x35, x37, x39, x41, x52, x54, x56, x58, x60,
        x62, x64, x74, x76, x78, x81, x83, x85, x87, x92, x94, x96, x98, x101;
    fiat_mulx_u64(&x1, &x2, (arg1[0]), (arg1[3]));
    fiat_mulx_u64(&x3, &x4, (arg1[0]), (arg1[2]));
    fiat_mulx_u64(&x5, &x6, (arg1[0]), (arg1[1]));
    fiat_mulx_u64(&x7, &x8, (arg1[3]), (arg1[2]));
    fiat_mulx_u64(&x9, &x10, (arg1[3]), (arg1[1]));
    fiat_addcarryx_u64(&x11, &x12, 0x0, x6, x3);
    fiat_addcarryx_u64(&x13, &x14, x12, x4, x1);
    fiat_addcarryx_u64(&x15, &x16, x14, x2, x9);
    fiat_addcarryx_u64(&x17, &x18, x16, x10, x7);
    x19 = (x18 + x8);
    fiat_mulx_u64(&x20, &x21, (arg1[1]), (arg1[2]));
    fiat_addcarryx_u64(&x22, &x23, 0x0, x13, x20);
    fiat_addcarryx_u64(&x24, &x25, x23, x15, x21);
    fiat_addcarryx_u64(&x26, &x27, x25, x17, 0x0);
    fiat_addcarryx_u64(&x28, &x29, x27, x19, 0x0);
    fiat_addcarryx_u64(&x30, &x31, 0x0, x5, x5);
    fiat_addcarryx_u64(&x32, &x33, x31, x11, x11);
    fiat_addcarryx_u64(&x34, &x35, x33, x22, x22);
    fiat_addcarryx_u64(&x36, &x37, x35, x24, x24);
    fiat_addcarryx_u64(&x38, &x39, x37, x26, x26);
    fiat_addcarryx_u64(&x40, &x41, x39, x28, x28);
    x42 = (((std::uint64_t)x41 + x29) + (std::uint64_t)x29);
    fiat_mulx_u64(&x43, &x44, (arg1[3]), (arg1[3]));
    fiat_mulx_u64(&x45, &x46, (arg1[2]), (arg1[2]));
    fiat_mulx_u64(&x47, &x48, (arg1[1]), (arg1[1]));
    fiat_mulx_u64(&x49, &x50, (arg1[0]), (arg1[0]));
    fiat_addcarryx_u64(&x51, &x52, 0x0, x30, x50);
    fiat_addcarryx_u64(&x53, &x54, x52, x32, x47);
    fiat_addcarryx_u64(&x55, &x56, x54, x34, x48);
    fiat_addcarryx_u64(&x57, &x58, x56, x36, x45);
    fiat_addcarryx_u64(&x59, &x60, x58, x38, x46);
    fiat_addcarryx_u64(&x61, &x62, x60, x40, x43);
    fiat_addcarryx_u64(&x63, &x64, x62, x42, x44);
    fiat_mulx_u64(&x65, &x66, 0x26, x63);
    fiat_mulx_u64(&x67, &x68, 0x26, x61);
    fiat_mulx_u64(&x69, &x70, 0x26, x59);
    fiat_mulx_u64(&x71, &x72, 0x26, x57);
    fiat_addcarryx_u64(&x73, &x74, 0x0, x51, x69);
    fiat_addcarryx_u64(&x75, &x76, x74, x53, x67);
    fiat_addcarryx_u64(&x77, &x78, x76, x55, x65);
    x79 = (x78 + x66);
    fiat_addcarryx_u64(&x80, &x81, 0x0, x49, x71);
    fiat_addcarryx_u64(&x82, &x83, x81, x73, x72);
    fiat_addcarryx_u64(&x84, &x85, x83, x75, x70);
    fiat_addcarryx_u64(&x86, &x87, x85, x77, x68);
    x88 = (x87 + x79);
    fiat_mulx_u64(&x89, &x90, 0x26, x88);
    fiat_addcarryx_u64(&x91, &x92, 0x0, x80, x89);
    fiat_addcarryx_u64(&x93, &x94, x92, x82, 0x0);
    fiat_addcarryx_u64(&x95, &x96, x94, x84, 0x0);
    fiat_addcarryx_u64(&x97, &x98, x96, x86, 0x0);
    fiat_25519_cmovznz_u64(&x99, x98, 0x0, 0x26);
    fiat_addcarryx_u64(&x100, &x101, 0x0, x99, x91);
    out1[0] = x100, out1[1] = x93, out1[2] = x95, out1[3] = x97;
}

/**
 *  @brief Adds saturated 4-limb elements mod 2^255-19.
 *  @see BoringSSL origin, main of 2026-08-04:
 *    https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_adx.h#L169
 */
UCALL_X25519_TARGET_ADX inline void fe4_add(std::uint64_t out1[4], std::uint64_t const arg1[4],
                                            std::uint64_t const arg2[4]) noexcept {
    std::uint64_t x1, x3, x5, x7, x9, x10, x12, x14, x16, x18, x19;
    fiat_25519_uint1_t x2, x4, x6, x8, x11, x13, x15, x17, x20;
    fiat_addcarryx_u64(&x1, &x2, 0x0, (arg1[0]), (arg2[0]));
    fiat_addcarryx_u64(&x3, &x4, x2, (arg1[1]), (arg2[1]));
    fiat_addcarryx_u64(&x5, &x6, x4, (arg1[2]), (arg2[2]));
    fiat_addcarryx_u64(&x7, &x8, x6, (arg1[3]), (arg2[3]));
    fiat_25519_cmovznz_u64(&x9, x8, 0x0, 0x26);
    fiat_addcarryx_u64(&x10, &x11, 0x0, x1, x9);
    fiat_addcarryx_u64(&x12, &x13, x11, x3, 0x0);
    fiat_addcarryx_u64(&x14, &x15, x13, x5, 0x0);
    fiat_addcarryx_u64(&x16, &x17, x15, x7, 0x0);
    fiat_25519_cmovznz_u64(&x18, x17, 0x0, 0x26);
    fiat_addcarryx_u64(&x19, &x20, 0x0, x10, x18);
    out1[0] = x19, out1[1] = x12, out1[2] = x14, out1[3] = x16;
}

/**
 *  @brief Subtracts saturated 4-limb elements mod 2^255-19.
 *  @see BoringSSL origin, main of 2026-08-04:
 *    https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_adx.h#L215
 */
UCALL_X25519_TARGET_ADX inline void fe4_sub(std::uint64_t out1[4], std::uint64_t const arg1[4],
                                            std::uint64_t const arg2[4]) noexcept {
    std::uint64_t x1, x2, x4, x5, x7, x8, x10, x11, x13, x14, x16, x18, x20, x22, x23;
    fiat_25519_uint1_t x3, x6, x9, x12, x15, x17, x19, x21, x24;
    x1 = (arg2[0]);
    fiat_subborrowx_u64(&x2, &x3, 0x0, (arg1[0]), x1);
    x4 = (arg2[1]);
    fiat_subborrowx_u64(&x5, &x6, x3, (arg1[1]), x4);
    x7 = (arg2[2]);
    fiat_subborrowx_u64(&x8, &x9, x6, (arg1[2]), x7);
    x10 = (arg2[3]);
    fiat_subborrowx_u64(&x11, &x12, x9, (arg1[3]), x10);
    fiat_25519_cmovznz_u64(&x13, x12, 0x0, 0x26);
    fiat_subborrowx_u64(&x14, &x15, 0x0, x2, x13);
    fiat_subborrowx_u64(&x16, &x17, x15, x5, 0x0);
    fiat_subborrowx_u64(&x18, &x19, x17, x8, 0x0);
    fiat_subborrowx_u64(&x20, &x21, x19, x11, 0x0);
    fiat_25519_cmovznz_u64(&x22, x21, 0x0, 0x26);
    fiat_subborrowx_u64(&x23, &x24, 0x0, x14, x22);
    out1[0] = x23, out1[1] = x16, out1[2] = x18, out1[3] = x20;
}

/**
 *  @brief Multiplies a saturated 4-limb element by a small scalar constant, at most 2^58-1.
 *  @see BoringSSL origin, main of 2026-08-04:
 *    https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_adx.h#L269
 */
UCALL_X25519_TARGET_ADX inline void fe4_scmul(std::uint64_t out1[4], std::uint64_t const arg1[4],
                                              std::uint64_t arg2) noexcept {
    std::uint64_t x1, x2, x3, x4, x5, x7, x8, x9, x11, x12, x13, x15, x16, x17, x19, x21, x23, x25, x26;
    fiat_25519_uint1_t x6, x10, x14, x18, x20, x22, x24, x27;
    fiat_mulx_u64(&x1, &x2, (arg1[0]), arg2);
    fiat_mulx_u64(&x3, &x4, (arg1[1]), arg2);
    fiat_addcarryx_u64(&x5, &x6, 0x0, x2, x3);
    fiat_mulx_u64(&x7, &x8, (arg1[2]), arg2);
    fiat_addcarryx_u64(&x9, &x10, x6, x4, x7);
    fiat_mulx_u64(&x11, &x12, (arg1[3]), arg2);
    fiat_addcarryx_u64(&x13, &x14, x10, x8, x11);
    fiat_mulx_u64(&x15, &x16, (x12 + (std::uint64_t)x14), 0x26);
    fiat_addcarryx_u64(&x17, &x18, 0x0, x1, x15);
    fiat_addcarryx_u64(&x19, &x20, x18, x5, 0x0);
    fiat_addcarryx_u64(&x21, &x22, x20, x9, 0x0);
    fiat_addcarryx_u64(&x23, &x24, x22, x13, 0x0);
    fiat_25519_cmovznz_u64(&x25, x24, 0x0, 0x26);
    fiat_addcarryx_u64(&x26, &x27, 0x0, x17, x25);
    out1[0] = x26, out1[1] = x19, out1[2] = x21, out1[3] = x23;
}

/**
 *  @brief Reduces a saturated 4-limb element to its canonical representative below 2^255-19.
 *  @see BoringSSL origin, main of 2026-08-04:
 *    https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_adx.h#L324
 */
UCALL_X25519_TARGET_ADX inline void fe4_canon(std::uint64_t out1[4], std::uint64_t const arg1[4]) noexcept {
    std::uint64_t x1, x3, x5, x7, x9, x10, x11, x12, x13, x15, x17, x19, x21, x22, x23, x24;
    fiat_25519_uint1_t x2, x4, x6, x8, x14, x16, x18, x20;
    fiat_subborrowx_u64(&x1, &x2, 0x0, (arg1[0]), 0xffffffffffffffedULL);
    fiat_subborrowx_u64(&x3, &x4, x2, (arg1[1]), 0xffffffffffffffffULL);
    fiat_subborrowx_u64(&x5, &x6, x4, (arg1[2]), 0xffffffffffffffffULL);
    fiat_subborrowx_u64(&x7, &x8, x6, (arg1[3]), 0x7fffffffffffffffULL);
    fiat_25519_cmovznz_u64(&x9, x8, x1, (arg1[0]));
    fiat_25519_cmovznz_u64(&x10, x8, x3, (arg1[1]));
    fiat_25519_cmovznz_u64(&x11, x8, x5, (arg1[2]));
    fiat_25519_cmovznz_u64(&x12, x8, x7, (arg1[3]));
    fiat_subborrowx_u64(&x13, &x14, 0x0, x9, 0xffffffffffffffedULL);
    fiat_subborrowx_u64(&x15, &x16, x14, x10, 0xffffffffffffffffULL);
    fiat_subborrowx_u64(&x17, &x18, x16, x11, 0xffffffffffffffffULL);
    fiat_subborrowx_u64(&x19, &x20, x18, x12, 0x7fffffffffffffffULL);
    fiat_25519_cmovznz_u64(&x21, x20, x13, x9);
    fiat_25519_cmovznz_u64(&x22, x20, x15, x10);
    fiat_25519_cmovznz_u64(&x23, x20, x17, x11);
    fiat_25519_cmovznz_u64(&x24, x20, x19, x12);
    out1[0] = x21, out1[1] = x22, out1[2] = x23, out1[3] = x24;
}

/**
 *  @brief Constant-time conditional swap of two saturated 4-limb elements; outputs may alias inputs.
 *  @see BoringSSL origin, main of 2026-08-04:
 *    https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_adx.h#L381
 */
UCALL_X25519_TARGET_ADX inline void fe4_cswap(std::uint64_t out1[4], std::uint64_t out2[4], fiat_25519_uint1_t arg1,
                                              std::uint64_t const arg2[4], std::uint64_t const arg3[4]) noexcept {
    std::uint64_t x1, x2, x3, x4, x5, x6, x7, x8;
    fiat_25519_cmovznz_u64(&x1, arg1, (arg2[0]), (arg3[0]));
    fiat_25519_cmovznz_u64(&x2, arg1, (arg2[1]), (arg3[1]));
    fiat_25519_cmovznz_u64(&x3, arg1, (arg2[2]), (arg3[2]));
    fiat_25519_cmovznz_u64(&x4, arg1, (arg2[3]), (arg3[3]));
    fiat_25519_cmovznz_u64(&x5, arg1, (arg3[0]), (arg2[0]));
    fiat_25519_cmovznz_u64(&x6, arg1, (arg3[1]), (arg2[1]));
    fiat_25519_cmovznz_u64(&x7, arg1, (arg3[2]), (arg2[2]));
    fiat_25519_cmovznz_u64(&x8, arg1, (arg3[3]), (arg2[3]));
    out1[0] = x1, out1[1] = x2, out1[2] = x3, out1[3] = x4, out2[0] = x5, out2[1] = x6, out2[2] = x7, out2[3] = x8;
}

/**
 *  @brief The saturated field backend: four full 64-bit limbs, little-endian, carry-chained.
 *
 *  `fe4` is fiat's name for this shape - a field element in four limbs. Values stay
 *  unreduced anywhere below 2^256 between operations; @c fe4_canon produces the canonical
 *  representative below 2^255-19 only at serialization.
 */
struct field_adx_t {
    struct element_t {
        std::uint64_t limb[4];
    };

    static element_t zero() noexcept { return {{0, 0, 0, 0}}; }
    static element_t one() noexcept { return {{1, 0, 0, 0}}; }

    static void add(element_t &out, element_t const &first, element_t const &second) noexcept {
        fe4_add(out.limb, first.limb, second.limb);
    }

    static void subtract(element_t &out, element_t const &first, element_t const &second) noexcept {
        fe4_sub(out.limb, first.limb, second.limb);
    }

    /** @brief May alias @p out with either input - fiat kernels read everything before writing. */
    static void multiply(element_t &out, element_t const &first, element_t const &second) noexcept {
        fiat_25519_solinas_mul(out.limb, first.limb, second.limb);
    }

    static void square(element_t &out, element_t const &value) noexcept {
        fiat_25519_solinas_square(out.limb, value.limb);
    }

    static void multiply_small(element_t &out, element_t const &value, std::uint64_t small) noexcept {
        fe4_scmul(out.limb, value.limb, small);
    }

    /** @brief Constant-time swap when @p bit is 1: a barriered mask select, never a branch. */
    static void conditional_swap(element_t &first, element_t &second, std::uint64_t bit) noexcept {
        fe4_cswap(first.limb, second.limb, (fiat_25519_uint1_t)bit, first.limb, second.limb);
    }

    /** @brief Precondition: bit 255 of @p bytes is already clear - the caller masks it per RFC 7748 §5. */
    static void from_bytes(element_t &out, std::uint8_t const bytes[x25519_key_size_k]) noexcept {
        for (std::size_t limb_index = 0; limb_index != 4; ++limb_index) {
            std::uint64_t assembled = 0;
            for (std::size_t byte_index = 0; byte_index != 8; ++byte_index)
                assembled |= (std::uint64_t)bytes[8 * limb_index + byte_index] << (8 * byte_index);
            out.limb[limb_index] = assembled;
        }
    }

    static void to_bytes(std::uint8_t bytes[x25519_key_size_k], element_t const &value) noexcept {
        element_t canonical;
        fe4_canon(canonical.limb, value.limb);
        for (std::size_t limb_index = 0; limb_index != 4; ++limb_index)
            for (std::size_t byte_index = 0; byte_index != 8; ++byte_index)
                bytes[8 * limb_index + byte_index] = (std::uint8_t)(canonical.limb[limb_index] >> (8 * byte_index));
    }
};

#pragma endregion Saturated Field Arithmetic

#pragma region RFC 7748 Ladder

template <typename field_type_>
void field_square_repeated(typename field_type_::element_t &value, unsigned count) noexcept {
    for (unsigned index = 0; index != count; ++index) field_type_::square(value, value);
}

/**
 *  @brief Modular inversion via Fermat: @p out = @p value ^ (p-2) mod p, p = 2^255-19.
 *
 *  The squaring counts are forced by the exponent p-2 = 2^255-21 in binary - 250 set bits,
 *  then 01011 - via the standard square-and-multiply-by-`2^k-1` chain. See the inversion
 *  permalink in this file's header comment for one worked reference.
 */
template <typename field_type_>
void field_invert(typename field_type_::element_t &out, typename field_type_::element_t const &value) noexcept {
    using element_t = typename field_type_::element_t;

    element_t squared;
    field_type_::square(squared, value); // value^2

    element_t power_9;
    field_type_::square(power_9, squared);
    field_type_::square(power_9, power_9);          // value^8
    field_type_::multiply(power_9, value, power_9); // value^9

    element_t power_11;
    field_type_::multiply(power_11, squared, power_9); // value^11

    element_t power_2_5_minus_1;
    field_type_::square(power_2_5_minus_1, power_11);
    field_type_::multiply(power_2_5_minus_1, power_9, power_2_5_minus_1); // value^(2^5-1)

    element_t power_2_10_minus_1 = power_2_5_minus_1;
    field_square_repeated<field_type_>(power_2_10_minus_1, 5);
    field_type_::multiply(power_2_10_minus_1, power_2_10_minus_1, power_2_5_minus_1); // value^(2^10-1)

    element_t power_2_20_minus_1 = power_2_10_minus_1;
    field_square_repeated<field_type_>(power_2_20_minus_1, 10);
    field_type_::multiply(power_2_20_minus_1, power_2_20_minus_1, power_2_10_minus_1); // value^(2^20-1)

    element_t power_2_40_minus_1 = power_2_20_minus_1;
    field_square_repeated<field_type_>(power_2_40_minus_1, 20);
    field_type_::multiply(power_2_40_minus_1, power_2_40_minus_1, power_2_20_minus_1); // value^(2^40-1)

    element_t power_2_50_minus_1 = power_2_40_minus_1;
    field_square_repeated<field_type_>(power_2_50_minus_1, 10);
    field_type_::multiply(power_2_50_minus_1, power_2_50_minus_1, power_2_10_minus_1); // value^(2^50-1)

    element_t power_2_100_minus_1 = power_2_50_minus_1;
    field_square_repeated<field_type_>(power_2_100_minus_1, 50);
    field_type_::multiply(power_2_100_minus_1, power_2_100_minus_1, power_2_50_minus_1); // value^(2^100-1)

    element_t power_2_200_minus_1 = power_2_100_minus_1;
    field_square_repeated<field_type_>(power_2_200_minus_1, 100);
    field_type_::multiply(power_2_200_minus_1, power_2_200_minus_1, power_2_100_minus_1); // value^(2^200-1)

    element_t power_2_250_minus_1 = power_2_200_minus_1;
    field_square_repeated<field_type_>(power_2_250_minus_1, 50);
    field_type_::multiply(power_2_250_minus_1, power_2_250_minus_1, power_2_50_minus_1); // value^(2^250-1)

    field_square_repeated<field_type_>(power_2_250_minus_1, 5); // value^(2^255-2^5)
    field_type_::multiply(out, power_2_250_minus_1, power_11);  // value^(2^255-32+11) = value^(p-2)
}

/**
 *  @brief The Montgomery ladder of RFC 7748 §5, transcribed with the specification's own
 *    variable names so it reads side by side with the RFC text rather than any implementation.
 */
template <typename field_type_>
void montgomery_ladder(typename field_type_::element_t &output_u, std::uint8_t const clamped_scalar[x25519_key_size_k],
                       typename field_type_::element_t const &x1) noexcept {
    using element_t = typename field_type_::element_t;

    element_t x2 = field_type_::one();
    element_t z2 = field_type_::zero();
    element_t x3 = x1;
    element_t z3 = field_type_::one();
    std::uint64_t swap = 0;

    for (int bit_index = 254; bit_index >= 0; --bit_index) {
        std::uint64_t const scalar_bit = (clamped_scalar[bit_index / 8] >> (bit_index % 8)) & 1u;
        swap ^= scalar_bit;
        field_type_::conditional_swap(x2, x3, swap);
        field_type_::conditional_swap(z2, z3, swap);
        swap = scalar_bit;

        element_t a, aa, b, bb, e, c, d, da, cb;
        field_type_::add(a, x2, z2);
        field_type_::square(aa, a);
        field_type_::subtract(b, x2, z2);
        field_type_::square(bb, b);
        field_type_::subtract(e, aa, bb);
        field_type_::add(c, x3, z3);
        field_type_::subtract(d, x3, z3);
        field_type_::multiply(da, d, a);
        field_type_::multiply(cb, c, b);

        element_t sum_da_cb, difference_da_cb, difference_squared;
        field_type_::add(sum_da_cb, da, cb);
        field_type_::square(x3, sum_da_cb);
        field_type_::subtract(difference_da_cb, da, cb);
        field_type_::square(difference_squared, difference_da_cb);
        field_type_::multiply(z3, x1, difference_squared);

        element_t scaled_e, aa_plus_scaled_e;
        field_type_::multiply(x2, aa, bb);
        field_type_::multiply_small(scaled_e, e, 121665u); // RFC 7748's a24 = (486662 - 2) / 4
        field_type_::add(aa_plus_scaled_e, aa, scaled_e);
        field_type_::multiply(z2, e, aa_plus_scaled_e);
    }
    field_type_::conditional_swap(x2, x3, swap);
    field_type_::conditional_swap(z2, z3, swap);

    typename field_type_::element_t z2_inverted;
    field_invert<field_type_>(z2_inverted, z2);
    field_type_::multiply(output_u, x2, z2_inverted);
}

/** @brief Clamps, runs the ladder over @p field_type_, and applies RFC 7748 §6.1's small-order check. */
template <typename field_type_>
[[nodiscard]] bool scalar_multiply_through(std::uint8_t out[x25519_key_size_k],
                                           std::uint8_t const scalar[x25519_key_size_k],
                                           std::uint8_t const point[x25519_key_size_k]) noexcept {
    std::uint8_t clamped_scalar[x25519_key_size_k];
    std::memcpy(clamped_scalar, scalar, x25519_key_size_k);
    clamped_scalar[0] &= 248;
    clamped_scalar[31] &= 127;
    clamped_scalar[31] |= 64;

    std::uint8_t masked_point[x25519_key_size_k];
    std::memcpy(masked_point, point, x25519_key_size_k);
    masked_point[31] &= 0x7Fu; // RFC 7748 §5: X25519 masks the u-coordinate's top bit.

    typename field_type_::element_t input_u, output_u;
    field_type_::from_bytes(input_u, masked_point);
    montgomery_ladder<field_type_>(output_u, clamped_scalar, input_u);
    field_type_::to_bytes(out, output_u);

    // A constant-time OR-reduction: which byte is nonzero must not be observable either.
    std::uint8_t difference_from_zero = 0;
    for (std::size_t index = 0; index != x25519_key_size_k; ++index) difference_from_zero |= out[index];
    return difference_from_zero != 0;
}

#pragma endregion RFC 7748 Ladder

} // namespace

#if defined(__SIZEOF_INT128__)
bool x25519_scalar_multiply_serial(std::uint8_t out[x25519_key_size_k], std::uint8_t const scalar[x25519_key_size_k],
                                   std::uint8_t const point[x25519_key_size_k]) noexcept {
    return scalar_multiply_through<field_serial_t>(out, scalar, point);
}
#endif

bool x25519_scalar_multiply_adx(std::uint8_t out[x25519_key_size_k], std::uint8_t const scalar[x25519_key_size_k],
                                std::uint8_t const point[x25519_key_size_k]) noexcept {
    return scalar_multiply_through<field_adx_t>(out, scalar, point);
}

bool x25519_scalar_multiply(std::uint8_t out[x25519_key_size_k], std::uint8_t const scalar[x25519_key_size_k],
                            std::uint8_t const point[x25519_key_size_k]) noexcept {
#if defined(__SIZEOF_INT128__)
    static bool const use_saturated_tier = cpu_supports_adx_and_bmi2();
    return use_saturated_tier ? x25519_scalar_multiply_adx(out, scalar, point)
                              : x25519_scalar_multiply_serial(out, scalar, point);
#else
    // Without 128-bit integers only the saturated tier compiles, and it runs on any x86-64.
    return x25519_scalar_multiply_adx(out, scalar, point);
#endif
}

void x25519_derive_public(std::uint8_t out[x25519_key_size_k], std::uint8_t const scalar[x25519_key_size_k]) noexcept {
    static constexpr std::uint8_t base_point_k[x25519_key_size_k] = {9};
    // The standard base point has prime order, so a clamped scalar never maps it to zero.
    [[maybe_unused]] bool const nonzero = x25519_scalar_multiply(out, scalar, base_point_k);
}

} // namespace unum::ucall

#undef UCALL_X25519_TARGET_ADX
