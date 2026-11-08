/**
 *  @file src/crypto_x25519.hpp
 *  @author Ash Vardanian
 *  @date August 4, 2026
 *  @brief Saturated Curve25519 field arithmetic and the RFC 7748 §5 ladder, over a kit's words.
 *
 *  Each X25519 kit is one translation unit that includes this header and names its words, a struct
 *  of @c fiat_mulx_u64, @c fiat_addcarryx_u64 and @c fiat_subborrowx_u64, which the kernels call.
 *  The words are local to the kit's function, which gives every template here internal linkage, so
 *  no unit's flags can reach another's copy.
 *
 *  @section x25519_provenance Provenance
 *
 *  Every @c fiat_25519_*, @c fiat_*_u64, and @c fe4_* kernel below is a mechanical,
 *  statement-preserving transcription of fiat-crypto's machine-verified output, whose Coq proofs
 *  cover functional correctness and constant-time execution. Only surface syntax differs: type
 *  spellings, grouped declarations, comma-collapsed assignment runs. The transcription is held to
 *  the RFC 7748 and Wycheproof vectors plus a differential suite across the kits in
 *  <tt>test/x25519.cpp</tt>, so regenerate a kernel from the pinned sources below rather than
 *  hand-editing its body. The inversion chain's shape is forced by the exponent p-2 = 2^255-21
 *  itself, so any correct Fermat inversion for this prime performs the same squarings in order.
 *
 *  @see Fiat Cryptography, the saturated @c fiat_25519_solinas_* pair: https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_solinas_64.c
 *  @see BoringSSL origin, main of 2026-08-04, the @c fe4_* family and the carry shims: https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_adx.h
 *  @see BoringSSL origin, main of 2026-08-04, the inversion chain's shape: https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/crypto/curve25519/curve25519.cc#L311-L367
 *
 *  The ladder in @c montgomery_ladder, the clamping, and the small-order check are transcribed from
 *  RFC 7748 §5's pseudocode with the specification's own variable names, and are shared by every
 *  kit through the field-backend template parameter.
 *
 *  @section x25519_licenses Licenses
 *
 *  The kernels are Copyright 2015-2020 the fiat-crypto authors, offered as MIT, Apache-2.0 or
 *  BSD-1-Clause at the recipient's option, and BoringSSL's @c third_party/fiat carries them as
 *  Apache-2.0. The inversion chain follows code Copyright 2020 The BoringSSL Authors, Apache-2.0.
 *  Both are used and modified here under the Apache License, Version 2.0, the terms of this
 *  repository's @c LICENSE file: kernels became templates over a kit's words, as described above.
 */
#pragma once

#include <cstdint> // `std::uint64_t`
#include <cstring> // `std::memcpy`

#include "ucall/tunnel/curve25519.hpp"

#if UCALL_COMPILER_MSVC_
#include <intrin.h> // `__umulh`, `_addcarry_u64`, `_subborrow_u64`
#endif

namespace unum::ucall {

using tunnel::x25519_key_size_k;
using utilities::byte_t;
using utilities::span;

#pragma region Compiler Shims

using fiat_25519_uint1_t = unsigned char;
using fiat_25519_int1_t = signed char;

/**
 *  @brief Returns @p value while hiding everything the optimizer knows about it.
 *
 *  Without this, a compiler that can prove the mask in @c fiat_25519_cmovznz_u64 is 0 or ~0 may
 *  rewrite the masked select into a branch, turning a constant-time kernel into a key-dependent
 *  one. MSVC has no empty-asm barrier and no equivalent intrinsic - @c _ReadWriteBarrier is a
 *  deprecated memory-ordering fence that does not hide a register value's range - so the conforming
 *  substitute is a volatile round-trip: the load cannot be folded, and no range fact survives it.
 *  fiat-crypto and BoringSSL both compile this barrier to a plain identity under MSVC, so the
 *  round-trip is strictly stronger.
 */
[[nodiscard]] inline static std::uint64_t value_barrier(std::uint64_t value) noexcept {
#if UCALL_COMPILER_GCC_ || UCALL_COMPILER_CLANG_
    __asm__("" : "+r"(value));
    return value;
#else
    volatile std::uint64_t laundered = value;
    return laundered;
#endif
}

/**
 *  @brief The portable words: four 32×32 → 64 partial products and carries in plain C.
 *  @tparam unit_type_ A type local to the kit's function, which keeps this instantiation internal.
 *
 *  The baseline's multiply, slower than the alternative and chosen for a property rather than for
 *  speed: with no widening operation present there is nothing a compiler can lower to @c MULX , so
 *  the serial kit stays runnable on every x86-64.
 */
template <typename unit_type_>
struct serial_words {
    static void fiat_mulx_u64(std::uint64_t* out1, std::uint64_t* out2, std::uint64_t arg1,
                              std::uint64_t arg2) noexcept {
        std::uint64_t const arg1_low = arg1 & 0xFFFFFFFFull, arg1_high = arg1 >> 32;
        std::uint64_t const arg2_low = arg2 & 0xFFFFFFFFull, arg2_high = arg2 >> 32;
        std::uint64_t partial = arg1_low * arg2_low;
        std::uint64_t const lowest_word = partial & 0xFFFFFFFFull;
        partial = arg1_high * arg2_low + (partial >> 32);
        std::uint64_t const middle_word = partial & 0xFFFFFFFFull;
        std::uint64_t const middle_carry = partial >> 32;
        partial = arg1_low * arg2_high + middle_word;
        *out1 = (partial << 32) | lowest_word;
        *out2 = arg1_high * arg2_high + middle_carry + (partial >> 32);
    }

    /**
     *  @brief 64-bit add with carry: @p out1 = @p arg2 + @p arg3 + @p arg1, @p out2 the carry-out.
     *  @see BoringSSL origin, main of 2026-08-04: https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_adx.h#L76
     */
    static void fiat_addcarryx_u64(std::uint64_t* out1, fiat_25519_uint1_t* out2, fiat_25519_uint1_t arg1,
                                   std::uint64_t arg2, std::uint64_t arg3) noexcept {
        arg2 += arg1;
        fiat_25519_uint1_t carried = arg2 < arg1;
        std::uint64_t const summed = arg2 + arg3;
        carried += summed < arg2;
        *out1 = summed, *out2 = carried;
    }

    /**
     *  @brief 64-bit subtract: @p out1 = @p arg2 - @p arg3 - @p arg1, @p out2 the borrow-out.
     *  @see BoringSSL origin, main of 2026-08-04: https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_adx.h#L116
     */
    static void fiat_subborrowx_u64(std::uint64_t* out1, fiat_25519_uint1_t* out2, fiat_25519_uint1_t arg1,
                                    std::uint64_t arg2, std::uint64_t arg3) noexcept {
        *out1 = arg2 - arg3 - arg1;
        *out2 = (arg2 < arg3) | ((arg2 == arg3) & arg1);
    }
};

/**
 *  @brief Constant-time select: @p out1 = @p arg1 ? @p arg3 : @p arg2, masked rather than branched.
 *      Every field uses it.
 *  @see Fiat Cryptography origin v0.1.6+137: https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c#L116
 */
inline static void fiat_25519_cmovznz_u64(std::uint64_t* out1, fiat_25519_uint1_t arg1, std::uint64_t arg2,
                                          std::uint64_t arg3) noexcept {
    fiat_25519_uint1_t x1;
    std::uint64_t x2, x3;
    x1 = (!(!arg1)), x2 = ((fiat_25519_int1_t)(0x0 - x1) & 0xffffffffffffffffULL),
    x3 = ((value_barrier(x2) & arg3) | (value_barrier((~x2)) & arg2)), *out1 = x3;
}

#pragma endregion Compiler Shims

#pragma region Saturated Field Arithmetic

/**
 *  @brief The saturated field backend: four full 64-bit limbs, little-endian, carry-chained.
 *
 *  The words are the only thing that separates the saturated kits, so they are the only thing
 *  parameterised: @c serial_words keeps the kernels free of any widening operation at all, and
 *  @c haswell_words_t spells them in @c MULX and @c ADC.
 *
 *  @c fe4 is fiat's name for this shape - a field element in four limbs. Values stay unreduced
 *  anywhere below 2^256 between operations; @c fe4_canon produces the canonical representative
 *  below 2^255-19 only at serialization.
 */
template <typename words_>
struct field_saturated {

    /**
     *  @brief Multiplies two saturated 4-limb elements mod 2^255-19.
     *  @see Fiat Cryptography origin v0.1.6+137: https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_solinas_64.c#L150
     */
    static void fiat_25519_solinas_mul(std::uint64_t out1[4], std::uint64_t const arg1[4],
                                       std::uint64_t const arg2[4]) noexcept {
        std::uint64_t x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21,
            x22, x23, x24, x25, x26, x27, x28, x29, x30, x31, x32, x33, x35, x37, x38, x40, x42, x44, x45, x47, x49,
            x51, x53, x55, x56, x58, x60, x62, x64, x66, x68, x70, x72, x74, x76, x78, x80, x82, x84, x86, x88, x90,
            x92, x94, x96, x97, x98, x99, x100, x101, x102, x103, x104, x106, x108, x110, x111, x113, x115, x117, x119,
            x120, x121, x122, x124, x126, x128, x130, x131;
        fiat_25519_uint1_t x34, x36, x39, x41, x43, x46, x48, x50, x52, x54, x57, x59, x61, x63, x65, x67, x69, x71,
            x73, x75, x77, x79, x81, x83, x85, x87, x89, x91, x93, x95, x105, x107, x109, x112, x114, x116, x118, x123,
            x125, x127, x129, x132;
        words_::fiat_mulx_u64(&x1, &x2, (arg1[3]), (arg2[3]));
        words_::fiat_mulx_u64(&x3, &x4, (arg1[3]), (arg2[2]));
        words_::fiat_mulx_u64(&x5, &x6, (arg1[3]), (arg2[1]));
        words_::fiat_mulx_u64(&x7, &x8, (arg1[3]), (arg2[0]));
        words_::fiat_mulx_u64(&x9, &x10, (arg1[2]), (arg2[3]));
        words_::fiat_mulx_u64(&x11, &x12, (arg1[2]), (arg2[2]));
        words_::fiat_mulx_u64(&x13, &x14, (arg1[2]), (arg2[1]));
        words_::fiat_mulx_u64(&x15, &x16, (arg1[2]), (arg2[0]));
        words_::fiat_mulx_u64(&x17, &x18, (arg1[1]), (arg2[3]));
        words_::fiat_mulx_u64(&x19, &x20, (arg1[1]), (arg2[2]));
        words_::fiat_mulx_u64(&x21, &x22, (arg1[1]), (arg2[1]));
        words_::fiat_mulx_u64(&x23, &x24, (arg1[1]), (arg2[0]));
        words_::fiat_mulx_u64(&x25, &x26, (arg1[0]), (arg2[3]));
        words_::fiat_mulx_u64(&x27, &x28, (arg1[0]), (arg2[2]));
        words_::fiat_mulx_u64(&x29, &x30, (arg1[0]), (arg2[1]));
        words_::fiat_mulx_u64(&x31, &x32, (arg1[0]), (arg2[0]));
        words_::fiat_addcarryx_u64(&x33, &x34, 0x0, x28, x7);
        words_::fiat_addcarryx_u64(&x35, &x36, x34, x26, x5);
        x37 = (x36 + x18);
        words_::fiat_addcarryx_u64(&x38, &x39, 0x0, x33, x13);
        words_::fiat_addcarryx_u64(&x40, &x41, x39, x35, x8);
        words_::fiat_addcarryx_u64(&x42, &x43, x41, x37, 0x0);
        x44 = (x43 + x10);
        words_::fiat_addcarryx_u64(&x45, &x46, 0x0, x30, x15);
        words_::fiat_addcarryx_u64(&x47, &x48, x46, x38, x16);
        words_::fiat_addcarryx_u64(&x49, &x50, x48, x40, x11);
        words_::fiat_addcarryx_u64(&x51, &x52, x50, x42, x3);
        words_::fiat_addcarryx_u64(&x53, &x54, x52, x44, 0x0);
        x55 = (x54 + x2);
        words_::fiat_addcarryx_u64(&x56, &x57, 0x0, x45, x21);
        words_::fiat_addcarryx_u64(&x58, &x59, x57, x47, x19);
        words_::fiat_addcarryx_u64(&x60, &x61, x59, x49, x14);
        words_::fiat_addcarryx_u64(&x62, &x63, x61, x51, x6);
        words_::fiat_addcarryx_u64(&x64, &x65, x63, x53, 0x0);
        words_::fiat_addcarryx_u64(&x66, &x67, x65, x55, 0x0);
        words_::fiat_addcarryx_u64(&x68, &x69, 0x0, x32, x23);
        words_::fiat_addcarryx_u64(&x70, &x71, x69, x56, x24);
        words_::fiat_addcarryx_u64(&x72, &x73, x71, x58, x22);
        words_::fiat_addcarryx_u64(&x74, &x75, x73, x60, x17);
        words_::fiat_addcarryx_u64(&x76, &x77, x75, x62, x9);
        words_::fiat_addcarryx_u64(&x78, &x79, x77, x64, x1);
        words_::fiat_addcarryx_u64(&x80, &x81, x79, x66, 0x0);
        words_::fiat_addcarryx_u64(&x82, &x83, 0x0, x68, x29);
        words_::fiat_addcarryx_u64(&x84, &x85, x83, x70, x27);
        words_::fiat_addcarryx_u64(&x86, &x87, x85, x72, x25);
        words_::fiat_addcarryx_u64(&x88, &x89, x87, x74, x20);
        words_::fiat_addcarryx_u64(&x90, &x91, x89, x76, x12);
        words_::fiat_addcarryx_u64(&x92, &x93, x91, x78, x4);
        words_::fiat_addcarryx_u64(&x94, &x95, x93, x80, 0x0);
        words_::fiat_mulx_u64(&x96, &x97, 0x26, x94);
        words_::fiat_mulx_u64(&x98, &x99, 0x26, x92);
        words_::fiat_mulx_u64(&x100, &x101, 0x26, x90);
        words_::fiat_mulx_u64(&x102, &x103, 0x26, x88);
        words_::fiat_addcarryx_u64(&x104, &x105, 0x0, x82, x100);
        words_::fiat_addcarryx_u64(&x106, &x107, x105, x84, x98);
        words_::fiat_addcarryx_u64(&x108, &x109, x107, x86, x96);
        x110 = (x109 + x97);
        words_::fiat_addcarryx_u64(&x111, &x112, 0x0, x31, x102);
        words_::fiat_addcarryx_u64(&x113, &x114, x112, x104, x103);
        words_::fiat_addcarryx_u64(&x115, &x116, x114, x106, x101);
        words_::fiat_addcarryx_u64(&x117, &x118, x116, x108, x99);
        x119 = (x118 + x110);
        words_::fiat_mulx_u64(&x120, &x121, 0x26, x119);
        words_::fiat_addcarryx_u64(&x122, &x123, 0x0, x111, x120);
        words_::fiat_addcarryx_u64(&x124, &x125, x123, x113, 0x0);
        words_::fiat_addcarryx_u64(&x126, &x127, x125, x115, 0x0);
        words_::fiat_addcarryx_u64(&x128, &x129, x127, x117, 0x0);
        fiat_25519_cmovznz_u64(&x130, x129, 0x0, 0x26);
        words_::fiat_addcarryx_u64(&x131, &x132, 0x0, x130, x122);
        out1[0] = x131, out1[1] = x124, out1[2] = x126, out1[3] = x128;
    }

    /**
     *  @brief Squares a saturated 4-limb element mod 2^255-19.
     *  @see Fiat Cryptography origin v0.1.6+137: https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_solinas_64.c#L369
     */
    static void fiat_25519_solinas_square(std::uint64_t out1[4], std::uint64_t const arg1[4]) noexcept {
        std::uint64_t x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x13, x15, x17, x19, x20, x21, x22, x24, x26, x28,
            x30, x32, x34, x36, x38, x40, x42, x43, x44, x45, x46, x47, x48, x49, x50, x51, x53, x55, x57, x59, x61,
            x63, x65, x66, x67, x68, x69, x70, x71, x72, x73, x75, x77, x79, x80, x82, x84, x86, x88, x89, x90, x91,
            x93, x95, x97, x99, x100;
        fiat_25519_uint1_t x12, x14, x16, x18, x23, x25, x27, x29, x31, x33, x35, x37, x39, x41, x52, x54, x56, x58,
            x60, x62, x64, x74, x76, x78, x81, x83, x85, x87, x92, x94, x96, x98, x101;
        words_::fiat_mulx_u64(&x1, &x2, (arg1[0]), (arg1[3]));
        words_::fiat_mulx_u64(&x3, &x4, (arg1[0]), (arg1[2]));
        words_::fiat_mulx_u64(&x5, &x6, (arg1[0]), (arg1[1]));
        words_::fiat_mulx_u64(&x7, &x8, (arg1[3]), (arg1[2]));
        words_::fiat_mulx_u64(&x9, &x10, (arg1[3]), (arg1[1]));
        words_::fiat_addcarryx_u64(&x11, &x12, 0x0, x6, x3);
        words_::fiat_addcarryx_u64(&x13, &x14, x12, x4, x1);
        words_::fiat_addcarryx_u64(&x15, &x16, x14, x2, x9);
        words_::fiat_addcarryx_u64(&x17, &x18, x16, x10, x7);
        x19 = (x18 + x8);
        words_::fiat_mulx_u64(&x20, &x21, (arg1[1]), (arg1[2]));
        words_::fiat_addcarryx_u64(&x22, &x23, 0x0, x13, x20);
        words_::fiat_addcarryx_u64(&x24, &x25, x23, x15, x21);
        words_::fiat_addcarryx_u64(&x26, &x27, x25, x17, 0x0);
        words_::fiat_addcarryx_u64(&x28, &x29, x27, x19, 0x0);
        words_::fiat_addcarryx_u64(&x30, &x31, 0x0, x5, x5);
        words_::fiat_addcarryx_u64(&x32, &x33, x31, x11, x11);
        words_::fiat_addcarryx_u64(&x34, &x35, x33, x22, x22);
        words_::fiat_addcarryx_u64(&x36, &x37, x35, x24, x24);
        words_::fiat_addcarryx_u64(&x38, &x39, x37, x26, x26);
        words_::fiat_addcarryx_u64(&x40, &x41, x39, x28, x28);
        x42 = (((std::uint64_t)x41 + x29) + (std::uint64_t)x29);
        words_::fiat_mulx_u64(&x43, &x44, (arg1[3]), (arg1[3]));
        words_::fiat_mulx_u64(&x45, &x46, (arg1[2]), (arg1[2]));
        words_::fiat_mulx_u64(&x47, &x48, (arg1[1]), (arg1[1]));
        words_::fiat_mulx_u64(&x49, &x50, (arg1[0]), (arg1[0]));
        words_::fiat_addcarryx_u64(&x51, &x52, 0x0, x30, x50);
        words_::fiat_addcarryx_u64(&x53, &x54, x52, x32, x47);
        words_::fiat_addcarryx_u64(&x55, &x56, x54, x34, x48);
        words_::fiat_addcarryx_u64(&x57, &x58, x56, x36, x45);
        words_::fiat_addcarryx_u64(&x59, &x60, x58, x38, x46);
        words_::fiat_addcarryx_u64(&x61, &x62, x60, x40, x43);
        words_::fiat_addcarryx_u64(&x63, &x64, x62, x42, x44);
        words_::fiat_mulx_u64(&x65, &x66, 0x26, x63);
        words_::fiat_mulx_u64(&x67, &x68, 0x26, x61);
        words_::fiat_mulx_u64(&x69, &x70, 0x26, x59);
        words_::fiat_mulx_u64(&x71, &x72, 0x26, x57);
        words_::fiat_addcarryx_u64(&x73, &x74, 0x0, x51, x69);
        words_::fiat_addcarryx_u64(&x75, &x76, x74, x53, x67);
        words_::fiat_addcarryx_u64(&x77, &x78, x76, x55, x65);
        x79 = (x78 + x66);
        words_::fiat_addcarryx_u64(&x80, &x81, 0x0, x49, x71);
        words_::fiat_addcarryx_u64(&x82, &x83, x81, x73, x72);
        words_::fiat_addcarryx_u64(&x84, &x85, x83, x75, x70);
        words_::fiat_addcarryx_u64(&x86, &x87, x85, x77, x68);
        x88 = (x87 + x79);
        words_::fiat_mulx_u64(&x89, &x90, 0x26, x88);
        words_::fiat_addcarryx_u64(&x91, &x92, 0x0, x80, x89);
        words_::fiat_addcarryx_u64(&x93, &x94, x92, x82, 0x0);
        words_::fiat_addcarryx_u64(&x95, &x96, x94, x84, 0x0);
        words_::fiat_addcarryx_u64(&x97, &x98, x96, x86, 0x0);
        fiat_25519_cmovznz_u64(&x99, x98, 0x0, 0x26);
        words_::fiat_addcarryx_u64(&x100, &x101, 0x0, x99, x91);
        out1[0] = x100, out1[1] = x93, out1[2] = x95, out1[3] = x97;
    }

    /**
     *  @brief Adds saturated 4-limb elements mod 2^255-19.
     *  @see BoringSSL origin, main of 2026-08-04: https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_adx.h#L169
     */
    static void fe4_add(std::uint64_t out1[4], std::uint64_t const arg1[4], std::uint64_t const arg2[4]) noexcept {
        std::uint64_t x1, x3, x5, x7, x9, x10, x12, x14, x16, x18, x19;
        fiat_25519_uint1_t x2, x4, x6, x8, x11, x13, x15, x17, x20;
        words_::fiat_addcarryx_u64(&x1, &x2, 0x0, (arg1[0]), (arg2[0]));
        words_::fiat_addcarryx_u64(&x3, &x4, x2, (arg1[1]), (arg2[1]));
        words_::fiat_addcarryx_u64(&x5, &x6, x4, (arg1[2]), (arg2[2]));
        words_::fiat_addcarryx_u64(&x7, &x8, x6, (arg1[3]), (arg2[3]));
        fiat_25519_cmovznz_u64(&x9, x8, 0x0, 0x26);
        words_::fiat_addcarryx_u64(&x10, &x11, 0x0, x1, x9);
        words_::fiat_addcarryx_u64(&x12, &x13, x11, x3, 0x0);
        words_::fiat_addcarryx_u64(&x14, &x15, x13, x5, 0x0);
        words_::fiat_addcarryx_u64(&x16, &x17, x15, x7, 0x0);
        fiat_25519_cmovznz_u64(&x18, x17, 0x0, 0x26);
        words_::fiat_addcarryx_u64(&x19, &x20, 0x0, x10, x18);
        out1[0] = x19, out1[1] = x12, out1[2] = x14, out1[3] = x16;
    }

    /**
     *  @brief Subtracts saturated 4-limb elements mod 2^255-19.
     *  @see BoringSSL origin, main of 2026-08-04: https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_adx.h#L215
     */
    static void fe4_sub(std::uint64_t out1[4], std::uint64_t const arg1[4], std::uint64_t const arg2[4]) noexcept {
        std::uint64_t x1, x2, x4, x5, x7, x8, x10, x11, x13, x14, x16, x18, x20, x22, x23;
        fiat_25519_uint1_t x3, x6, x9, x12, x15, x17, x19, x21, x24;
        x1 = (arg2[0]);
        words_::fiat_subborrowx_u64(&x2, &x3, 0x0, (arg1[0]), x1);
        x4 = (arg2[1]);
        words_::fiat_subborrowx_u64(&x5, &x6, x3, (arg1[1]), x4);
        x7 = (arg2[2]);
        words_::fiat_subborrowx_u64(&x8, &x9, x6, (arg1[2]), x7);
        x10 = (arg2[3]);
        words_::fiat_subborrowx_u64(&x11, &x12, x9, (arg1[3]), x10);
        fiat_25519_cmovznz_u64(&x13, x12, 0x0, 0x26);
        words_::fiat_subborrowx_u64(&x14, &x15, 0x0, x2, x13);
        words_::fiat_subborrowx_u64(&x16, &x17, x15, x5, 0x0);
        words_::fiat_subborrowx_u64(&x18, &x19, x17, x8, 0x0);
        words_::fiat_subborrowx_u64(&x20, &x21, x19, x11, 0x0);
        fiat_25519_cmovznz_u64(&x22, x21, 0x0, 0x26);
        words_::fiat_subborrowx_u64(&x23, &x24, 0x0, x14, x22);
        out1[0] = x23, out1[1] = x16, out1[2] = x18, out1[3] = x20;
    }

    /**
     *  @brief Multiplies a saturated 4-limb element by a small scalar constant, at most 2^58-1.
     *  @see BoringSSL origin, main of 2026-08-04: https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_adx.h#L269
     */
    static void fe4_scmul(std::uint64_t out1[4], std::uint64_t const arg1[4], std::uint64_t arg2) noexcept {
        std::uint64_t x1, x2, x3, x4, x5, x7, x8, x9, x11, x12, x13, x15, x16, x17, x19, x21, x23, x25, x26;
        fiat_25519_uint1_t x6, x10, x14, x18, x20, x22, x24, x27;
        words_::fiat_mulx_u64(&x1, &x2, (arg1[0]), arg2);
        words_::fiat_mulx_u64(&x3, &x4, (arg1[1]), arg2);
        words_::fiat_addcarryx_u64(&x5, &x6, 0x0, x2, x3);
        words_::fiat_mulx_u64(&x7, &x8, (arg1[2]), arg2);
        words_::fiat_addcarryx_u64(&x9, &x10, x6, x4, x7);
        words_::fiat_mulx_u64(&x11, &x12, (arg1[3]), arg2);
        words_::fiat_addcarryx_u64(&x13, &x14, x10, x8, x11);
        words_::fiat_mulx_u64(&x15, &x16, (x12 + (std::uint64_t)x14), 0x26);
        words_::fiat_addcarryx_u64(&x17, &x18, 0x0, x1, x15);
        words_::fiat_addcarryx_u64(&x19, &x20, x18, x5, 0x0);
        words_::fiat_addcarryx_u64(&x21, &x22, x20, x9, 0x0);
        words_::fiat_addcarryx_u64(&x23, &x24, x22, x13, 0x0);
        fiat_25519_cmovznz_u64(&x25, x24, 0x0, 0x26);
        words_::fiat_addcarryx_u64(&x26, &x27, 0x0, x17, x25);
        out1[0] = x26, out1[1] = x19, out1[2] = x21, out1[3] = x23;
    }

    /**
     *  @brief Reduces a saturated 4-limb element to its canonical representative below 2^255-19.
     *  @see BoringSSL origin, main of 2026-08-04: https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_adx.h#L324
     */
    static void fe4_canon(std::uint64_t out1[4], std::uint64_t const arg1[4]) noexcept {
        std::uint64_t x1, x3, x5, x7, x9, x10, x11, x12, x13, x15, x17, x19, x21, x22, x23, x24;
        fiat_25519_uint1_t x2, x4, x6, x8, x14, x16, x18, x20;
        words_::fiat_subborrowx_u64(&x1, &x2, 0x0, (arg1[0]), 0xffffffffffffffedULL);
        words_::fiat_subborrowx_u64(&x3, &x4, x2, (arg1[1]), 0xffffffffffffffffULL);
        words_::fiat_subborrowx_u64(&x5, &x6, x4, (arg1[2]), 0xffffffffffffffffULL);
        words_::fiat_subborrowx_u64(&x7, &x8, x6, (arg1[3]), 0x7fffffffffffffffULL);
        fiat_25519_cmovznz_u64(&x9, x8, x1, (arg1[0]));
        fiat_25519_cmovznz_u64(&x10, x8, x3, (arg1[1]));
        fiat_25519_cmovznz_u64(&x11, x8, x5, (arg1[2]));
        fiat_25519_cmovznz_u64(&x12, x8, x7, (arg1[3]));
        words_::fiat_subborrowx_u64(&x13, &x14, 0x0, x9, 0xffffffffffffffedULL);
        words_::fiat_subborrowx_u64(&x15, &x16, x14, x10, 0xffffffffffffffffULL);
        words_::fiat_subborrowx_u64(&x17, &x18, x16, x11, 0xffffffffffffffffULL);
        words_::fiat_subborrowx_u64(&x19, &x20, x18, x12, 0x7fffffffffffffffULL);
        fiat_25519_cmovznz_u64(&x21, x20, x13, x9);
        fiat_25519_cmovznz_u64(&x22, x20, x15, x10);
        fiat_25519_cmovznz_u64(&x23, x20, x17, x11);
        fiat_25519_cmovznz_u64(&x24, x20, x19, x12);
        out1[0] = x21, out1[1] = x22, out1[2] = x23, out1[3] = x24;
    }

    /**
     *  @brief Constant-time conditional swap of two saturated 4-limb elements; outputs may alias.
     *  @see BoringSSL origin, main of 2026-08-04: https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_adx.h#L381
     */
    static void fe4_cswap(std::uint64_t out1[4], std::uint64_t out2[4], fiat_25519_uint1_t arg1,
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

    struct element_t {
        std::uint64_t limb[4];
    };

    static element_t zero() noexcept { return {{0, 0, 0, 0}}; }
    static element_t one() noexcept { return {{1, 0, 0, 0}}; }

    static void add(element_t& out, element_t const& first, element_t const& second) noexcept {
        fe4_add(out.limb, first.limb, second.limb);
    }

    static void subtract(element_t& out, element_t const& first, element_t const& second) noexcept {
        fe4_sub(out.limb, first.limb, second.limb);
    }

    /** May alias @p out with either input - fiat kernels read everything before writing. */
    static void multiply(element_t& out, element_t const& first, element_t const& second) noexcept {
        fiat_25519_solinas_mul(out.limb, first.limb, second.limb);
    }

    static void square(element_t& out, element_t const& value) noexcept {
        fiat_25519_solinas_square(out.limb, value.limb);
    }

    static void multiply_121666(element_t& out, element_t const& value) noexcept {
        fe4_scmul(out.limb, value.limb, 121666);
    }

    /** Constant-time swap when @p bit is 1: a barriered mask select, never a branch. */
    static void conditional_swap(element_t& first, element_t& second, std::uint64_t bit) noexcept {
        fe4_cswap(first.limb, second.limb, (fiat_25519_uint1_t)bit, first.limb, second.limb);
    }

    /** Precondition: bit 255 of @p bytes is already clear - the caller masks it per RFC 7748 §5. */
    static void from_bytes(element_t& out, std::uint8_t const bytes[x25519_key_size_k]) noexcept {
        for (std::size_t limb_index = 0; limb_index != 4; ++limb_index) {
            std::uint64_t assembled = 0;
            for (std::size_t byte_index = 0; byte_index != 8; ++byte_index)
                assembled |= (std::uint64_t)bytes[8 * limb_index + byte_index] << (8 * byte_index);
            out.limb[limb_index] = assembled;
        }
    }

    static void to_bytes(std::uint8_t bytes[x25519_key_size_k], element_t const& value) noexcept {
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
inline static void field_square_repeated(typename field_type_::element_t& value, unsigned count) noexcept {
    for (unsigned index = 0; index != count; ++index) field_type_::square(value, value);
}

/**
 *  @brief Modular inversion via Fermat: @p out = @p value ^ (p-2) mod p, p = 2^255-19.
 *
 *  The squaring counts are forced by the exponent p-2 = 2^255-21 in binary - 250 set bits, then
 *  01011 - via the standard square-and-multiply-by-<tt>2^k-1</tt> chain. See the inversion permalink
 *  in this file's header comment for one worked reference.
 */
template <typename field_type_>
inline static void field_invert(typename field_type_::element_t& out,
                                typename field_type_::element_t const& value) noexcept {
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

/** The Montgomery ladder of RFC 7748 §5, transcribed with the specification's own variable names
 *  so it reads side by side with the RFC text rather than any implementation. */
template <typename field_type_>
inline static void montgomery_ladder(typename field_type_::element_t& output_u,
                                     std::uint8_t const clamped_scalar[x25519_key_size_k],
                                     typename field_type_::element_t const& x1) noexcept {
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

        // RFC 7748's AA + 121665 × E is BB + 121666 × E, as E = AA - BB; fiat proves that scale.
        element_t scaled_e, bb_plus_scaled_e;
        field_type_::multiply(x2, aa, bb);
        field_type_::multiply_121666(scaled_e, e);
        field_type_::add(bb_plus_scaled_e, bb, scaled_e);
        field_type_::multiply(z2, e, bb_plus_scaled_e);
    }
    field_type_::conditional_swap(x2, x3, swap);
    field_type_::conditional_swap(z2, z3, swap);

    typename field_type_::element_t z2_inverted;
    field_invert<field_type_>(z2_inverted, z2);
    field_type_::multiply(output_u, x2, z2_inverted);
}

/** Clamps, runs the ladder over @p field_type_, and applies RFC 7748 §6.1's small-order check. */
template <typename field_type_>
[[nodiscard]] inline static bool scalar_multiply_through(span<byte_t, x25519_key_size_k> out,
                                                         span<byte_t const, x25519_key_size_k> scalar,
                                                         span<byte_t const, x25519_key_size_k> point) noexcept {
    std::uint8_t clamped_scalar[x25519_key_size_k];
    std::memcpy(clamped_scalar, scalar.data(), x25519_key_size_k);
    clamped_scalar[0] &= 248;
    clamped_scalar[31] &= 127;
    clamped_scalar[31] |= 64;

    std::uint8_t masked_point[x25519_key_size_k];
    std::memcpy(masked_point, point.data(), x25519_key_size_k);
    masked_point[31] &= 0x7Fu; // RFC 7748 §5: X25519 masks the u-coordinate's top bit.

    typename field_type_::element_t input_u, output_u;
    field_type_::from_bytes(input_u, masked_point);
    montgomery_ladder<field_type_>(output_u, clamped_scalar, input_u);
    std::uint8_t* const out_bytes = reinterpret_cast<std::uint8_t*>(out.data());
    field_type_::to_bytes(out_bytes, output_u);

    // A constant-time OR-reduction: which byte is nonzero must not be observable either.
    std::uint8_t difference_from_zero = 0;
    for (std::size_t index = 0; index != x25519_key_size_k; ++index) difference_from_zero |= out_bytes[index];
    return difference_from_zero != 0;
}

#pragma endregion RFC 7748 Ladder

} // namespace unum::ucall
