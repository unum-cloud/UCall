/**
 *  @file src/crypto_x25519_radix51.hpp
 *  @author Ash Vardanian
 *  @date August 4, 2026
 *  @brief Radix-51 Curve25519 field arithmetic with no wide integers, over a kit's words.
 *
 *  fiat-crypto's @c --no-wide-int output spells every 128-bit product as a pair of 64-bit words
 *  through @c fiat_mulx_u64 and @c fiat_addcarryx_u64, so these kernels only call the two members
 *  they need from a kit's words. Provenance and licenses are those of <tt>crypto_x25519.hpp</tt>.
 *
 *  @see BoringSSL origin, main of 2026-08-04, the @c --no-wide-int kernels: https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_msvc.h
 *  @see Fiat Cryptography, the radix-51 @c fiat_25519_* kernels outside the three products: https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c
 */
#pragma once

#include "crypto_x25519.hpp"

namespace unum::ucall {

#pragma region Radix 51 Field Arithmetic

/**
 *  @brief Adds @p arg2, @p arg3, and carry-in @p arg1 within a 51-bit limb, into sum and carry.
 *  @see Fiat Cryptography origin v0.1.6+137: https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c#L66
 */
inline static void fiat_25519_addcarryx_u51(std::uint64_t* out1, fiat_25519_uint1_t* out2, fiat_25519_uint1_t arg1,
                                            std::uint64_t arg2, std::uint64_t arg3) noexcept {
    std::uint64_t x1, x2;
    fiat_25519_uint1_t x3;
    x1 = ((arg1 + arg2) + arg3), x2 = (x1 & 0x7ffffffffffffULL), x3 = (fiat_25519_uint1_t)(x1 >> 51), *out1 = x2,
    *out2 = x3;
}

/**
 *  @brief Subtracts @p arg3 and borrow-in @p arg1 from @p arg2 within a 51-bit limb, into
 *      difference and borrow.
 *  @see Fiat Cryptography origin v0.1.6+137: https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c#L92
 */
inline static void fiat_25519_subborrowx_u51(std::uint64_t* out1, fiat_25519_uint1_t* out2, fiat_25519_uint1_t arg1,
                                             std::uint64_t arg2, std::uint64_t arg3) noexcept {
    std::int64_t x1;
    fiat_25519_int1_t x2;
    std::uint64_t x3;
    x1 = ((std::int64_t)(arg2 - (std::int64_t)arg1) - (std::int64_t)arg3), x2 = (fiat_25519_int1_t)(x1 >> 51),
    x3 = (x1 & 0x7ffffffffffffULL), *out1 = x3, *out2 = (fiat_25519_uint1_t)(0x0 - x2);
}

/**
 *  @brief Multiplies two radix-51 elements and reduces mod 2^255-19 into tight bounds.
 *  @see BoringSSL origin, main of 2026-08-04: https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_msvc.h#L201
 */
template <typename words_>
inline static void fiat_25519_carry_mul(std::uint64_t out1[5], std::uint64_t const arg1[5],
                                        std::uint64_t const arg2[5]) noexcept {
    std::uint64_t x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22,
        x23, x24, x25, x26, x27, x28, x29, x30, x31, x32, x33, x34, x35, x36, x37, x38, x39, x40, x41, x42, x43, x44,
        x45, x46, x47, x48, x49, x50, x51, x53, x55, x57, x59, x61, x63, x65, x67, x68, x69, x71, x73, x75, x77, x79,
        x81, x83, x85, x87, x89, x91, x93, x95, x97, x99, x101, x103, x105, x107, x109, x111, x113, x115, x117, x119,
        x121, x123, x125, x127, x129, x131, x133, x135, x136, x137, x138, x140, x141, x142, x143, x145, x146, x147,
        x148, x150, x151, x152, x153, x154, x155, x156, x157, x159, x160;
    fiat_25519_uint1_t x52, x54, x56, x58, x60, x62, x64, x66, x70, x72, x74, x76, x78, x80, x82, x84, x86, x88, x90,
        x92, x94, x96, x98, x100, x102, x104, x106, x108, x110, x112, x114, x116, x118, x120, x122, x124, x126, x128,
        x130, x132, x134, x139, x144, x149, x158;
    words_::fiat_mulx_u64(&x1, &x2, (arg1[4]), ((arg2[4]) * 0x13));
    words_::fiat_mulx_u64(&x3, &x4, (arg1[4]), ((arg2[3]) * 0x13));
    words_::fiat_mulx_u64(&x5, &x6, (arg1[4]), ((arg2[2]) * 0x13));
    words_::fiat_mulx_u64(&x7, &x8, (arg1[4]), ((arg2[1]) * 0x13));
    words_::fiat_mulx_u64(&x9, &x10, (arg1[3]), ((arg2[4]) * 0x13));
    words_::fiat_mulx_u64(&x11, &x12, (arg1[3]), ((arg2[3]) * 0x13));
    words_::fiat_mulx_u64(&x13, &x14, (arg1[3]), ((arg2[2]) * 0x13));
    words_::fiat_mulx_u64(&x15, &x16, (arg1[2]), ((arg2[4]) * 0x13));
    words_::fiat_mulx_u64(&x17, &x18, (arg1[2]), ((arg2[3]) * 0x13));
    words_::fiat_mulx_u64(&x19, &x20, (arg1[1]), ((arg2[4]) * 0x13));
    words_::fiat_mulx_u64(&x21, &x22, (arg1[4]), (arg2[0]));
    words_::fiat_mulx_u64(&x23, &x24, (arg1[3]), (arg2[1]));
    words_::fiat_mulx_u64(&x25, &x26, (arg1[3]), (arg2[0]));
    words_::fiat_mulx_u64(&x27, &x28, (arg1[2]), (arg2[2]));
    words_::fiat_mulx_u64(&x29, &x30, (arg1[2]), (arg2[1]));
    words_::fiat_mulx_u64(&x31, &x32, (arg1[2]), (arg2[0]));
    words_::fiat_mulx_u64(&x33, &x34, (arg1[1]), (arg2[3]));
    words_::fiat_mulx_u64(&x35, &x36, (arg1[1]), (arg2[2]));
    words_::fiat_mulx_u64(&x37, &x38, (arg1[1]), (arg2[1]));
    words_::fiat_mulx_u64(&x39, &x40, (arg1[1]), (arg2[0]));
    words_::fiat_mulx_u64(&x41, &x42, (arg1[0]), (arg2[4]));
    words_::fiat_mulx_u64(&x43, &x44, (arg1[0]), (arg2[3]));
    words_::fiat_mulx_u64(&x45, &x46, (arg1[0]), (arg2[2]));
    words_::fiat_mulx_u64(&x47, &x48, (arg1[0]), (arg2[1]));
    words_::fiat_mulx_u64(&x49, &x50, (arg1[0]), (arg2[0]));
    words_::fiat_addcarryx_u64(&x51, &x52, 0x0, x13, x7);
    words_::fiat_addcarryx_u64(&x53, &x54, x52, x14, x8);
    words_::fiat_addcarryx_u64(&x55, &x56, 0x0, x17, x51);
    words_::fiat_addcarryx_u64(&x57, &x58, x56, x18, x53);
    words_::fiat_addcarryx_u64(&x59, &x60, 0x0, x19, x55);
    words_::fiat_addcarryx_u64(&x61, &x62, x60, x20, x57);
    words_::fiat_addcarryx_u64(&x63, &x64, 0x0, x49, x59);
    words_::fiat_addcarryx_u64(&x65, &x66, x64, x50, x61);
    x67 = ((x63 >> 51) | ((x65 << 13) & 0xffffffffffffffffULL));
    x68 = (x63 & 0x7ffffffffffffULL);
    words_::fiat_addcarryx_u64(&x69, &x70, 0x0, x23, x21);
    words_::fiat_addcarryx_u64(&x71, &x72, x70, x24, x22);
    words_::fiat_addcarryx_u64(&x73, &x74, 0x0, x27, x69);
    words_::fiat_addcarryx_u64(&x75, &x76, x74, x28, x71);
    words_::fiat_addcarryx_u64(&x77, &x78, 0x0, x33, x73);
    words_::fiat_addcarryx_u64(&x79, &x80, x78, x34, x75);
    words_::fiat_addcarryx_u64(&x81, &x82, 0x0, x41, x77);
    words_::fiat_addcarryx_u64(&x83, &x84, x82, x42, x79);
    words_::fiat_addcarryx_u64(&x85, &x86, 0x0, x25, x1);
    words_::fiat_addcarryx_u64(&x87, &x88, x86, x26, x2);
    words_::fiat_addcarryx_u64(&x89, &x90, 0x0, x29, x85);
    words_::fiat_addcarryx_u64(&x91, &x92, x90, x30, x87);
    words_::fiat_addcarryx_u64(&x93, &x94, 0x0, x35, x89);
    words_::fiat_addcarryx_u64(&x95, &x96, x94, x36, x91);
    words_::fiat_addcarryx_u64(&x97, &x98, 0x0, x43, x93);
    words_::fiat_addcarryx_u64(&x99, &x100, x98, x44, x95);
    words_::fiat_addcarryx_u64(&x101, &x102, 0x0, x9, x3);
    words_::fiat_addcarryx_u64(&x103, &x104, x102, x10, x4);
    words_::fiat_addcarryx_u64(&x105, &x106, 0x0, x31, x101);
    words_::fiat_addcarryx_u64(&x107, &x108, x106, x32, x103);
    words_::fiat_addcarryx_u64(&x109, &x110, 0x0, x37, x105);
    words_::fiat_addcarryx_u64(&x111, &x112, x110, x38, x107);
    words_::fiat_addcarryx_u64(&x113, &x114, 0x0, x45, x109);
    words_::fiat_addcarryx_u64(&x115, &x116, x114, x46, x111);
    words_::fiat_addcarryx_u64(&x117, &x118, 0x0, x11, x5);
    words_::fiat_addcarryx_u64(&x119, &x120, x118, x12, x6);
    words_::fiat_addcarryx_u64(&x121, &x122, 0x0, x15, x117);
    words_::fiat_addcarryx_u64(&x123, &x124, x122, x16, x119);
    words_::fiat_addcarryx_u64(&x125, &x126, 0x0, x39, x121);
    words_::fiat_addcarryx_u64(&x127, &x128, x126, x40, x123);
    words_::fiat_addcarryx_u64(&x129, &x130, 0x0, x47, x125);
    words_::fiat_addcarryx_u64(&x131, &x132, x130, x48, x127);
    words_::fiat_addcarryx_u64(&x133, &x134, 0x0, x67, x129);
    x135 = (x134 + x131);
    x136 = ((x133 >> 51) | ((x135 << 13) & 0xffffffffffffffffULL));
    x137 = (x133 & 0x7ffffffffffffULL);
    words_::fiat_addcarryx_u64(&x138, &x139, 0x0, x136, x113);
    x140 = (x139 + x115);
    x141 = ((x138 >> 51) | ((x140 << 13) & 0xffffffffffffffffULL));
    x142 = (x138 & 0x7ffffffffffffULL);
    words_::fiat_addcarryx_u64(&x143, &x144, 0x0, x141, x97);
    x145 = (x144 + x99);
    x146 = ((x143 >> 51) | ((x145 << 13) & 0xffffffffffffffffULL));
    x147 = (x143 & 0x7ffffffffffffULL);
    words_::fiat_addcarryx_u64(&x148, &x149, 0x0, x146, x81);
    x150 = (x149 + x83);
    x151 = ((x148 >> 51) | ((x150 << 13) & 0xffffffffffffffffULL));
    x152 = (x148 & 0x7ffffffffffffULL);
    x153 = (x151 * 0x13);
    x154 = (x68 + x153);
    x155 = (x154 >> 51);
    x156 = (x154 & 0x7ffffffffffffULL);
    x157 = (x155 + x137);
    x158 = (fiat_25519_uint1_t)(x157 >> 51);
    x159 = (x157 & 0x7ffffffffffffULL);
    x160 = (x158 + x142);
    out1[0] = x156;
    out1[1] = x159;
    out1[2] = x160;
    out1[3] = x147;
    out1[4] = x152;
}

/**
 *  @brief Squares a radix-51 element and reduces mod 2^255-19 into tight bounds.
 *  @see BoringSSL origin, main of 2026-08-04: https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_msvc.h#L467
 */
template <typename words_>
inline static void fiat_25519_carry_square(std::uint64_t out1[5], std::uint64_t const arg1[5]) noexcept {
    std::uint64_t x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22,
        x23, x24, x25, x26, x27, x28, x29, x30, x31, x32, x33, x34, x35, x36, x37, x38, x39, x41, x43, x45, x47, x48,
        x49, x51, x53, x55, x57, x59, x61, x63, x65, x67, x69, x71, x73, x75, x77, x79, x81, x83, x84, x85, x86, x88,
        x89, x90, x91, x93, x94, x95, x96, x98, x99, x100, x101, x102, x103, x104, x105, x107, x108;
    fiat_25519_uint1_t x40, x42, x44, x46, x50, x52, x54, x56, x58, x60, x62, x64, x66, x68, x70, x72, x74, x76, x78,
        x80, x82, x87, x92, x97, x106;
    x1 = ((arg1[4]) * 0x13);
    x2 = (x1 * 0x2);
    x3 = ((arg1[4]) * 0x2);
    x4 = ((arg1[3]) * 0x13);
    x5 = (x4 * 0x2);
    x6 = ((arg1[3]) * 0x2);
    x7 = ((arg1[2]) * 0x2);
    x8 = ((arg1[1]) * 0x2);
    words_::fiat_mulx_u64(&x9, &x10, (arg1[4]), x1);
    words_::fiat_mulx_u64(&x11, &x12, (arg1[3]), x2);
    words_::fiat_mulx_u64(&x13, &x14, (arg1[3]), x4);
    words_::fiat_mulx_u64(&x15, &x16, (arg1[2]), x2);
    words_::fiat_mulx_u64(&x17, &x18, (arg1[2]), x5);
    words_::fiat_mulx_u64(&x19, &x20, (arg1[2]), (arg1[2]));
    words_::fiat_mulx_u64(&x21, &x22, (arg1[1]), x2);
    words_::fiat_mulx_u64(&x23, &x24, (arg1[1]), x6);
    words_::fiat_mulx_u64(&x25, &x26, (arg1[1]), x7);
    words_::fiat_mulx_u64(&x27, &x28, (arg1[1]), (arg1[1]));
    words_::fiat_mulx_u64(&x29, &x30, (arg1[0]), x3);
    words_::fiat_mulx_u64(&x31, &x32, (arg1[0]), x6);
    words_::fiat_mulx_u64(&x33, &x34, (arg1[0]), x7);
    words_::fiat_mulx_u64(&x35, &x36, (arg1[0]), x8);
    words_::fiat_mulx_u64(&x37, &x38, (arg1[0]), (arg1[0]));
    words_::fiat_addcarryx_u64(&x39, &x40, 0x0, x21, x17);
    words_::fiat_addcarryx_u64(&x41, &x42, x40, x22, x18);
    words_::fiat_addcarryx_u64(&x43, &x44, 0x0, x37, x39);
    words_::fiat_addcarryx_u64(&x45, &x46, x44, x38, x41);
    x47 = ((x43 >> 51) | ((x45 << 13) & 0xffffffffffffffffULL));
    x48 = (x43 & 0x7ffffffffffffULL);
    words_::fiat_addcarryx_u64(&x49, &x50, 0x0, x23, x19);
    words_::fiat_addcarryx_u64(&x51, &x52, x50, x24, x20);
    words_::fiat_addcarryx_u64(&x53, &x54, 0x0, x29, x49);
    words_::fiat_addcarryx_u64(&x55, &x56, x54, x30, x51);
    words_::fiat_addcarryx_u64(&x57, &x58, 0x0, x25, x9);
    words_::fiat_addcarryx_u64(&x59, &x60, x58, x26, x10);
    words_::fiat_addcarryx_u64(&x61, &x62, 0x0, x31, x57);
    words_::fiat_addcarryx_u64(&x63, &x64, x62, x32, x59);
    words_::fiat_addcarryx_u64(&x65, &x66, 0x0, x27, x11);
    words_::fiat_addcarryx_u64(&x67, &x68, x66, x28, x12);
    words_::fiat_addcarryx_u64(&x69, &x70, 0x0, x33, x65);
    words_::fiat_addcarryx_u64(&x71, &x72, x70, x34, x67);
    words_::fiat_addcarryx_u64(&x73, &x74, 0x0, x15, x13);
    words_::fiat_addcarryx_u64(&x75, &x76, x74, x16, x14);
    words_::fiat_addcarryx_u64(&x77, &x78, 0x0, x35, x73);
    words_::fiat_addcarryx_u64(&x79, &x80, x78, x36, x75);
    words_::fiat_addcarryx_u64(&x81, &x82, 0x0, x47, x77);
    x83 = (x82 + x79);
    x84 = ((x81 >> 51) | ((x83 << 13) & 0xffffffffffffffffULL));
    x85 = (x81 & 0x7ffffffffffffULL);
    words_::fiat_addcarryx_u64(&x86, &x87, 0x0, x84, x69);
    x88 = (x87 + x71);
    x89 = ((x86 >> 51) | ((x88 << 13) & 0xffffffffffffffffULL));
    x90 = (x86 & 0x7ffffffffffffULL);
    words_::fiat_addcarryx_u64(&x91, &x92, 0x0, x89, x61);
    x93 = (x92 + x63);
    x94 = ((x91 >> 51) | ((x93 << 13) & 0xffffffffffffffffULL));
    x95 = (x91 & 0x7ffffffffffffULL);
    words_::fiat_addcarryx_u64(&x96, &x97, 0x0, x94, x53);
    x98 = (x97 + x55);
    x99 = ((x96 >> 51) | ((x98 << 13) & 0xffffffffffffffffULL));
    x100 = (x96 & 0x7ffffffffffffULL);
    x101 = (x99 * 0x13);
    x102 = (x48 + x101);
    x103 = (x102 >> 51);
    x104 = (x102 & 0x7ffffffffffffULL);
    x105 = (x103 + x85);
    x106 = (fiat_25519_uint1_t)(x105 >> 51);
    x107 = (x105 & 0x7ffffffffffffULL);
    x108 = (x106 + x90);
    out1[0] = x104;
    out1[1] = x107;
    out1[2] = x108;
    out1[3] = x95;
    out1[4] = x100;
}

/**
 *  @brief Multiplies a radix-51 element by 121666 and reduces mod 2^255-19 into tight bounds.
 *  @see BoringSSL origin, main of 2026-08-04: https://github.com/google/boringssl/blob/eeccc518e91ddebe290349092f0f75fcef24a86e/third_party/fiat/curve25519_64_msvc.h#L1204
 */
template <typename words_>
inline static void fiat_25519_carry_scmul_121666(std::uint64_t out1[5], std::uint64_t const arg1[5]) noexcept {
    std::uint64_t x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x15, x16, x17, x18, x20, x21, x22, x23, x25,
        x26, x27, x28, x30, x31, x32, x33, x34, x36, x37, x39, x40;
    fiat_25519_uint1_t x14, x19, x24, x29, x35, x38;
    words_::fiat_mulx_u64(&x1, &x2, 0x1db42, (arg1[4]));
    words_::fiat_mulx_u64(&x3, &x4, 0x1db42, (arg1[3]));
    words_::fiat_mulx_u64(&x5, &x6, 0x1db42, (arg1[2]));
    words_::fiat_mulx_u64(&x7, &x8, 0x1db42, (arg1[1]));
    words_::fiat_mulx_u64(&x9, &x10, 0x1db42, (arg1[0]));
    x11 = ((x9 >> 51) | ((x10 << 13) & 0xffffffffffffffffULL));
    x12 = (x9 & 0x7ffffffffffffULL);
    words_::fiat_addcarryx_u64(&x13, &x14, 0x0, x11, x7);
    x15 = (x14 + x8);
    x16 = ((x13 >> 51) | ((x15 << 13) & 0xffffffffffffffffULL));
    x17 = (x13 & 0x7ffffffffffffULL);
    words_::fiat_addcarryx_u64(&x18, &x19, 0x0, x16, x5);
    x20 = (x19 + x6);
    x21 = ((x18 >> 51) | ((x20 << 13) & 0xffffffffffffffffULL));
    x22 = (x18 & 0x7ffffffffffffULL);
    words_::fiat_addcarryx_u64(&x23, &x24, 0x0, x21, x3);
    x25 = (x24 + x4);
    x26 = ((x23 >> 51) | ((x25 << 13) & 0xffffffffffffffffULL));
    x27 = (x23 & 0x7ffffffffffffULL);
    words_::fiat_addcarryx_u64(&x28, &x29, 0x0, x26, x1);
    x30 = (x29 + x2);
    x31 = ((x28 >> 51) | ((x30 << 13) & 0xffffffffffffffffULL));
    x32 = (x28 & 0x7ffffffffffffULL);
    x33 = (x31 * 0x13);
    x34 = (x12 + x33);
    x35 = (fiat_25519_uint1_t)(x34 >> 51);
    x36 = (x34 & 0x7ffffffffffffULL);
    x37 = (x35 + x17);
    x38 = (fiat_25519_uint1_t)(x37 >> 51);
    x39 = (x37 & 0x7ffffffffffffULL);
    x40 = (x38 + x22);
    out1[0] = x36;
    out1[1] = x39;
    out1[2] = x40;
    out1[3] = x27;
    out1[4] = x32;
}

/**
 *  @brief Carries a loose radix-51 element back into tight bounds.
 *  @see Fiat Cryptography origin v0.1.6+137: https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c#L367
 */
inline static void fiat_25519_carry(std::uint64_t out1[5], std::uint64_t const arg1[5]) noexcept {
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
 *  @see Fiat Cryptography origin v0.1.6+137: https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c#L406
 */
inline static void fiat_25519_add(std::uint64_t out1[5], std::uint64_t const arg1[5],
                                  std::uint64_t const arg2[5]) noexcept {
    std::uint64_t x1, x2, x3, x4, x5;
    x1 = ((arg1[0]) + (arg2[0])), x2 = ((arg1[1]) + (arg2[1])), x3 = ((arg1[2]) + (arg2[2])),
    x4 = ((arg1[3]) + (arg2[3])), x5 = ((arg1[4]) + (arg2[4])), out1[0] = x1, out1[1] = x2, out1[2] = x3, out1[3] = x4,
    out1[4] = x5;
}

/**
 *  @brief Subtracts tight radix-51 elements into a loose result awaiting @c fiat_25519_carry.
 *  @see Fiat Cryptography origin v0.1.6+137: https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c#L431
 */
inline static void fiat_25519_sub(std::uint64_t out1[5], std::uint64_t const arg1[5],
                                  std::uint64_t const arg2[5]) noexcept {
    std::uint64_t x1, x2, x3, x4, x5;
    x1 = ((0xfffffffffffdaULL + (arg1[0])) - (arg2[0])), x2 = ((0xffffffffffffeULL + (arg1[1])) - (arg2[1])),
    x3 = ((0xffffffffffffeULL + (arg1[2])) - (arg2[2])), x4 = ((0xffffffffffffeULL + (arg1[3])) - (arg2[3])),
    x5 = ((0xffffffffffffeULL + (arg1[4])) - (arg2[4])), out1[0] = x1, out1[1] = x2, out1[2] = x3, out1[3] = x4,
    out1[4] = x5;
}

/**
 *  @brief Serializes a tight radix-51 element to 32 canonical little-endian bytes.
 *  @see Fiat Cryptography origin v0.1.6+137: https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c#L514
 */
inline static void fiat_25519_to_bytes(std::uint8_t out1[32], std::uint64_t const arg1[5]) noexcept {
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
 *  @see Fiat Cryptography origin v0.1.6+137: https://github.com/mit-plv/fiat-crypto/blob/330f965d024902f7b0667acc230277854c782464/fiat-c/src/curve25519_64.c#L730
 */
inline static void fiat_25519_from_bytes(std::uint64_t out1[5], std::uint8_t const arg1[32]) noexcept {
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
 *  @brief The radix-51 field backend: five 51-bit limbs, little-endian, over a kit's words.
 *
 *  fiat-crypto distinguishes "tight" (freshly carried) from "loose" (freshly added or subtracted,
 *  wider) limb bounds so a caller can skip a carry between them. That distinction buys throughput,
 *  and throughput is not the concern of a primitive that runs four times per handshake rather than
 *  once per byte, so every sum and difference is carried back to tight bounds before reuse. A tight
 *  value always satisfies a loose precondition, so this is never unsafe, only slower.
 */
template <typename words_>
struct field_radix51 {
    struct element_t {
        std::uint64_t limb[5];
    };

    static element_t zero() noexcept { return {{0, 0, 0, 0, 0}}; }
    static element_t one() noexcept { return {{1, 0, 0, 0, 0}}; }

    static void add(element_t& out, element_t const& first, element_t const& second) noexcept {
        element_t loose;
        fiat_25519_add(loose.limb, first.limb, second.limb);
        fiat_25519_carry(out.limb, loose.limb);
    }

    static void subtract(element_t& out, element_t const& first, element_t const& second) noexcept {
        element_t loose;
        fiat_25519_sub(loose.limb, first.limb, second.limb);
        fiat_25519_carry(out.limb, loose.limb);
    }

    /** May alias @p out with either input - fiat kernels read everything before writing. */
    static void multiply(element_t& out, element_t const& first, element_t const& second) noexcept {
        fiat_25519_carry_mul<words_>(out.limb, first.limb, second.limb);
    }

    static void square(element_t& out, element_t const& value) noexcept {
        fiat_25519_carry_square<words_>(out.limb, value.limb);
    }

    static void multiply_121666(element_t& out, element_t const& value) noexcept {
        fiat_25519_carry_scmul_121666<words_>(out.limb, value.limb);
    }

    /** Constant-time swap when @p bit is 1: a barriered mask select, never a branch. */
    static void conditional_swap(element_t& first, element_t& second, std::uint64_t bit) noexcept {
        std::uint64_t const mask = value_barrier(0 - bit);
        for (std::size_t index = 0; index != 5; ++index) {
            std::uint64_t const difference = (first.limb[index] ^ second.limb[index]) & mask;
            first.limb[index] ^= difference;
            second.limb[index] ^= difference;
        }
    }

    /** Precondition: bit 255 of @p bytes is already clear - the caller masks it per RFC 7748 §5. */
    static void from_bytes(element_t& out, std::uint8_t const bytes[x25519_key_size_k]) noexcept {
        fiat_25519_from_bytes(out.limb, bytes);
    }

    static void to_bytes(std::uint8_t bytes[x25519_key_size_k], element_t const& value) noexcept {
        fiat_25519_to_bytes(bytes, value.limb);
    }
};

#pragma endregion Radix 51 Field Arithmetic

} // namespace unum::ucall
