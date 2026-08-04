/**
 *  @brief Tests for @c crypto_x25519.hpp against RFC 7748 §5.2 and Project Wycheproof vectors.
 *
 *  Vectors are pulled verbatim from RFC 7748's text and from Google's Project Wycheproof
 *  (`x25519_test.json`, `XdhComp` group, curve25519) - the low-order-point cases exercise
 *  the small-order rejection RFC 7748 §6.1 requires, and are not hand-derived.
 *
 *  @file scripts/test_x25519.cpp
 *  @author Ash Vardanian
 */
#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <string>

#include "crypto_x25519.hpp"

using namespace unum::ucall;

#pragma region Helpers

static void from_hex(char const *hex, std::uint8_t out[x25519_key_size_k]) {
    for (std::size_t index = 0; index != x25519_key_size_k; ++index) {
        unsigned high, low;
        std::sscanf(hex + 2 * index, "%1x", &high);
        std::sscanf(hex + 2 * index + 1, "%1x", &low);
        out[index] = static_cast<std::uint8_t>((high << 4) | low);
    }
}

static std::string to_hex(std::uint8_t const *data) {
    static char const digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(2 * x25519_key_size_k);
    for (std::size_t index = 0; index != x25519_key_size_k; ++index) {
        result.push_back(digits[data[index] >> 4]);
        result.push_back(digits[data[index] & 0x0Fu]);
    }
    return result;
}

#pragma endregion Helpers

#pragma region Shared Secret Vectors

/**
 *  Generated from RFC 7748 section 5.2 and Project Wycheproof's x25519_test.json - do not
 *  hand-edit the hex literals below, regenerate from those sources instead.
 */
struct x25519_vector_t {
    char const *label;
    char const *scalar_hex;
    char const *point_hex;
    char const *shared_hex;
    bool expect_nonzero;
};

static x25519_vector_t const x25519_vectors_k[] = {
    {"rfc7748_vector1", "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
     "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
     "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", true},
    {"rfc7748_vector2", "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
     "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
     "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", true},
    {"wycheproof_100", "a046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a44",
     "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
     "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", true}, // RFC 7748
    {"wycheproof_101", "4866e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba4d",
     "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413",
     "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", true}, // RFC 7748
    {"wycheproof_102", "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
     "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
     "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", true}, // RFC 8037, Section A.6
    {"wycheproof_32", "88227494038f2bb811d47805bcdf04a2ac585ada7f2f23389bfd4658f9ddd45e",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000", false}, // public key = 0
    {"wycheproof_33", "48232e8972b61c7e61930eb9450b5070eae1c670475685541f0476217e48184f",
     "0100000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000", false}, // public key = 1
    {"wycheproof_63", "e0f978dfcd3a8f1a5093418de54136a584c20b7b349afdf6c0520886f95b1272",
     "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
     "0000000000000000000000000000000000000000000000000000000000000000", false}, // public key with low order
    {"wycheproof_64", "387355d995616090503aafad49da01fb3dc3eda962704eaee6b86f9e20c92579",
     "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
     "0000000000000000000000000000000000000000000000000000000000000000", false}, // public key with low order
    {"wycheproof_65", "c8fe0df92ae68a03023fc0c9adb9557d31be7feed0d3ab36c558143daf4dbb40",
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
     "0000000000000000000000000000000000000000000000000000000000000000", false}, // public key with low order
    {"wycheproof_66", "c8d74acde5934e64b9895d5ff7afbffd7f704f7dfccff7ac28fa62a1e6410347",
     "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
     "0000000000000000000000000000000000000000000000000000000000000000", false}, // public key with low order
    {"wycheproof_1", "c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475",
     "504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829",
     "436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320", true}, // normal case
};

class X25519Vector : public testing::TestWithParam<x25519_vector_t> {};

TEST_P(X25519Vector, MatchesReferenceSharedSecret) {
    x25519_vector_t const &vector = GetParam();
    std::uint8_t scalar[x25519_key_size_k], point[x25519_key_size_k], actual[x25519_key_size_k];
    from_hex(vector.scalar_hex, scalar);
    from_hex(vector.point_hex, point);

    bool const nonzero = x25519_scalar_multiply(actual, scalar, point);

    EXPECT_EQ(to_hex(actual), vector.shared_hex);
    EXPECT_EQ(nonzero, vector.expect_nonzero);

    // Every vector must also hold through each field-arithmetic tier directly, since the
    // dispatcher above only ever exercises the one this machine selects.
    std::uint8_t adx_output[x25519_key_size_k];
    EXPECT_EQ(x25519_scalar_multiply_adx(adx_output, scalar, point), vector.expect_nonzero);
    EXPECT_EQ(to_hex(adx_output), vector.shared_hex);
#if defined(__SIZEOF_INT128__)
    std::uint8_t serial_output[x25519_key_size_k];
    EXPECT_EQ(x25519_scalar_multiply_serial(serial_output, scalar, point), vector.expect_nonzero);
    EXPECT_EQ(to_hex(serial_output), vector.shared_hex);
#endif
}

INSTANTIATE_TEST_SUITE_P(Rfc7748AndWycheproof, X25519Vector, testing::ValuesIn(x25519_vectors_k),
                         [](testing::TestParamInfo<x25519_vector_t> const &info) { return info.param.label; });

#pragma endregion Shared Secret Vectors

#pragma region Iterated Vectors

TEST(X25519, RfcIteratedOnce) {
    // RFC 7748 5.2's iterated test: k = u = 9, then k = X25519(k, u) repeatedly.
    std::uint8_t k[x25519_key_size_k] {}, u[x25519_key_size_k] {}, next[x25519_key_size_k];
    k[0] = 9;
    u[0] = 9;
    [[maybe_unused]] bool const nonzero = x25519_scalar_multiply(next, k, u);
    EXPECT_EQ(to_hex(next), "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
}

TEST(X25519, RfcIteratedOneThousandTimes) {
    std::uint8_t k[x25519_key_size_k] {}, u[x25519_key_size_k] {};
    k[0] = 9;
    u[0] = 9;
    for (int iteration = 0; iteration < 1000; ++iteration) {
        std::uint8_t next[x25519_key_size_k];
        [[maybe_unused]] bool const nonzero = x25519_scalar_multiply(next, k, u);
        std::memcpy(u, k, x25519_key_size_k);
        std::memcpy(k, next, x25519_key_size_k);
    }
    EXPECT_EQ(to_hex(k), "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
}

#if defined(__SIZEOF_INT128__)
TEST(X25519, BackendsAgreeAlongIteratedChain) {
    // A hundred steps of the RFC's iterated construction, with the radix-51 and saturated
    // tiers computing every step independently. Reference vectors pin down single calls;
    // this catches a carry bug that only compounds across dependent invocations.
    std::uint8_t k[x25519_key_size_k] {}, u[x25519_key_size_k] {};
    k[0] = 9;
    u[0] = 9;
    for (int iteration = 0; iteration != 100; ++iteration) {
        std::uint8_t serial_next[x25519_key_size_k], adx_next[x25519_key_size_k];
        [[maybe_unused]] bool const serial_nonzero = x25519_scalar_multiply_serial(serial_next, k, u);
        [[maybe_unused]] bool const adx_nonzero = x25519_scalar_multiply_adx(adx_next, k, u);
        ASSERT_EQ(to_hex(serial_next), to_hex(adx_next)) << "tiers diverge at iteration " << iteration;
        std::memcpy(u, k, x25519_key_size_k);
        std::memcpy(k, serial_next, x25519_key_size_k);
    }
}
#endif

#pragma endregion Iterated Vectors

#pragma region Clamping And Public Derivation

TEST(X25519, ClampingIsIdempotent) {
    // RFC 7748 vector 1's raw scalar and Wycheproof's tcId=100 store the same key, before and
    // after clamping respectively - both must drive x25519_scalar_multiply to the same result.
    std::uint8_t raw_scalar[x25519_key_size_k], clamped_scalar[x25519_key_size_k], point[x25519_key_size_k];
    std::uint8_t from_raw[x25519_key_size_k], from_clamped[x25519_key_size_k];
    from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", raw_scalar);
    from_hex("a046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a44", clamped_scalar);
    from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", point);

    [[maybe_unused]] bool const raw_nonzero = x25519_scalar_multiply(from_raw, raw_scalar, point);
    [[maybe_unused]] bool const clamped_nonzero = x25519_scalar_multiply(from_clamped, clamped_scalar, point);

    EXPECT_EQ(to_hex(from_raw), to_hex(from_clamped));
    EXPECT_EQ(to_hex(from_raw), "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
}

TEST(X25519, DerivePublicMatchesScalarMultiplyByBasePoint) {
    // x25519_derive_public(9) is exactly X25519(9, 9), the RFC's own first iteration step.
    std::uint8_t scalar[x25519_key_size_k] {};
    scalar[0] = 9;
    std::uint8_t derived[x25519_key_size_k];
    x25519_derive_public(derived, scalar);
    EXPECT_EQ(to_hex(derived), "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
}

#pragma endregion Clamping And Public Derivation
