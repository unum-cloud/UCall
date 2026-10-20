/**
 *  @file test/x25519.cpp
 *  @author Ash Vardanian
 *  @date August 4, 2026
 *  @brief Tests for @c crypto_x25519.hpp against RFC 7748 §5.2 and Project Wycheproof vectors.
 *
 *  Vectors come verbatim from RFC 7748 and from Google's Project Wycheproof (`x25519_test.json`,
 *  `XdhComp` group, curve25519); the low-order-point cases are that suite's, not hand-derived.
 *
 *  Checked once against the tier this machine dispatches to, and separately against every tier
 *  compiled in, because a dispatcher only ever exercises one.
 */
#include <cstdint> // `std::uint8_t`
#include <cstring> // `std::memcpy`

#include "ucall/curve25519.hpp" // `x25519_scalar_multiply`, `x25519_derive_public`
#include "harness.hpp"          // `expect`, `run_test`, `from_hex`

using namespace unum::ucall;
using namespace unum::ucall::test;

#pragma region Fixtures

/** What a scalar multiplication yields, which a bare @c bool cannot name. */
enum class shared_secret_t : std::uint8_t {

    /** A usable secret: the peer's point had large order. */
    usable_k,

    /** All zeros, which RFC 7748 §6.1 requires be treated as a failed exchange. */
    all_zero_k,
};

/** Generated from RFC 7748 section 5.2 and Project Wycheproof's x25519_test.json - do not
 *  hand-edit the hex literals below, regenerate from those sources instead. */
struct x25519_vector_t {
    char const* label;
    char const* scalar_hex;
    char const* point_hex;
    char const* shared_hex;
    shared_secret_t expected;
};

static x25519_vector_t const x25519_vectors_k[] = {
    {"rfc7748_vector1", "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
     "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
     "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", shared_secret_t::usable_k},
    {"rfc7748_vector2", "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
     "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
     "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", shared_secret_t::usable_k},
    {"wycheproof_100", "a046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a44",
     "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
     "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", shared_secret_t::usable_k}, // RFC 7748
    {"wycheproof_101", "4866e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba4d",
     "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413",
     "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", shared_secret_t::usable_k}, // RFC 7748
    {"wycheproof_102", "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
     "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
     "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
     shared_secret_t::usable_k}, // RFC 8037, Section A.6
    {"wycheproof_32", "88227494038f2bb811d47805bcdf04a2ac585ada7f2f23389bfd4658f9ddd45e",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000", shared_secret_t::all_zero_k}, // public key = 0
    {"wycheproof_33", "48232e8972b61c7e61930eb9450b5070eae1c670475685541f0476217e48184f",
     "0100000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000", shared_secret_t::all_zero_k}, // public key = 1
    {"wycheproof_63", "e0f978dfcd3a8f1a5093418de54136a584c20b7b349afdf6c0520886f95b1272",
     "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
     "0000000000000000000000000000000000000000000000000000000000000000",
     shared_secret_t::all_zero_k}, // public key with low order
    {"wycheproof_64", "387355d995616090503aafad49da01fb3dc3eda962704eaee6b86f9e20c92579",
     "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
     "0000000000000000000000000000000000000000000000000000000000000000",
     shared_secret_t::all_zero_k}, // public key with low order
    {"wycheproof_65", "c8fe0df92ae68a03023fc0c9adb9557d31be7feed0d3ab36c558143daf4dbb40",
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
     "0000000000000000000000000000000000000000000000000000000000000000",
     shared_secret_t::all_zero_k}, // public key with low order
    {"wycheproof_66", "c8d74acde5934e64b9895d5ff7afbffd7f704f7dfccff7ac28fa62a1e6410347",
     "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
     "0000000000000000000000000000000000000000000000000000000000000000",
     shared_secret_t::all_zero_k}, // public key with low order
    {"wycheproof_1", "c8a9d5a91091ad851c668b0736c1c9a02936c0d3ad62670858088047ba057475",
     "504a36999f489cd2fdbc08baff3d88fa00569ba986cba22548ffde80f9806829",
     "436a2c040cf45fea9b29a0cb81b1f41458f863d0d61b453d0a982720d6d61320", shared_secret_t::usable_k}, // normal case
};

/** A vector's two input literals, decoded into bytes ready to hand to the library. */
struct decoded_vector_t {
    byte_t scalar[x25519_key_size_k] {};
    byte_t point[x25519_key_size_k] {};

    /** Decodes @p vector, counting a malformed literal into @p failures. */
    decoded_vector_t(x25519_vector_t const& vector, std::size_t& failures) {
        failures += expect(from_hex(vector.scalar_hex, {scalar, scalar + x25519_key_size_k}),
                           "{} has a bad scalar literal", vector.label);
        failures += expect(from_hex(vector.point_hex, {point, point + x25519_key_size_k}), "{} has a bad point literal",
                           vector.label);
    }
};

/** One field-arithmetic backend, so a check is written once and run against each. */
struct x25519_backend_t {
    char const* name;

    /** Which tier must be runnable here, or @c none_k for one that always is. */
    x25519_tiers_t tier;
    bool (*multiply)(byte_t*, byte_t const*, byte_t const*) noexcept;
};

/*  The dispatcher leads, so whatever it picks is checked against the tiers themselves, and the
 *  baseline follows as the reference every candidate is compared with. This is the only place in
 *  the file where a tier is named by the preprocessor. */
static x25519_backend_t const x25519_backends_k[] = {
    {"dispatched", x25519_tiers_t::none_k, &x25519_scalar_multiply},
    {"serial", x25519_tiers_t::serial_k, &x25519_scalar_multiply_serial},
#if UCALL_HAS_INT128_
    {"radix51", x25519_tiers_t::radix51_k, &x25519_scalar_multiply_radix51},
#endif
#if UCALL_TARGET_X86_ADX
    {"adx", x25519_tiers_t::adx_k, &x25519_scalar_multiply_adx},
#endif
};

/** The backend every other one is checked against: the one always built and always runnable. */
static x25519_backend_t const& x25519_reference_k = x25519_backends_k[1];

/** Whether this machine can execute @p backend. Compiled in does not mean runnable. */
[[nodiscard]] static bool runnable_here(x25519_backend_t const& backend) noexcept {
    return backend.tier == x25519_tiers_t::none_k || x25519_has_tiers(x25519_tiers_runtime(), backend.tier);
}

/** Reads the library's yes/no answer as the named state it stands for. */
[[nodiscard]] static shared_secret_t reported(bool usable) noexcept {
    return usable ? shared_secret_t::usable_k : shared_secret_t::all_zero_k;
}

/** Lets `{}` name a secret's state rather than print its ordinal. Found by ADL at file scope. */
[[nodiscard]] inline auto format_as(shared_secret_t secret) noexcept {
    return secret == shared_secret_t::usable_k ? "usable" : "all_zero";
}

#pragma endregion Fixtures

#pragma region Known Answers

case_result_t test_x25519_unit() {
    std::size_t failures = 0;

    // RFC 7748 §5.2: k = u = 9, then k = X25519(k, u). The trip counts are the specification's
    // own, so they are fixed rather than scaled.
    announce("rfc7748_iterated");
    byte_t scalar[x25519_key_size_k] {}, point[x25519_key_size_k] {};
    scalar[0] = byte_t {9}, point[0] = byte_t {9};

    byte_t after_one[x25519_key_size_k];
    failures += expect(x25519_scalar_multiply(after_one, scalar, point));
    failures += expect_hex(after_one, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");

    for (std::size_t iteration = 0; iteration != 1000; ++iteration) {
        byte_t next[x25519_key_size_k];
        [[maybe_unused]] bool const usable = x25519_scalar_multiply(next, scalar, point);
        std::memcpy(point, scalar, x25519_key_size_k);
        std::memcpy(scalar, next, x25519_key_size_k);
    }
    failures += expect_hex(scalar, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");

    // RFC 7748 vector 1 and Wycheproof tcId=100 hold the same key, before and after clamping.
    announce("clamping_is_idempotent");
    byte_t raw_scalar[x25519_key_size_k], clamped_scalar[x25519_key_size_k], shared_point[x25519_key_size_k];
    failures += expect(from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                                {raw_scalar, raw_scalar + x25519_key_size_k}));
    failures += expect(from_hex("a046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a44",
                                {clamped_scalar, clamped_scalar + x25519_key_size_k}));
    failures += expect(from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                                {shared_point, shared_point + x25519_key_size_k}));

    byte_t from_raw[x25519_key_size_k], from_clamped[x25519_key_size_k];
    failures += expect(x25519_scalar_multiply(from_raw, raw_scalar, shared_point));
    failures += expect(x25519_scalar_multiply(from_clamped, clamped_scalar, shared_point));
    failures += expect_bytes(from_raw, from_clamped);
    failures += expect_hex(from_raw, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

    announce("derive_public_matches_base_point");
    byte_t nine[x25519_key_size_k] {};
    nine[0] = byte_t {9};
    byte_t derived[x25519_key_size_k];
    x25519_derive_public(derived, nine);
    failures += expect_hex(derived, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    return failures;
}

#pragma endregion Known Answers

#pragma region Tier Differential

/**
 *  @brief Every tier compiled into this build, against every vector and along a dependent chain.
 *
 *  The chain matters separately from the vectors: a carry bug a single multiplication hides
 *  compounds once each result feeds the next.
 */
case_result_t test_x25519_all() {
    std::size_t failures = 0;

    for (x25519_backend_t const& backend : x25519_backends_k) {
        if (!runnable_here(backend)) continue;
        announce("{}", backend.name);
        for (x25519_vector_t const& vector : x25519_vectors_k) {
            decoded_vector_t const decoded(vector, failures);
            byte_t produced[x25519_key_size_k];
            shared_secret_t const answer = reported(backend.multiply(produced, decoded.scalar, decoded.point));
            failures += expect(answer == vector.expected, "{} called {} a {} secret, expected {}", backend.name,
                               vector.label, answer, vector.expected);
            failures += expect_hex(produced, vector.shared_hex);
        }
    }

    // A carry bug one multiplication hides compounds once each result feeds the next, so every
    // backend walks the same dependent chain and must match the reference at every step.
    for (x25519_backend_t const& backend : x25519_backends_k) {
        if (!runnable_here(backend) || &backend == &x25519_reference_k) continue;
        announce("{} along an iterated chain", backend.name);

        byte_t scalar[x25519_key_size_k] {}, point[x25519_key_size_k] {};
        scalar[0] = byte_t {9}, point[0] = byte_t {9};
        for (std::size_t iteration = 0; iteration != scale_iterations(100); ++iteration) {
            byte_t expected[x25519_key_size_k], produced[x25519_key_size_k];
            [[maybe_unused]] bool const reference_usable = x25519_reference_k.multiply(expected, scalar, point);
            [[maybe_unused]] bool const candidate_usable = backend.multiply(produced, scalar, point);
            failures += expect(bytes_equal(produced, expected), "{} left {} at iteration {}", backend.name,
                               x25519_reference_k.name, iteration);
            std::memcpy(point, scalar, x25519_key_size_k);
            std::memcpy(scalar, expected, x25519_key_size_k);
        }
    }
    return failures;
}

#pragma endregion Tier Differential

int main(int, char** argv) {
    install_test_signal_handlers();
    fmt::print("Hi, dear tester! You look nice today!\n");
    fmt::print("  x25519 tiers built     serial={} radix51={} adx={}\n",
               x25519_has_tiers(x25519_tiers_compiled(), x25519_tiers_t::serial_k),
               x25519_has_tiers(x25519_tiers_compiled(), x25519_tiers_t::radix51_k),
               x25519_has_tiers(x25519_tiers_compiled(), x25519_tiers_t::adx_k));
    fmt::print("  x25519 adx runnable    {}\n", x25519_has_tiers(x25519_tiers_runtime(), x25519_tiers_t::adx_k));
    fmt::print("  x25519 tier preferred  {}\n", x25519_tier_name(x25519_tier_preferred()));
    configure_tests();

    suite_totals_t totals {.program = argv[0]};
    run_test(totals, "test_x25519_unit", test_x25519_unit);
    run_test(totals, "test_x25519_all", test_x25519_all);
    return suite_exit_code(totals);
}
