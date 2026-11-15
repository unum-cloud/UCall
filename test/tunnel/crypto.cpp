/**
 *  @file test/tunnel/crypto.cpp
 *  @author Ash Vardanian
 *  @date August 4, 2026
 *  @brief HMAC, HKDF and entropy vectors, and the X25519 kits against
 *      RFC 7748 §5.2 and Project Wycheproof vectors.
 *
 *  Vectors come verbatim from RFC 7748 and from Google's Project Wycheproof (`x25519_test.json`,
 *  `XdhComp` group, curve25519); the low-order-point cases are that suite's, not hand-derived.
 *
 *  Checked against every kit compiled in and this machine runs, because a CPU class only ever
 *  exercises one, and against the radix-51 field on targets no kit picks it for.
 */
#include <cstdint> // `std::uint8_t`
#include <cstring> // `std::memcpy`

#include "crypto_x25519_radix51.hpp" // `field_radix51`, `serial_words`, `scalar_multiply_through`
#include "secure_tunnel.hpp"         // `crypto_t`, `hmac_of`, `run_of`, `from_hex`

#include "ucall/tunnel/crypto.hpp" // `serial_x25519_kit_t`, `haswell_x25519_kit_t`, `neon_x25519_kit_t`

namespace unum::ucall::test::tunnel {

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

    /** Which capability must be runnable here. */
    sz_capability_t capability;

    /** Empty for a kit this build left out. Called with spans, as GCC 16 decays an array argument
     *  of an indirect call to a pointer. */
    bool (*multiply)(span<byte_t, x25519_key_size_k>, span<byte_t const, x25519_key_size_k>,
                     span<byte_t const, x25519_key_size_k>) noexcept;
};

template <typename kit_type_>
constexpr x25519_backend_t row_of(char const* name) noexcept {
    if constexpr (kit_type_::compiled_k) return {name, kit_type_::capability_k, kit_type_::multiply};
    else return {name, kit_type_::capability_k, nullptr};
}

[[nodiscard]] static bool multiply_radix51(span<byte_t, x25519_key_size_k> out,
                                           span<byte_t const, x25519_key_size_k> scalar,
                                           span<byte_t const, x25519_key_size_k> point) noexcept {
    return scalar_multiply_through<field_radix51<serial_words<void>>>(out, scalar, point);
}

/*  The baseline leads as the reference every candidate is compared with. */
static x25519_backend_t const x25519_backends_k[] = {
    row_of<serial_x25519_kit_t>("serial"),
    row_of<haswell_x25519_kit_t>("haswell"),
    row_of<neon_x25519_kit_t>("neon"),
    {"radix51", sz_cap_serial_k, &multiply_radix51}, // Instantiates `field_radix51` on every target.
};

/** The backend every other one is checked against: the one always built and always runnable. */
static x25519_backend_t const& x25519_reference_k = x25519_backends_k[0];

/** Whether this build carries @p backend and this machine can execute it. */
[[nodiscard]] static bool runnable_here(x25519_backend_t const& backend) noexcept {
    sz_capability_t detected = sz_cap_serial_k;
    if (sz_capabilities_detected_cpu(&detected) != sz_success_k) detected = sz_cap_serial_k;
    return backend.multiply && (detected & backend.capability) != 0;
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

static std::size_t test_x25519() {
    std::size_t failures = 0;

    // RFC 7748 §5.2: k = u = 9, then k = X25519(k, u). The trip counts are the specification's
    // own, so they are fixed rather than scaled.
    byte_t scalar[x25519_key_size_k] {}, point[x25519_key_size_k] {};
    scalar[0] = byte_t {9}, point[0] = byte_t {9};

    byte_t after_one[x25519_key_size_k];
    failures += expect(x25519_multiply_serial(after_one, scalar, point));
    failures += expect_hex(after_one, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");

    for (std::size_t iteration = 0; iteration != 1000; ++iteration) {
        byte_t next[x25519_key_size_k];
        [[maybe_unused]] bool const usable = x25519_multiply_serial(next, scalar, point);
        std::memcpy(point, scalar, x25519_key_size_k);
        std::memcpy(scalar, next, x25519_key_size_k);
    }
    failures += expect_hex(scalar, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");

    // RFC 7748 vector 1 and Wycheproof tcId=100 hold the same key, before and after clamping.
    byte_t raw_scalar[x25519_key_size_k], clamped_scalar[x25519_key_size_k], shared_point[x25519_key_size_k];
    failures += expect(from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                                {raw_scalar, raw_scalar + x25519_key_size_k}));
    failures += expect(from_hex("a046e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449a44",
                                {clamped_scalar, clamped_scalar + x25519_key_size_k}));
    failures += expect(from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                                {shared_point, shared_point + x25519_key_size_k}));

    byte_t from_raw[x25519_key_size_k], from_clamped[x25519_key_size_k];
    failures += expect(x25519_multiply_serial(from_raw, raw_scalar, shared_point));
    failures += expect(x25519_multiply_serial(from_clamped, clamped_scalar, shared_point));
    failures += expect_bytes(from_raw, from_clamped);
    failures += expect_hex(from_raw, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

    byte_t nine[x25519_key_size_k] {};
    nine[0] = byte_t {9};
    byte_t derived[x25519_key_size_k];
    x25519_derive_public<serial_x25519_kit_t>(derived, nine);
    failures += expect_hex(derived, "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    return failures;
}

#pragma endregion Known Answers

#pragma region Kit Differential

/**
 *  @brief Every kit compiled into this build, against every vector and along a dependent chain.
 *
 *  The chain matters separately from the vectors: a carry bug a single multiplication hides
 *  compounds once each result feeds the next.
 */
static std::size_t test_x25519_kits() {
    std::size_t failures = 0;

    for (x25519_backend_t const& backend : x25519_backends_k) {
        if (!runnable_here(backend)) continue;
        for (x25519_vector_t const& vector : x25519_vectors_k) {
            decoded_vector_t const decoded(vector, failures);
            byte_t produced[x25519_key_size_k];
            shared_secret_t const answer = reported(
                backend.multiply(std::span {produced}, std::span {decoded.scalar}, std::span {decoded.point}));
            failures += expect(answer == vector.expected, "{} called {} a {} secret, expected {}", backend.name,
                               vector.label, answer, vector.expected);
            failures += expect_hex(produced, vector.shared_hex);
        }
    }

    // A carry bug one multiplication hides compounds once each result feeds the next, so every
    // backend walks the same dependent chain and must match the reference at every step.
    for (x25519_backend_t const& backend : x25519_backends_k) {
        if (!runnable_here(backend) || &backend == &x25519_reference_k) continue;

        byte_t scalar[x25519_key_size_k] {}, point[x25519_key_size_k] {};
        scalar[0] = byte_t {9}, point[0] = byte_t {9};
        for (std::size_t iteration = 0; iteration != scale_iterations(100); ++iteration) {
            byte_t expected[x25519_key_size_k], produced[x25519_key_size_k];
            [[maybe_unused]] bool const reference_usable = x25519_reference_k.multiply(
                std::span {expected}, std::span {scalar}, std::span {point});
            [[maybe_unused]] bool const candidate_usable = backend.multiply(std::span {produced}, std::span {scalar},
                                                                            std::span {point});
            failures += expect(bytes_equal(produced, expected), "{} left {} at iteration {}", backend.name,
                               x25519_reference_k.name, iteration);
            std::memcpy(point, scalar, x25519_key_size_k);
            std::memcpy(scalar, expected, x25519_key_size_k);
        }
    }
    return failures;
}

#pragma endregion Kit Differential

#pragma region Primitives

static std::size_t test_hmac() {
    std::size_t failures = 0;
    byte_t key_storage[131];
    byte_t data_storage[50];
    byte_t digest[crypto_t::hash_size_k];

    // RFC 4231 §4.2-§4.7, byte for byte: the named reproducer for `-fno-strict-aliasing`, so a
    // digest that drifts here is a miscompile rather than a redesign.
    failures += expect_hex(
        hmac_of(run_of({key_storage, key_storage + 20}, byte_t {0x0b}), byte_span("Hi There"), digest),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    failures += expect_hex(hmac_of(byte_span("Jefe"), byte_span("what do ya want for nothing?"), digest),
                           "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    failures += expect_hex(hmac_of(run_of({key_storage, key_storage + 20}, byte_t {0xaa}),
                                   run_of({data_storage, data_storage + 50}, byte_t {0xdd}), digest),
                           "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    failures += expect_hex(hmac_of(run_of({key_storage, key_storage + 131}, byte_t {0xaa}),
                                   byte_span("Test Using Larger Than Block-Size Key - Hash Key First"), digest),
                           "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    span<byte_t const> const cached_key = run_of({key_storage, key_storage + 40}, byte_t {0x5a});
    crypto_t::hmac_sha256_t cached;
    cached.reset(cached_key);
    for (char const* message : {"", "a", "the quick brown fox", "0123456789012345678901234567890123456789"}) {
        span<byte_t const> const data = byte_span(message);
        byte_t reused[crypto_t::hash_size_k], fresh[crypto_t::hash_size_k];
        cached.compute(data, {}, reused);
        crypto_t::hmac_sha256(cached_key, data, fresh);
        failures += expect_bytes(reused, fresh);
    }

    byte_t joined[17];
    std::memcpy(joined, "chaining-material", 17);
    crypto_t::hmac_sha256_t split_hmac;
    split_hmac.reset(run_of({key_storage, key_storage + 32}, byte_t {0x0b}));
    byte_t split[crypto_t::hash_size_k];
    split_hmac.compute(byte_span("chaining"), byte_span("-material"), split);
    failures += expect_bytes(split, hmac_of(run_of({key_storage, key_storage + 32}, byte_t {0x0b}), joined, digest));
    return failures;
}

static std::size_t test_hkdf() {
    std::size_t failures = 0;
    byte_t digest[crypto_t::hash_size_k];
    byte_t material_storage[22];
    span<byte_t const> const material = run_of({material_storage, material_storage + 22}, byte_t {0x0b});

    // Noise's HKDF is RFC 5869 with an empty info string, so the published key applies unchanged.
    byte_t const salt_storage[] = {byte_t {0x00}, byte_t {0x01}, byte_t {0x02}, byte_t {0x03}, byte_t {0x04},
                                   byte_t {0x05}, byte_t {0x06}, byte_t {0x07}, byte_t {0x08}, byte_t {0x09},
                                   byte_t {0x0a}, byte_t {0x0b}, byte_t {0x0c}};
    failures += expect_hex(hmac_of(salt_storage, material, digest),
                           "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");

    // With an empty info string, RFC 5869's T(1) reduces to HMAC(PRK, 0x01).
    byte_t chaining_key[crypto_t::hash_size_k];
    for (std::size_t index = 0; index != crypto_t::hash_size_k; ++index)
        chaining_key[index] = static_cast<byte_t>(index);

    byte_t outputs[3][crypto_t::hash_size_k];
    crypto_t::hkdf_sha256(chaining_key, material, 2, outputs);

    byte_t pseudo_random_key[crypto_t::hash_size_k];
    crypto_t::hmac_sha256(chaining_key, material, pseudo_random_key);
    byte_t const one = byte_t {0x01};
    byte_t expected[crypto_t::hash_size_k];
    crypto_t::hmac_sha256(pseudo_random_key, {&one, &one + 1}, expected);
    failures += expect_bytes(outputs[0], expected);

    byte_t empty_chaining_key[crypto_t::hash_size_k] {};
    byte_t chained[3][crypto_t::hash_size_k];
    crypto_t::hkdf_sha256(empty_chaining_key, {}, 2, chained);

    crypto_t::hmac_sha256(empty_chaining_key, {}, pseudo_random_key);
    byte_t const two = byte_t {0x02};
    crypto_t::hmac_sha256_t chaining_hmac;
    chaining_hmac.reset(pseudo_random_key);
    chaining_hmac.compute(chained[0], {&two, &two + 1}, expected);
    failures += expect_bytes(chained[1], expected);
    failures += expect(!bytes_equal(chained[0], chained[1]));

    byte_t two_outputs[3][crypto_t::hash_size_k] {};
    byte_t three_outputs[3][crypto_t::hash_size_k] {};
    crypto_t::hkdf_sha256(empty_chaining_key, {}, 2, two_outputs);
    crypto_t::hkdf_sha256(empty_chaining_key, {}, 3, three_outputs);
    failures += expect_bytes(two_outputs[0], three_outputs[0]);
    failures += expect_bytes(two_outputs[1], three_outputs[1]);
    failures += expect(all_zero(two_outputs[2]));
    failures += expect(!all_zero(three_outputs[2]));
    return failures;
}

static std::size_t test_entropy() {
    std::size_t failures = 0;
    // Not a statistical test - proof the platform call is wired, since zeros here would silently
    // destroy every ephemeral key.
    byte_t first[32] {}, second[32] {};
    failures += expect(crypto_t::secure_random_bytes(first) == secure_tunnel_fault_t::none_k);
    failures += expect(crypto_t::secure_random_bytes(second) == secure_tunnel_fault_t::none_k);
    failures += expect(!all_zero(first));
    failures += expect(!bytes_equal(first, second));
    return failures;
}

#pragma endregion Primitives

std::size_t check_crypto(settings_t const& settings) {
    if (!settings.filter.selects("tunnel crypto")) return 0;
    std::size_t failures = 0;
    failures += test_hmac();
    failures += test_hkdf();
    failures += test_entropy();
    failures += test_x25519();
    failures += test_x25519_kits();
    return report("tunnel crypto", failures);
}

} // namespace unum::ucall::test::tunnel
