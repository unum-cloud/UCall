/**
 *  @file test/noise.cpp
 *  @author Ash Vardanian
 *  @date August 9, 2026
 *  @brief Known-answer cryptographic vectors, Noise handshakes, framing, and record authentication.
 */
#include <cstring> // `std::memcpy`, `std::memmove`, `std::memset`

#include <string_view> // `std::string_view`

#include "harness.hpp" // `expect`, `require`, `run_test`, `scale_iterations`

#include "ucall/tunnel/crypto.hpp"        // `secure_tunnel_crypto`, the serial kits
#include "ucall/tunnel/secure_tunnel.hpp" // `secure_tunnel_t`

using namespace unum::ucall;
using namespace unum::ucall::tunnel;
using namespace unum::ucall::test;

using crypto_t = secure_tunnel_crypto<serial_sha256_kit_t, serial_aes256_gcm_kit_t, serial_x25519_kit_t>;

#pragma region Fixtures

/** Why a handshake stopped, which one @c bool cannot distinguish. */
enum class handshake_outcome_t : std::uint8_t {

    /** Both ends reached @c ready_k. */
    settled_k,

    /** One end reported a fault and stopped. */
    broken_k,

    /** Neither end faulted, and neither reached @c ready_k within the pattern's messages. */
    stalled_k,

    /** A key could not be drawn, or @c make refused the configuration. */
    misconfigured_k,
};

/** Lets `{}` name an outcome, so a failed handshake reads as a sentence. */
[[nodiscard]] inline auto format_as(handshake_outcome_t outcome) noexcept {
    switch (outcome) {
    case handshake_outcome_t::settled_k: return "settled";
    case handshake_outcome_t::broken_k: return "broken";
    case handshake_outcome_t::stalled_k: return "stalled";
    case handshake_outcome_t::misconfigured_k: return "misconfigured";
    }
    return "unknown";
}

/** Every pattern, in table form, so a sweep is a loop and not a copy-paste. */
static constexpr secure_tunnel_mode_t tunnel_modes_k[] = {
    secure_tunnel_mode_t::noise_xx_k, secure_tunnel_mode_t::noise_ik_k, secure_tunnel_mode_t::noise_kk_k};

/** Payload widths worth distinguishing, spelled out - never a raw count at a call site. */
enum class payload_width_t : std::uint32_t {
    empty_k = 0,
    single_byte_k = 1,
    typical_request_k = 512,
    small_buffer_k = fixture_buffer_bytes_k,
    ceiling_k = secure_tunnel_payload_ceiling_k,
};

static constexpr payload_width_t payload_widths_k[] = {payload_width_t::empty_k, payload_width_t::single_byte_k,
                                                       payload_width_t::typical_request_k,
                                                       payload_width_t::small_buffer_k, payload_width_t::ceiling_k};

/** Lets `{}` name a payload width rather than print its byte count twice. */
[[nodiscard]] inline auto format_as(payload_width_t width) noexcept {
    switch (width) {
    case payload_width_t::empty_k: return "empty";
    case payload_width_t::single_byte_k: return "single_byte";
    case payload_width_t::typical_request_k: return "typical_request";
    case payload_width_t::small_buffer_k: return "small_buffer";
    case payload_width_t::ceiling_k: return "ceiling";
    }
    return "unknown";
}

/** One driver's record buffer: reserved once, written in place, never copied out of. */
struct wire_t {
    st::vector<byte_t> storage {};
    std::size_t length {};

    /** Room for the widest record the wire format can name. */
    [[nodiscard]] bool reserve() noexcept { return reserve(secure_tunnel_max_record_k); }

    /** Room for exactly @p capacity bytes, as a driver sizing from @c record_size would. */
    [[nodiscard]] bool reserve(std::size_t capacity) noexcept { return !st::failed(storage.resize(capacity)); }
    [[nodiscard]] span<byte_t> whole() noexcept { return {storage.data(), storage.data() + storage.capacity()}; }
    [[nodiscard]] span<byte_t> arrived() noexcept { return {storage.data(), storage.data() + length}; }
    [[nodiscard]] span<byte_t const> received() const noexcept { return {storage.data(), storage.data() + length}; }
};

/** A Curve25519 keypair, drawn through the same call a bind or a client handle uses. */
struct keypair_t {
    byte_t secret[secure_tunnel_key_size_k] {};
    byte_t shared[secure_tunnel_key_size_k] {};

    [[nodiscard]] bool draw() noexcept {
        return secure_tunnel_generate_keypair(secret, shared) == secure_tunnel_fault_t::none_k;
    }
    [[nodiscard]] span<byte_t const> private_half() const noexcept { return secret; }
    [[nodiscard]] span<byte_t const> public_half() const noexcept { return shared; }
};

/** One direction of the in-memory wire between two handshaking ends. */
struct handshake_stream_t {

    /** Fixed storage: at most two messages are ever in flight at once. */
    byte_t bytes[crypto_t::outbound_capacity_k * 4] {};
    std::size_t length {};

    /** Appends @p more, or answers false and appends nothing when it would overflow. */
    [[nodiscard]] bool append(span<byte_t const> more) noexcept {
        if (length + more.size() > sizeof(bytes)) return false;
        if (more.size()) std::memcpy(bytes + length, more.data(), more.size());
        length += more.size();
        return true;
    }

    /** Drops @p count leading bytes, or answers false and drops nothing when fewer are pending. */
    [[nodiscard]] bool consume(std::size_t count) noexcept {
        if (count > length) return false;
        if (count && count != length) std::memmove(bytes, bytes + count, length - count);
        length -= count;
        return true;
    }

    /** What the peer sent and this end has not yet consumed. */
    [[nodiscard]] span<byte_t const> pending() const noexcept { return {bytes, bytes + length}; }
};

/**
 *  @brief Drives both ends of a handshake to completion over an in-memory wire.
 *
 *  @c advance promises neither side loops, so each end is driven exactly once per round. Needing
 *  more rounds than the pattern has messages would break that promise, which is why running out is
 *  reported apart from either side breaking.
 */
[[nodiscard]] static handshake_outcome_t complete_handshake(secure_tunnel_t& initiator,
                                                            secure_tunnel_t& responder) noexcept {
    handshake_stream_t toward_responder, toward_initiator;

    auto pump = [](secure_tunnel_t& tunnel, handshake_stream_t& inbound,
                   handshake_stream_t& outbound) noexcept -> secure_tunnel_state_t {
        secure_tunnel_step_t const step = tunnel.advance(inbound.pending());
        // A step consuming past its input or overflowing the wire reads as a broken peer.
        if (!inbound.consume(step.consumed) || !outbound.append(step.outbound)) return secure_tunnel_state_t::broken_k;
        return step.state;
    };

    for (std::size_t round = 0; round != 8; ++round) {
        if (pump(initiator, toward_initiator, toward_responder) == secure_tunnel_state_t::broken_k)
            return handshake_outcome_t::broken_k;
        if (pump(responder, toward_responder, toward_initiator) == secure_tunnel_state_t::broken_k)
            return handshake_outcome_t::broken_k;
        if (initiator.state() == secure_tunnel_state_t::ready_k && responder.state() == secure_tunnel_state_t::ready_k)
            return handshake_outcome_t::settled_k;
    }
    return handshake_outcome_t::stalled_k;
}

/** A connected pair in the given pattern, with fresh static keys on both sides. */
struct connected_pair_t {
    keypair_t client_keys, server_keys;
    secure_tunnel_t client, server;

    /** Completes a handshake in @p mode, counting a failure that names the pattern and outcome. */
    [[nodiscard]] std::size_t connect(secure_tunnel_mode_t mode, std::size_t max_payload = 0) {
        handshake_outcome_t const outcome = attempt(mode, max_payload);
        return expect(outcome == handshake_outcome_t::settled_k, "{} handshake {}", mode, outcome);
    }

    /** Whether @c attempt draws fresh static keys or uses the ones already in place. */
    enum class keys_t : bool { fresh_k, supplied_k };

    /** Reconnects on keys the caller already holds, for the cases about identity reuse. */
    [[nodiscard]] std::size_t connect_with(secure_tunnel_mode_t mode, keypair_t const& client_identity,
                                           keypair_t const& server_identity) {
        client_keys = client_identity;
        server_keys = server_identity;
        handshake_outcome_t const outcome = attempt(mode, 0, keys_t::supplied_k);
        return expect(outcome == handshake_outcome_t::settled_k, "{} handshake {}", mode, outcome);
    }

    [[nodiscard]] handshake_outcome_t attempt(secure_tunnel_mode_t mode, std::size_t max_payload,
                                              keys_t keys = keys_t::fresh_k) noexcept {
        if (keys == keys_t::fresh_k && (!client_keys.draw() || !server_keys.draw()))
            return handshake_outcome_t::misconfigured_k;

        secure_tunnel_config_t client_config;
        client_config.mode = mode;
        client_config.role = secure_tunnel_role_t::initiator_k;
        client_config.local_private = client_keys.private_half();
        client_config.local_public = client_keys.public_half();
        client_config.max_payload = max_payload;
        // `IK` and `KK` give the initiator the responder's key ahead of the first message.
        if (mode == secure_tunnel_mode_t::noise_ik_k || mode == secure_tunnel_mode_t::noise_kk_k)
            client_config.peer_public = server_keys.public_half();

        secure_tunnel_config_t server_config;
        server_config.mode = mode;
        server_config.role = secure_tunnel_role_t::responder_k;
        server_config.local_private = server_keys.private_half();
        server_config.local_public = server_keys.public_half();
        server_config.max_payload = max_payload;
        // Only `KK` pre-shares the initiator's key with the responder.
        if (mode == secure_tunnel_mode_t::noise_kk_k) server_config.peer_public = client_keys.public_half();

        if (client.make(client_config) != secure_tunnel_fault_t::none_k) return handshake_outcome_t::misconfigured_k;
        if (server.make(server_config) != secure_tunnel_fault_t::none_k) return handshake_outcome_t::misconfigured_k;
        return complete_handshake(client, server);
    }
};

/** Seals one payload into @p wire, in place, as a driver would, counting a refusal as a failure. */
[[nodiscard]] static std::size_t seal_into(secure_tunnel_t& tunnel, span<byte_t const> payload, wire_t& wire) {
    span<byte_t> const window = tunnel.payload_window(wire.whole());
    require(0, window.size() >= payload.size(), "a {}-byte window cannot hold {} bytes", window.size(), payload.size());
    if (payload.size()) std::memcpy(window.data(), payload.data(), payload.size());
    wire.length = tunnel.seal(wire.whole(), payload.size()).size();
    return expect(wire.length > 0u, "the tunnel refused a {}-byte payload with {}", payload.size(), tunnel.fault());
}

/** Opens one whole record from a wire buffer, in place,
 *  passing the record's own body as the destination. */
[[nodiscard]] static secure_tunnel_opened_t open_from(secure_tunnel_t& tunnel, wire_t& wire) noexcept {
    span<byte_t> const arrived = wire.arrived();
    return tunnel.open(arrived, arrived.subspan(arrived.size() < secure_tunnel_headroom_k ? arrived.size()
                                                                                          : secure_tunnel_headroom_k));
}

/** The big-endian length a record declares in its prefix. */
[[nodiscard]] static std::size_t declared_length(wire_t& wire) noexcept {
    span<byte_t const> const prefix = wire.received();
    return (static_cast<std::size_t>(prefix[0]) << 8) | static_cast<std::size_t>(prefix[1]);
}

/**
 *  @brief Builds a run of one repeated byte in scratch storage and views it.
 *
 *  Safe to alias its own argument only because the storage is scratch the caller never reads back;
 *  a sweep that re-reads its buffer keeps the fill and the view apart.
 */
[[nodiscard]] static span<byte_t const> run_of(span<byte_t> bytes, byte_t value) noexcept {
    fill_with(bytes, value);
    return bytes;
}

/** Computes one tag into @p digest and returns a view of it. */
[[nodiscard]] static span<byte_t const> hmac_of(span<byte_t const> key, span<byte_t const> data,
                                                span<byte_t, crypto_t::hash_size_k> digest) noexcept {
    crypto_t::hmac_sha256(key, data, digest);
    return digest;
}

#pragma endregion Fixtures

#pragma region Primitives

case_result_t test_hmac_unit() {
    std::size_t failures = 0;
    byte_t key_storage[131];
    byte_t data_storage[50];
    byte_t digest[crypto_t::hash_size_k];

    // RFC 4231 §4.2-§4.7, byte for byte: the named reproducer for `-fno-strict-aliasing`, so a
    // digest that drifts here is a miscompile rather than a redesign.
    announce("rfc4231_case1");
    failures += expect_hex(
        hmac_of(run_of({key_storage, key_storage + 20}, byte_t {0x0b}), byte_span("Hi There"), digest),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    announce("rfc4231_case2");
    failures += expect_hex(hmac_of(byte_span("Jefe"), byte_span("what do ya want for nothing?"), digest),
                           "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    announce("rfc4231_case3");
    failures += expect_hex(hmac_of(run_of({key_storage, key_storage + 20}, byte_t {0xaa}),
                                   run_of({data_storage, data_storage + 50}, byte_t {0xdd}), digest),
                           "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    announce("rfc4231_case6_key_longer_than_block");
    failures += expect_hex(hmac_of(run_of({key_storage, key_storage + 131}, byte_t {0xaa}),
                                   byte_span("Test Using Larger Than Block-Size Key - Hash Key First"), digest),
                           "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    announce("cached_state_matches_one_shot");
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

    announce("split_input_matches_concatenated");
    byte_t joined[17];
    std::memcpy(joined, "chaining-material", 17);
    crypto_t::hmac_sha256_t split_hmac;
    split_hmac.reset(run_of({key_storage, key_storage + 32}, byte_t {0x0b}));
    byte_t split[crypto_t::hash_size_k];
    split_hmac.compute(byte_span("chaining"), byte_span("-material"), split);
    failures += expect_bytes(split, hmac_of(run_of({key_storage, key_storage + 32}, byte_t {0x0b}), joined, digest));
    return failures;
}

case_result_t test_hkdf_unit() {
    std::size_t failures = 0;
    byte_t digest[crypto_t::hash_size_k];
    byte_t material_storage[22];
    span<byte_t const> const material = run_of({material_storage, material_storage + 22}, byte_t {0x0b});

    // Noise's HKDF is RFC 5869 with an empty info string, so the published key applies unchanged.
    announce("rfc5869_case1_extract");
    byte_t const salt_storage[] = {byte_t {0x00}, byte_t {0x01}, byte_t {0x02}, byte_t {0x03}, byte_t {0x04},
                                   byte_t {0x05}, byte_t {0x06}, byte_t {0x07}, byte_t {0x08}, byte_t {0x09},
                                   byte_t {0x0a}, byte_t {0x0b}, byte_t {0x0c}};
    failures += expect_hex(hmac_of(salt_storage, material, digest),
                           "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");

    // With an empty info string, RFC 5869's T(1) reduces to HMAC(PRK, 0x01).
    announce("first_output_is_expand_of_extract");
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

    announce("second_output_chains_from_the_first");
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

    announce("third_output_only_derived_when_asked");
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

case_result_t test_transcript_unit() {
    std::size_t failures = 0;
    std::string_view const name = "Noise_XX_25519_AESGCM_SHA256";

    announce("a_short_protocol_name_is_zero_padded");
    require(failures, name.size() <= crypto_t::hash_size_k);
    crypto_t::secure_tunnel_transcript_t padded;
    padded.initialize(name);
    byte_t expected[crypto_t::hash_size_k] {};
    std::memcpy(expected, name.data(), name.size());
    failures += expect_bytes(padded.hash(), expected);

    announce("a_long_protocol_name_is_hashed");
    char long_name[40];
    for (char& character : long_name) character = 'x';
    crypto_t::secure_tunnel_transcript_t hashed;
    hashed.initialize({long_name, sizeof(long_name)});

    sz_sha256_state_t digest_state;
    crypto_t::sha_init(&digest_state, nullptr);
    crypto_t::sha_update(&digest_state, long_name, sizeof(long_name), nullptr);
    byte_t hashed_expected[crypto_t::hash_size_k];
    crypto_t::sha_digest(&digest_state, reinterpret_cast<sz_u8_t*>(hashed_expected), nullptr);
    failures += expect_bytes(hashed.hash(), hashed_expected);

    announce("mixing_is_order_sensitive");
    crypto_t::secure_tunnel_transcript_t forward, backward;
    forward.initialize(name);
    backward.initialize(name);
    byte_t const first[4] = {byte_t {1}, byte_t {2}, byte_t {3}, byte_t {4}};
    byte_t const second[4] = {byte_t {5}, byte_t {6}, byte_t {7}, byte_t {8}};
    forward.mix_hash(first);
    forward.mix_hash(second);
    backward.mix_hash(second);
    backward.mix_hash(first);
    // A transcript that ignored ordering would let a peer reorder the handshake.
    failures += expect(!bytes_equal(forward.hash(), backward.hash()));

    announce("an_empty_prologue_still_advances_the_transcript");
    crypto_t::secure_tunnel_transcript_t prologued;
    prologued.initialize(name);
    byte_t before[crypto_t::hash_size_k];
    std::memcpy(before, prologued.hash().data(), crypto_t::hash_size_k);
    prologued.mix_hash({});
    failures += expect(!bytes_equal(prologued.hash(), before));
    return failures;
}

case_result_t test_entropy_unit() {
    std::size_t failures = 0;
    // Not a statistical test - proof the platform call is wired, since zeros here would silently
    // destroy every ephemeral key.
    announce("distinct_and_never_all_zero");
    byte_t first[32] {}, second[32] {};
    failures += expect(crypto_t::secure_random_bytes(first) == secure_tunnel_fault_t::none_k);
    failures += expect(crypto_t::secure_random_bytes(second) == secure_tunnel_fault_t::none_k);
    failures += expect(!all_zero(first));
    failures += expect(!bytes_equal(first, second));
    return failures;
}

#pragma endregion Primitives

#pragma region Configuration

case_result_t test_config_unit() {
    std::size_t failures = 0;
    announce("plaintext_is_born_ready_and_frames_nothing");
    secure_tunnel_t plain;
    failures += expect(plain.state() == secure_tunnel_state_t::ready_k);
    failures += expect(!plain.encrypts());
    failures += expect(plain.may_seal());
    failures += expect(plain.may_open());
    failures += expect(plain.geometry().headroom == 0u);
    failures += expect(plain.geometry().tailroom == 0u);
    failures += expect(plain.bytes_until_boundary({}) == 0u);

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{}", mode);

        connected_pair_t pair;
        failures += pair.connect(mode);
        secure_tunnel_geometry_t const geometry = pair.client.geometry();
        failures += expect(geometry.headroom == secure_tunnel_headroom_k);
        failures += expect(geometry.tailroom == secure_tunnel_tailroom_k);
        failures += expect(geometry.max_payload == secure_tunnel_default_payload_k);
        failures += expect(geometry.record_size() == secure_tunnel_default_payload_k + secure_tunnel_overhead_k);

        connected_pair_t oversized;
        failures += oversized.connect(mode, secure_tunnel_payload_ceiling_k + 4096);
        failures += expect(oversized.client.geometry().max_payload == secure_tunnel_payload_ceiling_k);
    }
    return failures;
}

case_result_t test_config_safety() {
    std::size_t failures = 0;
    // An absent static key would silently become a scalar of zeros.
    announce("every_pattern_demands_a_local_static_key");
    for (secure_tunnel_mode_t const mode : tunnel_modes_k)
        for (secure_tunnel_role_t const role : {secure_tunnel_role_t::initiator_k, secure_tunnel_role_t::responder_k}) {
            secure_tunnel_t tunnel;
            secure_tunnel_config_t config;
            config.mode = mode;
            config.role = role;
            failures += expect(tunnel.make(config) == secure_tunnel_fault_t::misconfigured_k,
                               "{} {} accepted a configuration with no local static key", mode, role);
        }

    keypair_t keys;
    failures += expect(keys.draw());

    announce("a_key_of_the_wrong_width_is_rejected");
    secure_tunnel_t narrow;
    secure_tunnel_config_t narrow_config;
    narrow_config.mode = secure_tunnel_mode_t::noise_xx_k;
    narrow_config.role = secure_tunnel_role_t::responder_k;
    narrow_config.local_private = {keys.secret, keys.secret + 16}; // half a key
    failures += expect(narrow.make(narrow_config) == secure_tunnel_fault_t::misconfigured_k);

    // An `IK` initiator hashes the responder's static before message one, so it cannot come from
    // the wire - the transcripts would diverge before anything is sent.
    announce("a_pre_shared_key_is_required_where_the_pattern_hashes_it_first");
    secure_tunnel_t unshared;
    secure_tunnel_config_t unshared_config;
    unshared_config.mode = secure_tunnel_mode_t::noise_ik_k;
    unshared_config.role = secure_tunnel_role_t::initiator_k;
    unshared_config.local_private = keys.private_half();
    failures += expect(unshared.make(unshared_config) == secure_tunnel_fault_t::misconfigured_k);
    return failures;
}

/**
 *  @brief What a bind's `max_payload` bounds on ingress.
 *
 *  The sender sizes records from its own `geometry().record_size()`, so a peer configured wider can
 *  seal records this side never agreed to hold. `open` bounds every record by this side's cap.
 */
case_result_t test_geometry_safety() {
    std::size_t failures = 0;
    wire_t wire;
    require(failures, wire.reserve());

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{} an_ingress_record_wider_than_this_binds_cap_is_refused", mode);

        keypair_t client_identity, server_identity;
        failures += expect(client_identity.draw());
        failures += expect(server_identity.draw());

        // The mismatch a deployment actually produces: one side bounds its memory, the other
        // was configured by someone else and never agreed to.
        secure_tunnel_config_t client_config, server_config;
        client_config.mode = server_config.mode = mode;
        client_config.role = secure_tunnel_role_t::initiator_k;
        server_config.role = secure_tunnel_role_t::responder_k;
        client_config.local_private = client_identity.private_half();
        client_config.local_public = client_identity.public_half();
        server_config.local_private = server_identity.private_half();
        server_config.local_public = server_identity.public_half();
        if (mode != secure_tunnel_mode_t::noise_xx_k) client_config.peer_public = server_identity.public_half();
        if (mode == secure_tunnel_mode_t::noise_kk_k) server_config.peer_public = client_identity.public_half();
        client_config.max_payload = secure_tunnel_payload_ceiling_k;
        server_config.max_payload = 1024;

        secure_tunnel_t client, server;
        failures += expect(client.make(client_config) == secure_tunnel_fault_t::none_k);
        failures += expect(server.make(server_config) == secure_tunnel_fault_t::none_k);
        failures += expect(complete_handshake(client, server) == handshake_outcome_t::settled_k);

        std::size_t const server_buffer = server.geometry().record_size();
        failures += expect(server_buffer == 1024 + secure_tunnel_overhead_k);

        span<byte_t> const window = client.payload_window(wire.whole());
        failures += expect(window.size() == secure_tunnel_payload_ceiling_k);
        fill_with(window, byte_t {'X'});
        wire.length = client.seal(wire.whole(), 1024).size();
        secure_tunnel_opened_t const at_cap = open_from(server, wire);
        failures += expect(at_cap.consumed == wire.length, "{} refused a record at its cap with {}", mode,
                           server.fault());
        failures += expect(at_cap.payload.size() == 1024u);

        fill_with(window, byte_t {'X'});
        wire.length = client.seal(wire.whole(), 1025).size();
        failures += expect(wire.length > server_buffer, "the capped side was not the smaller one");

        // What a driver sees first: two bytes of prefix, and a demand the boundary rule trusts.
        std::size_t const demanded = server.bytes_until_boundary(wire.whole().first(secure_tunnel_headroom_k));
        failures += expect(demanded == wire.length - secure_tunnel_headroom_k);

        failures += expect(open_from(server, wire).consumed == 0u, "{} opened a record past its cap", mode);
        failures += expect(server.fault() == secure_tunnel_fault_t::malformed_k);
        failures += expect(server.state() == secure_tunnel_state_t::broken_k);
    }
    return failures;
}

#pragma endregion Configuration

#pragma region Handshake

case_result_t test_handshake_unit() {
    std::size_t failures = 0;
    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{}", mode);

        connected_pair_t pair;
        failures += pair.connect(mode);
        failures += expect(pair.client.may_seal());
        failures += expect(pair.client.may_open());
        failures += expect(pair.server.may_seal());
        failures += expect(pair.server.may_open());

        // `KK` transmits no static token, so nothing promotes a peer key while reading - only the
        // split does, which is what makes this hold for that pattern.
        byte_t seen_by_client[secure_tunnel_key_size_k];
        byte_t seen_by_server[secure_tunnel_key_size_k];
        failures += expect(pair.client.peer_key(seen_by_client));
        failures += expect(pair.server.peer_key(seen_by_server));
        failures += expect_bytes(seen_by_client, pair.server_keys.public_half());
        failures += expect_bytes(seen_by_server, pair.client_keys.public_half());
    }

    // A configured key is assumed, not proven, and must stay unreported until authenticated.
    announce("a_configured_peer_key_is_not_yet_a_proven_one");
    keypair_t client_keys, server_keys;
    failures += expect(client_keys.draw());
    failures += expect(server_keys.draw());

    secure_tunnel_t unproven;
    secure_tunnel_config_t unproven_config;
    unproven_config.mode = secure_tunnel_mode_t::noise_ik_k;
    unproven_config.role = secure_tunnel_role_t::initiator_k;
    unproven_config.local_private = client_keys.private_half();
    unproven_config.peer_public = server_keys.public_half();
    failures += expect(unproven.make(unproven_config) == secure_tunnel_fault_t::none_k);

    byte_t seen[secure_tunnel_key_size_k];
    failures += expect(!unproven.peer_key(seen));
    failures += expect(unproven.state() == secure_tunnel_state_t::starting_k);

    announce("each_role_parks_where_it_cannot_deadlock");
    keypair_t keys;
    failures += expect(keys.draw());
    secure_tunnel_config_t config;
    config.mode = secure_tunnel_mode_t::noise_xx_k;
    config.local_private = keys.private_half();

    secure_tunnel_t initiator;
    config.role = secure_tunnel_role_t::initiator_k;
    failures += expect(initiator.make(config) == secure_tunnel_fault_t::none_k);
    secure_tunnel_step_t const first = initiator.advance({});
    failures += expect(first.state == secure_tunnel_state_t::transmitting_k); // an initiator writes before reading
    failures += expect(first.outbound.size() > 0u);

    secure_tunnel_t responder;
    config.role = secure_tunnel_role_t::responder_k;
    failures += expect(responder.make(config) == secure_tunnel_fault_t::none_k);
    secure_tunnel_step_t const second = responder.advance({});
    failures += expect(second.state == secure_tunnel_state_t::receiving_k); // a responder has nothing to say first
    failures += expect(second.outbound.size() == 0u);

    // Forward secrecy: an attacker who later takes the static key, or reads this process's
    // memory, must not be able to reconstruct session keys for traffic already sent.
    announce("ephemeral_secrets_are_destroyed_at_the_split");
    crypto_t::secure_tunnel_noise_t noise;
    noise.role = secure_tunnel_role_t::initiator_k;
    std::memset(noise.local_ephemeral_private, 0xAB, sizeof(noise.local_ephemeral_private));
    std::memset(noise.remote_ephemeral, 0xCD, sizeof(noise.remote_ephemeral));
    std::memset(noise.local_static_private, 0xEF, sizeof(noise.local_static_private));
    std::memset(noise.remote_static, 0x22, sizeof(noise.remote_static));
    noise.remote_static_state = crypto_t::remote_static_t::authenticated_k;

    crypto_t::finish_handshake(noise);

    failures += expect(all_zero(noise.local_ephemeral_private));
    failures += expect(all_zero(noise.remote_ephemeral));
    failures += expect(all_zero(noise.local_static_private));
    // The peer's public half survives - it is the answer `peer_key` exists to give.
    failures += expect(all_equal_to(noise.remote_static, byte_t {0x22}));
    failures += expect(noise.sending.has_key());
    failures += expect(noise.receiving.has_key());
    return failures;
}

case_result_t test_handshake_safety() {
    std::size_t failures = 0;
    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{}", mode);

        keypair_t client_keys, server_keys;
        failures += expect(client_keys.draw());
        failures += expect(server_keys.draw());

        secure_tunnel_config_t client_config;
        client_config.mode = mode;
        client_config.role = secure_tunnel_role_t::initiator_k;
        client_config.local_private = client_keys.private_half();
        client_config.local_public = client_keys.public_half();
        if (mode != secure_tunnel_mode_t::noise_xx_k) client_config.peer_public = server_keys.public_half();

        secure_tunnel_config_t server_config;
        server_config.mode = mode;
        server_config.role = secure_tunnel_role_t::responder_k;
        server_config.local_private = server_keys.private_half();
        server_config.local_public = server_keys.public_half();
        if (mode == secure_tunnel_mode_t::noise_kk_k) server_config.peer_public = client_keys.public_half();

        // A peer forcing a shared secret it already knows is an attack, not the operating system
        // refusing entropy, and the two must not collapse into one fault.
        secure_tunnel_t initiator, responder;
        failures += expect(initiator.make(client_config) == secure_tunnel_fault_t::none_k);
        failures += expect(responder.make(server_config) == secure_tunnel_fault_t::none_k);

        secure_tunnel_step_t const first = initiator.advance({});
        failures += expect(first.state == secure_tunnel_state_t::transmitting_k);
        handshake_stream_t message;
        failures += expect(message.append(first.outbound));

        // Every pattern's opening message carries one ephemeral in the clear behind the length
        // prefix. All zeros is the canonical small-order point.
        failures += expect(message.length >= secure_tunnel_headroom_k + secure_tunnel_key_size_k);
        std::memset(message.bytes + secure_tunnel_headroom_k, 0, secure_tunnel_key_size_k);

        secure_tunnel_step_t const answer = responder.advance(message.pending());
        failures += expect(answer.state == secure_tunnel_state_t::broken_k);
        failures += expect(responder.fault() == secure_tunnel_fault_t::authentication_failed_k);

        // Too short for the ephemeral is malformed, not hostile; the faults must differ.
        secure_tunnel_t truncated_responder;
        failures += expect(truncated_responder.make(server_config) == secure_tunnel_fault_t::none_k);
        byte_t const truncated[] = {byte_t {0x00}, byte_t {0x04}, byte_t {0xde},
                                    byte_t {0xad}, byte_t {0xbe}, byte_t {0xef}};
        secure_tunnel_step_t const refused = truncated_responder.advance(truncated);
        failures += expect(refused.state == secure_tunnel_state_t::broken_k);
        failures += expect(truncated_responder.fault() == secure_tunnel_fault_t::malformed_k);
    }
    return failures;
}

/**
 *  @brief Every handshake message delivered one byte at a time.
 *
 *  `advance` reports what it consumed, so a partial message must leave the bytes in the caller's
 *  hands and emit nothing until a whole one has landed.
 */
case_result_t test_handshake_delivery() {
    std::size_t failures = 0;
    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{}", mode);

        connected_pair_t pair;
        keypair_t client_identity, server_identity;
        failures += expect(client_identity.draw());
        failures += expect(server_identity.draw());
        pair.client_keys = client_identity;
        pair.server_keys = server_identity;

        secure_tunnel_config_t client_config, server_config;
        client_config.mode = server_config.mode = mode;
        client_config.role = secure_tunnel_role_t::initiator_k;
        server_config.role = secure_tunnel_role_t::responder_k;
        client_config.local_private = client_identity.private_half();
        client_config.local_public = client_identity.public_half();
        server_config.local_private = server_identity.private_half();
        server_config.local_public = server_identity.public_half();
        if (mode != secure_tunnel_mode_t::noise_xx_k) client_config.peer_public = server_identity.public_half();
        if (mode == secure_tunnel_mode_t::noise_kk_k) server_config.peer_public = client_identity.public_half();

        secure_tunnel_t initiator, responder;
        failures += expect(initiator.make(client_config) == secure_tunnel_fault_t::none_k);
        failures += expect(responder.make(server_config) == secure_tunnel_fault_t::none_k);

        handshake_stream_t toward_responder, toward_initiator;
        auto trickle = [&failures](secure_tunnel_t& tunnel, handshake_stream_t& inbound, handshake_stream_t& outbound) {
            // Everything but the last byte must be refused as incomplete.
            for (std::size_t fed = 1; fed < inbound.length; ++fed) {
                secure_tunnel_step_t const partial = tunnel.advance({inbound.bytes, inbound.bytes + fed});
                failures += expect(partial.state != secure_tunnel_state_t::broken_k,
                                   "{} bytes of a message broke the peer", fed);
                failures += expect(partial.consumed == 0u, "{} of {} bytes were consumed from a partial message",
                                   partial.consumed, inbound.length);
                failures += expect(partial.outbound.size() == 0u, "a partial message produced {} outbound bytes",
                                   partial.outbound.size());
            }
            secure_tunnel_step_t const step = tunnel.advance(inbound.pending());
            if (!inbound.consume(step.consumed) || !outbound.append(step.outbound))
                return secure_tunnel_state_t::broken_k;
            return step.state;
        };

        for (std::size_t round = 0; round != 8; ++round) {
            failures += expect(trickle(initiator, toward_initiator, toward_responder) !=
                               secure_tunnel_state_t::broken_k);
            failures += expect(trickle(responder, toward_responder, toward_initiator) !=
                               secure_tunnel_state_t::broken_k);
            if (initiator.state() == secure_tunnel_state_t::ready_k &&
                responder.state() == secure_tunnel_state_t::ready_k)
                break;
        }
        failures += expect(initiator.state() == secure_tunnel_state_t::ready_k,
                           "a trickled {} handshake left the initiator {}", mode, initiator.state());
        failures += expect(responder.state() == secure_tunnel_state_t::ready_k,
                           "a trickled {} handshake left the responder {}", mode, responder.state());
    }
    return failures;
}

#pragma endregion Handshake

#pragma region Records

case_result_t test_records_unit() {
    std::size_t failures = 0;
    wire_t wire;
    require(failures, wire.reserve());

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{}", mode);

        connected_pair_t pair;
        failures += pair.connect(mode);

        failures += seal_into(pair.client, byte_span("GET / HTTP/1.1"), wire);
        failures += expect(pair.server.bytes_until_boundary(wire.received()) == 0u);
        secure_tunnel_opened_t const request = open_from(pair.server, wire);
        failures += expect(request.consumed > 0u);
        failures += expect(request.kind == secure_tunnel_record_t::application_k);
        failures += expect(request.payload.data() == wire.whole().subspan(secure_tunnel_headroom_k).data());
        failures += expect_bytes(request.payload, byte_span("GET / HTTP/1.1"));

        failures += seal_into(pair.server, byte_span("HTTP/1.1 200 OK"), wire);
        failures += expect(pair.client.bytes_until_boundary(wire.received()) == 0u);
        secure_tunnel_opened_t const reply = open_from(pair.client, wire);
        failures += expect(reply.consumed > 0u);
        failures += expect_bytes(reply.payload, byte_span("HTTP/1.1 200 OK"));

        // A driver opening into its own buffer finds the payload there
        // and the record as it arrived.
        failures += seal_into(pair.client, byte_span("into a destination"), wire);
        byte_t sealed[64] {}, destination[64] {};
        std::memcpy(sealed, wire.received().data(), wire.received().size_bytes());
        secure_tunnel_opened_t const apart = pair.server.open(wire.arrived(), destination);
        failures += expect(apart.consumed == wire.length);
        failures += expect(apart.payload.data() == destination);
        failures += expect_bytes(apart.payload, byte_span("into a destination"));
        failures += expect(bytes_equal(wire.received(), {sealed, sealed + wire.length}),
                           "opening into a destination rewrote the record");

        // One byte less than this minimum decrypts to nothing, after which reading the kind byte
        // would run off the end of the plaintext.
        failures += seal_into(pair.client, {}, wire);
        failures += expect(wire.length == secure_tunnel_headroom_k + secure_tunnel_tailroom_k);
        failures += expect(declared_length(wire) == crypto_t::tag_size_k + crypto_t::kind_size_k);
        secure_tunnel_opened_t const empty = open_from(pair.server, wire);
        failures += expect(empty.consumed > 0u);
        failures += expect(empty.payload.size() == 0u);

        // Diverging counts diverge the rekey schedules, after which every record fails
        // authentication while looking exactly like an attack.
        std::size_t const already_sealed = pair.client.records_sealed();
        std::size_t const already_opened = pair.server.records_opened();
        for (std::size_t index = 0; index != 16; ++index) {
            failures += seal_into(pair.client, byte_span("ping"), wire);
            failures += expect(open_from(pair.server, wire).consumed > 0u);
            failures += seal_into(pair.server, byte_span("pong"), wire);
            failures += expect(open_from(pair.client, wire).consumed > 0u);
        }
        failures += expect(pair.client.records_sealed() == pair.server.records_opened());
        failures += expect(pair.server.records_sealed() == pair.client.records_opened());
        failures += expect(pair.client.records_sealed() == already_sealed + 16);
        failures += expect(pair.server.records_opened() == already_opened + 16);
    }

    // A ceiling that ignored the kind byte would declare 65536, mask to zero, and be rejected.
    announce("a_maximum_size_payload_fits_the_wire_format");
    st::vector<byte_t> payload;
    require(failures, !st::failed(payload.resize(secure_tunnel_payload_ceiling_k)));
    span<byte_t> const widest_scratch {payload.data(), payload.data() + secure_tunnel_payload_ceiling_k};
    fill_with(widest_scratch, byte_t {'M'});
    span<byte_t const> const widest = widest_scratch;

    connected_pair_t widest_pair;
    failures += widest_pair.connect(secure_tunnel_mode_t::noise_xx_k, secure_tunnel_payload_ceiling_k);
    failures += seal_into(widest_pair.client, widest, wire);
    failures += expect(declared_length(wire) == crypto_t::max_message_k);
    failures += expect(wire.length == secure_tunnel_headroom_k + crypto_t::max_message_k);
    failures += expect(widest_pair.server.bytes_until_boundary(wire.received()) == 0u);
    secure_tunnel_opened_t const opened = open_from(widest_pair.server, wire);
    failures += expect(opened.consumed > 0u);
    failures += expect(opened.payload.size() == secure_tunnel_payload_ceiling_k);

    // Isolated from framing: two identical senders produce identical records, so the only
    // variable left is what a reader offers as associated data. Invisible to any test that
    // tampers with the prefix instead, because tampering also moves the tag.
    // A driver reserves `record_size()`, not the format's maximum, so the exact buffer is what
    // exposes an off-by-one that a generous one hides.
    announce("a_driver_sized_buffer_holds_a_maximum_payload");
    connected_pair_t exact_pair;
    failures += exact_pair.connect(secure_tunnel_mode_t::noise_xx_k, secure_tunnel_payload_ceiling_k);
    wire_t exact;
    require(failures, exact.reserve(exact_pair.client.geometry().record_size()));
    failures += expect(exact.storage.capacity() == secure_tunnel_max_record_k,
                       "the ceiling's record_size should be the maximum");
    failures += seal_into(exact_pair.client, widest, exact);
    failures += expect(exact.length == exact.storage.capacity(), "a maximum record did not fill its exact buffer");
    failures += expect(open_from(exact_pair.server, exact).payload.size() == secure_tunnel_payload_ceiling_k);

    // The same at a modest cap, where `record_size()` is nowhere near the format's maximum.
    connected_pair_t modest_pair;
    failures += modest_pair.connect(secure_tunnel_mode_t::noise_xx_k, 1024);
    wire_t modest;
    require(failures, modest.reserve(modest_pair.client.geometry().record_size()));
    span<byte_t> const modest_window = modest_pair.client.payload_window(modest.whole());
    failures += expect(modest_window.size() == 1024u, "a {}-byte buffer offered a {}-byte window",
                       modest.storage.capacity(), modest_window.size());
    fill_with(modest_window, byte_t {'m'});
    modest.length = modest_pair.client.seal(modest.whole(), modest_window.size()).size();
    failures += expect(modest.length == modest.storage.capacity(), "a capped record did not fill its exact buffer");
    failures += expect(open_from(modest_pair.server, modest).payload.size() == 1024u);

    // A client reusing one static identity across connections is ordinary; the sessions must still
    // be independent, so byte-identical plaintext must not produce byte-identical ciphertext.
    announce("one_identity_yields_independent_sessions");
    keypair_t reused_client, reused_server;
    failures += expect(reused_client.draw());
    failures += expect(reused_server.draw());

    wire_t first_session, second_session;
    require(failures, first_session.reserve());
    require(failures, second_session.reserve());
    connected_pair_t earlier, later;
    failures += earlier.connect_with(secure_tunnel_mode_t::noise_xx_k, reused_client, reused_server);
    failures += later.connect_with(secure_tunnel_mode_t::noise_xx_k, reused_client, reused_server);
    failures += seal_into(earlier.client, byte_span("identical plaintext"), first_session);
    failures += seal_into(later.client, byte_span("identical plaintext"), second_session);
    failures += expect(first_session.length == second_session.length);
    failures += expect(!bytes_equal(first_session.received(), second_session.received()),
                       "two sessions on one identity produced the same ciphertext");

    announce("sealing_binds_the_length_prefix_into_the_tag");
    byte_t key[secure_tunnel_key_size_k];
    for (std::size_t index = 0; index != sizeof(key); ++index) key[index] = static_cast<byte_t>(index * 7u + 1u);

    auto seal_from_a_fresh_sender = [&key, &failures](span<byte_t> record) {
        crypto_t::secure_tunnel_noise_t sender;
        sender.sending.initialize(key);
        std::memcpy(record.subspan(secure_tunnel_headroom_k).data(), "bound", 5);
        std::size_t const produced = crypto_t::seal_record(sender, record, 5, secure_tunnel_record_t::application_k);
        failures += expect(produced > 0u, "a fresh sender refused a five-byte payload");
        return produced;
    };

    byte_t first_record[64] {}, second_record[64] {};
    std::size_t const written = seal_from_a_fresh_sender(first_record);
    failures += expect(seal_from_a_fresh_sender(second_record) == written,
                       "two identical seals produced different lengths");
    failures += expect(bytes_equal({first_record, first_record + written}, {second_record, second_record + written}),
                       "identical senders sealing identical payloads must agree byte for byte");

    std::size_t const body_size = 5 + crypto_t::kind_size_k;
    crypto_t::secure_tunnel_cipher_t honest;
    honest.initialize(key);
    failures += expect(
        honest.open({first_record, first_record + secure_tunnel_headroom_k},
                    {first_record + secure_tunnel_headroom_k, first_record + secure_tunnel_headroom_k + body_size},
                    first_record + secure_tunnel_headroom_k + body_size,
                    first_record + secure_tunnel_headroom_k) == secure_tunnel_fault_t::none_k);

    crypto_t::secure_tunnel_cipher_t forgetful;
    forgetful.initialize(key);
    failures += expect(
        forgetful.open({},
                       {second_record + secure_tunnel_headroom_k, second_record + secure_tunnel_headroom_k + body_size},
                       second_record + secure_tunnel_headroom_k + body_size,
                       second_record + secure_tunnel_headroom_k) == secure_tunnel_fault_t::authentication_failed_k);
    return failures;
}

case_result_t test_records_safety() {
    std::size_t failures = 0;
    wire_t wire, replayed;
    require(failures, wire.reserve());
    require(failures, replayed.reserve());

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        {
            announce("{} a_forged_tag_breaks_the_connection", mode);
            connected_pair_t pair;
            failures += pair.connect(mode);
            failures += seal_into(pair.client, byte_span("authentic"), wire);
            span<byte_t> const bytes = wire.whole();
            bytes[wire.length - 1] ^= byte_t {0x01u};
            failures += expect(open_from(pair.server, wire).consumed == 0u);
            failures += expect(pair.server.fault() == secure_tunnel_fault_t::authentication_failed_k);
            failures += expect(pair.server.state() == secure_tunnel_state_t::broken_k);
        }
        {
            // A shortened prefix still leaves a whole record present by the boundary rule, so
            // `open` has to be the thing that objects.
            announce("{} a_shortened_prefix_yields_no_plaintext", mode);
            connected_pair_t pair;
            failures += pair.connect(mode);
            failures += seal_into(pair.client, byte_span("prefix authenticated"), wire);
            span<byte_t> const bytes = wire.whole();
            bytes[1] = byte_t {static_cast<unsigned char>(std::to_integer<unsigned>(bytes[1]) - 1)};
            failures += expect(pair.server.bytes_until_boundary(wire.received()) == 0u);
            failures += expect(open_from(pair.server, wire).consumed == 0u);
            failures += expect(pair.server.fault() == secure_tunnel_fault_t::authentication_failed_k);
        }
        {
            announce("{} a_sixteen_byte_record_is_refused", mode);
            connected_pair_t pair;
            failures += pair.connect(mode);
            span<byte_t> const bytes = wire.whole();
            std::memset(bytes.data(), 0, 2 + 16);
            bytes[1] = byte_t {16};
            wire.length = 2 + 16;
            failures += expect(open_from(pair.server, wire).consumed == 0u);
            failures += expect(pair.server.fault() == secure_tunnel_fault_t::malformed_k);
        }
        {
            announce("{} a_payload_wider_than_the_cap_is_refused", mode);
            connected_pair_t pair;
            failures += pair.connect(mode, 64);
            failures += expect(pair.client.payload_window(wire.whole()).size() == 64u);
            failures += expect(pair.client.seal(wire.whole(), 65).size() == 0u);
            failures += expect(pair.client.fault() == secure_tunnel_fault_t::malformed_k);
            failures += expect(pair.client.state() == secure_tunnel_state_t::broken_k);
        }
        {
            announce("{} empty_records_do_not_impose_a_connection_quota", mode);
            connected_pair_t pair;
            failures += pair.connect(mode);
            for (std::size_t index = 0; index != 64; ++index) {
                failures += seal_into(pair.client, {}, wire);
                failures += expect(open_from(pair.server, wire).consumed > 0u);
            }
            failures += seal_into(pair.client, byte_span("still open"), wire);
            failures += expect(open_from(pair.server, wire).consumed > 0u);
        }
        {
            // Re-delivering a record the peer already opened is what a retrying proxy does. The
            // receiving nonce has advanced, so the tag no longer matches.
            announce("{} a_replayed_record_is_refused", mode);
            connected_pair_t pair;
            failures += pair.connect(mode);
            failures += seal_into(pair.client, byte_span("once"), wire);

            // Kept before opening, because `open` uncovers the plaintext over the ciphertext.
            replayed.length = wire.length;
            std::memcpy(replayed.whole().data(), wire.received().data(), wire.received().size_bytes());
            failures += expect(open_from(pair.server, wire).consumed > 0u);

            failures += expect(open_from(pair.server, replayed).consumed == 0u, "a replayed record was accepted");
            failures += expect(pair.server.fault() == secure_tunnel_fault_t::authentication_failed_k);
        }
        {
            // Two sessions between the same two identities. Only the ephemerals separate them, so
            // this is the case that proves they are doing that work.
            announce("{} a_record_from_another_session_is_refused", mode);
            keypair_t client_identity, server_identity;
            failures += expect(client_identity.draw());
            failures += expect(server_identity.draw());

            connected_pair_t earlier, later;
            failures += earlier.connect_with(mode, client_identity, server_identity);
            failures += later.connect_with(mode, client_identity, server_identity);

            failures += seal_into(earlier.client, byte_span("session one"), wire);
            failures += expect(open_from(later.server, wire).consumed == 0u, "a record crossed between sessions");
            failures += expect(later.server.fault() == secure_tunnel_fault_t::authentication_failed_k);
        }
    }
    return failures;
}

case_result_t test_records_delivery(random_generator_t& generator) {
    std::size_t failures = 0;
    wire_t wire, second_wire;
    require(failures, wire.reserve());
    require(failures, second_wire.reserve());

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{}", mode);

        connected_pair_t pair;
        failures += pair.connect(mode);

        // Until the length prefix has landed there is nothing to read a length from, so the
        // answer is the rest of the prefix - a progress guarantee rather than the record's width.
        failures += seal_into(pair.client, byte_span("boundary"), wire);
        std::size_t const stride = sweep_stride(wire.length);
        for (std::size_t prefix = 0; prefix < wire.length; prefix += stride) {
            std::size_t const expected = prefix < secure_tunnel_headroom_k ? secure_tunnel_headroom_k - prefix
                                                                           : wire.length - prefix;
            std::size_t const answered = pair.server.bytes_until_boundary(wire.whole().first(prefix));
            failures += expect(answered == expected, "{} at prefix {} of {} the boundary answered {}, expected {}",
                               mode, prefix, wire.length, answered, expected);
        }
        failures += expect(pair.server.bytes_until_boundary(wire.received()) == 0u);
        failures += expect(pair.server.bytes_until_boundary({}) == secure_tunnel_headroom_k);

        // Sealing advanced the sender's nonce, so leaving the swept record unopened would part
        // the two ends' schedules and read as a tunnel defect rather than a skipped step.
        secure_tunnel_opened_t const swept = open_from(pair.server, wire);
        failures += expect(swept.consumed > 0u, "the record the boundary sweep walked would not open");
        failures += expect_bytes(swept.payload, byte_span("boundary"));

        failures += seal_into(pair.client, byte_span("first"), wire);
        failures += seal_into(pair.client, byte_span("second"), second_wire);
        std::memcpy(wire.whole().subspan(wire.length).data(), second_wire.received().data(),
                    second_wire.received().size_bytes());
        wire.length += second_wire.length;

        failures += expect(pair.server.bytes_until_boundary(wire.received()) == 0u);
        secure_tunnel_opened_t const one = open_from(pair.server, wire);
        failures += expect(one.consumed > 0u);
        failures += expect(one.consumed < wire.length);
        failures += expect_bytes(one.payload, byte_span("first"));

        std::memmove(wire.whole().data(), wire.received().subspan(one.consumed).data(), wire.length - one.consumed);
        wire.length -= one.consumed;
        failures += expect(pair.server.bytes_until_boundary(wire.received()) == 0u);
        secure_tunnel_opened_t const two = open_from(pair.server, wire);
        failures += expect(two.consumed > 0u);
        failures += expect_bytes(two.payload, byte_span("second"));

        // A stream of records arriving in chunks a driver never chose, reassembled the way a
        // driver has to: read, ask the boundary rule, open only when it answers zero.
        std::size_t const records = scale_iterations(8);
        announce("{} reassembled_from_{}_records_in_random_chunks", mode, records);

        wire_t sent;
        require(failures, sent.reserve());
        std::size_t produced = 0;
        for (std::size_t index = 0; index != records; ++index) {
            failures += seal_into(pair.client, byte_span("chunked payload"), second_wire);
            require(failures, produced + second_wire.length <= sent.storage.capacity(),
                    "the stream outgrew its buffer");
            std::memcpy(sent.whole().subspan(produced).data(), second_wire.received().data(),
                        second_wire.received().size_bytes());
            produced += second_wire.length;
        }

        wire_t inbox;
        require(failures, inbox.reserve());
        std::size_t offered = 0, opened_count = 0;
        while (opened_count != records) {
            std::size_t const wanted = pair.server.bytes_until_boundary(inbox.received());
            require(failures, wanted > 0u || inbox.length > 0u, "the boundary rule stopped asking for bytes");
            if (wanted) {
                // A chunk no larger than what is still owed, and never zero, so this terminates.
                std::size_t const remaining = produced - offered;
                require(failures, remaining > 0u, "the boundary asked for {} more bytes than were ever sent", wanted);
                std::size_t const chunk = 1 + generator.below(remaining < wanted ? remaining : wanted);
                std::memcpy(inbox.whole().subspan(inbox.length).data(), sent.whole().subspan(offered).data(), chunk);
                inbox.length += chunk;
                offered += chunk;
                continue;
            }
            secure_tunnel_opened_t const next = open_from(pair.server, inbox);
            require(failures, next.consumed > 0u, "record {} of {} failed with {}", opened_count, records,
                    pair.server.fault());
            failures += expect_bytes(next.payload, byte_span("chunked payload"));
            std::memmove(inbox.whole().data(), inbox.received().subspan(next.consumed).data(),
                         inbox.length - next.consumed);
            inbox.length -= next.consumed;
            ++opened_count;
        }
        failures += expect(offered == produced, "{} of {} stream bytes were never delivered", offered, produced);
    }
    return failures;
}

#pragma endregion Records

#pragma region Closing

case_result_t test_close_unit() {
    std::size_t failures = 0;
    wire_t wire;
    require(failures, wire.reserve());

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        {
            announce("{} a_close_shuts_one_direction", mode);
            connected_pair_t pair;
            failures += pair.connect(mode);
            failures += seal_into(pair.client, byte_span("before"), wire);
            failures += expect(open_from(pair.server, wire).consumed > 0u);

            secure_tunnel_step_t const closing = pair.client.advance({}, secure_tunnel_request_t::close_k);
            failures += expect(closing.state == secure_tunnel_state_t::transmitting_k);
            failures += expect(closing.outbound.size() > 0u);
            failures += expect(!pair.client.may_seal());
            failures += expect(pair.client.may_open());

            std::memcpy(wire.whole().data(), closing.outbound.data(), closing.outbound.size_bytes());
            wire.length = closing.outbound.size();
            secure_tunnel_opened_t const received = open_from(pair.server, wire);
            failures += expect(received.consumed > 0u);
            failures += expect(received.kind == secure_tunnel_record_t::close_k);
            failures += expect(received.payload.size() == 0u);
            failures += expect(!pair.server.may_open());
            failures += expect(pair.server.may_seal());

            // The close goes through the sealing path, so it advances both counts or the rekey
            // schedules diverge with no diagnosable symptom.
            failures += expect(pair.client.records_sealed() == 2u);
            failures += expect(pair.server.records_opened() == 2u);

            failures += seal_into(pair.server, byte_span("last words"), wire);
            failures += expect(open_from(pair.client, wire).consumed > 0u);

            // Nothing legitimate follows an authenticated close, so this is a protocol violation.
            std::memset(wire.whole().data(), 0, 64);
            wire.length = 64;
            failures += expect(open_from(pair.server, wire).consumed == 0u);
            failures += expect(pair.server.fault() == secure_tunnel_fault_t::malformed_k);
        }
        {
            announce("{} both_directions_shut_reports_closed", mode);
            connected_pair_t pair;
            failures += pair.connect(mode);

            secure_tunnel_step_t const server_closing = pair.server.advance({}, secure_tunnel_request_t::close_k);
            std::memcpy(wire.whole().data(), server_closing.outbound.data(), server_closing.outbound.size_bytes());
            wire.length = server_closing.outbound.size();
            failures += expect(open_from(pair.client, wire).consumed > 0u);
            failures += expect(!pair.client.may_open());

            secure_tunnel_step_t const client_closing = pair.client.advance({}, secure_tunnel_request_t::close_k);
            failures += expect(client_closing.state == secure_tunnel_state_t::closed_k);
            failures += expect(client_closing.outbound.size() > 0u); // the close still has to reach the peer

            secure_tunnel_step_t const again = pair.client.advance({});
            failures += expect(again.state == secure_tunnel_state_t::closed_k);
            failures += expect(again.outbound.size() == 0u);
        }
    }
    return failures;
}

/** A close coalesced into one read behind the peer's last data record. */
case_result_t test_close_delivery() {
    std::size_t failures = 0;
    wire_t wire, tail;
    require(failures, wire.reserve());
    require(failures, tail.reserve());

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{} a_close_behind_data_in_one_read", mode);

        connected_pair_t pair;
        failures += pair.connect(mode);
        failures += seal_into(pair.client, byte_span("last request"), wire);

        secure_tunnel_step_t const closing = pair.client.advance({}, secure_tunnel_request_t::close_k);
        failures += expect(closing.outbound.size() > 0u);
        std::memcpy(wire.whole().subspan(wire.length).data(), closing.outbound.data(), closing.outbound.size_bytes());
        wire.length += closing.outbound.size();

        // The data record has to come out first, with the close still untouched behind it.
        failures += expect(pair.server.bytes_until_boundary(wire.received()) == 0u);
        secure_tunnel_opened_t const data = open_from(pair.server, wire);
        failures += expect(data.consumed > 0u);
        failures += expect(data.kind == secure_tunnel_record_t::application_k);
        failures += expect_bytes(data.payload, byte_span("last request"));
        failures += expect(pair.server.may_open(), "the close took effect before its record was opened");

        std::memmove(wire.whole().data(), wire.received().subspan(data.consumed).data(), wire.length - data.consumed);
        wire.length -= data.consumed;
        secure_tunnel_opened_t const shut = open_from(pair.server, wire);
        failures += expect(shut.consumed > 0u);
        failures += expect(shut.kind == secure_tunnel_record_t::close_k);
        failures += expect(!pair.server.may_open());
        failures += expect(pair.server.may_seal(), "a received close shut the reply direction too");
    }
    return failures;
}

#pragma endregion Closing

#pragma region Lifecycle

/**
 *  @brief A pooled tunnel serving a second connection.
 *
 *  `make` calls `reset`, so re-using a `secure_tunnel_t` is the normal server shape. What a second
 *  session must not inherit is the first one's nonces, counters, or direction flags.
 */
case_result_t test_reuse_unit() {
    std::size_t failures = 0;
    wire_t wire;
    require(failures, wire.reserve());

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{}", mode);

        connected_pair_t pair;
        failures += pair.connect(mode);
        for (std::size_t index = 0; index != 4; ++index) {
            failures += seal_into(pair.client, byte_span("first session"), wire);
            failures += expect(open_from(pair.server, wire).consumed > 0u);
        }
        [[maybe_unused]] secure_tunnel_step_t const closing = pair.client.advance({}, secure_tunnel_request_t::close_k);
        failures += expect(!pair.client.may_seal());
        failures += expect(pair.client.records_sealed() > 0u);

        // A fresh `make` on the same objects, exactly as a connection pool would.
        failures += expect(
            pair.attempt(mode, 0, connected_pair_t::keys_t::supplied_k) == handshake_outcome_t::settled_k,
            "a reused tunnel could not handshake again");

        failures += expect(pair.client.records_sealed() == 0u, "a reused tunnel kept {} sealed records",
                           pair.client.records_sealed());
        failures += expect(pair.server.records_opened() == 0u, "a reused tunnel kept {} opened records",
                           pair.server.records_opened());
        failures += expect(pair.client.may_seal(), "a reused tunnel inherited a shut sending direction");
        failures += expect(pair.client.may_open());
        failures += expect(pair.client.fault() == secure_tunnel_fault_t::none_k);

        // The nonces reset with everything else, so the second session's first record opens.
        failures += seal_into(pair.client, byte_span("second session"), wire);
        secure_tunnel_opened_t const opened = open_from(pair.server, wire);
        failures += expect(opened.consumed > 0u, "a reused tunnel's first record failed with {}", pair.server.fault());
        failures += expect_bytes(opened.payload, byte_span("second session"));
    }
    return failures;
}

#pragma endregion Lifecycle

#pragma region Sweeps

/**
 *  @brief Every pattern against every payload width, exchanged both ways under a rekey schedule.
 *
 *  The named cases above each pin one property at one width. This is the cross-product, so a width
 *  that only misbehaves under a particular pattern has somewhere to show up.
 */
case_result_t test_tunnel_stress(random_generator_t& generator) {
    std::size_t failures = 0;
    wire_t wire;
    require(failures, wire.reserve());
    st::vector<byte_t> payload;
    require(failures, !st::failed(payload.resize(secure_tunnel_payload_ceiling_k)));

    std::size_t const exchanges = scale_iterations(16);

    for (secure_tunnel_mode_t const mode : tunnel_modes_k)
        for (payload_width_t const width : payload_widths_k) {
            std::size_t const rounds = exchanges;
            announce("{} {} x{}", mode, width, rounds);

            std::size_t const filled = static_cast<std::size_t>(width);
            connected_pair_t pair;
            failures += pair.connect(mode, secure_tunnel_payload_ceiling_k);

            for (std::size_t exchange = 0; exchange != rounds; ++exchange) {
                byte_t const marker = static_cast<byte_t>(generator());
                span<byte_t> const scratch {payload.data(), payload.data() + filled};
                fill_with(scratch, marker);
                span<byte_t const> const sent = scratch;

                failures += seal_into(pair.client, sent, wire);
                failures += expect(pair.server.bytes_until_boundary(wire.received()) == 0u);
                secure_tunnel_opened_t const request = open_from(pair.server, wire);
                failures += expect(request.consumed > 0u, "{} {} exchange {} was refused with {}", mode, width,
                                   exchange, pair.server.fault());
                failures += expect(request.payload.size() == filled, "opened {} bytes, sealed {}",
                                   request.payload.size(), filled);
                failures += expect(request.payload.data() == wire.whole().subspan(secure_tunnel_headroom_k).data());
                failures += expect(all_equal_to(request.payload, marker));

                failures += seal_into(pair.server, sent, wire);
                secure_tunnel_opened_t const reply = open_from(pair.client, wire);
                failures += expect(reply.consumed > 0u);
                failures += expect(reply.payload.size() == filled);
                failures += expect(all_equal_to(reply.payload, marker));
            }

            failures += expect(pair.client.records_sealed() == pair.server.records_opened());
            failures += expect(pair.server.records_sealed() == pair.client.records_opened());
        }
    return failures;
}

#pragma endregion Sweeps

int main(int, char** argv) {
    install_test_signal_handlers();
    fmt::print("Hi, dear tester! You look nice today!\n");
    configure_tests();

    suite_totals_t totals {.program = argv[0]};
    run_test(totals, "test_hmac_unit", test_hmac_unit);
    run_test(totals, "test_hkdf_unit", test_hkdf_unit);
    run_test(totals, "test_transcript_unit", test_transcript_unit);
    run_test(totals, "test_entropy_unit", test_entropy_unit);

    run_test(totals, "test_config_unit", test_config_unit);
    run_test(totals, "test_config_safety", test_config_safety);
    run_test(totals, "test_geometry_safety", test_geometry_safety);

    run_test(totals, "test_handshake_unit", test_handshake_unit);
    run_test(totals, "test_handshake_safety", test_handshake_safety);

    run_test(totals, "test_handshake_delivery", test_handshake_delivery);

    run_test(totals, "test_records_unit", test_records_unit);
    run_test(totals, "test_records_safety", test_records_safety);
    run_test(totals, "test_records_delivery", test_records_delivery);

    run_test(totals, "test_close_unit", test_close_unit);
    run_test(totals, "test_close_delivery", test_close_delivery);

    run_test(totals, "test_reuse_unit", test_reuse_unit);
    run_test(totals, "test_tunnel_stress", test_tunnel_stress);
    return suite_exit_code(totals);
}
