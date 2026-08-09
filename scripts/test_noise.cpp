/**
 *  @brief Tests for `secure_tunnel.cpp` - the keyed-hash layer, the handshake, and the record layer.
 *  @file scripts/test_noise.cpp
 *  @author Ash Vardanian
 *
 *  @section Why This Includes a `.cpp`
 *
 *  Everything below the tunnel's public surface has internal linkage: the primitives live in an
 *  anonymous namespace so that no translation unit which merely @b drives a tunnel can depend on
 *  the layout of a key schedule. That is the property being relied on, and the cost of it is that
 *  a test reaches them by compiling the file rather than linking it. The target must therefore
 *  @b not also list `src/secure_tunnel.cpp`.
 *
 *  @section What Is Pinned Here
 *
 *  The RFC 4231 and RFC 5869 vectors are the only thing standing between us and a tag that looks
 *  well-formed and interoperates with nobody. They are also the named reproducer for the
 *  `-fno-strict-aliasing` flag in `CMakeLists.txt`, so they are carried byte for byte.
 *
 *  Above them, every record-layer and closing case runs against all three handshake patterns.
 *  The record layer is pattern-independent by construction, and running it against one pattern
 *  would be assuming that rather than checking it - `KK` in particular transmits no static key at
 *  all, so its peer is proven at the split rather than by anything it sent.
 */
#include <cstring> // `std::memcpy`, `std::memmove`, `std::memset`, `std::strlen`

#include "test.hpp" // `verify`, `run_test`, `scale_iterations`

#include "secure_tunnel.cpp" // the implementation, compiled into this test

using namespace unum::ucall;
using namespace unum::ucall::scripts;

#pragma region Fixtures

/** @brief Why a handshake stopped, which one @c bool cannot distinguish. */
enum class handshake_outcome_t : std::uint8_t {
    /** @brief Both ends reached @c ready_k. */
    settled_k,
    /** @brief One end reported a fault and stopped. */
    broken_k,
    /** @brief Neither end faulted, and neither reached @c ready_k within the pattern's messages. */
    stalled_k,
    /** @brief A key could not be drawn, or @c make refused the configuration. */
    misconfigured_k,
};

/** @brief Lets `{}` name an outcome, so a failed handshake reads as a sentence. */
[[nodiscard]] inline auto format_as(handshake_outcome_t outcome) noexcept {
    switch (outcome) {
    case handshake_outcome_t::settled_k: return "settled";
    case handshake_outcome_t::broken_k: return "broken";
    case handshake_outcome_t::stalled_k: return "stalled";
    case handshake_outcome_t::misconfigured_k: return "misconfigured";
    }
    return "unknown";
}

/** @brief Every pattern, in table form, so a sweep is a loop and not a copy-paste. */
static constexpr secure_tunnel_mode_t tunnel_modes_k[] = {
    secure_tunnel_mode_t::noise_xx_k, secure_tunnel_mode_t::noise_ik_k, secure_tunnel_mode_t::noise_kk_k};

/** @brief Payload widths worth distinguishing, spelled out - never a raw count at a call site. */
enum class payload_width_t : std::uint32_t {
    empty_k = 0,
    single_byte_k = 1,
    typical_request_k = 512,
    one_page_k = ram_page_size_k,
    ceiling_k = secure_tunnel_payload_ceiling_k,
};

static constexpr payload_width_t payload_widths_k[] = {payload_width_t::empty_k, payload_width_t::single_byte_k,
                                                       payload_width_t::typical_request_k, payload_width_t::one_page_k,
                                                       payload_width_t::ceiling_k};

/** @brief Lets `{}` name a payload width rather than print its byte count twice. */
[[nodiscard]] inline auto format_as(payload_width_t width) noexcept {
    switch (width) {
    case payload_width_t::empty_k: return "empty";
    case payload_width_t::single_byte_k: return "single_byte";
    case payload_width_t::typical_request_k: return "typical_request";
    case payload_width_t::one_page_k: return "one_page";
    case payload_width_t::ceiling_k: return "ceiling";
    }
    return "unknown";
}

/** @brief One driver's record buffer: reserved once, written in place, never copied out of. */
struct wire_t {
    array<byte_t> storage {};
    std::size_t length {};

    /** @brief Room for the widest record the wire format can name. */
    [[nodiscard]] bool reserve() noexcept { return storage.reserve(secure_tunnel_max_record_k); }

    /** @brief Room for exactly @p capacity bytes, as a driver sizing from @c record_size would. */
    [[nodiscard]] bool reserve(std::size_t capacity) noexcept { return storage.reserve(capacity); }
    [[nodiscard]] span<byte_t> whole() noexcept { return {storage.data(), storage.data() + storage.capacity()}; }
    [[nodiscard]] span<byte_t> arrived() noexcept { return {storage.data(), storage.data() + length}; }
    [[nodiscard]] span<byte_t const> received() const noexcept { return {storage.data(), storage.data() + length}; }
    [[nodiscard]] byte_t *bytes() noexcept { return storage.data(); }
    [[nodiscard]] byte_t const *bytes() const noexcept { return storage.data(); }
};

/** @brief A Curve25519 keypair, drawn through the same call a bind or a client handle uses. */
struct keypair_t {
    byte_t secret[secure_tunnel_key_size_k] {};
    byte_t shared[secure_tunnel_key_size_k] {};

    [[nodiscard]] bool draw() noexcept { return secure_tunnel_generate_keypair(secret, shared); }
    [[nodiscard]] span<byte_t const> private_half() const noexcept { return secret; }
    [[nodiscard]] span<byte_t const> public_half() const noexcept { return shared; }
};

/** @brief One direction of the in-memory wire between two handshaking ends. */
struct handshake_stream_t {
    /** @brief Fixed storage: at most two messages are ever in flight at once. */
    byte_t bytes[outbound_capacity_k * 4] {};
    std::size_t length {};

    void append(span<byte_t const> more) noexcept {
        verify(length + more.size() <= sizeof(bytes));
        if (more.size()) std::memcpy(bytes + length, more.data(), more.size());
        length += more.size();
    }
    void consume(std::size_t count) noexcept {
        verify(count <= length);
        if (count && count != length) std::memmove(bytes, bytes + count, length - count);
        length -= count;
    }
    /** @brief What the peer sent and this end has not yet consumed. */
    [[nodiscard]] span<byte_t const> pending() const noexcept { return {bytes, bytes + length}; }
};

/**
 *  @brief Drives both ends of a handshake to completion over an in-memory wire.
 *
 *  @c advance promises neither side loops, so each end is driven exactly once per round. Needing
 *  more rounds than the pattern has messages would break that promise, which is why running out
 *  is reported apart from either side breaking.
 */
[[nodiscard]] static handshake_outcome_t complete_handshake(secure_tunnel_t &initiator,
                                                            secure_tunnel_t &responder) noexcept {
    handshake_stream_t toward_responder, toward_initiator;

    auto pump = [](secure_tunnel_t &tunnel, handshake_stream_t &inbound,
                   handshake_stream_t &outbound) noexcept -> secure_tunnel_state_t {
        secure_tunnel_step_t const step = tunnel.advance(inbound.pending());
        inbound.consume(step.consumed);
        outbound.append(step.outbound);
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

/** @brief A connected pair in the given pattern, with fresh static keys on both sides. */
struct connected_pair_t {
    keypair_t client_keys, server_keys;
    secure_tunnel_t client, server;

    /** @brief Completes a handshake in @p mode, naming the pattern and the failure if one comes. */
    void connect(secure_tunnel_mode_t mode, std::size_t max_payload = 0) {
        handshake_outcome_t const outcome = attempt(mode, max_payload);
        verify(outcome == handshake_outcome_t::settled_k, "{} handshake {}", mode, outcome);
    }

    /** @brief Whether @c attempt draws fresh static keys or uses the ones already in place. */
    enum class keys_t : bool { fresh_k, supplied_k };

    /** @brief Reconnects on keys the caller already holds, for the cases about identity reuse. */
    void connect_with(secure_tunnel_mode_t mode, keypair_t const &client_identity, keypair_t const &server_identity) {
        client_keys = client_identity;
        server_keys = server_identity;
        handshake_outcome_t const outcome = attempt(mode, 0, keys_t::supplied_k);
        verify(outcome == handshake_outcome_t::settled_k, "{} handshake {}", mode, outcome);
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
            client_config.remote_public = server_keys.public_half();

        secure_tunnel_config_t server_config;
        server_config.mode = mode;
        server_config.role = secure_tunnel_role_t::responder_k;
        server_config.local_private = server_keys.private_half();
        server_config.local_public = server_keys.public_half();
        server_config.max_payload = max_payload;
        // Only `KK` pre-shares the initiator's key with the responder.
        if (mode == secure_tunnel_mode_t::noise_kk_k) server_config.remote_public = client_keys.public_half();

        if (client.make(client_config) != secure_tunnel_fault_t::none_k) return handshake_outcome_t::misconfigured_k;
        if (server.make(server_config) != secure_tunnel_fault_t::none_k) return handshake_outcome_t::misconfigured_k;
        return complete_handshake(client, server);
    }
};

/** @brief Seals one payload into @p wire, in place, as a driver would. Aborts if the tunnel refuses. */
static void seal_into(secure_tunnel_t &tunnel, span<byte_t const> payload, wire_t &wire) {
    span<byte_t> const window = tunnel.payload_window(wire.whole());
    verify(window.size() >= payload.size(), "a {}-byte window cannot hold {} bytes", window.size(), payload.size());
    if (payload.size()) std::memcpy(window.data(), payload.data(), payload.size());
    wire.length = tunnel.seal(wire.whole(), payload.size()).size();
    verify(wire.length > 0u, "the tunnel refused a {}-byte payload with {}", payload.size(), tunnel.fault());
}

/** @brief Opens one whole record from a wire buffer, in place, exactly as a driver would. */
[[nodiscard]] static secure_tunnel_opened_t open_from(secure_tunnel_t &tunnel, wire_t &wire) noexcept {
    return tunnel.open(wire.arrived());
}

/** @brief The big-endian length a record declares in its prefix. */
[[nodiscard]] static std::size_t declared_length(wire_t &wire) noexcept {
    return (static_cast<std::size_t>(wire.bytes()[0]) << 8) | static_cast<std::size_t>(wire.bytes()[1]);
}

/**
 *  @brief Builds a run of one repeated byte in scratch storage and views it.
 *
 *  Safe to alias its own argument only because the storage is scratch the caller never reads
 *  back; a sweep that re-reads its buffer keeps the fill and the view apart.
 */
[[nodiscard]] static span<byte_t const> run_of(span<byte_t> bytes, byte_t value) noexcept {
    fill_with(bytes, value);
    return bytes;
}

/** @brief Computes one tag into @p digest and returns a view of it. */
[[nodiscard]] static span<byte_t const> hmac_of(span<byte_t const> key, span<byte_t const> data,
                                                byte_t digest[hash_size_k]) noexcept {
    hmac_sha256(key, data, digest);
    return {digest, digest + hash_size_k};
}

#pragma endregion Fixtures

#pragma region Primitives

void test_hmac_unit() {
    byte_t key_storage[131];
    byte_t data_storage[50];
    byte_t digest[hash_size_k];

    // RFC 4231 §4.2-§4.7, byte for byte: the named reproducer for `-fno-strict-aliasing`, so a
    // digest that drifts here is a miscompile rather than a redesign.
    announce("rfc4231_case1");
    verify_hex(hmac_of(run_of({key_storage, key_storage + 20}, 0x0b), ascii_bytes("Hi There"), digest),
               "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    announce("rfc4231_case2");
    verify_hex(hmac_of(ascii_bytes("Jefe"), ascii_bytes("what do ya want for nothing?"), digest),
               "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    announce("rfc4231_case3");
    verify_hex(
        hmac_of(run_of({key_storage, key_storage + 20}, 0xaa), run_of({data_storage, data_storage + 50}, 0xdd), digest),
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    announce("rfc4231_case6_key_longer_than_block");
    verify_hex(hmac_of(run_of({key_storage, key_storage + 131}, 0xaa),
                       ascii_bytes("Test Using Larger Than Block-Size Key - Hash Key First"), digest),
               "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

    announce("cached_state_matches_one_shot");
    span<byte_t const> const cached_key = run_of({key_storage, key_storage + 40}, 0x5a);
    hmac_sha256_t cached;
    cached.reset(cached_key);
    for (char const *message : {"", "a", "the quick brown fox", "0123456789012345678901234567890123456789"}) {
        span<byte_t const> const data = ascii_bytes(message, std::strlen(message));
        byte_t reused[hash_size_k], fresh[hash_size_k];
        cached.compute(data, {}, reused);
        hmac_sha256(cached_key, data, fresh);
        verify_bytes(reused, fresh);
    }

    announce("split_input_matches_concatenated");
    byte_t joined[17];
    std::memcpy(joined, "chaining-material", 17);
    hmac_sha256_t split_hmac;
    split_hmac.reset(run_of({key_storage, key_storage + 32}, 0x0b));
    byte_t split[hash_size_k];
    split_hmac.compute(ascii_bytes("chaining"), ascii_bytes("-material"), split);
    verify_bytes(split, hmac_of(run_of({key_storage, key_storage + 32}, 0x0b), joined, digest));
}

void test_hkdf_unit() {
    byte_t digest[hash_size_k];
    byte_t material_storage[22];
    span<byte_t const> const material = run_of({material_storage, material_storage + 22}, 0x0b);

    // Noise's HKDF is RFC 5869 with an empty info string, so the published key applies unchanged.
    announce("rfc5869_case1_extract");
    byte_t const salt_storage[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    verify_hex(hmac_of(salt_storage, material, digest),
               "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");

    // With an empty info string, RFC 5869's T(1) reduces to HMAC(PRK, 0x01).
    announce("first_output_is_expand_of_extract");
    byte_t chaining_key[hash_size_k];
    for (std::size_t index = 0; index != hash_size_k; ++index) chaining_key[index] = static_cast<byte_t>(index);

    byte_t outputs[3][hash_size_k];
    hkdf_sha256(chaining_key, material, 2, outputs);

    byte_t pseudo_random_key[hash_size_k];
    hmac_sha256(chaining_key, material, pseudo_random_key);
    byte_t const one = 0x01;
    byte_t expected[hash_size_k];
    hmac_sha256(pseudo_random_key, {&one, &one + 1}, expected);
    verify_bytes(outputs[0], expected);

    announce("second_output_chains_from_the_first");
    byte_t empty_chaining_key[hash_size_k] {};
    byte_t chained[3][hash_size_k];
    hkdf_sha256(empty_chaining_key, {}, 2, chained);

    hmac_sha256(empty_chaining_key, {}, pseudo_random_key);
    byte_t const two = 0x02;
    hmac_sha256_t chaining_hmac;
    chaining_hmac.reset(pseudo_random_key);
    chaining_hmac.compute(chained[0], {&two, &two + 1}, expected);
    verify_bytes(chained[1], expected);
    verify(!bytes_equal(chained[0], chained[1]));

    announce("third_output_only_derived_when_asked");
    byte_t two_outputs[3][hash_size_k] {};
    byte_t three_outputs[3][hash_size_k] {};
    hkdf_sha256(empty_chaining_key, {}, 2, two_outputs);
    hkdf_sha256(empty_chaining_key, {}, 3, three_outputs);
    verify_bytes(two_outputs[0], three_outputs[0]);
    verify_bytes(two_outputs[1], three_outputs[1]);
    verify(all_zero(two_outputs[2]));
    verify(!all_zero(three_outputs[2]));
}

void test_transcript_unit() {
    char const *const name = "Noise_XX_25519_AESGCM_SHA256";
    std::size_t const name_length = std::strlen(name);

    announce("a_short_protocol_name_is_zero_padded");
    verify(name_length <= hash_size_k);
    secure_tunnel_transcript_t padded;
    padded.initialize(name, name_length);
    byte_t expected[hash_size_k] {};
    std::memcpy(expected, name, name_length);
    verify_bytes(padded.hash(), expected);

    announce("a_long_protocol_name_is_hashed");
    char long_name[40];
    for (char &character : long_name) character = 'x';
    secure_tunnel_transcript_t hashed;
    hashed.initialize(long_name, sizeof(long_name));

    sz_sha256_state_t digest_state;
    sz_sha256_state_init(&digest_state);
    sz_sha256_state_update(&digest_state, long_name, sizeof(long_name));
    byte_t hashed_expected[hash_size_k];
    sz_sha256_state_digest(&digest_state, hashed_expected);
    verify_bytes(hashed.hash(), hashed_expected);

    announce("mixing_is_order_sensitive");
    secure_tunnel_transcript_t forward, backward;
    forward.initialize(name, name_length);
    backward.initialize(name, name_length);
    byte_t const first[4] = {1, 2, 3, 4};
    byte_t const second[4] = {5, 6, 7, 8};
    forward.mix_hash(first);
    forward.mix_hash(second);
    backward.mix_hash(second);
    backward.mix_hash(first);
    // A transcript that ignored ordering would let a peer reorder the handshake.
    verify(!bytes_equal(forward.hash(), backward.hash()));

    announce("an_empty_prologue_still_advances_the_transcript");
    secure_tunnel_transcript_t prologued;
    prologued.initialize(name, name_length);
    byte_t before[hash_size_k];
    std::memcpy(before, prologued.hash().data(), hash_size_k);
    prologued.mix_hash({});
    verify(!bytes_equal(prologued.hash(), before));
}

void test_entropy_unit() {
    // Not a statistical test - proof the platform call is wired, since zeros here would silently
    // destroy every ephemeral key.
    announce("distinct_and_never_all_zero");
    byte_t first[32] {}, second[32] {};
    verify(secure_random_bytes(first, sizeof(first)));
    verify(secure_random_bytes(second, sizeof(second)));
    verify(!all_zero(first));
    verify(!bytes_equal(first, second));
}

#pragma endregion Primitives

#pragma region Configuration

void test_config_unit() {
    announce("plaintext_is_born_ready_and_frames_nothing");
    secure_tunnel_t plain;
    verify(plain.state() == secure_tunnel_state_t::ready_k);
    verify(!plain.encrypts());
    verify(plain.may_seal());
    verify(plain.may_open());
    verify(plain.geometry().headroom == 0u);
    verify(plain.geometry().tailroom == 0u);
    verify(plain.bytes_until_boundary({}) == 0u);

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{}", mode);

        connected_pair_t pair;
        pair.connect(mode);
        secure_tunnel_geometry_t const geometry = pair.client.geometry();
        verify(geometry.headroom == secure_tunnel_headroom_k);
        verify(geometry.tailroom == secure_tunnel_tailroom_k);
        verify(geometry.max_payload == secure_tunnel_default_payload_k);
        verify(geometry.record_size() == secure_tunnel_default_payload_k + secure_tunnel_overhead_k);

        connected_pair_t oversized;
        oversized.connect(mode, secure_tunnel_payload_ceiling_k + 4096);
        verify(oversized.client.geometry().max_payload == secure_tunnel_payload_ceiling_k);
    }
}

void test_config_safety() {
    // An absent static key would silently become a scalar of zeros.
    announce("every_pattern_demands_a_local_static_key");
    for (secure_tunnel_mode_t const mode : tunnel_modes_k)
        for (secure_tunnel_role_t const role : {secure_tunnel_role_t::initiator_k, secure_tunnel_role_t::responder_k}) {
            secure_tunnel_t tunnel;
            secure_tunnel_config_t config;
            config.mode = mode;
            config.role = role;
            verify(tunnel.make(config) == secure_tunnel_fault_t::misconfigured_k,
                   "{} {} accepted a configuration with no local static key", mode, role);
        }

    keypair_t keys;
    verify(keys.draw());

    announce("a_key_of_the_wrong_width_is_rejected");
    secure_tunnel_t narrow;
    secure_tunnel_config_t narrow_config;
    narrow_config.mode = secure_tunnel_mode_t::noise_xx_k;
    narrow_config.role = secure_tunnel_role_t::responder_k;
    narrow_config.local_private = {keys.secret, keys.secret + 16}; // half a key
    verify(narrow.make(narrow_config) == secure_tunnel_fault_t::misconfigured_k);

    // An `IK` initiator hashes the responder's static before message one, so it cannot come from
    // the wire - the transcripts would diverge before anything is sent.
    announce("a_pre_shared_key_is_required_where_the_pattern_hashes_it_first");
    secure_tunnel_t unshared;
    secure_tunnel_config_t unshared_config;
    unshared_config.mode = secure_tunnel_mode_t::noise_ik_k;
    unshared_config.role = secure_tunnel_role_t::initiator_k;
    unshared_config.local_private = keys.private_half();
    verify(unshared.make(unshared_config) == secure_tunnel_fault_t::misconfigured_k);
}

/**
 *  @brief What a bind's `max_payload` does and does not bound.
 *
 *  A bind sets it to bound per-connection memory, and `protocol_shared.hpp:289` sizes the
 *  connection's record buffer from `geometry().record_size()`. But `open` bounds an incoming
 *  record by `max_message_k` alone, so a peer that never agreed to the smaller cap can make
 *  `bytes_until_boundary` demand far more than that buffer can ever hold.
 *
 *  Pinned as it behaves today. If ingress is ever bounded too, this is the case that says so.
 */
void test_geometry_safety() {
    wire_t wire;
    verify(wire.reserve());

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{} an_ingress_record_is_not_bounded_by_this_binds_cap", mode);

        keypair_t client_identity, server_identity;
        verify(client_identity.draw());
        verify(server_identity.draw());

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
        if (mode != secure_tunnel_mode_t::noise_xx_k) client_config.remote_public = server_identity.public_half();
        if (mode == secure_tunnel_mode_t::noise_kk_k) server_config.remote_public = client_identity.public_half();
        client_config.max_payload = secure_tunnel_payload_ceiling_k;
        server_config.max_payload = 1024;

        secure_tunnel_t client, server;
        verify(client.make(client_config) == secure_tunnel_fault_t::none_k);
        verify(server.make(server_config) == secure_tunnel_fault_t::none_k);
        verify(complete_handshake(client, server) == handshake_outcome_t::settled_k);

        std::size_t const server_buffer = server.geometry().record_size();
        verify(server_buffer == 1024 + secure_tunnel_overhead_k);

        span<byte_t> const window = client.payload_window(wire.whole());
        verify(window.size() == secure_tunnel_payload_ceiling_k);
        fill_with(window, 'X');
        wire.length = client.seal(wire.whole(), window.size()).size();
        verify(wire.length > server_buffer, "the capped side was not the smaller one");

        // What a driver sees first: two bytes of prefix, and a demand for the rest.
        std::size_t const demanded =
            server.bytes_until_boundary({wire.bytes(), wire.bytes() + secure_tunnel_headroom_k});
        verify(demanded == wire.length - secure_tunnel_headroom_k);
        verify(demanded + secure_tunnel_headroom_k > server_buffer,
               "the boundary asked for {} bytes into a {}-byte buffer", demanded + secure_tunnel_headroom_k,
               server_buffer);

        // And `open` accepts it, because ingress is bounded by `max_message_k` and nothing else.
        secure_tunnel_opened_t const opened = open_from(server, wire);
        verify(opened.consumed == wire.length, "{} refused an over-cap record with {}", mode, server.fault());
        verify(opened.payload.size() == secure_tunnel_payload_ceiling_k);
    }
}

#pragma endregion Configuration

#pragma region Handshake

void test_handshake_unit() {
    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{}", mode);

        connected_pair_t pair;
        pair.connect(mode);
        verify(pair.client.may_seal());
        verify(pair.client.may_open());
        verify(pair.server.may_seal());
        verify(pair.server.may_open());

        // `KK` transmits no static token, so nothing promotes a peer key while reading - only the
        // split does, which is what makes this hold for that pattern.
        byte_t seen_by_client[secure_tunnel_key_size_k];
        byte_t seen_by_server[secure_tunnel_key_size_k];
        verify(pair.client.peer_key(seen_by_client));
        verify(pair.server.peer_key(seen_by_server));
        verify_bytes(seen_by_client, pair.server_keys.public_half());
        verify_bytes(seen_by_server, pair.client_keys.public_half());
    }

    // A configured key is assumed, not proven, and must stay unreported until authenticated.
    announce("a_configured_peer_key_is_not_yet_a_proven_one");
    keypair_t client_keys, server_keys;
    verify(client_keys.draw());
    verify(server_keys.draw());

    secure_tunnel_t unproven;
    secure_tunnel_config_t unproven_config;
    unproven_config.mode = secure_tunnel_mode_t::noise_ik_k;
    unproven_config.role = secure_tunnel_role_t::initiator_k;
    unproven_config.local_private = client_keys.private_half();
    unproven_config.remote_public = server_keys.public_half();
    verify(unproven.make(unproven_config) == secure_tunnel_fault_t::none_k);

    byte_t seen[secure_tunnel_key_size_k];
    verify(!unproven.peer_key(seen));
    verify(unproven.state() == secure_tunnel_state_t::starting_k);

    announce("each_role_parks_where_it_cannot_deadlock");
    keypair_t keys;
    verify(keys.draw());
    secure_tunnel_config_t config;
    config.mode = secure_tunnel_mode_t::noise_xx_k;
    config.local_private = keys.private_half();

    secure_tunnel_t initiator;
    config.role = secure_tunnel_role_t::initiator_k;
    verify(initiator.make(config) == secure_tunnel_fault_t::none_k);
    secure_tunnel_step_t const first = initiator.advance({});
    verify(first.state == secure_tunnel_state_t::transmitting_k); // an initiator writes before reading
    verify(first.outbound.size() > 0u);

    secure_tunnel_t responder;
    config.role = secure_tunnel_role_t::responder_k;
    verify(responder.make(config) == secure_tunnel_fault_t::none_k);
    secure_tunnel_step_t const second = responder.advance({});
    verify(second.state == secure_tunnel_state_t::receiving_k); // a responder has nothing to say first
    verify(second.outbound.size() == 0u);

    // Forward secrecy: an attacker who later takes the static key, or reads this process's
    // memory, must not be able to reconstruct session keys for traffic already sent.
    announce("ephemeral_secrets_are_destroyed_at_the_split");
    secure_tunnel_noise_t noise;
    noise.role = secure_tunnel_role_t::initiator_k;
    std::memset(noise.local_ephemeral_private, 0xAB, sizeof(noise.local_ephemeral_private));
    std::memset(noise.remote_ephemeral, 0xCD, sizeof(noise.remote_ephemeral));
    std::memset(noise.local_static_private, 0xEF, sizeof(noise.local_static_private));
    std::memset(noise.remote_static, 0x22, sizeof(noise.remote_static));
    noise.remote_static_state = remote_static_t::authenticated_k;

    finish_handshake(noise);

    verify(all_zero(noise.local_ephemeral_private));
    verify(all_zero(noise.remote_ephemeral));
    verify(all_zero(noise.local_static_private));
    // The peer's public half survives - it is the answer `peer_key` exists to give.
    verify(all_equal_to(noise.remote_static, 0x22));
    verify(noise.sending.has_key());
    verify(noise.receiving.has_key());
}

void test_handshake_safety() {
    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{}", mode);

        keypair_t client_keys, server_keys;
        verify(client_keys.draw());
        verify(server_keys.draw());

        secure_tunnel_config_t client_config;
        client_config.mode = mode;
        client_config.role = secure_tunnel_role_t::initiator_k;
        client_config.local_private = client_keys.private_half();
        client_config.local_public = client_keys.public_half();
        if (mode != secure_tunnel_mode_t::noise_xx_k) client_config.remote_public = server_keys.public_half();

        secure_tunnel_config_t server_config;
        server_config.mode = mode;
        server_config.role = secure_tunnel_role_t::responder_k;
        server_config.local_private = server_keys.private_half();
        server_config.local_public = server_keys.public_half();
        if (mode == secure_tunnel_mode_t::noise_kk_k) server_config.remote_public = client_keys.public_half();

        // A peer forcing a shared secret it already knows is an attack, not the operating system
        // refusing entropy, and the two must not collapse into one fault.
        secure_tunnel_t initiator, responder;
        verify(initiator.make(client_config) == secure_tunnel_fault_t::none_k);
        verify(responder.make(server_config) == secure_tunnel_fault_t::none_k);

        secure_tunnel_step_t const first = initiator.advance({});
        verify(first.state == secure_tunnel_state_t::transmitting_k);
        handshake_stream_t message;
        message.append(first.outbound);

        // Every pattern's opening message carries one ephemeral in the clear behind the length
        // prefix. All zeros is the canonical small-order point.
        verify(message.length >= secure_tunnel_headroom_k + secure_tunnel_key_size_k);
        std::memset(message.bytes + secure_tunnel_headroom_k, 0, secure_tunnel_key_size_k);

        secure_tunnel_step_t const answer = responder.advance(message.pending());
        verify(answer.state == secure_tunnel_state_t::broken_k);
        verify(responder.fault() == secure_tunnel_fault_t::authentication_failed_k);

        // Too short for the ephemeral is malformed, not hostile; the faults must differ.
        secure_tunnel_t truncated_responder;
        verify(truncated_responder.make(server_config) == secure_tunnel_fault_t::none_k);
        byte_t const truncated[] = {0x00, 0x04, 0xde, 0xad, 0xbe, 0xef};
        secure_tunnel_step_t const refused = truncated_responder.advance(truncated);
        verify(refused.state == secure_tunnel_state_t::broken_k);
        verify(truncated_responder.fault() == secure_tunnel_fault_t::malformed_k);
    }
}

/**
 *  @brief Every handshake message delivered one byte at a time.
 *
 *  `advance` reports what it consumed, so a partial message must leave the bytes in the caller's
 *  hands and emit nothing until a whole one has landed.
 */
void test_handshake_delivery() {
    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{}", mode);

        connected_pair_t pair;
        keypair_t client_identity, server_identity;
        verify(client_identity.draw());
        verify(server_identity.draw());
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
        if (mode != secure_tunnel_mode_t::noise_xx_k) client_config.remote_public = server_identity.public_half();
        if (mode == secure_tunnel_mode_t::noise_kk_k) server_config.remote_public = client_identity.public_half();

        secure_tunnel_t initiator, responder;
        verify(initiator.make(client_config) == secure_tunnel_fault_t::none_k);
        verify(responder.make(server_config) == secure_tunnel_fault_t::none_k);

        handshake_stream_t toward_responder, toward_initiator;
        auto trickle = [](secure_tunnel_t &tunnel, handshake_stream_t &inbound, handshake_stream_t &outbound) {
            // Everything but the last byte must be refused as incomplete.
            for (std::size_t fed = 1; fed < inbound.length; ++fed) {
                secure_tunnel_step_t const partial = tunnel.advance({inbound.bytes, inbound.bytes + fed});
                verify(partial.state != secure_tunnel_state_t::broken_k, "{} bytes of a message broke the peer", fed);
                verify(partial.consumed == 0u, "{} of {} bytes were consumed from a partial message", partial.consumed,
                       inbound.length);
                verify(partial.outbound.size() == 0u, "a partial message produced {} outbound bytes",
                       partial.outbound.size());
            }
            secure_tunnel_step_t const step = tunnel.advance(inbound.pending());
            inbound.consume(step.consumed);
            outbound.append(step.outbound);
            return step.state;
        };

        for (std::size_t round = 0; round != 8; ++round) {
            verify(trickle(initiator, toward_initiator, toward_responder) != secure_tunnel_state_t::broken_k);
            verify(trickle(responder, toward_responder, toward_initiator) != secure_tunnel_state_t::broken_k);
            if (initiator.state() == secure_tunnel_state_t::ready_k &&
                responder.state() == secure_tunnel_state_t::ready_k)
                break;
        }
        verify(initiator.state() == secure_tunnel_state_t::ready_k, "a trickled {} handshake left the initiator {}",
               mode, initiator.state());
        verify(responder.state() == secure_tunnel_state_t::ready_k, "a trickled {} handshake left the responder {}",
               mode, responder.state());
    }
}

#pragma endregion Handshake

#pragma region Records

void test_records_unit() {
    wire_t wire;
    verify(wire.reserve());

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{}", mode);

        connected_pair_t pair;
        pair.connect(mode);

        seal_into(pair.client, ascii_bytes("GET / HTTP/1.1"), wire);
        verify(pair.server.bytes_until_boundary(wire.received()) == 0u);
        secure_tunnel_opened_t const request = open_from(pair.server, wire);
        verify(request.consumed > 0u);
        verify(request.kind == secure_tunnel_record_t::application_k);
        verify(request.payload.data() == wire.bytes() + secure_tunnel_headroom_k);
        verify_bytes(request.payload, ascii_bytes("GET / HTTP/1.1"));

        seal_into(pair.server, ascii_bytes("HTTP/1.1 200 OK"), wire);
        verify(pair.client.bytes_until_boundary(wire.received()) == 0u);
        secure_tunnel_opened_t const reply = open_from(pair.client, wire);
        verify(reply.consumed > 0u);
        verify_bytes(reply.payload, ascii_bytes("HTTP/1.1 200 OK"));

        // One byte less than this minimum decrypts to nothing, after which reading the kind byte
        // would run off the end of the plaintext.
        seal_into(pair.client, {}, wire);
        verify(wire.length == secure_tunnel_headroom_k + secure_tunnel_tailroom_k);
        verify(declared_length(wire) == tag_size_k + kind_size_k);
        secure_tunnel_opened_t const empty = open_from(pair.server, wire);
        verify(empty.consumed > 0u);
        verify(empty.payload.size() == 0u);

        // Diverging counts diverge the rekey schedules, after which every record fails
        // authentication while looking exactly like an attack.
        std::size_t const already_sealed = pair.client.records_sealed();
        std::size_t const already_opened = pair.server.records_opened();
        for (std::size_t index = 0; index != 16; ++index) {
            seal_into(pair.client, ascii_bytes("ping"), wire);
            verify(open_from(pair.server, wire).consumed > 0u);
            seal_into(pair.server, ascii_bytes("pong"), wire);
            verify(open_from(pair.client, wire).consumed > 0u);
        }
        verify(pair.client.records_sealed() == pair.server.records_opened());
        verify(pair.server.records_sealed() == pair.client.records_opened());
        verify(pair.client.records_sealed() == already_sealed + 16);
        verify(pair.server.records_opened() == already_opened + 16);
    }

    // A ceiling that ignored the kind byte would declare 65536, mask to zero, and be rejected.
    announce("a_maximum_size_payload_fits_the_wire_format");
    array<byte_t> payload;
    verify(payload.reserve(secure_tunnel_payload_ceiling_k));
    span<byte_t> const widest_scratch {payload.data(), payload.data() + secure_tunnel_payload_ceiling_k};
    fill_with(widest_scratch, 'M');
    span<byte_t const> const widest = widest_scratch;

    connected_pair_t widest_pair;
    widest_pair.connect(secure_tunnel_mode_t::noise_xx_k, secure_tunnel_payload_ceiling_k);
    seal_into(widest_pair.client, widest, wire);
    verify(declared_length(wire) == max_message_k);
    verify(wire.length == secure_tunnel_headroom_k + max_message_k);
    verify(widest_pair.server.bytes_until_boundary(wire.received()) == 0u);
    secure_tunnel_opened_t const opened = open_from(widest_pair.server, wire);
    verify(opened.consumed > 0u);
    verify(opened.payload.size() == secure_tunnel_payload_ceiling_k);

    // Isolated from framing: two identical senders produce identical records, so the only
    // variable left is what a reader offers as associated data. Invisible to any test that
    // tampers with the prefix instead, because tampering also moves the tag.
    // A driver reserves `record_size()`, not the format's maximum, so the exact buffer is what
    // exposes an off-by-one that a generous one hides.
    announce("a_driver_sized_buffer_holds_a_maximum_payload");
    connected_pair_t exact_pair;
    exact_pair.connect(secure_tunnel_mode_t::noise_xx_k, secure_tunnel_payload_ceiling_k);
    wire_t exact;
    verify(exact.reserve(exact_pair.client.geometry().record_size()));
    verify(exact.storage.capacity() == secure_tunnel_max_record_k, "the ceiling's record_size should be the maximum");
    seal_into(exact_pair.client, widest, exact);
    verify(exact.length == exact.storage.capacity(), "a maximum record did not fill its exact buffer");
    verify(open_from(exact_pair.server, exact).payload.size() == secure_tunnel_payload_ceiling_k);

    // The same at a modest cap, where `record_size()` is nowhere near the format's maximum.
    connected_pair_t modest_pair;
    modest_pair.connect(secure_tunnel_mode_t::noise_xx_k, 1024);
    wire_t modest;
    verify(modest.reserve(modest_pair.client.geometry().record_size()));
    span<byte_t> const modest_window = modest_pair.client.payload_window(modest.whole());
    verify(modest_window.size() == 1024u, "a {}-byte buffer offered a {}-byte window", modest.storage.capacity(),
           modest_window.size());
    fill_with(modest_window, 'm');
    modest.length = modest_pair.client.seal(modest.whole(), modest_window.size()).size();
    verify(modest.length == modest.storage.capacity(), "a capped record did not fill its exact buffer");
    verify(open_from(modest_pair.server, modest).payload.size() == 1024u);

    // A client reusing one static identity across connections is ordinary; the sessions must still
    // be independent, so byte-identical plaintext must not produce byte-identical ciphertext.
    announce("one_identity_yields_independent_sessions");
    keypair_t reused_client, reused_server;
    verify(reused_client.draw());
    verify(reused_server.draw());

    wire_t first_session, second_session;
    verify(first_session.reserve());
    verify(second_session.reserve());
    connected_pair_t earlier, later;
    earlier.connect_with(secure_tunnel_mode_t::noise_xx_k, reused_client, reused_server);
    later.connect_with(secure_tunnel_mode_t::noise_xx_k, reused_client, reused_server);
    seal_into(earlier.client, ascii_bytes("identical plaintext"), first_session);
    seal_into(later.client, ascii_bytes("identical plaintext"), second_session);
    verify(first_session.length == second_session.length);
    verify(!bytes_equal(first_session.received(), second_session.received()),
           "two sessions on one identity produced the same ciphertext");

    announce("sealing_binds_the_length_prefix_into_the_tag");
    byte_t key[secure_tunnel_key_size_k];
    for (std::size_t index = 0; index != sizeof(key); ++index) key[index] = static_cast<byte_t>(index * 7u + 1u);

    auto seal_from_a_fresh_sender = [&key](byte_t *record) {
        secure_tunnel_noise_t sender;
        sender.sending.initialize(key);
        std::memcpy(record + secure_tunnel_headroom_k, "bound", 5);
        std::size_t const produced = seal_record(sender, record, 5, secure_tunnel_record_t::application_k);
        verify(produced > 0u, "a fresh sender refused a five-byte payload");
        return produced;
    };

    byte_t first_record[64] {}, second_record[64] {};
    std::size_t const written = seal_from_a_fresh_sender(first_record);
    verify(seal_from_a_fresh_sender(second_record) == written, "two identical seals produced different lengths");
    verify(bytes_equal({first_record, first_record + written}, {second_record, second_record + written}),
           "identical senders sealing identical payloads must agree byte for byte");

    std::size_t const body_size = 5 + kind_size_k;
    secure_tunnel_cipher_t honest;
    honest.initialize(key);
    verify(honest.open({first_record, first_record + secure_tunnel_headroom_k},
                       {first_record + secure_tunnel_headroom_k, first_record + secure_tunnel_headroom_k + body_size},
                       first_record + secure_tunnel_headroom_k + body_size));

    secure_tunnel_cipher_t forgetful;
    forgetful.initialize(key);
    verify(!forgetful.open(
        {}, {second_record + secure_tunnel_headroom_k, second_record + secure_tunnel_headroom_k + body_size},
        second_record + secure_tunnel_headroom_k + body_size));
}

void test_records_safety() {
    wire_t wire, replayed;
    verify(wire.reserve());
    verify(replayed.reserve());

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        {
            announce("{} a_forged_tag_breaks_the_connection", mode);
            connected_pair_t pair;
            pair.connect(mode);
            seal_into(pair.client, ascii_bytes("authentic"), wire);
            wire.bytes()[wire.length - 1] ^= 0x01u;
            verify(open_from(pair.server, wire).consumed == 0u);
            verify(pair.server.fault() == secure_tunnel_fault_t::authentication_failed_k);
            verify(pair.server.state() == secure_tunnel_state_t::broken_k);
        }
        {
            // A shortened prefix still leaves a whole record present by the boundary rule, so
            // `open` has to be the thing that objects.
            announce("{} a_shortened_prefix_yields_no_plaintext", mode);
            connected_pair_t pair;
            pair.connect(mode);
            seal_into(pair.client, ascii_bytes("prefix authenticated"), wire);
            --wire.bytes()[1];
            verify(pair.server.bytes_until_boundary(wire.received()) == 0u);
            verify(open_from(pair.server, wire).consumed == 0u);
            verify(pair.server.fault() == secure_tunnel_fault_t::authentication_failed_k);
        }
        {
            announce("{} a_sixteen_byte_record_is_refused", mode);
            connected_pair_t pair;
            pair.connect(mode);
            std::memset(wire.bytes(), 0, 2 + 16);
            wire.bytes()[1] = 16;
            wire.length = 2 + 16;
            verify(open_from(pair.server, wire).consumed == 0u);
            verify(pair.server.fault() == secure_tunnel_fault_t::malformed_k);
        }
        {
            announce("{} a_payload_wider_than_the_cap_is_refused", mode);
            connected_pair_t pair;
            pair.connect(mode, 64);
            verify(pair.client.payload_window(wire.whole()).size() == 64u);
            verify(pair.client.seal(wire.whole(), 65).size() == 0u);
            verify(pair.client.fault() == secure_tunnel_fault_t::malformed_k);
            verify(pair.client.state() == secure_tunnel_state_t::broken_k);
        }
        {
            // Each empty record costs a decryption and resets the idle timer, so an unbounded run
            // holds a connection open forever at nineteen bytes apiece.
            announce("{} consecutive_empty_records_are_bounded", mode);
            connected_pair_t pair;
            pair.connect(mode);
            for (std::size_t index = 0; index != empty_record_limit_k; ++index) {
                seal_into(pair.client, {}, wire);
                verify(open_from(pair.server, wire).consumed > 0u);
            }
            seal_into(pair.client, {}, wire);
            verify(open_from(pair.server, wire).consumed == 0u);
            verify(pair.server.fault() == secure_tunnel_fault_t::malformed_k);
        }
        {
            // Without the reset a long-lived connection eventually trips the limit on legitimate
            // traffic.
            announce("{} a_carrying_record_resets_the_empty_run", mode);
            connected_pair_t pair;
            pair.connect(mode);
            for (std::size_t cycle = 0; cycle != 3; ++cycle) {
                for (std::size_t index = 0; index != empty_record_limit_k - 1; ++index) {
                    seal_into(pair.client, {}, wire);
                    verify(open_from(pair.server, wire).consumed > 0u);
                }
                seal_into(pair.client, ascii_bytes("x"), wire);
                verify(open_from(pair.server, wire).consumed > 0u);
            }
        }
        {
            // Re-delivering a record the peer already opened is what a retrying proxy does. The
            // receiving nonce has advanced, so the tag no longer matches.
            announce("{} a_replayed_record_is_refused", mode);
            connected_pair_t pair;
            pair.connect(mode);
            seal_into(pair.client, ascii_bytes("once"), wire);

            // Kept before opening, because `open` uncovers the plaintext over the ciphertext.
            replayed.length = wire.length;
            std::memcpy(replayed.bytes(), wire.bytes(), wire.length);
            verify(open_from(pair.server, wire).consumed > 0u);

            verify(open_from(pair.server, replayed).consumed == 0u, "a replayed record was accepted");
            verify(pair.server.fault() == secure_tunnel_fault_t::authentication_failed_k);
        }
        {
            // Two sessions between the same two identities. Only the ephemerals separate them, so
            // this is the case that proves they are doing that work.
            announce("{} a_record_from_another_session_is_refused", mode);
            keypair_t client_identity, server_identity;
            verify(client_identity.draw());
            verify(server_identity.draw());

            connected_pair_t earlier, later;
            earlier.connect_with(mode, client_identity, server_identity);
            later.connect_with(mode, client_identity, server_identity);

            seal_into(earlier.client, ascii_bytes("session one"), wire);
            verify(open_from(later.server, wire).consumed == 0u, "a record crossed between sessions");
            verify(later.server.fault() == secure_tunnel_fault_t::authentication_failed_k);
        }
    }
}

void test_records_delivery() {
    wire_t wire, second_wire;
    verify(wire.reserve());
    verify(second_wire.reserve());

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{}", mode);

        connected_pair_t pair;
        pair.connect(mode);

        // Until the length prefix has landed there is nothing to read a length from, so the
        // answer is the rest of the prefix - a progress guarantee rather than the record's width.
        seal_into(pair.client, ascii_bytes("boundary"), wire);
        std::size_t const stride = sweep_stride(wire.length);
        for (std::size_t prefix = 0; prefix < wire.length; prefix += stride) {
            std::size_t const expected =
                prefix < secure_tunnel_headroom_k ? secure_tunnel_headroom_k - prefix : wire.length - prefix;
            std::size_t const answered = pair.server.bytes_until_boundary({wire.bytes(), wire.bytes() + prefix});
            verify(answered == expected, "{} at prefix {} of {} the boundary answered {}, expected {}", mode, prefix,
                   wire.length, answered, expected);
        }
        verify(pair.server.bytes_until_boundary(wire.received()) == 0u);
        verify(pair.server.bytes_until_boundary({}) == secure_tunnel_headroom_k);

        // Sealing advanced the sender's nonce, so leaving the swept record unopened would part
        // the two ends' schedules and read as a tunnel defect rather than a skipped step.
        secure_tunnel_opened_t const swept = open_from(pair.server, wire);
        verify(swept.consumed > 0u, "the record the boundary sweep walked would not open");
        verify_bytes(swept.payload, ascii_bytes("boundary"));

        seal_into(pair.client, ascii_bytes("first"), wire);
        seal_into(pair.client, ascii_bytes("second"), second_wire);
        std::memcpy(wire.bytes() + wire.length, second_wire.bytes(), second_wire.length);
        wire.length += second_wire.length;

        verify(pair.server.bytes_until_boundary(wire.received()) == 0u);
        secure_tunnel_opened_t const one = open_from(pair.server, wire);
        verify(one.consumed > 0u);
        verify(one.consumed < wire.length);
        verify_bytes(one.payload, ascii_bytes("first"));

        std::memmove(wire.bytes(), wire.bytes() + one.consumed, wire.length - one.consumed);
        wire.length -= one.consumed;
        verify(pair.server.bytes_until_boundary(wire.received()) == 0u);
        secure_tunnel_opened_t const two = open_from(pair.server, wire);
        verify(two.consumed > 0u);
        verify_bytes(two.payload, ascii_bytes("second"));

        // A stream of records arriving in chunks a driver never chose, reassembled the way a
        // driver has to: read, ask the boundary rule, open only when it answers zero.
        std::size_t const records = scale_iterations(8);
        announce("{} reassembled_from_{}_records_in_random_chunks", mode, records);

        wire_t sent;
        verify(sent.reserve());
        std::size_t produced = 0;
        for (std::size_t index = 0; index != records; ++index) {
            seal_into(pair.client, ascii_bytes("chunked payload"), second_wire);
            verify(produced + second_wire.length <= sent.storage.capacity(), "the stream outgrew its buffer");
            std::memcpy(sent.bytes() + produced, second_wire.bytes(), second_wire.length);
            produced += second_wire.length;
        }

        wire_t inbox;
        verify(inbox.reserve());
        std::size_t offered = 0, opened_count = 0;
        while (opened_count != records) {
            std::size_t const wanted = pair.server.bytes_until_boundary(inbox.received());
            verify(wanted > 0u || inbox.length > 0u, "the boundary rule stopped asking for bytes");
            if (wanted) {
                // A chunk no larger than what is still owed, and never zero, so this terminates.
                std::size_t const remaining = produced - offered;
                verify(remaining > 0u, "the boundary asked for {} more bytes than were ever sent", wanted);
                std::size_t const chunk = 1 + global_random_generator().below(remaining < wanted ? remaining : wanted);
                std::memcpy(inbox.bytes() + inbox.length, sent.bytes() + offered, chunk);
                inbox.length += chunk;
                offered += chunk;
                continue;
            }
            secure_tunnel_opened_t const next = open_from(pair.server, inbox);
            verify(next.consumed > 0u, "record {} of {} failed with {}", opened_count, records, pair.server.fault());
            verify_bytes(next.payload, ascii_bytes("chunked payload"));
            std::memmove(inbox.bytes(), inbox.bytes() + next.consumed, inbox.length - next.consumed);
            inbox.length -= next.consumed;
            ++opened_count;
        }
        verify(offered == produced, "{} of {} stream bytes were never delivered", offered, produced);
    }
}

#pragma endregion Records

#pragma region Closing

void test_close_unit() {
    wire_t wire;
    verify(wire.reserve());

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        {
            announce("{} a_close_shuts_one_direction", mode);
            connected_pair_t pair;
            pair.connect(mode);
            seal_into(pair.client, ascii_bytes("before"), wire);
            verify(open_from(pair.server, wire).consumed > 0u);

            secure_tunnel_step_t const closing = pair.client.advance({}, secure_tunnel_request_t::close_k);
            verify(closing.state == secure_tunnel_state_t::transmitting_k);
            verify(closing.outbound.size() > 0u);
            verify(!pair.client.may_seal());
            verify(pair.client.may_open());

            std::memcpy(wire.bytes(), closing.outbound.data(), closing.outbound.size());
            wire.length = closing.outbound.size();
            secure_tunnel_opened_t const received = open_from(pair.server, wire);
            verify(received.consumed > 0u);
            verify(received.kind == secure_tunnel_record_t::close_k);
            verify(received.payload.size() == 0u);
            verify(!pair.server.may_open());
            verify(pair.server.may_seal());

            // The close goes through the sealing path, so it advances both counts or the rekey
            // schedules diverge with no diagnosable symptom.
            verify(pair.client.records_sealed() == 2u);
            verify(pair.server.records_opened() == 2u);

            seal_into(pair.server, ascii_bytes("last words"), wire);
            verify(open_from(pair.client, wire).consumed > 0u);

            // Nothing legitimate follows an authenticated close, so this is a protocol violation.
            std::memset(wire.bytes(), 0, 64);
            wire.length = 64;
            verify(open_from(pair.server, wire).consumed == 0u);
            verify(pair.server.fault() == secure_tunnel_fault_t::malformed_k);
        }
        {
            announce("{} both_directions_shut_reports_closed", mode);
            connected_pair_t pair;
            pair.connect(mode);

            secure_tunnel_step_t const server_closing = pair.server.advance({}, secure_tunnel_request_t::close_k);
            std::memcpy(wire.bytes(), server_closing.outbound.data(), server_closing.outbound.size());
            wire.length = server_closing.outbound.size();
            verify(open_from(pair.client, wire).consumed > 0u);
            verify(!pair.client.may_open());

            secure_tunnel_step_t const client_closing = pair.client.advance({}, secure_tunnel_request_t::close_k);
            verify(client_closing.state == secure_tunnel_state_t::closed_k);
            verify(client_closing.outbound.size() > 0u); // the close still has to reach the peer

            secure_tunnel_step_t const again = pair.client.advance({});
            verify(again.state == secure_tunnel_state_t::closed_k);
            verify(again.outbound.size() == 0u);
        }
    }
}

/** @brief A close coalesced into one read behind the peer's last data record. */
void test_close_delivery() {
    wire_t wire, tail;
    verify(wire.reserve());
    verify(tail.reserve());

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{} a_close_behind_data_in_one_read", mode);

        connected_pair_t pair;
        pair.connect(mode);
        seal_into(pair.client, ascii_bytes("last request"), wire);

        secure_tunnel_step_t const closing = pair.client.advance({}, secure_tunnel_request_t::close_k);
        verify(closing.outbound.size() > 0u);
        std::memcpy(wire.bytes() + wire.length, closing.outbound.data(), closing.outbound.size());
        wire.length += closing.outbound.size();

        // The data record has to come out first, with the close still untouched behind it.
        verify(pair.server.bytes_until_boundary(wire.received()) == 0u);
        secure_tunnel_opened_t const data = open_from(pair.server, wire);
        verify(data.consumed > 0u);
        verify(data.kind == secure_tunnel_record_t::application_k);
        verify_bytes(data.payload, ascii_bytes("last request"));
        verify(pair.server.may_open(), "the close took effect before its record was opened");

        std::memmove(wire.bytes(), wire.bytes() + data.consumed, wire.length - data.consumed);
        wire.length -= data.consumed;
        secure_tunnel_opened_t const shut = open_from(pair.server, wire);
        verify(shut.consumed > 0u);
        verify(shut.kind == secure_tunnel_record_t::close_k);
        verify(!pair.server.may_open());
        verify(pair.server.may_seal(), "a received close shut the reply direction too");
    }
}

#pragma endregion Closing

#pragma region Lifecycle

/**
 *  @brief A pooled tunnel serving a second connection.
 *
 *  `make` calls `reset`, so re-using a `secure_tunnel_t` is the normal server shape. What a second
 *  session must not inherit is the first one's nonces, counters, or direction flags.
 */
void test_reuse_unit() {
    wire_t wire;
    verify(wire.reserve());

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        announce("{}", mode);

        connected_pair_t pair;
        pair.connect(mode);
        for (std::size_t index = 0; index != 4; ++index) {
            seal_into(pair.client, ascii_bytes("first session"), wire);
            verify(open_from(pair.server, wire).consumed > 0u);
        }
        [[maybe_unused]] secure_tunnel_step_t const closing = pair.client.advance({}, secure_tunnel_request_t::close_k);
        verify(!pair.client.may_seal());
        verify(pair.client.records_sealed() > 0u);

        // A fresh `make` on the same objects, exactly as a connection pool would.
        verify(pair.attempt(mode, 0, connected_pair_t::keys_t::supplied_k) == handshake_outcome_t::settled_k,
               "a reused tunnel could not handshake again");

        verify(pair.client.records_sealed() == 0u, "a reused tunnel kept {} sealed records",
               pair.client.records_sealed());
        verify(pair.server.records_opened() == 0u, "a reused tunnel kept {} opened records",
               pair.server.records_opened());
        verify(pair.client.may_seal(), "a reused tunnel inherited a shut sending direction");
        verify(pair.client.may_open());
        verify(pair.client.fault() == secure_tunnel_fault_t::none_k);

        // The nonces reset with everything else, so the second session's first record opens.
        seal_into(pair.client, ascii_bytes("second session"), wire);
        secure_tunnel_opened_t const opened = open_from(pair.server, wire);
        verify(opened.consumed > 0u, "a reused tunnel's first record failed with {}", pair.server.fault());
        verify_bytes(opened.payload, ascii_bytes("second session"));
    }
}

#pragma endregion Lifecycle

#pragma region Sweeps

/**
 *  @brief Every pattern against every payload width, exchanged both ways under a rekey schedule.
 *
 *  The named cases above each pin one property at one width. This is the cross-product, so a
 *  width that only misbehaves under a particular pattern has somewhere to show up.
 */
void test_tunnel_stress() {
    wire_t wire;
    verify(wire.reserve());
    array<byte_t> payload;
    verify(payload.reserve(secure_tunnel_payload_ceiling_k));

    std::size_t const exchanges = scale_iterations(16);

    for (secure_tunnel_mode_t const mode : tunnel_modes_k)
        for (payload_width_t const width : payload_widths_k) {
            // Past `empty_record_limit_k` the tunnel shuts the connection; that refusal is
            // `test_records_safety`'s case, not this one's.
            std::size_t const rounds = width == payload_width_t::empty_k
                                           ? (exchanges < empty_record_limit_k ? exchanges : empty_record_limit_k)
                                           : exchanges;
            announce("{} {} x{}", mode, width, rounds);

            std::size_t const filled = static_cast<std::size_t>(width);
            connected_pair_t pair;
            pair.connect(mode, secure_tunnel_payload_ceiling_k);

            for (std::size_t exchange = 0; exchange != rounds; ++exchange) {
                byte_t const marker = static_cast<byte_t>(global_random_generator()());
                span<byte_t> const scratch {payload.data(), payload.data() + filled};
                fill_with(scratch, marker);
                span<byte_t const> const sent = scratch;

                seal_into(pair.client, sent, wire);
                verify(pair.server.bytes_until_boundary(wire.received()) == 0u);
                secure_tunnel_opened_t const request = open_from(pair.server, wire);
                verify(request.consumed > 0u, "{} {} exchange {} was refused with {}", mode, width, exchange,
                       pair.server.fault());
                verify(request.payload.size() == filled, "opened {} bytes, sealed {}", request.payload.size(), filled);
                verify(request.payload.data() == wire.bytes() + secure_tunnel_headroom_k);
                verify(all_equal_to(request.payload, marker));

                seal_into(pair.server, sent, wire);
                secure_tunnel_opened_t const reply = open_from(pair.client, wire);
                verify(reply.consumed > 0u);
                verify(reply.payload.size() == filled);
                verify(all_equal_to(reply.payload, marker));
            }

            verify(pair.client.records_sealed() == pair.server.records_opened());
            verify(pair.server.records_sealed() == pair.client.records_opened());
        }
}

#pragma endregion Sweeps

int main() {
    install_test_signal_handlers();
    fmt::print("Hi, dear tester! You look nice today!\n");
    configure_tests();

    run_test("test_hmac_unit", test_hmac_unit);
    run_test("test_hkdf_unit", test_hkdf_unit);
    run_test("test_transcript_unit", test_transcript_unit);
    run_test("test_entropy_unit", test_entropy_unit);

    run_test("test_config_unit", test_config_unit);
    run_test("test_config_safety", test_config_safety);
    run_test("test_geometry_safety", test_geometry_safety);

    run_test("test_handshake_unit", test_handshake_unit);
    run_test("test_handshake_safety", test_handshake_safety);

    run_test("test_handshake_delivery", test_handshake_delivery);

    run_test("test_records_unit", test_records_unit);
    run_test("test_records_safety", test_records_safety);
    run_test("test_records_delivery", test_records_delivery);

    run_test("test_close_unit", test_close_unit);
    run_test("test_close_delivery", test_close_delivery);

    run_test("test_reuse_unit", test_reuse_unit);
    run_test("test_tunnel_stress", test_tunnel_stress);

    fmt::print("All tests passed.\n");
    return 0;
}
