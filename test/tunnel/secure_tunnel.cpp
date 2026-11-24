/**
 *  @file test/tunnel/secure_tunnel.cpp
 *  @author Ash Vardanian
 *  @date August 9, 2026
 *  @brief Noise handshakes, framing, record authentication, closing and reuse.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build

#include "properties.hpp"    // `property_tunnel_pair_t`, `check_tunnel_records`
#include "secure_tunnel.hpp" // `connected_pair_t`, `wire_t`, `keypair_t`

namespace unum::ucall::test::tunnel {

static void test_transcript() {
    std::string_view const name = "Noise_XX_25519_AESGCM_SHA256";

    if (!expect_true(name.size() <= crypto_t::hash_size_k)) return;
    crypto_t::secure_tunnel_transcript_t padded;
    padded.initialize(name);
    byte_t expected[crypto_t::hash_size_k] {};
    std::memcpy(expected, name.data(), name.size());
    expect_equal_bytes(padded.hash(), expected);

    char long_name[40];
    for (char& character : long_name) character = 'x';
    crypto_t::secure_tunnel_transcript_t hashed;
    hashed.initialize({long_name, sizeof(long_name)});

    sz_sha256_state_t digest_state;
    crypto_t::sha_init(&digest_state, nullptr);
    crypto_t::sha_update(&digest_state, long_name, sizeof(long_name), nullptr);
    byte_t hashed_expected[crypto_t::hash_size_k];
    crypto_t::sha_digest(&digest_state, reinterpret_cast<sz_u8_t*>(hashed_expected), nullptr);
    expect_equal_bytes(hashed.hash(), hashed_expected);

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
    expect_true(!bytes_equal(forward.hash(), backward.hash()));

    crypto_t::secure_tunnel_transcript_t prologued;
    prologued.initialize(name);
    byte_t before[crypto_t::hash_size_k];
    std::memcpy(before, prologued.hash().data(), crypto_t::hash_size_k);
    prologued.mix_hash({});
    expect_true(!bytes_equal(prologued.hash(), before));
}

#pragma endregion Primitives

#pragma region Configuration

static void test_config() {
    secure_tunnel_t plain;
    expect_true(plain.state() == secure_tunnel_state_t::ready_k);
    expect_true(!plain.encrypts());
    expect_true(plain.may_seal());
    expect_true(plain.may_open());
    expect_true(plain.geometry().headroom == 0u);
    expect_true(plain.geometry().tailroom == 0u);
    expect_true(plain.bytes_until_boundary({}) == 0u);

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {

        connected_pair_t pair;
        pair.connect(mode);
        secure_tunnel_geometry_t const geometry = pair.client.geometry();
        expect_true(geometry.headroom == secure_tunnel_headroom_k);
        expect_true(geometry.tailroom == secure_tunnel_tailroom_k);
        expect_true(geometry.max_payload == secure_tunnel_default_payload_k);
        expect_true(geometry.record_size() == secure_tunnel_default_payload_k + secure_tunnel_overhead_k);

        connected_pair_t oversized;
        oversized.connect(mode, secure_tunnel_payload_ceiling_k + 4096);
        expect_true(oversized.client.geometry().max_payload == secure_tunnel_payload_ceiling_k);
    }
}

static void test_config_hostile() {
    // An absent static key would silently become a scalar of zeros.
    for (secure_tunnel_mode_t const mode : tunnel_modes_k)
        for (secure_tunnel_role_t const role : {secure_tunnel_role_t::initiator_k, secure_tunnel_role_t::responder_k}) {
            secure_tunnel_t tunnel;
            secure_tunnel_config_t config;
            config.mode = mode;
            config.role = role;
            expect_true(tunnel.make(config) == secure_tunnel_fault_t::misconfigured_k,
                        "{} {} accepted a configuration with no local static key", mode, role);
        }

    keypair_t keys;
    expect_true(keys.draw());

    secure_tunnel_t narrow;
    secure_tunnel_config_t narrow_config;
    narrow_config.mode = secure_tunnel_mode_t::noise_xx_k;
    narrow_config.role = secure_tunnel_role_t::responder_k;
    narrow_config.local_private = {keys.secret, keys.secret + 16}; // half a key
    expect_true(narrow.make(narrow_config) == secure_tunnel_fault_t::misconfigured_k);

    // An `IK` initiator hashes the responder's static before message one, so it cannot come from
    // the wire - the transcripts would diverge before anything is sent.
    secure_tunnel_t unshared;
    secure_tunnel_config_t unshared_config;
    unshared_config.mode = secure_tunnel_mode_t::noise_ik_k;
    unshared_config.role = secure_tunnel_role_t::initiator_k;
    unshared_config.local_private = keys.private_half();
    expect_true(unshared.make(unshared_config) == secure_tunnel_fault_t::misconfigured_k);
}

/**
 *  @brief What a bind's `max_payload` bounds on ingress.
 *
 *  The sender sizes records from its own `geometry().record_size()`, so a peer configured wider can
 *  seal records this side never agreed to hold. `open` bounds every record by this side's cap.
 */
static void test_geometry_hostile() {
    wire_t wire;
    if (!expect_true(wire.reserve())) return;

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {

        keypair_t client_identity, server_identity;
        expect_true(client_identity.draw());
        expect_true(server_identity.draw());

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
        expect_true(client.make(client_config) == secure_tunnel_fault_t::none_k);
        expect_true(server.make(server_config) == secure_tunnel_fault_t::none_k);
        expect_true(complete_handshake(client, server) == handshake_outcome_t::settled_k);

        std::size_t const server_buffer = server.geometry().record_size();
        expect_true(server_buffer == 1024 + secure_tunnel_overhead_k);

        span<byte_t> const window = client.payload_window(wire.whole());
        expect_true(window.size() == secure_tunnel_payload_ceiling_k);
        fill_with(window, byte_t {'X'});
        wire.length = client.seal(wire.whole(), 1024).size();
        secure_tunnel_opened_t const at_cap = open_from(server, wire);
        expect_true(at_cap.consumed == wire.length, "{} refused a record at its cap with {}", mode, server.fault());
        expect_true(at_cap.payload.size() == 1024u);

        fill_with(window, byte_t {'X'});
        wire.length = client.seal(wire.whole(), 1025).size();
        expect_true(wire.length > server_buffer, "the capped side was not the smaller one");

        // What a driver sees first: two bytes of prefix, and a demand the boundary rule trusts.
        std::size_t const demanded = server.bytes_until_boundary(wire.whole().first(secure_tunnel_headroom_k));
        expect_true(demanded == wire.length - secure_tunnel_headroom_k);

        expect_true(open_from(server, wire).consumed == 0u, "{} opened a record past its cap", mode);
        expect_true(server.fault() == secure_tunnel_fault_t::malformed_k);
        expect_true(server.state() == secure_tunnel_state_t::broken_k);
    }
}

#pragma endregion Configuration

#pragma region Handshake

static void test_handshake() {
    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {

        connected_pair_t pair;
        pair.connect(mode);
        expect_true(pair.client.may_seal());
        expect_true(pair.client.may_open());
        expect_true(pair.server.may_seal());
        expect_true(pair.server.may_open());

        // `KK` transmits no static token, so nothing promotes a peer key while reading - only the
        // split does, which is what makes this hold for that pattern.
        byte_t seen_by_client[secure_tunnel_key_size_k];
        byte_t seen_by_server[secure_tunnel_key_size_k];
        expect_true(pair.client.peer_key(seen_by_client));
        expect_true(pair.server.peer_key(seen_by_server));
        expect_equal_bytes(seen_by_client, pair.server_keys.public_half());
        expect_equal_bytes(seen_by_server, pair.client_keys.public_half());
    }

    // A configured key is assumed, not proven, and must stay unreported until authenticated.
    keypair_t client_keys, server_keys;
    expect_true(client_keys.draw());
    expect_true(server_keys.draw());

    secure_tunnel_t unproven;
    secure_tunnel_config_t unproven_config;
    unproven_config.mode = secure_tunnel_mode_t::noise_ik_k;
    unproven_config.role = secure_tunnel_role_t::initiator_k;
    unproven_config.local_private = client_keys.private_half();
    unproven_config.peer_public = server_keys.public_half();
    expect_true(unproven.make(unproven_config) == secure_tunnel_fault_t::none_k);

    byte_t seen[secure_tunnel_key_size_k];
    expect_true(!unproven.peer_key(seen));
    expect_true(unproven.state() == secure_tunnel_state_t::starting_k);

    // The patterns that send a static key overwrite nothing a configuration pinned.
    for (secure_tunnel_mode_t const mode : {secure_tunnel_mode_t::noise_ik_k, secure_tunnel_mode_t::noise_xx_k}) {
        keypair_t pinned, stranger, serving;
        expect_true(pinned.draw() && stranger.draw() && serving.draw());
        for (keypair_t const* arriving : {&pinned, &stranger}) {
            secure_tunnel_config_t arriving_config;
            arriving_config.mode = mode;
            arriving_config.role = secure_tunnel_role_t::initiator_k;
            arriving_config.local_private = arriving->private_half();
            arriving_config.local_public = arriving->public_half();
            if (mode == secure_tunnel_mode_t::noise_ik_k) arriving_config.peer_public = serving.public_half();
            secure_tunnel_config_t pinning_config;
            pinning_config.mode = mode;
            pinning_config.role = secure_tunnel_role_t::responder_k;
            pinning_config.local_private = serving.private_half();
            pinning_config.local_public = serving.public_half();
            pinning_config.peer_public = pinned.public_half();
            secure_tunnel_t initiator, responder;
            expect_true(initiator.make(arriving_config) == secure_tunnel_fault_t::none_k &&
                        responder.make(pinning_config) == secure_tunnel_fault_t::none_k);
            bool const admitted = complete_handshake(initiator, responder) == handshake_outcome_t::settled_k;
            expect_true(admitted == (arriving == &pinned), "{} admitted {} key", mode,
                        arriving == &pinned ? "no pinned" : "a stranger's");
            expect_true(responder.peer_key(seen) == admitted, "{} reported a key it never proved", mode);
        }
    }

    keypair_t keys;
    expect_true(keys.draw());
    secure_tunnel_config_t config;
    config.mode = secure_tunnel_mode_t::noise_xx_k;
    config.local_private = keys.private_half();

    secure_tunnel_t initiator;
    config.role = secure_tunnel_role_t::initiator_k;
    expect_true(initiator.make(config) == secure_tunnel_fault_t::none_k);
    secure_tunnel_step_t const first = initiator.advance({});
    expect_true(first.state == secure_tunnel_state_t::transmitting_k); // an initiator writes before reading
    expect_true(first.outbound.size() > 0u);

    secure_tunnel_t responder;
    config.role = secure_tunnel_role_t::responder_k;
    expect_true(responder.make(config) == secure_tunnel_fault_t::none_k);
    secure_tunnel_step_t const second = responder.advance({});
    expect_true(second.state == secure_tunnel_state_t::receiving_k); // a responder has nothing to say first
    expect_true(second.outbound.size() == 0u);

    // Forward secrecy: an attacker who later takes the static key, or reads this process's
    // memory, must not be able to reconstruct session keys for traffic already sent.
    crypto_t::secure_tunnel_noise_t noise;
    noise.role = secure_tunnel_role_t::initiator_k;
    std::memset(noise.local_ephemeral_private, 0xAB, sizeof(noise.local_ephemeral_private));
    std::memset(noise.remote_ephemeral, 0xCD, sizeof(noise.remote_ephemeral));
    std::memset(noise.local_static_private, 0xEF, sizeof(noise.local_static_private));
    std::memset(noise.remote_static, 0x22, sizeof(noise.remote_static));
    noise.remote_static_state = crypto_t::remote_static_t::authenticated_k;

    crypto_t::finish_handshake(noise);

    expect_true(all_zero(noise.local_ephemeral_private));
    expect_true(all_zero(noise.remote_ephemeral));
    expect_true(all_zero(noise.local_static_private));
    // The peer's public half survives - it is the answer `peer_key` exists to give.
    expect_true(all_equal_to(noise.remote_static, byte_t {0x22}));
    expect_true(noise.sending.has_key());
    expect_true(noise.receiving.has_key());
}

static void test_handshake_hostile() {
    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {

        keypair_t client_keys, server_keys;
        expect_true(client_keys.draw());
        expect_true(server_keys.draw());

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
        expect_true(initiator.make(client_config) == secure_tunnel_fault_t::none_k);
        expect_true(responder.make(server_config) == secure_tunnel_fault_t::none_k);

        secure_tunnel_step_t const first = initiator.advance({});
        expect_true(first.state == secure_tunnel_state_t::transmitting_k);
        handshake_stream_t message;
        expect_true(message.append(first.outbound));

        // Every pattern's opening message contains one ephemeral in the clear behind the length
        // prefix. All zeros is the canonical small-order point.
        expect_true(message.length >= secure_tunnel_headroom_k + secure_tunnel_key_size_k);
        std::memset(message.bytes + secure_tunnel_headroom_k, 0, secure_tunnel_key_size_k);

        secure_tunnel_step_t const answer = responder.advance(message.pending());
        expect_true(answer.state == secure_tunnel_state_t::broken_k);
        expect_true(responder.fault() == secure_tunnel_fault_t::authentication_failed_k);

        // Too short for the ephemeral is malformed, not hostile; the faults must differ.
        secure_tunnel_t truncated_responder;
        expect_true(truncated_responder.make(server_config) == secure_tunnel_fault_t::none_k);
        byte_t const truncated[] = {byte_t {0x00}, byte_t {0x04}, byte_t {0xde},
                                    byte_t {0xad}, byte_t {0xbe}, byte_t {0xef}};
        secure_tunnel_step_t const refused = truncated_responder.advance(truncated);
        expect_true(refused.state == secure_tunnel_state_t::broken_k);
        expect_true(truncated_responder.fault() == secure_tunnel_fault_t::malformed_k);
    }
}

/**
 *  @brief Every handshake message delivered one byte at a time.
 *
 *  `advance` reports what it consumed, so a partial message must leave the bytes in the caller's
 *  hands and emit nothing until a whole one has landed.
 */
static void test_handshake_delivery() {
    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {

        connected_pair_t pair;
        keypair_t client_identity, server_identity;
        expect_true(client_identity.draw());
        expect_true(server_identity.draw());
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
        expect_true(initiator.make(client_config) == secure_tunnel_fault_t::none_k);
        expect_true(responder.make(server_config) == secure_tunnel_fault_t::none_k);

        handshake_stream_t toward_responder, toward_initiator;
        auto trickle = [](secure_tunnel_t& tunnel, handshake_stream_t& inbound, handshake_stream_t& outbound) {
            // Everything but the last byte must be refused as incomplete.
            for (std::size_t fed = 1; fed < inbound.length; ++fed) {
                secure_tunnel_step_t const partial = tunnel.advance({inbound.bytes, inbound.bytes + fed});
                expect_true(partial.state != secure_tunnel_state_t::broken_k, "{} bytes of a message broke the peer",
                            fed);
                expect_true(partial.consumed == 0u, "{} of {} bytes were consumed from a partial message",
                            partial.consumed, inbound.length);
                expect_true(partial.outbound.size() == 0u, "a partial message produced {} outbound bytes",
                            partial.outbound.size());
            }
            secure_tunnel_step_t const step = tunnel.advance(inbound.pending());
            if (!inbound.consume(step.consumed) || !outbound.append(step.outbound))
                return secure_tunnel_state_t::broken_k;
            return step.state;
        };

        for (std::size_t round = 0; round != 8; ++round) {
            expect_true(trickle(initiator, toward_initiator, toward_responder) != secure_tunnel_state_t::broken_k);
            expect_true(trickle(responder, toward_responder, toward_initiator) != secure_tunnel_state_t::broken_k);
            if (initiator.state() == secure_tunnel_state_t::ready_k &&
                responder.state() == secure_tunnel_state_t::ready_k)
                break;
        }
        expect_true(initiator.state() == secure_tunnel_state_t::ready_k,
                    "a trickled {} handshake left the initiator {}", mode, initiator.state());
        expect_true(responder.state() == secure_tunnel_state_t::ready_k,
                    "a trickled {} handshake left the responder {}", mode, responder.state());
    }
}

#pragma endregion Handshake

#pragma region Records

static void test_records() {
    wire_t wire;
    if (!expect_true(wire.reserve())) return;

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {

        connected_pair_t pair;
        pair.connect(mode);

        seal_into(pair.client, byte_span("GET / HTTP/1.1"), wire);
        expect_true(pair.server.bytes_until_boundary(wire.received()) == 0u);
        secure_tunnel_opened_t const request = open_from(pair.server, wire);
        expect_true(request.consumed > 0u);
        expect_true(request.kind == secure_tunnel_record_t::application_k);
        expect_true(request.payload.data() == wire.whole().subspan(secure_tunnel_headroom_k).data());
        expect_equal_bytes(request.payload, byte_span("GET / HTTP/1.1"));

        seal_into(pair.server, byte_span("HTTP/1.1 200 OK"), wire);
        expect_true(pair.client.bytes_until_boundary(wire.received()) == 0u);
        secure_tunnel_opened_t const reply = open_from(pair.client, wire);
        expect_true(reply.consumed > 0u);
        expect_equal_bytes(reply.payload, byte_span("HTTP/1.1 200 OK"));

        // A driver opening into its own buffer finds the payload there
        // and the record as it arrived.
        seal_into(pair.client, byte_span("into a destination"), wire);
        byte_t sealed[64] {}, destination[64] {};
        std::memcpy(sealed, wire.received().data(), wire.received().size_bytes());
        secure_tunnel_opened_t const apart = pair.server.open(wire.arrived(), destination);
        expect_true(apart.consumed == wire.length);
        expect_true(apart.payload.data() == destination);
        expect_equal_bytes(apart.payload, byte_span("into a destination"));
        expect_true(bytes_equal(wire.received(), {sealed, sealed + wire.length}),
                    "opening into a destination rewrote the record");

        // One byte less than this minimum decrypts to nothing, after which reading the kind byte
        // would run off the end of the plaintext.
        seal_into(pair.client, {}, wire);
        expect_true(wire.length == secure_tunnel_headroom_k + secure_tunnel_tailroom_k);
        expect_true(declared_length(wire) == crypto_t::tag_size_k + crypto_t::kind_size_k);
        secure_tunnel_opened_t const empty = open_from(pair.server, wire);
        expect_true(empty.consumed > 0u);
        expect_true(empty.payload.size() == 0u);

        // Diverging counts diverge the rekey schedules, after which every record fails
        // authentication while looking exactly like an attack.
        std::size_t const already_sealed = pair.client.records_sealed();
        std::size_t const already_opened = pair.server.records_opened();
        for (std::size_t index = 0; index != 16; ++index) {
            seal_into(pair.client, byte_span("ping"), wire);
            expect_true(open_from(pair.server, wire).consumed > 0u);
            seal_into(pair.server, byte_span("pong"), wire);
            expect_true(open_from(pair.client, wire).consumed > 0u);
        }
        expect_true(pair.client.records_sealed() == pair.server.records_opened());
        expect_true(pair.server.records_sealed() == pair.client.records_opened());
        expect_true(pair.client.records_sealed() == already_sealed + 16);
        expect_true(pair.server.records_opened() == already_opened + 16);
    }

    // A ceiling that ignored the kind byte would declare 65536, mask to zero, and be rejected.
    st::vector<byte_t> payload;
    if (!expect_true(!st::failed(payload.resize(secure_tunnel_payload_ceiling_k)))) return;
    span<byte_t> const widest_scratch {payload.data(), payload.data() + secure_tunnel_payload_ceiling_k};
    fill_with(widest_scratch, byte_t {'M'});
    span<byte_t const> const widest = widest_scratch;

    connected_pair_t widest_pair;
    widest_pair.connect(secure_tunnel_mode_t::noise_xx_k, secure_tunnel_payload_ceiling_k);
    seal_into(widest_pair.client, widest, wire);
    expect_true(declared_length(wire) == crypto_t::max_message_k);
    expect_true(wire.length == secure_tunnel_headroom_k + crypto_t::max_message_k);
    expect_true(widest_pair.server.bytes_until_boundary(wire.received()) == 0u);
    secure_tunnel_opened_t const opened = open_from(widest_pair.server, wire);
    expect_true(opened.consumed > 0u);
    expect_true(opened.payload.size() == secure_tunnel_payload_ceiling_k);

    // Isolated from framing: two identical senders produce identical records, so the only
    // variable left is what a reader offers as associated data. Invisible to any test that
    // tampers with the prefix instead, because tampering also moves the tag.
    // A driver reserves `record_size()`, not the format's maximum, so the exact buffer is what
    // exposes an off-by-one that a generous one hides.
    connected_pair_t exact_pair;
    exact_pair.connect(secure_tunnel_mode_t::noise_xx_k, secure_tunnel_payload_ceiling_k);
    wire_t exact;
    if (!expect_true(exact.reserve(exact_pair.client.geometry().record_size()))) return;
    expect_true(exact.storage.capacity() == secure_tunnel_max_record_k,
                "the ceiling's record_size should be the maximum");
    seal_into(exact_pair.client, widest, exact);
    expect_true(exact.length == exact.storage.capacity(), "a maximum record did not fill its exact buffer");
    expect_true(open_from(exact_pair.server, exact).payload.size() == secure_tunnel_payload_ceiling_k);

    // The same at a modest cap, where `record_size()` is nowhere near the format's maximum.
    connected_pair_t modest_pair;
    modest_pair.connect(secure_tunnel_mode_t::noise_xx_k, 1024);
    wire_t modest;
    if (!expect_true(modest.reserve(modest_pair.client.geometry().record_size()))) return;
    span<byte_t> const modest_window = modest_pair.client.payload_window(modest.whole());
    expect_true(modest_window.size() == 1024u, "a {}-byte buffer offered a {}-byte window", modest.storage.capacity(),
                modest_window.size());
    fill_with(modest_window, byte_t {'m'});
    modest.length = modest_pair.client.seal(modest.whole(), modest_window.size()).size();
    expect_true(modest.length == modest.storage.capacity(), "a capped record did not fill its exact buffer");
    expect_true(open_from(modest_pair.server, modest).payload.size() == 1024u);

    // A client reusing one static identity across connections is ordinary; the sessions must still
    // be independent, so byte-identical plaintext must not produce byte-identical ciphertext.
    keypair_t reused_client, reused_server;
    expect_true(reused_client.draw());
    expect_true(reused_server.draw());

    wire_t first_session, second_session;
    if (!expect_true(first_session.reserve())) return;
    if (!expect_true(second_session.reserve())) return;
    connected_pair_t earlier, later;
    earlier.connect_with(secure_tunnel_mode_t::noise_xx_k, reused_client, reused_server);
    later.connect_with(secure_tunnel_mode_t::noise_xx_k, reused_client, reused_server);
    seal_into(earlier.client, byte_span("identical plaintext"), first_session);
    seal_into(later.client, byte_span("identical plaintext"), second_session);
    expect_true(first_session.length == second_session.length);
    expect_true(!bytes_equal(first_session.received(), second_session.received()),
                "two sessions on one identity produced the same ciphertext");

    byte_t key[secure_tunnel_key_size_k];
    for (std::size_t index = 0; index != sizeof(key); ++index) key[index] = static_cast<byte_t>(index * 7u + 1u);

    auto seal_from_a_fresh_sender = [&key](span<byte_t> record) {
        crypto_t::secure_tunnel_noise_t sender;
        sender.sending.initialize(key);
        std::memcpy(record.subspan(secure_tunnel_headroom_k).data(), "bound", 5);
        std::size_t const produced = crypto_t::seal_record(sender, record, 5, secure_tunnel_record_t::application_k);
        expect_true(produced > 0u, "a fresh sender refused a five-byte payload");
        return produced;
    };

    byte_t first_record[64] {}, second_record[64] {};
    std::size_t const written = seal_from_a_fresh_sender(first_record);
    expect_true(seal_from_a_fresh_sender(second_record) == written, "two identical seals produced different lengths");
    expect_true(bytes_equal({first_record, first_record + written}, {second_record, second_record + written}),
                "identical senders sealing identical payloads must agree byte for byte");

    std::size_t const body_size = 5 + crypto_t::kind_size_k;
    crypto_t::secure_tunnel_cipher_t honest;
    honest.initialize(key);
    expect_true(
        honest.open({first_record, first_record + secure_tunnel_headroom_k},
                    {first_record + secure_tunnel_headroom_k, first_record + secure_tunnel_headroom_k + body_size},
                    first_record + secure_tunnel_headroom_k + body_size,
                    first_record + secure_tunnel_headroom_k) == secure_tunnel_fault_t::none_k);

    crypto_t::secure_tunnel_cipher_t forgetful;
    forgetful.initialize(key);
    expect_true(
        forgetful.open({},
                       {second_record + secure_tunnel_headroom_k, second_record + secure_tunnel_headroom_k + body_size},
                       second_record + secure_tunnel_headroom_k + body_size,
                       second_record + secure_tunnel_headroom_k) == secure_tunnel_fault_t::authentication_failed_k);
}

static void test_records_hostile() {
    wire_t wire, replayed;
    if (!expect_true(wire.reserve())) return;
    if (!expect_true(replayed.reserve())) return;

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        {
            connected_pair_t pair;
            pair.connect(mode);
            seal_into(pair.client, byte_span("authentic"), wire);
            span<byte_t> const bytes = wire.whole();
            bytes[wire.length - 1] ^= byte_t {0x01u};
            expect_true(open_from(pair.server, wire).consumed == 0u);
            expect_true(pair.server.fault() == secure_tunnel_fault_t::authentication_failed_k);
            expect_true(pair.server.state() == secure_tunnel_state_t::broken_k);
        }
        {
            // A shortened prefix still leaves a whole record present by the boundary rule, so
            // `open` has to be the thing that objects.
            connected_pair_t pair;
            pair.connect(mode);
            seal_into(pair.client, byte_span("prefix authenticated"), wire);
            span<byte_t> const bytes = wire.whole();
            bytes[1] = byte_t {static_cast<unsigned char>(std::to_integer<unsigned>(bytes[1]) - 1)};
            expect_true(pair.server.bytes_until_boundary(wire.received()) == 0u);
            expect_true(open_from(pair.server, wire).consumed == 0u);
            expect_true(pair.server.fault() == secure_tunnel_fault_t::authentication_failed_k);
        }
        {
            connected_pair_t pair;
            pair.connect(mode);
            span<byte_t> const bytes = wire.whole();
            std::memset(bytes.data(), 0, 2 + 16);
            bytes[1] = byte_t {16};
            wire.length = 2 + 16;
            expect_true(open_from(pair.server, wire).consumed == 0u);
            expect_true(pair.server.fault() == secure_tunnel_fault_t::malformed_k);
        }
        {
            connected_pair_t pair;
            pair.connect(mode, 64);
            expect_true(pair.client.payload_window(wire.whole()).size() == 64u);
            expect_true(pair.client.seal(wire.whole(), 65).size() == 0u);
            expect_true(pair.client.fault() == secure_tunnel_fault_t::malformed_k);
            expect_true(pair.client.state() == secure_tunnel_state_t::broken_k);
        }
        {
            connected_pair_t pair;
            pair.connect(mode);
            for (std::size_t index = 0; index != 64; ++index) {
                seal_into(pair.client, {}, wire);
                expect_true(open_from(pair.server, wire).consumed > 0u);
            }
            seal_into(pair.client, byte_span("still open"), wire);
            expect_true(open_from(pair.server, wire).consumed > 0u);
        }
        {
            // Re-delivering a record the peer already opened is what a retrying proxy does. The
            // receiving nonce has advanced, so the tag no longer matches.
            connected_pair_t pair;
            pair.connect(mode);
            seal_into(pair.client, byte_span("once"), wire);

            // Kept before opening, because `open` uncovers the plaintext over the ciphertext.
            replayed.length = wire.length;
            std::memcpy(replayed.whole().data(), wire.received().data(), wire.received().size_bytes());
            expect_true(open_from(pair.server, wire).consumed > 0u);

            expect_true(open_from(pair.server, replayed).consumed == 0u, "a replayed record was accepted");
            expect_true(pair.server.fault() == secure_tunnel_fault_t::authentication_failed_k);
        }
        {
            // Two sessions between the same two identities. Only the ephemerals separate them, so
            // this is the case that proves they are doing that work.
            keypair_t client_identity, server_identity;
            expect_true(client_identity.draw());
            expect_true(server_identity.draw());

            connected_pair_t earlier, later;
            earlier.connect_with(mode, client_identity, server_identity);
            later.connect_with(mode, client_identity, server_identity);

            seal_into(earlier.client, byte_span("session one"), wire);
            expect_true(open_from(later.server, wire).consumed == 0u, "a record crossed between sessions");
            expect_true(later.server.fault() == secure_tunnel_fault_t::authentication_failed_k);
        }
    }
}

static void test_records_delivery(split_mix_generator_t& generator) {
    wire_t wire, second_wire;
    if (!expect_true(wire.reserve())) return;
    if (!expect_true(second_wire.reserve())) return;

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {

        connected_pair_t pair;
        pair.connect(mode);

        // Until the length prefix has landed there is nothing to read a length from, so the
        // answer is the rest of the prefix - a progress guarantee rather than the record's width.
        seal_into(pair.client, byte_span("boundary"), wire);
        // Every prefix at ten times the usual scale, a tenth of them at the usual one.
        std::size_t const stride = sweep_stride(test_run.settings.scale / 10);
        for (std::size_t prefix = 0; prefix < wire.length; prefix += stride) {
            std::size_t const expected = prefix < secure_tunnel_headroom_k ? secure_tunnel_headroom_k - prefix
                                                                           : wire.length - prefix;
            std::size_t const answered = pair.server.bytes_until_boundary(wire.whole().first(prefix));
            expect_true(answered == expected, "{} at prefix {} of {} the boundary answered {}, expected {}", mode,
                        prefix, wire.length, answered, expected);
        }
        expect_true(pair.server.bytes_until_boundary(wire.received()) == 0u);
        expect_true(pair.server.bytes_until_boundary({}) == secure_tunnel_headroom_k);

        // Sealing advanced the sender's nonce, so leaving the swept record unopened would part
        // the two ends' schedules and read as a tunnel defect rather than a skipped step.
        secure_tunnel_opened_t const swept = open_from(pair.server, wire);
        expect_true(swept.consumed > 0u, "the record the boundary sweep walked would not open");
        expect_equal_bytes(swept.payload, byte_span("boundary"));

        seal_into(pair.client, byte_span("first"), wire);
        seal_into(pair.client, byte_span("second"), second_wire);
        std::memcpy(wire.whole().subspan(wire.length).data(), second_wire.received().data(),
                    second_wire.received().size_bytes());
        wire.length += second_wire.length;

        expect_true(pair.server.bytes_until_boundary(wire.received()) == 0u);
        secure_tunnel_opened_t const one = open_from(pair.server, wire);
        expect_true(one.consumed > 0u);
        expect_true(one.consumed < wire.length);
        expect_equal_bytes(one.payload, byte_span("first"));

        std::memmove(wire.whole().data(), wire.received().subspan(one.consumed).data(), wire.length - one.consumed);
        wire.length -= one.consumed;
        expect_true(pair.server.bytes_until_boundary(wire.received()) == 0u);
        secure_tunnel_opened_t const two = open_from(pair.server, wire);
        expect_true(two.consumed > 0u);
        expect_equal_bytes(two.payload, byte_span("second"));

        // A stream of records arriving in chunks a driver never chose, reassembled the way a
        // driver has to: read, ask the boundary rule, open only when it answers zero.
        std::size_t const records = scaled_iterations(8);

        wire_t sent;
        if (!expect_true(sent.reserve())) return;
        std::size_t produced = 0;
        for (std::size_t index = 0; index != records; ++index) {
            seal_into(pair.client, byte_span("chunked payload"), second_wire);
            if (!expect_true(produced + second_wire.length <= sent.storage.capacity(), "the stream outgrew its buffer"))
                return;
            std::memcpy(sent.whole().subspan(produced).data(), second_wire.received().data(),
                        second_wire.received().size_bytes());
            produced += second_wire.length;
        }

        wire_t inbox;
        if (!expect_true(inbox.reserve())) return;
        std::size_t offered = 0, opened_count = 0;
        while (opened_count != records) {
            std::size_t const wanted = pair.server.bytes_until_boundary(inbox.received());
            if (!expect_true(wanted > 0u || inbox.length > 0u, "the boundary rule stopped asking for bytes")) return;
            if (wanted) {
                // A chunk no larger than what is still owed, and never zero, so this terminates.
                std::size_t const remaining = produced - offered;
                if (!expect_true(remaining > 0u, "the boundary asked for {} more bytes than were ever sent", wanted))
                    return;
                std::size_t const chunk = 1 + generator.below(remaining < wanted ? remaining : wanted);
                std::memcpy(inbox.whole().subspan(inbox.length).data(), sent.whole().subspan(offered).data(), chunk);
                inbox.length += chunk;
                offered += chunk;
                continue;
            }
            secure_tunnel_opened_t const next = open_from(pair.server, inbox);
            if (!expect_true(next.consumed > 0u, "record {} of {} failed with {}", opened_count, records,
                             pair.server.fault()))
                return;
            expect_equal_bytes(next.payload, byte_span("chunked payload"));
            std::memmove(inbox.whole().data(), inbox.received().subspan(next.consumed).data(),
                         inbox.length - next.consumed);
            inbox.length -= next.consumed;
            ++opened_count;
        }
        expect_true(offered == produced, "{} of {} stream bytes were never delivered", offered, produced);
    }
}

#pragma endregion Records

#pragma region Closing

static void test_close() {
    wire_t wire;
    if (!expect_true(wire.reserve())) return;

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {
        {
            connected_pair_t pair;
            pair.connect(mode);
            seal_into(pair.client, byte_span("before"), wire);
            expect_true(open_from(pair.server, wire).consumed > 0u);

            secure_tunnel_step_t const closing = pair.client.advance({}, secure_tunnel_request_t::close_k);
            expect_true(closing.state == secure_tunnel_state_t::transmitting_k);
            expect_true(closing.outbound.size() > 0u);
            expect_true(!pair.client.may_seal());
            expect_true(pair.client.may_open());

            std::memcpy(wire.whole().data(), closing.outbound.data(), closing.outbound.size_bytes());
            wire.length = closing.outbound.size();
            secure_tunnel_opened_t const received = open_from(pair.server, wire);
            expect_true(received.consumed > 0u);
            expect_true(received.kind == secure_tunnel_record_t::close_k);
            expect_true(received.payload.size() == 0u);
            expect_true(!pair.server.may_open());
            expect_true(pair.server.may_seal());

            // The close goes through the sealing path, so it advances both counts or the rekey
            // schedules diverge with no diagnosable symptom.
            expect_true(pair.client.records_sealed() == 2u);
            expect_true(pair.server.records_opened() == 2u);

            seal_into(pair.server, byte_span("last words"), wire);
            expect_true(open_from(pair.client, wire).consumed > 0u);

            // Nothing legitimate follows an authenticated close, so this is a protocol violation.
            std::memset(wire.whole().data(), 0, 64);
            wire.length = 64;
            expect_true(open_from(pair.server, wire).consumed == 0u);
            expect_true(pair.server.fault() == secure_tunnel_fault_t::malformed_k);
        }
        {
            connected_pair_t pair;
            pair.connect(mode);

            secure_tunnel_step_t const server_closing = pair.server.advance({}, secure_tunnel_request_t::close_k);
            std::memcpy(wire.whole().data(), server_closing.outbound.data(), server_closing.outbound.size_bytes());
            wire.length = server_closing.outbound.size();
            expect_true(open_from(pair.client, wire).consumed > 0u);
            expect_true(!pair.client.may_open());

            secure_tunnel_step_t const client_closing = pair.client.advance({}, secure_tunnel_request_t::close_k);
            expect_true(client_closing.state == secure_tunnel_state_t::closed_k);
            expect_true(client_closing.outbound.size() > 0u); // the close still has to reach the peer

            secure_tunnel_step_t const again = pair.client.advance({});
            expect_true(again.state == secure_tunnel_state_t::closed_k);
            expect_true(again.outbound.size() == 0u);
        }
    }
}

/** A close coalesced into one read behind the peer's last data record. */
static void test_close_delivery() {
    wire_t wire, tail;
    if (!expect_true(wire.reserve())) return;
    if (!expect_true(tail.reserve())) return;

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {

        connected_pair_t pair;
        pair.connect(mode);
        seal_into(pair.client, byte_span("last request"), wire);

        secure_tunnel_step_t const closing = pair.client.advance({}, secure_tunnel_request_t::close_k);
        expect_true(closing.outbound.size() > 0u);
        std::memcpy(wire.whole().subspan(wire.length).data(), closing.outbound.data(), closing.outbound.size_bytes());
        wire.length += closing.outbound.size();

        // The data record has to come out first, with the close still untouched behind it.
        expect_true(pair.server.bytes_until_boundary(wire.received()) == 0u);
        secure_tunnel_opened_t const data = open_from(pair.server, wire);
        expect_true(data.consumed > 0u);
        expect_true(data.kind == secure_tunnel_record_t::application_k);
        expect_equal_bytes(data.payload, byte_span("last request"));
        expect_true(pair.server.may_open(), "the close took effect before its record was opened");

        std::memmove(wire.whole().data(), wire.received().subspan(data.consumed).data(), wire.length - data.consumed);
        wire.length -= data.consumed;
        secure_tunnel_opened_t const shut = open_from(pair.server, wire);
        expect_true(shut.consumed > 0u);
        expect_true(shut.kind == secure_tunnel_record_t::close_k);
        expect_true(!pair.server.may_open());
        expect_true(pair.server.may_seal(), "a received close shut the reply direction too");
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
static void test_reuse() {
    wire_t wire;
    if (!expect_true(wire.reserve())) return;

    for (secure_tunnel_mode_t const mode : tunnel_modes_k) {

        connected_pair_t pair;
        pair.connect(mode);
        for (std::size_t index = 0; index != 4; ++index) {
            seal_into(pair.client, byte_span("first session"), wire);
            expect_true(open_from(pair.server, wire).consumed > 0u);
        }
        [[maybe_unused]] secure_tunnel_step_t const closing = pair.client.advance({}, secure_tunnel_request_t::close_k);
        expect_true(!pair.client.may_seal());
        expect_true(pair.client.records_sealed() > 0u);

        // A fresh `make` on the same objects, exactly as a connection pool would.
        expect_true(pair.attempt(mode, 0, connected_pair_t::keys_t::supplied_k) == handshake_outcome_t::settled_k,
                    "a reused tunnel could not handshake again");

        expect_true(pair.client.records_sealed() == 0u, "a reused tunnel kept {} sealed records",
                    pair.client.records_sealed());
        expect_true(pair.server.records_opened() == 0u, "a reused tunnel kept {} opened records",
                    pair.server.records_opened());
        expect_true(pair.client.may_seal(), "a reused tunnel inherited a shut sending direction");
        expect_true(pair.client.may_open());
        expect_true(pair.client.fault() == secure_tunnel_fault_t::none_k);

        // The nonces reset with everything else, so the second session's first record opens.
        seal_into(pair.client, byte_span("second session"), wire);
        secure_tunnel_opened_t const opened = open_from(pair.server, wire);
        expect_true(opened.consumed > 0u, "a reused tunnel's first record failed with {}", pair.server.fault());
        expect_equal_bytes(opened.payload, byte_span("second session"));
    }
}

#pragma endregion Lifecycle

#pragma region Sweeps

/**
 *  @brief Every pattern against every payload width, exchanged both ways under a rekey schedule.
 *
 *  The named cases above each pin one property at one width. This is the cross-product, so a width
 *  that only misbehaves under a particular pattern has somewhere to show up.
 */
static void test_tunnel_sweep(split_mix_generator_t& generator) {
    wire_t wire;
    if (!expect_true(wire.reserve())) return;
    st::vector<byte_t> payload;
    if (!expect_true(!st::failed(payload.resize(secure_tunnel_payload_ceiling_k)))) return;

    std::size_t const exchanges = scaled_iterations(16);

    for (secure_tunnel_mode_t const mode : tunnel_modes_k)
        for (payload_width_t const width : payload_widths_k) {
            std::size_t const rounds = exchanges;

            std::size_t const filled = static_cast<std::size_t>(width);
            connected_pair_t pair;
            pair.connect(mode, secure_tunnel_payload_ceiling_k);

            for (std::size_t exchange = 0; exchange != rounds; ++exchange) {
                byte_t const marker = static_cast<byte_t>(generator());
                span<byte_t> const scratch {payload.data(), payload.data() + filled};
                fill_with(scratch, marker);
                span<byte_t const> const sent = scratch;

                seal_into(pair.client, sent, wire);
                expect_true(pair.server.bytes_until_boundary(wire.received()) == 0u);
                secure_tunnel_opened_t const request = open_from(pair.server, wire);
                expect_true(request.consumed > 0u, "{} {} exchange {} was refused with {}", mode, width, exchange,
                            pair.server.fault());
                expect_true(request.payload.size() == filled, "opened {} bytes, sealed {}", request.payload.size(),
                            filled);
                expect_true(request.payload.data() == wire.whole().subspan(secure_tunnel_headroom_k).data());
                expect_true(all_equal_to(request.payload, marker));

                seal_into(pair.server, sent, wire);
                secure_tunnel_opened_t const reply = open_from(pair.client, wire);
                expect_true(reply.consumed > 0u);
                expect_true(reply.payload.size() == filled);
                expect_true(all_equal_to(reply.payload, marker));
            }

            expect_true(pair.client.records_sealed() == pair.server.records_opened());
            expect_true(pair.server.records_sealed() == pair.client.records_opened());
        }
}

#pragma endregion Sweeps

static void test_tunnel_records(split_mix_generator_t& generator) {
    property_tunnel_pair_t pair;
    if (!expect_true(pair.draw(), "keys could not be drawn")) return;
    for (std::size_t iteration = 0; iteration != scaled_iterations(500); ++iteration) {
        std::string input(generator.below(160), '\0');
        for (auto& byte : input) byte = static_cast<char>(generator.below(256));
        std::size_t const found = check_tunnel_records(byte_span(input), pair);
        expect_true(!found, "{} broken promises on a {}-byte input", found, input.size());
        if (found) break;
    }
}

void run_secure_tunnel_cases() {
    run_test_case("run_secure_tunnel_cases", [] {
        split_mix_generator_t generator {case_stream_key()};
        test_transcript();
        test_config();
        test_config_hostile();
        test_geometry_hostile();
        test_handshake();
        test_handshake_hostile();
        test_handshake_delivery();
        test_records();
        test_records_hostile();
        test_records_delivery(generator);
        test_close();
        test_close_delivery();
        test_reuse();
        test_tunnel_sweep(generator);
        test_tunnel_records(generator);
    });
}

} // namespace unum::ucall::test::tunnel
