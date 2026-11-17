/**
 *  @file test/tunnel/secure_tunnel.hpp
 *  @author Ash Vardanian
 *  @date August 9, 2026
 *  @brief The in-memory wires, keypairs and connected pairs the tunnel suites share.
 */
#pragma once
#include <cstring> // `std::memcpy`, `std::memmove`, `std::memset`

#include <string_view> // `std::string_view`

#include "harness.hpp" // `expect_true`, `scaled_iterations`

#include "ucall/tunnel/crypto.hpp"        // `secure_tunnel_crypto`, the serial kits
#include "ucall/tunnel/secure_tunnel.hpp" // `secure_tunnel_t`

namespace unum::ucall::test::tunnel {

using namespace unum::ucall::tunnel;

using crypto_t = secure_tunnel_crypto<serial_sha256_kit_t, serial_aes256_gcm_kit_t, serial_x25519_kit_t>;

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

/** Lets <tt>{}</tt> name an outcome, so a failed handshake reads as a sentence. */
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
inline constexpr secure_tunnel_mode_t tunnel_modes_k[] = {
    secure_tunnel_mode_t::noise_xx_k, secure_tunnel_mode_t::noise_ik_k, secure_tunnel_mode_t::noise_kk_k};

/** Payload widths worth distinguishing, spelled out - never a raw count at a call site. */
enum class payload_width_t : std::uint32_t {
    empty_k = 0,
    single_byte_k = 1,
    typical_request_k = 512,
    small_buffer_k = fixture_buffer_bytes_k,
    ceiling_k = secure_tunnel_payload_ceiling_k,
};

inline constexpr payload_width_t payload_widths_k[] = {payload_width_t::empty_k, payload_width_t::single_byte_k,
                                                       payload_width_t::typical_request_k,
                                                       payload_width_t::small_buffer_k, payload_width_t::ceiling_k};

/** Lets <tt>{}</tt> name a payload width rather than print its byte count twice. */
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
[[nodiscard]] inline handshake_outcome_t complete_handshake(secure_tunnel_t& initiator,
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

    /** Completes a handshake in @p mode, checking it settles, or naming the pattern and outcome. */
    bool connect(secure_tunnel_mode_t mode, std::size_t max_payload = 0) {
        handshake_outcome_t const outcome = attempt(mode, max_payload);
        return expect_true(outcome == handshake_outcome_t::settled_k, "{} handshake {}", mode, outcome);
    }

    /** Whether @c attempt draws fresh static keys or uses the ones already in place. */
    enum class keys_t : bool { fresh_k, supplied_k };

    /** Reconnects on keys the caller already holds, for the cases about identity reuse. */
    bool connect_with(secure_tunnel_mode_t mode, keypair_t const& client_identity, keypair_t const& server_identity) {
        client_keys = client_identity;
        server_keys = server_identity;
        handshake_outcome_t const outcome = attempt(mode, 0, keys_t::supplied_k);
        return expect_true(outcome == handshake_outcome_t::settled_k, "{} handshake {}", mode, outcome);
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

/** Seals one payload into @p wire, in place, as a driver would, checking the tunnel takes it. */
inline bool seal_into(secure_tunnel_t& tunnel, span<byte_t const> payload, wire_t& wire) {
    span<byte_t> const window = tunnel.payload_window(wire.whole());
    if (!expect_true(window.size() >= payload.size(), "a {}-byte window cannot hold {} bytes", window.size(),
                     payload.size()))
        return false;
    if (payload.size()) std::memcpy(window.data(), payload.data(), payload.size());
    wire.length = tunnel.seal(wire.whole(), payload.size()).size();
    return expect_true(wire.length > 0u, "the tunnel refused a {}-byte payload with {}", payload.size(),
                       tunnel.fault());
}

/** Opens one whole record from a wire buffer, in place,
 *  passing the record's own body as the destination. */
[[nodiscard]] inline secure_tunnel_opened_t open_from(secure_tunnel_t& tunnel, wire_t& wire) noexcept {
    span<byte_t> const arrived = wire.arrived();
    return tunnel.open(arrived, arrived.subspan(arrived.size() < secure_tunnel_headroom_k ? arrived.size()
                                                                                          : secure_tunnel_headroom_k));
}

/** The big-endian length a record declares in its prefix. */
[[nodiscard]] inline std::size_t declared_length(wire_t& wire) noexcept {
    span<byte_t const> const prefix = wire.received();
    return (static_cast<std::size_t>(prefix[0]) << 8) | static_cast<std::size_t>(prefix[1]);
}

/**
 *  @brief Builds a run of one repeated byte in scratch storage and views it.
 *
 *  Safe to alias its own argument only because the storage is scratch the caller never reads back;
 *  a sweep that re-reads its buffer keeps the fill and the view apart.
 */
[[nodiscard]] inline span<byte_t const> run_of(span<byte_t> bytes, byte_t value) noexcept {
    fill_with(bytes, value);
    return bytes;
}

/** Computes one tag into @p digest and returns a view of it. */
[[nodiscard]] inline span<byte_t const> hmac_of(span<byte_t const> key, span<byte_t const> data,
                                                span<byte_t, crypto_t::hash_size_k> digest) noexcept {
    crypto_t::hmac_sha256(key, data, digest);
    return digest;
}

} // namespace unum::ucall::test::tunnel
