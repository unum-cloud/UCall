/**
 *  @file include/ucall/tunnel/types.hpp
 *  @author Ash Vardanian
 *  @date August 9, 2026
 *  @brief Noise modes, roles, requests, states, faults and records, the record geometry, and the
 *      configuration and results a tunnel trades with its caller.
 */
#pragma once

#include <cstddef> // `std::size_t`
#include <cstdint> // `std::uint8_t`

#include "ucall/utilities/types.hpp" // `span`, `byte_t`

namespace unum::ucall::tunnel {

using utilities::byte_t;
using utilities::span;

#pragma region Vocabulary

/**
 *  @brief Which record layer a connection speaks.
 *
 *  Plaintext is a mode, not the absence of one, so no call site has to decide what a missing tunnel
 *  means. The three Noise patterns differ only in which static keys are known before the first
 *  message; they share every line of the record layer and every byte of state.
 */
enum class secure_tunnel_mode_t : std::uint8_t {

    /** Bytes pass through untouched. No handshake, no framing, no keys. */
    plain_k = 0,

    /** Neither side knows the other's static key; both are exchanged and authenticated. */
    noise_xx_k,

    /** The initiator knows the responder's static key in advance. */
    noise_ik_k,

    /** Each side knows the other's static key in advance, and neither transmits one. */
    noise_kk_k,
};

/** Names a mode for a log, including when no tunnel exists yet to ask. */
[[nodiscard]] inline char const* secure_tunnel_mode_name(secure_tunnel_mode_t mode) noexcept {
    switch (mode) {
    case secure_tunnel_mode_t::plain_k: return "plain";
    case secure_tunnel_mode_t::noise_xx_k: return "noise_xx";
    case secure_tunnel_mode_t::noise_ik_k: return "noise_ik";
    case secure_tunnel_mode_t::noise_kk_k: return "noise_kk";
    }
    return "unknown";
}

/** Lets <tt>{}</tt> print a mode by name. */
[[nodiscard]] inline auto format_as(secure_tunnel_mode_t value) noexcept { return secure_tunnel_mode_name(value); }

/**
 *  @brief True when a mode frames and encrypts, false when bytes pass through.
 *
 *  A function of the mode alone, so a bind can decide whether to reserve decoded, encoded, and
 *  record buffers before any connection - and therefore any tunnel - exists.
 */
[[nodiscard]] inline bool secure_tunnel_mode_encrypts(secure_tunnel_mode_t mode) noexcept {
    return mode != secure_tunnel_mode_t::plain_k;
}

/**
 *  @brief Which half of the handshake this endpoint performs.
 *
 *  An enumeration rather than a flag, because the answer is not permanently two-valued. Noise Pipes
 *  has an initiator attempt @c IK on a remembered static key and, when the responder cannot decrypt
 *  it, fall back to @c XXfallback - at which point the roles stop dividing the way they started.
 *  A third enumerator absorbs that; a @c bool cannot.
 */
enum class secure_tunnel_role_t : std::uint8_t { initiator_k, responder_k };

/** Names a role for a log, alongside the mode. */
[[nodiscard]] inline char const* secure_tunnel_role_name(secure_tunnel_role_t role) noexcept {
    return role == secure_tunnel_role_t::initiator_k ? "initiator" : "responder";
}

/** Lets <tt>{}</tt> print a role by name. */
[[nodiscard]] inline auto format_as(secure_tunnel_role_t value) noexcept { return secure_tunnel_role_name(value); }

/**
 *  @brief What the caller wants of the pump: its half of the control channel.
 *
 *  An enumeration rather than a flag, because the control channel is not permanently two-valued. An
 *  in-band key update, the day it lands, is a third request and changes no signature.
 */
enum class secure_tunnel_request_t : std::uint8_t {

    /** Carry on: finish the handshake, or do nothing because it is finished. */
    proceed_k,

    /** Produce a close record and shut this side's sending direction. */
    close_k,
};

/**
 *  @brief What the tunnel needs next, as a direction rather than a byte count to decode.
 *
 *  Both the machine's resting place and the caller's instruction, because every value is
 *  simultaneously somewhere the machine stops and something the caller can act on. A verdict that
 *  were not also a state would have to be recomputed on the next call from something else; a state
 *  that were not also a verdict would be unobservable and untestable.
 *
 *  Deliberately absent, each because no caller would act on it differently: a handshaking or
 *  established distinction, since a driver acts on a direction and never on a phase; a closing
 *  state, since after flushing a close you close the descriptor either way; a draining state, since
 *  one outstanding operation per connection leaves nothing to drain; and a rekeying state, since
 *  rekey is scheduled rather than signalled and making it observable would resurrect exactly the
 *  read-that-secretly-needs-a-write problem this layering avoids.
 */
enum class secure_tunnel_state_t : std::uint8_t {

    /**
     *  @brief Nothing has been exchanged yet.
     *
     *  Call @c advance before performing any IO: an initiator receives its first message and
     *  @c transmitting_k, a responder receives @c receiving_k. The only state in which @c advance
     *  may be called before an IO operation, and the reason it exists - an initiator parked in
     *  @c receiving_k would read from a peer that is waiting for it.
     */
    starting_k,

    /** The peer owes bytes. Read, then call @c advance again. Nothing was produced. */
    receiving_k,

    /**
     *  @brief Bytes wait in @c secure_tunnel_step_t::outbound: send them all, then call again.
     *
     *  Says the bytes must go out; it does not say what follows, because what follows is a property
     *  of the tunnel rather than of the message. Ask @c may_seal(): the transport keys become live
     *  on the @b write path, so after the final handshake message they are already usable and a
     *  caller may put its first record in the same write.
     */
    transmitting_k,

    /**
     *  @brief The record layer is live in at least one direction.
     *
     *  @c may_seal() and @c may_open() say which. On first reaching this state, the bytes
     *      @c advance did not consume are the peer's first record, not handshake data.
     */
    ready_k,

    /** Both directions are shut, cleanly. Close the descriptor and report success. */
    closed_k,

    /** Unrecoverable. Close the descriptor and report failure; @c fault() says why. */
    broken_k,
};

/** Names a state for a log. */
[[nodiscard]] inline char const* secure_tunnel_state_name(secure_tunnel_state_t state) noexcept {
    switch (state) {
    case secure_tunnel_state_t::starting_k: return "starting";
    case secure_tunnel_state_t::receiving_k: return "receiving";
    case secure_tunnel_state_t::transmitting_k: return "transmitting";
    case secure_tunnel_state_t::ready_k: return "ready";
    case secure_tunnel_state_t::closed_k: return "closed";
    case secure_tunnel_state_t::broken_k: return "broken";
    }
    return "unknown";
}

/** Lets <tt>{}</tt> print a state by name. */
[[nodiscard]] inline auto format_as(secure_tunnel_state_t value) noexcept { return secure_tunnel_state_name(value); }

/**
 *  @brief Why an operation failed, so a log can tell a bad key from an attack.
 *
 *  One failure code for every cause makes "your configuration is wrong" and "the peer forged a tag"
 *  the same line in the logs, and they call for opposite responses.
 */
enum class secure_tunnel_fault_t : std::uint8_t {

    /** Nothing has failed. */
    none_k,

    /** Configuration is wrong - a missing key, or a pattern this build does not carry. */
    misconfigured_k,

    /** A length, a kind byte, or a record shape the wire format does not allow. */
    malformed_k,

    /** A tag did not verify. Treat as hostile. */
    authentication_failed_k,

    /** The message counter reached the value the specification reserves for rekeying. */
    keys_exhausted_k,

    /** The operating system refused entropy, so no ephemeral key could be drawn. */
    entropy_unavailable_k,
};

/** Names a fault for a log, including when no tunnel was ever built. */
[[nodiscard]] inline char const* secure_tunnel_fault_name(secure_tunnel_fault_t fault) noexcept {
    switch (fault) {
    case secure_tunnel_fault_t::none_k: return "none";
    case secure_tunnel_fault_t::misconfigured_k: return "misconfigured";
    case secure_tunnel_fault_t::malformed_k: return "malformed";
    case secure_tunnel_fault_t::authentication_failed_k: return "authentication_failed";
    case secure_tunnel_fault_t::keys_exhausted_k: return "keys_exhausted";
    case secure_tunnel_fault_t::entropy_unavailable_k: return "entropy_unavailable";
    }
    return "unknown";
}

/** Lets <tt>{}</tt> print a fault by name. */
[[nodiscard]] inline auto format_as(secure_tunnel_fault_t value) noexcept { return secure_tunnel_fault_name(value); }

/**
 *  @brief What a record carries, from the byte sealed inside its authenticated encryption.
 *
 *  Named for records rather than messages, because a message in a tunnel is what @c advance writes
 *  during a handshake, and the two are framed alike but mean nothing alike.
 *
 *  Two kinds, not three: an enumerator with no implementation is a case nobody can write, where an
 *  unhandled one arriving later is a compiler warning. The values are pinned, being on the wire.
 *
 *  A clean close is a sealed record of this kind carrying no payload. A truncation is its absence -
 *  a socket that ends while the tunnel is not closed - which is why no enumerator names it and why
 *  forging one is impossible without the key.
 */
enum class secure_tunnel_record_t : std::uint8_t {

    /** Bytes for the protocol above. The only kind an application can seal. */
    application_k = 0,

    /** The peer will send no more records. Its sending direction is now shut. */
    close_k = 1,
};

#pragma endregion Vocabulary

#pragma region Shape

/**
 *  @brief Width of a Curve25519 key, a SHA-256 digest, and an AES-256 key alike.
 *
 *  One of only three independent numbers in this region. The prefix and the trailer are the other
 *  two; every constant below is arithmetic over them, so none can drift from the wire format or
 *  from what @c secure_tunnel_geometry_t reports for a live connection.
 */
static constexpr std::size_t secure_tunnel_key_size_k = 32;

/** Bytes written ahead of a payload: the big-endian length prefix. */
static constexpr std::size_t secure_tunnel_headroom_k = 2;

/** Bytes written behind it: the record kind, sealed inside the tag that follows it. */
static constexpr std::size_t secure_tunnel_tailroom_k = 1 + 16;

/** What a record adds to its payload. Derived, so it can never disagree with the two. */
static constexpr std::size_t secure_tunnel_overhead_k = secure_tunnel_headroom_k + secure_tunnel_tailroom_k;

/**
 *  @brief Largest payload the wire format can carry, whatever a configuration asks for.
 *
 *  A two-byte length prefix names at most 65535 bytes, and the kind and tag come out of that
 *  budget. This is the ceiling @c secure_tunnel_config_t::max_payload is clamped down to.
 */
static constexpr std::size_t secure_tunnel_payload_ceiling_k = 65535 - secure_tunnel_tailroom_k;

/**
 *  @brief Largest a whole record can ever be, for a caller sizing storage at compile time.
 *
 *  @c secure_tunnel_geometry_t answers the same question exactly for one connection, which is what
 *      a runtime allocation wants. This is for the stack arrays that cannot ask.
 */
static constexpr std::size_t secure_tunnel_max_record_k = secure_tunnel_payload_ceiling_k + secure_tunnel_overhead_k;

/**
 *  @brief How much room this connection needs around a payload, and how much payload it carries.
 *
 *  One value rather than three accessors, because a caller wanting any of these usually wants the
 *  sum. Per connection rather than per mode: the payload cap is policy in every mode - a loopback
 *  bind can afford records a wide-area bind should not - and framing width would vary for a tunnel
 *  that padded records to hide their length.
 */
struct secure_tunnel_geometry_t {

    /** Bytes written ahead of the payload. Zero when the mode frames nothing. */
    std::size_t headroom {};

    /** Bytes written behind it. Zero when the mode frames nothing. */
    std::size_t tailroom {};

    /** Largest payload a single record carries on this connection. */
    std::size_t max_payload {};

    /** Bytes one whole record occupies, which is what a caller must reserve. */
    [[nodiscard]] std::size_t record_size() const noexcept { return headroom + max_payload + tailroom; }
};

#pragma endregion Shape

#pragma region Setup

/** A default record uses the full payload representable by its two-byte wire length. */
static constexpr std::size_t secure_tunnel_default_payload_k = secure_tunnel_payload_ceiling_k;

/**
 *  @brief Draws a fresh static keypair from the operating system's entropy.
 *  @param[out] private_half The secret scalar, which never leaves the process.
 *  @param[out] public_half Its Curve25519 public point, which the peer will see.
 *  @return @c secure_tunnel_fault_t::entropy_unavailable_k when the platform refused entropy, which
 *      must abort rather than proceed with whatever was in the buffer.
 *
 *  Here rather than in a caller because every mode needs one and there is exactly one right way to
 *  make it: real entropy, never a fast pseudo-random generator, and the public half derived rather
 *  than invented. A bind draws one at startup and a client handle draws one per process.
 */
[[nodiscard]] secure_tunnel_fault_t secure_tunnel_generate_keypair(
    span<byte_t, secure_tunnel_key_size_k> private_half, span<byte_t, secure_tunnel_key_size_k> public_half) noexcept;

/**
 *  @brief Everything @c make needs, so a new knob does not re-sign every construction site.
 *
 *  @warning Every pointer here is read during @c make and never retained. A caller may pass a stack
 *      temporary and drop it the moment @c make returns, which is what lets a per-call
 *      configuration be a local rather than something with the connection's lifetime.
 */
struct secure_tunnel_config_t {

    secure_tunnel_mode_t mode {secure_tunnel_mode_t::plain_k};

    /** Per connection, unlike the keys, which a whole bind shares. */
    secure_tunnel_role_t role {secure_tunnel_role_t::responder_k};

    /**
     *  @brief Local static secret. Required in every mode and both roles.
     *
     *  Not optional anywhere, despite @c XX authenticating both sides only during the handshake:
     *  all three patterns either transmit this side's static key or perform a Diffie-Hellman
     *  against it, in both roles, so an absent one would silently become a scalar of zeros.
     *
     *  @note Spans rather than bare pointers throughout this struct.
     *
     *  A member cannot carry a fixed extent the way a parameter can, so a pointer would make the
     *  width an assumption no one could check; a span of the wrong width is @c misconfigured_k
     *  instead of silent memory the tunnel reads past. Empty means absent, so no separate flag can
     *  disagree with the bytes beside it.
     */
    span<byte_t const> local_private {};

    /**
     *  @brief Public half of @c local_private, derived once when the bind was configured.
     *
     *  Supplying it is not an optimisation. Leaving it empty makes @c make derive it, which puts a
     *  Curve25519 base-point ladder - order 100'000 cycles - inside the accept completion, on the
     *  thread servicing every other connection on the bind, recomputing one answer per connection.
     */
    span<byte_t const> local_public {};

    /**
     *  @brief The peer's static public key, or empty.
     *
     *  Required by @c IK on the initiator and by @c KK on both sides, because those patterns fold
     *  it into the transcript before the first message. Learned from the wire in @c XX.
     */
    span<byte_t const> peer_public {};

    /**
     *  @brief Largest payload one record may carry, or zero for @c secure_tunnel_default_payload_k.
     *
     *  Clamped downwards to @c secure_tunnel_payload_ceiling_k, never upwards, so asking for more
     *  than the wire format allows yields the wire format's answer rather than a failure. Set it
     *  small in a test and the fragmentation path becomes reachable without a large message.
     */
    std::size_t max_payload {};
};

#pragma endregion Setup

#pragma region Results

/**
 *  @brief One step of the pump: what it produced, what it cost, and where the machine is.
 *
 *  @note @c state mirrors @c secure_tunnel_t::state() after the call. Here that is not a second
 *      authority but the return value's entire purpose - the driver switches on it.
 */
struct secure_tunnel_step_t {

    /**
     *  @brief Bytes to transmit. Non-empty only on @c transmitting_k and a closing @c closed_k.
     *
     *  A view into the tunnel's own outbound buffer, valid until the next call on this tunnel -
     *  which is exactly the window in which the caller is already obliged to send it. The lifetime
     *  rule and the protocol rule are the same sentence.
     */
    span<byte_t const> outbound {};

    /** Leading bytes of the inbound buffer absorbed. The caller must drop exactly these. */
    std::size_t consumed {};

    secure_tunnel_state_t state {secure_tunnel_state_t::starting_k};
};

/**
 *  @brief What opening one record produced: a window into the caller's own buffer, and its cost.
 *
 *  Returned by value rather than filled through an out-parameter, because it is three fields of
 *  which two are views - light enough that a reference would buy nothing and would make @c open the
 *  only call in this header that does not simply hand back its result.
 *
 *  @c consumed is zero if and only if the record could not be opened, with @c fault() saying why.
 *      That is the same idiom @c seal uses, and it is unambiguous in a way an empty @c payload
 *      would not be: a close record legitimately carries no payload, while a record that opened at
 *      all consumed at least its own framing.
 *
 *  Carries no state of its own. A peer's close leaves the tunnel @c ready_k with @c may_open()
 *  false, so a caller must read @c kind regardless, and a mirrored state field would be a second
 *  authority that says nothing the first does not.
 */
struct secure_tunnel_opened_t {

    /** The plaintext: a window into the destination handed in,
     *  or into the record when nothing is framed. */
    span<byte_t> payload {};

    /** Bytes of the record buffer absorbed, framing included. Zero means nothing opened. */
    std::size_t consumed {};

    secure_tunnel_record_t kind {secure_tunnel_record_t::application_k};
};

#pragma endregion Results

} // namespace unum::ucall::tunnel
