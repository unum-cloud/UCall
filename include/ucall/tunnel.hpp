/**
 *  @file include/ucall/tunnel.hpp
 *  @author Ash Vardanian
 *  @date August 9, 2026
 *  @brief Capability-specialized Noise handshakes and authenticated records, independent of I/O.
 */
#pragma once

#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <cstring>

#if defined(__linux__)
#include <sys/random.h>
#elif defined(_WIN32)
#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#endif

#include <new>

#include <stringzilla/capabilities.h>
#include <stringzilla/hash/serial.h>
#include <stringzilla/cipher/serial.h>
#if STRINGZILLA_TARGET_NEONSHA
#include <stringzilla/hash/neonsha.h>
#endif
#if STRINGZILLA_TARGET_GOLDMONT
#include <stringzilla/hash/goldmont.h>
#endif
#if STRINGZILLA_TARGET_NEONAES
#include <stringzilla/cipher/neonaes.h>
#endif
#if STRINGZILLA_TARGET_WESTMERE
#include <stringzilla/cipher/westmere.h>
#endif

#if STRINGZILLA_TARGET_ICELAKE
#include <stringzilla/cipher/icelake.h>
#endif
#if STRINGZILLA_TARGET_SVE2AES
#include <stringzilla/cipher/sve2aes.h>
#endif

#include "ucall/curve25519.hpp"
#include "ucall/types.hpp"

namespace unum::ucall {

#pragma region Cipher Kits

/** Portable scalar SHA-256, the floor of its ladder. */
struct serial_sha256_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_serial_k;
    static constexpr bool compiled_k = true;
    static constexpr auto init = sz_sha256_state_init_serial;
    static constexpr auto update = sz_sha256_state_update_serial;
    static constexpr auto digest = sz_sha256_state_digest_serial;
};

/** Portable scalar AES-256-GCM, the floor of its ladder. */
struct serial_aes256_gcm_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_serial_k;
    static constexpr bool compiled_k = true;
    static constexpr auto key_init = sz_aes256_gcm_key_init_serial;
    static constexpr auto encrypt = sz_aes256_gcm_encrypt_serial;
    static constexpr auto decrypt = sz_aes256_gcm_decrypt_serial;
};

#if STRINGZILLA_TARGET_NEONSHA

/** Arm NEON with the SHA-2 extension. */
struct neonsha_sha256_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_neonsha_k;
    static constexpr bool compiled_k = true;
    static constexpr auto init = sz_sha256_state_init_neonsha;
    static constexpr auto update = sz_sha256_state_update_neonsha;
    static constexpr auto digest = sz_sha256_state_digest_neonsha;
};
#else

/** The kit this build cannot carry, kept so the ladder stays one list. */
struct neonsha_sha256_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_neonsha_k;
    static constexpr bool compiled_k = false;
};
#endif // STRINGZILLA_TARGET_NEONSHA

#if STRINGZILLA_TARGET_GOLDMONT

/** Intel Goldmont SHA-NI. */
struct goldmont_sha256_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_goldmont_k;
    static constexpr bool compiled_k = true;
    static constexpr auto init = sz_sha256_state_init_goldmont;
    static constexpr auto update = sz_sha256_state_update_goldmont;
    static constexpr auto digest = sz_sha256_state_digest_goldmont;
};
#else

/** The kit this build cannot carry, kept so the ladder stays one list. */
struct goldmont_sha256_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_goldmont_k;
    static constexpr bool compiled_k = false;
};
#endif // STRINGZILLA_TARGET_GOLDMONT

#if STRINGZILLA_TARGET_SVE2AES

/** Arm SVE2 with the AES extension. */
struct sve2aes_aes256_gcm_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_sve2aes_k;
    static constexpr bool compiled_k = true;
    static constexpr auto key_init = sz_aes256_gcm_key_init_sve2aes;
    static constexpr auto encrypt = sz_aes256_gcm_encrypt_sve2aes;
    static constexpr auto decrypt = sz_aes256_gcm_decrypt_sve2aes;
};
#else

/** The kit this build cannot carry, kept so the ladder stays one list. */
struct sve2aes_aes256_gcm_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_sve2aes_k;
    static constexpr bool compiled_k = false;
};
#endif // STRINGZILLA_TARGET_SVE2AES

#if STRINGZILLA_TARGET_ICELAKE

/** Intel Ice Lake with VAES and VPCLMULQDQ. */
struct icelake_aes256_gcm_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_icelake_k;
    static constexpr bool compiled_k = true;
    static constexpr auto key_init = sz_aes256_gcm_key_init_icelake;
    static constexpr auto encrypt = sz_aes256_gcm_encrypt_icelake;
    static constexpr auto decrypt = sz_aes256_gcm_decrypt_icelake;
};
#else

/** The kit this build cannot carry, kept so the ladder stays one list. */
struct icelake_aes256_gcm_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_icelake_k;
    static constexpr bool compiled_k = false;
};
#endif // STRINGZILLA_TARGET_ICELAKE

#if STRINGZILLA_TARGET_NEONAES

/** Arm NEON with the AES extension. */
struct neonaes_aes256_gcm_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_neonaes_k;
    static constexpr bool compiled_k = true;
    static constexpr auto key_init = sz_aes256_gcm_key_init_neonaes;
    static constexpr auto encrypt = sz_aes256_gcm_encrypt_neonaes;
    static constexpr auto decrypt = sz_aes256_gcm_decrypt_neonaes;
};
#else

/** The kit this build cannot carry, kept so the ladder stays one list. */
struct neonaes_aes256_gcm_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_neonaes_k;
    static constexpr bool compiled_k = false;
};
#endif // STRINGZILLA_TARGET_NEONAES

#if STRINGZILLA_TARGET_WESTMERE

/** Intel Westmere AES-NI with carry-less multiplication. */
struct westmere_aes256_gcm_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_westmere_k;
    static constexpr bool compiled_k = true;
    static constexpr auto key_init = sz_aes256_gcm_key_init_westmere;
    static constexpr auto encrypt = sz_aes256_gcm_encrypt_westmere;
    static constexpr auto decrypt = sz_aes256_gcm_decrypt_westmere;
};
#else

/** The kit this build cannot carry, kept so the ladder stays one list. */
struct westmere_aes256_gcm_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_westmere_k;
    static constexpr bool compiled_k = false;
};
#endif // STRINGZILLA_TARGET_WESTMERE

/** The widest SHA-256 kit among the backends @p caps_ admits, newest first. */
template <sz_capability_t caps_>
using sha256_kit = typename highest_kit<caps_, serial_sha256_kit_t, neonsha_sha256_kit_t, goldmont_sha256_kit_t>::type;

/** The widest AES-256-GCM kit among the backends @p caps_ admits, newest first. */
template <sz_capability_t caps_>
using aes256_gcm_kit =
    typename highest_kit<caps_, serial_aes256_gcm_kit_t, sve2aes_aes256_gcm_kit_t, icelake_aes256_gcm_kit_t,
                         neonaes_aes256_gcm_kit_t, westmere_aes256_gcm_kit_t>::type;

#pragma endregion Cipher Kits

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

/** Lets `{}` print a mode by name. */
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
 *  it, fall back to @c XXfallback - at which point the roles no longer divide the way they started.
 *  A third enumerator absorbs that; a @c bool cannot.
 */
enum class secure_tunnel_role_t : std::uint8_t { initiator_k, responder_k };

/** Names a role for a log, alongside the mode. */
[[nodiscard]] inline char const* secure_tunnel_role_name(secure_tunnel_role_t role) noexcept {
    return role == secure_tunnel_role_t::initiator_k ? "initiator" : "responder";
}

/** Lets `{}` print a role by name. */
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
     *  @brief Bytes are waiting in @c secure_tunnel_step_t::outbound. Send them all, then call
     *      again.
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

/** Lets `{}` print a state by name. */
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

/** Lets `{}` print a fault by name. */
[[nodiscard]] inline auto format_as(secure_tunnel_fault_t value) noexcept { return secure_tunnel_fault_name(value); }

/**
 *  @brief What a record carries, from the byte sealed inside its authenticated encryption.
 *
 *  Named for records rather than messages, because a message in this file is what @c advance writes
 *  during a handshake, and the two are framed alike but mean nothing alike.
 *
 *  Two kinds, not three: an enumerator with no implementation is a case nobody can write, where an
 *  unhandled one arriving later is a compiler warning. The values are pinned because they are on
 *  the wire.
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
 *  @return False when the platform refused entropy, which must abort rather than proceed with
 *      whatever was in the buffer.
 *
 *  Here rather than in a caller because every mode needs one and there is exactly one right way to
 *  make it: real entropy, never a fast pseudo-random generator, and the public half derived rather
 *  than invented. A bind draws one at startup and a client handle draws one per process.
 */
[[nodiscard]] bool secure_tunnel_generate_keypair(byte_t private_half[secure_tunnel_key_size_k],
                                                  byte_t public_half[secure_tunnel_key_size_k]) noexcept;

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
     *  @note Spans rather than bare pointers throughout this struct. A member cannot carry a fixed
     *      extent the way a parameter can, so a pointer would make the width an assumption no one
     *      could check; a span of the wrong width is @c misconfigured_k instead of silent memory
     *      the tunnel reads past. Empty means absent, so no separate flag can disagree with the
     *      bytes beside it.
     */
    span<byte_t const> local_private {};

    /**
     *  @brief Public half of @c local_private, derived once when the bind was configured.
     *
     *  Supplying it is not an optimisation. Leaving it empty makes @c make derive it, which puts a
     *  Curve25519 base-point ladder - order 100'000 cycles - inside the accept completion, on the
     *  thread servicing every other connection on the bind, to recompute the same answer for every
     *  connection.
     */
    span<byte_t const> local_public {};

    /**
     *  @brief The peer's static public key, or empty.
     *
     *  Required by @c IK on the initiator and by @c KK on both sides, because those patterns fold
     *  it into the transcript before the first message. Learned from the wire in @c XX.
     */
    span<byte_t const> remote_public {};

    /**
     *  @brief Largest payload one record may carry, or zero for @c secure_tunnel_default_payload_k.
     *
     *  Clamped downwards to @c secure_tunnel_payload_ceiling_k, never upwards, so asking for more
     *  than the wire format allows yields the wire format's answer rather than a failure. Set it
     *  small in a test and the fragmentation path becomes reachable without manufacturing a large
     *  message.
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

    /** The plaintext, uncovered in place: a window into the record buffer handed in. */
    span<byte_t> payload {};

    /** Bytes of the record buffer absorbed, framing included. Zero means nothing opened. */
    std::size_t consumed {};

    secure_tunnel_record_t kind {secure_tunnel_record_t::application_k};
};

#pragma endregion Results

#pragma region Tunnel

/** Cryptographic primitives and pattern state specialized for the admitted instruction set. */
template <sz_capability_t capabilities_>
struct secure_tunnel_crypto {
    using sha256_kit_t = sha256_kit<capabilities_>;
    using aes256_gcm_kit_t = aes256_gcm_kit<capabilities_>;

    static constexpr auto sha_init = sha256_kit_t::init;
    static constexpr auto sha_update = sha256_kit_t::update;
    static constexpr auto sha_digest = sha256_kit_t::digest;
    static constexpr auto aes_init = aes256_gcm_kit_t::key_init;
    static constexpr auto aes_encrypt = aes256_gcm_kit_t::encrypt;
    static constexpr auto aes_decrypt = aes256_gcm_kit_t::decrypt;

#pragma region Wire Constants

    /**
     *  @brief Output width of SHA-256, and therefore of every chaining value and derived key.
     *
     *  Defined in terms of the key width because this cipher suite pins both to thirty-two, not
     *  because a digest and a key are the same thing. A suite with a wider hash would break the
     *  equality, and this is the line that would have to say so.
     */
    static constexpr std::size_t hash_size_k = secure_tunnel_key_size_k;

    /** Width of an AES-GCM authentication tag. */
    static constexpr std::size_t tag_size_k = 16;

    /** The record kind, sealed one byte behind the payload and inside the tag. */
    static constexpr std::size_t kind_size_k = 1;

    /** Width of the big-endian length that prefixes every message on the wire. */
    static constexpr std::size_t prefix_size_k = secure_tunnel_headroom_k;

    /** Hard ceiling a two-byte prefix can name, and the specification's message limit besides. */
    static constexpr std::size_t max_message_k = 65535;

    /**
     *  @brief Shortest a record's declared length may be: an empty payload, its kind, and the tag.
     *
     *  Accepting anything smaller lets a peer declare a length that decrypts to nothing, after
     *  which reading the kind byte behind a zero-length plaintext reads outside the buffer. The
     *  kind byte is what makes this seventeen rather than sixteen.
     */
    static constexpr std::size_t min_record_body_k = tag_size_k + kind_size_k;

    /** Width of the AES-GCM nonce: 32 zero bits ahead of the 64-bit counter. */
    static constexpr std::size_t nonce_size_k = 12;

    /**
     *  @brief The counter value the specification reserves for @c Rekey.
     *
     *  Reaching it means the key is exhausted, and encrypting under it would collide with the rekey
     *  derivation. Both directions refuse rather than wrap.
     */
    static constexpr std::uint64_t nonce_exhausted_k = ~static_cast<std::uint64_t>(0);

    /**
     *  @brief Records sealed or opened under one key before it is replaced.
     *
     *  AES-GCM's forgery margin degrades with the volume encrypted under a single key, which is why
     *  TLS 1.3 caps AES-GCM at roughly 2^24.5 records. At 16 KB a record this is a few gigabytes,
     *  comfortably inside the bound, and it needs no signalling because both sides count
     *  identically.
     *
     *  @warning The two sides stay in step only if every sealed record is also opened, the close
     *      record included. Anything that seals without the peer opening - or opens without the
     *      peer having sealed - desynchronises the two schedules, after which every subsequent
     *      record fails authentication with nothing in the logs to explain it.
     */
    static constexpr std::size_t rekey_interval_k = 1u << 20;

    /** A handshake message can fill the wire format's entire uint16 length. */
    static constexpr std::size_t max_handshake_payload_k = max_message_k;

    /**
     *  @brief Bytes reserved inside the connection's storage for what @c advance generates.
     *
     *  The widest handshake message any supported pattern writes carries an ephemeral in the clear,
     *  a static under the AEAD, and the empty payload's tag - ninety-eight bytes with its prefix. A
     *  close record's nineteen fit easily inside the same buffer, and the two are never live at
     *  once because a close cannot be requested before the handshake completes.
     *
     */
    static constexpr std::size_t outbound_capacity_k = prefix_size_k + 2 * secure_tunnel_key_size_k + 2 * tag_size_k;

#pragma endregion Wire Constants

#pragma region Secrets

    /**
     *  @brief Overwrites secret bytes so that dead-store elimination cannot remove the write.
     *
     *  Every key, chaining value, and shared secret below is wiped on storage that dies immediately
     *  afterwards, which makes a plain @c memset a dead store the compiler may legally delete.
     *  Writing through a volatile pointer is what keeps it.
     */
    static void secure_zero(void* data, std::size_t length) noexcept {
        auto volatile* cursor = static_cast<byte_t volatile*>(data);
        for (std::size_t index = 0; index != length; ++index) cursor[index] = byte_t {};
    }

    /**
     *  @brief Wipes a whole object or array, taking its width from the type.
     *
     *  One overload covers a fixed-width key, a key schedule, and a table of derived outputs alike,
     *  which is why no separate span-over-an-array helper exists: the width a caller would have had
     *  to spell is the width the compiler already knows.
     */
    template <typename secret_type_>
    static void secure_zero(secret_type_& secret) noexcept {
        secure_zero(&secret, sizeof(secret));
    }

    /**
     *  @brief Fills @p output with bytes from the operating system's cryptographic generator.
     *  @return False when the platform refused, which must abort key generation rather than
     *      continue.
     *
     *  @warning Never substitute a fast pseudo-random generator here. StringZilla's
     *      @c sz_fill_random is an AES-based hash - excellent for buffers, and fatal for keys.
     */
    [[nodiscard]] static bool secure_random_bytes(byte_t* output, std::size_t length) noexcept {
#if UCALL_OS_LINUX_
        while (length) {
            ssize_t const taken = ::getrandom(output, length, 0);
            if (taken < 0 && errno == EINTR) continue;
            if (taken <= 0) return false;
            output += taken;
            length -= static_cast<std::size_t>(taken);
        }
        return true;
#elif UCALL_OS_WINDOWS_
        return BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(output), static_cast<ULONG>(length),
                               BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
        arc4random_buf(output, length);
        return true;
#endif
    }

#pragma endregion Secrets

    /**
     *  @brief Reads the big-endian length that prefixes every message on the wire.
     *  @return Zero when the prefix has not fully arrived, which every caller already rejects as a
     *      length too short to hold even a tag.
     */
    [[nodiscard]] static std::size_t peek_length(span<byte_t const> input) noexcept {
        if (input.size() < prefix_size_k) return 0;
        return (static_cast<std::size_t>(input[0]) << 8) | static_cast<std::size_t>(input[1]);
    }

    static void poke_length(byte_t* output, std::size_t length) noexcept {
        assert(length <= max_message_k && "a length prefix names at most sixty-five thousand bytes");
        output[0] = static_cast<byte_t>((length >> 8) & 0xFFu);
        output[1] = static_cast<byte_t>(length & 0xFFu);
    }

    /** Bytes still needed before @p received holds one whole prefixed message. */
    [[nodiscard]] static std::size_t bytes_until_prefixed_boundary(span<byte_t const> received) noexcept {
        if (received.size() < prefix_size_k) return prefix_size_k - received.size();
        std::size_t const whole = prefix_size_k + peek_length(received);
        return received.size() >= whole ? 0 : whole - received.size();
    }

#pragma region HMAC and HKDF

    /**
     *  @brief HMAC-SHA256 with both padded key states cached, per RFC 2104.
     *
     *  Noise derives keys two or three times per @c MixKey under the same key, so absorbing the
     *  inner and outer padding once and copying the midstates is worth the twelve lines. That
     *  @c sz_sha256_state_t is a transparent, trivially copyable struct is what makes it possible
     *  without StringZilla exporting anything extra.
     */
    class hmac_sha256_t {

        /**
         *  @brief SHA-256's compression block, which RFC 2104 calls @c B.
         *
         *  Not a tuning knob. The padding constants are repeated exactly this many times and the
         *  key is zero-extended to exactly this width, so any other value computes something that
         *  is not HMAC. Distinct from the 32-byte digest, and confusing the two is the classic way
         *  to produce a tag that looks well-formed and interoperates with nobody - which is what
         *  the RFC 4231 vectors in `test/noise.cpp` exist to catch.
         */
        static constexpr std::size_t block_size_k = 64;

        sz_sha256_state_t inner_ {};
        sz_sha256_state_t outer_ {};

      public:
        void reset(span<byte_t const> key) noexcept {
            byte_t padded[block_size_k] {};
            if (key.size() > block_size_k) {
                sz_sha256_state_t shrink;
                sha_init(&shrink, nullptr);
                sha_update(&shrink, reinterpret_cast<sz_cptr_t>(key.data()), key.size(), nullptr);
                sha_digest(&shrink, reinterpret_cast<sz_u8_t*>(padded), nullptr);
            }
            else if (key.size()) { std::memcpy(padded, key.data(), key.size()); }

            byte_t block[block_size_k];
            sha_init(&inner_, nullptr);
            for (std::size_t index = 0; index != block_size_k; ++index) block[index] = padded[index] ^ byte_t { 0x36 };
            sha_update(&inner_, reinterpret_cast<sz_cptr_t>(block), block_size_k, nullptr);

            sha_init(&outer_, nullptr);
            for (std::size_t index = 0; index != block_size_k; ++index) block[index] = padded[index] ^ byte_t { 0x5C };
            sha_update(&outer_, reinterpret_cast<sz_cptr_t>(block), block_size_k, nullptr);

            secure_zero(padded);
            secure_zero(block);
        }

        /** Computes the tag over one or two concatenated inputs, reusing both midstates. */
        void compute(span<byte_t const> first, span<byte_t const> second, byte_t output[hash_size_k]) const noexcept {
            sz_sha256_state_t inner = inner_;
            if (first.size()) sha_update(&inner, reinterpret_cast<sz_cptr_t>(first.data()), first.size(), nullptr);
            if (second.size()) sha_update(&inner, reinterpret_cast<sz_cptr_t>(second.data()), second.size(), nullptr);
            byte_t digest[hash_size_k];
            sha_digest(&inner, reinterpret_cast<sz_u8_t*>(digest), nullptr);

            sz_sha256_state_t outer = outer_;
            sha_update(&outer, reinterpret_cast<sz_cptr_t>(digest), sizeof(digest), nullptr);
            sha_digest(&outer, reinterpret_cast<sz_u8_t*>(output), nullptr);
            secure_zero(digest);
        }
    };

    /** One-shot HMAC-SHA256, for callers with no key to reuse. */
    static void hmac_sha256(span<byte_t const> key, span<byte_t const> data, byte_t output[hash_size_k]) noexcept {
        hmac_sha256_t hmac;
        hmac.reset(key);
        hmac.compute(data, {}, output);
    }

    /**
     *  @brief The Noise specification's HKDF, which is RFC 5869 with an empty info string.
     *  @param[in] outputs How many 32-byte outputs to derive: two, or three for a pattern with a
     *      pre-shared key. Each feeds the next, so they must be produced in order.
     */
    static void hkdf_sha256(span<byte_t const> chaining_key, span<byte_t const> material, std::size_t outputs,
                            byte_t results[3][hash_size_k]) noexcept {
        byte_t temporary_key[hash_size_k];
        hmac_sha256(chaining_key, material, temporary_key);

        hmac_sha256_t hmac;
        hmac.reset({temporary_key, temporary_key + hash_size_k});

        byte_t const counters[3] {byte_t {0x01}, byte_t {0x02}, byte_t {0x03}};
        hmac.compute({counters, counters + 1}, {}, results[0]);
        hmac.compute({results[0], results[0] + hash_size_k}, {counters + 1, counters + 2}, results[1]);
        if (outputs > 2) hmac.compute({results[1], results[1] + hash_size_k}, {counters + 2, counters + 3}, results[2]);
        secure_zero(temporary_key);
    }

#pragma endregion HMAC and HKDF

#pragma region Cipher State

    /** One AEAD key with its message counter, per the specification's CipherState. */
    class secure_tunnel_cipher_t {

        sz_aes256_gcm_key_t schedule_ {};
        byte_t key_[secure_tunnel_key_size_k] {};
        std::uint64_t nonce_ {};
        bool keyed_ {};

        /** Noise encodes the 96-bit nonce as 32 zero bits then the counter, big-endian. */
        void encode_nonce(byte_t output[nonce_size_k]) const noexcept {
            std::memset(output, 0, 4);
            for (std::size_t index = 0; index != 8; ++index)
                output[4 + index] = static_cast<byte_t>(nonce_ >> (56 - 8 * index));
        }

      public:
        [[nodiscard]] bool has_key() const noexcept { return keyed_; }

        /** True once this key has sealed or opened everything it may, and must be replaced. */
        [[nodiscard]] bool exhausted() const noexcept { return keyed_ && nonce_ == nonce_exhausted_k; }

        void initialize(byte_t const key[secure_tunnel_key_size_k]) noexcept {
            std::memcpy(key_, key, secure_tunnel_key_size_k);
            aes_init(&schedule_, reinterpret_cast<sz_u8_t const*>(key_), nullptr);
            nonce_ = 0;
            keyed_ = true;
        }

        void clear() noexcept {
            secure_zero(schedule_);
            secure_zero(key_);
            nonce_ = 0;
            keyed_ = false;
        }

        /**
         *  @brief Seals @p plaintext in place and appends a tag behind it.
         *  @param[inout] text The bytes to seal, which the ciphertext replaces.
         *  @param[out] tag Sixteen bytes immediately behind @p text, written on success.
         *  @return False when the key is exhausted.
         *
         *  Before the first @c MixKey the state has no key and the specification says plaintext
         *  passes through untouched with no tag, which is how a handshake's opening message stays
         *  readable. A caller learns which happened from @c has_key rather than from a length it
         *  must compare.
         */
        [[nodiscard]] bool seal(span<byte_t const> associated, span<byte_t> text, byte_t* tag) noexcept {
            if (!keyed_) return true;
            if (exhausted()) return false;
            byte_t nonce[nonce_size_k];
            encode_nonce(nonce);
            aes_encrypt(&schedule_, reinterpret_cast<sz_u8_t const*>(nonce),               //
                        reinterpret_cast<sz_cptr_t>(associated.data()), associated.size(), //
                        reinterpret_cast<sz_cptr_t>(text.data()), text.size(),             //
                        reinterpret_cast<sz_ptr_t>(text.data()), reinterpret_cast<sz_u8_t*>(tag), nullptr);
            ++nonce_;
            secure_zero(nonce);
            return true;
        }

        /**
         *  @brief Verifies a tag and opens @p text in place.
         *  @param[inout] text The ciphertext body, without its tag, which the plaintext replaces.
         *  @param[in] tag Sixteen bytes immediately behind @p text.
         *  @return False when the tag does not verify or the key is exhausted, which closes the
         *      connection either way.
         *
         *  @warning StringZilla zeroes @p text when the tag is rejected rather than leaving
         *      unauthenticated plaintext behind, so a caller that ignores the result still cannot
         *      act on forged data - and cannot retry, which suits a caller that drops the
         *      connection anyway.
         */
        [[nodiscard]] bool open(span<byte_t const> associated, span<byte_t> text, byte_t const* tag) noexcept {
            if (!keyed_) return true;
            if (exhausted()) return false;
            byte_t nonce[nonce_size_k];
            encode_nonce(nonce);
            sz_status_t const status = aes_decrypt(&schedule_, reinterpret_cast<sz_u8_t const*>(nonce),               //
                                                   reinterpret_cast<sz_cptr_t>(associated.data()), associated.size(), //
                                                   reinterpret_cast<sz_cptr_t>(text.data()), text.size(),             //
                                                   reinterpret_cast<sz_ptr_t>(text.data()),
                                                   reinterpret_cast<sz_u8_t const*>(tag), nullptr);
            secure_zero(nonce);
            if (status != sz_success_k) return false;
            ++nonce_;
            return true;
        }

        /**
         *  @brief Replaces the key with one derived from it, per the specification's Rekey.
         *
         *  The counter deliberately survives, because Noise defines @c Rekey as changing the key
         *  without resetting @c n - which is what keeps a nonce from repeating across the boundary.
         */
        void rekey() noexcept {
            if (!keyed_) return;
            byte_t const zeros[secure_tunnel_key_size_k] {};
            byte_t derived[secure_tunnel_key_size_k];
            byte_t tag[tag_size_k];
            byte_t nonce[nonce_size_k];
            std::memset(nonce, 0, 4);
            std::memset(nonce + 4, 0xFF, 8); // the specification's maximum nonce
            aes_encrypt(&schedule_, reinterpret_cast<sz_u8_t const*>(nonce), nullptr, 0,
                        reinterpret_cast<sz_cptr_t>(zeros), sizeof(zeros), reinterpret_cast<sz_ptr_t>(derived),
                        reinterpret_cast<sz_u8_t*>(tag), nullptr);

            std::uint64_t const preserved = nonce_;
            initialize(derived);
            nonce_ = preserved;
            secure_zero(derived);
            secure_zero(tag);
            secure_zero(nonce);
        }
    };

#pragma endregion Cipher State

#pragma region Transcript

    /**
     *  @brief The chaining key, the running hash, and the mixing rules over both.
     *
     *  What the specification calls @c SymmetricState. Named for what it accumulates: every key and
     *  every byte either side has sent enters here, and the two sides agreeing on it at the end is
     *  precisely what authenticates the handshake.
     */
    class secure_tunnel_transcript_t {

        byte_t chaining_key_[hash_size_k] {};
        byte_t hash_[hash_size_k] {};
        secure_tunnel_cipher_t cipher_ {};

      public:
        [[nodiscard]] secure_tunnel_cipher_t& cipher() noexcept { return cipher_; }
        [[nodiscard]] span<byte_t const> hash() const noexcept { return {hash_, hash_ + hash_size_k}; }

        void initialize(char const* protocol_name, std::size_t name_length) noexcept {
            if (name_length <= hash_size_k) {
                std::memset(hash_, 0, hash_size_k);
                std::memcpy(hash_, protocol_name, name_length);
            }
            else {
                sz_sha256_state_t state;
                sha_init(&state, nullptr);
                sha_update(&state, protocol_name, name_length, nullptr);
                sha_digest(&state, reinterpret_cast<sz_u8_t*>(hash_), nullptr);
            }
            std::memcpy(chaining_key_, hash_, hash_size_k);
            cipher_.clear();
        }

        void mix_hash(span<byte_t const> data) noexcept {
            sz_sha256_state_t state;
            sha_init(&state, nullptr);
            sha_update(&state, reinterpret_cast<sz_cptr_t>(hash_), hash_size_k, nullptr);
            if (data.size()) sha_update(&state, reinterpret_cast<sz_cptr_t>(data.data()), data.size(), nullptr);
            sha_digest(&state, reinterpret_cast<sz_u8_t*>(hash_), nullptr);
        }

        void mix_key(byte_t const material[secure_tunnel_key_size_k]) noexcept {
            byte_t derived[3][hash_size_k];
            hkdf_sha256({chaining_key_, chaining_key_ + hash_size_k}, {material, material + secure_tunnel_key_size_k},
                        2, derived);
            std::memcpy(chaining_key_, derived[0], hash_size_k);
            cipher_.initialize(derived[1]);
            secure_zero(derived);
        }

        /**
         *  @brief Seals in place with the running hash as associated data, then absorbs the result.
         *  @param[out] written Bytes now occupying @p text and what follows: its width, plus a tag
         *      once a key exists - so zero is a legitimate answer for an empty payload before the
         *      first @c MixKey, and is why this reports success separately rather than through the
         *      count.
         */
        [[nodiscard]] bool seal_and_hash(span<byte_t> text, std::size_t& written) noexcept {
            byte_t* const tag = text.data() + text.size();
            if (!cipher_.seal(hash(), text, tag)) return false;
            written = text.size() + (cipher_.has_key() ? tag_size_k : 0);
            mix_hash({text.data(), text.data() + written});
            return true;
        }

        /**
         *  @brief Verifies against the running hash, then absorbs the ciphertext as it arrived.
         *  @param[in] sealed The message field as it came off the wire, tag included.
         *  @param[out] plain Receives the opened bytes, which must not alias @p sealed.
         *
         *  The successor hash is computed before opening, and committed only once the tag verifies,
         *  because the transcript must absorb the ciphertext rather than the plaintext. Deriving it
         *  afterwards from a staged copy would work only up to that copy's width and silently hash
         *  the plaintext beyond it, with the divergence surfacing one message later as an
         *  unexplained authentication failure.
         */
        [[nodiscard]] bool open_and_hash(span<byte_t const> sealed, span<byte_t> plain,
                                         std::size_t& produced) noexcept {
            if (cipher_.has_key() && sealed.size() < tag_size_k) return false;
            std::size_t const body = cipher_.has_key() ? sealed.size() - tag_size_k : sealed.size();
            if (plain.size() < body) return false;

            byte_t next_hash[hash_size_k];
            sz_sha256_state_t state;
            sha_init(&state, nullptr);
            sha_update(&state, reinterpret_cast<sz_cptr_t>(hash_), hash_size_k, nullptr);
            if (sealed.size()) sha_update(&state, reinterpret_cast<sz_cptr_t>(sealed.data()), sealed.size(), nullptr);
            sha_digest(&state, reinterpret_cast<sz_u8_t*>(next_hash), nullptr);

            if (body) std::memcpy(plain.data(), sealed.data(), body);
            if (!cipher_.open(hash(), {plain.data(), plain.data() + body}, sealed.data() + body)) return false;

            std::memcpy(hash_, next_hash, hash_size_k);
            produced = body;
            return true;
        }

        /** Derives the two record-layer keys once the pattern's tokens are exhausted. */
        void split(secure_tunnel_cipher_t& first, secure_tunnel_cipher_t& second) noexcept {
            byte_t derived[3][hash_size_k];
            hkdf_sha256({chaining_key_, chaining_key_ + hash_size_k}, {}, 2, derived);
            first.initialize(derived[0]);
            second.initialize(derived[1]);
            secure_zero(derived);
        }

        /** Wipes the chaining key, the running hash, and the handshake's own AEAD key. */
        void clear() noexcept {
            secure_zero(chaining_key_);
            secure_zero(hash_);
            cipher_.clear();
        }
    };

#pragma endregion Transcript

#pragma region Patterns

    /** The token vocabulary the three supported patterns are built from. */
    enum class secure_tunnel_token_t : std::uint8_t {
        end_k = 0,

        /** Ephemeral public key, sent in the clear. */
        ephemeral_k,

        /** Static public key, sealed once a key exists. */
        static_k,

        /** Diffie-Hellman between the two ephemerals. */
        ephemeral_ephemeral_k,

        /** The initiator's ephemeral against the responder's static. */
        ephemeral_static_k,

        /** The initiator's static against the responder's ephemeral. */
        static_ephemeral_k,

        /** The two statics. */
        static_static_k,
    };

    /**
     *  @brief Which static keys a pattern folds into the transcript before its first message.
     *
     *  One enumerator per configuration rather than two flags: the combinations are a closed set,
     *  and a pair of booleans can express "the initiator's but not the responder's", which no
     *  pattern here defines and no code below could serve.
     */
    enum class secure_tunnel_pre_shared_t : std::uint8_t {

        /** Neither, as @c XX - both sides learn the other's key during the handshake. */
        neither_k,

        /** The responder's only, as @c IK - the initiator must know where it is calling. */
        responder_static_k,

        /** Both, as @c KK - neither side transmits a static key at all. */
        both_statics_k,
    };

    struct secure_tunnel_pattern_t {

        /** Tokens one message may carry, which the longest supported message needs all of. */
        static constexpr std::size_t max_tokens_k = 6;

        /** Messages a pattern may define. Three is XX's count, and the largest of the three. */
        static constexpr std::size_t max_messages_k = 3;

        char const* name;
        secure_tunnel_pre_shared_t pre_shared;
        std::size_t message_count;
        secure_tunnel_token_t messages[max_messages_k][max_tokens_k];

        /** Whether the initiator's static key is in the transcript before any message. */
        [[nodiscard]] bool shares_initiator_static() const noexcept {
            return pre_shared == secure_tunnel_pre_shared_t::both_statics_k;
        }

        /** Whether the responder's is. */
        [[nodiscard]] bool shares_responder_static() const noexcept {
            return pre_shared != secure_tunnel_pre_shared_t::neither_k;
        }
    };

    /**
     *  @brief `XX` - neither side knows the other in advance, and both authenticate during.
     *  @code
     * → e
     * ← e, ee, s, es
     * → s, se
     *  @endcode
     */
    static constexpr secure_tunnel_pattern_t pattern_xx_k {
        "Noise_XX_25519_AESGCM_SHA256",
        secure_tunnel_pre_shared_t::neither_k,
        3,
        {
            {secure_tunnel_token_t::ephemeral_k, secure_tunnel_token_t::end_k},
            {secure_tunnel_token_t::ephemeral_k, secure_tunnel_token_t::ephemeral_ephemeral_k,
             secure_tunnel_token_t::static_k, secure_tunnel_token_t::ephemeral_static_k, secure_tunnel_token_t::end_k},
            {secure_tunnel_token_t::static_k, secure_tunnel_token_t::static_ephemeral_k, secure_tunnel_token_t::end_k},
        },
    };

    /**
     *  @brief `IK` - the initiator already knows the responder's static key.
     *  @code
     * ← s
     * ...
     * → e, es, s, ss
     * ← e, ee, se
     *  @endcode
     */
    static constexpr secure_tunnel_pattern_t pattern_ik_k {
        "Noise_IK_25519_AESGCM_SHA256",
        secure_tunnel_pre_shared_t::responder_static_k,
        2,
        {
            {secure_tunnel_token_t::ephemeral_k, secure_tunnel_token_t::ephemeral_static_k,
             secure_tunnel_token_t::static_k, secure_tunnel_token_t::static_static_k, secure_tunnel_token_t::end_k},
            {secure_tunnel_token_t::ephemeral_k, secure_tunnel_token_t::ephemeral_ephemeral_k,
             secure_tunnel_token_t::static_ephemeral_k, secure_tunnel_token_t::end_k},
        },
    };

    /**
     *  @brief `KK` - both static keys are configured ahead of time, and neither is transmitted.
     *  @code
     * → s
     * ← s
     * ...
     * → e, es, ss
     * ← e, ee, se
     *  @endcode
     *
     *  @note No message carries a @c static_k, so the peer's key is never received and never
     *      promoted by the reading path. It is proven instead by the @c ss and @c es operations,
     *      whose results only agree if the peer holds the private half - which is why the promotion
     *      at @c finish_handshake is load-bearing for this pattern specifically.
     */
    static constexpr secure_tunnel_pattern_t pattern_kk_k {
        "Noise_KK_25519_AESGCM_SHA256",
        secure_tunnel_pre_shared_t::both_statics_k,
        2,
        {
            {secure_tunnel_token_t::ephemeral_k, secure_tunnel_token_t::ephemeral_static_k,
             secure_tunnel_token_t::static_static_k, secure_tunnel_token_t::end_k},
            {secure_tunnel_token_t::ephemeral_k, secure_tunnel_token_t::ephemeral_ephemeral_k,
             secure_tunnel_token_t::static_ephemeral_k, secure_tunnel_token_t::end_k},
        },
    };

    [[nodiscard]] static secure_tunnel_pattern_t const* pattern_for(secure_tunnel_mode_t mode) noexcept {
        switch (mode) {
        case secure_tunnel_mode_t::noise_xx_k: return &pattern_xx_k;
        case secure_tunnel_mode_t::noise_ik_k: return &pattern_ik_k;
        case secure_tunnel_mode_t::noise_kk_k: return &pattern_kk_k;
        case secure_tunnel_mode_t::plain_k: return nullptr;
        }
        return nullptr;
    }

#pragma endregion Patterns

#pragma region Handshake State

    /**
     *  @brief How much is known about the peer's static key, and how much of it can be trusted.
     *
     *  @c IK and @c KK take the peer key from configuration and merely assume it until the
     *      handshake completes; @c XX learns it from the wire and authenticates it there. One flag
     *      conflates the two, and the difference is the whole value of asking who the peer is.
     */
    enum class remote_static_t : std::uint8_t {

        /** Neither configured nor yet received. */
        unknown_k,

        /** Supplied by the application ahead of the handshake, and so far only assumed. */
        configured_k,

        /** Proven during the handshake, by a verified tag or by a Diffie-Hellman that agreed. */
        authenticated_k,
    };

    /**
     *  @brief One connection's Noise state, from the first handshake byte to the last record.
     *
     *  Identical across all three patterns, which was checked rather than assumed: every one
     *  carries @c e and at least one static-touching token, so all six key buffers are live in all
     *  three and a union across modes would save nothing. What differs is the message count, the
     *  two pre-message flags, and when the peer's key becomes trustworthy - all carried by
     *  @c pattern and @c remote_static_state.
     */
    struct secure_tunnel_noise_t {

        secure_tunnel_transcript_t transcript {};

        byte_t local_static_private[secure_tunnel_key_size_k] {};
        byte_t local_static_public[secure_tunnel_key_size_k] {};
        byte_t local_ephemeral_private[secure_tunnel_key_size_k] {};
        byte_t local_ephemeral_public[secure_tunnel_key_size_k] {};
        byte_t remote_static[secure_tunnel_key_size_k] {};
        byte_t remote_ephemeral[secure_tunnel_key_size_k] {};
        remote_static_t remote_static_state {remote_static_t::unknown_k};

        /** Live once the pattern's tokens are exhausted and @c split has run. */
        secure_tunnel_cipher_t sending {};
        secure_tunnel_cipher_t receiving {};

        secure_tunnel_pattern_t const* pattern {};
        secure_tunnel_role_t role {secure_tunnel_role_t::responder_k};

        /** Index of the next pattern message to write or read. */
        std::size_t message_index {};

        std::size_t records_sealed {};
        std::size_t records_opened {};

        /** What @c advance generated and the caller has not yet been told is sent. */
        byte_t outbound[outbound_capacity_k] {};
        std::size_t outbound_length {};

        /** True on the side that sends the first handshake message. */
        [[nodiscard]] bool initiates() const noexcept { return role == secure_tunnel_role_t::initiator_k; }

        /** True once every message the pattern defines has been written or read. */
        [[nodiscard]] bool handshake_complete() const noexcept { return message_index >= pattern->message_count; }

        /**
         *  @brief Mixes a Diffie-Hellman result into the chaining key.
         *  @return False on a small-order peer point, which must abort rather than continue with a
         *      shared secret an attacker already knows.
         *
         *  @warning Both parameters are exactly this wide and swapping them still compiles. A span
         *      would not help, since two dynamic spans are equally interchangeable; the fixed
         *      extent is what lets the compiler object to a digest or a nonce arriving here by
         *      mistake.
         */
        [[nodiscard]] bool mix_diffie_hellman(byte_t const scalar[secure_tunnel_key_size_k],
                                              byte_t const point[secure_tunnel_key_size_k]) noexcept {
            byte_t shared[secure_tunnel_key_size_k];
            if (!x25519_scalar_multiply(shared, scalar, point)) return false;
            transcript.mix_key(shared);
            secure_zero(shared);
            return true;
        }

        [[nodiscard]] bool generate_ephemeral() noexcept {
            if (!secure_random_bytes(local_ephemeral_private, secure_tunnel_key_size_k)) return false;
            x25519_derive_public(local_ephemeral_public, local_ephemeral_private);
            return true;
        }

        void clear() noexcept {
            transcript.clear();
            sending.clear();
            receiving.clear();
            secure_zero(local_static_private);
            secure_zero(local_static_public);
            secure_zero(local_ephemeral_private);
            secure_zero(local_ephemeral_public);
            secure_zero(remote_static);
            secure_zero(remote_ephemeral);
            secure_zero(outbound);
        }
    };

#pragma endregion Handshake State

#pragma region Handshake Steps

    /**
     *  @brief Applies one Diffie-Hellman token, picking the operands by role.
     *  @param[out] fault Why it failed, so a peer's small-order point is never logged as ours.
     *
     *  The only way this fails on well-formed input is a peer point of small order, which is a
     *  deliberate act: it forces a shared secret the attacker already knows. Reporting it as
     *  anything but hostile would put an attack and an operating-system problem on the same line in
     *  the logs.
     */
    [[nodiscard]] static bool apply_diffie_hellman(secure_tunnel_noise_t& noise, secure_tunnel_token_t token,
                                                   secure_tunnel_fault_t& fault) noexcept {
        bool const initiator = noise.initiates();
        bool agreed = false;
        switch (token) {
        case secure_tunnel_token_t::ephemeral_ephemeral_k:
            agreed = noise.mix_diffie_hellman(noise.local_ephemeral_private, noise.remote_ephemeral);
            break;
        case secure_tunnel_token_t::ephemeral_static_k:
            agreed = initiator ? noise.mix_diffie_hellman(noise.local_ephemeral_private, noise.remote_static)
                               : noise.mix_diffie_hellman(noise.local_static_private, noise.remote_ephemeral);
            break;
        case secure_tunnel_token_t::static_ephemeral_k:
            agreed = initiator ? noise.mix_diffie_hellman(noise.local_static_private, noise.remote_ephemeral)
                               : noise.mix_diffie_hellman(noise.local_ephemeral_private, noise.remote_static);
            break;
        case secure_tunnel_token_t::static_static_k:
            agreed = noise.mix_diffie_hellman(noise.local_static_private, noise.remote_static);
            break;
        // A token no pattern in this file emits, which means the pattern table and this switch
        // disagree - a build-time mistake rather than anything the peer did.
        default: fault = secure_tunnel_fault_t::misconfigured_k; return false;
        }
        if (!agreed) fault = secure_tunnel_fault_t::authentication_failed_k;
        return agreed;
    }

    /**
     *  @brief Derives the record-layer keys, then destroys everything the handshake no longer
     *      needs.
     *
     *  The wipe is not tidiness. Forward secrecy is the entire reason Noise carries ephemerals:
     *  once the keys are split, an attacker who later compromises the static key - or simply reads
     *  this process's memory - must not be able to reconstruct session keys for traffic already
     *  sent, and they can if the ephemeral private half is still lying in the connection's storage.
     *  Roughly six hundred bytes of spent secret per connection, which at a thousand connections a
     *  bind is six hundred kilobytes of it resident for as long as the server runs.
     *
     *  Safe in every mode because the state is identical across the three patterns: no pattern
     *  needs any of these buffers after its own messages are exhausted. @c remote_static
     *  deliberately survives - it is the answer @c peer_key exists to give.
     */
    static void finish_handshake(secure_tunnel_noise_t& noise) noexcept {
        secure_tunnel_cipher_t first, second;
        noise.transcript.split(first, second);
        // The specification assigns the first state to the initiator's sending direction.
        noise.sending = noise.initiates() ? first : second;
        noise.receiving = noise.initiates() ? second : first;
        first.clear();
        second.clear();

        // A key merely configured is proven by here: every pattern that pre-shares one also
        // performs a Diffie-Hellman against it, and the transcripts agree only if the peer holds
        // the private half.
        if (noise.remote_static_state != remote_static_t::unknown_k)
            noise.remote_static_state = remote_static_t::authenticated_k;

        noise.transcript.clear();
        secure_zero(noise.local_ephemeral_private);
        secure_zero(noise.local_ephemeral_public);
        secure_zero(noise.remote_ephemeral);
        secure_zero(noise.local_static_private);
    }

    /**
     *  @brief Writes the pattern message at @c message_index into the tunnel's outbound buffer.
     *  @param[out] fault Why it failed. Never a single code for every cause - an exhausted entropy
     *      pool, a peer forcing a known shared secret, and an outbound buffer this build sized
     *      wrongly are three different problems calling for three different responses.
     *
     *  Runs @c finish_handshake when this was the pattern's last message, which is what makes the
     *  record layer usable on the write path - a caller may put its first record in the same write
     *  as the final handshake message rather than waiting a round trip to discover it could have.
     */
    [[nodiscard]] static bool write_handshake_message(secure_tunnel_noise_t& noise,
                                                      secure_tunnel_fault_t& fault) noexcept {
        if (noise.handshake_complete()) {
            fault = secure_tunnel_fault_t::misconfigured_k;
            return false;
        }

        byte_t* const body = noise.outbound + prefix_size_k;
        std::size_t const capacity = outbound_capacity_k - prefix_size_k;
        std::size_t written = 0;

        for (secure_tunnel_token_t const token : noise.pattern->messages[noise.message_index]) {
            if (token == secure_tunnel_token_t::end_k) break;
            switch (token) {
            case secure_tunnel_token_t::ephemeral_k: {
                if (!noise.generate_ephemeral()) {
                    fault = secure_tunnel_fault_t::entropy_unavailable_k;
                    return false;
                }
                if (written + secure_tunnel_key_size_k > capacity) {
                    fault = secure_tunnel_fault_t::misconfigured_k;
                    return false;
                }
                std::memcpy(body + written, noise.local_ephemeral_public, secure_tunnel_key_size_k);
                noise.transcript.mix_hash(
                    {noise.local_ephemeral_public, noise.local_ephemeral_public + secure_tunnel_key_size_k});
                written += secure_tunnel_key_size_k;
                break;
            }
            case secure_tunnel_token_t::static_k: {
                if (written + secure_tunnel_key_size_k + tag_size_k > capacity) {
                    fault = secure_tunnel_fault_t::misconfigured_k;
                    return false;
                }
                std::memcpy(body + written, noise.local_static_public, secure_tunnel_key_size_k);
                std::size_t sealed = 0;
                if (!noise.transcript.seal_and_hash({body + written, body + written + secure_tunnel_key_size_k},
                                                    sealed)) {
                    fault = secure_tunnel_fault_t::keys_exhausted_k;
                    return false;
                }
                written += sealed;
                break;
            }
            default:
                if (!apply_diffie_hellman(noise, token, fault)) return false;
                break;
            }
        }

        // Every handshake message ends with a sealed payload. Ours are empty, which still
        // contributes a tag once a key exists, and nothing at all before that.
        if (written + tag_size_k > capacity) {
            fault = secure_tunnel_fault_t::misconfigured_k;
            return false;
        }
        std::size_t trailer = 0;
        if (!noise.transcript.seal_and_hash({body + written, body + written}, trailer)) {
            fault = secure_tunnel_fault_t::keys_exhausted_k;
            return false;
        }
        written += trailer;

        poke_length(noise.outbound, written);
        noise.outbound_length = prefix_size_k + written;
        ++noise.message_index;
        if (noise.handshake_complete()) finish_handshake(noise);
        return true;
    }

    /**
     *  @brief Reads the pattern message at @c message_index, discarding whatever payload it
     *      carried.
     *  @param[in] body The message without its length prefix.
     *  @param[out] fault Why it failed. A message too short to hold the field a token demands is
     *      @c malformed_k; a tag that did not verify is @c authentication_failed_k. Collapsing the
     *      two would make a truncating middlebox and an active attacker indistinguishable in the
     *      logs.
     *
     *  The prefix is deliberately not authenticated here, unlike a record's. The transcript is the
     *  Noise specification's, and mixing our framing into it would break interoperation with a
     *  conformant peer; a tampered handshake prefix mis-frames the message and is caught by the
     *  very next tag check regardless.
     */
    [[nodiscard]] static bool read_handshake_message(secure_tunnel_noise_t& noise, span<byte_t const> body,
                                                     secure_tunnel_fault_t& fault) noexcept {
        if (noise.handshake_complete()) {
            fault = secure_tunnel_fault_t::misconfigured_k;
            return false;
        }

        std::size_t const length = body.size();
        std::size_t consumed = 0;

        for (secure_tunnel_token_t const token : noise.pattern->messages[noise.message_index]) {
            if (token == secure_tunnel_token_t::end_k) break;
            switch (token) {
            case secure_tunnel_token_t::ephemeral_k: {
                if (consumed + secure_tunnel_key_size_k > length) {
                    fault = secure_tunnel_fault_t::malformed_k;
                    return false;
                }
                std::memcpy(noise.remote_ephemeral, body.data() + consumed, secure_tunnel_key_size_k);
                noise.transcript.mix_hash({noise.remote_ephemeral, noise.remote_ephemeral + secure_tunnel_key_size_k});
                consumed += secure_tunnel_key_size_k;
                break;
            }
            case secure_tunnel_token_t::static_k: {
                std::size_t const expected = noise.transcript.cipher().has_key() ? secure_tunnel_key_size_k + tag_size_k
                                                                                 : secure_tunnel_key_size_k;
                if (consumed + expected > length) {
                    fault = secure_tunnel_fault_t::malformed_k;
                    return false;
                }
                std::size_t produced = 0;
                if (!noise.transcript.open_and_hash(
                        {body.data() + consumed, body.data() + consumed + expected},
                        {noise.remote_static, noise.remote_static + secure_tunnel_key_size_k}, produced)) {
                    fault = secure_tunnel_fault_t::authentication_failed_k;
                    return false;
                }
                if (produced != secure_tunnel_key_size_k) {
                    fault = secure_tunnel_fault_t::malformed_k;
                    return false;
                }
                // The tag verified against the transcript, so this key is proven rather than
                // assumed.
                noise.remote_static_state = remote_static_t::authenticated_k;
                consumed += expected;
                break;
            }
            default:
                if (!apply_diffie_hellman(noise, token, fault)) return false;
                break;
            }
        }

        // The trailing payload. Our patterns always write an empty one, but the peer's still has to
        // be authenticated so that both transcripts advance identically.
        byte_t payload[max_handshake_payload_k];
        std::size_t produced = 0;
        if (length - consumed > sizeof(payload) + tag_size_k) {
            fault = secure_tunnel_fault_t::malformed_k;
            return false;
        }
        if (!noise.transcript.open_and_hash({body.data() + consumed, body.data() + length},
                                            {payload, payload + sizeof(payload)}, produced)) {
            fault = secure_tunnel_fault_t::authentication_failed_k;
            return false;
        }
        secure_zero(payload);

        ++noise.message_index;
        if (noise.handshake_complete()) finish_handshake(noise);
        return true;
    }

#pragma endregion Handshake Steps

#pragma region Records

    /**
     *  @brief Seals @p filled payload bytes sitting one prefix into @p record, as one whole record.
     *  @param[in] kind What the record carries, sealed behind the payload and inside the tag.
     *  @return Bytes the finished record occupies, or zero when the key is exhausted.
     *
     *  The prefix is written before the payload is sealed and passed as associated data, exactly as
     *  TLS 1.3 authenticates its record header. That binds the declared length to the tag, so the
     *  same ciphertext cannot be presented under a framing it was not sealed with.
     *
     *  It is defence in depth rather than the only line: shortening a prefix also moves the tag,
     *  which the framing check would catch on its own. Lengthening one is not caught here at all -
     *  the boundary check must trust the prefix, so an inflated length simply makes the receiver
     *  wait. Only encrypting the length would close that, and BOLT #8 pays an
     *  authenticated-encryption invocation per record to do it.
     */
    [[nodiscard]] static std::size_t seal_record(secure_tunnel_noise_t& noise, byte_t* record, std::size_t filled,
                                                 secure_tunnel_record_t kind) noexcept {
        std::size_t const declared = filled + kind_size_k + tag_size_k;
        poke_length(record, declared);
        record[prefix_size_k + filled] = static_cast<byte_t>(kind);

        byte_t* const body = record + prefix_size_k;
        std::size_t const plain_size = filled + kind_size_k;
        if (!noise.sending.seal({record, record + prefix_size_k}, {body, body + plain_size}, body + plain_size))
            return 0;

        if (++noise.records_sealed % rekey_interval_k == 0) noise.sending.rekey();
        return prefix_size_k + declared;
    }

#pragma endregion Records

    /**
     *  @brief The Noise state constructed inside a tunnel's aligned storage.
     *
     *  A @c reinterpret_cast rather than anything cleverer, because the object really is there: the
     *  only way into these overloads is through a tunnel whose @c mode_ says @c make
     *  placement-newed one, and @c mode_ is assigned last precisely so a rejected configuration
     *  cannot get here.
     */
    [[nodiscard]] static secure_tunnel_noise_t& noise_of(byte_t* storage) noexcept {
        return *reinterpret_cast<secure_tunnel_noise_t*>(storage);
    }

    [[nodiscard]] static secure_tunnel_noise_t const& noise_of(byte_t const* storage) noexcept {
        return *reinterpret_cast<secure_tunnel_noise_t const*>(storage);
    }
};

/**
 *  @brief One connection's record layer, whichever mode it speaks.
 *
 *  Neither copyable nor movable: the state lives inside the object, so a move would relocate bytes
 *  that holds live cryptographic state. Nothing needs to move one - a server's tunnel lives in a
 *  pooled connection and a client's in a stack frame.
 *
 *  @warning A default-constructed tunnel is a valid plaintext tunnel, already @c ready_k. That is
 *      deliberate: a pooled connection needs no separate "built yet" flag, and a recycled one is
 *      plaintext until configured. Every Noise operation requires @c make first.
 *
 *  @warning A record buffer handed to @c open and a slot handed to @c stage must not overlap the
 *      inbound buffer given to @c advance. Absorbing the peer's message and writing the reply
 *      happen in one call, and opening works in place, so a returned payload aliases the buffer it
 *      came from. Overlap corrupts a record pipelined behind a handshake message, silently, inside
 *      one live allocation that no sanitizer sees.
 */
template <sz_capability_t capabilities_ = sz_cap_serial_k>
class secure_tunnel : private secure_tunnel_crypto<capabilities_> {
    using crypto_t = secure_tunnel_crypto<capabilities_>;
    using crypto_t::bytes_until_prefixed_boundary;
    using crypto_t::hash_size_k;
    using crypto_t::kind_size_k;
    using crypto_t::max_message_k;
    using crypto_t::min_record_body_k;
    using crypto_t::noise_of;
    using crypto_t::outbound_capacity_k;
    using crypto_t::pattern_for;
    using crypto_t::peek_length;
    using crypto_t::prefix_size_k;
    using crypto_t::read_handshake_message;
    using crypto_t::rekey_interval_k;
    using crypto_t::seal_record;
    using crypto_t::secure_zero;
    using crypto_t::tag_size_k;
    using crypto_t::write_handshake_message;
    using typename crypto_t::remote_static_t;
    using typename crypto_t::secure_tunnel_noise_t;
    using typename crypto_t::secure_tunnel_pattern_t;

    /**
     *  @brief Whether one direction can carry a record, and why not when it cannot.
     *
     *  Private, and the caller never sees it: @c may_seal and @c may_open are the questions worth
     *  asking, and @c state and @c fault already say publicly why a connection stopped. Its job is
     *  entirely internal - two of these replaced four booleans whose combinations were mutually
     *  dependent, so each predicate became one comparison rather than a disjunction across three
     *  variables. It cannot be derived from @c secure_tunnel_state_t, because @c ready_k covers
     *  three different pairs of these once half-close exists.
     */
    enum class direction_t : std::uint8_t {

        /** The handshake has not yet produced keys for this direction. */
        unavailable_k,

        /** Usable: records may be sealed into it, or opened from it. */
        open_k,

        /** A close record went through it - ours if sending, the peer's if receiving. */
        shut_k,
    };

    secure_tunnel_mode_t mode_ {secure_tunnel_mode_t::plain_k};
    secure_tunnel_role_t role_ {secure_tunnel_role_t::responder_k};

    /** Plaintext is born usable; a Noise tunnel starts over at @c make. */
    secure_tunnel_state_t state_ {secure_tunnel_state_t::ready_k};
    secure_tunnel_fault_t fault_ {secure_tunnel_fault_t::none_k};

    /**
     *  @brief What each direction can currently do.
     *
     *  Born open, because a default-constructed tunnel is plaintext. @c make moves both to
     *  @c unavailable_k for a Noise mode, the handshake moves both to @c open_k together - the
     *  split produces two cipher states in one step - and a close moves one to @c shut_k.
     */
    direction_t sending_ {direction_t::open_k};
    direction_t receiving_ {direction_t::open_k};

    std::size_t max_payload_ {secure_tunnel_default_payload_k};

    /**
     *  @brief The mode's state, deliberately left uninitialised.
     *
     *  No default member initialiser, so constructing a pool of connections does not write these
     *  pages and a reservation that never carries a Noise tunnel is never faulted in.
     */
    alignas(secure_tunnel_noise_t) byte_t storage_[sizeof(secure_tunnel_noise_t)];

  public:
    secure_tunnel() noexcept = default;
    secure_tunnel(secure_tunnel const&) = delete;
    secure_tunnel& operator=(secure_tunnel const&) = delete;
    secure_tunnel(secure_tunnel&&) = delete;
    secure_tunnel& operator=(secure_tunnel&&) = delete;
    ~secure_tunnel() noexcept { reset(); }

    /**
     *  @brief Builds the tunnel in place, copying whatever keys the configuration names.
     *  @return @c none_k on success, or why it failed - so a caller can tell a bad key from an
     *      exhausted entropy pool, which one boolean could not.
     *
     *  Leaves a Noise tunnel in @c starting_k, meaning the handshake has not begun: call @c advance
     *  before any IO. Leaves a plaintext tunnel in @c ready_k with nothing built.
     */
    [[nodiscard]] secure_tunnel_fault_t make(secure_tunnel_config_t const& config) noexcept {

        static_assert(sizeof(secure_tunnel_geometry_t) == 3 * sizeof(std::size_t),
                      "a field was added to the geometry that `geometry()` does not fill");
        static_assert(secure_tunnel_payload_ceiling_k + secure_tunnel_overhead_k == secure_tunnel_max_record_k,
                      "the record ceiling and the payload ceiling disagree about framing");

        reset();

        // Clamped downwards only, so asking for more than a two-byte prefix can name yields the
        // wire format's answer rather than a refusal.
        std::size_t const requested = config.max_payload ? config.max_payload : secure_tunnel_default_payload_k;
        max_payload_ = requested < secure_tunnel_payload_ceiling_k ? requested : secure_tunnel_payload_ceiling_k;
        role_ = config.role;

        if (config.mode == secure_tunnel_mode_t::plain_k) return secure_tunnel_fault_t::none_k;

        secure_tunnel_pattern_t const* const pattern = pattern_for(config.mode);
        if (!pattern) return fault_ = secure_tunnel_fault_t::misconfigured_k;

        // Every supported pattern either transmits this side's static key or performs a
        // Diffie-Hellman against it, in both roles - so an absent one would silently become a
        // scalar of zeros.
        if (config.local_private.size() != secure_tunnel_key_size_k)
            return fault_ = secure_tunnel_fault_t::misconfigured_k;
        if (config.local_public.size() && config.local_public.size() != secure_tunnel_key_size_k)
            return fault_ = secure_tunnel_fault_t::misconfigured_k;
        if (config.remote_public.size() && config.remote_public.size() != secure_tunnel_key_size_k)
            return fault_ = secure_tunnel_fault_t::misconfigured_k;

        // A pre-message key this side is supposed to already know, and does not, cannot be
        // recovered from the wire: the transcript would diverge before the first message and every
        // tag after it would fail for a reason no log could distinguish from an attack.
        bool const initiator = config.role == secure_tunnel_role_t::initiator_k;
        bool const needs_remote = initiator ? pattern->shares_responder_static() : pattern->shares_initiator_static();
        if (needs_remote && config.remote_public.size() != secure_tunnel_key_size_k)
            return fault_ = secure_tunnel_fault_t::misconfigured_k;

        auto& noise = *new (storage_) secure_tunnel_noise_t {};
        noise.pattern = pattern;
        noise.role = config.role;

        std::memcpy(noise.local_static_private, config.local_private.data(), secure_tunnel_key_size_k);
        if (config.local_public.size())
            std::memcpy(noise.local_static_public, config.local_public.data(), secure_tunnel_key_size_k);
        else x25519_derive_public(noise.local_static_public, noise.local_static_private);

        if (config.remote_public.size()) {
            std::memcpy(noise.remote_static, config.remote_public.data(), secure_tunnel_key_size_k);
            noise.remote_static_state = remote_static_t::configured_k;
        }

        std::size_t name_length = 0;
        while (pattern->name[name_length]) ++name_length;
        noise.transcript.initialize(pattern->name, name_length);
        noise.transcript.mix_hash({}); // an empty prologue

        // Pre-message keys enter the transcript before any message, the initiator's first.
        if (pattern->shares_initiator_static()) {
            byte_t const* const key = initiator ? noise.local_static_public : noise.remote_static;
            noise.transcript.mix_hash({key, key + secure_tunnel_key_size_k});
        }
        if (pattern->shares_responder_static()) {
            byte_t const* const key = initiator ? noise.remote_static : noise.local_static_public;
            noise.transcript.mix_hash({key, key + secure_tunnel_key_size_k});
        }

        // Assigned last: until here the tunnel is still plaintext, so a configuration rejected
        // above leaves nothing constructed for `reset` to find and nothing for a driver to misread.
        mode_ = config.mode;
        state_ = secure_tunnel_state_t::starting_k;
        sending_ = direction_t::unavailable_k;
        receiving_ = direction_t::unavailable_k;
        return secure_tunnel_fault_t::none_k;
    }

    /** Wipes every secret and returns the tunnel to plaintext. Safe on an unbuilt one. */
    void reset() noexcept {
        if (encrypts()) {
            auto& noise = noise_of(storage_);
            noise.clear();
            noise.~secure_tunnel_noise_t();
        }
        mode_ = secure_tunnel_mode_t::plain_k;
        role_ = secure_tunnel_role_t::responder_k;
        state_ = secure_tunnel_state_t::ready_k;
        fault_ = secure_tunnel_fault_t::none_k;
        sending_ = direction_t::open_k;
        receiving_ = direction_t::open_k;
        max_payload_ = secure_tunnel_default_payload_k;
    }

    [[nodiscard]] secure_tunnel_mode_t mode() const noexcept { return mode_; }
    [[nodiscard]] secure_tunnel_role_t role() const noexcept { return role_; }
    [[nodiscard]] secure_tunnel_state_t state() const noexcept { return state_; }
    [[nodiscard]] secure_tunnel_fault_t fault() const noexcept { return fault_; }

    /**
     *  @brief True when this connection frames and encrypts. A bind can ask the mode instead.
     *
     *  Also the answer to whether @c storage_ holds a constructed state, which is why no separate
     *  flag records it: @c make assigns @c mode_ only once construction has succeeded, so a
     *  configuration it rejected leaves a plaintext tunnel with nothing to destroy.
     */
    [[nodiscard]] bool encrypts() const noexcept { return secure_tunnel_mode_encrypts(mode_); }

    /**
     *  @brief True while this side may still seal records.
     *
     *  Asks the sending direction, not the state, and the difference is load-bearing: the transport
     *  keys become live on the @b write path, so this is already true while @c advance is reporting
     *  @c transmitting_k for the final handshake message. That is what lets a caller put its first
     *      record in the same write, and what lets a half-closed connection keep answering - a
     *      peer's close shuts the receiving direction and leaves this one alone.
     */
    [[nodiscard]] bool may_seal() const noexcept { return sending_ == direction_t::open_k; }

    /** True while this side may still open records. */
    [[nodiscard]] bool may_open() const noexcept { return receiving_ == direction_t::open_k; }

    /**
     *  @brief Records sealed into, and opened from, this connection so far.
     *
     *  Diagnostics rather than telemetry - @c traffic_stats_t already counts bytes and packets, and
     *  these are neither. They earn their place because the two counts drive the rekey schedules on
     *  the two ends independently, and a schedule that desynchronises is the one failure in this
     *  layer with no distinguishable symptom: every record after it fails authentication and looks
     *  exactly like an attack. Peers that agree must end a conversation with these two mirrored,
     *  which is a thing a test can assert and a log can print.
     */
    [[nodiscard]] std::size_t records_sealed() const noexcept {
        return encrypts() ? noise_of(storage_).records_sealed : 0;
    }
    [[nodiscard]] std::size_t records_opened() const noexcept {
        return encrypts() ? noise_of(storage_).records_opened : 0;
    }

    /** Framing widths and payload cap for this connection. */
    [[nodiscard]] secure_tunnel_geometry_t geometry() const noexcept {
        secure_tunnel_geometry_t result;
        result.headroom = encrypts() ? secure_tunnel_headroom_k : 0;
        result.tailroom = encrypts() ? secure_tunnel_tailroom_k : 0;
        result.max_payload = max_payload_;
        return result;
    }

    /**
     *  @brief Copies out the peer's authenticated static key.
     *  @param[out] out Receives @c secure_tunnel_key_size_k bytes, untouched on false.
     *  @return False until the handshake proves the peer holds the matching private half. A boolean
     *      rather than a fault, because there being no peer yet is an absence and not a failure -
     *      and the one caller does one thing with it: run the authorizer, or not.
     *
     *  A copy rather than a view, because this is the one answer that crosses the C ABI into code
     *  with no way to learn when a borrowed pointer went stale. A fixed extent rather than a span,
     *  because a parameter can carry one and a struct member cannot - so the width is checked by
     *  the compiler here and by @c make there, and neither is assumed. A key merely supplied by
     *  configuration - as @c IK and @c KK both do - is assumed, not proven, and is not reported
     *  here until the exchange completes.
     */
    [[nodiscard]] bool peer_key(byte_t out[secure_tunnel_key_size_k]) const noexcept {
        if (!encrypts()) return false;
        auto const& noise = noise_of(storage_);
        if (noise.remote_static_state != remote_static_t::authenticated_k) return false;
        std::memcpy(out, noise.remote_static, secure_tunnel_key_size_k);
        return true;
    }

    /**
     *  @brief Advances the tunnel by exactly one IO operation's worth of work.
     *
     *  @param[in] inbound Bytes buffered from the peer.
     *  @param[in] request What the caller wants. Defaulted, so the hot call site stays at one.
     *  @return @c outbound points into the tunnel and is valid until the next call on it.
     *
     *  @warning Absorbs the peer's message and produces whatever reply it owes in @b one call, then
     *      reports @c transmitting_k. No returned state obliges another @c advance without an
     *      intervening send or read. This function may loop internally; it may never make the
     *      caller loop. Without that rule every caller reconstructs the transition from byte
     *      counts, in its own order, and no driver can be shared between backends.
     *
     *  On first reaching @c ready_k, the bytes past @c consumed are the peer's first record and
     *  must be opened before posting a read, or both sides wait until the idle timeout.
     *
     *  Idempotent once the record layer is live, so a driver may call it on every completion
     *  without checking first.
     */
    [[nodiscard]] secure_tunnel_step_t advance(
        span<byte_t const> inbound, secure_tunnel_request_t request = secure_tunnel_request_t::proceed_k) noexcept {

        secure_tunnel_step_t step;
        step.state = state_;
        if (state_ == secure_tunnel_state_t::broken_k) return step;

        // A plaintext tunnel has no handshake to drive and no close record to send. Its only
        // control action is shutting both directions at once: TCP's own half-close is the engine's
        // business, and inventing an in-band signal here would be a framing this mode does not
        // have.
        if (!encrypts()) {
            if (request == secure_tunnel_request_t::close_k) {
                sending_ = direction_t::shut_k;
                receiving_ = direction_t::shut_k;
                state_ = secure_tunnel_state_t::closed_k;
            }
            step.state = state_;
            return step;
        }

        auto& noise = noise_of(storage_);
        auto const fail = [&](secure_tunnel_fault_t reason) noexcept {
            fault_ = reason;
            state_ = secure_tunnel_state_t::broken_k;
            step.outbound = {};
            step.state = state_;
            return step;
        };

        // The loop is internal so that no caller ever needs one: absorbing the peer's message and
        // producing the reply it obliges happen in a single call, and every exit either hands the
        // caller bytes to send or asks for bytes to read.
        for (;;) {
            switch (state_) {

            case secure_tunnel_state_t::starting_k:
                if (role_ == secure_tunnel_role_t::initiator_k) {
                    secure_tunnel_fault_t reason = secure_tunnel_fault_t::none_k;
                    if (!write_handshake_message(noise, reason)) return fail(reason);
                    if (noise.handshake_complete()) {
                        sending_ = direction_t::open_k;
                        receiving_ = direction_t::open_k;
                    }
                    state_ = secure_tunnel_state_t::transmitting_k;
                    step.outbound = {noise.outbound, noise.outbound + noise.outbound_length};
                    step.state = state_;
                    return step;
                }
                // A responder that parked here would be waiting for a peer that is waiting for it.
                state_ = secure_tunnel_state_t::receiving_k;
                continue;

            case secure_tunnel_state_t::transmitting_k:
                // Reaching here means the caller sent what it was handed, which is the contract.
                noise.outbound_length = 0;
                state_ = noise.handshake_complete() ? secure_tunnel_state_t::ready_k
                                                    : secure_tunnel_state_t::receiving_k;
                continue;

            case secure_tunnel_state_t::receiving_k: {
                span<byte_t const> const pending {inbound.data() + step.consumed, inbound.data() + inbound.size()};
                if (bytes_until_prefixed_boundary(pending)) {
                    step.state = state_;
                    return step;
                }
                std::size_t const declared = peek_length(pending);
                if (declared > max_message_k) return fail(secure_tunnel_fault_t::malformed_k);
                secure_tunnel_fault_t reason = secure_tunnel_fault_t::none_k;
                if (!read_handshake_message(
                        noise, {pending.data() + prefix_size_k, pending.data() + prefix_size_k + declared}, reason))
                    return fail(reason);
                step.consumed += prefix_size_k + declared;

                if (noise.handshake_complete()) {
                    sending_ = direction_t::open_k;
                    receiving_ = direction_t::open_k;
                    state_ = secure_tunnel_state_t::ready_k;
                    continue;
                }

                // The peer's message obliged a reply, so it goes out in this same call rather than
                // making the caller come back and ask.
                if (!write_handshake_message(noise, reason)) return fail(reason);
                if (noise.handshake_complete()) {
                    sending_ = direction_t::open_k;
                    receiving_ = direction_t::open_k;
                }
                state_ = secure_tunnel_state_t::transmitting_k;
                step.outbound = {noise.outbound, noise.outbound + noise.outbound_length};
                step.state = state_;
                return step;
            }

            case secure_tunnel_state_t::ready_k: {
                if (request == secure_tunnel_request_t::close_k && sending_ == direction_t::open_k) {
                    std::size_t const written = seal_record(noise, noise.outbound, 0, secure_tunnel_record_t::close_k);
                    if (!written) return fail(secure_tunnel_fault_t::keys_exhausted_k);
                    noise.outbound_length = written;
                    sending_ = direction_t::shut_k;
                }
                if (sending_ == direction_t::shut_k && receiving_ == direction_t::shut_k)
                    state_ = secure_tunnel_state_t::closed_k;
                else if (noise.outbound_length) state_ = secure_tunnel_state_t::transmitting_k;
                step.outbound = {noise.outbound, noise.outbound + noise.outbound_length};
                step.state = state_;
                return step;
            }

            case secure_tunnel_state_t::closed_k:
                // Whatever the closing step handed over has been sent by now; handing it back a
                // second time would put a duplicate close record on the wire.
                noise.outbound_length = 0;
                step.state = state_;
                return step;

            case secure_tunnel_state_t::broken_k: step.state = state_; return step;
            }
        }
    }

    /**
     *  @brief Where a producer writes the payload of the record @p record will become.
     *  @param[in] record Caller memory, ideally @c geometry().record_size() bytes.
     *  @return The largest window inside @p record that a payload may occupy, empty when the buffer
     *      cannot hold even a minimal record or this side may no longer seal.
     *
     *  Total: a capacity to read, never a failure to diagnose. Serialise into this window and the
     *  bytes are already where the wire wants them - @c seal writes the framing around them and
     *  nothing is ever copied. This is the only place the layout rule lives, so no call site
     *  composes headroom and tailroom by hand.
     */
    [[nodiscard]] span<byte_t> payload_window(span<byte_t> record) const noexcept {
        if (sending_ != direction_t::open_k) return {};
        if (!encrypts()) {
            std::size_t const room = record.size() < max_payload_ ? record.size() : max_payload_;
            return {record.data(), record.data() + room};
        }
        if (record.size() < secure_tunnel_overhead_k) return {};
        std::size_t const spare = record.size() - secure_tunnel_overhead_k;
        std::size_t const room = spare < max_payload_ ? spare : max_payload_;
        return {record.data() + secure_tunnel_headroom_k, record.data() + secure_tunnel_headroom_k + room};
    }

    /**
     *  @brief Seals @p filled payload bytes, written into @c payload_window, into one record.
     *  @param[inout] record The same buffer that was handed to @c payload_window.
     *  @param[in] filled How many bytes the producer wrote there.
     *  @return The framed record, inside @p record, or an empty span on failure with @c fault()
     *      set.
     *
     *  The buffer and a length rather than a descriptor, because a record's layout is entirely
     *  determined by those two: the payload sits one headroom in, and the framing wraps it. A
     *  four-pointer window would carry the same information and invite a caller to hand back one
     *  that did not come from @c payload_window.
     */
    [[nodiscard]] span<byte_t const> seal(span<byte_t> record, std::size_t filled) noexcept {

        // Every exit that names a fault also breaks the tunnel, so `fault()` and `state()` can
        // never describe the same connection differently. A caller that hands back more than
        // `payload_window` offered has ignored a total answer, and carrying on from that is worse
        // than stopping.
        auto const fail = [&](secure_tunnel_fault_t reason) noexcept {
            fault_ = reason;
            state_ = secure_tunnel_state_t::broken_k;
            return span<byte_t const> {};
        };

        if (sending_ != direction_t::open_k) return fail(secure_tunnel_fault_t::malformed_k);
        if (!encrypts()) {
            if (filled > record.size()) return fail(secure_tunnel_fault_t::malformed_k);
            return {record.data(), record.data() + filled};
        }

        if (filled > max_payload_ || record.size() < secure_tunnel_overhead_k + filled)
            return fail(secure_tunnel_fault_t::malformed_k);

        auto& noise = noise_of(storage_);
        std::size_t const written = seal_record(noise, record.data(), filled, secure_tunnel_record_t::application_k);
        if (!written) return fail(secure_tunnel_fault_t::keys_exhausted_k);
        return {record.data(), record.data() + written};
    }

    /**
     *  @brief Bytes still needed before the buffered prefix names a whole record.
     *  @return Zero once a whole record is present, and zero for a plaintext tunnel.
     *
     *  Const, keyless, and total: it never faults and never advances anything, which is what lets a
     *  driver ask it before it has any key and on every completion.
     *
     *  @warning Being keyless means it believes the prefix. A peer that inflates one makes this ask
     *      for bytes that will never arrive, and nothing here can tell that from a large record
     *      still in flight. The idle timeout is what closes such a connection, not this function.
     *
     *  A declared length the wire format does not allow still reads as a boundary here; that is
     *  @c open's to reject.
     */
    [[nodiscard]] std::size_t bytes_until_boundary(span<byte_t const> received) const noexcept {
        if (!encrypts()) return 0;
        return bytes_until_prefixed_boundary(received);
    }

    /**
     *  @brief Opens the first whole record in @p record, in place.
     *  @param[inout] record A buffer whose front holds a complete record.
     *  @return The plaintext as a window into @p record, or a zero @c consumed on a malformed or
     *      unauthenticated record - in which case @c fault() says why and the tunnel is
     *      @c broken_k.
     *
     *  @warning A whole record must be present - @c bytes_until_boundary must have returned zero
     *      for this buffer. Calling with a partial record is a caller error, not an incomplete
     *      read, and is answered as one. That is what makes the outcome two-valued instead of
     *      three, and it costs nothing: both drivers already ask the boundary first.
     */
    [[nodiscard]] secure_tunnel_opened_t open(span<byte_t> record) noexcept {

        secure_tunnel_opened_t opened;
        if (!encrypts()) {
            // Guarded because `consumed == 0` means failure, and an empty buffer is not one - it is
            // a caller asking a question with no bytes in hand.
            if (!record.size()) return opened;
            opened.payload = record;
            opened.consumed = record.size();
            return opened;
        }

        auto const fail = [&](secure_tunnel_fault_t reason) noexcept {
            fault_ = reason;
            state_ = secure_tunnel_state_t::broken_k;
            return secure_tunnel_opened_t {};
        };

        // A record arriving after the peer said it would send no more is a protocol violation, not
        // a race: its close was authenticated, so nothing legitimate follows it.
        if (receiving_ != direction_t::open_k) return fail(secure_tunnel_fault_t::malformed_k);

        span<byte_t const> const readable {record.data(), record.data() + record.size()};
        if (record.size() < prefix_size_k) return fail(secure_tunnel_fault_t::malformed_k);

        std::size_t const declared = peek_length(readable);
        if (declared < min_record_body_k || declared > max_message_k) return fail(secure_tunnel_fault_t::malformed_k);
        std::size_t const whole = prefix_size_k + declared;
        if (record.size() < whole) return fail(secure_tunnel_fault_t::malformed_k);

        // Opened where it lies: the plaintext replaces the ciphertext it came from, which the
        // underlying AES-GCM permits when the output pointer exactly equals the input pointer.
        auto& noise = noise_of(storage_);
        byte_t* const body = record.data() + prefix_size_k;
        std::size_t const plain_size = declared - tag_size_k;
        if (!noise.receiving.open({record.data(), record.data() + prefix_size_k}, {body, body + plain_size},
                                  body + plain_size))
            return fail(secure_tunnel_fault_t::authentication_failed_k);

        if (++noise.records_opened % rekey_interval_k == 0) noise.receiving.rekey();

        // The kind is the last byte of the plaintext, inside the tag rather than beside it, so it
        // cannot be forged by flipping a cleartext byte.
        std::size_t const payload_size = plain_size - kind_size_k;
        auto const kind = static_cast<secure_tunnel_record_t>(body[payload_size]);

        switch (kind) {
        case secure_tunnel_record_t::application_k: break;
        case secure_tunnel_record_t::close_k:
            // A close carries nothing. Allowing a payload would give a peer a second, unnumbered
            // way to deliver bytes that the protocol above never sees.
            if (payload_size) return fail(secure_tunnel_fault_t::malformed_k);
            receiving_ = direction_t::shut_k;
            break;
        default:
            // An unknown kind is fatal rather than skipped. Ignoring it would let a future
            // extension mean one thing to a new peer and nothing to an old one, on the same
            // authenticated stream.
            return fail(secure_tunnel_fault_t::malformed_k);
        }

        opened.payload = {body, body + payload_size};
        opened.consumed = whole;
        opened.kind = kind;
        return opened;
    }
};

#pragma endregion Tunnel

/** Portable tunnel specialization for callers without a CPU dispatch point. */
using secure_tunnel_t = secure_tunnel<sz_cap_serial_k>;

} // namespace unum::ucall
