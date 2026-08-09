/**
 *  @brief A secure tunnel: one state machine, driven identically by every IO backend.
 *
 *  @section What a Tunnel Is
 *
 *  A tunnel carries one protocol inside another. Here it carries application bytes inside
 *  authenticated records, and the carried protocol is unaware - `protocol_http.hpp` contains
 *  not one reference to this header.
 *
 *  It is more than encryption, which is why it is not called a cipher: it agrees keys, seals
 *  and opens records, frames them, and names the peer.
 *
 *  @section One Driver, Every Backend
 *
 *  A tunnel never performs IO, never allocates, and never sees a descriptor. It answers one
 *  question - @b what @b must @b happen @b next - and the caller performs it. That is what
 *  lets a blocking client, an `io_uring` completion loop, and a coroutine drive the identical
 *  machine with no shared code between them and no duplicated decisions:
 *
 *  @code
 *  secure_tunnel_step_t const step = tunnel.advance(inbound);
 *  switch (step.state) {
 *  case secure_tunnel_state_t::receiving_k:    ... read, then call again
 *  case secure_tunnel_state_t::transmitting_k: ... send step.outbound, then call again
 *  case secure_tunnel_state_t::ready_k:        ... the record layer is live
 *  case secure_tunnel_state_t::closed_k:
 *  case secure_tunnel_state_t::broken_k:       ... drop the connection
 *  }
 *  @endcode
 *
 *  There is no loop in that sketch and none is needed, which is the whole design.
 *
 *  @section Framing
 *
 *  Noise defines no framing, so this file imposes one. Every message - handshake or record -
 *  is a big-endian @c uint16 length followed by that many bytes. A record's payload carries a
 *  one-byte kind @b inside the authenticated encryption, exactly as TLS 1.3 places
 *  @c TLSInnerPlaintext.type, so a close cannot be forged into application data by flipping a
 *  cleartext byte.
 *
 *  The length prefix travels in the clear, as a TLS record header does, which is what lets
 *  @c bytes_until_boundary stay keyless and total. Cleartext is not the same as unauthenticated:
 *  a record's prefix is passed as associated data, exactly as TLS 1.3 §5.2 treats its record
 *  header, so a peer cannot be made to accept one ciphertext under a framing it was not sealed
 *  with.
 *
 *  What that does @b not buy is protection from a prefix inflated in flight. The boundary check
 *  has to trust the prefix - being keyless is the whole point of it - so an inflated length is
 *  indistinguishable from a large record until the idle timeout fires. That is inherent to a
 *  cleartext length, and the idle timeout is what answers it. Lightning's BOLT #8 encrypts the
 *  length to close exactly that gap, and pays a second authenticated-encryption invocation per
 *  record for it - a poor trade when a typical reply is a few hundred bytes.
 *
 *  Handshake prefixes are deliberately excluded from that treatment. The handshake transcript
 *  is the Noise specification's, and mixing our framing into it would break interoperation
 *  with a conformant peer. A tampered handshake prefix mis-frames the message and is caught by
 *  the very next tag check. Record framing is ours to define, so authenticating it is ours to
 *  choose.
 *
 *  @section Where Bytes Live
 *
 *  Two rules, and between them they decide every signature below.
 *
 *  The caller owns every buffer a payload passes through, and @b nothing @b is @b copied. A
 *  producer asks @c payload_window where its bytes belong inside a record-sized buffer and
 *  serialises straight into it; @c seal writes the framing around them without moving one. In
 *  the other direction @c open uncovers the plaintext where the ciphertext lay and hands back a
 *  window into the same buffer.
 *
 *  This is why neither direction takes a source and a destination. A signature that accepted
 *  bytes from elsewhere would make the copy permanent for every caller that inherits it, and a
 *  caller that cannot yet serialise in place is a caller to fix, not a reason to widen the
 *  contract.
 *
 *  The tunnel owns exactly one buffer, for the one thing the caller has no payload for: the
 *  handshake and close messages @c advance writes, which are generated from key material rather
 *  than transformed from anything. Hence @c advance takes no output buffer, and the span it
 *  returns is valid exactly as long as the caller's obligation to send it - until the next call.
 *
 *  @file src/secure_tunnel.hpp
 *  @author Ash Vardanian
 */
#pragma once

#include "shared.hpp" // `span`, `byte_t`

namespace unum::ucall {

#pragma region Vocabulary

/**
 *  @brief Which record layer a connection speaks.
 *
 *  Plaintext is a mode, not the absence of one, so no call site has to decide what a missing
 *  tunnel means. The three Noise patterns differ only in which static keys are known before
 *  the first message; they share every line of the record layer and every byte of state.
 */
enum class secure_tunnel_mode_t : std::uint8_t {
    /** @brief Bytes pass through untouched. No handshake, no framing, no keys. */
    plain_k = 0,
    /** @brief Neither side knows the other's static key; both are exchanged and authenticated. */
    noise_xx_k,
    /** @brief The initiator knows the responder's static key in advance. */
    noise_ik_k,
    /** @brief Each side knows the other's static key in advance, and neither transmits one. */
    noise_kk_k,
};

/** @brief Names a mode for a log, including when no tunnel exists yet to ask. */
[[nodiscard]] inline char const *secure_tunnel_mode_name(secure_tunnel_mode_t mode) noexcept {
    switch (mode) {
    case secure_tunnel_mode_t::plain_k: return "plain";
    case secure_tunnel_mode_t::noise_xx_k: return "noise_xx";
    case secure_tunnel_mode_t::noise_ik_k: return "noise_ik";
    case secure_tunnel_mode_t::noise_kk_k: return "noise_kk";
    }
    return "unknown";
}

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
 *  An enumeration rather than a flag, because the answer is not permanently two-valued. Noise
 *  Pipes has an initiator attempt @c IK on a remembered static key and, when the responder
 *  cannot decrypt it, fall back to @c XXfallback - at which point the roles no longer divide
 *  the way they started. A third enumerator absorbs that; a @c bool cannot.
 */
enum class secure_tunnel_role_t : std::uint8_t { initiator_k, responder_k };

/** @brief Names a role for a log, alongside the mode. */
[[nodiscard]] inline char const *secure_tunnel_role_name(secure_tunnel_role_t role) noexcept {
    return role == secure_tunnel_role_t::initiator_k ? "initiator" : "responder";
}

/**
 *  @brief What the caller wants of the pump: its half of the control channel.
 *
 *  An enumeration rather than a flag, because the control channel is not permanently
 *  two-valued. An in-band key update, the day it lands, is a third request and changes no
 *  signature.
 */
enum class secure_tunnel_request_t : std::uint8_t {
    /** @brief Carry on: finish the handshake, or do nothing because it is finished. */
    proceed_k,
    /** @brief Produce a close record and shut this side's sending direction. */
    close_k,
};

/**
 *  @brief What the tunnel needs next, as a direction rather than a byte count to decode.
 *
 *  Both the machine's resting place and the caller's instruction, because every value is
 *  simultaneously somewhere the machine stops and something the caller can act on. A verdict
 *  that were not also a state would have to be recomputed on the next call from something
 *  else; a state that were not also a verdict would be unobservable and untestable.
 *
 *  Deliberately absent, each because no caller would act on it differently: a handshaking or
 *  established distinction, since a driver acts on a direction and never on a phase; a closing
 *  state, since after flushing a close you close the descriptor either way; a draining state,
 *  since one outstanding operation per connection leaves nothing to drain; and a rekeying
 *  state, since rekey is scheduled rather than signalled and making it observable would
 *  resurrect exactly the read-that-secretly-needs-a-write problem this layering avoids.
 */
enum class secure_tunnel_state_t : std::uint8_t {
    /**
     *  @brief Nothing has been exchanged yet.
     *
     *  Call @c advance before performing any IO: an initiator receives its first message and
     *  @c transmitting_k, a responder receives @c receiving_k. The only state in which
     *  @c advance may be called before an IO operation, and the reason it exists - an
     *  initiator parked in @c receiving_k would read from a peer that is waiting for it.
     */
    starting_k,
    /** @brief The peer owes bytes. Read, then call @c advance again. Nothing was produced. */
    receiving_k,
    /**
     *  @brief Bytes are waiting in @c secure_tunnel_step_t::outbound. Send them all, then call again.
     *
     *  Says the bytes must go out; it does not say what follows, because what follows is a
     *  property of the tunnel rather than of the message. Ask @c may_seal(): the transport keys
     *  become live on the @b write path, so after the final handshake message they are already
     *  usable and a caller may put its first record in the same write.
     */
    transmitting_k,
    /**
     *  @brief The record layer is live in at least one direction.
     *
     *  @c may_seal() and @c may_open() say which. On first reaching this state, the bytes
     *  @c advance did not consume are the peer's first record, not handshake data.
     */
    ready_k,
    /** @brief Both directions are shut, cleanly. Close the descriptor and report success. */
    closed_k,
    /** @brief Unrecoverable. Close the descriptor and report failure; @c fault() says why. */
    broken_k,
};

/** @brief Names a state for a log. */
[[nodiscard]] inline char const *secure_tunnel_state_name(secure_tunnel_state_t state) noexcept {
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

/**
 *  @brief Why an operation failed, so a log can tell a bad key from an attack.
 *
 *  One failure code for every cause makes "your configuration is wrong" and "the peer forged a
 *  tag" the same line in the logs, and they call for opposite responses.
 */
enum class secure_tunnel_fault_t : std::uint8_t {
    /** @brief Nothing has failed. */
    none_k,
    /** @brief Configuration is wrong - a missing key, or a pattern this build does not carry. */
    misconfigured_k,
    /** @brief A length, a kind byte, or a record shape the wire format does not allow. */
    malformed_k,
    /** @brief A tag did not verify. Treat as hostile. */
    authentication_failed_k,
    /** @brief The message counter reached the value the specification reserves for rekeying. */
    keys_exhausted_k,
    /** @brief The operating system refused entropy, so no ephemeral key could be drawn. */
    entropy_unavailable_k,
};

/** @brief Names a fault for a log, including when no tunnel was ever built. */
[[nodiscard]] inline char const *secure_tunnel_fault_name(secure_tunnel_fault_t fault) noexcept {
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

/**
 *  @brief What a record carries, from the byte sealed inside its authenticated encryption.
 *
 *  Named for records rather than messages, because a message in this file is what @c advance
 *  writes during a handshake, and the two are framed alike but mean nothing alike.
 *
 *  Two kinds, not three: an enumerator with no implementation is a case nobody can write,
 *  where an unhandled one arriving later is a compiler warning. The values are pinned because
 *  they are on the wire.
 *
 *  A clean close is a sealed record of this kind carrying no payload. A truncation is its
 *  absence - a socket that ends while the tunnel is not closed - which is why no enumerator
 *  names it and why forging one is impossible without the key.
 */
enum class secure_tunnel_record_t : std::uint8_t {
    /** @brief Bytes for the protocol above. The only kind an application can seal. */
    application_k = 0,
    /** @brief The peer will send no more records. Its sending direction is now shut. */
    close_k = 1,
};

#pragma endregion Vocabulary

#pragma region Shape

/**
 *  @brief Width of a Curve25519 key, a SHA-256 digest, and an AES-256 key alike.
 *
 *  One of only three independent numbers in this region. The prefix and the trailer are the
 *  other two; every constant below is arithmetic over them, so none can drift from the wire
 *  format or from what @c secure_tunnel_geometry_t reports for a live connection.
 */
static constexpr std::size_t secure_tunnel_key_size_k = 32;

/** @brief Bytes written ahead of a payload: the big-endian length prefix. */
static constexpr std::size_t secure_tunnel_headroom_k = 2;

/** @brief Bytes written behind it: the record kind, sealed inside the tag that follows it. */
static constexpr std::size_t secure_tunnel_tailroom_k = 1 + 16;

/** @brief What a record adds to its payload. Derived, so it can never disagree with the two. */
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
 *  @c secure_tunnel_geometry_t answers the same question exactly for one connection, which is
 *  what a runtime allocation wants. This is for the stack arrays that cannot ask.
 */
static constexpr std::size_t secure_tunnel_max_record_k = secure_tunnel_payload_ceiling_k + secure_tunnel_overhead_k;

/**
 *  @brief How much room this connection needs around a payload, and how much payload it carries.
 *
 *  One value rather than three accessors, because a caller wanting any of these usually wants
 *  the sum. Per connection rather than per mode: the payload cap is policy in every mode - a
 *  loopback bind can afford records a wide-area bind should not - and framing width would vary
 *  for a tunnel that padded records to hide their length.
 */
struct secure_tunnel_geometry_t {
    /** @brief Bytes written ahead of the payload. Zero when the mode frames nothing. */
    std::size_t headroom {};
    /** @brief Bytes written behind it. Zero when the mode frames nothing. */
    std::size_t tailroom {};
    /** @brief Largest payload a single record carries on this connection. */
    std::size_t max_payload {};

    /** @brief Bytes one whole record occupies, which is what a caller must reserve. */
    [[nodiscard]] std::size_t record_size() const noexcept { return headroom + max_payload + tailroom; }
};

#pragma endregion Shape

#pragma region Setup

/** @brief Payload cap applied when a configuration does not name one. */
static constexpr std::size_t secure_tunnel_default_payload_k = 16u * 1024u;

/**
 *  @brief Draws a fresh static keypair from the operating system's entropy.
 *  @param[out] private_half The secret scalar, which never leaves the process.
 *  @param[out] public_half Its Curve25519 public point, which the peer will see.
 *  @return False when the platform refused entropy, which must abort rather than proceed with
 *    whatever was in the buffer.
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
 *  @warning Every pointer here is read during @c make and never retained. A caller may pass a
 *    stack temporary and drop it the moment @c make returns, which is what lets a per-call
 *    configuration be a local rather than something with the connection's lifetime.
 */
struct secure_tunnel_config_t {

    secure_tunnel_mode_t mode {secure_tunnel_mode_t::plain_k};

    /** @brief Per connection, unlike the keys, which a whole bind shares. */
    secure_tunnel_role_t role {secure_tunnel_role_t::responder_k};

    /**
     *  @brief Local static secret. Required in every mode and both roles.
     *
     *  Not optional anywhere, despite @c XX authenticating both sides only during the handshake:
     *  all three patterns either transmit this side's static key or perform a Diffie-Hellman
     *  against it, in both roles, so an absent one would silently become a scalar of zeros.
     *
     *  @note Spans rather than bare pointers throughout this struct. A member cannot carry a
     *    fixed extent the way a parameter can, so a pointer would make the width an assumption
     *    no one could check; a span of the wrong width is @c misconfigured_k instead of silent
     *    memory the tunnel reads past. Empty means absent, so no separate flag can disagree
     *    with the bytes beside it.
     */
    span<byte_t const> local_private {};

    /**
     *  @brief Public half of @c local_private, derived once when the bind was configured.
     *
     *  Supplying it is not an optimisation. Leaving it empty makes @c make derive it, which
     *  puts a Curve25519 base-point ladder - order 100'000 cycles - inside the accept
     *  completion, on the thread servicing every other connection on the bind, to recompute
     *  the same answer for every connection.
     */
    span<byte_t const> local_public {};

    /**
     *  @brief The peer's static public key, or empty.
     *
     *  Required by @c IK on the initiator and by @c KK on both sides, because those patterns
     *  fold it into the transcript before the first message. Learned from the wire in @c XX.
     */
    span<byte_t const> remote_public {};

    /**
     *  @brief Largest payload one record may carry, or zero for @c secure_tunnel_default_payload_k.
     *
     *  Clamped downwards to @c secure_tunnel_payload_ceiling_k, never upwards, so asking for more
     *  than the wire format allows yields the wire format's answer rather than a failure. Set
     *  it small in a test and the fragmentation path becomes reachable without manufacturing a
     *  large message.
     */
    std::size_t max_payload {};
};

#pragma endregion Setup

#pragma region Results

/**
 *  @brief One step of the pump: what it produced, what it cost, and where the machine is.
 *
 *  @note @c state mirrors @c secure_tunnel_t::state() after the call. Here that is not a second
 *    authority but the return value's entire purpose - the driver switches on it.
 */
struct secure_tunnel_step_t {

    /**
     *  @brief Bytes to transmit. Non-empty only on @c transmitting_k and a closing @c closed_k.
     *
     *  A view into the tunnel's own outbound buffer, valid until the next call on this tunnel -
     *  which is exactly the window in which the caller is already obliged to send it. The
     *  lifetime rule and the protocol rule are the same sentence.
     */
    span<byte_t const> outbound {};

    /** @brief Leading bytes of the inbound buffer absorbed. The caller must drop exactly these. */
    std::size_t consumed {};

    secure_tunnel_state_t state {secure_tunnel_state_t::starting_k};
};

/**
 *  @brief What opening one record produced: a window into the caller's own buffer, and its cost.
 *
 *  Returned by value rather than filled through an out-parameter, because it is three fields of
 *  which two are views - light enough that a reference would buy nothing and would make @c open
 *  the only call in this header that does not simply hand back its result.
 *
 *  @c consumed is zero if and only if the record could not be opened, with @c fault() saying
 *  why. That is the same idiom @c seal uses, and it is unambiguous in a way an empty @c payload
 *  would not be: a close record legitimately carries no payload, while a record that opened at
 *  all consumed at least its own framing.
 *
 *  Carries no state of its own. A peer's close leaves the tunnel @c ready_k with @c may_open()
 *  false, so a caller must read @c kind regardless, and a mirrored state field would be a
 *  second authority that says nothing the first does not.
 */
struct secure_tunnel_opened_t {

    /** @brief The plaintext, uncovered in place: a window into the record buffer handed in. */
    span<byte_t> payload {};

    /** @brief Bytes of the record buffer absorbed, framing included. Zero means nothing opened. */
    std::size_t consumed {};

    secure_tunnel_record_t kind {secure_tunnel_record_t::application_k};
};

#pragma endregion Results

#pragma region Tunnel

/**
 *  @brief One connection's record layer, whichever mode it speaks.
 *
 *  Neither copyable nor movable: the state lives inside the object, so a move would relocate
 *  bytes whose type this header deliberately does not name. Nothing needs to move one - a
 *  server's tunnel lives in a pooled connection and a client's in a stack frame.
 *
 *  @warning A default-constructed tunnel is a valid plaintext tunnel, already @c ready_k. That
 *    is deliberate: a pooled connection needs no separate "built yet" flag, and a recycled one
 *    is plaintext until configured. Every Noise operation requires @c make first.
 *
 *  @warning A record buffer handed to @c open and a slot handed to @c stage must not overlap
 *    the inbound buffer given to @c advance. Absorbing the peer's message and writing the reply
 *    happen in one call, and opening works in place, so a returned payload aliases the buffer it
 *    came from. Overlap corrupts a record pipelined behind a handshake message, silently, inside
 *    one live allocation that no sanitizer sees.
 */
class secure_tunnel_t {

    /**
     *  @brief Storage for the mode's state and its outbound buffer.
     *
     *  Declared ahead of @c storage_ because an array bound is not a complete-class context, so
     *  a constant used by one must precede it. Checked in `secure_tunnel.cpp`, where the real
     *  type is visible: a field added to the state fails the build in the one file that can fix
     *  it, rather than corrupting memory in every file that cannot.
     */
    /**
     *  @brief Whether one direction can carry a record, and why not when it cannot.
     *
     *  Private, and the caller never sees it: @c may_seal and @c may_open are the questions
     *  worth asking, and @c state and @c fault already say publicly why a connection stopped.
     *  Its job is entirely internal - two of these replaced four booleans whose combinations
     *  were mutually dependent, so each predicate became one comparison rather than a
     *  disjunction across three variables. It cannot be derived from @c secure_tunnel_state_t,
     *  because @c ready_k covers three different pairs of these once half-close exists.
     */
    enum class direction_t : std::uint8_t {
        /** @brief The handshake has not yet produced keys for this direction. */
        unavailable_k,
        /** @brief Usable: records may be sealed into it, or opened from it. */
        open_k,
        /** @brief A close record went through it - ours if sending, the peer's if receiving. */
        shut_k,
    };

    /**
     *  @brief A budget for the mode's state, not a measurement of it.
     *
     *  Round and roomy on purpose. The Noise state is a shade under 1.7 KB today, and pinning this
     *  to that figure would mean re-taking the measurement every time a field moved - which says
     *  nothing about correctness and everything about bookkeeping. Overrunning it is not silent
     *  either way: placing an oversized object into a fixed array is a diagnostic in `secure_tunnel.cpp`,
     *  the one file that can see both the type and this bound.
     *
     *  Alignment is eight - what the AES key schedule and the message counters ask for - and
     *  sixteen is carried so a wider schedule in a future StringZilla cannot land misaligned.
     */
    static constexpr std::size_t state_bytes_k = 2048;
    static constexpr std::size_t state_align_k = 16;

    /**
     *  @brief Largest message @c advance will ever write, and the buffer inside @c storage_ for it.
     *
     *  A handshake message carrying two public keys and two tags is the widest any supported
     *  pattern produces, and a close record's nineteen bytes fit easily inside that. Private
     *  because a caller never sizes anything from it - it receives a span that already knows.
     */
    static constexpr std::size_t max_outbound_k = 128;

    secure_tunnel_mode_t mode_ {secure_tunnel_mode_t::plain_k};
    secure_tunnel_role_t role_ {secure_tunnel_role_t::responder_k};

    /** @brief Plaintext is born usable; a Noise tunnel starts over at @c make. */
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
    alignas(state_align_k) byte_t storage_[state_bytes_k];

  public:
    secure_tunnel_t() noexcept = default;
    secure_tunnel_t(secure_tunnel_t const &) = delete;
    secure_tunnel_t &operator=(secure_tunnel_t const &) = delete;
    secure_tunnel_t(secure_tunnel_t &&) = delete;
    secure_tunnel_t &operator=(secure_tunnel_t &&) = delete;
    ~secure_tunnel_t() noexcept;

    /**
     *  @brief Builds the tunnel in place, copying whatever keys the configuration names.
     *  @return @c none_k on success, or why it failed - so a caller can tell a bad key from an
     *    exhausted entropy pool, which one boolean could not.
     *
     *  Leaves a Noise tunnel in @c starting_k, meaning the handshake has not begun: call
     *  @c advance before any IO. Leaves a plaintext tunnel in @c ready_k with nothing built.
     */
    [[nodiscard]] secure_tunnel_fault_t make(secure_tunnel_config_t const &config) noexcept;

    /** @brief Wipes every secret and returns the tunnel to plaintext. Safe on an unbuilt one. */
    void reset() noexcept;

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
     *  Asks the sending direction, not the state, and the difference is load-bearing: the
     *  transport keys become live on the @b write path, so this is already true while @c advance
     *  is reporting @c transmitting_k for the final handshake message. That is what lets a caller
     *  put its first record in the same write, and what lets a half-closed connection keep
     *  answering - a peer's close shuts the receiving direction and leaves this one alone.
     */
    [[nodiscard]] bool may_seal() const noexcept { return sending_ == direction_t::open_k; }

    /** @brief True while this side may still open records. */
    [[nodiscard]] bool may_open() const noexcept { return receiving_ == direction_t::open_k; }

    /**
     *  @brief Records sealed into, and opened from, this connection so far.
     *
     *  Diagnostics rather than telemetry - @c traffic_stats_t already counts bytes and packets,
     *  and these are neither. They earn their place because the two counts drive the rekey
     *  schedules on the two ends independently, and a schedule that desynchronises is the one
     *  failure in this layer with no distinguishable symptom: every record after it fails
     *  authentication and looks exactly like an attack. Peers that agree must end a conversation
     *  with these two mirrored, which is a thing a test can assert and a log can print.
     */
    [[nodiscard]] std::size_t records_sealed() const noexcept;
    [[nodiscard]] std::size_t records_opened() const noexcept;

    /** @brief Framing widths and payload cap for this connection. */
    [[nodiscard]] secure_tunnel_geometry_t geometry() const noexcept;

    /**
     *  @brief Copies out the peer's authenticated static key.
     *  @param[out] out Receives @c secure_tunnel_key_size_k bytes, untouched on false.
     *  @return False until the handshake proves the peer holds the matching private half. A
     *    boolean rather than a fault, because there being no peer yet is an absence and not a
     *    failure - and the one caller does one thing with it: run the authorizer, or not.
     *
     *  A copy rather than a view, because this is the one answer that crosses the C ABI into
     *  code with no way to learn when a borrowed pointer went stale. A fixed extent rather than
     *  a span, because a parameter can carry one and a struct member cannot - so the width is
     *  checked by the compiler here and by @c make there, and neither is assumed. A key merely supplied by
     *  configuration - as @c IK and @c KK both do - is assumed, not proven, and is not reported
     *  here until the exchange completes.
     */
    [[nodiscard]] bool peer_key(byte_t out[secure_tunnel_key_size_k]) const noexcept;

    /**
     *  @brief Advances the tunnel by exactly one IO operation's worth of work.
     *
     *  @param[in] inbound Bytes buffered from the peer.
     *  @param[in] request What the caller wants. Defaulted, so the hot call site stays at one.
     *  @return @c outbound points into the tunnel and is valid until the next call on it.
     *
     *  @warning Absorbs the peer's message and produces whatever reply it owes in @b one call,
     *    then reports @c transmitting_k. No returned state obliges another @c advance without
     *    an intervening send or read. This function may loop internally; it may never make the
     *    caller loop. Without that rule every caller reconstructs the transition from byte
     *    counts, in its own order, and no driver can be shared between backends.
     *
     *  On first reaching @c ready_k, the bytes past @c consumed are the peer's first record and
     *  must be opened before posting a read, or both sides wait until the idle timeout.
     *
     *  Idempotent once the record layer is live, so a driver may call it on every completion
     *  without checking first.
     */
    [[nodiscard]] secure_tunnel_step_t advance(
        span<byte_t const> inbound, secure_tunnel_request_t request = secure_tunnel_request_t::proceed_k) noexcept;

    /**
     *  @brief Where a producer writes the payload of the record @p record will become.
     *  @param[in] record Caller memory, ideally @c geometry().record_size() bytes.
     *  @return The largest window inside @p record that a payload may occupy, empty when the
     *    buffer cannot hold even a minimal record or this side may no longer seal.
     *
     *  Total: a capacity to read, never a failure to diagnose. Serialise into this window and
     *  the bytes are already where the wire wants them - @c seal writes the framing around them
     *  and nothing is ever copied. This is the only place the layout rule lives, so no call site
     *  composes headroom and tailroom by hand.
     */
    [[nodiscard]] span<byte_t> payload_window(span<byte_t> record) const noexcept;

    /**
     *  @brief Seals @p filled payload bytes, written into @c payload_window, into one record.
     *  @param[in,out] record The same buffer that was handed to @c payload_window.
     *  @param[in] filled How many bytes the producer wrote there.
     *  @return The framed record, inside @p record, or an empty span on failure with @c fault() set.
     *
     *  The buffer and a length rather than a descriptor, because a record's layout is entirely
     *  determined by those two: the payload sits one headroom in, and the framing wraps it. A
     *  four-pointer window would carry the same information and invite a caller to hand back one
     *  that did not come from @c payload_window.
     */
    [[nodiscard]] span<byte_t const> seal(span<byte_t> record, std::size_t filled) noexcept;

    /**
     *  @brief Bytes still needed before the buffered prefix names a whole record.
     *  @return Zero once a whole record is present, and zero for a plaintext tunnel.
     *
     *  Const, keyless, and total: it never faults and never advances anything, which is what lets a
     *  driver ask it before it has any key and on every completion.
     *
     *  @warning Being keyless means it believes the prefix. A peer that inflates one makes this
     *    ask for bytes that will never arrive, and nothing here can tell that from a large record
     *    still in flight. The idle timeout is what closes such a connection, not this function.
     *
     *  A declared length the wire format does not allow still reads as a boundary here; that is
     *  @c open's to reject.
     */
    [[nodiscard]] std::size_t bytes_until_boundary(span<byte_t const> received) const noexcept;

    /**
     *  @brief Opens the first whole record in @p record, in place.
     *  @param[in,out] record A buffer whose front holds a complete record.
     *  @return The plaintext as a window into @p record, or a zero @c consumed on a malformed or
     *    unauthenticated record - in which case @c fault() says why and the tunnel is @c broken_k.
     *
     *  @warning A whole record must be present - @c bytes_until_boundary must have returned zero
     *    for this buffer. Calling with a partial record is a caller error, not an incomplete
     *    read, and is answered as one. That is what makes the outcome two-valued instead of
     *    three, and it costs nothing: both drivers already ask the boundary first.
     */
    [[nodiscard]] secure_tunnel_opened_t open(span<byte_t> record) noexcept;
};

#pragma endregion Tunnel

} // namespace unum::ucall
