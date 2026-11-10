/**
 *  @file include/ucall/tunnel/secure_tunnel.hpp
 *  @author Ash Vardanian
 *  @date August 9, 2026
 *  @brief One connection's record layer: plaintext, or a Noise handshake and authenticated records.
 */
#pragma once

#include <cassert>
#include <cstring>

#include <memory> // `std::construct_at`

#include "ucall/tunnel/crypto.hpp"   // `secure_tunnel_crypto`, the serial kits
#include "ucall/tunnel/types.hpp"    // `secure_tunnel_state_t`, `secure_tunnel_config_t`, `secure_tunnel_geometry_t`
#include "ucall/utilities/types.hpp" // `span`, `byte_t`

namespace unum::ucall::tunnel {

using utilities::byte_t;
using utilities::span;

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
 *  @warning A record buffer or destination handed to @c open and a slot handed to @c stage must not
 *      overlap the inbound buffer given to @c advance.
 *
 *  Absorbing the peer's message and writing the reply happen in one call, and opening may work in
 *  place, so a returned payload can alias the buffer it came from. Overlap corrupts a record
 *  pipelined behind a handshake message, silently, inside one live allocation no sanitizer sees.
 */
template <typename sha256_kit_type_, typename aes256_gcm_kit_type_, typename x25519_kit_type_>
class secure_tunnel {
    using crypto_t = secure_tunnel_crypto<sha256_kit_type_, aes256_gcm_kit_type_, x25519_kit_type_>;
    using remote_static_t = typename crypto_t::remote_static_t;
    using secure_tunnel_noise_t = typename crypto_t::secure_tunnel_noise_t;
    using secure_tunnel_pattern_t = typename crypto_t::secure_tunnel_pattern_t;

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
    ~secure_tunnel() noexcept { clear(); }

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

        clear();

        // Clamped downwards only, so asking for more than a two-byte prefix can name yields the
        // wire format's answer rather than a refusal.
        std::size_t const requested = config.max_payload ? config.max_payload : secure_tunnel_default_payload_k;
        max_payload_ = requested < secure_tunnel_payload_ceiling_k ? requested : secure_tunnel_payload_ceiling_k;
        role_ = config.role;

        if (config.mode == secure_tunnel_mode_t::plain_k) return secure_tunnel_fault_t::none_k;

        secure_tunnel_pattern_t const* const pattern = crypto_t::pattern_for(config.mode);
        if (!pattern) return fault_ = secure_tunnel_fault_t::misconfigured_k;

        // Every supported pattern either transmits this side's static key or performs a
        // Diffie-Hellman against it, in both roles - so an absent one would silently become a
        // scalar of zeros.
        if (config.local_private.size() != secure_tunnel_key_size_k)
            return fault_ = secure_tunnel_fault_t::misconfigured_k;
        if (config.local_public.size() && config.local_public.size() != secure_tunnel_key_size_k)
            return fault_ = secure_tunnel_fault_t::misconfigured_k;
        if (config.peer_public.size() && config.peer_public.size() != secure_tunnel_key_size_k)
            return fault_ = secure_tunnel_fault_t::misconfigured_k;

        // A pre-message key this side is supposed to already know, and does not, cannot be
        // recovered from the wire: the transcript would diverge before the first message and every
        // tag after it would fail for a reason no log could distinguish from an attack.
        bool const initiator = config.role == secure_tunnel_role_t::initiator_k;
        bool const needs_remote = initiator ? pattern->shares_responder_static() : pattern->shares_initiator_static();
        if (needs_remote && config.peer_public.size() != secure_tunnel_key_size_k)
            return fault_ = secure_tunnel_fault_t::misconfigured_k;

        auto& noise = *std::construct_at(reinterpret_cast<secure_tunnel_noise_t*>(storage_));
        noise.pattern = pattern;
        noise.role = config.role;

        std::memcpy(noise.local_static_private, config.local_private.data(), secure_tunnel_key_size_k);
        if (config.local_public.size())
            std::memcpy(noise.local_static_public, config.local_public.data(), secure_tunnel_key_size_k);
        else x25519_derive_public<x25519_kit_type_>(noise.local_static_public, noise.local_static_private);

        if (config.peer_public.size()) {
            std::memcpy(noise.remote_static, config.peer_public.data(), secure_tunnel_key_size_k);
            noise.remote_static_state = remote_static_t::configured_k;
        }

        noise.transcript.initialize(pattern->name);
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
    void clear() noexcept {
        if (encrypts()) {
            auto& noise = crypto_t::noise_of(storage_);
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
     *  Diagnostics rather than telemetry. They earn their place because the two counts drive the
     *  rekey schedules on the two ends independently, and a schedule that desynchronises is the one
     *  failure in this layer with no distinguishable symptom: every record after it fails
     *  authentication and looks exactly like an attack. Peers that agree must end a conversation
     *  with these two mirrored, which is a thing a test can assert and a log can print.
     */
    [[nodiscard]] std::size_t records_sealed() const noexcept {
        return encrypts() ? crypto_t::noise_of(storage_).records_sealed : 0;
    }
    [[nodiscard]] std::size_t records_opened() const noexcept {
        return encrypts() ? crypto_t::noise_of(storage_).records_opened : 0;
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
     *  with no way to learn when a borrowed pointer went stale. A fixed extent rather than a
     *  dynamic span, because a parameter can carry one and a struct member cannot - so the width is
     *  checked by the compiler here and by @c make there, and neither is assumed. A key merely
     *  supplied by configuration - as @c IK and @c KK both do - is assumed, not proven, and is not
     *  reported here until the exchange completes.
     */
    [[nodiscard]] bool peer_key(span<byte_t, secure_tunnel_key_size_k> out) const noexcept {
        if (!encrypts()) return false;
        auto const& noise = crypto_t::noise_of(storage_);
        if (noise.remote_static_state != remote_static_t::authenticated_k) return false;
        std::memcpy(out.data(), noise.remote_static, out.size_bytes());
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
     *      reports @c transmitting_k.
     *
     *  No returned state obliges another @c advance without an intervening send or read. This
     *  function may loop internally; it may never make the caller loop. Without that rule every
     *  caller reconstructs the transition from byte counts, in its own order, and no driver can be
     *  shared between backends.
     *
     *  On first reaching @c ready_k, the bytes past @c consumed are the peer's first record and
     *  must be opened before posting a read, or both sides wait until a client call's deadline or
     *  the server's saturation eviction closes the connection.
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
        // business, and inventing an in-band signal here would add a framing this mode lacks.
        if (!encrypts()) {
            if (request == secure_tunnel_request_t::close_k) {
                sending_ = direction_t::shut_k;
                receiving_ = direction_t::shut_k;
                state_ = secure_tunnel_state_t::closed_k;
            }
            step.state = state_;
            return step;
        }

        auto& noise = crypto_t::noise_of(storage_);
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
                    if (secure_tunnel_fault_t const reason = crypto_t::write_handshake_message(noise);
                        reason != secure_tunnel_fault_t::none_k)
                        return fail(reason);
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
                if (crypto_t::bytes_until_prefixed_boundary(pending)) {
                    step.state = state_;
                    return step;
                }
                std::size_t const declared = crypto_t::peek_length(pending);
                if (declared > crypto_t::max_message_k) return fail(secure_tunnel_fault_t::malformed_k);
                if (secure_tunnel_fault_t const reason = crypto_t::read_handshake_message(
                        noise, {pending.data() + crypto_t::prefix_size_k,
                                pending.data() + crypto_t::prefix_size_k + declared});
                    reason != secure_tunnel_fault_t::none_k)
                    return fail(reason);
                step.consumed += crypto_t::prefix_size_k + declared;

                if (noise.handshake_complete()) {
                    sending_ = direction_t::open_k;
                    receiving_ = direction_t::open_k;
                    state_ = secure_tunnel_state_t::ready_k;
                    continue;
                }

                // The peer's message obliged a reply, so it goes out in this same call rather than
                // making the caller come back and ask.
                if (secure_tunnel_fault_t const reason = crypto_t::write_handshake_message(noise);
                    reason != secure_tunnel_fault_t::none_k)
                    return fail(reason);
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
                    std::size_t const written = crypto_t::seal_record(noise, noise.outbound, 0,
                                                                      secure_tunnel_record_t::close_k);
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
     *      cannot hold even a minimal record or this side has shut its sending direction.
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
     *  @param[in,out] record The same buffer that was handed to @c payload_window.
     *  @param[in] filled How many bytes the producer wrote there.
     *  @return The framed record, inside @p record, or on failure an empty span, with @c fault()
     *      naming the reason.
     *
     *  The buffer and a length rather than a descriptor, because a record's layout is entirely
     *  determined by those two: the payload sits one headroom in, and the framing wraps it. A
     *  four-pointer window would carry the same information and invite a caller to hand back one
     *  that did not come from @c payload_window.
     */
    [[nodiscard]] span<byte_t const> seal(span<byte_t> record, std::size_t filled) noexcept {

        // Every exit that names a fault also breaks the tunnel, so `fault()` and `state()` can
        // never describe the same connection differently. A caller that hands back more than
        // `payload_window` offered has ignored a total answer, and stopping beats carrying on.
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

        auto& noise = crypto_t::noise_of(storage_);
        std::size_t const written = crypto_t::seal_record(noise, record, filled, secure_tunnel_record_t::application_k);
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
     *      still in flight. A client call's deadline or the server's saturation eviction closes
     *      such a connection, while this function never does.
     *
     *  A declared length the wire format does not allow still reads as a boundary here; that is
     *  @c open's to reject.
     */
    [[nodiscard]] std::size_t bytes_until_boundary(span<byte_t const> received) const noexcept {
        if (!encrypts()) return 0;
        return crypto_t::bytes_until_prefixed_boundary(received);
    }

    /**
     *  @brief Opens the first whole record in @p record into @p destination.
     *  @param[in] record A buffer whose front holds a complete record.
     *  @param[out] destination Room for the payload and its kind byte: the record's own body, one
     *      prefix in, to open in place, or memory that does not overlap the record. The record's
     *      declared length, which @c bytes_until_boundary of its prefix alone answers, always fits.
     *  @return The plaintext as a window into @p destination, or into @p record for a plaintext
     *      tunnel, which frames nothing; a zero @c consumed on a malformed or unauthenticated
     *      record - in which case @c fault() says why and the tunnel is @c broken_k.
     *
     *  @warning A whole record must be present - @c bytes_until_boundary must have returned zero
     *      for this buffer.
     *
     *  Calling with a partial record is a caller error, not an incomplete read, and is answered as
     *  one. That is what makes the outcome two-valued instead of three, and it costs nothing: both
     *  drivers already ask the boundary first.
     */
    [[nodiscard]] secure_tunnel_opened_t open(span<byte_t> record, span<byte_t> destination) noexcept {

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
        if (record.size() < crypto_t::prefix_size_k) return fail(secure_tunnel_fault_t::malformed_k);

        std::size_t const declared = crypto_t::peek_length(readable);
        // Bounded by this side's cap, as the peer's sender may have been configured wider.
        if (declared < crypto_t::min_record_body_k || declared - crypto_t::min_record_body_k > max_payload_)
            return fail(secure_tunnel_fault_t::malformed_k);
        std::size_t const whole = crypto_t::prefix_size_k + declared;
        std::size_t const plain_size = declared - crypto_t::tag_size_k;
        if (record.size() < whole || destination.size() < plain_size) return fail(secure_tunnel_fault_t::malformed_k);

        auto& noise = crypto_t::noise_of(storage_);
        byte_t* const body = record.data() + crypto_t::prefix_size_k;
        if (secure_tunnel_fault_t const opened = noise.receiving.open(
                {record.data(), record.data() + crypto_t::prefix_size_k}, {body, body + plain_size}, body + plain_size,
                destination.data());
            opened != secure_tunnel_fault_t::none_k)
            return fail(opened);

        if (++noise.records_opened % crypto_t::rekey_interval_k == 0) noise.receiving.rekey();

        // The kind is the last byte of the plaintext, inside the tag rather than beside it, so it
        // cannot be forged by flipping a cleartext byte.
        std::size_t const payload_size = plain_size - crypto_t::kind_size_k;
        auto const kind = static_cast<secure_tunnel_record_t>(destination[payload_size]);

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

        opened.payload = destination.first(payload_size);
        opened.consumed = whole;
        opened.kind = kind;
        return opened;
    }
};

/** Portable tunnel specialization for callers without a CPU dispatch point. */
using secure_tunnel_t = secure_tunnel<serial_sha256_kit_t, serial_aes256_gcm_kit_t, serial_x25519_kit_t>;

} // namespace unum::ucall::tunnel
