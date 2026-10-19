/**
 *  @file src/secure_tunnel.cpp
 *  @author Ash Vardanian
 *  @date August 9, 2026
 *  @brief The whole of UCall's encryption, compiled once.
 *
 *  @section What Is Here
 *
 *  `secure_tunnel.hpp` names a state machine and a size. This file is the only translation unit
 *  that knows what fills that size, which is why a backend driving a tunnel compiles not one line
 *  of cryptography and cannot accidentally depend on the layout of a key schedule.
 *
 *  The Noise specification builds a handshake from three nested pieces, and the regions below
 *  mirror them:
 *
 *  - @b CipherState wraps one AEAD key with a counter nonce - `secure_tunnel_cipher_t`.
 *  - @b SymmetricState adds the chaining key and running hash - `secure_tunnel_transcript_t`, named
 *    for what it accumulates rather than for the specification's section heading.
 *  - @b HandshakeState walks a pattern's tokens and, when they run out, splits into the two
 *    record-layer cipher states - `secure_tunnel_noise_t`.
 *
 *  @section Borrowed Pieces
 *
 *  SHA-256 and AES-256-GCM come from StringZilla, runtime-dispatched across Westmere, Ice Lake, and
 *  the NEON crypto extensions. HMAC and HKDF are built here on the SHA-256 state, whose transparent
 *  layout lets both padded midstates be cached across the three derivations one @c MixKey performs.
 *  Curve25519 lives in `crypto_x25519.cpp`, isolated because its constant-time discipline sits
 *  badly beside code compiled for throughput.
 *
 *  @section What Is Deliberately Absent
 *
 *  No allocation, no syscall other than the entropy draw, and no reference to a descriptor. The one
 *  buffer this file owns is the outbound scratch inside the connection's own storage, and it exists
 *  because handshake and close messages are generated rather than transformed.
 */
#include <cassert> // `assert`
#include <cstddef> // `std::size_t`
#include <cstdint> // `std::uint64_t`
#include <cstdlib> // `arc4random_buf`
#include <cstring> // `std::memcpy`, `std::memset`

#if defined(__linux__)
#include <sys/random.h> // `getrandom`
#elif defined(_WIN32)
#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h> // `BCryptGenRandom`
#endif

#include <new> // placement `new`

#include <stringzilla/cipher.h> // `sz_aes256_gcm_key_t`, `sz_aes256_gcm_encrypt_best`, `sz_aes256_gcm_decrypt_best`
#include <stringzilla/hash.h>   // `sz_sha256_state_t`, and its `_init` / `_update` / `_digest`

#include "crypto_x25519.hpp" // `x25519_scalar_multiply`, `x25519_derive_public`
#include "secure_tunnel.hpp" // the contract this file implements

namespace unum::ucall {
namespace {

[[nodiscard]] sz_capability_t crypto_capabilities() noexcept {
    static sz_capability_t const capabilities = [] {
        sz_capability_t enabled = 0;
        return sz_capabilities_enabled_cpu(&enabled) == sz_success_k ? enabled : sz_cap_serial_k;
    }();
    return capabilities;
}

#pragma region Wire Constants

/**
 *  @brief Output width of SHA-256, and therefore of every chaining value and derived key.
 *
 *  Defined in terms of the key width because this cipher suite pins both to thirty-two, not because
 *  a digest and a key are the same thing. A suite with a wider hash would break the equality, and
 *  this is the line that would have to say so.
 */
constexpr std::size_t hash_size_k = secure_tunnel_key_size_k;

/** Width of an AES-GCM authentication tag. */
constexpr std::size_t tag_size_k = 16;

/** The record kind, sealed one byte behind the payload and inside the tag. */
constexpr std::size_t kind_size_k = 1;

/** Width of the big-endian length that prefixes every message on the wire. */
constexpr std::size_t prefix_size_k = secure_tunnel_headroom_k;

/** Hard ceiling a two-byte prefix can name, and the specification's message limit besides. */
constexpr std::size_t max_message_k = 65535;

/**
 *  @brief Shortest a record's declared length may be: an empty payload, its kind, and the tag.
 *
 *  Accepting anything smaller lets a peer declare a length that decrypts to nothing, after which
 *  reading the kind byte behind a zero-length plaintext reads outside the buffer. The kind byte is
 *  what makes this seventeen rather than sixteen.
 */
constexpr std::size_t min_record_body_k = tag_size_k + kind_size_k;

/** Width of the AES-GCM nonce: 32 zero bits ahead of the 64-bit counter. */
constexpr std::size_t nonce_size_k = 12;

/**
 *  @brief The counter value the specification reserves for @c Rekey.
 *
 *  Reaching it means the key is exhausted, and encrypting under it would collide with the rekey
 *  derivation. Both directions refuse rather than wrap.
 */
constexpr std::uint64_t nonce_exhausted_k = ~static_cast<std::uint64_t>(0);

/**
 *  @brief Records sealed or opened under one key before it is replaced.
 *
 *  AES-GCM's forgery margin degrades with the volume encrypted under a single key, which is why TLS
 *  1.3 caps AES-GCM at roughly 2^24.5 records. At 16 KB a record this is a few gigabytes,
 *  comfortably inside the bound, and it needs no signalling because both sides count identically.
 *
 *  @warning The two sides stay in step only if every sealed record is also opened, the close record
 *      included. Anything that seals without the peer opening - or opens without the peer having
 *      sealed
 *  - desynchronises the two schedules, after which every subsequent record fails authentication
 *    with nothing in the logs to explain it.
 */
constexpr std::size_t rekey_interval_k = 1u << 20;

/**
 *  @brief Consecutive empty application records tolerated before the peer is treated as hostile.
 *
 *  An empty record is legal - TLS 1.3 §5.1 permits them and they are occasionally useful for
 *  traffic shaping - but each one costs an authenticated decryption and resets the connection's
 *  idle timer, so an unbounded run is a connection held open indefinitely at nineteen bytes apiece.
 *  Reset by the first record that carries anything.
 */
constexpr std::size_t empty_record_limit_k = 32;

/**
 *  @brief Largest handshake payload this side will accept from a peer and discard.
 *
 *  Our patterns write empty payloads, and a conforming peer under them sends nothing but the tag,
 *  so this buffer is committed on every handshake and filled on none.
 *
 *  It stays at a kilobyte rather than shrinking to what our own patterns emit. The Noise
 *  specification permits a payload in any handshake message, and refusing one we merely do not
 *  expect would break interoperation with a conformant peer for no gain - a kilobyte of stack on a
 *  thread with megabytes of it is not worth an interoperability failure. What the bound is actually
 *  for is the wire format's own 64 KB ceiling, which would be 64 KB of stack per handshake on the
 *  thread driving every other connection on the bind.
 *
 *  It is a stack frame rather than a window into the peer's bytes because @c advance takes its
 *  input @c const: a handshake payload is decrypted somewhere and then dropped, and the alternative
 *  is a mutable inbound buffer, which would let a driver hand the same bytes to two tunnels.
 */
constexpr std::size_t max_handshake_payload_k = 1024;

/**
 *  @brief Bytes reserved inside the connection's storage for what @c advance generates.
 *
 *  The widest handshake message any supported pattern writes carries an ephemeral in the clear, a
 *  static under the AEAD, and the empty payload's tag - ninety-eight bytes with its prefix. A close
 *  record's nineteen fit easily inside the same buffer, and the two are never live at once because
 *  a close cannot be requested before the handshake completes.
 *
 *  Checked against the header's private constant in @c secure_tunnel_t::make, where both are
 *  visible, so the two cannot drift.
 */
constexpr std::size_t outbound_capacity_k = 128;

#pragma endregion Wire Constants

#pragma region Secrets

/**
 *  @brief Overwrites secret bytes so that dead-store elimination cannot remove the write.
 *
 *  Every key, chaining value, and shared secret below is wiped on storage that dies immediately
 *  afterwards, which makes a plain @c memset a dead store the compiler may legally delete. Writing
 *  through a volatile pointer is what keeps it.
 */
void secure_zero(void* data, std::size_t length) noexcept {
    auto volatile* cursor = static_cast<byte_t volatile*>(data);
    for (std::size_t index = 0; index != length; ++index) cursor[index] = 0;
}

/**
 *  @brief Wipes a whole object or array, taking its width from the type.
 *
 *  One overload covers a fixed-width key, a key schedule, and a table of derived outputs alike,
 *  which is why no separate span-over-an-array helper exists: the width a caller would have had to
 *  spell is the width the compiler already knows.
 */
template <typename secret_type_>
void secure_zero(secret_type_& secret) noexcept {
    secure_zero(&secret, sizeof(secret));
}

/**
 *  @brief Fills @p output with bytes from the operating system's cryptographic generator.
 *  @return False when the platform refused, which must abort key generation rather than continue.
 *
 *  @warning Never substitute a fast pseudo-random generator here. StringZilla's @c sz_fill_random
 *      is an AES-based hash - excellent for buffers, and fatal for keys.
 */
[[nodiscard]] bool secure_random_bytes(byte_t* output, std::size_t length) noexcept {
#if defined(__linux__)
    while (length) {
        ssize_t const taken = ::getrandom(output, length, 0);
        if (taken <= 0) return false;
        output += taken;
        length -= static_cast<std::size_t>(taken);
    }
    return true;
#elif defined(_WIN32)
    return BCryptGenRandom(nullptr, output, static_cast<ULONG>(length), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
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
[[nodiscard]] std::size_t peek_length(span<byte_t const> input) noexcept {
    if (input.size() < prefix_size_k) return 0;
    return (static_cast<std::size_t>(input[0]) << 8) | static_cast<std::size_t>(input[1]);
}

void poke_length(byte_t* output, std::size_t length) noexcept {
    assert(length <= max_message_k && "a length prefix names at most sixty-five thousand bytes");
    output[0] = static_cast<byte_t>((length >> 8) & 0xFFu);
    output[1] = static_cast<byte_t>(length & 0xFFu);
}

/** Bytes still needed before @p received holds one whole prefixed message. */
[[nodiscard]] std::size_t bytes_until_prefixed_boundary(span<byte_t const> received) noexcept {
    if (received.size() < prefix_size_k) return prefix_size_k - received.size();
    std::size_t const whole = prefix_size_k + peek_length(received);
    return received.size() >= whole ? 0 : whole - received.size();
}

#pragma region HMAC and HKDF

/**
 *  @brief HMAC-SHA256 with both padded key states cached, per RFC 2104.
 *
 *  Noise derives keys two or three times per @c MixKey under the same key, so absorbing the inner
 *  and outer padding once and copying the midstates is worth the twelve lines. That @c
 *  sz_sha256_state_t is a transparent, trivially copyable struct is what makes it possible without
 *  StringZilla exporting anything extra.
 */
class hmac_sha256_t {

    /**
     *  @brief SHA-256's compression block, which RFC 2104 calls @c B.
     *
     *  Not a tuning knob. The padding constants are repeated exactly this many times and the key is
     *  zero-extended to exactly this width, so any other value computes something that is not HMAC.
     *  Distinct from the 32-byte digest, and confusing the two is the classic way to produce a tag
     *  that looks well-formed and interoperates with nobody - which is what the RFC 4231 vectors in
     *  `test/noise.cpp` exist to catch.
     */
    static constexpr std::size_t block_size_k = 64;

    sz_sha256_state_t inner_ {};
    sz_sha256_state_t outer_ {};

  public:
    void reset(span<byte_t const> key) noexcept {
        byte_t padded[block_size_k] {};
        if (key.size() > block_size_k) {
            sz_sha256_state_t shrink;
            sz_sha256_state_init_best(&shrink, crypto_capabilities(), nullptr);
            sz_sha256_state_update_best(&shrink, reinterpret_cast<sz_cptr_t>(key.data()), key.size(),
                                        crypto_capabilities(), nullptr);
            sz_sha256_state_digest_best(&shrink, padded, crypto_capabilities(), nullptr);
        }
        else if (key.size()) { std::memcpy(padded, key.data(), key.size()); }

        byte_t block[block_size_k];
        sz_sha256_state_init_best(&inner_, crypto_capabilities(), nullptr);
        for (std::size_t index = 0; index != block_size_k; ++index) block[index] = padded[index] ^ 0x36u;
        sz_sha256_state_update_best(&inner_, reinterpret_cast<sz_cptr_t>(block), block_size_k, crypto_capabilities(),
                                    nullptr);

        sz_sha256_state_init_best(&outer_, crypto_capabilities(), nullptr);
        for (std::size_t index = 0; index != block_size_k; ++index) block[index] = padded[index] ^ 0x5Cu;
        sz_sha256_state_update_best(&outer_, reinterpret_cast<sz_cptr_t>(block), block_size_k, crypto_capabilities(),
                                    nullptr);

        secure_zero(padded);
        secure_zero(block);
    }

    /** Computes the tag over one or two concatenated inputs, reusing both midstates. */
    void compute(span<byte_t const> first, span<byte_t const> second, byte_t output[hash_size_k]) const noexcept {
        sz_sha256_state_t inner = inner_;
        if (first.size())
            sz_sha256_state_update_best(&inner, reinterpret_cast<sz_cptr_t>(first.data()), first.size(),
                                        crypto_capabilities(), nullptr);
        if (second.size())
            sz_sha256_state_update_best(&inner, reinterpret_cast<sz_cptr_t>(second.data()), second.size(),
                                        crypto_capabilities(), nullptr);
        byte_t digest[hash_size_k];
        sz_sha256_state_digest_best(&inner, digest, crypto_capabilities(), nullptr);

        sz_sha256_state_t outer = outer_;
        sz_sha256_state_update_best(&outer, reinterpret_cast<sz_cptr_t>(digest), sizeof(digest), crypto_capabilities(),
                                    nullptr);
        sz_sha256_state_digest_best(&outer, output, crypto_capabilities(), nullptr);
        secure_zero(digest);
    }
};

/** One-shot HMAC-SHA256, for callers with no key to reuse. */
void hmac_sha256(span<byte_t const> key, span<byte_t const> data, byte_t output[hash_size_k]) noexcept {
    hmac_sha256_t hmac;
    hmac.reset(key);
    hmac.compute(data, {}, output);
}

/**
 *  @brief The Noise specification's HKDF, which is RFC 5869 with an empty info string.
 *  @param[in] outputs How many 32-byte outputs to derive: two, or three for a pattern with a
 *      pre-shared key. Each feeds the next, so they must be produced in order.
 */
void hkdf_sha256(span<byte_t const> chaining_key, span<byte_t const> material, std::size_t outputs,
                 byte_t results[3][hash_size_k]) noexcept {
    byte_t temporary_key[hash_size_k];
    hmac_sha256(chaining_key, material, temporary_key);

    hmac_sha256_t hmac;
    hmac.reset({temporary_key, temporary_key + hash_size_k});

    byte_t const counters[3] {0x01, 0x02, 0x03};
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
        sz_aes256_gcm_key_init_best(&schedule_, key_, crypto_capabilities(), nullptr);
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
     *  Before the first @c MixKey the state has no key and the specification says plaintext passes
     *  through untouched with no tag, which is how a handshake's opening message stays readable. A
     *  caller learns which happened from @c has_key rather than from a length it must compare.
     */
    [[nodiscard]] bool seal(span<byte_t const> associated, span<byte_t> text, byte_t* tag) noexcept {
        if (!keyed_) return true;
        if (exhausted()) return false;
        byte_t nonce[nonce_size_k];
        encode_nonce(nonce);
        sz_aes256_gcm_encrypt_best(&schedule_, nonce,                                                 //
                                   reinterpret_cast<sz_cptr_t>(associated.data()), associated.size(), //
                                   reinterpret_cast<sz_cptr_t>(text.data()), text.size(),             //
                                   reinterpret_cast<sz_ptr_t>(text.data()), tag, crypto_capabilities(), nullptr);
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
     *      unauthenticated plaintext behind, so a caller that ignores the result still cannot act
     *      on forged data - and cannot retry, which suits a caller that drops the connection
     *      anyway.
     */
    [[nodiscard]] bool open(span<byte_t const> associated, span<byte_t> text, byte_t const* tag) noexcept {
        if (!keyed_) return true;
        if (exhausted()) return false;
        byte_t nonce[nonce_size_k];
        encode_nonce(nonce);
        sz_status_t const status = sz_aes256_gcm_decrypt_best(
            &schedule_, nonce,                                                 //
            reinterpret_cast<sz_cptr_t>(associated.data()), associated.size(), //
            reinterpret_cast<sz_cptr_t>(text.data()), text.size(),             //
            reinterpret_cast<sz_ptr_t>(text.data()), tag, crypto_capabilities(), nullptr);
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
        sz_aes256_gcm_encrypt_best(&schedule_, nonce, nullptr, 0, reinterpret_cast<sz_cptr_t>(zeros), sizeof(zeros),
                                   reinterpret_cast<sz_ptr_t>(derived), tag, crypto_capabilities(), nullptr);

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
            sz_sha256_state_init_best(&state, crypto_capabilities(), nullptr);
            sz_sha256_state_update_best(&state, protocol_name, name_length, crypto_capabilities(), nullptr);
            sz_sha256_state_digest_best(&state, hash_, crypto_capabilities(), nullptr);
        }
        std::memcpy(chaining_key_, hash_, hash_size_k);
        cipher_.clear();
    }

    void mix_hash(span<byte_t const> data) noexcept {
        sz_sha256_state_t state;
        sz_sha256_state_init_best(&state, crypto_capabilities(), nullptr);
        sz_sha256_state_update_best(&state, reinterpret_cast<sz_cptr_t>(hash_), hash_size_k, crypto_capabilities(),
                                    nullptr);
        if (data.size())
            sz_sha256_state_update_best(&state, reinterpret_cast<sz_cptr_t>(data.data()), data.size(),
                                        crypto_capabilities(), nullptr);
        sz_sha256_state_digest_best(&state, hash_, crypto_capabilities(), nullptr);
    }

    void mix_key(byte_t const material[secure_tunnel_key_size_k]) noexcept {
        byte_t derived[3][hash_size_k];
        hkdf_sha256({chaining_key_, chaining_key_ + hash_size_k}, {material, material + secure_tunnel_key_size_k}, 2,
                    derived);
        std::memcpy(chaining_key_, derived[0], hash_size_k);
        cipher_.initialize(derived[1]);
        secure_zero(derived);
    }

    /**
     *  @brief Seals in place with the running hash as associated data, then absorbs the result.
     *  @param[out] written Bytes now occupying @p text and what follows: its width, plus a tag once
     *      a key exists - so zero is a legitimate answer for an empty payload before the first @c
     *      MixKey, and is why this reports success separately rather than through the count.
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
     *  afterwards from a staged copy would work only up to that copy's width and silently hash the
     *  plaintext beyond it, with the divergence surfacing one message later as an unexplained
     *  authentication failure.
     */
    [[nodiscard]] bool open_and_hash(span<byte_t const> sealed, span<byte_t> plain, std::size_t& produced) noexcept {
        if (cipher_.has_key() && sealed.size() < tag_size_k) return false;
        std::size_t const body = cipher_.has_key() ? sealed.size() - tag_size_k : sealed.size();
        if (plain.size() < body) return false;

        byte_t next_hash[hash_size_k];
        sz_sha256_state_t state;
        sz_sha256_state_init_best(&state, crypto_capabilities(), nullptr);
        sz_sha256_state_update_best(&state, reinterpret_cast<sz_cptr_t>(hash_), hash_size_k, crypto_capabilities(),
                                    nullptr);
        if (sealed.size())
            sz_sha256_state_update_best(&state, reinterpret_cast<sz_cptr_t>(sealed.data()), sealed.size(),
                                        crypto_capabilities(), nullptr);
        sz_sha256_state_digest_best(&state, next_hash, crypto_capabilities(), nullptr);

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
 *  One enumerator per configuration rather than two flags: the combinations are a closed set, and a
 *  pair of booleans can express "the initiator's but not the responder's", which no pattern here
 *  defines and no code below could serve.
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
constexpr secure_tunnel_pattern_t pattern_xx_k {
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
constexpr secure_tunnel_pattern_t pattern_ik_k {
    "Noise_IK_25519_AESGCM_SHA256",
    secure_tunnel_pre_shared_t::responder_static_k,
    2,
    {
        {secure_tunnel_token_t::ephemeral_k, secure_tunnel_token_t::ephemeral_static_k, secure_tunnel_token_t::static_k,
         secure_tunnel_token_t::static_static_k, secure_tunnel_token_t::end_k},
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
 *  @note No message carries a @c static_k, so the peer's key is never received and never promoted
 *      by the reading path. It is proven instead by the @c ss and @c es operations, whose results
 *      only agree if the peer holds the private half - which is why the promotion at @c
 *      finish_handshake is load-bearing for this pattern specifically.
 */
constexpr secure_tunnel_pattern_t pattern_kk_k {
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

[[nodiscard]] secure_tunnel_pattern_t const* pattern_for(secure_tunnel_mode_t mode) noexcept {
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
 *  @c IK and @c KK take the peer key from configuration and merely assume it until the handshake
 *  completes; @c XX learns it from the wire and authenticates it there. One flag conflates the two,
 *  and the difference is the whole value of asking who the peer is.
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
 *  Identical across all three patterns, which was checked rather than assumed: every one carries @c
 *  e and at least one static-touching token, so all six key buffers are live in all three and a
 *  union across modes would save nothing. What differs is the message count, the two pre-message
 *  flags, and when the peer's key becomes trustworthy - all carried by @c pattern and @c
 *  remote_static_state.
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

    /** Consecutive empty application records opened, reset by the first that carries bytes. */
    std::size_t empty_records {};

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
     *      would not help, since two dynamic spans are equally interchangeable; the fixed extent is
     *      what lets the compiler object to a digest or a nonce arriving here by mistake.
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
 *  deliberate act: it forces a shared secret the attacker already knows. Reporting it as anything
 *  but hostile would put an attack and an operating-system problem on the same line in the logs.
 */
[[nodiscard]] bool apply_diffie_hellman(secure_tunnel_noise_t& noise, secure_tunnel_token_t token,
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
 *  @brief Derives the record-layer keys, then destroys everything the handshake no longer needs.
 *
 *  The wipe is not tidiness. Forward secrecy is the entire reason Noise carries ephemerals: once
 *  the keys are split, an attacker who later compromises the static key - or simply reads this
 *  process's memory - must not be able to reconstruct session keys for traffic already sent, and
 *  they can if the ephemeral private half is still lying in the connection's storage. Roughly six
 *  hundred bytes of spent secret per connection, which at a thousand connections a bind is six
 *  hundred kilobytes of it resident for as long as the server runs.
 *
 *  Safe in every mode because the state is identical across the three patterns: no pattern needs
 *  any of these buffers after its own messages are exhausted. @c remote_static deliberately
 *  survives - it is the answer @c peer_key exists to give.
 */
void finish_handshake(secure_tunnel_noise_t& noise) noexcept {
    secure_tunnel_cipher_t first, second;
    noise.transcript.split(first, second);
    // The specification assigns the first state to the initiator's sending direction.
    noise.sending = noise.initiates() ? first : second;
    noise.receiving = noise.initiates() ? second : first;
    first.clear();
    second.clear();

    // A key merely configured is proven by here: every pattern that pre-shares one also performs a
    // Diffie-Hellman against it, and the transcripts agree only if the peer holds the private half.
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
 *      pool, a peer forcing a known shared secret, and an outbound buffer this build sized wrongly
 *      are three different problems calling for three different responses.
 *
 *  Runs @c finish_handshake when this was the pattern's last message, which is what makes the
 *  record layer usable on the write path - a caller may put its first record in the same write as
 *  the final handshake message rather than waiting a round trip to discover it could have.
 */
[[nodiscard]] bool write_handshake_message(secure_tunnel_noise_t& noise, secure_tunnel_fault_t& fault) noexcept {
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
            if (!noise.transcript.seal_and_hash({body + written, body + written + secure_tunnel_key_size_k}, sealed)) {
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

    // Every handshake message ends with a sealed payload. Ours are empty, which still contributes a
    // tag once a key exists, and nothing at all before that.
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
 *  @brief Reads the pattern message at @c message_index, discarding whatever payload it carried.
 *  @param[in] body The message without its length prefix.
 *  @param[out] fault Why it failed. A message too short to hold the field a token demands is @c
 *      malformed_k; a tag that did not verify is @c authentication_failed_k. Collapsing the two
 *      would make a truncating middlebox and an active attacker indistinguishable in the logs.
 *
 *  The prefix is deliberately not authenticated here, unlike a record's. The transcript is the
 *  Noise specification's, and mixing our framing into it would break interoperation with a
 *  conformant peer; a tampered handshake prefix mis-frames the message and is caught by the very
 *  next tag check regardless.
 */
[[nodiscard]] bool read_handshake_message(secure_tunnel_noise_t& noise, span<byte_t const> body,
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
            if (!noise.transcript.open_and_hash({body.data() + consumed, body.data() + consumed + expected},
                                                {noise.remote_static, noise.remote_static + secure_tunnel_key_size_k},
                                                produced)) {
                fault = secure_tunnel_fault_t::authentication_failed_k;
                return false;
            }
            if (produced != secure_tunnel_key_size_k) {
                fault = secure_tunnel_fault_t::malformed_k;
                return false;
            }
            // The tag verified against the transcript, so this key is proven rather than assumed.
            noise.remote_static_state = remote_static_t::authenticated_k;
            consumed += expected;
            break;
        }
        default:
            if (!apply_diffie_hellman(noise, token, fault)) return false;
            break;
        }
    }

    // The trailing payload. Our patterns always write an empty one, but the peer's still has to be
    // authenticated so that both transcripts advance identically.
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
 *  The prefix is written before the payload is sealed and passed as associated data, exactly as TLS
 *  1.3 authenticates its record header. That binds the declared length to the tag, so the same
 *  ciphertext cannot be presented under a framing it was not sealed with.
 *
 *  It is defence in depth rather than the only line: shortening a prefix also moves the tag, which
 *  the framing check would catch on its own. Lengthening one is not caught here at all - the
 *  boundary check must trust the prefix, so an inflated length simply makes the receiver wait. Only
 *  encrypting the length would close that, and BOLT #8 pays an authenticated-encryption invocation
 *  per record to do it.
 */
[[nodiscard]] std::size_t seal_record(secure_tunnel_noise_t& noise, byte_t* record, std::size_t filled,
                                      secure_tunnel_record_t kind) noexcept {
    std::size_t const declared = filled + kind_size_k + tag_size_k;
    poke_length(record, declared);
    record[prefix_size_k + filled] = static_cast<byte_t>(kind);

    byte_t* const body = record + prefix_size_k;
    std::size_t const plain_size = filled + kind_size_k;
    if (!noise.sending.seal({record, record + prefix_size_k}, {body, body + plain_size}, body + plain_size)) return 0;

    if (++noise.records_sealed % rekey_interval_k == 0) noise.sending.rekey();
    return prefix_size_k + declared;
}

#pragma endregion Records

/**
 *  @brief The Noise state living inside a tunnel's opaque storage.
 *
 *  A @c reinterpret_cast rather than anything cleverer, because the object really is there: the
 *  only way into these overloads is through a tunnel whose @c mode_ says @c make placement-newed
 *  one, and @c mode_ is assigned last precisely so a rejected configuration cannot get here.
 */
[[nodiscard]] secure_tunnel_noise_t& noise_of(byte_t* storage) noexcept {
    return *reinterpret_cast<secure_tunnel_noise_t*>(storage);
}

[[nodiscard]] secure_tunnel_noise_t const& noise_of(byte_t const* storage) noexcept {
    return *reinterpret_cast<secure_tunnel_noise_t const*>(storage);
}

} // namespace

#pragma region Tunnel

bool secure_tunnel_generate_keypair(byte_t private_half[secure_tunnel_key_size_k],
                                    byte_t public_half[secure_tunnel_key_size_k]) noexcept {
    if (!secure_random_bytes(private_half, secure_tunnel_key_size_k)) return false;
    x25519_derive_public(public_half, private_half);
    return true;
}

secure_tunnel_t::~secure_tunnel_t() noexcept { reset(); }

secure_tunnel_fault_t secure_tunnel_t::make(secure_tunnel_config_t const& config) noexcept {

    static_assert(outbound_capacity_k == max_outbound_k, "the outbound buffer and its advertised bound disagree");
    static_assert(sizeof(secure_tunnel_geometry_t) == 3 * sizeof(std::size_t),
                  "a field was added to the geometry that `geometry()` does not fill");
    static_assert(secure_tunnel_payload_ceiling_k + secure_tunnel_overhead_k == secure_tunnel_max_record_k,
                  "the record ceiling and the payload ceiling disagree about framing");

    reset();

    // Clamped downwards only, so asking for more than a two-byte prefix can name yields the wire
    // format's answer rather than a refusal.
    std::size_t const requested = config.max_payload ? config.max_payload : secure_tunnel_default_payload_k;
    max_payload_ = requested < secure_tunnel_payload_ceiling_k ? requested : secure_tunnel_payload_ceiling_k;
    role_ = config.role;

    if (config.mode == secure_tunnel_mode_t::plain_k) return secure_tunnel_fault_t::none_k;

    secure_tunnel_pattern_t const* const pattern = pattern_for(config.mode);
    if (!pattern) return fault_ = secure_tunnel_fault_t::misconfigured_k;

    // Every supported pattern either transmits this side's static key or performs a Diffie-Hellman
    // against it, in both roles - so an absent one would silently become a scalar of zeros.
    if (config.local_private.size() != secure_tunnel_key_size_k) return fault_ = secure_tunnel_fault_t::misconfigured_k;
    if (config.local_public.size() && config.local_public.size() != secure_tunnel_key_size_k)
        return fault_ = secure_tunnel_fault_t::misconfigured_k;
    if (config.remote_public.size() && config.remote_public.size() != secure_tunnel_key_size_k)
        return fault_ = secure_tunnel_fault_t::misconfigured_k;

    // A pre-message key this side is supposed to already know, and does not, cannot be recovered
    // from the wire: the transcript would diverge before the first message and every tag after it
    // would fail for a reason no log could distinguish from an attack.
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

    // Assigned last: until here the tunnel is still plaintext, so a configuration rejected above
    // leaves nothing constructed for `reset` to find and nothing for a driver to misread.
    mode_ = config.mode;
    state_ = secure_tunnel_state_t::starting_k;
    sending_ = direction_t::unavailable_k;
    receiving_ = direction_t::unavailable_k;
    return secure_tunnel_fault_t::none_k;
}

void secure_tunnel_t::reset() noexcept {
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

secure_tunnel_geometry_t secure_tunnel_t::geometry() const noexcept {
    secure_tunnel_geometry_t result;
    result.headroom = encrypts() ? secure_tunnel_headroom_k : 0;
    result.tailroom = encrypts() ? secure_tunnel_tailroom_k : 0;
    result.max_payload = max_payload_;
    return result;
}

std::size_t secure_tunnel_t::records_sealed() const noexcept {
    return encrypts() ? noise_of(storage_).records_sealed : 0;
}

std::size_t secure_tunnel_t::records_opened() const noexcept {
    return encrypts() ? noise_of(storage_).records_opened : 0;
}

bool secure_tunnel_t::peer_key(byte_t out[secure_tunnel_key_size_k]) const noexcept {
    if (!encrypts()) return false;
    auto const& noise = noise_of(storage_);
    if (noise.remote_static_state != remote_static_t::authenticated_k) return false;
    std::memcpy(out, noise.remote_static, secure_tunnel_key_size_k);
    return true;
}

secure_tunnel_step_t secure_tunnel_t::advance(span<byte_t const> inbound, secure_tunnel_request_t request) noexcept {

    secure_tunnel_step_t step;
    step.state = state_;
    if (state_ == secure_tunnel_state_t::broken_k) return step;

    // A plaintext tunnel has no handshake to drive and no close record to send. Its only control
    // action is shutting both directions at once: TCP's own half-close is the engine's business,
    // and inventing an in-band signal here would be a framing this mode does not have.
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
            state_ = noise.handshake_complete() ? secure_tunnel_state_t::ready_k : secure_tunnel_state_t::receiving_k;
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
            // Whatever the closing step handed over has been sent by now; handing it back a second
            // time would put a duplicate close record on the wire.
            noise.outbound_length = 0;
            step.state = state_;
            return step;

        case secure_tunnel_state_t::broken_k: step.state = state_; return step;
        }
    }
}

span<byte_t> secure_tunnel_t::payload_window(span<byte_t> record) const noexcept {
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

span<byte_t const> secure_tunnel_t::seal(span<byte_t> record, std::size_t filled) noexcept {

    // Every exit that names a fault also breaks the tunnel, so `fault()` and `state()` can never
    // describe the same connection differently. A caller that hands back more than
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

std::size_t secure_tunnel_t::bytes_until_boundary(span<byte_t const> received) const noexcept {
    if (!encrypts()) return 0;
    return bytes_until_prefixed_boundary(received);
}

secure_tunnel_opened_t secure_tunnel_t::open(span<byte_t> record) noexcept {

    secure_tunnel_opened_t opened;
    if (!encrypts()) {
        // Guarded because `consumed == 0` means failure, and an empty buffer is not one - it is a
        // caller asking a question with no bytes in hand.
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

    // A record arriving after the peer said it would send no more is a protocol violation, not a
    // race: its close was authenticated, so nothing legitimate follows it.
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
    case secure_tunnel_record_t::application_k:
        if (payload_size) { noise.empty_records = 0; }
        else if (++noise.empty_records > empty_record_limit_k) return fail(secure_tunnel_fault_t::malformed_k);
        break;
    case secure_tunnel_record_t::close_k:
        // A close carries nothing. Allowing a payload would give a peer a second, unnumbered way
        // to deliver bytes that the protocol above never sees.
        if (payload_size) return fail(secure_tunnel_fault_t::malformed_k);
        receiving_ = direction_t::shut_k;
        break;
    default:
        // An unknown kind is fatal rather than skipped. Ignoring it would let a future extension
        // mean one thing to a new peer and nothing to an old one, on the same authenticated stream.
        return fail(secure_tunnel_fault_t::malformed_k);
    }

    opened.payload = {body, body + payload_size};
    opened.consumed = whole;
    opened.kind = kind;
    return opened;
}

#pragma endregion Tunnel

} // namespace unum::ucall
