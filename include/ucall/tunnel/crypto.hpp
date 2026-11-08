/**
 *  @file include/ucall/tunnel/crypto.hpp
 *  @author Ash Vardanian
 *  @date August 9, 2026
 *  @brief SHA-256, AES-256-GCM and X25519 kits, with the Noise primitives and state over them.
 */
#pragma once

#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <cstring>

#include <string_view> // `std::string_view`

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

#include "ucall/tunnel/curve25519.hpp" // `x25519_multiply_serial`, `x25519_derive_public`
#include "ucall/tunnel/types.hpp"      // `secure_tunnel_fault_t`, `secure_tunnel_key_size_k`, `secure_tunnel_mode_t`
#include "ucall/utilities/types.hpp"   // `highest_kit`, `span`, `byte_t`

#if UCALL_OS_LINUX_
#include <sys/random.h> // `getrandom`
#elif UCALL_OS_WINDOWS_
#include <bcrypt.h> // `BCryptGenRandom`
#endif

namespace unum::ucall::tunnel {

using utilities::byte_t;
using utilities::highest_kit;
using utilities::span;

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

/** Saturated X25519 over 32×32 partial products, the floor of its ladder. */
struct serial_x25519_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_serial_k;
    static constexpr bool compiled_k = true;
    static constexpr auto multiply = x25519_multiply_serial;
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

#if STRINGZILLA_TARGET_HASWELL

/** Saturated X25519 over MULX, ADC and SBB chains. */
struct haswell_x25519_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_haswell_k;
    static constexpr bool compiled_k = true;
    static constexpr auto multiply = x25519_multiply_haswell;
};
#else

/** The kit this build cannot carry, kept so the ladder stays one list. */
struct haswell_x25519_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_haswell_k;
    static constexpr bool compiled_k = false;
};
#endif // STRINGZILLA_TARGET_HASWELL

#if STRINGZILLA_TARGET_NEON

/** Radix-51 X25519 over UMULH. */
struct neon_x25519_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_neon_k;
    static constexpr bool compiled_k = true;
    static constexpr auto multiply = x25519_multiply_neon;
};
#else

/** The kit this build cannot carry, kept so the ladder stays one list. */
struct neon_x25519_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_neon_k;
    static constexpr bool compiled_k = false;
};
#endif // STRINGZILLA_TARGET_NEON

/** The widest SHA-256 kit among the backends @p caps_ admits, newest first. */
template <sz_capability_t caps_>
using sha256_kit = typename highest_kit<caps_, serial_sha256_kit_t, neonsha_sha256_kit_t, goldmont_sha256_kit_t>::type;

/** The widest AES-256-GCM kit among the backends @p caps_ admits, newest first. */
template <sz_capability_t caps_>
using aes256_gcm_kit = typename highest_kit<caps_, serial_aes256_gcm_kit_t, icelake_aes256_gcm_kit_t,
                                            neonaes_aes256_gcm_kit_t, westmere_aes256_gcm_kit_t>::type;

/** The X25519 kit among the backends @p caps_ admits. */
template <sz_capability_t caps_>
using x25519_kit = typename highest_kit<caps_, serial_x25519_kit_t, haswell_x25519_kit_t, neon_x25519_kit_t>::type;

#pragma endregion Cipher Kits

/** Cryptographic primitives and pattern state over the hashing, cipher and X25519 kits it is
 *  handed. */
template <typename sha256_kit_type_, typename aes256_gcm_kit_type_, typename x25519_kit_type_>
struct secure_tunnel_crypto {
    using sha256_kit_t = sha256_kit_type_;
    using aes256_gcm_kit_t = aes256_gcm_kit_type_;
    using x25519_kit_t = x25519_kit_type_;

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
    static void secure_zero(span<byte_t> bytes) noexcept {
        byte_t volatile* const cursor = bytes.data();
        for (std::size_t index = 0; index != bytes.size(); ++index) cursor[index] = byte_t {};
    }

    /**
     *  @brief Wipes a whole object or array, taking its width from the type.
     *
     *  One overload covers a key schedule, a table of derived outputs, and a C key alike: the width
     *  a caller would have had to spell is the width the compiler already knows. A byte array or a
     *  span wipes the bytes it holds or views, never the span itself.
     */
    template <typename secret_type_>
    static void secure_zero(secret_type_& secret) noexcept {
        if constexpr (std::is_convertible_v<secret_type_&, span<byte_t>>) secure_zero(span<byte_t> {secret});
        else secure_zero(std::as_writable_bytes(span<secret_type_, 1> {&secret, 1}));
    }

    /**
     *  @brief Fills @p output with bytes from the operating system's cryptographic generator.
     *  @return @c secure_tunnel_fault_t::entropy_unavailable_k when the platform refused, which
     *      must abort key generation rather than continue.
     *
     *  @warning Never substitute a fast pseudo-random generator here. StringZilla's
     *      @c sz_fill_random is an AES-based hash - excellent for buffers, and fatal for keys.
     */
    [[nodiscard]] static secure_tunnel_fault_t secure_random_bytes(span<byte_t> output) noexcept {
#if UCALL_OS_LINUX_
        while (!output.empty()) {
            ssize_t const taken = ::getrandom(output.data(), output.size(), 0);
            if (taken < 0 && errno == EINTR) continue;
            if (taken <= 0) return secure_tunnel_fault_t::entropy_unavailable_k;
            output = output.subspan(static_cast<std::size_t>(taken));
        }
        return secure_tunnel_fault_t::none_k;
#elif UCALL_OS_WINDOWS_
        return BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(output.data()), static_cast<ULONG>(output.size()),
                               BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0
                   ? secure_tunnel_fault_t::none_k
                   : secure_tunnel_fault_t::entropy_unavailable_k;
#else
        arc4random_buf(output.data(), output.size());
        return secure_tunnel_fault_t::none_k;
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

    static void poke_length(span<byte_t, prefix_size_k> output, std::size_t length) noexcept {
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
         *  the RFC 4231 vectors in <tt>test/noise.cpp</tt> exist to catch.
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
        void compute(span<byte_t const> first, span<byte_t const> second,
                     span<byte_t, hash_size_k> output) const noexcept {
            sz_sha256_state_t inner = inner_;
            if (first.size()) sha_update(&inner, reinterpret_cast<sz_cptr_t>(first.data()), first.size(), nullptr);
            if (second.size()) sha_update(&inner, reinterpret_cast<sz_cptr_t>(second.data()), second.size(), nullptr);
            byte_t digest[hash_size_k];
            sha_digest(&inner, reinterpret_cast<sz_u8_t*>(digest), nullptr);

            sz_sha256_state_t outer = outer_;
            sha_update(&outer, reinterpret_cast<sz_cptr_t>(digest), sizeof(digest), nullptr);
            sha_digest(&outer, reinterpret_cast<sz_u8_t*>(output.data()), nullptr);
            secure_zero(digest);
        }
    };

    /** One-shot HMAC-SHA256, for callers with no key to reuse. */
    static void hmac_sha256(span<byte_t const> key, span<byte_t const> data,
                            span<byte_t, hash_size_k> output) noexcept {
        hmac_sha256_t hmac;
        hmac.reset(key);
        hmac.compute(data, {}, output);
    }

    /**
     *  @brief The Noise specification's HKDF, which is RFC 5869 with an empty info string.
     *  @param[in] chaining_key The running chaining key, which keys the extraction.
     *  @param[in] material The input key material to extract from.
     *  @param[in] outputs How many 32-byte outputs to derive: two, or three for a pattern with a
     *      pre-shared key. Each feeds the next, so they must be produced in order.
     *  @param[out] results Receives the derived outputs, one hash-sized block each.
     */
    static void hkdf_sha256(span<byte_t const> chaining_key, span<byte_t const> material, std::size_t outputs,
                            span<byte_t[hash_size_k], 3> results) noexcept {
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

    /** Whether a cipher holds a key yet. */
    enum class cipher_key_t : std::uint8_t { empty_k, keyed_k };

    /** One AEAD key with its message counter, per the specification's CipherState. */
    class secure_tunnel_cipher_t {

        sz_aes256_gcm_key_t schedule_ {};
        byte_t key_[secure_tunnel_key_size_k] {};
        std::uint64_t nonce_ {};
        cipher_key_t key_state_ {cipher_key_t::empty_k};

        /** Noise encodes the 96-bit nonce as 32 zero bits then the counter, big-endian. */
        void encode_nonce(span<byte_t, nonce_size_k> output) const noexcept {
            std::memset(output.data(), 0, 4);
            for (std::size_t index = 0; index != 8; ++index)
                output[4 + index] = static_cast<byte_t>(nonce_ >> (56 - 8 * index));
        }

      public:
        [[nodiscard]] bool has_key() const noexcept { return key_state_ == cipher_key_t::keyed_k; }

        /** True once this key has sealed or opened everything it may, and must be replaced. */
        [[nodiscard]] bool exhausted() const noexcept { return has_key() && nonce_ == nonce_exhausted_k; }

        void initialize(span<byte_t const, secure_tunnel_key_size_k> key) noexcept {
            std::memcpy(key_, key.data(), key.size_bytes());
            aes_init(&schedule_, reinterpret_cast<sz_u8_t const*>(key_), nullptr);
            nonce_ = 0;
            key_state_ = cipher_key_t::keyed_k;
        }

        void clear() noexcept {
            secure_zero(schedule_);
            secure_zero(key_);
            nonce_ = 0;
            key_state_ = cipher_key_t::empty_k;
        }

        /**
         *  @brief Seals @p plaintext in place and appends a tag behind it.
         *  @param[in] associated The bytes authenticated alongside the text but not sealed.
         *  @param[in,out] text The bytes to seal, which the ciphertext replaces.
         *  @param[out] tag Sixteen bytes immediately behind @p text, written on success.
         *  @return @c secure_tunnel_fault_t::keys_exhausted_k when the key is exhausted.
         *
         *  Before the first @c MixKey the state has no key and the specification says plaintext
         *  passes through untouched with no tag, which is how a handshake's opening message stays
         *  readable. A caller learns which happened from @c has_key rather than from a length it
         *  must compare.
         */
        [[nodiscard]] secure_tunnel_fault_t seal(span<byte_t const> associated, span<byte_t> text,
                                                 byte_t* tag) noexcept {
            if (!has_key()) return secure_tunnel_fault_t::none_k;
            if (exhausted()) return secure_tunnel_fault_t::keys_exhausted_k;
            byte_t nonce[nonce_size_k];
            encode_nonce(nonce);
            aes_encrypt(&schedule_, reinterpret_cast<sz_u8_t const*>(nonce),               //
                        reinterpret_cast<sz_cptr_t>(associated.data()), associated.size(), //
                        reinterpret_cast<sz_cptr_t>(text.data()), text.size(),             //
                        reinterpret_cast<sz_ptr_t>(text.data()), reinterpret_cast<sz_u8_t*>(tag), nullptr);
            ++nonce_;
            secure_zero(nonce);
            return secure_tunnel_fault_t::none_k;
        }

        /**
         *  @brief Verifies a tag and opens @p text into @p plaintext.
         *  @param[in] associated The bytes authenticated alongside the text but not sealed.
         *  @param[in] text The ciphertext body, without its tag.
         *  @param[in] tag Sixteen bytes immediately behind @p text.
         *  @param[out] plaintext Room for @p text.size() bytes: @p text itself to open in place, or
         *      memory that does not overlap it, as AES-GCM allows nothing in between.
         *  @return @c secure_tunnel_fault_t::authentication_failed_k when the tag does not verify,
         *      or @c secure_tunnel_fault_t::keys_exhausted_k when the key is, which closes the
         *      connection either way.
         *
         *  @warning StringZilla zeroes @p plaintext when the tag is rejected rather than leaving
         *      unauthenticated plaintext behind, so a caller that ignores the result still cannot
         *      act on forged data - and cannot retry, which suits a caller that drops the
         *      connection anyway.
         */
        [[nodiscard]] secure_tunnel_fault_t open(span<byte_t const> associated, span<byte_t const> text,
                                                 byte_t const* tag, byte_t* plaintext) noexcept {
            if (!has_key()) {
                if (text.size() && plaintext != text.data()) std::memcpy(plaintext, text.data(), text.size());
                return secure_tunnel_fault_t::none_k;
            }
            if (exhausted()) return secure_tunnel_fault_t::keys_exhausted_k;
            byte_t nonce[nonce_size_k];
            encode_nonce(nonce);
            sz_status_t const status = aes_decrypt(&schedule_, reinterpret_cast<sz_u8_t const*>(nonce),               //
                                                   reinterpret_cast<sz_cptr_t>(associated.data()), associated.size(), //
                                                   reinterpret_cast<sz_cptr_t>(text.data()), text.size(),             //
                                                   reinterpret_cast<sz_ptr_t>(plaintext),
                                                   reinterpret_cast<sz_u8_t const*>(tag), nullptr);
            secure_zero(nonce);
            if (status != sz_success_k) return secure_tunnel_fault_t::authentication_failed_k;
            ++nonce_;
            return secure_tunnel_fault_t::none_k;
        }

        /**
         *  @brief Replaces the key with one derived from it, per the specification's Rekey.
         *
         *  The counter deliberately survives, because Noise defines @c Rekey as changing the key
         *  without resetting @c n - which is what keeps a nonce from repeating across the boundary.
         */
        void rekey() noexcept {
            if (!has_key()) return;
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

        void initialize(std::string_view protocol_name) noexcept {
            if (protocol_name.size() <= hash_size_k) {
                std::memset(hash_, 0, hash_size_k);
                std::memcpy(hash_, protocol_name.data(), protocol_name.size());
            }
            else {
                sz_sha256_state_t state;
                sha_init(&state, nullptr);
                sha_update(&state, protocol_name.data(), protocol_name.size(), nullptr);
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

        void mix_key(span<byte_t const, secure_tunnel_key_size_k> material) noexcept {
            byte_t derived[3][hash_size_k];
            hkdf_sha256({chaining_key_, chaining_key_ + hash_size_k}, material, 2, derived);
            std::memcpy(chaining_key_, derived[0], hash_size_k);
            cipher_.initialize(derived[1]);
            secure_zero(derived);
        }

        /**
         *  @brief Seals in place with the running hash as associated data, then absorbs the result.
         *  @param[in,out] text The bytes to seal, which the ciphertext replaces.
         *  @param[out] written Bytes now occupying @p text and what follows: its width, plus a tag
         *      once a key exists - so zero is a legitimate answer for an empty payload before the
         *      first @c MixKey, and is why this reports its fault separately rather than through
         *      the count.
         */
        [[nodiscard]] secure_tunnel_fault_t seal_and_hash(span<byte_t> text, std::size_t& written) noexcept {
            byte_t* const tag = text.data() + text.size();
            if (secure_tunnel_fault_t const fault = cipher_.seal(hash(), text, tag);
                fault != secure_tunnel_fault_t::none_k)
                return fault;
            written = text.size() + (cipher_.has_key() ? tag_size_k : 0);
            mix_hash({text.data(), text.data() + written});
            return secure_tunnel_fault_t::none_k;
        }

        /**
         *  @brief Verifies against the running hash, then absorbs the ciphertext as it arrived.
         *  @param[in] sealed The message field as it came off the wire, tag included.
         *  @param[out] plain Receives the opened bytes, which must not alias @p sealed.
         *  @param[out] produced How many opened bytes @p plain now holds.
         *
         *  The successor hash is computed before opening, and committed only once the tag verifies,
         *  because the transcript must absorb the ciphertext rather than the plaintext. Deriving it
         *  afterwards from a staged copy would work only up to that copy's width and silently hash
         *  the plaintext beyond it, with the divergence surfacing one message later as an
         *  unexplained authentication failure.
         */
        [[nodiscard]] secure_tunnel_fault_t open_and_hash(span<byte_t const> sealed, span<byte_t> plain,
                                                          std::size_t& produced) noexcept {
            if (cipher_.has_key() && sealed.size() < tag_size_k) return secure_tunnel_fault_t::malformed_k;
            std::size_t const body = cipher_.has_key() ? sealed.size() - tag_size_k : sealed.size();
            if (plain.size() < body) return secure_tunnel_fault_t::malformed_k;

            byte_t next_hash[hash_size_k];
            sz_sha256_state_t state;
            sha_init(&state, nullptr);
            sha_update(&state, reinterpret_cast<sz_cptr_t>(hash_), hash_size_k, nullptr);
            if (sealed.size()) sha_update(&state, reinterpret_cast<sz_cptr_t>(sealed.data()), sealed.size(), nullptr);
            sha_digest(&state, reinterpret_cast<sz_u8_t*>(next_hash), nullptr);

            if (secure_tunnel_fault_t const fault = cipher_.open(hash(), {sealed.data(), sealed.data() + body},
                                                                 sealed.data() + body, plain.data());
                fault != secure_tunnel_fault_t::none_k)
                return fault;

            std::memcpy(hash_, next_hash, hash_size_k);
            produced = body;
            return secure_tunnel_fault_t::none_k;
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
     *  @brief @c XX - neither side knows the other in advance, and both authenticate during.
     *  @code{.unparsed}
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
     *  @brief @c IK - the initiator already knows the responder's static key.
     *  @code{.unparsed}
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
     *  @brief @c KK - both static keys are configured ahead of time, and neither is transmitted.
     *  @code{.unparsed}
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
         *  @return @c secure_tunnel_fault_t::authentication_failed_k on a small-order peer
         *      point, which must abort rather than continue with a shared secret an attacker
         *      already knows.
         *
         *  @warning Both parameters are exactly this wide and swapping them still compiles. A
         *      dynamic span would not help, since two of them are equally interchangeable; the
         *      fixed extent is what lets the compiler object to a nonce or a tag arriving here.
         */
        [[nodiscard]] secure_tunnel_fault_t mix_diffie_hellman(
            span<byte_t const, secure_tunnel_key_size_k> scalar,
            span<byte_t const, secure_tunnel_key_size_k> point) noexcept {
            byte_t shared[secure_tunnel_key_size_k];
            if (!x25519_kit_t::multiply(std::span {shared}, scalar, point))
                return secure_tunnel_fault_t::authentication_failed_k;
            transcript.mix_key(shared);
            secure_zero(shared);
            return secure_tunnel_fault_t::none_k;
        }

        [[nodiscard]] secure_tunnel_fault_t generate_ephemeral() noexcept {
            if (secure_tunnel_fault_t const fault = secure_random_bytes(local_ephemeral_private);
                fault != secure_tunnel_fault_t::none_k)
                return fault;
            x25519_derive_public<x25519_kit_t>(local_ephemeral_public, local_ephemeral_private);
            return secure_tunnel_fault_t::none_k;
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
     *  @return Why it failed, so a peer's small-order point is never logged as ours.
     *
     *  The only way this fails on well-formed input is a peer point of small order, which is a
     *  deliberate act: it forces a shared secret the attacker already knows. Reporting it as
     *  anything but hostile would put an attack and an operating-system problem on the same line in
     *  the logs.
     */
    [[nodiscard]] static secure_tunnel_fault_t apply_diffie_hellman(secure_tunnel_noise_t& noise,
                                                                    secure_tunnel_token_t token) noexcept {
        bool const initiator = noise.initiates();
        switch (token) {
        case secure_tunnel_token_t::ephemeral_ephemeral_k:
            return noise.mix_diffie_hellman(noise.local_ephemeral_private, noise.remote_ephemeral);
        case secure_tunnel_token_t::ephemeral_static_k:
            return initiator ? noise.mix_diffie_hellman(noise.local_ephemeral_private, noise.remote_static)
                             : noise.mix_diffie_hellman(noise.local_static_private, noise.remote_ephemeral);
        case secure_tunnel_token_t::static_ephemeral_k:
            return initiator ? noise.mix_diffie_hellman(noise.local_static_private, noise.remote_ephemeral)
                             : noise.mix_diffie_hellman(noise.local_ephemeral_private, noise.remote_static);
        case secure_tunnel_token_t::static_static_k:
            return noise.mix_diffie_hellman(noise.local_static_private, noise.remote_static);
        // A token no pattern in this file emits, which means the pattern table and this switch
        // disagree - a build-time mistake rather than anything the peer did.
        default: return secure_tunnel_fault_t::misconfigured_k;
        }
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
     *  @return Why it failed. Never a single code for every cause - an exhausted entropy pool, a
     *      peer forcing a known shared secret, and an outbound buffer this build sized wrongly are
     *      three different problems calling for three different responses.
     *
     *  Runs @c finish_handshake when this was the pattern's last message, which is what makes the
     *  record layer usable on the write path - a caller may put its first record in the same write
     *  as the final handshake message rather than waiting a round trip to discover it could have.
     */
    [[nodiscard]] static secure_tunnel_fault_t write_handshake_message(secure_tunnel_noise_t& noise) noexcept {
        if (noise.handshake_complete()) return secure_tunnel_fault_t::misconfigured_k;

        byte_t* const body = noise.outbound + prefix_size_k;
        std::size_t const capacity = outbound_capacity_k - prefix_size_k;
        std::size_t written = 0;

        for (secure_tunnel_token_t const token : noise.pattern->messages[noise.message_index]) {
            if (token == secure_tunnel_token_t::end_k) break;
            switch (token) {
            case secure_tunnel_token_t::ephemeral_k: {
                if (secure_tunnel_fault_t const fault = noise.generate_ephemeral();
                    fault != secure_tunnel_fault_t::none_k)
                    return fault;
                if (written + secure_tunnel_key_size_k > capacity) return secure_tunnel_fault_t::misconfigured_k;
                std::memcpy(body + written, noise.local_ephemeral_public, secure_tunnel_key_size_k);
                noise.transcript.mix_hash(
                    {noise.local_ephemeral_public, noise.local_ephemeral_public + secure_tunnel_key_size_k});
                written += secure_tunnel_key_size_k;
                break;
            }
            case secure_tunnel_token_t::static_k: {
                if (written + secure_tunnel_key_size_k + tag_size_k > capacity)
                    return secure_tunnel_fault_t::misconfigured_k;
                std::memcpy(body + written, noise.local_static_public, secure_tunnel_key_size_k);
                std::size_t sealed = 0;
                if (secure_tunnel_fault_t const fault = noise.transcript.seal_and_hash(
                        {body + written, body + written + secure_tunnel_key_size_k}, sealed);
                    fault != secure_tunnel_fault_t::none_k)
                    return fault;
                written += sealed;
                break;
            }
            default:
                if (secure_tunnel_fault_t const fault = apply_diffie_hellman(noise, token);
                    fault != secure_tunnel_fault_t::none_k)
                    return fault;
                break;
            }
        }

        // Every handshake message ends with a sealed payload. Ours are empty, which still
        // contributes a tag once a key exists, and nothing at all before that.
        if (written + tag_size_k > capacity) return secure_tunnel_fault_t::misconfigured_k;
        std::size_t trailer = 0;
        if (secure_tunnel_fault_t const fault = noise.transcript.seal_and_hash({body + written, body + written},
                                                                               trailer);
            fault != secure_tunnel_fault_t::none_k)
            return fault;
        written += trailer;

        poke_length(span<byte_t> {noise.outbound}.first<prefix_size_k>(), written);
        noise.outbound_length = prefix_size_k + written;
        ++noise.message_index;
        if (noise.handshake_complete()) finish_handshake(noise);
        return secure_tunnel_fault_t::none_k;
    }

    /**
     *  @brief Reads the pattern message at @c message_index, discarding whatever payload it
     *      carried.
     *  @param[in,out] noise The handshake state the message advances.
     *  @param[in] body The message without its length prefix.
     *  @return Why it failed. A message too short to hold the field a token demands is
     *      @c malformed_k; a tag that did not verify is @c authentication_failed_k. Collapsing the
     *      two would make a truncating middlebox and an active attacker indistinguishable in the
     *      logs.
     *
     *  The prefix is deliberately not authenticated here, unlike a record's. The transcript is the
     *  Noise specification's, and mixing our framing into it would break interoperation with a
     *  conformant peer; a tampered handshake prefix mis-frames the message and is caught by the
     *  very next tag check regardless.
     */
    [[nodiscard]] static secure_tunnel_fault_t read_handshake_message(secure_tunnel_noise_t& noise,
                                                                      span<byte_t const> body) noexcept {
        if (noise.handshake_complete()) return secure_tunnel_fault_t::misconfigured_k;

        std::size_t const length = body.size();
        std::size_t consumed = 0;

        for (secure_tunnel_token_t const token : noise.pattern->messages[noise.message_index]) {
            if (token == secure_tunnel_token_t::end_k) break;
            switch (token) {
            case secure_tunnel_token_t::ephemeral_k: {
                if (consumed + secure_tunnel_key_size_k > length) return secure_tunnel_fault_t::malformed_k;
                std::memcpy(noise.remote_ephemeral, body.data() + consumed, secure_tunnel_key_size_k);
                noise.transcript.mix_hash({noise.remote_ephemeral, noise.remote_ephemeral + secure_tunnel_key_size_k});
                consumed += secure_tunnel_key_size_k;
                break;
            }
            case secure_tunnel_token_t::static_k: {
                std::size_t const expected = noise.transcript.cipher().has_key() ? secure_tunnel_key_size_k + tag_size_k
                                                                                 : secure_tunnel_key_size_k;
                if (consumed + expected > length) return secure_tunnel_fault_t::malformed_k;
                std::size_t produced = 0;
                if (secure_tunnel_fault_t const fault = noise.transcript.open_and_hash(
                        {body.data() + consumed, body.data() + consumed + expected},
                        {noise.remote_static, noise.remote_static + secure_tunnel_key_size_k}, produced);
                    fault != secure_tunnel_fault_t::none_k)
                    return fault;
                if (produced != secure_tunnel_key_size_k) return secure_tunnel_fault_t::malformed_k;
                // The tag verified against the transcript, so this key is proven rather than
                // assumed.
                noise.remote_static_state = remote_static_t::authenticated_k;
                consumed += expected;
                break;
            }
            default:
                if (secure_tunnel_fault_t const fault = apply_diffie_hellman(noise, token);
                    fault != secure_tunnel_fault_t::none_k)
                    return fault;
                break;
            }
        }

        // The trailing payload. Our patterns always write an empty one, but the peer's still has to
        // be authenticated so that both transcripts advance identically.
        byte_t payload[max_handshake_payload_k];
        std::size_t produced = 0;
        if (length - consumed > sizeof(payload) + tag_size_k) return secure_tunnel_fault_t::malformed_k;
        if (secure_tunnel_fault_t const fault = noise.transcript.open_and_hash(
                {body.data() + consumed, body.data() + length}, {payload, payload + sizeof(payload)}, produced);
            fault != secure_tunnel_fault_t::none_k)
            return fault;
        secure_zero(payload);

        ++noise.message_index;
        if (noise.handshake_complete()) finish_handshake(noise);
        return secure_tunnel_fault_t::none_k;
    }

#pragma endregion Handshake Steps

#pragma region Records

    /**
     *  @brief Seals @p filled payload bytes sitting one prefix into @p record, as one whole record.
     *  @param[in,out] noise The established session state, whose sending cipher seals the record.
     *  @param[in,out] record The buffer holding the payload at one prefix in, which becomes it.
     *  @param[in] filled How many payload bytes sit behind the prefix.
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
    [[nodiscard]] static std::size_t seal_record(secure_tunnel_noise_t& noise, span<byte_t> record, std::size_t filled,
                                                 secure_tunnel_record_t kind) noexcept {
        std::size_t const declared = filled + kind_size_k + tag_size_k;
        assert(record.size() >= prefix_size_k + declared && "the record must hold its prefix, payload and tag");
        poke_length(record.first<prefix_size_k>(), declared);
        record[prefix_size_k + filled] = static_cast<byte_t>(kind);

        span<byte_t> const body = record.subspan(prefix_size_k);
        std::size_t const plain_size = filled + kind_size_k;
        if (noise.sending.seal(record.first(prefix_size_k), body.first(plain_size), body.data() + plain_size) !=
            secure_tunnel_fault_t::none_k)
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

} // namespace unum::ucall::tunnel
