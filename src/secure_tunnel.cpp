/**
 *  @file src/secure_tunnel.cpp
 *  @author Ash Vardanian
 *  @date August 9, 2026
 *  @brief Key generation shared by the tunnel's capability specializations.
 */
#include "ucall/tunnel.hpp"

namespace unum::ucall {

bool secure_tunnel_generate_keypair(span<byte_t, secure_tunnel_key_size_k> private_half,
                                    span<byte_t, secure_tunnel_key_size_k> public_half) noexcept {
    if (!secure_tunnel_crypto<serial_sha256_kit_t, serial_aes256_gcm_kit_t>::secure_random_bytes(private_half))
        return false;
    x25519_derive_public(public_half, private_half);
    return true;
}

} // namespace unum::ucall
