/**
 *  @file src/secure_tunnel.cpp
 *  @author Ash Vardanian
 *  @date August 9, 2026
 *  @brief Key generation shared by the tunnel's capability specializations.
 */
#include "ucall/tunnel.hpp"

namespace unum::ucall {

secure_tunnel_fault_t secure_tunnel_generate_keypair(span<byte_t, secure_tunnel_key_size_k> private_half,
                                                     span<byte_t, secure_tunnel_key_size_k> public_half) noexcept {
    if (secure_tunnel_fault_t const fault =
            secure_tunnel_crypto<serial_sha256_kit_t, serial_aes256_gcm_kit_t>::secure_random_bytes(private_half);
        fault != secure_tunnel_fault_t::none_k)
        return fault;
    x25519_derive_public(public_half, private_half);
    return secure_tunnel_fault_t::none_k;
}

} // namespace unum::ucall
