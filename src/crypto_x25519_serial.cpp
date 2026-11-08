/**
 *  @file src/crypto_x25519_serial.cpp
 *  @author Ash Vardanian
 *  @date August 4, 2026
 *  @brief The serial X25519 kit: saturated limbs over 32×32 partial products.
 */
#include "crypto_x25519.hpp"

namespace unum::ucall {

bool tunnel::x25519_multiply_serial(span<byte_t, x25519_key_size_k> out, span<byte_t const, x25519_key_size_k> scalar,
                                    span<byte_t const, x25519_key_size_k> point) noexcept {
    struct unit_t {};
    return scalar_multiply_through<field_saturated<serial_words<unit_t>>>(out, scalar, point);
}

} // namespace unum::ucall
