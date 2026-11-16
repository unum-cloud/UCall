/**
 *  @file src_stub/types.cpp
 *  @author Ash Vardanian
 *  @date November 16, 2026
 *  @brief The stand-in's outcome word, percent codec and Noise keys, real over the serial kits.
 *
 *  Names and the version come from @c src/types.cpp itself, which the stand-in compiles as is,
 *  so the two libraries can never spell a status differently.
 */
#include <cstring> // `std::memset`

#include <span> // `std::as_bytes`, `std::as_writable_bytes`

#include "ucall/http/percent.hpp"  // `percent_codec`
#include "ucall/tunnel/crypto.hpp" // `secure_tunnel_crypto`, `serial_x25519_kit_t`, `x25519_derive_public`

#include "lib.hpp"

using namespace unum::ucall;
using namespace unum::ucall::stub;

/** The serial kits' tunnel, whose operating-system entropy draws the keys. */
using serial_crypto_t = tunnel::secure_tunnel_crypto<tunnel::serial_sha256_kit_t, tunnel::serial_aes256_gcm_kit_t,
                                                     tunnel::serial_x25519_kit_t>;

extern "C" {

ucall_status_t ucall_outcome_status(ucall_outcome_t* outcome) {
    return atomic_ref<ucall_status_t const> {outcome->status}.load(std::memory_order_acquire);
}

ucall_status_t ucall_outcome_wait(ucall_outcome_t* outcome) {
    atomic_ref<ucall_status_t const> const status {outcome->status};
    ucall_status_t seen = status.load(std::memory_order_acquire);
    for (; seen == ucall_status_deferred_k; seen = status.load(std::memory_order_acquire))
        fu::standard_yield_t {}(&outcome->status, seen, 0u, fu::wait_uncapped_k);
    return seen;
}

ucall_status_t ucall_decode_percent(ucall_bytes_view_t encoded, ucall_byte_t* decoded, size_t* length,
                                    ucall_percent_mode_t mode) {
    if (!length || mode > ucall_percent_query_k || (encoded.length && (!encoded.data || !decoded)))
        return ucall_status_invalid_argument_k;
    return http::percent_codec<http::serial_byteset_kit_t>::decode(encoded, decoded, length, mode);
}

void ucall_noise_key_generate(ucall_noise_key_generate_t* arguments) {
    if (!arguments) return;
    if (arguments->private_key) std::memset(*arguments->private_key, 0, sizeof(ucall_noise_key_t));
    if (arguments->public_key) std::memset(*arguments->public_key, 0, sizeof(ucall_noise_key_t));
    if (!arguments->private_key || !arguments->public_key) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    // Entropy the platform refused is an I/O failure at the ABI, which names no tunnel faults.
    if (serial_crypto_t::secure_random_bytes(std::as_writable_bytes(std::span {*arguments->private_key})) !=
        tunnel::secure_tunnel_fault_t::none_k) {
        std::memset(*arguments->private_key, 0, sizeof(ucall_noise_key_t));
        publish(arguments->outcome, ucall_status_io_k);
        return;
    }
    tunnel::x25519_derive_public<tunnel::serial_x25519_kit_t>(
        std::as_writable_bytes(std::span {*arguments->public_key}), std::as_bytes(std::span {*arguments->private_key}));
    publish(arguments->outcome, ucall_status_success_k);
}

void ucall_noise_key_derive(ucall_noise_key_derive_t* arguments) {
    if (!arguments) return;
    if (arguments->public_key) std::memset(*arguments->public_key, 0, sizeof(ucall_noise_key_t));
    if (!arguments->private_key || !arguments->public_key) {
        publish(arguments->outcome, ucall_status_invalid_argument_k);
        return;
    }
    tunnel::x25519_derive_public<tunnel::serial_x25519_kit_t>(
        std::as_writable_bytes(std::span {*arguments->public_key}), std::as_bytes(std::span {*arguments->private_key}));
    publish(arguments->outcome, ucall_status_success_k);
}

} // extern "C"
