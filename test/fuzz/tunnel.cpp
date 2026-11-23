/**
 *  @file test/fuzz/tunnel.cpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief libFuzzer harness for Noise responders fed hostile first messages, and for records
 *      whose flipped bytes must never open.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build

#include <cstdlib> // `std::abort`

#include "properties.hpp" // `check_tunnel_records`, `property_tunnel_pair_t`

namespace util = unum::ucall::utilities;

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) {
    using namespace unum::ucall;
    using util::byte_t;
    // Keys are drawn once per process; the pair reconnects on them only after a refusal broke it.
    static test::property_tunnel_pair_t pair;
    static bool const drawn = pair.draw();
    if (!drawn || test::check_tunnel_records({reinterpret_cast<byte_t const*>(data), size}, pair)) std::abort();
    return 0;
}
