/**
 *  @file test/fuzz/http.cpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief libFuzzer harness for request framing: whole, cut into pieces, and streamed.
 *
 *  The first byte picks how many cuts follow, each next byte is one cut, and the rest is the wire.
 */
#include <cstdlib> // `std::abort`

#include <algorithm> // `std::sort`

#include "properties.hpp" // `check_http_fragmentation`

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) {
    using namespace unum::ucall;
    if (size < 2) return 0;
    std::size_t cuts[8];
    std::size_t const count = std::min<std::size_t>(data[0] % 9, size - 1);
    std::size_t const wire_size = size - 1 - count;
    for (std::size_t index = 0; index != count; ++index)
        cuts[index] = wire_size ? data[1 + index] % (wire_size + 1) : 0;
    std::sort(cuts, cuts + count);
    span<byte_t const> const wire {reinterpret_cast<byte_t const*>(data) + 1 + count, wire_size};
    if (test::check_http_fragmentation(wire, {cuts, count}, http::http_role_t::request_k)) std::abort();
    if (test::check_http_fragmentation(wire, {cuts, count}, http::http_role_t::response_k)) std::abort();
    return 0;
}
