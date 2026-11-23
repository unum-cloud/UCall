/**
 *  @file test/fuzz/dns.cpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief libFuzzer harness for the stub resolver's answer decoder.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build

#include <cstdlib> // `std::abort`

#include "properties.hpp" // `check_dns_answer`

namespace util = unum::ucall::utilities;

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) {
    using namespace unum::ucall;
    using util::byte_t;
    static dns::wire_name_t const question = [] {
        dns::wire_name_t wire {};
        [[maybe_unused]] bool const spelt = dns::spell_name("a.example", wire);
        return wire;
    }();
    if (test::check_dns_answer({reinterpret_cast<byte_t const*>(data), size}, question)) std::abort();
    return 0;
}
