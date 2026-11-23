/**
 *  @file test/fuzz/multipart.cpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief libFuzzer harness for splitting multipart/form-data bodies against the linear reference.
 *
 *  The input's first line is the boundary, and the rest the body.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build

#include <cstdlib> // `std::abort`

#include "properties.hpp" // `check_multipart`

namespace util = unum::ucall::utilities;

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) {
    using namespace unum::ucall;
    using util::byte_span;
    std::string_view const text {reinterpret_cast<char const*>(data), size};
    std::size_t const newline = fu::min_of(text.find('\n'), text.size());
    std::string_view const body = text.substr(fu::min_of(newline + 1, text.size()));
    if (test::check_multipart(text.substr(0, newline), byte_span(body))) std::abort();
    return 0;
}
