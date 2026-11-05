/**
 *  @file test/fuzz/url.cpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief libFuzzer harness for the client's URL parsing and its joins of relative redirects.
 *
 *  The input is a URL to parse, and its text past the first newline a redirect location.
 */
#include <cstdlib> // `std::abort`

#include "properties.hpp" // `check_url`, `check_redirect_join`

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) {
    using namespace unum::ucall;
    std::string_view const text {reinterpret_cast<char const*>(data), size};
    std::size_t const newline = std::min(text.find('\n'), text.size());
    if (test::check_url(text.substr(0, newline))) std::abort();
    if (newline != text.size() && test::check_redirect_join("http://127.0.0.1:8080/a/b?q=1", text.substr(newline + 1)))
        std::abort();
    return 0;
}
