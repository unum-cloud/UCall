/**
 *  @file test/http/multipart.cpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief Seeded multipart bodies against the reference splitter the libFuzzer harness shares.
 */
#include <string> // `std::string`

#include "harness.hpp"    // `expect`, `scale_iterations`, `mutate`
#include "properties.hpp" // `check_multipart`

namespace unum::ucall::test::http {

using namespace unum::ucall::http;

/** Bodies every delimiter rule reaches: a preamble, an empty part, a part holding a near miss, and
 *  a delimiter sharing its CRLF with the line before it. */
static constexpr std::string_view multipart_seeds_k[] {
    "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nalpha\r\n--B\r\n\r\nbeta\r\n--B--\r\n",
    "preamble\r\n--B\r\n\r\n\r\n--B\r\n\r\n-B --B\r\n--B--",
    "--B\r\n--B--",
    "--B--",
};

static std::size_t test_multipart(random_generator_t& generator) {
    static constexpr std::string_view boundaries_k[] {"B", "-", "B--", "xyz"};
    std::size_t failures = 0;
    for (std::size_t iteration = 0; iteration != scale_iterations(20000); ++iteration) {
        std::string const body = mutate(std::string(multipart_seeds_k[generator.below(std::size(multipart_seeds_k))]),
                                        generator);
        std::string_view const boundary = boundaries_k[generator.below(std::size(boundaries_k))];
        std::size_t const found = test::check_multipart(boundary, byte_span(body));
        failures += expect(!found, "{} disagreements splitting {:?} on {:?}", found, body, boundary);
        if (found) break;
    }
    using named_t = std::pair<std::string_view, std::string_view>;
    for (auto [value, name] : {named_t {"form-data; x; name=\"a\"", "a"}, named_t {"form-data; name=a; x", "a"},
                               named_t {"form-data; x;name=\"a;b\"; y", "a;b"}, named_t {"form-data; x", ""}}) {
        std::string_view const read = header_parameter<property_http_t>(value, "name");
        failures += expect(read == name, "{:?} named {:?}", value, read);
    }
    return failures;
}

std::size_t check_multipart(settings_t const& settings) {
    if (!settings.filter.selects("http multipart")) return 0;
    random_generator_t generator {stream_key(settings.seed, "http multipart")};
    return report("http multipart", test_multipart(generator));
}

} // namespace unum::ucall::test::http
