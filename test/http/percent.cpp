/**
 *  @file test/http/percent.cpp
 *  @author Ash Vardanian
 *  @date November 13, 2025
 *  @brief Path and query percent decoding through the C verb.
 */
#include "harness.hpp" // `expect`, `require`

namespace unum::ucall::test::http {

/** Path and query decoding through the C verb, in place and into a separate buffer. */
static std::size_t test_percent_codec() {
    std::size_t failures = 0;
    struct decoding_t {
        ucall_status_t status;
        std::string_view text;
    };
    char buffer[64] {};
    auto decode = [&](std::string_view encoded, ucall_percent_mode_t mode) noexcept {
        std::size_t length = 0;
        ucall_status_t const status = ucall_decode_percent(bytes_view(encoded), reinterpret_cast<ucall_byte_t*>(buffer),
                                                           &length, mode);
        return decoding_t {status, {buffer, status == ucall_status_success_k ? length : 0}};
    };
    auto decodes = [&](std::string_view encoded, ucall_percent_mode_t mode, std::string_view expected) noexcept {
        decoding_t const decoded = decode(encoded, mode);
        return expect(decoded.status == ucall_status_success_k && decoded.text == expected,
                      "'{}' decoded to '{}' with status {}, not '{}'", encoded, decoded.text,
                      ucall_status_name(decoded.status), expected);
    };
    failures += decodes("a+b%20c", ucall_percent_path_k, "a+b c");
    failures += decodes("a+b%20c", ucall_percent_query_k, "a b c");
    failures += decodes("%2B+%2b", ucall_percent_query_k, "+ +");
    failures += decodes("%E2%9c%93", ucall_percent_path_k, "\xE2\x9C\x93");
    failures += decodes("", ucall_percent_query_k, "");
    for (std::string_view malformed : {"100%", "%4", "%zz", "a%+20"})
        for (ucall_percent_mode_t mode : {ucall_percent_path_k, ucall_percent_query_k})
            failures += expect(decode(malformed, mode).status == ucall_status_invalid_argument_k,
                               "'{}' decoded although its escape is malformed", malformed);

    char in_place[] = "name=caf%C3%A9+au+lait&x=%2541";
    std::size_t length = 0;
    ucall_byte_t* const bytes = reinterpret_cast<ucall_byte_t*>(in_place);
    failures += expect(ucall_decode_percent({bytes, sizeof(in_place) - 1}, bytes, &length, ucall_percent_query_k) ==
                               ucall_status_success_k &&
                           std::string_view(in_place, length) == "name=caf\xC3\xA9 au lait&x=%41",
                       "decoding in place gave '{}'", std::string_view(in_place, length));
    return failures;
}

std::size_t check_percent(settings_t const& settings) {
    if (!settings.filter.selects("http percent")) return 0;
    return report("http percent", test_percent_codec());
}

} // namespace unum::ucall::test::http
