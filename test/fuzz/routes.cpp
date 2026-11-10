/**
 *  @file test/fuzz/routes.cpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief libFuzzer harness for the route trie against the linear reference matcher.
 *
 *  The first input byte picks how many lines are templates, each prefixed by a byte picking its
 *  verb, and every later line is a path to match.
 */
#include <cstdlib> // `std::abort`

#include "properties.hpp" // `check_route_match`

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) {
    using namespace unum::ucall;
    if (!size) return 0;
    static constexpr ucall_verb_t verbs_k[] {ucall_verb_get_k, ucall_verb_post_k, ucall_verb_head_k, ucall_verb_any_k};
    std::size_t const templates_count = data[0] % 9;
    std::string_view text {reinterpret_cast<char const*>(data) + 1, size - 1};
    std::vector<std::string_view> templates, paths;
    std::vector<ucall_verb_t> verbs;
    while (!text.empty() && paths.size() != 8) {
        std::size_t const end = fu::min_of(text.find('\n'), text.size());
        std::string_view const line = text.substr(0, end);
        text.remove_prefix(fu::min_of(end + 1, text.size()));
        if (templates.size() == templates_count) paths.push_back(line);
        else if (!line.empty()) {
            verbs.push_back(verbs_k[static_cast<unsigned char>(line.front()) % 4]);
            templates.push_back(line.substr(1));
        }
    }
    if (test::check_route_match(templates, verbs, paths)) std::abort();
    return 0;
}
