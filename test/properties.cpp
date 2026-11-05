/**
 *  @file test/properties.cpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief Seeded property cases over the parsers that read untrusted bytes, through the oracles
 *      the libFuzzer harnesses share.
 *
 *  Each case starts from valid messages and mutates them, so most draws reach deep into a parser
 *  while still covering the malformed paths; @c UCALL_SEED replays any failure.
 */
#include <string> // `std::string`

#include <fmt/ranges.h> // formatting the drawn routes and paths

#include "harness.hpp"    // `expect`, `run_test`, `scale_iterations`
#include "properties.hpp" // `check_http_fragmentation`, `check_route_match`, `check_url`, `check_multipart`

using namespace unum::ucall;
using namespace unum::ucall::test;

/** Requests every framing reaches: declared lengths, chunks with extensions and trailers, and
 *  a second request pipelined behind the first. */
static constexpr std::string_view request_seeds_k[] {
    "GET /echo HTTP/1.1\r\nHost: a\r\n\r\n",
    "POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello",
    "POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;x=y\r\n world\r\n0\r\n\r\n",
    "POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nTrailer: v\r\nOther: " //
    "w\r\n\r\n",
    "POST /a HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhiGET /b HTTP/1.1\r\nHost: a\r\n\r\n",
    "GET /echo HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
};

static std::string mutate(std::string text, random_generator_t& generator) {
    static constexpr std::string_view alphabet_k = "\r\n:;0123456789abcdefABCDEF -\t\x00\x7f\xff";
    for (std::size_t edits = generator.below(4); edits; --edits) {
        std::size_t const at = generator.below(text.size() + 1);
        switch (generator.below(4)) {
        case 0:
            if (at < text.size()) text[at] = alphabet_k[generator.below(alphabet_k.size())];
            break;
        case 1: text.insert(at, 1, alphabet_k[generator.below(alphabet_k.size())]); break;
        case 2:
            if (at < text.size()) text.erase(at, 1 + generator.below(4));
            break;
        default: text.insert(at, text.substr(generator.below(text.size() + 1), generator.below(8))); break;
        }
    }
    return text;
}

static case_result_t test_framing_fragmentation_property(random_generator_t& generator) {
    std::size_t failures = 0;
    announce("prefixes_and_streamed_bodies_agree_with_the_whole_wire");
    for (std::size_t iteration = 0; iteration != scale_iterations(20000); ++iteration) {
        std::string const wire = mutate(std::string(request_seeds_k[generator.below(std::size(request_seeds_k))]),
                                        generator);
        std::size_t cuts[8];
        std::size_t const count = generator.below(9);
        for (std::size_t index = 0; index != count; ++index) cuts[index] = generator.below(wire.size() + 1);
        std::sort(cuts, cuts + count);
        std::size_t const found = check_http_fragmentation(byte_span(wire), {cuts, count},
                                                           http::http_role_t::request_k);
        failures += expect(!found, "{} disagreements framing {:?} cut at {} points", found, wire, count);
        if (found) break;
    }
    return failures;
}

/** Joins @p count segments drawn from @p vocabulary into a path that starts with a slash. */
template <std::size_t size_>
static std::string draw_path(std::string_view const (&vocabulary)[size_], std::size_t count,
                             random_generator_t& generator) {
    std::string path;
    for (std::size_t index = 0; index != count; ++index) path += fmt::format("/{}", vocabulary[generator.below(size_)]);
    return path.empty() ? "/" : path;
}

static case_result_t test_route_match_property(random_generator_t& generator) {
    static constexpr std::string_view template_segments_k[] {"a", "b", "", "{x}", "{y}", "{*rest}"};
    static constexpr std::string_view path_segments_k[] {"a", "b", "", "c"};
    static constexpr ucall_verb_t verbs_k[] {ucall_verb_get_k, ucall_verb_post_k, ucall_verb_head_k, ucall_verb_any_k};
    std::size_t failures = 0;
    announce("the_trie_answers_as_the_linear_reference");
    for (std::size_t iteration = 0; iteration != scale_iterations(5000); ++iteration) {
        std::vector<std::string> templates, paths;
        std::vector<ucall_verb_t> verbs;
        for (std::size_t count = generator.below(9); count; --count) {
            templates.push_back(draw_path(template_segments_k, generator.below(4), generator));
            verbs.push_back(verbs_k[generator.below(std::size(verbs_k))]);
        }
        for (std::size_t count = 1 + generator.below(8); count; --count)
            paths.push_back(draw_path(path_segments_k, generator.below(5), generator) +
                            (generator.below(4) ? "" : "?q"));
        std::vector<std::string_view> template_views {templates.begin(), templates.end()},
            path_views {paths.begin(), paths.end()};
        std::size_t const found = check_route_match(template_views, verbs, path_views);
        failures += expect(!found, "{} disagreements routing {} over {}", found, paths, templates);
        if (found) break;
    }
    return failures;
}

#if UCALL_OS_POSIX_
static case_result_t test_url_and_redirect_property(random_generator_t& generator) {
    static constexpr std::string_view url_seeds_k[] {
        "http://127.0.0.1:8080/a/b?q=1#f", "http+noise://[::1]:9/", "http://host", "http://h:1?x", "http://h#frag",
    };
    static constexpr std::string_view location_seeds_k[] {"/c", "c/d", "?only", "../up", "#frag", ":9/x", "@evil/x"};
    std::size_t failures = 0;
    announce("urls_round_trip_and_relative_redirects_keep_the_origin");
    for (std::size_t iteration = 0; iteration != scale_iterations(20000); ++iteration) {
        std::string const url = mutate(std::string(url_seeds_k[generator.below(std::size(url_seeds_k))]), generator);
        std::string const location = mutate(std::string(location_seeds_k[generator.below(std::size(location_seeds_k))]),
                                            generator);
        std::size_t const found = check_url(url) + check_redirect_join("http://127.0.0.1:8080/a/b?q=1", location);
        failures += expect(!found, "{} broken promises parsing {:?} or joining {:?}", found, url, location);
        if (found) break;
    }
    return failures;
}
#endif // UCALL_OS_POSIX_

/** Bodies every delimiter rule reaches: a preamble, an empty part, a part holding a near miss, and
 *  a delimiter sharing its CRLF with the line before it. */
static constexpr std::string_view multipart_seeds_k[] {
    "--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nalpha\r\n--B\r\n\r\nbeta\r\n--B--\r\n",
    "preamble\r\n--B\r\n\r\n\r\n--B\r\n\r\n-B --B\r\n--B--",
    "--B\r\n--B--",
    "--B--",
};

static case_result_t test_multipart_property(random_generator_t& generator) {
    static constexpr std::string_view boundaries_k[] {"B", "-", "B--", "xyz"};
    std::size_t failures = 0;
    announce("parts_match_the_reference_and_stay_inside_the_body");
    for (std::size_t iteration = 0; iteration != scale_iterations(20000); ++iteration) {
        std::string const body = mutate(std::string(multipart_seeds_k[generator.below(std::size(multipart_seeds_k))]),
                                        generator);
        std::string_view const boundary = boundaries_k[generator.below(std::size(boundaries_k))];
        std::size_t const found = check_multipart(boundary, byte_span(body));
        failures += expect(!found, "{} disagreements splitting {:?} on {:?}", found, body, boundary);
        if (found) break;
    }
    return failures;
}

static case_result_t test_tunnel_records_property(random_generator_t& generator) {
    std::size_t failures = 0;
    property_tunnel_pair_t pair;
    require(failures, pair.draw(), "keys could not be drawn");
    announce("handshakes_refuse_or_advance_and_flipped_records_never_open");
    for (std::size_t iteration = 0; iteration != scale_iterations(500); ++iteration) {
        std::string input(generator.below(160), '\0');
        for (auto& byte : input) byte = static_cast<char>(generator.below(256));
        std::size_t const found = check_tunnel_records(byte_span(input), pair);
        failures += expect(!found, "{} broken promises on a {}-byte input", found, input.size());
        if (found) break;
    }
    return failures;
}

int main(int, char** argv) {
    install_test_signal_handlers();
    fmt::print("Hi, dear tester! You look nice today!\n");
    configure_tests();

    suite_totals_t totals {.program = argv[0]};
    run_test(totals, "test_framing_fragmentation_property", test_framing_fragmentation_property);
    run_test(totals, "test_route_match_property", test_route_match_property);
    run_test(totals, "test_multipart_property", test_multipart_property);
    run_test(totals, "test_tunnel_records_property", test_tunnel_records_property);
#if UCALL_OS_POSIX_
    run_test(totals, "test_url_and_redirect_property", test_url_and_redirect_property);
#endif
    return suite_exit_code(totals);
}
