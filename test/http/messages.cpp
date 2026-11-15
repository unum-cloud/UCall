/**
 *  @file test/http/messages.cpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief Seeded fragmentation of the request framing and of URLs and redirects, through the
 *      oracles the libFuzzer harnesses share.
 */
#include <string> // `std::string`

#include "harness.hpp"    // `expect`, `scale_iterations`, `mutate`
#include "properties.hpp" // `check_http_fragmentation`, `check_url`, `check_redirect_join`

namespace unum::ucall::test::http {

using namespace unum::ucall::http;

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

static std::size_t test_framing_fragmentation(random_generator_t& generator) {
    std::size_t failures = 0;
    for (std::size_t iteration = 0; iteration != scale_iterations(20000); ++iteration) {
        std::string const wire = mutate(std::string(request_seeds_k[generator.below(std::size(request_seeds_k))]),
                                        generator);
        std::size_t cuts[8];
        std::size_t const count = generator.below(9);
        // Cuts slide into place as drawn; `std::sort` over this array trips GCC's bounds analysis.
        for (std::size_t index = 0; index != count; ++index) {
            std::size_t const cut = generator.below(wire.size() + 1);
            std::size_t slot = index;
            for (; slot && cuts[slot - 1] > cut; --slot) cuts[slot] = cuts[slot - 1];
            cuts[slot] = cut;
        }
        std::size_t const found = check_http_fragmentation(byte_span(wire), {cuts, count}, http_role_t::request_k);
        failures += expect(!found, "{} disagreements framing {:?} cut at {} points", found, wire, count);
        if (found) break;
    }
    return failures;
}

#if UCALL_OS_POSIX_
static std::size_t test_url_and_redirect(random_generator_t& generator) {
    static constexpr std::string_view url_seeds_k[] {
        "http://127.0.0.1:8080/a/b?q=1#f", "http+noise://[::1]:9/", "http://host", "http://h:1?x", "http://h#frag",
    };
    static constexpr std::string_view location_seeds_k[] {"/c", "c/d", "?only", "../up", "#frag", ":9/x", "@evil/x"};
    std::size_t failures = 0;
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

std::size_t check_http_messages(settings_t const& settings) {
    if (!settings.filter.selects("http messages")) return 0;
    random_generator_t generator {stream_key(settings.seed, "http messages")};
    std::size_t failures = test_framing_fragmentation(generator);
#if UCALL_OS_POSIX_
    failures += test_url_and_redirect(generator);
#endif
    return report("http messages", failures);
}

} // namespace unum::ucall::test::http
