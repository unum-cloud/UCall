/**
 *  @file bench/ucall_server.cpp
 *  @author Ash Vardanian
 *  @date October 25, 2026
 *  @brief Native UCall echo, sum and file server, with the flags and counters of the examples.
 */
#include <cstddef> // `std::size_t`
#include <cstdint> // `std::int64_t`

#include <charconv>    // `std::from_chars`, `std::to_chars`
#include <limits>      // `std::numeric_limits`
#include <string_view> // `std::string_view`
#include <utility>     // `std::move`
#include <vector>      // `std::vector`

#include <forkunion/atomics.hpp> // `fu::preferred_atomic_ref`
#include <forkunion/types.hpp>   // `fu::default_alignment_k`

#include "ucall/ucall.hpp" // `uc::request_t`, `uc::deferred`, `uc::status_t`, `uc::bytes_view`
#include "server.hpp"      // `uc::tools::server_t`

namespace uc = unum::ucall;
namespace fu = ashvardanian::forkunion;

/** Answers @p request with an error @p status and a plain-text @p message. */
static void reply_error(uc::request_t request, ucall_http_status_t status, std::string_view message) noexcept {
    [[maybe_unused]] uc::status_t const replied = std::move(request).reply_error(status, message);
}

static void echo(uc::request_t request) noexcept {
    auto [body, body_status] = request.body();
    if (body_status.failed()) return reply_error(std::move(request), ucall_http_status_bad_request_k, "No body\n");
    ucall_bytes_view_t const header = uc::bytes_view("content-type: application/octet-stream");
    [[maybe_unused]] uc::status_t const replied = std::move(request).reply(ucall_http_status_ok_k, {&header, 1}, body);
}

static bool query_integer(uc::request_t const& request, std::string_view name, std::int64_t& integer) noexcept {
    auto [text, text_status] = request.query(name);
    if (text_status.failed()) return false;
    std::from_chars_result const parsed = std::from_chars(text.data(), text.data() + text.size(), integer);
    return parsed.ec == std::errc {} && parsed.ptr == text.data() + text.size();
}

static void sum(uc::request_t request) noexcept {
    using limits_t = std::numeric_limits<std::int64_t>;
    std::int64_t a {}, b {};
    if (!query_integer(request, "a", a) || !query_integer(request, "b", b) ||
        (b > 0 ? a > (limits_t::max)() - b : a < (limits_t::min)() - b))
        return reply_error(std::move(request), ucall_http_status_bad_request_k,
                           "Expected integers a and b with a representable sum\n");
    char digits[limits_t::digits10 + 2] {};
    char* const end = std::to_chars(digits, digits + sizeof(digits), a + b).ptr;
    ucall_bytes_view_t const header = uc::bytes_view("content-type: text/plain");
    [[maybe_unused]] uc::status_t const replied = std::move(request).reply(ucall_http_status_ok_k, {&header, 1},
                                                                           {digits, end});
}

/** Sends file @c {name} beneath the reply directory: each reply stays deferred until this polling
 *  thread sends it, so it lives in a slot of a ring holding every exchange the server may hold,
 *  twice over, and the claim passes slots still sending rather than wait on them here. */
struct file_server_t {
    std::vector<uc::deferred<>> replies;
    alignas(fu::default_alignment_k) std::size_t cursor {};

    uc::deferred<>& claim() noexcept {
        for (;;) {
            std::size_t const index = fu::preferred_atomic_ref<std::size_t> {cursor}.fetch_add(1) % replies.size();
            if (replies[index].status() != uc::status_code_t::deferred_k) return replies[index];
        }
    }

    void file(uc::request_t request) noexcept {
        auto [name, name_status] = request.path_parameter("name");
        if (name_status.failed())
            return reply_error(std::move(request), ucall_http_status_bad_request_k, "Expected /file/{name}\n");
        ucall_reply_part_t const part = uc::path_part({.directory_index = 0, .relative_path = uc::bytes_view(name)});
        ucall_bytes_view_t const header = uc::bytes_view("content-type: application/octet-stream");
        [[maybe_unused]] uc::status_t const queued = std::move(request).reply_parts(ucall_http_status_ok_k,
                                                                                    {&header, 1}, {&part, 1}, claim());
    }
};

int main(int argc, char** argv) {
    file_server_t files {};
    uc::tools::server_t application {};
    if (int const result = application.init(argc, argv)) return result < 0 ? 1 : 0;
    files.replies = std::vector<uc::deferred<>>(2 * application.connections * application.pipelined_requests);
    uc::server_t& server = application.server;
    if (server.route<echo>("/echo", ucall_verb_any_k).failed() || server.get<sum>("/sum").failed() ||
        server.get<&file_server_t::file>("/file/{name}", files).failed())
        return 1;
    return application.run();
}
