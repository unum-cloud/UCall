/**
 *  @file bench/ucall_server.cpp
 *  @author Ash Vardanian
 *  @date October 25, 2026
 *  @brief Native UCall echo and sum server, with the flags and counters of the examples.
 */
#include <cstdint> // `std::int64_t`

#include <charconv>    // `std::from_chars`, `std::to_chars`
#include <limits>      // `std::numeric_limits`
#include <string_view> // `std::string_view`

#include "server.hpp"

static void reply(ucall_server_t server, ucall_received_http_request_t request, std::string_view content_type,
                  ucall_bytes_view_t body) {
    ucall_outcome_t outcome {};
    ucall_bytes_view_t const header = uc::bytes_view(content_type);
    ucall_server_reply_content_t content {server, &outcome, request, &header, 1, body, ucall_http_status_ok_k};
    ucall_server_reply_content(&content);
}

static void echo(ucall_received_http_request_t request, void* context) {
    ucall_server_t const server = *static_cast<ucall_server_t*>(context);
    ucall_outcome_t outcome {};
    ucall_bytes_view_t body {};
    ucall_server_request_body_t extract {server, &outcome, request, &body};
    ucall_server_request_body(&extract);
    reply(server, request, "content-type: application/octet-stream", body);
}

static bool query_integer(ucall_server_t server, ucall_received_http_request_t request, std::string_view name,
                          std::int64_t& integer) {
    ucall_outcome_t outcome {};
    ucall_bytes_view_t value {};
    ucall_server_request_query_parameter_t query {server, &outcome, request, uc::bytes_view(name), &value};
    ucall_server_request_query_parameter(&query);
    if (outcome.status != ucall_status_success_k) return false;
    std::string_view const text = uc::text_view(value);
    std::from_chars_result const parsed = std::from_chars(text.data(), text.data() + text.size(), integer);
    return parsed.ec == std::errc {} && parsed.ptr == text.data() + text.size();
}

static void sum(ucall_received_http_request_t request, void* context) {
    ucall_server_t const server = *static_cast<ucall_server_t*>(context);
    using limits_t = std::numeric_limits<std::int64_t>;
    std::int64_t a {}, b {};
    if (!query_integer(server, request, "a", a) || !query_integer(server, request, "b", b) ||
        (b > 0 ? a > limits_t::max() - b : a < limits_t::min() - b))
        return uc::tools::reply_error(server, request, ucall_http_status_bad_request_k,
                                      "Expected integers a and b with a representable sum\n");
    char digits[limits_t::digits10 + 2] {};
    char* const end = std::to_chars(digits, digits + sizeof(digits), a + b).ptr;
    reply(server, request, "content-type: text/plain", uc::bytes_view({digits, end}));
}

int main(int argc, char** argv) {
    uc::tools::server_t application {};
    if (int const result = application.init(argc, argv)) return result < 0 ? 1 : 0;
    if (!application.add_endpoint("/echo", ucall_verb_any_k, echo, &application.server) ||
        !application.add_endpoint("/sum", ucall_verb_get_k, sum, &application.server))
        return 1;
    return application.run();
}
