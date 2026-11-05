/**
 *  @file examples/echo/server.cpp
 *  @author Ash Vardanian
 *  @date May 13, 2024
 *  @brief Binary HTTP echo service for transport benchmarks.
 */
#include <cstdint> // `std::uint64_t`
#include <cstdio>  // `std::snprintf`

#include <array>       // `std::array`
#include <charconv>    // `std::from_chars`
#include <limits>      // `std::numeric_limits`
#include <mutex>       // `std::mutex`, `std::lock_guard`
#include <span>        // `std::span`
#include <string_view> // `std::string_view`

#include <smashtable/basic_hash_table.hpp>
#include <stringzilla/hash/serial.h>

#include "server.hpp"

static void echo(ucall_received_http_request_t request, void* context) {
    ucall_server_t const server = *static_cast<ucall_server_t*>(context);
    ucall_outcome_t outcome {};
    ucall_bytes_view_t body {};
    ucall_server_request_body_t extract {server, &outcome, request, &body};
    ucall_server_request_body(&extract);
    ucall_server_reply_content_t reply {server, &outcome, request, ucall_http_status_ok_k, nullptr, 0, body};
    ucall_server_reply_content(&reply);
}

namespace st = ashvardanian::smashtable;
using pair_key_t = std::array<std::uint64_t, 3>;

struct pair_hash_t {
    std::size_t operator()(pair_key_t const& key) const noexcept {
        return static_cast<std::size_t>(sz_hash_serial_(reinterpret_cast<char const*>(key.data()), sizeof(key), 0));
    }
};
using pair_table_t = st::hash_map<pair_key_t, std::array<ucall_received_http_request_t, 2>, pair_hash_t>;
struct reordered_t {
    ucall_server_t server {};
    std::mutex mutex;
    pair_table_t pending;
};

static void reordered(ucall_received_http_request_t request, void* context) {
    reordered_t& service = *static_cast<reordered_t*>(context);
    ucall_outcome_t outcome {};
    ucall_bytes_view_t key_view {}, member_view {};
    ucall_server_request_header_t header {service.server, &outcome, request, uc::bytes_view("x-ucall-pair"), &key_view};
    ucall_server_request_header(&header);
    bool valid = outcome.status == ucall_status_success_k && key_view.length;
    header.name = uc::bytes_view("x-ucall-member");
    header.value = &member_view;
    ucall_server_request_header(&header);
    valid &= outcome.status == ucall_status_success_k && member_view.length == 1 &&
             (member_view.data[0] == '0' || member_view.data[0] == '1');
    pair_key_t key {};
    std::string_view text = uc::text_view(key_view);
    for (std::size_t i = 0; valid && i != key.size(); ++i) {
        auto parsed = std::from_chars(text.data(), text.data() + text.size(), key[i]);
        valid = parsed.ec == std::errc {} &&
                (i + 1 == key.size() ? parsed.ptr == text.data() + text.size()
                                     : parsed.ptr != text.data() + text.size() && *parsed.ptr == ':');
        if (valid && i + 1 != key.size()) text.remove_prefix(parsed.ptr + 1 - text.data());
    }
    if (!valid)
        return uc::tools::reply_error(service.server, request, ucall_http_status_bad_request_k,
                                      "Expected pair ID and member 0 or 1\n");
    std::array<ucall_received_http_request_t, 2> pair {};
    {
        std::lock_guard<std::mutex> lock {service.mutex};
        auto found = service.pending.find(key);
        if (found == service.pending.end()) {
            auto inserted = service.pending.emplace<pair_table_t::emplace_report_t::insert_result_k>(key, pair);
            if (inserted.failed())
                return uc::tools::reply_error(service.server, request, ucall_http_status_service_unavailable_k,
                                              "Allocation failed\n");
            found = inserted.position;
        }
        auto& pending = (*found).mapped;
        std::size_t const member = static_cast<std::size_t>(member_view.data[0] - '0');
        if (pending[member])
            return uc::tools::reply_error(service.server, request, ucall_http_status_conflict_k,
                                          "Duplicate pair member\n");
        pending[member] = request;
        if (!pending[0] || !pending[1]) return;
        pair = pending;
        service.pending.erase(found);
    }
    for (std::size_t member : {1u, 0u}) {
        ucall_received_http_request_t const held = pair[member];
        ucall_bytes_view_t body {};
        ucall_server_request_body_t extract {service.server, &outcome, held, &body};
        ucall_server_request_body(&extract);
        char pair_header[sizeof("x-ucall-pair: ::") + 3 * (std::numeric_limits<std::uint64_t>::digits10 + 1)] {};
        int const length = std::snprintf(
            pair_header, sizeof(pair_header), "x-ucall-pair: %llu:%llu:%llu", static_cast<unsigned long long>(key[0]),
            static_cast<unsigned long long>(key[1]), static_cast<unsigned long long>(key[2]));
        ucall_bytes_view_t headers[] = {uc::bytes_view({pair_header, static_cast<std::size_t>(length)}),
                                        uc::bytes_view(member ? "x-ucall-member: 1" : "x-ucall-member: 0")};
        ucall_server_reply_content_t reply {service.server, &outcome, held, ucall_http_status_ok_k, headers, 2, body};
        ucall_server_reply_content(&reply);
    }
}

static void echo_batch(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
    std::span<ucall_received_http_request_t const> const batch {requests, count};
    for (ucall_received_http_request_t const request : batch) echo(request, context);
}

int main(int argc, char** argv) {
    uc::tools::server_t application {};
    if (int const result = application.init(argc, argv)) return result < 0 ? 1 : 0;
    reordered_t service;
    service.server = application.server;
    if (!application.add_endpoint("/echo", ucall_verb_post_k, echo, &application.server) ||
        !application.add_endpoint("/echo/reordered", ucall_verb_post_k, reordered, &service) ||
        !application.add_batch_endpoint("/echo/batch", ucall_verb_post_k, echo_batch, &application.server))
        return 1;
    return application.run();
}
