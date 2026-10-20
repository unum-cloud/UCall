/**
 *  @file examples/echo/server.cpp
 *  @author Ash Vardanian
 *  @date May 13, 2024
 *  @brief Binary HTTP echo service for transport benchmarks.
 */
#include <cstdio>
#include <cstdint>
#include <cstring>

#include <array>
#include <charconv>
#include <limits>
#include <mutex>
#include <string_view>

#include <smashtable/basic_hash_table.hpp>
#include <stringzilla/hash/serial.h>

#include "../server.hpp"

static ucall_bytes_view_t view(char const* text) {
    return {reinterpret_cast<ucall_byte_t const*>(text), std::strlen(text)};
}

static void echo(ucall_received_http_request_t request, void* context) {
    auto server = *static_cast<ucall_server_t*>(context);
    ucall_outcome_t outcome {};
    ucall_bytes_view_t body {};
    ucall_server_request_body_t extract {server, &outcome, request, &body};
    ucall_server_request_body(&extract);
    ucall_server_reply_content_t reply {server, &outcome, request, nullptr, 0, body, ucall_http_status_ok_k};
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
    auto& service = *static_cast<reordered_t*>(context);
    ucall_outcome_t outcome {};
    ucall_bytes_view_t key_view {}, member_view {};
    ucall_server_request_header_t header {service.server, &outcome, request, view("x-ucall-pair"), &key_view};
    ucall_server_request_header(&header);
    bool valid = outcome.status == ucall_status_success_k && key_view.length;
    header.name = view("x-ucall-member");
    header.value = &member_view;
    ucall_server_request_header(&header);
    valid &= outcome.status == ucall_status_success_k && member_view.length == 1 &&
             (member_view.data[0] == '0' || member_view.data[0] == '1');
    pair_key_t key {};
    auto text = std::string_view {reinterpret_cast<char const*>(key_view.data), key_view.length};
    for (std::size_t i = 0; valid && i != key.size(); ++i) {
        auto parsed = std::from_chars(text.data(), text.data() + text.size(), key[i]);
        valid = parsed.ec == std::errc {} &&
                (i + 1 == key.size() ? parsed.ptr == text.data() + text.size()
                                     : parsed.ptr != text.data() + text.size() && *parsed.ptr == ':');
        if (valid && i + 1 != key.size()) text.remove_prefix(parsed.ptr + 1 - text.data());
    }
    auto fail = [&](ucall_http_status_t status, char const* message) {
        ucall_server_reply_error_t reply {service.server, &outcome, request, status, view(message)};
        ucall_server_reply_error(&reply);
    };
    if (!valid) return fail(ucall_http_status_bad_request_k, "Expected pair ID and member 0 or 1\n");
    std::array<ucall_received_http_request_t, 2> pair {};
    {
        std::lock_guard<std::mutex> lock {service.mutex};
        auto found = service.pending.find(key);
        if (found == service.pending.end()) {
            auto inserted = service.pending.emplace<pair_table_t::emplace_report_t::insert_result_k>(key, pair);
            if (inserted.failed()) return fail(ucall_http_status_service_unavailable_k, "Allocation failed\n");
            found = inserted.position;
        }
        auto& pending = (*found).mapped;
        auto member = static_cast<std::size_t>(member_view.data[0] - '0');
        if (pending[member]) return fail(ucall_http_status_conflict_k, "Duplicate pair member\n");
        pending[member] = request;
        if (!pending[0] || !pending[1]) return;
        pair = pending;
        service.pending.erase(found);
    }
    for (auto member : {1u, 0u}) {
        auto held = pair[member];
        ucall_bytes_view_t body {};
        ucall_server_request_body_t extract {service.server, &outcome, held, &body};
        ucall_server_request_body(&extract);
        char pair_header[sizeof("x-ucall-pair: ::") + 3 * (std::numeric_limits<std::uint64_t>::digits10 + 1)] {};
        auto length = std::snprintf(pair_header, sizeof(pair_header), "x-ucall-pair: %llu:%llu:%llu",
                                    static_cast<unsigned long long>(key[0]), static_cast<unsigned long long>(key[1]),
                                    static_cast<unsigned long long>(key[2]));
        ucall_bytes_view_t headers[] = {
            {reinterpret_cast<ucall_byte_t const*>(pair_header), static_cast<std::size_t>(length)},
            view(member ? "x-ucall-member: 1" : "x-ucall-member: 0")};
        ucall_server_reply_content_t reply {service.server, &outcome, held, headers, 2, body, ucall_http_status_ok_k};
        ucall_server_reply_content(&reply);
    }
}

static void echo_batch(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
    for (std::size_t i = 0; i != count; ++i) echo(requests[i], context);
}

static void health(ucall_received_http_request_t request, void* context) {
    auto server = *static_cast<ucall_server_t*>(context);
    ucall_outcome_t outcome {};
    ucall_server_reply_content_t reply {server, &outcome, request, nullptr, 0, view("ready\n"), ucall_http_status_ok_k};
    ucall_server_reply_content(&reply);
}

int main(int argc, char** argv) {
    examples::server_t application {};
    if (auto result = application.init(argc, argv)) return result < 0 ? 1 : 0;
    ucall_outcome_t outcome {};
    ucall_server_add_http_endpoint_t add {application.server, &outcome, view("/echo"),
                                          ucall_verb_post_k,  echo,     &application.server};
    ucall_server_add_http_endpoint(&add);
    if (!application.succeeded(outcome)) return 1;
    reordered_t service;
    service.server = application.server;
    add.uri_template = view("/echo/reordered");
    add.callback = reordered;
    add.context = &service;
    ucall_server_add_http_endpoint(&add);
    if (!application.succeeded(outcome)) return 1;
    add.context = &application.server;
    add.uri_template = view("/health");
    add.verb = ucall_verb_get_k;
    add.callback = health;
    ucall_server_add_http_endpoint(&add);
    if (!application.succeeded(outcome)) return 1;
    ucall_server_add_batch_endpoint_t batch {};
    batch.server = application.server;
    batch.outcome = &outcome;
    batch.uri_template = view("/echo/batch");
    batch.verb = ucall_verb_post_k;
    batch.callback = echo_batch;
    batch.context = &application.server;
    ucall_server_add_batch_endpoint(&batch);
    if (!application.succeeded(outcome)) return 1;
    auto result = application.run();
    // The last ForkUnion thread drains batches rather than polling an event loop.
    for (std::size_t index = 0; index + 1 < application.outcomes.size(); ++index) {
        ucall_event_loop_statistics_t counters {};
        ucall_server_event_loop_statistics_t query {application.server, &outcome, index, &counters};
        ucall_server_event_loop_statistics(&query);
        if (!application.succeeded(outcome)) return 1;
        std::printf("Event loop %zu: %llu requests, %llu accepts, %llu polls, %llu empty polls, %llu kernel enters, "
                    "%llu submissions, %llu completions, %llu cancellations, %llu receive re-arms, "
                    "%llu bytes received, %llu bytes sent, %llu bytes copied\n",
                    index, static_cast<unsigned long long>(counters.requests),
                    static_cast<unsigned long long>(counters.accepts), static_cast<unsigned long long>(counters.polls),
                    static_cast<unsigned long long>(counters.empty_polls),
                    static_cast<unsigned long long>(counters.kernel_enters),
                    static_cast<unsigned long long>(counters.submissions),
                    static_cast<unsigned long long>(counters.completions),
                    static_cast<unsigned long long>(counters.cancellations),
                    static_cast<unsigned long long>(counters.receive_rearms),
                    static_cast<unsigned long long>(counters.bytes_received),
                    static_cast<unsigned long long>(counters.bytes_sent),
                    static_cast<unsigned long long>(counters.bytes_copied));
    }
    return result;
}
