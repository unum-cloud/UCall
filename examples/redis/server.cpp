/**
 *  @file examples/redis/server.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Binary HTTP key-value storage with strictly serializable conditional writes.
 */
#include <cstring> // `std::memcpy`

#include <charconv>    // `std::to_chars`
#include <limits>      // `std::numeric_limits`
#include <span>        // `std::span`
#include <string_view> // `std::string_view`

#include <smashtable/locked_store.hpp>
#include <smashtable/snapshot_store.hpp>
#include <stringzilla/hash/serial.h>

#include "server.hpp"

namespace st = ashvardanian::smashtable;
using uc::tools::reply_error;

using bytes_t = st::vector<uc::byte_t>;

struct key_hash_t {
    std::size_t operator()(bytes_t const& key) const noexcept {
        sz_u64_t hash {};
        sz_hash_serial(uc::text_view(key).data(), key.size(), 0, &hash, nullptr);
        return static_cast<std::size_t>(hash);
    }
};
struct key_equal_t {
    bool operator()(bytes_t const& left, bytes_t const& right) const noexcept {
        return uc::text_view(left) == uc::text_view(right);
    }
};
struct value_t {
    bytes_t bytes;
    st::generation_t revision {};
    st::expected<value_t> copy() const noexcept {
        auto copied = bytes.copy();
        if (!copied) return copied.status();
        return value_t {std::move(*copied), revision};
    }
};
struct service_t {
    ucall_server_t server {};
    st::locked_store<st::strict_serializable_hash_map<bytes_t, value_t, key_hash_t, key_equal_t>> store;
};

static void key_value(ucall_received_http_request_t request, void* context) {
    service_t& service = *static_cast<service_t*>(context);
    ucall_outcome_t outcome {};
    ucall_bytes_view_t key_view {}, body {}, match {}, absent {};
    ucall_server_request_path_parameter_t key_args {service.server, &outcome, request, uc::bytes_view("key"),
                                                    &key_view};
    ucall_server_request_path_parameter(&key_args);
    if (outcome.status != ucall_status_success_k || !key_view.length)
        return reply_error(service.server, request, ucall_http_status_bad_request_k, "A key is required\n");
    bytes_t key;
    if (reply_error(service.server, request, key.resize(key_view.length))) return;
    std::memcpy(key.data(), key_view.data, key_view.length);
    ucall_verb_t const verb = ucall_server_request_verb(service.server, request);
    if (verb != ucall_verb_get_k && verb != ucall_verb_put_k && verb != ucall_verb_delete_k)
        return reply_error(service.server, request, ucall_http_status_method_not_allowed_k, "Use GET, PUT or DELETE\n");
    ucall_server_request_header_t header {service.server, &outcome, request, uc::bytes_view("If-Match"), &match};
    ucall_server_request_header(&header);
    bool const has_match = outcome.status == ucall_status_success_k;
    header.name = uc::bytes_view("If-None-Match");
    header.value = &absent;
    ucall_server_request_header(&header);
    bool const has_absent = outcome.status == ucall_status_success_k;
    if ((has_match && has_absent) || (has_absent && uc::text_view(absent) != "*"))
        return reply_error(service.server, request, ucall_http_status_bad_request_k,
                           "Use one ETag or If-None-Match: *\n");
    auto transaction = service.store.transaction();
    if (!transaction) {
        reply_error(service.server, request, transaction.status());
        return;
    }
    value_t previous {};
    bool found {};
    st::status_t copied = st::status_t::success_k;
    if (reply_error(service.server, request,
                    transaction->find(key,
                                      [&](auto const& row) noexcept {
                                          auto value = row.mapped.copy();
                                          copied = value.status();
                                          if (value) previous = std::move(*value);
                                          found = true;
                                      })) ||
        reply_error(service.server, request, copied))
        return;
    char etag[2 + std::numeric_limits<st::generation_t>::digits10 + 2] {'"'};
    auto revision_end = std::to_chars(etag + 1, etag + sizeof(etag) - 1, previous.revision).ptr;
    *revision_end++ = '"';
    bool const not_modified = has_absent && found && verb == ucall_verb_get_k;
    std::string_view const match_text = uc::text_view(match);
    if ((has_absent && found && !not_modified) ||
        (has_match && (!found || (match_text != "*" && match_text != std::string_view(etag, revision_end)))))
        return reply_error(service.server, request, ucall_http_status_precondition_failed_k,
                           "ETag precondition failed\n");
    if (verb == ucall_verb_get_k || verb == ucall_verb_delete_k) {
        if (!found) return reply_error(service.server, request, ucall_http_status_not_found_k, "Key not found\n");
    }
    value_t result = std::move(previous);
    if (verb == ucall_verb_put_k) {
        ucall_server_request_body_t extract {service.server, &outcome, request, &body};
        ucall_server_request_body(&extract);
        if (outcome.status != ucall_status_success_k)
            return reply_error(service.server, request, ucall_http_status_bad_request_k,
                               "Request body is unavailable\n");
        result.bytes.clear();
        if (reply_error(service.server, request, result.bytes.resize(body.length))) return;
        if (body.length) std::memcpy(result.bytes.data(), body.data, body.length);
        result.revision = transaction->generation();
        st::expected<value_t> stored = result.copy();
        if (!stored) {
            reply_error(service.server, request, stored.status());
            return;
        }
        if (reply_error(service.server, request, transaction->upsert({std::move(key), std::move(*stored)}))) return;
    }
    else if (verb == ucall_verb_delete_k && reply_error(service.server, request, transaction->erase(key))) return;
    if (reply_error(service.server, request, transaction->stage()) ||
        reply_error(service.server, request, transaction->commit()))
        return;
    char etag_header[sizeof(etag) + sizeof("ETag: ")] {};
    std::memcpy(etag_header, "ETag: \"", 7);
    char* end = std::to_chars(etag_header + 7, etag_header + sizeof(etag_header) - 1, result.revision).ptr;
    *end++ = '"';
    ucall_bytes_view_t headers[] {uc::bytes_view({etag_header, end}),
                                  uc::bytes_view("Content-Type: application/octet-stream")};
    ucall_bytes_view_t const response = verb == ucall_verb_get_k && !not_modified
                                            ? uc::bytes_view(uc::text_view(result.bytes))
                                            : ucall_bytes_view_t {};
    ucall_server_reply_content_t reply {service.server, &outcome, request, ucall_http_status_ok_k,
                                        headers,        2,        response};
    if (not_modified) reply.http_status = ucall_http_status_not_modified_k;
    ucall_server_reply_content(&reply);
}

static void key_value_batch(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
    std::span<ucall_received_http_request_t const> const batch {requests, count};
    for (ucall_received_http_request_t const request : batch) key_value(request, context);
}

int main(int argc, char** argv) {
    service_t service {};
    uc::tools::server_t application {};
    if (int const result = application.init(argc, argv)) return result < 0 ? 1 : 0;
    service.server = application.server;
    if (!application.add_endpoint("/kv/{*key}", ucall_verb_any_k, key_value, &service) ||
        !application.add_batch_endpoint("/batch/kv/{*key}", ucall_verb_any_k, key_value_batch, &service))
        return 1;
    return application.run();
}
