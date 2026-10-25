/**
 *  @file examples/redis/server.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Binary HTTP key-value storage with strictly serializable conditional writes.
 */
#include <cstdio>
#include <cstring>

#include <charconv>
#include <limits>
#include <string_view>

#include <smashtable/locked_store.hpp>
#include <smashtable/snapshot_store.hpp>
#include <stringzilla/hash/serial.h>

#include "../server.hpp"

namespace st = ashvardanian::smashtable;

using bytes_t = st::basic_vector<char>;
static std::string_view text(bytes_t const& bytes) noexcept { return {bytes.begin(), bytes.end()}; }

struct key_hash_t {
    std::size_t operator()(bytes_t const& key) const noexcept {
        sz_u64_t hash {};
        sz_hash_serial(key.data(), key.size(), 0, &hash, nullptr);
        return static_cast<std::size_t>(hash);
    }
};
struct key_equal_t {
    bool operator()(bytes_t const& left, bytes_t const& right) const noexcept { return text(left) == text(right); }
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

static ucall_bytes_view_t view(std::string_view text) {
    return {reinterpret_cast<ucall_byte_t const*>(text.data()), text.size()};
}
static std::string_view text(ucall_bytes_view_t bytes) {
    return {reinterpret_cast<char const*>(bytes.data), bytes.length};
}
static void fail(service_t& service, ucall_received_http_request_t request, ucall_http_status_t status,
                 char const* message) {
    ucall_outcome_t outcome {};
    ucall_server_reply_error_t reply {service.server, &outcome, request, status, view(message)};
    ucall_server_reply_error(&reply);
}
static bool checked(service_t& service, ucall_received_http_request_t request, st::status_t status) {
    if (st::succeeded(status)) return true;
    if (status == st::status_t::write_conflict_k)
        fail(service, request, ucall_http_status_conflict_k, "Concurrent write; read and retry\n");
    else fail(service, request, ucall_http_status_service_unavailable_k, "Storage allocation failed\n");
    return false;
}
static void key_value(ucall_received_http_request_t request, void* context) {
    auto& service = *static_cast<service_t*>(context);
    ucall_outcome_t outcome {};
    ucall_bytes_view_t key_view {}, body {}, match {}, absent {};
    ucall_server_request_path_parameter_t key_args {service.server, &outcome, request, view("key"), &key_view};
    ucall_server_request_path_parameter(&key_args);
    if (outcome.status != ucall_status_success_k || !key_view.length)
        return fail(service, request, ucall_http_status_bad_request_k, "A key is required\n");
    bytes_t key;
    if (!checked(service, request, key.resize(key_view.length))) return;
    std::memcpy(key.data(), key_view.data, key_view.length);
    auto verb = ucall_server_request_verb(service.server, request);
    if (verb != ucall_verb_get_k && verb != ucall_verb_put_k && verb != ucall_verb_delete_k)
        return fail(service, request, ucall_http_status_method_not_allowed_k, "Use GET, PUT or DELETE\n");
    ucall_server_request_header_t header {service.server, &outcome, request, view("If-Match"), &match};
    ucall_server_request_header(&header);
    bool has_match = outcome.status == ucall_status_success_k;
    header.name = view("If-None-Match");
    header.value = &absent;
    ucall_server_request_header(&header);
    bool has_absent = outcome.status == ucall_status_success_k;
    if ((has_match && has_absent) || (has_absent && text(absent) != "*"))
        return fail(service, request, ucall_http_status_bad_request_k, "Use one ETag or If-None-Match: *\n");
    auto transaction = service.store.transaction();
    if (!transaction) {
        checked(service, request, transaction.status());
        return;
    }
    value_t previous {};
    bool found {};
    auto copied = st::status_t::success_k;
    if (!checked(service, request,
                 transaction->find(key,
                                   [&](auto const& row) noexcept {
                                       auto value = row.mapped.copy();
                                       copied = value.status();
                                       if (value) previous = std::move(*value);
                                       found = true;
                                   })) ||
        !checked(service, request, copied))
        return;
    char etag[2 + std::numeric_limits<st::generation_t>::digits10 + 2] {'"'};
    auto revision_end = std::to_chars(etag + 1, etag + sizeof(etag) - 1, previous.revision).ptr;
    *revision_end++ = '"';
    bool not_modified = has_absent && found && verb == ucall_verb_get_k;
    if ((has_absent && found && !not_modified) ||
        (has_match && (!found || (text(match) != "*" && text(match) != std::string_view(etag, revision_end)))))
        return fail(service, request, ucall_http_status_precondition_failed_k, "ETag precondition failed\n");
    if (verb == ucall_verb_get_k || verb == ucall_verb_delete_k) {
        if (!found) return fail(service, request, ucall_http_status_not_found_k, "Key not found\n");
    }
    value_t result = std::move(previous);
    if (verb == ucall_verb_put_k) {
        ucall_server_request_body_t extract {service.server, &outcome, request, &body};
        ucall_server_request_body(&extract);
        if (outcome.status != ucall_status_success_k)
            return fail(service, request, ucall_http_status_bad_request_k, "Request body is unavailable\n");
        result.bytes.clear();
        if (!checked(service, request, result.bytes.resize(body.length))) return;
        if (body.length) std::memcpy(result.bytes.data(), body.data, body.length);
        result.revision = transaction->generation();
        auto stored = result.copy();
        if (!stored) {
            checked(service, request, stored.status());
            return;
        }
        if (!checked(service, request, transaction->upsert({std::move(key), std::move(*stored)}))) return;
    }
    else if (verb == ucall_verb_delete_k && !checked(service, request, transaction->erase(key))) return;
    if (!checked(service, request, transaction->stage()) || !checked(service, request, transaction->commit())) return;
    char etag_header[sizeof(etag) + sizeof("ETag: ")] {};
    std::memcpy(etag_header, "ETag: \"", 7);
    auto end = std::to_chars(etag_header + 7, etag_header + sizeof(etag_header) - 1, result.revision).ptr;
    *end++ = '"';
    ucall_bytes_view_t headers[] {view({etag_header, end}), view("Content-Type: application/octet-stream")};
    auto response = verb == ucall_verb_get_k && !not_modified ? view(text(result.bytes)) : ucall_bytes_view_t {};
    ucall_server_reply_content_t reply {service.server, &outcome, request, headers, 2, response};
    if (not_modified) reply.http_status = ucall_http_status_not_modified_k;
    ucall_server_reply_content(&reply);
}

static void key_value_batch(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
    for (std::size_t i = 0; i != count; ++i) key_value(requests[i], context);
}

int main(int argc, char** argv) {
    service_t service {};
    examples::server_t application {};
    if (auto result = application.init(argc, argv)) return result < 0 ? 1 : 0;
    service.server = application.server;
    ucall_outcome_t outcome {};
    ucall_server_add_http_endpoint_t add {service.server,   &outcome,  view("/kv/{*key}"),
                                          ucall_verb_any_k, key_value, &service};
    ucall_server_add_http_endpoint(&add);
    if (!application.succeeded(outcome)) return 1;
    ucall_server_add_http_batch_endpoint_t batch {};
    batch.server = application.server;
    batch.outcome = &outcome;
    batch.uri_template = view("/batch/kv/{*key}");
    batch.verb = ucall_verb_any_k;
    batch.callback = key_value_batch;
    batch.context = &service;
    batch.endpoint = &application.batch_endpoint;
    ucall_server_add_http_batch_endpoint(&batch);
    return application.succeeded(outcome) ? application.run() : 1;
}
