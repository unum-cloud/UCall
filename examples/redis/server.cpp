/**
 *  @file examples/redis/server.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Binary HTTP key-value storage with strictly serializable conditional writes.
 */
#include <cstddef> // `std::size_t`
#include <cstring> // `std::memcpy`

#include <charconv>    // `std::to_chars`
#include <limits>      // `std::numeric_limits`
#include <string_view> // `std::string_view`
#include <utility>     // `std::move`

#include <smashtable/locked_store.hpp>   // `st::locked_store`
#include <smashtable/snapshot_store.hpp> // `st::strict_serializable_hash_map`
#include <stringzilla/hash.hpp>          // `sz::hash_t`
#include <stringzilla/string.hpp>        // `sz::string_t`, `sz::equal_to_t`

#include "ucall/ucall.hpp" // `uc::request_t`, `uc::batch_t`, `uc::status_t`, `uc::bytes_view`
#include "server.hpp"

namespace st = ashvardanian::smashtable;
namespace sz = ashvardanian::stringzilla;
namespace uc = unum::ucall;

struct value_t {
    sz::string_t bytes;
    st::generation_t revision {};
    st::expected<value_t> copy() const noexcept {
        value_t copied {{}, revision};
        if (sz::failed(copied.bytes.assign(bytes))) return st::status_t::out_of_memory_heap_k;
        return copied;
    }
};

using store_t = st::locked_store<st::strict_serializable_hash_map<sz::string_t, value_t, sz::hash_t, sz::equal_to_t>>;

/** Answers @p request with an error @p status and a plain-text @p message. */
static void reply_error(uc::request_t request, ucall_http_status_t status, std::string_view message) noexcept {
    [[maybe_unused]] uc::status_t const replied = std::move(request).reply_error(status, message);
}

/** Answers a failed storage @p status, 409 for a conflict a retry can overcome and 503 for
 *  the rest. */
static void reply_error(uc::request_t request, st::status_t status) noexcept {
    if (st::conflicted(status))
        return reply_error(std::move(request), ucall_http_status_conflict_k,
                           "Concurrent transaction; read and retry\n");
    reply_error(std::move(request), ucall_http_status_service_unavailable_k, "Storage unavailable\n");
}

struct service_t {
    store_t store;

    void key_value(uc::request_t request) noexcept {
        auto [key_text, key_status] = request.path_parameter("key");
        if (key_status.failed() || key_text.empty())
            return reply_error(std::move(request), ucall_http_status_bad_request_k, "A key is required\n");
        sz::string_t key;
        if (sz::failed(key.assign(key_text)))
            return reply_error(std::move(request), ucall_http_status_service_unavailable_k, "Storage unavailable\n");
        ucall_verb_t const verb = request.verb();
        if (verb != ucall_verb_get_k && verb != ucall_verb_put_k && verb != ucall_verb_delete_k)
            return reply_error(std::move(request), ucall_http_status_method_not_allowed_k, "Use GET, PUT or DELETE\n");
        auto [match, match_status] = request.header("If-Match");
        auto [absent, absent_status] = request.header("If-None-Match");
        bool const has_match = !match_status.failed();
        bool const has_absent = !absent_status.failed();
        if ((has_match && has_absent) || (has_absent && absent != "*"))
            return reply_error(std::move(request), ucall_http_status_bad_request_k,
                               "Use one ETag or If-None-Match: *\n");
        auto [transaction, transaction_status] = store.transaction();
        if (st::failed(transaction_status)) return reply_error(std::move(request), transaction_status);
        value_t previous {};
        bool found {};
        st::status_t copied = st::status_t::success_k;
        st::status_t status = transaction.find(key, [&](auto const& row) noexcept {
            auto value = row.mapped.copy();
            copied = value.status();
            if (value) previous = std::move(*value);
            found = true;
        });
        if (st::succeeded(status)) status = copied;
        if (st::failed(status)) return reply_error(std::move(request), status);
        char etag[2 + std::numeric_limits<st::generation_t>::digits10 + 2] {'"'};
        char* revision_end = std::to_chars(etag + 1, etag + sizeof(etag) - 1, previous.revision).ptr;
        *revision_end++ = '"';
        bool const not_modified = has_absent && found && verb == ucall_verb_get_k;
        if ((has_absent && found && !not_modified) ||
            (has_match && (!found || (match != "*" && match != std::string_view(etag, revision_end)))))
            return reply_error(std::move(request), ucall_http_status_precondition_failed_k,
                               "ETag precondition failed\n");
        if ((verb == ucall_verb_get_k || verb == ucall_verb_delete_k) && !found)
            return reply_error(std::move(request), ucall_http_status_not_found_k, "Key not found\n");
        value_t result = std::move(previous);
        if (verb == ucall_verb_put_k) {
            auto [body, body_status] = request.body();
            if (body_status.failed())
                return reply_error(std::move(request), ucall_http_status_bad_request_k, "Expected a buffered body\n");
            if (sz::failed(result.bytes.assign(body)))
                return reply_error(std::move(request), st::status_t::out_of_memory_heap_k);
            result.revision = transaction.generation();
            auto [stored, copy_status] = result.copy();
            if (st::failed(copy_status)) return reply_error(std::move(request), copy_status);
            status = transaction.upsert({std::move(key), std::move(stored)});
        }
        else if (verb == ucall_verb_delete_k) status = transaction.erase(key);
        if (st::succeeded(status)) status = transaction.stage();
        if (st::succeeded(status)) status = transaction.commit();
        if (st::failed(status)) return reply_error(std::move(request), status);
        char etag_header[sizeof(etag) + sizeof("ETag: ")] {};
        std::memcpy(etag_header, "ETag: \"", 7);
        char* end = std::to_chars(etag_header + 7, etag_header + sizeof(etag_header) - 1, result.revision).ptr;
        *end++ = '"';
        ucall_bytes_view_t const headers[] {uc::bytes_view({etag_header, end}),
                                            uc::bytes_view("Content-Type: application/octet-stream")};
        std::string_view const response = verb == ucall_verb_get_k && !not_modified ? std::string_view(result.bytes)
                                                                                    : std::string_view {};
        ucall_http_status_t const http_status = not_modified ? ucall_http_status_not_modified_k
                                                             : ucall_http_status_ok_k;
        [[maybe_unused]] uc::status_t const replied = std::move(request).reply(http_status, headers, response);
    }

    void key_value_batch(uc::batch_t batch) noexcept {
        for (uc::request_t request : batch) key_value(std::move(request));
    }
};

int main(int argc, char** argv) {
    service_t service {};
    uc::tools::server_t application {};
    if (int const result = application.init(argc, argv)) return result < 0 ? 1 : 0;
    uc::server_t& server = application.server;
    auto [batch, batch_status] = server.batch<&service_t::key_value_batch>("/batch/kv/{*key}", ucall_verb_any_k,
                                                                           application.batching, service);
    if (server.route<&service_t::key_value>("/kv/{*key}", ucall_verb_any_k, service).failed() || batch_status.failed())
        return 1;
    uc::batch_endpoint_t const batches[] {batch};
    return application.run(batches);
}
