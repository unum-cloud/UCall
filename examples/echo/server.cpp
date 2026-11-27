/**
 *  @file examples/echo/server.cpp
 *  @author Ash Vardanian
 *  @date May 13, 2024
 *  @brief Binary HTTP echo service for transport benchmarks.
 */
#include <cstddef> // `std::size_t`
#include <cstdint> // `std::uint64_t`
#include <cstdio>  // `std::snprintf`

#include <array>       // `std::array`
#include <charconv>    // `std::from_chars`
#include <limits>      // `std::numeric_limits`
#include <mutex>       // `std::mutex`, `std::lock_guard`
#include <string_view> // `std::string_view`
#include <utility>     // `std::move`

#include <smashtable/basic_hash_table.hpp> // `st::hash_map`
#include <stringzilla/hash.hpp>            // `sz::hash_t`
#include <stringzilla/string.hpp>          // `sz::string_view_t`, `sz::equal_to_t`

#include "ucall/ucall.hpp" // `uc::request_t`, `uc::batch_t`, `uc::status_t`, `uc::bytes_view`
#include "server.hpp"

namespace st = ashvardanian::smashtable;
namespace sz = ashvardanian::stringzilla;
namespace uc = unum::ucall;

/** A pair ID's three words, hashed and compared as the bytes they occupy. */
struct pair_key_t {
    std::array<std::uint64_t, 3> words {};
    operator sz::string_view_t() const noexcept { return {reinterpret_cast<char const*>(words.data()), sizeof(words)}; }
};

/** The member of a pair that arrived first, held until its partner does. */
struct held_member_t {
    uc::request_t request;
    std::size_t member {};
};

using pair_table_t = st::hash_map<pair_key_t, held_member_t, sz::hash_t, sz::equal_to_t>;

/** Reads a pair ID spelled as three decimal words joined by colons. */
static bool parse_pair_key(std::string_view text, pair_key_t& key) noexcept {
    char const* const end = text.data() + text.size();
    std::from_chars_result parsed {text.data(), std::errc {}};
    for (std::size_t index = 0; index != key.words.size(); ++index) {
        if (index != 0 && (parsed.ptr == end || *parsed.ptr != ':')) return false;
        parsed = std::from_chars(parsed.ptr + (index != 0), end, key.words[index]);
        if (parsed.ec != std::errc {}) return false;
    }
    return parsed.ptr == end;
}

/** Answers @p request with an error @p status and a plain-text @p message. */
static void reply_error(uc::request_t request, ucall_http_status_t status, std::string_view message) noexcept {
    [[maybe_unused]] uc::status_t const replied = std::move(request).reply_error(status, message);
}

struct service_t {
    std::mutex mutex;
    pair_table_t pending;

    void echo(uc::request_t request) noexcept {
        auto [body, body_status] = request.body();
        if (body_status.failed())
            return reply_error(std::move(request), ucall_http_status_bad_request_k, "Expected a buffered body\n");
        [[maybe_unused]] uc::status_t const replied = std::move(request).reply(ucall_http_status_ok_k, {}, body);
    }

    void reordered(uc::request_t request) noexcept {
        auto [key_text, key_status] = request.header("x-ucall-pair");
        auto [member_text, member_status] = request.header("x-ucall-member");
        pair_key_t key {};
        if (key_status.failed() || !parse_pair_key(key_text, key) || member_status.failed() ||
            (member_text != "0" && member_text != "1"))
            return reply_error(std::move(request), ucall_http_status_bad_request_k,
                               "Expected pair ID and member 0 or 1\n");
        std::size_t const member = static_cast<std::size_t>(member_text.front() - '0');
        std::array<uc::request_t, 2> pair {};
        {
            std::lock_guard<std::mutex> lock {mutex};
            pair_table_t::iterator const found = pending.find(key);
            if (found == pending.end()) {
                pair_table_t::insert_result_t const inserted =
                    pending.emplace<pair_table_t::emplace_report_t::insert_result_k>(key, held_member_t {});
                if (inserted.failed())
                    return reply_error(std::move(request), ucall_http_status_service_unavailable_k,
                                       "Allocation failed\n");
                (*inserted.position).mapped = {std::move(request), member};
                return;
            }
            held_member_t& held = (*found).mapped;
            if (held.member == member)
                return reply_error(std::move(request), ucall_http_status_conflict_k, "Duplicate pair member\n");
            pair[held.member] = std::move(held.request);
            pending.erase(found);
        }
        pair[member] = std::move(request);
        char pair_header[sizeof("x-ucall-pair: ::") + 3 * (std::numeric_limits<std::uint64_t>::digits10 + 1)] {};
        int const length = std::snprintf(pair_header, sizeof(pair_header), "x-ucall-pair: %llu:%llu:%llu",
                                         static_cast<unsigned long long>(key.words[0]),
                                         static_cast<unsigned long long>(key.words[1]),
                                         static_cast<unsigned long long>(key.words[2]));
        for (std::size_t const replied_member : {std::size_t {1}, std::size_t {0}}) {
            auto [body, body_status] = pair[replied_member].body();
            if (body_status.failed()) {
                reply_error(std::move(pair[replied_member]), ucall_http_status_bad_request_k,
                            "Expected a buffered body\n");
                continue;
            }
            ucall_bytes_view_t const headers[] {
                uc::bytes_view({pair_header, static_cast<std::size_t>(length)}),
                uc::bytes_view(replied_member ? "x-ucall-member: 1" : "x-ucall-member: 0")};
            [[maybe_unused]] uc::status_t const replied =
                std::move(pair[replied_member]).reply(ucall_http_status_ok_k, headers, body);
        }
    }

    void echo_batch(uc::batch_t batch) noexcept {
        for (uc::request_t request : batch) echo(std::move(request));
    }
};

int main(int argc, char** argv) {
    uc::tools::server_t application {};
    if (int const result = application.init(argc, argv)) return result < 0 ? 1 : 0;
    // Declared after the server, so the requests it still holds answer before the server is freed.
    service_t service;
    uc::server_t& server = application.server;
    auto [batch, batch_status] = server.batch<&service_t::echo_batch>("/echo/batch", ucall_verb_post_k,
                                                                      application.batching, service);
    if (server.post<&service_t::echo>("/echo", service).failed() ||
        server.post<&service_t::reordered>("/echo/reordered", service).failed() || batch_status.failed())
        return 1;
    uc::batch_endpoint_t const batches[] {batch};
    return application.run(batches);
}
