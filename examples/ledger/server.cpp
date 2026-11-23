/**
 *  @file examples/ledger/server.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Atomic transfers between in-memory accounts through the UCall C++ interface.
 */
#include <cstddef> // `std::size_t`
#include <cstdint> // `std::uint64_t`

#include <charconv>    // `std::from_chars`, `std::to_chars`
#include <limits>      // `std::numeric_limits`
#include <string_view> // `std::string_view`
#include <utility>     // `std::move`

#include <smashtable/locked_store.hpp>   // `st::locked_store`
#include <smashtable/snapshot_store.hpp> // `st::strict_serializable_hash_map`

#include "ucall/ucall.hpp" // `uc::request_t`, `uc::batch_t`, `uc::status_t`
#include "server.hpp"

namespace st = ashvardanian::smashtable;
namespace uc = unum::ucall;

using accounts_t = st::locked_store<st::strict_serializable_hash_map<std::uint64_t, std::uint64_t>>;

static bool number(std::string_view text, std::uint64_t& result) {
    std::from_chars_result const parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    return parsed.ec == std::errc {} && parsed.ptr == text.data() + text.size();
}
static bool parameter(uc::request_t const& request, std::string_view name, std::uint64_t& value) {
    auto [text, status] = request.path_parameter(name);
    return !status.failed() && number(text, value);
}

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
    accounts_t accounts;

    void account(uc::request_t request) noexcept {
        std::uint64_t id {}, balance {};
        if (!parameter(request, "id", id))
            return reply_error(std::move(request), ucall_http_status_bad_request_k,
                               "An unsigned account ID is required\n");
        auto [transaction, transaction_status] = accounts.transaction();
        if (st::failed(transaction_status)) return reply_error(std::move(request), transaction_status);
        bool found {};
        st::status_t status = transaction.find(id, [&](auto const& row) noexcept {
            balance = row.mapped;
            found = true;
        });
        if (st::failed(status)) return reply_error(std::move(request), status);
        if (!found) return reply_error(std::move(request), ucall_http_status_not_found_k, "Account not found\n");
        status = transaction.stage();
        if (st::succeeded(status)) status = transaction.commit();
        if (st::failed(status)) return reply_error(std::move(request), status);
        char result[std::numeric_limits<std::uint64_t>::digits10 + 2] {};
        char* end = std::to_chars(result, result + sizeof(result), balance).ptr;
        *end++ = '\n';
        [[maybe_unused]] uc::status_t const replied = std::move(request).reply(ucall_http_status_ok_k, {},
                                                                               {result, end});
    }

    void transfer(uc::request_t request) noexcept {
        std::uint64_t from {}, to {}, amount {};
        auto [body, body_status] = request.body();
        if (!parameter(request, "from", from) || !parameter(request, "to", to) || body_status.failed() ||
            !number(body, amount) || !amount || from == to)
            return reply_error(std::move(request), ucall_http_status_bad_request_k,
                               "Use distinct accounts and a positive amount\n");
        auto [transaction, transaction_status] = accounts.transaction();
        if (st::failed(transaction_status)) return reply_error(std::move(request), transaction_status);
        std::uint64_t source {}, destination {};
        bool source_found {}, destination_found {};
        st::status_t status = transaction.find(from, [&](auto const& row) noexcept {
            source = row.mapped;
            source_found = true;
        });
        if (st::succeeded(status))
            status = transaction.find(to, [&](auto const& row) noexcept {
                destination = row.mapped;
                destination_found = true;
            });
        if (st::failed(status)) return reply_error(std::move(request), status);
        if (!source_found || !destination_found)
            return reply_error(std::move(request), ucall_http_status_not_found_k, "Account not found\n");
        if (source < amount || destination > (std::numeric_limits<std::uint64_t>::max)() - amount)
            return reply_error(std::move(request), ucall_http_status_conflict_k,
                               "Insufficient funds or unrepresentable balance\n");
        status = transaction.upsert({from, source - amount});
        if (st::succeeded(status)) status = transaction.upsert({to, destination + amount});
        if (st::succeeded(status)) status = transaction.stage();
        if (st::succeeded(status)) status = transaction.commit();
        if (st::failed(status)) return reply_error(std::move(request), status);
        [[maybe_unused]] uc::status_t const replied = std::move(request).reply(ucall_http_status_ok_k, {},
                                                                               "committed\n");
    }

    void transfer_batch(uc::batch_t batch) noexcept {
        for (uc::request_t request : batch) transfer(std::move(request));
    }
};

int main(int argc, char** argv) {
    service_t service {};
    uc::tools::server_t application {};
    if (int const result = application.init(argc, argv)) return result < 0 ? 1 : 0;
    if (st::failed(service.accounts.upsert({1, 1000})) || st::failed(service.accounts.upsert({2, 1000}))) return 1;
    uc::server_t& server = application.server;
    auto [batch, batch_status] = server.batch<&service_t::transfer_batch>(
        "/batch/transfers/{from}/{to}", ucall_verb_post_k, application.batching, service);
    if (server.get<&service_t::account>("/accounts/{id}", service).failed() ||
        server.post<&service_t::transfer>("/transfers/{from}/{to}", service).failed() || batch_status.failed())
        return 1;
    uc::batch_endpoint_t const batches[] {batch};
    return application.run(batches);
}
