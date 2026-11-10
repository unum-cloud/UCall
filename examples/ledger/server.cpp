/**
 *  @file examples/ledger/server.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Atomic transfers between in-memory accounts through the UCall C interface.
 */
#include <cstdint> // `std::uint64_t`

#include <charconv>    // `std::from_chars`, `std::to_chars`
#include <limits>      // `std::numeric_limits`
#include <span>        // `std::span`
#include <string_view> // `std::string_view`

#include <smashtable/locked_store.hpp>
#include <smashtable/snapshot_store.hpp>

#include "server.hpp"

namespace st = ashvardanian::smashtable;
using uc::tools::reply_error;

struct service_t {
    ucall_server_t server {};
    st::locked_store<st::strict_serializable_hash_map<std::uint64_t, std::uint64_t>> accounts;
};

static bool number(std::string_view text, std::uint64_t& result) {
    std::from_chars_result const parsed = std::from_chars(text.data(), text.data() + text.size(), result);
    return parsed.ec == std::errc {} && parsed.ptr == text.data() + text.size();
}
static bool parameter(service_t& service, ucall_received_http_request_t request, std::string_view name,
                      std::uint64_t& value) {
    ucall_outcome_t outcome {};
    ucall_bytes_view_t bytes {};
    ucall_server_request_path_parameter_t extract {service.server, &outcome, request, uc::bytes_view(name), &bytes};
    ucall_server_request_path_parameter(&extract);
    return outcome.status == ucall_status_success_k && number(uc::text_view(bytes), value);
}
static void account(ucall_received_http_request_t request, void* context) {
    service_t& service = *static_cast<service_t*>(context);
    std::uint64_t id {}, balance {};
    if (!parameter(service, request, "id", id))
        return reply_error(service.server, request, ucall_http_status_bad_request_k,
                           "An unsigned account ID is required\n");
    auto transaction = service.accounts.transaction();
    if (!transaction) {
        reply_error(service.server, request, transaction.status());
        return;
    }
    bool found {};
    st::status_t const status = transaction->find(id, [&](auto const& row) noexcept {
        balance = row.mapped;
        found = true;
    });
    if (reply_error(service.server, request, status)) return;
    if (!found) return reply_error(service.server, request, ucall_http_status_not_found_k, "Account not found\n");
    if (reply_error(service.server, request, transaction->stage()) ||
        reply_error(service.server, request, transaction->commit()))
        return;
    char result[std::numeric_limits<std::uint64_t>::digits10 + 2] {};
    char* end = std::to_chars(result, result + sizeof(result), balance).ptr;
    *end++ = '\n';
    ucall_outcome_t outcome {};
    ucall_server_reply_content_t reply {
        service.server, &outcome, request, ucall_http_status_ok_k, nullptr, 0, uc::bytes_view({result, end})};
    ucall_server_reply_content(&reply);
}
static void transfer(ucall_received_http_request_t request, void* context) {
    service_t& service = *static_cast<service_t*>(context);
    std::uint64_t from {}, to {}, amount {};
    ucall_outcome_t outcome {};
    ucall_bytes_view_t body {};
    ucall_server_request_body_t extract {service.server, &outcome, request, &body};
    ucall_server_request_body(&extract);
    if (!parameter(service, request, "from", from) || !parameter(service, request, "to", to) ||
        outcome.status != ucall_status_success_k || !number(uc::text_view(body), amount) || !amount || from == to)
        return reply_error(service.server, request, ucall_http_status_bad_request_k,
                           "Use distinct accounts and a positive amount\n");
    auto transaction = service.accounts.transaction();
    if (!transaction) {
        reply_error(service.server, request, transaction.status());
        return;
    }
    std::uint64_t source {}, destination {};
    bool source_found {}, destination_found {};
    if (reply_error(service.server, request, transaction->find(from, [&](auto const& row) noexcept {
            source = row.mapped;
            source_found = true;
        })))
        return;
    if (reply_error(service.server, request, transaction->find(to, [&](auto const& row) noexcept {
            destination = row.mapped;
            destination_found = true;
        })))
        return;
    if (!source_found || !destination_found)
        return reply_error(service.server, request, ucall_http_status_not_found_k, "Account not found\n");
    if (source < amount || destination > (std::numeric_limits<std::uint64_t>::max)() - amount)
        return reply_error(service.server, request, ucall_http_status_conflict_k,
                           "Insufficient funds or unrepresentable balance\n");
    if (reply_error(service.server, request, transaction->upsert({from, source - amount})) ||
        reply_error(service.server, request, transaction->upsert({to, destination + amount})) ||
        reply_error(service.server, request, transaction->stage()) ||
        reply_error(service.server, request, transaction->commit()))
        return;
    ucall_server_reply_content_t reply {
        service.server, &outcome, request, ucall_http_status_ok_k, nullptr, 0, uc::bytes_view("committed\n")};
    ucall_server_reply_content(&reply);
}

static void transfer_batch(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
    std::span<ucall_received_http_request_t const> const batch {requests, count};
    for (ucall_received_http_request_t const request : batch) transfer(request, context);
}

int main(int argc, char** argv) {
    service_t service {};
    uc::tools::server_t application {};
    if (int const result = application.init(argc, argv)) return result < 0 ? 1 : 0;
    service.server = application.server;
    if (st::failed(service.accounts.upsert({1, 1000})) || st::failed(service.accounts.upsert({2, 1000}))) return 1;
    if (!application.add_endpoint("/accounts/{id}", ucall_verb_get_k, account, &service) ||
        !application.add_endpoint("/transfers/{from}/{to}", ucall_verb_post_k, transfer, &service) ||
        !application.add_batch_endpoint("/batch/transfers/{from}/{to}", ucall_verb_post_k, transfer_batch, &service))
        return 1;
    return application.run();
}
