/**
 *  @file examples/ledger/server.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Atomic transfers between in-memory accounts through the UCall C interface.
 */
#include <cstdio>
#include <cstdint>

#include <charconv>
#include <limits>
#include <string_view>

#include <smashtable/locked_store.hpp>
#include <smashtable/snapshot_store.hpp>

#include "../server.hpp"

namespace st = ashvardanian::smashtable;

struct service_t {
    ucall_server_t server {};
    st::locked_store<st::strict_serializable_hash_map<std::uint64_t, std::uint64_t>> accounts;
};

static ucall_bytes_view_t view(std::string_view text) {
    return {reinterpret_cast<ucall_byte_t const*>(text.data()), text.size()};
}
static bool number(ucall_bytes_view_t bytes, std::uint64_t& result) {
    if (!bytes.length) return false;
    auto first = reinterpret_cast<char const*>(bytes.data);
    auto parsed = std::from_chars(first, first + bytes.length, result);
    return parsed.ec == std::errc {} && parsed.ptr == first + bytes.length;
}
static void fail(service_t& service, ucall_received_http_request_t request, ucall_http_status_t status,
                 char const* message) {
    ucall_outcome_t outcome {};
    ucall_server_reply_error_t reply {service.server, &outcome, request, status, view(message)};
    ucall_server_reply_error(&reply);
}
static bool checked(service_t& service, ucall_received_http_request_t request, st::status_t status) {
    if (st::succeeded(status)) return true;
    auto code = status == st::status_t::write_conflict_k ? ucall_http_status_conflict_k
                                                         : ucall_http_status_service_unavailable_k;
    fail(service, request, code, "Transaction failed; retry from a fresh read\n");
    return false;
}
static bool parameter(service_t& service, ucall_received_http_request_t request, char const* name,
                      std::uint64_t& value) {
    ucall_outcome_t outcome {};
    ucall_bytes_view_t bytes {};
    ucall_server_request_path_parameter_t extract {service.server, &outcome, request, view(name), &bytes};
    ucall_server_request_path_parameter(&extract);
    return outcome.status == ucall_status_success_k && number(bytes, value);
}
static void account(ucall_received_http_request_t request, void* context) {
    auto& service = *static_cast<service_t*>(context);
    std::uint64_t id {}, balance {};
    if (!parameter(service, request, "id", id))
        return fail(service, request, ucall_http_status_bad_request_k, "An unsigned account ID is required\n");
    auto transaction = service.accounts.transaction();
    if (!transaction) {
        checked(service, request, transaction.status());
        return;
    }
    bool found {};
    auto status = transaction->find(id, [&](auto const& row) noexcept {
        balance = row.mapped;
        found = true;
    });
    if (!checked(service, request, status)) return;
    if (!found) return fail(service, request, ucall_http_status_not_found_k, "Account not found\n");
    if (!checked(service, request, transaction->stage()) || !checked(service, request, transaction->commit())) return;
    char result[std::numeric_limits<std::uint64_t>::digits10 + 2] {};
    auto end = std::to_chars(result, result + sizeof(result), balance).ptr;
    *end++ = '\n';
    ucall_outcome_t outcome {};
    ucall_server_reply_content_t reply {service.server, &outcome, request, nullptr, 0, view({result, end})};
    ucall_server_reply_content(&reply);
}
static void transfer(ucall_received_http_request_t request, void* context) {
    auto& service = *static_cast<service_t*>(context);
    std::uint64_t from {}, to {}, amount {};
    ucall_outcome_t outcome {};
    ucall_bytes_view_t body {};
    ucall_server_request_body_t extract {service.server, &outcome, request, &body};
    ucall_server_request_body(&extract);
    if (!parameter(service, request, "from", from) || !parameter(service, request, "to", to) ||
        outcome.status != ucall_status_success_k || !number(body, amount) || !amount || from == to)
        return fail(service, request, ucall_http_status_bad_request_k, "Use distinct accounts and a positive amount\n");
    auto transaction = service.accounts.transaction();
    if (!transaction) {
        checked(service, request, transaction.status());
        return;
    }
    std::uint64_t source {}, destination {};
    bool source_found {}, destination_found {};
    if (!checked(service, request, transaction->find(from, [&](auto const& row) noexcept {
            source = row.mapped;
            source_found = true;
        })))
        return;
    if (!checked(service, request, transaction->find(to, [&](auto const& row) noexcept {
            destination = row.mapped;
            destination_found = true;
        })))
        return;
    if (!source_found || !destination_found)
        return fail(service, request, ucall_http_status_not_found_k, "Account not found\n");
    if (source < amount || destination > std::numeric_limits<std::uint64_t>::max() - amount)
        return fail(service, request, ucall_http_status_conflict_k, "Insufficient funds or unrepresentable balance\n");
    if (!checked(service, request, transaction->upsert({from, source - amount})) ||
        !checked(service, request, transaction->upsert({to, destination + amount})) ||
        !checked(service, request, transaction->stage()) || !checked(service, request, transaction->commit()))
        return;
    ucall_server_reply_content_t reply {service.server, &outcome, request, nullptr, 0, view("committed\n")};
    ucall_server_reply_content(&reply);
}

static void transfer_batch(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
    for (std::size_t i = 0; i != count; ++i) transfer(requests[i], context);
}

int main(int argc, char** argv) {
    service_t service {};
    examples::server_t application {};
    if (auto result = application.init(argc, argv)) return result < 0 ? 1 : 0;
    service.server = application.server;
    if (st::failed(service.accounts.upsert({1, 1000})) || st::failed(service.accounts.upsert({2, 1000}))) return 1;
    ucall_outcome_t outcome {};
    ucall_server_add_http_endpoint_t add {service.server,   &outcome, view("/accounts/{id}"),
                                          ucall_verb_get_k, account,  &service};
    ucall_server_add_http_endpoint(&add);
    if (!application.succeeded(outcome)) return 1;
    add.uri_template = view("/transfers/{from}/{to}");
    add.verb = ucall_verb_post_k;
    add.callback = transfer;
    ucall_server_add_http_endpoint(&add);
    if (!application.succeeded(outcome)) return 1;
    ucall_server_add_http_batch_endpoint_t batch {};
    batch.server = application.server;
    batch.outcome = &outcome;
    batch.uri_template = view("/batch/transfers/{from}/{to}");
    batch.verb = ucall_verb_post_k;
    batch.callback = transfer_batch;
    batch.context = &service;
    batch.endpoint = &application.batch_endpoint;
    ucall_server_add_http_batch_endpoint(&batch);
    return application.succeeded(outcome) ? application.run() : 1;
}
