/**
 *  @file test/polling.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Caller-driven progress, retained requests, completion credits, and application batching.
 */
#include <cstring> // `std::memcmp`, `std::strcmp`, `std::strlen`
#include <ctime>   // `std::clock`

#include <array>   // `std::array`
#include <atomic>  // `std::atomic`
#include <chrono>  // `std::chrono::steady_clock`
#include <limits>  // `std::numeric_limits`
#include <string>  // `std::string`
#include <thread>  // `std::thread`
#include <utility> // `std::pair`

#include "ucall/ucall.h"
#include "ucall/types.hpp"
#include "ucall/network.hpp"

#include "harness.hpp" // `expect`, `require`, `run_test`

namespace uc = unum::ucall;
using namespace unum::ucall::test;

static ucall_bytes_view_t view(std::string const& value) {
    return {reinterpret_cast<ucall_byte_t const*>(value.data()), value.size()};
}
static ucall_bytes_view_t view(char const* value) {
    return {reinterpret_cast<ucall_byte_t const*>(value), std::strlen(value)};
}
static std::chrono::steady_clock::time_point deadline_after(long milliseconds) {
    return std::chrono::steady_clock::now() + std::chrono::milliseconds {milliseconds};
}
static bool expired(std::chrono::steady_clock::time_point deadline) {
    return std::chrono::steady_clock::now() > deadline;
}

struct fixture_t {
    ucall_server_t server {};
    ucall_http_batch_endpoint_t batch_endpoint {};
    std::array<ucall_client_t, 2> clients {};
    ucall_received_http_request_t held {};
    std::size_t echoes {};
    std::string address;

    /** The first setup step that failed, which every case checks before it starts. */
    ucall_status_t status {ucall_status_success_k};

    /** Checks that failed in callbacks and helpers, which no case frame returns. */
    std::atomic<std::size_t> failures {};

    void reply(ucall_received_http_request_t request) {
        ucall_outcome_t outcome {};
        ucall_bytes_view_t body {};
        ucall_server_request_body_t extract {server, &outcome, request, &body};
        ucall_server_request_body(&extract);
        failures += expect(outcome.status == ucall_status_success_k);
        ucall_server_reply_content_t response {server, &outcome, request, nullptr, 0, body};
        ucall_server_reply_content(&response);
        failures += expect(outcome.status == ucall_status_success_k);
    }
    static void echo(ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<fixture_t*>(context);
        ++fixture.echoes;
        fixture.reply(request);
    }
    static void hold(ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<fixture_t*>(context);
        fixture.failures += expect(!fixture.held, "a second request arrived while one is held");
        fixture.held = request;
    }
    explicit fixture_t(ucall_received_http_batch_callback_t batch_callback = nullptr, void* batch_context = nullptr) {
        ucall_outcome_t outcome {};
        ucall_network_interface_t network_interface {};
        network_interface.address = "127.0.0.1:0";
        network_interface.max_concurrent_connections = 2;
        ucall_server_config_t config {};
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
        ucall_server_config_t resolved {};
        ucall_server_init_t init {&server, &outcome, &config, &resolved};
        ucall_server_init(&init);
        if ((status = outcome.status) != ucall_status_success_k) return;
        address = "http://";
        address += resolved.interfaces[0].address;
        using route_t = std::pair<char const*, ucall_received_http_request_callback_t>;
        for (auto [route, callback] : {route_t {"/echo", echo}, route_t {"/hold", hold}}) {
            ucall_server_add_http_endpoint_t add {server, &outcome, view(route), ucall_verb_post_k, callback, this};
            ucall_server_add_http_endpoint(&add);
            if ((status = outcome.status) != ucall_status_success_k) return;
        }
        for (auto& client : clients) {
            ucall_client_config_t client_config {};
            client_config.max_concurrent_connections = 1;
            client_config.max_concurrent_calls = 2;
            ucall_client_init_t client_init {&client, &outcome, &client_config, nullptr};
            ucall_client_init(&client_init);
            if ((status = outcome.status) != ucall_status_success_k) return;
        }
        if (batch_callback) {
            ucall_server_add_http_batch_endpoint_t add {
                server, &outcome, view("/batch"), ucall_verb_post_k, batch_callback, batch_context,
                2,      2,        100000,         &batch_endpoint};
            ucall_server_add_http_batch_endpoint(&add);
            status = outcome.status;
        }
    }
    ~fixture_t() {
        for (auto client : clients) ucall_client_free(client);
        ucall_server_free(server);
    }
    void serve(std::size_t timeout = 0) {
        ucall_outcome_t outcome {};
        ucall_server_take_call_t serving {server, &outcome, 0, timeout};
        ucall_server_take_call(&serving);
        failures += expect(outcome.status == ucall_status_success_k);
    }
    std::size_t take(std::size_t client, ucall_completed_call_t* calls = nullptr, std::size_t capacity = 0) {
        ucall_outcome_t outcome {};
        std::size_t count {};
        ucall_client_take_completed_t take {clients[client], &outcome, calls, capacity, &count, 0};
        ucall_client_take_completed(&take);
        failures += expect(outcome.status == ucall_status_success_k);
        return count;
    }

    /** The next call @p client completes, or one with a timeout outcome after five seconds. */
    ucall_completed_call_t wait(std::size_t client) {
        auto const deadline = deadline_after(5000);
        ucall_completed_call_t completed {};
        do {
            serve();
            if (take(client, &completed, 1)) return completed;
        } while (!expired(deadline));
        completed.outcome.status = ucall_status_timeout_k;
        return completed;
    }

    /** Polls until `/hold` retains a request, answering whether one came within five seconds. */
    [[nodiscard]] bool await_held(std::size_t client) {
        auto const deadline = deadline_after(5000);
        while (!held) {
            serve();
            take(client);
            if (expired(deadline)) return false;
        }
        return true;
    }
};

struct call_t {
    ucall_outcome_t outcome {};
    ucall_received_http_response_t response {};
    std::string url;

    void submit(fixture_t& fixture, std::size_t client = 0, char const* path = "/echo", std::size_t timeout = 0) {
        url = fixture.address + path;
        ucall_client_call_t call {};
        call.client = fixture.clients[client];
        call.outcome = &outcome;
        call.url = view(url);
        call.verb = ucall_verb_post_k;
        call.body = view("echo");
        call.context = this;
        call.options.timeout_microseconds = timeout;
        ucall_client_call(&call);
    }

    /** Checks @p completed is this call's successful response, keeping it to free later. */
    [[nodiscard]] std::size_t success(ucall_completed_call_t const& completed) {
        response = completed.response;
        bool const succeeded = completed.context == this && completed.outcome.status == ucall_status_success_k &&
                               completed.response;
        return expect(succeeded, "{}", ucall_status_name(completed.outcome.status));
    }
    ~call_t() { ucall_client_response_free(response); }
};

#pragma region Progress

static case_result_t test_progress_and_retention_unit() {
    fixture_t fixture;
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    call_t held, fast;
    held.submit(fixture, 0, "/hold");
    failures += expect(held.outcome.status == ucall_status_success_k && !fixture.held);
    fixture.serve();
    failures += expect(!fixture.held);
    require(failures, fixture.await_held(0), "the held request never arrived");
    fast.submit(fixture, 1);
    failures += expect(fast.outcome.status == ucall_status_success_k);
    failures += fast.success(fixture.wait(1));
    ucall_completed_call_t completed {};
    failures += expect(!fixture.take(0, &completed, 1));
    fixture.reply(fixture.held);
    fixture.held = nullptr;
    failures += held.success(fixture.wait(0));
    return failures + fixture.failures;
}

static case_result_t test_completion_credits_unit() {
    fixture_t fixture;
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    call_t first, second, refill;
    first.submit(fixture);
    second.submit(fixture);
    failures += expect(first.outcome.status == ucall_status_success_k &&
                       second.outcome.status == ucall_status_success_k);
    auto const deadline = deadline_after(5000);
    while (fixture.echoes != 2) {
        fixture.serve();
        fixture.take(0);
        require(failures, !expired(deadline), "{} of 2 echoes arrived", fixture.echoes);
    }
    refill.submit(fixture);
    failures += expect(refill.outcome.status == ucall_status_contended_k);
    failures += first.success(fixture.wait(0));
    refill.submit(fixture);
    failures += expect(refill.outcome.status == ucall_status_success_k);
    failures += second.success(fixture.wait(0));
    failures += refill.success(fixture.wait(0));
    return failures + fixture.failures;
}

static case_result_t test_timeout_and_cancel_unit() {
    std::size_t failures = 0;
    {
        announce("a held call times out");
        fixture_t fixture;
        require(failures, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
        call_t timed;
        timed.submit(fixture, 0, "/hold", 100000);
        require(failures, fixture.await_held(0), "the held request never arrived");
        auto completed = fixture.wait(0);
        failures += expect(completed.context == &timed && completed.outcome.status == ucall_status_timeout_k &&
                           !completed.response);
        failures += fixture.failures;
    }
    {
        announce("a reply after the client and server stop");
        fixture_t fixture;
        require(failures, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
        call_t held, queued;
        held.submit(fixture, 0, "/hold");
        require(failures, fixture.await_held(0), "the held request never arrived");
        queued.submit(fixture);
        failures += expect(queued.outcome.status == ucall_status_success_k);
        ucall_client_free(fixture.clients[0]);
        fixture.clients[0] = nullptr;
        ucall_server_stop(fixture.server);
        ucall_outcome_t outcome {};
        ucall_server_reply_content_t detached {fixture.server, &outcome, fixture.held, nullptr, 0, view("closed")};
        ucall_server_reply_content(&detached);
        failures += expect(outcome.status == ucall_status_connection_closed_k);
        fixture.held = nullptr;
        failures += fixture.failures;
    }
    return failures;
}

static case_result_t test_capability_admission_unit() {
    std::size_t failures = 0;
    ucall_client_handle_t client {};
    client.string_capabilities = std::numeric_limits<std::uint64_t>::max();
    ucall_outcome_t outcome {};
    std::size_t count = 1;
    ucall_client_take_completed_t take {&client, &outcome, nullptr, 0, &count, 0};
    ucall_client_take_completed(&take);
    failures += expect(outcome.status == ucall_status_unsupported_k && !count);
    ucall_server_handle_t server {};
    server.string_capabilities = client.string_capabilities;
    ucall_server_take_call_t poll {&server, &outcome, 0, 0};
    ucall_server_take_call(&poll);
    failures += expect(outcome.status == ucall_status_unsupported_k);
    ucall_server_stop(&server);
    failures += expect(server.stopped);
    return failures;
}

static case_result_t test_origin_reuse_and_fairness_unit() {
#if UCALL_WITH_POSIX
    using network_t = uc::serial_network<uc::posix_engine_t>;
    std::size_t failures = 0;
    ucall_client_t handle {};
    ucall_outcome_t outcome {};
    ucall_client_config_t config {};
    config.backend = ucall_io_backend_posix_k;
    config.cpu_class = ucall_cpu_class_serial_k;
    config.max_concurrent_connections = 3;
    config.max_concurrent_calls = 4;
    ucall_client_init_t init {&handle, &outcome, &config, nullptr};
    ucall_client_init(&init);
    require(failures, outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    auto& client = *static_cast<network_t::client_t*>(handle);
    for (auto url :
         {"http://127.0.0.1:18545/", "http://127.0.0.1:18545/", "http://127.0.0.1:18546/", "http://127.0.0.1:18545/"}) {
        ucall_client_call_t call {};
        call.client = handle;
        call.outcome = &outcome;
        call.url = view(url);
        call.verb = ucall_verb_get_k;
        ucall_client_call(&call);
        failures += expect(outcome.status == ucall_status_success_k);
    }
    std::array<uc::descriptor_t, 3> descriptors {};
    for (std::size_t i = 0; i != client.peers.size(); ++i) {
        auto& peer = *client.peers[i];
        auto& exchange = client.exchanges[i == 1 ? 2 : 0];
        failures += expect(
            network_t::copy_text(peer.authority, {exchange.authority.data(), exchange.authority.size() - 1}));
        peer.authority_hash = exchange.authority_hash;
        failures += expect(peer.connection.configure({}) == ucall_status_success_k);
        descriptors[i] = peer.connection.descriptor = client.engine.open_socket(AF_INET);
        failures += expect(descriptors[i] >= 0);
        peer.connection.stage = network_t::connection_stage_t::open_k;
    }
    auto& busy = *client.peers[2];
    busy.oldest_exchange = busy.newest_exchange = &client.exchanges[3];
    busy.exchanges_in_flight = 1;
    busy.connection.transmitting = network_t::transmit_state_t::sending_k;
    busy.connection.transmit_operation = network_t::operation_state_t::pending_k;
    network_t::unqueue_call(client, client.exchanges[3], &client.exchanges[2]);
    client.exchanges[3].stage = network_t::client_exchange_t::stage_t::active_k;
    network_t::client_progress(client);
    // Each idle connection takes its origin's waiting call due first, leaving the rest in order.
    failures += expect(client.peers[0]->oldest_exchange == &client.exchanges[0]);
    failures += expect(client.peers[1]->oldest_exchange == &client.exchanges[2]);
    failures += expect(client.exchanges[1].stage == network_t::client_exchange_t::stage_t::queued_k &&
                       client.waiting_head == &client.exchanges[1] && client.waiting_tail == &client.exchanges[1]);
    for (std::size_t i = 0; i != descriptors.size(); ++i)
        failures += expect(client.peers[i]->connection.descriptor == descriptors[i]);
    client.engine.stop();
    auto& released = *client.peers[1];
    released.oldest_exchange = released.newest_exchange = nullptr;
    released.exchanges_in_flight = 0;
    released.connection.transmitting = network_t::transmit_state_t::idle_k;
    released.connection.transmit_operation = network_t::operation_state_t::idle_k;
    client.exchanges[2].stage = network_t::client_exchange_t::stage_t::idle_k;
    network_t::client_progress(client);
    // The waiting call closes an idle connection to another origin, and dials once it has closed.
    failures += expect(client.exchanges[1].stage == network_t::client_exchange_t::stage_t::queued_k &&
                       client.waiting_head == &client.exchanges[1]);
    failures += expect(released.connection.stage == network_t::connection_stage_t::closing_k);
    ucall_client_free(handle);
    return failures;
#else
    return case_result_t::skipped("the POSIX backend is not compiled");
#endif
}

#pragma endregion Progress

#pragma region Batches

struct batch_context_t {
    fixture_t* fixture {};
    std::array<ucall_received_http_request_t, 4> requests {};
    std::array<std::size_t, 2> sizes {};
    std::chrono::steady_clock::time_point fired {};
    std::atomic<std::size_t> completed {};

    /** Checks that failed on the draining thread. */
    std::atomic<std::size_t> failures {};

    static void receive(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
        auto& state = *static_cast<batch_context_t*>(context);
        state.failures += expect(count && count <= state.requests.size(), "a batch of {}", count);
        if (!count || count > state.requests.size()) return;
        for (std::size_t i = 0; i != count; ++i) {
            state.failures += expect(requests[i]);
            state.requests[i] = requests[i];
        }
        auto completed = state.completed.load(std::memory_order_relaxed);
        state.failures += expect(completed < state.sizes.size(), "batch {} is one too many", completed);
        if (completed < state.sizes.size()) state.sizes[completed] = count;
        state.fired = std::chrono::steady_clock::now();
        state.completed.store(completed + 1, std::memory_order_release);
    }

    /** Polls until @p count batches have fired, answering whether they did in five seconds. */
    [[nodiscard]] bool wait(std::size_t count) {
        auto const deadline = deadline_after(5000);
        while (completed.load(std::memory_order_acquire) != count) {
            for (std::size_t i = 0; i != fixture->clients.size(); ++i) fixture->take(i);
            fixture->serve(200000);
            if (expired(deadline)) return false;
        }
        return true;
    }
};

static std::thread drain_batches(ucall_server_t server, std::atomic<std::size_t>& failures,
                                 ucall_http_batch_endpoint_t endpoint) {
    return std::thread {[server, &failures, endpoint] {
        ucall_outcome_t outcome {};
        ucall_server_take_batches_t take {server, &outcome, endpoint};
        ucall_server_take_batches(&take);
        failures += expect(outcome.status == ucall_status_success_k);
    }};
}

static case_result_t test_application_batches_unit() {
    batch_context_t batches;
    fixture_t fixture {batch_context_t::receive, &batches};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    batches.fixture = &fixture;
    std::size_t failures = 0;
    ucall_outcome_t outcome {};
    ucall_http_batch_endpoint_t prompt {};
    ucall_server_add_http_batch_endpoint_t add {
        fixture.server, &outcome, view("/prompt"), ucall_verb_post_k, batch_context_t::receive, &batches, 2, 2, 300,
        &prompt};
    ucall_server_add_http_batch_endpoint(&add);
    require(failures, outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    auto requests = [&] {
        ucall_event_loop_statistics_t counters {};
        ucall_server_event_loop_statistics_t query {fixture.server, &outcome, 0, &counters};
        ucall_server_event_loop_statistics(&query);
        return counters.requests;
    };
    auto batch_statistics = [&](ucall_http_batch_endpoint_t endpoint) {
        ucall_batch_endpoint_statistics_t counters {};
        ucall_server_batch_endpoint_statistics_t query {fixture.server, &outcome, endpoint, &counters};
        ucall_server_batch_endpoint_statistics(&query);
        return counters;
    };
    auto drain = drain_batches(fixture.server, batches.failures, fixture.batch_endpoint);
    auto prompt_drain = drain_batches(fixture.server, batches.failures, prompt);
    call_t first, second, partial;
    first.submit(fixture, 0, "/batch");
    second.submit(fixture, 1, "/batch");
    bool const fired = batches.wait(1);
    failures += expect(fired, "the full batch never fired");
    if (fired) {
        failures += expect(batches.sizes[0] == 2);
        auto const full = batch_statistics(fixture.batch_endpoint);
        failures += expect(full.batches == 1 && full.requests == 2 && full.filled_batches == 1 &&
                               full.ready_batches == 0 && full.expired_batches == 0,
                           "a 2/2 batch counted {} batches, {} filled, {} ready, {} expired", full.batches,
                           full.filled_batches, full.ready_batches, full.expired_batches);
        fixture.reply(batches.requests[1]);
        fixture.reply(batches.requests[0]);
        failures += first.success(fixture.wait(0));
        failures += second.success(fixture.wait(1));
        // The serving round that dispatched the request began no later than its deposit.
        auto const dispatched_before = requests();
        auto const deadline = deadline_after(5000);
        std::chrono::steady_clock::time_point deposited {};
        partial.submit(fixture, 0, "/prompt");
        while (batches.completed.load(std::memory_order_acquire) != 2 && !expired(deadline)) {
            fixture.take(0);
            auto const round = std::chrono::steady_clock::now();
            fixture.serve();
            if (deposited == std::chrono::steady_clock::time_point {} && requests() != dispatched_before)
                deposited = round;
        }
        bool const partial_fired = batches.completed.load(std::memory_order_acquire) == 2;
        failures += expect(partial_fired, "the partial batch never fired");
        if (partial_fired) {
            auto const late = std::chrono::duration_cast<std::chrono::microseconds>(batches.fired - deposited).count();
            failures += expect(batches.sizes[1] == 1);
            auto const partial_counted = batch_statistics(prompt);
            failures += expect(partial_counted.batches == 1 && partial_counted.requests == 1 &&
                                   partial_counted.expired_batches == 1 && partial_counted.filled_batches == 0,
                               "a partial batch counted {} batches, {} expired", partial_counted.batches,
                               partial_counted.expired_batches);
            failures += expect(late < 1000, "a 300 microsecond budget fired {} microseconds after the deposit", late);
            fixture.reply(batches.requests[0]);
            failures += partial.success(fixture.wait(0));
        }
    }
    ucall_server_stop(fixture.server);
    fixture.serve();
    drain.join();
    prompt_drain.join();
    return failures + fixture.failures + batches.failures;
}

static case_result_t test_batches_across_loops_unit() {
    if (UCALL_OS_WINDOWS_) return case_result_t::skipped("IOCP accepts one loop per interface");
    std::size_t failures = 0;
    ucall_server_t server {};
    ucall_client_t client {};
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = "127.0.0.1:0";
    network_interface.max_concurrent_connections = 4;
    network_interface.event_loops = 2;
    ucall_server_config_t config {}, resolved {};
    config.interfaces = &network_interface;
    config.interfaces_count = 1;
    ucall_server_init_t init {&server, &outcome, &config, &resolved};
    ucall_server_init(&init);
    require(failures, outcome.status == ucall_status_success_k && resolved.interfaces[0].event_loops == 2, "{}",
            ucall_status_name(outcome.status));
    batch_context_t batches;
    ucall_http_batch_endpoint_t endpoint {};
    ucall_server_add_http_batch_endpoint_t add {
        server, &outcome, view("/batch"), ucall_verb_post_k, batch_context_t::receive, &batches,
        4,      4,        10000000,       &endpoint};
    ucall_server_add_http_batch_endpoint(&add);
    failures += expect(outcome.status == ucall_status_success_k);
    ucall_client_config_t client_config {};
    client_config.max_concurrent_connections = 4;
    ucall_client_init_t client_init {&client, &outcome, &client_config, nullptr};
    ucall_client_init(&client_init);
    failures += expect(outcome.status == ucall_status_success_k);
    auto drain = drain_batches(server, batches.failures, endpoint);
    // Each loop owns two of the four connections, so each receives exactly half of the batch.
    std::string url = std::string {"http://"} + resolved.interfaces[0].address + "/batch";
    for (std::size_t i = 0; i != 4; ++i) {
        ucall_client_call_t call {};
        call.client = client;
        call.outcome = &outcome;
        call.url = view(url);
        call.verb = ucall_verb_post_k;
        call.body = view("echo");
        ucall_client_call(&call);
        failures += expect(outcome.status == ucall_status_success_k);
    }
    std::array<ucall_completed_call_t, 4> completed {};
    std::size_t received {};
    auto const deadline = deadline_after(5000);
    auto progress = [&] {
        for (std::size_t loop = 0; loop != 2; ++loop) {
            ucall_server_take_call_t serving {server, &outcome, loop, 0};
            ucall_server_take_call(&serving);
            failures += expect(outcome.status == ucall_status_success_k);
        }
        std::size_t count {};
        ucall_client_take_completed_t take {client, &outcome, completed.data() + received, completed.size() - received,
                                            &count, 0};
        ucall_client_take_completed(&take);
        failures += expect(outcome.status == ucall_status_success_k);
        received += count;
        return !expired(deadline);
    };
    while (!batches.completed.load(std::memory_order_acquire) && progress()) {}
    failures += expect(batches.completed == 1 && batches.sizes[0] == 4, "{} batches, the first of {}",
                       batches.completed.load(), batches.sizes[0]);
    if (batches.completed == 1)
        for (auto request : batches.requests) {
            ucall_server_reply_content_t response {server, &outcome, request, nullptr, 0, view("echo")};
            ucall_server_reply_content(&response);
            failures += expect(outcome.status == ucall_status_success_k);
        }
    while (received != completed.size() && progress()) {}
    failures += expect(received == completed.size(), "{} of {} calls completed", received, completed.size());
    for (std::size_t i = 0; i != received; ++i) {
        failures += expect(completed[i].outcome.status == ucall_status_success_k);
        ucall_client_response_free(completed[i].response);
    }
    failures += expect(batches.completed == 1);
    ucall_server_stop(server);
    progress();
    drain.join();
    ucall_client_free(client);
    ucall_server_free(server);
    return failures + batches.failures;
}

/** Two batch endpoints, the first of whose callbacks blocks until the second's batch arrives. */
struct relay_t {
    std::array<std::atomic<ucall_received_http_request_t>, 2> requests {};
    std::atomic<std::size_t> failures {};

    static void first(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
        auto& relay = *static_cast<relay_t*>(context);
        relay.requests[0].store(requests[0], std::memory_order_release);
        auto const deadline = deadline_after(5000);
        while (!relay.requests[1].load(std::memory_order_acquire) && !expired(deadline)) std::this_thread::yield();
        relay.failures += expect(count == 1 && relay.requests[1].load(std::memory_order_acquire),
                                 "the second endpoint's batch waited behind the first's callback");
    }
    static void second(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
        auto& relay = *static_cast<relay_t*>(context);
        relay.failures += expect(count == 1);
        relay.requests[1].store(requests[0], std::memory_order_release);
    }
};

static case_result_t test_batch_endpoints_drain_apart_unit() {
    fixture_t fixture;
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    relay_t relay;
    using route_t = std::pair<char const*, ucall_received_http_batch_callback_t>;
    std::array routes {route_t {"/first", relay_t::first}, route_t {"/second", relay_t::second}};
    std::array<ucall_http_batch_endpoint_t, 2> endpoints {};
    for (std::size_t i = 0; i != routes.size(); ++i) {
        ucall_outcome_t outcome {};
        ucall_server_add_http_batch_endpoint_t add {
            fixture.server, &outcome, view(routes[i].first), ucall_verb_post_k, routes[i].second, &relay, 1, 1, 0,
            &endpoints[i]};
        ucall_server_add_http_batch_endpoint(&add);
        require(failures, outcome.status == ucall_status_success_k && endpoints[i], "{}",
                ucall_status_name(outcome.status));
    }
    auto first_drain = drain_batches(fixture.server, relay.failures, endpoints[0]);
    auto second_drain = drain_batches(fixture.server, relay.failures, endpoints[1]);
    auto const deadline = deadline_after(5000);
    auto serve_until = [&](std::size_t endpoint) {
        while (!relay.requests[endpoint].load(std::memory_order_acquire) && !expired(deadline)) {
            for (std::size_t client = 0; client != fixture.clients.size(); ++client) fixture.take(client);
            fixture.serve(1000);
        }
        return relay.requests[endpoint].load(std::memory_order_acquire);
    };
    call_t first, second;
    first.submit(fixture, 0, "/first");
    auto first_request = serve_until(0);
    failures += expect(first_request, "the first batch never fired");
    second.submit(fixture, 1, "/second");
    auto second_request = serve_until(1);
    failures += expect(second_request, "the second batch never fired");
    if (first_request && second_request) {
        fixture.reply(second_request);
        fixture.reply(first_request);
        failures += first.success(fixture.wait(0));
        failures += second.success(fixture.wait(1));
    }
    ucall_server_stop(fixture.server);
    fixture.serve();
    first_drain.join();
    second_drain.join();
    return failures + fixture.failures + relay.failures;
}

static case_result_t test_batch_timeout_sleeps_unit() {
    batch_context_t batches;
    fixture_t fixture {batch_context_t::receive, &batches};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    ucall_outcome_t outcome {};
    ucall_server_take_batch_t missing {fixture.server, &outcome, nullptr, 0};
    ucall_server_take_batch(&missing);
    failures += expect(outcome.status == ucall_status_invalid_argument_k, "{}", ucall_status_name(outcome.status));
    // No event loop is ever polled, so only the drain's own wait can end the call.
    auto const started = std::chrono::steady_clock::now();
    auto const processor_started = std::clock();
    ucall_server_take_batch_t take {fixture.server, &outcome, fixture.batch_endpoint, 100000};
    ucall_server_take_batch(&take);
    auto const processor_spent = std::clock() - processor_started;
    auto const waited =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
    failures += expect(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    failures += expect(waited >= 100 && waited < 2000, "returned after {} ms", waited);
    failures += expect(processor_spent < CLOCKS_PER_SEC / 20, "spent {} processor ticks waiting",
                       static_cast<long long>(processor_spent));
    failures += expect(!batches.completed.load());
    return failures + fixture.failures + batches.failures;
}

/** Four requests in one segment over one connection fill a batch of four, and their replies,
 *  given in reverse, leave in request order. */
static case_result_t test_pipelined_batches_unit() {
#if UCALL_OS_POSIX_
    std::size_t failures = 0;
    ucall_server_t server {};
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = "127.0.0.1:0";
    network_interface.max_concurrent_connections = 1;
    network_interface.max_pipelined_requests = 4;
    ucall_server_config_t config {}, resolved {};
    config.interfaces = &network_interface;
    config.interfaces_count = 1;
    ucall_server_init_t init {&server, &outcome, &config, &resolved};
    ucall_server_init(&init);
    require(failures, outcome.status == ucall_status_success_k && resolved.interfaces[0].max_pipelined_requests == 4,
            "{}", ucall_status_name(outcome.status));
    batch_context_t batches;
    ucall_http_batch_endpoint_t endpoint {};
    ucall_server_add_http_batch_endpoint_t add {
        server, &outcome, view("/batch"), ucall_verb_post_k, batch_context_t::receive, &batches,
        4,      4,        10000000,       &endpoint};
    ucall_server_add_http_batch_endpoint(&add);
    failures += expect(outcome.status == ucall_status_success_k);
    auto drain = drain_batches(server, batches.failures, endpoint);
    std::thread serving {[&] {
        ucall_outcome_t served {};
        ucall_server_take_calls_t take {server, &served, 0};
        ucall_server_take_calls(&take);
        batches.failures += expect(served.status == ucall_status_success_k);
    }};
    std::string burst;
    for (std::size_t i = 0; i != 4; ++i)
        burst += fmt::format("POST /batch HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\n{}", i);
    raw_client_t client;
    bool const written = client.connect(resolved.interfaces[0].address) &&
                         client.write(ascii_bytes(burst.data(), burst.size()), burst.size(), deadline_after(5000));
    failures += expect(written, "the burst was not written");
    auto const deadline = deadline_after(5000);
    while (written && !batches.completed.load(std::memory_order_acquire) && !expired(deadline))
        std::this_thread::sleep_for(std::chrono::milliseconds {1});
    bool const fired = batches.completed.load(std::memory_order_acquire) == 1 && batches.sizes[0] == 4;
    failures += expect(fired, "{} batches, the first of {}", batches.completed.load(), batches.sizes[0]);
    if (fired) {
        for (std::size_t i = 4; i--;) {
            ucall_bytes_view_t body {};
            ucall_server_request_body_t extract {server, &outcome, batches.requests[i], &body};
            ucall_server_request_body(&extract);
            failures += expect(outcome.status == ucall_status_success_k && body.length == 1 && body.data[0] == '0' + i,
                               "request {} of the batch", i);
            ucall_server_reply_content_t response {server, &outcome, batches.requests[i], nullptr, 0, body};
            ucall_server_reply_content(&response);
            failures += expect(outcome.status == ucall_status_success_k);
        }
        std::size_t offset = 0;
        for (std::size_t i = 0; i != 4; ++i) {
            auto const response = read_response(client, offset);
            failures += expect(response.status == 200 && response.body == std::to_string(i), "response {}: {} {}", i,
                               response.status, response.body);
            if (!response.length) break;
            offset += response.length;
        }
    }
    ucall_server_stop(server);
    serving.join();
    drain.join();
    ucall_server_free(server);
    return failures + batches.failures;
#else
    return case_result_t::skipped("raw sockets need POSIX");
#endif
}

#pragma endregion Batches

#pragma region Allocators

struct allocator_state_t {
    std::size_t allocations {}, live {};
    std::size_t remaining {std::numeric_limits<std::size_t>::max()};
};
template <typename value_type_>
struct counting_allocator {
    using value_type = value_type_;
    using propagate_on_container_move_assignment = std::true_type;
    allocator_state_t* state {};
    counting_allocator() noexcept = default;
    explicit counting_allocator(allocator_state_t& state) noexcept : state(&state) {}
    template <typename other_type_>
    counting_allocator(counting_allocator<other_type_> const& other) noexcept : state(other.state) {}
    value_type_* allocate(std::size_t count) noexcept {
        if (!state->remaining) return nullptr;
        --state->remaining;
        auto* pointer = uc::st::default_allocator<value_type_> {}.allocate(count);
        if (pointer) {
            ++state->allocations;
            ++state->live;
        }
        return pointer;
    }
    void deallocate(value_type_* pointer, std::size_t count) noexcept {
        --state->live;
        uc::st::default_allocator<value_type_> {}.deallocate(pointer, count);
    }
};

#if UCALL_WITH_POSIX
using counted_network_t = uc::serial_network<uc::posix_engine_t, counting_allocator<uc::byte_t>>;

/** A server whose echo route keeps the outcome of its last reply, which no client can observe. */
struct echo_route_t {
    ucall_server_t server {};
    ucall_status_t replied {ucall_status_success_k};

    static void echo(ucall_received_http_request_t request, void* context) {
        auto& route = *static_cast<echo_route_t*>(context);
        ucall_outcome_t outcome {};
        ucall_bytes_view_t body {};
        ucall_server_request_body_t get {route.server, &outcome, request, &body};
        ucall_server_request_body(&get);
        ucall_server_reply_content_t reply {route.server, &outcome, request, nullptr, 0, body};
        ucall_server_reply_content(&reply);
        route.replied = outcome.status;
    }

    /** Registers @c echo at `/echo/{id}`, answering the outcome. */
    ucall_status_t add() {
        ucall_outcome_t outcome {};
        ucall_server_add_http_endpoint_t add {server, &outcome, view("/echo/{id}"), ucall_verb_post_k, echo, this};
        ucall_server_add_http_endpoint(&add);
        return outcome.status;
    }
};

/** Polls @p route and @p client until the client completes a call, answering it, or a call whose
 *  outcome is the server's own failure or a timeout after @p milliseconds. */
static ucall_completed_call_t complete_call(echo_route_t const& route, ucall_client_t client, long milliseconds) {
    ucall_completed_call_t completed {};
    std::size_t count {};
    ucall_outcome_t outcome {};
    auto const deadline = deadline_after(milliseconds);
    while (!count) {
        ucall_server_take_call_t serve {route.server, &outcome, 0, 0};
        ucall_server_take_call(&serve);
        if (outcome.status == ucall_status_success_k) outcome.status = route.replied;
        if (outcome.status != ucall_status_success_k) {
            completed.outcome.status = outcome.status;
            break;
        }
        ucall_client_take_completed_t take {client, &outcome, &completed, 1, &count, 0};
        ucall_client_take_completed(&take);
        if (!count && expired(deadline)) {
            completed.outcome.status = ucall_status_timeout_k;
            break;
        }
    }
    return completed;
}
#endif

static case_result_t test_allocator_propagation_unit() {
#if UCALL_WITH_POSIX
    using allocator_t = counting_allocator<uc::byte_t>;
    std::size_t failures = 0;
    allocator_state_t state;
    allocator_t allocator {state};
    echo_route_t route;
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = "127.0.0.1:0";
    network_interface.max_concurrent_connections = 1;
    ucall_server_config_t server_config {}, resolved {};
    server_config.interfaces = &network_interface;
    server_config.interfaces_count = 1;
    server_config.backend = ucall_io_backend_posix_k;
    ucall_server_init_t server_init {&route.server, &outcome, &server_config, &resolved};
    counted_network_t::server_init(&server_init, allocator);
    require(failures, outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    failures += expect(route.add() == ucall_status_success_k);
    ucall_client_t client {};
    ucall_client_config_t client_config {};
    client_config.backend = ucall_io_backend_posix_k;
    client_config.max_concurrent_connections = 1;
    ucall_client_init_t client_init {&client, &outcome, &client_config, nullptr};
    auto live = state.live;
    state.remaining = 0;
    counted_network_t::client_init(&client_init, allocator);
    failures += expect(!client && outcome.status == ucall_status_out_of_memory_k && state.live == live);
    state.remaining = std::numeric_limits<std::size_t>::max();
    counted_network_t::client_init(&client_init, allocator);
    require(failures, outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    std::string url = std::string {"http://"} + resolved.interfaces[0].address + "/echo/1";
    std::string payload(1024, '\0');
    ucall_client_call_t call {};
    call.client = client;
    call.outcome = &outcome;
    call.url = view(url);
    call.verb = ucall_verb_post_k;
    call.body = view(payload);
    ucall_client_call(&call);
    failures += expect(outcome.status == ucall_status_success_k);
    auto completed = complete_call(route, client, 5000);
    failures += expect(completed.outcome.status == ucall_status_success_k, "{}",
                       ucall_status_name(completed.outcome.status));
    ucall_bytes_view_t body {};
    if (completed.response) {
        ucall_client_response_body_t get {completed.response, &outcome, &body};
        ucall_client_response_body(&get);
        failures += expect(outcome.status == ucall_status_success_k && body.length == payload.size());
    }
    ucall_client_free(client);
    ucall_server_free(route.server);
    // The response outlives both, so its bytes still come from the allocator.
    failures += expect(state.allocations && state.live && body.length == payload.size() &&
                       !std::memcmp(body.data, payload.data(), body.length));
    ucall_client_response_free(completed.response);
    failures += expect(!state.live, "{} allocations outlived every owner", state.live);
    return failures;
#else
    return case_result_t::skipped("the POSIX backend is not compiled");
#endif
}

/** Starves the server of allocations from a growing budget onward, across its init and its first
 *  exchange. Each budget completes the exchange, or fails cleanly with every byte returned. */
static case_result_t test_allocation_failure_safety() {
#if UCALL_WITH_POSIX
    std::size_t failures = 0;
    std::string const payload(64, 'x');
    for (std::size_t budget = 0;; ++budget) {
        require(failures, budget != 10000, "no budget completed the exchange");
        allocator_state_t state;
        state.remaining = budget;
        echo_route_t route;
        ucall_outcome_t outcome {};
        ucall_network_interface_t network_interface {};
        network_interface.address = "127.0.0.1:0";
        network_interface.max_concurrent_connections = 1;
        ucall_server_config_t server_config {}, resolved {};
        server_config.interfaces = &network_interface;
        server_config.interfaces_count = 1;
        ucall_server_init_t server_init {&route.server, &outcome, &server_config, &resolved};
        counted_network_t::server_init(&server_init, counting_allocator<uc::byte_t> {state});
        if (outcome.status == ucall_status_success_k) outcome.status = route.add();
        ucall_status_t completion = outcome.status;
        if (outcome.status == ucall_status_success_k) {
            ucall_client_t client {};
            ucall_client_config_t client_config {};
            client_config.max_concurrent_connections = 1;
            ucall_client_init_t client_init {&client, &outcome, &client_config, nullptr};
            ucall_client_init(&client_init);
            require(failures, outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
            std::string url = std::string {"http://"} + resolved.interfaces[0].address + "/echo/1";
            ucall_client_call_t call {};
            call.client = client;
            call.outcome = &outcome;
            call.url = view(url);
            call.verb = ucall_verb_post_k;
            call.body = view(payload);
            ucall_client_call(&call);
            failures += expect(outcome.status == ucall_status_success_k);
            auto completed = complete_call(route, client, 500);
            completion = completed.outcome.status;
            if (completed.response) {
                ucall_bytes_view_t body {};
                ucall_client_response_body_t get {completed.response, &outcome, &body};
                ucall_client_response_body(&get);
                bool const echoed = body.length == payload.size() && !std::memcmp(body.data, payload.data(), 64);
                failures += expect(echoed, "budget {} answered {} bytes", budget, body.length);
                ucall_client_response_free(completed.response);
            }
            ucall_client_free(client);
        }
        ucall_server_free(route.server);
        failures += expect(!state.live, "budget {} kept {} allocations", budget, state.live);
        // A starved connection can only be dropped, which its client sees as a close or a reset.
        failures += expect(completion == ucall_status_success_k || completion == ucall_status_out_of_memory_k ||
                               completion == ucall_status_connection_closed_k || completion == ucall_status_io_k,
                           "budget {} ended with {}", budget, ucall_status_name(completion));
        if (completion == ucall_status_success_k) {
            announce("{} budgets swept", budget + 1);
            return failures;
        }
    }
#else
    return case_result_t::skipped("the POSIX backend is not compiled");
#endif
}

#pragma endregion Allocators

int main(int, char** argv) {
    install_test_signal_handlers();
    fmt::print("Hi, dear tester! You look nice today!\n");
    configure_tests();

    suite_totals_t totals {.program = argv[0]};
    run_test(totals, "test_allocator_propagation_unit", test_allocator_propagation_unit);
    run_test(totals, "test_allocation_failure_safety", test_allocation_failure_safety);
    run_test(totals, "test_origin_reuse_and_fairness_unit", test_origin_reuse_and_fairness_unit);
    run_test(totals, "test_capability_admission_unit", test_capability_admission_unit);
    run_test(totals, "test_progress_and_retention_unit", test_progress_and_retention_unit);
    run_test(totals, "test_completion_credits_unit", test_completion_credits_unit);
    run_test(totals, "test_timeout_and_cancel_unit", test_timeout_and_cancel_unit);
    run_test(totals, "test_application_batches_unit", test_application_batches_unit);
    run_test(totals, "test_batches_across_loops_unit", test_batches_across_loops_unit);
    run_test(totals, "test_batch_endpoints_drain_apart_unit", test_batch_endpoints_drain_apart_unit);
    run_test(totals, "test_batch_timeout_sleeps_unit", test_batch_timeout_sleeps_unit);
    run_test(totals, "test_pipelined_batches_unit", test_pipelined_batches_unit);
    return suite_exit_code(totals);
}
