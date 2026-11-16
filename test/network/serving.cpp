/**
 *  @file test/network/serving.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Caller-driven progress, retained requests, completion credits, application batches, and
 *      the eviction of idle and stalled connections.
 */
#include <ctime> // `std::clock`

#include <network.hpp>

#include "ucall/utilities/sockets.hpp" // `monotonic_ns`, `nonblocking`

#if UCALL_OS_POSIX_
#include <sys/resource.h> // `getrlimit`, `setrlimit`, `RLIMIT_MEMLOCK`
#endif

namespace unum::ucall::test::network {

/** A server with POST echo and hold routes, an optional batch route, and two clients, all polled
 *  from the case's own thread. */
struct polling_fixture_t {
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
        ucall_server_reply_content_t response {server, &outcome, request, ucall_http_status_ok_k, nullptr, 0, body};
        ucall_server_reply_content(&response);
        failures += expect(outcome.status == ucall_status_success_k);
    }
    static void echo(ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<polling_fixture_t*>(context);
        ++fixture.echoes;
        fixture.reply(request);
    }
    static void hold(ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<polling_fixture_t*>(context);
        fixture.failures += expect(!fixture.held, "a second request arrived while one is held");
        fixture.held = request;
    }
    polling_fixture_t(sweep_cell_t const& cell, ucall_received_http_batch_callback_t batch_callback = nullptr,
                      void* batch_context = nullptr) {
        ucall_outcome_t outcome {};
        ucall_network_interface_t network_interface {};
        network_interface.address = uc::bytes_view("127.0.0.1:0");
        network_interface.max_concurrent_connections = 2;
        ucall_server_options_t config {};
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
        config.backend = cell.backend;
        config.cpu_class_ceiling = cell.cpu_class_ceiling;
        ucall_server_options_t resolved {};
        ucall_server_init_t init {&server, &outcome, &config, &resolved};
        ucall_server_init(&init);
        if ((status = outcome.status) != ucall_status_success_k) return;
        address = fmt::format("http://{}", uc::text_view(resolved.interfaces[0].address));
        using route_t = std::pair<char const*, ucall_received_http_request_callback_t>;
        for (auto [route, callback] : {route_t {"/echo", echo}, route_t {"/hold", hold}}) {
            ucall_server_add_http_endpoint_t add {server,   &outcome, uc::bytes_view(route), ucall_verb_post_k,
                                                  callback, this};
            ucall_server_add_http_endpoint(&add);
            if ((status = outcome.status) != ucall_status_success_k) return;
        }
        for (auto& client : clients) {
            ucall_client_options_t client_config {};
            client_config.max_concurrent_connections = 1;
            client_config.max_concurrent_calls = 2;
            client_config.backend = cell.backend;
            client_config.cpu_class_ceiling = cell.cpu_class_ceiling;
            ucall_client_init_t client_init {&client, &outcome, &client_config, nullptr};
            ucall_client_init(&client_init);
            if ((status = outcome.status) != ucall_status_success_k) return;
        }
        if (batch_callback) {
            ucall_server_add_http_batch_endpoint_t add {
                server, &outcome, uc::bytes_view("/batch"), ucall_verb_post_k, batch_callback, batch_context, 2,
                2,      100000,   &batch_endpoint};
            ucall_server_add_http_batch_endpoint(&add);
            status = outcome.status;
        }
    }
    ~polling_fixture_t() {
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

    /** The next call @p client completes, or one with a timeout outcome once @c wait_limit_k
     *  passes. */
    ucall_completed_call_t wait(std::size_t client) {
        steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
        ucall_completed_call_t completed {};
        do {
            serve();
            if (take(client, &completed, 1)) return completed;
        } while (steady_clock::now() <= deadline);
        completed.outcome.status = ucall_status_timeout_k;
        return completed;
    }

    /** Polls until <tt>/hold</tt> retains a request, answering whether one came within @c wait_limit_k. */
    [[nodiscard]] bool await_held(std::size_t client) {
        steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
        while (!held) {
            serve();
            take(client);
            if (steady_clock::now() > deadline) return false;
        }
        return true;
    }
};

struct call_t {
    ucall_outcome_t outcome {};
    ucall_received_http_response_t response {};
    std::string url;

    void submit(polling_fixture_t& fixture, std::size_t client = 0, char const* path = "/echo",
                std::size_t timeout = 0) {
        url = fmt::format("{}{}", fixture.address, path);
        ucall_client_call_t call {};
        call.client = fixture.clients[client];
        call.outcome = &outcome;
        call.url = uc::bytes_view(url);
        call.verb = ucall_verb_post_k;
        call.body = uc::bytes_view("echo");
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

static std::size_t test_progress_and_retention(sweep_cell_t const& cell) {
    polling_fixture_t fixture {cell};
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

static std::size_t test_completion_credits(sweep_cell_t const& cell) {
    polling_fixture_t fixture {cell};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    call_t first, second, refill;
    first.submit(fixture);
    second.submit(fixture);
    failures += expect(first.outcome.status == ucall_status_success_k &&
                       second.outcome.status == ucall_status_success_k);
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
    while (fixture.echoes != 2) {
        fixture.serve();
        fixture.take(0);
        require(failures, steady_clock::now() <= deadline, "{} of 2 echoes arrived", fixture.echoes);
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

static std::size_t test_timeout_and_cancel(sweep_cell_t const& cell) {
    std::size_t failures = 0;
    {
        polling_fixture_t fixture {cell};
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
        polling_fixture_t fixture {cell};
        require(failures, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
        call_t held, queued;
        held.submit(fixture, 0, "/hold");
        require(failures, fixture.await_held(0), "the held request never arrived");
        queued.submit(fixture);
        failures += expect(queued.outcome.status == ucall_status_success_k);
        ucall_client_free(fixture.clients[0]);
        fixture.clients[0] = nullptr;
        // The first stop drains, which still takes replies; the second refuses them.
        ucall_server_stop(fixture.server);
        ucall_server_stop(fixture.server);
        ucall_outcome_t outcome {};
        ucall_server_reply_content_t detached {
            fixture.server, &outcome, fixture.held, ucall_http_status_ok_k, nullptr, 0, uc::bytes_view("closed")};
        ucall_server_reply_content(&detached);
        failures += expect(outcome.status == ucall_status_connection_closed_k);
        fixture.held = nullptr;
        failures += fixture.failures;
    }
    return failures;
}

/** Once a stopped loop retires, every later round reports @c ucall_status_connection_closed_k, so a
 *  caller polling in slices knows when to stop. */
static std::size_t test_take_call_reports_retired(sweep_cell_t const& cell) {
    polling_fixture_t fixture {cell};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    fixture.serve();
    ucall_server_stop(fixture.server);
    ucall_outcome_t outcome {};
    ucall_server_take_call_t serving {fixture.server, &outcome, 0, 1000};
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
    do ucall_server_take_call(&serving);
    while (outcome.status == ucall_status_success_k && steady_clock::now() <= deadline);
    failures += expect(outcome.status == ucall_status_connection_closed_k, "the drained loop answered {}",
                       ucall_status_name(outcome.status));
    ucall_server_take_call(&serving);
    failures += expect(outcome.status == ucall_status_connection_closed_k, "a later round answered {}",
                       ucall_status_name(outcome.status));
    return failures + fixture.failures;
}

#pragma endregion Progress

#pragma region Batches

struct batch_context_t {
    polling_fixture_t* fixture {};
    std::array<ucall_received_http_request_t, 4> requests {};
    std::array<std::size_t, 2> sizes {};
    std::atomic<std::size_t> completed {};

    /** Checks that failed on the polling thread. */
    std::atomic<std::size_t> failures {};

    static void receive(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
        auto& state = *static_cast<batch_context_t*>(context);
        uc::span<ucall_received_http_request_t const> const batch {requests, count};
        state.failures += expect(!batch.empty() && batch.size() <= state.requests.size(), "a batch of {}",
                                 batch.size());
        if (batch.empty() || batch.size() > state.requests.size()) return;
        for (std::size_t i = 0; i != batch.size(); ++i) {
            state.failures += expect(batch[i]);
            state.requests[i] = batch[i];
        }
        auto completed = state.completed.load(std::memory_order_relaxed);
        state.failures += expect(completed < state.sizes.size(), "batch {} is one too many", completed);
        if (completed < state.sizes.size()) state.sizes[completed] = batch.size();
        state.completed.store(completed + 1, std::memory_order_release);
    }

    /** Polls until @p count batches have fired, answering whether they did within
     *  @c wait_limit_k. */
    [[nodiscard]] bool wait(std::size_t count) {
        steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
        while (completed.load(std::memory_order_acquire) != count) {
            for (std::size_t i = 0; i != fixture->clients.size(); ++i) fixture->take(i);
            fixture->serve(200000);
            if (steady_clock::now() > deadline) return false;
        }
        return true;
    }
};

static std::thread poll_batches(ucall_server_t server, std::atomic<std::size_t>& failures,
                                ucall_http_batch_endpoint_t endpoint) {
    return std::thread {[server, &failures, endpoint] {
        ucall_outcome_t outcome {};
        ucall_server_take_batches_t take {server, &outcome, endpoint};
        ucall_server_take_batches(&take);
        failures += expect(outcome.status == ucall_status_success_k);
    }};
}

static std::size_t test_application_batches(sweep_cell_t const& cell) {
    batch_context_t batches;
    polling_fixture_t fixture {cell, batch_context_t::receive, &batches};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    batches.fixture = &fixture;
    std::size_t failures = 0;
    ucall_outcome_t outcome {};
    ucall_http_batch_endpoint_t prompt {};
    ucall_server_add_http_batch_endpoint_t add {fixture.server,
                                                &outcome,
                                                uc::bytes_view("/prompt"),
                                                ucall_verb_post_k,
                                                batch_context_t::receive,
                                                &batches,
                                                2,
                                                2,
                                                300,
                                                &prompt};
    ucall_server_add_http_batch_endpoint(&add);
    require(failures, outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    auto batch_statistics = [&](ucall_http_batch_endpoint_t endpoint) {
        ucall_batch_endpoint_statistics_t counters {};
        ucall_server_batch_endpoint_statistics_t query {fixture.server, &outcome, endpoint, &counters};
        ucall_server_batch_endpoint_statistics(&query);
        return counters;
    };
    auto poller = poll_batches(fixture.server, batches.failures, fixture.batch_endpoint);
    auto prompt_poller = poll_batches(fixture.server, batches.failures, prompt);
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
        steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
        partial.submit(fixture, 0, "/prompt");
        while (batches.completed.load(std::memory_order_acquire) != 2 && steady_clock::now() <= deadline) {
            fixture.take(0);
            fixture.serve();
        }
        bool const partial_fired = batches.completed.load(std::memory_order_acquire) == 2;
        failures += expect(partial_fired, "the partial batch never fired");
        if (partial_fired) {
            failures += expect(batches.sizes[1] == 1);
            auto const partial_counted = batch_statistics(prompt);
            // Its latency budget, not a stopwatch, fired it: expired below the minimum, not ready.
            failures += expect(partial_counted.batches == 1 && partial_counted.requests == 1 &&
                                   partial_counted.expired_batches == 1 && partial_counted.ready_batches == 0 &&
                                   partial_counted.filled_batches == 0,
                               "a partial batch counted {} batches, {} expired, {} ready", partial_counted.batches,
                               partial_counted.expired_batches, partial_counted.ready_batches);
            fixture.reply(batches.requests[0]);
            failures += partial.success(fixture.wait(0));
        }
    }
    // A second stop cuts, so the polling owners return without the loops polled until they retire.
    ucall_server_stop(fixture.server);
    ucall_server_stop(fixture.server);
    ucall_server_take_call_t serving {fixture.server, &outcome, 0, 0};
    ucall_server_take_call(&serving);
    failures += expect(outcome.status == ucall_status_success_k || outcome.status == ucall_status_connection_closed_k,
                       "a cut round answered {}", ucall_status_name(outcome.status));
    poller.join();
    prompt_poller.join();
    return failures + fixture.failures + batches.failures;
}

static std::size_t test_batches_across_loops(sweep_cell_t const& cell) {
    if (UCALL_OS_WINDOWS_) return report("test_batches_across_loops", "IOCP accepts one loop per interface");
    std::size_t failures = 0;
    ucall_server_t server {};
    ucall_client_t client {};
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = uc::bytes_view("127.0.0.1:0");
    network_interface.max_concurrent_connections = 4;
    network_interface.event_loops = 2;
    ucall_server_options_t config {}, resolved {};
    config.backend = cell.backend;
    config.cpu_class_ceiling = cell.cpu_class_ceiling;
    config.interfaces = &network_interface;
    config.interfaces_count = 1;
    ucall_server_init_t init {&server, &outcome, &config, &resolved};
    ucall_server_init(&init);
    require(failures, outcome.status == ucall_status_success_k && resolved.interfaces[0].event_loops == 2, "{}",
            ucall_status_name(outcome.status));
    batch_context_t batches;
    ucall_http_batch_endpoint_t endpoint {};
    ucall_server_add_http_batch_endpoint_t add {
        server,   &outcome, uc::bytes_view("/batch"), ucall_verb_post_k, batch_context_t::receive, &batches, 4, 4,
        10000000, &endpoint};
    ucall_server_add_http_batch_endpoint(&add);
    failures += expect(outcome.status == ucall_status_success_k);
    ucall_client_options_t client_config {};
    client_config.backend = cell.backend;
    client_config.cpu_class_ceiling = cell.cpu_class_ceiling;
    client_config.max_concurrent_connections = 4;
    ucall_client_init_t client_init {&client, &outcome, &client_config, nullptr};
    ucall_client_init(&client_init);
    failures += expect(outcome.status == ucall_status_success_k);
    auto poller = poll_batches(server, batches.failures, endpoint);
    // Each loop owns two of the four connections, so each receives exactly half of the batch.
    std::string url = fmt::format("http://{}/batch", uc::text_view(resolved.interfaces[0].address));
    for (std::size_t i = 0; i != 4; ++i) {
        ucall_client_call_t call {};
        call.client = client;
        call.outcome = &outcome;
        call.url = uc::bytes_view(url);
        call.verb = ucall_verb_post_k;
        call.body = uc::bytes_view("echo");
        ucall_client_call(&call);
        failures += expect(outcome.status == ucall_status_success_k);
    }
    std::array<ucall_completed_call_t, 4> completed {};
    std::size_t received {};
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
    auto progress = [&] {
        for (std::size_t loop = 0; loop != 2; ++loop) {
            ucall_server_take_call_t serving {server, &outcome, loop, 0};
            ucall_server_take_call(&serving);
            // A round after the cut may retire the loop.
            failures += expect(outcome.status == ucall_status_success_k ||
                               outcome.status == ucall_status_connection_closed_k);
        }
        std::size_t count {};
        ucall_client_take_completed_t take {client, &outcome, completed.data() + received, completed.size() - received,
                                            &count, 0};
        ucall_client_take_completed(&take);
        failures += expect(outcome.status == ucall_status_success_k);
        received += count;
        return steady_clock::now() <= deadline;
    };
    while (!batches.completed.load(std::memory_order_acquire) && progress()) {}
    failures += expect(batches.completed == 1 && batches.sizes[0] == 4, "{} batches, the first of {}",
                       batches.completed.load(), batches.sizes[0]);
    if (batches.completed == 1)
        for (auto request : batches.requests) {
            ucall_server_reply_content_t response {
                server, &outcome, request, ucall_http_status_ok_k, nullptr, 0, uc::bytes_view("echo")};
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
    // A second stop cuts, so the polling owner returns without the loop polled until it retires.
    ucall_server_stop(server);
    ucall_server_stop(server);
    progress();
    poller.join();
    ucall_client_free(client);
    ucall_server_free(server);
    return failures + batches.failures;
}

/** A loop whose first poll fails retires at once and keeps reporting the failure, so one stop
 *  still ends the batch polling once the other loop drained. */
static std::size_t test_setup_failure_ends_batch_polling(sweep_cell_t const&) {
#if UCALL_WITH_POSIX && !UCALL_OS_WINDOWS_
    using network_t = serial_network<uc::io::io_engine_variant<uc::io::posix_engine_t>>;
    std::size_t failures = 0;
    ucall_server_t server {};
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = uc::bytes_view("127.0.0.1:0");
    network_interface.max_concurrent_connections = 2;
    network_interface.event_loops = 2;
    ucall_server_options_t config {};
    config.interfaces = &network_interface;
    config.interfaces_count = 1;
    config.backend = ucall_io_backend_posix_k;
    ucall_server_init_t init {&server, &outcome, &config, nullptr};
    network_t::server_t::server_init(&init);
    require(failures, outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    batch_context_t batches;
    ucall_http_batch_endpoint_t endpoint {};
    ucall_server_add_http_batch_endpoint_t add {
        server, &outcome, uc::bytes_view("/batch"), ucall_verb_post_k, batch_context_t::receive, &batches, 1, 1,
        0,      &endpoint};
    ucall_server_add_http_batch_endpoint(&add);
    require(failures, outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    // Past the counters a first poll sizes, as on a host with far more connections per loop.
    static_cast<network_t::server_t*>(server)->event_loops[1]->max_exchanges =
        std::size_t {(std::numeric_limits<std::uint32_t>::max)() / 8} + 1;
    std::atomic<bool> returned {false};
    std::thread poller {[&] {
        ucall_outcome_t ended {};
        ucall_server_take_batches_t take {server, &ended, endpoint};
        ucall_server_take_batches(&take);
        returned.store(true, std::memory_order_release);
    }};
    auto poll = [&](std::size_t loop) {
        ucall_server_take_call_t serving {server, &outcome, loop, 1000};
        ucall_server_take_call(&serving);
        return outcome.status;
    };
    failures += expect(poll(0) == ucall_status_success_k, "loop 0 answered {}", ucall_status_name(outcome.status));
    for (std::size_t round = 0; round != 2; ++round)
        failures += expect(poll(1) == ucall_status_overflow_k, "loop 1 answered {} in round {}",
                           ucall_status_name(outcome.status), round);
    ucall_server_stop(server);
    steady_clock::time_point const deadline = steady_clock::now() + 2s;
    while (poll(0) == ucall_status_success_k && steady_clock::now() <= deadline) {}
    while (!returned.load(std::memory_order_acquire) && steady_clock::now() <= deadline)
        std::this_thread::sleep_for(1ms);
    failures += expect(returned.load(std::memory_order_acquire), "the batch polling owner outlived one stop by 2 s");
    // A cut ends a polling owner stuck behind the failed loop, so a failure never hangs the suite.
    ucall_server_stop(server);
    poller.join();
    ucall_server_free(server);
    return failures + batches.failures;
#else
    return report("test_setup_failure_ends_batch_polling", "needs the POSIX backend on a POSIX host");
#endif
}

/** Two batch endpoints, the first of whose callbacks blocks until the second's batch arrives. */
struct relay_t {
    std::array<std::atomic<ucall_received_http_request_t>, 2> requests {};
    std::atomic<std::size_t> failures {};

    static void first(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
        auto& relay = *static_cast<relay_t*>(context);
        relay.requests[0].store(requests[0], std::memory_order_release);
        steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
        while (!relay.requests[1].load(std::memory_order_acquire) && steady_clock::now() <= deadline)
            std::this_thread::yield();
        relay.failures += expect(count == 1 && relay.requests[1].load(std::memory_order_acquire),
                                 "the second endpoint's batch waited behind the first's callback");
    }
    static void second(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
        auto& relay = *static_cast<relay_t*>(context);
        relay.failures += expect(count == 1);
        relay.requests[1].store(requests[0], std::memory_order_release);
    }
};

static std::size_t test_batch_endpoints_poll_apart(sweep_cell_t const& cell) {
    polling_fixture_t fixture {cell};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    relay_t relay;
    using route_t = std::pair<char const*, ucall_received_http_batch_callback_t>;
    std::array routes {route_t {"/first", relay_t::first}, route_t {"/second", relay_t::second}};
    std::array<ucall_http_batch_endpoint_t, 2> endpoints {};
    for (std::size_t i = 0; i != routes.size(); ++i) {
        ucall_outcome_t outcome {};
        ucall_server_add_http_batch_endpoint_t add {fixture.server,
                                                    &outcome,
                                                    uc::bytes_view(routes[i].first),
                                                    ucall_verb_post_k,
                                                    routes[i].second,
                                                    &relay,
                                                    1,
                                                    1,
                                                    0,
                                                    &endpoints[i]};
        ucall_server_add_http_batch_endpoint(&add);
        require(failures, outcome.status == ucall_status_success_k && endpoints[i], "{}",
                ucall_status_name(outcome.status));
    }
    auto first_poller = poll_batches(fixture.server, relay.failures, endpoints[0]);
    auto second_poller = poll_batches(fixture.server, relay.failures, endpoints[1]);
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
    auto serve_until = [&](std::size_t endpoint) {
        while (!relay.requests[endpoint].load(std::memory_order_acquire) && steady_clock::now() <= deadline) {
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
    // A second stop cuts, so the polling owners return without the loops polled until they retire.
    ucall_server_stop(fixture.server);
    ucall_server_stop(fixture.server);
    ucall_outcome_t outcome {};
    ucall_server_take_call_t serving {fixture.server, &outcome, 0, 0};
    ucall_server_take_call(&serving);
    failures += expect(outcome.status == ucall_status_success_k || outcome.status == ucall_status_connection_closed_k,
                       "a cut round answered {}", ucall_status_name(outcome.status));
    first_poller.join();
    second_poller.join();
    return failures + fixture.failures + relay.failures;
}

static std::size_t test_batch_timeout_sleeps(sweep_cell_t const& cell) {
    batch_context_t batches;
    polling_fixture_t fixture {cell, batch_context_t::receive, &batches};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    ucall_outcome_t outcome {};
    ucall_server_take_batch_t missing {fixture.server, &outcome, nullptr, 0};
    ucall_server_take_batch(&missing);
    failures += expect(outcome.status == ucall_status_invalid_argument_k, "{}", ucall_status_name(outcome.status));
    // No event loop is ever polled, so only the polling owner's own wait can end the call.
    // The Windows `clock` counts wall time, so there the process's processor time is read.
    auto const processor_now = [] {
#if UCALL_OS_WINDOWS_
        FILETIME created, exited, kernel, user;
        GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user);
        auto const hundreds = [](FILETIME time) {
            return std::uint64_t {time.dwHighDateTime} << 32 | time.dwLowDateTime;
        };
        return static_cast<std::clock_t>((hundreds(kernel) + hundreds(user)) * CLOCKS_PER_SEC / 10'000'000);
#else
        return std::clock();
#endif
    };
    auto const started = std::chrono::steady_clock::now();
    auto const processor_started = processor_now();
    ucall_server_take_batch_t take {fixture.server, &outcome, fixture.batch_endpoint, 100000};
    ucall_server_take_batch(&take);
    auto const processor_spent = processor_now() - processor_started;
    auto const waited =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
    failures += expect(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    // A loaded host only lengthens the wait, so the lower bound alone is a property of the call.
    failures += expect(waited >= 100, "returned after {} ms", waited);
    failures += expect(processor_spent < CLOCKS_PER_SEC / 20, "spent {} processor ticks waiting",
                       static_cast<long long>(processor_spent));
    failures += expect(!batches.completed.load());
    ucall_batch_endpoint_statistics_t counted {};
    ucall_server_batch_endpoint_statistics_t query {fixture.server, &outcome, fixture.batch_endpoint, &counted};
    ucall_server_batch_endpoint_statistics(&query);
    failures += expect(counted.batches == 0 && counted.requests == 0, "{} batches fired while nothing was sent",
                       counted.batches);
    return failures + fixture.failures + batches.failures;
}

/** Four requests in one segment over one connection fill a batch of four, and their replies,
 *  given in reverse, leave in request order. */
static std::size_t test_pipelined_batches([[maybe_unused]] sweep_cell_t const& cell,
                                          [[maybe_unused]] random_generator_t& generator) {
#if UCALL_OS_POSIX_
    std::size_t failures = 0;
    ucall_server_t server {};
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = uc::bytes_view("127.0.0.1:0");
    network_interface.max_concurrent_connections = 1;
    network_interface.max_pipelined_requests = 4;
    ucall_server_options_t config {}, resolved {};
    config.backend = cell.backend;
    config.cpu_class_ceiling = cell.cpu_class_ceiling;
    config.interfaces = &network_interface;
    config.interfaces_count = 1;
    ucall_server_init_t init {&server, &outcome, &config, &resolved};
    ucall_server_init(&init);
    require(failures, outcome.status == ucall_status_success_k && resolved.interfaces[0].max_pipelined_requests == 4,
            "{}", ucall_status_name(outcome.status));
    batch_context_t batches;
    ucall_http_batch_endpoint_t endpoint {};
    ucall_server_add_http_batch_endpoint_t add {
        server,   &outcome, uc::bytes_view("/batch"), ucall_verb_post_k, batch_context_t::receive, &batches, 4, 4,
        10000000, &endpoint};
    ucall_server_add_http_batch_endpoint(&add);
    failures += expect(outcome.status == ucall_status_success_k);
    auto poller = poll_batches(server, batches.failures, endpoint);
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
    bool const written = client.connect(uc::text_view(resolved.interfaces[0].address)) &&
                         client.write(uc::byte_span(burst), burst.size(), generator,
                                      steady_clock::now() + wait_limit_k);
    failures += expect(written, "the burst was not written");
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
    while (written && !batches.completed.load(std::memory_order_acquire) && steady_clock::now() <= deadline)
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
            ucall_server_reply_content_t response {
                server, &outcome, batches.requests[i], ucall_http_status_ok_k, nullptr, 0, body};
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
    poller.join();
    ucall_server_free(server);
    return failures + batches.failures;
#else
    return report("test_pipelined_batches", "raw sockets need POSIX");
#endif
}

/** A request whose peer reset before its batch fired never reaches the application: the batch
 *  round ends it, so peers that deposit and leave cost the batch owner no work. */
static std::size_t test_batches_skip_abandoned([[maybe_unused]] sweep_cell_t const& cell,
                                               [[maybe_unused]] random_generator_t& generator) {
#if UCALL_OS_POSIX_
    std::size_t failures = 0;
    ucall_server_t server {};
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = uc::bytes_view("127.0.0.1:0");
    network_interface.max_concurrent_connections = 2;
    // A second request slot keeps a receive armed behind the deposited one, so the reset is seen.
    network_interface.max_pipelined_requests = 2;
    ucall_server_options_t config {}, resolved {};
    config.backend = cell.backend;
    config.cpu_class_ceiling = cell.cpu_class_ceiling;
    config.interfaces = &network_interface;
    config.interfaces_count = 1;
    ucall_server_init_t init {&server, &outcome, &config, &resolved};
    ucall_server_init(&init);
    require(failures, outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    batch_context_t batches;
    ucall_http_batch_endpoint_t endpoint {};
    ucall_server_add_http_batch_endpoint_t add {
        server, &outcome, uc::bytes_view("/batch"), ucall_verb_post_k, batch_context_t::receive, &batches, 2, 2,
        200000, &endpoint};
    ucall_server_add_http_batch_endpoint(&add);
    failures += expect(outcome.status == ucall_status_success_k);
    auto poller = poll_batches(server, batches.failures, endpoint);
    std::thread serving {[&] {
        ucall_outcome_t served {};
        ucall_server_take_calls_t take {server, &served, 0};
        ucall_server_take_calls(&take);
        batches.failures += expect(served.status == ucall_status_success_k);
    }};
    auto dispatched = [&] {
        ucall_event_loop_statistics_t counters {};
        ucall_server_event_loop_statistics_t query {server, &outcome, 0, &counters};
        ucall_server_event_loop_statistics(&query);
        return counters.requests;
    };
    std::string_view const request = "POST /batch HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\nx";
    raw_client_t leaving;
    bool const written = leaving.connect(uc::text_view(resolved.interfaces[0].address)) &&
                         leaving.write(uc::byte_span(request), request.size(), generator,
                                       steady_clock::now() + wait_limit_k);
    failures += expect(written, "the request was not written");
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
    while (written && !dispatched() && steady_clock::now() <= deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds {1});
    linger const reset {1, 0};
    failures += expect(setsockopt(leaving.descriptor, SOL_SOCKET, SO_LINGER, &reset, sizeof(reset)) == 0);
    leaving.close();
    // Twice the latency budget, past which the lone request would have fired a batch of one.
    std::this_thread::sleep_for(std::chrono::milliseconds {400});
    ucall_batch_endpoint_statistics_t counters {};
    ucall_server_batch_endpoint_statistics_t query {server, &outcome, endpoint, &counters};
    ucall_server_batch_endpoint_statistics(&query);
    failures += expect(!batches.completed.load(std::memory_order_acquire) && !counters.batches,
                       "{} batches fired for a request whose peer left", counters.batches);
    ucall_server_stop(server);
    serving.join();
    poller.join();
    ucall_server_free(server);
    return failures + batches.failures;
#else
    return report("test_batches_skip_abandoned", "raw sockets need POSIX");
#endif
}

#pragma endregion Batches

#pragma region Eviction
#if UCALL_OS_POSIX_

/** At its connection budget the server evicts the keep-alive connection idle longest for a waiting
 *  peer, closing it in order, but never one that holds a request; a peer finding only busy ones is
 *  never served past the budget. */
static std::size_t test_keepalive_eviction(sweep_cell_t const& cell, random_generator_t& generator) {
    fixture_t fixture {cell, {.connections = 2}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    std::string_view const echo = "GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n";
    std::string_view const gate = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
    auto send = [&](raw_client_t& client, std::string_view bytes) {
        failures += expect(client.write(uc::byte_span(bytes), 0, generator, steady_clock::now() + wait_limit_k));
    };
    {
        raw_client_t first, second, third;
        for (auto* client : {&first, &second}) {
            require(failures + fixture.stop(), client->connect(fixture.address));
            send(*client, echo);
            failures += expect(read_response(*client, 0).status == 200, "an admitted client was not served");
        }
        require(failures + fixture.stop(), third.connect(fixture.address));
        send(third, echo);
        auto const answered = third.read(1, steady_clock::now() + 1s);
        failures += expect(answered == read_end_t::filled_k && read_response(third, 0).status == 200,
                           "the waiting client ended as {}", static_cast<int>(answered));
        failures += expect(first.read_until_close(steady_clock::now() + 1s) == read_end_t::closed_k,
                           "the longest-idle client was not closed in order");
    }
    // The evicted and served peers must close first, so the next step starts with a free budget.
    std::this_thread::sleep_for(100ms);
    {
        raw_client_t first, second, third;
        for (auto* client : {&first, &second}) {
            require(failures + fixture.stop(), client->connect(fixture.address));
            send(*client, gate);
        }
        failures += await_held_in_background(fixture, 2);
        require(failures + fixture.stop(), third.connect(fixture.address));
        // A probe armed while a connection was idle may close this peer, so its write may fail.
        [[maybe_unused]] bool const written = third.write(uc::byte_span(echo), 0, generator, steady_clock::now() + 1s);
        failures += expect(third.read(1, steady_clock::now() + 300ms) != read_end_t::filled_k,
                           "a peer was served past a budget of busy connections");
        for (std::size_t held = 0; held != 2; ++held) {
            ucall_outcome_t outcome {};
            ucall_server_reply_content_t reply {fixture.server, &outcome, fixture.take_held(),   ucall_http_status_ok_k,
                                                nullptr,        0,        uc::bytes_view("held")};
            ucall_server_reply_content(&reply);
            failures += expect(outcome.status == ucall_status_success_k, "reply: {}",
                               ucall_status_name(outcome.status));
        }
        for (auto* client : {&first, &second})
            failures += expect(read_response(*client, 0).status == 200, "a held client lost its reply");
    }
    return failures + fixture.stop();
}

/** At its connection budget the server evicts a peer that sent a streamed head and stalled on its
 *  body ahead of a keep-alive connection idle since, so a dribbler cannot hold its slot. */
static std::size_t test_stalled_stream_eviction(sweep_cell_t const& cell, random_generator_t& generator) {
    fixture_t fixture {cell, {.connections = 2}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    std::string_view const stalled = "POST /stream HTTP/1.1\r\nHost: a\r\nContent-Length: 1000\r\n\r\n";
    std::string_view const echo = "GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n";
    auto send = [&](raw_client_t& client, std::string_view bytes) {
        failures += expect(client.write(uc::byte_span(bytes), 0, generator, steady_clock::now() + wait_limit_k));
    };
    raw_client_t dribbler, idle, waiting;
    require(failures + fixture.stop(), dribbler.connect(fixture.address));
    send(dribbler, stalled);
    failures += await_held_in_background(fixture, 1);
    require(failures + fixture.stop(), idle.connect(fixture.address));
    send(idle, echo);
    failures += expect(read_response(idle, 0).status == 200, "the idle client was not served");
    require(failures + fixture.stop(), waiting.connect(fixture.address));
    send(waiting, echo);
    read_end_t const answered = waiting.read(1, steady_clock::now() + 1s);
    failures += expect(answered == read_end_t::filled_k && read_response(waiting, 0).status == 200,
                       "the waiting client ended as {}", static_cast<int>(answered));
    failures += expect(dribbler.read_until_close(steady_clock::now() + 1s) == read_end_t::closed_k,
                       "the stalled stream was not evicted first");
    failures += expect(idle.read(idle.received.size() + 1, steady_clock::now() + 100ms) == read_end_t::timed_out_k,
                       "the idle client was evicted ahead of the stalled stream");
    ucall_outcome_t outcome {};
    ucall_server_reply_content_t reply {fixture.server, &outcome, fixture.take_held(),   ucall_http_status_ok_k,
                                        nullptr,        0,        uc::bytes_view("late")};
    ucall_server_reply_content(&reply);
    failures += expect(outcome.status == ucall_status_success_k || outcome.status == ucall_status_connection_closed_k,
                       "the evicted stream's reply answered {}", ucall_status_name(outcome.status));
    return failures + fixture.stop();
}

#endif // UCALL_OS_POSIX_
#pragma endregion Eviction

std::size_t check_serving(sweep_cell_t const& cell, settings_t const& settings) {
    random_generator_t generator {stream_key(settings.seed, name_of(cell))};
    std::size_t failures = 0;
    if (cell.security == ucall_security_none_k) {
        failures += test_progress_and_retention(cell);
        failures += test_completion_credits(cell);
        failures += test_timeout_and_cancel(cell);
        failures += test_take_call_reports_retired(cell);
        failures += test_application_batches(cell);
        failures += test_batches_across_loops(cell);
        failures += test_batch_endpoints_poll_apart(cell);
        failures += test_setup_failure_ends_batch_polling(cell);
        failures += test_batch_timeout_sleeps(cell);
        failures += test_pipelined_batches(cell, generator);
        failures += test_batches_skip_abandoned(cell, generator);
    }
#if UCALL_OS_POSIX_
    if (cell.security == ucall_security_none_k) {
        failures += test_keepalive_eviction(cell, generator);
        failures += test_stalled_stream_eviction(cell, generator);
    }
#endif
    return failures;
}

} // namespace unum::ucall::test::network
