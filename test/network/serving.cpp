/**
 *  @file test/network/serving.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Caller-driven progress, retained requests, completion credits, application batches, and
 *      the eviction of idle and stalled connections.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build

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

    void reply(ucall_received_http_request_t request) {
        ucall_outcome_t outcome {};
        ucall_bytes_view_t body {};
        ucall_server_request_body_t extract {server, &outcome, request, &body};
        ucall_server_request_body(&extract);
        expect_true(outcome.status == ucall_status_success_k);
        ucall_server_reply_content_t response {server, &outcome, &request, ucall_http_status_ok_k, nullptr, 0, body};
        ucall_server_reply_content(&response);
        expect_true(outcome.status == ucall_status_success_k);
    }
    static void echo(ucall_server_t, ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<polling_fixture_t*>(context);
        ++fixture.echoes;
        fixture.reply(request);
    }
    static void hold(ucall_server_t, ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<polling_fixture_t*>(context);
        expect_true(!fixture.held, "a second request arrived while one is held");
        fixture.held = request;
    }
    polling_fixture_t(sweep_cell_t const& cell, ucall_received_http_batch_callback_t batch_callback = nullptr,
                      void* batch_context = nullptr) {
        ucall_outcome_t outcome {};
        ucall_network_interface_t network_interface {};
        network_interface.address = bytes_view("127.0.0.1:0");
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
        address = fmt::format("http://{}", text_view(resolved.interfaces[0].address));
        using route_t = std::pair<char const*, ucall_received_http_request_callback_t>;
        for (auto [route, callback] : {route_t {"/echo", echo}, route_t {"/hold", hold}}) {
            ucall_server_add_http_endpoint_t add {server,   &outcome, bytes_view(route), ucall_verb_post_k,
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
                server, &outcome, bytes_view("/batch"), ucall_verb_post_k, batch_callback, batch_context, 2,
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
        expect_true(outcome.status == ucall_status_success_k);
    }
    std::size_t take(std::size_t client, ucall_completed_call_t* calls = nullptr, std::size_t capacity = 0) {
        ucall_outcome_t outcome {};
        std::size_t count {};
        ucall_client_take_completed_t take {clients[client], &outcome, calls, capacity, &count, 0};
        ucall_client_take_completed(&take);
        expect_true(outcome.status == ucall_status_success_k);
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
        call.url = bytes_view(url);
        call.verb = ucall_verb_post_k;
        call.body = bytes_view("echo");
        call.context = this;
        call.options.timeout_microseconds = timeout;
        ucall_client_call(&call);
    }

    /** Checks @p completed is this call's successful response, keeping it to free later. */
    bool success(ucall_completed_call_t const& completed) {
        response = completed.response;
        bool const succeeded = completed.context == this && completed.outcome.status == ucall_status_success_k &&
                               completed.response;
        return expect_true(succeeded, "{}", ucall_status_name(completed.outcome.status));
    }
    ~call_t() { ucall_client_response_free(response); }
};

#pragma region Progress

static void test_progress_and_retention(sweep_cell_t const& cell) {
    polling_fixture_t fixture {cell};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    call_t held, fast;
    held.submit(fixture, 0, "/hold");
    expect_true(held.outcome.status == ucall_status_success_k && !fixture.held);
    fixture.serve();
    expect_true(!fixture.held);
    if (!expect_true(fixture.await_held(0), "the held request never arrived")) return;
    fast.submit(fixture, 1);
    expect_true(fast.outcome.status == ucall_status_success_k);
    fast.success(fixture.wait(1));
    ucall_completed_call_t completed {};
    expect_true(!fixture.take(0, &completed, 1));
    fixture.reply(fixture.held);
    fixture.held = nullptr;
    held.success(fixture.wait(0));
}

static void test_completion_credits(sweep_cell_t const& cell) {
    polling_fixture_t fixture {cell};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    call_t first, second, refill;
    first.submit(fixture);
    second.submit(fixture);
    expect_true(first.outcome.status == ucall_status_success_k && second.outcome.status == ucall_status_success_k);
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
    while (fixture.echoes != 2) {
        fixture.serve();
        fixture.take(0);
        if (!expect_true(steady_clock::now() <= deadline, "{} of 2 echoes arrived", fixture.echoes)) return;
    }
    refill.submit(fixture);
    expect_true(refill.outcome.status == ucall_status_contended_k);
    first.success(fixture.wait(0));
    refill.submit(fixture);
    expect_true(refill.outcome.status == ucall_status_success_k);
    second.success(fixture.wait(0));
    refill.success(fixture.wait(0));
}

static void test_timeout_and_cancel(sweep_cell_t const& cell) {
    {
        polling_fixture_t fixture {cell};
        if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
            return;
        call_t timed;
        timed.submit(fixture, 0, "/hold", 100000);
        if (!expect_true(fixture.await_held(0), "the held request never arrived")) return;
        auto completed = fixture.wait(0);
        expect_true(completed.context == &timed && completed.outcome.status == ucall_status_timeout_k &&
                    !completed.response);
    }
    {
        polling_fixture_t fixture {cell};
        if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
            return;
        call_t held, queued;
        held.submit(fixture, 0, "/hold");
        if (!expect_true(fixture.await_held(0), "the held request never arrived")) return;
        queued.submit(fixture);
        expect_true(queued.outcome.status == ucall_status_success_k);
        ucall_client_free(fixture.clients[0]);
        fixture.clients[0] = nullptr;
        // The first stop drains, which still takes replies; the second refuses them.
        ucall_server_stop(fixture.server);
        ucall_server_stop(fixture.server);
        ucall_outcome_t outcome {};
        ucall_server_reply_content_t detached {fixture.server, &outcome, &fixture.held,       ucall_http_status_ok_k,
                                               nullptr,        0,        bytes_view("closed")};
        ucall_server_reply_content(&detached);
        expect_true(outcome.status == ucall_status_connection_closed_k);
        fixture.held = nullptr;
    }
}

/** Once a stopped loop retires, every later round reports @c ucall_status_connection_closed_k, so a
 *  caller polling in slices knows when to stop. */
static void test_take_call_reports_retired(sweep_cell_t const& cell) {
    polling_fixture_t fixture {cell};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve();
    ucall_server_stop(fixture.server);
    ucall_outcome_t outcome {};
    ucall_server_take_call_t serving {fixture.server, &outcome, 0, 1000};
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
    do ucall_server_take_call(&serving);
    while (outcome.status == ucall_status_success_k && steady_clock::now() <= deadline);
    expect_true(outcome.status == ucall_status_connection_closed_k, "the drained loop answered {}",
                ucall_status_name(outcome.status));
    ucall_server_take_call(&serving);
    expect_true(outcome.status == ucall_status_connection_closed_k, "a later round answered {}",
                ucall_status_name(outcome.status));
}

/** A caller polling a loop another thread polls finishes @c ucall_status_contended_k without
 *  running, while the owner keeps the loop until it retires. */
static void test_second_poller_is_refused(sweep_cell_t const& cell) {
    polling_fixture_t fixture {cell};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    std::thread owner {[&] {
        ucall_outcome_t owned {};
        ucall_server_take_calls_t take {fixture.server, &owned, 0};
        // The second poller may claim the loop first, between whose rounds the owner takes it.
        do ucall_server_take_calls(&take);
        while (owned.status == ucall_status_contended_k);
    }};
    ucall_outcome_t outcome {};
    ucall_server_take_call_t second {fixture.server, &outcome, 0, 0};
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
    do ucall_server_take_call(&second);
    while (outcome.status == ucall_status_success_k && steady_clock::now() <= deadline);
    expect_true(outcome.status == ucall_status_contended_k, "a second poller answered {}",
                ucall_status_name(outcome.status));
    ucall_server_stop(fixture.server);
    owner.join();
}

#pragma endregion Progress

#pragma region Batches

struct batch_context_t {
    polling_fixture_t* fixture {};
    std::array<ucall_received_http_request_t, 4> requests {};
    std::array<std::size_t, 2> sizes {};
    std::atomic<std::size_t> completed {};

    static void receive(ucall_server_t, ucall_received_http_request_t const* requests, std::size_t count,
                        void* context) {
        auto& state = *static_cast<batch_context_t*>(context);
        span<ucall_received_http_request_t const> const batch {requests, count};
        expect_true(!batch.empty() && batch.size() <= state.requests.size(), "a batch of {}", batch.size());
        if (batch.empty() || batch.size() > state.requests.size()) return;
        for (std::size_t i = 0; i != batch.size(); ++i) {
            expect_true(batch[i]);
            state.requests[i] = batch[i];
        }
        auto completed = state.completed.load(std::memory_order_relaxed);
        expect_true(completed < state.sizes.size(), "batch {} is one too many", completed);
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

static std::thread poll_batches(ucall_server_t server, ucall_http_batch_endpoint_t endpoint) {
    return std::thread {[server, endpoint] {
        ucall_outcome_t outcome {};
        ucall_server_take_batches_t take {server, &outcome, endpoint};
        ucall_server_take_batches(&take);
        expect_true(outcome.status == ucall_status_success_k);
    }};
}

static void test_application_batches(sweep_cell_t const& cell) {
    batch_context_t batches;
    polling_fixture_t fixture {cell, batch_context_t::receive, &batches};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    batches.fixture = &fixture;
    ucall_outcome_t outcome {};
    ucall_http_batch_endpoint_t prompt {};
    ucall_server_add_http_batch_endpoint_t add {fixture.server,
                                                &outcome,
                                                bytes_view("/prompt"),
                                                ucall_verb_post_k,
                                                batch_context_t::receive,
                                                &batches,
                                                2,
                                                2,
                                                300,
                                                &prompt};
    ucall_server_add_http_batch_endpoint(&add);
    if (!expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status))) return;
    auto batch_statistics = [&](ucall_http_batch_endpoint_t endpoint) {
        ucall_batch_endpoint_statistics_t counters {};
        ucall_server_batch_endpoint_statistics_t query {fixture.server, &outcome, endpoint, &counters};
        ucall_server_batch_endpoint_statistics(&query);
        return counters;
    };
    auto poller = poll_batches(fixture.server, fixture.batch_endpoint);
    auto prompt_poller = poll_batches(fixture.server, prompt);
    call_t first, second, partial;
    first.submit(fixture, 0, "/batch");
    second.submit(fixture, 1, "/batch");
    bool const fired = batches.wait(1);
    expect_true(fired, "the full batch never fired");
    if (fired) {
        expect_true(batches.sizes[0] == 2);
        auto const full = batch_statistics(fixture.batch_endpoint);
        expect_true(full.batches == 1 && full.requests == 2 && full.filled_batches == 1 && full.ready_batches == 0 &&
                        full.expired_batches == 0,
                    "a 2/2 batch counted {} batches, {} filled, {} ready, {} expired", full.batches,
                    full.filled_batches, full.ready_batches, full.expired_batches);
        fixture.reply(batches.requests[1]);
        fixture.reply(batches.requests[0]);
        first.success(fixture.wait(0));
        second.success(fixture.wait(1));
        steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
        partial.submit(fixture, 0, "/prompt");
        while (batches.completed.load(std::memory_order_acquire) != 2 && steady_clock::now() <= deadline) {
            fixture.take(0);
            fixture.serve();
        }
        bool const partial_fired = batches.completed.load(std::memory_order_acquire) == 2;
        expect_true(partial_fired, "the partial batch never fired");
        if (partial_fired) {
            expect_true(batches.sizes[1] == 1);
            auto const partial_counted = batch_statistics(prompt);
            // Its latency budget, not a stopwatch, fired it: expired below the minimum, not ready.
            expect_true(partial_counted.batches == 1 && partial_counted.requests == 1 &&
                            partial_counted.expired_batches == 1 && partial_counted.ready_batches == 0 &&
                            partial_counted.filled_batches == 0,
                        "a partial batch counted {} batches, {} expired, {} ready", partial_counted.batches,
                        partial_counted.expired_batches, partial_counted.ready_batches);
            fixture.reply(batches.requests[0]);
            partial.success(fixture.wait(0));
        }
    }
    // A second stop cuts, so the polling owners return without the loops polled until they retire.
    ucall_server_stop(fixture.server);
    ucall_server_stop(fixture.server);
    ucall_server_take_call_t serving {fixture.server, &outcome, 0, 0};
    ucall_server_take_call(&serving);
    expect_true(outcome.status == ucall_status_success_k || outcome.status == ucall_status_connection_closed_k,
                "a cut round answered {}", ucall_status_name(outcome.status));
    poller.join();
    prompt_poller.join();
}

static case_result_t test_batches_across_loops(sweep_cell_t const& cell) {
    if (UCALL_OS_WINDOWS_) return case_result_t::skipped(loops_refused_k);
    ucall_server_t server {};
    ucall_client_t client {};
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = bytes_view("127.0.0.1:0");
    network_interface.max_concurrent_connections = 8;
    network_interface.event_loops = 2;
    ucall_server_options_t config {}, resolved {};
    config.backend = cell.backend;
    config.cpu_class_ceiling = cell.cpu_class_ceiling;
    config.interfaces = &network_interface;
    config.interfaces_count = 1;
    ucall_server_init_t init {&server, &outcome, &config, &resolved};
    ucall_server_init(&init);
    if (!expect_true(outcome.status == ucall_status_success_k && resolved.interfaces[0].event_loops == 2, "{}",
                     ucall_status_name(outcome.status)))
        return {};
    batch_context_t batches;
    ucall_http_batch_endpoint_t endpoint {};
    ucall_server_add_http_batch_endpoint_t add {
        server,   &outcome, bytes_view("/batch"), ucall_verb_post_k, batch_context_t::receive, &batches, 4, 4,
        10000000, &endpoint};
    ucall_server_add_http_batch_endpoint(&add);
    expect_true(outcome.status == ucall_status_success_k);
    ucall_client_options_t client_config {};
    client_config.backend = cell.backend;
    client_config.cpu_class_ceiling = cell.cpu_class_ceiling;
    client_config.max_concurrent_connections = 4;
    ucall_client_init_t client_init {&client, &outcome, &client_config, nullptr};
    ucall_client_init(&client_init);
    expect_true(outcome.status == ucall_status_success_k);
    auto poller = poll_batches(server, endpoint);
    // Each loop's share of eight admits all four connections, however the kernel spreads them, so
    // every call reaches the one batch.
    std::string url = fmt::format("http://{}/batch", text_view(resolved.interfaces[0].address));
    for (std::size_t i = 0; i != 4; ++i) {
        ucall_client_call_t call {};
        call.client = client;
        call.outcome = &outcome;
        call.url = bytes_view(url);
        call.verb = ucall_verb_post_k;
        call.body = bytes_view("echo");
        ucall_client_call(&call);
        expect_true(outcome.status == ucall_status_success_k);
    }
    std::array<ucall_completed_call_t, 4> completed {};
    std::size_t received {};
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
    auto progress = [&] {
        for (std::size_t loop = 0; loop != 2; ++loop) {
            ucall_server_take_call_t serving {server, &outcome, loop, 0};
            ucall_server_take_call(&serving);
            // A round after the cut may retire the loop.
            expect_true(outcome.status == ucall_status_success_k || outcome.status == ucall_status_connection_closed_k);
        }
        std::size_t count {};
        ucall_client_take_completed_t take {client, &outcome, completed.data() + received, completed.size() - received,
                                            &count, 0};
        ucall_client_take_completed(&take);
        expect_true(outcome.status == ucall_status_success_k);
        received += count;
        return steady_clock::now() <= deadline;
    };
    while (!batches.completed.load(std::memory_order_acquire) && progress()) {}
    expect_true(batches.completed == 1 && batches.sizes[0] == 4, "{} batches, the first of {}",
                batches.completed.load(), batches.sizes[0]);
    // The one batch holds every loop's requests, whichever loops the kernel handed the connections.
    std::uint64_t dispatched = 0;
    for (std::size_t loop = 0; loop != 2; ++loop) {
        ucall_event_loop_statistics_t statistics {};
        ucall_server_event_loop_statistics_t query {server, &outcome, loop, &statistics};
        ucall_server_event_loop_statistics(&query);
        expect_true(outcome.status == ucall_status_success_k);
        dispatched += statistics.requests;
    }
    expect_true(dispatched == 4, "the loops dispatched {} of the batch's four requests", dispatched);
    if (batches.completed == 1)
        for (auto request : batches.requests) {
            ucall_server_reply_content_t response {server,  &outcome, &request,          ucall_http_status_ok_k,
                                                   nullptr, 0,        bytes_view("echo")};
            ucall_server_reply_content(&response);
            expect_true(outcome.status == ucall_status_success_k);
        }
    while (received != completed.size() && progress()) {}
    expect_true(received == completed.size(), "{} of {} calls completed", received, completed.size());
    for (std::size_t i = 0; i != received; ++i) {
        expect_true(completed[i].outcome.status == ucall_status_success_k);
        ucall_client_response_free(completed[i].response);
    }
    expect_true(batches.completed == 1);
    // A second stop cuts, so the polling owner returns without the loop polled until it retires.
    ucall_server_stop(server);
    ucall_server_stop(server);
    progress();
    poller.join();
    ucall_client_free(client);
    ucall_server_free(server);
    return {};
}

/** A loop whose first poll fails retires at once and keeps reporting the failure, so one stop
 *  still ends the batch polling once the other loop drained. */
static case_result_t test_setup_failure_ends_batch_polling(sweep_cell_t const&) {
#if UCALL_WITH_POSIX && !UCALL_OS_WINDOWS_
    using network_t = serial_network<uc::io::io_queue_variant<uc::io::posix_queue_t>>;
    ucall_server_t server {};
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = bytes_view("127.0.0.1:0");
    network_interface.max_concurrent_connections = 2;
    network_interface.event_loops = 2;
    ucall_server_options_t config {};
    config.interfaces = &network_interface;
    config.interfaces_count = 1;
    config.backend = ucall_io_backend_posix_k;
    ucall_server_init_t init {&server, &outcome, &config, nullptr};
    network_t::server_t::server_init(&init);
    if (!expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status))) return {};
    batch_context_t batches;
    ucall_http_batch_endpoint_t endpoint {};
    ucall_server_add_http_batch_endpoint_t add {
        server, &outcome, bytes_view("/batch"), ucall_verb_post_k, batch_context_t::receive, &batches, 1, 1,
        0,      &endpoint};
    ucall_server_add_http_batch_endpoint(&add);
    if (!expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status))) return {};
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
    expect_true(poll(0) == ucall_status_success_k, "loop 0 answered {}", ucall_status_name(outcome.status));
    for (std::size_t round = 0; round != 2; ++round)
        expect_true(poll(1) == ucall_status_overflow_k, "loop 1 answered {} in round {}",
                    ucall_status_name(outcome.status), round);
    ucall_server_stop(server);
    steady_clock::time_point const deadline = steady_clock::now() + 2s;
    while (poll(0) == ucall_status_success_k && steady_clock::now() <= deadline) {}
    while (!returned.load(std::memory_order_acquire) && steady_clock::now() <= deadline)
        std::this_thread::sleep_for(1ms);
    expect_true(returned.load(std::memory_order_acquire), "the batch polling owner outlived one stop by 2 s");
    // A cut ends a polling owner stuck behind the failed loop, so a failure never hangs the suite.
    ucall_server_stop(server);
    poller.join();
    ucall_server_free(server);
    return {};
#else
    return case_result_t::skipped("needs the POSIX backend on a POSIX host");
#endif
}

/** Two batch endpoints, the first of whose callbacks blocks until the second's batch arrives. */
struct relay_t {
    std::array<std::atomic<ucall_received_http_request_t>, 2> requests {};

    static void first(ucall_server_t, ucall_received_http_request_t const* requests, std::size_t count, void* context) {
        auto& relay = *static_cast<relay_t*>(context);
        relay.requests[0].store(requests[0], std::memory_order_release);
        steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
        while (!relay.requests[1].load(std::memory_order_acquire) && steady_clock::now() <= deadline)
            std::this_thread::yield();
        expect_true(count == 1 && relay.requests[1].load(std::memory_order_acquire),
                    "the second endpoint's batch waited behind the first's callback");
    }
    static void second(ucall_server_t, ucall_received_http_request_t const* requests, std::size_t count,
                       void* context) {
        auto& relay = *static_cast<relay_t*>(context);
        expect_true(count == 1);
        relay.requests[1].store(requests[0], std::memory_order_release);
    }
};

static void test_batch_endpoints_poll_apart(sweep_cell_t const& cell) {
    polling_fixture_t fixture {cell};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    relay_t relay;
    using route_t = std::pair<char const*, ucall_received_http_batch_callback_t>;
    std::array routes {route_t {"/first", relay_t::first}, route_t {"/second", relay_t::second}};
    std::array<ucall_http_batch_endpoint_t, 2> endpoints {};
    for (std::size_t i = 0; i != routes.size(); ++i) {
        ucall_outcome_t outcome {};
        ucall_server_add_http_batch_endpoint_t add {
            fixture.server, &outcome, bytes_view(routes[i].first), ucall_verb_post_k, routes[i].second, &relay, 1, 1, 0,
            &endpoints[i]};
        ucall_server_add_http_batch_endpoint(&add);
        if (!expect_true(outcome.status == ucall_status_success_k && endpoints[i], "{}",
                         ucall_status_name(outcome.status)))
            return;
    }
    auto first_poller = poll_batches(fixture.server, endpoints[0]);
    auto second_poller = poll_batches(fixture.server, endpoints[1]);
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
    expect_true(first_request, "the first batch never fired");
    second.submit(fixture, 1, "/second");
    auto second_request = serve_until(1);
    expect_true(second_request, "the second batch never fired");
    if (first_request && second_request) {
        fixture.reply(second_request);
        fixture.reply(first_request);
        first.success(fixture.wait(0));
        second.success(fixture.wait(1));
    }
    // A second stop cuts, so the polling owners return without the loops polled until they retire.
    ucall_server_stop(fixture.server);
    ucall_server_stop(fixture.server);
    ucall_outcome_t outcome {};
    ucall_server_take_call_t serving {fixture.server, &outcome, 0, 0};
    ucall_server_take_call(&serving);
    expect_true(outcome.status == ucall_status_success_k || outcome.status == ucall_status_connection_closed_k,
                "a cut round answered {}", ucall_status_name(outcome.status));
    first_poller.join();
    second_poller.join();
}

static void test_batch_timeout_sleeps(sweep_cell_t const& cell) {
    batch_context_t batches;
    polling_fixture_t fixture {cell, batch_context_t::receive, &batches};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    ucall_outcome_t outcome {};
    ucall_server_take_batch_t missing {fixture.server, &outcome, nullptr, 0};
    ucall_server_take_batch(&missing);
    expect_true(outcome.status == ucall_status_invalid_argument_k, "{}", ucall_status_name(outcome.status));
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
    expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    // A loaded host only lengthens the wait, so the lower bound alone is a property of the call.
    expect_true(waited >= 100, "returned after {} ms", waited);
    expect_true(processor_spent < CLOCKS_PER_SEC / 20, "spent {} processor ticks waiting",
                static_cast<long long>(processor_spent));
    expect_true(!batches.completed.load());
    ucall_batch_endpoint_statistics_t counted {};
    ucall_server_batch_endpoint_statistics_t query {fixture.server, &outcome, fixture.batch_endpoint, &counted};
    ucall_server_batch_endpoint_statistics(&query);
    expect_true(counted.batches == 0 && counted.requests == 0, "{} batches fired while nothing was sent",
                counted.batches);
}

/** Four requests in one segment over one connection fill a batch of four, and their replies,
 *  given in reverse, leave in request order. */
static case_result_t test_pipelined_batches([[maybe_unused]] sweep_cell_t const& cell) {
#if UCALL_OS_POSIX_
    split_mix_generator_t generator {case_stream_key()};
    ucall_server_t server {};
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = bytes_view("127.0.0.1:0");
    network_interface.max_concurrent_connections = 1;
    network_interface.max_pipelined_requests = 4;
    ucall_server_options_t config {}, resolved {};
    config.backend = cell.backend;
    config.cpu_class_ceiling = cell.cpu_class_ceiling;
    config.interfaces = &network_interface;
    config.interfaces_count = 1;
    ucall_server_init_t init {&server, &outcome, &config, &resolved};
    ucall_server_init(&init);
    if (!expect_true(outcome.status == ucall_status_success_k && resolved.interfaces[0].max_pipelined_requests == 4,
                     "{}", ucall_status_name(outcome.status)))
        return {};
    batch_context_t batches;
    ucall_http_batch_endpoint_t endpoint {};
    ucall_server_add_http_batch_endpoint_t add {
        server,   &outcome, bytes_view("/batch"), ucall_verb_post_k, batch_context_t::receive, &batches, 4, 4,
        10000000, &endpoint};
    ucall_server_add_http_batch_endpoint(&add);
    expect_true(outcome.status == ucall_status_success_k);
    auto poller = poll_batches(server, endpoint);
    std::thread serving {[&] {
        ucall_outcome_t served {};
        ucall_server_take_calls_t take {server, &served, 0};
        ucall_server_take_calls(&take);
        expect_true(served.status == ucall_status_success_k);
    }};
    std::string burst;
    for (std::size_t i = 0; i != 4; ++i)
        burst += fmt::format("POST /batch HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\n{}", i);
    raw_client_t client;
    bool const written = client.connect(text_view(resolved.interfaces[0].address)) &&
                         client.write(byte_span(burst), burst.size(), generator, steady_clock::now() + wait_limit_k);
    expect_true(written, "the burst was not written");
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
    while (written && !batches.completed.load(std::memory_order_acquire) && steady_clock::now() <= deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds {1});
    bool const fired = batches.completed.load(std::memory_order_acquire) == 1 && batches.sizes[0] == 4;
    expect_true(fired, "{} batches, the first of {}", batches.completed.load(), batches.sizes[0]);
    if (fired) {
        for (std::size_t i = 4; i--;) {
            ucall_bytes_view_t body {};
            ucall_server_request_body_t extract {server, &outcome, batches.requests[i], &body};
            ucall_server_request_body(&extract);
            expect_true(outcome.status == ucall_status_success_k && body.length == 1 && body.data[0] == '0' + i,
                        "request {} of the batch", i);
            ucall_server_reply_content_t response {
                server, &outcome, &batches.requests[i], ucall_http_status_ok_k, nullptr, 0, body};
            ucall_server_reply_content(&response);
            expect_true(outcome.status == ucall_status_success_k);
        }
        std::size_t offset = 0;
        for (std::size_t i = 0; i != 4; ++i) {
            auto const response = read_response(client, offset);
            expect_true(response.status == 200 && response.body == fmt::format("{}", i), "response {}: {} {}", i,
                        response.status, response.body);
            if (!response.length) break;
            offset += response.length;
        }
    }
    ucall_server_stop(server);
    serving.join();
    poller.join();
    ucall_server_free(server);
    return {};
#else
    return case_result_t::skipped(needs_posix_sockets_k);
#endif
}

/** Answers each request of a batch at once, and holds the first batch until released, so the round
 *  that fired it runs on while the loop takes the request its reply let the peer send. */
struct held_batch_t {
    ucall_server_t server {};
    std::atomic<std::size_t> fired {};
    std::atomic<bool> released {};

    static void receive(ucall_server_t server, ucall_received_http_request_t const* requests, std::size_t count,
                        void* context) {
        auto& state = *static_cast<held_batch_t*>(context);
        for (std::size_t i = 0; i != count; ++i) {
            ucall_outcome_t outcome {};
            ucall_received_http_request_t request = requests[i];
            ucall_server_reply_content_t reply {server,  &outcome, &request,         ucall_http_status_ok_k,
                                                nullptr, 0,        bytes_view("ok")};
            ucall_server_reply_content(&reply);
            expect_true(outcome.status == ucall_status_success_k, "a reply ended with {}",
                        ucall_status_name(outcome.status));
        }
        if (state.fired.fetch_add(1, std::memory_order_acq_rel)) return;
        expect_true(spin_until([&] { return state.released.load(std::memory_order_acquire); }),
                    "the first batch was never released");
    }
};

/** A batch frees the queue slots it took before it fires, so the request its reply lets the peer
 *  send finds room while the round that fired it still runs. One connection pipelining two
 *  requests fills a queue of exactly two, and batches of one fire the first while the second
 *  waits, so a slot freed only once the round ended would refuse the third request with 503. */
static case_result_t test_batch_slots_free_before_firing([[maybe_unused]] sweep_cell_t const& cell) {
#if UCALL_OS_POSIX_
    held_batch_t batches;
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = bytes_view("127.0.0.1:0");
    network_interface.max_concurrent_connections = 1;
    network_interface.max_pipelined_requests = 2;
    ucall_server_options_t config {}, resolved {};
    config.backend = cell.backend;
    config.cpu_class_ceiling = cell.cpu_class_ceiling;
    config.interfaces = &network_interface;
    config.interfaces_count = 1;
    ucall_server_init_t init {&batches.server, &outcome, &config, &resolved};
    ucall_server_init(&init);
    if (!expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status))) return {};
    ucall_http_batch_endpoint_t endpoint {};
    ucall_server_add_http_batch_endpoint_t add {
        batches.server, &outcome, bytes_view("/batch"), ucall_verb_post_k, held_batch_t::receive, &batches, 1, 1,
        10000000,       &endpoint};
    ucall_server_add_http_batch_endpoint(&add);
    expect_true(outcome.status == ucall_status_success_k);
    auto poller = poll_batches(batches.server, endpoint);
    // The test polls the loop itself, so each request's dispatch is over once a round returns.
    auto const round = [&] {
        ucall_outcome_t served {};
        ucall_server_take_call_t take {batches.server, &served, 0, 1000};
        ucall_server_take_call(&take);
        expect_true(served.status == ucall_status_success_k, "a round ended with {}", ucall_status_name(served.status));
    };
    auto const dispatched = [&] {
        ucall_outcome_t queried {};
        ucall_event_loop_statistics_t counters {};
        ucall_server_event_loop_statistics_t query {batches.server, &queried, 0, &counters};
        ucall_server_event_loop_statistics(&query);
        return counters.requests;
    };
    std::string_view const request = "POST /batch HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\nx";
    raw_client_t client;
    bool const connected = client.connect(text_view(resolved.interfaces[0].address));
    expect_true(connected && ::send(client.descriptor, request.data(), request.size(), 0) ==
                                 static_cast<ssize_t>(request.size()) &&
                    ::send(client.descriptor, request.data(), request.size(), 0) == static_cast<ssize_t>(request.size()),
                "the two pipelined requests were not written");
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
    std::size_t offset = 0;
    wire_response_t first {};
    while (connected && !(first = parse_response(client.received)).length && steady_clock::now() <= deadline) {
        round();
        [[maybe_unused]] read_end_t const read = client.read(client.received.size() + 1,
                                                             steady_clock::now() + std::chrono::milliseconds {1});
    }
    expect_true(first.status == 200 && batches.fired.load() == 1, "the first request answered {} after {} batches",
                first.status, batches.fired.load());
    offset += first.length;
    expect_true(::send(client.descriptor, request.data(), request.size(), 0) == static_cast<ssize_t>(request.size()),
                "the third request was not written");
    while (dispatched() != 3 && steady_clock::now() <= deadline) round();
    expect_true(dispatched() == 3, "the loop dispatched {} of 3 requests", dispatched());
    batches.released.store(true, std::memory_order_release);
    for (std::size_t i = 1; i != 3; ++i) {
        wire_response_t response {};
        while (!(response = parse_response(std::string_view {client.received}.substr(offset))).length &&
               steady_clock::now() <= deadline) {
            round();
            [[maybe_unused]] read_end_t const read = client.read(client.received.size() + 1,
                                                                 steady_clock::now() + std::chrono::milliseconds {1});
        }
        expect_true(response.status == 200, "request {} answered {} with {}", i + 1, response.status, response.body);
        offset += response.length;
    }
    ucall_server_stop(batches.server);
    // The loop retires on a later round, which ends the batch polling.
    for (ucall_outcome_t served {}; served.status == ucall_status_success_k && steady_clock::now() <= deadline;) {
        ucall_server_take_call_t take {batches.server, &served, 0, 1000};
        ucall_server_take_call(&take);
    }
    poller.join();
    ucall_server_free(batches.server);
    return {};
#else
    return case_result_t::skipped(needs_posix_sockets_k);
#endif
}

/** A request whose peer reset before its batch fired never reaches the application: the batch
 *  round ends it, so peers that deposit and leave cost the batch owner no work. */
static case_result_t test_batches_skip_abandoned([[maybe_unused]] sweep_cell_t const& cell) {
#if UCALL_OS_POSIX_
    split_mix_generator_t generator {case_stream_key()};
    ucall_server_t server {};
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = bytes_view("127.0.0.1:0");
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
    if (!expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status))) return {};
    batch_context_t batches;
    ucall_http_batch_endpoint_t endpoint {};
    ucall_server_add_http_batch_endpoint_t add {
        server, &outcome, bytes_view("/batch"), ucall_verb_post_k, batch_context_t::receive, &batches, 2, 2,
        200000, &endpoint};
    ucall_server_add_http_batch_endpoint(&add);
    expect_true(outcome.status == ucall_status_success_k);
    auto poller = poll_batches(server, endpoint);
    std::thread serving {[&] {
        ucall_outcome_t served {};
        ucall_server_take_calls_t take {server, &served, 0};
        ucall_server_take_calls(&take);
        expect_true(served.status == ucall_status_success_k);
    }};
    auto dispatched = [&] {
        ucall_event_loop_statistics_t counters {};
        ucall_server_event_loop_statistics_t query {server, &outcome, 0, &counters};
        ucall_server_event_loop_statistics(&query);
        return counters.requests;
    };
    std::string_view const request = "POST /batch HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\n\r\nx";
    raw_client_t leaving;
    bool const written = leaving.connect(text_view(resolved.interfaces[0].address)) &&
                         leaving.write(byte_span(request), request.size(), generator,
                                       steady_clock::now() + wait_limit_k);
    expect_true(written, "the request was not written");
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
    while (written && !dispatched() && steady_clock::now() <= deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds {1});
    linger const reset {1, 0};
    expect_true(setsockopt(leaving.descriptor, SOL_SOCKET, SO_LINGER, &reset, sizeof(reset)) == 0);
    leaving.close();
    // Twice the latency budget, past which the lone request would have fired a batch of one.
    std::this_thread::sleep_for(std::chrono::milliseconds {400});
    ucall_batch_endpoint_statistics_t counters {};
    ucall_server_batch_endpoint_statistics_t query {server, &outcome, endpoint, &counters};
    ucall_server_batch_endpoint_statistics(&query);
    expect_true(!batches.completed.load(std::memory_order_acquire) && !counters.batches,
                "{} batches fired for a request whose peer left", counters.batches);
    ucall_server_stop(server);
    serving.join();
    poller.join();
    ucall_server_free(server);
    return {};
#else
    return case_result_t::skipped(needs_posix_sockets_k);
#endif
}

#pragma endregion Batches

#pragma region Eviction
#if UCALL_OS_POSIX_

/** At its connection budget the server evicts the keep-alive connection idle longest for a waiting
 *  peer, closing it in order, but never one that holds a request; a peer finding only busy ones is
 *  never served past the budget. */
static void test_keepalive_eviction(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {.connections = 2}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    std::string_view const echo = "GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n";
    std::string_view const gate = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
    auto send = [&](raw_client_t& client, std::string_view bytes) {
        expect_true(client.write(byte_span(bytes), 0, generator, steady_clock::now() + wait_limit_k));
    };
    {
        raw_client_t first, second, third;
        for (auto* client : {&first, &second}) {
            if (!expect_true(client->connect(fixture.address))) return;
            send(*client, echo);
            expect_true(read_response(*client, 0).status == 200, "an admitted client was not served");
        }
        if (!expect_true(third.connect(fixture.address))) return;
        send(third, echo);
        auto const answered = third.read(1, steady_clock::now() + 1s);
        expect_true(answered == read_end_t::filled_k && read_response(third, 0).status == 200,
                    "the waiting client ended as {}", static_cast<int>(answered));
        expect_true(first.read_until_close(steady_clock::now() + 1s) == read_end_t::closed_k,
                    "the longest-idle client was not closed in order");
    }
    // The evicted and served peers must close first, so the next step starts with a free budget.
    std::this_thread::sleep_for(100ms);
    {
        raw_client_t first, second, third;
        for (auto* client : {&first, &second}) {
            if (!expect_true(client->connect(fixture.address))) return;
            send(*client, gate);
        }
        await_held_in_background(fixture, 2);
        if (!expect_true(third.connect(fixture.address))) return;
        // A probe armed while a connection was idle may close this peer, so its write may fail.
        [[maybe_unused]] bool const written = third.write(byte_span(echo), 0, generator, steady_clock::now() + 1s);
        expect_true(third.read(1, steady_clock::now() + 300ms) != read_end_t::filled_k,
                    "a peer was served past a budget of busy connections");
        for (std::size_t held = 0; held != 2; ++held) {
            ucall_outcome_t outcome {};
            ucall_received_http_request_t taken = fixture.take_held();
            ucall_server_reply_content_t reply {fixture.server,    &outcome, &taken, ucall_http_status_ok_k, nullptr, 0,
                                                bytes_view("held")};
            ucall_server_reply_content(&reply);
            expect_true(outcome.status == ucall_status_success_k, "reply: {}", ucall_status_name(outcome.status));
        }
        for (auto* client : {&first, &second})
            expect_true(read_response(*client, 0).status == 200, "a held client lost its reply");
    }
    fixture.stop();
}

/** At its connection budget the server evicts a peer that sent a streamed head and stalled on its
 *  body ahead of a keep-alive connection idle since, so a dribbler cannot hold its slot. */
static void test_stalled_stream_eviction(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {.connections = 2}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    std::string_view const stalled = "POST /stream HTTP/1.1\r\nHost: a\r\nContent-Length: 1000\r\n\r\n";
    std::string_view const echo = "GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n";
    auto send = [&](raw_client_t& client, std::string_view bytes) {
        expect_true(client.write(byte_span(bytes), 0, generator, steady_clock::now() + wait_limit_k));
    };
    raw_client_t dribbler, idle, waiting;
    if (!expect_true(dribbler.connect(fixture.address))) return;
    send(dribbler, stalled);
    await_held_in_background(fixture, 1);
    if (!expect_true(idle.connect(fixture.address))) return;
    send(idle, echo);
    expect_true(read_response(idle, 0).status == 200, "the idle client was not served");
    if (!expect_true(waiting.connect(fixture.address))) return;
    send(waiting, echo);
    read_end_t const answered = waiting.read(1, steady_clock::now() + 1s);
    expect_true(answered == read_end_t::filled_k && read_response(waiting, 0).status == 200,
                "the waiting client ended as {}", static_cast<int>(answered));
    expect_true(dribbler.read_until_close(steady_clock::now() + 1s) == read_end_t::closed_k,
                "the stalled stream was not evicted first");
    expect_true(idle.read(idle.received.size() + 1, steady_clock::now() + 100ms) == read_end_t::timed_out_k,
                "the idle client was evicted ahead of the stalled stream");
    ucall_outcome_t outcome {};
    ucall_received_http_request_t taken = fixture.take_held();
    ucall_server_reply_content_t reply {fixture.server,    &outcome, &taken, ucall_http_status_ok_k, nullptr, 0,
                                        bytes_view("late")};
    ucall_server_reply_content(&reply);
    expect_true(outcome.status == ucall_status_success_k || outcome.status == ucall_status_connection_closed_k,
                "the evicted stream's reply answered {}", ucall_status_name(outcome.status));
    fixture.stop();
}

#endif // UCALL_OS_POSIX_
#pragma endregion Eviction

void test_serving_cell(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    if (cell.security == ucall_security_none_k) {
        test_progress_and_retention(cell);
        test_completion_credits(cell);
        test_timeout_and_cancel(cell);
        test_take_call_reports_retired(cell);
        test_second_poller_is_refused(cell);
        test_application_batches(cell);
        test_batch_endpoints_poll_apart(cell);
        test_batch_timeout_sleeps(cell);
    }
#if UCALL_OS_POSIX_
    if (cell.security == ucall_security_none_k) {
        test_keepalive_eviction(cell, generator);
        test_stalled_stream_eviction(cell, generator);
    }
#endif
}

void run_serving_cases(sweep_cell_t const& cell, sz::string_t const& cell_label) {
    if (cell.security == ucall_security_none_k) {
        run_cell_case(cell_label, "test_batches_across_loops", test_batches_across_loops, cell);
        run_cell_case(cell_label, "test_setup_failure_ends_batch_polling", test_setup_failure_ends_batch_polling, cell);
        run_cell_case(cell_label, "test_pipelined_batches", test_pipelined_batches, cell);
        run_cell_case(cell_label, "test_batch_slots_free_before_firing", test_batch_slots_free_before_firing, cell);
        run_cell_case(cell_label, "test_batches_skip_abandoned", test_batches_skip_abandoned, cell);
    }
}

} // namespace unum::ucall::test::network
