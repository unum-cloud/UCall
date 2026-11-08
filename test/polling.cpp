/**
 *  @file test/polling.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Caller-driven progress, retained requests, completion credits, and application batching.
 */
#include <cstring> // `std::memcmp`
#include <ctime>   // `std::clock`

#include <array>       // `std::array`
#include <atomic>      // `std::atomic`
#include <chrono>      // `std::chrono::steady_clock`
#include <limits>      // `std::numeric_limits`
#include <string>      // `std::string`
#include <string_view> // `std::string_view`
#include <thread>      // `std::thread`
#include <utility>     // `std::pair`

#include "ucall/ucall.h"
#include "ucall/io/bsd_kqueue_engine.hpp"     // `bsd_kqueue_engine_t`
#include "ucall/io/linux_epollaio_engine.hpp" // `linux_epollaio_engine_t`
#include "ucall/io/posix_engine.hpp"          // `posix_engine_t`
#include "ucall/network.hpp"                  // `serial_network`
#include "ucall/utilities/sockets.hpp"        // `file_direct_alignment`, `io_vector_t`, `monotonic_ns`, `nonblocking`
#include "ucall/utilities/types.hpp"          // `byte_t`, `bytes_view`, `text_view`

#include "harness.hpp" // `expect`, `require`, `run_test`, `direct_directory_t`, `aligned_bytes_t`

#if UCALL_OS_POSIX_
#include <fcntl.h>        // `open`, `O_DIRECT`
#include <sys/resource.h> // `getrlimit`, `setrlimit`, `RLIMIT_MEMLOCK`
#include <sys/stat.h>     // `mkfifo`, `mkdir`
#endif

namespace uc = unum::ucall;
using namespace unum::ucall::test;
using namespace std::chrono_literals;
using std::chrono::steady_clock;

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
        ucall_server_reply_content_t response {server, &outcome, request, ucall_http_status_ok_k, nullptr, 0, body};
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
        network_interface.address = uc::bytes_view("127.0.0.1:0");
        network_interface.max_concurrent_connections = 2;
        ucall_server_options_t config {};
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
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
        steady_clock::time_point const deadline = steady_clock::now() + 5s;
        ucall_completed_call_t completed {};
        do {
            serve();
            if (take(client, &completed, 1)) return completed;
        } while (steady_clock::now() <= deadline);
        completed.outcome.status = ucall_status_timeout_k;
        return completed;
    }

    /** Polls until `/hold` retains a request, answering whether one came within five seconds. */
    [[nodiscard]] bool await_held(std::size_t client) {
        steady_clock::time_point const deadline = steady_clock::now() + 5s;
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

    void submit(fixture_t& fixture, std::size_t client = 0, char const* path = "/echo", std::size_t timeout = 0) {
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
    steady_clock::time_point const deadline = steady_clock::now() + 5s;
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
static case_result_t test_take_call_reports_retired() {
    fixture_t fixture;
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    fixture.serve();
    ucall_server_stop(fixture.server);
    ucall_outcome_t outcome {};
    ucall_server_take_call_t serving {fixture.server, &outcome, 0, 1000};
    steady_clock::time_point const deadline = steady_clock::now() + 5s;
    do ucall_server_take_call(&serving);
    while (outcome.status == ucall_status_success_k && steady_clock::now() <= deadline);
    failures += expect(outcome.status == ucall_status_connection_closed_k, "the drained loop answered {}",
                       ucall_status_name(outcome.status));
    ucall_server_take_call(&serving);
    failures += expect(outcome.status == ucall_status_connection_closed_k, "a later round answered {}",
                       ucall_status_name(outcome.status));
    return failures + fixture.failures;
}

/** Under a locked-memory limit just short of a one-connection ring's, an automatic server lands on
 *  epollaio at init instead of refusing its first poll. */
static case_result_t test_ring_refused_at_init_falls_back() {
#if UCALL_WITH_LINUX_URING && UCALL_WITH_LINUX_EPOLLAIO
    // The backend an automatic server of `connections` picked and its first poll's status.
    auto serve_once = [](std::size_t connections) {
        std::pair<ucall_io_backend_t, ucall_status_t> result {ucall_io_backend_automatic_k, ucall_status_success_k};
        ucall_server_t server {};
        ucall_outcome_t outcome {};
        ucall_network_interface_t network_interface {};
        network_interface.address = uc::bytes_view("127.0.0.1:0");
        network_interface.max_concurrent_connections = connections;
        ucall_server_options_t config {}, resolved {};
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
        ucall_server_init_t init {&server, &outcome, &config, &resolved};
        ucall_server_init(&init);
        result.second = outcome.status;
        if (outcome.status != ucall_status_success_k) return result;
        result.first = resolved.backend;
        ucall_server_take_call_t serving {server, &outcome, 0, 0};
        ucall_server_take_call(&serving);
        result.second = outcome.status;
        ucall_server_free(server);
        return result;
    };
    auto const on_ring = [](ucall_io_backend_t backend) {
        return backend == ucall_io_backend_linux_uring618_k || backend == ucall_io_backend_linux_uring612_k;
    };
    rlimit original {};
    if (::getrlimit(RLIMIT_MEMLOCK, &original) != 0) return case_result_t::skipped("the limit cannot be read");
    rlim_t low = 0, high = original.rlim_cur == RLIM_INFINITY ? rlim_t {64} << 20 : original.rlim_cur;
    if (!on_ring(serve_once(1).first)) return case_result_t::skipped("no io_uring backend serves here");
    rlimit const none {0, original.rlim_max};
    if (::setrlimit(RLIMIT_MEMLOCK, &none) == 0 && on_ring(serve_once(1).first)) {
        [[maybe_unused]] int const restored = ::setrlimit(RLIMIT_MEMLOCK, &original);
        return case_result_t::skipped("this kernel bills no ring to the locked-memory limit");
    }
    // Bisects the least limit at which a one-connection ring serves; just under it, no ring opens.
    while (high - low > 16 * 1024) {
        rlim_t const middle = low + (high - low) / 2;
        rlimit lowered {middle, original.rlim_max};
        if (::setrlimit(RLIMIT_MEMLOCK, &lowered) != 0) break;
        auto const [backend, status] = serve_once(1);
        (on_ring(backend) && status == ucall_status_success_k ? high : low) = middle;
    }
    rlimit lowered {low, original.rlim_max};
    std::size_t failures = 0;
    failures += expect(::setrlimit(RLIMIT_MEMLOCK, &lowered) == 0, "the locked-memory limit stayed");
    auto const [backend, status] = serve_once(4096);
    failures += expect(::setrlimit(RLIMIT_MEMLOCK, &original) == 0, "the locked-memory limit stayed lowered");
    failures += expect(status == ucall_status_success_k && backend == ucall_io_backend_linux_epollaio_k,
                       "under {} KiB a large loop picked {} and polled {}", low / 1024, int(backend),
                       ucall_status_name(status));
    return failures;
#else
    return case_result_t::skipped("io_uring or epollaio is not compiled");
#endif
}

static case_result_t test_cpu_class_ceiling_unit() {
    std::size_t failures = 0;
    bool refused = false;
    for (auto cpu_class = ucall_cpu_class_serial_k; cpu_class <= ucall_cpu_class_aws_g5_k;
         cpu_class = static_cast<ucall_cpu_class_t>(cpu_class + 1)) {
        ucall_client_t handle {};
        ucall_outcome_t outcome {};
        ucall_client_options_t config {};
        config.cpu_class = cpu_class;
        config.max_concurrent_connections = 1;
        ucall_client_init_t init {&handle, &outcome, &config, nullptr};
        ucall_client_init(&init);
        // No CPU runs both the x86 and the Arm classes, so a pin past what this one runs must fail.
        refused |= outcome.status == ucall_status_unsupported_k && !handle;
        failures += expect(outcome.status == ucall_status_success_k || outcome.status == ucall_status_unsupported_k);
        failures += expect(cpu_class != ucall_cpu_class_serial_k || outcome.status == ucall_status_success_k);
        ucall_client_free(handle);
    }
    failures += expect(refused);
    return failures;
}

static case_result_t test_origin_reuse_and_fairness_unit() {
#if UCALL_WITH_POSIX
    using network_t = uc::network::serial_network<uc::io::posix_engine_t>;
    std::size_t failures = 0;
    ucall_client_t handle {};
    ucall_outcome_t outcome {};
    ucall_client_options_t config {};
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
        call.url = uc::bytes_view(url);
        call.verb = ucall_verb_get_k;
        ucall_client_call(&call);
        failures += expect(outcome.status == ucall_status_success_k);
    }
    std::array<uc::descriptor_t, 3> descriptors {};
    for (std::size_t i = 0; i != client.connections.size(); ++i) {
        auto& connection = *client.connections[i];
        connection.origin = client.exchanges[i == 1 ? 2 : 0].origin;
        ++connection.origin->connections;
        failures += expect(connection.transport.configure({}, &connection) == ucall_status_success_k);
        descriptors[i] = connection.transport.descriptor = client.engine->open_socket(AF_INET);
        failures += expect(descriptors[i] >= 0);
        connection.transport.stage = network_t::transport_stage_t::open_k;
        network_t::client_t::mark_ready(client, connection);
    }
    auto& origin = *client.exchanges[0].origin;
    failures += expect(client.exchanges[1].origin == &origin && client.exchanges[3].origin == &origin &&
                       client.exchanges[2].origin != &origin && origin.waiting == 3);
    auto& busy = *client.connections[2];
    busy.oldest_exchange = busy.newest_exchange = &network_t::client_t::unqueue_call(origin);
    busy.outstanding_exchanges = 1;
    busy.transport.transmitting = network_t::transmit_state_t::sending_k;
    busy.transport.transmit_operation = network_t::operation_state_t::submitted_k;
    client.exchanges[0].stage = uc::network::client_exchange_stage_t::pipelined_k;
    network_t::client_t::client_progress(client);
    // Each idle connection takes its origin's waiting call due first, leaving the rest in order.
    failures += expect(client.connections[0]->oldest_exchange == &client.exchanges[1]);
    failures += expect(client.connections[1]->oldest_exchange == &client.exchanges[2]);
    failures += expect(client.exchanges[3].stage == uc::network::client_exchange_stage_t::waiting_k &&
                       origin.waiting_head == &client.exchanges[3] && origin.waiting_tail == &client.exchanges[3]);
    for (std::size_t i = 0; i != descriptors.size(); ++i)
        failures += expect(client.connections[i]->transport.descriptor == descriptors[i]);
    client.engine->stop();
    auto& released = *client.connections[1];
    released.oldest_exchange = released.newest_exchange = nullptr;
    released.outstanding_exchanges = 0;
    released.transport.transmitting = network_t::transmit_state_t::idle_k;
    released.transport.transmit_operation = network_t::operation_state_t::idle_k;
    client.exchanges[2].stage = uc::network::client_exchange_stage_t::idle_k;
    network_t::client_t::mark_ready(client, released);
    network_t::client_t::client_progress(client);
    // The waiting call closes an idle connection to another origin, and dials once it has closed.
    failures += expect(client.exchanges[3].stage == uc::network::client_exchange_stage_t::waiting_k &&
                       origin.waiting_head == &client.exchanges[3]);
    failures += expect(released.transport.stage == network_t::transport_stage_t::closing_k);
    ucall_client_free(handle);
    return failures;
#else
    return case_result_t::skipped("the POSIX backend is not compiled");
#endif
}

/** An open connection at a depth of sixteen takes every one of sixteen waiting calls into one
 *  output, in call order, so a single send carries them all. */
static case_result_t test_client_batches_sends_unit() {
#if UCALL_WITH_POSIX
    using network_t = uc::network::serial_network<uc::io::posix_engine_t>;
    std::size_t failures = 0;
    ucall_client_t handle {};
    ucall_outcome_t outcome {};
    ucall_client_options_t config {};
    config.backend = ucall_io_backend_posix_k;
    config.cpu_class = ucall_cpu_class_serial_k;
    config.max_concurrent_connections = 1;
    config.max_pipelined_calls = 16;
    ucall_client_init_t init {&handle, &outcome, &config, nullptr};
    ucall_client_init(&init);
    require(failures, outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    auto& client = *static_cast<network_t::client_t*>(handle);
    for (std::size_t i = 0; i != 16; ++i) {
        ucall_client_call_t call {};
        call.client = handle;
        call.outcome = &outcome;
        call.url = uc::bytes_view("http://127.0.0.1:18545/");
        call.verb = ucall_verb_put_k;
        ucall_client_call(&call);
        failures += expect(outcome.status == ucall_status_success_k);
    }
    auto& connection = *client.connections[0];
    auto& origin = *client.exchanges[0].origin;
    connection.origin = &origin;
    ++origin.connections;
    failures += expect(connection.transport.configure({}, &connection) == ucall_status_success_k);
    connection.transport.descriptor = client.engine->open_socket(AF_INET);
    failures += expect(connection.transport.descriptor >= 0);
    connection.transport.stage = network_t::transport_stage_t::open_k;
    network_t::client_t::mark_ready(client, connection);
    network_t::client_t::client_progress(client);
    failures += expect(connection.outstanding_exchanges == 16 && !origin.waiting, "{} calls aboard, {} waiting",
                       connection.outstanding_exchanges, origin.waiting);
    std::size_t order = 0;
    for (auto* exchange = connection.oldest_exchange; exchange; exchange = exchange->next)
        failures += expect(exchange == &client.exchanges[order++]);
    std::string_view const output {reinterpret_cast<char const*>(connection.transport.output.data()),
                                   connection.transport.output.size()};
    std::size_t requests = 0;
    for (std::size_t at = output.find("PUT / HTTP/1.1"); at != std::string_view::npos;
         at = output.find("PUT / HTTP/1.1", at + 1))
        ++requests;
    failures += expect(requests == 16, "one output holds {} requests", requests);
    client.engine->stop();
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
        state.fired = std::chrono::steady_clock::now();
        state.completed.store(completed + 1, std::memory_order_release);
    }

    /** Polls until @p count batches have fired, answering whether they did in five seconds. */
    [[nodiscard]] bool wait(std::size_t count) {
        steady_clock::time_point const deadline = steady_clock::now() + 5s;
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

static case_result_t test_application_batches_unit() {
    batch_context_t batches;
    fixture_t fixture {batch_context_t::receive, &batches};
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
        // The serving round that dispatched the request began no later than its deposit.
        auto const dispatched_before = requests();
        steady_clock::time_point const deadline = steady_clock::now() + 5s;
        std::chrono::steady_clock::time_point deposited {};
        partial.submit(fixture, 0, "/prompt");
        while (batches.completed.load(std::memory_order_acquire) != 2 && steady_clock::now() <= deadline) {
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

static case_result_t test_batches_across_loops_unit() {
    if (UCALL_OS_WINDOWS_) return case_result_t::skipped("IOCP accepts one loop per interface");
    std::size_t failures = 0;
    ucall_server_t server {};
    ucall_client_t client {};
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = uc::bytes_view("127.0.0.1:0");
    network_interface.max_concurrent_connections = 4;
    network_interface.event_loops = 2;
    ucall_server_options_t config {}, resolved {};
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
    steady_clock::time_point const deadline = steady_clock::now() + 5s;
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
static case_result_t test_setup_failure_ends_batch_polling() {
#if UCALL_WITH_POSIX && !UCALL_OS_WINDOWS_
    using network_t = uc::network::serial_network<uc::io::posix_engine_t>;
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
        std::size_t {std::numeric_limits<std::uint32_t>::max() / 8} + 1;
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
    return case_result_t::skipped("needs the POSIX backend on a POSIX host");
#endif
}

/** Two batch endpoints, the first of whose callbacks blocks until the second's batch arrives. */
struct relay_t {
    std::array<std::atomic<ucall_received_http_request_t>, 2> requests {};
    std::atomic<std::size_t> failures {};

    static void first(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
        auto& relay = *static_cast<relay_t*>(context);
        relay.requests[0].store(requests[0], std::memory_order_release);
        steady_clock::time_point const deadline = steady_clock::now() + 5s;
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

static case_result_t test_batch_endpoints_poll_apart_unit() {
    fixture_t fixture;
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
    steady_clock::time_point const deadline = steady_clock::now() + 5s;
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

static case_result_t test_batch_timeout_sleeps_unit() {
    batch_context_t batches;
    fixture_t fixture {batch_context_t::receive, &batches};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    ucall_outcome_t outcome {};
    ucall_server_take_batch_t missing {fixture.server, &outcome, nullptr, 0};
    ucall_server_take_batch(&missing);
    failures += expect(outcome.status == ucall_status_invalid_argument_k, "{}", ucall_status_name(outcome.status));
    // No event loop is ever polled, so only the polling owner's own wait can end the call.
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
static case_result_t test_pipelined_batches_unit([[maybe_unused]] random_generator_t& generator) {
#if UCALL_OS_POSIX_
    std::size_t failures = 0;
    ucall_server_t server {};
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = uc::bytes_view("127.0.0.1:0");
    network_interface.max_concurrent_connections = 1;
    network_interface.max_pipelined_requests = 4;
    ucall_server_options_t config {}, resolved {};
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
                         client.write(uc::byte_span(burst), burst.size(), generator, steady_clock::now() + 5s);
    failures += expect(written, "the burst was not written");
    steady_clock::time_point const deadline = steady_clock::now() + 5s;
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
    return case_result_t::skipped("raw sockets need POSIX");
#endif
}

#pragma endregion Batches

#pragma region Allocators

#if UCALL_WITH_POSIX
using counted_network_t = uc::network::serial_network<uc::io::posix_engine_t, counting_allocator<uc::byte_t>>;

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
        ucall_server_reply_content_t reply {route.server, &outcome, request, ucall_http_status_ok_k, nullptr, 0, body};
        ucall_server_reply_content(&reply);
        route.replied = outcome.status;
    }

    /** Registers @c echo at `/echo/{id}`, answering the outcome. */
    ucall_status_t add() {
        ucall_outcome_t outcome {};
        ucall_server_add_http_endpoint_t add {server, &outcome, uc::bytes_view("/echo/{id}"), ucall_verb_post_k,
                                              echo,   this};
        ucall_server_add_http_endpoint(&add);
        return outcome.status;
    }
};

/** Polls @p route and @p client until the client completes a call, answering it, or a call whose
 *  outcome is the server's own failure or a timeout at @p deadline. */
static ucall_completed_call_t complete_call(echo_route_t const& route, ucall_client_t client,
                                            steady_clock::time_point deadline) {
    ucall_completed_call_t completed {};
    std::size_t count {};
    ucall_outcome_t outcome {};
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
        if (!count && steady_clock::now() > deadline) {
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
    allocation_counts_t counts;
    allocator_t allocator {counts};
    echo_route_t route;
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = uc::bytes_view("127.0.0.1:0");
    network_interface.max_concurrent_connections = 1;
    ucall_server_options_t server_config {}, resolved {};
    server_config.interfaces = &network_interface;
    server_config.interfaces_count = 1;
    server_config.backend = ucall_io_backend_posix_k;
    ucall_server_init_t server_init {&route.server, &outcome, &server_config, &resolved};
    counted_network_t::server_t::server_init(&server_init, allocator);
    require(failures, outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    failures += expect(route.add() == ucall_status_success_k);
    ucall_client_t client {};
    ucall_client_options_t client_config {};
    client_config.backend = ucall_io_backend_posix_k;
    client_config.max_concurrent_connections = 1;
    ucall_client_init_t client_init {&client, &outcome, &client_config, nullptr};
    std::size_t const live = counts.live();
    counts.fail_from = counts.attempts;
    counted_network_t::client_t::client_init(&client_init, allocator);
    failures += expect(!client && outcome.status == ucall_status_out_of_memory_k && counts.live() == live);
    counts.fail_from = std::numeric_limits<std::size_t>::max();
    counted_network_t::client_t::client_init(&client_init, allocator);
    require(failures, outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    std::string url = fmt::format("http://{}/echo/1", uc::text_view(resolved.interfaces[0].address));
    std::string payload(1024, '\0');
    ucall_client_call_t call {};
    call.client = client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(url);
    call.verb = ucall_verb_post_k;
    call.body = uc::bytes_view(payload);
    ucall_client_call(&call);
    failures += expect(outcome.status == ucall_status_success_k);
    auto completed = complete_call(route, client, steady_clock::now() + 5s);
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
    failures += expect(counts.allocations && counts.live() && body.length == payload.size() &&
                       !std::memcmp(body.data, payload.data(), body.length));
    ucall_client_response_free(completed.response);
    failures += expect(!counts.live(), "{} allocations outlived every owner", counts.live());
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
        allocation_counts_t counts;
        counts.fail_from = budget;
        echo_route_t route;
        ucall_outcome_t outcome {};
        ucall_network_interface_t network_interface {};
        network_interface.address = uc::bytes_view("127.0.0.1:0");
        network_interface.max_concurrent_connections = 1;
        ucall_server_options_t server_config {}, resolved {};
        server_config.interfaces = &network_interface;
        server_config.interfaces_count = 1;
        ucall_server_init_t server_init {&route.server, &outcome, &server_config, &resolved};
        counted_network_t::server_t::server_init(&server_init, counting_allocator<uc::byte_t> {counts});
        if (outcome.status == ucall_status_success_k) outcome.status = route.add();
        ucall_status_t completion = outcome.status;
        if (outcome.status == ucall_status_success_k) {
            ucall_client_t client {};
            ucall_client_options_t client_config {};
            client_config.max_concurrent_connections = 1;
            ucall_client_init_t client_init {&client, &outcome, &client_config, nullptr};
            ucall_client_init(&client_init);
            require(failures, outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
            std::string url = fmt::format("http://{}/echo/1", uc::text_view(resolved.interfaces[0].address));
            ucall_client_call_t call {};
            call.client = client;
            call.outcome = &outcome;
            call.url = uc::bytes_view(url);
            call.verb = ucall_verb_post_k;
            call.body = uc::bytes_view(payload);
            ucall_client_call(&call);
            failures += expect(outcome.status == ucall_status_success_k);
            auto completed = complete_call(route, client, steady_clock::now() + 500ms);
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
        failures += expect(!counts.live(), "budget {} kept {} allocations", budget, counts.live());
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

#pragma region Direct Files
#if UCALL_OS_POSIX_

/** The byte at @p offset of the patterned file the file cases read. */
static uc::byte_t file_byte(std::uint64_t offset) noexcept {
    return static_cast<uc::byte_t>((offset * 2654435761u) >> 13);
}

/** Polls @p engine until @p request completes, answering its result, or `-ETIMEDOUT` once
 *  @p deadline passes; other completions are dropped. */
template <typename engine_type_>
static uc::descriptor_t finish(engine_type_& engine, uc::io::io_request_t const& request, std::uint64_t deadline) {
    uc::io::io_completion_t completed[1] {};
    while (uc::utilities::monotonic_ns() < deadline)
        if (engine.poll(completed, uc::io::io_wait_t::blocking_k, deadline) == 1 && completed[0].request == &request)
            return completed[0].result;
    return -ETIMEDOUT;
}
template <typename engine_type_>
static uc::descriptor_t await(engine_type_& engine, uc::io::io_request_t& request, std::uint64_t deadline) {
    return engine.submit(request) == ucall_status_success_k ? finish(engine, request, deadline) : -EIO;
}

/** A disk-backed directory holding `data.bin`, 64 alignments and 123 bytes of patterned content,
 *  beside a FIFO, a subdirectory and a symlink out of it. */
struct direct_files_t {
    direct_directory_t directory;
    std::string content;
    [[nodiscard]] bool fill() {
        content.resize(64 * directory.alignment + 123);
        for (std::size_t i = 0; i != content.size(); ++i) content[i] = static_cast<char>(file_byte(i));
        return directory.write("data.bin", content) && mkfifo(directory.name("fifo").c_str(), 0600) == 0 &&
               symlink("/etc/hostname", directory.name("absolute").c_str()) == 0 &&
               mkdir(directory.name("subdir").c_str(), 0700) == 0;
    }
};

/** Opens beneath a directory for unbuffered reads, refusing escapes, FIFOs and directories without
 *  waiting on a writer; refuses a buffered descriptor; then reads aligned extents, a short tail and
 *  vectors, counting each read as asynchronous or blocking as the engine performed it. */
template <typename engine_type_>
static case_result_t direct_files() {
    direct_files_t files;
    if (!files.directory.ready()) {
        announce("{}", files.directory.reason);
        return case_result_t::skipped("the directory serves no unbuffered reads");
    }
    engine_type_ engine;
    ucall_status_t const opened = engine.open(4, 4);
    if (opened == ucall_status_unsupported_k) return case_result_t::skipped("the kernel lacks this backend");
    require(0, opened == ucall_status_success_k);
    std::size_t failures = 0;
    require(failures, files.fill());
    std::size_t const alignment = files.directory.alignment;
    loopback_pair_t sockets = loopback_pair();
    require(failures, sockets.connected() && uc::utilities::nonblocking(sockets.client) == ucall_status_success_k);
    auto const socket = engine.import_socket(std::exchange(sockets.client, -1));
    auto const deadline = uc::utilities::deadline_after(5000000);

    announce("opening beneath a directory");
    int file = -1;
    for (std::string_view path : {"data.bin", "fifo", "subdir", "absolute", "../data.bin", "missing"}) {
        std::string terminated {path};
        uc::io::io_request_t opening {.operation = uc::io::io_operation_t::file_open_k,
                                      .descriptor = socket,
                                      .data = reinterpret_cast<uc::byte_t*>(terminated.data()),
                                      .length = terminated.size() + 1,
                                      .file = {0, -1, files.directory.descriptor}};
        uc::descriptor_t const opened = await(engine, opening, deadline);
        if (path == "data.bin") {
            uc::utilities::file_geometry_t const geometry = opened >= 0 ? uc::utilities::file_direct_alignment(opened)
                                                                        : uc::utilities::file_geometry_t {};
            failures += expect(opened >= 0 && !geometry.error && geometry.size == files.content.size(),
                               "{} opened as {} measuring {}", path, opened, geometry.size);
            file = static_cast<int>(opened);
        }
        else {
            failures += expect(opened < 0, "{} opened as {}", path, opened);
            if (opened >= 0) ::close(opened);
        }
    }
    require(failures, file >= 0);

    announce("refusing a buffered descriptor");
    int const buffered = ::open(files.directory.name("data.bin").c_str(), O_RDONLY | O_CLOEXEC);
    failures += expect(uc::utilities::file_direct_check(buffered) == ucall_status_invalid_argument_k &&
                       uc::utilities::file_direct_check(file) == ucall_status_success_k);
    ::close(buffered);

    announce("reading aligned extents, a short tail and vectors");
    aligned_bytes_t window {4 * alignment};
    failures += expect(engine.register_memory(window.bytes()).pinning == uc::io::range_pinning_t::unpinned_k);
    uc::io::io_request_t reading {.operation = uc::io::io_operation_t::file_read_k,
                                  .descriptor = socket,
                                  .data = window.data,
                                  .length = 2 * alignment,
                                  .file = {3 * alignment, file, -1}};
    failures += expect(await(engine, reading, deadline) == static_cast<uc::descriptor_t>(2 * alignment) &&
                       std::memcmp(window.data, files.content.data() + 3 * alignment, 2 * alignment) == 0);
    reading.file.offset = 64 * alignment;
    reading.length = alignment;
    failures += expect(await(engine, reading, deadline) == 123 &&
                       std::memcmp(window.data, files.content.data() + 64 * alignment, 123) == 0);
    uc::utilities::io_vector_t vectors[2] {{window.data, alignment}, {window.data + 2 * alignment, alignment}};
    uc::io::io_request_t scattering {.operation = uc::io::io_operation_t::file_read_vectors_k,
                                     .descriptor = socket,
                                     .data = reinterpret_cast<uc::byte_t*>(vectors),
                                     .length = 2,
                                     .file = {5 * alignment, file, -1}};
    failures += expect(await(engine, scattering, deadline) == static_cast<uc::descriptor_t>(2 * alignment) &&
                       std::memcmp(window.data, files.content.data() + 5 * alignment, alignment) == 0 &&
                       std::memcmp(window.data + 2 * alignment, files.content.data() + 6 * alignment, alignment) == 0);
    failures += expect(engine.statistics.file_reads_asynchronous + engine.statistics.file_reads_blocking == 3);
    ::close(file);
    failures += expect(engine.close_socket(socket) == 0);
    return failures;
}

static case_result_t test_direct_files_unit() {
    std::size_t failures = 0;
#if UCALL_WITH_POSIX
    announce("posix");
    failures += keeping_descriptors(direct_files<uc::io::posix_engine_t>).failures;
#endif
#if UCALL_WITH_LINUX_EPOLLAIO
    announce("linux-epollaio");
    failures += keeping_descriptors(direct_files<uc::io::linux_epollaio_engine_t>).failures;
#endif
#if UCALL_WITH_KQUEUE
    announce("bsd-kqueue");
    failures += keeping_descriptors(direct_files<uc::io::bsd_kqueue_engine_t>).failures;
#endif
    return failures;
}

#endif // UCALL_OS_POSIX_

#if UCALL_WITH_LINUX_EPOLLAIO

/** Linux AIO reads land asynchronously; a cancel in flight completes once the kernel answered;
 *  one AIO event serializes several reads without losing any; and a host refusing AIO refuses the
 *  engine, naming the setting to raise. */
static case_result_t epollaio_reads() {
    direct_files_t files;
    if (!files.directory.ready()) {
        announce("{}", files.directory.reason);
        return case_result_t::skipped("the directory serves no unbuffered reads");
    }
    std::size_t failures = 0;
    require(failures, files.fill());
    std::size_t const alignment = files.directory.alignment;
    int const file = ::open(files.directory.name("data.bin").c_str(), O_RDONLY | O_DIRECT | O_CLOEXEC);
    require(failures, file >= 0);
    loopback_pair_t sockets = loopback_pair();
    require(failures, sockets.connected());
    auto const deadline = uc::utilities::deadline_after(5000000);

    announce("a host refusing AIO refuses the engine");
    {
        uc::io::linux_epollaio_engine_t engine;
        engine.files.depth = 0;
        failures += expect(engine.open(4, 4) == ucall_status_unsupported_k && engine.refusal &&
                           std::strstr(engine.refusal, "fs.aio-max-nr"));
    }

    announce("one AIO event serializes four reads");
    uc::io::linux_epollaio_engine_t engine;
    engine.files.depth = 1;
    ucall_status_t const opened = engine.open(8, 8);
    if (opened == ucall_status_unsupported_k) {
        ::close(file);
        return case_result_t::skipped("the kernel lacks Linux AIO");
    }
    require(failures, opened == ucall_status_success_k && engine.files.depth == 1);
    std::array<aligned_bytes_t, 4> windows {aligned_bytes_t {alignment}, aligned_bytes_t {alignment},
                                            aligned_bytes_t {alignment}, aligned_bytes_t {alignment}};
    std::array<uc::io::io_request_t, 4> reads {};
    for (std::size_t i = 0; i != reads.size(); ++i) {
        reads[i] = {.operation = uc::io::io_operation_t::file_read_k,
                    .descriptor = sockets.client,
                    .data = windows[i].data,
                    .length = alignment,
                    .file = {(2 * i + 1) * alignment, file, -1}};
        require(failures, engine.submit(reads[i]) == ucall_status_success_k);
    }
    std::size_t landed = 0;
    while (landed != reads.size() && uc::utilities::monotonic_ns() < deadline) {
        uc::io::io_completion_t completed[4] {};
        int const count = engine.poll(completed, uc::io::io_wait_t::blocking_k, deadline);
        require(failures, count >= 0, "polling ended with {}", count);
        for (int i = 0; i != count; ++i) {
            auto const index = static_cast<std::size_t>(completed[i].request - reads.data());
            failures += expect(
                index < reads.size() && completed[i].result == static_cast<uc::descriptor_t>(alignment) &&
                    std::memcmp(windows[index].data, files.content.data() + (2 * index + 1) * alignment, alignment) ==
                        0,
                "read {} ended with {}", index, completed[i].result);
            ++landed;
        }
    }
    failures += expect(landed == reads.size() && engine.statistics.file_reads_asynchronous == reads.size() &&
                           !engine.statistics.file_reads_blocking,
                       "{} of {} reads landed", landed, reads.size());

    announce("cancelling reads in flight and waiting for an event");
    aligned_bytes_t large {32 * alignment};
    reads[0] = {.operation = uc::io::io_operation_t::file_read_k,
                .descriptor = sockets.client,
                .data = large.data,
                .length = large.size,
                .file = {0, file, -1}};
    reads[1] = reads[0];
    require(failures,
            engine.submit(reads[0]) == ucall_status_success_k && engine.submit(reads[1]) == ucall_status_success_k);
    failures += expect(engine.cancel(reads[1]) == ucall_status_success_k &&
                       engine.cancel(reads[0]) == ucall_status_success_k);
    std::array<uc::descriptor_t, 2> cancelled {0, 0};
    for (std::size_t count = 0; count != cancelled.size() && uc::utilities::monotonic_ns() < deadline;) {
        uc::io::io_completion_t completed[2] {};
        int const polled = engine.poll(completed, uc::io::io_wait_t::blocking_k, deadline);
        require(failures, polled >= 0, "polling ended with {}", polled);
        for (int i = 0; i != polled; ++i, ++count)
            cancelled[static_cast<std::size_t>(completed[i].request - reads.data())] = completed[i].result;
    }
    failures += expect(cancelled[0] == -ECANCELED && cancelled[1] == -ECANCELED, "the reads ended with {} and {}",
                       cancelled[0], cancelled[1]);
    failures += expect(await(engine, reads[0], deadline) == static_cast<uc::descriptor_t>(large.size) &&
                       std::memcmp(large.data, files.content.data(), large.size) == 0);
    ::close(file);
    return failures;
}

/** A `MSG_ZEROCOPY` send completes once the socket took its bytes, and its release only once the
 *  error queue reported it; loopback copies, so that report demotes the socket, whose next
 *  zero-copy send copies and whose next release completes at once. */
static case_result_t epollaio_zero_copy_sends() {
    uc::io::linux_epollaio_engine_t engine;
    ucall_status_t const opened = engine.open(8, 8);
    if (opened == ucall_status_unsupported_k) return case_result_t::skipped("the kernel lacks Linux AIO");
    require(0, opened == ucall_status_success_k);
    std::size_t failures = 0;
    loopback_pair_t sockets = loopback_pair();
    require(failures, sockets.connected() && uc::utilities::nonblocking(sockets.client) == ucall_status_success_k &&
                          uc::utilities::nonblocking(sockets.peer) == ucall_status_success_k);
    aligned_bytes_t window {16384};
    for (std::size_t i = 0; i != window.size; ++i) window.data[i] = file_byte(i);
    auto const deadline = uc::utilities::deadline_after(5000000);
    std::string received;
    auto drain = [&](std::size_t expected) {
        char buffer[16384];
        while (received.size() < expected && uc::utilities::monotonic_ns() < deadline)
            if (ssize_t const length = recv(sockets.peer, buffer, sizeof(buffer), 0); length > 0)
                received.append(buffer, static_cast<std::size_t>(length));
        return received.size() == expected && std::memcmp(received.data(), window.data, received.size()) == 0;
    };

    announce("a release completes only after its notification, and cancelling it changes nothing");
    engine.reserve_releases(1);
    uc::io::io_request_t release {.operation = uc::io::io_operation_t::zero_copy_release_k};
    uc::io::io_request_t sending {.operation = uc::io::io_operation_t::send_zero_copy_k,
                                  .descriptor = sockets.client,
                                  .data = window.data,
                                  .length = window.size,
                                  .release_request = &release};
    uc::descriptor_t const sent = await(engine, sending, deadline);
    failures += expect(sent > 0 && engine.statistics.zero_copy_sends == 1, "sending ended with {} after {} sends", sent,
                       engine.statistics.zero_copy_sends);
    require(failures, engine.submit(release) == ucall_status_success_k);
    failures += expect(engine.cancel(release) == ucall_status_success_k);
    failures += expect(finish(engine, release, deadline) == 0 && engine.statistics.zero_copy_fallbacks == 1,
                       "the release completed with {} fallbacks counted", engine.statistics.zero_copy_fallbacks);
    failures += expect(drain(static_cast<std::size_t>(sent)));

    announce("a copied notification demotes the socket");
    received.clear();
    uc::descriptor_t const copied = await(engine, sending, deadline);
    failures += expect(copied > 0 && engine.statistics.zero_copy_sends == 1);
    failures += expect(await(engine, release, deadline) == 0);
    failures += expect(drain(static_cast<std::size_t>(copied)));
    failures += expect(engine.close_socket(std::exchange(sockets.client, -1)) == 0);
    return failures;
}

static case_result_t test_epollaio_reads_unit() { return keeping_descriptors(epollaio_reads); }
static case_result_t test_epollaio_zero_copy_sends_unit() { return keeping_descriptors(epollaio_zero_copy_sends); }

#endif // UCALL_WITH_LINUX_EPOLLAIO
#pragma endregion Direct Files

int main(int, char** argv) {
    install_test_signal_handlers();
    fmt::print("Hi, dear tester! You look nice today!\n");
    configure_tests();

    suite_totals_t totals {.program = argv[0]};
    run_test(totals, "test_allocator_propagation_unit", test_allocator_propagation_unit);
    run_test(totals, "test_allocation_failure_safety", test_allocation_failure_safety);
    run_test(totals, "test_origin_reuse_and_fairness_unit", test_origin_reuse_and_fairness_unit);
    run_test(totals, "test_client_batches_sends_unit", test_client_batches_sends_unit);
    run_test(totals, "test_ring_refused_at_init_falls_back", test_ring_refused_at_init_falls_back);
    run_test(totals, "test_cpu_class_ceiling_unit", test_cpu_class_ceiling_unit);
    run_test(totals, "test_progress_and_retention_unit", test_progress_and_retention_unit);
    run_test(totals, "test_completion_credits_unit", test_completion_credits_unit);
    run_test(totals, "test_timeout_and_cancel_unit", test_timeout_and_cancel_unit);
    run_test(totals, "test_take_call_reports_retired", test_take_call_reports_retired);
    run_test(totals, "test_application_batches_unit", test_application_batches_unit);
    run_test(totals, "test_batches_across_loops_unit", test_batches_across_loops_unit);
    run_test(totals, "test_batch_endpoints_poll_apart_unit", test_batch_endpoints_poll_apart_unit);
    run_test(totals, "test_setup_failure_ends_batch_polling", test_setup_failure_ends_batch_polling);
    run_test(totals, "test_batch_timeout_sleeps_unit", test_batch_timeout_sleeps_unit);
    run_test(totals, "test_pipelined_batches_unit", test_pipelined_batches_unit);
#if UCALL_OS_POSIX_
    run_test(totals, "test_direct_files_unit", test_direct_files_unit);
#endif
#if UCALL_WITH_LINUX_EPOLLAIO
    run_test(totals, "test_epollaio_reads_unit", test_epollaio_reads_unit);
    run_test(totals, "test_epollaio_zero_copy_sends_unit", test_epollaio_zero_copy_sends_unit);
#endif
    return suite_exit_code(totals);
}
