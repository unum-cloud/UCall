/**
 *  @file test/network.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief C ABI loopback framing, connection reuse, shared admission, Noise authentication, and
 *      engine duplex.
 *
 *  Every case runs against the backend `--backend` names, or the automatic one without it. Backend
 *  parity runs only in the automatic invocation, since it walks every backend the build carries.
 */
#include <cstring> // `std::memcmp`, `std::strlen`

#include <array>       // `std::array`
#include <atomic>      // `std::atomic`
#include <charconv>    // `std::from_chars`
#include <chrono>      // `std::chrono::steady_clock`
#include <mutex>       // `std::mutex`, `std::lock_guard`
#include <span>        // `std::span`
#include <string>      // `std::string`
#include <string_view> // `std::string_view`
#include <thread>      // `std::thread`
#include <utility>     // `std::pair`
#include <vector>      // `std::vector`

#include "ucall/ucall.h"
#include "ucall/curve25519.hpp"
#include "ucall/io.hpp"
#if UCALL_WITH_LINUX_URING
#include "ucall/uring612.hpp"
#include "ucall/uring700.hpp"
#endif

#include "harness.hpp" // `expect`, `require`, `run_test`, `raw_client_t`

namespace uc = unum::ucall;
using namespace unum::ucall::test;

/** The backend under test, which `--backend` names. */
static ucall_io_backend_t backend_under_test = ucall_io_backend_automatic_k;
static ucall_cpu_class_t cpu_class_under_test = ucall_cpu_class_unknown_k;

static ucall_bytes_view_t view(std::string_view text) {
    return {reinterpret_cast<ucall_byte_t const*>(text.data()), text.size()};
}
static ucall_status_t authorize(ucall_noise_key_t const* key, void* context) {
    return std::memcmp(*key, context, sizeof(ucall_noise_key_t)) == 0 ? ucall_status_success_k
                                                                      : ucall_status_peer_rejected_k;
}
static std::chrono::steady_clock::time_point deadline_after(long milliseconds) {
    return std::chrono::steady_clock::now() + std::chrono::milliseconds {milliseconds};
}

/** What a fixture varies between cases; every other setting is fixed. */
struct fixture_config_t {
    ucall_security_mode_t security = ucall_security_mode_none_k;
    std::size_t event_loops = 1;

    /** Open-connection budget of the server and the client alike. */
    std::size_t connections = 1;

    /** Requests the server reads ahead on one connection; zero means one. */
    std::size_t pipelined_requests = 0;

    /** Calls the client sends ahead on one connection; zero means one. */
    std::size_t pipelined_calls = 0;

    ucall_io_backend_t backend = backend_under_test;
};

/**
 *  @brief A loopback server with echo, gated, and header-lookup routes, and a client to call it.
 *
 *  Cases either poll both from their own thread, or serve every loop in the background while raw
 *  clients block on the wire.
 */
struct fixture_t {
    ucall_server_t server {};
    ucall_client_t client {};
    ucall_server_config_t resolved {};
    ucall_client_config_t resolved_client {};
    ucall_noise_key_t server_private {}, server_public {}, client_private {}, client_public {};
    std::string address {}, url {};

    /** The first setup step that failed, which every case checks before it starts. */
    ucall_status_t status {ucall_status_success_k};

    /** Checks that failed in callbacks and polling threads, which no case frame returns. */
    std::atomic<std::size_t> failures {};

    /** Requests that reached the echo or header-lookup routes. */
    std::atomic<std::size_t> dispatched {};

    std::mutex held_mutex {};
    std::vector<ucall_received_http_request_t> held {};
    std::vector<std::thread> pollers {};

    /** Checks the peer is the fixture's client, then replies with the request body and an
     *  `X-UCall: passed` header. */
    void reply_echo(ucall_received_http_request_t request) {
        ucall_outcome_t outcome {};
        std::size_t network_interface_index = resolved.interfaces_count;
        ucall_noise_key_t peer_static_key {}, expected_key {};
        if (resolved.interfaces[0].security_mode != ucall_security_mode_none_k)
            std::memcpy(expected_key, client_public, sizeof(expected_key));
        ucall_server_request_peer_t peer {server, &outcome, request, &network_interface_index, &peer_static_key};
        ucall_server_request_peer(&peer);
        failures += expect(outcome.status == ucall_status_success_k && network_interface_index == 0 &&
                               std::memcmp(peer_static_key, expected_key, sizeof(expected_key)) == 0,
                           "peer: {} on interface {}", ucall_status_name(outcome.status), network_interface_index);
        ucall_bytes_view_t body {};
        ucall_server_request_body_t extract {server, &outcome, request, &body};
        ucall_server_request_body(&extract);
        failures += expect(outcome.status == ucall_status_success_k);
        ucall_bytes_view_t header = view("X-UCall: passed");
        ucall_server_reply_content_t reply {server, &outcome, request, &header, 1, body};
        ucall_server_reply_content(&reply);
        failures += expect(outcome.status == ucall_status_success_k, "reply: {}", ucall_status_name(outcome.status));
    }
    static void echo(ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<fixture_t*>(context);
        fixture.dispatched.fetch_add(1, std::memory_order_relaxed);
        fixture.reply_echo(request);
    }
    static void gate(ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<fixture_t*>(context);
        std::lock_guard lock {fixture.held_mutex};
        fixture.held.push_back(request);
    }

    /** Replies with what four lookups found, each value or status name followed by a semicolon. */
    static void lookup(ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<fixture_t*>(context);
        fixture.dispatched.fetch_add(1, std::memory_order_relaxed);
        std::string answer;
        for (std::string_view name : {"Content-TYPE", "X-~", "x-^", "X-Absent"}) {
            ucall_outcome_t outcome {};
            ucall_bytes_view_t value {};
            ucall_server_request_header_t get {fixture.server, &outcome, request, view(name), &value};
            ucall_server_request_header(&get);
            if (outcome.status == ucall_status_success_k)
                answer.append(reinterpret_cast<char const*>(value.data), value.length);
            else answer += ucall_status_name(outcome.status);
            answer += ';';
        }
        ucall_outcome_t outcome {};
        ucall_server_reply_content_t reply {fixture.server, &outcome, request, nullptr, 0, view(answer)};
        ucall_server_reply_content(&reply);
        fixture.failures += expect(outcome.status == ucall_status_success_k);
    }

    std::size_t held_count() {
        std::lock_guard lock {held_mutex};
        return held.size();
    }

    /** Pops one request the `/gate` route retained, or null when none waits. */
    ucall_received_http_request_t take_held() {
        std::lock_guard lock {held_mutex};
        if (held.empty()) return nullptr;
        auto request = held.back();
        held.pop_back();
        return request;
    }

    explicit fixture_t(fixture_config_t const& settings) {
        for (std::size_t i = 0; i != sizeof(server_private); ++i) {
            server_private[i] = static_cast<ucall_byte_t>(i + 1);
            client_private[i] = static_cast<ucall_byte_t>(i + sizeof(server_private) + 1);
        }
        uc::x25519_derive_public(std::as_writable_bytes(std::span {server_public}).data(),
                                 std::as_bytes(std::span {server_private}).data());
        uc::x25519_derive_public(std::as_writable_bytes(std::span {client_public}).data(),
                                 std::as_bytes(std::span {client_private}).data());
        ucall_network_interface_t network_interface {};
        network_interface.address = "127.0.0.1:0";
        network_interface.event_loops = settings.event_loops;
        network_interface.max_concurrent_connections = settings.connections;
        network_interface.max_pipelined_requests = settings.pipelined_requests;
        network_interface.security_mode = settings.security;
        network_interface.noise_private_key = &server_private;
        network_interface.peer_authorizer = authorize;
        network_interface.peer_authorizer_context = client_public;
        ucall_server_config_t config {};
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
        config.backend = settings.backend;
        config.cpu_class = cpu_class_under_test;
        ucall_outcome_t outcome {};
        ucall_server_init_t init {&server, &outcome, &config, &resolved};
        ucall_server_init(&init);
        if ((status = outcome.status) != ucall_status_success_k) return;
        using route_t = std::pair<char const*, ucall_received_http_request_callback_t>;
        for (auto [route, callback] :
             {route_t {"/echo/{id}", echo}, route_t {"/gate", gate}, route_t {"/headers", lookup}}) {
            ucall_server_add_http_endpoint_t add {server, &outcome, view(route), ucall_verb_any_k, callback, this};
            ucall_server_add_http_endpoint(&add);
            if ((status = outcome.status) != ucall_status_success_k) return;
        }
        ucall_client_config_t client_config {};
        client_config.max_concurrent_connections = settings.connections;
        client_config.max_pipelined_calls = settings.pipelined_calls;
        client_config.max_concurrent_calls = 2 * settings.connections *
                                             (settings.pipelined_calls ? settings.pipelined_calls : 1);
        client_config.noise_private_key = &client_private;
        client_config.peer_authorizer = authorize;
        client_config.peer_authorizer_context = server_public;
        client_config.backend = settings.backend;
        client_config.cpu_class = cpu_class_under_test;
        ucall_client_init_t client_init {&client, &outcome, &client_config, &resolved_client};
        ucall_client_init(&client_init);
        if ((status = outcome.status) != ucall_status_success_k) return;
        address = resolved.interfaces[0].address;
        url = settings.security == ucall_security_mode_none_k ? "http://" : "http+noise://";
        url += address;
    }
    ~fixture_t() {
        stop();
        ucall_client_free(client);
        ucall_server_free(server);
    }

    /** Polls every event loop on its own thread until @c stop, for cases whose clients block. */
    void serve_in_background() {
        for (std::size_t loop = 0; loop != resolved.interfaces[0].event_loops; ++loop)
            pollers.emplace_back([this, loop] {
                ucall_outcome_t outcome {};
                ucall_server_take_calls_t serving {server, &outcome, loop};
                ucall_server_take_calls(&serving);
                failures += expect(outcome.status == ucall_status_success_k, "loop {} ended with {}", loop,
                                   ucall_status_name(outcome.status));
            });
    }

    /** Stops and joins the background loops, answering the failures counted outside a case. */
    std::size_t stop() {
        if (!pollers.empty()) ucall_server_stop(server);
        for (auto& poller : pollers) poller.join();
        pollers.clear();
        return failures.load();
    }

    std::size_t poll(ucall_completed_call_t& completed) {
        ucall_outcome_t outcome {};
        for (std::size_t i = 0; i != resolved.interfaces[0].event_loops; ++i) {
            ucall_server_take_call_t serving {server, &outcome, i, 0};
            ucall_server_take_call(&serving);
            failures += expect(outcome.status == ucall_status_success_k);
        }
        std::size_t count {};
        ucall_client_take_completed_t take {client, &outcome, &completed, 1, &count, 0};
        ucall_client_take_completed(&take);
        failures += expect(outcome.status == ucall_status_success_k);
        return count;
    }

    /** The next completed call, or one with a timeout outcome after five seconds. */
    ucall_completed_call_t wait() {
        auto const deadline = deadline_after(5000);
        ucall_completed_call_t completed {};
        while (!poll(completed))
            if (std::chrono::steady_clock::now() > deadline) {
                completed.outcome.status = ucall_status_timeout_k;
                break;
            }
        return completed;
    }
};

/** Checks a 200 response carries @p expected and the echo header, then frees it. */
static std::size_t check_response(fixture_t& fixture, ucall_received_http_response_t response,
                                  std::string_view expected) {
    std::size_t failures = 0;
    failures += expect(ucall_client_response_status(fixture.client, response) == ucall_http_status_ok_k);
    ucall_outcome_t outcome {};
    ucall_bytes_view_t body {}, header {};
    ucall_client_response_body_t get {fixture.client, &outcome, response, &body};
    ucall_client_response_body(&get);
    failures += expect(outcome.status == ucall_status_success_k && body.length == expected.size(),
                       "{} body bytes against {}", body.length, expected.size());
    failures += expect(body.length != expected.size() || !body.length ||
                       std::memcmp(body.data, expected.data(), body.length) == 0);
    ucall_client_response_header_t get_header {fixture.client, &outcome, response, view("X-UCALL"), &header};
    ucall_client_response_header(&get_header);
    failures += expect(outcome.status == ucall_status_success_k && header.length == 6 &&
                       std::memcmp(header.data, "passed", 6) == 0);
    ucall_client_response_free(response);
    return failures;
}

#pragma region Library Clients

static case_result_t exchanges(ucall_security_mode_t security) {
    fixture_t fixture {{.security = security}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    // Four records under Noise, which seals and opens them where they lie.
    std::string payload(200 * 1024, 'x');
    payload[0] = '\0';
    auto url = fixture.url + "/echo/42?key=value";
    ucall_outcome_t outcome {};
    ucall_client_call_t call {};
    call.client = fixture.client;
    call.outcome = &outcome;
    call.url = view(url);
    call.verb = ucall_verb_post_k;
    call.body = view(payload);
    call.options.security = security;
    call.options.server_key = &fixture.server_public;
    auto exchange = [&](std::string_view expected) {
        ucall_client_call(&call);
        failures += expect(outcome.status == ucall_status_success_k);
        auto completed = fixture.wait();
        failures += expect(completed.outcome.status == ucall_status_success_k && completed.response, "{}",
                           ucall_status_name(completed.outcome.status));
        if (completed.response) failures += check_response(fixture, completed.response, expected);
    };
    auto copies_beyond_receipt = [&] {
        ucall_event_loop_statistics_t counters {};
        ucall_outcome_t queried {};
        ucall_server_event_loop_statistics_t query {fixture.server, &queried, 0, &counters};
        ucall_server_event_loop_statistics(&query);
        return counters.bytes_copied - counters.bytes_received;
    };
    // A reply's copy is counted once its send completes, which can trail the client's completion.
    auto settled_copies = [&](std::uint64_t since, std::uint64_t expected) {
        auto const deadline = deadline_after(2000);
        ucall_completed_call_t completed {};
        auto copies = copies_beyond_receipt();
        while (copies - since < expected && std::chrono::steady_clock::now() < deadline) {
            failures += expect(!fixture.poll(completed), "a call completed unasked");
            copies = copies_beyond_receipt();
        }
        return copies;
    };
    announce("two calls over one connection");
    exchange(payload);
    auto const before = settled_copies(0, payload.size());
    exchange(payload);
    auto const copied = settled_copies(before, payload.size()) - before;
    failures += expect(copied == payload.size(), "{} bytes copied beyond those received for a {}-byte echo", copied,
                       payload.size());
    if (security != ucall_security_mode_none_k) return failures + fixture.stop();
    announce("a named host");
    auto named_url = url;
    named_url.replace(named_url.find("127.0.0.1"), std::strlen("127.0.0.1"), "localhost");
    call.url = view(named_url);
    exchange(payload);
    announce("a closing call, then a fresh connection");
    call.url = view(url);
    ucall_bytes_view_t close = view("Connection: close");
    call.headers = &close;
    call.headers_count = 1;
    exchange(payload);
    call.verb = ucall_verb_get_k;
    call.body = {};
    call.headers = nullptr;
    call.headers_count = 0;
    exchange({});
    return failures + fixture.stop();
}

static case_result_t test_exchanges_plain() { return exchanges(ucall_security_mode_none_k); }
static case_result_t test_exchanges_noise_xx() { return exchanges(ucall_security_mode_noise_xx_k); }
static case_result_t test_exchanges_noise_ik() { return exchanges(ucall_security_mode_noise_ik_k); }

/** A request retained on one loop does not stall a call the other loop serves meanwhile. */
static case_result_t test_multiloop_retention() {
    if (UCALL_OS_WINDOWS_) return case_result_t::skipped("IOCP accepts one loop per interface");
    fixture_t fixture {{.event_loops = 2, .connections = 2}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    ucall_outcome_t outcome {};
    auto gate_url = fixture.url + "/gate", echo_url = fixture.url + "/echo/42";
    ucall_client_call_t call {};
    call.client = fixture.client;
    call.outcome = &outcome;
    call.url = view(gate_url);
    call.verb = ucall_verb_post_k;
    call.context = &gate_url;
    ucall_client_call(&call);
    failures += expect(outcome.status == ucall_status_success_k);
    auto const deadline = deadline_after(5000);
    ucall_received_http_request_t held {};
    while (!(held = fixture.take_held())) {
        ucall_completed_call_t completed {};
        failures += expect(!fixture.poll(completed));
        require(failures, std::chrono::steady_clock::now() < deadline, "the gated request never arrived");
    }
    call.url = view(echo_url);
    call.context = &echo_url;
    ucall_client_call(&call);
    failures += expect(outcome.status == ucall_status_success_k);
    auto completed = fixture.wait();
    failures += expect(completed.context == &echo_url && completed.outcome.status == ucall_status_success_k);
    if (completed.response) failures += check_response(fixture, completed.response, {});
    fixture.reply_echo(held);
    completed = fixture.wait();
    failures += expect(completed.context == &gate_url && completed.outcome.status == ucall_status_success_k);
    if (completed.response) failures += check_response(fixture, completed.response, {});
    return failures + fixture.stop();
}

/** Application threads reply to retained requests while the test thread polls the loop. */
static case_result_t test_cross_thread_replies_stress() {
    constexpr std::size_t threads_count = 4;
    fixture_t fixture {{.connections = threads_count}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::atomic<bool> finished {false};
    std::vector<std::thread> repliers;
    for (std::size_t i = 0; i != threads_count; ++i)
        repliers.emplace_back([&] {
            while (!finished.load(std::memory_order_acquire))
                if (auto request = fixture.take_held()) fixture.reply_echo(request);
                else std::this_thread::yield();
        });
    std::size_t failures = 0;
    std::string const gate_url = fixture.url + "/gate";
    std::array<std::string, threads_count> bodies;
    std::size_t const rounds = scale_iterations(64);
    for (std::size_t round = 0; round != rounds && !failures; ++round) {
        for (std::size_t i = 0; i != threads_count; ++i) {
            bodies[i] = fmt::format("round {} call {}", round, i);
            ucall_outcome_t outcome {};
            ucall_client_call_t call {};
            call.client = fixture.client;
            call.outcome = &outcome;
            call.url = view(gate_url);
            call.verb = ucall_verb_post_k;
            call.body = view(bodies[i]);
            call.context = &bodies[i];
            ucall_client_call(&call);
            failures += expect(outcome.status == ucall_status_success_k);
        }
        for (std::size_t i = 0; i != threads_count; ++i) {
            auto completed = fixture.wait();
            failures += expect(completed.outcome.status == ucall_status_success_k && completed.response, "round {}: {}",
                               round, ucall_status_name(completed.outcome.status));
            if (!completed.response) break;
            failures += check_response(fixture, completed.response, *static_cast<std::string*>(completed.context));
        }
    }
    finished.store(true, std::memory_order_release);
    for (auto& replier : repliers) replier.join();
    return failures + fixture.stop();
}

/** Polls until the `/gate` route holds @p count requests, with no call completing meanwhile. */
static std::size_t await_held(fixture_t& fixture, std::size_t count) {
    std::size_t failures = 0;
    auto const deadline = deadline_after(5000);
    while (fixture.held_count() != count && !failures) {
        ucall_completed_call_t completed {};
        failures += expect(!fixture.poll(completed), "a call completed early");
        failures += expect(std::chrono::steady_clock::now() < deadline, "the server holds {} of {} requests",
                           fixture.held_count(), count);
    }
    return failures;
}

/** Eight calls at depth four share one connection: the server holds four at once, which lockstep
 *  calls never reach, and the responses to replies given in reverse complete in call order. */
static case_result_t pipelined_calls(ucall_security_mode_t security) {
    fixture_t fixture {{.security = security, .pipelined_requests = 4, .pipelined_calls = 4}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    require(0, fixture.resolved_client.max_pipelined_calls == 4);
    std::size_t failures = 0;
    std::string const gate_url = fixture.url + "/gate";
    std::array<std::string, 8> bodies;
    for (std::size_t i = 0; i != bodies.size(); ++i) {
        // Growing bodies, so later replies span several records each behind shorter ones.
        bodies[i] = fmt::format("call {}", i) + std::string(i * 40 * 1024, '.');
        ucall_outcome_t outcome {};
        ucall_client_call_t call {};
        call.client = fixture.client;
        call.outcome = &outcome;
        call.url = view(gate_url);
        call.verb = ucall_verb_post_k;
        call.body = view(bodies[i]);
        call.context = &bodies[i];
        call.options.security = security;
        call.options.server_key = &fixture.server_public;
        ucall_client_call(&call);
        failures += expect(outcome.status == ucall_status_success_k);
    }
    for (std::size_t next = 0; next != bodies.size() && !failures;) {
        failures += await_held(fixture, 4);
        while (auto request = fixture.take_held()) fixture.reply_echo(request);
        for (auto const end = next + 4; next != end && !failures; ++next) {
            auto completed = fixture.wait();
            failures += expect(completed.context == &bodies[next] && completed.response, "call {} completed {}: {}",
                               next, static_cast<std::string const*>(completed.context) - bodies.data(),
                               ucall_status_name(completed.outcome.status));
            if (completed.response) failures += check_response(fixture, completed.response, bodies[next]);
        }
    }
    return failures + fixture.stop();
}

static case_result_t test_pipelined_calls_plain() { return pipelined_calls(ucall_security_mode_none_k); }
static case_result_t test_pipelined_calls_noise_xx() { return pipelined_calls(ucall_security_mode_noise_xx_k); }

/** The server closes after its second response with a POST and a GET still on the connection: the
 *  POST finishes as closed without reaching the server, and the GET is retried and answered. */
static case_result_t test_pipelined_call_loss() {
    fixture_t fixture {{.pipelined_requests = 4, .pipelined_calls = 4}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    std::string const gate_url = fixture.url + "/gate", post_url = fixture.url + "/echo/3",
                      get_url = fixture.url + "/echo/4";
    ucall_bytes_view_t const close = view("Connection: close");
    struct planned_call_t {
        std::string const* url;
        ucall_verb_t verb;
        ucall_status_t expected;
    };
    std::array<planned_call_t, 4> plan {{{&gate_url, ucall_verb_get_k, ucall_status_success_k},
                                         {&gate_url, ucall_verb_get_k, ucall_status_success_k},
                                         {&post_url, ucall_verb_post_k, ucall_status_connection_closed_k},
                                         {&get_url, ucall_verb_get_k, ucall_status_success_k}}};
    for (auto& planned : plan) {
        ucall_outcome_t outcome {};
        ucall_client_call_t call {};
        call.client = fixture.client;
        call.outcome = &outcome;
        call.url = view(*planned.url);
        call.verb = planned.verb;
        call.context = &planned;
        if (&planned == &plan[1]) {
            call.headers = &close;
            call.headers_count = 1;
        }
        ucall_client_call(&call);
        failures += expect(outcome.status == ucall_status_success_k);
    }
    failures += await_held(fixture, 2);
    // The server stops reading at the closing request; meanwhile the last two calls leave too.
    for (auto const settled = deadline_after(100); std::chrono::steady_clock::now() < settled;) {
        ucall_completed_call_t completed {};
        failures += expect(!fixture.poll(completed), "a call completed early");
    }
    while (auto request = fixture.take_held()) fixture.reply_echo(request);
    for (auto const& planned : plan) {
        auto completed = fixture.wait();
        failures += expect(completed.context == &planned && completed.outcome.status == planned.expected,
                           "call {} completed {}: {}", &planned - plan.data(),
                           static_cast<planned_call_t const*>(completed.context) - plan.data(),
                           ucall_status_name(completed.outcome.status));
        if (completed.response) failures += check_response(fixture, completed.response, {});
    }
    failures += expect(fixture.dispatched.load() == 1, "{} echo requests were dispatched", fixture.dispatched.load());
    return failures + fixture.stop();
}

#pragma endregion Library Clients

#pragma region Raw Clients
#if UCALL_OS_POSIX_

static uc::span<uc::byte_t const> wire_bytes(std::string_view text) { return ascii_bytes(text.data(), text.size()); }

/** Sends @p request whole, reads until the server closes, and answers the first response. */
static wire_response_t exchange_until_close(raw_client_t& client, std::string_view request, std::size_t max_chunk,
                                            std::size_t& failures) {
    auto const deadline = deadline_after(10000);
    auto const written = client.write(wire_bytes(request), max_chunk, deadline);
    auto const end = client.read_until_close(deadline);
    int const error = end == read_end_t::failed_k ? errno : 0;
    auto const response = parse_response(client.received);
    // Closing over unread request bytes cuts writes short and resets reads, until servers linger.
    bool const answered = response.length && response.length == client.received.size();
    failures += expect(written || answered, "the server stopped reading");
    failures += expect(end == read_end_t::closed_k || (error == ECONNRESET && answered),
                       "the read ended as {} after {} bytes, errno {}", static_cast<int>(end), client.received.size(),
                       error);
    return response;
}

/** Three requests arriving in one segment, the second closing, come back as two responses in
 *  order, then the close, even when the server may read four ahead. */
static case_result_t test_pipelined_delivery() {
    fixture_t fixture {{.pipelined_requests = 4}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t client;
    require(failures, client.connect(fixture.address));
    std::string_view const burst = "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nfirst"
                                   "POST /echo/2 HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\n"
                                   "Connection: close\r\n\r\nsecond"
                                   "POST /echo/3 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nthird";
    // One send, so the server has read the third request before it closes,
    // and the close is no reset.
    failures += expect(::send(client.descriptor, burst.data(), burst.size(), 0) == static_cast<ssize_t>(burst.size()));
    auto const end = client.read_until_close(deadline_after(10000));
    failures += expect(end == read_end_t::closed_k, "the read ended as {}", static_cast<int>(end));
    auto const first = parse_response(client.received);
    auto const second = parse_response(std::string_view {client.received}.substr(first.length));
    failures += expect(first.status == 200 && first.body == "first", "first answered {} {}", first.status, first.body);
    failures += expect(second.status == 200 && second.body == "second", "second answered {} {}", second.status,
                       second.body);
    failures += expect(first.length + second.length == client.received.size());
    failures += expect(fixture.dispatched.load() == 2, "{} requests were dispatched", fixture.dispatched.load());
    return failures + fixture.stop();
}

/** Headers written one byte per segment still parse. */
static case_result_t test_fragmented_headers_delivery() {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t client;
    require(failures, client.connect(fixture.address));
    auto const response = exchange_until_close(
        client, "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody", 1, failures);
    failures += expect(response.status == 200 && response.body == "body", "answered {} {}", response.status,
                       response.body);
    return failures + fixture.stop();
}

/** A mebibyte body sent in random fragments echoes back byte for byte, in full-length sends. */
static case_result_t test_megabyte_echo_delivery() {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    std::size_t const body_length = std::size_t {1} << 20;
    std::string request = fmt::format(
        "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body_length);
    std::size_t const headers_length = request.size();
    auto& generator = global_random_generator();
    for (std::size_t i = 0; i != body_length; ++i) request.push_back(static_cast<char>(generator()));
    raw_client_t client;
    require(failures, client.connect(fixture.address));
    auto const response = exchange_until_close(client, request, 65536, failures);
    failures += expect(response.status == 200, "answered {}", response.status);
    failures += expect_bytes(wire_bytes(response.body), wire_bytes(std::string_view {request}.substr(headers_length)));
    return failures + fixture.stop();
}

/** A request a proxy could frame differently than UCall, which must be refused whole. */
struct smuggling_row_t {
    char const* name;
    std::string_view request;
    unsigned expected_status {400};
};

static constexpr smuggling_row_t smuggling_rows_k[] {
    {"length beside chunked", "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n"
                              "\r\n0\r\n\r\nGET /echo/2 HTTP/1.1\r\nHost: a\r\n\r\n"},
    {"two lengths", "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nContent-Length: 4\r\n\r\nbody"},
    {"gzip coding", "POST /echo/1 HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n0\r\n\r\n", 501},
    {"17 hex digits", "POST /echo/1 HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000001\r\nx\r\n"
                      "0\r\n\r\n"},
    {"bare line feed", "POST /echo/1 HTTP/1.1\r\nHost: a\r\nX-Pad: 1\nContent-Length: 4\r\n\r\nbody"},
    {"space before colon", "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length : 4\r\n\r\nbody"},
    {"no host", "GET /echo/1 HTTP/1.1\r\n\r\n"},
};

/** Every smuggling row is answered with an error status and a close, and never dispatched. */
static case_result_t test_smuggling_safety() {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    for (auto const& row : smuggling_rows_k) {
        announce("{}", row.name);
        auto const dispatched = fixture.dispatched.load();
        raw_client_t client;
        require(failures, client.connect(fixture.address));
        auto const response = exchange_until_close(client, row.request, 0, failures);
        failures += expect(response.status == row.expected_status, "{} answered {} bytes: {:?}", row.name,
                           client.received.size(), client.received);
        failures += expect(fixture.dispatched.load() == dispatched, "{} was dispatched", row.name);
    }
    return failures + fixture.stop();
}

/** Header names match without regard to letter case, and only letters fold. */
static case_result_t test_header_lookup_unit() {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t client;
    require(failures, client.connect(fixture.address));
    std::string_view const request = "GET /headers HTTP/1.1\r\nHost: a\r\nContent-Type: text/plain\r\nX-~: tilde\r\n"
                                     "Connection: close\r\n\r\n";
    auto const response = exchange_until_close(client, request, 8, failures);
    // `^` and `~` differ only in the bit that folds ASCII letters.
    failures += expect(response.body == "text/plain;tilde;not-found;not-found;", "answered {} {}", response.status,
                       response.body);
    return failures + fixture.stop();
}

/** Two loops share a budget of two: a third client waits in the backlog until one closes. */
static case_result_t test_admission_across_loops() {
    if (UCALL_OS_WINDOWS_) return case_result_t::skipped("IOCP accepts one loop per interface");
    fixture_t fixture {{.event_loops = 2, .connections = 2}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    require(0, fixture.resolved.interfaces[0].event_loops == 2);
    fixture.serve_in_background();
    std::size_t failures = 0;
    std::string_view const request = "GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n";
    raw_client_t clients[3];
    for (std::size_t i = 0; i != 3; ++i) {
        require(failures, clients[i].connect(fixture.address), "client {} could not connect", i);
        failures += expect(clients[i].write(wire_bytes(request), 0, deadline_after(5000)));
        if (i != 2) failures += expect(read_response(clients[i], 0).status == 200, "client {} was not served", i);
    }
    failures += expect(clients[2].read(1, deadline_after(300)) == read_end_t::timed_out_k,
                       "the third client was served over budget");
    clients[0].close();
    failures += expect(read_response(clients[2], 0).status == 200, "the third client was not served after a close");
    return failures + fixture.stop();
}

/** Drops every `date:` line, the one header two identical exchanges may differ in. */
static std::string without_dates(std::string wire) {
    for (auto start = wire.find("\r\ndate: "); start != std::string::npos; start = wire.find("\r\ndate: ", start))
        wire.erase(start, wire.find("\r\n", start + 2) - start);
    return wire;
}

/** Every backend this process can create answers one raw transcript with the same bytes. */
static case_result_t test_backend_parity() {
    static constexpr ucall_io_backend_t backends_k[] {
        ucall_io_backend_posix_k,          ucall_io_backend_linux_epoll_k,  ucall_io_backend_linux_uring612_k,
        ucall_io_backend_linux_uring700_k, ucall_io_backend_macos_kqueue_k, ucall_io_backend_windows_iocp_k};
    std::size_t failures = 0, compared = 0;
    std::string reference;
    char const* reference_name = "";
    for (auto backend : backends_k) {
        fixture_t fixture {{.backend = backend}};
        if (fixture.status == ucall_status_unsupported_k) continue;
        char const* name = ucall_io_backend_name(backend);
        require(failures, fixture.status == ucall_status_success_k, "{} setup: {}", name,
                ucall_status_name(fixture.status));
        announce("{}", name);
        fixture.serve_in_background();
        raw_client_t client;
        require(failures, client.connect(fixture.address));
        std::size_t offset = 0;
        for (std::string_view request : {"GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n",
                                         "POST /echo/2 HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\n\r\nposted",
                                         "GET /missing HTTP/1.1\r\nHost: a\r\n\r\n"}) {
            failures += expect(client.write(wire_bytes(request), 16, deadline_after(5000)));
            offset += read_response(client, offset).length;
        }
        exchange_until_close(client,
                             "POST /echo/3 HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\nleft"
                             "POST /echo/4 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nConnection: close\r\n\r\nright",
                             0, failures);
        failures += fixture.stop();
        auto transcript = without_dates(client.received);
        if (!compared++) {
            reference = transcript;
            reference_name = name;
        }
        else
            failures += expect(transcript == reference, "{} answered {:?}, {} answered {:?}", name, transcript,
                               reference_name, reference);
    }
    if (compared < 2) return case_result_t::skipped("fewer than two backends are available", failures);
    return failures;
}

#endif // UCALL_OS_POSIX_
#pragma endregion Raw Clients

#pragma region Engines
#if UCALL_OS_POSIX_

/** A mebibyte send and a receive wait on one socket together,
 *  and each completes as its own request. */
template <typename engine_type_>
static case_result_t engine_duplex() {
    engine_type_ engine;
    auto const status = engine.open(2, 2);
    if (status == ucall_status_unsupported_k) return case_result_t::skipped("the kernel lacks this backend");
    require(0, status == ucall_status_success_k, "{}", ucall_status_name(status));
    std::size_t failures = 0;
    int sockets[2] {-1, -1};
    require(failures, socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    // A send buffer far below a mebibyte keeps the send pending until the peer drains it.
    int const send_buffer = static_cast<int>(fixture_buffer_bytes_k);
    require(failures, uc::nonblocking(sockets[0]) && uc::nonblocking(sockets[1]) &&
                          uc::socket_option(sockets[0], SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)) == 0);
    auto const owned = engine.import_socket(sockets[0]);
    require(failures, owned >= 0, "importing ended with {}", owned);
    auto const peer = sockets[1];

    std::vector<uc::byte_t> payload(std::size_t {1} << 20), drained(payload.size());
    auto& generator = global_random_generator();
    for (auto& byte : payload) byte = static_cast<uc::byte_t>(generator());
    auto const message = ascii_bytes("receive");
    std::array<uc::byte_t, fixture_buffer_bytes_k> buffer {};
    uc::io_request_t receiving {uc::io_operation_t::receive_k, owned, buffer.data(), buffer.size()};
    uc::io_request_t sending {uc::io_operation_t::send_k, owned, payload.data(), payload.size()};
    require(failures, engine.submit(receiving) == ucall_status_success_k);
    require(failures, engine.submit(sending) == ucall_status_success_k);

    std::size_t received = 0, sent = 0, read = 0;
    bool written = false;
    uc::io_completion_t completions[2] {};
    auto const deadline = uc::deadline_after(5000000);
    while (!received || sent != payload.size() || read != payload.size()) {
        // Nothing drains the peer before the receive completes,
        // so the send stays pending throughout.
        auto const wait = written && !received ? uc::io_wait_t::blocking_k : uc::io_wait_t::nonblocking_k;
        int const count = engine.poll(uc::span<uc::io_completion_t> {completions}, wait, deadline);
        require(failures, count >= 0, "polling ended with {}", count);
        for (auto const& completed :
             uc::span<uc::io_completion_t> {completions}.first(static_cast<std::size_t>(count))) {
            if (completed.request == &sending) {
                require(failures, completed.result > 0, "sending ended with {}", completed.result);
                sent += static_cast<std::size_t>(completed.result);
                sending.data = payload.data() + sent;
                sending.length = payload.size() - sent;
                if (sent != payload.size()) require(failures, engine.submit(sending) == ucall_status_success_k);
            }
            else {
                require(failures, completed.request == &receiving, "a completion named neither request");
                require(failures, completed.result > 0, "receiving ended with {}", completed.result);
                received = static_cast<std::size_t>(completed.result);
                uc::span<uc::byte_t const> const delivered {completed.data ? completed.data : receiving.data, received};
                failures += expect_bytes(delivered, message);
                failures += expect(sent != payload.size(), "the send finished before the peer read");
            }
            engine.release(completed);
        }
        if (!written && !count) {
            require(failures,
                    ::send(peer, message.data(), message.size(), MSG_NOSIGNAL) == static_cast<ssize_t>(message.size()));
            written = true;
        }
        if (received && read != drained.size()) {
            auto const length = ::recv(peer, drained.data() + read, drained.size() - read, 0);
            if (length > 0) read += static_cast<std::size_t>(length);
            else require(failures, length < 0 && uc::io_pending(-errno), "draining ended with {}", length);
        }
        require(failures, uc::monotonic_ns() < deadline, "{} received, {} sent and {} read of {}", received, sent, read,
                payload.size());
    }
    failures += expect(drained == payload);
    failures += expect(engine.close_socket(owned) == 0);
    uc::socket_close(peer);
    return failures;
}

/** The engine `--backend` names keeps a receive and a send pending on one socket at once. */
static case_result_t test_engine_duplex_delivery() {
    switch (backend_under_test) {
#if UCALL_WITH_POSIX
    case ucall_io_backend_posix_k: return engine_duplex<uc::posix_engine_t>();
#endif
#if UCALL_WITH_LINUX_EPOLL
    case ucall_io_backend_linux_epoll_k: return engine_duplex<uc::linux_epoll_engine_t>();
#endif
#if UCALL_WITH_LINUX_URING
    case ucall_io_backend_linux_uring612_k: return engine_duplex<uc::linux_uring612_engine_t>();
    case ucall_io_backend_linux_uring700_k: return engine_duplex<uc::linux_uring700_engine_t>();
#endif
#if UCALL_WITH_KQUEUE
    case ucall_io_backend_macos_kqueue_k: return engine_duplex<uc::kqueue_engine_t>();
#endif
    default: return case_result_t::skipped("no named POSIX engine");
    }
}

#endif // UCALL_OS_POSIX_
#pragma endregion Engines

int main(int argc, char** argv) {
    install_test_signal_handlers();
    fmt::print("Hi, dear tester! You look nice today!\n");
    configure_tests();

    std::string command = argv[0];
    for (int index = 1; index != argc; index += 2) {
        std::string_view flag = argv[index], name = index + 1 != argc ? argv[index + 1] : "";
        if (name.empty()) flag = {};
        if (flag == "--backend") {
            backend_under_test = ucall_io_backend_from_name(view(argv[index + 1]));
            if (name != ucall_io_backend_name(backend_under_test)) {
                fmt::print(stderr, "Unknown backend {}\n", name);
                return 1;
            }
        }
        else if (flag == "--cpu-class") {
            cpu_class_under_test = ucall_cpu_class_from_name(view(argv[index + 1]));
            if (name != ucall_cpu_class_name(cpu_class_under_test)) {
                fmt::print(stderr, "Unknown CPU class {}\n", name);
                return 1;
            }
        }
        else {
            fmt::print(stderr, "Usage: {} [--backend <name>] [--cpu-class <name>]\n", argv[0]);
            return 1;
        }
        command = command + " " + argv[index] + " " + argv[index + 1];
    }
    fmt::print("  backend          {}\n", ucall_io_backend_name(backend_under_test));
    fmt::print("  CPU class        {}\n", ucall_cpu_class_name(cpu_class_under_test));
    ucall_client_t probe {};
    ucall_outcome_t outcome {};
    ucall_client_config_t config {};
    config.max_concurrent_connections = 1;
    config.backend = backend_under_test;
    ucall_client_init_t init {&probe, &outcome, &config, nullptr};
    ucall_client_init(&init);
    ucall_client_free(probe);
    if (outcome.status == ucall_status_unsupported_k) {
        fmt::print("The kernel lacks this backend, so every case skips\n");
        return 77;
    }

    suite_totals_t totals {.program = command.c_str()};
    run_test(totals, "test_exchanges_plain", test_exchanges_plain);
    run_test(totals, "test_exchanges_noise_xx", test_exchanges_noise_xx);
    run_test(totals, "test_exchanges_noise_ik", test_exchanges_noise_ik);
    run_test(totals, "test_multiloop_retention", test_multiloop_retention);
    run_test(totals, "test_cross_thread_replies_stress", test_cross_thread_replies_stress);
    run_test(totals, "test_pipelined_calls_plain", test_pipelined_calls_plain);
    run_test(totals, "test_pipelined_calls_noise_xx", test_pipelined_calls_noise_xx);
    run_test(totals, "test_pipelined_call_loss", test_pipelined_call_loss);
#if UCALL_OS_POSIX_
    run_test(totals, "test_pipelined_delivery", test_pipelined_delivery);
    run_test(totals, "test_fragmented_headers_delivery", test_fragmented_headers_delivery);
    run_test(totals, "test_megabyte_echo_delivery", test_megabyte_echo_delivery);
    run_test(totals, "test_smuggling_safety", test_smuggling_safety);
    run_test(totals, "test_header_lookup_unit", test_header_lookup_unit);
    run_test(totals, "test_admission_across_loops", test_admission_across_loops);
    run_test(totals, "test_engine_duplex_delivery", test_engine_duplex_delivery);
    if (backend_under_test == ucall_io_backend_automatic_k)
        run_test(totals, "test_backend_parity", test_backend_parity);
#endif
    return suite_exit_code(totals);
}
