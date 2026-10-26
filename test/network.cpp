/**
 *  @file test/network.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief C ABI loopback framing, connection reuse, shared admission, Noise authentication, engine
 *      duplex, and cross-thread teardown.
 *
 *  Every case runs against the backend `--backend` names, or the automatic one without it. Backend
 *  parity runs only in the automatic invocation, since it walks every backend the build carries.
 */
#include <cstdlib> // `std::quick_exit`
#include <cstring> // `std::memcmp`, `std::strlen`

#include <algorithm>   // `std::max`
#include <array>       // `std::array`
#include <atomic>      // `std::atomic`
#include <charconv>    // `std::from_chars`
#include <chrono>      // `std::chrono::steady_clock`
#include <functional>  // `std::function`
#include <future>      // `std::promise`
#include <mutex>       // `std::mutex`, `std::lock_guard`
#include <string>      // `std::string`
#include <string_view> // `std::string_view`
#include <thread>      // `std::thread`
#include <utility>     // `std::pair`, `std::exchange`
#include <vector>      // `std::vector`

#include "ucall/ucall.h"
#include "ucall/io.hpp"
#if UCALL_WITH_LINUX_URING
#include "ucall/uring612.hpp"
#include "ucall/uring700.hpp"
#endif

#include "harness.hpp" // `expect`, `require`, `run_test`, `raw_client_t`

namespace uc = unum::ucall;
using namespace unum::ucall::test;
using namespace std::chrono_literals;
using std::chrono::steady_clock;

/** The backend under test, which `--backend` names. */
static ucall_io_backend_t backend_under_test = ucall_io_backend_automatic_k;
static ucall_cpu_class_t cpu_class_under_test = ucall_cpu_class_unknown_k;

static ucall_status_t authorize(ucall_noise_key_t const* key, void* context) {
    return std::memcmp(*key, context, sizeof(ucall_noise_key_t)) == 0 ? ucall_status_success_k
                                                                      : ucall_status_peer_rejected_k;
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
 *  @brief A loopback server with echo, gated, header-lookup, and bodiless status routes, and a
 *      client to call it.
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

    /** The query parameter @p name of @p request, empty when absent. */
    std::string query(ucall_received_http_request_t request, std::string_view name) {
        ucall_outcome_t outcome {};
        ucall_bytes_view_t value {};
        ucall_server_request_query_parameter_t get {server, &outcome, request, uc::bytes_view(name), &value};
        ucall_server_request_query_parameter(&get);
        return outcome.status == ucall_status_success_k
                   ? std::string {reinterpret_cast<char const*>(value.data), value.length}
                   : std::string {};
    }
    std::uint64_t query_number(ucall_received_http_request_t request, std::string_view name) {
        std::string const text = query(request, name);
        std::uint64_t number = 0;
        std::from_chars(text.data(), text.data() + text.size(), number);
        return number;
    }

    /** Replies 201 with five parts, two of them empty, behind two headers. */
    static void vectored(ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<fixture_t*>(context);
        static std::string const middle(100 * 1024, 'v');
        ucall_bytes_view_t const headers[] {uc::bytes_view("X-UCall: passed"),
                                            uc::bytes_view("Content-Type: application/octet-stream")};
        ucall_bytes_view_t const parts[] {uc::bytes_view(""), uc::bytes_view("first|"), uc::bytes_view(middle),
                                          uc::bytes_view(""), uc::bytes_view("|last")};
        ucall_outcome_t outcome {};
        ucall_server_reply_vectored_t reply {fixture.server, &outcome, request, ucall_http_status_created_k,
                                             headers,        2,        parts,   5};
        ucall_server_reply_vectored(&reply);
        fixture.failures += expect(outcome.status == ucall_status_success_k, "vectored: {}",
                                   ucall_status_name(outcome.status));
    }

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
        ucall_bytes_view_t header = uc::bytes_view("X-UCall: passed");
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

    /** Replies with the path and what four lookups found, each followed by a semicolon. */
    static void lookup(ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<fixture_t*>(context);
        fixture.dispatched.fetch_add(1, std::memory_order_relaxed);
        ucall_outcome_t path_outcome {};
        ucall_bytes_view_t path {};
        ucall_server_request_path_t get_path {fixture.server, &path_outcome, request, &path};
        ucall_server_request_path(&get_path);
        fixture.failures += expect(path_outcome.status == ucall_status_success_k);
        std::string answer {reinterpret_cast<char const*>(path.data), path.length};
        answer += ';';
        for (std::string_view name : {"Content-TYPE", "X-~", "x-^", "X-Absent"}) {
            ucall_outcome_t outcome {};
            ucall_bytes_view_t value {};
            ucall_server_request_header_t get {fixture.server, &outcome, request, uc::bytes_view(name), &value};
            ucall_server_request_header(&get);
            if (outcome.status == ucall_status_success_k)
                answer.append(reinterpret_cast<char const*>(value.data), value.length);
            else answer += ucall_status_name(outcome.status);
            answer += ';';
        }
        ucall_outcome_t outcome {};
        ucall_server_reply_content_t reply {fixture.server, &outcome, request, nullptr, 0, uc::bytes_view(answer)};
        ucall_server_reply_content(&reply);
        fixture.failures += expect(outcome.status == ucall_status_success_k);
    }

    /** Replies with no body and the status the `{code}` segment names. */
    static void status_only(ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<fixture_t*>(context);
        fixture.dispatched.fetch_add(1, std::memory_order_relaxed);
        ucall_outcome_t outcome {};
        ucall_bytes_view_t code {};
        ucall_server_request_path_parameter_t get {fixture.server, &outcome, request, uc::bytes_view("code"), &code};
        ucall_server_request_path_parameter(&get);
        fixture.failures += expect(outcome.status == ucall_status_success_k);
        ucall_http_status_t status {};
        std::from_chars(reinterpret_cast<char const*>(code.data),
                        reinterpret_cast<char const*>(code.data) + code.length, status);
        ucall_server_reply_content_t reply {fixture.server, &outcome, request, nullptr, 0, {}, status};
        ucall_server_reply_content(&reply);
        fixture.failures += expect(outcome.status == ucall_status_success_k, "reply {}: {}", status,
                                   ucall_status_name(outcome.status));
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
        // A generated server key, and a derived client key the server must report as the peer's.
        ucall_outcome_t outcome {};
        ucall_noise_key_generate_t generate {&outcome, &server_private, &server_public};
        ucall_noise_key_generate(&generate);
        if ((status = outcome.status) != ucall_status_success_k) return;
        for (std::size_t i = 0; i != sizeof(client_private); ++i) client_private[i] = static_cast<ucall_byte_t>(i + 1);
        ucall_noise_key_derive_t derive {&outcome, &client_private, &client_public};
        ucall_noise_key_derive(&derive);
        if ((status = outcome.status) != ucall_status_success_k) return;
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
        ucall_server_init_t init {&server, &outcome, &config, &resolved};
        ucall_server_init(&init);
        if ((status = outcome.status) != ucall_status_success_k) return;
        using route_t = std::pair<char const*, ucall_received_http_request_callback_t>;
        for (auto [route, callback] :
             {route_t {"/echo/{id}", echo}, route_t {"/gate", gate}, route_t {"/headers", lookup},
              route_t {"/status/{code}", status_only}, route_t {"/vectored", vectored}}) {
            ucall_server_add_http_endpoint_t add {server,           &outcome, uc::bytes_view(route),
                                                  ucall_verb_any_k, callback, this};
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
        steady_clock::time_point const deadline = steady_clock::now() + 5s;
        ucall_completed_call_t completed {};
        while (!poll(completed))
            if (steady_clock::now() > deadline) {
                completed.outcome.status = ucall_status_timeout_k;
                break;
            }
        return completed;
    }
};

/** Checks a 200 response carries @p expected and the echo header, then frees it. */
static std::size_t check_response(ucall_received_http_response_t response, std::string_view expected) {
    std::size_t failures = 0;
    failures += expect(ucall_client_response_status(response) == ucall_http_status_ok_k);
    ucall_outcome_t outcome {};
    ucall_bytes_view_t body {}, header {};
    ucall_client_response_body_t get {response, &outcome, &body};
    ucall_client_response_body(&get);
    failures += expect(outcome.status == ucall_status_success_k && body.length == expected.size(),
                       "{} body bytes against {}", body.length, expected.size());
    failures += expect(body.length != expected.size() || !body.length ||
                       std::memcmp(body.data, expected.data(), body.length) == 0);
    ucall_client_response_header_t get_header {response, &outcome, uc::bytes_view("X-UCALL"), &header};
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
    call.url = uc::bytes_view(url);
    call.verb = ucall_verb_post_k;
    call.body = uc::bytes_view(payload);
    call.options.security = security;
    call.options.server_key = &fixture.server_public;
    auto exchange = [&](std::string_view expected) {
        ucall_client_call(&call);
        failures += expect(outcome.status == ucall_status_success_k);
        auto completed = fixture.wait();
        failures += expect(completed.outcome.status == ucall_status_success_k && completed.response, "{}",
                           ucall_status_name(completed.outcome.status));
        if (completed.response) failures += check_response(completed.response, expected);
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
        steady_clock::time_point const deadline = steady_clock::now() + 2s;
        ucall_completed_call_t completed {};
        auto copies = copies_beyond_receipt();
        while (copies - since < expected && steady_clock::now() < deadline) {
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
    call.url = uc::bytes_view(named_url);
    exchange(payload);
    announce("a closing call, then a fresh connection");
    call.url = uc::bytes_view(url);
    ucall_bytes_view_t close = uc::bytes_view("Connection: close");
    call.headers = &close;
    call.headers_count = 1;
    exchange(payload);
    announce("a response read after its client is freed");
    call.verb = ucall_verb_get_k;
    call.body = {};
    call.headers = nullptr;
    call.headers_count = 0;
    ucall_client_call(&call);
    failures += expect(outcome.status == ucall_status_success_k);
    auto completed = fixture.wait();
    ucall_client_free(std::exchange(fixture.client, nullptr));
    failures += expect(completed.outcome.status == ucall_status_success_k && completed.response, "{}",
                       ucall_status_name(completed.outcome.status));
    if (completed.response) failures += check_response(completed.response, {});
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
    call.url = uc::bytes_view(gate_url);
    call.verb = ucall_verb_post_k;
    call.context = &gate_url;
    ucall_client_call(&call);
    failures += expect(outcome.status == ucall_status_success_k);
    steady_clock::time_point const deadline = steady_clock::now() + 5s;
    ucall_received_http_request_t held {};
    while (!(held = fixture.take_held())) {
        ucall_completed_call_t completed {};
        failures += expect(!fixture.poll(completed));
        require(failures, steady_clock::now() < deadline, "the gated request never arrived");
    }
    call.url = uc::bytes_view(echo_url);
    call.context = &echo_url;
    ucall_client_call(&call);
    failures += expect(outcome.status == ucall_status_success_k);
    auto completed = fixture.wait();
    failures += expect(completed.context == &echo_url && completed.outcome.status == ucall_status_success_k);
    if (completed.response) failures += check_response(completed.response, {});
    fixture.reply_echo(held);
    completed = fixture.wait();
    failures += expect(completed.context == &gate_url && completed.outcome.status == ucall_status_success_k);
    if (completed.response) failures += check_response(completed.response, {});
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
            call.url = uc::bytes_view(gate_url);
            call.verb = ucall_verb_post_k;
            call.body = uc::bytes_view(bodies[i]);
            call.context = &bodies[i];
            ucall_client_call(&call);
            failures += expect(outcome.status == ucall_status_success_k);
        }
        for (std::size_t i = 0; i != threads_count; ++i) {
            auto completed = fixture.wait();
            failures += expect(completed.outcome.status == ucall_status_success_k && completed.response, "round {}: {}",
                               round, ucall_status_name(completed.outcome.status));
            if (!completed.response) break;
            failures += check_response(completed.response, *static_cast<std::string*>(completed.context));
        }
    }
    finished.store(true, std::memory_order_release);
    for (auto& replier : repliers) replier.join();
    return failures + fixture.stop();
}

/** Polls until the `/gate` route holds @p count requests, with no call completing meanwhile. */
static std::size_t await_held(fixture_t& fixture, std::size_t count) {
    std::size_t failures = 0;
    steady_clock::time_point const deadline = steady_clock::now() + 5s;
    while (fixture.held_count() != count && !failures) {
        ucall_completed_call_t completed {};
        failures += expect(!fixture.poll(completed), "a call completed early");
        failures += expect(steady_clock::now() < deadline, "the server holds {} of {} requests", fixture.held_count(),
                           count);
    }
    return failures;
}

/** Eight idempotent calls at depth four share one connection: the server holds four at once,
 *  which lockstep calls never reach, and the responses to replies given in reverse complete in
 *  call order. */
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
        call.url = uc::bytes_view(gate_url);
        call.verb = ucall_verb_put_k;
        call.body = uc::bytes_view(bodies[i]);
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
            if (completed.response) failures += check_response(completed.response, bodies[next]);
        }
    }
    return failures + fixture.stop();
}

static case_result_t test_pipelined_calls_plain() { return pipelined_calls(ucall_security_mode_none_k); }
static case_result_t test_pipelined_calls_noise_xx() { return pipelined_calls(ucall_security_mode_noise_xx_k); }

/** A caller's `Connection: close` on the second call keeps the POST and GET behind it off that
 *  connection: both wait for the next one and are answered there. */
static case_result_t test_pipelined_call_loss() {
    fixture_t fixture {{.pipelined_requests = 4, .pipelined_calls = 4}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    std::string const gate_url = fixture.url + "/gate", post_url = fixture.url + "/echo/3",
                      get_url = fixture.url + "/echo/4";
    ucall_bytes_view_t const close = uc::bytes_view("Connection: close");
    struct planned_call_t {
        std::string const* url;
        ucall_verb_t verb;
        ucall_status_t expected;
    };
    std::array<planned_call_t, 4> plan {{{&gate_url, ucall_verb_get_k, ucall_status_success_k},
                                         {&gate_url, ucall_verb_get_k, ucall_status_success_k},
                                         {&post_url, ucall_verb_post_k, ucall_status_success_k},
                                         {&get_url, ucall_verb_get_k, ucall_status_success_k}}};
    for (auto& planned : plan) {
        ucall_outcome_t outcome {};
        ucall_client_call_t call {};
        call.client = fixture.client;
        call.outcome = &outcome;
        call.url = uc::bytes_view(*planned.url);
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
    // Neither call behind the closing one leaves before its response.
    for (steady_clock::time_point const settled = steady_clock::now() + 100ms; steady_clock::now() < settled;) {
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
        if (completed.response) failures += check_response(completed.response, {});
    }
    failures += expect(fixture.dispatched.load() == 2, "{} echo requests were dispatched", fixture.dispatched.load());
    return failures + fixture.stop();
}

/** 204 and 304 replies, which UCall sends without `content-length`, keep the connection: calls
 *  pipelined ahead of and behind them all complete over the one connection the server accepted. */
static case_result_t test_bodiless_responses_keep_connection() {
    fixture_t fixture {{.pipelined_requests = 4, .pipelined_calls = 4}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    struct planned_status_t {
        std::string url;
        ucall_http_status_t expected;
    };
    std::array<planned_status_t, 5> plan {{{fixture.url + "/echo/1", ucall_http_status_ok_k},
                                           {fixture.url + "/status/204", ucall_http_status_no_content_k},
                                           {fixture.url + "/echo/2", ucall_http_status_ok_k},
                                           {fixture.url + "/status/304", ucall_http_status_not_modified_k},
                                           {fixture.url + "/echo/3", ucall_http_status_ok_k}}};
    ucall_outcome_t outcome {};
    for (auto& planned : plan) {
        ucall_client_call_t call {};
        call.client = fixture.client;
        call.outcome = &outcome;
        call.url = uc::bytes_view(planned.url);
        call.verb = ucall_verb_get_k;
        call.context = &planned;
        ucall_client_call(&call);
        failures += expect(outcome.status == ucall_status_success_k);
    }
    for (auto const& planned : plan) {
        auto completed = fixture.wait();
        failures += expect(completed.context == &planned && completed.response &&
                               ucall_client_response_status(completed.response) == planned.expected,
                           "call {} completed {}: {}", &planned - plan.data(),
                           static_cast<planned_status_t const*>(completed.context) - plan.data(),
                           ucall_status_name(completed.outcome.status));
        if (completed.response) ucall_client_response_free(completed.response);
    }
    ucall_event_loop_statistics_t counters {};
    ucall_server_event_loop_statistics_t query {fixture.server, &outcome, 0, &counters};
    ucall_server_event_loop_statistics(&query);
    failures += expect(counters.accepts == 1, "the server accepted {} connections", counters.accepts);
    return failures + fixture.stop();
}

/** Calls @p target with @p verb, then waits for the completion, whose response the caller frees. */
static ucall_completed_call_t call_and_wait(fixture_t& fixture, ucall_verb_t verb, std::string_view target,
                                            ucall_security_mode_t security, std::size_t& failures) {
    std::string const url = fixture.url + std::string {target};
    ucall_outcome_t outcome {};
    ucall_client_call_t call {};
    call.client = fixture.client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(url);
    call.verb = verb;
    call.options.security = security;
    call.options.server_key = &fixture.server_public;
    ucall_client_call(&call);
    failures += expect(outcome.status == ucall_status_success_k, "call: {}", ucall_status_name(outcome.status));
    auto completed = fixture.wait();
    failures += expect(completed.outcome.status == ucall_status_success_k && completed.response, "{}: {}", target,
                       ucall_status_name(completed.outcome.status));
    return completed;
}
static std::string_view response_body(ucall_received_http_response_t response) {
    ucall_outcome_t outcome {};
    ucall_bytes_view_t body {};
    ucall_client_response_body_t get {response, &outcome, &body};
    ucall_client_response_body(&get);
    return {reinterpret_cast<char const*>(body.data), body.length};
}
static std::string_view response_header(ucall_received_http_response_t response, std::string_view name) {
    ucall_outcome_t outcome {};
    ucall_bytes_view_t value {};
    ucall_client_response_header_t get {response, &outcome, uc::bytes_view(name), &value};
    ucall_client_response_header(&get);
    return {reinterpret_cast<char const*>(value.data), value.length};
}

/** Checks @p completed answered @p status with @p body, then frees its response. */
static std::size_t check_answer(ucall_completed_call_t const& completed, ucall_http_status_t status,
                                std::string_view body) {
    if (!completed.response) return 1;
    std::size_t failures = 0;
    auto const answered = response_body(completed.response);
    failures += expect(ucall_client_response_status(completed.response) == status, "answered {} rather than {}",
                       ucall_client_response_status(completed.response), status);
    failures += expect(answered == body, "a {}-byte body rather than {} bytes", answered.size(), body.size());
    ucall_client_response_free(completed.response);
    return failures;
}

/** The body `stream_reply` sends as @p count chunks of growing, labelled sizes. */
static std::vector<std::string> stream_chunks(std::size_t count, char label) {
    std::vector<std::string> chunks;
    for (std::size_t i = 0; i != count; ++i)
        chunks.push_back(fmt::format("{}{}:", label, i) + std::string(i * 37, label));
    return chunks;
}

/** Streams @p chunks to @p request from the calling thread, retrying a chunk the socket lags
 *  behind, and answers how many checks failed, expecting @p ended from the end. */
static std::size_t stream_reply(ucall_server_t server, ucall_received_http_request_t request,
                                std::vector<std::string> const& chunks, std::vector<ucall_bytes_view_t> headers = {},
                                ucall_status_t ended = ucall_status_success_k) {
    std::size_t failures = 0;
    ucall_outcome_t outcome {};
    ucall_server_reply_begin_t begin {server, &outcome, request, 0, headers.data(), headers.size()};
    ucall_server_reply_begin(&begin);
    failures += expect(outcome.status == ucall_status_success_k, "begin: {}", ucall_status_name(outcome.status));
    for (auto const& chunk : chunks) {
        ucall_server_reply_chunk_t append {server, &outcome, request, uc::bytes_view(chunk)};
        for (ucall_server_reply_chunk(&append); outcome.status == ucall_status_would_block_k;
             ucall_server_reply_chunk(&append))
            std::this_thread::sleep_for(100us);
        failures += expect(outcome.status == ucall_status_success_k, "chunk: {}", ucall_status_name(outcome.status));
    }
    ucall_server_reply_end_t end {server, &outcome, request};
    ucall_server_reply_end(&end);
    failures += expect(outcome.status == ended, "end: {}", ucall_status_name(outcome.status));
    return failures;
}
static std::string joined(std::vector<std::string> const& chunks) {
    std::string whole;
    for (auto const& chunk : chunks) whole += chunk;
    return whole;
}

/** Five parts, two of them empty, arrive concatenated under the status and headers given, and a
 *  @c HEAD request gets the same head without a body. */
static case_result_t reply_vectored(ucall_security_mode_t security) {
    fixture_t fixture {{.security = security}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    std::string const expected = "first|" + std::string(100 * 1024, 'v') + "|last";
    auto completed = call_and_wait(fixture, ucall_verb_get_k, "/vectored", security, failures);
    if (completed.response) {
        failures += expect(response_header(completed.response, "x-ucall") == "passed");
        failures += expect(response_header(completed.response, "content-type") == "application/octet-stream");
    }
    failures += check_answer(completed, ucall_http_status_created_k, expected);
    completed = call_and_wait(fixture, ucall_verb_head_k, "/vectored", security, failures);
    if (completed.response)
        failures += expect(response_header(completed.response, "content-length") == std::to_string(expected.size()));
    failures += check_answer(completed, ucall_http_status_created_k, {});
    return failures + fixture.stop();
}
static case_result_t test_reply_vectored_plain() { return reply_vectored(ucall_security_mode_none_k); }
static case_result_t test_reply_vectored_noise_xx() { return reply_vectored(ucall_security_mode_noise_xx_k); }

/** An application thread streams a reply of many chunks long after the callback returned, while
 *  this thread polls, and the client reads the chunked body whole. */
static case_result_t streamed_reply(ucall_security_mode_t security) {
    fixture_t fixture {{.security = security}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    std::string const url = fixture.url + "/gate";
    ucall_outcome_t outcome {};
    ucall_client_call_t call {};
    call.client = fixture.client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(url);
    call.verb = ucall_verb_get_k;
    call.options.security = security;
    call.options.server_key = &fixture.server_public;
    ucall_client_call(&call);
    failures += await_held(fixture, 1);
    auto const chunks = stream_chunks(300, 's');
    std::atomic<std::size_t> streamed_failures {};
    std::thread streamer {
        [&, request = fixture.take_held()] { streamed_failures += stream_reply(fixture.server, request, chunks); }};
    auto completed = fixture.wait();
    streamer.join();
    failures += streamed_failures.load();
    if (completed.response) failures += expect(response_header(completed.response, "transfer-encoding") == "chunked");
    failures += check_answer(completed, ucall_http_status_ok_k, joined(chunks));
    return failures + fixture.stop();
}
static case_result_t test_streamed_reply_plain() { return streamed_reply(ucall_security_mode_none_k); }
static case_result_t test_streamed_reply_noise_xx() { return streamed_reply(ucall_security_mode_noise_xx_k); }

/** Two threads stream to two requests pipelined on one connection at once, the second thread
 *  starting first, and both replies arrive whole and in request order. */
static case_result_t pipelined_streams(ucall_security_mode_t security) {
    fixture_t fixture {{.security = security, .pipelined_requests = 2, .pipelined_calls = 2}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    std::array<std::string, 2> urls {fixture.url + "/gate?n=0", fixture.url + "/gate?n=1"};
    std::array<std::vector<std::string>, 2> const chunks {stream_chunks(200, 'a'), stream_chunks(250, 'b')};
    for (auto& url : urls) {
        ucall_outcome_t outcome {};
        ucall_client_call_t call {};
        call.client = fixture.client;
        call.outcome = &outcome;
        call.url = uc::bytes_view(url);
        call.verb = ucall_verb_get_k;
        call.context = &url;
        call.options.security = security;
        call.options.server_key = &fixture.server_public;
        ucall_client_call(&call);
        failures += expect(outcome.status == ucall_status_success_k);
    }
    failures += await_held(fixture, 2);
    std::array<ucall_received_http_request_t, 2> requests {};
    while (auto request = fixture.take_held()) requests[fixture.query_number(request, "n")] = request;
    std::atomic<std::size_t> streamed_failures {};
    std::thread later {[&] { streamed_failures += stream_reply(fixture.server, requests[1], chunks[1]); }};
    std::thread earlier {[&] { streamed_failures += stream_reply(fixture.server, requests[0], chunks[0]); }};
    for (std::size_t i = 0; i != 2; ++i) {
        auto completed = fixture.wait();
        failures += expect(completed.context == &urls[i], "call {} completed out of order", i);
        failures += check_answer(completed, ucall_http_status_ok_k, joined(chunks[i]));
    }
    later.join();
    earlier.join();
    failures += streamed_failures.load();
    ucall_outcome_t outcome {};
    ucall_event_loop_statistics_t counters {};
    ucall_server_event_loop_statistics_t query {fixture.server, &outcome, 0, &counters};
    ucall_server_event_loop_statistics(&query);
    failures += expect(counters.accepts == 1, "the server accepted {} connections", counters.accepts);
    return failures + fixture.stop();
}
static case_result_t test_pipelined_streams_plain() { return pipelined_streams(ucall_security_mode_none_k); }
static case_result_t test_pipelined_streams_noise_xx() { return pipelined_streams(ucall_security_mode_noise_xx_k); }

/** @c HEAD on a vectored and two streamed replies answers each head with no body, and the @c GET
 *  behind each on the same connection still parses. */
static case_result_t test_head_replies() {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    auto security = ucall_security_mode_none_k;
    auto completed = call_and_wait(fixture, ucall_verb_head_k, "/vectored", security, failures);
    if (completed.response)
        failures += expect(!response_header(completed.response, "content-length").empty(), "no content-length");
    failures += check_answer(completed, ucall_http_status_created_k, {});
    completed = call_and_wait(fixture, ucall_verb_get_k, "/echo/1", security, failures);
    failures += check_answer(completed, ucall_http_status_ok_k, {});
    std::string const url = fixture.url + "/gate";
    auto const chunks = stream_chunks(20, 'h');
    std::string const length = fmt::format("Content-Length: {}", joined(chunks).size());
    for (std::vector<ucall_bytes_view_t> headers :
         {std::vector<ucall_bytes_view_t> {}, std::vector<ucall_bytes_view_t> {uc::bytes_view(length)}}) {
        announce("HEAD on a stream with {} headers", headers.size());
        ucall_outcome_t outcome {};
        ucall_client_call_t call {};
        call.client = fixture.client;
        call.outcome = &outcome;
        call.url = uc::bytes_view(url);
        call.verb = ucall_verb_head_k;
        ucall_client_call(&call);
        failures += await_held(fixture, 1);
        failures += stream_reply(fixture.server, fixture.take_held(), chunks, headers);
        completed = fixture.wait();
        failures += check_answer(completed, ucall_http_status_ok_k, {});
        completed = call_and_wait(fixture, ucall_verb_get_k, "/echo/1", security, failures);
        failures += check_answer(completed, ucall_http_status_ok_k, {});
    }
    ucall_outcome_t outcome {};
    ucall_event_loop_statistics_t counters {};
    ucall_server_event_loop_statistics_t query {fixture.server, &outcome, 0, &counters};
    ucall_server_event_loop_statistics(&query);
    failures += expect(counters.accepts == 1, "the server accepted {} connections", counters.accepts);
    return failures + fixture.stop();
}

#pragma endregion Library Clients

#pragma region Raw Clients
#if UCALL_OS_POSIX_

/** Sends @p request whole, reads until the server closes in order, never with a reset, and
 *  answers the first response. */
static wire_response_t exchange_until_close(raw_client_t& client, std::string_view request, std::size_t max_chunk,
                                            random_generator_t& generator, std::size_t& failures) {
    steady_clock::time_point const deadline = steady_clock::now() + 10s;
    failures += expect(client.write(uc::byte_span(request), max_chunk, generator, deadline),
                       "the server stopped reading");
    auto const end = client.read_until_close(deadline);
    int const error = end == read_end_t::failed_k ? errno : 0;
    auto const response = parse_response(client.received);
    failures += expect(end == read_end_t::closed_k && response.length, "the read ended as {} after {} bytes, errno {}",
                       static_cast<int>(end), client.received.size(), error);
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
    auto const end = client.read_until_close(steady_clock::now() + 10s);
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
static case_result_t test_fragmented_headers_delivery(random_generator_t& generator) {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t client;
    require(failures, client.connect(fixture.address));
    auto const response = exchange_until_close(
        client, "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody", 1, generator,
        failures);
    failures += expect(response.status == 200 && response.body == "body", "answered {} {}", response.status,
                       response.body);
    return failures + fixture.stop();
}

/** A mebibyte body sent in random fragments echoes back byte for byte, in full-length sends. */
static case_result_t test_megabyte_echo_delivery(random_generator_t& generator) {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    std::size_t const body_length = std::size_t {1} << 20;
    std::string request = fmt::format(
        "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body_length);
    std::size_t const headers_length = request.size();
    for (std::size_t i = 0; i != body_length; ++i) request.push_back(static_cast<char>(generator()));
    raw_client_t client;
    require(failures, client.connect(fixture.address));
    auto const response = exchange_until_close(client, request, 65536, generator, failures);
    failures += expect(response.status == 200, "answered {}", response.status);
    failures += expect_bytes(uc::byte_span(response.body),
                             uc::byte_span(std::string_view {request}.substr(headers_length)));
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
    {"length past size_t", "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 18446744073709551615\r\n\r\nbody", 413},
};

/** Every smuggling row is answered with an error status and an orderly close, and never
 *  dispatched, though the client keeps sending far past one receive after the row. */
static case_result_t test_smuggling_safety(random_generator_t& generator) {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    // Past what any engine reads ahead, so a server closing without lingering leaves bytes unread.
    std::string const unread(std::size_t {64} << 10, 'x');
    for (auto const& row : smuggling_rows_k) {
        announce("{}", row.name);
        auto const dispatched = fixture.dispatched.load();
        raw_client_t client;
        require(failures, client.connect(fixture.address));
        failures += expect(client.write(uc::byte_span(row.request), 0, generator, steady_clock::now() + 5s),
                           "{} was cut short", row.name);
        auto const response = exchange_until_close(client, unread, 4096, generator, failures);
        failures += expect(response.status == row.expected_status && response.length == client.received.size(),
                           "{} answered {} bytes: {:?}", row.name, client.received.size(), client.received);
        failures += expect(fixture.dispatched.load() == dispatched, "{} was dispatched", row.name);
    }
    return failures + fixture.stop();
}

/** Paths keep their slashes and drop the query, and header names match without regard to letter
 *  case, where only letters fold. */
static case_result_t test_header_lookup_unit(random_generator_t& generator) {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t client;
    require(failures, client.connect(fixture.address));
    std::string_view const request = "GET //headers?x=1 HTTP/1.1\r\nHost: a\r\nContent-Type: text/plain\r\n"
                                     "X-~: tilde\r\nConnection: close\r\n\r\n";
    auto const response = exchange_until_close(client, request, 8, generator, failures);
    // `^` and `~` differ only in the bit that folds ASCII letters.
    failures += expect(response.body == "//headers;text/plain;tilde;not-found;not-found;", "answered {} {}",
                       response.status, response.body);
    return failures + fixture.stop();
}

/** Frees a server from a thread other than its poller while a keep-alive peer stays connected.
 *  An engine stopped off its poller hangs there, or leaks its ring storage under LeakSanitizer. */
static case_result_t test_cross_thread_teardown_delivery(random_generator_t& generator) {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t client;
    require(failures, client.connect(fixture.address));
    std::string_view const request = "GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n";
    failures += expect(client.write(uc::byte_span(request), 0, generator, steady_clock::now() + 5s));
    failures += expect(read_response(client, 0).status == 200, "the keep-alive request was not served");
    failures += fixture.stop();
    // A hang here is the failure, so a stuck free ends the process instead of the case.
    std::promise<void> freed;
    auto finished = freed.get_future();
    std::thread {[&freed, server = std::exchange(fixture.server, nullptr)] {
        ucall_server_free(server);
        freed.set_value();
    }}.detach();
    if (finished.wait_for(std::chrono::seconds {5}) != std::future_status::ready) {
        std::fputs("ucall_server_free blocked on a ring its poller had issued\n", stderr);
        std::quick_exit(EXIT_FAILURE);
    }
    return failures;
}

/** Two loops share a budget of two: a third client waits in the backlog until one closes. */
static case_result_t test_admission_across_loops(random_generator_t& generator) {
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
        failures += expect(clients[i].write(uc::byte_span(request), 0, generator, steady_clock::now() + 5s));
        if (i != 2) failures += expect(read_response(clients[i], 0).status == 200, "client {} was not served", i);
    }
    failures += expect(clients[2].read(1, steady_clock::now() + 300ms) == read_end_t::timed_out_k,
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
static case_result_t test_backend_parity(random_generator_t& generator) {
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
            failures += expect(client.write(uc::byte_span(request), 16, generator, steady_clock::now() + 5s));
            offset += read_response(client, offset).length;
        }
        exchange_until_close(client,
                             "POST /echo/3 HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\nleft"
                             "POST /echo/4 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nConnection: close\r\n\r\nright",
                             0, generator, failures);
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

/** Waits until the background loops hold @p count requests at `/gate`. */
static std::size_t await_held_in_background(fixture_t& fixture, std::size_t count) {
    steady_clock::time_point const deadline = steady_clock::now() + 5s;
    while (fixture.held_count() != count && steady_clock::now() < deadline) std::this_thread::sleep_for(1ms);
    return expect(fixture.held_count() == count, "the server holds {} of {} requests", fixture.held_count(), count);
}

/** Chunks outrunning a peer that reads nothing report @c ucall_status_would_block_k, and once the
 *  peer reads, the retried rest completes a body of the declared length byte for byte. */
static case_result_t test_streamed_reply_would_block() {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t client;
    require(failures, client.connect(fixture.address));
    std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
    failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                       static_cast<ssize_t>(request.size()));
    failures += await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    require(failures + fixture.stop(), held);
    std::size_t const chunk_length = 64 * 1024, chunks_count = 512;
    std::string chunk(chunk_length, '\0');
    std::string const length = fmt::format("Content-Length: {}", chunk_length * chunks_count);
    ucall_bytes_view_t const header = uc::bytes_view(length);
    ucall_outcome_t outcome {};
    ucall_server_reply_begin_t begin {fixture.server, &outcome, held, 0, &header, 1};
    ucall_server_reply_begin(&begin);
    failures += expect(outcome.status == ucall_status_success_k, "begin: {}", ucall_status_name(outcome.status));
    auto fill = [&](std::size_t index) {
        for (std::size_t i = 0; i != chunk_length; ++i) chunk[i] = static_cast<char>('a' + (index + i) % 26);
    };
    std::size_t queued = 0;
    for (; queued != chunks_count; ++queued) {
        fill(queued);
        ucall_server_reply_chunk_t append {fixture.server, &outcome, held, uc::bytes_view(chunk)};
        ucall_server_reply_chunk(&append);
        if (outcome.status == ucall_status_would_block_k) break;
        failures += expect(outcome.status == ucall_status_success_k, "chunk: {}", ucall_status_name(outcome.status));
    }
    failures += expect(queued != chunks_count, "every chunk queued while the peer read nothing");
    std::atomic<std::size_t> read_failures {};
    std::thread reader {[&] {
        auto const response = read_response(client, 0);
        read_failures += expect(response.status == 200 && response.body.size() == chunk_length * chunks_count,
                                "read {} with {} body bytes", response.status, response.body.size());
        for (std::size_t index = 0; index != chunks_count && response.body.size() == chunk_length * chunks_count;
             ++index)
            if (response.body[index * chunk_length] != static_cast<char>('a' + index % 26)) {
                read_failures += expect(false, "chunk {} arrived corrupted", index);
                break;
            }
    }};
    for (; queued != chunks_count; ++queued) {
        fill(queued);
        ucall_server_reply_chunk_t append {fixture.server, &outcome, held, uc::bytes_view(chunk)};
        for (ucall_server_reply_chunk(&append); outcome.status == ucall_status_would_block_k;
             ucall_server_reply_chunk(&append))
            std::this_thread::sleep_for(100us);
        failures += expect(outcome.status == ucall_status_success_k, "chunk: {}", ucall_status_name(outcome.status));
    }
    ucall_server_reply_end_t end {fixture.server, &outcome, held};
    ucall_server_reply_end(&end);
    failures += expect(outcome.status == ucall_status_success_k, "end: {}", ucall_status_name(outcome.status));
    reader.join();
    return failures + read_failures.load() + fixture.stop();
}

/** A peer leaving mid-stream turns later chunks and the end into
 *  @c ucall_status_connection_closed_k, and the server goes on answering others. */
static case_result_t test_streamed_reply_detach() {
    fixture_t fixture {{.connections = 2}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t client;
    require(failures, client.connect(fixture.address));
    std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
    failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                       static_cast<ssize_t>(request.size()));
    failures += await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    require(failures + fixture.stop(), held);
    ucall_outcome_t outcome {};
    ucall_server_reply_begin_t begin {fixture.server, &outcome, held, 0, nullptr, 0};
    ucall_server_reply_begin(&begin);
    failures += expect(outcome.status == ucall_status_success_k, "begin: {}", ucall_status_name(outcome.status));
    std::string const chunk(4096, 'd');
    ucall_server_reply_chunk_t append {fixture.server, &outcome, held, uc::bytes_view(chunk)};
    ucall_server_reply_chunk(&append);
    failures += expect(outcome.status == ucall_status_success_k, "chunk: {}", ucall_status_name(outcome.status));
    client.close();
    steady_clock::time_point const deadline = steady_clock::now() + 5s;
    do {
        std::this_thread::sleep_for(1ms);
        ucall_server_reply_chunk(&append);
    } while (outcome.status != ucall_status_connection_closed_k && steady_clock::now() < deadline);
    failures += expect(outcome.status == ucall_status_connection_closed_k, "chunk after the close: {}",
                       ucall_status_name(outcome.status));
    ucall_server_reply_end_t end {fixture.server, &outcome, held};
    ucall_server_reply_end(&end);
    failures += expect(outcome.status == ucall_status_connection_closed_k, "end: {}",
                       ucall_status_name(outcome.status));
    raw_client_t other;
    require(failures + fixture.stop(), other.connect(fixture.address));
    std::string_view const echo = "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nok";
    failures += expect(::send(other.descriptor, echo.data(), echo.size(), 0) == static_cast<ssize_t>(echo.size()));
    auto const response = read_response(other, 0);
    failures += expect(response.status == 200 && response.body == "ok", "answered {} {}", response.status,
                       response.body);
    return failures + fixture.stop();
}

/** An HTTP/1.0 peer gets a streamed body delimited by the close, with no framing field. */
static case_result_t test_streamed_reply_http10() {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t client;
    require(failures, client.connect(fixture.address));
    std::string_view const request = "GET /gate HTTP/1.0\r\nConnection: keep-alive\r\n\r\n";
    failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                       static_cast<ssize_t>(request.size()));
    failures += await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    require(failures + fixture.stop(), held);
    auto const chunks = stream_chunks(50, 'c');
    failures += stream_reply(fixture.server, held, chunks);
    auto const end = client.read_until_close(steady_clock::now() + 5s);
    failures += expect(end == read_end_t::closed_k, "the read ended as {}", static_cast<int>(end));
    std::string_view const wire = client.received;
    auto const headers_end = wire.find("\r\n\r\n");
    require(failures + fixture.stop(), headers_end != std::string_view::npos);
    auto const headers = wire.substr(0, headers_end);
    failures += expect(headers.starts_with("HTTP/1.1 200 OK\r\n"));
    failures += expect(headers.find("connection: close") != std::string_view::npos);
    failures += expect(headers.find("content-length") == std::string_view::npos &&
                           headers.find("transfer-encoding") == std::string_view::npos,
                       "framed head: {}", headers);
    failures += expect(wire.substr(headers_end + 4) == joined(chunks), "{} body bytes", wire.size() - headers_end - 4);
    return failures + fixture.stop();
}

/** A declared `content-length` frames chunks as identity, refuses a chunk running past it, and an
 *  end short of it reports @c ucall_status_malformed_k and closes after the bytes sent. */
static case_result_t test_streamed_reply_identity() {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t client;
    require(failures, client.connect(fixture.address));
    std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
    ucall_bytes_view_t const header = uc::bytes_view("Content-Length: 10");
    auto send_and_take = [&] {
        failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                           static_cast<ssize_t>(request.size()));
        failures += await_held_in_background(fixture, 1);
        return fixture.take_held();
    };
    ucall_outcome_t outcome {};
    auto chunk = [&](ucall_received_http_request_t held, std::string_view data) {
        ucall_server_reply_chunk_t append {fixture.server, &outcome, held, uc::bytes_view(data)};
        ucall_server_reply_chunk(&append);
        return outcome.status;
    };
    auto* held = send_and_take();
    require(failures + fixture.stop(), held);
    ucall_server_reply_begin_t begin {fixture.server, &outcome, held, 0, &header, 1};
    ucall_server_reply_begin(&begin);
    failures += expect(outcome.status == ucall_status_success_k, "begin: {}", ucall_status_name(outcome.status));
    failures += expect(chunk(held, "hello") == ucall_status_success_k);
    failures += expect(chunk(held, "worldwide!") == ucall_status_overflow_k, "past the length: {}",
                       ucall_status_name(outcome.status));
    failures += expect(chunk(held, "world") == ucall_status_success_k);
    ucall_server_reply_end_t end {fixture.server, &outcome, held};
    ucall_server_reply_end(&end);
    failures += expect(outcome.status == ucall_status_success_k, "end: {}", ucall_status_name(outcome.status));
    auto const response = read_response(client, 0);
    failures += expect(response.status == 200 && response.body == "helloworld", "answered {} {}", response.status,
                       response.body);
    held = send_and_take();
    require(failures + fixture.stop(), held);
    begin.request = held;
    ucall_server_reply_begin(&begin);
    failures += expect(chunk(held, "short") == ucall_status_success_k);
    end.request = held;
    ucall_server_reply_end(&end);
    failures += expect(outcome.status == ucall_status_malformed_k, "a short end: {}",
                       ucall_status_name(outcome.status));
    auto const closed = client.read_until_close(steady_clock::now() + 5s);
    failures += expect(closed == read_end_t::closed_k, "the read ended as {}", static_cast<int>(closed));
    failures += expect(std::string_view {client.received}.substr(response.length).ends_with("\r\n\r\nshort"),
                       "the cut reply: {}", std::string_view {client.received}.substr(response.length));
    return failures + fixture.stop();
}

#endif // UCALL_OS_POSIX_
#pragma endregion Raw Clients

#pragma region Scripted Servers
#if UCALL_OS_POSIX_

/** The length of the first whole request in @p wire, framed by its `content-length`, or zero. */
static std::size_t request_length(std::string_view wire) {
    auto const headers_end = wire.find("\r\n\r\n");
    if (headers_end == std::string_view::npos) return 0;
    std::size_t body_length = 0;
    if (auto field = wire.substr(0, headers_end + 2).find("\r\ncontent-length: "); field != std::string_view::npos)
        std::from_chars(wire.data() + field + 18, wire.data() + headers_end, body_length);
    std::size_t const length = headers_end + 4 + body_length;
    return wire.size() >= length ? length : 0;
}

static std::size_t whole_requests(std::string_view wire) {
    std::size_t count = 0;
    for (std::size_t length; (length = request_length(wire)); wire.remove_prefix(length)) ++count;
    return count;
}

/** The target of @p request, between its verb and its version. */
static std::string_view request_target(std::string_view request) {
    auto const start = request.find(' ') + 1;
    return request.substr(start, request.find(' ', start) - start);
}

/** What a scripted server does with a connection once it has written an answer. */
enum class after_answer_t { keep_open_k, close_k };

struct scripted_answer_t {
    std::string bytes {};
    after_answer_t after = after_answer_t::keep_open_k;
};

/** A 200 carrying @p body, announcing `connection: close` when @p after closes. */
static scripted_answer_t answer_ok(std::string_view body, after_answer_t after = after_answer_t::keep_open_k) {
    return {fmt::format("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n{}\r\n{}", body.size(),
                        after == after_answer_t::close_k ? "connection: close\r\n" : "", body),
            after};
}

/**
 *  @brief A loopback server thread that answers each whole request as its script says, for cases
 *      whose server behaves in ways UCall's own never does.
 *
 *  It serves one connection at a time. Once a request arrives it waits @c pause for any the client
 *  pipelines behind it. After an answer that closes, it shuts its side and drains the client until
 *  it closes too, so the close is never a reset.
 */
struct scripted_server_t {
    using script_t =
        std::function<scripted_answer_t(std::string_view request, std::size_t connection, std::size_t index)>;
    raw_listener_t listener;
    script_t script;
    std::chrono::milliseconds pause {};
    random_generator_t generator;

    /** Whole requests read on each connection, in accept order; read them after @c stop. */
    std::vector<std::size_t> requests_per_connection;

    /** The most requests read and not yet answered at once; read it after @c stop. */
    std::size_t deepest = 0;

    std::atomic<bool> stopping {false};
    std::thread thread;

    scripted_server_t(random_generator_t& seeds, script_t script, std::chrono::milliseconds pause = {})
        : script(std::move(script)), pause(pause), generator(seeds()) {
        if (!listener.address.empty()) thread = std::thread {[this] { serve(); }};
    }
    ~scripted_server_t() { stop(); }

    std::string url(std::string_view target) const { return "http://" + listener.address + std::string {target}; }

    void stop() {
        stopping.store(true, std::memory_order_release);
        if (thread.joinable()) thread.join();
    }

    void serve() {
        auto running = [&] { return !stopping.load(std::memory_order_acquire); };
        while (running()) {
            raw_client_t peer;
            if (!listener.accept(peer, steady_clock::now() + 20ms)) continue;
            std::size_t const connection = requests_per_connection.size();
            requests_per_connection.push_back(0);
            std::size_t answered_bytes = 0, answered = 0;
            for (bool open = true; open && running();) {
                if (!request_length(std::string_view {peer.received}.substr(answered_bytes))) {
                    auto const end = peer.read(peer.received.size() + 1, steady_clock::now() + 20ms);
                    open = end == read_end_t::filled_k || end == read_end_t::timed_out_k;
                    continue;
                }
                for (auto const until = steady_clock::now() + pause;
                     peer.read(peer.received.size() + 1, until) == read_end_t::filled_k;) {}
                deepest = std::max(deepest, whole_requests(std::string_view {peer.received}.substr(answered_bytes)));
                for (std::size_t length;
                     open && (length = request_length(std::string_view {peer.received}.substr(answered_bytes)));) {
                    auto const answer = script(std::string_view {peer.received}.substr(answered_bytes, length),
                                               connection, answered++);
                    answered_bytes += length;
                    if (!answer.bytes.empty())
                        open = peer.write(uc::byte_span(answer.bytes), answer.bytes.size(), generator,
                                          steady_clock::now() + 5s);
                    if (answer.after != after_answer_t::close_k) continue;
                    ::shutdown(peer.descriptor, SHUT_WR);
                    for (auto const until = steady_clock::now() + 5s;
                         running() && steady_clock::now() < until &&
                         peer.read_until_close(steady_clock::now() + 20ms) == read_end_t::timed_out_k;) {}
                    open = false;
                }
            }
            requests_per_connection[connection] = whole_requests(peer.received);
        }
    }
};

/** One call a case sends a scripted server, and the body of the 200 that must answer it. */
struct scripted_call_t {
    std::string url {};
    ucall_verb_t verb = ucall_verb_get_k;
    std::string_view expected {};
    ucall_bytes_view_t header {};
    std::size_t timeout_microseconds = 0;
};

static std::size_t submit(fixture_t& fixture, scripted_call_t& planned) {
    ucall_outcome_t outcome {};
    ucall_client_call_t call {};
    call.client = fixture.client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(planned.url);
    call.verb = planned.verb;
    call.context = &planned;
    call.headers = planned.header.length ? &planned.header : nullptr;
    call.headers_count = planned.header.length ? 1 : 0;
    call.options.timeout_microseconds = planned.timeout_microseconds;
    ucall_client_call(&call);
    return expect(outcome.status == ucall_status_success_k, "submitting {}: {}", planned.url,
                  ucall_status_name(outcome.status));
}

/** Checks a completed call is a 200 carrying its own planned body, then frees the response. */
static std::size_t check_answer(ucall_completed_call_t const& completed) {
    auto const* planned = static_cast<scripted_call_t const*>(completed.context);
    std::size_t failures = expect(planned && completed.outcome.status == ucall_status_success_k && completed.response,
                                  "{} completed {}", planned ? planned->url : "no call",
                                  ucall_status_name(completed.outcome.status));
    if (!completed.response) return failures;
    ucall_outcome_t outcome {};
    ucall_bytes_view_t body {};
    ucall_client_response_body_t get {completed.response, &outcome, &body};
    ucall_client_response_body(&get);
    std::string_view const text {reinterpret_cast<char const*>(body.data), body.length};
    auto const status = ucall_client_response_status(completed.response);
    failures += expect(status == ucall_http_status_ok_k && planned && text == planned->expected, "{} answered {} {:?}",
                       planned ? planned->url : "no call", status, text);
    ucall_client_response_free(completed.response);
    return failures;
}

/** Submits every call of @p plan in order, then checks each answer in whatever order they come. */
template <std::size_t count_>
static std::size_t exchange_all(fixture_t& fixture, std::array<scripted_call_t, count_>& plan) {
    std::size_t failures = 0;
    for (auto& planned : plan) failures += submit(fixture, planned);
    for (std::size_t i = 0; i != count_ && !failures; ++i) failures += check_answer(fixture.wait());
    return failures;
}

/** Answers every request with its own target, closing when the request asks to. */
static scripted_answer_t answer_target(std::string_view request, std::size_t, std::size_t) {
    bool const closes = request.find("\r\nconnection: close\r\n") != std::string_view::npos;
    return answer_ok(request_target(request), closes ? after_answer_t::close_k : after_answer_t::keep_open_k);
}

/** A HEAD answered without `content-length` keeps the connection for the GET behind it. */
static case_result_t test_lengthless_head_keeps_connection(random_generator_t& generator) {
    fixture_t fixture {{.pipelined_calls = 4}};
    scripted_server_t server {generator,
                              [](std::string_view request, std::size_t connection, std::size_t index) {
                                  return request.starts_with("HEAD ") ? scripted_answer_t {"HTTP/1.1 200 OK\r\n\r\n"}
                                                                      : answer_target(request, connection, index);
                              },
                              100ms};
    require(0, fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
            ucall_status_name(fixture.status));
    std::array<scripted_call_t, 2> plan {{{server.url("/head"), ucall_verb_head_k, ""}, {server.url("/get")}}};
    plan[1].expected = "/get";
    std::size_t failures = exchange_all(fixture, plan);
    server.stop();
    failures += expect(server.requests_per_connection == (std::vector<std::size_t> {2}),
                       "{} connections carried the calls", server.requests_per_connection.size());
    return failures + fixture.stop();
}

/** A caller's `Connection: close` on the second of four calls keeps the last two off its
 *  connection: they leave on the next one, and every call is answered. */
static case_result_t test_caller_close_mid_pipeline(random_generator_t& generator) {
    fixture_t fixture {{.pipelined_calls = 4}};
    scripted_server_t server {generator, answer_target, 100ms};
    require(0, fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
            ucall_status_name(fixture.status));
    std::array<scripted_call_t, 4> plan {
        {{server.url("/a"), ucall_verb_get_k, "/a"},
         {server.url("/b"), ucall_verb_get_k, "/b", uc::bytes_view("Connection: close")},
         {server.url("/c"), ucall_verb_get_k, "/c"},
         {server.url("/d"), ucall_verb_get_k, "/d"}}};
    std::size_t failures = exchange_all(fixture, plan);
    server.stop();
    failures += expect(server.requests_per_connection == (std::vector<std::size_t> {2, 2}),
                       "{} connections, the first carrying {} requests", server.requests_per_connection.size(),
                       server.requests_per_connection.empty() ? 0 : server.requests_per_connection[0]);
    return failures + fixture.stop();
}

/** A POST waits for the response to the POST before it, per RFC 9112 §9.3.2, rather than
 *  pipelining behind it. */
static case_result_t test_post_waits_behind_post(random_generator_t& generator) {
    fixture_t fixture {{.pipelined_calls = 4}};
    scripted_server_t server {generator, answer_target, 100ms};
    require(0, fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
            ucall_status_name(fixture.status));
    std::array<scripted_call_t, 2> plan {
        {{server.url("/first"), ucall_verb_post_k, "/first"}, {server.url("/second"), ucall_verb_post_k, "/second"}}};
    std::size_t failures = exchange_all(fixture, plan);
    server.stop();
    failures += expect(server.deepest == 1, "the server held {} requests at once", server.deepest);
    failures += expect(server.requests_per_connection == (std::vector<std::size_t> {2}), "{} connections",
                       server.requests_per_connection.size());
    return failures + fixture.stop();
}

/** A call with a short timeout behind one with a long timeout times out on its own deadline, and
 *  the longer call is answered on a fresh connection. */
static case_result_t test_short_timeout_behind_long(random_generator_t& generator) {
    fixture_t fixture {{.pipelined_calls = 4}};
    scripted_server_t server {generator, [](std::string_view request, std::size_t connection, std::size_t index) {
                                  return connection ? answer_target(request, connection, index) : scripted_answer_t {};
                              }};
    require(0, fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
            ucall_status_name(fixture.status));
    std::array<scripted_call_t, 2> plan {{{server.url("/long"), ucall_verb_get_k, "/long", {}, 3'000'000},
                                          {server.url("/short"), ucall_verb_get_k, "/short", {}, 200'000}}};
    // The queue runs by deadline, so the short call follows only once the long one has left.
    std::size_t failures = submit(fixture, plan[0]);
    for (steady_clock::time_point const settled = steady_clock::now() + 100ms; steady_clock::now() < settled;) {
        ucall_completed_call_t completed {};
        failures += expect(!fixture.poll(completed), "a call completed early");
    }
    failures += submit(fixture, plan[1]);
    auto const submitted = steady_clock::now();
    auto completed = fixture.wait();
    auto const elapsed = steady_clock::now() - submitted;
    failures += expect(completed.context == &plan[1] && completed.outcome.status == ucall_status_timeout_k &&
                           elapsed >= 200ms && elapsed < 1s,
                       "{} completed {} after {} ms", completed.context == &plan[1] ? "the short call" : "another",
                       ucall_status_name(completed.outcome.status),
                       std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
    if (completed.response) ucall_client_response_free(completed.response);
    if (!failures) failures += check_answer(fixture.wait());
    return failures + fixture.stop();
}

/** A keep-alive connection the server closes while idle is noticed, so the POST after it opens a
 *  new one; and a POST whose reused connection closes before any byte of its response is sent
 *  again. */
static case_result_t test_stale_idle_connection(random_generator_t& generator) {
    fixture_t fixture {{.pipelined_calls = 4}};
    scripted_server_t server {
        generator, [](std::string_view request, std::size_t connection, std::size_t index) -> scripted_answer_t {
            if (connection == 0) return {answer_target(request, connection, index).bytes, after_answer_t::close_k};
            if (connection == 1 && index == 1) return {{}, after_answer_t::close_k};
            return answer_target(request, connection, index);
        }};
    require(0, fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
            ucall_status_name(fixture.status));
    std::array<scripted_call_t, 3> plan {{{server.url("/first"), ucall_verb_get_k, "/first"},
                                          {server.url("/second"), ucall_verb_post_k, "/second"},
                                          {server.url("/third"), ucall_verb_post_k, "/third"}}};
    std::size_t failures = submit(fixture, plan[0]);
    failures += check_answer(fixture.wait());
    for (steady_clock::time_point const settled = steady_clock::now() + 200ms; steady_clock::now() < settled;) {
        ucall_completed_call_t completed {};
        failures += expect(!fixture.poll(completed), "a call completed unasked");
    }
    for (std::size_t i = 1; i != plan.size(); ++i) {
        failures += submit(fixture, plan[i]);
        failures += check_answer(fixture.wait());
    }
    server.stop();
    failures += expect(server.requests_per_connection == (std::vector<std::size_t> {1, 2, 1}), "{} connections",
                       server.requests_per_connection.size());
    return failures + fixture.stop();
}

/** The server closes after answering the first of two pipelined calls: the POST it never read is
 *  sent again on a new connection, per RFC 9112 §9.6, and answered. */
static case_result_t test_server_close_mid_pipeline(random_generator_t& generator) {
    fixture_t fixture {{.pipelined_calls = 4}};
    scripted_server_t server {generator,
                              [](std::string_view request, std::size_t connection, std::size_t index) {
                                  return connection ? answer_target(request, connection, index)
                                                    : answer_ok(request_target(request), after_answer_t::close_k);
                              },
                              100ms};
    require(0, fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
            ucall_status_name(fixture.status));
    std::array<scripted_call_t, 2> plan {
        {{server.url("/first"), ucall_verb_get_k, "/first"}, {server.url("/second"), ucall_verb_post_k, "/second"}}};
    std::size_t failures = exchange_all(fixture, plan);
    server.stop();
    failures += expect(server.requests_per_connection == (std::vector<std::size_t> {2, 1}), "{} connections",
                       server.requests_per_connection.size());
    return failures + fixture.stop();
}

/** A redirect in the middle of a pipeline, sent with `connection: close`, is followed, and the POST
 *  behind it is sent again on the next connection; each call gets its own answer. */
static case_result_t test_redirect_mid_pipeline(random_generator_t& generator) {
    fixture_t fixture {{.pipelined_calls = 4}};
    scripted_server_t server {generator,
                              [](std::string_view request, std::size_t connection, std::size_t index) {
                                  if (request_target(request) != "/moved")
                                      return answer_target(request, connection, index);
                                  return scripted_answer_t {"HTTP/1.1 302 Found\r\nlocation: /landed\r\n"
                                                            "content-length: 0\r\nconnection: close\r\n\r\n",
                                                            after_answer_t::close_k};
                              },
                              100ms};
    require(0, fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
            ucall_status_name(fixture.status));
    std::array<scripted_call_t, 3> plan {{{server.url("/first"), ucall_verb_get_k, "/first"},
                                          {server.url("/moved"), ucall_verb_get_k, "/landed"},
                                          {server.url("/last"), ucall_verb_post_k, "/last"}}};
    std::size_t failures = exchange_all(fixture, plan);
    server.stop();
    failures += expect(server.requests_per_connection == (std::vector<std::size_t> {3, 2}), "{} connections",
                       server.requests_per_connection.size());
    return failures + fixture.stop();
}

#endif // UCALL_OS_POSIX_
#pragma endregion Scripted Servers

#pragma region Engines
#if UCALL_OS_POSIX_

/** A mebibyte send and a receive wait on one socket together,
 *  and each completes as its own request. */
template <typename engine_type_>
static case_result_t engine_duplex(random_generator_t& generator) {
    engine_type_ engine;
    auto const status = engine.open(2, 2);
    if (status == ucall_status_unsupported_k) return case_result_t::skipped("the kernel lacks this backend");
    require(0, status == ucall_status_success_k, "{}", ucall_status_name(status));
    std::size_t failures = 0;
    loopback_pair_t sockets = loopback_pair();
    require(failures, sockets.connected());
    // A send buffer far below a mebibyte keeps the send pending until the peer drains it.
    int const send_buffer = static_cast<int>(fixture_buffer_bytes_k);
    require(failures,
            uc::nonblocking(sockets.client) == ucall_status_success_k &&
                uc::nonblocking(sockets.peer) == ucall_status_success_k &&
                uc::socket_option(sockets.client, SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)) == 0);
    auto const owned = engine.import_socket(std::exchange(sockets.client, -1));
    require(failures, owned >= 0, "importing ended with {}", owned);
    int const peer = sockets.peer;

    std::vector<uc::byte_t> payload(std::size_t {1} << 20), drained(payload.size());
    for (auto& byte : payload) byte = static_cast<uc::byte_t>(generator());
    uc::span<uc::byte_t const> const message = uc::byte_span("receive");
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
    return failures;
}

/** The engine `--backend` names keeps a receive and a send pending on one socket at once. */
static case_result_t test_engine_duplex_delivery(random_generator_t& generator) {
    switch (backend_under_test) {
#if UCALL_WITH_POSIX
    case ucall_io_backend_posix_k: return engine_duplex<uc::posix_engine_t>(generator);
#endif
#if UCALL_WITH_LINUX_EPOLL
    case ucall_io_backend_linux_epoll_k: return engine_duplex<uc::linux_epoll_engine_t>(generator);
#endif
#if UCALL_WITH_LINUX_URING
    case ucall_io_backend_linux_uring612_k: return engine_duplex<uc::linux_uring612_engine_t>(generator);
    case ucall_io_backend_linux_uring700_k: return engine_duplex<uc::linux_uring700_engine_t>(generator);
#endif
#if UCALL_WITH_KQUEUE
    case ucall_io_backend_macos_kqueue_k: return engine_duplex<uc::kqueue_engine_t>(generator);
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
            backend_under_test = ucall_io_backend_from_name(uc::bytes_view(argv[index + 1]));
            if (name != ucall_io_backend_name(backend_under_test)) {
                fmt::print(stderr, "Unknown backend {}\n", name);
                return 1;
            }
        }
        else if (flag == "--cpu-class") {
            cpu_class_under_test = ucall_cpu_class_from_name(uc::bytes_view(argv[index + 1]));
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
    run_test(totals, "test_bodiless_responses_keep_connection", test_bodiless_responses_keep_connection);
    run_test(totals, "test_reply_vectored_plain", test_reply_vectored_plain);
    run_test(totals, "test_reply_vectored_noise_xx", test_reply_vectored_noise_xx);
    run_test(totals, "test_streamed_reply_plain", test_streamed_reply_plain);
    run_test(totals, "test_streamed_reply_noise_xx", test_streamed_reply_noise_xx);
    run_test(totals, "test_pipelined_streams_plain", test_pipelined_streams_plain);
    run_test(totals, "test_pipelined_streams_noise_xx", test_pipelined_streams_noise_xx);
    run_test(totals, "test_head_replies", test_head_replies);
#if UCALL_OS_POSIX_
    run_test(totals, "test_streamed_reply_would_block", test_streamed_reply_would_block);
    run_test(totals, "test_streamed_reply_detach", test_streamed_reply_detach);
    run_test(totals, "test_streamed_reply_http10", test_streamed_reply_http10);
    run_test(totals, "test_streamed_reply_identity", test_streamed_reply_identity);
    run_test(totals, "test_lengthless_head_keeps_connection", test_lengthless_head_keeps_connection);
    run_test(totals, "test_caller_close_mid_pipeline", test_caller_close_mid_pipeline);
    run_test(totals, "test_post_waits_behind_post", test_post_waits_behind_post);
    run_test(totals, "test_short_timeout_behind_long", test_short_timeout_behind_long);
    run_test(totals, "test_stale_idle_connection", test_stale_idle_connection);
    run_test(totals, "test_server_close_mid_pipeline", test_server_close_mid_pipeline);
    run_test(totals, "test_redirect_mid_pipeline", test_redirect_mid_pipeline);
    run_test(totals, "test_pipelined_delivery", test_pipelined_delivery);
    run_test(totals, "test_fragmented_headers_delivery", test_fragmented_headers_delivery);
    run_test(totals, "test_megabyte_echo_delivery", test_megabyte_echo_delivery);
    run_test(totals, "test_smuggling_safety", test_smuggling_safety);
    run_test(totals, "test_header_lookup_unit", test_header_lookup_unit);
    run_test(totals, "test_cross_thread_teardown_delivery", test_cross_thread_teardown_delivery);
    run_test(totals, "test_admission_across_loops", test_admission_across_loops);
    run_test(totals, "test_engine_duplex_delivery", test_engine_duplex_delivery);
    if (backend_under_test == ucall_io_backend_automatic_k)
        run_test(totals, "test_backend_parity", test_backend_parity);
#endif
    return suite_exit_code(totals);
}
