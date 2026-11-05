/**
 *  @file test/network.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The loopback fixture and the call, reply and outcome checks the network suites share.
 */
#pragma once

#include <cstdlib> // `std::quick_exit`
#include <cstring> // `std::memcmp`, `std::strlen`

#include <algorithm>   // `std::max`
#include <array>       // `std::array`
#include <atomic>      // `std::atomic`
#include <charconv>    // `std::from_chars`
#include <chrono>      // `std::chrono::steady_clock`
#include <filesystem>  // `std::filesystem::remove_all`
#include <functional>  // `std::function`
#include <future>      // `std::promise`
#include <mutex>       // `std::mutex`, `std::lock_guard`
#include <string>      // `std::string`
#include <string_view> // `std::string_view`
#include <memory>      // `std::make_shared`
#include <thread>      // `std::thread`
#include <utility>     // `std::pair`, `std::exchange`
#include <vector>      // `std::vector`

#include "ucall/ucall.h"
#include "ucall/io/posix_engine.hpp"   // `posix_engine_t`
#include "ucall/network.hpp"           // `serial_network`
#include "ucall/utilities/sockets.hpp" // `nonblocking`, `monotonic_ns`, `deadline_after`

#include "harness.hpp" // `expect`, `require`, `run_test`, `raw_client_t`

#if UCALL_OS_POSIX_
#include <fcntl.h>    // `open`, `fcntl`
#include <sys/stat.h> // `mkfifo`, `chmod`
#endif

namespace unum::ucall::test {

namespace uc = unum::ucall;
using namespace std::chrono_literals;
using std::chrono::steady_clock;

/** The backend under test, which <tt>--backend</tt> names. */
inline ucall_io_backend_t backend_under_test = ucall_io_backend_automatic_k;
inline ucall_cpu_class_t cpu_class_under_test = ucall_cpu_class_unknown_k;

inline ucall_status_t authorize(ucall_noise_key_t const* key, void* context) {
    return std::memcmp(*key, context, sizeof(ucall_noise_key_t)) == 0 ? ucall_status_success_k
                                                                      : ucall_status_peer_rejected_k;
}

/** A reply part holding @p data. */
inline ucall_reply_part_t bytes_part(std::string_view data) {
    ucall_reply_part_t part {};
    part.kind = ucall_reply_part_bytes_k;
    part.data.bytes = uc::bytes_view(data);
    return part;
}

/** What a fixture varies between cases; every other setting is fixed. */
struct fixture_config_t {
    ucall_security_t security = ucall_security_none_k;
    std::size_t event_loops = 1;

    /** Open-connection budget of the server and the client alike. */
    std::size_t connections = 1;

    /** Requests the server reads ahead on one connection; zero means one. */
    std::size_t pipelined_requests = 0;

    /** Calls the client sends ahead on one connection; zero means one. */
    std::size_t pipelined_calls = 0;

    ucall_io_backend_t backend = backend_under_test;

    /** The one directory path parts resolve beneath, or empty for none. */
    std::string_view directory {};

    /** The largest buffered request the server takes; zero lets the kernel decide. */
    std::size_t max_request_bytes = 0;

    /** A StatsD listener the server reports to every 10 ms as @c probe with two tags, or empty. */
    std::string_view metrics_address {};

    /** Where the server writes its log lines, or nowhere. */
    ucall_log_t log {};

    /** The largest response the client buffers; zero lets the kernel decide. */
    std::size_t max_response_bytes = 0;
};

/** The global tags a fixture reporting metrics attaches to every line. */
inline ucall_bytes_view_t const metrics_tags_k[] {{reinterpret_cast<ucall_byte_t const*>("env:test"), 8},
                                                  {reinterpret_cast<ucall_byte_t const*>("team:core"), 9}};

/**
 *  @brief A loopback server with echo, gated, header-lookup, GET-only, and bodiless status routes,
 *      and a client to call it.
 *
 *  Cases either poll both from their own thread, or serve every loop in the background while raw
 *  clients block on the wire.
 */
struct fixture_t {
    ucall_server_t server {};
    ucall_client_t client {};
    ucall_server_options_t resolved {};
    ucall_client_options_t resolved_client {};
    ucall_noise_key_t server_private {}, server_public {}, client_private {}, client_public {};
    std::string address {}, url {};

    /** The first setup step that failed, which every case checks before it starts. */
    ucall_status_t status {ucall_status_success_k};

    /** Checks that failed in callbacks and polling threads, which no case frame returns. */
    std::atomic<std::size_t> failures {};

    /** Requests that reached the echo or header-lookup routes. */
    std::atomic<std::size_t> dispatched {};

    /** What @c /stream/pull answered. */
    std::atomic<ucall_status_t> polling_pull_status {ucall_status_success_k};

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
        ucall_reply_part_t const parts[] {bytes_part(""), bytes_part("first|"), bytes_part(middle), bytes_part(""),
                                          bytes_part("|last")};
        ucall_outcome_t outcome {};
        ucall_server_reply_vectored_t reply {fixture.server, &outcome, request, ucall_http_status_created_k,
                                             headers,        2,        parts,   5};
        ucall_server_reply_vectored(&reply);
        fixture.failures += expect(outcome.status == ucall_status_success_k, "vectored: {}",
                                   ucall_status_name(outcome.status));
    }

    /** Checks the peer is the fixture's client on loopback, then replies with the request body and
     *  an <tt>X-UCall: passed</tt> header. */
    void reply_echo(ucall_received_http_request_t request) {
        ucall_outcome_t outcome {};
        std::size_t network_interface_index = resolved.interfaces_count;
        ucall_noise_key_t peer_static_key {}, expected_key {};
        ucall_peer_address_t address {};
        if (resolved.interfaces[0].security != ucall_security_none_k)
            std::memcpy(expected_key, client_public, sizeof(expected_key));
        ucall_server_request_peer_t peer {server,           &outcome, request, &network_interface_index,
                                          &peer_static_key, &address};
        ucall_server_request_peer(&peer);
        failures += expect(outcome.status == ucall_status_success_k && network_interface_index == 0 &&
                               std::memcmp(peer_static_key, expected_key, sizeof(expected_key)) == 0,
                           "peer: {} on interface {}", ucall_status_name(outcome.status), network_interface_index);
        ucall_byte_t const loopback[4] {127, 0, 0, 1};
        failures += expect(address.family == ucall_address_family_ipv4_k &&
                               std::memcmp(address.bytes, loopback, sizeof(loopback)) == 0 && address.port,
                           "peer address family {} port {}", address.family, address.port);
        ucall_bytes_view_t body {};
        ucall_server_request_body_t extract {server, &outcome, request, &body};
        ucall_server_request_body(&extract);
        failures += expect(outcome.status == ucall_status_success_k);
        ucall_bytes_view_t header = uc::bytes_view("X-UCall: passed");
        ucall_server_reply_content_t reply {server, &outcome, request, ucall_http_status_ok_k, &header, 1, body};
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

    /** Pulls once on the polling thread, keeping what the pull answered, then retains the request
     *  like @c gate. */
    static void pulling_gate(ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<fixture_t*>(context);
        ucall_outcome_t outcome {};
        ucall_bytes_view_t data {};
        ucall_server_request_body_chunk_t pull {fixture.server, &outcome, request, &data};
        ucall_server_request_body_chunk(&pull);
        fixture.polling_pull_status.store(outcome.status, std::memory_order_relaxed);
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
        ucall_server_reply_content_t reply {
            fixture.server, &outcome, request, ucall_http_status_ok_k, nullptr, 0, uc::bytes_view(answer)};
        ucall_server_reply_content(&reply);
        fixture.failures += expect(outcome.status == ucall_status_success_k);
    }

    /** Replies with the part count, then each multipart part as <tt>name=type=data</tt>, all
     *  <tt>;</tt>-ended. */
    static void parts(ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<fixture_t*>(context);
        std::size_t const count = ucall_server_request_parts_count(fixture.server, request);
        std::string answer = fmt::format("{};", count);
        for (std::size_t index = 0; index != count; ++index) {
            ucall_outcome_t outcome {};
            ucall_bytes_view_t name {}, type {}, data {};
            ucall_server_request_part_t get {fixture.server, &outcome, request, index, &name, &type, &data};
            ucall_server_request_part(&get);
            fixture.failures += expect(outcome.status == ucall_status_success_k, "part {}: {}", index,
                                       ucall_status_name(outcome.status));
            answer += fmt::format("{}={}={};", uc::text_view(name), uc::text_view(type), uc::text_view(data));
        }
        ucall_outcome_t probe {};
        ucall_bytes_view_t name {}, type {}, data {};
        ucall_server_request_part_t past {fixture.server, &probe, request, count, &name, &type, &data};
        ucall_server_request_part(&past);
        if (probe.status == ucall_status_malformed_k) answer += "malformed;";
        ucall_outcome_t outcome {};
        ucall_server_reply_content_t reply {
            fixture.server, &outcome, request, ucall_http_status_ok_k, nullptr, 0, uc::bytes_view(answer)};
        ucall_server_reply_content(&reply);
        fixture.failures += expect(outcome.status == ucall_status_success_k);
    }

    /** Replies with no body and the status the <tt>{code}</tt> segment names. */
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
        ucall_server_reply_content_t reply {fixture.server, &outcome, request, status, nullptr, 0, {}};
        ucall_server_reply_content(&reply);
        fixture.failures += expect(outcome.status == ucall_status_success_k, "reply {}: {}", status,
                                   ucall_status_name(outcome.status));
    }

    std::size_t held_count() {
        std::lock_guard lock {held_mutex};
        return held.size();
    }

    /** Pops one request the @c /gate route retained, or null when none waits. */
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
        network_interface.address = uc::bytes_view("127.0.0.1:0");
        network_interface.event_loops = settings.event_loops;
        network_interface.max_concurrent_connections = settings.connections;
        network_interface.max_pipelined_requests = settings.pipelined_requests;
        network_interface.max_request_bytes = settings.max_request_bytes;
        network_interface.security = settings.security;
        network_interface.noise_private_key = &server_private;
        if (settings.security == ucall_security_noise_kk_k) network_interface.noise_peer_key = &client_public;
        network_interface.peer_authorizer = authorize;
        network_interface.peer_authorizer_context = client_public;
        ucall_bytes_view_t const directory = uc::bytes_view(settings.directory);
        network_interface.reply_directories = &directory;
        network_interface.reply_directories_count = settings.directory.empty() ? 0 : 1;
        ucall_server_options_t config {};
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
        config.backend = settings.backend;
        config.cpu_class = cpu_class_under_test;
        config.log = settings.log;
        if (!settings.metrics_address.empty()) {
            config.metrics_address = uc::bytes_view(settings.metrics_address);
            config.metrics_prefix = uc::bytes_view("probe");
            config.metrics_tags = metrics_tags_k;
            config.metrics_tags_count = 2;
            config.metrics_interval_microseconds = 10'000;
        }
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
        ucall_server_add_http_endpoint_t only_get {server,           &outcome, uc::bytes_view("/only-get"),
                                                   ucall_verb_get_k, echo,     this};
        ucall_server_add_http_endpoint(&only_get);
        if ((status = outcome.status) != ucall_status_success_k) return;
        ucall_server_add_http_endpoint_t parts_route {server,           &outcome, uc::bytes_view("/parts"),
                                                      ucall_verb_any_k, parts,    this};
        ucall_server_add_http_endpoint(&parts_route);
        if ((status = outcome.status) != ucall_status_success_k) return;
        ucall_server_add_http_endpoint_t stream {server, &outcome, uc::bytes_view("/stream"),     ucall_verb_any_k,
                                                 gate,   this,     ucall_body_delivery_streamed_k};
        ucall_server_add_http_endpoint(&stream);
        if ((status = outcome.status) != ucall_status_success_k) return;
        ucall_server_add_http_endpoint_t pulling {
            server,       &outcome, uc::bytes_view("/stream/pull"), ucall_verb_any_k,
            pulling_gate, this,     ucall_body_delivery_streamed_k};
        ucall_server_add_http_endpoint(&pulling);
        if ((status = outcome.status) != ucall_status_success_k) return;
        ucall_client_options_t client_config {};
        client_config.max_concurrent_connections = settings.connections;
        client_config.max_response_bytes = settings.max_response_bytes;
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
        address = uc::text_view(resolved.interfaces[0].address);
        url = fmt::format("{}{}", settings.security == ucall_security_none_k ? "http://" : "http+noise://", address);
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
inline std::size_t check_response(ucall_received_http_response_t response, std::string_view expected) {
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

/** Polls until the @c /gate route holds @p count requests, with no call completing meanwhile. */
inline std::size_t await_held(fixture_t& fixture, std::size_t count) {
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

/** Calls @p target with @p verb, then waits for the completion, whose response the caller frees. */
inline ucall_completed_call_t call_and_wait(fixture_t& fixture, ucall_verb_t verb, std::string_view target,
                                            ucall_security_t security, std::size_t& failures) {
    std::string const url = fmt::format("{}{}", fixture.url, target);
    ucall_outcome_t outcome {};
    ucall_client_call_t call {};
    call.client = fixture.client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(url);
    call.verb = verb;
    call.options.security = security;
    call.options.noise_peer_key = &fixture.server_public;
    ucall_client_call(&call);
    failures += expect(outcome.status == ucall_status_success_k, "call: {}", ucall_status_name(outcome.status));
    auto completed = fixture.wait();
    failures += expect(completed.outcome.status == ucall_status_success_k && completed.response, "{}: {}", target,
                       ucall_status_name(completed.outcome.status));
    return completed;
}
inline std::string_view response_body(ucall_received_http_response_t response) {
    ucall_outcome_t outcome {};
    ucall_bytes_view_t body {};
    ucall_client_response_body_t get {response, &outcome, &body};
    ucall_client_response_body(&get);
    return {reinterpret_cast<char const*>(body.data), body.length};
}
inline std::string_view response_header(ucall_received_http_response_t response, std::string_view name) {
    ucall_outcome_t outcome {};
    ucall_bytes_view_t value {};
    ucall_client_response_header_t get {response, &outcome, uc::bytes_view(name), &value};
    ucall_client_response_header(&get);
    return {reinterpret_cast<char const*>(value.data), value.length};
}

/** Checks @p completed answered @p status with @p body, then frees its response. */
inline std::size_t check_answer(ucall_completed_call_t const& completed, ucall_http_status_t status,
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

#if UCALL_OS_POSIX_

/** Sends @p request whole, reads until the server closes in order, never with a reset, and
 *  answers the first response. */
inline wire_response_t exchange_until_close(raw_client_t& client, std::string_view request, std::size_t max_chunk,
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

/** Waits until the background loops hold @p count requests at @c /gate. */
inline std::size_t await_held_in_background(fixture_t& fixture, std::size_t count) {
    steady_clock::time_point const deadline = steady_clock::now() + 5s;
    while (fixture.held_count() != count && steady_clock::now() < deadline) std::this_thread::sleep_for(1ms);
    return expect(fixture.held_count() == count, "the server holds {} of {} requests", fixture.held_count(), count);
}

/** Calls @c /gate with @p verb and polls until the server holds the request, which it answers. */
inline ucall_received_http_request_t hold_call(fixture_t& fixture, ucall_verb_t verb, ucall_security_t security,
                                               std::size_t& failures, std::string_view target = "/gate") {
    std::string const url = fmt::format("{}{}", fixture.url, target);
    ucall_outcome_t outcome {};
    ucall_client_call_t call {};
    call.client = fixture.client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(url);
    call.verb = verb;
    call.options.security = security;
    call.options.noise_peer_key = &fixture.server_public;
    ucall_client_call(&call);
    failures += expect(outcome.status == ucall_status_success_k, "call: {}", ucall_status_name(outcome.status));
    failures += await_held(fixture, fixture.held_count() + 1);
    return fixture.take_held();
}

/** Polls the server until @p outcome is final, answering its status, or deferred after five
 *  seconds. */
inline ucall_status_t await_outcome(fixture_t& fixture, ucall_outcome_t& outcome) {
    steady_clock::time_point const deadline = steady_clock::now() + 5s;
    while (ucall_outcome_status(&outcome) == ucall_status_deferred_k && steady_clock::now() < deadline) {
        ucall_outcome_t polled {};
        ucall_server_take_call_t serving {fixture.server, &polled, 0, 0};
        if (fixture.pollers.empty()) ucall_server_take_call(&serving);
        else std::this_thread::sleep_for(1ms);
    }
    return ucall_outcome_status(&outcome);
}

/** Checks @p outcome turns final as @p expected, polling the server while it is deferred. */
inline std::size_t expect_outcome(fixture_t& fixture, ucall_outcome_t& outcome, ucall_status_t expected) {
    ucall_status_t const status = await_outcome(fixture, outcome);
    return expect(status == expected, "the outcome turned {} rather than {}", ucall_status_name(status),
                  ucall_status_name(expected));
}

/** One counter of event loop zero, read from any thread. */
inline ucall_event_loop_statistics_t loop_statistics(fixture_t& fixture) {
    ucall_outcome_t outcome {};
    ucall_event_loop_statistics_t statistics {};
    ucall_server_event_loop_statistics_t query {fixture.server, &outcome, 0, &statistics};
    ucall_server_event_loop_statistics(&query);
    return statistics;
}

#if UCALL_WITH_POSIX
using counted_network_t = uc::network::serial_network<uc::io::posix_engine_t, counting_allocator<uc::byte_t>>;
#endif
#endif // UCALL_OS_POSIX_

namespace network {
void run_exchanges(suite_totals_t& totals);
#if UCALL_OS_POSIX_
void run_bodies(suite_totals_t& totals);
void run_client(suite_totals_t& totals);
void run_files(suite_totals_t& totals);
#endif
} // namespace network

} // namespace unum::ucall::test
