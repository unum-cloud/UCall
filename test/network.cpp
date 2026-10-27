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
#include <filesystem>  // `std::filesystem::remove_all`
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
#include "ucall/network.hpp"
#if UCALL_WITH_LINUX_URING
#include "ucall/uring612.hpp"
#include "ucall/uring618.hpp"
#endif

#include "harness.hpp" // `expect`, `require`, `run_test`, `raw_client_t`

#if UCALL_OS_POSIX_
#include <fcntl.h>    // `open`, `fcntl`
#include <sys/stat.h> // `mkfifo`, `chmod`
#endif

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

/** A reply part holding @p data. */
static ucall_reply_part_t bytes_part(std::string_view data) {
    ucall_reply_part_t part {};
    part.kind = ucall_reply_part_bytes_k;
    part.data.bytes = uc::bytes_view(data);
    return part;
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

    /** The one directory path parts resolve beneath, or empty for none. */
    std::string_view directory {};

    /** The largest buffered request the server takes; zero lets the kernel decide. */
    std::size_t max_request_bytes = 0;

    /** A StatsD listener the server reports to every 10 ms as `probe` with two tags, or empty. */
    std::string_view metrics_address {};
};

/** The global tags a fixture reporting metrics attaches to every line. */
static ucall_bytes_view_t const metrics_tags_k[] {{reinterpret_cast<ucall_byte_t const*>("env:test"), 8},
                                                  {reinterpret_cast<ucall_byte_t const*>("team:core"), 9}};

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
        ucall_reply_part_t const parts[] {bytes_part(""), bytes_part("first|"), bytes_part(middle), bytes_part(""),
                                          bytes_part("|last")};
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

    /** Replies with the part count, then each multipart part as `name=type=data`, all `;`-ended. */
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
        network_interface.address = uc::bytes_view("127.0.0.1:0");
        network_interface.event_loops = settings.event_loops;
        network_interface.max_concurrent_connections = settings.connections;
        network_interface.max_pipelined_requests = settings.pipelined_requests;
        network_interface.max_request_bytes = settings.max_request_bytes;
        network_interface.security_mode = settings.security;
        network_interface.noise_private_key = &server_private;
        if (settings.security == ucall_security_mode_noise_kk_k) network_interface.noise_peer_key = &client_public;
        network_interface.peer_authorizer = authorize;
        network_interface.peer_authorizer_context = client_public;
        ucall_bytes_view_t const directory = uc::bytes_view(settings.directory);
        network_interface.reply_directories = &directory;
        network_interface.reply_directories_count = settings.directory.empty() ? 0 : 1;
        ucall_server_config_t config {};
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
        config.backend = settings.backend;
        config.cpu_class = cpu_class_under_test;
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
        ucall_server_add_http_endpoint_t parts_route {server,           &outcome, uc::bytes_view("/parts"),
                                                      ucall_verb_any_k, parts,    this};
        ucall_server_add_http_endpoint(&parts_route);
        if ((status = outcome.status) != ucall_status_success_k) return;
        ucall_server_add_http_endpoint_t stream {server, &outcome, uc::bytes_view("/stream"),     ucall_verb_any_k,
                                                 gate,   this,     ucall_body_delivery_streamed_k};
        ucall_server_add_http_endpoint(&stream);
        if ((status = outcome.status) != ucall_status_success_k) return;
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
        address = uc::text_view(resolved.interfaces[0].address);
        url = fmt::format("{}{}", settings.security == ucall_security_mode_none_k ? "http://" : "http+noise://",
                          address);
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
    auto url = fmt::format("{}/echo/42?key=value", fixture.url);
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
static case_result_t test_exchanges_noise_kk() { return exchanges(ucall_security_mode_noise_kk_k); }

/** A KK interface refuses an initiator whose static key is not the one it names. */
static case_result_t test_server_kk_wrong_initiator() {
    fixture_t fixture {{.security = ucall_security_mode_noise_kk_k}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    ucall_noise_key_t stranger {}, stranger_public {};
    ucall_outcome_t outcome {};
    ucall_noise_key_generate_t generate {&outcome, &stranger, &stranger_public};
    ucall_noise_key_generate(&generate);
    require(failures + fixture.stop(), outcome.status == ucall_status_success_k, "{}",
            ucall_status_name(outcome.status));
    auto const url = fmt::format("{}/echo/1", fixture.url);
    ucall_client_call_t call {};
    call.client = fixture.client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(url);
    call.verb = ucall_verb_get_k;
    call.options.security = ucall_security_mode_noise_kk_k;
    call.options.server_key = &fixture.server_public;
    call.options.client_key = &stranger;
    ucall_client_call(&call);
    failures += expect(outcome.status == ucall_status_success_k);
    auto completed = fixture.wait();
    failures += expect(completed.outcome.status != ucall_status_success_k, "a stranger's KK call answered {}",
                       ucall_status_name(completed.outcome.status));
    failures += expect(!fixture.dispatched, "{} requests reached a route", fixture.dispatched.load());
    return failures + fixture.stop();
}

/** A request retained on one loop does not stall a call the other loop serves meanwhile. */
static case_result_t test_multiloop_retention() {
    if (UCALL_OS_WINDOWS_) return case_result_t::skipped("IOCP accepts one loop per interface");
    fixture_t fixture {{.event_loops = 2, .connections = 2}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    ucall_outcome_t outcome {};
    auto gate_url = fmt::format("{}/gate", fixture.url), echo_url = fmt::format("{}/echo/42", fixture.url);
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
    std::string const gate_url = fmt::format("{}/gate", fixture.url);
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
    std::string const gate_url = fmt::format("{}/gate", fixture.url);
    std::array<std::string, 8> bodies;
    for (std::size_t i = 0; i != bodies.size(); ++i) {
        // Growing bodies, so later replies span several records each behind shorter ones.
        bodies[i] = fmt::format("call {}{}", i, std::string(i * 40 * 1024, '.'));
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
    std::string const gate_url = fmt::format("{}/gate", fixture.url), post_url = fmt::format("{}/echo/3", fixture.url),
                      get_url = fmt::format("{}/echo/4", fixture.url);
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
    std::array<planned_status_t, 5> plan {
        {{fmt::format("{}/echo/1", fixture.url), ucall_http_status_ok_k},
         {fmt::format("{}/status/204", fixture.url), ucall_http_status_no_content_k},
         {fmt::format("{}/echo/2", fixture.url), ucall_http_status_ok_k},
         {fmt::format("{}/status/304", fixture.url), ucall_http_status_not_modified_k},
         {fmt::format("{}/echo/3", fixture.url), ucall_http_status_ok_k}}};
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
    std::string const url = fmt::format("{}{}", fixture.url, target);
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
        chunks.push_back(fmt::format("{}{}:{}", label, i, std::string(i * 37, label)));
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
        ucall_reply_part_t const part = bytes_part(chunk);
        ucall_server_reply_append_t append {server, &outcome, request, &part, 1};
        for (ucall_server_reply_append(&append); outcome.status == ucall_status_would_block_k;
             ucall_server_reply_append(&append))
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
    std::string const expected = fmt::format("first|{}|last", std::string(100 * 1024, 'v'));
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
    std::string const url = fmt::format("{}/gate", fixture.url);
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
    std::array<std::string, 2> urls {fmt::format("{}/gate?n=0", fixture.url), fmt::format("{}/gate?n=1", fixture.url)};
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
    std::string const url = fmt::format("{}/gate", fixture.url);
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
    fixture_t fixture {{.max_request_bytes = std::size_t {2} << 20}};
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
        ucall_io_backend_posix_k,          ucall_io_backend_linux_epollaio_k, ucall_io_backend_linux_uring612_k,
        ucall_io_backend_linux_uring618_k, ucall_io_backend_macos_kqueue_k,   ucall_io_backend_windows_iocp_k};
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
        ucall_reply_part_t const part = bytes_part(chunk);
        ucall_server_reply_append_t append {fixture.server, &outcome, held, &part, 1};
        ucall_server_reply_append(&append);
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
        ucall_reply_part_t const part = bytes_part(chunk);
        ucall_server_reply_append_t append {fixture.server, &outcome, held, &part, 1};
        for (ucall_server_reply_append(&append); outcome.status == ucall_status_would_block_k;
             ucall_server_reply_append(&append))
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
    ucall_reply_part_t const part = bytes_part(chunk);
    ucall_server_reply_append_t append {fixture.server, &outcome, held, &part, 1};
    ucall_server_reply_append(&append);
    failures += expect(outcome.status == ucall_status_success_k, "chunk: {}", ucall_status_name(outcome.status));
    client.close();
    steady_clock::time_point const deadline = steady_clock::now() + 5s;
    do {
        std::this_thread::sleep_for(1ms);
        ucall_server_reply_append(&append);
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
        ucall_reply_part_t const part = bytes_part(data);
        ucall_server_reply_append_t append {fixture.server, &outcome, held, &part, 1};
        ucall_server_reply_append(&append);
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

/** Configuration strings are views: an address carved from a longer buffer binds by its length
 *  alone, and a device name holding a zero byte is refused. */
static case_result_t test_configuration_byte_views() {
    return keeping_descriptors([]() -> case_result_t {
        std::string_view const carved = "127.0.0.1:0trailing";
        ucall_network_interface_t network_interface {};
        network_interface.address = uc::bytes_view(carved.substr(0, 11));
        network_interface.max_concurrent_connections = 1;
        ucall_server_config_t config {}, resolved {};
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
        config.backend = backend_under_test;
        ucall_server_t server {};
        ucall_outcome_t outcome {};
        ucall_server_init_t init {&server, &outcome, &config, &resolved};
        ucall_server_init(&init);
        require(0, outcome.status == ucall_status_success_k, "a carved address: {}", ucall_status_name(outcome.status));
        std::size_t failures = 0;
        std::string_view const bound = uc::text_view(resolved.interfaces[0].address);
        failures += expect(bound.starts_with("127.0.0.1:") && bound.size() > 10, "bound {}", bound);
        raw_client_t client;
        failures += expect(client.connect(bound), "no connection to {}", bound);
        client.close();
        ucall_server_free(server);
        network_interface.device_name = uc::bytes_view(std::string_view {"lo\0x", 4});
        ucall_server_init(&init);
        failures += expect(outcome.status == ucall_status_invalid_argument_k, "a zero byte in a device: {}",
                           ucall_status_name(outcome.status));
        ucall_server_free(server);
        network_interface.device_name = {};
        ucall_noise_key_t const key {1};
        network_interface.security_mode = ucall_security_mode_noise_kk_k;
        network_interface.noise_private_key = &key;
        ucall_server_init(&init);
        failures += expect(outcome.status == ucall_status_invalid_argument_k, "KK without the initiator key: {}",
                           ucall_status_name(outcome.status));
        ucall_server_free(server);
        return failures;
    });
}

/** A mebibyte of letters, so a misplaced byte shows in the diff. */
static std::string lettered_body() {
    std::string body(std::size_t {1} << 20, '\0');
    for (std::size_t i = 0; i != body.size(); ++i) body[i] = static_cast<char>('a' + i % 23);
    return body;
}

/** @p body framed in chunks of random lengths, one with an extension, and a trailer after them. */
static std::string chunked_body(std::string_view body, random_generator_t& generator) {
    std::string wire;
    for (std::size_t offset = 0; offset != body.size();) {
        std::size_t const length = std::min<std::size_t>(1 + generator.below(70000), body.size() - offset);
        wire += fmt::format("{:x}{}\r\n{}\r\n", length, offset ? "" : ";first=1", body.substr(offset, length));
        offset += length;
    }
    wire += "0\r\nX-Trailer: done\r\n\r\n";
    return wire;
}

/** Pulls @p request's streamed body to its end from this thread, counting the pulls it took. */
static std::string pull_body(fixture_t& fixture, ucall_received_http_request_t request, std::size_t& failures,
                             std::size_t& pulls) {
    std::string body;
    for (;;) {
        ucall_outcome_t outcome {};
        ucall_bytes_view_t data {};
        ucall_server_request_body_chunk_t pull {fixture.server, &outcome, request, &data};
        ucall_server_request_body_chunk(&pull);
        ucall_status_t const status = ucall_outcome_wait(&outcome);
        ++pulls;
        if (status != ucall_status_success_k) {
            failures += expect(false, "pull {} ended with {}", pulls, ucall_status_name(status));
            return body;
        }
        if (!data.length) return body;
        body += uc::text_view(data);
    }
}

/** Answers @p request with the length of what it received, once a streamed case pulled it all. */
static std::size_t reply_length(fixture_t& fixture, ucall_received_http_request_t request, std::size_t length) {
    std::string const answer = fmt::format("{}", length);
    ucall_outcome_t outcome {};
    ucall_server_reply_content_t reply {fixture.server, &outcome, request, nullptr, 0, uc::bytes_view(answer)};
    ucall_server_reply_content(&reply);
    return expect(outcome.status == ucall_status_success_k, "reply: {}", ucall_status_name(outcome.status));
}

/** Identity and chunked mebibyte bodies arrive through several pulls that add up to the bytes
 *  sent, a streamed request has no parts and no buffered body, and the reply reaches the peer. */
static case_result_t test_streamed_body_plain(random_generator_t& generator) {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    std::string const body = lettered_body();
    for (std::string_view const framing : {"Content-Length", "Transfer-Encoding"}) {
        announce("a body framed by {}", framing);
        std::string const request =
            framing == "Content-Length"
                ? fmt::format("POST /stream HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n{}", body.size(), body)
                : fmt::format("POST /stream HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n{}",
                              chunked_body(body, generator));
        raw_client_t client;
        require(failures + fixture.stop(), client.connect(fixture.address));
        bool written = false;
        std::thread writer {
            [&] { written = client.write(uc::byte_span(request), 65536, generator, steady_clock::now() + 5s); }};
        failures += await_held_in_background(fixture, 1);
        auto* held = fixture.take_held();
        if (!held) {
            writer.join();
            return failures + fixture.stop();
        }
        failures += expect(ucall_server_request_parts_count(fixture.server, held) == 0, "a streamed request had parts");
        ucall_outcome_t outcome {};
        ucall_bytes_view_t whole {};
        ucall_server_request_body_t buffered {fixture.server, &outcome, held, &whole};
        ucall_server_request_body(&buffered);
        failures += expect(outcome.status == ucall_status_invalid_argument_k, "a streamed body read whole: {}",
                           ucall_status_name(outcome.status));
        std::size_t pulls = 0;
        std::string const received = pull_body(fixture, held, failures, pulls);
        writer.join();
        failures += expect(written, "the request was not written");
        failures += expect(pulls > 2, "{} pulls took a mebibyte", pulls);
        failures += expect_bytes(uc::byte_span(received), uc::byte_span(body));
        failures += reply_length(fixture, held, received.size());
        auto const response = read_response(client, 0);
        failures += expect(response.status == 200 && response.body == fmt::format("{}", body.size()), "answered {} {}",
                           response.status, response.body);
    }
    return failures + fixture.stop();
}

/** The next completed call of the fixture's client alone, for cases whose server loops run in the
 *  background, or one with a timeout outcome after five seconds. */
static ucall_completed_call_t client_wait(fixture_t& fixture) {
    steady_clock::time_point const deadline = steady_clock::now() + 5s;
    ucall_completed_call_t completed {};
    std::size_t count = 0;
    while (!count && steady_clock::now() < deadline) {
        ucall_outcome_t outcome {};
        ucall_client_take_completed_t take {fixture.client, &outcome, &completed, 1, &count, 1000};
        ucall_client_take_completed(&take);
    }
    if (!count) completed.outcome.status = ucall_status_timeout_k;
    return completed;
}

/** Over Noise XX, a mebibyte the library client sends arrives through pulls byte for byte, and a
 *  multipart body splits into its parts. */
static case_result_t test_streamed_body_noise_xx() {
    fixture_t fixture {{.security = ucall_security_mode_noise_xx_k}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    std::string const body = lettered_body();
    std::string const stream_url = fmt::format("{}/stream", fixture.url);
    ucall_outcome_t outcome {};
    ucall_client_call_t call {};
    call.client = fixture.client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(stream_url);
    call.verb = ucall_verb_post_k;
    call.body = uc::bytes_view(body);
    call.options.security = ucall_security_mode_noise_xx_k;
    ucall_client_call(&call);
    failures += expect(outcome.status == ucall_status_success_k);
    // The client stays on the thread that made it, as single-issuer rings need; pulls run apart.
    std::string received;
    std::size_t pull_failures = 0;
    std::thread puller {[&] {
        pull_failures += await_held_in_background(fixture, 1);
        auto* held = fixture.take_held();
        std::size_t pulls = 0;
        if (held) received = pull_body(fixture, held, pull_failures, pulls);
        if (held) pull_failures += reply_length(fixture, held, received.size());
    }};
    ucall_completed_call_t completed = client_wait(fixture);
    puller.join();
    failures += pull_failures;
    failures += expect_bytes(uc::byte_span(received), uc::byte_span(body));
    failures += expect(completed.outcome.status == ucall_status_success_k && completed.response, "{}",
                       ucall_status_name(completed.outcome.status));
    if (completed.response) ucall_client_response_free(completed.response);
    std::string const parts_url = fmt::format("{}/parts", fixture.url);
    std::string_view const parts_body = "--zz\r\nContent-Disposition: form-data; name=\"k\"\r\n\r\nv\r\n--zz--";
    ucall_bytes_view_t const type = uc::bytes_view("Content-Type: multipart/form-data; boundary=zz");
    call.url = uc::bytes_view(parts_url);
    call.body = uc::bytes_view(parts_body);
    call.headers = &type;
    call.headers_count = 1;
    ucall_client_call(&call);
    completed = client_wait(fixture);
    ucall_bytes_view_t answer {};
    if (completed.response) {
        ucall_client_response_body_t get {completed.response, &outcome, &answer};
        ucall_client_response_body(&get);
    }
    failures += expect(uc::text_view(answer) == "1;k==v;", "the parts answered `{}`", uc::text_view(answer));
    if (completed.response) ucall_client_response_free(completed.response);
    return failures + fixture.stop();
}

/** A held stream whose bytes nobody pulls leaves another connection's hundred echoes unhindered. */
static case_result_t test_streamed_body_slow_puller(random_generator_t& generator) {
    fixture_t fixture {{.connections = 2}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    std::string const body = lettered_body();
    std::string const request = fmt::format("POST /stream HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n{}",
                                            body.size(), body);
    raw_client_t slow, quick;
    require(failures + fixture.stop(), slow.connect(fixture.address) && quick.connect(fixture.address));
    bool written = false;
    std::thread writer {
        [&] { written = slow.write(uc::byte_span(request), 65536, generator, steady_clock::now() + 5s); }};
    failures += await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    std::string_view const echo = "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi";
    for (std::size_t i = 0; i != 100; ++i) {
        std::size_t const offset = quick.received.size();
        failures += expect(::send(quick.descriptor, echo.data(), echo.size(), 0) == static_cast<ssize_t>(echo.size()));
        auto const response = read_response(quick, offset);
        if (response.status != 200 || response.body != "hi") {
            failures += expect(false, "echo {} answered {} {}", i, response.status, response.body);
            break;
        }
    }
    std::size_t pulls = 0;
    std::string const received = held ? pull_body(fixture, held, failures, pulls) : std::string {};
    writer.join();
    failures += expect(written && received == body, "the held stream took {} of {} bytes", received.size(),
                       body.size());
    if (held) failures += reply_length(fixture, held, received.size());
    return failures + fixture.stop();
}

/** A request pipelined behind a streamed body reaches its route only once the body was pulled
 *  through, and a reply sent before any pull still lets the request behind it through. */
static case_result_t test_streamed_body_barrier(random_generator_t& generator) {
    fixture_t fixture {{.pipelined_requests = 2}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    std::string const body = lettered_body();
    std::string const request = fmt::format(
        "POST /stream HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n{}GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n",
        body.size(), body);
    for (std::string_view const order : {"pull first", "reply first"}) {
        announce("{}", order);
        std::size_t const dispatched = fixture.dispatched.load();
        raw_client_t client;
        require(failures + fixture.stop(), client.connect(fixture.address));
        bool written = false;
        std::thread writer {
            [&] { written = client.write(uc::byte_span(request), 65536, generator, steady_clock::now() + 5s); }};
        failures += await_held_in_background(fixture, 1);
        auto* held = fixture.take_held();
        std::this_thread::sleep_for(20ms);
        failures += expect(fixture.dispatched.load() == dispatched, "a request behind the stream was dispatched");
        std::size_t pulls = 0;
        if (held && order == "pull first") {
            failures += expect(pull_body(fixture, held, failures, pulls) == body, "the body arrived altered");
            failures += reply_length(fixture, held, body.size());
        }
        else if (held) failures += reply_length(fixture, held, 0);
        writer.join();
        failures += expect(written, "the requests were not written");
        auto const first = read_response(client, 0);
        auto const second = read_response(client, first.length);
        failures += expect(first.status == 200 && second.status == 200, "answered {} and {}", first.status,
                           second.status);
        failures += expect(fixture.dispatched.load() == dispatched + 1, "the request behind the stream was not served");
    }
    return failures + fixture.stop();
}

/** A chunk size that is not hexadecimal ends the waiting pull as malformed and the stream. */
static case_result_t test_streamed_body_malformed() {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t client;
    require(failures + fixture.stop(), client.connect(fixture.address));
    std::string_view const request =
        "POST /stream HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\nzz\r\n";
    failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                       static_cast<ssize_t>(request.size()));
    failures += await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    ucall_status_t status = ucall_status_success_k;
    for (std::size_t pulls = 0; held && status == ucall_status_success_k && pulls != 3; ++pulls) {
        ucall_outcome_t outcome {};
        ucall_bytes_view_t data {};
        ucall_server_request_body_chunk_t pull {fixture.server, &outcome, held, &data};
        ucall_server_request_body_chunk(&pull);
        status = ucall_outcome_wait(&outcome);
    }
    failures += expect(status == ucall_status_malformed_k, "the bad chunk ended the pull with {}",
                       ucall_status_name(status));
    failures += expect(client.read_until_close(steady_clock::now() + 5s) == read_end_t::closed_k,
                       "the connection stayed open");
    return failures + fixture.stop();
}

/** Bodies past the request cap get 413 and an orderly close, framed by length or in chunks, and so
 *  does a head past it; the resolved configuration reports the cap. */
static case_result_t test_oversized_request_refused(random_generator_t& generator) {
    std::size_t const cap = 64 * 1024;
    fixture_t fixture {{.max_request_bytes = cap}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    failures += expect(fixture.resolved.interfaces[0].max_request_bytes == cap, "resolved a cap of {}",
                       fixture.resolved.interfaces[0].max_request_bytes);
    fixture.serve_in_background();
    std::string const body(2 * cap, 'b');
    std::string const field(cap, 'h');
    std::string const requests[] {
        fmt::format("POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n{}", body.size(), body),
        fmt::format("POST /echo/1 HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n{}",
                    chunked_body(body, generator)),
        fmt::format("GET /echo/1 HTTP/1.1\r\nHost: a\r\nX-Long: {}\r\n\r\n", field),
    };
    for (std::string const& request : requests) {
        announce("{} bytes beginning {}", request.size(), std::string_view {request}.substr(0, 20));
        raw_client_t client;
        require(failures + fixture.stop(), client.connect(fixture.address));
        bool written = false;
        std::thread writer {
            [&] { written = client.write(uc::byte_span(request), 65536, generator, steady_clock::now() + 5s); }};
        auto const response = read_response(client, 0);
        failures += expect(response.status == 413, "answered {}", response.status);
        failures += expect(client.read_until_close(steady_clock::now() + 5s) == read_end_t::closed_k,
                           "the refusal did not end in an orderly close");
        writer.join();
    }
    // A cap of zero takes what the kernel grants, which a mebibyte echo needs on stock settings.
    fixture_t derived {{}};
    require(failures + fixture.stop(), derived.status == ucall_status_success_k, "setup: {}",
            ucall_status_name(derived.status));
    failures += expect(derived.resolved.interfaces[0].max_request_bytes > 0, "no cap was derived");
    return failures + fixture.stop();
}

/** Parts split on the boundary only where a delimiter line starts, keep quoted names whole, may be
 *  empty or headerless, and a body missing its closing delimiter answers as malformed. */
static case_result_t test_multipart_parts() {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    struct row_t {
        std::string_view name, type, body, expected;
    };
    row_t const rows[] {
        {"quoted boundary", "multipart/form-data; boundary=\"b-1\"",
         "--b-1\r\nContent-Disposition: form-data; name=\"a;b\"\r\nContent-Type: text/plain\r\n\r\nx--b-1y\r\n"
         "--b-1\r\nContent-Disposition: form-data; name=empty\r\n\r\n\r\n--b-1\r\n\r\nheaderless\r\n--b-1--\r\n",
         "3;a;b=text/plain=x--b-1y;empty==;==headerless;"},
        {"preamble and padding", "Multipart/Form-Data; charset=utf-8; boundary=zz",
         "preamble\r\n--zz  \r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n--zz--epilogue", "1;f==v;"},
        {"no closing delimiter", "multipart/form-data; boundary=q",
         "--q\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n", "0;malformed;"},
        {"not multipart", "application/json", "{}", "0;malformed;"},
    };
    raw_client_t client;
    require(failures + fixture.stop(), client.connect(fixture.address));
    for (auto const& row : rows) {
        announce("{}", row.name);
        std::string const request = fmt::format(
            "POST /parts HTTP/1.1\r\nHost: a\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n{}", row.type,
            row.body.size(), row.body);
        std::size_t const offset = client.received.size();
        failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                           static_cast<ssize_t>(request.size()));
        auto const response = read_response(client, offset);
        failures += expect(response.status == 200 && response.body == row.expected, "{} answered {} `{}`", row.name,
                           response.status, response.body);
    }
    return failures + fixture.stop();
}

/** The value of every `name:value|type` line in @p lines whose tags contain @p tag, summed. */
static std::uint64_t metric_sum(std::vector<std::string> const& lines, std::string_view name, std::string_view tag) {
    std::uint64_t sum = 0;
    for (std::string_view line : lines) {
        if (!line.starts_with(name) || line.size() <= name.size() || line[name.size()] != ':') continue;
        if (!tag.empty() && line.find(tag) == std::string_view::npos) continue;
        std::uint64_t value = 0;
        std::from_chars(line.data() + name.size() + 1, line.data() + line.size(), value);
        sum += value;
    }
    return sum;
}

/** A StatsD listener receives counter deltas adding up to the requests served, a refusal tagged by
 *  status, a latency line per echo, and the prefix and global tags on every line; bad settings are
 *  refused and the resolved configuration fills the defaults. */
static case_result_t test_statsd_metrics() {
    int const listener = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in bound {};
    bound.sin_family = AF_INET;
    bound.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t length = sizeof(bound);
    require(0,
            listener >= 0 && ::bind(listener, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) == 0 &&
                ::getsockname(listener, reinterpret_cast<sockaddr*>(&bound), &length) == 0,
            "no UDP listener");
    std::string const address = fmt::format("127.0.0.1:{}", ntohs(bound.sin_port));
    std::size_t failures = 0;
    {
        fixture_t fixture {{.max_request_bytes = 4096, .metrics_address = address}};
        require(failures, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
        auto const& resolved = fixture.resolved;
        failures += expect(
            uc::text_view(resolved.metrics_prefix) == "probe" && resolved.metrics_sample_rate == 1.f &&
                resolved.metrics_tags_count == 2 && uc::text_view(resolved.metrics_tags[1]) == "team:core",
            "resolved prefix `{}` at rate {}", uc::text_view(resolved.metrics_prefix), resolved.metrics_sample_rate);
        std::string const echo_url = fmt::format("{}/echo/1", fixture.url),
                          missing_url = fmt::format("{}/missing", fixture.url);
        std::string const large(8192, 'l');
        auto call = [&](std::string const& url, std::string_view body) {
            ucall_outcome_t outcome {};
            ucall_client_call_t call {};
            call.client = fixture.client;
            call.outcome = &outcome;
            call.url = uc::bytes_view(url);
            call.verb = ucall_verb_post_k;
            call.body = uc::bytes_view(body);
            ucall_client_call(&call);
            auto completed = fixture.wait();
            if (completed.response) ucall_client_response_free(completed.response);
        };
        for (std::size_t i = 0; i != 50; ++i) call(echo_url, "hi");
        call(missing_url, "");
        call(echo_url, large);
        std::vector<std::string> lines;
        char datagram[65536];
        steady_clock::time_point const deadline = steady_clock::now() + 2s;
        while (metric_sum(lines, "probe.requests", "") < 51 || metric_sum(lines, "probe.refused", "status:413") < 1) {
            if (steady_clock::now() > deadline) break;
            ucall_completed_call_t completed {};
            failures += expect(!fixture.poll(completed), "a call completed unasked");
            for (ssize_t received; (received = ::recv(listener, datagram, sizeof(datagram), MSG_DONTWAIT)) > 0;)
                for (std::string_view rest {datagram, static_cast<std::size_t>(received)}; !rest.empty();) {
                    auto const end = std::min(rest.find('\n'), rest.size());
                    lines.emplace_back(rest.substr(0, end));
                    rest.remove_prefix(std::min(end + 1, rest.size()));
                }
        }
        failures += expect(metric_sum(lines, "probe.requests", "") == 51, "requests added up to {}",
                           metric_sum(lines, "probe.requests", ""));
        failures += expect(metric_sum(lines, "probe.refused", "status:413") == 1 &&
                               metric_sum(lines, "probe.refused", "status:404") == 1,
                           "refused {} with 413 and {} with 404", metric_sum(lines, "probe.refused", "status:413"),
                           metric_sum(lines, "probe.refused", "status:404"));
        std::size_t latencies = 0, untagged = 0;
        for (std::string_view line : lines) {
            latencies += line.starts_with("probe.latency:") &&
                         line.find("endpoint:/echo/{id}") != std::string_view::npos &&
                         line.find("status:200") != std::string_view::npos;
            untagged += line.find("|#env:test,team:core") == std::string_view::npos;
        }
        failures += expect(latencies == 50, "{} latency lines for 50 echoes", latencies);
        failures += expect(!untagged, "{} of {} lines lacked the global tags", untagged, lines.size());
        failures += fixture.stop();
    }
    ucall_network_interface_t network_interface {};
    network_interface.address = uc::bytes_view("127.0.0.1:0");
    network_interface.max_concurrent_connections = 1;
    ucall_bytes_view_t const bad_tag = uc::bytes_view("a,b");
    for (std::string_view const case_name : {"a rate past one", "a tag holding a comma"}) {
        ucall_server_config_t config {};
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
        config.metrics_address = uc::bytes_view(address);
        if (case_name == "a rate past one") config.metrics_sample_rate = 1.5f;
        else config.metrics_tags = &bad_tag, config.metrics_tags_count = 1;
        ucall_server_t server {};
        ucall_outcome_t outcome {};
        ucall_server_init_t init {&server, &outcome, &config, nullptr};
        ucall_server_init(&init);
        failures += expect(outcome.status == ucall_status_invalid_argument_k, "{} answered {}", case_name,
                           ucall_status_name(outcome.status));
        ucall_server_free(server);
    }
    ::close(listener);
    return failures;
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

    std::string url(std::string_view target) const { return fmt::format("http://{}{}", listener.address, target); }

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

#pragma region File Parts
#if UCALL_OS_POSIX_

/** Whether @p descriptor is still open. */
static bool open_descriptor(int descriptor) { return fcntl(descriptor, F_GETFD) != -1; }

/** The byte at @p offset of the patterned files, which a misplaced range never matches. */
static char pattern_byte(std::uint64_t offset) { return static_cast<char>((offset * 2654435761u) >> 13); }

/** Bytes one window reads in plaintext, which ranges straddle to cross from one window into the
 *  next. */
static constexpr std::uint64_t window_capacity_k = std::uint64_t {256} << 10;

/** The files that file and path parts read, in a directory whose filesystem serves unbuffered
 *  reads: `served` is what the server registers, beside `outside.txt`, for links to escape to. */
struct file_tree_t {
    static constexpr std::string_view hello_k = "hello, file parts\n";
    static constexpr std::size_t big_size_k = std::size_t {4} << 20;
    static constexpr std::uint64_t far_offset_k = (std::uint64_t {1} << 32) + 100;
    static constexpr std::string_view far_text_k = "far away";

    direct_directory_t directory;
    std::string served;
    bool prepared {};

    file_tree_t() : served(directory.name("served")) {
        std::error_code failed;
        if (!directory.ready() || !std::filesystem::create_directories(fmt::format("{}/subdir", served), failed))
            return;
        bool const written = write("hello.txt", hello_k) && write("subdir/inner.txt", "inner") &&
                             write("locked.txt", "locked") && write("big.bin", big()) &&
                             directory.write("outside.txt", "outside");
        bool const linked = chmod(name("locked.txt").c_str(), 0) == 0 && mkfifo(name("fifo").c_str(), 0600) == 0 &&
                            symlink("../outside.txt", name("outward").c_str()) == 0 &&
                            symlink("/etc/hostname", name("absolute").c_str()) == 0 &&
                            symlink("/proc/self/fd/0", name("magic").c_str()) == 0;
        int const sparse = ::open(name("sparse.bin").c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
        bool const extended = sparse >= 0 && ftruncate(sparse, static_cast<off_t>(far_offset_k + 4096)) == 0 &&
                              pwrite(sparse, far_text_k.data(), far_text_k.size(), static_cast<off_t>(far_offset_k)) ==
                                  static_cast<ssize_t>(far_text_k.size());
        if (sparse >= 0) ::close(sparse);
        prepared = written && linked && extended;
    }

    /** Why file cases cannot run here, or null once the tree is ready. */
    char const* unusable() const {
        if (prepared) return nullptr;
        static std::string reason;
        reason = directory.ready() ? fmt::format("the file tree could not be created in {}", directory.path)
                                   : directory.reason;
        return reason.c_str();
    }
    std::string name(std::string_view relative) const { return fmt::format("{}/{}", served, relative); }
    [[nodiscard]] bool write(std::string_view relative, std::string_view content) const {
        return directory.write(fmt::format("served/{}", relative), content);
    }

    /** Opens @p relative for the unbuffered reads every file part demands. */
    int open(std::string_view relative) const {
        return ::open(name(relative).c_str(), O_RDONLY | O_CLOEXEC | O_DIRECT);
    }

    /** The patterned bytes `big.bin` holds from @p offset on, @p length of them. */
    static std::string big(std::size_t offset = 0, std::size_t length = big_size_k) {
        std::string bytes(length, '\0');
        for (std::size_t i = 0; i != length; ++i) bytes[i] = pattern_byte(offset + i);
        return bytes;
    }
};

static ucall_reply_part_t file_part(int descriptor, std::uint64_t offset = 0, std::uint64_t length = 0) {
    ucall_reply_part_t part {};
    part.kind = ucall_reply_part_file_k;
    part.data.file = {descriptor, offset, length};
    return part;
}
static ucall_reply_part_t path_part(std::string_view path, std::uint64_t offset = 0, std::uint64_t length = 0,
                                    std::size_t directory = 0) {
    ucall_reply_part_t part {};
    part.kind = ucall_reply_part_path_k;
    part.data.path = {directory, uc::bytes_view(path), offset, length};
    return part;
}

/** Calls `/gate` with @p verb and polls until the server holds the request, which it answers. */
static ucall_received_http_request_t hold_call(fixture_t& fixture, ucall_verb_t verb, ucall_security_mode_t security,
                                               std::size_t& failures, std::string_view target = "/gate") {
    std::string const url = fmt::format("{}{}", fixture.url, target);
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
    failures += await_held(fixture, fixture.held_count() + 1);
    return fixture.take_held();
}

/** Polls the server until @p outcome is final, answering its status, or deferred after five
 *  seconds. */
static ucall_status_t await_outcome(fixture_t& fixture, ucall_outcome_t& outcome) {
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
static std::size_t expect_outcome(fixture_t& fixture, ucall_outcome_t& outcome, ucall_status_t expected) {
    ucall_status_t const status = await_outcome(fixture, outcome);
    return expect(status == expected, "the outcome turned {} rather than {}", ucall_status_name(status),
                  ucall_status_name(expected));
}

/** Replies @p request with @p parts under @p headers, expecting a deferred outcome on return. */
static std::size_t reply_parts(fixture_t& fixture, ucall_received_http_request_t request, ucall_outcome_t& outcome,
                               std::vector<ucall_reply_part_t> const& parts,
                               std::vector<ucall_bytes_view_t> const& headers = {},
                               ucall_status_t expected = ucall_status_deferred_k) {
    ucall_server_reply_vectored_t reply {fixture.server, &outcome,       request,      0,
                                         headers.data(), headers.size(), parts.data(), parts.size()};
    ucall_server_reply_vectored(&reply);
    ucall_status_t const status = ucall_outcome_status(&outcome);
    // A loop polled in the background may make a deferred outcome final before this reads it.
    bool const settled = expected == ucall_status_deferred_k && !fixture.pollers.empty();
    return expect(status == expected || settled, "vectored: {} rather than {}", ucall_status_name(status),
                  ucall_status_name(expected));
}

/** One counter of event loop zero, read from any thread. */
static ucall_event_loop_statistics_t loop_statistics(fixture_t& fixture) {
    ucall_outcome_t outcome {};
    ucall_event_loop_statistics_t statistics {};
    ucall_server_event_loop_statistics_t query {fixture.server, &outcome, 0, &statistics};
    ucall_server_event_loop_statistics(&query);
    return statistics;
}

/** Bytes, two ranges of one file, two paths, one far past 2^32 in a sparse file, arrive
 *  concatenated under a measured `content-length`; a @c HEAD request gets the length alone. Each
 *  outcome reads deferred on return and success once sent; the file's descriptor is still open by
 *  then, and the descriptors opened for the paths are not. */
static case_result_t file_parts_vectored(ucall_security_mode_t security) {
    file_tree_t tree;
    if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
    fixture_t fixture {{.security = security, .directory = tree.served}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    std::string const hello {file_tree_t::hello_k};
    std::string const expected = fmt::format("head|{}{}|{}{}|tail", hello.substr(7), file_tree_t::big(),
                                             file_tree_t::far_text_k, hello);
    for (ucall_verb_t verb : {ucall_verb_get_k, ucall_verb_head_k}) {
        announce("{} with every kind of part", verb == ucall_verb_get_k ? "GET" : "HEAD");
        int const file = tree.open("hello.txt");
        auto* request = hold_call(fixture, verb, security, failures);
        require(failures, request && file >= 0);
        std::size_t const descriptors = open_descriptors();
        ucall_outcome_t outcome {};
        failures += reply_parts(fixture, request, outcome,
                                {bytes_part("head|"), file_part(file, 7), path_part("big.bin"), bytes_part("|"),
                                 path_part("sparse.bin", file_tree_t::far_offset_k, file_tree_t::far_text_k.size()),
                                 file_part(file), bytes_part("|tail")});
        auto completed = fixture.wait();
        failures += expect(completed.outcome.status == ucall_status_success_k, "{}",
                           ucall_status_name(completed.outcome.status));
        if (completed.response)
            failures += expect(response_header(completed.response, "content-length") == std::to_string(expected.size()),
                               "content-length {}", response_header(completed.response, "content-length"));
        failures += check_answer(completed, ucall_http_status_ok_k, verb == ucall_verb_get_k ? expected : "");
        failures += expect_outcome(fixture, outcome, ucall_status_success_k);
        failures += expect(open_descriptor(file), "the file part's descriptor was closed");
        failures += expect(open_descriptors() == descriptors, "{} descriptors open before the reply, {} after",
                           descriptors, open_descriptors());
        ::close(file);
    }
    return failures + fixture.stop();
}
static case_result_t test_direct_files_plain() {
    return keeping_descriptors([] { return file_parts_vectored(ucall_security_mode_none_k); });
}
static case_result_t test_direct_files_noise_xx() {
    return keeping_descriptors([] { return file_parts_vectored(ucall_security_mode_noise_xx_k); });
}

/** Ranges starting and ending on every side of the unbuffered alignment A and of a window's
 *  capacity C arrive intact from four file sizes, measured from a path and chunked from a
 *  descriptor: each window reads aligned extents covering its slice and sends the slice alone. A
 *  measured range past the end earns @c 416. */
static case_result_t misaligned_ranges(ucall_security_mode_t security) {
    file_tree_t tree;
    if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
    fixture_t fixture {{.security = security, .directory = tree.served}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    std::uint64_t const alignment = tree.directory.alignment, capacity = window_capacity_k;
    std::uint64_t const offsets[] {0, 1, alignment - 1, alignment, alignment + 1, capacity - 1, capacity, capacity + 1};
    std::uint64_t const lengths[] {1, alignment - 1, alignment, capacity + 1, 2 * capacity + 3, 0};
    for (std::uint64_t size : {capacity - 1, 2 * capacity, 3 * capacity + alignment + 5, 4 * capacity + 3}) {
        announce("{} bytes at alignment {}", size, alignment);
        require(failures, tree.write("ranged.bin", file_tree_t::big(0, size)));
        int const file = tree.open("ranged.bin");
        require(failures, file >= 0);
        for (std::uint64_t offset : offsets)
            for (std::uint64_t length : lengths) {
                std::uint64_t const end = length ? offset + length : size;
                bool const fits = offset <= size && end <= size;
                std::string const body = fits ? file_tree_t::big(offset, end - offset) : std::string {};
                auto* measured = hold_call(fixture, ucall_verb_get_k, security, failures);
                require(failures, measured);
                ucall_outcome_t outcome {};
                failures += reply_parts(fixture, measured, outcome, {path_part("ranged.bin", offset, length)});
                failures += check_answer(fixture.wait(),
                                         fits ? ucall_http_status_ok_k : ucall_http_status_range_not_satisfiable_k,
                                         fits ? body : std::string_view {"Range not satisfiable"});
                failures += expect_outcome(fixture, outcome, fits ? ucall_status_success_k : ucall_status_overflow_k);
                if (!fits) continue;
                auto* chunked = hold_call(fixture, ucall_verb_get_k, security, failures);
                require(failures, chunked);
                ucall_outcome_t begun {}, appended {}, ended {};
                ucall_server_reply_begin_t begin {fixture.server, &begun, chunked, 0, nullptr, 0};
                ucall_server_reply_begin(&begin);
                ucall_reply_part_t const part = file_part(file, offset, length ? length : size - offset);
                ucall_server_reply_append_t append {fixture.server, &appended, chunked, &part, 1};
                ucall_server_reply_append(&append);
                ucall_server_reply_end_t finish {fixture.server, &ended, chunked};
                ucall_server_reply_end(&finish);
                failures += expect(begun.status == ucall_status_success_k && appended.status == ucall_status_success_k,
                                   "begin {}, append {}", ucall_status_name(begun.status),
                                   ucall_status_name(appended.status));
                failures += check_answer(fixture.wait(), ucall_http_status_ok_k, body);
                failures += expect_outcome(fixture, ended, ucall_status_success_k);
                if (failures) {
                    announce("first failure at offset {} for {} bytes", offset, length);
                    ::close(file);
                    return failures + fixture.stop();
                }
            }
        ::close(file);
    }
    return failures + fixture.stop();
}
static case_result_t test_misaligned_ranges_plain() {
    return keeping_descriptors([] { return misaligned_ranges(ucall_security_mode_none_k); });
}
static case_result_t test_misaligned_ranges_noise_xx() {
    return keeping_descriptors([] { return misaligned_ranges(ucall_security_mode_noise_xx_k); });
}

/** A path that is missing, unreadable, a FIFO, a directory, or a link out of the directory replaces
 *  the reply with @c 404, without hanging, and a range past the end with @c 416 naming the size;
 *  the outcome turns from deferred to the cause. Paths naming `..`, absolute ones, and directories
 *  past the interface's list are refused on the spot, leaving the descriptors with the caller. */
static case_result_t path_refusals(ucall_security_mode_t security) {
    file_tree_t tree;
    if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
    fixture_t fixture {{.security = security, .directory = tree.served}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    std::uint64_t const size = file_tree_t::hello_k.size();
    struct row_t {
        std::string_view path;
        std::uint64_t offset, length;
        ucall_http_status_t http_status;
        ucall_status_t status;
    };
    std::vector<row_t> rows {
        {"missing.txt", 0, 0, 404, ucall_status_not_found_k},     {"fifo", 0, 0, 404, ucall_status_not_found_k},
        {"subdir", 0, 0, 404, ucall_status_not_found_k},          {"outward", 0, 0, 404, ucall_status_not_found_k},
        {"absolute", 0, 0, 404, ucall_status_not_found_k},        {"magic", 0, 0, 404, ucall_status_not_found_k},
        {"hello.txt", size + 1, 0, 416, ucall_status_overflow_k}, {"hello.txt", 1, size, 416, ucall_status_overflow_k},
        {"subdir/inner.txt", 0, 0, 200, ucall_status_success_k},
    };
    // The superuser reads any mode, so only others can see an unreadable file refused.
    if (geteuid()) rows.push_back({"locked.txt", 0, 0, 404, ucall_status_not_found_k});
    for (row_t const& row : rows)
        for (ucall_verb_t verb : {ucall_verb_get_k, ucall_verb_head_k}) {
            announce("{} {} at {} for {} bytes", verb == ucall_verb_get_k ? "GET" : "HEAD", row.path, row.offset,
                     row.length);
            auto* request = hold_call(fixture, verb, security, failures);
            require(failures, request);
            ucall_outcome_t outcome {};
            failures += reply_parts(fixture, request, outcome,
                                    {bytes_part("never|"), path_part(row.path, row.offset, row.length)});
            auto completed = fixture.wait();
            failures += expect(completed.outcome.status == ucall_status_success_k && completed.response, "{}",
                               ucall_status_name(completed.outcome.status));
            if (!completed.response) continue;
            auto const answered = ucall_client_response_status(completed.response);
            failures += expect(answered == row.http_status, "answered {}", answered);
            if (row.http_status == 416)
                failures += expect(
                    response_header(completed.response, "content-range") == fmt::format("bytes */{}", size),
                    "content-range {}", response_header(completed.response, "content-range"));
            if (row.http_status == 200)
                failures += expect(response_body(completed.response) ==
                                   (verb == ucall_verb_get_k ? "never|inner" : ""));
            else failures += expect(response_body(completed.response).find("never") == std::string_view::npos);
            ucall_client_response_free(completed.response);
            failures += expect_outcome(fixture, outcome, row.status);
        }
    std::string_view const nul {"a\0b", 3};
    int const kept = tree.open("hello.txt");
    for (ucall_reply_part_t const& refused : {path_part("../hello.txt"), path_part("subdir/../../outside.txt"),
                                              path_part("/etc/hostname"), path_part("/proc/self/fd/0"), path_part(""),
                                              path_part(nul), path_part("hello.txt", 0, 0, 1), file_part(-1)}) {
        announce("refusing {:?}", refused.kind == ucall_reply_part_path_k
                                      ? uc::text_view(refused.data.path.relative_path)
                                      : std::string_view {"descriptor -1"});
        auto* request = hold_call(fixture, ucall_verb_get_k, security, failures);
        require(failures, request);
        ucall_outcome_t outcome {};
        failures += reply_parts(fixture, request, outcome, {file_part(kept), refused}, {},
                                ucall_status_invalid_argument_k);
        failures += expect(open_descriptor(kept), "a refused reply closed the caller's descriptor");
        ucall_server_reply_error_t error {fixture.server, &outcome, request, 400, uc::bytes_view("refused")};
        ucall_server_reply_error(&error);
        failures += expect(outcome.status == ucall_status_success_k);
        failures += check_answer(fixture.wait(), ucall_http_status_bad_request_k, "refused");
    }
    ::close(kept);
    return failures + fixture.stop();
}
static case_result_t test_path_refusals_plain() {
    return keeping_descriptors([] { return path_refusals(ucall_security_mode_none_k); });
}
static case_result_t test_path_refusals_noise_xx() {
    return keeping_descriptors([] { return path_refusals(ucall_security_mode_noise_xx_k); });
}

/** A descriptor opened without `O_DIRECT` is refused on the spot, vectored or streamed: nothing of
 *  its call is queued, and the caller keeps the descriptor. */
static case_result_t test_buffered_descriptor_refused() {
#if UCALL_OS_LINUX_
    return keeping_descriptors([]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        fixture_t fixture {{.directory = tree.served}};
        require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
        std::size_t failures = 0;
        int const buffered = ::open(tree.name("hello.txt").c_str(), O_RDONLY | O_CLOEXEC);
        require(failures, buffered >= 0);
        auto* vectored = hold_call(fixture, ucall_verb_get_k, ucall_security_mode_none_k, failures);
        require(failures, vectored);
        ucall_outcome_t outcome {};
        failures += reply_parts(fixture, vectored, outcome, {bytes_part("never"), file_part(buffered)}, {},
                                ucall_status_invalid_argument_k);
        ucall_server_reply_error_t error {fixture.server, &outcome, vectored, 400, uc::bytes_view("buffered")};
        ucall_server_reply_error(&error);
        failures += check_answer(fixture.wait(), ucall_http_status_bad_request_k, "buffered");
        auto* streamed = hold_call(fixture, ucall_verb_get_k, ucall_security_mode_none_k, failures);
        require(failures, streamed);
        ucall_server_reply_begin_t begin {fixture.server, &outcome, streamed, 0, nullptr, 0};
        ucall_server_reply_begin(&begin);
        std::vector<ucall_reply_part_t> const refused {bytes_part("never"), file_part(buffered)};
        ucall_server_reply_append_t append {fixture.server, &outcome, streamed, refused.data(), refused.size()};
        ucall_server_reply_append(&append);
        failures += expect(outcome.status == ucall_status_invalid_argument_k, "streamed: {}",
                           ucall_status_name(outcome.status));
        ucall_reply_part_t const kept = bytes_part("kept");
        ucall_server_reply_append_t again {fixture.server, &outcome, streamed, &kept, 1};
        ucall_server_reply_append(&again);
        ucall_outcome_t ended {};
        ucall_server_reply_end_t end {fixture.server, &ended, streamed};
        ucall_server_reply_end(&end);
        failures += check_answer(fixture.wait(), ucall_http_status_ok_k, "kept");
        failures += expect(open_descriptor(buffered), "the refused descriptor was closed");
        ::close(buffered);
        return failures + fixture.stop();
    });
#else
    return case_result_t::skipped("only Linux tells a buffered descriptor apart");
#endif
}

/** A path part answering a request on an interface that registered no directory is refused on the
 *  spot, while one on the interface owning the directory is served. */
static case_result_t test_path_beyond_interface() {
    return keeping_descriptors([]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        struct state_t {
            ucall_server_t server {};
            ucall_outcome_t deferred {}; // Outlives the callback, as the loop makes it final later.
            std::atomic<std::size_t> failures {};
        } state;
        auto answer = [](ucall_received_http_request_t request, void* context) {
            auto& owner = *static_cast<state_t*>(context);
            ucall_outcome_t outcome {};
            std::size_t network_interface_index = 0;
            ucall_noise_key_t key {};
            ucall_server_request_peer_t peer {owner.server, &outcome, request, &network_interface_index, &key};
            ucall_server_request_peer(&peer);
            ucall_reply_part_t const part = path_part("hello.txt");
            ucall_outcome_t& replied = network_interface_index ? outcome : owner.deferred;
            ucall_server_reply_vectored_t reply {owner.server, &replied, request, 0, nullptr, 0, &part, 1};
            ucall_server_reply_vectored(&reply);
            if (network_interface_index == 0) {
                owner.failures += expect(ucall_outcome_status(&replied) == ucall_status_deferred_k, "{}",
                                         ucall_status_name(ucall_outcome_status(&replied)));
                return;
            }
            owner.failures += expect(outcome.status == ucall_status_invalid_argument_k, "{}",
                                     ucall_status_name(outcome.status));
            ucall_server_reply_error_t error {owner.server, &outcome, request, 400, uc::bytes_view("no directory")};
            ucall_server_reply_error(&error);
        };
        ucall_bytes_view_t directory = uc::bytes_view(tree.served);
        ucall_network_interface_t interfaces[2] {};
        for (auto& network_interface : interfaces) {
            network_interface.address = uc::bytes_view("127.0.0.1:0");
            network_interface.max_concurrent_connections = 2;
        }
        interfaces[0].reply_directories = &directory;
        interfaces[0].reply_directories_count = 1;
        ucall_server_config_t config {};
        config.interfaces = interfaces;
        config.interfaces_count = 2;
        config.backend = backend_under_test;
        config.cpu_class = cpu_class_under_test;
        ucall_server_config_t resolved {};
        ucall_outcome_t outcome {};
        ucall_server_init_t init {&state.server, &outcome, &config, &resolved};
        ucall_server_init(&init);
        require(0, outcome.status == ucall_status_success_k, "init: {}", ucall_status_name(outcome.status));
        std::size_t failures = 0;
        failures += expect(resolved.interfaces[0].reply_directories_count == 1 &&
                           uc::text_view(resolved.interfaces[0].reply_directories[0]) == tree.served);
        ucall_server_add_http_endpoint_t add {state.server,     &outcome, uc::bytes_view("/file"),
                                              ucall_verb_get_k, answer,   &state};
        ucall_server_add_http_endpoint(&add);
        std::thread serving {[&] {
            ucall_outcome_t served {};
            ucall_server_take_calls_t calls {state.server, &served, 0};
            ucall_server_take_calls(&calls);
        }};
        std::string_view const request = "GET /file HTTP/1.1\r\nHost: a\r\n\r\n";
        for (std::size_t index : {0, 1}) {
            raw_client_t client;
            if (!client.connect(uc::text_view(resolved.interfaces[index].address))) {
                failures += expect(false, "connecting to interface {}", index);
                continue;
            }
            failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                               static_cast<ssize_t>(request.size()));
            auto const response = read_response(client, 0);
            failures += expect(response.status == (index ? 400u : 200u) &&
                                   response.body == (index ? "no directory" : file_tree_t::hello_k),
                               "interface {} answered {} {}", index, response.status, response.body);
        }
        ucall_server_stop(state.server);
        serving.join();
        ucall_server_free(state.server);
        failures += expect(ucall_outcome_status(&state.deferred) == ucall_status_success_k, "outcome {}",
                           ucall_status_name(state.deferred.status));
        // A directory that cannot be opened fails initialization with its cause.
        std::string const missing = fmt::format("{}/absent", tree.served);
        directory = uc::bytes_view(missing);
        ucall_server_t refused {};
        ucall_server_init_t again {&refused, &outcome, &config, nullptr};
        ucall_server_init(&again);
        failures += expect(outcome.status == ucall_status_not_found_k && !refused, "init with a missing directory: {}",
                           ucall_status_name(outcome.status));
        ucall_server_free(refused);
        return failures + state.failures.load();
    });
}

/** Streams memory, @p file, a path and memory again from a thread, with a zero-length range
 *  between, then ends with the outcome deferred until the parts are sent. */
static std::size_t stream_parts(fixture_t& fixture, ucall_received_http_request_t request, int file,
                                ucall_outcome_t& ended, std::vector<ucall_bytes_view_t> const& headers = {}) {
    std::size_t failures = 0;
    ucall_outcome_t outcome {};
    ucall_server_reply_begin_t begin {fixture.server, &outcome, request, 0, headers.data(), headers.size()};
    ucall_server_reply_begin(&begin);
    failures += expect(outcome.status == ucall_status_success_k, "begin: {}", ucall_status_name(outcome.status));
    std::vector<std::vector<ucall_reply_part_t>> const chunks {
        {bytes_part("memory|"), file_part(file, 0, 5)},
        {path_part("big.bin", 1000, 300000), path_part("hello.txt", file_tree_t::hello_k.size(), 0)},
        {bytes_part(""), bytes_part("|memory")},
    };
    for (auto const& chunk : chunks) {
        ucall_server_reply_append_t append {fixture.server, &outcome, request, chunk.data(), chunk.size()};
        for (ucall_server_reply_append(&append); outcome.status == ucall_status_would_block_k;
             ucall_server_reply_append(&append))
            std::this_thread::sleep_for(100us);
        failures += expect(outcome.status == ucall_status_success_k, "chunk: {}", ucall_status_name(outcome.status));
    }
    ucall_server_reply_end_t end {fixture.server, &ended, request};
    ucall_server_reply_end(&end);
    ucall_status_t const status = ucall_outcome_status(&ended);
    failures += expect(status == ucall_status_deferred_k || status == ucall_status_success_k, "end: {}",
                       ucall_status_name(status));
    return failures;
}
static std::string streamed_parts_body() {
    return fmt::format("memory|{}{}|memory", file_tree_t::hello_k.substr(0, 5), file_tree_t::big(1000, 300000));
}

/** A chunked stream mixing memory, file and path parts, a zero-length range among them, arrives
 *  whole through the library client, and two such replies pipelined on one connection keep their
 *  order. */
static case_result_t mixed_stream(ucall_security_mode_t security) {
    file_tree_t tree;
    if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
    fixture_t fixture {{.security = security, .pipelined_requests = 2, .pipelined_calls = 2, .directory = tree.served}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    std::array<std::string, 2> urls {fmt::format("{}/gate?n=0", fixture.url), fmt::format("{}/gate?n=1", fixture.url)};
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
    // The later request answers first, with a measured reply, while the earlier one streams.
    ucall_outcome_t measured {}, streamed {};
    failures += reply_parts(fixture, requests[1], measured, {path_part("big.bin"), bytes_part("|done")});
    int const file = tree.open("hello.txt");
    std::atomic<std::size_t> streamed_failures {};
    std::thread streamer {[&] { streamed_failures += stream_parts(fixture, requests[0], file, streamed); }};
    std::array<std::string, 2> const bodies {streamed_parts_body(), fmt::format("{}|done", file_tree_t::big())};
    for (std::size_t i = 0; i != 2; ++i) {
        auto completed = fixture.wait();
        failures += expect(completed.context == &urls[i], "call {} completed out of order", i);
        if (i == 0 && completed.response)
            failures += expect(response_header(completed.response, "transfer-encoding") == "chunked");
        failures += check_answer(completed, ucall_http_status_ok_k, bodies[i]);
    }
    streamer.join();
    failures += streamed_failures.load();
    failures += expect_outcome(fixture, measured, ucall_status_success_k);
    failures += expect_outcome(fixture, streamed, ucall_status_success_k);
    ::close(file);
    return failures + fixture.stop();
}
static case_result_t test_mixed_stream_plain() {
    return keeping_descriptors([] { return mixed_stream(ucall_security_mode_none_k); });
}
static case_result_t test_mixed_stream_noise_xx() {
    return keeping_descriptors([] { return mixed_stream(ucall_security_mode_noise_xx_k); });
}

/** The same mixed stream over the wire: chunked with every file chunk framed once sized and no
 *  framing for the zero-length range, identity under a declared `content-length`, which refuses a
 *  part it cannot size, and delimited by the close for an HTTP/1.0 peer. */
static case_result_t test_mixed_stream_framing() {
    return keeping_descriptors([]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        fixture_t fixture {{.connections = 3, .directory = tree.served}};
        require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
        fixture.serve_in_background();
        std::size_t failures = 0;
        std::string const body = streamed_parts_body();
        auto exchange = [&](std::string_view request, std::vector<ucall_bytes_view_t> const& headers,
                            raw_client_t& client) {
            failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                               static_cast<ssize_t>(request.size()));
            failures += await_held_in_background(fixture, 1);
            auto* held = fixture.take_held();
            int const file = tree.open("hello.txt");
            ucall_outcome_t ended {};
            failures += stream_parts(fixture, held, file, ended, headers);
            failures += expect_outcome(fixture, ended, ucall_status_success_k);
            ::close(file);
        };
        announce("chunked");
        raw_client_t client;
        require(failures + fixture.stop(), client.connect(fixture.address));
        exchange("GET /gate HTTP/1.1\r\nHost: a\r\n\r\n", {}, client);
        std::string expected_wire;
        std::string const big = file_tree_t::big(1000, 300000);
        for (std::string_view piece : {std::string_view {"memory|"}, file_tree_t::hello_k.substr(0, 5),
                                       std::string_view {big}, std::string_view {"|memory"}})
            expected_wire += fmt::format("{:x}\r\n{}\r\n", piece.size(), piece);
        expected_wire += "0\r\n\r\n";
        auto const deadline = steady_clock::now() + 5s;
        while (client.received.find("\r\n\r\n") == std::string::npos &&
               client.read(client.received.size() + 1, deadline) == read_end_t::filled_k) {}
        std::size_t const head = client.received.find("\r\n\r\n") + 4;
        [[maybe_unused]] auto const read = client.read(head + expected_wire.size(), deadline);
        failures += expect(std::string_view {client.received}.substr(head) == expected_wire,
                           "the chunked body differs over {} bytes", client.received.size() - head);
        announce("identity");
        std::string const length = fmt::format("Content-Length: {}", body.size());
        raw_client_t identity;
        require(failures + fixture.stop(), identity.connect(fixture.address));
        std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
        failures += expect(::send(identity.descriptor, request.data(), request.size(), 0) ==
                           static_cast<ssize_t>(request.size()));
        failures += await_held_in_background(fixture, 1);
        auto* held = fixture.take_held();
        ucall_bytes_view_t const declared = uc::bytes_view(length);
        ucall_outcome_t outcome {};
        ucall_server_reply_begin_t begin {fixture.server, &outcome, held, 0, &declared, 1};
        ucall_server_reply_begin(&begin);
        int const file = tree.open("hello.txt");
        ucall_reply_part_t const unsized = file_part(file);
        ucall_server_reply_append_t refused {fixture.server, &outcome, held, &unsized, 1};
        ucall_server_reply_append(&refused);
        failures += expect(outcome.status == ucall_status_invalid_argument_k, "an unsized part: {}",
                           ucall_status_name(outcome.status));
        std::vector<ucall_reply_part_t> const parts {bytes_part("memory|"), file_part(file, 0, 5),
                                                     path_part("big.bin", 1000, 300000), bytes_part("|memory")};
        ucall_server_reply_append_t append {fixture.server, &outcome, held, parts.data(), parts.size()};
        ucall_server_reply_append(&append);
        failures += expect(outcome.status == ucall_status_success_k, "chunk: {}", ucall_status_name(outcome.status));
        ucall_outcome_t ended {};
        ucall_server_reply_end_t end {fixture.server, &ended, held};
        ucall_server_reply_end(&end);
        auto const response = read_response(identity, 0);
        failures += expect(response.status == 200 && response.body == body, "identity answered {} with {} bytes",
                           response.status, response.body.size());
        failures += expect_outcome(fixture, ended, ucall_status_success_k);
        ::close(file);
        announce("HTTP/1.0");
        raw_client_t legacy;
        require(failures + fixture.stop(), legacy.connect(fixture.address));
        exchange("GET /gate HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", {}, legacy);
        auto const end_of_stream = legacy.read_until_close(steady_clock::now() + 5s);
        failures += expect(end_of_stream == read_end_t::closed_k, "the read ended as {}",
                           static_cast<int>(end_of_stream));
        std::size_t const legacy_head = legacy.received.find("\r\n\r\n");
        failures += expect(legacy_head != std::string::npos && legacy.received.substr(legacy_head + 4) == body,
                           "the close-delimited body differs");
        return failures + fixture.stop();
    });
}

/** Bodies around one and two whole Noise records arrive intact, whether a file read into a window,
 *  an echoed body copied into one segment of records with gaps, or a streamed chunk, so every
 *  record seals in place with no neighbour's bytes saved and restored. */
static case_result_t test_noise_record_boundaries() {
    return keeping_descriptors([]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        auto const security = ucall_security_mode_noise_xx_k;
        fixture_t fixture {{.security = security, .directory = tree.served}};
        require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
        std::size_t failures = 0;
        // A record's payload is a 16-bit length less its kind byte and its tag.
        constexpr std::size_t payload = 65535 - 1 - 16;
        std::vector<std::size_t> sizes {payload - 1,     payload,     payload + 1,
                                        2 * payload - 1, 2 * payload, 2 * payload + 1};
        // An echo's head fills part of its first record, so these walk its body over the boundary.
        for (std::size_t size = payload - 200; size != payload - 100; ++size) sizes.push_back(size);
        for (std::size_t size : sizes) {
            std::string const body = file_tree_t::big(0, size);
            require(failures, tree.write("sized.bin", body));
            auto* request = hold_call(fixture, ucall_verb_get_k, security, failures);
            require(failures, request);
            ucall_outcome_t outcome {};
            failures += reply_parts(fixture, request, outcome, {path_part("sized.bin")});
            failures += check_answer(fixture.wait(), ucall_http_status_ok_k, body);
            failures += expect_outcome(fixture, outcome, ucall_status_success_k);
            std::string const echo_url = fmt::format("{}/echo/1", fixture.url);
            ucall_outcome_t called {};
            ucall_client_call_t call {};
            call.client = fixture.client;
            call.outcome = &called;
            call.url = uc::bytes_view(echo_url);
            call.verb = ucall_verb_post_k;
            call.body = uc::bytes_view(body);
            call.options.security = security;
            call.options.server_key = &fixture.server_public;
            ucall_client_call(&call);
            failures += check_answer(fixture.wait(), ucall_http_status_ok_k, body);
            auto* streamed = hold_call(fixture, ucall_verb_get_k, security, failures);
            require(failures, streamed);
            ucall_server_reply_begin_t begin {fixture.server, &outcome, streamed, 0, nullptr, 0};
            ucall_server_reply_begin(&begin);
            ucall_reply_part_t const chunk = bytes_part(body);
            ucall_server_reply_append_t append {fixture.server, &outcome, streamed, &chunk, 1};
            ucall_server_reply_append(&append);
            ucall_server_reply_end_t end {fixture.server, &outcome, streamed};
            ucall_server_reply_end(&end);
            failures += check_answer(fixture.wait(), ucall_http_status_ok_k, body);
            if (failures) {
                announce("first failure at {} bytes", size);
                break;
            }
        }
        return failures + fixture.stop();
    });
}

/** A file shrinking under a reply whose head left resets the connection, so the peer never takes
 *  the cut body for a whole one, and the deferred outcome reports @c ucall_status_io_k. */
static case_result_t test_short_file_reset() {
    return keeping_descriptors([]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        fixture_t fixture {{.directory = tree.served}};
        require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
        fixture.serve_in_background();
        std::size_t failures = 0;
        // Far more than the loopback buffers hold, so the server is mid-file when it shrinks.
        int const shrinking = ::open(tree.name("shrinking.bin").c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_DIRECT, 0600);
        require(failures + fixture.stop(), shrinking >= 0 && ftruncate(shrinking, off_t {256} << 20) == 0);
        raw_client_t client;
        require(failures + fixture.stop(), client.connect(fixture.address));
        std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
        failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                           static_cast<ssize_t>(request.size()));
        failures += await_held_in_background(fixture, 1);
        ucall_outcome_t outcome {};
        failures += reply_parts(fixture, fixture.take_held(), outcome, {file_part(shrinking)});
        auto const deadline = steady_clock::now() + 5s;
        while (client.received.find("\r\n\r\n") == std::string::npos &&
               client.read(client.received.size() + 1, deadline) == read_end_t::filled_k) {}
        failures += expect(ftruncate(shrinking, 4096) == 0);
        auto const end = client.read_until_close(steady_clock::now() + 10s);
        int const error = errno;
        failures += expect(end == read_end_t::failed_k && error == ECONNRESET, "the read ended as {} with errno {}",
                           static_cast<int>(end), error);
        failures += expect_outcome(fixture, outcome, ucall_status_io_k);
        failures += expect(open_descriptor(shrinking), "the borrowed descriptor was closed");
        ::close(shrinking);
        return failures + fixture.stop();
    });
}

/** Under Noise, the same shrinking file fails the call and reports @c ucall_status_io_k. */
static case_result_t test_short_file_noise_xx() {
    return keeping_descriptors([]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        auto const security = ucall_security_mode_noise_xx_k;
        fixture_t fixture {{.security = security, .directory = tree.served}};
        require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
        std::size_t failures = 0;
        int const shrinking = ::open(tree.name("shrinking.bin").c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_DIRECT, 0600);
        require(failures, shrinking >= 0 && ftruncate(shrinking, off_t {64} << 20) == 0);
        // A lost POST is never retried, so the cut reply ends the call.
        auto* request = hold_call(fixture, ucall_verb_post_k, security, failures);
        require(failures, request);
        ucall_outcome_t outcome {};
        failures += reply_parts(fixture, request, outcome, {file_part(shrinking)});
        // A few rounds size the file and send its head and first records before it shrinks.
        for (std::size_t round = 0; round != 8; ++round) {
            ucall_completed_call_t completed {};
            failures += expect(!fixture.poll(completed), "the call completed before the file shrank");
        }
        failures += expect(ftruncate(shrinking, 4096) == 0);
        auto completed = fixture.wait();
        failures += expect(completed.outcome.status != ucall_status_success_k, "a cut body read as whole");
        ucall_client_response_free(completed.response);
        failures += expect_outcome(fixture, outcome, ucall_status_io_k);
        ::close(shrinking);
        return failures + fixture.stop();
    });
}

/** A peer leaving mid-file makes the deferred outcome @c ucall_status_connection_closed_k, and the
 *  server goes on answering others. */
static case_result_t test_file_detach() {
    return keeping_descriptors([]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        fixture_t fixture {{.connections = 2, .directory = tree.served}};
        require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
        fixture.serve_in_background();
        std::size_t failures = 0;
        int const huge = ::open(tree.name("huge.bin").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        require(failures + fixture.stop(), huge >= 0 && ftruncate(huge, off_t {256} << 20) == 0);
        ::close(huge);
        raw_client_t client;
        require(failures + fixture.stop(), client.connect(fixture.address));
        std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
        failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                           static_cast<ssize_t>(request.size()));
        failures += await_held_in_background(fixture, 1);
        ucall_outcome_t outcome {};
        failures += reply_parts(fixture, fixture.take_held(), outcome, {path_part("huge.bin")});
        auto const deadline = steady_clock::now() + 5s;
        while (client.received.find("\r\n\r\n") == std::string::npos &&
               client.read(client.received.size() + 1, deadline) == read_end_t::filled_k) {}
        client.close();
        failures += expect_outcome(fixture, outcome, ucall_status_connection_closed_k);
        raw_client_t other;
        require(failures + fixture.stop(), other.connect(fixture.address));
        std::string_view const echo = "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nok";
        failures += expect(::send(other.descriptor, echo.data(), echo.size(), 0) == static_cast<ssize_t>(echo.size()));
        auto const response = read_response(other, 0);
        failures += expect(response.status == 200 && response.body == "ok", "answered {} {}", response.status,
                           response.body);
        return failures + fixture.stop();
    });
}

/** Stopping the server while it opens a reply's many paths still makes the outcome final, and
 *  freeing it leaves no descriptor open. */
static case_result_t test_stop_while_opening() {
    return keeping_descriptors([]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        ucall_outcome_t outcome {};
        std::size_t failures = 0;
        {
            fixture_t fixture {{.directory = tree.served}};
            require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
            fixture.serve_in_background();
            raw_client_t client;
            require(failures + fixture.stop(), client.connect(fixture.address));
            std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
            failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                               static_cast<ssize_t>(request.size()));
            failures += await_held_in_background(fixture, 1);
            std::vector<ucall_reply_part_t> parts(256, path_part("big.bin"));
            failures += reply_parts(fixture, fixture.take_held(), outcome, parts);
            ucall_server_stop(fixture.server);
            failures += fixture.stop();
        }
        failures += expect(ucall_outcome_status(&outcome) != ucall_status_deferred_k, "the outcome stayed deferred");
        return failures;
    });
}

/** Stopping the server while a peer that reads nothing holds a file's windows in its socket ends
 *  within two linger periods: the close lingers for the kernel to let go of the windows, then
 *  resets the peer, and the loop frees its pool only once every window came back. */
static case_result_t test_stop_while_releasing() {
    return keeping_descriptors([]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        ucall_outcome_t outcome {};
        std::size_t failures = 0;
        raw_client_t client;
        {
            fixture_t fixture {{.directory = tree.served}};
            require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
            fixture.serve_in_background();
            int const huge = ::open(tree.name("huge.bin").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
            require(failures + fixture.stop(), huge >= 0 && ftruncate(huge, off_t {64} << 20) == 0);
            ::close(huge);
            require(failures + fixture.stop(), client.connect(fixture.address));
            int const small = 4096;
            failures += expect(setsockopt(client.descriptor, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small)) == 0);
            std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
            failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                               static_cast<ssize_t>(request.size()));
            failures += await_held_in_background(fixture, 1);
            failures += reply_parts(fixture, fixture.take_held(), outcome, {path_part("huge.bin")});
            auto const deadline = steady_clock::now() + 5s;
            while (client.received.find("\r\n\r\n") == std::string::npos &&
                   client.read(client.received.size() + 1, deadline) == read_end_t::filled_k) {}
            std::this_thread::sleep_for(50ms);
            auto const stopping = steady_clock::now();
            ucall_server_stop(fixture.server);
            failures += fixture.stop();
            auto const stopped = steady_clock::now() - stopping;
            failures += expect(stopped < 3s, "stopping took {} ms",
                               std::chrono::duration_cast<std::chrono::milliseconds>(stopped).count());
        }
        failures += expect(ucall_outcome_status(&outcome) == ucall_status_connection_closed_k, "the outcome turned {}",
                           ucall_status_name(ucall_outcome_status(&outcome)));
        // A wider window drains what an orderly close still delivers, instead of a trickle.
        int const wide = 4 << 20;
        failures += expect(setsockopt(client.descriptor, SOL_SOCKET, SO_RCVBUF, &wide, sizeof(wide)) == 0);
        auto const end = client.read_until_close(steady_clock::now() + 5s);
        failures += expect(end == read_end_t::closed_k || end == read_end_t::failed_k, "the read ended as {}",
                           static_cast<int>(end));
        return failures;
    });
}

/** A peer that stops reading after a `connection: close` reply holds its connection no longer
 *  than two linger periods: the close lingers for the peer's FIN and for the kernel to let go of
 *  what it sent without copying, resets once the deadline passes with the reply still unread,
 *  and frees the one connection slot for the next peer. A copying engine closes in order. */
static case_result_t test_linger_then_reset() {
#if UCALL_OS_POSIX_
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t silent;
    require(failures + fixture.stop(), silent.connect(fixture.address));
    int const small = 4096;
    failures += expect(setsockopt(silent.descriptor, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small)) == 0);
    std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    failures += expect(::send(silent.descriptor, request.data(), request.size(), 0) ==
                       static_cast<ssize_t>(request.size()));
    failures += await_held_in_background(fixture, 1);
    // Zero-copy engines take one send far past the peer's window, so its release waits on the peer,
    // while a copying engine takes only what fits its socket buffer.
    bool const copies = backend_under_test == ucall_io_backend_posix_k;
    std::string const body(copies ? 12000 : std::size_t {1} << 20, 'l');
    ucall_outcome_t outcome {};
    ucall_server_reply_content_t reply {fixture.server, &outcome, fixture.take_held(),
                                        nullptr,        0,        uc::bytes_view(body)};
    auto const replied = steady_clock::now();
    ucall_server_reply_content(&reply);
    failures += expect(outcome.status == ucall_status_success_k, "reply: {}", ucall_status_name(outcome.status));
    raw_client_t next;
    require(failures + fixture.stop(), next.connect(fixture.address));
    std::string_view const echo = "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nok";
    failures += expect(::send(next.descriptor, echo.data(), echo.size(), 0) == static_cast<ssize_t>(echo.size()));
    auto const response = read_response(next, 0);
    auto const freed = std::chrono::duration_cast<std::chrono::milliseconds>(steady_clock::now() - replied);
    failures += expect(response.body == "ok" && freed < 4s, "the next peer was served after {} ms", freed.count());
    auto const end = silent.read_until_close(steady_clock::now() + 5s);
    int const error = errno;
    bool const reset = end == read_end_t::failed_k && error == ECONNRESET;
    bool const whole = end == read_end_t::closed_k && parse_response(silent.received).body == body;
    failures += expect(copies ? whole : reset, "the read ended as {} with {} bytes", static_cast<int>(end),
                       silent.received.size());
    announce("{} after {} ms", reset ? "reset" : "closed in order", freed.count());
    return failures + fixture.stop();
#else
    return case_result_t::skipped("raw sockets need POSIX");
#endif
}

/** A file of eight windows sent to a peer reading slowly reads each window while the one before it
 *  waits or sends, as the loop counts at least six such overlaps, and arrives byte for byte. */
static case_result_t test_file_window_overlap() {
    return keeping_descriptors([]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        fixture_t fixture {{.directory = tree.served}};
        require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
        fixture.serve_in_background();
        std::size_t failures = 0;
        std::string const body = file_tree_t::big(0, 8 * window_capacity_k);
        require(failures + fixture.stop(), tree.write("eight.bin", body));
        raw_client_t client;
        require(failures + fixture.stop(), client.connect(fixture.address));
        std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
        failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                           static_cast<ssize_t>(request.size()));
        failures += await_held_in_background(fixture, 1);
        std::uint64_t const before = loop_statistics(fixture).file_window_overlaps;
        ucall_outcome_t outcome {};
        failures += reply_parts(fixture, fixture.take_held(), outcome, {path_part("eight.bin")});
        auto const deadline = steady_clock::now() + 10s;
        wire_response_t response;
        while (!(response = parse_response(client.received)).length &&
               client.read(client.received.size() + 1, deadline) == read_end_t::filled_k)
            std::this_thread::sleep_for(1ms);
        failures += expect(response.status == 200 && response.body == body, "answered {} with {} bytes of {} read",
                           response.status, response.body.size(), client.received.size());
        failures += expect_outcome(fixture, outcome, ucall_status_success_k);
        ucall_event_loop_statistics_t const statistics = loop_statistics(fixture);
        std::uint64_t const overlaps = statistics.file_window_overlaps - before;
        announce("{} zero-copy sends, {} copied anyway", statistics.zero_copy_sends, statistics.zero_copy_fallbacks);
        failures += expect(overlaps >= 6, "{} reads overlapped a send", overlaps);
        return failures + fixture.stop();
    });
}

/** A peer that never reads takes no more than its windows: eight others fetch four mebibytes each
 *  meanwhile, byte for byte, and the stalled reply ends once its peer leaves. */
static case_result_t test_file_fairness() {
    return keeping_descriptors([]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        constexpr std::size_t readers_count = 8;
        fixture_t fixture {{.connections = readers_count + 1, .directory = tree.served}};
        require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
        fixture.serve_in_background();
        std::size_t failures = 0;
        std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
        // Far more than loopback buffers hold, behind a small receive buffer, so it surely stalls.
        int const huge = ::open(tree.name("huge.bin").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        require(failures + fixture.stop(), huge >= 0 && ftruncate(huge, off_t {256} << 20) == 0);
        ::close(huge);
        raw_client_t stalled;
        require(failures + fixture.stop(), stalled.connect(fixture.address));
        int const small = 4096;
        failures += expect(setsockopt(stalled.descriptor, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small)) == 0);
        failures += expect(::send(stalled.descriptor, request.data(), request.size(), 0) ==
                           static_cast<ssize_t>(request.size()));
        failures += await_held_in_background(fixture, 1);
        ucall_outcome_t stalled_outcome {};
        failures += reply_parts(fixture, fixture.take_held(), stalled_outcome, {path_part("huge.bin")});
        std::array<raw_client_t, readers_count> readers;
        for (auto& reader : readers) {
            require(failures + fixture.stop(), reader.connect(fixture.address));
            failures += expect(::send(reader.descriptor, request.data(), request.size(), 0) ==
                               static_cast<ssize_t>(request.size()));
        }
        failures += await_held_in_background(fixture, readers_count);
        std::array<ucall_outcome_t, readers_count> outcomes {};
        for (auto& outcome : outcomes)
            failures += reply_parts(fixture, fixture.take_held(), outcome, {path_part("big.bin")});
        std::string const expected = file_tree_t::big();
        std::atomic<std::size_t> read_failures {};
        std::vector<std::thread> threads;
        for (auto& reader : readers)
            threads.emplace_back([&] {
                auto const response = read_response(reader, 0);
                read_failures += expect(response.status == 200 && response.body == expected,
                                        "answered {} with {} bytes", response.status, response.body.size());
            });
        for (auto& thread : threads) thread.join();
        for (auto& outcome : outcomes) failures += expect_outcome(fixture, outcome, ucall_status_success_k);
        failures += expect(ucall_outcome_status(&stalled_outcome) == ucall_status_deferred_k,
                           "the stalled reply finished unread");
        stalled.close();
        failures += expect_outcome(fixture, stalled_outcome, ucall_status_connection_closed_k);
        return failures + read_failures.load() + fixture.stop();
    });
}

#if UCALL_WITH_POSIX
using counted_network_t = uc::serial_network<uc::posix_engine_t, counting_allocator<uc::byte_t>>;
#endif

/** Once a keep-alive connection served one request, its second file reply allocates nothing: the
 *  exchange, file segment, window and segments all come back from the first. */
static case_result_t test_warm_file_reply_allocates_nothing() {
#if UCALL_WITH_POSIX
    return keeping_descriptors([]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        struct route_t {
            ucall_server_t server {};
            std::array<ucall_outcome_t, 3> deferred {};
            std::size_t replies {};
            static void serve(ucall_received_http_request_t request, void* context) {
                auto& route = *static_cast<route_t*>(context);
                ucall_reply_part_t const parts[] {bytes_part("head|"), path_part("big.bin", 3, 600000)};
                // The first request only warms the connection's receive buffer.
                ucall_server_reply_vectored_t reply {
                    route.server, &route.deferred[route.replies], request, 0, nullptr, 0,
                    parts,        route.replies ? 2u : 1u};
                ++route.replies;
                ucall_server_reply_vectored(&reply);
            }
        } route;
        allocation_counts_t counts;
        ucall_bytes_view_t const directory = uc::bytes_view(tree.served);
        ucall_network_interface_t network_interface {};
        network_interface.address = uc::bytes_view("127.0.0.1:0");
        network_interface.max_concurrent_connections = 1;
        network_interface.reply_directories = &directory;
        network_interface.reply_directories_count = 1;
        ucall_server_config_t config {}, resolved {};
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
        config.backend = ucall_io_backend_posix_k;
        ucall_outcome_t outcome {};
        ucall_server_init_t init {&route.server, &outcome, &config, &resolved};
        counted_network_t::server_init(&init, counting_allocator<uc::byte_t> {counts});
        require(0, outcome.status == ucall_status_success_k, "init: {}", ucall_status_name(outcome.status));
        std::size_t failures = 0;
        ucall_server_add_http_endpoint_t add {route.server,     &outcome,       uc::bytes_view("/file"),
                                              ucall_verb_get_k, route_t::serve, &route};
        ucall_server_add_http_endpoint(&add);
        raw_client_t client;
        require(failures, client.connect(uc::text_view(resolved.interfaces[0].address)));
        std::string const file_body = fmt::format("head|{}", file_tree_t::big(3, 600000));
        std::string_view const request = "GET /file HTTP/1.1\r\nHost: a\r\n\r\n";
        std::size_t warm_allocations = 0;
        for (std::size_t round = 0; round != 3; ++round) {
            std::string_view const expected = round ? std::string_view {file_body} : std::string_view {"head|"};
            if (round == 2) warm_allocations = counts.allocations;
            failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                               static_cast<ssize_t>(request.size()));
            std::size_t const offset = client.received.size();
            auto const deadline = steady_clock::now() + 5s;
            wire_response_t response;
            while (!(response = parse_response(std::string_view {client.received}.substr(offset))).length &&
                   steady_clock::now() < deadline) {
                ucall_server_take_call_t serving {route.server, &outcome, 0, 0};
                ucall_server_take_call(&serving);
                [[maybe_unused]] auto const read = client.read(client.received.size() + 1, steady_clock::now());
            }
            failures += expect(response.status == 200 && response.body == expected,
                               "round {} answered {} with {} bytes", round, response.status, response.body.size());
            while (ucall_outcome_status(&route.deferred[round]) == ucall_status_deferred_k &&
                   steady_clock::now() < deadline) {
                ucall_server_take_call_t serving {route.server, &outcome, 0, 0};
                ucall_server_take_call(&serving);
            }
        }
        failures += expect(counts.allocations == warm_allocations, "the warm reply allocated {} times",
                           counts.allocations - warm_allocations);
        client.close();
        ucall_server_free(route.server);
        failures += expect(!counts.live(), "{} allocations outlived the server", counts.live());
        return failures;
    });
#else
    return case_result_t::skipped("the POSIX backend is not compiled");
#endif
}

#endif // UCALL_OS_POSIX_
#pragma endregion File Parts

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
    uc::io_request_t receiving {.operation = uc::io_operation_t::receive_k,
                                .descriptor = owned,
                                .data = buffer.data(),
                                .length = buffer.size()};
    uc::io_request_t sending {.operation = uc::io_operation_t::send_k,
                              .descriptor = owned,
                              .data = payload.data(),
                              .length = payload.size()};
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
#if UCALL_WITH_LINUX_EPOLLAIO
    case ucall_io_backend_linux_epollaio_k: return engine_duplex<uc::linux_epollaio_engine_t>(generator);
#endif
#if UCALL_WITH_LINUX_URING
    case ucall_io_backend_linux_uring612_k: return engine_duplex<uc::linux_uring612_engine_t>(generator);
    case ucall_io_backend_linux_uring618_k: return engine_duplex<uc::linux_uring618_engine_t>(generator);
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
        command = fmt::format("{} {} {}", command, argv[index], argv[index + 1]);
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
    run_test(totals, "test_exchanges_noise_kk", test_exchanges_noise_kk);
    run_test(totals, "test_server_kk_wrong_initiator", test_server_kk_wrong_initiator);
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
    run_test(totals, "test_configuration_byte_views", test_configuration_byte_views);
    run_test(totals, "test_streamed_body_plain", test_streamed_body_plain);
    run_test(totals, "test_streamed_body_noise_xx", test_streamed_body_noise_xx);
    run_test(totals, "test_streamed_body_slow_puller", test_streamed_body_slow_puller);
    run_test(totals, "test_streamed_body_barrier", test_streamed_body_barrier);
    run_test(totals, "test_streamed_body_malformed", test_streamed_body_malformed);
    run_test(totals, "test_oversized_request_refused", test_oversized_request_refused);
    run_test(totals, "test_multipart_parts", test_multipart_parts);
    run_test(totals, "test_statsd_metrics", test_statsd_metrics);
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
    run_test(totals, "test_direct_files_plain", test_direct_files_plain);
    run_test(totals, "test_direct_files_noise_xx", test_direct_files_noise_xx);
    run_test(totals, "test_misaligned_ranges_plain", test_misaligned_ranges_plain);
    run_test(totals, "test_misaligned_ranges_noise_xx", test_misaligned_ranges_noise_xx);
    run_test(totals, "test_path_refusals_plain", test_path_refusals_plain);
    run_test(totals, "test_path_refusals_noise_xx", test_path_refusals_noise_xx);
    run_test(totals, "test_buffered_descriptor_refused", test_buffered_descriptor_refused);
    run_test(totals, "test_path_beyond_interface", test_path_beyond_interface);
    run_test(totals, "test_mixed_stream_plain", test_mixed_stream_plain);
    run_test(totals, "test_mixed_stream_noise_xx", test_mixed_stream_noise_xx);
    run_test(totals, "test_mixed_stream_framing", test_mixed_stream_framing);
    run_test(totals, "test_noise_record_boundaries", test_noise_record_boundaries);
    run_test(totals, "test_short_file_reset", test_short_file_reset);
    run_test(totals, "test_short_file_noise_xx", test_short_file_noise_xx);
    run_test(totals, "test_file_detach", test_file_detach);
    run_test(totals, "test_stop_while_opening", test_stop_while_opening);
    run_test(totals, "test_stop_while_releasing", test_stop_while_releasing);
    run_test(totals, "test_linger_then_reset", test_linger_then_reset);
    run_test(totals, "test_file_window_overlap", test_file_window_overlap);
    run_test(totals, "test_file_fairness", test_file_fairness);
    run_test(totals, "test_warm_file_reply_allocates_nothing", test_warm_file_reply_allocates_nothing);
    if (backend_under_test == ucall_io_backend_automatic_k)
        run_test(totals, "test_backend_parity", test_backend_parity);
#endif
    return suite_exit_code(totals);
}
