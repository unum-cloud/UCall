/**
 *  @file test/network.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief C ABI loopback framing, connection reuse, shared admission, and Noise authentication.
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstring>

#include <chrono>
#include <span>
#include <string>
#include <string_view>

#include "ucall/ucall.h"
#include "ucall/curve25519.hpp"

namespace uc = unum::ucall;

static ucall_io_backend_t backend_k = ucall_io_backend_automatic_k;

static ucall_bytes_view_t view(std::string const& text) {
    return {reinterpret_cast<ucall_byte_t const*>(text.data()), text.size()};
}
static ucall_bytes_view_t view(char const* text) {
    return {reinterpret_cast<ucall_byte_t const*>(text), std::strlen(text)};
}
static bool authorize(ucall_noise_key_t const* key, void* context) {
    return std::memcmp(*key, context, sizeof(ucall_noise_key_t)) == 0;
}
struct fixture_t {
    ucall_server_t server {};
    ucall_client_t client {};
    ucall_server_config_t resolved {};
    ucall_noise_key_t server_private {}, server_public {}, client_private {}, client_public {};
    ucall_received_http_request_t held {};
    std::string url {};

    static void echo(ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<fixture_t*>(context);
        ucall_outcome_t outcome {};
        ucall_bytes_view_t body {};
        ucall_server_request_body_t extract {fixture.server, &outcome, request, &body};
        ucall_server_request_body(&extract);
        assert(outcome.status == ucall_status_success_k);
        ucall_bytes_view_t header = view("X-UCall: passed");
        ucall_server_reply_content_t reply {fixture.server, &outcome, request, &header, 1, body};
        ucall_server_reply_content(&reply);
        assert(outcome.status == ucall_status_success_k);
    }
    static void gated(ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<fixture_t*>(context);
        assert(!fixture.held);
        fixture.held = request;
    }
    explicit fixture_t(ucall_security_mode_t security, std::size_t loops = 1) {
        for (std::size_t i = 0; i != sizeof(server_private); ++i) {
            server_private[i] = static_cast<ucall_byte_t>(i + 1);
            client_private[i] = static_cast<ucall_byte_t>(i + sizeof(server_private) + 1);
        }
        uc::x25519_derive_public(std::as_writable_bytes(std::span {server_public}).data(),
                                 std::as_bytes(std::span {server_private}).data());
        uc::x25519_derive_public(std::as_writable_bytes(std::span {client_public}).data(),
                                 std::as_bytes(std::span {client_private}).data());
        ucall_network_interface_t interface {};
        interface.address = "127.0.0.1:0";
        interface.event_loops = loops;
        interface.max_concurrent_connections = loops;
        interface.security_mode = security;
        interface.noise_private_key = &server_private;
        interface.peer_authorizer = authorize;
        interface.peer_authorizer_context = client_public;
        ucall_server_config_t config {};
        config.interfaces = &interface;
        config.interfaces_count = 1;
        config.backend = backend_k;
        ucall_outcome_t outcome {};
        ucall_server_init_t init {&server, &outcome, &config, &resolved};
        ucall_server_init(&init);
        assert(outcome.status == ucall_status_success_k && server);
        for (auto route : {"/echo/{id}", "/gate"}) {
            auto callback = std::strcmp(route, "/gate") == 0 ? gated : echo;
            ucall_server_add_http_endpoint_t add {server, &outcome, view(route), ucall_verb_any_k, callback, this};
            ucall_server_add_http_endpoint(&add);
            assert(outcome.status == ucall_status_success_k);
        }
        ucall_client_config_t client_config {};
        client_config.max_concurrent_connections = loops;
        client_config.max_concurrent_calls = 2;
        client_config.noise_private_key = &client_private;
        client_config.peer_authorizer = authorize;
        client_config.peer_authorizer_context = server_public;
        client_config.backend = backend_k;
        ucall_client_init_t client_init {&client, &outcome, &client_config, nullptr};
        ucall_client_init(&client_init);
        assert(outcome.status == ucall_status_success_k && client);
        url = security == ucall_security_mode_none_k ? "http://" : "http+noise://";
        url += resolved.interfaces[0].address;
    }
    ~fixture_t() {
        ucall_client_free(client);
        ucall_server_free(server);
    }
    std::size_t poll(ucall_completed_call_t& completed) {
        ucall_outcome_t outcome {};
        for (std::size_t i = 0; i != resolved.interfaces[0].event_loops; ++i) {
            ucall_server_take_call_t serving {server, &outcome, i, 0};
            ucall_server_take_call(&serving);
            assert(outcome.status == ucall_status_success_k);
        }
        std::size_t count {};
        ucall_client_take_completed_t take {client, &outcome, &completed, 1, &count, 0};
        ucall_client_take_completed(&take);
        assert(outcome.status == ucall_status_success_k);
        return count;
    }
    ucall_completed_call_t wait() {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {5};
        ucall_completed_call_t completed {};
        while (!poll(completed)) assert(std::chrono::steady_clock::now() < deadline);
        return completed;
    }
};
static void check_response(fixture_t& fixture, ucall_received_http_response_t response, std::string const& expected) {
    assert(ucall_received_http_response_status(fixture.client, response) == ucall_http_status_ok_k);
    ucall_outcome_t outcome {};
    ucall_bytes_view_t body {}, header {};
    ucall_received_http_response_body_t get {fixture.client, &outcome, response, &body};
    ucall_received_http_response_body(&get);
    assert(outcome.status == ucall_status_success_k && body.length == expected.size());
    assert(body.length == 0 || std::memcmp(body.data, expected.data(), body.length) == 0);
    ucall_received_http_response_header_t get_header {fixture.client, &outcome, response, view("X-UCALL"), &header};
    ucall_received_http_response_header(&get_header);
    assert(outcome.status == ucall_status_success_k && header.length == 6 &&
           std::memcmp(header.data, "passed", 6) == 0);
    ucall_received_http_response_free(response);
}
static void exchanges(ucall_security_mode_t security) {
    fixture_t fixture {security};
    std::string payload(65536, 'x');
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
    for (int i = 0; i != 2; ++i) {
        ucall_client_call(&call);
        assert(outcome.status == ucall_status_success_k);
        auto completed = fixture.wait();
        assert(completed.outcome.status == ucall_status_success_k && completed.response);
        check_response(fixture, completed.response, payload);
    }
    if (security != ucall_security_mode_none_k) return;
    ucall_bytes_view_t close = view("Connection: close");
    call.headers = &close;
    call.headers_count = 1;
    ucall_client_call(&call);
    assert(outcome.status == ucall_status_success_k);
    auto completed = fixture.wait();
    assert(completed.outcome.status == ucall_status_success_k);
    check_response(fixture, completed.response, payload);
    call.verb = ucall_verb_get_k;
    call.body = {};
    call.headers = nullptr;
    call.headers_count = 0;
    ucall_client_call(&call);
    assert(outcome.status == ucall_status_success_k);
    completed = fixture.wait();
    assert(completed.outcome.status == ucall_status_success_k);
    check_response(fixture, completed.response, {});
}
#if !defined(_WIN32)
static void multiloop() {
    fixture_t fixture {ucall_security_mode_none_k, 2};
    ucall_outcome_t outcome {};
    auto gate_url = fixture.url + "/gate", echo_url = fixture.url + "/echo/42";
    ucall_client_call_t call {};
    call.client = fixture.client;
    call.outcome = &outcome;
    call.url = view(gate_url);
    call.verb = ucall_verb_post_k;
    call.context = &gate_url;
    ucall_client_call(&call);
    assert(outcome.status == ucall_status_success_k);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {5};
    while (!fixture.held) {
        ucall_completed_call_t completed {};
        assert(!fixture.poll(completed));
        assert(std::chrono::steady_clock::now() < deadline);
    }
    call.url = view(echo_url);
    call.context = &echo_url;
    ucall_client_call(&call);
    assert(outcome.status == ucall_status_success_k);
    auto completed = fixture.wait();
    assert(completed.context == &echo_url && completed.outcome.status == ucall_status_success_k);
    check_response(fixture, completed.response, {});
    fixture_t::echo(fixture.held, &fixture);
    fixture.held = nullptr;
    completed = fixture.wait();
    assert(completed.context == &gate_url && completed.outcome.status == ucall_status_success_k);
    check_response(fixture, completed.response, {});
}
#endif
int main(int argc, char** argv) {
    if (argc == 3 && std::string_view(argv[1]) == "--backend") {
        bool found {};
        for (auto backend : {ucall_io_backend_automatic_k, ucall_io_backend_posix_k, ucall_io_backend_linux_epoll_k,
                             ucall_io_backend_linux_uring612_k, ucall_io_backend_linux_uring700_k,
                             ucall_io_backend_macos_kqueue_k, ucall_io_backend_windows_iocp_k})
            if (std::string_view(argv[2]) == ucall_io_backend_name(backend)) {
                backend_k = backend;
                found = true;
            }
        assert(found);
    }
    else assert(argc == 1);
    ucall_client_t probe {};
    ucall_outcome_t outcome {};
    ucall_client_config_t config {};
    config.max_concurrent_connections = 1;
    config.backend = backend_k;
    ucall_client_init_t init {&probe, &outcome, &config, nullptr};
    ucall_client_init(&init);
    if (outcome.status == ucall_status_unsupported_k) return 77;
    assert(outcome.status == ucall_status_success_k);
    ucall_client_free(probe);
#if !defined(_WIN32)
    multiloop();
#endif
    exchanges(ucall_security_mode_none_k);
    exchanges(ucall_security_mode_noise_xx_k);
    exchanges(ucall_security_mode_noise_ik_k);
}
