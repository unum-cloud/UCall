/**
 *  @file test/polling.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Caller-driven progress, retained requests, completion credits, and application batching.
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstring>

#include <array>
#include <chrono>
#include <string>

#include "ucall/ucall.h"

static ucall_bytes_view_t view(std::string const& value) {
    return {reinterpret_cast<ucall_byte_t const*>(value.data()), value.size()};
}
static ucall_bytes_view_t view(char const* value) {
    return {reinterpret_cast<ucall_byte_t const*>(value), std::strlen(value)};
}

struct fixture_t {
    ucall_server_t server {};
    std::array<ucall_client_t, 2> clients {};
    ucall_received_http_request_t held {};
    std::size_t echoes {};
    std::string address;

    void reply(ucall_received_http_request_t request) {
        ucall_outcome_t outcome {};
        ucall_bytes_view_t body {};
        ucall_server_request_body_t extract {server, &outcome, request, &body};
        ucall_server_request_body(&extract);
        assert(outcome.status == ucall_status_success_k);
        ucall_server_reply_content_t response {server, &outcome, request, nullptr, 0, body};
        ucall_server_reply_content(&response);
        assert(outcome.status == ucall_status_success_k);
    }
    static void echo(ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<fixture_t*>(context);
        ++fixture.echoes;
        fixture.reply(request);
    }
    static void hold(ucall_received_http_request_t request, void* context) {
        auto& fixture = *static_cast<fixture_t*>(context);
        assert(!fixture.held);
        fixture.held = request;
    }
    explicit fixture_t(ucall_received_batch_http_request_callback_t batch_callback = nullptr,
                       void* batch_context = nullptr) {
        ucall_outcome_t outcome {};
        ucall_network_interface_t interface {};
        interface.address = "127.0.0.1:0";
        interface.max_concurrent_connections = 2;
        ucall_server_config_t config {};
        config.interfaces = &interface;
        config.interfaces_count = 1;
        ucall_server_config_t resolved {};
        ucall_server_init_t init {&server, &outcome, &config, &resolved};
        ucall_server_init(&init);
        assert(outcome.status == ucall_status_success_k);
        address = "http://";
        address += resolved.interfaces[0].address;
        for (auto route : {"/echo", "/hold"}) {
            auto callback = std::strcmp(route, "/hold") == 0 ? hold : echo;
            ucall_server_add_http_endpoint_t add {server, &outcome, view(route), ucall_verb_post_k, callback, this};
            ucall_server_add_http_endpoint(&add);
            assert(outcome.status == ucall_status_success_k);
        }
        for (auto& client : clients) {
            ucall_client_config_t client_config {};
            client_config.max_concurrent_connections = 1;
            client_config.max_concurrent_calls = 2;
            ucall_client_init_t client_init {&client, &outcome, &client_config, nullptr};
            ucall_client_init(&client_init);
            assert(outcome.status == ucall_status_success_k);
        }
        if (batch_callback) {
            ucall_server_add_batch_endpoint_t add {
                server, &outcome, view("/batch"), ucall_verb_post_k, batch_callback, batch_context, 2, 2, 100000};
            ucall_server_add_batch_endpoint(&add);
            assert(outcome.status == ucall_status_success_k);
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
        assert(outcome.status == ucall_status_success_k);
    }
    std::size_t take(std::size_t client, ucall_completed_call_t* calls = nullptr, std::size_t capacity = 0) {
        ucall_outcome_t outcome {};
        std::size_t count {};
        ucall_client_take_completed_t take {clients[client], &outcome, calls, capacity, &count, 0};
        ucall_client_take_completed(&take);
        assert(outcome.status == ucall_status_success_k);
        return count;
    }
    ucall_completed_call_t wait(std::size_t client) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {5};
        ucall_completed_call_t completed {};
        do {
            serve();
            if (take(client, &completed, 1)) return completed;
            assert(std::chrono::steady_clock::now() < deadline);
        } while (true);
    }
    void await_held(std::size_t client) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {5};
        while (!held) {
            serve();
            take(client);
            assert(std::chrono::steady_clock::now() < deadline);
        }
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
    void success(ucall_completed_call_t const& completed) {
        assert(completed.context == this && completed.outcome.status == ucall_status_success_k && completed.response);
        response = completed.response;
    }
    ~call_t() { ucall_received_http_response_free(response); }
};

static void progress_and_retention() {
    fixture_t fixture;
    call_t held, fast;
    held.submit(fixture, 0, "/hold");
    assert(held.outcome.status == ucall_status_success_k && !fixture.held);
    fixture.serve();
    assert(!fixture.held);
    fixture.await_held(0);
    fast.submit(fixture, 1);
    assert(fast.outcome.status == ucall_status_success_k);
    fast.success(fixture.wait(1));
    ucall_completed_call_t completed {};
    assert(!fixture.take(0, &completed, 1));
    fixture.reply(fixture.held);
    fixture.held = nullptr;
    held.success(fixture.wait(0));
}

static void completion_credits() {
    fixture_t fixture;
    call_t first, second, refill;
    first.submit(fixture);
    second.submit(fixture);
    assert(first.outcome.status == ucall_status_success_k && second.outcome.status == ucall_status_success_k);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {5};
    while (fixture.echoes != 2) {
        fixture.serve();
        fixture.take(0);
        assert(std::chrono::steady_clock::now() < deadline);
    }
    refill.submit(fixture);
    assert(refill.outcome.status == ucall_status_contended_k);
    first.success(fixture.wait(0));
    refill.submit(fixture);
    assert(refill.outcome.status == ucall_status_success_k);
    second.success(fixture.wait(0));
    refill.success(fixture.wait(0));
}

static void timeout_and_cancel() {
    {
        fixture_t fixture;
        call_t timed;
        timed.submit(fixture, 0, "/hold", 100000);
        fixture.await_held(0);
        auto completed = fixture.wait(0);
        assert(completed.context == &timed && completed.outcome.status == ucall_status_timeout_k &&
               !completed.response);
    }
    {
        fixture_t fixture;
        call_t held, queued;
        held.submit(fixture, 0, "/hold");
        fixture.await_held(0);
        queued.submit(fixture);
        assert(queued.outcome.status == ucall_status_success_k);
        ucall_client_free(fixture.clients[0]);
        fixture.clients[0] = nullptr;
        ucall_server_stop(fixture.server);
        ucall_outcome_t outcome {};
        ucall_server_reply_content_t detached {fixture.server, &outcome, fixture.held, nullptr, 0, view("closed")};
        ucall_server_reply_content(&detached);
        assert(outcome.status == ucall_status_connection_closed_k);
        fixture.held = nullptr;
    }
}

struct batch_context_t {
    fixture_t* fixture {};
    std::array<ucall_received_http_request_t, 2> requests {};
    std::array<std::size_t, 2> sizes {};
    std::size_t completed {};

    static void receive(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
        auto& state = *static_cast<batch_context_t*>(context);
        assert(count && count <= state.requests.size());
        for (std::size_t i = 0; i != count; ++i) {
            assert(requests[i]);
            state.requests[i] = requests[i];
        }
        assert(state.completed < state.sizes.size());
        state.sizes[state.completed++] = count;
    }
    void wait(std::size_t count) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {5};
        while (completed != count) {
            for (std::size_t i = 0; i != fixture->clients.size(); ++i) fixture->take(i);
            fixture->serve(200000);
            assert(std::chrono::steady_clock::now() < deadline);
        }
    }
};

static void application_batches() {
    batch_context_t batches;
    fixture_t fixture {batch_context_t::receive, &batches};
    batches.fixture = &fixture;
    call_t first, second, partial;
    first.submit(fixture, 0, "/batch");
    second.submit(fixture, 1, "/batch");
    batches.wait(1);
    assert(batches.sizes[0] == 2);
    fixture.reply(batches.requests[1]);
    fixture.reply(batches.requests[0]);
    first.success(fixture.wait(0));
    second.success(fixture.wait(1));
    partial.submit(fixture, 0, "/batch");
    batches.wait(2);
    assert(batches.sizes[1] == 1);
    fixture.reply(batches.requests[0]);
    partial.success(fixture.wait(0));
}

int main() {
    progress_and_retention();
    completion_credits();
    timeout_and_cancel();
    application_batches();
}
