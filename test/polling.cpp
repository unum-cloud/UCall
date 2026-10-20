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
#include <atomic>
#include <chrono>
#include <string>
#include <thread>

#include "ucall/ucall.h"
#include "ucall/types.hpp"
#include "ucall/network.hpp"

namespace uc = unum::ucall;

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
    std::array<ucall_received_http_request_t, 4> requests {};
    std::array<std::size_t, 2> sizes {};
    std::atomic<std::size_t> completed {};

    static void receive(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
        auto& state = *static_cast<batch_context_t*>(context);
        assert(count && count <= state.requests.size());
        for (std::size_t i = 0; i != count; ++i) {
            assert(requests[i]);
            state.requests[i] = requests[i];
        }
        auto completed = state.completed.load(std::memory_order_relaxed);
        assert(completed < state.sizes.size());
        state.sizes[completed] = count;
        state.completed.store(completed + 1, std::memory_order_release);
    }
    void wait(std::size_t count) {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {5};
        while (completed.load(std::memory_order_acquire) != count) {
            for (std::size_t i = 0; i != fixture->clients.size(); ++i) fixture->take(i);
            fixture->serve(200000);
            assert(std::chrono::steady_clock::now() < deadline);
        }
    }
};

static std::thread drain_batches(ucall_server_t server) {
    return std::thread {[server] {
        ucall_outcome_t outcome {};
        ucall_server_take_batches_t take {server, &outcome};
        ucall_server_take_batches(&take);
        assert(outcome.status == ucall_status_success_k);
    }};
}

static void application_batches() {
    batch_context_t batches;
    fixture_t fixture {batch_context_t::receive, &batches};
    batches.fixture = &fixture;
    auto drain = drain_batches(fixture.server);
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
    ucall_server_stop(fixture.server);
    fixture.serve();
    drain.join();
}

static void batches_across_loops() {
#if !UCALL_OS_WINDOWS_
    ucall_server_t server {};
    ucall_client_t client {};
    ucall_outcome_t outcome {};
    ucall_network_interface_t interface {};
    interface.address = "127.0.0.1:0";
    interface.max_concurrent_connections = 4;
    interface.event_loops = 2;
    ucall_server_config_t config {}, resolved {};
    config.interfaces = &interface;
    config.interfaces_count = 1;
    ucall_server_init_t init {&server, &outcome, &config, &resolved};
    ucall_server_init(&init);
    assert(outcome.status == ucall_status_success_k && resolved.interfaces[0].event_loops == 2);
    batch_context_t batches;
    ucall_server_add_batch_endpoint_t add {
        server, &outcome, view("/batch"), ucall_verb_post_k, batch_context_t::receive, &batches, 4, 4, 10000000};
    ucall_server_add_batch_endpoint(&add);
    assert(outcome.status == ucall_status_success_k);
    ucall_client_config_t client_config {};
    client_config.max_concurrent_connections = 4;
    ucall_client_init_t client_init {&client, &outcome, &client_config, nullptr};
    ucall_client_init(&client_init);
    assert(outcome.status == ucall_status_success_k);
    auto drain = drain_batches(server);
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
        assert(outcome.status == ucall_status_success_k);
    }
    std::array<ucall_completed_call_t, 4> completed {};
    std::size_t received {};
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {5};
    auto progress = [&] {
        for (std::size_t loop = 0; loop != 2; ++loop) {
            ucall_server_take_call_t serving {server, &outcome, loop, 0};
            ucall_server_take_call(&serving);
            assert(outcome.status == ucall_status_success_k);
        }
        std::size_t count {};
        ucall_client_take_completed_t take {client, &outcome, completed.data() + received, completed.size() - received,
                                            &count, 0};
        ucall_client_take_completed(&take);
        assert(outcome.status == ucall_status_success_k);
        received += count;
        assert(std::chrono::steady_clock::now() < deadline);
    };
    while (!batches.completed.load(std::memory_order_acquire)) progress();
    assert(batches.completed == 1 && batches.sizes[0] == 4);
    for (auto request : batches.requests) {
        ucall_bytes_view_t body = view("echo");
        ucall_server_reply_content_t response {server, &outcome, request, nullptr, 0, body};
        ucall_server_reply_content(&response);
        assert(outcome.status == ucall_status_success_k);
    }
    while (received != completed.size()) progress();
    for (auto& call : completed) {
        assert(call.outcome.status == ucall_status_success_k);
        ucall_received_http_response_free(call.response);
    }
    assert(batches.completed == 1);
    ucall_server_stop(server);
    progress();
    drain.join();
    ucall_client_free(client);
    ucall_server_free(server);
#endif
}

static void capability_admission() {
    ucall_client_handle_t client {};
    client.string_capabilities = std::numeric_limits<std::uint64_t>::max();
    ucall_outcome_t outcome {};
    std::size_t count = 1;
    ucall_client_take_completed_t take {&client, &outcome, nullptr, 0, &count, 0};
    ucall_client_take_completed(&take);
    assert(outcome.status == ucall_status_unsupported_k && !count);
    ucall_server_handle_t server {};
    server.string_capabilities = client.string_capabilities;
    ucall_server_take_call_t poll {&server, &outcome, 0, 0};
    ucall_server_take_call(&poll);
    assert(outcome.status == ucall_status_unsupported_k);
    ucall_server_stop(&server);
    assert(server.stopped);
}

static void origin_reuse_and_fairness() {
#if UCALL_WITH_POSIX
    using network_t = uc::network_variant<uc::posix_engine_t, uc::cpu_class_t::serial_k>;
    ucall_client_t handle {};
    ucall_outcome_t outcome {};
    ucall_client_config_t config {};
    config.backend = ucall_io_backend_posix_k;
    config.cpu_class = ucall_cpu_class_serial_k;
    config.max_concurrent_connections = 3;
    config.max_concurrent_calls = 4;
    ucall_client_init_t init {&handle, &outcome, &config, nullptr};
    ucall_client_init(&init);
    assert(outcome.status == ucall_status_success_k);
    auto& client = *static_cast<network_t::client_t*>(handle);
    for (auto url :
         {"http://127.0.0.1:18545/", "http://127.0.0.1:18545/", "http://127.0.0.1:18546/", "http://127.0.0.1:18545/"}) {
        ucall_client_call_t call {};
        call.client = handle;
        call.outcome = &outcome;
        call.url = view(url);
        call.verb = ucall_verb_get_k;
        ucall_client_call(&call);
        assert(outcome.status == ucall_status_success_k);
    }
    std::array<uc::descriptor_t, 3> descriptors {};
    for (std::size_t i = 0; i != client.peers.size(); ++i) {
        auto& peer = *client.peers[i];
        auto& job = client.jobs[i == 1 ? 2 : 0];
        assert(network_t::copy_text(peer.authority, {job.authority.data(), job.authority.size() - 1}));
        peer.authority_hash = job.authority_hash;
        assert(peer.connection.configure({}) == ucall_status_success_k);
        descriptors[i] = peer.connection.descriptor = client.engine.open_socket(AF_INET);
        assert(descriptors[i] >= 0);
    }
    auto& busy = *client.peers[2];
    busy.job = &client.jobs[3];
    busy.connection.flags = network_t::connection_pending_k;
    busy.connection.stage = network_t::connection_stage_t::transmitting_k;
    client.jobs[3].stage = network_t::client_job_t::stage_t::active_k;
    network_t::client_progress(client);
    assert(client.peers[0]->job == &client.jobs[0]);
    assert(client.peers[1]->job == &client.jobs[2]);
    assert(client.jobs[1].stage == network_t::client_job_t::stage_t::queued_k && client.next_job == 1);
    for (std::size_t i = 0; i != descriptors.size(); ++i)
        assert(client.peers[i]->connection.descriptor == descriptors[i]);
    client.engine.stop();
    auto& released = *client.peers[1];
    released.job = nullptr;
    released.connection.flags = network_t::connection_none_k;
    released.connection.stage = network_t::connection_stage_t::idle_k;
    client.jobs[2].stage = network_t::client_job_t::stage_t::idle_k;
    network_t::client_progress(client);
    assert(released.job == &client.jobs[1] && client.next_job == 2);
    assert(released.connection.stage == network_t::connection_stage_t::closing_k);
    ucall_client_free(handle);
#endif
}

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
        assert(state);
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
        assert(state && state->live);
        --state->live;
        uc::st::default_allocator<value_type_> {}.deallocate(pointer, count);
    }
};

static void allocator_propagation() {
#if UCALL_WITH_POSIX
    using allocator_t = counting_allocator<uc::byte_t>;
    using network_t = uc::network_variant<uc::posix_engine_t, uc::cpu_class_t::serial_k, allocator_t>;
    allocator_state_t state;
    allocator_t allocator {state};
    ucall_server_t server {};
    ucall_outcome_t outcome {};
    ucall_network_interface_t interface {};
    interface.address = "127.0.0.1:0";
    interface.max_concurrent_connections = 1;
    ucall_server_config_t server_config {}, resolved {};
    server_config.interfaces = &interface;
    server_config.interfaces_count = 1;
    server_config.backend = ucall_io_backend_posix_k;
    ucall_server_init_t server_init {&server, &outcome, &server_config, &resolved};
    network_t::server_init(&server_init, allocator);
    assert(outcome.status == ucall_status_success_k);
    auto echo = [](ucall_received_http_request_t request, void* context) {
        auto server = *static_cast<ucall_server_t*>(context);
        ucall_outcome_t outcome {};
        ucall_bytes_view_t body {};
        ucall_server_request_body_t get {server, &outcome, request, &body};
        ucall_server_request_body(&get);
        assert(outcome.status == ucall_status_success_k);
        ucall_server_reply_content_t reply {server, &outcome, request, nullptr, 0, body};
        ucall_server_reply_content(&reply);
        assert(outcome.status == ucall_status_success_k);
    };
    ucall_server_add_http_endpoint_t add {server, &outcome, view("/echo/{id}"), ucall_verb_post_k, echo, &server};
    ucall_server_add_http_endpoint(&add);
    assert(outcome.status == ucall_status_success_k);
    ucall_client_t client {};
    ucall_client_config_t client_config {};
    client_config.backend = ucall_io_backend_posix_k;
    client_config.max_concurrent_connections = 1;
    ucall_client_init_t client_init {&client, &outcome, &client_config, nullptr};
    auto live = state.live;
    state.remaining = 0;
    network_t::client_init(&client_init, allocator);
    assert(!client && outcome.status == ucall_status_out_of_memory_k && state.live == live);
    state.remaining = std::numeric_limits<std::size_t>::max();
    network_t::client_init(&client_init, allocator);
    assert(outcome.status == ucall_status_success_k);
    std::string url = std::string {"http://"} + resolved.interfaces[0].address + "/echo/1";
    std::string payload(1024, '\0');
    ucall_client_call_t call {};
    call.client = client;
    call.outcome = &outcome;
    call.url = view(url);
    call.verb = ucall_verb_post_k;
    call.body = view(payload);
    ucall_client_call(&call);
    assert(outcome.status == ucall_status_success_k);
    ucall_completed_call_t completed {};
    std::size_t count {};
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds {5};
    while (!count) {
        ucall_server_take_call_t serve {server, &outcome, 0, 0};
        ucall_server_take_call(&serve);
        assert(outcome.status == ucall_status_success_k);
        ucall_client_take_completed_t take {client, &outcome, &completed, 1, &count, 0};
        ucall_client_take_completed(&take);
        assert(outcome.status == ucall_status_success_k && std::chrono::steady_clock::now() < deadline);
    }
    assert(completed.outcome.status == ucall_status_success_k);
    ucall_bytes_view_t body {};
    ucall_received_http_response_body_t get {client, &outcome, completed.response, &body};
    ucall_received_http_response_body(&get);
    assert(outcome.status == ucall_status_success_k && body.length == payload.size());
    ucall_client_free(client);
    ucall_server_free(server);
    assert(state.allocations && state.live && !std::memcmp(body.data, payload.data(), body.length));
    ucall_received_http_response_free(completed.response);
    assert(!state.live);
#endif
}

int main() {
    allocator_propagation();
    origin_reuse_and_fairness();
    capability_admission();
    progress_and_retention();
    completion_credits();
    timeout_and_cancel();
    application_batches();
    batches_across_loops();
}
