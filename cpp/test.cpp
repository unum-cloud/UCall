/**
 *  @file cpp/test.cpp
 *  @author Ash Vardanian
 *  @date November 18, 2026
 *  @brief The C++ interface over a loopback server: a greeting round trip with a polling thread,
 *      and a file reply awaited through a fixed ring of posted polls on one thread.
 *
 *  The one argument names the directory holding this suite's build script, which the file reply
 *  serves and the suite reads back to compare. Against the stand-in, which serves no network, the
 *  suite registers routes and runs the cases without a round trip.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build

#include <cstdio>  // `std::printf`, `std::snprintf`, `std::fprintf`, `std::fopen`, `std::fread`
#include <cstdlib> // `std::abort`

#include <array>       // `std::array`
#include <chrono>      // `std::chrono::milliseconds`
#include <coroutine>   // `std::suspend_never`
#include <string_view> // `std::string_view`
#include <thread>      // `std::thread`

#include "ucall/ucall.hpp"

namespace uc = unum::ucall;

static void check(bool is_satisfied, char const* what) {
    if (is_satisfied) return;
    std::fprintf(stderr, "%s failed\n", what);
    std::abort();
}

static void check(uc::status_t const& status, char const* what) {
    if (!status.failed()) return;
    std::string_view const name = uc::status_name(status.code);
    std::fprintf(stderr, "%s failed: %.*s: %s\n", what, static_cast<int>(name.size()), name.data(),
                 status.note ? status.note : "");

    std::abort();
}

/** A fixed ring of posted polls, run one round at a time between the server's polls. */
struct test_loop_t {
    struct posted_t {
        void (*poll)(void*) noexcept;
        void* poll_state;
    };
    std::array<posted_t, 64> ring {};
    std::size_t head = 0, tail = 0;

    void post(void (*poll)(void*) noexcept, void* state) noexcept {
        check(tail - head < ring.size(), "keeping the ring from overflowing");
        ring[tail++ % ring.size()] = {poll, state};
    }

    /** Runs what was posted before the round began, so a poll posting itself waits for the next. */
    void run() noexcept {
        std::size_t const last = tail;
        while (head != last) {
            posted_t const next = ring[head++ % ring.size()];
            next.poll(next.poll_state);
        }
    }
};

/** A coroutine that starts at once and frees itself at its end. */
struct detached_t {
    struct promise_type {
        detached_t get_return_object() noexcept { return {}; }
        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_never final_suspend() noexcept { return {}; }
        void return_void() noexcept {}
        void unhandled_exception() noexcept { std::abort(); }
    };
};

/** The body of a buffered @p response, which the suite expects readable. */
static std::string_view body_of(uc::response_t const& response) {
    auto [body, body_status] = response.body();
    check(body_status, "reading a body");
    return body;
}

/** Formats the URL of @p path on @p address into @p url, answering the written text. */
static std::string_view url_of(std::array<char, 128>& url, std::string_view address, char const* path) {
    int const length = std::snprintf(url.data(), url.size(), "http://%.*s%s", static_cast<int>(address.size()),
                                     address.data(), path);
    return {url.data(), static_cast<std::size_t>(length)};
}

/** Answers each request with what it holds, so routes register a member with its object. */
struct echo_service_t {
    std::size_t answered = 0;

    void echo_query(uc::request_t request) noexcept {
        auto [query, query_status] = request.query_string();
        if (query_status.failed()) return;
        ++answered;
        [[maybe_unused]] uc::status_t const replied = std::move(request).reply(ucall_http_status_ok_k, {}, query);
    }
};

/** Counts the peers it admitted, which no two polling loops may do at once. */
struct counting_authorizer_t {
    std::size_t admitted = 0;
    bool operator()(ucall_noise_key_t const&) noexcept { return ++admitted != 0; }
};
static_assert(!uc::peer_authorizer<counting_authorizer_t>, "a stateful authorizer races across polling loops");

/** Counts the lines it heard, which no two logging threads may do at once. */
struct counting_log_handler_t {
    std::size_t lines = 0;
    void operator()(ucall_log_level_t, std::string_view) noexcept { ++lines; }
};
static_assert(!uc::log_handler<counting_log_handler_t>, "a stateful log handler races across logging threads");

/** Counts the requests it answered, which no two polling loops may do at once. */
struct counting_request_handler_t {
    std::size_t answered = 0;
    void operator()(uc::request_t) noexcept { ++answered; }
};
static_assert(!uc::request_handler<counting_request_handler_t>, "a stateful route handler races across polling loops");

static void greet(uc::request_t request) noexcept {
    auto [name, name_status] = request.path_parameter("name");
    if (name_status.failed()) return;
    ucall_reply_part_t const parts[] {uc::bytes_part("Hello, "), uc::bytes_part(name)};
    uc::deferred<> sent; // final on return, as the parts are bytes alone
    [[maybe_unused]] uc::status_t const replied = std::move(request).reply_parts(ucall_http_status_ok_k, {}, parts,
                                                                                 sent);
}

static void greet_batch(uc::batch_t batch) noexcept {
    for (uc::request_t request : batch) greet(std::move(request));
}

static void test_greeting_round_trip() {
    uc::interface_t const interfaces[] {{.address = "127.0.0.1:0"}};
    auto [server, server_status] = uc::server_t::make(interfaces);
    check(server_status, "starting the server");
    echo_service_t service;
    check(server.get<greet>("/hello/{name}"), "routing the greeting");
    check(server.get<&echo_service_t::echo_query>("/echo", service), "routing the echo");
    auto [address, address_status] = server.address(0);
    check(address_status, "reading the address");
    check(server.event_loops() == 1, "running one event loop");
    auto [domain, domain_status] = server.memory_domain(0);
    check(domain_status, "reading the memory domain");
    check(domain == -1, "reporting no memory domain for loopback");

    std::thread polling([&server] { check(server.take_calls(0), "polling"); });
    auto [client, client_status] = uc::client_t::make({.max_concurrent_connections = 2});
    check(client_status, "starting the client");
    std::array<char, 128> greeting_url {};
    auto [response, response_status] = client.get(url_of(greeting_url, address, "/hello/world"));
    check(response_status, "greeting");
    check(response.status_code() == ucall_http_status_ok_k, "answering the greeting with 200");
    check(body_of(response) == "Hello, world", "greeting the world");

    // A submitted call and a blocking one: the library keeps the other's completion queued.
    std::array<char, 128> first_url {}, second_url {};
    int first_context = 0;
    check(client.submit({.url = url_of(first_url, address, "/echo?first")}, &first_context), "submitting");
    auto [second, second_status] = client.get(url_of(second_url, address, "/echo?second"));
    check(second_status, "calling while another call is in flight");
    check(body_of(second) == "second", "echoing the blocking call");
    std::array<ucall_completed_call_t, 2> storage {};
    std::size_t taken = 0;
    while (taken == 0) {
        auto [finished, finished_status] = client.take_completed(storage, std::chrono::milliseconds(100));
        check(finished_status, "taking completions");
        for (uc::completed_t completed : finished) {
            check(completed.context == &first_context, "completing the submitted context");
            auto [first, first_status] = std::move(completed.response);
            check(first_status, "the submitted call");
            check(body_of(first) == "first", "echoing the submitted call");
            ++taken;
        }
    }
    check(taken == 1 && service.answered == 2, "answering both echoes once");

    server.stop();
    polling.join();
    auto [statistics, statistics_status] = server.event_loop_statistics(0);
    check(statistics_status, "reading statistics");
    check(statistics.requests == 3, "counting three requests");
    std::printf("passed greeting round trip\n");
}

static detached_t send_build_script(uc::request_t request, test_loop_t& loop, uc::status_t& sent_status) {
    ucall_reply_part_t const parts[] {
        uc::path_part({.directory_index = 0, .relative_path = uc::bytes_view("CMakeLists.txt")})};
    uc::deferred<> sent;
    check(std::move(request).reply_parts(ucall_http_status_ok_k, {}, parts, sent), "queueing the file reply");
    check(sent.status() == uc::status_code_t::deferred_k, "deferring the file reply");
    sent_status = co_await sent.wait(loop);
}

/** The build script's bytes, read through C stdio to compare with what the server sent. */
struct script_t {
    std::array<char, 4096> bytes {};
    std::size_t length = 0;
};

static void test_awaited_file_reply(char const* directory) {
    std::array<char, 1024> script_path {};
    std::snprintf(script_path.data(), script_path.size(), "%s/CMakeLists.txt", directory);
    std::FILE* const script_file = std::fopen(script_path.data(), "rb");
    check(script_file != nullptr, "opening the build script");
    script_t script;
    script.length = std::fread(script.bytes.data(), 1, script.bytes.size(), script_file);
    std::fclose(script_file);

    ucall_bytes_view_t const directories[] {uc::bytes_view(directory)};
    uc::interface_t const interfaces[] {{.address = "127.0.0.1:0", .reply_directories = directories}};
    auto [server, server_status] = uc::server_t::make(interfaces);
    check(server_status, "starting the file server");
    test_loop_t loop;
    uc::status_t sent_status {uc::status_code_t::deferred_k};
    auto send = [&loop, &sent_status](uc::request_t request) noexcept {
        send_build_script(std::move(request), loop, sent_status);
    };
    check(server.get("/script", send), "routing the file");
    auto [address, address_status] = server.address(0);
    check(address_status, "reading the address");

    // A client bound to the loop advances as the loop polls, so one thread drives everything.
    auto [client, client_status] = uc::client_t::make({.max_concurrent_connections = 1, .server = &server});
    check(client_status, "binding the client");
    std::array<char, 128> url {};
    check(client.submit({.url = url_of(url, address, "/script")}, nullptr), "submitting the file call");

    std::array<ucall_completed_call_t, 1> storage {};
    uc::completed_t completed {};
    std::size_t taken = 0;
    while (taken == 0 || sent_status == uc::status_code_t::deferred_k) {
        check(server.take_call(0, std::chrono::milliseconds(1)), "polling the file server");
        loop.run();
        if (taken != 0) continue;
        auto [finished, finished_status] = client.take_completed(storage, std::chrono::microseconds(0));
        check(finished_status, "taking the file completion");
        taken = finished.size();
        if (taken != 0) completed = finished.take(0);
    }
    check(sent_status, "sending the file");
    auto [response, response_status] = std::move(completed.response);
    check(response_status, "the file call");
    check(body_of(response) == std::string_view(script.bytes.data(), script.length), "sending the build script");
    std::printf("passed awaited file reply\n");
}

/** A stand-in for the library that finishes one call after a few turns of the loop. */
struct late_engine_t {
    ucall_outcome_t* outcome = nullptr;
    ucall_bytes_view_t* written = nullptr;
    std::size_t turns_left = 3;
    test_loop_t* loop = nullptr;

    static void turn(void* engine_state) noexcept {
        late_engine_t& engine = *static_cast<late_engine_t*>(engine_state);
        if (--engine.turns_left != 0) return engine.loop->post(&turn, engine_state);
        *engine.written = uc::bytes_view("late");
        engine.outcome->status = ucall_status_success_k;
    }
};

/** Awaits a call @p engine finishes later on @p loop and copies its answer's length out. */
static detached_t awaited_late_call(late_engine_t& engine, test_loop_t& loop, std::size_t& answered) {
    uc::deferred<std::string_view> call; // an empty slot, reused without waiting
    call.resubmit([&](ucall_outcome_t* outcome, uc::outputs<std::string_view>* written) noexcept {
        engine.outcome = outcome;
        engine.written = &written->value;
        outcome->status = ucall_status_deferred_k;
    });
    loop.post(&late_engine_t::turn, &engine);
    auto [value, status] = co_await call.wait(loop);
    check(status, "awaiting a call that finishes later");
    answered = value.size();
}

/** A coroutine suspends only while its call is not final, and resumes with its outputs. */
static void test_awaited_late_call() {
    test_loop_t loop;
    late_engine_t engine {.loop = &loop};
    std::size_t answered = 0;
    awaited_late_call(engine, loop, answered);
    check(answered == 0, "suspending until the call is final");
    while (loop.head != loop.tail) loop.run();
    check(answered == 4 && engine.turns_left == 0, "resuming with the late answer");
    std::printf("passed awaited late call\n");
}

static void test_names_and_keys() {
    auto [code, code_status] = uc::status_from_name(uc::status_name(uc::status_code_t::connection_failed_k));
    check(code_status, "parsing a status name");
    check(code == ucall_status_connection_failed_k, "round-tripping a status name");
    auto [unknown, unknown_status] = uc::status_from_name("no-such-status");
    check(unknown_status == uc::status_code_t::invalid_argument_k, "refusing an unknown status name");

    auto [keypair, keypair_status] = uc::noise_key_generate();
    check(keypair_status, "generating a keypair");
    auto [derived, derived_status] = uc::noise_key_derive(keypair.private_key);
    check(derived_status, "deriving a public key");
    check(uc::noise_keys_equal(derived.public_key, keypair.public_key), "deriving the same public key");

    std::array<char, 16> decoded {};
    auto [text, text_status] = uc::decode_percent("a%20b+c", decoded, ucall_percent_query_k);
    check(text_status, "decoding percent escapes");
    check(text == "a b c", "decoding to spaces");
    std::printf("passed names and keys\n");
}

/** Routes register against either library, and the linked one tells whether it serves sockets:
 *  the stand-in answers a poll with @c status_code_t::unsupported_k. */
static bool test_routes_and_network() {
    uc::interface_t const interfaces[] {{.address = "127.0.0.1:0"}};
    auto [server, server_status] = uc::server_t::make(interfaces);
    check(server_status, "starting the probing server");
    echo_service_t service;
    auto echo = [&service](uc::request_t request) noexcept { service.echo_query(std::move(request)); };
    check(server.get<greet>("/hello/{name}"), "routing a function");
    check(server.post<&echo_service_t::echo_query>("/echo", service), "routing a member");
    check(server.put("/echo", echo), "routing a callable");
    check(server.get<greet>("/hello/{name}") == uc::status_code_t::already_exists_k, "refusing a second route");
    uc::batching_t const batching {};
    auto [batch, batch_status] = server.batch<greet_batch>("/batch/{name}", ucall_verb_get_k, batching);
    check(batch_status, "batching a function");
    auto [client, client_status] = uc::client_t::make({.max_concurrent_connections = 1});
    check(client_status, "starting the probing client");
    uc::status_t const polled = server.take_call(0, std::chrono::microseconds(0));
    std::printf("passed routes and network probe\n");
    if (polled == uc::status_code_t::unsupported_k) return false;
    check(polled, "polling the probing server");
    return true;
}

int main(int argc, char** argv) {
    test_names_and_keys();
    test_awaited_late_call();
    if (!test_routes_and_network()) {
        std::printf("skipped the round trips, which the stand-in does not serve\n");
        return 0;
    }
    test_greeting_round_trip();
    test_awaited_file_reply(argc > 1 ? argv[1] : "cpp");
    return 0;
}
