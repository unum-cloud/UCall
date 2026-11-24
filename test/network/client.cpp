/**
 *  @file test/network/client.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The scripted server against the client pipeline, and client allocations and lifetime.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build
#include <network.hpp>

#include "variants.hpp" // `io_queues_t`

namespace unum::ucall::test::network {

#pragma region Scripted Servers
#if UCALL_OS_POSIX_

/** The length of the first whole request in @p wire, framed by <tt>content-length</tt>, or zero. */
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

/** A 200 carrying @p body, announcing <tt>connection: close</tt> when @p after closes. */
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
    split_mix_generator_t generator;

    /** Whole requests read on each connection, in accept order; read them after @c stop. */
    std::vector<std::size_t> requests_per_connection;

    /** The most requests read and not yet answered at once; read it after @c stop. */
    std::size_t deepest = 0;

    std::atomic<bool> stopping {false};
    std::thread thread;

    scripted_server_t(split_mix_generator_t& seeds, script_t script, std::chrono::milliseconds pause = {})
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
                deepest = fu::max_of(deepest, whole_requests(std::string_view {peer.received}.substr(answered_bytes)));
                for (std::size_t length;
                     open && (length = request_length(std::string_view {peer.received}.substr(answered_bytes)));) {
                    auto const answer = script(std::string_view {peer.received}.substr(answered_bytes, length),
                                               connection, answered++);
                    answered_bytes += length;
                    if (!answer.bytes.empty())
                        open = peer.write(byte_span(answer.bytes), answer.bytes.size(), generator,
                                          steady_clock::now() + wait_limit_k);
                    if (answer.after != after_answer_t::close_k) continue;
                    ::shutdown(peer.descriptor, SHUT_WR);
                    for (auto const until = steady_clock::now() + wait_limit_k;
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

static bool submit(fixture_t& fixture, scripted_call_t& planned) {
    ucall_outcome_t outcome {};
    ucall_client_call_t call {};
    call.client = fixture.client;
    call.outcome = &outcome;
    call.url = bytes_view(planned.url);
    call.verb = planned.verb;
    call.context = &planned;
    call.headers = planned.header.length ? &planned.header : nullptr;
    call.headers_count = planned.header.length ? 1 : 0;
    call.options.timeout_microseconds = planned.timeout_microseconds;
    ucall_client_call(&call);
    return expect_true(outcome.status == ucall_status_success_k, "submitting {}: {}", planned.url,
                       ucall_status_name(outcome.status));
}

/** Checks a completed call is a 200 carrying its own planned body, then frees the response. */
static void check_answer(ucall_completed_call_t const& completed) {
    auto const* planned = static_cast<scripted_call_t const*>(completed.context);
    expect_true(planned && completed.outcome.status == ucall_status_success_k && completed.response, "{} completed {}",
                planned ? planned->url : "no call", ucall_status_name(completed.outcome.status));
    if (!completed.response) return;
    ucall_outcome_t outcome {};
    ucall_bytes_view_t body {};
    ucall_client_response_body_t get {completed.response, &outcome, &body};
    ucall_client_response_body(&get);
    std::string_view const text {reinterpret_cast<char const*>(body.data), body.length};
    auto const status = ucall_client_response_status(completed.response);
    expect_true(status == ucall_http_status_ok_k && planned && text == planned->expected, "{} answered {} {:?}",
                planned ? planned->url : "no call", status, text);
    ucall_client_response_free(completed.response);
}

/** Submits every call of @p plan in order, then checks each answer in whatever order they come. */
template <std::size_t count_>
static void exchange_all(fixture_t& fixture, std::array<scripted_call_t, count_>& plan) {
    std::size_t const failed_before = test_run.failed_checks.load();
    for (auto& planned : plan) submit(fixture, planned);
    for (std::size_t i = 0; i != count_ && test_run.failed_checks.load() == failed_before; ++i)
        check_answer(fixture.wait());
}

/** Answers every request with its own target, closing when the request asks to. */
static scripted_answer_t answer_target(std::string_view request, std::size_t, std::size_t) {
    bool const closes = request.find("\r\nconnection: close\r\n") != std::string_view::npos;
    return answer_ok(request_target(request), closes ? after_answer_t::close_k : after_answer_t::keep_open_k);
}

/** A HEAD answered without <tt>content-length</tt> keeps the connection for the GET behind it. */
static void test_lengthless_head_keeps_connection(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {.pipelined_calls = 4}};
    scripted_server_t server {generator,
                              [](std::string_view request, std::size_t connection, std::size_t index) {
                                  return request.starts_with("HEAD ") ? scripted_answer_t {"HTTP/1.1 200 OK\r\n\r\n"}
                                                                      : answer_target(request, connection, index);
                              },
                              100ms};
    if (!expect_true(fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
                     ucall_status_name(fixture.status)))
        return;
    std::array<scripted_call_t, 2> plan {{{server.url("/head"), ucall_verb_head_k, ""}, {server.url("/get")}}};
    plan[1].expected = "/get";
    exchange_all(fixture, plan);
    server.stop();
    expect_true(server.requests_per_connection == (std::vector<std::size_t> {2}), "{} connections sent the calls",
                server.requests_per_connection.size());
    fixture.stop();
}

/** A caller's <tt>Connection: close</tt> on the second of four calls keeps the last two off its
 *  connection: they leave on the next one, and every call is answered. */
static void test_caller_close_mid_pipeline(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {.pipelined_calls = 4}};
    scripted_server_t server {generator, answer_target, 100ms};
    if (!expect_true(fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
                     ucall_status_name(fixture.status)))
        return;
    std::array<scripted_call_t, 4> plan {{{server.url("/a"), ucall_verb_get_k, "/a"},
                                          {server.url("/b"), ucall_verb_get_k, "/b", bytes_view("Connection: close")},
                                          {server.url("/c"), ucall_verb_get_k, "/c"},
                                          {server.url("/d"), ucall_verb_get_k, "/d"}}};
    exchange_all(fixture, plan);
    server.stop();
    expect_true(server.requests_per_connection == (std::vector<std::size_t> {2, 2}),
                "{} connections, the first carrying {} requests", server.requests_per_connection.size(),
                server.requests_per_connection.empty() ? 0 : server.requests_per_connection[0]);
    fixture.stop();
}

/** A POST waits for the response to the POST before it, per RFC 9112 §9.3.2, rather than
 *  pipelining behind it. */
static void test_post_waits_behind_post(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {.pipelined_calls = 4}};
    scripted_server_t server {generator, answer_target, 100ms};
    if (!expect_true(fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
                     ucall_status_name(fixture.status)))
        return;
    std::array<scripted_call_t, 2> plan {
        {{server.url("/first"), ucall_verb_post_k, "/first"}, {server.url("/second"), ucall_verb_post_k, "/second"}}};
    exchange_all(fixture, plan);
    server.stop();
    expect_true(server.deepest == 1, "the server held {} requests at once", server.deepest);
    expect_true(server.requests_per_connection == (std::vector<std::size_t> {2}), "{} connections",
                server.requests_per_connection.size());
    fixture.stop();
}

/** A call with a short timeout behind one with a long timeout times out on its own deadline, and
 *  the longer call is answered on a fresh connection. */
static void test_short_timeout_behind_long(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    std::size_t const failed_before = test_run.failed_checks.load();
    fixture_t fixture {cell, {.pipelined_calls = 4}};
    scripted_server_t server {generator, [](std::string_view request, std::size_t connection, std::size_t index) {
                                  return connection ? answer_target(request, connection, index) : scripted_answer_t {};
                              }};
    if (!expect_true(fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
                     ucall_status_name(fixture.status)))
        return;
    std::array<scripted_call_t, 2> plan {{{server.url("/long"), ucall_verb_get_k, "/long", {}, 3'000'000},
                                          {server.url("/short"), ucall_verb_get_k, "/short", {}, 200'000}}};
    // The queue runs by deadline, so the short call follows only once the long one has left.
    submit(fixture, plan[0]);
    for (steady_clock::time_point const settled = steady_clock::now() + 100ms; steady_clock::now() < settled;) {
        ucall_completed_call_t completed {};
        expect_true(!fixture.poll(completed), "a call completed early");
    }
    submit(fixture, plan[1]);
    auto const submitted = steady_clock::now();
    auto completed = fixture.wait();
    auto const elapsed = steady_clock::now() - submitted;
    expect_true(completed.context == &plan[1] && completed.outcome.status == ucall_status_timeout_k &&
                    elapsed >= 200ms && elapsed < 1s,
                "{} completed {} after {} ms", completed.context == &plan[1] ? "the short call" : "another",
                ucall_status_name(completed.outcome.status),
                std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
    if (completed.response) ucall_client_response_free(completed.response);
    if (test_run.failed_checks.load() == failed_before) check_answer(fixture.wait());
    fixture.stop();
}

/** A keep-alive connection the server closes while idle is noticed, so the POST after it opens a
 *  new one; a POST whose reused connection closes before any response byte is sent again. */
static void test_stale_idle_connection(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {.pipelined_calls = 4}};
    scripted_server_t server {
        generator, [](std::string_view request, std::size_t connection, std::size_t index) -> scripted_answer_t {
            if (connection == 0) return {answer_target(request, connection, index).bytes, after_answer_t::close_k};
            if (connection == 1 && index == 1) return {{}, after_answer_t::close_k};
            return answer_target(request, connection, index);
        }};
    if (!expect_true(fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
                     ucall_status_name(fixture.status)))
        return;
    std::array<scripted_call_t, 3> plan {{{server.url("/first"), ucall_verb_get_k, "/first"},
                                          {server.url("/second"), ucall_verb_post_k, "/second"},
                                          {server.url("/third"), ucall_verb_post_k, "/third"}}};
    submit(fixture, plan[0]);
    check_answer(fixture.wait());
    for (steady_clock::time_point const settled = steady_clock::now() + 200ms; steady_clock::now() < settled;) {
        ucall_completed_call_t completed {};
        expect_true(!fixture.poll(completed), "a call completed unasked");
    }
    for (std::size_t i = 1; i != plan.size(); ++i) {
        submit(fixture, plan[i]);
        check_answer(fixture.wait());
    }
    server.stop();
    expect_true(server.requests_per_connection == (std::vector<std::size_t> {1, 2, 1}), "{} connections",
                server.requests_per_connection.size());
    fixture.stop();
}

/** The server closes after answering the first of two pipelined calls: the POST it never read is
 *  sent again on a new connection, per RFC 9112 §9.6, and answered. */
static void test_server_close_mid_pipeline(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {.pipelined_calls = 4}};
    scripted_server_t server {generator,
                              [](std::string_view request, std::size_t connection, std::size_t index) {
                                  return connection ? answer_target(request, connection, index)
                                                    : answer_ok(request_target(request), after_answer_t::close_k);
                              },
                              100ms};
    if (!expect_true(fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
                     ucall_status_name(fixture.status)))
        return;
    std::array<scripted_call_t, 2> plan {
        {{server.url("/first"), ucall_verb_get_k, "/first"}, {server.url("/second"), ucall_verb_post_k, "/second"}}};
    exchange_all(fixture, plan);
    server.stop();
    expect_true(server.requests_per_connection == (std::vector<std::size_t> {2, 1}), "{} connections",
                server.requests_per_connection.size());
    fixture.stop();
}

/** A redirect in the middle of a pipeline, sent with <tt>connection: close</tt>, is followed, and
 *  the POST behind it is sent again on the next connection; each call gets its own answer. */
static void test_redirect_mid_pipeline(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {.pipelined_calls = 4}};
    scripted_server_t server {generator,
                              [](std::string_view request, std::size_t connection, std::size_t index) {
                                  if (request_target(request) != "/moved")
                                      return answer_target(request, connection, index);
                                  return scripted_answer_t {"HTTP/1.1 302 Found\r\nlocation: /landed\r\n" //
                                                            "content-length: 0\r\nconnection: close\r\n\r\n",
                                                            after_answer_t::close_k};
                              },
                              100ms};
    if (!expect_true(fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
                     ucall_status_name(fixture.status)))
        return;
    std::array<scripted_call_t, 3> plan {{{server.url("/first"), ucall_verb_get_k, "/first"},
                                          {server.url("/moved"), ucall_verb_get_k, "/landed"},
                                          {server.url("/last"), ucall_verb_post_k, "/last"}}};
    exchange_all(fixture, plan);
    server.stop();
    expect_true(server.requests_per_connection == (std::vector<std::size_t> {3, 2}), "{} connections",
                server.requests_per_connection.size());
    fixture.stop();
}

/** A client logs a dial that fails every address, naming the address it could not reach. */
static void test_client_log_lines(sweep_cell_t const& cell) {
    struct collected_t {
        std::mutex mutex;
        std::vector<std::string> lines;
    } collected;
    auto collect = [](ucall_log_level_t, ucall_bytes_view_t line, void* context) {
        auto& into = *static_cast<collected_t*>(context);
        std::lock_guard lock {into.mutex};
        into.lines.emplace_back(reinterpret_cast<char const*>(line.data), line.length);
    };
    // A port bound and released again, so nothing listens on it.
    int const probe = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in bound {};
    bound.sin_family = AF_INET;
    bound.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t length = sizeof(bound);
    if (!expect_true(probe >= 0 && ::bind(probe, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) == 0 &&
                         ::getsockname(probe, reinterpret_cast<sockaddr*>(&bound), &length) == 0,
                     "no free port"))
        return;
    ::close(probe);
    std::string const address = fmt::format("127.0.0.1:{}", ntohs(bound.sin_port));
    std::string const url = fmt::format("http://{}/", address);
    ucall_client_t client {};
    ucall_outcome_t outcome {};
    ucall_client_options_t config {};
    config.max_concurrent_connections = 1;
    config.backend = cell.backend;
    config.cpu_class_ceiling = cell.cpu_class_ceiling;
    config.log = {collect, &collected, ucall_log_format_human_k, ucall_log_level_info_k};
    ucall_client_init_t init {&client, &outcome, &config, nullptr};
    ucall_client_init(&init);
    if (!expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status))) return;
    ucall_client_call_t call {};
    call.client = client;
    call.outcome = &outcome;
    call.url = bytes_view(url);
    call.verb = ucall_verb_get_k;
    call.options.max_retries = 1;
    ucall_client_call(&call);
    expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    ucall_completed_call_t completed {};
    std::size_t count = 0;
    for (auto const deadline = steady_clock::now() + wait_limit_k; !count && steady_clock::now() < deadline;) {
        ucall_client_take_completed_t take {client, &outcome, &completed, 1, &count, 100'000};
        ucall_client_take_completed(&take);
    }
    expect_true(count && completed.outcome.status == ucall_status_connection_failed_k, "the dial ended as {}",
                ucall_status_name(completed.outcome.status));
    ucall_client_free(client);
    std::string const expected = fmt::format("warning connect_failed address={}", address);
    std::lock_guard lock {collected.mutex};
    expect_true(std::any_of(collected.lines.begin(), collected.lines.end(),
                            [&](std::string const& line) { return line.starts_with(expected); }),
                "{} lines, the first: {}", collected.lines.size(),
                collected.lines.empty() ? std::string {} : collected.lines.front());
}

/** A <tt>location</tt> holding only a query keeps the whole path it redirects from, per RFC 3986
 *  5.2.2, rather than resolving against its directory. */
static void test_redirect_query_only(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {}};
    scripted_server_t server {
        generator, [](std::string_view request, std::size_t connection, std::size_t index) {
            if (request_target(request) != "/dir/page") return answer_target(request, connection, index);
            return scripted_answer_t {"HTTP/1.1 302 Found\r\nlocation: ?q=1\r\ncontent-length: 0\r\n\r\n"};
        }};
    if (!expect_true(fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
                     ucall_status_name(fixture.status)))
        return;
    std::array<scripted_call_t, 1> plan {{{server.url("/dir/page"), ucall_verb_get_k, "/dir/page?q=1"}}};
    exchange_all(fixture, plan);
    server.stop();
    fixture.stop();
}

/** A plaintext call redirected to <tt>http+noise://</tt> is refused: a redirect never changes the
 *  security a call was made under, and such a client may hold no Noise key at all. */
static void test_redirect_to_noise_refused(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {}};
    scripted_server_t server {generator, [](std::string_view, std::size_t, std::size_t) {
                                  return scripted_answer_t {"HTTP/1.1 302 Found\r\n"                  //
                                                            "location: http+noise://127.0.0.1:1/\r\n" //
                                                            "content-length: 0\r\n\r\n"};
                              }};
    if (!expect_true(fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
                     ucall_status_name(fixture.status)))
        return;
    scripted_call_t planned {server.url("/moved"), ucall_verb_get_k, ""};
    submit(fixture, planned);
    auto const completed = fixture.wait();
    expect_true(!completed.response && completed.outcome.status == ucall_status_peer_rejected_k,
                "the call completed {}", ucall_status_name(completed.outcome.status));
    if (completed.response) ucall_client_response_free(completed.response);
    server.stop();
    fixture.stop();
}

/** Response field lines read back by index in arrival order, repeated names apart, names lowercased
 *  as the parser keeps them and values trimmed, and an index past the last one is not found. */
static void test_client_response_fields(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {}};
    scripted_server_t server {
        generator, [](std::string_view, std::size_t, std::size_t) {
            return scripted_answer_t {"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\ncontent-length: 2\r\n" //
                                      "X-Mixed:  spaced  \r\nset-cookie: b=2\r\n\r\nok"};
        }};
    if (!expect_true(fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
                     ucall_status_name(fixture.status)))
        return;
    scripted_call_t planned {server.url("/fields"), ucall_verb_get_k, "ok"};
    submit(fixture, planned);
    auto const completed = fixture.wait();
    if (!expect_true(completed.response, "the call completed {}", ucall_status_name(completed.outcome.status))) return;
    std::size_t const count = ucall_client_response_fields_count(completed.response);
    ucall_outcome_t outcome {};
    expect_true(count == 4, "{} fields", count);
    std::string read;
    for (std::size_t index = 0; index <= count; ++index) {
        ucall_bytes_view_t name {}, value {};
        ucall_client_response_field_t field {completed.response, &outcome, index, &name, &value};
        ucall_client_response_field(&field);
        if (outcome.status != ucall_status_success_k) {
            expect_true(index == count && outcome.status == ucall_status_not_found_k, "field {}: {}", index,
                        ucall_status_name(outcome.status));
            break;
        }
        read += fmt::format("{}={};", text_view(name), text_view(value));
    }
    expect_true(read == "set-cookie=a=1;content-length=2;x-mixed=spaced;set-cookie=b=2;", "read {}", read);
    ucall_client_response_free(completed.response);
    server.stop();
    fixture.stop();
}

/** A close-delimited response past the client's cap fails its call with @c ucall_status_overflow_k
 *  rather than buffering until the server closes. */
static void test_client_response_cap(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    std::size_t const cap = 64 * 1024;
    fixture_t fixture {cell, {.max_response_bytes = cap}};
    std::string const body(2 * cap, 'r');
    scripted_server_t server {generator, [&](std::string_view, std::size_t, std::size_t) {
                                  return scripted_answer_t {fmt::format("HTTP/1.1 200 OK\r\n\r\n{}", body),
                                                            after_answer_t::close_k};
                              }};
    if (!expect_true(fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
                     ucall_status_name(fixture.status)))
        return;
    scripted_call_t planned {server.url("/large")};
    submit(fixture, planned);
    auto const completed = fixture.wait();
    expect_true(completed.outcome.status == ucall_status_overflow_k, "a body twice the cap completed {}",
                ucall_status_name(completed.outcome.status));
    if (completed.response) ucall_client_response_free(completed.response);
    server.stop();
    fixture.stop();
}

/** A response that overtakes its own long request waits in the transport behind a receive armed
 *  meanwhile, which must follow the buffer once that response moves into its call, as the next
 *  response lands through it. */
static void test_receive_follows_early_response(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {}};
    raw_listener_t listener;
    if (!expect_true(fixture.status == ucall_status_success_k && !listener.address.empty(), "setup: {}",
                     ucall_status_name(fixture.status)))
        return;
    // Beyond what the sockets buffer while the peer reads nothing, so the send stays pending.
    std::string const body(std::size_t {16} << 20, 'b');
    std::string const url = fmt::format("http://{}/long", listener.address);
    std::thread peer_thread {[&, seed = generator()] {
        split_mix_generator_t peer_generator {seed};
        auto const deadline = steady_clock::now() + wait_limit_k;
        raw_client_t peer;
        if (!listener.accept(peer, deadline)) return;
        auto read_head = [&](std::size_t from) {
            while (peer.received.find("\r\n\r\n", from) == std::string::npos)
                if (peer.read(peer.received.size() + 1, deadline) != read_end_t::filled_k) return std::string::npos;
            return peer.received.find("\r\n\r\n", from) + 4;
        };
        std::size_t const head = read_head(0);
        std::string const early = answer_ok("early").bytes, late = answer_ok("late").bytes;
        if (head == std::string::npos || !peer.write(byte_span(early), early.size(), peer_generator, deadline)) return;
        // The client reads the response and arms its next receive before the request ends.
        std::this_thread::sleep_for(100ms);
        if (peer.read(head + body.size(), deadline) != read_end_t::filled_k) return;
        if (read_head(head + body.size()) == std::string::npos) return;
        [[maybe_unused]] bool const written = peer.write(byte_span(late), late.size(), peer_generator, deadline);
    }};
    auto call = [&](ucall_verb_t verb, std::string_view sent, std::string_view expected) {
        ucall_outcome_t outcome {};
        ucall_client_call_t arguments {};
        arguments.client = fixture.client;
        arguments.outcome = &outcome;
        arguments.url = bytes_view(url);
        arguments.verb = verb;
        arguments.body = bytes_view(sent);
        ucall_client_call(&arguments);
        expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
        auto const completed = fixture.wait();
        expect_true(completed.outcome.status == ucall_status_success_k && completed.response, "{}",
                    ucall_status_name(completed.outcome.status));
        if (!completed.response) return;
        ucall_bytes_view_t answered {};
        ucall_client_response_body_t get {completed.response, &outcome, &answered};
        ucall_client_response_body(&get);
        std::string_view const text {reinterpret_cast<char const*>(answered.data), answered.length};
        expect_true(text == expected, "answered {:?} for {:?}", text, expected);
        ucall_client_response_free(completed.response);
    };
    call(ucall_verb_post_k, body, "early");
    call(ucall_verb_get_k, {}, "late");
    peer_thread.join();
    fixture.stop();
}

/** A plaintext client on @p cell's backend drawing every allocation from @p ledger, or null when
 *  it fails to start. */
static ucall_client_t counted_client(allocation_ledger_t& ledger, sweep_cell_t const& cell) {
    ucall_client_t client {};
    ucall_outcome_t outcome {};
    ucall_client_options_t config {};
    config.max_concurrent_connections = 1;
    config.backend = cell.backend;
    ucall_client_init_t init {&client, &outcome, &config, nullptr};
    counted_network_t::client_t::client_init(&init, counting_allocator<byte_t> {ledger});
    return outcome.status == ucall_status_success_k ? client : nullptr;
}

/** Calls @p url on @p client and waits up to @c wait_limit_k for the call to complete. */
static ucall_completed_call_t counted_call(ucall_client_t client, std::string const& url) {
    ucall_outcome_t outcome {};
    ucall_client_call_t call {};
    call.client = client;
    call.outcome = &outcome;
    call.url = bytes_view(url);
    call.verb = ucall_verb_get_k;
    ucall_client_call(&call);
    ucall_completed_call_t completed {};
    completed.outcome.status = outcome.status;
    if (outcome.status != ucall_status_success_k) return completed;
    std::size_t count {};
    ucall_client_take_completed_t take {client, &outcome, &completed, 1, &count, 5'000'000};
    ucall_client_take_completed(&take);
    if (!count) completed.outcome.status = ucall_status_timeout_k;
    return completed;
}

/** A front server's handler calls out to an upstream through a client bound to its loop, and the
 *  loop's own thread replies once the bound client finished, with no other thread involved. */
struct bound_front_t {
    ucall_server_t server {};
    ucall_client_t bound {};
    std::string upstream_url {};
    ucall_received_http_request_t held {};
    static void forward(ucall_server_t, ucall_received_http_request_t request, void* context) {
        auto& front = *static_cast<bound_front_t*>(context);
        expect_true(!front.held, "a second request arrived while one is held");
        front.held = request;
        ucall_outcome_t outcome {};
        ucall_client_call_t call {};
        call.client = front.bound;
        call.outcome = &outcome;
        call.url = bytes_view(front.upstream_url);
        call.verb = ucall_verb_post_k;
        call.body = bytes_view("upstream says hi");
        ucall_client_call(&call);
        expect_true(outcome.status == ucall_status_success_k, "the bound call was refused: {}",
                    ucall_status_name(outcome.status));
    }
};

static void test_bound_client_calls_from_handler(sweep_cell_t const& cell) {
    fixture_t upstream {cell, {}};
    if (!expect_true(upstream.status == ucall_status_success_k, "setup: {}", ucall_status_name(upstream.status)))
        return;
    bound_front_t front;
    front.upstream_url = fmt::format("{}/echo/1", upstream.url);
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = bytes_view("127.0.0.1:0");
    network_interface.max_concurrent_connections = 1;
    ucall_server_options_t config {}, resolved {};
    config.interfaces = &network_interface;
    config.interfaces_count = 1;
    config.backend = cell.backend;
    config.cpu_class_ceiling = cell.cpu_class_ceiling;
    ucall_server_init_t init {&front.server, &outcome, &config, &resolved};
    ucall_server_init(&init);
    if (!expect_true(outcome.status == ucall_status_success_k, "front: {}", ucall_status_name(outcome.status))) return;
    ucall_server_add_http_endpoint_t add {front.server,           &outcome, bytes_view("/front"), ucall_verb_any_k,
                                          bound_front_t::forward, &front};
    ucall_server_add_http_endpoint(&add);
    expect_true(outcome.status == ucall_status_success_k);
    ucall_client_options_t bound_config {};
    bound_config.max_concurrent_connections = 1;
    bound_config.server = front.server;
    ucall_client_init_t bind {&front.bound, &outcome, &bound_config, nullptr};
    // A backend other than the loop's is refused, and the cell's own backend and ceiling bind.
    bound_config.backend = resolved.backend == ucall_io_backend_posix_k ? ucall_io_backend_linux_epollaio_k
                                                                        : ucall_io_backend_posix_k;
    ucall_client_init(&bind);
    expect_true(outcome.status == ucall_status_invalid_argument_k && !front.bound,
                "a bound client pinned to another backend turned {}", ucall_status_name(outcome.status));
    bound_config.backend = resolved.backend;
    bound_config.cpu_class_ceiling = cell.cpu_class_ceiling;
    ucall_client_init(&bind);
    expect_true(outcome.status == ucall_status_success_k, "bind: {}", ucall_status_name(outcome.status));
    ucall_server_free(front.server);
    expect_true(front.bound, "the server freed under its bound client");
    if (front.bound) {
        std::string const url = fmt::format("http://{}/front", text_view(resolved.interfaces[0].address));
        ucall_client_call_t call {};
        call.client = upstream.client;
        call.outcome = &outcome;
        call.url = bytes_view(url);
        call.verb = ucall_verb_get_k;
        ucall_client_call(&call);
        expect_true(outcome.status == ucall_status_success_k);
        steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
        ucall_completed_call_t answered {};
        while (steady_clock::now() < deadline && !upstream.poll(answered)) {
            ucall_server_take_call_t serving {front.server, &outcome, 0, 0};
            ucall_server_take_call(&serving);
            expect_true(outcome.status == ucall_status_success_k);
            ucall_completed_call_t upstream_answer {};
            std::size_t count = 0;
            ucall_client_take_completed_t take {front.bound, &outcome, &upstream_answer, 1, &count, 0};
            ucall_client_take_completed(&take);
            if (!count) continue;
            ucall_bytes_view_t body {};
            if (upstream_answer.response) {
                ucall_client_response_body_t get {upstream_answer.response, &outcome, &body};
                ucall_client_response_body(&get);
            }
            expect_true(front.held && upstream_answer.outcome.status == ucall_status_success_k,
                        "the upstream call ended with {}", ucall_status_name(upstream_answer.outcome.status));
            ucall_server_reply_content_t reply {front.server, &outcome, &front.held, ucall_http_status_ok_k,
                                                nullptr,      0,        body};
            ucall_server_reply_content(&reply);
            expect_true(outcome.status == ucall_status_success_k);
            front.held = {};
            ucall_client_response_free(upstream_answer.response);
        }
        expect_true(answered.outcome.status == ucall_status_success_k && answered.response,
                    "the front call ended with {}", ucall_status_name(answered.outcome.status));
        if (answered.response) {
            ucall_bytes_view_t body {};
            ucall_client_response_body_t get {answered.response, &outcome, &body};
            ucall_client_response_body(&get);
            expect_true(text_view(body) == "upstream says hi", "the front answered {}", text_view(body));
            ucall_client_response_free(answered.response);
        }
        ucall_client_free(front.bound);
    }
    ucall_server_free(front.server);
    upstream.stop();
}

/** A response freed after its client returns, with the client's pool, every byte the client
 *  allocated. */
static void test_client_responses_outlive_free(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    allocation_ledger_t ledger;
    ucall_client_t client = counted_client(ledger, cell);
    if (!expect_true(client, "the counted client failed to start")) return;
    auto const url = fmt::format("{}/echo/1", fixture.url);
    ucall_completed_call_t const freed = counted_call(client, url);
    ucall_completed_call_t const late = counted_call(client, url);
    expect_true(freed.response && late.response, "{} then {}", ucall_status_name(freed.outcome.status),
                ucall_status_name(late.outcome.status));
    if (freed.response) check_response(freed.response, {});
    ucall_client_free(client);
    expect_true(ledger.live() != 0, "the late response lost its pool with the client");
    if (late.response) check_response(late.response, {});
    expect_true(!ledger.live() && !ledger.live_bytes, "{} allocations of {} bytes outlived the last response",
                ledger.live(), ledger.live_bytes.load());
    fixture.stop();
}

/** Once 64 responses warmed the client, 1,000 more allocate nothing: each takes a freed response
 *  back and swaps its capacity with the connection's input. */
static void test_warm_client_allocates_nothing(sweep_cell_t const& cell) {
    std::size_t const failed_before = test_run.failed_checks.load();
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    allocation_ledger_t ledger;
    ucall_client_t client = counted_client(ledger, cell);
    if (!expect_true(client, "the counted client failed to start")) return;
    auto const url = fmt::format("{}/echo/1", fixture.url);
    std::size_t warm_allocations = 0;
    for (std::size_t call = 0; call != 64 + 1000 && test_run.failed_checks.load() == failed_before; ++call) {
        if (call == 64) warm_allocations = ledger.allocations;
        ucall_completed_call_t const completed = counted_call(client, url);
        expect_true(completed.response, "call {}: {}", call, ucall_status_name(completed.outcome.status));
        if (completed.response) check_response(completed.response, {});
    }
    expect_true(ledger.allocations == warm_allocations, "1,000 warm calls allocated {} times",
                ledger.allocations - warm_allocations);
    ucall_client_free(client);
    expect_true(!ledger.live(), "{} allocations outlived the client", ledger.live());
    fixture.stop();
}

/** Advances @p fixture's server loop and client once each, retrieving no completion. */
static void advance(fixture_t& fixture) {
    ucall_outcome_t outcome {};
    ucall_server_take_call_t serving {fixture.server, &outcome, 0, 0};
    ucall_server_take_call(&serving);
    std::size_t count = 0;
    ucall_client_take_completed_t take {fixture.client, &outcome, nullptr, 0, &count, 0};
    ucall_client_take_completed(&take);
}

/** Submits a streamed call of @p verb to @p url under @p security, its cookie @p context. */
static bool submit_streamed(fixture_t& fixture, std::string const& url, ucall_security_t security,
                            void* context = nullptr, ucall_verb_t verb = ucall_verb_get_k) {
    ucall_outcome_t outcome {};
    ucall_client_call_t call {};
    call.client = fixture.client;
    call.outcome = &outcome;
    call.url = bytes_view(url);
    call.verb = verb;
    call.context = context;
    call.options.security = security;
    call.options.noise_peer_key = &fixture.server_public;
    call.options.body_delivery = ucall_body_delivery_streamed_k;
    ucall_client_call(&call);
    return expect_true(outcome.status == ucall_status_success_k, "submitting {}: {}", url,
                       ucall_status_name(outcome.status));
}

/** One pull of @p response, answering its status and writing what it handed into @p data. */
static ucall_status_t pull_once(ucall_client_t client, ucall_received_http_response_t response,
                                std::string_view& data) {
    ucall_outcome_t outcome {};
    ucall_bytes_view_t chunk {};
    ucall_client_response_body_chunk_t pull {client, &outcome, response, &chunk};
    ucall_client_response_body_chunk(&pull);
    data = {reinterpret_cast<char const*>(chunk.data), chunk.length};
    return outcome.status;
}

/** Pulls @p response until its body ends or fails, handing @p each every chunk and advancing the
 *  fixture while nothing was decoded; answers how the body ended, or a timeout. */
template <typename each_type_>
static ucall_status_t pull_until_end(fixture_t& fixture, ucall_received_http_response_t response, each_type_&& each) {
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
    for (;;) {
        std::string_view data;
        ucall_status_t const status = pull_once(fixture.client, response, data);
        if (status == ucall_status_would_block_k) {
            if (steady_clock::now() > deadline) return ucall_status_timeout_k;
            advance(fixture);
            continue;
        }
        if (status != ucall_status_success_k || data.empty()) return status;
        each(data);
    }
}

/** The 64 MiB body the download routes send, as one view and as uneven chunk-sized parts. */
struct download_t {
    std::string body;
    std::vector<ucall_reply_part_t> parts;
    ucall_server_t server {};

    explicit download_t(split_mix_generator_t& generator) : body(std::size_t {64} << 20, '\0') {
        for (std::size_t offset = 0; offset != body.size(); offset += sizeof(std::uint64_t)) {
            std::uint64_t const word = generator();
            std::memcpy(body.data() + offset, &word, sizeof(word));
        }
        // Sizes straddling every receive boundary, from one byte to past the client's cap.
        std::size_t const sizes[] {1, 7, 4093, 65536, 300'001, 1 << 20, 3 << 20};
        for (std::size_t offset = 0, index = 0; offset != body.size(); ++index) {
            std::size_t const size = fu::min_of(sizes[index % std::size(sizes)], body.size() - offset);
            parts.push_back(bytes_part(std::string_view {body}.substr(offset, size)));
            offset += size;
        }
    }

    /** Replies with the whole body behind its <tt>content-length</tt>. */
    static void length(ucall_server_t, ucall_received_http_request_t request, void* context) {
        auto& download = *static_cast<download_t*>(context);
        ucall_outcome_t outcome {};
        ucall_server_reply_content_t reply {
            download.server, &outcome, &request, ucall_http_status_ok_k, nullptr, 0, bytes_view(download.body)};
        ucall_server_reply_content(&reply);
        expect_true(outcome.status == ucall_status_success_k, "reply: {}", ucall_status_name(outcome.status));
    }

    /** Replies with the body in chunks of every size in @c parts. */
    static void chunked(ucall_server_t, ucall_received_http_request_t request, void* context) {
        auto& download = *static_cast<download_t*>(context);
        ucall_outcome_t outcome {};
        ucall_server_reply_begin_t begin {download.server, &outcome, &request, ucall_http_status_ok_k, nullptr, 0};
        ucall_server_reply_begin(&begin);
        expect_true(outcome.status == ucall_status_success_k, "begin: {}", ucall_status_name(outcome.status));
        ucall_server_reply_append_t append {download.server, &outcome, request, download.parts.data(),
                                            download.parts.size()};
        ucall_server_reply_append(&append);
        expect_true(outcome.status == ucall_status_success_k, "append: {}", ucall_status_name(outcome.status));
        ucall_outcome_t ended {};
        ucall_server_reply_end_t end {download.server, &ended, &request};
        ucall_server_reply_end(&end);
        expect_true(ended.status == ucall_status_success_k, "end: {}", ucall_status_name(ended.status));
    }
};

/** A 64 MiB download through a 1 MiB response cap, by <tt>content-length</tt> and by chunks: the
 *  call completes at the head, and the pulls hand every byte in order, then the end. */
static void test_streamed_download(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    std::size_t const cap = std::size_t {1} << 20;
    fixture_t fixture {cell, {.max_response_bytes = cap}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    download_t download {generator};
    download.server = fixture.server;
    for (auto [route, callback] :
         {std::pair {"/download/length", &download_t::length}, std::pair {"/download/chunked", &download_t::chunked}}) {
        ucall_outcome_t outcome {};
        ucall_server_add_http_endpoint_t add {fixture.server,   &outcome, bytes_view(route),
                                              ucall_verb_get_k, callback, &download};
        ucall_server_add_http_endpoint(&add);
        if (!expect_true(outcome.status == ucall_status_success_k, "route: {}", ucall_status_name(outcome.status)))
            return;
    }
    for (std::string_view route : {"/download/length", "/download/chunked"}) {
        submit_streamed(fixture, fmt::format("{}{}", fixture.url, route), cell.security);
        auto const completed = fixture.wait();
        expect_true(completed.outcome.status == ucall_status_success_k && completed.response, "{}: {}", route,
                    ucall_status_name(completed.outcome.status));
        if (!completed.response) break;
        expect_true(ucall_client_response_status(completed.response) == ucall_http_status_ok_k);
        ucall_outcome_t outcome {};
        ucall_bytes_view_t whole {};
        ucall_client_response_body_t get {completed.response, &outcome, &whole};
        ucall_client_response_body(&get);
        expect_true(outcome.status == ucall_status_invalid_argument_k, "a streamed body read whole: {}",
                    ucall_status_name(outcome.status));
        std::size_t received = 0, pulls = 0, largest = 0;
        bool matches = true;
        ucall_status_t const ended = pull_until_end(fixture, completed.response, [&](std::string_view data) {
            matches = matches && received + data.size() <= download.body.size() &&
                      std::memcmp(data.data(), download.body.data() + received, data.size()) == 0;
            received += data.size();
            largest = fu::max_of(largest, data.size());
            ++pulls;
        });
        expect_true(ended == ucall_status_success_k && received == download.body.size() && matches,
                    "{} ended {} after {} of {} bytes in {} pulls, {}", route, ucall_status_name(ended), received,
                    download.body.size(), pulls, matches ? "in order" : "corrupted");
        // Each pull drains at most the window its connection reads into, which the cap bounds.
        expect_true(pulls > 1 && largest <= 2 * cap, "{} pulls, the largest {} bytes", pulls, largest);
        std::string_view data;
        expect_true(pull_once(fixture.client, completed.response, data) == ucall_status_success_k && data.empty(),
                    "a pull past the end handed {} bytes", data.size());
        ucall_client_response_free(completed.response);
    }
    fixture.stop();
}

/** A streamed call's small or missing body answers in one pull and then the end, a larger one in
 *  however many pulls it arrived in, and a buffered response refuses pulls. */
static void test_streamed_whole_bodies(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    struct planned_t {
        ucall_verb_t verb;
        std::string_view target;
        ucall_http_status_t status;
    };
    for (planned_t const planned : {planned_t {ucall_verb_get_k, "/vectored", ucall_http_status_created_k},
                                    planned_t {ucall_verb_head_k, "/vectored", ucall_http_status_created_k},
                                    planned_t {ucall_verb_get_k, "/status/204", 204},
                                    planned_t {ucall_verb_get_k, "/headers", ucall_http_status_ok_k}}) {
        submit_streamed(fixture, fmt::format("{}{}", fixture.url, planned.target), cell.security, nullptr,
                        planned.verb);
        auto const completed = fixture.wait();
        expect_true(completed.outcome.status == ucall_status_success_k && completed.response, "{}: {}", planned.target,
                    ucall_status_name(completed.outcome.status));
        if (!completed.response) break;
        expect_true(ucall_client_response_status(completed.response) == planned.status, "{} answered {}",
                    planned.target, ucall_client_response_status(completed.response));
        bool const bodiless = planned.verb == ucall_verb_head_k || planned.status == 204;
        if (bodiless || planned.target == "/headers") {
            std::string_view first, second;
            ucall_status_t const once = pull_once(fixture.client, completed.response, first);
            ucall_status_t const twice = pull_once(fixture.client, completed.response, second);
            expect_true(once == ucall_status_success_k && twice == ucall_status_success_k && second.empty() &&
                            first.empty() == bodiless,
                        "{} {} pulled {} bytes as {}, then {} bytes as {}",
                        planned.verb == ucall_verb_head_k ? "HEAD" : "GET", planned.target, first.size(),
                        ucall_status_name(once), second.size(), ucall_status_name(twice));
        }
        else {
            std::size_t received = 0;
            ucall_status_t const ended = pull_until_end(fixture, completed.response,
                                                        [&](std::string_view data) { received += data.size(); });
            expect_true(ended == ucall_status_success_k && received == 100 * 1024 + 11, "{} ended {} after {} bytes",
                        planned.target, ucall_status_name(ended), received);
        }
        ucall_client_response_free(completed.response);
    }
    auto const buffered = call_and_wait(fixture, ucall_verb_get_k, "/echo/1", cell.security);
    if (buffered.response) {
        std::string_view data;
        expect_true(pull_once(fixture.client, buffered.response, data) == ucall_status_invalid_argument_k,
                    "a buffered response was pulled");
        ucall_client_response_free(buffered.response);
    }
    fixture.stop();
}

/** A body cut short, a malformed chunk size, and a close-delimited body past the cap: the pulls
 *  hand what was decoded, then how the body ended. */
static void test_streamed_endings(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    std::size_t const cap = 64 * 1024;
    std::string const long_body(2 * cap, 'c');
    struct planned_t {
        std::string answer;
        std::string_view expected;
        ucall_status_t ended;
    };
    planned_t const plan[] {
        {"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\nzz\r\n", "hello",
         ucall_status_malformed_k},
        {"HTTP/1.1 200 OK\r\ncontent-length: 100\r\n\r\nshort", "short", ucall_status_connection_closed_k},
        {fmt::format("HTTP/1.1 200 OK\r\n\r\n{}", long_body), long_body, ucall_status_success_k},
    };
    for (planned_t const& planned : plan) {
        fixture_t fixture {cell, {.max_response_bytes = cap}};
        scripted_server_t server {generator, [&](std::string_view, std::size_t, std::size_t) {
                                      return scripted_answer_t {planned.answer, after_answer_t::close_k};
                                  }};
        if (!expect_true(fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
                         ucall_status_name(fixture.status)))
            return;
        submit_streamed(fixture, server.url("/ending"), ucall_security_none_k);
        auto const completed = fixture.wait();
        expect_true(completed.outcome.status == ucall_status_success_k && completed.response, "the head: {}",
                    ucall_status_name(completed.outcome.status));
        if (completed.response) {
            std::string received;
            ucall_status_t const ended = pull_until_end(fixture, completed.response,
                                                        [&](std::string_view data) { received += data; });
            expect_true(ended == planned.ended && received == planned.expected,
                        "ended {} rather than {} after {} bytes", ucall_status_name(ended),
                        ucall_status_name(planned.ended), received.size());
            ucall_client_response_free(completed.response);
        }
        server.stop();
        fixture.stop();
    }
}

/** A streamed body past the cap is a barrier before the response pipelined behind it, which
 *  answers its own call once the body ended, on the same connection. */
static void test_streamed_barrier(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    std::size_t const cap = 64 * 1024;
    std::string const body(4 * cap, 'b');
    fixture_t fixture {cell, {.pipelined_calls = 2, .max_response_bytes = cap}};
    scripted_server_t server {generator,
                              [&](std::string_view request, std::size_t connection, std::size_t index) {
                                  return index ? answer_target(request, connection, index) : answer_ok(body);
                              },
                              100ms};
    if (!expect_true(fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
                     ucall_status_name(fixture.status)))
        return;
    int streamed = 0;
    scripted_call_t follower {server.url("/follower")};
    follower.expected = "/follower";
    submit_streamed(fixture, server.url("/streamed"), ucall_security_none_k, &streamed);
    submit(fixture, follower);
    auto const head = fixture.wait();
    expect_true(head.context == &streamed && head.outcome.status == ucall_status_success_k && head.response,
                "the streamed call completed {}", ucall_status_name(head.outcome.status));
    if (head.response) {
        std::size_t received = 0;
        ucall_status_t const ended = pull_until_end(fixture, head.response,
                                                    [&](std::string_view data) { received += data.size(); });
        expect_true(ended == ucall_status_success_k && received == body.size(), "ended {} after {} bytes",
                    ucall_status_name(ended), received);
        ucall_client_response_free(head.response);
    }
    check_answer(fixture.wait());
    server.stop();
    expect_true(server.requests_per_connection == (std::vector<std::size_t> {2}), "{} connections sent the calls",
                server.requests_per_connection.size());
    fixture.stop();
}

/** Freeing a streamed response mid-body closes its connection and ends the call pipelined behind it
 *  with @c ucall_status_connection_closed_k, never sending it again; freeing the client then cuts
 *  another streamed body short. */
static void test_streamed_free_mid_body(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {.pipelined_calls = 2}};
    scripted_server_t server {
        generator,
        [](std::string_view, std::size_t, std::size_t index) {
            std::string_view const head = "HTTP/1.1 200 OK\r\ncontent-length: 1000000\r\n\r\npartial";
            return scripted_answer_t {std::string {index ? std::string_view {} : head}};
        },
        100ms};
    if (!expect_true(fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
                     ucall_status_name(fixture.status)))
        return;
    int streamed = 0;
    scripted_call_t follower {server.url("/follower")};
    submit_streamed(fixture, server.url("/streamed"), ucall_security_none_k, &streamed);
    submit(fixture, follower);
    auto const head = fixture.wait();
    expect_true(head.context == &streamed && head.outcome.status == ucall_status_success_k && head.response,
                "the streamed call completed {}", ucall_status_name(head.outcome.status));
    if (head.response) {
        std::string received;
        steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
        while (received.size() < 7 && steady_clock::now() < deadline) {
            std::string_view data;
            if (pull_once(fixture.client, head.response, data) == ucall_status_success_k) received += data;
            else advance(fixture);
        }
        expect_true(received == "partial", "pulled {:?}", received);
        ucall_client_response_free(head.response);
    }
    auto const settled = fixture.wait();
    expect_true(
        settled.context == &follower && settled.outcome.status == ucall_status_connection_closed_k && !settled.response,
        "the follower completed {}", ucall_status_name(settled.outcome.status));
    if (settled.response) ucall_client_response_free(settled.response);

    // A second connection streams another body, which the client's free cuts short.
    submit_streamed(fixture, server.url("/streamed"), ucall_security_none_k, &streamed);
    auto const second = fixture.wait();
    expect_true(second.outcome.status == ucall_status_success_k && second.response, "the second call: {}",
                ucall_status_name(second.outcome.status));
    // A pull names the client its response came from, whose handle it never reads.
    ucall_client_t const freed = std::exchange(fixture.client, nullptr);
    ucall_client_free(freed);
    if (second.response) {
        std::string_view data;
        ucall_status_t const status = pull_once(freed, second.response, data);
        expect_true(status == ucall_status_connection_closed_k && data.empty(),
                    "a pull after the client's free answered {} with {} bytes", ucall_status_name(status), data.size());
        ucall_client_response_free(second.response);
    }
    server.stop();
    expect_true(server.requests_per_connection == (std::vector<std::size_t> {2, 1}), "{} connections sent the calls",
                server.requests_per_connection.size());
    fixture.stop();
}

void test_client_cell(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    if (cell.security == ucall_security_none_k) {
        test_lengthless_head_keeps_connection(cell, generator);
        test_caller_close_mid_pipeline(cell, generator);
        test_post_waits_behind_post(cell, generator);
        test_short_timeout_behind_long(cell, generator);
        test_stale_idle_connection(cell, generator);
        test_server_close_mid_pipeline(cell, generator);
        test_redirect_mid_pipeline(cell, generator);
        test_client_response_cap(cell, generator);
        test_receive_follows_early_response(cell, generator);
        test_redirect_query_only(cell, generator);
        test_redirect_to_noise_refused(cell, generator);
        test_client_response_fields(cell, generator);
        test_client_log_lines(cell);
        test_bound_client_calls_from_handler(cell);
        test_streamed_endings(cell, generator);
        test_streamed_free_mid_body(cell, generator);
        test_streamed_barrier(cell, generator);
    }
    test_streamed_whole_bodies(cell);
    test_streamed_download(cell, generator);
    if (cell.security == ucall_security_none_k && cell.cpu_class_ceiling == ucall_cpu_class_unknown_k) {
        test_client_responses_outlive_free(cell);
        test_warm_client_allocates_nothing(cell);
    }
}

#endif // UCALL_OS_POSIX_
#pragma endregion Scripted Servers

} // namespace unum::ucall::test::network
