/**
 *  @file test/network/client.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The scripted server against the client pipeline, and client allocations and lifetime.
 */
#include <network.hpp>

#include "variants.hpp" // `io_engines_t`

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
                deepest = fu::max_of(deepest, whole_requests(std::string_view {peer.received}.substr(answered_bytes)));
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

/** A HEAD answered without <tt>content-length</tt> keeps the connection for the GET behind it. */
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

/** A caller's <tt>Connection: close</tt> on the second of four calls keeps the last two off its
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
 *  new one; a POST whose reused connection closes before any response byte is sent again. */
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

/** A redirect in the middle of a pipeline, sent with <tt>connection: close</tt>, is followed, and
 *  the POST behind it is sent again on the next connection; each call gets its own answer. */
static case_result_t test_redirect_mid_pipeline(random_generator_t& generator) {
    fixture_t fixture {{.pipelined_calls = 4}};
    scripted_server_t server {generator,
                              [](std::string_view request, std::size_t connection, std::size_t index) {
                                  if (request_target(request) != "/moved")
                                      return answer_target(request, connection, index);
                                  return scripted_answer_t {"HTTP/1.1 302 Found\r\nlocation: /landed\r\n" //
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

/** A client logs a dial that fails every address, naming the address it could not reach. */
static case_result_t test_client_log_lines() {
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
    require(0,
            probe >= 0 && ::bind(probe, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) == 0 &&
                ::getsockname(probe, reinterpret_cast<sockaddr*>(&bound), &length) == 0,
            "no free port");
    ::close(probe);
    std::string const address = fmt::format("127.0.0.1:{}", ntohs(bound.sin_port));
    std::string const url = fmt::format("http://{}/", address);
    ucall_client_t client {};
    ucall_outcome_t outcome {};
    ucall_client_options_t config {};
    config.max_concurrent_connections = 1;
    config.backend = backend_under_test;
    config.cpu_class = cpu_class_under_test;
    config.log = {collect, &collected, ucall_log_format_human_k, ucall_log_level_info_k};
    ucall_client_init_t init {&client, &outcome, &config, nullptr};
    ucall_client_init(&init);
    require(0, outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    ucall_client_call_t call {};
    call.client = client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(url);
    call.verb = ucall_verb_get_k;
    call.options.max_retries = 1;
    ucall_client_call(&call);
    std::size_t failures = expect(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    ucall_completed_call_t completed {};
    std::size_t count = 0;
    for (auto const deadline = steady_clock::now() + 10s; !count && steady_clock::now() < deadline;) {
        ucall_client_take_completed_t take {client, &outcome, &completed, 1, &count, 100'000};
        ucall_client_take_completed(&take);
    }
    failures += expect(count && completed.outcome.status == ucall_status_connection_failed_k, "the dial ended as {}",
                       ucall_status_name(completed.outcome.status));
    ucall_client_free(client);
    std::string const expected = fmt::format("warning connect_failed address={}", address);
    std::lock_guard lock {collected.mutex};
    failures += expect(std::any_of(collected.lines.begin(), collected.lines.end(),
                                   [&](std::string const& line) { return line.starts_with(expected); }),
                       "{} lines, the first: {}", collected.lines.size(),
                       collected.lines.empty() ? std::string {} : collected.lines.front());
    return failures;
}

/** A <tt>location</tt> holding only a query keeps the whole path it redirects from, per RFC 3986
 *  5.2.2, rather than resolving against its directory. */
static case_result_t test_redirect_query_only(random_generator_t& generator) {
    fixture_t fixture {{}};
    scripted_server_t server {
        generator, [](std::string_view request, std::size_t connection, std::size_t index) {
            if (request_target(request) != "/dir/page") return answer_target(request, connection, index);
            return scripted_answer_t {"HTTP/1.1 302 Found\r\nlocation: ?q=1\r\ncontent-length: 0\r\n\r\n"};
        }};
    require(0, fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
            ucall_status_name(fixture.status));
    std::array<scripted_call_t, 1> plan {{{server.url("/dir/page"), ucall_verb_get_k, "/dir/page?q=1"}}};
    std::size_t failures = exchange_all(fixture, plan);
    server.stop();
    return failures + fixture.stop();
}

/** Response field lines read back by index in arrival order, repeated names apart, names lowercased
 *  as the parser keeps them and values trimmed, and an index past the last one is not found. */
static case_result_t test_client_response_fields(random_generator_t& generator) {
    fixture_t fixture {{}};
    scripted_server_t server {
        generator, [](std::string_view, std::size_t, std::size_t) {
            return scripted_answer_t {"HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\ncontent-length: 2\r\n" //
                                      "X-Mixed:  spaced  \r\nset-cookie: b=2\r\n\r\nok"};
        }};
    require(0, fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
            ucall_status_name(fixture.status));
    scripted_call_t planned {server.url("/fields"), ucall_verb_get_k, "ok"};
    std::size_t failures = submit(fixture, planned);
    auto const completed = fixture.wait();
    require(failures + fixture.stop(), completed.response, "the call completed {}",
            ucall_status_name(completed.outcome.status));
    std::size_t count = 0;
    ucall_outcome_t outcome {};
    ucall_client_response_fields_count_t counting {completed.response, &outcome, &count};
    ucall_client_response_fields_count(&counting);
    failures += expect(outcome.status == ucall_status_success_k && count == 4, "{} fields", count);
    std::string read;
    for (std::size_t index = 0; index <= count; ++index) {
        ucall_bytes_view_t name {}, value {};
        ucall_client_response_field_t field {completed.response, &outcome, index, &name, &value};
        ucall_client_response_field(&field);
        if (outcome.status != ucall_status_success_k) {
            failures += expect(index == count && outcome.status == ucall_status_not_found_k, "field {}: {}", index,
                               ucall_status_name(outcome.status));
            break;
        }
        read += fmt::format("{}={};", uc::text_view(name), uc::text_view(value));
    }
    failures += expect(read == "set-cookie=a=1;content-length=2;x-mixed=spaced;set-cookie=b=2;", "read {}", read);
    ucall_client_response_free(completed.response);
    server.stop();
    return failures + fixture.stop();
}

/** A close-delimited response past the client's cap fails its call with @c ucall_status_overflow_k
 *  rather than buffering until the server closes. */
static case_result_t test_client_response_cap(random_generator_t& generator) {
    std::size_t const cap = 64 * 1024;
    fixture_t fixture {{.max_response_bytes = cap}};
    std::string const body(2 * cap, 'r');
    scripted_server_t server {generator, [&](std::string_view, std::size_t, std::size_t) {
                                  return scripted_answer_t {fmt::format("HTTP/1.1 200 OK\r\n\r\n{}", body),
                                                            after_answer_t::close_k};
                              }};
    require(0, fixture.status == ucall_status_success_k && !server.listener.address.empty(), "setup: {}",
            ucall_status_name(fixture.status));
    scripted_call_t planned {server.url("/large")};
    std::size_t failures = submit(fixture, planned);
    auto const completed = fixture.wait();
    failures += expect(completed.outcome.status == ucall_status_overflow_k, "a body twice the cap completed {}",
                       ucall_status_name(completed.outcome.status));
    if (completed.response) ucall_client_response_free(completed.response);
    server.stop();
    return failures + fixture.stop();
}

/** A response that overtakes its own long request waits in the transport behind a receive armed
 *  meanwhile, which must follow the buffer once that response moves into its call, as the next
 *  response lands through it. */
static case_result_t test_receive_follows_early_response(random_generator_t& generator) {
    fixture_t fixture {{}};
    raw_listener_t listener;
    require(0, fixture.status == ucall_status_success_k && !listener.address.empty(), "setup: {}",
            ucall_status_name(fixture.status));
    // Beyond what the sockets buffer while the peer reads nothing, so the send stays pending.
    std::string const body(std::size_t {16} << 20, 'b');
    std::string const url = fmt::format("http://{}/long", listener.address);
    std::thread peer_thread {[&, seed = generator()] {
        random_generator_t peer_generator {seed};
        auto const deadline = steady_clock::now() + 10s;
        raw_client_t peer;
        if (!listener.accept(peer, deadline)) return;
        auto read_head = [&](std::size_t from) {
            while (peer.received.find("\r\n\r\n", from) == std::string::npos)
                if (peer.read(peer.received.size() + 1, deadline) != read_end_t::filled_k) return std::string::npos;
            return peer.received.find("\r\n\r\n", from) + 4;
        };
        std::size_t const head = read_head(0);
        std::string const early = answer_ok("early").bytes, late = answer_ok("late").bytes;
        if (head == std::string::npos || !peer.write(uc::byte_span(early), early.size(), peer_generator, deadline))
            return;
        // The client reads the response and arms its next receive before the request ends.
        std::this_thread::sleep_for(100ms);
        if (peer.read(head + body.size(), deadline) != read_end_t::filled_k) return;
        if (read_head(head + body.size()) == std::string::npos) return;
        [[maybe_unused]] bool const written = peer.write(uc::byte_span(late), late.size(), peer_generator, deadline);
    }};
    std::size_t failures = 0;
    auto call = [&](ucall_verb_t verb, std::string_view sent, std::string_view expected) {
        ucall_outcome_t outcome {};
        ucall_client_call_t arguments {};
        arguments.client = fixture.client;
        arguments.outcome = &outcome;
        arguments.url = uc::bytes_view(url);
        arguments.verb = verb;
        arguments.body = uc::bytes_view(sent);
        ucall_client_call(&arguments);
        failures += expect(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
        auto const completed = fixture.wait();
        failures += expect(completed.outcome.status == ucall_status_success_k && completed.response, "{}",
                           ucall_status_name(completed.outcome.status));
        if (!completed.response) return;
        ucall_bytes_view_t answered {};
        ucall_client_response_body_t get {completed.response, &outcome, &answered};
        ucall_client_response_body(&get);
        std::string_view const text {reinterpret_cast<char const*>(answered.data), answered.length};
        failures += expect(text == expected, "answered {:?} for {:?}", text, expected);
        ucall_client_response_free(completed.response);
    };
    call(ucall_verb_post_k, body, "early");
    call(ucall_verb_get_k, {}, "late");
    peer_thread.join();
    return failures + fixture.stop();
}

#pragma region Scripted Resolver

/** One resource record of a scripted answer, its data already in wire form, its owner not yet. */
struct dns_record_t {
    std::string owner;
    std::uint16_t type {};
    std::uint32_t ttl {};
    std::string data;
};

/** @p dotted as length-prefixed labels ending in the root's zero byte. */
static std::string dns_wire_name(std::string_view dotted) {
    std::string wire;
    while (!dotted.empty()) {
        auto const dot = fu::min_of(dotted.find('.'), dotted.size());
        wire += static_cast<char>(dot);
        wire += dotted.substr(0, dot);
        dotted.remove_prefix(fu::min_of(dot + 1, dotted.size()));
    }
    return wire + '\0';
}

/** The SOA a negative answer carries, its TTL and MINIMUM both @p ttl. */
static dns_record_t dns_soa(std::string_view owner, std::uint32_t ttl) {
    std::string data = dns_wire_name("ns.test") + dns_wire_name("admin.test");
    for (std::uint32_t const value : {1u, 60u, 60u, 60u, ttl})
        for (int shift = 24; shift >= 0; shift -= 8) data += static_cast<char>(value >> shift);
    return {std::string {owner}, 6, ttl, data};
}

/** Whether a scripted answer sets the truncation bit, which sends a UDP client over to TCP. */
enum class dns_truncation_t : std::uint8_t { whole_k, truncated_k };

/** The answer to @p query: its ID and question echoed, then @p answers and @p authorities. */
static std::string dns_reply(std::string_view query, unsigned code, dns_truncation_t truncation,
                             std::vector<dns_record_t> const& answers,
                             std::vector<dns_record_t> const& authorities = {}) {
    std::size_t name_end = 12;
    while (name_end < query.size() && query[name_end]) name_end += 1 + static_cast<unsigned char>(query[name_end]);
    std::string reply {query.substr(0, 2)};
    reply += static_cast<char>(0x80 | (truncation == dns_truncation_t::truncated_k ? 0x02 : 0) | (query[2] & 0x01));
    reply += static_cast<char>(0x80 | code);
    for (std::size_t const count : {std::size_t {1}, answers.size(), authorities.size(), std::size_t {0}})
        reply += std::string {static_cast<char>(count >> 8), static_cast<char>(count)};
    reply += query.substr(12, name_end + 5 - 12);
    for (auto const* section : {&answers, &authorities})
        for (auto const& record : *section) {
            reply += dns_wire_name(record.owner);
            reply += std::string {static_cast<char>(record.type >> 8), static_cast<char>(record.type), 0, 1};
            for (int shift = 24; shift >= 0; shift -= 8) reply += static_cast<char>(record.ttl >> shift);
            reply += std::string {static_cast<char>(record.data.size() >> 8), static_cast<char>(record.data.size())};
            reply += record.data;
        }
    return reply;
}

inline constexpr std::uint16_t dns_a_k = 1, dns_cname_k = 5, dns_aaaa_k = 28;
static std::string const loopback_v4_k {"\x7f\x00\x00\x01", 4};

/** Which transport a scripted resolver heard a question over. */
enum class dns_transport_t : std::uint8_t { datagram_k, stream_k };

/** One question a scripted resolver saw: its name, type and transport. */
struct dns_question_t {
    std::string name;
    std::uint16_t type {};
    dns_transport_t transport {};
};

/**
 *  @brief A loopback DNS server answering UDP and TCP on one port as its script says, for cases
 *      that need answers no real resolver gives on cue.
 *
 *  An empty script answer stays silent. Every question it saw is kept in order.
 */
struct scripted_resolver_t {
    using script_t = std::function<std::string(dns_question_t const&, std::string_view query)>;
    script_t script;
    int datagram = -1, listener = -1;
    sockaddr_in bound {};
    std::mutex mutex;
    std::vector<dns_question_t> asked;
    std::atomic<bool> stopping {false};
    std::thread thread;

    explicit scripted_resolver_t(script_t answer) : script(std::move(answer)) {
        // The kernel picks the UDP port, which TCP may hold elsewhere, so it may take a few picks.
        for (int pick = 0; pick != 16 && !ready(); ++pick) {
            if (datagram >= 0) ::close(datagram);
            if (listener >= 0) ::close(listener);
            datagram = ::socket(AF_INET, SOCK_DGRAM, 0);
            listener = ::socket(AF_INET, SOCK_STREAM, 0);
            int enabled = 1;
            bound = {};
            bound.sin_family = AF_INET;
            bound.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            socklen_t length = sizeof(bound);
            bool const bound_both = datagram >= 0 && listener >= 0 &&
                                    ::setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) == 0 &&
                                    ::bind(datagram, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) == 0 &&
                                    ::getsockname(datagram, reinterpret_cast<sockaddr*>(&bound), &length) == 0 &&
                                    ::bind(listener, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) == 0 &&
                                    ::listen(listener, 4) == 0;
            if (!bound_both) bound.sin_port = 0;
        }
        if (ready()) thread = std::thread {[this] { serve(); }};
    }
    ~scripted_resolver_t() {
        stopping.store(true, std::memory_order_release);
        if (thread.joinable()) thread.join();
        if (datagram >= 0) ::close(datagram);
        if (listener >= 0) ::close(listener);
    }
    [[nodiscard]] bool ready() const noexcept { return bound.sin_port != 0; }

    /** Options pointing a client at this server alone, @p search holding NUL-separated names. */
    uc::dns::resolver_options_t options(std::string_view search = {}) const {
        uc::dns::resolver_options_t settings {};
        std::memcpy(&settings.nameservers[0], &bound, sizeof(bound));
        settings.nameservers_count = 1;
        search.copy(settings.search, search.size());
        settings.search_length = static_cast<std::uint32_t>(search.size());
        settings.timeout_seconds = 1;
        return settings;
    }
    std::vector<dns_question_t> questions() {
        std::lock_guard lock {mutex};
        return asked;
    }

    std::string answer(std::string_view query, dns_transport_t transport) {
        dns_question_t question {{}, 0, transport};
        std::size_t position = 12;
        while (position < query.size() && query[position]) {
            std::size_t const length = static_cast<unsigned char>(query[position]);
            if (!question.name.empty()) question.name += '.';
            question.name += query.substr(position + 1, length);
            position += 1 + length;
        }
        if (position + 3 >= query.size()) return {};
        question.type = static_cast<std::uint16_t>(static_cast<unsigned char>(query[position + 1]) << 8 |
                                                   static_cast<unsigned char>(query[position + 2]));
        {
            std::lock_guard lock {mutex};
            asked.push_back(question);
        }
        return script(question, query);
    }
    void serve() {
        while (!stopping.load(std::memory_order_acquire)) {
            pollfd watched[2] {{datagram, POLLIN, 0}, {listener, POLLIN, 0}};
            if (::poll(watched, 2, 20) <= 0) continue;
            if (watched[0].revents & POLLIN) {
                char query[512];
                sockaddr_storage from {};
                socklen_t from_length = sizeof(from);
                ssize_t const received = ::recvfrom(datagram, query, sizeof(query), 0,
                                                    reinterpret_cast<sockaddr*>(&from), &from_length);
                std::string const reply = received > 0 ? answer({query, static_cast<std::size_t>(received)},
                                                                dns_transport_t::datagram_k)
                                                       : "";
                if (!reply.empty())
                    ::sendto(datagram, reply.data(), reply.size(), 0, reinterpret_cast<sockaddr*>(&from), from_length);
            }
            if (watched[1].revents & POLLIN) {
                raw_client_t peer;
                peer.descriptor = ::accept(listener, nullptr, nullptr);
                if (peer.descriptor < 0 || peer.read(2, steady_clock::now() + 1s) != read_end_t::filled_k) continue;
                std::size_t const length = static_cast<unsigned char>(peer.received[0]) << 8 |
                                           static_cast<unsigned char>(peer.received[1]);
                if (peer.read(2 + length, steady_clock::now() + 1s) != read_end_t::filled_k) continue;
                std::string const reply = answer(std::string_view {peer.received}.substr(2, length),
                                                 dns_transport_t::stream_k);
                std::string const framed =
                    std::string {static_cast<char>(reply.size() >> 8), static_cast<char>(reply.size())} + reply;
                if (!reply.empty()) ::send(peer.descriptor, framed.data(), framed.size(), MSG_NOSIGNAL);
            }
        }
    }
};

/** A client of @p connections on the backend under test that asks @p options' nameservers. */
static ucall_client_t resolving_client(uc::dns::resolver_options_t const& options, std::size_t connections = 1) {
    using network_t = uc::network::serial_network<uc::io_engines_t>;
    ucall_client_t client {};
    ucall_outcome_t outcome {};
    ucall_client_options_t config {};
    config.max_concurrent_connections = connections;
    config.backend = backend_under_test;
    ucall_client_init_t init {&client, &outcome, &config, nullptr};
    network_t::client_t::client_init(&init);
    if (outcome.status != ucall_status_success_k) return nullptr;
    // Settings are read once at init, so a case points the client at its own server after it.
    static_cast<network_t::client_t*>(client)->resolver = options;
    return client;
}

/** Calls @p url once on @p client over a connection of its own, which it closes, and waits up to
 *  five seconds for it, freeing any response and answering its outcome. */
static ucall_status_t resolved_call(ucall_client_t client, std::string const& url) {
    ucall_outcome_t outcome {};
    ucall_client_call_t call {};
    ucall_bytes_view_t const closing = uc::bytes_view("Connection: close");
    call.headers = &closing;
    call.headers_count = 1;
    call.client = client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(url);
    call.verb = ucall_verb_get_k;
    ucall_client_call(&call);
    if (outcome.status != ucall_status_success_k) return outcome.status;
    ucall_completed_call_t completed {};
    std::size_t count = 0;
    for (auto const deadline = steady_clock::now() + 5s; !count && steady_clock::now() < deadline;) {
        ucall_client_take_completed_t take {client, &outcome, &completed, 1, &count, 100'000};
        ucall_client_take_completed(&take);
    }
    if (completed.response) ucall_client_response_free(completed.response);
    return count ? completed.outcome.status : ucall_status_timeout_k;
}

/** An echo server and the scripted resolver naming it, which a case calls by name. */
struct resolving_fixture_t {
    fixture_t server {{.connections = 4}};
    scripted_resolver_t resolver;
    std::string port;
    explicit resolving_fixture_t(scripted_resolver_t::script_t script) : resolver(std::move(script)) {
        if (server.status == ucall_status_success_k) server.serve_in_background();
        port = server.address.substr(server.address.rfind(':') + 1);
    }
    [[nodiscard]] bool ready() const noexcept { return server.status == ucall_status_success_k && resolver.ready(); }
    std::string url(std::string_view host) const { return fmt::format("http://{}:{}/echo/1", host, port); }
};

/** A CNAME chain leads A to the address its last name owns, and AAAA to none. */
static case_result_t test_client_follows_cname_chain() {
    resolving_fixture_t fixture {[](dns_question_t const& question, std::string_view query) {
        dns_record_t const alias {"alias.test", dns_cname_k, 60, dns_wire_name("middle.test")};
        dns_record_t const middle {"middle.test", dns_cname_k, 60, dns_wire_name("real.test")};
        if (question.type == dns_a_k)
            return dns_reply(query, 0, dns_truncation_t::whole_k,
                             {alias, middle, {"real.test", dns_a_k, 60, loopback_v4_k}});
        return dns_reply(query, 0, dns_truncation_t::whole_k, {alias, middle}, {dns_soa("test", 60)});
    }};
    require(0, fixture.ready(), "setup");
    ucall_client_t client = resolving_client(fixture.resolver.options());
    require(fixture.server.stop(), client, "the resolving client failed to start");
    std::size_t failures = 0;
    ucall_status_t const status = resolved_call(client, fixture.url("alias.test"));
    failures += expect(status == ucall_status_success_k, "the alias answered {}", ucall_status_name(status));
    ucall_client_free(client);
    return failures + fixture.server.stop();
}

/** An A cut short over UDP is asked again over TCP, whose whole answer the call dials. */
static case_result_t test_client_retries_truncated_answer_over_tcp() {
    resolving_fixture_t fixture {[](dns_question_t const& question, std::string_view query) {
        if (question.type != dns_a_k) return dns_reply(query, 0, dns_truncation_t::whole_k, {}, {dns_soa("test", 60)});
        if (question.transport == dns_transport_t::datagram_k)
            return dns_reply(query, 0, dns_truncation_t::truncated_k, {});
        return dns_reply(query, 0, dns_truncation_t::whole_k, {{"wide.test", dns_a_k, 60, loopback_v4_k}});
    }};
    require(0, fixture.ready(), "setup");
    ucall_client_t client = resolving_client(fixture.resolver.options());
    require(fixture.server.stop(), client, "the resolving client failed to start");
    std::size_t failures = 0;
    ucall_status_t const status = resolved_call(client, fixture.url("wide.test"));
    failures += expect(status == ucall_status_success_k, "the truncated name answered {}", ucall_status_name(status));
    auto const questions = fixture.resolver.questions();
    failures += expect(
        std::any_of(questions.begin(), questions.end(),
                    [](dns_question_t const& question) { return question.transport == dns_transport_t::stream_k; }),
        "no question came over TCP");
    ucall_client_free(client);
    return failures + fixture.server.stop();
}

/** A name that does not exist fails its calls with @c ucall_status_not_found_k, and the refusal is
 *  cached for its SOA's minimum, so the second call asks nothing. */
static case_result_t test_client_caches_absent_name() {
    resolving_fixture_t fixture {[](dns_question_t const&, std::string_view query) {
        return dns_reply(query, 3, dns_truncation_t::whole_k, {}, {dns_soa("test", 60)});
    }};
    require(0, fixture.ready(), "setup");
    ucall_client_t client = resolving_client(fixture.resolver.options());
    require(fixture.server.stop(), client, "the resolving client failed to start");
    std::size_t failures = 0;
    ucall_status_t status = resolved_call(client, fixture.url("missing.test"));
    failures += expect(status == ucall_status_not_found_k, "the absent name answered {}", ucall_status_name(status));
    std::size_t const asked = fixture.resolver.questions().size();
    status = resolved_call(client, fixture.url("missing.test"));
    failures += expect(status == ucall_status_not_found_k, "the cached refusal answered {}", ucall_status_name(status));
    failures += expect(fixture.resolver.questions().size() == asked, "{} questions after a cached refusal, {} before",
                       fixture.resolver.questions().size(), asked);
    ucall_client_free(client);
    return failures + fixture.server.stop();
}

/** An answer is reused until its TTL passes, then asked again. */
static case_result_t test_client_asks_again_after_ttl() {
    resolving_fixture_t fixture {[](dns_question_t const& question, std::string_view query) {
        if (question.type != dns_a_k) return dns_reply(query, 0, dns_truncation_t::whole_k, {}, {dns_soa("test", 1)});
        return dns_reply(query, 0, dns_truncation_t::whole_k, {{"brief.test", dns_a_k, 1, loopback_v4_k}});
    }};
    require(0, fixture.ready(), "setup");
    ucall_client_t client = resolving_client(fixture.resolver.options());
    require(fixture.server.stop(), client, "the resolving client failed to start");
    std::size_t failures = 0;
    auto count_a = [&] {
        auto const questions = fixture.resolver.questions();
        return std::count_if(questions.begin(), questions.end(),
                             [](dns_question_t const& question) { return question.type == dns_a_k; });
    };
    failures += expect(resolved_call(client, fixture.url("brief.test")) == ucall_status_success_k);
    failures += expect(resolved_call(client, fixture.url("brief.test")) == ucall_status_success_k);
    failures += expect(count_a() == 1, "{} A questions within the TTL", count_a());
    std::this_thread::sleep_for(1200ms);
    failures += expect(resolved_call(client, fixture.url("brief.test")) == ucall_status_success_k);
    failures += expect(count_a() == 2, "{} A questions after the TTL", count_a());
    ucall_client_free(client);
    return failures + fixture.server.stop();
}

/** A name with fewer dots than @c ndots is asked with each search suffix first, in order. */
static case_result_t test_client_walks_search_names() {
    resolving_fixture_t fixture {[](dns_question_t const& question, std::string_view query) {
        if (question.name != "svc.two.test")
            return dns_reply(query, 3, dns_truncation_t::whole_k, {}, {dns_soa("test", 60)});
        if (question.type != dns_a_k) return dns_reply(query, 0, dns_truncation_t::whole_k, {}, {dns_soa("test", 60)});
        return dns_reply(query, 0, dns_truncation_t::whole_k, {{"svc.two.test", dns_a_k, 60, loopback_v4_k}});
    }};
    require(0, fixture.ready(), "setup");
    ucall_client_t client = resolving_client(fixture.resolver.options(std::string_view {"one.test\0two.test\0", 18}));
    require(fixture.server.stop(), client, "the resolving client failed to start");
    std::size_t failures = 0;
    ucall_status_t const status = resolved_call(client, fixture.url("svc"));
    failures += expect(status == ucall_status_success_k, "the short name answered {}", ucall_status_name(status));
    std::vector<std::string> names;
    for (auto const& question : fixture.resolver.questions())
        if (question.type == dns_a_k) names.push_back(question.name);
    std::vector<std::string> const expected {"svc.one.test", "svc.two.test"};
    failures += expect(names == expected, "asked {} names first {}", names.size(),
                       names.empty() ? std::string {} : names.front());
    ucall_client_free(client);
    return failures + fixture.server.stop();
}

/** Whether a SYN to @p address, whose listener's queue is full, goes unanswered for 200 ms: Linux
 *  drops it, where Darwin completes the handshake anyway and FreeBSD's syncache resets it. */
static bool syn_swallowed(sockaddr_in6 const& address) {
    int const probe = ::socket(AF_INET6, SOCK_STREAM, 0);
    if (probe < 0) return false;
    fcntl(probe, F_SETFL, fcntl(probe, F_GETFL) | O_NONBLOCK);
    bool const started = ::connect(probe, reinterpret_cast<sockaddr const*>(&address), sizeof(address)) != 0 &&
                         errno == EINPROGRESS;
    pollfd watched {probe, POLLOUT, 0};
    bool const swallowed = started && ::poll(&watched, 1, 200) == 0;
    ::close(probe);
    return swallowed;
}

/** When the AAAA address takes SYNs and never answers them, the A address races it after RFC
 *  8305's attempt delay on a second connection, long before the connect timeout. */
static case_result_t test_client_races_ipv4_after_silent_ipv6() {
    resolving_fixture_t fixture {[](dns_question_t const& question, std::string_view query) {
        if (question.type == dns_aaaa_k)
            return dns_reply(query, 0, dns_truncation_t::whole_k,
                             {{"dual.test", dns_aaaa_k, 60, std::string(15, '\0') + std::string(1, '\1')}});
        return dns_reply(query, 0, dns_truncation_t::whole_k, {{"dual.test", dns_a_k, 60, loopback_v4_k}});
    }};
    require(0, fixture.ready(), "setup");
    // A full accept queue on [::1] at the server's port drops every further SYN without a word.
    int const silent = ::socket(AF_INET6, SOCK_STREAM, 0);
    int enabled = 1;
    sockaddr_in6 bound {};
    bound.sin6_family = AF_INET6;
    bound.sin6_addr = in6addr_loopback;
    bound.sin6_port = htons(static_cast<std::uint16_t>(std::stoi(fixture.port)));
    if (silent < 0 || ::setsockopt(silent, IPPROTO_IPV6, IPV6_V6ONLY, &enabled, sizeof(enabled)) != 0 ||
        ::bind(silent, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) != 0 || ::listen(silent, 0) != 0) {
        if (silent >= 0) ::close(silent);
        return case_result_t::skipped("::1 cannot bind beside the server", fixture.server.stop());
    }
    int const filler = ::socket(AF_INET6, SOCK_STREAM, 0);
    fcntl(filler, F_SETFL, fcntl(filler, F_GETFL) | O_NONBLOCK);
    [[maybe_unused]] int const filled = ::connect(filler, reinterpret_cast<sockaddr*>(&bound), sizeof(bound));
    std::this_thread::sleep_for(50ms);
    if (!syn_swallowed(bound)) {
        ::close(filler);
        ::close(silent);
        return case_result_t::skipped("the kernel answers SYNs a full queue would drop", fixture.server.stop());
    }
    ucall_client_t client = resolving_client(fixture.resolver.options(), 2);
    std::size_t failures = 0;
    if (client) {
        auto const started = steady_clock::now();
        ucall_status_t const status = resolved_call(client, fixture.url("dual.test"));
        auto const elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(steady_clock::now() - started);
        failures += expect(status == ucall_status_success_k && elapsed < 2s,
                           "the dual-stack name answered {} after {} ms", ucall_status_name(status), elapsed.count());
        ucall_client_free(client);
    }
    else failures += expect(false, "the resolving client failed to start");
    ::close(filler);
    ::close(silent);
    return failures + fixture.server.stop();
}

#pragma endregion Scripted Resolver

#if UCALL_WITH_POSIX

/** A plain POSIX client drawing every allocation from @p counts, or null when it fails to start. */
static ucall_client_t counted_client(allocation_counts_t& counts) {
    ucall_client_t client {};
    ucall_outcome_t outcome {};
    ucall_client_options_t config {};
    config.max_concurrent_connections = 1;
    config.backend = ucall_io_backend_posix_k;
    ucall_client_init_t init {&client, &outcome, &config, nullptr};
    counted_network_t::client_t::client_init(&init, counting_allocator<uc::byte_t> {counts});
    return outcome.status == ucall_status_success_k ? client : nullptr;
}

/** Calls @p url on @p client and waits up to five seconds for the call to complete. */
static ucall_completed_call_t counted_call(ucall_client_t client, std::string const& url) {
    ucall_outcome_t outcome {};
    ucall_client_call_t call {};
    call.client = client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(url);
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
#endif

/** A front server's handler calls out to an upstream through a client bound to its loop, and the
 *  loop's own thread replies once the bound client finished, with no other thread involved. */
struct bound_front_t {
    ucall_server_t server {};
    ucall_client_t bound {};
    std::string upstream_url {};
    ucall_received_http_request_t held {};
    std::size_t failures {};
    static void forward(ucall_received_http_request_t request, void* context) {
        auto& front = *static_cast<bound_front_t*>(context);
        front.failures += expect(!front.held, "a second request arrived while one is held");
        front.held = request;
        ucall_outcome_t outcome {};
        ucall_client_call_t call {};
        call.client = front.bound;
        call.outcome = &outcome;
        call.url = uc::bytes_view(front.upstream_url);
        call.verb = ucall_verb_post_k;
        call.body = uc::bytes_view("upstream says hi");
        ucall_client_call(&call);
        front.failures += expect(outcome.status == ucall_status_success_k, "the bound call was refused: {}",
                                 ucall_status_name(outcome.status));
    }
};

static case_result_t test_bound_client_calls_from_handler() {
    fixture_t upstream {{}};
    require(0, upstream.status == ucall_status_success_k, "setup: {}", ucall_status_name(upstream.status));
    bound_front_t front;
    front.upstream_url = fmt::format("{}/echo/1", upstream.url);
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = uc::bytes_view("127.0.0.1:0");
    network_interface.max_concurrent_connections = 1;
    ucall_server_options_t config {}, resolved {};
    config.interfaces = &network_interface;
    config.interfaces_count = 1;
    config.backend = backend_under_test;
    config.cpu_class = cpu_class_under_test;
    ucall_server_init_t init {&front.server, &outcome, &config, &resolved};
    ucall_server_init(&init);
    require(0, outcome.status == ucall_status_success_k, "front: {}", ucall_status_name(outcome.status));
    ucall_server_add_http_endpoint_t add {front.server,           &outcome, uc::bytes_view("/front"), ucall_verb_any_k,
                                          bound_front_t::forward, &front};
    ucall_server_add_http_endpoint(&add);
    std::size_t failures = expect(outcome.status == ucall_status_success_k);
    ucall_client_options_t bound_config {};
    bound_config.max_concurrent_connections = 1;
    bound_config.server = front.server;
    ucall_client_init_t bind {&front.bound, &outcome, &bound_config, nullptr};
    ucall_client_init(&bind);
    failures += expect(outcome.status == ucall_status_success_k, "bind: {}", ucall_status_name(outcome.status));
    ucall_server_free(front.server);
    failures += expect(front.bound, "the server freed under its bound client");
    if (front.bound) {
        std::string const url = fmt::format("http://{}/front", uc::text_view(resolved.interfaces[0].address));
        ucall_client_call_t call {};
        call.client = upstream.client;
        call.outcome = &outcome;
        call.url = uc::bytes_view(url);
        call.verb = ucall_verb_get_k;
        ucall_client_call(&call);
        failures += expect(outcome.status == ucall_status_success_k);
        steady_clock::time_point const deadline = steady_clock::now() + 5s;
        ucall_completed_call_t answered {};
        while (steady_clock::now() < deadline && !upstream.poll(answered)) {
            ucall_server_take_call_t serving {front.server, &outcome, 0, 0};
            ucall_server_take_call(&serving);
            failures += expect(outcome.status == ucall_status_success_k);
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
            failures += expect(front.held && upstream_answer.outcome.status == ucall_status_success_k,
                               "the upstream call ended with {}", ucall_status_name(upstream_answer.outcome.status));
            ucall_server_reply_content_t reply {front.server, &outcome, front.held, ucall_http_status_ok_k,
                                                nullptr,      0,        body};
            ucall_server_reply_content(&reply);
            failures += expect(outcome.status == ucall_status_success_k);
            front.held = {};
            ucall_client_response_free(upstream_answer.response);
        }
        failures += expect(answered.outcome.status == ucall_status_success_k && answered.response,
                           "the front call ended with {}", ucall_status_name(answered.outcome.status));
        if (answered.response) {
            ucall_bytes_view_t body {};
            ucall_client_response_body_t get {answered.response, &outcome, &body};
            ucall_client_response_body(&get);
            failures += expect(uc::text_view(body) == "upstream says hi", "the front answered {}", uc::text_view(body));
            ucall_client_response_free(answered.response);
        }
        ucall_client_free(front.bound);
    }
    ucall_server_free(front.server);
    return failures + front.failures + upstream.stop();
}

/** A response freed after its client returns, with the client's pool, every byte the client
 *  allocated. */
static case_result_t test_client_responses_outlive_free_unit() {
#if UCALL_WITH_POSIX
    fixture_t fixture {{.backend = ucall_io_backend_posix_k}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    allocation_counts_t counts;
    ucall_client_t client = counted_client(counts);
    require(failures + fixture.stop(), client, "the counted client failed to start");
    auto const url = fmt::format("{}/echo/1", fixture.url);
    ucall_completed_call_t const freed = counted_call(client, url);
    ucall_completed_call_t const late = counted_call(client, url);
    failures += expect(freed.response && late.response, "{} then {}", ucall_status_name(freed.outcome.status),
                       ucall_status_name(late.outcome.status));
    if (freed.response) failures += check_response(freed.response, {});
    ucall_client_free(client);
    failures += expect(counts.live() != 0, "the late response lost its pool with the client");
    if (late.response) failures += check_response(late.response, {});
    failures += expect(!counts.live() && !counts.bytes, "{} allocations of {} bytes outlived the last response",
                       counts.live(), counts.bytes);
    return failures + fixture.stop();
#else
    return case_result_t::skipped("the POSIX backend is not compiled");
#endif
}

/** Once 64 responses warmed the client, 1,000 more allocate nothing: each takes a freed response
 *  back and swaps its capacity with the connection's input. */
static case_result_t test_warm_client_allocates_nothing() {
#if UCALL_WITH_POSIX
    fixture_t fixture {{.backend = ucall_io_backend_posix_k}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    allocation_counts_t counts;
    ucall_client_t client = counted_client(counts);
    require(failures + fixture.stop(), client, "the counted client failed to start");
    auto const url = fmt::format("{}/echo/1", fixture.url);
    std::size_t warm_allocations = 0;
    for (std::size_t call = 0; call != 64 + 1000 && !failures; ++call) {
        if (call == 64) warm_allocations = counts.allocations;
        ucall_completed_call_t const completed = counted_call(client, url);
        failures += expect(completed.response, "call {}: {}", call, ucall_status_name(completed.outcome.status));
        if (completed.response) failures += check_response(completed.response, {});
    }
    failures += expect(counts.allocations == warm_allocations, "1,000 warm calls allocated {} times",
                       counts.allocations - warm_allocations);
    ucall_client_free(client);
    failures += expect(!counts.live(), "{} allocations outlived the client", counts.live());
    return failures + fixture.stop();
#else
    return case_result_t::skipped("the POSIX backend is not compiled");
#endif
}

void run_client(suite_totals_t& totals) {
    run_test(totals, "test_lengthless_head_keeps_connection", test_lengthless_head_keeps_connection);
    run_test(totals, "test_caller_close_mid_pipeline", test_caller_close_mid_pipeline);
    run_test(totals, "test_post_waits_behind_post", test_post_waits_behind_post);
    run_test(totals, "test_short_timeout_behind_long", test_short_timeout_behind_long);
    run_test(totals, "test_stale_idle_connection", test_stale_idle_connection);
    run_test(totals, "test_server_close_mid_pipeline", test_server_close_mid_pipeline);
    run_test(totals, "test_redirect_mid_pipeline", test_redirect_mid_pipeline);
    run_test(totals, "test_client_response_cap", test_client_response_cap);
    run_test(totals, "test_receive_follows_early_response", test_receive_follows_early_response);
    run_test(totals, "test_redirect_query_only", test_redirect_query_only);
    run_test(totals, "test_client_response_fields", test_client_response_fields);
    run_test(totals, "test_client_log_lines", test_client_log_lines);
    run_test(totals, "test_client_follows_cname_chain", test_client_follows_cname_chain);
    run_test(totals, "test_client_retries_truncated_answer_over_tcp", test_client_retries_truncated_answer_over_tcp);
    run_test(totals, "test_client_caches_absent_name", test_client_caches_absent_name);
    run_test(totals, "test_client_asks_again_after_ttl", test_client_asks_again_after_ttl);
    run_test(totals, "test_client_walks_search_names", test_client_walks_search_names);
    run_test(totals, "test_client_races_ipv4_after_silent_ipv6", test_client_races_ipv4_after_silent_ipv6);
    run_test(totals, "test_client_responses_outlive_free_unit", test_client_responses_outlive_free_unit);
    run_test(totals, "test_warm_client_allocates_nothing", test_warm_client_allocates_nothing);
    run_test(totals, "test_bound_client_calls_from_handler", test_bound_client_calls_from_handler);
}

#endif // UCALL_OS_POSIX_
#pragma endregion Scripted Servers

} // namespace unum::ucall::test::network
