/**
 *  @file test/network/exchanges.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Library-client exchanges, Noise modes, pipelining, vectored, streamed and head replies,
 *      raw delivery, smuggling and admission.
 */
#include <network.hpp>

namespace unum::ucall::test::network {

#pragma region Library Clients

static case_result_t exchanges(ucall_security_t security) {
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
    call.options.noise_peer_key = &fixture.server_public;
    auto exchange = [&](std::string_view expected) {
        ucall_client_call(&call);
        failures += expect(outcome.status == ucall_status_success_k);
        auto completed = fixture.wait();
        failures += expect(completed.outcome.status == ucall_status_success_k && completed.response, "{}",
                           ucall_status_name(completed.outcome.status));
        if (completed.response) failures += check_response(completed.response, expected);
    };
    // Rings and Registered I/O copy what lands in their pool; other engines land straight in the
    // transport's buffers.
    ucall_io_backend_t const backend = fixture.resolved.backend;
    bool const pooled = backend == ucall_io_backend_linux_uring612_k || backend == ucall_io_backend_linux_uring618_k ||
                        backend == ucall_io_backend_windows_rio_k;
    auto copies_beyond_receipt = [&] {
        ucall_event_loop_statistics_t const counters = loop_statistics(fixture);
        return pooled ? counters.bytes_copied - counters.bytes_received : counters.bytes_copied;
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
    // A 618 stream that outruns its receive copies those bytes into the backlog as well.
    bool const streams = backend == ucall_io_backend_linux_uring618_k;
    std::size_t const copied_limit = streams ? 3 * payload.size() : payload.size();
    failures += expect(copied >= payload.size() && copied <= copied_limit,
                       "{} bytes copied beyond those received for a {}-byte echo", copied, payload.size());
    // Only a socket accepted in Registered I/O sends unregistered bytes through a slice.
    failures += expect(backend != ucall_io_backend_windows_rio_k || loop_statistics(fixture).copying_sends > 0,
                       "the server's connections sent outside Registered I/O");
    if (security != ucall_security_none_k) return failures + fixture.stop();
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

/** A warm 64 KB echo costs a handful of completions, however many pages its records span, as a
 *  receive takes all that the socket holds; only the first ones grow the room it lands in. */
static case_result_t echo_completions(ucall_security_t security) {
    fixture_t fixture {{.security = security}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    std::string const payload(64 * 1024, 'x');
    auto const url = fmt::format("{}/echo/42", fixture.url);
    ucall_outcome_t outcome {};
    ucall_client_call_t call {};
    call.client = fixture.client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(url);
    call.verb = ucall_verb_post_k;
    call.body = uc::bytes_view(payload);
    call.options.security = security;
    call.options.noise_peer_key = &fixture.server_public;
    auto echo = [&] {
        ucall_client_call(&call);
        failures += expect(outcome.status == ucall_status_success_k);
        auto const completed = fixture.wait();
        failures += expect(completed.outcome.status == ucall_status_success_k && completed.response, "{}",
                           ucall_status_name(completed.outcome.status));
        if (completed.response) ucall_client_response_free(completed.response);
    };
    auto completions = [&] {
        ucall_event_loop_statistics_t counters {};
        ucall_outcome_t queried {};
        ucall_server_event_loop_statistics_t query {fixture.server, &queried, 0, &counters};
        ucall_server_event_loop_statistics(&query);
        return counters.completions;
    };
    for (std::size_t warming = 0; warming != 8; ++warming) echo();
    std::uint64_t const warm = completions();
    std::size_t const echoes = 16;
    for (std::size_t measured = 0; measured != echoes; ++measured) echo();
    std::uint64_t const spent = completions() - warm;
    failures += expect(spent <= 8 * echoes, "{} completions for {} echoes", spent, echoes);
    return failures + fixture.stop();
}
static case_result_t test_echo_completions_plain() { return echo_completions(ucall_security_none_k); }
static case_result_t test_echo_completions_noise_xx() { return echo_completions(ucall_security_noise_xx_k); }

static case_result_t test_exchanges_plain() { return exchanges(ucall_security_none_k); }
static case_result_t test_exchanges_noise_xx() { return exchanges(ucall_security_noise_xx_k); }
static case_result_t test_exchanges_noise_ik() { return exchanges(ucall_security_noise_ik_k); }
static case_result_t test_exchanges_noise_kk() { return exchanges(ucall_security_noise_kk_k); }

/** A KK interface refuses an initiator whose static key is not the one it names. */
static case_result_t test_server_kk_wrong_initiator() {
    fixture_t fixture {{.security = ucall_security_noise_kk_k}};
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
    call.options.security = ucall_security_noise_kk_k;
    call.options.noise_peer_key = &fixture.server_public;
    call.options.noise_private_key = &stranger;
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

/** Eight idempotent calls at depth four share one connection: the server holds four at once, which
 *  lockstep calls never reach, and replies given in reverse still complete in call order. */
static case_result_t pipelined_calls(ucall_security_t security) {
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
        call.options.noise_peer_key = &fixture.server_public;
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

static case_result_t test_pipelined_calls_plain() { return pipelined_calls(ucall_security_none_k); }

/** Calls made at once open only the connections their depth needs: 64 at a depth of 16 open four
 *  of eight, and 16 at a depth of one open all eight. */
static case_result_t test_client_dials_for_depth() {
    std::size_t failures = 0;
    struct point_t {
        std::size_t depth, calls, connections;
    };
    for (auto [depth, calls, connections] : {point_t {16, 64, 4}, point_t {1, 16, 8}}) {
        fixture_t fixture {{.connections = 8, .pipelined_requests = depth, .pipelined_calls = depth}};
        require(failures, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
        std::vector<std::string> bodies(calls);
        for (std::size_t i = 0; i != bodies.size(); ++i) {
            bodies[i] = fmt::format("call {}", i);
            std::string const url = fmt::format("{}/echo/{}", fixture.url, i);
            ucall_outcome_t outcome {};
            ucall_client_call_t call {};
            call.client = fixture.client;
            call.outcome = &outcome;
            call.url = uc::bytes_view(url);
            call.verb = ucall_verb_put_k;
            call.body = uc::bytes_view(bodies[i]);
            call.context = &bodies[i];
            ucall_client_call(&call);
            failures += expect(outcome.status == ucall_status_success_k);
        }
        for (std::size_t i = 0; i != bodies.size() && !failures; ++i) {
            auto completed = fixture.wait();
            failures += expect(completed.response, "depth {}: {}", depth, ucall_status_name(completed.outcome.status));
            if (completed.response)
                failures += check_response(completed.response, *static_cast<std::string*>(completed.context));
        }
        ucall_outcome_t outcome {};
        ucall_event_loop_statistics_t counters {};
        ucall_server_event_loop_statistics_t query {fixture.server, &outcome, 0, &counters};
        ucall_server_event_loop_statistics(&query);
        failures += expect(counters.accepts == connections, "depth {} opened {} connections", depth, counters.accepts);
        failures += fixture.stop();
    }
    return failures;
}
static case_result_t test_pipelined_calls_noise_xx() { return pipelined_calls(ucall_security_noise_xx_k); }

/** A caller's <tt>Connection: close</tt> on the second call keeps the POST and GET behind it
 *  off that connection: both wait for the next one and are answered there. */
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

/** 204 and 304 replies, which UCall sends without <tt>content-length</tt>, keep the connection:
 *  calls pipelined ahead of and behind them all complete over the one connection accepted. */
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

/** The body @c stream_reply sends as @p count chunks of growing, labelled sizes. */
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
static case_result_t reply_vectored(ucall_security_t security) {
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
static case_result_t test_reply_vectored_plain() { return reply_vectored(ucall_security_none_k); }
static case_result_t test_reply_vectored_noise_xx() { return reply_vectored(ucall_security_noise_xx_k); }

/** An application thread streams a reply of many chunks long after the callback returned, while
 *  this thread polls, and the client reads the chunked body whole. */
static case_result_t streamed_reply(ucall_security_t security) {
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
    call.options.noise_peer_key = &fixture.server_public;
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
static case_result_t test_streamed_reply_plain() { return streamed_reply(ucall_security_none_k); }
static case_result_t test_streamed_reply_noise_xx() { return streamed_reply(ucall_security_noise_xx_k); }

/** Two threads stream to two requests pipelined on one connection at once, the second thread
 *  starting first, and both replies arrive whole and in request order. */
static case_result_t pipelined_streams(ucall_security_t security) {
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
        call.options.noise_peer_key = &fixture.server_public;
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
static case_result_t test_pipelined_streams_plain() { return pipelined_streams(ucall_security_none_k); }
static case_result_t test_pipelined_streams_noise_xx() { return pipelined_streams(ucall_security_noise_xx_k); }

/** @c HEAD on a vectored and two streamed replies answers each head with no body, and the @c GET
 *  behind each on the same connection still parses. */
static case_result_t test_head_replies() {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    std::size_t failures = 0;
    auto security = ucall_security_none_k;
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

/** A listener the caller hands over is served by an engine accepting from any listener: an
 *  automatic server passes over Registered I/O, and one naming it is refused, saying why. */
static case_result_t test_borrowed_listener_backend() {
    uc::utilities::descriptor_t const listener = uc::utilities::socket_open(AF_INET);
    sockaddr_in bound {};
    bound.sin_family = AF_INET;
    bound.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    require(0,
            listener >= 0 && ::bind(listener, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) == 0 &&
                ::listen(listener, 4) == 0,
            "no TCP listener");
    std::intptr_t const handed = listener;
    ucall_network_interface_t network_interface {};
    network_interface.listen_descriptor = &handed;
    network_interface.max_concurrent_connections = 1;
    ucall_server_options_t config {};
    config.interfaces = &network_interface;
    config.interfaces_count = 1;
    config.backend = backend_under_test;
    config.cpu_class = cpu_class_under_test;
    ucall_server_t server {};
    ucall_server_options_t resolved {};
    ucall_outcome_t outcome {};
    ucall_server_init_t init {&server, &outcome, &config, &resolved};
    ucall_server_init(&init);
    std::size_t failures = 0;
    if (backend_under_test == ucall_io_backend_windows_rio_k)
        failures += expect(outcome.status == ucall_status_unsupported_k && outcome.message &&
                               std::string_view {outcome.message}.find("listen_descriptor") != std::string_view::npos,
                           "Registered I/O over a borrowed listener: {}", ucall_status_name(outcome.status));
    else
        failures += expect(
            outcome.status == ucall_status_success_k && resolved.backend != ucall_io_backend_windows_rio_k,
            "a borrowed listener: {} on {}", ucall_status_name(outcome.status),
            ucall_io_backend_name(resolved.backend));
    ucall_server_free(server);
    uc::utilities::socket_close(listener);
    return failures;
}

#pragma endregion Library Clients

#pragma region Raw Clients
#if UCALL_OS_POSIX_

/** Three requests arriving in one segment, the second closing, come back as two responses in
 *  order, then the close, even when the server may read four ahead. */
static case_result_t test_pipelined_delivery() {
    fixture_t fixture {{.pipelined_requests = 4}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t client;
    require(failures, client.connect(fixture.address));
    std::string_view const burst = "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nfirst" //
                                   "POST /echo/2 HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\n"          //
                                   "Connection: close\r\n\r\nsecond"                                    //
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

/** Headers, and a chunked body with its trailers, written one byte per segment still parse. */
static case_result_t test_fragmented_headers_delivery(random_generator_t& generator) {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    for (std::string_view const request :
         {"POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody",
          "POST /echo/1 HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" //
          "2;x=1\r\nbo\r\n2\r\ndy\r\n0\r\nX-Trailer: done\r\nX-Other: too\r\n\r\n"}) {
        raw_client_t client;
        require(failures + fixture.stop(), client.connect(fixture.address));
        auto const response = exchange_until_close(client, request, 1, generator, failures);
        failures += expect(response.status == 200 && response.body == "body", "answered {} {}", response.status,
                           response.body);
    }
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
    {"length beside chunked",
     "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n" //
     "\r\n0\r\n\r\nGET /echo/2 HTTP/1.1\r\nHost: a\r\n\r\n"},
    {"two lengths", "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nContent-Length: 4\r\n\r\nbody"},
    {"gzip coding", "POST /echo/1 HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n0\r\n\r\n", 501},
    {"17 hex digits",
     "POST /echo/1 HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n10000000000000001\r\nx\r\n" //
     "0\r\n\r\n"},
    {"bare line feed", "POST /echo/1 HTTP/1.1\r\nHost: a\r\nX-Pad: 1\nContent-Length: 4\r\n\r\nbody"},
    {"space before colon", "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length : 4\r\n\r\nbody"},
    {"no host", "GET /echo/1 HTTP/1.1\r\n\r\n"},
    {"length past size_t", "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 18446744073709551615\r\n\r\nbody", 413},
    {"chunked over HTTP/1.0", "POST /echo/1 HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n"},
    {"HTTP/2.0", "GET /echo/1 HTTP/2.0\r\nHost: a\r\n\r\n", 505},
    {"lowercase version", "GET /echo/1 http/1.1\r\nHost: a\r\n\r\n"},
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

/** A CRLF ahead of a request, as clients that end a body with one leave, is skipped rather than
 *  refused, both before the first request and between two. */
static case_result_t test_leading_empty_line_ignored(random_generator_t& generator) {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t client;
    require(failures + fixture.stop(), client.connect(fixture.address));
    std::string_view const requests = "\r\nPOST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi\r\n" //
                                      "GET /echo/2 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    auto const first = exchange_until_close(client, requests, 4, generator, failures);
    auto const second = parse_response(std::string_view {client.received}.substr(first.length));
    failures += expect(first.status == 200 && first.body == "hi", "first answered {} {}", first.status, first.body);
    failures += expect(second.status == 200 && second.length == client.received.size() - first.length,
                       "second answered {}", second.status);
    return failures + fixture.stop();
}

/** Whitespace between a chunk size and its extension, which RFC 9112 7.1.1 allows, still frames. */
static case_result_t test_chunk_extension_whitespace(random_generator_t& generator) {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t client;
    require(failures + fixture.stop(), client.connect(fixture.address));
    auto const response = exchange_until_close(
        client,
        "POST /echo/1 HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" //
        "2 ;a=1\r\nbo\r\n2\t ;b\r\ndy\r\n0\r\n\r\n",
        8, generator, failures);
    failures += expect(response.status == 200 && response.body == "body", "answered {} {}", response.status,
                       response.body);
    return failures + fixture.stop();
}

/** A verb its path does not take answers 405 listing the ones it does, HEAD falls back to GET,
 *  OPTIONS answers 204 with the same list, an absolute-form target routes by its path, and
 *  <tt>OPTIONS *</tt> lists every verb. */
static case_result_t test_method_routing(random_generator_t& generator) {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t client;
    require(failures + fixture.stop(), client.connect(fixture.address));
    struct row_t {
        std::string_view request;
        unsigned status;
        std::string_view header;
    };
    row_t const rows[] {
        {"POST /only-get HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n", 405, "\r\nallow: GET, HEAD, OPTIONS\r\n"},
        {"HEAD /only-get HTTP/1.1\r\nHost: a\r\n\r\n", 200, "\r\nx-ucall: passed\r\n"},
        {"OPTIONS /only-get HTTP/1.1\r\nHost: a\r\n\r\n", 204, "\r\nallow: GET, HEAD, OPTIONS\r\n"},
        {"GET http://a/only-get?x=1 HTTP/1.1\r\nHost: a\r\n\r\n", 200, "\r\nx-ucall: passed\r\n"},
        {"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n", 204, "\r\nallow: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS\r\n"},
        {"GET /missing HTTP/1.1\r\nHost: a\r\n\r\n", 404, "\r\ncontent-length: 9\r\n"},
    };
    for (auto const& row : rows) {
        std::size_t const offset = client.received.size();
        failures += expect(client.write(uc::byte_span(row.request), 0, generator, steady_clock::now() + 5s));
        auto const response = read_response(client, offset);
        std::string_view const head = std::string_view {client.received}.substr(offset, response.length);
        failures += expect(response.status == row.status && head.find(row.header) != std::string_view::npos &&
                               response.body.empty() == (row.status < 300),
                           "{:?} answered {:?}", row.request, head);
    }
    return failures + fixture.stop();
}

/** A reply naming its own @c connection field is refused, since the loop writes the one that
 *  decides whether the connection stays, and the same reply without it goes out. */
static case_result_t test_reply_connection_header_refused() {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t client;
    require(failures + fixture.stop(), client.connect(fixture.address));
    std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
    failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                       static_cast<ssize_t>(request.size()));
    failures += await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    require(failures + fixture.stop(), held);
    ucall_outcome_t outcome {};
    ucall_bytes_view_t const header = uc::bytes_view("Connection: close");
    ucall_server_reply_content_t refused {fixture.server,     &outcome, held, ucall_http_status_ok_k, &header, 1,
                                          uc::bytes_view("x")};
    ucall_server_reply_content(&refused);
    failures += expect(outcome.status == ucall_status_invalid_argument_k, "a reply's connection field answered {}",
                       ucall_status_name(outcome.status));
    ucall_server_reply_content_t reply {fixture.server,     &outcome, held, ucall_http_status_ok_k, nullptr, 0,
                                        uc::bytes_view("x")};
    ucall_server_reply_content(&reply);
    failures += expect(outcome.status == ucall_status_success_k, "reply: {}", ucall_status_name(outcome.status));
    auto const response = read_response(client, 0);
    failures += expect(response.status == 200 && response.body == "x", "answered {} {}", response.status,
                       response.body);
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
    std::string_view const request = "GET /headers?x=1 HTTP/1.1\r\nHost: a\r\nContent-Type: text/plain\r\n" //
                                     "X-~: tilde\r\nConnection: close\r\n\r\n";
    auto const response = exchange_until_close(client, request, 8, generator, failures);
    // `^` and `~` differ only in the bit that folds ASCII letters.
    failures += expect(response.body == "/headers;text/plain;tilde;not-found;not-found;", "answered {} {}",
                       response.status, response.body);
    return failures + fixture.stop();
}

/** Holds one request @p wire sends to the gate route, runs @p inspect on it, and answers it. */
template <typename inspect_type_>
static std::size_t held_request(std::string_view wire, inspect_type_&& inspect) {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t client;
    require(failures + fixture.stop(), client.connect(fixture.address));
    failures += expect(::send(client.descriptor, wire.data(), wire.size(), 0) == static_cast<ssize_t>(wire.size()));
    failures += await_held_in_background(fixture, 1);
    auto* request = fixture.take_held();
    require(failures + fixture.stop(), request);
    failures += inspect(fixture.server, request);
    ucall_outcome_t outcome {};
    ucall_server_reply_content_t reply {fixture.server,      &outcome, request, ucall_http_status_ok_k, nullptr, 0,
                                        uc::bytes_view("ok")};
    ucall_server_reply_content(&reply);
    failures += expect(read_response(client, 0).body == "ok");
    return failures + fixture.stop();
}

/** Field lines read back by index in arrival order, repeated names apart, names lowercased as the
 *  parser keeps them and values trimmed, and an index past the last one is not found. */
static case_result_t test_request_fields_in_order() {
    std::string_view const wire = "GET /gate HTTP/1.1\r\nHost: a\r\nX-B:  two \r\nx-a:one\r\nX-B: again\r\n\r\n";
    return held_request(wire, [](ucall_server_t server, ucall_received_http_request_t request) {
        std::size_t failures = 0, count = 0;
        ucall_outcome_t outcome {};
        ucall_server_request_fields_count_t counting {server, &outcome, request, &count};
        ucall_server_request_fields_count(&counting);
        failures += expect(outcome.status == ucall_status_success_k && count == 4, "{} fields", count);
        std::string read;
        for (std::size_t index = 0; index <= count; ++index) {
            ucall_bytes_view_t name {}, value {};
            ucall_server_request_field_t field {server, &outcome, request, index, &name, &value};
            ucall_server_request_field(&field);
            if (outcome.status != ucall_status_success_k) {
                failures += expect(index == count && outcome.status == ucall_status_not_found_k, "field {}: {}", index,
                                   ucall_status_name(outcome.status));
                break;
            }
            read += fmt::format("{}={};", uc::text_view(name), uc::text_view(value));
        }
        failures += expect(read == "host=a;x-b=two;x-a=one;x-b=again;", "read {}", read);
        return failures;
    });
}

/** The raw query after the first @c ?, still percent-encoded, or empty for a target without one. */
static case_result_t test_request_query() {
    auto query_is = [](std::string_view expected) {
        return [expected](ucall_server_t server, ucall_received_http_request_t request) {
            ucall_outcome_t outcome {};
            ucall_bytes_view_t query {};
            ucall_server_request_query_t get {server, &outcome, request, &query};
            ucall_server_request_query(&get);
            return expect(outcome.status == ucall_status_success_k && uc::text_view(query) == expected, "{}: {:?}",
                          ucall_status_name(outcome.status), uc::text_view(query));
        };
    };
    return held_request("GET /gate?b=2&a=%20&b=?x HTTP/1.1\r\nHost: a\r\n\r\n", query_is("b=2&a=%20&b=?x")) +
           held_request("GET /gate HTTP/1.1\r\nHost: a\r\n\r\n", query_is(""));
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

/** Two loops share a budget of two: a third client is served only once an eviction closes one of
 *  the two idle ones. */
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
    failures += expect(read_response(clients[2], 0).status == 200, "the third client was not served");
    std::size_t closed = 0;
    for (std::size_t i = 0; i != 2; ++i)
        closed += clients[i].read_until_close(steady_clock::now() + 300ms) == read_end_t::closed_k;
    failures += expect(closed == 1, "{} of the two idle clients were closed for the third", closed);
    return failures + fixture.stop();
}

/** At its connection budget the server evicts the keep-alive connection idle longest for a waiting
 *  peer, closing it in order, but never one that holds a request; a peer finding only busy ones is
 *  never served past the budget. */
static case_result_t test_keepalive_eviction(random_generator_t& generator) {
    fixture_t fixture {{.connections = 2}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    std::string_view const echo = "GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n";
    std::string_view const gate = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
    auto send = [&](raw_client_t& client, std::string_view bytes) {
        failures += expect(client.write(uc::byte_span(bytes), 0, generator, steady_clock::now() + 5s));
    };
    {
        announce("idle connections");
        raw_client_t first, second, third;
        for (auto* client : {&first, &second}) {
            require(failures + fixture.stop(), client->connect(fixture.address));
            send(*client, echo);
            failures += expect(read_response(*client, 0).status == 200, "an admitted client was not served");
        }
        require(failures + fixture.stop(), third.connect(fixture.address));
        send(third, echo);
        auto const answered = third.read(1, steady_clock::now() + 1s);
        failures += expect(answered == read_end_t::filled_k && read_response(third, 0).status == 200,
                           "the waiting client ended as {}", static_cast<int>(answered));
        failures += expect(first.read_until_close(steady_clock::now() + 1s) == read_end_t::closed_k,
                           "the longest-idle client was not closed in order");
    }
    // The evicted and served peers must close first, so the next step starts with a free budget.
    std::this_thread::sleep_for(100ms);
    {
        announce("busy connections");
        raw_client_t first, second, third;
        for (auto* client : {&first, &second}) {
            require(failures + fixture.stop(), client->connect(fixture.address));
            send(*client, gate);
        }
        failures += await_held_in_background(fixture, 2);
        require(failures + fixture.stop(), third.connect(fixture.address));
        // A probe armed while a connection was idle may close this peer, so its write may fail.
        [[maybe_unused]] bool const written = third.write(uc::byte_span(echo), 0, generator, steady_clock::now() + 1s);
        failures += expect(third.read(1, steady_clock::now() + 300ms) != read_end_t::filled_k,
                           "a peer was served past a budget of busy connections");
        for (std::size_t held = 0; held != 2; ++held) {
            ucall_outcome_t outcome {};
            ucall_server_reply_content_t reply {fixture.server, &outcome, fixture.take_held(),   ucall_http_status_ok_k,
                                                nullptr,        0,        uc::bytes_view("held")};
            ucall_server_reply_content(&reply);
            failures += expect(outcome.status == ucall_status_success_k, "reply: {}",
                               ucall_status_name(outcome.status));
        }
        for (auto* client : {&first, &second})
            failures += expect(read_response(*client, 0).status == 200, "a held client lost its reply");
    }
    return failures + fixture.stop();
}

/** A request whose peer left lives until answered, so once a loop holds as many of those as it
 *  holds exchanges, new requests answer 503 until one is answered. */
static case_result_t test_orphaned_exchanges_bounded(random_generator_t& generator) {
    // A second request slot keeps a receive armed behind the held one, so peers leaving are seen.
    fixture_t fixture {{.pipelined_requests = 2}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    for (std::size_t left = 0; left != 2; ++left) {
        raw_client_t leaving;
        require(failures + fixture.stop(), leaving.connect(fixture.address));
        std::string_view const gate = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
        failures += expect(leaving.write(uc::byte_span(gate), 0, generator, steady_clock::now() + 5s));
        failures += await_held_in_background(fixture, left + 1);
        // A reset rather than a FIN, which the server would answer on the half-closed connection.
        linger const abrupt {1, 0};
        failures += expect(::setsockopt(leaving.descriptor, SOL_SOCKET, SO_LINGER, &abrupt, sizeof(abrupt)) == 0);
    }
    raw_client_t next;
    require(failures + fixture.stop(), next.connect(fixture.address));
    std::string_view const echo = "GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n";
    failures += expect(next.write(uc::byte_span(echo), 0, generator, steady_clock::now() + 5s));
    auto const refused = read_response(next, 0);
    failures += expect(refused.status == 503, "a request past the abandoned budget answered {}", refused.status);
    ucall_outcome_t outcome {};
    ucall_server_reply_content_t reply {fixture.server, &outcome, fixture.take_held(),   ucall_http_status_ok_k,
                                        nullptr,        0,        uc::bytes_view("late")};
    ucall_server_reply_content(&reply);
    failures += expect(outcome.status == ucall_status_success_k || outcome.status == ucall_status_connection_closed_k,
                       "the abandoned reply answered {}", ucall_status_name(outcome.status));
    failures += expect(next.write(uc::byte_span(echo), 0, generator, steady_clock::now() + 5s));
    auto const served = read_response(next, refused.length);
    failures += expect(served.status == 200, "a request after the abandoned one was answered got {}", served.status);
    reply.request = fixture.take_held();
    ucall_server_reply_content(&reply);
    return failures + fixture.stop();
}

/** A peer reaching an IPv6 listener is reported by the address and port its own socket names. */
static case_result_t test_request_peer_ipv6() {
    struct captured_t {
        ucall_server_t server {};
        ucall_peer_address_t address {};
    } captured;
    ucall_network_interface_t network_interface {};
    network_interface.address = uc::bytes_view("[::1]:0");
    network_interface.max_concurrent_connections = 1;
    ucall_server_options_t config {}, resolved {};
    config.interfaces = &network_interface;
    config.interfaces_count = 1;
    config.backend = backend_under_test;
    config.cpu_class = cpu_class_under_test;
    ucall_outcome_t outcome {};
    ucall_server_init_t init {&captured.server, &outcome, &config, &resolved};
    ucall_server_init(&init);
    if (outcome.status == ucall_status_connection_failed_k) return case_result_t::skipped("::1 cannot bind here");
    require(0, outcome.status == ucall_status_success_k, "setup: {}", ucall_status_name(outcome.status));
    auto capture = [](ucall_received_http_request_t request, void* context) {
        auto& into = *static_cast<captured_t*>(context);
        ucall_outcome_t queried {};
        std::size_t network_interface_index = 0;
        ucall_noise_key_t key {};
        ucall_server_request_peer_t peer {into.server, &queried,     request, &network_interface_index,
                                          &key,        &into.address};
        ucall_server_request_peer(&peer);
        ucall_server_reply_content_t reply {
            into.server, &queried, request, ucall_http_status_ok_k, nullptr, 0, uc::bytes_view("seen")};
        ucall_server_reply_content(&reply);
    };
    ucall_server_add_http_endpoint_t add {captured.server,  &outcome, uc::bytes_view("/peer"),
                                          ucall_verb_any_k, capture,  &captured};
    ucall_server_add_http_endpoint(&add);
    std::size_t failures = expect(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    std::thread poller {[&] {
        ucall_outcome_t served {};
        ucall_server_take_calls_t serving {captured.server, &served, 0};
        ucall_server_take_calls(&serving);
    }};
    std::string_view const bound = uc::text_view(resolved.interfaces[0].address);
    sockaddr_in6 target {};
    target.sin6_family = AF_INET6;
    target.sin6_addr = in6addr_loopback;
    target.sin6_port = htons(static_cast<std::uint16_t>(std::stoi(std::string {bound.substr(bound.rfind(':') + 1)})));
    raw_client_t client;
    client.descriptor = ::socket(AF_INET6, SOCK_STREAM, 0);
    failures += expect(::connect(client.descriptor, reinterpret_cast<sockaddr const*>(&target), sizeof(target)) == 0,
                       "no connection to {}: {}", bound, errno);
    sockaddr_in6 own {};
    socklen_t own_length = sizeof(own);
    failures += expect(::getsockname(client.descriptor, reinterpret_cast<sockaddr*>(&own), &own_length) == 0);
    std::string_view const request = "GET /peer HTTP/1.1\r\nHost: a\r\n\r\n";
    failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                       static_cast<ssize_t>(request.size()));
    failures += expect(read_response(client, 0).body == "seen", "the request was not answered");
    ucall_server_stop(captured.server);
    poller.join();
    failures += expect(captured.address.family == ucall_address_family_ipv6_k &&
                           std::memcmp(captured.address.bytes, &own.sin6_addr, 16) == 0 &&
                           captured.address.port == ntohs(own.sin6_port),
                       "reported family {} port {} for port {}", captured.address.family, captured.address.port,
                       ntohs(own.sin6_port));
    ucall_server_free(captured.server);
    return failures;
}

/** A listener the caller hands over is accepted on through duplicates: a TCP one echoes on two
 *  loops and keeps accepting after the server is freed, and an AF_UNIX one echoes 64 KiB, reports
 *  its path as the bound address, and reports its peers as AF_UNIX. */
static case_result_t test_interface_listen_descriptor(random_generator_t& generator) {
    struct served_t {
        ucall_server_t server {};
        ucall_server_options_t resolved {};
        std::atomic<std::uint8_t> family {};
        std::thread poller {};
    };
    auto echo = [](ucall_received_http_request_t request, void* context) {
        auto& into = *static_cast<served_t*>(context);
        ucall_outcome_t outcome {};
        std::size_t network_interface_index = 0;
        ucall_noise_key_t key {};
        ucall_peer_address_t address {};
        ucall_server_request_peer_t peer {into.server, &outcome, request, &network_interface_index, &key, &address};
        ucall_server_request_peer(&peer);
        into.family.store(address.family);
        ucall_bytes_view_t body {};
        ucall_server_request_body_t extract {into.server, &outcome, request, &body};
        ucall_server_request_body(&extract);
        ucall_server_reply_content_t reply {into.server, &outcome, request, ucall_http_status_ok_k, nullptr, 0, body};
        ucall_server_reply_content(&reply);
    };
    // Serves `listener` on `event_loops` loops, answering whether the server started.
    auto serve = [&](served_t& served, std::intptr_t listener, std::size_t event_loops) -> ucall_status_t {
        ucall_network_interface_t network_interface {};
        network_interface.listen_descriptor = &listener;
        network_interface.event_loops = event_loops;
        network_interface.max_concurrent_connections = 4;
        network_interface.max_request_bytes = 1 << 20;
        ucall_server_options_t config {};
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
        config.backend = backend_under_test;
        config.cpu_class = cpu_class_under_test;
        ucall_outcome_t outcome {};
        ucall_server_init_t init {&served.server, &outcome, &config, &served.resolved};
        ucall_server_init(&init);
        if (outcome.status != ucall_status_success_k) return outcome.status;
        ucall_server_add_http_endpoint_t add {served.server,    &outcome, uc::bytes_view("/echo"),
                                              ucall_verb_any_k, echo,     &served};
        ucall_server_add_http_endpoint(&add);
        if (outcome.status != ucall_status_success_k) return outcome.status;
        served.poller = std::thread {[&served, event_loops] {
            std::vector<std::thread> loops;
            for (std::size_t loop = 1; loop < event_loops; ++loop)
                loops.emplace_back([&served, loop] {
                    ucall_outcome_t ended {};
                    ucall_server_take_calls_t taking {served.server, &ended, loop};
                    ucall_server_take_calls(&taking);
                });
            ucall_outcome_t ended {};
            ucall_server_take_calls_t taking {served.server, &ended, 0};
            ucall_server_take_calls(&taking);
            for (auto& loop : loops) loop.join();
        }};
        return ucall_status_success_k;
    };
    auto finish = [](served_t& served) {
        ucall_server_stop(served.server);
        if (served.poller.joinable()) served.poller.join();
        ucall_server_free(served.server);
    };
    auto exchange = [&](raw_client_t& client, std::string_view body, std::size_t& failures) {
        std::string const request = fmt::format("POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n{}",
                                                body.size(), body);
        std::size_t const offset = client.received.size();
        failures += expect(client.write(uc::byte_span(request), 65536, generator, steady_clock::now() + 5s));
        auto const response = read_response(client, offset);
        failures += expect(response.status == 200 && response.body == body, "echoed {} with {} of {} bytes",
                           response.status, response.body.size(), body.size());
    };
    std::size_t failures = 0;
    {
        announce("TCP over two loops");
        int const listener = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in bound {};
        bound.sin_family = AF_INET;
        bound.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t length = sizeof(bound);
        require(failures,
                listener >= 0 && ::bind(listener, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) == 0 &&
                    ::getsockname(listener, reinterpret_cast<sockaddr*>(&bound), &length) == 0 &&
                    ::listen(listener, 16) == 0,
                "no TCP listener");
        std::string const address = fmt::format("127.0.0.1:{}", ntohs(bound.sin_port));
        served_t served;
        ucall_status_t const started = serve(served, listener, UCALL_OS_WINDOWS_ ? 1 : 2);
        failures += expect(started == ucall_status_success_k, "a handed TCP listener: {}", ucall_status_name(started));
        if (started == ucall_status_success_k) {
            failures += expect(uc::text_view(served.resolved.interfaces[0].address) == address, "reported {}",
                               uc::text_view(served.resolved.interfaces[0].address));
            raw_client_t clients[3];
            for (auto& client : clients) {
                failures += expect(client.connect(address), "no connection to {}", address);
                if (client.descriptor >= 0) exchange(client, "over tcp", failures);
            }
            failures += expect(served.family.load() == ucall_address_family_ipv4_k);
        }
        finish(served);
        raw_client_t after;
        failures += expect(::fcntl(listener, F_GETFD) != -1 && after.connect(address),
                           "the caller's listener closed with the server");
        ::close(listener);
    }
    {
        announce("AF_UNIX");
        scratch_directory_t directory;
        std::string const path = directory.name("listen.sock");
        int const listener = ::socket(AF_UNIX, SOCK_STREAM, 0);
        sockaddr_un bound {};
        bound.sun_family = AF_UNIX;
        std::memcpy(bound.sun_path, path.c_str(), fu::min_of(path.size() + 1, sizeof(bound.sun_path) - 1));
        require(failures,
                listener >= 0 && path.size() < sizeof(bound.sun_path) &&
                    ::bind(listener, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) == 0 &&
                    ::listen(listener, 16) == 0,
                "no AF_UNIX listener at {}", path);
        served_t served;
        ucall_status_t const started = serve(served, listener, 1);
        failures += expect(started == ucall_status_success_k, "a handed AF_UNIX listener: {}",
                           ucall_status_name(started));
        if (started == ucall_status_success_k) {
            failures += expect(uc::text_view(served.resolved.interfaces[0].address) == path, "reported {}",
                               uc::text_view(served.resolved.interfaces[0].address));
            raw_client_t client;
            client.descriptor = ::socket(AF_UNIX, SOCK_STREAM, 0);
            failures += expect(::connect(client.descriptor, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) == 0,
                               "no connection to {}: {}", path, errno);
            std::string const body(64 * 1024, 'u');
            exchange(client, body, failures);
            failures += expect(served.family.load() == ucall_address_family_unix_k, "reported family {}",
                               served.family.load());
        }
        finish(served);
        ::close(listener);
    }
    return failures;
}

/** A drain closes the listener at once: a peer connecting after one stop is refused or reset rather
 *  than parked in a backlog nobody accepts, while the held reply still arrives. */
static case_result_t test_drain_closes_listener(random_generator_t& generator) {
    fixture_t fixture {{.connections = 2}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    raw_client_t busy;
    require(failures + fixture.stop(), busy.connect(fixture.address));
    std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
    failures += expect(::send(busy.descriptor, request.data(), request.size(), 0) ==
                       static_cast<ssize_t>(request.size()));
    failures += await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    require(failures + fixture.stop(), held);
    ucall_server_stop(fixture.server);
    // A connect racing the loop's next round lands in the backlog, which the close then resets.
    std::this_thread::sleep_for(50ms);
    raw_client_t late;
    if (late.connect(fixture.address)) {
        std::string_view const probe = "GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n";
        [[maybe_unused]] bool const written = late.write(uc::byte_span(probe), 0, generator, steady_clock::now() + 1s);
        auto const end = late.read(1, steady_clock::now() + 1s);
        failures += expect(end == read_end_t::failed_k || end == read_end_t::closed_k,
                           "a peer connecting after the stop waited as {}", static_cast<int>(end));
    }
    ucall_outcome_t outcome {};
    ucall_server_reply_content_t reply {fixture.server,           &outcome, held, ucall_http_status_ok_k, nullptr, 0,
                                        uc::bytes_view("drained")};
    ucall_server_reply_content(&reply);
    failures += expect(outcome.status == ucall_status_success_k, "reply: {}", ucall_status_name(outcome.status));
    auto const response = read_response(busy, 0);
    failures += expect(response.status == 200 && response.body == "drained", "answered {} {}", response.status,
                       response.body);
    return failures + fixture.stop();
}

/** Running out of descriptors sheds the peers queued behind the exhausted table rather than
 *  stalling them or cutting the server: each reads a 503 or a close within two seconds, or is
 *  served where descriptors came back first or a ring accepts into slots of its own, and a fresh
 *  peer is served afterwards. */
static case_result_t test_accept_exhaustion_sheds(random_generator_t& generator) {
    fixture_t fixture {{.connections = 4}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    std::string_view const request = "GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n";
    // A served request proves the loop opened its engine, which needs descriptors of its own.
    raw_client_t fresh;
    require(failures + fixture.stop(), fresh.connect(fixture.address));
    failures += expect(fresh.write(uc::byte_span(request), 0, generator, steady_clock::now() + 5s));
    failures += expect(read_response(fresh, 0).status == 200, "the first client was not served");
    sockaddr_in target {};
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    target.sin_port = htons(
        static_cast<std::uint16_t>(std::stoi(fixture.address.substr(fixture.address.rfind(':') + 1))));
    // Sockets made before the limit drops, so only the server's accepts find the table full.
    raw_client_t clients[3];
    for (auto& client : clients) client.descriptor = ::socket(AF_INET, SOCK_STREAM, 0);
    rlimit original {};
    require(failures + fixture.stop(), ::getrlimit(RLIMIT_NOFILE, &original) == 0);
    int const lowest = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    ::close(lowest);
    rlimit lowered = original;
    lowered.rlim_cur = static_cast<rlim_t>(lowest);
    failures += expect(::setrlimit(RLIMIT_NOFILE, &lowered) == 0, "the descriptor limit stayed");
    for (auto& client : clients)
        failures += expect(
            ::connect(client.descriptor, reinterpret_cast<sockaddr const*>(&target), sizeof(target)) == 0,
            "a backlog client could not connect: {}", errno);
    std::this_thread::sleep_for(200ms);
    failures += expect(::setrlimit(RLIMIT_NOFILE, &original) == 0, "the descriptor limit stayed lowered");
    for (auto& client : clients) {
        // A shed peer may be gone before it writes, so only what it reads decides.
        [[maybe_unused]] bool const written = client.write(uc::byte_span(request), 0, generator,
                                                           steady_clock::now() + 2s);
        auto const deadline = steady_clock::now() + 2s;
        read_end_t end = read_end_t::filled_k;
        wire_response_t response = parse_response(client.received);
        while (!response.length && end == read_end_t::filled_k) {
            end = client.read(client.received.size() + 1, deadline);
            response = parse_response(client.received);
        }
        bool const closed = !response.length && (end == read_end_t::closed_k || end == read_end_t::failed_k);
        failures += expect(response.status == 503 || response.status == 200 || closed,
                           "a backlog client read {} bytes, answered {}, ending as {}", client.received.size(),
                           response.status, static_cast<int>(end));
    }
    fresh.received.clear();
    require(failures + fixture.stop(), fresh.connect(fixture.address));
    failures += expect(fresh.write(uc::byte_span(request), 0, generator, steady_clock::now() + 5s));
    failures += expect(read_response(fresh, 0).status == 200, "a fresh client was not served");
    bool const rings = fixture.resolved.backend == ucall_io_backend_linux_uring612_k ||
                       fixture.resolved.backend == ucall_io_backend_linux_uring618_k;
    std::uint64_t const shed = loop_statistics(fixture).shed_connections;
    failures += expect(rings || shed, "no peer was shed on {}", ucall_io_backend_name(fixture.resolved.backend));
    return failures + fixture.stop();
}

/** The log sink receives a line when the server starts serving and one per refusal, in either
 *  format, from whichever loop wrote it. */
static case_result_t test_log_lines() {
    std::size_t failures = 0;
    for (ucall_log_format_t format : {ucall_log_format_human_k, ucall_log_format_json_k}) {
        struct collected_t {
            std::mutex mutex;
            std::vector<std::string> lines;
        } collected;
        auto collect = [](ucall_log_level_t, ucall_bytes_view_t line, void* context) {
            auto& into = *static_cast<collected_t*>(context);
            std::lock_guard lock {into.mutex};
            into.lines.emplace_back(reinterpret_cast<char const*>(line.data), line.length);
        };
        fixture_t fixture {{.log = {collect, &collected, format, ucall_log_level_info_k}}};
        require(failures, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
        fixture.serve_in_background();
        raw_client_t client;
        require(failures + fixture.stop(), client.connect(fixture.address));
        std::string_view const request = "GET /missing HTTP/1.1\r\nHost: a\r\n\r\n";
        failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                           static_cast<ssize_t>(request.size()));
        auto const deadline = steady_clock::now() + 5s;
        while (client.received.find("Not found") == std::string::npos &&
               client.read(client.received.size() + 1, deadline) == read_end_t::filled_k) {}
        failures += fixture.stop();
        bool const json = format == ucall_log_format_json_k;
        std::string const serving = json ? R"({"level":"info","event":"serving","address":")" : "info serving address=";
        std::string const refused = json ? R"({"level":"info","event":"refused","status":"404",)"
                                         : "info refused status=404 ";
        std::lock_guard lock {collected.mutex};
        auto starting = [&](std::string const& prefix) {
            return std::any_of(collected.lines.begin(), collected.lines.end(),
                               [&](std::string const& line) { return line.starts_with(prefix); });
        };
        failures += expect(starting(serving) && starting(refused), "format {} wrote {} lines, first: {}",
                           static_cast<int>(format), collected.lines.size(),
                           collected.lines.empty() ? std::string {} : collected.lines.front());
    }
    return failures;
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

/** A declared @c content-length frames chunks as identity, refuses a chunk running past it, and an
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

#endif // UCALL_OS_POSIX_
#pragma endregion Raw Clients

void run_exchanges(suite_totals_t& totals) {
    run_test(totals, "test_exchanges_plain", test_exchanges_plain);
    run_test(totals, "test_exchanges_noise_xx", test_exchanges_noise_xx);
    run_test(totals, "test_exchanges_noise_ik", test_exchanges_noise_ik);
    run_test(totals, "test_exchanges_noise_kk", test_exchanges_noise_kk);
    run_test(totals, "test_echo_completions_plain", test_echo_completions_plain);
    run_test(totals, "test_echo_completions_noise_xx", test_echo_completions_noise_xx);
    run_test(totals, "test_server_kk_wrong_initiator", test_server_kk_wrong_initiator);
    run_test(totals, "test_multiloop_retention", test_multiloop_retention);
    run_test(totals, "test_cross_thread_replies_stress", test_cross_thread_replies_stress);
    run_test(totals, "test_pipelined_calls_plain", test_pipelined_calls_plain);
    run_test(totals, "test_client_dials_for_depth", test_client_dials_for_depth);
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
    run_test(totals, "test_borrowed_listener_backend", test_borrowed_listener_backend);
#if UCALL_OS_POSIX_
    run_test(totals, "test_log_lines", test_log_lines);
    run_test(totals, "test_streamed_reply_would_block", test_streamed_reply_would_block);
    run_test(totals, "test_streamed_reply_detach", test_streamed_reply_detach);
    run_test(totals, "test_streamed_reply_http10", test_streamed_reply_http10);
    run_test(totals, "test_streamed_reply_identity", test_streamed_reply_identity);
    run_test(totals, "test_pipelined_delivery", test_pipelined_delivery);
    run_test(totals, "test_fragmented_headers_delivery", test_fragmented_headers_delivery);
    run_test(totals, "test_megabyte_echo_delivery", test_megabyte_echo_delivery);
    run_test(totals, "test_smuggling_safety", test_smuggling_safety);
    run_test(totals, "test_leading_empty_line_ignored", test_leading_empty_line_ignored);
    run_test(totals, "test_chunk_extension_whitespace", test_chunk_extension_whitespace);
    run_test(totals, "test_header_lookup_unit", test_header_lookup_unit);
    run_test(totals, "test_request_fields_in_order", test_request_fields_in_order);
    run_test(totals, "test_request_query", test_request_query);
    run_test(totals, "test_method_routing", test_method_routing);
    run_test(totals, "test_reply_connection_header_refused", test_reply_connection_header_refused);
    run_test(totals, "test_cross_thread_teardown_delivery", test_cross_thread_teardown_delivery);
    run_test(totals, "test_admission_across_loops", test_admission_across_loops);
    run_test(totals, "test_drain_closes_listener", test_drain_closes_listener);
    run_test(totals, "test_accept_exhaustion_sheds", test_accept_exhaustion_sheds);
    run_test(totals, "test_keepalive_eviction", test_keepalive_eviction);
    run_test(totals, "test_orphaned_exchanges_bounded", test_orphaned_exchanges_bounded);
    run_test(totals, "test_request_peer_ipv6", test_request_peer_ipv6);
    run_test(totals, "test_interface_listen_descriptor", test_interface_listen_descriptor);
#endif
}

} // namespace unum::ucall::test::network
