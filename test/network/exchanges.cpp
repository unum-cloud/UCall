/**
 *  @file test/network/exchanges.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Library-client exchanges, Noise modes, pipelining, vectored, streamed and head replies,
 *      raw delivery, smuggling and admission.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build
#include <network.hpp>

namespace unum::ucall::test::network {

#pragma region Library Clients

static void test_exchanges(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
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
    call.options.security = cell.security;
    call.options.noise_peer_key = &fixture.server_public;
    auto exchange = [&](std::string_view expected) {
        ucall_client_call(&call);
        expect_true(outcome.status == ucall_status_success_k);
        auto completed = fixture.wait();
        expect_true(completed.outcome.status == ucall_status_success_k && completed.response, "{}",
                    ucall_status_name(completed.outcome.status));
        if (completed.response) check_response(completed.response, expected);
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
            expect_true(!fixture.poll(completed), "a call completed unasked");
            copies = copies_beyond_receipt();
        }
        return copies;
    };
    exchange(payload);
    auto const before = settled_copies(0, payload.size());
    exchange(payload);
    auto const copied = settled_copies(before, payload.size()) - before;
    // A 618 stream that outruns its receive copies those bytes into the backlog as well.
    bool const streams = backend == ucall_io_backend_linux_uring618_k;
    std::size_t const copied_limit = streams ? 3 * payload.size() : payload.size();
    expect_true(copied >= payload.size() && copied <= copied_limit,
                "{} bytes copied beyond those received for a {}-byte echo", copied, payload.size());
    // Only a socket accepted in Registered I/O sends unregistered bytes through a slice.
    expect_true(backend != ucall_io_backend_windows_rio_k || loop_statistics(fixture).copying_sends > 0,
                "the server's connections sent outside Registered I/O");
    if (cell.security != ucall_security_none_k) {
        fixture.stop();
        return;
    }
    auto named_url = url;
    named_url.replace(named_url.find("127.0.0.1"), std::strlen("127.0.0.1"), "localhost");
    call.url = uc::bytes_view(named_url);
    exchange(payload);
    call.url = uc::bytes_view(url);
    ucall_bytes_view_t close = uc::bytes_view("Connection: close");
    call.headers = &close;
    call.headers_count = 1;
    exchange(payload);
    call.verb = ucall_verb_get_k;
    call.body = {};
    call.headers = nullptr;
    call.headers_count = 0;
    ucall_client_call(&call);
    expect_true(outcome.status == ucall_status_success_k);
    auto completed = fixture.wait();
    ucall_client_free(std::exchange(fixture.client, nullptr));
    expect_true(completed.outcome.status == ucall_status_success_k && completed.response, "{}",
                ucall_status_name(completed.outcome.status));
    if (completed.response) check_response(completed.response, {});
    fixture.stop();
}

/** A warm 64 KB echo costs a handful of completions, however many pages its records span, as a
 *  receive takes all that the socket holds; only the first ones grow the room it lands in. */
static void test_echo_completions(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    std::string const payload(64 * 1024, 'x');
    auto const url = fmt::format("{}/echo/42", fixture.url);
    ucall_outcome_t outcome {};
    ucall_client_call_t call {};
    call.client = fixture.client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(url);
    call.verb = ucall_verb_post_k;
    call.body = uc::bytes_view(payload);
    call.options.security = cell.security;
    call.options.noise_peer_key = &fixture.server_public;
    auto echo = [&] {
        ucall_client_call(&call);
        expect_true(outcome.status == ucall_status_success_k);
        auto const completed = fixture.wait();
        expect_true(completed.outcome.status == ucall_status_success_k && completed.response, "{}",
                    ucall_status_name(completed.outcome.status));
        if (completed.response) ucall_client_response_free(completed.response);
    };
    for (std::size_t warming = 0; warming != 8; ++warming) echo();
    ucall_event_loop_statistics_t const warm = loop_statistics(fixture);
    std::size_t const echoes = 16;
    for (std::size_t measured = 0; measured != echoes; ++measured) echo();
    ucall_event_loop_statistics_t const after = loop_statistics(fixture);
    std::uint64_t const spent = after.completions - warm.completions;
    expect_true(spent <= 8 * echoes, "{} completions for {} echoes", spent, echoes);
    // Every engine counts each reply's send once, copying or not, and only a ring fills entries.
    std::uint64_t const sends = after.zero_copy_sends + after.copying_sends - warm.zero_copy_sends - warm.copying_sends;
    expect_true(sends >= echoes && sends <= 2 * echoes, "{} sends counted for {} echoes", sends, echoes);
    bool const ring = fixture.resolved.backend == ucall_io_backend_linux_uring612_k ||
                      fixture.resolved.backend == ucall_io_backend_linux_uring618_k;
    expect_true(ring == (after.kernel_entries != 0), "{} ring entries on {}", after.kernel_entries,
                ucall_io_backend_name(fixture.resolved.backend));
    fixture.stop();
}

/** A KK interface refuses an initiator whose static key is not the one it names. */
static void test_server_kk_wrong_initiator(sweep_cell_t const& cell) {
    fixture_t fixture {{cell.backend, cell.cpu_class_ceiling, ucall_security_noise_kk_k}, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    ucall_noise_key_t stranger {}, stranger_public {};
    ucall_outcome_t outcome {};
    ucall_noise_key_generate_t generate {&outcome, &stranger, &stranger_public};
    ucall_noise_key_generate(&generate);
    if (!expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status))) return;
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
    expect_true(outcome.status == ucall_status_success_k);
    auto completed = fixture.wait();
    expect_true(completed.outcome.status != ucall_status_success_k, "a stranger's KK call answered {}",
                ucall_status_name(completed.outcome.status));
    expect_true(!fixture.dispatched, "{} requests reached a route", fixture.dispatched.load());
    fixture.stop();
}

/** A request retained on one loop does not stall a call the other loop serves meanwhile. */
static case_result_t test_multiloop_retention(sweep_cell_t const& cell) {
    if (UCALL_OS_WINDOWS_) return case_result_t::skipped(loops_refused_k);
    fixture_t fixture {cell, {.event_loops = 2, .connections = 2}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
        return {};
    ucall_outcome_t outcome {};
    auto gate_url = fmt::format("{}/gate", fixture.url), echo_url = fmt::format("{}/echo/42", fixture.url);
    ucall_client_call_t call {};
    call.client = fixture.client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(gate_url);
    call.verb = ucall_verb_post_k;
    call.context = &gate_url;
    ucall_client_call(&call);
    expect_true(outcome.status == ucall_status_success_k);
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
    ucall_received_http_request_t held {};
    while (!(held = fixture.take_held())) {
        ucall_completed_call_t completed {};
        expect_true(!fixture.poll(completed));
        if (!expect_true(steady_clock::now() < deadline, "the gated request never arrived")) return {};
    }
    call.url = uc::bytes_view(echo_url);
    call.context = &echo_url;
    ucall_client_call(&call);
    expect_true(outcome.status == ucall_status_success_k);
    auto completed = fixture.wait();
    expect_true(completed.context == &echo_url && completed.outcome.status == ucall_status_success_k);
    if (completed.response) check_response(completed.response, {});
    fixture.reply_echo(held);
    completed = fixture.wait();
    expect_true(completed.context == &gate_url && completed.outcome.status == ucall_status_success_k);
    if (completed.response) check_response(completed.response, {});
    fixture.stop();
    return {};
}

/** Application threads reply to retained requests while the test thread polls the loop. */
static void test_cross_thread_replies(sweep_cell_t const& cell) {
    std::size_t const failed_before = test_run.failed_checks.load();
    constexpr std::size_t threads_count = 4;
    fixture_t fixture {cell, {.connections = threads_count}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    std::atomic<bool> finished {false};
    std::vector<std::thread> repliers;
    for (std::size_t i = 0; i != threads_count; ++i)
        repliers.emplace_back([&] {
            while (!finished.load(std::memory_order_acquire))
                if (auto request = fixture.take_held()) fixture.reply_echo(request);
                else std::this_thread::yield();
        });
    std::string const gate_url = fmt::format("{}/gate", fixture.url);
    std::array<std::string, threads_count> bodies;
    std::size_t const rounds = scaled_iterations(64);
    for (std::size_t round = 0; round != rounds && test_run.failed_checks.load() == failed_before; ++round) {
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
            expect_true(outcome.status == ucall_status_success_k);
        }
        for (std::size_t i = 0; i != threads_count; ++i) {
            auto completed = fixture.wait();
            expect_true(completed.outcome.status == ucall_status_success_k && completed.response, "round {}: {}", round,
                        ucall_status_name(completed.outcome.status));
            if (!completed.response) break;
            check_response(completed.response, *static_cast<std::string*>(completed.context));
        }
    }
    finished.store(true, std::memory_order_release);
    for (auto& replier : repliers) replier.join();
    fixture.stop();
}

/** Eight idempotent calls at depth four share one connection: the server holds four at once, which
 *  lockstep calls never reach, and replies given in reverse still complete in call order. */
static void test_pipelined_calls(sweep_cell_t const& cell) {
    std::size_t const failed_before = test_run.failed_checks.load();
    fixture_t fixture {cell, {.pipelined_requests = 4, .pipelined_calls = 4}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    if (!expect_true(fixture.resolved_client.max_pipelined_calls == 4)) return;
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
        call.options.security = cell.security;
        call.options.noise_peer_key = &fixture.server_public;
        ucall_client_call(&call);
        expect_true(outcome.status == ucall_status_success_k);
    }
    for (std::size_t next = 0; next != bodies.size() && test_run.failed_checks.load() == failed_before;) {
        await_held(fixture, 4);
        while (auto request = fixture.take_held()) fixture.reply_echo(request);
        for (auto const end = next + 4; next != end && test_run.failed_checks.load() == failed_before; ++next) {
            auto completed = fixture.wait();
            expect_true(completed.context == &bodies[next] && completed.response, "call {} completed {}: {}", next,
                        static_cast<std::string const*>(completed.context) - bodies.data(),
                        ucall_status_name(completed.outcome.status));
            if (completed.response) check_response(completed.response, bodies[next]);
        }
    }
    fixture.stop();
}

/** Calls made at once open only the connections their depth needs: 64 at a depth of 16 open four
 *  of eight, and 16 at a depth of one open all eight. */
static void test_client_dials_for_depth(sweep_cell_t const& cell) {
    std::size_t const failed_before = test_run.failed_checks.load();
    struct point_t {
        std::size_t depth, calls, connections;
    };
    for (auto [depth, calls, connections] : {point_t {16, 64, 4}, point_t {1, 16, 8}}) {
        fixture_t fixture {cell, {.connections = 8, .pipelined_requests = depth, .pipelined_calls = depth}};
        if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
            return;
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
            expect_true(outcome.status == ucall_status_success_k);
        }
        for (std::size_t i = 0; i != bodies.size() && test_run.failed_checks.load() == failed_before; ++i) {
            auto completed = fixture.wait();
            expect_true(completed.response, "depth {}: {}", depth, ucall_status_name(completed.outcome.status));
            if (completed.response) check_response(completed.response, *static_cast<std::string*>(completed.context));
        }
        ucall_outcome_t outcome {};
        ucall_event_loop_statistics_t counters {};
        ucall_server_event_loop_statistics_t query {fixture.server, &outcome, 0, &counters};
        ucall_server_event_loop_statistics(&query);
        expect_true(counters.accepts == connections, "depth {} opened {} connections", depth, counters.accepts);
        fixture.stop();
    }
}

/** A caller's <tt>Connection: close</tt> on the second call keeps the POST and GET behind it
 *  off that connection: both wait for the next one and are answered there. */
static void test_pipelined_call_loss(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {.pipelined_requests = 4, .pipelined_calls = 4}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
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
        expect_true(outcome.status == ucall_status_success_k);
    }
    await_held(fixture, 2);
    // Neither call behind the closing one leaves before its response.
    for (steady_clock::time_point const settled = steady_clock::now() + 100ms; steady_clock::now() < settled;) {
        ucall_completed_call_t completed {};
        expect_true(!fixture.poll(completed), "a call completed early");
    }
    while (auto request = fixture.take_held()) fixture.reply_echo(request);
    for (auto const& planned : plan) {
        auto completed = fixture.wait();
        expect_true(completed.context == &planned && completed.outcome.status == planned.expected,
                    "call {} completed {}: {}", &planned - plan.data(),
                    static_cast<planned_call_t const*>(completed.context) - plan.data(),
                    ucall_status_name(completed.outcome.status));
        if (completed.response) check_response(completed.response, {});
    }
    expect_true(fixture.dispatched.load() == 2, "{} echo requests were dispatched", fixture.dispatched.load());
    fixture.stop();
}

/** 204 and 304 replies, which UCall sends without <tt>content-length</tt>, keep the connection:
 *  calls pipelined ahead of and behind them all complete over the one connection accepted. */
static void test_bodiless_responses_keep_connection(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {.pipelined_requests = 4, .pipelined_calls = 4}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
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
        expect_true(outcome.status == ucall_status_success_k);
    }
    for (auto const& planned : plan) {
        auto completed = fixture.wait();
        expect_true(completed.context == &planned && completed.response &&
                        ucall_client_response_status(completed.response) == planned.expected,
                    "call {} completed {}: {}", &planned - plan.data(),
                    static_cast<planned_status_t const*>(completed.context) - plan.data(),
                    ucall_status_name(completed.outcome.status));
        if (completed.response) ucall_client_response_free(completed.response);
    }
    ucall_event_loop_statistics_t counters {};
    ucall_server_event_loop_statistics_t query {fixture.server, &outcome, 0, &counters};
    ucall_server_event_loop_statistics(&query);
    expect_true(counters.accepts == 1, "the server accepted {} connections", counters.accepts);
    fixture.stop();
}

/** The body @c stream_reply sends as @p count chunks of growing, labelled sizes. */
static std::vector<std::string> stream_chunks(std::size_t count, char label) {
    std::vector<std::string> chunks;
    for (std::size_t i = 0; i != count; ++i)
        chunks.push_back(fmt::format("{}{}:{}", label, i, std::string(i * 37, label)));
    return chunks;
}

/** Streams @p chunks to @p request from the calling thread, retrying a chunk the socket lags
 *  behind, and expects @p ended from the end. */
static void stream_reply(ucall_server_t server, ucall_received_http_request_t request,
                         std::vector<std::string> const& chunks, std::vector<ucall_bytes_view_t> headers = {},
                         ucall_status_t ended = ucall_status_success_k) {
    ucall_outcome_t outcome {};
    ucall_server_reply_begin_t begin {server, &outcome, request, 0, headers.data(), headers.size()};
    ucall_server_reply_begin(&begin);
    expect_true(outcome.status == ucall_status_success_k, "begin: {}", ucall_status_name(outcome.status));
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
    for (auto const& chunk : chunks) {
        ucall_reply_part_t const part = bytes_part(chunk);
        ucall_server_reply_append_t append {server, &outcome, request, &part, 1};
        append_when_room(append, deadline);
        expect_true(outcome.status == ucall_status_success_k, "chunk: {}", ucall_status_name(outcome.status));
    }
    ucall_server_reply_end_t end {server, &outcome, request};
    ucall_server_reply_end(&end);
    expect_true(outcome.status == ended, "end: {}", ucall_status_name(outcome.status));
}
static std::string joined(std::vector<std::string> const& chunks) {
    std::string whole;
    for (auto const& chunk : chunks) whole += chunk;
    return whole;
}

/** Five parts, two of them empty, arrive concatenated under the status and headers given, and a
 *  @c HEAD request gets the same head without a body. */
static void test_reply_vectored(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    std::string const expected = fmt::format("first|{}|last", std::string(100 * 1024, 'v'));
    auto completed = call_and_wait(fixture, ucall_verb_get_k, "/vectored", cell.security);
    if (completed.response) {
        expect_true(response_header(completed.response, "x-ucall") == "passed");
        expect_true(response_header(completed.response, "content-type") == "application/octet-stream");
    }
    check_answer(completed, ucall_http_status_created_k, expected);
    completed = call_and_wait(fixture, ucall_verb_head_k, "/vectored", cell.security);
    if (completed.response)
        expect_true(response_header(completed.response, "content-length") == fmt::format("{}", expected.size()));
    check_answer(completed, ucall_http_status_created_k, {});
    fixture.stop();
}

/** An application thread streams a reply of many chunks long after the callback returned, while
 *  this thread polls, and the client reads the chunked body whole. */
static void test_streamed_reply(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    std::string const url = fmt::format("{}/gate", fixture.url);
    ucall_outcome_t outcome {};
    ucall_client_call_t call {};
    call.client = fixture.client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(url);
    call.verb = ucall_verb_get_k;
    call.options.security = cell.security;
    call.options.noise_peer_key = &fixture.server_public;
    ucall_client_call(&call);
    await_held(fixture, 1);
    auto const chunks = stream_chunks(300, 's');
    std::thread streamer {[&, request = fixture.take_held()] { stream_reply(fixture.server, request, chunks); }};
    auto completed = fixture.wait();
    streamer.join();
    if (completed.response) expect_true(response_header(completed.response, "transfer-encoding") == "chunked");
    check_answer(completed, ucall_http_status_ok_k, joined(chunks));
    fixture.stop();
}

/** Two threads stream to two requests pipelined on one connection at once, the second thread
 *  starting first, and both replies arrive whole and in request order. */
static void test_pipelined_streams(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {.pipelined_requests = 2, .pipelined_calls = 2}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
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
        call.options.security = cell.security;
        call.options.noise_peer_key = &fixture.server_public;
        ucall_client_call(&call);
        expect_true(outcome.status == ucall_status_success_k);
    }
    await_held(fixture, 2);
    std::array<ucall_received_http_request_t, 2> requests {};
    while (auto request = fixture.take_held()) requests[fixture.query_number(request, "n")] = request;
    std::thread later {[&] { stream_reply(fixture.server, requests[1], chunks[1]); }};
    std::thread earlier {[&] { stream_reply(fixture.server, requests[0], chunks[0]); }};
    for (std::size_t i = 0; i != 2; ++i) {
        auto completed = fixture.wait();
        expect_true(completed.context == &urls[i], "call {} completed out of order", i);
        check_answer(completed, ucall_http_status_ok_k, joined(chunks[i]));
    }
    later.join();
    earlier.join();
    ucall_outcome_t outcome {};
    ucall_event_loop_statistics_t counters {};
    ucall_server_event_loop_statistics_t query {fixture.server, &outcome, 0, &counters};
    ucall_server_event_loop_statistics(&query);
    expect_true(counters.accepts == 1, "the server accepted {} connections", counters.accepts);
    fixture.stop();
}

/** @c HEAD on a vectored and two streamed replies answers each head with no body, and the @c GET
 *  behind each on the same connection still parses. */
static void test_head_replies(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    auto security = ucall_security_none_k;
    auto completed = call_and_wait(fixture, ucall_verb_head_k, "/vectored", security);
    if (completed.response)
        expect_true(!response_header(completed.response, "content-length").empty(), "no content-length");
    check_answer(completed, ucall_http_status_created_k, {});
    completed = call_and_wait(fixture, ucall_verb_get_k, "/echo/1", security);
    check_answer(completed, ucall_http_status_ok_k, {});
    std::string const url = fmt::format("{}/gate", fixture.url);
    auto const chunks = stream_chunks(20, 'h');
    std::string const length = fmt::format("Content-Length: {}", joined(chunks).size());
    for (std::vector<ucall_bytes_view_t> headers :
         {std::vector<ucall_bytes_view_t> {}, std::vector<ucall_bytes_view_t> {uc::bytes_view(length)}}) {
        ucall_outcome_t outcome {};
        ucall_client_call_t call {};
        call.client = fixture.client;
        call.outcome = &outcome;
        call.url = uc::bytes_view(url);
        call.verb = ucall_verb_head_k;
        ucall_client_call(&call);
        await_held(fixture, 1);
        stream_reply(fixture.server, fixture.take_held(), chunks, headers);
        completed = fixture.wait();
        check_answer(completed, ucall_http_status_ok_k, {});
        completed = call_and_wait(fixture, ucall_verb_get_k, "/echo/1", security);
        check_answer(completed, ucall_http_status_ok_k, {});
    }
    ucall_outcome_t outcome {};
    ucall_event_loop_statistics_t counters {};
    ucall_server_event_loop_statistics_t query {fixture.server, &outcome, 0, &counters};
    ucall_server_event_loop_statistics(&query);
    expect_true(counters.accepts == 1, "the server accepted {} connections", counters.accepts);
    fixture.stop();
}

/** A listener the caller hands over is served by an engine accepting from any listener: an
 *  automatic server passes over Registered I/O, and one naming it is refused, saying why. */
static void test_borrowed_listener_backend(sweep_cell_t const& cell) {
    uc::utilities::descriptor_t const listener = uc::utilities::socket_open(AF_INET);
    sockaddr_in bound {};
    bound.sin_family = AF_INET;
    bound.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (!expect_true(listener >= 0 && ::bind(listener, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) == 0 &&
                         ::listen(listener, 4) == 0,
                     "no TCP listener"))
        return;
    std::intptr_t const handed = listener;
    ucall_network_interface_t network_interface {};
    network_interface.listen_descriptor = &handed;
    network_interface.max_concurrent_connections = 1;
    ucall_server_options_t config {};
    config.interfaces = &network_interface;
    config.interfaces_count = 1;
    config.backend = cell.backend;
    config.cpu_class_ceiling = cell.cpu_class_ceiling;
    ucall_server_t server {};
    ucall_server_options_t resolved {};
    ucall_outcome_t outcome {};
    ucall_server_init_t init {&server, &outcome, &config, &resolved};
    ucall_server_init(&init);
    if (cell.backend == ucall_io_backend_windows_rio_k)
        expect_true(outcome.status == ucall_status_unsupported_k && outcome.message &&
                        std::string_view {outcome.message}.find("listen_descriptor") != std::string_view::npos,
                    "Registered I/O over a borrowed listener: {}", ucall_status_name(outcome.status));
    else
        expect_true(outcome.status == ucall_status_success_k && resolved.backend != ucall_io_backend_windows_rio_k,
                    "a borrowed listener: {} on {}", ucall_status_name(outcome.status),
                    ucall_io_backend_name(resolved.backend));
    ucall_server_free(server);
    uc::utilities::socket_close(listener);
}

#pragma endregion Library Clients

#pragma region Raw Clients
#if UCALL_OS_POSIX_

/** Three requests arriving in one segment, the second closing, come back as two responses in
 *  order, then the close, even when the server may read four ahead. */
static void test_pipelined_delivery(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {.pipelined_requests = 4}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return;
    std::string_view const burst = "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nfirst" //
                                   "POST /echo/2 HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\n"          //
                                   "Connection: close\r\n\r\nsecond"                                    //
                                   "POST /echo/3 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nthird";
    // One send, so the server has read the third request before it closes,
    // and the close is no reset.
    expect_true(::send(client.descriptor, burst.data(), burst.size(), 0) == static_cast<ssize_t>(burst.size()));
    auto const end = client.read_until_close(steady_clock::now() + wait_limit_k);
    expect_true(end == read_end_t::closed_k, "the read ended as {}", static_cast<int>(end));
    auto const first = parse_response(client.received);
    auto const second = parse_response(std::string_view {client.received}.substr(first.length));
    expect_true(first.status == 200 && first.body == "first", "first answered {} {}", first.status, first.body);
    expect_true(second.status == 200 && second.body == "second", "second answered {} {}", second.status, second.body);
    expect_true(first.length + second.length == client.received.size());
    expect_true(fixture.dispatched.load() == 2, "{} requests were dispatched", fixture.dispatched.load());
    fixture.stop();
}

/** Headers, and a chunked body with its trailers, written one byte per segment still parse. */
static void test_fragmented_headers_delivery(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    for (std::string_view const request :
         {"POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody",
          "POST /echo/1 HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" //
          "2;x=1\r\nbo\r\n2\r\ndy\r\n0\r\nX-Trailer: done\r\nX-Other: too\r\n\r\n"}) {
        raw_client_t client;
        if (!expect_true(client.connect(fixture.address))) return;
        auto const response = exchange_until_close(client, request, 1, generator);
        expect_true(response.status == 200 && response.body == "body", "answered {} {}", response.status,
                    response.body);
    }
    fixture.stop();
}

/** A mebibyte body sent in random fragments echoes back byte for byte, in full-length sends. */
static void test_megabyte_echo_delivery(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {.max_request_bytes = std::size_t {2} << 20}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    std::size_t const body_length = std::size_t {1} << 20;
    std::string request = fmt::format(
        "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body_length);
    std::size_t const headers_length = request.size();
    for (std::size_t i = 0; i != body_length; ++i) request.push_back(static_cast<char>(generator()));
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return;
    auto const response = exchange_until_close(client, request, 65536, generator);
    expect_true(response.status == 200, "answered {}", response.status);
    expect_equal_bytes(uc::byte_span(response.body), uc::byte_span(std::string_view {request}.substr(headers_length)));
    fixture.stop();
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
static void test_smuggling(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    // Past what any engine reads ahead, so a server closing without lingering leaves bytes unread.
    std::string const unread(std::size_t {64} << 10, 'x');
    for (auto const& row : smuggling_rows_k) {
        auto const dispatched = fixture.dispatched.load();
        raw_client_t client;
        if (!expect_true(client.connect(fixture.address))) return;
        expect_true(client.write(uc::byte_span(row.request), 0, generator, steady_clock::now() + wait_limit_k),
                    "{} was cut short", row.name);
        auto const response = exchange_until_close(client, unread, 4096, generator);
        expect_true(response.status == row.expected_status && response.length == client.received.size(),
                    "{} answered {} bytes: {:?}", row.name, client.received.size(), client.received);
        expect_true(fixture.dispatched.load() == dispatched, "{} was dispatched", row.name);
    }
    fixture.stop();
}

/** A CRLF ahead of a request, as clients that end a body with one leave, is skipped rather than
 *  refused, both before the first request and between two. */
static void test_leading_empty_line_ignored(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return;
    std::string_view const requests = "\r\nPOST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi\r\n" //
                                      "GET /echo/2 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    auto const first = exchange_until_close(client, requests, 4, generator);
    auto const second = parse_response(std::string_view {client.received}.substr(first.length));
    expect_true(first.status == 200 && first.body == "hi", "first answered {} {}", first.status, first.body);
    expect_true(second.status == 200 && second.length == client.received.size() - first.length, "second answered {}",
                second.status);
    fixture.stop();
}

/** Whitespace between a chunk size and its extension, which RFC 9112 7.1.1 allows, still frames. */
static void test_chunk_extension_whitespace(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return;
    auto const response = exchange_until_close(
        client,
        "POST /echo/1 HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" //
        "2 ;a=1\r\nbo\r\n2\t ;b\r\ndy\r\n0\r\n\r\n",
        8, generator);
    expect_true(response.status == 200 && response.body == "body", "answered {} {}", response.status, response.body);
    fixture.stop();
}

/** A verb its path does not take answers 405 listing the ones it does, HEAD falls back to GET,
 *  OPTIONS answers 204 with the same list, an absolute-form target routes by its path, and
 *  <tt>OPTIONS *</tt> lists every verb. */
static void test_method_routing(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return;
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
        expect_true(client.write(uc::byte_span(row.request), 0, generator, steady_clock::now() + wait_limit_k));
        auto const response = read_response(client, offset);
        std::string_view const head = std::string_view {client.received}.substr(offset, response.length);
        expect_true(response.status == row.status && head.find(row.header) != std::string_view::npos &&
                        response.body.empty() == (row.status < 300),
                    "{:?} answered {:?}", row.request, head);
    }
    fixture.stop();
}

/** A reply naming its own @c connection field is refused, since the loop writes the one that
 *  decides whether the connection stays, and the same reply without it goes out. */
static void test_reply_connection_header_refused(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return;
    std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
    expect_true(::send(client.descriptor, request.data(), request.size(), 0) == static_cast<ssize_t>(request.size()));
    await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    if (!expect_true(held)) return;
    ucall_outcome_t outcome {};
    ucall_bytes_view_t const header = uc::bytes_view("Connection: close");
    ucall_server_reply_content_t refused {fixture.server,     &outcome, held, ucall_http_status_ok_k, &header, 1,
                                          uc::bytes_view("x")};
    ucall_server_reply_content(&refused);
    expect_true(outcome.status == ucall_status_invalid_argument_k, "a reply's connection field answered {}",
                ucall_status_name(outcome.status));
    ucall_server_reply_content_t reply {fixture.server,     &outcome, held, ucall_http_status_ok_k, nullptr, 0,
                                        uc::bytes_view("x")};
    ucall_server_reply_content(&reply);
    expect_true(outcome.status == ucall_status_success_k, "reply: {}", ucall_status_name(outcome.status));
    auto const response = read_response(client, 0);
    expect_true(response.status == 200 && response.body == "x", "answered {} {}", response.status, response.body);
    fixture.stop();
}

/** Paths keep their slashes and drop the query, and header names match without regard to letter
 *  case, where only letters fold. */
static void test_header_lookup(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return;
    std::string_view const request = "GET /headers?x=1 HTTP/1.1\r\nHost: a\r\nContent-Type: text/plain\r\n" //
                                     "X-~: tilde\r\nConnection: close\r\n\r\n";
    auto const response = exchange_until_close(client, request, 8, generator);
    // `^` and `~` differ only in the bit that folds ASCII letters.
    expect_true(response.body == "/headers;text/plain;tilde;not-found;not-found;", "answered {} {}", response.status,
                response.body);
    fixture.stop();
}

/** Holds one request @p wire sends to the gate route, runs @p inspect on it, and answers it. */
template <typename inspect_type_>
static void held_request(sweep_cell_t const& cell, std::string_view wire, inspect_type_&& inspect) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return;
    expect_true(::send(client.descriptor, wire.data(), wire.size(), 0) == static_cast<ssize_t>(wire.size()));
    await_held_in_background(fixture, 1);
    auto* request = fixture.take_held();
    if (!expect_true(request)) return;
    inspect(fixture.server, request);
    ucall_outcome_t outcome {};
    ucall_server_reply_content_t reply {fixture.server,      &outcome, request, ucall_http_status_ok_k, nullptr, 0,
                                        uc::bytes_view("ok")};
    ucall_server_reply_content(&reply);
    expect_true(read_response(client, 0).body == "ok");
    fixture.stop();
}

/** Field lines read back by index in arrival order, repeated names apart, names lowercased as the
 *  parser keeps them and values trimmed, and an index past the last one is not found. */
static void test_request_fields_in_order(sweep_cell_t const& cell) {
    std::string_view const wire = "GET /gate HTTP/1.1\r\nHost: a\r\nX-B:  two \r\nx-a:one\r\nX-B: again\r\n\r\n";
    held_request(cell, wire, [](ucall_server_t server, ucall_received_http_request_t request) {
        std::size_t count = 0;
        ucall_outcome_t outcome {};
        ucall_server_request_fields_count_t counting {server, &outcome, request, &count};
        ucall_server_request_fields_count(&counting);
        expect_true(outcome.status == ucall_status_success_k && count == 4, "{} fields", count);
        std::string read;
        for (std::size_t index = 0; index <= count; ++index) {
            ucall_bytes_view_t name {}, value {};
            ucall_server_request_field_t field {server, &outcome, request, index, &name, &value};
            ucall_server_request_field(&field);
            if (outcome.status != ucall_status_success_k) {
                expect_true(index == count && outcome.status == ucall_status_not_found_k, "field {}: {}", index,
                            ucall_status_name(outcome.status));
                break;
            }
            read += fmt::format("{}={};", uc::text_view(name), uc::text_view(value));
        }
        expect_true(read == "host=a;x-b=two;x-a=one;x-b=again;", "read {}", read);
        return;
    });
}

/** The raw query after the first @c ?, still percent-encoded, or empty for a target without one. */
static void test_request_query(sweep_cell_t const& cell) {
    auto query_is = [](std::string_view expected) {
        return [expected](ucall_server_t server, ucall_received_http_request_t request) {
            ucall_outcome_t outcome {};
            ucall_bytes_view_t query {};
            ucall_server_request_query_t get {server, &outcome, request, &query};
            ucall_server_request_query(&get);
            return expect_true(outcome.status == ucall_status_success_k && uc::text_view(query) == expected, "{}: {:?}",
                               ucall_status_name(outcome.status), uc::text_view(query));
        };
    };
    held_request(cell, "GET /gate?b=2&a=%20&b=?x HTTP/1.1\r\nHost: a\r\n\r\n", query_is("b=2&a=%20&b=?x"));
    held_request(cell, "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n", query_is(""));
}

/** Frees a server from a thread other than its poller while a keep-alive peer stays connected.
 *  An engine stopped off its poller hangs there, or leaks its ring storage under LeakSanitizer. */
static void test_cross_thread_teardown_delivery(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return;
    std::string_view const request = "GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n";
    expect_true(client.write(uc::byte_span(request), 0, generator, steady_clock::now() + wait_limit_k));
    expect_true(read_response(client, 0).status == 200, "the keep-alive request was not served");
    fixture.stop();
    // A hang here is the failure, so a stuck free ends the process instead of the case.
    std::promise<void> freed;
    auto finished = freed.get_future();
    std::thread {[&freed, server = std::exchange(fixture.server, nullptr)] {
        ucall_server_free(server);
        freed.set_value();
    }}.detach();
    if (finished.wait_for(wait_limit_k) != std::future_status::ready) {
        std::fputs("ucall_server_free blocked on a ring its poller had issued\n", stderr);
        std::quick_exit(EXIT_FAILURE);
    }
}

/** A burst of small pipelined requests written at once is answered whole and in order at any
 *  depth, as the server parses on from where it stopped rather than moving the rest each time. */
static void test_pipelined_burst(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    for (std::size_t depth : {std::size_t {1}, std::size_t {4}}) {
        fixture_t fixture {cell, {.pipelined_requests = depth}};
        if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
            return;
        fixture.serve_in_background();
        std::size_t const count = 3000;
        std::string burst;
        for (std::size_t i = 0; i != count; ++i)
            burst += fmt::format("POST /echo/{} HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n{}", i,
                                 fmt::formatted_size("{}", i), i);
        raw_client_t client;
        if (!expect_true(client.connect(fixture.address))) return;
        // The writer must not wait on replies the reader has not taken yet.
        bool written = false;
        std::thread writer {[&] {
            split_mix_generator_t chunks {generator};
            written = client.write(uc::byte_span(burst), burst.size(), chunks, steady_clock::now() + wait_limit_k);
        }};
        std::size_t offset = 0, answered = 0;
        for (; answered != count; ++answered) {
            auto const response = read_response(client, offset);
            if (response.status != 200 || response.body != fmt::format("{}", answered)) break;
            offset += response.length;
        }
        writer.join();
        expect_true(written, "the burst was not written");
        expect_true(answered == count, "{} of {} pipelined requests were answered in order", answered, count);
        fixture.stop();
    }
}

/** A request whose peer left lives until answered, so once a loop holds as many of those as it
 *  holds exchanges, new requests answer 503 until one is answered. */
static void test_orphaned_exchanges_bounded(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    // A second request slot keeps a receive armed behind the held one, so peers leaving are seen.
    fixture_t fixture {cell, {.pipelined_requests = 2}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    for (std::size_t left = 0; left != 2; ++left) {
        raw_client_t leaving;
        if (!expect_true(leaving.connect(fixture.address))) return;
        std::string_view const gate = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
        expect_true(leaving.write(uc::byte_span(gate), 0, generator, steady_clock::now() + wait_limit_k));
        await_held_in_background(fixture, left + 1);
        // A reset rather than a FIN, which the server would answer on the half-closed connection.
        linger const abrupt {1, 0};
        expect_true(::setsockopt(leaving.descriptor, SOL_SOCKET, SO_LINGER, &abrupt, sizeof(abrupt)) == 0);
    }
    raw_client_t next;
    if (!expect_true(next.connect(fixture.address))) return;
    std::string_view const echo = "GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n";
    expect_true(next.write(uc::byte_span(echo), 0, generator, steady_clock::now() + wait_limit_k));
    auto const refused = read_response(next, 0);
    expect_true(refused.status == 503, "a request past the abandoned budget answered {}", refused.status);
    ucall_outcome_t outcome {};
    ucall_server_reply_content_t reply {fixture.server, &outcome, fixture.take_held(),   ucall_http_status_ok_k,
                                        nullptr,        0,        uc::bytes_view("late")};
    ucall_server_reply_content(&reply);
    expect_true(outcome.status == ucall_status_success_k || outcome.status == ucall_status_connection_closed_k,
                "the abandoned reply answered {}", ucall_status_name(outcome.status));
    expect_true(next.write(uc::byte_span(echo), 0, generator, steady_clock::now() + wait_limit_k));
    auto const served = read_response(next, refused.length);
    expect_true(served.status == 200, "a request after the abandoned one was answered got {}", served.status);
    reply.request = fixture.take_held();
    ucall_server_reply_content(&reply);
    fixture.stop();
}

/** A peer reaching an IPv6 listener is reported by the address and port its own socket names. */
static case_result_t test_request_peer_ipv6(sweep_cell_t const& cell) {
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
    config.backend = cell.backend;
    config.cpu_class_ceiling = cell.cpu_class_ceiling;
    ucall_outcome_t outcome {};
    ucall_server_init_t init {&captured.server, &outcome, &config, &resolved};
    ucall_server_init(&init);
    if (outcome.status == ucall_status_connection_failed_k) return case_result_t::skipped(ipv6_refused_k);
    if (!expect_true(outcome.status == ucall_status_success_k, "setup: {}", ucall_status_name(outcome.status)))
        return {};
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
    expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
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
    expect_true(::connect(client.descriptor, reinterpret_cast<sockaddr const*>(&target), sizeof(target)) == 0,
                "no connection to {}: {}", bound, errno);
    sockaddr_in6 own {};
    socklen_t own_length = sizeof(own);
    expect_true(::getsockname(client.descriptor, reinterpret_cast<sockaddr*>(&own), &own_length) == 0);
    std::string_view const request = "GET /peer HTTP/1.1\r\nHost: a\r\n\r\n";
    expect_true(::send(client.descriptor, request.data(), request.size(), 0) == static_cast<ssize_t>(request.size()));
    expect_true(read_response(client, 0).body == "seen", "the request was not answered");
    ucall_server_stop(captured.server);
    poller.join();
    expect_true(captured.address.family == ucall_address_family_ipv6_k &&
                    std::memcmp(captured.address.bytes, &own.sin6_addr, 16) == 0 &&
                    captured.address.port == ntohs(own.sin6_port),
                "reported family {} port {} for port {}", captured.address.family, captured.address.port,
                ntohs(own.sin6_port));
    ucall_server_free(captured.server);
    return {};
}

/** A listener the caller hands over is accepted on through duplicates: a TCP one echoes on two
 *  loops and keeps accepting after the server is freed, and an AF_UNIX one echoes 64 KiB, reports
 *  its path as the bound address, and reports its peers as AF_UNIX. */
static void test_interface_listen_descriptor(sweep_cell_t const& cell, split_mix_generator_t& generator) {
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
        config.backend = cell.backend;
        config.cpu_class_ceiling = cell.cpu_class_ceiling;
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
    auto exchange = [&](raw_client_t& client, std::string_view body) {
        std::string const request = fmt::format("POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n{}",
                                                body.size(), body);
        std::size_t const offset = client.received.size();
        expect_true(client.write(uc::byte_span(request), 65536, generator, steady_clock::now() + wait_limit_k));
        auto const response = read_response(client, offset);
        expect_true(response.status == 200 && response.body == body, "echoed {} with {} of {} bytes", response.status,
                    response.body.size(), body.size());
    };
    {
        int const listener = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in bound {};
        bound.sin_family = AF_INET;
        bound.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t length = sizeof(bound);
        if (!expect_true(listener >= 0 && ::bind(listener, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) == 0 &&
                             ::getsockname(listener, reinterpret_cast<sockaddr*>(&bound), &length) == 0 &&
                             ::listen(listener, 16) == 0,
                         "no TCP listener"))
            return;
        std::string const address = fmt::format("127.0.0.1:{}", ntohs(bound.sin_port));
        served_t served;
        ucall_status_t const started = serve(served, listener, UCALL_OS_WINDOWS_ ? 1 : 2);
        expect_true(started == ucall_status_success_k, "a handed TCP listener: {}", ucall_status_name(started));
        if (started == ucall_status_success_k) {
            expect_true(uc::text_view(served.resolved.interfaces[0].address) == address, "reported {}",
                        uc::text_view(served.resolved.interfaces[0].address));
            raw_client_t clients[3];
            for (auto& client : clients) {
                expect_true(client.connect(address), "no connection to {}", address);
                if (client.descriptor >= 0) exchange(client, "over tcp");
            }
            expect_true(served.family.load() == ucall_address_family_ipv4_k);
        }
        finish(served);
        raw_client_t after;
        expect_true(::fcntl(listener, F_GETFD) != -1 && after.connect(address),
                    "the caller's listener closed with the server");
        ::close(listener);
    }
    {
        scratch_directory_t directory;
        std::string const path = directory.name("listen.sock");
        int const listener = ::socket(AF_UNIX, SOCK_STREAM, 0);
        sockaddr_un bound {};
        bound.sun_family = AF_UNIX;
        std::memcpy(bound.sun_path, path.c_str(), fu::min_of(path.size() + 1, sizeof(bound.sun_path) - 1));
        if (!expect_true(listener >= 0 && path.size() < sizeof(bound.sun_path) &&
                             ::bind(listener, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) == 0 &&
                             ::listen(listener, 16) == 0,
                         "no AF_UNIX listener at {}", path))
            return;
        served_t served;
        ucall_status_t const started = serve(served, listener, 1);
        expect_true(started == ucall_status_success_k, "a handed AF_UNIX listener: {}", ucall_status_name(started));
        if (started == ucall_status_success_k) {
            expect_true(uc::text_view(served.resolved.interfaces[0].address) == path, "reported {}",
                        uc::text_view(served.resolved.interfaces[0].address));
            raw_client_t client;
            client.descriptor = ::socket(AF_UNIX, SOCK_STREAM, 0);
            expect_true(::connect(client.descriptor, reinterpret_cast<sockaddr*>(&bound), sizeof(bound)) == 0,
                        "no connection to {}: {}", path, errno);
            std::string const body(64 * 1024, 'u');
            exchange(client, body);
            expect_true(served.family.load() == ucall_address_family_unix_k, "reported family {}",
                        served.family.load());
        }
        finish(served);
        ::close(listener);
    }
}

/** A drain closes the listener at once: a peer connecting after one stop is refused or reset rather
 *  than parked in a backlog nobody accepts, while the held reply still arrives. */
static void test_drain_closes_listener(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {.connections = 2}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    raw_client_t busy;
    if (!expect_true(busy.connect(fixture.address))) return;
    std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
    expect_true(::send(busy.descriptor, request.data(), request.size(), 0) == static_cast<ssize_t>(request.size()));
    await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    if (!expect_true(held)) return;
    ucall_server_stop(fixture.server);
    // A connect racing the loop's next round lands in the backlog, which the close then resets.
    std::this_thread::sleep_for(50ms);
    raw_client_t late;
    if (late.connect(fixture.address)) {
        std::string_view const probe = "GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n";
        [[maybe_unused]] bool const written = late.write(uc::byte_span(probe), 0, generator, steady_clock::now() + 1s);
        auto const end = late.read(1, steady_clock::now() + 1s);
        expect_true(end == read_end_t::failed_k || end == read_end_t::closed_k,
                    "a peer connecting after the stop waited as {}", static_cast<int>(end));
    }
    ucall_outcome_t outcome {};
    ucall_server_reply_content_t reply {fixture.server,           &outcome, held, ucall_http_status_ok_k, nullptr, 0,
                                        uc::bytes_view("drained")};
    ucall_server_reply_content(&reply);
    expect_true(outcome.status == ucall_status_success_k, "reply: {}", ucall_status_name(outcome.status));
    auto const response = read_response(busy, 0);
    expect_true(response.status == 200 && response.body == "drained", "answered {} {}", response.status, response.body);
    fixture.stop();
}

/** The log sink receives a line when the server starts serving and one per refusal, in either
 *  format, from whichever loop wrote it. */
static void test_log_lines(sweep_cell_t const& cell) {
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
        fixture_t fixture {cell, {.log = {collect, &collected, format, ucall_log_level_info_k}}};
        if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
            return;
        fixture.serve_in_background();
        raw_client_t client;
        if (!expect_true(client.connect(fixture.address))) return;
        std::string_view const request = "GET /missing HTTP/1.1\r\nHost: a\r\n\r\n";
        expect_true(::send(client.descriptor, request.data(), request.size(), 0) ==
                    static_cast<ssize_t>(request.size()));
        auto const deadline = steady_clock::now() + wait_limit_k;
        while (client.received.find("Not found") == std::string::npos &&
               client.read(client.received.size() + 1, deadline) == read_end_t::filled_k) {}
        fixture.stop();
        bool const json = format == ucall_log_format_json_k;
        std::string const serving = json ? R"({"level":"info","event":"serving","address":")" : "info serving address=";
        std::string const refused = json ? R"({"level":"info","event":"refused","status":"404",)"
                                         : "info refused status=404 ";
        std::lock_guard lock {collected.mutex};
        auto starting = [&](std::string const& prefix) {
            return std::any_of(collected.lines.begin(), collected.lines.end(),
                               [&](std::string const& line) { return line.starts_with(prefix); });
        };
        expect_true(starting(serving) && starting(refused), "format {} wrote {} lines, first: {}",
                    static_cast<int>(format), collected.lines.size(),
                    collected.lines.empty() ? std::string {} : collected.lines.front());
    }
}

/** Chunks outrunning a peer that reads nothing report @c ucall_status_would_block_k, and once the
 *  peer reads, the retried rest completes a body of the declared length byte for byte. */
static void test_streamed_reply_would_block(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return;
    std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
    expect_true(::send(client.descriptor, request.data(), request.size(), 0) == static_cast<ssize_t>(request.size()));
    await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    if (!expect_true(held)) return;
    std::size_t const chunk_length = 64 * 1024, chunks_count = 512;
    std::string chunk(chunk_length, '\0');
    std::string const length = fmt::format("Content-Length: {}", chunk_length * chunks_count);
    ucall_bytes_view_t const header = uc::bytes_view(length);
    ucall_outcome_t outcome {};
    ucall_server_reply_begin_t begin {fixture.server, &outcome, held, 0, &header, 1};
    ucall_server_reply_begin(&begin);
    expect_true(outcome.status == ucall_status_success_k, "begin: {}", ucall_status_name(outcome.status));
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
        expect_true(outcome.status == ucall_status_success_k, "chunk: {}", ucall_status_name(outcome.status));
    }
    expect_true(queued != chunks_count, "every chunk queued while the peer read nothing");
    std::thread reader {[&] {
        auto const response = read_response(client, 0);
        expect_true(response.status == 200 && response.body.size() == chunk_length * chunks_count,
                    "read {} with {} body bytes", response.status, response.body.size());
        for (std::size_t index = 0; index != chunks_count && response.body.size() == chunk_length * chunks_count;
             ++index)
            if (response.body[index * chunk_length] != static_cast<char>('a' + index % 26)) {
                expect_true(false, "chunk {} arrived corrupted", index);
                break;
            }
    }};
    for (; queued != chunks_count; ++queued) {
        fill(queued);
        ucall_reply_part_t const part = bytes_part(chunk);
        ucall_server_reply_append_t append {fixture.server, &outcome, held, &part, 1};
        append_when_room(append, steady_clock::now() + wait_limit_k);
        expect_true(outcome.status == ucall_status_success_k, "chunk: {}", ucall_status_name(outcome.status));
    }
    ucall_server_reply_end_t end {fixture.server, &outcome, held};
    ucall_server_reply_end(&end);
    expect_true(outcome.status == ucall_status_success_k, "end: {}", ucall_status_name(outcome.status));
    reader.join();
    fixture.stop();
}

/** A peer leaving mid-stream turns later chunks and the end into
 *  @c ucall_status_connection_closed_k, and the server goes on answering others. */
static void test_streamed_reply_detach(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {.connections = 2}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return;
    std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
    expect_true(::send(client.descriptor, request.data(), request.size(), 0) == static_cast<ssize_t>(request.size()));
    await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    if (!expect_true(held)) return;
    ucall_outcome_t outcome {};
    ucall_server_reply_begin_t begin {fixture.server, &outcome, held, 0, nullptr, 0};
    ucall_server_reply_begin(&begin);
    expect_true(outcome.status == ucall_status_success_k, "begin: {}", ucall_status_name(outcome.status));
    std::string const chunk(4096, 'd');
    ucall_reply_part_t const part = bytes_part(chunk);
    ucall_server_reply_append_t append {fixture.server, &outcome, held, &part, 1};
    ucall_server_reply_append(&append);
    expect_true(outcome.status == ucall_status_success_k, "chunk: {}", ucall_status_name(outcome.status));
    client.close();
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
    do {
        std::this_thread::sleep_for(1ms);
        ucall_server_reply_append(&append);
    } while (outcome.status != ucall_status_connection_closed_k && steady_clock::now() < deadline);
    expect_true(outcome.status == ucall_status_connection_closed_k, "chunk after the close: {}",
                ucall_status_name(outcome.status));
    ucall_server_reply_end_t end {fixture.server, &outcome, held};
    ucall_server_reply_end(&end);
    expect_true(outcome.status == ucall_status_connection_closed_k, "end: {}", ucall_status_name(outcome.status));
    raw_client_t other;
    if (!expect_true(other.connect(fixture.address))) return;
    std::string_view const echo = "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nok";
    expect_true(::send(other.descriptor, echo.data(), echo.size(), 0) == static_cast<ssize_t>(echo.size()));
    auto const response = read_response(other, 0);
    expect_true(response.status == 200 && response.body == "ok", "answered {} {}", response.status, response.body);
    fixture.stop();
}

/** An HTTP/1.0 peer gets a streamed body delimited by the close, with no framing field. */
static void test_streamed_reply_http10(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return;
    std::string_view const request = "GET /gate HTTP/1.0\r\nConnection: keep-alive\r\n\r\n";
    expect_true(::send(client.descriptor, request.data(), request.size(), 0) == static_cast<ssize_t>(request.size()));
    await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    if (!expect_true(held)) return;
    auto const chunks = stream_chunks(50, 'c');
    stream_reply(fixture.server, held, chunks);
    auto const end = client.read_until_close(steady_clock::now() + wait_limit_k);
    expect_true(end == read_end_t::closed_k, "the read ended as {}", static_cast<int>(end));
    std::string_view const wire = client.received;
    auto const headers_end = wire.find("\r\n\r\n");
    if (!expect_true(headers_end != std::string_view::npos)) return;
    auto const headers = wire.substr(0, headers_end);
    expect_true(headers.starts_with("HTTP/1.1 200 OK\r\n"));
    expect_true(headers.find("connection: close") != std::string_view::npos);
    expect_true(headers.find("content-length") == std::string_view::npos &&
                    headers.find("transfer-encoding") == std::string_view::npos,
                "framed head: {}", headers);
    expect_true(wire.substr(headers_end + 4) == joined(chunks), "{} body bytes", wire.size() - headers_end - 4);
    fixture.stop();
}

/** A declared @c content-length frames chunks as identity, refuses a chunk running past it, and an
 *  end short of it reports @c ucall_status_malformed_k and closes after the bytes sent. */
static void test_streamed_reply_identity(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return;
    std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
    ucall_bytes_view_t const header = uc::bytes_view("Content-Length: 10");
    auto send_and_take = [&] {
        expect_true(::send(client.descriptor, request.data(), request.size(), 0) ==
                    static_cast<ssize_t>(request.size()));
        await_held_in_background(fixture, 1);
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
    if (!expect_true(held)) return;
    ucall_server_reply_begin_t begin {fixture.server, &outcome, held, 0, &header, 1};
    ucall_server_reply_begin(&begin);
    expect_true(outcome.status == ucall_status_success_k, "begin: {}", ucall_status_name(outcome.status));
    expect_true(chunk(held, "hello") == ucall_status_success_k);
    expect_true(chunk(held, "worldwide!") == ucall_status_overflow_k, "past the length: {}",
                ucall_status_name(outcome.status));
    expect_true(chunk(held, "world") == ucall_status_success_k);
    ucall_server_reply_end_t end {fixture.server, &outcome, held};
    ucall_server_reply_end(&end);
    expect_true(outcome.status == ucall_status_success_k, "end: {}", ucall_status_name(outcome.status));
    auto const response = read_response(client, 0);
    expect_true(response.status == 200 && response.body == "helloworld", "answered {} {}", response.status,
                response.body);
    held = send_and_take();
    if (!expect_true(held)) return;
    begin.request = held;
    ucall_server_reply_begin(&begin);
    expect_true(chunk(held, "short") == ucall_status_success_k);
    end.request = held;
    ucall_server_reply_end(&end);
    expect_true(outcome.status == ucall_status_malformed_k, "a short end: {}", ucall_status_name(outcome.status));
    auto const closed = client.read_until_close(steady_clock::now() + wait_limit_k);
    expect_true(closed == read_end_t::closed_k, "the read ended as {}", static_cast<int>(closed));
    expect_true(std::string_view {client.received}.substr(response.length).ends_with("\r\n\r\nshort"),
                "the cut reply: {}", std::string_view {client.received}.substr(response.length));
    fixture.stop();
}

#endif // UCALL_OS_POSIX_
#pragma endregion Raw Clients

#pragma region Request Bodies
#if UCALL_OS_POSIX_

/** Configuration strings are views: an address carved from a longer buffer binds by its length
 *  alone, and a device name holding a zero byte is refused. */
static void test_configuration_byte_views(sweep_cell_t const& cell) {
    keeping_descriptors([&] {
        std::string_view const carved = "127.0.0.1:0trailing";
        ucall_network_interface_t network_interface {};
        network_interface.address = uc::bytes_view(carved.substr(0, 11));
        network_interface.max_concurrent_connections = 1;
        ucall_server_options_t config {}, resolved {};
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
        config.backend = cell.backend;
        config.cpu_class_ceiling = cell.cpu_class_ceiling;
        ucall_server_t server {};
        ucall_outcome_t outcome {};
        ucall_server_init_t init {&server, &outcome, &config, &resolved};
        ucall_server_init(&init);
        if (!expect_true(outcome.status == ucall_status_success_k, "a carved address: {}",
                         ucall_status_name(outcome.status)))
            return;
        std::string_view const bound = uc::text_view(resolved.interfaces[0].address);
        expect_true(bound.starts_with("127.0.0.1:") && bound.size() > 10, "bound {}", bound);
        raw_client_t client;
        expect_true(client.connect(bound), "no connection to {}", bound);
        client.close();
        ucall_server_free(server);
        network_interface.device_name = uc::bytes_view(std::string_view {"lo\0x", 4});
        ucall_server_init(&init);
        expect_true(outcome.status == ucall_status_invalid_argument_k, "a zero byte in a device: {}",
                    ucall_status_name(outcome.status));
        ucall_server_free(server);
        network_interface.device_name = {};
        ucall_noise_key_t const key {1};
        network_interface.security = ucall_security_noise_kk_k;
        network_interface.noise_private_key = &key;
        ucall_server_init(&init);
        expect_true(outcome.status == ucall_status_invalid_argument_k, "KK without the initiator key: {}",
                    ucall_status_name(outcome.status));
        ucall_server_free(server);
    });
}

/** A mebibyte of letters, so a misplaced byte shows in the diff. */
static std::string lettered_body() {
    std::string body(std::size_t {1} << 20, '\0');
    for (std::size_t i = 0; i != body.size(); ++i) body[i] = static_cast<char>('a' + i % 23);
    return body;
}

/** @p body framed in chunks of random lengths, one with an extension, and a trailer after them. */
static std::string chunked_body(std::string_view body, split_mix_generator_t& generator) {
    std::string wire;
    for (std::size_t offset = 0; offset != body.size();) {
        std::size_t const length = fu::min_of<std::size_t>(1 + generator.below(70000), body.size() - offset);
        wire += fmt::format("{:x}{}\r\n{}\r\n", length, offset ? "" : ";first=1", body.substr(offset, length));
        offset += length;
    }
    wire += "0\r\nX-Trailer: done\r\n\r\n";
    return wire;
}

/** Pulls @p request's streamed body to its end from this thread, counting the pulls it took. */
static std::string pull_body(fixture_t& fixture, ucall_received_http_request_t request, std::size_t& pulls) {
    std::string body;
    for (;;) {
        ucall_outcome_t outcome {};
        ucall_bytes_view_t data {};
        ucall_server_request_body_chunk_t pull {fixture.server, &outcome, request, &data};
        ucall_server_request_body_chunk(&pull);
        ucall_status_t const status = ucall_outcome_wait(&outcome);
        ++pulls;
        if (status != ucall_status_success_k) {
            expect_true(false, "pull {} ended with {}", pulls, ucall_status_name(status));
            return body;
        }
        if (!data.length) return body;
        body += uc::text_view(data);
    }
}

/** Answers @p request with the length of what it received, once a streamed case pulled it all. */
static bool reply_length(fixture_t& fixture, ucall_received_http_request_t request, std::size_t length) {
    std::string const answer = fmt::format("{}", length);
    ucall_outcome_t outcome {};
    ucall_server_reply_content_t reply {fixture.server,        &outcome, request, ucall_http_status_ok_k, nullptr, 0,
                                        uc::bytes_view(answer)};
    ucall_server_reply_content(&reply);
    return expect_true(outcome.status == ucall_status_success_k, "reply: {}", ucall_status_name(outcome.status));
}

/** Identity and chunked mebibyte bodies arrive through several pulls that add up to the bytes
 *  sent, a streamed request has no parts and no buffered body, and the reply reaches the peer. */
static void test_streamed_body(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    std::string const body = lettered_body();
    for (std::string_view const framing : {"Content-Length", "Transfer-Encoding"}) {
        std::string const request =
            framing == "Content-Length"
                ? fmt::format("POST /stream HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n{}", body.size(), body)
                : fmt::format("POST /stream HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n{}",
                              chunked_body(body, generator));
        raw_client_t client;
        if (!expect_true(client.connect(fixture.address))) return;
        bool written = false;
        std::thread writer {[&] {
            written = client.write(uc::byte_span(request), 65536, generator, steady_clock::now() + wait_limit_k);
        }};
        await_held_in_background(fixture, 1);
        auto* held = fixture.take_held();
        if (!held) {
            writer.join();
            fixture.stop();
            return;
        }
        expect_true(ucall_server_request_parts_count(fixture.server, held) == 0, "a streamed request had parts");
        ucall_outcome_t outcome {};
        ucall_bytes_view_t whole {};
        ucall_server_request_body_t buffered {fixture.server, &outcome, held, &whole};
        ucall_server_request_body(&buffered);
        expect_true(outcome.status == ucall_status_invalid_argument_k, "a streamed body read whole: {}",
                    ucall_status_name(outcome.status));
        std::size_t pulls = 0;
        std::string const received = pull_body(fixture, held, pulls);
        writer.join();
        expect_true(written, "the request was not written");
        expect_true(pulls > 1, "{} pulls took a mebibyte", pulls);
        expect_equal_bytes(uc::byte_span(received), uc::byte_span(body));
        reply_length(fixture, held, received.size());
        auto const response = read_response(client, 0);
        expect_true(response.status == 200 && response.body == fmt::format("{}", body.size()), "answered {} {}",
                    response.status, response.body);
    }
    fixture.stop();
}

/** The next completed call of the fixture's client alone, for cases whose server loops run in the
 *  background, or one with a timeout outcome once @c wait_limit_k passes. */
static ucall_completed_call_t client_wait(fixture_t& fixture) {
    steady_clock::time_point const deadline = steady_clock::now() + wait_limit_k;
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
static void test_streamed_body_noise(sweep_cell_t const& cell) {
    fixture_t fixture {{cell.backend, cell.cpu_class_ceiling, ucall_security_noise_xx_k}, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    std::string const body = lettered_body();
    std::string const stream_url = fmt::format("{}/stream", fixture.url);
    ucall_outcome_t outcome {};
    ucall_client_call_t call {};
    call.client = fixture.client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(stream_url);
    call.verb = ucall_verb_post_k;
    call.body = uc::bytes_view(body);
    call.options.security = ucall_security_noise_xx_k;
    ucall_client_call(&call);
    expect_true(outcome.status == ucall_status_success_k);
    // The client stays on the thread that made it, as single-issuer rings need; pulls run apart.
    std::string received;
    std::thread puller {[&] {
        await_held_in_background(fixture, 1);
        auto* held = fixture.take_held();
        std::size_t pulls = 0;
        if (held) received = pull_body(fixture, held, pulls);
        if (held) reply_length(fixture, held, received.size());
    }};
    ucall_completed_call_t completed = client_wait(fixture);
    puller.join();
    expect_equal_bytes(uc::byte_span(received), uc::byte_span(body));
    expect_true(completed.outcome.status == ucall_status_success_k && completed.response, "{}",
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
    expect_true(uc::text_view(answer) == "1;k==v;", "the parts answered `{}`", uc::text_view(answer));
    if (completed.response) ucall_client_response_free(completed.response);
    fixture.stop();
}

/** A held stream whose bytes nobody pulls leaves another connection's hundred echoes unhindered. */
static void test_streamed_body_slow_puller(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {.connections = 2}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    std::string const body = lettered_body();
    std::string const request = fmt::format("POST /stream HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n{}",
                                            body.size(), body);
    raw_client_t slow, quick;
    if (!expect_true(slow.connect(fixture.address) && quick.connect(fixture.address))) return;
    bool written = false;
    std::thread writer {
        [&] { written = slow.write(uc::byte_span(request), 65536, generator, steady_clock::now() + wait_limit_k); }};
    await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    std::string_view const echo = "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi";
    for (std::size_t i = 0; i != 100; ++i) {
        std::size_t const offset = quick.received.size();
        expect_true(::send(quick.descriptor, echo.data(), echo.size(), 0) == static_cast<ssize_t>(echo.size()));
        auto const response = read_response(quick, offset);
        if (response.status != 200 || response.body != "hi") {
            expect_true(false, "echo {} answered {} {}", i, response.status, response.body);
            break;
        }
    }
    std::size_t pulls = 0;
    std::string const received = held ? pull_body(fixture, held, pulls) : std::string {};
    writer.join();
    expect_true(written && received == body, "the held stream took {} of {} bytes", received.size(), body.size());
    if (held) reply_length(fixture, held, received.size());
    fixture.stop();
}

/** A pull on the request's polling thread with nothing decoded yet answers @c would_block at once
 *  and keeps no outcome, and the body still arrives through later pulls. */
static void test_body_chunk_would_block_on_polling_thread(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    std::string const body = lettered_body();
    std::string const head = fmt::format("POST /stream/pull HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n",
                                         body.size());
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return;
    expect_true(::send(client.descriptor, head.data(), head.size(), 0) == static_cast<ssize_t>(head.size()));
    await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    if (!held) {
        fixture.stop();
        return;
    }
    ucall_status_t const answered = fixture.polling_pull_status.load(std::memory_order_relaxed);
    expect_true(answered == ucall_status_would_block_k, "the polling-thread pull answered {}",
                ucall_status_name(answered));
    bool written = false;
    std::thread writer {
        [&] { written = client.write(uc::byte_span(body), 65536, generator, steady_clock::now() + wait_limit_k); }};
    std::size_t pulls = 0;
    std::string const received = pull_body(fixture, held, pulls);
    writer.join();
    expect_true(written, "the body was not written");
    expect_equal_bytes(uc::byte_span(received), uc::byte_span(body));
    reply_length(fixture, held, received.size());
    auto const response = read_response(client, 0);
    expect_true(response.status == 200 && response.body == fmt::format("{}", body.size()), "answered {} {}",
                response.status, response.body);
    fixture.stop();
}

/** A request pipelined behind a streamed body reaches its route only once the body was pulled
 *  through, and a reply sent before any pull still lets the request behind it through. */
static void test_streamed_body_barrier(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {.pipelined_requests = 2}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    std::string const body = lettered_body();
    std::string const request = fmt::format(
        "POST /stream HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n{}GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n",
        body.size(), body);
    for (std::string_view const order : {"pull first", "reply first"}) {
        std::size_t const dispatched = fixture.dispatched.load();
        raw_client_t client;
        if (!expect_true(client.connect(fixture.address))) return;
        bool written = false;
        std::thread writer {[&] {
            written = client.write(uc::byte_span(request), 65536, generator, steady_clock::now() + wait_limit_k);
        }};
        await_held_in_background(fixture, 1);
        auto* held = fixture.take_held();
        std::this_thread::sleep_for(20ms);
        expect_true(fixture.dispatched.load() == dispatched, "a request behind the stream was dispatched");
        std::size_t pulls = 0;
        if (held && order == "pull first") {
            expect_true(pull_body(fixture, held, pulls) == body, "the body arrived altered");
            reply_length(fixture, held, body.size());
        }
        else if (held) reply_length(fixture, held, 0);
        writer.join();
        expect_true(written, "the requests were not written");
        auto const first = read_response(client, 0);
        auto const second = read_response(client, first.length);
        expect_true(first.status == 200 && second.status == 200, "answered {} and {}", first.status, second.status);
        expect_true(fixture.dispatched.load() == dispatched + 1, "the request behind the stream was not served");
    }
    fixture.stop();
}

/** A chunk size that is not hexadecimal ends the waiting pull as malformed and the stream. */
static void test_streamed_body_malformed(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return;
    std::string_view const request =
        "POST /stream HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\nzz\r\n";
    expect_true(::send(client.descriptor, request.data(), request.size(), 0) == static_cast<ssize_t>(request.size()));
    await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    ucall_status_t status = ucall_status_success_k;
    for (std::size_t pulls = 0; held && status == ucall_status_success_k && pulls != 3; ++pulls) {
        ucall_outcome_t outcome {};
        ucall_bytes_view_t data {};
        ucall_server_request_body_chunk_t pull {fixture.server, &outcome, held, &data};
        ucall_server_request_body_chunk(&pull);
        status = ucall_outcome_wait(&outcome);
    }
    expect_true(status == ucall_status_malformed_k, "the bad chunk ended the pull with {}", ucall_status_name(status));
    expect_true(client.read_until_close(steady_clock::now() + wait_limit_k) == read_end_t::closed_k,
                "the connection stayed open");
    fixture.stop();
}

/** A chunk-size line that never ends ends the waiting pull with @c ucall_status_overflow_k once it
 *  passes the request cap, and the connection closes, rather than buffering without bound. */
static void test_streamed_chunk_line_bounded(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {.max_request_bytes = 64 * 1024}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    std::string const request = fmt::format(
        "POST /stream HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n1;{}", std::string(256 * 1024, 'e'));
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return;
    std::thread writer {[&] {
        [[maybe_unused]] bool const written = client.write(uc::byte_span(request), 65536, generator,
                                                           steady_clock::now() + wait_limit_k);
    }};
    await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    if (held) {
        ucall_outcome_t outcome {};
        ucall_bytes_view_t data {};
        ucall_server_request_body_chunk_t pull {fixture.server, &outcome, held, &data};
        ucall_server_request_body_chunk(&pull);
        ucall_status_t const status = await_outcome(fixture, outcome);
        expect_true(status == ucall_status_overflow_k, "the endless size line ended the pull with {}",
                    ucall_status_name(status));
        auto const end = client.read_until_close(steady_clock::now() + wait_limit_k);
        expect_true(end == read_end_t::closed_k || end == read_end_t::failed_k, "the connection ended as {}",
                    static_cast<int>(end));
        // The connection is gone, so the reply only releases the request.
        ucall_server_reply_content_t reply {fixture.server, &outcome, held, ucall_http_status_ok_k, nullptr, 0, {}};
        ucall_server_reply_content(&reply);
    }
    writer.join();
    client.close();
    fixture.stop();
}

/** A client expecting <tt>100-continue</tt> is told to send at once for a buffered body, and for a
 *  streamed one only once its handler pulls, after which the body arrives as usual. */
static void test_expect_continue(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    std::string_view const interim = "HTTP/1.1 100 Continue\r\n\r\n";
    auto send = [&](raw_client_t& client, std::string_view bytes) {
        expect_true(client.write(uc::byte_span(bytes), 0, generator, steady_clock::now() + wait_limit_k));
    };
    auto await_interim = [&](raw_client_t& client) {
        auto const end = client.read(interim.size(), steady_clock::now() + 500ms);
        expect_true(end == read_end_t::filled_k && client.received == interim, "awaited the 100 as {}: {:?}",
                    static_cast<int>(end), client.received);
    };
    {
        raw_client_t client;
        if (!expect_true(client.connect(fixture.address))) return;
        send(client, "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n");
        await_interim(client);
        send(client, "hello");
        auto const response = read_response(client, interim.size());
        expect_true(response.status == 200 && response.body == "hello", "answered {} {}", response.status,
                    response.body);
    }
    {
        raw_client_t client;
        if (!expect_true(client.connect(fixture.address))) return;
        send(client, "POST /stream HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n");
        await_held_in_background(fixture, 1);
        auto* held = fixture.take_held();
        if (!expect_true(held)) return;
        expect_true(client.read(1, steady_clock::now() + 200ms) == read_end_t::timed_out_k,
                    "the 100 left before any pull: {:?}", client.received);
        ucall_outcome_t pulled {};
        ucall_bytes_view_t data {};
        ucall_server_request_body_chunk_t pull {fixture.server, &pulled, held, &data};
        ucall_server_request_body_chunk(&pull);
        await_interim(client);
        send(client, "hello");
        expect_true(ucall_outcome_wait(&pulled) == ucall_status_success_k, "the pull ended with {}",
                    ucall_status_name(pulled.status));
        std::string body {uc::text_view(data)};
        std::size_t pulls = 1;
        body += pull_body(fixture, held, pulls);
        expect_true(body == "hello", "the stream pulled {:?}", body);
        reply_length(fixture, held, body.size());
        auto const response = read_response(client, interim.size());
        expect_true(response.status == 200 && response.body == "5", "answered {} {}", response.status, response.body);
    }
    fixture.stop();
}

/** Bodies past the request cap get 413 and an orderly close, framed by length or in chunks, and so
 *  does a head past it; the resolved configuration reports the cap. */
static void test_oversized_request_refused(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    std::size_t const cap = 64 * 1024;
    fixture_t fixture {cell, {.max_request_bytes = cap}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    expect_true(fixture.resolved.interfaces[0].max_request_bytes == cap, "resolved a cap of {}",
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
        raw_client_t client;
        if (!expect_true(client.connect(fixture.address))) return;
        bool written = false;
        std::thread writer {[&] {
            written = client.write(uc::byte_span(request), 65536, generator, steady_clock::now() + wait_limit_k);
        }};
        auto const response = read_response(client, 0);
        expect_true(response.status == 413, "answered {}", response.status);
        expect_true(client.read_until_close(steady_clock::now() + wait_limit_k) == read_end_t::closed_k,
                    "the refusal did not end in an orderly close");
        writer.join();
    }
    // A cap of zero takes what the kernel grants, which a mebibyte echo needs on stock settings.
    fixture_t derived {cell, {}};
    if (!expect_true(derived.status == ucall_status_success_k, "setup: {}", ucall_status_name(derived.status))) return;
    expect_true(derived.resolved.interfaces[0].max_request_bytes > 0, "no cap was derived");
    fixture.stop();
}

/** Parts split on the boundary only where a delimiter line starts, keep quoted names whole, may be
 *  empty or headerless, and a body missing its closing delimiter answers as malformed. */
static void test_multipart_parts(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    struct row_t {
        std::string_view name, type, body, expected;
    };
    row_t const rows[] {
        {"quoted boundary", "multipart/form-data; boundary=\"b-1\"",
         "--b-1\r\nContent-Disposition: form-data; name=\"a;b\"\r\nContent-Type: text/plain\r\n\r\nx--b-1y\r\n" //
         "--b-1\r\nContent-Disposition: form-data; name=empty\r\n\r\n\r\n--b-1\r\n\r\nheaderless\r\n--b-1--\r\n",
         "3;a;b=text/plain=x--b-1y;empty==;==headerless;"},
        {"preamble and padding", "Multipart/Form-Data; charset=utf-8; boundary=zz",
         "preamble\r\n--zz  \r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n--zz--epilogue", "1;f==v;"},
        {"no closing delimiter", "multipart/form-data; boundary=q",
         "--q\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nv\r\n", "0;malformed;"},
        {"not multipart", "application/json", "{}", "0;malformed;"},
    };
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return;
    for (auto const& row : rows) {
        std::string const request = fmt::format(
            "POST /parts HTTP/1.1\r\nHost: a\r\nContent-Type: {}\r\nContent-Length: {}\r\n\r\n{}", row.type,
            row.body.size(), row.body);
        std::size_t const offset = client.received.size();
        expect_true(::send(client.descriptor, request.data(), request.size(), 0) ==
                    static_cast<ssize_t>(request.size()));
        auto const response = read_response(client, offset);
        expect_true(response.status == 200 && response.body == row.expected, "{} answered {} `{}`", row.name,
                    response.status, response.body);
    }
    fixture.stop();
}

#endif // UCALL_OS_POSIX_
#pragma endregion Request Bodies

void test_exchanges_cell(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    test_exchanges(cell);
    test_echo_completions(cell);
    test_pipelined_calls(cell);
    test_reply_vectored(cell);
    test_streamed_reply(cell);
    test_pipelined_streams(cell);
    if (cell.security == ucall_security_noise_kk_k) test_server_kk_wrong_initiator(cell);
#if UCALL_OS_POSIX_
    if (cell.security == ucall_security_noise_xx_k) test_streamed_body_noise(cell);
#endif
    if (cell.security == ucall_security_none_k) {
        test_cross_thread_replies(cell);
        test_client_dials_for_depth(cell);
        test_pipelined_call_loss(cell);
        test_bodiless_responses_keep_connection(cell);
        test_head_replies(cell);
        test_borrowed_listener_backend(cell);
    }
#if UCALL_OS_POSIX_
    if (cell.security == ucall_security_none_k) {
        test_log_lines(cell);
        test_streamed_reply_would_block(cell);
        test_streamed_reply_detach(cell);
        test_streamed_reply_http10(cell);
        test_streamed_reply_identity(cell);
        test_pipelined_delivery(cell);
        test_fragmented_headers_delivery(cell, generator);
        test_megabyte_echo_delivery(cell, generator);
        test_smuggling(cell, generator);
        test_leading_empty_line_ignored(cell, generator);
        test_chunk_extension_whitespace(cell, generator);
        test_header_lookup(cell, generator);
        test_request_fields_in_order(cell);
        test_request_query(cell);
        test_method_routing(cell, generator);
        test_reply_connection_header_refused(cell);
        test_cross_thread_teardown_delivery(cell, generator);
        test_drain_closes_listener(cell, generator);
        test_pipelined_burst(cell, generator);
        test_orphaned_exchanges_bounded(cell, generator);
        test_interface_listen_descriptor(cell, generator);
        test_configuration_byte_views(cell);
        test_streamed_body(cell, generator);
        test_streamed_body_slow_puller(cell, generator);
        test_body_chunk_would_block_on_polling_thread(cell, generator);
        test_streamed_body_barrier(cell, generator);
        test_streamed_body_malformed(cell);
        test_streamed_chunk_line_bounded(cell, generator);
        test_oversized_request_refused(cell, generator);
        test_expect_continue(cell, generator);
        test_multipart_parts(cell);
    }
#endif
}

void run_exchanges_cases(sweep_cell_t const& cell, sz::string_t const& cell_label) {
    if (cell.security != ucall_security_none_k) return;
    run_cell_case(cell_label, "test_multiloop_retention", test_multiloop_retention, cell);
#if UCALL_OS_POSIX_
    run_cell_case(cell_label, "test_request_peer_ipv6", test_request_peer_ipv6, cell);
#endif
}

} // namespace unum::ucall::test::network
