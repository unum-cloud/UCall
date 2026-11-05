/**
 *  @file test/network/bodies.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Byte-view configuration, streamed and multipart bodies, request limits and StatsD.
 */
#include <network.hpp>

namespace unum::ucall::test::network {

#pragma region Raw Clients
#if UCALL_OS_POSIX_

/** Configuration strings are views: an address carved from a longer buffer binds by its length
 *  alone, and a device name holding a zero byte is refused. */
static case_result_t test_configuration_byte_views() {
    return keeping_descriptors([]() -> case_result_t {
        std::string_view const carved = "127.0.0.1:0trailing";
        ucall_network_interface_t network_interface {};
        network_interface.address = uc::bytes_view(carved.substr(0, 11));
        network_interface.max_concurrent_connections = 1;
        ucall_server_options_t config {}, resolved {};
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
        network_interface.security = ucall_security_noise_kk_k;
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
    ucall_server_reply_content_t reply {fixture.server,        &outcome, request, ucall_http_status_ok_k, nullptr, 0,
                                        uc::bytes_view(answer)};
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
    fixture_t fixture {{.security = ucall_security_noise_xx_k}};
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
    call.options.security = ucall_security_noise_xx_k;
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

/** A pull on the request's polling thread with nothing decoded yet answers @c would_block at once
 *  and keeps no outcome, and the body still arrives through later pulls. */
static case_result_t test_body_chunk_would_block_on_polling_thread(random_generator_t& generator) {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    std::string const body = lettered_body();
    std::string const head = fmt::format("POST /stream/pull HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n",
                                         body.size());
    raw_client_t client;
    require(failures + fixture.stop(), client.connect(fixture.address));
    failures += expect(::send(client.descriptor, head.data(), head.size(), 0) == static_cast<ssize_t>(head.size()));
    failures += await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    if (!held) return failures + fixture.stop();
    ucall_status_t const answered = fixture.polling_pull_status.load(std::memory_order_relaxed);
    failures += expect(answered == ucall_status_would_block_k, "the polling-thread pull answered {}",
                       ucall_status_name(answered));
    bool written = false;
    std::thread writer {
        [&] { written = client.write(uc::byte_span(body), 65536, generator, steady_clock::now() + 5s); }};
    std::size_t pulls = 0;
    std::string const received = pull_body(fixture, held, failures, pulls);
    writer.join();
    failures += expect(written, "the body was not written");
    failures += expect_bytes(uc::byte_span(received), uc::byte_span(body));
    failures += reply_length(fixture, held, received.size());
    auto const response = read_response(client, 0);
    failures += expect(response.status == 200 && response.body == fmt::format("{}", body.size()), "answered {} {}",
                       response.status, response.body);
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

/** A chunk-size line that never ends ends the waiting pull with @c ucall_status_overflow_k once it
 *  passes the request cap, and the connection closes, rather than buffering without bound. */
static case_result_t test_streamed_chunk_line_bounded(random_generator_t& generator) {
    fixture_t fixture {{.max_request_bytes = 64 * 1024}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    std::string const request = fmt::format(
        "POST /stream HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n1;{}", std::string(256 * 1024, 'e'));
    raw_client_t client;
    require(failures + fixture.stop(), client.connect(fixture.address));
    std::thread writer {[&] {
        [[maybe_unused]] bool const written = client.write(uc::byte_span(request), 65536, generator,
                                                           steady_clock::now() + 5s);
    }};
    failures += await_held_in_background(fixture, 1);
    auto* held = fixture.take_held();
    if (held) {
        ucall_outcome_t outcome {};
        ucall_bytes_view_t data {};
        ucall_server_request_body_chunk_t pull {fixture.server, &outcome, held, &data};
        ucall_server_request_body_chunk(&pull);
        ucall_status_t const status = await_outcome(fixture, outcome);
        failures += expect(status == ucall_status_overflow_k, "the endless size line ended the pull with {}",
                           ucall_status_name(status));
        auto const end = client.read_until_close(steady_clock::now() + 5s);
        failures += expect(end == read_end_t::closed_k || end == read_end_t::failed_k, "the connection ended as {}",
                           static_cast<int>(end));
        // The connection is gone, so the reply only releases the request.
        ucall_server_reply_content_t reply {fixture.server, &outcome, held, ucall_http_status_ok_k, nullptr, 0, {}};
        ucall_server_reply_content(&reply);
    }
    client.close();
    writer.join();
    return failures + fixture.stop();
}

/** A client expecting <tt>100-continue</tt> is told to send at once for a buffered body, and for a
 *  streamed one only once its handler pulls, after which the body arrives as usual. */
static case_result_t test_expect_continue(random_generator_t& generator) {
    fixture_t fixture {{}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    fixture.serve_in_background();
    std::size_t failures = 0;
    std::string_view const interim = "HTTP/1.1 100 Continue\r\n\r\n";
    auto send = [&](raw_client_t& client, std::string_view bytes) {
        failures += expect(client.write(uc::byte_span(bytes), 0, generator, steady_clock::now() + 5s));
    };
    auto await_interim = [&](raw_client_t& client) {
        auto const end = client.read(interim.size(), steady_clock::now() + 500ms);
        failures += expect(end == read_end_t::filled_k && client.received == interim, "awaited the 100 as {}: {:?}",
                           static_cast<int>(end), client.received);
    };
    {
        announce("buffered");
        raw_client_t client;
        require(failures + fixture.stop(), client.connect(fixture.address));
        send(client, "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n");
        await_interim(client);
        send(client, "hello");
        auto const response = read_response(client, interim.size());
        failures += expect(response.status == 200 && response.body == "hello", "answered {} {}", response.status,
                           response.body);
    }
    {
        announce("streamed");
        raw_client_t client;
        require(failures + fixture.stop(), client.connect(fixture.address));
        send(client, "POST /stream HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n");
        failures += await_held_in_background(fixture, 1);
        auto* held = fixture.take_held();
        require(failures + fixture.stop(), held);
        failures += expect(client.read(1, steady_clock::now() + 200ms) == read_end_t::timed_out_k,
                           "the 100 left before any pull: {:?}", client.received);
        ucall_outcome_t pulled {};
        ucall_bytes_view_t data {};
        ucall_server_request_body_chunk_t pull {fixture.server, &pulled, held, &data};
        ucall_server_request_body_chunk(&pull);
        await_interim(client);
        send(client, "hello");
        failures += expect(ucall_outcome_wait(&pulled) == ucall_status_success_k, "the pull ended with {}",
                           ucall_status_name(pulled.status));
        std::string body {uc::text_view(data)};
        std::size_t pulls = 1;
        body += pull_body(fixture, held, failures, pulls);
        failures += expect(body == "hello", "the stream pulled {:?}", body);
        failures += reply_length(fixture, held, body.size());
        auto const response = read_response(client, interim.size());
        failures += expect(response.status == 200 && response.body == "5", "answered {} {}", response.status,
                           response.body);
    }
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

/** The value of every <tt>name:value|type</tt> line in @p lines whose tags hold @p tag, summed. */
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
        ucall_server_options_t config {};
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

/** A drain stays visible in metrics: datagrams keep arriving after the first stop, reporting the
 *  connection still held open. */
static case_result_t test_statsd_metrics_while_draining() {
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
        fixture_t fixture {{.metrics_address = address}};
        require(failures, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
        fixture.serve_in_background();
        raw_client_t client;
        require(failures + fixture.stop(), client.connect(fixture.address));
        std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
        failures += expect(::send(client.descriptor, request.data(), request.size(), 0) ==
                           static_cast<ssize_t>(request.size()));
        failures += await_held_in_background(fixture, 1);
        auto* held = fixture.take_held();
        require(failures + fixture.stop(), held);
        ucall_server_stop(fixture.server);
        char datagram[65536];
        // What was sent before the stop drains first, over a few report intervals.
        steady_clock::time_point const settled = steady_clock::now() + 50ms;
        while (steady_clock::now() < settled)
            if (::recv(listener, datagram, sizeof(datagram), MSG_DONTWAIT) <= 0) std::this_thread::sleep_for(1ms);
        std::string reported;
        steady_clock::time_point const deadline = steady_clock::now() + 1s;
        while (reported.find("probe.connections:1|g") == std::string::npos && steady_clock::now() < deadline) {
            ssize_t const received = ::recv(listener, datagram, sizeof(datagram), MSG_DONTWAIT);
            if (received > 0) reported.append(datagram, static_cast<std::size_t>(received));
            else std::this_thread::sleep_for(1ms);
        }
        failures += expect(reported.find("probe.connections:1|g") != std::string::npos,
                           "no datagram reported the drain: {:?}", reported);
        ucall_outcome_t outcome {};
        ucall_server_reply_content_t reply {
            fixture.server, &outcome, held, ucall_http_status_ok_k, nullptr, 0, uc::bytes_view("drained")};
        ucall_server_reply_content(&reply);
        failures += expect(outcome.status == ucall_status_success_k, "reply: {}", ucall_status_name(outcome.status));
        failures += expect(read_response(client, 0).status == 200, "the held reply did not arrive");
        failures += fixture.stop();
    }
    ::close(listener);
    return failures;
}

void run_bodies(suite_totals_t& totals) {
    run_test(totals, "test_configuration_byte_views", test_configuration_byte_views);
    run_test(totals, "test_streamed_body_plain", test_streamed_body_plain);
    run_test(totals, "test_streamed_body_noise_xx", test_streamed_body_noise_xx);
    run_test(totals, "test_streamed_body_slow_puller", test_streamed_body_slow_puller);
    run_test(totals, "test_body_chunk_would_block_on_polling_thread", test_body_chunk_would_block_on_polling_thread);
    run_test(totals, "test_streamed_body_barrier", test_streamed_body_barrier);
    run_test(totals, "test_streamed_body_malformed", test_streamed_body_malformed);
    run_test(totals, "test_streamed_chunk_line_bounded", test_streamed_chunk_line_bounded);
    run_test(totals, "test_oversized_request_refused", test_oversized_request_refused);
    run_test(totals, "test_expect_continue", test_expect_continue);
    run_test(totals, "test_multipart_parts", test_multipart_parts);
    run_test(totals, "test_statsd_metrics", test_statsd_metrics);
    run_test(totals, "test_statsd_metrics_while_draining", test_statsd_metrics_while_draining);
}

#endif // UCALL_OS_POSIX_
#pragma endregion Raw Clients

} // namespace unum::ucall::test::network
