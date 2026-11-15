/**
 *  @file test/network/metrics.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The StatsD lines a server reports: counters and gauges, a refused batch, and draining.
 */
#include <network.hpp>

namespace unum::ucall::test::network {

#if UCALL_OS_POSIX_

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
static std::size_t test_statsd_metrics(sweep_cell_t const& cell) {
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
        fixture_t fixture {cell, {.max_request_bytes = 4096, .metrics_address = address}};
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
                    auto const end = fu::min_of(rest.find('\n'), rest.size());
                    lines.emplace_back(rest.substr(0, end));
                    rest.remove_prefix(fu::min_of(end + 1, rest.size()));
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

/** A batch endpoint whose route template the server refused is no batch endpoint: metrics report
 *  the one that registered beside it and nothing for the refused one. */
static std::size_t test_statsd_skips_refused_batch(sweep_cell_t const& cell) {
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
        fixture_t fixture {cell, {.metrics_address = address}};
        require(failures, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
        auto const ignore = [](ucall_received_http_request_t const*, std::size_t, void*) {};
        using added_t = std::pair<std::string_view, ucall_status_t>;
        // Listed newest first, so the refused one comes ahead of the registered one.
        for (auto [uri_template, expected] :
             {added_t {"/kept", ucall_status_success_k}, added_t {"/refused/{", ucall_status_invalid_argument_k}}) {
            ucall_outcome_t outcome {};
            ucall_http_batch_endpoint_t endpoint {};
            ucall_server_add_http_batch_endpoint_t add {
                fixture.server, &outcome, uc::bytes_view(uri_template), ucall_verb_post_k, +ignore, nullptr, 1, 4,
                1000,           &endpoint};
            ucall_server_add_http_batch_endpoint(&add);
            failures += expect(outcome.status == expected, "{} answered {}", uri_template,
                               ucall_status_name(outcome.status));
        }
        std::vector<std::string> lines;
        char datagram[65536];
        steady_clock::time_point const deadline = steady_clock::now() + 200ms;
        while (steady_clock::now() < deadline) {
            ucall_completed_call_t completed {};
            failures += expect(!fixture.poll(completed), "a call completed unasked");
            for (ssize_t received; (received = ::recv(listener, datagram, sizeof(datagram), MSG_DONTWAIT)) > 0;)
                for (std::string_view rest {datagram, static_cast<std::size_t>(received)}; !rest.empty();) {
                    auto const end = fu::min_of(rest.find('\n'), rest.size());
                    lines.emplace_back(rest.substr(0, end));
                    rest.remove_prefix(fu::min_of(end + 1, rest.size()));
                }
        }
        std::size_t kept = 0, refused = 0;
        for (std::string_view line : lines) {
            kept += line.find("endpoint:/kept") != std::string_view::npos;
            refused += line.find("endpoint:/refused") != std::string_view::npos;
        }
        failures += expect(kept && !refused, "{} lines named the registered endpoint and {} the refused one", kept,
                           refused);
        failures += fixture.stop();
    }
    ::close(listener);
    return failures;
}

/** A drain stays visible in metrics: datagrams keep arriving after the first stop, reporting the
 *  connection still held open. */
static std::size_t test_statsd_metrics_while_draining(sweep_cell_t const& cell) {
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
        fixture_t fixture {cell, {.metrics_address = address}};
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

std::size_t check_metrics(sweep_cell_t const& cell, [[maybe_unused]] settings_t const& settings) {
    std::size_t failures = 0;
    if (cell.security == ucall_security_none_k) {
        failures += test_statsd_metrics(cell);
        failures += test_statsd_skips_refused_batch(cell);
        failures += test_statsd_metrics_while_draining(cell);
    }
    return failures;
}

#endif // UCALL_OS_POSIX_

} // namespace unum::ucall::test::network
