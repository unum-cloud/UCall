/**
 *  @file test/network/resolving.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The client's stub resolver against scripted nameservers: CNAME chains, truncation over
 *      TCP, negative caching, TTLs, search names and the IPv4 race behind a silent IPv6.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build
#include <network.hpp>

#include "variants.hpp" // `io_queues_t`, `network_t`

namespace unum::ucall::test::network {

#if UCALL_OS_POSIX_

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

/** The SOA a negative answer includes, its TTL and MINIMUM both @p ttl. */
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

/** A client of @p connections on @p cell 's backend and class that asks @p options' nameservers. */
static ucall_client_t resolving_client(sweep_cell_t const& cell, uc::dns::resolver_options_t const& options,
                                       std::size_t connections = 1) {
    using network_t = serial_network<uc::io_queues_t>;
    ucall_client_t client {};
    ucall_outcome_t outcome {};
    ucall_client_options_t config {};
    config.max_concurrent_connections = connections;
    config.backend = cell.backend;
    config.cpu_class_ceiling = cell.cpu_class_ceiling;
    ucall_client_init_t init {&client, &outcome, &config, nullptr};
    network_t::client_t::client_init(&init);
    if (outcome.status != ucall_status_success_k) return nullptr;
    // Settings are read once at init, so a case points the client at its own server after it.
    static_cast<network_t::client_t*>(client)->resolver = options;
    return client;
}

/** Calls @p url once on @p client over a connection of its own, which it closes, and waits up to
 *  @c wait_limit_k for it, freeing any response and answering its outcome. */
static ucall_status_t resolved_call(ucall_client_t client, std::string const& url) {
    ucall_outcome_t outcome {};
    ucall_client_call_t call {};
    ucall_bytes_view_t const closing = bytes_view("Connection: close");
    call.headers = &closing;
    call.headers_count = 1;
    call.client = client;
    call.outcome = &outcome;
    call.url = bytes_view(url);
    call.verb = ucall_verb_get_k;
    ucall_client_call(&call);
    if (outcome.status != ucall_status_success_k) return outcome.status;
    ucall_completed_call_t completed {};
    std::size_t count = 0;
    for (auto const deadline = steady_clock::now() + wait_limit_k; !count && steady_clock::now() < deadline;) {
        ucall_client_take_completed_t take {client, &outcome, &completed, 1, &count, 100'000};
        ucall_client_take_completed(&take);
    }
    if (completed.response) ucall_client_response_free(completed.response);
    return count ? completed.outcome.status : ucall_status_timeout_k;
}

/** A lookup whose questions all answer at once, as they do with no nameserver to ask, walks every
 *  search name and fails its call, asking nothing more of a lookup it already ended. */
static void test_resolver_without_nameservers(sweep_cell_t const& cell) {
    uc::dns::resolver_options_t settings {};
    std::string_view const search {"first.test\0second.test\0", 23};
    search.copy(settings.search, search.size());
    settings.search_length = static_cast<std::uint32_t>(search.size());
    settings.timeout_seconds = 1;
    ucall_client_t client = resolving_client(cell, settings);
    if (!expect_true(client, "no client on this backend")) return;
    ucall_status_t const status = resolved_call(client, "http://unnamed-host:80/");
    expect_true(status != ucall_status_success_k && status != ucall_status_timeout_k, "the call ended {}",
                ucall_status_name(status));
    ucall_client_free(client);
}

/** An echo server and the scripted resolver naming it, which a case calls by name. */
struct resolving_fixture_t {
    fixture_t server;
    scripted_resolver_t resolver;
    std::string port;
    resolving_fixture_t(sweep_cell_t const& cell, scripted_resolver_t::script_t script)
        : server(cell, {.connections = 4}), resolver(std::move(script)) {
        if (server.status == ucall_status_success_k) server.serve_in_background();
        port = server.address.substr(server.address.rfind(':') + 1);
    }
    [[nodiscard]] bool ready() const noexcept { return server.status == ucall_status_success_k && resolver.ready(); }
    std::string url(std::string_view host) const { return fmt::format("http://{}:{}/echo/1", host, port); }
};

/** A CNAME chain leads A to the address its last name owns, and AAAA to none. */
static void test_client_follows_cname_chain(sweep_cell_t const& cell) {
    resolving_fixture_t fixture {
        cell, [](dns_question_t const& question, std::string_view query) {
            dns_record_t const alias {"alias.test", dns_cname_k, 60, dns_wire_name("middle.test")};
            dns_record_t const middle {"middle.test", dns_cname_k, 60, dns_wire_name("real.test")};
            if (question.type == dns_a_k)
                return dns_reply(query, 0, dns_truncation_t::whole_k,
                                 {alias, middle, {"real.test", dns_a_k, 60, loopback_v4_k}});
            return dns_reply(query, 0, dns_truncation_t::whole_k, {alias, middle}, {dns_soa("test", 60)});
        }};
    if (!expect_true(fixture.ready(), "setup")) return;
    ucall_client_t client = resolving_client(cell, fixture.resolver.options());
    if (!expect_true(client, "the resolving client failed to start")) return;
    ucall_status_t const status = resolved_call(client, fixture.url("alias.test"));
    expect_true(status == ucall_status_success_k, "the alias answered {}", ucall_status_name(status));
    ucall_client_free(client);
    fixture.server.stop();
}

/** An A cut short over UDP is asked again over TCP, whose whole answer the call dials. */
static void test_client_retries_truncated_answer_over_tcp(sweep_cell_t const& cell) {
    resolving_fixture_t fixture {
        cell, [](dns_question_t const& question, std::string_view query) {
            if (question.type != dns_a_k)
                return dns_reply(query, 0, dns_truncation_t::whole_k, {}, {dns_soa("test", 60)});
            if (question.transport == dns_transport_t::datagram_k)
                return dns_reply(query, 0, dns_truncation_t::truncated_k, {});
            return dns_reply(query, 0, dns_truncation_t::whole_k, {{"wide.test", dns_a_k, 60, loopback_v4_k}});
        }};
    if (!expect_true(fixture.ready(), "setup")) return;
    ucall_client_t client = resolving_client(cell, fixture.resolver.options());
    if (!expect_true(client, "the resolving client failed to start")) return;
    ucall_status_t const status = resolved_call(client, fixture.url("wide.test"));
    expect_true(status == ucall_status_success_k, "the truncated name answered {}", ucall_status_name(status));
    auto const questions = fixture.resolver.questions();
    expect_true(
        std::any_of(questions.begin(), questions.end(),
                    [](dns_question_t const& question) { return question.transport == dns_transport_t::stream_k; }),
        "no question came over TCP");
    ucall_client_free(client);
    fixture.server.stop();
}

/** A name that does not exist fails its calls with @c ucall_status_not_found_k, and the refusal is
 *  cached for its SOA's minimum, so the second call asks nothing. */
static void test_client_caches_absent_name(sweep_cell_t const& cell) {
    resolving_fixture_t fixture {cell, [](dns_question_t const&, std::string_view query) {
                                     return dns_reply(query, 3, dns_truncation_t::whole_k, {}, {dns_soa("test", 60)});
                                 }};
    if (!expect_true(fixture.ready(), "setup")) return;
    ucall_client_t client = resolving_client(cell, fixture.resolver.options());
    if (!expect_true(client, "the resolving client failed to start")) return;
    ucall_status_t status = resolved_call(client, fixture.url("missing.test"));
    expect_true(status == ucall_status_not_found_k, "the absent name answered {}", ucall_status_name(status));
    std::size_t const asked = fixture.resolver.questions().size();
    status = resolved_call(client, fixture.url("missing.test"));
    expect_true(status == ucall_status_not_found_k, "the cached refusal answered {}", ucall_status_name(status));
    expect_true(fixture.resolver.questions().size() == asked, "{} questions after a cached refusal, {} before",
                fixture.resolver.questions().size(), asked);
    ucall_client_free(client);
    fixture.server.stop();
}

/** An answer is reused until its TTL passes, then asked again. */
static void test_client_asks_again_after_ttl(sweep_cell_t const& cell) {
    resolving_fixture_t fixture {
        cell, [](dns_question_t const& question, std::string_view query) {
            if (question.type != dns_a_k)
                return dns_reply(query, 0, dns_truncation_t::whole_k, {}, {dns_soa("test", 1)});
            return dns_reply(query, 0, dns_truncation_t::whole_k, {{"brief.test", dns_a_k, 1, loopback_v4_k}});
        }};
    if (!expect_true(fixture.ready(), "setup")) return;
    ucall_client_t client = resolving_client(cell, fixture.resolver.options());
    if (!expect_true(client, "the resolving client failed to start")) return;
    auto count_a = [&] {
        auto const questions = fixture.resolver.questions();
        return std::count_if(questions.begin(), questions.end(),
                             [](dns_question_t const& question) { return question.type == dns_a_k; });
    };
    expect_true(resolved_call(client, fixture.url("brief.test")) == ucall_status_success_k);
    expect_true(resolved_call(client, fixture.url("brief.test")) == ucall_status_success_k);
    expect_true(count_a() == 1, "{} A questions within the TTL", count_a());
    std::this_thread::sleep_for(1200ms);
    expect_true(resolved_call(client, fixture.url("brief.test")) == ucall_status_success_k);
    expect_true(count_a() == 2, "{} A questions after the TTL", count_a());
    ucall_client_free(client);
    fixture.server.stop();
}

/** A name with fewer dots than @c ndots is asked with each search suffix first, in order. */
static void test_client_walks_search_names(sweep_cell_t const& cell) {
    resolving_fixture_t fixture {
        cell, [](dns_question_t const& question, std::string_view query) {
            if (question.name != "svc.two.test")
                return dns_reply(query, 3, dns_truncation_t::whole_k, {}, {dns_soa("test", 60)});
            if (question.type != dns_a_k)
                return dns_reply(query, 0, dns_truncation_t::whole_k, {}, {dns_soa("test", 60)});
            return dns_reply(query, 0, dns_truncation_t::whole_k, {{"svc.two.test", dns_a_k, 60, loopback_v4_k}});
        }};
    if (!expect_true(fixture.ready(), "setup")) return;
    ucall_client_t client = resolving_client(cell,
                                             fixture.resolver.options(std::string_view {"one.test\0two.test\0", 18}));
    if (!expect_true(client, "the resolving client failed to start")) return;
    ucall_status_t const status = resolved_call(client, fixture.url("svc"));
    expect_true(status == ucall_status_success_k, "the short name answered {}", ucall_status_name(status));
    std::vector<std::string> names;
    for (auto const& question : fixture.resolver.questions())
        if (question.type == dns_a_k) names.push_back(question.name);
    std::vector<std::string> const expected {"svc.one.test", "svc.two.test"};
    expect_true(names == expected, "asked {} names first {}", names.size(),
                names.empty() ? std::string {} : names.front());
    ucall_client_free(client);
    fixture.server.stop();
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
static case_result_t test_client_races_ipv4_after_silent_ipv6(sweep_cell_t const& cell) {
    resolving_fixture_t fixture {
        cell, [](dns_question_t const& question, std::string_view query) {
            if (question.type == dns_aaaa_k)
                return dns_reply(query, 0, dns_truncation_t::whole_k,
                                 {{"dual.test", dns_aaaa_k, 60, std::string(15, '\0') + std::string(1, '\1')}});
            return dns_reply(query, 0, dns_truncation_t::whole_k, {{"dual.test", dns_a_k, 60, loopback_v4_k}});
        }};
    if (!expect_true(fixture.ready(), "setup")) return {};
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
        fixture.server.stop();
        return case_result_t::skipped(ipv6_refused_k);
    }
    int const filler = ::socket(AF_INET6, SOCK_STREAM, 0);
    fcntl(filler, F_SETFL, fcntl(filler, F_GETFL) | O_NONBLOCK);
    [[maybe_unused]] int const filled = ::connect(filler, reinterpret_cast<sockaddr*>(&bound), sizeof(bound));
    std::this_thread::sleep_for(50ms);
    if (!syn_swallowed(bound)) {
        ::close(filler);
        ::close(silent);
        fixture.server.stop();
        return case_result_t::skipped("needs a kernel that drops SYNs past a full accept queue");
    }
    ucall_client_t client = resolving_client(cell, fixture.resolver.options(), 2);
    if (client) {
        auto const started = steady_clock::now();
        ucall_status_t const status = resolved_call(client, fixture.url("dual.test"));
        auto const elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(steady_clock::now() - started);
        expect_true(status == ucall_status_success_k && elapsed < 2s, "the dual-stack name answered {} after {} ms",
                    ucall_status_name(status), elapsed.count());
        ucall_client_free(client);
    }
    else expect_true(false, "the resolving client failed to start");
    ::close(filler);
    ::close(silent);
    fixture.server.stop();
    return {};
}

#pragma endregion Scripted Resolver

void test_resolving_cell(sweep_cell_t const& cell) {
    if (cell.security == ucall_security_none_k) {
        test_client_follows_cname_chain(cell);
        test_client_retries_truncated_answer_over_tcp(cell);
        test_client_caches_absent_name(cell);
        test_client_asks_again_after_ttl(cell);
        test_client_walks_search_names(cell);
        test_resolver_without_nameservers(cell);
    }
}

void run_resolving_cases(sweep_cell_t const& cell, sz::string_t const& cell_label) {
    if (cell.security == ucall_security_none_k) {
        run_cell_case(cell_label, "test_client_races_ipv4_after_silent_ipv6", test_client_races_ipv4_after_silent_ipv6,
                      cell);
    }
}

#endif // UCALL_OS_POSIX_

} // namespace unum::ucall::test::network
