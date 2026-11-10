/**
 *  @file test/network.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The network suite's entry point, with engine duplex, accept batches and backend parity.
 *
 *  Every case runs against the backend `--backend` names, or the automatic one without it. Backend
 *  parity runs only in the automatic invocation, since it walks every backend the build carries.
 */
#include "ucall/io/types.hpp" // `io_request_t`, `io_completion_t`, `io_wait_t`

#include "network.hpp"
#include "variants.hpp" // `io_engines_t`

using namespace unum::ucall::test;
using namespace unum::ucall::test::network;

#pragma region Raw Clients
#if UCALL_OS_POSIX_

/** Drops every `date:` line, the one header two identical exchanges may differ in. */
static std::string without_dates(std::string wire) {
    for (auto start = wire.find("\r\ndate: "); start != std::string::npos; start = wire.find("\r\ndate: ", start))
        wire.erase(start, wire.find("\r\n", start + 2) - start);
    return wire;
}

/** Every backend this process can create answers one raw transcript with the same bytes. */
static case_result_t test_backend_parity(random_generator_t& generator) {
    static constexpr ucall_io_backend_t backends_k[] {
        ucall_io_backend_posix_k,          ucall_io_backend_linux_epollaio_k, ucall_io_backend_linux_uring612_k,
        ucall_io_backend_linux_uring618_k, ucall_io_backend_bsd_kqueue_k,     ucall_io_backend_windows_iocp_k,
        ucall_io_backend_windows_rio_k};
    std::size_t failures = 0, compared = 0;
    std::string reference;
    char const* reference_name = "";
    for (auto backend : backends_k) {
        fixture_t fixture {{.backend = backend}};
        if (fixture.status == ucall_status_unsupported_k) continue;
        char const* name = ucall_io_backend_name(backend);
        require(failures, fixture.status == ucall_status_success_k, "{} setup: {}", name,
                ucall_status_name(fixture.status));
        announce("{}", name);
        fixture.serve_in_background();
        raw_client_t client;
        require(failures, client.connect(fixture.address));
        std::size_t offset = 0;
        for (std::string_view request : {"GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n",
                                         "POST /echo/2 HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\n\r\nposted",
                                         "GET /missing HTTP/1.1\r\nHost: a\r\n\r\n"}) {
            failures += expect(client.write(uc::byte_span(request), 16, generator, steady_clock::now() + 5s));
            offset += read_response(client, offset).length;
        }
        exchange_until_close(client,
                             "POST /echo/3 HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\nleft"
                             "POST /echo/4 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nConnection: close\r\n\r\nright",
                             0, generator, failures);
        failures += fixture.stop();
        auto transcript = without_dates(client.received);
        if (!compared++) {
            reference = transcript;
            reference_name = name;
        }
        else
            failures += expect(transcript == reference, "{} answered {:?}, {} answered {:?}", name, transcript,
                               reference_name, reference);
    }
    if (compared < 2) return case_result_t::skipped("fewer than two backends are available", failures);
    return failures;
}

#endif // UCALL_OS_POSIX_
#pragma endregion Raw Clients

#pragma region Engines
#if UCALL_OS_POSIX_

/** The engine <tt>--backend</tt> names keeps a mebibyte send and a receive pending on one socket
 *  at once, and each completes as its own request. */
static case_result_t test_engine_duplex_delivery(random_generator_t& generator) {
    uc::io_engines_t engine;
    auto const status = engine.open(backend_under_test, 2, 2);
    if (status == ucall_status_unsupported_k) return skipped_backend(backend_under_test, engine.backend());
    require(0, status == ucall_status_success_k, "{}", ucall_status_name(status));
    std::size_t failures = 0;
    loopback_pair_t sockets = loopback_pair();
    require(failures, sockets.connected());
    // A send buffer far below a mebibyte keeps the send pending until the peer drains it, yet above
    // a page, as FreeBSD acknowledges each small segment only after its 40 ms delayed-ACK timer.
    int const send_buffer = static_cast<int>(16 * fixture_buffer_bytes_k);
    require(failures, uc::utilities::nonblocking(sockets.client) == ucall_status_success_k &&
                          uc::utilities::nonblocking(sockets.peer) == ucall_status_success_k &&
                          uc::utilities::socket_option(sockets.client, SOL_SOCKET, SO_SNDBUF, &send_buffer,
                                                       sizeof(send_buffer)) == 0);
    auto const owned = engine.import_socket(std::exchange(sockets.client, -1));
    require(failures, owned >= 0, "importing ended with {}", owned);
    int const peer = sockets.peer;

    std::vector<uc::byte_t> payload(std::size_t {1} << 20), drained(payload.size());
    for (auto& byte : payload) byte = static_cast<uc::byte_t>(generator());
    uc::span<uc::byte_t const> const message = uc::byte_span("receive");
    std::array<uc::byte_t, fixture_buffer_bytes_k> buffer {};
    uc::io::io_vector_t room {buffer.data(), sizeof(buffer)};
    uc::io::io_request_t receiving {.operation = uc::io::io_operation_t::receive_k,
                                    .descriptor = owned,
                                    .data = reinterpret_cast<uc::byte_t*>(&room),
                                    .length = 1};
    uc::io::io_request_t sending {.operation = uc::io::io_operation_t::send_k,
                                  .descriptor = owned,
                                  .data = payload.data(),
                                  .length = payload.size()};
    require(failures, engine.submit(receiving) == ucall_status_success_k);
    require(failures, engine.submit(sending) == ucall_status_success_k);

    std::size_t received = 0, sent = 0, read = 0;
    bool written = false;
    uc::io::io_completion_t completions[2] {};
    auto const deadline = uc::utilities::deadline_after(5000000);
    while (!received || sent != payload.size() || read != payload.size()) {
        // Nothing drains the peer before the receive completes,
        // so the send stays pending throughout.
        auto const wait = written && !received ? uc::io::io_wait_t::blocking_k : uc::io::io_wait_t::nonblocking_k;
        int const count = engine.poll(uc::span<uc::io::io_completion_t> {completions}, wait, deadline);
        require(failures, count >= 0, "polling ended with {}", count);
        for (auto const& completed :
             uc::span<uc::io::io_completion_t> {completions}.first(static_cast<std::size_t>(count))) {
            if (completed.request == &sending) {
                require(failures, completed.result > 0, "sending ended with {}", completed.result);
                sent += static_cast<std::size_t>(completed.result);
                sending.data = payload.data() + sent;
                sending.length = payload.size() - sent;
                if (sent != payload.size()) require(failures, engine.submit(sending) == ucall_status_success_k);
            }
            else {
                require(failures, completed.request == &receiving, "a completion named neither request");
                require(failures, completed.result > 0, "receiving ended with {}", completed.result);
                received = static_cast<std::size_t>(completed.result);
                uc::span<uc::byte_t const> const delivered {completed.data ? completed.data : buffer.data(), received};
                failures += expect_bytes(delivered, message);
                failures += expect(sent != payload.size(), "the send finished before the peer read");
            }
            engine.release(completed);
        }
        if (!written && !count) {
            require(failures,
                    ::send(peer, message.data(), message.size(), MSG_NOSIGNAL) == static_cast<ssize_t>(message.size()));
            written = true;
        }
        if (received && read != drained.size()) {
            auto const length = ::recv(peer, drained.data() + read, drained.size() - read, 0);
            if (length > 0) read += static_cast<std::size_t>(length);
            else require(failures, length < 0 && uc::io::io_pending(-errno), "draining ended with {}", length);
        }
        require(failures, uc::utilities::monotonic_ns() < deadline, "{} received, {} sent and {} read of {}", received,
                sent, read, payload.size());
    }
    failures += expect(drained == payload);
    failures += expect(engine.close_socket(owned) == 0);
    return failures;
}

/** One accept of the engine <tt>--backend</tt> names takes every queued connection, each completing
 *  with its own peer while the request stays pending, and the request then ends exactly once. */
static case_result_t test_engine_accept_batch(random_generator_t&) {
    constexpr std::size_t connections_k = 8;
    uc::io_engines_t engine;
    auto const status = engine.open(backend_under_test, 64, 64);
    if (status == ucall_status_unsupported_k) return skipped_backend(backend_under_test, engine.backend());
    require(0, status == ucall_status_success_k, "{}", ucall_status_name(status));
    std::size_t failures = 0;
    int const listener = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t address_length = sizeof(address);
    require(failures, listener >= 0 && ::bind(listener, reinterpret_cast<sockaddr*>(&address), address_length) == 0 &&
                          ::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_length) == 0 &&
                          ::listen(listener, connections_k) == 0 &&
                          uc::utilities::nonblocking(listener) == ucall_status_success_k);
    auto const owned = engine.import_socket(listener);
    require(failures, owned >= 0, "importing the listener ended with {}", owned);
    std::array<uc::io::io_peer_address_t, connections_k> peers {};
    uc::io::io_request_t accepting {.operation = uc::io::io_operation_t::accept_k,
                                    .descriptor = owned,
                                    .data = reinterpret_cast<uc::byte_t*>(peers.data()),
                                    .length = connections_k};
    require(failures, engine.submit(accepting) == ucall_status_success_k);

    std::string const target = fmt::format("127.0.0.1:{}", ntohs(address.sin_port));
    std::array<raw_client_t, connections_k> clients;
    std::vector<unsigned> ports;
    for (auto& client : clients) {
        sockaddr_in local {};
        socklen_t local_length = sizeof(local);
        require(failures,
                client.connect(target) &&
                    ::getsockname(client.descriptor, reinterpret_cast<sockaddr*>(&local), &local_length) == 0);
        ports.push_back(ntohs(local.sin_port));
    }
    std::vector<uc::descriptor_t> accepted;
    std::size_t endings = 0;
    // Room past every connection, so a readiness engine never ends the accept for want of it.
    uc::io::io_completion_t completions[4 * connections_k] {};
    auto const deadline = uc::utilities::deadline_after(5000000);
    while (!endings) {
        // Every client connected, so a request still pending afterwards only ends once cancelled.
        if (accepted.size() == connections_k && accepting.length)
            require(failures, engine.cancel(accepting) == ucall_status_success_k);
        int const count = engine.poll(uc::span<uc::io::io_completion_t> {completions}, uc::io::io_wait_t::blocking_k,
                                      deadline);
        require(failures, count >= 0, "polling ended with {}", count);
        for (auto const& completed :
             uc::span<uc::io::io_completion_t> {completions}.first(static_cast<std::size_t>(count))) {
            require(failures, completed.request == &accepting, "a completion named another request");
            if (completed.result < 0) {
                failures += expect(completed.result == -ECANCELED, "accepting ended with {}", completed.result);
                continue;
            }
            accepted.push_back(completed.result);
            auto const* written = completed.data ? completed.data : accepting.data;
            auto const& peer = reinterpret_cast<uc::io::io_peer_address_t const*>(written)->address;
            auto const port = ntohs(reinterpret_cast<sockaddr_in const&>(peer).sin_port);
            auto const found = std::find(ports.begin(), ports.end(), port);
            failures += expect(peer.ss_family == AF_INET && found != ports.end(), "a peer at port {} connected", port);
            if (found != ports.end()) ports.erase(found);
        }
        endings += accepting.length == 0;
        require(failures, uc::utilities::monotonic_ns() < deadline, "{} of {} accepted", accepted.size(),
                connections_k);
    }
    failures += expect(accepted.size() == connections_k && ports.empty(), "{} of {} accepted", accepted.size(),
                       connections_k);
    failures += expect(
        engine.poll(uc::span<uc::io::io_completion_t> {completions}, uc::io::io_wait_t::nonblocking_k) == 0,
        "the accept completed after it ended");
    for (auto descriptor : accepted) failures += expect(engine.close_socket(descriptor) == 0);
    failures += expect(engine.close_socket(owned) == 0);
    return failures;
}

#endif // UCALL_OS_POSIX_
#pragma endregion Engines

int main(int argc, char** argv) {
    install_test_signal_handlers();
    fmt::print("Hi, dear tester! You look nice today!\n");
    configure_tests();

    std::string command = argv[0];
    for (int index = 1; index != argc; index += 2) {
        std::string_view flag = argv[index], name = index + 1 != argc ? argv[index + 1] : "";
        if (name.empty()) flag = {};
        if (flag == "--backend") {
            backend_under_test = ucall_io_backend_from_name(uc::bytes_view(argv[index + 1]));
            if (name != ucall_io_backend_name(backend_under_test)) {
                fmt::print(stderr, "Unknown backend {}\n", name);
                return 1;
            }
        }
        else if (flag == "--cpu-class") {
            cpu_class_under_test = ucall_cpu_class_from_name(uc::bytes_view(argv[index + 1]));
            if (name != ucall_cpu_class_name(cpu_class_under_test)) {
                fmt::print(stderr, "Unknown CPU class {}\n", name);
                return 1;
            }
        }
        else {
            fmt::print(stderr, "Usage: {} [--backend <name>] [--cpu-class <name>]\n", argv[0]);
            return 1;
        }
        command = fmt::format("{} {} {}", command, argv[index], argv[index + 1]);
    }
    fmt::print("  backend          {}\n", ucall_io_backend_name(backend_under_test));
    fmt::print("  CPU class        {}\n", ucall_cpu_class_name(cpu_class_under_test));
    ucall_client_t probe {};
    ucall_outcome_t outcome {};
    ucall_client_options_t config {};
    config.max_concurrent_connections = 1;
    config.backend = backend_under_test;
    ucall_client_init_t init {&probe, &outcome, &config, nullptr};
    ucall_client_init(&init);
    ucall_client_free(probe);
    if (outcome.status == ucall_status_unsupported_k) {
        fmt::print("The kernel lacks this backend, so every case skips\n");
        return 77;
    }

    suite_totals_t totals {.program = command.c_str()};
    network::run_exchanges(totals);
#if UCALL_OS_POSIX_
    network::run_bodies(totals);
    network::run_client(totals);
    network::run_files(totals);
    run_test(totals, "test_engine_duplex_delivery", test_engine_duplex_delivery);
    run_test(totals, "test_engine_accept_batch", test_engine_accept_batch);
    if (backend_under_test == ucall_io_backend_automatic_k)
        run_test(totals, "test_backend_parity", test_backend_parity);
#endif
    return suite_exit_code(totals);
}
