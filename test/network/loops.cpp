/**
 *  @file test/network/loops.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Backend parity, admission across loops, accept shedding, CPU class ceilings, allocator
 *      propagation and queue faults.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build
#include <network.hpp>

#include "ucall/utilities/sockets.hpp" // `monotonic_ns`, `nonblocking`

#include "variants.hpp"          // `io_queues_t`, `network_t`
#include "io/faulting_queue.hpp" // `faulting_network_t`

#if UCALL_OS_POSIX_
#include <sys/resource.h> // `getrlimit`, `setrlimit`, `RLIMIT_MEMLOCK`
#endif

namespace unum::ucall::test::network {

#pragma region Queues

/** Under a locked-memory limit just short of a one-connection ring's, an automatic server lands on
 *  epollaio at init instead of refusing its first poll. */
static case_result_t test_ring_refused_at_init_falls_back() {
#if UCALL_WITH_LINUX_URING && UCALL_WITH_LINUX_EPOLLAIO
    // The backend an automatic server of `connections` picked and its first poll's status.
    auto serve_once = [](std::size_t connections) {
        std::pair<ucall_io_backend_t, ucall_status_t> result {ucall_io_backend_automatic_k, ucall_status_success_k};
        ucall_server_t server {};
        ucall_outcome_t outcome {};
        ucall_network_interface_t network_interface {};
        network_interface.address = uc::bytes_view("127.0.0.1:0");
        network_interface.max_concurrent_connections = connections;
        ucall_server_options_t config {}, resolved {};
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
        ucall_server_init_t init {&server, &outcome, &config, &resolved};
        ucall_server_init(&init);
        result.second = outcome.status;
        if (outcome.status != ucall_status_success_k) return result;
        result.first = resolved.backend;
        ucall_server_take_call_t serving {server, &outcome, 0, 0};
        ucall_server_take_call(&serving);
        result.second = outcome.status;
        ucall_server_free(server);
        return result;
    };
    auto const on_ring = [](ucall_io_backend_t backend) {
        return backend == ucall_io_backend_linux_uring618_k || backend == ucall_io_backend_linux_uring612_k;
    };
    rlimit original {};
    if (::getrlimit(RLIMIT_MEMLOCK, &original) != 0) return case_result_t::skipped("needs a readable RLIMIT_MEMLOCK");
    rlim_t low = 0, high = original.rlim_cur == RLIM_INFINITY ? rlim_t {64} << 20 : original.rlim_cur;
    if (!on_ring(serve_once(1).first))
        return case_result_t::skipped(
            "ucall_io_backend_linux_uring618_k and ucall_io_backend_linux_uring612_k are refused on this machine");
    rlimit const none {0, original.rlim_max};
    if (::setrlimit(RLIMIT_MEMLOCK, &none) == 0 && on_ring(serve_once(1).first)) {
        [[maybe_unused]] int const restored = ::setrlimit(RLIMIT_MEMLOCK, &original);
        return case_result_t::skipped("needs a kernel that bills rings to RLIMIT_MEMLOCK");
    }
    // Bisects the least limit at which a one-connection ring serves; just under it, no ring opens.
    while (high - low > 16 * 1024) {
        rlim_t const middle = low + (high - low) / 2;
        rlimit lowered {middle, original.rlim_max};
        if (::setrlimit(RLIMIT_MEMLOCK, &lowered) != 0) break;
        auto const [backend, status] = serve_once(1);
        (on_ring(backend) && status == ucall_status_success_k ? high : low) = middle;
    }
    rlimit lowered {low, original.rlim_max};
    expect_true(::setrlimit(RLIMIT_MEMLOCK, &lowered) == 0, "the locked-memory limit stayed");
    auto const [backend, status] = serve_once(4096);
    expect_true(::setrlimit(RLIMIT_MEMLOCK, &original) == 0, "the locked-memory limit stayed lowered");
    expect_true(status == ucall_status_success_k && backend == ucall_io_backend_linux_epollaio_k,
                "under {} KiB a large loop picked {} and polled {}", low / 1024, int(backend),
                ucall_status_name(status));
    return {};
#else
    return case_result_t::skipped("built without UCALL_WITH_LINUX_URING or UCALL_WITH_LINUX_EPOLLAIO");
#endif
}

/** The class a client under @p ceiling resolves to, or unknown when it does not initialize. */
static ucall_cpu_class_t resolved_class(ucall_cpu_class_t ceiling, ucall_status_t& status) {
    ucall_client_t handle {};
    ucall_outcome_t outcome {};
    ucall_client_options_t config {}, resolved {};
    config.cpu_class_ceiling = ceiling;
    config.max_concurrent_connections = 1;
    ucall_client_init_t init {&handle, &outcome, &config, &resolved};
    ucall_client_init(&init);
    ucall_client_free(handle);
    status = outcome.status;
    return status == ucall_status_success_k ? resolved.cpu_class_ceiling : ucall_cpu_class_unknown_k;
}

static void test_cpu_class_ceiling() {
    bool capped = false;
    for (ucall_cpu_class_t const cpu_class : uc::cpu_classes_k) {
        ucall_status_t status;
        ucall_cpu_class_t const picked = resolved_class(cpu_class, status);
        // A monoversioned build fits under no ceiling below its one class's capabilities.
        if (UCALL_TARGET_MONOVERSIONED) {
            expect_true(status == ucall_status_success_k || status == ucall_status_unsupported_k);
            continue;
        }
        // The ceiling intersects with this CPU, so every class, another architecture's included,
        // lands on one the machine runs, which as a ceiling picks itself again.
        char const* const name = ucall_cpu_class_name(cpu_class);
        expect_true(status == ucall_status_success_k, "the {} ceiling initializes", name);
        expect_true(picked != ucall_cpu_class_unknown_k, "the {} ceiling names its pick", name);
        ucall_status_t again;
        expect_true(resolved_class(picked, again) == picked, "{} under the {} ceiling picks itself",
                    ucall_cpu_class_name(picked), name);
        // No CPU runs the classes of two architectures, so some ceiling lands on serial.
        capped |= cpu_class != ucall_cpu_class_serial_k && picked == ucall_cpu_class_serial_k;
    }
    expect_true(UCALL_TARGET_MONOVERSIONED || capped, "a foreign ceiling resolves to serial");
    ucall_status_t status;
    resolved_class(static_cast<ucall_cpu_class_t>(4), status);
    expect_true(status == ucall_status_invalid_argument_k, "a value no class takes is refused");
}

static case_result_t test_origin_reuse_and_fairness() {
#if UCALL_WITH_POSIX
    // The library builds a serial client over every queue, so the handle reads as that network's.
    using network_t = serial_network<uc::io_queues_t>;
    ucall_client_t handle {};
    ucall_outcome_t outcome {};
    ucall_client_options_t config {};
    config.backend = ucall_io_backend_posix_k;
    config.cpu_class_ceiling = ucall_cpu_class_serial_k;
    config.max_concurrent_connections = 3;
    config.max_concurrent_calls = 4;
    ucall_client_init_t init {&handle, &outcome, &config, nullptr};
    ucall_client_init(&init);
    if (!expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status))) return {};
    auto& client = *static_cast<network_t::client_t*>(handle);
    for (auto url :
         {"http://127.0.0.1:18545/", "http://127.0.0.1:18545/", "http://127.0.0.1:18546/", "http://127.0.0.1:18545/"}) {
        ucall_client_call_t call {};
        call.client = handle;
        call.outcome = &outcome;
        call.url = uc::bytes_view(url);
        call.verb = ucall_verb_get_k;
        ucall_client_call(&call);
        expect_true(outcome.status == ucall_status_success_k);
    }
    std::array<uc::descriptor_t, 3> descriptors {};
    for (std::size_t i = 0; i != client.connections.size(); ++i) {
        auto& connection = *client.connections[i];
        connection.origin = client.exchanges[i == 1 ? 2 : 0].origin;
        ++connection.origin->connections;
        expect_true(connection.transport.configure({}, &connection) == ucall_status_success_k);
        descriptors[i] = connection.transport.descriptor = client.queue->open_socket(AF_INET);
        expect_true(descriptors[i] >= 0);
        connection.transport.stage = network_t::transport_stage_t::open_k;
        network_t::client_t::mark_ready(client, connection);
    }
    auto& origin = *client.exchanges[0].origin;
    expect_true(client.exchanges[1].origin == &origin && client.exchanges[3].origin == &origin &&
                client.exchanges[2].origin != &origin && origin.waiting == 3);
    auto& busy = *client.connections[2];
    busy.oldest_exchange = busy.newest_exchange = &network_t::client_t::unqueue_call(origin);
    busy.outstanding_exchanges = 1;
    busy.transport.transmitting = network_t::transmit_state_t::sending_k;
    busy.transport.transmit_operation = network_t::operation_state_t::submitted_k;
    client.exchanges[0].stage = client_exchange_stage_t::pipelined_k;
    network_t::client_t::client_progress(client);
    // Each idle connection takes its origin's waiting call due first, leaving the rest in order.
    expect_true(client.connections[0]->oldest_exchange == &client.exchanges[1]);
    expect_true(client.connections[1]->oldest_exchange == &client.exchanges[2]);
    expect_true(client.exchanges[3].stage == client_exchange_stage_t::waiting_k &&
                origin.waiting_head == &client.exchanges[3] && origin.waiting_tail == &client.exchanges[3]);
    for (std::size_t i = 0; i != descriptors.size(); ++i)
        expect_true(client.connections[i]->transport.descriptor == descriptors[i]);
    client.queue->stop();
    auto& released = *client.connections[1];
    released.oldest_exchange = released.newest_exchange = nullptr;
    released.outstanding_exchanges = 0;
    released.transport.transmitting = network_t::transmit_state_t::idle_k;
    released.transport.transmit_operation = network_t::operation_state_t::idle_k;
    client.exchanges[2].stage = client_exchange_stage_t::idle_k;
    network_t::client_t::mark_ready(client, released);
    network_t::client_t::client_progress(client);
    // The waiting call closes an idle connection to another origin, and dials once it has closed.
    expect_true(client.exchanges[3].stage == client_exchange_stage_t::waiting_k &&
                origin.waiting_head == &client.exchanges[3]);
    expect_true(released.transport.stage == network_t::transport_stage_t::closing_k);
    ucall_client_free(handle);
    return {};
#else
    return case_result_t::skipped("built without UCALL_WITH_POSIX");
#endif
}

/** An open connection at a depth of sixteen takes every one of sixteen waiting calls into one
 *  output, in call order, so a single send takes them all. */
static case_result_t test_client_batches_sends() {
#if UCALL_WITH_POSIX
    // The library builds a serial client over every queue, so the handle reads as that network's.
    using network_t = serial_network<uc::io_queues_t>;
    ucall_client_t handle {};
    ucall_outcome_t outcome {};
    ucall_client_options_t config {};
    config.backend = ucall_io_backend_posix_k;
    config.cpu_class_ceiling = ucall_cpu_class_serial_k;
    config.max_concurrent_connections = 1;
    config.max_pipelined_calls = 16;
    ucall_client_init_t init {&handle, &outcome, &config, nullptr};
    ucall_client_init(&init);
    if (!expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status))) return {};
    auto& client = *static_cast<network_t::client_t*>(handle);
    for (std::size_t i = 0; i != 16; ++i) {
        ucall_client_call_t call {};
        call.client = handle;
        call.outcome = &outcome;
        call.url = uc::bytes_view("http://127.0.0.1:18545/");
        call.verb = ucall_verb_put_k;
        ucall_client_call(&call);
        expect_true(outcome.status == ucall_status_success_k);
    }
    auto& connection = *client.connections[0];
    auto& origin = *client.exchanges[0].origin;
    connection.origin = &origin;
    ++origin.connections;
    expect_true(connection.transport.configure({}, &connection) == ucall_status_success_k);
    connection.transport.descriptor = client.queue->open_socket(AF_INET);
    expect_true(connection.transport.descriptor >= 0);
    connection.transport.stage = network_t::transport_stage_t::open_k;
    network_t::client_t::mark_ready(client, connection);
    network_t::client_t::client_progress(client);
    expect_true(connection.outstanding_exchanges == 16 && !origin.waiting, "{} calls aboard, {} waiting",
                connection.outstanding_exchanges, origin.waiting);
    std::size_t order = 0;
    for (auto* exchange = connection.oldest_exchange; exchange; exchange = exchange->next)
        expect_true(exchange == &client.exchanges[order++]);
    std::string_view const output {reinterpret_cast<char const*>(connection.requests.data()),
                                   connection.requests.size()};
    std::size_t requests = 0;
    for (std::size_t at = output.find("PUT / HTTP/1.1"); at != std::string_view::npos;
         at = output.find("PUT / HTTP/1.1", at + 1))
        ++requests;
    expect_true(requests == 16, "one output holds {} requests", requests);
    client.queue->stop();
    ucall_client_free(handle);
    return {};
#else
    return case_result_t::skipped("built without UCALL_WITH_POSIX");
#endif
}
#pragma endregion Queues

#pragma region Raw Clients
#if UCALL_OS_POSIX_

/** Drops every <tt>date:</tt> line, the one header two identical exchanges may differ in. */
static std::string without_dates(std::string wire) {
    for (auto start = wire.find("\r\ndate: "); start != std::string::npos; start = wire.find("\r\ndate: ", start))
        wire.erase(start, wire.find("\r\n", start + 2) - start);
    return wire;
}

/** Every backend this process can create answers one raw transcript with the same bytes. */
static case_result_t test_backend_parity(sweep_cell_t const& cell) {
    split_mix_generator_t generator {case_stream_key()};
    static constexpr ucall_io_backend_t backends_k[] {
        ucall_io_backend_posix_k,          ucall_io_backend_linux_epollaio_k, ucall_io_backend_linux_uring612_k,
        ucall_io_backend_linux_uring618_k, ucall_io_backend_bsd_kqueue_k,     ucall_io_backend_windows_iocp_k,
        ucall_io_backend_windows_rio_k};
    std::size_t compared = 0;
    std::string reference;
    char const* reference_name = "";
    for (auto backend : backends_k) {
        fixture_t fixture {{backend, cell.cpu_class_ceiling, ucall_security_none_k}, {}};
        if (fixture.status == ucall_status_unsupported_k) continue;
        char const* name = ucall_io_backend_name(backend);
        if (!expect_true(fixture.status == ucall_status_success_k, "{} setup: {}", name,
                         ucall_status_name(fixture.status)))
            return {};
        fixture.serve_in_background();
        raw_client_t client;
        if (!expect_true(client.connect(fixture.address))) return {};
        std::size_t offset = 0;
        for (std::string_view request : {"GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n",
                                         "POST /echo/2 HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\n\r\nposted",
                                         "GET /missing HTTP/1.1\r\nHost: a\r\n\r\n"}) {
            expect_true(client.write(uc::byte_span(request), 16, generator, steady_clock::now() + wait_limit_k));
            offset += read_response(client, offset).length;
        }
        exchange_until_close(client,
                             "POST /echo/3 HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\nleft" //
                             "POST /echo/4 HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nConnection: close\r\n\r\nright",
                             0, generator);
        fixture.stop();
        auto transcript = without_dates(client.received);
        if (!compared++) {
            reference = transcript;
            reference_name = name;
        }
        else
            expect_true(transcript == reference, "{} answered {:?}, {} answered {:?}", name, transcript, reference_name,
                        reference);
    }
    if (compared < 2) return case_result_t::skipped("needs two backends");
    return {};
}

/** Two loops share a budget of two: a third client is served only once an eviction closes one of
 *  the two idle ones. */
static case_result_t test_admission_across_loops(sweep_cell_t const& cell) {
    split_mix_generator_t generator {case_stream_key()};
    if (UCALL_OS_WINDOWS_) return case_result_t::skipped(loops_refused_k);
    fixture_t fixture {cell, {.event_loops = 2, .connections = 2}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
        return {};
    if (!expect_true(fixture.resolved.interfaces[0].event_loops == 2)) return {};
    fixture.serve_in_background();
    std::string_view const request = "GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n";
    raw_client_t clients[3];
    for (std::size_t i = 0; i != 3; ++i) {
        if (!expect_true(clients[i].connect(fixture.address), "client {} could not connect", i)) return {};
        expect_true(clients[i].write(uc::byte_span(request), 0, generator, steady_clock::now() + wait_limit_k));
        if (i != 2) expect_true(read_response(clients[i], 0).status == 200, "client {} was not served", i);
    }
    expect_true(read_response(clients[2], 0).status == 200, "the third client was not served");
    std::size_t closed = 0;
    for (std::size_t i = 0; i != 2; ++i)
        closed += clients[i].read_until_close(steady_clock::now() + 300ms) == read_end_t::closed_k;
    expect_true(closed == 1, "{} of the two idle clients were closed for the third", closed);
    fixture.stop();
    return {};
}

/** Running out of descriptors sheds the peers queued behind the exhausted table rather than
 *  stalling them or cutting the server: each reads a 503 or a close within two seconds, or is
 *  served where descriptors came back first or a ring accepts into slots of its own, and a fresh
 *  peer is served afterwards. */
static void test_accept_exhaustion_sheds(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    fixture_t fixture {cell, {.connections = 4}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    std::string_view const request = "GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n";
    // A served request proves the loop opened its queue, which needs descriptors of its own.
    raw_client_t fresh;
    if (!expect_true(fresh.connect(fixture.address))) return;
    expect_true(fresh.write(uc::byte_span(request), 0, generator, steady_clock::now() + wait_limit_k));
    expect_true(read_response(fresh, 0).status == 200, "the first client was not served");
    sockaddr_in target {};
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    target.sin_port = htons(
        static_cast<std::uint16_t>(std::stoi(fixture.address.substr(fixture.address.rfind(':') + 1))));
    // Sockets made before the limit drops, so only the server's accepts find the table full.
    raw_client_t clients[3];
    for (auto& client : clients) client.descriptor = ::socket(AF_INET, SOCK_STREAM, 0);
    rlimit original {};
    if (!expect_true(::getrlimit(RLIMIT_NOFILE, &original) == 0)) return;
    int const lowest = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    ::close(lowest);
    rlimit lowered = original;
    lowered.rlim_cur = static_cast<rlim_t>(lowest);
    expect_true(::setrlimit(RLIMIT_NOFILE, &lowered) == 0, "the descriptor limit stayed");
    for (auto& client : clients)
        expect_true(::connect(client.descriptor, reinterpret_cast<sockaddr const*>(&target), sizeof(target)) == 0,
                    "a backlog client could not connect: {}", errno);
    std::this_thread::sleep_for(200ms);
    expect_true(::setrlimit(RLIMIT_NOFILE, &original) == 0, "the descriptor limit stayed lowered");
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
        expect_true(response.status == 503 || response.status == 200 || closed,
                    "a backlog client read {} bytes, answered {}, ending as {}", client.received.size(),
                    response.status, static_cast<int>(end));
    }
    fresh.received.clear();
    if (!expect_true(fresh.connect(fixture.address))) return;
    expect_true(fresh.write(uc::byte_span(request), 0, generator, steady_clock::now() + wait_limit_k));
    expect_true(read_response(fresh, 0).status == 200, "a fresh client was not served");
    bool const rings = fixture.resolved.backend == ucall_io_backend_linux_uring612_k ||
                       fixture.resolved.backend == ucall_io_backend_linux_uring618_k;
    std::uint64_t const shed = loop_statistics(fixture).shed_connections;
    expect_true(rings || shed, "no peer was shed on {}", ucall_io_backend_name(fixture.resolved.backend));
    fixture.stop();
}

#endif // UCALL_OS_POSIX_
#pragma endregion Raw Clients

#pragma region Allocators

/** A server whose echo route keeps the outcome of its last reply, which no client can observe. */
struct echo_route_t {
    ucall_server_t server {};
    ucall_status_t replied {ucall_status_success_k};

    static void echo(ucall_received_http_request_t request, void* context) {
        auto& route = *static_cast<echo_route_t*>(context);
        ucall_outcome_t outcome {};
        ucall_bytes_view_t body {};
        ucall_server_request_body_t get {route.server, &outcome, request, &body};
        ucall_server_request_body(&get);
        ucall_server_reply_content_t reply {route.server, &outcome, request, ucall_http_status_ok_k, nullptr, 0, body};
        ucall_server_reply_content(&reply);
        route.replied = outcome.status;
    }

    /** Registers @c echo under the echo route with one path parameter, answering the outcome. */
    ucall_status_t add() {
        ucall_outcome_t outcome {};
        ucall_server_add_http_endpoint_t add {server, &outcome, uc::bytes_view("/echo/{id}"), ucall_verb_post_k,
                                              echo,   this};
        ucall_server_add_http_endpoint(&add);
        return outcome.status;
    }
};

/** Polls @p route and @p client until the client completes a call, answering it, or a call whose
 *  outcome is the server's own failure or a timeout at @p deadline. */
static ucall_completed_call_t complete_call(echo_route_t const& route, ucall_client_t client,
                                            steady_clock::time_point deadline) {
    ucall_completed_call_t completed {};
    std::size_t count {};
    ucall_outcome_t outcome {};
    while (!count) {
        ucall_server_take_call_t serve {route.server, &outcome, 0, 0};
        ucall_server_take_call(&serve);
        if (outcome.status == ucall_status_success_k) outcome.status = route.replied;
        if (outcome.status != ucall_status_success_k) {
            completed.outcome.status = outcome.status;
            break;
        }
        ucall_client_take_completed_t take {client, &outcome, &completed, 1, &count, 0};
        ucall_client_take_completed(&take);
        if (!count && steady_clock::now() > deadline) {
            completed.outcome.status = ucall_status_timeout_k;
            break;
        }
    }
    return completed;
}

static void test_allocator_propagation(sweep_cell_t const& cell) {
    using allocator_t = counting_allocator<uc::byte_t>;
    allocation_ledger_t ledger;
    allocator_t allocator {ledger};
    echo_route_t route;
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = uc::bytes_view("127.0.0.1:0");
    network_interface.max_concurrent_connections = 1;
    ucall_server_options_t server_config {}, resolved {};
    server_config.interfaces = &network_interface;
    server_config.interfaces_count = 1;
    server_config.backend = cell.backend;
    ucall_server_init_t server_init {&route.server, &outcome, &server_config, &resolved};
    counted_network_t::server_t::server_init(&server_init, allocator);
    if (!expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status))) return;
    expect_true(route.add() == ucall_status_success_k);
    ucall_client_t client {};
    ucall_client_options_t client_config {};
    client_config.backend = cell.backend;
    client_config.max_concurrent_connections = 1;
    ucall_client_init_t client_init {&client, &outcome, &client_config, nullptr};
    std::size_t const live = ledger.live();
    ledger.refuse_from = ledger.allocations + ledger.refusals;
    counted_network_t::client_t::client_init(&client_init, allocator);
    expect_true(!client && outcome.status == ucall_status_out_of_memory_k && ledger.live() == live);
    ledger.refuse_from = (std::numeric_limits<std::size_t>::max)();
    counted_network_t::client_t::client_init(&client_init, allocator);
    if (!expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status))) return;
    std::string url = fmt::format("http://{}/echo/1", uc::text_view(resolved.interfaces[0].address));
    std::string payload(1024, '\0');
    ucall_client_call_t call {};
    call.client = client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(url);
    call.verb = ucall_verb_post_k;
    call.body = uc::bytes_view(payload);
    ucall_client_call(&call);
    expect_true(outcome.status == ucall_status_success_k);
    auto completed = complete_call(route, client, steady_clock::now() + wait_limit_k);
    expect_true(completed.outcome.status == ucall_status_success_k, "{}", ucall_status_name(completed.outcome.status));
    ucall_bytes_view_t body {};
    if (completed.response) {
        ucall_client_response_body_t get {completed.response, &outcome, &body};
        ucall_client_response_body(&get);
        expect_true(outcome.status == ucall_status_success_k && body.length == payload.size());
    }
    ucall_client_free(client);
    ucall_server_free(route.server);
    // The response outlives both, so its bytes still come from the allocator.
    expect_true(ledger.allocations && ledger.live() && body.length == payload.size() &&
                !std::memcmp(body.data, payload.data(), body.length));
    ucall_client_response_free(completed.response);
    expect_true(!ledger.live(), "{} allocations outlived every owner", ledger.live());
}

/** Starves the server of allocations from a growing budget onward, across its init and its first
 *  exchange. Each budget completes the exchange, or fails cleanly with every byte returned. */
static void test_allocation_failure(sweep_cell_t const& cell) {
    std::string const payload(64, 'x');
    for (std::size_t budget = 0;; ++budget) {
        if (!expect_true(budget != 10000, "no budget completed the exchange")) return;
        allocation_ledger_t ledger;
        ledger.refuse_from = budget;
        echo_route_t route;
        ucall_outcome_t outcome {};
        ucall_network_interface_t network_interface {};
        network_interface.address = uc::bytes_view("127.0.0.1:0");
        network_interface.max_concurrent_connections = 1;
        ucall_server_options_t server_config {}, resolved {};
        server_config.interfaces = &network_interface;
        server_config.interfaces_count = 1;
        server_config.backend = cell.backend;
        ucall_server_init_t server_init {&route.server, &outcome, &server_config, &resolved};
        counted_network_t::server_t::server_init(&server_init, counting_allocator<uc::byte_t> {ledger});
        if (outcome.status == ucall_status_success_k) outcome.status = route.add();
        ucall_status_t completion = outcome.status;
        if (outcome.status == ucall_status_success_k) {
            ucall_client_t client {};
            ucall_client_options_t client_config {};
            client_config.max_concurrent_connections = 1;
            client_config.backend = cell.backend;
            ucall_client_init_t client_init {&client, &outcome, &client_config, nullptr};
            ucall_client_init(&client_init);
            if (!expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status))) return;
            std::string url = fmt::format("http://{}/echo/1", uc::text_view(resolved.interfaces[0].address));
            ucall_client_call_t call {};
            call.client = client;
            call.outcome = &outcome;
            call.url = uc::bytes_view(url);
            call.verb = ucall_verb_post_k;
            call.body = uc::bytes_view(payload);
            ucall_client_call(&call);
            expect_true(outcome.status == ucall_status_success_k);
            auto completed = complete_call(route, client, steady_clock::now() + 500ms);
            completion = completed.outcome.status;
            if (completed.response) {
                ucall_bytes_view_t body {};
                ucall_client_response_body_t get {completed.response, &outcome, &body};
                ucall_client_response_body(&get);
                bool const echoed = body.length == payload.size() && !std::memcmp(body.data, payload.data(), 64);
                expect_true(echoed, "budget {} answered {} bytes", budget, body.length);
                ucall_client_response_free(completed.response);
            }
            ucall_client_free(client);
        }
        ucall_server_free(route.server);
        expect_true(!ledger.live(), "budget {} kept {} allocations", budget, ledger.live());
        // A starved connection can only be dropped, which its client sees as a close or a reset.
        expect_true(completion == ucall_status_success_k || completion == ucall_status_out_of_memory_k ||
                        completion == ucall_status_connection_closed_k || completion == ucall_status_io_k,
                    "budget {} ended with {}", budget, ucall_status_name(completion));
        if (completion == ucall_status_success_k) { return; }
    }
}

#pragma endregion Allocators

#pragma region Faults

/** A server whose queue delays some transfers and resets others never answers with the wrong
 *  bytes, keeps serving new connections, and gives every descriptor back at its end. */
static case_result_t test_queue_faults() {
#if UCALL_WITH_POSIX
    split_mix_generator_t generator {case_stream_key()};
    std::size_t const descriptors_before = open_descriptors();
    {
        echo_route_t route;
        ucall_outcome_t outcome {};
        ucall_network_interface_t network_interface {};
        network_interface.address = uc::bytes_view("127.0.0.1:0");
        network_interface.max_concurrent_connections = 4;
        network_interface.max_pipelined_requests = 2;
        ucall_server_options_t config {}, resolved {};
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
        config.backend = ucall_io_backend_posix_k;
        ucall_server_init_t init {&route.server, &outcome, &config, &resolved};
        io::faulting_network_t::server_t::server_init(&init, {});
        if (!expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status))) return {};
        expect_true(route.add() == ucall_status_success_k);
        std::thread serving {[&] {
            ucall_outcome_t served {};
            ucall_server_take_calls_t take {route.server, &served, 0};
            ucall_server_take_calls(&take);
            expect_true(served.status == ucall_status_success_k, "serving ended {}", ucall_status_name(served.status));
        }};
        std::size_t answered = 0, dropped = 0, wrong = 0;
        raw_client_t client;
        std::size_t offset = 0;
        for (std::size_t round = 0; round != scaled_iterations(400); ++round) {
            if (client.descriptor < 0) {
                if (!expect_true(client.connect(uc::text_view(resolved.interfaces[0].address)))) return {};
                client.received.clear();
                offset = 0;
            }
            std::string const body = fmt::format("round {}", round);
            std::string const request = fmt::format("POST /echo/{} HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n{}",
                                                    round, body.size(), body);
            bool const written = client.write(uc::byte_span(request), request.size(), generator,
                                              steady_clock::now() + wait_limit_k);
            auto const response = written ? read_response(client, offset) : wire_response_t {};
            if (response.status == 200 && response.body == body) {
                ++answered;
                offset += response.length;
                continue;
            }
            // A reset transfer costs its connection, never a wrong reply.
            wrong += response.length != 0;
            ++dropped;
            client.close();
        }
        expect_true(!wrong, "{} replies had the wrong status or bytes", wrong);
        expect_true(answered > dropped, "{} requests answered against {} dropped", answered, dropped);
        client.close();
        ucall_server_stop(route.server);
        ucall_server_stop(route.server);
        serving.join();
        ucall_server_free(route.server);
    }
    std::size_t const descriptors_after = open_descriptors();
    expect_true(descriptors_after == descriptors_before, "{} descriptors open after, {} before", descriptors_after,
                descriptors_before);
    return {};
#else
    return case_result_t::skipped("built without UCALL_WITH_POSIX");
#endif
}

/** A client bound to a server's loop counts into that loop: calling the loop's own server, every
 *  byte one end sends the other receives, so the loop's two byte counters agree. */
static case_result_t test_bound_client_counts_into_its_loop() {
#if UCALL_WITH_POSIX
    echo_route_t route;
    ucall_outcome_t outcome {};
    ucall_network_interface_t network_interface {};
    network_interface.address = uc::bytes_view("127.0.0.1:0");
    network_interface.max_concurrent_connections = 2;
    ucall_server_options_t server_config {}, resolved {};
    server_config.interfaces = &network_interface;
    server_config.interfaces_count = 1;
    ucall_server_init_t server_init {&route.server, &outcome, &server_config, &resolved};
    ucall_server_init(&server_init);
    if (!expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status))) return {};
    expect_true(route.add() == ucall_status_success_k);
    ucall_client_t client {};
    ucall_client_options_t client_config {};
    client_config.server = route.server;
    client_config.max_concurrent_connections = 1;
    ucall_client_init_t client_init {&client, &outcome, &client_config, nullptr};
    ucall_client_init(&client_init);
    if (!expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status))) return {};
    std::string const url = fmt::format("http://{}/echo/1", uc::text_view(resolved.interfaces[0].address));
    std::string const payload(1024, 'b');
    ucall_client_call_t call {};
    call.client = client;
    call.outcome = &outcome;
    call.url = uc::bytes_view(url);
    call.verb = ucall_verb_post_k;
    call.body = uc::bytes_view(payload);
    ucall_client_call(&call);
    expect_true(outcome.status == ucall_status_success_k, "{}", ucall_status_name(outcome.status));
    ucall_completed_call_t completed {};
    std::size_t count = 0;
    for (auto const deadline = steady_clock::now() + wait_limit_k; !count && steady_clock::now() < deadline;) {
        ucall_server_take_call_t serve {route.server, &outcome, 0, 1000};
        ucall_server_take_call(&serve);
        ucall_client_take_completed_t take {client, &outcome, &completed, 1, &count, 0};
        ucall_client_take_completed(&take);
    }
    expect_true(count && completed.outcome.status == ucall_status_success_k, "the call ended {}",
                ucall_status_name(completed.outcome.status));
    if (completed.response) ucall_client_response_free(completed.response);
    ucall_event_loop_statistics_t counters {};
    ucall_server_event_loop_statistics_t query {route.server, &outcome, 0, &counters};
    ucall_server_event_loop_statistics(&query);
    expect_true(counters.bytes_sent == counters.bytes_received && counters.bytes_sent > 2 * payload.size(),
                "the loop sent {} bytes and received {}", counters.bytes_sent, counters.bytes_received);
    ucall_client_free(client);
    ucall_server_stop(route.server);
    ucall_server_stop(route.server);
    ucall_server_take_call_t last {route.server, &outcome, 0, 0};
    ucall_server_take_call(&last);
    ucall_server_free(route.server);
    return {};
#else
    return case_result_t::skipped("built without UCALL_WITH_POSIX");
#endif
}

#pragma endregion Faults

void test_loops_cell(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    if (cell.security == ucall_security_none_k && cell.cpu_class_ceiling == ucall_cpu_class_unknown_k) {
        test_allocator_propagation(cell);
        test_allocation_failure(cell);
    }
#if UCALL_OS_POSIX_
    if (cell.security == ucall_security_none_k) test_accept_exhaustion_sheds(cell, generator);
#endif
    if (cell.security == ucall_security_none_k && cell.cpu_class_ceiling == ucall_cpu_class_unknown_k &&
        cell.backend == ucall_io_backend_posix_k)
        test_cpu_class_ceiling();
}

void run_loops_cases(sweep_cell_t const& cell, sz::string_t const& cell_label) {
#if UCALL_OS_POSIX_
    if (cell.security == ucall_security_none_k) {
        run_cell_case(cell_label, "test_admission_across_loops", test_admission_across_loops, cell);
    }
#endif
    if (cell.security == ucall_security_none_k && cell.cpu_class_ceiling == ucall_cpu_class_unknown_k &&
        cell.backend == ucall_io_backend_posix_k) {
        run_cell_case(cell_label, "test_ring_refused_at_init_falls_back", test_ring_refused_at_init_falls_back);
        run_cell_case(cell_label, "test_origin_reuse_and_fairness", test_origin_reuse_and_fairness);
        run_cell_case(cell_label, "test_client_batches_sends", test_client_batches_sends);
        run_cell_case(cell_label, "test_queue_faults", test_queue_faults);
        run_cell_case(cell_label, "test_bound_client_counts_into_its_loop", test_bound_client_counts_into_its_loop);
    }
#if UCALL_OS_POSIX_
    if (cell.security == ucall_security_none_k && cell.cpu_class_ceiling == ucall_cpu_class_unknown_k &&
        cell.backend == ucall_io_backend_posix_k) {
        run_cell_case(cell_label, "test_backend_parity", test_backend_parity, cell);
    }
#endif
}

} // namespace unum::ucall::test::network
