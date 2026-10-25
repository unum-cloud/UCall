/**
 *  @file test/uring.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Registered I/O ownership after a failed submission syscall.
 *
 *  Every case skips when the kernel lacks the io_uring generation it drives.
 */
#include <cstring> // `std::memcmp`

#include <algorithm> // `std::fill`
#include <vector>    // `std::vector`

#include "ucall/uring612.hpp"
#include "ucall/uring700.hpp"

#include "harness.hpp" // `expect`, `require`, `run_test`, `counting_allocator`, `loopback_pair`

using namespace unum::ucall;
using namespace unum::ucall::test;

/** Sends all of @p bytes through @p descriptor, blocking. */
[[nodiscard]] static bool send_all(int descriptor, span<byte_t const> bytes) noexcept {
    while (!bytes.empty()) {
        ssize_t const count = ::send(descriptor, bytes.data(), bytes.size(), MSG_NOSIGNAL);
        if (count <= 0) return false;
        bytes = bytes.subspan(static_cast<std::size_t>(count));
    }
    return true;
}

/** Checks the registered socket @p handle has `TCP_NODELAY`, through a descriptor it installs. */
template <typename engine_type_>
static std::size_t expect_nodelay(engine_type_& engine, descriptor_t handle) {
    auto* submission = engine.entry();
    if (expect(submission)) return 1;
    engine.control.result.reset();
    io_uring_prep_fixed_fd_install(submission, static_cast<int>(engine_type_::registered_socket_t::index_of(handle)),
                                   0);
    io_uring_sqe_set_data64(submission, engine.tag(&engine.control, engine.control_tag_k));
    auto descriptor = engine.wait_control();
    if (expect(descriptor >= 0, "installing failed with {}", descriptor)) return 1;
    int enabled {};
    socket_length_t length = sizeof(enabled);
    std::size_t failures = expect(getsockopt(descriptor, IPPROTO_TCP, TCP_NODELAY, &enabled, &length) == 0 &&
                                  enabled == 1);
    socket_close(descriptor);
    return failures;
}

template <typename engine_type_>
static case_result_t failed_submission() {
    engine_type_ engine;
    auto status = engine.open(8, 4);
    if (status == ucall_status_unsupported_k) return case_result_t::skipped("the kernel lacks this generation");
    require(0, status == ucall_status_success_k, "{}", ucall_status_name(status));
    std::size_t failures = 0;
    auto direct = engine.open_socket(AF_INET);
    require(failures, direct >= 0);
    failures += expect_nodelay(engine, direct);
    failures += expect(engine.close_socket(direct) == 0);
    loopback_pair_t sockets = loopback_pair();
    require(failures, sockets.connected());
    auto owned = engine.import_socket(sockets.client);
    require(failures, owned >= 0);
    sockets.client = -1;
    failures += expect_nodelay(engine, owned);
    byte_t content[1] {byte_t {42}};
    io_request_t sending {io_operation_t::send_k, owned, content, sizeof(content)};
    io_request_t receiving {io_operation_t::receive_k, owned, nullptr, engine.page};
    require(failures, engine.submit(sending) == ucall_status_success_k);
    require(failures, engine.submit(receiving) == ucall_status_success_k);
    require(failures, engine.enter(0, 0) >= 0);
    byte_t received {};
    failures += expect(recv(sockets.peer, &received, sizeof(received), 0) == 1 && received == content[0]);

    io_request_t unsubmitted {io_operation_t::send_k, owned, content, sizeof(content)};
    failures += expect(engine.submit(unsubmitted) == ucall_status_success_k);
    auto descriptor = engine.ring.ring_fd;
    auto enter_descriptor = engine.ring.enter_ring_fd;
    engine.ring.ring_fd = -1;
    engine.ring.enter_ring_fd = -1;
    auto failure = engine.enter(0, 0);
    failures += expect(failure < 0);
    engine.ring.ring_fd = descriptor;
    engine.ring.enter_ring_fd = enter_descriptor;
    engine.fault = failure;
    engine.stop();

    failures += expect(!engine.is_open() && engine.registrations == engine.registration_none_k);
    failures += expect(!engine.receive_ring && engine.storage);
    failures += expect(!engine.has_kernel_work());
    failures += expect(recv(sockets.peer, &received, sizeof(received), 0) == 0);
    return failures;
}

template <typename engine_type_>
static case_result_t streamed_transmit() {
    engine_type_ engine;
    auto status = engine.open(1, 1);
    if (status == ucall_status_unsupported_k) return case_result_t::skipped("the kernel lacks this generation");
    require(0, status == ucall_status_success_k, "{}", ucall_status_name(status));
    std::size_t failures = 0;
    loopback_pair_t sockets = loopback_pair();
    require(failures, sockets.connected());
    auto owned = engine.import_socket(sockets.client);
    require(failures, owned >= 0);
    sockets.client = -1;
    require(failures, nonblocking(sockets.peer));
    std::vector<byte_t> payload(65536, byte_t {85}), received(payload.size());
    std::size_t sent {}, read {};
    bool pending {};
    io_request_t sending {io_operation_t::send_k, owned};
    auto deadline = deadline_after(1000000);
    while (sent != payload.size() || read != payload.size()) {
        if (!pending && sent != payload.size()) {
            sending.data = payload.data() + sent;
            sending.length = payload.size() - sent;
            sending.deadline = deadline;
            require(failures, engine.submit(sending) == ucall_status_success_k);
            pending = true;
        }
        io_completion_t completed {};
        if (engine.poll(span<io_completion_t> {&completed, &completed + 1}, io_wait_t::nonblocking_k)) {
            require(failures, completed.request == &sending && completed.result > 0, "sending ended with {}",
                    completed.result);
            sent += static_cast<std::size_t>(completed.result);
            pending = false;
        }
        if (read != received.size()) {
            auto count = recv(sockets.peer, received.data() + read, received.size() - read, 0);
            if (count > 0) read += static_cast<std::size_t>(count);
            else require(failures, count < 0 && io_pending(-errno), "receiving ended with {}", count);
        }
        require(failures, monotonic_ns() < deadline, "{} sent and {} read of {}", sent, read, payload.size());
    }
    failures += expect(received == payload);
    failures += expect(engine.close_socket(owned) == 0);
    return failures;
}

static case_result_t test_uring612_failed_submission() { return failed_submission<linux_uring612_engine_t>(); }
static case_result_t test_uring700_failed_submission() { return failed_submission<linux_uring700_engine_t>(); }
static case_result_t test_uring612_streamed_transmit() { return streamed_transmit<linux_uring612_engine_t>(); }
static case_result_t test_uring700_streamed_transmit() { return streamed_transmit<linux_uring700_engine_t>(); }

static case_result_t test_uring700_paused_receive() {
    allocation_counts_t counts;
    std::size_t failures = 0;
    {
        linux_uring700_engine<counting_allocator<byte_t>> engine {counting_allocator<byte_t> {counts}};
        auto status = engine.open(8, 4);
        if (status == ucall_status_unsupported_k) return case_result_t::skipped("the kernel lacks this generation");
        require(failures, status == ucall_status_success_k, "{}", ucall_status_name(status));
        loopback_pair_t held = loopback_pair(), other = loopback_pair();
        require(failures, held.connected() && other.connected());
        auto first = engine.import_socket(held.client);
        auto second = engine.import_socket(other.client);
        require(failures, first >= 0 && second >= 0);
        held.client = other.client = -1;
        auto original = engine.page * (engine.buffer_count + 1);
        std::vector<byte_t> payload(original + engine.page, byte_t {17});
        std::fill(payload.begin() + static_cast<std::ptrdiff_t>(original), payload.end(), byte_t {34});
        io_request_t receiving {io_operation_t::receive_k, first, nullptr, engine.page};
        require(failures, engine.submit(receiving) == ucall_status_success_k);
        require(failures, send_all(held.peer, span<byte_t const> {payload}.first(original)));
        io_completion_t completed[2] {};
        require(failures, engine.poll(completed, io_wait_t::blocking_k, deadline_after(1000000)) == 1);
        require(failures, completed[0].result > 0, "receiving ended with {}", completed[0].result);
        auto received = static_cast<std::size_t>(completed[0].result);
        failures += expect(std::memcmp(completed[0].data, payload.data(), received) == 0);

        announce("a paused socket parks its backlog");
        auto* owner = engine.socket_slot(first);
        auto deadline = deadline_after(1000000);
        while (owner->receive_head == engine.absent_k) {
            auto const spare = span<io_completion_t> {completed}.subspan(1);
            failures += expect(engine.poll(spare, io_wait_t::nonblocking_k) == 0);
            require(failures, monotonic_ns() < deadline, "the backlog never filled");
        }
        engine.receive_pause(first);
        engine.release(completed[0]);
        require(failures, send_all(held.peer, span<byte_t const> {payload}.subspan(original)));

        byte_t marker[1] {byte_t {51}};
        io_request_t independent {io_operation_t::receive_k, second, nullptr, engine.page};
        require(failures, engine.submit(independent) == ucall_status_success_k);
        require(failures, send_all(other.peer, marker));
        require(failures, engine.poll(completed, io_wait_t::blocking_k, deadline) == 1);
        failures += expect(completed[0].request == &independent && completed[0].result == 1 &&
                           completed[0].data[0] == marker[0]);
        engine.release(completed[0]);
        while (owner->receive_in_flight()) {
            failures += expect(engine.poll(completed, io_wait_t::nonblocking_k) == 0);
            require(failures, monotonic_ns() < deadline, "the paused receive never retired");
        }
        failures += expect(owner->receive_head == engine.absent_k && !owner->backlog.empty());
        failures += expect(engine.available_buffers == engine.buffer_count);

        announce("pausing with a receive in flight, then cancelling one");
        require(failures, engine.submit(independent) == ucall_status_success_k);
        engine.receive_pause(second);
        require(failures, send_all(other.peer, marker));
        require(failures, engine.poll(completed, io_wait_t::blocking_k, deadline) == 1);
        failures += expect(completed[0].request == &independent && completed[0].result == 1 &&
                           completed[0].data[0] == marker[0]);
        engine.release(completed[0]);
        require(failures, engine.submit(independent) == ucall_status_success_k);
        failures += expect(engine.cancel(independent) == ucall_status_success_k);
        require(failures, engine.poll(completed, io_wait_t::blocking_k, deadline) == 1);
        failures += expect(completed[0].request == &independent && completed[0].result == -ECANCELED &&
                           !completed[0].lease);

        announce("draining the parked backlog in order");
        while (received != payload.size()) {
            receiving.deadline = deadline_after(1000000);
            require(failures, engine.submit(receiving) == ucall_status_success_k);
            require(failures, engine.poll(completed, io_wait_t::blocking_k, receiving.deadline) == 1);
            require(failures, completed[0].request == &receiving && completed[0].result > 0, "receiving ended with {}",
                    completed[0].result);
            auto length = static_cast<std::size_t>(completed[0].result);
            require(failures, length <= payload.size() - received);
            failures += expect(std::memcmp(completed[0].data, payload.data() + received, length) == 0);
            received += length;
            engine.release(completed[0]);
        }
        require(failures, engine.submit(receiving) == ucall_status_success_k);
        failures += expect(engine.close_socket(first) == 0);
        require(failures, engine.poll(completed, io_wait_t::nonblocking_k) == 1);
        failures += expect(completed[0].request == &receiving && completed[0].result == -ECANCELED &&
                           !completed[0].lease);
        auto reused = engine.open_socket(AF_INET);
        failures += expect(reused == first);
        failures += expect(engine.close_socket(reused) == 0 && engine.close_socket(second) == 0);
        engine.stop();
        failures += expect(!engine.has_kernel_work());
    }
    failures += expect(counts.allocations && !counts.bytes && counts.allocations == counts.deallocations,
                       "{} allocations, {} deallocations, {} bytes kept", counts.allocations, counts.deallocations,
                       counts.bytes);
    return failures;
}

/** A failed allocation during setup answers out-of-memory, returning every byte taken before it. */
static case_result_t test_uring612_allocation_failure() {
    bool kernel_available = false;
    {
        linux_uring612_engine_t probe;
        kernel_available = probe.open(1, 1) != ucall_status_unsupported_k;
    }
    std::size_t failures = 0;
    // Only a kernel with rings reaches the sixth allocation.
    for (auto fail_from : {std::size_t {0}, std::size_t {4}, std::size_t {5}}) {
        if (fail_from == 5 && !kernel_available) continue;
        allocation_counts_t counts;
        counts.fail_from = fail_from;
        {
            linux_uring612_engine<counting_allocator<byte_t>> engine {counting_allocator<byte_t> {counts}};
            auto status = engine.open(4, 4);
            failures += expect(status == ucall_status_out_of_memory_k, "failing allocation {} answered {}", fail_from,
                               ucall_status_name(status));
        }
        failures += expect(!counts.bytes && counts.allocations == counts.deallocations,
                           "failing allocation {} kept {} bytes", fail_from, counts.bytes);
    }
    return failures;
}

int main(int, char** argv) {
    install_test_signal_handlers();
    fmt::print("Hi, dear tester! You look nice today!\n");
    configure_tests();

    suite_totals_t totals {.program = argv[0]};
    run_test(totals, "test_uring612_failed_submission", test_uring612_failed_submission);
    run_test(totals, "test_uring700_failed_submission", test_uring700_failed_submission);
    run_test(totals, "test_uring612_allocation_failure", test_uring612_allocation_failure);
    run_test(totals, "test_uring612_streamed_transmit", test_uring612_streamed_transmit);
    run_test(totals, "test_uring700_streamed_transmit", test_uring700_streamed_transmit);
    run_test(totals, "test_uring700_paused_receive", test_uring700_paused_receive);
    return suite_exit_code(totals);
}
