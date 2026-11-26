/**
 *  @file test/io/linux_uring618_queue.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The io_uring 6.18 queue under every admitted CPU class: the shared queue and ring
 *      cases, and the ones only this generation has.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build

#include "io/queues.hpp" // `run_queue_cases`, `test_failed_submission`, `test_zero_copy_sends`

namespace unum::ucall::test::io {

/** A request landing before its receive waits one round uncopied, and past that leaves the pool. */
static case_result_t test_slice_waits_a_round() {
    allocation_ledger_t ledger;
    {
        linux_uring618_queue<counting_allocator<byte_t>> queue {counting_allocator<byte_t> {ledger}};
        auto status = queue.open(8, 4);
        if (status == ucall_status_unsupported_k) return case_result_t::skipped(generation_refused_k);
        if (!expect_true(status == ucall_status_success_k, "{}", ucall_status_name(status))) return {};
        loopback_pair_t sockets = loopback_pair();
        if (!expect_true(sockets.connected())) return {};
        auto descriptor = queue.import_socket(sockets.client);
        if (!expect_true(descriptor >= 0)) return {};
        sockets.client = -1;
        byte_t const message[16] {byte_t {7}};
        auto deadline = util::deadline_after(1000000);
        io_request_t receiving {.operation = io_operation_t::receive_k, .descriptor = descriptor};
        io_completion_t completed[2] {};
        queue.submit(receiving);
        if (!expect_true(send_all(sockets.peer, message))) return {};
        if (!expect_true(queue.poll(completed, io_wait_t::blocking_k, deadline) == 1)) return {};
        queue.release(completed[0]);

        auto* owner = queue.socket_slots.find(descriptor);
        auto const copied = queue.statistics.bytes_copied;
        if (!expect_true(send_all(sockets.peer, message))) return {};
        while (owner->waiting_slice.empty()) {
            queue.reap();
            if (!expect_true(monotonic_ns() < deadline, "the slice never landed")) return {};
            [[maybe_unused]] int const entered = queue.state.enter(0, 0);
        }
        queue.submit(receiving);
        if (!expect_true(queue.poll(completed, io_wait_t::blocking_k, deadline) == 1)) return {};
        expect_true(completed[0].result == sizeof(message) && queue.statistics.bytes_copied == copied,
                    "{} bytes arrived and {} were copied", completed[0].result, queue.statistics.bytes_copied - copied);
        queue.release(completed[0]);

        if (!expect_true(send_all(sockets.peer, message))) return {};
        while (owner->backlog.empty()) {
            expect_true(queue.poll(span<io_completion_t> {completed}.first(1), io_wait_t::nonblocking_k) == 0);
            if (!expect_true(monotonic_ns() < deadline, "the slice never left the pool")) return {};
        }
        expect_true(owner->waiting_slice.empty() && owner->backlog.size() == sizeof(message));
    }
    return {};
}

static case_result_t test_paused_receive() {
    allocation_ledger_t ledger;
    {
        linux_uring618_queue<counting_allocator<byte_t>> queue {counting_allocator<byte_t> {ledger}};
        auto status = queue.open(8, 4);
        if (status == ucall_status_unsupported_k) return case_result_t::skipped(generation_refused_k);
        if (!expect_true(status == ucall_status_success_k, "{}", ucall_status_name(status))) return {};
        loopback_pair_t held = loopback_pair(), other = loopback_pair();
        if (!expect_true(held.connected() && other.connected())) return {};
        auto first = queue.import_socket(held.client);
        auto second = queue.import_socket(other.client);
        if (!expect_true(first >= 0 && second >= 0)) return {};
        held.client = other.client = -1;
        auto& provided = queue.state.provided;
        auto original = provided.buffer_bytes() * (provided.buffer_count() + 1);
        std::vector<byte_t> payload(original + provided.buffer_bytes(), byte_t {17});
        std::fill(payload.begin() + static_cast<std::ptrdiff_t>(original), payload.end(), byte_t {34});
        io_request_t receiving {.operation = io_operation_t::receive_k, .descriptor = first};
        queue.submit(receiving);
        if (!expect_true(send_all(held.peer, span<byte_t const> {payload}.first(original)))) return {};
        io_completion_t completed[2] {};
        if (!expect_true(queue.poll(completed, io_wait_t::blocking_k, util::deadline_after(1000000)) == 1)) return {};
        if (!expect_true(completed[0].result > 0, "receiving ended with {}", completed[0].result)) return {};
        auto received = static_cast<std::size_t>(completed[0].result);
        expect_true(std::memcmp(completed[0].data, payload.data(), received) == 0);

        auto* owner = queue.socket_slots.find(first);
        auto deadline = util::deadline_after(1000000);
        while (owner->backlog.empty()) {
            auto const spare = span<io_completion_t> {completed}.subspan(1);
            expect_true(queue.poll(spare, io_wait_t::nonblocking_k) == 0);
            if (!expect_true(monotonic_ns() < deadline, "the backlog never filled")) return {};
        }
        queue.receive_pause(first);
        queue.release(completed[0]);
        if (!expect_true(send_all(held.peer, span<byte_t const> {payload}.subspan(original)))) return {};

        byte_t marker[1] {byte_t {51}};
        io_request_t independent {.operation = io_operation_t::receive_k, .descriptor = second};
        queue.submit(independent);
        if (!expect_true(send_all(other.peer, marker))) return {};
        if (!expect_true(queue.poll(completed, io_wait_t::blocking_k, deadline) == 1)) return {};
        expect_true(completed[0].request == &independent && completed[0].result == 1 &&
                    completed[0].data[0] == marker[0]);
        queue.release(completed[0]);
        while (owner->receive_in_flight()) {
            expect_true(queue.poll(completed, io_wait_t::nonblocking_k) == 0);
            if (!expect_true(monotonic_ns() < deadline, "the paused receive never retired")) return {};
        }
        expect_true(!owner->backlog.empty());
        expect_true(provided.available_buffers == provided.provided_buffers);

        queue.submit(independent);
        queue.receive_pause(second);
        if (!expect_true(send_all(other.peer, marker))) return {};
        if (!expect_true(queue.poll(completed, io_wait_t::blocking_k, deadline) == 1)) return {};
        expect_true(completed[0].request == &independent && completed[0].result == 1 &&
                    completed[0].data[0] == marker[0]);
        queue.release(completed[0]);
        queue.submit(independent);
        expect_true(queue.cancel(independent) == ucall_status_success_k);
        if (!expect_true(queue.poll(completed, io_wait_t::blocking_k, deadline) == 1)) return {};
        expect_true(completed[0].request == &independent && completed[0].result == -ECANCELED &&
                    !completed[0].release_token);

        while (received != payload.size()) {
            receiving.deadline = util::deadline_after(1000000);
            queue.submit(receiving);
            if (!expect_true(queue.poll(completed, io_wait_t::blocking_k, receiving.deadline) == 1)) return {};
            if (!expect_true(completed[0].request == &receiving && completed[0].result > 0, "receiving ended with {}",
                             completed[0].result))
                return {};
            auto length = static_cast<std::size_t>(completed[0].result);
            if (!expect_true(length <= payload.size() - received)) return {};
            expect_true(std::memcmp(completed[0].data, payload.data() + received, length) == 0);
            received += length;
            queue.release(completed[0]);
        }
        queue.submit(receiving);
        expect_true(queue.close_socket(first) == 0);
        if (!expect_true(queue.poll(completed, io_wait_t::nonblocking_k) == 1)) return {};
        expect_true(completed[0].request == &receiving && completed[0].result == -ECANCELED &&
                    !completed[0].release_token);
        auto reused = queue.open_socket(AF_INET);
        expect_true(reused == first);
        expect_true(queue.close_socket(reused) == 0 && queue.close_socket(second) == 0);
        queue.stop();
        expect_true(!queue.has_kernel_work());
    }
    expect_true(ledger.allocations && !ledger.live_bytes && ledger.allocations == ledger.deallocations,
                "{} allocations, {} deallocations, {} bytes kept", ledger.allocations.load(),
                ledger.deallocations.load(), ledger.live_bytes.load());
    return {};
}

/** A receive naming room takes what the stream already holds out of the pool first, then lands in
 *  that room uncopied once its stream was cancelled, a cancel ends one waiting there, and the next
 *  receive into the pool arms the stream again. A deadline ends one with @c -ETIMEDOUT on either
 *  path: waiting in the queue for an armed stream's cancel, and in the kernel beside its linked
 *  timeout once the stream ended; the shortest deadline passes before any byte could arrive. */
static case_result_t test_receive_in_place() {
    linux_uring618_queue_t queue;
    auto status = queue.open(8, 4);
    if (status == ucall_status_unsupported_k) return case_result_t::skipped(generation_refused_k);
    if (!expect_true(status == ucall_status_success_k, "{}", ucall_status_name(status))) return {};
    loopback_pair_t sockets = loopback_pair();
    if (!expect_true(sockets.connected())) return {};
    auto descriptor = queue.import_socket(std::exchange(sockets.client, -1));
    if (!expect_true(descriptor >= 0)) return {};
    auto* owner = queue.socket_slots.find(descriptor);
    auto const deadline = util::deadline_after(1000000);
    byte_t const marker[16] {byte_t {7}};
    io_completion_t completed[1] {};
    io_request_t streaming {.operation = io_operation_t::receive_k, .descriptor = descriptor};
    queue.submit(streaming);
    if (!expect_true(send_all(sockets.peer, marker))) return {};
    if (!expect_true(queue.poll(completed, io_wait_t::blocking_k, deadline) == 1)) return {};
    expect_true(completed[0].result == sizeof(marker) && completed[0].release_token, "the stream answered {}",
                completed[0].result);
    queue.release(completed[0]);
    if (!expect_true(send_all(sockets.peer, marker))) return {};
    while (owner->waiting_slice.empty()) {
        queue.reap();
        if (!expect_true(monotonic_ns() < deadline, "the slice never landed")) return {};
        [[maybe_unused]] int const entered = queue.state.enter(0, 0);
    }

    std::vector<byte_t> body(queue.state.page_bytes * 16), room(body.size());
    for (std::size_t index = 0; index != body.size(); ++index) body[index] = static_cast<byte_t>(index % 251);
    util::io_vector_t vector {};
    // The receive in place fills the room past what it already holds.
    auto aim_past = [&](std::size_t filled) { vector = {room.data() + filled, room.size() - filled}; };
    aim_past(0);
    io_request_t in_place {.operation = io_operation_t::receive_k,
                           .descriptor = descriptor,
                           .data = reinterpret_cast<byte_t*>(&vector),
                           .length = 1};
    queue.submit(in_place);
    if (!expect_true(queue.poll(completed, io_wait_t::blocking_k, deadline) == 1)) return {};
    expect_true(
        completed[0].request == &in_place && completed[0].result == sizeof(marker) && completed[0].release_token,
        "the held slice answered {}", completed[0].result);
    queue.release(completed[0]);

    auto const copied = queue.statistics.bytes_copied;
    std::size_t received = 0;
    queue.submit(in_place);
    if (!expect_true(send_all(sockets.peer, body))) return {};
    while (received != body.size()) {
        if (!expect_true(queue.poll(completed, io_wait_t::blocking_k, deadline) == 1)) return {};
        if (!expect_true(completed[0].request == &in_place && completed[0].result > 0 && !completed[0].release_token,
                         "receiving in place ended with {}", completed[0].result))
            return {};
        received += static_cast<std::size_t>(completed[0].result);
        aim_past(received);
        if (received != body.size()) queue.submit(in_place);
    }
    expect_true(room == body && queue.statistics.bytes_copied == copied, "{} bytes copied landing {} in place",
                queue.statistics.bytes_copied - copied, body.size());
    expect_true(!owner->receive_in_flight(), "the stream stayed armed beside a receive in place");

    aim_past(0);
    queue.submit(in_place);
    expect_true(queue.cancel(in_place) == ucall_status_success_k);
    if (!expect_true(queue.poll(completed, io_wait_t::blocking_k, deadline) == 1)) return {};
    expect_true(completed[0].request == &in_place && completed[0].result == -ECANCELED && !completed[0].release_token,
                "the cancelled receive ended with {}", completed[0].result);

    auto const rearms = queue.statistics.receive_rearms;
    queue.submit(streaming);
    if (!expect_true(send_all(sockets.peer, marker))) return {};
    if (!expect_true(queue.poll(completed, io_wait_t::blocking_k, deadline) == 1)) return {};
    expect_true(completed[0].request == &streaming && completed[0].result == sizeof(marker) &&
                    completed[0].release_token && queue.statistics.receive_rearms > rearms,
                "the stream answered {} after {} re-arms", completed[0].result,
                queue.statistics.receive_rearms - rearms);
    queue.release(completed[0]);

    // The stream is armed again, so the receive waits in the queue for its cancel.
    in_place.deadline = util::deadline_after(1);
    queue.submit(in_place);
    expect_true(owner->receive_stage == linux_uring618_queue_t::receive_stage_t::cancelling_k &&
                    owner->receive_operation != absent_k,
                "the receive left for the kernel beside an armed stream");
    if (!expect_true(queue.poll(completed, io_wait_t::blocking_k, deadline) == 1)) return {};
    expect_true(completed[0].request == &in_place && completed[0].result == -ETIMEDOUT,
                "waiting for the cancel past its deadline ended with {}", completed[0].result);
    while (owner->receive_in_flight()) {
        expect_true(queue.poll(completed, io_wait_t::nonblocking_k) == 0);
        if (!expect_true(monotonic_ns() < deadline, "the cancelled stream never ended")) return {};
    }
    queue.submit(in_place);
    expect_true(owner->receive_operation == absent_k, "the receive waited in the queue beside an ended stream");
    if (!expect_true(queue.poll(completed, io_wait_t::blocking_k, deadline) == 1)) return {};
    expect_true(completed[0].request == &in_place && completed[0].result == -ETIMEDOUT,
                "the kernel's receive past its deadline ended with {}", completed[0].result);
    expect_true(queue.close_socket(descriptor) == 0);
    queue.stop();
    expect_true(!queue.has_kernel_work());
    return {};
}

void run_linux_uring618_queue_cases() {
    run_queue_cases<linux_uring618_queue_t>(
        ucall_io_backend_linux_uring618_k, []<typename queue_type_>(sz::string_t const& label) {
            run_test_case(called("test_queue_cell", label).c_str(), [] {
                return keeping_descriptors([] {
                    split_mix_generator_t generator {case_stream_key()};
                    test_queue_duplex<queue_type_>(generator);
                    test_gathered_send<queue_type_>(generator);
                    test_wait_follows_rounds<queue_type_>();
                    test_accept_batch<queue_type_>();
                });
            });
            run_cell_case(label, "test_failed_submission", test_failed_submission<queue_type_>);
            run_cell_case(label, "test_streamed_transmit", test_streamed_transmit<queue_type_>);
            run_cell_case(label, "test_end_of_stream", test_end_of_stream<queue_type_>);
            run_cell_case(label, "test_sockets_interleave", test_sockets_interleave<queue_type_>);
            run_cell_case(label, "test_registered_direct_files", test_registered_direct_files<queue_type_>);
            run_cell_case(label, "test_zero_copy_sends", test_zero_copy_sends<queue_type_>);
            run_cell_case(label, "test_ring_receive_in_place", test_ring_receive_in_place<queue_type_>);
            run_cell_case(label, "test_ring_retains_while_spare", test_ring_retains_while_spare<queue_type_>);
            run_cell_case(label, "test_slice_waits_a_round", test_slice_waits_a_round);
            run_cell_case(label, "test_paused_receive", test_paused_receive);
            run_cell_case(label, "test_ring_past_file_table", test_ring_past_file_table<queue_type_>);
            run_cell_case(label, "test_receive_in_place", test_receive_in_place);
        });
}

} // namespace unum::ucall::test::io
