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
            run_cell_case(label, "test_slice_waits_a_round", test_slice_waits_a_round);
            run_cell_case(label, "test_paused_receive", test_paused_receive);
        });
}

} // namespace unum::ucall::test::io
