/**
 *  @file test/io/linux_uring612_queue.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The io_uring 6.12 queue under every admitted CPU class: the shared queue and ring
 *      cases, and the ones only this generation has.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build

#include "io/queues.hpp" // `run_queue_cases`, `test_failed_submission`, `test_zero_copy_sends`

namespace unum::ucall::test::io {

/** Exhausting the buffers provided at open doubles them from memory already reserved. */
static case_result_t test_provides_past_two_buffers() {
    allocation_ledger_t ledger;
    {
        linux_uring612_queue<counting_allocator<byte_t>> queue {counting_allocator<byte_t> {ledger}};
        auto status = queue.open(8, 8192);
        if (status == ucall_status_unsupported_k) return case_result_t::skipped(generation_refused_k);
        if (!expect_true(status == ucall_status_success_k, "{}", ucall_status_name(status))) return {};
        auto& provided = queue.state.provided;
        if (provided.buffer_count() < 4) return case_result_t::skipped("needs a pool past two buffers");
        expect_true(provided.provided_buffers == 2 && provided.available_buffers == 2);
        loopback_pair_t sockets = loopback_pair();
        if (!expect_true(sockets.connected())) return {};
        auto const socket = queue.import_socket(std::exchange(sockets.client, -1));
        if (!expect_true(socket >= 0)) return {};
        std::size_t const allocations = ledger.allocations;
        std::vector<byte_t> chunk(65536, byte_t {7});
        std::vector<io_completion_t> unreleased;
        io_request_t receiving {.operation = io_operation_t::receive_k, .descriptor = socket};
        auto const deadline = deadline_after(10000000);
        while (provided.provided_buffers == 2) {
            if (!expect_true(send_all(sockets.peer, chunk))) return {};
            for (std::size_t landed = 0; landed != chunk.size();) {
                io_completion_t completed {};
                queue.submit(receiving);
                if (!expect_true(queue.poll({&completed, 1}, io_wait_t::blocking_k, deadline) == 1)) return {};
                if (!expect_true(completed.result > 0, "receiving ended with {}", completed.result)) return {};
                landed += static_cast<std::size_t>(completed.result);
                unreleased.push_back(completed);
            }
            if (!expect_true(monotonic_ns() < deadline, "{} slices kept two buffers", unreleased.size())) return {};
        }
        expect_true(provided.provided_buffers == 4 && ledger.allocations == allocations,
                    "{} buffers provided after {} allocations", provided.provided_buffers,
                    ledger.allocations - allocations);
        for (auto const& completed : unreleased) queue.release(completed);
        expect_true(provided.available_buffers == provided.provided_buffers);
        expect_true(queue.close_socket(socket) == 0);
    }
    expect_true(!ledger.live_bytes && ledger.allocations == ledger.deallocations);
    return {};
}

/** A failed allocation during setup answers out-of-memory, returning every byte taken before it. */
static void test_ring_allocation_failure() {
    bool kernel_available = false;
    {
        linux_uring612_queue_t probe;
        kernel_available = probe.open(1, 1) != ucall_status_unsupported_k;
    }
    // Only a kernel with rings reaches the seventh allocation, the probe's.
    for (auto refuse_from : {std::size_t {0}, std::size_t {4}, std::size_t {6}}) {
        if (refuse_from == 6 && !kernel_available) continue;
        allocation_ledger_t ledger;
        ledger.refuse_from = refuse_from;
        {
            linux_uring612_queue<counting_allocator<byte_t>> queue {counting_allocator<byte_t> {ledger}};
            auto status = queue.open(4, 4);
            expect_true(status == ucall_status_out_of_memory_k, "failing allocation {} answered {}", refuse_from,
                        ucall_status_name(status));
        }
        expect_true(!ledger.live_bytes && ledger.allocations == ledger.deallocations,
                    "failing allocation {} kept {} bytes", refuse_from, ledger.live_bytes.load());
    }
}

void run_linux_uring612_queue_cases() {
    run_queue_cases<linux_uring612_queue_t>(
        ucall_io_backend_linux_uring612_k, []<typename queue_type_>(sz::string_t const& label) {
            run_test_case(called("test_queue_cell", label).c_str(), [] {
                return keeping_descriptors([] {
                    split_mix_generator_t generator {case_stream_key()};
                    test_queue_duplex<queue_type_>(generator);
                    test_accept_batch<queue_type_>();
                    test_ring_allocation_failure();
                });
            });
            run_cell_case(label, "test_failed_submission", test_failed_submission<queue_type_>);
            run_cell_case(label, "test_streamed_transmit", test_streamed_transmit<queue_type_>);
            run_cell_case(label, "test_end_of_stream", test_end_of_stream<queue_type_>);
            run_cell_case(label, "test_sockets_interleave", test_sockets_interleave<queue_type_>);
            run_cell_case(label, "test_registered_direct_files", test_registered_direct_files<queue_type_>);
            run_cell_case(label, "test_zero_copy_sends", test_zero_copy_sends<queue_type_>);
            run_cell_case(label, "test_provides_past_two_buffers", test_provides_past_two_buffers);
        });
}

} // namespace unum::ucall::test::io
