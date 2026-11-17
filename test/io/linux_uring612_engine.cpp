/**
 *  @file test/io/linux_uring612_engine.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The io_uring 6.12 engine under every admitted CPU class: the shared engine and ring
 *      cases, and the ones only this generation has.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build

#include "io/engines.hpp" // `run_engine_cases`, `test_failed_submission`, `test_zero_copy_sends`

namespace unum::ucall::test::io {

/** Exhausting the buffers provided at open doubles them from memory already reserved. */
static case_result_t test_provides_past_two_buffers() {
    allocation_ledger_t ledger;
    {
        linux_uring612_engine<counting_allocator<byte_t>> engine {counting_allocator<byte_t> {ledger}};
        auto status = engine.open(8, 8192);
        if (status == ucall_status_unsupported_k) return case_result_t::skipped(generation_refused_k);
        if (!expect_true(status == ucall_status_success_k, "{}", ucall_status_name(status))) return {};
        auto& provided = engine.queue.provided;
        if (provided.buffer_count() < 4) return case_result_t::skipped("needs a pool past two buffers");
        expect_true(provided.provided_buffers == 2 && provided.available_buffers == 2);
        loopback_pair_t sockets = loopback_pair();
        if (!expect_true(sockets.connected())) return {};
        auto const socket = engine.import_socket(std::exchange(sockets.client, -1));
        if (!expect_true(socket >= 0)) return {};
        std::size_t const allocations = ledger.allocations;
        std::vector<byte_t> chunk(65536, byte_t {7});
        std::vector<io_completion_t> lent;
        io_request_t receiving {.operation = io_operation_t::receive_k, .descriptor = socket};
        auto const deadline = deadline_after(10000000);
        while (provided.provided_buffers == 2) {
            if (!expect_true(send_all(sockets.peer, chunk))) return {};
            for (std::size_t landed = 0; landed != chunk.size();) {
                io_completion_t completed {};
                engine.submit(receiving);
                if (!expect_true(engine.poll({&completed, 1}, io_wait_t::blocking_k, deadline) == 1)) return {};
                if (!expect_true(completed.result > 0, "receiving ended with {}", completed.result)) return {};
                landed += static_cast<std::size_t>(completed.result);
                lent.push_back(completed);
            }
            if (!expect_true(monotonic_ns() < deadline, "{} slices kept two buffers", lent.size())) return {};
        }
        expect_true(provided.provided_buffers == 4 && ledger.allocations == allocations,
                    "{} buffers provided after {} allocations", provided.provided_buffers,
                    ledger.allocations - allocations);
        for (auto const& completed : lent) engine.release(completed);
        expect_true(provided.available_buffers == provided.provided_buffers);
        expect_true(engine.close_socket(socket) == 0);
    }
    expect_true(!ledger.live_bytes && ledger.allocations == ledger.deallocations);
    return {};
}

/** A failed allocation during setup answers out-of-memory, returning every byte taken before it. */
static void test_ring_allocation_failure() {
    bool kernel_available = false;
    {
        linux_uring612_engine_t probe;
        kernel_available = probe.open(1, 1) != ucall_status_unsupported_k;
    }
    // Only a kernel with rings reaches the seventh allocation, the probe's.
    for (auto refuse_from : {std::size_t {0}, std::size_t {4}, std::size_t {6}}) {
        if (refuse_from == 6 && !kernel_available) continue;
        allocation_ledger_t ledger;
        ledger.refuse_from = refuse_from;
        {
            linux_uring612_engine<counting_allocator<byte_t>> engine {counting_allocator<byte_t> {ledger}};
            auto status = engine.open(4, 4);
            expect_true(status == ucall_status_out_of_memory_k, "failing allocation {} answered {}", refuse_from,
                        ucall_status_name(status));
        }
        expect_true(!ledger.live_bytes && ledger.allocations == ledger.deallocations,
                    "failing allocation {} kept {} bytes", refuse_from, ledger.live_bytes.load());
    }
}

void run_linux_uring612_engine_cases() {
    run_engine_cases<linux_uring612_engine_t>(
        ucall_io_backend_linux_uring612_k, []<typename engine_type_>(sz::string_t const& label) {
            run_test_case(called("test_engine_cell", label).c_str(), [] {
                return keeping_descriptors([] {
                    split_mix_generator_t generator {case_stream_key()};
                    test_engine_duplex<engine_type_>(generator);
                    test_accept_batch<engine_type_>();
                    test_ring_allocation_failure();
                });
            });
            run_cell_case(label, "test_failed_submission", test_failed_submission<engine_type_>);
            run_cell_case(label, "test_streamed_transmit", test_streamed_transmit<engine_type_>);
            run_cell_case(label, "test_end_of_stream", test_end_of_stream<engine_type_>);
            run_cell_case(label, "test_sockets_interleave", test_sockets_interleave<engine_type_>);
            run_cell_case(label, "test_registered_direct_files", test_registered_direct_files<engine_type_>);
            run_cell_case(label, "test_zero_copy_sends", test_zero_copy_sends<engine_type_>);
            run_cell_case(label, "test_provides_past_two_buffers", test_provides_past_two_buffers);
        });
}

} // namespace unum::ucall::test::io
