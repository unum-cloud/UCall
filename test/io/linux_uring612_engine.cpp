/**
 *  @file test/io/linux_uring612_engine.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The io_uring 6.12 engine under every admitted CPU class: the shared engine and ring
 *      cases, and the ones only this generation has.
 */
#include "io/engines.hpp" // `check_engine`, `test_failed_submission`, `test_zero_copy_sends`

namespace unum::ucall::test::io {

/** Exhausting the buffers provided at open doubles them from memory already reserved. */
static std::size_t test_provides_past_two_buffers() {
    allocation_counts_t counts;
    std::size_t failures = 0;
    {
        linux_uring612_engine<counting_allocator<byte_t>> engine {counting_allocator<byte_t> {counts}};
        auto status = engine.open(8, 8192);
        if (status == ucall_status_unsupported_k)
            return report("test_provides_past_two_buffers", "the kernel lacks this generation");
        require(failures, status == ucall_status_success_k, "{}", ucall_status_name(status));
        auto& provided = engine.queue.provided;
        if (provided.buffer_count() < 4) return report("test_provides_past_two_buffers", "the pool holds two buffers");
        failures += expect(provided.provided_buffers == 2 && provided.available_buffers == 2);
        loopback_pair_t sockets = loopback_pair();
        require(failures, sockets.connected());
        auto const socket = engine.import_socket(std::exchange(sockets.client, -1));
        require(failures, socket >= 0);
        std::size_t const allocations = counts.allocations;
        std::vector<byte_t> chunk(65536, byte_t {7});
        std::vector<io_completion_t> lent;
        io_request_t receiving {.operation = io_operation_t::receive_k, .descriptor = socket};
        auto const deadline = deadline_after(10000000);
        while (provided.provided_buffers == 2) {
            require(failures, send_all(sockets.peer, chunk));
            for (std::size_t landed = 0; landed != chunk.size();) {
                io_completion_t completed {};
                engine.submit(receiving);
                require(failures, engine.poll({&completed, 1}, io_wait_t::blocking_k, deadline) == 1);
                require(failures, completed.result > 0, "receiving ended with {}", completed.result);
                landed += static_cast<std::size_t>(completed.result);
                lent.push_back(completed);
            }
            require(failures, monotonic_ns() < deadline, "{} slices kept two buffers", lent.size());
        }
        failures += expect(provided.provided_buffers == 4 && counts.allocations == allocations,
                           "{} buffers provided after {} allocations", provided.provided_buffers,
                           counts.allocations - allocations);
        for (auto const& completed : lent) engine.release(completed);
        failures += expect(provided.available_buffers == provided.provided_buffers);
        failures += expect(engine.close_socket(socket) == 0);
    }
    failures += expect(!counts.bytes && counts.allocations == counts.deallocations);
    return failures;
}

/** A failed allocation during setup answers out-of-memory, returning every byte taken before it. */
static std::size_t test_ring_allocation_failure() {
    bool kernel_available = false;
    {
        linux_uring612_engine_t probe;
        kernel_available = probe.open(1, 1) != ucall_status_unsupported_k;
    }
    std::size_t failures = 0;
    // Only a kernel with rings reaches the seventh allocation, the probe's.
    for (auto fail_from : {std::size_t {0}, std::size_t {4}, std::size_t {6}}) {
        if (fail_from == 6 && !kernel_available) continue;
        allocation_counts_t counts;
        counts.fail_from = fail_from;
        {
            linux_uring612_engine<counting_allocator<byte_t>> engine {counting_allocator<byte_t> {counts}};
            auto status = engine.open(4, 4);
            failures += expect(status == ucall_status_out_of_memory_k, "failing allocation {} answered {}", fail_from,
                               ucall_status_name(status));
        }
        failures += expect(!counts.bytes && counts.allocations == counts.deallocations,
                           "failing allocation {} kept {} bytes", fail_from, counts.bytes.load());
    }
    return failures;
}

std::size_t check_linux_uring612_engine(settings_t const& settings) {
    return check_engine<linux_uring612_engine_t>(
        ucall_io_backend_linux_uring612_k, settings, []<typename engine_type_>(random_generator_t& generator) {
            std::size_t failures = test_engine_duplex<engine_type_>(generator);
            failures += test_accept_batch<engine_type_>();
            failures += test_failed_submission<engine_type_>();
            failures += test_streamed_transmit<engine_type_>();
            failures += keeping_descriptors(test_end_of_stream<engine_type_>);
            failures += keeping_descriptors(test_sockets_interleave<engine_type_>);
            failures += keeping_descriptors(test_registered_direct_files<engine_type_>);
            failures += test_zero_copy_sends<engine_type_>();
            failures += test_provides_past_two_buffers();
            failures += test_ring_allocation_failure();
            return failures;
        });
}

} // namespace unum::ucall::test::io
