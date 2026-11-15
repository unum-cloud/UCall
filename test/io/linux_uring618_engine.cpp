/**
 *  @file test/io/linux_uring618_engine.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The io_uring 6.18 engine under every admitted CPU class: the shared engine and ring
 *      cases, and the ones only this generation has.
 */
#include "io/engines.hpp" // `check_engine`, `test_failed_submission`, `test_zero_copy_sends`

namespace unum::ucall::test::io {

/** A request landing before its receive waits one round uncopied, and past that leaves the pool. */
static std::size_t test_slice_waits_a_round() {
    allocation_counts_t counts;
    std::size_t failures = 0;
    {
        linux_uring618_engine<counting_allocator<byte_t>> engine {counting_allocator<byte_t> {counts}};
        auto status = engine.open(8, 4);
        if (status == ucall_status_unsupported_k)
            return report("test_slice_waits_a_round", "the kernel lacks this generation");
        require(failures, status == ucall_status_success_k, "{}", ucall_status_name(status));
        loopback_pair_t sockets = loopback_pair();
        require(failures, sockets.connected());
        auto descriptor = engine.import_socket(sockets.client);
        require(failures, descriptor >= 0);
        sockets.client = -1;
        byte_t const message[16] {byte_t {7}};
        auto deadline = deadline_after(1000000);
        io_request_t receiving {.operation = io_operation_t::receive_k, .descriptor = descriptor};
        io_completion_t completed[2] {};
        engine.submit(receiving);
        require(failures, send_all(sockets.peer, message));
        require(failures, engine.poll(completed, io_wait_t::blocking_k, deadline) == 1);
        engine.release(completed[0]);

        auto* owner = engine.socket_slots.find(descriptor);
        auto const copied = engine.statistics.bytes_copied;
        require(failures, send_all(sockets.peer, message));
        while (owner->waiting_slice.empty()) {
            engine.reap();
            require(failures, monotonic_ns() < deadline, "the slice never landed");
            [[maybe_unused]] int const entered = engine.queue.enter(0, 0);
        }
        engine.submit(receiving);
        require(failures, engine.poll(completed, io_wait_t::blocking_k, deadline) == 1);
        failures += expect(completed[0].result == sizeof(message) && engine.statistics.bytes_copied == copied,
                           "{} bytes arrived and {} were copied", completed[0].result,
                           engine.statistics.bytes_copied - copied);
        engine.release(completed[0]);

        require(failures, send_all(sockets.peer, message));
        while (owner->backlog.empty()) {
            failures += expect(engine.poll(span<io_completion_t> {completed}.first(1), io_wait_t::nonblocking_k) == 0);
            require(failures, monotonic_ns() < deadline, "the slice never left the pool");
        }
        failures += expect(owner->waiting_slice.empty() && owner->backlog.size() == sizeof(message));
    }
    return failures;
}

static std::size_t test_paused_receive() {
    allocation_counts_t counts;
    std::size_t failures = 0;
    {
        linux_uring618_engine<counting_allocator<byte_t>> engine {counting_allocator<byte_t> {counts}};
        auto status = engine.open(8, 4);
        if (status == ucall_status_unsupported_k)
            return report("test_paused_receive", "the kernel lacks this generation");
        require(failures, status == ucall_status_success_k, "{}", ucall_status_name(status));
        loopback_pair_t held = loopback_pair(), other = loopback_pair();
        require(failures, held.connected() && other.connected());
        auto first = engine.import_socket(held.client);
        auto second = engine.import_socket(other.client);
        require(failures, first >= 0 && second >= 0);
        held.client = other.client = -1;
        auto& provided = engine.queue.provided;
        auto original = provided.buffer_bytes() * (provided.buffer_count() + 1);
        std::vector<byte_t> payload(original + provided.buffer_bytes(), byte_t {17});
        std::fill(payload.begin() + static_cast<std::ptrdiff_t>(original), payload.end(), byte_t {34});
        io_request_t receiving {.operation = io_operation_t::receive_k, .descriptor = first};
        engine.submit(receiving);
        require(failures, send_all(held.peer, span<byte_t const> {payload}.first(original)));
        io_completion_t completed[2] {};
        require(failures, engine.poll(completed, io_wait_t::blocking_k, deadline_after(1000000)) == 1);
        require(failures, completed[0].result > 0, "receiving ended with {}", completed[0].result);
        auto received = static_cast<std::size_t>(completed[0].result);
        failures += expect(std::memcmp(completed[0].data, payload.data(), received) == 0);

        auto* owner = engine.socket_slots.find(first);
        auto deadline = deadline_after(1000000);
        while (owner->backlog.empty()) {
            auto const spare = span<io_completion_t> {completed}.subspan(1);
            failures += expect(engine.poll(spare, io_wait_t::nonblocking_k) == 0);
            require(failures, monotonic_ns() < deadline, "the backlog never filled");
        }
        engine.receive_pause(first);
        engine.release(completed[0]);
        require(failures, send_all(held.peer, span<byte_t const> {payload}.subspan(original)));

        byte_t marker[1] {byte_t {51}};
        io_request_t independent {.operation = io_operation_t::receive_k, .descriptor = second};
        engine.submit(independent);
        require(failures, send_all(other.peer, marker));
        require(failures, engine.poll(completed, io_wait_t::blocking_k, deadline) == 1);
        failures += expect(completed[0].request == &independent && completed[0].result == 1 &&
                           completed[0].data[0] == marker[0]);
        engine.release(completed[0]);
        while (owner->receive_in_flight()) {
            failures += expect(engine.poll(completed, io_wait_t::nonblocking_k) == 0);
            require(failures, monotonic_ns() < deadline, "the paused receive never retired");
        }
        failures += expect(!owner->backlog.empty());
        failures += expect(provided.available_buffers == provided.provided_buffers);

        engine.submit(independent);
        engine.receive_pause(second);
        require(failures, send_all(other.peer, marker));
        require(failures, engine.poll(completed, io_wait_t::blocking_k, deadline) == 1);
        failures += expect(completed[0].request == &independent && completed[0].result == 1 &&
                           completed[0].data[0] == marker[0]);
        engine.release(completed[0]);
        engine.submit(independent);
        failures += expect(engine.cancel(independent) == ucall_status_success_k);
        require(failures, engine.poll(completed, io_wait_t::blocking_k, deadline) == 1);
        failures += expect(completed[0].request == &independent && completed[0].result == -ECANCELED &&
                           !completed[0].lease);

        while (received != payload.size()) {
            receiving.deadline = deadline_after(1000000);
            engine.submit(receiving);
            require(failures, engine.poll(completed, io_wait_t::blocking_k, receiving.deadline) == 1);
            require(failures, completed[0].request == &receiving && completed[0].result > 0, "receiving ended with {}",
                    completed[0].result);
            auto length = static_cast<std::size_t>(completed[0].result);
            require(failures, length <= payload.size() - received);
            failures += expect(std::memcmp(completed[0].data, payload.data() + received, length) == 0);
            received += length;
            engine.release(completed[0]);
        }
        engine.submit(receiving);
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
                       "{} allocations, {} deallocations, {} bytes kept", counts.allocations.load(),
                       counts.deallocations.load(), counts.bytes.load());
    return failures;
}

std::size_t check_linux_uring618_engine(settings_t const& settings) {
    return check_engine<linux_uring618_engine_t>(
        ucall_io_backend_linux_uring618_k, settings, []<typename engine_type_>(random_generator_t& generator) {
            std::size_t failures = test_engine_duplex<engine_type_>(generator);
            failures += test_accept_batch<engine_type_>();
            failures += test_failed_submission<engine_type_>();
            failures += test_streamed_transmit<engine_type_>();
            failures += keeping_descriptors(test_end_of_stream<engine_type_>);
            failures += keeping_descriptors(test_sockets_interleave<engine_type_>);
            failures += keeping_descriptors(test_registered_direct_files<engine_type_>);
            failures += test_zero_copy_sends<engine_type_>();
            failures += test_slice_waits_a_round();
            failures += test_paused_receive();
            return failures;
        });
}

} // namespace unum::ucall::test::io
