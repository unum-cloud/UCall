/**
 *  @file test/uring.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Registered I/O ownership after a failed submission syscall.
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstring>

#include <algorithm>
#include <vector>

#include "ucall/uring612.hpp"
#include "ucall/uring700.hpp"

using namespace unum::ucall;

struct allocation_counts_t {
    std::size_t attempts {}, allocations {}, deallocations {}, bytes {};
    std::size_t fail_at {std::numeric_limits<std::size_t>::max()};
};

template <typename value_type_>
struct counting_allocator {
    using value_type = value_type_;
    using propagate_on_container_move_assignment = std::true_type;
    allocation_counts_t* counts {};
    counting_allocator() noexcept = default;
    explicit counting_allocator(allocation_counts_t& state) noexcept : counts(&state) {}
    template <typename other_type_>
    counting_allocator(counting_allocator<other_type_> const& other) noexcept : counts(other.counts) {}
    value_type_* allocate(std::size_t count) noexcept {
        assert(counts);
        if (counts->attempts++ == counts->fail_at) return nullptr;
        auto* result = st::default_allocator<value_type_> {}.allocate(count);
        if (result) {
            ++counts->allocations;
            counts->bytes += count * sizeof(value_type_);
        }
        return result;
    }
    void deallocate(value_type_* pointer, std::size_t count) noexcept {
        assert(counts && counts->bytes >= count * sizeof(value_type_));
        ++counts->deallocations;
        counts->bytes -= count * sizeof(value_type_);
        st::default_allocator<value_type_> {}.deallocate(pointer, count);
    }
    template <typename other_type_>
    bool operator==(counting_allocator<other_type_> const& other) const noexcept {
        return counts == other.counts;
    }
};

struct tcp_pair_t {
    descriptor_t client {-1}, peer {-1};
    tcp_pair_t() {
        auto listener = socket_open(AF_INET);
        assert(listener >= 0);
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        assert(bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
        socket_length_t address_length = sizeof(address);
        assert(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_length) == 0);
        assert(listen(listener, 1) == 0);
        client = socket(AF_INET, SOCK_STREAM, 0);
        assert(client >= 0);
        assert(connect(client, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
        peer = accept(listener, nullptr, nullptr);
        assert(peer >= 0);
        int enabled {};
        socket_length_t option_length = sizeof(enabled);
        assert(getsockopt(peer, IPPROTO_TCP, TCP_NODELAY, &enabled, &option_length) == 0 && enabled == 1);
        socket_close(listener);
    }
    ~tcp_pair_t() {
        if (client >= 0) socket_close(client);
        socket_close(peer);
    }
    void send(span<byte_t const> bytes) {
        while (!bytes.empty()) {
            auto count = ::send(peer, bytes.data(), bytes.size(), MSG_NOSIGNAL);
            assert(count > 0);
            bytes = bytes.subspan(static_cast<std::size_t>(count));
        }
    }
};

template <typename engine_type_>
static void assert_nodelay(engine_type_& engine, descriptor_t handle) {
    auto* submission = engine.entry();
    assert(submission);
    engine.control.result.reset();
    io_uring_prep_fixed_fd_install(submission, static_cast<int>(engine_type_::registered_socket_t::index_of(handle)),
                                   0);
    io_uring_sqe_set_data64(submission, engine.tag(&engine.control, engine.control_tag_k));
    auto descriptor = engine.wait_control();
    assert(descriptor >= 0);
    int enabled {};
    socket_length_t length = sizeof(enabled);
    assert(getsockopt(descriptor, IPPROTO_TCP, TCP_NODELAY, &enabled, &length) == 0 && enabled == 1);
    socket_close(descriptor);
}

template <typename engine_type_>
static bool failed_submission() {
    engine_type_ engine;
    auto status = engine.open(8, 4);
    if (status == ucall_status_unsupported_k) return false;
    assert(status == ucall_status_success_k);
    auto direct = engine.open_socket(AF_INET);
    assert(direct >= 0);
    assert_nodelay(engine, direct);
    assert(engine.close_socket(direct) == 0);
    tcp_pair_t sockets;
    auto owned = engine.import_socket(sockets.client);
    assert(owned >= 0);
    sockets.client = -1;
    assert_nodelay(engine, owned);
    byte_t content[1] {byte_t {42}};
    io_request_t sending {io_operation_t::send_k, owned, content, sizeof(content)};
    io_request_t receiving {io_operation_t::receive_k, owned, nullptr, engine.page};
    assert(engine.submit(sending));
    assert(engine.submit(receiving));
    assert(engine.enter(0, 0) >= 0);
    byte_t received {};
    assert(recv(sockets.peer, &received, sizeof(received), 0) == 1 && received == content[0]);

    io_request_t unsubmitted {io_operation_t::send_k, owned, content, sizeof(content)};
    assert(engine.submit(unsubmitted));
    auto descriptor = engine.ring.ring_fd;
    auto enter_descriptor = engine.ring.enter_ring_fd;
    engine.ring.ring_fd = -1;
    engine.ring.enter_ring_fd = -1;
    auto failure = engine.enter(0, 0);
    assert(failure < 0);
    engine.ring.ring_fd = descriptor;
    engine.ring.enter_ring_fd = enter_descriptor;
    engine.fault = failure;
    engine.stop();

    assert(!engine.is_open() && engine.registrations == engine.registration_none_k);
    assert(!engine.receive_ring && engine.storage);
    assert(!engine.has_kernel_work());
    assert(recv(sockets.peer, &received, sizeof(received), 0) == 0);
    return true;
}

template <typename engine_type_>
static void streamed_transmit() {
    engine_type_ engine;
    assert(engine.open(1, 1) == ucall_status_success_k);
    tcp_pair_t sockets;
    auto owned = engine.import_socket(sockets.client);
    assert(owned >= 0);
    sockets.client = -1;
    assert(nonblocking(sockets.peer));
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
            assert(engine.submit(sending));
            pending = true;
        }
        io_completion_t completed {};
        if (engine.poll(span<io_completion_t> {&completed, &completed + 1}, io_wait_t::nonblocking_k)) {
            assert(completed.request == &sending && completed.result > 0);
            sent += static_cast<std::size_t>(completed.result);
            pending = false;
        }
        if (read != received.size()) {
            auto count = recv(sockets.peer, received.data() + read, received.size() - read, 0);
            if (count > 0) read += static_cast<std::size_t>(count);
            else assert(count < 0 && io_pending(-errno));
        }
        assert(monotonic_ns() < deadline);
    }
    assert(received == payload);
    assert(engine.close_socket(owned) == 0);
}

static void paused_receive(counting_allocator<byte_t> const& allocator) {
    linux_uring700_engine<counting_allocator<byte_t>> engine {allocator};
    assert(engine.open(8, 4) == ucall_status_success_k);
    tcp_pair_t held, other;
    auto first = engine.import_socket(held.client);
    auto second = engine.import_socket(other.client);
    assert(first >= 0 && second >= 0);
    held.client = other.client = -1;
    auto original = engine.page * (engine.buffer_count + 1);
    std::vector<byte_t> payload(original + engine.page, byte_t {17});
    std::fill(payload.begin() + static_cast<std::ptrdiff_t>(original), payload.end(), byte_t {34});
    io_request_t receiving {io_operation_t::receive_k, first, nullptr, engine.page};
    assert(engine.submit(receiving));
    held.send(span<byte_t const> {payload}.first(original));
    io_completion_t completed[2] {};
    assert(engine.poll(completed, io_wait_t::blocking_k, deadline_after(1000000)) == 1);
    assert(completed[0].result > 0);
    auto received = static_cast<std::size_t>(completed[0].result);
    assert(std::memcmp(completed[0].data, payload.data(), received) == 0);
    auto* owner = engine.resource(first);
    auto deadline = deadline_after(1000000);
    while (owner->receive_head == engine.absent_k) {
        assert(engine.poll(span<io_completion_t> {completed}.subspan(1), io_wait_t::nonblocking_k) == 0);
        assert(monotonic_ns() < deadline);
    }
    engine.receive_pause(first);
    engine.release(completed[0]);
    held.send(span<byte_t const> {payload}.subspan(original));

    byte_t marker[1] {byte_t {51}};
    io_request_t independent {io_operation_t::receive_k, second, nullptr, engine.page};
    assert(engine.submit(independent));
    other.send(marker);
    assert(engine.poll(completed, io_wait_t::blocking_k, deadline) == 1);
    assert(completed[0].request == &independent && completed[0].result == 1 && completed[0].data[0] == marker[0]);
    engine.release(completed[0]);
    while (owner->receive_in_flight()) {
        assert(engine.poll(completed, io_wait_t::nonblocking_k) == 0);
        assert(monotonic_ns() < deadline);
    }
    assert(owner->receive_head == engine.absent_k && !owner->backlog.empty());
    assert(engine.available_buffers == engine.buffer_count);

    assert(engine.submit(independent));
    engine.receive_pause(second);
    other.send(marker);
    assert(engine.poll(completed, io_wait_t::blocking_k, deadline) == 1);
    assert(completed[0].request == &independent && completed[0].result == 1 && completed[0].data[0] == marker[0]);
    engine.release(completed[0]);
    assert(engine.submit(independent) && engine.cancel(independent));
    assert(engine.poll(completed, io_wait_t::blocking_k, deadline) == 1);
    assert(completed[0].request == &independent && completed[0].result == -ECANCELED && !completed[0].lease);
    while (received != payload.size()) {
        receiving.deadline = deadline_after(1000000);
        assert(engine.submit(receiving));
        assert(engine.poll(completed, io_wait_t::blocking_k, receiving.deadline) == 1);
        assert(completed[0].request == &receiving && completed[0].result > 0);
        auto length = static_cast<std::size_t>(completed[0].result);
        assert(length <= payload.size() - received);
        assert(std::memcmp(completed[0].data, payload.data() + received, length) == 0);
        received += length;
        engine.release(completed[0]);
    }
    assert(engine.submit(receiving));
    assert(engine.close_socket(first) == 0);
    assert(engine.poll(completed, io_wait_t::nonblocking_k) == 1);
    assert(completed[0].request == &receiving && completed[0].result == -ECANCELED && !completed[0].lease);
    auto reused = engine.open_socket(AF_INET);
    assert(reused == first);
    assert(engine.close_socket(reused) == 0 && engine.close_socket(second) == 0);
    engine.stop();
    assert(!engine.has_kernel_work());
}

static void allocation_failure(bool kernel_available) {
    for (auto fail_at : {std::size_t {0}, std::size_t {4}, std::size_t {5}}) {
        if (fail_at == 5 && !kernel_available) continue;
        allocation_counts_t counts;
        counts.fail_at = fail_at;
        {
            linux_uring612_engine<counting_allocator<byte_t>> engine {counting_allocator<byte_t> {counts}};
            assert(engine.open(4, 4) == ucall_status_out_of_memory_k);
        }
        assert(!counts.bytes && counts.allocations == counts.deallocations);
    }
}

int main() {
    bool baseline = failed_submission<linux_uring612_engine_t>();
    bool advanced = failed_submission<linux_uring700_engine_t>();
    allocation_failure(baseline);
    if (baseline) streamed_transmit<linux_uring612_engine_t>();
    if (advanced) streamed_transmit<linux_uring700_engine_t>();
    if (advanced) {
        allocation_counts_t counts;
        paused_receive(counting_allocator<byte_t> {counts});
        assert(counts.allocations && !counts.bytes && counts.allocations == counts.deallocations);
    }
    return baseline || advanced ? 0 : 77;
}
