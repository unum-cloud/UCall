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

#include "ucall/uring.hpp"

using namespace unum::ucall;

template <typename engine_type_>
static bool failed_submission() {
    engine_type_ engine;
    auto status = engine.open(8, 4);
    if (status == ucall_status_unsupported_k) return false;
    assert(status == ucall_status_success_k);
    auto listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    socket_length_t address_length = sizeof(address);
    assert(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_length) == 0);
    assert(listen(listener, 1) == 0);
    auto client = socket(AF_INET, SOCK_STREAM, 0);
    assert(client >= 0);
    assert(connect(client, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    auto peer = accept(listener, nullptr, nullptr);
    assert(peer >= 0);
    socket_close(listener);
    auto owned = engine.import_socket(client);
    assert(owned >= 0);
    byte_t content[1] {byte_t {42}};
    io_request_t sending {io_operation_t::send_k, owned, content, sizeof(content)};
    io_request_t receiving {io_operation_t::receive_k, owned, nullptr, engine.page};
    assert(engine.submit(sending));
    assert(engine.submit(receiving));
    assert(engine.enter(0, 0) >= 0);
    byte_t received {};
    assert(recv(peer, &received, sizeof(received), 0) == 1 && received == content[0]);

    io_request_t unsubmitted {io_operation_t::send_k, owned, content, sizeof(content)};
    assert(engine.submit(unsubmitted));
    auto descriptor = engine.ring.ring_fd;
    auto enter_descriptor = engine.ring.enter_ring_fd;
    engine.ring.ring_fd = -1;
    engine.ring.enter_ring_fd = -1;
    auto failure = engine.enter(0, 0);
    assert(failure == -EBADF);
    engine.ring.ring_fd = descriptor;
    engine.ring.enter_ring_fd = enter_descriptor;
    engine.fault = failure;
    engine.stop();

    assert(!engine.opened && !engine.files_registered && !engine.buffers_registered);
    assert(!engine.receive_ring && engine.storage);
    assert(!engine.live_operations && !engine.live_transmissions && !engine.live_streams && !engine.control.live);
    assert(recv(peer, &received, sizeof(received), 0) == 0);
    socket_close(peer);
    return true;
}

int main() {
    bool baseline = failed_submission<linux_uring612_engine_t>();
    bool advanced = failed_submission<linux_uring700_engine_t>();
    return baseline || advanced ? 0 : 77;
}
