/**
 *  @brief   IO Uring-based backend for UCall.
 *  @author  Ash Vardanian
 *
 *  Supports:
 *  > Thousands of concurrent stateful connections.
 *  > Hundreds of physical execution threads.
 *  > Both HTTP and HTTP-less raw JSON-RPC calls.
 *
 *  @section Primary structures
 *  - `engine_t`: primary server instance.
 *  - `connection_t`: lifetime state of a single TCP connection.
 *  - `scratch_space_t`: temporary memory used by a single thread at a time.
 *  - `automata_t`: automata that accepts and responds to messages.
 *
 *  @section Concurrency
 *  The whole class is thread safe and can be used with as many threads as
 *  defined during construction with `ucall_init`. Some `connection_t`-s
 *  can, however, be simultaneously handled by two threads, if one logical
 *  operation is split into multiple physical calls:
 *
 *       1.  Receiving packets with timeouts.
 *           This allows us to reconsider closing a connection every once
 *           in a while, instead of loyally waiting for more data to come.
 *       2.  Closing sockets gracefully.
 *
 *  @section Linux kernel requirements
 *  We need Submission Queue Polling to extract maximum performance from `io_uring`.
 *  Many of the requests would get an additional `IOSQE_FIXED_FILE` flag, and the
 *  setup call would receive `IORING_SETUP_SQPOLL`. Aside from those, we also
 *  need to prioritize following efficient interfaces:
 *  - `io_uring_prep_accept_direct` to alloc from reusable files list > 5.19..
 *  - `io_uring_prep_read_fixed` to read into registered buffers.
 *  - `io_uring_register_buffers`.
 *  - `io_uring_register_files_sparse` > 5.19, or `io_uring_register_files` before that.
 *  - `IORING_SETUP_COOP_TASKRUN` > 5.19.
 *  - `IORING_SETUP_SINGLE_ISSUER` > 6.0.
 *
 *  @see Notable links:
 *  https://man7.org/linux/man-pages/dir_by_project.html#liburing
 *  https://jvns.ca/blog/2017/06/03/async-io-on-linux--select--poll--and-epoll/
 *  https://stackoverflow.com/a/17665015/2766161
 */
#include <arpa/inet.h>  // `inet_addr`
#include <netinet/in.h> // `sockaddr_in`
#include <sys/socket.h> //  `setsockopt`
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <liburing.h>

#include <simdjson.h>

#include "engine_common.hpp"

#pragma region Cpp Declaration

namespace sj = simdjson;
namespace sjd = sj::dom;
using namespace unum::ucall;

struct uring_server_t {
    server_state_t state;
    mutex_t submission_mutex{};
    memory_map_t fixed_buffers{};
    io_uring uring{};
};

void ucall_init(ucall_config_t* config_inout, ucall_server_t* server_out) {

    // Simple sanity check
    if (!server_out && !config_inout)
        return;

    // Retrieve configs, if present
    ucall_config_t& config = *config_inout;
    if (!config.port)
        config.port = 8545u;
    if (!config.queue_depth)
        config.queue_depth = 4096u;
    if (!config.max_callbacks)
        config.max_callbacks = 128u;
    if (!config.max_concurrent_connections)
        config.max_concurrent_connections = 1024u;
    if (!config.max_threads)
        config.max_threads = 1u;
    if (!config.max_lifetime_micro_seconds)
        config.max_lifetime_micro_seconds = 100'000u;
    if (!config.max_lifetime_exchanges)
        config.max_lifetime_exchanges = 100u;
    if (!config.hostname)
        config.hostname = "0.0.0.0";

    // Allocate
    int socket_options{1};
    int socket_descriptor{-1};
    int uring_result{-1};
    uring_server_t* uctx = new uring_server_t();
    struct io_uring* uring = &uctx->uring;
    struct io_uring_params uring_params {};
    struct io_uring_sqe* uring_sqe{};
    struct io_uring_cqe* uring_cqe{};
    uring_params.features |= IORING_FEAT_FAST_POLL;
    uring_params.features |= IORING_FEAT_SQPOLL_NONFIXED;
    // uring_params.flags |= IORING_SETUP_COOP_TASKRUN;
    uring_params.flags |= IORING_SETUP_SQPOLL;
    uring_params.sq_thread_idle = wakeup_initial_frequency_ns_k;
    // uring_params.flags |= config.max_threads == 1 ? IORING_SETUP_SINGLE_ISSUER : 0; // 6.0+
    server_state_t* server_ptr{};
    pool_gt<connection_t> connections{};
    array_gt<endpoint_t> callbacks{};
    buffer_gt<struct iovec> registered_buffers{};
    std::unique_ptr<ssl_context_t> ssl_context{};

    // By default, let's open TCP port for IPv4.
    struct sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(config.hostname);
    address.sin_port = htons(config.port);

    // Initialize `io_uring` first, it is the most likely to fail.
    uring_result = io_uring_queue_init_params(config.queue_depth, uring, &uring_params);
    if (uring_result != 0)
        goto cleanup;

    // Try allocating all the necessary memory.
    server_ptr = (server_state_t*)std::malloc(sizeof(server_state_t));
    if (!server_ptr)
        goto cleanup;
    if (!callbacks.reserve(config.max_callbacks))
        goto cleanup;
    if (!uctx->fixed_buffers.reserve(ram_page_size_k * 2u * config.max_concurrent_connections))
        goto cleanup;
    if (!connections.reserve(config.max_concurrent_connections))
        goto cleanup;

    // Additional `io_uring` setup.
    if (!registered_buffers.resize(config.max_concurrent_connections * 2u))
        goto cleanup;
    for (std::size_t i = 0; i != config.max_concurrent_connections; ++i) {
        auto& connection = connections.at_offset(i);
        auto inputs = uctx->fixed_buffers.ptr + ram_page_size_k * 2u * i;
        auto outputs = inputs + ram_page_size_k;
        connection.pipes.mount(inputs, outputs);

        registered_buffers[i * 2u].iov_base = inputs;
        registered_buffers[i * 2u].iov_len = ram_page_size_k;
        registered_buffers[i * 2u + 1u].iov_base = outputs;
        registered_buffers[i * 2u + 1u].iov_len = ram_page_size_k;
    }
    uring_result = io_uring_register_files_sparse(uring, config.max_concurrent_connections);
    if (uring_result != 0)
        goto cleanup;
    uring_result =
        io_uring_register_buffers(uring, registered_buffers.data(), static_cast<unsigned>(registered_buffers.size()));
    if (uring_result != 0)
        goto cleanup;

    // Configure the socket.

    uring_sqe = io_uring_get_sqe(uring);
    io_uring_prep_socket_direct(uring_sqe, AF_INET, SOCK_STREAM, 0, IORING_FILE_INDEX_ALLOC, 0);
    uring_result = io_uring_submit_and_wait(uring, 1);
    uring_result = io_uring_wait_cqe(uring, &uring_cqe);
    socket_descriptor = uring_cqe->res;
    if (socket_descriptor < 0)
        goto cleanup;
    // Not sure if this is required, after we have a kernel with `IORING_OP_SENDMSG_ZC` support, we can check.
    // if (setsockopt(socket_descriptor, SOL_SOCKET, SO_ZEROCOPY, &socket_options, sizeof(socket_options)) == -1)
    //     goto cleanup;
    if (setsockopt(socket_descriptor, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                   reinterpret_cast<char const*>(&socket_options), sizeof(socket_options)) == -1)
        errno;
    if (bind(socket_descriptor, (struct sockaddr*)&address, sizeof(address)) < 0)
        goto cleanup;
    if (listen(socket_descriptor, config.queue_depth) < 0)
        goto cleanup;
    if (config.ssl_certificates_count != 0) {
        ssl_context = std::make_unique<ssl_context_t>();
        if (ssl_context->init(config.ssl_private_key_path, config.ssl_certificates_paths,
                              config.ssl_certificates_count) != 0)
            goto cleanup;
    }

    // Initialize all the members.
    new (server_ptr) server_state_t();
    server_ptr->network_engine.network_data = uctx;
    server_ptr->socket = descriptor_t{socket_descriptor};
    server_ptr->ssl_context = std::move(ssl_context);
    server_ptr->protocol_type = config.protocol;
    server_ptr->max_lifetime_micro_seconds = config.max_lifetime_micro_seconds;
    server_ptr->max_lifetime_exchanges = config.max_lifetime_exchanges;
    server_ptr->engine.callbacks = std::move(callbacks);
    server_ptr->connections = std::move(connections);
    server_ptr->logs_file_descriptor = config.logs_file_descriptor;
    server_ptr->logs_format = config.logs_format ? std::string_view(config.logs_format) : std::string_view();
    *server_out = (ucall_server_t)server_ptr;
    return;

cleanup:
    errno;
    if (uring->ring_fd)
        io_uring_queue_exit(uring);
    if (socket_descriptor >= 0)
        close(socket_descriptor);
    std::free(server_ptr);
    delete uctx;
    *server_out = nullptr;
}

void ucall_free(ucall_server_t punned_server) {
    if (!punned_server)
        return;

    server_state_t& server = *reinterpret_cast<server_state_t*>(punned_server);
    uring_server_t* ctx = reinterpret_cast<uring_server_t*>(server.network_engine.network_data);
    io_uring_unregister_buffers(&ctx->uring);
    io_uring_queue_exit(&ctx->uring);
    close(server.socket);
    server.~server_state_t();
    std::free(punned_server);
    delete ctx;
}

bool io_check_send_zc() noexcept {
    io_uring_probe* probe = io_uring_get_probe();
    if (!probe)
        return false;

    // Available since 6.0.
    bool res = io_uring_opcode_supported(probe, IORING_OP_SEND_ZC);
    io_uring_free_probe(probe);
    return res;
}

int network_engine_t::try_accept(descriptor_t socket, connection_t& connection) noexcept {
    uring_server_t* ctx = reinterpret_cast<uring_server_t*>(network_data);
    io_uring* uring = &ctx->uring;
    io_uring_sqe* uring_sqe{};
    ctx->submission_mutex.lock();
    uring_sqe = io_uring_get_sqe(uring);
    io_uring_prep_accept_direct(uring_sqe, socket, &connection.client_address, &connection.client_address_length, 0,
                                IORING_FILE_INDEX_ALLOC);
    io_uring_sqe_set_data(uring_sqe, &connection);

    // Accepting new connections can be time-less.
    // io_uring_sqe_set_flags(uring_sqe, IOSQE_IO_LINK);
    // uring_sqe = io_uring_get_sqe(uring);
    // io_uring_prep_link_timeout(uring_sqe, &connection.next_wakeup, 0);
    // io_uring_sqe_set_data(uring_sqe, NULL);

    int res = io_uring_submit(uring);
    ctx->submission_mutex.unlock();
    return res;
}

void network_engine_t::set_stats_heartbeat(connection_t& connection) noexcept {
    uring_server_t* ctx = reinterpret_cast<uring_server_t*>(network_data);
    __kernel_timespec wakeup{0, connection.next_wakeup};
    io_uring* uring = &ctx->uring;
    ctx->submission_mutex.lock();
    io_uring_sqe* uring_sqe = io_uring_get_sqe(uring);
    io_uring_prep_timeout(uring_sqe, &wakeup, 0, 0);
    io_uring_sqe_set_data(uring_sqe, &connection);
    io_uring_submit(uring);
    ctx->submission_mutex.unlock();
}

void network_engine_t::close_connection_gracefully(connection_t& connection) noexcept {
    uring_server_t* ctx = reinterpret_cast<uring_server_t*>(network_data);
    // The operations are not expected to complete in exactly the same order
    // as their submissions. So to stop all existing communication on the
    // socket, we can cancel everything related to its "file descriptor",
    // and then close.
    io_uring* uring = &ctx->uring;
    ctx->submission_mutex.lock();
    io_uring_sqe* uring_sqe = io_uring_get_sqe(uring);
    io_uring_prep_cancel_fd(uring_sqe, int(connection.descriptor), 0);
    io_uring_sqe_set_data(uring_sqe, NULL);
    io_uring_sqe_set_flags(uring_sqe, IOSQE_IO_HARDLINK);

    uring_sqe = io_uring_get_sqe(uring);
    io_uring_prep_shutdown(uring_sqe, int(connection.descriptor), SHUT_WR);
    io_uring_sqe_set_data(uring_sqe, NULL);
    io_uring_sqe_set_flags(uring_sqe, IOSQE_IO_HARDLINK);

    uring_sqe = io_uring_get_sqe(uring);
    io_uring_prep_close(uring_sqe, int(connection.descriptor));
    io_uring_sqe_set_data(uring_sqe, &connection);
    io_uring_sqe_set_flags(uring_sqe, 0);

    io_uring_submit(uring);
    ctx->submission_mutex.unlock();
}

void network_engine_t::send_packet(connection_t& connection, void* buffer, size_t buffer_length,
                                   size_t buf_index) noexcept {
    uring_server_t* ctx = reinterpret_cast<uring_server_t*>(network_data);
    io_uring* uring = &ctx->uring;
    ctx->submission_mutex.lock();
    io_uring_sqe* uring_sqe = io_uring_get_sqe(uring);

    // TODO: Test and benchmark the `send_zc option`.
    // if (io_check_send_zc()) {
    //     io_uring_prep_send_zc_fixed(uring_sqe, int(connection.descriptor), buffer, buffer_length, 0, 0, buf_index);
    // } else {
    io_uring_prep_send(uring_sqe, int(connection.descriptor), buffer, buffer_length, 0);
    uring_sqe->flags |= IOSQE_FIXED_FILE;
    uring_sqe->buf_index = buf_index;
    // }
    io_uring_sqe_set_data(uring_sqe, &connection);
    io_uring_sqe_set_flags(uring_sqe, 0);
    io_uring_submit(uring);
    ctx->submission_mutex.unlock();
}

void network_engine_t::recv_packet(connection_t& connection, void* buffer, size_t buffer_length,
                                   size_t buf_index) noexcept {
    uring_server_t* ctx = reinterpret_cast<uring_server_t*>(network_data);
    ctx->submission_mutex.lock();
    io_uring* uring = &ctx->uring;

    // Choosing between `recv` and `read` system calls:
    // > If a zero-length datagram is pending, read(2) and recv() with a
    // > flags argument of zero provide different behavior. In this
    // > circumstance, read(2) has no effect (the datagram remains
    // > pending), while recv() consumes the pending datagram.
    // https://man7.org/linux/man-pages/man2/recv.2.html
    //
    // In this case we are waiting for an actual data, not some artificial wakeup.
    io_uring_sqe* uring_sqe = io_uring_get_sqe(uring);
    io_uring_prep_read_fixed(uring_sqe, int(connection.descriptor), buffer, buffer_length, 0, buf_index);
    io_uring_sqe_set_data(uring_sqe, &connection);
    io_uring_sqe_set_flags(uring_sqe, IOSQE_IO_LINK);

    // More than other operations this depends on the information coming from the client.
    // We can't afford to keep connections alive indefinitely, so we need to set a timeout
    // on this operation.
    // The `io_uring_prep_link_timeout` is a convenience method for poorly documented `IORING_OP_LINK_TIMEOUT`.
    uring_sqe = io_uring_get_sqe(uring);
    __kernel_timespec wakeup{0, connection.next_wakeup};
    io_uring_prep_link_timeout(uring_sqe, &wakeup, 0);
    io_uring_sqe_set_data(uring_sqe, NULL);
    io_uring_sqe_set_flags(uring_sqe, 0);
    io_uring_submit(uring);
    ctx->submission_mutex.unlock();
}

bool network_engine_t::is_canceled(ssize_t res, unum::ucall::connection_t const& conn) noexcept {
    return res == -ECANCELED;
}

bool network_engine_t::is_corrupted(ssize_t res, unum::ucall::connection_t const& conn) noexcept {
    // Since the socket operates in blocking mode, a return value of 0 is unlikely,
    // but just in case allow the possibility of occasional occurrences.
    return res == -EBADF || res == -EPIPE || (res == 0 && conn.empty_transmits > 8);
}

template <size_t max_count_ak> std::size_t network_engine_t::pop_completed_events(completed_event_t* events) noexcept {
    uring_server_t* ctx = reinterpret_cast<uring_server_t*>(network_data);
    io_uring* uring = &ctx->uring;
    unsigned uring_head = 0;
    unsigned completed = 0;
    unsigned passed = 0;
    io_uring_cqe* uring_cqe{};

    ctx->submission_mutex.lock();
    io_uring_for_each_cqe(uring, uring_head, uring_cqe) {
        ++passed;
        if (!uring_cqe->user_data)
            continue;

        events[completed].connection_ptr = (connection_t*)uring_cqe->user_data;
        events[completed].result = uring_cqe->res;
        ++completed;
        if (completed == max_count_ak)
            break;
    }

    io_uring_cq_advance(uring, passed);
    ctx->submission_mutex.unlock();
    return completed;
}
