/**
 * @brief   POSIX-based backend for UCall.
 * @author  Ash Vardanian
 */

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#define UCALL_IS_WINDOWS
#include <Ws2tcpip.h>
#include <io.h>
#include <winsock2.h>

#define SHUT_WR SD_SEND
#define SHUT_RD SD_RECEIVE
#define SHUT_RDWR SD_BOTH
// SO_REUSEPORT, MSG_NOSIGNAL is not supported on Windows.
#define SO_REUSEPORT 0
#define MSG_NOSIGNAL 0
#pragma comment(lib, "Ws2_32.lib")
#define UNICODE

#else
#include <arpa/inet.h> // `inet_addr`
#include <fcntl.h>
#include <netinet/in.h> // `sockaddr_in`

#include <sys/ioctl.h>
#include <sys/socket.h> // `recv`, `setsockopt`

#include <sys/uio.h>
#include <unistd.h>
#endif

#include <queue>

#include "engine_common.hpp"

#pragma region Cpp Declaration

namespace sj = simdjson;
namespace sjd = sj::dom;
using namespace unum::ucall;

static constexpr std::size_t initial_buffer_size_k = ram_page_size_k * 4;

struct conn_ctx_t {
    connection_t* conn_ptr;
    ssize_t res;
};

struct posix_ctx_t {
    std::queue<conn_ctx_t> res_queue; // TODO replace with custom
    mutex_t queue_mutex;
    memory_map_t fixed_buffers{};
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
    posix_ctx_t* uctx = new posix_ctx_t();
    server_t* server_ptr{};
    pool_gt<connection_t> connections{};
    array_gt<named_callback_t> callbacks{};
    std::unique_ptr<ssl_context_t> ssl_ctx{};

    // By default, let's open TCP port for IPv4.
    struct sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(config.hostname);
    address.sin_port = htons(config.port);

    // Try allocating all the necessary memory.
    server_ptr = (server_t*)std::malloc(sizeof(server_t));
    if (!server_ptr)
        goto cleanup;
    if (!callbacks.reserve(config.max_callbacks))
        goto cleanup;
    if (!uctx->fixed_buffers.reserve(ram_page_size_k * 2u * config.max_concurrent_connections))
        goto cleanup;
    if (!connections.reserve(config.max_concurrent_connections))
        goto cleanup;

    for (std::size_t i = 0; i != config.max_concurrent_connections; ++i) {
        auto& connection = connections.at_offset(i);
        auto inputs = uctx->fixed_buffers.ptr + ram_page_size_k * 2u * i;
        auto outputs = inputs + ram_page_size_k;
        connection.pipes.mount(inputs, outputs);
    }

    // Configure the socket.
    socket_descriptor = socket(AF_INET, SOCK_STREAM, 0);
    {
#if defined(UCALL_IS_WINDOWS)
        u_long mode = 1; // 1 to enable non-blocking socket, 0 to disable
        ioctlsocket(socket_descriptor, FIONBIO, &mode);
#else
        int flags = fcntl(socket_descriptor, F_GETFL, 0);
        flags |= O_NONBLOCK;
        fcntl(socket_descriptor, F_SETFL, flags);
#endif
    }
    if (socket_descriptor < 0)
        goto cleanup;
    if (setsockopt(socket_descriptor, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                   reinterpret_cast<char const*>(&socket_options), sizeof(socket_options)) == -1)
        errno;
    if (bind(socket_descriptor, (struct sockaddr*)&address, sizeof(address)) < 0)
        goto cleanup;
    if (listen(socket_descriptor, config.queue_depth) < 0)
        goto cleanup;
    if (config.ssl_certificates_count != 0) {
        ssl_ctx = std::make_unique<ssl_context_t>();
        if (ssl_ctx->init(config.ssl_private_key_path, config.ssl_certificates_paths, config.ssl_certificates_count) !=
            0)
            goto cleanup;
    }

    // Initialize all the members.
    new (server_ptr) server_t();
    server_ptr->network_engine.network_data = uctx;
    server_ptr->socket = descriptor_t{socket_descriptor};
    server_ptr->ssl_ctx = std::move(ssl_ctx);
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
    if (socket_descriptor >= 0)
        close(socket_descriptor);
    std::free(server_ptr);
    delete uctx;
    *server_out = nullptr;
}

void ucall_free(ucall_server_t punned_server) {
    if (!punned_server)
        return;

    server_t& server = *reinterpret_cast<server_t*>(punned_server);
    posix_ctx_t* ctx = reinterpret_cast<posix_ctx_t*>(server.network_engine.network_data);
    close(server.socket);
    server.~server_t();
    std::free(punned_server);
    delete ctx;
}

int network_engine_t::try_accept(descriptor_t socket, connection_t& connection) noexcept {
    posix_ctx_t* ctx = reinterpret_cast<posix_ctx_t*>(network_data);

    conn_ctx_t coctx{&connection};

    coctx.res = accept(socket, &connection.client_address, &connection.client_address_len);
    if (coctx.res == -1)
        coctx.res = -errno;
    else {
#if defined(UCALL_IS_WINDOWS)
        u_long mode = 1; // 1 to enable non-blocking socket, 0 to disable
        ioctlsocket(coctx.res, FIONBIO, &mode);
#else
        int flags = fcntl(coctx.res, F_GETFL, 0);
        flags |= O_NONBLOCK;
        fcntl(coctx.res, F_SETFL, flags);
#endif
    }
    ctx->queue_mutex.lock();
    ctx->res_queue.push(coctx);
    ctx->queue_mutex.unlock();

    return 0;
}

void network_engine_t::set_stats_heartbeat(connection_t& connection) noexcept {
    posix_ctx_t* ctx = reinterpret_cast<posix_ctx_t*>(network_data);

    conn_ctx_t coctx{&connection, 0};
    // TODO what?

    ctx->queue_mutex.lock();
    ctx->res_queue.push(coctx);
    ctx->queue_mutex.unlock();
}

void network_engine_t::close_connection_gracefully(connection_t& connection) noexcept {
    posix_ctx_t* ctx = reinterpret_cast<posix_ctx_t*>(network_data);

    conn_ctx_t coctx{&connection, close(connection.descriptor)};
    if (coctx.res == -1)
        coctx.res = errno;

    ctx->queue_mutex.lock();
    ctx->res_queue.push(coctx);
    ctx->queue_mutex.unlock();
}

void network_engine_t::send_packet(connection_t& connection, void* buffer, size_t buffer_length,
                                   size_t buf_index) noexcept {
    posix_ctx_t* ctx = reinterpret_cast<posix_ctx_t*>(network_data);
    conn_ctx_t coctx{&connection};
    ssize_t res = 0;

    res = send(connection.descriptor, (const char*)buffer, buffer_length, MSG_NOSIGNAL);
    coctx.res = (res == -1) ? -errno : res;

    ctx->queue_mutex.lock();
    ctx->res_queue.push(coctx);
    ctx->queue_mutex.unlock();
}

void network_engine_t::recv_packet(connection_t& connection, void* buffer, size_t buffer_length,
                                   size_t buf_index) noexcept {
    posix_ctx_t* ctx = reinterpret_cast<posix_ctx_t*>(network_data);

    conn_ctx_t coctx{&connection};
    ssize_t res = 0;

    res = recv(connection.descriptor, (char*)buffer, buffer_length, MSG_NOSIGNAL);
    coctx.res = (res == -1) ? -errno : res;

    ctx->queue_mutex.lock();
    ctx->res_queue.push(coctx);
    ctx->queue_mutex.unlock();
}

bool network_engine_t::is_canceled(ssize_t res, unum::ucall::connection_t const& conn) noexcept {
    return res == -ECANCELED || res == -EWOULDBLOCK || res == -EAGAIN;
}

bool network_engine_t::is_corrupted(ssize_t res, unum::ucall::connection_t const& conn) noexcept {
    return res == -EBADF || res == -EPIPE;
}

template <size_t max_count_ak> std::size_t network_engine_t::pop_completed_events(completed_event_t* events) noexcept {
    posix_ctx_t* ctx = reinterpret_cast<posix_ctx_t*>(network_data);

    size_t completed = 0;

    ctx->queue_mutex.lock();

    while (!ctx->res_queue.empty() && completed < max_count_ak) {
        auto& ev = ctx->res_queue.front();

        events[completed].connection_ptr = ev.conn_ptr;
        events[completed].result = ev.res;

        ++completed;
        ctx->res_queue.pop();
    }

    ctx->queue_mutex.unlock();

    return completed;
}