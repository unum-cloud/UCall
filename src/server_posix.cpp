/**
 *  @brief Server backend implementation for HTTP 1.1, WebSockets, and Noise Protocol
 *    over TCP/IP for POSIX systems.
 *
 *  This is the simplest baseline server implementation used as a self-contained reference
 *  for future implementations of epoll and io_uring backends on Linux, and IOCP on Windows.
 *
 *  Requests and responses are handled in a blocking manner, one at a time, per connection.
 *  Batch-capable endpoints come with dynamically growing buffers, to dispatch only once a
 *  critical number of requests is collected or a timeout is reached.
 *
 *  @file src/server_posix.cpp
 *  @author Ash Vardanian
 *  @date November 14, 2025
 */

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#define UCALL_IS_WINDOWS
#include <Ws2tcpip.h>
#include <io.h>
#include <winsock2.h>

#define SHUT_WR SD_SEND
#define SHUT_RD SD_RECEIVE
#define SHUT_RDWR SD_BOTH
#define SO_REUSEPORT 0 // `SO_REUSEPORT` is not supported on Windows
#define MSG_NOSIGNAL 0 // `MSG_NOSIGNAL` is not supported on Windows
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

#include "protocol_shared.hpp"

#include <charconv> // `std::to_chars`
#include <chrono>   // `std::chrono`

#include <ucall/ucall.h>
#include "routes.hpp"

using namespace unum::ucall;
using namespace unum;
namespace sj = simdjson;
namespace sjd = simdjson::dom;

static constexpr std::size_t initial_buffer_size_k = ram_page_size_k * 4;

/**
 *  @brief A POSIX-specific implementation of a connection to a specific client.
 *    The @c posix_server_t will have one such structure per active connection.
 */
struct posix_connection_t {

    /** @brief The file descriptor of the stateful connection over TCP. */
    descriptor_t connection {};

    /** @brief A small memory buffer to store small requests. */
    alignas(align_k) char packet_buffer[ram_page_size_k + sj::SIMDJSON_PADDING] {};
};

struct posix_server_t {
    ~posix_server_t() noexcept {}

    /** @brief The file descriptor of the listening socket. */
    descriptor_t socket {};

    /** @brief A trie of endpoints mapping to function callbacks. Can be in hundreds. */
    route_trie_t endpoints {};

    /** @brief Statically allocated memory to process small requests. */
    array<byte_t> scratch {};

    /** @brief Separate dynamic buffer for every batch endpoint with per-request TTL. */
    array<char> buffer {};

    traffic_stats_t stats {};
    std::int32_t logs_file_descriptor {};
    std::string_view logs_format {};
    time_point_t log_last_time {};
};

sj::simdjson_result<sjd::element> param_at(ucall_call_t call, ucall_str_t name, size_t name_len) noexcept {
    posix_server_t &engine = *reinterpret_cast<posix_server_t *>(call);
    scratch_space_t &scratch = engine.scratch;
    name_len = string_length(name, name_len);
    return scratch.point_to_param({name, name_len});
}

sj::simdjson_result<sjd::element> param_at(ucall_call_t call, size_t position) noexcept {
    posix_server_t &engine = *reinterpret_cast<posix_server_t *>(call);
    scratch_space_t &scratch = engine.scratch;
    return scratch.point_to_param(position);
}

void send_message(posix_server_t &engine, array<char> const &message) noexcept {
    char const *buf = message.data();
    size_t const len = message.size();
    long idx = 0;
    long res = 0;

    while (idx < len && (res = send(engine.connection, buf + idx, len - idx, 0)) > 0) idx += res;

    if (res < 0) {
        if (errno == EMSGSIZE) ucall_call_reply_error_out_of_memory(&engine);
        return;
    }
    engine.stats.bytes_sent += idx;
    engine.stats.packets_sent++;
}

void forward_call(posix_server_t &engine) noexcept {
    scratch_space_t &scratch = engine.scratch;
    auto callback_or_error = find_callback(engine.callbacks, scratch);
    if (auto error_ptr = std::get_if<default_error_t>(&callback_or_error); error_ptr)
        return ucall_call_reply_error(&engine, error_ptr->code, error_ptr->note.data(), error_ptr->note.size());

    named_callback_t call_data = std::get<named_callback_t>(callback_or_error);
    return call_data.callback(&engine, call_data.callback_tag);
}

/**
 *  @brief A POSIX-specific implementation of the UCall server, that augments `server_state_t`
 *  with a LIFO queue of
 */
struct posix_server_t {
    server_state_t state;

    // The major difference between batch and single-request paths is that
    // in the first case we need to keep a copy of the data somewhere,
    // until answers to all requests are accumulated and we can submit them
    // simultaneously.
    // Linux supports `MSG_MORE` flag for submissions, which could have helped,
    // but it is less effective than assembling a copy here.
    if (one_or_many.is_array()) {
        sjd::array many = one_or_many.get_array().value_unsafe();
        scratch.is_batch = false;

        // Start a JSON array.
        scratch.is_batch = true;
        bool res = true;
        if (scratch.is_http) res &= engine.buffer.append_n(http_header_k, http_header_size_k);

        res &= engine.buffer.append_n("[", 1);

        for (sjd::element const one : many) {
            scratch.tree = one;
            forward_call(engine);
        }

        if (engine.buffer[engine.buffer.size() - 1] == ',') engine.buffer.pop_back();

        res &= engine.buffer.append_n("]", 1);

        if (!res) return ucall_call_reply_error_out_of_memory(&engine);

        if (scratch.is_http) set_http_content_length(engine.buffer.data(), engine.buffer.size() - http_header_size_k);

        send_message(engine, engine.buffer);

        engine.buffer.reset();
    }
    else {
        scratch.is_batch = false;
        scratch.tree = one_or_many.value_unsafe();
        forward_call(engine);
        engine.buffer.reset();
    }
}

void forward_packet(posix_server_t& engine) noexcept {
    scratch_space_t &scratch = engine.scratch;
    auto json_or_error = split_body_headers(scratch.dynamic_packet);
    if (auto error_ptr = std::get_if<default_error_t>(&json_or_error); error_ptr)
        return ucall_call_reply_error(&engine, error_ptr->code, error_ptr->note.data(), error_ptr->note.size());

    auto request = std::get<parsed_request_t>(json_or_error);
    scratch.is_http = request.type.size();
    scratch.dynamic_packet = request.body;
    return forward_call_or_calls(engine);
}

int recv_all(posix_server_t &engine, char *buf, size_t len) {
    size_t idx = 0;
    int res = 0;

    while (idx < len && (res = recv(engine.connection, buf + idx, len - idx, 0)) > 0) idx += res;

    return idx;
}

void ucall_take_call(ucall_server_t server, uint16_t) {
    posix_server_t &engine = *reinterpret_cast<posix_server_t *>(server);
    scratch_space_t &scratch = engine.scratch;

    // Log stats, if enough time has passed since last call.
    if (engine.logs_file_descriptor > 0) {
        auto now = time_clock_t::now();
        auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(now - engine.log_last_time).count();
        if (dt > traffic_stats_t::default_frequency_secs_k * 1000ul) {
            auto len = engine.logs_format == "json" //
                           ? engine.stats.log_json(engine.packet_buffer, ram_page_size_k)
                           : engine.stats.log_human_readable(engine.packet_buffer, ram_page_size_k, dt / 1000ul);
            len = write(engine.logs_file_descriptor, engine.packet_buffer, len);
            engine.log_last_time = now;
        }
    }

    // If no pending connections are present on the queue, and the
    // socket is not marked as nonblocking, accept() blocks the caller
    // until a connection is present. If the socket is marked
    // nonblocking and no pending connections are present on the queue,
    // accept() fails with the error EAGAIN or EWOULDBLOCK.
    int connection_fd = accept(engine.socket, (struct sockaddr *)NULL, NULL);
    if (connection_fd < 0) {
        // Drop the last error.
        errno;
        return;
    }

    // Wait until we have input.
    engine.connection = descriptor_t {connection_fd};
    engine.stats.added_connections++;
    engine.stats.closed_connections++;
    char *buffer_ptr = &engine.packet_buffer[0];

    size_t bytes_received = 0, bytes_expected = 0;
    bytes_received = recv(engine.connection, buffer_ptr, http_head_max_size_k, 0);

    auto json_or_error = split_body_headers(std::string_view(buffer_ptr, bytes_received));
    if (auto error_ptr = std::get_if<default_error_t>(&json_or_error); error_ptr)
        return ucall_call_reply_error(&engine, error_ptr->code, error_ptr->note.data(), error_ptr->note.size());
    parsed_request_t request = std::get<parsed_request_t>(json_or_error);
    auto res = std::from_chars(request.content_length.data(),
                               request.content_length.data() + request.content_length.size(), bytes_expected);
    bytes_expected += (request.body.data() - buffer_ptr);

    if (res.ec == std::errc::invalid_argument || bytes_expected <= 0)
#if !defined(UCALL_IS_WINDOWS)
        if (ioctl(engine.connection, FIONREAD, &bytes_expected) == -1 || bytes_expected == 0)
#endif
            bytes_expected = bytes_received; // TODO what?

    // Either process it in the statically allocated memory,
    // or allocate dynamically, if the message is too long.
    size_t bytes_left = bytes_expected - bytes_received;

    if (bytes_expected <= ram_page_size_k) {
        bytes_received += recv_all(engine, buffer_ptr + bytes_received, bytes_left);
        scratch.dynamic_parser = &scratch.parser;
        scratch.dynamic_packet = std::string_view(buffer_ptr, bytes_received);
        engine.stats.bytes_received += bytes_received;
        engine.stats.packets_received++;
        forward_packet(engine);
    }
    else {
        sjd::parser parser;
        if (parser.allocate(bytes_expected, bytes_expected / 2) != sj::SUCCESS)
            return ucall_call_reply_error_out_of_memory(&engine);

#if defined(UCALL_IS_WINDOWS)
        buffer_ptr = (char *)_aligned_malloc(round_up_to<align_k>(bytes_expected + sj::SIMDJSON_PADDING), align_k);
#else
        buffer_ptr = (char *)std::aligned_alloc(align_k, round_up_to<align_k>(bytes_expected + sj::SIMDJSON_PADDING));
#endif
        if (!buffer_ptr) return ucall_call_reply_error_out_of_memory(&engine);

        memcpy(buffer_ptr, &engine.packet_buffer[0], bytes_received);

        bytes_received += recv_all(engine, buffer_ptr + bytes_received, bytes_left);
        scratch.dynamic_parser = &parser;
        scratch.dynamic_packet = std::string_view(buffer_ptr, bytes_received);
        engine.stats.bytes_received += bytes_received;
        engine.stats.packets_received++;
        forward_packet(engine);
#if defined(UCALL_IS_WINDOWS)
        _aligned_free(buffer_ptr);
#else
        std::free(buffer_ptr);
#endif
        buffer_ptr = nullptr;
    }

    shutdown(connection_fd, SHUT_WR);
    // If later on some UB is detected for client not recieving full data,
    // then it may be required to put a `recv` with timeout between `shutdown` and `close`
    close(connection_fd);
}

void ucall_init(ucall_config_t *config_inout, ucall_server_t *server_out) {

    // Simple sanity check
    if (!server_out && !config_inout) return;

    // Retrieve configs, if present
    ucall_config_t &config = *config_inout;
    if (!config.port) config.port = 8545u;
    if (!config.queue_depth) config.queue_depth = 4096u;
    if (!config.max_callbacks) config.max_callbacks = 128u;
    if (!config.max_concurrent_connections) config.max_concurrent_connections = 1024u;
    if (!config.max_threads) config.max_threads = 1u;
    if (!config.max_lifetime_micro_seconds) config.max_lifetime_micro_seconds = 100'000u;
    if (!config.max_lifetime_exchanges) config.max_lifetime_exchanges = 100u;
    if (!config.hostname) config.hostname = "0.0.0.0";

    // Allocate
    int socket_options {1};
    int socket_descriptor {-1};
    posix_server_t *server_ptr = nullptr;
    array<char> buffer;
    array<named_callback_t> embedded_callbacks;
    sjd::parser parser;

    // By default, let's open TCP port for IPv4.
    struct sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(config.hostname);
    address.sin_port = htons(config.port);

    // Try allocating all the necessary memory.
    server_ptr = (server_state_t *)std::malloc(sizeof(server_state_t));
    if (!server_ptr) goto cleanup;
    if (!callbacks.reserve(config.max_callbacks)) goto cleanup;
    if (!posix_server->fixed_buffers.reserve(ram_page_size_k * 2u * config.max_concurrent_connections)) goto cleanup;
    if (!connections.reserve(config.max_concurrent_connections)) goto cleanup;

    for (std::size_t i = 0; i != config.max_concurrent_connections; ++i) {
        auto &connection = connections.at_offset(i);
        auto inputs = posix_server->fixed_buffers.ptr + ram_page_size_k * 2u * i;
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
    if (socket_descriptor < 0) goto cleanup;
    if (setsockopt(socket_descriptor, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                   reinterpret_cast<char const *>(&socket_options), sizeof(socket_options)) == -1)
        errno;
    if (bind(socket_descriptor, (struct sockaddr *)&address, sizeof(address)) < 0) goto cleanup;
    if (listen(socket_descriptor, config.queue_depth) < 0) goto cleanup;
    if (parser.allocate(ram_page_size_k, ram_page_size_k / 2) != sj::SUCCESS) goto cleanup;

    // Initialize all the members.
    new (server_ptr) server_state_t();
    server_ptr->network_engine.network_data = posix_server;
    server_ptr->socket = descriptor_t {socket_descriptor};
    server_ptr->ssl_context = std::move(ssl_context);
    server_ptr->protocol_type = config.protocol;
    server_ptr->max_lifetime_micro_seconds = config.max_lifetime_micro_seconds;
    server_ptr->max_lifetime_exchanges = config.max_lifetime_exchanges;
    server_ptr->engine.callbacks = std::move(callbacks);
    server_ptr->connections = std::move(connections);
    server_ptr->logs_file_descriptor = config.logs_file_descriptor;
    server_ptr->logs_format = config.logs_format ? std::string_view(config.logs_format) : std::string_view();
    server_ptr->log_last_time = time_clock_t::now();
    *server_out = (ucall_server_t)server_ptr;
    return;

cleanup:
    errno;
    if (socket_descriptor >= 0) close(socket_descriptor);
    std::free(server_ptr);
    delete posix_server;
    *server_out = nullptr;
}

void ucall_free(ucall_server_t punned_server) {
    if (!punned_server) return;

    posix_server_t *ctx = reinterpret_cast<posix_server_t *>(server.network_engine.network_data);
    close(server.socket);
    server.~server_state_t();
    std::free(punned_server);
    delete ctx;
}

int posix_server_t::try_accept(descriptor_t socket, connection_t &connection) noexcept {

    posix_server_t *ctx = reinterpret_cast<posix_server_t *>(network_data);

    conn_ctx_t coctx {&connection};

    coctx.res = accept(socket, &connection.client_address, &connection.client_address_length);
    if (coctx.res == -1) coctx.res = -errno;
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

void posix_server_t::set_stats_heartbeat(connection_t &connection) noexcept {

    posix_server_t *ctx = reinterpret_cast<posix_server_t *>(network_data);

    conn_ctx_t coctx {&connection, 0};
    // TODO what?

    ctx->queue_mutex.lock();
    ctx->res_queue.push(coctx);
    ctx->queue_mutex.unlock();
}

void posix_server_t::close_connection_gracefully(connection_t &connection) noexcept {
    posix_server_t *ctx = reinterpret_cast<posix_server_t *>(network_data);

    conn_ctx_t coctx {&connection, close(connection.descriptor)};
    if (coctx.res == -1) coctx.res = errno;

    ctx->queue_mutex.lock();
    ctx->res_queue.push(coctx);
    ctx->queue_mutex.unlock();
}

void posix_server_t::send_packet(connection_t& connection, void* buffer, size_t buffer_length,
    posix_server_t* ctx = reinterpret_cast<posix_server_t*>(network_data);
    conn_ctx_t coctx{&connection};
    ssize_t res = 0;

    res = send(connection.descriptor, (const char*)buffer, buffer_length, MSG_NOSIGNAL);
    coctx.res = (res == -1) ? -errno : res;

    ctx->queue_mutex.lock();
    ctx->res_queue.push(coctx);
    ctx->queue_mutex.unlock();
}

void posix_server_t::recv_packet(connection_t& connection, void* buffer, size_t buffer_length,
    posix_server_t* ctx = reinterpret_cast<posix_server_t*>(network_data);

    conn_ctx_t coctx{&connection};
    ssize_t res = 0;

    res = recv(connection.descriptor, (char*)buffer, buffer_length, MSG_NOSIGNAL);
    coctx.res = (res == -1) ? -errno : res;

    ctx->queue_mutex.lock();
    ctx->res_queue.push(coctx);
    ctx->queue_mutex.unlock();
}

bool posix_server_t::is_canceled(ssize_t res, unum::ucall::connection_t const &conn) noexcept {
    return res == -ECANCELED || res == -EWOULDBLOCK || res == -EAGAIN;
}

bool posix_server_t::is_corrupted(ssize_t res, unum::ucall::connection_t const &conn) noexcept {
    return res == -EBADF || res == -EPIPE;
}

template <size_t max_count_ak>
std::size_t posix_server_t::pop_completed_events(completed_event_t *events) noexcept {

    posix_server_t *ctx = reinterpret_cast<posix_server_t *>(network_data);

    size_t completed = 0;

    ctx->queue_mutex.lock();

    while (!ctx->res_queue.empty() && completed < max_count_ak) {
        auto &ev = ctx->res_queue.front();

        events[completed].connection_ptr = ev.conn_ptr;
        events[completed].result = ev.res;

        ++completed;
        ctx->res_queue.pop();
    }

    bool ucall_param_positional_str(ucall_call_t call, size_t position, ucall_str_t *result_ptr,
                                    size_t *result_len_ptr) {
        if (auto value = param_at(call, position); value.is_string()) {
            *result_ptr = value.get_string().value_unsafe().data();
            *result_len_ptr = value.get_string_length().value_unsafe();
            return true;
        }
        else return false;
    }
