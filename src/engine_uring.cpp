/**
 * @brief JSON-RPC implementation for TCP/IP stack with `io_uring`.
 *
 * Supports:
 * > Thousands of concurrent stateful connections.
 * > Hundreds of physical execution threads.
 * > Both HTTP and HTTP-less raw JSON-RPC calls.
 *
 * @section Primary structures
 * - `engine_t`: primary server instance.
 * - `connection_t`: lifetime state of a single TCP connection.
 * - `scratch_space_t`: temporary memory used by a single thread at a time.
 * - `automata_t`: automata that accepts and responds to messages.
 *
 * @section Concurrency
 * The whole class is thread safe and can be used with as many threads as
 * defined during construction with `ucall_init`. Some `connection_t`-s
 * can, however, be simultaneously handled by two threads, if one logical
 * operation is split into multiple physical calls:
 *
 *      1.  Receiving packets with timeouts.
 *          This allows us to reconsider closing a connection every once
 *          in a while, instead of loyally waiting for more data to come.
 *      2.  Closing sockets gracefully.
 *
 * @section Linux kernel requirements
 * We need Submission Queue Polling to extract maximum performance from `io_uring`.
 * Many of the requests would get an additional `IOSQE_FIXED_FILE` flag, and the
 * setup call would receive `IORING_SETUP_SQPOLL`. Aside from those, we also
 * need to prioritize following efficient interfaces:
 * - `io_uring_prep_accept_direct` to alloc from reusable files list > 5.19..
 * - `io_uring_prep_read_fixed` to read into registered buffers.
 * - `io_uring_register_buffers`.
 * - `io_uring_register_files_sparse` > 5.19, or `io_uring_register_files` before that.
 * - `IORING_SETUP_COOP_TASKRUN` > 5.19.
 * - `IORING_SETUP_SINGLE_ISSUER` > 6.0.
 *
 * @author Ash Vardanian
 *
 * @see Notable links:
 * https://man7.org/linux/man-pages/dir_by_project.html#liburing
 * https://jvns.ca/blog/2017/06/03/async-io-on-linux--select--poll--and-epoll/
 * https://stackoverflow.com/a/17665015/2766161
 */
#include <arpa/inet.h>  // `inet_addr`
#include <fcntl.h>      // `fcntl`
#include <netinet/in.h> // `sockaddr_in`
#include <stdlib.h>     // `std::aligned_malloc`
#include <sys/ioctl.h>
#include <sys/mman.h>   // `mmap`
#include <sys/socket.h> // `recv`, `setsockopt`
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <liburing.h>

#include <charconv> // `std::to_chars`
#include <mutex>    // `std::mutex`
#include <optional> // `std::optional`

#include <simdjson.h>

#include "ucall/ucall.h"

#include "helpers/exchange.hpp"
#include "helpers/log.hpp"
#include "helpers/parse.hpp"
#include "helpers/reply.hpp"
#include "helpers/shared.hpp"

#pragma region Cpp Declaration

namespace sj = simdjson;
namespace sjd = sj::dom;
using namespace unum::ucall;

/// @brief As we use SIMDJSON, we don't want to fill our message buffers entirely.
/// If there is a @b padding at the end, matching the size of the largest CPU register
/// on the machine, we would avoid copies.
static constexpr std::size_t max_embedded_length_k{ram_page_size_k - sj::SIMDJSON_PADDING};
static constexpr std::size_t sleep_growth_factor_k{4};
static constexpr std::size_t wakeup_initial_frequency_ns_k{3'000};
static constexpr std::size_t max_inactive_duration_ns_k{100'000'000'000};
static constexpr descriptor_t invalid_descriptor_k{-1};

struct completed_event_t;
struct connection_t;
struct engine_t;
struct automata_t;

enum class stage_t {
    waiting_to_accept_k = 0,
    expecting_reception_k,
    responding_in_progress_k,
    waiting_to_close_k,
    log_stats_k,
    unknown_k,
};

struct completed_event_t {
    connection_t* connection_ptr{};
    stage_t stage{};
    int result{};
};

class alignas(align_k) mutex_t {
    std::atomic<bool> flag{false};

  public:
    void lock() noexcept {
        while (flag.exchange(true, std::memory_order_relaxed))
            ;
        std::atomic_thread_fence(std::memory_order_acquire);
    }

    void unlock() noexcept {
        std::atomic_thread_fence(std::memory_order_release);
        flag.store(false, std::memory_order_relaxed);
    }
};

struct connection_t {

    /// @brief Exchange buffers to pipe information in both directions.
    exchange_pipes_t pipes{};

    /// @brief The file descriptor of the stateful connection over TCP.
    descriptor_t descriptor{invalid_descriptor_k};
    /// @brief Current state at which the automata has arrived.
    stage_t stage{};

    struct sockaddr client_address {};
    socklen_t client_address_len{sizeof(struct sockaddr)};

    /// @brief Accumulated duration of sleep cycles.
    std::size_t sleep_ns{};
    std::size_t empty_transmits{};
    std::size_t exchanges{};

    /// @brief Relative time set for the last wake-up call.
    struct __kernel_timespec next_wakeup {
        0, wakeup_initial_frequency_ns_k
    };
    /// @brief Absolute time extracted from HTTP headers, for the requested lifetime of this channel.
    std::optional<struct __kernel_timespec> keep_alive{};
    /// @brief Expected reception length extracted from HTTP headers.
    std::optional<std::size_t> content_length{};
    /// @brief Expected MIME type of payload extracted from HTTP headers. Generally "application/json".
    std::optional<std::string_view> content_type{};

    connection_t() noexcept {}

    bool expired() const noexcept;
    void reset() noexcept;
};

struct memory_map_t {
    char* ptr{};
    std::size_t length{};

    memory_map_t() = default;
    memory_map_t(memory_map_t const&) = delete;
    memory_map_t& operator=(memory_map_t const&) = delete;

    memory_map_t(memory_map_t&& other) noexcept {
        std::swap(ptr, other.ptr);
        std::swap(length, other.length);
    }

    memory_map_t& operator=(memory_map_t&& other) noexcept {
        std::swap(ptr, other.ptr);
        std::swap(length, other.length);
        return *this;
    }

    bool reserve(std::size_t length, int flags = MAP_ANONYMOUS | MAP_PRIVATE) noexcept {
        // Make sure that the `length` is a multiple of `page_size`
        // auto page_size = sysconf(_SC_PAGE_SIZE);
        auto new_ptr = (char*)mmap(ptr, length, PROT_WRITE | PROT_READ, flags, -1, 0);
        if (new_ptr == MAP_FAILED) {
            errno;
            return false;
        }
        std::memset(new_ptr, 0, length);
        ptr = new_ptr;
        return true;
    }

    ~memory_map_t() noexcept {
        if (ptr)
            munmap(ptr, length);
        ptr = nullptr;
        length = 0;
    }
};

struct engine_t {
    descriptor_t socket{};
    struct io_uring uring {};
    bool has_send_zc{};

    std::atomic<std::size_t> active_connections{};
    std::atomic<std::size_t> reserved_connections{};
    std::atomic<std::size_t> dismissed_connections{};
    std::uint32_t max_lifetime_micro_seconds{};
    std::uint32_t max_lifetime_exchanges{};

    mutex_t submission_mutex{};
    mutex_t completion_mutex{};
    mutex_t connections_mutex{};

    stats_t stats{};
    connection_t stats_pseudo_connection{};
    std::int32_t logs_file_descriptor{};
    std::string_view logs_format{};

    /// @brief An array of function callbacks. Can be in dozens.
    array_gt<named_callback_t> callbacks{};
    /// @brief A circular container of reusable connections. Can be in millions.
    pool_gt<connection_t> connections{};
    /// @brief Same number of them, as max physical threads. Can be in hundreds.
    buffer_gt<scratch_space_t> spaces{};
    /// @brief Pre-allocated buffered to be submitted to `io_uring` for shared use.
    memory_map_t fixed_buffers{};

    bool consider_accepting_new_connection() noexcept;
    void submit_stats_heartbeat() noexcept;
    void release_connection(connection_t&) noexcept;
    void log_and_reset_stats() noexcept;

    template <std::size_t max_count_ak> std::size_t pop_completed(completed_event_t*) noexcept;
};

bool io_check_send_zc() noexcept {
    io_uring_probe* probe = io_uring_get_probe();
    if (!probe)
        return false;

    // Available since 6.0.
    bool res = io_uring_opcode_supported(probe, IORING_OP_SEND_ZC);
    io_uring_free_probe(probe);
    return res;
}

struct automata_t {

    engine_t& engine;
    scratch_space_t& scratch;
    connection_t& connection;
    stage_t completed_stage{};
    int completed_result{};

    void operator()() noexcept;
    bool is_corrupted() const noexcept { return completed_result == -EPIPE || completed_result == -EBADF; }

    // Computed properties:
    bool received_full_request() const noexcept;
    bool should_release() const noexcept;

    // Submitting to io_uring:
    void send_next() noexcept;
    void receive_next() noexcept;
    void close_gracefully() noexcept;

    // Helpers:
    void raise_call() noexcept;
    void raise_call_or_calls() noexcept;
    void parse_and_raise_request() noexcept;
};

sj::simdjson_result<sjd::element> param_at(ucall_call_t call, ucall_str_t name, size_t name_len) noexcept {
    automata_t& automata = *reinterpret_cast<automata_t*>(call);
    scratch_space_t& scratch = automata.scratch;
    name_len = string_length(name, name_len);
    return scratch.point_to_param({name, name_len});
}

sj::simdjson_result<sjd::element> param_at(ucall_call_t call, size_t position) noexcept {
    automata_t& automata = *reinterpret_cast<automata_t*>(call);
    scratch_space_t& scratch = automata.scratch;
    return scratch.point_to_param(position);
}

#pragma endregion Cpp Declaration
#pragma region C Definitions

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
    struct io_uring uring {};
    struct io_uring_params uring_params {};
    struct io_uring_sqe* uring_sqe{};
    struct io_uring_cqe* uring_cqe{};
    uring_params.features |= IORING_FEAT_FAST_POLL;
    uring_params.features |= IORING_FEAT_SQPOLL_NONFIXED;
    // uring_params.flags |= IORING_SETUP_COOP_TASKRUN;
    uring_params.flags |= IORING_SETUP_SQPOLL;
    uring_params.sq_thread_idle = wakeup_initial_frequency_ns_k;
    // uring_params.flags |= config.max_threads == 1 ? IORING_SETUP_SINGLE_ISSUER : 0; // 6.0+
    engine_t* server_ptr{};
    pool_gt<connection_t> connections{};
    array_gt<named_callback_t> callbacks{};
    buffer_gt<scratch_space_t> spaces{};
    buffer_gt<struct iovec> registered_buffers{};
    memory_map_t fixed_buffers{};

    // By default, let's open TCP port for IPv4.
    struct sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(config.hostname);
    address.sin_port = htons(config.port);

    // Initialize `io_uring` first, it is the most likely to fail.
    uring_result = io_uring_queue_init_params(config.queue_depth, &uring, &uring_params);
    if (uring_result != 0)
        goto cleanup;

    // Try allocating all the necessary memory.
    server_ptr = (engine_t*)std::malloc(sizeof(engine_t));
    if (!server_ptr)
        goto cleanup;
    if (!callbacks.reserve(config.max_callbacks))
        goto cleanup;
    if (!fixed_buffers.reserve(ram_page_size_k * 2u * config.max_concurrent_connections))
        goto cleanup;
    if (!connections.reserve(config.max_concurrent_connections))
        goto cleanup;
    if (!spaces.resize(config.max_threads))
        goto cleanup;
    for (auto& space : spaces)
        if (space.parser.allocate(ram_page_size_k, ram_page_size_k / 2u) != sj::SUCCESS)
            goto cleanup;

    // Additional `io_uring` setup.
    if (!registered_buffers.resize(config.max_concurrent_connections * 2u))
        goto cleanup;
    for (std::size_t i = 0; i != config.max_concurrent_connections; ++i) {
        auto& connection = connections.at_offset(i);
        auto inputs = fixed_buffers.ptr + ram_page_size_k * 2u * i;
        auto outputs = inputs + ram_page_size_k;
        connection.pipes.mount(inputs, outputs);

        registered_buffers[i * 2u].iov_base = inputs;
        registered_buffers[i * 2u].iov_len = ram_page_size_k;
        registered_buffers[i * 2u + 1u].iov_base = outputs;
        registered_buffers[i * 2u + 1u].iov_len = ram_page_size_k;
    }
    uring_result = io_uring_register_files_sparse(&uring, config.max_concurrent_connections);
    if (uring_result != 0)
        goto cleanup;
    uring_result =
        io_uring_register_buffers(&uring, registered_buffers.data(), static_cast<unsigned>(registered_buffers.size()));
    if (uring_result != 0)
        goto cleanup;

    // Configure the socket.
    // In the past we would use the normal POSIX call, but we should prefer direct descriptors over it.
    // socket_descriptor = socket(AF_INET, SOCK_STREAM, 0);
    uring_sqe = io_uring_get_sqe(&uring);
    io_uring_prep_socket_direct(uring_sqe, AF_INET, SOCK_STREAM, 0, IORING_FILE_INDEX_ALLOC, 0);
    uring_result = io_uring_submit_and_wait(&uring, 1);
    uring_result = io_uring_wait_cqe(&uring, &uring_cqe);
    socket_descriptor = uring_cqe->res;
    if (socket_descriptor < 0)
        goto cleanup;
    // Not sure if this is required, after we have a kernel with `IORING_OP_SENDMSG_ZC` support, we can check.
    // if (setsockopt(socket_descriptor, SOL_SOCKET, SO_ZEROCOPY, &socket_options, sizeof(socket_options)) == -1)
    //     goto cleanup;
    if (bind(socket_descriptor, (struct sockaddr*)&address, sizeof(address)) < 0)
        goto cleanup;
    if (listen(socket_descriptor, config.queue_depth) < 0)
        goto cleanup;

    // Initialize all the members.
    new (server_ptr) engine_t();
    server_ptr->socket = descriptor_t{socket_descriptor};
    server_ptr->max_lifetime_micro_seconds = config.max_lifetime_micro_seconds;
    server_ptr->max_lifetime_exchanges = config.max_lifetime_exchanges;
    server_ptr->callbacks = std::move(callbacks);
    server_ptr->connections = std::move(connections);
    server_ptr->spaces = std::move(spaces);
    server_ptr->uring = uring;
    server_ptr->has_send_zc = io_check_send_zc();
    server_ptr->logs_file_descriptor = config.logs_file_descriptor;
    server_ptr->logs_format = config.logs_format ? std::string_view(config.logs_format) : std::string_view();
    *server_out = (ucall_server_t)server_ptr;
    return;

cleanup:
    errno;
    if (uring.ring_fd)
        io_uring_queue_exit(&uring);
    if (socket_descriptor >= 0)
        close(socket_descriptor);
    std::free(server_ptr);
    *server_out = nullptr;
}

void ucall_add_procedure(ucall_server_t server, ucall_str_t name, ucall_callback_t callback,
                         ucall_callback_tag_t callback_tag) {
    engine_t& engine = *reinterpret_cast<engine_t*>(server);
    if (engine.callbacks.size() + 1 < engine.callbacks.capacity())
        engine.callbacks.push_back_reserved({name, callback, callback_tag});
}

void ucall_free(ucall_server_t server) {
    if (!server)
        return;

    engine_t& engine = *reinterpret_cast<engine_t*>(server);
    io_uring_unregister_buffers(&engine.uring);
    io_uring_queue_exit(&engine.uring);
    close(engine.socket);
    engine.~engine_t();
    std::free(server);
}

void ucall_take_calls(ucall_server_t server, uint16_t thread_idx) {
    engine_t& engine = *reinterpret_cast<engine_t*>(server);
    if (!thread_idx && engine.logs_file_descriptor > 0)
        engine.submit_stats_heartbeat();
    while (true) {
        ucall_take_call(server, thread_idx);
    }
}

void ucall_take_call(ucall_server_t server, uint16_t thread_idx) {
    // Unlike the classical synchronous interface, this implements only a part of the connection machine,
    // is responsible for checking if a specific request has been completed. All of the submitted
    // memory must be preserved until we get the confirmation.
    engine_t& engine = *reinterpret_cast<engine_t*>(server);
    if (!thread_idx)
        engine.consider_accepting_new_connection();

    constexpr std::size_t completed_max_k{16};
    completed_event_t completed_events[completed_max_k]{};
    std::size_t completed_count = engine.pop_completed<completed_max_k>(completed_events);

    for (std::size_t i = 0; i != completed_count; ++i) {
        completed_event_t& completed = completed_events[i];
        automata_t automata{
            engine, //
            engine.spaces[thread_idx],
            *completed.connection_ptr,
            completed.stage,
            completed.result,
        };

        // If everything is fine, let automata work in its normal regime.
        automata();
    }
}

void ucall_call_reply_content(ucall_call_t call, ucall_str_t body, size_t body_len) {
    automata_t& automata = *reinterpret_cast<automata_t*>(call);
    connection_t& connection = automata.connection;
    scratch_space_t& scratch = automata.scratch;
    // No response is needed for "id"-less notifications.
    if (scratch.dynamic_id.empty())
        return;

    body_len = string_length(body, body_len);
    struct iovec iovecs[iovecs_for_content_k]{};
    fill_with_content(iovecs, scratch.dynamic_id, std::string_view(body, body_len), true);
    connection.pipes.append_outputs<iovecs_for_content_k>(iovecs);
}

void ucall_call_reply_error(ucall_call_t call, int code_int, ucall_str_t note, size_t note_len) {
    automata_t& automata = *reinterpret_cast<automata_t*>(call);
    connection_t& connection = automata.connection;
    scratch_space_t& scratch = automata.scratch;
    // No response is needed for "id"-less notifications.
    if (scratch.dynamic_id.empty())
        return;

    note_len = string_length(note, note_len);
    char code[max_integer_length_k]{};
    std::to_chars_result res = std::to_chars(code, code + max_integer_length_k, code_int);
    auto code_len = res.ptr - code;
    if (res.ec != std::error_code())
        return ucall_call_reply_error_unknown(call);

    struct iovec iovecs[iovecs_for_error_k]{};
    fill_with_error(iovecs, scratch.dynamic_id, std::string_view(code, code_len), std::string_view(note, note_len),
                    true);
    if (!connection.pipes.append_outputs<iovecs_for_error_k>(iovecs))
        return ucall_call_reply_error_out_of_memory(call);
}

void ucall_call_reply_error_invalid_params(ucall_call_t call) {
    return ucall_call_reply_error(call, -32602, "Invalid method param(s).", 24);
}

void ucall_call_reply_error_unknown(ucall_call_t call) {
    return ucall_call_reply_error(call, -32603, "Unknown error.", 14);
}

void ucall_call_reply_error_out_of_memory(ucall_call_t call) {
    return ucall_call_reply_error(call, -32000, "Out of memory.", 14);
}

bool ucall_param_named_bool(ucall_call_t call, ucall_str_t name, size_t name_len, bool* result_ptr) {
    if (auto value = param_at(call, name, name_len); value.is_bool()) {
        *result_ptr = value.get_bool().value_unsafe();
        return true;
    } else
        return false;
}

bool ucall_param_named_i64(ucall_call_t call, ucall_str_t name, size_t name_len, int64_t* result_ptr) {
    if (auto value = param_at(call, name, name_len); value.is_int64()) {
        *result_ptr = value.get_int64().value_unsafe();
        return true;
    } else
        return false;
}

bool ucall_param_named_f64(ucall_call_t call, ucall_str_t name, size_t name_len, double* result_ptr) {
    if (auto value = param_at(call, name, name_len); value.is_double()) {
        *result_ptr = value.get_double().value_unsafe();
        return true;
    } else
        return false;
}

bool ucall_param_named_str(ucall_call_t call, ucall_str_t name, size_t name_len, ucall_str_t* result_ptr,
                           size_t* result_len_ptr) {
    if (auto value = param_at(call, name, name_len); value.is_string()) {
        *result_ptr = value.get_string().value_unsafe().data();
        *result_len_ptr = value.get_string_length().value_unsafe();
        return true;
    } else
        return false;
}

bool ucall_param_positional_bool(ucall_call_t call, size_t position, bool* result_ptr) {
    if (auto value = param_at(call, position); value.is_bool()) {
        *result_ptr = value.get_bool().value_unsafe();
        return true;
    } else
        return false;
}

bool ucall_param_positional_i64(ucall_call_t call, size_t position, int64_t* result_ptr) {
    if (auto value = param_at(call, position); value.is_int64()) {
        *result_ptr = value.get_int64().value_unsafe();
        return true;
    } else
        return false;
}

bool ucall_param_positional_f64(ucall_call_t call, size_t position, double* result_ptr) {
    if (auto value = param_at(call, position); value.is_double()) {
        *result_ptr = value.get_double().value_unsafe();
        return true;
    } else
        return false;
}

bool ucall_param_positional_str(ucall_call_t call, size_t position, ucall_str_t* result_ptr, size_t* result_len_ptr) {
    if (auto value = param_at(call, position); value.is_string()) {
        *result_ptr = value.get_string().value_unsafe().data();
        *result_len_ptr = value.get_string_length().value_unsafe();
        return true;
    } else
        return false;
}

#pragma endregion C Definitions
#pragma region Cpp Declarations

bool connection_t::expired() const noexcept {
    if (sleep_ns > max_inactive_duration_ns_k)
        return true;

    return false;
}

void connection_t::reset() noexcept {

    stage = stage_t::unknown_k;
    client_address = {};

    pipes.release_inputs();
    pipes.release_outputs();

    keep_alive.reset();
    content_length.reset();
    content_type.reset();

    sleep_ns = 0;
    empty_transmits = 0;
    exchanges = 0;
    next_wakeup.tv_nsec = wakeup_initial_frequency_ns_k;
}

bool automata_t::should_release() const noexcept {
    return connection.expired() || engine.dismissed_connections || connection.empty_transmits > 100;
}

bool automata_t::received_full_request() const noexcept {

    auto span = connection.pipes.input_span();
    // if (!connection.content_length) {
    size_t bytes_expected = 0;

    auto json_or_error = split_body_headers(std::string_view(span.data(), span.size()));
    if (auto error_ptr = std::get_if<default_error_t>(&json_or_error); error_ptr)
        return true;
    parsed_request_t request = std::get<parsed_request_t>(json_or_error);

    auto res = std::from_chars(request.content_length.begin(), request.content_length.end(), bytes_expected);
    bytes_expected += (request.body.begin() - span.data());

    if (res.ec == std::errc::invalid_argument || bytes_expected <= 0)
        // TODO: Maybe not a HTTP request, What to do?
        return true;

    connection.content_length = bytes_expected;
    // }

    if (span.size() < *connection.content_length)
        return false;

    return true;
}

void automata_t::raise_call() noexcept {
    auto callback_or_error = find_callback(engine.callbacks, scratch);
    if (auto error_ptr = std::get_if<default_error_t>(&callback_or_error); error_ptr)
        return ucall_call_reply_error(this, error_ptr->code, error_ptr->note.data(), error_ptr->note.size());

    named_callback_t named_callback = std::get<named_callback_t>(callback_or_error);
    return named_callback.callback(this, named_callback.callback_tag);
}

void automata_t::raise_call_or_calls() noexcept {
    exchange_pipes_t& pipes = connection.pipes;
    sjd::parser& parser = *scratch.dynamic_parser;
    std::string_view json_body = scratch.dynamic_packet;
    parser.set_max_capacity(json_body.size());
    auto one_or_many = parser.parse(json_body.data(), json_body.size(), false);
    if (one_or_many.error() == sj::CAPACITY)
        return ucall_call_reply_error_out_of_memory(this);

    // We may need to prepend the response with HTTP headers.
    if (scratch.is_http)
        pipes.append_reserved(http_header_k, http_header_size_k);

    size_t body_size = pipes.output_span().size();

    if (one_or_many.error() != sj::SUCCESS)
        return ucall_call_reply_error(this, -32700, "Invalid JSON was received by the server.", 40);

    // Check if we hve received a batch request.
    else if (one_or_many.is_array()) {
        sjd::array many = one_or_many.get_array().value_unsafe();
        scratch.is_batch = true;

        // Start a JSON array. Originally it must fit into `embedded` part.
        pipes.push_back_reserved('[');

        for (sjd::element const one : many) {
            scratch.tree = one;
            raise_call();
        }

        // Replace the last comma with the closing bracket.
        pipes.output_pop_back();
        pipes.push_back_reserved(']');
    }
    // This is a single request
    else {
        scratch.is_batch = false;
        scratch.tree = one_or_many.value_unsafe();
        raise_call();

        if (scratch.dynamic_id.empty()) {
            pipes.push_back_reserved('{');
            pipes.push_back_reserved('}');
        } else if (pipes.has_outputs()) // Drop the last comma, if present.
            pipes.output_pop_back();
    }

    // Now, as we know the length of the whole response, we can update
    // the HTTP headers to indicate thr real "Content-Length".
    if (scratch.is_http) {
        auto output = pipes.output_span();
        body_size = output.size() - body_size;
        if (!set_http_content_length(output.data(), body_size))
            return ucall_call_reply_error_out_of_memory(this);
    }
}

void automata_t::parse_and_raise_request() noexcept {
    auto request = connection.pipes.input_span();
    auto parsed_request_or_error = split_body_headers(request);
    if (auto error_ptr = std::get_if<default_error_t>(&parsed_request_or_error); error_ptr)
        // TODO: This error message may have to be wrapped into an HTTP header separately
        return ucall_call_reply_error(this, error_ptr->code, error_ptr->note.data(), error_ptr->note.size());

    auto parsed_request = std::get<parsed_request_t>(parsed_request_or_error);
    scratch.is_http = request.size() != parsed_request.body.size();
    scratch.dynamic_packet = parsed_request.body;
    if (scratch.dynamic_packet.size() > ram_page_size_k) {
        sjd::parser parser;
        if (parser.allocate(scratch.dynamic_packet.size(), scratch.dynamic_packet.size() / 2) != sj::SUCCESS)
            return ucall_call_reply_error_out_of_memory(this);
        else {
            scratch.dynamic_parser = &parser;
            return raise_call_or_calls();
        }
    } else {
        scratch.dynamic_parser = &scratch.parser;
        return raise_call_or_calls();
    }
}

template <std::size_t max_count_ak> std::size_t engine_t::pop_completed(completed_event_t* events) noexcept {

    unsigned uring_head{};
    unsigned completed{};
    unsigned passed{};
    struct io_uring_cqe* uring_cqe{};

    completion_mutex.lock();
    io_uring_for_each_cqe(&uring, uring_head, uring_cqe) {
        ++passed;
        if (!uring_cqe->user_data)
            continue;
        events[completed].connection_ptr = (connection_t*)uring_cqe->user_data;
        events[completed].stage = events[completed].connection_ptr->stage;
        events[completed].result = uring_cqe->res;
        ++completed;
        if (completed == max_count_ak)
            break;
    }

    io_uring_cq_advance(&uring, passed);
    completion_mutex.unlock();
    return completed;
}

bool engine_t::consider_accepting_new_connection() noexcept {
    std::size_t reserved_connections_old{};
    if (!reserved_connections.compare_exchange_strong(reserved_connections_old, 1u))
        return false;

    connections_mutex.lock();
    connection_t* con_ptr = connections.alloc();
    connections_mutex.unlock();
    if (!con_ptr) {
        dismissed_connections++;
        return false;
    }

    int uring_result{};
    struct io_uring_sqe* uring_sqe{};
    connection_t& connection = *con_ptr;
    connection.stage = stage_t::waiting_to_accept_k;
    submission_mutex.lock();

    uring_sqe = io_uring_get_sqe(&uring);
    io_uring_prep_accept_direct(uring_sqe, socket, &connection.client_address, &connection.client_address_len, 0,
                                IORING_FILE_INDEX_ALLOC);
    io_uring_sqe_set_data(uring_sqe, &connection);

    // Accepting new connections can be time-less.
    // io_uring_sqe_set_flags(uring_sqe, IOSQE_IO_LINK);
    // uring_sqe = io_uring_get_sqe(&uring);
    // io_uring_prep_link_timeout(uring_sqe, &connection.next_wakeup, 0);
    // io_uring_sqe_set_data(uring_sqe, NULL);

    uring_result = io_uring_submit(&uring);
    submission_mutex.unlock();
    if (uring_result < 0) {
        connections.release(con_ptr);
        reserved_connections--;
        return false;
    }

    dismissed_connections = 0;
    return true;
}

void engine_t::submit_stats_heartbeat() noexcept {
    int uring_result{};
    struct io_uring_sqe* uring_sqe{};
    connection_t& connection = stats_pseudo_connection;
    connection.stage = stage_t::log_stats_k;
    connection.next_wakeup.tv_sec = stats_t::default_frequency_secs_k;
    submission_mutex.lock();

    uring_sqe = io_uring_get_sqe(&uring);
    io_uring_prep_timeout(uring_sqe, &connection.next_wakeup, 0, 0);
    io_uring_sqe_set_data(uring_sqe, &connection);
    uring_result = io_uring_submit(&uring);
    submission_mutex.unlock();
}

void engine_t::log_and_reset_stats() noexcept {
    static char printed_message_k[ram_page_size_k]{};
    auto len = logs_format == "json" //
                   ? stats.log_json(printed_message_k, ram_page_size_k)
                   : stats.log_human_readable(printed_message_k, ram_page_size_k, stats_t::default_frequency_secs_k);
    len = write(logs_file_descriptor, printed_message_k, len);
}

void engine_t::release_connection(connection_t& connection) noexcept {
    auto is_active = connection.stage != stage_t::waiting_to_accept_k;
    connection.reset();
    connections_mutex.lock();
    connections.release(&connection);
    connections_mutex.unlock();
    active_connections -= is_active;
    stats.closed_connections.fetch_add(is_active, std::memory_order_relaxed);
}

void automata_t::close_gracefully() noexcept {
    int uring_result{};
    struct io_uring_sqe* uring_sqe{};
    connection.stage = stage_t::waiting_to_close_k;

    // The operations are not expected to complete in exactly the same order
    // as their submissions. So to stop all existing communication on the
    // socket, we can cancel everything related to its "file descriptor",
    // and then close.
    engine.submission_mutex.lock();
    uring_sqe = io_uring_get_sqe(&engine.uring);
    io_uring_prep_cancel_fd(uring_sqe, int(connection.descriptor), 0);
    io_uring_sqe_set_data(uring_sqe, NULL);
    io_uring_sqe_set_flags(uring_sqe, IOSQE_IO_HARDLINK);

    uring_sqe = io_uring_get_sqe(&engine.uring);
    io_uring_prep_shutdown(uring_sqe, int(connection.descriptor), SHUT_WR);
    io_uring_sqe_set_data(uring_sqe, NULL);
    io_uring_sqe_set_flags(uring_sqe, IOSQE_IO_HARDLINK);

    uring_sqe = io_uring_get_sqe(&engine.uring);
    io_uring_prep_close(uring_sqe, int(connection.descriptor));
    io_uring_sqe_set_data(uring_sqe, &connection);
    io_uring_sqe_set_flags(uring_sqe, 0);

    uring_result = io_uring_submit(&engine.uring);
    engine.submission_mutex.unlock();
}

void automata_t::send_next() noexcept {
    exchange_pipes_t& pipes = connection.pipes;
    int uring_result{};
    struct io_uring_sqe* uring_sqe{};
    connection.stage = stage_t::responding_in_progress_k;
    pipes.release_inputs();

    // TODO: Test and benchmark the `send_zc option`.
    engine.submission_mutex.lock();
    uring_sqe = io_uring_get_sqe(&engine.uring);
    if (engine.has_send_zc) {
        io_uring_prep_send_zc_fixed(uring_sqe, int(connection.descriptor), (void*)pipes.next_output_address(),
                                    pipes.next_output_length(), 0, 0,
                                    engine.connections.offset_of(connection) * 2u + 1u);
    } else {
        io_uring_prep_send(uring_sqe, int(connection.descriptor), (void*)pipes.next_output_address(),
                           pipes.next_output_length(), 0);
        uring_sqe->flags |= IOSQE_FIXED_FILE;
        uring_sqe->buf_index = engine.connections.offset_of(connection) * 2u + 1u;
    }
    io_uring_sqe_set_data(uring_sqe, &connection);
    io_uring_sqe_set_flags(uring_sqe, 0);
    uring_result = io_uring_submit(&engine.uring);
    engine.submission_mutex.unlock();
}

void automata_t::receive_next() noexcept {
    exchange_pipes_t& pipes = connection.pipes;
    int uring_result{};
    struct io_uring_sqe* uring_sqe{};
    connection.stage = stage_t::expecting_reception_k;
    pipes.release_outputs();

    engine.submission_mutex.lock();

    // Choosing between `recv` and `read` system calls:
    // > If a zero-length datagram is pending, read(2) and recv() with a
    // > flags argument of zero provide different behavior. In this
    // > circumstance, read(2) has no effect (the datagram remains
    // > pending), while recv() consumes the pending datagram.
    // https://man7.org/linux/man-pages/man2/recv.2.html
    //
    // In this case we are waiting for an actual data, not some artificial wakeup.
    uring_sqe = io_uring_get_sqe(&engine.uring);
    io_uring_prep_read_fixed(uring_sqe, int(connection.descriptor), (void*)pipes.next_input_address(),
                             pipes.next_input_length(), 0, engine.connections.offset_of(connection) * 2u);
    io_uring_sqe_set_data(uring_sqe, &connection);
    io_uring_sqe_set_flags(uring_sqe, IOSQE_IO_LINK);

    // More than other operations this depends on the information coming from the client.
    // We can't afford to keep connections alive indefinitely, so we need to set a timeout
    // on this operation.
    // The `io_uring_prep_link_timeout` is a convenience method for poorly documented `IORING_OP_LINK_TIMEOUT`.
    uring_sqe = io_uring_get_sqe(&engine.uring);
    io_uring_prep_link_timeout(uring_sqe, &connection.next_wakeup, 0);
    io_uring_sqe_set_data(uring_sqe, NULL);
    io_uring_sqe_set_flags(uring_sqe, 0);
    uring_result = io_uring_submit(&engine.uring);

    engine.submission_mutex.unlock();
}

void automata_t::operator()() noexcept {

    if (is_corrupted())
        return close_gracefully();

    switch (connection.stage) {

    case stage_t::waiting_to_accept_k:

        if (completed_result == -ECANCELED) {
            engine.release_connection(connection);
            engine.reserved_connections--;
            engine.consider_accepting_new_connection();
            return;
        }

        // Check if accepting the new connection request worked out.
        engine.reserved_connections--;
        engine.active_connections++;
        engine.stats.added_connections.fetch_add(1, std::memory_order_relaxed);
        connection.descriptor = descriptor_t{completed_result};
        return receive_next();

    case stage_t::expecting_reception_k:

        // From documentation:
        // > If used, the timeout specified in the command will cancel the linked command,
        // > unless the linked command completes before the timeout. The timeout will complete
        // > with -ETIME if the timer expired and the linked request was attempted canceled,
        // > or -ECANCELED if the timer got canceled because of completion of the linked request.
        //
        // So we expect only two outcomes here:
        // 1. reception expired with: `ECANCELED`, and subsequent timeout expired with `ETIME`.
        // 2. reception can continue and subsequent timer returned `ECANCELED`.
        //
        // If the following timeout request has happened,
        // we don't want to do anything here. Let's leave the faith of
        // this connection to the subsequent timer to decide.
        if (completed_result == -ECANCELED) {
            connection.sleep_ns += connection.next_wakeup.tv_nsec;
            connection.next_wakeup.tv_nsec *= sleep_growth_factor_k;
            completed_result = 0;
        }

        // No data was received.
        if (completed_result == 0) {
            connection.empty_transmits++;
            return should_release() ? close_gracefully() : receive_next();
        }

        // Absorb the arrived data.
        engine.stats.bytes_received.fetch_add(completed_result, std::memory_order_relaxed);
        engine.stats.packets_received.fetch_add(1, std::memory_order_relaxed);
        connection.empty_transmits = 0;
        connection.sleep_ns = 0;
        if (!connection.pipes.absorb_input(completed_result)) {
            ucall_call_reply_error_out_of_memory(this);
            return send_next();
        }

        // If we have reached the end of the stream,
        // it is time to analyze the contents
        // and send back a response.
        if (received_full_request()) {
            parse_and_raise_request();
            connection.pipes.release_inputs();
            // Some requests require no response at all,
            // so we can go back to listening the port.
            if (!connection.pipes.has_outputs()) {
                connection.exchanges++;
                if (connection.exchanges >= engine.max_lifetime_exchanges)
                    return close_gracefully();
                else
                    return receive_next();
            } else {
                connection.pipes.prepare_more_outputs();
                return send_next();
            }
        }
        // We are looking for more data to come
        else if (connection.pipes.shift_input_to_dynamic()) {
            return receive_next();
        }
        // We may fail to allocate memory to receive the next input
        else {
            ucall_call_reply_error_out_of_memory(this);
            return send_next();
        }

    case stage_t::responding_in_progress_k:

        connection.empty_transmits = completed_result == 0 ? ++connection.empty_transmits : 0;

        if (should_release())
            return close_gracefully();

        engine.stats.bytes_sent.fetch_add(completed_result, std::memory_order_relaxed);
        engine.stats.packets_sent.fetch_add(1, std::memory_order_relaxed);
        connection.pipes.mark_submitted_outputs(completed_result);
        if (!connection.pipes.has_remaining_outputs()) {
            connection.exchanges++;
            if (connection.exchanges >= engine.max_lifetime_exchanges)
                return close_gracefully();
            else
                return receive_next();
        } else {
            connection.pipes.prepare_more_outputs();
            return send_next();
        }

    case stage_t::waiting_to_close_k:
        return engine.release_connection(connection);

    case stage_t::log_stats_k:
        engine.log_and_reset_stats();
        return engine.submit_stats_heartbeat();

    case stage_t::unknown_k:
        return;
    }
}

#pragma endregion Cpp Declarations
