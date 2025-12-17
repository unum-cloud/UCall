/**
 *  @brief Protocol-specific shared logic for HTTP and WebSockets including Noise Protocol encryption,
 *         memory buffers, exchange pipes, and URI routing.
 *
 *  @section Overview
 *
 *  This file implements the core connection management and protocol state machine shared between
 *  HTTP and WebSocket implementations. Key features:
 *
 *  - **Noise Protocol encryption**: Replaces TLS with lightweight Noise Framework (XX/IK/KK patterns)
 *  - **URI template routing**: Immutable trie-based routing for efficient endpoint matching
 *  - **Zero-copy buffers**: Exchange pipes with embedded+dynamic memory management
 *  - **Connection pooling**: Reusable connection states for millions of concurrent connections
 *
 *  @note This file doesn't contain general-purpose utilities - those belong in @c shared.hpp.
 *        It only focuses on network protocol-related shared logic.
 *
 *  @file src/protocol_shared.hpp
 *  @author Ash Vardanian
 *  @date January 13, 2025
 */
#pragma once

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#define UCALL_IS_WINDOWS
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

#if defined(__linux__)
#define UCALL_IS_LINUX
#endif

#if defined(UCALL_IS_WINDOWS)
#include <Windows.h>
#else
#include <sys/mman.h>
#endif

#include <atomic>
#include <cerrno>
#include <cstring>
#include <memory>
#include <string_view> // `std::string_view`

#if defined(__x86_64__)
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
#endif

#include <ucall/ucall.h> // `ucall_callback_t`

#include <noise/protocol.h> // Noise Protocol Framework
#include "routes.hpp"       // URI template routing trie

namespace unum::ucall {

using network_data_t = void *;

/// @brief To avoid dynamic memory allocations on tiny requests,
/// for every connection we keep a tiny embedded buffer of this capacity.
static constexpr std::size_t ram_page_size_k = 4096;

/// @brief Number of bytes in a printed integer.
/// Used either for error codes, or for request IDs.
static constexpr std::size_t max_integer_length_k = 32;

/// @brief Needed for largest-register-aligned memory addressing.
static constexpr std::size_t align_k = 128;

/// @brief Accessing real time from user-space is very expensive.
/// To approximate we can use CPU cycle counters.
constexpr std::size_t cpu_cycles_per_micro_second_k = 3'000;

static constexpr std::size_t max_inactive_duration_ns_k {10'000'000'000}; // 10 sec
static constexpr std::size_t wakeup_initial_frequency_ns_k {100};
static constexpr std::size_t sleep_growth_factor_k {2};

inline std::size_t string_length(char const *c_str, std::size_t optional_length) noexcept {
    return c_str && !optional_length ? std::strlen(c_str) : optional_length;
}

/**
 *  @brief Rounds integer to the next multiple of a given number. Is needed for aligned memory allocations.
 */
template <std::size_t step_>
constexpr std::size_t round_up_to(std::size_t n) noexcept {
    return ((n + step_ - 1) / step_) * step_;
}

/**
 *  @brief Represents the various stages a connection can be in during its lifecycle.
 *
 *  State transitions follow this pattern:
 *  @code
 *  unknown_k → waiting_to_accept_k → expecting_reception_k ↔ responding_in_progress_k → waiting_to_close_k → unknown_k
 *  @endcode
 */
enum class stage_t {
    waiting_to_accept_k = 0,  // Waiting for incoming connection to be accepted
    expecting_reception_k,    // Waiting to receive data from client
    responding_in_progress_k, // Sending response data to client
    waiting_to_close_k,       // Closing connection gracefully
    log_stats_k,              // Pseudo-connection state for periodic stats logging
    unknown_k,                // Initial/invalid state
};

/**
 *  @brief Describes a combination of static and dynamic memory used by a single
 *    client-server connection for uni-directional communication, either inbound or outbound.
 */
struct exchange_pipe_t {
    byte_t *embedded {};
    std::size_t embedded_used {};
    array<byte_t> dynamic {};

    span<byte_t> span() noexcept {
        return dynamic.size() ? span<byte_t> {dynamic.begin(), dynamic.end()}
                              : span<byte_t> {embedded, embedded + embedded_used};
    }
};

/**
 *  @brief Manages bidirectional data exchange with hybrid embedded/dynamic buffering.
 *
 *  Each connection has two pipes (input/output) with two-tier memory management:
 *  - @b Embedded buffers (4KB): Stack-allocated, zero-allocation fast path for small messages
 *  - @b Dynamic buffers: Heap-allocated fallback for large messages
 *
 *  Data flow:
 *  1. Incoming data lands in embedded input buffer
 *  2. If more data expected, shifts to dynamic buffer
 *  3. Response builds in embedded output buffer
 *  4. If response exceeds 4KB, shifts to dynamic buffer
 *
 *  @note Non-copyable and non-movable to maintain buffer pointer stability.
 */
class exchange_pipes_t {
    /**
     *  @brief A combination of an embedded and dynamic memory pool for content reception.
     *  We always absorb new packets in the embedded part, later moving them into dynamic memory,
     *  if any more data is expected. Requires @b padding at the end, to accelerate parsing.
     */
    exchange_pipe_t input_ {};
    /**  @brief A combination of an embedded and dynamic memory pool for response content. */
    exchange_pipe_t output_ {};
    std::size_t output_submitted_ {};

  public:
    exchange_pipes_t() noexcept = default;
    exchange_pipes_t(exchange_pipes_t &&) = delete;
    exchange_pipes_t(exchange_pipes_t const &) = delete;
    exchange_pipes_t &operator=(exchange_pipes_t &&) = delete;
    exchange_pipes_t &operator=(exchange_pipes_t const &) = delete;

    void mount(byte_t *inputs, byte_t *outputs) noexcept {
        input_.embedded = inputs;
        output_.embedded = outputs;
    }

#pragma region Context Switching

    void release_inputs() noexcept {
        input_.dynamic.reset();
        input_.embedded_used = 0;
    }

    void release_current_input() noexcept { input_.embedded_used = 0; }

    void release_outputs() noexcept {
        output_.dynamic.reset();
        output_.embedded_used = 0;
        output_submitted_ = 0;
    }

    span<byte_t> input_span() noexcept { return input_.span(); }
    span<byte_t> output_span() noexcept { return output_.span(); }

#pragma endregion

#pragma region Piping Inputs
    char *next_input_address() noexcept { return input_.embedded; }
    std::size_t next_input_length() const noexcept { return ram_page_size_k; }

    /**
     *  @brief Discards the first 'cnt' elements from the embedded buffer.
     */
    void drop_embedded_n(size_t cnt) noexcept {
        if (cnt > input_.embedded_used) return release_inputs();
        input_.embedded_used -= cnt;
        std::memmove(input_.embedded, input_.embedded + cnt, input_.embedded_used);
    }

    void drop_last_input(size_t cnt) noexcept {
        if (input_.dynamic.size() >= cnt) input_.dynamic.pop_back(cnt);
        else if (input_.embedded_used >= cnt) input_.embedded_used -= cnt;
    }

    bool shift_input_to_dynamic() noexcept {
        if (!input_.dynamic.append_n(input_.embedded, input_.embedded_used)) return false;
        input_.embedded_used = 0;
        return true;
    }

    bool absorb_input(std::size_t embedded_used) noexcept {
        input_.embedded_used = embedded_used;
        if (!input_.dynamic.size()) return true;
        return shift_input_to_dynamic();
    }

#pragma endregion
#pragma region Piping Outputs

    void mark_submitted_outputs(std::size_t n) noexcept { output_submitted_ += n; }
    void prepare_more_outputs() noexcept {
        if (!output_.dynamic.size()) return;
        output_.embedded_used = (std::min)(output_.dynamic.size() - output_submitted_, ram_page_size_k);
        std::memcpy(output_.embedded, output_.dynamic.data() + output_submitted_, output_.embedded_used);
    }
    bool has_outputs() const noexcept { return (std::max)(output_.embedded_used, output_.dynamic.size()); }
    bool has_remaining_outputs() const noexcept {
        return output_submitted_ < (std::max)(output_.embedded_used, output_.dynamic.size());
    }
    char const *next_output_address() const noexcept {
        return output_.dynamic.size() ? output_.embedded : output_.embedded + output_submitted_;
    }

    std::size_t next_output_length() const noexcept {
        return output_.dynamic.size() ? output_.embedded_used : output_.embedded_used - output_submitted_;
    }

    bool append_outputs(std::string_view body) noexcept {
        bool was_in_embedded = !output_.dynamic.size();
        bool fit_into_embedded = output_.embedded_used + body.size() < ram_page_size_k;

        if (was_in_embedded && fit_into_embedded) {
            memcpy(output_.embedded + output_.embedded_used, body.data(), body.size());
            output_.embedded_used += body.size();
            return true;
        }
        else {
            if (!output_.dynamic.reserve(output_.dynamic.size() + output_.embedded_used + body.size())) return false;
            if (was_in_embedded) {
                if (!output_.dynamic.append_n(output_.embedded, output_.embedded_used)) return false;
                output_.embedded_used = 0;
            }
            if (!output_.dynamic.append_n(body.data(), body.size())) return false;
            return true;
        }
    }

#pragma endregion

#pragma region Replacing

    void output_pop_back() noexcept {
        if (output_.dynamic.size()) output_.dynamic.pop_back();
        else output_.embedded_used--;
    }

    void push_back_reserved(char c) noexcept {
        if (output_.dynamic.size()) output_.dynamic.push_back_reserved(c);
        else output_.embedded[output_.embedded_used++] = c;
    }

    void append_reserved(char const *c, std::size_t n) noexcept {
        if (output_.dynamic.size()) output_.dynamic.append_n(c, n);
        else std::memcpy(output_.embedded + output_.embedded_used, c, n), output_.embedded_used += n;
    }

#pragma endregion
};

/**
 *  @brief  A named callback needed to describe an endpoint.
 */
struct endpoint_t {
    std::string_view name {};
    ucall_callback_t callback {};
    ucall_verb_t verb {};
    ucall_endpoint_tag_t tag {};
};

struct connection_stats_t {
    std::size_t exchanged_messages {};
    std::size_t exchanged_packets {};
    std::size_t exchanged_bytes {};
    std::size_t empty_transmits {};
    std::size_t time_start {};
    std::size_t time_last {};
    std::size_t time_keep_alive {};
};

/**
 *  @brief Represents a connection with Noise Protocol encryption, buffering,
 *    and state management for secure communication.
 */
struct connection_t {
    /// @brief Exchange buffers to pipe information in both directions.
    exchange_pipes_t pipes {};

    /// @brief The file descriptor of the stateful connection over TCP.
    descriptor_t descriptor {bad_descriptor_k};

    /// @brief Current state at which the automata has arrived.
    stage_t stage {};

    /// @brief The IP address of the client on the opposite end of this connection.
    sockaddr client_address {};
    socklen_t client_address_length {sizeof(client_address)};

    /// @brief Accumulated duration of sleep cycles.
    std::size_t last_active_ns {};
    std::size_t exchanges {};
    std::size_t empty_transmits {};

    /// @brief Relative time set for the last wake-up call.
    /// This value is incremented for every following wake-up.
    ssize_t next_wakeup {wakeup_initial_frequency_ns_k};

    /// @brief Noise Protocol handshake state for secure key exchange.
    /// Active during handshake phase, freed after transitioning to transport phase.
    NoiseHandshakeState *noise_handshake {};

    /// @brief Send cipher state for encrypting outbound messages in transport phase.
    NoiseCipherState *noise_send_cipher {};

    /// @brief Receive cipher state for decrypting inbound messages in transport phase.
    NoiseCipherState *noise_recv_cipher {};

    /// @brief Flag indicating whether handshake is complete and transport phase has begun.
    bool noise_handshake_complete {};

    void record_activity() noexcept {
        last_active_ns = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    }

    bool expired() const noexcept {
        return std::chrono::high_resolution_clock::now().time_since_epoch().count() - last_active_ns >
               max_inactive_duration_ns_k;
    }

    bool must_close() const noexcept {
        auto conn = protocol.get_header("Connection");
        return conn == "Close" || conn == "close";
    }

    /**
     *  @brief Initialize Noise Protocol handshake for this connection.
     *  @param[in] pattern_name Noise pattern (e.g., "Noise_XX_25519_ChaChaPoly_BLAKE2s")
     *  @param[in] is_initiator True if this side initiates the handshake, false if responding
     *  @param[in] local_private_key Optional pointer to 32-byte local private key (for IK/KK patterns)
     *  @param[in] remote_public_key Optional pointer to 32-byte remote public key (for IK/KK patterns)
     *  @return True on success, false on failure
     */
    [[nodiscard]] bool noise_init_handshake(                  //
        char const *pattern_name, bool is_initiator,          //
        ucall_noise_key_t const *local_private_key = nullptr, //
        ucall_noise_key_t const *remote_public_key = nullptr) noexcept {

        int role = is_initiator ? NOISE_ROLE_INITIATOR : NOISE_ROLE_RESPONDER;
        int err = noise_handshakestate_new_by_name(&noise_handshake, pattern_name, role);
        if (err != NOISE_ERROR_NONE) return false;

        // Set local private key if provided
        if (local_private_key) {
            NoiseDHState *dh = noise_handshakestate_get_local_keypair_dh(noise_handshake);
            if (dh) {
                err = noise_dhstate_set_keypair_private(dh, *local_private_key, sizeof(ucall_noise_key_t));
                if (err != NOISE_ERROR_NONE) {
                    noise_handshakestate_free(noise_handshake);
                    noise_handshake = nullptr;
                    return false;
                }
            }
        }

        // Set remote public key if provided (for IK/KK patterns)
        if (remote_public_key) {
            NoiseDHState *dh = noise_handshakestate_get_remote_public_key_dh(noise_handshake);
            if (dh) {
                err = noise_dhstate_set_public_key(dh, *remote_public_key, sizeof(ucall_noise_key_t));
                if (err != NOISE_ERROR_NONE) {
                    noise_handshakestate_free(noise_handshake);
                    noise_handshake = nullptr;
                    return false;
                }
            }
        }

        // Start the handshake
        err = noise_handshakestate_start(noise_handshake);
        if (err != NOISE_ERROR_NONE) {
            noise_handshakestate_free(noise_handshake);
            noise_handshake = nullptr;
            return false;
        }

        noise_handshake_complete = false;
        return true;
    }

    /**
     *  @brief Perform one step of the Noise handshake protocol.
     *  @return True if handshake step succeeded, false on error
     *
     *  @note Checks if handshake is complete and transitions to transport phase automatically.
     */
    [[nodiscard]] bool noise_handshake_step() noexcept {
        if (!noise_handshake || noise_handshake_complete) return false;

        int action = noise_handshakestate_get_action(noise_handshake);
        NoiseBuffer mbuf;
        int err;

        if (action == NOISE_ACTION_WRITE_MESSAGE) {
            // Generate handshake message to send
            noise_buffer_set_output(mbuf, pipes.next_output_address(), pipes.next_output_length());
            err = noise_handshakestate_write_message(noise_handshake, &mbuf, nullptr);
            if (err != NOISE_ERROR_NONE) return false;
            pipes.append_outputs({(char const *)mbuf.data, mbuf.size});
        }
        else if (action == NOISE_ACTION_READ_MESSAGE) {
            // Process received handshake message
            auto input = pipes.input_span();
            noise_buffer_set_input(mbuf, input.data(), input.size());
            err = noise_handshakestate_read_message(noise_handshake, &mbuf, nullptr);
            if (err != NOISE_ERROR_NONE) return false;
        }

        // Check if handshake is complete
        action = noise_handshakestate_get_action(noise_handshake);
        if (action == NOISE_ACTION_SPLIT) {
            // Transition to transport phase
            err = noise_handshakestate_split(noise_handshake, &noise_send_cipher, &noise_recv_cipher);
            if (err != NOISE_ERROR_NONE) return false;

            // Free handshake state, no longer needed
            noise_handshakestate_free(noise_handshake);
            noise_handshake = nullptr;
            noise_handshake_complete = true;
        }

        return true;
    }

    /**
     *  @brief Encrypt outbound message payload using Noise transport cipher.
     *  @return True on success, false on failure
     *
     *  @note Only works after handshake is complete. Operates on pipes.output_span().
     */
    [[nodiscard]] bool noise_encrypt() noexcept {
        if (!noise_handshake_complete || !noise_send_cipher) return false;

        auto plaintext = pipes.output_span();
        constexpr std::size_t tag_size = 16; // ChaCha20-Poly1305 authentication tag
        std::size_t ciphertext_len = plaintext.size() + tag_size;

        // Use stack-allocated buffer (up to page size)
        if (ciphertext_len > ram_page_size_k) return false;
        byte_t ciphertext_buf[ram_page_size_k];

        NoiseBuffer mbuf;
        noise_buffer_set_output(mbuf, ciphertext_buf, ciphertext_len);
        noise_buffer_set_input(mbuf, plaintext.data(), plaintext.size());

        int err = noise_cipherstate_encrypt(noise_send_cipher, &mbuf);
        if (err != NOISE_ERROR_NONE) return false;

        // Replace plaintext output with ciphertext
        pipes.release_outputs();
        return pipes.append_outputs({(char const *)ciphertext_buf, mbuf.size});
    }

    /**
     *  @brief Decrypt inbound message payload using Noise transport cipher.
     *  @param[in] ciphertext_len Length of received ciphertext
     *  @return True on success, false on authentication failure or other error
     *
     *  @note Only works after handshake is complete. Operates on pipes.input_span().
     */
    [[nodiscard]] bool noise_decrypt(std::size_t ciphertext_len) noexcept {
        if (!noise_handshake_complete || !noise_recv_cipher) return false;

        auto ciphertext = pipes.input_span();
        if (ciphertext.size() < ciphertext_len) return false;

        // Use stack-allocated buffer (up to page size)
        if (ciphertext_len > ram_page_size_k) return false;
        byte_t plaintext_buf[ram_page_size_k];

        NoiseBuffer mbuf;
        noise_buffer_set_input(mbuf, ciphertext.data(), ciphertext_len);
        noise_buffer_set_output(mbuf, plaintext_buf, ciphertext_len);

        int err = noise_cipherstate_decrypt(noise_recv_cipher, &mbuf);
        if (err != NOISE_ERROR_NONE) return false;

        // Replace ciphertext input with plaintext
        pipes.release_current_input();
        if (!pipes.absorb_input(mbuf.size)) return false;
        std::memcpy(pipes.next_input_address(), plaintext_buf, mbuf.size);
        return true;
    }

    void reset() noexcept {
        stage = stage_t::unknown_k;
        client_address = {};

        pipes.release_inputs();
        pipes.release_outputs();

        // Clean up Noise Protocol state
        if (noise_handshake) {
            noise_handshakestate_free(noise_handshake);
            noise_handshake = nullptr;
        }
        if (noise_send_cipher) {
            noise_cipherstate_free(noise_send_cipher);
            noise_send_cipher = nullptr;
        }
        if (noise_recv_cipher) {
            noise_cipherstate_free(noise_recv_cipher);
            noise_recv_cipher = nullptr;
        }
        noise_handshake_complete = false;

        exchanges = 0;
        empty_transmits = 0;
        next_wakeup = wakeup_initial_frequency_ns_k;
    }
};

struct completed_event_t {
    connection_t *connection_ptr {};
    int result {};
};

enum class stats_logs_format_t {
    human_readable_k,
    json_k,
    none_k,
};

/**
 *  @brief A state common to any backend. Contains a routing trie for `endpoints`, settings for the
 *  connection, the `socket` descriptor, a pool of `connections`, and a pool of `buffers`,
 *  and aggregates stats across all of the connections.
 *
 *  @section How to keep track of connections and reuse them when the time comes?
 *
 */
struct server_state_t {
    /// @brief Immutable routing trie for URI template matching. Routes registered at startup.
    route_trie_t routes {};

    std::uint32_t max_lifetime_micro_seconds {};
    std::uint32_t max_lifetime_exchanges {};

    /// @brief File descriptor of the TCP socket.
    descriptor_t socket {};

    /// @brief A container of reusable connections. Can be in millions.
    pool<connection_t> connections_pool {};

    /// @brief A binary heap, with a root, that is the oldest accessed connection.
    /// When we reach the capacity of `connections_pool`, we pop elements from here,
    /// until the popped element has a better "importance score", then the next root.
    /// If the new root is has lower score, the extracted element is returned into the
    /// heap, and the process continues. Otherwise, the extracted "root" connection is reused.
    /// To ensure that there are no in-flight messages coming on that socket
    span<connection_t *> connections_heap {};

    /// @brief Atomic counter for the number of allocated elements in the `connections_pool` pool.
    std::atomic<std::size_t> active_connections {};

    /// @brief Synchronizes concurrent access to `connections` from different threads.
    mutex_t connections_mutex {};

    /// @brief Pre-allocated buffered for small messages, often registered for
    /// shared use between this user-space server program and kernel-space NIC driver.
    memory_map_t fixed_buffers {};

    traffic_stats_t stats {};

    /// @brief A connection context we use to schedule logging using the same underlying engine.
    connection_t stats_pseudo_connection {};

    stats_logs_format_t logs_format {stats_logs_format_t::human_readable_k};
    std::int32_t logs_file_descriptor {};

    void log_and_reset_stats() noexcept {
        static char printed_message_k[ram_page_size_k] {};
        std::size_t len;
        switch (logs_format) {
        case stats_logs_format_t::json_k: len = stats.log_json(printed_message_k, ram_page_size_k); break;
        case stats_logs_format_t::human_readable_k:
            len =
                stats.log_human_readable(printed_message_k, ram_page_size_k, traffic_stats_t::default_frequency_secs_k);
            break;
        default: len = 0; break;
        }
        len = write(logs_file_descriptor, printed_message_k, len);
    }

    void release_connection(connection_t &connection) noexcept {
        auto is_active = connection.stage != stage_t::waiting_to_accept_k;
        connection.reset();
        connections_mutex.lock();
        connections.release(&connection);
        connections_mutex.unlock();
        active_connections -= is_active;
        stats.closed_connections.fetch_add(is_active, std::memory_order_relaxed);
    }
};

/**
 *  @brief Non-owning view of parsed HTTP request components.
 *
 *  All @c std::string_view members point into the connection's input buffer.
 *  Valid only while the buffer remains unchanged.
 */
struct parsed_request_t {
    ucall_verb_t type {};               // HTTP method (GET, POST, PUT, DELETE, etc.)
    std::string_view path {};           // Request path (e.g., "/users/123")
    std::string_view content_type {};   // Content-Type header value
    std::string_view content_length {}; // Content-Length header value
    std::string_view body {};           // Request body payload
};

parsed_request_t parse_request(std::string_view) {
    // TODO:
    return {};
}

/**
 *  @brief Registers an endpoint handler in the routing trie.
 *  @param[in] uri_template The URI template pattern (e.g., "/users/{id}").
 *  @param[in] verb The HTTP verb for this endpoint.
 *  @param[in] callback The callback function pointer.
 *  @param[in] callback_tag Optional user context for the callback.
 *  @return True if registration succeeded, false on error.
 *
 *  @note Must be called during server initialization before handling requests.
 */
[[nodiscard]] inline bool server_state_t::register_endpoint( //
    std::string_view uri_template, ucall_verb_t verb,        //
    ucall_callback_t callback, void *callback_tag = nullptr) noexcept {
    return routes.insert(uri_template, verb, (void *)callback, callback_tag);
}

void server_state_t::submit_stats_heartbeat() noexcept {
    connection_t &connection = stats_pseudo_connection;
    connection.stage = stage_t::log_stats_k;
    connection.next_wakeup = traffic_stats_t::default_frequency_secs_k;

    network_engine.set_stats_heartbeat(connection);
}

bool server_state_t::consider_accepting_new_connection() noexcept {

    connections_mutex.lock();
    connection_t *con_ptr = connections.alloc();
    connections_mutex.unlock();

    if (!con_ptr) return false;

    connection_t &connection = *con_ptr;
    connection.stage = stage_t::waiting_to_accept_k;
    int result = network_engine.try_accept(socket, connection);

    if (result < 0) {
        connections.release(con_ptr);
        return false;
    }

    return true;
}

/**
 *  @brief  A class that suggests transitions from one `connection.stage` to another.
 */

struct update_status_t {
    ssize_t code {};

    bool is_corrupted() const noexcept { return code == -EPIPE || code == -EBADF; }
};

template <typename engine_type_>
update_status_t update_connection(server_state_t &server, connection_t &connection, engine_type_ &&engine) noexcept {

    auto close_gracefully = [&]() noexcept {
        connection.stage = stage_t::waiting_to_close_k;
        engine.close_connection_gracefully(connection);
    };

    auto send_next = [&]() noexcept {
        exchange_pipes_t &pipes = connection.pipes;
        connection.stage = stage_t::responding_in_progress_k;
        pipes.release_inputs();

        engine.send_packet(connection, (void *)pipes.next_output_address(), pipes.next_output_length(),
                           server.connections.offset_of(connection) * 2u + 1u);
    };

    auto receive_next = [&]() noexcept {
        exchange_pipes_t &pipes = connection.pipes;
        connection.stage = stage_t::expecting_reception_k;
        pipes.release_outputs();

        engine.recv_packet(connection, (void *)pipes.next_input_address(), pipes.next_input_length(),
                           server.connections.offset_of(connection) * 2u);
    };

    auto raise_request = [&]() noexcept {
        exchange_pipes_t &pipes = connection.pipes;
        parsed_request_t request = parse_request(pipes.input_span());
        if (request.type == ucall_verb_t::unknown_k) return ucall_reply_error(call, -EINVAL, "Unknown verb", 12);

        // TODO:
        // pipes.append_reserved(http_header_k, http_header_size_k);
        // content_length = pipes.output_span().size();

        //     auto error_ptr = protocol.populate_response(pipes, [&](std::string_view& method_name, ucall_verb_t verb)
        //     {
        //         auto endpoints_end = endpoints.data() + endpoints.size();
        //         auto endpoint_it = std::find_if(endpoints.data(), endpoints_end, [&](endpoint_t const& endpoint)
        //         noexcept {
        //             return endpoint.type == verb && endpoint.method_matches(method_name);
        //         });
        //         if (endpoint_it == endpoints_end)
        //             return false;

        //         endpoint_t named_endpoint = *endpoint_it;
        //         method_name = named_endpoint.name;
        //         named_endpoint.endpoint(call, named_endpoint.endpoint_tag);
        //         return true;
        //     });
        //     if (error_ptr)
        //         return ucall_reply_error(call, error_ptr->code, error_ptr->note.data(), error_ptr->note.size());
        //     protocol.finalize_response(pipes);
    };

    switch (connection.stage) {

    case stage_t::waiting_to_accept_k:

        if (engine.is_canceled(completed_result, connection)) {
            server.release_connection(connection);
            return;
        }

        // Check if accepting the new connection request worked out.
        connection.record_activity();
        ++server.active_connections;
        server.stats.added_connections.fetch_add(1, std::memory_order_relaxed);
        connection.descriptor = descriptor_t {completed_result};
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
        if (engine.is_corrupted(completed_result, connection) || connection.expired()) return close_gracefully();

        if (engine.is_canceled(completed_result, connection)) {
            connection.next_wakeup *= sleep_growth_factor_k;
            completed_result = 0;
        }

        // No data was received.
        if (completed_result == 0) {
            connection.empty_transmits++;
            return receive_next();
        }

        // Absorb the arrived data.
        server.stats.bytes_received.fetch_add(completed_result, std::memory_order_relaxed);
        server.stats.packets_received.fetch_add(1, std::memory_order_relaxed);
        connection.empty_transmits = 0;
        connection.record_activity();
        if (!connection.pipes.absorb_input(completed_result)) {
            ucall_reply_error_out_of_memory(this);
            return send_next();
        }

        // If we have reached the end of the stream,
        // it is time to analyze the contents
        // and send back a response.
        if (connection.protocol.is_input_complete(connection.pipes.input_span())) {
            server.engine.raise_request(connection.pipes, connection.protocol, this);

            connection.pipes.release_inputs();
            // Some requests require no response at all,
            // so we can go back to listening the port.
            if (!connection.pipes.has_outputs()) {
                connection.exchanges++;
                // if (connection.exchanges >= server.max_lifetime_exchanges) TODO Why?
                //     return close_gracefully();
                // else
                return receive_next();
            }
            else {
                connection.pipes.prepare_more_outputs();
                return send_next();
            }
        }
        // We are looking for more data to come
        else if (connection.pipes.shift_input_to_dynamic()) { return receive_next(); }
        // We may fail to allocate memory to receive the next input
        else {
            ucall_reply_error_out_of_memory(this);
            return send_next();
        }

    case stage_t::responding_in_progress_k:
        if (engine.is_corrupted(completed_result, connection) || connection.expired()) return close_gracefully();

        connection.empty_transmits = completed_result == 0 ? ++connection.empty_transmits : 0;

        if (engine.is_canceled(completed_result, connection)) {
            connection.next_wakeup *= sleep_growth_factor_k;
            completed_result = 0;
        }

        connection.record_activity();
        server.stats.bytes_sent.fetch_add(completed_result, std::memory_order_relaxed);
        server.stats.packets_sent.fetch_add(1, std::memory_order_relaxed);
        connection.pipes.mark_submitted_outputs(completed_result);
        if (!connection.pipes.has_remaining_outputs()) {
            connection.exchanges++;
            if (connection.must_close()) return close_gracefully();
            else return receive_next();
        }
        else {
            connection.pipes.prepare_more_outputs();
            return send_next();
        }

    case stage_t::waiting_to_close_k: return server.release_connection(connection);

    case stage_t::log_stats_k: server.log_and_reset_stats(); return server.submit_stats_heartbeat();

    case stage_t::unknown_k: return;
    }
}

} // namespace unum::ucall
