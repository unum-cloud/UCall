/**
 *  @file include/ucall/network/serving.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Admission, dispatch, and the steps of a server's event loops.
 */
#pragma once

#include "ucall/http/messages.hpp"      // `http_chunk_state_t`, `http_framing_t`, `http_parse_t`, `http_role_t`
#include "ucall/http/routes.hpp"        // `extract_path_component`
#include "ucall/io/types.hpp"           // `io_completion_t`, `io_operation_t`, `io_request_t`, `tally`
#include "ucall/network/exchanges.hpp"  // `detached_k`, `listed_k`
#include "ucall/network/formatting.hpp" // `shed_reply_k`
#include "ucall/network/loops.hpp"      // `event_loop_stage_t`, `metrics_state_t`
#include "ucall/network/transports.hpp" // `transport`
#include "ucall/network/types.hpp" // `server_stage_t`, `transport_stage_t`, `linger_microseconds_k`, `operation_state_t`
#include "ucall/tunnel/types.hpp"  // `secure_tunnel_role_t`
#include "ucall/utilities/sockets.hpp" // `deadline_after`, `io_vector_t`, `monotonic_ns`, `socket_open`
#include "ucall/utilities/types.hpp"   // `text_view`, `byte_t`, `bytes_view`, `publish`

namespace unum::ucall::network {

using http::every_verb_k;
using http::extract_path_component;
using http::http_chunk_state_t;
using http::http_connection_t;
using http::http_framing_t;
using http::http_parse_t;
using http::http_role_t;
using http::verb_set_t;
using io::io_completion_t;
using io::io_operation_t;
using io::io_peer_address_t;
using io::io_request_t;
using io::tally;
using tunnel::secure_tunnel_role_t;
using utilities::accept_failure_t;
using utilities::allocate_unique;
using utilities::byte_t;
using utilities::bytes_view;
using utilities::deadline_after;
using utilities::io_vector_t;
using utilities::monotonic_ns;
using utilities::publish;
using utilities::socket_close;
using utilities::socket_open;
using utilities::span;
using utilities::text_view;

/** An accepted connection: its transport first, then what serving it needs. */
template <typename network_type_>
struct server_connection {
    using network_t = network_type_;
    using allocator_t = typename network_t::allocator_t;
    using transport_t = typename network_t::transport_t;
    using connection_t = typename network_t::server_connection_t;
    using endpoint_t = typename network_t::endpoint_t;
    using server_exchange_t = typename network_t::server_exchange_t;
    using network_interface_t = typename network_t::network_interface_t;
    template <typename value_type_>
    using atomic_ref = typename network_t::template atomic_ref<value_type_>;

    explicit server_connection(allocator_t const& allocator = {}) noexcept : transport(allocator) {
        // Measured on Linux AArch64 LP64 with a stateless allocator; other targets go unmeasured.
        if constexpr (UCALL_OS_LINUX_ && UCALL_ARCH_ARM64_ && std::is_empty_v<allocator_t>)
            static_assert(sizeof(server_connection) == 2408);
    }
    server_connection(server_connection const&) = delete;
    server_connection& operator=(server_connection const&) = delete;
    server_connection(server_connection&&) = delete;
    server_connection& operator=(server_connection&&) = delete;

    transport_t transport;

    /** Reads the files a reply streams. */
    io_request_t file_read_request {};
    operation_state_t file_read_operation {};
    file_read_state_t file_reading {};
    send_mode_t send_mode {};
    continue_state_t continuing {};
    connection_order_t order {};

    /** The verbs the path being parsed takes, as a miss reports them in @c allow. */
    verb_set_t routed_verbs {};

    /** @c SO_SNDBUF read once, bounding what the kernel holds for it. */
    std::size_t send_buffer_bytes {};

    /** The stream's windows in file order. */
    std::uint32_t oldest_window {absent_k}, newest_window {absent_k};

    /** Releases the close waits for. */
    std::uint32_t releasing_windows {}, releasing_exchanges {};

    /** Links the order @c order names. */
    order_link_t order_link {};
    io_vector_t file_read_vectors[file_window_records_k] {};

    /** Links the loop's FIFO of streams waiting for a window. */
    connection_t* next_waiting_connection {};
    network_interface_t* network_interface {};

    /** Matched once the head of the request being parsed arrived. */
    endpoint_t* routed {};

    /** The exchange whose body is arriving; nothing parses behind it. */
    server_exchange_t* streaming {};

    /** Replies leave in this order. */
    server_exchange_t* oldest_exchange {};
    server_exchange_t* newest_exchange {};
    std::uint32_t outstanding_exchanges {};

    /** In its event loop's connections, as windows and orders name it. */
    std::uint32_t index {};

    /** Links the event loop's idle list or ready queue. */
    connection_t* next {};

    ucall_status_t configure(secure_tunnel_config_t const& config) noexcept {
        file_read_request = {.context = this};
        file_read_operation = operation_state_t::idle_k;
        file_reading = file_read_state_t::idle_k;
        send_mode = send_mode_t::zero_copy_k;
        continuing = continue_state_t::none_k;
        routed = nullptr;
        streaming = nullptr;
        return transport.configure(config, this);
    }

    /** Records one completion as @c transport_t::complete does, and a file operation's, whose
     *  outcome belongs to the segment it served, which the server lands. */
    void complete(io_completion_t const& completion) noexcept {
        if (completion.request != &file_read_request)
            return transport.complete(completion, network_interface->config.max_request_bytes);
        file_read_operation = operation_state_t::idle_k;
        if (transport.statistics && completion.result > 0 &&
            completion.request->operation != io_operation_t::file_open_k)
            tally<atomic_ref>(transport.statistics->bytes_read, static_cast<std::uint64_t>(completion.result));
    }

    /** The transport's next request, after any file operation, holding a close back while the
     *  kernel still holds what it sent. */
    io_request_t* advance() noexcept {
        if (file_read_operation == operation_state_t::submitted_k) return nullptr;
        io_request_t* next_request = transport.advance();
        // A close sends what the kernel still holds, unless it resets, which purges it.
        if (!next_request || next_request->operation != io_operation_t::close_k || !outstanding_releases() ||
            transport.close_mode != close_mode_t::orderly_k)
            return next_request;
        transport.stage = transport_stage_t::releasing_k;
        transport.deadline = deadline_after(linger_microseconds_k);
        return nullptr;
    }

    /** Marks @p request, one of its three, in flight once the engine took it. */
    void submitted(io_request_t const& request) noexcept {
        if (&request == &file_read_request) file_read_operation = operation_state_t::submitted_k;
        else transport.submitted(request);
    }

    /** Whether the kernel still holds memory this connection sent without copying. */
    bool outstanding_releases() const noexcept { return releasing_windows || releasing_exchanges; }
};

/** Admits connections, dispatches requests, and steps the event loops of a server. */
template <typename network_type_>
struct serving {
    using network_t = network_type_;
    using http_t = typename network_t::http_t;
    using crypto_t = typename network_t::crypto_t;
    using http_message_t = typename network_t::http_message_t;
    using connection_t = typename network_t::server_connection_t;
    using endpoint_t = typename network_t::endpoint_t;
    using server_exchange_t = typename network_t::server_exchange_t;
    using network_interface_t = typename network_t::network_interface_t;
    using interface_acceptor_t = typename network_t::interface_acceptor_t;
    using acceptor_stage_t = typename interface_acceptor_t::stage_t;
    using event_loop_t = typename network_t::event_loop_t;
    using server_t = typename network_t::server_t;
    using formatting_t = typename network_t::formatting_t;
    using replies_t = typename network_t::replies_t;
    using metrics_t = typename network_t::metrics_t;
    template <typename value_type_>
    using atomic_ref = typename network_t::template atomic_ref<value_type_>;

    /** Frees @p exchange for the next request once its reply ended, making a deferred outcome final
     *  with @p status after the loop let go of every file segment. While the kernel still holds its
     *  sent segments, it waits as @c releasing_k for the release to complete. */
    static void recycle_exchange(event_loop_t& event_loop, server_exchange_t& exchange,
                                 ucall_status_t status) noexcept {
        if (status == ucall_status_success_k) metrics_t::time_request(*event_loop.server, event_loop, exchange);
        tally<atomic_ref>(event_loop.statistics.bytes_copied, std::exchange(exchange.copied, 0));
        exchange.input.clear();
        replies_t::release_all_segments(exchange);
        replies_t::publish_reply_outcome(exchange, status);
        if (exchange.releasing()) {
            exchange.stage = exchange_stage_t::releasing_k;
            return;
        }
        free_exchange(event_loop, exchange);
    }

    /** Lists @p exchange, whose segments nothing holds any longer, among the free ones. */
    static void free_exchange(event_loop_t& event_loop, server_exchange_t& exchange) noexcept {
        exchange.head_segment.bytes.clear();
        exchange.end_segment.bytes.clear();
        exchange.connection = nullptr;
        // A replier listing an ended reply late finds a free exchange nothing recycles twice.
        exchange.stage = exchange_stage_t::dispatched_k;
        crypto_t::secure_zero(exchange.peer_static_key);
        exchange.replied_next = event_loop.free_exchanges;
        event_loop.free_exchanges = &exchange;
    }
    static void mark_ready(event_loop_t& event_loop, connection_t& connection) noexcept {
        if (connection.transport.readiness == listing_t::listed_k) return;
        connection.transport.readiness = listing_t::listed_k;
        connection.next = event_loop.ready;
        event_loop.ready = &connection;
    }

    /** Drains the replied queue and adopts each exchange's pushed segments, readying a connection
     *  only for what its transmit stage has not adopted already; a reply stays on its connection
     *  until sent, and only orphans release theirs here, recycling once ended. */
    static ucall_status_t collect_replies(event_loop_t& event_loop) noexcept {
        auto* exchange = replies_t::dequeue_replied(event_loop);
        if (!exchange) return ucall_status_would_block_k;
        for (; exchange; exchange = replies_t::dequeue_replied(event_loop)) {
            tally<atomic_ref>(event_loop.statistics.replied_dequeues);
            // Unlisting before adopting makes a later push list the exchange again.
            atomic_ref<std::uint32_t> {exchange->shared.state}.fetch_and(~std::uint32_t {listed_k},
                                                                         std::memory_order_acq_rel);
            bool const adopted = replies_t::adopt_segments(*exchange);
            bool const pulling = atomic_ref<std::uint32_t> {exchange->shared.pull_requested}.load(
                std::memory_order_acquire);
            if (pull_ready(*exchange)) finish_pull(*exchange, ucall_status_success_k);
            if (auto* connection = exchange->connection) {
                bool const detached =
                    atomic_ref<std::uint32_t> {exchange->shared.state}.load(std::memory_order_acquire) & detached_k;
                if (detached) connection->transport.fail(ucall_status_connection_closed_k);
                if (adopted || pulling || detached) mark_ready(event_loop, *connection);
            }
            else {
                replies_t::release_all_segments(*exchange);
                if (exchange->stage == exchange_stage_t::ended_k) {
                    --event_loop.orphaned_exchanges;
                    recycle_exchange(event_loop, *exchange, ucall_status_connection_closed_k);
                }
            }
        }
        return ucall_status_success_k;
    }

    /** Answers on the event loop itself, failing the connection when no reply was queued. */
    static void answer(connection_t& connection, server_exchange_t& exchange, unsigned status, std::string_view body,
                       span<ucall_bytes_view_t const> headers) noexcept {
        ucall_reply_part_t part {};
        part.data.bytes = bytes_view(body);
        auto result = replies_t::reply(exchange, nullptr, status, headers, {&part, 1});
        if (result == ucall_status_success_k || result == ucall_status_connection_closed_k) return;
        // Never pushed, so the close recycles it.
        exchange.stage = exchange_stage_t::ended_k;
        connection.transport.fail(ucall_status_out_of_memory_k);
    }

    /** Answers a request the loop turns away, counting and logging it by @p status. */
    static void refuse(connection_t& connection, server_exchange_t& exchange, unsigned status, std::string_view body,
                       span<ucall_bytes_view_t const> headers) noexcept {
        if (auto* counters = connection.transport.interface_statistics)
            for (std::size_t i = 0; i != std::size(refused_statuses_k); ++i)
                if (refused_statuses_k[i] == status) tally<atomic_ref>(counters->refused[i]);
        char digits[std::numeric_limits<unsigned>::digits10 + 1];
        formatting_t::log_line(exchange.event_loop->server->config.log, ucall_log_level_info_k, "refused",
                               {{"status", formatting_t::format_decimal(digits, status)},
                                {"address", text_view(connection.network_interface->config.address)}});
        answer(connection, exchange, status, body, headers);
    }

    /** Answers a request no endpoint took: 404 when its path takes no verb, or else the
     *  verbs @p allowed holds in @c allow, with 204 to an OPTIONS, which is no refusal,
     *  and 405 otherwise. */
    static void refuse_unrouted(connection_t& connection, server_exchange_t& exchange, verb_set_t allowed) noexcept {
        if (!allowed) return refuse(connection, exchange, 404, "Not found", {});
        if (allowed & verb_set_t(1u << ucall_verb_get_k)) allowed |= verb_set_t(1u << ucall_verb_head_k);
        allowed |= verb_set_t(1u << ucall_verb_options_k);
        char text[64] = "allow: ";
        std::size_t length = 7;
        for (int verb = ucall_verb_get_k; verb <= ucall_verb_options_k; ++verb) {
            if (!(allowed & (1u << verb))) continue;
            std::string_view const name = http_t::http_verb_name(static_cast<ucall_verb_t>(verb));
            if (length != 7) text[length++] = ',', text[length++] = ' ';
            std::memcpy(text + length, name.data(), name.size());
            length += name.size();
        }
        ucall_bytes_view_t const header = bytes_view({text, length});
        if (exchange.message.verb == ucall_verb_options_k) return answer(connection, exchange, 204, {}, {&header, 1});
        refuse(connection, exchange, 405, "Method not allowed", {&header, 1});
    }

    /** A fresh exchange at the back of @p connection's FIFO,
     *  or null once the connection failed for memory. */
    static server_exchange_t* enqueue_exchange(event_loop_t& event_loop, connection_t& connection) noexcept {
        auto* exchange = event_loop.free_exchanges;
        if (exchange) event_loop.free_exchanges = exchange->replied_next;
        else if ((exchange =
                      allocate_unique<server_exchange_t>(event_loop.allocator, event_loop.allocator).release())) {
            exchange->next = event_loop.exchanges;
            event_loop.exchanges = exchange;
        }
        if (!exchange) {
            connection.transport.fail(ucall_status_out_of_memory_k);
            return nullptr;
        }
        // A late listing of the last life stays queued for this one, so its link queues once.
        atomic_ref<std::uint32_t> {exchange->shared.state}.clear_bits(~std::uint32_t {listed_k},
                                                                      std::memory_order_relaxed);
        exchange->stage = exchange_stage_t::dispatched_k;
        exchange->shared.unsent_bytes = 0;
        exchange->shared.unsent_file_segments = 0;
        exchange->reply_head = reply_head_t::pushed_k;
        exchange->declared = exchange->streamed = 0;
        exchange->outcome = nullptr;
        exchange->pull_outcome = nullptr;
        exchange->pulled_view = nullptr;
        exchange->shared.pushed_segments = exchange->pushed_tail = exchange->newest_segment = nullptr;
        exchange->shared.pushed_file_segments = exchange->pushed_file_tail = exchange->newest_file_segment = nullptr;
        exchange->parts_state = parts_state_t::unlocated_k;
        exchange->shared.pull_requested = pull_unrequested_k;
        exchange->body_stage = body_stage_t::buffered_k;
        exchange->body_status = ucall_status_success_k;
        exchange->reply_status = 0;
        exchange->arrived = monotonic_ns();
        exchange->body_chunk.clear();
        exchange->pulled_chunk.clear();
        exchange->event_loop = &event_loop;
        exchange->connection = &connection;
        exchange->endpoint = nullptr;
        exchange->network_interface = connection.network_interface;
        exchange->geometry = connection.transport.tunnel.geometry();
        std::memcpy(exchange->peer_static_key, connection.transport.peer_static_key, sizeof(exchange->peer_static_key));
        exchange->peer_address = connection.transport.peer_address;
        if (connection.newest_exchange) connection.newest_exchange->connection_next = exchange;
        else connection.oldest_exchange = exchange;
        connection.newest_exchange = exchange;
        ++connection.outstanding_exchanges;
        return exchange;
    }

    /** Moves the request parsed at @p offset of @c input into a fresh exchange, and routes it. */
    static void dispatch(server_t& server, event_loop_t& event_loop, connection_t& connection,
                         std::size_t offset) noexcept {
        auto* exchange = enqueue_exchange(event_loop, connection);
        if (!exchange) return;
        auto wire = connection.transport.message.wire_length;
        if (!offset && wire == connection.transport.input.size() && connection.transport.input_may_leave(wire))
            std::swap(exchange->input, connection.transport.input);
        else if (ucall_status_t const appended = http_t::append_text(
                     exchange->input, {text_view(connection.transport.input).substr(offset, wire)});
                 appended == ucall_status_success_k)
            tally<atomic_ref>(event_loop.statistics.bytes_copied, wire);
        else {
            // Never handed out, so the close recycles it.
            exchange->stage = exchange_stage_t::ended_k;
            return connection.transport.fail(appended);
        }
        tally<atomic_ref>(event_loop.statistics.requests);
        exchange->message = std::exchange(connection.transport.message, http_message_t {});
        auto* endpoint = std::exchange(connection.routed, nullptr);
        exchange->endpoint = endpoint;
        if (!endpoint) return refuse_unrouted(connection, *exchange, std::exchange(connection.routed_verbs, 0));
        // An exchange whose peer left lives until answered, so a peer reconnecting must
        // not grow them.
        if (event_loop.orphaned_exchanges >= event_loop.max_exchanges)
            return refuse(connection, *exchange, 503, "Too many abandoned requests", {});
        if (endpoint->callback) return endpoint->callback(exchange, endpoint->context);
        auto& batch = *endpoint->batch;
        auto tail = atomic_ref<std::uint64_t> {batch.tail};
        // Exchanges of closed connections outlive their admission, so this check alone bounds it.
        if (tail.load(std::memory_order_relaxed) -
                atomic_ref<std::uint64_t> {batch.head}.load(std::memory_order_acquire) >=
            server.requests_budget)
            return refuse(connection, *exchange, 503, "Batch queue full", {});
        auto index = tail.fetch_add(1, std::memory_order_seq_cst);
        atomic_ref<server_exchange_t*> {batch.slots[index & (batch.slots.size() - 1)]}.store(exchange,
                                                                                             std::memory_order_release);
        auto wake_state = atomic_ref<wake_state_t> {batch.wake_state};
        if (wake_state.load(std::memory_order_seq_cst) == wake_state_t::sleeping_k &&
            wake_state.exchange(wake_state_t::awake_k, std::memory_order_seq_cst) == wake_state_t::sleeping_k)
            batch.wake.notify();
    }

    /** The endpoint the request whose head parsed at the front of @p unparsed goes to, or null. */
    static endpoint_t* route(server_t& server, connection_t& connection, span<byte_t> unparsed) noexcept {
        auto target = connection.transport.message.target(text_view(unparsed));
        // `OPTIONS *` asks what the server takes, not what one resource does.
        if (target == "*") {
            connection.routed_verbs = every_verb_k;
            return nullptr;
        }
        connection.routed_verbs = 0;
        return static_cast<endpoint_t*>(server.routes.match(extract_path_component<http_t>(target),
                                                            connection.transport.message.verb, nullptr,
                                                            &connection.routed_verbs));
    }

    /** Hands a streamed request to its callback once its head parsed at @p offset of @c input:
     *  the head moves to the exchange, and the body behind it stays in @c input to stream. */
    static void dispatch_streamed(event_loop_t& event_loop, connection_t& connection, std::size_t offset) noexcept {
        auto* exchange = enqueue_exchange(event_loop, connection);
        if (!exchange) return;
        auto const head = connection.transport.message.headers_length;
        if (ucall_status_t const appended = http_t::append_text(
                exchange->input, {text_view(connection.transport.input).substr(offset, head)});
            appended != ucall_status_success_k) {
            // Never handed out, so the close recycles it.
            exchange->stage = exchange_stage_t::ended_k;
            return connection.transport.fail(appended);
        }
        tally<atomic_ref>(event_loop.statistics.bytes_copied, head);
        tally<atomic_ref>(event_loop.statistics.requests);
        http_t::drop_bytes(connection.transport.input, offset + head);
        exchange->message = connection.transport.message;
        exchange->message.body_length = 0;
        // The connection keeps the framing and decodes the body from the front of what remains.
        connection.transport.message.decoded_length = connection.transport.message.chunk_remaining = 0;
        connection.transport.message.cursor = connection.transport.message.scanned = 0;
        connection.transport.message.chunk_state = http_chunk_state_t::size_k;
        auto* endpoint = std::exchange(connection.routed, nullptr);
        exchange->endpoint = endpoint;
        if (event_loop.orphaned_exchanges >= event_loop.max_exchanges) {
            // The body behind the head cannot be framed past, so the connection reads no further.
            connection.transport.receiving = receive_state_t::ended_k;
            exchange->message.connection = http_connection_t::close_k;
            return refuse(connection, *exchange, 503, "Too many abandoned requests", {});
        }
        exchange->body_stage = body_stage_t::streaming_k;
        connection.streaming = exchange;
        endpoint->callback(exchange, endpoint->context);
    }

    /** Hands a waiting pull @c body_chunk, or the end of the body, and makes its outcome final. */
    static void finish_pull(server_exchange_t& exchange, ucall_status_t status) noexcept {
        // Acquiring the request orders the puller's outcome and view before these reads.
        auto requested = atomic_ref<std::uint32_t> {exchange.shared.pull_requested};
        if (requested.load(std::memory_order_acquire) != pull_waiting_k) return;
        requested.store(pull_unrequested_k, std::memory_order_relaxed);
        auto* outcome = std::exchange(exchange.pull_outcome, nullptr);
        *exchange.pulled_view = {};
        if (status == ucall_status_success_k && exchange.body_chunk.empty()) status = exchange.body_status;
        if (status == ucall_status_success_k) {
            std::swap(exchange.pulled_chunk, exchange.body_chunk);
            exchange.body_chunk.clear();
            *exchange.pulled_view = bytes_view(text_view(exchange.pulled_chunk));
        }
        publish(outcome, status);
    }

    /** Whether a waiting pull of @p exchange can take bytes or the end now. */
    static bool pull_ready(server_exchange_t& exchange) noexcept {
        return atomic_ref<std::uint32_t> {exchange.shared.pull_requested}.load(std::memory_order_acquire) &&
               (!exchange.body_chunk.empty() || exchange.body_stage == body_stage_t::ended_k);
    }

    /** Decodes what @c input holds of the streamed body in place and, once the last chunk was
     *  pulled, rotates @c input into @c body_chunk and finishes a waiting pull; complete once the
     *  body ended, leaving the bytes behind it in @c input. */
    static http_parse_t stream_body(connection_t& connection) noexcept {
        auto& exchange = *connection.streaming;
        // A reply that ended before its body drains the rest, so nothing behind it stalls.
        bool const draining = exchange.stage == exchange_stage_t::ended_k;
        if (draining) exchange.body_chunk.clear();
        if (!exchange.body_chunk.empty()) return http_parse_t::incomplete_k;
        std::size_t payload = 0, consumed = 0;
        auto parsed = http_t::http_stream_body(connection.transport.input, connection.transport.message,
                                               connection.network_interface->config.max_request_bytes, payload,
                                               consumed);
        if (parsed != http_parse_t::complete_k && parsed != http_parse_t::incomplete_k) {
            ucall_status_t const failure = parsed == http_parse_t::overflow_k ? ucall_status_overflow_k
                                                                              : ucall_status_malformed_k;
            exchange.body_status = failure;
            finish_pull(exchange, failure);
            exchange.body_stage = body_stage_t::ended_k;
            connection.streaming = nullptr;
            connection.transport.receiving = receive_state_t::ended_k;
            connection.transport.fail(failure);
            return parsed;
        }
        if (payload && !draining) {
            // Rotating buffers hands the payload over where it was decoded, never copying it.
            std::swap(exchange.body_chunk, connection.transport.input);
            connection.transport.input.clear();
            ucall_status_t const kept = http_t::append_text(connection.transport.input,
                                                            {text_view(exchange.body_chunk).substr(consumed)});
            if (kept != ucall_status_success_k) connection.transport.fail(kept);
            // Never grows.
            [[maybe_unused]] st::status_t const shrunk = exchange.body_chunk.resize(payload);
        }
        else http_t::drop_bytes(connection.transport.input, consumed);
        if (parsed == http_parse_t::complete_k) {
            exchange.body_stage = body_stage_t::ended_k;
            connection.streaming = nullptr;
            bool const closes = !connection.transport.message.keep_alive();
            connection.transport.message = {};
            if (closes) connection.transport.receiving = receive_state_t::ended_k;
        }
        else if (connection.transport.peer_stream == peer_stream_t::closed_k) {
            exchange.body_status = ucall_status_connection_closed_k;
            finish_pull(exchange, ucall_status_connection_closed_k);
            exchange.body_stage = body_stage_t::ended_k;
            connection.streaming = nullptr;
            connection.transport.receiving = receive_state_t::ended_k;
        }
        if (pull_ready(exchange)) finish_pull(exchange, ucall_status_success_k);
        return parsed;
    }

    /** Whether the request line opening @p request names HTTP/1.0, which has
     * no interim responses. */
    static bool requests_http_1_0(std::string_view request) noexcept {
        return request.substr(0, http_t::find(request, "\r\n")).ends_with("HTTP/1.0");
    }

    /** The interim @c 100 an expecting client waits for, once nothing is sending and no reply is
     *  ahead of its request, or null; a streamed request owes it only once its handler pulls, and a
     *  body or a final reply arriving first drops it. */
    static io_request_t* continue_request(connection_t& connection) noexcept {
        if (connection.continuing != continue_state_t::owed_k || connection.transport.sending) return nullptr;
        auto* const streamed = connection.streaming;
        if ((!streamed && !connection.transport.message.headers_length) ||
            (streamed && streamed->stage != exchange_stage_t::dispatched_k)) {
            connection.continuing = continue_state_t::none_k;
            return nullptr;
        }
        if (connection.oldest_exchange != streamed ||
            (streamed && !atomic_ref<std::uint32_t> {streamed->shared.pull_requested}.load(std::memory_order_acquire)))
            return nullptr;
        connection.continuing = continue_state_t::none_k;
        std::string_view const interim = "HTTP/1.1 100 Continue\r\n\r\n";
        auto const geometry = connection.transport.tunnel.geometry();
        std::size_t const length = geometry.headroom + interim.size() + geometry.tailroom;
        // The handshake's buffer is free once the connection opened.
        if (length > connection.transport.record.size() && st::failed(connection.transport.record.resize(length))) {
            connection.transport.fail(ucall_status_out_of_memory_k);
            return nullptr;
        }
        std::memcpy(connection.transport.record.data() + geometry.headroom, interim.data(), interim.size());
        span<byte_t> const bytes {connection.transport.record.data(), length};
        if (ucall_status_t const sealed = connection.transport.seal_records(bytes); sealed != ucall_status_success_k) {
            connection.transport.fail(sealed);
            return nullptr;
        }
        return connection.transport.emit_send(bytes);
    }

    /** Queues the refusal of a request that cannot be parsed behind every earlier reply. */
    static void refuse_unparsable(event_loop_t& event_loop, connection_t& connection, http_parse_t parsed) noexcept {
        connection.transport.input.clear();
        connection.transport.message = {};
        connection.routed = nullptr;
        auto* exchange = enqueue_exchange(event_loop, connection);
        if (!exchange) return;
        // A default message never keeps the connection alive.
        exchange->message = {};
        refuse(connection, *exchange,
               parsed == http_parse_t::unsupported_k           ? 501
               : parsed == http_parse_t::unsupported_version_k ? 505
               : parsed == http_parse_t::overflow_k            ? 413
                                                               : 400,
               {}, {});
    }

    /** Steps an open server connection, answering its next engine request or null, by these rules
     *  in order:
     *  R1 replies sent: with the transmit side free, retire the oldest replies' sent segments, then
     *     each exchange whose reply ended, submitting its release first, and a full receive side
     *     reads again.
     *  R2 requests: while reading, dispatch each complete request; the depth makes the side full,
     *     and <tt>connection: close</tt>, a peer close, or an unparsable request, refused in its turn,
     *     ends it.
     *  R3 file side: the oldest reply adopts what its replier pushed, in the pass that reads and
     *     sends it, then a free file request advances its files, as @c read_reply steps them,
     *     measuring every file of a deferred head before completing it.
     *  R4 socket side: a free transmit side advances the oldest reply once adopted, as
     *     @c transmit_reply steps it.
     *  R5 receive: a receive while reading.
     *  R6 done: ended with every reply sent, the connection lingers half-closed until the peer
     *     closes, so request bytes it never read cannot turn the close into a reset. */
    static io_request_t* serve_open(server_t& server, event_loop_t& event_loop, connection_t& connection) noexcept {
        if (connection.transport.transmit_operation == operation_state_t::idle_k && !connection.transport.sending)
            if (io_request_t* release = replies_t::retire_sent_segments(event_loop, connection)) return release;
        if (connection.transport.stage != transport_stage_t::open_k) return connection.advance();
        connection.transport.open_records();
        auto depth = connection.network_interface->config.max_pipelined_requests;
        auto const cap = connection.network_interface->config.max_request_bytes;
        // Requests dispatched this round, erased from `input` once after it rather than one by one.
        std::size_t consumed = 0;
        while (connection.transport.stage == transport_stage_t::open_k &&
               connection.transport.receiving == receive_state_t::reading_k) {
            // A streamed body is a barrier: nothing behind it parses until it ended.
            if (connection.streaming) {
                if (stream_body(connection) == http_parse_t::complete_k) continue;
                // An engine prefetching into a shared ring parks what an unpulled body holds there.
                if (connection.streaming && !connection.streaming->body_chunk.empty())
                    event_loop.engine.receive_pause(connection.transport.descriptor);
                break;
            }
            if (connection.outstanding_exchanges == depth) {
                connection.transport.receiving = receive_state_t::full_k;
                break;
            }
            span<byte_t> unparsed {connection.transport.input.data() + consumed,
                                   connection.transport.input.data() + connection.transport.input.size()};
            bool const headless = !connection.transport.message.headers_length;
            // RFC 9112 2.2: some clients end a body with a CRLF, which must not kill
            // the next request.
            if (headless && text_view(unparsed).starts_with("\r\n")) {
                consumed += 2;
                continue;
            }
            auto parsed = http_t::http_parse(unparsed, connection.transport.message, http_role_t::request_k);
            auto const& message = connection.transport.message;
            auto const head = message.headers_length;
            if (headless && head) {
                connection.routed = route(server, connection, unparsed);
                // RFC 9110 10.1.1: such a client sends its body only once told to, or
                // after a timeout.
                connection.continuing = parsed == http_parse_t::incomplete_k &&
                                                !requests_http_1_0(text_view(unparsed)) &&
                                                http_t::equal_ascii_uncased(
                                                    message.header(text_view(unparsed), "expect"), "100-continue")
                                            ? continue_state_t::owed_k
                                            : continue_state_t::none_k;
            }
            bool const head_fits = head ? head <= cap : unparsed.size() <= cap;
            // A parsed head is valid, so what the body holds is the stream's to report.
            if (head && head_fits && connection.routed &&
                connection.routed->body_delivery == ucall_body_delivery_streamed_k) {
                dispatch_streamed(event_loop, connection, consumed);
                consumed = 0;
                continue;
            }
            bool const body_fits = message.framing != http_framing_t::length_k
                                       ? (parsed == http_parse_t::complete_k ? message.wire_length : unparsed.size()) <=
                                             cap
                                       : message.content_length <= cap - std::min(cap, head);
            if ((!head_fits || (head && !body_fits)) &&
                (parsed == http_parse_t::incomplete_k || parsed == http_parse_t::complete_k))
                parsed = http_parse_t::overflow_k;
            if (parsed == http_parse_t::incomplete_k) {
                if (connection.transport.peer_stream == peer_stream_t::closed_k)
                    connection.transport.receiving = receive_state_t::ended_k;
                break;
            }
            if (parsed != http_parse_t::complete_k) {
                connection.transport.receiving = receive_state_t::ended_k;
                refuse_unparsable(event_loop, connection, parsed);
                consumed = 0;
                break;
            }
            http_t::http_decode_chunks(unparsed, connection.transport.message);
            if (!connection.transport.message.keep_alive()) connection.transport.receiving = receive_state_t::ended_k;
            auto wire = connection.transport.message.wire_length;
            dispatch(server, event_loop, connection, consumed);
            consumed = connection.transport.input.empty() ? 0 : consumed + wire;
        }
        if (consumed) http_t::drop_bytes(connection.transport.input, consumed);
        connection.transport.aim_receive();
        if (connection.transport.stage != transport_stage_t::open_k) return connection.advance();
        if (auto* oldest = connection.oldest_exchange) replies_t::adopt_segments(*oldest);
        if (connection.file_read_operation == operation_state_t::idle_k) {
            if (auto* next = replies_t::read_reply(event_loop, connection)) return next;
            if (connection.transport.stage != transport_stage_t::open_k) return connection.advance();
        }
        if (connection.transport.transmit_operation == operation_state_t::idle_k) {
            if (auto* next = continue_request(connection)) return next;
            if (auto* next = replies_t::transmit_reply(event_loop, connection)) return next;
            if (connection.transport.stage != transport_stage_t::open_k) return connection.advance();
        }
        // A streamed body reads on only once its last chunk was pulled.
        if (connection.transport.receiving == receive_state_t::reading_k &&
            connection.transport.receive_operation == operation_state_t::idle_k &&
            (!connection.streaming || connection.streaming->body_chunk.empty()))
            return connection.transport.emit_receive();
        if (connection.transport.receiving == receive_state_t::ended_k && !connection.oldest_exchange &&
            connection.transport.transmitting == transmit_state_t::idle_k) {
            // A peer that closed left nothing unread, so only a live receive side lingers.
            if (connection.transport.peer_stream == peer_stream_t::closed_k)
                connection.transport.fail(ucall_status_success_k);
            else {
                connection.transport.stage = transport_stage_t::lingering_k;
                connection.transport.deadline = deadline_after(linger_microseconds_k);
            }
            return connection.advance();
        }
        return nullptr;
    }

    /** The orders of @p network_interface's connections on @p event_loop. */
    static interface_order_t& interface_order(server_t& server, event_loop_t& event_loop,
                                              network_interface_t const& network_interface) noexcept {
        return event_loop
            .interface_orders[static_cast<std::size_t>(&network_interface - server.network_interfaces.data())];
    }

    /** The order links of a loop's connections by index, as its intrusive lists walk them. */
    struct order_links_t {
        event_loop_t& event_loop;
        order_link_t& operator[](std::uint32_t index) const noexcept {
            return event_loop.connections[index]->order_link;
        }
    };
    static st::intrusive_list<std::uint32_t>& order_list(event_loop_t& event_loop, connection_t& connection,
                                                         connection_order_t order) noexcept {
        return order == connection_order_t::expiring_k
                   ? event_loop.expiring
                   : interface_order(*event_loop.server, event_loop, *connection.network_interface).keepalive;
    }

    /** Takes @p connection off whichever order holds it. */
    static void unlist(event_loop_t& event_loop, connection_t& connection) noexcept {
        if (connection.order == connection_order_t::unlisted_k) return;
        order_links_t links {event_loop};
        [[maybe_unused]] st::status_t const erased =
            order_list(event_loop, connection, connection.order).erase(links, connection.index);
        connection.order = connection_order_t::unlisted_k;
    }

    /** Moves @p connection to the newest end of @p order. */
    static void relist(event_loop_t& event_loop, connection_t& connection, connection_order_t order) noexcept {
        unlist(event_loop, connection);
        order_links_t links {event_loop};
        order_list(event_loop, connection, order).push(links, connection.index);
        connection.order = order;
    }
    static void release_admission(server_t& server, network_interface_t& network_interface) noexcept {
        auto before = atomic_ref<std::size_t> {network_interface.active}.fetch_sub(1, std::memory_order_relaxed);
        if (before == network_interface.config.max_concurrent_connections)
            for (auto& event_loop : server.event_loops) event_loop->notify();
    }
    static server_stage_t server_stage(server_t& server) noexcept {
        return static_cast<server_stage_t>(atomic_ref<std::uint32_t> {server.stage}.load(std::memory_order_acquire));
    }

    /** Takes @p connection off its loop's queue of streams waiting for a window. */
    static void leave_window_queue(event_loop_t& event_loop, connection_t& connection) noexcept {
        auto& pool = event_loop.file_windows;
        connection.file_reading = file_read_state_t::idle_k;
        connection_t* previous = nullptr;
        for (connection_t* waiting = pool.oldest_waiting_connection; waiting != &connection;
             waiting = waiting->next_waiting_connection)
            previous = waiting;
        connection_t* next = std::exchange(connection.next_waiting_connection, nullptr);
        (previous ? previous->next_waiting_connection : pool.oldest_waiting_connection) = next;
        if (pool.newest_waiting_connection == &connection) pool.newest_waiting_connection = previous;
    }
    static void advance_connection(server_t& server, event_loop_t& event_loop, connection_t& connection,
                                   server_stage_t server_stage) noexcept {
        auto& engine = event_loop.engine;
        auto const entered = connection.transport.stage;
        if (entered == transport_stage_t::idle_k) return;
        tally<atomic_ref>(event_loop.statistics.ready_passes);
        // A drain closes idle connections and lets busy ones close after their last reply.
        if (server_stage == server_stage_t::draining_k &&
            (connection.transport.stage == transport_stage_t::open_k ||
             connection.transport.stage == transport_stage_t::handshake_k)) {
            if (!connection.oldest_exchange) connection.transport.fail(ucall_status_connection_closed_k);
            else if (!connection.streaming) connection.transport.receiving = receive_state_t::ended_k;
        }
        if (server_stage == server_stage_t::cutting_k && connection.transport.stage != transport_stage_t::closing_k &&
            connection.transport.stage != transport_stage_t::closed_k) {
            // A reply cut off at stop must not read as whole; a linger would only delay the peer.
            if (connection.oldest_exchange || connection.transport.stage == transport_stage_t::releasing_k)
                connection.transport.close_mode = close_mode_t::reset_k;
            connection.transport.fail(ucall_status_connection_closed_k);
        }
        if (connection.transport.stage == transport_stage_t::closing_k &&
            connection.file_reading == file_read_state_t::waiting_window_k)
            leave_window_queue(event_loop, connection);
        for (;;) {
            io_request_t* next = connection.transport.stage == transport_stage_t::closing_k
                                     ? replies_t::drain_releases(event_loop, connection)
                                     : nullptr;
            if (!next) next = connection.advance();
            if (!next && connection.transport.stage == transport_stage_t::open_k)
                next = serve_open(server, event_loop, connection);
            if (!next) break;
            if (next->operation == io_operation_t::close_k &&
                connection.transport.close_mode == close_mode_t::reset_k) {
                [[maybe_unused]] ucall_status_t const reset = engine.reset_on_close(connection.transport.descriptor);
                connection.transport.close_mode = close_mode_t::orderly_k;
            }
            // A failed submission is retried on the loop's next round rather than this one.
            if (engine.submit(*next) != ucall_status_success_k) {
                mark_ready(event_loop, connection);
                return;
            }
            if (next->operation == io_operation_t::zero_copy_release_k)
                replies_t::release_submitted(event_loop, connection, *next);
            else connection.submitted(*next);
        }
        auto const stage = connection.transport.stage;
        // Saturation evicts the connection that progressed least recently and holds no request.
        if ((stage == transport_stage_t::open_k || stage == transport_stage_t::handshake_k) &&
            !connection.oldest_exchange) {
            relist(event_loop, connection, connection_order_t::keepalive_k);
            // A peer parked while every connection was busy evicts the first to turn idle.
            evict(event_loop, interface_order(server, event_loop, *connection.network_interface));
        }
        // Lingers and releases all wait linger_microseconds_k from their start, so appending
        // keeps deadline order.
        else if ((stage == transport_stage_t::releasing_k || stage == transport_stage_t::lingering_k) &&
                 stage != entered)
            relist(event_loop, connection, connection_order_t::expiring_k);
        else if (connection.order == connection_order_t::keepalive_k) unlist(event_loop, connection);
        // The close waits until the other operations complete or are cancelled.
        if (connection.transport.stage == transport_stage_t::closing_k) {
            if (connection.transport.receive_operation == operation_state_t::submitted_k &&
                connection.transport.receive_request.operation != io_operation_t::close_k)
                engine.cancel(connection.transport.receive_request);
            if (connection.transport.transmit_operation == operation_state_t::submitted_k)
                engine.cancel(connection.transport.transmit_request);
            if (connection.file_read_operation == operation_state_t::submitted_k)
                engine.cancel(connection.file_read_request);
        }
        // A reset close purges what the kernel held, whose releases still arrive after it.
        if (connection.transport.stage == transport_stage_t::closed_k && !connection.outstanding_releases()) {
            replies_t::detach(event_loop, connection);
            unlist(event_loop, connection);
            // A descriptor just came free, so the reserves the residue held closed reopen now.
            if (std::exchange(event_loop.accept_deadline, 0))
                for (auto& acceptor : event_loop.interface_acceptors)
                    if (acceptor.stage == acceptor_stage_t::idle_k) reopen_reserve(event_loop, acceptor);
            if (auto* counters = connection.transport.interface_statistics)
                atomic_ref<std::uint64_t> {counters->connections}.store(counters->connections - 1,
                                                                        std::memory_order_relaxed);
            if (connection.transport.status == ucall_status_handshake_failed_k)
                formatting_t::log_line(
                    server.config.log, ucall_log_level_warning_k, "handshake_failed",
                    {{"fault", tunnel::secure_tunnel_fault_name(connection.transport.tunnel.fault())},
                     {"address", text_view(connection.network_interface->config.address)}});
            connection.transport.tunnel.clear();
            connection.transport.input.clear();
            connection.transport.encrypted.clear();
            connection.transport.output.clear();
            connection.transport.sending = nullptr;
            connection.transport.output_offset = 0;
            connection.transport.peer_stream = peer_stream_t::writing_k;
            connection.transport.stage = transport_stage_t::idle_k;
            connection.next = event_loop.idle;
            event_loop.idle = &connection;
            --event_loop.open_connections;
            // Admission passes straight to a peer an eviction parked, on the record just freed.
            auto& network_interface = *connection.network_interface;
            if (auto& order = interface_order(server, event_loop, network_interface); order.evicting >= 0) {
                order.evicted = absent_k;
                admit(server, event_loop, network_interface, std::exchange(order.evicting, -1), order.evicting_peer);
            }
            else release_admission(server, network_interface);
        }
    }

    /** Ends every linger whose deadline passed, and resets every close whose deadline
     *  passed while the kernel still held what it sent, oldest first; entries that already
     *  moved on just leave. */
    static void expire_releases(event_loop_t& event_loop) noexcept {
        std::uint64_t const now = monotonic_ns();
        while (!event_loop.expiring.empty()) {
            auto& connection = *event_loop.connections[event_loop.expiring.oldest];
            if (connection.transport.deadline > now) return;
            unlist(event_loop, connection);
            if (connection.transport.stage == transport_stage_t::lingering_k)
                connection.transport.fail(ucall_status_success_k);
            else if (connection.transport.stage == transport_stage_t::releasing_k) {
                connection.transport.close_mode = close_mode_t::reset_k;
                tally<atomic_ref>(event_loop.statistics.linger_resets);
                formatting_t::log_line(event_loop.server->config.log, ucall_log_level_info_k, "linger_reset",
                                       {{"address", text_view(connection.network_interface->config.address)}});
                connection.transport.stage = transport_stage_t::closing_k;
            }
            else continue;
            mark_ready(event_loop, connection);
        }
    }

    /** When the oldest linger or release expires, or zero when none waits. */
    static std::uint64_t release_deadline(event_loop_t const& event_loop) noexcept {
        return event_loop.expiring.empty() ? 0 : event_loop.connections[event_loop.expiring.oldest]->transport.deadline;
    }
    static ucall_status_t server_progress(server_t& server, event_loop_t& event_loop) noexcept {
        auto& engine = event_loop.engine;
        auto stage = server_stage(server);
        for (auto& acceptor : event_loop.interface_acceptors) {
            auto& network_interface = *acceptor.network_interface;
            auto& order = interface_order(server, event_loop, network_interface);
            if (stage != server_stage_t::serving_k) {
                // An open listener keeps completing handshakes that no loop will accept.
                if (acceptor.stage == acceptor_stage_t::submitted_k || acceptor.stage == acceptor_stage_t::probing_k ||
                    (acceptor.stage == acceptor_stage_t::shedding_k && acceptor.shed_request.descriptor < 0))
                    engine.cancel(acceptor.request);
                else if (acceptor.request.descriptor >= 0) {
                    engine.close_socket(acceptor.request.descriptor);
                    acceptor.request.descriptor = -1;
                }
                if (order.evicting >= 0) engine.close_socket(std::exchange(order.evicting, -1));
                order.evicted = absent_k;
                continue;
            }
            // Nothing accepts without a reserve, which the residue holds closed until its deadline.
            if (acceptor.stage == acceptor_stage_t::idle_k && acceptor.reserve_descriptor < 0) {
                if (event_loop.accept_deadline && monotonic_ns() < event_loop.accept_deadline) continue;
                event_loop.accept_deadline = 0;
                reopen_reserve(event_loop, acceptor);
                if (acceptor.reserve_descriptor < 0) continue;
            }
            // A pending accept reads its budget at each attempt, so every round renews it.
            if (acceptor.stage == acceptor_stage_t::submitted_k) aim_accept(event_loop, acceptor);
            if (acceptor.stage != acceptor_stage_t::idle_k || order.evicting >= 0) continue;
            auto active = atomic_ref<std::size_t> {network_interface.active};
            auto const limit = network_interface.config.max_concurrent_connections;
            bool const admitted = event_loop.idle &&
                                  active.fetch_add_if_at_most(1, limit, std::memory_order_relaxed) < limit;
            auto accepting = atomic_ref<std::size_t> {network_interface.accepting};
            // Saturated by connections, not by other loops' pending accepts, an accept probes for a
            // peer to evict for.
            if (!admitted &&
                (order.keepalive.empty() ||
                 active.load(std::memory_order_relaxed) - accepting.load(std::memory_order_relaxed) < limit))
                continue;
            acceptor.stage = admitted ? acceptor_stage_t::submitted_k : acceptor_stage_t::probing_k;
            if (admitted) accepting.add(1, std::memory_order_relaxed);
            aim_accept(event_loop, acceptor);
            if (engine.submit(acceptor.request) == ucall_status_success_k) continue;
            acceptor.stage = acceptor_stage_t::idle_k;
            if (admitted) {
                accepting.sub(1, std::memory_order_relaxed);
                active.sub(1, std::memory_order_relaxed);
            }
        }
        collect_replies(event_loop);
        expire_releases(event_loop);
        if (stage != server_stage_t::cutting_k) metrics_t::emit_metrics(server, event_loop);
        else if (event_loop.metrics.state == metrics_state_t::sending_k) engine.cancel(event_loop.metrics.send_request);
        auto const loop_stage = stage == server_stage_t::cutting_k ? event_loop_stage_t::cutting_k
                                                                   : event_loop_stage_t::draining_k;
        if (stage != server_stage_t::serving_k && event_loop.stage < loop_stage) {
            // Each connection sees every new stage once; later passes move what completions mark.
            for (auto& connection : event_loop.connections)
                if (connection->transport.stage != transport_stage_t::idle_k) mark_ready(event_loop, *connection);
            event_loop.stage = loop_stage;
        }
        do {
            for (auto* connection = std::exchange(event_loop.ready, nullptr); connection;) {
                auto& current = *connection;
                connection = current.next;
                current.transport.readiness = listing_t::unlisted_k;
                advance_connection(server, event_loop, current, stage);
            }
        } while (collect_replies(event_loop) == ucall_status_success_k);
        if (stage != server_stage_t::serving_k) {
            bool busy = event_loop.open_connections != 0 || event_loop.metrics.state == metrics_state_t::sending_k;
            for (auto& acceptor : event_loop.interface_acceptors) busy |= acceptor.stage != acceptor_stage_t::idle_k;
            if (!busy) {
                if (event_loop.metrics.state != metrics_state_t::closed_k) {
                    engine.close_socket(event_loop.metrics.send_request.descriptor);
                    event_loop.metrics.state = metrics_state_t::closed_k;
                }
                for (auto const& acceptor : event_loop.interface_acceptors)
                    assert((acceptor.reserve_descriptor >= 0 || event_loop.accept_deadline) &&
                           "an idle loop's reserves are open unless the residue holds them closed");
                retire_event_loop(server, event_loop);
            }
        }
        return ucall_status_success_k;
    }

    /** Retires @p event_loop for good, and once every loop is retired, wakes the batch polling
     *  owners a drained server keeps answering, as no deposit can follow. */
    static void retire_event_loop(server_t& server, event_loop_t& event_loop) noexcept {
        // Retire the engine on its polling owner; a single-issuer ring completes nothing elsewhere.
        event_loop.engine.stop();
        event_loop.stage = event_loop_stage_t::retired_k;
        auto retired = atomic_ref<std::uint32_t> {server.retired_event_loops};
        if (retired.fetch_add(1, std::memory_order_acq_rel) + 1 == server.event_loops.size())
            for (auto* endpoint : server.batch_endpoints) endpoint->wake.notify();
    }

    /** Points @p acceptor's accept at its first peer address, for as many connections as it may
     *  take at once: the admission a submitted accept holds, and what the interface's budget and
     *  the loop's idle connections still admit beside it; a probe takes one. */
    static void aim_accept(event_loop_t const& event_loop, interface_acceptor_t& acceptor) noexcept {
        std::size_t headroom = 0;
        if (acceptor.stage == acceptor_stage_t::submitted_k) {
            std::size_t const limit = acceptor.network_interface->config.max_concurrent_connections;
            std::size_t const active = atomic_ref<std::size_t> {acceptor.network_interface->active}.load(
                std::memory_order_relaxed);
            std::size_t const idle = event_loop.connections.size() - event_loop.open_connections;
            headroom = std::min(
                {limit > active ? limit - active : 0, idle ? idle - 1 : 0, acceptor.peer_addresses.size() - 1});
        }
        acceptor.request.data = reinterpret_cast<byte_t*>(acceptor.peer_addresses.data());
        acceptor.request.length = 1 + headroom;
    }

    /** Frees the reserve so the accept queued behind an exhausted table goes through, refusing its
     *  peer; a shed takes no admission. A shed accept refused again, as kernel memory or another
     *  thread can make it, or one without a reserve to free, leaves the reserve closed until a
     *  close frees a descriptor or @c accept_deadline passes. */
    static void shed_accept(event_loop_t& event_loop, interface_acceptor_t& acceptor,
                            acceptor_stage_t failed) noexcept {
        if (failed == acceptor_stage_t::shedding_k || acceptor.reserve_descriptor < 0) {
            if (!event_loop.accept_deadline) event_loop.accept_deadline = deadline_after(linger_microseconds_k);
            return;
        }
        socket_close(std::exchange(acceptor.reserve_descriptor, -1));
        acceptor.stage = acceptor_stage_t::shedding_k;
        aim_accept(event_loop, acceptor);
        if (event_loop.engine.submit(acceptor.request) == ucall_status_success_k) return;
        acceptor.stage = acceptor_stage_t::idle_k;
        reopen_reserve(event_loop, acceptor);
    }

    /** Closes the shed peer once its refusal is done, counts it, and reopens the reserve. */
    static void shed_sent(event_loop_t& event_loop, interface_acceptor_t& acceptor) noexcept {
        event_loop.engine.close_socket(std::exchange(acceptor.shed_request.descriptor, -1));
        tally<atomic_ref>(event_loop.statistics.shed_connections);
        acceptor.stage = acceptor_stage_t::idle_k;
        reopen_reserve(event_loop, acceptor);
    }

    /** Reopens @p acceptor's reserve, or, refused, holds it closed until a close frees a descriptor
     *  or @c accept_deadline passes. */
    static void reopen_reserve(event_loop_t& event_loop, interface_acceptor_t& acceptor) noexcept {
        if (acceptor.reserve_descriptor < 0)
            acceptor.reserve_descriptor = socket_open(acceptor.network_interface->family);
        if (acceptor.reserve_descriptor < 0 && !event_loop.accept_deadline)
            event_loop.accept_deadline = deadline_after(linger_microseconds_k);
    }

    /** The acceptor whose refusal @p request sends, or null. */
    static interface_acceptor_t* shedding_acceptor(event_loop_t& event_loop, io_request_t const* request) noexcept {
        for (auto& acceptor : event_loop.interface_acceptors)
            if (request == &acceptor.shed_request) return &acceptor;
        return nullptr;
    }

    /** Takes one connection an accept completed with, or its failure. An accept stays pending while
     *  its request keeps a @c length, each further connection then taking an admission of its own,
     *  and ends, cancelled, once none is left. */
    static void accepted(io_completion_t const& completion) noexcept {
        auto& acceptor = *static_cast<interface_acceptor_t*>(completion.request->context);
        auto& event_loop = *acceptor.event_loop;
        auto& server = *event_loop.server;
        auto& network_interface = *acceptor.network_interface;
        bool const pending = completion.request->length != 0;
        auto const stage = pending ? acceptor.stage : std::exchange(acceptor.stage, acceptor_stage_t::idle_k);
        if (stage == acceptor_stage_t::submitted_k && !pending)
            atomic_ref<std::size_t> {network_interface.accepting}.sub(1, std::memory_order_relaxed);
        if (completion.result < 0) {
            if (stage == acceptor_stage_t::submitted_k) release_admission(server, network_interface);
            auto const failure = utilities::accept_failure(static_cast<int>(-completion.result));
            if (stage == acceptor_stage_t::shedding_k && failure != accept_failure_t::exhausted_k)
                reopen_reserve(event_loop, acceptor);
            if (failure == accept_failure_t::peer_k) return;
            char digits[std::numeric_limits<int>::digits10 + 1];
            formatting_t::log_line(
                server.config.log,
                failure == accept_failure_t::exhausted_k ? ucall_log_level_warning_k : ucall_log_level_error_k,
                failure == accept_failure_t::exhausted_k ? "accept_exhausted" : "accept_failed",
                {{"errno", formatting_t::format_decimal(digits, -completion.result)},
                 {"address", text_view(network_interface.config.address)}});
            if (failure == accept_failure_t::broken_k) {
                atomic_ref<ucall_status_t> {server.failure}.store(ucall_status_io_k, std::memory_order_release);
                return server_t::server_cut(server);
            }
            return shed_accept(event_loop, acceptor, stage);
        }
        descriptor_t const descriptor = completion.result;
        // A connection the accept took on its way names its own address; the last one, where the
        // request now points.
        byte_t const* const written = completion.data ? completion.data : completion.request->data;
        auto const peer = formatting_t::peer_address(reinterpret_cast<io_peer_address_t const*>(written)->address);
        auto active = atomic_ref<std::size_t> {network_interface.active};
        auto const limit = network_interface.config.max_concurrent_connections;
        if (stage == acceptor_stage_t::submitted_k) {
            admit(server, event_loop, network_interface, descriptor, peer);
            if (!pending) return;
            // The accept still pending holds an admission of its own, or, saturated, ends.
            if (event_loop.idle && active.fetch_add_if_at_most(1, limit, std::memory_order_relaxed) < limit) return;
            atomic_ref<std::size_t> {network_interface.accepting}.sub(1, std::memory_order_relaxed);
            acceptor.stage = acceptor_stage_t::probing_k;
            event_loop.engine.cancel(*completion.request);
            return;
        }
        if (stage == acceptor_stage_t::shedding_k) acceptor.reserve_descriptor = socket_open(network_interface.family);
        // A reserve that reopens shows the descriptor freed for a shed peer was not the last, so
        // only a peer that took the last is refused: a plaintext one reads `shed_reply_k` before
        // the close, and a Noise one, which no plaintext reaches, takes a reset.
        if (stage == acceptor_stage_t::shedding_k && acceptor.reserve_descriptor < 0) {
            acceptor.stage = acceptor_stage_t::shedding_k;
            acceptor.shed_request = {.operation = io_operation_t::send_k,
                                     .descriptor = descriptor,
                                     .context = &acceptor};
            if (network_interface.config.security != ucall_security_none_k) {
                [[maybe_unused]] ucall_status_t const reset = event_loop.engine.reset_on_close(descriptor);
                return shed_sent(event_loop, acceptor);
            }
            static_assert(shed_reply_k.size() <= sizeof(io_peer_address_t));
            // The accept is done with its peer address, and a send takes writable bytes.
            byte_t* const reply = reinterpret_cast<byte_t*>(acceptor.peer_addresses.data());
            std::memcpy(reply, shed_reply_k.data(), shed_reply_k.size());
            acceptor.shed_request.data = reply;
            acceptor.shed_request.length = shed_reply_k.size();
            if (event_loop.engine.submit(acceptor.shed_request) != ucall_status_success_k)
                shed_sent(event_loop, acceptor);
            return;
        }
        // A probe or a shed accept took no admission, so it admits only what a close freed
        // meanwhile, or else evicts.
        if (event_loop.idle && active.fetch_add_if_at_most(1, limit, std::memory_order_relaxed) < limit)
            return admit(server, event_loop, network_interface, descriptor, peer);
        auto& order = interface_order(server, event_loop, network_interface);
        // One peer waits for an eviction at a time; a saturated accept's later ones are refused.
        if (server_stage(server) != server_stage_t::serving_k || order.evicting >= 0) {
            event_loop.engine.close_socket(descriptor);
            return;
        }
        // The next close passes its slot to this peer, so admission never passes its budget.
        order.evicting = descriptor;
        order.evicting_peer = peer;
        evict(event_loop, order);
    }

    /** Closes the longest-idle connection for the peer parked in @p order, unless one already
     *  closes for it or every connection holds a request. */
    static void evict(event_loop_t& event_loop, interface_order_t& order) noexcept {
        if (order.evicting < 0 || order.evicted != absent_k || order.keepalive.empty()) return;
        auto& evicted = *event_loop.connections[order.keepalive.oldest];
        unlist(event_loop, evicted);
        evicted.transport.fail(ucall_status_connection_closed_k);
        mark_ready(event_loop, evicted);
        order.evicted = evicted.index;
    }

    /** Starts serving @p descriptor on an idle connection of @p event_loop under an admission it
     *  already holds, or closes it and gives the admission back. */
    static void admit(server_t& server, event_loop_t& event_loop, network_interface_t& network_interface,
                      descriptor_t descriptor, ucall_peer_address_t const& peer) noexcept {
        auto* chosen = event_loop.idle;
        if (!chosen || atomic_ref<std::uint32_t> {server.stage}.load(std::memory_order_acquire)) {
            event_loop.engine.close_socket(descriptor);
            release_admission(server, network_interface);
            return;
        }
        tally<atomic_ref>(event_loop.statistics.accepts);
        event_loop.idle = chosen->next;
        ++event_loop.open_connections;
        chosen->transport.descriptor = descriptor;
        chosen->transport.receive_memory = event_loop.engine.receive_memory();
        chosen->transport.peer_address = peer;
        chosen->network_interface = &network_interface;
        chosen->send_buffer_bytes = network_interface.send_buffer_bytes;
        chosen->transport.stage = transport_stage_t::handshake_k;
        chosen->transport.status = ucall_status_success_k;
        chosen->transport.authorizer = network_interface.config.peer_authorizer;
        chosen->transport.interface_statistics =
            &event_loop
                 .interface_statistics[static_cast<std::size_t>(&network_interface - server.network_interfaces.data())];
        tally<atomic_ref>(chosen->transport.interface_statistics->connections);
        chosen->transport.authorizer_context = network_interface.config.peer_authorizer_context;
        auto result = chosen->configure(
            formatting_t::tunnel_config(network_interface.config.security, secure_tunnel_role_t::responder_k,
                                        network_interface.config.noise_private_key, network_interface.public_key,
                                        network_interface.config.noise_peer_key));
        if (result != ucall_status_success_k) chosen->transport.fail(result);
        mark_ready(event_loop, *chosen);
    }
};

} // namespace unum::ucall::network
