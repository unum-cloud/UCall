#pragma once

#include "connection.hpp"
#include "server.hpp"
#include "shared.hpp"

namespace unum::ucall {

struct automata_t {
    server_t& server;
    connection_t& connection;
    ssize_t completed_result{};

    void operator()() noexcept;

    // Computed properties:
    bool should_release() const noexcept;
    bool is_corrupted() const noexcept;

    void send_next() noexcept;
    void receive_next() noexcept;
    void close_gracefully() noexcept;
    protocol_t const& get_protocol() const noexcept;
};

protocol_t const& automata_t::get_protocol() const noexcept { return connection.protocol; };

bool automata_t::is_corrupted() const noexcept { return completed_result == -EPIPE || completed_result == -EBADF; }

void automata_t::close_gracefully() noexcept {
    connection.stage = stage_t::waiting_to_close_k;
    server.network_engine.close_connection_gracefully(connection);
}

void automata_t::send_next() noexcept {
    exchange_pipes_t& pipes = connection.pipes;
    connection.stage = stage_t::responding_in_progress_k;
    connection.protocol.reset();
    pipes.release_inputs();

    connection.encrypt();
    server.network_engine.send_packet(connection, (void*)pipes.next_output_address(), pipes.next_output_length(),
                                      server.connections.offset_of(connection) * 2u + 1u);
}

void automata_t::receive_next() noexcept {
    exchange_pipes_t& pipes = connection.pipes;
    connection.stage = stage_t::expecting_reception_k;
    pipes.release_outputs();

    server.network_engine.recv_packet(connection, (void*)pipes.next_input_address(), pipes.next_input_length(),
                                      server.connections.offset_of(connection) * 2u);
}

void automata_t::operator()() noexcept {

    switch (connection.stage) {

    case stage_t::waiting_to_accept_k:

        if (server.network_engine.is_canceled(completed_result, connection)) {
            server.release_connection(connection);
            return;
        }
        if (server.ssl_ctx)
            connection.make_tls(&server.ssl_ctx->ssl);

        // Check if accepting the new connection request worked out.
        connection.record_activity();
        ++server.active_connections;
        server.stats.added_connections.fetch_add(1, std::memory_order_relaxed);
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
        if (server.network_engine.is_corrupted(completed_result, connection) || connection.expired())
            return close_gracefully();

        if (server.network_engine.is_canceled(completed_result, connection)) {
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
            ucall_call_reply_error_out_of_memory(this);
            return send_next();
        }

        if (!connection.prepare_step())
            return send_next();

        // If we have reached the end of the stream,
        // it is time to analyze the contents
        // and send back a response.
        connection.decrypt(completed_result);
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
        if (server.network_engine.is_corrupted(completed_result, connection) || connection.expired())
            return close_gracefully();

        connection.empty_transmits = completed_result == 0 ? ++connection.empty_transmits : 0;

        if (server.network_engine.is_canceled(completed_result, connection)) {
            connection.next_wakeup *= sleep_growth_factor_k;
            completed_result = 0;
        }

        if (!connection.is_ready())
            return receive_next();

        connection.record_activity();
        server.stats.bytes_sent.fetch_add(completed_result, std::memory_order_relaxed);
        server.stats.packets_sent.fetch_add(1, std::memory_order_relaxed);
        connection.pipes.mark_submitted_outputs(completed_result);
        if (!connection.pipes.has_remaining_outputs()) {
            connection.exchanges++;
            if (connection.must_close())
                return close_gracefully();
            else
                return receive_next();
        } else {
            connection.pipes.prepare_more_outputs();
            return send_next();
        }

    case stage_t::waiting_to_close_k:
        return server.release_connection(connection);

    case stage_t::log_stats_k:
        server.log_and_reset_stats();
        return server.submit_stats_heartbeat();

    case stage_t::unknown_k:
        return;
    }
}

} // namespace unum::ucall
