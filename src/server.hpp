#pragma once

#include "connection.hpp"
#include "containers.hpp"
#include "engine.hpp"
#include "network.hpp"
#include "shared.hpp"

namespace unum::ucall {

struct server_t {
    descriptor_t socket{};
    network_engine_t network_engine{};
    engine_t engine{};
    protocol_type_t protocol_type{};
    std::unique_ptr<ssl_context_t> ssl_ctx{};

    std::atomic<std::size_t> active_connections{};
    std::uint32_t max_lifetime_micro_seconds{};
    std::uint32_t max_lifetime_exchanges{};

    stats_t stats{};
    connection_t stats_pseudo_connection{};

    std::int32_t logs_file_descriptor{};
    std::string_view logs_format{};

    /// @brief A circular container of reusable connections. Can be in millions.
    pool_gt<connection_t> connections{};
    mutex_t connections_mutex{};
    /// @brief Same number of them, as max physical threads. Can be in hundreds.
    /// @brief Pre-allocated buffered to be submitted for shared use.
    memory_map_t fixed_buffers{};

    void submit_stats_heartbeat() noexcept;
    void release_connection(connection_t&) noexcept;
    void log_and_reset_stats() noexcept;
    bool consider_accepting_new_connection() noexcept;
};

void server_t::submit_stats_heartbeat() noexcept {
    connection_t& connection = stats_pseudo_connection;
    connection.stage = stage_t::log_stats_k;
    connection.next_wakeup = stats_t::default_frequency_secs_k;

    network_engine.set_stats_heartbeat(connection);
}

void server_t::log_and_reset_stats() noexcept {
    static char printed_message_k[ram_page_size_k]{};
    auto len = logs_format == "json" //
                   ? stats.log_json(printed_message_k, ram_page_size_k)
                   : stats.log_human_readable(printed_message_k, ram_page_size_k, stats_t::default_frequency_secs_k);
    len = write(logs_file_descriptor, printed_message_k, len);
}

void server_t::release_connection(connection_t& connection) noexcept {
    auto is_active = connection.stage != stage_t::waiting_to_accept_k;
    connection.reset();
    connections_mutex.lock();
    connections.release(&connection);
    connections_mutex.unlock();
    active_connections -= is_active;
    stats.closed_connections.fetch_add(is_active, std::memory_order_relaxed);
}

bool server_t::consider_accepting_new_connection() noexcept {

    connections_mutex.lock();
    connection_t* con_ptr = connections.alloc();
    connections_mutex.unlock();

    if (!con_ptr)
        return false;

    con_ptr->protocol.reset_protocol(protocol_type);
    connection_t& connection = *con_ptr;
    connection.stage = stage_t::waiting_to_accept_k;
    int result = network_engine.try_accept(socket, connection);

    if (result < 0) {
        connections.release(con_ptr);
        return false;
    }

    return true;
}

} // namespace unum::ucall
