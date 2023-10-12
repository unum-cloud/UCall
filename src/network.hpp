#pragma once

#include <cstddef>

#include "connection.hpp"

namespace unum::ucall {
struct network_engine_t {
    network_data_t network_data;

    int try_accept(descriptor_t, connection_t&) noexcept;
    void set_stats_heartbeat(connection_t&) noexcept;
    void send_packet(connection_t&, void*, std::size_t, std::size_t) noexcept;
    void recv_packet(connection_t&, void*, std::size_t, std::size_t) noexcept;
    void close_connection_gracefully(connection_t&) noexcept;

    bool is_canceled(ssize_t, connection_t const&) noexcept;
    bool is_corrupted(ssize_t, connection_t const&) noexcept;

    template <size_t max_count_ak> std::size_t pop_completed_events(completed_event_t*) noexcept;
};
} // namespace unum::ucall