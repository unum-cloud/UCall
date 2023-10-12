#pragma once
#include <atomic>
#include <stdio.h> // `std::snprintf`

namespace unum::ucall {

struct number_and_suffix_t {
    float number{};
    char suffix{};
};

inline number_and_suffix_t printable(std::size_t n) noexcept {
    if (n > 1'000'000'000)
        return {n / 1'000'000'000.0f, 'G'};
    if (n > 1'000'000)
        return {n / 1'000'000.0f, 'M'};
    if (n > 1'000)
        return {n / 1'000.0f, 'K'};
    return {n + 0.0f, ' '};
}

struct stats_t {

    static constexpr std::size_t default_frequency_secs_k{5};

    std::atomic<std::size_t> added_connections{};
    std::atomic<std::size_t> closed_connections{};
    std::atomic<std::size_t> bytes_received{};
    std::atomic<std::size_t> bytes_sent{};
    std::atomic<std::size_t> packets_received{};
    std::atomic<std::size_t> packets_sent{};

    inline std::size_t log_human_readable(char* buffer, std::size_t buffer_capacity, std::size_t seconds) noexcept {
        auto& s = *this;
        auto printable_normalized = [=](std::atomic<std::size_t>& i) noexcept {
            return printable(double(i.exchange(0, std::memory_order_relaxed)) / seconds);
        };
        auto added_connections = printable_normalized(s.added_connections);
        auto closed_connections = printable_normalized(s.closed_connections);
        auto bytes_received = printable_normalized(s.bytes_received);
        auto bytes_sent = printable_normalized(s.bytes_sent);
        auto packets_received = printable_normalized(s.packets_received);
        auto packets_sent = printable_normalized(s.packets_sent);
        auto len = snprintf( //
            buffer, buffer_capacity,
            "connections: +%.1f %c/s, "
            "-%.1f %c/s, "
            "RX: %.1f %c msgs/s, "
            "%.1f %cb/s, "
            "TX: %.1f %c msgs/s, "
            "%.1f %cb/s. \n",
            added_connections.number, added_connections.suffix,   //
            closed_connections.number, closed_connections.suffix, //
            packets_received.number, packets_received.suffix,     //
            bytes_received.number, bytes_received.suffix,         //
            packets_sent.number, packets_sent.suffix,             //
            bytes_sent.number, bytes_sent.suffix                  //
        );
        return static_cast<std::size_t>(len);
    }

    inline std::size_t log_json(char* buffer, std::size_t buffer_capacity) noexcept {
        auto& s = *this;
        auto added_connections = s.added_connections.exchange(0, std::memory_order_relaxed);
        auto closed_connections = s.closed_connections.exchange(0, std::memory_order_relaxed);
        auto bytes_received = s.bytes_received.exchange(0, std::memory_order_relaxed);
        auto bytes_sent = s.bytes_sent.exchange(0, std::memory_order_relaxed);
        auto packets_received = s.packets_received.exchange(0, std::memory_order_relaxed);
        auto packets_sent = s.packets_sent.exchange(0, std::memory_order_relaxed);
        auto format =
            R"( {"add":%zu,"close":%zu,"recv_bytes":%zu,"sent_bytes":%zu,"recv_packs":%zu,"sent_packs":%zu} \n )";
        auto len = snprintf(         //
            buffer, buffer_capacity, //
            format,                  //
            added_connections,       //
            closed_connections,      //
            bytes_received,          //
            bytes_sent,              //
            packets_received,        //
            packets_sent             //
        );
        return static_cast<std::size_t>(len);
    }
};

} // namespace unum::ucall