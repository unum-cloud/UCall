/**
 *  @file include/ucall/network/metrics.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief StatsD datagrams an event loop composes from its counters.
 */
#pragma once

#include "ucall/io/types.hpp"          // `io_completion_t`
#include "ucall/network/loops.hpp"     // `metrics_state_t`
#include "ucall/network/types.hpp"     // `refused_statuses_k`, `interface_statistics_t`
#include "ucall/utilities/sockets.hpp" // `deadline_after`, `monotonic_ns`
#include "ucall/utilities/types.hpp"   // `text_view`, `byte_t`

namespace unum::ucall::network {

using io::io_completion_t;
using utilities::byte_t;
using utilities::deadline_after;
using utilities::monotonic_ns;
using utilities::text_view;

/** A statistics counter and the metric name it is reported under. */
template <typename counter_pointer_type_>
struct counter_name {
    std::string_view name;
    counter_pointer_type_ counter;
};

/** Composes and sends the StatsD datagrams of an event loop. */
template <typename network_type_>
struct metrics {
    using network_t = network_type_;
    using http_t = typename network_t::http_t;
    using server_exchange_t = typename network_t::server_exchange_t;
    using loop_metrics_t = typename network_t::loop_metrics_t;
    using event_loop_t = typename network_t::event_loop_t;
    using server_t = typename network_t::server_t;
    using formatting_t = typename network_t::formatting_t;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;
    template <typename value_type_>
    using atomic_ref = typename network_t::template atomic_ref<value_type_>;

    /** @p key followed by the decimal @p value, written into @p output. */
    template <std::size_t capacity_>
    static std::string_view tag_text(char (&output)[capacity_], std::string_view key, std::uint64_t value) noexcept {
        std::memcpy(output, key.data(), key.size());
        auto written = std::to_chars(output + key.size(), output + capacity_, value);
        return {output, static_cast<std::size_t>(written.ptr - output)};
    }

    /** @p key followed by as much of @p value as @p output holds. */
    template <std::size_t capacity_>
    static std::string_view tag_text(char (&output)[capacity_], std::string_view key, std::string_view value) noexcept {
        std::size_t const length = std::min(value.size(), capacity_ - key.size());
        std::memcpy(output, key.data(), key.size());
        if (length) std::memcpy(output + key.size(), value.data(), length);
        return {output, key.size() + length};
    }

    /** Appends one StatsD line, <tt>prefix.name:value|type</tt> with the global tags and
     *  @p tags, or leaves @p datagram as it was with overflow when the line would pass
     *  the datagram's bound. */
    static ucall_status_t append_metric(server_t const& server, vector<byte_t>& datagram, std::string_view name,
                                        std::string_view value, std::string_view type,
                                        std::initializer_list<std::string_view> tags) noexcept {
        std::size_t const before = datagram.size();
        ucall_status_t status = http_t::append_text(
            datagram, {before ? "\n" : "", text_view(server.metrics_prefix), ".", name, ":", value, "|", type});
        std::string_view separator = "|#";
        for (ucall_bytes_view_t tag : server.metrics_tag_views) {
            if (status == ucall_status_success_k) status = http_t::append_text(datagram, {separator, text_view(tag)});
            separator = ",";
        }
        for (std::string_view tag : tags) {
            if (status == ucall_status_success_k) status = http_t::append_text(datagram, {separator, tag});
            separator = ",";
        }
        if (status == ucall_status_success_k && datagram.size() > server.metrics_datagram_bytes)
            status = ucall_status_overflow_k;
        if (status != ucall_status_success_k) {
            // Never grows.
            [[maybe_unused]] st::status_t const shrunk = datagram.resize(before);
        }
        return status;
    }

    /** Hands the composing datagram to the engine, when the previous one left. */
    static void send_metrics(event_loop_t& event_loop) noexcept {
        auto& metrics = event_loop.metrics;
        if (metrics.state != metrics_state_t::idle_k || metrics.composing.empty()) return;
        std::swap(metrics.composing, metrics.sending);
        metrics.composing.clear();
        metrics.send_request.data = metrics.sending.data();
        metrics.send_request.length = metrics.sending.size();
        if (event_loop.engine.submit(metrics.send_request) == ucall_status_success_k)
            metrics.state = metrics_state_t::sending_k;
        else metrics.sending.clear();
    }

    /** Starts the next datagram's counters from what the last delivered one reported. */
    static void restart_reporting(loop_metrics_t& metrics) noexcept {
        metrics.reporting = metrics.reported;
        std::memcpy(metrics.interfaces_reporting.data(), metrics.interfaces_reported.data(),
                    metrics.interfaces_reported.size() * sizeof(interface_statistics_t));
        if (!metrics.batches_reported.empty())
            std::memcpy(metrics.batches_reporting.data(), metrics.batches_reported.data(),
                        metrics.batches_reported.size() * sizeof(ucall_batch_endpoint_statistics_t));
    }

    /** Settles a sent datagram: delivered counters become the base of the next deltas, and a failed
     *  one leaves them to the next datagram. */
    static void complete_metrics(event_loop_t& event_loop, io_completion_t const& completion) noexcept {
        auto& metrics = event_loop.metrics;
        metrics.state = metrics_state_t::idle_k;
        metrics.sending.clear();
        if (completion.result < 0) return;
        metrics.reported = metrics.reporting;
        std::memcpy(metrics.interfaces_reported.data(), metrics.interfaces_reporting.data(),
                    metrics.interfaces_reporting.size() * sizeof(interface_statistics_t));
        if (!metrics.batches_reporting.empty())
            std::memcpy(metrics.batches_reported.data(), metrics.batches_reporting.data(),
                        metrics.batches_reporting.size() * sizeof(ucall_batch_endpoint_statistics_t));
    }

    /** Writes a latency line for one in every <tt>1 / metrics_sample_rate</tt> finished requests,
     *  sending early when it would not fit, and dropping it when both datagrams are taken. */
    static void time_request(server_t& server, event_loop_t& event_loop, server_exchange_t const& exchange) noexcept {
        auto& metrics = event_loop.metrics;
        if (metrics.state == metrics_state_t::closed_k || !exchange.endpoint || !exchange.reply_status) return;
        float const rate = server.config.metrics_sample_rate;
        metrics.sample_credit += rate;
        if (metrics.sample_credit < 1.f) return;
        metrics.sample_credit -= 1.f;
        std::uint64_t const micros = (monotonic_ns() - exchange.arrived) / 1000;
        char value[32], type[24], endpoint_text[256], method_text[32], status_text[24];
        char* const point = std::to_chars(value, value + sizeof(value) - 4, micros / 1000).ptr;
        point[0] = '.';
        point[1] = static_cast<char>('0' + micros / 100 % 10);
        point[2] = static_cast<char>('0' + micros / 10 % 10);
        point[3] = static_cast<char>('0' + micros % 10);
        std::memcpy(type, "ms|@", 4);
        std::size_t const type_length =
            rate < 1.f ? static_cast<std::size_t>(std::to_chars(type + 4, type + sizeof(type), rate).ptr - type) : 2;
        char const* const verb = http_t::http_verb_name(exchange.message.verb);
        std::initializer_list<std::string_view> const tags {
            tag_text(endpoint_text, "endpoint:", exchange.endpoint->path),
            tag_text(method_text, "method:", verb ? std::string_view {verb} : std::string_view {}),
            tag_text(status_text, "status:", exchange.reply_status)};
        std::string_view const text {value, static_cast<std::size_t>(point + 4 - value)}, kind {type, type_length};
        if (append_metric(server, metrics.composing, "latency", text, kind, tags) == ucall_status_success_k) return;
        if (metrics.state == metrics_state_t::idle_k) {
            restart_reporting(metrics);
            send_metrics(event_loop);
            if (append_metric(server, metrics.composing, "latency", text, kind, tags) == ucall_status_success_k) return;
        }
        ++metrics.dropped_lines;
    }

    /** Once due, writes the loop's counter deltas and gauges behind the latency lines waiting, and
     *  sends them; a datagram still sending leaves its window's deltas to the next one. */
    static void emit_metrics(server_t& server, event_loop_t& event_loop) noexcept {
        auto& metrics = event_loop.metrics;
        if (metrics.state == metrics_state_t::closed_k || monotonic_ns() < metrics.due) return;
        metrics.due = deadline_after(server.config.metrics_interval_microseconds);
        if (metrics.state != metrics_state_t::idle_k) return;
        restart_reporting(metrics);
        auto& datagram = metrics.composing;
        char digits[24], loop_text[32], interface_text[32], status_text[32];
        std::string_view const loop = tag_text(loop_text, "loop:", event_loop.index);
        using counter_t = std::uint64_t ucall_event_loop_statistics_t::*;
        static constexpr counter_name<counter_t> counters_k[] {
            {"polls", &ucall_event_loop_statistics_t::polls},
            {"empty_polls", &ucall_event_loop_statistics_t::empty_polls},
            {"kernel_enters", &ucall_event_loop_statistics_t::kernel_enters},
            {"submissions", &ucall_event_loop_statistics_t::submissions},
            {"completions", &ucall_event_loop_statistics_t::completions},
            {"cancellations", &ucall_event_loop_statistics_t::cancellations},
            {"accepts", &ucall_event_loop_statistics_t::accepts},
            {"requests", &ucall_event_loop_statistics_t::requests},
            {"receive_rearms", &ucall_event_loop_statistics_t::receive_rearms},
            {"bytes_received", &ucall_event_loop_statistics_t::bytes_received},
            {"bytes_sent", &ucall_event_loop_statistics_t::bytes_sent},
            {"bytes_copied", &ucall_event_loop_statistics_t::bytes_copied},
            {"zero_copy_sends", &ucall_event_loop_statistics_t::zero_copy_sends},
            {"zero_copy_fallbacks", &ucall_event_loop_statistics_t::zero_copy_fallbacks},
            {"copying_sends", &ucall_event_loop_statistics_t::copying_sends},
            {"file_reads_asynchronous", &ucall_event_loop_statistics_t::file_reads_asynchronous},
            {"file_reads_blocking", &ucall_event_loop_statistics_t::file_reads_blocking},
            {"bytes_read", &ucall_event_loop_statistics_t::bytes_read},
            {"file_window_overlaps", &ucall_event_loop_statistics_t::file_window_overlaps},
            {"linger_resets", &ucall_event_loop_statistics_t::linger_resets},
            {"ready_passes", &ucall_event_loop_statistics_t::ready_passes},
            {"replied_dequeues", &ucall_event_loop_statistics_t::replied_dequeues}};
        ucall_event_loop_statistics_t const totals = server_t::loop_totals(event_loop);
        ucall_status_t fitted = ucall_status_success_k;
        for (auto [name, counter] : counters_k) {
            std::uint64_t const delta = totals.*counter - metrics.reported.*counter;
            if (!delta || fitted != ucall_status_success_k) continue;
            fitted = append_metric(server, datagram, name, formatting_t::format_decimal(digits, delta), "c", {loop});
            if (fitted == ucall_status_success_k) metrics.reporting.*counter = totals.*counter;
        }
        for (std::size_t i = 0; i != event_loop.interface_statistics.size() && fitted == ucall_status_success_k; ++i) {
            auto const& live = event_loop.interface_statistics[i];
            auto const& reported = metrics.interfaces_reported[i];
            auto& reporting = metrics.interfaces_reporting[i];
            std::string_view const interface = tag_text(interface_text, "interface:", i);
            fitted = append_metric(server, datagram, "connections",
                                   formatting_t::format_decimal(digits, live.connections), "g", {loop, interface});
            for (std::size_t j = 0; j != std::size(refused_statuses_k) && fitted == ucall_status_success_k; ++j) {
                if (live.refused[j] == reported.refused[j]) continue;
                fitted = append_metric(server, datagram, "refused",
                                       formatting_t::format_decimal(digits, live.refused[j] - reported.refused[j]), "c",
                                       {loop, interface, tag_text(status_text, "status:", refused_statuses_k[j])});
                if (fitted == ucall_status_success_k) reporting.refused[j] = live.refused[j];
            }
            using failure_t = std::uint64_t interface_statistics_t::*;
            for (auto [name, failure] :
                 {counter_name<failure_t> {"handshake_failures", &interface_statistics_t::handshake_failures},
                  counter_name<failure_t> {"authorizer_refusals", &interface_statistics_t::authorizer_refusals}}) {
                if (live.*failure == reported.*failure || fitted != ucall_status_success_k) continue;
                fitted = append_metric(server, datagram, name,
                                       formatting_t::format_decimal(digits, live.*failure - reported.*failure), "c",
                                       {loop, interface});
                if (fitted == ucall_status_success_k) reporting.*failure = live.*failure;
            }
        }
        std::size_t batch_index = 0;
        for (auto* endpoint = server.endpoints; endpoint && !event_loop.index && fitted == ucall_status_success_k;
             endpoint = endpoint->next) {
            if (!endpoint->batch) continue;
            auto& batch = *endpoint->batch;
            auto& reported = metrics.batches_reported[batch_index];
            auto& reporting = metrics.batches_reporting[batch_index++];
            char endpoint_text[256];
            std::string_view const tag = tag_text(endpoint_text, "endpoint:", endpoint->path);
            std::uint64_t const queued = atomic_ref<std::uint64_t> {batch.tail}.load(std::memory_order_relaxed) -
                                         atomic_ref<std::uint64_t> {batch.head}.load(std::memory_order_relaxed);
            fitted = append_metric(server, datagram, "batch.queue", formatting_t::format_decimal(digits, queued), "g",
                                   {tag});
            using batch_counter_t = std::uint64_t ucall_batch_endpoint_statistics_t::*;
            static constexpr counter_name<batch_counter_t> batch_counters_k[] {
                {"batch.batches", &ucall_batch_endpoint_statistics_t::batches},
                {"batch.requests", &ucall_batch_endpoint_statistics_t::requests},
                {"batch.filled", &ucall_batch_endpoint_statistics_t::filled_batches},
                {"batch.ready", &ucall_batch_endpoint_statistics_t::ready_batches},
                {"batch.expired", &ucall_batch_endpoint_statistics_t::expired_batches}};
            for (auto [name, counter] : batch_counters_k) {
                std::uint64_t const total = atomic_ref<std::uint64_t> {batch.statistics.*counter}.load(
                    std::memory_order_relaxed);
                if (total == reported.*counter || fitted != ucall_status_success_k) continue;
                fitted = append_metric(server, datagram, name,
                                       formatting_t::format_decimal(digits, total - reported.*counter), "c", {tag});
                if (fitted == ucall_status_success_k) reporting.*counter = total;
            }
        }
        if (metrics.dropped_lines && append_metric(server, datagram, "metrics_dropped",
                                                   formatting_t::format_decimal(digits, metrics.dropped_lines), "c",
                                                   {loop}) == ucall_status_success_k)
            metrics.dropped_lines = 0;
        send_metrics(event_loop);
    }
};

} // namespace unum::ucall::network
