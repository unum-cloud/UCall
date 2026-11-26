/**
 *  @file tools/server.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Shared CLI, caller-owned polling, and graceful shutdown for the native services.
 */
#pragma once

#include <csignal> // `std::signal`, `std::sig_atomic_t`, `SIGINT`, `SIGTERM`
#include <cstddef> // `std::size_t`
#include <cstdint> // `std::uint16_t`, `std::uint64_t`
#include <cstdio>  // `stdout`, `stderr`, `std::fflush`
#include <cstring> // `std::memcpy`

#include <algorithm>        // `std::find_if`
#include <chrono>           // `std::chrono::milliseconds`, `std::chrono::microseconds`
#include <initializer_list> // `std::initializer_list`
#include <limits>           // `std::numeric_limits`
#include <span>             // `std::span`
#include <string_view>      // `std::string_view`
#include <thread>           // `std::this_thread::sleep_for`
#include <utility>          // `std::move`

#include <fmt/format.h> // `fmt::print`, `fmt::format_to_n`, `fmt::format_to`, `fmt::basic_memory_buffer`

#include <forkunion/forkunion.h>       // `fu_pool_t`, `fu_pool_unsafe_for_threads`, `fu_pool_capabilities`
#include <forkunion/types.hpp>         // `fu::min_of`
#include <smashtable/basic_vector.hpp> // `st::vector`, `st::failed`

#include "ucall/ucall.hpp" // `server_t`, `request_t`, `batch_endpoint_t`, `status_t`, `bytes_view`

#include "arguments.hpp" // `parse_count`, `parse_key`, `process_clocks_t`

namespace unum::ucall::tools {

namespace fu = ashvardanian::forkunion;
namespace st = ashvardanian::smashtable;

/** Set by the first SIGINT or SIGTERM, or by a failing loop; the main thread checks it every
 *  100 ms, and the server answers what it holds before the process exits. */
inline volatile std::sig_atomic_t stop_requested {0};

/** Asks the server to stop, and leaves a second signal its default action, ending the process. */
inline void request_stop(int) noexcept {
    stop_requested = 1;
    std::signal(SIGINT, SIG_DFL);
    std::signal(SIGTERM, SIG_DFL);
}

/** Human-readable lines, or one JSON object, for the counters printed at exit. */
enum class statistics_format_t { human_k, json_k };

/** A count only one service accepts, such as the scoring matrix's rows. */
struct count_flag_t {
    std::string_view name, help;
    std::size_t& value;
};

/** The flags, the server and the polling threads every native service shares: @c init parses the
 *  command line and starts the server, the service registers its routes on @c server, and @c run
 *  polls every event loop and batch endpoint until a signal. */
struct server_t {
    fu_pool_t pool {};
    fu_generation_t generation {};
    st::vector<status_t> statuses;
    ucall::server_t server {};
    std::size_t event_loops {};
    std::size_t connections {1024}, pipelined_requests {1};

    /** The command line's batch budgets, which zeros leave to the library. */
    batching_t batching {};

    /** Each gets its own polling thread, named once @c run starts. */
    std::span<batch_endpoint_t const> batch_endpoints {};
    statistics_format_t statistics_format {statistics_format_t::human_k};

    /** Read when the loops start, so the report spans the server's life. */
    process_clocks_t serving {};
    interface_t network_interface {};
    ucall_bytes_view_t reply_directory {};
    ucall_noise_key_t private_key {};
    char address[sizeof("[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:65535")] {};

    /** Admits every client key, as Noise XX needs a vetter and the services trust any. */
    struct any_peer_t {
        bool operator()(ucall_noise_key_t const&) const noexcept { return true; }
    } any_peer {};

    static bool succeeded(status_t status) {
        if (!status.failed()) return true;
        std::string_view const name = status_name(status.code);
        fmt::print(stderr, "{}{}{}\n", name, status.note ? ": " : "", status.note ? status.note : "");
        return false;
    }
    static void health(request_t request) noexcept {
        [[maybe_unused]] status_t const replied = std::move(request).reply(ucall_http_status_ok_k, {}, "ready\n");
    }
    int init(int argc, char** argv, std::initializer_list<count_flag_t> counts = {}) {
        server_options_t options {.cpu_class_ceiling = ucall_cpu_class_serial_k};
        std::size_t threads = 1;
        std::size_t port = 8545;
        std::size_t latency_microseconds = 0;
        std::string_view host {"127.0.0.1"};
        std::string_view key {};
        for (int i = 1; i != argc; ++i) {
            std::string_view flag {argv[i]};
            if (flag == "--help") {
                fmt::print(
                    "Usage: {} [--backend name] [--cpu-class-ceiling name] [--threads N] [--host IP] [--port N]\n"   //
                    "       [--connections N] [--pipelined-requests N] [--security none|xx|ik] [--key HEX]\n"        //
                    "       [--batch-min N] [--batch-max N] [--batch-latency-us N] [--stats human|json]\n"           //
                    "       [--reply-directory PATH]\n"                                                              //
                    "Backend defaults to automatic, the CPU class ceiling to serial, and threads to 1.\n"            //
                    "The host defaults to 127.0.0.1 and the port to 8545; pass 0.0.0.0 or :: to accept every NIC.\n" //
                    "Admission defaults to 1024 connections of 1 request each.\n"                                    //
                    "Noise needs the 64-digit hex server private key; without --key one is generated.\n"             //
                    "Either way the public key is printed; XX admits every client key.\n"                            //
                    "Batch budgets default to the library's 1, 32, and 10000 microseconds.\n"                        //
                    "--stats json prints every loop's and batch endpoint's counters as a JSON object.\n"             //
                    "--reply-directory registers the directory path parts of replies open files beneath.\n",
                    argv[0]);
                for (count_flag_t const& count : counts)
                    fmt::print("{} N: {} ({})\n", count.name, count.help, count.value);
                return 1;
            }
            std::string_view value {};
            std::size_t const separator = flag.find('=');
            if (separator != flag.npos) {
                value = flag.substr(separator + 1);
                flag = flag.substr(0, separator);
            }
            else if (i + 1 != argc) value = argv[++i];
            bool valid {};
            std::initializer_list<count_flag_t>::iterator const extra = std::find_if(
                counts.begin(), counts.end(), [&](count_flag_t const& count) { return count.name == flag; });
            if (flag == "--port")
                valid = parse_count(value, port) && port <= (std::numeric_limits<std::uint16_t>::max)();
            else if (flag == "--host") {
                host = value;
                valid = !value.empty() && value.size() <= sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - 1;
            }
            else if (flag == "--threads") valid = parse_count(value, threads, 1);
            else if (flag == "--connections") valid = parse_count(value, connections, 1);
            else if (flag == "--pipelined-requests") valid = parse_count(value, pipelined_requests, 1);
            else if (flag == "--reply-directory") {
                reply_directory = bytes_view(value);
                valid = !value.empty();
            }
            else if (flag == "--batch-min") valid = parse_count(value, batching.min_batch_size, 1);
            else if (flag == "--batch-max") valid = parse_count(value, batching.max_batch_size, 1);
            else if (flag == "--batch-latency-us") valid = parse_count(value, latency_microseconds, 1);
            else if (flag == "--key") {
                key = value;
                valid = parse_key(value, private_key);
            }
            else if (flag == "--security") {
                valid = value == "none" || value == "xx" || value == "ik";
                network_interface.security = value == "xx"   ? ucall_security_noise_xx_k
                                             : value == "ik" ? ucall_security_noise_ik_k
                                                             : ucall_security_none_k;
            }
            else if (flag == "--stats") {
                valid = value == "human" || value == "json";
                statistics_format = value == "json" ? statistics_format_t::json_k : statistics_format_t::human_k;
            }
            else if (flag == "--backend") valid = parse_backend(value, options.backend);
            else if (flag == "--cpu-class-ceiling") valid = parse_cpu_class(value, options.cpu_class_ceiling);
            else if (extra != counts.end()) valid = parse_count(value, extra->value);
            if (!valid) {
                fmt::print(stderr, "Invalid argument: {}={}\n", flag, value);
                return -1;
            }
        }
        batching.max_latency = std::chrono::microseconds(latency_microseconds);
        if (network_interface.security != ucall_security_none_k) {
            auto [keypair, keypair_status] = key.empty() ? noise_key_generate() : noise_key_derive(private_key);
            if (keypair_status.failed()) {
                fmt::print(stderr, "The server key is unavailable: {}\n",
                           keypair_status.note ? keypair_status.note : "");
                return -1;
            }
            std::memcpy(private_key, keypair.private_key, sizeof(ucall_noise_key_t));
            fmt::print("Server public key: ");
            print_key(stdout, keypair.public_key);
            network_interface.noise_private_key = &private_key;
            if (network_interface.security == ucall_security_noise_xx_k) network_interface.peer_authorizer = any_peer;
        }
        std::signal(SIGINT, request_stop);
        std::signal(SIGTERM, request_stop);
        // IPv6 literals take brackets, as the server prints its own bound addresses.
        bool const bracketed = host.find(':') != host.npos;
        auto const written = bracketed ? fmt::format_to_n(address, sizeof(address) - 1, "[{}]:{}", host, port)
                                       : fmt::format_to_n(address, sizeof(address) - 1, "{}:{}", host, port);
        network_interface.address = {address, written.out};
        network_interface.max_concurrent_connections = connections;
        network_interface.max_pipelined_requests = pipelined_requests;
        network_interface.event_loops = fu::min_of(threads, connections);
        if (reply_directory.length) network_interface.reply_directories = {&reply_directory, 1};
        interface_t const interfaces[] {network_interface};
        auto [started, started_status] = ucall::server_t::make(interfaces, options);
        if (!succeeded(started_status) || !succeeded(started.get<health>("/health"))) return -1;
        server = std::move(started);
        event_loops = server.event_loops();
        auto [bound, bound_status] = server.address(0);
        if (!succeeded(bound_status)) return -1;
        fmt::print("Listening on {} using {}, {}, {} application-owned serving loops\n", bound,
                   io_backend_name(server.backend()), cpu_class_name(server.cpu_class_ceiling()), event_loops);
        std::fflush(stdout); // Scripts read the public key and the address before the server exits.
        return 0;
    }
    static void serve(void* context, std::size_t index, std::size_t) {
        server_t& application = *static_cast<server_t*>(context);
        status_t& status = application.statuses[index];
        if (index < application.event_loops) status = application.server.take_calls(index);
        else status = application.batch_endpoints[index - application.event_loops].take_batches();
        if (status.failed()) stop_requested = 1;
    }

    /** Polls every event loop and each of @p batches on a thread of its own until a signal, then
     *  reports the counters. */
    int run(std::span<batch_endpoint_t const> batches = {}) {
        batch_endpoints = batches;
        serving = process_clocks_t::now();
        std::size_t const threads = event_loops + batch_endpoints.size();
        if (st::failed(statuses.resize(threads))) {
            fmt::print(stderr, "No memory for {} polling threads\n", threads);
            return 1;
        }
        fu_topology_t topology {};
        fu_status_t status = fu_topology_new(&topology);
        if (status == fu_success_k) status = fu_pool_new("ucall-server", fu_capabilities_all_k, &pool);
        if (status == fu_success_k) status = fu_pool_spawn(topology, pool, threads, fu_caller_exclusive_k);
        if (topology) fu_topology_delete(topology);
        if (status != fu_success_k) {
            fmt::print(stderr, "ForkUnion initialization failed: {}\n", static_cast<int>(status));
            return 1;
        }
        if (fu_pool_unsafe_for_threads(pool, serve, this, &generation) != fu_success_k) return 1;
        while (!stop_requested) std::this_thread::sleep_for(std::chrono::milliseconds {100});
        server.stop();
        fu_pool_unsafe_join(pool, generation);
        // Every loop drained cleanly only when a signal, not a failure, stopped them.
        int result = exit_stopped_k;
        for (status_t const& polled : statuses)
            if (!succeeded(polled)) result = 1;
        return report() ? result : 1;
    }

    /** Prints the counters of every loop and batch endpoint, then the seconds served and spent. */
    bool report() const {
        bool const json = statistics_format == statistics_format_t::json_k;
        struct named_counter_t {
            char const *json_name, *human_name;
            std::uint64_t ucall_event_loop_statistics_t::* counter;
        };
        static constexpr named_counter_t counters_k[] {
            {"polls", "polls", &ucall_event_loop_statistics_t::polls},
            {"empty_polls", "empty polls", &ucall_event_loop_statistics_t::empty_polls},
            {"kernel_enters", "kernel enters", &ucall_event_loop_statistics_t::kernel_enters},
            {"submissions", "submissions", &ucall_event_loop_statistics_t::submissions},
            {"completions", "completions", &ucall_event_loop_statistics_t::completions},
            {"kernel_entries", "kernel entries", &ucall_event_loop_statistics_t::kernel_entries},
            {"cancellations", "cancellations", &ucall_event_loop_statistics_t::cancellations},
            {"accepts", "accepts", &ucall_event_loop_statistics_t::accepts},
            {"requests", "requests", &ucall_event_loop_statistics_t::requests},
            {"receive_rearms", "receive re-arms", &ucall_event_loop_statistics_t::receive_rearms},
            {"bytes_received", "bytes received", &ucall_event_loop_statistics_t::bytes_received},
            {"bytes_sent", "bytes sent", &ucall_event_loop_statistics_t::bytes_sent},
            {"bytes_copied", "bytes copied", &ucall_event_loop_statistics_t::bytes_copied},
            {"zero_copy_sends", "zero-copy sends", &ucall_event_loop_statistics_t::zero_copy_sends},
            {"zero_copy_fallbacks", "zero-copy fallbacks", &ucall_event_loop_statistics_t::zero_copy_fallbacks},
            {"copying_sends", "copying sends", &ucall_event_loop_statistics_t::copying_sends},
            {"file_reads_asynchronous", "asynchronous file reads",
             &ucall_event_loop_statistics_t::file_reads_asynchronous},
            {"file_reads_blocking", "blocking file reads", &ucall_event_loop_statistics_t::file_reads_blocking},
            {"bytes_read", "bytes read", &ucall_event_loop_statistics_t::bytes_read},
            {"file_window_overlaps", "file window overlaps", &ucall_event_loop_statistics_t::file_window_overlaps},
            {"linger_resets", "linger resets", &ucall_event_loop_statistics_t::linger_resets},
            {"ready_passes", "ready passes", &ucall_event_loop_statistics_t::ready_passes},
            {"replied_dequeues", "replied dequeues", &ucall_event_loop_statistics_t::replied_dequeues},
            {"refused_requests", "refused requests", &ucall_event_loop_statistics_t::refused_requests},
            {"handshake_failures", "handshake failures", &ucall_event_loop_statistics_t::handshake_failures},
            {"authorizer_refusals", "authorizer refusals", &ucall_event_loop_statistics_t::authorizer_refusals},
            {"shed_connections", "shed connections", &ucall_event_loop_statistics_t::shed_connections},
            {"windows_unpinned", "unpinned windows", &ucall_event_loop_statistics_t::windows_unpinned},
            {"receive_slices_refused", "refused receive slices",
             &ucall_event_loop_statistics_t::receive_slices_refused},
            {"receive_pool_buffers", "receive pool buffers", &ucall_event_loop_statistics_t::receive_pool_buffers},
            {"receive_pool_buffer_bytes", "receive pool buffer bytes",
             &ucall_event_loop_statistics_t::receive_pool_buffer_bytes}};
        // Each row composes on the stack and leaves in one write, so no log line splits a row.
        fmt::basic_memory_buffer<char, 4096> row;
        auto emit = [&] {
            std::fwrite(row.data(), 1, row.size(), stdout);
            row.clear();
        };
        if (json) fmt::format_to(fmt::appender(row), "{{\"event_loops\":[");
        for (std::size_t index = 0; index != event_loops; ++index) {
            auto [counters, counters_status] = server.event_loop_statistics(index);
            if (!succeeded(counters_status)) return false;
            if (json) fmt::format_to(fmt::appender(row), "{}{{\"index\":{}", index ? "," : "", index);
            else fmt::format_to(fmt::appender(row), "Event loop {}:", index);
            char const* separator = " ";
            for (named_counter_t const& named : counters_k) {
                if (json) fmt::format_to(fmt::appender(row), ",\"{}\":{}", named.json_name, counters.*named.counter);
                else
                    fmt::format_to(fmt::appender(row), "{}{} {}", separator, counters.*named.counter, named.human_name);
                separator = ", ";
            }
            fmt::format_to(fmt::appender(row), "{}", json ? "}" : "\n");
            emit();
        }
        if (json) fmt::format_to(fmt::appender(row), "],\"batch_endpoints\":[");
        for (std::size_t index = 0; index != batch_endpoints.size(); ++index) {
            auto [counters, counters_status] = batch_endpoints[index].statistics();
            if (!succeeded(counters_status)) return false;
            if (json)
                fmt::format_to(fmt::appender(row),
                               "{}{{\"index\":{},\"batches\":{},\"requests\":{},\"filled_batches\":{}," //
                               "\"ready_batches\":{},\"expired_batches\":{}}}",
                               index ? "," : "", index, counters.batches, counters.requests, counters.filled_batches,
                               counters.ready_batches, counters.expired_batches);
            else
                fmt::format_to(fmt::appender(row),
                               "Batch endpoint {}: {} batches, {} requests, {} filled, {} ready, {} expired\n", index,
                               counters.batches, counters.requests, counters.filled_batches, counters.ready_batches,
                               counters.expired_batches);
            emit();
        }
        process_clocks_t const spent = process_clocks_t::now() - serving;
        if (json)
            fmt::format_to(fmt::appender(row), "],\"wall_seconds\":{:.6f},\"cpu_seconds\":{:.6f}}}\n",
                           spent.wall_seconds, spent.cpu_seconds);
        else
            fmt::format_to(fmt::appender(row), "Served for {:.6f} s using {:.6f} s of CPU\n", spent.wall_seconds,
                           spent.cpu_seconds);
        emit();
        return true;
    }
    ~server_t() {
        server.stop();
        if (generation) fu_pool_unsafe_join(pool, generation);
        fu_pool_delete(pool);
    }
};

} // namespace unum::ucall::tools
