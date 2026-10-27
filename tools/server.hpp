/**
 *  @file tools/server.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Shared CLI, caller-owned polling, and graceful shutdown for the native services.
 */
#pragma once

#include <csignal> // `std::signal`, `SIGINT`, `SIGTERM`
#include <cstddef> // `std::size_t`
#include <cstdint> // `std::uint16_t`, `std::uint64_t`
#include <cstdio>  // `std::printf`, `std::fprintf`, `std::snprintf`

#include <algorithm>        // `std::min`, `std::find_if`
#include <atomic>           // `std::atomic`
#include <chrono>           // `std::chrono::milliseconds`
#include <initializer_list> // `std::initializer_list`
#include <limits>           // `std::numeric_limits`
#include <string_view>      // `std::string_view`
#include <thread>           // `std::this_thread::sleep_for`
#include <vector>           // `std::vector`

#include <forkunion.h> // `fu_pool_t`, `fu_pool_unsafe_for_threads`

#include "ucall/types.hpp" // `bytes_view`, `st::status_t`

#include "arguments.hpp" // `parse_count`, `parse_key`, `admit_any_peer`

namespace unum::ucall::tools {

/** Set by SIGINT, SIGTERM or a failing loop; the main thread checks it every 100 ms. */
inline std::atomic<bool> stop_requested {false};

inline void request_stop(int) noexcept { stop_requested.store(true, std::memory_order_relaxed); }

/** Answers @p request with an error @p status and @p message as its body. */
inline void reply_error(ucall_server_t server, ucall_received_http_request_t request, ucall_http_status_t status,
                        std::string_view message) noexcept {
    ucall_outcome_t outcome {};
    ucall_server_reply_error_t reply {server, &outcome, request, status, bytes_view(message)};
    ucall_server_reply_error(&reply);
}

/** Answers a failed storage @p status, 409 for a conflict a retry can overcome and 503 for
 *  the rest; true once it replied. */
inline bool reply_error(ucall_server_t server, ucall_received_http_request_t request, st::status_t status) noexcept {
    if (st::succeeded(status)) return false;
    if (st::conflicted(status))
        reply_error(server, request, ucall_http_status_conflict_k, "Concurrent transaction; read and retry\n");
    else reply_error(server, request, ucall_http_status_service_unavailable_k, "Storage unavailable\n");
    return true;
}

/** Human-readable lines, or one JSON object, for the counters printed at exit. */
enum class statistics_format_t { human_k, json_k };

/** A count only one service accepts, such as the scoring matrix's rows. */
struct count_flag_t {
    std::string_view name, help;
    std::size_t& value;
};

struct server_t {
    fu_pool_t pool {};
    fu_generation_t generation {};
    std::vector<ucall_outcome_t> outcomes;
    ucall_server_t server {};
    std::size_t event_loops {};
    std::vector<ucall_http_batch_endpoint_t> batch_endpoints;                      // Each gets its own drain thread.
    std::size_t min_batch_size {}, max_batch_size {}, max_latency_microseconds {}; // Zeros take the defaults.
    statistics_format_t statistics_format {statistics_format_t::human_k};
    ucall_network_interface_t network_interface {};
    ucall_noise_key_t private_key {};
    char address[sizeof("[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:65535")] {};

    static bool succeeded(ucall_outcome_t const& outcome) {
        if (outcome.status == ucall_status_success_k) return true;
        std::fprintf(stderr, "%s%s%s\n", ucall_status_name(outcome.status), outcome.message ? ": " : "",
                     outcome.message ? outcome.message : "");
        return false;
    }
    static void health(ucall_received_http_request_t request, void* context) {
        ucall_outcome_t outcome {};
        ucall_server_reply_content_t reply {*static_cast<ucall_server_t*>(context),
                                            &outcome,
                                            request,
                                            nullptr,
                                            0,
                                            bytes_view("ready\n"),
                                            ucall_http_status_ok_k};
        ucall_server_reply_content(&reply);
    }
    int init(int argc, char** argv, std::initializer_list<count_flag_t> counts = {}) {
        ucall_server_config_t config {};
        config.cpu_class = ucall_cpu_class_serial_k;
        std::size_t threads = 1;
        std::size_t connections = 1024;
        std::size_t pipelined_requests = 1;
        std::size_t port = 8545;
        std::string_view host {"127.0.0.1"};
        std::string_view key {};
        for (int i = 1; i != argc; ++i) {
            std::string_view flag {argv[i]};
            if (flag == "--help") {
                std::printf(
                    "Usage: %s [--backend name] [--cpu-class name] [--threads N] [--host IP] [--port N]\n"
                    "       [--connections N] [--pipelined-requests N] [--security none|xx|ik] [--key HEX]\n"
                    "       [--batch-min N] [--batch-max N] [--batch-latency-us N] [--stats human|json]\n"
                    "Backend defaults to automatic, CPU class to serial, and threads to 1.\n"
                    "The host defaults to 127.0.0.1 and the port to 8545; pass 0.0.0.0 or :: to accept every NIC.\n"
                    "Admission defaults to 1024 connections of 1 request each.\n"
                    "Noise needs the 64-digit hex server private key; without --key one is generated.\n"
                    "Either way the public key is printed; XX admits every client key.\n"
                    "Batch budgets default to the library's 1, 32, and 10000 microseconds.\n"
                    "--stats json prints every loop's and batch endpoint's counters as one JSON object.\n",
                    argv[0]);
                for (count_flag_t const& count : counts)
                    std::printf("%.*s N: %.*s (%zu)\n", static_cast<int>(count.name.size()), count.name.data(),
                                static_cast<int>(count.help.size()), count.help.data(), count.value);
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
            ucall_bytes_view_t const name = bytes_view(value);
            std::initializer_list<count_flag_t>::iterator const extra = std::find_if(
                counts.begin(), counts.end(), [&](count_flag_t const& count) { return count.name == flag; });
            if (flag == "--port") valid = parse_count(value, port) && port <= std::numeric_limits<std::uint16_t>::max();
            else if (flag == "--host") {
                host = value;
                valid = !value.empty() && value.size() <= sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255") - 1;
            }
            else if (flag == "--threads") valid = parse_count(value, threads, 1);
            else if (flag == "--connections") valid = parse_count(value, connections, 1);
            else if (flag == "--pipelined-requests") valid = parse_count(value, pipelined_requests, 1);
            else if (flag == "--batch-min") valid = parse_count(value, min_batch_size, 1);
            else if (flag == "--batch-max") valid = parse_count(value, max_batch_size, 1);
            else if (flag == "--batch-latency-us") valid = parse_count(value, max_latency_microseconds, 1);
            else if (flag == "--key") {
                key = value;
                valid = parse_key(value, private_key);
            }
            else if (flag == "--security") {
                valid = value == "none" || value == "xx" || value == "ik";
                network_interface.security_mode = value == "xx"   ? ucall_security_mode_noise_xx_k
                                                  : value == "ik" ? ucall_security_mode_noise_ik_k
                                                                  : ucall_security_mode_none_k;
            }
            else if (flag == "--stats") {
                valid = value == "human" || value == "json";
                statistics_format = value == "json" ? statistics_format_t::json_k : statistics_format_t::human_k;
            }
            else if (flag == "--backend") {
                config.backend = ucall_io_backend_from_name(name);
                valid = value == ucall_io_backend_name(config.backend);
            }
            else if (flag == "--cpu-class") {
                config.cpu_class = ucall_cpu_class_from_name(name);
                valid = value == ucall_cpu_class_name(config.cpu_class);
            }
            else if (extra != counts.end()) valid = parse_count(value, extra->value);
            if (!valid) {
                std::fprintf(stderr, "Invalid argument: %.*s=%.*s\n", static_cast<int>(flag.size()), flag.data(),
                             static_cast<int>(value.size()), value.data());
                return -1;
            }
        }
        if (network_interface.security_mode != ucall_security_mode_none_k) {
            ucall_noise_key_t public_key {};
            ucall_outcome_t outcome {};
            if (!key.empty()) {
                ucall_noise_key_derive_t derive {&outcome, &private_key, &public_key};
                ucall_noise_key_derive(&derive);
            }
            else {
                ucall_noise_key_generate_t generate {&outcome, &private_key, &public_key};
                ucall_noise_key_generate(&generate);
            }
            if (outcome.status != ucall_status_success_k) {
                std::fprintf(stderr, "The server key is unavailable: %s\n", outcome.message);
                return -1;
            }
            std::printf("Server public key: ");
            for (ucall_byte_t byte : public_key) std::printf("%02x", byte);
            std::printf("\n");
            network_interface.noise_private_key = &private_key;
            if (network_interface.security_mode == ucall_security_mode_noise_xx_k)
                network_interface.peer_authorizer = admit_any_peer;
        }
        std::signal(SIGINT, request_stop);
        std::signal(SIGTERM, request_stop);
        // IPv6 literals take brackets, as the server prints its own bound addresses.
        bool const bracketed = host.find(':') != host.npos;
        std::snprintf(address, sizeof(address), bracketed ? "[%.*s]:%zu" : "%.*s:%zu", static_cast<int>(host.size()),
                      host.data(), port);
        network_interface.address = bytes_view(address);
        network_interface.max_concurrent_connections = connections;
        network_interface.max_pipelined_requests = pipelined_requests;
        network_interface.event_loops = std::min(threads, connections);
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
        ucall_outcome_t outcome {};
        ucall_server_config_t resolved {};
        ucall_server_init_t init {&server, &outcome, &config, &resolved};
        ucall_server_init(&init);
        if (!succeeded(outcome)) return -1;
        if (!add_endpoint("/health", ucall_verb_get_k, health, &server)) return -1;
        event_loops = resolved.interfaces[0].event_loops;
        std::string_view const bound = text_view(resolved.interfaces[0].address);
        std::printf("Listening on %.*s using %s, %s, %zu application-owned serving loops\n",
                    static_cast<int>(bound.size()), bound.data(), ucall_io_backend_name(resolved.backend),
                    ucall_cpu_class_name(resolved.cpu_class), event_loops);
        std::fflush(stdout); // Scripts read the public key and the address before the server exits.
        return 0;
    }

    /** Registers an individual endpoint, answered on the polling loop that parsed each request. */
    bool add_endpoint(std::string_view uri_template, ucall_verb_t verb, ucall_received_http_request_callback_t callback,
                      void* context) {
        ucall_outcome_t outcome {};
        ucall_server_add_http_endpoint_t add {server, &outcome, bytes_view(uri_template), verb, callback, context};
        ucall_server_add_http_endpoint(&add);
        return succeeded(outcome);
    }

    /** Registers a batch endpoint under the command line's budgets, drained by its own thread. */
    bool add_batch_endpoint(std::string_view uri_template, ucall_verb_t verb,
                            ucall_received_http_batch_callback_t callback, void* context) {
        ucall_outcome_t outcome {};
        ucall_server_add_http_batch_endpoint_t add {server,
                                                    &outcome,
                                                    bytes_view(uri_template),
                                                    verb,
                                                    callback,
                                                    context,
                                                    min_batch_size,
                                                    max_batch_size,
                                                    max_latency_microseconds,
                                                    &batch_endpoints.emplace_back()};
        ucall_server_add_http_batch_endpoint(&add);
        return succeeded(outcome);
    }
    static void serve(void* context, std::size_t index, std::size_t) {
        server_t& application = *static_cast<server_t*>(context);
        ucall_outcome_t& outcome = application.outcomes[index];
        if (index < application.event_loops) {
            ucall_server_take_calls_t serving {application.server, &outcome, index};
            ucall_server_take_calls(&serving);
        }
        else {
            ucall_http_batch_endpoint_t const endpoint = application.batch_endpoints[index - application.event_loops];
            ucall_server_take_batches_t draining {application.server, &outcome, endpoint};
            ucall_server_take_batches(&draining);
        }
        if (outcome.status != ucall_status_success_k) stop_requested.store(true, std::memory_order_relaxed);
    }
    int run() {
        std::size_t const threads = event_loops + batch_endpoints.size();
        outcomes.resize(threads);
        fu_topology_t topology {};
        fu_status_t status = fu_topology_new(&topology);
        if (status == fu_success_k) status = fu_pool_new("ucall-server", fu_capabilities_all_k, &pool);
        if (status == fu_success_k) status = fu_pool_spawn(topology, pool, threads, fu_caller_exclusive_k);
        if (topology) fu_topology_delete(topology);
        if (status != fu_success_k) {
            std::fprintf(stderr, "ForkUnion initialization failed: %d\n", static_cast<int>(status));
            return 1;
        }
        if (fu_pool_unsafe_for_threads(pool, serve, this, &generation) != fu_success_k) return 1;
        while (!stop_requested.load(std::memory_order_relaxed))
            std::this_thread::sleep_for(std::chrono::milliseconds {100});
        ucall_server_stop(server);
        fu_pool_unsafe_join(pool, generation);
        int result = 0;
        for (ucall_outcome_t const& outcome : outcomes)
            if (!succeeded(outcome)) result = 1;
        return report() ? result : 1;
    }

    /** Prints the counters of every loop and batch endpoint. */
    bool report() const {
        bool const json = statistics_format == statistics_format_t::json_k;
        auto number = [](std::uint64_t value) { return static_cast<unsigned long long>(value); };
        ucall_outcome_t outcome {};
        if (json) std::printf("{\"event_loops\":[");
        for (std::size_t index = 0; index != event_loops; ++index) {
            ucall_event_loop_statistics_t counters {};
            ucall_server_event_loop_statistics_t query {server, &outcome, index, &counters};
            ucall_server_event_loop_statistics(&query);
            if (!succeeded(outcome)) return false;
            std::printf(json ? "%s{\"index\":%zu,\"requests\":%llu,\"accepts\":%llu,\"polls\":%llu,"
                               "\"empty_polls\":%llu,\"kernel_enters\":%llu,\"submissions\":%llu,"
                               "\"completions\":%llu,\"cancellations\":%llu,\"receive_rearms\":%llu,"
                               "\"bytes_received\":%llu,\"bytes_sent\":%llu,\"bytes_copied\":%llu,"
                               "\"zero_copy_sends\":%llu,\"zero_copy_fallbacks\":%llu,\"refused_requests\":%llu}"
                             : "%sEvent loop %zu: %llu requests, %llu accepts, %llu polls, %llu empty polls, "
                               "%llu kernel enters, %llu submissions, %llu completions, %llu cancellations, "
                               "%llu receive re-arms, %llu bytes received, %llu bytes sent, %llu bytes copied, "
                               "%llu zero-copy sends, %llu zero-copy fallbacks, %llu refused requests\n",
                        json && index ? "," : "", index, number(counters.requests), number(counters.accepts),
                        number(counters.polls), number(counters.empty_polls), number(counters.kernel_enters),
                        number(counters.submissions), number(counters.completions), number(counters.cancellations),
                        number(counters.receive_rearms), number(counters.bytes_received), number(counters.bytes_sent),
                        number(counters.bytes_copied), number(counters.zero_copy_sends),
                        number(counters.zero_copy_fallbacks), number(counters.refused_requests));
        }
        if (json) std::printf("],\"batch_endpoints\":[");
        for (std::size_t index = 0; index != batch_endpoints.size(); ++index) {
            ucall_batch_endpoint_statistics_t counters {};
            ucall_server_batch_endpoint_statistics_t query {server, &outcome, batch_endpoints[index], &counters};
            ucall_server_batch_endpoint_statistics(&query);
            if (!succeeded(outcome)) return false;
            std::printf(json ? "%s{\"index\":%zu,\"batches\":%llu,\"requests\":%llu,\"filled_batches\":%llu,"
                               "\"ready_batches\":%llu,\"expired_batches\":%llu}"
                             : "%sBatch endpoint %zu: %llu batches, %llu requests, %llu filled, %llu ready, "
                               "%llu expired\n",
                        json && index ? "," : "", index, number(counters.batches), number(counters.requests),
                        number(counters.filled_batches), number(counters.ready_batches),
                        number(counters.expired_batches));
        }
        if (json) std::printf("]}\n");
        return true;
    }
    ~server_t() {
        ucall_server_stop(server);
        if (generation) fu_pool_unsafe_join(pool, generation);
        fu_pool_delete(pool);
        ucall_server_free(server);
    }
};

} // namespace unum::ucall::tools
