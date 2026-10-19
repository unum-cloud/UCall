/**
 *  @file bench/http.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Fixed-count HTTP exchanges driven by application-owned ForkUnion workers.
 */
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <forkunion.h>

#include "ucall/ucall.h"

namespace unum::ucall::bench {

using clock_t = std::chrono::steady_clock;

struct settings_t {
    std::string url = "http://127.0.0.1:8545/echo";
    std::size_t requests {}, warmup_requests {}, connections = 64, in_flight = 64, threads = 1;
    std::size_t bytes = 1024;
    ucall_io_backend_t backend = ucall_io_backend_automatic_k;
    ucall_cpu_class_t cpu_class = ucall_cpu_class_unknown_k;
    ucall_verb_t verb = ucall_verb_post_k;
    bool verify_echo = false;
};

static void usage(char const* binary) {
    std::printf("Usage: %s --requests count [options]\n"
                "  --url URL            External HTTP service (http://127.0.0.1:8545/echo)\n"
                "  --warmup-requests N   Unmeasured exchanges before the fixed-count run (0)\n"
                "  --connections N      Maximum open connections (64)\n"
                "  --in-flight N        Maximum outstanding calls across all clients (64)\n"
                "  --threads N          Application-owned ForkUnion workers (1)\n"
                "  --bytes N            Request body bytes (1024)\n"
                "  --backend name       automatic, posix, linux-epoll, linux-uring612,\n"
                "                       linux-uring700, macos-kqueue, windows-iocp\n"
                "  --cpu-class name     automatic, serial, intel-haswell, intel-skylake,\n"
                "                       intel-icelake, intel-alder, intel-sierra, aws-g2, apple-m2, aws-g5\n"
                "  --verb post|get|put  HTTP method (post)\n"
                "  --verify-echo        Require identical request and response bodies\n"
                "  --help               Print this usage\n",
                binary);
}

static bool parse(int argc, char** argv, settings_t& settings) {
    for (int i = 1; i != argc; ++i) {
        std::string_view flag = argv[i];
        if (flag == "--verify-echo") {
            settings.verify_echo = true;
            continue;
        }
        auto equal = flag.find('=');
        std::string_view value;
        if (equal != flag.npos) {
            value = flag.substr(equal + 1);
            flag = flag.substr(0, equal);
        }
        else if (i + 1 != argc) value = argv[++i];
        else {
            std::fprintf(stderr, "%.*s requires a value\n", static_cast<int>(flag.size()), flag.data());
            return false;
        }
        auto count = [&](std::size_t& destination, bool zero = false) {
            auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), destination);
            return error == std::errc {} && end == value.data() + value.size() && (zero || destination != 0);
        };
        bool valid = false;
        if (flag == "--url") {
            settings.url = value;
            valid = value.starts_with("http://");
        }
        else if (flag == "--requests") valid = count(settings.requests);
        else if (flag == "--warmup-requests") valid = count(settings.warmup_requests, true);
        else if (flag == "--connections") valid = count(settings.connections);
        else if (flag == "--in-flight") valid = count(settings.in_flight);
        else if (flag == "--threads") valid = count(settings.threads);
        else if (flag == "--bytes") valid = count(settings.bytes, true);
        else if (flag == "--verb") {
            valid = value == "post" || value == "get" || value == "put";
            settings.verb = value == "get" ? ucall_verb_get_k : value == "put" ? ucall_verb_put_k : ucall_verb_post_k;
        }
        else if (flag == "--backend") {
            for (auto backend : {ucall_io_backend_automatic_k, ucall_io_backend_posix_k, ucall_io_backend_linux_epoll_k,
                                 ucall_io_backend_linux_uring612_k, ucall_io_backend_linux_uring700_k,
                                 ucall_io_backend_macos_kqueue_k, ucall_io_backend_windows_iocp_k})
                if (value == ucall_io_backend_name(backend)) {
                    settings.backend = backend;
                    valid = true;
                    break;
                }
        }
        else if (flag == "--cpu-class") {
            valid = value == "automatic";
            if (valid) settings.cpu_class = ucall_cpu_class_unknown_k;
            for (auto cpu_class :
                 {ucall_cpu_class_serial_k, ucall_cpu_class_intel_haswell_k, ucall_cpu_class_intel_skylake_k,
                  ucall_cpu_class_intel_icelake_k, ucall_cpu_class_intel_alder_k, ucall_cpu_class_intel_sierra_k,
                  ucall_cpu_class_aws_g2_k, ucall_cpu_class_apple_m2_k, ucall_cpu_class_aws_g5_k})
                if (value == ucall_cpu_class_name(cpu_class)) {
                    settings.cpu_class = cpu_class;
                    valid = true;
                    break;
                }
        }
        if (!valid) {
            std::fprintf(stderr, "Invalid argument: %.*s=%.*s\n", static_cast<int>(flag.size()), flag.data(),
                         static_cast<int>(value.size()), value.data());
            return false;
        }
    }
    if (!settings.requests) {
        std::fputs("--requests must specify a positive fixed request count\n", stderr);
        return false;
    }
    return true;
}

static std::uint64_t now_nanoseconds() noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(clock_t::now().time_since_epoch()).count());
}

static ucall_bytes_view_t view(std::string const& text) noexcept {
    return {reinterpret_cast<ucall_byte_t const*>(text.data()), text.size()};
}

static bool succeeded(ucall_outcome_t const& outcome, char const* operation) {
    if (outcome.status == ucall_status_success_k) return true;
    std::fprintf(stderr, "%s: %s%s%s\n", operation, ucall_status_name(outcome.status), outcome.message ? ": " : "",
                 outcome.message ? outcome.message : "");
    return false;
}

struct slot_t {
    std::uint64_t started_nanoseconds {};
    std::size_t request_index {};
};

struct sample_t {
    std::uint64_t nanoseconds {};
    bool successful {};
};

struct worker_t {
    ucall_client_t client {};
    ucall_client_config_t resolved {};
    std::vector<slot_t> slots;
    std::vector<ucall_completed_call_t> completed;
    std::span<sample_t> samples;
    std::size_t requests {}, warmup_requests {}, successful {}, failures {}, response_bytes {}, rejected {};
    char const* first_error {};
    ucall_http_status_t first_http_status {};
    ucall_status_t first_rejection {};
    bool ready {}, valid {};

    bool phase(settings_t const& settings, std::string const& payload, bool warmup) {
        successful = failures = response_bytes = rejected = 0;
        first_error = nullptr;
        first_rejection = {};
        auto count = warmup ? warmup_requests : requests;
        std::size_t issued = 0, outstanding = 0;
        auto fill = [&](slot_t& slot) {
            while (issued != count) {
                slot.request_index = issued++;
                ucall_outcome_t outcome {};
                ucall_client_call_t call {};
                call.client = client;
                call.outcome = &outcome;
                call.url = view(settings.url);
                call.verb = settings.verb;
                call.body = view(payload);
                call.context = &slot;
                slot.started_nanoseconds = now_nanoseconds();
                ucall_client_call(&call);
                if (outcome.status == ucall_status_success_k) {
                    ++outstanding;
                    return;
                }
                ++rejected;
                if (!first_rejection) first_rejection = outcome.status;
            }
        };
        for (auto& slot : slots) fill(slot);
        while (outstanding) {
            ucall_outcome_t outcome {};
            std::size_t count {};
            ucall_client_take_completed_t take {};
            take.client = client;
            take.outcome = &outcome;
            take.calls = completed.data();
            take.capacity = completed.size();
            take.count = &count;
            take.timeout_microseconds = resolved.request_timeout_microseconds;
            ucall_client_take_completed(&take);
            auto completed_at = now_nanoseconds();
            if (!succeeded(outcome, "Completion retrieval")) return false;
            for (std::size_t i = 0; i != count; ++i) {
                auto const& completion = completed[i];
                auto& slot = *static_cast<slot_t*>(completion.context);
                --outstanding;
                auto status = completion.outcome.status;
                char const* error = status == ucall_status_success_k ? nullptr : ucall_status_name(status);
                ucall_http_status_t http_status {};
                std::size_t bytes {};
                if (!error) {
                    http_status = ucall_received_http_response_status(client, completion.response);
                    if (http_status < 200 || http_status >= 300) error = "unsuccessful HTTP status";
                    else {
                        ucall_bytes_view_t body {};
                        ucall_received_http_response_body_t get {client, &outcome, completion.response, &body};
                        ucall_received_http_response_body(&get);
                        if (outcome.status != ucall_status_success_k) error = "response body unavailable";
                        else if (settings.verify_echo &&
                                 (body.length != payload.size() ||
                                  (body.length && std::memcmp(body.data, payload.data(), body.length))))
                            error = "response body differs from request";
                        else bytes = body.length;
                    }
                }
                if (error) {
                    ++failures;
                    if (!first_error) {
                        first_error = error;
                        first_http_status = http_status;
                    }
                }
                else {
                    ++successful;
                    response_bytes += bytes;
                    if (!warmup) samples[slot.request_index] = {completed_at - slot.started_nanoseconds, true};
                }
                ucall_received_http_response_free(completion.response);
                fill(slot);
            }
        }
        return true;
    }
};

struct resources_t {
    fu_pool_t pool {};
    std::vector<worker_t> workers;
    static void release(void* context, std::size_t index, std::size_t) {
        auto& workers = static_cast<resources_t*>(context)->workers;
        if (index < workers.size()) ucall_client_free(workers[index].client);
    }
    ~resources_t() {
        if (pool) {
            fu_pool_for_threads(pool, release, this);
            fu_pool_delete(pool);
        }
    }
};

struct run_t {
    resources_t& resources;
    settings_t const& settings;
    std::string const& payload;
    bool warmup {};
    static void initialize(void* context, std::size_t index, std::size_t) {
        auto& run = *static_cast<run_t*>(context);
        if (index >= run.resources.workers.size()) return;
        auto& worker = run.resources.workers[index];
        auto count = run.resources.workers.size();
        ucall_client_config_t config {};
        config.max_concurrent_connections = run.settings.connections / count +
                                            (index < run.settings.connections % count);
        config.max_concurrent_calls = worker.slots.size();
        config.backend = run.settings.backend;
        config.cpu_class = run.settings.cpu_class;
        ucall_outcome_t outcome {};
        ucall_client_init_t init {&worker.client, &outcome, &config, &worker.resolved};
        ucall_client_init(&init);
        worker.ready = succeeded(outcome, "Client initialization");
    }
    static void execute(void* context, std::size_t index, std::size_t) {
        auto& run = *static_cast<run_t*>(context);
        if (index < run.resources.workers.size()) {
            auto& worker = run.resources.workers[index];
            worker.valid = worker.phase(run.settings, run.payload, run.warmup);
        }
    }
};

static int run(settings_t const& settings) {
    resources_t resources;
    auto clients = std::min({settings.threads, settings.connections, settings.in_flight});
    resources.workers.resize(clients);
    std::vector<sample_t> samples(settings.requests);
    std::size_t offset = 0;
    for (std::size_t i = 0; i != clients; ++i) {
        auto& worker = resources.workers[i];
        auto slots = settings.in_flight / clients + (i < settings.in_flight % clients);
        worker.slots.resize(slots);
        worker.completed.resize(slots);
        worker.requests = settings.requests / clients + (i < settings.requests % clients);
        worker.warmup_requests = settings.warmup_requests / clients + (i < settings.warmup_requests % clients);
        worker.samples = std::span {samples}.subspan(offset, worker.requests);
        offset += worker.requests;
    }
    fu_topology_t topology {};
    auto status = fu_topology_new(&topology);
    if (status == fu_success_k) status = fu_pool_new("ucall-bench", fu_capabilities_all_k, &resources.pool);
    if (status == fu_success_k)
        status = fu_pool_spawn(topology, resources.pool, settings.threads, fu_caller_exclusive_k);
    if (topology) fu_topology_delete(topology);
    if (status != fu_success_k) {
        std::fprintf(stderr, "ForkUnion initialization failed: %d\n", static_cast<int>(status));
        return 1;
    }
    std::string payload(settings.bytes, 'x');
    if (!payload.empty()) payload.front() = '\0';
    run_t run {resources, settings, payload};
    if (fu_pool_for_threads(resources.pool, run_t::initialize, &run) != fu_success_k) return 1;
    for (auto const& worker : resources.workers)
        if (!worker.ready) return 1;
    run.warmup = true;
    if (fu_pool_for_threads(resources.pool, run_t::execute, &run) != fu_success_k) return 1;
    for (auto const& worker : resources.workers)
        if (!worker.valid || worker.failures || worker.rejected) {
            std::fprintf(stderr, "Warmup failed: %s\n",
                         worker.first_error ? worker.first_error : ucall_status_name(worker.first_rejection));
            return 1;
        }
    run.warmup = false;
    auto begin = clock_t::now();
    if (fu_pool_for_threads(resources.pool, run_t::execute, &run) != fu_success_k) return 1;
    auto seconds = std::chrono::duration<double>(clock_t::now() - begin).count();
    auto& workers = resources.workers;
    std::size_t successful = 0, failures = 0, response_bytes = 0;
    for (std::size_t i = 0; i != workers.size(); ++i) {
        auto& worker = workers[i];
        successful += worker.successful;
        failures += worker.failures;
        response_bytes += worker.response_bytes;
        if (worker.first_error)
            std::fprintf(stderr, "Worker %zu: %s (HTTP %u)\n", i, worker.first_error, worker.first_http_status);
    }
    std::size_t rejected = 0;
    bool valid = true;
    for (auto const& worker : workers) {
        rejected += worker.rejected;
        valid &= worker.valid;
        if (worker.rejected) std::fprintf(stderr, "Rejected calls: %s\n", ucall_status_name(worker.first_rejection));
    }
    std::printf("Configuration\n  URL: %s\n  ForkUnion workers: %zu\n  Clients: %zu\n"
                "  Connections: %zu\n  In-flight calls: %zu\n"
                "  Request body: %zu bytes\n  Warmup requests: %zu\n  Measured requests: %zu\n"
                "Exchanges\n  Successful: %zu\n  Failures: %zu\n  Rejected: %zu\n  Elapsed: %.6f s\n"
                "  Throughput: %.1f requests/s\n  Response body throughput: %.3f GB/s\n",
                settings.url.c_str(), settings.threads, clients, settings.connections, settings.in_flight,
                settings.bytes, settings.warmup_requests, settings.requests, successful, failures, rejected, seconds,
                successful / seconds, response_bytes / seconds / 1e9);
    if (!successful) return 1;
    long double sum = 0;
    std::uint64_t maximum = 0;
    std::size_t index = 0;
    for (auto const sample : samples)
        if (sample.successful) {
            samples[index++] = sample;
            sum += sample.nanoseconds;
            maximum = std::max(maximum, sample.nanoseconds);
        }
    auto percentile = [&](double fraction) {
        auto rank = static_cast<std::size_t>(std::ceil(fraction * successful)) - 1;
        std::nth_element(samples.begin(), samples.begin() + rank, samples.begin() + successful,
                         [](auto left, auto right) { return left.nanoseconds < right.nanoseconds; });
        return samples[rank].nanoseconds / 1e3;
    };
    auto p50 = percentile(0.50), p95 = percentile(0.95), p99 = percentile(0.99);
    std::printf("  Latency: mean %.2f us, p50 %.2f us, p95 %.2f us, p99 %.2f us, max %.2f us\n",
                static_cast<double>(sum / successful / 1e3), p50, p95, p99, maximum / 1e3);
    for (std::size_t i = 0; i != workers.size(); ++i)
        std::printf("  Worker %zu: %s, %s, %zu successful, %zu failed\n", i,
                    ucall_io_backend_name(workers[i].resolved.backend),
                    ucall_cpu_class_name(workers[i].resolved.cpu_class), workers[i].successful, workers[i].failures);
    return !valid || failures || rejected || successful != settings.requests ? 1 : 0;
}

} // namespace unum::ucall::bench

int main(int argc, char** argv) {
    using namespace unum::ucall::bench;
    for (int i = 1; i != argc; ++i)
        if (std::string_view {argv[i]} == "--help") {
            usage(argv[0]);
            return 0;
        }
    settings_t settings;
    return parse(argc, argv, settings) ? run(settings) : 1;
}
