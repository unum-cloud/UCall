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
#include <array>
#include <charconv>
#include <chrono>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <forkunion.h>

#include "ucall/ucall.h"

namespace unum::ucall::bench {

using clock_t = std::chrono::steady_clock;

struct settings_t {
    std::vector<std::string> urls;
    std::size_t requests {}, warmup_requests {}, connections = 64, in_flight = 64, threads = 1;
    std::size_t bytes = 1024;
    ucall_io_backend_t backend = ucall_io_backend_automatic_k;
    ucall_cpu_class_t cpu_class = ucall_cpu_class_unknown_k;
    ucall_verb_t verb = ucall_verb_post_k;
    bool verify_echo = false, reorder = false, close = false;
};

static void usage(char const* binary) {
    std::printf("Usage: %s --requests count [options]\n"
                "  --url URL            External HTTP service; repeat for multiple origins\n"
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
                "  --reorder            Paired retained replies at the supplied /echo/reordered URLs\n"
                "  --close              Request Connection: close for connection churn\n"
                "  --help               Print this usage\n",
                binary);
}

static bool parse(int argc, char** argv, settings_t& settings) {
    for (int i = 1; i != argc; ++i) {
        std::string_view flag = argv[i];
        if (flag == "--verify-echo" || flag == "--reorder" || flag == "--close") {
            if (flag == "--verify-echo") settings.verify_echo = true;
            else if (flag == "--reorder") settings.reorder = settings.verify_echo = true;
            else settings.close = true;
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
            settings.urls.emplace_back(value);
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
    if (settings.urls.empty())
        settings.urls.emplace_back(settings.reorder ? "http://127.0.0.1:8545/echo/reordered"
                                                    : "http://127.0.0.1:8545/echo");
    if (settings.reorder &&
        (settings.requests % 2 || settings.warmup_requests % 2 || settings.verb != ucall_verb_post_k)) {
        std::fputs("Paired replies require POST and even measured/warmup request counts\n", stderr);
        return false;
    }
    return true;
}

static std::uint64_t now_nanoseconds() noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(clock_t::now().time_since_epoch()).count());
}

static ucall_bytes_view_t view(std::string_view text) noexcept {
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
    std::size_t group {}, member {}, sequence {};
    char pair_header[sizeof("x-ucall-pair: ::") + std::numeric_limits<std::uint64_t>::digits10 +
                     2 * (std::numeric_limits<std::size_t>::digits10 + 1) + 1] {};
    std::array<ucall_bytes_view_t, 3> headers {};
    std::string_view pair {};
};
struct group_t {
    std::array<slot_t, 2> slots;
    std::size_t origin {}, outstanding {};
};
struct sample_t {
    std::uint64_t nanoseconds {};
    bool successful {};
};
struct origin_result_t {
    std::size_t issued {}, completed {}, successful {}, failures {}, response_bytes {}, rejected {}, byte_checks {},
        reordered {};
    std::size_t largest_sequence {};
    std::uint64_t first_completed {}, last_completed {}, latency_max {};
    long double latency_sum {};
};
struct origin_t {
    std::size_t requests {}, warmup_requests {};
    std::span<sample_t> samples;
    origin_result_t result;
};
struct worker_t {
    ucall_client_t client {};
    ucall_client_config_t resolved {};
    std::vector<group_t> groups;
    std::vector<ucall_completed_call_t> completed;
    std::vector<origin_t> origins;
    std::uint64_t run_id {};
    std::size_t index {}, capacity {}, successful {}, failures {}, response_bytes {}, rejected {};
    char const* first_error {};
    ucall_http_status_t first_http_status {};
    ucall_status_t first_rejection {};
    bool ready {}, valid {};

    bool phase(settings_t const& settings, std::string const& payload, bool warmup) {
        successful = failures = response_bytes = rejected = 0;
        first_error = nullptr;
        first_rejection = {};
        for (auto& origin : origins) origin.result = {};
        auto width = settings.reorder ? 2u : 1u;
        std::size_t outstanding = 0;
        auto fill = [&](group_t& group) {
            auto& origin = origins[group.origin];
            auto count = warmup ? origin.warmup_requests : origin.requests;
            while (origin.result.issued != count && !group.outstanding) {
                auto pair = origin.result.issued / width;
                for (std::size_t member = 0; member != width; ++member) {
                    auto& slot = group.slots[member];
                    slot.sequence = origin.result.issued++;
                    ucall_outcome_t outcome {};
                    ucall_client_call_t call {};
                    call.client = client;
                    call.outcome = &outcome;
                    call.url = view(settings.urls[group.origin]);
                    call.verb = settings.verb;
                    call.body = view(payload);
                    call.context = &slot;
                    std::size_t headers = 0;
                    if (settings.reorder) {
                        auto length = std::snprintf(slot.pair_header, sizeof(slot.pair_header),
                                                    "x-ucall-pair: %llu:%zu:%zu",
                                                    static_cast<unsigned long long>(run_id + warmup), index,
                                                    pair * origins.size() + group.origin);
                        slot.headers[headers++] = view({slot.pair_header, static_cast<std::size_t>(length)});
                        slot.pair = {slot.pair_header + sizeof("x-ucall-pair: ") - 1,
                                     static_cast<std::size_t>(length) - (sizeof("x-ucall-pair: ") - 1)};
                        slot.headers[headers++] = view(member ? "x-ucall-member: 1" : "x-ucall-member: 0");
                    }
                    if (settings.close) slot.headers[headers++] = view("connection: close");
                    call.headers = slot.headers.data();
                    call.headers_count = headers;
                    slot.started_nanoseconds = now_nanoseconds();
                    ucall_client_call(&call);
                    if (outcome.status == ucall_status_success_k) {
                        ++outstanding;
                        ++group.outstanding;
                    }
                    else {
                        ++rejected;
                        ++origin.result.rejected;
                        if (!first_rejection) first_rejection = outcome.status;
                    }
                }
            }
        };
        for (auto& group : groups) fill(group);
        while (outstanding) {
            ucall_outcome_t outcome {};
            std::size_t count {};
            ucall_client_take_completed_t take {client,           &outcome, completed.data(),
                                                completed.size(), &count,   resolved.request_timeout_microseconds};
            ucall_client_take_completed(&take);
            auto completed_at = now_nanoseconds();
            if (!succeeded(outcome, "Completion retrieval")) return false;
            for (std::size_t i = 0; i != count; ++i) {
                auto const& completion = completed[i];
                auto& slot = *static_cast<slot_t*>(completion.context);
                auto& group = groups[slot.group];
                auto& origin = origins[group.origin];
                auto& result = origin.result;
                --outstanding;
                --group.outstanding;
                ++result.completed;
                if (!result.first_completed) result.first_completed = completed_at;
                result.last_completed = completed_at;
                auto elapsed = completed_at - slot.started_nanoseconds;
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
                        else if (settings.verify_echo) {
                            ++result.byte_checks;
                            if (body.length != payload.size() ||
                                (body.length && std::memcmp(body.data, payload.data(), body.length)))
                                error = "response body differs from request";
                        }
                        bytes = body.length;
                    }
                    if (!error && settings.reorder) {
                        for (auto name : {"x-ucall-pair", "x-ucall-member"}) {
                            ucall_bytes_view_t value {};
                            ucall_received_http_response_header_t get {client, &outcome, completion.response,
                                                                       view(name), &value};
                            ucall_received_http_response_header(&get);
                            auto expected = std::string_view {name} == "x-ucall-pair" ? slot.pair
                                                                                      : (slot.member ? "1" : "0");
                            if (outcome.status != ucall_status_success_k || value.length != expected.size() ||
                                (value.length && std::memcmp(value.data, expected.data(), value.length)))
                                error = "response pair identifier differs from request";
                        }
                    }
                }
                if (error) {
                    ++failures;
                    ++result.failures;
                    if (!first_error) {
                        first_error = error;
                        first_http_status = http_status;
                    }
                }
                else {
                    ++successful;
                    ++result.successful;
                    response_bytes += bytes;
                    result.response_bytes += bytes;
                    result.latency_sum += elapsed;
                    result.latency_max = std::max(result.latency_max, elapsed);
                    if (slot.sequence < result.largest_sequence) ++result.reordered;
                    result.largest_sequence = std::max(result.largest_sequence, slot.sequence);
                    if (!warmup) origin.samples[slot.sequence] = {elapsed, true};
                }
                ucall_received_http_response_free(completion.response);
                if (!group.outstanding) fill(group);
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
        auto width = run.settings.reorder ? 2u : 1u;
        auto connection_groups = run.settings.connections / width;
        config.max_concurrent_connections = (connection_groups / count + (index < connection_groups % count)) * width +
                                            (index == 0 ? run.settings.connections % width : 0);
        config.max_concurrent_calls = worker.capacity;
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
    auto width = settings.reorder ? 2u : 1u;
    auto clients = std::min({settings.threads, settings.connections / settings.urls.size() / width,
                             settings.in_flight / settings.urls.size() / width});
    if (!clients) {
        std::fprintf(stderr, "Each active origin needs at least %u connections and in-flight slots per worker\n",
                     width);
        return 1;
    }
    resources.workers.resize(clients);
    std::vector<sample_t> samples(settings.requests);
    std::size_t offset = 0, capacity = 0;
    auto run_id = now_nanoseconds();
    auto group_budget = settings.in_flight / width;
    if (settings.reorder) group_budget = std::min(group_budget, settings.connections / width);
    for (std::size_t i = 0; i != clients; ++i) {
        auto& worker = resources.workers[i];
        worker.index = i;
        worker.run_id = run_id;
        auto groups = group_budget / clients + (i < group_budget % clients);
        worker.groups.resize(groups);
        worker.capacity = groups * width;
        capacity += worker.capacity;
        worker.completed.resize(worker.capacity);
        worker.origins.resize(settings.urls.size());
        for (std::size_t origin_index = 0; origin_index != settings.urls.size(); ++origin_index) {
            auto& origin = worker.origins[origin_index];
            auto requests = settings.requests / width / settings.urls.size() +
                            (origin_index < settings.requests / width % settings.urls.size());
            auto warmup = settings.warmup_requests / width / settings.urls.size() +
                          (origin_index < settings.warmup_requests / width % settings.urls.size());
            origin.requests = (requests / clients + (i < requests % clients)) * width;
            origin.warmup_requests = (warmup / clients + (i < warmup % clients)) * width;
            origin.samples = std::span {samples}.subspan(offset, origin.requests);
            offset += origin.requests;
        }
        for (std::size_t group_index = 0; group_index != groups; ++group_index) {
            auto& group = worker.groups[group_index];
            group.origin = group_index % settings.urls.size();
            for (std::size_t member = 0; member != width; ++member) {
                group.slots[member].group = group_index;
                group.slots[member].member = member;
            }
        }
    }
    fu_topology_t topology {};
    auto status = fu_topology_new(&topology);
    if (status == fu_success_k) status = fu_pool_new("ucall-bench", fu_capabilities_all_k, &resources.pool);
    if (status == fu_success_k)
        status = fu_pool_spawn(topology, resources.pool, settings.threads, fu_caller_inclusive_k);
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
    auto begin_nanoseconds = now_nanoseconds();
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
    std::printf("Configuration\n  Origins: %zu\n  ForkUnion workers: %zu\n  Clients: %zu\n"
                "  Workload: %s\n  Connection reuse: %s\n  Connections: %zu\n  In-flight calls: %zu\n"
                "  Request body: %zu bytes\n  Warmup requests: %zu\n  Measured requests: %zu\n"
                "Exchanges\n  Successful: %zu\n  Failures: %zu\n  Rejected: %zu\n  Elapsed: %.6f s\n"
                "  Throughput: %.1f requests/s\n  Response body throughput: %.3f GB/s\n",
                settings.urls.size(), settings.threads, clients, settings.reorder ? "paired replies" : "ordinary",
                settings.close ? "close after response" : "keep-alive", settings.connections, capacity, settings.bytes,
                settings.warmup_requests, settings.requests, successful, failures, rejected, seconds,
                successful / seconds, response_bytes / seconds / 1e9);
    for (std::size_t origin_index = 0; origin_index != settings.urls.size(); ++origin_index) {
        origin_result_t total;
        for (auto const& worker : workers) {
            auto const& result = worker.origins[origin_index].result;
            total.issued += result.issued;
            total.completed += result.completed;
            total.successful += result.successful;
            total.failures += result.failures;
            total.rejected += result.rejected;
            total.response_bytes += result.response_bytes;
            total.byte_checks += result.byte_checks;
            total.reordered += result.reordered;
            total.latency_sum += result.latency_sum;
            total.latency_max = std::max(total.latency_max, result.latency_max);
            if (result.first_completed && (!total.first_completed || result.first_completed < total.first_completed))
                total.first_completed = result.first_completed;
            total.last_completed = std::max(total.last_completed, result.last_completed);
        }
        std::printf("  Origin %zu %s: issued %zu, completed %zu, successful %zu, failed %zu, rejected %zu, byte checks "
                    "%zu, reordered %zu, bytes %zu\n"
                    "    Mean latency: %.2f us, max: %.2f us, first/last completion: %.3f/%.3f ms\n",
                    origin_index, settings.urls[origin_index].c_str(), total.issued, total.completed, total.successful,
                    total.failures, total.rejected, total.byte_checks, total.reordered, total.response_bytes,
                    total.successful ? static_cast<double>(total.latency_sum / total.successful / 1e3L) : 0,
                    total.latency_max / 1e3,
                    total.first_completed ? (total.first_completed - begin_nanoseconds) / 1e6 : 0,
                    total.last_completed ? (total.last_completed - begin_nanoseconds) / 1e6 : 0);
    }
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
