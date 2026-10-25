/**
 *  @file bench/http.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief HTTP exchanges from application-owned ForkUnion workers, closed-loop or at a fixed rate.
 *
 *  One table names every flag: it parses the command line, prints the usage, and reads each default
 *  from a @c UCALL_BENCH_ variable named after the flag, so @c --time-limit defaults to
 *  @c UCALL_BENCH_TIME_LIMIT and the command line overrides it.
 */
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/resource.h>
#endif // defined(_WIN32)

#include <algorithm>
#include <array>
#include <bit>
#include <bitset>
#include <charconv>
#include <chrono>
#include <limits>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <vector>

#include <forkunion.h>

#include "ucall/ucall.h"

namespace unum::ucall::bench {

using clock_t = std::chrono::steady_clock;

/** Whether each response body must equal the request body. */
enum class echo_check_t { none_k, bytes_k };

/** Whether calls go out in tagged pairs that the server answers in reverse. */
enum class reply_order_t { ordinary_k, reordered_k };

/** Whether each response closes its connection, measuring churn instead of reuse. */
enum class connection_reuse_t { keep_alive_k, close_k };

/** Whether ForkUnion pins each worker to its own core. */
enum class thread_placement_t { floating_k, pinned_k };

/** Aligned lines for people, or one JSON object per row for scripts. */
enum class output_format_t { human_k, json_k };

/** The unmeasured run that fills caches and pools, then the measured one. */
enum class phase_t { warmup_k, measured_k };

/** A quota no run reaches, for a phase bounded by its time limit alone. */
static constexpr std::size_t unlimited_k = std::numeric_limits<std::size_t>::max();

static constexpr double nanoseconds_per_second_k = std::chrono::nanoseconds(std::chrono::seconds(1)).count();
static constexpr double nanoseconds_per_millisecond_k = std::chrono::nanoseconds(std::chrono::milliseconds(1)).count();
static constexpr double nanoseconds_per_microsecond_k = std::chrono::nanoseconds(std::chrono::microseconds(1)).count();
static constexpr double bytes_per_gigabyte_k = std::giga::num;

struct settings_t {
    std::vector<std::string> urls;
    std::size_t requests {}, warmup_requests {}, connections = 64, in_flight = 64, threads = 1, bytes = 1024;
    std::size_t rate {}, pipeline_depth = 1;
    std::chrono::nanoseconds warmup {}, time_limit {};
    std::uint32_t seed = 42;
    ucall_io_backend_t backend = ucall_io_backend_automatic_k;
    ucall_cpu_class_t cpu_class = ucall_cpu_class_unknown_k;
    ucall_verb_t verb = ucall_verb_post_k;
    echo_check_t echo_check = echo_check_t::none_k;
    reply_order_t reply_order = reply_order_t::ordinary_k;
    connection_reuse_t connection_reuse = connection_reuse_t::keep_alive_k;
    thread_placement_t placement = thread_placement_t::floating_k;
    output_format_t format = output_format_t::human_k;
};

static ucall_bytes_view_t view(std::string_view text) noexcept {
    return {reinterpret_cast<ucall_byte_t const*>(text.data()), text.size()};
}

static bool parse_count(std::string_view text, std::size_t& value, std::size_t minimum = 0) noexcept {
    std::size_t parsed {};
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (error != std::errc {} || end != text.data() + text.size() || parsed < minimum) return false;
    value = parsed;
    return true;
}

/** A duration like "1s", "500ms" or "250us". */
static bool parse_duration(std::string_view text, std::chrono::nanoseconds& value) noexcept {
    std::uint32_t count {};
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), count);
    if (error != std::errc {} || end == text.data()) return false;
    auto unit = text.substr(static_cast<std::size_t>(end - text.data()));
    if (unit == "s") value = std::chrono::seconds(count);
    else if (unit == "ms") value = std::chrono::milliseconds(count);
    else if (unit == "us") value = std::chrono::microseconds(count);
    else return false;
    return true;
}

/** A switch: present, "1" or "true" select @p on, and "0" or "false" the zero enumerator. */
template <typename mode_type_>
static bool parse_switch(std::string_view text, mode_type_& value, mode_type_ on) noexcept {
    if (text.empty() || text == "1" || text == "true") value = on;
    else if (text == "0" || text == "false") value = mode_type_ {};
    else return false;
    return true;
}

/** One flag: its name, its placeholder, empty for a switch, a help line, and its destination. */
struct flag_t {
    std::string_view name, placeholder, help;
    bool (*assign)(std::string_view text, settings_t& settings) noexcept;
};

static constexpr std::array flags_k {
    flag_t {"--url", "URL", "HTTP service, repeated for several origins (http://127.0.0.1:8545/echo)",
            [](std::string_view text, settings_t& settings) noexcept {
                settings.urls.emplace_back(text);
                return text.starts_with("http://");
            }},
    flag_t {"--requests", "count", "measured exchanges, or 0 to run until --time-limit (0)",
            [](std::string_view text, settings_t& settings) noexcept { return parse_count(text, settings.requests); }},
    flag_t {
        "--time-limit", "duration", "measured interval like 10s, or 0s for --requests alone (0s)",
        [](std::string_view text, settings_t& settings) noexcept { return parse_duration(text, settings.time_limit); }},
    flag_t {"--warmup-requests", "count", "unmeasured exchanges ahead of the measured ones (0)",
            [](std::string_view text, settings_t& settings) noexcept {
                return parse_count(text, settings.warmup_requests);
            }},
    flag_t {"--warmup", "duration", "unmeasured interval like 1s, ending early at --warmup-requests (0s)",
            [](std::string_view text, settings_t& settings) noexcept { return parse_duration(text, settings.warmup); }},
    flag_t {"--rate", "count", "open-loop arrivals per second across workers, or 0 for closed-loop (0)",
            [](std::string_view text, settings_t& settings) noexcept { return parse_count(text, settings.rate); }},
    flag_t {"--connections", "count", "maximum open connections (64)",
            [](std::string_view text, settings_t& settings) noexcept {
                return parse_count(text, settings.connections, 1);
            }},
    flag_t {
        "--in-flight", "count", "maximum outstanding calls across all clients (64)",
        [](std::string_view text, settings_t& settings) noexcept { return parse_count(text, settings.in_flight, 1); }},
    flag_t {"--pipeline-depth", "count", "calls one connection carries before awaiting a response (1)",
            [](std::string_view text, settings_t& settings) noexcept {
                return parse_count(text, settings.pipeline_depth, 1);
            }},
    flag_t {
        "--threads", "count", "application-owned ForkUnion workers, the caller included (1)",
        [](std::string_view text, settings_t& settings) noexcept { return parse_count(text, settings.threads, 1); }},
    flag_t {"--bytes", "count", "request body bytes (1024)",
            [](std::string_view text, settings_t& settings) noexcept { return parse_count(text, settings.bytes); }},
    flag_t {"--backend", "name", "automatic, posix, linux-epoll, linux-uring612, linux-uring700, ... (automatic)",
            [](std::string_view text, settings_t& settings) noexcept {
                settings.backend = ucall_io_backend_from_name(view(text));
                return text == ucall_io_backend_name(settings.backend);
            }},
    flag_t {"--cpu-class", "name", "automatic, serial, intel-haswell, apple-m2, aws-g5, ... (automatic)",
            [](std::string_view text, settings_t& settings) noexcept {
                settings.cpu_class = ucall_cpu_class_from_name(view(text));
                return text == ucall_cpu_class_name(settings.cpu_class);
            }},
    flag_t {"--verb", "name", "post, get or put (post)",
            [](std::string_view text, settings_t& settings) noexcept {
                settings.verb = text == "get" ? ucall_verb_get_k : text == "put" ? ucall_verb_put_k : ucall_verb_post_k;
                return text == "post" || text == "get" || text == "put";
            }},
    flag_t {"--verify-echo", "", "require identical request and response bodies",
            [](std::string_view text, settings_t& settings) noexcept {
                return parse_switch(text, settings.echo_check, echo_check_t::bytes_k);
            }},
    flag_t {"--reorder", "", "paired retained replies at /echo/reordered, implying --verify-echo",
            [](std::string_view text, settings_t& settings) noexcept {
                return parse_switch(text, settings.reply_order, reply_order_t::reordered_k);
            }},
    flag_t {"--close", "", "request connection: close for connection churn",
            [](std::string_view text, settings_t& settings) noexcept {
                return parse_switch(text, settings.connection_reuse, connection_reuse_t::close_k);
            }},
    flag_t {"--pin", "", "pin each ForkUnion worker to its own core where the OS allows",
            [](std::string_view text, settings_t& settings) noexcept {
                return parse_switch(text, settings.placement, thread_placement_t::pinned_k);
            }},
    flag_t {"--seed", "number", "seed of the request body bytes (42)",
            [](std::string_view text, settings_t& settings) noexcept {
                auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), settings.seed);
                return error == std::errc {} && end == text.data() + text.size();
            }},
    flag_t {"--format", "name", "human or json, one object per row (human)",
            [](std::string_view text, settings_t& settings) noexcept {
                settings.format = text == "json" ? output_format_t::json_k : output_format_t::human_k;
                return text == "json" || text == "human";
            }},
};

/** The variable that sets @p flag's default: `--time-limit` reads `UCALL_BENCH_TIME_LIMIT`. */
static std::string environment_variable(flag_t const& flag) {
    std::string variable = "UCALL_BENCH_";
    for (char letter : flag.name.substr(2))
        variable += letter == '-' ? '_' : static_cast<char>(std::toupper(static_cast<unsigned char>(letter)));
    return variable;
}

static void usage(char const* binary) {
    constexpr int column_k = 28;
    std::printf("Usage: %s --requests count | --time-limit duration [flags]\n", binary);
    for (auto const& flag : flags_k) {
        auto width = static_cast<int>(flag.name.size() + (flag.placeholder.empty() ? 0 : flag.placeholder.size() + 1));
        std::printf("  %.*s%s%.*s%*s%.*s [env: %s]\n", static_cast<int>(flag.name.size()), flag.name.data(),
                    flag.placeholder.empty() ? "" : " ", static_cast<int>(flag.placeholder.size()),
                    flag.placeholder.data(), std::max(column_k - width, 1), "", static_cast<int>(flag.help.size()),
                    flag.help.data(), environment_variable(flag).c_str());
    }
    std::printf("  --help%*sprint this usage\n", column_k - 6, "");
}

static bool parse(int argc, char** argv, settings_t& settings) {
    std::bitset<flags_k.size()> given;
    for (int i = 1; i != argc; ++i) {
        std::string_view argument = argv[i];
        auto equal = argument.find('=');
        auto name = argument.substr(0, equal);
        auto found = std::find_if(flags_k.begin(), flags_k.end(),
                                  [&](flag_t const& flag) { return flag.name == name; });
        if (found == flags_k.end()) {
            std::fprintf(stderr, "%.*s is not a flag, see --help\n", static_cast<int>(name.size()), name.data());
            return false;
        }
        std::string_view value;
        if (equal != argument.npos) value = argument.substr(equal + 1);
        else if (!found->placeholder.empty()) {
            if (i + 1 == argc) {
                std::fprintf(stderr, "%.*s requires a value\n", static_cast<int>(name.size()), name.data());
                return false;
            }
            value = argv[++i];
        }
        if (!found->assign(value, settings)) {
            std::fprintf(stderr, "Invalid argument: %.*s=%.*s\n", static_cast<int>(name.size()), name.data(),
                         static_cast<int>(value.size()), value.data());
            return false;
        }
        given.set(static_cast<std::size_t>(found - flags_k.begin()));
    }
    for (std::size_t index = 0; index != flags_k.size(); ++index) {
        if (given[index]) continue;
        auto variable = environment_variable(flags_k[index]);
        char const* value = std::getenv(variable.c_str());
        if (!value || !*value || flags_k[index].assign(value, settings)) continue;
        std::fprintf(stderr, "%s=\"%s\" does not parse\n", variable.c_str(), value);
        return false;
    }
    if (settings.reply_order == reply_order_t::reordered_k) settings.echo_check = echo_check_t::bytes_k;
    if (!settings.requests && !settings.time_limit.count()) {
        std::fputs("--requests or --time-limit must bound the measured run\n", stderr);
        return false;
    }
    if (settings.urls.empty())
        settings.urls.emplace_back(settings.reply_order == reply_order_t::reordered_k
                                       ? "http://127.0.0.1:8545/echo/reordered"
                                       : "http://127.0.0.1:8545/echo");
    if (settings.reply_order == reply_order_t::reordered_k &&
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

/** SplitMix64's step, so that @c --seed fixes every request body byte. */
static std::uint64_t next_random(std::uint64_t& state) noexcept {
    std::uint64_t value = state += 0x9E3779B97F4A7C15ull;
    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
    value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
    return value ^ (value >> 31);
}

/** User and system CPU time the whole client process has spent. */
struct cpu_time_t {
    std::chrono::nanoseconds user {}, system {};
};

static cpu_time_t cpu_time() noexcept {
#if defined(_WIN32)
    using filetime_ticks_t = std::chrono::duration<std::uint64_t, std::ratio<1, 10'000'000>>;
    FILETIME creation {}, exit {}, kernel {}, user {};
    if (!GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user)) return {};
    auto duration = [](FILETIME time) {
        return std::chrono::duration_cast<std::chrono::nanoseconds>(
            filetime_ticks_t {std::uint64_t {time.dwHighDateTime} << 32 | time.dwLowDateTime});
    };
    return {duration(user), duration(kernel)};
#else
    rusage usage {};
    if (getrusage(RUSAGE_SELF, &usage)) return {};
    auto duration = [](timeval time) {
        return std::chrono::nanoseconds(std::chrono::seconds(time.tv_sec) + std::chrono::microseconds(time.tv_usec));
    };
    return {duration(usage.ru_utime), duration(usage.ru_stime)};
#endif // defined(_WIN32)
}

static bool succeeded(ucall_outcome_t const& outcome, char const* operation) {
    if (outcome.status == ucall_status_success_k) return true;
    std::fprintf(stderr, "%s: %s%s%s\n", operation, ucall_status_name(outcome.status), outcome.message ? ": " : "",
                 outcome.message ? outcome.message : "");
    return false;
}

/** Nanosecond latencies in 16 linear bins per power of two: percentiles read at most 1/16 high. */
struct latency_histogram_t {
    static constexpr std::size_t sub_bins_k = 16;

    /** Bits of the largest value with an exact bin: every latency below 32 ns gets one. */
    static constexpr int exact_bits_k = std::bit_width(2 * sub_bins_k - 1);

    /** The exact bins, then 16 for each shift up to the 64th bit. */
    static constexpr std::size_t bins_k = (std::numeric_limits<std::uint64_t>::digits - exact_bits_k + 2) * sub_bins_k;

    std::array<std::uint64_t, bins_k> bins {};

    static std::size_t bin_of(std::uint64_t nanoseconds) noexcept {
        if (nanoseconds < 2 * sub_bins_k) return static_cast<std::size_t>(nanoseconds);
        auto shift = static_cast<std::size_t>(std::bit_width(nanoseconds) - exact_bits_k);
        return shift * sub_bins_k + static_cast<std::size_t>(nanoseconds >> shift);
    }
    static std::uint64_t upper_edge(std::size_t bin) noexcept {
        if (bin < 2 * sub_bins_k) return bin;
        auto shift = bin / sub_bins_k - 1;
        std::uint64_t leading = bin % sub_bins_k + sub_bins_k;
        return ((leading + 1) << shift) - 1;
    }
    void record(std::uint64_t nanoseconds) noexcept { ++bins[bin_of(nanoseconds)]; }
    void merge(latency_histogram_t const& other) noexcept {
        for (std::size_t bin = 0; bin != bins_k; ++bin) bins[bin] += other.bins[bin];
    }

    /** The upper edge of the bin holding the nearest-rank @p fraction, like 0.999 for p99.9. */
    std::uint64_t percentile(double fraction) const noexcept {
        std::uint64_t total = 0;
        for (auto count : bins) total += count;
        if (!total) return 0;
        auto rank = std::max<std::uint64_t>(1, static_cast<std::uint64_t>(std::ceil(fraction * total)));
        std::uint64_t cumulative = 0;
        std::size_t bin = 0;
        while (bin + 1 != bins_k && (cumulative += bins[bin]) < rank) ++bin;
        return upper_edge(bin);
    }
};

struct slot_t {
    std::uint64_t intended_nanoseconds {};
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
struct origin_result_t {
    std::size_t issued {}, completed {}, successful {}, failures {}, response_bytes {}, rejected {}, byte_checks {},
        reordered {};
    std::size_t largest_sequence {};
    std::uint64_t first_completed {}, last_completed {}, latency_max {};
    long double latency_sum {};
};
struct origin_t {
    std::size_t requests {}, warmup_requests {};
    origin_result_t result;
};

/** When a phase starts, when it stops issuing calls, and which quotas bound it. */
struct schedule_t {
    phase_t phase {phase_t::measured_k};
    std::uint64_t begin {}, deadline {};
};

struct worker_t {
    ucall_client_t client {};
    ucall_client_config_t resolved {};
    std::vector<group_t> groups;
    std::vector<group_t*> idle;
    std::vector<ucall_completed_call_t> completed;
    std::vector<origin_t> origins;
    latency_histogram_t latencies;
    std::uint64_t run_id {};
    std::size_t index {}, workers {}, capacity {}, successful {}, failures {}, response_bytes {}, rejected {};
    char const* first_error {};
    ucall_http_status_t first_http_status {};
    ucall_status_t first_rejection {};
    bool ready {}, valid {};

    /** When this worker's arrival @p arrival is due, its turn on the one global schedule. */
    std::uint64_t arrival_time(settings_t const& settings, std::uint64_t begin, std::size_t arrival) const noexcept {
        auto global = static_cast<double>(index + arrival * workers);
        return begin + static_cast<std::uint64_t>(global * nanoseconds_per_second_k / settings.rate);
    }

    bool phase(settings_t const& settings, std::string const& payload, schedule_t schedule) {
        successful = failures = response_bytes = rejected = 0;
        first_error = nullptr;
        first_rejection = {};
        for (auto& origin : origins) origin.result = {};
        auto width = settings.reply_order == reply_order_t::reordered_k ? 2u : 1u;
        auto measured = schedule.phase == phase_t::measured_k;
        std::size_t outstanding = 0, arrivals = 0;
        auto exhausted = [&](group_t const& group) {
            auto const& origin = origins[group.origin];
            return origin.result.issued == (measured ? origin.requests : origin.warmup_requests);
        };
        auto issue = [&](group_t& group, std::uint64_t intended) {
            auto& origin = origins[group.origin];
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
                if (settings.reply_order == reply_order_t::reordered_k) {
                    auto length = std::snprintf(slot.pair_header, sizeof(slot.pair_header),
                                                "x-ucall-pair: %llu:%zu:%zu",
                                                static_cast<unsigned long long>(run_id + !measured), index,
                                                pair * origins.size() + group.origin);
                    slot.headers[headers++] = view({slot.pair_header, static_cast<std::size_t>(length)});
                    slot.pair = {slot.pair_header + sizeof("x-ucall-pair: ") - 1,
                                 static_cast<std::size_t>(length) - (sizeof("x-ucall-pair: ") - 1)};
                    slot.headers[headers++] = view(member ? "x-ucall-member: 1" : "x-ucall-member: 0");
                }
                if (settings.connection_reuse == connection_reuse_t::close_k)
                    slot.headers[headers++] = view("connection: close");
                call.headers = slot.headers.data();
                call.headers_count = headers;
                slot.intended_nanoseconds = intended;
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
        };
        auto fill = [&](group_t& group) {
            for (auto now = now_nanoseconds();
                 !group.outstanding && !exhausted(group) && (!schedule.deadline || now < schedule.deadline);
                 now = now_nanoseconds())
                issue(group, now);
        };
        // Returns the arrival an idle group waits for, or zero when only completions can help.
        auto issue_due = [&]() -> std::uint64_t {
            auto now = now_nanoseconds();
            while (!idle.empty()) {
                auto intended = arrival_time(settings, schedule.begin, arrivals);
                if (schedule.deadline && intended >= schedule.deadline) return 0;
                if (intended > now) return intended;
                auto& group = *idle.back();
                idle.pop_back();
                if (exhausted(group)) continue;
                issue(group, intended);
                arrivals += width;
                if (!group.outstanding) idle.push_back(&group);
            }
            return 0;
        };
        idle.clear();
        for (auto& group : groups)
            if (settings.rate) idle.push_back(&group);
            else fill(group);
        for (;;) {
            auto wake = settings.rate ? issue_due() : 0;
            if (!outstanding && !wake) break;
            auto now = now_nanoseconds();
            auto until_wake = std::chrono::nanoseconds(wake > now ? wake - now : 0);
            if (!outstanding) {
                std::this_thread::sleep_for(until_wake);
                continue;
            }
            ucall_outcome_t outcome {};
            std::size_t count {};
            ucall_client_take_completed_t take {client,           &outcome, completed.data(),
                                                completed.size(), &count,   resolved.request_timeout_microseconds};
            if (wake)
                take.timeout_microseconds = static_cast<std::size_t>(
                    std::chrono::duration_cast<std::chrono::microseconds>(until_wake).count());
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
                auto elapsed = completed_at - slot.intended_nanoseconds;
                auto status = completion.outcome.status;
                char const* error = status == ucall_status_success_k ? nullptr : ucall_status_name(status);
                ucall_http_status_t http_status {};
                std::size_t bytes {};
                if (!error) {
                    http_status = ucall_client_response_status(client, completion.response);
                    if (http_status < 200 || http_status >= 300) error = "unsuccessful HTTP status";
                    else {
                        ucall_bytes_view_t body {};
                        ucall_client_response_body_t get {client, &outcome, completion.response, &body};
                        ucall_client_response_body(&get);
                        if (outcome.status != ucall_status_success_k) error = "response body unavailable";
                        else if (settings.echo_check == echo_check_t::bytes_k) {
                            ++result.byte_checks;
                            if (body.length != payload.size() ||
                                (body.length && std::memcmp(body.data, payload.data(), body.length)))
                                error = "response body differs from request";
                        }
                        bytes = body.length;
                    }
                    if (!error && settings.reply_order == reply_order_t::reordered_k) {
                        for (auto name : {"x-ucall-pair", "x-ucall-member"}) {
                            ucall_bytes_view_t value {};
                            ucall_client_response_header_t get {client, &outcome, completion.response, view(name),
                                                                &value};
                            ucall_client_response_header(&get);
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
                    if (measured) latencies.record(elapsed);
                }
                ucall_client_response_free(completion.response);
                if (group.outstanding) continue;
                if (settings.rate) idle.push_back(&group);
                else fill(group);
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
    schedule_t schedule {};
    static void initialize(void* context, std::size_t index, std::size_t) {
        auto& run = *static_cast<run_t*>(context);
        if (index >= run.resources.workers.size()) return;
        auto& worker = run.resources.workers[index];
        auto count = run.resources.workers.size();
        ucall_client_config_t config {};
        auto width = run.settings.reply_order == reply_order_t::reordered_k ? 2u : 1u;
        auto connection_groups = run.settings.connections / width;
        config.max_concurrent_connections = (connection_groups / count + (index < connection_groups % count)) * width +
                                            (index == 0 ? run.settings.connections % width : 0);
        config.max_concurrent_calls = worker.capacity;
        config.max_pipelined_calls = run.settings.pipeline_depth;
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
            worker.valid = worker.phase(run.settings, run.payload, run.schedule);
        }
    }
    bool dispatch(phase_t phase, std::chrono::nanoseconds limit) {
        schedule.phase = phase;
        schedule.begin = now_nanoseconds();
        schedule.deadline = limit.count() ? schedule.begin + static_cast<std::uint64_t>(limit.count()) : 0;
        return fu_pool_for_threads(resources.pool, execute, this) == fu_success_k;
    }
};

/** Prints @p text as a JSON string, escaping the quote and backslash that URLs may carry. */
static void print_json_string(std::string_view text) {
    std::putchar('"');
    for (char character : text) {
        if (character == '"' || character == '\\') std::putchar('\\');
        std::putchar(character);
    }
    std::putchar('"');
}

static int run(settings_t const& settings) {
    resources_t resources;
    auto width = settings.reply_order == reply_order_t::reordered_k ? 2u : 1u;
    auto clients = std::min({settings.threads, settings.connections / settings.urls.size() / width,
                             settings.in_flight / settings.urls.size() / width});
    if (!clients) {
        std::fprintf(stderr, "Each active origin needs at least %u connections and in-flight slots per worker\n",
                     width);
        return 1;
    }
    resources.workers.resize(clients);
    std::size_t capacity = 0;
    auto run_id = now_nanoseconds();
    auto group_budget = settings.in_flight / width;
    if (settings.reply_order == reply_order_t::reordered_k)
        group_budget = std::min(group_budget, settings.connections / width);
    // Splits a total across origins, then workers, in pairs; zero leaves it to the time limit.
    auto share = [&](std::size_t total, std::size_t origin_index, std::size_t worker_index) {
        if (!total) return unlimited_k;
        auto origin_total = total / width / settings.urls.size() +
                            (origin_index < total / width % settings.urls.size());
        return (origin_total / clients + (worker_index < origin_total % clients)) * width;
    };
    for (std::size_t i = 0; i != clients; ++i) {
        auto& worker = resources.workers[i];
        worker.index = i;
        worker.workers = clients;
        worker.run_id = run_id;
        auto groups = group_budget / clients + (i < group_budget % clients);
        worker.groups.resize(groups);
        worker.idle.reserve(groups);
        worker.capacity = groups * width;
        capacity += worker.capacity;
        worker.completed.resize(worker.capacity);
        worker.origins.resize(settings.urls.size());
        for (std::size_t origin_index = 0; origin_index != settings.urls.size(); ++origin_index) {
            auto& origin = worker.origins[origin_index];
            origin.requests = share(settings.requests, origin_index, i);
            origin.warmup_requests = share(settings.warmup_requests, origin_index, i);
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
    // A whole-machine pool pins workers to cores only when it may place both threads and memory.
    auto placement = static_cast<fu_capabilities_t>(fu_capability_place_threads_by_affinity_k |
                                                    fu_capability_place_memory_on_domain_k);
    auto allowed = settings.placement == thread_placement_t::pinned_k
                       ? fu_capabilities_all_k
                       : static_cast<fu_capabilities_t>(fu_capabilities_all_k & ~placement);
    fu_topology_t topology {};
    auto status = fu_topology_new(&topology);
    if (status == fu_success_k) status = fu_pool_new("ucall-bench", allowed, &resources.pool);
    if (status == fu_success_k)
        status = fu_pool_spawn(topology, resources.pool, settings.threads, fu_caller_inclusive_k);
    if (topology) fu_topology_delete(topology);
    fu_capabilities_t effective {};
    if (status == fu_success_k) status = fu_pool_capabilities(resources.pool, &effective);
    if (status != fu_success_k) {
        std::fprintf(stderr, "ForkUnion initialization failed: %d\n", static_cast<int>(status));
        return 1;
    }
    auto pinned = (effective & placement) == placement;
    std::string payload(settings.bytes, '\0');
    std::uint64_t random_state = settings.seed;
    for (auto& byte : payload) byte = static_cast<char>(next_random(random_state));
    run_t run {resources, settings, payload};
    if (fu_pool_for_threads(resources.pool, run_t::initialize, &run) != fu_success_k) return 1;
    for (auto const& worker : resources.workers)
        if (!worker.ready) return 1;
    if (settings.warmup_requests || settings.warmup.count()) {
        if (!run.dispatch(phase_t::warmup_k, settings.warmup)) return 1;
        for (auto const& worker : resources.workers)
            if (!worker.valid || worker.failures || worker.rejected) {
                std::fprintf(stderr, "Warmup failed: %s\n",
                             worker.first_error ? worker.first_error : ucall_status_name(worker.first_rejection));
                return 1;
            }
    }
    auto cpu_before = cpu_time();
    auto begin = clock_t::now();
    if (!run.dispatch(phase_t::measured_k, settings.time_limit)) return 1;
    auto seconds = std::chrono::duration<double>(clock_t::now() - begin).count();
    auto cpu_after = cpu_time();
    auto& workers = resources.workers;
    std::size_t successful = 0, failures = 0, rejected = 0, response_bytes = 0;
    bool valid = true;
    latency_histogram_t latencies;
    for (std::size_t i = 0; i != workers.size(); ++i) {
        auto& worker = workers[i];
        successful += worker.successful;
        failures += worker.failures;
        rejected += worker.rejected;
        response_bytes += worker.response_bytes;
        valid &= worker.valid;
        latencies.merge(worker.latencies);
        if (worker.first_error)
            std::fprintf(stderr, "Worker %zu: %s (HTTP %u)\n", i, worker.first_error, worker.first_http_status);
        if (worker.rejected) std::fprintf(stderr, "Rejected calls: %s\n", ucall_status_name(worker.first_rejection));
    }
    std::vector<origin_result_t> origins(settings.urls.size());
    long double latency_sum = 0;
    std::uint64_t latency_max = 0;
    for (std::size_t origin_index = 0; origin_index != settings.urls.size(); ++origin_index) {
        auto& total = origins[origin_index];
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
        latency_sum += total.latency_sum;
        latency_max = std::max(latency_max, total.latency_max);
    }
    auto microseconds = [](auto nanoseconds) {
        return static_cast<double>(nanoseconds) / nanoseconds_per_microsecond_k;
    };
    auto per_request = [&](std::chrono::nanoseconds spent) {
        return successful ? microseconds((spent).count()) / successful : 0.0;
    };
    auto mean = successful ? static_cast<double>(latency_sum / successful) / nanoseconds_per_microsecond_k : 0.0;
    auto offset = [&](std::uint64_t at) {
        return at ? static_cast<double>(at - run.schedule.begin) / nanoseconds_per_millisecond_k : 0.0;
    };
    auto gigabytes_per_second = response_bytes / seconds / bytes_per_gigabyte_k;
    double const fractions[] = {0.5, 0.9, 0.99, 0.999, 0.9999};
    char const* const percentiles[] = {"p50", "p90", "p99", "p99.9", "p99.99"};
    auto user = per_request(cpu_after.user - cpu_before.user),
         system = per_request(cpu_after.system - cpu_before.system);
    auto load = settings.rate ? "open-loop" : "closed-loop";
    if (settings.format == output_format_t::json_k) {
        std::printf("{\"row\":\"configuration\",\"origins\":%zu,\"threads\":%zu,\"clients\":%zu,\"placement\":\"%s\","
                    "\"workload\":\"%s\",\"connection_reuse\":\"%s\",\"load\":\"%s\",\"rate_requests_per_second\":%zu,"
                    "\"connections\":%zu,\"in_flight_calls\":%zu,\"pipeline_depth\":%zu,\"request_body_bytes\":%zu,"
                    "\"warmup_requests\":%zu,\"warmup_seconds\":%.6f,\"measured_requests\":%zu,"
                    "\"time_limit_seconds\":%.6f,\"seed\":%u}\n",
                    settings.urls.size(), settings.threads, clients, pinned ? "pinned" : "floating",
                    settings.reply_order == reply_order_t::reordered_k ? "paired replies" : "ordinary",
                    settings.connection_reuse == connection_reuse_t::close_k ? "close" : "keep-alive", load,
                    settings.rate, settings.connections, capacity, settings.pipeline_depth, settings.bytes,
                    settings.warmup_requests, std::chrono::duration<double>(settings.warmup).count(), settings.requests,
                    std::chrono::duration<double>(settings.time_limit).count(), settings.seed);
        std::printf("{\"row\":\"total\",\"successful_requests\":%zu,\"failed_requests\":%zu,\"rejected_requests\":%zu,"
                    "\"elapsed_seconds\":%.6f,\"throughput_requests_per_second\":%.1f,"
                    "\"response_body_gigabytes_per_second\":%.3f,\"latency_mean_us\":%.2f",
                    successful, failures, rejected, seconds, successful / seconds, gigabytes_per_second, mean);
        for (std::size_t i = 0; i != std::size(fractions); ++i)
            std::printf(",\"latency_%s_us\":%.2f", percentiles[i], microseconds(latencies.percentile(fractions[i])));
        std::printf(",\"latency_max_us\":%.2f,\"cpu_user_us_per_request\":%.3f,\"cpu_system_us_per_request\":%.3f}\n",
                    microseconds(latency_max), user, system);
        for (std::size_t origin_index = 0; origin_index != origins.size(); ++origin_index) {
            auto const& total = origins[origin_index];
            std::printf("{\"row\":\"origin\",\"index\":%zu,\"url\":", origin_index);
            print_json_string(settings.urls[origin_index]);
            std::printf(",\"issued_requests\":%zu,\"completed_requests\":%zu,\"successful_requests\":%zu,"
                        "\"failed_requests\":%zu,\"rejected_requests\":%zu,\"byte_checks\":%zu,"
                        "\"reordered_completions\":%zu,\"response_body_bytes\":%zu,\"latency_mean_us\":%.2f,"
                        "\"latency_max_us\":%.2f,\"first_completion_ms\":%.3f,\"last_completion_ms\":%.3f}\n",
                        total.issued, total.completed, total.successful, total.failures, total.rejected,
                        total.byte_checks, total.reordered, total.response_bytes,
                        total.successful
                            ? static_cast<double>(total.latency_sum / total.successful) / nanoseconds_per_microsecond_k
                            : 0.0,
                        microseconds(total.latency_max), offset(total.first_completed), offset(total.last_completed));
        }
        for (std::size_t i = 0; i != workers.size(); ++i)
            std::printf("{\"row\":\"worker\",\"index\":%zu,\"backend\":\"%s\",\"cpu_class\":\"%s\","
                        "\"successful_requests\":%zu,\"failed_requests\":%zu}\n",
                        i, ucall_io_backend_name(workers[i].resolved.backend),
                        ucall_cpu_class_name(workers[i].resolved.cpu_class), workers[i].successful,
                        workers[i].failures);
        std::fputs("Server counters: stop the echo example with SIGINT or SIGTERM and divide its exit line by its "
                   "requests\n",
                   stderr);
    }
    else {
        std::printf("Configuration\n  Origins: %zu\n  ForkUnion workers: %zu, %s\n  Clients: %zu\n  Workload: %s\n"
                    "  Connection reuse: %s\n  Load: %s",
                    settings.urls.size(), settings.threads, pinned ? "pinned to cores" : "floating", clients,
                    settings.reply_order == reply_order_t::reordered_k ? "paired replies" : "ordinary",
                    settings.connection_reuse == connection_reuse_t::close_k ? "close after response" : "keep-alive",
                    load);
        if (settings.rate) std::printf(" at %zu requests/s", settings.rate);
        std::printf("\n  Connections: %zu\n  In-flight calls: %zu\n  Pipeline depth: %zu\n"
                    "  Request body: %zu bytes, seed %u\n",
                    settings.connections, capacity, settings.pipeline_depth, settings.bytes, settings.seed);
        // Zero leaves a phase to its other bound.
        for (auto [name, requests, limit] : {std::tuple {"Warmup", settings.warmup_requests, settings.warmup},
                                             std::tuple {"Measured", settings.requests, settings.time_limit}}) {
            std::printf("  %s: ", name);
            if (requests) std::printf("%zu requests%s", requests, limit.count() ? " or " : "\n");
            if (limit.count()) std::printf("%.3f s\n", std::chrono::duration<double>(limit).count());
            if (!requests && !limit.count()) std::printf("none\n");
        }
        std::printf("Exchanges\n  Successful: %zu requests\n  Failures: %zu requests\n  Rejected: %zu requests\n"
                    "  Elapsed: %.6f s\n  Throughput: %.1f requests/s\n  Response body throughput: %.3f GB/s\n"
                    "  Latency: mean %.2f us",
                    successful, failures, rejected, seconds, successful / seconds, gigabytes_per_second, mean);
        for (std::size_t i = 0; i != std::size(fractions); ++i)
            std::printf(", %s %.2f us", percentiles[i], microseconds(latencies.percentile(fractions[i])));
        std::printf(", max %.2f us\n  Client CPU: user %.3f us/request, system %.3f us/request\n",
                    microseconds(latency_max), user, system);
        for (std::size_t origin_index = 0; origin_index != origins.size(); ++origin_index) {
            auto const& total = origins[origin_index];
            std::printf(
                "  Origin %zu %s: issued %zu requests, completed %zu, successful %zu, failed %zu, rejected %zu, "
                "byte checks %zu, reordered %zu, body %zu bytes\n"
                "    Mean latency: %.2f us, max: %.2f us, first/last completion: %.3f/%.3f ms\n",
                origin_index, settings.urls[origin_index].c_str(), total.issued, total.completed, total.successful,
                total.failures, total.rejected, total.byte_checks, total.reordered, total.response_bytes,
                total.successful
                    ? static_cast<double>(total.latency_sum / total.successful) / nanoseconds_per_microsecond_k
                    : 0.0,
                microseconds(total.latency_max), offset(total.first_completed), offset(total.last_completed));
        }
        for (std::size_t i = 0; i != workers.size(); ++i)
            std::printf("  Worker %zu: %s, %s, %zu successful requests, %zu failed requests\n", i,
                        ucall_io_backend_name(workers[i].resolved.backend),
                        ucall_cpu_class_name(workers[i].resolved.cpu_class), workers[i].successful,
                        workers[i].failures);
        std::printf("Server counters\n  Stop the echo example with SIGINT or SIGTERM: it prints one line per loop.\n"
                    "  Divide its submissions, completions, kernel enters and bytes copied by its requests.\n");
    }
    if (!successful) return 1;
    auto complete = settings.time_limit.count() || successful == settings.requests;
    return !valid || failures || rejected || !complete ? 1 : 0;
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
