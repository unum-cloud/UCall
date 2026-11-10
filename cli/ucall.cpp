/**
 *  @file cli/ucall.cpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief One HTTP or Noise call from the command line, a proxy between plaintext and Noise, and
 *      Noise keys to use them with.
 *
 *  @code{.sh}
 *  ucall [-X VERB] [-H 'name: value']... [-d @FILE | -d @- | -d TEXT] [-i] [-o FILE]
 *        [--key FILE] [--server-key FILE] [--timeout 30s] URL
 *  ucall proxy --listen HOST:PORT --to http+noise://HOST:PORT --key FILE --server-key FILE
 *  ucall proxy --listen HOST:PORT --security xx|ik --key FILE [--peer-key FILE]... --to http://HOST:PORT
 *  ucall keygen FILE
 *  @endcode
 *
 *  The proxy is one server event loop with a client bound to it: every request goes on with its
 *  verb, target and fields but the hop-by-hop ones, and an upstream failure answers 502. It
 *  prints the address it listens on, and on SIGINT or SIGTERM stops once it answered every
 *  request in flight.
 *
 *  An <tt>http+noise://</tt> URL needs <tt>--server-key</tt> and dials IK, so the tool never trusts a server it
 *  was not told about; without <tt>--key</tt> it calls under a fresh identity. It exits 0 for a 2xx
 *  answer, the status's hundreds digit for 3xx to 5xx, 1 when the call fails, and 2 for a
 *  malformed command line.
 */
#include <csignal> // `std::signal`, `SIGINT`, `SIGTERM`
#include <cstdio>  // `std::fopen`, `std::fwrite`
#include <cstring> // `std::strlen`

#include <limits> // `std::numeric_limits`
#include <span>   // `std::span`
#include <string> // `std::string`
#include <vector> // `std::vector`

#include "ucall/ucall.h"
#include "arguments.hpp" // `parse_key`, `parse_duration`

namespace tools = unum::ucall::tools;

enum exit_code_t : int { exit_success_k = 0, exit_failure_k = 1, exit_usage_k = 2 };

/** Whether the answer's status line goes out ahead of its body. */
enum class head_output_t { omitted_k, included_k };

static int usage() {
    std::fputs("usage: ucall [-X VERB] [-H 'name: value']... [-d @FILE | -d @- | -d TEXT] [-i] [-o FILE]\n"       //
               "             [--key FILE] [--server-key FILE] [--timeout 30s] URL\n"                              //
               "       ucall proxy --listen HOST:PORT --to http+noise://HOST:PORT --key FILE --server-key FILE\n" //
               "       ucall proxy --listen HOST:PORT --security xx|ik --key FILE [--peer-key FILE]...\n"         //
               "             --to http://HOST:PORT\n"                                                             //
               "       ucall keygen FILE\n",
               stderr);
    return exit_usage_k;
}

/** Reads all of @p path, or of standard input for <tt>-</tt>, appending it to @p bytes. */
static bool read_all(char const* path, std::vector<char>& bytes) {
    bool const standard = std::strcmp(path, "-") == 0;
    std::FILE* file = standard ? stdin : std::fopen(path, "rb");
    if (!file) return false;
    char chunk[64 * 1024];
    for (std::size_t read; (read = std::fread(chunk, 1, sizeof(chunk), file)) != 0;)
        bytes.insert(bytes.end(), chunk, chunk + read);
    bool const complete = !std::ferror(file);
    if (!standard) std::fclose(file);
    return complete;
}

/** A Noise key from a file holding 64 hexadecimal digits, trailing whitespace allowed. */
static bool read_key(char const* path, ucall_noise_key_t& key) {
    std::vector<char> text;
    if (!read_all(path, text)) return false;
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ')) text.pop_back();
    return tools::parse_key(std::string_view {text.begin(), text.end()}, key);
}

static bool parse_verb(std::string_view name, ucall_verb_t& verb) {
    constexpr std::pair<std::string_view, ucall_verb_t> verbs[] {
        {"GET", ucall_verb_get_k},        {"POST", ucall_verb_post_k},   {"PUT", ucall_verb_put_k},
        {"DELETE", ucall_verb_delete_k},  {"PATCH", ucall_verb_patch_k}, {"HEAD", ucall_verb_head_k},
        {"OPTIONS", ucall_verb_options_k}};
    for (auto const& [spelling, value] : verbs)
        if (spelling == name) return verb = value, true;
    return false;
}

/** What one call asks for, as the command line spelled it. */
struct call_plan_t {
    ucall_verb_t verb {ucall_verb_unknown_k};
    std::string_view url {};
    std::vector<std::string_view> headers {};
    std::vector<char> body {};
    ucall_noise_key_t private_key {}, server_key {};

    /** Each names its key above once a file supplied it. */
    ucall_noise_key_t const *private_key_read {}, *server_key_read {};
    head_output_t head {head_output_t::omitted_k};
    char const* output_path {};
    std::chrono::nanoseconds timeout {std::chrono::seconds {30}};
};

static bool parse_call(std::span<char*> arguments, call_plan_t& plan) {
    for (std::size_t index = 0; index != arguments.size(); ++index) {
        std::string_view const flag = arguments[index];
        bool const valued = flag == "-X" || flag == "-H" || flag == "-d" || flag == "-o" || flag == "--key" ||
                            flag == "--server-key" || flag == "--timeout";
        if (valued && index + 1 == arguments.size()) return false;
        char const* const value = valued ? arguments[++index] : nullptr;
        if (flag == "-X") {
            if (!parse_verb(value, plan.verb)) return false;
        }
        else if (flag == "-H") plan.headers.emplace_back(value);
        else if (flag == "-d") {
            if (value[0] == '@') {
                if (!read_all(value + 1, plan.body)) return false;
            }
            else plan.body.insert(plan.body.end(), value, value + std::strlen(value));
        }
        else if (flag == "-o") plan.output_path = value;
        else if (flag == "-i") plan.head = head_output_t::included_k;
        else if (flag == "--key") {
            if (!read_key(value, plan.private_key)) return false;
            plan.private_key_read = &plan.private_key;
        }
        else if (flag == "--server-key") {
            if (!read_key(value, plan.server_key)) return false;
            plan.server_key_read = &plan.server_key;
        }
        else if (flag == "--timeout") {
            if (!tools::parse_duration(value, plan.timeout)) return false;
        }
        else if (!flag.starts_with('-') && plan.url.empty()) plan.url = flag;
        else return false;
    }
    if (plan.url.empty()) return false;
    if (plan.verb == ucall_verb_unknown_k) plan.verb = plan.body.empty() ? ucall_verb_get_k : ucall_verb_post_k;
    // A Noise URL with no pinned server key would trust whoever answers.
    return !plan.url.starts_with("http+noise://") || plan.server_key_read;
}

static int report(char const* step, ucall_outcome_t const& outcome) {
    std::fprintf(stderr, "ucall: %s failed: %s\n", step, outcome.message ? outcome.message : "unknown status");
    return exit_failure_k;
}

/** Writes the status line and every field line of @p response in arrival order, then a blank. */
static void write_head(std::FILE* output, ucall_received_http_response_t response, int status) {
    std::fprintf(output, "HTTP/1.1 %d\n", status);
    ucall_outcome_t outcome {};
    std::size_t count = 0;
    ucall_client_response_fields_count_t counting {response, &outcome, &count};
    ucall_client_response_fields_count(&counting);
    for (std::size_t index = 0; index != count; ++index) {
        ucall_bytes_view_t name {}, value {};
        ucall_client_response_field_t field {response, &outcome, index, &name, &value};
        ucall_client_response_field(&field);
        std::fprintf(output, "%.*s: %.*s\n", static_cast<int>(name.length), reinterpret_cast<char const*>(name.data),
                     static_cast<int>(value.length), reinterpret_cast<char const*>(value.data));
    }
    std::fputc('\n', output);
}

static int call(std::span<char*> arguments) {
    call_plan_t plan {};
    if (!parse_call(arguments, plan)) return usage();

    // IK sends the caller's static key, so a caller without one gets a fresh identity for this run.
    if (plan.server_key_read && !plan.private_key_read) {
        ucall_noise_key_t public_key {};
        ucall_outcome_t generated {};
        ucall_noise_key_generate_t generate {&generated, &plan.private_key, &public_key};
        ucall_noise_key_generate(&generate);
        if (generated.status != ucall_status_success_k) return report("key generation", generated);
        plan.private_key_read = &plan.private_key;
    }
    ucall_client_options_t config {};
    config.max_concurrent_connections = 1;
    config.noise_private_key = plan.private_key_read;
    ucall_client_t client {};
    ucall_outcome_t outcome {};
    ucall_client_init_t init {};
    init.client = &client, init.outcome = &outcome, init.options = &config;
    ucall_client_init(&init);
    if (outcome.status != ucall_status_success_k) return report("client init", outcome);

    std::vector<ucall_bytes_view_t> headers;
    for (auto header : plan.headers)
        headers.push_back({reinterpret_cast<ucall_byte_t const*>(header.data()), header.size()});
    ucall_client_call_t request {};
    request.client = client, request.outcome = &outcome;
    request.url = {reinterpret_cast<ucall_byte_t const*>(plan.url.data()), plan.url.size()};
    request.verb = plan.verb;
    request.headers = headers.data(), request.headers_count = headers.size();
    request.body = {reinterpret_cast<ucall_byte_t const*>(plan.body.data()), plan.body.size()};
    request.options.timeout_microseconds = static_cast<std::size_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(plan.timeout).count());
    if (plan.server_key_read) {
        request.options.security = ucall_security_noise_ik_k;
        request.options.noise_peer_key = plan.server_key_read;
    }
    ucall_client_call(&request);
    if (outcome.status != ucall_status_success_k) {
        ucall_client_free(client);
        return report("call", outcome);
    }

    ucall_completed_call_t completed {};
    std::size_t count = 0;
    while (!count) {
        ucall_client_take_completed_t take {client, &outcome, &completed,
                                            1,      &count,   request.options.timeout_microseconds};
        ucall_client_take_completed(&take);
        if (outcome.status != ucall_status_success_k) break;
    }
    int code = exit_failure_k;
    if (!count) report("polling", outcome);
    else if (completed.outcome.status != ucall_status_success_k) report("call", completed.outcome);
    else {
        auto const status = static_cast<int>(ucall_client_response_status(completed.response));
        ucall_bytes_view_t body {};
        ucall_client_response_body_t read {completed.response, &outcome, &body};
        ucall_client_response_body(&read);
        std::FILE* output = plan.output_path ? std::fopen(plan.output_path, "wb") : stdout;
        if (!output) std::fprintf(stderr, "ucall: cannot write %s\n", plan.output_path);
        else {
            if (plan.head == head_output_t::included_k) write_head(output, completed.response, status);
            std::fwrite(body.data, 1, body.length, output);
            if (output != stdout) std::fclose(output);
            code = status / 100 == 2 ? exit_success_k : status / 100;
        }
        ucall_client_response_free(completed.response);
    }
    ucall_client_free(client);
    return code;
}

/** Connections the proxy admits and dials, as @c ucall-server admits by default. */
inline constexpr std::size_t proxy_connections_k = 1024;

/** Fields that end at the proxy, RFC 9110 §7.6.1, and those the library writes on each side. */
inline constexpr std::string_view hop_by_hop_k[] {"connection", "proxy-connection",  "keep-alive",
                                                  "te",         "transfer-encoding", "upgrade"};
inline constexpr std::string_view request_written_k[] {"host", "user-agent", "content-length"};
inline constexpr std::string_view reply_written_k[] {"date", "server", "content-length"};

static bool among(std::span<std::string_view const> names, std::string_view name) {
    for (std::string_view const candidate : names)
        if (candidate == name) return true;
    return false;
}

/** Whether @p connection, a Connection field's value, lists @p name, which arrives lowercased. */
static bool listed_in(std::string_view connection, std::string_view name) {
    while (!connection.empty()) {
        std::size_t const comma = connection.find(',');
        std::string_view token = connection.substr(0, comma);
        while (!token.empty() && (token.front() == ' ' || token.front() == '\t')) token.remove_prefix(1);
        while (!token.empty() && (token.back() == ' ' || token.back() == '\t')) token.remove_suffix(1);
        bool equal = token.size() == name.size();
        for (std::size_t i = 0; equal && i != name.size(); ++i)
            equal = (token[i] >= 'A' && token[i] <= 'Z' ? token[i] - 'A' + 'a' : token[i]) == name[i];
        if (equal) return true;
        connection = comma == std::string_view::npos ? std::string_view {} : connection.substr(comma + 1);
    }
    return false;
}

static std::string_view text(ucall_bytes_view_t view) {
    return {reinterpret_cast<char const*>(view.data), view.length};
}
static ucall_bytes_view_t view(std::string_view text) {
    return {reinterpret_cast<ucall_byte_t const*>(text.data()), text.size()};
}

/** A request the proxy forwards: the one it answers and the head it sends on, reused after. */
struct forward_t {
    ucall_received_http_request_t request {};
    std::string url {};
    std::vector<std::string> lines {};
    std::vector<ucall_bytes_view_t> views {};
    forward_t* next_free {};
};

/** A Noise static key the reverse proxy admits. */
struct peer_key_t {
    ucall_noise_key_t key {};
};

struct proxy_t {
    std::string_view listen {}, to {};
    ucall_security_t security {ucall_security_none_k};
    ucall_noise_key_t key {}, server_key {};
    ucall_noise_key_t const *key_read {}, *server_key_read {};
    std::vector<peer_key_t> peer_keys {};
    ucall_server_t server {};
    ucall_client_t client {};
    std::vector<forward_t> forwards {};
    forward_t* free_forwards {};

    /** The fields of the head being forwarded, in arrival order. */
    std::vector<std::pair<std::string_view, std::string_view>> fields {};

    /** Where replies report, as nothing reads it. */
    ucall_outcome_t reply_outcome {};

    static ucall_status_t authorize(ucall_noise_key_t const* peer_static_key, void* context) {
        auto const& proxy = *static_cast<proxy_t const*>(context);
        if (proxy.peer_keys.empty()) return ucall_status_success_k;
        for (peer_key_t const& admitted : proxy.peer_keys)
            if (std::memcmp(admitted.key, *peer_static_key, sizeof(admitted.key)) == 0) return ucall_status_success_k;
        return ucall_status_peer_rejected_k;
    }
    static void forward(ucall_received_http_request_t request, void* context) {
        auto& proxy = *static_cast<proxy_t*>(context);
        if (!proxy.submit(request)) proxy.reply_failure(request, "the upstream call was refused");
    }

    bool open() {
        ucall_outcome_t outcome {};
        ucall_network_interface_t network_interface {};
        network_interface.address = view(listen);
        network_interface.event_loops = 1;
        network_interface.max_concurrent_connections = proxy_connections_k;
        network_interface.security = security;
        network_interface.noise_private_key = security == ucall_security_none_k ? nullptr : key_read;
        network_interface.peer_authorizer = authorize;
        network_interface.peer_authorizer_context = this;
        ucall_server_options_t config {}, resolved {};
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
        ucall_server_init_t init {&server, &outcome, &config, &resolved};
        ucall_server_init(&init);
        if (outcome.status != ucall_status_success_k) return report("server init", outcome), false;
        // A greedy wildcard takes at least one segment, so the root has its own route.
        for (std::string_view const route : {"/", "/{*path}"}) {
            ucall_server_add_http_endpoint_t add {server, &outcome, view(route), ucall_verb_any_k, forward, this};
            ucall_server_add_http_endpoint(&add);
            if (outcome.status != ucall_status_success_k) return report("endpoint", outcome), false;
        }
        ucall_client_options_t client_config {};
        client_config.max_concurrent_connections = proxy_connections_k;
        client_config.noise_private_key = key_read;
        client_config.server = server;
        ucall_client_options_t client_resolved {};
        ucall_client_init_t bind {&client, &outcome, &client_config, &client_resolved};
        ucall_client_init(&bind);
        if (outcome.status != ucall_status_success_k) return report("client init", outcome), false;
        forwards.resize(client_resolved.max_concurrent_calls);
        for (auto& slot : forwards) slot.next_free = std::exchange(free_forwards, &slot);
        std::printf("Proxying %.*s to %.*s\n", static_cast<int>(resolved.interfaces[0].address.length),
                    reinterpret_cast<char const*>(resolved.interfaces[0].address.data), static_cast<int>(to.size()),
                    to.data());
        std::fflush(stdout);
        return true;
    }

    /** Sends @p request on with its verb, target and fields but the hop-by-hop ones, answering
     *  whether the bound client took it. */
    bool submit(ucall_received_http_request_t request) {
        forward_t* slot = free_forwards;
        if (!slot) return false;
        ucall_outcome_t outcome {};
        ucall_bytes_view_t path {}, query {}, body {};
        ucall_server_request_path_t get_path {server, &outcome, request, &path};
        ucall_server_request_path(&get_path);
        ucall_server_request_query_t get_query {server, &outcome, request, &query};
        ucall_server_request_query(&get_query);
        ucall_server_request_body_t get_body {server, &outcome, request, &body};
        ucall_server_request_body(&get_body);
        if (outcome.status != ucall_status_success_k) return false;
        std::string_view base = to;
        if (base.ends_with('/')) base.remove_suffix(1);
        slot->url.assign(base);
        slot->url.append(text(path));
        if (query.length) slot->url.append("?").append(text(query));
        std::size_t count = 0;
        ucall_server_request_fields_count_t counting {server, &outcome, request, &count};
        ucall_server_request_fields_count(&counting);
        std::string_view connection {};
        fields.resize(count);
        for (std::size_t index = 0; index != count; ++index) {
            ucall_bytes_view_t name {}, value {};
            ucall_server_request_field_t field {server, &outcome, request, index, &name, &value};
            ucall_server_request_field(&field);
            fields[index] = {text(name), text(value)};
            if (text(name) == "connection") connection = text(value);
        }
        slot->lines.resize(count);
        slot->views.clear();
        for (std::size_t index = 0; index != count; ++index) {
            auto const [name, value] = fields[index];
            if (among(hop_by_hop_k, name) || among(request_written_k, name) || listed_in(connection, name)) continue;
            slot->lines[index].assign(name).append(": ").append(value);
            slot->views.push_back(view(slot->lines[index]));
        }
        ucall_client_call_t call {};
        call.client = client;
        call.outcome = &outcome;
        call.url = view(slot->url);
        call.verb = ucall_server_request_verb(server, request);
        call.headers = slot->views.data();
        call.headers_count = slot->views.size();
        call.body = body;
        call.context = slot;
        if (to.starts_with("http+noise://")) {
            call.options.security = ucall_security_noise_ik_k;
            call.options.noise_peer_key = server_key_read;
        }
        ucall_client_call(&call);
        if (outcome.status != ucall_status_success_k) return false;
        free_forwards = slot->next_free;
        slot->request = request;
        return true;
    }

    void reply_failure(ucall_received_http_request_t request, std::string_view message) {
        ucall_server_reply_error_t reply {server, &reply_outcome, request, ucall_http_status_bad_gateway_k,
                                          view(message)};
        ucall_server_reply_error(&reply);
    }

    /** Replies to every request whose upstream call the bound client finished. */
    void answer_completed() {
        ucall_completed_call_t completed[64];
        for (std::size_t count = std::size(completed); count == std::size(completed);) {
            ucall_outcome_t outcome {};
            ucall_client_take_completed_t take {client, &outcome, completed, std::size(completed), &count, 0};
            ucall_client_take_completed(&take);
            for (std::size_t index = 0; index != count; ++index) answer(completed[index]);
        }
    }
    void answer(ucall_completed_call_t const& completed) {
        auto& slot = *static_cast<forward_t*>(completed.context);
        ucall_received_http_response_t const response = completed.response;
        if (completed.outcome.status != ucall_status_success_k)
            reply_failure(slot.request, ucall_status_name(completed.outcome.status));
        else {
            ucall_outcome_t outcome {};
            std::size_t count = 0;
            ucall_client_response_fields_count_t counting {response, &outcome, &count};
            ucall_client_response_fields_count(&counting);
            std::string_view connection {};
            fields.resize(count);
            for (std::size_t index = 0; index != count; ++index) {
                ucall_bytes_view_t name {}, value {};
                ucall_client_response_field_t field {response, &outcome, index, &name, &value};
                ucall_client_response_field(&field);
                fields[index] = {text(name), text(value)};
                if (text(name) == "connection") connection = text(value);
            }
            slot.lines.resize(count);
            slot.views.clear();
            for (std::size_t index = 0; index != count; ++index) {
                auto const [name, value] = fields[index];
                if (among(hop_by_hop_k, name) || among(reply_written_k, name) || listed_in(connection, name)) continue;
                slot.lines[index].assign(name).append(": ").append(value);
                slot.views.push_back(view(slot.lines[index]));
            }
            ucall_bytes_view_t body {};
            ucall_client_response_body_t read {response, &outcome, &body};
            ucall_client_response_body(&read);
            ucall_server_reply_content_t reply {server,
                                                &reply_outcome,
                                                slot.request,
                                                ucall_client_response_status(response),
                                                slot.views.data(),
                                                slot.views.size(),
                                                body};
            ucall_server_reply_content(&reply);
            if (reply_outcome.status != ucall_status_success_k && reply_outcome.status != ucall_status_deferred_k)
                reply_failure(slot.request, ucall_status_name(reply_outcome.status));
        }
        ucall_client_response_free(response);
        slot.request = {};
        slot.next_free = std::exchange(free_forwards, &slot);
    }
};

/** The server a signal stops, so the polling loop drains and returns. */
static ucall_server_t stopping_server {};

static bool parse_proxy(std::span<char*> arguments, proxy_t& proxy) {
    for (std::size_t index = 0; index != arguments.size(); ++index) {
        std::string_view const flag = arguments[index];
        if (index + 1 == arguments.size()) return false;
        char const* const value = arguments[++index];
        if (flag == "--listen") proxy.listen = value;
        else if (flag == "--to") proxy.to = value;
        else if (flag == "--key") {
            if (!read_key(value, proxy.key)) return false;
            proxy.key_read = &proxy.key;
        }
        else if (flag == "--server-key") {
            if (!read_key(value, proxy.server_key)) return false;
            proxy.server_key_read = &proxy.server_key;
        }
        else if (flag == "--peer-key") {
            if (!read_key(value, proxy.peer_keys.emplace_back().key)) return false;
        }
        else if (flag == "--security") {
            std::string_view const security = value;
            if (security == "xx") proxy.security = ucall_security_noise_xx_k;
            else if (security == "ik") proxy.security = ucall_security_noise_ik_k;
            else return false;
        }
        else return false;
    }
    bool const sealed_upstream = proxy.to.starts_with("http+noise://");
    if (proxy.listen.empty() || (!sealed_upstream && !proxy.to.starts_with("http://"))) return false;
    // Noise on either side needs this proxy's key, a sealed upstream its pinned key, XX its peers.
    if ((sealed_upstream || proxy.security != ucall_security_none_k) && !proxy.key_read) return false;
    if (sealed_upstream && !proxy.server_key_read) return false;
    return proxy.security != ucall_security_noise_xx_k || !proxy.peer_keys.empty();
}

static int proxy(std::span<char*> arguments) {
    proxy_t proxy {};
    if (!parse_proxy(arguments, proxy)) return usage();
    int code = exit_failure_k;
    if (proxy.open()) {
        stopping_server = proxy.server;
        auto const stop = [](int) { ucall_server_stop(stopping_server); };
        std::signal(SIGINT, stop);
        std::signal(SIGTERM, stop);
        for (;;) {
            ucall_outcome_t outcome {};
            // Waits for a request or an answer; a stop wakes it, and it drains before closing.
            ucall_server_take_call_t take {proxy.server, &outcome, 0, (std::numeric_limits<std::uint32_t>::max)()};
            ucall_server_take_call(&take);
            proxy.answer_completed();
            if (outcome.status == ucall_status_connection_closed_k) {
                code = exit_success_k;
                break;
            }
            if (outcome.status != ucall_status_success_k) {
                report("polling", outcome);
                break;
            }
        }
    }
    ucall_client_free(proxy.client);
    ucall_server_free(proxy.server);
    return code;
}

/** Writes a fresh private key to @p path and prints its public half, both as hexadecimal. */
static int keygen(std::span<char*> arguments) {
    if (arguments.size() != 1) return usage();
    ucall_noise_key_t private_key {}, public_key {};
    ucall_outcome_t outcome {};
    ucall_noise_key_generate_t generate {&outcome, &private_key, &public_key};
    ucall_noise_key_generate(&generate);
    if (outcome.status != ucall_status_success_k) return report("key generation", outcome);
    std::FILE* file = std::fopen(arguments[0], "wx");
    if (!file) {
        std::fprintf(stderr, "ucall: cannot create %s, or it already exists\n", arguments[0]);
        return exit_failure_k;
    }
    for (auto byte : private_key) std::fprintf(file, "%02x", static_cast<unsigned>(byte));
    std::fputc('\n', file);
    std::fclose(file);
    for (auto byte : public_key) std::printf("%02x", static_cast<unsigned>(byte));
    std::putchar('\n');
    return exit_success_k;
}

int main(int argc, char** argv) {
    std::span<char*> arguments {argv + 1, static_cast<std::size_t>(argc > 0 ? argc - 1 : 0)};
    std::string_view const command = arguments.empty() ? "" : arguments.front();
    if (command == "keygen") return keygen(arguments.subspan(1));
    if (command == "proxy") return proxy(arguments.subspan(1));
    if (arguments.empty()) return usage();
    return call(arguments);
}
