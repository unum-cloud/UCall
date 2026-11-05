/**
 *  @file test/cli.cpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief Drives the <tt>ucall</tt> command-line client, whose path is the first argument, against
 *      an in-process fixture server.
 */
#include <poll.h>     // `poll`
#include <signal.h>   // `kill`, `SIGINT`
#include <sys/wait.h> // `WIFEXITED`, `WEXITSTATUS`, `waitpid`
#include <unistd.h>   // `fork`, `execv`, `pipe`

#include <network.hpp>

using namespace unum::ucall::test;

/** The command line under test, set once from the arguments. */
static std::string cli_path;

/** What one run of the tool printed to its standard output, and how it exited. */
struct cli_run_t {
    int exit_code = -1;
    std::string output;
};

/** Runs the tool with @p arguments through the shell, so a redirection can feed its standard
 *  input. */
static cli_run_t run_cli(scratch_directory_t const& scratch, std::string_view arguments) {
    std::string const output_path = scratch.name("stdout");
    int const status = std::system(fmt::format("{} {} > {}", cli_path, arguments, output_path).c_str());
    cli_run_t run;
    run.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    if (std::FILE* file = std::fopen(output_path.c_str(), "rb")) {
        char chunk[4096];
        for (std::size_t read; (read = std::fread(chunk, 1, sizeof(chunk), file)) != 0;) run.output.append(chunk, read);
        std::fclose(file);
    }
    return run;
}

static std::string hexadecimal(ucall_noise_key_t const& key) {
    std::string text;
    for (auto byte : key) text += fmt::format("{:02x}", static_cast<unsigned>(byte));
    return text;
}

/** Plaintext calls: a GET to standard output, a POST from a file and from standard input, a header
 *  reaching the handler, <tt>-i</tt> printing the status line and fields before the body, and a 404
 *  exiting with its hundreds digit. */
static case_result_t test_cli_plaintext() {
    fixture_t fixture {{.connections = 4}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    scratch_directory_t scratch;
    require(0, scratch.ready() && scratch.write("body.txt", "from a file"));
    fixture.serve_in_background();
    std::size_t failures = 0;

    auto const got = run_cli(scratch, fmt::format("{}/headers", fixture.url));
    failures += expect(got.exit_code == 0 && got.output.starts_with("/headers;"), "GET exited {} with {:?}",
                       got.exit_code, got.output);

    auto const filed = run_cli(scratch, fmt::format("-d @{} {}/echo/1", scratch.name("body.txt"), fixture.url));
    failures += expect(filed.exit_code == 0 && filed.output == "from a file", "POST from a file exited {} with {:?}",
                       filed.exit_code, filed.output);

    auto const piped = run_cli(scratch, fmt::format("-d @- {}/echo/2 < {}", fixture.url, scratch.name("body.txt")));
    failures += expect(piped.exit_code == 0 && piped.output == "from a file", "POST from stdin exited {} with {:?}",
                       piped.exit_code, piped.output);

    auto const headed = run_cli(scratch, fmt::format("-H 'X-~: tilde' {}/headers", fixture.url));
    failures += expect(headed.exit_code == 0 && headed.output.find(";tilde;") != std::string::npos,
                       "a header exited {} with {:?}", headed.exit_code, headed.output);

    auto const headed_output = run_cli(scratch, fmt::format("-i -d echoed {}/echo/5", fixture.url));
    failures += expect(headed_output.exit_code == 0 && headed_output.output.starts_with("HTTP/1.1 200\n") &&
                           headed_output.output.find("\nx-ucall: passed\n") != std::string::npos &&
                           headed_output.output.ends_with("\n\nechoed"),
                       "-i exited {} with {:?}", headed_output.exit_code, headed_output.output);

    auto const missing = run_cli(scratch, fmt::format("{}/missing", fixture.url));
    failures += expect(missing.exit_code == 4, "a 404 exited {}", missing.exit_code);
    return failures + fixture.stop();
}

/** An IK call over <tt>http+noise://</tt> with the server's key pinned from a file and the
 *  caller's own. */
static case_result_t test_cli_noise_ik() {
    fixture_t fixture {{.security = ucall_security_noise_ik_k}};
    require(0, fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status));
    scratch_directory_t scratch;
    require(0, scratch.ready() && scratch.write("server.key", hexadecimal(fixture.server_public) + "\n") &&
                   scratch.write("client.key", hexadecimal(fixture.client_private) + "\n"));
    fixture.serve_in_background();
    std::size_t failures = 0;
    auto const run = run_cli(scratch, fmt::format("--server-key {} --key {} -d sealed {}/echo/3",
                                                  scratch.name("server.key"), scratch.name("client.key"), fixture.url));
    failures += expect(run.exit_code == 0 && run.output == "sealed", "IK exited {} with {:?}", run.exit_code,
                       run.output);
    auto const unpinned = run_cli(scratch, fmt::format("-d sealed {}/echo/4 2>/dev/null", fixture.url));
    failures += expect(unpinned.exit_code == 2, "a Noise URL without --server-key exited {}", unpinned.exit_code);
    return failures + fixture.stop();
}

/** An upstream answering every target with its verb, target and fields, all on one background
 *  loop. */
struct echo_upstream_t {
    ucall_server_t server {};
    std::string address {};
    std::thread poller {};
    static void echo_head(ucall_received_http_request_t request, void* context) {
        auto& upstream = *static_cast<echo_upstream_t*>(context);
        ucall_outcome_t outcome {};
        ucall_bytes_view_t path {}, query {};
        ucall_server_request_path_t get_path {upstream.server, &outcome, request, &path};
        ucall_server_request_path(&get_path);
        ucall_server_request_query_t get_query {upstream.server, &outcome, request, &query};
        ucall_server_request_query(&get_query);
        std::string answer = fmt::format("{} {}?{}|",
                                         static_cast<int>(ucall_server_request_verb(upstream.server, request)),
                                         uc::text_view(path), uc::text_view(query));
        std::size_t count = 0;
        ucall_server_request_fields_count_t counting {upstream.server, &outcome, request, &count};
        ucall_server_request_fields_count(&counting);
        for (std::size_t index = 0; index != count; ++index) {
            ucall_bytes_view_t name {}, value {};
            ucall_server_request_field_t field {upstream.server, &outcome, request, index, &name, &value};
            ucall_server_request_field(&field);
            answer += fmt::format("{}={};", uc::text_view(name), uc::text_view(value));
        }
        ucall_bytes_view_t const header = uc::bytes_view("X-Upstream: answered");
        ucall_server_reply_content_t reply {
            upstream.server, &outcome, request, ucall_http_status_ok_k, &header, 1, uc::bytes_view(answer)};
        ucall_server_reply_content(&reply);
    }
    bool start() {
        ucall_outcome_t outcome {};
        ucall_network_interface_t network_interface {};
        network_interface.address = uc::bytes_view("127.0.0.1:0");
        network_interface.event_loops = 1;
        network_interface.max_concurrent_connections = 4;
        ucall_server_options_t config {}, resolved {};
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
        ucall_server_init_t init {&server, &outcome, &config, &resolved};
        ucall_server_init(&init);
        if (outcome.status != ucall_status_success_k) return false;
        address = uc::text_view(resolved.interfaces[0].address);
        ucall_server_add_http_endpoint_t add {server,           &outcome,  uc::bytes_view("/{*path}"),
                                              ucall_verb_any_k, echo_head, this};
        ucall_server_add_http_endpoint(&add);
        if (outcome.status != ucall_status_success_k) return false;
        poller = std::thread([this] {
            ucall_outcome_t serving_outcome {};
            ucall_server_take_calls_t serving {server, &serving_outcome, 0};
            ucall_server_take_calls(&serving);
        });
        return true;
    }
    ~echo_upstream_t() {
        if (poller.joinable()) {
            ucall_server_stop(server);
            poller.join();
        }
        ucall_server_free(server);
    }
};

/** A <tt>ucall proxy</tt> child and the address it printed it listens on. */
struct proxy_run_t {
    pid_t pid = -1;
    std::string address {};

    /** Stops the child with SIGINT, answering how it exited. */
    int stop() {
        if (pid < 0) return -1;
        ::kill(pid, SIGINT);
        int status = 0;
        ::waitpid(std::exchange(pid, -1), &status, 0);
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }
    ~proxy_run_t() { stop(); }
};

/** Starts <tt>ucall proxy</tt> with @p arguments and reads the address from the line it prints
 *  first. */
static void spawn_proxy(proxy_run_t& run, std::vector<std::string> arguments) {
    int channel[2];
    if (::pipe(channel) != 0) return;
    arguments.insert(arguments.begin(), {cli_path, "proxy"});
    std::vector<char*> argv;
    for (auto& argument : arguments) argv.push_back(argument.data());
    argv.push_back(nullptr);
    run.pid = ::fork();
    if (run.pid == 0) {
        ::dup2(channel[1], STDOUT_FILENO);
        ::close(channel[0]);
        ::close(channel[1]);
        ::execv(argv[0], argv.data());
        ::_exit(127);
    }
    ::close(channel[1]);
    std::string line;
    pollfd waiting {channel[0], POLLIN, 0};
    char byte = 0;
    while (line.find('\n') == std::string::npos && ::poll(&waiting, 1, 5000) == 1 && ::read(channel[0], &byte, 1) == 1)
        line += byte;
    ::close(channel[0]);
    // "Proxying HOST:PORT to URL"
    std::size_t const start = line.find(' '), end = line.find(" to ");
    if (start != std::string::npos && end != std::string::npos) run.address = line.substr(start + 1, end - start - 1);
}

/** A plaintext call through a forward proxy into Noise IK, and through a reverse proxy back to a
 *  plaintext upstream, keeping verb, path, query and fields but the hop-by-hop ones both ways; and
 *  an unreachable upstream answering 502. */
static case_result_t test_cli_proxy_round_trip() {
    echo_upstream_t upstream;
    require(0, upstream.start(), "the upstream failed to start");
    ucall_noise_key_t reverse_private {}, reverse_public {}, forward_private {}, forward_public {};
    ucall_outcome_t outcome {};
    ucall_noise_key_generate_t reverse_keys {&outcome, &reverse_private, &reverse_public};
    ucall_noise_key_generate(&reverse_keys);
    ucall_noise_key_generate_t forward_keys {&outcome, &forward_private, &forward_public};
    ucall_noise_key_generate(&forward_keys);
    scratch_directory_t scratch;
    require(0, scratch.ready() && scratch.write("reverse.key", hexadecimal(reverse_private)) &&
                   scratch.write("reverse.pub", hexadecimal(reverse_public)) &&
                   scratch.write("forward.key", hexadecimal(forward_private)) &&
                   scratch.write("forward.pub", hexadecimal(forward_public)));
    proxy_run_t reverse, forward, broken;
    spawn_proxy(reverse, {"--listen", "127.0.0.1:0", "--security", "ik", "--key", scratch.name("reverse.key"),
                          "--peer-key", scratch.name("forward.pub"), "--to", "http://" + upstream.address});
    require(0, !reverse.address.empty(), "the reverse proxy printed no address");
    spawn_proxy(forward, {"--listen", "127.0.0.1:0", "--to", "http+noise://" + reverse.address, "--key",
                          scratch.name("forward.key"), "--server-key", scratch.name("reverse.pub")});
    require(0, !forward.address.empty(), "the forward proxy printed no address");
    std::size_t failures = 0;
    auto const run = run_cli(scratch, fmt::format("-i -X PUT -d payload -H 'X-Kept: one' -H 'Connection: x-drop' " //
                                                  "-H 'X-Drop: gone' 'http://{}/a/b?q=1&r=two'",
                                                  forward.address));
    std::string_view const output = run.output;
    failures += expect(run.exit_code == 0 && output.find("\nx-upstream: answered\n") != std::string_view::npos &&
                           output.find(fmt::format("{} /a/b?q=1&r=two|", static_cast<int>(ucall_verb_put_k))) !=
                               std::string_view::npos &&
                           output.find("x-kept=one;") != std::string_view::npos &&
                           output.find("x-drop") == std::string_view::npos &&
                           output.find("connection=") == std::string_view::npos,
                       "the round trip exited {} with {:?}", run.exit_code, run.output);
    spawn_proxy(broken, {"--listen", "127.0.0.1:0", "--to", "http://127.0.0.1:1"});
    require(failures, !broken.address.empty(), "the broken proxy printed no address");
    auto const refused = run_cli(scratch, fmt::format("http://{}/ 2>/dev/null", broken.address));
    failures += expect(refused.exit_code == 5, "an unreachable upstream exited {}", refused.exit_code);
    failures += expect(forward.stop() == 0 && reverse.stop() == 0 && broken.stop() == 0,
                       "a proxy did not stop cleanly");
    return failures;
}

int main(int argc, char** argv) {
    install_test_signal_handlers();
    fmt::print("Hi, dear tester! You look nice today!\n");
    configure_tests();
    if (argc != 2) {
        fmt::print(stderr, "Usage: {} <path to the ucall tool>\n", argv[0]);
        return 1;
    }
    cli_path = argv[1];
    suite_totals_t totals {.program = argv[0]};
    run_test(totals, "test_cli_plaintext", test_cli_plaintext);
    run_test(totals, "test_cli_noise_ik", test_cli_noise_ik);
    run_test(totals, "test_cli_proxy_round_trip", test_cli_proxy_round_trip);
    return suite_exit_code(totals);
}
