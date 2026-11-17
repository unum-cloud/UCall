/**
 *  @file test/tools.cpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief Drives the <tt>ucall</tt> command-line client, which the arguments after <tt>--</tt> run,
 *      against an in-process fixture server.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build

#include <poll.h>     // `poll`
#include <signal.h>   // `kill`, `SIGINT`
#include <sys/stat.h> // `stat`, `lstat`
#include <sys/wait.h> // `WIFEXITED`, `WEXITSTATUS`, `waitpid`
#include <unistd.h>   // `fork`, `execv`, `pipe`

#include <network.hpp>

using namespace unum::ucall::test;

/** The words of the command that runs the tool, an emulator and its options first in a cross
 *  build, set once from the arguments after <tt>--</tt>. */
static std::vector<std::string> cli_words;

/** What one run of the tool printed to its standard output, and how it exited. */
struct cli_run_t {
    int exit_code = -1;
    std::string output;
};

/** Runs the tool with @p arguments through the shell, so a redirection can feed its standard
 *  input. */
static cli_run_t run_cli(scratch_directory_t const& scratch, std::string_view arguments) {
    std::string const output_path = scratch.name("stdout");
    std::string command;
    for (std::string const& word : cli_words) command += fmt::format("'{}' ", word);
    int const status = std::system(fmt::format("{}{} > {}", command, arguments, output_path).c_str());
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
static void test_cli_plaintext(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {.connections = 4}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    scratch_directory_t scratch;
    if (!expect_true(scratch.ready() && scratch.write("body.txt", "from a file"))) return;
    fixture.serve_in_background();

    auto const got = run_cli(scratch, fmt::format("{}/headers", fixture.url));
    expect_true(got.exit_code == 0 && got.output.starts_with("/headers;"), "GET exited {} with {:?}", got.exit_code,
                got.output);

    auto const filed = run_cli(scratch, fmt::format("-d @{} {}/echo/1", scratch.name("body.txt"), fixture.url));
    expect_true(filed.exit_code == 0 && filed.output == "from a file", "POST from a file exited {} with {:?}",
                filed.exit_code, filed.output);

    auto const piped = run_cli(scratch, fmt::format("-d @- {}/echo/2 < {}", fixture.url, scratch.name("body.txt")));
    expect_true(piped.exit_code == 0 && piped.output == "from a file", "POST from stdin exited {} with {:?}",
                piped.exit_code, piped.output);

    auto const headed = run_cli(scratch, fmt::format("-H 'X-~: tilde' {}/headers", fixture.url));
    expect_true(headed.exit_code == 0 && headed.output.find(";tilde;") != std::string::npos,
                "a header exited {} with {:?}", headed.exit_code, headed.output);

    auto const headed_output = run_cli(scratch, fmt::format("-i -d echoed {}/echo/5", fixture.url));
    expect_true(headed_output.exit_code == 0 && headed_output.output.starts_with("HTTP/1.1 200\n") &&
                    headed_output.output.find("\nx-ucall: passed\n") != std::string::npos &&
                    headed_output.output.ends_with("\n\nechoed"),
                "-i exited {} with {:?}", headed_output.exit_code, headed_output.output);

    auto const missing = run_cli(scratch, fmt::format("{}/missing", fixture.url));
    expect_true(missing.exit_code == 4, "a 404 exited {}", missing.exit_code);
    fixture.stop();
}

/** Everything a file under @p scratch holds, or empty when it won't open. */
static std::string read_file(scratch_directory_t const& scratch, std::string_view relative) {
    std::string text;
    if (std::FILE* file = std::fopen(scratch.name(relative).c_str(), "rb")) {
        char chunk[4096];
        for (std::size_t read; (read = std::fread(chunk, 1, sizeof(chunk), file)) != 0;) text.append(chunk, read);
        std::fclose(file);
    }
    return text;
}

/** Files the tool writes land whole through a temporary: <tt>-o</tt> replaces an earlier answer,
 *  a stale or linked temporary refuses the write and leaves the target alone, and
 *  <tt>keygen</tt> writes an owner-only key and never replaces an existing one. */
static void test_cli_landing(sweep_cell_t const& cell) {
    fixture_t fixture {cell, {.connections = 4, .max_request_bytes = 8 << 20}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    scratch_directory_t scratch;
    if (!expect_true(scratch.ready() && scratch.write("out.txt", "earlier"))) return;
    fixture.serve_in_background();
    std::string const output = scratch.name("out.txt"), temporary = scratch.name("out.txt.tmp");

    auto const landed = run_cli(scratch, fmt::format("-o {} -d landed {}/echo/6", output, fixture.url));
    expect_true(landed.exit_code == 0 && read_file(scratch, "out.txt") == "landed", "-o exited {} leaving {:?}",
                landed.exit_code, read_file(scratch, "out.txt"));

    // Several MiB stream through the pulls into the landed file, byte for byte.
    std::string large(6 << 20, '\0');
    for (std::size_t i = 0; i != large.size(); ++i) large[i] = static_cast<char>('a' + i % 23);
    if (!expect_true(scratch.write("large.bin", large))) return;
    auto const streamed = run_cli(scratch, fmt::format("-o {} -d @{} {}/echo/9", scratch.name("large.out"),
                                                       scratch.name("large.bin"), fixture.url));
    expect_true(streamed.exit_code == 0 && read_file(scratch, "large.out") == large,
                "a streamed -o exited {} leaving {} bytes", streamed.exit_code, read_file(scratch, "large.out").size());

    if (!expect_true(scratch.write("out.txt.tmp", "stale"))) return;
    auto const stale = run_cli(scratch, fmt::format("-o {} -d lost {}/echo/7 2>/dev/null", output, fixture.url));
    expect_true(stale.exit_code == 1 && read_file(scratch, "out.txt") == "landed" &&
                    read_file(scratch, "out.txt.tmp") == "stale",
                "a stale temporary exited {} leaving {:?}", stale.exit_code, read_file(scratch, "out.txt"));
    std::remove(temporary.c_str());

    if (!expect_true(scratch.write("aside.txt", "aside") &&
                     ::symlink(scratch.name("aside.txt").c_str(), temporary.c_str()) == 0))
        return;
    auto const linked = run_cli(scratch, fmt::format("-o {} -d lost {}/echo/8 2>/dev/null", output, fixture.url));
    expect_true(linked.exit_code == 1 && read_file(scratch, "out.txt") == "landed" &&
                    read_file(scratch, "aside.txt") == "aside",
                "a linked temporary exited {}", linked.exit_code);
    std::remove(temporary.c_str());

    std::string const key = scratch.name("own.key");
    auto const generated = run_cli(scratch, fmt::format("keygen {}", key));
    struct stat key_stat {};
    bool const owner_only = ::stat(key.c_str(), &key_stat) == 0 && (key_stat.st_mode & 0777) == 0600;
    expect_true(generated.exit_code == 0 && owner_only, "keygen exited {} with mode {:o}", generated.exit_code,
                key_stat.st_mode & 0777);
    std::string const first_key = read_file(scratch, "own.key");
    auto const again = run_cli(scratch, fmt::format("keygen {} 2>/dev/null", key));
    struct stat temporary_stat {};
    expect_true(again.exit_code == 1 && read_file(scratch, "own.key") == first_key &&
                    ::lstat(scratch.name("own.key.tmp").c_str(), &temporary_stat) != 0,
                "a second keygen exited {}", again.exit_code);
    fixture.stop();
}

/** An IK call over <tt>http+noise://</tt> with the server's key pinned from a file and the
 *  caller's own. */
static void test_cli_noise_ik(sweep_cell_t const& cell) {
    fixture_t fixture {{cell.backend, cell.cpu_class_ceiling, ucall_security_noise_ik_k}, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    scratch_directory_t scratch;
    if (!expect_true(scratch.ready() && scratch.write("server.key", hexadecimal(fixture.server_public) + "\n") &&
                     scratch.write("client.key", hexadecimal(fixture.client_private) + "\n")))
        return;
    fixture.serve_in_background();
    auto const run = run_cli(scratch, fmt::format("--server-key {} --key {} -d sealed {}/echo/3",
                                                  scratch.name("server.key"), scratch.name("client.key"), fixture.url));
    expect_true(run.exit_code == 0 && run.output == "sealed", "IK exited {} with {:?}", run.exit_code, run.output);
    auto const unpinned = run_cli(scratch, fmt::format("-d sealed {}/echo/4 2>/dev/null", fixture.url));
    expect_true(unpinned.exit_code == 2, "a Noise URL without --server-key exited {}", unpinned.exit_code);
    fixture.stop();
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
    arguments.insert(arguments.begin(), "proxy");
    arguments.insert(arguments.begin(), cli_words.begin(), cli_words.end());
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
static void test_cli_proxy_round_trip() {
    echo_upstream_t upstream;
    if (!expect_true(upstream.start(), "the upstream failed to start")) return;
    ucall_noise_key_t reverse_private {}, reverse_public {}, forward_private {}, forward_public {};
    ucall_outcome_t outcome {};
    ucall_noise_key_generate_t reverse_keys {&outcome, &reverse_private, &reverse_public};
    ucall_noise_key_generate(&reverse_keys);
    ucall_noise_key_generate_t forward_keys {&outcome, &forward_private, &forward_public};
    ucall_noise_key_generate(&forward_keys);
    scratch_directory_t scratch;
    if (!expect_true(scratch.ready() && scratch.write("reverse.key", hexadecimal(reverse_private)) &&
                     scratch.write("reverse.pub", hexadecimal(reverse_public)) &&
                     scratch.write("forward.key", hexadecimal(forward_private)) &&
                     scratch.write("forward.pub", hexadecimal(forward_public))))
        return;
    proxy_run_t reverse, forward, broken;
    spawn_proxy(reverse, {"--listen", "127.0.0.1:0", "--security", "ik", "--key", scratch.name("reverse.key"),
                          "--peer-key", scratch.name("forward.pub"), "--to", "http://" + upstream.address});
    if (!expect_true(!reverse.address.empty(), "the reverse proxy printed no address")) return;
    spawn_proxy(forward, {"--listen", "127.0.0.1:0", "--to", "http+noise://" + reverse.address, "--key",
                          scratch.name("forward.key"), "--server-key", scratch.name("reverse.pub")});
    if (!expect_true(!forward.address.empty(), "the forward proxy printed no address")) return;
    auto const run = run_cli(scratch, fmt::format("-i -X PUT -d payload -H 'X-Kept: one' -H 'Connection: x-drop' " //
                                                  "-H 'X-Drop: gone' 'http://{}/a/b?q=1&r=two'",
                                                  forward.address));
    std::string_view const output = run.output;
    expect_true(run.exit_code == 0 && output.find("\nx-upstream: answered\n") != std::string_view::npos &&
                    output.find(fmt::format("{} /a/b?q=1&r=two|", static_cast<int>(ucall_verb_put_k))) !=
                        std::string_view::npos &&
                    output.find("x-kept=one;") != std::string_view::npos &&
                    output.find("x-drop") == std::string_view::npos &&
                    output.find("connection=") == std::string_view::npos,
                "the round trip exited {} with {:?}", run.exit_code, run.output);
    spawn_proxy(broken, {"--listen", "127.0.0.1:0", "--to", "http://127.0.0.1:1"});
    if (!expect_true(!broken.address.empty(), "the broken proxy printed no address")) return;
    auto const refused = run_cli(scratch, fmt::format("http://{}/ 2>/dev/null", broken.address));
    expect_true(refused.exit_code == 5, "an unreachable upstream exited {}", refused.exit_code);
    expect_true(forward.stop() == exit_stopped_k && reverse.stop() == exit_stopped_k && broken.stop() == exit_stopped_k,
                "a proxy did not stop as a signal stops a command");
}

int main(int argc, char** argv) {
    for (int index = 1; index < argc; ++index)
        if (std::string_view {argv[index]} == "--") {
            cli_words.assign(argv + index + 1, argv + argc);
            break;
        }
    if (cli_words.empty()) {
        fmt::println(stderr, "Usage: {} -- <command that runs the ucall tool>", argv[0]);
        return 1;
    }
    start_test_run(argc, argv);
    sweep_cell_t const cell {test_run.settings.backend, test_run.settings.cpu_class_ceiling, ucall_security_none_k};
    run_test_case("main", [&] {
        return keeping_descriptors([&] {
            test_cli_plaintext(cell);
            test_cli_landing(cell);
            test_cli_noise_ik(cell);
            test_cli_proxy_round_trip();
        });
    });
    return finish_test_run();
}
