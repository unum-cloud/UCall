/**
 * @brief Example of a web server built with UCall in C++.
 */
#include <charconv> // `std::to_chars`
#include <cstdio>   // `std::fprintf`
#include <thread>
#include <vector>

#include <cxxopts.hpp>

#include "ucall/ucall.h"

static void validate_session(ucall_message_t call, ucall_endpoint_tag_t) {
    int64_t a{}, b{};
    char c_str[256]{};
    bool got_a = ucall_param_named_i64(call, "user_id", 0, &a);
    bool got_b = ucall_param_named_i64(call, "session_id", 0, &b);
    if (!got_a || !got_b)
        return ucall_reply_error_invalid_params(call);

    const char* res = ((a ^ b) % 23 == 0) ? "true" : "false";
    ucall_reply_content(call, res, strlen(res));
}

int main(int argc, char** argv) {

    cxxopts::Options options("Summation Server", "If device can't sum integers, just send them over with JSON-RPC :)");
    options.add_options()                                                                                             //
        ("h,help", "Print usage")                                                                                     //
        ("nic", "Networking Interface Internal IP to use", cxxopts::value<std::string>()->default_value("127.0.0.1")) //
        ("p,port", "On which port to server JSON-RPC", cxxopts::value<int>()->default_value("8545"))                  //
        ("j,threads", "How many threads to run", cxxopts::value<int>()->default_value("1"))                           //
        ("s,silent", "Silence statistics output", cxxopts::value<bool>()->default_value("false"))                     //
        ;
    auto result = options.parse(argc, argv);
    if (result.count("help")) {
        std::cout << options.help() << std::endl;
        exit(0);
    }

    ucall_server_t server{};
    ucall_config_t config{};
    config.hostname = result["nic"].as<std::string>().c_str();
    config.port = result["port"].as<int>();
    config.max_threads = result["threads"].as<int>();
    config.max_concurrent_connections = 1024;
    config.queue_depth = 4096 * config.max_threads;
    config.max_lifetime_exchanges = UINT32_MAX;
    config.logs_file_descriptor = result["silent"].as<bool>() ? -1 : fileno(stdin);
    config.logs_format = "human";
    config.protocol = protocol_kind_t::jsonrpc_http_k;
    // config.ssl_private_key_path = "./examples/login/certs/main.key";
    // const char* crts[] = {"./examples/login/certs/srv.crt", "./examples/login/certs/cas.pem"};
    // config.ssl_certificates_paths = crts;
    // config.ssl_certificates_count = 2;

    ucall_init(&config, &server);
    if (!server) {
        std::printf("Failed to start server: %s:%i\n", config.hostname, config.port);
        return -1;
    }

    std::printf("Initialized server: %s:%i\n", config.hostname, config.port);
    std::printf("- %zu threads\n", static_cast<std::size_t>(config.max_threads));
    std::printf("- %zu max concurrent connections\n", static_cast<std::size_t>(config.max_concurrent_connections));
    if (result["silent"].as<bool>())
        std::printf("- silent\n");

    // Add all the callbacks we need
    ucall_add_endpoint(server, "validate_session", &validate_session, ucall_verb_t::post_k, nullptr);

    if (config.max_threads > 1) {
        std::vector<std::thread> threads;
        for (uint16_t i = 0; i != config.max_threads; ++i)
            threads.emplace_back(&ucall_take_calls, server, i);
        for (auto& thread : threads)
            thread.join();
    } else
        ucall_take_calls(server, 0);

    ucall_free(server);
    return 0;
}