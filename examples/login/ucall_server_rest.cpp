/**
 *  @file examples/login/ucall_server_rest.cpp
 *  @author Ash Vardanian
 *  @date January 17, 2023
 *  @brief Example of a web server built with UCall in C++.
 */
#include <charconv> // `std::to_chars`
#include <cstdio>   // `std::fprintf`
#include <map>
#include <thread>
#include <vector>

#include <cxxopts.hpp>

#include "ucall/ucall.h"

static bool get_param_int_from_path(ucall_message_t call, char const* name, int64_t* res) {
    ucall_string_t param_str;
    size_t param_str_len;
    if (!ucall_request_param(call, name, 0, &param_str, &param_str_len)) return false;

    char* endptr = nullptr;
    *res = std::strtoul(param_str, &endptr, 10);
    if (*res == 0 && endptr == param_str) return false;
    return true;
}

static void validate_session(ucall_message_t call, ucall_endpoint_tag_t) {

    int64_t a {}, b {};
    char c_str[256] {};

    bool got_a = ucall_param_named_i64(call, "user_id", 0, &a);
    bool got_b = get_param_int_from_path(call, "session_id", &b);
    if (!got_a || !got_b) return ucall_reply_error_invalid_params(call);

    const char* res = ((a ^ b) % 23 == 0) ? "{\"response\": true}" : "{\"response\": false}";
    ucall_reply_content(call, res, strlen(res));
}

static void upload_binary(ucall_message_t call, ucall_endpoint_tag_t) {
    char const* user_agent = nullptr;
    char const* binary = nullptr;
    char const* path = nullptr;
    size_t user_agent_len = 0;
    size_t binary_len = 0;
    size_t path_len = 0;

    bool got_path = ucall_request_param(call, "path", 0, &path, &path_len);
    bool got_bin = ucall_request_body(call, &binary, &binary_len);
    bool got_head = ucall_request_header(call, "User-Agent", 0, &user_agent, &user_agent_len);
    if (!got_bin || !got_head) return ucall_reply_error_invalid_params(call);

    std::string res = "{\"uploaded_binary_size\": " + std::to_string(binary_len) + "}";
    ucall_reply_content(call, res.data(), res.size());
}

static void get_books(ucall_message_t call, ucall_endpoint_tag_t punned_books) noexcept {
    auto* books = reinterpret_cast<std::map<std::size_t, std::string>*>(punned_books);
    std::string response = "{ \"books\": [";
    for (auto const& book : *books) response += "\"" + book.second + "\",";
    if (response[response.size() - 1] == ',') response.pop_back();
    response += "]}";

    ucall_reply_content(call, response.data(), response.size());
}

static void get_book_by_id(ucall_message_t call, ucall_endpoint_tag_t punned_books) noexcept {
    auto* books = reinterpret_cast<std::map<std::size_t, std::string>*>(punned_books);
    int64_t book_id;
    bool got_id = get_param_int_from_path(call, "id", &book_id);
    if (!got_id) return ucall_reply_error_invalid_params(call);

    auto found_book = books->find(static_cast<size_t>(book_id));

    if (found_book == books->end()) return ucall_reply_error(call, 404, "Book not found", 14);

    std::string response = "{ \"book\": \"" + found_book->second + "\" }";

    ucall_reply_content(call, response.data(), response.size());
}

static void add_book(ucall_message_t call, ucall_endpoint_tag_t punned_books) noexcept {
    auto* books = reinterpret_cast<std::map<std::size_t, std::string>*>(punned_books);
    ucall_string_t new_book;
    size_t new_book_len = 0;
    int64_t book_id = 0;
    bool got_book = ucall_request_param(call, "book_name", 0, &new_book, &new_book_len);
    bool got_id = ucall_param_named_i64(call, "book_id", 0, &book_id);
    if (!got_book || !got_id) return ucall_reply_error_invalid_params(call);

    std::string_view book_name(new_book, new_book_len);
    auto added_book = books->emplace(static_cast<size_t>(book_id), book_name);

    if (!added_book.second) return ucall_reply_error(call, 409, "Book with given Id already exists", 33);

    std::string response = "{ \"book\": \"" + std::string(book_name) + "\" }";

    ucall_reply_content(call, response.data(), response.size());
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

    ucall_server_t server {};
    ucall_config_t config {};
    config.hostname = result["nic"].as<std::string>().c_str();
    config.port = result["port"].as<int>();
    config.max_threads = result["threads"].as<int>();
    config.max_concurrent_connections = 1024;
    config.queue_depth = 4096 * config.max_threads;
    config.max_lifetime_exchanges = UINT32_MAX;
    config.logs_file_descriptor = result["silent"].as<bool>() ? -1 : fileno(stdin);
    config.logs_format = "human";
    config.protocol = protocol_kind_t::rest_k;
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
    if (result["silent"].as<bool>()) std::printf("- silent\n");

    std::map<std::size_t, std::string> books;

    // Add all the callbacks we need
    ucall_add_endpoint(server, "/books", &get_books, ucall_verb_t::get_k, &books);
    ucall_add_endpoint(server, "/books", &add_book, ucall_verb_t::post_k, &books);
    ucall_add_endpoint(server, "/books/{id}", &get_book_by_id, ucall_verb_t::get_k, &books);

    ucall_add_endpoint(server, "/validate_session/{session_id}", &validate_session, ucall_verb_t::get_k, nullptr);

    ucall_add_endpoint(server, "/upload_binary/{path}", &upload_binary, ucall_verb_t::put_k, nullptr);

    if (config.max_threads > 1) {
        std::vector<std::thread> threads;
        for (uint16_t i = 0; i != config.max_threads; ++i) threads.emplace_back(&ucall_take_calls, server, i);
        for (auto& thread : threads) thread.join();
    }
    else ucall_take_calls(server, 0);

    ucall_free(server);
    return 0;
}
