/**
 * @brief Example of building a Redis-like in-memory store with UCall.
 *
 * @see Reading materials on using the C++ PyTorch Frontend.
 * https://pytorch.org/tutorials/advanced/cpp_frontend.html
 * https://pytorch.org/cppdocs/installing.html
 */
#include <cstdio> // `std::printf`
#include <string>
#include <unordered_map>

#include <torch/torch.h>

#include "ucall/ucall.h"

static std::unordered_map<std::string, std::string> store;

static void summarize(ucall_message_t call) {
    char const* text_ptr{};
    size_t text_len{};
    bool text_found = ucall_request_param(call, "text", 3, &text_ptr, &text_len);
    if (!text_found)
        return ucall_reply_error_invalid_params(call);

    return ucall_reply_content(call, "OK", 2);
}

static void continue_(ucall_message_t call) {
    char const* text_ptr{};
    size_t text_len{};
    bool text_found = ucall_request_param(call, "text", 4, &text_ptr, &text_len);
    if (!text_found)
        return ucall_reply_error_invalid_params(call);

    return ucall_reply_content(call, "", 0);
}

int main(int argc, char** argv) {
    ucall_server_t server{};
    ucall_config_t config{};
    config.port = 6379;
    ucall_init(&config, &server);
    if (!server) {
        std::printf("Failed to initialize server!\n");
        return -1;
    }

    std::printf("Initialized server!\n");
    ucall_add_endpoint(server, "summarize", &summarize);
    ucall_add_endpoint(server, "continue", &continue_);

    ucall_take_calls(server, 0);
    ucall_free(server);
    return 0;
}