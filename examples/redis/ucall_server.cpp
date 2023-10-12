/**
 * @brief Example of building a Redis-like in-memory store with UCall.
 */
#include <cstdio> // `std::printf`
#include <string>
#include <unordered_map>

#include "ucall/ucall.h"

static std::unordered_map<std::string, std::string> store;

static void set(ucall_message_t call) {
    char const* key_ptr{};
    char const* value_ptr{};
    size_t key_len{};
    size_t value_len{};
    bool key_found = ucall_request_param(call, "key", 3, &key_ptr, &key_len);
    bool value_found = ucall_request_param(call, "value", 5, &value_ptr, &value_len);
    if (!key_found || !value_found)
        return ucall_reply_error_invalid_params(call);

    store.insert_or_assign(std::string_view{key_ptr, key_len}, std::string_view{value_ptr, value_len});
    return ucall_reply_content(call, "OK", 2);
}

static void get(ucall_message_t call) {
    char const* key_ptr{};
    size_t key_len{};
    bool key_found = ucall_request_param(call, "key", 4, &key_ptr, &key_len);
    if (!key_found)
        return ucall_reply_error_invalid_params(call);

    auto iterator = store.find(std::string_view{key_ptr, key_len});
    if (iterator == store.end())
        return ucall_reply_content(call, "", 0);
    else
        return ucall_reply_content(call, iterator.second.c_str(), iterator.second.size());
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
    ucall_add_endpoint(server, "set", &set);
    ucall_add_endpoint(server, "get", &get);

    ucall_take_calls(server, 0);
    ucall_free(server);
    return 0;
}