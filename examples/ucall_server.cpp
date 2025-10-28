/**
 *  @brief  Example server application.
 *  @file   ucall_server.cpp
 *
 *  This module implements a pseudo-backend for benchmarking and demostration purposes for the
 *  UCall JSON-RPC implementation. It provides a simplified in-memory key-value store and image
 *  manipulation functions, alongside user management utilities.
 */
#include <cstdio>        // `std::printf`
#include <cstring>       // `std::memcpy`
#include <mutex>         // `std::unique_lock`
#include <new>           // `std::bad_alloc`
#include <shared_mutex>  // `std::shared_mutex`
#include <string>        // `std::string`
#include <string_view>   // `std::string_view`
#include <thread>        // `std::thread`
#include <unordered_set> // `std::unordered_set`

#include <cxxopts.hpp> // Parsing CLI arguments

#include <fmt/ranges.h>
#include <ucall/ucall.h>

/**
 * Echoes back the received data.
 *
 * @param call A ucall_call_t object that represents the RPC call context.
 * @param data A byte string received from the client.
 */
static void echo(ucall_call_t call, ucall_callback_tag_t) {
    ucall_str_t data_ptr{};
    std::size_t data_len{};
    if (!ucall_param_named_str(call, "data", 4, &data_ptr, &data_len)) {
        return ucall_call_reply_error_invalid_params(call);
    }
    ucall_call_reply_content(call, data_ptr, data_len);
}

/**
 * Validates if the session ID is valid for the given user ID based on a hashing scheme.
 *
 * @param call A ucall_call_t object that represents the RPC call context.
 * @param user_id The user's unique identifier as an integer.
 * @param session_id The session's unique identifier as an integer.
 */
static void validate_session(ucall_call_t call, ucall_callback_tag_t) {
    int64_t user_id{}, session_id{};
    if (!ucall_param_named_i64(call, "user_id", 7, &user_id) ||
        !ucall_param_named_i64(call, "session_id", 10, &session_id)) {
        return ucall_call_reply_error_invalid_params(call);
    }
    char const* res = ((user_id ^ session_id) % 23 == 0) ? "true" : "false";
    ucall_call_reply_content(call, res, strlen(res));
}

/**
 * Registers a new user with the given details and returns a summary.
 *
 * @param call A ucall_call_t object that represents the RPC call context.
 * @param age The user's age as an integer.
 * @param name The user's full name as a string.
 * @param avatar Binary data representing the user's avatar.
 * @param bio The user's biography as a string.
 */
static void create_user(ucall_call_t call, ucall_callback_tag_t) {
    ucall_str_t name_ptr{}, bio_ptr{}, avatar_ptr{};
    std::size_t name_len{}, bio_len{}, avatar_len{};
    int64_t age{};
    if (!ucall_param_named_i64(call, "age", 3, &age) || //
        !ucall_param_named_str(call, "name", 4, &name_ptr, &name_len) ||
        !ucall_param_named_str(call, "avatar", 6, &avatar_ptr, &avatar_len) ||
        !ucall_param_named_str(call, "bio", 3, &bio_ptr, &bio_len)) {
        return ucall_call_reply_error_invalid_params(call);
    }

    char result[1024];
    ucall_call_reply_content(call, result, strlen(result));
}

#include <stdexcept> // for std::invalid_argument
#include <string>    // for std::string
#include <vector>    // for std::vector

/**
 * Validates the user's identity similar to JWT. Showcases argument validation & exception handling in the C++ layer,
 * as well as complex structured returned values.
 *
 * @param call A ucall_call_t object that represents the RPC call context.
 * @param user_id An integer user identifier. Must be provided as a 64-bit integer.
 * @param name The user's name. Provided as a string.
 * @param age The user's age. Must be a floating-point number and over 18.
 * @param access_token A binary string representing an authentication token. Must start with the user's name.
 */
static void validate_user_identity(ucall_call_t call, ucall_callback_tag_t) {
    int64_t user_id{};
    double age{};
    ucall_str_t name_ptr{}, token_ptr{};
    std::size_t name_len{}, token_len{};

    if (!ucall_param_named_i64(call, "user_id", 7, &user_id) || !ucall_param_named_f64(call, "age", 3, &age) ||
        !ucall_param_named_str(call, "name", 4, &name_ptr, &name_len) ||
        !ucall_param_named_str(call, "access_token", 12, &token_ptr, &token_len)) {
        return ucall_call_reply_error_invalid_params(call);
    }

    char result[1024];
    std::vector<double> suggested_session_ids;
    // TODO: populate suggested_session_ids
    auto format_result = fmt::format_to_n(
        result,
        sizeof(result),
        "{{\n"
        "  \"session_ids\": [{0}],\n"
        "  \"user\": {{\n"
        "    \"name\": \"{1}\",\n"
        "    \"age\": {2},\n"
        "    \"user_id\": {3},\n"
        "    \"access_token\": \"{4}\",\n"
        "    \"repeated_sesson_ids\": [{0}]\n"
        "  }}\n"
        "}}",
        fmt::join(suggested_session_ids, ", "),
        fmt::string_view(name_ptr, name_len),
        age,
        user_id,
        fmt::string_view(token_ptr, token_len));
    if (format_result.size > sizeof(result)) {
      return ucall_call_reply_error_out_of_memory(call);
    }
    ucall_call_reply_content(call, result, format_result.size);
}

struct key_value_pair {
    char* key_and_value = nullptr;
    std::size_t key_length = 0;
    std::size_t value_length = 0;

    std::string_view key() const noexcept { return std::string_view(key_and_value, key_length); }
    std::string_view value() const noexcept { return std::string_view(key_and_value + key_length, value_length); }
    explicit operator bool() const noexcept { return key_length && value_length && key_and_value; }

    key_value_pair() = default;
    key_value_pair(std::string_view key, std::string_view value) : key_length(key.size()), value_length(value.size()) {
        std::size_t total_length = key_length + value_length;
        key_and_value = reinterpret_cast<char*>(std::malloc(total_length));
        if (total_length && !key_and_value)
            return; // Invalid state
        if (key_and_value)
            std::memcpy(key_and_value, key.data(), key_length),
                std::memcpy(key_and_value + key_length, value.data(), value_length);
        else
            key_length = value_length = 0;
    }
    key_value_pair(key_value_pair const& other) : key_length(other.key_length), value_length(other.value_length) {
        std::size_t total_length = key_length + value_length;
        key_and_value = reinterpret_cast<char*>(std::malloc(total_length));
        if (total_length && !key_and_value)
            return; // Invalid state
        if (key_and_value)
            std::memcpy(key_and_value, other.key_and_value, total_length);
        else
            key_length = value_length = 0;
    }
    key_value_pair(key_value_pair&& other) noexcept
        : key_and_value(other.key_and_value), key_length(other.key_length), value_length(other.value_length) {
        other.key_and_value = nullptr;
        other.key_length = other.value_length = 0;
    }
    key_value_pair& operator=(key_value_pair const& other) {
        if (this == &other)
            return *this;

        std::free(key_and_value);
        key_length = other.key_length;
        value_length = other.value_length;
        key_and_value = reinterpret_cast<char*>(std::malloc(key_length + value_length));
        if (key_and_value)
            std::memcpy(key_and_value, other.key_and_value, key_length + value_length);
        else
            key_length = value_length = 0;

        return *this;
    }
    key_value_pair& operator=(key_value_pair&& other) noexcept {
        if (this == &other)
            return *this;

        std::free(key_and_value);
        key_and_value = other.key_and_value;
        key_length = other.key_length;
        value_length = other.value_length;
        other.key_and_value = nullptr;
        other.key_length = other.value_length = 0;

        return *this;
    }
};

std::string_view get_key(key_value_pair const& pair) noexcept { return pair.key(); }
std::string_view get_key(std::string_view const& key) noexcept { return key; }

struct key_hash {
    using is_transparent = void;

    template <typename key_type> std::size_t operator()(key_type const& key) const noexcept {
        return std::hash<std::string_view>{}(get_key(key));
    }
};

struct key_equal {
    using is_transparent = void;

    template <typename first_at, typename second_at>
    bool operator()(first_at const& lhs, second_at const& rhs) const noexcept {
        return get_key(lhs) == get_key(rhs);
    }
};

static std::shared_mutex store_mutex;
static std::unordered_set<key_value_pair, key_hash, key_equal> store;

/**
 * Sets a key-value pair in the store.
 *
 * @param call A ucall_call_t object that represents the RPC call context.
 * @param key The key under which the value is stored as a string.
 * @param value The value to be stored as a string.
 */
static void set(ucall_call_t call, ucall_callback_tag_t) {
    ucall_str_t key_ptr{}, value_ptr{};
    std::size_t key_len{}, value_len{};
    if (!ucall_param_named_str(call, "key", 3, &key_ptr, &key_len) ||
        !ucall_param_named_str(call, "value", 5, &value_ptr, &value_len)) {
        return ucall_call_reply_error_invalid_params(call);
    }
    std::unique_lock<std::shared_mutex> lock(store_mutex);
    key_value_pair pair{std::string_view(key_ptr, key_len), std::string_view(value_ptr, value_len)};
    if (!pair)
        return ucall_call_reply_error_out_of_memory(call);
    store.insert(std::move(pair));
    ucall_call_reply_content(call, "OK", 2);
}

/**
 * Retrieves a value from the store based on the key.
 *
 * @param call A ucall_call_t object that represents the RPC call context.
 * @param key The key for which the value needs to be retrieved as a string.
 */
static void get(ucall_call_t call, ucall_callback_tag_t) {
    ucall_str_t key_ptr{};
    std::size_t key_len{};
    if (!ucall_param_named_str(call, "key", 3, &key_ptr, &key_len)) {
        return ucall_call_reply_error_invalid_params(call);
    }
    std::shared_lock<std::shared_mutex> lock(store_mutex);
    auto iterator = store.find(std::string_view(key_ptr, key_len));
    if (iterator == store.end())
        return ucall_call_reply_content(call, "", 0);
    else
        return ucall_call_reply_content(call, iterator->value().data(), iterator->value().size());
}

/**
 * Resizes an image provided as a binary string.
 *
 * @param call A ucall_call_t object that represents the RPC call context.
 * @param image A binary string that represents the image to resize.
 * @param width The target width as an integer.
 * @param height The target height as an integer.
 */
static void resize(ucall_call_t call, ucall_callback_tag_t) {
    ucall_str_t image_data{};
    std::size_t image_len{};
    int64_t width{}, height{};
    if (!ucall_param_named_str(call, "image", 5, &image_data, &image_len) ||
        !ucall_param_named_i64(call, "width", 5, &width) || !ucall_param_named_i64(call, "height", 6, &height)) {
        return ucall_call_reply_error_invalid_params(call);
    }

    char resized_image[1024]; // Placeholder for actual image processing logic
    ucall_call_reply_content(call, resized_image, strlen(resized_image));
}

/**
 * Resizes a batch of images provided as a list of binary strings.
 *
 * @param call A ucall_call_t object that represents the RPC call context.
 * @param images A list of binary strings each representing an image to resize.
 * @param width The target width for all images as an integer.
 * @param height The target height for all images as an integer.
 */
static void resize_batch(ucall_call_t call, ucall_callback_tag_t) {
    // Implementing batch processing might involve more complex data handling
    std::vector<std::string> images; // Placeholder for actual image processing logic
    int64_t width{}, height{};
    if (!ucall_param_named_i64(call, "width", 5, &width) || !ucall_param_named_i64(call, "height", 6, &height)) {
        return ucall_call_reply_error_invalid_params(call);
    }

    char result[1024]; // Placeholder for actual result
    ucall_call_reply_content(call, result, strlen(result));
}

/**
 * Calculates the dot product of two vectors provided as binary strings.
 *
 * @param call A ucall_call_t object that represents the RPC call context.
 * @param a A binary string representing the first vector.
 * @param b A binary string representing the second vector.
 */
static void dot_product(ucall_call_t call, ucall_callback_tag_t) {
    ucall_str_t a_data{}, b_data{};
    std::size_t a_len{}, b_len{};
    if (!ucall_param_named_str(call, "a", 1, &a_data, &a_len) ||
        !ucall_param_named_str(call, "b", 1, &b_data, &b_len)) {
        return ucall_call_reply_error_invalid_params(call);
    }

    // Assuming vector processing and dot product calculation
    char const* result = "0.0";
    ucall_call_reply_content(call, result, strlen(result));
}

/**
 * Calculates the dot products of multiple pairs of vectors provided as lists of binary strings.
 *
 * @param call A ucall_call_t object that represents the RPC call context.
 * @param a List of binary strings each representing a first vector in a pair.
 * @param b List of binary strings each representing a second vector in a pair.
 */
static void dot_product_batch(ucall_call_t call, ucall_callback_tag_t) {
    char const* result = "0.0";
    ucall_call_reply_content(call, result, strlen(result));
}

int main(int argc, char** argv) {

    auto server_description = "";

    cxxopts::Options options("UCall Example Server", server_description);
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

    // Initialize the server
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

    ucall_init(&config, &server);
    if (!server) {
        std::printf("Failed to initialize server!\n");
        return -1;
    }

    std::printf("Initialized server: %s:%i\n", config.hostname, config.port);
    std::printf("- %zu threads\n", static_cast<std::size_t>(config.max_threads));
    std::printf("- %zu max concurrent connections\n", static_cast<std::size_t>(config.max_concurrent_connections));
    if (result["silent"].as<bool>())
        std::printf("- silent\n");

    // Basic operations and types
    ucall_add_procedure(server, "echo", &echo, NULL);
    ucall_add_procedure(server, "validate_session", &validate_session, NULL);
    ucall_add_procedure(server, "create_user", &create_user, NULL);
    ucall_add_procedure(server, "validate_user_identity", &validate_user_identity, NULL);

    // Redis functionality
    ucall_add_procedure(server, "set", &set, NULL);
    ucall_add_procedure(server, "get", &get, NULL);

    // Rich data types
    ucall_add_procedure(server, "resize", &resize, NULL);
    ucall_add_procedure(server, "resize_batch", &resize_batch, NULL);
    ucall_add_procedure(server, "dot_product", &dot_product, NULL);
    ucall_add_procedure(server, "dot_product_batch", &dot_product_batch, NULL);

    // Start the server
    if (config.max_threads > 1) {
        // Allocate `config.max_threads - 1` threads in addition to the current one
        std::vector<std::thread> threads;
        for (uint16_t i = 1; i != config.max_threads; ++i)
            threads.emplace_back(&ucall_take_calls, server, i);
        // Populate the current main thread
        ucall_take_calls(server, 0);
        for (auto& thread : threads)
            thread.join();
    } else
        ucall_take_calls(server, 0);

    ucall_free(server);
    return 0;
}