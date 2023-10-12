#pragma once

#include <charconv>
#include <optional>
#include <picohttpparser.h>
#include <string_view>
#include <variant>

#include "containers.hpp"
#include "shared.hpp"

namespace unum::ucall {

// TODO Let higher protocols modify, add, remove Headers
static constexpr char const* http_header_k =
    "HTTP/1.1 200 OK\r\nContent-Length:          \r\nContent-Type: application/json\r\n\r\n";
static constexpr std::size_t http_header_size_k = 78;
static constexpr std::size_t http_header_length_offset_k = 33;
static constexpr std::size_t http_header_length_capacity_k = 9;
static constexpr std::size_t http_max_headers_k = 32;

struct http_protocol_t {
    /// @brief Expected receiving/sending length extracted from HTTP headers.
    std::optional<std::size_t> content_length{};
    /// @brief Active parsed request
    parsed_request_t parsed{};

    phr_header headers[http_max_headers_k]{};
    size_t count_headers = http_max_headers_k;

    std::string_view get_content() const noexcept;
    request_type_t get_request_type() const noexcept;
    any_param_t get_param(size_t) const noexcept;
    any_param_t get_param(std::string_view) const noexcept;
    std::string_view get_header(std::string_view) const noexcept;

    inline void prepare_response(exchange_pipes_t& pipes) noexcept;

    inline bool append_response(exchange_pipes_t&, std::string_view) noexcept;
    inline bool append_error(exchange_pipes_t&, std::string_view, std::string_view) noexcept;

    inline void finalize_response(exchange_pipes_t& pipes) noexcept;

    inline void reset() noexcept;

    bool is_input_complete(span_gt<char> input) noexcept;

    /**
     * @brief Analyzes the contents of the packet, bifurcating pure JSON-RPC from HTTP1-based.
     * @warning This doesn't check the headers for validity or additional metadata.
     */
    inline std::optional<default_error_t> parse_headers(std::string_view body) noexcept;
    inline std::optional<default_error_t> parse_content() noexcept { return std::nullopt; };

    template <typename calle_at>
    std::optional<default_error_t> populate_response(exchange_pipes_t&, calle_at) noexcept {
        return std::nullopt;
    }
};

inline void http_protocol_t::prepare_response(exchange_pipes_t& pipes) noexcept {
    pipes.append_reserved(http_header_k, http_header_size_k);
    content_length = pipes.output_span().size();
}

inline bool http_protocol_t::append_response(exchange_pipes_t& pipes, std::string_view response) noexcept {
    return pipes.append_outputs(response);
}

inline bool http_protocol_t::append_error(exchange_pipes_t& pipes, std::string_view error_code,
                                          std::string_view message) noexcept {
    return pipes.append_outputs(error_code);
}

inline void http_protocol_t::finalize_response(exchange_pipes_t& pipes) noexcept {
    auto output = pipes.output_span();
    content_length = output.size() - *content_length;
    auto res =
        std::to_chars(output.data() + http_header_length_offset_k,
                      output.data() + http_header_length_offset_k + http_header_length_capacity_k, *content_length);

    if (res.ec != std::errc()) {
        // TODO Return error
    }
}

void http_protocol_t::reset() noexcept { content_length.reset(); }

std::string_view http_protocol_t::get_content() const noexcept { return parsed.body; }

inline request_type_t http_protocol_t::get_request_type() const noexcept { return parsed.type; }

inline any_param_t http_protocol_t::get_param(size_t) const noexcept { return any_param_t(); }

inline any_param_t http_protocol_t::get_param(std::string_view) const noexcept { return any_param_t(); }

inline std::string_view http_protocol_t::get_header(std::string_view header_name) const noexcept {
    for (std::size_t i = 0; i < count_headers; ++i) {
        if (headers[i].name_len == 0)
            continue;
        if (std::string_view(headers[i].name, headers[i].name_len) == header_name)
            return std::string_view(headers[i].value, headers[i].value_len);
    }
    return std::string_view();
}

bool http_protocol_t::is_input_complete(span_gt<char> input) noexcept {

    if (!content_length) {
        size_t bytes_expected = 0;

        auto json_or_error = parse_headers(std::string_view(input.data(), input.size()));
        if (json_or_error)
            return false;

        auto res = std::from_chars(parsed.content_length.data(),
                                   parsed.content_length.data() + parsed.content_length.size(), bytes_expected);
        bytes_expected += (parsed.body.data() - input.data());

        content_length = bytes_expected;
    }

    return input.size() >= content_length;
}

/**
 * @brief Analyzes the contents of the packet, bifurcating pure JSON-RPC from HTTP1-based.
 * @warning This doesn't check the headers for validity or additional metadata.
 */
inline std::optional<default_error_t> http_protocol_t::parse_headers(std::string_view body) noexcept {

    char const* method{};
    size_t method_len{};
    char const* path{};
    size_t path_len{};
    int minor_version{};
    count_headers = http_max_headers_k;

    int res = phr_parse_request(body.data(), body.size(), &method, &method_len, &path, &path_len, &minor_version,
                                headers, &count_headers, 0);

    if (res == -2)
        return default_error_t{206, "Partial HTTP request"};

    if (res < 0)
        return default_error_t{400, "Not a HTTP request"};

    parsed.path = std::string_view(path, path_len);
    auto type_str = std::string_view(method, method_len);
    if (type_str == "GET")
        parsed.type = get_k;
    else if (type_str == "PUT")
        parsed.type = put_k;
    else if (type_str == "POST")
        parsed.type = post_k;
    else if (type_str == "DELETE")
        parsed.type = delete_k;
    else
        return default_error_t{405, "Unsupported request type"};

    for (std::size_t i = 0; i < count_headers; ++i) {
        if (headers[i].name_len == 0)
            continue;
        if (std::string_view(headers[i].name, headers[i].name_len) == std::string_view("Content-Type"))
            parsed.content_type = std::string_view(headers[i].value, headers[i].value_len);
        else if (std::string_view(headers[i].name, headers[i].name_len) == std::string_view("Content-Length"))
            parsed.content_length = std::string_view(headers[i].value, headers[i].value_len);
    }

    auto pos = body.find("\r\n\r\n");
    if (pos != std::string_view::npos)
        parsed.body = body.substr(pos + 4);

    return std::nullopt;
}

} // namespace unum::ucall
