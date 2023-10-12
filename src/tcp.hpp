#pragma once

#include <charconv>
#include <optional>

#include "containers.hpp"
#include "shared.hpp"

namespace unum::ucall {

struct tcp_protocol_t {
    static constexpr char tcp_termination_symbol = '\0';
    /// @brief Active parsed request
    parsed_request_t parsed{};

    std::string_view get_content() const noexcept;
    request_type_t get_request_type() const noexcept;
    any_param_t get_param(size_t) const noexcept;
    any_param_t get_param(std::string_view) const noexcept;
    std::string_view get_header(std::string_view) const noexcept;

    inline void prepare_response(exchange_pipes_t& pipes) noexcept;

    inline bool append_response(exchange_pipes_t&, std::string_view) noexcept;
    inline bool append_error(exchange_pipes_t&, std::string_view, std::string_view) noexcept;

    inline void finalize_response(exchange_pipes_t& pipes) noexcept;

    bool is_input_complete(span_gt<char> input) noexcept;

    inline void reset() noexcept;

    inline std::optional<default_error_t> parse_headers(std::string_view body) noexcept;
    inline std::optional<default_error_t> parse_content() noexcept;

    template <typename calle_at>
    std::optional<default_error_t> populate_response(exchange_pipes_t&, calle_at) noexcept {
        return std::nullopt;
    }
};

std::string_view tcp_protocol_t::get_content() const noexcept { return parsed.body; }

inline request_type_t tcp_protocol_t::get_request_type() const noexcept { return request_type_t::post_k; }

inline any_param_t tcp_protocol_t::get_param(size_t) const noexcept { return any_param_t(); }

inline any_param_t tcp_protocol_t::get_param(std::string_view) const noexcept { return any_param_t(); }

inline std::string_view tcp_protocol_t::get_header(std::string_view) const noexcept { return std::string_view(); }

inline void tcp_protocol_t::prepare_response(exchange_pipes_t& pipes) noexcept {}

inline bool tcp_protocol_t::append_response(exchange_pipes_t& pipes, std::string_view response) noexcept {
    return pipes.append_outputs(response);
};

inline bool tcp_protocol_t::append_error(exchange_pipes_t& pipes, std::string_view error_code,
                                         std::string_view message) noexcept {
    return pipes.append_outputs(error_code);
};

inline void tcp_protocol_t::finalize_response(exchange_pipes_t& pipes) noexcept {
    pipes.push_back_reserved(tcp_termination_symbol);
}

bool tcp_protocol_t::is_input_complete(span_gt<char> input) noexcept {
    return input[input.size() - 1] == tcp_termination_symbol;
}

void tcp_protocol_t::reset() noexcept {}

std::optional<default_error_t> tcp_protocol_t::parse_headers(std::string_view body) noexcept {
    parsed.body = body;
    parsed.body.remove_suffix(1);
    return std::nullopt;
}

std::optional<default_error_t> tcp_protocol_t::parse_content() noexcept { return std::nullopt; }

} // namespace unum::ucall
