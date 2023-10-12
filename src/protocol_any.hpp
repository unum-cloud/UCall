#pragma once

#include <variant>

#include "protocol_http.hpp"
#include "protocol_jsonrpc.hpp"
#include "protocol_rest.hpp"
#include "protocol_tcp.hpp"

namespace unum::ucall {

class protocol_t {
  private:
    using variant_t = std::variant<tcp_protocol_t, http_protocol_t, jsonrpc_protocol_t<tcp_protocol_t>,
                                   jsonrpc_protocol_t<http_protocol_t>, rest_protocol_t>;

    variant_t variant_;
    protocol_kind_t kind_;

  public:
    explicit protocol_t(protocol_kind_t = protocol_kind_t::tcp_k) noexcept;

    void reset_protocol(protocol_kind_t) noexcept;
    void reset() noexcept;

    std::string_view get_content() const noexcept;
    ucall_verb_t get_request_type() const noexcept;
    any_param_t get_param(size_t) const noexcept;
    any_param_t get_param(std::string_view) const noexcept;
    std::string_view get_header(std::string_view) const noexcept;

    void prepare_response(exchange_pipes_t&) noexcept;
    bool append_response(exchange_pipes_t&, std::string_view) noexcept;
    bool append_error(exchange_pipes_t&, std::string_view, std::string_view) noexcept;
    void finalize_response(exchange_pipes_t&) noexcept;

    bool is_input_complete(span_gt<char>) noexcept;

    std::optional<default_error_t> parse_headers(std::string_view) noexcept;
    std::optional<default_error_t> parse_content() noexcept;

    template <typename callee_at>
    std::optional<default_error_t> populate_response(exchange_pipes_t&, callee_at) noexcept;
};

protocol_t::protocol_t(protocol_kind_t kind) noexcept : variant_({}), kind_(kind) { reset_protocol(kind); }

void protocol_t::reset_protocol(protocol_kind_t kind) noexcept {
    kind_ = kind;
    switch (kind_) {
    case protocol_kind_t::tcp_k:
        variant_.emplace<tcp_protocol_t>();
        break;
    case protocol_kind_t::http_k:
        variant_.emplace<http_protocol_t>();
        break;
    case protocol_kind_t::jsonrpc_tcp_k:
        variant_.emplace<jsonrpc_protocol_t<tcp_protocol_t>>();
        break;
    case protocol_kind_t::jsonrpc_http_k:
        variant_.emplace<jsonrpc_protocol_t<http_protocol_t>>();
        break;
    case protocol_kind_t::rest_k:
        variant_.emplace<rest_protocol_t>();
        break;
    }
}

void protocol_t::reset() noexcept {
    switch (kind_) {
    case protocol_kind_t::tcp_k:
        return std::get<tcp_protocol_t>(variant_).reset();
    case protocol_kind_t::http_k:
        return std::get<http_protocol_t>(variant_).reset();
    case protocol_kind_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(variant_).reset();
    case protocol_kind_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(variant_).reset();
    case protocol_kind_t::rest_k:
        return std::get<rest_protocol_t>(variant_).reset();
    }
}

inline std::string_view protocol_t::get_content() const noexcept {
    switch (kind_) {
    case protocol_kind_t::tcp_k:
        return std::get<tcp_protocol_t>(variant_).get_content();
    case protocol_kind_t::http_k:
        return std::get<http_protocol_t>(variant_).get_content();
    case protocol_kind_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(variant_).get_content();
    case protocol_kind_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(variant_).get_content();
    case protocol_kind_t::rest_k:
        return std::get<rest_protocol_t>(variant_).get_content();
    }

    return {};
}

inline ucall_verb_t protocol_t::get_request_type() const noexcept {
    switch (kind_) {
    case protocol_kind_t::tcp_k:
        return std::get<tcp_protocol_t>(variant_).get_request_type();
    case protocol_kind_t::http_k:
        return std::get<http_protocol_t>(variant_).get_request_type();
    case protocol_kind_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(variant_).get_request_type();
    case protocol_kind_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(variant_).get_request_type();
    case protocol_kind_t::rest_k:
        return std::get<rest_protocol_t>(variant_).get_request_type();
    }

    return ucall_verb_t::post_k;
}

inline any_param_t protocol_t::get_param(size_t param_idx) const noexcept {
    switch (kind_) {
    case protocol_kind_t::tcp_k:
        return std::get<tcp_protocol_t>(variant_).get_param(param_idx);
    case protocol_kind_t::http_k:
        return std::get<http_protocol_t>(variant_).get_param(param_idx);
    case protocol_kind_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(variant_).get_param(param_idx);
    case protocol_kind_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(variant_).get_param(param_idx);
    case protocol_kind_t::rest_k:
        return std::get<rest_protocol_t>(variant_).get_param(param_idx);
    }

    return nullptr;
}

inline any_param_t protocol_t::get_param(std::string_view param_name) const noexcept {
    switch (kind_) {
    case protocol_kind_t::tcp_k:
        return std::get<tcp_protocol_t>(variant_).get_param(param_name);
    case protocol_kind_t::http_k:
        return std::get<http_protocol_t>(variant_).get_param(param_name);
    case protocol_kind_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(variant_).get_param(param_name);
    case protocol_kind_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(variant_).get_param(param_name);
    case protocol_kind_t::rest_k:
        return std::get<rest_protocol_t>(variant_).get_param(param_name);
    }

    return nullptr;
}

inline std::string_view protocol_t::get_header(std::string_view header_name) const noexcept {
    switch (kind_) {
    case protocol_kind_t::tcp_k:
        return std::get<tcp_protocol_t>(variant_).get_header(header_name);
    case protocol_kind_t::http_k:
        return std::get<http_protocol_t>(variant_).get_header(header_name);
    case protocol_kind_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(variant_).get_header(header_name);
    case protocol_kind_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(variant_).get_header(header_name);
    case protocol_kind_t::rest_k:
        return std::get<rest_protocol_t>(variant_).get_header(header_name);
    }

    return std::string_view();
}

void protocol_t::prepare_response(exchange_pipes_t& pipes) noexcept {
    switch (kind_) {
    case protocol_kind_t::tcp_k:
        return std::get<tcp_protocol_t>(variant_).prepare_response(pipes);
    case protocol_kind_t::http_k:
        return std::get<http_protocol_t>(variant_).prepare_response(pipes);
    case protocol_kind_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(variant_).prepare_response(pipes);
    case protocol_kind_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(variant_).prepare_response(pipes);
    case protocol_kind_t::rest_k:
        return std::get<rest_protocol_t>(variant_).prepare_response(pipes);
    }
}

bool protocol_t::append_response(exchange_pipes_t& pipes, std::string_view response) noexcept {
    switch (kind_) {
    case protocol_kind_t::tcp_k:
        return std::get<tcp_protocol_t>(variant_).append_response(pipes, response);
    case protocol_kind_t::http_k:
        return std::get<http_protocol_t>(variant_).append_response(pipes, response);
    case protocol_kind_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(variant_).append_response(pipes, response);
    case protocol_kind_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(variant_).append_response(pipes, response);
    case protocol_kind_t::rest_k:
        return std::get<rest_protocol_t>(variant_).append_response(pipes, response);
    }
    return false;
};

bool protocol_t::append_error(exchange_pipes_t& pipes, std::string_view error_code,
                              std::string_view response) noexcept {
    switch (kind_) {
    case protocol_kind_t::tcp_k:
        return std::get<tcp_protocol_t>(variant_).append_error(pipes, error_code, response);
    case protocol_kind_t::http_k:
        return std::get<http_protocol_t>(variant_).append_error(pipes, error_code, response);
    case protocol_kind_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(variant_).append_error(pipes, error_code, response);
    case protocol_kind_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(variant_).append_error(pipes, error_code, response);
    case protocol_kind_t::rest_k:
        return std::get<rest_protocol_t>(variant_).append_error(pipes, error_code, response);
    }
    return false;
};

void protocol_t::finalize_response(exchange_pipes_t& pipes) noexcept {
    switch (kind_) {
    case protocol_kind_t::tcp_k:
        return std::get<tcp_protocol_t>(variant_).finalize_response(pipes);
    case protocol_kind_t::http_k:
        return std::get<http_protocol_t>(variant_).finalize_response(pipes);
    case protocol_kind_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(variant_).finalize_response(pipes);
    case protocol_kind_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(variant_).finalize_response(pipes);
    case protocol_kind_t::rest_k:
        return std::get<rest_protocol_t>(variant_).finalize_response(pipes);
    }
};

bool protocol_t::is_input_complete(span_gt<char> input) noexcept {
    switch (kind_) {
    case protocol_kind_t::tcp_k:
        return std::get<tcp_protocol_t>(variant_).is_input_complete(input);
    case protocol_kind_t::http_k:
        return std::get<http_protocol_t>(variant_).is_input_complete(input);
    case protocol_kind_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(variant_).is_input_complete(input);
    case protocol_kind_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(variant_).is_input_complete(input);
    case protocol_kind_t::rest_k:
        return std::get<rest_protocol_t>(variant_).is_input_complete(input);
    }
    return true;
};

std::optional<default_error_t> protocol_t::parse_headers(std::string_view body) noexcept {
    switch (kind_) {
    case protocol_kind_t::tcp_k:
        return std::get<tcp_protocol_t>(variant_).parse_headers(body);
    case protocol_kind_t::http_k:
        return std::get<http_protocol_t>(variant_).parse_headers(body);
    case protocol_kind_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(variant_).parse_headers(body);
    case protocol_kind_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(variant_).parse_headers(body);
    case protocol_kind_t::rest_k:
        return std::get<rest_protocol_t>(variant_).parse_headers(body);
    }

    return default_error_t{-1, "Unknown"};
}

std::optional<default_error_t> protocol_t::parse_content() noexcept {
    switch (kind_) {
    case protocol_kind_t::tcp_k:
        return std::get<tcp_protocol_t>(variant_).parse_content();
    case protocol_kind_t::http_k:
        return std::get<http_protocol_t>(variant_).parse_content();
    case protocol_kind_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(variant_).parse_content();
    case protocol_kind_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(variant_).parse_content();
    case protocol_kind_t::rest_k:
        return std::get<rest_protocol_t>(variant_).parse_content();
    }

    return default_error_t{-1, "Unknown"};
}

template <typename callee_at>
inline std::optional<default_error_t> protocol_t::populate_response(exchange_pipes_t& pipes,
                                                                    callee_at caller) noexcept {
    switch (kind_) {
    case protocol_kind_t::tcp_k:
        return std::get<tcp_protocol_t>(variant_).populate_response(pipes, caller);
    case protocol_kind_t::http_k:
        return std::get<http_protocol_t>(variant_).populate_response(pipes, caller);
    case protocol_kind_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(variant_).populate_response(pipes, caller);
    case protocol_kind_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(variant_).populate_response(pipes, caller);
    case protocol_kind_t::rest_k:
        return std::get<rest_protocol_t>(variant_).populate_response(pipes, caller);
    }

    return default_error_t{-1, "Unknown"};
}

} // namespace unum::ucall
