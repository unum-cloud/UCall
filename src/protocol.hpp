#pragma once

#include <variant>

#include "containers.hpp"
#include "parse/protocol/http.hpp"
#include "parse/protocol/jsonrpc.hpp"
#include "parse/protocol/rest.hpp"
#include "parse/protocol/tcp.hpp"
#include "shared.hpp"
#include "ucall/ucall.h"

namespace unum::ucall {

class protocol_t {
  private:
    using protocol_variants_t = std::variant<tcp_protocol_t, http_protocol_t, jsonrpc_protocol_t<tcp_protocol_t>,
                                             jsonrpc_protocol_t<http_protocol_t>, rest_protocol_t>;

    protocol_variants_t sp_proto;
    protocol_type_t type;

  public:
    explicit protocol_t(protocol_type_t = protocol_type_t::tcp_k) noexcept;

    void reset_protocol(protocol_type_t) noexcept;

    void reset() noexcept;

    std::string_view get_content() const noexcept;
    request_type_t get_request_type() const noexcept;
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

    template <typename calle_at> std::optional<default_error_t> populate_response(exchange_pipes_t&, calle_at) noexcept;
};

protocol_t::protocol_t(protocol_type_t p_type) noexcept : sp_proto({}), type(p_type) { reset_protocol(p_type); }

void protocol_t::reset_protocol(protocol_type_t p_type) noexcept {
    type = p_type;
    switch (type) {
    case protocol_type_t::tcp_k:
        sp_proto.emplace<tcp_protocol_t>();
        break;
    case protocol_type_t::http_k:
        sp_proto.emplace<http_protocol_t>();
        break;
    case protocol_type_t::jsonrpc_tcp_k:
        sp_proto.emplace<jsonrpc_protocol_t<tcp_protocol_t>>();
        break;
    case protocol_type_t::jsonrpc_http_k:
        sp_proto.emplace<jsonrpc_protocol_t<http_protocol_t>>();
        break;
    case protocol_type_t::rest_k:
        sp_proto.emplace<rest_protocol_t>();
        break;
    }
}

void protocol_t::reset() noexcept {
    switch (type) {
    case protocol_type_t::tcp_k:
        return std::get<tcp_protocol_t>(sp_proto).reset();
    case protocol_type_t::http_k:
        return std::get<http_protocol_t>(sp_proto).reset();
    case protocol_type_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(sp_proto).reset();
    case protocol_type_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(sp_proto).reset();
    case protocol_type_t::rest_k:
        return std::get<rest_protocol_t>(sp_proto).reset();
    }
}

inline std::string_view protocol_t::get_content() const noexcept {
    switch (type) {
    case protocol_type_t::tcp_k:
        return std::get<tcp_protocol_t>(sp_proto).get_content();
    case protocol_type_t::http_k:
        return std::get<http_protocol_t>(sp_proto).get_content();
    case protocol_type_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(sp_proto).get_content();
    case protocol_type_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(sp_proto).get_content();
    case protocol_type_t::rest_k:
        return std::get<rest_protocol_t>(sp_proto).get_content();
    }

    return {};
}

inline request_type_t protocol_t::get_request_type() const noexcept {
    switch (type) {
    case protocol_type_t::tcp_k:
        return std::get<tcp_protocol_t>(sp_proto).get_request_type();
    case protocol_type_t::http_k:
        return std::get<http_protocol_t>(sp_proto).get_request_type();
    case protocol_type_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(sp_proto).get_request_type();
    case protocol_type_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(sp_proto).get_request_type();
    case protocol_type_t::rest_k:
        return std::get<rest_protocol_t>(sp_proto).get_request_type();
    }

    return request_type_t::post_k;
}

inline any_param_t protocol_t::get_param(size_t param_idx) const noexcept {
    switch (type) {
    case protocol_type_t::tcp_k:
        return std::get<tcp_protocol_t>(sp_proto).get_param(param_idx);
    case protocol_type_t::http_k:
        return std::get<http_protocol_t>(sp_proto).get_param(param_idx);
    case protocol_type_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(sp_proto).get_param(param_idx);
    case protocol_type_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(sp_proto).get_param(param_idx);
    case protocol_type_t::rest_k:
        return std::get<rest_protocol_t>(sp_proto).get_param(param_idx);
    }

    return nullptr;
}

inline any_param_t protocol_t::get_param(std::string_view param_name) const noexcept {
    switch (type) {
    case protocol_type_t::tcp_k:
        return std::get<tcp_protocol_t>(sp_proto).get_param(param_name);
    case protocol_type_t::http_k:
        return std::get<http_protocol_t>(sp_proto).get_param(param_name);
    case protocol_type_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(sp_proto).get_param(param_name);
    case protocol_type_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(sp_proto).get_param(param_name);
    case protocol_type_t::rest_k:
        return std::get<rest_protocol_t>(sp_proto).get_param(param_name);
    }

    return nullptr;
}

inline std::string_view protocol_t::get_header(std::string_view header_name) const noexcept {
    switch (type) {
    case protocol_type_t::tcp_k:
        return std::get<tcp_protocol_t>(sp_proto).get_header(header_name);
    case protocol_type_t::http_k:
        return std::get<http_protocol_t>(sp_proto).get_header(header_name);
    case protocol_type_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(sp_proto).get_header(header_name);
    case protocol_type_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(sp_proto).get_header(header_name);
    case protocol_type_t::rest_k:
        return std::get<rest_protocol_t>(sp_proto).get_header(header_name);
    }

    return std::string_view();
}

void protocol_t::prepare_response(exchange_pipes_t& pipes) noexcept {
    switch (type) {
    case protocol_type_t::tcp_k:
        return std::get<tcp_protocol_t>(sp_proto).prepare_response(pipes);
    case protocol_type_t::http_k:
        return std::get<http_protocol_t>(sp_proto).prepare_response(pipes);
    case protocol_type_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(sp_proto).prepare_response(pipes);
    case protocol_type_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(sp_proto).prepare_response(pipes);
    case protocol_type_t::rest_k:
        return std::get<rest_protocol_t>(sp_proto).prepare_response(pipes);
    }
}

bool protocol_t::append_response(exchange_pipes_t& pipes, std::string_view response) noexcept {
    switch (type) {
    case protocol_type_t::tcp_k:
        return std::get<tcp_protocol_t>(sp_proto).append_response(pipes, response);
    case protocol_type_t::http_k:
        return std::get<http_protocol_t>(sp_proto).append_response(pipes, response);
    case protocol_type_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(sp_proto).append_response(pipes, response);
    case protocol_type_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(sp_proto).append_response(pipes, response);
    case protocol_type_t::rest_k:
        return std::get<rest_protocol_t>(sp_proto).append_response(pipes, response);
    }
    return false;
};

bool protocol_t::append_error(exchange_pipes_t& pipes, std::string_view error_code,
                              std::string_view response) noexcept {
    switch (type) {
    case protocol_type_t::tcp_k:
        return std::get<tcp_protocol_t>(sp_proto).append_error(pipes, error_code, response);
    case protocol_type_t::http_k:
        return std::get<http_protocol_t>(sp_proto).append_error(pipes, error_code, response);
    case protocol_type_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(sp_proto).append_error(pipes, error_code, response);
    case protocol_type_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(sp_proto).append_error(pipes, error_code, response);
    case protocol_type_t::rest_k:
        return std::get<rest_protocol_t>(sp_proto).append_error(pipes, error_code, response);
    }
    return false;
};

void protocol_t::finalize_response(exchange_pipes_t& pipes) noexcept {
    switch (type) {
    case protocol_type_t::tcp_k:
        return std::get<tcp_protocol_t>(sp_proto).finalize_response(pipes);
    case protocol_type_t::http_k:
        return std::get<http_protocol_t>(sp_proto).finalize_response(pipes);
    case protocol_type_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(sp_proto).finalize_response(pipes);
    case protocol_type_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(sp_proto).finalize_response(pipes);
    case protocol_type_t::rest_k:
        return std::get<rest_protocol_t>(sp_proto).finalize_response(pipes);
    }
};

bool protocol_t::is_input_complete(span_gt<char> input) noexcept {
    switch (type) {
    case protocol_type_t::tcp_k:
        return std::get<tcp_protocol_t>(sp_proto).is_input_complete(input);
    case protocol_type_t::http_k:
        return std::get<http_protocol_t>(sp_proto).is_input_complete(input);
    case protocol_type_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(sp_proto).is_input_complete(input);
    case protocol_type_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(sp_proto).is_input_complete(input);
    case protocol_type_t::rest_k:
        return std::get<rest_protocol_t>(sp_proto).is_input_complete(input);
    }
    return true;
};

std::optional<default_error_t> protocol_t::parse_headers(std::string_view body) noexcept {
    switch (type) {
    case protocol_type_t::tcp_k:
        return std::get<tcp_protocol_t>(sp_proto).parse_headers(body);
    case protocol_type_t::http_k:
        return std::get<http_protocol_t>(sp_proto).parse_headers(body);
    case protocol_type_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(sp_proto).parse_headers(body);
    case protocol_type_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(sp_proto).parse_headers(body);
    case protocol_type_t::rest_k:
        return std::get<rest_protocol_t>(sp_proto).parse_headers(body);
    }

    return default_error_t{-1, "Unknown"};
}

std::optional<default_error_t> protocol_t::parse_content() noexcept {
    switch (type) {
    case protocol_type_t::tcp_k:
        return std::get<tcp_protocol_t>(sp_proto).parse_content();
    case protocol_type_t::http_k:
        return std::get<http_protocol_t>(sp_proto).parse_content();
    case protocol_type_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(sp_proto).parse_content();
    case protocol_type_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(sp_proto).parse_content();
    case protocol_type_t::rest_k:
        return std::get<rest_protocol_t>(sp_proto).parse_content();
    }

    return default_error_t{-1, "Unknown"};
}

template <typename calle_at>
inline std::optional<default_error_t> protocol_t::populate_response(exchange_pipes_t& pipes, calle_at caller) noexcept {
    switch (type) {
    case protocol_type_t::tcp_k:
        return std::get<tcp_protocol_t>(sp_proto).populate_response(pipes, caller);
    case protocol_type_t::http_k:
        return std::get<http_protocol_t>(sp_proto).populate_response(pipes, caller);
    case protocol_type_t::jsonrpc_tcp_k:
        return std::get<jsonrpc_protocol_t<tcp_protocol_t>>(sp_proto).populate_response(pipes, caller);
    case protocol_type_t::jsonrpc_http_k:
        return std::get<jsonrpc_protocol_t<http_protocol_t>>(sp_proto).populate_response(pipes, caller);
    case protocol_type_t::rest_k:
        return std::get<rest_protocol_t>(sp_proto).populate_response(pipes, caller);
    }

    return default_error_t{-1, "Unknown"};
}

} // namespace unum::ucall
