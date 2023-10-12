#pragma once

#include <charconv>
#include <optional>

#include "containers.hpp"
#include "shared.hpp"
#include <simdjson.h>

namespace unum::ucall {

namespace sj = simdjson;
namespace sjd = sj::dom;

struct jsonrpc_obj_t {
    char printed_int_id[max_integer_length_k]{};

    sjd::element element{};
    std::string_view dynamic_id{};
    std::string_view method_name{};
};

template <typename base_protocol_t> struct jsonrpc_protocol_t {
    base_protocol_t base_proto{};
    jsonrpc_obj_t active_obj{};
    sjd::parser parser{};
    std::variant<sjd::element, sjd::array> elements{};

    inline any_param_t as_variant(sj::simdjson_result<sjd::element> const& elm) const noexcept;

    inline std::string_view get_content() const noexcept;
    request_type_t get_request_type() const noexcept;

    inline any_param_t get_param(std::string_view name) const noexcept;

    inline any_param_t get_param(std::size_t position) const noexcept;

    std::string_view get_header(std::string_view) const noexcept;

    std::optional<default_error_t> set_to(sjd::element const&) noexcept;

    inline void prepare_response(exchange_pipes_t& pipes) noexcept;

    bool append_response(exchange_pipes_t&, std::string_view) noexcept;
    bool append_error(exchange_pipes_t&, std::string_view, std::string_view) noexcept;

    inline void finalize_response(exchange_pipes_t& pipes) noexcept;

    bool is_input_complete(span_gt<char> input) noexcept;

    inline void reset() noexcept;

    inline std::optional<default_error_t> parse_headers(std::string_view body) noexcept;
    inline std::optional<default_error_t> parse_content() noexcept;

    template <typename calle_at> std::optional<default_error_t> populate_response(exchange_pipes_t&, calle_at) noexcept;
};

template <typename base_protocol_t>
inline void jsonrpc_protocol_t<base_protocol_t>::prepare_response(exchange_pipes_t& pipes) noexcept {
    base_proto.prepare_response(pipes);
    if (std::holds_alternative<sjd::array>(elements))
        pipes.push_back_reserved('[');
}

template <typename base_protocol_t>
inline bool jsonrpc_protocol_t<base_protocol_t>::append_response(exchange_pipes_t& pipes,
                                                                 std::string_view response) noexcept {
    // Communication example would be:
    // --> {"jsonrpc": "2.0", "method": "subtract", "params": [42, 23], "id": 1}
    // <-- {"jsonrpc": "2.0", "id": 1, "result": 19}
    if (active_obj.dynamic_id.empty())
        return true;
    if (!pipes.append_outputs({R"({"jsonrpc":"2.0","id":)", 22}))
        return false;
    if (!pipes.append_outputs(active_obj.dynamic_id))
        return false;
    if (!pipes.append_outputs({R"(,"result":)", 10}))
        return false;
    if (!pipes.append_outputs(response))
        return false;
    if (!pipes.append_outputs({R"(},)", 2}))
        return false;
    return true;
}

template <typename base_protocol_t>
inline bool jsonrpc_protocol_t<base_protocol_t>::append_error(exchange_pipes_t& pipes, std::string_view error_code,
                                                              std::string_view message) noexcept {
    // Communication example would be:
    // --> {"jsonrpc": "2.0", "method": "foobar", "id": "1"}
    // <-- {"jsonrpc": "2.0", "id": "1", "error": {"code": -32601, "message": "Method not found"}}
    if (!pipes.append_outputs({R"({"jsonrpc":"2.0","id":)", 22}))
        return false;
    if (!pipes.append_outputs(active_obj.dynamic_id))
        return false;
    if (!pipes.append_outputs({R"(,"error":{"code":)", 17}))
        return false;
    if (!pipes.append_outputs(error_code))
        return false;
    if (!pipes.append_outputs({R"(,"message":")", 12}))
        return false;
    if (!pipes.append_outputs(message))
        return false;
    if (!pipes.append_outputs({R"("}})", 3}))
        return false;
    return true;
}

template <typename base_protocol_t>
inline void jsonrpc_protocol_t<base_protocol_t>::finalize_response(exchange_pipes_t& pipes) noexcept {
    // Drop last comma.
    if (pipes.output_span()[pipes.output_span().size() - 1] == ',')
        pipes.output_pop_back();

    if (std::holds_alternative<sjd::array>(elements))
        pipes.push_back_reserved(']');

    base_proto.finalize_response(pipes);
}

template <typename base_protocol_t>
bool jsonrpc_protocol_t<base_protocol_t>::is_input_complete(span_gt<char> input) noexcept {
    return base_proto.is_input_complete(input);
}

template <typename base_protocol_t> void jsonrpc_protocol_t<base_protocol_t>::reset() noexcept { base_proto.reset(); }

template <typename base_protocol_t>
inline std::optional<default_error_t>
jsonrpc_protocol_t<base_protocol_t>::parse_headers(std::string_view body) noexcept {
    return base_proto.parse_headers(body);
}

template <typename base_protocol_t>
inline std::optional<default_error_t> jsonrpc_protocol_t<base_protocol_t>::parse_content() noexcept {
    std::string_view json_doc = base_proto.get_content();

    if (json_doc.size() > parser.capacity()) {
        if (parser.allocate(json_doc.size(), json_doc.size() / 2) != sj::SUCCESS)
            return default_error_t{-32000, "Out of memory"};
        parser.set_max_capacity(json_doc.size());
    }

    auto one_or_many = parser.parse(json_doc.data(), json_doc.size(), false);

    if (one_or_many.error() == sj::CAPACITY)
        return default_error_t{-32000, "Out of memory"};

    if (one_or_many.error() != sj::SUCCESS)
        return default_error_t{-32700, "Invalid JSON was received by the server."};

    if (one_or_many.is_array())
        elements.emplace<sjd::array>(one_or_many.get_array().value_unsafe());
    else
        elements.emplace<sjd::element>(one_or_many.value_unsafe());

    return std::nullopt;
}

template <typename base_protocol_t>
inline any_param_t
jsonrpc_protocol_t<base_protocol_t>::as_variant(sj::simdjson_result<sjd::element> const& elm) const noexcept {
    if (elm.is_bool())
        return elm.get_bool().value_unsafe();
    if (elm.is_int64())
        return elm.get_int64().value_unsafe();
    if (elm.is_double())
        return elm.get_double().value_unsafe();
    if (elm.is_string())
        return elm.get_string().value_unsafe();
    return nullptr;
}

template <typename base_protocol_t>
inline std::string_view jsonrpc_protocol_t<base_protocol_t>::get_content() const noexcept {
    return base_proto.get_content();
}

template <typename base_protocol_t>
inline request_type_t jsonrpc_protocol_t<base_protocol_t>::get_request_type() const noexcept {
    return base_proto.get_request_type();
}

template <typename base_protocol_t>
inline any_param_t jsonrpc_protocol_t<base_protocol_t>::get_param(std::string_view name) const noexcept {
    char json_pointer[json_pointer_capacity_k]{};
    bool has_slash = name.size() && name.front() == '/';
    std::size_t final_size = name.size() + 8u - has_slash;
    if (final_size > json_pointer_capacity_k)
        return nullptr;
    std::memcpy((void*)json_pointer, "/params/", 8u);
    std::memcpy((void*)(json_pointer + 8u - has_slash), name.data(), name.size());
    return as_variant(active_obj.element.at_pointer({json_pointer, final_size}));
}

template <typename base_protocol_t>
inline any_param_t jsonrpc_protocol_t<base_protocol_t>::get_param(std::size_t position) const noexcept {
    char json_pointer[json_pointer_capacity_k]{};
    std::memcpy((void*)json_pointer, "/params/", 8u);
    std::to_chars_result res = std::to_chars(json_pointer + 8u, json_pointer + json_pointer_capacity_k, position);
    if (res.ec != std::errc(0))
        return nullptr;
    std::size_t final_size = res.ptr - json_pointer;
    return as_variant(active_obj.element.at_pointer({json_pointer, final_size}));
}

template <typename base_protocol_t>
inline std::string_view jsonrpc_protocol_t<base_protocol_t>::get_header(std::string_view header_name) const noexcept {
    return base_proto.get_header(header_name);
}

template <typename base_protocol_t>
std::optional<default_error_t> jsonrpc_protocol_t<base_protocol_t>::set_to(sjd::element const& doc) noexcept {
    if (!doc.is_object())
        return default_error_t{-32600, "The JSON sent is not a valid request object."};

    // We don't support JSON-RPC before version 2.0.
    sj::simdjson_result<sjd::element> version = doc["jsonrpc"];
    if (!version.is_string() || version.get_string().value_unsafe() != "2.0")
        return default_error_t{-32600, "The request doesn't specify the 2.0 version."};

    // Check if the shape of the request is correct:
    sj::simdjson_result<sjd::element> id = doc["id"];
    // SIMDJSON will consider a field a `double` even if it is simply convertible to it.
    bool id_invalid = (id.is_double() && !id.is_int64() && !id.is_uint64()) || id.is_object() || id.is_array();
    if (id_invalid)
        return default_error_t{-32600, "The request must have integer or string id."};
    sj::simdjson_result<sjd::element> method = doc["method"];
    bool method_invalid = !method.is_string();
    if (method_invalid)
        return default_error_t{-32600, "The method must be a string."};
    sj::simdjson_result<sjd::element> params = doc["params"];
    bool params_present_and_invalid = !params.is_array() && !params.is_object() && params.error() == sj::SUCCESS;
    if (params_present_and_invalid)
        return default_error_t{-32600, "Parameters can only be passed in arrays or objects."};

    if (id.is_string()) {
        active_obj.dynamic_id = id.get_string().value_unsafe();
    } else if (id.is_int64() || id.is_uint64()) {
        char* code = &active_obj.printed_int_id[0];
        std::to_chars_result res = std::to_chars(code, code + max_integer_length_k, id.get_int64().value_unsafe());
        auto code_len = res.ptr - code;
        if (res.ec != std::errc(0))
            return default_error_t{-32600, "The request ID is invalid integer."};
        active_obj.dynamic_id = std::string_view(code, code_len);
    } else
        active_obj.dynamic_id = "";

    active_obj.method_name = method.get_string().value_unsafe();
    active_obj.element = doc;
    return std::nullopt;
}

template <typename base_protocol_t>
template <typename calle_at>
inline std::optional<default_error_t>
jsonrpc_protocol_t<base_protocol_t>::populate_response(exchange_pipes_t& pipes, calle_at find_and_call) noexcept {
    if (std::holds_alternative<sjd::array>(elements)) {
        for (auto const& elm : std::get<sjd::array>(elements)) {
            set_to(elm);
            if (!find_and_call(active_obj.method_name, get_request_type()))
                return default_error_t{-32601, "Method not found"};
        }
    } else {
        set_to(std::get<sjd::element>(elements));
        if (!find_and_call(active_obj.method_name, get_request_type()))
            return default_error_t{-32601, "Method not found"};
    }

    return std::nullopt;
}

} // namespace unum::ucall
