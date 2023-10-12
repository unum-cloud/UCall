#pragma once

#include <charconv>
#include <optional>

#include "containers.hpp"
#include "parse/protocol/http.hpp"
#include "shared.hpp"
#include <simdjson.h>

namespace unum::ucall {

namespace sj = simdjson;
namespace sjd = sj::dom;

struct rest_obj {
    char printed_int_id[max_integer_length_k]{};

    sjd::element element{};
    std::string_view dynamic_id{};
    std::string_view method_name{};
};

struct rest_protocol_t {
    http_protocol_t base_proto{};
    rest_obj active_obj{};
    sjd::parser parser{};
    std::variant<std::nullptr_t, sjd::element, sjd::array> elements{};

    inline any_param_t as_variant(sj::simdjson_result<sjd::element> const& elm) const noexcept;

    inline std::string_view get_content() const noexcept;
    request_type_t get_request_type() const noexcept;

    inline any_param_t get_param(std::string_view name) const noexcept;

    inline any_param_t get_param(std::size_t position) const noexcept;

    std::string_view get_header(std::string_view) const noexcept;

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

inline void rest_protocol_t::prepare_response(exchange_pipes_t& pipes) noexcept { base_proto.prepare_response(pipes); }

inline bool rest_protocol_t::append_response(exchange_pipes_t& pipes, std::string_view response) noexcept {
    if (!pipes.append_outputs(response))
        return false;
    return true;
}

inline bool rest_protocol_t::append_error(exchange_pipes_t& pipes, std::string_view error_code,
                                          std::string_view message) noexcept {

    if (!pipes.append_outputs({R"({"error":)", 9}))
        return false;
    if (!pipes.append_outputs(error_code))
        return false;
    if (!pipes.append_outputs({R"(,"message":)", 11}))
        return false;
    if (!pipes.append_outputs(message))
        return false;
    if (!pipes.append_outputs({"}", 1}))
        return false;
    return true;
};

inline void rest_protocol_t::finalize_response(exchange_pipes_t& pipes) noexcept {
    // Drop last comma.
    if (pipes.output_span()[pipes.output_span().size() - 1] == ',')
        pipes.output_pop_back();

    base_proto.finalize_response(pipes);
}

bool rest_protocol_t::is_input_complete(span_gt<char> input) noexcept { return base_proto.is_input_complete(input); }

void rest_protocol_t::reset() noexcept { base_proto.reset(); }

inline std::optional<default_error_t> rest_protocol_t::parse_headers(std::string_view body) noexcept {
    return base_proto.parse_headers(body);
}

inline std::optional<default_error_t> rest_protocol_t::parse_content() noexcept {
    std::string_view json_doc = base_proto.get_content();
    if (base_proto.parsed.content_type != "application/json") {
        elements.emplace<std::nullptr_t>();
        return std::nullopt; // Only json parser is currently implemented
        // return default_error_t{415, "Unsupported: Only application/json is currently supported"};
    }
    if (json_doc.size() > parser.capacity()) {
        if (parser.allocate(json_doc.size(), json_doc.size() / 2) != sj::SUCCESS)
            return default_error_t{500, "Out of memory"};
        parser.set_max_capacity(json_doc.size());
    }

    auto one_or_many = parser.parse(json_doc.data(), json_doc.size(), false);

    if (one_or_many.error() == sj::CAPACITY)
        return default_error_t{500, "Out of memory"};

    if (one_or_many.error() != sj::SUCCESS)
        return default_error_t{400, "Invalid JSON was received by the server."};

    elements.emplace<sjd::element>(one_or_many.value_unsafe());

    return std::nullopt;
}

inline any_param_t rest_protocol_t::as_variant(sj::simdjson_result<sjd::element> const& elm) const noexcept {
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

inline std::string_view rest_protocol_t::get_content() const noexcept { return base_proto.get_content(); }

inline request_type_t rest_protocol_t::get_request_type() const noexcept { return base_proto.get_request_type(); }

inline any_param_t rest_protocol_t::get_param(std::string_view name) const noexcept {
    char json_pointer[json_pointer_capacity_k]{};
    bool has_slash = name.size() && name.front() == '/';
    std::size_t final_size = name.size() + 1u - has_slash;
    if (final_size > json_pointer_capacity_k)
        return nullptr;
    std::memcpy((void*)(json_pointer), "/", 1);
    std::memcpy((void*)(json_pointer + 1u - has_slash), name.data(), name.size());
    if (!std::holds_alternative<nullptr_t>(elements)) {
        auto from_body = as_variant(active_obj.element.at_pointer({json_pointer, final_size}));
        if (!std::holds_alternative<nullptr_t>(from_body))
            return from_body;
    }

    json_pointer[0] = '{';
    json_pointer[final_size++] = '}';
    size_t position_in_path = active_obj.method_name.find({json_pointer, final_size}, 0);
    if (position_in_path == std::string_view::npos)
        return nullptr;
    size_t len = std::count_if(base_proto.parsed.path.begin() + position_in_path, base_proto.parsed.path.end(),
                               [](char sym) { return sym != '/'; });
    return std::string_view{base_proto.parsed.path.data() + position_in_path, len};
}

inline any_param_t rest_protocol_t::get_param(std::size_t position) const noexcept { return nullptr; }

inline std::string_view rest_protocol_t::get_header(std::string_view header_name) const noexcept {
    return base_proto.get_header(header_name);
}

template <typename calle_at>
inline std::optional<default_error_t> rest_protocol_t::populate_response(exchange_pipes_t& pipes,
                                                                         calle_at find_and_call) noexcept {
    // if (std::holds_alternative<sjd::array>(elements)) {
    //     for (auto const& elm : std::get<sjd::array>(elements)) {
    //         set_to(elm);
    //         if (!find_and_call(get_method_name(), get_request_type()))
    //             return default_error_t{-32601, "Method not found"};
    //     }
    // } else {
    active_obj.method_name = base_proto.parsed.path;
    if (std::holds_alternative<sjd::element>(elements))
        active_obj.element = std::get<sjd::element>(elements);

    if (!find_and_call(active_obj.method_name, get_request_type()))
        return default_error_t{404, "Method not found"};
    // }

    return std::nullopt;
}

} // namespace unum::ucall
