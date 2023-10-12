#pragma once

#include <atomic>
#include <optional>

#include "connection.hpp"
#include "containers.hpp"
#include "log.hpp"
#include "network.hpp"
#include "parse/protocol/protocol.hpp"
#include "shared.hpp"

namespace unum::ucall {

struct named_callback_t {
    std::string_view name{};
    ucall_callback_t callback{};
    request_type_t type{};
    ucall_callback_tag_t callback_tag{};

    bool method_matches(std::string_view) const noexcept;
};

struct engine_t {

    /// @brief An array of function callbacks. Can be in dozens.
    array_gt<named_callback_t> callbacks{};

    void raise_request(exchange_pipes_t&, protocol_t&, ucall_call_t) const noexcept;

    void try_add_callback(named_callback_t&&) noexcept;
};

void engine_t::raise_request(exchange_pipes_t& pipes, protocol_t& protocol, ucall_call_t call) const noexcept {

    if (auto error_ptr = protocol.parse_headers(pipes.input_span()); error_ptr)
        return ucall_call_reply_error(call, error_ptr->code, error_ptr->note.data(), error_ptr->note.size());

    if (auto error_ptr = protocol.parse_content(); error_ptr)
        return ucall_call_reply_error(call, error_ptr->code, error_ptr->note.data(), error_ptr->note.size());

    protocol.prepare_response(pipes);
    auto error_ptr = protocol.populate_response(pipes, [&](std::string_view& method_name, request_type_t req_type) {
        auto callbacks_end = callbacks.data() + callbacks.size();
        auto callback_it =
            std::find_if(callbacks.data(), callbacks_end, [&](named_callback_t const& callback) noexcept {
                return callback.type == req_type && callback.method_matches(method_name);
            });
        if (callback_it == callbacks_end)
            return false;

        named_callback_t named_callback = *callback_it;
        method_name = named_callback.name;
        named_callback.callback(call, named_callback.callback_tag);
        return true;
    });
    if (error_ptr)
        return ucall_call_reply_error(call, error_ptr->code, error_ptr->note.data(), error_ptr->note.size());
    protocol.finalize_response(pipes);
}

inline void engine_t::try_add_callback(named_callback_t&& named) noexcept {
    if (callbacks.size() + 1 >= callbacks.capacity())
        return;

    callbacks.push_back_reserved(named);
}

bool named_callback_t::method_matches(std::string_view dynamic_name) const noexcept {
    auto first1 = dynamic_name.begin();
    auto end1 = dynamic_name.end();
    auto first2 = name.begin();
    auto end2 = name.end();
    while (first1 != end1 && first2 != end2) {
        if (*first2 == '{') {
            while (first2 != end2 && *first2++ != '}')
                ;

            while (first1 != end1 && *++first1 != *first2)
                ;

        } else if (*first1++ != *first2++)
            return false;
    }

    return first2 == end2 && first1 == end1;
}

} // namespace unum::ucall
