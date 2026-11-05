/**
 *  @file include/ucall/http/percent.hpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief Percent-decoding of paths and queries over StringZilla's URL unescape helper.
 */
#pragma once

#include <stringzilla/strings/serial.h> // `sz_strings_unescape_url_`, `sz_strings_walks_t`

#include "ucall/http/messages.hpp" // `byteset_kit`

namespace unum::ucall::http {

/** Percent-decoding whose search for escapes runs on @p byteset_kit_type_. */
template <typename byteset_kit_type_>
struct percent_codec {

    /** The kit's byteset search, as a match pointer the unescape walks below take. */
    static sz_cptr_t find_byteset(sz_cptr_t text, sz_size_t length, sz_byteset_t const* set) noexcept {
        sz_cptr_t match = nullptr;
        byteset_kit_type_::find_byteset(text, length, set, &match, nullptr);
        return match;
    }

    /** Decodes @p encoded into @p decoded, which may alias it, as @c ucall_decode_percent does. */
    static ucall_status_t decode(ucall_bytes_view_t encoded, ucall_byte_t* decoded, std::size_t* length,
                                 ucall_percent_mode_t mode) noexcept {
        auto source = reinterpret_cast<sz_cptr_t>(encoded.data);
        if (mode == ucall_percent_query_k) {
            // Spaces first, so an escaped `%2B` still decodes to a literal `+`.
            for (std::size_t index = 0; index != encoded.length; ++index)
                decoded[index] = encoded.data[index] == '+' ? ucall_byte_t {' '} : encoded.data[index];
            source = reinterpret_cast<sz_cptr_t>(decoded);
        }
        sz_strings_walks_t const walks {find_byteset, sz_strings_lookup_bytes_serial_};
        sz_size_t const written = sz_strings_unescape_url_(source, encoded.length, reinterpret_cast<sz_ptr_t>(decoded),
                                                           &walks);
        if (written == STRINGZILLA_SIZE_MAX) return ucall_status_invalid_argument_k;
        *length = written;
        return ucall_status_success_k;
    }
};

/** The percent codec over the widest byte-set search kit among the backends @p caps_ admits. */
template <sz_capability_t caps_>
using percent_kit = percent_codec<byteset_kit<caps_>>;

} // namespace unum::ucall::http
