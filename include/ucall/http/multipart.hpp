/**
 *  @file include/ucall/http/multipart.hpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief Splitting @c multipart/form-data bodies into parts, and the header fields they carry.
 */
#pragma once

#include <cstdint> // `std::uint64_t`

#include <string_view> // `std::string_view`

#include "ucall/utilities/types.hpp" // `st::failed`

namespace unum::ucall::http {

/** The value of parameter @p name in a header value such as <tt>form-data; name="x"</tt>,
 *  unquoted but not unescaped, or an empty dataless view. */
template <typename search_type_>
std::string_view header_parameter(std::string_view value, std::string_view name) noexcept {
    for (std::size_t cursor = search_type_::find(value, ';'); cursor != std::string_view::npos;) {
        auto rest = value.substr(cursor + 1);
        auto const equals = search_type_::find(rest, '=');
        if (equals == std::string_view::npos) return {};
        auto const key = search_type_::trim_http(rest.substr(0, equals));
        rest = search_type_::trim_http(rest.substr(equals + 1));
        std::string_view found;
        std::size_t next = 0;
        if (!rest.empty() && rest.front() == '"') {
            std::size_t end = 1;
            while (end < rest.size() && rest[end] != '"') end += rest[end] == '\\' ? 2 : 1;
            if (end >= rest.size()) return {};
            found = rest.substr(1, end - 1);
            next = search_type_::find(rest, ';', end);
        }
        else {
            next = search_type_::find(rest, ';');
            found = search_type_::trim_http(rest.substr(0, next));
        }
        if (search_type_::equal_ascii_uncased(key, name)) return found;
        if (next == std::string_view::npos) return {};
        cursor = static_cast<std::size_t>(rest.data() - value.data()) + next;
    }
    return {};
}

/** The first field named @p name in a multipart part's header @p block, trimmed, or empty. */
template <typename search_type_>
std::string_view part_header(std::string_view block, std::string_view name) noexcept {
    for (std::size_t start = 0; start < block.size();) {
        auto end = fu::min_of(search_type_::find(block, "\r\n", start), block.size());
        auto const colon = search_type_::find(block, ':', start);
        if (colon < end && search_type_::equal_ascii_uncased(block.substr(start, colon - start), name))
            return search_type_::trim_http(block.substr(colon + 1, end - colon - 1));
        start = end + 2;
    }
    return {};
}

/** Splits a @c multipart/form-data @p body, whose @p content_type names the boundary, into @p parts
 *  as <tt>{offset, length}</tt> records from @p body_offset on: a delimiter is @c -- and the boundary at
 *  the body's start or after a CRLF, and the one followed by @c -- closes. Answers false for any
 *  other media type, a body without the closing delimiter, or a failed append. */
template <typename search_type_, typename parts_type_>
bool split_multipart(std::string_view content_type, std::string_view body, std::uint64_t body_offset,
                     parts_type_& parts) noexcept {
    using part_t = typename parts_type_::value_type;
    auto const media = search_type_::trim_http(content_type.substr(0, search_type_::find(content_type, ';')));
    auto const boundary = header_parameter<search_type_>(content_type, "boundary");
    if (!search_type_::equal_ascii_uncased(media, "multipart/form-data") || boundary.empty() || boundary.size() > 70)
        return false;
    std::size_t start = std::string_view::npos;
    for (std::size_t cursor = 0;;) {
        auto const match = search_type_::find(body, boundary, cursor);
        if (match == std::string_view::npos) return false;
        cursor = match + boundary.size();
        bool const leads = match == 2 && body.substr(0, 2) == "--";
        // A delimiter's CRLF belongs to the part before, so it never reaches into the prior line.
        bool const follows = match >= 4 && body.substr(match - 4, 4) == "\r\n--" &&
                             (start == std::string_view::npos || match - 4 >= start);
        if (!leads && !follows) continue;
        std::size_t const delimiter = leads ? 0 : match - 4;
        if (start != std::string_view::npos &&
            st::failed(parts.push_back(part_t {body_offset + start, static_cast<std::uint64_t>(delimiter - start)})))
            return false;
        if (body.substr(cursor, 2) == "--") return true;
        auto const line_end = search_type_::find(body, "\r\n", cursor);
        if (line_end == std::string_view::npos) return false;
        start = cursor = line_end + 2;
    }
}

} // namespace unum::ucall::http
