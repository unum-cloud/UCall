/**
 *  @file include/ucall/http.hpp
 *  @author Ash Vardanian
 *  @date July 21, 2023
 *  @brief Incremental HTTP framing and borrowed views, independent of sockets and event loops.
 */
#pragma once

#include <charconv>
#include <initializer_list>
#include <limits>
#include <string_view>

#include <stringzilla/capabilities.h>
#include <stringzilla/compare/serial.h>
#include <stringzilla/find/serial.h>
#include <stringzilla/hash/serial.h>
#include <stringzilla/utf8_uncased_fold/serial.h>
#if STRINGZILLA_TARGET_NEON
#include <stringzilla/compare/neon.h>
#include <stringzilla/find/neon.h>
#include <stringzilla/utf8_uncased_fold/neon.h>
#endif
#if STRINGZILLA_TARGET_NEONAES
#include <stringzilla/hash/neonaes.h>
#endif
#if STRINGZILLA_TARGET_SVE
#include <stringzilla/compare/sve.h>
#include <stringzilla/find/sve.h>
#endif
#if STRINGZILLA_TARGET_SVE2
#include <stringzilla/find/sve2.h>
#include <stringzilla/utf8_uncased_fold/sve2.h>
#endif
#if STRINGZILLA_TARGET_SVE2AES
#include <stringzilla/hash/sve2aes.h>
#endif
#if STRINGZILLA_TARGET_HASWELL
#include <stringzilla/compare/haswell.h>
#include <stringzilla/find/haswell.h>
#include <stringzilla/utf8_uncased_fold/haswell.h>
#endif
#if STRINGZILLA_TARGET_WESTMERE
#include <stringzilla/compare/westmere.h>
#include <stringzilla/find/westmere.h>
#include <stringzilla/hash/westmere.h>
#endif
#if STRINGZILLA_TARGET_SKYLAKE
#include <stringzilla/compare/skylake.h>
#include <stringzilla/find/skylake.h>
#include <stringzilla/hash/skylake.h>
#endif
#if STRINGZILLA_TARGET_ICELAKE
#include <stringzilla/find/icelake.h>
#include <stringzilla/hash/icelake.h>
#include <stringzilla/utf8_uncased_fold/icelake.h>
#endif

#include "ucall/types.hpp"

namespace unum::ucall {

#pragma region String Kits

/** Portable scalar kernels, the floor of every string ladder. */
struct serial_compare_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_serial_k;
    static constexpr bool compiled_k = true;
    static constexpr auto equal = sz_equal_serial;
};
struct serial_find_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_serial_k;
    static constexpr bool compiled_k = true;
    static constexpr auto find = sz_find_serial;
    static constexpr auto rfind = sz_rfind_serial;
};
struct serial_byteset_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_serial_k;
    static constexpr bool compiled_k = true;
    static constexpr auto find_byteset = sz_find_byteset_serial;
    static constexpr auto rfind_byteset = sz_rfind_byteset_serial;
};
struct serial_hash_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_serial_k;
    static constexpr bool compiled_k = true;
    static constexpr auto hash = sz_hash_serial;
};
struct serial_fold_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_serial_k;
    static constexpr bool compiled_k = true;
    static constexpr auto uncased_fold = sz_utf8_uncased_fold_serial;
};

#if STRINGZILLA_TARGET_SVE

/** Arm SVE with scalable vector lengths. */
struct sve_compare_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_sve_k;
    static constexpr bool compiled_k = true;
    static constexpr auto equal = sz_equal_sve;
};
struct sve_find_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_sve_k;
    static constexpr bool compiled_k = true;
    static constexpr auto find = sz_find_sve;
    static constexpr auto rfind = sz_rfind_sve;
};
#else

/** The kits this build cannot carry, kept so each ladder stays one list. */
struct sve_compare_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_sve_k;
    static constexpr bool compiled_k = false;
};
struct sve_find_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_sve_k;
    static constexpr bool compiled_k = false;
};
#endif // STRINGZILLA_TARGET_SVE

#if STRINGZILLA_TARGET_SVE2

/** Arm SVE2, whose byte matching serves the byte sets. */
struct sve2_byteset_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_sve2_k;
    static constexpr bool compiled_k = true;
    static constexpr auto find_byteset = sz_find_byteset_sve2;
    static constexpr auto rfind_byteset = sz_rfind_byteset_sve2;
};
struct sve2_fold_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_sve2_k;
    static constexpr bool compiled_k = true;
    static constexpr auto uncased_fold = sz_utf8_uncased_fold_sve2;
};
#else

/** The kits this build cannot carry, kept so each ladder stays one list. */
struct sve2_byteset_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_sve2_k;
    static constexpr bool compiled_k = false;
};
struct sve2_fold_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_sve2_k;
    static constexpr bool compiled_k = false;
};
#endif // STRINGZILLA_TARGET_SVE2

#if STRINGZILLA_TARGET_SVE2AES

/** Arm SVE2 with the AES extension. */
struct sve2aes_hash_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_sve2aes_k;
    static constexpr bool compiled_k = true;
    static constexpr auto hash = sz_hash_sve2aes;
};
#else

/** The kit this build cannot carry, kept so the ladder stays one list. */
struct sve2aes_hash_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_sve2aes_k;
    static constexpr bool compiled_k = false;
};
#endif // STRINGZILLA_TARGET_SVE2AES

#if STRINGZILLA_TARGET_SKYLAKE

/** Intel Skylake-X AVX-512. */
struct skylake_compare_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_skylake_k;
    static constexpr bool compiled_k = true;
    static constexpr auto equal = sz_equal_skylake;
};
struct skylake_find_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_skylake_k;
    static constexpr bool compiled_k = true;
    static constexpr auto find = sz_find_skylake;
    static constexpr auto rfind = sz_rfind_skylake;
};
struct skylake_hash_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_skylake_k;
    static constexpr bool compiled_k = true;
    static constexpr auto hash = sz_hash_skylake;
};
#else

/** The kits this build cannot carry, kept so each ladder stays one list. */
struct skylake_compare_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_skylake_k;
    static constexpr bool compiled_k = false;
};
struct skylake_find_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_skylake_k;
    static constexpr bool compiled_k = false;
};
struct skylake_hash_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_skylake_k;
    static constexpr bool compiled_k = false;
};
#endif // STRINGZILLA_TARGET_SKYLAKE

#if STRINGZILLA_TARGET_ICELAKE

/** Intel Ice Lake AVX-512 with VBMI and VAES. */
struct icelake_byteset_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_icelake_k;
    static constexpr bool compiled_k = true;
    static constexpr auto find_byteset = sz_find_byteset_icelake;
    static constexpr auto rfind_byteset = sz_rfind_byteset_icelake;
};
struct icelake_hash_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_icelake_k;
    static constexpr bool compiled_k = true;
    static constexpr auto hash = sz_hash_icelake;
};
struct icelake_fold_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_icelake_k;
    static constexpr bool compiled_k = true;
    static constexpr auto uncased_fold = sz_utf8_uncased_fold_icelake;
};
#else

/** The kits this build cannot carry, kept so each ladder stays one list. */
struct icelake_byteset_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_icelake_k;
    static constexpr bool compiled_k = false;
};
struct icelake_hash_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_icelake_k;
    static constexpr bool compiled_k = false;
};
struct icelake_fold_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_icelake_k;
    static constexpr bool compiled_k = false;
};
#endif // STRINGZILLA_TARGET_ICELAKE

#if STRINGZILLA_TARGET_NEON

/** Arm NEON. */
struct neon_compare_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_neon_k;
    static constexpr bool compiled_k = true;
    static constexpr auto equal = sz_equal_neon;
};
struct neon_find_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_neon_k;
    static constexpr bool compiled_k = true;
    static constexpr auto find = sz_find_neon;
    static constexpr auto rfind = sz_rfind_neon;
};
struct neon_byteset_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_neon_k;
    static constexpr bool compiled_k = true;
    static constexpr auto find_byteset = sz_find_byteset_neon;
    static constexpr auto rfind_byteset = sz_rfind_byteset_neon;
};
struct neon_fold_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_neon_k;
    static constexpr bool compiled_k = true;
    static constexpr auto uncased_fold = sz_utf8_uncased_fold_neon;
};
#else

/** The kits this build cannot carry, kept so each ladder stays one list. */
struct neon_compare_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_neon_k;
    static constexpr bool compiled_k = false;
};
struct neon_find_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_neon_k;
    static constexpr bool compiled_k = false;
};
struct neon_byteset_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_neon_k;
    static constexpr bool compiled_k = false;
};
struct neon_fold_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_neon_k;
    static constexpr bool compiled_k = false;
};
#endif // STRINGZILLA_TARGET_NEON

#if STRINGZILLA_TARGET_NEONAES

/** Arm NEON with the AES extension. */
struct neonaes_hash_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_neonaes_k;
    static constexpr bool compiled_k = true;
    static constexpr auto hash = sz_hash_neonaes;
};
#else

/** The kit this build cannot carry, kept so the ladder stays one list. */
struct neonaes_hash_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_neonaes_k;
    static constexpr bool compiled_k = false;
};
#endif // STRINGZILLA_TARGET_NEONAES

#if STRINGZILLA_TARGET_HASWELL

/** Intel Haswell AVX2. */
struct haswell_compare_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_haswell_k;
    static constexpr bool compiled_k = true;
    static constexpr auto equal = sz_equal_haswell;
};
struct haswell_find_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_haswell_k;
    static constexpr bool compiled_k = true;
    static constexpr auto find = sz_find_haswell;
    static constexpr auto rfind = sz_rfind_haswell;
};
struct haswell_byteset_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_haswell_k;
    static constexpr bool compiled_k = true;
    static constexpr auto find_byteset = sz_find_byteset_haswell;
    static constexpr auto rfind_byteset = sz_rfind_byteset_haswell;
};
struct haswell_fold_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_haswell_k;
    static constexpr bool compiled_k = true;
    static constexpr auto uncased_fold = sz_utf8_uncased_fold_haswell;
};
#else

/** The kits this build cannot carry, kept so each ladder stays one list. */
struct haswell_compare_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_haswell_k;
    static constexpr bool compiled_k = false;
};
struct haswell_find_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_haswell_k;
    static constexpr bool compiled_k = false;
};
struct haswell_byteset_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_haswell_k;
    static constexpr bool compiled_k = false;
};
struct haswell_fold_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_haswell_k;
    static constexpr bool compiled_k = false;
};
#endif // STRINGZILLA_TARGET_HASWELL

#if STRINGZILLA_TARGET_WESTMERE

/** Intel Westmere SSE4.2 with AES-NI. */
struct westmere_compare_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_westmere_k;
    static constexpr bool compiled_k = true;
    static constexpr auto equal = sz_equal_westmere;
};
struct westmere_find_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_westmere_k;
    static constexpr bool compiled_k = true;
    static constexpr auto find = sz_find_westmere;
    static constexpr auto rfind = sz_rfind_westmere;
};
struct westmere_hash_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_westmere_k;
    static constexpr bool compiled_k = true;
    static constexpr auto hash = sz_hash_westmere;
};
#else

/** The kits this build cannot carry, kept so each ladder stays one list. */
struct westmere_compare_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_westmere_k;
    static constexpr bool compiled_k = false;
};
struct westmere_find_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_westmere_k;
    static constexpr bool compiled_k = false;
};
struct westmere_hash_kit_t {
    static constexpr sz_capability_t capability_k = sz_cap_westmere_k;
    static constexpr bool compiled_k = false;
};
#endif // STRINGZILLA_TARGET_WESTMERE

/** The widest @c equal kit among the backends @p caps_ admits, newest first. */
template <sz_capability_t caps_>
using compare_kit = typename highest_kit<caps_, serial_compare_kit_t, sve_compare_kit_t, skylake_compare_kit_t,
                                         neon_compare_kit_t, haswell_compare_kit_t, westmere_compare_kit_t>::type;

/** The widest substring @c find and @c rfind kit among the backends @p caps_ admits. */
template <sz_capability_t caps_>
using find_kit = typename highest_kit<caps_, serial_find_kit_t, sve_find_kit_t, skylake_find_kit_t, neon_find_kit_t,
                                      haswell_find_kit_t, westmere_find_kit_t>::type;

/** The widest byte-set search kit among the backends @p caps_ admits. */
template <sz_capability_t caps_>
using byteset_kit = typename highest_kit<caps_, serial_byteset_kit_t, sve2_byteset_kit_t, icelake_byteset_kit_t,
                                         neon_byteset_kit_t, haswell_byteset_kit_t>::type;

/** The widest @c hash kit among the backends @p caps_ admits. */
template <sz_capability_t caps_>
using hash_kit = typename highest_kit<caps_, serial_hash_kit_t, sve2aes_hash_kit_t, icelake_hash_kit_t,
                                      skylake_hash_kit_t, neonaes_hash_kit_t, westmere_hash_kit_t>::type;

/** The widest UTF-8 case-folding kit among the backends @p caps_ admits. */
template <sz_capability_t caps_>
using fold_kit = typename highest_kit<caps_, serial_fold_kit_t, sve2_fold_kit_t, icelake_fold_kit_t, neon_fold_kit_t,
                                      haswell_fold_kit_t>::type;

/** Every byte @p predicate admits, as a set built at compile time. */
template <typename predicate_type_>
constexpr sz_byteset_t byteset_where(predicate_type_ predicate) noexcept {
    sz_byteset_t result {};
    for (unsigned byte = 0; byte != 256; ++byte)
        if (predicate(static_cast<sz_u8_t>(byte))) sz_byteset_add_u8(&result, static_cast<sz_u8_t>(byte));
    return result;
}

/** Bytes outside RFC 9110 @c tchar, which no method or field name may hold. */
inline constexpr sz_byteset_t http_non_token_bytes_k = byteset_where([](sz_u8_t byte) noexcept {
    return std::string_view {"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"}.find(
               static_cast<char>(byte)) == std::string_view::npos;
});

/** Control bytes other than the tab, which no field value may hold. */
inline constexpr sz_byteset_t http_control_bytes_k = byteset_where(
    [](sz_u8_t byte) noexcept { return (byte < 0x20 && byte != '\t') || byte == 0x7F; });

/** Bytes other than the spaces and tabs that pad a field value. */
inline constexpr sz_byteset_t http_non_padding_bytes_k = byteset_where(
    [](sz_u8_t byte) noexcept { return byte != ' ' && byte != '\t'; });

/** Bytes other than the slash that separates path segments. */
inline constexpr sz_byteset_t non_slash_bytes_k = byteset_where([](sz_u8_t byte) noexcept { return byte != '/'; });

#pragma endregion String Kits

enum class http_role_t { request_k, response_k, head_response_k };
enum class http_parse_t { incomplete_k, complete_k, malformed_k, unsupported_k, overflow_k };
enum class http_framing_t { length_k, chunked_k, until_close_k };
enum class http_connection_t { close_k, keep_alive_k };
enum class http_body_state_t { framed_k, decoded_k };
enum class http_chunk_state_t { size_k, payload_k, payload_end_k, trailers_k };

/** A received response keeps its bytes independently of the client and its CPU specialization. */
struct received_response_t : ucall_received_http_response_handle_t {
    span<byte_t const> content {};
    std::size_t headers_length {}, body_length {};
    ucall_http_status_t status {};
    void (*destroy)(received_response_t*) noexcept {};

    received_response_t() noexcept = default;
    received_response_t(received_response_t const&) = delete;
    received_response_t& operator=(received_response_t const&) = delete;
    received_response_t(received_response_t&&) = delete;
    received_response_t& operator=(received_response_t&&) = delete;
    span<byte_t const> bytes() const noexcept { return content; }
};

template <typename allocator_type_ = st::default_allocator<byte_t>>
struct received_response : received_response_t {
    st::basic_vector<byte_t, allocator_type_> storage;

    explicit received_response(allocator_type_ const& allocator) noexcept : storage(allocator) { destroy = &release; }
    received_response(received_response const&) = delete;
    received_response& operator=(received_response const&) = delete;
    received_response(received_response&&) = delete;
    received_response& operator=(received_response&&) = delete;

    static void release(received_response_t* response) noexcept {
        auto* owned = static_cast<received_response*>(response);
        using deleter_t = allocator_delete<received_response, allocator_type_>;
        deleter_t {typename deleter_t::allocator_t {owned->storage.get_allocator()}}(owned);
    }
};

extern template struct received_response<st::default_allocator<byte_t>>;

/** The text a byte vector holds, borrowing it. */
template <typename element_type_, typename allocator_type_>
std::string_view text_view(st::basic_vector<element_type_, allocator_type_> const& bytes) noexcept {
    static_assert(sizeof(element_type_) == 1);
    return {reinterpret_cast<char const*>(bytes.data()), bytes.size()};
}

template <typename compare_kit_type_, typename find_kit_type_, typename byteset_kit_type_, typename hash_kit_type_,
          typename fold_kit_type_>
struct http {
    using compare_kit_t = compare_kit_type_;
    using find_kit_t = find_kit_type_;
    using byteset_kit_t = byteset_kit_type_;
    using hash_kit_t = hash_kit_type_;
    using fold_kit_t = fold_kit_type_;

    static bool valid_view(ucall_bytes_view_t bytes) noexcept { return bytes.data || !bytes.length; }
    static bool equal(std::string_view left, std::string_view right) noexcept {
        if (left.size() != right.size()) return false;
        if (left.empty()) return true;
        sz_bool_t same;
        compare_kit_t::equal(left.data(), right.data(), left.size(), &same, nullptr);
        return same;
    }

    /** Whether @p left and @p right match with ASCII letters folded, as HTTP compares names. */
    static bool equal_ascii_uncased(std::string_view left, std::string_view right) noexcept {
        if (left.size() != right.size()) return false;
        for (std::size_t i = 0; i != left.size(); ++i) {
            unsigned char first = static_cast<unsigned char>(left[i]), second = static_cast<unsigned char>(right[i]);
            if (first - 'A' < 26u) first += 'a' - 'A';
            if (second - 'A' < 26u) second += 'a' - 'A';
            if (first != second) return false;
        }
        return true;
    }
    static std::size_t find(std::string_view text, std::string_view needle, std::size_t offset = 0) noexcept {
        if (offset > text.size()) return std::string_view::npos;
        if (needle.empty()) return offset;
        if (needle.size() > text.size() - offset) return std::string_view::npos;
        char const* match;
        find_kit_t::find(text.data() + offset, text.size() - offset, needle.data(), needle.size(), &match, nullptr);
        return match ? static_cast<std::size_t>(match - text.data()) : std::string_view::npos;
    }
    static std::size_t find(std::string_view text, char needle, std::size_t offset = 0) noexcept {
        return find(text, std::string_view {&needle, 1}, offset);
    }
    static std::size_t rfind(std::string_view text, char needle) noexcept {
        if (text.empty()) return std::string_view::npos;
        char const* match;
        find_kit_t::rfind(text.data(), text.size(), &needle, 1, &match, nullptr);
        return match ? static_cast<std::size_t>(match - text.data()) : std::string_view::npos;
    }
    static std::size_t find_set(std::string_view text, sz_byteset_t const& set) noexcept {
        if (text.empty()) return std::string_view::npos;
        char const* match;
        byteset_kit_t::find_byteset(text.data(), text.size(), &set, &match, nullptr);
        return match ? static_cast<std::size_t>(match - text.data()) : std::string_view::npos;
    }
    static std::size_t rfind_set(std::string_view text, sz_byteset_t const& set) noexcept {
        if (text.empty()) return std::string_view::npos;
        char const* match;
        byteset_kit_t::rfind_byteset(text.data(), text.size(), &set, &match, nullptr);
        return match ? static_cast<std::size_t>(match - text.data()) : std::string_view::npos;
    }
    static std::uint64_t hash(std::string_view text, std::uint64_t seed = 0) noexcept {
        sz_u64_t result;
        hash_kit_t::hash(text.data(), text.size(), seed, &result, nullptr);
        return result;
    }
    static bool http_token(std::string_view text) noexcept {
        return !text.empty() && find_set(text, http_non_token_bytes_k) == std::string_view::npos;
    }
    static bool http_value(std::string_view text) noexcept {
        return find_set(text, http_control_bytes_k) == std::string_view::npos;
    }
    static std::string_view trim_http(std::string_view text) noexcept {
        std::size_t const first = find_set(text, http_non_padding_bytes_k);
        if (first == std::string_view::npos) return text.substr(text.size());
        std::size_t const last = rfind_set(text, http_non_padding_bytes_k);
        return text.substr(first, last - first + 1);
    }
    static void lowercase_ascii(span<char> text) noexcept {
        sz_size_t written = 0;
        fold_kit_t::uncased_fold(text.data(), text.size(), text.data(), &written, nullptr);
    }

    /** Whether the comma-separated list @p text names @p token, in any letter case. */
    static bool http_has_token(std::string_view text, std::string_view token) noexcept {
        while (!text.empty()) {
            std::size_t end = find(text, ',');
            if (equal_ascii_uncased(trim_http(text.substr(0, end)), token)) return true;
            if (end == std::string_view::npos) break;
            text.remove_prefix(end + 1);
        }
        return false;
    }
    static char const* http_verb_name(ucall_verb_t verb) noexcept {
        switch (verb) {
        case ucall_verb_get_k: return "GET";
        case ucall_verb_post_k: return "POST";
        case ucall_verb_put_k: return "PUT";
        case ucall_verb_delete_k: return "DELETE";
        case ucall_verb_patch_k: return "PATCH";
        case ucall_verb_head_k: return "HEAD";
        case ucall_verb_options_k: return "OPTIONS";
        default: return nullptr;
        }
    }
    static ucall_verb_t http_verb(std::string_view name) noexcept {
        ucall_verb_t verb = ucall_verb_unknown_k;
        switch (name.size()) {
        case 3: verb = name[0] == 'G' ? ucall_verb_get_k : name[0] == 'P' ? ucall_verb_put_k : verb; break;
        case 4: verb = name[0] == 'P' ? ucall_verb_post_k : name[0] == 'H' ? ucall_verb_head_k : verb; break;
        case 5: verb = name[0] == 'P' ? ucall_verb_patch_k : verb; break;
        case 6: verb = name[0] == 'D' ? ucall_verb_delete_k : verb; break;
        case 7: verb = name[0] == 'O' ? ucall_verb_options_k : verb; break;
        }
        return verb != ucall_verb_unknown_k && name == http_verb_name(verb) ? verb : ucall_verb_unknown_k;
    }

    /** Offsets survive buffer growth; views exist only during message dispatch. */
    struct http_message_t {
        std::size_t headers_length {}, body_length {}, wire_length {};
        std::size_t target_offset {}, target_length {}, cursor {}, decoded_length {};
        std::size_t content_length {};
        http_framing_t framing {http_framing_t::length_k};
        ucall_verb_t verb {ucall_verb_unknown_k};
        ucall_http_status_t status {};
        http_connection_t connection {http_connection_t::close_k};
        http_body_state_t body_state {http_body_state_t::framed_k};
        http_chunk_state_t chunk_state {http_chunk_state_t::size_k}; // Where a streamed body's decoder stands.
        std::size_t chunk_remaining {};                              // Payload bytes left in its current chunk.
        bool keep_alive() const noexcept { return connection == http_connection_t::keep_alive_k; }

        std::string_view target(std::string_view bytes) const noexcept {
            return bytes.substr(target_offset, target_length);
        }
        std::string_view body(std::string_view bytes) const noexcept {
            return bytes.substr(headers_length, body_length);
        }

        /** The first field named @p name in any letter case, trimmed, or an empty dataless view. */
        std::string_view header(std::string_view bytes, std::string_view name) const noexcept {
            auto start = find(bytes, "\r\n") + 2;
            while (start + 2 < headers_length) {
                auto end = find(bytes, "\r\n", start), colon = find(bytes, ':', start);
                if (colon < end && equal_ascii_uncased(bytes.substr(start, colon - start), name))
                    return trim_http(bytes.substr(colon + 1, end - colon - 1));
                start = end + 2;
            }
            return {};
        }
    };

    /** Reads the chunk-size line at @p cursor into @p length, with @p line_end at its CRLF:
     *  complete once the line is whole, overflow when @p length would pass @p decoded bytes. */
    static http_parse_t http_chunk_size(std::string_view text, std::size_t cursor, std::size_t decoded,
                                        std::size_t& line_end, std::size_t& length) noexcept {
        line_end = find(text, "\r\n", cursor);
        if (line_end == std::string_view::npos) return http_parse_t::incomplete_k;
        auto line = text.substr(cursor, line_end - cursor);
        auto digits = line.substr(0, find(line, ';'));
        length = 0;
        auto result = std::from_chars(digits.data(), digits.data() + digits.size(), length, 16);
        if (digits.empty() || result.ec != std::errc {} || result.ptr != digits.data() + digits.size() ||
            !http_value(line))
            return http_parse_t::malformed_k;
        if (length > std::numeric_limits<std::size_t>::max() - decoded) return http_parse_t::overflow_k;
        return http_parse_t::complete_k;
    }

    /** Walks the trailers from @p trailer to the empty line ending them, lowercasing their names,
     *  with @p end past that line once complete. */
    static http_parse_t http_trailers(span<byte_t> bytes, std::size_t trailer, std::size_t& end) noexcept {
        auto text = text_view(bytes);
        for (;;) {
            auto trailer_end = find(text, "\r\n", trailer);
            if (trailer_end == std::string_view::npos) return http_parse_t::incomplete_k;
            if (trailer_end == trailer) {
                end = trailer + 2;
                return http_parse_t::complete_k;
            }
            auto colon = find(text, ':', trailer);
            if (colon >= trailer_end || !http_token(text.substr(trailer, colon - trailer)) ||
                !http_value(text.substr(colon + 1, trailer_end - colon - 1)))
                return http_parse_t::malformed_k;
            auto name = text.substr(trailer, colon - trailer);
            lowercase_ascii({reinterpret_cast<char*>(bytes.data()) + trailer, name.size()});
            if (equal(name, "content-length") || equal(name, "transfer-encoding") || equal(name, "host"))
                return http_parse_t::malformed_k;
            trailer = trailer_end + 2;
        }
    }

    static http_parse_t http_parse(span<byte_t> bytes, http_message_t& message, http_role_t role) noexcept {
        auto text = text_view(bytes);
        if (!message.headers_length) {
            auto end = find(text, "\r\n\r\n", message.cursor);
            if (end == std::string_view::npos) {
                message.cursor = text.size() > 3 ? text.size() - 3 : 0;
                return http_parse_t::incomplete_k;
            }
            auto first_end = find(text, "\r\n");
            auto first = text.substr(0, first_end);
            auto space = find(first, ' ');
            if (space == std::string_view::npos) return http_parse_t::malformed_k;
            std::string_view version;
            if (role == http_role_t::request_k) {
                auto second = find(first, ' ', space + 1);
                if (second == std::string_view::npos) return http_parse_t::malformed_k;
                message.verb = http_verb(first.substr(0, space));
                if (!http_token(first.substr(0, space))) return http_parse_t::malformed_k;
                if (message.verb == ucall_verb_unknown_k) return http_parse_t::unsupported_k;
                message.target_offset = space + 1;
                message.target_length = second - space - 1;
                auto target = first.substr(message.target_offset, message.target_length);
                if (target.empty() || target.front() != '/' ||
                    (find(target, ' ') != std::string_view::npos || find(target, '#') != std::string_view::npos ||
                     find(target, '\t') != std::string_view::npos) ||
                    !http_value(target))
                    return http_parse_t::malformed_k;
                version = first.substr(second + 1);
            }
            else {
                version = first.substr(0, space);
                auto code = first.substr(space + 1, 3);
                auto result = std::from_chars(code.data(), code.data() + code.size(), message.status);
                if (code.size() != 3 || result.ec != std::errc {} || result.ptr != code.data() + 3 ||
                    message.status < 100 || message.status > 599 ||
                    (first.size() > space + 4 && first[space + 4] != ' ') || !http_value(first))
                    return http_parse_t::malformed_k;
            }
            if (version != "HTTP/1.1" && version != "HTTP/1.0") return http_parse_t::unsupported_k;
            message.connection = version == "HTTP/1.1" ? http_connection_t::keep_alive_k : http_connection_t::close_k;
            bool has_length = false, has_transfer = false, has_host = false, has_close = false;
            std::size_t start = first_end + 2;
            while (start < end) {
                auto line_end = find(text, "\r\n", start), colon = find(text, ':', start);
                if (colon >= line_end) return http_parse_t::malformed_k;
                auto name = text.substr(start, colon - start),
                     value = trim_http(text.substr(colon + 1, line_end - colon - 1));
                if (!http_token(name) || !http_value(value)) return http_parse_t::malformed_k;
                lowercase_ascii({reinterpret_cast<char*>(bytes.data()) + start, name.size()});
                if (equal(name, "connection") || equal(name, "transfer-encoding")) {
                    auto tokens = value;
                    while (!tokens.empty()) {
                        auto comma = find(tokens, ',');
                        if (!http_token(trim_http(tokens.substr(0, comma)))) return http_parse_t::malformed_k;
                        if (comma == std::string_view::npos) break;
                        tokens.remove_prefix(comma + 1);
                    }
                    lowercase_ascii(
                        {reinterpret_cast<char*>(bytes.data()) + (value.data() - text.data()), value.size()});
                }
                if (equal(name, "content-length")) {
                    if (has_length || value.empty()) return http_parse_t::malformed_k;
                    auto result = std::from_chars(value.data(), value.data() + value.size(), message.content_length);
                    if (result.ec != std::errc {} || result.ptr != value.data() + value.size())
                        return http_parse_t::malformed_k;
                    has_length = true;
                }
                else if (equal(name, "transfer-encoding")) {
                    if (has_transfer) return http_parse_t::malformed_k;
                    if (!equal(value, "chunked")) return http_parse_t::unsupported_k;
                    has_transfer = true;
                }
                else if (equal(name, "connection")) {
                    if (http_has_token(value, "close")) has_close = true;
                    else if (version == "HTTP/1.0" && http_has_token(value, "keep-alive"))
                        message.connection = http_connection_t::keep_alive_k;
                }
                else if (equal(name, "host")) {
                    if (has_host || value.empty()) return http_parse_t::malformed_k;
                    has_host = true;
                }
                start = line_end + 2;
            }
            if (has_close) message.connection = http_connection_t::close_k;
            if (has_length && has_transfer) return http_parse_t::malformed_k;
            if (role == http_role_t::request_k && version == "HTTP/1.1" && !has_host) return http_parse_t::malformed_k;
            message.headers_length = end + 4;
            message.cursor = message.headers_length;
            message.framing = has_transfer ? http_framing_t::chunked_k : http_framing_t::length_k;
            bool const bodiless = role == http_role_t::head_response_k ||
                                  (message.status >= 100 && message.status < 200) || message.status == 204 ||
                                  message.status == 304;
            if (bodiless) {
                message.framing = http_framing_t::length_k;
                message.content_length = 0;
            }
            else if (role != http_role_t::request_k && !has_transfer && !has_length) {
                message.framing = http_framing_t::until_close_k;
                message.connection = http_connection_t::close_k;
            }
        }
        if (message.framing == http_framing_t::until_close_k) return http_parse_t::incomplete_k;
        if (message.framing == http_framing_t::length_k) {
            if (message.content_length > std::numeric_limits<std::size_t>::max() - message.headers_length)
                return http_parse_t::overflow_k;
            message.wire_length = message.headers_length + message.content_length;
            message.body_length = message.content_length;
            return text.size() >= message.wire_length ? http_parse_t::complete_k : http_parse_t::incomplete_k;
        }
        while (message.cursor < text.size()) {
            std::size_t line_end = 0, length = 0;
            if (auto sized = http_chunk_size(text, message.cursor, message.decoded_length, line_end, length);
                sized != http_parse_t::complete_k)
                return sized;
            if (!length) {
                std::size_t end = 0;
                if (auto trailed = http_trailers(bytes, line_end + 2, end); trailed != http_parse_t::complete_k)
                    return trailed;
                message.wire_length = end;
                message.body_length = message.decoded_length;
                return http_parse_t::complete_k;
            }
            if (length > std::numeric_limits<std::size_t>::max() - 2 || text.size() - line_end - 2 < length + 2)
                return http_parse_t::incomplete_k;
            if (text.substr(line_end + 2 + length, 2) != "\r\n") return http_parse_t::malformed_k;
            message.decoded_length += length;
            message.cursor = line_end + 2 + length + 2;
        }
        return http_parse_t::incomplete_k;
    }

    static void http_decode_chunks(span<byte_t> bytes, http_message_t& message) noexcept {
        if (message.framing != http_framing_t::chunked_k || message.body_state == http_body_state_t::decoded_k) return;
        auto text = text_view(bytes);
        std::size_t cursor = message.headers_length, destination = cursor;
        for (;;) {
            auto end = find(text, "\r\n", cursor), separator = find(text, ';', cursor);
            if (separator > end) separator = end;
            std::size_t length = 0;
            std::from_chars(text.data() + cursor, text.data() + separator, length, 16);
            if (!length) break;
            std::memmove(bytes.data() + destination, bytes.data() + end + 2, length);
            destination += length;
            cursor = end + 2 + length + 2;
        }
        message.body_state = http_body_state_t::decoded_k;
    }

    /** Decodes the body @p bytes holds from its front in place, leaving @p payload decoded bytes
     *  there, and reports in @p consumed how many bytes it walked; complete once the body and its
     *  trailers ended. An identity body takes what arrived up to its declared length. */
    static http_parse_t http_stream_body(span<byte_t> bytes, http_message_t& message, std::size_t& payload,
                                         std::size_t& consumed) noexcept {
        auto text = text_view(bytes);
        payload = consumed = 0;
        if (message.framing == http_framing_t::length_k) {
            payload = consumed = std::min(bytes.size(), message.content_length - message.decoded_length);
            message.decoded_length += payload;
            return message.decoded_length == message.content_length ? http_parse_t::complete_k
                                                                    : http_parse_t::incomplete_k;
        }
        while (consumed < text.size()) {
            switch (message.chunk_state) {
            case http_chunk_state_t::payload_k: {
                std::size_t const taken = std::min(message.chunk_remaining, text.size() - consumed);
                std::memmove(bytes.data() + payload, bytes.data() + consumed, taken);
                payload += taken, consumed += taken, message.chunk_remaining -= taken;
                message.decoded_length += taken;
                if (!message.chunk_remaining) message.chunk_state = http_chunk_state_t::payload_end_k;
                break;
            }
            case http_chunk_state_t::payload_end_k:
                if (text.size() - consumed < 2) return http_parse_t::incomplete_k;
                if (text.substr(consumed, 2) != "\r\n") return http_parse_t::malformed_k;
                consumed += 2;
                message.chunk_state = http_chunk_state_t::size_k;
                break;
            case http_chunk_state_t::size_k: {
                std::size_t line_end = 0, length = 0;
                if (auto sized = http_chunk_size(text, consumed, message.decoded_length, line_end, length);
                    sized != http_parse_t::complete_k)
                    return sized;
                consumed = line_end + 2;
                message.chunk_remaining = length;
                message.chunk_state = length ? http_chunk_state_t::payload_k : http_chunk_state_t::trailers_k;
                break;
            }
            case http_chunk_state_t::trailers_k: {
                std::size_t end = 0;
                auto trailed = http_trailers(bytes, consumed, end);
                if (trailed == http_parse_t::complete_k) consumed = end;
                return trailed;
            }
            }
        }
        return http_parse_t::incomplete_k;
    }

    /** Appends every one of @p texts to @p bytes in one resize, or nothing at all. */
    template <typename element_type_, typename allocator_type_>
    [[nodiscard]] static ucall_status_t append_text(st::basic_vector<element_type_, allocator_type_>& bytes,
                                                    std::initializer_list<std::string_view> texts) noexcept {
        static_assert(sizeof(element_type_) == 1);
        std::size_t offset = bytes.size(), length = offset;
        for (std::string_view const text : texts) {
            if (text.size() > std::numeric_limits<std::size_t>::max() - length) return ucall_status_overflow_k;
            length += text.size();
        }
        if (st::failed(bytes.resize(length))) return ucall_status_out_of_memory_k;
        for (std::string_view const text : texts) {
            if (!text.empty()) std::memcpy(bytes.data() + offset, text.data(), text.size());
            offset += text.size();
        }
        return ucall_status_success_k;
    }
    template <typename allocator_type_>
    static void drop_bytes(st::basic_vector<byte_t, allocator_type_>& bytes, std::size_t count) noexcept {
        bytes.erase(0, count);
    }
};

} // namespace unum::ucall
