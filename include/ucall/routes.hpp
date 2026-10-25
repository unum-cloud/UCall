/**
 *  @file include/ucall/routes.hpp
 *  @author Ash Vardanian
 *  @date January 10, 2025
 *  @brief Immutable URI routing with literal, parameter, and trailing wildcard precedence.
 */
#pragma once

#include <algorithm>
#include <string_view>

#include "ucall/http.hpp"
#include "ucall/types.hpp"
#include "ucall/ucall.h"

namespace unum::ucall {

enum class segment_type_t : std::uint8_t { literal_k, param_k, wildcard_k };
struct parsed_segment_t {
    segment_type_t type {};
    std::string_view content {};
};

using route_search_t =
    http<serial_compare_kit_t, serial_find_kit_t, serial_byteset_kit_t, serial_hash_kit_t, serial_fold_kit_t>;

template <typename search_type_ = route_search_t>
inline std::string_view extract_path_component(std::string_view url) noexcept {
    return url.substr(0, std::min(search_type_::find(url, '?'), search_type_::find(url, '#')));
}

/** A cursor keeps matching independent of path depth and needs no request-local allocation. */
template <typename search_type_ = route_search_t>
struct path_cursor {
    std::string_view path {};
    std::size_t offset {};

    std::string_view next() noexcept {
        std::size_t const found = search_type_::find_set(path.substr(offset), non_slash_bytes_k);
        if (found == std::string_view::npos) {
            offset = path.size();
            return {};
        }
        std::size_t const start = offset + found;
        auto end = search_type_::find(path, '/', start);
        if (end == std::string_view::npos) end = path.size();
        offset = end == path.size() ? end : end + 1;
        return path.substr(start, end - start);
    }
    void previous() noexcept {
        std::size_t const last = search_type_::rfind_set(path.substr(0, offset), non_slash_bytes_k);
        std::size_t const end = last == std::string_view::npos ? 0 : last + 1;
        auto slash = search_type_::rfind(path.substr(0, end), '/');
        offset = slash == std::string_view::npos ? 0 : slash + 1;
    }
};

template <typename search_type_ = route_search_t>
inline std::size_t count_path_segments(std::string_view path) noexcept {
    path_cursor<search_type_> cursor {path};
    std::size_t count {};
    while (!cursor.next().empty()) ++count;
    return count;
}

template <typename search_type_ = route_search_t>
inline bool parse_segment(std::string_view segment, parsed_segment_t& parsed) noexcept {
    if (segment.empty()) return false;
    parsed = {segment_type_t::literal_k, segment};
    if (segment.front() == '{') {
        if (segment.size() < 3 || segment.back() != '}') return false;
        auto name = segment.substr(1, segment.size() - 2);
        parsed.type = segment_type_t::param_k;
        if (name.front() == '*') {
            name.remove_prefix(1);
            parsed.type = segment_type_t::wildcard_k;
        }
        if (name.empty()) return false;
        parsed.content = name;
    }
    return search_type_::find(parsed.content, '{') == std::string_view::npos &&
           search_type_::find(parsed.content, '}') == std::string_view::npos;
}

/** Template strings remain borrowed; complete registration before concurrent matching begins. */
template <typename search_type_ = route_search_t, typename allocator_type_ = st::default_allocator<byte_t>>
class route_trie {
    template <typename element_type_>
    using rebind_allocator = typename std::allocator_traits<allocator_type_>::template rebind_alloc<element_type_>;
    struct node_t;
    struct endpoint_t {
        ucall_verb_t verb {};
        void* callback {};
        void* tag {};
        endpoint_t* next {};
    };
    struct edge_t {
        std::string_view segment {};
        node_t* child {};
        edge_t* next {};
    };
    struct node_t {
        edge_t* literals {};
        node_t* parameter {};
        node_t* wildcard {};
        std::string_view parameter_name {}, wildcard_name {};
        endpoint_t* endpoints {};
        node_t* parent {};
        segment_type_t kind {};
    };

    successive_pools<node_t, rebind_allocator<node_t>> nodes_;
    successive_pools<edge_t, rebind_allocator<edge_t>> edges_;
    successive_pools<endpoint_t, rebind_allocator<endpoint_t>> endpoints_;
    node_t* root_ {};

    node_t* literal(node_t const* node, std::string_view segment) const noexcept {
        for (auto edge = node->literals; edge; edge = edge->next)
            if (search_type_::equal(edge->segment, segment)) return edge->child;
        return nullptr;
    }
    static void* endpoint(node_t const* node, ucall_verb_t verb, void** tag) noexcept {
        endpoint_t const* fallback {};
        for (auto current = node->endpoints; current; current = current->next) {
            if (current->verb == ucall_verb_any_k) fallback = current;
            if (current->verb != verb) continue;
            if (tag) *tag = current->tag;
            return current->callback;
        }
        if (fallback && tag) *tag = fallback->tag;
        return fallback ? fallback->callback : nullptr;
    }
    node_t* child(node_t* parent, segment_type_t kind) noexcept {
        auto result = nodes_.alloc();
        if (result) {
            *result = {};
            result->parent = parent;
            result->kind = kind;
        }
        return result;
    }

  public:
    using allocator_t = allocator_type_;

    explicit route_trie(allocator_t const& allocator = {}) noexcept
        : nodes_(100, rebind_allocator<node_t> {allocator}), edges_(100, rebind_allocator<edge_t> {allocator}),
          endpoints_(100, rebind_allocator<endpoint_t> {allocator}) {}
    route_trie(route_trie const&) = delete;
    route_trie& operator=(route_trie const&) = delete;

    bool init() noexcept {
        if (!root_) root_ = child(nullptr, segment_type_t::literal_k);
        return root_;
    }
    ucall_status_t insert(std::string_view path, ucall_verb_t verb, void* callback, void* tag = nullptr) noexcept {
        if (!root_) return ucall_status_uninitialized_k;
        if (path.empty()) return ucall_status_invalid_argument_k;
        path_cursor<search_type_> cursor {path};
        bool wildcard {};
        std::size_t count {};
        for (auto segment = cursor.next(); !segment.empty(); segment = cursor.next()) {
            parsed_segment_t parsed {};
            if (wildcard || !parse_segment<search_type_>(segment, parsed)) return ucall_status_invalid_argument_k;
            wildcard = parsed.type == segment_type_t::wildcard_k;
            ++count;
        }
        if (!count && path != "/") return ucall_status_invalid_argument_k;
        cursor.offset = 0;
        auto current = root_;
        for (auto segment = cursor.next(); !segment.empty(); segment = cursor.next()) {
            parsed_segment_t parsed {};
            [[maybe_unused]] bool const validated = parse_segment<search_type_>(segment, parsed);
            if (parsed.type == segment_type_t::literal_k) {
                auto found = literal(current, parsed.content);
                if (!found) {
                    found = child(current, parsed.type);
                    auto edge = edges_.alloc();
                    if (!found || !edge) return ucall_status_out_of_memory_k;
                    *edge = {parsed.content, found, current->literals};
                    current->literals = edge;
                }
                current = found;
            }
            else {
                auto& next = parsed.type == segment_type_t::param_k ? current->parameter : current->wildcard;
                auto& name = parsed.type == segment_type_t::param_k ? current->parameter_name : current->wildcard_name;
                if (next && !search_type_::equal(name, parsed.content)) return ucall_status_invalid_argument_k;
                if (!next) {
                    next = child(current, parsed.type);
                    if (!next) return ucall_status_out_of_memory_k;
                    name = parsed.content;
                }
                current = next;
            }
        }
        for (auto existing = current->endpoints; existing; existing = existing->next)
            if (existing->verb == verb) return ucall_status_already_exists_k;
        auto added = endpoints_.alloc();
        if (!added) return ucall_status_out_of_memory_k;
        *added = {verb, callback, tag, current->endpoints};
        current->endpoints = added;
        return ucall_status_success_k;
    }
    void* match(std::string_view path, ucall_verb_t verb, void** tag = nullptr) const noexcept {
        if (!root_) return nullptr;
        path_cursor<search_type_> cursor {extract_path_component<search_type_>(path)};
        auto current = root_;
        for (;;) {
            auto before = cursor.offset;
            auto segment = cursor.next();
            if (segment.empty()) {
                if (auto found = endpoint(current, verb, tag)) return found;
            }
            else {
                if (auto found = literal(current, segment)) {
                    current = found;
                    continue;
                }
                if (current->parameter) {
                    current = current->parameter;
                    continue;
                }
                if (current->wildcard)
                    if (auto found = endpoint(current->wildcard, verb, tag)) return found;
            }
            cursor.offset = before;
            bool descend {};
            while (current != root_) {
                auto failed = current;
                current = current->parent;
                cursor.previous();
                if (failed->kind == segment_type_t::literal_k && current->parameter) {
                    [[maybe_unused]] std::string_view const skipped = cursor.next();
                    current = current->parameter;
                    descend = true;
                    break;
                }
                if (current->wildcard)
                    if (auto found = endpoint(current->wildcard, verb, tag)) return found;
            }
            if (!descend) return nullptr;
        }
    }
};

using route_trie_t = route_trie<>;

} // namespace unum::ucall
