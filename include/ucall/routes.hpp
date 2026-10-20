/**
 *  @file include/ucall/routes.hpp
 *  @author Ash Vardanian
 *  @date January 10, 2025
 *  @brief Immutable URI routing with literal, parameter, and trailing wildcard precedence.
 */
#pragma once

#include <algorithm>
#include <limits>
#include <optional>
#include <string_view>

#include <stringzilla/find/serial.h>

#include "ucall/types.hpp"
#include "ucall/ucall.h"

namespace unum::ucall {

enum class segment_type_t : std::uint8_t { literal_k, param_k, wildcard_k };
struct parsed_segment_t {
    segment_type_t type {};
    std::string_view content {};
};

struct route_search_t {
    static std::size_t find(std::string_view text, char needle, std::size_t offset = 0) noexcept {
        if (offset >= text.size()) return std::string_view::npos;
        auto found = sz_find_serial_(text.data() + offset, text.size() - offset, &needle, 1);
        return found ? static_cast<std::size_t>(found - text.data()) : std::string_view::npos;
    }
    static std::size_t rfind(std::string_view text, char needle) noexcept {
        if (text.empty()) return std::string_view::npos;
        auto found = sz_rfind_serial_(text.data(), text.size(), &needle, 1);
        return found ? static_cast<std::size_t>(found - text.data()) : std::string_view::npos;
    }
    static char const* find_set(std::string_view text, sz_byteset_t const& set) noexcept {
        return text.empty() ? nullptr : sz_find_byteset_serial_(text.data(), text.size(), &set);
    }
    static char const* rfind_set(std::string_view text, sz_byteset_t const& set) noexcept {
        return text.empty() ? nullptr : sz_rfind_byteset_serial_(text.data(), text.size(), &set);
    }
    static bool equal(std::string_view left, std::string_view right) noexcept {
        return left.size() == right.size() && sz_equal_serial_(left.data(), right.data(), left.size());
    }
};

template <typename search_type_ = route_search_t>
inline std::string_view extract_path_component(std::string_view url) noexcept {
    return url.substr(0, std::min(search_type_::find(url, '?'), search_type_::find(url, '#')));
}

/** A cursor keeps matching independent of path depth and needs no request-local allocation. */
template <typename search_type_ = route_search_t>
struct path_cursor {
    std::string_view path {};
    std::size_t offset {};

    static sz_byteset_t const& non_slashes() noexcept {
        static sz_byteset_t const set = [] {
            sz_byteset_t result {};
            sz_byteset_add(&result, '/');
            sz_byteset_invert(&result);
            return result;
        }();
        return set;
    }
    std::string_view next() noexcept {
        auto first = search_type_::find_set(path.substr(offset), non_slashes());
        if (!first) {
            offset = path.size();
            return {};
        }
        auto start = static_cast<std::size_t>(first - path.data());
        auto end = search_type_::find(path, '/', start);
        if (end == std::string_view::npos) end = path.size();
        offset = end == path.size() ? end : end + 1;
        return path.substr(start, end - start);
    }
    void previous() noexcept {
        auto last = search_type_::rfind_set(path.substr(0, offset), non_slashes());
        auto end = last ? static_cast<std::size_t>(last - path.data()) + 1 : 0;
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
inline std::size_t split_path(std::string_view path, std::string_view* segments, std::size_t capacity) noexcept {
    if (!segments) return 0;
    path_cursor<search_type_> cursor {path};
    std::size_t count {};
    while (count != capacity) {
        auto segment = cursor.next();
        if (segment.empty()) break;
        segments[count++] = segment;
    }
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

template <typename search_type_ = route_search_t>
inline std::size_t parse_uri_template(std::string_view path, parsed_segment_t* segments,
                                      std::size_t capacity) noexcept {
    if (path.empty()) return std::numeric_limits<std::size_t>::max();
    path_cursor<search_type_> cursor {path};
    std::size_t count {};
    bool wildcard {};
    for (auto segment = cursor.next(); !segment.empty(); segment = cursor.next()) {
        if (wildcard || count == capacity || !segments || !parse_segment<search_type_>(segment, segments[count]))
            return std::numeric_limits<std::size_t>::max();
        wildcard = segments[count++].type == segment_type_t::wildcard_k;
    }
    return count || path == "/" ? count : std::numeric_limits<std::size_t>::max();
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
    route_trie(route_trie&& other) noexcept
        : nodes_(std::move(other.nodes_)), edges_(std::move(other.edges_)), endpoints_(std::move(other.endpoints_)),
          root_(std::exchange(other.root_, nullptr)) {}
    route_trie& operator=(route_trie&& other) noexcept {
        if (this == &other) return *this;
        nodes_ = std::move(other.nodes_);
        edges_ = std::move(other.edges_);
        endpoints_ = std::move(other.endpoints_);
        root_ = std::exchange(other.root_, nullptr);
        return *this;
    }

    bool init() noexcept {
        if (!root_) root_ = child(nullptr, segment_type_t::literal_k);
        return root_;
    }
    static std::optional<route_trie> make(std::size_t estimated_routes = 100,
                                          allocator_t const& allocator = {}) noexcept {
        if (estimated_routes > std::numeric_limits<std::size_t>::max() / 2) return std::nullopt;
        route_trie trie {allocator};
        trie.nodes_ = decltype(nodes_) {estimated_routes * 2, rebind_allocator<node_t> {allocator}};
        trie.edges_ = decltype(edges_) {estimated_routes * 2, rebind_allocator<edge_t> {allocator}};
        trie.endpoints_ = decltype(endpoints_) {estimated_routes * 2, rebind_allocator<endpoint_t> {allocator}};
        if (!trie.init()) return std::nullopt;
        return trie;
    }
    bool insert(std::string_view path, ucall_verb_t verb, void* callback, void* tag = nullptr) noexcept {
        if (!root_ || path.empty()) return false;
        path_cursor<search_type_> cursor {path};
        bool wildcard {};
        std::size_t count {};
        for (auto segment = cursor.next(); !segment.empty(); segment = cursor.next()) {
            parsed_segment_t parsed {};
            if (wildcard || !parse_segment<search_type_>(segment, parsed)) return false;
            wildcard = parsed.type == segment_type_t::wildcard_k;
            ++count;
        }
        if (!count && path != "/") return false;
        cursor.offset = 0;
        auto current = root_;
        for (auto segment = cursor.next(); !segment.empty(); segment = cursor.next()) {
            parsed_segment_t parsed {};
            (void)parse_segment<search_type_>(segment, parsed);
            if (parsed.type == segment_type_t::literal_k) {
                auto found = literal(current, parsed.content);
                if (!found) {
                    found = child(current, parsed.type);
                    auto edge = edges_.alloc();
                    if (!found || !edge) return false;
                    *edge = {parsed.content, found, current->literals};
                    current->literals = edge;
                }
                current = found;
            }
            else {
                auto& next = parsed.type == segment_type_t::param_k ? current->parameter : current->wildcard;
                auto& name = parsed.type == segment_type_t::param_k ? current->parameter_name : current->wildcard_name;
                if (next && !search_type_::equal(name, parsed.content)) return false;
                if (!next) {
                    next = child(current, parsed.type);
                    if (!next) return false;
                    name = parsed.content;
                }
                current = next;
            }
        }
        for (auto existing = current->endpoints; existing; existing = existing->next)
            if (existing->verb == verb) return false;
        auto added = endpoints_.alloc();
        if (!added) return false;
        *added = {verb, callback, tag, current->endpoints};
        current->endpoints = added;
        return true;
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
                    (void)cursor.next();
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
    std::size_t capacity() const noexcept { return nodes_.capacity() + edges_.capacity() + endpoints_.capacity(); }
    std::size_t pool_count() const noexcept { return nodes_.pool_count(); }
};

using route_trie_t = route_trie<>;

} // namespace unum::ucall
