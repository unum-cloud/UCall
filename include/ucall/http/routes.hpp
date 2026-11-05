/**
 *  @file include/ucall/http/routes.hpp
 *  @author Ash Vardanian
 *  @date January 10, 2025
 *  @brief Immutable URI routing with literal, parameter, and trailing wildcard precedence.
 */
#pragma once

#include <algorithm>
#include <string_view>

#include <smashtable/basic_growing_pool.hpp>

#include "ucall/http/messages.hpp"   // `messages`, the serial kits
#include "ucall/utilities/types.hpp" // `byte_t`
#include "ucall/ucall.h"

namespace unum::ucall::http {

using utilities::byte_t;

enum class segment_type_t : std::uint8_t { literal_k, param_k, wildcard_k };

/** Verbs as bits, @c 1 << verb, as a miss reports the verbs its path takes. */
using verb_set_t = std::uint16_t;

/** Every verb a request may name, as @c OPTIONS @c * answers. */
inline constexpr verb_set_t every_verb_k = verb_set_t((1u << (ucall_verb_options_k + 1)) - (1u << ucall_verb_get_k));
struct parsed_segment_t {
    segment_type_t type {};
    std::string_view content {};
};

using route_search_t =
    messages<serial_compare_kit_t, serial_find_kit_t, serial_byteset_kit_t, serial_hash_kit_t, serial_fold_kit_t>;

template <typename search_type_ = route_search_t>
inline std::string_view extract_path_component(std::string_view url) noexcept {
    return url.substr(0, std::min(search_type_::find(url, '?'), search_type_::find(url, '#')));
}

/** Walks a path as @c / followed by segments split on @c /, exactly as sent: @c / holds none, and
 *  @c /a/ holds @c a and an empty one. Past the last segment @c next answers a null view, so an
 *  empty segment differs from none by its @c data. Matching needs no request-local allocation. */
template <typename search_type_ = route_search_t>
struct path_cursor {
    std::string_view path {};

    /** Where the next segment starts; zero before the first, past the leading slash. */
    std::size_t offset {};

    /** Whether @c next has no segment left, telling the end apart from an empty segment. */
    bool ended() const noexcept {
        std::size_t const start = offset ? offset : 1;
        return path.size() <= 1 || start > path.size();
    }
    std::string_view next() noexcept {
        if (ended()) {
            offset = path.size() + 1;
            return {};
        }
        std::size_t const start = offset ? offset : 1;
        auto end = search_type_::find(path, '/', start);
        if (end == std::string_view::npos) end = path.size();
        offset = end + 1;
        return path.substr(start, end - start);
    }
    void previous() noexcept {
        auto const slash = offset > 1 ? search_type_::rfind(path.substr(0, offset - 1), '/') : std::string_view::npos;
        offset = slash == std::string_view::npos ? 0 : slash + 1;
    }
};

template <typename search_type_ = route_search_t>
inline std::size_t count_path_segments(std::string_view path) noexcept {
    path_cursor<search_type_> cursor {path};
    std::size_t count {};
    while (cursor.next().data()) ++count;
    return count;
}

/** Parses one template segment; an empty one is a literal, matching only an empty segment. */
template <typename search_type_ = route_search_t>
inline bool parse_segment(std::string_view segment, parsed_segment_t& parsed) noexcept {
    parsed = {segment_type_t::literal_k, segment};
    if (segment.empty()) return true;
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

    using pool_allocator_t = rebind_allocator<byte_t>;
    template <typename record_type_>
    using pool = st::basic_growing_pool<record_type_, std::uint32_t, pool_allocator_t>;

    pool_allocator_t allocator_;
    pool<node_t> nodes_;
    pool<edge_t> edges_;
    pool<endpoint_t> endpoints_;
    node_t* root_ {};

    template <typename record_type_>
    static record_type_* take(pool<record_type_>& records) noexcept {
        auto const index = records.take();
        return index == pool<record_type_>::absent_k ? nullptr : &records[index];
    }

    node_t* literal(node_t const* node, std::string_view segment) const noexcept {
        for (auto edge = node->literals; edge; edge = edge->next)
            if (search_type_::equal(edge->segment, segment)) return edge->child;
        return nullptr;
    }

    /** The node's endpoint for @p verb, a GET serving HEAD, or its any-verb one; @p allowed gains
     *  every verb the node takes, which a 405 lists. */
    static void* endpoint(node_t const* node, ucall_verb_t verb, void** tag, verb_set_t* allowed) noexcept {
        endpoint_t const *exact {}, *getter {}, *fallback {};
        for (auto current = node->endpoints; current; current = current->next) {
            if (allowed) *allowed |= verb_set_t(1u << current->verb);
            if (current->verb == verb) exact = current;
            else if (current->verb == ucall_verb_get_k) getter = current;
            else if (current->verb == ucall_verb_any_k) fallback = current;
        }
        endpoint_t const* chosen = exact ? exact : verb == ucall_verb_head_k && getter ? getter : fallback;
        if (chosen && tag) *tag = chosen->tag;
        return chosen ? chosen->callback : nullptr;
    }
    node_t* child(node_t* parent, segment_type_t kind) noexcept {
        auto result = take(nodes_);
        if (result) *result = {.parent = parent, .kind = kind};
        return result;
    }

  public:
    using allocator_t = allocator_type_;

    explicit route_trie(allocator_t const& allocator = {}) noexcept
        : allocator_(allocator), nodes_(allocator_), edges_(allocator_), endpoints_(allocator_) {}
    route_trie(route_trie const&) = delete;
    route_trie& operator=(route_trie const&) = delete;

    [[nodiscard]] ucall_status_t init() noexcept {
        if (root_) return ucall_status_success_k;
        // Chunks never move, so the trie's links stay valid as registration grows the pools.
        auto nodes = pool<node_t>::make(64, pool<node_t>::capacity_max_k, allocator_);
        auto edges = pool<edge_t>::make(64, pool<edge_t>::capacity_max_k, allocator_);
        auto endpoints = pool<endpoint_t>::make(64, pool<endpoint_t>::capacity_max_k, allocator_);
        if (!nodes || !edges || !endpoints) return ucall_status_out_of_memory_k;
        nodes_ = std::move(*nodes), edges_ = std::move(*edges), endpoints_ = std::move(*endpoints);
        root_ = child(nullptr, segment_type_t::literal_k);
        return root_ ? ucall_status_success_k : ucall_status_out_of_memory_k;
    }
    ucall_status_t insert(std::string_view path, ucall_verb_t verb, void* callback, void* tag = nullptr) noexcept {
        if (!root_) return ucall_status_uninitialized_k;
        if (path.empty()) return ucall_status_invalid_argument_k;
        if (path.front() != '/') return ucall_status_invalid_argument_k;
        path_cursor<search_type_> cursor {path};
        bool wildcard {};
        for (auto segment = cursor.next(); segment.data(); segment = cursor.next()) {
            parsed_segment_t parsed {};
            if (wildcard || !parse_segment<search_type_>(segment, parsed)) return ucall_status_invalid_argument_k;
            wildcard = parsed.type == segment_type_t::wildcard_k;
        }
        cursor.offset = 0;
        auto current = root_;
        for (auto segment = cursor.next(); segment.data(); segment = cursor.next()) {
            parsed_segment_t parsed {};
            [[maybe_unused]] bool const validated = parse_segment<search_type_>(segment, parsed);
            if (parsed.type == segment_type_t::literal_k) {
                auto found = literal(current, parsed.content);
                if (!found) {
                    found = child(current, parsed.type);
                    auto edge = take(edges_);
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
        auto added = take(endpoints_);
        if (!added) return ucall_status_out_of_memory_k;
        *added = {verb, callback, tag, current->endpoints};
        current->endpoints = added;
        return ucall_status_success_k;
    }

    /** The callback of @p path's endpoint for @p verb, or null. Parameters never take an empty
     *  segment, and a wildcard takes only a non-empty remainder, which may hold empty segments. */
    void* match(std::string_view path, ucall_verb_t verb, void** tag = nullptr,
                verb_set_t* allowed = nullptr) const noexcept {
        if (!root_) return nullptr;
        path_cursor<search_type_> cursor {extract_path_component<search_type_>(path)};
        auto const remains = [&](std::size_t start) noexcept {
            return std::max<std::size_t>(start, 1) < cursor.path.size();
        };
        auto current = root_;
        for (;;) {
            auto before = cursor.offset;
            if (cursor.ended()) {
                if (auto found = endpoint(current, verb, tag, allowed)) return found;
            }
            else {
                auto segment = cursor.next();
                if (auto found = literal(current, segment)) {
                    current = found;
                    continue;
                }
                if (current->parameter && !segment.empty()) {
                    current = current->parameter;
                    continue;
                }
                if (current->wildcard && remains(static_cast<std::size_t>(segment.data() - cursor.path.data())))
                    if (auto found = endpoint(current->wildcard, verb, tag, allowed)) return found;
            }
            cursor.offset = before;
            bool descend {};
            while (current != root_) {
                auto failed = current;
                current = current->parent;
                cursor.previous();
                if (failed->kind == segment_type_t::literal_k && current->parameter) {
                    auto const resumed = cursor.offset;
                    if (!cursor.next().empty()) {
                        current = current->parameter;
                        descend = true;
                        break;
                    }
                    cursor.offset = resumed;
                }
                if (current->wildcard && remains(cursor.offset))
                    if (auto found = endpoint(current->wildcard, verb, tag, allowed)) return found;
            }
            if (!descend) return nullptr;
        }
    }
};

using route_trie_t = route_trie<>;

} // namespace unum::ucall::http
