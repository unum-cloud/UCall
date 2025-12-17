/**
 *  @brief URI template routing trie for efficient endpoint matching.
 *
 *  Implements a segment-level trie for matching HTTP request paths against registered
 *  URI templates. Supports literals, named parameters @c {name}, and greedy wildcards @c {*name}.
 *  Matching follows precedence: literals > parameters > wildcards.
 *
 *  Routes are @b immutable after initialization - register all endpoints during server startup.
 *  No locking is needed since routes never change during request processing.
 *
 *  @section memory_ownership Memory Ownership
 *
 *  This implementation uses a simple pool-based ownership model:
 *  - @c route_trie_t owns three pools: @c nodes, @c edges, and @c endpoints
 *  - All @c route_node_t instances are allocated from @c nodes pool
 *  - All @c route_edge_t instances (literal children) are allocated from @c edges pool
 *  - All @c route_endpoint_t instances (verb handlers) are allocated from @c endpoints pool
 *  - Pools handle deallocation automatically on destruction
 *  - All pointers within structures are @b non-owning - they point into pools
 *
 *  Literal children and endpoints are organized as linked lists for simplicity.
 *  This trades some cache efficiency for code clarity and flexibility.
 *
 *  @section path_limits Path Length and Segment Limits
 *
 *  HTTP/1.1 (RFC 7230, RFC 9110) does not impose hard limits on URI length, but recommends
 *  implementations support @b at @b least 8000 octets. Real-world limits vary:
 *
 *  @b Browsers:
 *  - Chrome/Edge: ~2MB (practically unlimited)
 *  - Firefox: ~65K characters
 *  - Safari: ~80K characters
 *  - Internet Explorer (legacy): 2,083 characters
 *
 *  @b Servers:
 *  - Apache: 8190 bytes (default, configurable via @c LimitRequestLine)
 *  - Nginx: 4K-8K (default, configurable via @c large_client_header_buffers)
 *  - IIS: 16K (configurable)
 *
 *  @b Segments: No RFC limit on number of path segments. This implementation supports up to
 *  16 segments per path (e.g., @c /api/v1/users/123/posts/456/comments), which covers 99%+
 *  of real-world APIs. Paths exceeding 16 segments will fail to match.
 *
 *  @section url_normalization URL Normalization
 *
 *  This routing trie performs basic query/fragment stripping but expects normalized paths.
 *  Path normalization (percent-decoding, slash collapsing) is handled by the URL parser
 *  before routing.
 *
 *  @file src/routes.hpp
 *  @author Ash Vardanian
 *  @date January 10, 2025
 */
#pragma once

#include <cstring>
#include <optional>
#include <string_view>

#include "shared.hpp"
#include "ucall/ucall.h"

namespace unum::ucall {

#pragma region Data Structures

/** @brief Types of path segments in URI templates. */
enum class segment_type_t : std::uint8_t {
    literal_k,  // Exact match segment (e.g., "users")
    param_k,    // Named parameter segment (e.g., "{id}")
    wildcard_k, // Greedy wildcard segment (e.g., "{*path}")
};

/** @brief Parsed segment from a URI template. */
struct parsed_segment_t {
    segment_type_t type;
    std::string_view content; // For literals: the segment text; for params: the parameter name
};

/**
 *  @brief Object-oriented routing trie for efficient URI template matching.
 *
 *  Implements a segment-level trie with automatic growth via successive_pools.
 *  Routes are immutable after registration - designed for lock-free concurrent matching.
 *
 *  Usage:
 *  @code
 *  auto trie = route_trie_t::make(100);  // Estimated routes
 *  if (!trie) return error;
 *  trie->insert("/users/{id}", ucall_verb_get_k, callback);
 *  void* handler = trie->match("/users/123", ucall_verb_get_k);
 *  @endcode
 */
class route_trie_t {
  private:
    // Forward declarations for internal structures
    struct route_node_t;
    struct route_endpoint_t;
    struct route_edge_t;

    /**
     *  @brief Endpoint handler for a specific HTTP verb at a route.
     *    Stored in pool and linked as a list to support multiple verbs per path.
     */
    struct route_endpoint_t {
        ucall_verb_t verb;      // HTTP verb for this endpoint
        void *callback;         // Callback function pointer
        void *callback_tag;     // User context pointer
        route_endpoint_t *next; // Next endpoint in list (or nullptr)
    };

    /**
     *  @brief Literal edge connecting parent to child node.
     *    Stored in pool and linked as a list of sibling edges from the same parent.
     */
    struct route_edge_t {
        std::string_view segment; // Literal segment name
        route_node_t *child;      // Non-owning pointer to child node
        route_edge_t *next;       // Next sibling edge (or nullptr)
    };

    /**
     *  @brief Trie node representing one level in the path hierarchy.
     *    All pointers are non-owning - actual objects live in pools.
     */
    struct route_node_t {
        route_edge_t *literal_children; // Head of literal edges list (or nullptr)
        route_node_t *param_child;      // Single {param} child (or nullptr)
        std::string_view param_name;    // Parameter name for param_child
        route_node_t *wildcard_child;   // Single {*wildcard} child (or nullptr)
        std::string_view wildcard_name; // Wildcard name for wildcard_child
        route_endpoint_t *endpoints;    // Head of endpoints list (or nullptr)
    };

    // Member data - growable pools for automatic capacity management
    successive_pools<route_node_t> nodes_;
    successive_pools<route_edge_t> edges_;
    successive_pools<route_endpoint_t> endpoints_;
    route_node_t *root_;

  public:
    route_trie_t() noexcept : nodes_(), edges_(), endpoints_(), root_(nullptr) {}

    route_trie_t(route_trie_t const &) = delete;
    route_trie_t &operator=(route_trie_t const &) = delete;
    route_trie_t(route_trie_t &&) noexcept = default;
    route_trie_t &operator=(route_trie_t &&) noexcept = default;
    ~route_trie_t() noexcept = default;

    /**
     *  @brief Initializes the routing trie by allocating the root node.
     *  @return True if initialization succeeded, false on allocation failure.
     *
     *  Must be called once before using insert() or match(). Safe to call multiple
     *  times (subsequent calls are no-ops if root already exists).
     */
    [[nodiscard]] bool init() noexcept {
        if (root_) return true; // Already initialized

        // Allocate and initialize root node
        root_ = nodes_.alloc();
        if (!root_) return false;

        root_->literal_children = nullptr;
        root_->param_child = nullptr;
        root_->wildcard_child = nullptr;
        root_->endpoints = nullptr;

        return true;
    }

    /**
     *  @brief Factory method to create and initialize a routing trie.
     *  @param[in] estimated_routes Estimated number of routes (default 100).
     *  @return Initialized trie, or nullopt on allocation failure.
     *
     *  Convenience method that creates a trie and calls init() automatically.
     *  The trie starts with pools sized for ~2x the estimated routes and grows
     *  automatically (2x each time) when capacity is exhausted.
     */
    [[nodiscard]] static std::optional<route_trie_t> make(std::size_t estimated_routes = 100) noexcept {
        route_trie_t trie;
        trie.nodes_ = successive_pools<route_node_t>(estimated_routes * 2);
        trie.edges_ = successive_pools<route_edge_t>(estimated_routes * 2);
        trie.endpoints_ = successive_pools<route_endpoint_t>(estimated_routes * 2);

        if (!trie.init()) return std::nullopt;
        return trie;
    }

    /**
     *  @brief Inserts an endpoint into the routing trie.
     *  @param[in] template_str The URI template (e.g., "/users/{id}").
     *  @param[in] verb The HTTP verb for this endpoint.
     *  @param[in] callback The callback function pointer.
     *  @param[in] callback_tag User context pointer for the callback (defaults to nullptr).
     *  @return True if insertion succeeded, false on error (duplicate, invalid template, etc.).
     *
     *  @warning The @p template_str string_view must remain valid for the lifetime of the trie.
     */
    [[nodiscard]] bool insert(std::string_view template_str, ucall_verb_t verb, void *callback,
                              void *callback_tag = nullptr) noexcept;

    /**
     *  @brief Matches a request path against the routing trie.
     *  @param[in] path The request path (e.g., "/users/123").
     *  @param[in] verb The HTTP verb.
     *  @param[in] callback_tag Optional output pointer for callback context (or nullptr).
     *  @return Callback function pointer if matched, or nullptr if no match.
     *
     *  @note This function is lock-free and safe for concurrent access since routes are immutable.
     */
    [[nodiscard]] void *match(std::string_view path, ucall_verb_t verb, void **callback_tag = nullptr) const noexcept;

    /** @brief Returns total capacity across all pools. */
    [[nodiscard]] std::size_t capacity() const noexcept {
        return nodes_.capacity() + edges_.capacity() + endpoints_.capacity();
    }

    /** @brief Returns number of pools allocated for growth tracking. */
    [[nodiscard]] std::size_t pool_count() const noexcept { return nodes_.pool_count(); }

  private:
    /**
     *  @brief Finds a literal child node by segment name.
     *  @param[in] node The node to search.
     *  @param[in] segment The segment name to find.
     *  @return Pointer to the child node, or nullptr if not found.
     */
    [[nodiscard]] route_node_t *find_literal_child(route_node_t const *node, std::string_view segment) const noexcept;
};

#pragma endregion Data Structures

#pragma region Helper Functions

/**
 *  @brief Extracts path component from URL, stripping query and fragment.
 *  @param[in] url The full URL or path (may include ?query and #fragment).
 *  @return Path component only, without query or fragment.
 *
 *  Examples:
 *  - "/users/123?limit=10" → "/users/123"
 *  - "/posts#top" → "/posts"
 *  - "/api/v1" → "/api/v1"
 */
inline std::string_view extract_path_component(std::string_view url) noexcept {
    auto query_pos = url.find('?');
    auto fragment_pos = url.find('#');
    auto end_pos = query_pos < fragment_pos ? query_pos : fragment_pos;
    return end_pos == std::string_view::npos ? url : url.substr(0, end_pos);
}

/**
 *  @brief Counts the number of segments in a path.
 *  @param[in] path The path string to analyze.
 *  @return Number of non-empty segments between `/` delimiters.
 */
inline std::size_t count_path_segments(std::string_view path) noexcept {
    if (path.empty()) return 0;

    std::size_t count = 0;
    std::size_t start = path[0] == '/' ? 1 : 0;

    for (std::size_t i = start; i < path.size(); ++i) {
        if (path[i] == '/') {
            if (i > start) count++;
            start = i + 1;
        }
    }

    if (start < path.size()) count++;
    return count;
}

/**
 *  @brief Splits a path into segments.
 *  @param[in] path The path string to split.
 *  @param[out] segments Pre-allocated array to store segments.
 *  @param[in] max_segments Maximum number of segments to extract.
 *  @return Number of segments extracted.
 */
inline std::size_t split_path(std::string_view path, std::string_view *segments, std::size_t max_segments) noexcept {
    if (path.empty() || !segments || max_segments == 0) return 0;

    std::size_t count = 0;
    std::size_t start = path[0] == '/' ? 1 : 0;

    for (std::size_t i = start; i < path.size() && count < max_segments; ++i) {
        if (path[i] == '/') {
            if (i > start) segments[count++] = path.substr(start, i - start);
            start = i + 1;
        }
    }

    if (start < path.size() && count < max_segments) segments[count++] = path.substr(start);
    return count;
}

#pragma endregion Helper Functions

#pragma region URI Template Parsing

/**
 *  @brief Parses a single segment to determine its type.
 *  @param[in] segment The segment string to parse.
 *  @param[out] result The parsed segment information.
 *  @return True if parsing succeeded, false if syntax is invalid.
 */
inline bool parse_segment(std::string_view segment, parsed_segment_t &result) noexcept {
    if (segment.empty()) return false;

    // Check for parameter or wildcard
    if (segment[0] == '{') {
        // Validate closing brace
        if (segment.back() != '}') return false;
        if (segment.size() < 3) return false; // At least "{x}"

        std::string_view name = segment.substr(1, segment.size() - 2);
        if (name.empty()) return false;

        // Check for wildcard
        if (name[0] == '*') {
            if (name.size() < 2) return false; // At least "{*x}"
            result.type = segment_type_t::wildcard_k;
            result.content = name.substr(1);
        }
        else {
            result.type = segment_type_t::param_k;
            result.content = name;
        }
        return true;
    }

    // Literal segment (cannot contain { or })
    if (segment.find('{') != std::string_view::npos || segment.find('}') != std::string_view::npos) return false;

    result.type = segment_type_t::literal_k;
    result.content = segment;
    return true;
}

/**
 *  @brief Parses a URI template into segments.
 *  @param[in] template_str The URI template to parse.
 *  @param[out] segments Pre-allocated array to store parsed segments.
 *  @param[in] max_segments Maximum number of segments to extract.
 *  @return Number of segments parsed. Returns 0 for root path "/" (not an error).
 *    Returns SIZE_MAX on parse error or if segment count exceeds @p max_segments.
 */
inline std::size_t parse_uri_template(std::string_view template_str, parsed_segment_t *segments,
                                      std::size_t max_segments) noexcept {
    // First count total segments to detect overflow
    std::size_t total_count = count_path_segments(template_str);

    // Root path "/" has 0 segments - this is valid
    if (total_count == 0) {
        // But make sure it's actually "/" not empty string
        if (template_str.empty() || (template_str != "/" && template_str != ""))
            return SIZE_MAX; // Error: empty or invalid template
        return 0;            // Valid root path
    }

    // Check if we exceed the limit BEFORE parsing
    if (total_count > max_segments) return SIZE_MAX;

    std::string_view raw_segments[16];
    std::size_t raw_count = split_path(template_str, raw_segments, 16);

    // Double-check (should be same as total_count)
    if (raw_count > max_segments) return SIZE_MAX;

    bool seen_wildcard = false;
    for (std::size_t i = 0; i < raw_count; ++i) {
        if (seen_wildcard) return SIZE_MAX; // Wildcard must be last

        if (!parse_segment(raw_segments[i], segments[i])) return SIZE_MAX;

        if (segments[i].type == segment_type_t::wildcard_k) seen_wildcard = true;
    }

    return raw_count;
}

#pragma endregion URI Template Parsing

#pragma region Routing Operations - Member Function Implementations

/**
 *  @brief Finds a literal child node by segment name.
 *  @note Walks linked list of literal edges - O(children) complexity.
 */
[[nodiscard]] inline route_trie_t::route_node_t *route_trie_t::find_literal_child(
    route_node_t const *node, std::string_view segment) const noexcept {
    if (!node) return nullptr;

    route_edge_t const *edge = node->literal_children;
    while (edge) {
        if (edge->segment == segment) return edge->child;
        edge = edge->next;
    }
    return nullptr;
}

/**
 *  @brief Inserts an endpoint into the routing trie - member function implementation.
 */
[[nodiscard]] inline bool route_trie_t::insert(std::string_view template_str, ucall_verb_t verb, void *callback,
                                               void *callback_tag) noexcept {
    parsed_segment_t segments[16];
    std::size_t segment_count = parse_uri_template(template_str, segments, 16);
    if (segment_count == SIZE_MAX) return false; // Parse error

    route_node_t *current = root_;
    for (std::size_t i = 0; i < segment_count; ++i) {
        auto &segment = segments[i];

        if (segment.type == segment_type_t::literal_k) {
            route_node_t *child = find_literal_child(current, segment.content);
            if (!child) {
                // Allocate new child node
                child = nodes_.alloc();
                if (!child) return false;

                // Initialize child
                child->literal_children = nullptr;
                child->param_child = nullptr;
                child->wildcard_child = nullptr;
                child->endpoints = nullptr;

                // Allocate edge and prepend to parent's literal_children list
                route_edge_t *edge = edges_.alloc();
                if (!edge) return false;

                edge->segment = segment.content;
                edge->child = child;
                edge->next = current->literal_children;
                current->literal_children = edge;
            }
            current = child;
        }
        else if (segment.type == segment_type_t::param_k) {
            if (!current->param_child) {
                current->param_child = nodes_.alloc();
                if (!current->param_child) return false;

                current->param_child->literal_children = nullptr;
                current->param_child->param_child = nullptr;
                current->param_child->wildcard_child = nullptr;
                current->param_child->endpoints = nullptr;
                current->param_name = segment.content;
            }
            // Conflicting parameter names at same position
            else if (current->param_name != segment.content) return false;
            current = current->param_child;
        }
        else if (segment.type == segment_type_t::wildcard_k) {
            if (!current->wildcard_child) {
                current->wildcard_child = nodes_.alloc();
                if (!current->wildcard_child) return false;

                current->wildcard_child->literal_children = nullptr;
                current->wildcard_child->param_child = nullptr;
                current->wildcard_child->wildcard_child = nullptr;
                current->wildcard_child->endpoints = nullptr;
                current->wildcard_name = segment.content;
            }
            current = current->wildcard_child;
        }
    }

    // Check for duplicate endpoint at this verb
    route_endpoint_t *endpoint = current->endpoints;
    while (endpoint) {
        if (endpoint->verb == verb) return false; // Duplicate
        endpoint = endpoint->next;
    }

    // Allocate and prepend new endpoint
    route_endpoint_t *new_endpoint = endpoints_.alloc();
    if (!new_endpoint) return false;

    new_endpoint->verb = verb;
    new_endpoint->callback = callback;
    new_endpoint->callback_tag = callback_tag;
    new_endpoint->next = current->endpoints;
    current->endpoints = new_endpoint;

    return true;
}

/**
 *  @brief Matches a request path against the routing trie - member function implementation.
 */
[[nodiscard]] inline void *route_trie_t::match(std::string_view path, ucall_verb_t verb,
                                               void **callback_tag) const noexcept {
    // Strip query and fragment if present
    path = extract_path_component(path);

    std::string_view segments[16];
    std::size_t segment_count = split_path(path, segments, 16);

    // Find the matching node
    route_node_t const *current = root_;
    if (!current) return nullptr;

    for (std::size_t i = 0; i < segment_count; ++i) {
        std::size_t segments_remaining = segment_count - i;

        // Priority 1: Try literal match
        route_node_t *literal_child = find_literal_child(current, segments[i]);
        if (literal_child) {
            current = literal_child;
            continue;
        }

        // Priority 2: Try parameter match (only if exactly 1 segment remains)
        // If multiple segments remain, prefer wildcard since param can only consume one
        if (current->param_child && segments_remaining == 1) {
            current = current->param_child;
            continue;
        }

        // Priority 3: Try wildcard (consumes rest of path)
        if (current->wildcard_child) {
            current = current->wildcard_child;
            break;
        }

        // Priority 4: If wildcard didn't exist, try param anyway (may fail later)
        if (current->param_child) {
            current = current->param_child;
            continue;
        }

        // No match
        return nullptr;
    }

    // Walk endpoints list to find matching verb
    route_endpoint_t const *endpoint = current->endpoints;
    while (endpoint) {
        if (endpoint->verb == verb) {
            if (callback_tag) *callback_tag = endpoint->callback_tag;
            return endpoint->callback;
        }
        endpoint = endpoint->next;
    }

    return nullptr;
}

#pragma endregion Routing Operations

} // namespace unum::ucall
