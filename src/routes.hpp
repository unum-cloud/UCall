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
 *  @file routes.hpp
 *  @author Ash Vardanian
 *  @date January 10, 2025
 */
#pragma once

#include <cstring>
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

// Forward declarations to resolve circular dependencies
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

/**
 *  @brief Main routing trie container with immutable routes.
 *    All memory owned by three pools. Routes are registered during initialization
 *    and never modified during request processing.
 */
struct route_trie_t {
    pool<route_node_t> nodes {};         // Pre-allocated pool of trie nodes
    pool<route_edge_t> edges {};         // Pre-allocated pool of literal edges
    pool<route_endpoint_t> endpoints {}; // Pre-allocated pool of endpoint handlers
    route_node_t *root {};               // Root node (empty path)
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
 *    Returns SIZE_MAX on parse error or if segment count exceeds max_segments.
 */
inline std::size_t parse_uri_template(std::string_view template_str, parsed_segment_t *segments,
                                      std::size_t max_segments) noexcept {
    // First count total segments to detect overflow
    std::size_t total_count = count_path_segments(template_str);

    // Root path "/" has 0 segments - this is valid
    if (total_count == 0) {
        // But make sure it's actually "/" not empty string
        if (template_str.empty() || (template_str != "/" && template_str != "")) {
            return SIZE_MAX; // Error: empty or invalid template
        }
        return 0; // Valid root path
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

#pragma region Trie Management

/**
 *  @brief Initializes a routing trie with pre-allocated pools.
 *  @param[out] trie The trie to initialize.
 *  @param[in] estimated_nodes Estimated number of trie nodes needed.
 *  @param[in] estimated_edges Estimated number of literal edges needed.
 *  @param[in] estimated_endpoints Estimated number of endpoint handlers needed.
 *  @return True if initialization succeeded, false on allocation failure.
 *
 *  Typical sizing for a REST API with 100 routes:
 *  - Nodes: ~200 (avg 2 segments per route)
 *  - Edges: ~200 (avg 1-2 literal children per node with children)
 *  - Endpoints: ~100-200 (1-2 verbs per route)
 *
 *  @sa route_trie_free() to release resources when done.
 */
[[nodiscard]] inline bool route_trie_init(route_trie_t &trie, std::size_t estimated_nodes, std::size_t estimated_edges,
                                          std::size_t estimated_endpoints) noexcept {
    if (!trie.nodes.reserve(estimated_nodes)) return false;
    if (!trie.edges.reserve(estimated_edges)) return false;
    if (!trie.endpoints.reserve(estimated_endpoints)) return false;

    trie.root = trie.nodes.alloc();
    if (!trie.root) return false;

    // Initialize root node (pool already default-constructs, but be explicit)
    trie.root->literal_children = nullptr;
    trie.root->param_child = nullptr;
    trie.root->wildcard_child = nullptr;
    trie.root->endpoints = nullptr;

    return true;
}

/**
 *  @brief Frees resources allocated by the routing trie.
 *  @param[inout] trie The trie to free.
 *
 *  @note @c pool destructors handle cleanup automatically, but this function provides
 *  explicit resource release if needed.
 */
inline void route_trie_free(route_trie_t &trie) noexcept {
    // pool<> destructors handle cleanup automatically
    trie.root = nullptr;
}

#pragma endregion Trie Management

#pragma region Routing Operations

/**
 *  @brief Finds a literal child node by segment name.
 *  @param[in] node The node to search.
 *  @param[in] segment The segment name to find.
 *  @return Pointer to the child node, or nullptr if not found.
 *
 *  @note Walks linked list of literal edges - O(children) complexity.
 *  @sa route_trie_insert() uses this to navigate the trie during insertion.
 *  @sa route_trie_match() uses this to find matching paths during routing.
 */
[[nodiscard]] inline route_node_t *find_literal_child(route_node_t const *node, std::string_view segment) noexcept {
    if (!node) return nullptr;

    route_edge_t const *edge = node->literal_children;
    while (edge) {
        if (edge->segment == segment) return edge->child;
        edge = edge->next;
    }
    return nullptr;
}

/**
 *  @brief Inserts an endpoint into the routing trie.
 *  @param[inout] trie The routing trie.
 *  @param[in] template_str The URI template (e.g., @c "/users/{id}").
 *  @param[in] verb The HTTP verb for this endpoint.
 *  @param[in] callback The callback function pointer.
 *  @param[in] callback_tag User context pointer for the callback (defaults to nullptr).
 *  @return True if insertion succeeded, false on error (duplicate, allocation failure, etc.).
 *
 *  @warning Routes are immutable - this function should only be called during initialization.
 *  @warning The @p template_str string_view must remain valid for the lifetime of the trie.
 */
[[nodiscard]] inline bool route_trie_insert(route_trie_t &trie, std::string_view template_str, ucall_verb_t verb,
                                            void *callback, void *callback_tag = nullptr) noexcept {
    parsed_segment_t segments[16];
    std::size_t segment_count = parse_uri_template(template_str, segments, 16);
    if (segment_count == SIZE_MAX) return false; // Parse error

    route_node_t *current = trie.root;
    for (std::size_t i = 0; i < segment_count; ++i) {
        auto &segment = segments[i];

        if (segment.type == segment_type_t::literal_k) {
            route_node_t *child = find_literal_child(current, segment.content);
            if (!child) {
                // Allocate new child node
                child = trie.nodes.alloc();
                if (!child) return false;

                // Initialize child
                child->literal_children = nullptr;
                child->param_child = nullptr;
                child->wildcard_child = nullptr;
                child->endpoints = nullptr;

                // Allocate edge and prepend to parent's literal_children list
                route_edge_t *edge = trie.edges.alloc();
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
                current->param_child = trie.nodes.alloc();
                if (!current->param_child) return false;

                current->param_child->literal_children = nullptr;
                current->param_child->param_child = nullptr;
                current->param_child->wildcard_child = nullptr;
                current->param_child->endpoints = nullptr;
                current->param_name = segment.content;
            }
            else if (current->param_name != segment.content) {
                // Conflicting parameter names at same position
                return false;
            }
            current = current->param_child;
        }
        else if (segment.type == segment_type_t::wildcard_k) {
            if (!current->wildcard_child) {
                current->wildcard_child = trie.nodes.alloc();
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
    route_endpoint_t *new_endpoint = trie.endpoints.alloc();
    if (!new_endpoint) return false;

    new_endpoint->verb = verb;
    new_endpoint->callback = callback;
    new_endpoint->callback_tag = callback_tag;
    new_endpoint->next = current->endpoints;
    current->endpoints = new_endpoint;

    return true;
}

/**
 *  @brief Matches a request path against the routing trie.
 *  @param[in] trie The routing trie.
 *  @param[in] path The request path (e.g., @c "/users/123").
 *  @param[in] verb The HTTP verb.
 *  @param[out] callback_tag Optional output pointer for callback context (or nullptr).
 *  @return Callback function pointer if matched, or nullptr if no match.
 *
 *  @note This function is lock-free and safe for concurrent access since routes are immutable.
 *  @note Query strings and fragments are stripped automatically by @c extract_path_component.
 *  @note Walks endpoint list to find matching verb - O(verbs_per_route) complexity.
 */
[[nodiscard]] inline void *route_trie_match(route_trie_t const &trie, std::string_view path, ucall_verb_t verb,
                                            void **callback_tag = nullptr) noexcept {
    // Strip query and fragment if present
    path = extract_path_component(path);

    std::string_view segments[16];
    std::size_t segment_count = split_path(path, segments, 16);

    // Find the matching node
    route_node_t const *current = trie.root;
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
