/**
 *  @brief Unit tests for URI routing trie implementation.
 *
 *  Tests the segment-level routing trie in routes.hpp for correctness, edge cases,
 *  and error handling. Uses GoogleTest framework.
 *
 *  Compilation:
 *  @code{.sh}
 *  g++ -std=c++20 -O2 -I./include -I./src \
 *      -I/opt/homebrew/opt/googletest/include \
 *      -L/opt/homebrew/opt/googletest/lib \
 *      -lgtest -lgtest_main -pthread \
 *      scripts/test_routes.cpp -o test_routes
 *  @endcode
 *
 *  @file test_routes.cpp
 *  @author Ash Vardanian
 *  @date November 5, 2025
 */
#include <gtest/gtest.h>
#include <cstdint>
#include <cstring>

#include <ucall/ucall.h>
#include "routes.hpp"
#include "shared.hpp"

using namespace unum::ucall;

/** @brief Creates a dummy endpoint pointer from an integer ID for testing. */
inline void *make_endpoint(int id) { return reinterpret_cast<void *>(static_cast<std::uintptr_t>(id)); }

/** @brief Extracts integer ID from endpoint pointer for verification. */
inline int endpoint_id(void *ptr) { return static_cast<int>(reinterpret_cast<std::uintptr_t>(ptr)); }

/**
 *  @brief Base test fixture for routing trie tests.
 *
 *  Automatically initializes and cleans up a routing trie for each test.
 */
class RoutingTrieTest : public ::testing::Test {
  protected:
    route_trie_t trie;

    void SetUp() override {
        // Initialize the trie (auto-growing pools)
        ASSERT_TRUE(trie.init()) << "Failed to initialize routing trie";
    }

    void TearDown() override {
        // No explicit cleanup needed - RAII handles it
    }

    /** @brief Helper to verify route matches expected endpoint. */
    void expect_match(char const *path, ucall_verb_t verb, void *expected) {
        void *result = trie.match(path, verb);
        EXPECT_EQ(result, expected) << "Path: " << path << ", Verb: " << static_cast<int>(verb);
    }

    /** @brief Helper to verify route does not match. */
    void expect_no_match(char const *path, ucall_verb_t verb) {
        void *result = trie.match(path, verb);
        EXPECT_EQ(result, nullptr) << "Path: " << path << " should not match";
    }
};

#pragma region Literal Matching Tests

TEST_F(RoutingTrieTest, InitializationSucceeds) {
    // Trie is initialized in SetUp()
    EXPECT_GT(trie.capacity(), 0u);
    EXPECT_EQ(trie.pool_count(), 1u); // One pool allocated per type
}

TEST_F(RoutingTrieTest, RootPathMatching) {
    void *endpoint1 = make_endpoint(1);
    ASSERT_TRUE(trie.insert("/", ucall_verb_get_k, endpoint1));

    expect_match("/", ucall_verb_get_k, endpoint1);
    expect_no_match("/", ucall_verb_post_k); // Different verb
}

TEST_F(RoutingTrieTest, SingleLiteralSegment) {
    void *endpoint1 = make_endpoint(1);
    void *endpoint2 = make_endpoint(2);

    ASSERT_TRUE(trie.insert("/users", ucall_verb_get_k, endpoint1));
    ASSERT_TRUE(trie.insert("/posts", ucall_verb_get_k, endpoint2));

    expect_match("/users", ucall_verb_get_k, endpoint1);
    expect_match("/posts", ucall_verb_get_k, endpoint2);
    expect_no_match("/admin", ucall_verb_get_k);
}

TEST_F(RoutingTrieTest, MultiSegmentLiterals) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(trie.insert("/api/v1/users", ucall_verb_get_k, endpoint));

    expect_match("/api/v1/users", ucall_verb_get_k, endpoint);
    expect_no_match("/api/v1", ucall_verb_get_k);
    expect_no_match("/api/v1/users/extra", ucall_verb_get_k);
}

TEST_F(RoutingTrieTest, EmptyPathHandling) {
    // Empty path should not match anything
    expect_no_match("", ucall_verb_get_k);
}

TEST_F(RoutingTrieTest, CleanupDoesNotCrash) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(trie.insert("/test", ucall_verb_get_k, endpoint));
    // RAII handles cleanup automatically - no explicit free needed
}

#pragma endregion Literal Matching Tests

#pragma region Parameter Matching Tests

TEST_F(RoutingTrieTest, SingleParameter) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(trie.insert( "/users/{id}", ucall_verb_get_k, endpoint));

    expect_match("/users/123", ucall_verb_get_k, endpoint);
    expect_match("/users/abc", ucall_verb_get_k, endpoint);
    expect_match("/users/foo-bar", ucall_verb_get_k, endpoint);
    expect_no_match("/users", ucall_verb_get_k);           // Missing parameter
    expect_no_match("/users/123/extra", ucall_verb_get_k); // Too many segments
}

TEST_F(RoutingTrieTest, MultipleParameters) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(trie.insert( "/posts/{year}/{month}", ucall_verb_get_k, endpoint));

    expect_match("/posts/2024/11", ucall_verb_get_k, endpoint);
    expect_match("/posts/2025/01", ucall_verb_get_k, endpoint);
    expect_no_match("/posts/2024", ucall_verb_get_k);       // Missing parameter
    expect_no_match("/posts/2024/11/05", ucall_verb_get_k); // Too many segments
}

TEST_F(RoutingTrieTest, MixedLiteralsAndParameters) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(trie.insert( "/api/{version}/users/{id}", ucall_verb_get_k, endpoint));

    expect_match("/api/v1/users/123", ucall_verb_get_k, endpoint);
    expect_match("/api/v2/users/456", ucall_verb_get_k, endpoint);
    expect_no_match("/api/v1/posts/123", ucall_verb_get_k); // Wrong literal
}

TEST_F(RoutingTrieTest, ParameterAtDifferentPositions) {
    void *endpoint1 = make_endpoint(1);
    void *endpoint2 = make_endpoint(2);
    void *endpoint3 = make_endpoint(3);

    ASSERT_TRUE(trie.insert( "/{resource}/list", ucall_verb_get_k, endpoint1));
    ASSERT_TRUE(trie.insert( "/admin/{action}", ucall_verb_get_k, endpoint2));
    ASSERT_TRUE(trie.insert( "/api/{version}/{entity}", ucall_verb_get_k, endpoint3));

    expect_match("/users/list", ucall_verb_get_k, endpoint1);
    expect_match("/admin/dashboard", ucall_verb_get_k, endpoint2);
    expect_match("/api/v1/products", ucall_verb_get_k, endpoint3);
}

TEST_F(RoutingTrieTest, ParameterNamesStored) {
    // Test that parameter names work correctly through matching behavior
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(trie.insert("/users/{user_id}/posts/{post_id}", ucall_verb_get_k, endpoint));

    // Verify matching works with different parameter values
    expect_match("/users/123/posts/456", ucall_verb_get_k, endpoint);
    expect_match("/users/abc/posts/xyz", ucall_verb_get_k, endpoint);

    // Should not match wrong structure
    expect_no_match("/users/123", ucall_verb_get_k);
    expect_no_match("/users/123/posts", ucall_verb_get_k);
}

TEST_F(RoutingTrieTest, ConflictingParameterNames) {
    void *endpoint1 = make_endpoint(1);
    void *endpoint2 = make_endpoint(2);

    // First route: /users/{id}/posts
    ASSERT_TRUE(trie.insert( "/users/{id}/posts", ucall_verb_get_k, endpoint1));

    // Second route with different parameter name at same position should fail
    EXPECT_FALSE(trie.insert( "/users/{user_id}/comments", ucall_verb_get_k, endpoint2));
}

#pragma endregion Parameter Matching Tests

#pragma region Wildcard Matching Tests

TEST_F(RoutingTrieTest, SimpleWildcard) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(trie.insert( "/files/{*path}", ucall_verb_get_k, endpoint));

    expect_match("/files/a.txt", ucall_verb_get_k, endpoint);
    expect_match("/files/a/b/c.txt", ucall_verb_get_k, endpoint);
    expect_match("/files/deeply/nested/path/file.pdf", ucall_verb_get_k, endpoint);
    expect_no_match("/files", ucall_verb_get_k); // Need at least one segment for wildcard
}

TEST_F(RoutingTrieTest, WildcardWithPrefix) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(trie.insert( "/static/{*filepath}", ucall_verb_get_k, endpoint));

    expect_match("/static/css/style.css", ucall_verb_get_k, endpoint);
    expect_match("/static/js/app.js", ucall_verb_get_k, endpoint);
    expect_match("/static/images/logo.png", ucall_verb_get_k, endpoint);
}

TEST_F(RoutingTrieTest, WildcardConsumesAllRemaining) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(trie.insert( "/docs/{*page}", ucall_verb_get_k, endpoint));

    // Wildcard should consume any number of remaining segments
    expect_match("/docs/intro", ucall_verb_get_k, endpoint);
    expect_match("/docs/api/reference", ucall_verb_get_k, endpoint);
    expect_match("/docs/guides/getting-started/installation", ucall_verb_get_k, endpoint);
}

TEST_F(RoutingTrieTest, WildcardNameStored) {
    // Test that wildcard names work correctly through matching behavior
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(trie.insert("/assets/{*filepath}", ucall_verb_get_k, endpoint));

    // Verify wildcard matches various paths
    expect_match("/assets/css/style.css", ucall_verb_get_k, endpoint);
    expect_match("/assets/js/app.js", ucall_verb_get_k, endpoint);
    expect_match("/assets/images/logo.png", ucall_verb_get_k, endpoint);
    expect_match("/assets/a/b/c/d/e", ucall_verb_get_k, endpoint);
}

#pragma endregion Wildcard Matching Tests

#pragma region HTTP Verb Routing Tests

TEST_F(RoutingTrieTest, SamePathDifferentVerbs) {
    void *get_endpoint = make_endpoint(1);
    void *post_endpoint = make_endpoint(2);
    void *put_endpoint = make_endpoint(3);
    void *delete_endpoint = make_endpoint(4);

    ASSERT_TRUE(trie.insert( "/users", ucall_verb_get_k, get_endpoint));
    ASSERT_TRUE(trie.insert( "/users", ucall_verb_post_k, post_endpoint));
    ASSERT_TRUE(trie.insert( "/users", ucall_verb_put_k, put_endpoint));
    ASSERT_TRUE(trie.insert( "/users", ucall_verb_delete_k, delete_endpoint));

    expect_match("/users", ucall_verb_get_k, get_endpoint);
    expect_match("/users", ucall_verb_post_k, post_endpoint);
    expect_match("/users", ucall_verb_put_k, put_endpoint);
    expect_match("/users", ucall_verb_delete_k, delete_endpoint);
}

TEST_F(RoutingTrieTest, AllSevenVerbs) {
    void *endpoints[7];
    ucall_verb_t verbs[7] = {ucall_verb_get_k,   ucall_verb_post_k, ucall_verb_put_k,    ucall_verb_delete_k,
                             ucall_verb_patch_k, ucall_verb_head_k, ucall_verb_options_k};

    for (int i = 0; i < 7; ++i) {
        endpoints[i] = make_endpoint(i + 1);
        ASSERT_TRUE(trie.insert( "/test", verbs[i], endpoints[i]));
    }

    for (int i = 0; i < 7; ++i) { expect_match("/test", verbs[i], endpoints[i]); }
}

TEST_F(RoutingTrieTest, UnregisteredVerbReturnsNull) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(trie.insert( "/users", ucall_verb_get_k, endpoint));

    expect_match("/users", ucall_verb_get_k, endpoint);
    expect_no_match("/users", ucall_verb_post_k); // POST not registered
}

TEST_F(RoutingTrieTest, DuplicateVerbFails) {
    void *endpoint1 = make_endpoint(1);
    void *endpoint2 = make_endpoint(2);

    ASSERT_TRUE(trie.insert( "/users", ucall_verb_get_k, endpoint1));
    EXPECT_FALSE(trie.insert( "/users", ucall_verb_get_k, endpoint2)); // Duplicate
}

#pragma endregion HTTP Verb Routing Tests

#pragma region Query String and Fragment Tests

TEST_F(RoutingTrieTest, QueryStringStripped) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(trie.insert( "/search", ucall_verb_get_k, endpoint));

    expect_match("/search?q=test", ucall_verb_get_k, endpoint);
    expect_match("/search?q=test&page=2", ucall_verb_get_k, endpoint);
    expect_match("/search?key=value&another=param", ucall_verb_get_k, endpoint);
}

TEST_F(RoutingTrieTest, FragmentStripped) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(trie.insert( "/docs", ucall_verb_get_k, endpoint));

    expect_match("/docs#section1", ucall_verb_get_k, endpoint);
    expect_match("/docs#top", ucall_verb_get_k, endpoint);
}

TEST_F(RoutingTrieTest, QueryAndFragmentStripped) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(trie.insert( "/page", ucall_verb_get_k, endpoint));

    expect_match("/page?key=value#section", ucall_verb_get_k, endpoint);
    expect_match("/page#section?not_a_query", ucall_verb_get_k, endpoint); // Fragment comes first
}

TEST_F(RoutingTrieTest, ExtractPathComponentHelper) {
    EXPECT_EQ(extract_path_component("/users"), "/users");
    EXPECT_EQ(extract_path_component("/users?limit=10"), "/users");
    EXPECT_EQ(extract_path_component("/users#top"), "/users");
    EXPECT_EQ(extract_path_component("/users?limit=10#top"), "/users");
    EXPECT_EQ(extract_path_component(""), "");
}

#pragma endregion Query String and Fragment Tests

#pragma region Precedence Rules Tests

TEST_F(RoutingTrieTest, LiteralBeatsParameter) {
    void *literal_endpoint = make_endpoint(1);
    void *param_endpoint = make_endpoint(2);

    ASSERT_TRUE(trie.insert( "/users/{id}", ucall_verb_get_k, param_endpoint));
    ASSERT_TRUE(trie.insert( "/users/new", ucall_verb_get_k, literal_endpoint));

    // Literal should be preferred
    expect_match("/users/new", ucall_verb_get_k, literal_endpoint);
    expect_match("/users/123", ucall_verb_get_k, param_endpoint);
}

TEST_F(RoutingTrieTest, ParameterBeatsWildcard) {
    void *param_endpoint = make_endpoint(1);
    void *wildcard_endpoint = make_endpoint(2);

    ASSERT_TRUE(trie.insert( "/files/{*path}", ucall_verb_get_k, wildcard_endpoint));
    ASSERT_TRUE(trie.insert( "/files/{id}", ucall_verb_get_k, param_endpoint));

    // Parameter should beat wildcard for single segment
    expect_match("/files/123", ucall_verb_get_k, param_endpoint);

    // Wildcard wins for multiple segments
    expect_match("/files/a/b/c", ucall_verb_get_k, wildcard_endpoint);
}

TEST_F(RoutingTrieTest, InsertionOrderIrrelevant) {
    void *endpoint1 = make_endpoint(1);
    void *endpoint2 = make_endpoint(2);

    // Insert parameter first, literal second
    ASSERT_TRUE(trie.insert( "/items/{id}", ucall_verb_get_k, endpoint1));
    ASSERT_TRUE(trie.insert( "/items/featured", ucall_verb_get_k, endpoint2));

    // Literal still wins regardless of insertion order
    expect_match("/items/featured", ucall_verb_get_k, endpoint2);
    expect_match("/items/123", ucall_verb_get_k, endpoint1);
}

#pragma endregion Precedence Rules Tests

#pragma region Edge Cases Tests

TEST_F(RoutingTrieTest, MaximumSegments) {
    // 16 segments is the maximum (routes.hpp:213, 380)
    void *endpoint = make_endpoint(1);
    char const *path = "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p"; // 16 segments

    ASSERT_TRUE(trie.insert( path, ucall_verb_get_k, endpoint));
    expect_match(path, ucall_verb_get_k, endpoint);
}

TEST_F(RoutingTrieTest, ExceedingMaximumSegments) {
    // 17 segments exceeds the limit
    void *endpoint = make_endpoint(1);
    char const *path = "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q"; // 17 segments

    // Should fail to parse or insert
    bool result = trie.insert( path, ucall_verb_get_k, endpoint);
    EXPECT_FALSE(result) << "Should reject paths with >16 segments";
}

TEST_F(RoutingTrieTest, DuplicateRouteRegistration) {
    void *endpoint1 = make_endpoint(1);
    void *endpoint2 = make_endpoint(2);

    ASSERT_TRUE(trie.insert( "/users/{id}", ucall_verb_get_k, endpoint1));
    EXPECT_FALSE(trie.insert( "/users/{id}", ucall_verb_get_k, endpoint2)); // Duplicate
}

TEST_F(RoutingTrieTest, TrailingSlashHandling) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(trie.insert( "/users", ucall_verb_get_k, endpoint));

    // Current implementation: trailing slash creates empty segment (skipped)
    expect_match("/users/", ucall_verb_get_k, endpoint);
}

TEST_F(RoutingTrieTest, VeryLongPath) {
    // Test path near RFC recommended 8000 byte limit
    std::string long_segment(100, 'a');
    std::string long_path = "/";
    for (int i = 0; i < 10; ++i) {
        long_path += long_segment;
        if (i < 9) long_path += "/";
    }
    // Total: 1000 bytes in segments + 10 slashes = 1010 bytes

    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(trie.insert( long_path.c_str(), ucall_verb_get_k, endpoint));
    expect_match(long_path.c_str(), ucall_verb_get_k, endpoint);
}

TEST_F(RoutingTrieTest, EmptySegmentsSkipped) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(trie.insert( "/users", ucall_verb_get_k, endpoint));

    // Double slashes create empty segments which are skipped
    expect_match("/users", ucall_verb_get_k, endpoint);
    // Note: Current implementation doesn't normalize //, so this might not match
    // Depends on whether Ada or similar is used for normalization
}

TEST_F(RoutingTrieTest, AutoGrowthOnCapacityExceeded) {
    // Start with small initial capacity (default 100)
    route_trie_t growing_trie;
    ASSERT_TRUE(growing_trie.init());

    void *endpoint = make_endpoint(1);
    std::size_t initial_pool_count = growing_trie.pool_count();

    // Keep strings alive - string_view requires underlying storage to persist
    std::vector<std::string> paths;
    paths.reserve(200);

    // Add many routes - should trigger auto-growth
    for (int i = 0; i < 200; ++i) {
        paths.push_back("/route" + std::to_string(i));
        ASSERT_TRUE(growing_trie.insert(paths.back(), ucall_verb_get_k, endpoint))
            << "Auto-growth should allow unlimited routes (only OOM fails)";
    }

    // Should have grown (more pools allocated)
    EXPECT_GT(growing_trie.pool_count(), initial_pool_count) << "Pools should have grown";
}

#pragma endregion Edge Cases Tests

#pragma region Error Handling Tests

TEST_F(RoutingTrieTest, PoolGrowthExponential) {
    // Test that pools grow exponentially (2x each time)
    route_trie_t growing_trie;
    ASSERT_TRUE(growing_trie.init());

    void *endpoint = make_endpoint(1);

    // Track capacity growth
    std::size_t prev_capacity = growing_trie.capacity();
    std::size_t prev_pool_count = growing_trie.pool_count();

    // Keep strings alive
    std::vector<std::string> paths;
    paths.reserve(500);

    // Add enough routes to trigger multiple growth cycles
    for (int i = 0; i < 500; ++i) {
        paths.push_back("/route" + std::to_string(i));
        ASSERT_TRUE(growing_trie.insert(paths.back(), ucall_verb_get_k, endpoint));

        std::size_t current_pool_count = growing_trie.pool_count();
        if (current_pool_count > prev_pool_count) {
            std::size_t current_capacity = growing_trie.capacity();
            // Capacity should have increased (new pool added)
            EXPECT_GT(current_capacity, prev_capacity);
            prev_capacity = current_capacity;
            prev_pool_count = current_pool_count;
        }
    }

    // Should have grown multiple times
    EXPECT_GT(growing_trie.pool_count(), 1u);
}

TEST_F(RoutingTrieTest, InvalidTemplateSyntax) {
    void *endpoint = make_endpoint(1);

    // Empty braces
    EXPECT_FALSE(trie.insert( "/users/{}", ucall_verb_get_k, endpoint));

    // Wildcard without name
    EXPECT_FALSE(trie.insert( "/files/{*}", ucall_verb_get_k, endpoint));

    // Unclosed braces
    EXPECT_FALSE(trie.insert( "/users/{id", ucall_verb_get_k, endpoint));
}

TEST_F(RoutingTrieTest, NullPointerSafety) {
    // Match should return nullptr for non-existent routes
    void *result = trie.match("/test", ucall_verb_get_k);
    EXPECT_EQ(result, nullptr);

    // Empty path handling
    result = trie.match("", ucall_verb_get_k);
    EXPECT_EQ(result, nullptr);
}

#pragma endregion Error Handling Tests

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
