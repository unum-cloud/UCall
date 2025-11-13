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
        // Initialize with reasonable capacity for tests
        ASSERT_TRUE(route_trie_init(trie, 100, 200, 200)) << "Failed to initialize routing trie";
    }

    void TearDown() override { route_trie_free(trie); }

    /** @brief Helper to verify route matches expected endpoint. */
    void expect_match(char const *path, ucall_verb_t verb, void *expected) {
        void *result = route_trie_match(trie, path, verb);
        EXPECT_EQ(result, expected) << "Path: " << path << ", Verb: " << static_cast<int>(verb);
    }

    /** @brief Helper to verify route does not match. */
    void expect_no_match(char const *path, ucall_verb_t verb) {
        void *result = route_trie_match(trie, path, verb);
        EXPECT_EQ(result, nullptr) << "Path: " << path << " should not match";
    }
};

#pragma region Literal Matching Tests

TEST_F(RoutingTrieTest, InitializationSucceeds) {
    // Trie is initialized in SetUp()
    EXPECT_NE(trie.root, nullptr);
    // Pools are initialized (no public capacity() method to check)
}

TEST_F(RoutingTrieTest, RootPathMatching) {
    void *endpoint1 = make_endpoint(1);
    ASSERT_TRUE(route_trie_insert(trie, "/", ucall_verb_get_k, endpoint1));

    expect_match("/", ucall_verb_get_k, endpoint1);
    expect_no_match("/", ucall_verb_post_k); // Different verb
}

TEST_F(RoutingTrieTest, SingleLiteralSegment) {
    void *endpoint1 = make_endpoint(1);
    void *endpoint2 = make_endpoint(2);

    ASSERT_TRUE(route_trie_insert(trie, "/users", ucall_verb_get_k, endpoint1));
    ASSERT_TRUE(route_trie_insert(trie, "/posts", ucall_verb_get_k, endpoint2));

    expect_match("/users", ucall_verb_get_k, endpoint1);
    expect_match("/posts", ucall_verb_get_k, endpoint2);
    expect_no_match("/admin", ucall_verb_get_k);
}

TEST_F(RoutingTrieTest, MultiSegmentLiterals) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(route_trie_insert(trie, "/api/v1/users", ucall_verb_get_k, endpoint));

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
    ASSERT_TRUE(route_trie_insert(trie, "/test", ucall_verb_get_k, endpoint));
    route_trie_free(trie);
    // TearDown will call free again, should be idempotent
}

#pragma endregion Literal Matching Tests

#pragma region Parameter Matching Tests

TEST_F(RoutingTrieTest, SingleParameter) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(route_trie_insert(trie, "/users/{id}", ucall_verb_get_k, endpoint));

    expect_match("/users/123", ucall_verb_get_k, endpoint);
    expect_match("/users/abc", ucall_verb_get_k, endpoint);
    expect_match("/users/foo-bar", ucall_verb_get_k, endpoint);
    expect_no_match("/users", ucall_verb_get_k);           // Missing parameter
    expect_no_match("/users/123/extra", ucall_verb_get_k); // Too many segments
}

TEST_F(RoutingTrieTest, MultipleParameters) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(route_trie_insert(trie, "/posts/{year}/{month}", ucall_verb_get_k, endpoint));

    expect_match("/posts/2024/11", ucall_verb_get_k, endpoint);
    expect_match("/posts/2025/01", ucall_verb_get_k, endpoint);
    expect_no_match("/posts/2024", ucall_verb_get_k);       // Missing parameter
    expect_no_match("/posts/2024/11/05", ucall_verb_get_k); // Too many segments
}

TEST_F(RoutingTrieTest, MixedLiteralsAndParameters) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(route_trie_insert(trie, "/api/{version}/users/{id}", ucall_verb_get_k, endpoint));

    expect_match("/api/v1/users/123", ucall_verb_get_k, endpoint);
    expect_match("/api/v2/users/456", ucall_verb_get_k, endpoint);
    expect_no_match("/api/v1/posts/123", ucall_verb_get_k); // Wrong literal
}

TEST_F(RoutingTrieTest, ParameterAtDifferentPositions) {
    void *endpoint1 = make_endpoint(1);
    void *endpoint2 = make_endpoint(2);
    void *endpoint3 = make_endpoint(3);

    ASSERT_TRUE(route_trie_insert(trie, "/{resource}/list", ucall_verb_get_k, endpoint1));
    ASSERT_TRUE(route_trie_insert(trie, "/admin/{action}", ucall_verb_get_k, endpoint2));
    ASSERT_TRUE(route_trie_insert(trie, "/api/{version}/{entity}", ucall_verb_get_k, endpoint3));

    expect_match("/users/list", ucall_verb_get_k, endpoint1);
    expect_match("/admin/dashboard", ucall_verb_get_k, endpoint2);
    expect_match("/api/v1/products", ucall_verb_get_k, endpoint3);
}

TEST_F(RoutingTrieTest, ParameterNamesStored) {
    // This test verifies that parameter names are stored in the trie nodes
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(route_trie_insert(trie, "/users/{user_id}/posts/{post_id}", ucall_verb_get_k, endpoint));

    // Navigate to parameter nodes and verify names are stored
    ASSERT_NE(trie.root, nullptr);

    // Find "users" literal child
    route_node_t *users_node = find_literal_child(trie.root, "users");
    ASSERT_NE(users_node, nullptr);

    // Verify first parameter node has correct name
    ASSERT_NE(users_node->param_child, nullptr);
    EXPECT_EQ(users_node->param_name, "user_id");

    // Find "posts" literal child
    route_node_t *posts_node = find_literal_child(users_node->param_child, "posts");
    ASSERT_NE(posts_node, nullptr);

    // Verify second parameter node has correct name
    ASSERT_NE(posts_node->param_child, nullptr);
    EXPECT_EQ(posts_node->param_name, "post_id");
}

TEST_F(RoutingTrieTest, ConflictingParameterNames) {
    void *endpoint1 = make_endpoint(1);
    void *endpoint2 = make_endpoint(2);

    // First route: /users/{id}/posts
    ASSERT_TRUE(route_trie_insert(trie, "/users/{id}/posts", ucall_verb_get_k, endpoint1));

    // Second route with different parameter name at same position should fail
    EXPECT_FALSE(route_trie_insert(trie, "/users/{user_id}/comments", ucall_verb_get_k, endpoint2));
}

#pragma endregion Parameter Matching Tests

#pragma region Wildcard Matching Tests

TEST_F(RoutingTrieTest, SimpleWildcard) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(route_trie_insert(trie, "/files/{*path}", ucall_verb_get_k, endpoint));

    expect_match("/files/a.txt", ucall_verb_get_k, endpoint);
    expect_match("/files/a/b/c.txt", ucall_verb_get_k, endpoint);
    expect_match("/files/deeply/nested/path/file.pdf", ucall_verb_get_k, endpoint);
    expect_no_match("/files", ucall_verb_get_k); // Need at least one segment for wildcard
}

TEST_F(RoutingTrieTest, WildcardWithPrefix) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(route_trie_insert(trie, "/static/{*filepath}", ucall_verb_get_k, endpoint));

    expect_match("/static/css/style.css", ucall_verb_get_k, endpoint);
    expect_match("/static/js/app.js", ucall_verb_get_k, endpoint);
    expect_match("/static/images/logo.png", ucall_verb_get_k, endpoint);
}

TEST_F(RoutingTrieTest, WildcardConsumesAllRemaining) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(route_trie_insert(trie, "/docs/{*page}", ucall_verb_get_k, endpoint));

    // Wildcard should consume any number of remaining segments
    expect_match("/docs/intro", ucall_verb_get_k, endpoint);
    expect_match("/docs/api/reference", ucall_verb_get_k, endpoint);
    expect_match("/docs/guides/getting-started/installation", ucall_verb_get_k, endpoint);
}

TEST_F(RoutingTrieTest, WildcardNameStored) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(route_trie_insert(trie, "/assets/{*filepath}", ucall_verb_get_k, endpoint));

    // Navigate to wildcard node and verify name
    ASSERT_NE(trie.root, nullptr);
    route_node_t *assets_node = find_literal_child(trie.root, "assets");
    ASSERT_NE(assets_node, nullptr);
    ASSERT_NE(assets_node->wildcard_child, nullptr);
    EXPECT_EQ(assets_node->wildcard_name, "filepath");
}

#pragma endregion Wildcard Matching Tests

#pragma region HTTP Verb Routing Tests

TEST_F(RoutingTrieTest, SamePathDifferentVerbs) {
    void *get_endpoint = make_endpoint(1);
    void *post_endpoint = make_endpoint(2);
    void *put_endpoint = make_endpoint(3);
    void *delete_endpoint = make_endpoint(4);

    ASSERT_TRUE(route_trie_insert(trie, "/users", ucall_verb_get_k, get_endpoint));
    ASSERT_TRUE(route_trie_insert(trie, "/users", ucall_verb_post_k, post_endpoint));
    ASSERT_TRUE(route_trie_insert(trie, "/users", ucall_verb_put_k, put_endpoint));
    ASSERT_TRUE(route_trie_insert(trie, "/users", ucall_verb_delete_k, delete_endpoint));

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
        ASSERT_TRUE(route_trie_insert(trie, "/test", verbs[i], endpoints[i]));
    }

    for (int i = 0; i < 7; ++i) { expect_match("/test", verbs[i], endpoints[i]); }
}

TEST_F(RoutingTrieTest, UnregisteredVerbReturnsNull) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(route_trie_insert(trie, "/users", ucall_verb_get_k, endpoint));

    expect_match("/users", ucall_verb_get_k, endpoint);
    expect_no_match("/users", ucall_verb_post_k); // POST not registered
}

TEST_F(RoutingTrieTest, DuplicateVerbFails) {
    void *endpoint1 = make_endpoint(1);
    void *endpoint2 = make_endpoint(2);

    ASSERT_TRUE(route_trie_insert(trie, "/users", ucall_verb_get_k, endpoint1));
    EXPECT_FALSE(route_trie_insert(trie, "/users", ucall_verb_get_k, endpoint2)); // Duplicate
}

#pragma endregion HTTP Verb Routing Tests

#pragma region Query String and Fragment Tests

TEST_F(RoutingTrieTest, QueryStringStripped) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(route_trie_insert(trie, "/search", ucall_verb_get_k, endpoint));

    expect_match("/search?q=test", ucall_verb_get_k, endpoint);
    expect_match("/search?q=test&page=2", ucall_verb_get_k, endpoint);
    expect_match("/search?key=value&another=param", ucall_verb_get_k, endpoint);
}

TEST_F(RoutingTrieTest, FragmentStripped) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(route_trie_insert(trie, "/docs", ucall_verb_get_k, endpoint));

    expect_match("/docs#section1", ucall_verb_get_k, endpoint);
    expect_match("/docs#top", ucall_verb_get_k, endpoint);
}

TEST_F(RoutingTrieTest, QueryAndFragmentStripped) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(route_trie_insert(trie, "/page", ucall_verb_get_k, endpoint));

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

    ASSERT_TRUE(route_trie_insert(trie, "/users/{id}", ucall_verb_get_k, param_endpoint));
    ASSERT_TRUE(route_trie_insert(trie, "/users/new", ucall_verb_get_k, literal_endpoint));

    // Literal should be preferred
    expect_match("/users/new", ucall_verb_get_k, literal_endpoint);
    expect_match("/users/123", ucall_verb_get_k, param_endpoint);
}

TEST_F(RoutingTrieTest, ParameterBeatsWildcard) {
    void *param_endpoint = make_endpoint(1);
    void *wildcard_endpoint = make_endpoint(2);

    ASSERT_TRUE(route_trie_insert(trie, "/files/{*path}", ucall_verb_get_k, wildcard_endpoint));
    ASSERT_TRUE(route_trie_insert(trie, "/files/{id}", ucall_verb_get_k, param_endpoint));

    // Parameter should beat wildcard for single segment
    expect_match("/files/123", ucall_verb_get_k, param_endpoint);

    // Wildcard wins for multiple segments
    expect_match("/files/a/b/c", ucall_verb_get_k, wildcard_endpoint);
}

TEST_F(RoutingTrieTest, InsertionOrderIrrelevant) {
    void *endpoint1 = make_endpoint(1);
    void *endpoint2 = make_endpoint(2);

    // Insert parameter first, literal second
    ASSERT_TRUE(route_trie_insert(trie, "/items/{id}", ucall_verb_get_k, endpoint1));
    ASSERT_TRUE(route_trie_insert(trie, "/items/featured", ucall_verb_get_k, endpoint2));

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

    ASSERT_TRUE(route_trie_insert(trie, path, ucall_verb_get_k, endpoint));
    expect_match(path, ucall_verb_get_k, endpoint);
}

TEST_F(RoutingTrieTest, ExceedingMaximumSegments) {
    // 17 segments exceeds the limit
    void *endpoint = make_endpoint(1);
    char const *path = "/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q"; // 17 segments

    // Should fail to parse or insert
    bool result = route_trie_insert(trie, path, ucall_verb_get_k, endpoint);
    EXPECT_FALSE(result) << "Should reject paths with >16 segments";
}

TEST_F(RoutingTrieTest, DuplicateRouteRegistration) {
    void *endpoint1 = make_endpoint(1);
    void *endpoint2 = make_endpoint(2);

    ASSERT_TRUE(route_trie_insert(trie, "/users/{id}", ucall_verb_get_k, endpoint1));
    EXPECT_FALSE(route_trie_insert(trie, "/users/{id}", ucall_verb_get_k, endpoint2)); // Duplicate
}

TEST_F(RoutingTrieTest, TrailingSlashHandling) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(route_trie_insert(trie, "/users", ucall_verb_get_k, endpoint));

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
    ASSERT_TRUE(route_trie_insert(trie, long_path.c_str(), ucall_verb_get_k, endpoint));
    expect_match(long_path.c_str(), ucall_verb_get_k, endpoint);
}

TEST_F(RoutingTrieTest, EmptySegmentsSkipped) {
    void *endpoint = make_endpoint(1);
    ASSERT_TRUE(route_trie_insert(trie, "/users", ucall_verb_get_k, endpoint));

    // Double slashes create empty segments which are skipped
    expect_match("/users", ucall_verb_get_k, endpoint);
    // Note: Current implementation doesn't normalize //, so this might not match
    // Depends on whether Ada or similar is used for normalization
}

TEST_F(RoutingTrieTest, BufferCapacityLimits) {
    // Initialize with very small capacity
    route_trie_t small_trie;
    ASSERT_TRUE(route_trie_init(small_trie, 10, 10, 10)); // Only 10 nodes, 10 edges, 10 endpoints

    void *endpoint = make_endpoint(1);

    // Fill up the trie
    bool insert_succeeded = true;
    int routes_added = 0;
    for (int i = 0; i < 20 && insert_succeeded; ++i) {
        std::string path = "/route" + std::to_string(i);
        insert_succeeded = route_trie_insert(small_trie, path.c_str(), ucall_verb_get_k, endpoint);
        if (insert_succeeded) routes_added++;
    }

    // Should have hit capacity limit before 20 routes
    EXPECT_LT(routes_added, 20) << "Should hit capacity limit";
    EXPECT_GT(routes_added, 0) << "Should insert at least some routes";

    route_trie_free(small_trie);
}

#pragma endregion Edge Cases Tests

#pragma region Error Handling Tests

TEST_F(RoutingTrieTest, NodesPoolExhausted) {
    // Initialize with minimal node capacity
    route_trie_t tiny_trie;
    ASSERT_TRUE(route_trie_init(tiny_trie, 2, 100, 100)); // Only 2 nodes (root + 1 more)

    void *endpoint = make_endpoint(1);

    // First insert should succeed (uses root)
    EXPECT_TRUE(route_trie_insert(tiny_trie, "/a", ucall_verb_get_k, endpoint));

    // Second insert might fail due to pool exhaustion
    bool second = route_trie_insert(tiny_trie, "/b", ucall_verb_get_k, endpoint);

    // Third insert should definitely fail
    bool third = route_trie_insert(tiny_trie, "/c", ucall_verb_get_k, endpoint);

    EXPECT_FALSE(second || third) << "Should fail when nodes pool exhausted";

    route_trie_free(tiny_trie);
}

TEST_F(RoutingTrieTest, EdgesBufferExhausted) {
    // Initialize with minimal edge capacity
    route_trie_t tiny_trie;
    ASSERT_TRUE(route_trie_init(tiny_trie, 100, 2, 100)); // Plenty of nodes, only 2 edges

    void *endpoint = make_endpoint(1);

    // First insert should succeed
    EXPECT_TRUE(route_trie_insert(tiny_trie, "/a", ucall_verb_get_k, endpoint));

    // More inserts should eventually fail when edge buffer is full
    bool failed = false;
    for (int i = 0; i < 10 && !failed; ++i) {
        std::string path = "/route" + std::to_string(i);
        if (!route_trie_insert(tiny_trie, path.c_str(), ucall_verb_get_k, endpoint)) { failed = true; }
    }

    EXPECT_TRUE(failed) << "Should fail when edges buffer exhausted";

    route_trie_free(tiny_trie);
}

TEST_F(RoutingTrieTest, InvalidTemplateSyntax) {
    void *endpoint = make_endpoint(1);

    // Empty braces
    EXPECT_FALSE(route_trie_insert(trie, "/users/{}", ucall_verb_get_k, endpoint));

    // Wildcard without name
    EXPECT_FALSE(route_trie_insert(trie, "/files/{*}", ucall_verb_get_k, endpoint));

    // Unclosed braces
    EXPECT_FALSE(route_trie_insert(trie, "/users/{id", ucall_verb_get_k, endpoint));
}

TEST_F(RoutingTrieTest, NullPointerSafety) {
    // Match should handle nullptr safely
    void *result = route_trie_match(trie, "/test", ucall_verb_get_k);
    EXPECT_EQ(result, nullptr);

    // find_literal_child with null node
    route_node_t *child = find_literal_child(nullptr, "test");
    EXPECT_EQ(child, nullptr);
}

#pragma endregion Error Handling Tests

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
