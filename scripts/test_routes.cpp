/**
 *  @brief Tests for the segment-level URI routing trie in @c routes.hpp.
 *  @file scripts/test_routes.cpp
 *  @author Ash Vardanian
 *
 *  Every case builds its own trie: precedence is a property of the whole registered set, so a
 *  shared trie would make the answers depend on which case ran first.
 */
#include <cstdint> // `std::uintptr_t`

#include <string_view> // `std::string_view`

#include "routes.hpp" // `route_trie_t`, `extract_path_component`
#include "test.hpp"   // `verify`, `run_test`, `scale_iterations`

using namespace unum::ucall;
using namespace unum::ucall::scripts;

#pragma region Fixtures

/** @brief Every verb the router distinguishes, so a sweep is a loop rather than seven copies. */
static constexpr ucall_verb_t routed_verbs_k[] = {ucall_verb_get_k,    ucall_verb_post_k,  ucall_verb_put_k,
                                                  ucall_verb_delete_k, ucall_verb_patch_k, ucall_verb_head_k,
                                                  ucall_verb_options_k};

/**
 *  @brief Lets `{}` name a verb rather than print its ordinal.
 *
 *  `ucall_verb_t` is a C enum at global scope, so the overload lives here for ADL to find.
 */
[[nodiscard]] inline auto format_as(ucall_verb_t verb) noexcept {
    switch (verb) {
    case ucall_verb_get_k: return "GET";
    case ucall_verb_post_k: return "POST";
    case ucall_verb_put_k: return "PUT";
    case ucall_verb_delete_k: return "DELETE";
    case ucall_verb_patch_k: return "PATCH";
    case ucall_verb_head_k: return "HEAD";
    case ucall_verb_options_k: return "OPTIONS";
    case ucall_verb_any_k: return "ANY";
    default: return "UNKNOWN";
    }
}

/** @brief A stand-in endpoint, distinguishable by the number it was made from. */
[[nodiscard]] static void *endpoint_numbered(std::uintptr_t number) noexcept {
    return reinterpret_cast<void *>(number);
}

/** @brief One case's trie, announced as it starts and torn down when its scope ends. */
struct routing_case_t {
    route_trie_t trie {};

    explicit routing_case_t(char const *label) {
        announce("{}", label);
        verify(trie.init(), "the trie for `{}` could not allocate", label);
    }

    /** @brief Registers a route that must be accepted. */
    void must_add(char const *route, ucall_verb_t verb, void *endpoint) {
        verify(trie.insert(route, verb, endpoint), "registering `{}` [{}] was refused", route, verb);
    }

    /** @brief Registers a route that must be rejected. */
    void must_refuse(char const *route, ucall_verb_t verb, void *endpoint) {
        verify(!trie.insert(route, verb, endpoint), "registering `{}` [{}] was accepted", route, verb);
    }

    void must_match(char const *path, ucall_verb_t verb, void *expected) const {
        void *const matched = trie.match(path, verb);
        verify(matched == expected, "`{}` [{}] matched endpoint {}, expected {}", path, verb,
               reinterpret_cast<std::uintptr_t>(matched), reinterpret_cast<std::uintptr_t>(expected));
    }

    void must_not_match(char const *path, ucall_verb_t verb) const { must_match(path, verb, nullptr); }
};

/**
 *  @brief Backing storage for generated route templates.
 *
 *  @c insert keeps the view it was handed rather than a copy, so the characters outlive the trie.
 */
struct path_arena_t {
    static constexpr std::size_t slot_width_k = 32;
    buffer<char> characters {};

    [[nodiscard]] bool reserve(std::size_t routes) noexcept { return characters.reallocate(routes * slot_width_k); }

    /** @brief Writes `/route<index>` into its own slot and returns a view of it. */
    [[nodiscard]] std::string_view emit(std::size_t index) {
        char *const slot = characters.data() + index * slot_width_k;
        auto const written = fmt::format_to_n(slot, slot_width_k - 1, "/route{}", index);
        verify(written.size < slot_width_k, "route {} needs {} characters, the slot holds {}", index, written.size,
               slot_width_k);
        *written.out = '\0';
        return {slot, written.size};
    }

    /** @brief The slot an earlier @c emit filled, as a zero-terminated string. */
    [[nodiscard]] char const *written(std::size_t index) const noexcept {
        return characters.data() + index * slot_width_k;
    }
};

#pragma endregion Fixtures

#pragma region Known Answers

void test_routes_unit() {
    void *const first = endpoint_numbered(1);
    void *const second = endpoint_numbered(2);
    void *const third = endpoint_numbered(3);

    {
        routing_case_t routes("root_path");
        routes.must_add("/", ucall_verb_get_k, first);
        routes.must_match("/", ucall_verb_get_k, first);
        routes.must_not_match("/", ucall_verb_post_k);
    }
    {
        routing_case_t routes("single_literal_segment");
        routes.must_add("/users", ucall_verb_get_k, first);
        routes.must_add("/posts", ucall_verb_get_k, second);
        routes.must_match("/users", ucall_verb_get_k, first);
        routes.must_match("/posts", ucall_verb_get_k, second);
        routes.must_not_match("/admin", ucall_verb_get_k);
    }
    {
        routing_case_t routes("multi_segment_literals");
        routes.must_add("/api/v1/users", ucall_verb_get_k, first);
        routes.must_match("/api/v1/users", ucall_verb_get_k, first);
        routes.must_not_match("/api/v1", ucall_verb_get_k);
        routes.must_not_match("/api/v1/users/extra", ucall_verb_get_k);
    }
    {
        routing_case_t routes("single_parameter");
        routes.must_add("/users/{id}", ucall_verb_get_k, first);
        routes.must_match("/users/123", ucall_verb_get_k, first);
        routes.must_match("/users/abc", ucall_verb_get_k, first);
        routes.must_match("/users/foo-bar", ucall_verb_get_k, first);
        routes.must_not_match("/users", ucall_verb_get_k);
        routes.must_not_match("/users/123/extra", ucall_verb_get_k);
    }
    {
        routing_case_t routes("multiple_parameters");
        routes.must_add("/posts/{year}/{month}", ucall_verb_get_k, first);
        routes.must_match("/posts/2024/11", ucall_verb_get_k, first);
        routes.must_match("/posts/2025/01", ucall_verb_get_k, first);
        routes.must_not_match("/posts/2024", ucall_verb_get_k);
        routes.must_not_match("/posts/2024/11/05", ucall_verb_get_k);
    }
    {
        routing_case_t routes("mixed_literals_and_parameters");
        routes.must_add("/api/{version}/users/{id}", ucall_verb_get_k, first);
        routes.must_match("/api/v1/users/123", ucall_verb_get_k, first);
        routes.must_match("/api/v2/users/456", ucall_verb_get_k, first);
        routes.must_not_match("/api/v1/posts/123", ucall_verb_get_k);
    }
    {
        routing_case_t routes("parameters_at_different_positions");
        routes.must_add("/{resource}/list", ucall_verb_get_k, first);
        routes.must_add("/admin/{action}", ucall_verb_get_k, second);
        routes.must_add("/api/{version}/{entity}", ucall_verb_get_k, third);
        routes.must_match("/users/list", ucall_verb_get_k, first);
        routes.must_match("/admin/dashboard", ucall_verb_get_k, second);
        routes.must_match("/api/v1/products", ucall_verb_get_k, third);
    }
    {
        // Parameter names are not observable through `match`, so only the structure is pinned.
        routing_case_t routes("named_parameters_match_on_structure");
        routes.must_add("/users/{user_id}/posts/{post_id}", ucall_verb_get_k, first);
        routes.must_match("/users/123/posts/456", ucall_verb_get_k, first);
        routes.must_match("/users/abc/posts/xyz", ucall_verb_get_k, first);
        routes.must_not_match("/users/123", ucall_verb_get_k);
        routes.must_not_match("/users/123/posts", ucall_verb_get_k);
    }
    {
        routing_case_t routes("wildcard_consumes_every_remaining_segment");
        routes.must_add("/files/{*path}", ucall_verb_get_k, first);
        routes.must_match("/files/a.txt", ucall_verb_get_k, first);
        routes.must_match("/files/a/b/c.txt", ucall_verb_get_k, first);
        routes.must_match("/files/deeply/nested/path/file.pdf", ucall_verb_get_k, first);
        // A wildcard still demands a segment to consume, so the bare prefix is not a match.
        routes.must_not_match("/files", ucall_verb_get_k);
    }
    {
        routing_case_t routes("wildcard_behind_a_literal_prefix");
        routes.must_add("/static/{*filepath}", ucall_verb_get_k, first);
        routes.must_match("/static/css/style.css", ucall_verb_get_k, first);
        routes.must_match("/static/js/app.js", ucall_verb_get_k, first);
        routes.must_match("/static/images/logo.png", ucall_verb_get_k, first);
        routes.must_match("/static/a/b/c/d/e", ucall_verb_get_k, first);
    }
    {
        routing_case_t routes("one_path_many_verbs");
        std::uintptr_t number = 1;
        for (ucall_verb_t const verb : routed_verbs_k) routes.must_add("/test", verb, endpoint_numbered(number++));
        number = 1;
        for (ucall_verb_t const verb : routed_verbs_k) routes.must_match("/test", verb, endpoint_numbered(number++));
    }
    {
        routing_case_t routes("unregistered_verb_does_not_match");
        routes.must_add("/users", ucall_verb_get_k, first);
        routes.must_match("/users", ucall_verb_get_k, first);
        routes.must_not_match("/users", ucall_verb_post_k);
    }
    {
        routing_case_t routes("query_and_fragment_are_stripped");
        routes.must_add("/search", ucall_verb_get_k, first);
        routes.must_add("/page", ucall_verb_get_k, second);
        routes.must_match("/search?q=test", ucall_verb_get_k, first);
        routes.must_match("/search?q=test&page=2", ucall_verb_get_k, first);
        routes.must_match("/page#section1", ucall_verb_get_k, second);
        routes.must_match("/page?key=value#section", ucall_verb_get_k, second);
        // A fragment opens first, so everything after it is fragment - including a `?`.
        routes.must_match("/page#section?not_a_query", ucall_verb_get_k, second);

        verify(extract_path_component("/users") == "/users");
        verify(extract_path_component("/users?limit=10") == "/users");
        verify(extract_path_component("/users#top") == "/users");
        verify(extract_path_component("/users?limit=10#top") == "/users");
        verify(extract_path_component("") == "");
    }
    {
        routing_case_t routes("a_literal_outranks_a_parameter");
        routes.must_add("/users/{id}", ucall_verb_get_k, first);
        routes.must_add("/users/new", ucall_verb_get_k, second);
        routes.must_match("/users/new", ucall_verb_get_k, second);
        routes.must_match("/users/123", ucall_verb_get_k, first);
    }
    {
        routing_case_t routes("a_parameter_outranks_a_wildcard");
        routes.must_add("/files/{*path}", ucall_verb_get_k, first);
        routes.must_add("/files/{id}", ucall_verb_get_k, second);
        // One segment is what a parameter is for; more than one is only a wildcard's to take.
        routes.must_match("/files/123", ucall_verb_get_k, second);
        routes.must_match("/files/a/b/c", ucall_verb_get_k, first);
    }
    {
        // RFC 9110 makes a path case-sensitive, which surprises anyone expecting host semantics.
        routing_case_t routes("matching_is_case_sensitive");
        routes.must_add("/users", ucall_verb_get_k, first);
        routes.must_match("/users", ucall_verb_get_k, first);
        routes.must_not_match("/Users", ucall_verb_get_k);
        routes.must_not_match("/USERS", ucall_verb_get_k);
    }
    {
        // Percent-encoding is never decoded, so `%2F` stays one character of a segment rather
        // than becoming a separator. A guard written against the decoded form would not see what
        // this trie sees.
        routing_case_t routes("percent_encoding_is_not_decoded");
        routes.must_add("/files/{name}", ucall_verb_get_k, first);
        routes.must_match("/files/a%2Fb", ucall_verb_get_k, first);
        routes.must_match("/files/%2Ffoo", ucall_verb_get_k, first);
        // The decoded spelling is two segments, which one parameter cannot take.
        routes.must_not_match("/files/a/b", ucall_verb_get_k);
    }
    {
        routing_case_t routes("a_percent_escape_in_a_template_stays_literal");
        routes.must_add("/files/%2F", ucall_verb_get_k, second);
        routes.must_match("/files/%2F", ucall_verb_get_k, second);
        routes.must_not_match("/files//", ucall_verb_get_k);
    }
    {
        routing_case_t routes("precedence_ignores_insertion_order");
        routes.must_add("/items/{id}", ucall_verb_get_k, first);
        routes.must_add("/items/featured", ucall_verb_get_k, second);
        routes.must_match("/items/featured", ucall_verb_get_k, second);
        routes.must_match("/items/123", ucall_verb_get_k, first);
    }
}

#pragma endregion Known Answers

#pragma region Hostile And Malformed Input

void test_routes_safety() {
    void *const first = endpoint_numbered(1);
    void *const second = endpoint_numbered(2);

    {
        routing_case_t routes("an_empty_trie_matches_nothing");
        routes.must_not_match("/test", ucall_verb_get_k);
        routes.must_not_match("", ucall_verb_get_k);
    }
    {
        routing_case_t routes("malformed_templates_are_refused");
        routes.must_refuse("/users/{}", ucall_verb_get_k, first);  // a parameter with no name
        routes.must_refuse("/files/{*}", ucall_verb_get_k, first); // a wildcard with no name
        routes.must_refuse("/users/{id", ucall_verb_get_k, first); // a brace that never closes
    }
    {
        // The trie stores one name per node rather than one per route.
        routing_case_t routes("parameters_may_not_be_renamed_mid_trie");
        routes.must_add("/users/{id}/posts", ucall_verb_get_k, first);
        routes.must_refuse("/users/{user_id}/comments", ucall_verb_get_k, second);
    }
    {
        routing_case_t routes("a_verb_may_be_claimed_once");
        routes.must_add("/users", ucall_verb_get_k, first);
        routes.must_refuse("/users", ucall_verb_get_k, second);
    }
    {
        routing_case_t routes("a_route_may_be_claimed_once");
        routes.must_add("/users/{id}", ucall_verb_get_k, first);
        routes.must_refuse("/users/{id}", ucall_verb_get_k, second);
    }
    {
        // Accepting the last permitted depth and refusing the first forbidden one is what makes
        // `routes.hpp`'s sixteen a ceiling rather than a guess.
        routing_case_t routes("the_segment_ceiling_is_exact");
        routes.must_add("/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p", ucall_verb_get_k, first);
        routes.must_match("/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p", ucall_verb_get_k, first);
        routes.must_refuse("/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q", ucall_verb_get_k, second);
    }
    {
        // A thousand characters, inside RFC 9110's advisory limit and past any fixed segment
        // buffer.
        routing_case_t routes("a_very_long_path_still_routes");
        char long_path[1 + 10 * 101] {};
        std::size_t written = 0;
        for (std::size_t segment = 0; segment != 10; ++segment) {
            long_path[written++] = '/';
            for (std::size_t character = 0; character != 100; ++character) long_path[written++] = 'a';
        }
        long_path[written] = '\0';
        routes.must_add(long_path, ucall_verb_get_k, first);
        routes.must_match(long_path, ucall_verb_get_k, first);
    }
    {
        // `routes.hpp` says routes are immutable after registration and that matching is lock-free
        // because of it. Nothing enforces that: a late `insert` is accepted and takes effect, so a
        // server registering an endpoint after it starts serving races its own matcher with no
        // guard anywhere. Pinned as it behaves, so a decision to refuse late writes is visible.
        routing_case_t routes("a_late_registration_is_silently_accepted");
        routes.must_add("/users", ucall_verb_get_k, first);
        routes.must_match("/users", ucall_verb_get_k, first);
        routes.must_add("/posts", ucall_verb_get_k, second);
        routes.must_match("/posts", ucall_verb_get_k, second);
        routes.must_match("/users", ucall_verb_get_k, first);
    }
    {
        // Empty segments are skipped rather than matched, so all three spellings reach one route.
        routing_case_t routes("empty_segments_are_skipped");
        routes.must_add("/users", ucall_verb_get_k, first);
        routes.must_match("/users", ucall_verb_get_k, first);
        routes.must_match("/users/", ucall_verb_get_k, first);
        routes.must_match("//users", ucall_verb_get_k, first);
        routes.must_match("/users//", ucall_verb_get_k, first);
    }
}

#pragma endregion Hostile And Malformed Input

#pragma region Sweeps

/**
 *  @brief Registration past the initial pool capacity, which must grow rather than refuse.
 *
 *  The pools chain rather than reallocate, so a sweep - not one insertion past the boundary - is
 *  what proves every earlier route kept its address.
 */
void test_routes_stress() {
    routing_case_t routes("pools_grow_and_keep_every_earlier_route");
    std::size_t const routes_count = scale_iterations(500);
    path_arena_t arena;
    verify(arena.reserve(routes_count), "an arena for {} routes could not allocate", routes_count);

    std::size_t const initial_pools = routes.trie.pool_count();
    std::size_t observed_capacity = routes.trie.capacity();
    std::size_t observed_pools = initial_pools;
    void *const endpoint = endpoint_numbered(1);

    for (std::size_t index = 0; index != routes_count; ++index) {
        std::string_view const route = arena.emit(index);
        verify(routes.trie.insert(route, ucall_verb_get_k, endpoint), "route {} of {} was refused", index,
               routes_count);

        std::size_t const pools_now = routes.trie.pool_count();
        if (pools_now > observed_pools) {
            verify(routes.trie.capacity() > observed_capacity);
            observed_capacity = routes.trie.capacity();
            observed_pools = pools_now;
        }
    }

    verify(observed_pools > initial_pools);

    // Growth relocates nothing, so a route registered before the first new pool still matches.
    for (std::size_t index = 0; index != routes_count; ++index)
        routes.must_match(arena.written(index), ucall_verb_get_k, endpoint);
}

#pragma endregion Sweeps

int main() {
    install_test_signal_handlers();
    fmt::print("Hi, dear tester! You look nice today!\n");
    configure_tests();

    run_test("test_routes_unit", test_routes_unit);
    run_test("test_routes_safety", test_routes_safety);
    run_test("test_routes_stress", test_routes_stress);

    fmt::print("All tests passed.\n");
    return 0;
}
