/**
 *  @file test/http/routes.cpp
 *  @author Ash Vardanian
 *  @date November 13, 2025
 *  @brief Tests for the segment-level URI routing trie in @c routes.hpp.
 *
 *  Every case builds its own trie: precedence is a property of the whole registered set, so a
 *  shared trie would make the answers depend on which case ran first.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build

#include <cstdint> // `std::uintptr_t`

#include <string>      // `std::string`
#include <string_view> // `std::string_view`

#include <fmt/ranges.h> // formatting the drawn routes and paths

#include "ucall/http/routes.hpp" // `route_trie_t`, `extract_path_component`
#include "harness.hpp"           // `expect_true`, `scaled_iterations`
#include "properties.hpp"        // `check_route_match`

/**
 *  @brief Lets <tt>{}</tt> name a verb rather than print its ordinal.
 *
 *  @c ucall_verb_t is a C enum at global scope, so the overload lives here for ADL to find.
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

namespace unum::ucall::test::http {

using namespace unum::ucall::http;

#pragma region Fixtures

/** Every verb the router distinguishes, so a sweep is a loop rather than seven copies. */
static constexpr ucall_verb_t routed_verbs_k[] = {ucall_verb_get_k,    ucall_verb_post_k,  ucall_verb_put_k,
                                                  ucall_verb_delete_k, ucall_verb_patch_k, ucall_verb_head_k,
                                                  ucall_verb_options_k};

/** A stand-in endpoint, distinguishable by the number it was made from. */
[[nodiscard]] static void* endpoint_numbered(std::uintptr_t number) noexcept { return reinterpret_cast<void*>(number); }

/** One step's trie, named in its allocation failure. */
struct routing_case_t {
    route_trie_t trie {st::default_allocator<byte_t> {}};

    explicit routing_case_t(char const* label) {
        expect_true(trie.init() == ucall_status_success_k, "the trie for `{}` could not allocate", label);
    }

    /** Registers a route that must be accepted. */
    void must_add(char const* route, ucall_verb_t verb, void* endpoint) {
        expect_true(trie.insert(route, verb, endpoint) == ucall_status_success_k, "registering `{}` [{}] was refused",
                    route, verb);
    }

    /** Registers a route that must be rejected. */
    void must_refuse(char const* route, ucall_verb_t verb, void* endpoint) {
        expect_true(trie.insert(route, verb, endpoint) != ucall_status_success_k, "registering `{}` [{}] was accepted",
                    route, verb);
    }

    void must_match(std::string_view path, ucall_verb_t verb, void* expected) const {
        void* const matched = trie.match(path, verb);
        expect_true(matched == expected, "`{}` [{}] matched endpoint {}, expected {}", path, verb,
                    reinterpret_cast<std::uintptr_t>(matched), reinterpret_cast<std::uintptr_t>(expected));
    }

    void must_not_match(std::string_view path, ucall_verb_t verb) const { must_match(path, verb, nullptr); }
};

/**
 *  @brief Backing storage for generated route templates.
 *
 *  @c insert keeps the view it was handed rather than a copy, so the characters outlive the trie.
 */
struct path_arena_t {
    static constexpr std::size_t slot_width_k = 32;
    st::vector<char> characters {};

    [[nodiscard]] bool reserve(std::size_t routes) noexcept {
        return !st::failed(characters.resize(routes * slot_width_k));
    }

    /** Writes `/route<index>` into its own slot and views it, or views nothing if it overflows. */
    [[nodiscard]] std::string_view emit(std::size_t index) {
        char* const slot = characters.data() + index * slot_width_k;
        auto const written = fmt::format_to_n(slot, slot_width_k - 1, "/route{}", index);
        *written.out = '\0';
        if (written.size >= slot_width_k) return {};
        return {slot, written.size};
    }

    /** The route an earlier @c emit wrote into slot @p index. */
    [[nodiscard]] std::string_view written(std::size_t index) const noexcept {
        return {characters.data() + index * slot_width_k};
    }
};

#pragma endregion Fixtures

#pragma region Known Answers

static void test_routes() {
    void* const first = endpoint_numbered(1);
    void* const second = endpoint_numbered(2);
    void* const third = endpoint_numbered(3);

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
        routing_case_t routes("head_falls_back_to_get");
        routes.must_add("/page", ucall_verb_get_k, first);
        routes.must_add("/both", ucall_verb_get_k, second);
        routes.must_add("/both", ucall_verb_head_k, third);
        routes.must_match("/page", ucall_verb_head_k, first);
        routes.must_match("/both", ucall_verb_head_k, third);
        routes.must_not_match("/page", ucall_verb_post_k);
        verb_set_t allowed {};
        expect_true(!routes.trie.match("/page", ucall_verb_post_k, nullptr, &allowed) &&
                        allowed == verb_set_t(1u << ucall_verb_get_k),
                    "a miss reported verbs {:#x}", allowed);
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

        expect_true(extract_path_component("/users") == "/users");
        expect_true(extract_path_component("/users?limit=10") == "/users");
        expect_true(extract_path_component("/users#top") == "/users");
        expect_true(extract_path_component("/users?limit=10#top") == "/users");
        expect_true(extract_path_component("") == "");
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
        routing_case_t routes("precedence_backtracks_from_a_dead_branch");
        routes.must_add("/files/featured/details", ucall_verb_get_k, first);
        routes.must_add("/files/{id}/content", ucall_verb_get_k, second);
        routes.must_add("/files/{*path}", ucall_verb_get_k, third);
        routes.must_match("/files/featured/details", ucall_verb_get_k, first);
        routes.must_match("/files/featured/content", ucall_verb_get_k, second);
        routes.must_match("/files/featured/other", ucall_verb_get_k, third);
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

#pragma region Hostile Input And Sweeps

static void test_routes_hostile() {
    void* const first = endpoint_numbered(1);
    void* const second = endpoint_numbered(2);

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
        routing_case_t routes("path_depth_does_not_truncate_matching");
        routes.must_add("/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p", ucall_verb_get_k, first);
        routes.must_add("/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q", ucall_verb_get_k, second);
        routes.must_match("/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p", ucall_verb_get_k, first);
        routes.must_match("/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q", ucall_verb_get_k, second);
        routes.must_not_match("/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r", ucall_verb_get_k);
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
        // Collapsing slashes would let `//admin//secret` past a rule guarding `/admin/secret`.
        routing_case_t routes("empty_segments_are_segments");
        routes.must_add("/users", ucall_verb_get_k, first);
        routes.must_add("/a//b", ucall_verb_get_k, second);
        routes.must_match("/users", ucall_verb_get_k, first);
        routes.must_not_match("//users", ucall_verb_get_k);
        routes.must_not_match("/users//", ucall_verb_get_k);
        routes.must_match("/a//b", ucall_verb_get_k, second);
        routes.must_not_match("/a/b", ucall_verb_get_k);
        expect_true(
            count_path_segments("/") == 0 && count_path_segments("/a/") == 2 && count_path_segments("//a//") == 4,
            "segment counts");
    }
    {
        routing_case_t routes("trailing_slash_is_significant");
        routes.must_add("/users", ucall_verb_get_k, first);
        routes.must_add("/users/", ucall_verb_get_k, second);
        routes.must_match("/users", ucall_verb_get_k, first);
        routes.must_match("/users/", ucall_verb_get_k, second);
        routes.must_not_match("/users//", ucall_verb_get_k);
    }
    {
        routing_case_t routes("a_parameter_takes_no_empty_segment");
        routes.must_add("/users/{id}", ucall_verb_get_k, first);
        routes.must_add("/users/{id}/posts", ucall_verb_get_k, second);
        routes.must_match("/users/7", ucall_verb_get_k, first);
        routes.must_not_match("/users/", ucall_verb_get_k);
        routes.must_not_match("/users//posts", ucall_verb_get_k);
    }
    {
        routing_case_t routes("a_wildcard_keeps_inner_empty_segments");
        routes.must_add("/files/{*path}", ucall_verb_get_k, first);
        routes.must_add("/files/new", ucall_verb_get_k, second);
        routes.must_match("/files//a", ucall_verb_get_k, first);
        routes.must_match("/files/a//b", ucall_verb_get_k, first);
        routes.must_match("/files/new/", ucall_verb_get_k, first);
        routes.must_not_match("/files/", ucall_verb_get_k);
    }
}

/**
 *  @brief Registration past the initial pool capacity, which must grow rather than refuse.
 *
 *  The pools chain rather than reallocate, so a sweep - not one insertion past the boundary - is
 *  what proves every earlier route kept its address.
 */
static void test_routes_sweep() {
    routing_case_t routes("pools_grow_and_keep_every_earlier_route");
    std::size_t const routes_count = scaled_iterations(500);
    path_arena_t arena;
    if (!expect_true(arena.reserve(routes_count), "an arena for {} routes could not allocate", routes_count)) return;

    void* const endpoint = endpoint_numbered(1);

    for (std::size_t index = 0; index != routes_count; ++index) {
        std::string_view const route = arena.emit(index);
        expect_true(!route.empty(), "route {} overflows a {}-character slot", index, path_arena_t::slot_width_k);
        expect_true(routes.trie.insert(route, ucall_verb_get_k, endpoint) == ucall_status_success_k,
                    "route {} of {} was refused", index, routes_count);
    }

    // Growth relocates nothing, so a route registered before the first new pool still matches.
    for (std::size_t index = 0; index != routes_count; ++index)
        routes.must_match(arena.written(index), ucall_verb_get_k, endpoint);
}

#pragma endregion Hostile Input And Sweeps

#pragma region Reference Matcher

/** Joins @p count segments drawn from @p vocabulary into a path that starts with a slash. */
template <std::size_t size_>
static std::string draw_path(std::string_view const (&vocabulary)[size_], std::size_t count,
                             split_mix_generator_t& generator) {
    std::string path;
    for (std::size_t index = 0; index != count; ++index) path += fmt::format("/{}", vocabulary[generator.below(size_)]);
    return path.empty() ? "/" : path;
}

static void test_route_match(split_mix_generator_t& generator) {
    static constexpr std::string_view template_segments_k[] {"a", "b", "", "{x}", "{y}", "{*rest}"};
    static constexpr std::string_view path_segments_k[] {"a", "b", "", "c"};
    static constexpr ucall_verb_t verbs_k[] {ucall_verb_get_k, ucall_verb_post_k, ucall_verb_head_k, ucall_verb_any_k};
    for (std::size_t iteration = 0; iteration != scaled_iterations(5000); ++iteration) {
        std::vector<std::string> templates, paths;
        std::vector<ucall_verb_t> verbs;
        for (std::size_t count = generator.below(9); count; --count) {
            templates.push_back(draw_path(template_segments_k, generator.below(4), generator));
            verbs.push_back(verbs_k[generator.below(std::size(verbs_k))]);
        }
        for (std::size_t count = 1 + generator.below(8); count; --count)
            paths.push_back(draw_path(path_segments_k, generator.below(5), generator) +
                            (generator.below(4) ? "" : "?q"));
        std::vector<std::string_view> template_views {templates.begin(), templates.end()},
            path_views {paths.begin(), paths.end()};
        std::size_t const found = check_route_match(template_views, verbs, path_views);
        expect_true(!found, "{} disagreements routing {} over {}", found, paths, templates);
        if (found) break;
    }
}

#pragma endregion Reference Matcher

void run_routes_cases() {
    run_test_case("run_routes_cases", [] {
        split_mix_generator_t generator {case_stream_key()};
        test_routes();
        test_routes_hostile();
        test_routes_sweep();
        test_route_match(generator);
    });
}

} // namespace unum::ucall::test::http
