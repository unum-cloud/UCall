/**
 *  @file c/test.c
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief A C caller of the linked library: names, versions, outcomes and Noise keys, then every
 *      documented refusal reachable without a peer, against the engine and the stand-in alike.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#undef NDEBUG
#include <assert.h>

#include "ucall/ucall.h"

/** A CPU class this machine never runs, which as a ceiling caps the pick down to serial. */
#if defined(__powerpc64__) || defined(__PPC64__)
#define FOREIGN_CPU_CLASS ucall_cpu_class_intel_haswell_k
#else
#define FOREIGN_CPU_CLASS ucall_cpu_class_ibm_power10_k
#endif

/** An I/O backend this operating system never offers. */
#if UCALL_OS_WINDOWS_
#define FOREIGN_BACKEND ucall_io_backend_bsd_kqueue_k
#else
#define FOREIGN_BACKEND ucall_io_backend_windows_rio_k
#endif

/** A device name outside Linux is unsupported, and on Linux one with no queues is invalid. */
#if UCALL_OS_LINUX_
#define MISSING_DEVICE_STATUS ucall_status_invalid_argument_k
#else
#define MISSING_DEVICE_STATUS ucall_status_unsupported_k
#endif

/** A counted view of a string literal, without its terminator. */
#define VIEW(text) ((ucall_bytes_view_t) {(ucall_byte_t const*)(text), sizeof(text) - 1})

static int failures = 0;

/** Records a mismatch, so one run lists every row the linked library answers differently. */
static void expect(char const* call, int line, ucall_outcome_t const* outcome, ucall_status_t expected) {
    int const message_matches = (outcome->status == ucall_status_success_k) == (outcome->message == NULL);
    if (outcome->status == expected && message_matches) return;
    fprintf(stderr, "c/test.c:%d: %s answered %s, expected %s%s\n", line, call, ucall_status_name(outcome->status),
            ucall_status_name(expected), message_matches ? "" : ", with a message that contradicts it");
    ++failures;
}

/** One row of the refusal matrix: calls @p verb with the designated fields of its arguments and
 *  expects @p expected; the outcome starts deferred, so a verb that never publishes fails too. */
#define EXPECT(expected, verb, ...)                                 \
    do {                                                            \
        ucall_outcome_t outcome_ = {ucall_status_deferred_k, NULL}; \
        verb##_t arguments_ = {__VA_ARGS__};                        \
        arguments_.outcome = &outcome_;                             \
        verb(&arguments_);                                          \
        expect(#verb, __LINE__, &outcome_, expected);               \
    } while (0)

/** One row initializing a server from the valid configuration with one @p edit applied to
 *  @c interface_ or @c options_, then freeing whatever it made. */
#define EXPECT_SERVER_INIT(expected, edit)                                             \
    do {                                                                               \
        ucall_network_interface_t interface_ = base_interface;                         \
        ucall_server_options_t options_ = base_options;                                \
        ucall_server_t server_ = NULL;                                                 \
        options_.interfaces = &interface_;                                             \
        edit;                                                                          \
        EXPECT(expected, ucall_server_init, .server = &server_, .options = &options_); \
        ucall_server_free(server_);                                                    \
    } while (0)

/** One row initializing a client from the valid configuration with one @p edit applied to
 *  @c options_, then freeing whatever it made. */
#define EXPECT_CLIENT_INIT(expected, edit)                                             \
    do {                                                                               \
        ucall_client_options_t options_ = base_client_options;                         \
        ucall_client_t client_ = NULL;                                                 \
        edit;                                                                          \
        EXPECT(expected, ucall_client_init, .client = &client_, .options = &options_); \
        ucall_client_free(client_);                                                    \
    } while (0)

/*  No row polls a loop or dials a peer, so the callbacks below are registered and never run. */

static void on_request(ucall_received_http_request_t request, void* context) {
    assert(!request && !context && "no request reaches this suite");
}

static void on_batch(ucall_received_http_request_t const* requests, size_t count, void* context) {
    assert(!requests && !count && !context && "no batch reaches this suite");
}

static ucall_status_t admit_peer(ucall_noise_key_t const* peer_static_key, void* context) {
    assert(!peer_static_key && !context && "no handshake runs in this suite");
    return ucall_status_peer_rejected_k;
}

static void test_names_and_keys(void) {
    uint8_t const text[] = {'x', 'd', 'e', 'f', 'e', 'r', 'r', 'e', 'd', 'x'};
    ucall_bytes_view_t name = {text + 1, sizeof(text) - 2};
    ucall_status_t read_status = ucall_status_success_k;
    assert(ucall_status_from_name(name, &read_status) == ucall_status_success_k);
    assert(read_status == ucall_status_deferred_k);
    assert(strcmp(ucall_status_name(ucall_status_deferred_k), "deferred") == 0);
    assert(strcmp(ucall_status_name((ucall_status_t)-1), "unrecognized") == 0);
    name.length = sizeof(text) - 1;
    assert(ucall_status_from_name(name, &read_status) == ucall_status_invalid_argument_k);
    name.data = NULL;
    name.length = 0;
    assert(ucall_status_from_name(name, &read_status) == ucall_status_invalid_argument_k);
    assert(read_status == ucall_status_deferred_k);

    ucall_bytes_view_t backend = {(ucall_byte_t const*)"linux-epollaio", 14};
    ucall_io_backend_t read_backend = ucall_io_backend_automatic_k;
    assert(ucall_io_backend_from_name(backend, &read_backend) == ucall_status_success_k);
    assert(read_backend == ucall_io_backend_linux_epollaio_k);
    backend.length = 5;
    assert(ucall_io_backend_from_name(backend, &read_backend) == ucall_status_invalid_argument_k);
    assert(read_backend == ucall_io_backend_linux_epollaio_k);
    ucall_bytes_view_t cpu_class = {(ucall_byte_t const*)"aws-g2", 6};
    ucall_cpu_class_t read_cpu_class = ucall_cpu_class_unknown_k;
    assert(ucall_cpu_class_from_name(cpu_class, &read_cpu_class) == ucall_status_success_k);
    assert(read_cpu_class == ucall_cpu_class_aws_g2_k);
    cpu_class.length = 5;
    assert(ucall_cpu_class_from_name(cpu_class, &read_cpu_class) == ucall_status_invalid_argument_k);
    assert(read_cpu_class == ucall_cpu_class_aws_g2_k);
    cpu_class = (ucall_bytes_view_t) {(ucall_byte_t const*)"unknown", 7};
    assert(ucall_cpu_class_from_name(cpu_class, &read_cpu_class) == ucall_status_success_k);
    assert(read_cpu_class == ucall_cpu_class_unknown_k);

    int major = -1, minor = -1, patch = -1;
    ucall_version(&major, &minor, &patch);
    assert(major == UCALL_VERSION_MAJOR && minor == UCALL_VERSION_MINOR && patch == UCALL_VERSION_PATCH);
    char expected[32];
    snprintf(expected, sizeof(expected), "%d.%d.%d", major, minor, patch);
    assert(strncmp(ucall_version_name(), expected, strlen(expected)) == 0);

    ucall_outcome_t outcome = {ucall_status_success_k, NULL};
    assert(ucall_outcome_status(&outcome) == ucall_status_success_k);
    assert(ucall_outcome_wait(&outcome) == ucall_status_success_k);

    ucall_noise_key_t private_key, public_key, derived_key, other_private_key, other_public_key;
    ucall_noise_key_generate_t generate = {&outcome, &private_key, &public_key};
    ucall_noise_key_generate(&generate);
    assert(outcome.status == ucall_status_success_k && outcome.message == NULL);
    ucall_noise_key_derive_t derive = {&outcome, (ucall_noise_key_t const*)&private_key, &derived_key};
    ucall_noise_key_derive(&derive);
    assert(outcome.status == ucall_status_success_k && memcmp(derived_key, public_key, sizeof(public_key)) == 0);
    generate.private_key = &other_private_key;
    generate.public_key = &other_public_key;
    ucall_noise_key_generate(&generate);
    assert(memcmp(other_private_key, private_key, sizeof(private_key)) != 0);
    derive.public_key = NULL;
    ucall_noise_key_derive(&derive);
    assert(outcome.status == ucall_status_invalid_argument_k);

    // The scalar 9 times the base point, a known answer `test/tunnel/crypto.cpp` also checks.
    static ucall_noise_key_t const nine = {9};
    static ucall_noise_key_t const nine_public = {0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc, 0xa1, 0x35, 0x0b,
                                                  0x3e, 0x2b, 0xb7, 0x27, 0x9f, 0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85,
                                                  0x4b, 0x78, 0x3c, 0x60, 0xe8, 0x03, 0x11, 0xae, 0x30, 0x79};
    derive.private_key = &nine;
    derive.public_key = &derived_key;
    ucall_noise_key_derive(&derive);
    assert(outcome.status == ucall_status_success_k && memcmp(derived_key, nine_public, sizeof(nine_public)) == 0);

    ucall_byte_t decoded[16];
    size_t decoded_length = 0;
    assert(ucall_decode_percent(VIEW("a%20b+c"), decoded, &decoded_length, ucall_percent_query_k) ==
           ucall_status_success_k);
    assert(decoded_length == 5 && memcmp(decoded, "a b c", 5) == 0);
    assert(ucall_decode_percent(VIEW("a+b"), decoded, &decoded_length, ucall_percent_path_k) == ucall_status_success_k);
    assert(decoded_length == 3 && memcmp(decoded, "a+b", 3) == 0);
}

/** Every refusal of @c types.h that needs no handle. */
static void test_type_refusals(void) {
    ucall_noise_key_t key;
    EXPECT(ucall_status_invalid_argument_k, ucall_noise_key_generate, .private_key = NULL, .public_key = &key);
    EXPECT(ucall_status_invalid_argument_k, ucall_noise_key_generate, .private_key = &key, .public_key = NULL);
    EXPECT(ucall_status_invalid_argument_k, ucall_noise_key_derive, .private_key = NULL, .public_key = &key);
    EXPECT(ucall_status_invalid_argument_k, ucall_noise_key_derive, .private_key = (ucall_noise_key_t const*)&key,
           .public_key = NULL);

    ucall_byte_t decoded[8];
    size_t length = 0;
    ucall_bytes_view_t const unescaped = {NULL, 3};
    assert(ucall_decode_percent(VIEW("a%zz"), decoded, &length, ucall_percent_path_k) ==
           ucall_status_invalid_argument_k);
    assert(ucall_decode_percent(VIEW("a%2"), decoded, &length, ucall_percent_path_k) ==
           ucall_status_invalid_argument_k);
    assert(ucall_decode_percent(VIEW("a"), decoded, NULL, ucall_percent_path_k) == ucall_status_invalid_argument_k);
    assert(ucall_decode_percent(VIEW("a"), NULL, &length, ucall_percent_path_k) == ucall_status_invalid_argument_k);
    assert(ucall_decode_percent(unescaped, decoded, &length, ucall_percent_path_k) == ucall_status_invalid_argument_k);
    assert(ucall_decode_percent(VIEW("a"), decoded, &length, (ucall_percent_mode_t)7) ==
           ucall_status_invalid_argument_k);
}

/** Every refusal of @c server.h and @c client.h reachable without a peer: initialization over each
 *  invalid field, then each verb's handle and argument checks on a live server and client. */
static void test_handle_refusals(void) {
    ucall_network_interface_t base_interface;
    memset(&base_interface, 0, sizeof(base_interface));
    base_interface.address = VIEW("127.0.0.1:0");
    base_interface.max_concurrent_connections = 4;
    ucall_server_options_t base_options;
    memset(&base_options, 0, sizeof(base_options));
    base_options.interfaces = &base_interface;
    base_options.interfaces_count = 1;
    ucall_noise_key_t key = {1};
    intptr_t const closed_descriptor = -1;
    ucall_bytes_view_t const empty_directory = {(ucall_byte_t const*)"", 0};
    ucall_bytes_view_t const missing_directory = VIEW("/nonexistent/ucall-test-missing-directory");
    ucall_bytes_view_t const prefix_with_colon = VIEW("a:b");

    EXPECT(ucall_status_invalid_argument_k, ucall_server_init, .server = NULL, .options = &base_options);
    EXPECT_SERVER_INIT(ucall_status_success_k, (void)0);
    {
        ucall_server_t server = NULL;
        EXPECT(ucall_status_invalid_argument_k, ucall_server_init, .server = &server, .options = NULL);
        assert(server == NULL);
    }
    EXPECT_SERVER_INIT(ucall_status_invalid_argument_k, options_.interfaces_count = 0);
    EXPECT_SERVER_INIT(ucall_status_invalid_argument_k, options_.interfaces = NULL);
    EXPECT_SERVER_INIT(ucall_status_invalid_argument_k, options_.cpu_class_ceiling = (ucall_cpu_class_t)4);
    EXPECT_SERVER_INIT(ucall_status_invalid_argument_k, options_.metrics_sample_rate = 2.f);
    EXPECT_SERVER_INIT(ucall_status_invalid_argument_k, options_.metrics_prefix = prefix_with_colon);
    EXPECT_SERVER_INIT(ucall_status_invalid_argument_k, options_.metrics_tags_count = 1);
    EXPECT_SERVER_INIT(ucall_status_invalid_argument_k, options_.metrics_address = VIEW("no-port"));
    EXPECT_SERVER_INIT(ucall_status_invalid_argument_k, interface_.address = empty_directory);
    EXPECT_SERVER_INIT(ucall_status_invalid_argument_k, interface_.address = VIEW("127.0.0.1"));
    EXPECT_SERVER_INIT(ucall_status_invalid_argument_k, interface_.security = (ucall_security_t)9);
    EXPECT_SERVER_INIT(ucall_status_invalid_argument_k, interface_.security = ucall_security_noise_ik_k);
    EXPECT_SERVER_INIT(ucall_status_invalid_argument_k,
                       (interface_.security = ucall_security_noise_xx_k, interface_.noise_private_key = &key));
    EXPECT_SERVER_INIT(ucall_status_invalid_argument_k,
                       (interface_.security = ucall_security_noise_kk_k, interface_.noise_private_key = &key));
    EXPECT_SERVER_INIT(ucall_status_invalid_argument_k, interface_.max_concurrent_connections = 0);
    EXPECT_SERVER_INIT(ucall_status_invalid_argument_k, interface_.reply_directories_count = 1);
    EXPECT_SERVER_INIT(ucall_status_invalid_argument_k,
                       (interface_.reply_directories = &empty_directory, interface_.reply_directories_count = 1));
    EXPECT_SERVER_INIT(ucall_status_invalid_argument_k, interface_.listen_descriptor = &closed_descriptor);
    EXPECT_SERVER_INIT(MISSING_DEVICE_STATUS, interface_.device_name = VIEW("ucall-missing0"));
    EXPECT_SERVER_INIT(ucall_status_unsupported_k, options_.backend = FOREIGN_BACKEND);
    EXPECT_SERVER_INIT(ucall_status_overflow_k, interface_.max_pipelined_requests = SIZE_MAX);
    EXPECT_SERVER_INIT(ucall_status_not_found_k,
                       (interface_.reply_directories = &missing_directory, interface_.reply_directories_count = 1));
    EXPECT_SERVER_INIT(ucall_status_success_k,
                       (interface_.security = ucall_security_noise_xx_k, interface_.noise_private_key = &key,
                        interface_.peer_authorizer = admit_peer));
    {
        // A ceiling naming a class this machine lacks intersects with what it runs, not refuses.
        ucall_network_interface_t interface_ = base_interface;
        ucall_server_options_t options_ = base_options;
        ucall_server_options_t resolved_;
        ucall_server_t server_ = NULL;
        options_.interfaces = &interface_;
        options_.cpu_class_ceiling = FOREIGN_CPU_CLASS;
        EXPECT(ucall_status_success_k, ucall_server_init, .server = &server_, .options = &options_,
               .resolved = &resolved_);
        assert(resolved_.cpu_class_ceiling == ucall_cpu_class_serial_k);
        ucall_server_free(server_);
    }

    ucall_server_t server = NULL;
    ucall_server_options_t resolved;
    EXPECT(ucall_status_success_k, ucall_server_init, .server = &server, .options = &base_options,
           .resolved = &resolved);
    assert(server != NULL && resolved.interfaces_count == 1 && resolved.interfaces[0].event_loops == 1);
    assert(resolved.interfaces[0].max_pipelined_requests == 1 && resolved.metrics_sample_rate == 1.f);

    ucall_event_loop_statistics_t loop_statistics;
    ucall_batch_endpoint_statistics_t batch_statistics;
    EXPECT(ucall_status_uninitialized_k, ucall_server_take_call, .server = NULL);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_take_call, .server = server, .event_loop_index = 1);
    EXPECT(ucall_status_uninitialized_k, ucall_server_take_calls, .server = NULL);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_take_calls, .server = server, .event_loop_index = 1);
    EXPECT(ucall_status_uninitialized_k, ucall_server_event_loop_statistics, .server = NULL,
           .statistics = &loop_statistics);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_event_loop_statistics, .server = server, .statistics = NULL);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_event_loop_statistics, .server = server, .event_loop_index = 1,
           .statistics = &loop_statistics);
    EXPECT(ucall_status_success_k, ucall_server_event_loop_statistics, .server = server,
           .statistics = &loop_statistics);
    EXPECT(ucall_status_uninitialized_k, ucall_server_take_batch, .server = NULL);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_take_batch, .server = server, .endpoint = NULL);
    EXPECT(ucall_status_uninitialized_k, ucall_server_take_batches, .server = NULL);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_take_batches, .server = server, .endpoint = NULL);
    EXPECT(ucall_status_uninitialized_k, ucall_server_batch_endpoint_statistics, .server = NULL,
           .statistics = &batch_statistics);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_batch_endpoint_statistics, .server = server, .endpoint = NULL,
           .statistics = &batch_statistics);

    EXPECT(ucall_status_uninitialized_k, ucall_server_add_http_endpoint, .server = NULL, .uri_template = VIEW("/users"),
           .verb = ucall_verb_get_k, .callback = on_request);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server,
           .uri_template = VIEW("/users"), .verb = ucall_verb_get_k, .callback = NULL);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server,
           .uri_template = VIEW("/users"), .verb = ucall_verb_unknown_k, .callback = on_request);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server, .uri_template = VIEW(""),
           .verb = ucall_verb_get_k, .callback = on_request);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server,
           .uri_template = VIEW("users"), .verb = ucall_verb_get_k, .callback = on_request);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server,
           .uri_template = VIEW("/users?page=1"), .verb = ucall_verb_get_k, .callback = on_request);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server,
           .uri_template = VIEW("/users#top"), .verb = ucall_verb_get_k, .callback = on_request);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server,
           .uri_template = VIEW("/users/{id"), .verb = ucall_verb_get_k, .callback = on_request);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server,
           .uri_template = VIEW("/files/{*path}/more"), .verb = ucall_verb_get_k, .callback = on_request);
    EXPECT(ucall_status_success_k, ucall_server_add_http_endpoint, .server = server,
           .uri_template = VIEW("/users/{id}"), .verb = ucall_verb_get_k, .callback = on_request);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server,
           .uri_template = VIEW("/users/{name}/posts"), .verb = ucall_verb_get_k, .callback = on_request);
    EXPECT(ucall_status_already_exists_k, ucall_server_add_http_endpoint, .server = server,
           .uri_template = VIEW("/users/{id}"), .verb = ucall_verb_get_k, .callback = on_request);
    EXPECT(ucall_status_success_k, ucall_server_add_http_endpoint, .server = server,
           .uri_template = VIEW("/users/{id}"), .verb = ucall_verb_any_k, .callback = on_request);
    EXPECT(ucall_status_success_k, ucall_server_add_http_endpoint, .server = server,
           .uri_template = VIEW("/users/{id}/posts"), .verb = ucall_verb_get_k, .callback = on_request);

    ucall_http_batch_endpoint_t endpoint = NULL;
    EXPECT(ucall_status_uninitialized_k, ucall_server_add_http_batch_endpoint, .server = NULL,
           .uri_template = VIEW("/batch"), .verb = ucall_verb_post_k, .callback = on_batch, .endpoint = &endpoint);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_add_http_batch_endpoint, .server = server,
           .uri_template = VIEW("/batch"), .verb = ucall_verb_post_k, .callback = on_batch, .endpoint = NULL);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_add_http_batch_endpoint, .server = server,
           .uri_template = VIEW("/batch"), .verb = ucall_verb_post_k, .callback = NULL, .endpoint = &endpoint);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_add_http_batch_endpoint, .server = server,
           .uri_template = VIEW("/batch"), .verb = ucall_verb_post_k, .callback = on_batch, .min_batch_size = 8,
           .max_batch_size = 4, .endpoint = &endpoint);
    EXPECT(ucall_status_success_k, ucall_server_add_http_batch_endpoint, .server = server,
           .uri_template = VIEW("/batch"), .verb = ucall_verb_post_k, .callback = on_batch, .endpoint = &endpoint);
    assert(endpoint != NULL);
    EXPECT(ucall_status_already_exists_k, ucall_server_add_http_batch_endpoint, .server = server,
           .uri_template = VIEW("/batch"), .verb = ucall_verb_post_k, .callback = on_batch, .endpoint = &endpoint);
    EXPECT(ucall_status_already_exists_k, ucall_server_add_http_endpoint, .server = server,
           .uri_template = VIEW("/batch"), .verb = ucall_verb_post_k, .callback = on_request);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_batch_endpoint_statistics, .server = server,
           .endpoint = endpoint, .statistics = NULL);
    EXPECT(ucall_status_success_k, ucall_server_batch_endpoint_statistics, .server = server, .endpoint = endpoint,
           .statistics = &batch_statistics);
    assert(batch_statistics.batches == 0 && batch_statistics.requests == 0);

    // No request reaches an unpolled server, so accessors and replies meet only their own checks.
    ucall_bytes_view_t view;
    ucall_noise_key_t peer_key;
    ucall_peer_address_t peer_address;
    size_t count = 0;
    EXPECT(ucall_status_uninitialized_k, ucall_server_request_path, .server = NULL, .path = &view);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_request_path, .server = server, .path = &view);
    EXPECT(ucall_status_uninitialized_k, ucall_server_request_query, .server = NULL, .query = &view);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_request_query, .server = server, .query = &view);
    EXPECT(ucall_status_uninitialized_k, ucall_server_request_path_segment, .server = NULL, .segment = &view);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_request_path_segment, .server = server, .segment = &view);
    EXPECT(ucall_status_uninitialized_k, ucall_server_request_path_parameter, .server = NULL, .value = &view);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_request_path_parameter, .server = server, .name = VIEW("id"),
           .value = &view);
    EXPECT(ucall_status_uninitialized_k, ucall_server_request_query_parameter, .server = NULL, .value = &view);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_request_query_parameter, .server = server,
           .name = VIEW("page"), .value = &view);
    EXPECT(ucall_status_uninitialized_k, ucall_server_request_header, .server = NULL, .value = &view);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_request_header, .server = server, .name = VIEW("Host"),
           .value = &view);
    EXPECT(ucall_status_uninitialized_k, ucall_server_request_fields_count, .server = NULL, .count = &count);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_request_fields_count, .server = server, .count = &count);
    EXPECT(ucall_status_uninitialized_k, ucall_server_request_field, .server = NULL, .name = &view, .value = &view);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_request_field, .server = server, .name = &view,
           .value = &view);
    EXPECT(ucall_status_uninitialized_k, ucall_server_request_peer, .server = NULL);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_request_peer, .server = server,
           .network_interface_index = &count, .static_key = &peer_key, .address = &peer_address);
    EXPECT(ucall_status_uninitialized_k, ucall_server_request_body, .server = NULL, .body = &view);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_request_body, .server = server, .body = &view);
    EXPECT(ucall_status_uninitialized_k, ucall_server_request_body_chunk, .server = NULL, .data = &view);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_request_body_chunk, .server = server, .data = &view);
    EXPECT(ucall_status_uninitialized_k, ucall_server_request_part, .server = NULL);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_request_part, .server = server, .name = &view,
           .content_type = &view, .data = &view);
    EXPECT(ucall_status_uninitialized_k, ucall_server_reply_content, .server = NULL);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_reply_content, .server = server, .request = NULL);
    EXPECT(ucall_status_uninitialized_k, ucall_server_reply_error, .server = NULL);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_reply_error, .server = server, .request = NULL,
           .http_status = 404);
    EXPECT(ucall_status_uninitialized_k, ucall_server_reply_vectored, .server = NULL);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_reply_vectored, .server = server, .request = NULL);
    EXPECT(ucall_status_uninitialized_k, ucall_server_reply_begin, .server = NULL);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_reply_begin, .server = server, .request = NULL);
    EXPECT(ucall_status_uninitialized_k, ucall_server_reply_append, .server = NULL);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_reply_append, .server = server, .request = NULL);
    EXPECT(ucall_status_uninitialized_k, ucall_server_reply_end, .server = NULL);
    EXPECT(ucall_status_invalid_argument_k, ucall_server_reply_end, .server = server, .request = NULL);
    assert(ucall_server_request_verb(NULL, NULL) == ucall_verb_unknown_k);
    assert(ucall_server_request_path_segments_count(NULL, NULL) == 0);
    assert(ucall_server_request_parts_count(NULL, NULL) == 0);

    ucall_client_options_t base_client_options;
    memset(&base_client_options, 0, sizeof(base_client_options));
    base_client_options.max_concurrent_connections = 2;
    EXPECT(ucall_status_invalid_argument_k, ucall_client_init, .client = NULL, .options = &base_client_options);
    EXPECT_CLIENT_INIT(ucall_status_success_k, (void)0);
    EXPECT_CLIENT_INIT(ucall_status_invalid_argument_k, options_.max_concurrent_connections = 0);
    EXPECT_CLIENT_INIT(ucall_status_invalid_argument_k, options_.cpu_class_ceiling = (ucall_cpu_class_t)4);
    EXPECT_CLIENT_INIT(ucall_status_invalid_argument_k,
                       (options_.max_concurrent_connections = SIZE_MAX, options_.max_pipelined_calls = 2));
    EXPECT_CLIENT_INIT(ucall_status_invalid_argument_k, (options_.server = server, options_.event_loop = 1));
    EXPECT_CLIENT_INIT(ucall_status_invalid_argument_k, (options_.server = server, options_.backend = FOREIGN_BACKEND));
    {
        ucall_client_options_t options_ = base_client_options;
        ucall_client_options_t resolved_;
        ucall_client_t client_ = NULL;
        options_.cpu_class_ceiling = FOREIGN_CPU_CLASS;
        EXPECT(ucall_status_success_k, ucall_client_init, .client = &client_, .options = &options_,
               .resolved = &resolved_);
        assert(resolved_.cpu_class_ceiling == ucall_cpu_class_serial_k);
        ucall_client_free(client_);
    }
    EXPECT_CLIENT_INIT(ucall_status_overflow_k,
                       (options_.max_pipelined_calls = SIZE_MAX, options_.max_concurrent_calls = 1));
    EXPECT_CLIENT_INIT(ucall_status_overflow_k, options_.max_concurrent_connections = (size_t)1 << 31);
    {
        ucall_client_t client = NULL;
        ucall_client_options_t options = {0};
        EXPECT(ucall_status_invalid_argument_k, ucall_client_init, .client = &client, .options = NULL);
        assert(client == NULL);
        options.max_concurrent_connections = 2;
        options.server = server;
        EXPECT(ucall_status_success_k, ucall_client_init, .client = &client, .options = &options);
        assert(client != NULL);
        // The bound client keeps its server, so this free returns and the rows below still use it.
        ucall_server_free(server);
        ucall_client_free(client);
    }

    ucall_client_t client = NULL;
    EXPECT(ucall_status_success_k, ucall_client_init, .client = &client, .options = &base_client_options);
    ucall_bytes_view_t const header = VIEW("Accept: */*");
    ucall_bytes_view_t const dangling = {NULL, 3};
    ucall_completed_call_t completed[2];
    EXPECT(ucall_status_uninitialized_k, ucall_client_call, .client = NULL, .url = VIEW("http://localhost/"),
           .verb = ucall_verb_get_k);
    EXPECT(ucall_status_invalid_argument_k, ucall_client_call, .client = client, .url = VIEW("http://localhost/"),
           .verb = ucall_verb_unknown_k);
    EXPECT(ucall_status_invalid_argument_k, ucall_client_call, .client = client, .url = VIEW("http://localhost/"),
           .verb = ucall_verb_any_k);
    EXPECT(ucall_status_invalid_argument_k, ucall_client_call, .client = client, .url = VIEW("localhost/"),
           .verb = ucall_verb_get_k);
    EXPECT(ucall_status_invalid_argument_k, ucall_client_call, .client = client, .url = VIEW("http://?page=1"),
           .verb = ucall_verb_get_k);
    EXPECT(ucall_status_invalid_argument_k, ucall_client_call, .client = client, .url = VIEW("http://localhost:0/"),
           .verb = ucall_verb_get_k);
    EXPECT(ucall_status_invalid_argument_k, ucall_client_call, .client = client, .url = VIEW("http://user@host/"),
           .verb = ucall_verb_get_k);
    EXPECT(ucall_status_invalid_argument_k, ucall_client_call, .client = client, .url = dangling,
           .verb = ucall_verb_get_k);
    EXPECT(ucall_status_invalid_argument_k, ucall_client_call, .client = client, .url = VIEW("http://localhost/"),
           .verb = ucall_verb_post_k, .body = dangling);
    EXPECT(ucall_status_invalid_argument_k, ucall_client_call, .client = client, .url = VIEW("http://localhost/"),
           .verb = ucall_verb_get_k, .headers_count = 1);
    EXPECT(ucall_status_invalid_argument_k, ucall_client_call, .client = client, .url = VIEW("http://localhost/"),
           .verb = ucall_verb_get_k, .options = {.security = (ucall_security_t)9});
    EXPECT(ucall_status_invalid_argument_k, ucall_client_call, .client = client, .url = VIEW("http+noise://localhost/"),
           .verb = ucall_verb_get_k);
    EXPECT(ucall_status_invalid_argument_k, ucall_client_call, .client = client, .url = VIEW("http://localhost/"),
           .verb = ucall_verb_get_k, .options = {.security = ucall_security_noise_ik_k, .noise_private_key = &key});
    EXPECT(ucall_status_unsupported_k, ucall_client_call, .client = client, .url = VIEW("ftp://localhost/"),
           .verb = ucall_verb_get_k, .headers = &header, .headers_count = 1);
    EXPECT(ucall_status_uninitialized_k, ucall_client_take_completed, .client = NULL, .count = &count);
    EXPECT(ucall_status_invalid_argument_k, ucall_client_take_completed, .client = client, .count = NULL);
    EXPECT(ucall_status_invalid_argument_k, ucall_client_take_completed, .client = client, .calls = NULL, .capacity = 2,
           .count = &count);
    EXPECT(ucall_status_success_k, ucall_client_take_completed, .client = client, .calls = completed, .capacity = 2,
           .count = &count);
    assert(count == 0);

    EXPECT(ucall_status_invalid_argument_k, ucall_client_response_header, .response = NULL, .name = VIEW("Date"),
           .value = &view);
    EXPECT(ucall_status_invalid_argument_k, ucall_client_response_fields_count, .response = NULL, .count = &count);
    EXPECT(ucall_status_invalid_argument_k, ucall_client_response_field, .response = NULL, .name = &view,
           .value = &view);
    EXPECT(ucall_status_invalid_argument_k, ucall_client_response_body, .response = NULL, .body = &view);
    assert(ucall_client_response_status(NULL) == 0);
    ucall_client_response_free(NULL);

    ucall_client_free(client);
    ucall_client_free(NULL);
    ucall_server_stop(NULL);
    ucall_server_stop(server);
    ucall_server_free(server);
    ucall_server_free(NULL);
}

int main(void) {
    test_names_and_keys();
    test_type_refusals();
    test_handle_refusals();
    if (failures) fprintf(stderr, "%d rows answered differently from the headers\n", failures);
    return failures ? 1 : 0;
}
