/**
 *  @file c/test.c
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief A C caller of the linked library: names, versions, outcomes and Noise keys, then every
 *      documented refusal reachable without a peer, against the queue and the stand-in alike.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>

#include "ucall/ucall.h"

#if UCALL_OS_WINDOWS_
#include <io.h> // `_write`
#else
#include <unistd.h> // `write`, `STDERR_FILENO`
#endif

/*  region Shared C Checks  */
static size_t failed_checks = 0;
static size_t failed_checks_before_case = 0;
static size_t passed_cases = 0;
static size_t failed_cases = 0;
static size_t skipped_cases = 0;
static char const* current_case = NULL;
static char const* program_name = "";
static uint64_t test_seed = 42;
static double test_scale = 1.0;
static bool refuse_skips = false;

/** Fills the settings above from the file's own spelled-out variables and flags. */
static void read_test_settings(int argc, char** argv);

/** SplitMix64's finalizer, a bijection that spreads every input bit over all 64 output bits. */
static inline uint64_t split_mix_bits(uint64_t value) {
    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ull;
    value = (value ^ (value >> 27)) * 0x94D049BB133111EBull;
    return value ^ (value >> 31);
}

/** Writes @p text to the standard error through a raw @c write, which a signal handler may call. */
static void write_text(char const* text) {
#if UCALL_OS_WINDOWS_
    (void)!_write(2, text, (unsigned)strlen(text));
#else
    (void)!write(STDERR_FILENO, text, strlen(text));
#endif
}

/** Counts a failed check at @p file : @p line without stopping, so one run lists every mismatch. */
static inline bool expect_at(bool is_met, char const* file, int line, char const* what) {
    if (is_met) return true;
    fflush(stdout);
    char message[512];
    snprintf(message, sizeof message, "  check failed at %s:%d\n    %s\n", file, line, what);
    write_text(message);
    ++failed_checks;
    return false;
}

/** The text of a setting: its @p flag when given, else its environment @p variable , else NULL. */
static inline char const* setting_text(int argc, char** argv, char const* variable, char const* flag) {
    size_t const flag_length = strlen(flag);
    for (int index = 1; index < argc; ++index) {
        if (strcmp(argv[index], flag) == 0)
            return index + 1 < argc && strncmp(argv[index + 1], "--", 2) != 0 ? argv[index + 1] : "1";
        if (strncmp(argv[index], flag, flag_length) == 0 && argv[index][flag_length] == '=')
            return argv[index] + flag_length + 1;
    }
    char const* text = getenv(variable);
    return text && *text ? text : NULL;
}

/** Exits with one line naming a setting that does not parse, so a bad value never runs anything. */
static inline void exit_unparsed(char const* variable, char const* text, char const* expected) {
    char message[512];
    snprintf(message, sizeof message, "%s=\"%s\" does not parse, expected %s\n", variable, text, expected);
    write_text(message);
    exit(1);
}

/** The run's seed: 42 when unset, drawn afresh for @c random , else any unsigned 64-bit value. */
static inline uint64_t read_seed_setting(int argc, char** argv, char const* variable, char const* flag) {
    char const* text = setting_text(argc, argv, variable, flag);
    char* end = NULL;
    if (!text) return 42;
    if (strcmp(text, "random") == 0) return split_mix_bits((uint64_t)time(NULL) ^ (uint64_t)clock());
    uint64_t const seed = (uint64_t)strtoull(text, &end, 10);
    if (*end != '\0' || *text == '-') exit_unparsed(variable, text, "an unsigned integer or random");
    return seed;
}

/** A positive real, @p fallback when unset. */
static inline double read_real_setting(int argc, char** argv, char const* variable, char const* flag, double fallback) {
    char const* text = setting_text(argc, argv, variable, flag);
    char* end = NULL;
    if (!text) return fallback;
    double const value = strtod(text, &end);
    if (*end != '\0' || !(value > 0)) exit_unparsed(variable, text, "a positive number like 0.1 or 10");
    return value;
}

/** A switch, @p fallback when unset: 0, false, off and no turn it off, anything else on. */
static inline bool read_flag_setting(int argc, char** argv, char const* variable, char const* flag, bool fallback) {
    char const* text = setting_text(argc, argv, variable, flag);
    if (!text) return fallback;
    return strcmp(text, "0") != 0 && strcmp(text, "false") != 0 && strcmp(text, "off") != 0 && strcmp(text, "no") != 0;
}

/** Reads the settings and prints the settings line, before the first case. */
static inline void start_test_run(int argc, char** argv) {
    program_name = argc != 0 ? argv[0] : "";
    read_test_settings(argc, argv);
    printf("- Seed: %" PRIu64 ", scale: %g\n", test_seed, test_scale);
}

/** Starts the case @p label, which every run runs. */
static inline void start_test_case(char const* label) {
    current_case = label;
    failed_checks_before_case = failed_checks;
}

/** Ends the case @ref start_test_case began: @p skip_reason when it skipped, NULL when it ran. */
static inline void finish_test_case(char const* skip_reason) {
    size_t const failed = failed_checks - failed_checks_before_case;
    if (skip_reason) {
        ++skipped_cases;
        printf("- %s ... skipped: %s\n", current_case, skip_reason);
    }
    else if (failed == 0) {
        ++passed_cases;
        printf("- %s ... ok\n", current_case);
    }
    else {
        ++failed_cases;
        fflush(stdout);
        char message[512];
        snprintf(message, sizeof message, "- %s ... FAILED: %zu failed check(s)\n", current_case, failed);
        write_text(message);
        snprintf(message, sizeof message, "  rerun: %s --seed %" PRIu64 "\n", program_name, test_seed);
        write_text(message);
    }
    current_case = NULL;
}

/** The exit code: 1 when a case or a check outside any case failed, or nothing ran; 3 when
 *  skips are refused and one happened; else 0. */
static inline int finish_test_run(void) {
    printf("%zu passed, %zu failed, %zu skipped, seed %" PRIu64 "\n", passed_cases, failed_cases, skipped_cases,
           test_seed);
    if (failed_cases != 0 || failed_checks != 0 || passed_cases + skipped_cases == 0) return 1;
    if (skipped_cases != 0 && refuse_skips) return 3;
    return 0;
}
/*  endregion Shared C Checks  */

static void read_test_settings(int argc, char** argv) {
    test_seed = read_seed_setting(argc, argv, "UCALL_SEED", "--seed");
    test_scale = read_real_setting(argc, argv, "UCALL_SCALE", "--scale", 1.0);
    refuse_skips = read_flag_setting(argc, argv, "UCALL_NO_SKIPS", "--no-skips", false);
}

#define expect_(condition) expect_at((condition), __FILE__, __LINE__, #condition)

/** A CPU class this machine never runs, which as a ceiling caps the pick down to serial. */
#if defined(__powerpc64__) || defined(__PPC64__)
static ucall_cpu_class_t const foreign_cpu_class = ucall_cpu_class_intel_haswell_k;
#else
static ucall_cpu_class_t const foreign_cpu_class = ucall_cpu_class_ibm_power10_k;
#endif

/** An I/O backend this operating system never offers. */
#if UCALL_OS_WINDOWS_
static ucall_io_backend_t const foreign_backend = ucall_io_backend_bsd_kqueue_k;
#else
static ucall_io_backend_t const foreign_backend = ucall_io_backend_windows_rio_k;
#endif

/** A device name outside Linux is unsupported, and on Linux one with no queues is invalid. */
#if UCALL_OS_LINUX_
static ucall_status_t const missing_device_status = ucall_status_invalid_argument_k;
#else
static ucall_status_t const missing_device_status = ucall_status_unsupported_k;
#endif

/** A counted view of a string literal, without its terminator. */
#define view_of_(text) ((ucall_bytes_view_t) {(ucall_byte_t const*)(text), sizeof(text) - 1})

/** Checks @p call published @p expected, with a message exactly when it failed, so one run lists
 *  every row the linked library answers differently. */
static bool expect_outcome_at(ucall_outcome_t const* outcome, ucall_status_t expected, char const* file, int line,
                              char const* call) {
    bool const message_matches = (outcome->status == ucall_status_success_k) == (outcome->message == NULL);
    if (outcome->status == expected && message_matches) return true;
    char what[256];
    snprintf(what, sizeof(what), "%s answered %s, expected %s%s", call, ucall_status_name(outcome->status),
             ucall_status_name(expected), message_matches ? "" : ", with a message that contradicts it");
    return expect_at(false, file, line, what);
}

/** One row of the refusal matrix: calls @p verb with the designated fields of its arguments and
 *  expects @p expected; the outcome starts deferred, so a verb that never publishes fails too. */
#define expect_call_(expected, verb, ...)                                  \
    do {                                                                   \
        ucall_outcome_t outcome_ = {ucall_status_deferred_k, NULL};        \
        verb##_t arguments_ = {__VA_ARGS__};                               \
        arguments_.outcome = &outcome_;                                    \
        verb(&arguments_);                                                 \
        expect_outcome_at(&outcome_, expected, __FILE__, __LINE__, #verb); \
    } while (0)

/** One row initializing a server from the valid configuration with one @p edit applied to
 *  @c interface_ or @c options_, then freeing whatever it made. */
#define expect_server_init_(expected, edit)                                                  \
    do {                                                                                     \
        ucall_network_interface_t interface_ = base_interface;                               \
        ucall_server_options_t options_ = base_options;                                      \
        ucall_server_t server_ = NULL;                                                       \
        options_.interfaces = &interface_;                                                   \
        edit;                                                                                \
        expect_call_(expected, ucall_server_init, .server = &server_, .options = &options_); \
        ucall_server_free(server_);                                                          \
    } while (0)

/** One row initializing a client from the valid configuration with one @p edit applied to
 *  @c options_, then freeing whatever it made. */
#define expect_client_init_(expected, edit)                                                  \
    do {                                                                                     \
        ucall_client_options_t options_ = base_client_options;                               \
        ucall_client_t client_ = NULL;                                                       \
        edit;                                                                                \
        expect_call_(expected, ucall_client_init, .client = &client_, .options = &options_); \
        ucall_client_free(client_);                                                          \
    } while (0)

/*  No row polls a loop or dials a peer, so the callbacks below are registered and never run. */

static void on_request(ucall_server_t server, ucall_received_http_request_t request, void* context) {
    expect_at(!server && !request && !context, __FILE__, __LINE__, "no request reaches this suite");
}

static void on_batch(ucall_server_t server, ucall_received_http_request_t const* requests, size_t count,
                     void* context) {
    expect_at(!server && !requests && !count && !context, __FILE__, __LINE__, "no batch reaches this suite");
}

static ucall_status_t admit_peer(ucall_noise_key_t const* peer_static_key, void* context) {
    expect_at(!peer_static_key && !context, __FILE__, __LINE__, "no handshake runs in this suite");
    return ucall_status_peer_rejected_k;
}

static void test_names_and_keys(void) {
    uint8_t const text[] = {'x', 'd', 'e', 'f', 'e', 'r', 'r', 'e', 'd', 'x'};
    ucall_bytes_view_t name = {text + 1, sizeof(text) - 2};
    ucall_status_t read_status = ucall_status_success_k;
    expect_(ucall_status_from_name(name, &read_status) == ucall_status_success_k);
    expect_(read_status == ucall_status_deferred_k);
    expect_(strcmp(ucall_status_name(ucall_status_deferred_k), "deferred") == 0);
    expect_(strcmp(ucall_status_name((ucall_status_t)-1), "unrecognized") == 0);
    name.length = sizeof(text) - 1;
    expect_(ucall_status_from_name(name, &read_status) == ucall_status_invalid_argument_k);
    name.data = NULL;
    name.length = 0;
    expect_(ucall_status_from_name(name, &read_status) == ucall_status_invalid_argument_k);
    expect_(read_status == ucall_status_deferred_k);

    ucall_bytes_view_t backend = {(ucall_byte_t const*)"linux-epollaio", 14};
    ucall_io_backend_t read_backend = ucall_io_backend_automatic_k;
    expect_(ucall_io_backend_from_name(backend, &read_backend) == ucall_status_success_k);
    expect_(read_backend == ucall_io_backend_linux_epollaio_k);
    backend.length = 5;
    expect_(ucall_io_backend_from_name(backend, &read_backend) == ucall_status_invalid_argument_k);
    expect_(read_backend == ucall_io_backend_linux_epollaio_k);
    ucall_bytes_view_t cpu_class = {(ucall_byte_t const*)"aws-g2", 6};
    ucall_cpu_class_t read_cpu_class = ucall_cpu_class_unknown_k;
    expect_(ucall_cpu_class_from_name(cpu_class, &read_cpu_class) == ucall_status_success_k);
    expect_(read_cpu_class == ucall_cpu_class_aws_g2_k);
    cpu_class.length = 5;
    expect_(ucall_cpu_class_from_name(cpu_class, &read_cpu_class) == ucall_status_invalid_argument_k);
    expect_(read_cpu_class == ucall_cpu_class_aws_g2_k);
    cpu_class = (ucall_bytes_view_t) {(ucall_byte_t const*)"unknown", 7};
    expect_(ucall_cpu_class_from_name(cpu_class, &read_cpu_class) == ucall_status_success_k);
    expect_(read_cpu_class == ucall_cpu_class_unknown_k);

    int major = -1, minor = -1, patch = -1;
    ucall_version(&major, &minor, &patch);
    expect_(major == UCALL_VERSION_MAJOR && minor == UCALL_VERSION_MINOR && patch == UCALL_VERSION_PATCH);
    char expected[32];
    snprintf(expected, sizeof(expected), "%d.%d.%d", major, minor, patch);
    expect_(strncmp(ucall_version_name(), expected, strlen(expected)) == 0);

    ucall_outcome_t outcome = {ucall_status_success_k, NULL};
    expect_(ucall_outcome_status(&outcome) == ucall_status_success_k);
    expect_(ucall_outcome_wait(&outcome) == ucall_status_success_k);

    ucall_noise_key_t private_key, public_key, derived_key, other_private_key, other_public_key;
    ucall_noise_key_generate_t generate = {&outcome, &private_key, &public_key};
    ucall_noise_key_generate(&generate);
    expect_(outcome.status == ucall_status_success_k && outcome.message == NULL);
    ucall_noise_key_derive_t derive = {&outcome, (ucall_noise_key_t const*)&private_key, &derived_key};
    ucall_noise_key_derive(&derive);
    expect_(outcome.status == ucall_status_success_k && memcmp(derived_key, public_key, sizeof(public_key)) == 0);
    generate.private_key = &other_private_key;
    generate.public_key = &other_public_key;
    ucall_noise_key_generate(&generate);
    expect_(memcmp(other_private_key, private_key, sizeof(private_key)) != 0);
    derive.public_key = NULL;
    ucall_noise_key_derive(&derive);
    expect_(outcome.status == ucall_status_invalid_argument_k);

    // The scalar 9 times the base point, a known answer `test/tunnel/crypto.cpp` also checks.
    static ucall_noise_key_t const nine = {9};
    static ucall_noise_key_t const nine_public = {0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc, 0xa1, 0x35, 0x0b,
                                                  0x3e, 0x2b, 0xb7, 0x27, 0x9f, 0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85,
                                                  0x4b, 0x78, 0x3c, 0x60, 0xe8, 0x03, 0x11, 0xae, 0x30, 0x79};
    derive.private_key = &nine;
    derive.public_key = &derived_key;
    ucall_noise_key_derive(&derive);
    expect_(outcome.status == ucall_status_success_k && memcmp(derived_key, nine_public, sizeof(nine_public)) == 0);

    ucall_byte_t decoded[16];
    size_t decoded_length = 0;
    expect_(ucall_decode_percent(view_of_("a%20b+c"), decoded, &decoded_length, ucall_percent_query_k) ==
            ucall_status_success_k);
    expect_(decoded_length == 5 && memcmp(decoded, "a b c", 5) == 0);
    expect_(ucall_decode_percent(view_of_("a+b"), decoded, &decoded_length, ucall_percent_path_k) ==
            ucall_status_success_k);
    expect_(decoded_length == 3 && memcmp(decoded, "a+b", 3) == 0);
}

/** Every refusal of @c types.h that needs no handle. */
static void test_type_refusals(void) {
    ucall_noise_key_t key;
    expect_call_(ucall_status_invalid_argument_k, ucall_noise_key_generate, .private_key = NULL, .public_key = &key);
    expect_call_(ucall_status_invalid_argument_k, ucall_noise_key_generate, .private_key = &key, .public_key = NULL);
    expect_call_(ucall_status_invalid_argument_k, ucall_noise_key_derive, .private_key = NULL, .public_key = &key);
    expect_call_(ucall_status_invalid_argument_k, ucall_noise_key_derive, .private_key = (ucall_noise_key_t const*)&key,
                 .public_key = NULL);

    ucall_byte_t decoded[8];
    size_t length = 0;
    ucall_bytes_view_t const unescaped = {NULL, 3};
    expect_(ucall_decode_percent(view_of_("a%zz"), decoded, &length, ucall_percent_path_k) ==
            ucall_status_invalid_argument_k);
    expect_(ucall_decode_percent(view_of_("a%2"), decoded, &length, ucall_percent_path_k) ==
            ucall_status_invalid_argument_k);
    expect_(ucall_decode_percent(view_of_("a"), decoded, NULL, ucall_percent_path_k) ==
            ucall_status_invalid_argument_k);
    expect_(ucall_decode_percent(view_of_("a"), NULL, &length, ucall_percent_path_k) ==
            ucall_status_invalid_argument_k);
    expect_(ucall_decode_percent(unescaped, decoded, &length, ucall_percent_path_k) == ucall_status_invalid_argument_k);
    expect_(ucall_decode_percent(view_of_("a"), decoded, &length, (ucall_percent_mode_t)7) ==
            ucall_status_invalid_argument_k);
}

/** Every refusal of @c server.h and @c client.h reachable without a peer: initialization over each
 *  invalid field, then each verb's handle and argument checks on a live server and client. */
static void test_handle_refusals(void) {
    ucall_network_interface_t base_interface;
    memset(&base_interface, 0, sizeof(base_interface));
    base_interface.address = view_of_("127.0.0.1:0");
    base_interface.max_concurrent_connections = 4;
    ucall_server_options_t base_options;
    memset(&base_options, 0, sizeof(base_options));
    base_options.interfaces = &base_interface;
    base_options.interfaces_count = 1;
    ucall_noise_key_t key = {1};
    intptr_t const closed_descriptor = -1;
    ucall_bytes_view_t const empty_directory = {(ucall_byte_t const*)"", 0};
    ucall_bytes_view_t const missing_directory = view_of_("/nonexistent/ucall-test-missing-directory");
    ucall_bytes_view_t const prefix_with_colon = view_of_("a:b");

    expect_call_(ucall_status_invalid_argument_k, ucall_server_init, .server = NULL, .options = &base_options);
    expect_server_init_(ucall_status_success_k, (void)0);
    {
        ucall_server_t server = NULL;
        expect_call_(ucall_status_invalid_argument_k, ucall_server_init, .server = &server, .options = NULL);
        expect_(server == NULL);
    }
    expect_server_init_(ucall_status_invalid_argument_k, options_.interfaces_count = 0);
    expect_server_init_(ucall_status_invalid_argument_k, options_.interfaces = NULL);
    expect_server_init_(ucall_status_invalid_argument_k, options_.cpu_class_ceiling = (ucall_cpu_class_t)4);
    expect_server_init_(ucall_status_invalid_argument_k, options_.metrics_sample_rate = 2.f);
    expect_server_init_(ucall_status_invalid_argument_k, options_.metrics_prefix = prefix_with_colon);
    expect_server_init_(ucall_status_invalid_argument_k, options_.metrics_tags_count = 1);
    expect_server_init_(ucall_status_invalid_argument_k, options_.metrics_address = view_of_("no-port"));
    expect_server_init_(ucall_status_invalid_argument_k, interface_.address = empty_directory);
    expect_server_init_(ucall_status_invalid_argument_k, interface_.address = view_of_("127.0.0.1"));
    expect_server_init_(ucall_status_invalid_argument_k, interface_.security = (ucall_security_t)9);
    expect_server_init_(ucall_status_invalid_argument_k, interface_.security = ucall_security_noise_ik_k);
    expect_server_init_(ucall_status_invalid_argument_k,
                        (interface_.security = ucall_security_noise_xx_k, interface_.noise_private_key = &key));
    expect_server_init_(ucall_status_invalid_argument_k,
                        (interface_.security = ucall_security_noise_kk_k, interface_.noise_private_key = &key));
    expect_server_init_(ucall_status_invalid_argument_k, interface_.max_concurrent_connections = 0);
    expect_server_init_(ucall_status_invalid_argument_k, interface_.reply_directories_count = 1);
    expect_server_init_(ucall_status_invalid_argument_k,
                        (interface_.reply_directories = &empty_directory, interface_.reply_directories_count = 1));
    expect_server_init_(ucall_status_invalid_argument_k, interface_.listen_descriptor = &closed_descriptor);
    expect_server_init_(missing_device_status, interface_.device_name = view_of_("ucall-missing0"));
    expect_server_init_(ucall_status_unsupported_k, options_.backend = foreign_backend);
    expect_server_init_(ucall_status_overflow_k, interface_.max_pipelined_requests = SIZE_MAX);
    expect_server_init_(ucall_status_not_found_k,
                        (interface_.reply_directories = &missing_directory, interface_.reply_directories_count = 1));
    expect_server_init_(ucall_status_success_k,
                        (interface_.security = ucall_security_noise_xx_k, interface_.noise_private_key = &key,
                         interface_.peer_authorizer = admit_peer));
    {
        // A ceiling naming a class this machine lacks intersects with what it runs, not refuses.
        ucall_network_interface_t interface_ = base_interface;
        ucall_server_options_t options_ = base_options;
        ucall_server_options_t resolved_;
        ucall_server_t server_ = NULL;
        options_.interfaces = &interface_;
        options_.cpu_class_ceiling = foreign_cpu_class;
        expect_call_(ucall_status_success_k, ucall_server_init, .server = &server_, .options = &options_,
                     .resolved = &resolved_);
        expect_(resolved_.cpu_class_ceiling == ucall_cpu_class_serial_k);
        ucall_server_free(server_);
    }

    ucall_server_t server = NULL;
    ucall_server_options_t resolved;
    expect_call_(ucall_status_success_k, ucall_server_init, .server = &server, .options = &base_options,
                 .resolved = &resolved);
    expect_(server != NULL && resolved.interfaces_count == 1 && resolved.interfaces[0].event_loops == 1);
    expect_(resolved.interfaces[0].max_pipelined_requests == 1 && resolved.metrics_sample_rate == 1.f);
    expect_(resolved.interfaces[0].memory_domain == -1);

    ucall_event_loop_statistics_t loop_statistics;
    ucall_batch_endpoint_statistics_t batch_statistics;
    expect_call_(ucall_status_uninitialized_k, ucall_server_take_call, .server = NULL);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_take_call, .server = server, .event_loop_index = 1);
    expect_call_(ucall_status_uninitialized_k, ucall_server_take_calls, .server = NULL);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_take_calls, .server = server, .event_loop_index = 1);
    expect_call_(ucall_status_uninitialized_k, ucall_server_event_loop_statistics, .server = NULL,
                 .statistics = &loop_statistics);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_event_loop_statistics, .server = server,
                 .statistics = NULL);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_event_loop_statistics, .server = server,
                 .event_loop_index = 1, .statistics = &loop_statistics);
    expect_call_(ucall_status_success_k, ucall_server_event_loop_statistics, .server = server,
                 .statistics = &loop_statistics);
    expect_call_(ucall_status_uninitialized_k, ucall_server_take_batch, .server = NULL);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_take_batch, .server = server, .endpoint = NULL);
    expect_call_(ucall_status_uninitialized_k, ucall_server_take_batches, .server = NULL);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_take_batches, .server = server, .endpoint = NULL);
    expect_call_(ucall_status_uninitialized_k, ucall_server_batch_endpoint_statistics, .server = NULL,
                 .statistics = &batch_statistics);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_batch_endpoint_statistics, .server = server,
                 .endpoint = NULL, .statistics = &batch_statistics);

    expect_call_(ucall_status_uninitialized_k, ucall_server_add_http_endpoint, .server = NULL,
                 .uri_template = view_of_("/users"), .verb = ucall_verb_get_k, .callback = on_request);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server,
                 .uri_template = view_of_("/users"), .verb = ucall_verb_get_k, .callback = NULL);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server,
                 .uri_template = view_of_("/users"), .verb = ucall_verb_unknown_k, .callback = on_request);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server,
                 .uri_template = view_of_(""), .verb = ucall_verb_get_k, .callback = on_request);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server,
                 .uri_template = view_of_("users"), .verb = ucall_verb_get_k, .callback = on_request);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server,
                 .uri_template = view_of_("/users?page=1"), .verb = ucall_verb_get_k, .callback = on_request);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server,
                 .uri_template = view_of_("/users#top"), .verb = ucall_verb_get_k, .callback = on_request);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server,
                 .uri_template = view_of_("/users/{id"), .verb = ucall_verb_get_k, .callback = on_request);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server,
                 .uri_template = view_of_("/files/{*path}/more"), .verb = ucall_verb_get_k, .callback = on_request);
    expect_call_(ucall_status_success_k, ucall_server_add_http_endpoint, .server = server,
                 .uri_template = view_of_("/users/{id}"), .verb = ucall_verb_get_k, .callback = on_request);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_add_http_endpoint, .server = server,
                 .uri_template = view_of_("/users/{name}/posts"), .verb = ucall_verb_get_k, .callback = on_request);
    expect_call_(ucall_status_already_exists_k, ucall_server_add_http_endpoint, .server = server,
                 .uri_template = view_of_("/users/{id}"), .verb = ucall_verb_get_k, .callback = on_request);
    expect_call_(ucall_status_success_k, ucall_server_add_http_endpoint, .server = server,
                 .uri_template = view_of_("/users/{id}"), .verb = ucall_verb_any_k, .callback = on_request);
    expect_call_(ucall_status_success_k, ucall_server_add_http_endpoint, .server = server,
                 .uri_template = view_of_("/users/{id}/posts"), .verb = ucall_verb_get_k, .callback = on_request);

    ucall_http_batch_endpoint_t endpoint = NULL;
    expect_call_(ucall_status_uninitialized_k, ucall_server_add_http_batch_endpoint, .server = NULL,
                 .uri_template = view_of_("/batch"), .verb = ucall_verb_post_k, .callback = on_batch,
                 .endpoint = &endpoint);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_add_http_batch_endpoint, .server = server,
                 .uri_template = view_of_("/batch"), .verb = ucall_verb_post_k, .callback = on_batch, .endpoint = NULL);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_add_http_batch_endpoint, .server = server,
                 .uri_template = view_of_("/batch"), .verb = ucall_verb_post_k, .callback = NULL,
                 .endpoint = &endpoint);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_add_http_batch_endpoint, .server = server,
                 .uri_template = view_of_("/batch"), .verb = ucall_verb_post_k, .callback = on_batch,
                 .min_batch_size = 8, .max_batch_size = 4, .endpoint = &endpoint);
    expect_call_(ucall_status_success_k, ucall_server_add_http_batch_endpoint, .server = server,
                 .uri_template = view_of_("/batch"), .verb = ucall_verb_post_k, .callback = on_batch,
                 .endpoint = &endpoint);
    expect_(endpoint != NULL);
    expect_call_(ucall_status_already_exists_k, ucall_server_add_http_batch_endpoint, .server = server,
                 .uri_template = view_of_("/batch"), .verb = ucall_verb_post_k, .callback = on_batch,
                 .endpoint = &endpoint);
    expect_call_(ucall_status_already_exists_k, ucall_server_add_http_endpoint, .server = server,
                 .uri_template = view_of_("/batch"), .verb = ucall_verb_post_k, .callback = on_request);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_batch_endpoint_statistics, .server = server,
                 .endpoint = endpoint, .statistics = NULL);
    expect_call_(ucall_status_success_k, ucall_server_batch_endpoint_statistics, .server = server, .endpoint = endpoint,
                 .statistics = &batch_statistics);
    expect_(batch_statistics.batches == 0 && batch_statistics.requests == 0);

    // No request reaches an unpolled server, so accessors and replies meet only their own checks.
    ucall_bytes_view_t view;
    ucall_noise_key_t peer_key;
    ucall_peer_address_t peer_address;
    size_t count = 0;
    expect_call_(ucall_status_uninitialized_k, ucall_server_request_path, .server = NULL, .path = &view);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_request_path, .server = server, .path = &view);
    expect_call_(ucall_status_uninitialized_k, ucall_server_request_query, .server = NULL, .query = &view);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_request_query, .server = server, .query = &view);
    expect_call_(ucall_status_uninitialized_k, ucall_server_request_path_segment, .server = NULL, .segment = &view);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_request_path_segment, .server = server,
                 .segment = &view);
    expect_call_(ucall_status_uninitialized_k, ucall_server_request_path_parameter, .server = NULL, .value = &view);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_request_path_parameter, .server = server,
                 .name = view_of_("id"), .value = &view);
    expect_call_(ucall_status_uninitialized_k, ucall_server_request_query_parameter, .server = NULL, .value = &view);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_request_query_parameter, .server = server,
                 .name = view_of_("page"), .value = &view);
    expect_call_(ucall_status_uninitialized_k, ucall_server_request_header, .server = NULL, .value = &view);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_request_header, .server = server,
                 .name = view_of_("Host"), .value = &view);
    expect_call_(ucall_status_uninitialized_k, ucall_server_request_field, .server = NULL, .name = &view,
                 .value = &view);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_request_field, .server = server, .name = &view,
                 .value = &view);
    expect_call_(ucall_status_uninitialized_k, ucall_server_request_peer, .server = NULL);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_request_peer, .server = server,
                 .network_interface_index = &count, .static_key = &peer_key, .address = &peer_address);
    expect_call_(ucall_status_uninitialized_k, ucall_server_request_body, .server = NULL, .body = &view);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_request_body, .server = server, .body = &view);
    expect_call_(ucall_status_uninitialized_k, ucall_server_request_body_chunk, .server = NULL, .data = &view);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_request_body_chunk, .server = server, .data = &view);
    expect_call_(ucall_status_uninitialized_k, ucall_server_request_part, .server = NULL);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_request_part, .server = server, .name = &view,
                 .content_type = &view, .data = &view);
    expect_call_(ucall_status_uninitialized_k, ucall_server_reply_content, .server = NULL);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_reply_content, .server = server, .request = NULL);
    expect_call_(ucall_status_uninitialized_k, ucall_server_reply_error, .server = NULL);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_reply_error, .server = server, .request = NULL,
                 .http_status = 404);
    expect_call_(ucall_status_uninitialized_k, ucall_server_reply_vectored, .server = NULL);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_reply_vectored, .server = server, .request = NULL);
    expect_call_(ucall_status_uninitialized_k, ucall_server_reply_begin, .server = NULL);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_reply_begin, .server = server, .request = NULL);
    expect_call_(ucall_status_uninitialized_k, ucall_server_reply_append, .server = NULL);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_reply_append, .server = server, .request = NULL);
    expect_call_(ucall_status_uninitialized_k, ucall_server_reply_end, .server = NULL);
    expect_call_(ucall_status_invalid_argument_k, ucall_server_reply_end, .server = server, .request = NULL);
    expect_(ucall_server_request_verb(NULL, NULL) == ucall_verb_unknown_k);
    expect_(ucall_server_request_path_segments_count(NULL, NULL) == 0);
    expect_(ucall_server_request_parts_count(NULL, NULL) == 0);
    expect_(ucall_server_request_fields_count(NULL, NULL) == 0);
    expect_(ucall_server_request_fields_count(server, NULL) == 0);

    ucall_client_options_t base_client_options;
    memset(&base_client_options, 0, sizeof(base_client_options));
    base_client_options.max_concurrent_connections = 2;
    expect_call_(ucall_status_invalid_argument_k, ucall_client_init, .client = NULL, .options = &base_client_options);
    expect_client_init_(ucall_status_success_k, (void)0);
    expect_client_init_(ucall_status_invalid_argument_k, options_.max_concurrent_connections = 0);
    expect_client_init_(ucall_status_invalid_argument_k, options_.cpu_class_ceiling = (ucall_cpu_class_t)4);
    expect_client_init_(ucall_status_invalid_argument_k,
                        (options_.max_concurrent_connections = SIZE_MAX, options_.max_pipelined_calls = 2));
    expect_client_init_(ucall_status_invalid_argument_k, (options_.server = server, options_.event_loop = 1));
    expect_client_init_(ucall_status_invalid_argument_k,
                        (options_.server = server, options_.backend = foreign_backend));
    {
        ucall_client_options_t options_ = base_client_options;
        ucall_client_options_t resolved_;
        ucall_client_t client_ = NULL;
        options_.cpu_class_ceiling = foreign_cpu_class;
        expect_call_(ucall_status_success_k, ucall_client_init, .client = &client_, .options = &options_,
                     .resolved = &resolved_);
        expect_(resolved_.cpu_class_ceiling == ucall_cpu_class_serial_k);
        ucall_client_free(client_);
    }
    expect_client_init_(ucall_status_overflow_k,
                        (options_.max_pipelined_calls = SIZE_MAX, options_.max_concurrent_calls = 1));
    expect_client_init_(ucall_status_overflow_k, options_.max_concurrent_connections = (size_t)1 << 31);
    {
        ucall_client_t client = NULL;
        ucall_client_options_t options = {0};
        expect_call_(ucall_status_invalid_argument_k, ucall_client_init, .client = &client, .options = NULL);
        expect_(client == NULL);
        options.max_concurrent_connections = 2;
        options.server = server;
        expect_call_(ucall_status_success_k, ucall_client_init, .client = &client, .options = &options);
        expect_(client != NULL);
        // The bound client keeps its server, so this free returns and the rows below still use it.
        ucall_server_free(server);
        ucall_client_free(client);
    }

    ucall_client_t client = NULL;
    expect_call_(ucall_status_success_k, ucall_client_init, .client = &client, .options = &base_client_options);
    ucall_bytes_view_t const header = view_of_("Accept: */*");
    ucall_bytes_view_t const dangling = {NULL, 3};
    ucall_completed_call_t completed[2];
    expect_call_(ucall_status_uninitialized_k, ucall_client_call, .client = NULL, .url = view_of_("http://localhost/"),
                 .verb = ucall_verb_get_k);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_call, .client = client,
                 .url = view_of_("http://localhost/"), .verb = ucall_verb_unknown_k);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_call, .client = client,
                 .url = view_of_("http://localhost/"), .verb = ucall_verb_any_k);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_call, .client = client, .url = view_of_("localhost/"),
                 .verb = ucall_verb_get_k);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_call, .client = client,
                 .url = view_of_("http://?page=1"), .verb = ucall_verb_get_k);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_call, .client = client,
                 .url = view_of_("http://localhost:0/"), .verb = ucall_verb_get_k);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_call, .client = client,
                 .url = view_of_("http://user@host/"), .verb = ucall_verb_get_k);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_call, .client = client, .url = dangling,
                 .verb = ucall_verb_get_k);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_call, .client = client,
                 .url = view_of_("http://localhost/"), .verb = ucall_verb_post_k, .body = dangling);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_call, .client = client,
                 .url = view_of_("http://localhost/"), .verb = ucall_verb_get_k, .headers_count = 1);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_call, .client = client,
                 .url = view_of_("http://localhost/"), .verb = ucall_verb_get_k,
                 .options = {.security = (ucall_security_t)9});
    expect_call_(ucall_status_invalid_argument_k, ucall_client_call, .client = client,
                 .url = view_of_("http+noise://localhost/"), .verb = ucall_verb_get_k);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_call, .client = client,
                 .url = view_of_("http://localhost/"), .verb = ucall_verb_get_k,
                 .options = {.security = ucall_security_noise_ik_k, .noise_private_key = &key});
    expect_call_(ucall_status_invalid_argument_k, ucall_client_call, .client = client,
                 .url = view_of_("http://localhost/"), .verb = ucall_verb_get_k,
                 .options = {.body_delivery = (ucall_body_delivery_t)2});
    expect_call_(ucall_status_unsupported_k, ucall_client_call, .client = client, .url = view_of_("ftp://localhost/"),
                 .verb = ucall_verb_get_k, .headers = &header, .headers_count = 1,
                 .options = {.body_delivery = ucall_body_delivery_streamed_k});
    expect_call_(ucall_status_uninitialized_k, ucall_client_take_completed, .client = NULL, .count = &count);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_take_completed, .client = client, .count = NULL);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_take_completed, .client = client, .calls = NULL,
                 .capacity = 2, .count = &count);
    expect_call_(ucall_status_success_k, ucall_client_take_completed, .client = client, .calls = completed,
                 .capacity = 2, .count = &count);
    expect_(count == 0);
    expect_call_(ucall_status_uninitialized_k, ucall_client_take_completed_call, .client = NULL, .call = completed);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_take_completed_call, .client = client, .call = NULL);
    expect_call_(ucall_status_not_found_k, ucall_client_take_completed_call, .client = client, .context = &count,
                 .call = completed);

    expect_call_(ucall_status_invalid_argument_k, ucall_client_response_header, .response = NULL,
                 .name = view_of_("Date"), .value = &view);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_response_field, .response = NULL, .name = &view,
                 .value = &view);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_response_body, .response = NULL, .body = &view);
    expect_call_(ucall_status_uninitialized_k, ucall_client_response_body_chunk, .client = NULL, .data = &view);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_response_body_chunk, .client = client, .response = NULL,
                 .data = &view);
    expect_call_(ucall_status_invalid_argument_k, ucall_client_response_body_chunk, .client = client, .data = NULL);
    expect_(ucall_client_response_status(NULL) == 0);
    expect_(ucall_client_response_fields_count(NULL) == 0);
    ucall_client_response_free(NULL);

    ucall_client_free(client);
    ucall_client_free(NULL);
    ucall_server_stop(NULL);
    ucall_server_stop(server);
    ucall_server_free(server);
    ucall_server_free(NULL);
}

int main(int argc, char** argv) {
    printf("UCall %s\n", ucall_version_name());
    start_test_run(argc, argv);
    start_test_case("test_names_and_keys"), test_names_and_keys(), finish_test_case(NULL);
    start_test_case("test_type_refusals"), test_type_refusals(), finish_test_case(NULL);
    start_test_case("test_handle_refusals"), test_handle_refusals(), finish_test_case(NULL);
    return finish_test_run();
}

#undef expect_client_init_
#undef expect_server_init_
#undef expect_call_
#undef view_of_
#undef expect_
