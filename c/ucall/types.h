/**
 *  @file c/ucall/types.h
 *  @author Ash Vardanian
 *  @date February 3, 2023
 *  @brief Shared handles, counted byte views, statuses, and outcomes.
 */

#ifndef UNUM_UCALL_TYPES_H
#define UNUM_UCALL_TYPES_H

#include <stddef.h> // size_t
#include <stdint.h> // uint32_t, int32_t

#pragma region Platform Identity

/*  Derived once from the OS and architecture predefines, which no other file reads. */
#if defined(UCALL_OS_LINUX_) || defined(UCALL_OS_APPLE_) || defined(UCALL_OS_WINDOWS_) || \
    defined(UCALL_OS_FREEBSD_) || defined(UCALL_OS_POSIX_) || defined(UCALL_ARCH_ARM64_)
#error "UCALL_OS_*_ and UCALL_ARCH_*_ are identity, derived from the compiler; set a UCALL_WITH_* facility instead"
#endif

/** Whether the kernel is Linux, Android included, as 1 or 0. */
#if defined(__linux__)
#define UCALL_OS_LINUX_ 1
#else
#define UCALL_OS_LINUX_ 0
#endif

/** Whether the kernel is Darwin: macOS, iOS, tvOS, watchOS or visionOS, as 1 or 0. */
#if defined(__APPLE__)
#define UCALL_OS_APPLE_ 1
#else
#define UCALL_OS_APPLE_ 0
#endif

/** Whether the target is Windows, MinGW included and Cygwin not, as 1 or 0. */
#if defined(_WIN32)
#define UCALL_OS_WINDOWS_ 1
#else
#define UCALL_OS_WINDOWS_ 0
#endif

/** Whether the kernel is FreeBSD, as 1 or 0. */
#if defined(__FreeBSD__)
#define UCALL_OS_FREEBSD_ 1
#else
#define UCALL_OS_FREEBSD_ 0
#endif

/** Whether the POSIX interfaces exist: Linux, Darwin, FreeBSD or Cygwin, as 1 or 0. */
#if UCALL_OS_LINUX_ || UCALL_OS_APPLE_ || UCALL_OS_FREEBSD_ || defined(__CYGWIN__)
#define UCALL_OS_POSIX_ 1
#else
#define UCALL_OS_POSIX_ 0
#endif

/** Whether the target is 64-bit Arm, as 1 or 0. */
#if defined(__aarch64__) || defined(_M_ARM64)
#define UCALL_ARCH_ARM64_ 1
#else
#define UCALL_ARCH_ARM64_ 0
#endif

#if UCALL_OS_LINUX_ + UCALL_OS_APPLE_ + UCALL_OS_WINDOWS_ + UCALL_OS_FREEBSD_ > 1
#error "Two operating-system identities hold at once"
#endif
#if UCALL_OS_POSIX_ && UCALL_OS_WINDOWS_
#error "POSIX and Windows identities hold at once"
#endif

#pragma endregion Platform Identity

/*  Kernel facilities default to what the operating system offers, and dependency facilities to 0,
 *  which the target linking the dependency sets; each refuses an operating system lacking it. */
#pragma region Facilities

/** Whether the portable engine over nonblocking POSIX calls and @c poll is compiled, as 1 or 0. */
#if !defined(UCALL_WITH_POSIX)
#define UCALL_WITH_POSIX UCALL_OS_POSIX_
#endif
#if UCALL_WITH_POSIX && !UCALL_OS_POSIX_
#error "UCALL_WITH_POSIX needs a POSIX system"
#endif

/** Whether the engine over epoll and Linux AIO is compiled, as 1 or 0. */
#if !defined(UCALL_WITH_LINUX_EPOLLAIO)
#define UCALL_WITH_LINUX_EPOLLAIO UCALL_OS_LINUX_
#endif
#if UCALL_WITH_LINUX_EPOLLAIO && !UCALL_OS_LINUX_
#error "UCALL_WITH_LINUX_EPOLLAIO needs Linux"
#endif

/** Whether the io_uring engines are compiled, as 1 or 0, which the target linking liburing sets. */
#if !defined(UCALL_WITH_LINUX_URING)
#define UCALL_WITH_LINUX_URING 0
#endif
#if UCALL_WITH_LINUX_URING && !UCALL_OS_LINUX_
#error "UCALL_WITH_LINUX_URING needs Linux"
#endif

/** Whether the kqueue engine is compiled, as 1 or 0. */
#if !defined(UCALL_WITH_BSD_KQUEUE)
#define UCALL_WITH_BSD_KQUEUE (UCALL_OS_APPLE_ || UCALL_OS_FREEBSD_)
#endif
#if UCALL_WITH_BSD_KQUEUE && !(UCALL_OS_APPLE_ || UCALL_OS_FREEBSD_)
#error "UCALL_WITH_BSD_KQUEUE needs Darwin or FreeBSD"
#endif

/** Whether the I/O completion port engine is compiled, as 1 or 0. */
#if !defined(UCALL_WITH_WINDOWS_IOCP)
#define UCALL_WITH_WINDOWS_IOCP UCALL_OS_WINDOWS_
#endif
#if UCALL_WITH_WINDOWS_IOCP && !UCALL_OS_WINDOWS_
#error "UCALL_WITH_WINDOWS_IOCP needs Windows"
#endif

/** Whether the Registered I/O engine is compiled, as 1 or 0. */
#if !defined(UCALL_WITH_WINDOWS_RIO)
#define UCALL_WITH_WINDOWS_RIO UCALL_OS_WINDOWS_
#endif
#if UCALL_WITH_WINDOWS_RIO && !UCALL_OS_WINDOWS_
#error "UCALL_WITH_WINDOWS_RIO needs Windows"
#endif

/** Whether this unit builds the shared library, as 1 or 0. */
#if !defined(UCALL_EXPORTING)
#define UCALL_EXPORTING 0
#endif

/** Whether this unit links the shared library rather than the archive, as 1 or 0. */
#if !defined(UCALL_SHARED)
#define UCALL_SHARED 0
#endif

/**
 *  @brief Marks every function the library exports, and nothing else.
 *
 *  On Windows it exports from the shared library, which builds with @c UCALL_EXPORTING, imports
 *  where a consumer of that library sets @c UCALL_SHARED, as linking @c ucall::shared does, and
 *  expands to nothing for the static library. GCC and Clang give the function default visibility,
 *  so it survives @c -fvisibility=hidden.
 */
#if !defined(UCALL_EXPORT)
#if UCALL_OS_WINDOWS_ && UCALL_EXPORTING
#define UCALL_EXPORT __declspec(dllexport)
#elif UCALL_OS_WINDOWS_ && UCALL_SHARED
#define UCALL_EXPORT __declspec(dllimport)
#elif UCALL_OS_WINDOWS_
#define UCALL_EXPORT
#elif defined(__GNUC__) || defined(__clang__)
#define UCALL_EXPORT __attribute__((visibility("default")))
#else
#define UCALL_EXPORT
#endif
#endif // !defined(UCALL_EXPORT)

#pragma endregion Facilities

/** Major version of the C interface; it changes when a release breaks it. */
#define UCALL_VERSION_MAJOR 1

/** Minor version of the C interface; it changes when a release adds to it. */
#define UCALL_VERSION_MINOR 0

/** Patch version of the C interface; it changes when a release only fixes it. */
#define UCALL_VERSION_PATCH 0

#ifdef __cplusplus
extern "C" {
#endif

/** One byte of raw storage shared by views and cryptographic keys. */
typedef uint8_t ucall_byte_t;

/** A borrowed run of bytes; text is bytes that happen to decode.
 *
 *  Empty is {NULL, 0}. Length never requests a null-terminator lookup. */
typedef struct ucall_bytes_view_t {

    /** First byte of the run. */
    ucall_byte_t const* data;

    /** Bytes the run spans, with no terminator assumed or written. */
    size_t length;

} ucall_bytes_view_t;

/** A concrete I/O implementation; automatic chooses an available native implementation. */
typedef enum ucall_io_backend_t {

    /** Initialization picks the fastest backend this machine and its limits allow. */
    ucall_io_backend_automatic_k = 0,

    /** Blocking sockets and files, polled with @c poll, on any POSIX system. */
    ucall_io_backend_posix_k,

    /** Linux epoll for sockets and Linux AIO for files, the path where io_uring is blocked. */
    ucall_io_backend_linux_epollaio_k,

    /** io_uring as Linux 6.12, the older LTS line, provides it. */
    ucall_io_backend_linux_uring612_k,

    /** io_uring as Linux 6.18, the newer LTS line, provides it, with multishot receives. */
    ucall_io_backend_linux_uring618_k,

    /** kqueue on FreeBSD, with FreeBSD AIO for files, and on macOS. */
    ucall_io_backend_bsd_kqueue_k,

    /** I/O completion ports on Windows. */
    ucall_io_backend_windows_iocp_k,

    /** Registered I/O on Windows for stream sockets, beside a completion port for the rest. */
    ucall_io_backend_windows_rio_k
} ucall_io_backend_t;

/** A CPU kernel bundle, named with the same native classes as the sibling libraries. */
typedef enum ucall_cpu_class_t {

    /** No class requested: initialization picks the best class this machine runs. */
    ucall_cpu_class_unknown_k = 0,

    /** Portable kernels with no SIMD, which every machine runs. */
    ucall_cpu_class_serial_k,

    /** AVX2 kernels, as on Intel Haswell. */
    ucall_cpu_class_intel_haswell_k,

    /** Adds AVX-512 kernels, as on Intel Skylake-X. */
    ucall_cpu_class_intel_skylake_k,

    /** Adds Ice Lake's AVX-512 extensions and SHA, as on Intel Ice Lake. */
    ucall_cpu_class_intel_icelake_k,

    /** AVX2 kernels with SHA and no AVX-512, as on Intel Alder Lake. */
    ucall_cpu_class_intel_alder_k,

    /** NEON kernels with the AES and SHA extensions, as on AWS Graviton2. */
    ucall_cpu_class_aws_g2_k,

    /** As on AWS Graviton5, running the kernels of @c ucall_cpu_class_aws_g2_k. */
    ucall_cpu_class_aws_g5_k,

    /** The one class a monoversioned build compiles, over every capability it targets. */
    ucall_cpu_class_monoversioned_k
} ucall_cpu_class_t;

/** Returns the stable name of an I/O backend. */
UCALL_EXPORT char const* ucall_io_backend_name(ucall_io_backend_t backend);

/** Returns the stable name of a CPU kernel class. */
UCALL_EXPORT char const* ucall_cpu_class_name(ucall_cpu_class_t cpu_class);

/**
 *  @brief Reads an I/O backend back from its stable name.
 *  @param[in] name The counted spelling @c ucall_io_backend_name() returns.
 *  @return The named backend, or @c ucall_io_backend_automatic_k for an unrecognized name, which
 *      callers tell from "automatic" by naming the result back.
 *
 *  @note @b Thread-safe.
 */
UCALL_EXPORT ucall_io_backend_t ucall_io_backend_from_name(ucall_bytes_view_t name);

/**
 *  @brief Reads a CPU kernel class back from its stable name.
 *  @param[in] name The counted spelling @c ucall_cpu_class_name() returns.
 *  @return The named class, or @c ucall_cpu_class_unknown_k for an unrecognized name.
 *
 *  @note @b Thread-safe.
 */
UCALL_EXPORT ucall_cpu_class_t ucall_cpu_class_from_name(ucall_bytes_view_t name);

/**
 *  @brief Opaque server handle.
 *  @sa Deals with @c ucall_received_http_request_t, individually or in counted arrays.
 *  @sa Use with @c ucall_server_init() and @c ucall_server_free() for lifetime.
 *  @sa Use @c ucall_server_add_http_endpoint() and @c ucall_server_take_calls() for logic.
 */
typedef struct ucall_server_handle_t* ucall_server_t;

/**
 *  @brief Opaque client handle.
 *  @sa Deals with @c ucall_received_http_response_t.
 *  @sa Use with @c ucall_client_init() and @c ucall_client_free() for lifetime.
 *  @sa Use @c ucall_client_call() for logic.
 *
 *  At a high level, a @b client is responsible for:
 *
 *  - Establishing connections to one or more servers, reusing encryption keys between requests.
 *  - Following redirects chains automatically, unless disabled.
 *  - Driving accepted calls when the application polls for completions.
 */
typedef struct ucall_client_handle_t* ucall_client_t;

/** Opaque handle for a single Remote Procedure Call on the @b server side. */
typedef struct ucall_received_http_request_handle_t* ucall_received_http_request_t;

/** One batch endpoint of a server, drained by one application thread; lives until
 *  @c ucall_server_free(). */
typedef struct ucall_http_batch_endpoint_handle_t* ucall_http_batch_endpoint_t;

/** Opaque handle for a single Remote Procedure Call reply on the @b client side. */
typedef struct ucall_received_http_response_handle_t* ucall_received_http_response_t;

/** When an endpoint's callback runs: once the body is buffered, or at headers time with the body
 *  pulled through ucall_server_request_body_chunk(). */
typedef enum ucall_body_delivery_t {

    /** The callback runs once the whole body is buffered, within @c max_request_bytes. */
    ucall_body_delivery_buffered_k = 0,

    /** The callback runs at headers time and pulls the body in chunks. */
    ucall_body_delivery_streamed_k = 1,
} ucall_body_delivery_t;

/**
 *  @brief Security modes for UCall server and client.
 *
 *  Noise protocol pattern to use for handshake. Supported values:
 *  - @c XX: Full mutual authentication (both parties authenticate during handshake).
 *  - @c IK: Client knows server's public key in advance (Identity Known).
 *  - @c KK: Both parties know each other's public keys (Known Known).
 *
 *  @note Use @c http+noise:// or @c ws+noise:// URL schemes to enable Noise transport.
 *  @see https://noiseprotocol.org/noise.html for pattern specifications.
 */
typedef enum ucall_security_t {

    /** No encryption, plain TCP/IP. */
    ucall_security_none_k,

    /** Trust on first use - no pre-shared keys needed. */
    ucall_security_noise_xx_k,

    /** Client knows server's public key in advance. */
    ucall_security_noise_ik_k,

    /** Both know each other's public keys in advance. */
    ucall_security_noise_kk_k
} ucall_security_t;

/** Noise protocol key (32 bytes for Curve25519). */
typedef ucall_byte_t ucall_noise_key_t[32];

/** HTTP request methods/verbs for endpoint routing. */
typedef enum ucall_verb_t {

    /** Unrecognized or not yet parsed. The zero-initialized default. */
    ucall_verb_unknown_k = 0,

    /** HTTP "GET" method for retrieving resources. */
    ucall_verb_get_k,

    /** HTTP "POST" method for creating resources. */
    ucall_verb_post_k,

    /** HTTP "PUT" method for updating resources. */
    ucall_verb_put_k,

    /** HTTP "DELETE" method for removing resources. */
    ucall_verb_delete_k,

    /** HTTP "PATCH" method for partial updates. */
    ucall_verb_patch_k,

    /** HTTP "HEAD" method for retrieving headers only. */
    ucall_verb_head_k,

    /** HTTP "OPTIONS" method for retrieving supported methods. */
    ucall_verb_options_k,

    /** Matches every method. Valid only when registering an endpoint. */
    ucall_verb_any_k
} ucall_verb_t;

/**
 *  @brief Library-level outcomes, preserving USearch numbers for shared statuses.
 *
 *  These codes represent library/transport-level outcomes. For HTTP-specific status codes (200,
 *  404, 500), use @c ucall_http_status_t.
 *
 *  Statuses fall into five categories. Resources: out of memory, I/O, and connections that failed
 *  or closed. Input: invalid arguments, malformed bytes, failed handshakes and rejected peers.
 *  State: uninitialized handles, unsupported features, names not found or already existing,
 *  overflow and contention. Interruptions: deferral, would-block and timeouts. Defects: internal
 *  failures. Any verb that allocates, binds a device or touches a file or a socket may also return
 *  a Resources status. A verb's own block lists only what its contract adds.
 */
typedef enum ucall_status_t {

    /** The call succeeded; the outcome message is NULL. */
    ucall_status_success_k = 0,

    /** A submitted call has not finished; the only status that is never final. */
    ucall_status_deferred_k = 1,

    /** An allocation or reservation could not be satisfied. */
    ucall_status_out_of_memory_k = 2,

    /** A socket or file could not be opened, read, written, or closed. */
    ucall_status_io_k = 7,

    /** The peer supplied bytes that cannot be decoded as the expected protocol. */
    ucall_status_malformed_k = 9,

    /** The engine violated its contract, which points at a defect. */
    ucall_status_internal_k = 10,

    /** The requested size exceeds the representable range. */
    ucall_status_overflow_k = 11,

    /** The call needs a handle that was never initialized. */
    ucall_status_uninitialized_k = 12,

    /** The call was refused rather than waited for, such as a handle another call holds. */
    ucall_status_contended_k = 14,

    /** The build, backend, or machine does not implement the requested feature. */
    ucall_status_unsupported_k = 16,

    /** An argument is null, out of range, or contradicts another argument. */
    ucall_status_invalid_argument_k = 17,

    /** The requested endpoint, header, or parameter does not exist. */
    ucall_status_not_found_k = 18,

    /** An endpoint with the same template and method is already registered. */
    ucall_status_already_exists_k = 19,

    /** DNS lookup or connection establishment failed. */
    ucall_status_connection_failed_k = 20,

    /** The connection closed before the exchange completed. */
    ucall_status_connection_closed_k = 21,

    /** The operation exceeded its time budget. */
    ucall_status_timeout_k = 22,

    /** The Noise handshake failed to authenticate or agree on keys. */
    ucall_status_handshake_failed_k = 23,

    /** The peer authorizer declined the authenticated static key. */
    ucall_status_peer_rejected_k = 24,

    /** A nonblocking poll had no progress to report. */
    ucall_status_would_block_k = 25,

} ucall_status_t;

/**
 *  @brief Decides whether a peer presenting a given static key may proceed past the handshake.
 *  @param[in] peer_static_key The remote party's 32-byte Curve25519 static public key.
 *  @param[in] context User-supplied context from the server or client configuration.
 *
 *  Required for @c ucall_security_noise_xx_k, where keys are learned during the handshake
 *  rather than known in advance. Called after the key is authenticated, before any payload.
 *  Returning @c ucall_status_success_k admits the peer.
 *
 *  @par Statuses:
 *  - @c ucall_status_peer_rejected_k The plain refusal. Any other status refuses the peer too, and
 *    becomes the connection's outcome.
 */
typedef ucall_status_t (*ucall_peer_authorizer_t)(ucall_noise_key_t const* peer_static_key, void* context);

/** Outcome of one call: a status to branch on, and a static message with the detail it cannot
 *  carry.
 *
 *  The message has static storage, is never freed, and is @c NULL exactly when the status is @c
 *  ucall_status_success_k. Every verb struct points at one. */
typedef struct ucall_outcome_t {

    /** The final status, or ucall_status_deferred_k while a submitted call is unfinished. */
    ucall_status_t status;

    /** Static detail, never freed; NULL exactly on success. */
    char const* message;

} ucall_outcome_t;

/**
 *  @brief Blocks until @p outcome is final, waiting on its status word through the CPU class's
 *      waiter, and with acquire ordering.
 *  @param[in] outcome An outcome passed to a call, read until its status leaves @c
 *      ucall_status_deferred_k.
 *  @return The final status.
 *
 *  Producers publish the final status with a release store on that word, which the waiter
 *  watches. Never wait from a callback that the call itself must finish before it can complete.
 *
 *
 *  @note @b Thread-safe. Any number of threads may wait on one outcome.
 */
UCALL_EXPORT ucall_status_t ucall_outcome_wait(ucall_outcome_t* outcome);

/**
 *  @brief Reads the outcome without waiting, with acquire ordering, so a final status publishes
 *      every output.
 *  @param[in] outcome An outcome passed to a call.
 *  @return The final status once the call is final.
 *
 *  Poll through this function; directly reading the field during a deferred call is not an atomic
 *  load.
 *
 *  @par Statuses:
 *  - @c ucall_status_deferred_k The call is not final.
 */
UCALL_EXPORT ucall_status_t ucall_outcome_status(ucall_outcome_t* outcome);

/** Arguments of @c ucall_noise_key_generate(). */
typedef struct ucall_noise_key_generate_t {

    /** The verb's status, listed on the verb. */
    ucall_outcome_t* outcome;

    /** Output for the secret scalar, drawn from the operating system's entropy. */
    ucall_noise_key_t* private_key;

    /** Output for the Curve25519 public key matching @c private_key. */
    ucall_noise_key_t* public_key;

} ucall_noise_key_generate_t;

/**
 *  @brief Draws a fresh static keypair for @c noise_private_key fields and peer authorizers.
 *
 *  Both outputs are zeroed unless the call succeeds.
 *
 *  @note @b Thread-safe.
 *
 *  @par Statuses:
 *  - @c ucall_status_invalid_argument_k An output is @c NULL.
 */
UCALL_EXPORT void ucall_noise_key_generate(ucall_noise_key_generate_t* arguments);

/** Arguments of @c ucall_noise_key_derive(). */
typedef struct ucall_noise_key_derive_t {

    /** Output for the outcome. */
    ucall_outcome_t* outcome;

    /** The secret scalar, as @c noise_private_key fields take it. */
    ucall_noise_key_t const* private_key;

    /** Output for the Curve25519 public key, which peers see during the handshake. */
    ucall_noise_key_t* public_key;

} ucall_noise_key_derive_t;

/**
 *  @brief Derives the public key of a stored private key, as peer authorizers compare it.
 *
 *  @note @b Thread-safe.
 *
 *  @par Statuses:
 *  - @c ucall_status_invalid_argument_k The @c private_key or the @c public_key output is @c NULL.
 */
UCALL_EXPORT void ucall_noise_key_derive(ucall_noise_key_derive_t* arguments);

/** The family of a peer's socket address. */
typedef enum ucall_address_family_t {

    /** No address was read for this peer. */
    ucall_address_family_unknown_k = 0,

    /** IPv4, in the first 4 bytes. */
    ucall_address_family_ipv4_k = 1,

    /** IPv6, in all 16 bytes, with its scope. */
    ucall_address_family_ipv6_k = 2,

    /** A local AF_UNIX peer, with no address bytes. */
    ucall_address_family_unix_k = 3,
} ucall_address_family_t;

/** A peer's socket address: IPv4 in the first 4 @c bytes, IPv6 in all 16, both in network order,
 *  the port in host order and the IPv6 scope; AF_UNIX peers carry only the family. */
typedef struct ucall_peer_address_t {

    /** The address in network order: IPv4 in the first 4 bytes, IPv6 in all 16. */
    ucall_byte_t bytes[16];

    /** The IPv6 scope, 0 otherwise. */
    uint32_t scope;

    /** The port in host order. */
    uint16_t port;

    /** A @c ucall_address_family_t, one byte wide. */
    uint8_t family;

    /** Zero, keeping the record at 24 bytes. */
    uint8_t reserved;
} ucall_peer_address_t;

/** HTTP status codes for server responses and client results.
 *
 *  Numeric codes also represent responses absent from the named constants below.
 *  For library outcomes, use @c ucall_status_t instead. */
typedef uint32_t ucall_http_status_t;
enum {

    /** Request succeeded. */
    ucall_http_status_ok_k = 200,

    /** Resource created. */
    ucall_http_status_created_k = 201,

    /** Success with an empty body. */
    ucall_http_status_no_content_k = 204,

    /** Success with the requested @c Range of the body. */
    ucall_http_status_partial_content_k = 206,

    /** Resource has a new permanent URL. */
    ucall_http_status_moved_permanently_k = 301,

    /** Resource is temporarily at a different URL. */
    ucall_http_status_found_k = 302,

    /** Cached copy is still fresh. */
    ucall_http_status_not_modified_k = 304,

    /** Malformed request syntax. */
    ucall_http_status_bad_request_k = 400,

    /** Authentication required or failed. */
    ucall_http_status_unauthorized_k = 401,

    /** Authenticated, but not permitted. */
    ucall_http_status_forbidden_k = 403,

    /** No endpoint matches the request path. */
    ucall_http_status_not_found_k = 404,

    /** Endpoint exists, but not for this verb. */
    ucall_http_status_method_not_allowed_k = 405,

    /** Client took too long to send the request. */
    ucall_http_status_timeout_k = 408,

    /** Request conflicts with current resource state. */
    ucall_http_status_conflict_k = 409,

    /** A request condition does not match the current resource. */
    ucall_http_status_precondition_failed_k = 412,

    /** Request body is too large. */
    ucall_http_status_payload_too_large_k = 413,

    /** A requested byte range starts or ends past the end of the resource. */
    ucall_http_status_range_not_satisfiable_k = 416,

    /** Rate limit exceeded. */
    ucall_http_status_too_many_requests_k = 429,

    /** Unhandled failure inside an endpoint. */
    ucall_http_status_internal_error_k = 500,

    /** Verb or feature not supported. */
    ucall_http_status_not_implemented_k = 501,

    /** An upstream answered with something no HTTP peer would send. */
    ucall_http_status_bad_gateway_k = 502,

    /** Server is overloaded or shutting down. */
    ucall_http_status_service_unavailable_k = 503,

    /** Upstream dependency timed out. */
    ucall_http_status_gateway_timeout_k = 504,

    /** Request names an HTTP version the server does not speak. */
    ucall_http_status_version_not_supported_k = 505,
};

/** Severity of a log line, from the most verbose up. */
typedef enum ucall_log_level_t {

    /** Detail for debugging. */
    ucall_log_level_debug_k,

    /** Normal lifecycle events. */
    ucall_log_level_info_k,

    /** Something unexpected that the library recovered from. */
    ucall_log_level_warning_k,

    /** An operation failed. */
    ucall_log_level_error_k,

    /** The server or client cannot continue. */
    ucall_log_level_fatal_k
} ucall_log_level_t;

/** Shape of each log line. */
typedef enum ucall_log_format_t {

    /** Human-readable unit-normalized lines. */
    ucall_log_format_human_k,

    /** Newline-delimited JSONs documents. */
    ucall_log_format_json_k,
} ucall_log_format_t;

/**
 *  @brief Receives one formatted log line, without a trailing newline.
 *  @param[in] level Severity of the line.
 *  @param[in] line The formatted line. Valid only for the duration of the call.
 *  @param[in] context User-supplied context from @c ucall_log_t.
 *
 *  Called on whichever thread produced the line, including application polling threads.
 *  The callback must be thread-safe and return quickly.
 */
typedef void (*ucall_log_callback_t)(ucall_log_level_t level, ucall_bytes_view_t line, void* context);

/** The single log sink of a client or a server.
 *
 *  UCall writes nothing anywhere on its own: every line goes to @c callback, and without one the
 *  library stays silent. */
typedef struct ucall_log_t {

    /** Receives every line at or above @c level. Default: NULL, logging nothing. */
    ucall_log_callback_t callback;

    /** Passed verbatim to @c callback. */
    void* context;

    /** Line format. Default: ucall_log_format_human_k. */
    ucall_log_format_t format;

    /** Lines below this severity are never formatted. Default: ucall_log_level_debug_k. */
    ucall_log_level_t level;

} ucall_log_t;

/**
 *  @brief Returns the canonical lowercase, dash-separated spelling of a status, as @c
 *      ucall_status_out_of_memory_k spells "out-of-memory".
 *  @param[in] status The status code to name.
 *  @return A @c NULL -terminated string with static storage duration. Never @c NULL.
 *
 *  @note @b Thread-safe.
 */
UCALL_EXPORT char const* ucall_status_name(ucall_status_t status);

/**
 *  @brief Reads a status back from its canonical spelling.
 *  @param[in] name The counted spelling @c ucall_status_name() returns.
 *  @return The named status.
 *
 *  @note @b Thread-safe.
 *
 *  @par Statuses:
 *  - @c ucall_status_invalid_argument_k An unrecognized name.
 */
UCALL_EXPORT ucall_status_t ucall_status_from_name(ucall_bytes_view_t name);

/** Which part of a URL @c ucall_decode_percent() reads, as only a query spells a space '+'. */
typedef enum ucall_percent_mode_t {

    /** A path, where '+' stays itself. */
    ucall_percent_path_k = 0,

    /** A query, where '+' is a space. */
    ucall_percent_query_k = 1
} ucall_percent_mode_t;

/**
 *  @brief Decodes the %XX escapes of @p encoded, and '+' as a space in query mode.
 *  @param[in] encoded A path or a query value, as a request lends it.
 *  @param[out] decoded At least @c encoded.length bytes; may alias @c encoded.data.
 *  @param[out] length The decoded length.
 *  @param[in] mode Whether a '+' is itself or a space.
 *  @return The decoding's status.
 *
 *  @note @b Thread-safe.
 *
 *  @par Statuses:
 *  - @c ucall_status_invalid_argument_k A '%' without two hexadecimal digits, an unknown @p mode,
 *    or a missing @p length, @p decoded or @c encoded.data while @c encoded.length is not zero.
 */
UCALL_EXPORT ucall_status_t ucall_decode_percent(ucall_bytes_view_t encoded, ucall_byte_t* decoded, size_t* length,
                                                 ucall_percent_mode_t mode);

/**
 *  @brief Reports the version of the linked library, which may differ from @c UCALL_VERSION_* in
 *      the header.
 *  @param[out] major Output for the major version.
 *  @param[out] minor Output for the minor version.
 *  @param[out] patch Output for the patch version.
 */
UCALL_EXPORT void ucall_version(int* major, int* minor, int* patch);

/** The linked library's version, including a release-candidate suffix, in static storage. */
UCALL_EXPORT char const* ucall_version_name(void);

#ifdef __cplusplus
}
#endif

#endif // UNUM_UCALL_TYPES_H
