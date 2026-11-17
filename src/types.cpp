/**
 *  @file src/types.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Status, backend and CPU class names, and the linked version.
 */
#include <cstddef> // `std::size_t`

#include <string_view> // `std::string_view`

#include "ucall/types.h"

#include "lib.hpp" // `cpu_classes_k`

using namespace unum::ucall;

static bool named(std::string_view spelling, ucall_bytes_view_t name) noexcept { return spelling == text_view(name); }

/** Writes the entry of @p values that @p name_of spells as @p name into @p value, else nothing. */
template <typename value_type_, std::size_t count_>
static ucall_status_t read_name(ucall_bytes_view_t name, value_type_ const (&values)[count_],
                                char const* (*name_of)(value_type_), value_type_* value) noexcept {
    for (value_type_ const candidate : values)
        if (named(name_of(candidate), name)) return *value = candidate, ucall_status_success_k;
    return ucall_status_invalid_argument_k;
}

/** Every status the C enum names. */
constexpr ucall_status_t statuses_k[] {
    ucall_status_success_k,           ucall_status_deferred_k,
    ucall_status_out_of_memory_k,     ucall_status_io_k,
    ucall_status_malformed_k,         ucall_status_internal_k,
    ucall_status_overflow_k,          ucall_status_uninitialized_k,
    ucall_status_contended_k,         ucall_status_unsupported_k,
    ucall_status_invalid_argument_k,  ucall_status_not_found_k,
    ucall_status_already_exists_k,    ucall_status_connection_failed_k,
    ucall_status_connection_closed_k, ucall_status_timeout_k,
    ucall_status_handshake_failed_k,  ucall_status_peer_rejected_k,
    ucall_status_would_block_k,
};

/** Every I/O backend the C enum names, "automatic" first. */
constexpr ucall_io_backend_t backends_k[] {
    ucall_io_backend_automatic_k,      ucall_io_backend_posix_k,          ucall_io_backend_linux_epollaio_k,
    ucall_io_backend_linux_uring612_k, ucall_io_backend_linux_uring618_k, ucall_io_backend_bsd_kqueue_k,
    ucall_io_backend_windows_iocp_k,   ucall_io_backend_windows_rio_k,
};

extern "C" {

char const* ucall_status_name(ucall_status_t status) {
    switch (status) {
    case ucall_status_success_k: return "success";
    case ucall_status_deferred_k: return "deferred";
    case ucall_status_out_of_memory_k: return "out-of-memory";
    case ucall_status_io_k: return "io";
    case ucall_status_malformed_k: return "malformed";
    case ucall_status_internal_k: return "internal";
    case ucall_status_overflow_k: return "overflow";
    case ucall_status_uninitialized_k: return "uninitialized";
    case ucall_status_contended_k: return "contended";
    case ucall_status_unsupported_k: return "unsupported";
    case ucall_status_invalid_argument_k: return "invalid-argument";
    case ucall_status_not_found_k: return "not-found";
    case ucall_status_already_exists_k: return "already-exists";
    case ucall_status_connection_failed_k: return "connection-failed";
    case ucall_status_connection_closed_k: return "connection-closed";
    case ucall_status_timeout_k: return "timeout";
    case ucall_status_handshake_failed_k: return "handshake-failed";
    case ucall_status_peer_rejected_k: return "peer-rejected";
    case ucall_status_would_block_k: return "would-block";
    default: return "unrecognized";
    }
}

ucall_status_t ucall_status_from_name(ucall_bytes_view_t name, ucall_status_t* status) {
    return read_name(name, statuses_k, ucall_status_name, status);
}

char const* ucall_io_backend_name(ucall_io_backend_t backend) {
    switch (backend) {
    case ucall_io_backend_automatic_k: return "automatic";
    case ucall_io_backend_posix_k: return "posix";
    case ucall_io_backend_linux_epollaio_k: return "linux-epollaio";
    case ucall_io_backend_linux_uring612_k: return "linux-uring612";
    case ucall_io_backend_linux_uring618_k: return "linux-uring618";
    case ucall_io_backend_bsd_kqueue_k: return "bsd-kqueue";
    case ucall_io_backend_windows_iocp_k: return "windows-iocp";
    case ucall_io_backend_windows_rio_k: return "windows-rio";
    }
    return "unrecognized";
}

char const* ucall_cpu_class_name(ucall_cpu_class_t cpu_class) {
    switch (cpu_class) {
    case ucall_cpu_class_unknown_k: return "unknown";
    case ucall_cpu_class_serial_k: return "serial";
    case ucall_cpu_class_monoversioned_k: return "monoversioned";
    case ucall_cpu_class_intel_haswell_k: return "intel-haswell";
    case ucall_cpu_class_intel_skylake_k: return "intel-skylake";
    case ucall_cpu_class_intel_icelake_k: return "intel-icelake";
    case ucall_cpu_class_intel_alder_k: return "intel-alder";
    case ucall_cpu_class_aws_g2_k: return "aws-g2";
    case ucall_cpu_class_apple_m4_k: return "apple-m4";
    case ucall_cpu_class_aws_g5_k: return "aws-g5";
    case ucall_cpu_class_alibaba_c930_k: return "alibaba-c930";
    case ucall_cpu_class_ibm_power10_k: return "ibm-power10";
    }
    return "unrecognized";
}

ucall_status_t ucall_io_backend_from_name(ucall_bytes_view_t name, ucall_io_backend_t* backend) {
    return read_name(name, backends_k, ucall_io_backend_name, backend);
}

ucall_status_t ucall_cpu_class_from_name(ucall_bytes_view_t name, ucall_cpu_class_t* cpu_class) {
    if (named(ucall_cpu_class_name(ucall_cpu_class_unknown_k), name))
        return *cpu_class = ucall_cpu_class_unknown_k, ucall_status_success_k;
    return read_name(name, cpu_classes_k, ucall_cpu_class_name, cpu_class);
}

void ucall_version(int* major, int* minor, int* patch) {
    *major = UCALL_VERSION_MAJOR;
    *minor = UCALL_VERSION_MINOR;
    *patch = UCALL_VERSION_PATCH;
}

char const* ucall_version_name(void) { return UCALL_VERSION_NAME; }
}
