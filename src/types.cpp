/**
 *  @file src/types.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Status names, outcome synchronization, and the version of the linked library.
 */
#include <cstddef> // `std::size_t`

#include <atomic>      // `std::atomic_ref`
#include <string_view> // `std::string_view`

#include "ucall/types.h"

extern "C" {

ucall_status_t ucall_outcome_status(ucall_outcome_t* outcome) {
    return std::atomic_ref<ucall_status_t> {outcome->status}.load(std::memory_order_acquire);
}

ucall_status_t ucall_outcome_wait(ucall_outcome_t* outcome) {
    std::atomic_ref<ucall_status_t> const word {outcome->status};
    for (;;) {
        ucall_status_t const seen = word.load(std::memory_order_acquire);
        if (seen != ucall_status_deferred_k) return seen;
        word.wait(seen, std::memory_order_acquire);
    }
}

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

ucall_status_t ucall_status_from_name(ucall_bytes_view_t name) {
    if (!name.data || !name.length) return ucall_status_invalid_argument_k;
    std::string_view const text {reinterpret_cast<char const*>(name.data), name.length};
    ucall_status_t const statuses[] = {ucall_status_success_k,           ucall_status_deferred_k,
                                       ucall_status_out_of_memory_k,     ucall_status_io_k,
                                       ucall_status_malformed_k,         ucall_status_internal_k,
                                       ucall_status_overflow_k,          ucall_status_uninitialized_k,
                                       ucall_status_contended_k,         ucall_status_unsupported_k,
                                       ucall_status_invalid_argument_k,  ucall_status_not_found_k,
                                       ucall_status_already_exists_k,    ucall_status_connection_failed_k,
                                       ucall_status_connection_closed_k, ucall_status_timeout_k,
                                       ucall_status_handshake_failed_k,  ucall_status_peer_rejected_k,
                                       ucall_status_would_block_k};
    for (ucall_status_t status : statuses) {
        if (std::string_view {ucall_status_name(status)} == text) return status;
    }
    return ucall_status_invalid_argument_k;
}

void ucall_version(int* major, int* minor, int* patch) {
    *major = UCALL_VERSION_MAJOR;
    *minor = UCALL_VERSION_MINOR;
    *patch = UCALL_VERSION_PATCH;
}

char const* ucall_version_name(void) { return UCALL_VERSION_NAME; }
}
