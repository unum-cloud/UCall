/**
 *  @file golang/shim.h
 *  @author Ash Vardanian
 *  @date November 18, 2026
 *  @brief Declarations the Go binding needs and the C header cannot give it: the Go-side
 *      trampolines that routes, batch endpoints, log sinks and peer authorizers install.
 *
 *  The definitions live in @c shim.c because a Go file carrying an @c //export directive may hold
 *  only declarations in its preamble.
 */
#ifndef UNUM_UCALL_GO_SHIM_H
#define UNUM_UCALL_GO_SHIM_H

#include <stdint.h> // `uintptr_t`

#include "ucall/ucall.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  @brief The callbacks Go defines and C calls - the symbols here that cross in that direction,
 *      which is why they alone wear Go's spelling.
 *
 *  cgo emits a C symbol named exactly as the Go function, and Go spells an unexported function
 *  in camel case, so the names are not this file's to choose. cgo also drops @c const from the
 *  pointers it declares, so the batch and the authorizer reach C through adapters in @c shim.c.
 */
void ucallServes(ucall_server_t server, ucall_received_http_request_t request, void* context);
void ucallBatches(ucall_server_t server, ucall_received_http_request_t* requests, size_t count, void* context);
void ucallLogs(ucall_log_level_t level, ucall_bytes_view_t line, void* context);
ucall_status_t ucallAuthorizes(void* key, void* context);

/** Hands back the trampolines above as function pointers. cgo renders a C function as a Go
 *  wrapper rather than an address, so the pointers have to be taken on this side. */
ucall_received_http_request_callback_t ucall_go_serves(void);
ucall_received_http_batch_callback_t ucall_go_batches(void);
ucall_log_callback_t ucall_go_logs(void);
ucall_peer_authorizer_t ucall_go_authorizes(void);

/** Passes a handle as a callback's opaque context, which Go may not spell as a pointer. */
void* ucall_go_context(uintptr_t handle);

/** Passes a pinned key, or @c NULL, as the key pointer a field takes, whose Go spelling differs
 *  between the platforms cgo runs on. */
ucall_noise_key_t const* ucall_go_key(void* key);

#ifdef __cplusplus
}
#endif

#endif // UNUM_UCALL_GO_SHIM_H
