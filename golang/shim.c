/**
 *  @file golang/shim.c
 *  @author Ash Vardanian
 *  @date November 18, 2026
 *  @brief The addresses of the Go-side trampolines, taken where C can take them.
 */
#include <shim.h>

ucall_received_http_request_callback_t ucall_go_serves(void) { return &ucallServes; }

static void ucall_go_batch(ucall_server_t server, ucall_received_http_request_t const* requests, size_t count,
                           void* context) {
    ucallBatches(server, (ucall_received_http_request_t*)requests, count, context);
}

ucall_received_http_batch_callback_t ucall_go_batches(void) { return &ucall_go_batch; }

ucall_log_callback_t ucall_go_logs(void) { return &ucallLogs; }

static ucall_status_t ucall_go_authorize(ucall_noise_key_t const* key, void* context) {
    return ucallAuthorizes((void*)key, context);
}

ucall_peer_authorizer_t ucall_go_authorizes(void) { return &ucall_go_authorize; }

void* ucall_go_context(uintptr_t handle) { return (void*)handle; }
