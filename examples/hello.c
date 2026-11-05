/**
 *  @file examples/hello.c
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief The C quickstart: an echo server on loopback port 8080 over the C ABI.
 */
#include <stdio.h>

#include "ucall/ucall.h"

static void echo(ucall_received_http_request_t request, void* context) {
    ucall_server_t server = *(ucall_server_t*)context;
    ucall_outcome_t outcome = {0};
    ucall_bytes_view_t body = {0};
    ucall_server_request_body_t read = {.server = server, .outcome = &outcome, .request = request, .body = &body};
    ucall_server_request_body(&read);
    ucall_server_reply_content_t reply = {.server = server, .outcome = &outcome, .request = request, .body = body};
    ucall_server_reply_content(&reply);
}

int main(void) {
    ucall_network_interface_t listener = {
        .address = {(ucall_byte_t const*)"127.0.0.1:8080", 14},
        .max_concurrent_connections = 1024,
    };
    ucall_server_options_t options = {.interfaces = &listener, .interfaces_count = 1};
    ucall_server_t server = NULL;
    ucall_outcome_t outcome = {0};
    ucall_server_init_t init = {.server = &server, .outcome = &outcome, .options = &options};
    ucall_server_init(&init);
    if (outcome.status != ucall_status_success_k) {
        fprintf(stderr, "%s\n", outcome.message);
        return 1;
    }

    ucall_server_add_http_endpoint_t route = {.server = server,
                                              .outcome = &outcome,
                                              .uri_template = {(ucall_byte_t const*)"/echo", 5},
                                              .verb = ucall_verb_post_k,
                                              .callback = echo,
                                              .context = &server};
    ucall_server_add_http_endpoint(&route);
    ucall_server_take_calls_t poll = {.server = server, .outcome = &outcome};
    ucall_server_take_calls(&poll);
    ucall_server_free(server);
    return outcome.status == ucall_status_success_k ? 0 : 1;
}
