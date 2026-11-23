/**
 *  @file examples/hello.c
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief The C quickstart: a server and a client bound to its event loop, greeting on one thread.
 */
#include <stdio.h>
#include <string.h>

#include "ucall/ucall.h"

static int failed(ucall_outcome_t const* outcome) {
    if (outcome->status == ucall_status_success_k) return 0;
    fprintf(stderr, "%s: %s\n", ucall_status_name(outcome->status), outcome->message);
    return 1;
}

static void hello(ucall_server_t server, ucall_received_http_request_t request, void* context) {
    char const* greeting = (char const*)context;
    ucall_outcome_t outcome = {0};
    ucall_bytes_view_t name = {0};
    ucall_server_request_path_parameter_t parameter = {.server = server,
                                                       .outcome = &outcome,
                                                       .request = request,
                                                       .name = {(ucall_byte_t const*)"name", 4},
                                                       .value = &name};
    ucall_server_request_path_parameter(&parameter);
    ucall_reply_part_t parts[2] = {
        {.kind = ucall_reply_part_bytes_k, .data.bytes = {(ucall_byte_t const*)greeting, strlen(greeting)}},
        {.kind = ucall_reply_part_bytes_k, .data.bytes = name}};
    ucall_server_reply_vectored_t reply = {.server = server,
                                           .outcome = &outcome,
                                           .request = &request,
                                           .parts = parts,
                                           .parts_count = 2};
    ucall_server_reply_vectored(&reply);
}

static char greeting[] = "Hello, ";

int main(void) {
    ucall_network_interface_t listener = {.address = {(ucall_byte_t const*)"127.0.0.1:0", 11},
                                          .max_concurrent_connections = 1};
    ucall_server_options_t options = {.interfaces = &listener, .interfaces_count = 1}, resolved = {0};
    ucall_server_t server = NULL;
    ucall_outcome_t outcome = {0};
    ucall_server_init_t init = {.server = &server, .outcome = &outcome, .options = &options, .resolved = &resolved};
    ucall_server_init(&init);
    if (failed(&outcome)) return 1;
    ucall_server_add_http_endpoint_t route = {.server = server,
                                              .outcome = &outcome,
                                              .uri_template = {(ucall_byte_t const*)"/hello/{name}", 13},
                                              .verb = ucall_verb_get_k,
                                              .callback = hello,
                                              .context = greeting};
    ucall_server_add_http_endpoint(&route);
    if (failed(&outcome)) return 1;

    // A client bound to the server's event loop advances whenever that loop is polled.
    ucall_client_options_t client_options = {.max_concurrent_connections = 1, .server = server};
    ucall_client_t client = NULL;
    ucall_client_init_t client_init = {.client = &client, .outcome = &outcome, .options = &client_options};
    ucall_client_init(&client_init);
    if (failed(&outcome)) return 1;
    char url[128];
    ucall_bytes_view_t address = resolved.interfaces[0].address;
    snprintf(url, sizeof url, "http://%.*s/hello/world", (int)address.length, (char const*)address.data);
    ucall_client_call_t call = {.client = client,
                                .outcome = &outcome,
                                .url = {(ucall_byte_t const*)url, strlen(url)},
                                .verb = ucall_verb_get_k};
    ucall_client_call(&call);
    if (failed(&outcome)) return 1;

    ucall_completed_call_t completed = {0};
    ucall_server_take_call_t poll = {.server = server, .outcome = &outcome, .timeout_microseconds = 1000};
    ucall_client_take_completed_call_t take = {.client = client, .outcome = &outcome, .call = &completed};
    do {
        ucall_server_take_call(&poll);
        if (failed(&outcome)) return 1;
        ucall_client_take_completed_call(&take);
    } while (outcome.status == ucall_status_would_block_k);
    if (failed(&outcome) || failed(&completed.outcome)) return 1;
    ucall_bytes_view_t body = {0};
    ucall_client_response_body_t body_read = {.response = completed.response, .outcome = &outcome, .body = &body};
    ucall_client_response_body(&body_read);
    printf("%.*s\n", (int)body.length, (char const*)body.data);
    int greeted = body.length == 12 && memcmp(body.data, "Hello, world", 12) == 0;

    ucall_client_response_free(completed.response);
    ucall_client_free(client);
    ucall_server_stop(server);
    ucall_server_free(server);
    return greeted ? 0 : 1;
}
