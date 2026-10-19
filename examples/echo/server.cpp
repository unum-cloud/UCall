/**
 *  @file examples/echo/server.cpp
 *  @author Ash Vardanian
 *  @date May 13, 2024
 *  @brief Binary HTTP echo service for transport benchmarks.
 */
#include <cstdio>
#include <cstring>

#include "../server.hpp"

static ucall_bytes_view_t view(char const* text) {
    return {reinterpret_cast<ucall_byte_t const*>(text), std::strlen(text)};
}

static void echo(ucall_received_http_request_t request, void* context) {
    auto server = *static_cast<ucall_server_t*>(context);
    ucall_outcome_t outcome {};
    ucall_bytes_view_t body {};
    ucall_server_request_body_t extract {server, &outcome, request, &body};
    ucall_server_request_body(&extract);
    ucall_server_reply_content_t reply {server, &outcome, request, nullptr, 0, body};
    ucall_server_reply_content(&reply);
}

static void echo_batch(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
    for (std::size_t i = 0; i != count; ++i) echo(requests[i], context);
}

static void health(ucall_received_http_request_t request, void* context) {
    auto server = *static_cast<ucall_server_t*>(context);
    ucall_outcome_t outcome {};
    ucall_server_reply_content_t reply {server, &outcome, request, nullptr, 0, view("ready\n")};
    ucall_server_reply_content(&reply);
}

int main(int argc, char** argv) {
    examples::server_t application {};
    if (auto result = application.init(argc, argv)) return result < 0 ? 1 : 0;
    ucall_outcome_t outcome {};
    ucall_server_add_http_endpoint_t add {application.server, &outcome, view("/echo"),
                                          ucall_verb_post_k,  echo,     &application.server};
    ucall_server_add_http_endpoint(&add);
    if (!application.succeeded(outcome)) return 1;
    add.uri_template = view("/health");
    add.verb = ucall_verb_get_k;
    add.callback = health;
    ucall_server_add_http_endpoint(&add);
    if (!application.succeeded(outcome)) return 1;
    ucall_server_add_batch_endpoint_t batch {};
    batch.server = application.server;
    batch.outcome = &outcome;
    batch.uri_template = view("/echo/batch");
    batch.verb = ucall_verb_post_k;
    batch.callback = echo_batch;
    batch.context = &application.server;
    ucall_server_add_batch_endpoint(&batch);
    return application.succeeded(outcome) ? application.run() : 1;
}
