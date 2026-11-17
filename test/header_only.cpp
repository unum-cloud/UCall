/**
 *  @file test/header_only.cpp
 *  @author Ash Vardanian
 *  @date November 12, 2026
 *  @brief The parser and tunnel suite's entry point: HTTP messages, routes, percent codec and
 *      multipart, DNS messages and configuration, and the tunnel's crypto and records.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build
#include "harness.hpp"

using namespace unum::ucall::test;

int main(int argc, char** argv) {
    start_test_run(argc, argv);
    http::run_http_messages_cases();
    http::run_routes_cases();
    http::run_percent_cases();
    http::run_multipart_cases();
    dns::run_dns_messages_cases();
    dns::run_dns_configuration_cases();
    tunnel::run_crypto_cases();
    tunnel::run_secure_tunnel_cases();
    return finish_test_run();
}
