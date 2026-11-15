/**
 *  @file test/header_only.cpp
 *  @author Ash Vardanian
 *  @date November 12, 2026
 *  @brief The parser and tunnel suite's entry point: HTTP messages, routes, percent codec and
 *      multipart, DNS messages and configuration, and the tunnel's crypto and records.
 */
#include "harness.hpp"

using namespace unum::ucall::test;

int main(int argc, char** argv) {
    install_test_signal_handlers();
    test_settings = read_settings(argc, argv, "ucall_test_header_only");
    settings_t const& settings = test_settings;
    fmt::println("- Seed: {}, multiplier: {:.2f}, filter: {}", settings.seed, settings.multiplier,
                 settings.filter.pattern.empty() ? "none" : settings.filter.pattern);
    std::size_t failures_count = 0;
    failures_count += http::check_http_messages(settings);
    failures_count += http::check_routes(settings);
    failures_count += http::check_percent(settings);
    failures_count += http::check_multipart(settings);
    failures_count += dns::check_dns_messages(settings);
    failures_count += dns::check_dns_configuration(settings);
    failures_count += tunnel::check_crypto(settings);
    failures_count += tunnel::check_secure_tunnel(settings);
    return report("total", failures_count) ? 1 : 0;
}
