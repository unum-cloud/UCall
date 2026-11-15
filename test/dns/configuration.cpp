/**
 *  @file test/dns/configuration.cpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief Tests for how the stub resolver reads <tt>resolv.conf</tt> and the hosts file.
 */
#include "ucall/dns/configuration.hpp" // `parse_resolv_conf`, `find_host`
#include "harness.hpp"                 // `expect`, `require`

namespace unum::ucall::test::dns {

using namespace unum::ucall::dns;

static std::size_t test_dns_configuration() {
    std::size_t failures = 0;
    {
        resolver_options_t options {};
        parse_resolv_conf("# comment\n"                                                 //
                          "nameserver 10.0.0.1\n"                                       //
                          "nameserver fe80::1%7\n"                                      //
                          "domain first.example\n"                                      //
                          "search svc.cluster.local cluster.local ; trailing comment\n" //
                          "nameserver 10.0.0.3\n"                                       //
                          "nameserver 10.0.0.4\n"                                       //
                          "options ndots:5 timeout:1 attempts:9 rotate\n",
                          options);
        failures += expect(options.nameservers_count == 3, "{} nameservers kept", options.nameservers_count);
        auto const& scoped = reinterpret_cast<sockaddr_in6 const&>(options.nameservers[1]);
        failures += expect(scoped.sin6_family == AF_INET6 && scoped.sin6_scope_id == 7 && ntohs(scoped.sin6_port) == 53,
                           "the scoped IPv6 nameserver was not read");
        std::string_view const search {options.search, options.search_length};
        failures += expect(search == std::string_view("svc.cluster.local\0cluster.local\0", 32),
                           "the search list reads `{}`", search);
        failures += expect(options.ndots == 5 && options.timeout_seconds == 1 && options.attempts == 5,
                           "options read ndots {} timeout {} attempts {}", options.ndots, options.timeout_seconds,
                           options.attempts);
    }

    {
        std::string_view const hosts = "127.0.0.1 localhost\n"                    //
                                       "::1 localhost ip6-localhost # loopback\n" //
                                       "# 10.0.0.9 commented.example\n"           //
                                       "10.0.0.2\tdb.Internal  db\n";
        byte_t address[16] {};
        failures += expect(find_host(hosts, "DB.internal.", record_type_t::a_k, address) == ucall_status_success_k &&
                               static_cast<unsigned>(address[3]) == 2,
                           "the alias was not found");
        failures += expect(find_host(hosts, "localhost", record_type_t::aaaa_k, address) == ucall_status_success_k &&
                               static_cast<unsigned>(address[15]) == 1,
                           "the IPv6 line was not found");
        failures += expect(
            find_host(hosts, "commented.example", record_type_t::a_k, address) == ucall_status_not_found_k,
            "a commented line matched");
        failures += expect(find_host(hosts, "db", record_type_t::aaaa_k, address) == ucall_status_not_found_k,
                           "an IPv4 line answered AAAA");
    }
    return failures;
}

std::size_t check_dns_configuration(settings_t const& settings) {
    if (!settings.filter.selects("dns configuration")) return 0;
    return report("dns configuration", test_dns_configuration());
}

} // namespace unum::ucall::test::dns
