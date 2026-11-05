/**
 *  @file test/dns.cpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief Tests for the stub resolver's query codec, and for how it reads <tt>resolv.conf</tt>
 *      and the hosts file.
 *
 *  Every hostile case is a packet a nameserver, or anyone spoofing one, could send: each must be
 *  refused as malformed without reading past its end, never decoded into an address.
 */
#include <cstdint> // `std::uint8_t`

#include <vector> // `std::vector`

#include "ucall/dns/configuration.hpp" // `parse_resolv_conf`, `find_host`
#include "ucall/dns/messages.hpp"      // `compose_query`, `decode_answer`
#include "harness.hpp"                 // `expect`, `require`, `run_test`
#include "properties.hpp"              // `check_dns_answer`

using namespace unum::ucall;
using namespace unum::ucall::dns;
using namespace unum::ucall::test;

#pragma region Fixtures

/** Writes a packet field by field, so each case reads as the answer it describes. */
struct packet_t {
    std::vector<std::uint8_t> bytes;

    packet_t& u16(unsigned value) {
        bytes.push_back(static_cast<std::uint8_t>(value >> 8)), bytes.push_back(static_cast<std::uint8_t>(value));
        return *this;
    }
    packet_t& u32(std::uint32_t value) { return u16(value >> 16).u16(value & 0xFFFF); }
    packet_t& raw(std::initializer_list<std::uint8_t> values) {
        bytes.insert(bytes.end(), values);
        return *this;
    }
    packet_t& name(std::string_view dotted) {
        while (!dotted.empty()) {
            auto const dot = dotted.find('.');
            auto const label = dotted.substr(0, dot);
            bytes.push_back(static_cast<std::uint8_t>(label.size()));
            bytes.insert(bytes.end(), label.begin(), label.end());
            dotted.remove_prefix(dot == std::string_view::npos ? dotted.size() : dot + 1);
        }
        bytes.push_back(0);
        return *this;
    }
    packet_t& pointer(std::size_t offset) {
        return raw({static_cast<std::uint8_t>(0xC0 | offset >> 8), static_cast<std::uint8_t>(offset)});
    }

    /** A response header: QR and RD set, RA too, with @p code and the four counts. */
    packet_t& header(unsigned id, unsigned code, unsigned answers, unsigned authorities, unsigned flags = 0x8180) {
        return u16(id).u16(flags | code).u16(1).u16(answers).u16(authorities).u16(0);
    }
    packet_t& question(std::string_view dotted, record_type_t type) {
        return name(dotted).u16(static_cast<unsigned>(type)).u16(1);
    }
    span<byte_t const> view() const { return {reinterpret_cast<byte_t const*>(bytes.data()), bytes.size()}; }
};

/** The question at offset 12 of every fixture packet, which answers compress against. */
constexpr std::size_t question_offset_k = 12;

wire_name_t spelled(std::string_view name) {
    wire_name_t wire {};
    [[maybe_unused]] bool const spelt = spell_name(name, wire);
    return wire;
}

#pragma endregion Fixtures

case_result_t test_dns_queries_unit() {
    std::size_t failures = 0;
    announce("a_query_spells_lowercased_labels");
    byte_t query[query_bytes_k] {};
    std::size_t const length = compose_query(query, 0xBEEF, spelled("Example.COM."), record_type_t::aaaa_k);
    packet_t expected;
    expected.u16(0xBEEF).u16(0x0100).u16(1).u16(0).u16(0).u16(0).question("example.com", record_type_t::aaaa_k);
    failures += expect(length == expected.bytes.size() && std::memcmp(query, expected.bytes.data(), length) == 0,
                       "a query of {} bytes differs from the expected {}", length, expected.bytes.size());

    announce("unspellable_names_are_refused");
    wire_name_t wire {};
    failures += expect(!spell_name("", wire) && !spell_name(".", wire) && !spell_name("a..b", wire),
                       "an empty name or label was spelled");
    failures += expect(!spell_name(std::string(64, 'a'), wire), "a 64-byte label was spelled");
    std::string longest;
    for (int label = 0; label != 64; ++label) longest += "abc.";
    failures += expect(!spell_name(longest, wire), "a name over 255 bytes was spelled");
    return failures;
}

case_result_t test_dns_answers_unit() {
    std::size_t failures = 0;
    byte_t addresses[64] {};

    announce("a_cname_chain_ends_in_addresses_at_its_least_ttl");
    {
        // www.example.com → edge.cdn → origin.cdn, then two addresses.
        packet_t packet;
        packet.header(7, 0, 4, 0).question("www.example.com", record_type_t::a_k);
        packet.pointer(question_offset_k).u16(5).u16(1).u32(300).u16(10).name("edge.cdn");
        std::size_t const edge_name = packet.bytes.size() - 10;
        packet.pointer(edge_name)
            .u16(5)
            .u16(1)
            .u32(60)
            .u16(9)
            .raw({6})
            .raw({'o', 'r', 'i', 'g', 'i', 'n'})
            .pointer(edge_name + 5);
        std::size_t const origin_name = packet.bytes.size() - 9;
        packet.pointer(origin_name).u16(1).u16(1).u32(120).u16(4).raw({192, 0, 2, 1});
        packet.pointer(origin_name).u16(1).u16(1).u32(90).u16(4).raw({192, 0, 2, 2});
        auto const decoded = decode_answer(packet.view(), 7, spelled("www.example.com"), record_type_t::a_k, addresses);
        failures += expect(decoded.answer == answer_t::addresses_k && decoded.addresses_count == 2,
                           "the chain answered {} with {} addresses", static_cast<int>(decoded.answer),
                           decoded.addresses_count);
        failures += expect(decoded.ttl_seconds == 60, "the chain's ttl is {}, not the least 60", decoded.ttl_seconds);
        failures += expect(static_cast<unsigned>(addresses[3]) == 1 && static_cast<unsigned>(addresses[7]) == 2,
                           "the addresses were not copied in order");
    }

    announce("records_of_other_owners_are_ignored");
    {
        packet_t packet;
        packet.header(1, 0, 1, 0).question("a.example", record_type_t::a_k);
        packet.name("b.example").u16(1).u16(1).u32(30).u16(4).raw({10, 0, 0, 1});
        auto const decoded = decode_answer(packet.view(), 1, spelled("a.example"), record_type_t::a_k, addresses);
        failures += expect(decoded.answer == answer_t::empty_k, "another owner's address was taken");
    }

    announce("nxdomain_caches_for_the_least_of_soa_ttl_and_minimum");
    {
        packet_t packet;
        packet.header(2, 3, 0, 1).question("missing.example", record_type_t::aaaa_k);
        packet.name("example").u16(6).u16(1).u32(900).u16(0);
        std::size_t const length_at = packet.bytes.size() - 2;
        std::size_t const rdata = packet.bytes.size();
        packet.name("ns.example").name("admin.example").u32(1).u32(2).u32(3).u32(4).u32(45);
        std::size_t const rdlength = packet.bytes.size() - rdata;
        packet.bytes[length_at] = static_cast<std::uint8_t>(rdlength >> 8);
        packet.bytes[length_at + 1] = static_cast<std::uint8_t>(rdlength);
        auto const decoded = decode_answer(packet.view(), 2, spelled("missing.example"), record_type_t::aaaa_k,
                                           addresses);
        failures += expect(decoded.answer == answer_t::absent_k && decoded.ttl_seconds == 45,
                           "NXDOMAIN answered {} for {} s", static_cast<int>(decoded.answer), decoded.ttl_seconds);
    }

    announce("a_ttl_with_its_top_bit_reads_as_zero");
    {
        packet_t packet;
        packet.header(3, 0, 1, 0).question("a.example", record_type_t::a_k);
        packet.pointer(question_offset_k).u16(1).u16(1).u32(0x80000010u).u16(4).raw({10, 0, 0, 1});
        auto const decoded = decode_answer(packet.view(), 3, spelled("a.example"), record_type_t::a_k, addresses);
        failures += expect(decoded.answer == answer_t::addresses_k && decoded.ttl_seconds == 0,
                           "a negative ttl read as {}", decoded.ttl_seconds);
    }

    announce("truncation_and_server_failure_are_reported");
    {
        packet_t packet;
        packet.header(4, 0, 0, 0, 0x8380).question("a.example", record_type_t::a_k);
        failures += expect(
            decode_answer(packet.view(), 4, spelled("a.example"), record_type_t::a_k, addresses).answer ==
                answer_t::truncated_k,
            "a truncated answer was not reported");
        packet_t failed;
        failed.header(5, 2, 0, 0).question("a.example", record_type_t::a_k);
        failures += expect(
            decode_answer(failed.view(), 5, spelled("a.example"), record_type_t::a_k, addresses).answer ==
                answer_t::failed_k,
            "SERVFAIL was not reported as failed");
    }
    return failures;
}

case_result_t test_dns_answers_safety() {
    std::size_t failures = 0;
    byte_t addresses[64] {};
    auto const refused = [&](packet_t const& packet, std::uint16_t id, std::string_view name, record_type_t type) {
        return decode_answer(packet.view(), id, spelled(name), type, addresses).answer == answer_t::malformed_k;
    };

    announce("a_wrong_id_or_question_is_refused");
    {
        packet_t packet;
        packet.header(9, 0, 1, 0).question("a.example", record_type_t::a_k);
        packet.pointer(question_offset_k).u16(1).u16(1).u32(30).u16(4).raw({10, 0, 0, 1});
        failures += expect(refused(packet, 8, "a.example", record_type_t::a_k), "a wrong id was accepted");
        failures += expect(refused(packet, 9, "b.example", record_type_t::a_k), "another name was accepted");
        failures += expect(refused(packet, 9, "a.example", record_type_t::aaaa_k), "another type was accepted");
    }

    announce("pointers_forward_or_at_themselves_are_refused");
    {
        packet_t forward;
        forward.header(1, 0, 1, 0).question("a.example", record_type_t::a_k);
        std::size_t const here = forward.bytes.size();
        forward.pointer(here + 2).u16(1).u16(1).u32(30).u16(4).raw({10, 0, 0, 1});
        failures += expect(refused(forward, 1, "a.example", record_type_t::a_k), "a forward pointer was followed");
        packet_t self;
        self.header(1, 0, 1, 0).question("a.example", record_type_t::a_k);
        self.pointer(self.bytes.size()).u16(1).u16(1).u32(30).u16(4).raw({10, 0, 0, 1});
        failures += expect(refused(self, 1, "a.example", record_type_t::a_k), "a self pointer was followed");
        packet_t outside;
        outside.header(1, 0, 1, 0).question("a.example", record_type_t::a_k).raw({0xC0});
        failures += expect(refused(outside, 1, "a.example", record_type_t::a_k), "a cut pointer was read");
    }

    announce("a_label_loop_through_backward_pointers_stops_at_255_bytes");
    {
        packet_t packet;
        packet.header(1, 0, 1, 0).question("a.example", record_type_t::a_k);
        std::size_t const loop = packet.bytes.size();
        packet.raw({1, 'x'}).pointer(loop).u16(1).u16(1).u32(30).u16(4).raw({10, 0, 0, 1});
        failures += expect(refused(packet, 1, "a.example", record_type_t::a_k), "a pointer loop was decoded");
    }

    announce("lengths_past_the_packet_are_refused");
    {
        packet_t overrun;
        overrun.header(1, 0, 1, 0).question("a.example", record_type_t::a_k);
        overrun.pointer(question_offset_k).u16(1).u16(1).u32(30).u16(40).raw({10, 0, 0, 1});
        failures += expect(refused(overrun, 1, "a.example", record_type_t::a_k), "an RDLENGTH overrun was read");
        packet_t wide;
        wide.header(1, 0, 1, 0).question("a.example", record_type_t::a_k);
        wide.pointer(question_offset_k).u16(1).u16(1).u32(30).u16(5).raw({10, 0, 0, 1, 2});
        failures += expect(refused(wide, 1, "a.example", record_type_t::a_k), "a 5-byte A record was taken");
        packet_t counted;
        counted.header(1, 0, 60000, 0).question("a.example", record_type_t::a_k);
        failures += expect(refused(counted, 1, "a.example", record_type_t::a_k), "an impossible count was walked");
        packet_t label;
        label.header(1, 0, 0, 0).raw({64}).raw({'a'});
        failures += expect(refused(label, 1, "a.example", record_type_t::a_k), "a 64-byte label prefix was read");
    }

    announce("every_cut_of_a_valid_answer_is_refused_without_reading_past_it");
    {
        packet_t packet;
        packet.header(1, 0, 1, 0).question("a.example", record_type_t::a_k);
        packet.pointer(question_offset_k).u16(1).u16(1).u32(30).u16(4).raw({10, 0, 0, 1});
        for (std::size_t cut = 0; cut != packet.bytes.size(); ++cut) {
            std::vector<std::uint8_t> const prefix(packet.bytes.begin(), packet.bytes.begin() + cut);
            auto const decoded = decode_answer({reinterpret_cast<byte_t const*>(prefix.data()), prefix.size()}, 1,
                                               spelled("a.example"), record_type_t::a_k, addresses);
            failures += expect(decoded.answer == answer_t::malformed_k, "a {}-byte prefix decoded", cut);
        }
    }
    return failures;
}

case_result_t test_dns_answers_property(random_generator_t& generator) {
    std::size_t failures = 0;
    announce("mutated_answers_keep_every_decoder_promise");
    packet_t chain;
    chain.header(1, 0, 3, 1).question("a.example", record_type_t::a_k);
    chain.pointer(question_offset_k).u16(5).u16(1).u32(30).u16(5).raw({1, 'b'}).pointer(question_offset_k + 2);
    chain.name("b.example").u16(1).u16(1).u32(30).u16(4).raw({10, 0, 0, 1});
    chain.pointer(question_offset_k)
        .u16(28)
        .u16(1)
        .u32(30)
        .u16(16)
        .raw({0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1});
    chain.name("example")
        .u16(6)
        .u16(1)
        .u32(60)
        .u16(42)
        .name("ns.example")
        .name("me.example")
        .u32(1)
        .u32(2)
        .u32(3)
        .u32(4)
        .u32(5);
    wire_name_t const question = spelled("a.example");
    for (std::size_t iteration = 0; iteration != scale_iterations(4000); ++iteration) {
        std::vector<std::uint8_t> mutated = chain.bytes;
        for (std::size_t edits = 1 + generator.below(4); edits && !mutated.empty(); --edits)
            switch (generator.below(3)) {
            case 0: mutated[generator.below(mutated.size())] = static_cast<std::uint8_t>(generator()); break;
            case 1: mutated.resize(generator.below(mutated.size() + 1)); break;
            default: {
                std::size_t const at = generator.below(mutated.size() + 1);
                mutated.insert(mutated.begin() + static_cast<std::ptrdiff_t>(at), static_cast<std::uint8_t>(0xC0));
            }
            }
        if (mutated.empty()) continue;
        failures += check_dns_answer({reinterpret_cast<byte_t const*>(mutated.data()), mutated.size()}, question);
    }
    return failures;
}

case_result_t test_dns_configuration_unit() {
    std::size_t failures = 0;
    announce("resolv_conf_keeps_three_nameservers_the_last_search_and_options");
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

    announce("hosts_lines_match_aliases_by_family_ignoring_case");
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

int main(int, char** argv) {
    install_test_signal_handlers();
    fmt::print("Hi, dear tester! You look nice today!\n");
    configure_tests();

    suite_totals_t totals {.program = argv[0]};
    run_test(totals, "test_dns_queries_unit", test_dns_queries_unit);
    run_test(totals, "test_dns_answers_unit", test_dns_answers_unit);
    run_test(totals, "test_dns_answers_safety", test_dns_answers_safety);
    run_test(totals, "test_dns_answers_property", test_dns_answers_property);
    run_test(totals, "test_dns_configuration_unit", test_dns_configuration_unit);
    return suite_exit_code(totals);
}
