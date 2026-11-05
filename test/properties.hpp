/**
 *  @file test/properties.hpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief Oracles over the parsers that read untrusted bytes, shared by the seeded suite cases and
 *      the libFuzzer harnesses in <tt>test/fuzz/</tt>.
 *
 *  Each oracle copies its input into a heap block of exactly its size, so an AddressSanitizer build
 *  catches any read past the wire, and answers how many of its checks failed instead of aborting,
 *  so a suite counts them and a harness aborts on any.
 */
#pragma once

#include <cstdint> // `std::uint8_t`
#include <cstring> // `std::memcpy`

#include <algorithm>   // `std::min`
#include <memory>      // `std::unique_ptr`
#include <string>      // `std::string`
#include <string_view> // `std::string_view`
#include <vector>      // `std::vector`

#include <fmt/format.h> // `fmt::format`

#include "ucall/dns/messages.hpp"         // `decode_answer`, `decode_name`
#include "ucall/http/messages.hpp"        // `messages`, the serial kits
#include "ucall/http/routes.hpp"          // `route_trie_t`, `parse_segment`
#include "ucall/http/multipart.hpp"       // `split_multipart`, `header_parameter`
#include "ucall/tunnel/secure_tunnel.hpp" // `secure_tunnel_t`
#if UCALL_OS_POSIX_
#include "ucall/io/posix_engine.hpp" // `posix_engine_t`
#include "ucall/network.hpp"         // `serial_network`
#endif

namespace unum::ucall::test {

/** A heap copy of @p input sized to it, so reading one byte past it is an ASan report. */
struct exact_copy_t {
    std::unique_ptr<byte_t[]> bytes;
    std::size_t size {};

    explicit exact_copy_t(span<byte_t const> input)
        : bytes(new byte_t[input.size() ? input.size() : 1]), size(input.size()) {
        if (size) std::memcpy(bytes.get(), input.data(), size);
    }
    [[nodiscard]] span<byte_t const> view() const noexcept { return {bytes.get(), size}; }
};

/**
 *  @brief Decodes @p packet as answers to A and AAAA questions for @p question, counting where the
 *      decoder broke a promise: an address count past its capacity, or a TTL on a non-answer.
 *
 *  The ID is the packet's own first two bytes, so mutated packets reach past the ID check.
 */
[[nodiscard]] inline std::size_t check_dns_answer(span<byte_t const> packet,
                                                  dns::wire_name_t const& question) noexcept {
    exact_copy_t const copy {packet};
    std::uint16_t const id = copy.size >= 2 ? static_cast<std::uint16_t>(static_cast<unsigned>(copy.bytes[0]) << 8 |
                                                                         static_cast<unsigned>(copy.bytes[1]))
                                            : 0;
    std::size_t failures = 0;
    byte_t addresses[48] {};
    for (auto type : {dns::record_type_t::a_k, dns::record_type_t::aaaa_k}) {
        std::size_t const width = type == dns::record_type_t::a_k ? 4 : 16;
        auto const decoded = dns::decode_answer(copy.view(), id, question, type, addresses);
        failures += decoded.addresses_count * width > sizeof(addresses);
        failures += decoded.answer == dns::answer_t::addresses_k && !decoded.addresses_count;
        failures += (decoded.answer == dns::answer_t::malformed_k || decoded.answer == dns::answer_t::failed_k ||
                     decoded.answer == dns::answer_t::truncated_k) &&
                    (decoded.addresses_count || decoded.ttl_seconds);
    }
    dns::wire_name_t name {};
    std::size_t next = 0;
    for (std::size_t offset = 0; offset < copy.size; ++offset)
        if (dns::decode_name(copy.view(), offset, name, next))
            failures += name.length > dns::name_bytes_k || next > copy.size || next <= offset;
    return failures;
}

/** The serial kits, which every class's framing must agree with. */
using property_http_t = http::messages<http::serial_compare_kit_t, http::serial_find_kit_t, http::serial_byteset_kit_t,
                                       http::serial_hash_kit_t, http::serial_fold_kit_t>;

/**
 *  @brief Frames @p wire once whole and again as it arrives in pieces cut at @p cuts, counting
 *      where the two disagree, and where a body streamed piece by piece differs from the buffered
 *      one it should match.
 *
 *  A prefix may only answer incomplete, or what the whole wire answers once the message is in it.
 */
[[nodiscard]] inline std::size_t check_http_fragmentation(span<byte_t const> wire, span<std::size_t const> cuts,
                                                          http::http_role_t role) {
    using message_t = property_http_t::http_message_t;
    std::size_t failures = 0;

    exact_copy_t whole {wire};
    message_t expected {};
    auto const verdict = property_http_t::http_parse({whole.bytes.get(), whole.size}, expected, role);
    std::string decoded;
    if (verdict == http::http_parse_t::complete_k) {
        property_http_t::http_decode_chunks({whole.bytes.get(), whole.size}, expected);
        decoded = std::string(text_view(whole.view()).substr(expected.headers_length, expected.body_length));
    }

    message_t message {};
    std::size_t previous = 0;
    for (std::size_t index = 0; index <= cuts.size(); ++index) {
        std::size_t const end = index == cuts.size() ? wire.size() : std::min(cuts[index], wire.size());
        if (end < previous) continue;
        previous = end;
        exact_copy_t prefix {wire.first(end)};
        auto const parsed = property_http_t::http_parse({prefix.bytes.get(), prefix.size}, message, role);
        if (parsed == http::http_parse_t::incomplete_k) continue;
        failures += parsed != verdict;
        if (parsed == http::http_parse_t::complete_k)
            failures += message.wire_length != expected.wire_length || message.framing != expected.framing ||
                        end < expected.wire_length;
        break;
    }
    if (verdict != http::http_parse_t::complete_k) return failures;

    // The same body streamed: arrivals append, and each pull drops what it walked.
    message_t streamed {};
    streamed.framing = expected.framing;
    streamed.content_length = expected.content_length;
    std::string pending, output;
    std::size_t delivered = expected.headers_length;
    auto const body_end = expected.wire_length;
    auto feed = [&](std::size_t until) -> http::http_parse_t {
        until = std::min(until, body_end);
        if (until > delivered) pending.append(text_view(wire).substr(delivered, until - delivered)), delivered = until;
        exact_copy_t input {byte_span(pending)};
        std::size_t payload = 0, consumed = 0;
        auto const stepped = property_http_t::http_stream_body({input.bytes.get(), input.size}, streamed,
                                                               ~std::size_t {0}, payload, consumed);
        output.append(reinterpret_cast<char const*>(input.bytes.get()), payload);
        pending.erase(0, consumed);
        return stepped;
    };
    http::http_parse_t stepped = http::http_parse_t::incomplete_k;
    for (std::size_t cut : cuts)
        if (cut > delivered && (stepped = feed(cut)) != http::http_parse_t::incomplete_k) break;
    while (stepped == http::http_parse_t::incomplete_k && delivered <= body_end) {
        std::size_t const before = output.size() + pending.size();
        stepped = feed(body_end);
        if (stepped == http::http_parse_t::incomplete_k && output.size() + pending.size() == before) break;
    }
    failures += stepped != http::http_parse_t::complete_k || output != decoded;
    return failures;
}

/** One route as the linear reference sees it: its template, verb, and the answer it registers. */
struct reference_route_t {
    std::string_view path;
    ucall_verb_t verb {};
    std::size_t answer {};
};

/** The segments of @p path as sent: none for @c /, and @c a with an empty one for @c /a/. */
inline std::vector<std::string_view> reference_segments(std::string_view path) {
    std::vector<std::string_view> segments;
    if (path.size() <= 1) return segments;
    for (std::size_t start = 1;;) {
        std::size_t const end = std::min(path.find('/', start), path.size());
        segments.push_back(path.substr(start, end - start));
        if (end == path.size()) return segments;
        start = end + 1;
    }
}

/** The kinds of @p route's segments when it matches @p path, literal below parameter below
 *  wildcard, or false when it does not. A parameter takes a non-empty segment, while a wildcard
 *  takes any non-empty rest. */
inline bool reference_match(std::string_view route, std::string_view path, std::vector<std::uint8_t>& kinds) {
    std::string_view const bare = path.substr(0, std::min(path.find('?'), path.find('#')));
    std::vector<std::string_view> const wanted = reference_segments(route), given = reference_segments(bare);
    kinds.clear();
    std::size_t start = 1;
    for (std::size_t index = 0; index != wanted.size(); ++index) {
        http::parsed_segment_t parsed {};
        if (!http::parse_segment(wanted[index], parsed)) return false;
        kinds.push_back(static_cast<std::uint8_t>(parsed.type));
        if (parsed.type == http::segment_type_t::wildcard_k) return index < given.size() && start < bare.size();
        if (index == given.size()) return false;
        bool const fits = parsed.type == http::segment_type_t::param_k ? !given[index].empty()
                                                                       : given[index] == parsed.content;
        if (!fits) return false;
        start += given[index].size() + 1;
    }
    return wanted.size() == given.size();
}

/** The answer of the route @p verb takes on @p path by the linear rule, or zero for none: the first
 *  matching route in literal, parameter, wildcard order, by its exact verb, then a GET answering
 *  HEAD, then one answering any verb. */
inline std::size_t reference_route(std::vector<reference_route_t> const& routes, std::string_view path,
                                   ucall_verb_t verb) {
    std::vector<std::uint8_t> best, kinds;
    std::size_t answer = 0;
    int answer_rank = 3;
    for (auto const& route : routes) {
        if (!reference_match(route.path, path, kinds)) continue;
        int const rank = route.verb == verb                                            ? 0
                         : verb == ucall_verb_head_k && route.verb == ucall_verb_get_k ? 1
                         : route.verb == ucall_verb_any_k                              ? 2
                                                                                       : 3;
        if (rank == 3) continue;
        if (!answer || kinds < best || (kinds == best && rank < answer_rank))
            best = kinds, answer = route.answer, answer_rank = rank;
    }
    return answer;
}

/**
 *  @brief Registers @p templates, each with its verb, and matches @p paths with every verb a
 *      request names, counting where the trie and the linear reference answer different routes.
 *
 *  Registration refusals are the trie's to make, so the reference holds the accepted routes alone.
 */
[[nodiscard]] inline std::size_t check_route_match(span<std::string_view const> templates,
                                                   span<ucall_verb_t const> verbs, span<std::string_view const> paths) {
    http::route_trie_t trie;
    if (trie.init() != ucall_status_success_k) return 1;
    std::vector<std::string> copies;
    copies.reserve(templates.size() + paths.size());
    std::vector<reference_route_t> routes;
    for (std::size_t index = 0; index != templates.size(); ++index) {
        // The trie borrows its templates, so each lives in an exact heap copy for as long as it.
        std::string const& route = copies.emplace_back(templates[index]);
        void* const answer = reinterpret_cast<void*>(index + 1);
        if (trie.insert(route, verbs[index], answer) == ucall_status_success_k)
            routes.push_back({route, verbs[index], index + 1});
    }
    std::size_t failures = 0;
    for (std::string_view path : paths) {
        exact_copy_t const copy {byte_span(path)};
        std::string_view const exact = text_view(copy.view());
        for (ucall_verb_t verb : {ucall_verb_get_k, ucall_verb_head_k, ucall_verb_post_k, ucall_verb_delete_k})
            failures += reinterpret_cast<std::size_t>(trie.match(exact, verb)) != reference_route(routes, exact, verb);
    }
    return failures;
}

#if UCALL_OS_POSIX_

/** The client of the serial network, whose URL parsing and redirect joins need no instance. */
using property_client_t = network::serial_network<io::posix_engine_t>::client_t;
using property_exchange_t = network::serial_network<io::posix_engine_t>::client_exchange_t;
using property_message_t = network::serial_network<io::posix_engine_t>::http_message_t;

/** Parses @p url as a client call would, and when it parses, parses the URL spelled back from its
 *  parts again, counting the parts that differ or break their promises: a target that starts with
 *  @c / and keeps no fragment, a host, and a port in range. */
[[nodiscard]] inline std::size_t check_url(std::string_view url) {
    exact_copy_t const copy {byte_span(url)};
    property_exchange_t first {};
    first.arguments.url = {reinterpret_cast<ucall_byte_t const*>(copy.bytes.get()), copy.size};
    if (property_client_t::parse_url(first) != ucall_status_success_k) return 0;
    std::string_view const authority = http::text_view(first.authority), target = http::text_view(first.target);
    std::size_t failures = target.empty() || target.front() != '/' || target.find('#') != std::string_view::npos ||
                           http::text_view(first.host).size() <= 1 || !first.port;
    std::string const spelled = fmt::format("{}://{}{}", url.substr(0, url.find("://")),
                                            authority.substr(0, authority.size() - 1), target);
    property_exchange_t second {};
    second.arguments.url = bytes_view(spelled);
    failures += property_client_t::parse_url(second) != ucall_status_success_k ||
                http::text_view(second.authority) != authority || http::text_view(second.target) != target ||
                http::text_view(second.host) != http::text_view(first.host) || second.port != first.port ||
                second.arguments.options.security != first.arguments.options.security;
    return failures;
}

/**
 *  @brief Answers a call to @p base with a redirect to @p location, counting a relative reference,
 *      one naming neither a scheme nor a network path, whose join leaves the base's origin.
 *
 *  @p base names a numeric host, so following the redirect resolves nothing.
 */
[[nodiscard]] inline std::size_t check_redirect_join(std::string_view base, std::string_view location) {
    std::string response = fmt::format("HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\n\r\n", location);
    property_message_t message {};
    if (property_http_t::http_parse({reinterpret_cast<byte_t*>(response.data()), response.size()}, message,
                                    http::http_role_t::response_k) != http::http_parse_t::complete_k)
        return 0;
    // The client reads the field trimmed, so a reference counts as relative by what it reads.
    std::string_view const read = message.header(response, "location");
    if (read.find("://") != std::string_view::npos || read.starts_with("//")) return 0;
    property_exchange_t exchange {};
    exchange.arguments.url = bytes_view(base);
    if (property_client_t::parse_url(exchange) != ucall_status_success_k) return 1;
    std::string const authority {http::text_view(exchange.authority)};
    if (property_client_t::redirect_exchange(exchange, message, response) != ucall_status_success_k) return 0;
    std::string_view const origin = base.substr(0, base.find("://") + 3 + authority.size() - 1);
    return http::text_view(exchange.authority) != authority ||
           !http::text_view(exchange.arguments.url).starts_with(origin);
}

#endif // UCALL_OS_POSIX_

/** One part @c split_multipart reports: where it starts in the body and how long it runs. */
struct multipart_part_t {
    std::uint64_t offset {}, length {};
    bool operator==(multipart_part_t const&) const = default;
};

/** The parts of @p body by the RFC 2046 rule spelled plainly: a delimiter is <tt>--boundary</tt> at
 *  the start or <tt>CRLF--boundary</tt> inside a part, its line runs to a CRLF, and one followed by
 *  @c -- closes; false without that close. */
inline bool reference_multipart(std::string_view body, std::string_view boundary,
                                std::vector<multipart_part_t>& parts) {
    std::string const dash = fmt::format("--{}", boundary), delimiter = fmt::format("\r\n{}", dash);
    std::size_t const first = body.starts_with(dash) ? 0 : body.find(delimiter);
    if (first == std::string_view::npos) return false;
    for (std::size_t after = first + (first == 0 && body.starts_with(dash) ? dash.size() : delimiter.size());;) {
        if (body.substr(after, 2) == "--") return true;
        std::size_t const line_end = body.find("\r\n", after);
        if (line_end == std::string_view::npos) return false;
        std::size_t const start = line_end + 2, next = body.find(delimiter, start);
        if (next == std::string_view::npos) return false;
        parts.push_back({start, next - start});
        after = next + delimiter.size();
    }
}

/** Splits @p body under a @c multipart/form-data type naming @p boundary, counting where
 *  @c split_multipart and the linear reference disagree, or a part leaves the body. */
[[nodiscard]] inline std::size_t check_multipart(std::string_view boundary, span<byte_t const> body) {
    exact_copy_t const copy {body};
    std::string_view const exact = text_view(copy.view());
    std::string const content_type = fmt::format("multipart/form-data; boundary=\"{}\"", boundary);
    st::vector<multipart_part_t> found;
    bool const split = http::split_multipart<property_http_t>(content_type, exact, 0, found);
    std::string_view const parameter = http::header_parameter<property_http_t>(content_type, "boundary");
    std::vector<multipart_part_t> expected;
    bool const reference = !parameter.empty() && parameter.size() <= 70 &&
                           reference_multipart(exact, parameter, expected);
    std::size_t failures = split != reference;
    if (split && reference) failures += !std::equal(found.begin(), found.end(), expected.begin(), expected.end());
    if (split)
        for (auto const& part : found) failures += part.offset > copy.size || part.length > copy.size - part.offset;
    return failures;
}

/** A Noise pair connected once and reconnected on the same static keys whenever a refused record
 *  broke it, as a refusal does by design; the record oracle seals and opens through it. */
struct property_tunnel_pair_t {
    byte_t client_private[tunnel::secure_tunnel_key_size_k] {}, client_public[tunnel::secure_tunnel_key_size_k] {};
    byte_t server_private[tunnel::secure_tunnel_key_size_k] {}, server_public[tunnel::secure_tunnel_key_size_k] {};
    tunnel::secure_tunnel_t client, server;
    st::vector<byte_t> wire;

    [[nodiscard]] bool draw() noexcept {
        return tunnel::secure_tunnel_generate_keypair(client_private, client_public) ==
                   tunnel::secure_tunnel_fault_t::none_k &&
               tunnel::secure_tunnel_generate_keypair(server_private, server_public) ==
                   tunnel::secure_tunnel_fault_t::none_k &&
               !st::failed(wire.resize(tunnel::secure_tunnel_max_record_k));
    }

    /** The responder configuration of @p mode on the server's keys. */
    [[nodiscard]] tunnel::secure_tunnel_config_t responder(tunnel::secure_tunnel_mode_t mode) const noexcept {
        tunnel::secure_tunnel_config_t config;
        config.mode = mode;
        config.role = tunnel::secure_tunnel_role_t::responder_k;
        config.local_private = server_private;
        config.local_public = server_public;
        if (mode == tunnel::secure_tunnel_mode_t::noise_kk_k) config.peer_public = client_public;
        return config;
    }

    [[nodiscard]] bool usable() const noexcept {
        return server.encrypts() && client.state() == tunnel::secure_tunnel_state_t::ready_k &&
               server.state() == tunnel::secure_tunnel_state_t::ready_k;
    }

    /** Completes an XX handshake over in-memory buffers. */
    [[nodiscard]] bool connect() {
        tunnel::secure_tunnel_config_t initiator;
        initiator.mode = tunnel::secure_tunnel_mode_t::noise_xx_k;
        initiator.role = tunnel::secure_tunnel_role_t::initiator_k;
        initiator.local_private = client_private;
        initiator.local_public = client_public;
        if (client.make(initiator) != tunnel::secure_tunnel_fault_t::none_k ||
            server.make(responder(tunnel::secure_tunnel_mode_t::noise_xx_k)) != tunnel::secure_tunnel_fault_t::none_k)
            return false;
        std::vector<byte_t> toward_server, toward_client;
        auto pump = [](tunnel::secure_tunnel_t& end, std::vector<byte_t>& inbound, std::vector<byte_t>& outbound) {
            auto const step = end.advance(inbound);
            inbound.erase(inbound.begin(), inbound.begin() + static_cast<std::ptrdiff_t>(step.consumed));
            outbound.insert(outbound.end(), step.outbound.begin(), step.outbound.end());
            return step.state != tunnel::secure_tunnel_state_t::broken_k;
        };
        for (std::size_t round = 0; round != 8 && !usable(); ++round)
            if (!pump(client, toward_client, toward_server) || !pump(server, toward_server, toward_client))
                return false;
        return usable();
    }
};

/**
 *  @brief Feeds @p input as the first handshake message to a fresh responder of every Noise mode,
 *      which must refuse or advance within it, and seals a record through @p pair, flips the bytes
 *      @p input names, and counts a changed record that still opens or an intact one that does not.
 *
 *  The input's first byte counts up to four flips, each two bytes, position then mask, and the
 *  payload follows them.
 */
[[nodiscard]] inline std::size_t check_tunnel_records(span<byte_t const> input, property_tunnel_pair_t& pair) {
    exact_copy_t const copy {input};
    std::size_t failures = 0;
    for (auto mode : {tunnel::secure_tunnel_mode_t::noise_xx_k, tunnel::secure_tunnel_mode_t::noise_ik_k,
                      tunnel::secure_tunnel_mode_t::noise_kk_k}) {
        tunnel::secure_tunnel_t responder;
        if (responder.make(pair.responder(mode)) != tunnel::secure_tunnel_fault_t::none_k) return failures + 1;
        auto const step = responder.advance(copy.view());
        failures += step.consumed > copy.size ||
                    (step.state == tunnel::secure_tunnel_state_t::broken_k && !step.outbound.empty());
    }

    if (!pair.usable() && !pair.connect()) return failures + 1;
    std::size_t const flips = copy.size ? std::to_integer<std::size_t>(copy.bytes[0]) % 5 : 0;
    std::size_t const payload_at = std::min(copy.size, 1 + 2 * flips);
    span<byte_t const> const payload {copy.bytes.get() + payload_at, copy.size - payload_at};
    span<byte_t> const window = pair.client.payload_window(pair.wire);
    std::size_t const filled = std::min(payload.size(), window.size());
    if (filled) std::memcpy(window.data(), payload.data(), filled);
    auto const sealed = pair.client.seal(pair.wire, filled);
    if (sealed.empty()) return failures + 1;
    exact_copy_t record {sealed};
    for (std::size_t flip = 0; flip != flips && 2 + 2 * flip < copy.size; ++flip)
        record.bytes[std::to_integer<std::size_t>(copy.bytes[1 + 2 * flip]) % record.size] ^= copy.bytes[2 + 2 * flip];
    bool const changed = std::memcmp(record.bytes.get(), sealed.data(), record.size) != 0;
    span<byte_t> const received {record.bytes.get(), record.size};
    if (pair.server.bytes_until_boundary(received)) {
        // A prefix declaring a longer record waits for bytes that never come, so the pair desyncs.
        failures += !changed;
        pair.server.clear();
        return failures;
    }
    exact_copy_t destination {sealed};
    auto const opened = pair.server.open(received, {destination.bytes.get(), destination.size});
    if (changed) failures += opened.consumed != 0;
    else
        failures += opened.consumed != record.size || opened.payload.size() != filled ||
                    (filled && std::memcmp(opened.payload.data(), payload.data(), filled) != 0);
    return failures;
}

} // namespace unum::ucall::test
