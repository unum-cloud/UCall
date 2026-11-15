/**
 *  @file include/ucall/network/resolving.hpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief The client's asynchronous stub resolver: its lookups, their questions, and the Happy
 *      Eyeballs order of the addresses they answer.
 *
 *  A lookup asks AAAA and A for each search name of its origin, each question on a connected UDP
 *  socket the client's engine drives, one operation at a time: the query's send, then its
 *  answer's receive, or over TCP a connect, the send and as many receives as the answer takes.
 *  Answers and refusals are cached on the origin until their TTL passes.
 */
#pragma once

#include "ucall/dns/configuration.hpp" // `find_host`, `resolver_options_t`
#include "ucall/dns/messages.hpp"      // `compose_query`, `decode_answer`, `spell_name`, `wire_name_t`
#include "ucall/dns/types.hpp"         // `record_type_t`, `answer_t`, RFC constants
#include "ucall/io/types.hpp"          // `io_request_t`, `io_completion_t`, `io_operation_t`
#include "ucall/network/types.hpp"     // `operation_state_t`
#include "ucall/utilities/sockets.hpp" // `datagram_open`, `deadline_after`, `socket_length_t`
#include "ucall/utilities/types.hpp"   // `byte_t`, `span`, `text_view`

namespace unum::ucall::network {

/** Whether an origin's addresses are unknown, being asked, known until @c expires, or known not to
 *  exist until then. */
enum class resolution_t : std::uint8_t { unresolved_k, resolving_k, resolved_k, refused_k };

/** Whether an origin waits on the client's free list or serves calls on its live one. */
enum class origin_list_t : std::uint8_t { free_k, live_k };

/** Addresses of each family an origin keeps: answers carry more, and the first few fail over. */
inline constexpr std::size_t origin_addresses_k = 8;

/** One origin's lookup: its two questions and the search name they ask; cold, one a connection. */
template <typename network_type_>
struct client_lookup {
    using network_t = network_type_;
    using allocator_t = typename network_t::allocator_t;
    using client_origin_t = typename network_t::client_origin_t;
    using client_lookup_t = typename network_t::client_lookup_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;

    explicit client_lookup(allocator_t const& allocator) noexcept : stream(rebound_allocator<byte_t> {allocator}) {}
    client_lookup(client_lookup const&) = delete;
    client_lookup& operator=(client_lookup const&) = delete;
    client_lookup(client_lookup&&) = delete;
    client_lookup& operator=(client_lookup&&) = delete;

    /** Unasked, waiting for its UDP answer, carried over TCP after a truncated one, or done. */
    enum class question_stage_t : std::uint8_t { idle_k, asking_k, streaming_k, answered_k };
    struct question_t {

        /** The query's send, or over TCP the connect to the nameserver and then the send. */
        io_request_t send_request {};

        /** Reads an answer into @c answer, again after a forged datagram or a partial TCP one. */
        io_request_t receive_request {};

        /** Its UDP or TCP socket to the nameserver asked, or negative while none is open. */
        descriptor_t descriptor {-1};

        /** The random ID of the query in flight, which its answer must echo. */
        std::uint16_t id {};

        /** Bytes of the query behind the length prefix in @c query. */
        std::uint16_t query_length {};

        /** AAAA for the first question and A for the second, set as each search name is asked. */
        dns::record_type_t type {};

        /** Its progress; streaming with no socket, it waits for the other question's stream. */
        question_stage_t stage {};

        /** One operation runs at a time, so a socket closes or moves on with nothing in flight. */
        operation_state_t operation {};

        /** What this search name earned: failed until an answer decodes, then that answer. */
        dns::answer_t verdict {};

        /** Rounds through the nameservers this search name took, up to @c attempts. */
        std::uint8_t attempt {};

        /** The index of the nameserver asked, rotating on each retry. */
        std::uint8_t nameserver {};

        /** The decoded answer's TTL, for its addresses or their absence; zero until one decodes. */
        std::uint32_t ttl_seconds {};

        /** A TCP length prefix, then the query. */
        byte_t query[2 + dns::query_bytes_k] {};

        /** One UDP answer, or the bytes of one TCP receive that @c stream gathers. */
        byte_t answer[dns::udp_answer_bytes_k] {};
    };

    /** AAAA, then A. */
    question_t questions[2] {};

    /** A TCP answer across receives, kept warm; one question streams at a time. */
    vector<byte_t> stream {};

    /** The search name @c candidate spells in wire form, which both questions ask. */
    dns::wire_name_t name {};

    /** The origin being resolved, or null while the lookup is free. */
    client_origin_t* origin {};

    /** RFC 8305 §3: once an A answered first, when to dial it without the AAAA. */
    std::uint64_t settle_deadline {};

    /** The index of the search name being asked, in @c candidate_name's order. */
    std::uint32_t candidate {};

    /** The least negative TTL the names before @c candidate earned, zero once one failed. */
    std::uint32_t ttl_seconds {};

    /** Links the client's free lookups; null while one resolves. */
    client_lookup_t* next {};
};

/** Starts, steps and completes the client's lookups, and orders the addresses they answer. */
template <typename network_type_>
struct resolving {
    using network_t = network_type_;
    using client_t = typename network_t::client_t;
    using client_origin_t = typename network_t::client_origin_t;
    using client_lookup_t = typename network_t::client_lookup_t;
    using crypto_t = typename network_t::crypto_t;
    using question_t = typename client_lookup_t::question_t;
    using question_stage_t = typename client_lookup_t::question_stage_t;

    static std::uint32_t addresses_count(client_origin_t const& origin) noexcept {
        return origin.ipv6_count + origin.ipv4_count;
    }

    /** Writes the address @p index dials into @p address and answers its length: RFC 8305 §4's
     *  order, AAAA and A alternating from the first AAAA, then the longer family's rest. */
    static utilities::socket_length_t target(client_origin_t const& origin, std::uint32_t index,
                                             sockaddr_storage& address) noexcept {
        std::uint32_t const shared = fu::min_of(origin.ipv6_count, origin.ipv4_count);
        bool const inet6 = index < 2 * shared ? index % 2 == 0 : origin.ipv6_count > origin.ipv4_count;
        std::uint32_t const slot = index < 2 * shared ? index / 2 : index - shared;
        address = {};
        if (inet6) {
            auto& inet = reinterpret_cast<sockaddr_in6&>(address);
            inet.sin6_family = AF_INET6;
            inet.sin6_port = htons(origin.port);
            std::memcpy(&inet.sin6_addr, origin.ipv6_addresses[slot], 16);
            return sizeof(sockaddr_in6);
        }
        auto& inet = reinterpret_cast<sockaddr_in&>(address);
        inet.sin_family = AF_INET;
        inet.sin_port = htons(origin.port);
        std::memcpy(&inet.sin_addr, origin.ipv4_addresses[slot], 4);
        return sizeof(sockaddr_in);
    }

    /** Resolves a numeric host at once and for good, answering whether it was one. */
    static bool resolve_numeric(client_origin_t& origin) noexcept {
        char const* const host = origin.host.data();
        origin.ipv6_count = inet_pton(AF_INET6, host, origin.ipv6_addresses[0]) == 1 ? 1 : 0;
        origin.ipv4_count = inet_pton(AF_INET, host, origin.ipv4_addresses[0]) == 1 ? 1 : 0;
        if (!addresses_count(origin)) return false;
        origin.resolution = resolution_t::resolved_k;
        origin.expires = 0;
        return true;
    }

    /** When @p origin next needs a look without any completion: an A waiting out its AAAA. */
    static std::uint64_t due(client_origin_t const& origin) noexcept {
        if (origin.lookup && origin.lookup->settle_deadline) return origin.lookup->settle_deadline;
        return (std::numeric_limits<std::uint64_t>::max)();
    }

    /** Asks for @p origin's addresses when it has none or they expired, and dials an answered A
     *  once its AAAA had RFC 8305's resolution delay to arrive. */
    static void refresh(client_t& client, client_origin_t& origin, std::uint64_t now) noexcept {
        if (client_lookup_t* lookup = origin.lookup) {
            if (lookup->settle_deadline && now >= lookup->settle_deadline) {
                lookup->settle_deadline = 0;
                origin.resolution = resolution_t::resolved_k;
            }
            return;
        }
        if (origin.resolution != resolution_t::unresolved_k && (!origin.expires || now < origin.expires)) return;
        start(client, origin);
    }

    /** Whether @p request is one of the client's lookups'. */
    static bool owns(client_t const& client, io_request_t const* request) noexcept {
        auto const* const begin = reinterpret_cast<byte_t const*>(client.lookups.data());
        auto const* const address = reinterpret_cast<byte_t const*>(request);
        return address >= begin && address < begin + client.lookups.size_bytes();
    }

    /** Lands one completion of a lookup's question and moves the question on. */
    static void complete(client_t& client, io_completion_t const& completion) noexcept {
        auto& lookup = *static_cast<client_lookup_t*>(completion.request->context);
        question_t& question = completion.request == &lookup.questions[0].send_request ||
                                       completion.request == &lookup.questions[0].receive_request
                                   ? lookup.questions[0]
                                   : lookup.questions[1];
        question.operation = operation_state_t::idle_k;
        bool const sent = completion.request == &question.send_request;
        auto const result = completion.result;
        if (sent && question.send_request.operation == io_operation_t::connect_k) {
            if (result < 0) return retry(client, lookup, question);
            question.send_request = {.operation = io_operation_t::send_k,
                                     .descriptor = question.descriptor,
                                     .data = question.query,
                                     .length = std::size_t {2} + question.query_length,
                                     .deadline = question.send_request.deadline,
                                     .context = &lookup};
            return submit(client, question, question.send_request);
        }
        if (sent) {
            if (result != static_cast<descriptor_t>(question.send_request.length))
                return retry(client, lookup, question);
            return submit(client, question, question.receive_request);
        }
        if (result <= 0) return retry(client, lookup, question);
        std::size_t const length = static_cast<std::size_t>(result);
        if (question.stage == question_stage_t::asking_k)
            return decided(client, lookup, question, {question.answer, length});
        auto& stream = lookup.stream;
        std::size_t const previous = stream.size();
        if (st::failed(stream.resize(previous + length))) return retry(client, lookup, question);
        std::memcpy(stream.data() + previous, question.answer, length);
        std::size_t const declared = stream.size() < 2 ? 0
                                                       : std::to_integer<std::size_t>(stream[0]) << 8 |
                                                             std::to_integer<std::size_t>(stream[1]);
        if (stream.size() < 2 || stream.size() < 2 + declared)
            return submit(client, question, question.receive_request);
        decided(client, lookup, question, {stream.data() + 2, declared});
    }

  private:
    static dns::resolver_options_t const& options(client_t const& client) noexcept { return client.resolver; }
    static std::string_view host(client_origin_t const& origin) noexcept {
        return {origin.host.data(), origin.host.size() - 1};
    }

    /** Spells search name @p index of @p host into @p name in <tt>resolv.h</tt>'s order: a name ending in
     * a dot as it is only; one with at least @c ndots dots as it is, then with each suffix; any
     * other with each suffix, then as it is. Not found past the last. */
    static ucall_status_t candidate_name(dns::resolver_options_t const& options, std::string_view host,
                                         std::uint32_t index, dns::wire_name_t& name) noexcept {
        if (host.ends_with('.'))
            return index ? ucall_status_not_found_k
                         : (dns::spell_name(host, name) ? ucall_status_success_k : ucall_status_invalid_argument_k);
        std::string_view suffixes {options.search, options.search_length};
        std::uint32_t const suffixes_count = static_cast<std::uint32_t>(
            std::count(suffixes.begin(), suffixes.end(), '\0'));
        bool const absolute_first = static_cast<std::uint32_t>(std::count(host.begin(), host.end(), '.')) >=
                                    options.ndots;
        if (index > suffixes_count) return ucall_status_not_found_k;
        if ((absolute_first && index == 0) || (!absolute_first && index == suffixes_count))
            return dns::spell_name(host, name) ? ucall_status_success_k : ucall_status_invalid_argument_k;
        for (std::uint32_t skipped = index - (absolute_first ? 1 : 0); skipped; --skipped)
            suffixes.remove_prefix(suffixes.find('\0') + 1);
        auto const suffix = suffixes.substr(0, suffixes.find('\0'));
        char joined[dns::name_bytes_k + 2];
        if (host.size() + 1 + suffix.size() > dns::name_bytes_k) return ucall_status_invalid_argument_k;
        std::memcpy(joined, host.data(), host.size());
        joined[host.size()] = '.';
        std::memcpy(joined + host.size() + 1, suffix.data(), suffix.size());
        return dns::spell_name({joined, host.size() + 1 + suffix.size()}, name) ? ucall_status_success_k
                                                                                : ucall_status_invalid_argument_k;
    }

    /** Takes a free lookup for @p origin, answering first from the hosts file; with none free the
     *  origin stays unresolved until one is. */
    static void start(client_t& client, client_origin_t& origin) noexcept {
        origin.ipv6_count = origin.ipv4_count = 0;
        std::string_view const hosts {client.hosts.begin(), client.hosts.end()};
        if (dns::find_host(hosts, host(origin), dns::record_type_t::aaaa_k, {origin.ipv6_addresses[0], 16}) ==
            ucall_status_success_k)
            origin.ipv6_count = 1;
        if (dns::find_host(hosts, host(origin), dns::record_type_t::a_k, {origin.ipv4_addresses[0], 4}) ==
            ucall_status_success_k)
            origin.ipv4_count = 1;
        if (addresses_count(origin)) {
            origin.resolution = resolution_t::resolved_k;
            origin.expires = 0;
            return;
        }
        client_lookup_t* const lookup = client.free_lookups;
        if (!lookup) {
            origin.resolution = resolution_t::unresolved_k;
            return;
        }
        client.free_lookups = std::exchange(lookup->next, nullptr);
        lookup->origin = &origin;
        lookup->candidate = 0;
        lookup->ttl_seconds = (std::numeric_limits<std::uint32_t>::max)();
        lookup->settle_deadline = 0;
        origin.lookup = lookup;
        origin.resolution = resolution_t::resolving_k;
        ask_candidate(client, *lookup);
    }

    /** Asks both questions for the next search name that spells, or refuses the origin past the
     *  last, caching the refusal for the least negative TTL its names earned. */
    static void ask_candidate(client_t& client, client_lookup_t& lookup) noexcept {
        for (;; ++lookup.candidate) {
            ucall_status_t const spelled = candidate_name(options(client), host(*lookup.origin), lookup.candidate,
                                                          lookup.name);
            if (spelled == ucall_status_success_k) break;
            if (spelled == ucall_status_not_found_k) return finish(client, lookup, resolution_t::refused_k);
        }
        dns::record_type_t const types[2] {dns::record_type_t::aaaa_k, dns::record_type_t::a_k};
        for (question_t& question : lookup.questions) question.stage = question_stage_t::idle_k;
        // A question answering at once may end the lookup, which then asks nothing more.
        for (std::size_t index = 0; index != 2 && lookup.origin; ++index) {
            question_t& question = lookup.questions[index];
            question.type = types[index];
            question.attempt = question.nameserver = 0;
            question.ttl_seconds = 0;
            ask(client, lookup, question);
        }
    }

    /** Asks @p question of its current nameserver over a fresh connected UDP socket. */
    static void ask(client_t& client, client_lookup_t& lookup, question_t& question) noexcept {
        auto const& settings = options(client);
        question.stage = question_stage_t::asking_k;
        question.verdict = dns::answer_t::failed_k;
        if (!settings.nameservers_count) return answer(client, lookup, question);
        sockaddr_storage const& server = settings.nameservers[question.nameserver];
        auto const length = static_cast<utilities::socket_length_t>(server.ss_family == AF_INET6 ? sizeof(sockaddr_in6)
                                                                                                 : sizeof(sockaddr_in));
        descriptor_t const opened = utilities::datagram_open(reinterpret_cast<sockaddr const*>(&server), length);
        question.descriptor = opened < 0 ? opened : client.engine->import_socket(opened);
        if (question.descriptor < 0) return retry(client, lookup, question);
        byte_t id[2] {};
        // An ID nobody can guess is what tells the nameserver's answer from a forged one.
        if (crypto_t::secure_random_bytes(id) != tunnel::secure_tunnel_fault_t::none_k) {
            question.attempt = settings.attempts;
            return retry(client, lookup, question);
        }
        question.id = static_cast<std::uint16_t>(std::to_integer<unsigned>(id[0]) << 8 |
                                                 std::to_integer<unsigned>(id[1]));
        question.query_length = static_cast<std::uint16_t>(
            dns::compose_query(span<byte_t, dns::query_bytes_k> {question.query + 2, dns::query_bytes_k}, question.id,
                               lookup.name, question.type));
        question.query[0] = static_cast<byte_t>(question.query_length >> 8);
        question.query[1] = static_cast<byte_t>(question.query_length);
        std::uint64_t const deadline = deadline_after(std::size_t {settings.timeout_seconds} * 1'000'000);
        question.send_request = {.operation = io_operation_t::send_k,
                                 .descriptor = question.descriptor,
                                 .data = question.query + 2,
                                 .length = question.query_length,
                                 .deadline = deadline,
                                 .context = &lookup};
        question.receive_request = {.operation = io_operation_t::read_k,
                                    .descriptor = question.descriptor,
                                    .data = question.answer,
                                    .length = sizeof(question.answer),
                                    .deadline = deadline,
                                    .context = &lookup};
        submit(client, question, question.send_request);
    }

    /** Carries @p question over TCP to the same nameserver, once no other question streams. */
    static void stream(client_t& client, client_lookup_t& lookup, question_t& question) noexcept {
        question.stage = question_stage_t::streaming_k;
        question_t const& other = &question == &lookup.questions[0] ? lookup.questions[1] : lookup.questions[0];
        if (other.stage == question_stage_t::streaming_k && other.descriptor >= 0) return;
        // The connect request names the address it dials, so it reads the client's own copy.
        sockaddr_storage& server = client.resolver.nameservers[question.nameserver];
        question.descriptor = client.engine->open_socket(server.ss_family);
        if (question.descriptor < 0) return retry(client, lookup, question);
        lookup.stream.clear();
        std::uint64_t const deadline = deadline_after(std::size_t {options(client).timeout_seconds} * 1'000'000);
        question.send_request = {.operation = io_operation_t::connect_k,
                                 .descriptor = question.descriptor,
                                 .data = reinterpret_cast<byte_t*>(&server),
                                 .length = server.ss_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in),
                                 .deadline = deadline,
                                 .context = &lookup};
        question.receive_request = {.operation = io_operation_t::read_k,
                                    .descriptor = question.descriptor,
                                    .data = question.answer,
                                    .length = sizeof(question.answer),
                                    .deadline = deadline,
                                    .context = &lookup};
        submit(client, question, question.send_request);
    }

    static void submit(client_t& client, question_t& question, io_request_t& request) noexcept {
        client.engine->submit(request);
        question.operation = operation_state_t::submitted_k;
    }

    static void close(client_t& client, question_t& question) noexcept {
        if (question.descriptor >= 0) client.engine->close_socket(std::exchange(question.descriptor, -1));
    }

    /** Asks @p question of the next nameserver, rotating through them for @c attempts rounds,
     *  then counts it failed. */
    static void retry(client_t& client, client_lookup_t& lookup, question_t& question) noexcept {
        close(client, question);
        auto const& settings = options(client);
        if (++question.nameserver >= settings.nameservers_count) {
            question.nameserver = 0;
            ++question.attempt;
        }
        if (question.attempt >= settings.attempts || !settings.nameservers_count) {
            question.verdict = dns::answer_t::failed_k;
            return answer(client, lookup, question);
        }
        ask(client, lookup, question);
    }

    /** Acts on the answer in @p packet to @p question. */
    static void decided(client_t& client, client_lookup_t& lookup, question_t& question,
                        span<byte_t const> packet) noexcept {
        client_origin_t& origin = *lookup.origin;
        bool const inet6 = question.type == dns::record_type_t::aaaa_k;
        span<byte_t> addresses = inet6 ? span<byte_t> {origin.ipv6_addresses[0], sizeof(origin.ipv6_addresses)}
                                       : span<byte_t> {origin.ipv4_addresses[0], sizeof(origin.ipv4_addresses)};
        dns::decoded_answer_t const decoded = dns::decode_answer(packet, question.id, lookup.name, question.type,
                                                                 addresses);
        bool const streamed = question.stage == question_stage_t::streaming_k;
        switch (decoded.answer) {
        case dns::answer_t::truncated_k:
            if (streamed) return retry(client, lookup, question);
            close(client, question);
            return stream(client, lookup, question);
        case dns::answer_t::failed_k: return retry(client, lookup, question);
        case dns::answer_t::malformed_k:
            // A datagram that is not this question's answer, as a forged one is, changes nothing:
            // the socket keeps waiting for the nameserver's own until the deadline.
            if (streamed) return retry(client, lookup, question);
            return submit(client, question, question.receive_request);
        default: break;
        }
        close(client, question);
        (inet6 ? origin.ipv6_count : origin.ipv4_count) = static_cast<std::uint32_t>(decoded.addresses_count);
        question.verdict = decoded.answer;
        question.ttl_seconds = decoded.ttl_seconds;
        answer(client, lookup, question);
    }

    /** Settles @p question, resolving its origin once an AAAA answered, or an A had the
     *  resolution delay to wait for one, and finishing the lookup or asking the next name
     *  once both settled. */
    static void answer(client_t& client, client_lookup_t& lookup, question_t& question) noexcept {
        question.stage = question_stage_t::answered_k;
        close(client, question);
        question_t& other = &question == &lookup.questions[0] ? lookup.questions[1] : lookup.questions[0];
        // A truncated twin waited for the stream this question held.
        if (other.stage == question_stage_t::streaming_k && other.descriptor < 0) stream(client, lookup, other);
        client_origin_t& origin = *lookup.origin;
        question_t const& inet6 = lookup.questions[0];
        question_t const& inet4 = lookup.questions[1];
        if (inet6.stage == question_stage_t::answered_k && origin.ipv6_count)
            origin.resolution = resolution_t::resolved_k;
        else if (inet4.stage == question_stage_t::answered_k && origin.ipv4_count && !lookup.settle_deadline &&
                 origin.resolution == resolution_t::resolving_k)
            lookup.settle_deadline = deadline_after(dns::resolution_delay_microseconds_k);
        if (inet6.stage != question_stage_t::answered_k || inet4.stage != question_stage_t::answered_k) return;
        if (addresses_count(origin)) return finish(client, lookup, resolution_t::resolved_k);
        bool const answered = inet6.verdict != dns::answer_t::failed_k && inet4.verdict != dns::answer_t::failed_k;
        lookup.ttl_seconds = answered ? fu::min_of(lookup.ttl_seconds, fu::min_of(inet6.ttl_seconds, inet4.ttl_seconds))
                                      : 0;
        ++lookup.candidate;
        ask_candidate(client, lookup);
    }

    /** Ends @p lookup with @p resolution, cached for the least TTL its answers relied on. */
    static void finish(client_t& client, client_lookup_t& lookup, resolution_t resolution) noexcept {
        client_origin_t& origin = *lookup.origin;
        std::uint32_t ttl = lookup.ttl_seconds == (std::numeric_limits<std::uint32_t>::max)() ? 0 : lookup.ttl_seconds;
        if (resolution == resolution_t::resolved_k) {
            ttl = (std::numeric_limits<std::uint32_t>::max)();
            for (question_t const& question : lookup.questions)
                if (question.verdict == dns::answer_t::addresses_k) ttl = fu::min_of(ttl, question.ttl_seconds);
        }
        // RFC 1035 §3.2.1: a zero TTL serves only the transaction at hand, which a second covers.
        origin.expires = deadline_after(std::size_t {fu::max_of(ttl, std::uint32_t {1})} * 1'000'000);
        origin.resolution = resolution;
        origin.lookup = nullptr;
        lookup.origin = nullptr;
        lookup.settle_deadline = 0;
        for (question_t& question : lookup.questions) question.stage = question_stage_t::idle_k;
        lookup.next = std::exchange(client.free_lookups, &lookup);
    }
};

} // namespace unum::ucall::network
