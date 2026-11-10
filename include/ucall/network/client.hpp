/**
 *  @file include/ucall/network/client.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief HTTP calls pipelined over pooled peer connections, and the pool homing their responses.
 */
#pragma once

#include <bit> // `std::bit_ceil`

#include <smashtable/atomic_intrusive_stack.hpp> // `atomic_intrusive_stack`
#include <smashtable/basic_hash_index.hpp>       // `basic_hash_index`, `default_hash_t`
#include <smashtable/basic_ring.hpp>             // `basic_ring`

#include "ucall/http/messages.hpp"      // `received_response_t`, `http_parse_t`, `http_connection_t`, `text_view`
#include "ucall/io/types.hpp"           // `io_request_t`, `io_completion_t`
#include "ucall/dns/configuration.hpp"  // `read_system`, `hosts_path`, `resolver_options_t`
#include "ucall/network/formatting.hpp" // `formatting`
#include "ucall/network/resolving.hpp"  // `client_lookup`, `resolving`, `resolution_t`
#include "ucall/network/transports.hpp" // `transport`
#include "ucall/network/types.hpp"      // `transport_stage_t`, `operation_state_t`, `transmit_state_t`
#include "ucall/tunnel/types.hpp"       // `secure_tunnel_geometry_t`, `secure_tunnel_mode_encrypts`
#include "ucall/utilities/sockets.hpp"  // `sockets_start`, `deadline_after`, `monotonic_ns`
#include "ucall/utilities/types.hpp"    // `byte_t`, `span`, `publish`, `allocator_delete`

namespace unum::ucall::network {

using http::http_connection_t;
using http::http_framing_t;
using http::http_parse_t;
using http::http_role_t;
using http::received_response_t;
using http::text_view;
using io::io_completion_t;
using io::io_operation_t;
using io::io_request_t;
using io::io_wait_t;
using tunnel::secure_tunnel_default_payload_k;
using tunnel::secure_tunnel_geometry_t;
using tunnel::secure_tunnel_headroom_k;
using tunnel::secure_tunnel_mode_encrypts;
using tunnel::secure_tunnel_role_t;
using tunnel::secure_tunnel_tailroom_k;
using utilities::allocate_unique;
using utilities::allocator_delete;
using utilities::byte_t;
using utilities::bytes_view;
using utilities::deadline_after;
using utilities::largest_receive_buffer;
using utilities::monotonic_ns;
using utilities::publish;
using utilities::sockets_start;
using utilities::span;
using utilities::text_view;

/** A received response, homed in its client's pool, which a free returns it to. */
template <typename network_type_>
struct response {
    using network_t = network_type_;
    using response_t = typename network_t::response_t;
    using response_pool_t = typename network_t::response_pool_t;
    using client_t = typename network_t::client_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;
    template <typename value_type_>
    using atomic_ref = typename network_t::template atomic_ref<value_type_>;
    explicit response(response_pool_t& home) noexcept
        : storage(rebound_allocator<byte_t> {home.allocator}), pool(&home) {
        static_assert(offsetof(response_t, received) == 0);
        received.destroy = &release;
    }

    /** First, so the handle the C face hands out converts back by its address. */
    received_response_t received;
    vector<byte_t> storage;
    response_t* next {};
    response_pool_t* pool {};

    static void release(received_response_t* response) noexcept {
        auto* owned = reinterpret_cast<response_t*>(response);
        response_pool_t& home = *owned->pool;
        // Home first, so the count never names a response nobody holds.
        home.returned.push(*owned);
        if (atomic_ref<std::size_t> {home.outside}.fetch_sub(1, std::memory_order_acq_rel) == 1)
            client_t::delete_pool(home);
    }
};

/** The home of a client's responses, outliving the client so a response freed late still has
 *  one; @c outside counts responses in callers' hands plus the client's own reference. */
template <typename network_type_>
struct response_pool {
    using network_t = network_type_;
    using allocator_t = typename network_t::allocator_t;
    using response_t = typename network_t::response_t;
    template <typename value_type_>
    using atomic_ref = typename network_t::template atomic_ref<value_type_>;
    explicit response_pool(allocator_t const& allocator) noexcept : allocator(allocator) {}

    st::atomic_intrusive_stack<response_t, atomic_ref> returned {};
    std::size_t outside {1};
    allocator_t allocator;
};

template <typename network_type_>
struct client_exchange {
    using network_t = network_type_;
    using allocator_t = typename network_t::allocator_t;
    using client_exchange_t = typename network_t::client_exchange_t;
    using client_origin_t = typename network_t::client_origin_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;
    explicit client_exchange(allocator_t const& allocator = {}) noexcept
        : authority(rebound_allocator<char> {allocator}), target(rebound_allocator<char> {allocator}),
          host(rebound_allocator<char> {allocator}), redirect(rebound_allocator<char> {allocator}),
          redirect_headers(rebound_allocator<ucall_bytes_view_t> {allocator}) {}
    client_exchange(client_exchange const&) = delete;
    client_exchange& operator=(client_exchange const&) = delete;
    client_exchange(client_exchange&&) = delete;
    client_exchange& operator=(client_exchange&&) = delete;

    ucall_client_call_t arguments {};
    client_exchange_stage_t stage {};
    std::uint64_t deadline {};

    /** The next of its origin's addresses to dial, in RFC 8305 order: AAAA and A alternating. */
    std::uint32_t address_index {};
    std::uint16_t port {};
    vector<char> authority {}, target {}, host {}, redirect {};
    vector<ucall_bytes_view_t> redirect_headers {};
    std::size_t attempts {}, redirects {};
    std::uint64_t authority_hash {};

    /** Close, when the caller's own @c connection header asks to. */
    http_connection_t connection_intent {};

    /** Interned from the authority, security and keys. */
    client_origin_t* origin {};

    /** Idle calls, an origin's waiting calls, or a connection's in order. */
    client_exchange_t* next {};
};

/** What makes two calls share a connection, and the calls waiting for one, earliest deadline
 *  first. A record lives while a call waits on it or a connection remembers it. */
template <typename network_type_>
struct client_origin {
    using network_t = network_type_;
    using allocator_t = typename network_t::allocator_t;
    using client_exchange_t = typename network_t::client_exchange_t;
    using client_origin_t = typename network_t::client_origin_t;
    using client_connection_t = typename network_t::client_connection_t;
    using client_lookup_t = typename network_t::client_lookup_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;
    explicit client_origin(allocator_t const& allocator = {}) noexcept
        : authority(rebound_allocator<char> {allocator}), host(rebound_allocator<char> {allocator}) {}
    client_origin(client_origin const&) = delete;
    client_origin& operator=(client_origin const&) = delete;
    client_origin(client_origin&&) = delete;
    client_origin& operator=(client_origin&&) = delete;

    vector<char> authority {};
    std::uint64_t authority_hash {};
    ucall_security_t security {};

    /** Zeroed when the calls name none. */
    ucall_noise_key_t private_key {}, peer_key {};
    client_exchange_t *waiting_head {}, *waiting_tail {};
    std::size_t waiting {};

    /** Calls its connections could still take, the sum of their credited shares. */
    std::size_t room {};

    /** Connections dialed to it, open or not. */
    std::size_t connections {};

    /** Open connections with room and nothing to send, stepped when a call queues. */
    client_connection_t* accepting_connections {};

    /** Live origins of the client, or free ones oldest first, keeping their
     * answers until reused. */
    client_origin_t *previous {}, *next {};
    origin_list_t list {};

    /** Its host, NUL-terminated, and its port, as the lookup asks and the dials target them. */
    vector<char> host {};
    std::uint16_t port {};
    resolution_t resolution {};

    /** When its answers or its refusal go stale; zero for a numeric host or a hosts-file entry. */
    std::uint64_t expires {};
    std::uint32_t ipv6_count {}, ipv4_count {};
    byte_t ipv6_addresses[origin_addresses_k][16] {};
    byte_t ipv4_addresses[origin_addresses_k][4] {};

    /** Asking for its addresses now, or null. */
    client_lookup_t* lookup {};
};

/** A dialed connection: its transport first, then its origin and pipelined calls. */
template <typename network_type_>
struct client_connection {
    using network_t = network_type_;
    using allocator_t = typename network_t::allocator_t;
    using transport_t = typename network_t::transport_t;
    using client_exchange_t = typename network_t::client_exchange_t;
    using client_origin_t = typename network_t::client_origin_t;
    using client_connection_t = typename network_t::client_connection_t;
    using client_t = typename network_t::client_t;
    explicit client_connection(allocator_t const& allocator = {}) noexcept : transport(allocator) {
        transport.role = transport_role_t::client_k;
        // Measured on Linux AArch64 LP64 with a stateless allocator; other targets go unmeasured.
        if constexpr (UCALL_OS_LINUX_ && UCALL_ARCH_ARM64_ && std::is_empty_v<allocator_t>)
            static_assert(sizeof(client_connection) == 2416);
    }
    client_connection(client_connection const&) = delete;
    client_connection& operator=(client_connection const&) = delete;
    client_connection(client_connection&&) = delete;
    client_connection& operator=(client_connection&&) = delete;

    transport_t transport;

    /** Responses arrive in this order. */
    client_exchange_t* oldest_exchange {};

    /** While sending, its request is the one in @c transport.output. */
    client_exchange_t* newest_exchange {};

    /** Whose connection it is, for a loop routing a bound client's completions. */
    client_t* client {};

    /** Since the dial, telling a reused connection from a fresh one. */
    std::size_t answered_exchanges {};

    /** Of the last dial, kept so an idle connection serves it again. */
    client_origin_t* origin {};

    /** Its share of its origin's room, as of its last step. */
    std::size_t room {};

    /** The client's connections free to dial. */
    client_connection_t *previous_vacant {}, *next_vacant {};

    /** Its origin's connections a queued call steps. */
    client_connection_t *previous_accepting {}, *next_accepting {};

    /** The address its connect dials. */
    sockaddr_storage target {};
    utilities::socket_length_t target_length {};
    std::uint32_t outstanding_exchanges {};

    /** The other connection racing it for one call, the first to open taking the call, or null. */
    client_connection_t* rival {};

    /** RFC 8305 §5: when the next address races this connect, or zero. */
    std::uint64_t race_deadline {};

    /** Links the client's ready queue. */
    client_connection_t* next {};
};

template <typename network_type_>
struct client : ucall_client_handle_t {
    using network_t = network_type_;
    using allocator_t = typename network_t::allocator_t;
    using row_kit_t = typename network_t::row_kit_t;
    using engine_t = typename network_t::engine_t;
    using crypto_t = typename network_t::crypto_t;
    using http_t = typename network_t::http_t;
    using http_message_t = typename network_t::http_message_t;
    using transport_t = typename network_t::transport_t;
    using response_t = typename network_t::response_t;
    using response_pool_t = typename network_t::response_pool_t;
    using client_exchange_t = typename network_t::client_exchange_t;
    using client_origin_t = typename network_t::client_origin_t;
    using client_connection_t = typename network_t::client_connection_t;
    using client_lookup_t = typename network_t::client_lookup_t;
    using client_t = typename network_t::client_t;
    using formatting_t = typename network_t::formatting_t;
    using resolving_t = typename network_t::resolving_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;
    template <typename value_type_>
    using owner = typename network_t::template owner<value_type_>;
    template <typename value_type_>
    using atomic_ref = typename network_t::template atomic_ref<value_type_>;
    using completed_ring_t = st::basic_ring<ucall_completed_call_t, rebound_allocator<ucall_completed_call_t>>;
    using origin_index_t =
        st::basic_hash_index<std::uint64_t, std::uint32_t, st::default_hash_t, rebound_allocator<byte_t>, row_kit_t>;
    allocator_t allocator;
    explicit client(allocator_t const& allocator = {}) noexcept
        : allocator(allocator), owned_engine(allocator), completions(rebound_allocator<io_completion_t> {allocator}),
          completed(rebound_allocator<ucall_completed_call_t> {allocator}),
          connections(rebound_allocator<owner<client_connection_t>> {allocator}),
          hosts(rebound_allocator<char> {allocator}) {}
    client(client const&) = delete;
    client& operator=(client const&) = delete;
    client(client&&) = delete;
    client& operator=(client&&) = delete;

    engine_t owned_engine {};

    /** Its own engine, or the one of the server event loop it is bound to. */
    engine_t* engine {&owned_engine};
    client_binding_t binding {};

    /** Links its loop's bound clients. */
    client_t* next_bound {};
    vector<io_completion_t> completions {};
    completed_ring_t completed {};
    ucall_status_t failure {ucall_status_success_k};
    ucall_client_options_t config {};
    ucall_noise_key_t private_key {};
    vector<owner<client_connection_t>> connections {};
    span<client_exchange_t> exchanges {};

    /** One per call, per connection and per lookup, so interning never runs out. */
    span<client_origin_t> origins {};

    /** One per connection, cold, and the free ones; their requests lie in this span alone. */
    span<client_lookup_t> lookups {};
    client_lookup_t* free_lookups {};

    /** The nameservers, search names and pacing, and the hosts file, both read once at init. */
    dns::resolver_options_t resolver {};
    vector<char> hosts {};

    /** Calls free to submit. */
    client_exchange_t* idle {};

    /** Connections to step, linked through @c next. */
    client_connection_t* ready {};

    /** Connections carrying no call, as of their last step. */
    client_connection_t* vacant_connections {};

    /** At most the earliest deadline of a connection carrying calls. */
    std::uint64_t earliest_connection_deadline {};
    client_origin_t *live {}, *free_origins {}, *newest_free_origin {};

    /** Live origins by @c authority_hash, confirmed against the origin itself. */
    origin_index_t origin_index {};
    std::size_t admitted {};

    /** Where freed responses return, and those taken back from it for the next answers. */
    response_pool_t* responses {};
    response_t* free_responses {};
    ~client() noexcept {
        owned_engine.stop();
        crypto_t::secure_zero(private_key);
        for (auto& connection : connections)
            if (connection) {
                auto& transport = connection->transport;
                if (transport.descriptor >= 0 && !(transport.receive_operation == operation_state_t::submitted_k &&
                                                   transport.receive_request.operation == io_operation_t::close_k &&
                                                   transport.receive_request.descriptor < 0))
                    engine->close_socket(transport.descriptor);
            }
        for (auto& lookup : lookups)
            for (auto& question : lookup.questions)
                if (question.descriptor >= 0) engine->close_socket(question.descriptor);
        for (std::size_t i = 0; i != completed.size(); ++i) ucall_client_response_free(completed[i].response);
        delete_responses(allocator, free_responses);
        if (responses && atomic_ref<std::size_t> {responses->outside}.fetch_sub(1, std::memory_order_acq_rel) == 1)
            delete_pool(*responses);
        connections.clear();
        for (auto& exchange : exchanges) std::destroy_at(&exchange);
        if (!exchanges.empty())
            rebound_allocator<client_exchange_t> {allocator}.deallocate(exchanges.data(), exchanges.size());
        for (auto& origin : origins) {
            crypto_t::secure_zero(origin.private_key);
            std::destroy_at(&origin);
        }
        if (!origins.empty()) rebound_allocator<client_origin_t> {allocator}.deallocate(origins.data(), origins.size());
        for (auto& lookup : lookups) std::destroy_at(&lookup);
        if (!lookups.empty()) rebound_allocator<client_lookup_t> {allocator}.deallocate(lookups.data(), lookups.size());
    }

    /** Frees the responses linked from @p newest through @c next. */
    static void delete_responses(allocator_t const& allocator, response_t* newest) noexcept {
        while (newest) allocator_delete<response_t, allocator_t> {allocator}(std::exchange(newest, newest->next));
    }

    /** Frees every response returned to @p pool, then the pool, once nothing counts on it. */
    static void delete_pool(response_pool_t& pool) noexcept {
        allocator_t const allocator = pool.allocator;
        delete_responses(allocator, pool.returned.take_all());
        allocator_delete<response_pool_t, allocator_t> {allocator}(&pool);
    }
    static ucall_status_t parse_url(client_exchange_t& exchange) noexcept {
        auto url = text_view(exchange.arguments.url);
        auto scheme = http_t::find(url, "://");
        if (scheme == std::string_view::npos) return ucall_status_invalid_argument_k;
        auto protocol = url.substr(0, scheme);
        if (protocol != "http" && protocol != "http+noise") return ucall_status_unsupported_k;
        if (protocol == "http+noise" && exchange.arguments.options.security == ucall_security_none_k)
            exchange.arguments.options.security = ucall_security_noise_xx_k;
        auto rest = url.substr(scheme + 3);
        auto slash = http_t::find(rest, '/'), query = http_t::find(rest, '?'), fragment = http_t::find(rest, '#');
        auto boundary = std::min(slash, std::min(query, fragment));
        auto authority = rest.substr(0, boundary);
        if (authority.empty() || http_t::find(authority, '@') != std::string_view::npos ||
            !http_t::http_value(authority) || http_t::find(authority, ' ') != std::string_view::npos ||
            http_t::find(authority, '\t') != std::string_view::npos ||
            http_t::find(authority, '\0') != std::string_view::npos)
            return ucall_status_invalid_argument_k;
        if (ucall_status_t const copied = formatting_t::copy_text(exchange.authority, authority);
            copied != ucall_status_success_k)
            return copied;
        exchange.authority_hash = http_t::hash(authority);
        auto tail = boundary == std::string_view::npos ? std::string_view {} : rest.substr(boundary);
        fragment = http_t::find(tail, '#');
        tail = tail.substr(0, fragment);
        exchange.target.clear();
        std::string_view const root = tail.empty() || tail.front() != '/' ? "/" : "";
        if (ucall_status_t const appended = http_t::append_text(exchange.target, {root, tail});
            appended != ucall_status_success_k)
            return appended;
        auto host = authority;
        std::string_view port = "80";
        if (host.front() == '[') {
            auto end = http_t::find(host, ']');
            if (end == std::string_view::npos) return ucall_status_invalid_argument_k;
            if (end + 1 < host.size()) {
                if (host[end + 1] != ':') return ucall_status_invalid_argument_k;
                port = host.substr(end + 2);
            }
            host = host.substr(1, end - 1);
        }
        else {
            auto colon = http_t::find(host, ':');
            if (colon != std::string_view::npos) {
                port = host.substr(colon + 1);
                host = host.substr(0, colon);
            }
        }
        unsigned number = 0;
        auto parsed = std::from_chars(port.data(), port.data() + port.size(), number);
        if (parsed.ec != std::errc {} || parsed.ptr != port.data() + port.size() || !number ||
            number > std::numeric_limits<std::uint16_t>::max() || host.empty())
            return ucall_status_invalid_argument_k;
        if (ucall_status_t const copied = formatting_t::copy_text(exchange.host, host);
            copied != ucall_status_success_k)
            return copied;
        exchange.address_index = 0;
        exchange.port = static_cast<std::uint16_t>(number);
        return ucall_status_success_k;
    }

    /** The record layout requests take under @p security, which a dial reads before it
     *  configures the tunnel. */
    static secure_tunnel_geometry_t request_geometry(ucall_security_t security) noexcept {
        bool const framed = secure_tunnel_mode_encrypts(formatting_t::tunnel_mode(security));
        return {.headroom = framed ? secure_tunnel_headroom_k : 0,
                .tailroom = framed ? secure_tunnel_tailroom_k : 0,
                .max_payload = secure_tunnel_default_payload_k};
    }

    /** Appends @p exchange's request to @p output in plain bytes, behind the requests already
     *  there, or leaves @p output as it was on failure. */
    static ucall_status_t append_request(vector<byte_t>& output, client_exchange_t const& exchange) noexcept {
        auto& arguments = exchange.arguments;
        auto target = text_view(exchange.target);
        if (!http_t::http_value(target) || http_t::find(target, ' ') != std::string_view::npos ||
            http_t::find(target, '\t') != std::string_view::npos)
            return ucall_status_invalid_argument_k;
        std::size_t const previous = output.size();
        ucall_status_t result = http_t::append_text(output, {http_t::http_verb_name(arguments.verb),
                                                             " ",
                                                             target,
                                                             " HTTP/1.1\r\nhost: ",
                                                             {exchange.authority.data(), exchange.authority.size() - 1},
                                                             "\r\nuser-agent: UCall\r\n"});
        if (result == ucall_status_success_k)
            result = formatting_t::append_headers(output, {arguments.headers, arguments.headers_count},
                                                  http_role_t::request_k);
        char digits[std::numeric_limits<std::size_t>::digits10 + 1];
        if (result == ucall_status_success_k)
            result = http_t::append_text(
                output, {"content-length: ", formatting_t::format_decimal(digits, arguments.body.length), "\r\n\r\n",
                         text_view(arguments.body)});
        if (result == ucall_status_success_k) return result;
        [[maybe_unused]] st::status_t const shrunk = output.resize(previous);
        return result;
    }

    /** Lays the requests appended after @p output's headroom out as records of @p geometry. */
    static ucall_status_t frame_requests(vector<byte_t>& output, secure_tunnel_geometry_t const& geometry) noexcept {
        if (ucall_status_t const spread = formatting_t::spread_records(output, geometry);
            spread != ucall_status_success_k)
            return spread;
        return st::failed(output.resize(output.size() + geometry.tailroom)) ? ucall_status_out_of_memory_k
                                                                            : ucall_status_success_k;
    }
    static void finish_exchange(client_t& client, client_exchange_t& exchange, ucall_status_t status,
                                response_t* response = nullptr) noexcept {
        // Every completed call was admitted, and admission stops at the ring's capacity.
        [[maybe_unused]] st::status_t const pushed = client.completed.push(
            st::assume_reserved,
            ucall_completed_call_t {exchange.arguments.context,
                                    {status, status == ucall_status_success_k ? nullptr : ucall_status_name(status)},
                                    response ? &response->received : nullptr});
        exchange.address_index = 0;
        exchange.redirect.clear();
        exchange.redirect_headers.clear();
        exchange.origin = nullptr;
        exchange.stage = client_exchange_stage_t::idle_k;
        exchange.next = std::exchange(client.idle, &exchange);
    }

    /** Frees @p origin once no call waits on it, no connection serves it and no lookup asks for it;
     *  it stays indexed with its answers until reused, oldest first. */
    static void retire_origin(client_t& client, client_origin_t& origin) noexcept {
        (origin.previous ? origin.previous->next : client.live) = origin.next;
        if (origin.next) origin.next->previous = origin.previous;
        origin.list = origin_list_t::free_k;
        origin.next = nullptr;
        origin.previous = std::exchange(client.newest_free_origin, &origin);
        (origin.previous ? origin.previous->next : client.free_origins) = &origin;
    }

    /** Unlinks free @p origin, to serve its authority again or another one. */
    static void take_free_origin(client_t& client, client_origin_t& origin) noexcept {
        (origin.previous ? origin.previous->next : client.free_origins) = origin.next;
        (origin.next ? origin.next->previous : client.newest_free_origin) = origin.previous;
        origin.previous = origin.next = nullptr;
    }

    /** Finds or makes the origin of @p exchange. A live origin holds a waiting call or a
     *  connection, so one is free while a call is not admitted. */
    static client_origin_t* intern_origin(client_t& client, client_exchange_t const& exchange) noexcept {
        auto& options = exchange.arguments.options;
        ucall_noise_key_t private_key {}, peer_key {};
        if (options.security != ucall_security_none_k) {
            std::memcpy(private_key,
                        options.noise_private_key ? *options.noise_private_key : *client.config.noise_private_key,
                        sizeof(private_key));
            if (options.noise_peer_key) std::memcpy(peer_key, *options.noise_peer_key, sizeof(peer_key));
        }
        std::uint32_t const found_index = client.origin_index.find(
            exchange.authority_hash, [&](std::uint32_t index) noexcept {
                client_origin_t const& origin = client.origins[index];
                return origin.security == options.security && origin.authority.size() == exchange.authority.size() &&
                       http_t::equal(text_view(origin.authority), text_view(exchange.authority)) &&
                       std::memcmp(origin.private_key, private_key, sizeof(private_key)) == 0 &&
                       std::memcmp(origin.peer_key, peer_key, sizeof(peer_key)) == 0;
            });
        client_origin_t* found = found_index == origin_index_t::absent_k ? nullptr : &client.origins[found_index];
        if (found && found->list == origin_list_t::live_k) {
            crypto_t::secure_zero(private_key);
            return found;
        }
        if (found) take_free_origin(client, *found);
        else {
            // The oldest free origin gives up its authority, its index entry and its answers.
            client_origin_t* const origin = client.free_origins;
            std::uint32_t const index = static_cast<std::uint32_t>(origin - client.origins.data());
            if (!origin->authority.empty()) {
                [[maybe_unused]] st::status_t const erased = client.origin_index.erase(origin->authority_hash, index);
            }
            if (formatting_t::copy_text(origin->authority, {exchange.authority.data(),
                                                            exchange.authority.size() - 1}) != ucall_status_success_k ||
                formatting_t::copy_text(origin->host, {exchange.host.data(), exchange.host.size() - 1}) !=
                    ucall_status_success_k) {
                origin->authority.clear();
                crypto_t::secure_zero(private_key);
                return nullptr;
            }
            take_free_origin(client, *origin);
            origin->authority_hash = exchange.authority_hash;
            origin->security = options.security;
            origin->port = exchange.port;
            origin->resolution = resolution_t::unresolved_k;
            origin->ipv6_count = origin->ipv4_count = 0;
            if (!resolving_t::resolve_numeric(*origin)) origin->expires = 0;
            std::memcpy(origin->private_key, private_key, sizeof(private_key));
            std::memcpy(origin->peer_key, peer_key, sizeof(peer_key));
            [[maybe_unused]] st::status_t const indexed = client.origin_index.insert(exchange.authority_hash, index,
                                                                                     st::assume_unique);
            found = origin;
        }
        found->list = origin_list_t::live_k;
        found->next = std::exchange(client.live, found);
        if (found->next) found->next->previous = found;
        crypto_t::secure_zero(private_key);
        return found;
    }

    /** Dials the address of @p connection's one call, whose request @c output already holds. */
    static ucall_status_t dial_connection(client_t& client, client_connection_t& connection,
                                          client_exchange_t& exchange) noexcept {
        auto& transport = connection.transport;
        client_origin_t const& origin = *connection.origin;
        while (exchange.address_index < resolving_t::addresses_count(origin)) {
            connection.target_length = resolving_t::target(origin, exchange.address_index, connection.target);
            auto descriptor = client.engine->open_socket(connection.target.ss_family);
            if (descriptor < 0) {
                ++exchange.address_index;
                continue;
            }
            auto& options = exchange.arguments.options;
            auto* key = options.noise_private_key ? options.noise_private_key : client.config.noise_private_key;
            auto config = formatting_t::tunnel_config(options.security, secure_tunnel_role_t::initiator_k, key, nullptr,
                                                      options.noise_peer_key);
            auto result = transport.configure(config, &connection);
            if (result != ucall_status_success_k) {
                client.engine->close_socket(descriptor);
                return result;
            }
            transport.descriptor = descriptor;
            transport.receive_memory = client.engine->receive_memory();
            connection.answered_exchanges = 0;
            transport.output_offset = 0;
            transport.sending = nullptr;
            transport.message = {};
            transport.peer_stream = peer_stream_t::writing_k;
            transport.stage = transport_stage_t::connecting_k;
            transport.transmitting = transmit_state_t::sending_k;
            transport.status = ucall_status_success_k;
            transport.authorizer = client.config.peer_authorizer;
            transport.authorizer_context = client.config.peer_authorizer_context;
            transport.deadline = std::min(exchange.deadline,
                                          deadline_after(client.config.connect_timeout_microseconds));
            transport.transmit_request = {.operation = io_operation_t::connect_k,
                                          .descriptor = descriptor,
                                          .data = reinterpret_cast<byte_t*>(&connection.target),
                                          .length = static_cast<std::size_t>(connection.target_length),
                                          .deadline = transport.deadline,
                                          .context = &connection};
            // A later address, even one answered after this dial, races a connect past
            // RFC 8305's delay.
            connection.race_deadline = deadline_after(dns::connection_attempt_delay_microseconds_k);
            return ucall_status_success_k;
        }
        return ucall_status_connection_failed_k;
    }
    static ucall_status_t redirect_exchange(client_exchange_t& exchange, http_message_t const& message,
                                            std::string_view text) noexcept {
        auto location = message.header(text, "location");
        if (location.empty()) return ucall_status_not_found_k;
        auto maximum = exchange.arguments.options.max_redirects ? exchange.arguments.options.max_redirects : 5;
        if (exchange.redirects++ >= maximum) return ucall_status_malformed_k;
        auto previous = text_view(exchange.arguments.url);
        auto scheme = http_t::find(previous, "://");
        auto origin_end = scheme + 3 + exchange.authority.size() - 1;
        vector<char> next {exchange.redirect.get_allocator()};
        ucall_status_t appended = ucall_status_success_k;
        if (http_t::find(location, "://") != std::string_view::npos) appended = http_t::append_text(next, {location});
        else if (location.starts_with("//"))
            appended = http_t::append_text(next, {previous.substr(0, scheme + 1), location});
        else {
            std::string_view directory {};
            auto path = text_view(exchange.target);
            path = path.substr(0, http_t::find(path, '?'));
            // RFC 3986 5.2.2: a reference holding only a query keeps the whole base path.
            if (location.front() == '?') directory = path;
            else if (location.front() != '/') {
                auto last = http_t::rfind(path, '/');
                directory = last != path.npos ? path.substr(0, last + 1) : "/";
            }
            appended = http_t::append_text(next, {previous.substr(0, origin_end), directory, location});
        }
        if (appended != ucall_status_success_k) return appended;
        if (exchange.arguments.options.security != ucall_security_none_k &&
            !text_view(next).starts_with("http+noise://"))
            return ucall_status_peer_rejected_k;
        exchange.redirect = std::move(next);
        exchange.arguments.url = bytes_view(text_view(exchange.redirect));
        if (message.status == 303 ||
            ((message.status == 301 || message.status == 302) && exchange.arguments.verb == ucall_verb_post_k)) {
            if (exchange.arguments.verb != ucall_verb_head_k) exchange.arguments.verb = ucall_verb_get_k;
            exchange.arguments.body = {};
        }
        // Credentials belong to the caller's original origin, never to a redirect target.
        vector<ucall_bytes_view_t> safe_headers {exchange.redirect_headers.get_allocator()};
        for (std::size_t i = 0; i != exchange.arguments.headers_count; ++i) {
            auto header = exchange.arguments.headers[i];
            auto name = text_view(header).substr(0, http_t::find(text_view(header), ':'));
            if (http_t::equal_ascii_uncased(name, "authorization") ||
                http_t::equal_ascii_uncased(name, "proxy-authorization") || http_t::equal_ascii_uncased(name, "cookie"))
                continue;
            if (st::failed(safe_headers.push_back(std::move(header)))) return ucall_status_out_of_memory_k;
        }
        exchange.redirect_headers = std::move(safe_headers);
        exchange.arguments.headers = exchange.redirect_headers.data();
        exchange.arguments.headers_count = exchange.redirect_headers.size();
        return parse_url(exchange);
    }

    /** Appends @p exchange to @p connection's calls, whose earliest deadline becomes the
     *  connection's; its request is composed into @c output before it starts sending. */
    static void push_call(client_connection_t& connection, client_exchange_t& exchange) noexcept {
        exchange.stage = client_exchange_stage_t::pipelined_k;
        std::uint64_t& deadline = connection.transport.deadline;
        deadline = connection.oldest_exchange ? std::min(deadline, exchange.deadline) : exchange.deadline;
        if (connection.newest_exchange) connection.newest_exchange->next = &exchange;
        else connection.oldest_exchange = &exchange;
        connection.newest_exchange = &exchange;
        ++connection.outstanding_exchanges;
    }

    /** Unlinks @p connection's oldest call, and moves the connection's deadline to the earliest of
     *  the calls left, a walk over at most @c max_pipelined_calls of them. */
    static client_exchange_t& pop_call(client_connection_t& connection) noexcept {
        auto& exchange = *connection.oldest_exchange;
        connection.oldest_exchange = std::exchange(exchange.next, nullptr);
        if (!connection.oldest_exchange) connection.newest_exchange = nullptr;
        --connection.outstanding_exchanges;
        std::uint64_t deadline = 0;
        for (client_exchange_t const* left = connection.oldest_exchange; left; left = left->next)
            deadline = deadline ? std::min(deadline, left->deadline) : left->deadline;
        connection.transport.deadline = deadline;
        return exchange;
    }

    /** Lists @p connection to be stepped in the round's next pass, once. */
    static void mark_ready(client_t& client, client_connection_t& connection) noexcept {
        transport_t& transport = connection.transport;
        if (transport.readiness == listing_t::listed_k) return;
        transport.readiness = listing_t::listed_k;
        connection.next = std::exchange(client.ready, &connection);
    }

    /** Queues @p exchange on its origin by deadline, behind every waiting call due no later,
     *  and readies the origin's accepting connections to take it. Equal timeouts append
     *  every new call. */
    static void queue_call(client_t& client, client_exchange_t& exchange) noexcept {
        client_origin_t& origin = *exchange.origin;
        for (client_connection_t* connection = std::exchange(origin.accepting_connections, nullptr); connection;) {
            client_connection_t& current = *connection;
            connection = std::exchange(current.next_accepting, nullptr);
            current.previous_accepting = nullptr;
            mark_ready(client, current);
        }
        exchange.stage = client_exchange_stage_t::waiting_k;
        client_exchange_t* previous = nullptr;
        if (origin.waiting_tail && origin.waiting_tail->deadline <= exchange.deadline) previous = origin.waiting_tail;
        else
            for (auto* waiting = origin.waiting_head; waiting && waiting->deadline <= exchange.deadline;
                 waiting = waiting->next)
                previous = waiting;
        exchange.next = previous ? previous->next : origin.waiting_head;
        (previous ? previous->next : origin.waiting_head) = &exchange;
        if (!exchange.next) origin.waiting_tail = &exchange;
        ++origin.waiting;
    }

    /** Unlinks the call of @p origin due first. */
    static client_exchange_t& unqueue_call(client_origin_t& origin) noexcept {
        client_exchange_t& exchange = *origin.waiting_head;
        origin.waiting_head = std::exchange(exchange.next, nullptr);
        if (!origin.waiting_head) origin.waiting_tail = nullptr;
        --origin.waiting;
        return exchange;
    }
    static std::size_t retry_budget(client_exchange_t const& exchange) noexcept {
        return exchange.arguments.options.max_retries ? exchange.arguments.options.max_retries : 3;
    }

    /** Whether the server may act on @p exchange twice to the same effect, per RFC 9110 §9.2.2. */
    static bool idempotent(client_exchange_t const& exchange) noexcept {
        ucall_verb_t verb = exchange.arguments.verb;
        return verb == ucall_verb_get_k || verb == ucall_verb_head_k || verb == ucall_verb_put_k ||
               verb == ucall_verb_delete_k || verb == ucall_verb_options_k;
    }

    /** Whether the caller's own @p headers ask to close the connection after the call. */
    static http_connection_t parse_connection_intent(span<ucall_bytes_view_t const> headers) noexcept {
        for (ucall_bytes_view_t const header : headers) {
            if (!http_t::valid_view(header)) continue;
            std::string_view line = text_view(header);
            std::size_t colon = http_t::find(line, ':');
            if (colon != std::string_view::npos && http_t::equal_ascii_uncased(line.substr(0, colon), "connection") &&
                http_t::http_has_token(line.substr(colon + 1), "close"))
                return http_connection_t::close_k;
        }
        return http_connection_t::keep_alive_k;
    }

    /** Whether @p connection may pipeline one more call: below the depth, and behind no call that
     *  closes the connection or, per RFC 9112 §9.3.2, cannot be replayed. */
    static bool accepts_another_exchange(client_t const& client, client_connection_t const& connection) noexcept {
        client_exchange_t const* newest = connection.newest_exchange;
        return connection.outstanding_exchanges < client.config.max_pipelined_calls &&
               (!newest || (newest->connection_intent == http_connection_t::keep_alive_k && idempotent(*newest)));
    }

    /** Whether a call older than the one being sent waits for its response. */
    static bool awaits_response(client_connection_t const& connection) noexcept {
        return connection.outstanding_exchanges >
               (connection.transport.transmitting == transmit_state_t::sending_k ? 1u : 0u);
    }

    /** Whether @p connection carries no call, so a call of any origin may take it,
     *  though an open connection keeps a receive posted meanwhile. */
    static bool connection_vacant(client_connection_t const& connection) noexcept {
        auto stage = connection.transport.stage;
        return !connection.oldest_exchange &&
               (stage == transport_stage_t::idle_k || stage == transport_stage_t::open_k ||
                stage == transport_stage_t::closed_k);
    }

    /** Calls @p connection could take on top of those it carries, by @c accepts_another_exchange,
     *  counting a connection still dialing at its full depth. */
    static std::size_t connection_room(client_t const& client, client_connection_t const& connection) noexcept {
        auto& transport = connection.transport;
        bool const carrying = transport.descriptor >= 0 && transport.receiving == receive_state_t::reading_k &&
                              (transport.stage == transport_stage_t::connecting_k ||
                               transport.stage == transport_stage_t::handshake_k ||
                               transport.stage == transport_stage_t::open_k);
        return carrying && accepts_another_exchange(client, connection)
                   ? client.config.max_pipelined_calls - connection.outstanding_exchanges
                   : 0;
    }

    /** Sets @p connection's share of its origin's room to what it could take now. */
    static void credit_room(client_t const& client, client_connection_t& connection) noexcept {
        std::size_t const room = connection_room(client, connection);
        connection.origin->room = connection.origin->room - connection.room + room;
        connection.room = room;
    }
    static void unlist_accepting(client_origin_t& origin, client_connection_t& connection) noexcept {
        (connection.previous_accepting ? connection.previous_accepting->next_accepting
                                       : origin.accepting_connections) = connection.next_accepting;
        if (connection.next_accepting) connection.next_accepting->previous_accepting = connection.previous_accepting;
        connection.previous_accepting = connection.next_accepting = nullptr;
    }

    /** Moves @p connection, with its share of room, from the origin it served to @p origin. */
    static void assign_origin(client_t& client, client_connection_t& connection, client_origin_t& origin) noexcept {
        client_origin_t* const previous = std::exchange(connection.origin, &origin);
        if (previous == &origin) return;
        ++origin.connections;
        origin.room += connection.room;
        if (!previous) return;
        previous->room -= connection.room;
        if (connection.previous_accepting || previous->accepting_connections == &connection)
            unlist_accepting(*previous, connection);
        if (!--previous->connections && !previous->waiting && !previous->lookup) retire_origin(client, *previous);
    }

    /** Files @p connection after its step where the rounds look for it: its share of
     *  room, its origin's accepting connections, the client's vacant ones, and the
     *  earliest connection deadline. */
    static void list_connection(client_t& client, client_connection_t& connection) noexcept {
        transport_t const& transport = connection.transport;
        if (client_origin_t* const origin = connection.origin) {
            credit_room(client, connection);
            bool const accepting = connection.room && transport.stage == transport_stage_t::open_k &&
                                   transport.transmitting == transmit_state_t::idle_k;
            bool const listed = connection.previous_accepting || origin->accepting_connections == &connection;
            if (accepting && !listed) {
                connection.next_accepting = std::exchange(origin->accepting_connections, &connection);
                if (connection.next_accepting) connection.next_accepting->previous_accepting = &connection;
            }
            else if (!accepting && listed) unlist_accepting(*origin, connection);
        }
        bool const listed = connection.previous_vacant || client.vacant_connections == &connection;
        if (connection_vacant(connection) && !listed) {
            connection.next_vacant = std::exchange(client.vacant_connections, &connection);
            if (connection.next_vacant) connection.next_vacant->previous_vacant = &connection;
        }
        else if (!connection_vacant(connection) && listed) {
            (connection.previous_vacant ? connection.previous_vacant->next_vacant
                                        : client.vacant_connections) = connection.next_vacant;
            if (connection.next_vacant) connection.next_vacant->previous_vacant = connection.previous_vacant;
            connection.previous_vacant = connection.next_vacant = nullptr;
        }
        std::uint64_t& earliest = client.earliest_connection_deadline;
        if (connection.oldest_exchange && (!earliest || connection_due(connection) < earliest))
            earliest = connection_due(connection);
    }

    /** When @p connection, carrying a call, next needs a step: its deadline, or a
     * stalled connect's race. */
    static std::uint64_t connection_due(client_connection_t const& connection) noexcept {
        std::uint64_t const deadline = connection.transport.deadline;
        return connection.race_deadline && connection.race_deadline < deadline ? connection.race_deadline : deadline;
    }

    /** Races @p connection's stalled connect with its call's next address on a fresh
     *  vacant connection, so the first to open takes the call; with none vacant, the
     *  attempts stay sequential. */
    static void start_rival(client_t& client, client_connection_t& connection) noexcept {
        connection.race_deadline = 0;
        client_exchange_t& exchange = *connection.oldest_exchange;
        client_origin_t& origin = *connection.origin;
        client_connection_t* rival = client.vacant_connections;
        while (rival && !(connection_vacant(*rival) && rival->transport.descriptor < 0 && rival != &connection))
            rival = rival->next_vacant;
        if (!rival || exchange.address_index + 1 >= resolving_t::addresses_count(origin)) return;
        assign_origin(client, *rival, origin);
        ++exchange.address_index;
        if (compose_request(rival->transport.output, exchange, request_geometry(origin.security)) !=
                ucall_status_success_k ||
            dial_connection(client, *rival, exchange) != ucall_status_success_k)
            return;
        rival->rival = &connection;
        connection.rival = rival;
        mark_ready(client, *rival);
    }

    /** The first of two racing connections to open takes their call, and the other closes. */
    static void settle_race(client_t& client, client_connection_t& winner) noexcept {
        client_connection_t& loser = *std::exchange(winner.rival, nullptr);
        loser.rival = nullptr;
        if (!winner.oldest_exchange) push_call(winner, pop_call(loser));
        loser.transport.fail(ucall_status_success_k);
        mark_ready(client, loser);
    }

    /** Lays @p exchange's request into @p output as the first one a fresh connection sends. */
    static ucall_status_t compose_request(vector<byte_t>& output, client_exchange_t const& exchange,
                                          secure_tunnel_geometry_t const& geometry) noexcept {
        output.clear();
        ucall_status_t result = st::failed(output.resize(geometry.headroom)) ? ucall_status_out_of_memory_k
                                                                             : ucall_status_success_k;
        if (result == ucall_status_success_k) result = append_request(output, exchange);
        if (result == ucall_status_success_k) result = frame_requests(output, geometry);
        return result;
    }

    /** Dials @p connection, which carries no call, for the call of @p origin due first. */
    static void dial_call(client_t& client, client_connection_t& connection, client_origin_t& origin) noexcept {
        assign_origin(client, connection, origin);
        client_exchange_t& exchange = unqueue_call(origin);
        mark_ready(client, connection);
        ucall_status_t result = compose_request(connection.transport.output, exchange,
                                                request_geometry(origin.security));
        if (result == ucall_status_success_k) {
            push_call(connection, exchange);
            result = dial_connection(client, connection, exchange);
            if (result != ucall_status_success_k) pop_call(connection);
        }
        if (result != ucall_status_success_k) finish_exchange(client, exchange, result);
        credit_room(client, connection);
    }

    /** A response for the next answer: one freed back to the pool, else a new one homed there. */
    static response_t* take_response(client_t& client) noexcept {
        if (!client.free_responses) client.free_responses = client.responses->returned.take_all();
        response_t* response = client.free_responses;
        if (response) {
            client.free_responses = response->next;
            response->storage.clear();
        }
        else response = allocate_unique<response_t>(client.allocator, *client.responses).release();
        if (response) atomic_ref<std::size_t> {client.responses->outside}.add(1, std::memory_order_relaxed);
        return response;
    }

    /** Answers @p connection's oldest call with the whole response at @p offset of @c input:
     *  a redirect queues the call again as a fresh one, and any other response completes it. */
    static void answer_call(client_t& client, client_connection_t& connection, std::size_t offset) noexcept {
        auto& transport = connection.transport;
        auto& message = transport.message;
        auto& exchange = *connection.oldest_exchange;
        auto code = message.status;
        ucall_status_t status = ucall_status_not_found_k;
        if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
            auto const text = transport.text().substr(offset);
            status = redirect_exchange(exchange, message, text);
            char digits[std::numeric_limits<unsigned>::digits10 + 1];
            if (status != ucall_status_not_found_k && status != ucall_status_success_k)
                formatting_t::log_line(client.config.log, ucall_log_level_warning_k, "redirect_refused",
                                       {{"status", formatting_t::format_decimal(digits, code)},
                                        {"location", message.header(text, "location")}});
        }
        response_t* response = nullptr;
        if (status == ucall_status_not_found_k) {
            response = take_response(client);
            if (!response) return transport.fail(ucall_status_out_of_memory_k);
            if (!offset && message.wire_length == transport.input.size() &&
                transport.input_may_leave(message.wire_length)) {
                std::swap(response->storage, transport.input);
            }
            else if (ucall_status_t const appended = http_t::append_text(
                         response->storage, {text_view(transport.input).substr(offset, message.wire_length)});
                     appended != ucall_status_success_k) {
                response_t::release(&response->received);
                return transport.fail(appended);
            }
            response->received.headers_length = message.headers_length;
            response->received.body_length = message.body_length;
            response->received.status = code;
            response->received.content = response->storage;
            status = ucall_status_success_k;
        }
        ++connection.answered_exchanges;
        if (!message.keep_alive() || exchange.connection_intent == http_connection_t::close_k)
            transport.fail(ucall_status_success_k);
        message = {};
        pop_call(connection);
        if (status != ucall_status_success_k || response) return finish_exchange(client, exchange, status, response);
        exchange.origin = intern_origin(client, exchange);
        if (!exchange.origin) return finish_exchange(client, exchange, ucall_status_out_of_memory_k);
        exchange.attempts = 0;
        queue_call(client, exchange);
    }

    /** Steps an open client connection, answering its next engine request or null, by these rules
     *  in order:
     *  C1 responses: while reading and a sent call awaits, each whole response answers the oldest
     *     call, a redirect queueing it again as a fresh call; a response without keep-alive, or to
     *     a call that asked to close, closes the connection.
     *  C2 requests: while reading, an idle transmit side composes every call of the origin's queue
     *     that @c accepts_another_exchange lets this connection carry into @c output, appending
     *     each to the FIFO, so one send takes them all.
     *  C3 emit: while reading, the next chunk of those requests while its send is idle, else a
     *     receive, posted even with no call so a peer close is seen before reuse.
     *  C4 done: a peer close, or bytes no call asked for, close the connection, losing any call
     *     still on the FIFO; with the FIFO empty and the side reading, the connection stays open.
     *  C5 loss: @c call_lost settles the calls of the closed connection. */
    static io_request_t* call_open(client_t& client, client_connection_t& connection) noexcept {
        auto& transport = connection.transport;
        auto& input = transport.input;
        if (transport.transmitting == transmit_state_t::sending_k &&
            transport.transmit_operation == operation_state_t::idle_k && !transport.sending &&
            transport.output_offset == transport.output.size())
            transport.transmitting = transmit_state_t::idle_k;
        transport.open_records();
        // Responses answered this round, erased from `input` once after it rather than one by one.
        std::size_t consumed = 0;
        while (transport.stage == transport_stage_t::open_k && transport.receiving == receive_state_t::reading_k &&
               awaits_response(connection)) {
            auto role = connection.oldest_exchange->arguments.verb == ucall_verb_head_k ? http_role_t::head_response_k
                                                                                        : http_role_t::response_k;
            span<byte_t> unparsed {input.data() + consumed, input.data() + input.size()};
            auto parsed = http_t::http_parse(unparsed, transport.message, role);
            auto const& message = transport.message;
            auto const cap = client.config.max_response_bytes;
            // Bounded as a server bounds requests: a declared length up front, anything else
            // as it arrives.
            bool const fits = message.headers_length && message.framing == http_framing_t::length_k
                                  ? message.content_length <= cap - std::min(cap, message.headers_length)
                                  : (parsed == http_parse_t::complete_k ? message.wire_length : unparsed.size()) <= cap;
            if (!fits && (parsed == http_parse_t::incomplete_k || parsed == http_parse_t::complete_k))
                parsed = http_parse_t::overflow_k;
            if (parsed == http_parse_t::incomplete_k && transport.peer_stream == peer_stream_t::closed_k) {
                // Over Noise only a close record, never a bare end of stream, may end a response.
                if (!transport.message.headers_length || transport.message.framing != http_framing_t::until_close_k ||
                    (transport.tunnel.encrypts() && transport.tunnel.may_open())) {
                    transport.fail(ucall_status_connection_closed_k);
                    break;
                }
                transport.message.body_length = unparsed.size() - transport.message.headers_length;
                transport.message.wire_length = unparsed.size();
                parsed = http_parse_t::complete_k;
            }
            if (parsed == http_parse_t::incomplete_k) break;
            if (parsed != http_parse_t::complete_k || transport.message.status == 101) {
                transport.fail(parsed == http_parse_t::overflow_k ? ucall_status_overflow_k
                               : parsed == http_parse_t::unsupported_k ||
                                       parsed == http_parse_t::unsupported_version_k ||
                                       parsed == http_parse_t::complete_k
                                   ? ucall_status_unsupported_k
                                   : ucall_status_malformed_k);
                break;
            }
            if (transport.message.status < 200) {
                consumed += transport.message.wire_length;
                transport.message = {};
                continue;
            }
            http_t::http_decode_chunks(unparsed, transport.message);
            auto wire = transport.message.wire_length;
            answer_call(client, connection, consumed);
            consumed = input.empty() ? 0 : consumed + wire;
        }
        if (consumed) http_t::drop_bytes(input, consumed);
        transport.aim_receive();
        if (transport.stage != transport_stage_t::open_k) return transport.advance();
        if (transport.peer_stream == peer_stream_t::closed_k || (!connection.oldest_exchange && !input.empty()))
            transport.receiving = receive_state_t::ended_k;
        if (transport.receiving == receive_state_t::reading_k) {
            client_origin_t& origin = *connection.origin;
            if (transport.transmitting == transmit_state_t::idle_k && origin.waiting_head &&
                accepts_another_exchange(client, connection)) {
                secure_tunnel_geometry_t const geometry = request_geometry(origin.security);
                auto& output = transport.output;
                output.clear();
                if (st::failed(output.resize(geometry.headroom))) transport.fail(ucall_status_out_of_memory_k);
                client_exchange_t* const newest = connection.newest_exchange;
                while (transport.stage == transport_stage_t::open_k && origin.waiting_head &&
                       accepts_another_exchange(client, connection)) {
                    client_exchange_t& exchange = unqueue_call(origin);
                    if (ucall_status_t const appended = append_request(output, exchange);
                        appended != ucall_status_success_k)
                        finish_exchange(client, exchange, appended);
                    else push_call(connection, exchange);
                }
                if (connection.newest_exchange != newest) {
                    if (ucall_status_t const framed = frame_requests(output, geometry);
                        framed != ucall_status_success_k)
                        transport.fail(framed);
                    transport.transmitting = transmit_state_t::sending_k;
                    transport.output_offset = 0;
                }
                if (transport.stage != transport_stage_t::open_k) return transport.advance();
            }
            if (transport.transmitting == transmit_state_t::sending_k &&
                transport.transmit_operation == operation_state_t::idle_k) {
                if (auto* next = transport.transmit_from(transport.output)) return next;
                // Sealing failed the connection.
                return transport.advance();
            }
            if (transport.receive_operation == operation_state_t::idle_k) return transport.emit_receive();
            return nullptr;
        }
        transport.fail(connection.oldest_exchange ? ucall_status_connection_closed_k : ucall_status_success_k);
        return transport.advance();
    }

    /** Settles the calls of @p connection's closed connection at @p now, rule C5 of @c call_open:
     *  - a failed connect queues its one call again on the next address or attempt;
     *  - a call past its deadline finishes with @c ucall_status_timeout_k;
     *  - after a close the server announced, every unread call queues again, as RFC 9112 §9.6 bars
     *    the server from processing it;
     *  - a lost connection, or one dropped for a later call's deadline, queues its idempotent calls
     *    again within their retry budget, and its oldest call too when a reused connection read no
     *    byte of its response, as the server had closed before the request reached it;
     *  - the oldest of the rest finishes with the connection's failure, and the others with
     *    @c ucall_status_connection_closed_k. */
    static void call_lost(client_t& client, client_connection_t& connection, std::uint64_t now) noexcept {
        transport_t& transport = connection.transport;
        ucall_status_t status = transport.status;
        // A timeout with several calls aboard expired one of them and dropped the rest with it.
        bool const lost = status == ucall_status_connection_closed_k || status == ucall_status_io_k ||
                          (status == ucall_status_timeout_k &&
                           connection.oldest_exchange != connection.newest_exchange);
        bool const unread = lost && connection.answered_exchanges && transport.input.empty() &&
                            transport.encrypted.empty();
        if (status == ucall_status_handshake_failed_k)
            formatting_t::log_line(client.config.log, ucall_log_level_warning_k, "handshake_failed",
                                   {{"fault", tunnel::secure_tunnel_fault_name(transport.tunnel.fault())}});
        if (client_connection_t* const rival = std::exchange(connection.rival, nullptr)) {
            rival->rival = nullptr;
            // A rival still dialing takes the call this connect could not deliver.
            if (status == ucall_status_connection_failed_k) {
                push_call(*rival, pop_call(connection));
                mark_ready(client, *rival);
                return;
            }
            rival->transport.fail(ucall_status_success_k);
            mark_ready(client, *rival);
        }
        for (bool oldest = true; connection.oldest_exchange; oldest = false) {
            auto& exchange = pop_call(connection);
            ucall_status_t outcome = oldest ? status : ucall_status_connection_closed_k;
            if (status == ucall_status_connection_failed_k) {
                // A connection carries no second call before it opens, so this request never left.
                std::uint32_t const addresses = resolving_t::addresses_count(*exchange.origin);
                if (++exchange.address_index >= addresses && exchange.attempts++ < retry_budget(exchange))
                    exchange.address_index = 0;
                if (exchange.address_index < addresses) queue_call(client, exchange);
                else
                    formatting_t::log_line(client.config.log, ucall_log_level_warning_k, "connect_failed",
                                           {{"address", {exchange.authority.data(), exchange.authority.size() - 1}},
                                            {"status", ucall_status_name(status)}});
            }
            else if (now >= exchange.deadline) outcome = ucall_status_timeout_k;
            else if (status == ucall_status_success_k ||
                     ((lost || !oldest) && (idempotent(exchange) || (oldest && unread)) &&
                      exchange.attempts++ < retry_budget(exchange))) {
                exchange.address_index = 0;
                queue_call(client, exchange);
            }
            if (exchange.stage != client_exchange_stage_t::waiting_k) finish_exchange(client, exchange, outcome);
        }
    }

    /** Advances one client connection as @c advance_connection advances a server's,
     *  submitting each request it asks for. */
    static void step_connection(client_t& client, client_connection_t& connection, std::uint64_t now) noexcept {
        auto& transport = connection.transport;
        // A pending receive keeps the deadline it was posted with, which a later call may undercut.
        if (transport.stage == transport_stage_t::open_k && connection.oldest_exchange && now >= transport.deadline)
            transport.fail(ucall_status_timeout_k);
        if (transport.stage == transport_stage_t::connecting_k && connection.oldest_exchange && !connection.rival &&
            connection.race_deadline && now >= connection.race_deadline)
            start_rival(client, connection);
        for (;;) {
            auto* next = transport.advance();
            if (!next && transport.stage == transport_stage_t::open_k) {
                if (connection.rival) settle_race(client, connection);
                next = call_open(client, connection);
            }
            if (!next) break;
            // A failed submission is retried on the next pass rather than this one.
            if (client.engine->submit(*next) != ucall_status_success_k) {
                mark_ready(client, connection);
                break;
            }
            transport.submitted(*next);
        }
        // The close waits until the other direction's operation completes or is cancelled.
        if (transport.stage == transport_stage_t::closing_k) {
            if (transport.receive_operation == operation_state_t::submitted_k &&
                transport.receive_request.operation != io_operation_t::close_k)
                client.engine->cancel(transport.receive_request);
            if (transport.transmit_operation == operation_state_t::submitted_k)
                client.engine->cancel(transport.transmit_request);
        }
        if (transport.stage == transport_stage_t::closed_k && connection.oldest_exchange)
            call_lost(client, connection, now);
        // A rival that lost its own connect leaves its connection dialing alone.
        if (transport.stage == transport_stage_t::closed_k && connection.rival) {
            connection.rival->rival = nullptr;
            connection.rival = nullptr;
        }
        if (transport.stage != transport_stage_t::connecting_k) connection.race_deadline = 0;
        list_connection(client, connection);
    }
    static void advance_completion(engine_t& engine, io_completion_t const& completion) noexcept {
        auto& connection = *static_cast<client_connection_t*>(completion.request->context);
        transport_t& transport = connection.transport;
        bool const connected = transport.stage == transport_stage_t::connecting_k && completion.result >= 0;
        transport.complete(completion, connection.client->config.max_response_bytes);
        if (connected && connection.oldest_exchange) transport.deadline = connection.oldest_exchange->deadline;
        engine.release(completion);
    }
    static void step_ready_connections(client_t& client, std::uint64_t now) noexcept {
        for (client_connection_t* connection = std::exchange(client.ready, nullptr); connection;) {
            client_connection_t& current = *connection;
            connection = std::exchange(current.next, nullptr);
            current.transport.readiness = listing_t::unlisted_k;
            step_connection(client, current, now);
        }
    }

    /** Hands vacant connections to the origins waiting for more calls than their room, the one due
     *  first each time: a fresh connection dials, else an idle connection to an origin with nothing
     *  waiting closes, holding its room for the needy origin until it has closed and dials. */
    static void dial_vacant_connections(client_t& client) noexcept {
        client_connection_t *fresh = client.vacant_connections, *idle = client.vacant_connections;
        for (;;) {
            client_origin_t* neediest = nullptr;
            for (client_origin_t* origin = client.live; origin; origin = origin->next)
                if (origin->waiting > origin->room && origin->resolution == resolution_t::resolved_k &&
                    (!neediest || origin->waiting_head->deadline < neediest->waiting_head->deadline))
                    neediest = origin;
            if (!neediest) return;
            while (fresh && !(connection_vacant(*fresh) && fresh->transport.descriptor < 0)) fresh = fresh->next_vacant;
            if (fresh) {
                dial_call(client, *std::exchange(fresh, fresh->next_vacant), *neediest);
                continue;
            }
            while (idle && !(connection_vacant(*idle) && idle->transport.descriptor >= 0 &&
                             (!idle->origin || !idle->origin->waiting)))
                idle = idle->next_vacant;
            if (!idle) return;
            client_connection_t& closing = *std::exchange(idle, idle->next_vacant);
            closing.transport.fail(ucall_status_success_k);
            assign_origin(client, closing, *neediest);
            mark_ready(client, closing);
        }
    }
    static std::uint64_t client_progress(client_t& client) noexcept {
        auto now = monotonic_ns();
        // A connection deadline that rose leaves the earliest stale but early, so it is
        // folded once due.
        if (std::uint64_t& earliest = client.earliest_connection_deadline; earliest && now >= earliest) {
            earliest = 0;
            for (auto& connection : client.connections) {
                if (!connection->oldest_exchange) continue;
                if (now >= connection_due(*connection)) mark_ready(client, *connection);
                else if (!earliest || connection_due(*connection) < earliest) earliest = connection_due(*connection);
            }
        }
        // Completions only record bytes, so ready connections answer and take calls before
        // the rest dial.
        step_ready_connections(client, now);
        // Each origin's queue runs by deadline, so expiry and the next wake-up read only its front.
        std::uint64_t deadline = 0;
        for (client_origin_t* origin = client.live; origin;) {
            client_origin_t& current = *origin;
            origin = current.next;
            while (current.waiting_head && now >= current.waiting_head->deadline)
                finish_exchange(client, unqueue_call(current), ucall_status_timeout_k);
            // A stale answer is asked again before any dial, and a cached refusal answers
            // every waiting call.
            if (current.waiting_head) resolving_t::refresh(client, current, now);
            while (current.waiting_head && current.resolution == resolution_t::refused_k)
                finish_exchange(client, unqueue_call(current), ucall_status_not_found_k);
            if (current.waiting_head) {
                std::uint64_t const due = std::min(current.waiting_head->deadline, resolving_t::due(current));
                deadline = !deadline ? due : std::min(deadline, due);
            }
            else if (!current.connections && !current.lookup) retire_origin(client, current);
        }
        dial_vacant_connections(client);
        step_ready_connections(client, now);
        std::uint64_t const earliest = client.earliest_connection_deadline;
        return !deadline || (earliest && earliest < deadline) ? earliest : deadline;
    }

    /** Engine slots a client needs: each connection an operation per direction, and each lookup one
     *  per question. */
    static std::size_t engine_slots(ucall_client_options_t const& config) noexcept {
        return 4 * config.max_concurrent_connections;
    }

    /** Makes a client over its own engine, or over @p bound, a server event loop's engine that loop
     *  advances it with. */
    static void client_init(ucall_client_init_t* arguments, allocator_t const& allocator = {},
                            engine_t* bound = nullptr) noexcept {
        if (!arguments) return;
        if (arguments->client) *arguments->client = nullptr;
        if (!arguments->client || !arguments->outcome || !arguments->options ||
            !arguments->options->max_concurrent_connections) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto client = allocate_unique<client_t>(allocator, allocator);
        if (!client) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        client->responses = allocate_unique<response_pool_t>(allocator, allocator).release();
        if (!client->responses) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        client->config = *arguments->options;
        auto& config = client->config;
        if (!config.connect_timeout_microseconds) config.connect_timeout_microseconds = 5'000'000;
        if (!config.call_timeout_microseconds) config.call_timeout_microseconds = 30'000'000;
        if (!config.max_response_bytes) {
            if (ucall_status_t const started = sockets_start(); started != ucall_status_success_k) {
                publish(arguments->outcome, started);
                return;
            }
            config.max_response_bytes = largest_receive_buffer(AF_INET, max_unsent_bytes_k);
        }
        if (!config.max_pipelined_calls) config.max_pipelined_calls = 1;
        if (!config.max_concurrent_calls) {
            // Every connection may carry its full pipeline at once.
            if (config.max_concurrent_connections >
                std::numeric_limits<std::size_t>::max() / config.max_pipelined_calls) {
                publish(arguments->outcome, ucall_status_invalid_argument_k);
                return;
            }
            config.max_concurrent_calls = config.max_concurrent_connections * config.max_pipelined_calls;
        }
        // Each connection keeps one operation per direction, and origin slots index one origin per
        // call and per connection below `absent_k`.
        if (config.max_pipelined_calls > std::numeric_limits<std::uint32_t>::max() ||
            config.max_concurrent_connections > std::numeric_limits<std::uint32_t>::max() / 4 ||
            config.max_concurrent_calls > std::numeric_limits<std::uint32_t>::max() / 4) {
            publish(arguments->outcome, ucall_status_overflow_k);
            return;
        }
        auto slots = engine_slots(config);
        if (config.noise_private_key) {
            std::memcpy(client->private_key, *config.noise_private_key, sizeof(client->private_key));
            config.noise_private_key = &client->private_key;
        }
        st::expected<completed_ring_t> completed = completed_ring_t::make(
            std::bit_ceil(config.max_concurrent_calls), rebound_allocator<ucall_completed_call_t> {allocator});
        if (!completed || st::failed(client->completions.resize(slots)) ||
            st::failed(client->connections.resize(config.max_concurrent_connections))) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        client->completed = std::move(*completed);
        rebound_allocator<client_exchange_t> exchange_allocator {allocator};
        auto* exchanges = exchange_allocator.allocate(config.max_concurrent_calls);
        if (!exchanges) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        for (std::size_t i = config.max_concurrent_calls; i != 0; --i)
            std::construct_at(exchanges + i - 1, allocator)->next = std::exchange(client->idle, exchanges + i - 1);
        client->exchanges = {exchanges, config.max_concurrent_calls};
        std::size_t const origins_count = config.max_concurrent_calls + 2 * config.max_concurrent_connections;
        auto* origins = rebound_allocator<client_origin_t> {allocator}.allocate(origins_count);
        if (!origins) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        for (std::size_t i = 0; i != origins_count; ++i) {
            client_origin_t& origin = *std::construct_at(origins + i, allocator);
            origin.previous = std::exchange(client->newest_free_origin, &origin);
            (origin.previous ? origin.previous->next : client->free_origins) = &origin;
        }
        client->origins = {origins, origins_count};
        auto* lookups = rebound_allocator<client_lookup_t> {allocator}.allocate(config.max_concurrent_connections);
        if (!lookups) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        for (std::size_t i = config.max_concurrent_connections; i != 0; --i)
            std::construct_at(lookups + i - 1, allocator)->next = std::exchange(client->free_lookups, lookups + i - 1);
        client->lookups = {lookups, config.max_concurrent_connections};
        dns::read_system(client->resolver);
        {
            char hosts[64 * 1024];
            std::size_t const length = dns::read_file(dns::hosts_path(), hosts);
            if (ucall_status_t const copied = http_t::append_text(client->hosts, {std::string_view {hosts, length}});
                copied != ucall_status_success_k) {
                publish(arguments->outcome, copied);
                return;
            }
        }
        st::expected<origin_index_t> origin_index = origin_index_t::make(origins_count, {},
                                                                         rebound_allocator<byte_t> {allocator});
        if (!origin_index) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        client->origin_index = std::move(*origin_index);
        if (bound) {
            client->engine = bound;
            client->binding = client_binding_t::bound_k;
        }
        else if (auto status = client->owned_engine.open(config.backend, slots, slots,
                                                         io::io_issuer_scope_t::any_thread_k);
                 status != ucall_status_success_k) {
            // An engine refused by a host setting names the setting to raise.
            char const* refusal = client->owned_engine.refusal();
            publish(arguments->outcome, status, refusal ? refusal : ucall_status_name(status));
            return;
        }
        else config.backend = client->owned_engine.backend();
        for (auto& connection : client->connections) {
            connection = allocate_unique<client_connection_t>(allocator, allocator);
            if (!connection) {
                publish(arguments->outcome, ucall_status_out_of_memory_k);
                return;
            }
            connection->client = client.get();
            connection->next_vacant = std::exchange(client->vacant_connections, connection.get());
            if (connection->next_vacant) connection->next_vacant->previous_vacant = connection.get();
        }
        if (arguments->resolved) *arguments->resolved = config;
        client->api = &client_api_k;
        *arguments->client = client.release();
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void client_free(ucall_client_t handle) noexcept {
        auto* client = static_cast<client_t*>(handle);
        if (client->binding == client_binding_t::owned_k)
            return allocator_delete<client_t, allocator_t> {client->allocator}(client);
        // The loop deletes it once the engine they share holds nothing of it.
        client->binding = client_binding_t::retiring_k;
        if (client->failure == ucall_status_success_k) client->failure = ucall_status_connection_closed_k;
        abandon_calls(*client);
        for (auto& connection : client->connections) {
            auto const stage = connection->transport.stage;
            if (stage == transport_stage_t::idle_k || stage == transport_stage_t::closed_k) continue;
            connection->transport.fail(ucall_status_success_k);
            mark_ready(*client, *connection);
        }
    }

    /** Whether a retiring client left nothing in its loop's engine, so the loop may delete it. */
    static bool retired(client_t const& client) noexcept {
        for (auto const& connection : client.connections) {
            auto const stage = connection->transport.stage;
            if ((stage != transport_stage_t::idle_k && stage != transport_stage_t::closed_k) ||
                connection->transport.in_flight())
                return false;
        }
        for (auto const& lookup : client.lookups)
            for (auto const& question : lookup.questions)
                if (question.operation == operation_state_t::submitted_k) return false;
        return true;
    }

    /** Ends every call with @c client.failure, detached from the connections carrying them. */
    static void abandon_calls(client_t& client) noexcept {
        for (client_origin_t* origin = client.live; origin; origin = origin->next) {
            origin->waiting_head = origin->waiting_tail = nullptr;
            origin->waiting = 0;
        }
        for (auto& connection : client.connections) {
            connection->oldest_exchange = connection->newest_exchange = nullptr;
            connection->outstanding_exchanges = 0;
        }
        for (auto& exchange : client.exchanges)
            if (exchange.stage != client_exchange_stage_t::idle_k) finish_exchange(client, exchange, client.failure);
    }

    /** Records one completion of @p client's, from its own engine or its bound loop's. */
    static void step_completion(client_t& client, io_completion_t const& completion) noexcept {
        if (resolving_t::owns(client, completion.request)) {
            resolving_t::complete(client, completion);
            client.engine->release(completion);
            return;
        }
        auto& connection = *static_cast<client_connection_t*>(completion.request->context);
        advance_completion(*client.engine, completion);
        mark_ready(client, connection);
    }
    static void client_call(ucall_client_call_t* arguments) noexcept {
        if (!arguments->outcome || !http_t::valid_view(arguments->url) || !http_t::valid_view(arguments->body) ||
            !http_t::http_verb_name(arguments->verb) || !formatting_t::security_valid(arguments->options.security) ||
            (arguments->headers_count && !arguments->headers)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& client = *static_cast<client_t*>(arguments->client);
        auto options = arguments->options;
        auto security = options.security;
        if (text_view(arguments->url).starts_with("http+noise://") && security == ucall_security_none_k)
            security = ucall_security_noise_xx_k;
        if ((security != ucall_security_none_k && !options.noise_private_key && !client.config.noise_private_key) ||
            (security == ucall_security_noise_xx_k && !client.config.peer_authorizer) ||
            ((security == ucall_security_noise_ik_k || security == ucall_security_noise_kk_k) &&
             !options.noise_peer_key)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        if (client.failure != ucall_status_success_k) {
            publish(arguments->outcome, client.failure);
            return;
        }
        if (client.admitted == client.exchanges.size()) {
            publish(arguments->outcome, ucall_status_contended_k);
            return;
        }
        auto timeout = options.timeout_microseconds ? options.timeout_microseconds
                                                    : client.config.call_timeout_microseconds;
        // Admission keeps one idle call for every call not admitted.
        auto& exchange = *client.idle;
        exchange.arguments = *arguments;
        exchange.arguments.outcome = nullptr;
        auto result = parse_url(exchange);
        if (result != ucall_status_success_k) {
            publish(arguments->outcome, result);
            return;
        }
        exchange.origin = intern_origin(client, exchange);
        if (!exchange.origin) {
            publish(arguments->outcome, ucall_status_out_of_memory_k);
            return;
        }
        client.idle = exchange.next;
        exchange.deadline = deadline_after(timeout);
        exchange.connection_intent = parse_connection_intent({arguments->headers, arguments->headers_count});
        exchange.attempts = exchange.redirects = 0;
        queue_call(client, exchange);
        ++client.admitted;
        publish(arguments->outcome, ucall_status_success_k);
    }
    static void client_take_completed(ucall_client_take_completed_t* arguments) noexcept {
        if (arguments->count) *arguments->count = 0;
        if (!arguments->count || (arguments->capacity && !arguments->calls)) {
            publish(arguments->outcome, ucall_status_invalid_argument_k);
            return;
        }
        auto& client = *static_cast<client_t*>(arguments->client);
        auto deadline = arguments->timeout_microseconds ? deadline_after(arguments->timeout_microseconds) : 0;
        // A bound client's loop advances it, so taking only pops what it finished.
        if (client.failure == ucall_status_success_k && client.binding == client_binding_t::owned_k) {
            auto next_deadline = client_progress(client);
            do {
                auto round_deadline = deadline && next_deadline ? std::min(next_deadline, deadline)
                                      : deadline                ? deadline
                                                                : next_deadline;
                auto wait = arguments->timeout_microseconds && client.admitted && client.completed.empty()
                                ? io_wait_t::blocking_k
                                : io_wait_t::nonblocking_k;
                int count = client.engine->poll(span<io_completion_t> {client.completions}, wait, round_deadline);
                if (count < 0) {
                    client.failure = ucall_status_io_k;
                    client.owned_engine.stop();
                    abandon_calls(client);
                    break;
                }
                for (int i = 0; i != count; ++i)
                    step_completion(client, client.completions[static_cast<std::size_t>(i)]);
                next_deadline = client_progress(client);
            } while (client.completed.empty() && client.admitted && arguments->timeout_microseconds &&
                     monotonic_ns() < deadline);
        }
        std::size_t const count = client.completed.pop_many({arguments->calls, arguments->capacity});
        client.admitted -= count;
        *arguments->count = count;
        publish(arguments->outcome, count ? ucall_status_success_k : client.failure);
    }

    inline static client_api_t const client_api_k {&client_free, &client_call, &client_take_completed};
};

} // namespace unum::ucall::network
