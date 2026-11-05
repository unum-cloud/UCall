/**
 *  @file include/ucall/network/formatting.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Configuration checks, socket binding, and the text of reply heads and records.
 */
#pragma once

#include <cstdio>  // `std::snprintf`
#include <cstring> // `std::memcpy`

#include <algorithm>        // `std::min`
#include <chrono>           // `std::chrono::year_month_day`, `std::chrono::hh_mm_ss`, `std::chrono::weekday`
#include <initializer_list> // `std::initializer_list`
#include <optional>         // `std::optional`

#include "ucall/http/messages.hpp" // `http_role_t`
#include "ucall/io/types.hpp"      // `io_operation_t`
#include "ucall/network/types.hpp" // `reply_framing_t`, `max_unsent_bytes_k`
#include "ucall/tunnel/types.hpp" // `secure_tunnel_config_t`, `secure_tunnel_geometry_t`, `secure_tunnel_mode_t`, `secure_tunnel_role_t`
#include "ucall/utilities/sockets.hpp" // `file_direct_check`, `socket_close`, `socket_length_t`, `socket_open`
#include "ucall/utilities/types.hpp"   // `text_view`, `byte_t`, `bytes_view`, `descriptor_t`

namespace unum::ucall::network {

using http::http_role_t;
using io::io_operation_t;
using tunnel::secure_tunnel_config_t;
using tunnel::secure_tunnel_geometry_t;
using tunnel::secure_tunnel_mode_t;
using tunnel::secure_tunnel_role_t;
using utilities::byte_t;
using utilities::bytes_view;
using utilities::descriptor_t;
using utilities::file_direct_check;
using utilities::receive_queues_count;
using utilities::socket_close;
using utilities::socket_duplicate_listener;
using utilities::socket_length_t;
using utilities::socket_open;
using utilities::socket_option;
using utilities::sockets_start;
using utilities::span;
using utilities::text_view;

/** One field of a log line: its name and its already formatted value. */
struct log_field_t {
    std::string_view name, value;
};

/** Configuration checks, socket binding, and the text of reply heads, records and log lines. */
template <typename network_type_>
struct formatting {
    using network_t = network_type_;
    using http_t = typename network_t::http_t;
    using server_exchange_t = typename network_t::server_exchange_t;
    using network_interface_t = typename network_t::network_interface_t;
    using interface_acceptor_t = typename network_t::interface_acceptor_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;
    template <typename value_type_>
    using atomic_ref = typename network_t::template atomic_ref<value_type_>;

    static secure_tunnel_mode_t tunnel_mode(ucall_security_t security) noexcept {
        return static_cast<secure_tunnel_mode_t>(security);
    }
    static bool security_valid(ucall_security_t security) noexcept {
        return security >= ucall_security_none_k && security <= ucall_security_noise_kk_k;
    }
    static secure_tunnel_config_t tunnel_config(ucall_security_t security, secure_tunnel_role_t role,
                                                ucall_noise_key_t const* private_key, byte_t const* public_key,
                                                ucall_noise_key_t const* peer_key) noexcept {
        secure_tunnel_config_t config {};
        config.mode = tunnel_mode(security);
        config.role = role;
        if (private_key) config.local_private = std::as_bytes(std::span {*private_key});
        if (public_key) config.local_public = {public_key, public_key + 32};
        if (peer_key) config.peer_public = std::as_bytes(std::span {*peer_key});
        return config;
    }
    [[nodiscard]] static ucall_status_t copy_text(vector<char>& destination, std::string_view text) noexcept {
        destination.clear();
        return http_t::append_text(destination, {text, std::string_view {"\0", 1}});
    }
    static ucall_status_t split_address(std::string_view address, vector<char>& host, vector<char>& service) noexcept {
        auto colon = http_t::rfind(address, ':');
        if (colon == std::string_view::npos || !colon || colon + 1 == address.size())
            return ucall_status_invalid_argument_k;
        auto name = address.substr(0, colon), port = address.substr(colon + 1);
        if (name.front() == '[' && name.back() == ']') {
            name.remove_prefix(1);
            name.remove_suffix(1);
        }
        else if (http_t::find(name, ':') != std::string_view::npos) return ucall_status_invalid_argument_k;
        unsigned number = 0;
        auto parsed = std::from_chars(port.data(), port.data() + port.size(), number);
        if (parsed.ec != std::errc {} || parsed.ptr != port.data() + port.size() || number > 65535 || name.empty() ||
            http_t::find(name, '\0') != std::string_view::npos)
            return ucall_status_invalid_argument_k;
        if (ucall_status_t const copied = copy_text(host, name); copied != ucall_status_success_k) return copied;
        return copy_text(service, port);
    }
    static std::size_t interface_event_loops(std::string_view device) noexcept {
        return device.empty() ? 1 : receive_queues_count(device);
    }

    /** The C face's view of the peer address an accept wrote, the port in host order. */
    static ucall_peer_address_t peer_address(sockaddr_storage const& address) noexcept {
        ucall_peer_address_t peer {};
        if (address.ss_family == AF_INET) {
            auto const& inet = reinterpret_cast<sockaddr_in const&>(address);
            peer.family = ucall_address_family_ipv4_k;
            std::memcpy(peer.bytes, &inet.sin_addr, sizeof(inet.sin_addr));
            peer.port = ntohs(inet.sin_port);
        }
        else if (address.ss_family == AF_INET6) {
            auto const& inet6 = reinterpret_cast<sockaddr_in6 const&>(address);
            peer.family = ucall_address_family_ipv6_k;
            std::memcpy(peer.bytes, &inet6.sin6_addr, sizeof(inet6.sin6_addr));
            peer.port = ntohs(inet6.sin6_port);
            peer.scope = inet6.sin6_scope_id;
        }
        else if (address.ss_family == AF_UNIX) peer.family = ucall_address_family_unix_k;
        return peer;
    }

    /** The largest @c SO_RCVBUF the kernel grants, probed on a socket of its own, since setting it
     *  on the listener would pin every accepted socket's buffer and stop receive autotuning. */
    static std::size_t largest_receive_buffer(int family) noexcept {
        descriptor_t const probe = socket_open(family);
        if (probe < 0) return max_unsent_bytes_k;
        // Linux clamps an oversized request where FreeBSD and macOS refuse it, so refusals bisect.
        int accepted = 0, refused = std::numeric_limits<int>::max();
        if (socket_option(probe, SOL_SOCKET, SO_RCVBUF, &refused, sizeof(refused)) == 0) accepted = refused;
        while (refused - accepted > 1) {
            int const requested = accepted + (refused - accepted) / 2;
            if (socket_option(probe, SOL_SOCKET, SO_RCVBUF, &requested, sizeof(requested)) == 0) accepted = requested;
            else refused = requested;
        }
        int granted = 0;
        socket_length_t length = sizeof(granted);
        if (!accepted || getsockopt(probe, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<char*>(&granted), &length) != 0 ||
            granted <= 0)
            granted = static_cast<int>(max_unsent_bytes_k);
        socket_close(probe);
        return static_cast<std::size_t>(granted);
    }

    /** Binds and listens on the interface's address, trying each address it resolves to. */
    static ucall_status_t bind_listener(network_interface_t& network_interface, descriptor_t& descriptor) noexcept {
        vector<char> host {rebound_allocator<char> {network_interface.address.get_allocator()}},
            service {host.get_allocator()};
        if (auto status = split_address(text_view(network_interface.config.address), host, service);
            status != ucall_status_success_k)
            return status;
        addrinfo hints {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE;
        addrinfo* addresses = nullptr;
        if (getaddrinfo(host.data(), service.data(), &hints, &addresses) != 0) return ucall_status_connection_failed_k;
        for (auto* address = addresses; address; address = address->ai_next) {
            descriptor = socket_open(address->ai_family);
            if (descriptor < 0) continue;
            int enabled = 1;
#if UCALL_OS_WINDOWS_
            bool configured = socket_option(descriptor, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &enabled, sizeof(enabled)) ==
                              0;
#else
            bool configured = socket_option(descriptor, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled)) == 0;
#endif
            // Accepted sockets inherit it, so the kernel's own keepalive settings reap dead peers.
            configured = configured &&
                         socket_option(descriptor, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled)) == 0;
#if UCALL_OS_LINUX_
            if (network_interface.config.device_name.length)
                configured = configured &&
                             socket_option(descriptor, SOL_SOCKET, SO_BINDTODEVICE, network_interface.device.data(),
                                           static_cast<socket_length_t>(network_interface.device.size())) == 0;
#endif // UCALL_OS_LINUX_
            if (configured && bind(descriptor, address->ai_addr, address->ai_addrlen) == 0 &&
                listen(descriptor,
                       static_cast<int>(std::min<std::size_t>(network_interface.config.max_concurrent_connections,
                                                              std::numeric_limits<int>::max()))) == 0)
                break;
            socket_close(descriptor);
            descriptor = -1;
        }
        freeaddrinfo(addresses);
        return descriptor < 0 ? ucall_status_connection_failed_k : ucall_status_success_k;
    }

    /** Readies loop zero's acceptor on a duplicate of the listener the interface was handed, or on
     *  one bound to its address, and reports the bound address, or an AF_UNIX socket's path. */
    static ucall_status_t bind_acceptor(network_interface_t& network_interface,
                                        interface_acceptor_t& acceptor) noexcept {
        if (ucall_status_t const started = sockets_start(); started != ucall_status_success_k) return started;
        descriptor_t descriptor = -1;
        if (network_interface.config.listen_descriptor) {
            descriptor = socket_duplicate_listener(*network_interface.config.listen_descriptor);
            if (descriptor < 0) return ucall_status_invalid_argument_k;
        }
        else if (ucall_status_t const listened = bind_listener(network_interface, descriptor);
                 listened != ucall_status_success_k)
            return listened;
        sockaddr_storage bound {};
        socket_length_t length = sizeof(bound);
        char numeric_host[NI_MAXHOST], numeric_service[NI_MAXSERV], text[NI_MAXHOST + NI_MAXSERV + 4];
        bool const unix_domain = getsockname(descriptor, reinterpret_cast<sockaddr*>(&bound), &length) == 0 &&
                                 bound.ss_family == AF_UNIX;
        int enabled = 1;
        // getnameinfo refuses AF_UNIX, whose address is its path; only inet
        // sockets take keepalives.
        if (unix_domain) {
            auto const& path = reinterpret_cast<sockaddr_un const&>(bound).sun_path;
            std::size_t const path_length = std::min(std::strlen(path), sizeof(path) - 1);
            std::memcpy(text, path, path_length);
            text[path_length] = '\0';
        }
        else if (getnameinfo(reinterpret_cast<sockaddr*>(&bound), length, numeric_host, sizeof(numeric_host),
                             numeric_service, sizeof(numeric_service), NI_NUMERICHOST | NI_NUMERICSERV) != 0 ||
                 socket_option(descriptor, SOL_SOCKET, SO_KEEPALIVE, &enabled, sizeof(enabled)) != 0) {
            socket_close(descriptor);
            return ucall_status_io_k;
        }
        else
            std::snprintf(text, sizeof(text), bound.ss_family == AF_INET6 ? "[%s]:%s" : "%s:%s", numeric_host,
                          numeric_service);
        if (ucall_status_t const copied = copy_text(network_interface.address, text);
            copied != ucall_status_success_k) {
            socket_close(descriptor);
            return copied;
        }
        network_interface.config.address = bytes_view(
            {network_interface.address.data(), network_interface.address.size() - 1});
        int send_buffer = 0;
        socket_length_t send_buffer_length = sizeof(send_buffer);
        if (getsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<char*>(&send_buffer), &send_buffer_length) !=
                0 ||
            send_buffer <= 0)
            send_buffer = static_cast<int>(max_unsent_bytes_k);
        network_interface.send_buffer_bytes = static_cast<std::size_t>(send_buffer);
        if (!network_interface.config.max_request_bytes)
            network_interface.config.max_request_bytes = largest_receive_buffer(bound.ss_family);
        acceptor.network_interface = &network_interface;
        acceptor.request = {.operation = io_operation_t::accept_k,
                            .descriptor = descriptor,
                            .data = reinterpret_cast<byte_t*>(&acceptor.peer_address),
                            .context = &acceptor};
        return ucall_status_success_k;
    }

    /** The status line of every named @c ucall_http_status_t, with its RFC 9110 reason phrase. */
    static std::string_view status_line(unsigned status) noexcept {
        switch (status) {
        case ucall_http_status_ok_k: return "HTTP/1.1 200 OK\r\n";
        case ucall_http_status_created_k: return "HTTP/1.1 201 Created\r\n";
        case ucall_http_status_no_content_k: return "HTTP/1.1 204 No Content\r\n";
        case ucall_http_status_partial_content_k: return "HTTP/1.1 206 Partial Content\r\n";
        case ucall_http_status_moved_permanently_k: return "HTTP/1.1 301 Moved Permanently\r\n";
        case ucall_http_status_found_k: return "HTTP/1.1 302 Found\r\n";
        case ucall_http_status_not_modified_k: return "HTTP/1.1 304 Not Modified\r\n";
        case ucall_http_status_bad_request_k: return "HTTP/1.1 400 Bad Request\r\n";
        case ucall_http_status_unauthorized_k: return "HTTP/1.1 401 Unauthorized\r\n";
        case ucall_http_status_forbidden_k: return "HTTP/1.1 403 Forbidden\r\n";
        case ucall_http_status_not_found_k: return "HTTP/1.1 404 Not Found\r\n";
        case ucall_http_status_method_not_allowed_k: return "HTTP/1.1 405 Method Not Allowed\r\n";
        case ucall_http_status_timeout_k: return "HTTP/1.1 408 Request Timeout\r\n";
        case ucall_http_status_conflict_k: return "HTTP/1.1 409 Conflict\r\n";
        case ucall_http_status_precondition_failed_k: return "HTTP/1.1 412 Precondition Failed\r\n";
        case ucall_http_status_payload_too_large_k: return "HTTP/1.1 413 Content Too Large\r\n";
        case ucall_http_status_range_not_satisfiable_k: return "HTTP/1.1 416 Range Not Satisfiable\r\n";
        case ucall_http_status_too_many_requests_k: return "HTTP/1.1 429 Too Many Requests\r\n";
        case ucall_http_status_internal_error_k: return "HTTP/1.1 500 Internal Server Error\r\n";
        case ucall_http_status_not_implemented_k: return "HTTP/1.1 501 Not Implemented\r\n";
        case ucall_http_status_bad_gateway_k: return "HTTP/1.1 502 Bad Gateway\r\n";
        case ucall_http_status_service_unavailable_k: return "HTTP/1.1 503 Service Unavailable\r\n";
        case ucall_http_status_gateway_timeout_k: return "HTTP/1.1 504 Gateway Timeout\r\n";
        case ucall_http_status_version_not_supported_k: return "HTTP/1.1 505 HTTP Version Not Supported\r\n";
        }
        return {};
    }
    template <std::size_t capacity_>
    static std::string_view format_decimal(char (&output)[capacity_], std::size_t value) noexcept {
        auto written = std::to_chars(output, output + capacity_, value);
        return {output, static_cast<std::size_t>(written.ptr - output)};
    }

    /** Hands @p event and its @p fields to @p log as one line in its format, when its level takes
     *  @p level; a line past the buffer is cut short. */
    static void log_line(ucall_log_t const& log, ucall_log_level_t level, std::string_view event,
                         std::initializer_list<log_field_t> fields) noexcept {
        if (!log.callback || level < log.level) return;
        constexpr std::string_view level_names_k[] {"debug", "info", "warning", "error", "fatal"};
        char line[512];
        std::size_t length = 0;
        auto put = [&](auto const&... texts) noexcept {
            for (std::string_view const text : {std::string_view {texts}...}) {
                std::size_t const fits = std::min(text.size(), sizeof(line) - length);
                std::memcpy(line + length, text.data(), fits);
                length += fits;
            }
        };
        std::string_view const level_name = level_names_k[static_cast<std::size_t>(level)];
        if (log.format == ucall_log_format_json_k) {
            put("{\"level\":\"", level_name, "\",\"event\":\"", event, "\"");
            for (log_field_t const& field : fields) put(",\"", field.name, "\":\"", field.value, "\"");
            put("}");
        }
        else {
            put(level_name, " ", event);
            for (log_field_t const& field : fields) put(" ", field.name, "=", field.value);
        }
        log.callback(level, {reinterpret_cast<ucall_byte_t const*>(line), length}, log.context);
    }
    static constexpr std::size_t http_date_length_k = sizeof("Sun, 06 Nov 1994 08:49:37 GMT") - 1;

    /** Formats the RFC 9110 IMF-fixdate through the calendar types, without allocating. */
    static std::string_view format_date(char (&output)[http_date_length_k], std::time_t now) noexcept {
        static constexpr char weekdays_k[] = "SunMonTueWedThuFriSat",
                              months_k[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
        std::chrono::sys_seconds const seconds {std::chrono::seconds {std::max<std::time_t>(now, 0)}};
        std::chrono::sys_days const days = std::chrono::floor<std::chrono::days>(seconds);
        std::chrono::year_month_day const date {days};
        std::chrono::hh_mm_ss<std::chrono::seconds> const time {seconds - days};
        auto put = [&](std::size_t offset, std::uint64_t value, std::size_t width) {
            for (auto position = offset + width; position != offset; value /= 10)
                output[--position] = static_cast<char>('0' + value % 10);
        };
        std::memcpy(output, weekdays_k + std::chrono::weekday {days}.c_encoding() * 3, 3);
        std::memcpy(output + 3, ", ", 2);
        put(5, static_cast<unsigned>(date.day()), 2);
        output[7] = ' ';
        std::memcpy(output + 8, months_k + (static_cast<unsigned>(date.month()) - 1) * 3, 3);
        output[11] = ' ';
        put(12, static_cast<std::uint64_t>(static_cast<int>(date.year())), 4);
        output[16] = ' ';
        put(17, static_cast<std::uint64_t>(time.hours().count()), 2);
        output[19] = ':';
        put(20, static_cast<std::uint64_t>(time.minutes().count()), 2);
        output[22] = ':';
        put(23, static_cast<std::uint64_t>(time.seconds().count()), 2);
        std::memcpy(output + 25, " GMT", 4);
        return {output, http_date_length_k};
    }

    /** Appends validated, lowercased @p headers. A @c content-length is refused, unless @p declared
     *  takes its value instead, as a streamed reply's framing. */
    static ucall_status_t append_headers(vector<byte_t>& output, span<ucall_bytes_view_t const> headers,
                                         http_role_t role, std::optional<std::uint64_t>* declared = nullptr) noexcept {
        for (ucall_bytes_view_t const header : headers) {
            if (!http_t::valid_view(header)) return ucall_status_invalid_argument_k;
            auto line = text_view(header);
            auto colon = http_t::find(line, ':');
            if (colon == std::string_view::npos || !http_t::http_token(line.substr(0, colon)) ||
                !http_t::http_value(line.substr(colon + 1)))
                return ucall_status_invalid_argument_k;
            auto previous = output.size();
            if (ucall_status_t const appended = http_t::append_text(output, {line.substr(0, colon)});
                appended != ucall_status_success_k)
                return appended;
            http_t::lowercase_ascii({reinterpret_cast<char*>(output.data()) + previous, colon});
            std::string_view name {reinterpret_cast<char const*>(output.data()) + previous, colon};
            if (declared && !*declared && http_t::equal(name, "content-length")) {
                std::string_view const value = http_t::trim_http(line.substr(colon + 1));
                std::uint64_t length {};
                auto parsed = std::from_chars(value.data(), value.data() + value.size(), length);
                if (value.empty() || parsed.ec != std::errc {} || parsed.ptr != value.data() + value.size())
                    return ucall_status_invalid_argument_k;
                *declared = length;
                [[maybe_unused]] st::status_t const dropped = output.resize(previous);
                continue;
            }
            if (http_t::equal(name, "content-length") || http_t::equal(name, "transfer-encoding") ||
                (role == http_role_t::request_k &&
                 (http_t::equal(name, "host") || http_t::equal(name, "user-agent"))) ||
                (role != http_role_t::request_k &&
                 (http_t::equal(name, "date") || http_t::equal(name, "server") || http_t::equal(name, "connection"))))
                return ucall_status_invalid_argument_k;
            if (ucall_status_t const appended = http_t::append_text(
                    output, {": ", http_t::trim_http(line.substr(colon + 1)), "\r\n"});
                appended != ucall_status_success_k)
                return appended;
        }
        return ucall_status_success_k;
    }

    /** Starts a reply head after the tunnel's headroom: the status line, @c server and @c date. */
    static ucall_status_t write_reply_head(vector<byte_t>& output, secure_tunnel_geometry_t const& geometry,
                                           unsigned status) noexcept {
        if (status < 200 || status > 599) return ucall_status_invalid_argument_k;
        static constexpr std::string_view classes_k[] {"Successful", "Redirection", "Client Error", "Server Error"};
        char digits[std::numeric_limits<std::size_t>::digits10 + 1], date[http_date_length_k];
        output.clear();
        if (st::failed(output.resize(geometry.headroom))) return ucall_status_out_of_memory_k;
        auto line = status_line(status);
        ucall_status_t result = line.empty() ? http_t::append_text(output, {"HTTP/1.1 ", format_decimal(digits, status),
                                                                            " ", classes_k[status / 100 - 2], "\r\n"})
                                             : http_t::append_text(output, {line});
        if (result != ucall_status_success_k) return result;
        return http_t::append_text(output, {"server: UCall\r\ndate: ", format_date(date, std::time(nullptr)), "\r\n"});
    }

    /** Ends a reply head with the field @p framing announces, @c connection, and the blank line. */
    static ucall_status_t finish_reply_head(vector<byte_t>& output, server_exchange_t const& exchange,
                                            reply_framing_t framing, std::uint64_t length) noexcept {
        char digits[std::numeric_limits<std::uint64_t>::digits10 + 1];
        // A draining server closes each connection after its replies in flight, so it says so.
        bool const keeps_alive = exchange.message.keep_alive() && server_stage(exchange) == server_stage_t::serving_k;
        std::string_view const connection = keeps_alive ? "connection: keep-alive\r\n\r\n"
                                                        : "connection: close\r\n\r\n";
        switch (framing) {
        case reply_framing_t::length_k:
            return http_t::append_text(output,
                                       {"content-length: ", format_decimal(digits, length), "\r\n", connection});
        case reply_framing_t::chunked_k:
            return http_t::append_text(output, {"transfer-encoding: chunked\r\n", connection});
        case reply_framing_t::until_close_k:
        case reply_framing_t::bodiless_k: break;
        }
        return http_t::append_text(output, {connection});
    }

    /** Appends @p texts to @p bytes, a segment laid out as whole records of @p geometry from its
     *  start: once a record's payload is full, a gap for its tag and the next record's header
     *  follows, so every record seals in place and a send takes them back to back. */
    static ucall_status_t append_records(vector<byte_t>& bytes, secure_tunnel_geometry_t const& geometry,
                                         std::initializer_list<std::string_view> texts) noexcept {
        if (!geometry.tailroom) return http_t::append_text(bytes, texts);
        std::size_t total = 0;
        for (std::string_view const text : texts) total += text.size();
        std::size_t const stride = geometry.record_size(), payload_end = geometry.headroom + geometry.max_payload,
                          overhead = stride - geometry.max_payload;
        if (st::failed(bytes.reserve(bytes.size() + total + (total / geometry.max_payload + 1) * overhead)))
            return ucall_status_out_of_memory_k;
        for (std::string_view text : texts)
            while (!text.empty()) {
                std::size_t position = bytes.size() % stride;
                if (position == payload_end) {
                    [[maybe_unused]] st::status_t const gap = bytes.resize(bytes.size() + overhead);
                    position = geometry.headroom;
                }
                std::size_t const taken = std::min(text.size(), payload_end - position), end = bytes.size();
                [[maybe_unused]] st::status_t const grown = bytes.resize(end + taken);
                std::memcpy(bytes.data() + end, text.data(), taken);
                text.remove_prefix(taken);
            }
        return ucall_status_success_k;
    }

    /** Spreads a head written contiguously after one headroom into whole records, which only a head
     *  longer than one record's payload needs. */
    static ucall_status_t spread_records(vector<byte_t>& bytes, secure_tunnel_geometry_t const& geometry) noexcept {
        std::size_t const payload_limit = geometry.max_payload;
        if (!geometry.tailroom || bytes.size() <= geometry.headroom + payload_limit) return ucall_status_success_k;
        std::size_t const payload = bytes.size() - geometry.headroom, stride = geometry.record_size(),
                          records = (payload + payload_limit - 1) / payload_limit;
        if (st::failed(bytes.resize(bytes.size() + (records - 1) * (stride - payload_limit))))
            return ucall_status_out_of_memory_k;
        for (std::size_t record = records - 1; record; --record)
            std::memmove(bytes.data() + record * stride + geometry.headroom,
                         bytes.data() + geometry.headroom + record * payload_limit,
                         std::min(payload_limit, payload - record * payload_limit));
        return ucall_status_success_k;
    }

    /** Lays @p texts out as whole records between the tunnel's headroom and tailroom, ready to seal
     *  in place. */
    static ucall_status_t frame_segment(vector<byte_t>& bytes, secure_tunnel_geometry_t const& geometry,
                                        std::initializer_list<std::string_view> texts) noexcept {
        bytes.clear();
        if (st::failed(bytes.resize(geometry.headroom))) return ucall_status_out_of_memory_k;
        if (ucall_status_t const appended = append_records(bytes, geometry, texts); appended != ucall_status_success_k)
            return appended;
        return st::failed(bytes.resize(bytes.size() + geometry.tailroom)) ? ucall_status_out_of_memory_k
                                                                          : ucall_status_success_k;
    }

    /** Serializes a whole reply of bytes parts into the end segment, its body the parts
     *  concatenated. */
    static ucall_status_t serialize_reply(server_exchange_t& exchange, unsigned status,
                                          span<ucall_bytes_view_t const> headers,
                                          span<ucall_reply_part_t const> parts) noexcept {
        auto& output = exchange.end_segment.bytes;
        if (!output.empty()) return ucall_status_already_exists_k;
        std::size_t length = 0;
        for (ucall_reply_part_t const& part : parts) {
            if (part.data.bytes.length > std::numeric_limits<std::size_t>::max() - length)
                return ucall_status_invalid_argument_k;
            length += part.data.bytes.length;
        }
        bool const bodiless = status == 204 || status == 304;
        if (bodiless && length) return ucall_status_invalid_argument_k;
        std::size_t const sent = exchange.message.verb != ucall_verb_head_k ? length : 0;
        ucall_status_t result = write_reply_head(output, exchange.geometry, status);
        if (result == ucall_status_success_k) result = append_headers(output, headers, http_role_t::response_k);
        if (result == ucall_status_success_k)
            result = finish_reply_head(output, exchange,
                                       bodiless ? reply_framing_t::bodiless_k : reply_framing_t::length_k, length);
        if (result == ucall_status_success_k) result = spread_records(output, exchange.geometry);
        if (sent)
            for (ucall_reply_part_t const& part : parts)
                if (result == ucall_status_success_k)
                    result = append_records(output, exchange.geometry, {text_view(part.data.bytes)});
        if (result == ucall_status_success_k && st::failed(output.resize(output.size() + exchange.geometry.tailroom)))
            result = ucall_status_out_of_memory_k;
        if (result != ucall_status_success_k) {
            output.clear();
            return result;
        }
        exchange.copied = sent;
        return ucall_status_success_k;
    }
    static server_stage_t server_stage(server_exchange_t const& exchange) noexcept {
        return static_cast<server_stage_t>(
            atomic_ref<std::uint32_t> {exchange.event_loop->server->stage}.load(std::memory_order_acquire));
    }

    /** Whether the request line names HTTP/1.0, whose peers take no chunked body. */
    static bool requests_http_1_0(server_exchange_t const& exchange) noexcept {
        std::string_view const text = exchange.text();
        std::size_t const end = http_t::find(text, "\r\n");
        return end != std::string_view::npos && end >= 8 && http_t::equal(text.substr(end - 8, 8), "HTTP/1.0");
    }

    /** Whether @p path names a file beneath a directory: not empty, not absolute, and free of NUL
     *  bytes and <tt>..</tt> components. */
    static bool stays_beneath_directory(std::string_view path) noexcept {
        if (path.empty() || path.front() == '/' || http_t::find(path, '\0') != std::string_view::npos) return false;
        for (std::size_t start = 0; start <= path.size();) {
            std::size_t const slash = http_t::find(path, '/', start);
            std::size_t const end = slash == std::string_view::npos ? path.size() : slash;
            if (http_t::equal(path.substr(start, end - start), "..")) return false;
            start = end + 1;
        }
        return true;
    }

    /** Refuses a range whose end overflows its counter, which no file can satisfy. */
    static ucall_status_t check_range(std::uint64_t offset, std::uint64_t length) noexcept {
        return length > std::numeric_limits<std::uint64_t>::max() - offset ? ucall_status_invalid_argument_k
                                                                           : ucall_status_success_k;
    }

    /** Checks one part against @p exchange's interface, answering why it cannot be queued. A
     *  caller's descriptor must read unbuffered, as the loop reads files only that way. */
    static ucall_status_t check_part(server_exchange_t const& exchange, ucall_reply_part_t const& part) noexcept {
        switch (part.kind) {
        case ucall_reply_part_bytes_k:
            return http_t::valid_view(part.data.bytes) ? ucall_status_success_k : ucall_status_invalid_argument_k;
        case ucall_reply_part_file_k: {
            ucall_file_range_t const& file = part.data.file;
            if (file.file_descriptor < 0 || file_direct_check(file.file_descriptor) != ucall_status_success_k)
                return ucall_status_invalid_argument_k;
            return check_range(file.offset, file.length);
        }
        case ucall_reply_part_path_k: {
            ucall_path_range_t const& path = part.data.path;
            if (!http_t::valid_view(path.relative_path) ||
                path.directory_index >= exchange.network_interface->reply_directory_descriptors.size() ||
                !stays_beneath_directory(text_view(path.relative_path)))
                return ucall_status_invalid_argument_k;
            return check_range(path.offset, path.length);
        }
        default: return ucall_status_invalid_argument_k;
        }
    }

    /** Checks every one of @p parts, counting the file and path parts into @p files. */
    static ucall_status_t check_parts(server_exchange_t const& exchange, span<ucall_reply_part_t const> parts,
                                      std::size_t& files) noexcept {
        files = 0;
        for (ucall_reply_part_t const& part : parts) {
            if (ucall_status_t const checked = check_part(exchange, part); checked != ucall_status_success_k)
                return checked;
            files += part.kind != ucall_reply_part_bytes_k;
        }
        return ucall_status_success_k;
    }
};

} // namespace unum::ucall::network
