/**
 *  @file include/ucall/dns/configuration.hpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief Reads the stub resolver's settings and the hosts file as the operating system has them.
 *
 *  POSIX reads <tt>/etc/resolv.conf</tt> and <tt>/etc/hosts</tt> as glibc's stub does; Windows asks its adapters
 *  for their nameservers and reads the hosts file under the system root. Nothing here adds a
 *  setting of UCall's own.
 */
#pragma once

#include <cstdio> // `std::fopen`, `std::fread`

#include <charconv> // `std::from_chars`

#include "ucall/dns/messages.hpp" // `lowercase`

#if UCALL_OS_WINDOWS_
#include <iphlpapi.h> // `GetAdaptersAddresses`
#else
#include <net/if.h> // `if_nametoindex`
#endif

namespace unum::ucall::dns {

inline bool is_blank(char character) noexcept { return character == ' ' || character == '\t' || character == '\r'; }

/** The next whitespace-separated word of @p line, consumed from it. */
inline std::string_view next_word(std::string_view& line) noexcept {
    std::size_t start = 0;
    while (start != line.size() && is_blank(line[start])) ++start;
    std::size_t end = start;
    while (end != line.size() && !is_blank(line[end])) ++end;
    auto const word = line.substr(start, end - start);
    line.remove_prefix(end);
    return word;
}

/** Parses a numeric IPv4 or IPv6 address, an IPv6 one optionally with a <tt>%scope</tt>, into @p address
 *  with @p port; answers false for anything else. */
inline bool parse_address(std::string_view text, std::uint16_t port, sockaddr_storage& address) noexcept {
    char spelled[64] {};
    auto const scope_mark = text.find('%');
    auto const host = text.substr(0, scope_mark);
    if (host.empty() || host.size() >= sizeof(spelled)) return false;
    std::memcpy(spelled, host.data(), host.size());
    address = {};
    if (scope_mark == std::string_view::npos) {
        auto& ipv4 = reinterpret_cast<sockaddr_in&>(address);
        if (inet_pton(AF_INET, spelled, &ipv4.sin_addr) == 1) {
            ipv4.sin_family = AF_INET;
            ipv4.sin_port = htons(port);
            return true;
        }
    }
    auto& ipv6 = reinterpret_cast<sockaddr_in6&>(address);
    if (inet_pton(AF_INET6, spelled, &ipv6.sin6_addr) != 1) return false;
    ipv6.sin6_family = AF_INET6;
    ipv6.sin6_port = htons(port);
    if (scope_mark == std::string_view::npos) return true;
    auto const scope = text.substr(scope_mark + 1);
    std::uint32_t index = 0;
    if (std::from_chars(scope.data(), scope.data() + scope.size(), index).ptr == scope.data() + scope.size())
        return ipv6.sin6_scope_id = index, true;
#if UCALL_OS_WINDOWS_
    return false;
#else
    char interface_name[IF_NAMESIZE + 1] {};
    if (scope.empty() || scope.size() > IF_NAMESIZE) return false;
    std::memcpy(interface_name, scope.data(), scope.size());
    ipv6.sin6_scope_id = if_nametoindex(interface_name);
    return ipv6.sin6_scope_id != 0;
#endif
}

/** Reads <tt>option:number</tt> into @p value, clipped to @p ceiling as <tt>resolv.h</tt> clips it. */
inline void parse_option(std::string_view word, std::string_view option, std::uint32_t ceiling,
                         std::uint32_t& value) noexcept {
    if (!word.starts_with(option)) return;
    word.remove_prefix(option.size());
    std::uint32_t parsed = 0;
    if (std::from_chars(word.data(), word.data() + word.size(), parsed).ptr != word.data() + word.size()) return;
    value = std::min(parsed, ceiling);
}

/** Reads the file at @p path into @p buffer, answering the bytes read, or zero without a file. */
inline std::size_t read_file(char const* path, span<char> buffer) noexcept {
    std::FILE* file = std::fopen(path, "rb");
    if (!file) return 0;
    std::size_t const read = std::fread(buffer.data(), 1, buffer.size(), file);
    std::fclose(file);
    return read;
}

/** Parses the text of a <tt>resolv.conf</tt> into @p options; later <tt>domain</tt> and <tt>search</tt> lines replace
 *  earlier ones, and nameservers past the third are ignored, as <tt>resolv.h</tt> does. */
inline void parse_resolv_conf(std::string_view text, resolver_options_t& options) noexcept {
    while (!text.empty()) {
        auto const newline = text.find('\n');
        auto line = text.substr(0, newline);
        text.remove_prefix(newline == std::string_view::npos ? text.size() : newline + 1);
        line = line.substr(0, std::min(line.find('#'), line.find(';')));
        auto const keyword = next_word(line);
        if (keyword == "nameserver") {
            if (options.nameservers_count == resolver_options_t::max_nameservers_k) continue;
            if (parse_address(next_word(line), 53, options.nameservers[options.nameservers_count]))
                ++options.nameservers_count;
        }
        else if (keyword == "domain" || keyword == "search") {
            options.search_length = 0;
            for (auto domain = next_word(line); !domain.empty(); domain = next_word(line)) {
                if (options.search_length + domain.size() + 1 > resolver_options_t::search_bytes_k) break;
                std::memcpy(options.search + options.search_length, domain.data(), domain.size());
                options.search_length += static_cast<std::uint32_t>(domain.size());
                options.search[options.search_length++] = '\0';
                if (keyword == "domain") break;
            }
        }
        else if (keyword == "options")
            for (auto option = next_word(line); !option.empty(); option = next_word(line)) {
                parse_option(option, "ndots:", 15, options.ndots);
                parse_option(option, "timeout:", 30, options.timeout_seconds);
                parse_option(option, "attempts:", 5, options.attempts);
            }
    }
}

/**
 *  @brief Finds @p name in the text of a hosts file, writing its first address of @p type into
 *      @p address: 4 bytes for A, 16 for AAAA.
 *  @return @c ucall_status_success_k, or @c ucall_status_not_found_k when no line names it.
 */
inline ucall_status_t find_host(std::string_view hosts, std::string_view name, record_type_t type,
                                span<byte_t> address) noexcept {
    if (!name.empty() && name.back() == '.') name.remove_suffix(1);
    auto const same = [](std::string_view left, std::string_view right) noexcept {
        if (left.size() != right.size()) return false;
        for (std::size_t index = 0; index != left.size(); ++index)
            if (lowercase(static_cast<byte_t>(left[index])) != lowercase(static_cast<byte_t>(right[index])))
                return false;
        return true;
    };
    while (!hosts.empty()) {
        auto const newline = hosts.find('\n');
        auto line = hosts.substr(0, newline);
        hosts.remove_prefix(newline == std::string_view::npos ? hosts.size() : newline + 1);
        line = line.substr(0, line.find('#'));
        sockaddr_storage parsed {};
        if (!parse_address(next_word(line), 0, parsed)) continue;
        bool const fits = type == record_type_t::a_k ? parsed.ss_family == AF_INET : parsed.ss_family == AF_INET6;
        if (!fits) continue;
        for (auto alias = next_word(line); !alias.empty(); alias = next_word(line)) {
            if (!same(alias, name)) continue;
            if (type == record_type_t::a_k)
                std::memcpy(address.data(), &reinterpret_cast<sockaddr_in const&>(parsed).sin_addr, 4);
            else std::memcpy(address.data(), &reinterpret_cast<sockaddr_in6 const&>(parsed).sin6_addr, 16);
            return ucall_status_success_k;
        }
    }
    return ucall_status_not_found_k;
}

/** The hosts file's path on this operating system. */
inline char const* hosts_path() noexcept {
#if UCALL_OS_WINDOWS_
    return "C:\\Windows\\System32\\drivers\\etc\\hosts";
#else
    return "/etc/hosts";
#endif
}

/** Reads this machine's resolver settings, defaulting to a loopback nameserver as <tt>resolv.h</tt> does
 *  when none is named. */
inline void read_system(resolver_options_t& options) noexcept {
    options = {};
#if UCALL_OS_WINDOWS_
    ULONG size = 16 * 1024;
    alignas(IP_ADAPTER_ADDRESSES) byte_t buffer[16 * 1024];
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer);
    ULONG const flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_FRIENDLY_NAME;
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &size) == NO_ERROR)
        for (auto* adapter = adapters; adapter; adapter = adapter->Next) {
            if (adapter->OperStatus != IfOperStatusUp) continue;
            for (auto* server = adapter->FirstDnsServerAddress; server; server = server->Next) {
                if (options.nameservers_count == resolver_options_t::max_nameservers_k) break;
                auto& slot = options.nameservers[options.nameservers_count++];
                std::memcpy(&slot, server->Address.lpSockaddr,
                            std::min<std::size_t>(server->Address.iSockaddrLength, sizeof(slot)));
                reinterpret_cast<sockaddr_in&>(slot).sin_port = htons(53);
            }
        }
#else
    char text[16 * 1024];
    parse_resolv_conf({text, read_file("/etc/resolv.conf", text)}, options);
#endif
    if (!options.nameservers_count && parse_address("127.0.0.1", 53, options.nameservers[0]))
        options.nameservers_count = 1;
}

} // namespace unum::ucall::dns
