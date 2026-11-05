/**
 *  @file include/ucall/dns/types.hpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief The records, answers, constants and operating-system settings of the stub resolver.
 */
#pragma once

#include <cstdint> // `std::uint16_t`, `std::uint32_t`

#include "ucall/utilities/sockets.hpp" // `sockaddr_storage`
#include "ucall/utilities/types.hpp"   // `byte_t`, `span`

namespace unum::ucall::dns {

using utilities::byte_t;
using utilities::span;

/** The resource record types the stub asks for or follows, as RFC 1035 and RFC 3596 number them. */
enum class record_type_t : std::uint16_t { a_k = 1, cname_k = 5, soa_k = 6, aaaa_k = 28 };

/** What one answer said about the question it was asked. */
enum class answer_t : std::uint8_t {

    /** At least one address of the asked type, at the end of any CNAME chain. */
    addresses_k,

    /** The name exists but holds no address of the asked type (NODATA). */
    empty_k,

    /** The name does not exist (NXDOMAIN). */
    absent_k,

    /** The answer was cut short over UDP, so the question goes again over TCP. */
    truncated_k,

    /** The server refused or failed the question, so the next server is asked. */
    failed_k,

    /** The packet broke the protocol or answered another question. */
    malformed_k,
};

/** RFC 8305 §3: how long an answered A waits for its AAAA before dialing. */
inline constexpr std::uint64_t resolution_delay_microseconds_k = 50'000;

/** RFC 8305 §5: how long one connection attempt runs before the next address races it. */
inline constexpr std::uint64_t connection_attempt_delay_microseconds_k = 250'000;

/** RFC 1035 §4.2.1: the largest UDP answer without EDNS. */
inline constexpr std::size_t udp_answer_bytes_k = 512;

/** RFC 1035 §2.3.4: the longest name on the wire, its length bytes and root label included. */
inline constexpr std::size_t name_bytes_k = 255;

/** A header, the longest name, then the question's type and class. */
inline constexpr std::size_t query_bytes_k = 12 + name_bytes_k + 4;

/** The nameservers, search domains and pacing <tt>resolv.h</tt> reads, bounded as it bounds them. */
struct resolver_options_t {
    static constexpr std::size_t max_nameservers_k = 3;
    static constexpr std::size_t search_bytes_k = 256;

    sockaddr_storage nameservers[max_nameservers_k] {};
    std::uint32_t nameservers_count {};

    /** The search domains, each followed by a NUL, in order. */
    char search[search_bytes_k] {};
    std::uint32_t search_length {};

    std::uint32_t ndots {1}, timeout_seconds {5}, attempts {2};
};

} // namespace unum::ucall::dns
