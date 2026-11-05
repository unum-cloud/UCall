/**
 *  @file include/ucall/dns/messages.hpp
 *  @author Ash Vardanian
 *  @date November 5, 2026
 *  @brief Composing recursive queries and decoding their answers, refusing every malformed packet.
 *
 *  Every read is bounded by the packet; a compression pointer must point strictly before itself,
 *  and a decoded name is at most 255 bytes, so no packet can loop the decoder or read past its end.
 *  Answers are taken in the order resolvers send them, following a CNAME chain from the question.
 */
#pragma once

#include <cstring> // `std::memcpy`, `std::memcmp`

#include <algorithm>   // `std::min`
#include <string_view> // `std::string_view`

#include "ucall/dns/types.hpp"

namespace unum::ucall::dns {

/** A name on the wire, lowercased, as length-prefixed labels ending in the root's zero byte. */
struct wire_name_t {
    byte_t bytes[name_bytes_k] {};
    std::size_t length {};

    [[nodiscard]] bool equals(wire_name_t const& other) const noexcept {
        return length == other.length && std::memcmp(bytes, other.bytes, length) == 0;
    }
};

inline std::uint16_t read_u16(byte_t const* bytes) noexcept {
    return static_cast<std::uint16_t>(static_cast<unsigned>(bytes[0]) << 8 | static_cast<unsigned>(bytes[1]));
}
inline std::uint32_t read_u32(byte_t const* bytes) noexcept {
    return static_cast<std::uint32_t>(read_u16(bytes)) << 16 | read_u16(bytes + 2);
}
inline void write_u16(byte_t* bytes, std::uint16_t value) noexcept {
    bytes[0] = static_cast<byte_t>(value >> 8);
    bytes[1] = static_cast<byte_t>(value);
}
inline byte_t lowercase(byte_t byte) noexcept {
    auto const value = static_cast<unsigned char>(byte);
    return value - 'A' < 26u ? static_cast<byte_t>(value + ('a' - 'A')) : byte;
}

/** Spells dotted @p name on the wire, lowercased; a trailing dot is allowed. Answers false for an
 *  empty name, an empty or over-long label, or a name over 255 bytes. */
[[nodiscard]] inline bool spell_name(std::string_view name, wire_name_t& wire) noexcept {
    if (!name.empty() && name.back() == '.') name.remove_suffix(1);
    if (name.empty()) return false;
    wire.length = 0;
    while (true) {
        auto const dot = name.find('.');
        auto const label = name.substr(0, dot);
        if (label.empty() || label.size() > 63 || wire.length + 1 + label.size() + 1 > name_bytes_k) return false;
        wire.bytes[wire.length++] = static_cast<byte_t>(label.size());
        for (char const character : label) wire.bytes[wire.length++] = lowercase(static_cast<byte_t>(character));
        if (dot == std::string_view::npos) break;
        name.remove_prefix(dot + 1);
    }
    wire.bytes[wire.length++] = byte_t {0};
    return true;
}

/** Writes a recursive query for @p name of @p type into @p query, answering its length. */
inline std::size_t compose_query(span<byte_t, query_bytes_k> query, std::uint16_t id, wire_name_t const& name,
                                 record_type_t type) noexcept {
    std::memset(query.data(), 0, 12);
    write_u16(query.data(), id);
    query[2] = byte_t {0x01}; // RD: the server recurses for the stub.
    write_u16(query.data() + 4, 1);
    std::memcpy(query.data() + 12, name.bytes, name.length);
    write_u16(query.data() + 12 + name.length, static_cast<std::uint16_t>(type));
    write_u16(query.data() + 14 + name.length, 1);
    return 16 + name.length;
}

/** Decodes the name at @p offset of @p packet into @p name, lowercased, and sets @p next past the
 *  name where it began; answers false for anything RFC 1035 §4.1.4 does not allow. */
[[nodiscard]] inline bool decode_name(span<byte_t const> packet, std::size_t offset, wire_name_t& name,
                                      std::size_t& next) noexcept {
    std::size_t position = offset;
    std::size_t resume = 0;
    name.length = 0;
    while (true) {
        if (position >= packet.size()) return false;
        auto const head = static_cast<unsigned>(packet[position]);
        if ((head & 0xC0) == 0xC0) {
            if (position + 1 >= packet.size()) return false;
            std::size_t const target = (head & 0x3F) << 8 | static_cast<unsigned>(packet[position + 1]);
            // Pointing only backward, every loop adds labels, which the 255-byte bound then stops.
            if (target >= position) return false;
            if (!resume) resume = position + 2;
            position = target;
            continue;
        }
        if (head & 0xC0) return false;
        if (head == 0) {
            if (name.length + 1 > name_bytes_k) return false;
            name.bytes[name.length++] = byte_t {0};
            next = resume ? resume : position + 1;
            return true;
        }
        if (position + 1 + head > packet.size() || name.length + 1 + head + 1 > name_bytes_k) return false;
        name.bytes[name.length++] = static_cast<byte_t>(head);
        for (std::size_t index = 0; index != head; ++index)
            name.bytes[name.length++] = lowercase(packet[position + 1 + index]);
        position += 1 + head;
    }
}

/** What an answer held: its verdict, the least TTL it relied on, and the addresses it carried. */
struct decoded_answer_t {
    answer_t answer {answer_t::malformed_k};
    std::uint32_t ttl_seconds {};
    std::size_t addresses_count {};
};

/** The negative-caching TTL of RFC 2308 §5: the SOA's own TTL or its MINIMUM, whichever is less,
 *  or zero without an SOA. Answers false for a malformed authority section. */
[[nodiscard]] inline bool negative_ttl(span<byte_t const> packet, std::size_t position, std::size_t records,
                                       std::uint32_t& ttl_seconds) noexcept {
    ttl_seconds = 0;
    wire_name_t owner {}, ignored {};
    for (std::size_t record = 0; record != records; ++record) {
        if (!decode_name(packet, position, owner, position) || position + 10 > packet.size()) return false;
        auto const type = read_u16(packet.data() + position);
        auto ttl = read_u32(packet.data() + position + 4);
        std::size_t const length = read_u16(packet.data() + position + 8);
        position += 10;
        if (position + length > packet.size()) return false;
        if (type == static_cast<std::uint16_t>(record_type_t::soa_k)) {
            std::size_t cursor = position;
            if (!decode_name(packet, cursor, ignored, cursor) || !decode_name(packet, cursor, ignored, cursor) ||
                cursor + 20 != position + length)
                return false;
            if (ttl & 0x80000000u) ttl = 0; // RFC 2181 §8: the top bit makes a TTL read as zero.
            ttl_seconds = std::min(ttl, read_u32(packet.data() + cursor + 16));
        }
        position += length;
    }
    return true;
}

/**
 *  @brief Decodes the answer to the query @p id asked for @p question of @p type, copying up to
 *      @p addresses' capacity of addresses, each 4 bytes for A and 16 for AAAA.
 *
 *  A truncated answer reports @c truncated_k once its question checks out, and a stream carrier
 *  treats that as malformed. NXDOMAIN and NODATA carry their negative-caching TTL.
 */
[[nodiscard]] inline decoded_answer_t decode_answer(span<byte_t const> packet, std::uint16_t id,
                                                    wire_name_t const& question, record_type_t type,
                                                    span<byte_t> addresses) noexcept {
    decoded_answer_t decoded {};
    if (packet.size() < 12 || read_u16(packet.data()) != id) return decoded;
    auto const flags = read_u16(packet.data() + 2);
    bool const response = flags & 0x8000, standard = ((flags >> 11) & 0xF) == 0, truncated = flags & 0x0200;
    unsigned const code = flags & 0xF;
    if (!response || !standard || read_u16(packet.data() + 4) != 1) return decoded;

    wire_name_t name {};
    std::size_t position = 0;
    if (!decode_name(packet, 12, name, position) || !name.equals(question) || position + 4 > packet.size() ||
        read_u16(packet.data() + position) != static_cast<std::uint16_t>(type) ||
        read_u16(packet.data() + position + 2) != 1)
        return decoded;
    position += 4;
    if (truncated) return decoded.answer = answer_t::truncated_k, decoded;
    if (code != 0 && code != 3) return decoded.answer = answer_t::failed_k, decoded;

    std::size_t const answers = read_u16(packet.data() + 6), authorities = read_u16(packet.data() + 8);
    // The smallest record is 11 bytes, so counts the packet cannot hold are refused before a walk.
    if ((answers + authorities) * 11 > packet.size() - position) return decoded;

    std::size_t const width = type == record_type_t::a_k ? 4 : 16;
    wire_name_t target = question, owner {};
    std::uint32_t least_ttl = ~std::uint32_t {0};
    for (std::size_t record = 0; record != answers; ++record) {
        if (!decode_name(packet, position, owner, position) || position + 10 > packet.size()) return decoded;
        auto const record_type = read_u16(packet.data() + position);
        auto const record_class = read_u16(packet.data() + position + 2);
        auto ttl = read_u32(packet.data() + position + 4);
        std::size_t const length = read_u16(packet.data() + position + 8);
        position += 10;
        if (position + length > packet.size()) return decoded;
        if (ttl & 0x80000000u) ttl = 0;
        if (record_class == 1 && owner.equals(target)) {
            if (record_type == static_cast<std::uint16_t>(record_type_t::cname_k)) {
                std::size_t end = 0;
                if (!decode_name(packet, position, target, end) || end != position + length) return decoded;
                least_ttl = std::min(least_ttl, ttl);
            }
            else if (record_type == static_cast<std::uint16_t>(type)) {
                if (length != width) return decoded;
                if ((decoded.addresses_count + 1) * width <= addresses.size())
                    std::memcpy(addresses.data() + decoded.addresses_count++ * width, packet.data() + position, width);
                least_ttl = std::min(least_ttl, ttl);
            }
        }
        position += length;
    }
    if (decoded.addresses_count) {
        decoded.ttl_seconds = least_ttl;
        return decoded.answer = answer_t::addresses_k, decoded;
    }
    if (!negative_ttl(packet, position, authorities, decoded.ttl_seconds)) return decoded;
    decoded.answer = code == 3 ? answer_t::absent_k : answer_t::empty_k;
    return decoded;
}

} // namespace unum::ucall::dns
