/**
 *  @file src_stub/lib.hpp
 *  @author Ash Vardanian
 *  @date November 16, 2026
 *  @brief The handles, outcomes and checks the stand-in's server, client and types units share.
 *
 *  The stand-in defines every @c UCALL_EXPORT symbol of the C interface without the engine: no
 *  event loop, no socket and no CPU class ladder. It validates each call as the headers document,
 *  keeps the state a refusal depends on, such as the registered routes and each server's loop
 *  count, and answers @c ucall_status_unsupported_k wherever the engine would touch the network.
 *  A binding, a downstream SDK or a bisect links it in seconds and meets the documented refusals.
 *
 *  It reuses the project's header-only parts rather than restating them: the route trie, the serial
 *  string kits, the socket helpers that read a device's queues and vet a caller-owned listener, and
 *  the outcome publisher. It runs the serial CPU class alone, through ForkUnion's standard atomic
 *  reference and yielding waiter.
 *
 *  So a server or client under any CPU class ceiling initializes and resolves to serial, the one
 *  class every ceiling admits, and only a value no class takes answers
 *  @c ucall_status_invalid_argument_k. A suite sweeping classes keeps the ceilings that resolve to
 *  themselves, as the native harness's @c opens does, and reads the rest as skipped.
 */
#pragma once

#include <cstddef> // `std::size_t`
#include <cstdint> // `std::uint32_t`
#include <cstring> // `std::strcmp`

#include <charconv>    // `std::from_chars`
#include <limits>      // `std::numeric_limits`
#include <utility>     // `std::exchange`
#include <string_view> // `std::string_view`

#include "ucall/ucall.h"
#include "ucall/http/routes.hpp"       // `route_trie_t`, `route_search_t`
#include "ucall/utilities/sockets.hpp" // `receive_queues_count`, `socket_duplicate_listener`
#include "ucall/utilities/types.hpp"   // `publish`, `allocate_unique`, `text_view`

namespace unum::ucall::stub {

/** The serial class's atomic reference, as @c src/lib.hpp picks it, since the stand-in runs no
 *  other class. */
template <typename value_type_>
using atomic_ref = fu::standard_atomic_ref<value_type_>;

/** The serial string kits, which every check below searches with. */
using http_t = http::route_search_t;

using allocator_t = st::default_allocator<byte_t>;

template <typename value_type_>
using vector = st::vector<value_type_, st::default_allocator<value_type_>>;

/** The message of every verb the engine would answer over a socket. */
inline constexpr char const* no_network_k = "the stub serves no network";

/** The message of every request or response accessor given a handle, as the stand-in receives
 *  none, so no handle it is given can be one. */
inline constexpr char const* no_exchange_k = "the stub receives no request or response";

/** The one final write to @p outcome, through the serial class's reference. */
inline void publish(ucall_outcome_t* outcome, ucall_status_t status, char const* message) noexcept {
    utilities::publish<atomic_ref>(outcome, status, message);
}
inline void publish(ucall_outcome_t* outcome, ucall_status_t status) noexcept {
    publish(outcome, status, ucall_status_name(status));
}

/** Answers @c ucall_status_uninitialized_k for a @c NULL @p handle, as @c src/lib.cpp admits it. */
template <typename handle_type_>
[[nodiscard]] bool admit(handle_type_ const* handle, ucall_outcome_t* outcome) noexcept {
    if (handle) return true;
    publish(outcome, ucall_status_uninitialized_k);
    return false;
}

/** Refuses an accessor's request or response: a @c NULL one as the engine does, and any other as
 *  a handle the stand-in never issued. */
inline void refuse_exchange(void const* exchange, ucall_outcome_t* outcome) noexcept {
    if (exchange) publish(outcome, ucall_status_invalid_argument_k, no_exchange_k);
    else publish(outcome, ucall_status_invalid_argument_k);
}

/** Whether @p name is the spelling of a value no member of its enumeration takes. */
inline bool unrecognized(char const* name) noexcept { return std::strcmp(name, "unrecognized") == 0; }

/** Whether this operating system offers @p backend, the engine's refusal of one it cannot open. */
inline bool backend_offered(ucall_io_backend_t backend) noexcept {
    switch (backend) {
    case ucall_io_backend_automatic_k: return true;
    case ucall_io_backend_posix_k: return UCALL_OS_POSIX_;
    case ucall_io_backend_linux_epollaio_k:
    case ucall_io_backend_linux_uring612_k:
    case ucall_io_backend_linux_uring618_k: return UCALL_OS_LINUX_;
    case ucall_io_backend_bsd_kqueue_k: return UCALL_OS_APPLE_ || UCALL_OS_FREEBSD_;
    case ucall_io_backend_windows_iocp_k:
    case ucall_io_backend_windows_rio_k: return UCALL_OS_WINDOWS_;
    }
    return false;
}

inline bool security_valid(ucall_security_t security) noexcept {
    return security >= ucall_security_none_k && security <= ucall_security_noise_kk_k;
}

/** Whether @p address spells "host:port" as the engine splits it before resolving: a host, in
 *  brackets when it holds a colon, and a decimal port up to 65535. */
inline bool address_valid(std::string_view address) noexcept {
    std::size_t const colon = http_t::rfind(address, ':');
    if (colon == std::string_view::npos || !colon || colon + 1 == address.size()) return false;
    std::string_view name = address.substr(0, colon), port = address.substr(colon + 1);
    if (name.front() == '[' && name.back() == ']') name = name.substr(1, name.size() - 2);
    else if (http_t::find(name, ':') != std::string_view::npos) return false;
    unsigned number = 0;
    auto const parsed = std::from_chars(port.data(), port.data() + port.size(), number);
    return parsed.ec == std::errc {} && parsed.ptr == port.data() + port.size() && number <= 65535 && !name.empty() &&
           http_t::find(name, '\0') == std::string_view::npos;
}

/** Overwrites a copied secret, through a volatile view the compiler cannot drop as a dead store. */
inline void secure_zero(ucall_noise_key_t& key) noexcept {
    auto volatile* bytes = key;
    for (std::size_t i = 0; i != sizeof(ucall_noise_key_t); ++i) bytes[i] = 0;
}

} // namespace unum::ucall::stub

/** A batch endpoint: nothing is ever deposited into it, so it only names its server. */
struct ucall_http_batch_endpoint_handle_t {
    ucall_server_t server {};
    ucall_http_batch_endpoint_handle_t* next {};
};

/** One template the routes point into, kept until the server is freed, as a refused one may already
 *  point the trie at its segments. */
struct ucall_stub_template_t {
    uc::stub::vector<char> text {};
    ucall_stub_template_t* next {};
};

/** The copies of one interface's keys, which the resolved configuration points at. */
struct ucall_stub_keys_t {
    ucall_noise_key_t private_key {};
    ucall_noise_key_t peer_key {};
};

/** A socketless server: its resolved configuration, its routes and its loop count, which the
 *  refusals of later calls read. */
struct ucall_server_handle_t {
    uc::stub::allocator_t allocator {};
    uc::http::route_trie_t routes {allocator};

    /** The resolved configuration, pointing into the copies below. */
    ucall_server_options_t config {};
    uc::stub::vector<ucall_network_interface_t> interfaces {};
    uc::stub::vector<ucall_stub_keys_t> keys {};

    /** Every reply directory of every interface, then the metric tags. */
    uc::stub::vector<ucall_bytes_view_t> views {};

    /** Addresses, device names, reply directories, each followed by a NUL, the prefix and the
     *  tags, sized once so the views above never move. */
    uc::stub::vector<char> text {};

    /** The largest @c event_loops among the interfaces, past which a loop index is refused. */
    std::size_t event_loops {};

    /** Clients bound to one of the loops, which @c ucall_server_free() waits out; touched through
     *  @c atomic_ref, as clients are made and freed on any thread. */
    std::size_t bound_clients {};

    ucall_stub_template_t* templates {};
    ucall_http_batch_endpoint_handle_t* batch_endpoints {};

    ~ucall_server_handle_t() noexcept {
        for (auto& keys : keys) uc::stub::secure_zero(keys.private_key);
        while (templates)
            uc::utilities::allocator_delete<ucall_stub_template_t, uc::stub::allocator_t> {allocator}(
                std::exchange(templates, templates->next));
        while (batch_endpoints)
            uc::utilities::allocator_delete<ucall_http_batch_endpoint_handle_t, uc::stub::allocator_t> {allocator}(
                std::exchange(batch_endpoints, batch_endpoints->next));
    }
};

/** A client that admits no call: its resolved configuration and the server it is bound to. */
struct ucall_client_handle_t {
    uc::stub::allocator_t allocator {};
    ucall_client_options_t config {};
    ucall_noise_key_t private_key {};

    ~ucall_client_handle_t() noexcept { uc::stub::secure_zero(private_key); }
};
