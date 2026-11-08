/**
 *  @file include/ucall/network.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Client and server composites over an I/O engine, string kernels, and atomic references.
 */
#pragma once

#include <smashtable/row_search.hpp> // `serial_row_kit_t`

#include "ucall/http/messages.hpp"        // `messages`, `serial_compare_kit_t`, `serial_find_kit_t`
#include "ucall/network/types.hpp"        // `transport_stage_t`, `reply_segment`, `file_segment`
#include "ucall/network/transports.hpp"   // `transport`
#include "ucall/network/exchanges.hpp"    // `endpoint`, `batch_endpoint`, `server_exchange`
#include "ucall/network/loops.hpp"        // `network_interface`, `interface_acceptor`, `event_loop`
#include "ucall/network/formatting.hpp"   // `formatting`
#include "ucall/network/replies.hpp"      // `replies`
#include "ucall/network/metrics.hpp"      // `metrics`
#include "ucall/network/serving.hpp"      // `server_connection`, `serving`
#include "ucall/network/server.hpp"       // `server`
#include "ucall/network/client.hpp"       // `client`, `client_connection`, `client_origin`, `response_pool`
#include "ucall/tunnel/crypto.hpp"        // `secure_tunnel_crypto`, `serial_sha256_kit_t`
#include "ucall/tunnel/secure_tunnel.hpp" // `secure_tunnel`
#include "ucall/utilities/types.hpp"      // `byte_t`, `allocated_ptr`

namespace unum::ucall::network {

using http::serial_byteset_kit_t;
using http::serial_compare_kit_t;
using http::serial_find_kit_t;
using http::serial_fold_kit_t;
using http::serial_hash_kit_t;
using tunnel::serial_aes256_gcm_kit_t;
using tunnel::serial_sha256_kit_t;
using tunnel::serial_x25519_kit_t;
using utilities::allocated_ptr;
using utilities::byte_t;

/** The kits, engine and allocator one network is built from, and the names of its records and verb
 *  groups, which take it as their one parameter and read each other through it. */
template <typename engine_type_, template <typename> class atomic_ref_template_, typename waiter_type_,
          typename compare_kit_type_, typename find_kit_type_, typename byteset_kit_type_, typename hash_kit_type_,
          typename fold_kit_type_, typename sha256_kit_type_, typename aes256_gcm_kit_type_, typename x25519_kit_type_,
          typename row_kit_type_, typename allocator_type_ = st::default_allocator<byte_t>>
struct network_variant {
    using http_t = http::messages<compare_kit_type_, find_kit_type_, byteset_kit_type_, hash_kit_type_, fold_kit_type_>;
    using tunnel_t = tunnel::secure_tunnel<sha256_kit_type_, aes256_gcm_kit_type_, x25519_kit_type_>;
    using crypto_t = tunnel::secure_tunnel_crypto<sha256_kit_type_, aes256_gcm_kit_type_, x25519_kit_type_>;
    using waiter_t = waiter_type_;
    using row_kit_t = row_kit_type_;
    using allocator_t = allocator_type_;
    using engine_t = typename engine_type_::template rebind<allocator_t, atomic_ref_template_, row_kit_type_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    template <typename value_type_>
    using vector = st::vector<value_type_, rebound_allocator<value_type_>>;
    template <typename value_type_>
    using owner = allocated_ptr<value_type_, allocator_t>;
    template <typename value_type_>
    using atomic_ref = atomic_ref_template_<value_type_>;
    using http_message_t = typename http_t::http_message_t;

    using reply_segment_t = reply_segment<network_variant>;
    using file_segment_t = file_segment<network_variant>;
    using transport_t = transport<network_variant>;
    using server_connection_t = server_connection<network_variant>;
    using batch_endpoint_t = batch_endpoint<network_variant>;
    using endpoint_t = endpoint<network_variant>;
    using exchange_release_t = exchange_release<network_variant>;
    using replied_link_t = replied_link<network_variant>;
    using server_exchange_t = server_exchange<network_variant>;
    using network_interface_t = network_interface<network_variant>;
    using interface_acceptor_t = interface_acceptor<network_variant>;
    using file_window_pool_t = file_window_pool<network_variant>;
    using loop_metrics_t = loop_metrics<network_variant>;
    using event_loop_t = event_loop<network_variant>;
    using server_t = server<network_variant>;
    using response_t = response<network_variant>;
    using response_pool_t = response_pool<network_variant>;
    using client_exchange_t = client_exchange<network_variant>;
    using client_origin_t = client_origin<network_variant>;
    using client_connection_t = client_connection<network_variant>;
    using client_lookup_t = client_lookup<network_variant>;
    using client_t = client<network_variant>;

    using formatting_t = formatting<network_variant>;
    using replies_t = replies<network_variant>;
    using metrics_t = metrics<network_variant>;
    using serving_t = serving<network_variant>;
    using resolving_t = resolving<network_variant>;

    using transport_stage_t = network::transport_stage_t;
    using operation_state_t = network::operation_state_t;
    using transmit_state_t = network::transmit_state_t;
};

/** Portable network over the serial kits, for callers without a CPU dispatch point. */
template <typename engine_type_, typename allocator_type_ = st::default_allocator<byte_t>>
using serial_network =
    network_variant<engine_type_, fu::standard_atomic_ref, fu::standard_yield_t, serial_compare_kit_t,
                    serial_find_kit_t, serial_byteset_kit_t, serial_hash_kit_t, serial_fold_kit_t, serial_sha256_kit_t,
                    serial_aes256_gcm_kit_t, serial_x25519_kit_t, st::serial_row_kit_t, allocator_type_>;

} // namespace unum::ucall::network
