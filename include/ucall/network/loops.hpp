/**
 *  @file include/ucall/network/loops.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Interfaces, their acceptors, file window pools, and the event loops that poll them.
 */
#pragma once

#include <smashtable/intrusive_list.hpp> // `intrusive_list`

#include "ucall/io/types.hpp"          // `io_completion_t`, `io_operation_t`, `io_request_t`, `range_pinning_t`
#include "ucall/network/exchanges.hpp" // `replied_k`
#include "ucall/network/types.hpp" // `operation_state_t`, `file_window_records_k`, `file_record_stride_k`, `page_bytes_k`
#include "ucall/utilities/sockets.hpp" // `close_native_file`, `socket_close`
#include "ucall/utilities/types.hpp"   // `allocator_delete`, `is_current_thread`, `polling_thread_t`, `byte_t`

namespace unum::ucall::network {

using io::io_completion_t;
using io::io_operation_t;
using io::io_peer_address_t;
using io::io_request_t;
using io::range_pinning_t;
using io::registered_memory_t;
using io::wake_channel_t;
using utilities::allocator_delete;
using utilities::byte_t;
using utilities::close_native_file;
using utilities::descriptor_t;
using utilities::is_current_thread;
using utilities::polling_thread_t;
using utilities::socket_close;
using utilities::span;

template <typename network_type_>
struct network_interface {
    using network_t = network_type_;
    using allocator_t = typename network_t::allocator_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;

    explicit network_interface(allocator_t const& allocator = {}) noexcept
        : address(rebound_allocator<char> {allocator}), device(rebound_allocator<char> {allocator}),
          reply_directory_descriptors(rebound_allocator<native_file_t> {allocator}),
          reply_directory_names(rebound_allocator<char> {allocator}),
          reply_directory_views(rebound_allocator<ucall_bytes_view_t> {allocator}) {}
    network_interface(network_interface const&) = delete;
    network_interface& operator=(network_interface const&) = delete;
    network_interface(network_interface&&) = delete;
    network_interface& operator=(network_interface&&) = delete;

    ~network_interface() noexcept {
        for (native_file_t directory : reply_directory_descriptors) close_native_file(directory);
    }

    ucall_network_interface_t config {};
    vector<char> address {}, device {};
    byte_t public_key[32] {};
    ucall_noise_key_t private_key {}, peer_key {};

    /** Opened from @c reply_directories, which path parts resolve beneath. */
    vector<native_file_t> reply_directory_descriptors {};

    /** The listener's @c SO_SNDBUF, which every accepted socket inherits. */
    std::size_t send_buffer_bytes {};

    /** The listener's address family, which each acceptor's reserve socket takes. */
    int family {};

    /** Every reply directory, NUL-terminated, back to back. */
    vector<char> reply_directory_names {};

    /** Views into @c reply_directory_names, as the resolved configuration reports them. */
    vector<ucall_bytes_view_t> reply_directory_views {};

    /** The share of @c max_concurrent_connections that event loop @p index admits, one of the
     *  interface's @c event_loops. */
    std::size_t quota(std::size_t index) const noexcept {
        return config.max_concurrent_connections / config.event_loops +
               (index < config.max_concurrent_connections % config.event_loops);
    }

    /** Admitted connections across every loop, and the admissions of them that pending accepts
     *  hold before any peer arrived, apart from the words each request reads. */
    alignas(fu::default_alignment_k) std::size_t active {}, accepting {};
};
template <typename network_type_>
struct interface_acceptor {
    using network_t = network_type_;
    using network_interface_t = typename network_t::network_interface_t;
    using event_loop_t = typename network_t::event_loop_t;
    using allocator_t = typename network_t::allocator_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;

    explicit interface_acceptor(allocator_t const& allocator = {}) noexcept
        : peer_addresses(rebound_allocator<io_peer_address_t> {allocator}) {}
    interface_acceptor(interface_acceptor const&) = delete;
    interface_acceptor& operator=(interface_acceptor const&) = delete;
    interface_acceptor(interface_acceptor&&) = delete;
    interface_acceptor& operator=(interface_acceptor&&) = delete;
    io_request_t request {};

    /** Where the engine writes the addresses of the peers one accept takes, one each, as many as
     *  the loop's share of the interface admits. */
    vector<io_peer_address_t> peer_addresses {};
    network_interface_t* network_interface {};
    event_loop_t* event_loop {};

    /** Idle, accepting, accepting without admission to find a peer worth an eviction, or shedding
     *  the peer an exhausted descriptor table queued: accepting it into the freed reserve, then,
     *  while @c shed_request holds its socket, refusing it. */
    enum class stage_t { idle_k, submitted_k, probing_k, shedding_k };
    stage_t stage {stage_t::idle_k};
    descriptor_t descriptor {-1};

    /** A socket of the listener's family held so that freeing it lets one accept through when the
     *  process ran out of descriptors; closed only while shedding or while the residue waits. */
    descriptor_t reserve_descriptor {-1};

    /** The refusal of a shed peer, whose socket its @c descriptor holds until closed: a send of
     *  @c shed_reply_k, or under Noise a reset at once. */
    io_request_t shed_request {};
};

/** One event loop's windows, after UStore's @c registered_memory_arena: each a page of headroom and
 *  four record strides, grown on demand up to @c max_windows in runs filling the allocator's page,
 *  each run registered with the engine once while the engine pins them, and never shrunk. Streams
 *  borrow windows in file order, and each comes back once the kernel let go of it, to serve the
 *  oldest stream waiting. */
template <typename network_type_>
struct file_window_pool {
    using network_t = network_type_;
    using allocator_t = typename network_t::allocator_t;
    using connection_t = typename network_t::server_connection_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;

    static constexpr std::size_t window_bytes = page_bytes_k + file_window_records_k * file_record_stride_k;
    struct alignas(page_bytes_k) page_t {
        byte_t bytes[page_bytes_k];
    };
    explicit file_window_pool(allocator_t const& allocator = {}) noexcept
        : window_runs(rebound_allocator<span<byte_t>> {allocator}),
          window_memory(rebound_allocator<byte_t*> {allocator}), windows(rebound_allocator<file_window_t> {allocator}),
          release_requests(rebound_allocator<io_request_t> {allocator}) {}
    file_window_pool(file_window_pool const&) = delete;
    file_window_pool& operator=(file_window_pool const&) = delete;
    file_window_pool(file_window_pool&&) = delete;
    file_window_pool& operator=(file_window_pool&&) = delete;

    /** One allocation each, holding whole windows. */
    vector<span<byte_t>> window_runs {};

    /** One window each. */
    vector<byte_t*> window_memory {};

    /** Reserved to @c max_windows at open, never moved. */
    vector<file_window_t> windows {};

    /** Parallel to @c windows, and engines hold pointers into it; each names the engine buffer
     *  its window's sends lie in as its @c registered_memory. */
    vector<io_request_t> release_requests {};
    std::uint32_t free_windows {absent_k}, allocated_windows {}, max_windows {}, releasing_windows {};
    connection_t *oldest_waiting_connection {}, *newest_waiting_connection {};
    range_pinning_t pinning {range_pinning_t::pinned_k};

    /** The window whose release @p request is, or @c absent_k for an exchange's. */
    std::uint32_t window_of(io_request_t const* request) const noexcept {
        std::size_t const index = static_cast<std::size_t>(request - release_requests.data());
        return request >= release_requests.data() && index < allocated_windows ? static_cast<std::uint32_t>(index)
                                                                               : absent_k;
    }
    registered_memory_t registered_memory(std::uint32_t window) const noexcept {
        return release_requests[window].registered_memory;
    }
};
enum class event_loop_stage_t { unopened_k, serving_k, draining_k, cutting_k, retired_k };

/** One loop's admitted connections of one interface that hold no exchange, least recently
 *  progressed first, the peer a saturated accept parked until a close frees its slot, and the
 *  connection evicted for it, absent while every connection is busy. */
struct interface_order_t {
    st::intrusive_list<std::uint32_t> keepalive {};
    descriptor_t evicting {-1};
    std::uint32_t evicted {absent_k};
    ucall_peer_address_t evicting_peer {};
};

/** Whether a loop's StatsD socket is absent, free to send, or sending a datagram. */
enum class metrics_state_t : std::uint8_t { closed_k, idle_k, sending_k };

/** One loop's StatsD socket, what its datagrams last reported, and two datagram buffers: one
 *  composing while the other sends. */
template <typename network_type_>
struct loop_metrics {
    using network_t = network_type_;
    using allocator_t = typename network_t::allocator_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;

    explicit loop_metrics(allocator_t const& allocator = {}) noexcept
        : composing(rebound_allocator<byte_t> {allocator}), sending(rebound_allocator<byte_t> {allocator}),
          interfaces_reported(rebound_allocator<interface_statistics_t> {allocator}),
          interfaces_reporting(rebound_allocator<interface_statistics_t> {allocator}),
          batches_reported(rebound_allocator<ucall_batch_endpoint_statistics_t> {allocator}),
          batches_reporting(rebound_allocator<ucall_batch_endpoint_statistics_t> {allocator}) {}
    io_request_t send_request {};
    metrics_state_t state {};

    /** Folded into the poll deadline, as the oldest linger's is. */
    std::uint64_t due {};

    /** Gains the sample rate per finished request; a latency line spends one. */
    float sample_credit {};

    /** Latency lines that found both buffers taken. */
    std::uint64_t dropped_lines {};
    vector<byte_t> composing {}, sending {};

    /** What the last delivered datagram reported, and what the one in flight will. */
    ucall_event_loop_statistics_t reported {}, reporting {};
    vector<interface_statistics_t> interfaces_reported {}, interfaces_reporting {};

    /** Loop zero only. */
    vector<ucall_batch_endpoint_statistics_t> batches_reported {}, batches_reporting {};
};

template <typename network_type_>
struct event_loop {
    using network_t = network_type_;
    using allocator_t = typename network_t::allocator_t;
    using engine_t = typename network_t::engine_t;
    using connection_t = typename network_t::server_connection_t;
    using replied_link_t = typename network_t::replied_link_t;
    using server_exchange_t = typename network_t::server_exchange_t;
    using interface_acceptor_t = typename network_t::interface_acceptor_t;
    using file_window_pool_t = typename network_t::file_window_pool_t;
    using loop_metrics_t = typename network_t::loop_metrics_t;
    using server_t = typename network_t::server_t;
    using client_t = typename network_t::client_t;
    template <typename value_type_>
    using rebound_allocator = typename network_t::template rebound_allocator<value_type_>;
    template <typename value_type_>
    using vector = typename network_t::template vector<value_type_>;
    template <typename value_type_>
    using owner = typename network_t::template owner<value_type_>;
    template <typename value_type_>
    using atomic_ref = typename network_t::template atomic_ref<value_type_>;

    allocator_t allocator;
    explicit event_loop(allocator_t const& allocator = {}) noexcept
        : allocator(allocator), engine(allocator), completions(rebound_allocator<io_completion_t> {allocator}),
          connections(rebound_allocator<owner<connection_t>> {allocator}),
          interface_statistics(rebound_allocator<interface_statistics_t> {allocator}),
          interface_orders(rebound_allocator<interface_order_t> {allocator}), metrics(allocator),
          file_windows(allocator) {}
    event_loop(event_loop const&) = delete;
    event_loop& operator=(event_loop const&) = delete;
    event_loop(event_loop&&) = delete;
    event_loop& operator=(event_loop&&) = delete;

    engine_t engine {};
    wake_channel_t wake {};
    vector<io_completion_t> completions {};
    server_t* server {};
    event_loop_stage_t stage {event_loop_stage_t::unopened_k};

    /** The thread inside @c take_call, written only by it; zero between polls. */
    polling_thread_t polling_thread {};
    vector<owner<connection_t>> connections {};
    span<interface_acceptor_t> interface_acceptors {};
    connection_t* idle {};
    connection_t* ready {};

    /** Connections off the idle list, so a stopping loop knows when it is done. */
    std::size_t open_connections {};

    /** Clients this loop advances, linked through @c next_bound, and the engine slots they take. */
    client_t* bound_clients {};
    std::size_t bound_slots {};
    server_exchange_t* exchanges {};
    server_exchange_t* free_exchanges {};
    ucall_status_t setup_status {ucall_status_success_k};

    /** Vyukov's intrusive queue of listed exchanges: any replying thread exchanges the tail,
     *  and the loop alone walks from the head, which starts at the stub. */
    replied_link_t replied_stub {};
    replied_link_t* replied_head {&replied_stub};
    alignas(fu::default_alignment_k) replied_link_t* replied_tail {&replied_stub};
    alignas(fu::default_alignment_k) wake_state_t wake_state {wake_state_t::awake_k};
    event_loop_statistics_t statistics {};
    std::uint32_t index {};

    /** One per interface, by its index. */
    vector<interface_statistics_t> interface_statistics {};
    vector<interface_order_t> interface_orders {};
    loop_metrics_t metrics;
    file_window_pool_t file_windows;

    /** Pipelined requests its connections may hold at once, which also bounds the exchanges that
     *  outlive their closed connections, @c orphaned_exchanges, until answered. */
    std::size_t max_exchanges {}, orphaned_exchanges {};

    /** Lingers and closes waiting for releases, in the order they started, which is deadline order
     *  as each waits @c linger_microseconds_k. */
    st::intrusive_list<std::uint32_t> expiring {};

    /** When the reserves a host short of more than descriptors held closed reopen, unless a
     *  connection closes first; zero when every reserve is open or shedding. */
    std::uint64_t accept_deadline {};
    void notify() noexcept {
        // A running loop meets what was listed before it sleeps, so only a sleeper is written.
        if (atomic_ref<wake_state_t> {wake_state}.exchange(wake_state_t::notified_k, std::memory_order_acq_rel) ==
            wake_state_t::sleeping_k)
            wake.notify();
    }

    /** Whether the calling thread is the one polling this loop. */
    bool polled_by_this_thread() const noexcept {
        return is_current_thread(atomic_ref<polling_thread_t const> {polling_thread}.load(std::memory_order_relaxed));
    }
    ~event_loop() noexcept {
        engine.stop();
        if (wake.descriptors[0] < 0 && wake.request.descriptor >= 0) engine.close_socket(wake.request.descriptor);
        if (metrics.state != metrics_state_t::closed_k) engine.close_socket(metrics.send_request.descriptor);
        for (auto& order : interface_orders)
            if (order.evicting >= 0) engine.close_socket(order.evicting);
        for (auto& connection : connections)
            if (connection && connection->transport.descriptor >= 0 &&
                !(connection->transport.receive_operation == operation_state_t::submitted_k &&
                  connection->transport.receive_request.operation == io_operation_t::close_k &&
                  connection->transport.receive_request.descriptor < 0))
                engine.close_socket(connection->transport.descriptor);
        while (exchanges) {
            auto* next = exchanges->next;
            allocator_delete<server_exchange_t, allocator_t> {allocator}(exchanges);
            exchanges = next;
        }
        for (span<byte_t> run : file_windows.window_runs)
            rebound_allocator<typename file_window_pool_t::page_t> {allocator}.deallocate(
                reinterpret_cast<typename file_window_pool_t::page_t*>(run.data()), run.size() / page_bytes_k);
        for (auto& acceptor : interface_acceptors) {
            if (acceptor.request.descriptor >= 0) {
                if (acceptor.descriptor >= 0) socket_close(acceptor.descriptor);
                else engine.close_socket(acceptor.request.descriptor);
            }
            if (acceptor.shed_request.descriptor >= 0) engine.close_socket(acceptor.shed_request.descriptor);
            if (acceptor.reserve_descriptor >= 0) socket_close(acceptor.reserve_descriptor);
            std::destroy_at(&acceptor);
        }
        if (!interface_acceptors.empty())
            rebound_allocator<interface_acceptor_t> {allocator}.deallocate(interface_acceptors.data(),
                                                                           interface_acceptors.size());
    }
};

} // namespace unum::ucall::network
