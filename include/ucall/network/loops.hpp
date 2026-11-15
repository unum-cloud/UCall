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

    explicit network_interface(allocator_t const& allocator) noexcept
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

    /** The caller's interface settings, resolved: its views and keys point into this record. */
    ucall_network_interface_t config {};

    /** The bound address as text, NUL-terminated, which @c config.address views once bound. */
    vector<char> address {};

    /** The device name, NUL-terminated, which @c config.device_name views; empty if unset. */
    vector<char> device {};

    /** Derived from @c private_key at initialization; zero when no private key was given. */
    byte_t public_key[32] {};

    /** A copy of the caller's Noise private key, which @c config points at; else zero. */
    ucall_noise_key_t private_key {};

    /** A copy of the caller's expected peer key, which @c config points at; else zero. */
    ucall_noise_key_t peer_key {};

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

    /** Admitted connections across every loop, apart from the words each request reads. */
    alignas(fu::default_alignment_k) std::size_t active {};

    /** Of those, the admissions that pending accepts hold before any peer arrived. */
    alignas(fu::default_alignment_k) std::size_t accepting {};
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

    explicit interface_acceptor(allocator_t const& allocator) noexcept
        : peer_addresses(rebound_allocator<io_peer_address_t> {allocator}) {}
    interface_acceptor(interface_acceptor const&) = delete;
    interface_acceptor& operator=(interface_acceptor const&) = delete;
    interface_acceptor(interface_acceptor&&) = delete;
    interface_acceptor& operator=(interface_acceptor&&) = delete;

    /** The accept on the listener, whose @c length counts down the peers it still takes. */
    io_request_t request {};

    /** Where the engine writes the addresses of the peers one accept takes, one each, as many as
     *  the loop's share of the interface admits. */
    vector<io_peer_address_t> peer_addresses {};

    /** The interface whose listener it accepts on, set at initialization. */
    network_interface_t* network_interface {};

    /** The loop that submits its accepts and admits its peers, set at initialization. */
    event_loop_t* event_loop {};

    /** Bound with its loop yet to import the listener @c request.descriptor names; idle; accepting
     *  under an admission; accepting without one to find a peer worth an eviction; accepting the
     *  peer an exhausted descriptor table queued into the freed reserve; refusing that peer, whose
     *  socket @c shed_request holds. */
    enum class stage_t : std::uint8_t {
        unimported_k,
        idle_k,
        accepting_k,
        probing_k,
        shedding_accept_k,
        shedding_refusal_k
    };

    /** Which of those it is in; only @c accepting_k holds one of the interface's @c accepting. */
    stage_t stage {stage_t::unimported_k};

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

    /** One window's memory: its headroom page and its record strides. */
    static constexpr std::size_t window_bytes = page_bytes_k + file_window_records_k * file_record_stride_k;

    /** The unit runs are allocated in, so every window starts page-aligned. */
    struct alignas(page_bytes_k) page_t {

        /** One page of a run of windows. */
        byte_t bytes[page_bytes_k];
    };
    explicit file_window_pool(allocator_t const& allocator) noexcept
        : window_runs(rebound_allocator<span<byte_t>> {allocator}),
          window_memory(rebound_allocator<byte_t*> {allocator}), windows(rebound_allocator<file_window_t> {allocator}),
          release_requests(rebound_allocator<io_request_t> {allocator}) {}
    file_window_pool(file_window_pool const&) = delete;
    file_window_pool& operator=(file_window_pool const&) = delete;
    file_window_pool(file_window_pool&&) = delete;
    file_window_pool& operator=(file_window_pool&&) = delete;

    /** One allocation each, holding whole windows. */
    vector<span<byte_t>> window_runs {};

    /** Each window's first byte, by window index. */
    vector<byte_t*> window_memory {};

    /** Each window's record, by index; reserved to @c max_windows at open, never moved. */
    vector<file_window_t> windows {};

    /** Parallel to @c windows, and engines hold pointers into it; each names the engine buffer
     *  its window's sends lie in as its @c registered_memory. */
    vector<io_request_t> release_requests {};

    /** The first vacant window, linked through @c file_window_t::next, or @c absent_k. */
    std::uint32_t free_windows {absent_k};

    /** The most windows the pool may hold, set when its loop opens. */
    std::uint32_t max_windows {};

    /** The stream waiting longest for a window, linked by @c next_waiting_connection. */
    connection_t* oldest_waiting_connection {};

    /** The stream that started waiting last; null when none waits. */
    connection_t* newest_waiting_connection {};

    /** Whether new runs are pinned; once a registration declines, later runs stay unpinned. */
    range_pinning_t pinning {range_pinning_t::pinned_k};

    /** The window whose release @p request is, or @c absent_k for an exchange's. */
    std::uint32_t window_of(io_request_t const* request) const noexcept {
        std::size_t const index = static_cast<std::size_t>(request - release_requests.data());
        return request >= release_requests.data() && index < windows.size() ? static_cast<std::uint32_t>(index)
                                                                            : absent_k;
    }
    registered_memory_t registered_memory(std::uint32_t window) const noexcept {
        return release_requests[window].registered_memory;
    }
};

/** Whether a loop is not yet opened by its first poll, serving, draining or cutting after a stop
 *  as its server's stage, or retired with its engine stopped once nothing was left in flight. */
enum class event_loop_stage_t { unopened_k, serving_k, draining_k, cutting_k, retired_k };

/** One loop's admitted connections of one interface that hold no exchange, least recently
 *  progressed first, the peer a saturated accept parked until a close frees its slot, and the
 *  connection evicted for it, absent while every connection is busy. A second peer queues
 *  behind the parked one: its arrival is the event that tells which busy connections sent
 *  nothing in between, and it is parked in turn once the first is admitted. */
struct interface_order_t {

    /** Connections holding no exchange, least recently progressed first, by @c order_link. */
    st::intrusive_list<std::uint32_t> keepalive {};

    /** The parked peer's accepted socket, which the next close admits; -1 when none is parked. */
    descriptor_t parked {-1};

    /** The second peer, waiting behind the parked one; -1 when none queued. */
    descriptor_t queued {-1};

    /** Whether a connection is closing for the parked peer, or none was chosen yet. */
    eviction_t eviction {eviction_t::none_k};

    /** The address @c parked was accepted from, valid while it is parked. */
    ucall_peer_address_t parked_peer {};

    /** The address @c queued was accepted from, valid while it queues. */
    ucall_peer_address_t queued_peer {};
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

    explicit loop_metrics(allocator_t const& allocator) noexcept
        : composing(rebound_allocator<byte_t> {allocator}), sending(rebound_allocator<byte_t> {allocator}),
          interfaces_reported(rebound_allocator<interface_statistics_t> {allocator}),
          interfaces_reporting(rebound_allocator<interface_statistics_t> {allocator}),
          batches_reported(rebound_allocator<ucall_batch_endpoint_statistics_t> {allocator}),
          batches_reporting(rebound_allocator<ucall_batch_endpoint_statistics_t> {allocator}) {}

    /** The send of @c sending to the StatsD socket, which its @c descriptor holds while open. */
    io_request_t send_request {};

    /** Whether the StatsD socket is open, and whether @c send_request is with the engine. */
    metrics_state_t state {};

    /** When counters are next due; folded into the poll deadline, as the oldest linger's is. */
    std::uint64_t due {};

    /** Gains the sample rate per finished request; a latency line spends one. */
    float sample_credit {};

    /** Latency lines that found both buffers taken. */
    std::uint64_t dropped_lines {};

    /** Where latency lines and counter deltas append, up to @c metrics_datagram_bytes. */
    vector<byte_t> composing {};

    /** The datagram with the engine, swapped from @c composing; empty while none is sending. */
    vector<byte_t> sending {};

    /** The counter totals the last delivered datagram reported, the base of the next deltas. */
    ucall_event_loop_statistics_t reported {};

    /** The totals the datagram in flight reports, which become @c reported once it is delivered. */
    ucall_event_loop_statistics_t reporting {};

    /** The interface counters the last delivered datagram reported, one per interface. */
    vector<interface_statistics_t> interfaces_reported {};

    /** The interface counters the datagram in flight reports, one per interface. */
    vector<interface_statistics_t> interfaces_reporting {};

    /** The batch endpoint counters the last delivered datagram reported; loop zero only. */
    vector<ucall_batch_endpoint_statistics_t> batches_reported {};

    /** The batch endpoint counters the datagram in flight reports; loop zero only. */
    vector<ucall_batch_endpoint_statistics_t> batches_reporting {};
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

    /** The server's allocator, which the loop's connections, exchanges and windows take. */
    allocator_t allocator;
    explicit event_loop(allocator_t const& allocator) noexcept
        : allocator(allocator), engine(allocator), completions(rebound_allocator<io_completion_t> {allocator}),
          connections(rebound_allocator<owner<connection_t>> {allocator}),
          interface_statistics(rebound_allocator<interface_statistics_t> {allocator}),
          interface_orders(rebound_allocator<interface_order_t> {allocator}), metrics(allocator),
          file_windows(allocator) {}
    event_loop(event_loop const&) = delete;
    event_loop& operator=(event_loop const&) = delete;
    event_loop(event_loop&&) = delete;
    event_loop& operator=(event_loop&&) = delete;

    /** The loop's own engine, which bound clients share. */
    engine_t engine {};

    /** What wakes a sleeping poll when another thread lists an exchange or stops the server. */
    wake_channel_t wake {};

    /** Where one poll lands its completions, sized to the engine's slots when the loop opens. */
    vector<io_completion_t> completions {};

    /** The server owning the loop, set at initialization. */
    server_t* server {};

    /** Where the loop is in its life; only its polling thread writes it. */
    event_loop_stage_t stage {event_loop_stage_t::unopened_k};

    /** The thread inside @c take_call, written only by it; zero between polls. */
    polling_thread_t polling_thread {};

    /** Every connection of the loop by index, each interface's quota of it, never resized. */
    vector<owner<connection_t>> connections {};

    /** One per interface served by this loop, allocated at initialization. */
    span<interface_acceptor_t> interface_acceptors {};

    /** Connections without a socket, linked through @c next, which admissions take from. */
    connection_t* idle {};

    /** Connections a completion or reply readied, linked through @c next, for the next pass. */
    connection_t* ready {};

    /** Ready connections still shaking hands, oldest first, which a pass advances one of once the
     *  open ones are served, so no stranger's handshake runs ahead of an admitted request. */
    connection_t* oldest_handshake {};

    /** The handshake listed last, which the next one links behind; null when none waits. */
    connection_t* newest_handshake {};

    /** Connections off the idle list, so a stopping loop knows when it is done. */
    std::size_t open_connections {};

    /** Clients this loop advances, linked through @c next_bound, and the engine slots they take. */
    client_t* bound_clients {};

    /** Engine slots the bound clients add to the loop's own, counted before the loop opens. */
    std::size_t bound_slots {};

    /** Every exchange the loop allocated, linked through @c next, freed only with the loop. */
    server_exchange_t* exchanges {};

    /** Exchanges ready for a new request, linked through @c next_queued. */
    server_exchange_t* free_exchanges {};

    /** Why opening the loop or growing its engine for a client failed; later polls return it. */
    ucall_status_t setup_status {ucall_status_success_k};

    /** Vyukov's intrusive queue of listed exchanges: any replying thread exchanges the tail,
     *  and the loop alone walks from the head, which starts at the stub. */
    replied_link_t replied_stub {};

    /** The link whose exchange the loop takes next, or the stub; only the loop touches it. */
    replied_link_t* replied_head {&replied_stub};

    /** The newest link, which every replying thread exchanges to append its own. */
    alignas(fu::default_alignment_k) replied_link_t* replied_tail {&replied_stub};

    /** Whether the polling thread runs, sleeps on @c wake, or was notified since. */
    alignas(fu::default_alignment_k) wake_state_t wake_state {wake_state_t::awake_k};

    /** The loop's own counters, which @c loop_totals adds to the engine's. */
    event_loop_statistics_t statistics {};

    /** The loop's place among its server's loops; loop zero binds listeners and reports batches. */
    std::uint32_t index {};

    /** One per interface, by its index. */
    vector<interface_statistics_t> interface_statistics {};

    /** One per interface, by its index, for the connections this loop admits on it. */
    vector<interface_order_t> interface_orders {};

    /** The StatsD socket and datagrams; closed when the server has no metrics destination. */
    loop_metrics_t metrics;

    /** The windows file segments are read into, grown on demand. */
    file_window_pool_t file_windows;

    /** Pipelined requests its connections may hold at once, which also bounds the exchanges that
     *  outlive their closed connections, @c orphaned_exchanges, until answered. */
    std::size_t max_exchanges {};

    /** Exchanges whose connection closed before their reply ended, which the loop still answers. */
    std::size_t orphaned_exchanges {};

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
            for (descriptor_t waiting : {order.parked, order.queued})
                if (waiting >= 0) engine.close_socket(waiting);
        for (auto& connection : connections)
            if (connection && connection->transport.descriptor >= 0)
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
                if (acceptor.stage == interface_acceptor_t::stage_t::unimported_k)
                    socket_close(acceptor.request.descriptor);
                else engine.close_socket(acceptor.request.descriptor);
            }
            if (acceptor.stage == interface_acceptor_t::stage_t::shedding_refusal_k)
                engine.close_socket(acceptor.shed_request.descriptor);
            if (acceptor.reserve_descriptor >= 0) socket_close(acceptor.reserve_descriptor);
            std::destroy_at(&acceptor);
        }
        if (!interface_acceptors.empty())
            rebound_allocator<interface_acceptor_t> {allocator}.deallocate(interface_acceptors.data(),
                                                                           interface_acceptors.size());
    }
};

} // namespace unum::ucall::network
