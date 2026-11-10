/**
 *  @file include/ucall/io/windows_rio_engine.hpp
 *  @author Ash Vardanian
 *  @date November 9, 2026
 *  @brief Registered I/O sockets beside overlapped accepts, connects and files on one port.
 */
#pragma once

#include <smashtable/basic_vector.hpp> // `vector`
#include <smashtable/row_search.hpp>   // `serial_row_kit_t`

#include "ucall/io/types.hpp"               // `registered_socket_t`, `io_request_t`, `memory_registration_t`
#include "ucall/io/windows_iocp_engine.hpp" // `windows_overlapped`, `windows_extensions_t`, `windows_scatter_pages`
#include "ucall/utilities/sockets.hpp"      // `nonblocking`, `socket_option`, `socket_reset_on_close`
#include "ucall/utilities/types.hpp"        // `byte_t`, `descriptor_t`, `span`

#if UCALL_OS_WINDOWS_

namespace unum::ucall::io {

using utilities::nonblocking;
using utilities::socket_option;

/*  The Registered I/O declarations of the Windows SDK's `mswsock.h`, which MinGW-w64 lacks, under
 *  names of their own so they never meet the SDK's. */
#pragma region Registered IO

/** @c RIO_BUFFERID, a registered range. */
enum class windows_rio_buffer_t : std::uintptr_t {};

/** @c RIO_CQ, a completion queue. */
enum class windows_rio_completion_queue_t : std::uintptr_t {};

/** @c RIO_RQ, a socket's request queue. */
enum class windows_rio_request_queue_t : std::uintptr_t {};

inline constexpr windows_rio_buffer_t windows_rio_invalid_buffer_k {0xFFFFFFFF};
inline constexpr windows_rio_completion_queue_t windows_rio_invalid_completion_queue_k {};
inline constexpr windows_rio_request_queue_t windows_rio_invalid_request_queue_k {};

/** What @c RIODequeueCompletion answers for a queue the kernel found corrupt. */
inline constexpr ULONG windows_rio_corrupt_queue_k = 0xFFFFFFFF;

/** @c RIO_IOCP_COMPLETION, notifying through a completion port. */
inline constexpr int windows_rio_port_notification_k = 2;

/** @c SIO_GET_MULTIPLE_EXTENSION_FUNCTION_POINTER and @c WSAID_MULTIPLE_RIO. */
inline constexpr DWORD windows_rio_extensions_ioctl_k = 0xC8000024;
inline constexpr GUID windows_rio_extensions_id_k {
    0x8509e081, 0x96dd, 0x4005, {0xb1, 0x65, 0x9e, 0x2e, 0xe8, 0xc7, 0x9e, 0x3f}};

/** @c RIO_BUF, a span of a registered range. */
struct windows_rio_span_t {
    windows_rio_buffer_t buffer {};
    ULONG offset {}, length {};
};
static_assert(sizeof(windows_rio_span_t) == sizeof(void*) + 8);

/** @c RIORESULT. */
struct windows_rio_result_t {
    LONG status {};
    ULONG bytes {};
    ULONGLONG socket_context {}, request_context {};
};
static_assert(sizeof(windows_rio_result_t) == 24);

/** @c RIO_NOTIFICATION_COMPLETION, in its port form. */
struct windows_rio_notification_t {
    int type {};
    HANDLE port {};
    void* key {};
    void* overlapped {};
};
static_assert(sizeof(windows_rio_notification_t) == 4 * sizeof(void*));

/** @c RIO_EXTENSION_FUNCTION_TABLE, in its order; the extended and resizing calls go unused. */
struct windows_rio_functions_t {
    DWORD size {};
    BOOL(WINAPI* receive)(windows_rio_request_queue_t, windows_rio_span_t*, ULONG, DWORD, void*) {};
    void* receive_extended {};
    BOOL(WINAPI* send)(windows_rio_request_queue_t, windows_rio_span_t*, ULONG, DWORD, void*) {};
    void* send_extended {};
    void(WINAPI* close_completion_queue)(windows_rio_completion_queue_t) {};
    windows_rio_completion_queue_t(WINAPI* create_completion_queue)(DWORD, windows_rio_notification_t*) {};
    windows_rio_request_queue_t(WINAPI* create_request_queue)(SOCKET, ULONG, ULONG, ULONG, ULONG,
                                                              windows_rio_completion_queue_t,
                                                              windows_rio_completion_queue_t, void*) {};
    ULONG(WINAPI* dequeue_completion)(windows_rio_completion_queue_t, windows_rio_result_t*, ULONG) {};
    void(WINAPI* deregister_buffer)(windows_rio_buffer_t) {};
    int(WINAPI* notify)(windows_rio_completion_queue_t) {};
    windows_rio_buffer_t(WINAPI* register_buffer)(char*, DWORD) {};
    void* resize_completion_queue {};
    void* resize_request_queue {};
};
static_assert(sizeof(windows_rio_functions_t) == 14 * sizeof(void*));

#pragma endregion Registered IO

/** The completion key a Registered I/O queue's notification reaches the port with. */
inline constexpr ULONG_PTR windows_rio_notification_key_k = 1;

/** Marks an @c operation_index as a Registered I/O direction, two per socket, apart from the
 *  overlapped records. */
inline constexpr std::uint32_t windows_rio_operation_tag_k = std::uint32_t {1} << 31;

/** Pages of one slice, and slices registered together as one range. */
inline constexpr std::size_t windows_rio_slice_pages_k = 16, windows_rio_range_slices_k = 16;

/** Where a socket of the engine is: free, open, closed by a cancel or a timeout while the network
 *  still holds it, or let go by the network with Registered I/O results still due, so its index
 *  waits for them before any reuse. */
enum class windows_rio_socket_stage_t : std::uint8_t { vacant_k, open_k, aborted_k, draining_k };

/** One direction of a socket in Registered I/O: its request, its place on the timed list, and
 *  whether it was cancelled or timed out. */
struct windows_rio_operation_t {
    io_request_t* request {};
    unsigned timed {operation_list_t::absent_k};
    windows_operation_stage_t stage {windows_operation_stage_t::pending_k};
};

/** A stream socket the engine opened or accepted: its request queue where Registered I/O took
 *  it, its receive and send there, the slice each direction holds, and the results still due. */
struct windows_rio_socket_t {
    SOCKET socket {INVALID_SOCKET};
    windows_rio_request_queue_t request_queue {};
    windows_rio_operation_t directions[2] {};
    unsigned slices[2] {operation_list_t::absent_k, operation_list_t::absent_k};
    unsigned next {operation_list_t::absent_k};
    std::uint8_t outstanding {};
    windows_rio_socket_stage_t stage {windows_rio_socket_stage_t::vacant_k};
};
static_assert(sizeof(windows_rio_socket_t) == 64);

/** A range @c register_memory registered, which sends find their offsets in. */
struct windows_rio_range_t {
    windows_rio_buffer_t buffer {};
    byte_t* base {};
    std::size_t size {};
};

/** The registered slices receives land in and unregistered sends leave from, each of
 *  @c windows_rio_slice_pages_k pages, grown a range of @c windows_rio_range_slices_k at a time up
 *  to what @c open sized, and lent until @c release. */
template <typename allocator_type_>
struct windows_rio_slices {
    struct alignas(4096) page_t {
        byte_t bytes[4096];
    };
    static constexpr std::size_t slice_bytes_k = windows_rio_slice_pages_k * sizeof(page_t);
    static constexpr unsigned absent_k = operation_list_t::absent_k;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_type_>::template rebind_alloc<value_type_>;

    explicit windows_rio_slices(allocator_type_ const& owner) noexcept
        : ranges(rebound_allocator<page_t*> {owner}), buffers(rebound_allocator<windows_rio_buffer_t> {owner}),
          free_slices(rebound_allocator<unsigned> {owner}), allocator(owner) {}
    windows_rio_slices(windows_rio_slices const&) = delete;
    windows_rio_slices& operator=(windows_rio_slices const&) = delete;
    windows_rio_slices(windows_rio_slices&&) = delete;
    windows_rio_slices& operator=(windows_rio_slices&&) = delete;

    st::vector<page_t*, rebound_allocator<page_t*>> ranges {};
    st::vector<windows_rio_buffer_t, rebound_allocator<windows_rio_buffer_t>> buffers {};
    st::vector<unsigned, rebound_allocator<unsigned>> free_slices {};
    allocator_type_ allocator;

    /** Reserves the bookkeeping for @p slices lent at once, so growing allocates only ranges. */
    ucall_status_t open(std::size_t slices) noexcept {
        if (st::failed(ranges.reserve((slices + windows_rio_range_slices_k - 1) / windows_rio_range_slices_k)) ||
            st::failed(buffers.reserve(ranges.capacity())) ||
            st::failed(free_slices.reserve(ranges.capacity() * windows_rio_range_slices_k)))
            return ucall_status_out_of_memory_k;
        return ucall_status_success_k;
    }

    /** A free slice, registering a further range when none is, or @c absent_k. */
    unsigned acquire(windows_rio_functions_t const& rio) noexcept {
        if (free_slices.empty() && grow(rio) != ucall_status_success_k) return absent_k;
        unsigned const slice = free_slices.back();
        free_slices.pop_back();
        return slice;
    }
    void release(unsigned slice) noexcept {
        [[maybe_unused]] st::status_t const freed = free_slices.push_back(st::assume_reserved, unsigned {slice});
    }
    byte_t* data(unsigned slice) const noexcept {
        return reinterpret_cast<byte_t*>(ranges[slice / windows_rio_range_slices_k]) +
               slice % windows_rio_range_slices_k * slice_bytes_k;
    }
    windows_rio_span_t span_of(unsigned slice) const noexcept {
        return {buffers[slice / windows_rio_range_slices_k],
                static_cast<ULONG>(slice % windows_rio_range_slices_k * slice_bytes_k),
                static_cast<ULONG>(slice_bytes_k)};
    }

    /** Allocates and registers one more range of slices, all free, while @c open left room. */
    ucall_status_t grow(windows_rio_functions_t const& rio) noexcept {
        if (ranges.size() == ranges.capacity()) return ucall_status_out_of_memory_k;
        std::size_t const slices = (ranges.size() + 1) * windows_rio_range_slices_k;
        rebound_allocator<page_t> pages {allocator};
        std::size_t const range_pages = windows_rio_range_slices_k * windows_rio_slice_pages_k;
        page_t* const range = pages.allocate(range_pages);
        if (!range) return ucall_status_out_of_memory_k;
        windows_rio_buffer_t const buffer = rio.register_buffer(reinterpret_cast<char*>(range),
                                                                static_cast<DWORD>(range_pages * sizeof(page_t)));
        if (buffer == windows_rio_invalid_buffer_k) {
            pages.deallocate(range, range_pages);
            return ucall_status_out_of_memory_k;
        }
        [[maybe_unused]] st::status_t const kept = ranges.push_back(st::assume_reserved, static_cast<page_t*>(range));
        [[maybe_unused]] st::status_t const named = buffers.push_back(st::assume_reserved,
                                                                      windows_rio_buffer_t {buffer});
        for (std::size_t slice = slices; slice-- != slices - windows_rio_range_slices_k;)
            release(static_cast<unsigned>(slice));
        return ucall_status_success_k;
    }

    /** Deregisters and frees every range, once no operation uses any. */
    void close(windows_rio_functions_t const& rio) noexcept {
        rebound_allocator<page_t> pages {allocator};
        for (std::size_t i = 0; i != ranges.size(); ++i) {
            rio.deregister_buffer(buffers[i]);
            pages.deallocate(ranges[i], windows_rio_range_slices_k * windows_rio_slice_pages_k);
        }
        ranges.clear();
        buffers.clear();
        free_slices.clear();
    }
};

/**
 *  @brief Registered I/O for the stream sockets it opens and accepts, overlapped operations for
 *      the rest, both on one completion port.
 *
 *  Receives land in registered slices of engine memory, as io_uring's do. A send of a range
 *  registered through @c register_memory leaves with @c RIOSend and no copy, so its completion is
 *  its release; any other send copies up to a slice into one and leaves with @c RIOSend as well, as
 *  such a socket refuses every plain send and receive. A listener hands out only sockets created
 *  with its own flags, so the engine creates its listeners in Registered I/O and serves no borrowed
 *  one. Accepts, connects and files stay overlapped, as do the listener, wakeup and metrics
 *  sockets, which it imports rather than adopts. @c poll drains the completion queue without a
 *  syscall and arms its notification through the port only when it would block with nothing
 *  collected. Registered I/O cannot cancel one operation, so a cancel or a timeout closes the
 *  socket, with a reset when a send stalled, and its index is reused only once every result still
 *  due has arrived.
 */
template <typename allocator_type_ = st::default_allocator<byte_t>,
          template <typename> class atomic_ref_template_ = fu::standard_atomic_ref,
          typename row_kit_type_ = st::serial_row_kit_t>
struct windows_rio_engine {
    using allocator_t = allocator_type_;
    using operation_stage_t = windows_operation_stage_t;
    static constexpr unsigned absent_k = operation_list_t::absent_k;
    static constexpr ucall_io_backend_t backend_k = ucall_io_backend_windows_rio_k;
    static constexpr io_receive_memory_t receive_memory_k = io_receive_memory_t::engine_k;

    /** Why the engine refuses a borrowed listener, whose accepted sockets would lack its flags. */
    static constexpr char const* borrowed_listener_refusal_k =
        "Registered I/O accepts only from listeners it creates; serve a `listen_descriptor` with `windows-iocp`";
    static constexpr unsigned receive_direction_k = static_cast<unsigned>(io_direction_t::receive_k);
    static constexpr unsigned transmit_direction_k = static_cast<unsigned>(io_direction_t::transmit_k);
    template <typename other_allocator_, template <typename> class other_atomic_ref_, typename other_row_kit_>
    using rebind = windows_rio_engine<other_allocator_, other_atomic_ref_, other_row_kit_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;

    explicit windows_rio_engine(allocator_t const& allocator = {}) noexcept
        : overlapped(allocator), scatter(allocator), results(rebound_allocator<windows_rio_result_t> {allocator}),
          sockets(rebound_allocator<windows_rio_socket_t> {allocator}),
          ranges(rebound_allocator<windows_rio_range_t> {allocator}), timed(rebound_allocator<unsigned> {allocator}),
          slices(allocator) {}
    windows_rio_engine(windows_rio_engine const&) = delete;
    windows_rio_engine& operator=(windows_rio_engine const&) = delete;
    windows_rio_engine(windows_rio_engine&&) = delete;
    windows_rio_engine& operator=(windows_rio_engine&&) = delete;
    ~windows_rio_engine() noexcept {
        if (completion_queue == windows_rio_invalid_completion_queue_k) return;
        stop();
        for (windows_rio_socket_t& socket : sockets)
            if (socket.socket != INVALID_SOCKET) closesocket(socket.socket);
        rio.close_completion_queue(completion_queue);
        for (windows_rio_range_t const& range : ranges) rio.deregister_buffer(range.buffer);
        slices.close(rio);
    }

    windows_overlapped<allocator_t, atomic_ref_template_> overlapped;
    windows_extensions_t extensions {};
    windows_scatter_pages<allocator_t> scatter;
    windows_rio_functions_t rio {};
    windows_rio_completion_queue_t completion_queue {windows_rio_invalid_completion_queue_k};
    OVERLAPPED notification {};
    listing_t notifying {listing_t::unlisted_k};
    st::vector<windows_rio_result_t, rebound_allocator<windows_rio_result_t>> results;
    st::vector<windows_rio_socket_t, rebound_allocator<windows_rio_socket_t>> sockets;
    operation_list_t free_sockets;
    st::vector<windows_rio_range_t, rebound_allocator<windows_rio_range_t>> ranges;

    /** Socket directions with a deadline, each as its socket's index twice plus its direction. */
    st::vector<unsigned, rebound_allocator<unsigned>> timed;
    windows_rio_slices<allocator_t> slices;
    io_statistics_t statistics {};

    /** Why the engine was refused, naming what to change, or null. */
    char const* refusal {};

    /** Registered I/O operations whose results are still due. */
    std::size_t active {};

    /** Loads Registered I/O through a probe socket, answering @c unsupported_k where the host
     *  refuses it, so an automatic open falls to the plain port. */
    ucall_status_t open(std::size_t, std::size_t capacity,
                        io_issuer_scope_t = io_issuer_scope_t::one_thread_k) noexcept {
        if (ucall_status_t const opened = overlapped.open(capacity); opened != ucall_status_success_k) return opened;
        if (ucall_status_t const loaded = extensions.load(); loaded != ucall_status_success_k) return loaded;
        if (ucall_status_t const sized = scatter.open(capacity); sized != ucall_status_success_k) return sized;
        SOCKET const probe = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                                        WSA_FLAG_OVERLAPPED | WSA_FLAG_REGISTERED_IO);
        if (probe == INVALID_SOCKET) return ucall_status_unsupported_k;
        GUID identifier = windows_rio_extensions_id_k;
        DWORD bytes {};
        rio.size = sizeof(rio);
        int const loaded = WSAIoctl(probe, windows_rio_extensions_ioctl_k, &identifier, sizeof(identifier), &rio,
                                    sizeof(rio), &bytes, nullptr, nullptr);
        closesocket(probe);
        if (loaded != 0) return ucall_status_unsupported_k;
        // Each socket keeps at most one receive and one send in flight, each holding a slice.
        if (capacity > static_cast<std::size_t>(registered_socket_t::tag_k) ||
            st::failed(results.resize(2 * capacity)) || st::failed(sockets.resize(capacity)) ||
            st::failed(timed.reserve(2 * capacity)) || slices.open(2 * capacity) != ucall_status_success_k)
            return ucall_status_out_of_memory_k;
        for (unsigned i = 0; i != sockets.size(); ++i) free_sockets.push(sockets, i);
        windows_rio_notification_t through_port {windows_rio_port_notification_k, overlapped.port,
                                                 reinterpret_cast<void*>(windows_rio_notification_key_k),
                                                 &notification};
        completion_queue = rio.create_completion_queue(static_cast<DWORD>(2 * capacity), &through_port);
        if (completion_queue == windows_rio_invalid_completion_queue_k) return ucall_status_io_k;
        overlapped.accept_flags |= WSA_FLAG_REGISTERED_IO;
        return ucall_status_success_k;
    }

    /** A stream socket of @p family, in Registered I/O where the family has it, for a listener
     *  to bind before the loop imports it. */
    descriptor_t open_listener(int family) noexcept {
        bool const internet = family == AF_INET || family == AF_INET6;
        SOCKET const socket = WSASocketW(family, SOCK_STREAM, internet ? IPPROTO_TCP : 0, nullptr, 0,
                                         internet ? overlapped.accept_flags : WSA_FLAG_OVERLAPPED);
        if (socket == INVALID_SOCKET) return -1;
        descriptor_t const descriptor = static_cast<descriptor_t>(socket);
        int enabled = 1;
        // Fragmented RPC writes must not wait for delayed ACKs before releasing TX credits.
        if (nonblocking(descriptor) == ucall_status_success_k &&
            (!internet || socket_option(descriptor, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) == 0))
            return descriptor;
        closesocket(socket);
        return -1;
    }

    /** A stream socket of @p family made as a listener's is, on the port and adopted. */
    descriptor_t open_socket(int family) noexcept {
        descriptor_t const descriptor = open_listener(family);
        if (descriptor < 0) return descriptor;
        SOCKET const socket = static_cast<SOCKET>(descriptor);
        if (overlapped.associate(reinterpret_cast<HANDLE>(socket)) != ucall_status_success_k) {
            closesocket(socket);
            return -1;
        }
        return adopt_socket(socket);
    }
    descriptor_t import_socket(descriptor_t descriptor) noexcept {
        if (overlapped.associate(reinterpret_cast<HANDLE>(descriptor)) == ucall_status_success_k) return descriptor;
        socket_close(descriptor);
        return -1;
    }
    int close_socket(descriptor_t descriptor) noexcept {
        if (!registered_socket_t::contains(descriptor)) return socket_close(descriptor);
        let_go(registered_socket_t::index_of(descriptor));
        return 0;
    }
    [[nodiscard]] ucall_status_t reset_on_close(descriptor_t descriptor) noexcept {
        SOCKET const socket = socket_of(descriptor);
        return socket == INVALID_SOCKET ? ucall_status_success_k
                                        : socket_reset_on_close(static_cast<descriptor_t>(socket));
    }

    /** Registers @p memory for sends without a copy; a refusal by the working-set quota leaves
     *  it unpinned, and any other fails it. */
    memory_registration_t register_memory(span<byte_t> memory) noexcept {
        if (memory.size() > (std::numeric_limits<DWORD>::max)() ||
            ranges.size() >= static_cast<std::size_t>(io_unregistered_k))
            return {};
        windows_rio_buffer_t const buffer = rio.register_buffer(reinterpret_cast<char*>(memory.data()),
                                                                static_cast<DWORD>(memory.size()));
        if (buffer == windows_rio_invalid_buffer_k)
            return {io_unregistered_k, range_pinning_t::unpinned_k,
                    WSAGetLastError() == WSAENOBUFS ? ucall_status_success_k : ucall_status_io_k};
        if (st::failed(ranges.push_back({buffer, memory.data(), memory.size()}))) {
            rio.deregister_buffer(buffer);
            return {};
        }
        return {static_cast<registered_memory_t>(ranges.size() - 1), range_pinning_t::pinned_k};
    }

    /** Takes back the receive slice a completion lent. */
    void release(io_completion_t const& completion) noexcept {
        if (completion.lease) slices.release(static_cast<unsigned>(completion.lease - 1));
    }

    ucall_status_t submit(io_request_t& request) noexcept {
        if (!registered_socket_t::contains(request.descriptor))
            return overlapped.submit(request, static_cast<SOCKET>(request.descriptor), extensions, scatter, statistics);
        unsigned const index = registered_socket_t::index_of(request.descriptor);
        windows_rio_socket_t& socket = sockets[index];
        if (request.operation == io_operation_t::close_k) {
            let_go(index);
            return overlapped.complete(request, 0, statistics);
        }
        if (socket.stage != windows_rio_socket_stage_t::open_k)
            return overlapped.complete(request, -ECONNABORTED, statistics);
        bool const registered = socket.request_queue != windows_rio_invalid_request_queue_k;
        bool const sends = request.operation == io_operation_t::send_k ||
                           request.operation == io_operation_t::send_zero_copy_k;
        if (registered && request.operation == io_operation_t::receive_k) return receive(index, request);
        if (registered && sends) return send(index, request);
        // A registered send's completion already released its bytes.
        if (registered && request.operation == io_operation_t::zero_copy_release_k)
            return overlapped.complete(request, 0, statistics);
        // A socket outside Registered I/O receives through the port into a slice all the same.
        if (request.operation == io_operation_t::receive_k) {
            unsigned const slice = slices.acquire(rio);
            if (slice == absent_k) return overlapped.complete(request, -ENOBUFS, statistics);
            socket.slices[receive_direction_k] = slice;
            io_vectors(request).front() = {slices.data(slice), windows_rio_slices<allocator_t>::slice_bytes_k};
        }
        return overlapped.submit(request, socket.socket, extensions, scatter, statistics);
    }

    ucall_status_t cancel(io_request_t& request) noexcept {
        std::uint32_t const code = request.operation_index;
        if (code == io_unindexed_k || !(code & windows_rio_operation_tag_k))
            return overlapped.cancel(request, statistics);
        unsigned const index = (code & ~windows_rio_operation_tag_k) >> 1;
        unsigned const direction = code & 1;
        if (index >= sockets.size() || sockets[index].directions[direction].request != &request)
            return ucall_status_not_found_k;
        windows_rio_operation_t& operation = sockets[index].directions[direction];
        if (operation.stage == operation_stage_t::pending_k) {
            tally<atomic_ref_template_>(statistics.cancellations);
            operation.stage = operation_stage_t::cancelling_k;
            abort(index, direction);
        }
        return ucall_status_success_k;
    }

    int poll(span<io_completion_t> completions, io_wait_t wait_policy, std::uint64_t deadline = 0) noexcept {
        std::size_t count {};
        if (!dequeue(completions, count)) return -EIO;
        std::uint64_t const earliest = expire(monotonic_ns());
        if (earliest && (!deadline || earliest < deadline)) deadline = earliest;
        if (count == completions.size()) return static_cast<int>(count);
        io_wait_t const waiting = count ? io_wait_t::nonblocking_k : wait_policy;
        // Only a poll about to sleep asks the queue to post its next result to the port.
        if (waiting == io_wait_t::blocking_k && active && notifying == listing_t::unlisted_k &&
            rio.notify(completion_queue) == 0) {
            notifying = listing_t::listed_k;
            ++overlapped.foreign;
        }
        std::size_t notifications {};
        int const polled = overlapped.poll(completions.subspan(count), waiting, deadline, extensions, statistics,
                                           notifications);
        if (polled < 0) return polled;
        for (io_completion_t& completion : completions.subspan(count, static_cast<std::size_t>(polled)))
            adopt_completion(completion);
        count += static_cast<std::size_t>(polled);
        if (notifications) notifying = listing_t::unlisted_k;
        if (notifications && !dequeue(completions, count)) return -EIO;
        return static_cast<int>(count);
    }

    /** Closes every socket with results due, collects them all, then stops the port. */
    void stop() noexcept {
        for (unsigned index = 0; index != sockets.size(); ++index)
            if (sockets[index].outstanding) abort(index, receive_direction_k);
        io_completion_t discarded[32];
        while (active) {
            int const count = poll(discarded, io_wait_t::blocking_k);
            if (count < 0) break;
            for (int i = 0; i != count; ++i) {
                if (discarded[i].request->operation == io_operation_t::accept_k && discarded[i].result >= 0)
                    close_socket(discarded[i].result);
                release(discarded[i]);
            }
        }
        overlapped.stop(extensions, statistics);
    }

    /** The socket @p descriptor names, or @c INVALID_SOCKET once the engine closed it. */
    SOCKET socket_of(descriptor_t descriptor) const noexcept {
        return registered_socket_t::contains(descriptor) ? sockets[registered_socket_t::index_of(descriptor)].socket
                                                         : static_cast<SOCKET>(descriptor);
    }

    /** Gives @p socket, already on the port, an index and a request queue where Registered I/O
     *  takes it: its handle, or -1 with the socket closed. */
    descriptor_t adopt_socket(SOCKET socket) noexcept {
        unsigned const index = free_sockets.pop(sockets);
        if (index == absent_k) {
            closesocket(socket);
            return -1;
        }
        windows_rio_socket_t& record = sockets[index];
        record = {};
        record.socket = socket;
        record.stage = windows_rio_socket_stage_t::open_k;
        // A socket the family keeps out of Registered I/O, such as a Unix one, stays overlapped.
        record.request_queue = rio.create_request_queue(socket, 1, 1, 1, 1, completion_queue, completion_queue,
                                                        reinterpret_cast<void*>(std::uintptr_t {index}));
        return registered_socket_t {index}.handle();
    }

    /** Turns what the port completed for a socket of the engine into what the network expects: an
     *  accepted socket into a handle, a receive outside Registered I/O into a lent slice. */
    void adopt_completion(io_completion_t& completion) noexcept {
        io_request_t const& request = *completion.request;
        if (request.operation == io_operation_t::accept_k && completion.result >= 0) {
            descriptor_t const handle = adopt_socket(static_cast<SOCKET>(completion.result));
            completion.result = handle < 0 ? -ECONNABORTED : handle;
            return;
        }
        if (request.operation != io_operation_t::receive_k || !registered_socket_t::contains(request.descriptor))
            return;
        windows_rio_socket_t& socket = sockets[registered_socket_t::index_of(request.descriptor)];
        unsigned const slice = std::exchange(socket.slices[receive_direction_k], absent_k);
        // A socket the network let go of already took its slice back.
        if (slice == absent_k) return;
        if (completion.result > 0) lend(completion, slice);
        else slices.release(slice);
    }

    void lend(io_completion_t& completion, unsigned slice) noexcept {
        completion.data = slices.data(slice);
        completion.lease = std::uintptr_t {slice} + 1;
    }

    ucall_status_t receive(unsigned index, io_request_t& request) noexcept {
        windows_rio_socket_t& socket = sockets[index];
        unsigned const slice = slices.acquire(rio);
        if (slice == absent_k) return overlapped.complete(request, -ENOBUFS, statistics);
        windows_rio_span_t room = slices.span_of(slice);
        tally<atomic_ref_template_>(statistics.kernel_enters);
        if (!rio.receive(socket.request_queue, &room, 1, 0,
                         reinterpret_cast<void*>(std::uintptr_t {receive_direction_k}))) {
            slices.release(slice);
            return overlapped.complete(request, -socket_last_error(), statistics);
        }
        socket.slices[receive_direction_k] = slice;
        begin(index, receive_direction_k, request);
        return ucall_status_success_k;
    }

    /** Sends a registered range in place, or copies up to a slice of other bytes and sends that,
     *  leaving the rest to the caller as any short send does. */
    ucall_status_t send(unsigned index, io_request_t& request) noexcept {
        windows_rio_socket_t& socket = sockets[index];
        windows_rio_span_t bytes {};
        unsigned slice = absent_k;
        if (request.registered_memory != io_unregistered_k) {
            windows_rio_range_t const& range = ranges[static_cast<std::size_t>(request.registered_memory)];
            assert(request.data >= range.base && request.data + request.length <= range.base + range.size &&
                   "a registered send lies in its range");
            bytes = {range.buffer, static_cast<ULONG>(request.data - range.base),
                     static_cast<ULONG>(fu::min_of<std::size_t>(request.length, (std::numeric_limits<int>::max)()))};
        }
        else {
            slice = slices.acquire(rio);
            if (slice == absent_k) return overlapped.complete(request, -ENOBUFS, statistics);
            bytes = slices.span_of(slice);
            bytes.length = static_cast<ULONG>(fu::min_of<std::size_t>(request.length, bytes.length));
            std::memcpy(slices.data(slice), request.data, bytes.length);
        }
        tally<atomic_ref_template_>(statistics.kernel_enters);
        if (!rio.send(socket.request_queue, &bytes, 1, 0,
                      reinterpret_cast<void*>(std::uintptr_t {transmit_direction_k}))) {
            if (slice != absent_k) slices.release(slice);
            return overlapped.complete(request, -socket_last_error(), statistics);
        }
        tally<atomic_ref_template_>(slice == absent_k ? statistics.zero_copy_sends : statistics.copying_sends);
        socket.slices[transmit_direction_k] = slice;
        begin(index, transmit_direction_k, request);
        return ucall_status_success_k;
    }

    /** Records @p request as socket @p index's operation in @p direction. */
    void begin(unsigned index, unsigned direction, io_request_t& request) noexcept {
        windows_rio_socket_t& socket = sockets[index];
        windows_rio_operation_t& operation = socket.directions[direction];
        operation = {&request};
        request.operation_index = windows_rio_operation_tag_k | index << 1 | direction;
        if (request.deadline) {
            operation.timed = static_cast<unsigned>(timed.size());
            [[maybe_unused]] st::status_t const tracked = timed.push_back(st::assume_reserved, index << 1 | direction);
        }
        ++socket.outstanding;
        ++active;
        tally<atomic_ref_template_>(statistics.submissions);
    }

    void untime(unsigned index, unsigned direction) noexcept {
        windows_rio_operation_t& operation = sockets[index].directions[direction];
        unsigned const moved = timed.back();
        timed[operation.timed] = moved;
        sockets[moved >> 1].directions[moved & 1].timed = operation.timed;
        timed.pop_back();
        operation.timed = absent_k;
    }

    /** Closes socket @p index for good while the network still holds it, so every result due
     *  arrives; a stalled send resets the stream rather than leave its bytes queued. */
    void abort(unsigned index, unsigned direction) noexcept {
        windows_rio_socket_t& socket = sockets[index];
        if (socket.stage != windows_rio_socket_stage_t::open_k) return;
        if (direction == transmit_direction_k) {
            [[maybe_unused]] ucall_status_t const reset = socket_reset_on_close(
                static_cast<descriptor_t>(socket.socket));
        }
        closesocket(std::exchange(socket.socket, INVALID_SOCKET));
        socket.stage = windows_rio_socket_stage_t::aborted_k;
    }

    /** The network lets socket @p index go: closed, and free once no result is due. */
    void let_go(unsigned index) noexcept {
        windows_rio_socket_t& socket = sockets[index];
        if (socket.socket != INVALID_SOCKET) closesocket(std::exchange(socket.socket, INVALID_SOCKET));
        socket.stage = windows_rio_socket_stage_t::draining_k;
        if (!socket.outstanding) vacate(index);
    }

    void vacate(unsigned index) noexcept {
        windows_rio_socket_t& socket = sockets[index];
        for (unsigned& slice : socket.slices)
            if (slice != absent_k) slices.release(std::exchange(slice, absent_k));
        socket.stage = windows_rio_socket_stage_t::vacant_k;
        free_sockets.push(sockets, index);
    }

    /** Times out each direction past its deadline by closing its socket, answering the earliest
     *  deadline still ahead, or zero. */
    std::uint64_t expire(std::uint64_t now) noexcept {
        std::uint64_t earliest = 0;
        for (std::size_t i = 0; i != timed.size();) {
            unsigned const index = timed[i] >> 1, direction = timed[i] & 1;
            windows_rio_operation_t& operation = sockets[index].directions[direction];
            std::uint64_t const expiry = operation.request->deadline;
            if (expiry > now) {
                if (!earliest || expiry < earliest) earliest = expiry;
                ++i;
                continue;
            }
            if (operation.stage == operation_stage_t::pending_k) operation.stage = operation_stage_t::timing_out_k;
            untime(index, direction);
            abort(index, direction);
        }
        return earliest;
    }

    /** Answers the results the completion queue holds into @p completions from @p count on, false
     *  once the kernel found the queue corrupt. */
    bool dequeue(span<io_completion_t> completions, std::size_t& count) noexcept {
        if (!active || count == completions.size()) return true;
        ULONG const limit = static_cast<ULONG>(fu::min_of(completions.size() - count, results.size()));
        ULONG const dequeued = rio.dequeue_completion(completion_queue, results.data(), limit);
        if (dequeued == windows_rio_corrupt_queue_k) return false;
        for (ULONG i = 0; i != dequeued; ++i) {
            windows_rio_result_t const& result = results[i];
            unsigned const index = static_cast<unsigned>(result.socket_context);
            unsigned const direction = static_cast<unsigned>(result.request_context);
            windows_rio_socket_t& socket = sockets[index];
            windows_rio_operation_t& operation = socket.directions[direction];
            io_request_t& request = *operation.request;
            descriptor_t answer = result.status ? -socket_error(static_cast<int>(result.status))
                                                : static_cast<descriptor_t>(result.bytes);
            if (answer < 0 && operation.stage == operation_stage_t::timing_out_k) answer = -ETIMEDOUT;
            else if (answer < 0 && operation.stage == operation_stage_t::cancelling_k) answer = -ECANCELED;
            io_completion_t completion {&request, answer};
            unsigned const slice = std::exchange(socket.slices[direction], absent_k);
            if (direction == receive_direction_k && answer > 0) lend(completion, slice);
            else if (slice != absent_k) slices.release(slice);
            if (operation.timed != absent_k) untime(index, direction);
            operation = {};
            request.operation_index = io_unindexed_k;
            --active;
            if (!--socket.outstanding && socket.stage == windows_rio_socket_stage_t::draining_k) vacate(index);
            tally<atomic_ref_template_>(statistics.completions);
            completions[count++] = completion;
        }
        return true;
    }
};
using windows_rio_engine_t = windows_rio_engine<>;

} // namespace unum::ucall::io

#endif // UCALL_OS_WINDOWS_
