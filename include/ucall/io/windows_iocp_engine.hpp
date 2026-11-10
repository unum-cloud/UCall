/**
 *  @file include/ucall/io/windows_iocp_engine.hpp
 *  @author Ash Vardanian
 *  @date January 13, 2025
 *  @brief Overlapped sockets and files completing through an I/O completion port.
 */
#pragma once

#include <bit> // `std::bit_cast`

#include <smashtable/basic_vector.hpp> // `vector`
#include <smashtable/row_search.hpp>   // `serial_row_kit_t`

#include "ucall/io/types.hpp"          // `operation_list_t`, `io_request_t`, `io_statistics_t`, `memory_registration_t`
#include "ucall/utilities/sockets.hpp" // `socket_open`, `socket_close`, `open_native_file_beneath`, `sockets_start`
#include "ucall/utilities/types.hpp"   // `byte_t`, `descriptor_t`, `span`

#if UCALL_OS_WINDOWS_

#include <mswsock.h>

namespace unum::ucall::io {

using utilities::accepted_socket;
using utilities::byte_t;
using utilities::descriptor_t;
using utilities::io_vector_t;
using utilities::monotonic_ns;
using utilities::open_native_file_beneath;
using utilities::page_size;
using utilities::socket_close;
using utilities::socket_error;
using utilities::socket_last_error;
using utilities::socket_open;
using utilities::socket_reset_on_close;
using utilities::sockets_start;
using utilities::span;

/** Where an overlapped operation is: in the kernel, finished at submission and queued for the next
 *  poll, being cancelled or timed out, or an accept's first record whose own accept finished while
 *  others of its request still wait, kept for their count. */
enum class windows_operation_stage_t : std::uint8_t { pending_k, immediate_k, cancelling_k, timing_out_k, parked_k };

/** Bytes @c AcceptEx writes per address, which it asks to exceed the largest by 16. */
inline constexpr DWORD windows_accept_address_bytes_k = sizeof(sockaddr_storage) + 16;

/** The completion key every handle an engine binds to its port carries; anything else posted there
 *  is a notification another component of the engine armed. */
inline constexpr ULONG_PTR windows_overlapped_key_k = 0;

/** The Winsock extensions accepts and connects go through, loaded once per engine. */
struct windows_extensions_t {
    LPFN_ACCEPTEX accept {};
    LPFN_CONNECTEX connect {};
    LPFN_GETACCEPTEXSOCKADDRS addresses {};

    /** Loads every extension through one probe socket of the TCP provider, which serves both
     *  families. */
    [[nodiscard]] ucall_status_t load() noexcept {
        SOCKET const probe = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
        if (probe == INVALID_SOCKET) return ucall_status_io_k;
        bool const loaded = load_one(probe, WSAID_ACCEPTEX, accept) && load_one(probe, WSAID_CONNECTEX, connect) &&
                            load_one(probe, WSAID_GETACCEPTEXSOCKADDRS, addresses);
        closesocket(probe);
        return loaded ? ucall_status_success_k : ucall_status_io_k;
    }

    template <typename function_type_>
    static bool load_one(SOCKET probe, GUID id, function_type_& function) noexcept {
        DWORD bytes {};
        return WSAIoctl(probe, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id), &function, sizeof(function), &bytes,
                        nullptr, nullptr) == 0;
    }
};

/** Page elements one @c ReadFileScatter takes: the 64 pages of the largest vectored read a file
 *  window issues, 256 KiB, and the terminating element. */
inline constexpr std::size_t windows_scatter_pages_k = 65;

/** The page lists vectored file reads scatter through, @c windows_scatter_pages_k elements per
 *  operation record, sized at @c open so no read allocates. */
template <typename allocator_type_>
struct windows_scatter_pages {
    using elements_allocator_t =
        typename std::allocator_traits<allocator_type_>::template rebind_alloc<FILE_SEGMENT_ELEMENT>;

    explicit windows_scatter_pages(allocator_type_ const& allocator) noexcept
        : elements(elements_allocator_t {allocator}) {}
    windows_scatter_pages(windows_scatter_pages const&) = delete;
    windows_scatter_pages& operator=(windows_scatter_pages const&) = delete;
    windows_scatter_pages(windows_scatter_pages&&) = delete;
    windows_scatter_pages& operator=(windows_scatter_pages&&) = delete;

    st::vector<FILE_SEGMENT_ELEMENT, elements_allocator_t> elements {};
    std::size_t page_bytes {};

    [[nodiscard]] ucall_status_t open(std::size_t capacity) noexcept {
        page_bytes = page_size();
        return st::failed(elements.resize(capacity * windows_scatter_pages_k)) ? ucall_status_out_of_memory_k
                                                                               : ucall_status_success_k;
    }

    /** Lists the pages of @p vectors for the read of operation @p index, then the terminator: the
     *  elements, or none when a vector spans no whole pages or they outnumber the list. */
    span<FILE_SEGMENT_ELEMENT> list(unsigned index, span<io_vector_t const> vectors) noexcept {
        FILE_SEGMENT_ELEMENT* const first = elements.data() + std::size_t {index} * windows_scatter_pages_k;
        std::size_t count = 0;
        for (io_vector_t const& vector : vectors) {
            std::uintptr_t const address = reinterpret_cast<std::uintptr_t>(vector.iov_base);
            if (address % page_bytes || vector.iov_len % page_bytes) return {};
            for (std::size_t offset = 0; offset != vector.iov_len; offset += page_bytes) {
                if (count + 1 == windows_scatter_pages_k) return {};
                first[count++].Alignment = address + offset;
            }
        }
        first[count].Alignment = 0;
        return {first, count + 1};
    }
};

/** One overlapped operation: the request it carries, the socket or file it was issued on, and an
 *  accept's socket and the addresses @c AcceptEx writes. */
struct windows_operation_t {
    OVERLAPPED overlapped {};
    io_request_t* request {};
    HANDLE handle {};
    SOCKET accepted {INVALID_SOCKET};
    descriptor_t immediate {};
    windows_operation_stage_t stage {windows_operation_stage_t::pending_k};
    unsigned next {operation_list_t::absent_k}, timed {operation_list_t::absent_k};

    /** On an accept's first record, its request's records still owed, its own until it parks. */
    unsigned accepting {};
    byte_t addresses[2 * windows_accept_address_bytes_k] {};
};

/**
 *  @brief Overlapped operations over one completion port: the records, the timed and immediate
 *      lists, and submit, settle, expire, wait and stop.
 *
 *  Every handle is bound to the port once, when it is opened, imported or accepted, and skips the
 *  port on synchronous success, so such a result rides the immediate list instead. A receive waits
 *  with a zero-byte @c WSARecv, pinning nothing, then reads its vector with @c recv, so the vector
 *  may move while it waits. An accept arms up to @c length sockets, each completing one connection
 *  that takes one from @c length; the one that would spend its last cancels the rest, and the last
 *  record to complete ends the request with @c length zero. Packets under another completion key
 *  count as notifications of the component that armed them.
 */
template <typename allocator_type_, template <typename> class atomic_ref_template_>
struct windows_overlapped {
    using allocator_t = allocator_type_;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    using operation_t = windows_operation_t;
    using operation_stage_t = windows_operation_stage_t;
    static constexpr unsigned absent_k = operation_list_t::absent_k;

    explicit windows_overlapped(allocator_t const& allocator = {}) noexcept
        : operations(rebound_allocator<operation_t> {allocator}), timed(rebound_allocator<unsigned> {allocator}),
          entries(rebound_allocator<OVERLAPPED_ENTRY> {allocator}) {}
    windows_overlapped(windows_overlapped const&) = delete;
    windows_overlapped& operator=(windows_overlapped const&) = delete;
    windows_overlapped(windows_overlapped&&) = delete;
    windows_overlapped& operator=(windows_overlapped&&) = delete;
    ~windows_overlapped() noexcept {
        if (port) CloseHandle(port);
    }

    HANDLE port {};
    st::vector<operation_t, rebound_allocator<operation_t>> operations {};
    st::vector<unsigned, rebound_allocator<unsigned>> timed {};
    st::vector<OVERLAPPED_ENTRY, rebound_allocator<OVERLAPPED_ENTRY>> entries {};
    operation_list_t free_operations, immediate_operations;

    /** Records the kernel or the immediate list still owes a completion. */
    std::size_t active {};

    /** Packets other components armed on the port and have not yet received. */
    std::size_t foreign {};

    /** The flags an accept creates an IPv4 or IPv6 socket with, which Registered I/O extends. */
    DWORD accept_flags {WSA_FLAG_OVERLAPPED};

    [[nodiscard]] ucall_status_t open(std::size_t capacity) noexcept {
        if (ucall_status_t const started = sockets_start(); started != ucall_status_success_k) return started;
        if (st::failed(operations.resize(capacity)) || st::failed(timed.reserve(capacity)) ||
            st::failed(entries.resize(capacity)))
            return ucall_status_out_of_memory_k;
        for (unsigned i = 0; i != operations.size(); ++i) free_operations.push(operations, i);
        port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
        return port ? ucall_status_success_k : ucall_status_io_k;
    }

    /** Binds @p handle to the port for good, so its completions arrive there, except those that
     *  succeed at once, and its own event is never signalled. */
    [[nodiscard]] ucall_status_t associate(HANDLE handle) noexcept {
        return CreateIoCompletionPort(handle, port, windows_overlapped_key_k, 0) &&
                       SetFileCompletionNotificationModes(
                           handle, FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE)
                   ? ucall_status_success_k
                   : ucall_status_io_k;
    }

    /** Completes @p request with @p result at the next poll, as if it finished on submission. */
    ucall_status_t complete(io_request_t& request, descriptor_t result, io_statistics_t& statistics) noexcept {
        unsigned const index = take(request, INVALID_SOCKET, statistics);
        if (index == absent_k) return ucall_status_contended_k;
        return settle_now(index, result);
    }

    /** Starts @p request on the @p socket it names, or on its file. */
    ucall_status_t submit(io_request_t& request, SOCKET socket, windows_extensions_t const& extensions,
                          windows_scatter_pages<allocator_t>& scatter, io_statistics_t& statistics) noexcept {
        unsigned const index = take(request, socket, statistics);
        if (index == absent_k) return ucall_status_contended_k;
        operation_t& operation = operations[index];
        if (request.deadline) {
            operation.timed = static_cast<unsigned>(timed.size());
            [[maybe_unused]] st::status_t const tracked = timed.push_back(st::assume_reserved, unsigned {index});
        }
        DWORD bytes {}, flags {};
        switch (request.operation) {
        case io_operation_t::close_k:
            return settle_now(index, socket_close(static_cast<descriptor_t>(socket)) == 0 ? 0 : -socket_last_error());
        case io_operation_t::shutdown_k:
            return settle_now(index, ::shutdown(socket, SD_SEND) == 0 ? 0 : -socket_last_error());
        case io_operation_t::zero_copy_release_k: return settle_now(index, 1);
        case io_operation_t::file_open_k: return settle_now(index, open_file(request));
        case io_operation_t::file_read_k:
        case io_operation_t::file_read_vectors_k:
            tally<atomic_ref_template_>(statistics.file_reads_asynchronous);
            return issued(index, read_file(index, scatter), statistics);
        case io_operation_t::accept_k: return arm_accepts(index, extensions, statistics);
        case io_operation_t::connect_k: {
            sockaddr* const remote = reinterpret_cast<sockaddr*>(request.data);
            sockaddr_storage local {};
            local.ss_family = remote->sa_family;
            int const length = local.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
            if (bind(socket, reinterpret_cast<sockaddr*>(&local), length) != 0)
                return settle_now(index, -socket_last_error());
            bool const connected = extensions.connect(socket, remote, static_cast<int>(request.length), nullptr, 0,
                                                      &bytes, &operation.overlapped);
            return issued(index, connected ? 0 : WSAGetLastError(), statistics);
        }
        case io_operation_t::receive_k: return issued(index, wait_readable(operation), statistics);
        case io_operation_t::read_k: {
            WSABUF buffer {static_cast<ULONG>(std::min<std::size_t>(request.length, std::numeric_limits<int>::max())),
                           reinterpret_cast<char*>(request.data)};
            bool const read = WSARecv(socket, &buffer, 1, &bytes, &flags, &operation.overlapped, nullptr) == 0;
            return issued(index, read ? 0 : WSAGetLastError(), statistics);
        }
        case io_operation_t::send_k:
        case io_operation_t::send_zero_copy_k: {
            WSABUF buffer {static_cast<ULONG>(std::min<std::size_t>(request.length, std::numeric_limits<int>::max())),
                           reinterpret_cast<char*>(request.data)};
            bool const sent = WSASend(socket, &buffer, 1, &bytes, 0, &operation.overlapped, nullptr) == 0;
            return issued(index, sent ? 0 : WSAGetLastError(), statistics);
        }
        }
        return settle_now(index, -EINVAL);
    }

    /** Cancels @p request; an accept's records all wait on its listener, as nothing else does. */
    ucall_status_t cancel(io_request_t& request, io_statistics_t& statistics) noexcept {
        unsigned const index = request.operation_index;
        if (index >= operations.size() || operations[index].request != &request) return ucall_status_not_found_k;
        operation_t& operation = operations[index];
        bool const accepting = request.operation == io_operation_t::accept_k;
        // An accept's first record may have finished or parked while others of its request wait.
        if (operation.stage == operation_stage_t::pending_k ||
            (accepting && operation.stage != operation_stage_t::cancelling_k)) {
            tally<atomic_ref_template_>(statistics.cancellations);
            operation.stage = operation_stage_t::cancelling_k;
            CancelIoEx(operation.handle, accepting ? nullptr : &operation.overlapped);
        }
        return ucall_status_success_k;
    }

    /** Answers settled operations into @p completions, waiting once when blocking finds none, until
     *  @p deadline or the earliest operation's; returns early once a notification arrived, counted
     *  into @p notifications. */
    int poll(span<io_completion_t> completions, io_wait_t wait_policy, std::uint64_t deadline,
             windows_extensions_t const& extensions, io_statistics_t& statistics, std::size_t& notifications) noexcept {
        std::size_t count {};
        while (count < completions.size() && (active || foreign) && !notifications) {
            std::uint64_t const now = monotonic_ns();
            DWORD wait = wait_policy == io_wait_t::blocking_k && !count ? INFINITE : DWORD {0};
            if (deadline) wait = std::min(wait, milliseconds_until(deadline, now));
            for (std::size_t i = 0; i != timed.size();) {
                operation_t& operation = operations[timed[i]];
                std::uint64_t const expiry = operation.request->deadline;
                if (expiry > now) {
                    wait = std::min(wait, milliseconds_until(expiry, now));
                    ++i;
                    continue;
                }
                if (operation.stage == operation_stage_t::pending_k) {
                    operation.stage = operation_stage_t::timing_out_k;
                    CancelIoEx(operation.handle, operation.request->operation == io_operation_t::accept_k
                                                     ? nullptr
                                                     : &operation.overlapped);
                }
                untime(operation);
            }
            if (unsigned const index = immediate_operations.pop(operations); index != absent_k) {
                count = settle(index, operations[index].immediate, completions, count, extensions, statistics);
                continue;
            }
            ULONG dequeued {};
            ULONG const limit = static_cast<ULONG>(std::min(completions.size() - count, entries.size()));
            tally<atomic_ref_template_>(statistics.kernel_enters);
            if (!GetQueuedCompletionStatusEx(port, entries.data(), limit, &dequeued, wait, FALSE)) {
                if (GetLastError() == WAIT_TIMEOUT) {
                    if (wait_policy == io_wait_t::blocking_k && !count && (!deadline || monotonic_ns() < deadline))
                        continue;
                    break;
                }
                return -EIO;
            }
            for (ULONG i = 0; i != dequeued; ++i) {
                if (entries[i].lpCompletionKey != windows_overlapped_key_k) {
                    --foreign;
                    ++notifications;
                    continue;
                }
                operation_t& operation = *reinterpret_cast<operation_t*>(entries[i].lpOverlapped);
                unsigned const index = static_cast<unsigned>(&operation - operations.data());
                count = settle(index, overlapped_result(operation), completions, count, extensions, statistics);
            }
        }
        return static_cast<int>(count);
    }

    /** Cancels every operation and waits for each, closing what accepts still took. */
    void stop(windows_extensions_t const& extensions, io_statistics_t& statistics) noexcept {
        for (operation_t& operation : operations)
            if (operation.request && operation.stage != operation_stage_t::immediate_k) {
                if (operation.stage == operation_stage_t::pending_k) operation.stage = operation_stage_t::cancelling_k;
                CancelIoEx(operation.handle, &operation.overlapped);
            }
        io_completion_t discarded[32];
        while (active) {
            std::size_t notifications {};
            int const count = poll(discarded, io_wait_t::blocking_k, 0, extensions, statistics, notifications);
            if (count < 0) break;
            for (int i = 0; i != count; ++i)
                if (discarded[i].request->operation == io_operation_t::accept_k && discarded[i].result >= 0)
                    socket_close(discarded[i].result);
        }
    }

    /** Milliseconds from @p now until @p moment, rounded up so a wait never ends early. */
    static DWORD milliseconds_until(std::uint64_t moment, std::uint64_t now) noexcept {
        std::uint64_t const duration = moment > now ? moment - now : 0;
        return static_cast<DWORD>(
            std::min<std::uint64_t>(duration / 1'000'000 + (duration % 1'000'000 != 0), INFINITE - 1));
    }

    /** A free record carrying @p request on @p socket, or @c absent_k. */
    unsigned take(io_request_t& request, SOCKET socket, io_statistics_t& statistics) noexcept {
        unsigned const index = free_operations.pop(operations);
        if (index == absent_k) return absent_k;
        operation_t& operation = operations[index];
        operation = {};
        operation.request = &request;
        operation.handle = reinterpret_cast<HANDLE>(socket);
        request.operation_index = index;
        ++active;
        tally<atomic_ref_template_>(statistics.submissions);
        return index;
    }

    ucall_status_t settle_now(unsigned index, descriptor_t result) noexcept {
        operation_t& operation = operations[index];
        operation.immediate = result;
        operation.stage = operation_stage_t::immediate_k;
        immediate_operations.push(operations, index);
        return ucall_status_success_k;
    }

    /** Follows up a call that started operation @p index and answered @p error: zero when it
     *  finished at once, @c ERROR_IO_PENDING while it runs, a failure otherwise. */
    ucall_status_t issued(unsigned index, DWORD error, io_statistics_t& statistics) noexcept {
        tally<atomic_ref_template_>(statistics.kernel_enters);
        operation_t& operation = operations[index];
        // A handle that skips the port on success posts nothing, so the record answers itself.
        if (!error) return settle_now(index, static_cast<descriptor_t>(operation.overlapped.InternalHigh));
        if (error == ERROR_IO_PENDING) return ucall_status_success_k;
        return settle_now(index, error == ERROR_HANDLE_EOF ? 0 : -socket_error(static_cast<int>(error)));
    }

    /** What a finished overlapped operation answered: a byte count or a negated errno. */
    descriptor_t overlapped_result(operation_t& operation) noexcept {
        DWORD bytes {}, flags {};
        io_operation_t const kind = operation.request->operation;
        if (kind == io_operation_t::file_read_k || kind == io_operation_t::file_read_vectors_k) {
            if (GetOverlappedResult(operation.handle, &operation.overlapped, &bytes, FALSE))
                return static_cast<descriptor_t>(bytes);
            DWORD const error = GetLastError();
            return error == ERROR_HANDLE_EOF ? 0 : -socket_error(static_cast<int>(error));
        }
        return WSAGetOverlappedResult(reinterpret_cast<SOCKET>(operation.handle), &operation.overlapped, &bytes, FALSE,
                                      &flags)
                   ? static_cast<descriptor_t>(bytes)
                   : -socket_last_error();
    }

    /** Opens the file @p request names beneath its directory, bound to the port. */
    descriptor_t open_file(io_request_t const& request) noexcept {
        descriptor_t const file = open_native_file_beneath(request.file.file,
                                                           reinterpret_cast<char const*>(request.data));
        if (file < 0 || associate(std::bit_cast<HANDLE>(file)) == ucall_status_success_k) return file;
        CloseHandle(std::bit_cast<HANDLE>(file));
        return -EIO;
    }

    /** Reads the file of operation @p index, scattering a vectored read page by page. */
    DWORD read_file(unsigned index, windows_scatter_pages<allocator_t>& scatter) noexcept {
        operation_t& operation = operations[index];
        io_request_t const& request = *operation.request;
        operation.handle = request.file.file;
        operation.overlapped.Offset = static_cast<DWORD>(request.file.offset);
        operation.overlapped.OffsetHigh = static_cast<DWORD>(request.file.offset >> 32);
        if (request.operation == io_operation_t::file_read_k) {
            DWORD const length = static_cast<DWORD>(
                std::min<std::size_t>(request.length, std::numeric_limits<DWORD>::max()));
            return ReadFile(operation.handle, request.data, length, nullptr, &operation.overlapped) ? 0
                                                                                                    : GetLastError();
        }
        span<FILE_SEGMENT_ELEMENT> const pages = scatter.list(index, io_vectors(request));
        if (pages.empty()) return ERROR_INVALID_PARAMETER;
        DWORD const length = static_cast<DWORD>((pages.size() - 1) * scatter.page_bytes);
        return ReadFileScatter(operation.handle, pages.data(), length, nullptr, &operation.overlapped) ? 0
                                                                                                       : GetLastError();
    }

    /** Posts the zero-byte receive that completes once @p operation's socket is readable. */
    DWORD wait_readable(operation_t& operation) noexcept {
        WSABUF nothing {};
        DWORD bytes {}, flags {};
        return WSARecv(reinterpret_cast<SOCKET>(operation.handle), &nothing, 1, &bytes, &flags, &operation.overlapped,
                       nullptr) == 0
                   ? 0
                   : WSAGetLastError();
    }

    /** Reads what a zero-byte receive announced into the vector its request names now. */
    descriptor_t receive_ready(operation_t const& operation, io_statistics_t& statistics) noexcept {
        tally<atomic_ref_template_>(statistics.kernel_enters);
        io_vector_t const& room = io_vectors(*operation.request).front();
        int const received = recv(
            reinterpret_cast<SOCKET>(operation.handle), static_cast<char*>(room.iov_base),
            static_cast<int>(std::min<std::size_t>(room.iov_len, std::numeric_limits<int>::max())), 0);
        return received >= 0 ? static_cast<descriptor_t>(received) : -socket_last_error();
    }

    /** Arms up to @c length accepts for the request of record @p index, each on a record and a
     *  socket of its own, stopping at the first refusal; only a refusal of the first ends the
     *  request, so exhaustion surfaces where @c WSASocketW refuses it. */
    ucall_status_t arm_accepts(unsigned index, windows_extensions_t const& extensions,
                               io_statistics_t& statistics) noexcept {
        operation_t& first = operations[index];
        io_request_t& request = *first.request;
        SOCKET const listener = reinterpret_cast<SOCKET>(first.handle);
        sockaddr_storage address {};
        int address_length = sizeof(address);
        first.accepting = 1;
        if (getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_length) != 0)
            return settle_now(index, -socket_last_error());
        first.accepting = 0;
        std::size_t const wanted = std::max<std::size_t>(request.length, 1);
        for (unsigned member = index;;) {
            DWORD const error = arm_accept(member, listener, address.ss_family, extensions);
            tally<atomic_ref_template_>(statistics.kernel_enters);
            if (error && error != ERROR_IO_PENDING) {
                if (member == index) {
                    first.accepting = 1;
                    return settle_now(index, -socket_error(static_cast<int>(error)));
                }
                release(member);
                --active;
                break;
            }
            ++first.accepting;
            if (!error) settle_now(member, 0);
            if (first.accepting == wanted) break;
            member = free_operations.pop(operations);
            if (member == absent_k) break;
            operations[member] = {};
            operations[member].request = &request;
            operations[member].handle = first.handle;
            ++active;
        }
        return ucall_status_success_k;
    }

    /** Creates the socket record @p index accepts into and posts its @c AcceptEx: zero, the
     *  pending code, or why either was refused. */
    DWORD arm_accept(unsigned index, SOCKET listener, int family, windows_extensions_t const& extensions) noexcept {
        operation_t& operation = operations[index];
        bool const internet = family == AF_INET || family == AF_INET6;
        operation.accepted = WSASocketW(family, SOCK_STREAM, internet ? IPPROTO_TCP : 0, nullptr, 0,
                                        internet ? accept_flags : WSA_FLAG_OVERLAPPED);
        if (operation.accepted == INVALID_SOCKET) return static_cast<DWORD>(WSAGetLastError());
        DWORD bytes {};
        if (extensions.accept(listener, operation.accepted, operation.addresses, 0, windows_accept_address_bytes_k,
                              windows_accept_address_bytes_k, &bytes, &operation.overlapped))
            return 0;
        DWORD const error = static_cast<DWORD>(WSAGetLastError());
        if (error != ERROR_IO_PENDING) closesocket(std::exchange(operation.accepted, INVALID_SOCKET));
        return error;
    }

    /** Readies the socket record @p index accepted for the loop, writing its peer's address where
     *  the request points: the descriptor, or a peer-level error with the socket closed. */
    descriptor_t adopt_accepted(operation_t& operation, windows_extensions_t const& extensions) noexcept {
        SOCKET const accepted = std::exchange(operation.accepted, INVALID_SOCKET);
        SOCKET const listener = reinterpret_cast<SOCKET>(operation.handle);
        if (setsockopt(accepted, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, reinterpret_cast<char const*>(&listener),
                       sizeof(listener)) != 0) {
            closesocket(accepted);
            return -ECONNABORTED;
        }
        sockaddr *local {}, *remote {};
        int local_length {}, remote_length {};
        extensions.addresses(operation.addresses, 0, windows_accept_address_bytes_k, windows_accept_address_bytes_k,
                             &local, &local_length, &remote, &remote_length);
        if (io_peer_address_t* const peer = reinterpret_cast<io_peer_address_t*>(operation.request->data)) {
            peer->length = std::min<int>(remote_length, static_cast<int>(sizeof(peer->address)));
            std::memcpy(&peer->address, remote, static_cast<std::size_t>(peer->length));
        }
        descriptor_t const descriptor = accepted_socket(static_cast<descriptor_t>(accepted), remote->sa_family);
        if (descriptor < 0 || associate(reinterpret_cast<HANDLE>(descriptor)) == ucall_status_success_k)
            return descriptor;
        socket_close(descriptor);
        return -ECONNABORTED;
    }

    /** Answers operation @p index, which finished with @p result, into @p completions from @p count
     *  on: a readable socket's bytes, an accept's connection, or nothing while either goes on. */
    std::size_t settle(unsigned index, descriptor_t result, span<io_completion_t> completions, std::size_t count,
                       windows_extensions_t const& extensions, io_statistics_t& statistics) noexcept {
        operation_t& operation = operations[index];
        io_request_t& request = *operation.request;
        while (request.operation == io_operation_t::receive_k && result >= 0) {
            result = receive_ready(operation, statistics);
            if (result != -EAGAIN) break;
            operation.overlapped = {};
            operation.stage = operation_stage_t::pending_k;
            DWORD const error = wait_readable(operation);
            if (error == ERROR_IO_PENDING) return count;
            result = error ? -socket_error(static_cast<int>(error)) : 0;
        }
        if (request.operation != io_operation_t::accept_k) {
            completions[count++] = finish(index, result, statistics);
            return count;
        }
        if (result >= 0) result = adopt_accepted(operation, extensions);
        else if (operation.accepted != INVALID_SOCKET) closesocket(std::exchange(operation.accepted, INVALID_SOCKET));
        unsigned const first = request.operation_index;
        if (--operations[first].accepting) {
            // A connection taken while others still wait is answered on its own; a refused one
            // leaves nothing to answer.
            if (result >= 0) {
                byte_t* const peer = request.data;
                if (peer) request.data = peer + sizeof(io_peer_address_t);
                // The server renews the length each round, so it may fall below the accepts armed.
                if (request.length > 1) --request.length;
                else cancel(request, statistics);
                tally<atomic_ref_template_>(statistics.completions);
                completions[count++] = {&request, result, peer};
            }
            if (index != first) release(index);
            // A cancel already asked of the request must not be asked again.
            else if (operation.stage != operation_stage_t::cancelling_k) operation.stage = operation_stage_t::parked_k;
            --active;
            return count;
        }
        if (index != first) release(first);
        completions[count++] = finish(index, result, statistics);
        return count;
    }

    void untime(operation_t& operation) noexcept {
        timed[operation.timed] = timed.back();
        operations[timed.back()].timed = operation.timed;
        timed.pop_back();
        operation.timed = absent_k;
    }

    /** Returns record @p index to the free list, owing nothing. */
    void release(unsigned index) noexcept {
        operation_t& operation = operations[index];
        if (operation.timed != absent_k) untime(operation);
        operation.request = nullptr;
        free_operations.push(operations, index);
    }

    io_completion_t finish(unsigned index, descriptor_t result, io_statistics_t& statistics) noexcept {
        operation_t& operation = operations[index];
        io_request_t& request = *operation.request;
        if (operation.stage == operation_stage_t::timing_out_k && result == -ECANCELED) result = -ETIMEDOUT;
        if (request.operation == io_operation_t::connect_k && result >= 0 &&
            setsockopt(reinterpret_cast<SOCKET>(operation.handle), SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, nullptr, 0) !=
                0)
            result = -socket_last_error();
        if (request.operation == io_operation_t::close_k && result >= 0) request.descriptor = -1;
        if (request.operation == io_operation_t::accept_k) request.length = 0;
        request.operation_index = io_unindexed_k;
        release(index);
        --active;
        tally<atomic_ref_template_>(statistics.completions);
        return {&request, result};
    }
};

/**
 *  @brief Overlapped sockets and files through one completion port.
 *
 *  A file opens overlapped and unbuffered on the port once, beneath its directory, or beneath a
 *  caller's descriptor with an empty name, and a vectored read scatters page by page. Zero-copy
 *  sends copy, so their releases complete as submitted.
 */
template <typename allocator_type_ = st::default_allocator<byte_t>,
          template <typename> class atomic_ref_template_ = fu::standard_atomic_ref,
          typename row_kit_type_ = st::serial_row_kit_t>
struct windows_iocp_engine {
    using allocator_t = allocator_type_;
    template <typename other_allocator_, template <typename> class other_atomic_ref_, typename other_row_kit_>
    using rebind = windows_iocp_engine<other_allocator_, other_atomic_ref_, other_row_kit_>;
    static constexpr ucall_io_backend_t backend_k = ucall_io_backend_windows_iocp_k;
    static constexpr io_receive_memory_t receive_memory_k = io_receive_memory_t::submitter_k;

    explicit windows_iocp_engine(allocator_t const& allocator = {}) noexcept
        : overlapped(allocator), scatter(allocator) {}
    windows_iocp_engine(windows_iocp_engine const&) = delete;
    windows_iocp_engine& operator=(windows_iocp_engine const&) = delete;
    windows_iocp_engine(windows_iocp_engine&&) = delete;
    windows_iocp_engine& operator=(windows_iocp_engine&&) = delete;
    ~windows_iocp_engine() noexcept { stop(); }

    windows_overlapped<allocator_t, atomic_ref_template_> overlapped;
    windows_extensions_t extensions {};
    windows_scatter_pages<allocator_t> scatter;
    io_statistics_t statistics {};

    ucall_status_t open(std::size_t, std::size_t capacity,
                        io_issuer_scope_t = io_issuer_scope_t::one_thread_k) noexcept {
        if (ucall_status_t const opened = overlapped.open(capacity); opened != ucall_status_success_k) return opened;
        if (ucall_status_t const loaded = extensions.load(); loaded != ucall_status_success_k) return loaded;
        return scatter.open(capacity);
    }
    descriptor_t open_socket(int family) noexcept {
        descriptor_t const descriptor = socket_open(family);
        return descriptor < 0 ? descriptor : import_socket(descriptor);
    }
    descriptor_t import_socket(descriptor_t descriptor) noexcept {
        if (overlapped.associate(reinterpret_cast<HANDLE>(descriptor)) == ucall_status_success_k) return descriptor;
        socket_close(descriptor);
        return -1;
    }
    int close_socket(descriptor_t descriptor) noexcept { return socket_close(descriptor); }
    [[nodiscard]] ucall_status_t reset_on_close(descriptor_t descriptor) noexcept {
        return socket_reset_on_close(descriptor);
    }
    memory_registration_t register_memory(span<byte_t>) noexcept { return {}; }
    void release(io_completion_t const&) noexcept {}
    ucall_status_t submit(io_request_t& request) noexcept {
        return overlapped.submit(request, static_cast<SOCKET>(request.descriptor), extensions, scatter, statistics);
    }
    ucall_status_t cancel(io_request_t& request) noexcept { return overlapped.cancel(request, statistics); }
    int poll(span<io_completion_t> completions, io_wait_t wait_policy, std::uint64_t deadline = 0) noexcept {
        std::size_t notifications {};
        return overlapped.poll(completions, wait_policy, deadline, extensions, statistics, notifications);
    }
    void stop() noexcept { overlapped.stop(extensions, statistics); }
};
using windows_iocp_engine_t = windows_iocp_engine<>;

} // namespace unum::ucall::io

#endif // UCALL_OS_WINDOWS_
