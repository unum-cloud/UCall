/**
 *  @file include/ucall/io/windows_iocp_engine.hpp
 *  @author Ash Vardanian
 *  @date January 13, 2025
 *  @brief Overlapped sockets and files completing through an I/O completion port.
 */
#pragma once

#include <smashtable/basic_vector.hpp> // `vector`
#include <smashtable/row_search.hpp>   // `serial_row_kit_t`

#include "ucall/io/types.hpp" // `operation_stage_t`, `operation_list_t`, `io_request_t`, `memory_registration_t`
#include "ucall/utilities/sockets.hpp" // `socket_open`, `socket_close`, `socket_reset_on_close`, `sockets_start`
#include "ucall/utilities/types.hpp"   // `byte_t`, `descriptor_t`, `span`

#if UCALL_OS_WINDOWS_

#include <mswsock.h>

namespace unum::ucall::io {

using utilities::byte_t;
using utilities::descriptor_t;
using utilities::file_open_beneath;
using utilities::io_vector_t;
using utilities::monotonic_ns;
using utilities::socket_close;
using utilities::socket_error;
using utilities::socket_last_error;
using utilities::socket_open;
using utilities::socket_reset_on_close;
using utilities::sockets_start;
using utilities::span;

/**
 *  @brief Overlapped socket operations retain their storage through cancellation completion.
 *
 *  A file read reopens its file unbuffered and overlapped on the port for its own lifetime; a path
 *  opens beneath its directory at once, vectored reads answer @c -ENOSYS, and zero-copy sends copy,
 *  so their releases complete as submitted. A receive waits with a zero-byte @c WSARecv, pinning
 *  nothing, then reads its vector with @c recv, so the vector may move while it waits.
 */
template <typename allocator_type_ = st::default_allocator<byte_t>,
          template <typename> class atomic_ref_template_ = fu::standard_atomic_ref,
          typename row_kit_type_ = st::serial_row_kit_t>
struct windows_iocp_engine {
    using allocator_t = allocator_type_;
    template <typename other_allocator_, template <typename> class other_atomic_ref_, typename other_row_kit_>
    using rebind = windows_iocp_engine<other_allocator_, other_atomic_ref_, other_row_kit_>;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    enum class operation_stage_t { pending_k, immediate_k, cancelling_k, timing_out_k };
    static constexpr unsigned absent_k = operation_list_t::absent_k;
    static constexpr io_receive_memory_t receive_memory_k = io_receive_memory_t::submitter_k;
    struct operation_t {
        OVERLAPPED overlapped {};
        io_request_t* request {};
        SOCKET accepted {INVALID_SOCKET};

        /** A file read's own unbuffered handle, closed as it finishes. */
        HANDLE file {};

        descriptor_t immediate {};
        operation_stage_t stage {operation_stage_t::pending_k};
        unsigned next {absent_k}, timed {absent_k};
        byte_t addresses[2 * (sizeof(sockaddr_storage) + 16)] {};
    };
    descriptor_t open_socket(int family) noexcept { return socket_open(family); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept { return descriptor; }
    int close_socket(descriptor_t descriptor) noexcept { return socket_close(descriptor); }
    [[nodiscard]] ucall_status_t reset_on_close(descriptor_t descriptor) noexcept {
        return socket_reset_on_close(descriptor);
    }
    memory_registration_t register_memory(span<byte_t>) noexcept { return {}; }
    void release(io_completion_t const&) noexcept {}
    static HANDLE handle_of(operation_t const& operation) noexcept {
        return operation.file ? operation.file : reinterpret_cast<HANDLE>(operation.request->descriptor);
    }
    ucall_status_t cancel(io_request_t& request) noexcept {
        for (auto& operation : operations)
            if (operation.request == &request) {
                if (operation.stage == operation_stage_t::pending_k) {
                    tally<atomic_ref_template_>(statistics.cancellations);
                    operation.stage = operation_stage_t::cancelling_k;
                    CancelIoEx(handle_of(operation), &operation.overlapped);
                }
                return ucall_status_success_k;
            }
        return ucall_status_not_found_k;
    }
    explicit windows_iocp_engine(allocator_t const& allocator = {}) noexcept
        : operations(rebound_allocator<operation_t> {allocator}), timed(rebound_allocator<unsigned> {allocator}),
          entries(rebound_allocator<OVERLAPPED_ENTRY> {allocator}) {}
    windows_iocp_engine(windows_iocp_engine const&) = delete;
    windows_iocp_engine& operator=(windows_iocp_engine const&) = delete;
    windows_iocp_engine(windows_iocp_engine&&) = delete;
    windows_iocp_engine& operator=(windows_iocp_engine&&) = delete;
    HANDLE port {};
    st::vector<operation_t, rebound_allocator<operation_t>> operations {};
    st::vector<unsigned, rebound_allocator<unsigned>> timed {};
    st::vector<OVERLAPPED_ENTRY, rebound_allocator<OVERLAPPED_ENTRY>> entries {};
    operation_list_t free_operations, immediate_operations;
    std::size_t active {};
    io_statistics_t statistics {};
    ucall_status_t open(std::size_t, std::size_t capacity,
                        io_issuer_scope_t = io_issuer_scope_t::one_thread_k) noexcept {
        if (ucall_status_t const started = sockets_start(); started != ucall_status_success_k) return started;
        if (st::failed(operations.resize(capacity)) || st::failed(timed.reserve(capacity)) ||
            st::failed(entries.resize(capacity)))
            return ucall_status_out_of_memory_k;
        for (unsigned i = 0; i != operations.size(); ++i) free_operations.push(operations, i);
        port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
        return port ? ucall_status_success_k : ucall_status_io_k;
    }
    void untime(operation_t& operation) noexcept {
        timed[operation.timed] = timed.back();
        operations[timed.back()].timed = operation.timed;
        timed.pop_back();
        operation.timed = absent_k;
    }
    template <typename function_type_>
    [[nodiscard]] ucall_status_t extension(SOCKET socket, GUID id, function_type_& function) noexcept {
        DWORD bytes {};
        return WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &id, sizeof(id), &function, sizeof(function),
                        &bytes, nullptr, nullptr) == 0
                   ? ucall_status_success_k
                   : ucall_status_io_k;
    }
    ucall_status_t submit(io_request_t& request) noexcept {
        auto index = free_operations.pop(operations);
        if (index == absent_k) return ucall_status_contended_k;
        auto* operation = &operations[index];
        *operation = {};
        operation->request = &request;
        tally<atomic_ref_template_>(statistics.submissions);
        auto socket = static_cast<SOCKET>(request.descriptor);
        auto complete_immediately = [&](descriptor_t result) noexcept {
            operation->immediate = result;
            operation->stage = operation_stage_t::immediate_k;
            immediate_operations.push(operations, index);
            ++active;
            return ucall_status_success_k;
        };
        if (request.operation == io_operation_t::close_k)
            return complete_immediately(socket_close(request.descriptor) == 0 ? 0 : -socket_last_error());
        if (request.operation == io_operation_t::shutdown_k)
            return complete_immediately(shutdown(socket, SD_SEND) == 0 ? 0 : -socket_last_error());
        if (request.operation == io_operation_t::zero_copy_release_k) return complete_immediately(1);
        // The open completes at once, as on POSIX; reads stay overlapped on the reopened handle.
        if (request.operation == io_operation_t::file_open_k)
            return complete_immediately(
                file_open_beneath(request.file.directory_descriptor, reinterpret_cast<char const*>(request.data)));
        if (request.operation == io_operation_t::file_read_vectors_k) return complete_immediately(-ENOSYS);
        if (request.operation == io_operation_t::file_read_k) return submit_file_read(index);
        if (!CreateIoCompletionPort(reinterpret_cast<HANDLE>(socket), port, 0, 0)) return complete_immediately(-EIO);
        DWORD bytes {}, flags {};
        int result = SOCKET_ERROR;
        switch (request.operation) {
        case io_operation_t::accept_k: {
            LPFN_ACCEPTEX accept_ex {};
            sockaddr_storage address {};
            int length = sizeof(address);
            if (extension(socket, WSAID_ACCEPTEX, accept_ex) != ucall_status_success_k ||
                getsockname(socket, reinterpret_cast<sockaddr*>(&address), &length) != 0)
                return complete_immediately(-socket_last_error());
            operation->accepted = static_cast<SOCKET>(socket_open(address.ss_family));
            if (operation->accepted == INVALID_SOCKET) return complete_immediately(-socket_last_error());
            result = accept_ex(socket, operation->accepted, operation->addresses, 0, sizeof(sockaddr_storage) + 16,
                               sizeof(sockaddr_storage) + 16, &bytes, &operation->overlapped)
                         ? 0
                         : SOCKET_ERROR;
            break;
        }
        case io_operation_t::connect_k: {
            LPFN_CONNECTEX connect_ex {};
            if (extension(socket, WSAID_CONNECTEX, connect_ex) != ucall_status_success_k)
                return complete_immediately(-socket_last_error());
            auto remote = reinterpret_cast<sockaddr*>(request.data);
            sockaddr_storage local {};
            local.ss_family = remote->sa_family;
            int length = local.ss_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
            if (bind(socket, reinterpret_cast<sockaddr*>(&local), length) != 0)
                return complete_immediately(-socket_last_error());
            result = connect_ex(socket, remote, static_cast<int>(request.length), nullptr, 0, &bytes,
                                &operation->overlapped)
                         ? 0
                         : SOCKET_ERROR;
            break;
        }
        case io_operation_t::receive_k: result = wait_readable(*operation); break;
        case io_operation_t::read_k: {
            WSABUF buffer {static_cast<ULONG>(std::min<std::size_t>(request.length, std::numeric_limits<int>::max())),
                           reinterpret_cast<char*>(request.data)};
            result = WSARecv(socket, &buffer, 1, &bytes, &flags, &operation->overlapped, nullptr);
            break;
        }
        case io_operation_t::send_k:
        case io_operation_t::send_zero_copy_k: {
            WSABUF buffer {static_cast<ULONG>(std::min<std::size_t>(request.length, std::numeric_limits<int>::max())),
                           reinterpret_cast<char*>(request.data)};
            result = WSASend(socket, &buffer, 1, &bytes, 0, &operation->overlapped, nullptr);
            break;
        }
        case io_operation_t::shutdown_k:
        case io_operation_t::close_k:
        case io_operation_t::file_open_k:
        case io_operation_t::file_read_k:
        case io_operation_t::file_read_vectors_k:
        case io_operation_t::zero_copy_release_k: break;
        }
        tally<atomic_ref_template_>(statistics.kernel_enters);
        if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
            auto error = socket_last_error();
            if (operation->accepted != INVALID_SOCKET) {
                closesocket(operation->accepted);
                operation->accepted = INVALID_SOCKET;
            }
            return complete_immediately(-error);
        }
        if (request.deadline) {
            operation->timed = static_cast<unsigned>(timed.size());
            [[maybe_unused]] st::status_t const tracked = timed.push_back(st::assume_reserved, unsigned {index});
        }
        ++active;
        return ucall_status_success_k;
    }

    /** Posts the zero-byte receive that completes once @p operation's socket is readable. */
    int wait_readable(operation_t& operation) noexcept {
        WSABUF nothing {};
        DWORD bytes {}, flags {};
        return WSARecv(static_cast<SOCKET>(operation.request->descriptor), &nothing, 1, &bytes, &flags,
                       &operation.overlapped, nullptr);
    }

    /** Reads what a zero-byte receive announced into the vector @p request names now. */
    descriptor_t receive_ready(io_request_t const& request) noexcept {
        tally<atomic_ref_template_>(statistics.kernel_enters);
        io_vector_t const& room = io_vectors(request).front();
        int const received = recv(
            static_cast<SOCKET>(request.descriptor), static_cast<char*>(room.iov_base),
            static_cast<int>(std::min<std::size_t>(room.iov_len, std::numeric_limits<int>::max())), 0);
        return received >= 0 ? static_cast<descriptor_t>(received) : -socket_last_error();
    }

    /** Reads through a handle reopened unbuffered and overlapped, associated with the port. */
    ucall_status_t submit_file_read(unsigned index) noexcept {
        auto& operation = operations[index];
        auto& request = *operation.request;
        ++active;
        if (request.deadline) {
            operation.timed = static_cast<unsigned>(timed.size());
            [[maybe_unused]] st::status_t const tracked = timed.push_back(st::assume_reserved, unsigned {index});
        }
        tally<atomic_ref_template_>(statistics.kernel_enters);
        HANDLE const file = ReOpenFile(reinterpret_cast<HANDLE>(_get_osfhandle(request.file.file_descriptor)),
                                       GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                       FILE_FLAG_NO_BUFFERING | FILE_FLAG_OVERLAPPED);
        descriptor_t failure = -EIO;
        if (file != INVALID_HANDLE_VALUE) {
            operation.file = file;
            operation.overlapped.Offset = static_cast<DWORD>(request.file.offset);
            operation.overlapped.OffsetHigh = static_cast<DWORD>(request.file.offset >> 32);
            auto const length = static_cast<DWORD>(
                std::min<std::size_t>(request.length, std::numeric_limits<DWORD>::max()));
            if (CreateIoCompletionPort(file, port, 0, 0) &&
                (ReadFile(file, request.data, length, nullptr, &operation.overlapped) ||
                 GetLastError() == ERROR_IO_PENDING)) {
                tally<atomic_ref_template_>(statistics.file_reads_asynchronous);
                return ucall_status_success_k;
            }
            failure = GetLastError() == ERROR_HANDLE_EOF ? 0 : -EIO;
        }
        operation.immediate = failure;
        operation.stage = operation_stage_t::immediate_k;
        immediate_operations.push(operations, index);
        return ucall_status_success_k;
    }
    io_completion_t finish(operation_t& operation, descriptor_t result) noexcept {
        auto& request = *operation.request;
        if (operation.file) {
            CloseHandle(operation.file);
            operation.file = {};
        }
        if (operation.timed != absent_k) untime(operation);
        if (operation.stage == operation_stage_t::timing_out_k && result == -ECANCELED) result = -ETIMEDOUT;
        if (request.operation == io_operation_t::accept_k && operation.accepted != INVALID_SOCKET) {
            if (result >= 0) {
                auto listener = static_cast<SOCKET>(request.descriptor);
                LPFN_GETACCEPTEXSOCKADDRS addresses_of {};
                if (setsockopt(operation.accepted, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                               reinterpret_cast<char const*>(&listener), sizeof(listener)) == 0 &&
                    extension(listener, WSAID_GETACCEPTEXSOCKADDRS, addresses_of) == ucall_status_success_k) {
                    if (auto* peer = reinterpret_cast<io_peer_address_t*>(request.data)) {
                        sockaddr *local {}, *remote {};
                        int local_length {}, remote_length {};
                        addresses_of(operation.addresses, 0, sizeof(sockaddr_storage) + 16,
                                     sizeof(sockaddr_storage) + 16, &local, &local_length, &remote, &remote_length);
                        peer->length = std::min<int>(remote_length, static_cast<int>(sizeof(peer->address)));
                        std::memcpy(&peer->address, remote, static_cast<std::size_t>(peer->length));
                    }
                    result = static_cast<descriptor_t>(operation.accepted);
                }
                else result = -socket_last_error();
            }
            if (result < 0) closesocket(operation.accepted);
        }
        else if (request.operation == io_operation_t::connect_k && result >= 0 &&
                 setsockopt(static_cast<SOCKET>(request.descriptor), SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, nullptr,
                            0) != 0)
            result = -socket_last_error();
        if (request.operation == io_operation_t::close_k && result >= 0) request.descriptor = -1;
        operation.request = nullptr;
        free_operations.push(operations, static_cast<unsigned>(&operation - operations.data()));
        --active;
        tally<atomic_ref_template_>(statistics.completions);
        return {&request, result};
    }
    int poll(span<io_completion_t> completions, io_wait_t wait_policy, std::uint64_t deadline = 0) noexcept {
        std::size_t count {};
        while (count < completions.size() && active) {
            auto now = monotonic_ns();
            auto wait = wait_policy == io_wait_t::blocking_k && !count ? INFINITE : DWORD {0};
            if (deadline) {
                auto duration = deadline > now ? deadline - now : 0;
                wait = std::min<DWORD>(wait, static_cast<DWORD>(std::min<std::uint64_t>(
                                                 duration / 1'000'000 + (duration % 1'000'000 != 0), INFINITE - 1)));
            }
            for (std::size_t i = 0; i != timed.size();) {
                auto& operation = operations[timed[i]];
                auto expiry = operation.request->deadline;
                if (expiry > now) {
                    wait = std::min<DWORD>(
                        wait, static_cast<DWORD>(std::min<std::uint64_t>(
                                  (expiry - now) / 1'000'000 + ((expiry - now) % 1'000'000 != 0), INFINITE - 1)));
                    ++i;
                    continue;
                }
                if (operation.stage == operation_stage_t::pending_k) {
                    operation.stage = operation_stage_t::timing_out_k;
                    CancelIoEx(handle_of(operation), &operation.overlapped);
                }
                untime(operation);
            }
            if (auto index = immediate_operations.pop(operations); index != absent_k) {
                completions[count++] = finish(operations[index], operations[index].immediate);
                continue;
            }
            ULONG dequeued {};
            auto limit = static_cast<ULONG>(std::min(completions.size() - count, entries.size()));
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
                auto& operation = *reinterpret_cast<operation_t*>(entries[i].lpOverlapped);
                DWORD bytes {}, flags {};
                // The per-packet status lives in the OVERLAPPED; this reads it without waiting.
                descriptor_t result {};
                if (operation.file)
                    result = GetOverlappedResult(operation.file, &operation.overlapped, &bytes, FALSE)
                                 ? static_cast<descriptor_t>(bytes)
                             : GetLastError() == ERROR_HANDLE_EOF ? 0
                                                                  : -socket_error(static_cast<int>(GetLastError()));
                else
                    result = WSAGetOverlappedResult(static_cast<SOCKET>(operation.request->descriptor),
                                                    &operation.overlapped, &bytes, FALSE, &flags)
                                 ? static_cast<descriptor_t>(bytes)
                                 : -socket_last_error();
                if (result >= 0 && operation.request->operation == io_operation_t::receive_k) {
                    result = receive_ready(*operation.request);
                    if (result == -EAGAIN) {
                        operation.overlapped = {};
                        if (wait_readable(operation) == 0 || WSAGetLastError() == WSA_IO_PENDING) continue;
                        result = -socket_last_error();
                    }
                }
                completions[count++] = finish(operation, result);
            }
        }
        return static_cast<int>(count);
    }
    void stop() noexcept {
        for (auto& operation : operations)
            if (operation.request && operation.stage != operation_stage_t::immediate_k) {
                if (operation.stage == operation_stage_t::pending_k) operation.stage = operation_stage_t::cancelling_k;
                CancelIoEx(handle_of(operation), &operation.overlapped);
            }
        io_completion_t discarded[32];
        while (active) {
            int count = poll(discarded, io_wait_t::blocking_k);
            if (count < 0) break;
            for (int i = 0; i != count; ++i)
                if (discarded[i].request->operation == io_operation_t::accept_k && discarded[i].result >= 0)
                    socket_close(discarded[i].result);
        }
    }
    ~windows_iocp_engine() noexcept {
        stop();
        if (port) CloseHandle(port);
    }
};
using windows_iocp_engine_t = windows_iocp_engine<>;

} // namespace unum::ucall::io

#endif // UCALL_OS_WINDOWS_
