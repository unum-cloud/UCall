/**
 *  @file include/ucall/io/posix_engine.hpp
 *  @author Ash Vardanian
 *  @date January 13, 2025
 *  @brief Nonblocking POSIX syscalls completed through poll readiness.
 */
#pragma once

#include <smashtable/basic_hash_index.hpp> // `basic_hash_index`
#include <smashtable/basic_vector.hpp>     // `vector`
#include <smashtable/row_search.hpp>       // `serial_row_kit_t`

#include "ucall/io/types.hpp"          // `operation_list_t`, `io_request_t`, `readiness_poll`, `io_statistics_t`
#include "ucall/utilities/sockets.hpp" // `socket_open`, `socket_close`, `socket_reset_on_close`, `socket_poll`
#include "ucall/utilities/types.hpp"   // `byte_t`, `descriptor_t`, `span`

#if UCALL_OS_POSIX_

namespace unum::ucall::io {

using utilities::byte_t;
using utilities::descriptor_t;
using utilities::socket_close;
using utilities::socket_open;
using utilities::socket_poll;
using utilities::socket_reset_on_close;
using utilities::span;

/** One @c pollfd per descriptor an operation waits on, naming the operation waiting in each
 *  direction, found by descriptor through an index at most half full; @c poll is level-triggered,
 *  so a direction leaves the set once its operation ends. */
template <typename allocator_type_ = st::default_allocator<byte_t>,
          template <typename> class atomic_ref_template_ = fu::standard_atomic_ref,
          typename row_kit_type_ = st::serial_row_kit_t>
struct poll_readiness {
    using allocator_t = allocator_type_;
    static constexpr unsigned absent_k = operation_list_t::absent_k;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    using position_index_t =
        st::basic_hash_index<std::int32_t, std::uint32_t, st::default_hash_t, rebound_allocator<byte_t>, row_kit_type_>;

    /** The operations waiting on one polled descriptor, one per direction. */
    struct waiters_t {
        unsigned receive_operation {absent_k};
        unsigned transmit_operation {absent_k};
    };

    explicit poll_readiness(allocator_t const& allocator = {}) noexcept
        : polled(rebound_allocator<pollfd> {allocator}), waiters(rebound_allocator<waiters_t> {allocator}) {}
    poll_readiness(poll_readiness const&) = delete;
    poll_readiness& operator=(poll_readiness const&) = delete;
    poll_readiness(poll_readiness&&) = delete;
    poll_readiness& operator=(poll_readiness&&) = delete;

    /** Parallel to @c waiters, as @c poll reads them. */
    st::vector<pollfd, rebound_allocator<pollfd>> polled {};
    st::vector<waiters_t, rebound_allocator<waiters_t>> waiters {};
    position_index_t positions {};

    ucall_status_t open(std::size_t capacity) noexcept {
        clear();
        if (st::failed(polled.reserve(capacity)) || st::failed(waiters.reserve(capacity)))
            return ucall_status_out_of_memory_k;
        st::expected<position_index_t> made = position_index_t::make(
            capacity, {}, rebound_allocator<byte_t> {polled.get_allocator()});
        if (!made) return ucall_status_out_of_memory_k;
        positions = std::move(*made);
        return ucall_status_success_k;
    }

    /** Points the @p direction of @p watched at operation @p index, polling the descriptor from now
     *  on: zero, or a negated errno once every record is taken. */
    int arm(descriptor_t watched, io_direction_t direction, unsigned index, io_statistics_t&) noexcept {
        std::uint32_t position = positions.find(static_cast<std::int32_t>(watched));
        if (position == position_index_t::absent_k) {
            if (polled.size() == polled.capacity()) return -ENOBUFS;
            position = static_cast<std::uint32_t>(polled.size());
            [[maybe_unused]] st::status_t const listed = polled.push_back(st::assume_reserved,
                                                                          pollfd {static_cast<int>(watched), 0, 0});
            [[maybe_unused]] st::status_t const named = waiters.push_back(st::assume_reserved, waiters_t {});
            [[maybe_unused]] st::status_t const indexed = positions.insert(static_cast<std::int32_t>(watched), position,
                                                                           st::assume_unique);
        }
        unsigned& waiter = direction == io_direction_t::receive_k ? waiters[position].receive_operation
                                                                  : waiters[position].transmit_operation;
        assert((waiter == absent_k || waiter == index) && "one pending operation per socket per direction");
        waiter = index;
        polled[position].events |= direction == io_direction_t::receive_k ? POLLIN : POLLOUT;
        return 0;
    }

    /** Stops polling @p direction of @p watched for operation @p index, and the descriptor once no
     *  operation waits on it. */
    void disarm(descriptor_t watched, io_direction_t direction, unsigned index) noexcept {
        std::uint32_t const position = positions.find(static_cast<std::int32_t>(watched));
        if (position == position_index_t::absent_k) return;
        waiters_t& waiting = waiters[position];
        unsigned& waiter = direction == io_direction_t::receive_k ? waiting.receive_operation
                                                                  : waiting.transmit_operation;
        if (waiter != index) return;
        waiter = absent_k;
        polled[position].events &= static_cast<short>(~(direction == io_direction_t::receive_k ? POLLIN : POLLOUT));
        if (waiting.receive_operation == absent_k && waiting.transmit_operation == absent_k) erase(position);
    }

    /** Stops polling @p watched, as its close must before the number is reused. */
    void remove(descriptor_t watched) noexcept {
        std::uint32_t const position = positions.find(static_cast<std::int32_t>(watched));
        if (position != position_index_t::absent_k) erase(position);
    }

    /** Polls nothing. */
    void clear() noexcept {
        polled.clear();
        waiters.clear();
        positions.clear();
    }

    /** Moves the last record into @p position, keeping the set dense. */
    void erase(std::uint32_t position) noexcept {
        auto const last = static_cast<std::uint32_t>(polled.size() - 1);
        [[maybe_unused]] st::status_t const unindexed = positions.erase(polled[position].fd, position);
        if (position != last) {
            polled[position] = polled[last];
            waiters[position] = waiters[last];
            [[maybe_unused]] st::status_t const moved = positions.erase(polled[position].fd, last);
            [[maybe_unused]] st::status_t const reindexed = positions.insert(polled[position].fd, position,
                                                                             st::assume_unique);
        }
        polled.pop_back();
        waiters.pop_back();
    }

    /** Waits up to @p nanoseconds, the maximum meaning forever, reporting each ready direction to
     *  @p fired; a hangup, an error or a closed descriptor wakes both, whose syscalls tell why. */
    template <typename fired_type_>
    int wait(std::uint64_t nanoseconds, fired_type_&& fired) noexcept {
        int const count = socket_poll(polled.data(), polled.size(), nanoseconds);
        for (std::size_t position = 0; count > 0 && position != polled.size(); ++position) {
            short const reported = std::exchange(polled[position].revents, short {});
            descriptor_t const descriptor = polled[position].fd;
            waiters_t const waiting = waiters[position];
            if ((reported & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) && waiting.receive_operation != absent_k)
                fired(waiting.receive_operation, descriptor, short {POLLIN});
            if ((reported & (POLLOUT | POLLHUP | POLLERR | POLLNVAL)) && waiting.transmit_operation != absent_k)
                fired(waiting.transmit_operation, descriptor, short {POLLOUT});
        }
        return count;
    }
};

/** Nonblocking POSIX syscalls, completed through poll readiness; files are read blocking, and
 *  zero-copy sends copy, so their releases complete as submitted. */
template <typename allocator_type_ = st::default_allocator<byte_t>,
          template <typename> class atomic_ref_template_ = fu::standard_atomic_ref,
          typename row_kit_type_ = st::serial_row_kit_t>
struct posix_engine {
    using allocator_t = allocator_type_;
    template <typename other_allocator_, template <typename> class other_atomic_ref_, typename other_row_kit_>
    using rebind = posix_engine<other_allocator_, other_atomic_ref_, other_row_kit_>;
    static constexpr unsigned absent_k = operation_list_t::absent_k;
    static constexpr ucall_io_backend_t backend_k = ucall_io_backend_posix_k;
    static constexpr io_receive_memory_t receive_memory_k = io_receive_memory_t::submitter_k;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;
    struct operation_t {
        io_request_t* request {};
        unsigned next {absent_k};
        operation_stage_t stage {operation_stage_t::fresh_k};
        io_interest_t interest {io_interest_t::unarmed_k};
    };
    static_assert(sizeof(operation_t) == 16);

    /** Touched only by timed operations. */
    struct operation_cold_t {
        unsigned timed {absent_k};
        descriptor_t result {};
    };
    explicit posix_engine(allocator_t const& allocator = {}) noexcept
        : operations(rebound_allocator<operation_t> {allocator}), cold(rebound_allocator<operation_cold_t> {allocator}),
          timed(rebound_allocator<unsigned> {allocator}), readiness(allocator) {}
    posix_engine(posix_engine const&) = delete;
    posix_engine& operator=(posix_engine const&) = delete;
    posix_engine(posix_engine&&) = delete;
    posix_engine& operator=(posix_engine&&) = delete;
    ~posix_engine() noexcept { stop(); }
    st::vector<operation_t, rebound_allocator<operation_t>> operations {};
    st::vector<operation_cold_t, rebound_allocator<operation_cold_t>> cold {};
    st::vector<unsigned, rebound_allocator<unsigned>> timed {};
    poll_readiness<allocator_t, atomic_ref_template_, row_kit_type_> readiness {};
    operation_list_t free_operations, fresh_operations, ready_operations, landed_operations;
    std::size_t active {};
    io_statistics_t statistics {};
    operation_list_t& free_list(unsigned) noexcept { return free_operations; }
    operation_cold_t& cold_fields(unsigned index) noexcept { return cold[index]; }

    descriptor_t open_socket(int family) noexcept { return socket_open(family); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept { return descriptor; }
    int close_socket(descriptor_t descriptor) noexcept {
        readiness.remove(descriptor);
        return socket_close(descriptor);
    }
    [[nodiscard]] ucall_status_t reset_on_close(descriptor_t descriptor) noexcept {
        return socket_reset_on_close(descriptor);
    }
    memory_registration_t register_memory(span<byte_t>) noexcept { return {}; }
    void release(io_completion_t const&) noexcept {}
    ucall_status_t cancel(io_request_t& request) noexcept {
        unsigned const index = request.operation_index;
        if (index >= operations.size() || operations[index].request != &request) return ucall_status_not_found_k;
        tally<atomic_ref_template_>(statistics.cancellations);
        operations[index].stage = operation_stage_t::cancelled_k;
        if (operations[index].interest == io_interest_t::armed_k) readiness_wake(*this, index);
        return ucall_status_success_k;
    }
    ucall_status_t open(std::size_t, std::size_t capacity,
                        io_issuer_scope_t = io_issuer_scope_t::one_thread_k) noexcept {
        // Sized first, so after a failed open `stop` walks no operation without a cold record.
        if (st::failed(cold.resize(capacity)) || st::failed(operations.resize(capacity)) ||
            st::failed(timed.reserve(capacity)))
            return ucall_status_out_of_memory_k;
        stop();
        return readiness.open(capacity);
    }
    void stop() noexcept {
        free_operations = fresh_operations = ready_operations = landed_operations = {};
        timed.clear();
        active = 0;
        for (unsigned i = 0; i != operations.size(); ++i) {
            operations[i] = {};
            cold[i] = {};
            free_operations.push(operations, i);
        }
        readiness.clear();
    }
    ucall_status_t submit(io_request_t& request) noexcept {
        auto index = free_operations.pop(operations);
        if (index == absent_k) return ucall_status_contended_k;
        operations[index] = {};
        cold[index] = {};
        operations[index].request = &request;
        request.operation_index = index;
        fresh_operations.push(operations, index);
        if (request.deadline) {
            cold[index].timed = static_cast<unsigned>(timed.size());
            [[maybe_unused]] st::status_t const tracked = timed.push_back(st::assume_reserved, unsigned {index});
        }
        ++active;
        tally<atomic_ref_template_>(statistics.submissions);
        return ucall_status_success_k;
    }
    descriptor_t attempt(unsigned index) noexcept {
        auto& operation = operations[index];
        if (operation.request->operation == io_operation_t::close_k) readiness.remove(operation.request->descriptor);
        return attempt_io<atomic_ref_template_>(*operation.request, operation.stage, operation.interest, statistics);
    }
    int wait(std::uint64_t nanoseconds) noexcept {
        tally<atomic_ref_template_>(statistics.kernel_enters);
        return readiness.wait(nanoseconds, [&](unsigned index, descriptor_t descriptor, short events) noexcept {
            readiness_fire(*this, index, descriptor, events);
        });
    }
    int poll(span<io_completion_t> completions, io_wait_t wait_policy, std::uint64_t deadline = 0) noexcept {
        return readiness_poll<atomic_ref_template_>(*this, completions, wait_policy, deadline);
    }
};

using posix_engine_t = posix_engine<>;

} // namespace unum::ucall::io

#endif // UCALL_OS_POSIX_
