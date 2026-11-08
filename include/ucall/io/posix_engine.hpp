/**
 *  @file include/ucall/io/posix_engine.hpp
 *  @author Ash Vardanian
 *  @date January 13, 2025
 *  @brief Nonblocking POSIX syscalls completed through poll readiness.
 */
#pragma once

#include <smashtable/basic_vector.hpp> // `vector`
#include <smashtable/row_search.hpp>   // `serial_row_kit_t`

#include "ucall/io/types.hpp"          // `operation_list_t`, `io_request_t`, `operation_stage_t`, `io_statistics_t`
#include "ucall/utilities/sockets.hpp" // `socket_open`, `socket_close`, `socket_reset_on_close`, `monotonic_ns`
#include "ucall/utilities/types.hpp"   // `byte_t`, `descriptor_t`, `span`

#if UCALL_OS_POSIX_

namespace unum::ucall::io {

using utilities::byte_t;
using utilities::descriptor_t;
using utilities::monotonic_ns;
using utilities::socket_close;
using utilities::socket_open;
using utilities::socket_reset_on_close;
using utilities::span;

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
    static constexpr io_receive_memory_t receive_memory_k = io_receive_memory_t::submitter_k;
    template <typename value_type_>
    using rebound_allocator = typename std::allocator_traits<allocator_t>::template rebind_alloc<value_type_>;

    /** Whether an operation is free, queued fresh, or waiting in @c polling. */
    enum class operation_place_t : std::uint8_t { free_k, queued_k, polled_k };
    struct operation_t {
        io_request_t* request {};

        /** The next free or fresh operation, or its slot in @c polling once polled. */
        unsigned next {absent_k};

        operation_stage_t stage {operation_stage_t::fresh_k};
        operation_place_t place {operation_place_t::free_k};
    };
    static_assert(sizeof(operation_t) == 16);
    st::vector<operation_t, rebound_allocator<operation_t>> operations {};
    st::vector<pollfd, rebound_allocator<pollfd>> polling {};
    st::vector<unsigned, rebound_allocator<unsigned>> polled {};
    operation_list_t free_operations, fresh_operations;
    unsigned waiting {};
    io_statistics_t statistics {};
    descriptor_t open_socket(int family) noexcept { return socket_open(family); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept { return descriptor; }
    int close_socket(descriptor_t descriptor) noexcept { return socket_close(descriptor); }
    [[nodiscard]] ucall_status_t reset_on_close(descriptor_t descriptor) noexcept {
        return socket_reset_on_close(descriptor);
    }
    memory_registration_t register_memory(span<byte_t>) noexcept { return {}; }
    void release(io_completion_t const&) noexcept {}
    ucall_status_t cancel(io_request_t& request) noexcept {
        for (unsigned i = 0; i != operations.size(); ++i)
            if (operations[i].request == &request) {
                tally<atomic_ref_template_>(statistics.cancellations);
                operations[i].stage = operation_stage_t::cancelled_k;
                if (operations[i].place == operation_place_t::polled_k) {
                    unpoll(operations[i]);
                    operations[i].place = operation_place_t::queued_k;
                    fresh_operations.push(operations, i);
                }
                return ucall_status_success_k;
            }
        return ucall_status_not_found_k;
    }
    explicit posix_engine(allocator_t const& allocator = {}) noexcept
        : operations(rebound_allocator<operation_t> {allocator}), polling(rebound_allocator<pollfd> {allocator}),
          polled(rebound_allocator<unsigned> {allocator}) {}
    posix_engine(posix_engine const&) = delete;
    posix_engine& operator=(posix_engine const&) = delete;
    posix_engine(posix_engine&&) = delete;
    posix_engine& operator=(posix_engine&&) = delete;
    ~posix_engine() noexcept { stop(); }
    ucall_status_t open(std::size_t, std::size_t capacity,
                        io_issuer_scope_t = io_issuer_scope_t::one_thread_k) noexcept {
        if (st::failed(operations.resize(capacity)) || st::failed(polling.resize(capacity)) ||
            st::failed(polled.resize(capacity)))
            return ucall_status_out_of_memory_k;
        stop();
        return ucall_status_success_k;
    }
    void stop() noexcept {
        free_operations = fresh_operations = {};
        waiting = 0;
        for (unsigned i = 0; i != operations.size(); ++i) {
            operations[i] = {};
            free_operations.push(operations, i);
        }
    }
    ucall_status_t submit(io_request_t& request) noexcept {
        auto index = free_operations.pop(operations);
        if (index == absent_k) return ucall_status_contended_k;
        operations[index] = {};
        operations[index].request = &request;
        operations[index].place = operation_place_t::queued_k;
        fresh_operations.push(operations, index);
        tally<atomic_ref_template_>(statistics.submissions);
        return ucall_status_success_k;
    }
    void unpoll(operation_t& operation) noexcept {
        auto position = operation.next;
        --waiting;
        polling[position] = polling[waiting];
        polled[position] = polled[waiting];
        operations[polled[position]].next = position;
        operation.next = absent_k;
    }
    io_completion_t finish(unsigned index, descriptor_t result) noexcept {
        auto& operation = operations[index];
        auto& request = *operation.request;
        if (operation.place == operation_place_t::polled_k) unpoll(operation);
        if (request.operation == io_operation_t::close_k && result >= 0) request.descriptor = -1;
        operation.request = nullptr;
        operation.place = operation_place_t::free_k;
        free_operations.push(operations, index);
        tally<atomic_ref_template_>(statistics.completions);
        return {&request, result};
    }
    int poll(span<io_completion_t> completions, io_wait_t wait_policy, std::uint64_t deadline = 0) noexcept {
        std::size_t count = 0;
        for (unsigned round = 0; round != 2; ++round) {
            auto now = monotonic_ns();
            auto wait = wait_policy == io_wait_t::blocking_k ? std::numeric_limits<std::uint64_t>::max() : 0;
            if (deadline)
                wait = std::min(wait, deadline > now ? (deadline - now) / 1000 + ((deadline - now) % 1000 != 0) : 0);
            while (count != completions.size()) {
                auto index = fresh_operations.pop(operations);
                if (index == absent_k) break;
                auto& operation = operations[index];
                auto& request = *operation.request;
                auto result = request.deadline && now >= request.deadline
                                  ? -ETIMEDOUT
                                  : attempt_io<atomic_ref_template_>(request, operation.stage, io_interest_t::unarmed_k,
                                                                     statistics);
                if (!io_pending(result)) {
                    completions[count++] = finish(index, result);
                    continue;
                }
                operation.place = operation_place_t::polled_k;
                operation.next = waiting;
                polling[waiting] = {static_cast<int>(request.descriptor), io_events(request.operation), 0};
                polled[waiting++] = index;
            }
            for (unsigned i = 0; i != waiting && count != completions.size();) {
                auto& operation = operations[polled[i]];
                auto& request = *operation.request;
                bool expired = request.deadline && now >= request.deadline;
                if (expired || polling[i].revents) {
                    auto result = expired ? -ETIMEDOUT
                                          : attempt_io<atomic_ref_template_>(request, operation.stage,
                                                                             io_interest_t::ready_k, statistics);
                    polling[i].revents = 0;
                    if (!io_pending(result)) {
                        completions[count++] = finish(polled[i], result);
                        continue;
                    }
                }
                if (request.deadline) wait = std::min(wait, (request.deadline - now + 999) / 1000);
                ++i;
            }
            if (count || round || !waiting) break;
            int timeout = wait == std::numeric_limits<std::uint64_t>::max()
                              ? -1
                              : static_cast<int>(std::min<std::uint64_t>(wait / 1000 + (wait % 1000 != 0),
                                                                         std::numeric_limits<int>::max()));
            tally<atomic_ref_template_>(statistics.kernel_enters);
            int result = ::poll(polling.data(), static_cast<nfds_t>(waiting), timeout);
            if (result < 0 && errno != EINTR) return -errno;
        }
        return static_cast<int>(count);
    }
};

using posix_engine_t = posix_engine<>;

} // namespace unum::ucall::io

#endif // UCALL_OS_POSIX_
