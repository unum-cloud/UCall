/**
 *  @file test/io/faulting_engine.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief A POSIX engine that delays and resets transfers, as a kernel under pressure does.
 */
#pragma once
#include "ucall/io/posix_engine.hpp" // `posix_engine_t`
#include "ucall/network.hpp"         // `serial_network`

#include "harness.hpp" // `expect_true`

namespace unum::ucall::test::io {

using namespace unum::ucall::io;

#if UCALL_WITH_POSIX

/**
 *  @brief A POSIX engine that mistreats every few transfers it is asked for, as a kernel under
 *      pressure does: one waits a poll before it starts, as a ring refusing an entry makes it,
 *      and another completes with a reset its socket never saw.
 *
 *  It keeps the seam's rule under both: every request submitted completes exactly once. The
 *  pattern is fixed by the count of transfers, so a failing run repeats.
 */
template <typename allocator_type_ = uc::st::default_allocator<byte_t>,
          template <typename> class atomic_ref_template_ = uc::fu::standard_atomic_ref,
          typename row_kit_type_ = uc::st::serial_row_kit_t>
struct faulting_engine {
    using allocator_t = allocator_type_;
    using inner_t = posix_engine<allocator_type_, atomic_ref_template_, row_kit_type_>;
    template <typename other_allocator_, template <typename> class other_atomic_ref_, typename other_row_kit_>
    using rebind = faulting_engine<other_allocator_, other_atomic_ref_, other_row_kit_>;
    static constexpr ucall_io_backend_t backend_k = inner_t::backend_k;
    static constexpr io_receive_memory_t receive_memory_k = inner_t::receive_memory_k;

    /** A request held back: started at the next poll while @c result is zero, else completed
     *  with it. */
    struct held_t {
        io_request_t* request {};
        descriptor_t result {};
    };

    inner_t inner;
    io_statistics_t& statistics {inner.statistics};
    std::vector<held_t> held {};
    std::size_t transfers {};

    explicit faulting_engine(allocator_t const& allocator = {}) noexcept : inner(allocator) {}
    descriptor_t open_socket(int family) noexcept { return inner.open_socket(family); }
    descriptor_t import_socket(descriptor_t descriptor) noexcept { return inner.import_socket(descriptor); }
    int close_socket(descriptor_t descriptor) noexcept { return inner.close_socket(descriptor); }
    [[nodiscard]] ucall_status_t reset_on_close(descriptor_t descriptor) noexcept {
        return inner.reset_on_close(descriptor);
    }
    memory_registration_t register_memory(span<byte_t> memory) noexcept { return inner.register_memory(memory); }
    void release(io_completion_t const& completion) noexcept { inner.release(completion); }
    ucall_status_t open(std::size_t depth, std::size_t capacity,
                        io_issuer_scope_t scope = io_issuer_scope_t::one_thread_k) noexcept {
        return inner.open(depth, capacity, scope);
    }
    void submit(io_request_t& request) noexcept {
        bool const transfer = request.operation == io_operation_t::send_k ||
                              request.operation == io_operation_t::send_zero_copy_k ||
                              request.operation == io_operation_t::receive_k;
        std::size_t const turn = transfer ? transfers++ : 0;
        if (transfer && turn % 7 == 3) held.push_back({&request, 0});
        else if (transfer && turn % 11 == 5) held.push_back({&request, -ECONNRESET});
        else inner.submit(request);
    }
    ucall_status_t cancel(io_request_t& request) noexcept {
        for (held_t& entry : held)
            if (entry.request == &request) {
                entry.result = -ECANCELED;
                return ucall_status_success_k;
            }
        return inner.cancel(request);
    }
    int poll(span<io_completion_t> completions, io_wait_t wait_policy, std::uint64_t deadline = 0) noexcept {
        std::size_t count = 0;
        std::vector<held_t> due;
        due.swap(held);
        for (held_t const& entry : due) {
            if (!entry.result) inner.submit(*entry.request);
            else if (count != completions.size()) completions[count++] = {entry.request, entry.result};
            else held.push_back(entry);
        }
        if (count == completions.size()) return static_cast<int>(count);
        int const landed = inner.poll(completions.subspan(count), count ? io_wait_t::nonblocking_k : wait_policy,
                                      deadline);
        return landed < 0 ? landed : static_cast<int>(count) + landed;
    }
    void stop() noexcept {
        held.clear();
        inner.stop();
    }
};

using faulting_network_t = uc::network::serial_network<io_engine_variant<faulting_engine<>>>;

#endif

} // namespace unum::ucall::test::io
