/**
 *  @file test/utilities/types.cpp
 *  @author Ash Vardanian
 *  @date November 10, 2025
 *  @brief Tests for the outcome word in @c ucall/utilities/types.hpp.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build

#include <thread> // `std::thread`

#include "harness.hpp" // `expect_true`, `run_test_case`

namespace unum::ucall::test::utilities {

/** A waiter blocked in @c ucall_outcome_wait sees the library's publish from another thread, and
 *  every write made before it. */
static void test_outcomes() {
    ucall_outcome_t outcome {ucall_status_deferred_k, "deferred"};
    expect_true(ucall_outcome_status(&outcome) == ucall_status_deferred_k);
    int output = 0;
    std::thread producer([&] {
        output = 42;
        util::publish<fu::standard_atomic_ref>(&outcome, ucall_status_success_k);
    });
    expect_true(ucall_outcome_wait(&outcome) == ucall_status_success_k);
    expect_true(output == 42 && outcome.message == nullptr);
    producer.join();
}

void run_utilities_cases() { run_test_case("test_outcomes", test_outcomes); }

} // namespace unum::ucall::test::utilities
