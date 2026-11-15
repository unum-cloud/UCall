/**
 *  @file test/utilities/types.cpp
 *  @author Ash Vardanian
 *  @date November 10, 2025
 *  @brief Tests for the outcome word in @c ucall/utilities/types.hpp.
 */
#include <thread> // `std::thread`

#include "harness.hpp" // `expect`, `report`

namespace unum::ucall::test::utilities {

using namespace unum::ucall::utilities;

/** A waiter blocked in @c ucall_outcome_wait sees the library's publish from another thread, and
 *  every write made before it. */
static std::size_t test_outcomes() {
    std::size_t failures = 0;
    ucall_outcome_t outcome {ucall_status_deferred_k, "deferred"};
    failures += expect(ucall_outcome_status(&outcome) == ucall_status_deferred_k);
    int output = 0;
    std::thread producer([&] {
        output = 42;
        publish<fu::standard_atomic_ref>(&outcome, ucall_status_success_k);
    });
    failures += expect(ucall_outcome_wait(&outcome) == ucall_status_success_k);
    failures += expect(output == 42 && outcome.message == nullptr);
    producer.join();
    return failures;
}

std::size_t check_utilities(settings_t const& settings) {
    if (!settings.filter.selects("utilities types")) return 0;
    return report("utilities types", test_outcomes());
}

} // namespace unum::ucall::test::utilities
