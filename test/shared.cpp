/**
 *  @file test/shared.cpp
 *  @author Ash Vardanian
 *  @date November 10, 2025
 *  @brief Tests for the utility types and containers in @c shared.hpp.
 *
 *  These stand in for their standard-library counterparts because they report an allocation failure
 *  rather than throwing, so every case that grows one checks the answer.
 */
#include <thread> // `std::thread`

#include "harness.hpp" // `expect`, `require`, `run_test`

using namespace unum::ucall;
using namespace unum::ucall::test;

#pragma region Utilities and Containers

case_result_t test_pool_unit() {
    std::size_t failures = 0;
    announce("allocation_hands_out_distinct_slots");
    successive_pools<int> slots(5);

    int* const first = slots.alloc();
    int* const second = slots.alloc();
    require(failures, first != nullptr);
    require(failures, second != nullptr);
    failures += expect(first != second);

    announce("a_released_slot_is_handed_out_again");
    *first = 42;
    slots.release(first);
    failures += expect(slots.alloc() == first);

    return failures;
}

case_result_t test_containers_safety() {
    std::size_t failures = 0;
    announce("a_full_pool_grows_without_moving_taken_slots");
    successive_pools<int> slots(5);
    int* taken[5];
    for (std::size_t index = 0; index != 5; ++index) {
        taken[index] = slots.alloc();
        require(failures, taken[index] != nullptr);
        *taken[index] = static_cast<int>(index);
    }
    // The sixth request must come from a new pool rather than hand back a slot already in use.
    int* const grown = slots.alloc();
    require(failures, grown != nullptr);
    for (std::size_t index = 0; index != 5; ++index)
        failures += expect(grown != taken[index] && *taken[index] == static_cast<int>(index));
    return failures;
}

#pragma endregion Utilities and Containers

case_result_t test_outcomes_unit() {
    std::size_t failures = 0;
    ucall_outcome_t outcome {ucall_status_deferred_k, "deferred"};
    failures += expect(ucall_outcome_status(&outcome) == ucall_status_deferred_k);
    int output = 0;
    std::thread producer([&] {
        output = 42;
        outcome.message = nullptr;
        std::atomic_ref<ucall_status_t> word {outcome.status};
        word.store(ucall_status_success_k, std::memory_order_release);
        word.notify_all();
    });
    failures += expect(ucall_outcome_wait(&outcome) == ucall_status_success_k);
    failures += expect(output == 42 && outcome.message == nullptr);
    producer.join();
    return failures;
}

int main(int, char** argv) {
    install_test_signal_handlers();
    fmt::print("Hi, dear tester! You look nice today!\n");
    configure_tests();

    suite_totals_t totals {.program = argv[0]};
    run_test(totals, "test_pool_unit", test_pool_unit);
    run_test(totals, "test_containers_safety", test_containers_safety);
    run_test(totals, "test_outcomes_unit", test_outcomes_unit);
    return suite_exit_code(totals);
}
