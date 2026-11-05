/**
 *  @file test/shared.cpp
 *  @author Ash Vardanian
 *  @date November 10, 2025
 *  @brief Tests for the utility types and containers in @c ucall/utilities/types.hpp.
 *
 *  These stand in for their standard-library counterparts because they report an allocation failure
 *  rather than throwing, so every case that grows one checks the answer.
 */
#include <thread> // `std::thread`

#include "harness.hpp" // `expect`, `require`, `run_test`

using namespace unum::ucall;
using namespace unum::ucall::test;

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
    run_test(totals, "test_outcomes_unit", test_outcomes_unit);
    return suite_exit_code(totals);
}
