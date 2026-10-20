/**
 *  @file test/shared.cpp
 *  @author Ash Vardanian
 *  @date November 10, 2025
 *  @brief Tests for the utility types and containers in @c shared.hpp.
 *
 *  These stand in for their standard-library counterparts because they report an allocation failure
 *  rather than throwing, so every case that grows one checks the answer.
 */
#include <cstring> // `std::strstr`

#include <thread>  // `std::thread`
#include <utility> // `std::move`

#include "harness.hpp" // `expect`, `require`, `run_test`

using namespace unum::ucall;
using namespace unum::ucall::test;

#pragma region Utilities

/** Whether two floats agree closely enough for a magnitude meant to be read by a human. */
[[nodiscard]] static bool nearly_equal(float left, float right) noexcept {
    float const difference = left - right;
    return (difference < 0.0f ? -difference : difference) < 1e-3f;
}

case_result_t test_utilities_unit() {
    std::size_t failures = 0;
    announce("string_length");
    // A length of zero means "measure it"; anything else is trusted without a scan.
    failures += expect(string_length("hello", 0) == 5u);
    failures += expect(string_length("hello", 5) == 5u);
    failures += expect(string_length("test", 4) == 4u);
    failures += expect(string_length("", 0) == 0u);
    failures += expect(string_length("", 5) == 5u);
    failures += expect(string_length(nullptr, 0) == 0u);
    failures += expect(string_length(nullptr, 10) == 0u);

    announce("printable");
    number_and_suffix_t scaled = printable(500);
    failures += expect(nearly_equal(scaled.number, 500.0f) && scaled.suffix == ' ');
    scaled = printable(1'500);
    failures += expect(nearly_equal(scaled.number, 1.5f) && scaled.suffix == 'K');
    scaled = printable(2'500'000);
    failures += expect(nearly_equal(scaled.number, 2.5f) && scaled.suffix == 'M');
    scaled = printable(3'500'000'000);
    failures += expect(nearly_equal(scaled.number, 3.5f) && scaled.suffix == 'G');
    return failures;
}

case_result_t test_traffic_stats_unit() {
    std::size_t failures = 0;
    announce("human_readable_drains_every_counter");
    traffic_stats_t stats;
    stats.added_connections.store(100);
    stats.bytes_sent.store(5'000'000);

    char rendered[512];
    std::size_t written = stats.log_human_readable(rendered, sizeof(rendered), 5);
    failures += expect(written > 0 && written < sizeof(rendered));
    // Rendering exchanges each counter for zero, or a second call over the same window would
    // double-count what it already reported.
    failures += expect(stats.added_connections.load() == 0u);
    failures += expect(stats.bytes_sent.load() == 0u);

    announce("a_zero_second_window_does_not_divide_by_zero");
    stats.packets_received.store(1000);
    written = stats.log_human_readable(rendered, sizeof(rendered), 0);
    failures += expect(written > 0);

    announce("json_names_every_counter");
    stats.added_connections.store(10);
    stats.closed_connections.store(5);
    stats.bytes_received.store(1024);
    stats.bytes_sent.store(2048);
    stats.packets_received.store(50);
    stats.packets_sent.store(75);

    written = stats.log_json(rendered, sizeof(rendered));
    require(failures, written > 0 && written < sizeof(rendered));
    rendered[written] = '\0';
    failures += expect(std::strstr(rendered, "\"add\":10") != nullptr);
    failures += expect(std::strstr(rendered, "\"close\":5") != nullptr);
    return failures;
}

#pragma endregion Utilities

#pragma region Containers

case_result_t test_pool_unit() {
    std::size_t failures = 0;
    announce("allocation_hands_out_distinct_slots");
    pool<int> slots;
    require(failures, slots.reserve(5));
    failures += expect(slots.capacity() == 5u);

    int* const first = slots.alloc();
    int* const second = slots.alloc();
    require(failures, first != nullptr);
    require(failures, second != nullptr);
    failures += expect(first != second);

    announce("a_released_slot_is_handed_out_again");
    *first = 42;
    slots.release(first);
    int* const reused = slots.alloc();
    failures += expect(reused != nullptr);

    announce("offsets_round_trip");
    std::size_t const offset = slots.offset_of(*second);
    require(failures, offset < 5u);
    failures += expect(&slots.at_offset(offset) == second);
    return failures;
}

case_result_t test_memory_map_unit() {
    std::size_t failures = 0;
    announce("remap_allocates_and_reports_its_size");
    memory_map_t mapping;
    require(failures, mapping.remap(fixture_buffer_bytes_k));
    require(failures, mapping.data() != nullptr);
    failures += expect(mapping.size() == fixture_buffer_bytes_k);

    announce("pages_arrive_zeroed");
    // A mapping that arrived dirty would hand a connection whatever the last one left behind.
    failures += expect(all_zero({mapping.data(), mapping.data() + mapping.size()}));

    announce("remapping_replaces_the_old_mapping");
    failures += expect(mapping.remap(fixture_buffer_bytes_k * 2));
    failures += expect(mapping.data() != nullptr);
    failures += expect(mapping.size() == fixture_buffer_bytes_k * 2);

    announce("reset_unmaps");
    mapping.reset();
    failures += expect(mapping.size() == 0u);
    return failures;
}

/**
 *  @brief Moving every container, in one place, because they all promise the same three things.
 *
 *  The source releases ownership, the destination reports the same capacity and count, and the
 *  elements are the same objects rather than copies.
 */
case_result_t test_containers_moves_unit() {
    std::size_t failures = 0;
    {
        announce("pool");
        pool<int> source;
        require(failures, source.reserve(5));
        int* const first = source.alloc();
        int* const second = source.alloc();
        require(failures, first != nullptr && second != nullptr);
        *first = 42;
        *second = 99;

        // A pool hands out addresses, so a move must not relocate what it already handed out.
        pool<int> constructed(std::move(source));
        failures += expect(*first == 42);
        failures += expect(*second == 99);
        failures += expect(constructed.capacity() == 5u);

        pool<int> assigned;
        assigned = std::move(constructed);
        failures += expect(*first == 42);
        failures += expect(*second == 99);
        failures += expect(assigned.capacity() == 5u);
    }
    return failures;
}

case_result_t test_containers_safety() {
    std::size_t failures = 0;
    announce("a_pool_refuses_rather_than_overruns");
    pool<int> slots;
    require(failures, slots.reserve(5));
    int* taken[5];
    for (std::size_t index = 0; index != 5; ++index) {
        taken[index] = slots.alloc();
        require(failures, taken[index] != nullptr);
    }
    // The sixth request must say so rather than hand back a slot already in use.
    failures += expect(slots.alloc() == nullptr);

    slots.release(taken[2]);
    failures += expect(slots.alloc() != nullptr);
    failures += expect(slots.alloc() == nullptr);
    return failures;
}

#pragma endregion Containers

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
    run_test(totals, "test_utilities_unit", test_utilities_unit);
    run_test(totals, "test_traffic_stats_unit", test_traffic_stats_unit);
    run_test(totals, "test_pool_unit", test_pool_unit);
    run_test(totals, "test_memory_map_unit", test_memory_map_unit);
    run_test(totals, "test_containers_moves_unit", test_containers_moves_unit);
    run_test(totals, "test_containers_safety", test_containers_safety);
    run_test(totals, "test_outcomes_unit", test_outcomes_unit);
    return suite_exit_code(totals);
}
