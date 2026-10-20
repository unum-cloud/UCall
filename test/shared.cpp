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

#include "harness.hpp" // `verify`, `run_test`, `scale_iterations`

using namespace unum::ucall;
using namespace unum::ucall::test;

#pragma region Utilities

/** Whether two floats agree closely enough for a magnitude meant to be read by a human. */
[[nodiscard]] static bool nearly_equal(float left, float right) noexcept {
    float const difference = left - right;
    return (difference < 0.0f ? -difference : difference) < 1e-3f;
}

void test_utilities_unit() {
    announce("string_length");
    // A length of zero means "measure it"; anything else is trusted without a scan.
    verify(string_length("hello", 0) == 5u);
    verify(string_length("hello", 5) == 5u);
    verify(string_length("test", 4) == 4u);
    verify(string_length("", 0) == 0u);
    verify(string_length("", 5) == 5u);
    verify(string_length(nullptr, 0) == 0u);
    verify(string_length(nullptr, 10) == 0u);

    announce("printable");
    number_and_suffix_t scaled = printable(500);
    verify(nearly_equal(scaled.number, 500.0f) && scaled.suffix == ' ');
    scaled = printable(1'500);
    verify(nearly_equal(scaled.number, 1.5f) && scaled.suffix == 'K');
    scaled = printable(2'500'000);
    verify(nearly_equal(scaled.number, 2.5f) && scaled.suffix == 'M');
    scaled = printable(3'500'000'000);
    verify(nearly_equal(scaled.number, 3.5f) && scaled.suffix == 'G');
}

void test_traffic_stats_unit() {
    announce("human_readable_drains_every_counter");
    traffic_stats_t stats;
    stats.added_connections.store(100);
    stats.bytes_sent.store(5'000'000);

    char rendered[512];
    std::size_t written = stats.log_human_readable(rendered, sizeof(rendered), 5);
    verify(written > 0 && written < sizeof(rendered));
    // Rendering exchanges each counter for zero, or a second call over the same window would
    // double-count what it already reported.
    verify(stats.added_connections.load() == 0u);
    verify(stats.bytes_sent.load() == 0u);

    announce("a_zero_second_window_does_not_divide_by_zero");
    stats.packets_received.store(1000);
    written = stats.log_human_readable(rendered, sizeof(rendered), 0);
    verify(written > 0);

    announce("json_names_every_counter");
    stats.added_connections.store(10);
    stats.closed_connections.store(5);
    stats.bytes_received.store(1024);
    stats.bytes_sent.store(2048);
    stats.packets_received.store(50);
    stats.packets_sent.store(75);

    written = stats.log_json(rendered, sizeof(rendered));
    verify(written > 0 && written < sizeof(rendered));
    rendered[written] = '\0';
    verify(std::strstr(rendered, "\"add\":10") != nullptr);
    verify(std::strstr(rendered, "\"close\":5") != nullptr);
}

#pragma endregion Utilities

#pragma region Containers

void test_pool_unit() {
    announce("allocation_hands_out_distinct_slots");
    pool<int> slots;
    verify(slots.reserve(5));
    verify(slots.capacity() == 5u);

    int* const first = slots.alloc();
    int* const second = slots.alloc();
    verify(first != nullptr);
    verify(second != nullptr);
    verify(first != second);

    announce("a_released_slot_is_handed_out_again");
    *first = 42;
    slots.release(first);
    int* const reused = slots.alloc();
    verify(reused != nullptr);

    announce("offsets_round_trip");
    std::size_t const offset = slots.offset_of(*second);
    verify(offset < 5u);
    verify(&slots.at_offset(offset) == second);
}

void test_memory_map_unit() {
    announce("remap_allocates_and_reports_its_size");
    memory_map_t mapping;
    verify(mapping.remap(fixture_buffer_bytes_k));
    verify(mapping.data() != nullptr);
    verify(mapping.size() == fixture_buffer_bytes_k);

    announce("pages_arrive_zeroed");
    // A mapping that arrived dirty would hand a connection whatever the last one left behind.
    verify(all_zero({mapping.data(), mapping.data() + mapping.size()}));

    announce("remapping_replaces_the_old_mapping");
    verify(mapping.remap(fixture_buffer_bytes_k * 2));
    verify(mapping.data() != nullptr);
    verify(mapping.size() == fixture_buffer_bytes_k * 2);

    announce("reset_unmaps");
    mapping.reset();
    verify(mapping.data() == nullptr);
    verify(mapping.size() == 0u);
}

/**
 *  @brief Moving every container, in one place, because they all promise the same three things.
 *
 *  The source releases ownership, the destination reports the same capacity and count, and the
 *  elements are the same objects rather than copies.
 */
void test_containers_moves_unit() {
    {
        announce("pool");
        pool<int> source;
        verify(source.reserve(5));
        int* const first = source.alloc();
        int* const second = source.alloc();
        verify(first != nullptr && second != nullptr);
        *first = 42;
        *second = 99;

        // A pool hands out addresses, so a move must not relocate what it already handed out.
        pool<int> constructed(std::move(source));
        verify(*first == 42);
        verify(*second == 99);
        verify(constructed.capacity() == 5u);

        pool<int> assigned;
        assigned = std::move(constructed);
        verify(*first == 42);
        verify(*second == 99);
        verify(assigned.capacity() == 5u);
    }
}

void test_containers_safety() {
    announce("a_pool_refuses_rather_than_overruns");
    pool<int> slots;
    verify(slots.reserve(5));
    int* taken[5];
    for (std::size_t index = 0; index != 5; ++index) {
        taken[index] = slots.alloc();
        verify(taken[index] != nullptr);
    }
    // The sixth request must say so rather than hand back a slot already in use.
    verify(slots.alloc() == nullptr);

    slots.release(taken[2]);
    verify(slots.alloc() != nullptr);
    verify(slots.alloc() == nullptr);
}

#pragma endregion Containers

void test_outcomes_unit() {
    ucall_outcome_t outcome {ucall_status_deferred_k, "deferred"};
    verify(ucall_outcome_status(&outcome) == ucall_status_deferred_k);
    int output = 0;
    std::thread producer([&] {
        output = 42;
        outcome.message = nullptr;
        std::atomic_ref<ucall_status_t> word {outcome.status};
        word.store(ucall_status_success_k, std::memory_order_release);
        word.notify_all();
    });
    verify(ucall_outcome_wait(&outcome) == ucall_status_success_k);
    verify(output == 42 && outcome.message == nullptr);
    producer.join();
}

int main() {
    install_test_signal_handlers();
    fmt::print("Hi, dear tester! You look nice today!\n");
    configure_tests();

    run_test("test_utilities_unit", test_utilities_unit);
    run_test("test_traffic_stats_unit", test_traffic_stats_unit);
    run_test("test_pool_unit", test_pool_unit);
    run_test("test_memory_map_unit", test_memory_map_unit);
    run_test("test_containers_moves_unit", test_containers_moves_unit);
    run_test("test_containers_safety", test_containers_safety);
    run_test("test_outcomes_unit", test_outcomes_unit);

    fmt::print("All tests passed.\n");
    return 0;
}
