/**
 *  @brief Tests for the utility types and containers in @c shared.hpp.
 *  @file scripts/test_shared.cpp
 *  @author Ash Vardanian
 *
 *  These stand in for their standard-library counterparts because they report an allocation
 *  failure rather than throwing, so every case that grows one checks the answer.
 */
#include <cstring> // `std::strstr`

#include <thread>  // `std::thread`
#include <utility> // `std::move`

#include "test.hpp" // `verify`, `run_test`, `scale_iterations`

using namespace unum::ucall;
using namespace unum::ucall::scripts;

#pragma region Utilities

/** @brief Whether two floats agree closely enough for a magnitude meant to be read by a human. */
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

    announce("cpu_cycle");
    // A counter that never advances would silently freeze every idle timer built on it.
    timestamp_t const before = cpu_cycle();
    volatile std::size_t sum = 0;
    for (std::size_t index = 0; index != 1000; ++index) sum = sum + index;
    timestamp_t const after = cpu_cycle();
    verify(after >= before);

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

#pragma region Views

void test_span_unit() {
    announce("construction_and_access");
    int values[] = {10, 20, 30, 40, 50};
    span<int> const viewed_values(values, values + 5);
    verify(viewed_values.size() == 5u);
    verify(viewed_values.data() == values);
    verify(viewed_values[0] == 10);
    verify(viewed_values[4] == 50);

    announce("iteration");
    int sum = 0;
    for (int const value : viewed_values) sum += value;
    verify(sum == 150);

    announce("string_view_conversion");
    char characters[] = "hello";
    span<char> const viewed_characters(characters, characters + 5);
    std::string_view const as_text = viewed_characters;
    verify(as_text == "hello");

    announce("an_empty_span_is_default_constructible");
    span<int> const empty;
    verify(empty.size() == 0u);
}

#pragma endregion Views

#pragma region Containers

void test_round_robin_unit() {
    announce("allocation_and_push");
    round_robin<int> ring;
    verify(ring.alloc(5));
    verify(ring.capacity() == 5u);
    verify(ring.size() == 0u);

    ring.push_ahead() = 100;
    verify(ring.size() == 1u);
    verify(ring.head() == 100);
    verify(ring.tail() == 100);

    ring.push_ahead() = 200;
    ring.push_ahead() = 300;
    verify(ring.size() == 3u);
    verify(ring.head() == 300);
    verify(ring.tail() == 100);

    announce("dropping_advances_the_tail");
    verify(ring.tail() == 100);
    ring.drop_tail();
    verify(ring.size() == 2u);
    verify(ring.tail() == 200);

    announce("polling_cycles");
    round_robin<int> polled;
    verify(polled.alloc(5));
    polled.push_ahead() = 1;
    polled.push_ahead() = 2;
    polled.push_ahead() = 3;
    verify(polled.poll() == 1);
    verify(polled.poll() == 2);
    verify(polled.poll() == 3);
    verify(polled.poll() == 1);
}

void test_buffer_unit() {
    announce("initial_state");
    buffer<int> values;
    verify(values.size() == 0u);
    verify(values.capacity() == 0u);

    announce("reallocate_allocates");
    verify(values.reallocate(10));
    verify(values.size() == 10u);
    verify(values.capacity() == 10u);
    verify(values.data() != nullptr);

    announce("element_access_and_iteration");
    verify(values.reallocate(5));
    int next = 0;
    for (int &element : values) element = next++;
    verify(values[0] == 0);
    verify(values[4] == 4);

    announce("reallocate_replaces_rather_than_grows");
    values[0] = 99;
    verify(values.reallocate(10));
    verify(values.capacity() == 10u);
    // A resize is a fresh mapping rather than a copy, which is why callers reach for `array`
    // when they need to grow.
}

void test_array_unit() {
    announce("initial_state_and_reserve");
    array<int> values;
    verify(values.size() == 0u);
    verify(values.capacity() == 0u);
    verify(values.reserve(10));
    verify(values.capacity() == 10u);
    verify(values.size() == 0u);

    announce("push_back_and_index");
    values.push_back_reserved(10);
    values.push_back_reserved(20);
    values.push_back_reserved(30);
    verify(values.size() == 3u);
    verify(values[0] == 10);
    verify(values[1] == 20);
    verify(values[2] == 30);

    announce("pop_back_takes_a_count");
    values.pop_back();
    verify(values.size() == 2u);
    values.pop_back(2);
    verify(values.size() == 0u);

    announce("append_n");
    int const appended[] = {5, 6, 7, 8, 9};
    verify(values.append_n(appended, 5));
    verify(values.size() == 5u);
    verify(values[0] == 5);
    verify(values[4] == 9);
    // Appending nothing is not a copy of length zero, so it must succeed without touching memory.
    verify(values.append_n(nullptr, 0));
    verify(values.size() == 5u);

    announce("reserve_grows_and_never_shrinks");
    verify(values.reserve(20));
    verify(values.capacity() == 20u);
    verify(values.size() == 5u);
    verify(values[0] == 5);
    verify(values.reserve(2));
    verify(values.capacity() == 20u);

    announce("iteration_covers_the_count_not_the_capacity");
    int sum = 0;
    for (int const value : values) sum += value;
    verify(sum == 35);

    announce("reset_releases_everything");
    values.reset();
    verify(values.size() == 0u);
    verify(values.capacity() == 0u);
}

void test_pool_unit() {
    announce("allocation_hands_out_distinct_slots");
    pool<int> slots;
    verify(slots.reserve(5));
    verify(slots.capacity() == 5u);

    int *const first = slots.alloc();
    int *const second = slots.alloc();
    verify(first != nullptr);
    verify(second != nullptr);
    verify(first != second);

    announce("a_released_slot_is_handed_out_again");
    *first = 42;
    slots.release(first);
    int *const reused = slots.alloc();
    verify(reused != nullptr);

    announce("offsets_round_trip");
    std::size_t const offset = slots.offset_of(*second);
    verify(offset < 5u);
    verify(&slots.at_offset(offset) == second);
}

void test_memory_map_unit() {
    announce("remap_allocates_and_reports_its_size");
    memory_map_t mapping;
    verify(mapping.remap(ram_page_size_k));
    verify(mapping.data() != nullptr);
    verify(mapping.size() == ram_page_size_k);

    announce("pages_arrive_zeroed");
    // A mapping that arrived dirty would hand a connection whatever the last one left behind.
    verify(all_zero({mapping.data(), mapping.data() + mapping.size()}));

    announce("remapping_replaces_the_old_mapping");
    verify(mapping.remap(ram_page_size_k * 2));
    verify(mapping.data() != nullptr);
    verify(mapping.size() == ram_page_size_k * 2);

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
        announce("round_robin");
        round_robin<int> source;
        verify(source.alloc(5));
        source.push_ahead() = 42;
        source.push_ahead() = 99;

        round_robin<int> constructed(std::move(source));
        verify(constructed.size() == 2u);
        verify(constructed.capacity() == 5u);
        verify(constructed.tail() == 42);

        round_robin<int> assigned;
        assigned = std::move(constructed);
        verify(assigned.size() == 2u);
        verify(assigned.capacity() == 5u);
        verify(assigned.tail() == 42);
    }
    {
        announce("buffer");
        buffer<int> source;
        verify(source.reallocate(5));
        source[0] = 42;
        source[1] = 99;

        buffer<int> constructed(std::move(source));
        verify(constructed.capacity() == 5u);
        verify(constructed[0] == 42);
        verify(constructed[1] == 99);
        verify(source.data() == nullptr);

        buffer<int> assigned;
        assigned = std::move(constructed);
        verify(assigned.capacity() == 5u);
        verify(assigned[0] == 42);
        verify(constructed.data() == nullptr);
    }
    {
        announce("array");
        array<int> source;
        verify(source.reserve(5));
        source.push_back_reserved(42);
        source.push_back_reserved(99);
        source.push_back_reserved(123);

        array<int> constructed(std::move(source));
        verify(constructed.size() == 3u);
        verify(constructed.capacity() == 5u);
        verify(constructed[0] == 42);
        verify(constructed[2] == 123);
        verify(source.data() == nullptr);

        array<int> assigned;
        assigned = std::move(constructed);
        verify(assigned.size() == 3u);
        verify(assigned[0] == 42);
        verify(constructed.data() == nullptr);
    }
    {
        announce("pool");
        pool<int> source;
        verify(source.reserve(5));
        int *const first = source.alloc();
        int *const second = source.alloc();
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
    int *taken[5];
    for (std::size_t index = 0; index != 5; ++index) {
        taken[index] = slots.alloc();
        verify(taken[index] != nullptr);
    }
    // The sixth request must say so rather than hand back a slot already in use.
    verify(slots.alloc() == nullptr);

    slots.release(taken[2]);
    verify(slots.alloc() != nullptr);
    verify(slots.alloc() == nullptr);

    announce("a_ring_reuses_the_slots_it_dropped");
    round_robin<int> ring;
    verify(ring.alloc(5));
    for (int value = 0; value != 5; ++value) ring.push_ahead() = value;
    verify(ring.size() == 5u);
    ring.drop_tail();
    ring.drop_tail();
    verify(ring.size() == 3u);
    // Pushing past the physical end of the storage has to land on the slots just freed.
    ring.push_ahead() = 100;
    ring.push_ahead() = 101;
    verify(ring.size() == 5u);
    verify(ring.head() == 101);
    verify(ring.tail() == 2);
}

#pragma endregion Containers

#pragma region Concurrency

/** @brief Two threads incrementing behind one lock, which is the only thing the mutex promises. */
void test_mutex_stress() {
    mutex_t guard;
    std::size_t counter = 0;
    std::size_t const increments = scale_iterations(100'000);
    announce("{} increments on each of two threads", increments);

    auto worker = [&]() noexcept {
        for (std::size_t index = 0; index != increments; ++index) {
            guard.lock();
            ++counter;
            guard.unlock();
        }
    };

    std::thread first(worker);
    std::thread second(worker);
    first.join();
    second.join();

    verify(counter == increments * 2, "counted {}, expected {} across two threads", counter, increments * 2);
}

#pragma endregion Concurrency

int main() {
    install_test_signal_handlers();
    fmt::print("Hi, dear tester! You look nice today!\n");
    configure_tests();

    run_test("test_utilities_unit", test_utilities_unit);
    run_test("test_traffic_stats_unit", test_traffic_stats_unit);
    run_test("test_span_unit", test_span_unit);
    run_test("test_round_robin_unit", test_round_robin_unit);
    run_test("test_buffer_unit", test_buffer_unit);
    run_test("test_array_unit", test_array_unit);
    run_test("test_pool_unit", test_pool_unit);
    run_test("test_memory_map_unit", test_memory_map_unit);
    run_test("test_containers_moves_unit", test_containers_moves_unit);
    run_test("test_containers_safety", test_containers_safety);
    run_test("test_mutex_stress", test_mutex_stress);

    fmt::print("All tests passed.\n");
    return 0;
}
