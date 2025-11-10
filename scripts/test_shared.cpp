/**
 *  @brief Unit tests for shared utility containers and functions.
 *
 *  Tests the container classes and utility functions in shared.hpp for correctness,
 *  edge cases, and error handling. Uses GoogleTest framework.
 *
 *  Compilation:
 *  @code{.sh}
 *  g++ -std=c++20 -O2 -I./include -I./src \
 *      -I/opt/homebrew/opt/googletest/include \
 *      -L/opt/homebrew/opt/googletest/lib \
 *      -lgtest -lgtest_main -pthread \
 *      scripts/test_shared.cpp -o test_shared
 *  @endcode
 *
 *  @file test_shared.cpp
 *  @author Ash Vardanian
 *  @date November 10, 2025
 */
#include <gtest/gtest.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <thread>

#include "shared.hpp"

using namespace unum::ucall;

#pragma region Utility Function Tests

TEST(UtilityFunctions, StringLength) {
    // Normal cases
    EXPECT_EQ(string_length("hello", 0), 5);
    EXPECT_EQ(string_length("hello", 5), 5);
    EXPECT_EQ(string_length("test", 4), 4);

    // Null pointer handling
    EXPECT_EQ(string_length(nullptr, 0), 0);
    EXPECT_EQ(string_length(nullptr, 10), 0);

    // Empty string
    EXPECT_EQ(string_length("", 0), 0);
    EXPECT_EQ(string_length("", 5), 5); // Trusts provided length
}

TEST(UtilityFunctions, CpuCycle) {
    // Basic test - just ensure it returns something and increments
    auto t1 = cpu_cycle();
    // Do some work to ensure cycles pass
    volatile int sum = 0;
    for (int i = 0; i < 100; i++) {
        sum += i;
    }
    auto t2 = cpu_cycle();
    EXPECT_GE(t2, t1); // Use >= since in rare cases they might be equal
}

TEST(UtilityFunctions, Printable) {
    auto result = printable(500);
    EXPECT_FLOAT_EQ(result.number, 500.0f);
    EXPECT_EQ(result.suffix, ' ');

    result = printable(1'500);
    EXPECT_FLOAT_EQ(result.number, 1.5f);
    EXPECT_EQ(result.suffix, 'K');

    result = printable(2'500'000);
    EXPECT_FLOAT_EQ(result.number, 2.5f);
    EXPECT_EQ(result.suffix, 'M');

    result = printable(3'500'000'000);
    EXPECT_FLOAT_EQ(result.number, 3.5f);
    EXPECT_EQ(result.suffix, 'G');
}

#pragma endregion Utility Function Tests

#pragma region Round Robin Tests

class RoundRobinTest : public ::testing::Test {
  protected:
    round_robin<int> rr;

    void SetUp() override {
        ASSERT_TRUE(rr.alloc(5)) << "Failed to allocate round_robin";
    }
};

TEST_F(RoundRobinTest, BasicAllocation) {
    EXPECT_EQ(rr.capacity(), 5);
    EXPECT_EQ(rr.size(), 0);
}

TEST_F(RoundRobinTest, PushAndSize) {
    EXPECT_EQ(rr.size(), 0);

    rr.push_ahead() = 1;
    EXPECT_EQ(rr.size(), 1);

    rr.push_ahead() = 2;
    EXPECT_EQ(rr.size(), 2);
}

TEST_F(RoundRobinTest, PushAndDrop) {
    rr.push_ahead() = 10;
    rr.push_ahead() = 20;
    rr.push_ahead() = 30;
    EXPECT_EQ(rr.size(), 3);

    EXPECT_EQ(rr.tail(), 10);
    rr.drop_tail();
    EXPECT_EQ(rr.size(), 2);

    EXPECT_EQ(rr.tail(), 20);
}

TEST_F(RoundRobinTest, HeadAndTail) {
    rr.push_ahead() = 100;
    EXPECT_EQ(rr.head(), 100);
    EXPECT_EQ(rr.tail(), 100);

    rr.push_ahead() = 200;
    EXPECT_EQ(rr.head(), 200);
    EXPECT_EQ(rr.tail(), 100);

    rr.push_ahead() = 300;
    EXPECT_EQ(rr.head(), 300);
    EXPECT_EQ(rr.tail(), 100);
}

TEST_F(RoundRobinTest, PollingBehavior) {
    // Add elements
    rr.push_ahead() = 1;
    rr.push_ahead() = 2;
    rr.push_ahead() = 3;

    // Poll should return elements in order and cycle
    EXPECT_EQ(rr.poll(), 1);
    EXPECT_EQ(rr.poll(), 2);
    EXPECT_EQ(rr.poll(), 3);
    EXPECT_EQ(rr.poll(), 1); // Should cycle back
}

TEST_F(RoundRobinTest, CircularWrapAround) {
    // Fill the buffer
    for (int i = 0; i < 5; i++) {
        rr.push_ahead() = i;
    }
    EXPECT_EQ(rr.size(), 5);

    // Drop and add to cause wrap-around
    rr.drop_tail();
    rr.drop_tail();
    EXPECT_EQ(rr.size(), 3);

    rr.push_ahead() = 100;
    rr.push_ahead() = 101;
    EXPECT_EQ(rr.size(), 5);
}

TEST_F(RoundRobinTest, CallerResponsibleForBounds) {
    // These methods are "unsafe" - caller must check size/capacity
    // Fill to capacity
    for (int i = 0; i < 5; i++) {
        rr.push_ahead() = i;
    }
    EXPECT_EQ(rr.size(), 5);

    // Caller should not push when full or drop when empty
    // (No overflow/underflow protection - undefined behavior if violated)
}

TEST_F(RoundRobinTest, MoveConstructor) {
    rr.push_ahead() = 42;
    rr.push_ahead() = 99;

    round_robin<int> rr2(std::move(rr));

    EXPECT_EQ(rr2.size(), 2);
    EXPECT_EQ(rr2.capacity(), 5);
    EXPECT_EQ(rr2.tail(), 42);
}

TEST_F(RoundRobinTest, MoveAssignment) {
    rr.push_ahead() = 42;

    round_robin<int> rr2;
    rr2 = std::move(rr);

    EXPECT_EQ(rr2.size(), 1);
    EXPECT_EQ(rr2.capacity(), 5);
}

#pragma endregion Round Robin Tests

#pragma region Mutex Tests

TEST(MutexTest, BasicLockUnlock) {
    mutex_t mtx;
    mtx.lock();
    mtx.unlock();
    // If we get here without hanging, basic functionality works
}

TEST(MutexTest, MultithreadedAccess) {
    mutex_t mtx;
    int counter = 0;
    constexpr int iterations = 1000;

    auto worker = [&]() {
        for (int i = 0; i < iterations; i++) {
            mtx.lock();
            counter++;
            mtx.unlock();
        }
    };

    std::thread t1(worker);
    std::thread t2(worker);

    t1.join();
    t2.join();

    EXPECT_EQ(counter, iterations * 2);
}

#pragma endregion Mutex Tests

#pragma region Memory Map Tests

TEST(MemoryMapTest, BasicRemap) {
    memory_map_t mmap;
    EXPECT_TRUE(mmap.remap(4096));
    EXPECT_NE(mmap.data(), nullptr);
    EXPECT_EQ(mmap.size(), 4096);
}

TEST(MemoryMapTest, MultipleRemaps) {
    memory_map_t mmap;
    EXPECT_TRUE(mmap.remap(4096));
    auto ptr1 = mmap.data();

    // Remap destroys old mapping and creates new one
    EXPECT_TRUE(mmap.remap(8192));
    EXPECT_NE(mmap.data(), nullptr);
    EXPECT_EQ(mmap.size(), 8192);
}

TEST(MemoryMapTest, ZeroInitialized) {
    memory_map_t mmap;
    EXPECT_TRUE(mmap.remap(1024));

    // Check that memory is zero-initialized
    bool all_zero = true;
    for (std::size_t i = 0; i < mmap.size(); i++) {
        if (mmap.data()[i] != 0) {
            all_zero = false;
            break;
        }
    }
    EXPECT_TRUE(all_zero);
}

TEST(MemoryMapTest, MoveSemantics) {
    memory_map_t mmap1;
    EXPECT_TRUE(mmap1.remap(4096));
    auto ptr = mmap1.data();

    memory_map_t mmap2 = std::move(mmap1);
    EXPECT_EQ(mmap2.data(), ptr);
    EXPECT_EQ(mmap2.size(), 4096);
}

TEST(MemoryMapTest, ResetCleanup) {
    memory_map_t mmap;
    EXPECT_TRUE(mmap.remap(4096));
    EXPECT_NE(mmap.data(), nullptr);

    mmap.reset();
    EXPECT_EQ(mmap.data(), nullptr);
    EXPECT_EQ(mmap.size(), 0);
}

#pragma endregion Memory Map Tests

#pragma region Buffer Tests

class BufferTest : public ::testing::Test {
  protected:
    buffer<int> buf;
};

TEST_F(BufferTest, InitialState) {
    EXPECT_EQ(buf.size(), 0);
    EXPECT_EQ(buf.capacity(), 0);
}

TEST_F(BufferTest, BasicResize) {
    EXPECT_TRUE(buf.resize(10));
    EXPECT_EQ(buf.size(), 10);
    EXPECT_EQ(buf.capacity(), 10);
    EXPECT_NE(buf.data(), nullptr);
}

TEST_F(BufferTest, ElementAccess) {
    ASSERT_TRUE(buf.resize(5));

    buf[0] = 10;
    buf[1] = 20;
    buf[4] = 50;

    EXPECT_EQ(buf[0], 10);
    EXPECT_EQ(buf[1], 20);
    EXPECT_EQ(buf[4], 50);
}

TEST_F(BufferTest, Iteration) {
    ASSERT_TRUE(buf.resize(5));

    int value = 0;
    for (auto &elem : buf) {
        elem = value++;
    }

    EXPECT_EQ(buf[0], 0);
    EXPECT_EQ(buf[4], 4);
}

TEST_F(BufferTest, ResizeReplacesOld) {
    ASSERT_TRUE(buf.resize(5));
    buf[0] = 99;

    ASSERT_TRUE(buf.resize(10));
    EXPECT_EQ(buf.capacity(), 10);
    // Old data is not preserved
}

TEST_F(BufferTest, MoveConstructor) {
    ASSERT_TRUE(buf.resize(5));
    buf[0] = 42;
    buf[1] = 99;

    buffer<int> buf2(std::move(buf));

    EXPECT_EQ(buf2.capacity(), 5);
    EXPECT_EQ(buf2[0], 42);
    EXPECT_EQ(buf2[1], 99);
}

TEST_F(BufferTest, MoveAssignment) {
    ASSERT_TRUE(buf.resize(5));
    buf[0] = 42;

    buffer<int> buf2;
    buf2 = std::move(buf);

    EXPECT_EQ(buf2.capacity(), 5);
    EXPECT_EQ(buf2[0], 42);
}

#pragma endregion Buffer Tests

#pragma region Pool Tests

class PoolTest : public ::testing::Test {
  protected:
    pool<int> p;

    void SetUp() override {
        ASSERT_TRUE(p.reserve(5));
    }
};

TEST_F(PoolTest, BasicAllocation) {
    auto *elem1 = p.alloc();
    ASSERT_NE(elem1, nullptr);

    auto *elem2 = p.alloc();
    ASSERT_NE(elem2, nullptr);
    EXPECT_NE(elem1, elem2);
}

TEST_F(PoolTest, ExhaustPool) {
    int *ptrs[5];
    for (int i = 0; i < 5; i++) {
        ptrs[i] = p.alloc();
        ASSERT_NE(ptrs[i], nullptr);
    }

    // Pool should be exhausted
    auto *extra = p.alloc();
    EXPECT_EQ(extra, nullptr);
}

TEST_F(PoolTest, ReleaseAndReuse) {
    auto *elem1 = p.alloc();
    ASSERT_NE(elem1, nullptr);
    *elem1 = 42;

    p.release(elem1);

    // Should be able to allocate again
    auto *elem2 = p.alloc();
    EXPECT_NE(elem2, nullptr);
}

// Note: ReleaseInvalidPointer, ReleaseNullPointer, and DoubleFreeProtection tests
// are removed because these conditions now trigger assertions in debug builds.
// In release builds (NDEBUG), the original runtime checks in release() would catch these.

TEST_F(PoolTest, OffsetOperations) {
    auto *elem = p.alloc();
    ASSERT_NE(elem, nullptr);

    auto offset = p.offset_of(*elem);
    EXPECT_LT(offset, 5);

    auto &retrieved = p.at_offset(offset);
    EXPECT_EQ(&retrieved, elem);
}

TEST_F(PoolTest, MoveConstructor) {
    auto *elem1 = p.alloc();
    auto *elem2 = p.alloc();
    ASSERT_NE(elem1, nullptr);
    ASSERT_NE(elem2, nullptr);
    *elem1 = 42;
    *elem2 = 99;

    pool<int> p2(std::move(p));

    EXPECT_EQ(*elem1, 42);
    EXPECT_EQ(*elem2, 99);
}

TEST_F(PoolTest, MoveAssignment) {
    auto *elem = p.alloc();
    ASSERT_NE(elem, nullptr);
    *elem = 99;

    pool<int> p2;
    p2 = std::move(p);

    // The moved pool should have the element
    EXPECT_EQ(*elem, 99);
}

#pragma endregion Pool Tests

#pragma region Span Tests

TEST(SpanTest, BasicConstruction) {
    int data[] = {1, 2, 3, 4, 5};
    span<int> s(data, data + 5);

    EXPECT_EQ(s.size(), 5);
    EXPECT_EQ(s.data(), data);
}

TEST(SpanTest, ElementAccess) {
    int data[] = {10, 20, 30};
    span<int> s(data, data + 3);

    EXPECT_EQ(s[0], 10);
    EXPECT_EQ(s[1], 20);
    EXPECT_EQ(s[2], 30);
}

TEST(SpanTest, Iteration) {
    int data[] = {1, 2, 3};
    span<int> s(data, data + 3);

    int sum = 0;
    for (auto val : s) {
        sum += val;
    }
    EXPECT_EQ(sum, 6);
}

TEST(SpanTest, StringViewConversion) {
    char data[] = "hello";
    span<char> s(data, data + 5);

    std::string_view sv = s;
    EXPECT_EQ(sv, "hello");
}

#pragma endregion Span Tests

#pragma region Array Tests

class ArrayTest : public ::testing::Test {
  protected:
    array<int> arr;
};

TEST_F(ArrayTest, InitialState) {
    EXPECT_EQ(arr.size(), 0);
    EXPECT_EQ(arr.capacity(), 0);
}

TEST_F(ArrayTest, BasicReserve) {
    EXPECT_TRUE(arr.reserve(10));
    EXPECT_EQ(arr.capacity(), 10);
    EXPECT_EQ(arr.size(), 0);
}

TEST_F(ArrayTest, PushBackReserved) {
    ASSERT_TRUE(arr.reserve(5));

    arr.push_back_reserved(10);
    arr.push_back_reserved(20);
    arr.push_back_reserved(30);

    EXPECT_EQ(arr.size(), 3);
    EXPECT_EQ(arr[0], 10);
    EXPECT_EQ(arr[1], 20);
    EXPECT_EQ(arr[2], 30);
}

TEST_F(ArrayTest, PopBack) {
    ASSERT_TRUE(arr.reserve(5));
    arr.push_back_reserved(1);
    arr.push_back_reserved(2);
    arr.push_back_reserved(3);

    EXPECT_EQ(arr.size(), 3);
    arr.pop_back();
    EXPECT_EQ(arr.size(), 2);
    arr.pop_back(2);
    EXPECT_EQ(arr.size(), 0);
}

TEST_F(ArrayTest, AppendN) {
    ASSERT_TRUE(arr.reserve(10));

    int data[] = {5, 6, 7, 8, 9};
    EXPECT_TRUE(arr.append_n(data, 5));

    EXPECT_EQ(arr.size(), 5);
    EXPECT_EQ(arr[0], 5);
    EXPECT_EQ(arr[4], 9);
}

TEST_F(ArrayTest, ReserveGrows) {
    ASSERT_TRUE(arr.reserve(5));
    arr.push_back_reserved(1);

    EXPECT_TRUE(arr.reserve(10));
    EXPECT_EQ(arr.capacity(), 10);
    EXPECT_EQ(arr.size(), 1);
    EXPECT_EQ(arr[0], 1);
}

TEST_F(ArrayTest, ReserveIdempotent) {
    ASSERT_TRUE(arr.reserve(10));
    EXPECT_TRUE(arr.reserve(5)); // Should succeed without shrinking
    EXPECT_EQ(arr.capacity(), 10);
}

TEST_F(ArrayTest, Reset) {
    ASSERT_TRUE(arr.reserve(5));
    arr.push_back_reserved(42);

    arr.reset();
    EXPECT_EQ(arr.size(), 0);
    EXPECT_EQ(arr.capacity(), 0);
}

TEST_F(ArrayTest, Iteration) {
    ASSERT_TRUE(arr.reserve(5));
    arr.push_back_reserved(1);
    arr.push_back_reserved(2);
    arr.push_back_reserved(3);

    int sum = 0;
    for (auto val : arr) {
        sum += val;
    }
    EXPECT_EQ(sum, 6);
}

TEST_F(ArrayTest, MoveConstructor) {
    ASSERT_TRUE(arr.reserve(5));
    arr.push_back_reserved(42);
    arr.push_back_reserved(99);
    arr.push_back_reserved(123);

    array<int> arr2(std::move(arr));

    EXPECT_EQ(arr2.size(), 3);
    EXPECT_EQ(arr2.capacity(), 5);
    EXPECT_EQ(arr2[0], 42);
    EXPECT_EQ(arr2[1], 99);
    EXPECT_EQ(arr2[2], 123);
}

TEST_F(ArrayTest, MoveAssignment) {
    ASSERT_TRUE(arr.reserve(5));
    arr.push_back_reserved(99);

    array<int> arr2;
    arr2 = std::move(arr);

    EXPECT_EQ(arr2.size(), 1);
    EXPECT_EQ(arr2[0], 99);
}

#pragma endregion Array Tests

#pragma region Traffic Stats Tests

TEST(TrafficStatsTest, LogHumanReadable) {
    traffic_stats_t stats;

    stats.added_connections.store(100);
    stats.bytes_sent.store(5'000'000);

    char buffer[512];
    auto len = stats.log_human_readable(buffer, sizeof(buffer), 5);

    EXPECT_GT(len, 0);
    EXPECT_LT(len, sizeof(buffer));

    // Values should be reset after logging
    EXPECT_EQ(stats.added_connections.load(), 0);
    EXPECT_EQ(stats.bytes_sent.load(), 0);
}

TEST(TrafficStatsTest, LogHumanReadableZeroSeconds) {
    traffic_stats_t stats;
    stats.packets_received.store(1000);

    char buffer[512];
    // Should not crash with zero seconds
    auto len = stats.log_human_readable(buffer, sizeof(buffer), 0);
    EXPECT_GT(len, 0);
}

TEST(TrafficStatsTest, LogJson) {
    traffic_stats_t stats;

    stats.added_connections.store(10);
    stats.closed_connections.store(5);
    stats.bytes_received.store(1024);
    stats.bytes_sent.store(2048);
    stats.packets_received.store(50);
    stats.packets_sent.store(75);

    char buffer[512];
    auto len = stats.log_json(buffer, sizeof(buffer));

    EXPECT_GT(len, 0);
    EXPECT_LT(len, sizeof(buffer));

    // Check that it looks like JSON
    std::string json(buffer, len);
    EXPECT_NE(json.find("\"add\":10"), std::string::npos);
    EXPECT_NE(json.find("\"close\":5"), std::string::npos);
}

#pragma endregion Traffic Stats Tests

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
