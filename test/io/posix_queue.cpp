/**
 *  @file test/io/posix_queue.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The portable queue under every admitted CPU class, and the composition of every queue's
 *      cells this build compiled.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build

#include <unordered_map> // `std::unordered_map`

#include "ucall/io/polled_file_reads.hpp" // `polled_file_reads`
#include "ucall/io/posix_queue.hpp"       // `posix_queue_t`

#include "io/queues.hpp" // `run_queue_cases`, `test_queue_duplex`, `test_accept_batch`, `test_direct_files`

namespace unum::ucall::test::io {

void run_posix_queue_cases() {
#if UCALL_WITH_POSIX
    run_queue_cases<posix_queue_t>(ucall_io_backend_posix_k, []<typename queue_type_>(sz::string_t const& label) {
        run_test_case(called("test_queue_cell", label).c_str(), [] {
            return keeping_descriptors([] {
                split_mix_generator_t generator {case_stream_key()};
                test_queue_duplex<queue_type_>(generator);
                test_accept_batch<queue_type_>();
            });
        });
        run_cell_case(label, "test_direct_files", test_direct_files<queue_type_>);
    });
#else
    run_test_case("run_posix_queue_cases", [] { return case_result_t::skipped("built without UCALL_WITH_POSIX"); });
#endif
}

/** Reads a file through polled AIO as macOS kqueue does: a single read, a vectored read spanning
 *  several batches, a short read at the end, a read with no pool room left reading blocking, a
 *  failing descriptor, and a stop draining what still flies. */
void test_polled_file_reads() {
    scratch_directory_t scratch;
    std::string content(3 << 20, '\0');
    for (std::size_t i = 0; i != content.size(); ++i) content[i] = static_cast<char>(file_byte(i));
    if (!expect_true(scratch.ready() && scratch.write("data.bin", content))) return;
    int const file = ::open(scratch.name("data.bin").c_str(), O_RDONLY | O_CLOEXEC);
    if (!expect_true(file >= 0)) return;
    polled_file_reads<> reads;
    if (!expect_true(reads.reserve(8) == ucall_status_success_k)) return;
    std::unordered_map<unsigned, descriptor_t> landed;
    auto settle = [&](unsigned owner, descriptor_t result) { landed[owner] = result; };
    auto await_all = [&] {
        for (auto const deadline = util::deadline_after(5000000); reads.in_flight();) {
            reads.reap(settle);
            if (monotonic_ns() > deadline) break;
        }
    };

    std::size_t const single_bytes = 65536;
    std::string single(single_bytes, '\0');
    io_vector_t single_vector {single.data(), single_bytes};
    descriptor_t result = -1;
    if (!reads.start(0, file, {&single_vector, 1}, 4096, result)) landed[0] = result;
    std::string scattered(40 * 1000, '\0');
    io_vector_t vectors[40];
    for (std::size_t i = 0; i != 40; ++i) vectors[i] = {scattered.data() + i * 1000, 1000};
    // Forty vectors outgrow the seven idle blocks, so this one reads blocking at once.
    bool const blocking = !reads.start(1, file, {vectors, 40}, 777, result);
    if (blocking) landed[1] = result;
    await_all();
    expect_true(landed.count(0) && landed[0] == 65536 && single == content.substr(4096, 65536),
                "the single read landed {}", landed.count(0) ? landed[0] : -1);
    expect_true(blocking && landed[1] == 40000 && scattered == content.substr(777, 40000),
                "the oversized vectored read landed {}", landed[1]);

    // Seven vectors fit, spanning batches wherever the batch limit is under seven.
    landed.clear();
    std::fill(scattered.begin(), scattered.end(), '\0');
    bool const flew = reads.start(2, file, {vectors, 7}, content.size() - 6500, result);
    if (!flew) landed[2] = result;
    await_all();
    expect_true(
        landed.count(2) && landed[2] == 6500 && scattered.substr(0, 6500) == content.substr(content.size() - 6500),
        "the short vectored read landed {}", landed.count(2) ? landed[2] : -1);
    expect_true(reads.free_blocks.size() == 8, "{} blocks came back of 8", reads.free_blocks.size());

    landed.clear();
    if (!reads.start(3, -1, {&single_vector, 1}, 0, result)) landed[3] = result;
    await_all();
    expect_true(landed.count(3) && landed[3] < 0, "a bad descriptor landed {}", landed.count(3) ? landed[3] : 0);

    landed.clear();
    if (!reads.start(4, file, {&single_vector, 1}, 0, result)) landed[4] = result;
    reads.drain(settle);
    expect_true(!reads.in_flight() && landed.count(4) && landed[4] == 65536, "the drain left reads flying");
    ::close(file);
}

void run_io_cases() {
    run_posix_queue_cases();
    run_test_case("test_polled_file_reads", test_polled_file_reads);
#if UCALL_WITH_LINUX_EPOLLAIO
    run_linux_epollaio_queue_cases();
#endif
#if UCALL_WITH_LINUX_URING
    run_linux_uring612_queue_cases();
    run_linux_uring618_queue_cases();
#endif
#if UCALL_WITH_BSD_KQUEUE
    run_bsd_kqueue_queue_cases();
#endif
}

} // namespace unum::ucall::test::io
