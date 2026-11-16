/**
 *  @file test/io/posix_engine.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The portable engine under every admitted CPU class, and the composition of every engine's
 *      cells this build compiled.
 */
#include <unordered_map> // `std::unordered_map`

#include "ucall/io/polled_file_reads.hpp" // `polled_file_reads`
#include "ucall/io/posix_engine.hpp"      // `posix_engine_t`

#include "io/engines.hpp" // `check_engine`, `test_engine_duplex`, `test_accept_batch`, `test_direct_files`

namespace unum::ucall::test::io {

std::size_t check_posix_engine(settings_t const& settings) {
#if UCALL_WITH_POSIX
    return check_engine<posix_engine_t>(ucall_io_backend_posix_k, settings,
                                        []<typename engine_type_>(random_generator_t& generator) {
                                            std::size_t failures = test_engine_duplex<engine_type_>(generator);
                                            failures += test_accept_batch<engine_type_>();
                                            failures += test_direct_files<engine_type_>();
                                            return failures;
                                        });
#else
    return settings.filter.selects("io posix") ? report("io posix", "built without UCALL_WITH_POSIX") : 0;
#endif
}

/** Reads a file through polled AIO as macOS kqueue does: a single read, a vectored read spanning
 *  several batches, a short read at the end, a read with no pool room left reading blocking, a
 *  failing descriptor, and a stop draining what still flies. */
std::size_t test_polled_file_reads() {
    scratch_directory_t scratch;
    std::string content(3 << 20, '\0');
    for (std::size_t i = 0; i != content.size(); ++i) content[i] = static_cast<char>(file_byte(i));
    require(0, scratch.ready() && scratch.write("data.bin", content));
    int const file = ::open(scratch.name("data.bin").c_str(), O_RDONLY | O_CLOEXEC);
    require(0, file >= 0);
    polled_file_reads<> reads;
    require(0, reads.reserve(8) == ucall_status_success_k);
    std::size_t failures = 0;
    std::unordered_map<unsigned, uc::descriptor_t> landed;
    auto settle = [&](unsigned owner, uc::descriptor_t result) { landed[owner] = result; };
    auto await_all = [&] {
        for (auto const deadline = uc::utilities::deadline_after(5000000); reads.in_flight();) {
            reads.reap(settle);
            if (monotonic_ns() > deadline) break;
        }
    };

    std::size_t const single_bytes = 65536;
    std::string single(single_bytes, '\0');
    io_vector_t single_vector {single.data(), single_bytes};
    uc::descriptor_t result = -1;
    if (!reads.start(0, file, {&single_vector, 1}, 4096, result)) landed[0] = result;
    std::string scattered(40 * 1000, '\0');
    io_vector_t vectors[40];
    for (std::size_t i = 0; i != 40; ++i) vectors[i] = {scattered.data() + i * 1000, 1000};
    // Forty vectors outgrow the seven idle blocks, so this one reads blocking at once.
    bool const blocking = !reads.start(1, file, {vectors, 40}, 777, result);
    if (blocking) landed[1] = result;
    await_all();
    failures += expect(landed.count(0) && landed[0] == 65536 && single == content.substr(4096, 65536),
                       "the single read landed {}", landed.count(0) ? landed[0] : -1);
    failures += expect(blocking && landed[1] == 40000 && scattered == content.substr(777, 40000),
                       "the oversized vectored read landed {}", landed[1]);

    // Seven vectors fit, spanning batches wherever the batch limit is under seven.
    landed.clear();
    std::fill(scattered.begin(), scattered.end(), '\0');
    bool const flew = reads.start(2, file, {vectors, 7}, content.size() - 6500, result);
    if (!flew) landed[2] = result;
    await_all();
    failures += expect(
        landed.count(2) && landed[2] == 6500 && scattered.substr(0, 6500) == content.substr(content.size() - 6500),
        "the short vectored read landed {}", landed.count(2) ? landed[2] : -1);
    failures += expect(reads.free_blocks.size() == 8, "{} blocks came back of 8", reads.free_blocks.size());

    landed.clear();
    if (!reads.start(3, -1, {&single_vector, 1}, 0, result)) landed[3] = result;
    await_all();
    failures += expect(landed.count(3) && landed[3] < 0, "a bad descriptor landed {}", landed.count(3) ? landed[3] : 0);

    landed.clear();
    if (!reads.start(4, file, {&single_vector, 1}, 0, result)) landed[4] = result;
    reads.drain(settle);
    failures += expect(!reads.in_flight() && landed.count(4) && landed[4] == 65536, "the drain left reads flying");
    ::close(file);
    return failures;
}

std::size_t check_io(settings_t const& settings) {
    std::size_t failures_count = check_posix_engine(settings);
    if (settings.filter.selects("io polled-reads"))
        failures_count += report("io polled-reads", test_polled_file_reads());
#if UCALL_WITH_LINUX_EPOLLAIO
    failures_count += check_linux_epollaio_engine(settings);
#endif
#if UCALL_WITH_LINUX_URING
    failures_count += check_linux_uring612_engine(settings);
    failures_count += check_linux_uring618_engine(settings);
#endif
#if UCALL_WITH_BSD_KQUEUE
    failures_count += check_bsd_kqueue_engine(settings);
#endif
    return failures_count;
}

} // namespace unum::ucall::test::io
