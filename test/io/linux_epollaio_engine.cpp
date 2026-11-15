/**
 *  @file test/io/linux_epollaio_engine.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The epoll and Linux AIO engine under every admitted CPU class: the shared engine cases,
 *      AIO reads and zero-copy sends.
 */
#include "ucall/io/linux_epollaio_engine.hpp" // `linux_epollaio_engine_t`

#include "io/engines.hpp" // `check_engine`, `test_engine_duplex`, `direct_files_t`

namespace unum::ucall::test::io {

/** Linux AIO reads land asynchronously; a cancel in flight completes once the kernel answered;
 *  one AIO event serializes several reads without losing any; and a host refusing AIO refuses the
 *  engine, naming the setting to raise. */
template <typename engine_type_>
static std::size_t test_epollaio_reads() {
    direct_files_t files;
    if (!files.directory.ready()) { return report("test_epollaio_reads", "the directory serves no unbuffered reads"); }
    std::size_t failures = 0;
    require(failures, files.fill());
    std::size_t const alignment = files.directory.alignment;
    int const file = ::open(files.directory.name("data.bin").c_str(), O_RDONLY | O_DIRECT | O_CLOEXEC);
    require(failures, file >= 0);
    loopback_pair_t sockets = loopback_pair();
    require(failures, sockets.connected());
    auto const deadline = uc::utilities::deadline_after(5000000);

    {
        engine_type_ engine;
        engine.files.depth = 0;
        failures += expect(engine.open(4, 4) == ucall_status_unsupported_k && engine.refusal &&
                           std::strstr(engine.refusal, "fs.aio-max-nr"));
    }

    engine_type_ engine;
    engine.files.depth = 1;
    ucall_status_t const opened = engine.open(8, 8);
    if (opened == ucall_status_unsupported_k) {
        ::close(file);
        return report("test_epollaio_reads", "the kernel lacks Linux AIO");
    }
    require(failures, opened == ucall_status_success_k && engine.files.depth == 1);
    std::array<aligned_bytes_t, 4> windows {aligned_bytes_t {alignment}, aligned_bytes_t {alignment},
                                            aligned_bytes_t {alignment}, aligned_bytes_t {alignment}};
    std::array<io_request_t, 4> reads {};
    for (std::size_t i = 0; i != reads.size(); ++i) {
        reads[i] = {.operation = io_operation_t::file_read_k,
                    .descriptor = sockets.client,
                    .data = windows[i].data,
                    .length = alignment,
                    .file = {(2 * i + 1) * alignment, file}};
        engine.submit(reads[i]);
    }
    std::size_t landed = 0;
    while (landed != reads.size() && uc::utilities::monotonic_ns() < deadline) {
        io_completion_t completed[4] {};
        int const count = engine.poll(completed, io_wait_t::blocking_k, deadline);
        require(failures, count >= 0, "polling ended with {}", count);
        for (int i = 0; i != count; ++i) {
            auto const index = static_cast<std::size_t>(completed[i].request - reads.data());
            failures += expect(
                index < reads.size() && completed[i].result == static_cast<uc::descriptor_t>(alignment) &&
                    std::memcmp(windows[index].data, files.content.data() + (2 * index + 1) * alignment, alignment) ==
                        0,
                "read {} ended with {}", index, completed[i].result);
            ++landed;
        }
    }
    failures += expect(landed == reads.size() && engine.statistics.file_reads_asynchronous == reads.size() &&
                           !engine.statistics.file_reads_blocking,
                       "{} of {} reads landed", landed, reads.size());

    aligned_bytes_t large {32 * alignment};
    reads[0] = {.operation = io_operation_t::file_read_k,
                .descriptor = sockets.client,
                .data = large.data,
                .length = large.size,
                .file = {0, file}};
    reads[1] = reads[0];
    engine.submit(reads[0]);
    engine.submit(reads[1]);
    failures += expect(engine.cancel(reads[1]) == ucall_status_success_k &&
                       engine.cancel(reads[0]) == ucall_status_success_k);
    std::array<uc::descriptor_t, 2> cancelled {0, 0};
    for (std::size_t count = 0; count != cancelled.size() && uc::utilities::monotonic_ns() < deadline;) {
        io_completion_t completed[2] {};
        int const polled = engine.poll(completed, io_wait_t::blocking_k, deadline);
        require(failures, polled >= 0, "polling ended with {}", polled);
        for (int i = 0; i != polled; ++i, ++count)
            cancelled[static_cast<std::size_t>(completed[i].request - reads.data())] = completed[i].result;
    }
    failures += expect(cancelled[0] == -ECANCELED && cancelled[1] == -ECANCELED, "the reads ended with {} and {}",
                       cancelled[0], cancelled[1]);
    failures += expect(await(engine, reads[0], deadline) == static_cast<uc::descriptor_t>(large.size) &&
                       std::memcmp(large.data, files.content.data(), large.size) == 0);
    ::close(file);
    return failures;
}

/** A @c MSG_ZEROCOPY send completes once the socket took its bytes, and its release only once the
 *  error queue reported it; loopback copies, so that report demotes the socket, whose next
 *  zero-copy send copies and whose next release completes at once. */
template <typename engine_type_>
static std::size_t test_epollaio_zero_copy_sends() {
    engine_type_ engine;
    ucall_status_t const opened = engine.open(8, 8);
    if (opened == ucall_status_unsupported_k)
        return report("test_epollaio_zero_copy_sends", "the kernel lacks Linux AIO");
    require(0, opened == ucall_status_success_k);
    std::size_t failures = 0;
    loopback_pair_t sockets = loopback_pair();
    require(failures, sockets.connected() && uc::utilities::nonblocking(sockets.client) == ucall_status_success_k &&
                          uc::utilities::nonblocking(sockets.peer) == ucall_status_success_k);
    aligned_bytes_t window {16384};
    for (std::size_t i = 0; i != window.size; ++i) window.data[i] = file_byte(i);
    auto const deadline = uc::utilities::deadline_after(5000000);
    std::string received;
    auto drain = [&](std::size_t expected) {
        char buffer[16384];
        while (received.size() < expected && uc::utilities::monotonic_ns() < deadline)
            if (ssize_t const length = recv(sockets.peer, buffer, sizeof(buffer), 0); length > 0)
                received.append(buffer, static_cast<std::size_t>(length));
        return received.size() == expected && std::memcmp(received.data(), window.data, received.size()) == 0;
    };

    engine.reserve_releases(1);
    io_request_t release {.operation = io_operation_t::zero_copy_release_k};
    io_request_t sending {.operation = io_operation_t::send_zero_copy_k,
                          .descriptor = sockets.client,
                          .data = window.data,
                          .length = window.size,
                          .release_request = &release};
    uc::descriptor_t const sent = await(engine, sending, deadline);
    failures += expect(sent > 0 && engine.statistics.zero_copy_sends == 1, "sending ended with {} after {} sends", sent,
                       engine.statistics.zero_copy_sends);
    engine.submit(release);
    failures += expect(engine.cancel(release) == ucall_status_success_k);
    failures += expect(finish(engine, release, deadline) == 0 && engine.statistics.zero_copy_fallbacks == 1,
                       "the release completed with {} fallbacks counted", engine.statistics.zero_copy_fallbacks);
    failures += expect(drain(static_cast<std::size_t>(sent)));

    received.clear();
    uc::descriptor_t const copied = await(engine, sending, deadline);
    failures += expect(copied > 0 && engine.statistics.zero_copy_sends == 1);
    failures += expect(await(engine, release, deadline) == 0);
    failures += expect(drain(static_cast<std::size_t>(copied)));
    failures += expect(engine.close_socket(std::exchange(sockets.client, -1)) == 0);
    return failures;
}

std::size_t check_linux_epollaio_engine(settings_t const& settings) {
    return check_engine<linux_epollaio_engine_t>(ucall_io_backend_linux_epollaio_k, settings,
                                                 []<typename engine_type_>(random_generator_t& generator) {
                                                     std::size_t failures = test_engine_duplex<engine_type_>(generator);
                                                     failures += test_accept_batch<engine_type_>();
                                                     failures += test_direct_files<engine_type_>();
                                                     failures += test_epollaio_reads<engine_type_>();
                                                     failures += test_epollaio_zero_copy_sends<engine_type_>();
                                                     return failures;
                                                 });
}

} // namespace unum::ucall::test::io
