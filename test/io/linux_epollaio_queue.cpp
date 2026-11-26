/**
 *  @file test/io/linux_epollaio_queue.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The epoll and Linux AIO queue under every admitted CPU class: the shared queue cases,
 *      AIO reads and zero-copy sends.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build

#include "ucall/io/linux_epollaio_queue.hpp" // `linux_epollaio_queue_t`

#include "io/queues.hpp" // `run_queue_cases`, `test_queue_duplex`, `direct_files_t`

namespace unum::ucall::test::io {

/** Why an AIO case skips on a host whose kernel refuses Linux AIO. */
static constexpr char const* aio_refused_k = "ucall_io_backend_linux_epollaio_k is refused on this machine";

/** Linux AIO reads land asynchronously; a cancel in flight completes once the kernel answered;
 *  one AIO event serializes several reads without losing any; and a host refusing AIO refuses the
 *  queue, naming the setting to raise. */
template <typename queue_type_>
static case_result_t test_epollaio_reads() {
    direct_files_t files;
    if (char const* reason = files.directory.unusable()) return case_result_t::skipped(reason);
    if (!expect_true(files.fill())) return {};
    std::size_t const alignment = files.directory.alignment;
    int const file = ::open(files.directory.name("data.bin").c_str(), O_RDONLY | O_DIRECT | O_CLOEXEC);
    if (!expect_true(file >= 0)) return {};
    loopback_pair_t sockets = loopback_pair();
    if (!expect_true(sockets.connected())) return {};
    auto const deadline = util::deadline_after(5000000);

    {
        queue_type_ queue;
        queue.files.depth = 0;
        expect_true(queue.open(4, 4) == ucall_status_unsupported_k && queue.refusal &&
                    std::strstr(queue.refusal, "fs.aio-max-nr"));
    }

    queue_type_ queue;
    queue.files.depth = 1;
    ucall_status_t const opened = queue.open(8, 8);
    if (opened == ucall_status_unsupported_k) {
        ::close(file);
        return case_result_t::skipped(aio_refused_k);
    }
    if (!expect_true(opened == ucall_status_success_k && queue.files.depth == 1)) return {};
    std::array<aligned_bytes_t, 4> windows {aligned_bytes_t {alignment}, aligned_bytes_t {alignment},
                                            aligned_bytes_t {alignment}, aligned_bytes_t {alignment}};
    std::array<io_request_t, 4> reads {};
    for (std::size_t i = 0; i != reads.size(); ++i) {
        reads[i] = {.operation = io_operation_t::file_read_k,
                    .descriptor = sockets.client,
                    .data = windows[i].data,
                    .length = alignment,
                    .file = {(2 * i + 1) * alignment, file}};
        queue.submit(reads[i]);
    }
    std::size_t landed = 0;
    while (landed != reads.size() && util::monotonic_ns() < deadline) {
        io_completion_t completed[4] {};
        int const count = queue.poll(completed, io_wait_t::blocking_k, deadline);
        if (!expect_true(count >= 0, "polling ended with {}", count)) return {};
        for (int i = 0; i != count; ++i) {
            auto const index = static_cast<std::size_t>(completed[i].request - reads.data());
            expect_true(index < reads.size() && completed[i].result == static_cast<descriptor_t>(alignment) &&
                            std::memcmp(windows[index].data, files.content.data() + (2 * index + 1) * alignment,
                                        alignment) == 0,
                        "read {} ended with {}", index, completed[i].result);
            ++landed;
        }
    }
    expect_true(landed == reads.size() && queue.statistics.file_reads_asynchronous == reads.size() &&
                    !queue.statistics.file_reads_blocking,
                "{} of {} reads landed", landed, reads.size());

    aligned_bytes_t large {32 * alignment};
    reads[0] = {.operation = io_operation_t::file_read_k,
                .descriptor = sockets.client,
                .data = large.data,
                .length = large.size,
                .file = {0, file}};
    reads[1] = reads[0];
    queue.submit(reads[0]);
    queue.submit(reads[1]);
    expect_true(queue.cancel(reads[1]) == ucall_status_success_k && queue.cancel(reads[0]) == ucall_status_success_k);
    std::array<descriptor_t, 2> cancelled {0, 0};
    for (std::size_t count = 0; count != cancelled.size() && util::monotonic_ns() < deadline;) {
        io_completion_t completed[2] {};
        int const polled = queue.poll(completed, io_wait_t::blocking_k, deadline);
        if (!expect_true(polled >= 0, "polling ended with {}", polled)) return {};
        for (int i = 0; i != polled; ++i, ++count)
            cancelled[static_cast<std::size_t>(completed[i].request - reads.data())] = completed[i].result;
    }
    expect_true(cancelled[0] == -ECANCELED && cancelled[1] == -ECANCELED, "the reads ended with {} and {}",
                cancelled[0], cancelled[1]);
    expect_true(await(queue, reads[0], deadline) == static_cast<descriptor_t>(large.size) &&
                std::memcmp(large.data, files.content.data(), large.size) == 0);
    ::close(file);
    return {};
}

/** A @c MSG_ZEROCOPY send completes once the socket took its bytes, and its release only once the
 *  error queue reported it; loopback copies, so that report demotes the socket, whose next
 *  zero-copy send copies and whose next release completes at once. */
template <typename queue_type_>
static case_result_t test_epollaio_zero_copy_sends() {
    queue_type_ queue;
    ucall_status_t const opened = queue.open(8, 8);
    if (opened == ucall_status_unsupported_k) return case_result_t::skipped(aio_refused_k);
    if (!expect_true(opened == ucall_status_success_k)) return {};
    loopback_pair_t sockets = loopback_pair();
    if (!expect_true(sockets.connected() && util::nonblocking(sockets.client) == ucall_status_success_k &&
                     util::nonblocking(sockets.peer) == ucall_status_success_k))
        return {};
    aligned_bytes_t window {16384};
    for (std::size_t i = 0; i != window.size; ++i) window.data[i] = file_byte(i);
    auto const deadline = util::deadline_after(5000000);
    std::string received;
    auto drain = [&](std::size_t expected) {
        char buffer[16384];
        while (received.size() < expected && util::monotonic_ns() < deadline)
            if (ssize_t const length = recv(sockets.peer, buffer, sizeof(buffer), 0); length > 0)
                received.append(buffer, static_cast<std::size_t>(length));
        return received.size() == expected && std::memcmp(received.data(), window.data, received.size()) == 0;
    };

    queue.reserve_releases(1);
    io_request_t release {.operation = io_operation_t::zero_copy_release_k};
    io_request_t sending {.operation = io_operation_t::send_zero_copy_k,
                          .descriptor = sockets.client,
                          .data = window.data,
                          .length = window.size,
                          .release_request = &release};
    descriptor_t const sent = await(queue, sending, deadline);
    expect_true(sent > 0 && queue.statistics.zero_copy_sends == 1, "sending ended with {} after {} sends", sent,
                queue.statistics.zero_copy_sends);
    queue.submit(release);
    expect_true(queue.cancel(release) == ucall_status_success_k);
    expect_true(finish(queue, release, deadline) == 0 && queue.statistics.zero_copy_fallbacks == 1,
                "the release completed with {} fallbacks counted", queue.statistics.zero_copy_fallbacks);
    expect_true(drain(static_cast<std::size_t>(sent)));

    received.clear();
    descriptor_t const copied = await(queue, sending, deadline);
    expect_true(copied > 0 && queue.statistics.zero_copy_sends == 1);
    expect_true(await(queue, release, deadline) == 0);
    expect_true(drain(static_cast<std::size_t>(copied)));
    expect_true(queue.close_socket(std::exchange(sockets.client, -1)) == 0);
    return {};
}

void run_linux_epollaio_queue_cases() {
    run_queue_cases<linux_epollaio_queue_t>(
        ucall_io_backend_linux_epollaio_k, []<typename queue_type_>(sz::string_t const& label) {
            run_test_case(called("test_queue_cell", label).c_str(), [] {
                return keeping_descriptors([] {
                    split_mix_generator_t generator {case_stream_key()};
                    test_queue_duplex<queue_type_>(generator);
                    test_gathered_send<queue_type_>(generator);
                    test_accept_batch<queue_type_>();
                });
            });
            run_cell_case(label, "test_direct_files", test_direct_files<queue_type_>);
            run_cell_case(label, "test_epollaio_reads", test_epollaio_reads<queue_type_>);
            run_cell_case(label, "test_epollaio_zero_copy_sends", test_epollaio_zero_copy_sends<queue_type_>);
        });
}

} // namespace unum::ucall::test::io
