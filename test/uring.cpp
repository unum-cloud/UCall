/**
 *  @file test/uring.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Registered I/O ownership after a failed submission syscall, unbuffered file reads into
 *      registered buffers, and zero-copy sends whose releases wait for the kernel.
 *
 *  Every case skips when the kernel lacks the io_uring generation it drives.
 */
#include <cstring> // `std::memcmp`

#include <fcntl.h>    // `open`, `O_DIRECT`
#include <sys/stat.h> // `mkfifo`, `mkdir`

#include <algorithm> // `std::fill`
#include <string>    // `std::string`
#include <vector>    // `std::vector`

#include "ucall/io/linux_uring612_engine.hpp" // `linux_uring612_engine`
#include "ucall/io/linux_uring618_engine.hpp" // `linux_uring618_engine`

#include "harness.hpp" // `expect`, `require`, `run_test`, `counting_allocator`, `loopback_pair`, `direct_directory_t`

using namespace unum::ucall;
using namespace unum::ucall::io;
using namespace unum::ucall::utilities;
using namespace unum::ucall::test;

/** Sends all of @p bytes through @p descriptor, blocking. */
[[nodiscard]] static bool send_all(int descriptor, span<byte_t const> bytes) noexcept {
    while (!bytes.empty()) {
        ssize_t const count = ::send(descriptor, bytes.data(), bytes.size(), MSG_NOSIGNAL);
        if (count <= 0) return false;
        bytes = bytes.subspan(static_cast<std::size_t>(count));
    }
    return true;
}

/** Checks the registered socket @p handle has `TCP_NODELAY`, through a descriptor it installs. */
template <typename engine_type_>
static std::size_t expect_nodelay(engine_type_& engine, descriptor_t handle) {
    auto* submission = engine.queue.entry();
    if (expect(submission)) return 1;
    engine.queue.control.result.reset();
    io_uring_prep_fixed_fd_install(submission, static_cast<int>(registered_socket_t::index_of(handle)), 0);
    io_uring_sqe_set_data64(submission, engine.queue.tag(&engine.queue.control, uring_control_tag_k));
    auto descriptor = engine.wait_control();
    if (expect(descriptor >= 0, "installing failed with {}", descriptor)) return 1;
    int enabled {};
    socket_length_t length = sizeof(enabled);
    std::size_t failures = expect(getsockopt(descriptor, IPPROTO_TCP, TCP_NODELAY, &enabled, &length) == 0 &&
                                  enabled == 1);
    socket_close(descriptor);
    return failures;
}

template <typename engine_type_>
static case_result_t failed_submission() {
    engine_type_ engine;
    auto status = engine.open(8, 4);
    if (status == ucall_status_unsupported_k) return case_result_t::skipped("the kernel lacks this generation");
    require(0, status == ucall_status_success_k, "{}", ucall_status_name(status));
    std::size_t failures = 0;
    auto direct = engine.open_socket(AF_INET);
    require(failures, direct >= 0);
    failures += expect_nodelay(engine, direct);
    failures += expect(engine.close_socket(direct) == 0);
    loopback_pair_t sockets = loopback_pair();
    require(failures, sockets.connected());
    auto owned = engine.import_socket(sockets.client);
    require(failures, owned >= 0);
    sockets.client = -1;
    failures += expect_nodelay(engine, owned);
    byte_t content[1] {byte_t {42}};
    io_request_t sending {.operation = io_operation_t::send_k,
                          .descriptor = owned,
                          .data = content,
                          .length = sizeof(content)};
    io_request_t receiving {.operation = io_operation_t::receive_k, .descriptor = owned, .length = engine.queue.page};
    require(failures, engine.submit(sending) == ucall_status_success_k);
    require(failures, engine.submit(receiving) == ucall_status_success_k);
    require(failures, engine.queue.enter(0, 0) >= 0);
    byte_t received {};
    failures += expect(recv(sockets.peer, &received, sizeof(received), 0) == 1 && received == content[0]);

    io_request_t unsubmitted {.operation = io_operation_t::send_k,
                              .descriptor = owned,
                              .data = content,
                              .length = sizeof(content)};
    failures += expect(engine.submit(unsubmitted) == ucall_status_success_k);
    auto descriptor = engine.queue.ring.ring_fd;
    auto enter_descriptor = engine.queue.ring.enter_ring_fd;
    engine.queue.ring.ring_fd = -1;
    engine.queue.ring.enter_ring_fd = -1;
    auto failure = engine.queue.enter(0, 0);
    failures += expect(failure < 0);
    engine.queue.ring.ring_fd = descriptor;
    engine.queue.ring.enter_ring_fd = enter_descriptor;
    engine.queue.fault = failure;
    engine.stop();

    failures += expect(!engine.is_open() && engine.queue.file_registration == uring_registration_t::unregistered_k &&
                       engine.queue.buffer_registration == uring_registration_t::unregistered_k);
    failures += expect(!engine.queue.receive_ring && engine.queue.storage);
    failures += expect(!engine.has_kernel_work());
    failures += expect(recv(sockets.peer, &received, sizeof(received), 0) == 0);
    return failures;
}

template <typename engine_type_>
static case_result_t streamed_transmit() {
    engine_type_ engine;
    auto status = engine.open(1, 1);
    if (status == ucall_status_unsupported_k) return case_result_t::skipped("the kernel lacks this generation");
    require(0, status == ucall_status_success_k, "{}", ucall_status_name(status));
    std::size_t failures = 0;
    loopback_pair_t sockets = loopback_pair();
    require(failures, sockets.connected());
    auto owned = engine.import_socket(sockets.client);
    require(failures, owned >= 0);
    sockets.client = -1;
    require(failures, nonblocking(sockets.peer) == ucall_status_success_k);
    std::vector<byte_t> payload(65536, byte_t {85}), received(payload.size());
    std::size_t sent {}, read {};
    bool pending {};
    io_request_t sending {.operation = io_operation_t::send_k, .descriptor = owned};
    auto deadline = deadline_after(1000000);
    while (sent != payload.size() || read != payload.size()) {
        if (!pending && sent != payload.size()) {
            sending.data = payload.data() + sent;
            sending.length = payload.size() - sent;
            sending.deadline = deadline;
            require(failures, engine.submit(sending) == ucall_status_success_k);
            pending = true;
        }
        io_completion_t completed {};
        if (engine.poll(span<io_completion_t> {&completed, &completed + 1}, io_wait_t::nonblocking_k)) {
            require(failures, completed.request == &sending && completed.result > 0, "sending ended with {}",
                    completed.result);
            sent += static_cast<std::size_t>(completed.result);
            pending = false;
        }
        if (read != received.size()) {
            auto count = recv(sockets.peer, received.data() + read, received.size() - read, 0);
            if (count > 0) read += static_cast<std::size_t>(count);
            else require(failures, count < 0 && io_pending(-errno), "receiving ended with {}", count);
        }
        require(failures, monotonic_ns() < deadline, "{} sent and {} read of {}", sent, read, payload.size());
    }
    failures += expect(received == payload);
    failures += expect(engine.close_socket(owned) == 0);
    return failures;
}

static case_result_t test_uring612_failed_submission() { return failed_submission<linux_uring612_engine_t>(); }
static case_result_t test_uring618_failed_submission() { return failed_submission<linux_uring618_engine_t>(); }
static case_result_t test_uring612_streamed_transmit() { return streamed_transmit<linux_uring612_engine_t>(); }
static case_result_t test_uring618_streamed_transmit() { return streamed_transmit<linux_uring618_engine_t>(); }

static case_result_t test_uring618_paused_receive() {
    allocation_counts_t counts;
    std::size_t failures = 0;
    {
        linux_uring618_engine<counting_allocator<byte_t>> engine {counting_allocator<byte_t> {counts}};
        auto status = engine.open(8, 4);
        if (status == ucall_status_unsupported_k) return case_result_t::skipped("the kernel lacks this generation");
        require(failures, status == ucall_status_success_k, "{}", ucall_status_name(status));
        loopback_pair_t held = loopback_pair(), other = loopback_pair();
        require(failures, held.connected() && other.connected());
        auto first = engine.import_socket(held.client);
        auto second = engine.import_socket(other.client);
        require(failures, first >= 0 && second >= 0);
        held.client = other.client = -1;
        auto original = engine.queue.page * (engine.queue.buffer_count + 1);
        std::vector<byte_t> payload(original + engine.queue.page, byte_t {17});
        std::fill(payload.begin() + static_cast<std::ptrdiff_t>(original), payload.end(), byte_t {34});
        io_request_t receiving {.operation = io_operation_t::receive_k,
                                .descriptor = first,
                                .length = engine.queue.page};
        require(failures, engine.submit(receiving) == ucall_status_success_k);
        require(failures, send_all(held.peer, span<byte_t const> {payload}.first(original)));
        io_completion_t completed[2] {};
        require(failures, engine.poll(completed, io_wait_t::blocking_k, deadline_after(1000000)) == 1);
        require(failures, completed[0].result > 0, "receiving ended with {}", completed[0].result);
        auto received = static_cast<std::size_t>(completed[0].result);
        failures += expect(std::memcmp(completed[0].data, payload.data(), received) == 0);

        announce("a paused socket parks its backlog");
        auto* owner = engine.socket_slots.find(first);
        auto deadline = deadline_after(1000000);
        while (owner->receive_head == engine.absent_k) {
            auto const spare = span<io_completion_t> {completed}.subspan(1);
            failures += expect(engine.poll(spare, io_wait_t::nonblocking_k) == 0);
            require(failures, monotonic_ns() < deadline, "the backlog never filled");
        }
        engine.receive_pause(first);
        engine.release(completed[0]);
        require(failures, send_all(held.peer, span<byte_t const> {payload}.subspan(original)));

        byte_t marker[1] {byte_t {51}};
        io_request_t independent {.operation = io_operation_t::receive_k,
                                  .descriptor = second,
                                  .length = engine.queue.page};
        require(failures, engine.submit(independent) == ucall_status_success_k);
        require(failures, send_all(other.peer, marker));
        require(failures, engine.poll(completed, io_wait_t::blocking_k, deadline) == 1);
        failures += expect(completed[0].request == &independent && completed[0].result == 1 &&
                           completed[0].data[0] == marker[0]);
        engine.release(completed[0]);
        while (owner->receive_in_flight()) {
            failures += expect(engine.poll(completed, io_wait_t::nonblocking_k) == 0);
            require(failures, monotonic_ns() < deadline, "the paused receive never retired");
        }
        failures += expect(owner->receive_head == engine.absent_k && !owner->backlog.empty());
        failures += expect(engine.queue.available_buffers == engine.queue.buffer_count);

        announce("pausing with a receive in flight, then cancelling one");
        require(failures, engine.submit(independent) == ucall_status_success_k);
        engine.receive_pause(second);
        require(failures, send_all(other.peer, marker));
        require(failures, engine.poll(completed, io_wait_t::blocking_k, deadline) == 1);
        failures += expect(completed[0].request == &independent && completed[0].result == 1 &&
                           completed[0].data[0] == marker[0]);
        engine.release(completed[0]);
        require(failures, engine.submit(independent) == ucall_status_success_k);
        failures += expect(engine.cancel(independent) == ucall_status_success_k);
        require(failures, engine.poll(completed, io_wait_t::blocking_k, deadline) == 1);
        failures += expect(completed[0].request == &independent && completed[0].result == -ECANCELED &&
                           !completed[0].lease);

        announce("draining the parked backlog in order");
        while (received != payload.size()) {
            receiving.deadline = deadline_after(1000000);
            require(failures, engine.submit(receiving) == ucall_status_success_k);
            require(failures, engine.poll(completed, io_wait_t::blocking_k, receiving.deadline) == 1);
            require(failures, completed[0].request == &receiving && completed[0].result > 0, "receiving ended with {}",
                    completed[0].result);
            auto length = static_cast<std::size_t>(completed[0].result);
            require(failures, length <= payload.size() - received);
            failures += expect(std::memcmp(completed[0].data, payload.data() + received, length) == 0);
            received += length;
            engine.release(completed[0]);
        }
        require(failures, engine.submit(receiving) == ucall_status_success_k);
        failures += expect(engine.close_socket(first) == 0);
        require(failures, engine.poll(completed, io_wait_t::nonblocking_k) == 1);
        failures += expect(completed[0].request == &receiving && completed[0].result == -ECANCELED &&
                           !completed[0].lease);
        auto reused = engine.open_socket(AF_INET);
        failures += expect(reused == first);
        failures += expect(engine.close_socket(reused) == 0 && engine.close_socket(second) == 0);
        engine.stop();
        failures += expect(!engine.has_kernel_work());
    }
    failures += expect(counts.allocations && !counts.bytes && counts.allocations == counts.deallocations,
                       "{} allocations, {} deallocations, {} bytes kept", counts.allocations, counts.deallocations,
                       counts.bytes);
    return failures;
}

/** The byte at @p offset of the patterned file the file cases read. */
static byte_t file_byte(std::uint64_t offset) noexcept { return static_cast<byte_t>((offset * 2654435761u) >> 13); }

/** Opens beneath a directory with `OPENAT2` for unbuffered reads, refusing escapes; refuses a
 *  buffered descriptor; then reads aligned extents, a short tail, a registered buffer through
 *  `READ_FIXED`, and vectors that `READV` or `READV_FIXED` scatter into. */
template <typename engine_type_>
static case_result_t direct_files() {
    direct_directory_t directory;
    if (!directory.ready()) {
        announce("{}", directory.reason);
        return case_result_t::skipped("the directory serves no unbuffered reads");
    }
    engine_type_ engine;
    auto status = engine.open(8, 8);
    if (status == ucall_status_unsupported_k) return case_result_t::skipped("the kernel lacks this generation");
    require(0, status == ucall_status_success_k, "{}", ucall_status_name(status));
    std::size_t failures = 0;
    std::size_t const alignment = directory.alignment;
    std::string content(64 * alignment + 123, '\0');
    for (std::size_t i = 0; i != content.size(); ++i) content[i] = static_cast<char>(file_byte(i));
    require(failures, directory.write("data.bin", content) && mkfifo(directory.name("fifo").c_str(), 0600) == 0 &&
                          symlink("/etc/hostname", directory.name("absolute").c_str()) == 0 &&
                          mkdir(directory.name("subdir").c_str(), 0700) == 0);
    loopback_pair_t sockets = loopback_pair();
    require(failures, sockets.connected());
    auto const socket = engine.import_socket(std::exchange(sockets.client, -1));
    require(failures, socket >= 0);
    auto const deadline = deadline_after(5000000);
    io_completion_t completed[1] {};
    auto await = [&](io_request_t& request) {
        if (engine.submit(request) != ucall_status_success_k) return descriptor_t {-EIO};
        while (monotonic_ns() < deadline)
            if (engine.poll(completed, io_wait_t::blocking_k, deadline) == 1 && completed[0].request == &request)
                return completed[0].result;
        return descriptor_t {-ETIMEDOUT};
    };

    announce("opening beneath a directory");
    int file = -1;
    for (std::string_view path : {"data.bin", "fifo", "subdir", "absolute", "../data.bin", "missing"}) {
        std::string terminated {path};
        io_request_t opening {.operation = io_operation_t::file_open_k,
                              .descriptor = socket,
                              .data = reinterpret_cast<byte_t*>(terminated.data()),
                              .length = terminated.size() + 1,
                              .file = {0, -1, directory.descriptor}};
        descriptor_t const opened = await(opening);
        if (path == "data.bin") {
            file_geometry_t const geometry = opened >= 0 ? file_direct_alignment(opened) : file_geometry_t {};
            failures += expect(
                opened >= 0 && !geometry.error && geometry.size == content.size() && geometry.alignment == alignment,
                "{} opened as {} measuring {} bytes aligned to {}", path, opened, geometry.size, geometry.alignment);
            file = static_cast<int>(opened);
        }
        else {
            failures += expect(opened < 0, "{} opened as {}", path, opened);
            if (opened >= 0) ::close(opened);
        }
    }
    require(failures, file >= 0);

    announce("refusing a buffered descriptor");
    int const buffered = ::open(directory.name("data.bin").c_str(), O_RDONLY | O_CLOEXEC);
    failures += expect(file_direct_check(buffered) == ucall_status_invalid_argument_k &&
                       file_direct_check(file) == ucall_status_success_k);
    ::close(buffered);

    announce("reading aligned extents and a short tail");
    aligned_bytes_t window {4 * alignment};
    io_request_t reading {.operation = io_operation_t::file_read_k,
                          .descriptor = socket,
                          .data = window.data,
                          .length = 2 * alignment,
                          .file = {3 * alignment, file, -1}};
    failures += expect(await(reading) == static_cast<descriptor_t>(2 * alignment) &&
                       std::memcmp(window.data, content.data() + 3 * alignment, 2 * alignment) == 0);
    reading.file.offset = 64 * alignment;
    reading.length = alignment;
    failures += expect(await(reading) == 123 && std::memcmp(window.data, content.data() + 64 * alignment, 123) == 0);

    announce("reading into registered memory");
    memory_registration_t const registration = engine.register_memory(window.bytes());
    failures += expect(registration.pinning == range_pinning_t::pinned_k && registration.index != io_unregistered_k,
                       "pinning {} bytes was refused", window.size);
    reading.registered_memory = registration.index;
    reading.file.offset = 7 * alignment;
    reading.length = 3 * alignment;
    failures += expect(await(reading) == static_cast<descriptor_t>(3 * alignment) &&
                       std::memcmp(window.data, content.data() + 7 * alignment, 3 * alignment) == 0);

    announce("scattering into vectors");
    std::memset(window.data, 0, window.size);
    io_vector_t vectors[2] {{window.data, alignment}, {window.data + 2 * alignment, alignment}};
    io_request_t scattering {.operation = io_operation_t::file_read_vectors_k,
                             .registered_memory = registration.index,
                             .descriptor = socket,
                             .data = reinterpret_cast<byte_t*>(vectors),
                             .length = 2,
                             .file = {5 * alignment, file, -1}};
    failures += expect(await(scattering) == static_cast<descriptor_t>(2 * alignment) &&
                       std::memcmp(window.data, content.data() + 5 * alignment, alignment) == 0 &&
                       std::memcmp(window.data + 2 * alignment, content.data() + 6 * alignment, alignment) == 0);
    failures += expect(engine.statistics.file_reads_asynchronous == 4 && !engine.statistics.file_reads_blocking);
    ::close(file);
    failures += expect(engine.close_socket(socket) == 0);
    return failures;
}
static case_result_t test_uring612_direct_files() { return keeping_descriptors(direct_files<linux_uring612_engine_t>); }
static case_result_t test_uring618_direct_files() { return keeping_descriptors(direct_files<linux_uring618_engine_t>); }

/** A zero-copy send completes once the socket took its bytes, and its release only once the
 *  kernel's notification arrived; loopback copies, so that notification demotes the socket, whose
 *  next zero-copy send copies and whose next release completes at once. */
template <typename engine_type_>
static case_result_t zero_copy_sends() {
    engine_type_ engine;
    auto status = engine.open(8, 8);
    if (status == ucall_status_unsupported_k) return case_result_t::skipped("the kernel lacks this generation");
    require(0, status == ucall_status_success_k, "{}", ucall_status_name(status));
    std::size_t failures = 0;
    loopback_pair_t sockets = loopback_pair();
    require(failures, sockets.connected() && nonblocking(sockets.peer) == ucall_status_success_k);
    auto const socket = engine.import_socket(std::exchange(sockets.client, -1));
    require(failures, socket >= 0);
    aligned_bytes_t window {16384};
    for (std::size_t i = 0; i != window.size; ++i) window.data[i] = file_byte(i);
    memory_registration_t const registration = engine.register_memory(window.bytes());
    auto const deadline = deadline_after(5000000);
    io_completion_t completed[1] {};
    auto finish = [&](io_request_t& request) {
        while (monotonic_ns() < deadline)
            if (engine.poll(completed, io_wait_t::blocking_k, deadline) == 1 && completed[0].request == &request)
                return completed[0].result;
        return descriptor_t {-ETIMEDOUT};
    };
    auto await = [&](io_request_t& request) {
        return engine.submit(request) == ucall_status_success_k ? finish(request) : descriptor_t {-EIO};
    };
    std::vector<byte_t> received;
    auto drain = [&](std::size_t expected) {
        byte_t buffer[16384];
        while (received.size() < expected && monotonic_ns() < deadline)
            if (ssize_t const length = recv(sockets.peer, buffer, sizeof(buffer), 0); length > 0)
                received.insert(received.end(), buffer, buffer + length);
        return received.size() == expected;
    };

    announce("a release completes only after its notification, and cancelling it changes nothing");
    io_request_t release {.operation = io_operation_t::zero_copy_release_k};
    io_request_t sending {.operation = io_operation_t::send_zero_copy_k,
                          .registered_memory = registration.index,
                          .descriptor = socket,
                          .data = window.data,
                          .length = window.size,
                          .release_request = &release};
    descriptor_t const sent = await(sending);
    failures += expect(sent > 0 && engine.statistics.zero_copy_sends == 1, "sending ended with {} after {} sends", sent,
                       engine.statistics.zero_copy_sends);
    require(failures, engine.submit(release) == ucall_status_success_k);
    failures += expect(engine.cancel(release) == ucall_status_success_k);
    failures += expect(finish(release) == 0 && engine.statistics.zero_copy_fallbacks == 1,
                       "the release completed with {} fallbacks counted", engine.statistics.zero_copy_fallbacks);
    failures += expect(drain(static_cast<std::size_t>(sent)) &&
                       std::memcmp(received.data(), window.data, received.size()) == 0);

    announce("a copied notification demotes the socket");
    received.clear();
    descriptor_t const copied = await(sending);
    failures += expect(copied > 0 && engine.statistics.zero_copy_sends == 1, "sending ended with {} after {} sends",
                       copied, engine.statistics.zero_copy_sends);
    failures += expect(await(release) == 0);
    failures += expect(drain(static_cast<std::size_t>(copied)) &&
                       std::memcmp(received.data(), window.data, received.size()) == 0);
    failures += expect(engine.close_socket(socket) == 0);
    return failures;
}
static case_result_t test_uring612_zero_copy_sends() { return zero_copy_sends<linux_uring612_engine_t>(); }
static case_result_t test_uring618_zero_copy_sends() { return zero_copy_sends<linux_uring618_engine_t>(); }

/** A failed allocation during setup answers out-of-memory, returning every byte taken before it. */
static case_result_t test_uring612_allocation_failure() {
    bool kernel_available = false;
    {
        linux_uring612_engine_t probe;
        kernel_available = probe.open(1, 1) != ucall_status_unsupported_k;
    }
    std::size_t failures = 0;
    // Only a kernel with rings reaches the seventh allocation, the probe's.
    for (auto fail_from : {std::size_t {0}, std::size_t {4}, std::size_t {6}}) {
        if (fail_from == 6 && !kernel_available) continue;
        allocation_counts_t counts;
        counts.fail_from = fail_from;
        {
            linux_uring612_engine<counting_allocator<byte_t>> engine {counting_allocator<byte_t> {counts}};
            auto status = engine.open(4, 4);
            failures += expect(status == ucall_status_out_of_memory_k, "failing allocation {} answered {}", fail_from,
                               ucall_status_name(status));
        }
        failures += expect(!counts.bytes && counts.allocations == counts.deallocations,
                           "failing allocation {} kept {} bytes", fail_from, counts.bytes);
    }
    return failures;
}

int main(int, char** argv) {
    install_test_signal_handlers();
    fmt::print("Hi, dear tester! You look nice today!\n");
    configure_tests();

    suite_totals_t totals {.program = argv[0]};
    run_test(totals, "test_uring612_failed_submission", test_uring612_failed_submission);
    run_test(totals, "test_uring618_failed_submission", test_uring618_failed_submission);
    run_test(totals, "test_uring612_allocation_failure", test_uring612_allocation_failure);
    run_test(totals, "test_uring612_streamed_transmit", test_uring612_streamed_transmit);
    run_test(totals, "test_uring618_streamed_transmit", test_uring618_streamed_transmit);
    run_test(totals, "test_uring618_paused_receive", test_uring618_paused_receive);
    run_test(totals, "test_uring612_direct_files", test_uring612_direct_files);
    run_test(totals, "test_uring618_direct_files", test_uring618_direct_files);
    run_test(totals, "test_uring612_zero_copy_sends", test_uring612_zero_copy_sends);
    run_test(totals, "test_uring618_zero_copy_sends", test_uring618_zero_copy_sends);
    return suite_exit_code(totals);
}
