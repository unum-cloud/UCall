/**
 *  @file test/io/queues.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The queue cases every queue runs, each templated on the queue, and the sweep that
 *      runs a queue rebound to every admitted CPU class's atomic reference and row kit.
 */
#pragma once
#include <cstring> // `std::memcmp`

#include <fcntl.h>        // `open`, `O_DIRECT`
#include <sys/resource.h> // `getrlimit`, `setrlimit`
#include <sys/stat.h>     // `mkfifo`, `mkdir`

#include <algorithm> // `std::find`, `std::fill`
#include <array>     // `std::array`
#include <string>    // `std::string`
#include <vector>    // `std::vector`

#include "ucall/io/types.hpp"          // `io_request_t`, `io_completion_t`, `io_wait_t`
#include "ucall/utilities/sockets.hpp" // `nonblocking`, `monotonic_ns`, `deadline_after`
#if UCALL_WITH_LINUX_URING
#include "ucall/io/linux_uring612_queue.hpp" // `linux_uring612_queue`
#include "ucall/io/linux_uring618_queue.hpp" // `linux_uring618_queue`
#endif

#include "harness.hpp" // `expect_true`, `run_test_case`, `loopback_pair`, `direct_directory_t`, `file_byte`
#include "lib.hpp"     // `cpu_class_t`, `atomic_ref_for_cpu_class`, `row_kit_for_cpu_class`

namespace unum::ucall::test::io {

using namespace unum::ucall::io;

/** Why a ring case skips on a kernel older than the generation its queue drives. */
inline constexpr char const* generation_refused_k = "this io_uring generation is refused on this machine";

#if UCALL_OS_POSIX_

#pragma region Every Queue

/** The queue keeps a mebibyte send and a receive pending on one socket
 *  at once, and each completes as its own request. */
template <typename queue_type_>
void test_queue_duplex(split_mix_generator_t& generator) {
    queue_type_ queue;
    auto const status = queue.open(2, 2);
    if (!expect_true(status == ucall_status_success_k, "{}", ucall_status_name(status))) return;
    loopback_pair_t sockets = loopback_pair();
    if (!expect_true(sockets.connected())) return;
    // A send buffer far below a mebibyte keeps the send pending until the peer drains it, yet above
    // a page, as FreeBSD acknowledges each small segment only after its 40 ms delayed-ACK timer.
    int const send_buffer = static_cast<int>(16 * fixture_buffer_bytes_k);
    if (!expect_true(util::nonblocking(sockets.client) == ucall_status_success_k &&
                     util::nonblocking(sockets.peer) == ucall_status_success_k &&
                     util::socket_option(sockets.client, SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)) ==
                         0))
        return;
    auto const owned = queue.import_socket(std::exchange(sockets.client, -1));
    if (!expect_true(owned >= 0, "importing ended with {}", owned)) return;
    int const peer = sockets.peer;

    std::vector<util::byte_t> payload(std::size_t {1} << 20), drained(payload.size());
    for (auto& byte : payload) byte = static_cast<util::byte_t>(generator());
    span<util::byte_t const> const message = util::byte_span("receive");
    std::array<util::byte_t, fixture_buffer_bytes_k> buffer {};
    util::io_vector_t room {buffer.data(), sizeof(buffer)};
    io_request_t receiving {.operation = io_operation_t::receive_k,
                            .descriptor = owned,
                            .data = reinterpret_cast<util::byte_t*>(&room),
                            .length = 1};
    io_request_t sending {.operation = io_operation_t::send_k,
                          .descriptor = owned,
                          .data = payload.data(),
                          .length = payload.size()};
    queue.submit(receiving);
    queue.submit(sending);

    std::size_t received = 0, sent = 0, read = 0;
    bool written = false;
    io_completion_t completions[2] {};
    auto const deadline = util::deadline_after(5000000);
    while (!received || sent != payload.size() || read != payload.size()) {
        // Nothing drains the peer before the receive completes,
        // so the send stays pending throughout.
        auto const wait = written && !received ? io_wait_t::blocking_k : io_wait_t::nonblocking_k;
        int const count = queue.poll(span<io_completion_t> {completions}, wait, deadline);
        if (!expect_true(count >= 0, "polling ended with {}", count)) return;
        for (auto const& completed : span<io_completion_t> {completions}.first(static_cast<std::size_t>(count))) {
            if (completed.request == &sending) {
                if (!expect_true(completed.result > 0, "sending ended with {}", completed.result)) return;
                sent += static_cast<std::size_t>(completed.result);
                sending.data = payload.data() + sent;
                sending.length = payload.size() - sent;
                if (sent != payload.size()) queue.submit(sending);
            }
            else {
                if (!expect_true(completed.request == &receiving, "a completion named neither request")) return;
                if (!expect_true(completed.result > 0, "receiving ended with {}", completed.result)) return;
                received = static_cast<std::size_t>(completed.result);
                span<util::byte_t const> const delivered {completed.data ? completed.data : buffer.data(), received};
                expect_equal_bytes(delivered, message);
                expect_true(sent != payload.size(), "the send finished before the peer read");
            }
            queue.release(completed);
        }
        if (!written && !count) {
            if (!expect_true(::send(peer, message.data(), message.size(), MSG_NOSIGNAL) ==
                             static_cast<ssize_t>(message.size())))
                return;
            written = true;
        }
        if (received && read != drained.size()) {
            auto const length = ::recv(peer, drained.data() + read, drained.size() - read, 0);
            if (length > 0) read += static_cast<std::size_t>(length);
            else if (!expect_true(length < 0 && io_pending(-errno), "draining ended with {}", length)) return;
        }
        if (!expect_true(util::monotonic_ns() < deadline, "{} received, {} sent and {} read of {}", received, sent,
                         read, payload.size()))
            return;
    }
    expect_true(drained == payload);
    expect_true(queue.close_socket(owned) == 0);
}

/** One accept of the queue takes every queued connection, each completing with its own peer and
 *  saying the request stays pending, and exactly one last completion ends it, however many of them
 *  one poll hands over together. */
template <typename queue_type_>
void test_accept_batch() {
    constexpr std::size_t connections_k = 8;
    queue_type_ queue;
    auto const status = queue.open(64, 64);
    if (!expect_true(status == ucall_status_success_k, "{}", ucall_status_name(status))) return;
    int const listener = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t address_length = sizeof(address);
    if (!expect_true(listener >= 0 && ::bind(listener, reinterpret_cast<sockaddr*>(&address), address_length) == 0 &&
                     ::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_length) == 0 &&
                     ::listen(listener, connections_k) == 0 && util::nonblocking(listener) == ucall_status_success_k))
        return;
    auto const owned = queue.import_socket(listener);
    if (!expect_true(owned >= 0, "importing the listener ended with {}", owned)) return;
    std::array<io_peer_address_t, connections_k> peers {};
    io_request_t accepting {.operation = io_operation_t::accept_k,
                            .descriptor = owned,
                            .data = reinterpret_cast<util::byte_t*>(peers.data()),
                            .length = connections_k};
    queue.submit(accepting);

    std::string const target = fmt::format("127.0.0.1:{}", ntohs(address.sin_port));
    std::array<raw_client_t, connections_k> clients;
    std::vector<unsigned> ports;
    for (auto& client : clients) {
        sockaddr_in local {};
        socklen_t local_length = sizeof(local);
        if (!expect_true(client.connect(target) &&
                         ::getsockname(client.descriptor, reinterpret_cast<sockaddr*>(&local), &local_length) == 0))
            return;
        ports.push_back(ntohs(local.sin_port));
    }
    std::vector<util::descriptor_t> accepted;
    std::size_t endings = 0;
    // Room past every connection, so a readiness queue never ends the accept for want of it.
    io_completion_t completions[4 * connections_k] {};
    auto const deadline = util::deadline_after(5000000);
    while (!endings) {
        // Every client connected, so a request still pending afterwards only ends once cancelled.
        if (accepted.size() == connections_k && accepting.length)
            if (!expect_true(queue.cancel(accepting) == ucall_status_success_k)) return;
        int const count = queue.poll(span<io_completion_t> {completions}, io_wait_t::blocking_k, deadline);
        if (!expect_true(count >= 0, "polling ended with {}", count)) return;
        for (auto const& completed : span<io_completion_t> {completions}.first(static_cast<std::size_t>(count))) {
            if (!expect_true(completed.request == &accepting, "a completion named another request")) return;
            expect_true(!endings, "a completion followed the one that ended the accept");
            endings += completed.continuation == io_continuation_t::ended_k;
            if (completed.result < 0) {
                expect_true(completed.result == -ECANCELED, "accepting ended with {}", completed.result);
                continue;
            }
            accepted.push_back(completed.result);
            auto const* written = completed.data ? completed.data : accepting.data;
            auto const& peer = reinterpret_cast<io_peer_address_t const*>(written)->address;
            auto const port = ntohs(reinterpret_cast<sockaddr_in const&>(peer).sin_port);
            auto const found = std::find(ports.begin(), ports.end(), port);
            expect_true(peer.ss_family == AF_INET && found != ports.end(), "a peer at port {} connected", port);
            if (found != ports.end()) ports.erase(found);
        }
        if (!expect_true(util::monotonic_ns() < deadline, "{} of {} accepted", accepted.size(), connections_k)) return;
    }
    expect_true(accepted.size() == connections_k && ports.empty(), "{} of {} accepted", accepted.size(), connections_k);
    expect_true(endings == 1 && !accepting.length, "{} completions ended the accept", endings);
    expect_true(queue.poll(span<io_completion_t> {completions}, io_wait_t::nonblocking_k) == 0,
                "the accept completed after it ended");
    for (auto descriptor : accepted) expect_true(queue.close_socket(descriptor) == 0);
    expect_true(queue.close_socket(owned) == 0);
}

/** The status flag @c F_GETFL reads back from a descriptor switched to unbuffered reads: Darwin's
 *  @c FNOCACHE, which its SDK keeps private, or @c O_DIRECT. */
#if UCALL_OS_APPLE_
inline constexpr int direct_flag_k = 0x40000;
#elif UCALL_OS_POSIX_
inline constexpr int direct_flag_k = O_DIRECT;
#endif

/** Polls @p queue until @p request completes, answering its result, or @c -ETIMEDOUT once
 *  @p deadline passes; other completions are dropped. */
template <typename queue_type_>
util::descriptor_t finish(queue_type_& queue, io_request_t const& request, std::uint64_t deadline) {
    io_completion_t completed[1] {};
    while (util::monotonic_ns() < deadline)
        if (queue.poll(completed, io_wait_t::blocking_k, deadline) == 1 && completed[0].request == &request)
            return completed[0].result;
    return -ETIMEDOUT;
}
template <typename queue_type_>
util::descriptor_t await(queue_type_& queue, io_request_t& request, std::uint64_t deadline) {
    queue.submit(request);
    return finish(queue, request, deadline);
}

/** A disk-backed directory holding <tt>data.bin</tt>, 64 alignments and 123 bytes of patterned
 *  content, beside a FIFO, a subdirectory and a symlink out of it. */
struct direct_files_t {
    direct_directory_t directory;
    std::string content;
    [[nodiscard]] bool fill() {
        content.resize(64 * directory.alignment + 123);
        for (std::size_t i = 0; i != content.size(); ++i) content[i] = static_cast<char>(file_byte(i));
        return directory.write("data.bin", content) && mkfifo(directory.name("fifo").c_str(), 0600) == 0 &&
               symlink("/etc/hostname", directory.name("absolute").c_str()) == 0 &&
               mkdir(directory.name("subdir").c_str(), 0700) == 0;
    }
};

/** Opens beneath a directory for unbuffered reads, refusing escapes, FIFOs and directories without
 *  waiting on a writer; switches a buffered descriptor, twice; then reads aligned extents, a short
 *  tail and vectors, counting each read as asynchronous or blocking as the queue performed it. */
template <typename queue_type_>
case_result_t test_direct_files() {
    direct_files_t files;
    if (char const* reason = files.directory.unusable()) return case_result_t::skipped(reason);
    queue_type_ queue;
    ucall_status_t const opened = queue.open(4, 4);
    if (!expect_true(opened == ucall_status_success_k)) return {};
    if (!expect_true(files.fill())) return {};
    std::size_t const alignment = files.directory.alignment;
    loopback_pair_t sockets = loopback_pair();
    if (!expect_true(sockets.connected() && util::nonblocking(sockets.client) == ucall_status_success_k)) return {};
    auto const socket = queue.import_socket(std::exchange(sockets.client, -1));
    auto const deadline = util::deadline_after(5000000);

    int file = -1;
    for (std::string_view path : {"data.bin", "fifo", "subdir", "absolute", "../data.bin", "missing"}) {
        std::string terminated {path};
        io_request_t opening {.operation = io_operation_t::file_open_k,
                              .descriptor = socket,
                              .data = reinterpret_cast<util::byte_t*>(terminated.data()),
                              .length = terminated.size() + 1,
                              .file = {0, files.directory.descriptor}};
        util::descriptor_t const opened = await(queue, opening, deadline);
        if (path == "data.bin") {
            util::file_geometry_t const geometry = opened >= 0 ? util::direct_alignment_of(opened)
                                                               : util::file_geometry_t {};
            expect_true(opened >= 0 && !geometry.error && geometry.size == files.content.size(),
                        "{} opened as {} measuring {}", path, opened, geometry.size);
            file = static_cast<int>(opened);
        }
        else {
            expect_true(opened < 0, "{} opened as {}", path, opened);
            if (opened >= 0) ::close(opened);
        }
    }
    if (!expect_true(file >= 0)) return {};

    util::native_file_t buffered = ::open(files.directory.name("data.bin").c_str(), O_RDONLY | O_CLOEXEC);
    expect_true(util::file_direct_switch(buffered) == ucall_status_success_k &&
                    util::file_direct_switch(buffered) == ucall_status_success_k &&
                    (fcntl(buffered, F_GETFL) & direct_flag_k),
                "the switch left flags {:#x}", fcntl(buffered, F_GETFL));
    ::close(buffered);

    aligned_bytes_t window {4 * alignment};
    expect_true(queue.register_memory(window.bytes()).pinning() == range_pinning_t::unpinned_k);
    io_request_t reading {.operation = io_operation_t::file_read_k,
                          .descriptor = socket,
                          .data = window.data,
                          .length = 2 * alignment,
                          .file = {3 * alignment, file}};
    expect_true(await(queue, reading, deadline) == static_cast<util::descriptor_t>(2 * alignment) &&
                std::memcmp(window.data, files.content.data() + 3 * alignment, 2 * alignment) == 0);
    reading.file.offset = 64 * alignment;
    reading.length = alignment;
    expect_true(await(queue, reading, deadline) == 123 &&
                std::memcmp(window.data, files.content.data() + 64 * alignment, 123) == 0);
    util::io_vector_t vectors[2] {{window.data, alignment}, {window.data + 2 * alignment, alignment}};
    io_request_t scattering {.operation = io_operation_t::file_read_vectors_k,
                             .descriptor = socket,
                             .data = reinterpret_cast<util::byte_t*>(vectors),
                             .length = 2,
                             .file = {5 * alignment, file}};
    expect_true(await(queue, scattering, deadline) == static_cast<util::descriptor_t>(2 * alignment) &&
                std::memcmp(window.data, files.content.data() + 5 * alignment, alignment) == 0 &&
                std::memcmp(window.data + 2 * alignment, files.content.data() + 6 * alignment, alignment) == 0);
    expect_true(queue.statistics.file_reads_asynchronous + queue.statistics.file_reads_blocking == 3);
    ::close(file);
    expect_true(queue.close_socket(socket) == 0);
    return {};
}

/** A blocking poll after a round that reaped many completions still ends as soon as a lone one
 *  arrives: the wait sized from that round gives up within the time the round took to handle, and
 *  no completion of either round goes missing. */
template <typename queue_type_>
void test_wait_follows_rounds() {
    constexpr std::size_t sockets_k = 8;
    queue_type_ queue;
    auto const status = queue.open(sockets_k, sockets_k);
    if (!expect_true(status == ucall_status_success_k, "{}", ucall_status_name(status))) return;
    std::vector<loopback_pair_t> pairs;
    pairs.reserve(sockets_k);
    std::array<int, sockets_k> owned {};
    std::array<std::array<util::byte_t, fixture_buffer_bytes_k>, sockets_k> buffers {};
    std::array<util::io_vector_t, sockets_k> rooms {};
    std::array<io_request_t, sockets_k> receiving {};
    for (std::size_t i = 0; i != sockets_k; ++i) {
        pairs.push_back(loopback_pair());
        if (!expect_true(pairs[i].connected())) return;
        owned[i] = queue.import_socket(std::exchange(pairs[i].client, -1));
        if (!expect_true(owned[i] >= 0, "importing ended with {}", owned[i])) return;
        rooms[i] = {buffers[i].data(), buffers[i].size()};
        receiving[i] = {.operation = io_operation_t::receive_k,
                        .descriptor = owned[i],
                        .data = reinterpret_cast<util::byte_t*>(&rooms[i]),
                        .length = 1};
    }
    span<util::byte_t const> const message = util::byte_span("round");
    // Collects one receive per written peer, answering how long the blocking polls took.
    auto const collect = [&](std::size_t writers) -> std::uint64_t {
        for (std::size_t i = 0; i != writers; ++i) queue.submit(receiving[i]);
        for (std::size_t i = 0; i != writers; ++i)
            if (!expect_true(::send(pairs[i].peer, message.data(), message.size(), MSG_NOSIGNAL) ==
                             static_cast<ssize_t>(message.size())))
                return 0;
        auto const started = util::monotonic_ns();
        auto const deadline = util::deadline_after(5000000);
        std::array<io_completion_t, sockets_k> completions {};
        std::size_t received = 0;
        while (received != writers && util::monotonic_ns() < deadline) {
            int const count = queue.poll(span<io_completion_t> {completions}, io_wait_t::blocking_k, deadline);
            if (!expect_true(count >= 0, "polling ended with {}", count)) return 0;
            for (auto const& completed : span<io_completion_t> {completions}.first(static_cast<std::size_t>(count))) {
                expect_true(completed.result == static_cast<int>(message.size()), "receiving ended with {}",
                            completed.result);
                ++received;
                queue.release(completed);
            }
        }
        expect_true(received == writers, "{} of {} receives completed", received, writers);
        return util::monotonic_ns() - started;
    };
    collect(sockets_k);
    std::uint64_t const lone = collect(1);
    expect_true(lone < 1000000000, "a lone receive after a full round took {} ns", lone);
    for (auto const descriptor : owned) expect_true(queue.close_socket(descriptor) == 0);
}

/** A gathered send of uneven vectors spanning a mebibyte, far past the send buffer, arrives in
 *  order byte for byte, as each completion takes part of it and the rest goes again past it. */
template <typename queue_type_>
void test_gathered_send(split_mix_generator_t& generator) {
    queue_type_ queue;
    auto const status = queue.open(2, 2);
    if (!expect_true(status == ucall_status_success_k, "{}", ucall_status_name(status))) return;
    loopback_pair_t sockets = loopback_pair();
    if (!expect_true(sockets.connected())) return;
    int const send_buffer = static_cast<int>(16 * fixture_buffer_bytes_k);
    if (!expect_true(util::nonblocking(sockets.client) == ucall_status_success_k &&
                     util::nonblocking(sockets.peer) == ucall_status_success_k &&
                     util::socket_option(sockets.client, SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof(send_buffer)) ==
                         0))
        return;
    auto const owned = queue.import_socket(std::exchange(sockets.client, -1));
    if (!expect_true(owned >= 0, "importing ended with {}", owned)) return;
    std::vector<util::byte_t> payload(std::size_t {1} << 20), drained(payload.size());
    for (auto& byte : payload) byte = static_cast<util::byte_t>(generator());
    std::vector<util::io_vector_t> vectors;
    for (std::size_t offset = 0; offset != payload.size();) {
        std::size_t const length = fu::min_of<std::size_t>(1 + generator.below(65536), payload.size() - offset);
        vectors.push_back({payload.data() + offset, length});
        offset += length;
    }
    io_request_t sending {.operation = io_operation_t::send_vectors_k,
                          .descriptor = owned,
                          .data = reinterpret_cast<util::byte_t*>(vectors.data()),
                          .length = vectors.size()};
    queue.submit(sending);
    std::size_t sent = 0, read = 0, first = 0;
    auto const deadline = util::deadline_after(5000000);
    while (sent != payload.size() || read != payload.size()) {
        io_completion_t completed {};
        if (queue.poll(span<io_completion_t> {&completed, 1}, io_wait_t::nonblocking_k) == 1) {
            if (!expect_true(completed.request == &sending && completed.result > 0, "sending ended with {}",
                             completed.result))
                return;
            sent += static_cast<std::size_t>(completed.result);
            // Steps past the vectors the socket took whole, and into the one it took in part.
            for (std::size_t taken = static_cast<std::size_t>(completed.result); taken;) {
                std::size_t const step = fu::min_of(taken, vectors[first].iov_len);
                vectors[first] = {static_cast<util::byte_t*>(vectors[first].iov_base) + step,
                                  vectors[first].iov_len - step};
                taken -= step;
                first += !vectors[first].iov_len;
            }
            sending.data = reinterpret_cast<util::byte_t*>(vectors.data() + first);
            sending.length = vectors.size() - first;
            if (sent != payload.size()) queue.submit(sending);
        }
        if (read != drained.size()) {
            auto const length = ::recv(sockets.peer, drained.data() + read, drained.size() - read, 0);
            if (length > 0) read += static_cast<std::size_t>(length);
            else if (!expect_true(length < 0 && io_pending(-errno), "draining ended with {}", length)) return;
        }
        if (!expect_true(util::monotonic_ns() < deadline, "{} sent and {} read of {}", sent, read, payload.size()))
            return;
    }
    expect_true(drained == payload);
    expect_true(queue.close_socket(owned) == 0);
}

#pragma endregion Every Queue

#if UCALL_WITH_LINUX_URING
#pragma region Rings

/** Sends all of @p bytes through @p descriptor, blocking. */
[[nodiscard]] inline bool send_all(int descriptor, span<util::byte_t const> bytes) noexcept {
    while (!bytes.empty()) {
        ssize_t const count = ::send(descriptor, bytes.data(), bytes.size(), MSG_NOSIGNAL);
        if (count <= 0) return false;
        bytes = bytes.subspan(static_cast<std::size_t>(count));
    }
    return true;
}

/** Checks the registered socket @p handle has @c TCP_NODELAY, through a descriptor it installs. */
template <typename queue_type_>
void expect_nodelay(queue_type_& queue, util::descriptor_t handle) {
    auto* submission = queue.state.entry();
    if (!expect_true(submission)) return;
    queue.state.control.result.reset();
    io_uring_prep_fixed_fd_install(submission, static_cast<int>(registered_socket_t::index_of(handle)), 0);
    io_uring_sqe_set_data64(submission, queue.state.tag(&queue.state.control, uring_control_tag_k));
    auto descriptor = queue.wait_control();
    if (!expect_true(descriptor >= 0, "installing failed with {}", descriptor)) return;
    int enabled {};
    util::socket_length_t length = sizeof(enabled);
    expect_true(getsockopt(descriptor, IPPROTO_TCP, TCP_NODELAY, &enabled, &length) == 0 && enabled == 1);
    util::socket_close(descriptor);
}

/** A ring sized for more operations than the kernel's file table holds still opens, registering
 *  sockets up to that table, as releases take no file: a server of thousands of connections, each
 *  naming a release per pipelined request, keeps its ring instead of the next queue it admits. */
template <typename queue_type_>
case_result_t test_ring_past_file_table() {
    if (queue_type_ {}.open(2, 2) == ucall_status_unsupported_k) return case_result_t::skipped(generation_refused_k);
    queue_type_ queue;
    auto const status = queue.open(2, uring_registered_files_limit_k + 1);
    expect_true(status == ucall_status_success_k, "a ring past the file table opened with {}",
                ucall_status_name(status));
    return {};
}

template <typename queue_type_>
case_result_t test_failed_submission() {
    queue_type_ queue;
    auto status = queue.open(8, 4);
    if (status == ucall_status_unsupported_k) return case_result_t::skipped(generation_refused_k);
    if (!expect_true(status == ucall_status_success_k, "{}", ucall_status_name(status))) return {};
    auto direct = queue.open_socket(AF_INET);
    if (!expect_true(direct >= 0)) return {};
    expect_nodelay(queue, direct);
    expect_true(queue.close_socket(direct) == 0);
    loopback_pair_t sockets = loopback_pair();
    if (!expect_true(sockets.connected())) return {};
    auto owned = queue.import_socket(sockets.client);
    if (!expect_true(owned >= 0)) return {};
    sockets.client = -1;
    expect_nodelay(queue, owned);
    util::byte_t content[1] {util::byte_t {42}};
    io_request_t sending {.operation = io_operation_t::send_k,
                          .descriptor = owned,
                          .data = content,
                          .length = sizeof(content)};
    io_request_t receiving {.operation = io_operation_t::receive_k, .descriptor = owned};
    queue.submit(sending);
    queue.submit(receiving);
    if (!expect_true(queue.state.enter(0, 0) >= 0)) return {};
    util::byte_t received {};
    expect_true(recv(sockets.peer, &received, sizeof(received), 0) == 1 && received == content[0]);

    io_request_t unsubmitted {.operation = io_operation_t::send_k,
                              .descriptor = owned,
                              .data = content,
                              .length = sizeof(content)};
    queue.submit(unsubmitted);
    auto descriptor = queue.state.ring.ring_fd;
    auto enter_descriptor = queue.state.ring.enter_ring_fd;
    queue.state.ring.ring_fd = -1;
    queue.state.ring.enter_ring_fd = -1;
    auto failure = queue.state.enter(0, 0);
    expect_true(failure < 0);
    queue.state.ring.ring_fd = descriptor;
    queue.state.ring.enter_ring_fd = enter_descriptor;
    queue.state.fault = failure;
    queue.stop();

    expect_true(!queue.is_open() && queue.state.file_registration == uring_registration_t::unregistered_k &&
                queue.state.buffer_registration == uring_registration_t::unregistered_k);
    expect_true(!queue.state.provided.receive_ring && queue.state.storage);
    expect_true(!queue.has_kernel_work());
    expect_true(recv(sockets.peer, &received, sizeof(received), 0) == 0);
    return {};
}

/** Polls @p queue until it answers a completion or @p deadline passes, answering whether it did. */
template <typename queue_type_>
bool poll_one(queue_type_& queue, io_completion_t& completed, std::uint64_t deadline) {
    return queue.poll(span<io_completion_t> {&completed, 1}, io_wait_t::blocking_k, deadline) == 1;
}

/** On either ring, a receive naming room lands there uncopied, a deadline ends one with
 *  @c -ETIMEDOUT, and a close ends one in flight with @c -ECANCELED. */
template <typename queue_type_>
case_result_t test_ring_receive_in_place() {
    queue_type_ queue;
    auto status = queue.open(8, 4);
    if (status == ucall_status_unsupported_k) return case_result_t::skipped(generation_refused_k);
    if (!expect_true(status == ucall_status_success_k, "{}", ucall_status_name(status))) return {};
    loopback_pair_t sockets = loopback_pair();
    if (!expect_true(sockets.connected())) return {};
    auto descriptor = queue.import_socket(std::exchange(sockets.client, -1));
    if (!expect_true(descriptor >= 0)) return {};
    auto const deadline = util::deadline_after(1000000);
    util::byte_t const marker[16] {util::byte_t {7}};
    io_completion_t completed {};
    io_request_t streaming {.operation = io_operation_t::receive_k, .descriptor = descriptor};
    queue.submit(streaming);
    if (!expect_true(send_all(sockets.peer, marker) && poll_one(queue, completed, deadline))) return {};
    expect_true(completed.result == sizeof(marker) && completed.release_token, "the pool answered {}",
                completed.result);
    queue.release(completed);

    std::vector<util::byte_t> body(queue.state.page_bytes * 4), room(body.size());
    for (std::size_t index = 0; index != body.size(); ++index) body[index] = static_cast<util::byte_t>(index % 251);
    util::io_vector_t vector {};
    auto aim_past = [&](std::size_t filled) { vector = {room.data() + filled, room.size() - filled}; };
    aim_past(0);
    io_request_t in_place {.operation = io_operation_t::receive_k,
                           .descriptor = descriptor,
                           .data = reinterpret_cast<util::byte_t*>(&vector),
                           .length = 1};
    // The shortest deadline passes before any byte could arrive.
    in_place.deadline = util::deadline_after(1);
    queue.submit(in_place);
    if (!expect_true(poll_one(queue, completed, deadline))) return {};
    expect_true(completed.request == &in_place && completed.result == -ETIMEDOUT && !completed.release_token,
                "a receive in place past its deadline ended with {}", completed.result);
    in_place.deadline = 0;

    auto const copied = queue.statistics.bytes_copied;
    std::size_t received = 0;
    queue.submit(in_place);
    if (!expect_true(send_all(sockets.peer, body))) return {};
    while (received != body.size()) {
        if (!expect_true(poll_one(queue, completed, deadline))) return {};
        if (!expect_true(completed.request == &in_place && completed.result > 0 && !completed.release_token,
                         "receiving in place ended with {}", completed.result))
            return {};
        received += static_cast<std::size_t>(completed.result);
        aim_past(received);
        if (received != body.size()) queue.submit(in_place);
    }
    expect_true(room == body && queue.statistics.bytes_copied == copied, "{} bytes copied landing {} in place",
                queue.statistics.bytes_copied - copied, body.size());

    aim_past(0);
    queue.submit(in_place);
    expect_true(queue.close_socket(descriptor) == 0);
    if (!expect_true(poll_one(queue, completed, deadline))) return {};
    expect_true(completed.request == &in_place && completed.result == -ECANCELED && !completed.release_token,
                "a receive in place cut by a close ended with {}", completed.result);
    queue.stop();
    expect_true(!queue.has_kernel_work());
    return {};
}

/** A ring lets its caller keep a pool slice past its round only while the pool spares a buffer
 *  for the kernel: kept slices of half a buffer each run the pool dry within twice its buffers,
 *  past which it refuses, and once they come back it lets slices be kept again. */
template <typename queue_type_>
case_result_t test_ring_retains_while_spare() {
    queue_type_ queue;
    auto status = queue.open(8, 4);
    if (status == ucall_status_unsupported_k) return case_result_t::skipped(generation_refused_k);
    if (!expect_true(status == ucall_status_success_k, "{}", ucall_status_name(status))) return {};
    loopback_pair_t sockets = loopback_pair();
    if (!expect_true(sockets.connected())) return {};
    auto descriptor = queue.import_socket(std::exchange(sockets.client, -1));
    if (!expect_true(descriptor >= 0)) return {};
    auto& provided = queue.state.provided;
    std::size_t const pool = provided.memory.size(), rounds = 2 * provided.buffer_count();
    std::vector<util::byte_t> const half(provided.buffer_bytes() / 2, util::byte_t {7});
    std::vector<io_completion_t> kept;
    bool refused = false;
    auto const deadline = util::deadline_after(1000000);
    io_request_t receiving {.operation = io_operation_t::receive_k, .descriptor = descriptor};
    for (std::size_t round = 0; round != rounds && !refused; ++round) {
        if (!expect_true(send_all(sockets.peer, half))) break;
        for (std::size_t received = 0; received != half.size() && !refused;) {
            io_completion_t completed {};
            queue.submit(receiving);
            if (!expect_true(poll_one(queue, completed, deadline) && completed.result > 0, "round {} received {}",
                             round, completed.result))
                return {};
            received += static_cast<std::size_t>(completed.result);
            // Only a slice of the pool is the pool's to spare; a 6.18 backlog never stays.
            bool const pooled = completed.release_token && completed.release_token <= pool;
            if (pooled && queue.retains(completed)) kept.push_back(completed);
            else {
                refused = refused || pooled;
                queue.release(completed);
            }
        }
    }
    expect_true(refused, "{} slices kept across {} buffers and none refused", kept.size(), provided.buffer_count());
    for (io_completion_t const& slice : kept) queue.release(slice);
    io_completion_t completed {};
    queue.submit(receiving);
    util::byte_t const marker[1] {util::byte_t {9}};
    if (expect_true(send_all(sockets.peer, marker) && poll_one(queue, completed, deadline))) {
        expect_true(queue.retains(completed), "a slice could not be kept once every kept one came back");
        queue.release(completed);
    }
    expect_true(queue.close_socket(descriptor) == 0);
    queue.stop();
    return {};
}

template <typename queue_type_>
case_result_t test_streamed_transmit() {
    queue_type_ queue;
    auto status = queue.open(1, 1);
    if (status == ucall_status_unsupported_k) return case_result_t::skipped(generation_refused_k);
    if (!expect_true(status == ucall_status_success_k, "{}", ucall_status_name(status))) return {};
    loopback_pair_t sockets = loopback_pair();
    if (!expect_true(sockets.connected())) return {};
    auto owned = queue.import_socket(sockets.client);
    if (!expect_true(owned >= 0)) return {};
    sockets.client = -1;
    if (!expect_true(util::nonblocking(sockets.peer) == ucall_status_success_k)) return {};
    std::vector<util::byte_t> payload(65536, util::byte_t {85}), received(payload.size());
    std::size_t sent {}, read {};
    bool pending {};
    io_request_t sending {.operation = io_operation_t::send_k, .descriptor = owned};
    auto deadline = util::deadline_after(1000000);
    while (sent != payload.size() || read != payload.size()) {
        if (!pending && sent != payload.size()) {
            sending.data = payload.data() + sent;
            sending.length = payload.size() - sent;
            sending.deadline = deadline;
            queue.submit(sending);
            pending = true;
        }
        io_completion_t completed {};
        if (queue.poll(span<io_completion_t> {&completed, &completed + 1}, io_wait_t::nonblocking_k)) {
            if (!expect_true(completed.request == &sending && completed.result > 0, "sending ended with {}",
                             completed.result))
                return {};
            sent += static_cast<std::size_t>(completed.result);
            pending = false;
        }
        if (read != received.size()) {
            auto count = recv(sockets.peer, received.data() + read, received.size() - read, 0);
            if (count > 0) read += static_cast<std::size_t>(count);
            else if (!expect_true(count < 0 && io_pending(-errno), "receiving ended with {}", count)) return {};
        }
        if (!expect_true(util::monotonic_ns() < deadline, "{} sent and {} read of {}", sent, read, payload.size()))
            return {};
    }
    expect_true(received == payload);
    expect_true(queue.close_socket(owned) == 0);
    return {};
}

/** A receive on @p handle answering @p expected, leaving its slice unreleased;
 *  @p completed names it. */
template <typename queue_type_>
void expect_slice(queue_type_& queue, io_request_t& receiving, io_completion_t& completed,
                  span<util::byte_t const> expected) {
    queue.submit(receiving);
    if (!expect_true(queue.poll({&completed, 1}, io_wait_t::blocking_k, util::deadline_after(1000000)) == 1)) return;
    expect_true(completed.request == &receiving && completed.result > 0 && completed.release_token,
                "receiving ended with {}", completed.result);
    expect_true(completed.result > 0 && static_cast<std::size_t>(completed.result) == expected.size() &&
                std::memcmp(completed.data, expected.data(), expected.size()) == 0);
}

/** An end of stream names the buffer being filled and consumes none of it, so the next socket's
 *  bytes land right behind the last ones. */
template <typename queue_type_>
case_result_t test_end_of_stream() {
    queue_type_ queue;
    auto status = queue.open(8, 8);
    if (status == ucall_status_unsupported_k) return case_result_t::skipped(generation_refused_k);
    if (!expect_true(status == ucall_status_success_k, "{}", ucall_status_name(status))) return {};
    loopback_pair_t leaving = loopback_pair(), staying = loopback_pair();
    if (!expect_true(leaving.connected() && staying.connected())) return {};
    auto const first = queue.import_socket(std::exchange(leaving.client, -1));
    auto const second = queue.import_socket(std::exchange(staying.client, -1));
    if (!expect_true(first >= 0 && second >= 0)) return {};
    auto& provided = queue.state.provided;
    util::byte_t const bytes[4] {util::byte_t {1}, util::byte_t {2}, util::byte_t {3}, util::byte_t {4}};
    io_request_t receiving {.operation = io_operation_t::receive_k, .descriptor = first};
    io_request_t other {.operation = io_operation_t::receive_k, .descriptor = second};
    io_completion_t completed {};
    if (!expect_true(send_all(leaving.peer, bytes))) return {};
    expect_slice(queue, receiving, completed, bytes);
    util::byte_t const* const landed = completed.data;
    queue.release(completed);
    unsigned const before = provided.available_buffers;

    if (!expect_true(::shutdown(leaving.peer, SHUT_WR) == 0)) return {};
    queue.submit(receiving);
    if (!expect_true(queue.poll({&completed, 1}, io_wait_t::blocking_k, util::deadline_after(1000000)) == 1)) return {};
    expect_true(completed.result == 0 && !completed.release_token && !completed.data, "the end answered {}",
                completed.result);
    queue.release(completed);
    expect_true(provided.available_buffers == before && provided.newest_buffer != absent_k &&
                    provided.records[provided.newest_buffer].consumed_bytes == sizeof(bytes),
                "{} buffers left of {}", provided.available_buffers, before);

    if (!expect_true(send_all(staying.peer, bytes))) return {};
    expect_slice(queue, other, completed, bytes);
    expect_true(completed.data == landed + sizeof(bytes));
    queue.release(completed);
    expect_true(queue.close_socket(first) == 0 && queue.close_socket(second) == 0);
    return {};
}

/** Two sockets take turns in one buffer, and neither slice moves while the other is unreleased. */
template <typename queue_type_>
case_result_t test_sockets_interleave() {
    queue_type_ queue;
    auto status = queue.open(8, 8);
    if (status == ucall_status_unsupported_k) return case_result_t::skipped(generation_refused_k);
    if (!expect_true(status == ucall_status_success_k, "{}", ucall_status_name(status))) return {};
    loopback_pair_t left = loopback_pair(), right = loopback_pair();
    if (!expect_true(left.connected() && right.connected())) return {};
    auto const first = queue.import_socket(std::exchange(left.client, -1));
    auto const second = queue.import_socket(std::exchange(right.client, -1));
    if (!expect_true(first >= 0 && second >= 0)) return {};
    util::byte_t const left_bytes[3] {util::byte_t {11}, util::byte_t {12}, util::byte_t {13}};
    util::byte_t const right_bytes[5] {util::byte_t {21}, util::byte_t {22}, util::byte_t {23}, util::byte_t {24},
                                       util::byte_t {25}};
    io_request_t left_receive {.operation = io_operation_t::receive_k, .descriptor = first};
    io_request_t right_receive {.operation = io_operation_t::receive_k, .descriptor = second};
    io_completion_t unreleased[4] {};
    if (!expect_true(send_all(left.peer, left_bytes))) return {};
    expect_slice(queue, left_receive, unreleased[0], left_bytes);
    if (!expect_true(send_all(right.peer, right_bytes))) return {};
    expect_slice(queue, right_receive, unreleased[1], right_bytes);
    if (!expect_true(send_all(left.peer, left_bytes))) return {};
    expect_slice(queue, left_receive, unreleased[2], left_bytes);
    if (!expect_true(send_all(right.peer, right_bytes))) return {};
    expect_slice(queue, right_receive, unreleased[3], right_bytes);
    expect_true(unreleased[1].data == unreleased[0].data + sizeof(left_bytes) &&
                unreleased[2].data == unreleased[1].data + sizeof(right_bytes) &&
                unreleased[3].data == unreleased[2].data + sizeof(left_bytes));
    expect_true(std::memcmp(unreleased[0].data, left_bytes, sizeof(left_bytes)) == 0 &&
                std::memcmp(unreleased[1].data, right_bytes, sizeof(right_bytes)) == 0);
    auto& provided = queue.state.provided;
    auto const& record = provided.records[provided.newest_buffer];
    expect_true(record.slices_awaiting_release == 4 &&
                record.consumed_bytes == 2 * sizeof(left_bytes) + 2 * sizeof(right_bytes));
    for (auto const& completed : unreleased) queue.release(completed);
    expect_true(!record.slices_awaiting_release && provided.available_buffers == provided.provided_buffers);
    expect_true(queue.close_socket(first) == 0 && queue.close_socket(second) == 0);
    return {};
}

/** Opens beneath a directory with @c OPENAT2 for unbuffered reads, refusing escapes; switches a
 *  buffered descriptor, twice; then reads aligned extents, a short tail, a registered buffer
 *  through @c READ_FIXED, and vectors that @c READV or @c READV_FIXED scatter into. */
template <typename queue_type_>
case_result_t test_registered_direct_files() {
    direct_directory_t directory;
    if (char const* reason = directory.unusable()) return case_result_t::skipped(reason);
    queue_type_ queue;
    auto status = queue.open(8, 8);
    if (status == ucall_status_unsupported_k) return case_result_t::skipped(generation_refused_k);
    if (!expect_true(status == ucall_status_success_k, "{}", ucall_status_name(status))) return {};
    std::size_t const alignment = directory.alignment;
    std::string content(64 * alignment + 123, '\0');
    for (std::size_t i = 0; i != content.size(); ++i) content[i] = static_cast<char>(file_byte(i));
    if (!expect_true(directory.write("data.bin", content) && mkfifo(directory.name("fifo").c_str(), 0600) == 0 &&
                     symlink("/etc/hostname", directory.name("absolute").c_str()) == 0 &&
                     mkdir(directory.name("subdir").c_str(), 0700) == 0))
        return {};
    loopback_pair_t sockets = loopback_pair();
    if (!expect_true(sockets.connected())) return {};
    auto const socket = queue.import_socket(std::exchange(sockets.client, -1));
    if (!expect_true(socket >= 0)) return {};
    auto const deadline = util::deadline_after(5000000);
    io_completion_t completed[1] {};
    auto await = [&](io_request_t& request) {
        queue.submit(request);
        while (util::monotonic_ns() < deadline)
            if (queue.poll(completed, io_wait_t::blocking_k, deadline) == 1 && completed[0].request == &request)
                return completed[0].result;
        return util::descriptor_t {-ETIMEDOUT};
    };

    int file = -1;
    for (std::string_view path : {"data.bin", "fifo", "subdir", "absolute", "../data.bin", "missing"}) {
        std::string terminated {path};
        io_request_t opening {.operation = io_operation_t::file_open_k,
                              .descriptor = socket,
                              .data = reinterpret_cast<util::byte_t*>(terminated.data()),
                              .length = terminated.size() + 1,
                              .file = {0, directory.descriptor}};
        util::descriptor_t const opened = await(opening);
        if (path == "data.bin") {
            util::file_geometry_t const geometry = opened >= 0 ? util::direct_alignment_of(opened)
                                                               : util::file_geometry_t {};
            std::size_t const measured = fu::max_of(geometry.memory_alignment, geometry.offset_alignment);
            expect_true(opened >= 0 && !geometry.error && geometry.size == content.size() && measured == alignment,
                        "{} opened as {} measuring {} bytes aligned to {}", path, opened, geometry.size, measured);
            file = static_cast<int>(opened);
        }
        else {
            expect_true(opened < 0, "{} opened as {}", path, opened);
            if (opened >= 0) ::close(opened);
        }
    }
    if (!expect_true(file >= 0)) return {};

    util::native_file_t buffered = ::open(directory.name("data.bin").c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    expect_true(util::file_direct_switch(buffered) == ucall_status_success_k &&
                    util::file_direct_switch(buffered) == ucall_status_success_k &&
                    (fcntl(buffered, F_GETFL) & (O_DIRECT | O_NONBLOCK)) == O_DIRECT,
                "the switch left flags {:#x}", fcntl(buffered, F_GETFL));
    ::close(buffered);

    aligned_bytes_t window {4 * alignment};
    io_request_t reading {.operation = io_operation_t::file_read_k,
                          .descriptor = socket,
                          .data = window.data,
                          .length = 2 * alignment,
                          .file = {3 * alignment, file}};
    expect_true(await(reading) == static_cast<util::descriptor_t>(2 * alignment) &&
                std::memcmp(window.data, content.data() + 3 * alignment, 2 * alignment) == 0);
    reading.file.offset = 64 * alignment;
    reading.length = alignment;
    expect_true(await(reading) == 123 && std::memcmp(window.data, content.data() + 64 * alignment, 123) == 0);

    memory_registration_t const registration = queue.register_memory(window.bytes());
    expect_true(registration.pinning() == range_pinning_t::pinned_k && registration.index != io_unregistered_k,
                "pinning {} bytes was refused", window.size);
    reading.registered_memory = registration.index;
    reading.file.offset = 7 * alignment;
    reading.length = 3 * alignment;
    expect_true(await(reading) == static_cast<util::descriptor_t>(3 * alignment) &&
                std::memcmp(window.data, content.data() + 7 * alignment, 3 * alignment) == 0);

    std::memset(window.data, 0, window.size);
    util::io_vector_t vectors[2] {{window.data, alignment}, {window.data + 2 * alignment, alignment}};
    io_request_t scattering {.operation = io_operation_t::file_read_vectors_k,
                             .registered_memory = registration.index,
                             .descriptor = socket,
                             .data = reinterpret_cast<util::byte_t*>(vectors),
                             .length = 2,
                             .file = {5 * alignment, file}};
    expect_true(await(scattering) == static_cast<util::descriptor_t>(2 * alignment) &&
                std::memcmp(window.data, content.data() + 5 * alignment, alignment) == 0 &&
                std::memcmp(window.data + 2 * alignment, content.data() + 6 * alignment, alignment) == 0);
    expect_true(queue.statistics.file_reads_asynchronous == 4 && !queue.statistics.file_reads_blocking);
    ::close(file);
    expect_true(queue.close_socket(socket) == 0);
    return {};
}

/** A zero-copy send completes once the socket took its bytes, and its release only once the
 *  kernel's notification arrived. Loopback copies, as a NIC copies what its stack coalesced, and
 *  that notification counts a fallback without demoting the socket, whose next send pins again. A
 *  send pinning past the locked-memory limit copies its retry alone, and the send after it pins,
 *  while a socket that @c copy_sends marks copies every send, its release completing at once. */
template <typename queue_type_>
case_result_t test_zero_copy_sends() {
    queue_type_ queue;
    auto status = queue.open(8, 8);
    if (status == ucall_status_unsupported_k) return case_result_t::skipped(generation_refused_k);
    if (!expect_true(status == ucall_status_success_k, "{}", ucall_status_name(status))) return {};
    loopback_pair_t sockets = loopback_pair();
    if (!expect_true(sockets.connected() && util::nonblocking(sockets.peer) == ucall_status_success_k)) return {};
    auto const socket = queue.import_socket(std::exchange(sockets.client, -1));
    if (!expect_true(socket >= 0)) return {};
    aligned_bytes_t window {16384};
    for (std::size_t i = 0; i != window.size; ++i) window.data[i] = file_byte(i);
    memory_registration_t const registration = queue.register_memory(window.bytes());
    auto const deadline = util::deadline_after(5000000);
    io_completion_t completed[1] {};
    auto finish = [&](io_request_t& request) {
        while (util::monotonic_ns() < deadline)
            if (queue.poll(completed, io_wait_t::blocking_k, deadline) == 1 && completed[0].request == &request)
                return completed[0].result;
        return util::descriptor_t {-ETIMEDOUT};
    };
    auto await = [&](io_request_t& request) {
        queue.submit(request);
        return finish(request);
    };
    std::vector<util::byte_t> received;
    auto drain = [&](std::size_t expected) {
        util::byte_t buffer[16384];
        while (received.size() < expected && util::monotonic_ns() < deadline)
            if (ssize_t const length = recv(sockets.peer, buffer, sizeof(buffer), 0); length > 0)
                received.insert(received.end(), buffer, buffer + length);
        return received.size() == expected;
    };
    auto send_and_release = [&](io_request_t& sending, io_request_t& release) {
        received.clear();
        util::descriptor_t const sent = await(sending);
        queue.submit(release);
        expect_true(queue.cancel(release) == ucall_status_success_k);
        expect_true(finish(release) == 0, "the release reported its socket copying for good");
        expect_true(drain(static_cast<std::size_t>(fu::max_of<util::descriptor_t>(sent, 0))) &&
                    std::memcmp(received.data(), window.data, received.size()) == 0);
        return sent;
    };

    queue.reserve_releases(1);
    io_request_t release {.operation = io_operation_t::zero_copy_release_k, .descriptor = socket};
    io_request_t sending {.operation = io_operation_t::send_zero_copy_k,
                          .registered_memory = registration.index,
                          .descriptor = socket,
                          .data = window.data,
                          .length = window.size,
                          .release_request = &release};
    util::descriptor_t const sent = send_and_release(sending, release);
    expect_true(sent > 0 && queue.statistics.zero_copy_sends == 1 && queue.statistics.zero_copy_fallbacks == 1,
                "sending ended with {} after {} sends and {} fallbacks", sent, queue.statistics.zero_copy_sends,
                queue.statistics.zero_copy_fallbacks);
    util::descriptor_t const pinned_again = send_and_release(sending, release);
    expect_true(pinned_again > 0 && queue.statistics.zero_copy_sends == 2,
                "a copied notification demoted the socket: {} after {} sends", pinned_again,
                queue.statistics.zero_copy_sends);

    // Root pins past RLIMIT_MEMLOCK, and registered memory was pinned once at registration.
    if (::geteuid() != 0) {
        io_request_t unregistered = sending;
        unregistered.registered_memory = io_unregistered_k;
        rlimit original {};
        expect_true(::getrlimit(RLIMIT_MEMLOCK, &original) == 0);
        rlimit lowered = original;
        lowered.rlim_cur = 0;
        expect_true(::setrlimit(RLIMIT_MEMLOCK, &lowered) == 0, "the locked-memory limit stayed");
        std::uint64_t const fallbacks = queue.statistics.zero_copy_fallbacks;
        util::descriptor_t const refused = send_and_release(unregistered, release);
        expect_true(::setrlimit(RLIMIT_MEMLOCK, &original) == 0, "the locked-memory limit stayed lowered");
        expect_true(
            refused > 0 && queue.statistics.zero_copy_fallbacks > fallbacks && queue.statistics.zero_copy_sends == 3,
            "a refused pinning sent {} after {} sends", refused, queue.statistics.zero_copy_sends);
        util::descriptor_t const pinned_after = send_and_release(unregistered, release);
        expect_true(pinned_after > 0 && queue.statistics.zero_copy_sends == 4,
                    "the send after a refused one copied: {} after {} sends", pinned_after,
                    queue.statistics.zero_copy_sends);
    }

    // A socket marked to copy sends without pinning, and its release reports it copying at once.
    std::uint64_t const pinned_sends = queue.statistics.zero_copy_sends;
    queue.copy_sends(socket);
    received.clear();
    util::descriptor_t const copied = await(sending);
    expect_true(copied > 0 && queue.statistics.zero_copy_sends == pinned_sends, "a copying socket pinned: {} sends",
                queue.statistics.zero_copy_sends);
    expect_true(await(release) == 1, "the release of a copying socket reported pinning");
    expect_true(drain(static_cast<std::size_t>(copied)) &&
                std::memcmp(received.data(), window.data, received.size()) == 0);
    expect_true(queue.close_socket(socket) == 0);
    return {};
}

#pragma endregion Rings
#endif // UCALL_WITH_LINUX_URING

#endif // UCALL_OS_POSIX_

#pragma region Class Sweep

/** @p queue_type_ rebound to the atomic reference and row kit of @p cpu_class_. */
template <cpu_class_t cpu_class_, typename queue_type_>
using rebound_queue_t = typename queue_type_::template rebind<st::default_allocator<util::byte_t>,
                                                              atomic_ref_for_cpu_class<cpu_class_>::template type,
                                                              typename row_kit_for_cpu_class<cpu_class_>::type>;

/** Visits @p queue_type_ rebound to the class @p cpu_class names. */
template <typename queue_type_, typename visit_type_>
void visit_rebound(ucall_cpu_class_t cpu_class, visit_type_&& visit) {
    switch (cpu_class) {
    case ucall_cpu_class_intel_haswell_k:
        return visit.template operator()<rebound_queue_t<cpu_class_t::intel_haswell_k, queue_type_>>();
    case ucall_cpu_class_intel_skylake_k:
        return visit.template operator()<rebound_queue_t<cpu_class_t::intel_skylake_k, queue_type_>>();
    case ucall_cpu_class_intel_icelake_k:
        return visit.template operator()<rebound_queue_t<cpu_class_t::intel_icelake_k, queue_type_>>();
    case ucall_cpu_class_intel_alder_k:
        return visit.template operator()<rebound_queue_t<cpu_class_t::intel_alder_k, queue_type_>>();
    case ucall_cpu_class_aws_g2_k:
        return visit.template operator()<rebound_queue_t<cpu_class_t::aws_g2_k, queue_type_>>();
    case ucall_cpu_class_aws_g5_k:
        return visit.template operator()<rebound_queue_t<cpu_class_t::aws_g5_k, queue_type_>>();
    case ucall_cpu_class_apple_m4_k:
        return visit.template operator()<rebound_queue_t<cpu_class_t::apple_m4_k, queue_type_>>();
    case ucall_cpu_class_alibaba_c930_k:
        return visit.template operator()<rebound_queue_t<cpu_class_t::alibaba_c930_k, queue_type_>>();
    case ucall_cpu_class_ibm_power10_k:
        return visit.template operator()<rebound_queue_t<cpu_class_t::ibm_power10_k, queue_type_>>();
    case ucall_cpu_class_monoversioned_k:
        return visit.template operator()<rebound_queue_t<cpu_class_t::monoversioned_k, queue_type_>>();
    default: return visit.template operator()<rebound_queue_t<cpu_class_t::serial_k, queue_type_>>();
    }
}

/** Why a queue's cells skip on a host that refuses it. */
inline constexpr char const* queue_refused_k = "the queue is refused on this machine";

/**
 *  @brief One cell per admitted CPU class, labelled like
 *      <tt>test_queue_cell(posix_k, aws_g2_k)</tt>: @p cases over @p queue_type_ rebound to that
 *      class, or a skip when the host refuses the queue.
 *
 *  @p cases is a generic lambda templated on the rebound queue and taking the cell's label, which
 *  runs the cell's case and, apart from it, each case that may skip.
 */
template <typename queue_type_, typename cases_type_>
void run_queue_cases(ucall_io_backend_t backend, cases_type_&& cases) {
    test_settings_t const& settings = test_run.settings;
    if (settings.backend != ucall_io_backend_automatic_k && settings.backend != backend) return;
    for (ucall_cpu_class_t const cpu_class : admitted_classes()) {
        if (settings.cpu_class_ceiling != ucall_cpu_class_unknown_k && settings.cpu_class_ceiling != cpu_class)
            continue;
        sz::string_t const label = formatted("{}, {}", backend_constant(backend), cpu_class_constant(cpu_class));
        if (queue_type_ {}.open(2, 2) != ucall_status_success_k) {
            run_test_case(called("test_queue_cell", label).c_str(),
                          [] { return case_result_t::skipped(queue_refused_k); });
            continue;
        }
        visit_rebound<queue_type_>(cpu_class,
                                   [&]<typename rebound_type_>() { cases.template operator()<rebound_type_>(label); });
    }
}

#pragma endregion Class Sweep

void run_posix_queue_cases();
void run_linux_epollaio_queue_cases();
void run_linux_uring612_queue_cases();
void run_linux_uring618_queue_cases();
void run_bsd_kqueue_queue_cases();

} // namespace unum::ucall::test::io
