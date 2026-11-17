/**
 *  @file test/network/replies.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief File and path reply parts, mixed streams, Noise record boundaries, stop, linger,
 *      windows and fairness.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build
#include <network.hpp>

namespace unum::ucall::test::network {

#pragma region File Parts
#if UCALL_OS_POSIX_

/** Whether @p descriptor is still open. */
static bool open_descriptor(int descriptor) { return fcntl(descriptor, F_GETFD) != -1; }

/** The byte at @p offset of the patterned files, which a misplaced range never matches. */
static char pattern_byte(std::uint64_t offset) { return static_cast<char>((offset * 2654435761u) >> 13); }

/** Bytes one window reads in plaintext, which ranges straddle to cross from one window into the
 *  next. */
static constexpr std::uint64_t window_capacity_k = std::uint64_t {256} << 10;

/** The files that file and path parts read, in a directory whose filesystem serves unbuffered
 *  reads: @c served is what the server registers, and <tt>outside.txt</tt> beside it is the place
 *  links escape to. */
struct file_tree_t {
    static constexpr std::string_view hello_k = "hello, file parts\n";
    static constexpr std::size_t big_size_k = std::size_t {4} << 20;
    static constexpr std::uint64_t far_offset_k = (std::uint64_t {1} << 32) + 100;
    static constexpr std::string_view far_text_k = "far away";

    direct_directory_t directory;
    std::string served;
    bool prepared {};

    file_tree_t() : served(directory.name("served")) {
        std::error_code failed;
        if (!directory.ready() || !std::filesystem::create_directories(fmt::format("{}/subdir", served), failed))
            return;
        bool const written = write("hello.txt", hello_k) && write("subdir/inner.txt", "inner") &&
                             write("locked.txt", "locked") && write("big.bin", big()) &&
                             directory.write("outside.txt", "outside");
        bool const linked = chmod(name("locked.txt").c_str(), 0) == 0 && mkfifo(name("fifo").c_str(), 0600) == 0 &&
                            symlink("../outside.txt", name("outward").c_str()) == 0 &&
                            symlink("/etc/hostname", name("absolute").c_str()) == 0 &&
                            symlink("/proc/self/fd/0", name("magic").c_str()) == 0;
        int const sparse = ::open(name("sparse.bin").c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
        bool const extended = sparse >= 0 && ftruncate(sparse, static_cast<off_t>(far_offset_k + 4096)) == 0 &&
                              pwrite(sparse, far_text_k.data(), far_text_k.size(), static_cast<off_t>(far_offset_k)) ==
                                  static_cast<ssize_t>(far_text_k.size());
        if (sparse >= 0) ::close(sparse);
        prepared = written && linked && extended;
    }

    /** Why file cases cannot run here, or null once the tree is ready. */
    char const* unusable() const {
        if (prepared) return nullptr;
        if (char const* reason = directory.unusable()) return reason;
        static std::string reason;
        reason = fmt::format("needs a file tree, which {} refused", directory.path);
        return reason.c_str();
    }
    std::string name(std::string_view relative) const { return fmt::format("{}/{}", served, relative); }
    [[nodiscard]] bool write(std::string_view relative, std::string_view content) const {
        return directory.write(fmt::format("served/{}", relative), content);
    }

    /** Opens @p relative for a file part, which switches it to unbuffered reads. */
    int open(std::string_view relative) const { return ::open(name(relative).c_str(), O_RDONLY | O_CLOEXEC); }

    /** The patterned bytes <tt>big.bin</tt> holds from @p offset on, @p length of them. */
    static std::string big(std::size_t offset = 0, std::size_t length = big_size_k) {
        std::string bytes(length, '\0');
        for (std::size_t i = 0; i != length; ++i) bytes[i] = pattern_byte(offset + i);
        return bytes;
    }
};

static ucall_reply_part_t file_part(int descriptor, std::uint64_t offset = 0, std::uint64_t length = 0) {
    ucall_reply_part_t part {};
    part.kind = ucall_reply_part_file_k;
    part.data.file = {descriptor, offset, length};
    return part;
}
static ucall_reply_part_t path_part(std::string_view path, std::uint64_t offset = 0, std::uint64_t length = 0,
                                    std::size_t directory = 0) {
    ucall_reply_part_t part {};
    part.kind = ucall_reply_part_path_k;
    part.data.path = {directory, uc::bytes_view(path), offset, length};
    return part;
}

/** Replies @p request with @p parts under @p headers, expecting a deferred outcome on return. */
static bool reply_parts(fixture_t& fixture, ucall_received_http_request_t request, ucall_outcome_t& outcome,
                        std::vector<ucall_reply_part_t> const& parts,
                        std::vector<ucall_bytes_view_t> const& headers = {},
                        ucall_status_t expected = ucall_status_deferred_k) {
    ucall_server_reply_vectored_t reply {fixture.server, &outcome,       request,      0,
                                         headers.data(), headers.size(), parts.data(), parts.size()};
    ucall_server_reply_vectored(&reply);
    ucall_status_t const status = ucall_outcome_status(&outcome);
    // A loop polled in the background may make a deferred outcome final before this reads it.
    bool const settled = expected == ucall_status_deferred_k && !fixture.pollers.empty();
    return expect_true(status == expected || settled, "vectored: {} rather than {}", ucall_status_name(status),
                       ucall_status_name(expected));
}

/** Bytes, two ranges of one file, two paths, one far past 2^32 in a sparse file, arrive
 *  concatenated under a measured <tt>content-length</tt>; a @c HEAD request gets the length alone.
 *  Each outcome reads deferred on return and success once sent; the file's descriptor is still open
 *  by then, and the descriptors opened for the paths are not. */
static case_result_t test_file_parts_vectored(sweep_cell_t const& cell) {
    file_tree_t tree;
    if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
    // The default cap follows the kernel's receive buffer, which BSD and macOS keep below big.bin.
    fixture_t fixture {cell, {.directory = tree.served, .max_response_bytes = std::size_t {128} << 20}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
        return {};
    std::string const hello {file_tree_t::hello_k};
    std::string const expected = fmt::format("head|{}{}|{}{}|tail", hello.substr(7), file_tree_t::big(),
                                             file_tree_t::far_text_k, hello);
    for (ucall_verb_t verb : {ucall_verb_get_k, ucall_verb_head_k}) {
        int const file = tree.open("hello.txt");
        auto* request = hold_call(fixture, verb, cell.security);
        if (!expect_true(request && file >= 0)) return {};
        std::size_t const descriptors = open_descriptors();
        ucall_outcome_t outcome {};
        reply_parts(fixture, request, outcome,
                    {bytes_part("head|"), file_part(file, 7), path_part("big.bin"), bytes_part("|"),
                     path_part("sparse.bin", file_tree_t::far_offset_k, file_tree_t::far_text_k.size()),
                     file_part(file), bytes_part("|tail")});
        auto completed = fixture.wait();
        expect_true(completed.outcome.status == ucall_status_success_k, "{}",
                    ucall_status_name(completed.outcome.status));
        if (completed.response)
            expect_true(response_header(completed.response, "content-length") == std::to_string(expected.size()),
                        "content-length {}", response_header(completed.response, "content-length"));
        check_answer(completed, ucall_http_status_ok_k, verb == ucall_verb_get_k ? expected : "");
        expect_outcome(fixture, outcome, ucall_status_success_k);
        expect_true(open_descriptor(file), "the file part's descriptor was closed");
        expect_true(open_descriptors() == descriptors, "{} descriptors open before the reply, {} after", descriptors,
                    open_descriptors());
        ::close(file);
    }
    fixture.stop();
    return {};
}

/** Ranges starting and ending on every side of the unbuffered alignment A and of a window's
 *  capacity C arrive intact from four file sizes, measured from a path and chunked from a
 *  descriptor: each window reads aligned extents covering its slice and sends the slice alone. A
 *  measured range past the end earns @c 416. */
static case_result_t test_misaligned_ranges(sweep_cell_t const& cell) {
    std::size_t const failed_before = test_run.failed_checks.load();
    file_tree_t tree;
    if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
    fixture_t fixture {cell, {.directory = tree.served}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
        return {};
    std::uint64_t const alignment = tree.directory.alignment, capacity = window_capacity_k;
    std::uint64_t const offsets[] {0, 1, alignment - 1, alignment, alignment + 1, capacity - 1, capacity, capacity + 1};
    std::uint64_t const lengths[] {1, alignment - 1, alignment, capacity + 1, 2 * capacity + 3, 0};
    for (std::uint64_t size : {capacity - 1, 2 * capacity, 3 * capacity + alignment + 5, 4 * capacity + 3}) {
        if (!expect_true(tree.write("ranged.bin", file_tree_t::big(0, size)))) return {};
        int const file = tree.open("ranged.bin");
        if (!expect_true(file >= 0)) return {};
        for (std::uint64_t offset : offsets)
            for (std::uint64_t length : lengths) {
                std::uint64_t const end = length ? offset + length : size;
                bool const fits = offset <= size && end <= size;
                std::string const body = fits ? file_tree_t::big(offset, end - offset) : std::string {};
                auto* measured = hold_call(fixture, ucall_verb_get_k, cell.security);
                if (!expect_true(measured)) return {};
                ucall_outcome_t outcome {};
                reply_parts(fixture, measured, outcome, {path_part("ranged.bin", offset, length)});
                check_answer(fixture.wait(), fits ? ucall_http_status_ok_k : ucall_http_status_range_not_satisfiable_k,
                             fits ? body : std::string_view {"Range not satisfiable"});
                expect_outcome(fixture, outcome, fits ? ucall_status_success_k : ucall_status_overflow_k);
                if (!fits) continue;
                auto* chunked = hold_call(fixture, ucall_verb_get_k, cell.security);
                if (!expect_true(chunked)) return {};
                ucall_outcome_t begun {}, appended {}, ended {};
                ucall_server_reply_begin_t begin {fixture.server, &begun, chunked, 0, nullptr, 0};
                ucall_server_reply_begin(&begin);
                ucall_reply_part_t const part = file_part(file, offset, length ? length : size - offset);
                ucall_server_reply_append_t append {fixture.server, &appended, chunked, &part, 1};
                ucall_server_reply_append(&append);
                ucall_server_reply_end_t finish {fixture.server, &ended, chunked};
                ucall_server_reply_end(&finish);
                expect_true(begun.status == ucall_status_success_k && appended.status == ucall_status_success_k,
                            "begin {}, append {}", ucall_status_name(begun.status), ucall_status_name(appended.status));
                check_answer(fixture.wait(), ucall_http_status_ok_k, body);
                expect_outcome(fixture, ended, ucall_status_success_k);
                if (test_run.failed_checks.load() != failed_before) {
                    ::close(file);
                    fixture.stop();
                    return {};
                }
            }
        ::close(file);
    }
    fixture.stop();
    return {};
}

/** A path that is missing, unreadable, a FIFO, a directory, or a link out of the directory replaces
 *  the reply with @c 404, without hanging, and a range past the end with @c 416 naming the size;
 *  the outcome turns from deferred to the cause. Paths naming @c .., absolute ones, ones holding a
 *  NUL, a backslash or a colon, and directories past the interface's list are refused at once; the
 *  caller keeps the descriptors. */
static case_result_t test_path_refusals(sweep_cell_t const& cell) {
    file_tree_t tree;
    if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
    fixture_t fixture {cell, {.directory = tree.served}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
        return {};
    std::uint64_t const size = file_tree_t::hello_k.size();
    struct row_t {
        std::string_view path;
        std::uint64_t offset, length;
        ucall_http_status_t http_status;
        ucall_status_t status;
    };
    std::vector<row_t> rows {
        {"missing.txt", 0, 0, 404, ucall_status_not_found_k},     {"fifo", 0, 0, 404, ucall_status_not_found_k},
        {"subdir", 0, 0, 404, ucall_status_not_found_k},          {"outward", 0, 0, 404, ucall_status_not_found_k},
        {"absolute", 0, 0, 404, ucall_status_not_found_k},        {"magic", 0, 0, 404, ucall_status_not_found_k},
        {"hello.txt", size + 1, 0, 416, ucall_status_overflow_k}, {"hello.txt", 1, size, 416, ucall_status_overflow_k},
        {"subdir/inner.txt", 0, 0, 200, ucall_status_success_k},
    };
    // The superuser reads any mode, so only others can see an unreadable file refused.
    if (geteuid()) rows.push_back({"locked.txt", 0, 0, 404, ucall_status_not_found_k});
    for (row_t const& row : rows)
        for (ucall_verb_t verb : {ucall_verb_get_k, ucall_verb_head_k}) {
            auto* request = hold_call(fixture, verb, cell.security);
            if (!expect_true(request)) return {};
            ucall_outcome_t outcome {};
            reply_parts(fixture, request, outcome, {bytes_part("never|"), path_part(row.path, row.offset, row.length)});
            auto completed = fixture.wait();
            expect_true(completed.outcome.status == ucall_status_success_k && completed.response, "{}",
                        ucall_status_name(completed.outcome.status));
            if (!completed.response) continue;
            auto const answered = ucall_client_response_status(completed.response);
            expect_true(answered == row.http_status, "answered {}", answered);
            if (row.http_status == 416)
                expect_true(response_header(completed.response, "content-range") == fmt::format("bytes */{}", size),
                            "content-range {}", response_header(completed.response, "content-range"));
            if (row.http_status == 200)
                expect_true(response_body(completed.response) == (verb == ucall_verb_get_k ? "never|inner" : ""));
            else expect_true(response_body(completed.response).find("never") == std::string_view::npos);
            ucall_client_response_free(completed.response);
            expect_outcome(fixture, outcome, row.status);
        }
    std::string_view const nul {"a\0b", 3};
    int const kept = tree.open("hello.txt");
    for (ucall_reply_part_t const& refused :
         {path_part("../hello.txt"), path_part("subdir/../../outside.txt"), path_part("/etc/hostname"),
          path_part("/proc/self/fd/0"), path_part(""), path_part(nul), path_part("..\\hello.txt"),
          path_part("c:hello.txt"), path_part("hello.txt", 0, 0, 1), file_part(-1)}) {
        auto* request = hold_call(fixture, ucall_verb_get_k, cell.security);
        if (!expect_true(request)) return {};
        ucall_outcome_t outcome {};
        reply_parts(fixture, request, outcome, {file_part(kept), refused}, {}, ucall_status_invalid_argument_k);
        expect_true(open_descriptor(kept), "a refused reply closed the caller's descriptor");
        ucall_server_reply_error_t error {fixture.server, &outcome, request, 400, uc::bytes_view("refused")};
        ucall_server_reply_error(&error);
        expect_true(outcome.status == ucall_status_success_k);
        check_answer(fixture.wait(), ucall_http_status_bad_request_k, "refused");
    }
    ::close(kept);
    fixture.stop();
    return {};
}

/** A descriptor that cannot switch to unbuffered reads, such as a socket, is refused on the spot,
 *  vectored or streamed: nothing of its call is queued, and the caller keeps the descriptor. */
static case_result_t test_unbufferable_descriptor_refused(sweep_cell_t const& cell) {
    return keeping_descriptors([&]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        fixture_t fixture {cell, {.directory = tree.served}};
        if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
            return {};
        int const socket_descriptor = ::socket(AF_INET, SOCK_STREAM, 0);
        if (!expect_true(socket_descriptor >= 0)) return {};
        auto* vectored = hold_call(fixture, ucall_verb_get_k, ucall_security_none_k);
        if (!expect_true(vectored)) return {};
        ucall_outcome_t outcome {};
        reply_parts(fixture, vectored, outcome, {bytes_part("never"), file_part(socket_descriptor)}, {},
                    ucall_status_invalid_argument_k);
        ucall_server_reply_error_t error {fixture.server, &outcome, vectored, 400, uc::bytes_view("refused")};
        ucall_server_reply_error(&error);
        check_answer(fixture.wait(), ucall_http_status_bad_request_k, "refused");
        auto* streamed = hold_call(fixture, ucall_verb_get_k, ucall_security_none_k);
        if (!expect_true(streamed)) return {};
        ucall_server_reply_begin_t begin {fixture.server, &outcome, streamed, 0, nullptr, 0};
        ucall_server_reply_begin(&begin);
        std::vector<ucall_reply_part_t> const refused {bytes_part("never"), file_part(socket_descriptor)};
        ucall_server_reply_append_t append {fixture.server, &outcome, streamed, refused.data(), refused.size()};
        ucall_server_reply_append(&append);
        expect_true(outcome.status == ucall_status_invalid_argument_k, "streamed: {}",
                    ucall_status_name(outcome.status));
        ucall_reply_part_t const kept = bytes_part("kept");
        ucall_server_reply_append_t again {fixture.server, &outcome, streamed, &kept, 1};
        ucall_server_reply_append(&again);
        ucall_outcome_t ended {};
        ucall_server_reply_end_t end {fixture.server, &ended, streamed};
        ucall_server_reply_end(&end);
        check_answer(fixture.wait(), ucall_http_status_ok_k, "kept");
        expect_true(open_descriptor(socket_descriptor), "the refused descriptor was closed");
        ::close(socket_descriptor);
        fixture.stop();
        return {};
    });
}

/** A path part answering a request on an interface that registered no directory is refused on the
 *  spot, while one on the interface owning the directory is served. */
static case_result_t test_path_beyond_interface(sweep_cell_t const& cell) {
    return keeping_descriptors([&]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        struct state_t {
            ucall_server_t server {};

            /** Outlives the callback, as the loop makes it final later. */
            ucall_outcome_t deferred {};
        } state;
        auto answer = [](ucall_received_http_request_t request, void* context) {
            auto& owner = *static_cast<state_t*>(context);
            ucall_outcome_t outcome {};
            std::size_t network_interface_index = 0;
            ucall_noise_key_t key {};
            ucall_peer_address_t address {};
            ucall_server_request_peer_t peer {owner.server, &outcome, request, &network_interface_index,
                                              &key,         &address};
            ucall_server_request_peer(&peer);
            ucall_reply_part_t const part = path_part("hello.txt");
            ucall_outcome_t& replied = network_interface_index ? outcome : owner.deferred;
            ucall_server_reply_vectored_t reply {owner.server, &replied, request, 0, nullptr, 0, &part, 1};
            ucall_server_reply_vectored(&reply);
            if (network_interface_index == 0) {
                expect_true(ucall_outcome_status(&replied) == ucall_status_deferred_k, "{}",
                            ucall_status_name(ucall_outcome_status(&replied)));
                return;
            }
            expect_true(outcome.status == ucall_status_invalid_argument_k, "{}", ucall_status_name(outcome.status));
            ucall_server_reply_error_t error {owner.server, &outcome, request, 400, uc::bytes_view("no directory")};
            ucall_server_reply_error(&error);
        };
        ucall_bytes_view_t directory = uc::bytes_view(tree.served);
        ucall_network_interface_t interfaces[2] {};
        for (auto& network_interface : interfaces) {
            network_interface.address = uc::bytes_view("127.0.0.1:0");
            network_interface.max_concurrent_connections = 2;
        }
        interfaces[0].reply_directories = &directory;
        interfaces[0].reply_directories_count = 1;
        ucall_server_options_t config {};
        config.interfaces = interfaces;
        config.interfaces_count = 2;
        config.backend = cell.backend;
        config.cpu_class_ceiling = cell.cpu_class_ceiling;
        ucall_server_options_t resolved {};
        ucall_outcome_t outcome {};
        ucall_server_init_t init {&state.server, &outcome, &config, &resolved};
        ucall_server_init(&init);
        if (!expect_true(outcome.status == ucall_status_success_k, "init: {}", ucall_status_name(outcome.status)))
            return {};
        expect_true(resolved.interfaces[0].reply_directories_count == 1 &&
                    uc::text_view(resolved.interfaces[0].reply_directories[0]) == tree.served);
        ucall_server_add_http_endpoint_t add {state.server,     &outcome, uc::bytes_view("/file"),
                                              ucall_verb_get_k, answer,   &state};
        ucall_server_add_http_endpoint(&add);
        std::thread serving {[&] {
            ucall_outcome_t served {};
            ucall_server_take_calls_t calls {state.server, &served, 0};
            ucall_server_take_calls(&calls);
        }};
        std::string_view const request = "GET /file HTTP/1.1\r\nHost: a\r\n\r\n";
        for (std::size_t index : {0, 1}) {
            raw_client_t client;
            if (!client.connect(uc::text_view(resolved.interfaces[index].address))) {
                expect_true(false, "connecting to interface {}", index);
                continue;
            }
            expect_true(::send(client.descriptor, request.data(), request.size(), 0) ==
                        static_cast<ssize_t>(request.size()));
            auto const response = read_response(client, 0);
            expect_true(response.status == (index ? 400u : 200u) &&
                            response.body == (index ? "no directory" : file_tree_t::hello_k),
                        "interface {} answered {} {}", index, response.status, response.body);
        }
        ucall_server_stop(state.server);
        serving.join();
        ucall_server_free(state.server);
        expect_true(ucall_outcome_status(&state.deferred) == ucall_status_success_k, "outcome {}",
                    ucall_status_name(state.deferred.status));
        // A directory that cannot be opened fails initialization with its cause.
        std::string const missing = fmt::format("{}/absent", tree.served);
        directory = uc::bytes_view(missing);
        ucall_server_t refused {};
        ucall_server_init_t again {&refused, &outcome, &config, nullptr};
        ucall_server_init(&again);
        expect_true(outcome.status == ucall_status_not_found_k && !refused, "init with a missing directory: {}",
                    ucall_status_name(outcome.status));
        ucall_server_free(refused);
        return {};
    });
}

/** Streams memory, @p file, a path and memory again from a thread, with a zero-length range
 *  between, then ends with the outcome deferred until the parts are sent. */
static void stream_parts(fixture_t& fixture, ucall_received_http_request_t request, int file, ucall_outcome_t& ended,
                         std::vector<ucall_bytes_view_t> const& headers = {}) {
    ucall_outcome_t outcome {};
    ucall_server_reply_begin_t begin {fixture.server, &outcome, request, 0, headers.data(), headers.size()};
    ucall_server_reply_begin(&begin);
    expect_true(outcome.status == ucall_status_success_k, "begin: {}", ucall_status_name(outcome.status));
    std::vector<std::vector<ucall_reply_part_t>> const chunks {
        {bytes_part("memory|"), file_part(file, 0, 5)},
        {path_part("big.bin", 1000, 300000), path_part("hello.txt", file_tree_t::hello_k.size(), 0)},
        {bytes_part(""), bytes_part("|memory")},
    };
    for (auto const& chunk : chunks) {
        ucall_server_reply_append_t append {fixture.server, &outcome, request, chunk.data(), chunk.size()};
        append_when_room(append, steady_clock::now() + wait_limit_k);
        expect_true(outcome.status == ucall_status_success_k, "chunk: {}", ucall_status_name(outcome.status));
    }
    ucall_server_reply_end_t end {fixture.server, &ended, request};
    ucall_server_reply_end(&end);
    ucall_status_t const status = ucall_outcome_status(&ended);
    expect_true(status == ucall_status_deferred_k || status == ucall_status_success_k, "end: {}",
                ucall_status_name(status));
}
static std::string streamed_parts_body() {
    return fmt::format("memory|{}{}|memory", file_tree_t::hello_k.substr(0, 5), file_tree_t::big(1000, 300000));
}

/** A chunked stream mixing memory, file and path parts, a zero-length range among them, arrives
 *  whole through the library client, and two such replies pipelined on a connection keep order. */
static case_result_t test_mixed_stream(sweep_cell_t const& cell) {
    file_tree_t tree;
    if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
    fixture_t fixture {cell,
                       {.pipelined_requests = 2,
                        .pipelined_calls = 2,
                        .directory = tree.served,
                        .max_response_bytes = std::size_t {128} << 20}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
        return {};
    std::array<std::string, 2> urls {fmt::format("{}/gate?n=0", fixture.url), fmt::format("{}/gate?n=1", fixture.url)};
    for (auto& url : urls) {
        ucall_outcome_t outcome {};
        ucall_client_call_t call {};
        call.client = fixture.client;
        call.outcome = &outcome;
        call.url = uc::bytes_view(url);
        call.verb = ucall_verb_get_k;
        call.context = &url;
        call.options.security = cell.security;
        call.options.noise_peer_key = &fixture.server_public;
        ucall_client_call(&call);
        expect_true(outcome.status == ucall_status_success_k);
    }
    await_held(fixture, 2);
    std::array<ucall_received_http_request_t, 2> requests {};
    while (auto request = fixture.take_held()) requests[fixture.query_number(request, "n")] = request;
    // The later request answers first, with a measured reply, while the earlier one streams.
    ucall_outcome_t measured {}, streamed {};
    reply_parts(fixture, requests[1], measured, {path_part("big.bin"), bytes_part("|done")});
    int const file = tree.open("hello.txt");
    std::thread streamer {[&] { stream_parts(fixture, requests[0], file, streamed); }};
    std::array<std::string, 2> const bodies {streamed_parts_body(), fmt::format("{}|done", file_tree_t::big())};
    for (std::size_t i = 0; i != 2; ++i) {
        auto completed = fixture.wait();
        expect_true(completed.context == &urls[i], "call {} completed out of order", i);
        if (i == 0 && completed.response)
            expect_true(response_header(completed.response, "transfer-encoding") == "chunked");
        check_answer(completed, ucall_http_status_ok_k, bodies[i]);
    }
    streamer.join();
    expect_outcome(fixture, measured, ucall_status_success_k);
    expect_outcome(fixture, streamed, ucall_status_success_k);
    ::close(file);
    fixture.stop();
    return {};
}

/** The same mixed stream over the wire: chunked with every file chunk framed once sized and no
 *  framing for the zero-length range, identity under a declared <tt>content-length</tt>, which
 *  refuses a part it cannot size, and delimited by the close for an HTTP/1.0 peer. */
static case_result_t test_mixed_stream_framing(sweep_cell_t const& cell) {
    return keeping_descriptors([&]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        fixture_t fixture {cell, {.connections = 3, .directory = tree.served}};
        if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
            return {};
        fixture.serve_in_background();
        std::string const body = streamed_parts_body();
        auto exchange = [&](std::string_view request, std::vector<ucall_bytes_view_t> const& headers,
                            raw_client_t& client) {
            // The stream settles unread, so its window must exceed FreeBSD's default.
            int const window = 1 << 20;
            expect_true(setsockopt(client.descriptor, SOL_SOCKET, SO_RCVBUF, &window, sizeof(window)) == 0);
            expect_true(::send(client.descriptor, request.data(), request.size(), 0) ==
                        static_cast<ssize_t>(request.size()));
            await_held_in_background(fixture, 1);
            auto* held = fixture.take_held();
            int const file = tree.open("hello.txt");
            ucall_outcome_t ended {};
            stream_parts(fixture, held, file, ended, headers);
            expect_outcome(fixture, ended, ucall_status_success_k);
            ::close(file);
        };
        raw_client_t client;
        if (!expect_true(client.connect(fixture.address))) return {};
        exchange("GET /gate HTTP/1.1\r\nHost: a\r\n\r\n", {}, client);
        std::string expected_wire;
        std::string const big = file_tree_t::big(1000, 300000);
        for (std::string_view piece : {std::string_view {"memory|"}, file_tree_t::hello_k.substr(0, 5),
                                       std::string_view {big}, std::string_view {"|memory"}})
            expected_wire += fmt::format("{:x}\r\n{}\r\n", piece.size(), piece);
        expected_wire += "0\r\n\r\n";
        auto const deadline = steady_clock::now() + wait_limit_k;
        while (client.received.find("\r\n\r\n") == std::string::npos &&
               client.read(client.received.size() + 1, deadline) == read_end_t::filled_k) {}
        std::size_t const head = client.received.find("\r\n\r\n") + 4;
        [[maybe_unused]] auto const read = client.read(head + expected_wire.size(), deadline);
        expect_true(std::string_view {client.received}.substr(head) == expected_wire,
                    "the chunked body differs over {} bytes", client.received.size() - head);
        std::string const length = fmt::format("Content-Length: {}", body.size());
        raw_client_t identity;
        if (!expect_true(identity.connect(fixture.address))) return {};
        std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
        expect_true(::send(identity.descriptor, request.data(), request.size(), 0) ==
                    static_cast<ssize_t>(request.size()));
        await_held_in_background(fixture, 1);
        auto* held = fixture.take_held();
        ucall_bytes_view_t const declared = uc::bytes_view(length);
        ucall_outcome_t outcome {};
        ucall_server_reply_begin_t begin {fixture.server, &outcome, held, 0, &declared, 1};
        ucall_server_reply_begin(&begin);
        int const file = tree.open("hello.txt");
        ucall_reply_part_t const unsized = file_part(file);
        ucall_server_reply_append_t refused {fixture.server, &outcome, held, &unsized, 1};
        ucall_server_reply_append(&refused);
        expect_true(outcome.status == ucall_status_invalid_argument_k, "an unsized part: {}",
                    ucall_status_name(outcome.status));
        std::vector<ucall_reply_part_t> const parts {bytes_part("memory|"), file_part(file, 0, 5),
                                                     path_part("big.bin", 1000, 300000), bytes_part("|memory")};
        ucall_server_reply_append_t append {fixture.server, &outcome, held, parts.data(), parts.size()};
        ucall_server_reply_append(&append);
        expect_true(outcome.status == ucall_status_success_k, "chunk: {}", ucall_status_name(outcome.status));
        ucall_outcome_t ended {};
        ucall_server_reply_end_t end {fixture.server, &ended, held};
        ucall_server_reply_end(&end);
        auto const response = read_response(identity, 0);
        expect_true(response.status == 200 && response.body == body, "identity answered {} with {} bytes",
                    response.status, response.body.size());
        expect_outcome(fixture, ended, ucall_status_success_k);
        ::close(file);
        raw_client_t legacy;
        if (!expect_true(legacy.connect(fixture.address))) return {};
        exchange("GET /gate HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", {}, legacy);
        auto const end_of_stream = legacy.read_until_close(steady_clock::now() + wait_limit_k);
        expect_true(end_of_stream == read_end_t::closed_k, "the read ended as {}", static_cast<int>(end_of_stream));
        std::size_t const legacy_head = legacy.received.find("\r\n\r\n");
        expect_true(legacy_head != std::string::npos && legacy.received.substr(legacy_head + 4) == body,
                    "the close-delimited body differs");
        fixture.stop();
        return {};
    });
}

/** Bodies around one and two whole Noise records arrive intact, whether a file read into a window,
 *  an echoed body copied into one segment of records with gaps, or a streamed chunk, so every
 *  record seals in place with no neighbour's bytes saved and restored. */
static case_result_t test_noise_record_boundaries(sweep_cell_t const& cell) {
    std::size_t const failed_before = test_run.failed_checks.load();
    return keeping_descriptors([&]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        fixture_t fixture {cell, {.directory = tree.served}};
        if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
            return {};
        // A record's payload is a 16-bit length less its kind byte and its tag.
        constexpr std::size_t payload = 65535 - 1 - 16;
        std::vector<std::size_t> sizes {payload - 1,     payload,     payload + 1,
                                        2 * payload - 1, 2 * payload, 2 * payload + 1};
        // An echo's head fills part of its first record, so these walk its body over the boundary.
        for (std::size_t size = payload - 200; size != payload - 100; ++size) sizes.push_back(size);
        for (std::size_t size : sizes) {
            std::string const body = file_tree_t::big(0, size);
            if (!expect_true(tree.write("sized.bin", body))) return {};
            auto* request = hold_call(fixture, ucall_verb_get_k, cell.security);
            if (!expect_true(request)) return {};
            ucall_outcome_t outcome {};
            reply_parts(fixture, request, outcome, {path_part("sized.bin")});
            check_answer(fixture.wait(), ucall_http_status_ok_k, body);
            expect_outcome(fixture, outcome, ucall_status_success_k);
            std::string const echo_url = fmt::format("{}/echo/1", fixture.url);
            ucall_outcome_t called {};
            ucall_client_call_t call {};
            call.client = fixture.client;
            call.outcome = &called;
            call.url = uc::bytes_view(echo_url);
            call.verb = ucall_verb_post_k;
            call.body = uc::bytes_view(body);
            call.options.security = cell.security;
            call.options.noise_peer_key = &fixture.server_public;
            ucall_client_call(&call);
            check_answer(fixture.wait(), ucall_http_status_ok_k, body);
            auto* streamed = hold_call(fixture, ucall_verb_get_k, cell.security);
            if (!expect_true(streamed)) return {};
            ucall_server_reply_begin_t begin {fixture.server, &outcome, streamed, 0, nullptr, 0};
            ucall_server_reply_begin(&begin);
            ucall_reply_part_t const chunk = bytes_part(body);
            ucall_server_reply_append_t append {fixture.server, &outcome, streamed, &chunk, 1};
            ucall_server_reply_append(&append);
            ucall_server_reply_end_t end {fixture.server, &outcome, streamed};
            ucall_server_reply_end(&end);
            check_answer(fixture.wait(), ucall_http_status_ok_k, body);
            if (test_run.failed_checks.load() != failed_before) { break; }
        }
        fixture.stop();
        return {};
    });
}

/** A file shrinking under a reply whose head left resets the connection, so the peer never takes
 *  the cut body for a whole one, and the deferred outcome reports @c ucall_status_io_k. */
static case_result_t test_short_file_reset(sweep_cell_t const& cell) {
    return keeping_descriptors([&]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        fixture_t fixture {cell, {.directory = tree.served}};
        if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
            return {};
        fixture.serve_in_background();
        // Far more than the loopback buffers hold, so the server is mid-file when it shrinks.
        int const shrinking = ::open(tree.name("shrinking.bin").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (!expect_true(shrinking >= 0 && ftruncate(shrinking, off_t {256} << 20) == 0)) return {};
        raw_client_t client;
        if (!expect_true(client.connect(fixture.address))) return {};
        std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
        expect_true(::send(client.descriptor, request.data(), request.size(), 0) ==
                    static_cast<ssize_t>(request.size()));
        await_held_in_background(fixture, 1);
        ucall_outcome_t outcome {};
        reply_parts(fixture, fixture.take_held(), outcome, {file_part(shrinking)});
        auto const deadline = steady_clock::now() + wait_limit_k;
        while (client.received.find("\r\n\r\n") == std::string::npos &&
               client.read(client.received.size() + 1, deadline) == read_end_t::filled_k) {}
        expect_true(ftruncate(shrinking, 4096) == 0);
        // The server reads on only as its peer takes what was sent, so the peer keeps reading.
        // Darwin may leave the reset unseen until the client writes into the connection it reset.
        auto end = client.read_until_close(steady_clock::now() + wait_limit_k);
        if (end != read_end_t::failed_k) {
            char const probe = 0;
            // A send the reset already refused reports it itself.
            end = ::send(client.descriptor, &probe, 1, MSG_NOSIGNAL) == 1
                      ? client.read_until_close(steady_clock::now() + wait_limit_k)
                      : read_end_t::failed_k;
        }
        int const error = errno;
        expect_true(end == read_end_t::failed_k && error == ECONNRESET, "the read ended as {} with errno {}",
                    static_cast<int>(end), error);
        expect_outcome(fixture, outcome, ucall_status_io_k);
        expect_true(open_descriptor(shrinking), "the borrowed descriptor was closed");
        ::close(shrinking);
        fixture.stop();
        return {};
    });
}

/** Under Noise, the same shrinking file fails the call and reports @c ucall_status_io_k. */
static case_result_t test_short_file_noise(sweep_cell_t const& cell) {
    return keeping_descriptors([&]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        // The client must take the whole file, past what the kernel's receive buffer would cap.
        fixture_t fixture {cell, {.directory = tree.served, .max_response_bytes = std::size_t {128} << 20}};
        if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
            return {};
        int const shrinking = ::open(tree.name("shrinking.bin").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (!expect_true(shrinking >= 0 && ftruncate(shrinking, off_t {64} << 20) == 0)) return {};
        // A lost POST is never retried, so the cut reply ends the call.
        auto* request = hold_call(fixture, ucall_verb_post_k, cell.security);
        if (!expect_true(request)) return {};
        ucall_outcome_t outcome {};
        reply_parts(fixture, request, outcome, {file_part(shrinking)});
        // A few rounds size the file and send its head and first records before it shrinks.
        for (std::size_t round = 0; round != 8; ++round) {
            ucall_completed_call_t completed {};
            expect_true(!fixture.poll(completed), "the call completed before the file shrank");
        }
        expect_true(ftruncate(shrinking, 4096) == 0);
        auto completed = fixture.wait();
        expect_true(completed.outcome.status != ucall_status_success_k, "a cut body read as whole");
        ucall_client_response_free(completed.response);
        expect_outcome(fixture, outcome, ucall_status_io_k);
        ::close(shrinking);
        fixture.stop();
        return {};
    });
}

/** A peer leaving mid-file makes the deferred outcome @c ucall_status_connection_closed_k, and the
 *  server goes on answering others. */
static case_result_t test_file_detach(sweep_cell_t const& cell) {
    return keeping_descriptors([&]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        fixture_t fixture {cell, {.connections = 2, .directory = tree.served}};
        if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
            return {};
        fixture.serve_in_background();
        int const huge = ::open(tree.name("huge.bin").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (!expect_true(huge >= 0 && ftruncate(huge, off_t {256} << 20) == 0)) return {};
        ::close(huge);
        raw_client_t client;
        if (!expect_true(client.connect(fixture.address))) return {};
        std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
        expect_true(::send(client.descriptor, request.data(), request.size(), 0) ==
                    static_cast<ssize_t>(request.size()));
        await_held_in_background(fixture, 1);
        ucall_outcome_t outcome {};
        reply_parts(fixture, fixture.take_held(), outcome, {path_part("huge.bin")});
        auto const deadline = steady_clock::now() + wait_limit_k;
        while (client.received.find("\r\n\r\n") == std::string::npos &&
               client.read(client.received.size() + 1, deadline) == read_end_t::filled_k) {}
        client.close();
        expect_outcome(fixture, outcome, ucall_status_connection_closed_k);
        raw_client_t other;
        if (!expect_true(other.connect(fixture.address))) return {};
        std::string_view const echo = "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nok";
        expect_true(::send(other.descriptor, echo.data(), echo.size(), 0) == static_cast<ssize_t>(echo.size()));
        auto const response = read_response(other, 0);
        expect_true(response.status == 200 && response.body == "ok", "answered {} {}", response.status, response.body);
        fixture.stop();
        return {};
    });
}

/** Stopping the server while it opens a reply's many paths still makes the outcome final, and
 *  freeing it leaves no descriptor open. */
static case_result_t test_stop_while_opening(sweep_cell_t const& cell) {
    return keeping_descriptors([&]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        ucall_outcome_t outcome {};
        {
            fixture_t fixture {cell, {.directory = tree.served}};
            if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
                return {};
            fixture.serve_in_background();
            raw_client_t client;
            if (!expect_true(client.connect(fixture.address))) return {};
            std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
            expect_true(::send(client.descriptor, request.data(), request.size(), 0) ==
                        static_cast<ssize_t>(request.size()));
            await_held_in_background(fixture, 1);
            std::vector<ucall_reply_part_t> parts(256, path_part("big.bin"));
            reply_parts(fixture, fixture.take_held(), outcome, parts);
            ucall_server_stop(fixture.server);
            fixture.stop();
        }
        expect_true(ucall_outcome_status(&outcome) != ucall_status_deferred_k, "the outcome stayed deferred");
        return {};
    });
}

/** Stopping the server while a peer that reads nothing holds a file's windows in its socket ends
 *  within two linger periods: the close lingers for the kernel to let go of the windows, then
 *  resets the peer, and the loop frees its pool only once every window came back. */
static case_result_t test_stop_while_releasing(sweep_cell_t const& cell) {
    return keeping_descriptors([&]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        ucall_outcome_t outcome {};
        raw_client_t client;
        {
            fixture_t fixture {cell, {.directory = tree.served}};
            if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
                return {};
            fixture.serve_in_background();
            int const huge = ::open(tree.name("huge.bin").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
            if (!expect_true(huge >= 0 && ftruncate(huge, off_t {64} << 20) == 0)) return {};
            ::close(huge);
            if (!expect_true(client.connect(fixture.address))) return {};
            int const receive_buffer_bytes = 4096;
            expect_true(setsockopt(client.descriptor, SOL_SOCKET, SO_RCVBUF, &receive_buffer_bytes,
                                   sizeof(receive_buffer_bytes)) == 0);
            std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
            expect_true(::send(client.descriptor, request.data(), request.size(), 0) ==
                        static_cast<ssize_t>(request.size()));
            await_held_in_background(fixture, 1);
            reply_parts(fixture, fixture.take_held(), outcome, {path_part("huge.bin")});
            auto const deadline = steady_clock::now() + wait_limit_k;
            while (client.received.find("\r\n\r\n") == std::string::npos &&
                   client.read(client.received.size() + 1, deadline) == read_end_t::filled_k) {}
            std::this_thread::sleep_for(50ms);
            auto const stopping = steady_clock::now();
            ucall_server_stop(fixture.server);
            fixture.stop();
            auto const stopped = steady_clock::now() - stopping;
            expect_true(stopped < 3s, "stopping took {} ms",
                        std::chrono::duration_cast<std::chrono::milliseconds>(stopped).count());
        }
        expect_true(ucall_outcome_status(&outcome) == ucall_status_connection_closed_k, "the outcome turned {}",
                    ucall_status_name(ucall_outcome_status(&outcome)));
        // A wider window drains what an orderly close still delivers instead of a trickle; Darwin
        // refuses it once the peer reset, which leaves nothing to drain anyway.
        int const wide = 1 << 20;
        [[maybe_unused]] int const widened = setsockopt(client.descriptor, SOL_SOCKET, SO_RCVBUF, &wide, sizeof(wide));
        auto const end = client.read_until_close(steady_clock::now() + wait_limit_k);
        expect_true(end == read_end_t::closed_k || end == read_end_t::failed_k, "the read ended as {}",
                    static_cast<int>(end));
        return {};
    });
}

/** One stop drains: an idle connection closes in order at once, and a held call still gets its
 *  whole reply, announced as its connection's last, before that connection closes in order. */
static void test_stop_drains_held_reply(sweep_cell_t const& cell) {
    keeping_descriptors([&] {
        ucall_outcome_t outcome {};
        raw_client_t busy, idle;
        read_end_t busy_end {}, idle_end {};
        {
            fixture_t fixture {cell, {.connections = 2}};
            if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
                return;
            fixture.serve_in_background();
            if (!expect_true(busy.connect(fixture.address) && idle.connect(fixture.address))) return;
            // A request answered first proves the idle connection was accepted before the stop.
            std::string_view const probe = "GET /missing HTTP/1.1\r\nHost: a\r\n\r\n";
            expect_true(::send(idle.descriptor, probe.data(), probe.size(), 0) == static_cast<ssize_t>(probe.size()));
            auto const deadline = steady_clock::now() + wait_limit_k;
            while (idle.received.find("Not found") == std::string::npos &&
                   idle.read(idle.received.size() + 1, deadline) == read_end_t::filled_k) {}
            std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
            expect_true(::send(busy.descriptor, request.data(), request.size(), 0) ==
                        static_cast<ssize_t>(request.size()));
            await_held_in_background(fixture, 1);
            ucall_server_stop(fixture.server);
            idle_end = idle.read_until_close(deadline);
            reply_parts(fixture, fixture.take_held(), outcome, {bytes_part("drained")});
            busy_end = busy.read_until_close(deadline);
            fixture.stop();
        }
        expect_true(idle_end == read_end_t::closed_k, "the idle connection ended as {}", static_cast<int>(idle_end));
        expect_true(busy_end == read_end_t::closed_k, "the busy connection ended as {}", static_cast<int>(busy_end));
        expect_true(
            busy.received.find("connection: close\r\n") != std::string::npos && busy.received.ends_with("drained"),
            "the drained reply read {}", busy.received);
        expect_true(ucall_outcome_status(&outcome) == ucall_status_success_k, "the outcome turned {}",
                    ucall_status_name(ucall_outcome_status(&outcome)));
    });
}

/** Opens a peer that asks for the gate, is answered a file far larger than the loopback buffers,
 *  and never reads it, so its reply is whole on the server's side and stalls in the kernel. */
static bool stall_on_file(fixture_t& fixture, raw_client_t& peer, int file, ucall_outcome_t& outcome) {
    expect_true(peer.connect(fixture.address), "a stalling peer was not accepted");
    std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
    expect_true(::send(peer.descriptor, request.data(), request.size(), 0) == static_cast<ssize_t>(request.size()));
    await_held_in_background(fixture, 1);
    return reply_parts(fixture, fixture.take_held(), outcome, {file_part(file)});
}

/** Whether the server reset @p peer by @p deadline, learned without reading, since a read would
 *  let its stalled reply flow again. */
static bool reset_unread(raw_client_t const& peer, steady_clock::time_point deadline) {
    auto const left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - steady_clock::now());
    pollfd watched {peer.descriptor, 0, 0};
    if (::poll(&watched, 1, static_cast<int>(fu::max_of<long long>(left.count(), 0))) <= 0) return false;
    int error = 0;
    socklen_t length = sizeof(error);
    return getsockopt(peer.descriptor, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == ECONNRESET;
}

/** At its connection budget, with every connection held by a peer that stopped reading its reply,
 *  a first arriving peer is parked and a second one's arrival resets a stalled connection for it,
 *  so peers that never read cannot keep the interface closed to new ones. */
static case_result_t test_stalled_senders_evicted(sweep_cell_t const& cell) {
    return keeping_descriptors([&]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        fixture_t fixture {cell, {.connections = 2, .directory = tree.served}};
        if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
            return {};
        fixture.serve_in_background();
        int const large = ::open(tree.name("large.bin").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (!expect_true(large >= 0 && ftruncate(large, off_t {256} << 20) == 0)) return {};
        raw_client_t stalled[2], parked, queued;
        ucall_outcome_t outcomes[2] {};
        for (std::size_t i = 0; i != 2; ++i) stall_on_file(fixture, stalled[i], large, outcomes[i]);
        // The kernel buffers fill and the sends stop completing well within this.
        std::this_thread::sleep_for(200ms);
        std::string_view const echo = "GET /echo/1 HTTP/1.1\r\nHost: a\r\n\r\n";
        if (!expect_true(parked.connect(fixture.address))) return {};
        expect_true(::send(parked.descriptor, echo.data(), echo.size(), 0) == static_cast<ssize_t>(echo.size()));
        expect_true(parked.read(1, steady_clock::now() + 300ms) != read_end_t::filled_k,
                    "a lone arrival was served past a budget of busy connections");
        if (!expect_true(queued.connect(fixture.address))) return {};
        expect_true(read_response(parked, 0).status == 200, "the parked peer was not served");
        std::size_t resets = 0;
        for (raw_client_t const& peer : stalled) resets += reset_unread(peer, steady_clock::now() + 200ms);
        expect_true(resets == 1, "{} stalled connections were reset for one admitted peer", resets);
        ::close(large);
        fixture.stop();
        return {};
    });
}

/** A drain cuts a peer that stopped reading its reply once the connections that still progress
 *  closed, rather than waiting on it for a second stop. */
static case_result_t test_drain_cuts_stalled_sender(sweep_cell_t const& cell) {
    return keeping_descriptors([&]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        fixture_t fixture {cell, {.connections = 2, .directory = tree.served}};
        if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
            return {};
        fixture.serve_in_background();
        int const large = ::open(tree.name("large.bin").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (!expect_true(large >= 0 && ftruncate(large, off_t {256} << 20) == 0)) return {};
        raw_client_t stalled, busy;
        ucall_outcome_t stalled_outcome {}, busy_outcome {};
        stall_on_file(fixture, stalled, large, stalled_outcome);
        if (!expect_true(busy.connect(fixture.address))) return {};
        std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
        expect_true(::send(busy.descriptor, request.data(), request.size(), 0) == static_cast<ssize_t>(request.size()));
        await_held_in_background(fixture, 1);
        std::this_thread::sleep_for(200ms);
        ucall_server_stop(fixture.server);
        // The drain's first pass must see the stalled send before the busy connection closes.
        std::this_thread::sleep_for(100ms);
        reply_parts(fixture, fixture.take_held(), busy_outcome, {bytes_part("drained")});
        expect_true(busy.read_until_close(steady_clock::now() + 2s) == read_end_t::closed_k &&
                        busy.received.ends_with("drained"),
                    "the busy connection lost its drained reply");
        // The busy connection lingers for its peer's close before its record frees.
        busy.close();
        expect_true(reset_unread(stalled, steady_clock::now() + 3s), "the stalled connection was not reset");
        ::close(large);
        fixture.stop();
        return {};
    });
}

/** A second stop, while a peer that reads slowly holds a path reply cut off past its head, resets
 *  the peer at once, rather than closing in order behind the unsent body or lingering. */
static case_result_t test_stop_resets_held_replies(sweep_cell_t const& cell) {
    return keeping_descriptors([&]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        ucall_outcome_t outcome {};
        raw_client_t client;
        auto stopping = steady_clock::now();
        {
            fixture_t fixture {cell, {.directory = tree.served}};
            if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
                return {};
            fixture.serve_in_background();
            int const huge = ::open(tree.name("huge.bin").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
            if (!expect_true(huge >= 0 && ftruncate(huge, off_t {64} << 20) == 0)) return {};
            ::close(huge);
            if (!expect_true(client.connect(fixture.address))) return {};
            int const receive_buffer_bytes = 4096;
            expect_true(setsockopt(client.descriptor, SOL_SOCKET, SO_RCVBUF, &receive_buffer_bytes,
                                   sizeof(receive_buffer_bytes)) == 0);
            std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
            expect_true(::send(client.descriptor, request.data(), request.size(), 0) ==
                        static_cast<ssize_t>(request.size()));
            await_held_in_background(fixture, 1);
            reply_parts(fixture, fixture.take_held(), outcome, {path_part("huge.bin")});
            auto const deadline = steady_clock::now() + wait_limit_k;
            while (client.received.find("\r\n\r\n") == std::string::npos &&
                   client.read(client.received.size() + 1, deadline) == read_end_t::filled_k) {}
            std::this_thread::sleep_for(50ms);
            stopping = steady_clock::now();
            ucall_server_stop(fixture.server);
            fixture.stop();
        }
        auto const end = client.read_until_close(stopping + 1s);
        auto const ended = std::chrono::duration_cast<std::chrono::milliseconds>(steady_clock::now() - stopping);
        expect_true(end == read_end_t::failed_k || end == read_end_t::closed_k, "the read ended as {} after {} ms",
                    static_cast<int>(end), ended.count());
        expect_true(ucall_outcome_status(&outcome) == ucall_status_connection_closed_k, "the outcome turned {}",
                    ucall_status_name(ucall_outcome_status(&outcome)));
        return {};
    });
}

/** A client freed on another thread that drives a ring of its own retires its own ring, as a
 *  language runtime's collector may free it anywhere, rather than spinning on the other ring. */
static void test_client_free_on_another_ring_thread(sweep_cell_t const& cell) {
    keeping_descriptors([&] {
        fixture_t fixture {cell, {}};
        if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
            return;
        auto completed = call_and_wait(fixture, ucall_verb_get_k, "/echo/1", ucall_security_none_k);
        if (completed.response) ucall_client_response_free(completed.response);
        // Left in flight, so the free also has to end what the polling thread started.
        std::string const url = fmt::format("{}/echo/2", fixture.url);
        ucall_outcome_t pending {};
        ucall_client_call_t call {};
        call.client = fixture.client;
        call.outcome = &pending;
        call.url = uc::bytes_view(url);
        call.verb = ucall_verb_get_k;
        ucall_client_call(&call);
        expect_true(pending.status == ucall_status_success_k, "call: {}", ucall_status_name(pending.status));
        // Shared, so a stuck thread left behind never writes into a finished case.
        auto freed = std::make_shared<std::atomic<int>>(0);
        std::thread freeing {[freed, cell, client = std::exchange(fixture.client, nullptr)] {
            ucall_client_t own {};
            ucall_outcome_t outcome {};
            ucall_client_options_t config {};
            config.max_concurrent_connections = 1;
            config.backend = cell.backend;
            config.cpu_class_ceiling = cell.cpu_class_ceiling;
            ucall_client_init_t init {&own, &outcome, &config, nullptr};
            ucall_client_init(&init);
            ucall_client_free(client);
            if (own) ucall_client_free(own);
            freed->store(outcome.status == ucall_status_success_k ? 1 : 2, std::memory_order_release);
        }};
        auto const deadline = steady_clock::now() + wait_limit_k;
        while (!freed->load(std::memory_order_acquire) && steady_clock::now() < deadline)
            std::this_thread::sleep_for(1ms);
        int const outcome = freed->load(std::memory_order_acquire);
        expect_true(outcome == 1, "the client was not freed within 5 s, or the second client did not open");
        if (outcome) freeing.join();
        else freeing.detach();
    });
}

/** A server freed off the thread that polled it, which a single-issuer ring refuses, waits for the
 *  kernel to end that ring instead of leaking what its requests may still reach. */
static void test_server_free_off_its_polling_owner(sweep_cell_t const& cell) {
    keeping_descriptors([&] {
        fixture_t fixture {cell, {}};
        if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
            return;
        std::thread owner {[&] {
            ucall_outcome_t outcome {};
            ucall_server_take_call_t serving {fixture.server, &outcome, 0, 0};
            ucall_server_take_call(&serving);
        }};
        owner.join();
        ucall_server_free(std::exchange(fixture.server, nullptr));
    });
}

/** A peer that stops reading after a reply that closes the connection holds it for at most two
 *  linger periods: the close lingers for the peer's FIN and for the kernel to let go of what it
 *  sent without copying, resets once the deadline passes with the reply still unread, and frees the
 *  one connection slot for the next peer. A copying engine closes in order. */
static case_result_t test_linger_then_reset(sweep_cell_t const& cell) {
#if UCALL_OS_POSIX_
    fixture_t fixture {cell, {}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
        return {};
    fixture.serve_in_background();
    raw_client_t silent;
    if (!expect_true(silent.connect(fixture.address))) return {};
    int const receive_buffer_bytes = 4096;
    expect_true(
        setsockopt(silent.descriptor, SOL_SOCKET, SO_RCVBUF, &receive_buffer_bytes, sizeof(receive_buffer_bytes)) == 0);
    std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    expect_true(::send(silent.descriptor, request.data(), request.size(), 0) == static_cast<ssize_t>(request.size()));
    await_held_in_background(fixture, 1);
    // Zero-copy engines take one send far past the peer's window, so its release waits on the peer,
    // while a copying engine, POSIX or kqueue, takes only what fits its socket buffer.
    bool const copies = cell.backend == ucall_io_backend_posix_k || cell.backend == ucall_io_backend_bsd_kqueue_k;
    std::string const body(copies ? 12000 : std::size_t {1} << 20, 'l');
    ucall_outcome_t outcome {};
    ucall_server_reply_content_t reply {fixture.server, &outcome, fixture.take_held(), ucall_http_status_ok_k,
                                        nullptr,        0,        uc::bytes_view(body)};
    auto const replied = steady_clock::now();
    ucall_server_reply_content(&reply);
    expect_true(outcome.status == ucall_status_success_k, "reply: {}", ucall_status_name(outcome.status));
    raw_client_t next;
    if (!expect_true(next.connect(fixture.address))) return {};
    std::string_view const echo = "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nok";
    expect_true(::send(next.descriptor, echo.data(), echo.size(), 0) == static_cast<ssize_t>(echo.size()));
    auto const response = read_response(next, 0);
    auto const freed = std::chrono::duration_cast<std::chrono::milliseconds>(steady_clock::now() - replied);
    expect_true(response.body == "ok" && freed < 4s, "the next peer was served after {} ms", freed.count());
    auto const end = silent.read_until_close(steady_clock::now() + wait_limit_k);
    int const error = errno;
    bool const reset = end == read_end_t::failed_k && error == ECONNRESET;
    bool const whole = end == read_end_t::closed_k && parse_response(silent.received).body == body;
    expect_true(copies ? whole : reset, "the read ended as {} with {} bytes", static_cast<int>(end),
                silent.received.size());
    fixture.stop();
    return {};
#else
    return case_result_t::skipped(needs_posix_sockets_k);
#endif
}

/** A ring's zero-copy send that would pin past the locked-memory limit falls back to copying, so
 *  a four-mebibyte reply still arrives whole rather than cutting the connection. */
static case_result_t test_zero_copy_pins_past_memlock(sweep_cell_t const& cell) {
    split_mix_generator_t generator {case_stream_key()};
    bool const ring = cell.backend == ucall_io_backend_linux_uring612_k ||
                      cell.backend == ucall_io_backend_linux_uring618_k;
    if (!ring) return case_result_t::skipped("needs an io_uring backend, the one pinning sends against RLIMIT_MEMLOCK");
    if (::geteuid() == 0)
        return case_result_t::skipped("needs an unprivileged user, as root pins without RLIMIT_MEMLOCK");
    std::size_t const body_length = std::size_t {4} << 20;
    fixture_t fixture {cell, {.connections = 2, .max_request_bytes = 2 * body_length}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
        return {};
    fixture.serve_in_background();
    {
        // An echo on another connection proves the loop registered rings under the lowered limit.
        // It also keeps this socket's first send zero-copy, as loopback demotes a socket after one.
        raw_client_t warm;
        if (!expect_true(warm.connect(fixture.address))) return {};
        std::string_view const echo = "POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nok";
        expect_true(warm.write(uc::byte_span(echo), 0, generator, steady_clock::now() + wait_limit_k));
        expect_true(read_response(warm, 0).status == 200, "the warm-up echo failed");
    }
    raw_client_t client;
    if (!expect_true(client.connect(fixture.address))) return {};
    std::string request = fmt::format("POST /echo/1 HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n", body_length);
    std::size_t const headers_length = request.size();
    for (std::size_t i = 0; i != body_length; ++i) request.push_back(static_cast<char>('a' + i % 23));
    rlimit original {};
    if (!expect_true(::getrlimit(RLIMIT_MEMLOCK, &original) == 0)) return {};
    rlimit lowered = original;
    lowered.rlim_cur = 0;
    expect_true(::setrlimit(RLIMIT_MEMLOCK, &lowered) == 0, "the locked-memory limit stayed");
    expect_true(client.write(uc::byte_span(request), 65536, generator, steady_clock::now() + wait_limit_k));
    auto const response = read_response(client, 0);
    expect_true(::setrlimit(RLIMIT_MEMLOCK, &original) == 0, "the locked-memory limit stayed lowered");
    expect_true(response.status == 200 && response.body.size() == body_length, "answered {} with {} bytes",
                response.status, response.body.size());
    expect_true(response.body == std::string_view {request}.substr(headers_length), "the echo arrived altered");
    auto const statistics = loop_statistics(fixture);
    expect_true(statistics.zero_copy_fallbacks > 0, "{} zero-copy sends, none fell back to copying",
                statistics.zero_copy_sends);
    fixture.stop();
    return {};
}

/** Thirty-two peers that each send <tt>connection: close</tt> yet never close fill the whole linger
 *  budget, and all expire oldest first, so a thirty-third peer in the backlog is served within a
 *  couple of linger periods. */
static void test_many_lingers_expire(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    std::size_t const lingering = 32;
    fixture_t fixture {cell, {.connections = lingering}};
    if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status))) return;
    fixture.serve_in_background();
    std::string_view const closing = "GET /echo/1 HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";
    std::vector<raw_client_t> clients(lingering);
    auto const started = steady_clock::now();
    for (auto& client : clients) {
        if (!expect_true(client.connect(fixture.address))) return;
        expect_true(client.write(uc::byte_span(closing), 0, generator, steady_clock::now() + wait_limit_k));
    }
    for (auto& client : clients) {
        auto const end = client.read_until_close(started + 3s);
        expect_true(end == read_end_t::closed_k && parse_response(client.received).status == 200,
                    "a lingering peer ended as {}", static_cast<int>(end));
    }
    raw_client_t last;
    if (!expect_true(last.connect(fixture.address))) return;
    std::string_view const echo = "GET /echo/2 HTTP/1.1\r\nHost: a\r\n\r\n";
    expect_true(last.write(uc::byte_span(echo), 0, generator, steady_clock::now() + wait_limit_k));
    expect_true(read_response(last, 0).status == 200, "the peer behind the lingers was not served");
    auto const served = std::chrono::duration_cast<std::chrono::milliseconds>(steady_clock::now() - started);
    expect_true(served < 3s, "the peer behind the lingers was served after {} ms", served.count());
    fixture.stop();
}

/** A file of eight windows sent to a peer reading slowly reads each window while the one before it
 *  waits or sends, as the loop counts at least six such overlaps, and arrives byte for byte. */
static case_result_t test_file_window_overlap(sweep_cell_t const& cell) {
    return keeping_descriptors([&]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        fixture_t fixture {cell, {.directory = tree.served}};
        if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
            return {};
        fixture.serve_in_background();
        std::string const body = file_tree_t::big(0, 8 * window_capacity_k);
        if (!expect_true(tree.write("eight.bin", body))) return {};
        raw_client_t client;
        if (!expect_true(client.connect(fixture.address))) return {};
        std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
        expect_true(::send(client.descriptor, request.data(), request.size(), 0) ==
                    static_cast<ssize_t>(request.size()));
        await_held_in_background(fixture, 1);
        std::uint64_t const before = loop_statistics(fixture).file_window_overlaps;
        ucall_outcome_t outcome {};
        reply_parts(fixture, fixture.take_held(), outcome, {path_part("eight.bin")});
        auto const deadline = steady_clock::now() + wait_limit_k;
        wire_response_t response;
        while (!(response = parse_response(client.received)).length &&
               client.read(client.received.size() + 1, deadline) == read_end_t::filled_k)
            std::this_thread::sleep_for(1ms);
        expect_true(response.status == 200 && response.body == body, "answered {} with {} bytes of {} read",
                    response.status, response.body.size(), client.received.size());
        expect_outcome(fixture, outcome, ucall_status_success_k);
        ucall_event_loop_statistics_t const statistics = loop_statistics(fixture);
        std::uint64_t const overlaps = statistics.file_window_overlaps - before;
        expect_true(overlaps >= 6, "{} reads overlapped a send", overlaps);
        fixture.stop();
        return {};
    });
}

/** A peer that never reads takes no more than its windows: eight others fetch four mebibytes each
 *  meanwhile, byte for byte, and the stalled reply ends once its peer leaves. */
static case_result_t test_file_fairness(sweep_cell_t const& cell) {
    return keeping_descriptors([&]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        constexpr std::size_t readers_count = 8;
        fixture_t fixture {cell, {.connections = readers_count + 1, .directory = tree.served}};
        if (!expect_true(fixture.status == ucall_status_success_k, "setup: {}", ucall_status_name(fixture.status)))
            return {};
        fixture.serve_in_background();
        std::string_view const request = "GET /gate HTTP/1.1\r\nHost: a\r\n\r\n";
        // Far more than loopback buffers hold, behind a small receive buffer, so it surely stalls.
        int const huge = ::open(tree.name("huge.bin").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (!expect_true(huge >= 0 && ftruncate(huge, off_t {256} << 20) == 0)) return {};
        ::close(huge);
        raw_client_t stalled;
        if (!expect_true(stalled.connect(fixture.address))) return {};
        int const receive_buffer_bytes = 4096;
        expect_true(setsockopt(stalled.descriptor, SOL_SOCKET, SO_RCVBUF, &receive_buffer_bytes,
                               sizeof(receive_buffer_bytes)) == 0);
        expect_true(::send(stalled.descriptor, request.data(), request.size(), 0) ==
                    static_cast<ssize_t>(request.size()));
        await_held_in_background(fixture, 1);
        ucall_outcome_t stalled_outcome {};
        reply_parts(fixture, fixture.take_held(), stalled_outcome, {path_part("huge.bin")});
        std::array<raw_client_t, readers_count> readers;
        for (auto& reader : readers) {
            if (!expect_true(reader.connect(fixture.address))) return {};
            expect_true(::send(reader.descriptor, request.data(), request.size(), 0) ==
                        static_cast<ssize_t>(request.size()));
        }
        await_held_in_background(fixture, readers_count);
        std::array<ucall_outcome_t, readers_count> outcomes {};
        for (auto& outcome : outcomes) reply_parts(fixture, fixture.take_held(), outcome, {path_part("big.bin")});
        std::string const expected = file_tree_t::big();
        std::vector<std::thread> threads;
        for (auto& reader : readers)
            threads.emplace_back([&] {
                auto const response = read_response(reader, 0);
                expect_true(response.status == 200 && response.body == expected, "answered {} with {} bytes",
                            response.status, response.body.size());
            });
        for (auto& thread : threads) thread.join();
        for (auto& outcome : outcomes) expect_outcome(fixture, outcome, ucall_status_success_k);
        expect_true(ucall_outcome_status(&stalled_outcome) == ucall_status_deferred_k,
                    "the stalled reply finished unread");
        stalled.close();
        expect_outcome(fixture, stalled_outcome, ucall_status_connection_closed_k);
        fixture.stop();
        return {};
    });
}

/** Once a keep-alive connection served one request, its second file reply allocates nothing: the
 *  exchange, file segment, window and segments all come back from the first. */
static case_result_t test_warm_file_reply_allocates_nothing(sweep_cell_t const& cell) {
    return keeping_descriptors([&]() -> case_result_t {
        file_tree_t tree;
        if (char const* reason = tree.unusable()) return case_result_t::skipped(reason);
        struct route_t {
            ucall_server_t server {};
            std::array<ucall_outcome_t, 3> deferred {};
            std::size_t replies {};
            static void serve(ucall_received_http_request_t request, void* context) {
                auto& route = *static_cast<route_t*>(context);
                ucall_reply_part_t const parts[] {bytes_part("head|"), path_part("big.bin", 3, 600000)};
                // The first request only warms the connection's receive buffer.
                ucall_server_reply_vectored_t reply {
                    route.server, &route.deferred[route.replies], request, 0, nullptr, 0,
                    parts,        route.replies ? 2u : 1u};
                ++route.replies;
                ucall_server_reply_vectored(&reply);
            }
        } route;
        allocation_ledger_t ledger;
        ucall_bytes_view_t const directory = uc::bytes_view(tree.served);
        ucall_network_interface_t network_interface {};
        network_interface.address = uc::bytes_view("127.0.0.1:0");
        network_interface.max_concurrent_connections = 1;
        network_interface.reply_directories = &directory;
        network_interface.reply_directories_count = 1;
        ucall_server_options_t config {}, resolved {};
        config.interfaces = &network_interface;
        config.interfaces_count = 1;
        config.backend = cell.backend;
        ucall_outcome_t outcome {};
        ucall_server_init_t init {&route.server, &outcome, &config, &resolved};
        counted_network_t::server_t::server_init(&init, counting_allocator<uc::byte_t> {ledger});
        if (!expect_true(outcome.status == ucall_status_success_k, "init: {}", ucall_status_name(outcome.status)))
            return {};
        ucall_server_add_http_endpoint_t add {route.server,     &outcome,       uc::bytes_view("/file"),
                                              ucall_verb_get_k, route_t::serve, &route};
        ucall_server_add_http_endpoint(&add);
        raw_client_t client;
        if (!expect_true(client.connect(uc::text_view(resolved.interfaces[0].address)))) return {};
        std::string const file_body = fmt::format("head|{}", file_tree_t::big(3, 600000));
        std::string_view const request = "GET /file HTTP/1.1\r\nHost: a\r\n\r\n";
        std::size_t warm_allocations = 0;
        for (std::size_t round = 0; round != 3; ++round) {
            std::string_view const expected = round ? std::string_view {file_body} : std::string_view {"head|"};
            if (round == 2) warm_allocations = ledger.allocations;
            expect_true(::send(client.descriptor, request.data(), request.size(), 0) ==
                        static_cast<ssize_t>(request.size()));
            std::size_t const offset = client.received.size();
            auto const deadline = steady_clock::now() + wait_limit_k;
            wire_response_t response;
            while (!(response = parse_response(std::string_view {client.received}.substr(offset))).length &&
                   steady_clock::now() < deadline) {
                ucall_server_take_call_t serving {route.server, &outcome, 0, 0};
                ucall_server_take_call(&serving);
                [[maybe_unused]] auto const read = client.read(client.received.size() + 1, steady_clock::now());
            }
            expect_true(response.status == 200 && response.body == expected, "round {} answered {} with {} bytes",
                        round, response.status, response.body.size());
            while (ucall_outcome_status(&route.deferred[round]) == ucall_status_deferred_k &&
                   steady_clock::now() < deadline) {
                ucall_server_take_call_t serving {route.server, &outcome, 0, 0};
                ucall_server_take_call(&serving);
            }
        }
        expect_true(ledger.allocations == warm_allocations, "the warm reply allocated {} times",
                    ledger.allocations - warm_allocations);
        client.close();
        ucall_server_free(route.server);
        expect_true(!ledger.live(), "{} allocations outlived the server", ledger.live());
        return {};
    });
}

void test_replies_cell(sweep_cell_t const& cell, split_mix_generator_t& generator) {
    if (cell.security == ucall_security_none_k) {
        test_stop_drains_held_reply(cell);
        test_client_free_on_another_ring_thread(cell);
        test_server_free_off_its_polling_owner(cell);
        test_many_lingers_expire(cell, generator);
    }
}

void run_replies_cases(sweep_cell_t const& cell, sz::string_t const& cell_label) {
    run_cell_case(cell_label, "test_file_parts_vectored", test_file_parts_vectored, cell);
    run_cell_case(cell_label, "test_misaligned_ranges", test_misaligned_ranges, cell);
    run_cell_case(cell_label, "test_path_refusals", test_path_refusals, cell);
    run_cell_case(cell_label, "test_mixed_stream", test_mixed_stream, cell);
    if (cell.security == ucall_security_noise_xx_k) {
        run_cell_case(cell_label, "test_noise_record_boundaries", test_noise_record_boundaries, cell);
        run_cell_case(cell_label, "test_short_file_noise", test_short_file_noise, cell);
    }
    if (cell.security == ucall_security_none_k) {
        run_cell_case(cell_label, "test_unbufferable_descriptor_refused", test_unbufferable_descriptor_refused, cell);
        run_cell_case(cell_label, "test_path_beyond_interface", test_path_beyond_interface, cell);
        run_cell_case(cell_label, "test_mixed_stream_framing", test_mixed_stream_framing, cell);
        run_cell_case(cell_label, "test_short_file_reset", test_short_file_reset, cell);
        run_cell_case(cell_label, "test_file_detach", test_file_detach, cell);
        run_cell_case(cell_label, "test_stop_while_opening", test_stop_while_opening, cell);
        run_cell_case(cell_label, "test_stop_while_releasing", test_stop_while_releasing, cell);
        run_cell_case(cell_label, "test_stop_resets_held_replies", test_stop_resets_held_replies, cell);
        run_cell_case(cell_label, "test_stalled_senders_evicted", test_stalled_senders_evicted, cell);
        run_cell_case(cell_label, "test_drain_cuts_stalled_sender", test_drain_cuts_stalled_sender, cell);
        run_cell_case(cell_label, "test_linger_then_reset", test_linger_then_reset, cell);
        run_cell_case(cell_label, "test_file_window_overlap", test_file_window_overlap, cell);
        run_cell_case(cell_label, "test_file_fairness", test_file_fairness, cell);
    }
    if (cell.security == ucall_security_none_k &&
        (cell.backend == ucall_io_backend_linux_uring612_k || cell.backend == ucall_io_backend_linux_uring618_k)) {
        run_cell_case(cell_label, "test_zero_copy_pins_past_memlock", test_zero_copy_pins_past_memlock, cell);
    }
    if (cell.security == ucall_security_none_k && cell.cpu_class_ceiling == ucall_cpu_class_unknown_k) {
        run_cell_case(cell_label, "test_warm_file_reply_allocates_nothing", test_warm_file_reply_allocates_nothing,
                      cell);
    }
}

#endif // UCALL_OS_POSIX_
#pragma endregion File Parts

} // namespace unum::ucall::test::network
