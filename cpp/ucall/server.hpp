/**
 *  @file cpp/ucall/server.hpp
 *  @author Ash Vardanian
 *  @date November 18, 2026
 *  @brief Servers over one or more interfaces, their routes and batch endpoints, and the requests
 *      handlers receive and reply to.
 *
 *  A server starts no thread: every handler runs on the thread polling the event loop or the batch
 *  endpoint that received its request. Handlers are @c noexcept: a plain function or a member
 *  function named as a template argument, the member's object borrowed until the server is freed,
 *  or a callable borrowed the same way, so no route keeps a record of its own.
 */
#pragma once

#include <cstddef> // `std::size_t`
#include <cstdint> // `std::intptr_t`

#include <array>       // `std::array`
#include <chrono>      // `std::chrono::microseconds`
#include <span>        // `std::span`
#include <string_view> // `std::string_view`
#include <type_traits> // `std::is_nothrow_invocable_r_v`, `std::is_object_v`
#include <utility>     // `std::exchange`, `std::move`, `std::swap`

#include "ucall/server.h"
#include "ucall/types.hpp" // `status_t`, `expected`, `deferred`, `answered_`, `owner`, `bytes_view`

namespace unum::ucall {

/** Counters of one event loop since the server started. */
using event_loop_statistics_t = ucall_event_loop_statistics_t;

/** Counters of one batch endpoint since it was registered. */
using batch_endpoint_statistics_t = ucall_batch_endpoint_statistics_t;

/** One part of a @c multipart/form-data request body, borrowing the received bytes. */
struct request_part_t {

    /** The name its @c Content-Disposition gives. */
    std::string_view name;

    /** Its @c Content-Type, empty when absent. */
    std::string_view content_type;

    /** Its payload, undecoded. */
    std::string_view data;
};

/** Who sent a request: the interface it arrived on, the client's authenticated static key, zeroed
 *  in plaintext, and its socket address. */
struct peer_t {

    /** The position of the interface among those the server answers on. */
    std::size_t network_interface_index = 0;

    /** The client's authenticated Noise static key, zeroed on plaintext interfaces. */
    ucall_noise_key_t static_key {};

    /** The client's socket address as accepted. */
    ucall_peer_address_t address {};
};

/** A reply part of bytes in memory, copied before the reply returns. */
inline ucall_reply_part_t bytes_part(std::string_view bytes) noexcept {
    return {.kind = ucall_reply_part_bytes_k, .data = {.bytes = bytes_view(bytes)}};
}

/** A reply part of a range of the caller's unbuffered descriptor, open until the reply is final. */
inline ucall_reply_part_t file_part(ucall_file_range_t range) noexcept {
    return {.kind = ucall_reply_part_file_k, .data = {.file = range}};
}

/** A reply part of a range of a file beneath one of the interface's reply directories. */
inline ucall_reply_part_t path_part(ucall_path_range_t range) noexcept {
    return {.kind = ucall_reply_part_path_k, .data = {.path = range}};
}

class request_t;

/** A reply whose head left and whose body is appended part by part until @c end; destroying it
 *  ends it and waits for its file parts to send. */
class reply_stream_t {
    ucall_server_t server_ = nullptr;
    ucall_received_http_request_t request_ = nullptr;

    friend class request_t;
    reply_stream_t(ucall_server_t server, ucall_received_http_request_t request) noexcept
        : server_(server), request_(request) {}

  public:
    reply_stream_t() noexcept = default;
    reply_stream_t(reply_stream_t&& other) noexcept
        : server_(other.server_), request_(std::exchange(other.request_, nullptr)) {}
    reply_stream_t& operator=(reply_stream_t&& other) noexcept {
        std::swap(server_, other.server_);
        std::swap(request_, other.request_);
        return *this;
    }
    reply_stream_t(reply_stream_t const&) = delete;
    reply_stream_t& operator=(reply_stream_t const&) = delete;

    ~reply_stream_t() noexcept {
        if (!request_) return;
        [[maybe_unused]] status_t const ended = std::move(*this).end().wait();
    }

    /** Queues @p parts on the body together, or none of them, answering
     *  @c status_code_t::would_block_k while the peer lags behind the parts already queued. */
    status_t append(std::span<ucall_reply_part_t const> parts) noexcept {
        ucall_server_reply_append_t arguments {.server = server_,
                                               .request = request_,
                                               .parts = parts.data(),
                                               .parts_count = parts.size()};
        return answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_server_reply_append(&arguments);
        });
    }

    /** Ends the body, final once its file parts are sent. */
    deferred<> end() && noexcept {
        return deferred<>([this](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            ucall_server_reply_end_t arguments {.server = server_, .outcome = outcome, .request = &request_};
            ucall_server_reply_end(&arguments);
        });
    }
};

/**
 *  @brief A received request, owned by one thread at a time, answered at most once.
 *
 *  Reads borrow the received bytes until the reply. A reply takes the request, as in
 *  @c std::move(request).reply(...), and a request destroyed without one answers 500. A reply the
 *  library refused leaves the request retained, answering 500 once destroyed.
 */
class request_t {
    ucall_server_t server_ = nullptr;
    ucall_received_http_request_t request_ = nullptr;

    /** Reads one counted view through a verb whose @p field receives it. */
    template <typename arguments_type_>
    expected<std::string_view> viewed_(void (*verb)(arguments_type_*),
                                       ucall_bytes_view_t* arguments_type_::* field) const noexcept {
        ucall_bytes_view_t value {};
        arguments_type_ arguments {.server = server_, .request = request_};
        arguments.*field = &value;
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            verb(&arguments);
        });
        if (status.failed()) return {{}, status};
        return {text_view_(value)};
    }

    /** Looks @p name up through one of the three verbs sharing a name and a value. */
    template <typename arguments_type_>
    expected<std::string_view> named_(void (*verb)(arguments_type_*), std::string_view name) const noexcept {
        ucall_bytes_view_t value {};
        arguments_type_ arguments {.server = server_, .request = request_, .name = bytes_view(name), .value = &value};
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            verb(&arguments);
        });
        if (status.failed()) return {{}, status};
        return {text_view_(value)};
    }

  public:
    request_t() noexcept = default;
    request_t(ucall_server_t server, ucall_received_http_request_t request) noexcept
        : server_(server), request_(request) {}
    request_t(request_t&& other) noexcept : server_(other.server_), request_(std::exchange(other.request_, nullptr)) {}
    request_t& operator=(request_t&& other) noexcept {
        std::swap(server_, other.server_);
        std::swap(request_, other.request_);
        return *this;
    }
    request_t(request_t const&) = delete;
    request_t& operator=(request_t const&) = delete;

    ~request_t() noexcept {
        if (!request_) return;
        ucall_server_reply_error_t arguments {.server = server_,
                                              .request = &request_,
                                              .http_status = ucall_http_status_internal_error_k,
                                              .message = bytes_view("The request was dropped without a reply")};
        [[maybe_unused]] status_t const answered = answered_<status_t>(
            [&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
                arguments.outcome = outcome;
                ucall_server_reply_error(&arguments);
            });
    }

    /** The HTTP method, which tells apart the requests of an endpoint taking any verb. */
    ucall_verb_t verb() const noexcept { return ucall_server_request_verb(server_, request_); }

    /** The path as sent, still percent-encoded, without the query. */
    expected<std::string_view> path() const noexcept {
        return viewed_(ucall_server_request_path, &ucall_server_request_path_t::path);
    }

    /** The query after the first '?', still percent-encoded, or empty without one. */
    expected<std::string_view> query_string() const noexcept {
        return viewed_(ucall_server_request_query, &ucall_server_request_query_t::query);
    }

    /** The body, decoded from chunked framing if it arrived that way; a streamed endpoint refuses
     *  it, as @c body_chunk pulls its body. */
    expected<std::string_view> body() const noexcept {
        return viewed_(ucall_server_request_body, &ucall_server_request_body_t::body);
    }

    /** The value the endpoint's template captured under @p name, case-sensitive. */
    expected<std::string_view> path_parameter(std::string_view name) const noexcept {
        return named_(ucall_server_request_path_parameter, name);
    }

    /** The value of query parameter @p name, case-sensitive and still percent-encoded. */
    expected<std::string_view> query(std::string_view name) const noexcept {
        return named_(ucall_server_request_query_parameter, name);
    }

    /** The value of header @p name, matched case-insensitively. */
    expected<std::string_view> header(std::string_view name) const noexcept {
        return named_(ucall_server_request_header, name);
    }

    /** Header field lines, repeated names apart. */
    std::size_t fields_count() const noexcept { return ucall_server_request_fields_count(server_, request_); }

    /** Header field line @p index in arrival order. */
    expected<field_t> field(std::size_t index) const noexcept {
        ucall_bytes_view_t name {}, value {};
        ucall_server_request_field_t arguments {.server = server_,
                                                .request = request_,
                                                .index = index,
                                                .name = &name,
                                                .value = &value};
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_server_request_field(&arguments);
        });
        if (status.failed()) return {{}, status};
        return {field_t {text_view_(name), text_view_(value)}};
    }

    /** Path components, as sent and still percent-encoded. */
    std::size_t path_segments_count() const noexcept {
        return ucall_server_request_path_segments_count(server_, request_);
    }

    /** Path component @p index, counting from zero. */
    expected<std::string_view> path_segment(std::size_t index) const noexcept {
        ucall_bytes_view_t segment {};
        ucall_server_request_path_segment_t arguments {.server = server_,
                                                       .request = request_,
                                                       .index = index,
                                                       .segment = &segment};
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_server_request_path_segment(&arguments);
        });
        if (status.failed()) return {{}, status};
        return {text_view_(segment)};
    }

    /** Parts of a @c multipart/form-data body, zero for any other body. */
    std::size_t parts_count() const noexcept { return ucall_server_request_parts_count(server_, request_); }

    /** Part @p index of a @c multipart/form-data body, its payload undecoded. */
    expected<request_part_t> part(std::size_t index) const noexcept {
        ucall_bytes_view_t name {}, content_type {}, data {};
        ucall_server_request_part_t arguments {.server = server_,
                                               .request = request_,
                                               .index = index,
                                               .name = &name,
                                               .content_type = &content_type,
                                               .data = &data};
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_server_request_part(&arguments);
        });
        if (status.failed()) return {{}, status};
        return {request_part_t {text_view_(name), text_view_(content_type), text_view_(data)}};
    }

    /** The interface the request arrived on, the client's key and its address, readable after its
     *  connection closed. */
    expected<peer_t> peer() const noexcept {
        peer_t peer;
        ucall_server_request_peer_t arguments {.server = server_,
                                               .request = request_,
                                               .network_interface_index = &peer.network_interface_index,
                                               .static_key = &peer.static_key,
                                               .address = &peer.address};
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_server_request_peer(&arguments);
        });
        if (status.failed()) return {{}, status};
        return {peer};
    }

    /**
     *  @brief Pulls the body bytes decoded since the last pull into @p into, empty once the body
     *      ended, valid until the next pull; answers a refusal, or success while the pull runs.
     *
     *  On a streamed endpoint the pull is final once the bytes arrive, which the polling thread
     *  delivers; a pull from the polling thread itself finding nothing answers
     *  @c status_code_t::would_block_k instead. On a buffered one the first pull is the whole body.
     *  The slot waits for its previous call first, if that still runs.
     */
    status_t body_chunk(deferred<std::string_view>& into) noexcept {
        into.resubmit([this](ucall_outcome_t* outcome, outputs<std::string_view>* written) noexcept {
            ucall_server_request_body_chunk_t arguments {.server = server_,
                                                         .outcome = outcome,
                                                         .request = request_,
                                                         .data = &written->value};
            ucall_server_request_body_chunk(&arguments);
        });
        if (into.status() == status_code_t::deferred_k) return {};
        return into.wait().status;
    }

    /** Replies with @p http_status, full header lines like "content-type: text/plain", and
     *  @p body, generating the length, date and server lines. */
    status_t reply(ucall_http_status_t http_status, std::span<ucall_bytes_view_t const> headers,
                   std::string_view body) && noexcept {
        ucall_server_reply_content_t arguments {.server = server_,
                                                .request = &request_,
                                                .http_status = http_status,
                                                .headers = headers.data(),
                                                .headers_count = headers.size(),
                                                .body = bytes_view(body)};
        return answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_server_reply_content(&arguments);
        });
    }

    /** Replies with an error @p http_status, 400 or above, and a plain-text @p message. */
    status_t reply_error(ucall_http_status_t http_status, std::string_view message) && noexcept {
        ucall_server_reply_error_t arguments {.server = server_,
                                              .request = &request_,
                                              .http_status = http_status,
                                              .message = bytes_view(message)};
        return answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_server_reply_error(&arguments);
        });
    }

    /**
     *  @brief Replies with @p http_status, header lines and @p parts concatenated into the body,
     *      its length measured from the files.
     *
     *  Final on return for bytes alone; with a file or path part the caller-lent slot @p into
     *  stays deferred until every part is sent, which the polling thread does, so await it there
     *  or wait elsewhere. Answers a refusal, or success while the parts send. A part failing
     *  before the head left replaces the reply with 404, 416 or 500, reported as a status. The
     *  slot waits for its previous call first, if that still runs.
     */
    status_t reply_parts(ucall_http_status_t http_status, std::span<ucall_bytes_view_t const> headers,
                         std::span<ucall_reply_part_t const> parts, deferred<>& into) && noexcept {
        into.resubmit([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            ucall_server_reply_vectored_t arguments {.server = server_,
                                                     .outcome = outcome,
                                                     .request = &request_,
                                                     .http_status = http_status,
                                                     .headers = headers.data(),
                                                     .headers_count = headers.size(),
                                                     .parts = parts.data(),
                                                     .parts_count = parts.size()};
            ucall_server_reply_vectored(&arguments);
        });
        if (into.status() == status_code_t::deferred_k) return {};
        return into.wait();
    }

    /** Sends the status line and header lines and opens a body appended part by part: chunked, or
     *  of the length a @c Content-Length line declares; a closed connection ends the reply here. */
    expected<reply_stream_t> reply_stream(ucall_http_status_t http_status,
                                          std::span<ucall_bytes_view_t const> headers) && noexcept {
        ucall_server_reply_begin_t arguments {.server = server_,
                                              .request = &request_,
                                              .http_status = http_status,
                                              .headers = headers.data(),
                                              .headers_count = headers.size()};
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_server_reply_begin(&arguments);
        });
        if (status.failed()) return {{}, status};
        return {reply_stream_t {server_, std::exchange(request_, nullptr)}};
    }
};

/** The requests one batch callback lends, each taken once by @c take or by iterating, which
 *  hands them over in arrival order. A request never taken stays unanswered until the server
 *  itself is freed, so take every one. */
class batch_t {
    ucall_server_t server_ = nullptr;
    std::span<ucall_received_http_request_t const> requests_ {};

  public:
    /** Hands over each request it passes once, as a range-for over a batch takes them all; one
     *  passed without being taken answers 500. */
    class iterator {
        ucall_server_t server_ = nullptr;
        std::span<ucall_received_http_request_t const>::iterator position_ {}, end_ {};
        request_t current_ {};

        void hold_() noexcept {
            if (position_ != end_) current_ = request_t {server_, *position_};
        }

      public:
        iterator(ucall_server_t server, std::span<ucall_received_http_request_t const>::iterator position,
                 std::span<ucall_received_http_request_t const>::iterator end) noexcept
            : server_(server), position_(position), end_(end) {
            hold_();
        }

        /** The request here, moved out, so a second dereference answers an empty request. */
        request_t operator*() noexcept { return std::move(current_); }
        iterator& operator++() noexcept {
            ++position_;
            hold_();
            return *this;
        }
        bool operator==(iterator const& other) const noexcept { return position_ == other.position_; }
    };

    batch_t(ucall_server_t server, std::span<ucall_received_http_request_t const> requests) noexcept
        : server_(server), requests_(requests) {}

    std::size_t size() const noexcept { return requests_.size(); }
    request_t take(std::size_t index) const noexcept { return {server_, requests_[index]}; }
    iterator begin() const noexcept { return {server_, requests_.begin(), requests_.end()}; }
    iterator end() const noexcept { return {server_, requests_.end(), requests_.end()}; }
};

/** A plain function handling each request of a route. */
using request_function_t = void (*)(request_t) noexcept;

/** A plain function handling each batch of a batch endpoint. */
using batch_function_t = void (*)(batch_t) noexcept;

/** A request handler with state, borrowed until the server is freed. */
template <typename handler_type_>
concept request_handler = std::is_object_v<handler_type_> &&
                          std::is_nothrow_invocable_r_v<void, handler_type_&, request_t>;

/** A batch handler with state, borrowed until the server is freed. */
template <typename handler_type_>
concept batch_handler = std::is_object_v<handler_type_> && std::is_nothrow_invocable_r_v<void, handler_type_&, batch_t>;

/** A member function of @p object_type_ handling each request, called on an object borrowed until
 *  the server is freed. */
template <auto member_, typename object_type_>
concept request_member = requires(object_type_& object, request_t request) {
    { (object.*member_)(std::move(request)) } noexcept;
};

/** A member function of @p object_type_ handling each batch, called on an object borrowed until the
 *  server is freed. */
template <auto member_, typename object_type_>
concept batch_member = requires(object_type_& object, batch_t batch) {
    { (object.*member_)(batch) } noexcept;
};

/** When a batch endpoint dispatches; zero fields take 1, 32 and 10 milliseconds. */
struct batching_t {

    /** Requests that dispatch a batch at once. */
    std::size_t min_batch_size = 0;

    /** Requests one batch holds at most. */
    std::size_t max_batch_size = 0;

    /** How long the oldest request of a smaller batch waits before it dispatches anyway. */
    std::chrono::microseconds max_latency {};
};

/** One batch endpoint, drained by one thread at a time; valid until its server is freed. */
class batch_endpoint_t {
    ucall_server_t server_ = nullptr;
    ucall_http_batch_endpoint_t endpoint_ = nullptr;

  public:
    batch_endpoint_t() noexcept = default;
    batch_endpoint_t(ucall_server_t server, ucall_http_batch_endpoint_t endpoint) noexcept
        : server_(server), endpoint_(endpoint) {}

    /** Runs the handler on this thread if a batch is due, waiting up to @p timeout for one; zero
     *  performs one nonblocking round. */
    status_t take_batch(std::chrono::microseconds timeout) const noexcept {
        ucall_server_take_batch_t arguments {.server = server_,
                                             .endpoint = endpoint_,
                                             .timeout_microseconds = static_cast<std::size_t>(timeout.count())};
        return answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_server_take_batch(&arguments);
        });
    }

    /** Runs the handler on this thread for every due batch until the server stops. */
    status_t take_batches() const noexcept {
        ucall_server_take_batches_t arguments {.server = server_, .endpoint = endpoint_};
        return answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_server_take_batches(&arguments);
        });
    }

    /** A snapshot of the endpoint's counters, readable from any thread while it is polled. */
    expected<batch_endpoint_statistics_t> statistics() const noexcept {
        batch_endpoint_statistics_t statistics {};
        ucall_server_batch_endpoint_statistics_t arguments {.server = server_,
                                                            .endpoint = endpoint_,
                                                            .statistics = &statistics};
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_server_batch_endpoint_statistics(&arguments);
        });
        if (status.failed()) return {{}, status};
        return {statistics};
    }
};

/** One address a server answers on, with the security and admission limits of the connections
 *  arriving there. */
struct interface_t {

    /** The listening address in "host:port" form; port zero picks a free one. */
    std::string_view address;

    /** A listening stream socket another owner opened, accepted on instead of @c address. */
    std::intptr_t const* listen_descriptor = nullptr;

    /** A physical device to pin the interface to, like "eth0", on Linux only. */
    std::string_view device_name;

    /** Encryption for connections accepted here. */
    ucall_security_t security = ucall_security_none_k;

    /** The server identity for handshakes, needed by every Noise mode. */
    ucall_noise_key_t const* noise_private_key = nullptr;

    /** The one initiator's static public key Noise KK admits. */
    ucall_noise_key_t const* noise_peer_key = nullptr;

    /** Vets each client's authenticated key, needed by Noise XX. */
    peer_authorizer_t peer_authorizer {};

    /** Event loops accepting here; zero means one, or a named device's receive queues. */
    std::size_t event_loops = 0;

    /** Connections open at once across this interface's loops. */
    std::size_t max_concurrent_connections = 1024;

    /** Requests one connection may have in flight; zero means one. */
    std::size_t max_pipelined_requests = 0;

    /** The largest request head and buffered body; zero takes the largest receive buffer. */
    std::size_t max_request_bytes = 0;

    /** Directories that path parts of replies resolve beneath, by position. */
    std::span<ucall_bytes_view_t const> reply_directories {};

    ucall_network_interface_t raw() const noexcept {
        return {.address = bytes_view(address),
                .listen_descriptor = listen_descriptor,
                .device_name = bytes_view(device_name),
                .security = security,
                .noise_private_key = noise_private_key,
                .noise_peer_key = noise_peer_key,
                .peer_authorizer = peer_authorizer.callback(),
                .peer_authorizer_context = peer_authorizer.context(),
                .event_loops = event_loops,
                .max_concurrent_connections = max_concurrent_connections,
                .max_pipelined_requests = max_pipelined_requests,
                .max_request_bytes = max_request_bytes,
                .reply_directories = reply_directories.data(),
                .reply_directories_count = reply_directories.size()};
    }
};

/** What a server runs on and reports through, beside its interfaces. */
struct server_options_t {

    /** Where log lines go; empty keeps the server silent. */
    log_t log {};

    /** The StatsD endpoint in "host:port" form; empty sends nothing. */
    std::string_view metrics_address;

    /** The fraction of finished requests whose latency is reported; zero means all. */
    float metrics_sample_rate = 0;

    /** The metric name prefix; empty means "ucall". */
    std::string_view metrics_prefix;

    /** Tags on every metric, each "key:value". */
    std::span<ucall_bytes_view_t const> metrics_tags {};

    /** The time between one event loop's datagrams; zero means one second. */
    std::chrono::microseconds metrics_interval {};

    /** The requested I/O backend, failing rather than substituting when it is unavailable. */
    ucall_io_backend_t backend = ucall_io_backend_automatic_k;

    /** A ceiling on the CPU class; unknown sets none. */
    ucall_cpu_class_t cpu_class_ceiling = ucall_cpu_class_unknown_k;
};

/**
 *  @brief An HTTP server over one or more interfaces, polled by application threads.
 *
 *  Register every route before any loop is polled, then poll each event loop from one thread at a
 *  time. Destroying it frees the server, which the bound clients must not outlive. A route keeps
 *  nothing here: its handler is a template argument, and a member's object or a callable is the
 *  context the library hands back.
 */
class server_t {
    owner<ucall_server_t, ucall_server_free> owner_ {};
    ucall_server_options_t resolved_ {};

    template <request_function_t function_>
    static void function_trampoline_(ucall_server_t server, ucall_received_http_request_t request, void*) noexcept {
        function_(request_t {server, request});
    }

    template <auto member_, typename object_type_>
    static void member_trampoline_(ucall_server_t server, ucall_received_http_request_t request,
                                   void* context) noexcept {
        (static_cast<object_type_*>(context)->*member_)(request_t {server, request});
    }

    template <typename handler_type_>
    static void handler_trampoline_(ucall_server_t server, ucall_received_http_request_t request,
                                    void* context) noexcept {
        (*static_cast<handler_type_*>(context))(request_t {server, request});
    }

    template <batch_function_t function_>
    static void batch_function_trampoline_(ucall_server_t server, ucall_received_http_request_t const* requests,
                                           std::size_t count, void*) noexcept {
        function_(batch_t {server, {requests, count}});
    }

    template <auto member_, typename object_type_>
    static void batch_member_trampoline_(ucall_server_t server, ucall_received_http_request_t const* requests,
                                         std::size_t count, void* context) noexcept {
        (static_cast<object_type_*>(context)->*member_)(batch_t {server, {requests, count}});
    }

    template <typename handler_type_>
    static void batch_handler_trampoline_(ucall_server_t server, ucall_received_http_request_t const* requests,
                                          std::size_t count, void* context) noexcept {
        (*static_cast<handler_type_*>(context))(batch_t {server, {requests, count}});
    }

    status_t routed_(std::string_view path, ucall_verb_t verb, ucall_body_delivery_t delivery,
                     ucall_received_http_request_callback_t callback, void* context) noexcept {
        ucall_server_add_http_endpoint_t arguments {.server = owner_.handle(),
                                                    .uri_template = bytes_view(path),
                                                    .verb = verb,
                                                    .callback = callback,
                                                    .context = context,
                                                    .body_delivery = delivery};
        return answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_server_add_http_endpoint(&arguments);
        });
    }

    expected<batch_endpoint_t> batch_routed_(std::string_view path, ucall_verb_t verb, batching_t const& batching,
                                             ucall_received_http_batch_callback_t callback, void* context) noexcept {
        ucall_http_batch_endpoint_t endpoint = nullptr;
        ucall_server_add_http_batch_endpoint_t arguments {
            .server = owner_.handle(),
            .uri_template = bytes_view(path),
            .verb = verb,
            .callback = callback,
            .context = context,
            .min_batch_size = batching.min_batch_size,
            .max_batch_size = batching.max_batch_size,
            .max_latency_microseconds = static_cast<std::size_t>(batching.max_latency.count()),
            .endpoint = &endpoint};
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_server_add_http_batch_endpoint(&arguments);
        });
        if (status.failed()) return {{}, status};
        return {batch_endpoint_t {owner_.handle(), endpoint}};
    }

  public:
    /** Starts a server answering on @p interfaces, whose callbacks it borrows until it is freed. */
    template <std::size_t count_>
    static expected<server_t> make(interface_t const (&interfaces)[count_],
                                   server_options_t const& options = {}) noexcept {
        std::array<ucall_network_interface_t, count_> lowered {};
        for (std::size_t index = 0; index != count_; ++index) lowered[index] = interfaces[index].raw();
        ucall_server_options_t const config {
            .interfaces = lowered.data(),
            .interfaces_count = lowered.size(),
            .log = options.log.raw(),
            .metrics_address = bytes_view(options.metrics_address),
            .metrics_sample_rate = options.metrics_sample_rate,
            .metrics_prefix = bytes_view(options.metrics_prefix),
            .metrics_tags = options.metrics_tags.data(),
            .metrics_tags_count = options.metrics_tags.size(),
            .metrics_interval_microseconds = static_cast<std::size_t>(options.metrics_interval.count()),
            .backend = options.backend,
            .cpu_class_ceiling = options.cpu_class_ceiling};
        server_t server;
        ucall_server_init_t arguments {.server = server.owner_.handle_field(),
                                       .options = &config,
                                       .resolved = &server.resolved_};
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_server_init(&arguments);
        });
        if (status.failed()) return {{}, status};
        return {std::move(server)};
    }

    ucall_server_t handle() const noexcept { return owner_.handle(); }

    /** Event loops the server runs, each polled by one thread at a time. */
    std::size_t event_loops() const noexcept {
        std::size_t count = 0;
        for (ucall_network_interface_t const& listener : resolved_interfaces_())
            count = listener.event_loops > count ? listener.event_loops : count;
        return count;
    }

    /** The I/O backend the server resolved to. */
    ucall_io_backend_t backend() const noexcept { return resolved_.backend; }

    /** The CPU class the server resolved to under its ceiling. */
    ucall_cpu_class_t cpu_class_ceiling() const noexcept { return resolved_.cpu_class_ceiling; }

    /** The numeric address interface @p index listens on, with the port it bound. */
    expected<std::string_view> address(std::size_t index) const noexcept {
        std::span<ucall_network_interface_t const> const interfaces = resolved_interfaces_();
        if (index >= interfaces.size())
            return {{}, status_t {status_code_t::invalid_argument_k, "The server has no such interface"}};
        return {text_view_(interfaces[index].address)};
    }

    /**
     *  @brief Routes requests matching @p path and @p verb to the plain function @p function_,
     *      which runs on the polling thread.
     *
     *  Templates capture @c {name} segments and a greedy @c {*name} tail; literal segments match
     *  before captures. A streamed @p delivery runs the handler once the headers arrive, the body
     *  still to be pulled through @c request_t::body_chunk.
     */
    template <request_function_t function_>
    status_t route(std::string_view path, ucall_verb_t verb,
                   ucall_body_delivery_t delivery = ucall_body_delivery_buffered_k) noexcept {
        return routed_(path, verb, delivery, &function_trampoline_<function_>, nullptr);
    }

    /** Routes like the function overload to the member function @p member_ of @p object, which
     *  stays borrowed until the server is freed. */
    template <auto member_, typename object_type_>
        requires request_member<member_, object_type_>
    status_t route(std::string_view path, ucall_verb_t verb, object_type_& object,
                   ucall_body_delivery_t delivery = ucall_body_delivery_buffered_k) noexcept {
        return routed_(path, verb, delivery, &member_trampoline_<member_, object_type_>, &object);
    }

    /** Routes like the function overload, borrowing a @p handler with state until the server is
     *  freed. */
    template <request_handler handler_type_>
    status_t route(std::string_view path, ucall_verb_t verb, handler_type_& handler,
                   ucall_body_delivery_t delivery = ucall_body_delivery_buffered_k) noexcept {
        return routed_(path, verb, delivery, &handler_trampoline_<handler_type_>, &handler);
    }

    /** Routes GET requests on @p path to the function or member @p handler_, the member's object
     *  following the path. */
    template <auto handler_, typename... object_types_>
    status_t get(std::string_view path, object_types_&... object) noexcept {
        return route<handler_>(path, ucall_verb_get_k, object...);
    }

    /** Routes GET requests on @p path to a borrowed @p handler. */
    template <request_handler handler_type_>
    status_t get(std::string_view path, handler_type_& handler) noexcept {
        return route(path, ucall_verb_get_k, handler);
    }

    /** Routes POST requests on @p path to the function or member @p handler_. */
    template <auto handler_, typename... object_types_>
    status_t post(std::string_view path, object_types_&... object) noexcept {
        return route<handler_>(path, ucall_verb_post_k, object...);
    }

    /** Routes POST requests on @p path to a borrowed @p handler. */
    template <request_handler handler_type_>
    status_t post(std::string_view path, handler_type_& handler) noexcept {
        return route(path, ucall_verb_post_k, handler);
    }

    /** Routes PUT requests on @p path to the function or member @p handler_. */
    template <auto handler_, typename... object_types_>
    status_t put(std::string_view path, object_types_&... object) noexcept {
        return route<handler_>(path, ucall_verb_put_k, object...);
    }

    /** Routes PUT requests on @p path to a borrowed @p handler. */
    template <request_handler handler_type_>
    status_t put(std::string_view path, handler_type_& handler) noexcept {
        return route(path, ucall_verb_put_k, handler);
    }

    /** Routes DELETE requests on @p path to the function or member @p handler_, spelled with an
     *  underscore as the method's name is a keyword. */
    template <auto handler_, typename... object_types_>
    status_t delete_(std::string_view path, object_types_&... object) noexcept {
        return route<handler_>(path, ucall_verb_delete_k, object...);
    }

    /** Routes DELETE requests on @p path to a borrowed @p handler. */
    template <request_handler handler_type_>
    status_t delete_(std::string_view path, handler_type_& handler) noexcept {
        return route(path, ucall_verb_delete_k, handler);
    }

    /** Routes PATCH requests on @p path to the function or member @p handler_. */
    template <auto handler_, typename... object_types_>
    status_t patch(std::string_view path, object_types_&... object) noexcept {
        return route<handler_>(path, ucall_verb_patch_k, object...);
    }

    /** Routes PATCH requests on @p path to a borrowed @p handler. */
    template <request_handler handler_type_>
    status_t patch(std::string_view path, handler_type_& handler) noexcept {
        return route(path, ucall_verb_patch_k, handler);
    }

    /** Collects requests matching @p path and @p verb from every event loop into one queue, which
     *  the returned endpoint drains into the plain function @p function_ on its polling thread. */
    template <batch_function_t function_>
    expected<batch_endpoint_t> batch(std::string_view path, ucall_verb_t verb, batching_t const& batching) noexcept {
        return batch_routed_(path, verb, batching, &batch_function_trampoline_<function_>, nullptr);
    }

    /** Batches like the function overload into the member function @p member_ of @p object, which
     *  stays borrowed until the server is freed. */
    template <auto member_, typename object_type_>
        requires batch_member<member_, object_type_>
    expected<batch_endpoint_t> batch(std::string_view path, ucall_verb_t verb, batching_t const& batching,
                                     object_type_& object) noexcept {
        return batch_routed_(path, verb, batching, &batch_member_trampoline_<member_, object_type_>, &object);
    }

    /** Batches like the function overload, borrowing a @p handler with state until the server is
     *  freed. */
    template <batch_handler handler_type_>
    expected<batch_endpoint_t> batch(std::string_view path, ucall_verb_t verb, batching_t const& batching,
                                     handler_type_& handler) noexcept {
        return batch_routed_(path, verb, batching, &batch_handler_trampoline_<handler_type_>, &handler);
    }

    /** Advances one event loop, running the handlers of the requests it completes on this thread,
     *  and waits up to @p timeout; @c status_code_t::connection_closed_k means the loop retired
     *  after @c stop. */
    status_t take_call(std::size_t event_loop, std::chrono::microseconds timeout) const noexcept {
        ucall_server_take_call_t arguments {.server = owner_.handle(),
                                            .event_loop_index = event_loop,
                                            .timeout_microseconds = static_cast<std::size_t>(timeout.count())};
        return answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_server_take_call(&arguments);
        });
    }

    /** Drives one event loop on this thread until @c stop or an I/O failure. */
    status_t take_calls(std::size_t event_loop) const noexcept {
        ucall_server_take_calls_t arguments {.server = owner_.handle(), .event_loop_index = event_loop};
        return answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_server_take_calls(&arguments);
        });
    }

    /** Requests shutdown from any thread, handlers included: the first call drains, answering the
     *  requests already held, and a second one cuts the replies still in flight. */
    void stop() const noexcept { ucall_server_stop(owner_.handle()); }

    /** A snapshot of one event loop's counters, readable from any thread while it is polled. */
    expected<event_loop_statistics_t> event_loop_statistics(std::size_t event_loop) const noexcept {
        event_loop_statistics_t statistics {};
        ucall_server_event_loop_statistics_t arguments {.server = owner_.handle(),
                                                        .event_loop_index = event_loop,
                                                        .statistics = &statistics};
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_server_event_loop_statistics(&arguments);
        });
        if (status.failed()) return {{}, status};
        return {statistics};
    }

  private:
    std::span<ucall_network_interface_t const> resolved_interfaces_() const noexcept {
        return {resolved_.interfaces, resolved_.interfaces_count};
    }
};

} // namespace unum::ucall
