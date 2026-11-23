/**
 *  @file cpp/ucall/client.hpp
 *  @author Ash Vardanian
 *  @date November 18, 2026
 *  @brief Clients that submit calls and take their completions, and the responses they own.
 *
 *  A client starts no thread: submitting never drives the network, and polling for completions
 *  does, on the calling thread. One owner at a time submits, polls and destroys it.
 */
#pragma once

#include <cstddef> // `std::size_t`, `std::byte`

#include <chrono>      // `std::chrono::microseconds`
#include <span>        // `std::span`
#include <string_view> // `std::string_view`
#include <utility>     // `std::exchange`, `std::swap`

#include "ucall/client.h"
#include "ucall/server.hpp" // `server_t`
#include "ucall/types.hpp"  // `status_t`, `expected`, `owner`, `answered_`, `field_t`, `bytes_view`

namespace unum::ucall {

/** What a client may hold open at once, how long it waits, and who it is under Noise; zero fields
 *  take their documented defaults, except the connection budget, which is required. */
struct client_options_t {

    /** Connections open at once; zero is refused. */
    std::size_t max_concurrent_connections = 0;

    /** Calls one connection may carry at once; zero means one. */
    std::size_t max_pipelined_calls = 0;

    /** Time budget for establishing a connection; zero means 5 seconds. */
    std::chrono::microseconds connect_timeout {};

    /** Time budget for a full exchange, queueing and redirects included; zero means 30 seconds. */
    std::chrono::microseconds call_timeout {};

    /** The client identity for Noise handshakes. */
    ucall_noise_key_t const* noise_private_key = nullptr;

    /** Vets each server's authenticated key, needed by Noise XX calls. */
    peer_authorizer_t peer_authorizer {};

    /** Where log lines go; empty keeps the client silent. */
    log_t log {};

    /** Calls admitted at once, unretrieved completions included; zero means connections times
     *  pipelined calls. */
    std::size_t max_concurrent_calls = 0;

    /** The requested I/O backend. */
    ucall_io_backend_t backend = ucall_io_backend_automatic_k;

    /** A ceiling on the CPU class; unknown sets none. */
    ucall_cpu_class_t cpu_class_ceiling = ucall_cpu_class_unknown_k;

    /** The largest response a call buffers; zero takes the largest receive buffer. */
    std::size_t max_response_bytes = 0;

    /** A server whose event loop drives this client, polled on that loop's thread only. */
    server_t const* server = nullptr;

    /** Which of @c server's event loops. */
    std::size_t event_loop = 0;
};

/** One call's time budget, retries, redirects, security and body delivery; zero fields take their
 *  defaults. */
struct client_call_options_t {

    /** Time budget including queueing and redirects; zero takes the client's. */
    std::chrono::microseconds timeout {};

    /** Additional connection attempts; zero means 3. */
    std::size_t max_retries = 0;

    /** Redirect hops followed; zero means 5. */
    std::size_t max_redirects = 0;

    /** Transport security for this call. */
    ucall_security_t security = ucall_security_none_k;

    /** The client's identity, needed by Noise KK. */
    ucall_noise_key_t const* noise_private_key = nullptr;

    /** The server's expected key, needed by Noise IK and KK. */
    ucall_noise_key_t const* noise_peer_key = nullptr;

    /** Whether the call completes once the body is buffered, or once the head arrived. */
    ucall_body_delivery_t body_delivery = ucall_body_delivery_buffered_k;
};

/** One call to submit, whose URL, header lines and body stay borrowed until it completes. */
struct client_call_t {

    /** The HTTP method. */
    ucall_verb_t verb = ucall_verb_get_k;

    /** The full URL, with an @c http or @c http+noise scheme. */
    std::string_view url;

    /** Full header lines; the host, length and user agent lines are generated. */
    std::span<ucall_bytes_view_t const> headers {};

    /** The request body; empty sends none. */
    std::string_view body;

    /** The call's own budget, security and body delivery. */
    client_call_options_t options {};
};

/** A received HTTP response, whatever its status, freed on destruction and readable after its
 *  client is gone. */
class response_t {
    ucall_client_t client_ = nullptr;
    owner<ucall_received_http_response_t, ucall_client_response_free> owner_ {};

  public:
    response_t() noexcept = default;
    response_t(ucall_client_t client, ucall_received_http_response_t response) noexcept : client_(client) {
        *owner_.handle_field() = response;
    }

    ucall_received_http_response_t handle() const noexcept { return owner_.handle(); }

    /** The status code the server sent. */
    ucall_http_status_t status_code() const noexcept { return ucall_client_response_status(owner_.handle()); }

    /** The body, decoded from chunked framing if it arrived that way; a streamed call refuses it,
     *  as @c body_chunk pulls its body. */
    expected<std::string_view> body() const noexcept {
        ucall_bytes_view_t body {};
        ucall_client_response_body_t arguments {.response = owner_.handle(), .body = &body};
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_client_response_body(&arguments);
        });
        if (status.failed()) return {{}, status};
        return {text_view_(body)};
    }

    /** The value of header @p name, matched case-insensitively. */
    expected<std::string_view> header(std::string_view name) const noexcept {
        ucall_bytes_view_t value {};
        ucall_client_response_header_t arguments {.response = owner_.handle(),
                                                  .name = bytes_view(name),
                                                  .value = &value};
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_client_response_header(&arguments);
        });
        if (status.failed()) return {{}, status};
        return {text_view_(value)};
    }

    /** Header field lines, repeated names apart. */
    std::size_t fields_count() const noexcept { return ucall_client_response_fields_count(owner_.handle()); }

    /** Header field line @p index in arrival order. */
    expected<field_t> field(std::size_t index) const noexcept {
        ucall_bytes_view_t name {}, value {};
        ucall_client_response_field_t arguments {.response = owner_.handle(),
                                                 .index = index,
                                                 .name = &name,
                                                 .value = &value};
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_client_response_field(&arguments);
        });
        if (status.failed()) return {{}, status};
        return {field_t {text_view_(name), text_view_(value)}};
    }

    /**
     *  @brief Pulls the body bytes of a streamed call decoded since the last pull, empty once the
     *      body ended, valid until the next pull.
     *
     *  Pulls run on the client's thread and never wait: with nothing decoded yet the pull answers
     *  @c status_code_t::would_block_k, and polling the client moves the next bytes in.
     */
    expected<std::string_view> body_chunk() noexcept {
        ucall_bytes_view_t data {};
        ucall_client_response_body_chunk_t arguments {.client = client_, .response = owner_.handle(), .data = &data};
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_client_response_body_chunk(&arguments);
        });
        if (status.failed()) return {{}, status};
        return {text_view_(data)};
    }
};

/** One finished call: the context it was submitted with, and its response or why none arrived. */
struct completed_t {

    /** The context passed to @c client_t::submit. */
    void* context = nullptr;

    /** The received response, whatever its HTTP status, or the failed exchange's status. */
    expected<response_t> response {{}, status_t {status_code_t::would_block_k}};
};

/** The response of the finished @p call of @p client, or why it has none, freeing what a failed
 *  call left. */
inline expected<response_t> response_of_(ucall_client_t client, ucall_completed_call_t const& call) noexcept {
    if (status_t const status {static_cast<status_code_t>(call.outcome.status), call.outcome.message};
        status.failed()) {

        ucall_client_response_free(call.response);
        return {{}, status};
    }
    if (!call.response)
        return {{}, status_t {status_code_t::internal_k, "A successful call completed without a response"}};
    return {response_t {client, call.response}};
}

/** The calls one @c client_t::take_completed finished, in the caller's storage and the order they
 *  finished, each handed over once by @c take or by iterating; the responses never taken are freed
 *  with the view. */
class completed_view_t {
    ucall_client_t client_ = nullptr;
    std::span<ucall_completed_call_t> calls_ {};

    /** Hands over @p call, leaving its slot without a response. */
    static completed_t taken_(ucall_client_t client, ucall_completed_call_t& call) noexcept {
        ucall_completed_call_t const taken = call;
        call.response = nullptr;
        return {taken.context, response_of_(client, taken)};
    }

  public:
    /** Hands over each call it passes, as a range-for over the view takes them all. */
    class iterator {
        ucall_client_t client_ = nullptr;
        std::span<ucall_completed_call_t>::iterator position_ {};

      public:
        iterator(ucall_client_t client, std::span<ucall_completed_call_t>::iterator position) noexcept
            : client_(client), position_(position) {}
        completed_t operator*() const noexcept { return taken_(client_, *position_); }
        iterator& operator++() noexcept {
            ++position_;
            return *this;
        }
        bool operator==(iterator const& other) const noexcept { return position_ == other.position_; }
    };

    completed_view_t() noexcept = default;
    completed_view_t(ucall_client_t client, std::span<ucall_completed_call_t> calls) noexcept
        : client_(client), calls_(calls) {}
    completed_view_t(completed_view_t&& other) noexcept
        : client_(other.client_), calls_(std::exchange(other.calls_, {})) {}
    completed_view_t& operator=(completed_view_t&& other) noexcept {
        std::swap(client_, other.client_);
        std::swap(calls_, other.calls_);
        return *this;
    }
    completed_view_t(completed_view_t const&) = delete;
    completed_view_t& operator=(completed_view_t const&) = delete;

    ~completed_view_t() noexcept {
        for (ucall_completed_call_t const& call : calls_) ucall_client_response_free(call.response);
    }

    std::size_t size() const noexcept { return calls_.size(); }
    completed_t take(std::size_t index) const noexcept { return taken_(client_, calls_[index]); }
    iterator begin() const noexcept { return {client_, calls_.begin()}; }
    iterator end() const noexcept { return {client_, calls_.end()}; }
};

/**
 *  @brief An HTTP client, made, submitted to, polled and destroyed by one owner at a time.
 *
 *  It owns its handle alone: completions land in storage the caller lends, and a blocking call
 *  takes its own completion out of the library, leaving the others queued there.
 */
class client_t {
    owner<ucall_client_t, ucall_client_free> owner_ {};

  public:
    /** Starts a client, which holds no connection until its first call is polled. */
    static expected<client_t> make(client_options_t const& options) noexcept {
        ucall_client_options_t const config {
            .max_concurrent_connections = options.max_concurrent_connections,
            .max_pipelined_calls = options.max_pipelined_calls,
            .connect_timeout_microseconds = static_cast<std::size_t>(options.connect_timeout.count()),
            .call_timeout_microseconds = static_cast<std::size_t>(options.call_timeout.count()),
            .noise_private_key = options.noise_private_key,
            .peer_authorizer = options.peer_authorizer.callback(),
            .peer_authorizer_context = options.peer_authorizer.context(),
            .log = options.log.raw(),
            .max_concurrent_calls = options.max_concurrent_calls,
            .backend = options.backend,
            .cpu_class_ceiling = options.cpu_class_ceiling,
            .max_response_bytes = options.max_response_bytes,
            .server = options.server ? options.server->handle() : nullptr,
            .event_loop = options.event_loop};
        client_t client;
        ucall_client_init_t arguments {.client = client.owner_.handle_field(), .options = &config};
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_client_init(&arguments);
        });
        if (status.failed()) return {{}, status};
        return {std::move(client)};
    }

    ucall_client_t handle() const noexcept { return owner_.handle(); }

    /** Admits @p call without driving the network; its one completion carries @p context. A full
     *  client refuses with @c status_code_t::contended_k until completions are taken. */
    status_t submit(client_call_t const& call, void* context) noexcept {
        client_call_options_t const& options = call.options;
        ucall_client_call_t arguments {
            .client = owner_.handle(),
            .url = bytes_view(call.url),
            .verb = call.verb,
            .headers = call.headers.data(),
            .headers_count = call.headers.size(),
            .body = bytes_view(call.body),
            .options = {.timeout_microseconds = static_cast<std::size_t>(options.timeout.count()),
                        .max_retries = options.max_retries,
                        .max_redirects = options.max_redirects,
                        .security = options.security,
                        .noise_private_key = options.noise_private_key,
                        .noise_peer_key = options.noise_peer_key,
                        .body_delivery = options.body_delivery},
            .context = context};
        return answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_client_call(&arguments);
        });
    }

    /** Drives every admitted call on this thread and fills the front of @p storage with finished
     *  ones, waiting up to @p timeout for the first; empty @p storage only advances the network. */
    expected<completed_view_t> take_completed(std::span<ucall_completed_call_t> storage,
                                              std::chrono::microseconds timeout) noexcept {
        std::size_t count = 0;
        ucall_client_take_completed_t arguments {.client = owner_.handle(),
                                                 .calls = storage.data(),
                                                 .capacity = storage.size(),
                                                 .count = &count,
                                                 .timeout_microseconds = static_cast<std::size_t>(timeout.count())};
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_client_take_completed(&arguments);
        });
        if (status.failed()) return {{}, status};
        return {completed_view_t {owner_.handle(), storage.first(count)}};
    }

    /** Submits @p call and polls until it finishes, leaving the completions of other calls queued
     *  for @c take_completed. The response arrives whatever its HTTP status. */
    expected<response_t> call(client_call_t const& call) noexcept {
        std::byte marker {};
        if (status_t const status = submit(call, &marker); status.failed()) return {{}, status};
        ucall_completed_call_t completed {};
        ucall_client_take_completed_call_t arguments {.client = owner_.handle(),
                                                      .context = &marker,
                                                      .call = &completed};
        status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
            arguments.outcome = outcome;
            ucall_client_take_completed_call(&arguments);
        });
        if (status.failed()) return {{}, status};
        return response_of_(owner_.handle(), completed);
    }

    /** Fetches @p url and polls until the response arrives. */
    expected<response_t> get(std::string_view url) noexcept { return call({.verb = ucall_verb_get_k, .url = url}); }

    /** Posts @p body to @p url and polls until the response arrives. */
    expected<response_t> post(std::string_view url, std::string_view body) noexcept {
        return call({.verb = ucall_verb_post_k, .url = url, .body = body});
    }

    /** Puts @p body at @p url and polls until the response arrives. */
    expected<response_t> put(std::string_view url, std::string_view body) noexcept {
        return call({.verb = ucall_verb_put_k, .url = url, .body = body});
    }

    /** Deletes @p url and polls until the response arrives, spelled with an underscore as the
     *  method's name is a keyword. */
    expected<response_t> delete_(std::string_view url) noexcept {
        return call({.verb = ucall_verb_delete_k, .url = url});
    }

    /** Patches @p url with @p body and polls until the response arrives. */
    expected<response_t> patch(std::string_view url, std::string_view body) noexcept {
        return call({.verb = ucall_verb_patch_k, .url = url, .body = body});
    }
};

} // namespace unum::ucall
