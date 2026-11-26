/**
 *  @file cpp/ucall/types.hpp
 *  @author Ash Vardanian
 *  @date November 18, 2026
 *  @brief Statuses and expected values, deferred calls and their awaiter, owners, byte views,
 *      and the callbacks servers and clients call, which add no logic and throw nothing.
 *
 *  Every verb answers a @c status_t, an @c expected value unpacked as @c auto @c [value, status],
 *  or a @c deferred call its one owner polls, waits on, or awaits through a caller's scheduler.
 *  Handlers are @c noexcept callables the caller keeps for the server's or the client's lifetime,
 *  so no fault unwinds through the library.
 */
#pragma once

#include <cstddef> // `std::size_t`
#include <cstring> // `std::memcmp`, `std::memcpy`

#include <concepts>    // `std::invocable`
#include <coroutine>   // `std::coroutine_handle`
#include <span>        // `std::span`
#include <string_view> // `std::string_view`
#include <type_traits> // `std::conditional_t`, `std::is_void_v`, `std::is_nothrow_invocable_r_v`
#include <utility>     // `std::exchange`, `std::move`, `std::swap`

#include "ucall/types.h" // `ucall_outcome_t`, `ucall_outcome_status`, `ucall_outcome_wait`

namespace unum::ucall {

/** What went wrong, with one enumerator per status the library reports. */
enum class status_code_t : int {
    success_k = ucall_status_success_k,
    deferred_k = ucall_status_deferred_k,
    out_of_memory_k = ucall_status_out_of_memory_k,
    io_k = ucall_status_io_k,
    malformed_k = ucall_status_malformed_k,
    internal_k = ucall_status_internal_k,
    overflow_k = ucall_status_overflow_k,
    uninitialized_k = ucall_status_uninitialized_k,
    contended_k = ucall_status_contended_k,
    unsupported_k = ucall_status_unsupported_k,
    invalid_argument_k = ucall_status_invalid_argument_k,
    not_found_k = ucall_status_not_found_k,
    already_exists_k = ucall_status_already_exists_k,
    connection_failed_k = ucall_status_connection_failed_k,
    connection_closed_k = ucall_status_connection_closed_k,
    timeout_k = ucall_status_timeout_k,
    handshake_failed_k = ucall_status_handshake_failed_k,
    peer_rejected_k = ucall_status_peer_rejected_k,
    would_block_k = ucall_status_would_block_k,
};

#pragma region Shared Core

/** Why a call failed: a code recovery branches on, and an optional static note naming the broken
 *  invariant, step or resource, for logs and regression analysis. */
struct [[nodiscard]] status_t {
    status_code_t code = status_code_t::success_k;
    char const* note = nullptr;

    constexpr status_t() noexcept = default;
    constexpr status_t(status_code_t reason, char const* detail = nullptr) noexcept : code(reason), note(detail) {}
    constexpr bool succeeded() const noexcept { return code == status_code_t::success_k; }
    constexpr bool failed() const noexcept { return code != status_code_t::success_k; }
    friend constexpr bool operator==(status_t const& status, status_code_t code) noexcept {
        return status.code == code;
    }
};

static_assert(sizeof(status_t) == 2 * sizeof(void*) && std::is_trivially_copyable_v<status_t>,
              "a status is a code and a note pointer, returned in two registers");

/** A call's value beside its status, bound natively as <tt>auto [value, status]</tt>. */
template <typename value_type_>
struct [[nodiscard]] expected {
    value_type_ value {};
    status_t status {};
};

/** Where a call writes what @p value_type_ is made of. */
template <typename value_type_>
struct outputs {

    /** The answer, which the call writes in place. */
    value_type_ value {};

    value_type_ answer() const noexcept { return value; }
};

/** A call that outputs nothing but its status. */
template <>
struct outputs<void> {};

/** Runs @p poll with @p state later on its own loop, storing the two words and allocating
 *  nothing. */
template <typename scheduler_type_>
concept a_scheduler = requires(scheduler_type_& loop, void (*poll)(void*) noexcept, void* state) {
    loop.post(poll, state);
};

template <typename value_type_, a_scheduler scheduler_type_>
class awaiter;

/**
 *  @brief A submitted call: its outcome and its outputs, owned until the call is final, while the
 *      receiver, inputs, arena and handlers it was handed stay allocated and unchanged until then.
 *
 *  It never moves, as the library writes into it, and its one owner polls @c status, blocks in
 *  @c wait or awaits @c wait on its own loop; destruction waits, so nothing the call writes into
 *  goes away under it.
 */
template <typename value_type_ = void>
class [[nodiscard]] deferred {
    ucall_outcome_t outcome_ {};
    outputs<value_type_> outputs_ {};

  public:
    /** What @c wait answers: what the blocking call would have. */
    using answer_type = std::conditional_t<std::is_void_v<value_type_>, status_t, expected<value_type_>>;

    /** An empty slot, final from the start, which @c resubmit fills. */
    deferred() noexcept = default;

    /** Runs @p submit with this call's outcome and outputs, where the library reports. */
    template <typename submit_type_>
        requires std::invocable<submit_type_ const&, ucall_outcome_t*, outputs<value_type_>*>
    explicit deferred(submit_type_ const& submit) noexcept {
        submit(&outcome_, &outputs_);
    }

    /** Waits only while the slot's previous call still runs, then runs @p submit in its place. */
    template <typename submit_type_>
        requires std::invocable<submit_type_ const&, ucall_outcome_t*, outputs<value_type_>*>
    void resubmit(submit_type_ const& submit) noexcept {
        ucall_outcome_wait(&outcome_);
        outcome_ = {};
        outputs_ = {};
        submit(&outcome_, &outputs_);
    }

    /** A call refused before it crossed, final from the start. */
    explicit deferred(status_t status) noexcept : outcome_ {static_cast<ucall_status_t>(status.code), status.note} {}

    deferred(deferred const&) = delete;
    deferred& operator=(deferred const&) = delete;
    ~deferred() noexcept { ucall_outcome_wait(&outcome_); }

    /** @c status_code_t::deferred_k until the call is final, then its final status, polled without
     *  blocking. */
    status_code_t status() noexcept { return static_cast<status_code_t>(ucall_outcome_status(&outcome_)); }

    /** Blocks until the call is final and answers what a blocking call would have. */
    answer_type wait() noexcept {
        ucall_outcome_wait(&outcome_);
        status_t const status {static_cast<status_code_t>(outcome_.status), outcome_.message};
        if constexpr (std::is_void_v<value_type_>) return status;
        else if (status.failed()) return {{}, status};
        else return {outputs_.answer()};
    }

    /** Awaits the call on @p loop, which polls its status until it is final. */
    template <a_scheduler scheduler_type_>
    awaiter<value_type_, scheduler_type_> wait(scheduler_type_& loop) noexcept {
        return {*this, loop};
    }
};

/** A @c deferred being awaited, living in the awaiting coroutine's frame: each poll reads the
 *  status word, and one not yet final posts itself again. */
template <typename value_type_, a_scheduler scheduler_type_>
class awaiter {
    deferred<value_type_>& call_;
    scheduler_type_& loop_;
    std::coroutine_handle<> caller_ {};

    static void poll_(void* state) noexcept {
        awaiter& awaited = *static_cast<awaiter*>(state);
        if (awaited.await_ready()) return awaited.caller_.resume();
        awaited.loop_.post(&poll_, state);
    }

  public:
    awaiter(deferred<value_type_>& call, scheduler_type_& loop) noexcept : call_(call), loop_(loop) {}
    bool await_ready() noexcept { return call_.status() != status_code_t::deferred_k; }
    void await_suspend(std::coroutine_handle<> caller) noexcept {
        caller_ = caller;
        loop_.post(&poll_, this);
    }
    typename deferred<value_type_>::answer_type await_resume() noexcept { return call_.wait(); }
};

/** Whether @p answer_type_ is a call the caller holds rather than a final answer. */
template <typename answer_type_>
inline constexpr bool is_deferred = false;
template <typename value_type_>
inline constexpr bool is_deferred<deferred<value_type_>> = true;

/** What a final @p answer_type_ carries beside its status, @c void for a bare @c status_t. */
template <typename answer_type_>
struct answer_value {
    using type = void;
};
template <typename value_type_>
struct answer_value<expected<value_type_>> {
    using type = value_type_;
};
template <typename answer_type_>
using answer_value_t = typename answer_value<answer_type_>::type;

/** Answers @p answer_type_ from a verb's @p body: a deferred call passes C its own outcome and
 *  outputs; a blocking call writes its outputs in place, then takes the C outcome's two words once
 *  it is final. */
template <typename answer_type_, typename body_type_>
answer_type_ answered_(body_type_ const& body) noexcept {
    if constexpr (is_deferred<answer_type_>) return answer_type_(body);
    else {
        using value_type = answer_value_t<answer_type_>;
        ucall_outcome_t reported {};
        outputs<value_type> written {};
        body(&reported, &written);
        status_t const status {static_cast<status_code_t>(reported.status), reported.message};
        if constexpr (std::is_void_v<value_type>) return status;
        else if (status.failed()) return {{}, status};
        else return {written.answer()};
    }
}

/** Answers a call refused before it crossed, final from the start. */
template <typename answer_type_>
answer_type_ answered_(status_t refused) noexcept {
    if constexpr (is_deferred<answer_type_> || std::is_same_v<answer_type_, status_t>) return answer_type_(refused);
    else return {{}, refused};
}

/** Owns one handle of @p handle_type_, which @p free_ releases, moving it and never copying it. */
template <typename handle_type_, void (*free_)(handle_type_)>
class owner {
    handle_type_ handle_ = nullptr;

  public:
    owner() noexcept = default;
    owner(owner&& other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    owner& operator=(owner&& other) noexcept {
        std::swap(handle_, other.handle_);
        return *this;
    }
    owner(owner const&) = delete;
    owner& operator=(owner const&) = delete;
    ~owner() noexcept { free_(handle_); }

    handle_type_ handle() const noexcept { return handle_; }

    /** The output field a lifecycle verb writes the new handle into. */
    handle_type_* handle_field() noexcept { return &handle_; }
};

/** Creates an @p owner_type_ through @p verb, which writes the new handle into @p field of
 *  @p arguments. */
template <typename owner_type_, typename arguments_type_, typename handle_type_>
expected<owner_type_> opened_(void (*verb)(arguments_type_*), arguments_type_& arguments,
                              handle_type_* arguments_type_::* field) noexcept {
    expected<owner_type_> opened;
    arguments.*field = opened.value.handle_field();
    opened.status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
        arguments.outcome = outcome;
        verb(&arguments);
    });
    return opened;
}

#pragma endregion Shared Core

#pragma region Bytes and Names

/** Views @p text as the counted bytes every verb reads, without a copy. */
inline ucall_bytes_view_t bytes_view(std::string_view text) noexcept {
    return {reinterpret_cast<ucall_byte_t const*>(text.data()), text.size()};
}

/** Views counted bytes the library owns as text, without a copy. */
inline std::string_view text_view_(ucall_bytes_view_t bytes) noexcept {
    return {reinterpret_cast<char const*>(bytes.data), bytes.length};
}

/** The bytes a call wrote into a counted view, read back as text once the call is final. */
template <>
struct outputs<std::string_view> {

    /** The view the call writes in place. */
    ucall_bytes_view_t value {};

    std::string_view answer() const noexcept { return text_view_(value); }
};

/** The stable lowercase spelling of @p code, such as "connection-failed". */
inline std::string_view status_name(status_code_t code) noexcept {
    return ucall_status_name(static_cast<ucall_status_t>(code));
}

/** Reads a status back from the spelling @c status_name gives it. */
inline expected<ucall_status_t> status_from_name(std::string_view name) noexcept {
    ucall_status_t parsed {};
    if (ucall_status_t const status = ucall_status_from_name(bytes_view(name), &parsed);
        status != ucall_status_success_k)
        return {{}, status_t {static_cast<status_code_t>(status), "Not a status name"}};
    return {parsed};
}

/** The stable name of an I/O backend, such as "linux-uring618". */
inline std::string_view io_backend_name(ucall_io_backend_t backend) noexcept { return ucall_io_backend_name(backend); }

/** Reads an I/O backend back from its stable name, "automatic" included. */
inline expected<ucall_io_backend_t> io_backend_from_name(std::string_view name) noexcept {
    ucall_io_backend_t parsed {};
    if (ucall_status_t const status = ucall_io_backend_from_name(bytes_view(name), &parsed);
        status != ucall_status_success_k)
        return {{}, status_t {static_cast<status_code_t>(status), "Not an I/O backend name"}};
    return {parsed};
}

/** The stable name of a CPU kernel class, such as "intel-icelake". */
inline std::string_view cpu_class_name(ucall_cpu_class_t cpu_class) noexcept { return ucall_cpu_class_name(cpu_class); }

/** Reads a CPU kernel class back from its stable name, "unknown" included. */
inline expected<ucall_cpu_class_t> cpu_class_from_name(std::string_view name) noexcept {
    ucall_cpu_class_t parsed {};
    if (ucall_status_t const status = ucall_cpu_class_from_name(bytes_view(name), &parsed);
        status != ucall_status_success_k)
        return {{}, status_t {static_cast<status_code_t>(status), "Not a CPU class name"}};
    return {parsed};
}

/** The linked library's version, a release-candidate suffix included. */
inline std::string_view version_name() noexcept { return ucall_version_name(); }

/** Decodes the percent escapes of @p encoded into @p decoded, which may alias it, and a '+' as a
 *  space in a query, answering the decoded prefix of @p decoded. */
inline expected<std::string_view> decode_percent(std::string_view encoded, std::span<char> decoded,
                                                 ucall_percent_mode_t mode) noexcept {
    if (decoded.size() < encoded.size())
        return {{}, status_t {status_code_t::invalid_argument_k, "The output is too short"}};
    std::size_t length = 0;
    ucall_byte_t* const target = reinterpret_cast<ucall_byte_t*>(decoded.data());
    ucall_status_t const status = ucall_decode_percent(bytes_view(encoded), target, &length, mode);
    if (status != ucall_status_success_k)
        return {{}, status_t {static_cast<status_code_t>(status), "A percent escape lacks two hexadecimal digits"}};
    return {std::string_view {decoded.data(), length}};
}

/** One header field line, its name lowercased and its value trimmed. */
struct field_t {

    /** The field name, lowercased as the parser keeps it. */
    std::string_view name;

    /** The field value, without surrounding whitespace. */
    std::string_view value;
};

#pragma endregion Bytes and Names

#pragma region Noise Keys

/** A static Curve25519 keypair, the private half kept secret. */
struct noise_keypair_t {

    /** The secret scalar a server interface or a client presents. */
    ucall_noise_key_t private_key {};

    /** The public key peers see during the handshake and compare in their authorizers. */
    ucall_noise_key_t public_key {};
};

/** Draws a fresh keypair from the operating system's entropy. */
inline expected<noise_keypair_t> noise_key_generate() noexcept {
    noise_keypair_t keypair;
    ucall_noise_key_generate_t arguments {.private_key = &keypair.private_key, .public_key = &keypair.public_key};
    status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
        arguments.outcome = outcome;
        ucall_noise_key_generate(&arguments);
    });
    if (status.failed()) return {{}, status};
    return {keypair};
}

/** Derives the public half of a stored @p private_key, answering both halves. */
inline expected<noise_keypair_t> noise_key_derive(ucall_noise_key_t const& private_key) noexcept {
    noise_keypair_t keypair;
    std::memcpy(keypair.private_key, private_key, sizeof(ucall_noise_key_t));
    ucall_noise_key_derive_t arguments {.private_key = &keypair.private_key, .public_key = &keypair.public_key};
    status_t const status = answered_<status_t>([&](ucall_outcome_t* outcome, outputs<void>*) noexcept {
        arguments.outcome = outcome;
        ucall_noise_key_derive(&arguments);
    });
    if (status.failed()) return {{}, status};
    return {keypair};
}

/** Whether two keys hold the same bytes, as an authorizer compares a peer with the one expected. */
inline bool noise_keys_equal(ucall_noise_key_t const& first, ucall_noise_key_t const& second) noexcept {
    return std::memcmp(first, second, sizeof(ucall_noise_key_t)) == 0;
}

#pragma endregion Noise Keys

#pragma region Callbacks

/** A peer authorizer: hears a peer's authenticated static key and answers whether it may go on,
 *  through a const call operator, since several polling loops may call it at once. */
template <typename handler_type_>
concept a_peer_authorizer = std::is_object_v<handler_type_> &&
                            std::is_nothrow_invocable_r_v<bool, handler_type_ const&, ucall_noise_key_t const&>;

/** A log handler: hears each formatted line and its level, through a const call operator, since
 *  every thread that logs may call it at once. */
template <typename handler_type_>
concept a_log_handler = std::is_object_v<handler_type_> &&
                        std::is_nothrow_invocable_r_v<void, handler_type_ const&, ucall_log_level_t, std::string_view>;

/** A peer authorizer the caller keeps for the server's or the client's lifetime; empty admits
 *  nobody under Noise XX, which needs one. */
class peer_authorizer_t {
    ucall_peer_authorizer_t callback_ = nullptr;
    void* context_ = nullptr;

    template <typename handler_type_>
    static ucall_status_t trampoline_(ucall_noise_key_t const* key, void* context) noexcept {
        if ((*static_cast<handler_type_ const*>(context))(*key)) return ucall_status_success_k;
        return ucall_status_peer_rejected_k;
    }

  public:
    peer_authorizer_t() noexcept = default;

    /** Asks @p handler about every authenticated peer, referring to it until the owner is freed. */
    template <a_peer_authorizer handler_type_>
    peer_authorizer_t(handler_type_& handler) noexcept : callback_(&trampoline_<handler_type_>), context_(&handler) {}

    ucall_peer_authorizer_t callback() const noexcept { return callback_; }
    void* context() const noexcept { return context_; }
};

/** The log sink of a server or a client: a handler the caller keeps for its lifetime, the line
 *  format, and the least severe level formatted; empty logs nothing. */
class log_t {
    ucall_log_t raw_ {};

    template <typename handler_type_>
    static void trampoline_(ucall_log_level_t level, ucall_bytes_view_t line, void* context) noexcept {
        (*static_cast<handler_type_ const*>(context))(level, text_view_(line));
    }

  public:
    log_t() noexcept = default;

    /** Hears every line at or above @p level in @p format through @p handler. */
    template <a_log_handler handler_type_>
    log_t(handler_type_& handler, ucall_log_format_t format = ucall_log_format_human_k,
          ucall_log_level_t level = ucall_log_level_debug_k) noexcept
        : raw_ {&trampoline_<handler_type_>, &handler, format, level} {}

    ucall_log_t raw() const noexcept { return raw_; }
};

#pragma endregion Callbacks

} // namespace unum::ucall
