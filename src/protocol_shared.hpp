#pragma once

#if defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
#define UCALL_IS_WINDOWS
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

#if defined(__linux__)
#define UCALL_IS_LINUX
#endif

#if defined(UCALL_IS_WINDOWS)
#include <Windows.h>
#else
#include <sys/mman.h>
#endif

#include <atomic>
#include <cerrno>
#include <cstring>
#include <memory>
#include <string_view> // `std::string_view`

#if defined(__x86_64__)
#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
#endif

#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <simdjson.h>

#include <ucall/ucall.h> // `ucall_callback_t`

namespace unum::ucall {

using descriptor_t = ssize_t;
using network_data_t = void*;

/// @brief To avoid dynamic memory allocations on tiny requests,
/// for every connection we keep a tiny embedded buffer of this capacity.
static constexpr std::size_t ram_page_size_k = 4096;

/// @brief The maximum length of JSON-Pointer, we will use
/// to lookup parameters in heavily nested requests.
/// A performance-oriented API will have maximum depth of 1 token.
/// Some may go as far as 5 token, or roughly 50 character.
static constexpr std::size_t json_pointer_capacity_k = 256;
/// @brief Number of bytes in a printed integer.
/// Used either for error codes, or for request IDs.
static constexpr std::size_t max_integer_length_k = 32;
/// @brief Needed for largest-register-aligned memory addressing.
static constexpr std::size_t align_k = 64;
/// @brief Accessing real time from user-space is very expensive.
/// To approximate we can use CPU cycle counters.
constexpr std::size_t cpu_cycles_per_micro_second_k = 3'000;

// /// @brief As we use SIMDJSON, we don't want to fill our message buffers entirely.
// /// If there is a @b padding at the end, matching the size of the largest CPU register
// /// on the machine, we would avoid copies.
// static constexpr std::size_t max_embedded_length_k{ram_page_size_k - sj::SIMDJSON_PADDING};

static constexpr descriptor_t invalid_descriptor_k{-1};
static constexpr std::size_t max_inactive_duration_ns_k{10'000'000'000}; // 10 sec
static constexpr std::size_t wakeup_initial_frequency_ns_k{100};
static constexpr std::size_t sleep_growth_factor_k{2};

static constexpr descriptor_t bad_descriptor_k{-1};

using any_param_t = std::variant<nullptr_t, bool, int64_t, double, std::string_view>;

struct default_error_t {
    int code{};
    std::string_view note;
};

inline std::size_t string_length(char const* c_str, std::size_t optional_length) noexcept {
    return c_str && !optional_length ? std::strlen(c_str) : optional_length;
}

/**
 * @brief Rounds integer to the next multiple of a given number. Is needed for aligned memory allocations.
 */
template <std::size_t step_ak> constexpr std::size_t round_up_to(std::size_t n) noexcept {
    return ((n + step_ak - 1) / step_ak) * step_ak;
}

struct parsed_request_t {
    ucall_verb_t type{};
    std::string_view path{};
    std::string_view content_type{};
    std::string_view content_length{};
    std::string_view body{};
};

enum class stage_t {
    waiting_to_accept_k = 0,
    expecting_reception_k,
    responding_in_progress_k,
    waiting_to_close_k,
    log_stats_k,
    unknown_k,
};

class alignas(align_k) mutex_t {
    std::atomic<bool> flag{false};

  public:
    void lock() noexcept {
        while (flag.exchange(true, std::memory_order_relaxed))
            ;
        std::atomic_thread_fence(std::memory_order_acquire);
    }

    void unlock() noexcept {
        std::atomic_thread_fence(std::memory_order_release);
        flag.store(false, std::memory_order_relaxed);
    }
};

struct memory_map_t {
    char* ptr{};
    std::size_t length{};

    memory_map_t() = default;
    memory_map_t(memory_map_t const&) = delete;
    memory_map_t& operator=(memory_map_t const&) = delete;

    memory_map_t(memory_map_t&& other) noexcept {
        std::swap(ptr, other.ptr);
        std::swap(length, other.length);
    }

    memory_map_t& operator=(memory_map_t&& other) noexcept {
        std::swap(ptr, other.ptr);
        std::swap(length, other.length);
        return *this;
    }

    bool reserve(std::size_t length) noexcept {
#if defined(UCALL_IS_WINDOWS)
        HANDLE hFile = INVALID_HANDLE_VALUE;
        HANDLE hMap = CreateFileMapping(hFile, nullptr, PAGE_READWRITE, 0, length, nullptr);
        if (hMap == nullptr)
            return false;

        char* new_ptr = (char*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, length); // Map a view of the file
        if (new_ptr == nullptr) {
            CloseHandle(hMap);
            return false;
        }
#else
        // Use mmap for Linux and other POSIX systems
        // Make sure that the `length` is a multiple of `page_size`
        // auto page_size = sysconf(_SC_PAGE_SIZE);
        char* new_ptr = (char*)mmap(ptr, length, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (new_ptr == MAP_FAILED) {
            errno;
            return false;
        }
#endif
        std::memset(new_ptr, 0, length);
        ptr = new_ptr;
        return true;
    }

    ~memory_map_t() noexcept {
#if defined(UCALL_IS_WINDOWS)
        if (ptr)
            UnmapViewOfFile(ptr); // Unmap the view of the file
#else
        if (ptr)
            munmap(ptr, length);
#endif
        ptr = nullptr;
        length = 0;
    }
};

template <typename element_at> class buffer_gt {
    element_at* elements_{};
    std::size_t capacity_{};
    static_assert(std::is_nothrow_default_constructible<element_at>());

  public:
    buffer_gt() noexcept = default;
    buffer_gt(buffer_gt&&) = delete;
    buffer_gt(buffer_gt const&) = delete;
    buffer_gt& operator=(buffer_gt const&) = delete;

    buffer_gt& operator=(buffer_gt&& other) noexcept {
        std::swap(elements_, other.elements_);
        std::swap(capacity_, other.capacity_);
        return *this;
    }
    [[nodiscard]] bool resize(std::size_t n) noexcept {
        elements_ = (element_at*)std::malloc(sizeof(element_at) * n);
        if (!elements_)
            return false;
        capacity_ = n;
        std::uninitialized_default_construct(elements_, elements_ + capacity_);
        return true;
    }
    ~buffer_gt() noexcept {
        if constexpr (!std::is_trivially_destructible<element_at>())
            std::destroy_n(elements_, capacity_);
        std::free(elements_);
        elements_ = nullptr;
    }
    [[nodiscard]] element_at const* data() const noexcept { return elements_; }
    [[nodiscard]] element_at* data() noexcept { return elements_; }
    [[nodiscard]] element_at* begin() noexcept { return elements_; }
    [[nodiscard]] element_at* end() noexcept { return elements_ + capacity_; }
    [[nodiscard]] std::size_t size() const noexcept { return capacity_; }
    [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
    [[nodiscard]] element_at& operator[](std::size_t i) noexcept { return elements_[i]; }
    [[nodiscard]] element_at const& operator[](std::size_t i) const noexcept { return elements_[i]; }
};

template <typename element_at> class pool_gt {
    std::size_t capacity_{};
    std::size_t free_count_{};
    element_at* elements_{};
    std::size_t* free_offsets_{};
    static_assert(std::is_nothrow_default_constructible<element_at>());

  public:
    pool_gt() = default;
    pool_gt(pool_gt&&) = delete;
    pool_gt(pool_gt const&) = delete;
    pool_gt& operator=(pool_gt const&) = delete;

    pool_gt& operator=(pool_gt&& other) noexcept {
        std::swap(capacity_, other.capacity_);
        std::swap(free_count_, other.free_count_);
        std::swap(elements_, other.elements_);
        std::swap(free_offsets_, other.free_offsets_);
        return *this;
    }

    [[nodiscard]] bool reserve(std::size_t n) noexcept {
        auto mem = std::malloc((sizeof(element_at) + sizeof(std::size_t)) * n);
        if (!mem)
            return false;
        elements_ = (element_at*)mem;
        free_offsets_ = (std::size_t*)(elements_ + n);
        free_count_ = capacity_ = n;
        std::uninitialized_default_construct(elements_, elements_ + capacity_);
        std::iota(free_offsets_, free_offsets_ + n, 0ul);
        return true;
    }

    ~pool_gt() noexcept {
        if constexpr (!std::is_trivially_destructible<element_at>())
            std::destroy_n(elements_, capacity_);
        std::free(elements_);
        elements_ = nullptr;
    }
    [[nodiscard]] element_at* alloc() noexcept {
        return free_count_ ? elements_ + free_offsets_[--free_count_] : nullptr;
    }
    void release(element_at* released) noexcept { free_offsets_[free_count_++] = released - elements_; }
    [[nodiscard]] std::size_t offset_of(element_at& element) const noexcept { return &element - elements_; }
    [[nodiscard]] element_at& at_offset(std::size_t i) const noexcept { return elements_[i]; }
};

template <typename element_at> class span_gt {
    element_at* begin_{};
    element_at* end_{};

  public:
    span_gt(element_at* b, element_at* e) noexcept : begin_(b), end_(e) {}

    [[nodiscard]] element_at const* data() const noexcept { return begin_; }
    [[nodiscard]] element_at* data() noexcept { return begin_; }
    [[nodiscard]] element_at* begin() noexcept { return begin_; }
    [[nodiscard]] element_at* end() noexcept { return end_; }
    [[nodiscard]] std::size_t size() const noexcept { return end_ - begin_; }
    [[nodiscard]] element_at& operator[](std::size_t i) noexcept { return begin_[i]; }
    [[nodiscard]] element_at const& operator[](std::size_t i) const noexcept { return begin_[i]; }
    operator std::basic_string_view<element_at>() const noexcept { return {data(), size()}; }
};

template <typename element_at> class array_gt {
    element_at* elements_{};
    std::size_t count_{};
    std::size_t capacity_{};
    static_assert(std::is_nothrow_default_constructible<element_at>());
    static_assert(std::is_trivially_copy_constructible<element_at>(), "Can't use realloc and memcpy");

  public:
    array_gt() = default;
    array_gt(array_gt&&) = delete;
    array_gt(array_gt const&) = delete;
    array_gt& operator=(array_gt const&) = delete;

    array_gt& operator=(array_gt&& other) noexcept {
        std::swap(elements_, other.elements_);
        std::swap(count_, other.count_);
        std::swap(capacity_, other.capacity_);
        return *this;
    }
    [[nodiscard]] bool reserve(std::size_t n) noexcept {
        if (n <= capacity_)
            return true;
        if (!elements_) {
            auto ptr = (element_at*)std::malloc(sizeof(element_at) * n);
            if (!ptr)
                return false;
            elements_ = ptr;
        } else {
            auto ptr = (element_at*)std::realloc(elements_, sizeof(element_at) * n);
            if (!ptr)
                return false;
            elements_ = ptr;
        }
        std::uninitialized_default_construct(elements_ + capacity_, elements_ + n);
        capacity_ = n;
        return true;
    }
    ~array_gt() noexcept { reset(); }
    void reset() noexcept {
        if constexpr (!std::is_trivially_destructible<element_at>())
            std::destroy_n(elements_, count_);
        std::free(elements_);
        elements_ = nullptr;
        capacity_ = count_ = 0;
    }
    [[nodiscard]] element_at const* data() const noexcept { return elements_; }
    [[nodiscard]] element_at* data() noexcept { return elements_; }
    [[nodiscard]] element_at* begin() noexcept { return elements_; }
    [[nodiscard]] element_at* end() noexcept { return elements_ + count_; }
    [[nodiscard]] std::size_t size() const noexcept { return count_; }
    [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }
    [[nodiscard]] element_at& operator[](std::size_t i) noexcept { return elements_[i]; }

    void push_back_reserved(element_at element) noexcept { new (elements_ + count_++) element_at(std::move(element)); }
    void pop_back(std::size_t n = 1) noexcept { count_ -= n; }
    [[nodiscard]] bool append_n(element_at const* elements, std::size_t n) noexcept {
        if (!reserve(size() + n))
            return false;
        std::memcpy(end(), elements, n * sizeof(element_at));
        count_ += n;
        return true;
    }
};

struct exchange_pipe_t {
    char* embedded{};
    std::size_t embedded_used{};
    array_gt<char> dynamic{};

    span_gt<char> span() noexcept {
        return dynamic.size() ? span_gt<char>{dynamic.begin(), dynamic.end()}
                              : span_gt<char>{embedded, embedded + embedded_used};
    }
};

class exchange_pipes_t {
    /// @brief A combination of a embedded and dynamic memory pools for content reception.
    /// We always absorb new packets in the embedded part, later moving them into dynamic memory,
    /// if any more data is expected. Requires @b padding at the end, to accelerate parsing.
    exchange_pipe_t input_{};
    /// @brief A combination of a embedded and dynamic memory pools for content reception.
    exchange_pipe_t output_{};
    std::size_t output_submitted_{};

  public:
    exchange_pipes_t() noexcept = default;
    exchange_pipes_t(exchange_pipes_t&&) = delete;
    exchange_pipes_t(exchange_pipes_t const&) = delete;
    exchange_pipes_t& operator=(exchange_pipes_t&&) = delete;
    exchange_pipes_t& operator=(exchange_pipes_t const&) = delete;

    void mount(char* inputs, char* outputs) noexcept {
        input_.embedded = inputs;
        output_.embedded = outputs;
    }

#pragma region Context Switching

    void release_inputs() noexcept {
        input_.dynamic.reset();
        input_.embedded_used = 0;
    }

    void release_current_input() noexcept { input_.embedded_used = 0; }

    void release_outputs() noexcept {
        output_.dynamic.reset();
        output_.embedded_used = 0;
        output_submitted_ = 0;
    }

    span_gt<char> input_span() noexcept { return input_.span(); }
    span_gt<char> output_span() noexcept { return output_.span(); }

#pragma endregion

#pragma region Piping Inputs
    char* next_input_address() noexcept { return input_.embedded; }
    std::size_t next_input_length() const noexcept { return ram_page_size_k; }

    /**
     * @brief Discards the first 'cnt' elements from the embedded buffer.
     */
    void drop_embedded_n(size_t cnt) noexcept {
        if (cnt > input_.embedded_used)
            return release_inputs();
        input_.embedded_used -= cnt;
        std::memmove(input_.embedded, input_.embedded + cnt, input_.embedded_used);
    }

    void drop_last_input(size_t cnt) noexcept {
        if (input_.dynamic.size() >= cnt)
            input_.dynamic.pop_back(cnt);
        else if (input_.embedded_used >= cnt)
            input_.embedded_used -= cnt;
    }

    bool shift_input_to_dynamic() noexcept {
        if (!input_.dynamic.append_n(input_.embedded, input_.embedded_used))
            return false;
        input_.embedded_used = 0;
        return true;
    }

    bool absorb_input(std::size_t embedded_used) noexcept {
        input_.embedded_used = embedded_used;
        if (!input_.dynamic.size())
            return true;
        return shift_input_to_dynamic();
    }

#pragma endregion
#pragma region Piping Outputs

    void mark_submitted_outputs(std::size_t n) noexcept { output_submitted_ += n; }
    void prepare_more_outputs() noexcept {
        if (!output_.dynamic.size())
            return;
        output_.embedded_used = (std::min)(output_.dynamic.size() - output_submitted_, ram_page_size_k);
        std::memcpy(output_.embedded, output_.dynamic.data() + output_submitted_, output_.embedded_used);
    }
    bool has_outputs() const noexcept { return (std::max)(output_.embedded_used, output_.dynamic.size()); }
    bool has_remaining_outputs() const noexcept {
        return output_submitted_ < (std::max)(output_.embedded_used, output_.dynamic.size());
    }
    char const* next_output_address() const noexcept {
        return output_.dynamic.size() ? output_.embedded : output_.embedded + output_submitted_;
    }

    std::size_t next_output_length() const noexcept {
        return output_.dynamic.size() ? output_.embedded_used : output_.embedded_used - output_submitted_;
    }

    bool append_outputs(std::string_view body) noexcept {
        bool was_in_embedded = !output_.dynamic.size();
        bool fit_into_embedded = output_.embedded_used + body.size() < ram_page_size_k;

        if (was_in_embedded && fit_into_embedded) {
            memcpy(output_.embedded + output_.embedded_used, body.data(), body.size());
            output_.embedded_used += body.size();
            return true;
        } else {
            if (!output_.dynamic.reserve(output_.dynamic.size() + output_.embedded_used + body.size()))
                return false;
            if (was_in_embedded) {
                if (!output_.dynamic.append_n(output_.embedded, output_.embedded_used))
                    return false;
                output_.embedded_used = 0;
            }
            if (!output_.dynamic.append_n(body.data(), body.size()))
                return false;
            return true;
        }
    }

#pragma endregion

#pragma region Replacing

    void output_pop_back() noexcept {
        if (output_.dynamic.size())
            output_.dynamic.pop_back();
        else
            output_.embedded_used--;
    }

    void push_back_reserved(char c) noexcept {
        if (output_.dynamic.size())
            output_.dynamic.push_back_reserved(c);
        else
            output_.embedded[output_.embedded_used++] = c;
    }

    void append_reserved(char const* c, std::size_t n) noexcept {
        if (output_.dynamic.size())
            output_.dynamic.append_n(c, n);
        else
            std::memcpy(output_.embedded + output_.embedded_used, c, n), output_.embedded_used += n;
    }

#pragma endregion
};

struct number_and_suffix_t {
    float number{};
    char suffix{};
};

inline number_and_suffix_t printable(std::size_t n) noexcept {
    if (n > 1'000'000'000)
        return {n / 1'000'000'000.0f, 'G'};
    if (n > 1'000'000)
        return {n / 1'000'000.0f, 'M'};
    if (n > 1'000)
        return {n / 1'000.0f, 'K'};
    return {n + 0.0f, ' '};
}

/**
 *  @brief Struct to gather and log statistical data, in both human-readable form and JSON.
 */
struct stats_t {

    static constexpr std::size_t default_frequency_secs_k{5};

    std::atomic<std::size_t> added_connections{};
    std::atomic<std::size_t> closed_connections{};
    std::atomic<std::size_t> bytes_received{};
    std::atomic<std::size_t> bytes_sent{};
    std::atomic<std::size_t> packets_received{};
    std::atomic<std::size_t> packets_sent{};

    /**
     *  @brief Logs statistical data in a human-readable format, normalized for a time period.
     *
     *  @param buffer Pointer to the buffer where the log string will be written.
     *  @param buffer_capacity Size of the buffer.
     *  @param seconds Time span over which the statistics were collected.
     *  @return The number of characters written to the buffer.
     */
    inline std::size_t log_human_readable(char* buffer, std::size_t buffer_capacity, std::size_t seconds) noexcept {
        auto& s = *this;
        auto printable_normalized = [=](std::atomic<std::size_t>& i) noexcept {
            return printable(double(i.exchange(0, std::memory_order_relaxed)) / seconds);
        };
        auto added_connections = printable_normalized(s.added_connections);
        auto closed_connections = printable_normalized(s.closed_connections);
        auto bytes_received = printable_normalized(s.bytes_received);
        auto bytes_sent = printable_normalized(s.bytes_sent);
        auto packets_received = printable_normalized(s.packets_received);
        auto packets_sent = printable_normalized(s.packets_sent);
        auto len = snprintf( //
            buffer, buffer_capacity,
            "connections: +%.1f %c/s, "
            "-%.1f %c/s, "
            "RX: %.1f %c msgs/s, "
            "%.1f %cb/s, "
            "TX: %.1f %c msgs/s, "
            "%.1f %cb/s. \n",
            added_connections.number, added_connections.suffix,   //
            closed_connections.number, closed_connections.suffix, //
            packets_received.number, packets_received.suffix,     //
            bytes_received.number, bytes_received.suffix,         //
            packets_sent.number, packets_sent.suffix,             //
            bytes_sent.number, bytes_sent.suffix                  //
        );
        return static_cast<std::size_t>(len);
    }

    /**
     *  @brief Logs statistical data in a JSON format.
     *
     *  @param buffer Pointer to the buffer where the log string will be written.
     *  @param buffer_capacity Size of the buffer.
     *  @return The number of characters written to the buffer.
     */
    inline std::size_t log_json(char* buffer, std::size_t buffer_capacity) noexcept {
        auto& s = *this;
        auto added_connections = s.added_connections.exchange(0, std::memory_order_relaxed);
        auto closed_connections = s.closed_connections.exchange(0, std::memory_order_relaxed);
        auto bytes_received = s.bytes_received.exchange(0, std::memory_order_relaxed);
        auto bytes_sent = s.bytes_sent.exchange(0, std::memory_order_relaxed);
        auto packets_received = s.packets_received.exchange(0, std::memory_order_relaxed);
        auto packets_sent = s.packets_sent.exchange(0, std::memory_order_relaxed);
        auto format =
            R"( {"add":%zu,"close":%zu,"recv_bytes":%zu,"sent_bytes":%zu,"recv_packs":%zu,"sent_packs":%zu} \n )";
        auto len = snprintf(         //
            buffer, buffer_capacity, //
            format,                  //
            added_connections,       //
            closed_connections,      //
            bytes_received,          //
            bytes_sent,              //
            packets_received,        //
            packets_sent             //
        );
        return static_cast<std::size_t>(len);
    }
};

struct named_callback_t {
    std::string_view name{};
    ucall_callback_t callback{};
    ucall_verb_t type{};
    ucall_endpoint_tag_t endpoint_tag{};

    bool method_matches(std::string_view) const noexcept;
};

struct engine_t {

    /// @brief An array of function callbacks. Can be in dozens.
    array_gt<named_callback_t> callbacks{};

    void raise_request(exchange_pipes_t&, protocol_t&, ucall_message_t) const noexcept;

    void try_add_callback(named_callback_t&&) noexcept;
};

void engine_t::raise_request(exchange_pipes_t& pipes, protocol_t& protocol, ucall_message_t call) const noexcept {

    if (auto error_ptr = protocol.parse_headers(pipes.input_span()); error_ptr)
        return ucall_reply_error(call, error_ptr->code, error_ptr->note.data(), error_ptr->note.size());

    if (auto error_ptr = protocol.parse_content(); error_ptr)
        return ucall_reply_error(call, error_ptr->code, error_ptr->note.data(), error_ptr->note.size());

    protocol.prepare_response(pipes);
    auto error_ptr = protocol.populate_response(pipes, [&](std::string_view& method_name, ucall_verb_t req_type) {
        auto callbacks_end = callbacks.data() + callbacks.size();
        auto callback_it =
            std::find_if(callbacks.data(), callbacks_end, [&](named_callback_t const& callback) noexcept {
                return callback.type == req_type && callback.method_matches(method_name);
            });
        if (callback_it == callbacks_end)
            return false;

        named_callback_t named_callback = *callback_it;
        method_name = named_callback.name;
        named_callback.callback(call, named_callback.endpoint_tag);
        return true;
    });
    if (error_ptr)
        return ucall_reply_error(call, error_ptr->code, error_ptr->note.data(), error_ptr->note.size());
    protocol.finalize_response(pipes);
}

inline void engine_t::try_add_callback(named_callback_t&& named) noexcept {
    if (callbacks.size() + 1 >= callbacks.capacity())
        return;

    callbacks.push_back_reserved(named);
}

bool named_callback_t::method_matches(std::string_view dynamic_name) const noexcept {
    auto first1 = dynamic_name.begin();
    auto end1 = dynamic_name.end();
    auto first2 = name.begin();
    auto end2 = name.end();
    while (first1 != end1 && first2 != end2) {
        if (*first2 == '{') {
            while (first2 != end2 && *first2++ != '}')
                ;

            while (first1 != end1 && *++first1 != *first2)
                ;

        } else if (*first1++ != *first2++)
            return false;
    }

    return first2 == end2 && first1 == end1;
}

/**
 * @brief   Represents a connection, handling TLS/SSL operations, buffering, and
 *          state management using OpenSSL.
 */
struct connection_t {
    /// @brief Exchange buffers to pipe information in both directions.
    exchange_pipes_t pipes{};

    /// @brief The file descriptor of the stateful connection over TCP.
    descriptor_t descriptor{invalid_descriptor_k};
    /// @brief Current state at which the automata has arrived.
    stage_t stage{};
    protocol_t protocol{};

    struct sockaddr client_address {};
    socklen_t client_address_len{sizeof(struct sockaddr)};

    /// @brief Accumulated duration of sleep cycles.
    std::size_t last_active_ns{};
    std::size_t exchanges{};
    std::size_t empty_transmits{};

    /// @brief TLS/SSL related data
    SSL* ssl_ctx{};   ///< OpenSSL SSL context for this connection.
    BIO* read_bio{};  ///< Memory BIO for reading.
    BIO* write_bio{}; ///< Memory BIO for writing.

    /// @brief Relative time set for the last wake-up call.
    ssize_t next_wakeup = wakeup_initial_frequency_ns_k;

    /**
     * @brief Initializes the SSL context for this connection.
     * @param ctx The global SSL_CTX context.
     */
    void make_tls(SSL_CTX* ctx) noexcept {
        ssl_ctx = SSL_new(ctx);
        read_bio = BIO_new(BIO_s_mem());
        write_bio = BIO_new(BIO_s_mem());
        SSL_set_bio(ssl_ctx, read_bio, write_bio);
    }

    void record_activity() noexcept {
        last_active_ns = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    }

    bool expired() const noexcept {
        return std::chrono::high_resolution_clock::now().time_since_epoch().count() - last_active_ns >
               max_inactive_duration_ns_k;
    }

    bool is_ready() const noexcept { return SSL_is_init_finished(ssl_ctx); }

    bool must_close() const noexcept {
        auto conn = protocol.get_header("Connection");
        return conn == "Close" || conn == "close";
    }

    bool prepare_step() noexcept {
        if (is_ready())
            return true;

        int ret = SSL_do_handshake(ssl_ctx);
        if (ret == 1)
            return true; // Handshake was successful
        int err = SSL_get_error(ssl_ctx, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            return false; // Want more data, keep going

        return false;
    }

    void encrypt() noexcept {
        if (!is_ready())
            return;

        char outbuf[4096];
        int ret = SSL_write(ssl_ctx, pipes.output_span().data(), pipes.output_span().size());
        if (ret > 0) {
            pipes.release_outputs();
            int pending = BIO_read(write_bio, outbuf, sizeof(outbuf));
            if (pending > 0) {
                pipes.append_outputs({outbuf, static_cast<size_t>(pending)});
            }
        }
    }

    void decrypt(size_t received_amount) noexcept {
        if (!is_ready())
            return;

        char inbuf[4096];
        BIO_write(read_bio, pipes.input_span().data(), received_amount);
        int ret = SSL_read(ssl_ctx, inbuf, sizeof(inbuf));
        while (ret > 0) {
            pipes.absorb_input(ret);
            ret = SSL_read(ssl_ctx, inbuf, sizeof(inbuf));
        }
    }

    void reset() noexcept {
        stage = stage_t::unknown_k;
        client_address = {};

        pipes.release_inputs();
        pipes.release_outputs();

        if (ssl_ctx) {
            SSL_free(ssl_ctx);
            ssl_ctx = nullptr;
            // No need to free read_bio and write_bio since SSL_free() takes care of it
        }

        exchanges = 0;
        empty_transmits = 0;
        next_wakeup = wakeup_initial_frequency_ns_k;
    }
};

/**
 * @brief   A smart-pointer to the OpenSSL context, handling the initialization,
 *          loading keys, and certificates.
 */
struct ssl_context_t {
    SSL_CTX* ctx;

    ssl_context_t() noexcept {
        OpenSSL_add_ssl_algorithms();
        ctx = SSL_CTX_new(TLS_server_method());
    }

    ~ssl_context_t() {
        SSL_CTX_free(ctx);
        EVP_cleanup();
    }

    /**
     * @brief Initializes the SSL context with a private key and certificates.
     * @param private_key_path Path to the private key `.pem` file.
     * @param certificates_paths Array of paths to certificate files.
     * @param certificates_count Count of certificate files.
     * @return 0 on success, -1 on failure.
     */
    int init(char const* private_key_path, char const** certificates_paths, size_t certificates_count) noexcept {
        if (SSL_CTX_use_PrivateKey_file(ctx, private_key_path, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        for (size_t i = 0; i < certificates_count; ++i) {
            if (SSL_CTX_use_certificate_file(ctx, certificates_paths[i], SSL_FILETYPE_PEM) <= 0) {
                ERR_print_errors_fp(stderr);
                return -1;
            }
        }

        return 0;
    }

    ssl_context_t(ssl_context_t const& other) = delete;
    ssl_context_t(ssl_context_t&& other) = delete;
    ssl_context_t& operator=(ssl_context_t const& other) = delete;
    ssl_context_t& operator=(ssl_context_t&& other) = delete;
};

struct completed_event_t {
    connection_t* connection_ptr{};
    int result{};
};

struct network_engine_t {
    network_data_t network_data;

    int try_accept(descriptor_t, connection_t&) noexcept;
    void set_stats_heartbeat(connection_t&) noexcept;
    void send_packet(connection_t&, void*, std::size_t, std::size_t) noexcept;
    void recv_packet(connection_t&, void*, std::size_t, std::size_t) noexcept;
    void close_connection_gracefully(connection_t&) noexcept;

    bool is_canceled(ssize_t, connection_t const&) noexcept;
    bool is_corrupted(ssize_t, connection_t const&) noexcept;

    template <size_t max_count_ak> std::size_t pop_completed_events(completed_event_t*) noexcept;
};

struct server_t {
    descriptor_t socket{};
    network_engine_t network_engine{};
    engine_t engine{};
    protocol_kind_t protocol_type{};
    std::unique_ptr<ssl_context_t> ssl_ctx{};

    std::atomic<std::size_t> active_connections{};
    std::uint32_t max_lifetime_micro_seconds{};
    std::uint32_t max_lifetime_exchanges{};

    stats_t stats{};
    connection_t stats_pseudo_connection{};

    std::int32_t logs_file_descriptor{};
    std::string_view logs_format{};

    /// @brief A circular container of reusable connections. Can be in millions.
    pool_gt<connection_t> connections{};
    mutex_t connections_mutex{};
    /// @brief Same number of them, as max physical threads. Can be in hundreds.
    /// @brief Pre-allocated buffered to be submitted for shared use.
    memory_map_t fixed_buffers{};

    void submit_stats_heartbeat() noexcept;
    void release_connection(connection_t&) noexcept;
    void log_and_reset_stats() noexcept;
    bool consider_accepting_new_connection() noexcept;
};

void server_t::submit_stats_heartbeat() noexcept {
    connection_t& connection = stats_pseudo_connection;
    connection.stage = stage_t::log_stats_k;
    connection.next_wakeup = stats_t::default_frequency_secs_k;

    network_engine.set_stats_heartbeat(connection);
}

void server_t::log_and_reset_stats() noexcept {
    static char printed_message_k[ram_page_size_k]{};
    auto len = logs_format == "json" //
                   ? stats.log_json(printed_message_k, ram_page_size_k)
                   : stats.log_human_readable(printed_message_k, ram_page_size_k, stats_t::default_frequency_secs_k);
    len = write(logs_file_descriptor, printed_message_k, len);
}

void server_t::release_connection(connection_t& connection) noexcept {
    auto is_active = connection.stage != stage_t::waiting_to_accept_k;
    connection.reset();
    connections_mutex.lock();
    connections.release(&connection);
    connections_mutex.unlock();
    active_connections -= is_active;
    stats.closed_connections.fetch_add(is_active, std::memory_order_relaxed);
}

bool server_t::consider_accepting_new_connection() noexcept {

    connections_mutex.lock();
    connection_t* con_ptr = connections.alloc();
    connections_mutex.unlock();

    if (!con_ptr)
        return false;

    con_ptr->protocol.reset_protocol(protocol_type);
    connection_t& connection = *con_ptr;
    connection.stage = stage_t::waiting_to_accept_k;
    int result = network_engine.try_accept(socket, connection);

    if (result < 0) {
        connections.release(con_ptr);
        return false;
    }

    return true;
}

/**
 *  @brief  A class that suggests transitions from one `connection.stage` to another.
 */
struct automata_t {
    server_t& server;
    connection_t& connection;
    ssize_t completed_result{};

    void operator()() noexcept;

    // Computed properties:
    bool should_release() const noexcept;
    bool is_corrupted() const noexcept;

    void send_next() noexcept;
    void receive_next() noexcept;
    void close_gracefully() noexcept;
    protocol_t const& get_protocol() const noexcept;
};

protocol_t const& automata_t::get_protocol() const noexcept { return connection.protocol; };

bool automata_t::is_corrupted() const noexcept { return completed_result == -EPIPE || completed_result == -EBADF; }

void automata_t::close_gracefully() noexcept {
    connection.stage = stage_t::waiting_to_close_k;
    server.network_engine.close_connection_gracefully(connection);
}

void automata_t::send_next() noexcept {
    exchange_pipes_t& pipes = connection.pipes;
    connection.stage = stage_t::responding_in_progress_k;
    connection.protocol.reset();
    pipes.release_inputs();

    connection.encrypt();
    server.network_engine.send_packet(connection, (void*)pipes.next_output_address(), pipes.next_output_length(),
                                      server.connections.offset_of(connection) * 2u + 1u);
}

void automata_t::receive_next() noexcept {
    exchange_pipes_t& pipes = connection.pipes;
    connection.stage = stage_t::expecting_reception_k;
    pipes.release_outputs();

    server.network_engine.recv_packet(connection, (void*)pipes.next_input_address(), pipes.next_input_length(),
                                      server.connections.offset_of(connection) * 2u);
}

void automata_t::operator()() noexcept {

    switch (connection.stage) {

    case stage_t::waiting_to_accept_k:

        if (server.network_engine.is_canceled(completed_result, connection)) {
            server.release_connection(connection);
            return;
        }
        if (server.ssl_ctx)
            connection.make_tls(&server.ssl_ctx->ssl);

        // Check if accepting the new connection request worked out.
        connection.record_activity();
        ++server.active_connections;
        server.stats.added_connections.fetch_add(1, std::memory_order_relaxed);
        connection.descriptor = descriptor_t{completed_result};
        return receive_next();

    case stage_t::expecting_reception_k:

        // From documentation:
        // > If used, the timeout specified in the command will cancel the linked command,
        // > unless the linked command completes before the timeout. The timeout will complete
        // > with -ETIME if the timer expired and the linked request was attempted canceled,
        // > or -ECANCELED if the timer got canceled because of completion of the linked request.
        //
        // So we expect only two outcomes here:
        // 1. reception expired with: `ECANCELED`, and subsequent timeout expired with `ETIME`.
        // 2. reception can continue and subsequent timer returned `ECANCELED`.
        //
        // If the following timeout request has happened,
        // we don't want to do anything here. Let's leave the faith of
        // this connection to the subsequent timer to decide.
        if (server.network_engine.is_corrupted(completed_result, connection) || connection.expired())
            return close_gracefully();

        if (server.network_engine.is_canceled(completed_result, connection)) {
            connection.next_wakeup *= sleep_growth_factor_k;
            completed_result = 0;
        }

        // No data was received.
        if (completed_result == 0) {
            connection.empty_transmits++;
            return receive_next();
        }

        // Absorb the arrived data.
        server.stats.bytes_received.fetch_add(completed_result, std::memory_order_relaxed);
        server.stats.packets_received.fetch_add(1, std::memory_order_relaxed);
        connection.empty_transmits = 0;
        connection.record_activity();
        if (!connection.pipes.absorb_input(completed_result)) {
            ucall_reply_error_out_of_memory(this);
            return send_next();
        }

        if (!connection.prepare_step())
            return send_next();

        // If we have reached the end of the stream,
        // it is time to analyze the contents
        // and send back a response.
        connection.decrypt(completed_result);
        if (connection.protocol.is_input_complete(connection.pipes.input_span())) {
            server.engine.raise_request(connection.pipes, connection.protocol, this);

            connection.pipes.release_inputs();
            // Some requests require no response at all,
            // so we can go back to listening the port.
            if (!connection.pipes.has_outputs()) {
                connection.exchanges++;
                // if (connection.exchanges >= server.max_lifetime_exchanges) TODO Why?
                //     return close_gracefully();
                // else
                return receive_next();
            } else {
                connection.pipes.prepare_more_outputs();
                return send_next();
            }
        }
        // We are looking for more data to come
        else if (connection.pipes.shift_input_to_dynamic()) {
            return receive_next();
        }
        // We may fail to allocate memory to receive the next input
        else {
            ucall_reply_error_out_of_memory(this);
            return send_next();
        }

    case stage_t::responding_in_progress_k:
        if (server.network_engine.is_corrupted(completed_result, connection) || connection.expired())
            return close_gracefully();

        connection.empty_transmits = completed_result == 0 ? ++connection.empty_transmits : 0;

        if (server.network_engine.is_canceled(completed_result, connection)) {
            connection.next_wakeup *= sleep_growth_factor_k;
            completed_result = 0;
        }

        if (!connection.is_ready())
            return receive_next();

        connection.record_activity();
        server.stats.bytes_sent.fetch_add(completed_result, std::memory_order_relaxed);
        server.stats.packets_sent.fetch_add(1, std::memory_order_relaxed);
        connection.pipes.mark_submitted_outputs(completed_result);
        if (!connection.pipes.has_remaining_outputs()) {
            connection.exchanges++;
            if (connection.must_close())
                return close_gracefully();
            else
                return receive_next();
        } else {
            connection.pipes.prepare_more_outputs();
            return send_next();
        }

    case stage_t::waiting_to_close_k:
        return server.release_connection(connection);

    case stage_t::log_stats_k:
        server.log_and_reset_stats();
        return server.submit_stats_heartbeat();

    case stage_t::unknown_k:
        return;
    }
}

} // namespace unum::ucall
