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

using byte_t = unsigned char;

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

struct status_t {
    int code{};
    std::string_view note;

    explicit operator bool() const noexcept { return code == 0; }
};

inline std::size_t string_length(char const* c_str, std::size_t optional_length) noexcept {
    return c_str && !optional_length ? std::strlen(c_str) : optional_length;
}

/**
 *  @brief Rounds integer to the next multiple of a given number. Is needed for aligned memory allocations.
 */
template <std::size_t step_ak> constexpr std::size_t round_up_to(std::size_t n) noexcept {
    return ((n + step_ak - 1) / step_ak) * step_ak;
}

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

/**
 *  @brief Represents the various stages a connection and the `automata_t` can be in.
 */
enum class stage_t {
    waiting_to_accept_k = 0,
    expecting_reception_k,
    responding_in_progress_k,
    waiting_to_close_k,
    log_stats_k,
    unknown_k,
};

/**
 *  @brief Lightweight `std::mutex` alternative, which is not recursive, and is not re-entrant.
 *  It works better for low number of concurrently accessing threads, otherwise throttles due to
 *  high contention around a single atomic boolean.
 */
class alignas(align_k) mutex_t {
    std::atomic<bool> flag{false};

  public:
    inline void lock() noexcept {
        while (flag.exchange(true, std::memory_order_relaxed))
            ;
        std::atomic_thread_fence(std::memory_order_acquire);
    }

    inline void unlock() noexcept {
        std::atomic_thread_fence(std::memory_order_release);
        flag.store(false, std::memory_order_relaxed);
    }
};

/**
 *  @brief Smart-pointer for memory-mapped pages, portable between UNIX and Windows.
 */
class memory_map_t {
    byte_t* data_{};
    std::size_t size_{};

  public:
    memory_map_t() = default;
    memory_map_t(memory_map_t const&) = delete;
    memory_map_t& operator=(memory_map_t const&) = delete;

    inline memory_map_t(memory_map_t&& other) noexcept {
        std::swap(data_, other.data_);
        std::swap(size_, other.size_);
    }

    inline memory_map_t& operator=(memory_map_t&& other) noexcept {
        std::swap(data_, other.data_);
        std::swap(size_, other.size_);
        return *this;
    }

    inline byte_t* data() const noexcept { return data_; }
    inline std::size_t size() const noexcept { return size_; }

    bool reserve(std::size_t size) noexcept {
#if defined(UCALL_IS_WINDOWS)
        HANDLE hFile = INVALID_HANDLE_VALUE;
        HANDLE hMap = CreateFileMapping(hFile, nullptr, PAGE_READWRITE, 0, size, nullptr);
        if (hMap == nullptr)
            return false;

        byte_t* new_ptr = (byte_t*)MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, size); // Map a view of the file
        if (new_ptr == nullptr) {
            CloseHandle(hMap);
            return false;
        }
#else
        // Use mmap for Linux and other POSIX systems
        // Make sure that the `size` is a multiple of `page_size`
        // auto page_size = sysconf(_SC_PAGE_SIZE);
        byte_t* new_ptr = (byte_t*)mmap(data_, size, PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (new_ptr == MAP_FAILED) {
            errno;
            return false;
        }
#endif
        std::memset(new_ptr, 0, size);
        data_ = new_ptr;
        size_ = size;
        return true;
    }

    ~memory_map_t() noexcept {
#if defined(UCALL_IS_WINDOWS)
        if (data_)
            UnmapViewOfFile(data_); // Unmap the view of the file
#else
        if (data_)
            munmap(data_, size_);
#endif
        data_ = nullptr;
        size_ = 0;
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

/**
 *  @brief Describes a combination of static and dynamic memory used by a single
 *  client-server connection for uni-directional communication, either inbound or outbound.
 */
struct exchange_pipe_t {
    byte_t* embedded{};
    std::size_t embedded_used{};
    array_gt<byte_t> dynamic{};

    span_gt<byte_t> span() noexcept {
        return dynamic.size() ? span_gt<byte_t>{dynamic.begin(), dynamic.end()}
                              : span_gt<byte_t>{embedded, embedded + embedded_used};
    }
};

/**
 *  @brief Describes a pair of `exchange_pipe_t` exchange pipes used by a single
 *  client-server connection for bi-directional communication, both inbound or outbound.
 */
class exchange_pipes_t {
    /// @brief A combination of an embedded and dynamic memory pool for content reception.
    /// We always absorb new packets in the embedded part, later moving them into dynamic memory,
    /// if any more data is expected. Requires @b padding at the end, to accelerate parsing.
    exchange_pipe_t input_{};
    /// @brief A combination of an embedded and dynamic memory pool for response content.
    exchange_pipe_t output_{};
    std::size_t output_submitted_{};

  public:
    exchange_pipes_t() noexcept = default;
    exchange_pipes_t(exchange_pipes_t&&) = delete;
    exchange_pipes_t(exchange_pipes_t const&) = delete;
    exchange_pipes_t& operator=(exchange_pipes_t&&) = delete;
    exchange_pipes_t& operator=(exchange_pipes_t const&) = delete;

    void mount(byte_t* inputs, byte_t* outputs) noexcept {
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

    span_gt<byte_t> input_span() noexcept { return input_.span(); }
    span_gt<byte_t> output_span() noexcept { return output_.span(); }

#pragma endregion

#pragma region Piping Inputs
    char* next_input_address() noexcept { return input_.embedded; }
    std::size_t next_input_length() const noexcept { return ram_page_size_k; }

    /**
     *  @brief Discards the first 'cnt' elements from the embedded buffer.
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

/**
 *  @brief  A named callback needed to describe an endpoint.
 */
struct endpoint_t {
    std::string_view name{};
    ucall_callback_t callback{};
    ucall_verb_t verb{};
    ucall_endpoint_tag_t tag{};
};

/**
 *  @brief  A smart-pointer to the OpenSSL context, handling the initialization,
 *          loading keys, and certificates.
 */
class ssl_context_t {
    SSL_CTX* raw_{};

  public:
    ssl_context_t() noexcept {
        OpenSSL_add_ssl_algorithms();
        raw_ = SSL_CTX_new(TLS_server_method());
    }

    ~ssl_context_t() {
        SSL_CTX_free(raw_);
        EVP_cleanup();
    }

    explicit operator bool() const noexcept { return raw_ != nullptr; }
    SSL_CTX* get() const noexcept { return raw_; }

    /**
     *  @brief Initializes the SSL context with a private key and certificates.
     *  @param private_key_path Path to the private key `.pem` file.
     *  @param certificates_paths Array of paths to certificate files.
     *  @param certificates_count Count of certificate files.
     *  @return 0 on success, -1 on failure.
     */
    status_t populate(char const* private_key_path, char const** certificates_paths,
                      std::size_t certificates_count) noexcept {
        if (SSL_CTX_use_PrivateKey_file(raw_, private_key_path, SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors_fp(stderr);
            return -1;
        }

        for (std::size_t i = 0; i < certificates_count; ++i) {
            if (SSL_CTX_use_certificate_file(raw_, certificates_paths[i], SSL_FILETYPE_PEM) <= 0) {
                ERR_print_errors_fp(stderr);
                return -1;
            }
        }

        return {};
    }

    ssl_context_t(ssl_context_t const& other) = delete;
    ssl_context_t(ssl_context_t&& other) = delete;
    ssl_context_t& operator=(ssl_context_t const& other) = delete;
    ssl_context_t& operator=(ssl_context_t&& other) = delete;
};

struct connection_stats_t {
    std::size_t exchanged_messages{};
    std::size_t exchanged_packets{};
    std::size_t exchanged_bytes{};
    std::size_t empty_transmits{};
    std::size_t time_start{};
    std::size_t time_last{};
    std::size_t time_keep_alive{};
};

/**
 *  @brief  Represents a connection, handling TLS/SSL operations, buffering,
 *          and state management using OpenSSL.
 */
struct connection_t {
    /// @brief Exchange buffers to pipe information in both directions.
    exchange_pipes_t pipes{};

    /// @brief The file descriptor of the stateful connection over TCP.
    descriptor_t descriptor{invalid_descriptor_k};

    /// @brief Current state at which the automata has arrived.
    stage_t stage{};

    /// @brief The IP address of the client on the opposite end of this connection.
    sockaddr client_address{};
    socklen_t client_address_length{sizeof(client_address)};

    /// @brief Accumulated duration of sleep cycles.
    std::size_t last_active_ns{};
    std::size_t exchanges{};
    std::size_t empty_transmits{};

    /// @brief TLS/SSL related data
    SSL* ssl_context{}; ///< OpenSSL SSL context for this connection.
    BIO* read_bio{};    ///< Memory BIO for reading.
    BIO* write_bio{};   ///< Memory BIO for writing.

    /// @brief Relative time set for the last wake-up call.
    /// This value is incremented for every following wake-up.
    ssize_t next_wakeup{wakeup_initial_frequency_ns_k};

    /**
     *  @brief Initializes the SSL context for this connection.
     *  @param ctx The global SSL_CTX context.
     */
    void make_tls(ssl_context_t& ssl) noexcept {
        ssl_context = SSL_new(ssl.get());
        read_bio = BIO_new(BIO_s_mem());
        write_bio = BIO_new(BIO_s_mem());
        SSL_set_bio(ssl_context, read_bio, write_bio);
    }

    void record_activity() noexcept {
        last_active_ns = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    }

    bool expired() const noexcept {
        return std::chrono::high_resolution_clock::now().time_since_epoch().count() - last_active_ns >
               max_inactive_duration_ns_k;
    }

    bool is_ready() const noexcept { return SSL_is_init_finished(ssl_context); }

    bool must_close() const noexcept {
        auto conn = protocol.get_header("Connection");
        return conn == "Close" || conn == "close";
    }

    bool prepare_step() noexcept {
        if (is_ready())
            return true;

        int ret = SSL_do_handshake(ssl_context);
        if (ret == 1)
            return true; // Handshake was successful
        int err = SSL_get_error(ssl_context, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            return false; // Want more data, keep going

        return false;
    }

    void encrypt() noexcept {
        if (!is_ready())
            return;

        char outbuf[4096];
        int ret = SSL_write(ssl_context, pipes.output_span().data(), pipes.output_span().size());
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
        int ret = SSL_read(ssl_context, inbuf, sizeof(inbuf));
        while (ret > 0) {
            pipes.absorb_input(ret);
            ret = SSL_read(ssl_context, inbuf, sizeof(inbuf));
        }
    }

    void reset() noexcept {
        stage = stage_t::unknown_k;
        client_address = {};

        pipes.release_inputs();
        pipes.release_outputs();

        if (ssl_context) {
            SSL_free(ssl_context);
            ssl_context = nullptr;
            // No need to free read_bio and write_bio since SSL_free() takes care of it
        }

        exchanges = 0;
        empty_transmits = 0;
        next_wakeup = wakeup_initial_frequency_ns_k;
    }
};

struct completed_event_t {
    connection_t* connection_ptr{};
    int result{};
};

enum class stats_logs_format_t {
    human_readable_k,
    json_k,
    none_k,
};

/**
 *  @brief A state common to any backend. Contains: a list of `endpoints`, settings for the
 *  connection, the `socket` descriptor, a pool of `connections`, and a pool of `buffers`,
 *  and aggregates stats across all of the connections.
 *
 *  @section How to keep track of connections and reuse them when the time comes?
 *
 */
struct server_state_t {
    /// @brief An array of function endpoints. Can be in dozens.
    array_gt<endpoint_t> endpoints{};

    std::uint32_t max_lifetime_micro_seconds{};
    std::uint32_t max_lifetime_exchanges{};

    /// @brief File descriptor of the TCP socket.
    descriptor_t socket{};

    /// @brief Parsed in-memory signing keys for the Diffie-Hellman exchange.
    ssl_context_t ssl_context{};

    /// @brief A container of reusable connections. Can be in millions.
    pool_gt<connection_t> connections_pool{};

    /// @brief A binary heap, with a root, that is the oldest accessed connection.
    /// When we reach the capacity of `connections_pool`, we pop elements from here,
    /// until the popped element has a better "importance score", then the next root.
    /// If the new root is has lower score, the extracted element is returned into the
    /// heap, and the process continues. Otherwise, the extracted "root" connection is reused.
    /// To ensure that there are no in-flight messages coming on that socket
    span_gt<connection_t*> connections_heap{};

    /// @brief Atomic counter for the number of allocated elements in the `connections_pool` pool.
    std::atomic<std::size_t> active_connections{};

    /// @brief Synchronizes concurrent access to `connections` from different threads.
    mutex_t connections_mutex{};

    /// @brief Pre-allocated buffered for small messages, often registered for
    /// shared use between this user-space server program and kernel-space NIC driver.
    memory_map_t fixed_buffers{};

    stats_t stats{};

    /// @brief A connection context we use to schedule logging using the same underlying engine.
    connection_t stats_pseudo_connection{};

    stats_logs_format_t logs_format{stats_logs_format_t::human_readable_k};
    std::int32_t logs_file_descriptor{};

    void log_and_reset_stats() noexcept {
        static char printed_message_k[ram_page_size_k]{};
        std::size_t len;
        switch (logs_format) {
        case stats_logs_format_t::json_k:
            len = stats.log_json(printed_message_k, ram_page_size_k);
            break;
        case stats_logs_format_t::human_readable_k:
            len = stats.log_human_readable(printed_message_k, ram_page_size_k, stats_t::default_frequency_secs_k);
            break;
        default:
            len = 0;
            break;
        }
        len = write(logs_file_descriptor, printed_message_k, len);
    }

    void release_connection(connection_t& connection) noexcept {
        auto is_active = connection.stage != stage_t::waiting_to_accept_k;
        connection.reset();
        connections_mutex.lock();
        connections.release(&connection);
        connections_mutex.unlock();
        active_connections -= is_active;
        stats.closed_connections.fetch_add(is_active, std::memory_order_relaxed);
    }
};

/**
 *  @brief A non-owning memory reference of the parsed parts of a received request.
 */
struct parsed_request_t {
    ucall_verb_t type{};
    std::string_view path{};
    std::string_view content_type{};
    std::string_view content_length{};
    std::string_view body{};
};

parsed_request_t parse_request(std::string_view) {
    // TODO:
    return {};
}

inline void server_state_t::try_add_callback(endpoint_t&& named) noexcept {
    if (endpoints.size() + 1 >= endpoints.capacity())
        return;

    endpoints.push_back_reserved(named);
}

void server_state_t::submit_stats_heartbeat() noexcept {
    connection_t& connection = stats_pseudo_connection;
    connection.stage = stage_t::log_stats_k;
    connection.next_wakeup = stats_t::default_frequency_secs_k;

    network_engine.set_stats_heartbeat(connection);
}

bool server_state_t::consider_accepting_new_connection() noexcept {

    connections_mutex.lock();
    connection_t* con_ptr = connections.alloc();
    connections_mutex.unlock();

    if (!con_ptr)
        return false;

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

struct update_status_t {
    ssize_t code{};

    bool is_corrupted() const noexcept { return code == -EPIPE || code == -EBADF; }
};

template <typename engine_at>
update_status_t update_connection(server_state_t& server, connection_t& connection, engine_at&& engine) noexcept {

    auto close_gracefully = [&]() noexcept {
        connection.stage = stage_t::waiting_to_close_k;
        engine.close_connection_gracefully(connection);
    };

    auto send_next = [&]() noexcept {
        exchange_pipes_t& pipes = connection.pipes;
        connection.stage = stage_t::responding_in_progress_k;
        pipes.release_inputs();

        connection.encrypt();
        engine.send_packet(connection, (void*)pipes.next_output_address(), pipes.next_output_length(),
                           server.connections.offset_of(connection) * 2u + 1u);
    };

    auto receive_next = [&]() noexcept {
        exchange_pipes_t& pipes = connection.pipes;
        connection.stage = stage_t::expecting_reception_k;
        pipes.release_outputs();

        engine.recv_packet(connection, (void*)pipes.next_input_address(), pipes.next_input_length(),
                           server.connections.offset_of(connection) * 2u);
    };

    auto raise_request = [&]() noexcept {
        exchange_pipes_t& pipes = connection.pipes;
        parsed_request_t request = parse_request(pipes.input_span());
        if (request.type == ucall_verb_t::unknown_k)
            return ucall_reply_error(call, -EINVAL, "Unknown verb", 12);

        // TODO:
        // pipes.append_reserved(http_header_k, http_header_size_k);
        // content_length = pipes.output_span().size();

        //     auto error_ptr = protocol.populate_response(pipes, [&](std::string_view& method_name, ucall_verb_t verb)
        //     {
        //         auto endpoints_end = endpoints.data() + endpoints.size();
        //         auto endpoint_it = std::find_if(endpoints.data(), endpoints_end, [&](endpoint_t const& endpoint)
        //         noexcept {
        //             return endpoint.type == verb && endpoint.method_matches(method_name);
        //         });
        //         if (endpoint_it == endpoints_end)
        //             return false;

        //         endpoint_t named_endpoint = *endpoint_it;
        //         method_name = named_endpoint.name;
        //         named_endpoint.endpoint(call, named_endpoint.endpoint_tag);
        //         return true;
        //     });
        //     if (error_ptr)
        //         return ucall_reply_error(call, error_ptr->code, error_ptr->note.data(), error_ptr->note.size());
        //     protocol.finalize_response(pipes);
    };

    switch (connection.stage) {

    case stage_t::waiting_to_accept_k:

        if (engine.is_canceled(completed_result, connection)) {
            server.release_connection(connection);
            return;
        }
        if (server.ssl_context)
            connection.make_tls(&server.ssl_context->ssl);

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
        if (engine.is_corrupted(completed_result, connection) || connection.expired())
            return close_gracefully();

        if (engine.is_canceled(completed_result, connection)) {
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
        if (engine.is_corrupted(completed_result, connection) || connection.expired())
            return close_gracefully();

        connection.empty_transmits = completed_result == 0 ? ++connection.empty_transmits : 0;

        if (engine.is_canceled(completed_result, connection)) {
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
