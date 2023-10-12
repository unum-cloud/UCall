#pragma once

#include <cstddef>
#include <cstring>
#include <memory>
#include <numeric>
#include <stdlib.h>
#include <string_view>
#include <type_traits>

#include "globals.hpp"

namespace unum::ucall {

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

    bool append_outputs(std::string_view) noexcept;

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

bool exchange_pipes_t::append_outputs(std::string_view body) noexcept {
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
} // namespace unum::ucall