/**
 *  @file verification/claims.cpp
 *  @author Ash Vardanian
 *  @date October 27, 2026
 *  @brief GenMC client for the reply claim in `include/ucall/network.hpp`: @c reply and
 *      @c begin_reply against the loop's @c detach of a closed connection.
 *
 *  Two repliers claim one exchange with @c fetch_test_and_set_bit on its claimed bit, acquiring
 *  and releasing, then load the state with an acquire to learn whether the connection left. The
 *  loop marks the exchange orphaned with a plain write, as @c detach clears its connection, then
 *  sets the detached bit with a release. Exactly one replier claims, and a claimer that reads the
 *  detached bit reads the orphaned mark too, so it never answers into a connection that is gone.
 *
 *  @verify pass sc,rc11,imm claims
 *  @verify fail rc11,imm claims_detach_order_relaxed: @c detach releases with its bit set; relaxed,
 *      a claimer reads the bit without the orphaned mark, racing with its write
 *  @verify fail rc11,imm claims_state_order_relaxed: a claimer acquires with its load of the state;
 *      relaxed, it reads the detached bit without the orphaned mark, racing with its write
 */
#include <cstdint> // `std::uint32_t` - the state word

#include <atomic> // `std::memory_order`

#include <genmc.hpp>

#include <forkunion/atomics.hpp> // `fu::standard_atomic_ref` - the reference UCall's portable builds use

namespace fu = ashvardanian::forkunion;

/** The header's choices; each mutant entry changes one. */
struct knobs_t {
    std::memory_order detach_order = std::memory_order_release;
    std::memory_order state_order = std::memory_order_acquire;
};

constexpr knobs_t header_k {};
constexpr knobs_t detach_order_relaxed_k {.detach_order = std::memory_order_relaxed};
constexpr knobs_t state_order_relaxed_k {.state_order = std::memory_order_relaxed};

/** The exchange state bits, as `exchange_state_t` numbers them. */
constexpr std::uint32_t claimed_k = 1, detached_k = 4;
constexpr unsigned claimed_bit_k = 0;

std::uint32_t state = 0;
std::uint32_t orphaned = 0; // plain: the loop's write before the detach, as `detach` clears `connection`
bool claimed[2] = {false, false};

/** A replier: claims, then reads whether the connection left, and if so the orphaned mark. */
template <knobs_t const& knobs_>
void* reply(void* index) noexcept {
    std::uint32_t const self = *static_cast<std::uint32_t*>(index);
    fu::standard_atomic_ref<std::uint32_t> const word(state);
    claimed[self] = !word.fetch_test_and_set_bit(claimed_bit_k, std::memory_order_acq_rel);
    if (!claimed[self]) return nullptr;
    if (word.load(knobs_.state_order) & detached_k) verify(orphaned == 1);
    return nullptr;
}

/** The loop's detach: the orphaned mark, then the detached bit. */
template <knobs_t const& knobs_>
void* detach(void*) noexcept {
    orphaned = 1;
    fu::standard_atomic_ref<std::uint32_t>(state).set_bits(detached_k, knobs_.detach_order);
    return nullptr;
}

template <knobs_t const& knobs_>
int claim_against_detach() noexcept {
    std::uint32_t indices[2] = {0, 1};
    thread_t const loop = spawn(detach<knobs_>);
    thread_t repliers[2] = {spawn(reply<knobs_>, &indices[0]), spawn(reply<knobs_>, &indices[1])};
    join(repliers[0]);
    join(repliers[1]);
    join(loop);
    verify(claimed[0] != claimed[1]);
    verify(fu::standard_atomic_ref<std::uint32_t>(state).load(std::memory_order_relaxed) == (claimed_k | detached_k));
    return 0;
}

extern "C" int claims() { return claim_against_detach<header_k>(); }
extern "C" int claims_detach_order_relaxed() { return claim_against_detach<detach_order_relaxed_k>(); }
extern "C" int claims_state_order_relaxed() { return claim_against_detach<state_order_relaxed_k>(); }
