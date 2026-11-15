/**
 *  @file verification/claims.pml
 *  @author Ash Vardanian
 *  @date November 12, 2026
 *  @brief Spin model of the reply claim in @c include/ucall/network/replies.hpp: @c reply and
 *      @c begin_reply against the loop's @c detach of a closed connection.
 *
 *  Two repliers claim one exchange by setting its claimed bit with an acquire-release or, and the
 *  one that finds it clear loads the state with an acquire to learn whether the connection left.
 *  The loop marks the exchange orphaned with a plain write, as @c detach clears its connection,
 *  then sets the detached bit with a release.
 *
 *  - Exactly one replier claims.
 *  - A claimer that reads the detached bit reads the orphaned mark too.
 *
 *  @verify pass sc,rc11
 *  @verify fail rc11 detach_order=order_relaxed: relaxed, a claimer reads the bit and then
 *      the mark from before the loop wrote it
 *  @verify fail rc11 state_order=order_relaxed: relaxed, it reads the detached bit and then
 *      the mark from before the loop wrote it
 */
#define thread_count 3
#define location_count 2
#define history_depth 4
#include <weak_memory.pml>

/** The words: the exchange's state and the mark the loop writes before detaching. */
#define state 0
#define orphaned 1

/** The state bits the model needs, as @c exchange_state_t numbers them. */
#define claimed 1
#define detached 4

/** The knobs: the header's choices, each overridden by a <tt>@verify</tt> line. */
#ifndef detach_order
#define detach_order order_release
#endif
#ifndef state_order
#define state_order order_acquire
#endif

byte claims;   // ghost: repliers that found the claimed bit clear
byte finished; // ghost: threads that ran to their end

/** A replier: claims, then reads whether the connection left, and if so the orphaned mark. */
proctype replier(byte t) {
    int observed, mark;
    read_modify_write(t, state, order_acq_rel, observed, observed | claimed);
    if
    :: (observed & claimed) == 0 ->
        claims++;
        load(t, state, state_order, observed);
        if
        :: (observed & detached) != 0 ->
            load(t, orphaned, order_relaxed, mark);
            assert(mark == 1)
        :: else
        fi
    :: else
    fi;
    finished++
}

/** The loop's detach: the orphaned mark, then the detached bit. */
proctype loop(byte t) {
    int observed;
    store(t, orphaned, order_relaxed, 1);
    read_modify_write(t, state, detach_order, observed, observed | detached);
    finished++
}

init {
    atomic {
        seed(state, 0);
        seed(orphaned, 0);
        run replier(0);
        run replier(1);
        run loop(2)
    };
    finished == 3 -> assert(claims == 1)
}
