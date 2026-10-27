/**
 *  @file verification/segment_links.pml
 *  @author Ash Vardanian
 *  @date October 27, 2026
 *  @brief Spin model of an exchange's reply segments in `include/ucall/network.hpp`: the replier's
 *      @c link_chain and @c list_replied against the loop's @c collect_replies, @c adopt_chain and
 *      the parking in @c retire_segment.
 *
 *  The replier writes each segment's payload, links it with a release store into the @c next of
 *  its previous segment, and lists the exchange by setting the listed bit with an acquire-release
 *  or. The loop adopts from its cursor with acquire loads, reads every payload, and retires each
 *  adopted segment: it hands back all but the cursor, which it parks until the cursor moves past
 *  it. Three segments, the third ending the reply.
 *
 *  - Every segment is adopted, its payload read as written.
 *  - The replier never links onto a segment the loop handed back.
 *
 *  @verify pass sc,rc11
 *  @verify fail sc park=false: handing the cursor back at once lets the replier link its next
 *      segment onto a record it no longer owns
 *  @verify stuck sc unlist_first=false: clearing the bit after adopting drops a push that landed
 *      between the adoption and the clear, which then never queues the exchange again
 *  @verify fail rc11 link_order=order_relaxed: relaxed, the loop follows a link and reads the
 *      payload from before it was written
 */
#define thread_count 2
#define location_count 9
#define history_depth 8
#include <weak_memory.pml>

/** The segments, and none, which no link names. */
#define segments 3
#define none 3

/** The words: the exchange's first link, each segment's `next`, its state, the queue the loop
 *  drains, and each segment's payload. */
#define first 0
#define next_of(segment) (1 + (segment))
#define state 4
#define queued 5
#define payload_of(segment) (6 + (segment))
#define listed 8

/** The knobs: the header's choices, each overridden by a `@verify` line. */
#ifndef link_order
#define link_order order_release
#endif
#ifndef park
#define park true
#endif
#ifndef unlist_first
#define unlist_first true
#endif

bit returned[segments]; // ghost: segments the loop handed back

/** The replier: links each segment behind the last, then lists the exchange. */
proctype replier(byte t) {
    int segment, observed, count;
    for (segment : 0 .. segments - 1) {
        store(t, payload_of(segment), order_relaxed, 1);
        store(t, next_of(segment), order_relaxed, none);
        if
        :: segment == 0 -> store(t, first, link_order, 0)
        :: else -> atomic { assert(!returned[segment - 1]); store(t, next_of(segment - 1), link_order, segment) }
        fi;
        read_modify_write(t, state, order_acq_rel, observed, observed | listed);
        if
        :: (observed & listed) == 0 -> read_modify_write(t, queued, order_release, count, count + 1)
        :: else
        fi
    }
}

/** The loop's unlisting: an acquire-release and of the listed bit. */
inline unlist(t, observed) { read_modify_write(t, state, order_acq_rel, observed, observed & ~listed) }

/** The loop: for each queueing, unlists and adopts from its cursor, parking the cursor. */
proctype loop(byte t) {
    int drained = 0, count, observed, cursor = none, next, payload, parked = none, adopted = 0;
    do
    :: adopted == segments -> break
    :: else ->
        // The wake: the loop blocks until a queueing it has not drained, which it reads like the
        // wake channel's syscall does, newest first.
        (newest_value(queued) > drained);
        read_modify_write(t, queued, order_acquire, count, count);
        drained++;
        if :: unlist_first -> unlist(t, observed) :: else fi;
        if
        :: cursor == none -> load(t, first, order_acquire, next)
        :: else -> load(t, next_of(cursor), order_acquire, next)
        fi;
        do
        :: next == none -> break
        :: else ->
            load(t, payload_of(next), order_relaxed, payload);
            assert(payload == 1);
            adopted++;
            if
            :: cursor != none && parked == cursor -> returned[parked] = 1; parked = none
            :: cursor != none && parked != cursor -> returned[cursor] = 1
            :: else
            fi;
            cursor = next;
            load(t, next_of(cursor), order_acquire, next)
        od;
        if :: !unlist_first -> unlist(t, observed) :: else fi;
        if
        :: adopted == segments -> returned[cursor] = 1
        :: park && cursor != none -> parked = cursor
        :: !park && cursor != none -> returned[cursor] = 1
        :: else
        fi
    od
}

init {
    atomic {
        seed(first, none);
        seed(next_of(0), none);
        seed(next_of(1), none);
        seed(next_of(2), none);
        run replier(0);
        run loop(1)
    }
}
