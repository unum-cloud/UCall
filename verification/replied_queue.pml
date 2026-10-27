/**
 *  @file verification/replied_queue.pml
 *  @author Ash Vardanian
 *  @date October 27, 2026
 *  @brief Spin model of an event loop's replied queue in `include/ucall/network.hpp`:
 *      @c enqueue_replied and @c dequeue_replied, Vyukov's intrusive queue with a stub.
 *
 *  A pusher clears its link's @c next, exchanges the tail to its link, and stores its link into
 *  the @c next of the link it displaced, with a release. The loop alone walks from its head, which
 *  starts at the stub. Two repliers each write a payload, then queue their exchange's link; the
 *  loop drains until it met both.
 *
 *  - Each link comes out exactly once.
 *  - The loop reads the payload its replier wrote before queueing it.
 *
 *  @verify pass sc,rc11
 *  @verify fail rc11 link_order=order_relaxed: relaxed, the loop follows the link and reads the
 *      payload from before the replier wrote it
 */
#define thread_count 3
#define location_count 6
#define history_depth 8
#include <weak_memory.pml>

/** The links: the loop's stub and one per replier, and none, which no `next` names. */
#define stub 0
#define none 3

/** The words: the tail, each link's `next`, and each replier's payload. */
#define tail 0
#define next_of(link) (1 + (link))
#define payload_of(link) (3 + (link))

/** The knob: the header's choice, overridden by a `@verify` line. */
#ifndef link_order
#define link_order order_release
#endif

bit dequeued[3]; // ghost: links the loop handed out
byte received;   // ghost: how many it handed out

/** @c enqueue_replied: one exchange of the tail, then the release store of the link behind it. */
inline enqueue(t, link, previous) {
    store(t, next_of(link), order_relaxed, none);
    read_modify_write(t, tail, order_acq_rel, previous, link);
    store(t, next_of(previous), link_order, link)
}

/** A replier that writes its payload, then queues its exchange's link. */
proctype replier(byte t; byte link) {
    int previous;
    store(t, payload_of(link), order_relaxed, 1);
    enqueue(t, link, previous)
}

/** The loop, calling @c dequeue_replied until it met both links, reading each one's payload. */
proctype loop(byte t) {
    int head = stub, next, seen_tail, previous, payload, popped;
    do
    :: received == 2 -> break
    :: else ->
        popped = none;
        load(t, next_of(head), order_acquire, next);
        if
        :: head == stub && next == none -> skip
        :: else ->
            if
            :: head == stub -> head = next; load(t, next_of(head), order_acquire, next)
            :: else
            fi;
            if
            :: next != none -> popped = head; head = next
            :: else ->
                load(t, tail, order_acquire, seen_tail);
                if
                :: head == seen_tail ->
                    enqueue(t, stub, previous);
                    load(t, next_of(head), order_acquire, next);
                    if
                    :: next != none -> popped = head; head = next
                    :: else
                    fi
                :: else
                fi
            fi
        fi;
        if
        :: popped != none ->
            assert(popped != stub && !dequeued[popped]);
            dequeued[popped] = 1;
            received++;
            load(t, payload_of(popped), order_relaxed, payload);
            assert(payload == 1)
        :: else
        fi
    od
}

init {
    atomic {
        seed(tail, stub);
        seed(next_of(stub), none);
        seed(next_of(1), none);
        seed(next_of(2), none);
        run replier(0, 1);
        run replier(1, 2);
        run loop(2)
    }
}
