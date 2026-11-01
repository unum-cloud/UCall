/**
 *  @file verification/replied_queue.pml
 *  @author Ash Vardanian
 *  @date October 27, 2026
 *  @brief Spin model of an event loop's replied queue in `include/ucall/network.hpp`:
 *      @c enqueue_replied and @c dequeue_replied, Vyukov's intrusive queue with a stub, the
 *      adoption in @c serve_open beside the one in @c collect_replies, and the wake-up between
 *      @c event_loop_t::notify and @c server_poll.
 *
 *  A pusher clears its link's @c next, exchanges the tail to its link, and stores its link into the
 *  @c next of the link it displaced, with a release. The loop alone walks from its head, which
 *  starts at the stub. Two repliers each write a payload, push it with a release store, queue their
 *  exchange's link, and notify: an exchange of the wake word, writing the wake channel only when it
 *  found the loop sleeping. The loop runs rounds: a pass serving a connection may adopt its
 *  replier's push with an acquire load before the queue hands the link out, then it drains the
 *  queue, adopting whatever is still unadopted. Before sleeping it exchanges the word to sleeping
 *  and drains again when a notify landed while it ran; it blocks until the channel was written,
 *  then marks itself awake with another exchange.
 *
 *  - Each link comes out exactly once.
 *  - Each push is adopted exactly once, its payload read as written, and a dequeued link whose
 *    push nobody adopted finds it.
 *  - The loop never sleeps with a link it did not drain and no write to its channel owed.
 *
 *  With @c recycle, one exchange lives twice. Its first replier links the end, the loop adopts it
 *  in a pass and recycles the exchange, and only then does the replier's listing land, queueing
 *  the link of a free or reused exchange. The loop reuses the exchange for a second replier, which
 *  pushes and lists again, while the late link may still be queued.
 *
 *  - A link is never queued while it is queued already.
 *  - A late listing of a free exchange recycles nothing a second time.
 *
 *  @verify pass sc,rc11
 *  @verify fail rc11 link_order=order_relaxed: relaxed, the loop follows the link and reads the
 *      payload from before the replier wrote it
 *  @verify fail rc11 adopt_order=order_relaxed: a relaxed adoption in the pass sees the push and
 *      reads the payload from before it
 *  @verify stuck sc redrain=false: a link queued while the loop ran, whose notify found it awake,
 *      is never drained once the loop sleeps
 *  @verify stuck rc11 clear_order=order_release: without acquiring, the drain after the clear can
 *      miss the link of the notify it read
 *  @verify stuck rc11 mark_order=order_release: a notify that found the channel already written
 *      is acquired by nobody, so its link can stay unseen while the loop sleeps again
 *  @verify pass sc,rc11 recycle=true
 *  @verify fail sc recycle=true keep_listed=false: clearing the listed bit at reuse lets the second
 *      replier queue the link the late listing queued already
 *  @verify fail sc recycle=true reset_stage=false: a free exchange still marked ended recycles
 *      again when the late listing is drained
 */
#define thread_count 3
#define location_count 11
#define history_depth 10
#include <weak_memory.pml>

/** The links: the loop's stub and one per replier, and none, which no `next` names. */
#define stub 0
#define none 3

/** The words: the tail, each link's @c next, each replier's payload and push, and the wake word. */
#define tail 0
#define next_of(link) (1 + (link))
#define payload_of(link) (3 + (link))
#define pushed_of(link) (5 + (link))
#define wake_word 8

/** The recycle scenario's words: the exchange's state, holding only its listed bit, and its push,
 *  naming the life that pushed. */
#define listed_word 9
#define pushed_word 10

/** The wake word's states, as @c wake_state_t spells them. */
#define awake 0
#define sleeping 1
#define notified 2

/** The knobs: the header's choices, each overridden by a <tt>@verify</tt> line. */
#ifndef link_order
#define link_order order_release
#endif
#ifndef adopt_order
#define adopt_order order_acquire
#endif
#ifndef redrain
#define redrain true
#endif
#ifndef clear_order
#define clear_order order_acq_rel
#endif
#ifndef mark_order
#define mark_order order_acq_rel
#endif
#ifndef recycle
#define recycle false
#endif
#ifndef keep_listed
#define keep_listed true
#endif
#ifndef reset_stage
#define reset_stage true
#endif

/** The exchange's stage in the recycle scenario, as @c exchange_stage_t spells the two it needs. */
#define dispatched_stage 0
#define ended_stage 2

bit dequeued[3]; // ghost: links the loop handed out
bit adopted[3];  // ghost: pushes the loop adopted
byte received;   // ghost: how many links it handed out
byte channel;    // ghost: wake channel writes not yet read
bit queued[3];   // ghost: links in the queue, the stub aside
byte life = 1;   // ghost: which life of the recycled exchange runs
bit freed;       // ghost: the recycled exchange is on the free list
byte stage;      // ghost: the recycled exchange's stage
bit pushed_life[3]; // ghost: lives whose push the loop adopted
bit late_done, second_done; // ghost: the recycle scenario's repliers finished

/** @c enqueue_replied: one exchange of the tail, then the release store of the link behind it. */
inline enqueue(t, link, previous) {
    if
    :: link != stub -> assert(!queued[link]); queued[link] = 1
    :: else
    fi;
    store(t, next_of(link), order_relaxed, none);
    read_modify_write(t, tail, order_acq_rel, previous, link);
    store(t, next_of(previous), link_order, link)
}

/** The loop adopts @p link's push, which it saw, and reads its payload. */
inline adopt(t, link, payload) {
    assert(!adopted[link]);
    adopted[link] = 1;
    load(t, payload_of(link), order_relaxed, payload);
    assert(payload == 1)
}

/** A replier that writes its payload, pushes it, queues its exchange's link and notifies. */
proctype replier(byte t; byte link) {
    int previous, observed;
    store(t, payload_of(link), order_relaxed, 1);
    store(t, pushed_of(link), order_release, 1);
    enqueue(t, link, previous);
    read_modify_write(t, wake_word, order_acq_rel, observed, notified);
    if
    :: observed == sleeping -> channel++
    :: else
    fi
}

/** @c dequeue_replied: the next link into @c popped, or none. */
inline dequeue(t) {
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
    :: popped != none -> queued[popped] = 0
    :: else
    fi
}

/** @c collect_replies: @c dequeue_replied until it hands out nothing, adopting each link's push
 *  unless a pass adopted it first. */
inline drain(t) {
    do
    :: dequeue(t);
        if
        :: popped != none ->
            assert(popped != stub && !dequeued[popped]);
            dequeued[popped] = 1;
            received++;
            if
            :: !adopted[popped] ->
                load(t, pushed_of(popped), order_acquire, pushed);
                assert(pushed == 1);
                adopt(t, popped, payload)
            :: else
            fi
        :: else -> break
        fi
    od
}

/** The loop's rounds of @c server_poll until it met both links. */
proctype loop(byte t) {
    int head = stub, next, seen_tail, previous, payload, popped, pushed, observed;
    byte link;
    do
    :: received == 2 -> break
    :: else ->
        // A pass over a connection may adopt its replier's push ahead of the queue.
        for (link : 1 .. 2) {
            if
            :: !adopted[link] ->
                load(t, pushed_of(link), adopt_order, pushed);
                if
                :: pushed == 1 -> adopt(t, link, payload)
                :: else
                fi
            :: skip
            fi
        }
        drain(t);
        if
        :: received == 2 -> break
        :: else
        fi;
        read_modify_write(t, wake_word, clear_order, observed, sleeping);
        if
        :: observed == notified && redrain -> drain(t)
        :: else
        fi;
        if
        :: received == 2 -> break
        :: else
        fi;
        atomic { channel > 0 -> channel = 0 };
        read_modify_write(t, wake_word, mark_order, observed, awake)
    od
}

/** The first life's replier: links the end, and lists the exchange only once the loop may
 *  have recycled it. */
proctype late_replier(byte t) {
    int previous, observed;
    store(t, pushed_word, order_release, 1);
    read_modify_write(t, listed_word, order_acq_rel, observed, 1);
    if
    :: observed == 0 -> enqueue(t, 1, previous)
    :: else
    fi;
    late_done = 1
}

/** The second life's replier, handed the request by the loop's dispatch. */
proctype second_replier(byte t; byte loop_thread) {
    int previous, observed;
    atomic { life == 2 -> merge_view(loop_thread, t) };
    store(t, pushed_word, order_release, 2);
    read_modify_write(t, listed_word, order_acq_rel, observed, 1);
    if
    :: observed == 0 -> enqueue(t, 1, previous)
    :: else
    fi;
    second_done = 1
}

/** The loop adopts the running life's push once it sees it, which ends that life's reply. */
inline adopt_life(t) {
    load(t, pushed_word, order_acquire, pushed);
    if
    :: pushed == life && !pushed_life[life] -> pushed_life[life] = 1; stage = ended_stage
    :: else
    fi
}

/** The loop over one exchange living twice: passes adopt, @c collect_replies unlists and adopts or
 *  meets an orphan, the first life recycles once adopted and is reused for the second. */
proctype recycling_loop(byte t) {
    int head = stub, next, seen_tail, previous, popped, pushed, observed;
    do
    :: life == 2 && pushed_life[2] && late_done && second_done && !queued[1] -> break
    :: else ->
        if
        :: !freed -> adopt_life(t)
        :: dequeue(t);
            if
            :: popped != none ->
                read_modify_write(t, listed_word, order_acq_rel, observed, 0);
                if
                :: freed -> assert(stage != ended_stage)
                :: else -> adopt_life(t)
                fi
            :: else
            fi
        fi;
        if
        :: life == 1 && pushed_life[1] && !freed ->
            freed = 1;
            if
            :: reset_stage -> stage = dispatched_stage
            :: else
            fi
        :: life == 1 && freed ->
            if
            :: !keep_listed -> store(t, listed_word, order_relaxed, 0)
            :: else
            fi;
            stage = dispatched_stage;
            freed = 0;
            life = 2
        :: skip
        fi
    od
}

init {
    atomic {
        seed(tail, stub);
        seed(next_of(stub), none);
        seed(next_of(1), none);
        seed(next_of(2), none);
        seed(wake_word, awake);
        seed(listed_word, 0);
        seed(pushed_word, 0);
        if
        :: recycle ->
            run late_replier(0);
            run second_replier(1, 2);
            run recycling_loop(2)
        :: else ->
            run replier(0, 1);
            run replier(1, 2);
            run loop(2)
        fi
    }
}
