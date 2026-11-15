/**
 *  @file verification/batch_ring.pml
 *  @author Ash Vardanian
 *  @date November 12, 2026
 *  @brief Spin model of a batch endpoint's ring in @c include/ucall/network/serving.hpp and
 *      @c include/ucall/network/server.hpp: the deposit in @c dispatch against
 *      @c collect_deposits, @c abandoned and @c wait_for_deposits, beside @c detach of
 *      @c include/ucall/network/replies.hpp.
 *
 *  Two event loops each write a request, claim an index with an add of the tail, store the
 *  exchange into that slot with a release, and wake the polling owner when they find it sleeping.
 *  The first loop's peer may then leave, which sets the exchange's detached bit. The owner reads
 *  the tail, waits on each claimed slot until its store lands, and ends an exchange it finds
 *  detached instead of handing it to the application; with nothing left it announces sleep and
 *  looks at the tail once more before blocking.
 *
 *  - Each deposit is taken exactly once, handed or ended, its request read as written.
 *  - An exchange is ended unanswered only after its peer left.
 *  - The owner never sleeps on a deposit no write to its channel is owed for.
 *
 *  @budget 4096
 *  @verify pass sc,rc11
 *  @verify stuck sc recheck_tail=false: a deposit landing between the owner's drain and its
 *      announced sleep finds it awake, wakes nobody, and is never taken
 */
#define thread_count 3
#define location_count 6
#define history_depth 12
#include <weak_memory.pml>
#include <monitor_wait.pml>

/** The deposits, one per event loop, and the value of a slot nothing was stored into. */
#define deposits 2
#define empty 0

/** The words: the ring's tail, its slots, each exchange, and the owner's wake state. */
#define tail 0
#define slot_of(index) (1 + (index))
#define exchange_of(exchange) (3 + (exchange))
#define wake_state 5

/** What an exchange's word holds: its request once written, and the state bits @c abandoned
 *  reads and sets. */
#define written 1
#define detached 2
#define claimed 4

/** The wake state's values, as @c wake_state_t spells them. */
#define awake 0
#define sleeping 1

/** The knob: the header's choice, overridden by a <tt>@verify</tt> line. */
#ifndef recheck_tail
#define recheck_tail true
#endif

byte handed[deposits]; // ghost: exchanges the application received
byte ended[deposits];  // ghost: exchanges the owner ended unanswered
bit left[deposits];    // ghost: exchanges whose peer left
byte channel;          // ghost: wake channel writes not yet read

/** A sequentially consistent load: every write to the words it reads is sequentially consistent
 *  too, so it reads the newest. */
inline load_consistent(t, l, out) { atomic { see_newest(t); load(t, l, order_acquire, out) } }

/** An event loop depositing @p exchange, whose peer leaves afterwards when @p leaves. */
proctype event_loop(byte t; byte exchange; bit leaves) {
    int index, observed;
    store(t, exchange_of(exchange), order_relaxed, written);
    read_modify_write(t, tail, order_acq_rel, index, index + 1);
    atomic { store(t, slot_of(index), order_release, exchange + 1); wake(slot_of(index)) };
    load_consistent(t, wake_state, observed);
    if
    :: observed == sleeping ->
        read_modify_write(t, wake_state, order_acq_rel, observed, awake);
        if
        :: observed == sleeping -> channel++
        :: else
        fi
    :: else
    fi;
    if
    :: leaves ->
        left[exchange] = 1;
        read_modify_write(t, exchange_of(exchange), order_release, observed, observed | detached)
    :: else
    fi
}

/** The polling owner: rounds of @c collect_deposits and @c wait_for_deposits until both came. */
proctype owner(byte t) {
    int head = 0, seen_tail, exchange, observed;
    do
    :: head == deposits -> break
    :: else ->
        load(t, tail, order_acquire, seen_tail);
        do
        :: head == seen_tail -> break
        :: else ->
            load(t, slot_of(head), order_acquire, exchange);
            do
            :: exchange != empty -> break
            :: else ->
                wait_on(t, slot_of(head), empty, false);
                load(t, slot_of(head), order_acquire, exchange)
            od;
            exchange = exchange - 1;
            load(t, exchange_of(exchange), order_acquire, observed);
            assert((observed & written) != 0);
            if
            :: (observed & detached) != 0 ->
                assert(left[exchange]);
                read_modify_write(t, exchange_of(exchange), order_release, observed, observed | claimed);
                ended[exchange]++
            :: else -> handed[exchange]++
            fi;
            assert(handed[exchange] + ended[exchange] == 1);
            head++
        od;
        if
        :: head == deposits -> break
        :: else
        fi;
        atomic { see_newest(t); store(t, wake_state, order_release, sleeping) };
        if
        :: recheck_tail -> load_consistent(t, tail, seen_tail)
        :: else
        fi;
        if
        :: seen_tail == head -> atomic { channel > 0 -> channel = 0 }
        :: else
        fi;
        atomic { see_newest(t); store(t, wake_state, order_release, awake) }
    od
}

init {
    atomic {
        seed(tail, 0);
        seed(slot_of(0), empty);
        seed(slot_of(1), empty);
        seed(exchange_of(0), 0);
        seed(exchange_of(1), 0);
        seed(wake_state, awake);
        run event_loop(0, 0, 1);
        run event_loop(1, 1, 0);
        run owner(2)
    }
}
