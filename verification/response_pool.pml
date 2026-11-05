/**
 *  @file verification/response_pool.pml
 *  @author Ash Vardanian
 *  @date November 2, 2026
 *  @brief Spin model of a client's responses in @c include/ucall/network/client.hpp:
 *      @c take_response, @c response_t::release, @c delete_pool and the teardown in @c ~client.
 *
 *  The pool holds a take-all stack @c returned and a count @c outside of one for the client plus
 *  one per response handed out. A free pushes its response with a releasing compare-exchange, then
 *  subtracts one with an acquire-release; whoever subtracts the last frees the pool. The client
 *  takes each response off its free list, refilled by an acquiring take of the stack, or allocates
 *  one, and hands it to one of two freers; then it frees its free list and drops its own count.
 *
 *  - No response and not the pool is freed twice, and no push or take touches freed memory.
 *  - Once everyone finished, every response and the pool are freed.
 *
 *  @verify pass sc,rc11
 *  @verify pass sc,rc11 handouts=3
 *  @verify fail sc push_first=false: subtracting first lets the client drop the last reference and
 *      drain the pool while the freer still pushes, which leaks its response or writes a freed pool
 *  @verify pass rc11 push_order=order_relaxed: the pool's freer acquires every link through the
 *      count, which each free subtracts only after its push
 *  @verify fail rc11 handouts=3 push_order=order_relaxed: the client's take reads the second
 *      pushed response's link from before its push, and leaks the first
 */
#define thread_count 3
#define location_count 5
#define history_depth 8
#include <weak_memory.pml>

/** The responses, and none, which no link names. */
#define none 3

/** The words: the pool's stack and count, and each response's @c next. */
#define returned 0
#define outside 1
#define next_of(response) (2 + (response))

/** The knobs: the header's choices, each overridden by a <tt>@verify</tt> line. */
#ifndef handouts
#define handouts 2
#endif
#ifndef push_first
#define push_first true
#endif
#ifndef push_order
#define push_order order_release
#endif

byte given[handouts]; // ghost: each handout's response plus one, once handed
byte allocated;       // ghost: responses allocated so far
bit deleted[3];       // ghost: responses freed
bit pool_deleted;     // ghost: the pool freed
byte finished;        // ghost: processes done

/** Frees the responses linked from @p head through @c next. */
inline delete_chain(t, head, next) {
    do
    :: head == none -> break
    :: else ->
        atomic { assert(!deleted[head]); load(t, next_of(head), order_relaxed, next); deleted[head] = 1 };
        head = next
    od
}

/** @c delete_pool: takes the whole stack, frees it, then the pool. */
inline delete_pool(t, head, next) {
    atomic { assert(!pool_deleted); read_modify_write(t, returned, order_acquire, head, none) };
    delete_chain(t, head, next);
    atomic { assert(!pool_deleted); pool_deleted = 1 }
}

/** @c atomic_intrusive_stack::push of @p response onto the pool's stack. */
inline push(t, response, head, done) {
    atomic { assert(!pool_deleted); load(t, returned, order_relaxed, head) };
    do
    :: atomic { assert(!deleted[response]); store(t, next_of(response), order_relaxed, head) };
        atomic { assert(!pool_deleted); compare_exchange(t, returned, push_order, head, response, done) };
        if :: done -> break :: else fi
    od
}

/** The last process to finish checks nothing leaked. */
inline finish() {
    atomic {
        finished++;
        if
        :: finished == 3 ->
            assert(pool_deleted);
            for (audited : 0 .. allocated - 1) { assert(deleted[audited]) }
        :: else
        fi
    }
}

/** The client: takes and hands out each response, then tears down. */
proctype client(byte t) {
    int free_list = none, response, observed, head, next;
    byte handout, audited;
    for (handout : 0 .. handouts - 1) {
        if
        :: free_list == none ->
            atomic { assert(!pool_deleted); read_modify_write(t, returned, order_acquire, free_list, none) }
        :: else
        fi;
        if
        :: free_list != none ->
            response = free_list;
            atomic { assert(!deleted[response]); load(t, next_of(response), order_relaxed, free_list) }
        :: else -> atomic { response = allocated; allocated++ }
        fi;
        read_modify_write(t, outside, order_relaxed, observed, observed + 1);
        given[handout] = response + 1
    }
    delete_chain(t, free_list, next);
    read_modify_write(t, outside, order_acq_rel, observed, observed - 1);
    if :: observed == 1 -> delete_pool(t, head, next) :: else fi;
    finish()
}

/** A freer of every other handout from @p first: @c response_t::release on each. */
proctype freer(byte t; byte first) {
    int response, observed, head, next, done;
    byte handout = first, audited;
    do
    :: handout >= handouts -> break
    :: else ->
        atomic { given[handout] != 0 -> response = given[handout] - 1; merge_view(0, t) };
        if :: push_first -> push(t, response, head, done) :: else fi;
        read_modify_write(t, outside, order_acq_rel, observed, observed - 1);
        if :: !push_first -> push(t, response, head, done) :: else fi;
        if :: observed == 1 -> delete_pool(t, head, next) :: else fi;
        handout = handout + 2
    od;
    finish()
}

init {
    atomic {
        seed(returned, none);
        seed(outside, 1);
        seed(next_of(0), none);
        seed(next_of(1), none);
        seed(next_of(2), none);
        run client(0);
        run freer(1, 0);
        run freer(2, 1)
    }
}
