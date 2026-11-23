/**
 *  @file verification/client_binding.pml
 *  @author Ash Vardanian
 *  @date November 12, 2026
 *  @brief Spin model of freeing a client bound to a server's event loop: @c client_free and
 *      @c retire in @c include/ucall/network/client.hpp against @c bound_progress in
 *      @c include/ucall/network/server.hpp.
 *
 *  A bound client's connections live in its loop's queue, so only the loop may touch them. Its
 *  owner frees it from any thread with one release store of the binding word. The loop steps the
 *  client every round, acquires the word, fails the connections of a freed client itself, and
 *  deletes the client once its last connection closed.
 *
 *  - No two threads touch the client's connections at once.
 *  - Nothing touches the client after the loop deleted it, and it is deleted exactly once.
 *
 *  @verify pass sc,rc11
 *  @verify fail sc retire_on_free=true: an owner that fails the connections itself races the
 *      loop stepping them, and may touch a client the loop already deleted
 */
#define thread_count 2
#define location_count 1
#define history_depth 2
#include <weak_memory.pml>

/** The word: the client's binding, and the two values of it the model needs, as
 *  @c client_binding_t spells them. */
#define binding 0
#define bound 1
#define freed 2

/** The knob: the header's choice, overridden by a <tt>@verify</tt> line. */
#ifndef retire_on_free
#define retire_on_free false
#endif

bit touching;   // ghost: a thread is inside the client's connections
bit failed;     // ghost: the connections were told to close
byte deleted;   // ghost: how often the client was deleted

/** One thread's access to the client's connections, which no other may overlap or outlive. */
inline touch() {
    atomic { assert(!touching && deleted == 0); touching = 1 };
    touching = 0
}

/** The owner: frees the client, and under the knob fails its connections as it does. */
proctype owner(byte t) {
    store(t, binding, order_release, freed);
    if
    :: retire_on_free -> touch(); failed = 1
    :: else
    fi
}

/** The loop: rounds of @c bound_progress until it deleted the client. */
proctype loop(byte t) {
    int observed;
    bit retiring = 0;
    do
    :: deleted != 0 -> break
    :: else ->
        load(t, binding, order_acquire, observed);
        if
        :: observed == freed && !retiring -> touch(); failed = 1; retiring = 1
        :: else
        fi;
        touch();
        if
        :: retiring && failed -> deleted++; assert(deleted == 1)
        :: else
        fi
    od
}

init {
    atomic {
        seed(binding, bound);
        run owner(0);
        run loop(1)
    }
}
