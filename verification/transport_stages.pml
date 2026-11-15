/**
 *  @file verification/transport_stages.pml
 *  @author Ash Vardanian
 *  @date November 12, 2026
 *  @brief Spin model of one server connection's way out in
 *      @c include/ucall/network/transports.hpp and @c include/ucall/network/serving.hpp: the
 *      stages of @c transport_stage_t past @c open_k, as @c advance, @c complete, @c submitted
 *      and @c complete_release of @c include/ucall/network/replies.hpp move them.
 *
 *  An open connection holds a receive, maybe a send, and up to two zero-copy releases the kernel
 *  still owes. It leaves by its last reply, which lingers, sends the FIN and discards what the
 *  peer still writes; by a failure, which cancels what is in flight; or by an orderly close that
 *  waits for its releases. The linger deadline ends a linger and turns a waiting close into a
 *  reset, whose releases arrive after the socket closed.
 *
 *  - Every run ends closed, entering each stage once, but for the closing that an orderly wait
 *    for releases interrupts and resumes.
 *  - The close is submitted with no other operation in flight.
 *  - The connection turns idle with no release outstanding.
 *
 *  @verify pass sc
 *  @verify fail sc hold_closed=false: a reset close that turns idle at once frees a connection
 *      whose releases still arrive
 */
#define open 0
#define lingering 1
#define discarding 2
#define releasing 3
#define closing 4
#define closing_socket 5
#define closed_holding 6
#define closed 7
#define idle 8

/** The knob: the header's choice, overridden by a <tt>@verify</tt> line. */
#ifndef hold_closed
#define hold_closed true
#endif

byte stage = open;
bit receiving = 1;    // the receive is with the engine
bit transmitting;     // a send, the FIN or the close record is with the engine
bit cancelled;        // what was in flight was asked to cancel
byte releases;        // zero-copy releases the kernel still owes
bit reset;            // the close purges what the kernel held
byte entered[9];      // ghost: how often each stage was entered

inline enter(next) {
    stage = next;
    entered[next]++;
    assert(entered[next] == 1 || (next == closing && entered[next] == 2 && entered[releasing] == 1))
}

/** What @c fail does: a close already submitted or done keeps its stage. */
inline fail() {
    if
    :: stage == closing || stage == closing_socket || stage == closed_holding || stage == closed
    :: else -> enter(closing)
    fi
}

active proctype connection() {
    if
    :: releases = 0
    :: releases = 1
    :: releases = 2
    fi;
    do
    :: stage == idle -> break

    /* The engine answers what it holds. */
    :: receiving && stage != closing_socket ->
        receiving = 0;
        if
        :: stage == open -> fail()
        :: stage == open
        :: stage == lingering || stage == discarding -> fail()
        :: else
        fi
    :: transmitting -> transmitting = 0
    :: releases > 0 && (reset || stage != closing_socket) ->
        releases--;
        if
        :: releases == 0 && stage == releasing -> enter(closing)
        :: releases == 0 && stage == closed_holding -> enter(closed)
        :: else
        fi
    :: receiving && stage == closing_socket ->
        receiving = 0;
        if
        :: releases > 0 && hold_closed -> enter(closed_holding)
        :: else -> enter(closed)
        fi

    /* The application and the clock. */
    :: stage == open && !transmitting -> enter(lingering)
    :: stage == open -> fail()
    :: stage == lingering || stage == discarding -> fail()
    :: stage == releasing -> reset = 1; enter(closing)

    /* One pass of the loop over the connection. */
    :: stage == open && !receiving -> receiving = 1
    :: stage == lingering && !receiving && !transmitting ->
        transmitting = 1;
        enter(discarding)
    :: stage == discarding && !receiving && !transmitting -> receiving = 1
    :: stage == closing && (receiving || transmitting) && !cancelled -> cancelled = 1
    :: stage == closing && !receiving && !transmitting && (releases == 0 || reset) ->
        receiving = 1;
        enter(closing_socket)
    :: stage == closing && !receiving && !transmitting && releases > 0 && !reset -> enter(releasing)
    :: stage == closed ->
        assert(releases == 0 && !receiving && !transmitting);
        enter(idle)
    od
}
