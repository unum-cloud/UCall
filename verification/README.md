# Verification

Model checking for the words UCall's threads share and the stages a connection leaves by: reply segments, the replied queue, the reply claim, batch rings, response pools, bound clients and transport stages.
[Spin](https://spinroot.com) checks each protocol as a Promela model, and [GenMC](https://github.com/MPI-SWS/genmc) checks the C++ against ForkUnion's atomic references where it fits.

- `segment_links.pml`: a replier linking an exchange's reply segments while the loop adopts and retires them.
- `replied_queue.pml`: the loop's intrusive queue of replied exchanges, its wake-up, and an exchange living twice.
- `claims.pml`, `claims.cpp`: two repliers claiming one exchange while the loop detaches its closed connection.
- `batch_ring.pml`: event loops depositing requests into a batch endpoint's ring while its polling owner collects, sleeps and ends abandoned ones.
- `response_pool.pml`: a client's responses freed from other threads, and the pool outliving the client.
- `client_binding.pml`: freeing a client bound to a server's event loop from another thread.
- `transport_stages.pml`: one server connection's stages from open to idle, through lingers, cancels, releases and resets.

## Running

`./check.sh` runs every model, and `./check.sh <file>...` only those; the GenMC clients run when `GENMC` names its executable.
The runner comes from the `forkunion` submodule, `git submodule update --init forkunion`, or from the checkout `FORKUNION_SOURCE` names.
ForkUnion's [verification README](https://github.com/ashvardanian/ForkUnion/blob/main/verification/README.md) documents the runner, the `@verify` grammar, the include roots and the memory budgets.

Each model's header names the functions it mirrors and lists its `@verify` lines.
A `pass` line is the header's own choice, and every `fail` or `stuck` line flips one knob to show what that choice protects.

## What the Models Found

- The loop parks the segment its cursor rests on, or a replier links onto a record it no longer owns: [`segment_links.pml`](segment_links.pml).
- The loop clears an exchange's listed bit before adopting, or a push landing in between is never queued again: [`segment_links.pml`](segment_links.pml).
- A segment's link is stored with a release, or the loop reads a payload from before it was written: [`segment_links.pml`](segment_links.pml), [`replied_queue.pml`](replied_queue.pml).
- The loop drains the replied queue once more after announcing sleep, and acquires both the clear and the awake mark of its wake word: [`replied_queue.pml`](replied_queue.pml).
- A reused exchange keeps its listed bit and resets its stage, or a late listing queues one link twice and recycles a free exchange again: [`replied_queue.pml`](replied_queue.pml).
- `detach` sets the detached bit with a release and a claimer loads the state with an acquire, or the claimer misses that its connection left: [`claims.pml`](claims.pml), [`claims.cpp`](claims.cpp).
- A batch owner reads the ring's tail once more after announcing sleep, or a deposit that found it awake is never taken: [`batch_ring.pml`](batch_ring.pml).
- The tail add, not the slot store, carries a deposited request to the owner, which waits on a claimed slot until its store lands: [`batch_ring.pml`](batch_ring.pml).
- A free pushes its response before subtracting the pool's count, or the client drains a pool the freer still writes: [`response_pool.pml`](response_pool.pml).
- With three responses out, a relaxed push leaks one, so the push releases: [`response_pool.pml`](response_pool.pml).
- The owner of a bound client only stores its binding word, and the loop alone fails and deletes its connections: [`client_binding.pml`](client_binding.pml).
- A reset close holds its connection in `closed_holding_k` until the releases of what it sent arrive, or the connection turns idle under them: [`transport_stages.pml`](transport_stages.pml).
