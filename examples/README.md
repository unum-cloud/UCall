# UCall Examples

The native examples use the public C ABI and run with any compiled transport backend.
They bind loopback unless `--host` names another address, and accept `--backend`, `--cpu-class`, `--threads`, `--port`, and the pipelining, Noise, batch-budget, and `--stats` flags the [benchmark guide](../bench/README.md) lists.
The backend defaults to automatic, the CPU class to serial, and the application polling thread count to one; the port defaults to 8545.

| Example                            | Individual endpoints                                | Batched endpoint                        |
| :--------------------------------- | :-------------------------------------------------- | :-------------------------------------- |
| [Echo](echo/README.md)             | `POST /echo`, `POST /echo/reordered`                | `POST /echo/batch`                      |
| [Key-value store](redis/README.md) | `GET`, `PUT`, `DELETE /kv/{key}`                    | The same methods at `/batch/kv/{key}`   |
| [Ledger](ledger/README.md)         | `GET /accounts/{id}`, `POST /transfers/{from}/{to}` | `POST /batch/transfers/{from}/{to}`     |
| [Inference](inference/README.md)   | `POST /infer`                                       | `POST /infer/batch`, `POST /slow/batch` |

Every example also answers `GET /health` with `ready`.
Each one is a single `server.cpp` over the flag parsing, polling loops, error replies and shutdown of `tools/server.hpp`, which the native benchmark server shares.

Each batch callback receives a borrowed array of request handles and its count, and views them once as a `std::span`; the echo, key-value, and ledger callbacks reuse the individual handler for each request.
These routes coalesce requests from every polling loop under the `--batch-min`, `--batch-max`, and `--batch-latency-us` budgets.
Every batch endpoint gets a pool thread of its own that drains it through the handle its registration returned, so batch callbacks never run on a polling loop and a slow endpoint never holds another's batches.
The inference example's `/infer/batch` scores a whole batch with one NumKong packed GEMM across a ForkUnion pool, and `/slow/batch` sleeps in its callback to test that isolation.
Each request keeps its own response; ledger transfers and key-value operations keep their individual transaction boundaries.

Build with `UCALL_BUILD_EXAMPLES=ON` and select `ucall_example_echo`, `ucall_example_redis`, `ucall_example_ledger`, or `ucall_example_inference`.
Each executable selects among the backends compiled into the single UCall library.
`--connections` supplies the admission budget, and `--threads` selects the application-owned polling loops.
The application dispatches those loops through its ForkUnion pool; UCall creates no threads.
Individual callbacks run on the polling caller.
`SIGINT` or `SIGTERM` sets a flag the main thread checks every 100 ms, after which the examples stop and join their threads.
The [benchmarks](../bench/README.md) run their own servers, so these stay applications rather than measurement fixtures.
