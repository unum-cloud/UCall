# UCall Examples

The native examples use the public C ABI and run with any compiled transport backend.
They bind loopback and accept `--backend`, `--cpu-class`, `--threads`, and `--port`.
The backend defaults to automatic, the CPU class to serial, and the application polling thread count to one; the port defaults to 8545.

| Example                             | Individual endpoints                                | Batched endpoint                      |
| :---------------------------------- | :-------------------------------------------------- | :------------------------------------ |
| [Echo](echo/server.cpp)             | `POST /echo`, `GET /health`                         | `POST /echo/batch`                    |
| [Key-value store](redis/server.cpp) | `GET`, `PUT`, `DELETE /kv/{key}`                    | The same methods at `/batch/kv/{key}` |
| [Ledger](ledger/server.cpp)         | `GET /accounts/{id}`, `POST /transfers/{from}/{to}` | `POST /batch/transfers/{from}/{to}`   |

Each batch callback receives a borrowed array of request handles and its count, and reuses the individual handler for each request.
These routes coalesce requests ready on one polling loop without waiting for a minimum group size.
Each request keeps its own response; ledger transfers and key-value operations keep their individual transaction boundaries.

The echo service also exposes `POST /echo/reordered` for the benchmark driver's `--reorder` workload.
It retains a tagged request until its partner arrives, then publishes the second member's response before the first without blocking the polling caller.
This demonstrates delayed retained replies; socket arrival and client polling order remain independently observable.

Build with `UCALL_BUILD_EXAMPLES=ON` and select `ucall_example_echo`, `ucall_example_redis`, or `ucall_example_ledger`.
Each executable selects among the backends compiled into the single UCall library.
`--connections` supplies the admission budget, and `--threads` selects the application-owned polling loops.
The application dispatches those loops through its ForkUnion pool; UCall creates no threads.
Callbacks run on the polling caller, and the examples stop and join their polling threads on SIGINT or SIGTERM.
The [benchmark driver](../bench/README.md) measures the same raw HTTP echo workload across backends.

[fastapi_server.py](fastapi_server.py) exposes the same echo and health routes for a Python comparison.
Run it with `uvicorn examples.fastapi_server:app --host 127.0.0.1 --port 8545`.
[fastapi_client.py](fastapi_client.py) checks either server with `python examples/fastapi_client.py`.
