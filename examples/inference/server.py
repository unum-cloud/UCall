"""UCall Python inference service, the twin of the FastAPI and LitServe baselines for `/infer`.

`/infer` scores one query on the polling thread that received it, and `/infer/batch` is a batch
endpoint whose drain thread scores each batch in one pass with the shared NumKong kernel in
`examples/inference/model.py`, so responses are byte-identical to `ucall_example_inference` for the same seed.
The binding starts no threads: this script starts one per event loop and one for the batch drain.

File: examples/inference/server.py
Author: Ash Vardanian
Date: October 25, 2026
"""

import argparse
import signal
import threading

import model
import numpy as np

import ucall

INVALID_QUERY = b"The body must be exactly one i8 query of --dimensions bytes\n"


def build_server(arguments: argparse.Namespace) -> ucall.Server:
    """Load the matrix and return a server with `/infer`, `/infer/batch` and `/health`."""
    matrix = model.load_matrix(arguments.rows, arguments.dimensions, arguments.seed)
    server = ucall.Server(
        ucall.Interface(
            f"127.0.0.1:{arguments.port}",
            event_loops=arguments.threads,
            connections=arguments.connections,
            pipelined_requests=arguments.pipelined_requests,
        ),
        backend=arguments.backend,
    )

    @server.post("/infer")
    def infer_one(request: ucall.Request) -> bytes | None:
        """Score one query on the polling thread, the unbatched baseline."""
        query = model.parse_query(request.body, arguments.dimensions)
        if query is None:
            request.reply_error(400, INVALID_QUERY)
            return None
        (response,) = model.infer(matrix, query[np.newaxis, :])
        return response

    @server.batch(
        "/infer/batch",
        min_size=arguments.batch_min,
        max_size=arguments.batch_max,
        max_latency_us=arguments.batch_latency_us,
    )
    def infer_batch(requests: list[ucall.Request]) -> None:
        """Score every valid query of the batch in one pass and answer each request."""
        valid, queries = [], []
        for request in requests:
            query = model.parse_query(request.body, arguments.dimensions)
            if query is None:
                request.reply_error(400, INVALID_QUERY)
            else:
                valid.append(request)
                queries.append(query)
        if not queries:
            return
        for request, response in zip(valid, model.infer(matrix, np.stack(queries)), strict=True):
            request.reply(response, headers=("content-type: application/octet-stream",))

    @server.get("/health")
    def health() -> bytes:
        """Report readiness."""
        return b"ready\n"

    return server


def main() -> None:
    """Parse the shared flags and serve until SIGINT or SIGTERM."""
    summary, _, _ = __doc__.partition("\n")
    parser = argparse.ArgumentParser(description=summary)
    parser.add_argument("--rows", type=int, default=100_000)
    parser.add_argument("--dimensions", type=int, default=1024)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--port", type=int, default=8545)
    parser.add_argument("--backend", default="automatic", help="I/O backend, such as linux-epoll or posix")
    parser.add_argument("--threads", type=int, default=1, help="event loops, each polled by its own thread")
    parser.add_argument("--connections", type=int, default=1024)
    parser.add_argument("--pipelined-requests", type=int, default=0)
    parser.add_argument("--batch-min", type=int, default=1)
    parser.add_argument("--batch-max", type=int, default=32)
    parser.add_argument("--batch-latency-us", type=int, default=10_000)
    arguments = parser.parse_args()

    server = build_server(arguments)
    stopping = threading.Event()
    for signal_number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signal_number, lambda *_: stopping.set())
    threads = [threading.Thread(target=server.take_calls, args=(loop,)) for loop in range(server.event_loops)]
    threads += [threading.Thread(target=endpoint.take_batches) for endpoint in server.batch_endpoints]
    for thread in threads:
        thread.start()
    print(
        f"Listening on {server.addresses[0]} using {server.backend.name}, {server.cpu_class.name}, "
        f"{server.event_loops} application-owned serving loops"
    )
    stopping.wait()
    server.stop()
    for thread in threads:
        thread.join()


if __name__ == "__main__":
    main()
