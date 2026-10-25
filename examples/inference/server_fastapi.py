"""FastAPI inference service with an asyncio micro-batcher, the baseline for `/infer/batch`.

Requests queue on the event loop; one batcher task flushes them to the shared NumKong kernel in
`examples/inference/model.py` under the same budgets as a UCall batch endpoint: at once on reaching the
maximum, on reaching the minimum, or once the oldest request waited the latency budget.
The kernel runs on a worker thread, so the event loop keeps accepting while a batch scores.

File: examples/inference/server_fastapi.py
Author: Ash Vardanian
Date: October 25, 2026
"""

import argparse
import asyncio
from contextlib import asynccontextmanager

import model
import numpy as np
import numpy.typing as npt
import uvicorn
from fastapi import FastAPI, Request, Response

import numkong as nk


class MicroBatcher:
    """Collect queries from concurrent requests and score each batch in one pass over the matrix."""

    def __init__(self, matrix: nk.PackedMatrix, min_size: int, max_size: int, latency_us: int) -> None:
        self.matrix = matrix
        self.min_size = min_size
        self.max_size = max_size
        self.latency = latency_us / 1e6
        self.queue: asyncio.Queue[tuple[npt.NDArray[np.int8], asyncio.Future[bytes]]] = asyncio.Queue()

    async def submit(self, query: npt.NDArray[np.int8]) -> bytes:
        """Queue one query and wait for its scored response."""
        future = asyncio.get_running_loop().create_future()
        self.queue.put_nowait((query, future))
        return await future

    async def run(self) -> None:
        """Flush batches until cancelled, one at a time like a UCall batch endpoint's one drain."""
        loop = asyncio.get_running_loop()
        while True:
            batch = [await self.queue.get()]
            deadline = loop.time() + self.latency
            while len(batch) < self.max_size:
                while len(batch) < self.max_size and not self.queue.empty():
                    batch.append(self.queue.get_nowait())
                remaining = deadline - loop.time()
                if len(batch) >= self.min_size or len(batch) == self.max_size or remaining <= 0:
                    break
                try:
                    batch.append(await asyncio.wait_for(self.queue.get(), remaining))
                except TimeoutError:
                    break
            queries = np.stack([query for query, _ in batch])
            responses = await asyncio.to_thread(model.infer, self.matrix, queries)
            for (_, future), response in zip(batch, responses, strict=True):
                if not future.cancelled():
                    future.set_result(response)


def build_app(arguments: argparse.Namespace) -> FastAPI:
    """Load the matrix and return the application with `/infer`, `/infer/batch` and `/health`."""
    matrix = model.load_matrix(arguments.rows, arguments.dimensions, arguments.seed)
    batcher = MicroBatcher(matrix, arguments.batch_min, arguments.batch_max, arguments.batch_latency_us)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        task = asyncio.create_task(batcher.run())
        yield
        task.cancel()

    app = FastAPI(lifespan=lifespan)
    invalid = Response(b"The body must be exactly one i8 query of --dimensions bytes\n", status_code=400)

    @app.post("/infer")
    async def infer_one(request: Request) -> Response:
        """Score one query on the event loop, the unbatched baseline."""
        query = model.parse_query(await request.body(), arguments.dimensions)
        if query is None:
            return invalid
        (response,) = model.infer(matrix, query[np.newaxis, :])
        return Response(response, media_type="application/octet-stream")

    @app.post("/infer/batch")
    async def infer_batch(request: Request) -> Response:
        """Score one query as part of the next micro-batch."""
        query = model.parse_query(await request.body(), arguments.dimensions)
        if query is None:
            return invalid
        return Response(await batcher.submit(query), media_type="application/octet-stream")

    @app.get("/health")
    async def health() -> Response:
        """Report readiness."""
        return Response(b"ready\n")

    return app


def main() -> None:
    """Parse the shared flags and serve on one Uvicorn worker."""
    summary, _, _ = __doc__.partition("\n")
    parser = argparse.ArgumentParser(description=summary)
    parser.add_argument("--rows", type=int, default=100_000)
    parser.add_argument("--dimensions", type=int, default=1024)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--port", type=int, default=8545)
    parser.add_argument("--batch-min", type=int, default=1)
    parser.add_argument("--batch-max", type=int, default=32)
    parser.add_argument("--batch-latency-us", type=int, default=10_000)
    arguments = parser.parse_args()
    uvicorn.run(build_app(arguments), host="127.0.0.1", port=arguments.port, log_level="warning", access_log=False)


if __name__ == "__main__":
    main()
