"""LitServe inference service with its own batching, the second baseline for `/infer/batch`.

LitServe gathers up to `max_batch_size` requests or waits `batch_timeout` seconds, then scores
the stack with the shared NumKong kernel in `examples/inference/model.py`. It has no minimum batch size, so
`--batch-min` is accepted for a uniform command line and ignored.
LitServe decodes request bodies as JSON, so a small ASGI middleware wraps each raw i8 body as a
hexadecimal JSON string before routing; the report should name that cost beside the results.

File: examples/inference/server_litserve.py
Author: Ash Vardanian
Date: October 25, 2026
"""

import argparse
import json

import litserve as ls
import model
import numpy as np
import numpy.typing as npt
from fastapi import HTTPException, Response


class RawQueryAsJson:
    """ASGI middleware presenting a raw POST body as `{"query": "<hex>"}` to LitServe."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST":
            await self.app(scope, receive, send)
            return
        chunks, more = [], True
        while more:
            message = await receive()
            chunks.append(message.get("body", b""))
            more = message.get("more_body", False)
        body = json.dumps({"query": b"".join(chunks).hex()}).encode()
        headers = [
            (name, value) for name, value in scope["headers"] if name not in (b"content-type", b"content-length")
        ]
        headers += [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
        delivered = False

        async def replay():
            nonlocal delivered
            if delivered:
                return await receive()
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(dict(scope, headers=headers), replay, send)


class InferenceAPI(ls.LitAPI):
    """Score batches of i8 queries against the resident matrix."""

    def __init__(self, arguments: argparse.Namespace) -> None:
        super().__init__(
            max_batch_size=arguments.batch_max,
            batch_timeout=arguments.batch_latency_us / 1e6,
            api_path="/infer/batch",
        )
        self.arguments = arguments

    def setup(self, device: str) -> None:
        """Load the matrix once per worker process."""
        self.matrix = model.load_matrix(self.arguments.rows, self.arguments.dimensions, self.arguments.seed)

    def decode_request(self, request: dict) -> npt.NDArray[np.int8]:
        """Turn one wrapped body back into an i8 query, refusing a body of the wrong size."""
        query = model.parse_query(bytes.fromhex(request["query"]), self.arguments.dimensions)
        if query is None:
            raise HTTPException(status_code=400, detail="The body must be exactly one i8 query of --dimensions bytes")
        return query

    def batch(self, inputs: list[npt.NDArray[np.int8]]) -> npt.NDArray[np.int8]:
        """Stack the decoded queries for one pass over the matrix."""
        return np.stack(inputs)

    def predict(self, queries: npt.NDArray[np.int8]) -> list[bytes]:
        """Score the whole batch with the shared kernel."""
        return model.infer(self.matrix, queries)

    def unbatch(self, output: list[bytes]) -> list[bytes]:
        """Hand each request its own response."""
        return output

    def encode_response(self, output: bytes) -> Response:
        """Return the native 80-byte layout unchanged."""
        return Response(content=output, media_type="application/octet-stream")


def main() -> None:
    """Parse the shared flags and serve one CPU worker."""
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
    server = ls.LitServer(
        InferenceAPI(arguments), accelerator="cpu", workers_per_device=1, middlewares=[RawQueryAsJson]
    )
    server.run(host="127.0.0.1", port=arguments.port, generate_client_file=False)


if __name__ == "__main__":
    main()
