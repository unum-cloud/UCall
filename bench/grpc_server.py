"""Python's asynchronous gRPC serving the echo and sum workloads, one process per thread.

File: bench/grpc_server.py
Author: Ash Vardanian
Date: October 19, 2026
"""

import asyncio
import multiprocessing
from contextlib import suppress

import arguments
import bench_pb2
import bench_pb2_grpc
import grpc


class Bench(bench_pb2_grpc.BenchServicer):
    """Answer both workloads from the decoded message alone."""

    async def Echo(self, request: bench_pb2.Payload, context: grpc.aio.ServicerContext) -> bench_pb2.Payload:
        """Echo one protobuf payload, including embedded zero bytes."""
        return request

    async def Sum(self, request: bench_pb2.Operands, context: grpc.aio.ServicerContext) -> bench_pb2.Total:
        """Add two typed integers."""
        return bench_pb2.Total(sum=request.a + request.b)


async def serve(port: int) -> None:
    """Serve until interrupted, letting the transport frame any representable payload."""
    # Every process binds the same port, and the kernel spreads connections across them.
    options = (
        ("grpc.max_receive_message_length", -1),
        ("grpc.max_send_message_length", -1),
        ("grpc.so_reuseport", 1),
    )
    server = grpc.aio.server(options=options)
    bench_pb2_grpc.add_BenchServicer_to_server(Bench(), server)
    if not server.add_insecure_port(f"127.0.0.1:{port}"):
        raise RuntimeError(f"Could not bind port {port}")
    await server.start()
    try:
        await server.wait_for_termination()
    finally:
        await server.stop(None)


def run(port: int) -> None:
    """Serve one process until SIGINT."""
    with suppress(KeyboardInterrupt):
        asyncio.run(serve(port))


def main() -> None:
    """Serve from this process and one more per extra thread."""
    port, threads = arguments.parse(__doc__)
    workers = [multiprocessing.Process(target=run, args=(port,)) for _ in range(threads - 1)]
    for worker in workers:
        worker.start()
    try:
        run(port)
    finally:
        for worker in workers:
            worker.terminate()
            worker.join()


if __name__ == "__main__":
    main()
