"""Measure fixed-count binary echo exchanges through Python's asynchronous gRPC client.

File: bench/grpc_client.py
Author: Ash Vardanian
Date: October 19, 2026
"""

import argparse
import asyncio
import math
import time
from contextlib import AsyncExitStack

import echo_pb2
import echo_pb2_grpc
import grpc


def count(value: str) -> int:
    """Parse a nonnegative count without imposing a workload ceiling."""
    result = int(value)
    if result < 0:
        raise argparse.ArgumentTypeError("Expected a nonnegative count")
    return result


async def phase(
    stubs: list[echo_pb2_grpc.EchoStub], payload: bytes, requests: int, concurrency: int
) -> tuple[list[int], int, float]:
    """Complete exactly the requested attempts using a fixed set of asynchronous workers."""
    samples = [0] * requests
    failures = [0] * concurrency
    message = echo_pb2.Payload(data=payload)

    async def worker(worker_index: int) -> None:
        stub = stubs[worker_index % len(stubs)]
        for request_index in range(worker_index, requests, concurrency):
            begin = time.perf_counter_ns()
            try:
                response = await stub.Exchange(message)
                elapsed = time.perf_counter_ns() - begin
                if response.data != payload:
                    failures[worker_index] += 1
                else:
                    samples[request_index] = elapsed
            except grpc.aio.AioRpcError:
                failures[worker_index] += 1

    begin = time.perf_counter_ns()
    await asyncio.gather(*(worker(index) for index in range(concurrency)))
    return samples, sum(failures), (time.perf_counter_ns() - begin) / 1e9


async def run(args: argparse.Namespace) -> int:
    """Warm the channels, then report the measured request count and verified latencies."""
    payload = b"\0" + b"x" * (args.bytes - 1) if args.bytes else b""
    options = (
        ("grpc.max_receive_message_length", -1),
        ("grpc.max_send_message_length", -1),
        ("grpc.use_local_subchannel_pool", 1),
    )
    async with AsyncExitStack() as stack:
        channels = [
            await stack.enter_async_context(grpc.aio.insecure_channel(args.address, options=options))
            for _ in range(args.connections)
        ]
        await asyncio.gather(*(channel.channel_ready() for channel in channels))
        stubs = [echo_pb2_grpc.EchoStub(channel) for channel in channels]
        _, failures, _ = await phase(stubs, payload, args.warmup_requests, args.concurrency)
        if failures:
            print(f"Warmup failed: {failures} exchanges")
            return 1
        samples, failures, elapsed = await phase(stubs, payload, args.requests, args.concurrency)
    successful = [sample for sample in samples if sample]
    print(f"Requests: {args.requests}, successful: {len(successful)}, failures: {failures}")
    if not successful:
        return 1
    print(f"Connections: {args.connections}, in-flight calls: {args.concurrency}, payload bytes: {args.bytes}")
    print(f"Elapsed: {elapsed:.6f} s, throughput: {len(successful) / elapsed:.1f} requests/s")
    mean = sum(successful) / len(successful) / 1e3
    successful.sort()
    percentiles = [successful[math.ceil(len(successful) * fraction) - 1] / 1e3 for fraction in (0.50, 0.95, 0.99)]
    print(
        f"Latency: mean {mean:.2f} us, p50 {percentiles[0]:.2f} us, p95 {percentiles[1]:.2f} us, p99 {percentiles[2]:.2f} us"
    )
    return int(failures != 0)


def main() -> None:
    """Select the request count, payload size, and transport concurrency."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", nargs="?", default="127.0.0.1:8546")
    parser.add_argument("--requests", type=count, required=True)
    parser.add_argument("--warmup-requests", type=count, default=0)
    parser.add_argument("--connections", type=count, default=1)
    parser.add_argument("--concurrency", type=count, default=64)
    parser.add_argument("--bytes", type=count, default=1024)
    args = parser.parse_args()
    if not args.requests or not args.connections or not args.concurrency:
        parser.error("--requests, --connections and --concurrency must be positive")
    raise SystemExit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
