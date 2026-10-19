"""Serve the binary echo workload through Python's asynchronous gRPC API.

File: bench/grpc_server.py
Author: Ash Vardanian
Date: October 19, 2026
"""

import argparse
import asyncio
from contextlib import suppress

import echo_pb2
import echo_pb2_grpc
import grpc


class Echo(echo_pb2_grpc.EchoServicer):
    """Return the application bytes without transforming them."""

    async def Exchange(self, request: echo_pb2.Payload, context: grpc.aio.ServicerContext) -> echo_pb2.Payload:
        """Echo one protobuf payload, including embedded zero bytes."""
        return request


async def serve(address: str) -> None:
    """Serve until interrupted, letting the transport frame any representable payload."""
    server = grpc.aio.server(options=(("grpc.max_receive_message_length", -1), ("grpc.max_send_message_length", -1)))
    echo_pb2_grpc.add_EchoServicer_to_server(Echo(), server)
    if not server.add_insecure_port(address):
        raise RuntimeError(f"Could not bind {address}")
    await server.start()
    try:
        await server.wait_for_termination()
    finally:
        await server.stop(None)


def main() -> None:
    """Select the listening address for the echo service."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", nargs="?", default="127.0.0.1:8546")
    args = parser.parse_args()
    with suppress(KeyboardInterrupt):
        asyncio.run(serve(args.address))


if __name__ == "__main__":
    main()
