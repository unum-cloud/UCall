"""Check the shared HTTP surface of the native and FastAPI echo examples.

File: examples/fastapi_client.py
Author: Ash Vardanian
Date: May 13, 2024
"""

import argparse

import httpx


def main() -> None:
    """Check health and binary echo against the selected server."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", nargs="?", default="http://127.0.0.1:8545")
    parser.add_argument("--bytes", type=int, default=1024)
    args = parser.parse_args()
    if args.bytes < 0:
        parser.error("--bytes must be nonnegative")
    with httpx.Client(base_url=args.url) as client:
        health = client.get("/health")
        health.raise_for_status()
        if health.content != b"ready\n":
            raise RuntimeError("Unexpected health response")
        payload = b"\0" + b"x" * (args.bytes - 1) if args.bytes else b""
        response = client.post("/echo", content=payload)
        response.raise_for_status()
        if response.content != payload:
            raise RuntimeError("Response body differs from request")
        print(f"Verified {len(payload)} binary echo bytes")


if __name__ == "__main__":
    main()
