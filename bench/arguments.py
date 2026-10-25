"""The `--port` and `--threads` arguments every Python server here shares.

File: bench/arguments.py
Author: Ash Vardanian
Date: October 25, 2026
"""

import argparse


def parse(description: str) -> tuple[int, int]:
    """Read `--port N` and `--threads N`, defaulting to 8545 and 1, under the docstring's first line."""
    summary, _, _ = description.partition("\n")
    parser = argparse.ArgumentParser(description=summary)
    parser.add_argument("--port", type=int, default=8545)
    parser.add_argument("--threads", type=int, default=1, help="event loops or worker processes")
    arguments = parser.parse_args()
    return arguments.port, arguments.threads
