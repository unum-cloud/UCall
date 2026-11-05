"""Shared NumKong model for the Python inference services: the UCall example and its benchmark baselines.

The matrix holds the same values as `ucall_example_inference` with the same seed: ForkUnion's counter-based
SplitMix64 keyed by the seed's own SplitMix64 output, eight little-endian i8 values per word.
NumKong packs it once and scores i8 queries against it with exact i32 dot products, as the native example does.
Responses use the native layout: 10 little-endian pairs of a u32 row and an i32 score, best first.

File: examples/inference/model.py
Author: Ash Vardanian
Date: October 25, 2026
"""

import os

import numpy as np
import numpy.typing as npt

import numkong as nk

RESULTS_PER_QUERY: int = 10
"""Rows in every response."""
RESPONSE_DTYPE: np.dtype = np.dtype([("row", "<u4"), ("score", "<i4")])
"""One response entry, a u32 row and an i32 score."""
THREADS: int = os.cpu_count() or 1
"""NumKong threads per packing and scoring call, one per logical core like the native pool."""


def split_mix(counters: npt.NDArray[np.uint64]) -> npt.NDArray[np.uint64]:
    """Return ForkUnion's SplitMix64 output for each counter, matching the native examples."""
    with np.errstate(over="ignore"):
        values = (counters + np.uint64(1)) * np.uint64(0x9E3779B97F4A7C15)
        values = (values ^ (values >> np.uint64(30))) * np.uint64(0xBF58476D1CE4E5B9)
        values = (values ^ (values >> np.uint64(27))) * np.uint64(0x94D049BB133111EB)
        return values ^ (values >> np.uint64(31))


def load_matrix(rows: int, dimensions: int, seed: int = 42) -> nk.PackedMatrix:
    """Return the resident `rows × dimensions` i8 matrix filled from `seed`, packed by NumKong."""
    count = rows * dimensions
    (key,) = split_mix(np.array([seed], dtype=np.uint64))
    with np.errstate(over="ignore"):
        words = split_mix(key + np.arange(-(-count // 8), dtype=np.uint64))
    values = words.astype("<u8").view(np.int8)[:count]
    return nk.dots_pack(values.reshape(rows, dimensions), dtype="i8", threads=THREADS)


def parse_query(body: bytes, dimensions: int) -> npt.NDArray[np.int8] | None:
    """Return a copy of the body as one i8 query, or None when it is not exactly `dimensions` bytes.

    The copy releases a UCall request's body, which a reply cannot outlive.
    """
    if len(body) != dimensions:
        return None
    return np.frombuffer(body, dtype=np.int8).copy()


def infer(matrix: nk.PackedMatrix, queries: npt.NDArray[np.int8]) -> list[bytes]:
    """Score a `batch × dimensions` stack of queries in one pass, returning one response per query."""
    scores = np.asarray(nk.dots_packed(queries, matrix, threads=THREADS))
    count = min(RESULTS_PER_QUERY, scores.shape[1])
    thresholds = np.partition(scores, -count, axis=1)[:, -count]
    responses = []
    for row_scores, threshold in zip(scores, thresholds, strict=True):
        above = np.flatnonzero(row_scores > threshold)
        tied = np.flatnonzero(row_scores == threshold)[: count - above.size]
        rows = np.concatenate((above, tied))
        order = np.lexsort((rows, -row_scores[rows]))
        response = np.empty(count, dtype=RESPONSE_DTYPE)
        response["row"] = rows[order]
        response["score"] = row_scores[rows[order]]
        responses.append(response.tobytes())
    return responses
