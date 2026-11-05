"""Exercises `ucall.Client`: its owning thread, its blocking calls, and the completions they
keep for later.

File: test/client.py
Author: Ash Vardanian
Date: October 25, 2026
"""

import socket
import threading
import time

import pytest

import ucall


def test_status_names_and_version_come_from_the_library():
    assert ucall.Status.from_name("would-block") is ucall.Status.WOULD_BLOCK
    assert ucall.Status.from_name("invalid-argument") is ucall.Status.INVALID_ARGUMENT
    with pytest.raises(ValueError):
        ucall.Status.from_name("would-bloc")
    assert ucall.version() == ucall.__version__


def test_client_refuses_other_threads():
    client = ucall.Client(connections=1)
    failures = []

    attempts = (
        lambda: client.submit("GET", "http://127.0.0.1:1/"),
        client.take_completed,
        lambda: client.get("http://127.0.0.1:1/"),
    )

    def intrude():
        for attempt in attempts:
            try:
                attempt()
            except ucall.Error as error:
                failures.append(error.status)

    intruder = threading.Thread(target=intrude)
    intruder.start()
    intruder.join()
    assert failures == [ucall.Status.INVALID_ARGUMENT] * 3
    assert client.take_completed() == []


def test_blocking_calls_keep_other_completions(backend, loopback, serving):
    server = ucall.Server(loopback(), backend=backend)

    @server.post("/echo")
    def echo(request: ucall.Request):
        return request.body

    with serving(server) as base:
        # One connection carrying one call at a time finishes the submitted calls before the blocking one.
        client = ucall.Client(connections=1, calls=3, backend=backend)
        client.submit("POST", f"{base}/echo", b"first", context="first")
        client.submit("POST", f"{base}/echo", b"second", context="second")
        response = client.post(f"{base}/echo", b"own")
        assert bytes(response.body) == b"own"
        kept = client.take_completed(capacity=1) + client.take_completed(capacity=1)
        assert [completed.context for completed in kept] == ["first", "second"]
        assert [bytes(completed.response.body) for completed in kept] == [b"first", b"second"]
        assert client.take_completed() == []

        with pytest.raises(ucall.Error) as refused:
            client.get("http://127.0.0.1:1/")
        assert refused.value.status == ucall.Status.CONNECTION_FAILED


def test_response_cap_fails_with_overflow(backend, loopback, serving):
    server = ucall.Server(loopback(), backend=backend)

    @server.post("/echo")
    def echo(request: ucall.Request):
        return request.body

    with serving(server) as base:
        client = ucall.Client(connections=1, backend=backend, max_response_bytes=1024)
        assert bytes(client.post(f"{base}/echo", b"small").body) == b"small"
        with pytest.raises(ucall.Error) as capped:
            client.post(f"{base}/echo", bytes(4096))
        assert capped.value.status == ucall.Status.OVERFLOW


def test_request_options_per_call(backend, loopback, serving):
    server = ucall.Server(loopback(), backend=backend)
    held = []

    @server.get("/slow")
    def slow(request: ucall.Request):
        held.append(request.detach())

    with serving(server) as base:
        client = ucall.Client(connections=1, backend=backend)
        started = time.monotonic()
        with pytest.raises(ucall.Error) as expired:
            client.get(f"{base}/slow", timeout_microseconds=200_000)
        elapsed = time.monotonic() - started
        held.clear()
    assert expired.value.status == ucall.Status.TIMEOUT
    assert elapsed < 5


def test_client_and_server_log_lines(loopback, serving):
    lines = []
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    client = ucall.Client(connections=1, log=lambda level, line: lines.append((level, line)))
    with pytest.raises(ucall.Error):
        client.get(f"http://127.0.0.1:{port}/", max_retries=1)
    assert (ucall.LogLevel.WARNING, f"warning connect_failed address=127.0.0.1:{port} status=connection-failed") in [
        (level, line.rstrip("\n")) for level, line in lines
    ]

    json_lines = []
    server = ucall.Server(
        loopback(),
        log=lambda level, line: json_lines.append(line),
        log_level=ucall.LogLevel.INFO,
        log_format=ucall.LogFormat.JSON,
    )
    with serving(server) as base:
        assert ucall.Client(connections=1).get(f"{base}/missing").status_code == 404
    assert any(line.startswith('{"level":"info","event":"refused","status":"404"') for line in json_lines)
