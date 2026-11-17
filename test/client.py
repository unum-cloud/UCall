"""Exercises `ucall.Client`: its owning thread, its blocking calls, and the completions they
keep for later.

Run:
    python -m pytest test/client.py -v
    UCALL_FILTER=linux_uring618 python -m pytest test/client.py

File: test/client.py
Author: Ash Vardanian
Date: October 25, 2026
"""

import asyncio
import socket
import threading
import time

import pytest

import ucall


def test_names_come_from_the_library():
    """Statuses parse from the library's own spellings, a misspelled one is refused, and the version matches."""
    assert ucall.Status.from_name("would-block") is ucall.Status.WOULD_BLOCK
    assert ucall.Status.from_name("invalid-argument") is ucall.Status.INVALID_ARGUMENT
    with pytest.raises(ValueError) as misspelled:  # noqa: PT011
        ucall.Status.from_name("would-bloc")
    assert str(misspelled.value) == "no ucall.Status is spelled 'would-bloc'"
    assert ucall.version() == ucall.__version__


def test_client_refuses_other_threads():
    """A client answers only the thread that made it, refusing submits, takes and blocking calls from any other."""
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


def test_blocking_calls_keep_other_completions_for_the_next_take(backend, loopback, serving):
    """A blocking call keeps the completions it drove past for the next take, and a refused connect raises."""
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

        with pytest.raises(ucall.ConnectionFailedError) as refused:
            client.get("http://127.0.0.1:1/")
        assert refused.value.status == ucall.Status.CONNECTION_FAILED
        assert isinstance(refused.value, ConnectionError)


def test_responses_over_the_cap_fail_with_overflow(backend, loopback, serving):
    """A response larger than `max_response_bytes` fails with an overflow, while a smaller one arrives whole."""
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


def test_streamed_bodies_download_past_the_response_cap(backend, loopback, serving):
    """A streamed body downloads past the response cap, pulled only on its own thread; a bodiless one pulls empty."""
    server = ucall.Server(loopback(), backend=backend)
    # A prime period, so a misplaced or repeated chunk shows.
    payload = (bytes(range(251)) * ((4 << 20) // 251 + 1))[: 4 << 20]

    @server.get("/large")
    def large(request: ucall.Request):
        return payload

    @server.get("/empty")
    def empty(request: ucall.Request):
        return b""

    with serving(server) as base:
        client = ucall.Client(connections=1, backend=backend, max_response_bytes=1 << 20)
        with pytest.raises(ucall.Error) as capped:
            client.get(f"{base}/large")
        assert capped.value.status == ucall.Status.OVERFLOW

        response = client.get(f"{base}/large", body_delivery=ucall.BodyDelivery.STREAMED)
        assert response.status_code == 200
        with pytest.raises(ucall.Error) as buffered:
            _ = response.body
        assert buffered.value.status == ucall.Status.INVALID_ARGUMENT
        chunks = response.body_chunks()
        first = next(chunks)
        head, kept = bytes(first), first[:1]
        with pytest.raises(BufferError):
            next(chunks)
        kept.release()
        assert head + b"".join(bytes(chunk) for chunk in chunks) == payload

        async def drain(response):
            return b"".join([bytes(chunk) async for chunk in response.body_chunks()])

        response = client.get(f"{base}/large", body_delivery=ucall.BodyDelivery.STREAMED)
        assert asyncio.run(drain(response)) == payload

        # A bodiless response is pulled too, before its connection carries the next call.
        response = client.get(f"{base}/empty", body_delivery=ucall.BodyDelivery.STREAMED)
        assert list(response.body_chunks()) == []
        response = client.get(f"{base}/empty")
        assert bytes(response.body) == b""
        with pytest.raises(ucall.Error) as refused:
            next(response.body_chunks())
        assert refused.value.status == ucall.Status.INVALID_ARGUMENT

        response = client.get(f"{base}/empty", body_delivery=ucall.BodyDelivery.STREAMED)
        failures = []

        def intrude():
            try:
                next(response.body_chunks())
            except ucall.Error as error:
                failures.append(error.status)

        intruder = threading.Thread(target=intrude)
        intruder.start()
        intruder.join()
        assert failures == [ucall.Status.INVALID_ARGUMENT]
        assert list(response.body_chunks()) == []


def test_request_options_timeout_overrides_client(backend, loopback, serving):
    """A timeout passed with one call ends that call, whatever the client's own default."""
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


def test_clients_and_servers_log_lines_in_text_and_json(loopback, serving):
    """A client logs a failed connect as a text line, and a server logs a refusal as a JSON line."""
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
