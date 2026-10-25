"""Exercises `ucall.Client`: its owning thread, its blocking calls, and the completions they keep for later."""

import threading

import pytest

import ucall


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
