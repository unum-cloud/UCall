"""Exercises `ucall.Server` against in-process clients on loopback, polled by threads the tests start."""

import json
import threading

import pytest

import ucall


def test_sum_through_query_and_json(backend, loopback):
    server = ucall.Server(loopback(), backend=backend)

    @server.get("/sum")
    def sum_query(a: int, b: int):
        return a + b

    @server.post("/sum")
    def sum_json(a: int, b: float = 0.5):
        return a + b

    runner = threading.Thread(target=server.run)
    runner.start()
    try:
        client = ucall.Client(connections=1, backend=backend)
        url = f"http://{server.addresses[0]}/sum"
        response = client.get(f"{url}?a=1&b=2")
        assert (response.status_code, bytes(response.body)) == (200, b"3")
        assert response.header("Content-Type") == "application/json"
        assert bytes(client.post(url, json={"a": 1, "b": 2}).body) == b"3.0"
        assert bytes(client.post(url, json={"a": 1}).body) == b"1.5"
        assert client.get(f"{url}?a=one&b=2").status_code == 400
        assert client.post(url, json={"b": 2}).status_code == 400
    finally:
        server.stop()
        runner.join()


def test_typed_parameters_bind_from_path_query_and_json(backend, loopback, serving):
    server = ucall.Server(loopback(), backend=backend)

    def describe(word: str, times: int = 1, loud: bool = False, ratio: float = 1.0, raw: bytes = b"", note=None):
        return {"word": word, "times": times, "loud": loud, "ratio": ratio, "raw": raw.decode(), "note": note}

    assert server.add_endpoint("/describe/{word}", ucall.Verb.ANY, describe) is describe

    @server.get("/scale/{value}")
    def scale(value: float, /, factor: float = 2.0):
        return value * factor

    @server.get("/need")
    def need(value: int):
        return value

    with serving(server) as base:
        client = ucall.Client(connections=1, backend=backend)

        def answer(response: ucall.Response) -> tuple[int, object]:
            body = bytes(response.body)
            return response.status_code, json.loads(body) if response.status_code == 200 else body.decode()

        defaults = {"word": "hi", "times": 1, "loud": False, "ratio": 1.0, "raw": "", "note": None}
        assert answer(client.get(f"{base}/describe/hi")) == (200, defaults)
        query = "times=3&ratio=2.5&raw=a%2Bb+c&note=x%20y%E2%82%AC&word=ignored"
        bound = {**defaults, "times": 3, "ratio": 2.5, "raw": "a+b c", "note": "x y€"}
        assert answer(client.get(f"{base}/describe/hi?{query}")) == (200, bound)
        for spelling, truth in [("1", True), ("true", True), ("Yes", True), ("ON", True), ("0", False), ("off", False)]:
            assert answer(client.get(f"{base}/describe/hi?loud={spelling}"))[1]["loud"] is truth
        document = {"times": 2, "ratio": 3, "raw": "z", "loud": True, "note": [1]}
        widened = {**defaults, "times": 2, "ratio": 3.0, "raw": "z", "loud": True, "note": [1]}
        assert answer(client.post(f"{base}/describe/hi?times=2", json=document)) == (200, widened)
        assert bytes(client.get(f"{base}/scale/1.5?factor=3").body) == b"4.5"

        with pytest.raises(json.JSONDecodeError) as malformed:
            json.loads(b"{")
        refusals = [
            (client.get(f"{base}/describe/hi?times=one"), "invalid literal for int() with base 10: 'one'\n"),
            (client.get(f"{base}/describe/hi?loud=maybe"), "expected a boolean, got 'maybe'\n"),
            (client.post(f"{base}/describe/hi", json={"times": "2"}), "expected int, got str\n"),
            (client.post(f"{base}/describe/hi", b"[1]"), "expected a JSON object body\n"),
            (client.post(f"{base}/describe/hi", b"{"), f"{malformed.value}\n"),
            (client.get(f"{base}/need"), "missing parameter 'value'\n"),
        ]
        assert [answer(response) for response, _ in refusals] == [(400, message) for _, message in refusals]


def test_replies_serialize_by_returned_type(backend, loopback, serving):
    server = ucall.Server(loopback(), backend=backend)
    results = {
        "bytes": b"\x00raw",
        "bytearray": bytearray(b"grown"),
        "memoryview": memoryview(b"viewed"),
        "text": "naïve",
        "json": {"list": [1, 2.5, None]},
    }

    @server.get("/typed/{kind}")
    def typed(kind: str):
        return results.get(kind)

    @server.get("/raw")
    def raw(request: ucall.Request):
        return "from the request"

    binary, text, document = "application/octet-stream", "text/plain; charset=utf-8", "application/json"
    with serving(server) as base:
        client = ucall.Client(connections=1, backend=backend)
        replies = {
            kind: client.get(f"{base}/typed/{kind}") for kind in ("bytes", "bytearray", "memoryview", "text", "json")
        }
        replies["none"] = client.get(f"{base}/typed/none")
        replies["raw"] = client.get(f"{base}/raw")
        observed = {
            kind: (reply.status_code, reply.header("content-type"), bytes(reply.body))
            for kind, reply in replies.items()
        }
    assert observed == {
        "bytes": (200, binary, b"\x00raw"),
        "bytearray": (200, binary, b"grown"),
        "memoryview": (200, binary, b"viewed"),
        "text": (200, text, "naïve".encode()),
        "json": (200, document, b'{"list": [1, 2.5, null]}'),
        "none": (204, None, b""),
        "raw": (200, text, b"from the request"),
    }


def test_registration_refuses_unbindable_parameters(loopback):
    server = ucall.Server(loopback())

    def variadic(*values: int):
        return values

    def keywords(**values: int):
        return values

    def listed(values: list):
        return values

    def wide(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16):
        return a0

    refusals = []
    for handler in (variadic, keywords, listed, wide):
        with pytest.raises(TypeError) as refused:
            server.get(f"/{handler.__name__}")(handler)
        refusals.append(str(refused.value))
    scope = "test_registration_refuses_unbindable_parameters.<locals>"
    assert refusals == [
        f"{scope}.variadic cannot bind *values from a request",
        f"{scope}.keywords cannot bind *values from a request",
        f"{scope}.listed annotates values as <class 'list'>, not a scalar or Request",
        f"{scope}.wide takes 17 parameters, more than the 16 a request binds",
    ]


def test_raw_request_echo(backend, loopback, serving):
    server = ucall.Server(loopback(), backend=backend)
    refusals = []

    @server.route("/echo/{name}", ucall.Verb.ANY)
    def echo(request: ucall.Request):
        view = request.body[1:]
        try:
            request.reply(b"too early")
        except BufferError as error:
            refusals.append(error)
        del view
        request.reply(
            request.body,
            headers=(
                f"x-verb: {request.verb.name}",
                f"x-path: {request.path}",
                f"x-name: {request.path_parameter('name')}",
                f"x-query: {request.query('q')}",
                f"x-header: {request.header('X-Custom')}",
            ),
        )
        try:
            request.reply(b"again")
        except ucall.Error as error:
            refusals.append(error.status)

    with serving(server) as base:
        client = ucall.Client(connections=1, backend=backend)
        response = client.put(f"{base}/echo/alpha?q=1", b"\x00binary\xff", headers=("x-custom: yes",))
        del client
        assert bytes(response.body) == b"\x00binary\xff"
        headers = {name: response.header(f"x-{name}") for name in ("verb", "path", "name", "query", "header")}
        assert headers == {"verb": "PUT", "path": "/echo/alpha", "name": "alpha", "query": "1", "header": "yes"}
        assert response.header("x-missing") is None
    assert [type(refusal) for refusal in refusals] == [BufferError, ucall.Status]
    assert refusals[1] == ucall.Status.ALREADY_EXISTS


def test_batch_replies_in_reverse_arrive_in_order(backend, loopback, serving):
    server = ucall.Server(loopback(connections=1, pipelined_requests=4), backend=backend)
    batches = []

    @server.batch("/batch", "PUT", min_size=4, max_size=4, max_latency_us=5_000_000)
    def reverse(requests: list[ucall.Request]):
        batches.append(len(requests))
        for request in reversed(requests):
            request.reply(request.body)

    assert server.batch_endpoints == (reverse,)
    assert reverse.statistics() == dict.fromkeys(
        ("batches", "requests", "filled_batches", "ready_batches", "expired_batches"), 0
    )
    with serving(server) as base:
        client = ucall.Client(connections=1, pipelined_calls=4, calls=4, backend=backend)
        for index in range(4):
            client.submit("PUT", f"{base}/batch", str(index).encode(), context=index)
        finished = []
        while len(finished) != 4:
            finished += client.take_completed(timeout_us=1_000_000)
    assert batches == [4]
    assert [completed.context for completed in finished] == [0, 1, 2, 3]
    assert all(completed.status == ucall.Status.SUCCESS for completed in finished)
    assert [bytes(completed.response.body) for completed in finished] == [b"0", b"1", b"2", b"3"]
    assert reverse.statistics() == {
        "batches": 1,
        "requests": 4,
        "filled_batches": 1,
        "ready_batches": 0,
        "expired_batches": 0,
    }


def test_peer_under_noise_xx(backend, loopback, serving):
    server_private, server_public = ucall.generate_noise_keypair()
    client_private, client_public = ucall.generate_noise_keypair()
    assert ucall.derive_noise_public_key(client_private) == client_public
    vetted = []

    def admit_client(key: bytes) -> bool:
        vetted.append(key)
        return key == client_public

    secure = loopback(security=ucall.Security.NOISE_XX, private_key=server_private, peer_authorizer=admit_client)
    server = ucall.Server(loopback(), secure, backend=backend)

    @server.get("/peer")
    def peer(request: ucall.Request):
        interface_index, static_key = request.peer
        return bytes([interface_index]) + static_key

    with serving(server):
        client = ucall.Client(
            connections=1,
            private_key=client_private,
            peer_authorizer=lambda key: key == server_public,
            backend=backend,
        )
        secure_body = bytes(client.get(f"http+noise://{server.addresses[1]}/peer").body)
        plain_body = bytes(client.get(f"http://{server.addresses[0]}/peer").body)
    assert secure_body == b"\x01" + client_public
    assert plain_body == b"\x00" + bytes(32)
    assert vetted == [client_public]


def test_handler_failures_answer_500(backend, loopback, serving, monkeypatch):
    server = ucall.Server(loopback(), backend=backend)
    unraisable = []
    monkeypatch.setattr("sys.unraisablehook", unraisable.append)

    @server.get("/fail")
    def fail():
        raise ValueError("boom")

    @server.get("/silent")
    def silent(request: ucall.Request):
        return None

    @server.get("/unserializable")
    def unserializable():
        return object()

    with serving(server) as base:
        client = ucall.Client(connections=1, backend=backend)
        assert client.get(f"{base}/fail").status_code == 500
        assert client.get(f"{base}/silent").status_code == 500
        assert client.get(f"{base}/unserializable").status_code == 500
        assert client.get(f"{base}/missing").status_code == 404
    assert [type(report.exc_value) for report in unraisable] == [ValueError, TypeError]


def test_run_refuses_more_than_one_loop_or_any_batch(loopback):
    several = ucall.Server(loopback(event_loops=2))
    assert several.event_loops == 2
    with pytest.raises(RuntimeError) as refusal:
        several.run()
    assert str(refusal.value) == (
        "Server.run() polls one event loop on the calling thread, and this server has 2 event loops and 0 batch "
        "endpoints, so poll each loop with take_calls and drain each batch endpoint with take_batches on threads of "
        "your own."
    )

    batched = ucall.Server(loopback())
    batched.batch("/batch")(lambda requests: None)
    with pytest.raises(RuntimeError) as refusal:
        batched.run()
    assert str(refusal.value) == (
        "Server.run() polls one event loop on the calling thread, and this server has 1 event loops and 1 batch "
        "endpoints, so poll each loop with take_calls and drain each batch endpoint with take_batches on threads of "
        "your own."
    )
