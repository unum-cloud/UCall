"""Exercises `ucall.Server` against in-process clients on loopback, polled by threads the tests
start.

File: test/server.py
Author: Ash Vardanian
Date: October 25, 2026
"""

import _thread
import asyncio
import concurrent.futures
import dataclasses
import hashlib
import json
import os
import socket
import sys
import sysconfig
import threading
import time

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
        nested = {"deep": {"exact": 2**60, "wide": -(2**70), "items": [1.5, None, True, "naïve"]}}
        assert answer(client.post(f"{base}/describe/hi", json={"note": nested}))[1]["note"] == nested
        assert bytes(client.get(f"{base}/scale/1.5?factor=3").body) == b"4.5"

        refusals = [
            (client.get(f"{base}/describe/hi?times=one"), "invalid literal for int() with base 10: 'one'\n"),
            (client.get(f"{base}/describe/hi?loud=maybe"), "expected a boolean, got 'maybe'\n"),
            (client.post(f"{base}/describe/hi", json={"times": "2"}), "expected int, got str\n"),
            (client.post(f"{base}/describe/hi", b"[1]"), "expected a JSON object body\n"),
            (client.post(f"{base}/describe/hi", b"{"), "the body is not JSON: unexpected end of data at byte 1\n"),
            (client.get(f"{base}/need"), "missing parameter 'value'\n"),
            (client.get(f"{base}/describe/hi?note=100%"), "a '%' in the query lacks two hexadecimal digits\n"),
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
        "keyed": {1: "one"},
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
            kind: client.get(f"{base}/typed/{kind}")
            for kind in ("bytes", "bytearray", "memoryview", "text", "json", "keyed")
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
        "json": (200, document, b'{"list":[1,2.5,null]}'),
        "keyed": (200, document, b'{"1": "one"}'),
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

    async def awaited(value: int):
        return value

    refusals = []
    for handler in (variadic, keywords, listed, wide, awaited):
        with pytest.raises(TypeError) as refused:
            server.get(f"/{handler.__name__}")(handler)
        refusals.append(str(refused.value))
    scope = "test_registration_refuses_unbindable_parameters.<locals>"
    assert refusals == [
        f"{scope}.variadic cannot bind *values from a request",
        f"{scope}.keywords cannot bind *values from a request",
        f"{scope}.listed annotates values as <class 'list'>, not a scalar or Request",
        f"{scope}.wide takes 17 parameters, more than the 16 a request binds",
        f"{awaited!r} is a coroutine function: register a plain function, call request.detach(), "
        "and reply from your own event loop",
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
                f"x-segments: {b'|'.join(request.path_segments).decode()}",
                f"x-field: {dict(request.fields())[b'x-custom'].decode()}",
                f"x-query-string: {request.query_string}",
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
        names = ("verb", "path", "name", "query", "header", "segments", "field", "query-string")
        headers = {name: response.header(f"x-{name}") for name in names}
        assert headers == {
            "verb": "PUT",
            "path": "/echo/alpha",
            "name": "alpha",
            "query": "1",
            "header": "yes",
            "segments": "echo|alpha",
            "field": "yes",
            "query-string": "q=1",
        }
        assert [name for name, _ in response.fields() if name.startswith(b"x-")] == [f"x-{n}".encode() for n in names]
        assert response.header("x-missing") is None
    assert [type(refusal) for refusal in refusals] == [BufferError, ucall.Status]
    assert refusals[1] == ucall.Status.ALREADY_EXISTS


def test_batch_replies_in_reverse_arrive_in_order(backend, loopback, serving):
    server = ucall.Server(loopback(connections=1, pipelined_requests=4), backend=backend)
    batches = []

    @server.batch("/batch", "PUT", min_size=4, max_size=4, max_latency_microseconds=5_000_000)
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
            finished += client.take_completed(timeout_microseconds=1_000_000)
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

    secure = loopback(security=ucall.Security.NOISE_XX, noise_private_key=server_private, peer_authorizer=admit_client)
    server = ucall.Server(loopback(), secure, backend=backend)

    addresses = []

    @server.get("/peer")
    def peer(request: ucall.Request):
        interface_index, static_key, address = request.peer
        addresses.append(address)
        return bytes([interface_index]) + static_key

    with serving(server):
        client = ucall.Client(
            connections=1,
            noise_private_key=client_private,
            peer_authorizer=lambda key: key == server_public,
            backend=backend,
        )
        secure_body = bytes(client.get(f"http+noise://{server.addresses[1]}/peer").body)
        plain_body = bytes(client.get(f"http://{server.addresses[0]}/peer").body)
    assert secure_body == b"\x01" + client_public
    assert plain_body == b"\x00" + bytes(32)
    assert vetted == [client_public]
    assert [(str(ip), port != 0) for ip, port in addresses] == [("127.0.0.1", True)] * 2


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

    @dataclasses.dataclass
    class Point:
        x: int

    @server.get("/unserializable")
    def unserializable():
        return Point(1)

    with serving(server) as base:
        client = ucall.Client(connections=1, backend=backend)
        assert client.get(f"{base}/fail").status_code == 500
        assert client.get(f"{base}/silent").status_code == 500
        assert client.get(f"{base}/unserializable").status_code == 500
        assert client.get(f"{base}/missing").status_code == 404
    assert [type(report.exc_value) for report in unraisable] == [ValueError, TypeError]
    assert str(unraisable[1].exc_value) == "Object of type Point is not JSON serializable"


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


def test_run_second_interrupt_cuts(backend, loopback):
    server = ucall.Server(loopback(), backend=backend)
    held = []
    arrived, ended = threading.Event(), threading.Event()
    interrupted = {}

    @server.get("/hold")
    def hold(request: ucall.Request):
        held.append(request.detach())
        arrived.set()

    def peer():
        host, _, port = server.addresses[0].rpartition(":")
        with socket.create_connection((host, int(port))) as connection:
            connection.sendall(b"GET /hold HTTP/1.1\r\nHost: a\r\n\r\n")
            if not arrived.wait(5):
                return
            _thread.interrupt_main()
            time.sleep(0.2)
            interrupted["second"] = time.monotonic()
            _thread.interrupt_main()
            # A drain deaf to the second interrupt ends only on this reply, so the case cannot hang.
            if not ended.wait(3):
                held[0].reply(b"late")

    peering = threading.Thread(target=peer)
    peering.start()
    try:
        with pytest.raises(KeyboardInterrupt):
            server.run()
    finally:
        returned = time.monotonic()
        ended.set()
        peering.join()
    assert returned - interrupted["second"] < 1.0


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="AF_UNIX sockets are missing here")
def test_unix_listener_echo(backend, serving, tmp_path):
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(tmp_path / "echo.sock"))
    listener.listen()
    server = ucall.Server(ucall.Interface(descriptor=listener, connections=8), backend=backend)
    peers = []

    @server.post("/echo")
    def echo(request: ucall.Request):
        peers.append(request.peer[2])
        return bytes(request.body)

    body = bytes(range(256)) * 64
    with serving(server), socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.connect(str(tmp_path / "echo.sock"))
        connection.sendall(b"POST /echo HTTP/1.1\r\nHost: a\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        response = b""
        while not response.endswith(body):
            chunk = connection.recv(65536)
            assert chunk, f"the server closed after {len(response)} bytes"
            response += chunk
    listener.close()
    assert response.startswith(b"HTTP/1.1 200 OK\r\n")
    assert server.addresses == (str(tmp_path / "echo.sock"),)
    assert peers == [""]


def test_reply_parts_path_and_bytes_on_worker(backend, loopback, serving, direct_directory):
    content = bytes(range(256)) * 32
    (direct_directory / "frame.bin").write_bytes(content)
    descriptor = os.open(direct_directory / "frame.bin", os.O_RDONLY | os.O_DIRECT)
    server = ucall.Server(loopback(reply_directories=[direct_directory]), backend=backend)
    answers = []

    def send(detached: ucall.DetachedRequest, parts: list):
        answer = detached.reply_parts(parts, headers=("content-type: application/octet-stream",))
        answers.append(type(answer))
        if answer is not None:
            answer.wait()

    @server.get("/frame")
    def frame(request: ucall.Request):
        parts = [b"<", ucall.Path(0, "frame.bin", 256, 512), b"|", ucall.File(descriptor, length=256), b">"]
        workers.submit(send, request.detach(), parts)

    @server.get("/bytes")
    def memory(request: ucall.Request):
        workers.submit(send, request.detach(), [b"in ", memoryview(b"memory")])

    with concurrent.futures.ThreadPoolExecutor(1) as workers, serving(server) as base:
        client = ucall.Client(connections=1, backend=backend)
        framed = bytes(client.get(f"{base}/frame").body)
        memory_only = bytes(client.get(f"{base}/bytes").body)
    os.close(descriptor)
    assert framed == b"<" + content[256:768] + b"|" + content[:256] + b">"
    assert memory_only == b"in memory"
    assert answers == [ucall.Deferred, type(None)]


def test_reply_parts_overflow_keeps_request(backend, loopback, serving, direct_directory):
    server = ucall.Server(loopback(reply_directories=[direct_directory]), backend=backend)
    refusals = []

    def send(detached: ucall.DetachedRequest):
        try:
            detached.reply_parts([ucall.Path(0, "clip.bin", 2**64 - 1, 1)])
        except ucall.Error as error:
            refusals.append(error.status)
        detached.reply(b"still answerable")

    @server.get("/clip")
    def clip(request: ucall.Request):
        workers.submit(send, request.detach())

    with concurrent.futures.ThreadPoolExecutor(1) as workers, serving(server) as base:
        response = ucall.Client(connections=1, backend=backend).get(f"{base}/clip")
        workers.shutdown()
    assert refusals == [ucall.Status.INVALID_ARGUMENT]
    assert (response.status_code, bytes(response.body)) == (200, b"still answerable")


def test_typed_handler_returning_path_raises(loopback, serving, monkeypatch):
    server = ucall.Server(loopback())
    unraisable = []
    monkeypatch.setattr("sys.unraisablehook", unraisable.append)

    @server.get("/video")
    def video():
        return ucall.Path(0, "intro.mp4")

    with serving(server) as base:
        assert ucall.Client(connections=1).get(f"{base}/video").status_code == 500
    assert [(type(report.exc_value), str(report.exc_value)) for report in unraisable] == [
        (
            TypeError,
            "a handler returned a ucall.Path, which may defer, so send it with DetachedRequest.reply_parts on "
            "another thread",
        )
    ]


def test_deferred_await_and_wait(backend, loopback, serving, direct_directory):
    (direct_directory / "note.txt").write_bytes(b"deferred note")
    server = ucall.Server(loopback(reply_directories=[direct_directory]), backend=backend)
    finished = {}

    def send(detached: ucall.DetachedRequest, name: str, waiting: str):
        deferred = detached.reply_parts([ucall.Path(0, name)])
        try:
            if waiting == "await":

                async def finish():
                    await deferred

                asyncio.run(finish())
            else:
                deferred.wait()
        except ucall.Error as error:
            finished[name, waiting] = error.status
        else:
            finished[name, waiting] = deferred.status()

    @server.get("/{name}/{waiting}")
    def note(request: ucall.Request):
        name, waiting = request.path_parameter("name"), request.path_parameter("waiting")
        workers.submit(send, request.detach(), name, waiting)

    with concurrent.futures.ThreadPoolExecutor(1) as workers, serving(server) as base:
        client = ucall.Client(connections=1, backend=backend)
        replies = [
            client.get(f"{base}/{name}/{waiting}")
            for name in ("note.txt", "missing.txt")
            for waiting in ("await", "wait")
        ]
        workers.shutdown()
    assert [(reply.status_code, bytes(reply.body)) for reply in replies[:2]] == [(200, b"deferred note")] * 2
    assert [reply.status_code for reply in replies[2:]] == [404, 404]
    assert finished == {
        ("note.txt", "await"): ucall.Status.SUCCESS,
        ("note.txt", "wait"): ucall.Status.SUCCESS,
        ("missing.txt", "await"): ucall.Status.NOT_FOUND,
        ("missing.txt", "wait"): ucall.Status.NOT_FOUND,
    }


def test_body_chunks_on_worker(backend, loopback, serving):
    server = ucall.Server(loopback(), backend=backend)
    payload = os.urandom(1 << 22)
    observed = []

    def receive(detached: ucall.DetachedRequest):
        digest = hashlib.sha256()
        chunks = detached.body_chunks()
        first = next(chunks)
        digest.update(first)

        async def rest():
            async for chunk in chunks:
                digest.update(chunk)

        asyncio.run(rest())
        try:
            first.tobytes()
        except ValueError:
            observed.append("released")
        detached.reply(digest.digest())

    @server.post("/upload", body=ucall.BodyDelivery.STREAMED)
    def upload(request: ucall.Request):
        workers.submit(receive, request.detach())

    with concurrent.futures.ThreadPoolExecutor(1) as workers, serving(server) as base:
        client = ucall.Client(connections=1, backend=backend)
        response = client.post(f"{base}/upload", payload)
        workers.shutdown()
    assert bytes(response.body) == hashlib.sha256(payload).digest()
    assert observed == ["released"]


def test_parts_pin_the_request(backend, loopback, serving):
    server = ucall.Server(loopback(), backend=backend)
    body = (
        b"--frontier\r\n"
        b'Content-Disposition: form-data; name="caption"\r\n\r\n'
        b"sunset\r\n"
        b"--frontier\r\n"
        b'Content-Disposition: form-data; name="image"; filename="a.png"\r\n'
        b"Content-Type: image/png\r\n\r\n"
        b"\x89PNG\r\n"
        b"--frontier--\r\n"
    )
    held = []
    arrived = threading.Event()

    @server.post("/upload")
    def upload(request: ucall.Request):
        held.append(request.parts)
        arrived.set()

    with serving(server) as base:
        replies = []

        def call():
            client = ucall.Client(connections=1, backend=backend)
            headers = ("content-type: multipart/form-data; boundary=frontier",)
            replies.append(client.post(f"{base}/upload", body, headers=headers).status_code)

        caller = threading.Thread(target=call)
        caller.start()
        assert arrived.wait(timeout=10)
        observed = [(part.name, part.content_type, bytes(part.data)) for part in held[0]]
        # The handler returned and dropped the request, which its parts keep unanswered.
        caller.join(timeout=0.2)
        assert caller.is_alive()
        held.clear()
        caller.join()
    assert observed == [("caption", "", b"sunset"), ("image", "image/png", b"\x89PNG")]
    assert replies == [500]


def test_body_keyword_on_decorators(loopback, serving):
    server = ucall.Server(loopback())
    seen = {}

    def record(request: ucall.Request):
        try:
            seen[request.path] = bytes(request.body)
        except ucall.Error as error:
            seen[request.path] = error.status
        return b""

    server.post("/buffered")(record)
    server.post("/post", body=ucall.BodyDelivery.STREAMED)(record)
    server.put("/put", body="streamed")(record)
    server.route("/route", ucall.Verb.POST, body=ucall.BodyDelivery.STREAMED)(record)
    server.add_endpoint("/add", "POST", record, body=ucall.BodyDelivery.STREAMED)
    with serving(server) as base:
        client = ucall.Client(connections=1)
        for path in ("/buffered", "/post", "/route", "/add"):
            client.post(f"{base}{path}")
        client.put(f"{base}/put")
    streamed = ucall.Status.INVALID_ARGUMENT
    assert seen == {"/buffered": b"", "/post": streamed, "/put": streamed, "/route": streamed, "/add": streamed}


def test_verb_decorators_route_each_verb(loopback, serving):
    server = ucall.Server(loopback())

    @server.get("/verb")
    def get(request: ucall.Request):
        return b"get"

    @server.post("/verb")
    def post(request: ucall.Request):
        return b"post"

    @server.put("/verb")
    def put(request: ucall.Request):
        return b"put"

    @server.delete("/verb")
    def delete(request: ucall.Request):
        return b"delete"

    @server.patch("/verb")
    def patch(request: ucall.Request):
        return b"patch"

    with serving(server) as base:
        client = ucall.Client(connections=1)
        for verb in ("get", "post", "put", "delete", "patch"):
            response = getattr(client, verb)(f"{base}/verb")
            assert (response.status_code, bytes(response.body)) == (200, verb.encode())


def test_kk_interface(backend, loopback, serving):
    server_private, server_public = ucall.generate_noise_keypair()
    client_private, client_public = ucall.generate_noise_keypair()
    stranger_private, _ = ucall.generate_noise_keypair()
    secure = loopback(security=ucall.Security.NOISE_KK, noise_private_key=server_private, noise_peer_key=client_public)
    assert secure.noise_peer_key == client_public
    server = ucall.Server(secure, backend=backend)

    @server.get("/peer")
    def peer(request: ucall.Request):
        return request.peer[1]

    with serving(server):
        client = ucall.Client(connections=1, backend=backend)
        url = f"http+noise://{server.addresses[0]}/peer"
        known = {"security": ucall.Security.NOISE_KK, "noise_peer_key": server_public}
        admitted = bytes(client.get(url, noise_private_key=client_private, **known).body)
        with pytest.raises(ucall.Error):
            client.get(url, noise_private_key=stranger_private, max_retries=1, **known)
    assert admitted == client_public


def test_handlers_on_four_loops_from_four_threads(backend, loopback, serving):
    server = ucall.Server(loopback(event_loops=4), backend=backend)
    loop_threads = set()

    @server.post("/echo")
    def echo(request: ucall.Request):
        loop_threads.add(threading.get_ident())
        return bytes(request.body)

    def post(sender: int) -> list[bytes]:
        client = ucall.Client(connections=1, backend=backend)
        return [bytes(client.post(f"{base}/echo", f"{sender}:{index}".encode()).body) for index in range(64)]

    with serving(server) as base, concurrent.futures.ThreadPoolExecutor(4) as pool:
        answers = list(pool.map(post, range(4)))
    assert answers == [[f"{sender}:{index}".encode() for index in range(64)] for sender in range(4)]
    assert len(loop_threads) >= 2
    if sysconfig.get_config_var("Py_GIL_DISABLED"):
        assert not sys._is_gil_enabled()
