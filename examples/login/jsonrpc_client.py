"""TCP and HTTP clients for the JSON-RPC session-validation example."""

import base64
import errno
import json
import os
import random
import socket
import string

import httpx
import requests

from ucall.client import Client, ClientTLS

# Using such strings is much faster than JSON package
# rpc = json.dumps({
#     'method': 'sum',
#     'params': {'a': a, 'b': b},
#     'jsonrpc': '2.0',
#     'id': identity,
# })
REQUEST_PATTERN = '{"jsonrpc":"2.0","id":%i,"method":"validate_session","params":{"user_id":%i,"session_id":%i}}'
REQUEST_BIG_PATTERN = (
    '{"jsonrpc":"2.0","id":%i,"method":"validate_session","params":{"user_id":%i,"session_id":%i,"text":"%s"}}'
)
HTTP_HEADERS = "POST / HTTP/1.1\r\nHost: 127.0.0.1:8540\r\nUser-Agent: python-requests/2.27.1\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: %i\r\nContent-Type: application/json\r\n\r\n"

# The ID of the current running process, used as a default
# identifier for requests originating from here.
PROCESS_ID = os.getpid()


def make_tcp_socket(ip: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    return sock


def socket_is_closed(sock: socket.socket) -> bool:
    """Returns True if the remote side did close the connection."""
    if sock is None:
        return True
    try:
        buf = sock.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
        if buf == b"":
            return True
    except BlockingIOError as exc:
        if exc.errno != errno.EAGAIN:
            # Raise on unknown exception
            raise
    return False


def recvall(sock, buffer_size=4096):
    data = b""
    while True:
        chunk = sock.recv(buffer_size)
        if not chunk:
            break
        data += chunk
    return data


def parse_response(response: bytes) -> object:
    if len(response) == 0:
        raise requests.Timeout()
    # return json.JSONDecoder().raw_decode(response.decode())[0]
    return json.loads(response.decode())


class CaseHTTP:
    """JSON-RPC Client that uses classic sync Python `requests` to pass JSON calls over HTTP."""

    def __init__(self, uri: str = "127.0.0.1", port: int = 8545, identity: int = PROCESS_ID) -> None:
        self.identity = identity
        self.response = None
        self.expected = 0
        self.url = f"http://{uri}:{port}/"
        self.payload = "".join(random.choices(string.ascii_uppercase, k=80))

    def __call__(self, **kwargs) -> int:
        self.send(**kwargs)
        return self.recv()

    def send(self, a: int | None = None, b: int | None = None) -> int:

        a = random.randint(1, 1000) if a is None else a
        b = random.randint(1, 1000) if b is None else b
        json_str = REQUEST_BIG_PATTERN % (self.identity, a, b, self.payload)
        jsonrpc = json.loads(json_str)
        self.expected = (a ^ b) % 23 == 0
        self.response = requests.post(self.url, json=jsonrpc)

    def recv(self):
        response = self.response.json()
        received = response["result"]

        assert response["jsonrpc"]
        assert response.get("id", None) == self.identity
        assert self.expected == received, "Wrong Answer"
        return received


class CaseTCP:
    """JSON-RPC Client that operates directly over TCP/IPv4 stack, without HTTP."""

    def __init__(self, uri: str = "127.0.0.1", port: int = 8545, identity: int = PROCESS_ID) -> None:
        self.identity = identity
        self.expected = -1
        self.client = Client(uri, port, use_http=False)
        self.response = None

    def __call__(self) -> str:
        self.send()
        return self.recv()

    def send(self):
        user_id = random.randint(1, 1000)
        session_id = random.randint(1, 1000)
        self.expected = ((user_id ^ session_id) % 23) == 0

        self.response = self.client.validate_session(user_id=user_id, session_id=session_id)

    def recv(self):
        assert self.response.json == self.expected
        return self.response.json


class CaseTLS:
    """JSON-RPC Client that operates directly over TCP/IPv4 stack, without HTTP."""

    def __init__(self, uri: str = "127.0.0.1", port: int = 8545, identity: int = PROCESS_ID) -> None:
        self.identity = identity
        self.expected = -1
        self.client = ClientTLS(uri, port, allow_self_signed=True)
        self.response = None

    def __call__(self) -> str:
        self.send()
        return self.recv()

    def send(self):
        user_id = random.randint(1, 1000)
        session_id = random.randint(1, 1000)
        self.expected = ((user_id ^ session_id) % 23) == 0

        self.response = self.client.validate_session(user_id=user_id, session_id=session_id)

    def recv(self):
        assert self.response.json == self.expected
        return self.response.json


class CaseTLSNoReuse:
    """JSON-RPC Client that operates directly over TCP/IPv4 stack, without HTTP."""

    def __init__(self, uri: str = "127.0.0.1", port: int = 8545, identity: int = PROCESS_ID) -> None:
        self.identity = identity
        self.expected = -1
        self.client = ClientTLS(uri, port, allow_self_signed=True)
        self.response = None

    def __call__(self) -> str:
        self.send()
        res = self.recv()
        self.client.sock.close()
        self.client.sock = None
        return res

    def send(self):
        user_id = random.randint(1, 1000)
        session_id = random.randint(1, 1000)
        self.expected = ((user_id ^ session_id) % 23) == 0

        self.response = self.client.validate_session(user_id=user_id, session_id=session_id)

    def recv(self):
        assert self.response.json == self.expected
        return self.response.json


class CaseTLSNoReuseX:
    def __init__(self, uri: str = "127.0.0.1", port: int = 8545, identity: int = PROCESS_ID) -> None:
        self.identity = identity
        self.url = f"https://{uri}:{port}/"

    def __call__(self, *, a: int | None = None, b: int | None = None) -> int:

        with httpx.Client(verify=False) as client:
            a = random.randint(1, 1000) if a is None else a
            b = random.randint(1, 1000) if b is None else b
            jsonrpc = {
                "jsonrpc": "2.0",
                "id": self.identity,
                "method": "validate_session",
                "params": {"user_id": a, "session_id": b},
            }
            result = client.post(
                f"{self.url}",
                json=jsonrpc,
                headers={"Connection": "close"},
            )
            result = result.text
            c = result != "false"
            return c


class CaseTCPHTTP:
    """JSON-RPC Client that operates directly over TCP/IPv4 stack, with HTTP."""

    def __init__(self, uri: str = "127.0.0.1", port: int = 8545, identity: int = PROCESS_ID) -> None:
        self.identity = identity
        self.expected = -1
        self.uri = uri
        self.port = port
        self.sock = None
        self.payload = "".join(random.choices(string.ascii_uppercase, k=80))

    def __call__(self, **kwargs) -> int:
        self.send(**kwargs)
        return self.recv()

    def send(self, *, a: int | None = None, b: int | None = None) -> int:
        a = random.randint(1, 1000) if a is None else a
        b = random.randint(1, 1000) if b is None else b
        jsonrpc = REQUEST_BIG_PATTERN % (self.identity, a, b, self.payload)
        headers = HTTP_HEADERS % (len(jsonrpc))
        self.expected = (a ^ b) % 23 == 0
        self.sock = make_tcp_socket(self.uri, self.port) if socket_is_closed(self.sock) else self.sock
        self.sock.send((headers + jsonrpc).encode())

    def recv(self) -> int:
        # self.sock.settimeout(0.01)
        response_bytes = self.sock.recv(4096).decode()
        self.sock.settimeout(None)
        response = json.loads(response_bytes[response_bytes.index("\r\n\r\n") :])
        assert "error" not in response, response["error"]
        received = response["result"]
        assert response["jsonrpc"]
        assert response.get("id", None) == self.identity
        assert self.expected == received, "Wrong Answer"
        return received


class CaseTCPHTTPBase64:
    """JSON-RPC Client that uses classic sync Python `requests` to pass JSON calls over HTTP."""

    def __init__(self, uri: str = "127.0.0.1", port: int = 8545, identity: int = PROCESS_ID) -> None:
        self.identity = identity
        self.expected = -1
        self.uri = uri
        self.port = port
        self.sock = None
        self.payload = base64.b64encode(random.randbytes(42)).decode()

    def __call__(self, **kwargs) -> int:
        self.send(**kwargs)
        return self.recv()

    def send(self):
        jsonrpc = json.dumps(
            {"jsonrpc": "2.0", "id": self.identity, "method": "echo", "params": {"data": self.payload}}
        )
        headers = HTTP_HEADERS % (len(jsonrpc))
        self.expected = self.payload
        self.sock = make_tcp_socket(self.uri, self.port) if socket_is_closed(self.sock) else self.sock
        self.sock.send((headers + jsonrpc).encode())

    def recv(self) -> int:
        # self.sock.settimeout(0.01)
        response_bytes = self.sock.recv(4096).decode()
        self.sock.settimeout(None)
        response = json.loads(response_bytes[response_bytes.index("\r\n\r\n") :])
        assert "error" not in response, response["error"]
        received = response["result"]
        assert response["jsonrpc"]
        assert response.get("id", None) == self.identity
        assert self.expected == received, "Wrong count"
        return received


class CaseHTTPBatches:
    """JSON-RPC Client that uses classic sync Python `requests` to pass JSON calls over HTTP."""

    def __init__(self, uri: str = "127.0.0.1", port: int = 8545, identity: int = PROCESS_ID) -> None:
        self.identity = identity
        self.response = None
        self.expected = None
        self.url = f"http://{uri}:{port}/"
        self.payload = "".join(random.choices(string.ascii_uppercase, k=80))

    def send(self, a: list[int] | None = None, b: list[int] | None = None) -> int:
        if a is None:
            a = [random.randint(0, 2**32) for _ in range(random.randint(2, 50))]
        if b is None:
            b = [random.randint(0, 2**32) for _ in range(random.randint(2, 50))]

        self.expected = [((ai ^ bi) % 23 == 0) for ai, bi in zip(a, b, strict=False)]
        json_str = [REQUEST_BIG_PATTERN % (self.identity, ai, bi, self.payload) for ai, bi in zip(a, b, strict=False)]
        jsonrpc = json.loads("[{}]".format(",".join(json_str)))
        self.response = requests.post(self.url, json=jsonrpc)

    def recv(self):
        response = self.response.json()
        received = []
        for ri in response:
            received.append(ri["result"])
            assert ri["jsonrpc"]

        assert self.expected == received, "Wrong Answer"
        return received


class CaseUserCreation:
    def __init__(self, uri: str = "127.0.0.1", port: int = 8545, identity: int = PROCESS_ID) -> None:
        self.identity = identity
        self.expected = -1
        self.client = Client(uri, port, use_http=True)
        self.bin_len = 512
        self.avatar = base64.b64encode(random.randbytes(self.bin_len)).decode()
        self.bio = "".join(random.choices(string.ascii_uppercase, k=self.bin_len))
        self.name = "John Lock"

    def __call__(self) -> str:
        age = random.randint(1, 1000)

        res = self.client.create_user(age=age, name=self.name, avatar=self.avatar, bio=self.bio)
        assert res.json == f"Created {self.name} aged {age} with bio {self.bio} and avatar_size {self.bin_len}"
        return res.json
