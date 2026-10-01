import errno
import json
import os
import random
import socket
import string
from typing import Optional

import requests

HTTP_HEADERS = '%s HTTP/1.1\r\nHost: 127.0.0.1:8540\r\nUser-Agent: python-requests/2.27.1\r\nAccept-Encoding: gzip, deflate\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: %i\r\nContent-Type: application/json\r\n\r\n'

# The ID of the current running process, used as a default
# identifier for requests originating from here.
PROCESS_ID = os.getpid()


def make_tcp_socket(ip: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    return sock


def socket_is_closed(sock: socket.socket) -> bool:
    """
    Returns True if the remote side did close the connection
    """
    if sock is None:
        return True
    try:
        buf = sock.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
        if buf == b'':
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


class CaseValidateUser:
    """REST Client that operates directly over TCP/IPv4 stack, with HTTP"""

    REQUEST_PATTERN = '{"user_id":%i,"text":"%s"}'

    def __init__(self, uri: str = '127.0.0.1', port: int = 8545, identity: int = PROCESS_ID) -> None:
        self.identity = identity
        self.expected = -1
        self.uri = uri
        self.port = port
        self.sock = None
        self.payload = ''.join(random.choices(
            string.ascii_uppercase, k=80))

    def __call__(self, **kwargs) -> int:
        self.send(**kwargs)
        return self.recv()

    def send(self, *, user_id: Optional[int] = None, session_id: Optional[int] = None) -> int:
        user_id = random.randint(1, 1000) if user_id is None else user_id
        session_id = random.randint(
            1, 1000) if session_id is None else session_id
        jsonrpc = self.REQUEST_PATTERN % (user_id, self.payload)
        path = 'GET /validate_session/' + str(session_id)
        headers = HTTP_HEADERS % (path, len(jsonrpc))
        self.expected = (user_id ^ session_id) % 23 == 0
        self.sock = make_tcp_socket(self.uri, self.port) if socket_is_closed(
            self.sock) else self.sock
        self.sock.send((headers + jsonrpc).encode())

    def recv(self) -> int:
        # self.sock.settimeout(0.01)
        response_bytes = self.sock.recv(4096).decode()
        self.sock.settimeout(None)
        response = json.loads(
            response_bytes[response_bytes.index("\r\n\r\n"):])
        assert 'error' not in response, response['error']
        received = response['response']
        assert self.expected == received, 'Wrong Answer'
        return received
