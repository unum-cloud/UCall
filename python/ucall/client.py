import ssl
import json
import errno
import base64
import random
import socket
from io import BytesIO
from typing import Union

import numpy as np
from PIL import Image


class Response:

    def __init__(self, data):
        self.data = data

    @property
    def json(self) -> Union[bool, int, float, str, dict, list, tuple]:
        self.raise_for_status()
        return self.data['result']

    def raise_for_status(self):
        if 'error' in self.data:
            raise RuntimeError(self.data['error'])

    @property
    def bytes(self) -> bytes:
        return base64.b64decode(self.json)

    @property
    def numpy(self) -> np.ndarray:
        buf = BytesIO(self.bytes)
        return np.load(buf, allow_pickle=True)

    @property
    def image(self) -> Image.Image:
        buf = BytesIO(self.bytes)
        return Image.open(buf)


class Request:

    def __init__(self, json):
        self.data = json
        self.packed = self.pack(json)

    def _pack_numpy(self, array):
        buf = BytesIO()
        np.save(buf, array)
        buf.seek(0)
        return base64.b64encode(buf.getvalue()).decode()

    def _pack_bytes(self, buffer):
        return base64.b64encode(buffer).decode()

    def _pack_pillow(self, image):
        buf = BytesIO()
        if not image.format:
            image.format = 'tiff'
        image.save(buf, image.format,  compression='raw', compression_level=0)
        buf.seek(0)
        return base64.b64encode(buf.getvalue()).decode()

    def pack(self, req):
        keys = None
        if isinstance(req['params'], dict):
            keys = req['params'].keys()
        else:
            keys = range(0, len(req['params']))

        for k in keys:
            if isinstance(req['params'][k], np.ndarray):
                req['params'][k] = self._pack_numpy(req['params'][k])

            elif isinstance(req['params'][k], Image.Image):
                req['params'][k] = self._pack_pillow(req['params'][k])

            elif isinstance(req['params'][k], bytes):
                req['params'][k] = self._pack_bytes(req['params'][k])

        return req


class Client:
    """JSON-RPC Client that uses classic sync Python `requests` to pass JSON calls over HTTP"""
    TCP_TERMINATOR = b'\0'

    def __init__(self, uri: str = '127.0.0.1', port: int = 8545, use_http: bool = True) -> None:
        self.uri = uri
        self.port = port
        self.use_http = use_http
        self.sock = None
        self.http_template = f'POST / HTTP/1.1\r\nHost: {uri}:{port}\r\nUser-Agent: py-ucall\r\nAccept: */*\r\nConnection: keep-alive\r\nContent-Length: %i\r\nContent-Type: application/json\r\n\r\n'

    def __getattr__(self, name):
        def call(*args, **kwargs):
            params = kwargs
            if len(args) != 0:
                assert len(
                    kwargs) == 0, 'Can\'t mix positional and keyword parameters!'
                params = args

            return self.__call__({
                'method': name,
                'params': params,
                'jsonrpc': '2.0',
            })

        return call

    def _make_socket(self):
        if not self._socket_is_closed():
            return
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.uri, self.port))

    def _socket_is_closed(self) -> bool:
        """
        Returns True if the remote side did close the connection
        """
        if self.sock is None:
            return True
        try:
            buf = self.sock.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
            if buf == b'':
                return True
        except BlockingIOError as exc:
            if exc.errno != errno.EAGAIN:
                raise
        return False

    def _send(self, json_data: dict):
        json_data['id'] = random.randint(1, 2**16)
        req_obj = Request(json_data)
        request = json.dumps(req_obj.packed)
        if self.use_http:
            request = self.http_template % (len(request)) + request
        else:
            request += self.TCP_TERMINATOR.decode()  # Termination for TCP NULL

        self._make_socket()
        self.sock.send(request.encode())

    def _receive_all_http(self, buffer_size=4096):
        body = None
        content_len = -1
        header = b''

        while b'\r\n\r\n' not in header:
            chunk = self.sock.recv(1024)
            if not chunk:
                break
            header += chunk

        header, body = header.split(b'\r\n\r\n', 1)

        pref = b'Content-Length:'
        for line in header.splitlines():
            if line.startswith(pref):
                content_len = int(line[len(pref):].strip())
                break

        content_len -= len(body)
        while content_len != 0:
            chunk = self.sock.recv(buffer_size)
            body += chunk
            content_len -= len(chunk)

        return body

    def _receive_all_tcp(self, buffer_size=4096):
        body = b''
        while not body.endswith(self.TCP_TERMINATOR):
            body += self.sock.recv(buffer_size)

        return body[:-1]

    def _recv(self) -> Response:
        response_bytes = None
        if self.use_http:
            response_bytes = self._receive_all_http()
        else:
            response_bytes = self._receive_all_tcp()
        response = json.loads(response_bytes)
        return Response(response)

    def __call__(self, jsonrpc: object) -> Response:
        self._send(jsonrpc)
        return self._recv()


class ClientTLS(Client):
    def __init__(
            self, uri: str = '127.0.0.1', port: int = 8545, ssl_context: ssl.SSLContext = None,
            allow_self_signed: bool = False, enable_session_resumption: bool = True) -> None:

        super().__init__(uri, port, use_http=True)

        if ssl_context is None:
            ssl_context = ssl.create_default_context()
            if allow_self_signed:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

        self.ssl_context = ssl_context
        self.session = None
        self.session_resumption = enable_session_resumption

    def _make_socket(self):
        if not self._socket_is_closed():
            return
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock = self.ssl_context.wrap_socket(
            self.sock, server_hostname=self.uri, session=self.session)
        self.sock.connect((self.uri, self.port))
        if self.session_resumption:
            self.session = self.sock.session

    def _socket_is_closed(self) -> bool:
        if self.sock is None:
            return True
        try:
            self.sock.setblocking(False)
            self.sock.read(1, None)
        except Exception:
            return False
        finally:
            self.sock.setblocking(True)

        return self.sock.pending() <= 0
