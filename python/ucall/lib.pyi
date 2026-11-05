"""Native HTTP and Noise networking with caller-owned polling and request batching.

A `Server` answers on one or more `Interface`s, and a `Client` calls other servers. Neither
starts a thread: the application polls each event loop with `Server.take_calls`, drains each
`BatchEndpoint` with `take_batches`, and drives each `Client` from the thread that made it.
Handlers registered with `Server.get` and its siblings bind typed parameters from the path,
the query and a JSON body, and what they return becomes the reply.

Example:
  >>> import threading, ucall
  >>> server = ucall.Server(ucall.Interface("127.0.0.1:0"))
  >>> @server.get("/sum")
  ... def sum(a: int, b: int):
  ...     return a + b
  >>> thread = threading.Thread(target=server.run)
  >>> thread.start()
  >>> client = ucall.Client(connections=1)
  >>> bytes(client.get(f"http://{server.addresses[0]}/sum?a=1&b=2").body)
  b'3'
  >>> server.stop()
  >>> thread.join()

File: python/ucall/lib.pyi
Author: Ash Vardanian
Date: October 25, 2026
"""

import enum
import os
import socket
from collections.abc import Awaitable, Buffer, Callable, Generator, Iterator, Sequence
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Final, TypeVar

F = TypeVar("F", bound=Callable[..., object])

__version__: Final[str]
DEFAULT_ADDRESS: Final[str]
"""The address a `Server` without interfaces answers on, "127.0.0.1:8545"."""

def generate_noise_keypair() -> tuple[bytes, bytes]: ...
def derive_noise_public_key(private_key: bytes, /) -> bytes: ...
def version() -> str: ...

class Status(enum.IntEnum):
    SUCCESS = 0
    DEFERRED = 1
    OUT_OF_MEMORY = 2
    IO = 7
    MALFORMED = 9
    INTERNAL = 10
    OVERFLOW = 11
    UNINITIALIZED = 12
    CONTENDED = 14
    UNSUPPORTED = 16
    INVALID_ARGUMENT = 17
    NOT_FOUND = 18
    ALREADY_EXISTS = 19
    CONNECTION_FAILED = 20
    CONNECTION_CLOSED = 21
    TIMEOUT = 22
    HANDSHAKE_FAILED = 23
    PEER_REJECTED = 24
    WOULD_BLOCK = 25
    @classmethod
    def from_name(cls, name: str, /) -> Status: ...

class Backend(enum.IntEnum):
    AUTOMATIC = 0
    POSIX = 1
    LINUX_EPOLLAIO = 2
    LINUX_URING612 = 3
    LINUX_URING618 = 4
    BSD_KQUEUE = 5
    WINDOWS_IOCP = 6

class CPUClass(enum.IntEnum):
    UNKNOWN = 0
    SERIAL = 1
    INTEL_HASWELL = 2
    INTEL_SKYLAKE = 3
    INTEL_ICELAKE = 4
    INTEL_ALDER = 5
    AWS_G2 = 6
    AWS_G5 = 7
    MONOVERSIONED = 8

class Security(enum.IntEnum):
    NONE = 0
    NOISE_XX = 1
    NOISE_IK = 2
    NOISE_KK = 3

class Verb(enum.IntEnum):
    UNKNOWN = 0
    GET = 1
    POST = 2
    PUT = 3
    DELETE = 4
    PATCH = 5
    HEAD = 6
    OPTIONS = 7
    ANY = 8

class BodyDelivery(enum.IntEnum):
    BUFFERED = 0
    STREAMED = 1

class LogLevel(enum.IntEnum):
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3
    FATAL = 4

class LogFormat(enum.IntEnum):
    HUMAN = 0
    JSON = 1

class Error(RuntimeError):
    def __init__(self, status: Status, message: str, /) -> None: ...
    @property
    def status(self) -> Status: ...
    @property
    def message(self) -> str: ...

class Interface:
    def __new__(
        cls,
        address: str = "",
        /,
        *,
        descriptor: int | socket.socket | None = None,
        device_name: str | None = None,
        security: Security | str = Security.NONE,
        noise_private_key: bytes | None = None,
        peer_authorizer: Callable[[bytes], bool] | None = None,
        noise_peer_key: bytes | None = None,
        event_loops: int = 0,
        connections: int = 1024,
        pipelined_requests: int = 0,
        max_request_bytes: int = 0,
        reply_directories: Sequence[str | bytes | os.PathLike[str] | os.PathLike[bytes]] = (),
    ) -> Interface: ...
    @property
    def address(self) -> str: ...
    @property
    def device_name(self) -> str | None: ...
    @property
    def security(self) -> Security: ...
    @property
    def noise_private_key(self) -> bytes | None: ...
    @property
    def peer_authorizer(self) -> Callable[[bytes], bool] | None: ...
    @property
    def event_loops(self) -> int: ...
    @property
    def connections(self) -> int: ...
    @property
    def pipelined_requests(self) -> int: ...
    @property
    def noise_peer_key(self) -> bytes | None: ...
    @property
    def max_request_bytes(self) -> int: ...
    @property
    def reply_directories(self) -> tuple[str | bytes, ...]: ...

class Metrics:
    def __new__(
        cls,
        address: str | bytes,
        sample_rate: float = 0.0,
        prefix: str | bytes | None = None,
        tags: Sequence[str | bytes] = (),
        interval_microseconds: int = 0,
    ) -> Metrics: ...
    @property
    def address(self) -> str | bytes: ...
    @property
    def sample_rate(self) -> float: ...
    @property
    def prefix(self) -> str | bytes | None: ...
    @property
    def tags(self) -> tuple[str | bytes, ...]: ...
    @property
    def interval_microseconds(self) -> int: ...

class Request(Buffer):
    @property
    def verb(self) -> Verb: ...
    @property
    def path(self) -> str: ...
    @property
    def body(self) -> memoryview: ...
    @property
    def peer(self) -> tuple[int, bytes, tuple[IPv4Address | IPv6Address, int] | str | None]: ...
    @property
    def parts(self) -> tuple[RequestPart, ...]: ...
    @property
    def path_segments(self) -> tuple[bytes, ...]: ...
    @property
    def query_string(self) -> str: ...
    def header(self, name: str | bytes, /) -> str | None: ...
    def fields(self) -> list[tuple[bytes, bytes]]: ...
    def query(self, name: str | bytes, /) -> str | None: ...
    def path_parameter(self, name: str | bytes, /) -> str | None: ...
    def reply(self, body: Buffer = b"", status: int = 200, headers: Sequence[str | bytes] = ()) -> None: ...
    def reply_error(self, status: int, message: str | bytes) -> None: ...
    def detach(self) -> DetachedRequest: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...

class RequestPart:
    @property
    def name(self) -> str: ...
    @property
    def content_type(self) -> str: ...
    @property
    def data(self) -> memoryview: ...

class File:
    def __new__(cls, descriptor: Any, offset: int = 0, length: int = 0) -> File: ...
    @property
    def descriptor(self) -> Any: ...
    @property
    def offset(self) -> int: ...
    @property
    def length(self) -> int: ...

class Path:
    def __new__(
        cls,
        directory: int,
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        offset: int = 0,
        length: int = 0,
    ) -> Path: ...
    @property
    def directory(self) -> int: ...
    @property
    def path(self) -> str | bytes: ...
    @property
    def offset(self) -> int: ...
    @property
    def length(self) -> int: ...

class Deferred(Awaitable[None]):
    def status(self) -> Status: ...
    def wait(self) -> None: ...
    def __await__(self) -> Generator[Any]: ...

class DetachedRequest(Buffer):
    @property
    def verb(self) -> Verb: ...
    @property
    def path(self) -> str: ...
    @property
    def body(self) -> memoryview: ...
    @property
    def peer(self) -> tuple[int, bytes, tuple[IPv4Address | IPv6Address, int] | str | None]: ...
    @property
    def parts(self) -> tuple[RequestPart, ...]: ...
    @property
    def path_segments(self) -> tuple[bytes, ...]: ...
    @property
    def query_string(self) -> str: ...
    def header(self, name: str | bytes, /) -> str | None: ...
    def fields(self) -> list[tuple[bytes, bytes]]: ...
    def query(self, name: str | bytes, /) -> str | None: ...
    def path_parameter(self, name: str | bytes, /) -> str | None: ...
    def reply(self, body: Buffer = b"", status: int = 200, headers: Sequence[str | bytes] = ()) -> None: ...
    def reply_error(self, status: int, message: str | bytes) -> None: ...
    def reply_parts(
        self,
        parts: Sequence[Buffer | File | Path],
        status: int = 200,
        headers: Sequence[str | bytes] = (),
    ) -> Deferred | None: ...
    def reply_stream(self, status: int = 200, headers: Sequence[str | bytes] = ()) -> ReplyStream: ...
    def body_chunks(self) -> BodyChunks: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...

class ReplyStream:
    def append(self, parts: Sequence[Buffer | File | Path], /) -> None: ...
    def end(self) -> Deferred | None: ...

class BodyChunks(Iterator[memoryview]):
    def __iter__(self) -> BodyChunks: ...
    def __next__(self) -> memoryview: ...

class BatchEndpoint:
    @property
    def handler(self) -> Callable[[list[Request]], object]: ...
    def take_batch(self, timeout_microseconds: int = 0) -> None: ...
    def take_batches(self) -> None: ...
    def statistics(self) -> dict[str, int]: ...

class Server:
    def __new__(
        cls,
        *interfaces: Interface,
        backend: Backend | str = Backend.AUTOMATIC,
        cpu_class: CPUClass | str = CPUClass.UNKNOWN,
        log: Callable[[LogLevel, str], object] | None = None,
        log_level: LogLevel | str = LogLevel.DEBUG,
        log_format: LogFormat | str = LogFormat.HUMAN,
        metrics: Metrics | None = None,
    ) -> Server: ...
    @property
    def event_loops(self) -> int: ...
    @property
    def backend(self) -> Backend: ...
    @property
    def cpu_class(self) -> CPUClass: ...
    @property
    def addresses(self) -> tuple[str, ...]: ...
    @property
    def batch_endpoints(self) -> tuple[BatchEndpoint, ...]: ...
    def add_endpoint(
        self,
        path: str | bytes,
        verb: Verb | str,
        handler: F,
        /,
        body: BodyDelivery | str = BodyDelivery.BUFFERED,
    ) -> F: ...
    def add_batch_endpoint(
        self,
        path: str | bytes,
        verb: Verb | str,
        handler: Callable[[list[Request]], object],
        /,
        min_size: int = 0,
        max_size: int = 0,
        max_latency_microseconds: int = 0,
    ) -> BatchEndpoint: ...
    def route(
        self,
        path: str | bytes,
        verb: Verb | str = Verb.GET,
        *,
        body: BodyDelivery | str = BodyDelivery.BUFFERED,
    ) -> Callable[[F], F]: ...
    def get(self, path: str | bytes, /, *, body: BodyDelivery | str = BodyDelivery.BUFFERED) -> Callable[[F], F]: ...
    def post(self, path: str | bytes, /, *, body: BodyDelivery | str = BodyDelivery.BUFFERED) -> Callable[[F], F]: ...
    def put(self, path: str | bytes, /, *, body: BodyDelivery | str = BodyDelivery.BUFFERED) -> Callable[[F], F]: ...
    def delete(self, path: str | bytes, /, *, body: BodyDelivery | str = BodyDelivery.BUFFERED) -> Callable[[F], F]: ...
    def patch(self, path: str | bytes, /, *, body: BodyDelivery | str = BodyDelivery.BUFFERED) -> Callable[[F], F]: ...
    def batch(
        self,
        path: str | bytes,
        verb: Verb | str = Verb.POST,
        *,
        min_size: int = 0,
        max_size: int = 0,
        max_latency_microseconds: int = 0,
    ) -> Callable[[Callable[[list[Request]], object]], BatchEndpoint]: ...
    def take_call(self, event_loop: int = 0, timeout_microseconds: int = 0) -> bool: ...
    def take_calls(self, event_loop: int = 0) -> None: ...
    def run(self) -> None: ...
    def stop(self) -> None: ...
    def event_loop_statistics(self, event_loop: int, /) -> dict[str, int]: ...

class Response(Buffer):
    @property
    def status_code(self) -> int: ...
    @property
    def body(self) -> memoryview: ...
    def header(self, name: str | bytes, /) -> str | None: ...
    def fields(self) -> list[tuple[bytes, bytes]]: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...

class Completed:
    @property
    def context(self) -> Any: ...
    @property
    def status(self) -> Status: ...
    @property
    def message(self) -> str | None: ...
    @property
    def response(self) -> Response | None: ...

class Client:
    def __new__(
        cls,
        *,
        connections: int,
        pipelined_calls: int = 0,
        calls: int = 0,
        connect_timeout_microseconds: int = 0,
        call_timeout_microseconds: int = 0,
        noise_private_key: bytes | None = None,
        peer_authorizer: Callable[[bytes], bool] | None = None,
        backend: Backend | str = Backend.AUTOMATIC,
        cpu_class: CPUClass | str = CPUClass.UNKNOWN,
        log: Callable[[LogLevel, str], object] | None = None,
        log_level: LogLevel | str = LogLevel.DEBUG,
        log_format: LogFormat | str = LogFormat.HUMAN,
        max_response_bytes: int = 0,
        server: Server | None = None,
        event_loop: int = 0,
    ) -> Client: ...
    def request(
        self,
        verb: Verb | str,
        url: str | bytes,
        /,
        body: Buffer = b"",
        *,
        json: object = None,
        headers: Sequence[str | bytes] = (),
        security: Security | str = Security.NONE,
        noise_peer_key: bytes | None = None,
        noise_private_key: bytes | None = None,
        timeout_microseconds: int = 0,
        max_retries: int = 0,
        max_redirects: int = 0,
    ) -> Response: ...
    def get(
        self,
        url: str | bytes,
        /,
        *,
        body: Buffer = b"",
        json: object = None,
        headers: Sequence[str | bytes] = (),
        security: Security | str = Security.NONE,
        noise_peer_key: bytes | None = None,
        noise_private_key: bytes | None = None,
        timeout_microseconds: int = 0,
        max_retries: int = 0,
        max_redirects: int = 0,
    ) -> Response: ...
    def post(
        self,
        url: str | bytes,
        /,
        body: Buffer = b"",
        *,
        json: object = None,
        headers: Sequence[str | bytes] = (),
        security: Security | str = Security.NONE,
        noise_peer_key: bytes | None = None,
        noise_private_key: bytes | None = None,
        timeout_microseconds: int = 0,
        max_retries: int = 0,
        max_redirects: int = 0,
    ) -> Response: ...
    def put(
        self,
        url: str | bytes,
        /,
        body: Buffer = b"",
        *,
        json: object = None,
        headers: Sequence[str | bytes] = (),
        security: Security | str = Security.NONE,
        noise_peer_key: bytes | None = None,
        noise_private_key: bytes | None = None,
        timeout_microseconds: int = 0,
        max_retries: int = 0,
        max_redirects: int = 0,
    ) -> Response: ...
    def delete(
        self,
        url: str | bytes,
        /,
        *,
        body: Buffer = b"",
        json: object = None,
        headers: Sequence[str | bytes] = (),
        security: Security | str = Security.NONE,
        noise_peer_key: bytes | None = None,
        noise_private_key: bytes | None = None,
        timeout_microseconds: int = 0,
        max_retries: int = 0,
        max_redirects: int = 0,
    ) -> Response: ...
    def patch(
        self,
        url: str | bytes,
        /,
        body: Buffer = b"",
        *,
        json: object = None,
        headers: Sequence[str | bytes] = (),
        security: Security | str = Security.NONE,
        noise_peer_key: bytes | None = None,
        noise_private_key: bytes | None = None,
        timeout_microseconds: int = 0,
        max_retries: int = 0,
        max_redirects: int = 0,
    ) -> Response: ...
    def submit(
        self,
        verb: Verb | str,
        url: str | bytes,
        /,
        body: Buffer = b"",
        headers: Sequence[str | bytes] = (),
        *,
        security: Security | str = Security.NONE,
        noise_peer_key: bytes | None = None,
        noise_private_key: bytes | None = None,
        timeout_microseconds: int = 0,
        max_retries: int = 0,
        max_redirects: int = 0,
        context: object = None,
    ) -> None: ...
    def take_completed(self, timeout_microseconds: int = 0, capacity: int = 64) -> list[Completed]: ...
