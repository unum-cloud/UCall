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
from collections.abc import Awaitable, Buffer, Callable, Generator, Iterator, Sequence
from typing import Any, Final, TypeVar

F = TypeVar("F", bound=Callable[..., object])

__version__: Final[str]
DEFAULT_ADDRESS: Final[str]
"""The address a `Server` without interfaces answers on, "127.0.0.1:8545"."""

def generate_noise_keypair() -> tuple[bytes, bytes]:
    """Draws a fresh Noise identity from the operating system's entropy.

    Returns:
      tuple[bytes, bytes]: The 32-byte private key, for `Interface` and `Client`, and
        the 32-byte public key that peer authorizers compare.

    Raises:
      Error: The operating system refused the entropy.

    Example:
      >>> private_key, public_key = ucall.generate_noise_keypair()
      >>> len(private_key), len(public_key)
      (32, 32)
    """

def derive_noise_public_key(private_key: bytes, /) -> bytes:
    """Recovers the public half of a stored Noise private key.

    Args:
      private_key (bytes): The 32-byte private key.

    Returns:
      bytes: The 32-byte public key, as a peer authorizer on the other side sees it.

    Raises:
      ValueError: `private_key` is not 32 bytes long.

    Example:
      >>> private_key, public_key = ucall.generate_noise_keypair()
      >>> ucall.derive_noise_public_key(private_key) == public_key
      True
    """

class Status(enum.IntEnum):
    """The outcome of a verb, which `Error.status` and `Completed.status` carry.

    Example:
      >>> ucall.Status.CONTENDED.name
      'CONTENDED'
    """

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

class Backend(enum.IntEnum):
    """An I/O implementation for `Server` and `Client`; `AUTOMATIC` picks the best one available.

    Example:
      >>> ucall.Server(ucall.Interface("127.0.0.1:0"), backend=ucall.Backend.POSIX).backend
      <Backend.POSIX: 1>
    """

    AUTOMATIC = 0
    POSIX = 1
    LINUX_EPOLLAIO = 2
    LINUX_URING612 = 3
    LINUX_URING618 = 4
    MACOS_KQUEUE = 5
    WINDOWS_IOCP = 6

class CPUClass(enum.IntEnum):
    """A bundle of CPU kernels for `Server` and `Client`; `AUTOMATIC` picks the initializing thread's.

    Example:
      >>> ucall.Server(ucall.Interface("127.0.0.1:0"), cpu_class="serial").cpu_class
      <CPUClass.SERIAL: 1>
    """

    AUTOMATIC = 0
    SERIAL = 1
    INTEL_HASWELL = 2
    INTEL_SKYLAKE = 3
    INTEL_ICELAKE = 4
    INTEL_ALDER = 5
    INTEL_SIERRA = 6
    AWS_G2 = 7
    APPLE_M2 = 8
    AWS_G5 = 9
    MONOVERSIONED = 10

class Security(enum.IntEnum):
    """Transport encryption of an `Interface` or a client call: plaintext or a Noise pattern.

    Example:
      >>> ucall.Security["NOISE_XX"]
      <Security.NOISE_XX: 1>
    """

    NONE = 0
    NOISE_XX = 1
    NOISE_IK = 2
    NOISE_KK = 3

class Verb(enum.IntEnum):
    """An HTTP method; `ANY` registers an endpoint for every method and never arrives itself.

    Example:
      >>> ucall.Verb.POST == 2
      True
    """

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
    """When an endpoint's handler runs: once the body is buffered, or at headers time with the
    body pulled through `DetachedRequest.body_chunks`.

    Example:
      >>> @server.post("/upload", body=ucall.BodyDelivery.STREAMED)
      ... def upload(request: ucall.Request):
      ...     workers.submit(store, request.detach())
    """

    BUFFERED = 0
    STREAMED = 1

class LogLevel(enum.IntEnum):
    """The severity of a line the `Server` log callback receives, from the most verbose up.

    Example:
      >>> ucall.LogLevel.WARNING > ucall.LogLevel.INFO
      True
    """

    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3
    FATAL = 4

class Error(RuntimeError):
    """A failed verb, raised with the `Status` it reported and a static detail.

    Args:
      status (Status): The failure, such as `Status.CONTENDED`.
      message (str): The detail of the failure, or the status name without one.

    Example:
      >>> error = ucall.Error(ucall.Status.TIMEOUT, "no reply")
      >>> error.status, error.message, str(error)
      (<Status.TIMEOUT: 22>, 'no reply', 'TIMEOUT: no reply')
    """

    def __init__(self, status: Status, message: str, /) -> None: ...
    @property
    def status(self) -> Status:
        """The `Status` of the failure."""
    @property
    def message(self) -> str:
        """The detail of the failure."""

class Interface:
    """One address a server answers on, with the security and admission of what arrives there.

    Args:
      address (str): The "host:port" to listen on; port 0 takes a free one, which
        `Server.addresses` reports.
      device_name (str, optional): A network device to pin the socket to, such as "eth0";
        None binds by address alone.
      security (Security, optional): Encryption of accepted connections. Defaults to
        `Security.NONE`.
      private_key (bytes, optional): The 32-byte Noise identity, required under Noise.
      peer_authorizer (Callable[[bytes], bool], optional): Admits a Noise peer by its 32-byte
        static key, required under `Security.NOISE_XX`; None admits every peer.
      noise_peer_key (bytes, optional): The one caller's 32-byte static public key, required
        under `Security.NOISE_KK`.
      event_loops (int, optional): Loops accepting here; 0 takes one for an address and one per
        receive queue for a device.
      connections (int, optional): Connections open at once. Defaults to 1024.
      pipelined_requests (int, optional): Requests one connection carries before the server
        stops reading from it; 0 means one.
      max_request_bytes (int, optional): The largest request head and buffered body, past which
        the reply is 413; 0 takes the largest receive buffer the kernel grants a socket.
      reply_directories (Sequence[str | bytes | os.PathLike], optional): The directories a
        `Path` part names by position, each opened once by the server.

    Raises:
      TypeError: An argument of the wrong type.
      ValueError: A key other than 32 bytes long, or an unknown `security`.

    Example:
      >>> interface = ucall.Interface("127.0.0.1:0", connections=64, pipelined_requests=16)
      >>> interface.connections, interface.security
      (64, <Security.NONE: 0>)
    """

    def __new__(
        cls,
        address: str,
        /,
        *,
        device_name: str | None = None,
        security: Security | str = Security.NONE,
        private_key: bytes | None = None,
        peer_authorizer: Callable[[bytes], bool] | None = None,
        noise_peer_key: bytes | None = None,
        event_loops: int = 0,
        connections: int = 1024,
        pipelined_requests: int = 0,
        max_request_bytes: int = 0,
        reply_directories: Sequence[str | bytes | os.PathLike[str] | os.PathLike[bytes]] = (),
    ) -> Interface: ...
    @property
    def address(self) -> str:
        """The "host:port" to listen on."""
    @property
    def device_name(self) -> str | None:
        """The pinned device, or None."""
    @property
    def security(self) -> Security:
        """Encryption of accepted connections."""
    @property
    def private_key(self) -> bytes | None:
        """The 32-byte Noise identity, or None."""
    @property
    def peer_authorizer(self) -> Callable[[bytes], bool] | None:
        """The Noise peer vetting, or None."""
    @property
    def event_loops(self) -> int:
        """Requested loops; 0 chooses."""
    @property
    def connections(self) -> int:
        """Connections open at once."""
    @property
    def pipelined_requests(self) -> int:
        """Requests one connection carries at once; 0 means one."""
    @property
    def noise_peer_key(self) -> bytes | None:
        """The 32-byte static key KK expects, or None."""
    @property
    def max_request_bytes(self) -> int:
        """The largest request head and buffered body; 0 takes the kernel's receive buffer."""
    @property
    def reply_directories(self) -> tuple[str | bytes, ...]:
        """The directories `Path` parts name by position."""

class Metrics:
    """Where a `Server` sends StatsD datagrams, each event loop on its own schedule.

    Args:
      address (str | bytes): The StatsD UDP endpoint, "host:port".
      sample_rate (float, optional): The fraction of finished requests whose latency is
        reported, in (0, 1]; 0 takes 1.
      prefix (str | bytes, optional): The metric name prefix; empty takes "ucall".
      tags (Sequence[str | bytes], optional): Global "key:value" tags.
      interval_us (int, optional): Microseconds between datagrams; 0 takes one second.

    Example:
      >>> metrics = ucall.Metrics("127.0.0.1:8125", tags=("service:inference",))
      >>> server = ucall.Server(ucall.Interface("127.0.0.1:0"), metrics=metrics)
    """

    def __new__(
        cls,
        address: str | bytes,
        sample_rate: float = 0.0,
        prefix: str | bytes | None = None,
        tags: Sequence[str | bytes] = (),
        interval_us: int = 0,
    ) -> Metrics: ...
    @property
    def address(self) -> str | bytes:
        """The StatsD "host:port"."""
    @property
    def sample_rate(self) -> float:
        """Latencies reported; 0 takes 1."""
    @property
    def prefix(self) -> str | bytes | None:
        """The metric name prefix, or None for "ucall"."""
    @property
    def tags(self) -> tuple[str | bytes, ...]:
        """Global "key:value" tags."""
    @property
    def interval_us(self) -> int:
        """Microseconds between datagrams."""

class Request(Buffer):
    """One received HTTP request, retained until a reply consumes it.

    A handler taking one parameter annotated `Request` receives it on the polling thread, and may
    keep it to answer later from any thread, once, or `detach` it to a worker for the replies that
    may defer. `body`, `parts` and the buffer protocol view the received bytes without a copy
    until the reply, which is refused while such a view is alive, except the `body` passed as the
    reply body itself. A request released without a reply answers 500.

    Example:
      >>> @server.put("/echo/{name}")
      ... def echo(request: ucall.Request):
      ...     interface_index, static_key = request.peer
      ...     greeting = f"{request.verb.name} {request.path_parameter('name')}"
      ...     request.reply(request.body, headers=(f"x-greeting: {greeting}",))
    """

    @property
    def verb(self) -> Verb:
        """The `Verb` it arrived with, never `Verb.ANY`."""
    @property
    def path(self) -> str:
        """The path as sent, still percent-encoded, without the query."""
    @property
    def body(self) -> memoryview:
        """A read-only memoryview of the body, valid until the reply."""
    @property
    def peer(self) -> tuple[int, bytes]:
        """The index of the interface it arrived on and the peer's 32-byte Noise key, zeros on plaintext."""
    @property
    def parts(self) -> tuple[RequestPart, ...]:
        """The `RequestPart`s of a multipart/form-data body, else empty."""
    @property
    def path_segments(self) -> tuple[bytes, ...]:
        """The path's components between slashes, as sent."""
    def header(self, name: str | bytes, /) -> str | None:
        """Looks up a header of the request by its case-insensitive name.

        Args:
          name (str | bytes): The header name, such as "Content-Type".

        Returns:
          str | None: The value as sent, or None when the request has no such header.

        Example:
          >>> @server.get("/agent")
          ... def agent(request: ucall.Request):
          ...     return request.header("user-agent") or "unknown"
        """
    def query(self, name: str | bytes, /) -> str | None:
        """Looks up a query parameter of the request by its case-sensitive name.

        Args:
          name (str | bytes): The parameter name.

        Returns:
          str | None: The value still percent-encoded, which `urllib.parse.unquote_plus`
            decodes, or None when the query has no such parameter.

        Example:
          >>> @server.get("/search")
          ... def search(request: ucall.Request):
          ...     return urllib.parse.unquote_plus(request.query("q") or "")
        """
    def path_parameter(self, name: str | bytes, /) -> str | None:
        """Looks up a placeholder the endpoint's URI template captured.

        Args:
          name (str | bytes): The placeholder name without braces, "path" for `{*path}`.

        Returns:
          str | None: The captured text as sent, or None when the template has no such
            placeholder.

        Example:
          >>> @server.get("/files/{*path}")
          ... def files(request: ucall.Request):
          ...     return request.path_parameter("path")
        """
    def reply(self, body: Buffer = b"", status: int = 200, headers: Sequence[str | bytes] = ()) -> None:
        """Answers the request, once, from any thread; a peer that disconnected consumes it silently.

        Args:
          body (Buffer, optional): Any bytes-like object, copied before the call returns; the
            request's own `body` passes without a copy and is released by the reply.
          status (int, optional): The HTTP status. Defaults to 200.
          headers (Sequence[str | bytes], optional): "name: value" lines; the server adds
            Content-Length, Date and Server itself.

        Raises:
          BufferError: A view over `body`, other than the one passed, is still alive.
          Error: The request was already answered, with `Status.ALREADY_EXISTS`.

        Example:
          >>> @server.post("/echo")
          ... def echo(request: ucall.Request):
          ...     request.reply(request.body, headers=("content-type: application/octet-stream",))
        """
    def reply_error(self, status: int, message: str | bytes) -> None:
        r"""Answers the request with an error status and a plain-text message, once.

        Args:
          status (int): The HTTP status, 400 or above.
          message (str | bytes): The body, sent as text/plain.

        Raises:
          BufferError: A view over `body` is still alive.
          Error: The request was already answered, with `Status.ALREADY_EXISTS`.

        Example:
          >>> @server.get("/teapot")
          ... def teapot(request: ucall.Request):
          ...     request.reply_error(418, "short and stout\n")
        """
    def detach(self) -> DetachedRequest:
        """Hands the request to another thread, the one way to the verbs whose replies may defer.

        The `DetachedRequest` owns the request from then on, and this object answers nothing. A
        `Deferred` waits when released, and a wait on the polling thread would wait for the loop
        running it, so pass the detached request to a worker rather than replying here.

        Raises:
          BufferError: A view over `body` or a part is still alive.
          Error: The request was already answered or detached, with `Status.ALREADY_EXISTS`.

        Example:
          >>> @server.get("/videos/{name}")
          ... def video(request: ucall.Request):
          ...     name = request.path_parameter("name")
          ...     workers.submit(send_video, request.detach(), name)
        """
    def __buffer__(self, flags: int, /) -> memoryview: ...

class RequestPart:
    """One part of a `multipart/form-data` request body, from `Request.parts`.

    `data` views the received bytes without a copy and keeps the request alive, so the request
    refuses its reply until every such view is gone, as it does for views over `body`.

    Example:
      >>> @server.post("/upload")
      ... def upload(request: ucall.Request):
      ...     return {part.name: len(part.data) for part in request.parts}
    """

    @property
    def name(self) -> str:
        """The name from Content-Disposition."""
    @property
    def content_type(self) -> str:
        """The part's Content-Type, empty if absent."""
    @property
    def data(self) -> memoryview:
        """A read-only memoryview of the payload, which refuses the request's reply while alive."""

class File:
    """A byte range of a file the caller opened, as one part of `DetachedRequest.reply_parts`.

    The event loop reads it unbuffered after the call returns, so the reply defers, and the
    `Deferred` keeps this part, and through it a file object, alive until it is final. UCall
    never closes the descriptor.

    Args:
      descriptor (int | HasFileno): A regular file opened with `os.O_DIRECT`, or an object
        whose `fileno()` answers one.
      offset (int, optional): The range's first byte. Defaults to 0.
      length (int, optional): The range's byte count; 0 sends through the end of the file.

    Example:
      >>> part = ucall.File(os.open("/srv/videos/intro.mp4", os.O_RDONLY | os.O_DIRECT))
    """

    def __new__(cls, descriptor: Any, offset: int = 0, length: int = 0) -> File: ...
    @property
    def descriptor(self) -> Any:
        """The descriptor or its file object."""
    @property
    def offset(self) -> int:
        """The range's first byte."""
    @property
    def length(self) -> int:
        """The range's bytes; 0 runs to the end."""

class Path:
    """A byte range of a file beneath a reply directory, as one part of `reply_parts`.

    The event loop opens it unbuffered beneath the directory and closes it once sent, so the
    reply defers. Absolute paths, ".." and any resolution leaving the directory are refused.

    Args:
      directory (int): A position in the `reply_directories` of the interface the request
        arrived on.
      path (str | bytes | os.PathLike): The file beneath that directory.
      offset (int, optional): The range's first byte. Defaults to 0.
      length (int, optional): The range's byte count; 0 sends through the end of the file.

    Example:
      >>> part = ucall.Path(0, "intro.mp4", offset=1 << 20)
    """

    def __new__(
        cls,
        directory: int,
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        offset: int = 0,
        length: int = 0,
    ) -> Path: ...
    @property
    def directory(self) -> int:
        """The position of the reply directory."""
    @property
    def path(self) -> str | bytes:
        """The file beneath the directory."""
    @property
    def offset(self) -> int:
        """The range's first byte."""
    @property
    def length(self) -> int:
        """The range's bytes; 0 runs to the end."""

class Deferred(Awaitable[None]):
    r"""A reply still sending file or path parts, from `reply_parts` or `ReplyStream.end`.

        It owns the reply's outcome and keeps the `File` parts it borrows alive until the outcome is
        final. `await` it in a coroutine, or call `wait()`; released unfinished, it waits, so keep it
        off the polling thread, as `Request.detach` does.

        Example:
          >>> deferred = detached.reply_parts([b"--frame
    ", ucall.Path(0, "intro.mp4")])
          >>> deferred.wait()  # or: await deferred
    """

    def status(self) -> Status:
        """Reads the reply's outcome without waiting.

        Returns:
          Status: `Status.DEFERRED` while parts still send, then the final one.

        Example:
          >>> deferred.status() in (ucall.Status.DEFERRED, ucall.Status.SUCCESS)
          True
        """
    def wait(self) -> None:
        """Blocks until every part is sent, without the interpreter lock.

        Raises:
          Error: The reply failed, such as `Status.NOT_FOUND` for a missing file, which answered
            404, or `Status.CONNECTION_CLOSED` for a peer that left.

        Example:
          >>> deferred.wait()
        """
    def __await__(self) -> Generator[Any]: ...

class DetachedRequest(Buffer):
    r"""A request taken off its polling thread by `Request.detach`, owning the replies that may defer.

        It reads and answers as `Request` does, and alone offers `reply_parts`, `reply_stream` and
        `body_chunks`, whose `Deferred` replies and waiting pulls belong on a worker thread. Released
        without a reply, it answers 500.

        Example:
          >>> def send_video(detached: ucall.DetachedRequest, name: str):
          ...     deferred = detached.reply_parts([b"--frame
    ", ucall.Path(0, name)])
          ...     deferred.wait()  # or: await deferred
    """

    @property
    def verb(self) -> Verb:
        """The `Verb` it arrived with, never `Verb.ANY`."""
    @property
    def path(self) -> str:
        """The path as sent, still percent-encoded, without the query."""
    @property
    def body(self) -> memoryview:
        """A read-only memoryview of the body, valid until the reply."""
    @property
    def peer(self) -> tuple[int, bytes]:
        """The index of the interface it arrived on and the peer's 32-byte Noise key, zeros on plaintext."""
    @property
    def parts(self) -> tuple[RequestPart, ...]:
        """The `RequestPart`s of a multipart/form-data body, else empty."""
    @property
    def path_segments(self) -> tuple[bytes, ...]:
        """The path's components between slashes, as sent."""
    def header(self, name: str | bytes, /) -> str | None:
        """Looks up a header of the request by its case-insensitive name, as `Request.header` does."""
    def query(self, name: str | bytes, /) -> str | None:
        """Looks up a query parameter of the request, as `Request.query` does."""
    def path_parameter(self, name: str | bytes, /) -> str | None:
        """Looks up a placeholder the endpoint's URI template captured, as `Request.path_parameter` does."""
    def reply(self, body: Buffer = b"", status: int = 200, headers: Sequence[str | bytes] = ()) -> None:
        """Answers the request, once, as `Request.reply` does."""
    def reply_error(self, status: int, message: str | bytes) -> None:
        """Answers the request with an error status and a plain-text message, as `Request.reply_error` does."""
    def reply_parts(
        self,
        parts: Sequence[Buffer | File | Path],
        status: int = 200,
        headers: Sequence[str | bytes] = (),
    ) -> Deferred | None:
        r"""Answers the request, once, with `parts` concatenated into the body.

                Bytes-like parts are copied before the call returns, and the reply is then final. A `File` or
                `Path` part is read by the event loop afterwards, sized first so Content-Length is measured,
                and its reply defers: one failing before the head replaces the reply with 404 or 416, and one
                failing after it resets the connection.

                Args:
                  parts (Sequence[Buffer | File | Path]): The body, in order.
                  status (int, optional): The HTTP status. Defaults to 200.
                  headers (Sequence[str | bytes], optional): "name: value" lines; the server adds
                    Content-Length, Date and Server itself.

                Returns:
                  Deferred | None: The `Deferred` of a reply with file or path parts, which may already be
                    final, or None for bytes alone, final on return.

                Raises:
                  BufferError: A view over the request's bytes is still alive.
                  Error: A refused part, such as a descriptor without O_DIRECT, or a request already
                    answered, with `Status.ALREADY_EXISTS`.

                Example:
                  >>> deferred = detached.reply_parts([b"--frame
        ", ucall.Path(0, "intro.mp4")])
                  >>> deferred.wait()  # or: await deferred
        """
    def reply_stream(self, status: int = 200, headers: Sequence[str | bytes] = ()) -> ReplyStream:
        r"""Answers the request with a body sent in parts, emitting the status line and headers now.

                The body is chunked for HTTP/1.1 peers, unless `headers` declare Content-Length, which the
                parts must then sum to. A peer that left already still opens the stream, whose parts drop.

                Args:
                  status (int, optional): The HTTP status. Defaults to 200.
                  headers (Sequence[str | bytes], optional): "name: value" lines.

                Returns:
                  ReplyStream: The open reply, which owns the request from then on.

                Raises:
                  BufferError: A view over the request's bytes is still alive.
                  Error: A malformed header, or a request already answered, with `Status.ALREADY_EXISTS`.

                Example:
                  >>> stream = detached.reply_stream(headers=("content-type: text/event-stream",))
                  >>> stream.append([b"data: 1

        "])
                  >>> stream.end()
        """
    def body_chunks(self) -> BodyChunks:
        """Iterates the request body as it arrives, each chunk the bytes decoded since the last pull.

        Each chunk is a read-only memoryview valid until the next pull, which releases it, and a
        pull waits for bytes without the interpreter lock. On a buffered endpoint the first chunk
        is the whole body.

        Returns:
          BodyChunks: The iterator, ending once the body did.

        Raises:
          BufferError: From a pull, while a view derived from the last chunk is still alive.
          Error: From a pull, `Status.CONNECTION_CLOSED` or `Status.MALFORMED` for a body cut short
            or badly framed, or `Status.WOULD_BLOCK` on the polling thread with nothing decoded.

        Example:
          >>> for chunk in detached.body_chunks():
          ...     digest.update(chunk)
        """
    def __buffer__(self, flags: int, /) -> memoryview: ...

class ReplyStream:
    r"""A reply sent in parts, from `DetachedRequest.reply_stream`, ended once.

        Released without `end()`, it ends the reply itself and waits for any file parts to send.

        Example:
          >>> stream = detached.reply_stream(headers=("content-type: application/x-ndjson",))
          >>> for row in rows:
          ...     stream.append([json.dumps(row).encode(), b"
    "])
          >>> stream.end()
    """

    def append(self, parts: Sequence[Buffer | File | Path], /) -> None:
        r"""Queues `parts` after the ones before, all of them or none.

                Bytes-like parts are copied before the call returns; `File` parts stay alive with the
                stream until its end is final.

                Args:
                  parts (Sequence[Buffer | File | Path]): The next parts of the body.

                Raises:
                  Error: `Status.WOULD_BLOCK` while the peer lags, to retry once it caught up, or
                    `Status.CONNECTION_CLOSED` once it left; nothing was queued either way.

                Example:
                  >>> stream.append([b"data: ", payload, b"

        "])
        """
    def end(self) -> Deferred | None:
        """Completes the reply, consuming the request whatever happens.

        Returns:
          Deferred | None: The `Deferred` of a stream that appended file or path parts, which
            may already be final, or None for bytes alone.

        Raises:
          Error: The parts fell short of a declared Content-Length, with `Status.MALFORMED`, or
            the stream already ended, with `Status.ALREADY_EXISTS`.

        Example:
          >>> deferred = stream.end()
        """

class BodyChunks(Iterator[memoryview]):
    """The iterator `DetachedRequest.body_chunks` returns, yielding memoryviews of the body.

    Example:
      >>> received = sum(len(chunk) for chunk in detached.body_chunks())
    """

    def __iter__(self) -> BodyChunks: ...
    def __next__(self) -> memoryview: ...

class BatchEndpoint:
    """One batching route of a server, drained by one application thread.

    Requests matching it from every event loop share one queue, which `take_batch` and
    `take_batches` hand to the handler as a list once enough arrived or the oldest waited long
    enough. The handler runs on the draining thread and replies to each request, in any order.

    Example:
      >>> @server.batch("/infer", min_size=8, max_size=64, max_latency_us=500)
      ... def infer(requests: list[ucall.Request]):
      ...     for request in requests:
      ...         request.reply(bytes(request.body))
      >>> infer in server.batch_endpoints
      True
    """

    @property
    def handler(self) -> Callable[[list[Request]], object]:
        """The function handed each batch."""
    def take_batch(self, timeout_us: int = 0) -> None:
        """Runs the handler on this thread if a batch is due, waiting for one at most `timeout_us`.

        Each batch endpoint has one draining owner, and the wait polls no event loop.

        Args:
          timeout_us (int, optional): The longest wait in microseconds; 0 checks once.

        Raises:
          Error: The server failed, or was released.

        Example:
          >>> endpoint.take_batch(timeout_us=1_000)
        """
    def take_batches(self) -> None:
        """Runs every due batch on this thread, sleeping in between, until `Server.stop()`.

        Requests still queued at the stop are released without a call to the handler.

        Raises:
          Error: The server failed, or was released.

        Example:
          >>> drainer = threading.Thread(target=endpoint.take_batches)
          >>> drainer.start()
        """
    def statistics(self) -> dict[str, int]:
        """Counts the batches the endpoint handed out since registration, and why each fired.

        Each counter is read on its own, so a snapshot of an endpoint being drained is not one
        instant, and batches a stop released count nowhere.

        Returns:
          dict[str, int]: `batches` handed to the handler and the `requests` in them, then the
            `filled_batches` that reached `max_size`, the `ready_batches` that reached `min_size`,
            and the `expired_batches` that waited out `max_latency_us`.

        Example:
          >>> counters = endpoint.statistics()
          >>> counters["requests"] / max(counters["batches"], 1)
          0.0
        """

class Server:
    """An HTTP server over one or more interfaces, polled by threads the application starts.

    It starts no threads: each event loop needs one owner calling `take_calls`, and each batch
    endpoint one calling `BatchEndpoint.take_batches`, while `run` serves the simplest server on
    the calling thread. Register every endpoint before the first poll.

    Args:
      *interfaces (Interface): Where to answer; none answers on `DEFAULT_ADDRESS`.
      backend (Backend, optional): The I/O implementation. Defaults to `Backend.AUTOMATIC`.
      cpu_class (CPUClass, optional): The CPU kernels. Defaults to `CPUClass.AUTOMATIC`.
      log (Callable[[LogLevel, str], object], optional): Receives every line the server writes,
        on whichever thread wrote it, holding the interpreter lock; None writes nothing.
      metrics (Metrics, optional): Where to send StatsD datagrams; None sends none.

    Raises:
      Error: An interface that cannot be bound, such as an address in use, or a reply directory
        that cannot be opened.

    Example:
      >>> server = ucall.Server(ucall.Interface("127.0.0.1:0"), backend="posix")
      >>> server.event_loops, server.backend
      (1, <Backend.POSIX: 1>)
    """

    def __new__(
        cls,
        *interfaces: Interface,
        backend: Backend | str = Backend.AUTOMATIC,
        cpu_class: CPUClass | str = CPUClass.AUTOMATIC,
        log: Callable[[LogLevel, str], object] | None = None,
        metrics: Metrics | None = None,
    ) -> Server: ...
    @property
    def event_loops(self) -> int:
        """Resolved loops, each needing one polling thread."""
    @property
    def backend(self) -> Backend:
        """The I/O implementation initialization chose."""
    @property
    def cpu_class(self) -> CPUClass:
        """The CPU kernels initialization chose."""
    @property
    def addresses(self) -> tuple[str, ...]:
        """The resolved "host:port" of each interface."""
    @property
    def batch_endpoints(self) -> tuple[BatchEndpoint, ...]:
        """Batch endpoints, each needing a drainer."""
    def add_endpoint(
        self,
        path: str | bytes,
        verb: Verb | str,
        handler: F,
        /,
        body: BodyDelivery | str = BodyDelivery.BUFFERED,
    ) -> F:
        """Routes `verb` requests matching the URI template `path` to `handler`, on the polling thread.

        A handler taking one parameter annotated `Request` receives the request, which it may answer
        later from any thread, and what it returns other than None is the reply. Any other handler's
        parameters, annotated `str`, `int`, `float`, `bool` or `bytes` or left bare, bind by name from
        a path placeholder, then the query, then a JSON object body, then their defaults; a missing
        or malformed value answers 400, and None returned answers 204. Returned bytes-like objects
        reply as binary, `str` as UTF-8 text, and anything else as JSON. An exception answers 500.

        Args:
          path (str): A URI template such as `/users/{name}` or `/files/{*path}`.
          verb (Verb): The method to answer; `Verb.ANY` answers every one.
          handler (Callable): The function to route to.
          body (BodyDelivery, optional): `BodyDelivery.STREAMED` runs the handler once the headers
            arrived, its body pulled through `DetachedRequest.body_chunks`. Defaults to buffered.

        Returns:
          Callable: `handler` itself.

        Raises:
          TypeError: A parameter that cannot bind, such as `*args` or one annotated `list`.
          Error: A duplicate route or an invalid template.

        Example:
          >>> def scale(value: float, factor: float = 2.0):
          ...     return value * factor
          >>> server.add_endpoint("/scale/{value}", ucall.Verb.GET, scale) is scale
          True
        """
    def add_batch_endpoint(
        self,
        path: str | bytes,
        verb: Verb | str,
        handler: Callable[[list[Request]], object],
        /,
        min_size: int = 0,
        max_size: int = 0,
        max_latency_us: int = 0,
    ) -> BatchEndpoint:
        """Queues matching requests from every event loop for `handler(requests)`, called in batches.

        A batch is due once `min_size` requests arrived, `max_size` are queued, or the oldest waited
        `max_latency_us`. The handler runs on the thread draining the returned endpoint and replies
        to each request.

        Args:
          path (str): A URI template such as "/infer".
          verb (Verb): The method to answer; `Verb.ANY` answers every one.
          handler (Callable[[list[Request]], object]): The function handed each batch.
          min_size (int, optional): Requests that make a batch due at once; 0 means 1.
          max_size (int, optional): Requests one batch holds at most; 0 means 32.
          max_latency_us (int, optional): The longest the oldest request waits for a batch to
            fill, in microseconds; 0 means 10 ms.

        Returns:
          BatchEndpoint: The endpoint to drain.

        Raises:
          Error: A duplicate route or an invalid template.

        Example:
          >>> endpoint = server.add_batch_endpoint("/sizes", "POST", lambda requests: None, 4)
          >>> endpoint in server.batch_endpoints
          True
        """
    def route(
        self,
        path: str | bytes,
        verb: Verb | str = Verb.GET,
        *,
        body: BodyDelivery | str = BodyDelivery.BUFFERED,
    ) -> Callable[[F], F]:
        """Registers the decorated function for `verb` requests matching the URI template `path`.

        Args:
          path (str): A URI template such as "/users/{name}".
          verb (Verb, optional): The method to answer. Defaults to `Verb.GET`.
          body (BodyDelivery, optional): When the handler runs, as `add_endpoint` takes it.

        Returns:
          Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.

        Example:
          >>> @server.route("/anything", ucall.Verb.ANY)
          ... def anything(request: ucall.Request):
          ...     return request.verb.name
        """
    def get(self, path: str | bytes, /, *, body: BodyDelivery | str = BodyDelivery.BUFFERED) -> Callable[[F], F]:
        """Registers the decorated function for GET requests matching the URI template `path`.

        Args:
          path (str): A URI template such as "/users/{name}".
          body (BodyDelivery, optional): When the handler runs, as `add_endpoint` takes it.

        Returns:
          Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.

        Example:
          >>> @server.get("/users/{name}")
          ... def user(name: str, verbose: bool = False):
          ...     return {"name": name, "verbose": verbose}
        """
    def post(self, path: str | bytes, /, *, body: BodyDelivery | str = BodyDelivery.BUFFERED) -> Callable[[F], F]:
        """Registers the decorated function for POST requests matching the URI template `path`.

        Args:
          path (str): A URI template such as "/sum".
          body (BodyDelivery, optional): When the handler runs, as `add_endpoint` takes it.

        Returns:
          Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.

        Example:
          >>> @server.post("/sum")
          ... def sum(a: int, b: float = 0.5):
          ...     return a + b
        """
    def put(self, path: str | bytes, /, *, body: BodyDelivery | str = BodyDelivery.BUFFERED) -> Callable[[F], F]:
        """Registers the decorated function for PUT requests matching the URI template `path`.

        Args:
          path (str): A URI template such as `/files/{*path}`.
          body (BodyDelivery, optional): When the handler runs, as `add_endpoint` takes it.

        Returns:
          Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.

        Example:
          >>> @server.put("/files/{*path}")
          ... def store(request: ucall.Request):
          ...     return len(request.body)
        """
    def delete(self, path: str | bytes, /, *, body: BodyDelivery | str = BodyDelivery.BUFFERED) -> Callable[[F], F]:
        """Registers the decorated function for DELETE requests matching the URI template `path`.

        Args:
          path (str): A URI template such as `/files/{*path}`.
          body (BodyDelivery, optional): When the handler runs, as `add_endpoint` takes it.

        Returns:
          Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.

        Example:
          >>> @server.delete("/files/{*path}")
          ... def remove(path: str):
          ...     return None
        """
    def patch(self, path: str | bytes, /, *, body: BodyDelivery | str = BodyDelivery.BUFFERED) -> Callable[[F], F]:
        """Registers the decorated function for PATCH requests matching the URI template `path`.

        Args:
          path (str): A URI template such as "/users/{name}".
          body (BodyDelivery, optional): When the handler runs, as `add_endpoint` takes it.

        Returns:
          Callable[[F], F]: A decorator calling `add_endpoint` and returning the function as is.

        Example:
          >>> @server.patch("/users/{name}")
          ... def rename(name: str, alias: str):
          ...     return f"{name} is {alias}"
        """
    def batch(
        self,
        path: str | bytes,
        verb: Verb | str = Verb.POST,
        *,
        min_size: int = 0,
        max_size: int = 0,
        max_latency_us: int = 0,
    ) -> Callable[[Callable[[list[Request]], object]], BatchEndpoint]:
        """Registers the decorated `handler(requests)` as a batch endpoint, replacing it with that.

        Args:
          path (str): A URI template such as "/infer".
          verb (Verb, optional): The method to answer. Defaults to `Verb.POST`.
          min_size (int, optional): Requests that make a batch due at once; 0 means 1.
          max_size (int, optional): Requests one batch holds at most; 0 means 32.
          max_latency_us (int, optional): The longest the oldest request waits, in microseconds;
            0 means 10 ms.

        Returns:
          Callable: A decorator calling `add_batch_endpoint` and returning its `BatchEndpoint`.

        Example:
          >>> @server.batch("/reverse", min_size=4, max_size=4)
          ... def reverse(requests: list[ucall.Request]):
          ...     for request in reversed(requests):
          ...         request.reply(request.body)
          >>> type(reverse).__name__
          'BatchEndpoint'
        """
    def take_call(self, event_loop: int = 0, timeout_us: int = 0) -> None:
        """Advances one event loop and runs its ready handlers on this thread.

        Each loop has one polling owner, and handlers run inside the call, so a slow one delays
        its return past `timeout_us`.

        Args:
          event_loop (int, optional): The loop to advance, below `event_loops`. Defaults to 0.
          timeout_us (int, optional): The longest wait for I/O in microseconds; 0 polls once.

        Raises:
          Error: An `event_loop` past the last one, or an I/O failure.

        Example:
          >>> server.take_call(0, timeout_us=1_000)
        """
    def take_calls(self, event_loop: int = 0) -> None:
        """Drives one event loop on this thread until `stop()` or an I/O failure.

        The interpreter lock is released meanwhile and taken back only to run handlers, so one
        thread per loop serves in parallel with the others. Signals reach Python only once it
        returns, so call it from threads other than the main one.

        Args:
          event_loop (int, optional): The loop to drive, below `event_loops`. Defaults to 0.

        Raises:
          Error: An `event_loop` past the last one, or an I/O failure.

        Example:
          >>> pollers = [threading.Thread(target=server.take_calls, args=(loop,))
          ...            for loop in range(server.event_loops)]
        """
    def run(self) -> None:
        """Serves a server of one event loop and no batch endpoints on the calling thread.

        It returns after `stop()` or `KeyboardInterrupt`, polling in slices of 100 ms and checking
        for signals between them, and once stopped it lets the loop finish the requests in flight.

        Raises:
          RuntimeError: The server has more than one event loop or any batch endpoint.
          KeyboardInterrupt: Ctrl+C arrived while serving.
          Error: An I/O failure.

        Example:
          >>> runner = threading.Thread(target=server.run)
          >>> runner.start()
          >>> server.stop()
          >>> runner.join()
        """
    def stop(self) -> None:
        """Asks the server to stop, waking every polling and draining caller to return.

        Safe from any thread and from a handler. Join the polling threads before releasing
        the server.

        Example:
          >>> server.stop()
        """
    def event_loop_statistics(self, event_loop: int, /) -> dict[str, int]:
        """Counts what one event loop did since initialization.

        Divided by `requests`, the counters price one call.

        Args:
          event_loop (int): The loop to read, below `event_loops`.

        Returns:
          dict[str, int]: `polls`, `empty_polls`, `kernel_enters`, `submissions`, `completions`,
            `cancellations`, `accepts`, `requests`, `receive_rearms`, `bytes_received`,
            `bytes_sent`, `bytes_copied`, `zero_copy_sends`, `zero_copy_fallbacks`,
            `copying_sends`, `file_reads_asynchronous`, `file_reads_blocking`, `bytes_read`,
            `file_window_overlaps`, `linger_resets`, `ready_passes`, `replied_dequeues`,
            `refused_requests`, `handshake_failures` and `authorizer_refusals`, each read on its own.

        Raises:
          Error: An `event_loop` past the last one.

        Example:
          >>> server.event_loop_statistics(0)["requests"]
          0
        """

class Response(Buffer):
    """One received HTTP response, which owns its bytes and outlives its client.

    `body` and the buffer protocol view the received bytes without a copy.

    Example:
      >>> response = client.post("http://127.0.0.1:8545/sum", json={"a": 1, "b": 2})
      >>> response.status_code, bytes(response.body), json.loads(bytes(response))
      (200, b'3', 3)
    """

    @property
    def status_code(self) -> int:
        """The HTTP status the server sent."""
    @property
    def body(self) -> memoryview:
        """A read-only memoryview of the body, alive as long as it is."""
    def header(self, name: str | bytes, /) -> str | None:
        """Looks up a header of the response by its case-insensitive name.

        Args:
          name (str | bytes): The header name, such as "Content-Type".

        Returns:
          str | None: The value as sent, or None when the response has no such header.

        Example:
          >>> response.header("content-type")
          'application/json'
        """
    def __buffer__(self, flags: int, /) -> memoryview: ...

class Completed:
    """The final result of one accepted client call, from `Client.take_completed`.

    `status` is `Status.SUCCESS` once any response arrived, whatever its HTTP status, and the
    failure otherwise, such as `Status.TIMEOUT`, with `response` None.

    Example:
      >>> client.submit("GET", "http://127.0.0.1:8545/health", context="health")
      >>> for completed in client.take_completed(timeout_us=1_000_000):
      ...     print(completed.context, completed.status.name)
      health SUCCESS
    """

    @property
    def context(self) -> Any:
        """The `context` given to `submit`."""
    @property
    def status(self) -> Status:
        """The final `Status` of the exchange."""
    @property
    def message(self) -> str | None:
        """The detail of a failure, or None."""
    @property
    def response(self) -> Response | None:
        """The `Response`, or None on failure."""

class Client:
    """An HTTP client that belongs to the thread creating it, which alone may submit and poll.

    Args:
      connections (int): Connections open at once, across every server it calls.
      pipelined_calls (int, optional): Calls one connection carries at once; 0 means one.
      calls (int, optional): Calls accepted at once, retrieved or not; 0 means `connections`
        times `pipelined_calls`.
      connect_timeout_us (int, optional): The budget to connect, in microseconds; 0 means 5 s.
      request_timeout_us (int, optional): The budget of a whole exchange, in microseconds;
        0 means 30 s.
      private_key (bytes, optional): The 32-byte Noise identity, required to call over Noise.
      peer_authorizer (Callable[[bytes], bool], optional): Admits a Noise server by its 32-byte
        static key, required to call under `Security.NOISE_XX`.
      backend (Backend, optional): The I/O implementation. Defaults to `Backend.AUTOMATIC`.
      cpu_class (CPUClass, optional): The CPU kernels. Defaults to `CPUClass.AUTOMATIC`.

    Raises:
      TypeError: A missing `connections`, or an argument of the wrong type.
      Error: The backend cannot start.

    Example:
      >>> client = ucall.Client(connections=4, pipelined_calls=16)
      >>> client.get("http://127.0.0.1:8545/health").status_code
      200
    """

    def __new__(
        cls,
        *,
        connections: int,
        pipelined_calls: int = 0,
        calls: int = 0,
        connect_timeout_us: int = 0,
        request_timeout_us: int = 0,
        private_key: bytes | None = None,
        peer_authorizer: Callable[[bytes], bool] | None = None,
        backend: Backend | str = Backend.AUTOMATIC,
        cpu_class: CPUClass | str = CPUClass.AUTOMATIC,
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
        server_key: bytes | None = None,
        client_key: bytes | None = None,
        timeout_us: int = 0,
        max_retries: int = 0,
        max_redirects: int = 0,
    ) -> Response:
        """Sends one exchange and waits for its response on this thread.

        It polls in slices of 100 ms, checking for signals between them, and keeps every other
        call it finishes meanwhile for the next `take_completed`.

        Args:
          verb (Verb): The method, such as `Verb.POST` or "post".
          url (str | bytes): The full URL, "http://" or "http+noise://" and the server.
          body (Buffer, optional): Any bytes-like object to send.
          json (object, optional): A value to send as JSON in place of `body`, with its content
            type; None sends `body`.
          headers (Sequence[str | bytes], optional): "name: value" lines.
          security (Security, optional): The handshake for this call. Defaults to `Security.NONE`.
          server_key (bytes, optional): The server's 32-byte static key, for `Security.NOISE_IK`
            and `Security.NOISE_KK`.
          client_key (bytes, optional): This call's 32-byte Noise private key in place of the
            client's own, as `Security.NOISE_KK` names the caller to the server.
          timeout_us (int, optional): The budget of this call, queueing and redirects included;
            0 takes the client's `request_timeout_us`.
          max_retries (int, optional): Connection attempts before sending; 0 takes 3.
          max_redirects (int, optional): Redirect hops followed before failing; 0 takes 5.

        Returns:
          Response: The response, whatever its HTTP status.

        Raises:
          Error: The exchange failed, such as `Status.CONNECTION_FAILED` or `Status.TIMEOUT`.
          KeyboardInterrupt: Ctrl+C arrived while waiting; the call completes later, unclaimed.

        Example:
          >>> response = client.request("POST", "http://127.0.0.1:8545/sum", json={"a": 1, "b": 2})
          >>> response.status_code
          200
        """
    def get(
        self,
        url: str | bytes,
        /,
        *,
        body: Buffer = b"",
        json: object = None,
        headers: Sequence[str | bytes] = (),
        security: Security | str = Security.NONE,
        server_key: bytes | None = None,
        client_key: bytes | None = None,
        timeout_us: int = 0,
        max_retries: int = 0,
        max_redirects: int = 0,
    ) -> Response:
        """Sends a GET and waits for its response, as `request` does.

        Args:
          url (str | bytes): The full URL.
          **options: `body`, `json`, `headers`, `security`, the keys and limits, as `request` takes them.

        Returns:
          Response: The response, whatever its HTTP status.

        Raises:
          Error: The exchange failed.

        Example:
          >>> bytes(client.get("http://127.0.0.1:8545/sum?a=1&b=2").body)
          b'3'
        """
    def post(
        self,
        url: str | bytes,
        /,
        body: Buffer = b"",
        *,
        json: object = None,
        headers: Sequence[str | bytes] = (),
        security: Security | str = Security.NONE,
        server_key: bytes | None = None,
        client_key: bytes | None = None,
        timeout_us: int = 0,
        max_retries: int = 0,
        max_redirects: int = 0,
    ) -> Response:
        """Sends a POST and waits for its response, as `request` does.

        Args:
          url (str | bytes): The full URL.
          body (Buffer, optional): Any bytes-like object to send.
          **options: `json`, `headers`, `security`, the keys and limits, as `request` takes them.

        Returns:
          Response: The response, whatever its HTTP status.

        Raises:
          Error: The exchange failed.

        Example:
          >>> bytes(client.post("http://127.0.0.1:8545/sum", json={"a": 1, "b": 2}).body)
          b'3.0'
        """
    def put(
        self,
        url: str | bytes,
        /,
        body: Buffer = b"",
        *,
        json: object = None,
        headers: Sequence[str | bytes] = (),
        security: Security | str = Security.NONE,
        server_key: bytes | None = None,
        client_key: bytes | None = None,
        timeout_us: int = 0,
        max_retries: int = 0,
        max_redirects: int = 0,
    ) -> Response:
        """Sends a PUT and waits for its response, as `request` does.

        Args:
          url (str | bytes): The full URL.
          body (Buffer, optional): Any bytes-like object to send.
          **options: `json`, `headers`, `security`, the keys and limits, as `request` takes them.

        Returns:
          Response: The response, whatever its HTTP status.

        Raises:
          Error: The exchange failed.

        Example:
          >>> client.put("http://127.0.0.1:8545/files/notes.txt", b"hello").status_code
          200
        """
    def delete(
        self,
        url: str | bytes,
        /,
        *,
        body: Buffer = b"",
        json: object = None,
        headers: Sequence[str | bytes] = (),
        security: Security | str = Security.NONE,
        server_key: bytes | None = None,
        client_key: bytes | None = None,
        timeout_us: int = 0,
        max_retries: int = 0,
        max_redirects: int = 0,
    ) -> Response:
        """Sends a DELETE and waits for its response, as `request` does.

        Args:
          url (str | bytes): The full URL.
          **options: `body`, `json`, `headers`, `security`, the keys and limits, as `request` takes them.

        Returns:
          Response: The response, whatever its HTTP status.

        Raises:
          Error: The exchange failed.

        Example:
          >>> client.delete("http://127.0.0.1:8545/files/notes.txt").status_code
          204
        """
    def patch(
        self,
        url: str | bytes,
        /,
        body: Buffer = b"",
        *,
        json: object = None,
        headers: Sequence[str | bytes] = (),
        security: Security | str = Security.NONE,
        server_key: bytes | None = None,
        client_key: bytes | None = None,
        timeout_us: int = 0,
        max_retries: int = 0,
        max_redirects: int = 0,
    ) -> Response:
        """Sends a PATCH and waits for its response, as `request` does.

        Args:
          url (str | bytes): The full URL.
          body (Buffer, optional): Any bytes-like object to send.
          **options: `json`, `headers`, `security`, the keys and limits, as `request` takes them.

        Returns:
          Response: The response, whatever its HTTP status.

        Raises:
          Error: The exchange failed.

        Example:
          >>> client.patch("http://127.0.0.1:8545/users/ada", json={"alias": "countess"}).status_code
          200
        """
    def submit(
        self,
        verb: Verb | str,
        url: str | bytes,
        /,
        body: Buffer = b"",
        headers: Sequence[str | bytes] = (),
        *,
        security: Security | str = Security.NONE,
        server_key: bytes | None = None,
        client_key: bytes | None = None,
        timeout_us: int = 0,
        max_retries: int = 0,
        max_redirects: int = 0,
        context: object = None,
    ) -> None:
        """Queues one exchange without driving I/O.

        `take_completed` later returns exactly one `Completed` carrying `context`.

        Args:
          verb (Verb): The method, such as `Verb.POST` or "post".
          url (str | bytes): The full URL, "http://" or "http+noise://" and the server.
          body (Buffer, optional): Any bytes-like object, borrowed until the call completes.
          headers (Sequence[str | bytes], optional): "name: value" lines; the client adds Host,
            Content-Length and User-Agent itself.
          security (Security, optional): The handshake for this call. Defaults to `Security.NONE`,
            and an "http+noise://" URL calls over Noise XX.
          server_key (bytes, optional): The server's 32-byte static key, required for
            `Security.NOISE_IK` and `Security.NOISE_KK`.
          client_key (bytes, optional): This call's 32-byte Noise private key in place of the
            client's own, as `Security.NOISE_KK` names the caller to the server.
          timeout_us (int, optional): The budget of this call, queueing and redirects included;
            0 takes the client's `request_timeout_us`.
          max_retries (int, optional): Connection attempts before sending; 0 takes 3.
          max_redirects (int, optional): Redirect hops followed before failing; 0 takes 5.
          context (object, optional): Anything, handed back as `Completed.context`.

        Raises:
          Error: The call was refused and will not complete, such as `Status.CONTENDED` once
            `calls` are in flight, or `Status.INVALID_ARGUMENT` from another thread.

        Example:
          >>> for index in range(4):
          ...     client.submit("POST", "http://127.0.0.1:8545/echo", b"payload", context=index)
        """
    def take_completed(self, timeout_us: int = 0, capacity: int = 64) -> list[Completed]:
        """Drives the client's I/O on this thread and returns the calls that finished.

        Completions a blocking call retrieved for other calls come first, without driving any I/O.

        Args:
          timeout_us (int, optional): The longest wait for the first, in microseconds; 0 polls once.
          capacity (int, optional): The most to return. Defaults to 64.

        Returns:
          list[Completed]: The finished calls in the order they finished, maybe none.

        Raises:
          Error: An I/O failure, or `Status.INVALID_ARGUMENT` from another thread.

        Example:
          >>> finished = []
          >>> while len(finished) != 4:
          ...     finished += client.take_completed(timeout_us=1_000_000)
        """
