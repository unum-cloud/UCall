"""Native HTTP and Noise networking with caller-owned polling and request batching, bound over its C ABI.

UCall serves and calls HTTP over plaintext or Noise, with synchronous handlers run on the threads
the application polls with. This package binds the whole C interface: servers with their routes,
batch endpoints and replies, clients with their calls and responses, and the shared vocabulary.

The library is reached by `dlopen`, so a consumer builds with no linker flags at all:

```mojo
from ucall import HTTPStatus, Interface, Library, Request, Server

def echo(request: Request) raises:
    request.reply(HTTPStatus.OK, request.body())

def main() raises:
    var server = Server(Library(), [Interface("127.0.0.1:8545")])
    server.post["/echo", echo]()
    server.take_calls(0)
```

Handlers are compile-time parameters of their routes, run on the thread polling the event loop,
and own each request they receive. This package root re-exports every public symbol from
the modules that mirror the C headers, so `from ucall import X` resolves whatever module X lives in.

File: mojo/ucall/__init__.mojo
Author: Ash Vardanian
Date: November 8, 2026
"""

from ucall.client import (
    Client,
    ClientCall,
    ClientCallOptions,
    ClientOptions,
    Completed,
    Response,
)
from ucall.library import Library
from ucall.server import (
    Batch,
    BatchEndpoint,
    BatchEndpointStatistics,
    Batching,
    DetachedRequest,
    EventLoopStatistics,
    FileRange,
    Interface,
    Metrics,
    Peer,
    Polling,
    ReplyPart,
    ReplyStream,
    Request,
    RequestPart,
    RequestReads,
    Server,
    ServerOptions,
)
from ucall.types import (
    AddressFamily,
    Backend,
    BodyDelivery,
    BytesView,
    CPUClass,
    Deferred,
    Error,
    HTTPStatus,
    Log,
    LogFormat,
    LogLevel,
    NoiseKey,
    PeerAddress,
    PeerAuthorizer,
    PercentMode,
    Security,
    Status,
    Verb,
)
