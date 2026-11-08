"""The HTTP server: interfaces, routes, batch endpoints, received requests and their replies.

A server has no pull model: `take_call` runs one round of an event loop on the calling thread and
invokes the handlers of the requests it completes there. Mojo cannot hand C a capturing closure,
so every handler is a compile-time parameter of its route, and one `thin abi("C")` trampoline is
instantiated per handler. The context the library passes back addresses the `Server`, which is
not `Movable`, so that address holds for as long as the server does.

A `Request` is owned by its handler, and its body is a `Span` whose origin is the request. Its
replies and `detach` consume it, and one dropped without them answers 500, which covers a handler
that raised. `detach` hands the request to a `DetachedRequest`, which may move to any thread and
gains the replies that may finish later.

File: mojo/ucall/server.mojo
Author: Ash Vardanian
Date: November 8, 2026
"""

from std.ffi import c_int, c_size_t
from std.memory import ArcPointer, OwnedPointer, stack_allocation

from ucall.library import Library
from ucall.types import (
    Address,
    Backend,
    BodyDelivery,
    BytesView,
    CPUClass,
    Deferred,
    Entry,
    Error,
    HTTPStatus,
    Log,
    NULL_ADDRESS,
    NoiseKey,
    Outcome,
    PeerAddress,
    PeerAuthorizer,
    Security,
    Status,
    Verb,
    _address_of,
    _cross,
)

# region Signatures

comptime RequestVerb = def(Address, Address) thin abi("C") -> c_int
"""`ucall_server_request_verb`: the method of a received request."""

comptime RequestCount = def(Address, Address) thin abi("C") -> c_size_t
"""`ucall_server_request_path_segments_count` and `ucall_server_request_parts_count`."""

comptime ServerInit = Entry[ServerInitArguments]
"""`ucall_server_init`."""
comptime ServerTakeCall = Entry[ServerTakeCallArguments]
"""`ucall_server_take_call`."""
comptime ServerTakeCalls = Entry[ServerTakeCallsArguments]
"""`ucall_server_take_calls`."""
comptime ServerEventLoopStatistics = Entry[ServerEventLoopStatisticsArguments]
"""`ucall_server_event_loop_statistics`."""
comptime ServerTakeBatch = Entry[ServerTakeBatchArguments]
"""`ucall_server_take_batch`."""
comptime ServerTakeBatches = Entry[ServerTakeBatchesArguments]
"""`ucall_server_take_batches`."""
comptime ServerBatchEndpointStatistics = Entry[ServerBatchEndpointStatisticsArguments]
"""`ucall_server_batch_endpoint_statistics`."""
comptime ServerAddHttpEndpoint = Entry[ServerAddHttpEndpointArguments]
"""`ucall_server_add_http_endpoint`."""
comptime ServerAddHttpBatchEndpoint = Entry[ServerAddHttpBatchEndpointArguments]
"""`ucall_server_add_http_batch_endpoint`."""
comptime ServerRequestView = Entry[ServerRequestViewArguments]
"""`ucall_server_request_path`, `_query`, `_body` and `_body_chunk`, which share one layout."""
comptime ServerRequestPathSegment = Entry[ServerRequestPathSegmentArguments]
"""`ucall_server_request_path_segment`."""
comptime ServerRequestNamed = Entry[ServerRequestNamedArguments]
"""`ucall_server_request_path_parameter`, `_query_parameter` and `_header`, which share one layout."""
comptime ServerRequestFieldsCount = Entry[ServerRequestFieldsCountArguments]
"""`ucall_server_request_fields_count`."""
comptime ServerRequestField = Entry[ServerRequestFieldArguments]
"""`ucall_server_request_field`."""
comptime ServerRequestPeer = Entry[ServerRequestPeerArguments]
"""`ucall_server_request_peer`."""
comptime ServerRequestPart = Entry[ServerRequestPartArguments]
"""`ucall_server_request_part`."""
comptime ServerReplyContent = Entry[ServerReplyContentArguments]
"""`ucall_server_reply_content`."""
comptime ServerReplyError = Entry[ServerReplyErrorArguments]
"""`ucall_server_reply_error`."""
comptime ServerReplyVectored = Entry[ServerReplyVectoredArguments]
"""`ucall_server_reply_vectored`."""
comptime ServerReplyBegin = Entry[ServerReplyBeginArguments]
"""`ucall_server_reply_begin`."""
comptime ServerReplyAppend = Entry[ServerReplyAppendArguments]
"""`ucall_server_reply_append`."""
comptime ServerReplyEnd = Entry[ServerReplyEndArguments]
"""`ucall_server_reply_end`."""

# endregion Signatures

# region Arguments


@fieldwise_init
struct NetworkInterfaceArguments(ImplicitlyCopyable):
    """`ucall_network_interface_t`, laid out as the ABI declares it."""

    var address: BytesView[ImmUntrackedOrigin]
    var listen_descriptor: Optional[Pointer[Int, ImmUntrackedOrigin]]
    var device_name: BytesView[ImmUntrackedOrigin]
    var security: Security
    var noise_private_key: Optional[Pointer[NoiseKey, ImmUntrackedOrigin]]
    var noise_peer_key: Optional[Pointer[NoiseKey, ImmUntrackedOrigin]]
    var peer_authorizer: Address
    var peer_authorizer_context: Address
    var event_loops: c_size_t
    var max_concurrent_connections: c_size_t
    var max_pipelined_requests: c_size_t
    var max_request_bytes: c_size_t
    var reply_directories: Optional[Pointer[BytesView[ImmUntrackedOrigin], ImmUntrackedOrigin]]
    var reply_directories_count: c_size_t


@fieldwise_init
struct ServerOptionsArguments(ImplicitlyCopyable):
    """`ucall_server_options_t`, laid out as the ABI declares it."""

    var interfaces: Optional[Pointer[NetworkInterfaceArguments, ImmUntrackedOrigin]]
    var interfaces_count: c_size_t
    var log: Log
    var metrics_address: BytesView[ImmUntrackedOrigin]
    var metrics_sample_rate: Float32
    var metrics_prefix: BytesView[ImmUntrackedOrigin]
    var metrics_tags: Optional[Pointer[BytesView[ImmUntrackedOrigin], ImmUntrackedOrigin]]
    var metrics_tags_count: c_size_t
    var metrics_interval_microseconds: c_size_t
    var backend: Backend
    var cpu_class: CPUClass


@fieldwise_init
struct ServerInitArguments(ImplicitlyCopyable):
    """`ucall_server_init_t`, laid out as the ABI declares it."""

    var server: Pointer[Address, MutUntrackedOrigin]
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var options: Pointer[ServerOptionsArguments, ImmUntrackedOrigin]
    var resolved: Pointer[ServerOptionsArguments, MutUntrackedOrigin]


@fieldwise_init
struct ServerTakeCallArguments(ImplicitlyCopyable):
    """`ucall_server_take_call_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var event_loop_index: c_size_t
    var timeout_microseconds: c_size_t


@fieldwise_init
struct ServerTakeCallsArguments(ImplicitlyCopyable):
    """`ucall_server_take_calls_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var event_loop_index: c_size_t


@fieldwise_init
struct ServerEventLoopStatisticsArguments(ImplicitlyCopyable):
    """`ucall_server_event_loop_statistics_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var event_loop_index: c_size_t
    var statistics: Pointer[EventLoopStatistics, MutUntrackedOrigin]


@fieldwise_init
struct ServerTakeBatchArguments(ImplicitlyCopyable):
    """`ucall_server_take_batch_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var endpoint: Address
    var timeout_microseconds: c_size_t


@fieldwise_init
struct ServerTakeBatchesArguments(ImplicitlyCopyable):
    """`ucall_server_take_batches_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var endpoint: Address


@fieldwise_init
struct ServerBatchEndpointStatisticsArguments(ImplicitlyCopyable):
    """`ucall_server_batch_endpoint_statistics_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var endpoint: Address
    var statistics: Pointer[BatchEndpointStatistics, MutUntrackedOrigin]


@fieldwise_init
struct ServerAddHttpEndpointArguments(ImplicitlyCopyable):
    """`ucall_server_add_http_endpoint_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var uri_template: BytesView[ImmUntrackedOrigin]
    var verb: Verb
    var callback: Address
    var context: Address
    var body_delivery: BodyDelivery


@fieldwise_init
struct ServerAddHttpBatchEndpointArguments(ImplicitlyCopyable):
    """`ucall_server_add_http_batch_endpoint_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var uri_template: BytesView[ImmUntrackedOrigin]
    var verb: Verb
    var callback: Address
    var context: Address
    var min_batch_size: c_size_t
    var max_batch_size: c_size_t
    var max_latency_microseconds: c_size_t
    var endpoint: Pointer[Address, MutUntrackedOrigin]


@fieldwise_init
struct ServerRequestViewArguments(ImplicitlyCopyable):
    """`ucall_server_request_path_t`, `_query_t`, `_body_t` and `_body_chunk_t`, laid out alike."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var request: Address
    var view: Pointer[BytesView[ImmUntrackedOrigin], MutUntrackedOrigin]


@fieldwise_init
struct ServerRequestPathSegmentArguments(ImplicitlyCopyable):
    """`ucall_server_request_path_segment_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var request: Address
    var index: c_size_t
    var segment: Pointer[BytesView[ImmUntrackedOrigin], MutUntrackedOrigin]


@fieldwise_init
struct ServerRequestNamedArguments(ImplicitlyCopyable):
    """`ucall_server_request_path_parameter_t`, `_query_parameter_t` and `_header_t`, laid out alike."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var request: Address
    var name: BytesView[ImmUntrackedOrigin]
    var value: Pointer[BytesView[ImmUntrackedOrigin], MutUntrackedOrigin]


@fieldwise_init
struct ServerRequestFieldsCountArguments(ImplicitlyCopyable):
    """`ucall_server_request_fields_count_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var request: Address
    var count: Pointer[c_size_t, MutUntrackedOrigin]


@fieldwise_init
struct ServerRequestFieldArguments(ImplicitlyCopyable):
    """`ucall_server_request_field_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var request: Address
    var index: c_size_t
    var name: Pointer[BytesView[ImmUntrackedOrigin], MutUntrackedOrigin]
    var value: Pointer[BytesView[ImmUntrackedOrigin], MutUntrackedOrigin]


@fieldwise_init
struct ServerRequestPeerArguments(ImplicitlyCopyable):
    """`ucall_server_request_peer_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var request: Address
    var network_interface_index: Pointer[c_size_t, MutUntrackedOrigin]
    var static_key: Pointer[NoiseKey, MutUntrackedOrigin]
    var address: Pointer[PeerAddress, MutUntrackedOrigin]


@fieldwise_init
struct ServerRequestPartArguments(ImplicitlyCopyable):
    """`ucall_server_request_part_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var request: Address
    var index: c_size_t
    var name: Pointer[BytesView[ImmUntrackedOrigin], MutUntrackedOrigin]
    var content_type: Pointer[BytesView[ImmUntrackedOrigin], MutUntrackedOrigin]
    var data: Pointer[BytesView[ImmUntrackedOrigin], MutUntrackedOrigin]


@fieldwise_init
struct ServerReplyContentArguments(ImplicitlyCopyable):
    """`ucall_server_reply_content_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var request: Address
    var http_status: HTTPStatus
    var headers: Optional[Pointer[BytesView[ImmUntrackedOrigin], ImmUntrackedOrigin]]
    var headers_count: c_size_t
    var body: BytesView[ImmUntrackedOrigin]


@fieldwise_init
struct ServerReplyErrorArguments(ImplicitlyCopyable):
    """`ucall_server_reply_error_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var request: Address
    var http_status: HTTPStatus
    var message: BytesView[ImmUntrackedOrigin]


@fieldwise_init
struct ServerReplyVectoredArguments(ImplicitlyCopyable):
    """`ucall_server_reply_vectored_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var request: Address
    var http_status: HTTPStatus
    var headers: Optional[Pointer[BytesView[ImmUntrackedOrigin], ImmUntrackedOrigin]]
    var headers_count: c_size_t
    var parts: Optional[Pointer[ReplyPart[ImmUntrackedOrigin], ImmUntrackedOrigin]]
    var parts_count: c_size_t


@fieldwise_init
struct ServerReplyBeginArguments(ImplicitlyCopyable):
    """`ucall_server_reply_begin_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var request: Address
    var http_status: HTTPStatus
    var headers: Optional[Pointer[BytesView[ImmUntrackedOrigin], ImmUntrackedOrigin]]
    var headers_count: c_size_t


@fieldwise_init
struct ServerReplyAppendArguments(ImplicitlyCopyable):
    """`ucall_server_reply_append_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var request: Address
    var parts: Optional[Pointer[ReplyPart[ImmUntrackedOrigin], ImmUntrackedOrigin]]
    var parts_count: c_size_t


@fieldwise_init
struct ServerReplyEndArguments(ImplicitlyCopyable):
    """`ucall_server_reply_end_t`, laid out as the ABI declares it."""

    var server: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var request: Address


def _lend[T: Copyable](ref value: Optional[T]) -> Optional[Pointer[T, ImmUntrackedOrigin]]:
    """The address of an optional value the caller keeps alive, or `None` for the null the ABI takes."""
    if value:
        return Pointer[T, ImmUntrackedOrigin](unsafe_from_address=Int(Pointer(to=value.value())))
    return None


def _array[T: Copyable](ref items: List[T]) -> Optional[Pointer[T, ImmUntrackedOrigin]]:
    """The first element of an array the caller keeps alive, or `None` for an empty one."""
    if len(items) == 0:
        return None
    return Pointer[T, ImmUntrackedOrigin](unsafe_from_address=Int(items.unsafe_ptr()))


def _headers[
    origin: ImmOrigin
](headers: Span[BytesView[origin], _]) -> Optional[Pointer[BytesView[ImmUntrackedOrigin], ImmUntrackedOrigin]]:
    """The header lines as the ABI's array, their borrow erased inside the verb that crosses."""
    if len(headers) == 0:
        return None
    return Pointer[BytesView[ImmUntrackedOrigin], ImmUntrackedOrigin](unsafe_from_address=Int(headers.unsafe_ptr()))


def _parts[
    origin: ImmOrigin
](parts: Span[ReplyPart[origin], _]) -> Optional[Pointer[ReplyPart[ImmUntrackedOrigin], ImmUntrackedOrigin]]:
    """The reply parts as the ABI's array, their borrow erased inside the verb that crosses."""
    if len(parts) == 0:
        return None
    return Pointer[ReplyPart[ImmUntrackedOrigin], ImmUntrackedOrigin](unsafe_from_address=Int(parts.unsafe_ptr()))


# endregion Arguments

# region Configuration


@fieldwise_init
struct Interface(Copyable, Movable):
    """One address the server answers on, with the security and admission limits of what arrives there.

    Several live under one server, so it may answer plaintext on loopback and Noise on the wire at once.
    """

    var address: String
    """Listening address in "host:port" form; port zero picks a free one, which `Server.address` reports."""
    var listen_descriptor: Optional[Int]
    """A listening stream socket another owner opened, accepted on instead of binding `address`."""
    var device_name: String
    """A physical device to pin the interface to, like "eth0", on Linux only; empty binds by address."""
    var security: Security
    """Encryption for connections accepted here; `NOISE_XX` also needs `peer_authorizer`."""
    var noise_private_key: Optional[NoiseKey]
    """The server identity for handshakes, required unless `security` is `NONE`."""
    var noise_peer_key: Optional[NoiseKey]
    """The one initiator's static public key a `NOISE_KK` interface admits."""
    var peer_authorizer: PeerAuthorizer
    """Vets each client's authenticated static key before any of its requests is read."""
    var event_loops: Int
    """Event loops accepting here; zero means one, or the receive-queue count of a named device."""
    var connections: Int
    """Connections open at once across this interface's loops."""
    var pipelined_requests: Int
    """Requests one connection may have in flight before the server stops reading it; zero means one."""
    var max_request_bytes: Int
    """The largest request head and buffered body; zero takes the largest socket receive buffer."""
    var reply_directories: List[String]
    """Directories the path parts of replies to this interface's requests resolve beneath, by position."""

    def __init__(out self, address: String, *, connections: Int = 1024, event_loops: Int = 0):
        """An interface listening on `address` with the default security and limits.

        Args:
            address: Where to listen, in "host:port" form.
            connections: Connections open at once.
            event_loops: Event loops accepting here; zero means one.
        """
        self.address = address
        self.listen_descriptor = None
        self.device_name = String()
        self.security = Security.NONE
        self.noise_private_key = None
        self.noise_peer_key = None
        self.peer_authorizer = PeerAuthorizer()
        self.event_loops = event_loops
        self.connections = connections
        self.pipelined_requests = 0
        self.max_request_bytes = 0
        self.reply_directories = List[String]()


@fieldwise_init
struct Metrics(Copyable, Defaultable, Movable):
    """The StatsD endpoint a server sends each event loop's counters and sampled latencies to."""

    var address: String
    """The endpoint in "host:port" form; empty sends nothing."""
    var sample_rate: Float32
    """The fraction of finished requests whose latency is reported, in (0, 1]; zero means 1."""
    var prefix: String
    """The metric name prefix; empty means "ucall"."""
    var tags: List[String]
    """Tags on every metric, each "key:value"."""
    var interval_microseconds: Int
    """The time between one event loop's datagrams; zero means one second."""

    def __init__(out self):
        """No endpoint, so no datagram leaves."""
        self = Self(String(), 0, String(), List[String](), 0)


@fieldwise_init
struct ServerOptions(Copyable, Defaultable, Movable):
    """What a server runs on and reports through, beside its interfaces."""

    var backend: Backend
    """The requested I/O backend, failing rather than substituting when it is unavailable."""
    var cpu_class: CPUClass
    """A ceiling on the CPU class; `UNKNOWN` takes what the constructing thread's CPU offers."""
    var log: Log
    """Where log lines go; the default keeps the server silent."""
    var metrics: Metrics
    """Where StatsD datagrams go; the default sends none."""

    def __init__(out self):
        """The automatic backend and CPU class, silent and without metrics."""
        self = Self(Backend.AUTOMATIC, CPUClass.UNKNOWN, Log(), Metrics())


@fieldwise_init
struct Polling(Equatable, ImplicitlyCopyable, TrivialRegisterPassable):
    """What `Server.take_call` found of its event loop. Binding-only."""

    var code: c_int
    """Which of the two it is."""
    comptime SERVING = Self(0)
    """The loop serves, or drains what it holds after a stop."""
    comptime RETIRED = Self(1)
    """The loop drained or cut everything after `Server.stop`, so a caller polling in slices stops."""


@fieldwise_init
struct Batching(Defaultable, ImplicitlyCopyable, TrivialRegisterPassable):
    """When a batch endpoint hands its queue to the handler; zero fields take 1, 32 and 10 milliseconds."""

    var min_size: Int
    """Dispatch as soon as this many requests wait."""
    var max_size: Int
    """Never hand the handler more than this many requests at once."""
    var max_latency_microseconds: Int
    """Dispatch a smaller batch once its oldest request waited this long."""

    def __init__(out self):
        """Every default."""
        self = Self(0, 0, 0)


@fieldwise_init
struct EventLoopStatistics(Defaultable, ImplicitlyCopyable):
    """Counters of one event loop since the server started, `ucall_event_loop_statistics_t` in C.

    Divided by `requests`, they price one call. Each counter is read on its own, so a snapshot of a
    running loop is not one instant.
    """

    var polls: UInt64
    """Engine polls the loop issued, each taking zero or more completions."""
    var empty_polls: UInt64
    """Engine polls that took no completion."""
    var kernel_enters: UInt64
    """System calls: io_uring enters, or other backends' waits, registrations and socket calls."""
    var submissions: UInt64
    """Operations queued."""
    var completions: UInt64
    """Results taken."""
    var cancellations: UInt64
    """Pending operations, or io_uring multishot receives, the engine asked to cancel."""
    var accepts: UInt64
    """Connections accepted and handed to this loop."""
    var requests: UInt64
    """HTTP requests parsed and dispatched to an endpoint or an error reply."""
    var receive_rearms: UInt64
    """Multishot receives armed again on a socket that already streamed."""
    var bytes_received: UInt64
    """Bytes the kernel reported received, ciphertext under Noise."""
    var bytes_sent: UInt64
    """Bytes the kernel reported sent, ciphertext under Noise."""
    var bytes_copied: UInt64
    """Bytes UCall copied: receive appends, reply bodies, Noise records and parked receives."""
    var zero_copy_sends: UInt64
    """Sends that left without copying."""
    var zero_copy_fallbacks: UInt64
    """Zero-copy sends the kernel copied anyway or refused to pin."""
    var copying_sends: UInt64
    """Sends that copied instead of pinning."""
    var file_reads_asynchronous: UInt64
    """File reads the kernel finishes later."""
    var file_reads_blocking: UInt64
    """File reads the loop issued itself and blocked on."""
    var bytes_read: UInt64
    """Bytes the kernel reported read from files into the loop's file windows."""
    var file_window_overlaps: UInt64
    """File reads submitted while an earlier window of the same stream waited to send or sent."""
    var linger_resets: UInt64
    """Lingering closes reset at their deadline because the kernel still held what they sent."""
    var ready_passes: UInt64
    """Passes the loop made over a ready connection."""
    var replied_dequeues: UInt64
    """Replied exchanges the loop took from its queue to adopt their reply segments."""
    var refused_requests: UInt64
    """Requests the loop answered itself with 400, 404, 405, 413, 501, 503 or 505."""
    var handshake_failures: UInt64
    """Connections whose Noise handshake failed."""
    var authorizer_refusals: UInt64
    """Connections whose authenticated peer key the interface's authorizer refused."""

    def __init__(out self):
        """Every counter at zero, as a failed read leaves them."""
        self = Self(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)


@fieldwise_init
struct BatchEndpointStatistics(Defaultable, ImplicitlyCopyable):
    """Counters of one batch endpoint since registration, `ucall_batch_endpoint_statistics_t` in C."""

    var batches: UInt64
    """Batches handed to the handler."""
    var requests: UInt64
    """Requests across those batches."""
    var filled_batches: UInt64
    """Batches dispatched on reaching `Batching.max_size`."""
    var ready_batches: UInt64
    """Batches dispatched on reaching `Batching.min_size`, below the maximum."""
    var expired_batches: UInt64
    """Batches dispatched below `Batching.min_size` once `Batching.max_latency_microseconds` passed."""

    def __init__(out self):
        """Every counter at zero, as a failed read leaves them."""
        self = Self(0, 0, 0, 0, 0)


# endregion Configuration

# region Server


struct _ServerCore(Movable):
    """The library's server handle and its resolved configuration, shared by the `Server`, its batch
    endpoints and every detached request, so the last of them frees it."""

    var library: Library
    var handle: Address
    var resolved: ServerOptionsArguments

    def __init__(out self, library: Library, handle: Address, resolved: ServerOptionsArguments):
        self.library = library
        self.handle = handle
        self.resolved = resolved

    def __deinit__(deinit self):
        """Frees the server. Calls `ucall_server_free`.

        The loader reference is surrendered only after the call, so Mojo cannot unmap the library
        between loading the entry point and branching to it.
        """
        self.library.symbols().server_free(self.handle)
        _ = self.library^


def _outcome_in[origin: MutOrigin](slot: Pointer[Outcome, origin]) -> Pointer[Outcome, MutAnyOrigin]:
    """Zeroes an outcome slot the caller allocated, as a callee's `alloca` dies with its frame."""
    var outcome = slot.unsafe_origin_cast[MutAnyOrigin]()
    outcome[unsafe_offset=0] = Outcome()
    return outcome


def _view_in[
    origin: MutOrigin
](slot: Pointer[BytesView[ImmUntrackedOrigin], origin]) -> Pointer[BytesView[ImmUntrackedOrigin], MutAnyOrigin]:
    """Empties a byte-view slot the caller allocated, for the library to overwrite."""
    var view = slot.unsafe_origin_cast[MutAnyOrigin]()
    view[unsafe_offset=0] = BytesView.empty()
    return view


def _route_trampoline[
    handler: def(var Request) thin raises -> None
](request: Address, context: Pointer[Server, MutAnyOrigin]) abi("C"):
    """The `ucall_received_http_request_callback_t` of one route, instantiated per handler.

    The handler owns the request, so one it raised past or left unreplied answers 500 as it drops.
    """
    try:
        handler(Request(Pointer[Server, ImmUntrackedOrigin](unsafe_from_address=Int(context)), request))
    except:
        pass


def _answer_internal(core: _ServerCore, request: Address, message: StringSlice):
    """Answers 500 with `message` for a request its handler left unreplied, consuming it."""
    var outcome = _outcome_in(stack_allocation[1, Outcome]())
    _cross(
        ServerReplyErrorArguments(
            core.handle,
            outcome.unsafe_origin_cast[MutUntrackedOrigin](),
            request,
            HTTPStatus.INTERNAL_ERROR,
            BytesView.of(message).arguments(),
        ),
        core.library.symbols().server_reply_error,
    )


struct Server:
    """An HTTP server over one or more interfaces, polled by application threads.

    Register every endpoint first, then poll each event loop from one thread at a time. Not
    `Movable`, as every route hands the library this server's address. Dropping it stops the server;
    the library frees it once the last batch endpoint and detached request are gone too.
    """

    var shared: ArcPointer[_ServerCore]
    """The handle, shared with batch endpoints and detached requests."""
    var _event_loops: Int
    """The largest event-loop count among the resolved interfaces."""

    def __init__(
        out self, library: Library, interfaces: Span[Interface, _], options: ServerOptions = ServerOptions()
    ) raises Error:
        """Starts a server answering on `interfaces`. Calls `ucall_server_init`.

        Args:
            library: The loaded library, kept so the shared object stays mapped.
            interfaces: At least one interface; their addresses, keys and directories are copied.
            options: The backend, CPU class, log sink and StatsD endpoint.

        Raises:
            `Error` if an interface is unusable, no backend serves the configuration, or an address
            cannot be bound.
        """
        var directories = List[List[BytesView[ImmUntrackedOrigin]]](capacity=len(interfaces))
        for ref interface in interfaces:
            var views = List[BytesView[ImmUntrackedOrigin]](capacity=len(interface.reply_directories))
            for ref path in interface.reply_directories:
                views.append(BytesView.of(StringSlice(path)).arguments())
            directories.append(views^)
        var raw = List[NetworkInterfaceArguments](capacity=len(interfaces))
        for index in range(len(interfaces)):
            ref interface = interfaces[index]
            raw.append(
                NetworkInterfaceArguments(
                    BytesView.of(StringSlice(interface.address)).arguments(),
                    _lend(interface.listen_descriptor),
                    BytesView.of(StringSlice(interface.device_name)).arguments(),
                    interface.security,
                    _lend(interface.noise_private_key),
                    _lend(interface.noise_peer_key),
                    interface.peer_authorizer.callback,
                    interface.peer_authorizer.context,
                    c_size_t(interface.event_loops),
                    c_size_t(interface.connections),
                    c_size_t(interface.pipelined_requests),
                    c_size_t(interface.max_request_bytes),
                    _array(directories[index]),
                    c_size_t(len(directories[index])),
                )
            )
        var tags = List[BytesView[ImmUntrackedOrigin]](capacity=len(options.metrics.tags))
        for ref tag in options.metrics.tags:
            tags.append(BytesView.of(StringSlice(tag)).arguments())

        var config = stack_allocation[2, ServerOptionsArguments]().unsafe_origin_cast[MutAnyOrigin]()
        config[unsafe_offset=0] = ServerOptionsArguments(
            _array(raw),
            c_size_t(len(raw)),
            options.log,
            BytesView.of(StringSlice(options.metrics.address)).arguments(),
            options.metrics.sample_rate,
            BytesView.of(StringSlice(options.metrics.prefix)).arguments(),
            _array(tags),
            c_size_t(len(tags)),
            c_size_t(options.metrics.interval_microseconds),
            options.backend,
            options.cpu_class,
        )
        config[unsafe_offset=1] = config[unsafe_offset=0]
        var created = stack_allocation[1, Address]().unsafe_origin_cast[MutAnyOrigin]()
        created[unsafe_offset=0] = NULL_ADDRESS
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerInitArguments(
                created.unsafe_origin_cast[MutUntrackedOrigin](),
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                Pointer[ServerOptionsArguments, ImmUntrackedOrigin](unsafe_from_address=Int(config)),
                config.unsafe_offset(1).unsafe_origin_cast[MutUntrackedOrigin](),
            ),
            library.symbols().server_init,
        )
        # Moved only after the call, as the library reads what they point at during it.
        _ = raw^
        _ = directories^
        _ = tags^
        var core = _ServerCore(library, created[unsafe_offset=0], config[unsafe_offset=1])
        library._check(outcome[unsafe_offset=0], "ucall_server_init")
        var event_loops = 0
        if case .Some(resolved) = core.resolved.interfaces:
            for index in range(Int(core.resolved.interfaces_count)):
                event_loops = max(event_loops, Int(resolved[unsafe_offset=index].event_loops))
        self.shared = ArcPointer(core^)
        self._event_loops = event_loops

    def __deinit__(deinit self):
        """Stops the server, which the library frees once nothing else holds it."""
        self.shared[].library.symbols().server_stop(self.shared[].handle)
        _ = self.shared^

    def event_loops(self) -> Int:
        """Event loops this server runs, each to be polled by one thread at a time. Binding-only."""
        return self._event_loops

    def backend(self) -> Backend:
        """The I/O backend the server resolved to. Binding-only."""
        return self.shared[].resolved.backend

    def cpu_class(self) -> CPUClass:
        """The CPU class the server resolved to. Binding-only."""
        return self.shared[].resolved.cpu_class

    def address(self, index: Int) -> Optional[String]:
        """The numeric address interface `index` listens on, with the port it bound. Binding-only.

        Args:
            index: The interface's position among those the server was started with.

        Returns:
            The bound address, or `None` past the last interface.
        """
        ref resolved = self.shared[].resolved
        if index >= Int(resolved.interfaces_count):
            return None
        if case .Some(interfaces) = resolved.interfaces:
            var address = interfaces[unsafe_offset=index].address
            return String(unsafe_from_utf8=address.span[ImmUntrackedOrigin]())
        return None

    def route[path: StaticString, handler: def(var Request) thin raises -> None](mut self, verb: Verb) raises Error:
        """Routes requests matching `path` and `verb` to `handler`, which runs on the polling thread.
        Calls `ucall_server_add_http_endpoint`.

        Templates capture `{name}` segments and a greedy `{*name}` tail, read back through
        `path_parameter`. A handler that raises, or leaves its request unreplied, answers 500.

        Parameters:
            path: The URI template.
            handler: Receives each matching request, owned from then on.

        Args:
            verb: The HTTP method, or `Verb.ANY`.

        Raises:
            `Error` with `ALREADY_EXISTS` for a template and verb registered before, or
            `INVALID_ARGUMENT` for a malformed template.
        """
        self.route_with[path, handler](verb, BodyDelivery.BUFFERED)

    def route_with[
        path: StaticString, handler: def(var Request) thin raises -> None
    ](mut self, verb: Verb, delivery: BodyDelivery) raises Error:
        """Routes like `route`, running `handler` once the body is buffered, or with `STREAMED` as
        soon as the headers arrived. Calls `ucall_server_add_http_endpoint`.

        Parameters:
            path: The URI template.
            handler: Receives each matching request, owned from then on.

        Args:
            verb: The HTTP method, or `Verb.ANY`.
            delivery: When the handler runs.

        Raises:
            `Error` as `route` does.
        """
        ref core = self.shared[]
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerAddHttpEndpointArguments(
                core.handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                BytesView.of(path).arguments(),
                verb,
                _address_of(_route_trampoline[handler]),
                Int(Pointer(to=self)),
                delivery,
            ),
            core.library.symbols().server_add_http_endpoint,
        )
        core.library._check(outcome[unsafe_offset=0], "ucall_server_add_http_endpoint")

    def get[path: StaticString, handler: def(var Request) thin raises -> None](mut self) raises Error:
        """Routes GET requests on `path` to `handler`. Calls `ucall_server_add_http_endpoint`."""
        self.route[path, handler](Verb.GET)

    def post[path: StaticString, handler: def(var Request) thin raises -> None](mut self) raises Error:
        """Routes POST requests on `path` to `handler`. Calls `ucall_server_add_http_endpoint`."""
        self.route[path, handler](Verb.POST)

    def put[path: StaticString, handler: def(var Request) thin raises -> None](mut self) raises Error:
        """Routes PUT requests on `path` to `handler`. Calls `ucall_server_add_http_endpoint`."""
        self.route[path, handler](Verb.PUT)

    def delete[path: StaticString, handler: def(var Request) thin raises -> None](mut self) raises Error:
        """Routes DELETE requests on `path` to `handler`. Calls `ucall_server_add_http_endpoint`."""
        self.route[path, handler](Verb.DELETE)

    def patch[path: StaticString, handler: def(var Request) thin raises -> None](mut self) raises Error:
        """Routes PATCH requests on `path` to `handler`. Calls `ucall_server_add_http_endpoint`."""
        self.route[path, handler](Verb.PATCH)

    def batch[
        path: StaticString, handler: def(Batch) thin raises -> None
    ](mut self, verb: Verb, batching: Batching = Batching()) raises Error -> BatchEndpoint:
        """Collects requests matching `path` and `verb` from every event loop into one queue, which
        the returned endpoint drains into `handler`. Calls `ucall_server_add_http_batch_endpoint`.

        Requests the handler does not take answer 500 once it returns.

        Parameters:
            path: The URI template.
            handler: Receives each due batch, lent for the call.

        Args:
            verb: The HTTP method, or `Verb.ANY`.
            batching: When a batch is due.

        Returns:
            The endpoint, polled by one thread at a time.

        Raises:
            `Error` as `route` does, or with `INVALID_ARGUMENT` for a minimum above the maximum.
        """
        ref core = self.shared[]
        var state = OwnedPointer(_BatchState(self.shared, List[Bool]()))
        var created = stack_allocation[1, Address]().unsafe_origin_cast[MutAnyOrigin]()
        created[unsafe_offset=0] = NULL_ADDRESS
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerAddHttpBatchEndpointArguments(
                core.handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                BytesView.of(path).arguments(),
                verb,
                _address_of(_batch_trampoline[handler]),
                Int(Pointer(to=state[])),
                c_size_t(batching.min_size),
                c_size_t(batching.max_size),
                c_size_t(batching.max_latency_microseconds),
                created.unsafe_origin_cast[MutUntrackedOrigin](),
            ),
            core.library.symbols().server_add_http_batch_endpoint,
        )
        core.library._check(outcome[unsafe_offset=0], "ucall_server_add_http_batch_endpoint")
        return BatchEndpoint(state^, created[unsafe_offset=0])

    def take_call(self, event_loop: Int, timeout_microseconds: Int = 0) raises Error -> Polling:
        """Advances one event loop, running the handlers of the requests it completes on this thread,
        and waits up to `timeout_microseconds` for progress. Calls `ucall_server_take_call`.

        Args:
            event_loop: The loop's index; each has one polling thread at a time.
            timeout_microseconds: The longest wait; zero performs one nonblocking round.

        Returns:
            `RETIRED` once the loop has nothing left to take after `stop`, `SERVING` otherwise.

        Raises:
            `Error` with `INVALID_ARGUMENT` past the last loop, or for an I/O failure.
        """
        ref core = self.shared[]
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerTakeCallArguments(
                core.handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                c_size_t(event_loop),
                c_size_t(timeout_microseconds),
            ),
            core.library.symbols().server_take_call,
        )
        if Status.of(outcome[unsafe_offset=0].status) == Status.CONNECTION_CLOSED:
            return Polling.RETIRED
        core.library._check(outcome[unsafe_offset=0], "ucall_server_take_call")
        return Polling.SERVING

    def take_calls(self, event_loop: Int) raises Error:
        """Drives one event loop on this thread until `stop` or an I/O failure. Calls `ucall_server_take_calls`.

        Args:
            event_loop: The loop's index; each has one polling thread at a time.

        Raises:
            `Error` with `INVALID_ARGUMENT` past the last loop, or for an I/O failure.
        """
        ref core = self.shared[]
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerTakeCallsArguments(core.handle, outcome.unsafe_origin_cast[MutUntrackedOrigin](), c_size_t(event_loop)),
            core.library.symbols().server_take_calls,
        )
        core.library._check(outcome[unsafe_offset=0], "ucall_server_take_calls")

    def stop(self):
        """Requests shutdown and wakes every polling thread, from any thread or handler. Calls `ucall_server_stop`.

        The first call drains the requests already held; a second one cuts the replies in flight.
        """
        self.shared[].library.symbols().server_stop(self.shared[].handle)

    def event_loop_statistics(self, event_loop: Int) raises Error -> EventLoopStatistics:
        """A snapshot of one event loop's counters, readable from any thread while it is polled.
        Calls `ucall_server_event_loop_statistics`.

        Args:
            event_loop: The loop's index.

        Returns:
            The counters since the server started.

        Raises:
            `Error` with `INVALID_ARGUMENT` past the last loop.
        """
        ref core = self.shared[]
        var statistics = stack_allocation[1, EventLoopStatistics]().unsafe_origin_cast[MutAnyOrigin]()
        statistics[unsafe_offset=0] = EventLoopStatistics()
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerEventLoopStatisticsArguments(
                core.handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                c_size_t(event_loop),
                statistics.unsafe_origin_cast[MutUntrackedOrigin](),
            ),
            core.library.symbols().server_event_loop_statistics,
        )
        core.library._check(outcome[unsafe_offset=0], "ucall_server_event_loop_statistics")
        return statistics[unsafe_offset=0]


# endregion Server

# region Batches


@fieldwise_init
struct _BatchState(Movable):
    """What a batch endpoint's trampoline reads: the server its requests retain, and which of the
    current batch's requests the handler took, grown once to the largest batch."""

    var shared: ArcPointer[_ServerCore]
    var taken: List[Bool]


def _batch_trampoline[
    handler: def(Batch) thin raises -> None
](requests: Pointer[Address, ImmUntrackedOrigin], count: c_size_t, context: Pointer[_BatchState, MutAnyOrigin]) abi("C"):
    """The `ucall_received_http_batch_callback_t` of one batch endpoint, instantiated per handler."""
    context[].taken.clear()
    context[].taken.resize(Int(count), False)
    var failure = Optional[String](None)
    try:
        handler(Batch(Int(context), requests, Int(count)))
    except error:
        failure = String(error)
    for index in range(Int(count)):
        if not context[].taken[index]:
            var message = failure.value() if failure else String("The request was dropped without a reply")
            _answer_internal(context[].shared[], requests[unsafe_offset=index], message)


struct Batch(Sized):
    """The requests of one due batch, from every event loop, lent to the handler in arrival order.

    Each request is taken at most once; whatever the handler leaves answers 500 once it returns.
    """

    var _state: Address
    """The endpoint's `_BatchState`, read for the server and the taken flags."""
    var _requests: Pointer[Address, ImmUntrackedOrigin]
    """The library's array of retained request handles, borrowed for the call."""
    var _count: Int
    """Requests in the batch."""

    def __init__(out self, state: Address, requests: Pointer[Address, ImmUntrackedOrigin], count: Int):
        self._state = state
        self._requests = requests
        self._count = count

    def __len__(self) -> Int:
        """Requests in the batch, taken or not."""
        return self._count

    def take(self, index: Int) raises Error -> DetachedRequest:
        """Takes request `index` out of the batch, to reply to it here or on another thread. Binding-only.

        Args:
            index: The request's position in arrival order.

        Returns:
            The request, owned from here on.

        Raises:
            `Error` with `INVALID_ARGUMENT` past the last request, or `ALREADY_EXISTS` once taken.
        """
        if index < 0 or index >= self._count:
            raise Error(Status.INVALID_ARGUMENT, "Batch.take")
        var state = Pointer[_BatchState, MutAnyOrigin](unsafe_from_address=self._state)
        if state[].taken[index]:
            raise Error(Status.ALREADY_EXISTS, "Batch.take")
        state[].taken[index] = True
        return DetachedRequest(state[].shared, self._requests[unsafe_offset=index])


struct BatchEndpoint(Movable):
    """One batch endpoint, polled by one thread at a time and observable from any.

    Requests from every event loop share its queue, so one thread drains what all of them received.
    """

    var _state: OwnedPointer[_BatchState]
    """What the trampoline reads, at the heap address the library was handed."""
    var _handle: Address
    """The `ucall_http_batch_endpoint_t`, alive until the server is freed."""

    def __init__(out self, var state: OwnedPointer[_BatchState], handle: Address):
        self._state = state^
        self._handle = handle

    def take_batch(self, timeout_microseconds: Int = 0) raises Error:
        """Runs the handler on this thread if a batch is due, waiting up to `timeout_microseconds` for one.
        Calls `ucall_server_take_batch`.

        Args:
            timeout_microseconds: The longest wait; zero performs one nonblocking round.

        Raises:
            `Error` if the library refuses the round.
        """
        ref core = self._state[].shared[]
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerTakeBatchArguments(
                core.handle, outcome.unsafe_origin_cast[MutUntrackedOrigin](), self._handle, c_size_t(timeout_microseconds)
            ),
            core.library.symbols().server_take_batch,
        )
        core.library._check(outcome[unsafe_offset=0], "ucall_server_take_batch")

    def take_batches(self) raises Error:
        """Runs the handler on this thread for every due batch until `Server.stop`.
        Calls `ucall_server_take_batches`.

        Raises:
            `Error` if the library refuses the polling.
        """
        ref core = self._state[].shared[]
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerTakeBatchesArguments(core.handle, outcome.unsafe_origin_cast[MutUntrackedOrigin](), self._handle),
            core.library.symbols().server_take_batches,
        )
        core.library._check(outcome[unsafe_offset=0], "ucall_server_take_batches")

    def statistics(self) raises Error -> BatchEndpointStatistics:
        """A snapshot of the endpoint's counters, readable from any thread while it is polled.
        Calls `ucall_server_batch_endpoint_statistics`.

        Returns:
            The counters since registration.

        Raises:
            `Error` if the library refuses the read.
        """
        ref core = self._state[].shared[]
        var statistics = stack_allocation[1, BatchEndpointStatistics]().unsafe_origin_cast[MutAnyOrigin]()
        statistics[unsafe_offset=0] = BatchEndpointStatistics()
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerBatchEndpointStatisticsArguments(
                core.handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                self._handle,
                statistics.unsafe_origin_cast[MutUntrackedOrigin](),
            ),
            core.library.symbols().server_batch_endpoint_statistics,
        )
        core.library._check(outcome[unsafe_offset=0], "ucall_server_batch_endpoint_statistics")
        return statistics[unsafe_offset=0]


# endregion Batches

# region Requests


@fieldwise_init
struct Peer(ImplicitlyCopyable):
    """Which interface a request arrived on, and who sent it."""

    var network_interface_index: Int
    """The position of its interface among those the server was started with."""
    var static_key: NoiseKey
    """The client's authenticated Noise static key, zeroed on plaintext interfaces."""
    var address: PeerAddress
    """The socket address the connection was accepted from."""


@fieldwise_init
struct RequestPart[origin: Origin](ImplicitlyCopyable):
    """One part of a `multipart/form-data` request body, borrowing the received bytes."""

    var name: Span[Byte, Self.origin]
    """The name its `Content-Disposition` gives."""
    var content_type: Span[Byte, Self.origin]
    """Its `Content-Type`, empty when absent."""
    var data: Span[Byte, Self.origin]
    """Its payload, undecoded."""


trait RequestReads:
    """The reads every received request offers, detached or not, each written once."""

    def _core(self) -> Pointer[_ServerCore, ImmUntrackedOrigin]:
        """The server the request belongs to."""
        ...

    def _raw(self) -> Address:
        """The retained `ucall_received_http_request_t`."""
        ...

    def _view(self, entry: ServerRequestView, symbol: StaticString) raises Error -> BytesView[ImmUntrackedOrigin]:
        """One of the views sharing `ServerRequestViewArguments`."""
        var core = self._core()
        var view = _view_in(stack_allocation[1, BytesView[ImmUntrackedOrigin]]())
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerRequestViewArguments(
                core[].handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                self._raw(),
                view.unsafe_origin_cast[MutUntrackedOrigin](),
            ),
            entry,
        )
        core[].library._check(outcome[unsafe_offset=0], symbol)
        return view[unsafe_offset=0]

    def _named(self, entry: ServerRequestNamed, name: StringSlice) -> Optional[BytesView[ImmUntrackedOrigin]]:
        """One of the lookups sharing `ServerRequestNamedArguments`, `None` when the name is absent."""
        var core = self._core()
        var value = _view_in(stack_allocation[1, BytesView[ImmUntrackedOrigin]]())
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerRequestNamedArguments(
                core[].handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                self._raw(),
                BytesView.of(name).arguments(),
                value.unsafe_origin_cast[MutUntrackedOrigin](),
            ),
            entry,
        )
        if outcome[unsafe_offset=0].status != c_int(0):
            return None
        return value[unsafe_offset=0]

    def verb(self) -> Verb:
        """The HTTP method, which tells apart the requests of a `Verb.ANY` endpoint.
        Calls `ucall_server_request_verb`."""
        var core = self._core()
        return Verb(core[].library.symbols().server_request_verb(core[].handle, self._raw()))

    def path(ref self) raises Error -> Span[Byte, ImmOrigin(origin_of(self))]:
        """The request path as sent, still percent-encoded, without the query. Calls `ucall_server_request_path`."""
        return self._view(self._core()[].library.symbols().server_request_path, "ucall_server_request_path").span[
            ImmOrigin(origin_of(self))
        ]()

    def query_string(ref self) raises Error -> Span[Byte, ImmOrigin(origin_of(self))]:
        """The query after the first '?', still percent-encoded, or empty without one.
        Calls `ucall_server_request_query`."""
        return self._view(self._core()[].library.symbols().server_request_query, "ucall_server_request_query").span[
            ImmOrigin(origin_of(self))
        ]()

    def body(ref self) raises Error -> Span[Byte, ImmOrigin(origin_of(self))]:
        """The buffered body, decoded from chunked framing if it arrived that way.
        Calls `ucall_server_request_body`.

        Raises:
            `Error` with `INVALID_ARGUMENT` on a streamed endpoint, whose body `body_chunk` pulls.
        """
        return self._view(self._core()[].library.symbols().server_request_body, "ucall_server_request_body").span[
            ImmOrigin(origin_of(self))
        ]()

    def path_parameter(ref self, name: StringSlice) -> Optional[Span[Byte, ImmOrigin(origin_of(self))]]:
        """The value the endpoint's template captured under `name`, case-sensitive.
        Calls `ucall_server_request_path_parameter`."""
        if case .Some(value) = self._named(self._core()[].library.symbols().server_request_path_parameter, name):
            return value.span[ImmOrigin(origin_of(self))]()
        return None

    def query(ref self, name: StringSlice) -> Optional[Span[Byte, ImmOrigin(origin_of(self))]]:
        """The value of query parameter `name`, case-sensitive and still percent-encoded.
        Calls `ucall_server_request_query_parameter`."""
        if case .Some(value) = self._named(self._core()[].library.symbols().server_request_query_parameter, name):
            return value.span[ImmOrigin(origin_of(self))]()
        return None

    def header(ref self, name: StringSlice) -> Optional[Span[Byte, ImmOrigin(origin_of(self))]]:
        """The value of header `name`, matched case-insensitively. Calls `ucall_server_request_header`."""
        if case .Some(value) = self._named(self._core()[].library.symbols().server_request_header, name):
            return value.span[ImmOrigin(origin_of(self))]()
        return None

    def fields_count(self) raises Error -> Int:
        """Header field lines in arrival order, repeated names included.
        Calls `ucall_server_request_fields_count`."""
        var core = self._core()
        var count = stack_allocation[1, c_size_t]().unsafe_origin_cast[MutAnyOrigin]()
        count[unsafe_offset=0] = c_size_t(0)
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerRequestFieldsCountArguments(
                core[].handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                self._raw(),
                count.unsafe_origin_cast[MutUntrackedOrigin](),
            ),
            core[].library.symbols().server_request_fields_count,
        )
        core[].library._check(outcome[unsafe_offset=0], "ucall_server_request_fields_count")
        return Int(count[unsafe_offset=0])

    def field(ref self, index: Int) raises Error -> Tuple[Span[Byte, ImmOrigin(origin_of(self))], Span[Byte, ImmOrigin(origin_of(self))]]:
        """Header field line `index`: its name, lowercased as the parser keeps it, and its trimmed value.
        Calls `ucall_server_request_field`.

        Raises:
            `Error` with `NOT_FOUND` past the last line.
        """
        var core = self._core()
        var name = _view_in(stack_allocation[1, BytesView[ImmUntrackedOrigin]]())
        var value = _view_in(stack_allocation[1, BytesView[ImmUntrackedOrigin]]())
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerRequestFieldArguments(
                core[].handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                self._raw(),
                c_size_t(index),
                name.unsafe_origin_cast[MutUntrackedOrigin](),
                value.unsafe_origin_cast[MutUntrackedOrigin](),
            ),
            core[].library.symbols().server_request_field,
        )
        core[].library._check(outcome[unsafe_offset=0], "ucall_server_request_field")
        return (name[unsafe_offset=0].span[ImmOrigin(origin_of(self))](), value[unsafe_offset=0].span[ImmOrigin(origin_of(self))]())

    def peer(self) raises Error -> Peer:
        """The interface the request arrived on, the sender's authenticated key and its socket address,
        readable after its connection closed. Calls `ucall_server_request_peer`."""
        var core = self._core()
        var index = stack_allocation[1, c_size_t]().unsafe_origin_cast[MutAnyOrigin]()
        index[unsafe_offset=0] = c_size_t(0)
        var key = stack_allocation[1, NoiseKey]().unsafe_origin_cast[MutAnyOrigin]()
        key[unsafe_offset=0] = NoiseKey(0)
        var address = stack_allocation[1, PeerAddress]().unsafe_origin_cast[MutAnyOrigin]()
        address[unsafe_offset=0] = PeerAddress()
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerRequestPeerArguments(
                core[].handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                self._raw(),
                index.unsafe_origin_cast[MutUntrackedOrigin](),
                key.unsafe_origin_cast[MutUntrackedOrigin](),
                address.unsafe_origin_cast[MutUntrackedOrigin](),
            ),
            core[].library.symbols().server_request_peer,
        )
        core[].library._check(outcome[unsafe_offset=0], "ucall_server_request_peer")
        return Peer(Int(index[unsafe_offset=0]), key[unsafe_offset=0], address[unsafe_offset=0])

    def path_segments_count(self) -> Int:
        """Path components in order, as sent. Calls `ucall_server_request_path_segments_count`."""
        var core = self._core()
        return Int(core[].library.symbols().server_request_path_segments_count(core[].handle, self._raw()))

    def path_segment(ref self, index: Int) -> Optional[Span[Byte, ImmOrigin(origin_of(self))]]:
        """Path component `index`, still percent-encoded, or `None` past the last one.
        Calls `ucall_server_request_path_segment`."""
        var core = self._core()
        var segment = _view_in(stack_allocation[1, BytesView[ImmUntrackedOrigin]]())
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerRequestPathSegmentArguments(
                core[].handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                self._raw(),
                c_size_t(index),
                segment.unsafe_origin_cast[MutUntrackedOrigin](),
            ),
            core[].library.symbols().server_request_path_segment,
        )
        if outcome[unsafe_offset=0].status != c_int(0):
            return None
        return segment[unsafe_offset=0].span[ImmOrigin(origin_of(self))]()

    def parts_count(self) -> Int:
        """Parts in a `multipart/form-data` body, zero for any other body.
        Calls `ucall_server_request_parts_count`."""
        var core = self._core()
        return Int(core[].library.symbols().server_request_parts_count(core[].handle, self._raw()))

    def part(ref self, index: Int) raises Error -> RequestPart[ImmOrigin(origin_of(self))]:
        """Part `index` of a `multipart/form-data` body, its payload undecoded. Calls `ucall_server_request_part`.

        Raises:
            `Error` with `INVALID_ARGUMENT` past the last part, or `MALFORMED` for a malformed body.
        """
        var core = self._core()
        var name = _view_in(stack_allocation[1, BytesView[ImmUntrackedOrigin]]())
        var content_type = _view_in(stack_allocation[1, BytesView[ImmUntrackedOrigin]]())
        var data = _view_in(stack_allocation[1, BytesView[ImmUntrackedOrigin]]())
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerRequestPartArguments(
                core[].handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                self._raw(),
                c_size_t(index),
                name.unsafe_origin_cast[MutUntrackedOrigin](),
                content_type.unsafe_origin_cast[MutUntrackedOrigin](),
                data.unsafe_origin_cast[MutUntrackedOrigin](),
            ),
            core[].library.symbols().server_request_part,
        )
        core[].library._check(outcome[unsafe_offset=0], "ucall_server_request_part")
        return RequestPart[ImmOrigin(origin_of(self))](
            name[unsafe_offset=0].span[ImmOrigin(origin_of(self))](),
            content_type[unsafe_offset=0].span[ImmOrigin(origin_of(self))](),
            data[unsafe_offset=0].span[ImmOrigin(origin_of(self))](),
        )


def _reply_content[
    origin: ImmOrigin
](core: _ServerCore, request: Address, status: HTTPStatus, headers: Span[BytesView[origin], _], body: Span[Byte, _]) -> Outcome:
    """Crosses `ucall_server_reply_content`, final on return."""
    var outcome = _outcome_in(stack_allocation[1, Outcome]())
    _cross(
        ServerReplyContentArguments(
            core.handle,
            outcome.unsafe_origin_cast[MutUntrackedOrigin](),
            request,
            status,
            _headers(headers),
            c_size_t(len(headers)),
            BytesView.of(body).arguments(),
        ),
        core.library.symbols().server_reply_content,
    )
    return outcome[unsafe_offset=0]


def _reply_error(core: _ServerCore, request: Address, status: HTTPStatus, message: StringSlice) -> Outcome:
    """Crosses `ucall_server_reply_error`, final on return."""
    var outcome = _outcome_in(stack_allocation[1, Outcome]())
    _cross(
        ServerReplyErrorArguments(
            core.handle,
            outcome.unsafe_origin_cast[MutUntrackedOrigin](),
            request,
            status,
            BytesView.of(message).arguments(),
        ),
        core.library.symbols().server_reply_error,
    )
    return outcome[unsafe_offset=0]


def _consumed(outcome: Outcome) -> Bool:
    """Whether a reply that is final on return consumed its request: success and a closed connection do."""
    var status = Status.of(outcome.status)
    return status == Status.SUCCESS or status == Status.CONNECTION_CLOSED


struct Request(Movable, RequestReads):
    """One received request, owned by its handler on the polling thread.

    `reply`, `reply_error` and `detach` consume it; one dropped without them answers 500. Reads
    borrow the received bytes with the request's origin.
    """

    var _server: Pointer[Server, ImmUntrackedOrigin]
    """The server whose route the request matched, alive while its loop is polled."""
    var _request: Address
    """The retained `ucall_received_http_request_t`."""

    def __init__(out self, server: Pointer[Server, ImmUntrackedOrigin], request: Address):
        self._server = server
        self._request = request

    def __deinit__(deinit self):
        """Answers 500 for a request no reply or detach consumed. Calls `ucall_server_reply_error`."""
        _answer_internal(self._server[].shared[], self._request, "The request was dropped without a reply")

    def _core(self) -> Pointer[_ServerCore, ImmUntrackedOrigin]:
        return Pointer[_ServerCore, ImmUntrackedOrigin](unsafe_from_address=Int(Pointer(to=self._server[].shared[])))

    def _raw(self) -> Address:
        return self._request

    def reply[
        origin: ImmOrigin
    ](deinit self, status: HTTPStatus, headers: Span[BytesView[origin], _], body: Span[Byte, _]) raises Error:
        """Replies with `status`, full header lines like "content-type: text/plain", and `body`.
        Calls `ucall_server_reply_content`.

        A closed connection still consumes the request and raises `CONNECTION_CLOSED`; any other
        refusal answers 500 before raising.

        Args:
            status: The response status; zero sends 200.
            headers: Every header line; Content-Length, Date and Server are generated.
            body: The response body.

        Raises:
            `Error` if the reply is refused.
        """
        ref core = self._server[].shared[]
        var outcome = _reply_content(core, self._request, status, headers, body)
        if not _consumed(outcome):
            _answer_internal(core, self._request, "The reply was refused")
        core.library._check(outcome, "ucall_server_reply_content")

    def reply(deinit self, status: HTTPStatus, body: Span[Byte, _]) raises Error:
        """Replies with `status` and `body` and no header lines of its own. Calls `ucall_server_reply_content`."""
        Request(self._server, self._request).reply(status, Span[BytesView[ImmUntrackedOrigin], ImmUntrackedOrigin](), body)

    def reply_error(deinit self, status: HTTPStatus, message: StringSlice) raises Error:
        """Replies with an error `status`, 400 or above, and a plain-text `message`.
        Calls `ucall_server_reply_error`.

        Raises:
            `Error` if the reply is refused, as `reply` does.
        """
        ref core = self._server[].shared[]
        var outcome = _reply_error(core, self._request, status, message)
        if not _consumed(outcome):
            _answer_internal(core, self._request, "The reply was refused")
        core.library._check(outcome, "ucall_server_reply_error")

    def detach(deinit self) -> DetachedRequest:
        """Hands the request to an owner that may move to any thread and reply after the handler
        returned, gaining the replies that may finish later. Binding-only.

        Returns:
            The request, owned from here on.
        """
        return DetachedRequest(self._server[].shared, self._request)


struct DetachedRequest(Movable, RequestReads):
    """A request taken off its polling thread, and the only owner of the verbs that may finish later:
    `reply_parts`, `reply_stream` and `body_chunk`.

    It reads like the `Request` it came from, moves to any thread, and answers 500 when dropped
    unreplied. Its replies hand back a `Deferred` while a file or path part still sends, and waiting
    on one belongs off the polling thread, as that thread is the one sending it.
    """

    var _shared: ArcPointer[_ServerCore]
    """The server, kept alive while the request is."""
    var _request: Address
    """The retained `ucall_received_http_request_t`."""

    def __init__(out self, shared: ArcPointer[_ServerCore], request: Address):
        self._shared = shared
        self._request = request

    def __deinit__(deinit self):
        """Answers 500 for a request dropped unreplied. Calls `ucall_server_reply_error`."""
        _ = _reply_error(self._shared[], self._request, HTTPStatus.INTERNAL_ERROR, "The request was dropped without a reply")
        _ = self._shared^

    def _core(self) -> Pointer[_ServerCore, ImmUntrackedOrigin]:
        return Pointer[_ServerCore, ImmUntrackedOrigin](unsafe_from_address=Int(Pointer(to=self._shared[])))

    def _raw(self) -> Address:
        return self._request

    def reply[
        origin: ImmOrigin
    ](deinit self, status: HTTPStatus, headers: Span[BytesView[origin], _], body: Span[Byte, _]) raises Error:
        """Replies with `status`, full header lines, and `body`, final on return. Calls `ucall_server_reply_content`.

        A refusal that keeps the request answers 500 before raising.

        Raises:
            `Error` if the reply is refused.
        """
        ref core = self._shared[]
        var outcome = _reply_content(core, self._request, status, headers, body)
        if not _consumed(outcome):
            _answer_internal(core, self._request, "The reply was refused")
        var library = core.library
        _ = self._shared^
        library._check(outcome, "ucall_server_reply_content")

    def reply(deinit self, status: HTTPStatus, body: Span[Byte, _]) raises Error:
        """Replies with `status` and `body` and no header lines of its own. Calls `ucall_server_reply_content`."""
        DetachedRequest(self._shared, self._request).reply(
            status, Span[BytesView[ImmUntrackedOrigin], ImmUntrackedOrigin](), body
        )
        _ = self._shared^

    def reply_error(deinit self, status: HTTPStatus, message: StringSlice) raises Error:
        """Replies with an error `status` and a plain-text `message`, final on return.
        Calls `ucall_server_reply_error`.

        Raises:
            `Error` if the reply is refused.
        """
        ref core = self._shared[]
        var outcome = _reply_error(core, self._request, status, message)
        if not _consumed(outcome):
            _answer_internal(core, self._request, "The reply was refused")
        var library = core.library
        _ = self._shared^
        library._check(outcome, "ucall_server_reply_error")

    def reply_parts[
        headers_origin: ImmOrigin, parts_origin: ImmOrigin
    ](
        deinit self,
        status: HTTPStatus,
        headers: Span[BytesView[headers_origin], _],
        parts: Span[ReplyPart[parts_origin], _],
    ) raises Error -> Optional[Deferred]:
        """Replies with `status`, full header lines, and `parts` concatenated into the body, its
        Content-Length measured. Calls `ucall_server_reply_vectored`.

        A part failing before the head left replaces the reply with 404, 416 or 500, and the
        `Deferred` reports the cause. A refusal on return answers 500 before raising.

        Returns:
            `None` once final, and a `Deferred` while a file or path part still sends.

        Raises:
            `Error` if the reply is refused or fails.
        """
        ref core = self._shared[]
        var deferred = Deferred(core.library, "ucall_server_reply_vectored")
        _cross(
            ServerReplyVectoredArguments(
                core.handle,
                deferred._outcome().unsafe_origin_cast[MutUntrackedOrigin](),
                self._request,
                status,
                _headers(headers),
                c_size_t(len(headers)),
                _parts(parts),
                c_size_t(len(parts)),
            ),
            core.library.symbols().server_reply_vectored,
        )
        var result = _finish(core, self._request, deferred^)
        _ = self._shared^
        return result^

    def reply_stream[
        origin: ImmOrigin
    ](deinit self, status: HTTPStatus, headers: Span[BytesView[origin], _]) raises Error -> ReplyStream:
        """Sends the status line and header lines, and opens a body appended part by part: chunked,
        or of the length a Content-Length header declares. Calls `ucall_server_reply_begin`.

        A closed connection still ends the stream and raises `CONNECTION_CLOSED`; any other failure
        answers 500 before raising.

        Returns:
            The open stream, which ends once dropped or `end` is called.

        Raises:
            `Error` if the head is refused.
        """
        ref core = self._shared[]
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerReplyBeginArguments(
                core.handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                self._request,
                status,
                _headers(headers),
                c_size_t(len(headers)),
            ),
            core.library.symbols().server_reply_begin,
        )
        var begun = Status.of(outcome[unsafe_offset=0].status)
        var library = core.library
        if begun == Status.SUCCESS:
            return ReplyStream(self._shared^, self._request)
        if begun == Status.CONNECTION_CLOSED:
            _ = ReplyStream(self._shared, self._request)
        else:
            _answer_internal(core, self._request, "The reply was refused")
        _ = self._shared^
        library._check(outcome[unsafe_offset=0], "ucall_server_reply_begin")
        raise Error(Status.INTERNAL, "ucall_server_reply_begin")

    def body_chunk(ref self) raises Error -> Span[Byte, ImmOrigin(origin_of(self))]:
        """Pulls the body bytes decoded since the last pull, waiting for them to arrive; empty once the
        body ended. Calls `ucall_server_request_body_chunk` and `ucall_outcome_wait`.

        On a buffered endpoint the first pull is the whole body. On the polling thread, where nothing
        can arrive while it runs, a pull finding nothing raises `WOULD_BLOCK` instead.

        Returns:
            The bytes, valid until the next pull.

        Raises:
            `Error` with `CONNECTION_CLOSED` for a body cut short, or `MALFORMED` for a malformed one.
        """
        ref core = self._shared[]
        var data = _view_in(stack_allocation[1, BytesView[ImmUntrackedOrigin]]())
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerRequestViewArguments(
                core.handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                self._request,
                data.unsafe_origin_cast[MutUntrackedOrigin](),
            ),
            core.library.symbols().server_request_body_chunk,
        )
        _ = core.library.symbols().outcome_wait(outcome)
        core.library._check(outcome[unsafe_offset=0], "ucall_server_request_body_chunk")
        return data[unsafe_offset=0].span[ImmOrigin(origin_of(self))]()


def _finish(core: _ServerCore, request: Address, var deferred: Deferred) raises Error -> Optional[Deferred]:
    """Settles a reply that may finish later: the refusals that queued nothing answer 500, and a final
    outcome is checked at once."""
    var status = Status.of(core.library.symbols().outcome_status(deferred._outcome()))
    if (
        status == Status.UNINITIALIZED
        or status == Status.INVALID_ARGUMENT
        or status == Status.ALREADY_EXISTS
        or status == Status.OUT_OF_MEMORY
    ):
        _answer_internal(core, request, "The reply was refused")
    if status == Status.DEFERRED:
        return deferred^
    deferred^.wait()
    return None


# endregion Requests

# region Replies


@fieldwise_init
struct FileRange(ImplicitlyCopyable, TrivialRegisterPassable):
    """A byte range of a regular file the caller opened with `O_DIRECT`, `ucall_file_range_t` in C."""

    var file_descriptor: c_int
    """The open file, borrowed and never closed by UCall, until the reply is final."""
    var offset: UInt64
    """The range's first byte."""
    var length: UInt64
    """The range's byte count; zero sends through the end of the file."""


@fieldwise_init
struct ReplyPart[origin: ImmOrigin = ImmUntrackedOrigin](ImplicitlyCopyable, TrivialRegisterPassable):
    """One part of a reply body, `ucall_reply_part_t` in C: bytes in memory, or a byte range of a file.

    Mojo has no unions, so the union's five words are spelled out, as the ABI lays them for each kind
    on the little-endian targets this binding runs on.

    Parameters:
        origin: The bytes or path a part borrows, named so they outlive the reply call.
    """

    var kind: c_int
    """`ucall_reply_part_kind_t`: 0 for bytes, 1 for a file, 2 for a path."""
    var first: UInt64
    var second: UInt64
    var third: UInt64
    var fourth: UInt64
    var fifth: UInt64

    @staticmethod
    def bytes[bytes_origin: ImmOrigin, //](bytes: Span[Byte, bytes_origin]) -> ReplyPart[bytes_origin]:
        """Bytes in memory, copied before the reply call returns.

        Args:
            bytes: The content.

        Returns:
            The part.
        """
        return ReplyPart[bytes_origin](c_int(0), UInt64(Int(bytes.unsafe_ptr())), UInt64(len(bytes)), 0, 0, 0)

    @staticmethod
    def file[part_origin: ImmOrigin = ImmUntrackedOrigin](range: FileRange) -> ReplyPart[part_origin]:
        """A range of an `O_DIRECT` file, which the event loop reads after the call returns.

        Parameters:
            part_origin: The origin of the parts it shares an array with.

        Args:
            range: The file and the range.

        Returns:
            The part.
        """
        return ReplyPart[part_origin](
            c_int(1), UInt64(UInt32(range.file_descriptor)), range.offset, range.length, 0, 0
        )

    @staticmethod
    def path[
        path_origin: ImmOrigin, //
    ](directory: Int, relative_path: StringSlice[path_origin], offset: UInt64 = 0, length: UInt64 = 0) -> ReplyPart[
        path_origin
    ]:
        """A range of a file beneath one of the interface's reply directories, opened by the event loop.

        Args:
            directory: The position of the directory among the interface's reply directories.
            relative_path: The file beneath it, copied before the call returns.
            offset: The range's first byte.
            length: The range's byte count; zero sends through the end of the file.

        Returns:
            The part.
        """
        return ReplyPart[path_origin](
            c_int(2),
            UInt64(directory),
            UInt64(Int(relative_path.unsafe_ptr())),
            UInt64(relative_path.byte_length()),
            offset,
            length,
        )


struct ReplyStream(Movable):
    """A reply whose head left and whose body is appended part by part, from one thread at a time,
    until `end`; dropping it ends it, waiting for its file parts to send."""

    var _shared: ArcPointer[_ServerCore]
    """The server, kept alive while the stream is."""
    var _request: Address
    """The request being replied to."""

    def __init__(out self, var shared: ArcPointer[_ServerCore], request: Address):
        self._shared = shared^
        self._request = request

    def __deinit__(deinit self):
        """Ends the body, waiting for its file parts. Calls `ucall_server_reply_end`."""
        try:
            var ended = _end(self._shared[], self._request)
            if ended:
                ended.take().wait()
        except:
            pass
        _ = self._shared^

    def append[origin: ImmOrigin](self, parts: Span[ReplyPart[origin], _]) raises Error:
        """Queues `parts` on the body together, or none of them. Calls `ucall_server_reply_append`.

        Raises:
            `Error` with `WOULD_BLOCK`, queueing nothing, while the peer lags behind the parts
            already queued; retry once it catches up.
        """
        ref core = self._shared[]
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ServerReplyAppendArguments(
                core.handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                self._request,
                _parts(parts),
                c_size_t(len(parts)),
            ),
            core.library.symbols().server_reply_append,
        )
        core.library._check(outcome[unsafe_offset=0], "ucall_server_reply_append")

    def end(deinit self) raises Error -> Optional[Deferred]:
        """Ends the body, consuming the request whatever the outcome. Calls `ucall_server_reply_end`.

        Returns:
            `None` once final, and a `Deferred` while file or path parts still send.

        Raises:
            `Error` with `MALFORMED` for a body short of its declared Content-Length.
        """
        var shared = self._shared^
        return _end(shared[], self._request)


def _end(core: _ServerCore, request: Address) raises Error -> Optional[Deferred]:
    """Crosses `ucall_server_reply_end`, answering the outcome while it is deferred."""
    var deferred = Deferred(core.library, "ucall_server_reply_end")
    _cross(
        ServerReplyEndArguments(core.handle, deferred._outcome().unsafe_origin_cast[MutUntrackedOrigin](), request),
        core.library.symbols().server_reply_end,
    )
    if Status.of(core.library.symbols().outcome_status(deferred._outcome())) == Status.DEFERRED:
        return deferred^
    deferred^.wait()
    return None


# endregion Replies
