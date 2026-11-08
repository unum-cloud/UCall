"""The HTTP client: calls submitted without driving the network, polled to completion on one thread.

A `Client` owns every input the library reads until a call completes, in slots sized once by the
resolved call budget, so polling allocates nothing past the first growth of the caller's list.
`submit` admits a call, `take_completed` drives the network and hands back what finished, and
`call` does both until its own response arrives, keeping other calls' completions for the next
`take_completed`. A `Response` owns its received bytes and stays readable after its client is gone.

File: mojo/ucall/client.mojo
Author: Ash Vardanian
Date: November 8, 2026
"""

from std.ffi import c_int, c_size_t
from std.memory import ArcPointer, stack_allocation

from ucall.library import Library
from ucall.server import Server, _ServerCore, _array, _lend, _outcome_in, _view_in
from ucall.types import (
    Address,
    Backend,
    BytesView,
    CPUClass,
    Entry,
    Error,
    HTTPStatus,
    Log,
    NULL_ADDRESS,
    NoiseKey,
    Outcome,
    PeerAuthorizer,
    Security,
    Status,
    Verb,
    _cross,
)

# region Signatures

comptime ResponseStatus = def(Address) thin abi("C") -> UInt32
"""`ucall_client_response_status`: the HTTP status of a received response."""

comptime ClientInit = Entry[ClientInitArguments]
"""`ucall_client_init`."""
comptime ClientCallEntry = Entry[ClientCallArguments]
"""`ucall_client_call`, named apart from the `ClientCall` it submits."""
comptime ClientTakeCompleted = Entry[ClientTakeCompletedArguments]
"""`ucall_client_take_completed`."""
comptime ClientResponseHeader = Entry[ClientResponseHeaderArguments]
"""`ucall_client_response_header`."""
comptime ClientResponseFieldsCount = Entry[ClientResponseFieldsCountArguments]
"""`ucall_client_response_fields_count`."""
comptime ClientResponseField = Entry[ClientResponseFieldArguments]
"""`ucall_client_response_field`."""
comptime ClientResponseBody = Entry[ClientResponseBodyArguments]
"""`ucall_client_response_body`."""

# endregion Signatures

# region Arguments


@fieldwise_init
struct ClientOptionsArguments(ImplicitlyCopyable):
    """`ucall_client_options_t`, laid out as the ABI declares it."""

    var max_concurrent_connections: c_size_t
    var max_pipelined_calls: c_size_t
    var connect_timeout_microseconds: c_size_t
    var call_timeout_microseconds: c_size_t
    var noise_private_key: Optional[Pointer[NoiseKey, ImmUntrackedOrigin]]
    var peer_authorizer: Address
    var peer_authorizer_context: Address
    var log: Log
    var max_concurrent_calls: c_size_t
    var backend: Backend
    var cpu_class: CPUClass
    var max_response_bytes: c_size_t
    var server: Address
    var event_loop: c_size_t


@fieldwise_init
struct ClientInitArguments(ImplicitlyCopyable):
    """`ucall_client_init_t`, laid out as the ABI declares it."""

    var client: Pointer[Address, MutUntrackedOrigin]
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var options: Pointer[ClientOptionsArguments, ImmUntrackedOrigin]
    var resolved: Pointer[ClientOptionsArguments, MutUntrackedOrigin]


@fieldwise_init
struct ClientCallOptionsArguments(ImplicitlyCopyable):
    """`ucall_client_call_options_t`, laid out as the ABI declares it."""

    var timeout_microseconds: c_size_t
    var max_retries: c_size_t
    var max_redirects: c_size_t
    var security: Security
    var noise_private_key: Optional[Pointer[NoiseKey, ImmUntrackedOrigin]]
    var noise_peer_key: Optional[Pointer[NoiseKey, ImmUntrackedOrigin]]


@fieldwise_init
struct ClientCallArguments(ImplicitlyCopyable):
    """`ucall_client_call_t`, laid out as the ABI declares it."""

    var client: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var url: BytesView[ImmUntrackedOrigin]
    var verb: Verb
    var headers: Optional[Pointer[BytesView[ImmUntrackedOrigin], ImmUntrackedOrigin]]
    var headers_count: c_size_t
    var body: BytesView[ImmUntrackedOrigin]
    var options: ClientCallOptionsArguments
    var context: Address


@fieldwise_init
struct CompletedCallArguments(ImplicitlyCopyable):
    """`ucall_completed_call_t`, laid out as the ABI declares it."""

    var context: Address
    var outcome: Outcome
    var response: Address


@fieldwise_init
struct ClientTakeCompletedArguments(ImplicitlyCopyable):
    """`ucall_client_take_completed_t`, laid out as the ABI declares it."""

    var client: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var calls: Pointer[CompletedCallArguments, MutUntrackedOrigin]
    var capacity: c_size_t
    var count: Pointer[c_size_t, MutUntrackedOrigin]
    var timeout_microseconds: c_size_t


@fieldwise_init
struct ClientResponseHeaderArguments(ImplicitlyCopyable):
    """`ucall_client_response_header_t`, laid out as the ABI declares it."""

    var response: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var name: BytesView[ImmUntrackedOrigin]
    var value: Pointer[BytesView[ImmUntrackedOrigin], MutUntrackedOrigin]


@fieldwise_init
struct ClientResponseFieldsCountArguments(ImplicitlyCopyable):
    """`ucall_client_response_fields_count_t`, laid out as the ABI declares it."""

    var response: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var count: Pointer[c_size_t, MutUntrackedOrigin]


@fieldwise_init
struct ClientResponseFieldArguments(ImplicitlyCopyable):
    """`ucall_client_response_field_t`, laid out as the ABI declares it."""

    var response: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var index: c_size_t
    var name: Pointer[BytesView[ImmUntrackedOrigin], MutUntrackedOrigin]
    var value: Pointer[BytesView[ImmUntrackedOrigin], MutUntrackedOrigin]


@fieldwise_init
struct ClientResponseBodyArguments(ImplicitlyCopyable):
    """`ucall_client_response_body_t`, laid out as the ABI declares it."""

    var response: Address
    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var body: Pointer[BytesView[ImmUntrackedOrigin], MutUntrackedOrigin]


# endregion Arguments

# region Calls


@fieldwise_init
struct ClientOptions(Copyable, Movable):
    """What a client may hold open at once, how long it waits, and who it is under Noise.

    `connections` is required; every other zero field takes its documented default.
    """

    var connections: Int
    """Connections open at once; zero fails with `INVALID_ARGUMENT`."""
    var pipelined_calls: Int
    """Calls one connection may carry at once; zero means one."""
    var calls: Int
    """Calls admitted at once, unretrieved completions included; zero means `connections` times
    `pipelined_calls`."""
    var connect_timeout_microseconds: Int
    """Time budget for establishing a connection; zero means 5 seconds."""
    var call_timeout_microseconds: Int
    """Time budget for a full exchange, including queueing and redirects; zero means 30 seconds."""
    var noise_private_key: Optional[NoiseKey]
    """The client identity for Noise handshakes."""
    var peer_authorizer: PeerAuthorizer
    """Vets each server's authenticated static key; required for Noise XX calls."""
    var backend: Backend
    """The requested I/O backend."""
    var cpu_class: CPUClass
    """A ceiling on the CPU class; `UNKNOWN` takes what the CPU offers."""
    var log: Log
    """Where log lines go; the default keeps the client silent."""
    var max_response_bytes: Int
    """The largest response a call buffers; zero takes the largest socket receive buffer."""

    def __init__(out self, *, connections: Int):
        """Every default but the connection budget.

        Args:
            connections: Connections open at once.
        """
        self = Self(connections, 0, 0, 0, 0, None, PeerAuthorizer(), Backend.AUTOMATIC, CPUClass.UNKNOWN, Log(), 0)


@fieldwise_init
struct ClientCallOptions(Copyable, Defaultable, Movable):
    """One call's time budget, retries, redirects and security, each zero field taking its default."""

    var timeout_microseconds: Int
    """Time budget including queueing and redirects; zero takes the client's call timeout."""
    var max_retries: Int
    """Connection attempts made again before sending the request; zero means 3."""
    var max_redirects: Int
    """Redirect hops followed before failing; zero means 5."""
    var security: Security
    """The transport security; an "http+noise://" URL implies Noise XX."""
    var noise_private_key: Optional[NoiseKey]
    """The private key this call authenticates with in place of the client's own."""
    var noise_peer_key: Optional[NoiseKey]
    """The server's static key, which Noise IK and KK need in advance."""

    def __init__(out self):
        """Every default."""
        self = Self(0, 0, 0, Security.NONE, None, None)


@fieldwise_init
struct ClientCall(Copyable, Movable):
    """One HTTP call, owning everything the library reads until the call completes."""

    var verb: Verb
    """The HTTP method."""
    var url: String
    """The full URL, "http://" or "http+noise://"."""
    var headers: List[String]
    """Full header lines like "accept: text/plain"; Host, Content-Length and User-Agent are generated."""
    var body: List[Byte]
    """The request body; empty sends no payload."""
    var options: ClientCallOptions
    """The call's own time budget, retries, redirects and security."""

    @staticmethod
    def get(url: String) -> Self:
        """A GET of `url` with no headers."""
        return Self(Verb.GET, url, List[String](), List[Byte](), ClientCallOptions())

    @staticmethod
    def post(url: String, body: Span[Byte, _]) -> Self:
        """A POST of `body` to `url` with no headers."""
        return Self(Verb.POST, url, List[String](), _copied(body), ClientCallOptions())

    @staticmethod
    def put(url: String, body: Span[Byte, _]) -> Self:
        """A PUT of `body` to `url` with no headers."""
        return Self(Verb.PUT, url, List[String](), _copied(body), ClientCallOptions())

    @staticmethod
    def delete(url: String) -> Self:
        """A DELETE of `url` with no headers."""
        return Self(Verb.DELETE, url, List[String](), List[Byte](), ClientCallOptions())

    @staticmethod
    def patch(url: String, body: Span[Byte, _]) -> Self:
        """A PATCH of `body` to `url` with no headers."""
        return Self(Verb.PATCH, url, List[String](), _copied(body), ClientCallOptions())


def _copied(bytes: Span[Byte, _]) -> List[Byte]:
    """An owned copy of borrowed bytes, which a call keeps until it completes."""
    var copy = List[Byte](capacity=len(bytes))
    for byte in bytes:
        copy.append(byte)
    return copy^


@fieldwise_init
struct _CallSlot(Copyable, Movable):
    """One admission slot: the caller's context and the inputs the library borrows until completion."""

    var context: UInt64
    var request: Optional[ClientCall]
    var headers: List[BytesView[ImmUntrackedOrigin]]


struct Completed(Movable):
    """One finished call: the context it was submitted with, and its response or failure."""

    var context: UInt64
    """The context passed to `Client.submit`."""
    var response: Optional[Response]
    """The received response whatever its HTTP status, or `None` when none arrived."""
    var error: Optional[Error]
    """Why no response arrived, or `None` when one did."""

    def __init__(out self, context: UInt64, var response: Optional[Response], error: Optional[Error]):
        self.context = context
        self.response = response^
        self.error = error


# endregion Calls

# region Client


struct Client(Movable):
    """An HTTP client, created, submitted to, polled, and dropped on one thread.

    Dropping it cancels the calls in flight, while retrieved responses stay readable.
    """

    var library: Library
    """The loaded library, held so the release can still reach `ucall_client_free`."""
    var handle: Address
    """The `ucall_client_t`."""
    var server: Optional[ArcPointer[_ServerCore]]
    """The server whose event loop drives a bound client, kept alive while the client is."""
    var slots: List[_CallSlot]
    """One per admitted call, sized once, so the inputs the library reads never move."""
    var free: List[Int]
    """Slots holding no call."""
    var retrieved: List[CompletedCallArguments]
    """The library's completion records, one per slot."""
    var kept: List[Completed]
    """Completions `call` retrieved for other calls, handed out by the next `take_completed` first."""
    var call_timeout_microseconds: Int
    """The resolved time budget of one exchange, which `call` waits in."""

    def __init__(out self, library: Library, options: ClientOptions) raises Error:
        """Starts a client with an engine of its own; it holds no connection until a call is polled.
        Calls `ucall_client_init`.

        Args:
            library: The loaded library, kept so the shared object stays mapped.
            options: The budgets, timeouts and identity.

        Raises:
            `Error` with `INVALID_ARGUMENT` for a zero connection budget, or `UNSUPPORTED` when no
            backend serves the configuration.
        """
        self = Self(library, options, None, 0)

    def __init__(out self, server: Server, options: ClientOptions, *, event_loop: Int = 0) raises Error:
        """Starts a client driven by one of `server`'s event loops, sharing its engine. Calls `ucall_client_init`.

        Bind it before the loop first polls, and use it only on that loop's polling thread, whose
        `take_call` advances it; its `take_completed` only hands out what the loop finished.

        Args:
            server: The server whose loop drives it, kept alive while the client is.
            options: The budgets, timeouts and identity.
            event_loop: Which of the server's loops.

        Raises:
            `Error` as the unbound constructor does.
        """
        self = Self(server.shared[].library, options, server.shared, event_loop)

    def __init__(
        out self, library: Library, options: ClientOptions, server: Optional[ArcPointer[_ServerCore]], event_loop: Int
    ) raises Error:
        var config = stack_allocation[2, ClientOptionsArguments]().unsafe_origin_cast[MutAnyOrigin]()
        config[unsafe_offset=0] = ClientOptionsArguments(
            c_size_t(options.connections),
            c_size_t(options.pipelined_calls),
            c_size_t(options.connect_timeout_microseconds),
            c_size_t(options.call_timeout_microseconds),
            _lend(options.noise_private_key),
            options.peer_authorizer.callback,
            options.peer_authorizer.context,
            options.log,
            c_size_t(options.calls),
            options.backend,
            options.cpu_class,
            c_size_t(options.max_response_bytes),
            server.value()[].handle if server else NULL_ADDRESS,
            c_size_t(event_loop),
        )
        config[unsafe_offset=1] = config[unsafe_offset=0]
        var created = stack_allocation[1, Address]().unsafe_origin_cast[MutAnyOrigin]()
        created[unsafe_offset=0] = NULL_ADDRESS
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ClientInitArguments(
                created.unsafe_origin_cast[MutUntrackedOrigin](),
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                Pointer[ClientOptionsArguments, ImmUntrackedOrigin](unsafe_from_address=Int(config)),
                config.unsafe_offset(1).unsafe_origin_cast[MutUntrackedOrigin](),
            ),
            library.symbols().client_init,
        )
        library._check(outcome[unsafe_offset=0], "ucall_client_init")
        var resolved = config[unsafe_offset=1]
        var capacity = Int(resolved.max_concurrent_calls)
        self.library = library
        self.handle = created[unsafe_offset=0]
        self.server = server
        self.slots = List[_CallSlot](capacity=capacity)
        self.free = List[Int](capacity=capacity)
        self.retrieved = List[CompletedCallArguments](capacity=capacity)
        for index in range(capacity):
            self.slots.append(_CallSlot(0, None, List[BytesView[ImmUntrackedOrigin]]()))
            self.free.append(capacity - 1 - index)
            self.retrieved.append(CompletedCallArguments(NULL_ADDRESS, Outcome(), NULL_ADDRESS))
        self.kept = List[Completed](capacity=capacity)
        self.call_timeout_microseconds = Int(resolved.call_timeout_microseconds)

    def __deinit__(deinit self):
        """Cancels the calls in flight and frees the client before the inputs they borrowed.
        Calls `ucall_client_free`."""
        self.library.symbols().client_free(self.handle)
        _ = self.slots^
        _ = self.server^
        _ = self.library^

    def _admit(mut self, var request: ClientCall, context: UInt64) raises Error -> Int:
        """Admits a call into a free slot, answering the slot it took."""
        if len(self.free) == 0:
            raise Error(Status.CONTENDED, "ucall_client_call")
        var index = self.free.pop()
        ref slot = self.slots[index]
        slot.context = context
        slot.request = request^
        ref call = slot.request.value()
        slot.headers.clear()
        for ref line in call.headers:
            slot.headers.append(BytesView.of(StringSlice(line)).arguments())
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ClientCallArguments(
                self.handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                BytesView.of(StringSlice(call.url)).arguments(),
                call.verb,
                _array(slot.headers),
                c_size_t(len(slot.headers)),
                BytesView.of(Span(call.body)).arguments(),
                ClientCallOptionsArguments(
                    c_size_t(call.options.timeout_microseconds),
                    c_size_t(call.options.max_retries),
                    c_size_t(call.options.max_redirects),
                    call.options.security,
                    _lend(call.options.noise_private_key),
                    _lend(call.options.noise_peer_key),
                ),
                index,
            ),
            self.library.symbols().client_call,
        )
        if outcome[unsafe_offset=0].status != c_int(0):
            slot.request = None
            self.free.append(index)
            self.library._check(outcome[unsafe_offset=0], "ucall_client_call")
        return index

    def submit(mut self, var request: ClientCall, context: UInt64 = 0) raises Error:
        """Admits `request` without driving the network; its completion carries `context`.
        Calls `ucall_client_call`.

        Success guarantees exactly one completion from `take_completed`.

        Args:
            request: The call, owned until it completes.
            context: Handed back with the completion.

        Raises:
            `Error` with `CONTENDED` while every call slot holds an unretrieved call, or
            `INVALID_ARGUMENT` for a malformed URL.
        """
        _ = self._admit(request^, context)

    def _retrieve(mut self, capacity: Int, timeout_microseconds: Int) raises Error -> Int:
        """Drives the library and retrieves up to `capacity` raw completions."""
        var count = stack_allocation[1, c_size_t]().unsafe_origin_cast[MutAnyOrigin]()
        count[unsafe_offset=0] = c_size_t(0)
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ClientTakeCompletedArguments(
                self.handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                self.retrieved.unsafe_ptr().unsafe_origin_cast[MutUntrackedOrigin](),
                c_size_t(min(capacity, len(self.retrieved))),
                count.unsafe_origin_cast[MutUntrackedOrigin](),
                c_size_t(timeout_microseconds),
            ),
            self.library.symbols().client_take_completed,
        )
        self.library._check(outcome[unsafe_offset=0], "ucall_client_take_completed")
        return Int(count[unsafe_offset=0])

    def _complete(mut self, position: Int) -> Completed:
        """Frees the slot of a retrieved completion and lifts it into its safe form."""
        var retrieved = Pointer(to=self.retrieved[position]).unsafe_origin_cast[MutAnyOrigin]()[]
        var index = retrieved.context
        self.slots[index].request = None
        self.free.append(index)
        var context = self.slots[index].context
        if retrieved.outcome.status != c_int(0):
            self.library.symbols().client_response_free(retrieved.response)
            return Completed(context, None, self.library._error(retrieved.outcome, "ucall_client_take_completed"))
        return Completed(context, Response(self.library, retrieved.response), None)

    def take_completed(mut self, mut completed: List[Completed], timeout_microseconds: Int = 0) raises Error:
        """Drives every admitted call on this thread and refills `completed` with finished ones,
        waiting up to `timeout_microseconds` for the first. Calls `ucall_client_take_completed`.

        Completions kept by `call` come first, without waiting.

        Args:
            completed: Cleared, then filled with what finished, empty when nothing did in time.
            timeout_microseconds: The longest wait; zero performs one nonblocking round.

        Raises:
            `Error` if the polling itself fails; a call's own failure arrives in its `Completed`.
        """
        completed.clear()
        if len(self.kept) != 0:
            while len(self.kept) != 0:
                completed.append(self.kept.pop(0))
            return
        var count = self._retrieve(len(self.retrieved), timeout_microseconds)
        for position in range(count):
            completed.append(self._complete(position))

    def call(mut self, var request: ClientCall) raises Error -> Response:
        """Submits `request` and polls until it finishes, keeping other calls' completions for the
        next `take_completed`. Calls `ucall_client_call` and `ucall_client_take_completed`.

        Returns:
            The response, whatever its HTTP status.

        Raises:
            `Error` if the call is refused or its exchange fails.
        """
        var index = self._admit(request^, 0)
        while True:
            var count = self._retrieve(len(self.retrieved), self.call_timeout_microseconds)
            var answer = Optional[Completed](None)
            for position in range(count):
                var mine = self.retrieved[position].context == index
                var done = self._complete(position)
                if mine:
                    answer = done^
                else:
                    self.kept.append(done^)
            if answer:
                var done = answer.take()
                if done.response:
                    return done.response.take()
                raise done.error.value()

    def get(mut self, url: String) raises Error -> Response:
        """Fetches `url` and polls until the response arrives."""
        return self.call(ClientCall.get(url))

    def post(mut self, url: String, body: Span[Byte, _]) raises Error -> Response:
        """Posts `body` to `url` and polls until the response arrives."""
        return self.call(ClientCall.post(url, body))

    def put(mut self, url: String, body: Span[Byte, _]) raises Error -> Response:
        """Puts `body` at `url` and polls until the response arrives."""
        return self.call(ClientCall.put(url, body))

    def delete(mut self, url: String) raises Error -> Response:
        """Deletes `url` and polls until the response arrives."""
        return self.call(ClientCall.delete(url))

    def patch(mut self, url: String, body: Span[Byte, _]) raises Error -> Response:
        """Patches `url` with `body` and polls until the response arrives."""
        return self.call(ClientCall.patch(url, body))


# endregion Client

# region Responses


struct Response(Movable):
    """A received HTTP response, freed once dropped.

    It owns its received bytes, so it stays readable after its client is dropped.
    """

    var library: Library
    """The loaded library, held so the release can still reach `ucall_client_response_free`."""
    var handle: Address
    """The `ucall_received_http_response_t`."""

    def __init__(out self, library: Library, handle: Address):
        self.library = library
        self.handle = handle

    def __deinit__(deinit self):
        """Frees the response. Calls `ucall_client_response_free`."""
        self.library.symbols().client_response_free(self.handle)
        _ = self.library^

    def status_code(self) -> HTTPStatus:
        """The status code the server sent. Calls `ucall_client_response_status`."""
        return HTTPStatus(self.library.symbols().client_response_status(self.handle))

    def body(ref self) raises Error -> Span[Byte, ImmOrigin(origin_of(self))]:
        """The response body, decoded from chunked framing if it arrived that way.
        Calls `ucall_client_response_body`."""
        var body = _view_in(stack_allocation[1, BytesView[ImmUntrackedOrigin]]())
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ClientResponseBodyArguments(
                self.handle, outcome.unsafe_origin_cast[MutUntrackedOrigin](), body.unsafe_origin_cast[MutUntrackedOrigin]()
            ),
            self.library.symbols().client_response_body,
        )
        self.library._check(outcome[unsafe_offset=0], "ucall_client_response_body")
        return body[unsafe_offset=0].span[ImmOrigin(origin_of(self))]()

    def header(ref self, name: StringSlice) -> Optional[Span[Byte, ImmOrigin(origin_of(self))]]:
        """The value of header `name`, matched case-insensitively, or `None` without one.
        Calls `ucall_client_response_header`."""
        var value = _view_in(stack_allocation[1, BytesView[ImmUntrackedOrigin]]())
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ClientResponseHeaderArguments(
                self.handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                BytesView.of(name).arguments(),
                value.unsafe_origin_cast[MutUntrackedOrigin](),
            ),
            self.library.symbols().client_response_header,
        )
        if outcome[unsafe_offset=0].status != c_int(0):
            return None
        return value[unsafe_offset=0].span[ImmOrigin(origin_of(self))]()

    def fields_count(self) raises Error -> Int:
        """Header field lines in arrival order, repeated names included.
        Calls `ucall_client_response_fields_count`."""
        var count = stack_allocation[1, c_size_t]().unsafe_origin_cast[MutAnyOrigin]()
        count[unsafe_offset=0] = c_size_t(0)
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ClientResponseFieldsCountArguments(
                self.handle, outcome.unsafe_origin_cast[MutUntrackedOrigin](), count.unsafe_origin_cast[MutUntrackedOrigin]()
            ),
            self.library.symbols().client_response_fields_count,
        )
        self.library._check(outcome[unsafe_offset=0], "ucall_client_response_fields_count")
        return Int(count[unsafe_offset=0])

    def field(ref self, index: Int) raises Error -> Tuple[Span[Byte, ImmOrigin(origin_of(self))], Span[Byte, ImmOrigin(origin_of(self))]]:
        """Header field line `index`: its lowercased name and its trimmed value.
        Calls `ucall_client_response_field`.

        Raises:
            `Error` with `NOT_FOUND` past the last line.
        """
        var name = _view_in(stack_allocation[1, BytesView[ImmUntrackedOrigin]]())
        var value = _view_in(stack_allocation[1, BytesView[ImmUntrackedOrigin]]())
        var outcome = _outcome_in(stack_allocation[1, Outcome]())
        _cross(
            ClientResponseFieldArguments(
                self.handle,
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                c_size_t(index),
                name.unsafe_origin_cast[MutUntrackedOrigin](),
                value.unsafe_origin_cast[MutUntrackedOrigin](),
            ),
            self.library.symbols().client_response_field,
        )
        self.library._check(outcome[unsafe_offset=0], "ucall_client_response_field")
        return (name[unsafe_offset=0].span[ImmOrigin(origin_of(self))](), value[unsafe_offset=0].span[ImmOrigin(origin_of(self))]())


# endregion Responses
