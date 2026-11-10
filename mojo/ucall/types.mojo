"""The vocabulary the client and the server share: statuses, byte views, enumerations and keys.

`Error` is the only error type the binding raises: Mojo allows at most one per function, so a
second would force every caller raising `Error` to catch and convert.

`MutAnyOrigin` rather than `MutUntrackedOrigin` is load-bearing on anything C writes through: with
a narrower origin the compiler folds a read of the slot back to whatever the caller last stored
there, and every out-parameter reads back as zero.

A typed C pointer that may be null crosses as `Optional[Pointer[T, ...]]`, whose empty case is the
null the ABI asks for and costs nothing to pass. Opaque handles and `void *` state name no element
type, so they cross as `Address`, their numeric value. A struct holding an `Optional` is not
`TrivialRegisterPassable`, so C reads those by address.

Every view that borrows caller storage carries that storage's origin as a struct parameter,
because Mojo destroys a value at its last use rather than at the end of its scope, and an address
laundered through `Address` is not a use. A verb takes the view with its origin and erases it
inside, while the view is still alive.

A struct whose address crosses to C is materialized into a `stack_allocation` slot rather than held
in a local whose address is taken, as an `alloca` is not a value Mojo owns, so nothing destroys it
and nothing folds its store away.

File: mojo/ucall/types.mojo
Author: Ash Vardanian
Date: November 8, 2026
"""

from std.ffi import c_char, c_int, c_size_t
from std.memory import OwnedPointer, stack_allocation

from ucall.library import Library

# region Pointers

comptime CString = Pointer[c_char, ImmUntrackedOrigin]
"""A borrowed null-terminated C string, such as an enumerator's spelling or an outcome's message."""

comptime Address = Int
"""An opaque handle or a `void *` crossing as its numeric value, zero for null.

A typed slot crosses as `Pointer`, or as `Optional[Pointer]` where it may be null; this is for the
slots that name no element type. The integer is pointer-width and shares the pointer's argument
class on both x86-64 and AArch64, so it lands in the same register a pointer would.
"""

comptime NULL_ADDRESS = 0
"""The null pointer, as `Address` spells it."""

comptime NoiseKey = SIMD[DType.uint8, 32]
"""A 32-byte Curve25519 key, private or public, as every Noise handshake takes it."""


def _address_of[F: TrivialRegisterPassable](function: F) -> Address:
    """The entry address of a `thin abi("C")` function, for a slot the ABI lets stay null."""
    var slot = function
    return Pointer(to=slot).unsafe_bitcast[Address]()[]


# endregion Pointers

# region Errors


@fieldwise_init
struct Status(Equatable, ImplicitlyCopyable, TrivialRegisterPassable):
    """Why a call failed, numbered as the library numbers it.

    An `Error` never carries `SUCCESS`, and only a `Deferred` reports `DEFERRED`, until its reply is
    final. `Library.status_name` spells each one as the library does.
    """

    var code: Int32
    """The raw `ucall_status_t` value, kept even when this build does not name it."""
    comptime SUCCESS = Self(0)
    """The call succeeded."""
    comptime DEFERRED = Self(1)
    """A submitted call has not finished; the only status that is never final."""
    comptime OUT_OF_MEMORY = Self(2)
    """An allocation or reservation could not be satisfied."""
    comptime IO = Self(7)
    """A socket or file could not be opened, read, written, or closed."""
    comptime MALFORMED = Self(9)
    """The peer supplied bytes that cannot be decoded as the expected protocol."""
    comptime INTERNAL = Self(10)
    """The library violated its contract, which points at a defect."""
    comptime OVERFLOW = Self(11)
    """The requested size exceeds the representable range."""
    comptime UNINITIALIZED = Self(12)
    """The call needs a handle that was never initialized."""
    comptime CONTENDED = Self(14)
    """The call was refused rather than waited for, like a submission to a full client."""
    comptime UNSUPPORTED = Self(16)
    """The build, backend, or machine does not implement the requested feature."""
    comptime INVALID_ARGUMENT = Self(17)
    """An argument is missing, out of range, or contradicts another argument."""
    comptime NOT_FOUND = Self(18)
    """The requested endpoint, header, or parameter does not exist."""
    comptime ALREADY_EXISTS = Self(19)
    """An endpoint with the same template and verb is already registered, or a request was answered."""
    comptime CONNECTION_FAILED = Self(20)
    """DNS lookup or connection establishment failed."""
    comptime CONNECTION_CLOSED = Self(21)
    """The connection closed before the exchange completed."""
    comptime TIMEOUT = Self(22)
    """The operation exceeded its time budget."""
    comptime HANDSHAKE_FAILED = Self(23)
    """The Noise handshake failed to authenticate or agree on keys."""
    comptime PEER_REJECTED = Self(24)
    """The peer authorizer declined the authenticated static key."""
    comptime WOULD_BLOCK = Self(25)
    """Nothing was ready: a nonblocking poll, a pull with no body bytes yet, or a lagging stream peer."""
    comptime LIBRARY_MISSING = Self(-1)
    """Nothing to `dlopen`; the binding's own."""
    comptime SYMBOL_MISSING = Self(-2)
    """The library loaded but does not export a symbol the binding needs; the binding's own."""
    comptime VERSION_MISMATCH = Self(-3)
    """The library loaded but reports another major version than the binding's; the binding's own."""

    @staticmethod
    def of(code: c_int) -> Self:
        """Lifts a raw `ucall_status_t`, keeping an unnamed one rather than guessing.

        Args:
            code: Whatever the C call reported, named by this build or not.

        Returns:
            The matching status, or one carrying the unrecognized code verbatim.
        """
        return Self(Int32(code))


@fieldwise_init
struct Outcome(ImplicitlyCopyable):
    """The `ucall_outcome_t` every verb reports through, laid out as the ABI declares it."""

    var status: c_int
    """The `ucall_status_t` the call reported."""
    var message: Optional[CString]
    """The library's own static message, or `None` when the call succeeded."""

    def __init__(out self):
        """Zeroes the slot, so a call that writes nothing still reads as a success."""
        self.status = c_int(0)
        self.message = None


@fieldwise_init
struct Error(Copyable, ImplicitlyCopyable, Writable):
    """What went wrong inside the library, and which entry point it was about."""

    var status: Status
    """Which class of failure the library reported."""
    var detail: StaticString
    """The entry point it was about, for a reader rather than for a branch."""
    var message: Optional[CString]
    """The library's own static message, or `None` when it carried none.

    Messages are static storage inside the shared object, so keeping the address costs nothing and
    outlives the call. `write_to` walks it; there is nothing to free.
    """
    var name: Optional[CString]
    """The library's spelling of `status` from `ucall_status_name`, or `None` where none named it."""
    var library: Optional[Library]
    """The library `message` and `name` live in, kept mapped for as long as the error is; Mojo would
    otherwise unload it at the last handle's last use, while the error is still being read."""

    def __init__(out self, status: Status, detail: StaticString):
        """A failure the binding caught before the library could name it.

        Args:
            status: Which class of failure it is.
            detail: The entry point or binding type it was about.
        """
        self.status = status
        self.detail = detail
        self.message = None
        self.name = None
        self.library = None

    def write_to(self, mut writer: Some[Writer]):
        """Writes the status name, the entry point, and the library's own message together.

        Args:
            writer: The sink the message is appended to.
        """
        writer.write("UCall: ")
        if case .Some(name) = self.name:
            writer.write(text_at(name))
        else:
            match self.status:
                case == Status.LIBRARY_MISSING:
                    writer.write("library-missing")
                case == Status.SYMBOL_MISSING:
                    writer.write("symbol-missing")
                case == Status.VERSION_MISMATCH:
                    writer.write("version-mismatch")
                case _:
                    writer.write("status ", self.status.code)
        writer.write(" [", self.detail, "]")
        if case .Some(message) = self.message:
            writer.write(": ", text_at(message))


def text_at(text: Optional[CString]) -> String:
    """Decodes a null-terminated C string the library owns, stopping at its terminator.

    Args:
        text: Where the bytes start; `None` reads as the empty string.

    Returns:
        A copy of the bytes, since the caller may keep it longer than it wants a raw address.
    """
    if case .Some(start) = text:
        var bytes = start.unsafe_bitcast[UInt8]()
        var length = 0
        while bytes[unsafe_offset=length] != 0:
            length += 1
        return String(unsafe_from_utf8=Span[UInt8, ImmUntrackedOrigin](unsafe_ptr=bytes, length=length))
    return String("")


# endregion Errors

# region Byte Runs


@fieldwise_init
struct BytesView[origin: ImmOrigin = ImmUntrackedOrigin](ImplicitlyCopyable, TrivialRegisterPassable):
    """A borrowed run of bytes and its length, `ucall_bytes_view_t` in C, never null-terminated.

    Crosses by value, which the two-word argument class handles on both x86-64 and AArch64.

    Parameters:
        origin: The borrowed storage, named so it outlives every call this view crosses.
    """

    var data: Pointer[Byte, Self.origin]
    """The first byte, borrowed for the duration of the call."""
    var length: c_size_t
    """How many bytes the run covers, since nothing terminates it."""

    @staticmethod
    def of[text_origin: ImmOrigin, //](text: StringSlice[text_origin]) -> BytesView[text_origin]:
        """Borrows a Mojo string's bytes, which the caller keeps alive across the call.

        Parameters:
            text_origin: The string's origin, inferred from the argument.

        Args:
            text: The characters to hand over.

        Returns:
            A view of exactly those bytes, with no terminator manufactured.
        """
        return BytesView[text_origin](text.unsafe_ptr(), c_size_t(text.byte_length()))

    @staticmethod
    def of[bytes_origin: ImmOrigin, //](bytes: Span[Byte, bytes_origin]) -> BytesView[bytes_origin]:
        """Borrows a run of raw bytes, such as a request body.

        Parameters:
            bytes_origin: The run's origin, inferred from the argument.

        Args:
            bytes: The bytes to hand over.

        Returns:
            A view of exactly those bytes.
        """
        return BytesView[bytes_origin](bytes.unsafe_ptr(), c_size_t(len(bytes)))

    @staticmethod
    def empty() -> BytesView[ImmUntrackedOrigin]:
        """A run of no bytes, which output slots hold until the library writes them.

        It points at a static empty string, since a `Pointer` is never null.

        Returns:
            A view of no bytes.
        """
        return BytesView.of(StaticString("")).arguments()

    def arguments(self) -> BytesView[ImmUntrackedOrigin]:
        """The same run with its borrow erased, as the one instantiation the ABI signatures name.

        Returns:
            A view of the same bytes, whose type no longer keeps their storage alive.
        """
        return BytesView[ImmUntrackedOrigin](self.data.unsafe_origin_cast[ImmUntrackedOrigin](), self.length)

    def span[target: Origin](self) -> Span[Byte, target]:
        """Reads a run the library wrote back as a span living as long as `target`.

        The library writes `{NULL, 0}` for an empty run, and a span of no bytes never reads its
        pointer, so the null needs no branch.

        Parameters:
            target: The owner whose lifetime bounds the bytes, such as a request or a response.

        Returns:
            The same bytes, borrowed from `target`.
        """
        return Span[Byte, target](
            unsafe_ptr=Pointer[Byte, target](unsafe_from_address=Int(self.data)), length=Int(self.length)
        )


# endregion Byte Runs

# region Enumerations


@fieldwise_init
struct Verb(Equatable, ImplicitlyCopyable, TrivialRegisterPassable):
    """An HTTP method, for routing and for client calls, `ucall_verb_t` in C."""

    var code: c_int
    """The raw `ucall_verb_t` value the ABI exchanges."""
    comptime UNKNOWN = Self(0)
    """Unrecognized or not yet parsed."""
    comptime GET = Self(1)
    """Retrieves a resource."""
    comptime POST = Self(2)
    """Creates a resource."""
    comptime PUT = Self(3)
    """Updates a resource."""
    comptime DELETE = Self(4)
    """Removes a resource."""
    comptime PATCH = Self(5)
    """Updates part of a resource."""
    comptime HEAD = Self(6)
    """Retrieves headers only."""
    comptime OPTIONS = Self(7)
    """Retrieves the supported methods."""
    comptime ANY = Self(8)
    """Matches every method; valid only when registering an endpoint."""


@fieldwise_init
struct Backend(Equatable, ImplicitlyCopyable, TrivialRegisterPassable):
    """A concrete I/O implementation, `ucall_io_backend_t` in C. `Library.io_backend_name` spells each one."""

    var code: c_int
    """The raw `ucall_io_backend_t` value the ABI exchanges."""
    comptime AUTOMATIC = Self(0)
    """The fastest backend this machine and its limits allow."""
    comptime POSIX = Self(1)
    """Blocking sockets and files, polled with `poll`, on any POSIX system."""
    comptime LINUX_EPOLLAIO = Self(2)
    """Linux epoll for sockets and Linux AIO for files, where io_uring is blocked."""
    comptime LINUX_URING612 = Self(3)
    """Linux io_uring as of 6.12, the older LTS line."""
    comptime LINUX_URING618 = Self(4)
    """Linux io_uring as of 6.18, the newer LTS line, with multishot receives."""
    comptime BSD_KQUEUE = Self(5)
    """BSD kqueue on FreeBSD, with FreeBSD AIO for files, and on macOS."""
    comptime WINDOWS_IOCP = Self(6)
    """I/O completion ports on Windows."""
    comptime WINDOWS_RIO = Self(7)
    """Registered I/O on Windows for stream sockets, beside a completion port for the rest."""


@fieldwise_init
struct CPUClass(Equatable, ImplicitlyCopyable, TrivialRegisterPassable):
    """A CPU kernel bundle, `ucall_cpu_class_t` in C. `Library.cpu_class_name` spells each one."""

    var code: c_int
    """The raw `ucall_cpu_class_t` value the ABI exchanges."""
    comptime UNKNOWN = Self(0)
    """No class requested: initialization picks the best class this machine runs."""
    comptime SERIAL = Self(1)
    """Portable kernels with no SIMD, which every machine runs."""
    comptime INTEL_HASWELL = Self(2)
    """AVX2 kernels, as on Intel Haswell."""
    comptime INTEL_SKYLAKE = Self(3)
    """Adds AVX-512 kernels, as on Intel Skylake-X."""
    comptime INTEL_ICELAKE = Self(4)
    """Adds Ice Lake's AVX-512 extensions and SHA."""
    comptime INTEL_ALDER = Self(5)
    """AVX2 kernels with SHA and no AVX-512, as on Intel Alder Lake."""
    comptime AWS_G2 = Self(6)
    """NEON kernels with the AES and SHA extensions, as on AWS Graviton2."""
    comptime AWS_G5 = Self(7)
    """As on AWS Graviton5, running the kernels of `AWS_G2`."""
    comptime MONOVERSIONED = Self(8)
    """The one class a monoversioned build compiles, over every capability it targets."""


@fieldwise_init
struct BodyDelivery(Equatable, ImplicitlyCopyable, TrivialRegisterPassable):
    """When an endpoint's handler runs, `ucall_body_delivery_t` in C."""

    var code: c_int
    """The raw `ucall_body_delivery_t` value the ABI exchanges."""
    comptime BUFFERED = Self(0)
    """Once the whole body is buffered."""
    comptime STREAMED = Self(1)
    """At headers time, the body pulled through `DetachedRequest.body_chunk`."""


@fieldwise_init
struct Security(Equatable, ImplicitlyCopyable, TrivialRegisterPassable):
    """The transport security of an interface or a call, `ucall_security_t` in C."""

    var code: c_int
    """The raw `ucall_security_t` value the ABI exchanges."""
    comptime NONE = Self(0)
    """No encryption, plain TCP."""
    comptime NOISE_XX = Self(1)
    """Trust on first use, needing an authorizer."""
    comptime NOISE_IK = Self(2)
    """The client knows the server's public key in advance."""
    comptime NOISE_KK = Self(3)
    """Both know each other's public keys in advance."""


@fieldwise_init
struct HTTPStatus(Equatable, ImplicitlyCopyable, TrivialRegisterPassable):
    """An HTTP status code a server sends and a client receives, `ucall_http_status_t` in C.

    Codes absent from the named constants are as valid as the named ones.
    """

    var code: UInt32
    """The numeric status code."""
    comptime OK = Self(200)
    """Request succeeded."""
    comptime CREATED = Self(201)
    """Resource created."""
    comptime NO_CONTENT = Self(204)
    """Success with an empty body."""
    comptime PARTIAL_CONTENT = Self(206)
    """Success with the requested range of the body."""
    comptime MOVED_PERMANENTLY = Self(301)
    """Resource has a new permanent URL."""
    comptime FOUND = Self(302)
    """Resource is temporarily at another URL."""
    comptime NOT_MODIFIED = Self(304)
    """Cached copy is still fresh."""
    comptime BAD_REQUEST = Self(400)
    """Malformed request syntax."""
    comptime UNAUTHORIZED = Self(401)
    """Authentication required or failed."""
    comptime FORBIDDEN = Self(403)
    """Authenticated, but not permitted."""
    comptime NOT_FOUND = Self(404)
    """No endpoint matches the request path."""
    comptime METHOD_NOT_ALLOWED = Self(405)
    """Endpoint exists, but not for this verb."""
    comptime TIMEOUT = Self(408)
    """Client took too long to send the request."""
    comptime CONFLICT = Self(409)
    """Request conflicts with the current resource state."""
    comptime PRECONDITION_FAILED = Self(412)
    """A request condition does not match the current resource."""
    comptime PAYLOAD_TOO_LARGE = Self(413)
    """Request body is too large."""
    comptime RANGE_NOT_SATISFIABLE = Self(416)
    """A requested byte range starts or ends past the end of the resource."""
    comptime TOO_MANY_REQUESTS = Self(429)
    """Rate limit exceeded."""
    comptime INTERNAL_ERROR = Self(500)
    """Unhandled failure inside an endpoint."""
    comptime NOT_IMPLEMENTED = Self(501)
    """Verb or feature not supported."""
    comptime BAD_GATEWAY = Self(502)
    """An upstream answered with something no HTTP peer would send."""
    comptime SERVICE_UNAVAILABLE = Self(503)
    """Server is overloaded or shutting down."""
    comptime GATEWAY_TIMEOUT = Self(504)
    """Upstream dependency timed out."""
    comptime VERSION_NOT_SUPPORTED = Self(505)
    """Request names an HTTP version the server does not speak."""


@fieldwise_init
struct PercentMode(Equatable, ImplicitlyCopyable, TrivialRegisterPassable):
    """Which part of a URL `Library.decode_percent` reads, as only a query spells a space '+'."""

    var code: c_int
    """The raw `ucall_percent_mode_t` value the ABI exchanges."""
    comptime PATH = Self(0)
    """A path, where '+' stays itself."""
    comptime QUERY = Self(1)
    """A query, where '+' is a space."""


@fieldwise_init
struct AddressFamily(Equatable, ImplicitlyCopyable, TrivialRegisterPassable):
    """The family of a peer's socket address, `ucall_address_family_t` in C, one byte wide."""

    var code: UInt8
    """The raw `ucall_address_family_t` value the ABI exchanges."""
    comptime UNKNOWN = Self(0)
    """No address was read for this peer."""
    comptime IPV4 = Self(1)
    """IPv4, in the first 4 bytes."""
    comptime IPV6 = Self(2)
    """IPv6, in all 16 bytes, with its scope."""
    comptime UNIX = Self(3)
    """A local AF_UNIX peer, with no address bytes."""


@fieldwise_init
struct PeerAddress(Defaultable, ImplicitlyCopyable):
    """A peer's socket address as its connection was accepted, `ucall_peer_address_t` in C."""

    var bytes: SIMD[DType.uint8, 16]
    """The address in network order: IPv4 in the first 4 bytes, IPv6 in all 16."""
    var scope: UInt32
    """The IPv6 scope, 0 otherwise."""
    var port: UInt16
    """The port in host order."""
    var family: AddressFamily
    """Which of the families the address belongs to."""
    var reserved: UInt8
    """Zero."""

    def __init__(out self):
        """No address, as a failed read leaves it."""
        self = Self(SIMD[DType.uint8, 16](0), 0, 0, AddressFamily.UNKNOWN, 0)


# endregion Enumerations

# region Logging


@fieldwise_init
struct LogLevel(Equatable, ImplicitlyCopyable, TrivialRegisterPassable):
    """Severity of a log line, from the most verbose up, `ucall_log_level_t` in C."""

    var code: c_int
    """The raw `ucall_log_level_t` value the ABI exchanges."""
    comptime DEBUG = Self(0)
    """Detail for debugging."""
    comptime INFO = Self(1)
    """Normal lifecycle events."""
    comptime WARNING = Self(2)
    """Something unexpected that the library recovered from."""
    comptime ERROR = Self(3)
    """An operation failed."""
    comptime FATAL = Self(4)
    """The server or client cannot continue."""


@fieldwise_init
struct LogFormat(Equatable, ImplicitlyCopyable, TrivialRegisterPassable):
    """Shape of each log line, `ucall_log_format_t` in C."""

    var code: c_int
    """The raw `ucall_log_format_t` value the ABI exchanges."""
    comptime HUMAN = Self(0)
    """Human-readable unit-normalized lines."""
    comptime JSON = Self(1)
    """Newline-delimited JSON documents."""


def _log_trampoline[
    State: AnyType, handler: def(LogLevel, StringSlice[ImmUntrackedOrigin], mut State) thin -> None
](level: c_int, line: BytesView[ImmUntrackedOrigin], context: Pointer[State, MutAnyOrigin]) abi("C"):
    """The `ucall_log_callback_t` of one log sink, instantiated per handler."""
    handler(LogLevel(level), StringSlice(unsafe_from_utf8=line.span[ImmUntrackedOrigin]()), context[])


@fieldwise_init
struct Log(Defaultable, ImplicitlyCopyable, TrivialRegisterPassable):
    """The single log sink of a client or a server, `ucall_log_t` in C; the default logs nothing."""

    var callback: Address
    """The `ucall_log_callback_t` every line at or above `level` goes to; `NULL_ADDRESS` logs nothing."""
    var context: Address
    """The state `callback` writes into, passed verbatim."""
    var format: LogFormat
    """Line format."""
    var level: LogLevel
    """Lines below this severity are never formatted."""

    def __init__(out self):
        """No sink, so the library stays silent."""
        self = Self(NULL_ADDRESS, NULL_ADDRESS, LogFormat.HUMAN, LogLevel.DEBUG)

    @staticmethod
    def to[
        State: AnyType, //, handler: def(LogLevel, StringSlice[ImmUntrackedOrigin], mut State) thin -> None
    ](mut state: State, level: LogLevel = LogLevel.DEBUG, format: LogFormat = LogFormat.HUMAN) -> Self:
        """A sink calling `handler` with every line at or above `level`, on whichever thread made it.

        Parameters:
            State: The state's type, inferred from the argument.
            handler: Receives the severity, the line borrowed for the call without a newline, and the state.

        Args:
            state: What `handler` writes into; it must outlive the client or server, which keep its address.
            level: Lines below this severity are never formatted.
            format: Line format.

        Returns:
            The sink, for a client's or a server's options.
        """
        return Self(
            _address_of(_log_trampoline[State, handler]), Int(Pointer(to=state)), format, level
        )


# endregion Logging

# region Peer Authorization


def _authorize_trampoline[
    handler: def(NoiseKey) thin -> Bool
](peer_static_key: Pointer[NoiseKey, ImmUntrackedOrigin], context: Address) abi("C") -> c_int:
    """The `ucall_peer_authorizer_t` of one authorizer, instantiated per handler."""
    if handler(peer_static_key[]):
        return c_int(Status.SUCCESS.code)
    return c_int(Status.PEER_REJECTED.code)


@fieldwise_init
struct PeerAuthorizer(Defaultable, ImplicitlyCopyable, TrivialRegisterPassable):
    """Whether a peer presenting an authenticated static key may proceed past the handshake.

    Noise XX learns keys during the handshake rather than in advance, so it needs one on both sides.
    The default admits nobody, as it installs no authorizer at all.
    """

    var callback: Address
    """The `ucall_peer_authorizer_t`; `NULL_ADDRESS` installs none."""
    var context: Address
    """Passed verbatim to `callback`; this binding's handlers need none."""

    def __init__(out self):
        """No authorizer."""
        self = Self(NULL_ADDRESS, NULL_ADDRESS)

    @staticmethod
    def to[handler: def(NoiseKey) thin -> Bool]() -> Self:
        """An authorizer admitting the peers whose authenticated static key `handler` accepts.

        Parameters:
            handler: Receives the peer's Curve25519 public key, and answers whether it may proceed.

        Returns:
            The authorizer, for an interface or a client's options.
        """
        return Self(_address_of(_authorize_trampoline[handler]), NULL_ADDRESS)


# endregion Peer Authorization

# region Signatures

comptime Entry[Arguments: AnyType] = def(Pointer[Arguments, MutAnyOrigin]) thin abi("C") -> None
"""Every struct entry point: one argument structure named after it, outputs written through its pointers."""

comptime Release = def(Address) thin abi("C") -> None
"""The positional `_free` family and `ucall_server_stop`; `NULL` is safe."""

comptime OutcomeStatus = def(Pointer[Outcome, MutAnyOrigin]) thin abi("C") -> c_int
"""`ucall_outcome_wait` and `ucall_outcome_status`: an outcome's status, the first once it is final."""

comptime NameOf = def(c_int) thin abi("C") -> Optional[CString]
"""The `_name` family: an enumerator's static spelling."""

comptime FromName = def(BytesView[ImmUntrackedOrigin]) thin abi("C") -> c_int
"""The `_from_name` family: reads a spelling back into its enumerator."""

comptime DecodePercent = def(
    BytesView[ImmUntrackedOrigin], Pointer[Byte, MutAnyOrigin], Pointer[c_size_t, MutAnyOrigin], c_int
) thin abi("C") -> c_int
"""`ucall_decode_percent`: decodes into a caller buffer at least as long as the input."""

comptime NoiseKeyGenerate = Entry[NoiseKeyGenerateArguments]
"""`ucall_noise_key_generate`."""
comptime NoiseKeyDerive = Entry[NoiseKeyDeriveArguments]
"""`ucall_noise_key_derive`."""

# endregion Signatures

# region Noise Keys


@fieldwise_init
struct NoiseKeyGenerateArguments(ImplicitlyCopyable):
    """`ucall_noise_key_generate_t`, laid out as the ABI declares it."""

    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var private_key: Pointer[NoiseKey, MutUntrackedOrigin]
    var public_key: Pointer[NoiseKey, MutUntrackedOrigin]


@fieldwise_init
struct NoiseKeyDeriveArguments(ImplicitlyCopyable):
    """`ucall_noise_key_derive_t`, laid out as the ABI declares it."""

    var outcome: Pointer[Outcome, MutUntrackedOrigin]
    var private_key: Pointer[NoiseKey, ImmUntrackedOrigin]
    var public_key: Pointer[NoiseKey, MutUntrackedOrigin]


# endregion Noise Keys

# region Deferred Replies


def _cross[Arguments: ImplicitlyCopyable & Deinitable, //](arguments: Arguments, entry: Entry[Arguments]):
    """Materializes one argument structure in a stack slot and hands its address to `entry`."""
    var slot = stack_allocation[1, Arguments]()
    slot[unsafe_offset=0] = arguments
    entry(slot.unsafe_origin_cast[MutAnyOrigin]())


struct Deferred(Movable):
    """A reply still sending a file or path part, which owns the outcome the event loop makes final.

    `status` reads `DEFERRED` until then without blocking, and `wait` blocks until the reply is
    final and raises its failure. Dropping one that is not final waits for it, so it belongs off the
    polling thread, which is the one finishing it. The descriptors its parts borrow stay open until
    it is final.
    """

    var library: Library
    """The loaded library, held so the wait can still reach `ucall_outcome_wait`."""
    var outcome: OwnedPointer[Outcome]
    """The outcome the event loop writes, on the heap since it outlives the verb."""
    var symbol: StaticString
    """The entry point the reply went through, carried into its failure."""

    def __init__(out self, library: Library, symbol: StaticString):
        """A pending outcome at a stable heap address, for a verb that may finish after it returns."""
        self.library = library
        self.outcome = OwnedPointer(Outcome())
        self.symbol = symbol

    def __deinit__(deinit self):
        """Waits until the reply is final, then frees its outcome. Calls `ucall_outcome_wait`."""
        _ = self.library.symbols().outcome_wait(self._outcome())
        _ = self.outcome^
        _ = self.library^

    def _outcome(self) -> Pointer[Outcome, MutAnyOrigin]:
        """The heap outcome, through the origin the event loop's writes need."""
        return Pointer[Outcome, MutAnyOrigin](unsafe_from_address=Int(Pointer(to=self.outcome[])))

    def status(self) -> Status:
        """`DEFERRED` until the reply is final, then its final status; never blocks. Calls `ucall_outcome_status`.

        Returns:
            The status the outcome holds.
        """
        return Status.of(self.library.symbols().outcome_status(self._outcome()))

    def wait(deinit self) raises Error:
        """Blocks until the reply is final, and raises its failure. Calls `ucall_outcome_wait`.

        Raises:
            `Error` carrying the reply's failure.
        """
        var outcome = self._outcome()
        _ = self.library.symbols().outcome_wait(outcome)
        var final = outcome[]
        var library = self.library
        _ = self.outcome^
        _ = self.library^
        library._check(final, self.symbol)


# endregion Deferred Replies
