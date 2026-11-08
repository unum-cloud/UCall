"""The loaded shared object and the one place a raw symbol address is ever touched.

The library is reached by `dlopen` rather than by linking, which is what lets a consumer build
without a single linker flag. Mojo's `@extern` cannot serve here: it resolves at link time, so a
symbol from a library that is only opened at run time is an undefined reference under both the JIT
and `lld`, and using it would put a link flag in every consumer's build.

Every entry point is resolved once, when the library loads, into a typed `thin abi("C")` function
pointer. `OwnedDLHandle.get_function` would run `dlsym` on every call and parameterises only on the
return type, leaving arguments unchecked; a request on the hot path can afford neither.

File: mojo/ucall/library.mojo
Author: Ash Vardanian
Date: November 8, 2026
"""

from std.ffi import OwnedDLHandle, __fn_type_is_cabi, c_int, c_size_t
from std.memory import ArcPointer, stack_allocation
from std.sys.info import CompilationTarget

from ucall.client import (
    ClientCallEntry,
    ClientInit,
    ClientResponseBody,
    ClientResponseField,
    ClientResponseFieldsCount,
    ClientResponseHeader,
    ClientTakeCompleted,
    ResponseStatus,
)
from ucall.server import (
    RequestCount,
    RequestVerb,
    ServerAddHttpBatchEndpoint,
    ServerAddHttpEndpoint,
    ServerBatchEndpointStatistics,
    ServerEventLoopStatistics,
    ServerInit,
    ServerReplyAppend,
    ServerReplyBegin,
    ServerReplyContent,
    ServerReplyEnd,
    ServerReplyError,
    ServerReplyVectored,
    ServerRequestField,
    ServerRequestFieldsCount,
    ServerRequestNamed,
    ServerRequestPart,
    ServerRequestPathSegment,
    ServerRequestPeer,
    ServerRequestView,
    ServerTakeBatch,
    ServerTakeBatches,
    ServerTakeCall,
    ServerTakeCalls,
)
from ucall.types import (
    Backend,
    BytesView,
    CPUClass,
    CString,
    DecodePercent,
    Error,
    FromName,
    NameOf,
    NoiseKey,
    NoiseKeyDerive,
    NoiseKeyDeriveArguments,
    NoiseKeyGenerate,
    NoiseKeyGenerateArguments,
    Outcome,
    OutcomeStatus,
    PercentMode,
    Release,
    Status,
    _cross,
    text_at,
)

comptime LIBRARY_FILE = StaticString(
    "libucall_shared.dylib" if CompilationTarget.is_macos() else "libucall_shared.so"
)
"""The loader already searches the environment's library directory, because `mojo build` bakes it
into the binary's runpath, so an unqualified name is enough for a library installed there."""

comptime BINDING_MAJOR = 1
"""The major version this binding was written against; a mismatch is refused at load."""

# region Signatures

comptime StaticText = def() thin abi("C") -> Optional[CString]
"""`ucall_version_name`: a static C string returned by value."""

comptime VersionOf = def(
    Pointer[c_int, MutAnyOrigin], Pointer[c_int, MutAnyOrigin], Pointer[c_int, MutAnyOrigin]
) thin abi("C") -> None
"""`ucall_version`: the linked library's major, minor and patch, written through three `int` pointers.

Typed pointers rather than `Address`: an `alloca` whose address crosses only as an integer argument
was measured reading back the value stored before the call."""

# endregion Signatures


@inline(.always)
def _resolve[
    Signature: TrivialRegisterPassable
](ref handle: OwnedDLHandle, name: StaticString) raises Error -> Signature:
    """One `dlsym`, checked once, typed from here on.

    `get_symbol` answers `Optional` where `get_function` aborts the process, which is what lets a
    stale library name the symbol it is missing instead of dying without a message.
    """
    comptime assert __fn_type_is_cabi[Signature](), 'the signature must carry abi("C")'
    if case .Some(address) = handle.get_symbol[NoneType](name):
        return Pointer(to=address).unsafe_bitcast[Signature]()[]
    raise Error(Status.SYMBOL_MISSING, name)


def _version(version: VersionOf) -> Tuple[Int, Int, Int]:
    """The linked library's major, minor and patch, read through `ucall_version`."""
    var parts = stack_allocation[3, c_int]().unsafe_origin_cast[MutAnyOrigin]()
    for part in range(3):
        parts[unsafe_offset=part] = c_int(0)
    version(parts, parts.unsafe_offset(1), parts.unsafe_offset(2))
    return (Int(parts[unsafe_offset=0]), Int(parts[unsafe_offset=1]), Int(parts[unsafe_offset=2]))


struct Symbols:
    """Every entry point the C ABI exports, resolved once when the library loads."""

    var version: VersionOf
    """`ucall_version`."""
    var version_name: StaticText
    """`ucall_version_name`."""
    var outcome_wait: OutcomeStatus
    """`ucall_outcome_wait`."""
    var outcome_status: OutcomeStatus
    """`ucall_outcome_status`."""
    var status_name: NameOf
    """`ucall_status_name`."""
    var status_from_name: FromName
    """`ucall_status_from_name`."""
    var io_backend_name: NameOf
    """`ucall_io_backend_name`."""
    var io_backend_from_name: FromName
    """`ucall_io_backend_from_name`."""
    var cpu_class_name: NameOf
    """`ucall_cpu_class_name`."""
    var cpu_class_from_name: FromName
    """`ucall_cpu_class_from_name`."""
    var decode_percent: DecodePercent
    """`ucall_decode_percent`."""
    var noise_key_generate: NoiseKeyGenerate
    """`ucall_noise_key_generate`."""
    var noise_key_derive: NoiseKeyDerive
    """`ucall_noise_key_derive`."""

    var server_init: ServerInit
    """`ucall_server_init`."""
    var server_free: Release
    """`ucall_server_free`."""
    var server_stop: Release
    """`ucall_server_stop`."""
    var server_take_call: ServerTakeCall
    """`ucall_server_take_call`."""
    var server_take_calls: ServerTakeCalls
    """`ucall_server_take_calls`."""
    var server_event_loop_statistics: ServerEventLoopStatistics
    """`ucall_server_event_loop_statistics`."""
    var server_take_batch: ServerTakeBatch
    """`ucall_server_take_batch`."""
    var server_take_batches: ServerTakeBatches
    """`ucall_server_take_batches`."""
    var server_batch_endpoint_statistics: ServerBatchEndpointStatistics
    """`ucall_server_batch_endpoint_statistics`."""
    var server_add_http_endpoint: ServerAddHttpEndpoint
    """`ucall_server_add_http_endpoint`."""
    var server_add_http_batch_endpoint: ServerAddHttpBatchEndpoint
    """`ucall_server_add_http_batch_endpoint`."""

    var server_request_verb: RequestVerb
    """`ucall_server_request_verb`."""
    var server_request_path: ServerRequestView
    """`ucall_server_request_path`."""
    var server_request_query: ServerRequestView
    """`ucall_server_request_query`."""
    var server_request_path_segments_count: RequestCount
    """`ucall_server_request_path_segments_count`."""
    var server_request_path_segment: ServerRequestPathSegment
    """`ucall_server_request_path_segment`."""
    var server_request_path_parameter: ServerRequestNamed
    """`ucall_server_request_path_parameter`."""
    var server_request_query_parameter: ServerRequestNamed
    """`ucall_server_request_query_parameter`."""
    var server_request_header: ServerRequestNamed
    """`ucall_server_request_header`."""
    var server_request_fields_count: ServerRequestFieldsCount
    """`ucall_server_request_fields_count`."""
    var server_request_field: ServerRequestField
    """`ucall_server_request_field`."""
    var server_request_peer: ServerRequestPeer
    """`ucall_server_request_peer`."""
    var server_request_body: ServerRequestView
    """`ucall_server_request_body`."""
    var server_request_body_chunk: ServerRequestView
    """`ucall_server_request_body_chunk`."""
    var server_request_parts_count: RequestCount
    """`ucall_server_request_parts_count`."""
    var server_request_part: ServerRequestPart
    """`ucall_server_request_part`."""

    var server_reply_content: ServerReplyContent
    """`ucall_server_reply_content`."""
    var server_reply_error: ServerReplyError
    """`ucall_server_reply_error`."""
    var server_reply_vectored: ServerReplyVectored
    """`ucall_server_reply_vectored`."""
    var server_reply_begin: ServerReplyBegin
    """`ucall_server_reply_begin`."""
    var server_reply_append: ServerReplyAppend
    """`ucall_server_reply_append`."""
    var server_reply_end: ServerReplyEnd
    """`ucall_server_reply_end`."""

    var client_init: ClientInit
    """`ucall_client_init`."""
    var client_free: Release
    """`ucall_client_free`."""
    var client_call: ClientCallEntry
    """`ucall_client_call`."""
    var client_take_completed: ClientTakeCompleted
    """`ucall_client_take_completed`."""
    var client_response_status: ResponseStatus
    """`ucall_client_response_status`."""
    var client_response_header: ClientResponseHeader
    """`ucall_client_response_header`."""
    var client_response_fields_count: ClientResponseFieldsCount
    """`ucall_client_response_fields_count`."""
    var client_response_field: ClientResponseField
    """`ucall_client_response_field`."""
    var client_response_body: ClientResponseBody
    """`ucall_client_response_body`."""
    var client_response_free: Release
    """`ucall_client_response_free`."""

    def __init__(out self, ref handle: OwnedDLHandle) raises Error:
        """Resolves every entry point at once, so no call ever pays for a `dlsym`.

        Args:
            handle: The opened library, borrowed only while the addresses are read out.

        Raises:
            With `SYMBOL_MISSING`, on the first symbol the loaded library does not export.
        """
        self.version = _resolve[VersionOf](handle, "ucall_version")
        self.version_name = _resolve[StaticText](handle, "ucall_version_name")
        self.outcome_wait = _resolve[OutcomeStatus](handle, "ucall_outcome_wait")
        self.outcome_status = _resolve[OutcomeStatus](handle, "ucall_outcome_status")
        self.status_name = _resolve[NameOf](handle, "ucall_status_name")
        self.status_from_name = _resolve[FromName](handle, "ucall_status_from_name")
        self.io_backend_name = _resolve[NameOf](handle, "ucall_io_backend_name")
        self.io_backend_from_name = _resolve[FromName](handle, "ucall_io_backend_from_name")
        self.cpu_class_name = _resolve[NameOf](handle, "ucall_cpu_class_name")
        self.cpu_class_from_name = _resolve[FromName](handle, "ucall_cpu_class_from_name")
        self.decode_percent = _resolve[DecodePercent](handle, "ucall_decode_percent")
        self.noise_key_generate = _resolve[NoiseKeyGenerate](handle, "ucall_noise_key_generate")
        self.noise_key_derive = _resolve[NoiseKeyDerive](handle, "ucall_noise_key_derive")

        self.server_init = _resolve[ServerInit](handle, "ucall_server_init")
        self.server_free = _resolve[Release](handle, "ucall_server_free")
        self.server_stop = _resolve[Release](handle, "ucall_server_stop")
        self.server_take_call = _resolve[ServerTakeCall](handle, "ucall_server_take_call")
        self.server_take_calls = _resolve[ServerTakeCalls](handle, "ucall_server_take_calls")
        self.server_event_loop_statistics = _resolve[ServerEventLoopStatistics](
            handle, "ucall_server_event_loop_statistics"
        )
        self.server_take_batch = _resolve[ServerTakeBatch](handle, "ucall_server_take_batch")
        self.server_take_batches = _resolve[ServerTakeBatches](handle, "ucall_server_take_batches")
        self.server_batch_endpoint_statistics = _resolve[ServerBatchEndpointStatistics](
            handle, "ucall_server_batch_endpoint_statistics"
        )
        self.server_add_http_endpoint = _resolve[ServerAddHttpEndpoint](handle, "ucall_server_add_http_endpoint")
        self.server_add_http_batch_endpoint = _resolve[ServerAddHttpBatchEndpoint](
            handle, "ucall_server_add_http_batch_endpoint"
        )

        self.server_request_verb = _resolve[RequestVerb](handle, "ucall_server_request_verb")
        self.server_request_path = _resolve[ServerRequestView](handle, "ucall_server_request_path")
        self.server_request_query = _resolve[ServerRequestView](handle, "ucall_server_request_query")
        self.server_request_path_segments_count = _resolve[RequestCount](
            handle, "ucall_server_request_path_segments_count"
        )
        self.server_request_path_segment = _resolve[ServerRequestPathSegment](
            handle, "ucall_server_request_path_segment"
        )
        self.server_request_path_parameter = _resolve[ServerRequestNamed](
            handle, "ucall_server_request_path_parameter"
        )
        self.server_request_query_parameter = _resolve[ServerRequestNamed](
            handle, "ucall_server_request_query_parameter"
        )
        self.server_request_header = _resolve[ServerRequestNamed](handle, "ucall_server_request_header")
        self.server_request_fields_count = _resolve[ServerRequestFieldsCount](
            handle, "ucall_server_request_fields_count"
        )
        self.server_request_field = _resolve[ServerRequestField](handle, "ucall_server_request_field")
        self.server_request_peer = _resolve[ServerRequestPeer](handle, "ucall_server_request_peer")
        self.server_request_body = _resolve[ServerRequestView](handle, "ucall_server_request_body")
        self.server_request_body_chunk = _resolve[ServerRequestView](handle, "ucall_server_request_body_chunk")
        self.server_request_parts_count = _resolve[RequestCount](handle, "ucall_server_request_parts_count")
        self.server_request_part = _resolve[ServerRequestPart](handle, "ucall_server_request_part")

        self.server_reply_content = _resolve[ServerReplyContent](handle, "ucall_server_reply_content")
        self.server_reply_error = _resolve[ServerReplyError](handle, "ucall_server_reply_error")
        self.server_reply_vectored = _resolve[ServerReplyVectored](handle, "ucall_server_reply_vectored")
        self.server_reply_begin = _resolve[ServerReplyBegin](handle, "ucall_server_reply_begin")
        self.server_reply_append = _resolve[ServerReplyAppend](handle, "ucall_server_reply_append")
        self.server_reply_end = _resolve[ServerReplyEnd](handle, "ucall_server_reply_end")

        self.client_init = _resolve[ClientInit](handle, "ucall_client_init")
        self.client_free = _resolve[Release](handle, "ucall_client_free")
        self.client_call = _resolve[ClientCallEntry](handle, "ucall_client_call")
        self.client_take_completed = _resolve[ClientTakeCompleted](handle, "ucall_client_take_completed")
        self.client_response_status = _resolve[ResponseStatus](handle, "ucall_client_response_status")
        self.client_response_header = _resolve[ClientResponseHeader](handle, "ucall_client_response_header")
        self.client_response_fields_count = _resolve[ClientResponseFieldsCount](
            handle, "ucall_client_response_fields_count"
        )
        self.client_response_field = _resolve[ClientResponseField](handle, "ucall_client_response_field")
        self.client_response_body = _resolve[ClientResponseBody](handle, "ucall_client_response_body")
        self.client_response_free = _resolve[Release](handle, "ucall_client_response_free")


struct _Loaded:
    """The handle and its symbols, kept together so neither outlives the other."""

    var handle: OwnedDLHandle
    var symbols: Symbols

    def __init__(out self) raises Error:
        try:
            self.handle = OwnedDLHandle(String(LIBRARY_FILE))
        except:
            raise Error(Status.LIBRARY_MISSING, LIBRARY_FILE)
        var major = _version(_resolve[VersionOf](self.handle, "ucall_version"))[0]
        if major != BINDING_MAJOR:
            raise Error(Status.VERSION_MISMATCH, "ucall_version")
        self.symbols = Symbols(self.handle)


struct Library(ImplicitlyCopyable):
    """A reference to the loaded library, cheap to copy and shared by everything it creates.

    Every handle carries one, which is what keeps the shared object mapped for as long as anything
    can still call into it.
    """

    var shared: ArcPointer[_Loaded]
    """The handle and its symbols, refcounted so the last holder unmaps the object."""

    def __init__(out self) raises Error:
        """Opens the shared object and resolves it, which every handle then shares.

        Raises:
            With `LIBRARY_MISSING`, when nothing is on the loader path, with `VERSION_MISMATCH`
            when what loaded is another major version, or with `SYMBOL_MISSING` when it does not
            export an entry point the binding needs.
        """
        self.shared = ArcPointer(_Loaded())

    @inline(.always)
    def symbols(self) -> ref[origin_of(self.shared[].symbols)] Symbols:
        """The resolved entry points, borrowed rather than copied on every call.

        Returns:
            A reference that stays valid for as long as this `Library` is held.
        """
        return self.shared[].symbols

    def version(self) -> Tuple[Int, Int, Int]:
        """The linked library's major, minor and patch. Calls `ucall_version`.

        Returns:
            The three numbers, which may differ from the ones this binding was written against.
        """
        return _version(self.symbols().version)

    def version_name(self) -> String:
        """The linked library's version, including a release-candidate suffix. Calls `ucall_version_name`.

        Returns:
            The version string the shared object reports for itself.
        """
        return text_at(self.symbols().version_name())

    def status_name(self, status: Status) -> String:
        """The library's spelling of a status, as `OUT_OF_MEMORY` spells "out-of-memory".
        Calls `ucall_status_name`."""
        return text_at(self.symbols().status_name(c_int(status.code)))

    def status_from_name(self, name: StringSlice) -> Status:
        """Reads a spelling back; `INVALID_ARGUMENT` when unrecognized. Calls `ucall_status_from_name`."""
        return Status.of(self.symbols().status_from_name(BytesView.of(name).arguments()))

    def io_backend_name(self, backend: Backend) -> String:
        """The library's spelling of an I/O backend, as `LINUX_URING618` spells "linux-uring618".
        Calls `ucall_io_backend_name`."""
        return text_at(self.symbols().io_backend_name(backend.code))

    def io_backend_from_name(self, name: StringSlice) -> Backend:
        """Reads a spelling back; `AUTOMATIC` when unrecognized. Calls `ucall_io_backend_from_name`."""
        return Backend(self.symbols().io_backend_from_name(BytesView.of(name).arguments()))

    def cpu_class_name(self, cpu_class: CPUClass) -> String:
        """The library's spelling of a CPU class, as `AWS_G5` spells "aws-g5". Calls `ucall_cpu_class_name`."""
        return text_at(self.symbols().cpu_class_name(cpu_class.code))

    def cpu_class_from_name(self, name: StringSlice) -> CPUClass:
        """Reads a spelling back; `UNKNOWN` when unrecognized. Calls `ucall_cpu_class_from_name`."""
        return CPUClass(self.symbols().cpu_class_from_name(BytesView.of(name).arguments()))

    def decode_percent(self, encoded: Span[Byte, _], mode: PercentMode) raises Error -> List[Byte]:
        """Decodes the `%XX` escapes of `encoded`, like a query value, and '+' as a space in `QUERY`
        mode. Calls `ucall_decode_percent`.

        Args:
            encoded: A path or a query value, still percent-encoded.
            mode: Whether a '+' is itself or a space.

        Returns:
            The decoded bytes.

        Raises:
            `Error` with `INVALID_ARGUMENT` on a '%' without two hexadecimal digits.
        """
        var decoded = List[Byte](length=max(len(encoded), 1), fill=0)
        var length = stack_allocation[1, c_size_t]().unsafe_origin_cast[MutAnyOrigin]()
        length[unsafe_offset=0] = c_size_t(0)
        var status = self.symbols().decode_percent(
            BytesView.of(encoded).arguments(),
            decoded.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin](),
            length,
            mode.code,
        )
        if status != c_int(0):
            raise Error(Status.of(status), "ucall_decode_percent")
        decoded.resize(Int(length[unsafe_offset=0]), 0)
        return decoded^

    def generate_noise_keypair(self) raises Error -> Tuple[NoiseKey, NoiseKey]:
        """Draws a fresh static keypair from the operating system's entropy. Calls `ucall_noise_key_generate`.

        Returns:
            The private key, then the public key matching it.

        Raises:
            `Error` if the operating system offers no entropy.
        """
        var keys = stack_allocation[2, NoiseKey]().unsafe_origin_cast[MutAnyOrigin]()
        var outcome = stack_allocation[1, Outcome]().unsafe_origin_cast[MutAnyOrigin]()
        outcome[unsafe_offset=0] = Outcome()
        _cross(
            NoiseKeyGenerateArguments(
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                keys.unsafe_origin_cast[MutUntrackedOrigin](),
                keys.unsafe_offset(1).unsafe_origin_cast[MutUntrackedOrigin](),
            ),
            self.symbols().noise_key_generate,
        )
        self._check(outcome[unsafe_offset=0], "ucall_noise_key_generate")
        return (keys[unsafe_offset=0], keys[unsafe_offset=1])

    def derive_noise_public_key(self, private_key: NoiseKey) raises Error -> NoiseKey:
        """The public key of a stored private key, as peers see it during the handshake.
        Calls `ucall_noise_key_derive`.

        Args:
            private_key: The secret scalar.

        Returns:
            The matching Curve25519 public key.

        Raises:
            `Error` if the library refuses the key.
        """
        var keys = stack_allocation[2, NoiseKey]().unsafe_origin_cast[MutAnyOrigin]()
        keys[unsafe_offset=0] = private_key
        var outcome = stack_allocation[1, Outcome]().unsafe_origin_cast[MutAnyOrigin]()
        outcome[unsafe_offset=0] = Outcome()
        _cross(
            NoiseKeyDeriveArguments(
                outcome.unsafe_origin_cast[MutUntrackedOrigin](),
                Pointer[NoiseKey, ImmUntrackedOrigin](unsafe_from_address=Int(keys)),
                keys.unsafe_offset(1).unsafe_origin_cast[MutUntrackedOrigin](),
            ),
            self.symbols().noise_key_derive,
        )
        self._check(outcome[unsafe_offset=0], "ucall_noise_key_derive")
        return keys[unsafe_offset=1]

    def _error(self, outcome: Outcome, symbol: StaticString) -> Error:
        """The failure a final outcome reports, its status spelled by the library's own table."""
        var status = Status.of(outcome.status)
        return Error(status, symbol, outcome.message, self.symbols().status_name(c_int(status.code)), self)

    def _check(self, outcome: Outcome, symbol: StaticString) raises Error:
        """Raises the failure a final outcome reports, and returns on success."""
        if outcome.status != c_int(0):
            raise self._error(outcome, symbol)
