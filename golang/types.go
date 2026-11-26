// Shared vocabulary of servers and clients: statuses, calls, names, keys and log sinks.
//
// File: golang/types.go
// Author: Ash Vardanian
// Date: November 18, 2026

package ucall

import (
	"fmt"
	"runtime"
	"runtime/cgo"
	"time"
	"unsafe"
)

/*
#cgo CFLAGS: -I${SRCDIR}/../c
#cgo LDFLAGS: -lucall_static
#cgo linux LDFLAGS: -luring -lstdc++ -lpthread -lm
#cgo darwin LDFLAGS: -lc++
#cgo freebsd LDFLAGS: -lc++ -lpthread
#cgo windows LDFLAGS: -lstdc++ -lbcrypt -lws2_32 -lmswsock -lntdll -liphlpapi

// A function is noescape when C keeps none of its Go pointers past the call, and nocallback when
// its argument structure carries no callback field: an executor runs only the callbacks of the call
// that names them.
#cgo noescape ucall_outcome_status
#cgo nocallback ucall_outcome_status
#cgo noescape ucall_outcome_wait
#cgo nocallback ucall_outcome_wait
#cgo noescape ucall_status_from_name
#cgo nocallback ucall_status_from_name
#cgo noescape ucall_io_backend_from_name
#cgo nocallback ucall_io_backend_from_name
#cgo noescape ucall_cpu_class_from_name
#cgo nocallback ucall_cpu_class_from_name
#cgo noescape ucall_decode_percent
#cgo nocallback ucall_decode_percent
#cgo noescape ucall_noise_key_generate
#cgo nocallback ucall_noise_key_generate
#cgo noescape ucall_noise_key_derive
#cgo nocallback ucall_noise_key_derive

#include "shim.h"
*/
import "C"

// region: Errors

// Status names what went wrong, in a vocabulary shared by the library and by this binding.
// Validation performed here before a call crosses reports the status the library would have
// reported for the same fault.
//
// A Status is an error, so errors.Is(err, ucall.StatusConnectionFailed) matches any failure
// carrying it.
type Status int32

// The statuses a call ends in. Only Deferred.Status reports StatusDeferred, the one status that is
// not final.
const (
	// StatusSuccess means the call completed and carries no message.
	StatusSuccess Status = C.ucall_status_success_k
	// StatusDeferred means a submitted call is not final yet.
	StatusDeferred Status = C.ucall_status_deferred_k
	// StatusOutOfMemory means an allocation or reservation could not be satisfied.
	StatusOutOfMemory Status = C.ucall_status_out_of_memory_k
	// StatusIO means a socket or file could not be opened, read, written or closed.
	StatusIO Status = C.ucall_status_io_k
	// StatusMalformed means the peer sent bytes that do not decode as the expected protocol.
	StatusMalformed Status = C.ucall_status_malformed_k
	// StatusInternal means the library violated its contract, which points at a defect.
	StatusInternal Status = C.ucall_status_internal_k
	// StatusOverflow means a size exceeds the representable range.
	StatusOverflow Status = C.ucall_status_overflow_k
	// StatusUninitialized means the call needs a handle that was never made or is closed.
	StatusUninitialized Status = C.ucall_status_uninitialized_k
	// StatusContended means the call was refused rather than waited for.
	StatusContended Status = C.ucall_status_contended_k
	// StatusUnsupported means the build, backend or machine lacks the feature.
	StatusUnsupported Status = C.ucall_status_unsupported_k
	// StatusInvalidArgument means an argument is missing, out of range or contradicts another.
	StatusInvalidArgument Status = C.ucall_status_invalid_argument_k
	// StatusNotFound means the endpoint, header or parameter does not exist.
	StatusNotFound Status = C.ucall_status_not_found_k
	// StatusAlreadyExists means an endpoint of the same template and verb is registered, or a
	// request was already answered.
	StatusAlreadyExists Status = C.ucall_status_already_exists_k
	// StatusConnectionFailed means a lookup or a connection attempt failed.
	StatusConnectionFailed Status = C.ucall_status_connection_failed_k
	// StatusConnectionClosed means the connection closed before the exchange completed.
	StatusConnectionClosed Status = C.ucall_status_connection_closed_k
	// StatusTimeout means the operation exceeded its time budget.
	StatusTimeout Status = C.ucall_status_timeout_k
	// StatusHandshakeFailed means the Noise handshake failed to authenticate or agree on keys.
	StatusHandshakeFailed Status = C.ucall_status_handshake_failed_k
	// StatusPeerRejected means the peer authorizer declined the authenticated static key.
	StatusPeerRejected Status = C.ucall_status_peer_rejected_k
	// StatusWouldBlock means a nonblocking poll or pull had no progress to report.
	StatusWouldBlock Status = C.ucall_status_would_block_k
)

// String renders the status as the library spells it, such as "connection-failed".
func (status Status) String() string {
	return C.GoString(C.ucall_status_name(C.ucall_status_t(status)))
}

// Error implements the error interface, so a bare Status is an errors.Is target.
func (status Status) Error() string { return status.String() }

// StatusFromName reads a status back from the spelling String gives it.
func StatusFromName(name string) (Status, error) {
	var status C.ucall_status_t
	if refusal := C.ucall_status_from_name(view(name), &status); refusal != C.ucall_status_success_k {
		return StatusInternal, fail(Status(refusal), "not a status name")
	}
	return Status(status), nil
}

// Error is one failed call: a status every caller can branch on, and the detail the status
// cannot carry. Reach the status with errors.Is or errors.As.
type Error struct {
	Status  Status
	Message string
}

// Error implements the error interface.
func (failure *Error) Error() string {
	return fmt.Sprintf("ucall: %s: %s", failure.Status, failure.Message)
}

// Unwrap exposes the status, which is what errors.Is compares.
func (failure *Error) Unwrap() error { return failure.Status }

// fail builds the failure this binding reports for a fault it caught before the boundary.
func fail(status Status, message string) *Error {
	return &Error{Status: status, Message: message}
}

// check turns a final outcome into a Go error. Messages are static library storage and need no
// deallocation, so the copy is the only cost.
func check(outcome C.ucall_outcome_t) error {
	if outcome.status == C.ucall_status_success_k {
		return nil
	}
	return &Error{Status: Status(outcome.status), Message: C.GoString(outcome.message)}
}

// endregion: Errors

// region: Calls

// slots is what the library reads and writes for every verb: the outcome, and the handles its
// callbacks reach Go through.
type slots struct {
	outcome C.ucall_outcome_t
	handles [2]cgo.Handle
}

// frame is one call's slots, argument structure and result in a single pinned allocation, whose
// only Go pointers are those the arguments hold, every one of them pinned until the call settles.
type frame[Arguments, Result any] struct {
	slots
	arguments Arguments
	result    Result
}

// call is one verb crossing into the library: the pins that keep every Go pointer its argument
// structure carries in place until the call is final, and the slots it reports through. cgo lets C
// keep a Go pointer only while it is pinned, and pinning is also what keeps every pointee on the
// heap, which the noescape promises rely on.
type call struct {
	pinner runtime.Pinner
	slots  *slots
	// arguments is the frame's argument structure, cleared once the call is final, so a settled
	// frame holds no Go pointer and its outcome may still cross to C unpinned.
	arguments []byte
}

// callWithResult is a call and the slot its result lands in, which the library writes in place.
type callWithResult[Result any] struct {
	call
	result *Result
}

// open pins a fresh frame and hands back its argument structure, which a verb fills and passes to
// C; verbs refuse before opening, so a refusal pins and allocates nothing. The arguments live in
// the frame because cgo moves to the heap whatever a C function that may call back into Go reaches.
func open[Arguments, Result any](opened *callWithResult[Result]) *Arguments {
	frame := new(frame[Arguments, Result])
	opened.pinner.Pin(frame)
	opened.slots, opened.result = &frame.slots, &frame.result
	opened.arguments = unsafe.Slice((*byte)(unsafe.Pointer(&frame.arguments)), unsafe.Sizeof(frame.arguments))
	return &frame.arguments
}

// outcome is where the library reports the call's status.
func (call *call) outcome() *C.ucall_outcome_t { return &call.slots.outcome }

// status reads the outcome word without waiting.
func (call *call) status() Status {
	return Status(C.ucall_outcome_status(call.outcome()))
}

// settle waits until the call is final, releases everything it pinned, and reports its failure, the
// same every time it is asked.
func (call *call) settle() error {
	if call.status() == StatusDeferred {
		C.ucall_outcome_wait(call.outcome())
	}
	for slot, handle := range call.slots.handles {
		if handle != 0 {
			handle.Delete()
			call.slots.handles[slot] = 0
		}
	}
	clear(call.arguments)
	call.pinner.Unpin()
	return check(call.slots.outcome)
}

// block settles the call a verb opened and hands back its result, or the verb's refusal.
func block[Result any](call *callWithResult[Result], refusal error) (Result, error) {
	var none Result
	if refusal != nil {
		return none, refusal
	}
	if err := call.settle(); err != nil {
		return none, err
	}
	return *call.result, nil
}

// configOf reads a nil config as the zero one, by value, so generic verbs allocate nothing for it.
func configOf[Config any](config *Config) Config {
	var options Config
	if config != nil {
		options = *config
	}
	return options
}

// pin keeps a Go object in place until the call is final and hands back its address. It takes no
// type parameter, since a generic call inlined into a generic verb reaches its callee through a
// dictionary, and escape analysis then moves the verb's call to the heap.
func (call *call) pin(pointer unsafe.Pointer) unsafe.Pointer {
	call.pinner.Pin(pointer)
	return pointer
}

// pinSlice pins the backing array of a slice of length elements at data until the call is final,
// and answers nil for an empty slice.
func (call *call) pinSlice(data unsafe.Pointer, length int) unsafe.Pointer {
	if length == 0 {
		return nil
	}
	return call.pin(data)
}

// view passes a string to a call that only reads it before returning.
func view(text string) C.ucall_bytes_view_t {
	view := C.ucall_bytes_view_t{data: (*C.uint8_t)(unsafe.Pointer(unsafe.StringData(text)))}
	// cgo names the length's typedef apart from size_t, though the two are as wide.
	*(*C.size_t)(unsafe.Pointer(&view.length)) = C.size_t(len(text))
	return view
}

// Deferred is a submitted call, which holds its outcome and inputs until it is final, owned by the
// one goroutine that polls or waits on it. Status polls without blocking, Wait blocks until the
// call is final and hands back its result, and Close waits the same way and drops it. A Deferred
// dropped without Wait or Close is released by the collector once the call is final, never
// blocking on it: until then every later collection checks it again.
type Deferred[Result any] struct {
	call    callWithResult[Result]
	cleanup runtime.Cleanup
}

// submitted hands the call a verb opened to its caller, who waits on it or closes it, or drops it
// to the collector; a verb's refusal comes back instead, with nothing submitted.
func submitted[Result any](deferred *Deferred[Result], refusal error) (*Deferred[Result], error) {
	if refusal != nil {
		return nil, refusal
	}
	deferred.cleanup = runtime.AddCleanup(deferred, release, deferred.call.call)
	return deferred, nil
}

// release settles a dropped call once it is final, and otherwise arms itself again for the next
// collection, since the collector's goroutine must not block.
func release(call call) {
	if call.status() == StatusDeferred {
		runtime.AddCleanup(&call, release, call)
		return
	}
	_ = call.settle()
}

// Status reports StatusDeferred until the call is final, then its final status, without blocking.
func (deferred *Deferred[Result]) Status() Status { return deferred.call.status() }

// Wait blocks until the call is final, releases its pins, then hands back its result, the same
// every time it is asked.
func (deferred *Deferred[Result]) Wait() (Result, error) {
	deferred.cleanup.Stop()
	return block(&deferred.call, nil)
}

// Close blocks until the call is final, releases its pins, and reports the call's failure. It is
// idempotent and safe after Wait.
func (deferred *Deferred[Result]) Close() error {
	deferred.cleanup.Stop()
	return deferred.call.settle()
}

// endregion: Calls

// region: Helpers

// bytes passes a byte slab as the view the C interface reads, with no terminator and no copy.
func (call *call) bytes(bytes []byte) C.ucall_bytes_view_t {
	return C.ucall_bytes_view_t{
		data:   (*C.ucall_byte_t)(call.pinSlice(unsafe.Pointer(unsafe.SliceData(bytes)), len(bytes))),
		length: C.size_t(len(bytes)),
	}
}

// text views a Go string as the counted bytes every verb reads. The string is never terminated,
// by contract, so nothing is copied and nothing is freed.
func (call *call) text(text string) C.ucall_bytes_view_t {
	if len(text) == 0 {
		return C.ucall_bytes_view_t{}
	}
	return C.ucall_bytes_view_t{
		data:   (*C.ucall_byte_t)(call.pin(unsafe.Pointer(unsafe.StringData(text)))),
		length: C.size_t(len(text)),
	}
}

// texts passes a run of strings as the array of views a header or directory list takes.
func (call *call) texts(texts []string) (*C.ucall_bytes_view_t, C.size_t) {
	if len(texts) == 0 {
		return nil, 0
	}
	views := make([]C.ucall_bytes_view_t, len(texts))
	for position, text := range texts {
		views[position] = call.text(text)
	}
	return (*C.ucall_bytes_view_t)(call.pinSlice(unsafe.Pointer(unsafe.SliceData(views)), len(views))), C.size_t(len(views))
}

// viewed views bytes the library owns, valid as long as the library says.
func viewed(view C.ucall_bytes_view_t) []byte {
	if view.length == 0 {
		return nil
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(view.data)), int(view.length))
}

// microseconds converts a duration into the whole microseconds every timeout field takes.
func microseconds(duration time.Duration) C.size_t {
	return C.size_t(duration / time.Microsecond)
}

// contextOf passes a handle to a C callback as its opaque context, which is no Go pointer.
func contextOf(handle cgo.Handle) unsafe.Pointer {
	return C.ucall_go_context(C.uintptr_t(handle))
}

// handled reads back the value behind a callback's opaque context.
func handled[Value any](context unsafe.Pointer) Value {
	return cgo.Handle(uintptr(context)).Value().(Value)
}

// endregion: Helpers

// region: Names

// Version reports the version of the linked library, a release-candidate suffix included.
func Version() string { return C.GoString(C.ucall_version_name()) }

// Backend is a concrete I/O implementation; BackendAutomatic picks the fastest one available.
type Backend int32

// The I/O backends a server or a client may ask for.
const (
	// BackendAutomatic picks the fastest backend the machine and its limits allow.
	BackendAutomatic Backend = C.ucall_io_backend_automatic_k
	// BackendPOSIX polls blocking sockets and files with poll, on any POSIX system.
	BackendPOSIX Backend = C.ucall_io_backend_posix_k
	// BackendLinuxEpollAIO runs epoll for sockets and Linux AIO for files.
	BackendLinuxEpollAIO Backend = C.ucall_io_backend_linux_epollaio_k
	// BackendLinuxUring612 runs io_uring as Linux 6.12 provides it.
	BackendLinuxUring612 Backend = C.ucall_io_backend_linux_uring612_k
	// BackendLinuxUring618 runs io_uring as Linux 6.18 provides it, with multishot receives.
	BackendLinuxUring618 Backend = C.ucall_io_backend_linux_uring618_k
	// BackendBSDKqueue runs kqueue on FreeBSD and macOS.
	BackendBSDKqueue Backend = C.ucall_io_backend_bsd_kqueue_k
	// BackendWindowsIOCP runs I/O completion ports on Windows.
	BackendWindowsIOCP Backend = C.ucall_io_backend_windows_iocp_k
	// BackendWindowsRIO runs Registered I/O for stream sockets on Windows.
	BackendWindowsRIO Backend = C.ucall_io_backend_windows_rio_k
)

// String renders the backend's stable name, such as "linux-uring618".
func (backend Backend) String() string {
	return C.GoString(C.ucall_io_backend_name(C.ucall_io_backend_t(backend)))
}

// BackendFromName reads a backend back from its stable name, "automatic" included.
func BackendFromName(name string) (Backend, error) {
	var backend C.ucall_io_backend_t
	if refusal := C.ucall_io_backend_from_name(view(name), &backend); refusal != C.ucall_status_success_k {
		return BackendAutomatic, fail(Status(refusal), "not an I/O backend name")
	}
	return Backend(backend), nil
}

// CPUClass is a bundle of CPU kernels; CPUClassUnknown sets no ceiling.
type CPUClass int32

// The CPU classes a ceiling may name.
const (
	// CPUClassUnknown sets no ceiling, picking the newest class the machine runs.
	CPUClassUnknown CPUClass = C.ucall_cpu_class_unknown_k
	// CPUClassSerial runs portable kernels with no SIMD on every machine.
	CPUClassSerial CPUClass = C.ucall_cpu_class_serial_k
	// CPUClassMonoversioned is the one class a monoversioned build compiles.
	CPUClassMonoversioned CPUClass = C.ucall_cpu_class_monoversioned_k
	// CPUClassIntelHaswell runs AVX2 kernels.
	CPUClassIntelHaswell CPUClass = C.ucall_cpu_class_intel_haswell_k
	// CPUClassIntelSkylake adds AVX-512 kernels.
	CPUClassIntelSkylake CPUClass = C.ucall_cpu_class_intel_skylake_k
	// CPUClassIntelIcelake adds Ice Lake's AVX-512 extensions and SHA.
	CPUClassIntelIcelake CPUClass = C.ucall_cpu_class_intel_icelake_k
	// CPUClassIntelAlder runs AVX2 kernels with SHA and no AVX-512.
	CPUClassIntelAlder CPUClass = C.ucall_cpu_class_intel_alder_k
	// CPUClassAWSG2 runs NEON kernels with the AES and SHA extensions.
	CPUClassAWSG2 CPUClass = C.ucall_cpu_class_aws_g2_k
	// CPUClassAppleM4 adds timed waits to the Graviton5 kernels.
	CPUClassAppleM4 CPUClass = C.ucall_cpu_class_apple_m4_k
	// CPUClassAWSG5 runs the Graviton2 kernels with newer atomics.
	CPUClassAWSG5 CPUClass = C.ucall_cpu_class_aws_g5_k
	// CPUClassAlibabaC930 runs RVV kernels with Zawrs waits and Zacas compare-and-swap.
	CPUClassAlibabaC930 CPUClass = C.ucall_cpu_class_alibaba_c930_k
	// CPUClassIBMPower10 runs VSX kernels with short pauses and store atomics.
	CPUClassIBMPower10 CPUClass = C.ucall_cpu_class_ibm_power10_k
)

// String renders the class's stable name, such as "intel-icelake".
func (class CPUClass) String() string {
	return C.GoString(C.ucall_cpu_class_name(C.ucall_cpu_class_t(class)))
}

// CPUClassFromName reads a class back from its stable name, "unknown" included.
func CPUClassFromName(name string) (CPUClass, error) {
	var class C.ucall_cpu_class_t
	if refusal := C.ucall_cpu_class_from_name(view(name), &class); refusal != C.ucall_status_success_k {
		return CPUClassUnknown, fail(Status(refusal), "not a CPU class name")
	}
	return CPUClass(class), nil
}

// PercentMode says whether a '+' decodes as itself, in a path, or as a space, in a query.
type PercentMode int32

// The parts of a URL DecodePercent reads.
const (
	// PercentPath decodes a path, where '+' stays itself.
	PercentPath PercentMode = C.ucall_percent_path_k
	// PercentQuery decodes a query value, where '+' is a space.
	PercentQuery PercentMode = C.ucall_percent_query_k
)

// DecodePercent decodes the percent escapes of a path or a query value, which requests hold still
// encoded, into a new slice.
func DecodePercent(encoded []byte, mode PercentMode) ([]byte, error) {
	decoded := make([]byte, len(encoded))
	var length C.size_t
	view := C.ucall_bytes_view_t{data: (*C.ucall_byte_t)(unsafe.Pointer(unsafe.SliceData(encoded))), length: C.size_t(len(encoded))}
	target := (*C.ucall_byte_t)(unsafe.Pointer(unsafe.SliceData(decoded)))
	if refusal := C.ucall_decode_percent(view, target, &length, C.ucall_percent_mode_t(mode)); refusal != C.ucall_status_success_k {
		return nil, fail(Status(refusal), "a percent escape lacks two hexadecimal digits")
	}
	return decoded[:length], nil
}

// endregion: Names

// region: Protocol

// Verb is an HTTP method a route takes or a request carries.
type Verb int32

// The HTTP methods.
const (
	// VerbUnknown is a method the parser did not recognize.
	VerbUnknown Verb = C.ucall_verb_unknown_k
	// VerbGet retrieves a resource.
	VerbGet Verb = C.ucall_verb_get_k
	// VerbPost creates a resource.
	VerbPost Verb = C.ucall_verb_post_k
	// VerbPut replaces a resource.
	VerbPut Verb = C.ucall_verb_put_k
	// VerbDelete removes a resource.
	VerbDelete Verb = C.ucall_verb_delete_k
	// VerbPatch updates part of a resource.
	VerbPatch Verb = C.ucall_verb_patch_k
	// VerbHead retrieves the headers alone.
	VerbHead Verb = C.ucall_verb_head_k
	// VerbOptions asks which methods a resource takes.
	VerbOptions Verb = C.ucall_verb_options_k
	// VerbAny matches every method, when registering a route only.
	VerbAny Verb = C.ucall_verb_any_k
)

// HTTPStatus is an HTTP status code, named or not.
type HTTPStatus uint32

// The HTTP status codes with names.
const (
	HTTPStatusOK                  HTTPStatus = C.ucall_http_status_ok_k
	HTTPStatusCreated             HTTPStatus = C.ucall_http_status_created_k
	HTTPStatusNoContent           HTTPStatus = C.ucall_http_status_no_content_k
	HTTPStatusPartialContent      HTTPStatus = C.ucall_http_status_partial_content_k
	HTTPStatusMovedPermanently    HTTPStatus = C.ucall_http_status_moved_permanently_k
	HTTPStatusFound               HTTPStatus = C.ucall_http_status_found_k
	HTTPStatusNotModified         HTTPStatus = C.ucall_http_status_not_modified_k
	HTTPStatusBadRequest          HTTPStatus = C.ucall_http_status_bad_request_k
	HTTPStatusUnauthorized        HTTPStatus = C.ucall_http_status_unauthorized_k
	HTTPStatusForbidden           HTTPStatus = C.ucall_http_status_forbidden_k
	HTTPStatusNotFound            HTTPStatus = C.ucall_http_status_not_found_k
	HTTPStatusMethodNotAllowed    HTTPStatus = C.ucall_http_status_method_not_allowed_k
	HTTPStatusTimeout             HTTPStatus = C.ucall_http_status_timeout_k
	HTTPStatusConflict            HTTPStatus = C.ucall_http_status_conflict_k
	HTTPStatusPreconditionFailed  HTTPStatus = C.ucall_http_status_precondition_failed_k
	HTTPStatusPayloadTooLarge     HTTPStatus = C.ucall_http_status_payload_too_large_k
	HTTPStatusRangeNotSatisfiable HTTPStatus = C.ucall_http_status_range_not_satisfiable_k
	HTTPStatusTooManyRequests     HTTPStatus = C.ucall_http_status_too_many_requests_k
	HTTPStatusInternalError       HTTPStatus = C.ucall_http_status_internal_error_k
	HTTPStatusNotImplemented      HTTPStatus = C.ucall_http_status_not_implemented_k
	HTTPStatusBadGateway          HTTPStatus = C.ucall_http_status_bad_gateway_k
	HTTPStatusServiceUnavailable  HTTPStatus = C.ucall_http_status_service_unavailable_k
	HTTPStatusGatewayTimeout      HTTPStatus = C.ucall_http_status_gateway_timeout_k
	HTTPStatusVersionNotSupported HTTPStatus = C.ucall_http_status_version_not_supported_k
)

// BodyDelivery says when a body is handed over: once buffered, or at headers time with the body
// pulled chunk by chunk.
type BodyDelivery int32

// The body deliveries a route or a call may ask for.
const (
	// BodyBuffered hands the body over once it is whole.
	BodyBuffered BodyDelivery = C.ucall_body_delivery_buffered_k
	// BodyStreamed hands the request or response over once the head arrived.
	BodyStreamed BodyDelivery = C.ucall_body_delivery_streamed_k
)

// Security is the transport an interface or a call runs over.
type Security int32

// The transports: plain TCP, or a Noise handshake pattern.
const (
	// SecurityNone is plain TCP.
	SecurityNone Security = C.ucall_security_none_k
	// SecurityNoiseXX authenticates both sides during the handshake.
	SecurityNoiseXX Security = C.ucall_security_noise_xx_k
	// SecurityNoiseIK has the client know the server's key in advance.
	SecurityNoiseIK Security = C.ucall_security_noise_ik_k
	// SecurityNoiseKK has both sides know each other's key in advance.
	SecurityNoiseKK Security = C.ucall_security_noise_kk_k
)

// endregion: Protocol

// region: Noise Keys

// NoiseKey is a 32-byte Curve25519 key.
type NoiseKey [32]byte

// GenerateNoiseKeypair draws a fresh private key and its public key from the operating system's
// entropy.
func GenerateNoiseKeypair() (NoiseKey, NoiseKey, error) {
	var call callWithResult[[2]NoiseKey]
	arguments := open[C.ucall_noise_key_generate_t](&call)
	*arguments = C.ucall_noise_key_generate_t{
		outcome:     call.outcome(),
		private_key: (*C.ucall_noise_key_t)(unsafe.Pointer(&call.result[0])),
		public_key:  (*C.ucall_noise_key_t)(unsafe.Pointer(&call.result[1])),
	}
	C.ucall_noise_key_generate(arguments)
	keys, err := block(&call, nil)
	return keys[0], keys[1], err
}

// DeriveNoisePublicKey recovers the public half of a stored private key, which peers compare in
// their authorizers.
func DeriveNoisePublicKey(privateKey NoiseKey) (NoiseKey, error) {
	var call callWithResult[[2]NoiseKey]
	arguments := open[C.ucall_noise_key_derive_t](&call)
	call.result[0] = privateKey
	*arguments = C.ucall_noise_key_derive_t{
		outcome:     call.outcome(),
		private_key: C.ucall_go_key(unsafe.Pointer(&call.result[0])),
		public_key:  (*C.ucall_noise_key_t)(unsafe.Pointer(&call.result[1])),
	}
	C.ucall_noise_key_derive(arguments)
	keys, err := block(&call, nil)
	return keys[1], err
}

// PeerAuthorizer decides whether a peer presenting an authenticated static key may proceed. It
// runs on the polling goroutine completing the handshake and must not panic.
type PeerAuthorizer func(key NoiseKey) bool

//export ucallAuthorizes
func ucallAuthorizes(key unsafe.Pointer, context unsafe.Pointer) C.ucall_status_t {
	if handled[PeerAuthorizer](context)(*(*NoiseKey)(key)) {
		return C.ucall_status_success_k
	}
	return C.ucall_status_peer_rejected_k
}

// key pins an optional key until the call is final; a field takes it through C.ucall_go_key, as
// cgo spells a key pointer field differently across platforms.
func (call *call) key(key *NoiseKey) unsafe.Pointer {
	if key == nil {
		return nil
	}
	return call.pin(unsafe.Pointer(key))
}

// endregion: Noise Keys

// region: Logs

// LogLevel is the severity of a log line, from the most verbose up.
type LogLevel int32

// The log severities.
const (
	// LogDebug is detail for debugging.
	LogDebug LogLevel = C.ucall_log_level_debug_k
	// LogInfo is a normal lifecycle event.
	LogInfo LogLevel = C.ucall_log_level_info_k
	// LogWarning is something unexpected the library recovered from.
	LogWarning LogLevel = C.ucall_log_level_warning_k
	// LogError is a failed operation.
	LogError LogLevel = C.ucall_log_level_error_k
	// LogFatal means the server or client cannot continue.
	LogFatal LogLevel = C.ucall_log_level_fatal_k
)

// LogFormat is the shape of each log line.
type LogFormat int32

// The log line shapes.
const (
	// LogHuman writes readable lines with normalized units.
	LogHuman LogFormat = C.ucall_log_format_human_k
	// LogJSON writes one JSON document per line.
	LogJSON LogFormat = C.ucall_log_format_json_k
)

// Log is the single sink of a server or a client: every line at or above Level, in Format,
// reaches Callback on whichever goroutine produced it, valid only during the call.
type Log struct {
	Callback func(level LogLevel, line []byte)
	Format   LogFormat
	Level    LogLevel
}

//export ucallLogs
func ucallLogs(level C.ucall_log_level_t, line C.ucall_bytes_view_t, context unsafe.Pointer) {
	handled[func(LogLevel, []byte)](context)(LogLevel(level), viewed(line))
}

// lowered keeps a log's callback behind a handle its owner deletes, as the library calls it until
// that owner is freed.
func (log *Log) lowered(handles *[]cgo.Handle) C.ucall_log_t {
	if log == nil || log.Callback == nil {
		return C.ucall_log_t{}
	}
	handle := cgo.NewHandle(log.Callback)
	*handles = append(*handles, handle)
	return C.ucall_log_t{
		callback: C.ucall_go_logs(),
		context:  contextOf(handle),
		format:   C.ucall_log_format_t(log.Format),
		level:    C.ucall_log_level_t(log.Level),
	}
}

// authorizer keeps an optional authorizer behind a handle its owner deletes.
func authorizer(authorize PeerAuthorizer, handles *[]cgo.Handle) (C.ucall_peer_authorizer_t, unsafe.Pointer) {
	if authorize == nil {
		return nil, nil
	}
	handle := cgo.NewHandle(authorize)
	*handles = append(*handles, handle)
	return C.ucall_go_authorizes(), contextOf(handle)
}

// endregion: Logs
