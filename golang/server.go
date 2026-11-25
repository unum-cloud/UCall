// Servers, their routes and batch endpoints, and the requests handlers receive and reply to.
//
// File: golang/server.go
// Author: Ash Vardanian
// Date: November 18, 2026

package ucall

import (
	"iter"
	"runtime/cgo"
	"time"
	"unsafe"
)

/*
// Request reads and replies carry no callback field, so each claims both promises.
#cgo noescape ucall_server_request_path
#cgo nocallback ucall_server_request_path
#cgo noescape ucall_server_request_query
#cgo nocallback ucall_server_request_query
#cgo noescape ucall_server_request_body
#cgo nocallback ucall_server_request_body
#cgo noescape ucall_server_request_body_chunk
#cgo nocallback ucall_server_request_body_chunk
#cgo noescape ucall_server_request_path_parameter
#cgo nocallback ucall_server_request_path_parameter
#cgo noescape ucall_server_request_query_parameter
#cgo nocallback ucall_server_request_query_parameter
#cgo noescape ucall_server_request_header
#cgo nocallback ucall_server_request_header
#cgo noescape ucall_server_request_fields_count
#cgo nocallback ucall_server_request_fields_count
#cgo noescape ucall_server_request_field
#cgo nocallback ucall_server_request_field
#cgo noescape ucall_server_request_peer
#cgo nocallback ucall_server_request_peer
#cgo noescape ucall_server_request_path_segment
#cgo nocallback ucall_server_request_path_segment
#cgo noescape ucall_server_request_part
#cgo nocallback ucall_server_request_part
#cgo noescape ucall_server_reply_content
#cgo nocallback ucall_server_reply_content
#cgo noescape ucall_server_reply_error
#cgo nocallback ucall_server_reply_error
#cgo noescape ucall_server_reply_vectored
#cgo nocallback ucall_server_reply_vectored
#cgo noescape ucall_server_reply_begin
#cgo nocallback ucall_server_reply_begin
#cgo noescape ucall_server_reply_append
#cgo nocallback ucall_server_reply_append
#cgo noescape ucall_server_reply_end
#cgo nocallback ucall_server_reply_end
#cgo noescape ucall_server_event_loop_statistics
#cgo nocallback ucall_server_event_loop_statistics
#cgo noescape ucall_server_batch_endpoint_statistics
#cgo nocallback ucall_server_batch_endpoint_statistics

// Starting a server and adding endpoints carry the callbacks they register, and polling runs them
// with no callback field of its own, so each claims only noescape.
#cgo noescape ucall_server_init
#cgo noescape ucall_server_add_http_endpoint
#cgo noescape ucall_server_add_http_batch_endpoint
#cgo noescape ucall_server_take_call
#cgo noescape ucall_server_take_calls
#cgo noescape ucall_server_take_batch
#cgo noescape ucall_server_take_batches

#include "shim.h"
*/
import "C"

// region: Options

// Interface is one address a server answers on, with the security and admission limits of the
// connections arriving there, so one server answers plaintext on loopback and Noise on the wire.
type Interface struct {
	// Address is the listening address in "host:port" form; port zero binds a free one, which
	// Server.Address reports.
	Address string
	// ListenDescriptor is a listening stream socket another owner opened, accepted on instead of
	// Address and never closed.
	ListenDescriptor *uintptr
	// DeviceName pins the interface to a physical device, like "eth0", on Linux only.
	DeviceName string
	// Security is the transport connections accepted here run over.
	Security Security
	// NoisePrivateKey is the server identity every Noise mode needs.
	NoisePrivateKey *NoiseKey
	// NoisePeerKey is the one initiator's static public key Noise KK admits.
	NoisePeerKey *NoiseKey
	// PeerAuthorizer vets each client's authenticated static key; Noise XX needs one.
	PeerAuthorizer PeerAuthorizer
	// EventLoops accepting here; zero means one, or a named device's receive queues.
	EventLoops uint
	// Connections open at once across this interface's loops; zero is refused.
	Connections uint
	// PipelinedRequests one connection may have in flight; zero means one.
	PipelinedRequests uint
	// MaxRequestBytes caps a request head and buffered body, answering 413 past it; zero takes
	// the largest receive buffer the kernel grants a socket.
	MaxRequestBytes uint
	// ReplyDirectories are the directories path parts of replies resolve beneath, by position.
	ReplyDirectories []string
}

// NewInterface listens on address, admitting 1024 connections at once.
func NewInterface(address string) Interface {
	return Interface{Address: address, Connections: 1024}
}

// Metrics is the StatsD endpoint a server sends each event loop's counters and sampled request
// latencies to.
type Metrics struct {
	// Address is the endpoint in "host:port" form.
	Address string
	// SampleRate is the fraction of finished requests whose latency is reported; zero means all.
	SampleRate float32
	// Prefix starts every metric name; empty means "ucall".
	Prefix string
	// Tags go on every metric, each "key:value".
	Tags []string
	// Interval is the time between one event loop's datagrams; zero means one second.
	Interval time.Duration
}

// ServerOptions is what a server runs on and reports through, beside its interfaces.
type ServerOptions struct {
	// Backend is the requested I/O backend, failing rather than substituting when unavailable.
	Backend Backend
	// CPUClassCeiling caps the CPU class; CPUClassUnknown sets no ceiling.
	CPUClassCeiling CPUClass
	// Log is where log lines go; nil keeps the server silent.
	Log *Log
	// Metrics is where StatsD datagrams go; nil sends none.
	Metrics *Metrics
}

// endregion: Options

// region: Server

// Server is an HTTP server over one or more interfaces, polled by application goroutines.
//
// Register every route before any loop is polled, then poll each event loop from one goroutine at
// a time, as `go server.TakeCalls(0)` does. Close it once its polling goroutines returned.
type Server struct {
	handle   C.ucall_server_t
	resolved C.ucall_server_options_t
	handles  []cgo.Handle
}

// started is what initialization reads and writes: the options, the server, and the options with
// every default filled.
type started struct {
	server            C.ucall_server_t
	options, resolved C.ucall_server_options_t
}

// NewServer starts a server answering on interfaces, with the backend, CPU class, log sink and
// StatsD endpoint options name; nil options take every default.
func NewServer(interfaces []Interface, config *ServerOptions) (*Server, error) {
	options := configOf(config)
	metrics := configOf(options.Metrics)
	server := &Server{}
	var call callWithResult[started]
	arguments := open[C.ucall_server_init_t](&call)
	lowered := make([]C.ucall_network_interface_t, len(interfaces))
	for position := range interfaces {
		lowered[position] = server.lower(&call.call, &interfaces[position])
	}
	tags, tagsCount := call.texts(metrics.Tags)
	call.result.options = C.ucall_server_options_t{
		interfaces:                    (*C.ucall_network_interface_t)(call.pinArray(unsafe.Pointer(unsafe.SliceData(lowered)), len(lowered))),
		interfaces_count:              C.size_t(len(lowered)),
		log:                           options.Log.lowered(&server.handles),
		metrics_address:               call.text(metrics.Address),
		metrics_sample_rate:           C.float(metrics.SampleRate),
		metrics_prefix:                call.text(metrics.Prefix),
		metrics_tags:                  tags,
		metrics_tags_count:            tagsCount,
		metrics_interval_microseconds: microseconds(metrics.Interval),
		backend:                       C.ucall_io_backend_t(options.Backend),
		cpu_class_ceiling:             C.ucall_cpu_class_t(options.CPUClassCeiling),
	}
	*arguments = C.ucall_server_init_t{
		server:   &call.result.server,
		outcome:  call.outcome(),
		options:  &call.result.options,
		resolved: &call.result.resolved,
	}
	C.ucall_server_init(arguments)
	result, err := block(&call, nil)
	if err != nil {
		server.release()
		return nil, err
	}
	server.handle, server.resolved = result.server, result.resolved
	return server, nil
}

// lower pins one interface's strings, keys and directories until initialization copies them, and
// keeps its authorizer behind a handle the server deletes.
func (server *Server) lower(call *call, network *Interface) C.ucall_network_interface_t {
	directories, directoriesCount := call.texts(network.ReplyDirectories)
	authorize, authorizeContext := authorizer(network.PeerAuthorizer, &server.handles)
	var descriptor *C.intptr_t
	if network.ListenDescriptor != nil {
		descriptor = (*C.intptr_t)(call.pin(unsafe.Pointer(network.ListenDescriptor)))
	}
	return C.ucall_network_interface_t{
		address:                    call.text(network.Address),
		listen_descriptor:          descriptor,
		device_name:                call.text(network.DeviceName),
		security:                   C.ucall_security_t(network.Security),
		noise_private_key:          C.ucall_go_key(call.key(network.NoisePrivateKey)),
		noise_peer_key:             C.ucall_go_key(call.key(network.NoisePeerKey)),
		peer_authorizer:            authorize,
		peer_authorizer_context:    authorizeContext,
		event_loops:                C.size_t(network.EventLoops),
		max_concurrent_connections: C.size_t(network.Connections),
		max_pipelined_requests:     C.size_t(network.PipelinedRequests),
		max_request_bytes:          C.size_t(network.MaxRequestBytes),
		reply_directories:          directories,
		reply_directories_count:    directoriesCount,
	}
}

// release deletes the handles the library calls back through, after the handle they serve is freed.
func (server *Server) release() {
	for _, handle := range server.handles {
		handle.Delete()
	}
	server.handles = nil
}

// Close frees the server once its polling goroutines returned and its bound clients are closed.
// It is idempotent.
func (server *Server) Close() error {
	if server.handle == nil {
		return nil
	}
	C.ucall_server_free(server.handle)
	server.handle = nil
	server.release()
	return nil
}

// interfaces views the interfaces as the library resolved them, every default filled in.
func (server *Server) interfaces() []C.ucall_network_interface_t {
	if server.handle == nil {
		return nil
	}
	return unsafe.Slice(server.resolved.interfaces, int(server.resolved.interfaces_count))
}

// EventLoops is how many event loops the server runs, each polled by one goroutine at a time.
func (server *Server) EventLoops() uint {
	var count uint
	for _, network := range server.interfaces() {
		count = max(count, uint(network.event_loops))
	}
	return count
}

// Backend is the I/O backend the server resolved to.
func (server *Server) Backend() Backend { return Backend(server.resolved.backend) }

// CPUClassCeiling is the CPU class the server resolved to under its ceiling.
func (server *Server) CPUClassCeiling() CPUClass { return CPUClass(server.resolved.cpu_class_ceiling) }

// Address is the numeric address interface index listens on, with the port it bound, and false
// past the last interface.
func (server *Server) Address(index uint) (string, bool) {
	interfaces := server.interfaces()
	if index >= uint(len(interfaces)) {
		return "", false
	}
	return string(viewed(interfaces[index].address)), true
}

// MemoryDomain is the NUMA node the kernel ties interface index's device to, or -1, and false past
// the last interface; init and poll from goroutines locked to threads there.
func (server *Server) MemoryDomain(index uint) (int32, bool) {
	interfaces := server.interfaces()
	if index >= uint(len(interfaces)) {
		return 0, false
	}
	return int32(interfaces[index].memory_domain), true
}

//export ucallServes
func ucallServes(server C.ucall_server_t, request C.ucall_received_http_request_t, context unsafe.Pointer) {
	received := &Request{server: server, handle: request}
	handled[func(request *Request)](context)(received)
	received.drop()
}

// Route sends requests matching path and verb to handler, which runs on the polling goroutine.
//
// Templates capture {name} segments and a greedy {*name} tail, read back through
// Request.PathParameter; literal segments match before captures. A handler that neither replies
// nor detaches its request answers 500, and one that panics crashes the process.
func (server *Server) Route(path string, verb Verb, handler func(request *Request)) error {
	return server.RouteWith(path, verb, BodyBuffered, handler)
}

// RouteWith routes like Server.Route, running handler once the body is buffered, or with
// BodyStreamed as soon as the headers arrived, the body still to be pulled through
// DetachedRequest.BodyChunk.
func (server *Server) RouteWith(path string, verb Verb, delivery BodyDelivery, handler func(request *Request)) error {
	handle := cgo.NewHandle(handler)
	// A missing handler crosses as a missing callback, which C refuses after a closed server.
	callback := C.ucall_go_serves()
	if handler == nil {
		callback = nil
	}
	var call callWithResult[struct{}]
	arguments := open[C.ucall_server_add_http_endpoint_t](&call)
	*arguments = C.ucall_server_add_http_endpoint_t{
		server:        server.handle,
		outcome:       call.outcome(),
		uri_template:  call.text(path),
		verb:          C.ucall_verb_t(verb),
		callback:      callback,
		context:       contextOf(handle),
		body_delivery: C.ucall_body_delivery_t(delivery),
	}
	C.ucall_server_add_http_endpoint(arguments)
	if _, err := block(&call, nil); err != nil {
		handle.Delete()
		return err
	}
	server.handles = append(server.handles, handle)
	return nil
}

// Get routes GET requests on path to handler.
func (server *Server) Get(path string, handler func(request *Request)) error {
	return server.Route(path, VerbGet, handler)
}

// Post routes POST requests on path to handler.
func (server *Server) Post(path string, handler func(request *Request)) error {
	return server.Route(path, VerbPost, handler)
}

// Put routes PUT requests on path to handler.
func (server *Server) Put(path string, handler func(request *Request)) error {
	return server.Route(path, VerbPut, handler)
}

// Delete routes DELETE requests on path to handler.
func (server *Server) Delete(path string, handler func(request *Request)) error {
	return server.Route(path, VerbDelete, handler)
}

// Patch routes PATCH requests on path to handler.
func (server *Server) Patch(path string, handler func(request *Request)) error {
	return server.Route(path, VerbPatch, handler)
}

// Polling is what Server.TakeCall found of its event loop.
type Polling int

// The states of a polled event loop.
const (
	// PollingServing means the loop serves, or drains what it holds after a stop.
	PollingServing Polling = iota
	// PollingRetired means the loop drained or cut everything after Server.Stop.
	PollingRetired
)

// TakeCall advances one event loop, running the handlers of the requests it completes on this
// goroutine, and waits up to timeout for progress; zero performs one nonblocking round.
func (server *Server) TakeCall(eventLoop uint, timeout time.Duration) (Polling, error) {
	var call callWithResult[struct{}]
	arguments := open[C.ucall_server_take_call_t](&call)
	*arguments = C.ucall_server_take_call_t{
		server:               server.handle,
		outcome:              call.outcome(),
		event_loop_index:     C.size_t(eventLoop),
		timeout_microseconds: microseconds(timeout),
	}
	C.ucall_server_take_call(arguments)
	_, err := block(&call, nil)
	if Status(call.slots.outcome.status) == StatusConnectionClosed {
		return PollingRetired, nil
	}
	return PollingServing, err
}

// TakeCalls drives one event loop on this goroutine until Server.Stop or an I/O failure.
func (server *Server) TakeCalls(eventLoop uint) error {
	var call callWithResult[struct{}]
	arguments := open[C.ucall_server_take_calls_t](&call)
	*arguments = C.ucall_server_take_calls_t{
		server:           server.handle,
		outcome:          call.outcome(),
		event_loop_index: C.size_t(eventLoop),
	}
	C.ucall_server_take_calls(arguments)
	_, err := block(&call, nil)
	return err
}

// Stop requests shutdown from any goroutine, handlers included: the first call drains, answering
// the requests already held, and a second one cuts the replies still in flight.
func (server *Server) Stop() { C.ucall_server_stop(server.handle) }

// EventLoopStatistics are the counters of one event loop since the server started; divided by
// Requests, they price one call.
type EventLoopStatistics struct {
	Polls                 uint64
	EmptyPolls            uint64
	KernelEnters          uint64
	Submissions           uint64
	Completions           uint64
	KernelEntries         uint64
	Cancellations         uint64
	Accepts               uint64
	Requests              uint64
	ReceiveRearms         uint64
	BytesReceived         uint64
	BytesSent             uint64
	BytesCopied           uint64
	ZeroCopySends         uint64
	ZeroCopyFallbacks     uint64
	CopyingSends          uint64
	FileReadsAsynchronous uint64
	FileReadsBlocking     uint64
	BytesRead             uint64
	FileWindowOverlaps    uint64
	LingerResets          uint64
	ReadyPasses           uint64
	ReplicaDequeues       uint64
	RefusedRequests       uint64
	HandshakeFailures     uint64
	AuthorizerRefusals    uint64
	ShedConnections       uint64
	WindowsUnpinned       uint64
}

// EventLoopStatistics copies one loop's counters, from any goroutine while it is polled.
func (server *Server) EventLoopStatistics(eventLoop uint) (EventLoopStatistics, error) {
	var call callWithResult[EventLoopStatistics]
	arguments := open[C.ucall_server_event_loop_statistics_t](&call)
	*arguments = C.ucall_server_event_loop_statistics_t{
		server:           server.handle,
		outcome:          call.outcome(),
		event_loop_index: C.size_t(eventLoop),
		statistics:       (*C.ucall_event_loop_statistics_t)(unsafe.Pointer(call.result)),
	}
	C.ucall_server_event_loop_statistics(arguments)
	return block(&call, nil)
}

// endregion: Server

// region: Requests

// Request is one received request, answered at most once. Its reads view the received bytes until
// the reply, which consumes it; a handler that neither replies nor detaches it answers 500.
type Request struct {
	server C.ucall_server_t
	handle C.ucall_received_http_request_t
}

// Peer is who sent a request: the interface it arrived on, the client's authenticated static
// key, zeroed in plaintext, and its socket address.
type Peer struct {
	NetworkInterfaceIndex uint
	StaticKey             NoiseKey
	Address               PeerAddress
}

// PeerAddress is a socket address: IPv4 in the first 4 bytes, IPv6 in all 16, both in network
// order, with the port and the IPv6 scope; a local socket carries only its family.
type PeerAddress struct {
	Bytes  [16]byte
	Scope  uint32
	Port   uint16
	Family AddressFamily
	_      uint8
}

// AddressFamily is the family of a peer's socket address.
type AddressFamily uint8

// The address families a peer arrives from.
const (
	// AddressUnknown means no address was read.
	AddressUnknown AddressFamily = C.ucall_address_family_unknown_k
	// AddressIPv4 is an IPv4 peer.
	AddressIPv4 AddressFamily = C.ucall_address_family_ipv4_k
	// AddressIPv6 is an IPv6 peer.
	AddressIPv6 AddressFamily = C.ucall_address_family_ipv6_k
	// AddressUnix is a local socket peer.
	AddressUnix AddressFamily = C.ucall_address_family_unix_k
)

// RequestPart is one part of a multipart/form-data body, viewing the received bytes.
type RequestPart struct {
	Name        []byte
	ContentType []byte
	Data        []byte
}

// drop answers 500 for a request its handler neither replied to nor detached.
func (request *Request) drop() {
	if request.handle == nil {
		return
	}
	_ = request.ReplyError(HTTPStatusInternalError, "The request was dropped without a reply")
	request.handle = nil
}

// Verb is the HTTP method, which tells apart the requests of a VerbAny route.
func (request *Request) Verb() Verb {
	return Verb(C.ucall_server_request_verb(request.server, request.handle))
}

// Path is the path as sent, still percent-encoded, without the query.
func (request *Request) Path() ([]byte, error) {
	var call callWithResult[C.ucall_bytes_view_t]
	arguments := open[C.ucall_server_request_path_t](&call)
	*arguments = C.ucall_server_request_path_t{
		server: request.server, outcome: call.outcome(), request: request.handle, path: call.result}
	C.ucall_server_request_path(arguments)
	path, err := block(&call, nil)
	return viewed(path), err
}

// QueryString is the query after the first '?', still percent-encoded, or empty without one.
func (request *Request) QueryString() ([]byte, error) {
	var call callWithResult[C.ucall_bytes_view_t]
	arguments := open[C.ucall_server_request_query_t](&call)
	*arguments = C.ucall_server_request_query_t{
		server: request.server, outcome: call.outcome(), request: request.handle, query: call.result}
	C.ucall_server_request_query(arguments)
	query, err := block(&call, nil)
	return viewed(query), err
}

// Body is the body, decoded from chunked framing if it arrived that way; a streamed route refuses
// it, as DetachedRequest.BodyChunk pulls its body.
func (request *Request) Body() ([]byte, error) {
	var call callWithResult[C.ucall_bytes_view_t]
	arguments := open[C.ucall_server_request_body_t](&call)
	*arguments = C.ucall_server_request_body_t{
		server: request.server, outcome: call.outcome(), request: request.handle, body: call.result}
	C.ucall_server_request_body(arguments)
	body, err := block(&call, nil)
	return viewed(body), err
}

// PathParameter is the value the route's template captured under name, case-sensitive, failing
// with StatusNotFound without one.
func (request *Request) PathParameter(name string) ([]byte, error) {
	var call callWithResult[C.ucall_bytes_view_t]
	arguments := open[C.ucall_server_request_path_parameter_t](&call)
	*arguments = C.ucall_server_request_path_parameter_t{
		server: request.server, outcome: call.outcome(), request: request.handle,
		name: call.text(name), value: call.result}
	C.ucall_server_request_path_parameter(arguments)
	value, err := block(&call, nil)
	return viewed(value), err
}

// Query is the value of query parameter name, case-sensitive and still percent-encoded, failing
// with StatusNotFound without one.
func (request *Request) Query(name string) ([]byte, error) {
	var call callWithResult[C.ucall_bytes_view_t]
	arguments := open[C.ucall_server_request_query_parameter_t](&call)
	*arguments = C.ucall_server_request_query_parameter_t{
		server: request.server, outcome: call.outcome(), request: request.handle,
		name: call.text(name), value: call.result}
	C.ucall_server_request_query_parameter(arguments)
	value, err := block(&call, nil)
	return viewed(value), err
}

// Header is the value of header name, matched case-insensitively, failing with StatusNotFound
// without one.
func (request *Request) Header(name string) ([]byte, error) {
	var call callWithResult[C.ucall_bytes_view_t]
	arguments := open[C.ucall_server_request_header_t](&call)
	*arguments = C.ucall_server_request_header_t{
		server: request.server, outcome: call.outcome(), request: request.handle,
		name: call.text(name), value: call.result}
	C.ucall_server_request_header(arguments)
	value, err := block(&call, nil)
	return viewed(value), err
}

// Fields yields every header field line in arrival order, repeated names apart, each name
// lowercased as the parser keeps it and its value trimmed.
func (request *Request) Fields() iter.Seq2[[]byte, []byte] {
	return func(yield func(name, value []byte) bool) {
		count := C.ucall_server_request_fields_count(request.server, request.handle)
		for index := C.size_t(0); index < count; index++ {
			var call callWithResult[[2]C.ucall_bytes_view_t]
			arguments := open[C.ucall_server_request_field_t](&call)
			*arguments = C.ucall_server_request_field_t{
				server: request.server, outcome: call.outcome(), request: request.handle, index: index,
				name: &call.result[0], value: &call.result[1]}
			C.ucall_server_request_field(arguments)
			field, err := block(&call, nil)
			if err != nil || !yield(viewed(field[0]), viewed(field[1])) {
				return
			}
		}
	}
}

// Peer is the interface the request arrived on, the client's key and its address, readable after
// its connection closed.
func (request *Request) Peer() (Peer, error) {
	var call callWithResult[Peer]
	arguments := open[C.ucall_server_request_peer_t](&call)
	*arguments = C.ucall_server_request_peer_t{
		server: request.server, outcome: call.outcome(), request: request.handle,
		network_interface_index: (*C.size_t)(unsafe.Pointer(&call.result.NetworkInterfaceIndex)),
		static_key:              (*C.ucall_noise_key_t)(unsafe.Pointer(&call.result.StaticKey)),
		address:                 (*C.ucall_peer_address_t)(unsafe.Pointer(&call.result.Address))}
	C.ucall_server_request_peer(arguments)
	return block(&call, nil)
}

// PathSegmentsCount is how many path components the request has, as sent.
func (request *Request) PathSegmentsCount() uint {
	return uint(C.ucall_server_request_path_segments_count(request.server, request.handle))
}

// PathSegment is path component index, counting from zero, failing with StatusNotFound past the
// last one.
func (request *Request) PathSegment(index uint) ([]byte, error) {
	var call callWithResult[C.ucall_bytes_view_t]
	arguments := open[C.ucall_server_request_path_segment_t](&call)
	*arguments = C.ucall_server_request_path_segment_t{
		server: request.server, outcome: call.outcome(), request: request.handle,
		index: C.size_t(index), segment: call.result}
	C.ucall_server_request_path_segment(arguments)
	segment, err := block(&call, nil)
	return viewed(segment), err
}

// PartsCount is how many parts a multipart/form-data body has, zero for any other body.
func (request *Request) PartsCount() uint {
	return uint(C.ucall_server_request_parts_count(request.server, request.handle))
}

// Part is part index of a multipart/form-data body, its payload undecoded.
func (request *Request) Part(index uint) (RequestPart, error) {
	var call callWithResult[[3]C.ucall_bytes_view_t]
	arguments := open[C.ucall_server_request_part_t](&call)
	*arguments = C.ucall_server_request_part_t{
		server: request.server, outcome: call.outcome(), request: request.handle, index: C.size_t(index),
		name: &call.result[0], content_type: &call.result[1], data: &call.result[2]}
	C.ucall_server_request_part(arguments)
	part, err := block(&call, nil)
	return RequestPart{Name: viewed(part[0]), ContentType: viewed(part[1]), Data: viewed(part[2])}, err
}

// taken passes a request handle to a reply, which clears it once it took the request, so a handle
// still held after a refusal answers 500 when dropped.
func (call *call) taken(handle *C.ucall_received_http_request_t) *C.ucall_received_http_request_t {
	return (*C.ucall_received_http_request_t)(call.pin(unsafe.Pointer(handle)))
}

// Reply answers with status, full header lines like "content-type: text/plain" and body, and
// consumes the request; the length, date and server lines are generated.
func (request *Request) Reply(status HTTPStatus, headers []string, body []byte) error {
	var call callWithResult[struct{}]
	lines, linesCount := call.texts(headers)
	arguments := open[C.ucall_server_reply_content_t](&call)
	*arguments = C.ucall_server_reply_content_t{
		server: request.server, outcome: call.outcome(), request: call.taken(&request.handle),
		http_status: C.ucall_http_status_t(status), headers: lines, headers_count: linesCount,
		body: call.bytes(body)}
	C.ucall_server_reply_content(arguments)
	_, err := block(&call, nil)
	return err
}

// ReplyError answers with an error status, 400 or above, and a plain-text message, and consumes
// the request.
func (request *Request) ReplyError(status HTTPStatus, message string) error {
	var call callWithResult[struct{}]
	arguments := open[C.ucall_server_reply_error_t](&call)
	*arguments = C.ucall_server_reply_error_t{
		server: request.server, outcome: call.outcome(), request: call.taken(&request.handle),
		http_status: C.ucall_http_status_t(status), message: call.text(message)}
	C.ucall_server_reply_error(arguments)
	_, err := block(&call, nil)
	return err
}

// Detach hands the request to a goroutine that may wait, where it gains the replies that may
// finish later; the polling goroutine itself must never wait on them.
func (request *Request) Detach() *DetachedRequest {
	detached := &DetachedRequest{Request: *request}
	request.handle = nil
	return detached
}

// DetachedRequest is a request taken off its polling goroutine, and the only owner of the verbs
// that may finish later: ReplyParts, ReplyStream and BodyChunk. Close answers 500 for one never
// replied to.
type DetachedRequest struct {
	Request
}

// Close answers 500 if the request was never replied to. It is idempotent.
func (detached *DetachedRequest) Close() error {
	detached.drop()
	return nil
}

// ReplyPart is one part of a reply body: bytes in memory, a range of the caller's unbuffered
// descriptor, or a range of a file beneath one of the interface's reply directories.
type ReplyPart struct {
	kind       C.ucall_reply_part_kind_t
	bytes      []byte
	path       string
	directory  uint
	descriptor int
	offset     uint64
	length     uint64
}

// BytesPart is bytes in memory, copied before the reply returns.
func BytesPart(bytes []byte) ReplyPart {
	return ReplyPart{kind: C.ucall_reply_part_bytes_k, bytes: bytes}
}

// FileRange is a range of the caller's unbuffered descriptor, open until the reply is final.
type FileRange struct {
	Descriptor int
	Offset     uint64
	// Length is the range's byte count; zero sends through the end of the file.
	Length uint64
}

// FilePart is a range of a regular file the event loop reads unbuffered after the call returns.
func FilePart(file FileRange) ReplyPart {
	return ReplyPart{kind: C.ucall_reply_part_file_k, descriptor: file.Descriptor, offset: file.Offset, length: file.Length}
}

// PathRange is a range of a file beneath one of the interface's reply directories.
type PathRange struct {
	Directory uint
	Path      string
	Offset    uint64
	// Length is the range's byte count; zero sends through the end of the file.
	Length uint64
}

// PathPart is a range of a file the event loop opens beneath a reply directory and closes once
// sent.
func PathPart(path PathRange) ReplyPart {
	return ReplyPart{kind: C.ucall_reply_part_path_k, directory: path.Directory, path: path.Path, offset: path.Offset, length: path.Length}
}

// parts passes reply parts as the array the library reads, their bytes and paths until the call is
// final, writing each part's union member in place, as cgo reads the union only as bytes.
func (call *call) parts(parts []ReplyPart) (*C.ucall_reply_part_t, C.size_t) {
	if len(parts) == 0 {
		return nil, 0
	}
	lowered := make([]C.ucall_reply_part_t, len(parts))
	for position, part := range parts {
		lowered[position].kind = part.kind
		data := unsafe.Pointer(&lowered[position].data)
		switch part.kind {
		case C.ucall_reply_part_file_k:
			*(*C.ucall_file_range_t)(data) = C.ucall_file_range_t{
				file_descriptor: C.int(part.descriptor), offset: C.uint64_t(part.offset), length: C.uint64_t(part.length)}
		case C.ucall_reply_part_path_k:
			*(*C.ucall_path_range_t)(data) = C.ucall_path_range_t{
				directory_index: C.size_t(part.directory), relative_path: call.text(part.path),
				offset: C.uint64_t(part.offset), length: C.uint64_t(part.length)}
		default:
			*(*C.ucall_bytes_view_t)(data) = call.bytes(part.bytes)
		}
	}
	return (*C.ucall_reply_part_t)(call.pinArray(unsafe.Pointer(unsafe.SliceData(lowered)), len(lowered))), C.size_t(len(lowered))
}

// ReplyParts answers with status, header lines and parts concatenated into the body, its length
// measured from the files, and consumes the request. It is final at once for bytes alone, and with
// a file or path part stays deferred until every part is sent; a part failing before the head left
// replaces the reply with 404, 416 or 500, and the Deferred reports the cause.
func (detached *DetachedRequest) ReplyParts(status HTTPStatus, headers []string, parts []ReplyPart) (*Deferred[struct{}], error) {
	deferred := new(Deferred[struct{}])
	call := &deferred.call
	lines, linesCount := call.texts(headers)
	lowered, loweredCount := call.parts(parts)
	arguments := open[C.ucall_server_reply_vectored_t](call)
	*arguments = C.ucall_server_reply_vectored_t{
		server: detached.server, outcome: call.outcome(), request: call.taken(&detached.handle),
		http_status: C.ucall_http_status_t(status), headers: lines, headers_count: linesCount,
		parts: lowered, parts_count: loweredCount}
	C.ucall_server_reply_vectored(arguments)
	return submitted(deferred, nil)
}

// ReplyStream sends the status line and header lines and opens a body appended part by part, which
// is chunked unless a Content-Length line declares its length.
func (detached *DetachedRequest) ReplyStream(status HTTPStatus, headers []string) (*ReplyStream, error) {
	var call callWithResult[struct{}]
	lines, linesCount := call.texts(headers)
	arguments := open[C.ucall_server_reply_begin_t](&call)
	*arguments = C.ucall_server_reply_begin_t{
		server: detached.server, outcome: call.outcome(), request: call.taken(&detached.handle),
		http_status: C.ucall_http_status_t(status), headers: lines, headers_count: linesCount}
	C.ucall_server_reply_begin(arguments)
	if _, err := block(&call, nil); err != nil {
		return nil, err
	}
	stream := &ReplyStream{server: detached.server, request: detached.handle}
	detached.handle = nil
	return stream, nil
}

// BodyChunk is the body bytes a pull answered, valid until the next pull.
type BodyChunk struct {
	view C.ucall_bytes_view_t
}

// Bytes are the pulled bytes, empty once the body ended.
func (chunk BodyChunk) Bytes() []byte { return viewed(chunk.view) }

// BodyChunk pulls the body bytes decoded since the last pull, final once they arrive and empty once
// the body ended; on a buffered route the first pull is the whole body. A pull on the polling
// goroutine finding nothing fails with StatusWouldBlock instead.
func (detached *DetachedRequest) BodyChunk() (*Deferred[BodyChunk], error) {
	deferred := new(Deferred[BodyChunk])
	call := &deferred.call
	arguments := open[C.ucall_server_request_body_chunk_t](call)
	*arguments = C.ucall_server_request_body_chunk_t{
		server: detached.server, outcome: call.outcome(), request: detached.handle, data: &call.result.view}
	C.ucall_server_request_body_chunk(arguments)
	return submitted(deferred, nil)
}

// ReplyStream is a reply whose head left and whose body is appended part by part until End.
type ReplyStream struct {
	server  C.ucall_server_t
	request C.ucall_received_http_request_t
}

// Append queues parts on the body together, or none of them, failing with StatusWouldBlock while
// the peer lags behind the parts already queued.
func (stream *ReplyStream) Append(parts []ReplyPart) error {
	var call callWithResult[struct{}]
	lowered, loweredCount := call.parts(parts)
	arguments := open[C.ucall_server_reply_append_t](&call)
	*arguments = C.ucall_server_reply_append_t{
		server: stream.server, outcome: call.outcome(), request: stream.request,
		parts: lowered, parts_count: loweredCount}
	C.ucall_server_reply_append(arguments)
	_, err := block(&call, nil)
	return err
}

// End ends the body, final once its file parts are sent.
func (stream *ReplyStream) End() (*Deferred[struct{}], error) {
	deferred := new(Deferred[struct{}])
	call := &deferred.call
	arguments := open[C.ucall_server_reply_end_t](call)
	*arguments = C.ucall_server_reply_end_t{
		server: stream.server, outcome: call.outcome(), request: call.taken(&stream.request)}
	C.ucall_server_reply_end(arguments)
	return submitted(deferred, nil)
}

// Close ends a stream not yet ended and waits for its file parts. It is idempotent.
func (stream *ReplyStream) Close() error {
	if stream.request == nil {
		return nil
	}
	ended, err := stream.End()
	if err != nil {
		return err
	}
	return ended.Close()
}

// endregion: Requests

// region: Batches

// Batching says when a batch endpoint dispatches; zero fields take 1, 32 and 10 milliseconds.
type Batching struct {
	// MinSize is how many waiting requests dispatch a batch at once.
	MinSize uint
	// MaxSize is how many requests one batch holds at most.
	MaxSize uint
	// MaxLatency is how long the oldest request of a smaller batch waits before it dispatches.
	MaxLatency time.Duration
}

// Batch holds the requests one batch callback received, in arrival order, each taken once. A
// request never taken stays unanswered until the server is closed.
type Batch struct {
	server   C.ucall_server_t
	requests []C.ucall_received_http_request_t
}

// Len is how many requests the batch holds.
func (batch Batch) Len() int { return len(batch.requests) }

// Take hands over request index, which its taker replies to.
func (batch Batch) Take(index int) *Request {
	return &Request{server: batch.server, handle: batch.requests[index]}
}

//export ucallBatches
func ucallBatches(server C.ucall_server_t, requests *C.ucall_received_http_request_t, count C.size_t, context unsafe.Pointer) {
	handled[func(batch Batch)](context)(Batch{server: server, requests: unsafe.Slice(requests, int(count))})
}

// BatchEndpoint is one batch endpoint, drained by one goroutine at a time until its server closes.
type BatchEndpoint struct {
	server C.ucall_server_t
	handle C.ucall_http_batch_endpoint_t
}

// Batch collects requests matching path and verb from every event loop into one queue, which the
// returned endpoint drains into handler on whichever goroutine polls it.
func (server *Server) Batch(path string, verb Verb, options Batching, handler func(batch Batch)) (*BatchEndpoint, error) {
	handle := cgo.NewHandle(handler)
	// A missing handler crosses as a missing callback, which C refuses after a closed server.
	callback := C.ucall_go_batches()
	if handler == nil {
		callback = nil
	}
	var call callWithResult[C.ucall_http_batch_endpoint_t]
	arguments := open[C.ucall_server_add_http_batch_endpoint_t](&call)
	*arguments = C.ucall_server_add_http_batch_endpoint_t{
		server:                   server.handle,
		outcome:                  call.outcome(),
		uri_template:             call.text(path),
		verb:                     C.ucall_verb_t(verb),
		callback:                 callback,
		context:                  contextOf(handle),
		min_batch_size:           C.size_t(options.MinSize),
		max_batch_size:           C.size_t(options.MaxSize),
		max_latency_microseconds: microseconds(options.MaxLatency),
		endpoint:                 call.result,
	}
	C.ucall_server_add_http_batch_endpoint(arguments)
	endpoint, err := block(&call, nil)
	if err != nil {
		handle.Delete()
		return nil, err
	}
	server.handles = append(server.handles, handle)
	return &BatchEndpoint{server: server.handle, handle: endpoint}, nil
}

// TakeBatch runs the handler on this goroutine if a batch is due, waiting up to timeout for one;
// zero performs one nonblocking round.
func (endpoint *BatchEndpoint) TakeBatch(timeout time.Duration) error {
	var call callWithResult[struct{}]
	arguments := open[C.ucall_server_take_batch_t](&call)
	*arguments = C.ucall_server_take_batch_t{
		server: endpoint.server, outcome: call.outcome(), endpoint: endpoint.handle,
		timeout_microseconds: microseconds(timeout)}
	C.ucall_server_take_batch(arguments)
	_, err := block(&call, nil)
	return err
}

// TakeBatches runs the handler on this goroutine for every due batch until the server stops.
func (endpoint *BatchEndpoint) TakeBatches() error {
	var call callWithResult[struct{}]
	arguments := open[C.ucall_server_take_batches_t](&call)
	*arguments = C.ucall_server_take_batches_t{
		server: endpoint.server, outcome: call.outcome(), endpoint: endpoint.handle}
	C.ucall_server_take_batches(arguments)
	_, err := block(&call, nil)
	return err
}

// BatchEndpointStatistics count a batch endpoint's batches and requests, and why each batch
// dispatched: on reaching the maximum size, the minimum size, or the latency.
type BatchEndpointStatistics struct {
	Batches        uint64
	Requests       uint64
	FilledBatches  uint64
	ReadyBatches   uint64
	ExpiredBatches uint64
}

// Statistics copies the endpoint's counters, from any goroutine while it is polled.
func (endpoint *BatchEndpoint) Statistics() (BatchEndpointStatistics, error) {
	var call callWithResult[BatchEndpointStatistics]
	arguments := open[C.ucall_server_batch_endpoint_statistics_t](&call)
	*arguments = C.ucall_server_batch_endpoint_statistics_t{
		server: endpoint.server, outcome: call.outcome(), endpoint: endpoint.handle,
		statistics: (*C.ucall_batch_endpoint_statistics_t)(unsafe.Pointer(call.result))}
	C.ucall_server_batch_endpoint_statistics(arguments)
	return block(&call, nil)
}

// endregion: Batches
