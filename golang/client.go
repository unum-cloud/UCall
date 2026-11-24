// Clients that submit calls and take their completions, and the responses they own.
//
// File: golang/client.go
// Author: Ash Vardanian
// Date: November 18, 2026

package ucall

import (
	"iter"
	"runtime"
	"runtime/cgo"
	"time"
	"unsafe"
)

/*
// Calls and response reads carry no callback field, so each claims both promises.
#cgo noescape ucall_client_call
#cgo nocallback ucall_client_call
#cgo noescape ucall_client_response_header
#cgo nocallback ucall_client_response_header
#cgo noescape ucall_client_response_fields_count
#cgo nocallback ucall_client_response_fields_count
#cgo noescape ucall_client_response_field
#cgo nocallback ucall_client_response_field
#cgo noescape ucall_client_response_body
#cgo nocallback ucall_client_response_body
#cgo noescape ucall_client_response_body_chunk
#cgo nocallback ucall_client_response_body_chunk

// Starting a client carries its log sink and authorizer, and taking completions runs them with no
// callback field of its own, so each claims only noescape.
#cgo noescape ucall_client_init
#cgo noescape ucall_client_take_completed
#cgo noescape ucall_client_take_completed_call

#include <stdlib.h>
#include "shim.h"
*/
import "C"

// region: Options

// ClientOptions is what a client may hold open at once, how long it waits, and who it is under
// Noise. Connections is required; every other zero field takes its documented default.
type ClientOptions struct {
	// Connections open at once; zero fails with StatusInvalidArgument.
	Connections uint
	// PipelinedCalls one connection may carry at once; zero means one.
	PipelinedCalls uint
	// Calls admitted at once, unretrieved completions included; zero means Connections times
	// PipelinedCalls.
	Calls uint
	// ConnectTimeout bounds establishing a connection; zero means 5 seconds.
	ConnectTimeout time.Duration
	// CallTimeout bounds a full exchange, queueing and redirects included; zero means 30 seconds.
	CallTimeout time.Duration
	// NoisePrivateKey is the client identity for Noise handshakes.
	NoisePrivateKey *NoiseKey
	// PeerAuthorizer vets each server's authenticated static key; Noise XX calls need one.
	PeerAuthorizer PeerAuthorizer
	// Backend is the requested I/O backend.
	Backend Backend
	// CPUClassCeiling caps the CPU class; CPUClassUnknown sets no ceiling.
	CPUClassCeiling CPUClass
	// Log is where log lines go; nil keeps the client silent.
	Log *Log
	// MaxResponseBytes caps what a call buffers, failing it with StatusOverflow past the cap; zero
	// takes the largest receive buffer the kernel grants a socket.
	MaxResponseBytes uint
	// Server, when set, drives this client through one of its event loops, polled on that loop's
	// goroutine only; the client must be closed before the server.
	Server *Server
	// EventLoop is which of Server's event loops.
	EventLoop uint
}

// ClientCallOptions is one call's time budget, retries, redirects, security and body delivery,
// each zero field taking its default.
type ClientCallOptions struct {
	// Timeout bounds the call, queueing and redirects included; zero takes the client's.
	Timeout time.Duration
	// MaxRetries are additional connection attempts; zero means 3.
	MaxRetries uint
	// MaxRedirects are the redirect hops followed; zero means 5.
	MaxRedirects uint
	// Security is the transport the call runs over.
	Security Security
	// NoisePrivateKey is the client's identity, needed by Noise KK.
	NoisePrivateKey *NoiseKey
	// NoisePeerKey is the server's expected key, needed by Noise IK and KK.
	NoisePeerKey *NoiseKey
	// BodyDelivery completes the call once the body is buffered, or once the head arrived.
	BodyDelivery BodyDelivery
}

// ClientCall is one call to submit; the client pins its URL, header lines and body until it
// completes.
type ClientCall struct {
	Verb    Verb
	URL     string
	Headers []string
	Body    []byte
	Options ClientCallOptions
}

// endregion: Options

// region: Client

// Completed is one finished call: the context it was submitted with, and its response, whatever
// its HTTP status, or why none arrived.
type Completed struct {
	Context  uint64
	Response *Response
	Err      error
}

// admitted is one call slot: the caller's context and the pins on the inputs the library reads
// until the call completes.
type admitted struct {
	context uint64
	inputs  call
}

// Client is an HTTP client used by one goroutine at a time. It submits calls without driving the
// network, and polls to drive them and take what finished.
//
// Its call slots, which pin each call's inputs, and its completion table are sized by its call
// budget when it starts; a blocking call takes its own completion out of the library, leaving the
// others queued there for TakeCompleted.
type Client struct {
	handle    C.ucall_client_t
	handles   []cgo.Handle
	calls     []admitted
	free      []int
	retrieved []C.ucall_completed_call_t
}

// initialized is what initialization reads and writes: the client, its options, and its options
// with every default filled.
type initialized struct {
	client            C.ucall_client_t
	options, resolved C.ucall_client_options_t
}

// NewClient starts a client, which holds no connection until its first call is polled.
func NewClient(config *ClientOptions) (*Client, error) {
	options := configOf(config)
	client := &Client{}
	var bound C.ucall_server_t
	if options.Server != nil {
		bound = options.Server.handle
	}
	var call callWithResult[initialized]
	arguments := open[C.ucall_client_init_t](&call)
	authorize, authorizeContext := authorizer(options.PeerAuthorizer, &client.handles)
	call.result.options = C.ucall_client_options_t{
		max_concurrent_connections:   C.size_t(options.Connections),
		max_pipelined_calls:          C.size_t(options.PipelinedCalls),
		connect_timeout_microseconds: microseconds(options.ConnectTimeout),
		call_timeout_microseconds:    microseconds(options.CallTimeout),
		noise_private_key:            C.ucall_go_key(call.key(options.NoisePrivateKey)),
		peer_authorizer:              authorize,
		peer_authorizer_context:      authorizeContext,
		log:                          options.Log.lowered(&client.handles),
		max_concurrent_calls:         C.size_t(options.Calls),
		backend:                      C.ucall_io_backend_t(options.Backend),
		cpu_class_ceiling:            C.ucall_cpu_class_t(options.CPUClassCeiling),
		max_response_bytes:           C.size_t(options.MaxResponseBytes),
		server:                       bound,
		event_loop:                   C.size_t(options.EventLoop),
	}
	*arguments = C.ucall_client_init_t{
		client:   &call.result.client,
		outcome:  call.outcome(),
		options:  &call.result.options,
		resolved: &call.result.resolved,
	}
	C.ucall_client_init(arguments)
	result, err := block(&call, nil)
	if err != nil {
		client.release()
		return nil, err
	}
	capacity := int(result.resolved.max_concurrent_calls)
	client.handle = result.client
	client.calls = make([]admitted, capacity)
	client.free = make([]int, capacity)
	for slot := range capacity {
		client.free[slot] = capacity - 1 - slot
	}
	// The library writes completions into C memory, so polling pins nothing.
	table := (*C.ucall_completed_call_t)(C.calloc(C.size_t(max(capacity, 1)), C.size_t(unsafe.Sizeof(C.ucall_completed_call_t{}))))
	client.retrieved = unsafe.Slice(table, capacity)
	return client, nil
}

// release deletes the handles the library calls back through, after the handle they serve is freed.
func (client *Client) release() {
	for _, handle := range client.handles {
		handle.Delete()
	}
	client.handles = nil
}

// Close cancels the calls in flight, discards completions not yet taken, and frees the client;
// responses already taken stay readable. It is idempotent.
func (client *Client) Close() error {
	if client.handle == nil {
		return nil
	}
	C.ucall_client_free(client.handle)
	client.handle = nil
	for slot := range client.calls {
		client.calls[slot].inputs.pinner.Unpin()
	}
	C.free(unsafe.Pointer(unsafe.SliceData(client.retrieved)))
	client.retrieved = nil
	client.release()
	return nil
}

// admit pins request's inputs in a free slot and submits it, answering the slot it took. A closed
// client refuses here, before its inputs are pinned for a call C would refuse.
func (client *Client) admit(request ClientCall, context uint64) (int, error) {
	if client.handle == nil {
		return 0, fail(StatusUninitialized, "the client is closed or was never started")
	}
	if len(client.free) == 0 {
		return 0, fail(StatusContended, "every call slot holds an unretrieved call")
	}
	slot := client.free[len(client.free)-1]
	client.free = client.free[:len(client.free)-1]
	admitted := &client.calls[slot]
	admitted.context = context
	inputs := &admitted.inputs
	headers, headersCount := inputs.texts(request.Headers)
	options := &request.Options
	var call callWithResult[struct{}]
	arguments := open[C.ucall_client_call_t](&call)
	*arguments = C.ucall_client_call_t{
		client:        client.handle,
		outcome:       call.outcome(),
		url:           inputs.text(request.URL),
		verb:          C.ucall_verb_t(request.Verb),
		headers:       headers,
		headers_count: headersCount,
		body:          inputs.bytes(request.Body),
		options: C.ucall_client_call_options_t{
			timeout_microseconds: microseconds(options.Timeout),
			max_retries:          C.size_t(options.MaxRetries),
			max_redirects:        C.size_t(options.MaxRedirects),
			security:             C.ucall_security_t(options.Security),
			noise_private_key:    C.ucall_go_key(inputs.key(options.NoisePrivateKey)),
			noise_peer_key:       C.ucall_go_key(inputs.key(options.NoisePeerKey)),
			body_delivery:        C.ucall_body_delivery_t(options.BodyDelivery),
		},
		context: C.ucall_go_context(C.uintptr_t(slot)),
	}
	C.ucall_client_call(arguments)
	if _, err := block(&call, nil); err != nil {
		admitted.inputs.pinner.Unpin()
		client.free = append(client.free, slot)
		return 0, err
	}
	return slot, nil
}

// Submit admits call without driving the network; its one completion carries context. A full
// client refuses with StatusContended until completions are taken.
func (client *Client) Submit(call ClientCall, context uint64) error {
	_, err := client.admit(call, context)
	return err
}

// retrieve drives the client and takes up to capacity completions into the table.
func (client *Client) retrieve(capacity int, timeout time.Duration) (int, error) {
	var call callWithResult[C.size_t]
	arguments := open[C.ucall_client_take_completed_t](&call)
	*arguments = C.ucall_client_take_completed_t{
		client:               client.handle,
		outcome:              call.outcome(),
		calls:                unsafe.SliceData(client.retrieved),
		capacity:             C.size_t(min(capacity, len(client.retrieved))),
		count:                call.result,
		timeout_microseconds: microseconds(timeout),
	}
	C.ucall_client_take_completed(arguments)
	count, err := block(&call, nil)
	return int(count), err
}

// complete frees the slot of a retrieved completion and lifts it into its Go form.
func (client *Client) complete(raw C.ucall_completed_call_t) (int, Completed) {
	slot := int(uintptr(raw.context))
	admitted := &client.calls[slot]
	admitted.inputs.pinner.Unpin()
	client.free = append(client.free, slot)
	completed := Completed{Context: admitted.context}
	if completed.Err = check(raw.outcome); completed.Err != nil {
		C.ucall_client_response_free(raw.response)
		return slot, completed
	}
	completed.Response = newResponse(client.handle, raw.response)
	return slot, completed
}

// TakeCompleted drives every admitted call on this goroutine and fills the front of completed with
// finished ones, waiting up to timeout for the first; zero performs one nonblocking round, and an
// empty completed only advances the network.
func (client *Client) TakeCompleted(completed []Completed, timeout time.Duration) ([]Completed, error) {
	count, err := client.retrieve(len(completed), timeout)
	if err != nil {
		return nil, err
	}
	for position := range count {
		_, completed[position] = client.complete(client.retrieved[position])
	}
	return completed[:count], nil
}

// Call submits request and polls until it finishes, leaving the completions of other calls queued
// for TakeCompleted. The response arrives whatever its HTTP status; a failed exchange answers its
// error.
func (client *Client) Call(request ClientCall) (*Response, error) {
	slot, err := client.admit(request, 0)
	if err != nil {
		return nil, err
	}
	var call callWithResult[C.ucall_completed_call_t]
	arguments := open[C.ucall_client_take_completed_call_t](&call)
	*arguments = C.ucall_client_take_completed_call_t{
		client: client.handle, outcome: call.outcome(), context: C.ucall_go_context(C.uintptr_t(slot)), call: call.result}
	C.ucall_client_take_completed_call(arguments)
	taken, err := block(&call, nil)
	if err != nil {
		return nil, err
	}
	_, completed := client.complete(taken)
	return completed.Response, completed.Err
}

// Get fetches url and polls until the response arrives.
func (client *Client) Get(url string) (*Response, error) {
	return client.Call(ClientCall{Verb: VerbGet, URL: url})
}

// Post posts body to url and polls until the response arrives.
func (client *Client) Post(url string, body []byte) (*Response, error) {
	return client.Call(ClientCall{Verb: VerbPost, URL: url, Body: body})
}

// Put puts body at url and polls until the response arrives.
func (client *Client) Put(url string, body []byte) (*Response, error) {
	return client.Call(ClientCall{Verb: VerbPut, URL: url, Body: body})
}

// Delete deletes url and polls until the response arrives.
func (client *Client) Delete(url string) (*Response, error) {
	return client.Call(ClientCall{Verb: VerbDelete, URL: url})
}

// Patch patches url with body and polls until the response arrives.
func (client *Client) Patch(url string, body []byte) (*Response, error) {
	return client.Call(ClientCall{Verb: VerbPatch, URL: url, Body: body})
}

// endregion: Client

// region: Responses

// Response is a received HTTP response, whatever its status. It owns its received bytes, so it
// stays readable after its client is closed; Close frees it, and the collector frees one dropped.
type Response struct {
	client  C.ucall_client_t
	handle  C.ucall_received_http_response_t
	cleanup runtime.Cleanup
}

func newResponse(client C.ucall_client_t, handle C.ucall_received_http_response_t) *Response {
	response := &Response{client: client, handle: handle}
	response.cleanup = runtime.AddCleanup(response, freeResponse, handle)
	return response
}

func freeResponse(handle C.ucall_received_http_response_t) { C.ucall_client_response_free(handle) }

// Close frees the response, ending every slice viewing it. It is idempotent.
func (response *Response) Close() error {
	if response.handle == nil {
		return nil
	}
	response.cleanup.Stop()
	C.ucall_client_response_free(response.handle)
	response.handle = nil
	return nil
}

// StatusCode is the status code the server sent.
func (response *Response) StatusCode() HTTPStatus {
	return HTTPStatus(C.ucall_client_response_status(response.handle))
}

// Body is the body, decoded from chunked framing if it arrived that way, valid until Close; a
// streamed call refuses it, as BodyChunk pulls its body.
func (response *Response) Body() ([]byte, error) {
	var call callWithResult[C.ucall_bytes_view_t]
	arguments := open[C.ucall_client_response_body_t](&call)
	*arguments = C.ucall_client_response_body_t{
		response: response.handle, outcome: call.outcome(), body: call.result}
	C.ucall_client_response_body(arguments)
	body, err := block(&call, nil)
	return viewed(body), err
}

// Header is the value of header name, matched case-insensitively, failing with StatusNotFound
// without one.
func (response *Response) Header(name string) ([]byte, error) {
	var call callWithResult[C.ucall_bytes_view_t]
	arguments := open[C.ucall_client_response_header_t](&call)
	*arguments = C.ucall_client_response_header_t{
		response: response.handle, outcome: call.outcome(), name: call.text(name), value: call.result}
	C.ucall_client_response_header(arguments)
	value, err := block(&call, nil)
	return viewed(value), err
}

// Fields yields every header field line in arrival order, as Request.Fields does.
func (response *Response) Fields() iter.Seq2[[]byte, []byte] {
	return func(yield func(name, value []byte) bool) {
		count := C.ucall_client_response_fields_count(response.handle)
		for index := C.size_t(0); index < count; index++ {
			var call callWithResult[[2]C.ucall_bytes_view_t]
			arguments := open[C.ucall_client_response_field_t](&call)
			*arguments = C.ucall_client_response_field_t{
				response: response.handle, outcome: call.outcome(), index: index,
				name: &call.result[0], value: &call.result[1]}
			C.ucall_client_response_field(arguments)
			field, err := block(&call, nil)
			if err != nil || !yield(viewed(field[0]), viewed(field[1])) {
				return
			}
		}
	}
}

// BodyChunk pulls the body bytes of a streamed call decoded since the last pull, valid until the
// next pull, empty once the body ended. Pulls never wait: with nothing decoded yet it fails with
// StatusWouldBlock, and polling the client with TakeCompleted moves the next bytes in.
func (response *Response) BodyChunk() ([]byte, error) {
	var call callWithResult[C.ucall_bytes_view_t]
	arguments := open[C.ucall_client_response_body_chunk_t](&call)
	*arguments = C.ucall_client_response_body_chunk_t{
		client: response.client, outcome: call.outcome(), response: response.handle, data: call.result}
	C.ucall_client_response_body_chunk(arguments)
	chunk, err := block(&call, nil)
	return viewed(chunk), err
}

// endregion: Responses
