//! Clients: HTTP calls submitted and polled on one owner thread.
//!
//! [`Client::submit`] admits a call without driving the network, and [`Client::take_completed`]
//! drives it and retrieves finished calls in batches tagged with the caller's context. The client
//! starts no threads, and the type system keeps it on the thread that created it.
//!
//! File: rust/client.rs
//! Author: Ash Vardanian
//! Date: October 25, 2026

// The C mirror keeps the C spelling of every name.
#![allow(non_camel_case_types)]

use core::ffi::c_void;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use core::ptr;
use core::task::{Context, Poll};
use core::time::Duration;
use std::borrow::Cow;
use std::sync::Arc;
use std::thread::{self, ThreadId};

use crate::server::{Server, ServerCore};
use crate::types::{
    Backend, BodyDelivery, CPUClass, HTTPStatus, Log, NoiseKey, PeerAuthorizer, Result, Security, Status, Verb, check,
    fail, microseconds, ucall_body_delivery_t, ucall_bytes_view_t, ucall_client_t, ucall_cpu_class_t,
    ucall_http_status_t, ucall_io_backend_t, ucall_log_t, ucall_noise_key_t, ucall_outcome_t, ucall_peer_authorizer_t,
    ucall_received_http_response_t, ucall_security_t, ucall_server_t, ucall_verb_t, view, viewed,
};

// region: Raw Declarations

#[repr(C)]
#[derive(Clone, Copy)]
struct ucall_client_options_t {
    max_concurrent_connections: usize,
    max_pipelined_calls: usize,
    connect_timeout_microseconds: usize,
    call_timeout_microseconds: usize,
    noise_private_key: *const ucall_noise_key_t,
    peer_authorizer: ucall_peer_authorizer_t,
    peer_authorizer_context: *mut c_void,
    log: ucall_log_t,
    max_concurrent_calls: usize,
    backend: ucall_io_backend_t,
    cpu_class_ceiling: ucall_cpu_class_t,
    max_response_bytes: usize,
    server: ucall_server_t,
    event_loop: usize,
}

#[repr(C)]
struct ucall_client_init_t {
    client: *mut ucall_client_t,
    outcome: *mut ucall_outcome_t,
    options: *const ucall_client_options_t,
    resolved: *mut ucall_client_options_t,
}

#[repr(C)]
struct ucall_client_call_options_t {
    timeout_microseconds: usize,
    max_retries: usize,
    max_redirects: usize,
    security: ucall_security_t,
    noise_private_key: *const ucall_noise_key_t,
    noise_peer_key: *const ucall_noise_key_t,
    body_delivery: ucall_body_delivery_t,
}

#[repr(C)]
struct ucall_client_call_t {
    client: ucall_client_t,
    outcome: *mut ucall_outcome_t,
    url: ucall_bytes_view_t,
    verb: ucall_verb_t,
    headers: *const ucall_bytes_view_t,
    headers_count: usize,
    body: ucall_bytes_view_t,
    options: ucall_client_call_options_t,
    context: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ucall_completed_call_t {
    context: *mut c_void,
    outcome: ucall_outcome_t,
    response: ucall_received_http_response_t,
}

#[repr(C)]
struct ucall_client_take_completed_t {
    client: ucall_client_t,
    outcome: *mut ucall_outcome_t,
    calls: *mut ucall_completed_call_t,
    capacity: usize,
    count: *mut usize,
    timeout_microseconds: usize,
}

#[repr(C)]
struct ucall_client_take_completed_call_t {
    client: ucall_client_t,
    outcome: *mut ucall_outcome_t,
    context: *mut c_void,
    call: *mut ucall_completed_call_t,
    timeout_microseconds: usize,
}

#[repr(C)]
struct ucall_client_response_header_t {
    response: ucall_received_http_response_t,
    outcome: *mut ucall_outcome_t,
    name: ucall_bytes_view_t,
    value: *mut ucall_bytes_view_t,
}

#[repr(C)]
struct ucall_client_response_field_t {
    response: ucall_received_http_response_t,
    outcome: *mut ucall_outcome_t,
    index: usize,
    name: *mut ucall_bytes_view_t,
    value: *mut ucall_bytes_view_t,
}

#[repr(C)]
struct ucall_client_response_body_t {
    response: ucall_received_http_response_t,
    outcome: *mut ucall_outcome_t,
    body: *mut ucall_bytes_view_t,
}

#[repr(C)]
struct ucall_client_response_body_chunk_t {
    client: ucall_client_t,
    outcome: *mut ucall_outcome_t,
    response: ucall_received_http_response_t,
    data: *mut ucall_bytes_view_t,
}

unsafe extern "C" {
    fn ucall_client_init(arguments: *mut ucall_client_init_t);
    fn ucall_client_free(client: ucall_client_t);
    fn ucall_client_call(arguments: *mut ucall_client_call_t);
    fn ucall_client_take_completed(arguments: *mut ucall_client_take_completed_t);
    fn ucall_client_take_completed_call(arguments: *mut ucall_client_take_completed_call_t);
    fn ucall_client_response_status(response: ucall_received_http_response_t) -> ucall_http_status_t;
    fn ucall_client_response_header(arguments: *mut ucall_client_response_header_t);
    fn ucall_client_response_fields_count(response: ucall_received_http_response_t) -> usize;
    fn ucall_client_response_field(arguments: *mut ucall_client_response_field_t);
    fn ucall_client_response_body(arguments: *mut ucall_client_response_body_t);
    fn ucall_client_response_body_chunk(arguments: *mut ucall_client_response_body_chunk_t);
    fn ucall_client_response_free(response: ucall_received_http_response_t);
}

// endregion: Raw Declarations

/// What a client may hold open at once, how long it waits, and who it is under Noise.
///
/// `connections` is required; every other zero field takes its documented default. The client
/// borrows the authorizer's and the log's handlers and the bound server for `'handlers`.
#[derive(Default)]
pub struct ClientOptions<'handlers> {
    /// Connections open at once; zero fails with [`Status::InvalidArgument`].
    pub connections: usize,
    /// Calls one connection may carry at once; zero means one.
    pub pipelined_calls: usize,
    /// Calls admitted at once, unretrieved completions included; zero means `connections` times
    /// `pipelined_calls`.
    pub calls: usize,
    /// Time budget for establishing a connection; zero means 5 seconds.
    pub connect_timeout: Duration,
    /// Time budget for a full exchange, including queueing and redirects; zero means 30 seconds.
    pub call_timeout: Duration,
    /// The client identity for Noise handshakes.
    pub noise_private_key: Option<NoiseKey>,
    /// Vets each server's authenticated static key; required for Noise XX calls.
    pub peer_authorizer: Option<PeerAuthorizer<'handlers>>,
    /// The requested I/O backend.
    pub backend: Backend,
    /// A ceiling on the CPU class, intersected with what the constructing thread's CPU runs: the
    /// newest compiled class fitting both runs, and `None` sets no ceiling.
    pub cpu_class_ceiling: Option<CPUClass>,
    /// Where log lines go; `None` keeps the client silent.
    pub log: Option<Log<'handlers>>,
    /// The largest response a call buffers, past which it fails with `Status::Overflow`; zero
    /// takes the largest receive buffer the kernel grants a socket.
    pub max_response_bytes: usize,
    /// A server whose event loop drives this client through that loop's polling, sharing its
    /// engine; bound before the loop first polls, used only on its polling thread, and its
    /// [`Client::take_completed`] only hands out what the loop finished.
    pub server: Option<&'handlers Server<'handlers>>,
    /// Which of `server`'s event loops; ignored without `server`.
    pub event_loop: usize,
}

/// One call's time budget, retries, redirects, security and body delivery, each zero field taking
/// its default.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ClientCallOptions {
    /// Time budget including queueing and redirects; zero takes the client's `call_timeout`.
    pub timeout: Duration,
    /// Connection attempts made again before sending the request; zero means 3.
    pub max_retries: usize,
    /// Redirect hops followed before failing; zero means 5.
    pub max_redirects: usize,
    /// The transport security; an `http+noise://` URL implies Noise XX.
    pub security: Security,
    /// The private key this call authenticates with in place of the client's own.
    pub noise_private_key: Option<NoiseKey>,
    /// The server's static key, which Noise IK and KK need in advance.
    pub noise_peer_key: Option<NoiseKey>,
    /// When the call completes: once the whole response is buffered, or with
    /// [`BodyDelivery::Streamed`] once its head arrived, the body pulled through
    /// [`Response::body_chunk`] past `max_response_bytes`. Redirects stay buffered.
    pub body_delivery: BodyDelivery,
}

/// One HTTP call, owning everything the library reads until the call completes.
#[derive(Clone, Debug)]
pub struct ClientCall {
    /// The HTTP method.
    pub verb: Verb,
    /// The full URL, `http://` or `http+noise://`.
    pub url: Cow<'static, str>,
    /// Full header lines like "accept: text/plain"; Host, Content-Length and User-Agent are
    /// generated.
    pub headers: Vec<Cow<'static, [u8]>>,
    /// The request body; empty sends no payload.
    pub body: Cow<'static, [u8]>,
    /// The call's own time budget, retries, redirects and security.
    pub options: ClientCallOptions,
}

impl ClientCall {
    /// A GET of `url` with no headers.
    pub fn get(url: impl Into<Cow<'static, str>>) -> Self {
        ClientCall {
            verb: Verb::Get,
            url: url.into(),
            headers: Vec::new(),
            body: Cow::Borrowed(&[]),
            options: ClientCallOptions::default(),
        }
    }

    /// A POST of `body` to `url` with no headers.
    pub fn post(url: impl Into<Cow<'static, str>>, body: impl Into<Cow<'static, [u8]>>) -> Self {
        ClientCall { verb: Verb::Post, body: body.into(), ..ClientCall::get(url) }
    }

    /// A PUT of `body` to `url` with no headers.
    pub fn put(url: impl Into<Cow<'static, str>>, body: impl Into<Cow<'static, [u8]>>) -> Self {
        ClientCall { verb: Verb::Put, ..ClientCall::post(url, body) }
    }

    /// A DELETE of `url` with no headers.
    pub fn delete(url: impl Into<Cow<'static, str>>) -> Self {
        ClientCall { verb: Verb::Delete, ..ClientCall::get(url) }
    }

    /// A PATCH of `body` to `url` with no headers.
    pub fn patch(url: impl Into<Cow<'static, str>>, body: impl Into<Cow<'static, [u8]>>) -> Self {
        ClientCall { verb: Verb::Patch, ..ClientCall::post(url, body) }
    }
}

/// The library's client handle and the server a bound one keeps alive.
struct ClientCore {
    raw: ucall_client_t,
    // A bound client's server must outlive the handle, which `Drop` frees before its fields.
    server: Option<Arc<ServerCore>>,
}

impl Drop for ClientCore {
    fn drop(&mut self) {
        unsafe { ucall_client_free(self.raw) }
    }
}

/// One admission slot: the caller's context and the inputs the library borrows until completion.
#[derive(Default)]
struct Call {
    context: u64,
    request: Option<ClientCall>,
    headers: Vec<ucall_bytes_view_t>,
}

/// An HTTP client, created, submitted to, polled, and dropped on one thread.
///
/// Allocations happen at construction, sized by the resolved call budget, and in header arrays
/// that grow to their largest call once; polling allocates nothing. Dropping it cancels the calls
/// in flight, while retrieved [`Response`]s stay readable.
///
/// ```
/// use std::time::Duration;
/// use ucall::*;
/// # let echo = |request: Request| {
/// #     let body = request.body().to_vec();
/// #     let _ = request.reply(HTTPStatus::OK, &[], &body);
/// # };
/// # let mut server = Server::new(&[Interface::new("127.0.0.1:0")])?;
/// # server.post("/echo", &echo)?;
/// # let address = server.address(0).unwrap().to_owned();
/// # std::thread::scope(|scope| {
/// # scope.spawn(|| server.take_calls(0));
/// # let calls = || -> Result<()> {
///
/// let mut client = Client::new(ClientOptions { connections: 2, pipelined_calls: 4, ..Default::default() })?;
/// for index in 0..8u64 {
///     client.submit(ClientCall::post(format!("http://{address}/echo"), vec![index as u8]), index)?;
/// }
/// let mut completed: [Completed; 8] = Default::default();
/// let mut answered = 0;
/// while answered < 8 {
///     for done in client.take_completed(&mut completed, Duration::from_secs(1))? {
///         let response = done.response.as_ref().map_err(|error| *error)?;
///         assert_eq!(response.body()?, [done.context as u8]);
///         answered += 1;
///     }
/// }
///
/// let response = client.post(format!("http://{address}/echo"), b"blocking".as_slice())?;
/// drop(client);
/// assert_eq!(response.body()?, b"blocking");
/// # Ok(())
/// # };
/// # let result = calls();
/// # server.stop();
/// # result
/// # })?;
/// # Ok::<(), ucall::Error>(())
/// ```
pub struct Client<'handlers> {
    // Dropped before `calls`: the library never reads call inputs once nobody polls it.
    core: ClientCore,
    calls: Vec<Call>,
    free: Vec<usize>,
    retrieved: Vec<ucall_completed_call_t>,
    handlers: PhantomData<&'handlers ()>,
}

impl<'handlers> Client<'handlers> {
    /// Starts a client; it holds no connection until the first call is polled.
    pub fn new(options: ClientOptions<'handlers>) -> Result<Client<'handlers>> {
        let mut core = ClientCore { raw: ptr::null_mut(), server: options.server.map(Server::core) };
        let (peer_authorizer, peer_authorizer_context) = PeerAuthorizer::raw(options.peer_authorizer);
        let config = ucall_client_options_t {
            max_concurrent_connections: options.connections,
            max_pipelined_calls: options.pipelined_calls,
            connect_timeout_microseconds: microseconds(options.connect_timeout),
            call_timeout_microseconds: microseconds(options.call_timeout),
            noise_private_key: options.noise_private_key.as_ref().map_or(ptr::null(), ptr::from_ref),
            peer_authorizer,
            peer_authorizer_context,
            log: Log::raw(options.log),
            max_concurrent_calls: options.calls,
            backend: options.backend.to_raw(),
            cpu_class_ceiling: CPUClass::to_raw(options.cpu_class_ceiling),
            max_response_bytes: options.max_response_bytes,
            server: core.server.as_ref().map_or(ptr::null_mut(), |server| server.raw),
            event_loop: options.event_loop,
        };
        let mut resolved = config;
        let mut outcome = ucall_outcome_t::default();
        let mut arguments = ucall_client_init_t {
            client: &mut core.raw,
            outcome: &mut outcome,
            options: &config,
            resolved: &mut resolved,
        };
        unsafe { ucall_client_init(&mut arguments) };
        check(outcome)?;

        let capacity = resolved.max_concurrent_calls;
        let empty = ucall_completed_call_t {
            context: ptr::null_mut(),
            outcome: ucall_outcome_t::default(),
            response: ptr::null_mut(),
        };
        Ok(Client {
            core,
            calls: (0..capacity).map(|_| Call::default()).collect(),
            free: (0..capacity).rev().collect(),
            retrieved: vec![empty; capacity],
            handlers: PhantomData,
        })
    }

    /// Admits a call into a free slot, answering the slot it took.
    fn admit(&mut self, request: ClientCall, context: u64) -> Result<usize> {
        let index = self.free.pop().ok_or(fail(Status::Contended, "every call slot holds an unretrieved call"))?;
        let call = &mut self.calls[index];
        call.context = context;
        let request = call.request.insert(request);
        call.headers.clear();
        call.headers.extend(request.headers.iter().map(|line| view(line)));
        let mut outcome = ucall_outcome_t::default();
        let mut arguments = ucall_client_call_t {
            client: self.core.raw,
            outcome: &mut outcome,
            url: view(request.url.as_bytes()),
            verb: request.verb.to_raw(),
            headers: call.headers.as_ptr(),
            headers_count: call.headers.len(),
            body: view(&request.body),
            options: ucall_client_call_options_t {
                timeout_microseconds: microseconds(request.options.timeout),
                max_retries: request.options.max_retries,
                max_redirects: request.options.max_redirects,
                security: request.options.security.to_raw(),
                noise_private_key: request.options.noise_private_key.as_ref().map_or(ptr::null(), ptr::from_ref),
                noise_peer_key: request.options.noise_peer_key.as_ref().map_or(ptr::null(), ptr::from_ref),
                body_delivery: request.options.body_delivery.to_raw(),
            },
            context: index as *mut c_void,
        };
        unsafe { ucall_client_call(&mut arguments) };
        if let Err(error) = check(outcome) {
            call.request = None;
            self.free.push(index);
            return Err(error);
        }
        Ok(index)
    }

    /// Admits `request` without driving the network; its completion carries `context`.
    ///
    /// Success guarantees exactly one completion from [`Client::take_completed`]; a full client
    /// refuses with [`Status::Contended`] until completions are retrieved.
    pub fn submit(&mut self, request: ClientCall, context: u64) -> Result<()> {
        self.admit(request, context).map(|_| ())
    }

    /// Drives the library and retrieves up to `capacity` raw completions into `retrieved`.
    fn retrieve(&mut self, capacity: usize, timeout: Duration) -> Result<usize> {
        let mut count = 0;
        let mut outcome = ucall_outcome_t::default();
        let mut arguments = ucall_client_take_completed_t {
            client: self.core.raw,
            outcome: &mut outcome,
            calls: self.retrieved.as_mut_ptr(),
            capacity: capacity.min(self.retrieved.len()),
            count: &mut count,
            timeout_microseconds: microseconds(timeout),
        };
        unsafe { ucall_client_take_completed(&mut arguments) };
        check(outcome).map(|()| count)
    }

    /// Frees the slot of a retrieved completion and lifts it into its safe form.
    fn complete(&mut self, raw: ucall_completed_call_t) -> Completed {
        let index = raw.context as usize;
        let call = &mut self.calls[index];
        call.request = None;
        self.free.push(index);
        let response = match check(raw.outcome) {
            Ok(()) if !raw.response.is_null() => Ok(Response {
                raw: raw.response,
                client: self.core.raw,
                owner: thread::current().id(),
                bound: self.core.server.is_some(),
            }),
            Ok(()) => Err(fail(Status::Internal, "a successful call completed without a response")),
            Err(error) => {
                unsafe { ucall_client_response_free(raw.response) };
                Err(error)
            }
        };
        Completed { context: call.context, response }
    }

    /// Drives every admitted call on this thread and fills the front of `completed` with finished
    /// ones, waiting up to `timeout` for the first; zero performs one nonblocking round.
    ///
    /// Answers the filled prefix, empty when nothing finished in time.
    pub fn take_completed<'completed>(
        &mut self,
        completed: &'completed mut [Completed],
        timeout: Duration,
    ) -> Result<&'completed mut [Completed]> {
        let count = self.retrieve(completed.len(), timeout)?;
        for (position, entry) in completed[..count].iter_mut().enumerate() {
            *entry = self.complete(self.retrieved[position]);
        }
        Ok(&mut completed[..count])
    }

    /// Submits `request` and polls until it finishes, leaving other calls' completions queued in
    /// the library for the next [`Client::take_completed`].
    ///
    /// The response arrives whatever its HTTP status; a failed exchange answers its [`Error`].
    ///
    /// [`Error`]: crate::Error
    pub fn call(&mut self, request: ClientCall) -> Result<Response> {
        let index = self.admit(request, 0)?;
        let mut taken = ucall_completed_call_t {
            context: ptr::null_mut(),
            outcome: ucall_outcome_t::default(),
            response: ptr::null_mut(),
        };
        let mut outcome = ucall_outcome_t::default();
        let mut arguments = ucall_client_take_completed_call_t {
            client: self.core.raw,
            outcome: &mut outcome,
            context: index as *mut c_void,
            call: &mut taken,
            timeout_microseconds: 0,
        };
        unsafe { ucall_client_take_completed_call(&mut arguments) };
        check(outcome)?;
        self.complete(taken).response
    }

    /// Fetches `url` and polls until the response arrives.
    pub fn get(&mut self, url: impl Into<Cow<'static, str>>) -> Result<Response> {
        self.call(ClientCall::get(url))
    }

    /// Posts `body` to `url` and polls until the response arrives.
    pub fn post(&mut self, url: impl Into<Cow<'static, str>>, body: impl Into<Cow<'static, [u8]>>) -> Result<Response> {
        self.call(ClientCall::post(url, body))
    }

    /// Puts `body` at `url` and polls until the response arrives.
    pub fn put(&mut self, url: impl Into<Cow<'static, str>>, body: impl Into<Cow<'static, [u8]>>) -> Result<Response> {
        self.call(ClientCall::put(url, body))
    }

    /// Deletes `url` and polls until the response arrives.
    pub fn delete(&mut self, url: impl Into<Cow<'static, str>>) -> Result<Response> {
        self.call(ClientCall::delete(url))
    }

    /// Patches `url` with `body` and polls until the response arrives.
    pub fn patch(
        &mut self,
        url: impl Into<Cow<'static, str>>,
        body: impl Into<Cow<'static, [u8]>>,
    ) -> Result<Response> {
        self.call(ClientCall::patch(url, body))
    }
}

/// One finished call: the context it was submitted with, and its response or failure.
pub struct Completed {
    /// The context passed to [`Client::submit`].
    pub context: u64,
    /// The received response, whatever its HTTP status, or why none arrived.
    pub response: Result<Response>,
}

impl Default for Completed {
    /// An entry no poll filled yet, for preparing a buffer.
    fn default() -> Self {
        Completed { context: 0, response: Err(fail(Status::WouldBlock, "no call completed into this entry")) }
    }
}

/// A received HTTP response, freed on drop.
///
/// It owns its received bytes, so it stays readable after its [`Client`] is dropped and may move
/// to another thread. A response of a [`BodyDelivery::Streamed`] call is pulled through
/// [`Response::body_chunk`] on its client's thread instead.
///
/// ```
/// use ucall::*;
/// # let missing = |request: Request| {
/// #     let _ = request.reply(HTTPStatus::NOT_FOUND, &["x-reason: gone".into()], b"no such page");
/// # };
/// # let mut server = Server::new(&[Interface::new("127.0.0.1:0")])?;
/// # server.get("/missing", &missing)?;
/// # let address = server.address(0).unwrap().to_owned();
/// # std::thread::scope(|scope| {
/// # scope.spawn(|| server.take_calls(0));
/// # let calls = || -> Result<()> {
///
/// let mut client = Client::new(ClientOptions { connections: 1, ..Default::default() })?;
/// let response = client.get(format!("http://{address}/missing"))?;
/// drop(client);
/// let reader = std::thread::spawn(move || {
///     assert_eq!(response.status_code(), HTTPStatus::NOT_FOUND);
///     assert_eq!(response.header("X-Reason"), Some(b"gone".as_slice()));
///     assert_eq!(response.body(), Ok(b"no such page".as_slice()));
/// });
/// reader.join().unwrap();
/// # Ok(())
/// # };
/// # let result = calls();
/// # server.stop();
/// # result
/// # })?;
/// # Ok::<(), ucall::Error>(())
/// ```
pub struct Response {
    raw: ucall_received_http_response_t,
    // A pull never reads through the client, which only its owner advances, and only while a
    // body still arrives, which a freed client has ended.
    client: ucall_client_t,
    owner: ThreadId,
    // A server's event loop advances a bound client, so a pull finding nothing returns to it.
    bound: bool,
}

// The library reads a response without its client, and one thread at a time uses it.
unsafe impl Send for Response {}

impl Response {
    /// The status code the server sent.
    pub fn status_code(&self) -> HTTPStatus {
        HTTPStatus(unsafe { ucall_client_response_status(self.raw) })
    }

    /// The response body, decoded from chunked framing if it arrived that way; a streamed call,
    /// whose body [`Response::body_chunk`] pulls, fails with [`Status::InvalidArgument`].
    pub fn body(&self) -> Result<&[u8]> {
        let mut body = view(&[]);
        let mut outcome = ucall_outcome_t::default();
        let mut arguments = ucall_client_response_body_t { response: self.raw, outcome: &mut outcome, body: &mut body };
        unsafe { ucall_client_response_body(&mut arguments) };
        check(outcome).map(|()| unsafe { viewed(body) })
    }

    /// The value of header `name`, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        let mut value = view(&[]);
        let mut outcome = ucall_outcome_t::default();
        let mut arguments = ucall_client_response_header_t {
            response: self.raw,
            outcome: &mut outcome,
            name: view(name.as_bytes()),
            value: &mut value,
        };
        unsafe { ucall_client_response_header(&mut arguments) };
        check(outcome).ok().map(|()| unsafe { viewed(value) })
    }

    /// Every header field line in arrival order, repeated names apart: each name lowercased as
    /// the parser keeps it, and its value trimmed.
    pub fn fields(&self) -> impl Iterator<Item = (&[u8], &[u8])> + '_ {
        let count = unsafe { ucall_client_response_fields_count(self.raw) };
        (0..count).map_while(move |index| {
            let (mut name, mut value) = (view(&[]), view(&[]));
            let mut outcome = ucall_outcome_t::default();
            let mut arguments = ucall_client_response_field_t {
                response: self.raw,
                outcome: &mut outcome,
                index,
                name: &mut name,
                value: &mut value,
            };
            unsafe { ucall_client_response_field(&mut arguments) };
            check(outcome).ok().map(|()| unsafe { (viewed(name), viewed(value)) })
        })
    }

    /// Pulls the body bytes decoded since the last pull, advancing the client until they arrive;
    /// empty once the body ended.
    ///
    /// Every response of a [`BodyDelivery::Streamed`] call is pulled to its end or dropped, since
    /// its connection carries no other call meanwhile; dropping it early closes that connection
    /// and fails the calls pipelined behind it with [`Status::ConnectionClosed`]. A body cut
    /// short fails with [`Status::ConnectionClosed`], a malformed one with [`Status::Malformed`],
    /// a buffered response or a thread other than the client's with [`Status::InvalidArgument`].
    /// A client bound to a server advances only as that server's loop polls, so a pull finding
    /// nothing there fails with [`Status::WouldBlock`] instead, to be pulled again after the next
    /// [`Server::take_call`].
    pub fn body_chunk(&mut self) -> Result<&[u8]> {
        if thread::current().id() != self.owner {
            return Err(fail(Status::InvalidArgument, "a streamed response pulls on its client's thread"));
        }
        let mut data = view(&[]);
        let mut outcome = ucall_outcome_t::default();
        let mut arguments = ucall_client_response_body_chunk_t {
            client: self.client,
            outcome: ptr::addr_of_mut!(outcome),
            response: self.raw,
            data: ptr::addr_of_mut!(data),
        };
        let (mut count, mut advanced) = (0, ucall_outcome_t::default());
        let mut advance = ucall_client_take_completed_t {
            client: self.client,
            outcome: ptr::addr_of_mut!(advanced),
            calls: ptr::null_mut(),
            capacity: 0,
            count: &mut count,
            timeout_microseconds: 0,
        };
        loop {
            unsafe { ucall_client_response_body_chunk(&mut arguments) };
            match check(outcome) {
                Err(error) if error.status == Status::WouldBlock && !self.bound => {
                    unsafe { ucall_client_take_completed(&mut advance) };
                    check(advanced)?;
                }
                pulled => return pulled.map(|()| unsafe { viewed(data) }),
            }
        }
    }

    /// Pulls the body bytes decoded since the last pull as a future for async code, answering
    /// what [`Response::body_chunk`] answers without spinning the thread that awaits it.
    ///
    /// Every poll pulls once and, while nothing was decoded, advances a client with its own engine
    /// and yields to the executor.
    pub fn next_body_chunk(&mut self) -> ResponseBodyChunk<'_> {
        ResponseBodyChunk { response: self }
    }
}

/// A pull of a response's next body bytes being awaited, from [`Response::next_body_chunk`].
#[must_use = "a body pull does nothing unless polled"]
pub struct ResponseBodyChunk<'r> {
    response: &'r mut Response,
}

impl<'r> Future for ResponseBodyChunk<'r> {
    type Output = Result<&'r [u8]>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let response = &*self.get_mut().response;
        if thread::current().id() != response.owner {
            return Poll::Ready(Err(fail(Status::InvalidArgument, "a streamed response pulls on its client's thread")));
        }
        let mut data = view(&[]);
        let mut outcome = ucall_outcome_t::default();
        let mut arguments = ucall_client_response_body_chunk_t {
            client: response.client,
            outcome: &mut outcome,
            response: response.raw,
            data: &mut data,
        };
        unsafe { ucall_client_response_body_chunk(&mut arguments) };
        match check(outcome) {
            Err(error) if error.status == Status::WouldBlock => {}
            // The bytes live in the response this future borrows for `'r`, until its next pull.
            pulled => return Poll::Ready(pulled.map(|()| unsafe { viewed(data) })),
        }
        if !response.bound {
            let (mut count, mut advanced) = (0, ucall_outcome_t::default());
            let mut advance = ucall_client_take_completed_t {
                client: response.client,
                outcome: ptr::addr_of_mut!(advanced),
                calls: ptr::null_mut(),
                capacity: 0,
                count: &mut count,
                timeout_microseconds: 0,
            };
            unsafe { ucall_client_take_completed(&mut advance) };
            if let Err(error) = check(advanced) {
                return Poll::Ready(Err(error));
            }
        }
        context.waker().wake_by_ref();
        Poll::Pending
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        unsafe { ucall_client_response_free(self.raw) }
    }
}

// region: Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::{Request, Server};
    use crate::testing::{block_on, client, loopback, pattern, serving};

    #[test]
    fn streamed_bodies_download_past_the_response_cap() {
        let body = pattern(4 << 20);
        let large = |request: Request| {
            let _ = request.reply(HTTPStatus::OK, &[], &body);
        };
        let empty = |request: Request| {
            let _ = request.reply(HTTPStatus::NO_CONTENT, &[], &[]);
        };
        let mut server = Server::new(&[loopback(1)]).unwrap();
        server.get("/large", &large).unwrap();
        server.get("/empty", &empty).unwrap();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            let mut client =
                Client::new(ClientOptions { connections: 1, max_response_bytes: 1 << 20, ..Default::default() })
                    .unwrap();
            let mut streamed = ClientCall::get(format!("http://{address}/large"));
            streamed.options.body_delivery = BodyDelivery::Streamed;
            let overflow = client.get(format!("http://{address}/large")).err().map(|error| error.status);
            assert_eq!(overflow, Some(Status::Overflow));

            let mut response = client.call(streamed.clone()).unwrap();
            assert_eq!(response.status_code(), HTTPStatus::OK);
            assert_eq!(response.body().unwrap_err().status, Status::InvalidArgument);
            let mut pulled = Vec::new();
            loop {
                let chunk = response.body_chunk().unwrap();
                if chunk.is_empty() {
                    break;
                }
                pulled.extend_from_slice(chunk);
            }
            assert!(pulled == body);

            let mut response = client.call(streamed.clone()).unwrap();
            pulled.clear();
            loop {
                let chunk = block_on(response.next_body_chunk()).unwrap();
                if chunk.is_empty() {
                    break;
                }
                pulled.extend_from_slice(chunk);
            }
            assert!(pulled == body);

            // A bodiless response is pulled too, its first pull answering the end at once.
            streamed.url = format!("http://{address}/empty").into();
            let mut empty = client.call(streamed.clone()).unwrap();
            assert_eq!(empty.status_code(), HTTPStatus::NO_CONTENT);
            assert_eq!(empty.body_chunk().unwrap(), b"");
            let mut buffered = client.get(format!("http://{address}/empty")).unwrap();
            assert_eq!(buffered.body_chunk().unwrap_err().status, Status::InvalidArgument);
            let mut moved = client.call(streamed).unwrap();
            let elsewhere = std::thread::spawn(move || moved.body_chunk().map(<[u8]>::len).unwrap_err().status);
            assert_eq!(elsewhere.join().unwrap(), Status::InvalidArgument);
        });
    }

    fn echo(request: Request) {
        // The reply consumes the request, so the bytes it sends cannot borrow from it.
        let body = request.body().to_vec();
        let _ = request.reply(HTTPStatus::OK, &[], &body);
    }

    fn echo_server() -> Server<'static> {
        let mut server = Server::new(&[loopback(1).pipelined_requests(2)]).unwrap();
        server.post("/echo", &echo).unwrap();
        server
    }

    #[test]
    fn responses_outlive_their_client() {
        let server = echo_server();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            let mut client = client(1);
            let body: Vec<u8> = (0..=255).collect();
            let response = client.post(format!("http://{address}/echo"), body.clone()).unwrap();
            drop(client);
            assert_eq!(response.status_code(), HTTPStatus::OK);
            assert_eq!(response.body().unwrap(), body.as_slice());
        });
    }

    #[test]
    fn blocking_calls_keep_other_completions_for_the_next_take() {
        let server = echo_server();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            let mut client = Client::new(ClientOptions { connections: 1, calls: 2, ..Default::default() }).unwrap();
            client.submit(ClientCall::post(format!("http://{address}/echo"), b"first".as_slice()), 7).unwrap();
            let blocking = client.post(format!("http://{address}/echo"), b"second".as_slice()).unwrap();
            assert_eq!(blocking.body().unwrap(), b"second");
            let mut completed: [Completed; 2] = Default::default();
            let kept = client.take_completed(&mut completed, Duration::ZERO).unwrap();
            assert_eq!(kept.len(), 1);
            assert_eq!(kept[0].context, 7);
            assert_eq!(kept[0].response.as_ref().unwrap().body().unwrap(), b"first");
        });
    }

    #[test]
    fn full_clients_refuse_until_completions_are_retrieved() {
        let mut client = Client::new(ClientOptions {
            connections: 1,
            calls: 1,
            connect_timeout: Duration::from_secs(1),
            ..Default::default()
        })
        .unwrap();
        // Nothing listens on port 1, so the admitted call fails once it is driven.
        client.submit(ClientCall::get("http://127.0.0.1:1/"), 1).unwrap();
        let refused = client.submit(ClientCall::get("http://127.0.0.1:1/"), 2).unwrap_err();
        assert_eq!(refused.status, Status::Contended);
        let mut completed: [Completed; 1] = Default::default();
        while client.take_completed(&mut completed, Duration::from_secs(1)).unwrap().is_empty() {}
        assert_eq!(completed[0].context, 1);
        assert!(completed[0].response.is_err());
        client.submit(ClientCall::get("http://127.0.0.1:1/"), 3).unwrap();
    }
}

// endregion: Tests
