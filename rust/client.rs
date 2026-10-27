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
use core::ptr;
use core::time::Duration;
use std::borrow::Cow;
use std::collections::VecDeque;
use std::sync::Arc;

use crate::types::{
    check, fail, lend_authorizer, microseconds, pending_outcome, silent_log, ucall_bytes_view_t,
    ucall_client_t, ucall_cpu_class_t, ucall_http_status_t, ucall_io_backend_t, ucall_log_t,
    ucall_noise_key_t, ucall_outcome_t, ucall_peer_authorizer_t, ucall_received_http_response_t,
    ucall_security_mode_t, ucall_verb_t, view, viewed, Backend, CPUClass, HTTPStatus, NoiseKey,
    PeerAuthorizer, Result, Security, Status, Verb,
};

// region: Raw Declarations

#[repr(C)]
#[derive(Clone, Copy)]
struct ucall_client_config_t {
    max_concurrent_connections: usize,
    max_pipelined_calls: usize,
    connect_timeout_microseconds: usize,
    request_timeout_microseconds: usize,
    noise_private_key: *const ucall_noise_key_t,
    peer_authorizer: ucall_peer_authorizer_t,
    peer_authorizer_context: *mut c_void,
    log: ucall_log_t,
    max_concurrent_calls: usize,
    backend: ucall_io_backend_t,
    cpu_class: ucall_cpu_class_t,
}

#[repr(C)]
struct ucall_client_init_t {
    client: *mut ucall_client_t,
    outcome: *mut ucall_outcome_t,
    config: *const ucall_client_config_t,
    resolved: *mut ucall_client_config_t,
}

#[repr(C)]
struct ucall_request_options_t {
    timeout_microseconds: usize,
    max_retries: usize,
    max_redirects: usize,
    security: ucall_security_mode_t,
    client_key: *const ucall_noise_key_t,
    server_key: *const ucall_noise_key_t,
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
    options: ucall_request_options_t,
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
struct ucall_client_response_header_t {
    response: ucall_received_http_response_t,
    outcome: *mut ucall_outcome_t,
    name: ucall_bytes_view_t,
    value: *mut ucall_bytes_view_t,
}

#[repr(C)]
struct ucall_client_response_body_t {
    response: ucall_received_http_response_t,
    outcome: *mut ucall_outcome_t,
    body: *mut ucall_bytes_view_t,
}

extern "C" {
    fn ucall_client_init(arguments: *mut ucall_client_init_t);
    fn ucall_client_free(client: ucall_client_t);
    fn ucall_client_call(arguments: *mut ucall_client_call_t);
    fn ucall_client_take_completed(arguments: *mut ucall_client_take_completed_t);
    fn ucall_client_response_status(
        response: ucall_received_http_response_t,
    ) -> ucall_http_status_t;
    fn ucall_client_response_header(arguments: *mut ucall_client_response_header_t);
    fn ucall_client_response_body(arguments: *mut ucall_client_response_body_t);
    fn ucall_client_response_free(response: ucall_received_http_response_t);
}

// endregion: Raw Declarations

/// What a client may hold open at once, how long it waits, and who it is under Noise.
///
/// `connections` is required; every other zero field takes its documented default.
#[derive(Default)]
pub struct ClientOptions {
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
    pub request_timeout: Duration,
    /// The client identity for Noise handshakes.
    pub private_key: Option<NoiseKey>,
    /// Vets each server's authenticated static key; required for Noise XX calls.
    pub peer_authorizer: Option<Arc<PeerAuthorizer>>,
    /// The requested I/O backend.
    pub backend: Backend,
    /// The requested CPU class.
    pub cpu_class: CPUClass,
}

/// One HTTP call, owning everything the library reads until the call completes.
#[derive(Clone, Debug)]
pub struct CallRequest {
    /// The HTTP method.
    pub verb: Verb,
    /// The full URL, `http://` or `http+noise://`.
    pub url: Cow<'static, str>,
    /// Full header lines like "accept: text/plain"; Host, Content-Length and User-Agent are
    /// generated.
    pub headers: Vec<Cow<'static, [u8]>>,
    /// The request body; empty sends no payload.
    pub body: Cow<'static, [u8]>,
    /// The transport security; an `http+noise://` URL implies Noise XX.
    pub security: Security,
    /// The server's static key, which Noise IK and KK need in advance.
    pub server_key: Option<NoiseKey>,
}

impl CallRequest {
    /// A GET of `url` with no headers.
    pub fn get(url: impl Into<Cow<'static, str>>) -> Self {
        CallRequest {
            verb: Verb::Get,
            url: url.into(),
            headers: Vec::new(),
            body: Cow::Borrowed(&[]),
            security: Security::None,
            server_key: None,
        }
    }

    /// A POST of `body` to `url` with no headers.
    pub fn post(url: impl Into<Cow<'static, str>>, body: impl Into<Cow<'static, [u8]>>) -> Self {
        CallRequest {
            verb: Verb::Post,
            body: body.into(),
            ..CallRequest::get(url)
        }
    }
}

/// The library's client handle and the authorizer it calls back into.
struct ClientCore {
    raw: ucall_client_t,
    // The callback context must outlive the handle, which `Drop` frees before its fields.
    authorizer: Option<Arc<PeerAuthorizer>>,
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
    request: Option<CallRequest>,
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
/// # let mut server = Server::new(&[Interface::new("127.0.0.1:0")])?;
/// # server.post("/echo", |request: Request| {
/// #     let body = request.body().to_vec();
/// #     let _ = request.reply(HTTPStatus::OK, &[], &body);
/// # })?;
/// # let address = server.address(0).unwrap().to_owned();
/// # std::thread::scope(|scope| {
/// # scope.spawn(|| server.take_calls(0));
/// # let calls = || -> Result<()> {
///
/// let mut client = Client::new(ClientOptions { connections: 2, pipelined_calls: 4, ..Default::default() })?;
/// for index in 0..8u64 {
///     client.submit(CallRequest::post(format!("http://{address}/echo"), vec![index as u8]), index)?;
/// }
/// let mut completed: [Completed; 8] = Default::default();
/// let mut answered = 0;
/// while answered < 8 {
///     for done in client.take_completed(&mut completed, Duration::from_secs(1))? {
///         assert_eq!(done.response.as_ref().map(Response::body), Ok([done.context as u8].as_slice()));
///         answered += 1;
///     }
/// }
///
/// let response = client.post(format!("http://{address}/echo"), b"blocking".as_slice())?;
/// drop(client);
/// assert_eq!(response.body(), b"blocking");
/// # Ok(())
/// # };
/// # let result = calls();
/// # server.stop();
/// # result
/// # })?;
/// # Ok::<(), ucall::Error>(())
/// ```
pub struct Client {
    // Completions the blocking calls retrieved for other calls, handed out by the next
    // `take_completed`; at most one per admitted call, so the queue never outgrows its capacity.
    kept: VecDeque<Completed>,
    // Dropped before `calls`: the library never reads call inputs once nobody polls it. Boxed, as
    // the library keeps the address of its authorizer.
    core: Box<ClientCore>,
    calls: Vec<Call>,
    free: Vec<usize>,
    retrieved: Vec<ucall_completed_call_t>,
    request_timeout: Duration,
}

impl Client {
    /// Starts a client; it holds no connection until the first call is polled.
    pub fn new(options: ClientOptions) -> Result<Client> {
        let mut core = Box::new(ClientCore {
            raw: ptr::null_mut(),
            authorizer: options.peer_authorizer,
        });
        let (peer_authorizer, peer_authorizer_context) = lend_authorizer(&core.authorizer);
        let config = ucall_client_config_t {
            max_concurrent_connections: options.connections,
            max_pipelined_calls: options.pipelined_calls,
            connect_timeout_microseconds: microseconds(options.connect_timeout),
            request_timeout_microseconds: microseconds(options.request_timeout),
            noise_private_key: options
                .private_key
                .as_ref()
                .map_or(ptr::null(), ptr::from_ref),
            peer_authorizer,
            peer_authorizer_context,
            log: silent_log(),
            max_concurrent_calls: options.calls,
            backend: options.backend.to_raw(),
            cpu_class: options.cpu_class.to_raw(),
        };
        let mut resolved = config;
        let mut outcome = pending_outcome();
        let mut arguments = ucall_client_init_t {
            client: &mut core.raw,
            outcome: &mut outcome,
            config: &config,
            resolved: &mut resolved,
        };
        unsafe { ucall_client_init(&mut arguments) };
        check(outcome)?;

        let capacity = resolved.max_concurrent_calls;
        let empty = ucall_completed_call_t {
            context: ptr::null_mut(),
            outcome: pending_outcome(),
            response: ptr::null_mut(),
        };
        Ok(Client {
            kept: VecDeque::with_capacity(capacity),
            core,
            calls: (0..capacity).map(|_| Call::default()).collect(),
            free: (0..capacity).rev().collect(),
            retrieved: vec![empty; capacity],
            request_timeout: Duration::from_micros(resolved.request_timeout_microseconds as u64),
        })
    }

    /// Admits a call into a free slot, answering the slot it took.
    fn admit(&mut self, request: CallRequest, context: u64) -> Result<usize> {
        let index = self.free.pop().ok_or(fail(
            Status::Contended,
            "every call slot holds an unretrieved call",
        ))?;
        let call = &mut self.calls[index];
        call.context = context;
        let request = call.request.insert(request);
        call.headers.clear();
        call.headers
            .extend(request.headers.iter().map(|line| view(line)));
        let mut outcome = pending_outcome();
        let mut arguments = ucall_client_call_t {
            client: self.core.raw,
            outcome: &mut outcome,
            url: view(request.url.as_bytes()),
            verb: request.verb.to_raw(),
            headers: call.headers.as_ptr(),
            headers_count: call.headers.len(),
            body: view(&request.body),
            options: ucall_request_options_t {
                timeout_microseconds: 0,
                max_retries: 0,
                max_redirects: 0,
                security: request.security.to_raw(),
                client_key: ptr::null(),
                server_key: request
                    .server_key
                    .as_ref()
                    .map_or(ptr::null(), ptr::from_ref),
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
    pub fn submit(&mut self, request: CallRequest, context: u64) -> Result<()> {
        self.admit(request, context).map(|_| ())
    }

    /// Drives the library and retrieves up to `capacity` raw completions into `retrieved`.
    fn retrieve(&mut self, capacity: usize, timeout: Duration) -> Result<usize> {
        let mut count = 0;
        let mut outcome = pending_outcome();
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
            Ok(()) if !raw.response.is_null() => Ok(Response { raw: raw.response }),
            Ok(()) => Err(fail(
                Status::Internal,
                "a successful call completed without a response",
            )),
            Err(error) => {
                unsafe { ucall_client_response_free(raw.response) };
                Err(error)
            }
        };
        Completed {
            context: call.context,
            response,
        }
    }

    /// Drives every admitted call on this thread and fills the front of `completed` with finished
    /// ones, waiting up to `timeout` for the first; zero performs one nonblocking round.
    ///
    /// Answers the filled prefix, empty when nothing finished in time. Completions kept by
    /// [`Client::call`], [`Client::get`] or [`Client::post`] come first, without waiting.
    pub fn take_completed<'completed>(
        &mut self,
        completed: &'completed mut [Completed],
        timeout: Duration,
    ) -> Result<&'completed mut [Completed]> {
        let count = match self.kept.is_empty() {
            false => {
                let count = completed.len().min(self.kept.len());
                for (entry, kept) in completed.iter_mut().zip(self.kept.drain(..count)) {
                    *entry = kept;
                }
                count
            }
            true => {
                let count = self.retrieve(completed.len(), timeout)?;
                for (position, entry) in completed[..count].iter_mut().enumerate() {
                    *entry = self.complete(self.retrieved[position]);
                }
                count
            }
        };
        Ok(&mut completed[..count])
    }

    /// Submits `request` and polls until it finishes, keeping other calls' completions for the
    /// next [`Client::take_completed`].
    ///
    /// The response arrives whatever its HTTP status; a failed exchange answers its [`Error`].
    ///
    /// [`Error`]: crate::Error
    pub fn call(&mut self, request: CallRequest) -> Result<Response> {
        let index = self.admit(request, 0)?;
        loop {
            let count = self.retrieve(self.retrieved.len(), self.request_timeout)?;
            let mut answer = None;
            for position in 0..count {
                let raw = self.retrieved[position];
                let completed = self.complete(raw);
                match raw.context as usize == index {
                    true => answer = Some(completed.response),
                    false => self.kept.push_back(completed),
                }
            }
            if let Some(response) = answer {
                return response;
            }
        }
    }

    /// Fetches `url` and polls until the response arrives.
    pub fn get(&mut self, url: impl Into<Cow<'static, str>>) -> Result<Response> {
        self.call(CallRequest::get(url))
    }

    /// Posts `body` to `url` and polls until the response arrives.
    pub fn post(
        &mut self,
        url: impl Into<Cow<'static, str>>,
        body: impl Into<Cow<'static, [u8]>>,
    ) -> Result<Response> {
        self.call(CallRequest::post(url, body))
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
        Completed {
            context: 0,
            response: Err(fail(
                Status::WouldBlock,
                "no call completed into this entry",
            )),
        }
    }
}

/// A received HTTP response, freed on drop.
///
/// It owns its received bytes, so it stays readable after its [`Client`] is dropped and may move
/// to another thread.
///
/// ```
/// use ucall::*;
/// # let mut server = Server::new(&[Interface::new("127.0.0.1:0")])?;
/// # server.get("/missing", |request: Request| {
/// #     let _ = request.reply(HTTPStatus::NOT_FOUND, &["x-reason: gone".into()], b"no such page");
/// # })?;
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
///     assert_eq!(response.body(), b"no such page");
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
}

// The library reads a response without its client, and one thread at a time uses it.
unsafe impl Send for Response {}

impl Response {
    /// The status code the server sent.
    pub fn status_code(&self) -> HTTPStatus {
        HTTPStatus(unsafe { ucall_client_response_status(self.raw) })
    }

    /// The response body, decoded from chunked framing if it arrived that way.
    pub fn body(&self) -> &[u8] {
        let mut body = view(&[]);
        let mut outcome = pending_outcome();
        let mut arguments = ucall_client_response_body_t {
            response: self.raw,
            outcome: &mut outcome,
            body: &mut body,
        };
        unsafe { ucall_client_response_body(&mut arguments) };
        unsafe { viewed(body) }
    }

    /// The value of header `name`, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        let mut value = view(&[]);
        let mut outcome = pending_outcome();
        let mut arguments = ucall_client_response_header_t {
            response: self.raw,
            outcome: &mut outcome,
            name: view(name.as_bytes()),
            value: &mut value,
        };
        unsafe { ucall_client_response_header(&mut arguments) };
        check(outcome).ok().map(|()| unsafe { viewed(value) })
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
    use crate::testing::{client, loopback, serving};

    fn echo_server() -> Server {
        let mut server = Server::new(&[loopback(1).pipelined_requests(2)]).unwrap();
        server
            .post("/echo", |request: Request| {
                // The reply consumes the request, so the bytes it sends cannot borrow from it.
                let body = request.body().to_vec();
                let _ = request.reply(HTTPStatus::OK, &[], &body);
            })
            .unwrap();
        server
    }

    #[test]
    fn responses_outlive_their_client() {
        let server = echo_server();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            let mut client = client(1);
            let body: Vec<u8> = (0..=255).collect();
            let response = client
                .post(format!("http://{address}/echo"), body.clone())
                .unwrap();
            drop(client);
            assert_eq!(response.status_code(), HTTPStatus::OK);
            assert_eq!(response.body(), body.as_slice());
        });
    }

    #[test]
    fn blocking_calls_keep_other_completions_for_the_next_take() {
        let server = echo_server();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            let mut client = Client::new(ClientOptions {
                connections: 1,
                calls: 2,
                ..Default::default()
            })
            .unwrap();
            client
                .submit(
                    CallRequest::post(format!("http://{address}/echo"), b"first".as_slice()),
                    7,
                )
                .unwrap();
            let blocking = client
                .post(format!("http://{address}/echo"), b"second".as_slice())
                .unwrap();
            assert_eq!(blocking.body(), b"second");
            let mut completed: [Completed; 2] = Default::default();
            let kept = client
                .take_completed(&mut completed, Duration::ZERO)
                .unwrap();
            assert_eq!(kept.len(), 1);
            assert_eq!(kept[0].context, 7);
            assert_eq!(kept[0].response.as_ref().unwrap().body(), b"first");
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
        client
            .submit(CallRequest::get("http://127.0.0.1:1/"), 1)
            .unwrap();
        let refused = client
            .submit(CallRequest::get("http://127.0.0.1:1/"), 2)
            .unwrap_err();
        assert_eq!(refused.status, Status::Contended);
        let mut completed: [Completed; 1] = Default::default();
        while client
            .take_completed(&mut completed, Duration::from_secs(1))
            .unwrap()
            .is_empty()
        {}
        assert_eq!(completed[0].context, 1);
        assert!(completed[0].response.is_err());
        client
            .submit(CallRequest::get("http://127.0.0.1:1/"), 3)
            .unwrap();
    }
}

// endregion: Tests
