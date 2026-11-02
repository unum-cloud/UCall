//! Servers: the interfaces they answer on, the endpoints they route to, the requests those
//! endpoints receive, and the polling verbs application threads drive them with.
//!
//! UCall starts no threads. Each event loop is driven by one application thread at a time
//! through [`Server::take_call`] or [`Server::take_calls`], and each batch endpoint by one thread
//! at a time through [`BatchEndpoint::take_batch`] or [`BatchEndpoint::take_batches`]. Plain
//! handlers run on the polling thread, batch handlers on the draining thread, and either may hand
//! its [`Request`] to any other thread to reply.
//!
//! File: rust/server.rs
//! Author: Ash Vardanian
//! Date: October 25, 2026

// The C mirror keeps the C spelling of every name.
#![allow(non_camel_case_types, non_upper_case_globals)]

use core::ffi::{c_int, c_void};
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ops::Deref;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use crate::types::{
    check, fail, lend_authorizer, lend_log, microseconds, pending_outcome, ucall_body_delivery_t,
    ucall_bytes_view_t, ucall_cpu_class_t, ucall_http_batch_endpoint_t, ucall_http_status_t,
    ucall_io_backend_t, ucall_log_t, ucall_noise_key_t, ucall_outcome_status, ucall_outcome_t,
    ucall_outcome_wait, ucall_peer_authorizer_t, ucall_received_http_request_t,
    ucall_security_mode_t, ucall_server_t, ucall_status_already_exists_k,
    ucall_status_connection_closed_k, ucall_status_deferred_k, ucall_status_invalid_argument_k,
    ucall_status_out_of_memory_k, ucall_status_success_k, ucall_status_uninitialized_k,
    ucall_verb_t, view, viewed, Backend, BodyDelivery, BytesView, CPUClass, Deferred, Descriptor,
    HTTPStatus, Log, NoiseKey, PeerAuthorizer, Result, Security, Status, Verb,
};

// region: Raw Declarations

#[repr(C)]
#[derive(Clone, Copy)]
struct ucall_network_interface_t {
    address: ucall_bytes_view_t,
    device_name: ucall_bytes_view_t,
    security_mode: ucall_security_mode_t,
    noise_private_key: *const ucall_noise_key_t,
    noise_peer_key: *const ucall_noise_key_t,
    peer_authorizer: ucall_peer_authorizer_t,
    peer_authorizer_context: *mut c_void,
    event_loops: usize,
    max_concurrent_connections: usize,
    max_pipelined_requests: usize,
    max_request_bytes: usize,
    reply_directories: *const ucall_bytes_view_t,
    reply_directories_count: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ucall_server_config_t {
    interfaces: *const ucall_network_interface_t,
    interfaces_count: usize,
    log: ucall_log_t,
    metrics_address: ucall_bytes_view_t,
    metrics_sample_rate: f32,
    metrics_prefix: ucall_bytes_view_t,
    metrics_tags: *const ucall_bytes_view_t,
    metrics_tags_count: usize,
    metrics_interval_microseconds: usize,
    backend: ucall_io_backend_t,
    cpu_class: ucall_cpu_class_t,
}

#[repr(C)]
struct ucall_server_init_t {
    server: *mut ucall_server_t,
    outcome: *mut ucall_outcome_t,
    config: *const ucall_server_config_t,
    resolved: *mut ucall_server_config_t,
}

#[repr(C)]
struct ucall_server_take_call_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    event_loop_index: usize,
    timeout_microseconds: usize,
}

#[repr(C)]
struct ucall_server_take_calls_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    event_loop_index: usize,
}

type ucall_event_loop_statistics_t = EventLoopStatistics;

#[repr(C)]
struct ucall_server_event_loop_statistics_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    event_loop_index: usize,
    statistics: *mut ucall_event_loop_statistics_t,
}

#[repr(C)]
struct ucall_server_take_batch_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    endpoint: ucall_http_batch_endpoint_t,
    timeout_microseconds: usize,
}

#[repr(C)]
struct ucall_server_take_batches_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    endpoint: ucall_http_batch_endpoint_t,
}

type ucall_batch_endpoint_statistics_t = BatchEndpointStatistics;

#[repr(C)]
struct ucall_server_batch_endpoint_statistics_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    endpoint: ucall_http_batch_endpoint_t,
    statistics: *mut ucall_batch_endpoint_statistics_t,
}

type ucall_received_http_request_callback_t =
    Option<unsafe extern "C" fn(request: ucall_received_http_request_t, context: *mut c_void)>;

type ucall_received_http_batch_callback_t = Option<
    unsafe extern "C" fn(
        requests: *const ucall_received_http_request_t,
        count: usize,
        context: *mut c_void,
    ),
>;

#[repr(C)]
struct ucall_server_add_http_endpoint_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    uri_template: ucall_bytes_view_t,
    verb: ucall_verb_t,
    callback: ucall_received_http_request_callback_t,
    context: *mut c_void,
    body_delivery: ucall_body_delivery_t,
}

#[repr(C)]
struct ucall_server_add_http_batch_endpoint_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    uri_template: ucall_bytes_view_t,
    verb: ucall_verb_t,
    callback: ucall_received_http_batch_callback_t,
    context: *mut c_void,
    min_batch_size: usize,
    max_batch_size: usize,
    max_latency_microseconds: usize,
    endpoint: *mut ucall_http_batch_endpoint_t,
}

#[repr(C)]
struct ucall_server_request_path_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    request: ucall_received_http_request_t,
    path: *mut ucall_bytes_view_t,
}

#[repr(C)]
struct ucall_server_request_path_parameter_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    request: ucall_received_http_request_t,
    name: ucall_bytes_view_t,
    value: *mut ucall_bytes_view_t,
}

// The header declares the three name lookups with one layout.
type ucall_server_request_query_parameter_t = ucall_server_request_path_parameter_t;
type ucall_server_request_header_t = ucall_server_request_path_parameter_t;

#[repr(C)]
struct ucall_server_request_peer_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    request: ucall_received_http_request_t,
    network_interface_index: *mut usize,
    static_key: *mut ucall_noise_key_t,
}

#[repr(C)]
struct ucall_server_request_body_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    request: ucall_received_http_request_t,
    body: *mut ucall_bytes_view_t,
}

#[repr(C)]
struct ucall_server_reply_content_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    request: ucall_received_http_request_t,
    headers: *const ucall_bytes_view_t,
    headers_count: usize,
    body: ucall_bytes_view_t,
    http_status: ucall_http_status_t,
}

#[repr(C)]
struct ucall_server_reply_error_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    request: ucall_received_http_request_t,
    http_status: ucall_http_status_t,
    message: ucall_bytes_view_t,
}

#[repr(C)]
struct ucall_server_request_path_segment_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    request: ucall_received_http_request_t,
    index: usize,
    segment: *mut ucall_bytes_view_t,
}

#[repr(C)]
struct ucall_server_request_body_chunk_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    request: ucall_received_http_request_t,
    data: *mut ucall_bytes_view_t,
}

#[repr(C)]
struct ucall_server_request_part_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    request: ucall_received_http_request_t,
    index: usize,
    name: *mut ucall_bytes_view_t,
    content_type: *mut ucall_bytes_view_t,
    data: *mut ucall_bytes_view_t,
}

type ucall_reply_part_kind_t = c_int;

const ucall_reply_part_bytes_k: ucall_reply_part_kind_t = 0;
const ucall_reply_part_file_k: ucall_reply_part_kind_t = 1;
const ucall_reply_part_path_k: ucall_reply_part_kind_t = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct ucall_file_range_t {
    file_descriptor: c_int,
    offset: u64,
    length: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ucall_path_range_t {
    directory_index: usize,
    relative_path: ucall_bytes_view_t,
    offset: u64,
    length: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
union ucall_reply_part_data_t {
    bytes: ucall_bytes_view_t,
    file: ucall_file_range_t,
    path: ucall_path_range_t,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ucall_reply_part_t {
    kind: ucall_reply_part_kind_t,
    data: ucall_reply_part_data_t,
}

#[repr(C)]
struct ucall_server_reply_vectored_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    request: ucall_received_http_request_t,
    http_status: ucall_http_status_t,
    headers: *const ucall_bytes_view_t,
    headers_count: usize,
    parts: *const ucall_reply_part_t,
    parts_count: usize,
}

#[repr(C)]
struct ucall_server_reply_begin_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    request: ucall_received_http_request_t,
    http_status: ucall_http_status_t,
    headers: *const ucall_bytes_view_t,
    headers_count: usize,
}

#[repr(C)]
struct ucall_server_reply_append_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    request: ucall_received_http_request_t,
    parts: *const ucall_reply_part_t,
    parts_count: usize,
}

#[repr(C)]
struct ucall_server_reply_end_t {
    server: ucall_server_t,
    outcome: *mut ucall_outcome_t,
    request: ucall_received_http_request_t,
}

extern "C" {
    fn ucall_server_init(arguments: *mut ucall_server_init_t);
    fn ucall_server_free(server: ucall_server_t);
    fn ucall_server_stop(server: ucall_server_t);
    fn ucall_server_take_call(arguments: *mut ucall_server_take_call_t);
    fn ucall_server_take_calls(arguments: *mut ucall_server_take_calls_t);
    fn ucall_server_event_loop_statistics(arguments: *mut ucall_server_event_loop_statistics_t);
    fn ucall_server_take_batch(arguments: *mut ucall_server_take_batch_t);
    fn ucall_server_take_batches(arguments: *mut ucall_server_take_batches_t);
    fn ucall_server_batch_endpoint_statistics(
        arguments: *mut ucall_server_batch_endpoint_statistics_t,
    );
    fn ucall_server_add_http_endpoint(arguments: *mut ucall_server_add_http_endpoint_t);
    fn ucall_server_add_http_batch_endpoint(arguments: *mut ucall_server_add_http_batch_endpoint_t);
    fn ucall_server_request_verb(
        server: ucall_server_t,
        request: ucall_received_http_request_t,
    ) -> ucall_verb_t;
    fn ucall_server_request_path(arguments: *mut ucall_server_request_path_t);
    fn ucall_server_request_path_segments_count(
        server: ucall_server_t,
        request: ucall_received_http_request_t,
    ) -> usize;
    fn ucall_server_request_path_segment(arguments: *mut ucall_server_request_path_segment_t);
    fn ucall_server_request_path_parameter(arguments: *mut ucall_server_request_path_parameter_t);
    fn ucall_server_request_query_parameter(arguments: *mut ucall_server_request_query_parameter_t);
    fn ucall_server_request_header(arguments: *mut ucall_server_request_header_t);
    fn ucall_server_request_peer(arguments: *mut ucall_server_request_peer_t);
    fn ucall_server_request_body(arguments: *mut ucall_server_request_body_t);
    fn ucall_server_request_body_chunk(arguments: *mut ucall_server_request_body_chunk_t);
    fn ucall_server_request_parts_count(
        server: ucall_server_t,
        request: ucall_received_http_request_t,
    ) -> usize;
    fn ucall_server_request_part(arguments: *mut ucall_server_request_part_t);
    fn ucall_server_reply_content(arguments: *mut ucall_server_reply_content_t);
    fn ucall_server_reply_error(arguments: *mut ucall_server_reply_error_t);
    fn ucall_server_reply_vectored(arguments: *mut ucall_server_reply_vectored_t);
    fn ucall_server_reply_begin(arguments: *mut ucall_server_reply_begin_t);
    fn ucall_server_reply_append(arguments: *mut ucall_server_reply_append_t);
    fn ucall_server_reply_end(arguments: *mut ucall_server_reply_end_t);
}

// endregion: Raw Declarations

/// One address a server answers on, with the security and admission limits of the connections
/// arriving there.
///
/// One server may answer plaintext on loopback and Noise on the wire at once, through two
/// interfaces:
///
/// ```
/// use ucall::*;
///
/// let (private_key, _) = generate_noise_keypair()?;
/// let plain = Interface::new("127.0.0.1:0");
/// let sealed = Interface::new("127.0.0.1:0")
///     .security(Security::NoiseXX, private_key)
///     .peer_authorizer(|client_key: &NoiseKey| client_key != &[0; 32]);
/// let server = Server::new(&[plain, sealed])?;
/// assert!(server.address(1).is_some());
/// # Ok::<(), ucall::Error>(())
/// ```
#[derive(Clone)]
pub struct Interface {
    address: String,
    device_name: Option<String>,
    security: Security,
    private_key: Option<NoiseKey>,
    noise_peer_key: Option<NoiseKey>,
    peer_authorizer: Option<Arc<PeerAuthorizer>>,
    event_loops: usize,
    connections: usize,
    pipelined_requests: usize,
    max_request_bytes: usize,
    reply_directories: Vec<String>,
}

impl Interface {
    /// An interface listening on `address` in "host:port" form, admitting 1024 connections at
    /// once; port zero picks a free one, which [`Server::address`] reports.
    pub fn new(address: impl Into<String>) -> Self {
        Interface {
            address: address.into(),
            device_name: None,
            security: Security::None,
            private_key: None,
            noise_peer_key: None,
            peer_authorizer: None,
            event_loops: 0,
            connections: 1024,
            pipelined_requests: 0,
            max_request_bytes: 0,
            reply_directories: Vec::new(),
        }
    }

    /// Pins the interface to a physical device, like "eth0"; only Linux supports it.
    pub fn device_name(mut self, name: impl Into<String>) -> Self {
        self.device_name = Some(name.into());
        self
    }

    /// Requires a Noise handshake under this server identity; `NoiseXX` also needs an authorizer,
    /// and `NoiseKK` the initiator's key.
    pub fn security(mut self, security: Security, private_key: NoiseKey) -> Self {
        self.security = security;
        self.private_key = Some(private_key);
        self
    }

    /// The one initiator's static public key a `NoiseKK` interface admits, known in advance.
    pub fn noise_peer_key(mut self, public_key: NoiseKey) -> Self {
        self.noise_peer_key = Some(public_key);
        self
    }

    /// Vets each client's authenticated static key before any of its requests is read.
    pub fn peer_authorizer(
        mut self,
        authorizer: impl Fn(&NoiseKey) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.peer_authorizer = Some(Arc::new(authorizer));
        self
    }

    /// Event loops accepting on this interface; zero means one, or the receive-queue count of a
    /// named Linux device.
    pub fn event_loops(mut self, count: usize) -> Self {
        self.event_loops = count;
        self
    }

    /// Connections open at once across this interface's loops; further ones wait in the listen
    /// queue until one closes.
    pub fn connections(mut self, count: usize) -> Self {
        self.connections = count;
        self
    }

    /// Requests one connection may have in flight before the server stops reading from it; zero
    /// means one, and replies still leave in request order.
    pub fn pipelined_requests(mut self, count: usize) -> Self {
        self.pipelined_requests = count;
        self
    }

    /// The largest request head and buffered body; past it the reply is 413 and the connection
    /// closes. Zero takes the largest receive buffer the kernel grants a socket, and streamed
    /// bodies are bounded by the handler's pulls instead.
    pub fn max_request_bytes(mut self, bytes: usize) -> Self {
        self.max_request_bytes = bytes;
        self
    }

    /// Directories the [`ReplyPart::Path`] parts of replies to this interface's requests resolve
    /// beneath, by position; each is opened when the server starts, failing it if one cannot be.
    pub fn reply_directories(
        mut self,
        directories: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.reply_directories = directories.into_iter().map(Into::into).collect();
        self
    }
}

/// What a server runs on and reports through, beside its interfaces.
#[derive(Clone, Default)]
pub struct ServerOptions {
    /// The requested I/O backend, failing rather than substituting when it is unavailable.
    pub backend: Backend,
    /// A ceiling on the CPU class, failing where the CPU does not run it; `None` takes what the
    /// constructing thread's CPU offers.
    pub cpu_class: Option<CPUClass>,
    /// Where log lines go; `None` keeps the server silent.
    pub log: Option<Log>,
    /// Where StatsD datagrams go; `None` sends none.
    pub metrics: Option<Metrics>,
}

/// The StatsD endpoint a server sends each event loop's counters and sampled request latencies
/// to, as UDP datagrams.
#[derive(Clone, Debug, Default)]
pub struct Metrics {
    /// The endpoint in "host:port" form.
    pub address: String,
    /// The fraction of finished requests whose latency is reported, in (0, 1]; zero means 1.
    pub sample_rate: f32,
    /// The metric name prefix; empty means "ucall".
    pub prefix: String,
    /// Tags on every metric, each "key:value".
    pub tags: Vec<String>,
    /// The time between one event loop's datagrams; zero means one second.
    pub interval: Duration,
}

/// The library's server handle and what its configuration points at, shared by the [`Server`],
/// its routes and batch endpoints, and every retained [`Request`], so the last of them frees it.
struct ServerCore {
    raw: ucall_server_t,
    resolved: ucall_server_config_t,
    // Interface and log callback contexts must outlive the handle, which `Drop` frees before its
    // fields.
    _authorizers: Vec<Option<Arc<PeerAuthorizer>>>,
    _log: Option<Box<Log>>,
}

// The handle's stop, statistics, request, and reply entry points are thread-safe; polling ones
// are serialized by the claims of the types that call them.
unsafe impl Send for ServerCore {}
unsafe impl Sync for ServerCore {}

impl ServerCore {
    /// The interfaces as the library resolved them, every default filled in.
    fn interfaces(&self) -> &[ucall_network_interface_t] {
        unsafe {
            core::slice::from_raw_parts(self.resolved.interfaces, self.resolved.interfaces_count)
        }
    }
}

impl Drop for ServerCore {
    fn drop(&mut self) {
        unsafe { ucall_server_free(self.raw) }
    }
}

/// One thread's exclusive turn at polling an event loop or draining a batch endpoint, released
/// when the polling call returns.
struct Claim<'owner>(&'owner AtomicBool);

impl<'owner> Claim<'owner> {
    /// Takes the turn `flag` guards, refusing with [`Status::Contended`] while another thread
    /// holds it.
    fn take(flag: &'owner AtomicBool, refusal: &'static str) -> Result<Self> {
        match flag.swap(true, Ordering::Acquire) {
            true => Err(fail(Status::Contended, refusal)),
            false => Ok(Claim(flag)),
        }
    }
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// A plain endpoint's handler and the server its requests retain.
struct Route {
    server: Arc<ServerCore>,
    handler: Box<dyn Fn(Request) + Send + Sync>,
}

/// # Safety
/// `context` must address a live [`Route`], and `request` be a retained handle of its server.
unsafe extern "C" fn route_trampoline(
    request: ucall_received_http_request_t,
    context: *mut c_void,
) {
    let route = &*context.cast::<Route>();
    let request = Request {
        server: Arc::clone(&route.server),
        raw: request,
    };
    // Unwinding drops the request, which answers 500.
    let _ = catch_unwind(AssertUnwindSafe(|| (route.handler)(request)));
}

/// An HTTP server over one or more interfaces, polled by application threads.
///
/// Register every endpoint first, through `&mut self`, then share `&Server` with the threads
/// that poll its event loops. Dropping it stops the server; the library frees it once the last
/// [`BatchEndpoint`] and retained [`Request`] are dropped too.
///
/// ```
/// use ucall::*;
///
/// let mut server = Server::new(&[Interface::new("127.0.0.1:0")])?;
/// server.get("/hello", |request: Request| {
///     let _ = request.reply(HTTPStatus::OK, &["content-type: text/plain".into()], b"Hello!");
/// })?;
/// let address = server.address(0).unwrap().to_owned();
///
/// let mut client = Client::new(ClientOptions { connections: 1, ..Default::default() })?;
/// std::thread::scope(|scope| {
///     for event_loop in 0..server.event_loops() {
///         let server = &server;
///         scope.spawn(move || server.take_calls(event_loop));
///     }
///     let response = client.get(format!("http://{address}/hello"));
///     server.stop();
///     assert_eq!(response?.body(), b"Hello!");
///     Ok::<(), Error>(())
/// })?;
/// assert_eq!(server.event_loop_statistics(0)?.requests, 1);
/// # Ok::<(), ucall::Error>(())
/// ```
pub struct Server {
    core: Arc<ServerCore>,
    polled: Box<[AtomicBool]>,
    routes: Vec<*mut Route>,
}

// Handlers are `Send + Sync`, and each event loop's single polling owner is claimed atomically.
unsafe impl Send for Server {}
unsafe impl Sync for Server {}

impl Server {
    /// Starts a server answering on `interfaces`, with the automatic backend and CPU class.
    pub fn new(interfaces: &[Interface]) -> Result<Server> {
        Server::with_options(interfaces, ServerOptions::default())
    }

    /// Starts a server answering on `interfaces` with the backend, CPU class, log sink and StatsD
    /// endpoint `options` name.
    pub fn with_options(interfaces: &[Interface], options: ServerOptions) -> Result<Server> {
        // The contexts point into this vector and box, which the core keeps until the free.
        let authorizers: Vec<Option<Arc<PeerAuthorizer>>> = interfaces
            .iter()
            .map(|interface| interface.peer_authorizer.clone())
            .collect();
        let log = options.log.map(Box::new);
        // The library copies the directories, keys and metric names during initialization.
        let directories: Vec<Vec<ucall_bytes_view_t>> = interfaces
            .iter()
            .map(|interface| {
                let directories = &interface.reply_directories;
                directories
                    .iter()
                    .map(|path| view(path.as_bytes()))
                    .collect()
            })
            .collect();
        let raw_interfaces: Vec<ucall_network_interface_t> = interfaces
            .iter()
            .zip(&authorizers)
            .zip(&directories)
            .map(|((interface, authorizer), directories)| {
                let (peer_authorizer, peer_authorizer_context) = lend_authorizer(authorizer);
                ucall_network_interface_t {
                    address: view(interface.address.as_bytes()),
                    device_name: view(interface.device_name.as_deref().unwrap_or("").as_bytes()),
                    security_mode: interface.security.to_raw(),
                    noise_private_key: interface
                        .private_key
                        .as_ref()
                        .map_or(ptr::null(), ptr::from_ref),
                    noise_peer_key: interface
                        .noise_peer_key
                        .as_ref()
                        .map_or(ptr::null(), ptr::from_ref),
                    peer_authorizer,
                    peer_authorizer_context,
                    event_loops: interface.event_loops,
                    max_concurrent_connections: interface.connections,
                    max_pipelined_requests: interface.pipelined_requests,
                    max_request_bytes: interface.max_request_bytes,
                    reply_directories: directories.as_ptr(),
                    reply_directories_count: directories.len(),
                }
            })
            .collect();

        let metrics = options.metrics.unwrap_or_default();
        let tags: Vec<ucall_bytes_view_t> = metrics
            .tags
            .iter()
            .map(|tag| view(tag.as_bytes()))
            .collect();
        let config = ucall_server_config_t {
            interfaces: raw_interfaces.as_ptr(),
            interfaces_count: raw_interfaces.len(),
            log: lend_log(&log),
            metrics_address: view(metrics.address.as_bytes()),
            metrics_sample_rate: metrics.sample_rate,
            metrics_prefix: view(metrics.prefix.as_bytes()),
            metrics_tags: tags.as_ptr(),
            metrics_tags_count: tags.len(),
            metrics_interval_microseconds: microseconds(metrics.interval),
            backend: options.backend.to_raw(),
            cpu_class: CPUClass::to_raw(options.cpu_class),
        };
        let mut raw: ucall_server_t = ptr::null_mut();
        let mut resolved = config;
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_init_t {
            server: &mut raw,
            outcome: &mut outcome,
            config: &config,
            resolved: &mut resolved,
        };
        unsafe { ucall_server_init(&mut arguments) };
        let core = ServerCore {
            raw,
            resolved,
            _authorizers: authorizers,
            _log: log,
        };
        check(outcome)?;

        let event_loops = core
            .interfaces()
            .iter()
            .map(|interface| interface.event_loops)
            .max()
            .unwrap_or(0);
        Ok(Server {
            core: Arc::new(core),
            polled: (0..event_loops).map(|_| AtomicBool::new(false)).collect(),
            routes: Vec::new(),
        })
    }

    /// Event loops this server runs, each to be polled by one thread at a time.
    pub fn event_loops(&self) -> usize {
        self.polled.len()
    }

    /// The I/O backend the server resolved to.
    pub fn backend(&self) -> Backend {
        Backend::from_raw(self.core.resolved.backend)
    }

    /// The CPU class the server resolved to.
    pub fn cpu_class(&self) -> CPUClass {
        CPUClass::from_raw(self.core.resolved.cpu_class).unwrap_or(CPUClass::Serial)
    }

    /// The numeric address interface `index` listens on, with the port it bound.
    pub fn address(&self, index: usize) -> Option<&str> {
        let address = self.core.interfaces().get(index)?.address;
        // The server owns the resolved copy until it is freed.
        Some(unsafe { core::str::from_utf8_unchecked(viewed(address)) })
    }

    /// Routes requests matching `path` and `verb` to `handler`, which runs on the polling thread.
    ///
    /// Templates capture `{name}` segments and a greedy `{*name}` tail, read back through
    /// [`Request::path_parameter`]; literal segments match before captures, and captures before a
    /// tail. A handler that panics, or drops its request unreplied, answers 500. Registering the
    /// same template and verb twice fails with [`Status::AlreadyExists`].
    pub fn route(
        &mut self,
        path: &str,
        verb: Verb,
        handler: impl Fn(Request) + Send + Sync + 'static,
    ) -> Result<()> {
        self.route_with(path, verb, BodyDelivery::Buffered, handler)
    }

    /// Routes like [`Server::route`], running `handler` once the body is buffered, or with
    /// [`BodyDelivery::Streamed`] as soon as the headers arrived, the body still to be pulled
    /// through [`DetachedRequest::body_chunk`].
    pub fn route_with(
        &mut self,
        path: &str,
        verb: Verb,
        delivery: BodyDelivery,
        handler: impl Fn(Request) + Send + Sync + 'static,
    ) -> Result<()> {
        let route = Box::into_raw(Box::new(Route {
            server: Arc::clone(&self.core),
            handler: Box::new(handler),
        }));
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_add_http_endpoint_t {
            server: self.core.raw,
            outcome: &mut outcome,
            uri_template: view(path.as_bytes()),
            verb: verb.to_raw(),
            callback: Some(route_trampoline),
            context: route.cast(),
            body_delivery: delivery.to_raw(),
        };
        unsafe { ucall_server_add_http_endpoint(&mut arguments) };
        let registered = check(outcome);
        match registered {
            Ok(()) => self.routes.push(route),
            Err(_) => drop(unsafe { Box::from_raw(route) }),
        }
        registered
    }

    /// Routes GET requests on `path` to `handler`.
    pub fn get(
        &mut self,
        path: &str,
        handler: impl Fn(Request) + Send + Sync + 'static,
    ) -> Result<()> {
        self.route(path, Verb::Get, handler)
    }

    /// Routes POST requests on `path` to `handler`.
    pub fn post(
        &mut self,
        path: &str,
        handler: impl Fn(Request) + Send + Sync + 'static,
    ) -> Result<()> {
        self.route(path, Verb::Post, handler)
    }

    /// Routes PUT requests on `path` to `handler`.
    pub fn put(
        &mut self,
        path: &str,
        handler: impl Fn(Request) + Send + Sync + 'static,
    ) -> Result<()> {
        self.route(path, Verb::Put, handler)
    }

    /// Routes DELETE requests on `path` to `handler`.
    pub fn delete(
        &mut self,
        path: &str,
        handler: impl Fn(Request) + Send + Sync + 'static,
    ) -> Result<()> {
        self.route(path, Verb::Delete, handler)
    }

    /// Routes PATCH requests on `path` to `handler`.
    pub fn patch(
        &mut self,
        path: &str,
        handler: impl Fn(Request) + Send + Sync + 'static,
    ) -> Result<()> {
        self.route(path, Verb::Patch, handler)
    }

    /// Collects requests matching `path` and `verb` from every event loop into one queue, which
    /// the returned endpoint drains into `handler` on whichever thread drains it.
    ///
    /// Requests the handler neither replies to nor keeps answer 500 once it returns, as do all of
    /// them when it panics.
    pub fn batch(
        &mut self,
        path: &str,
        verb: Verb,
        batching: Batching,
        handler: impl Fn(Batch<'_>) + Send + Sync + 'static,
    ) -> Result<BatchEndpoint> {
        let state = Box::into_raw(Box::new(BatchState {
            server: Arc::clone(&self.core),
            handler: Box::new(handler),
            requests: Vec::new(),
        }));
        let mut raw: ucall_http_batch_endpoint_t = ptr::null_mut();
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_add_http_batch_endpoint_t {
            server: self.core.raw,
            outcome: &mut outcome,
            uri_template: view(path.as_bytes()),
            verb: verb.to_raw(),
            callback: Some(batch_trampoline),
            context: state.cast(),
            min_batch_size: batching.min_size,
            max_batch_size: batching.max_size,
            max_latency_microseconds: microseconds(batching.max_latency),
            endpoint: &mut raw,
        };
        unsafe { ucall_server_add_http_batch_endpoint(&mut arguments) };
        let endpoint = BatchEndpoint {
            server: self.core.raw,
            raw,
            state,
            drained: AtomicBool::new(false),
        };
        check(outcome)?;
        Ok(endpoint)
    }

    /// Claims event loop `index` for the calling thread until the returned guard drops.
    fn claim(&self, index: usize) -> Result<Claim<'_>> {
        let polled = self.polled.get(index).ok_or(fail(
            Status::InvalidArgument,
            "the server has no event loop with that index",
        ))?;
        Claim::take(polled, "another thread is polling this event loop")
    }

    /// Advances one event loop, running the handlers of the requests it completes on this thread,
    /// and waits up to `timeout` for progress; zero performs one nonblocking round.
    ///
    /// Fails with [`Status::Contended`] while another thread polls the same loop.
    pub fn take_call(&self, event_loop: usize, timeout: Duration) -> Result<()> {
        let _claim = self.claim(event_loop)?;
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_take_call_t {
            server: self.core.raw,
            outcome: &mut outcome,
            event_loop_index: event_loop,
            timeout_microseconds: microseconds(timeout),
        };
        unsafe { ucall_server_take_call(&mut arguments) };
        check(outcome)
    }

    /// Drives one event loop on this thread until [`Server::stop`] or an I/O failure.
    ///
    /// Fails with [`Status::Contended`] while another thread polls the same loop.
    pub fn take_calls(&self, event_loop: usize) -> Result<()> {
        let _claim = self.claim(event_loop)?;
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_take_calls_t {
            server: self.core.raw,
            outcome: &mut outcome,
            event_loop_index: event_loop,
        };
        unsafe { ucall_server_take_calls(&mut arguments) };
        check(outcome)
    }

    /// Requests shutdown and wakes every polling and draining thread; callable from any thread,
    /// including from inside a handler.
    pub fn stop(&self) {
        unsafe { ucall_server_stop(self.core.raw) }
    }

    /// A snapshot of one event loop's counters, readable from any thread while it is polled.
    ///
    /// Fails with [`Status::InvalidArgument`] for an index past the last loop.
    pub fn event_loop_statistics(&self, event_loop: usize) -> Result<EventLoopStatistics> {
        let mut statistics = EventLoopStatistics::default();
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_event_loop_statistics_t {
            server: self.core.raw,
            outcome: &mut outcome,
            event_loop_index: event_loop,
            statistics: &mut statistics,
        };
        unsafe { ucall_server_event_loop_statistics(&mut arguments) };
        check(outcome).map(|()| statistics)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop();
        // A stopped server dispatches no request, and only `&self` polls it, so no handler can run.
        for route in self.routes.drain(..) {
            drop(unsafe { Box::from_raw(route) });
        }
    }
}

/// Counters of one event loop since the server started; divided by `requests`, they price one
/// call.
///
/// Each counter is read on its own, so a snapshot of a running loop is not one instant. Byte
/// counters cover the bytes UCall itself moves, never the kernel's own copies.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct EventLoopStatistics {
    /// Engine polls the loop issued, each taking zero or more completions.
    pub polls: u64,
    /// Engine polls that took no completion.
    pub empty_polls: u64,
    /// System calls: io_uring enters, or other backends' waits, registrations and socket calls.
    pub kernel_enters: u64,
    /// Operations queued: io_uring submission entries, or requests another backend accepted.
    pub submissions: u64,
    /// Results taken: io_uring completion entries, or operations another backend finished.
    pub completions: u64,
    /// Pending operations, or io_uring multishot receives, the engine asked to cancel.
    pub cancellations: u64,
    /// Connections accepted and handed to this loop.
    pub accepts: u64,
    /// HTTP requests parsed and dispatched to an endpoint or an error reply.
    pub requests: u64,
    /// Multishot receives armed again on a socket that already streamed, only on io_uring 7.0.
    pub receive_rearms: u64,
    /// Bytes the kernel reported received on this loop's connections, ciphertext under Noise.
    pub bytes_received: u64,
    /// Bytes the kernel reported sent from this loop's connections, ciphertext under Noise.
    pub bytes_sent: u64,
    /// Bytes UCall copied: receive appends, reply bodies, Noise records and parked receives.
    pub bytes_copied: u64,
    /// Sends that left without copying: reply segments and file windows.
    pub zero_copy_sends: u64,
    /// Zero-copy sends the kernel copied anyway or refused to pin, as loopback always does.
    pub zero_copy_fallbacks: u64,
    /// Sends that copied instead of pinning: the socket was demoted, refused zero-copy, or had no
    /// room to track one.
    pub copying_sends: u64,
    /// File reads handed to the kernel to finish later: io_uring, Linux or FreeBSD AIO, or
    /// overlapped reads.
    pub file_reads_asynchronous: u64,
    /// File reads the loop issued itself and blocked on, as the posix backend and macOS do.
    pub file_reads_blocking: u64,
    /// Bytes the kernel reported read from files into the loop's file windows.
    pub bytes_read: u64,
    /// File reads submitted while an earlier window of the same stream waited to send or sent.
    pub file_window_overlaps: u64,
    /// Lingering closes reset at their deadline because the kernel still held what they sent.
    pub linger_resets: u64,
    /// Passes the loop made over a ready connection, each advancing it as far as it goes.
    pub ready_passes: u64,
    /// Replied exchanges the loop took from its queue to adopt their reply segments.
    pub replied_dequeues: u64,
    /// Requests the loop answered itself with 400, 404, 413, 501 or 503.
    pub refused_requests: u64,
    /// Connections whose Noise handshake failed.
    pub handshake_failures: u64,
    /// Connections whose authenticated peer key the interface's authorizer refused.
    pub authorizer_refusals: u64,
}

/// When a batch endpoint hands its queue to the handler; zero fields take the defaults of 1
/// request, 32 requests, and 10 milliseconds.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Batching {
    /// Dispatch as soon as this many requests wait.
    pub min_size: usize,
    /// Never hand the handler more than this many requests at once.
    pub max_size: usize,
    /// Dispatch a smaller batch once its oldest request waited this long.
    pub max_latency: Duration,
}

/// Counters of one batch endpoint since registration: how large its batches were, and why each
/// was dispatched.
///
/// Each counter is read on its own, so a snapshot of an endpoint being drained is not one
/// instant. Requests released by [`Server::stop`] count nowhere.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct BatchEndpointStatistics {
    /// Batches handed to the handler.
    pub batches: u64,
    /// Requests across those batches.
    pub requests: u64,
    /// Batches dispatched on reaching [`Batching::max_size`].
    pub filled_batches: u64,
    /// Batches dispatched on reaching [`Batching::min_size`], below the maximum.
    pub ready_batches: u64,
    /// Batches dispatched below [`Batching::min_size`] once [`Batching::max_latency`] passed.
    pub expired_batches: u64,
}

/// A batch endpoint's handler, the server its requests retain, and the slots it lends them in.
struct BatchState {
    server: Arc<ServerCore>,
    handler: Box<dyn Fn(Batch<'_>) + Send + Sync>,
    // Grows to the largest batch once, then lends every later batch without allocating.
    requests: Vec<Option<Request>>,
}

/// # Safety
/// `context` must address the [`BatchState`] of the endpoint being drained, which its draining
/// claim borrows exclusively, and `requests` a counted array of its server's retained handles.
unsafe extern "C" fn batch_trampoline(
    requests: *const ucall_received_http_request_t,
    count: usize,
    context: *mut c_void,
) {
    let state = &mut *context.cast::<BatchState>();
    let handles = core::slice::from_raw_parts(requests, count);
    let server = &state.server;
    state.requests.extend(handles.iter().map(|&raw| {
        Some(Request {
            server: Arc::clone(server),
            raw,
        })
    }));
    let handler = &state.handler;
    let requests = &mut state.requests;
    let _ = catch_unwind(AssertUnwindSafe(|| handler(Batch { requests })));
    // Whatever the handler left behind answers 500 as it drops.
    state.requests.clear();
}

/// One batch endpoint, drained by one thread at a time and observable from any.
///
/// Requests from every event loop share its queue, so one thread drains what all of them
/// received. Dropping it leaves its queued requests unanswered until the server is freed, and the
/// queue, once full, refuses new ones with 503.
///
/// ```
/// use std::time::Duration;
/// use ucall::*;
///
/// let mut server = Server::new(&[Interface::new("127.0.0.1:0")])?;
/// let batching = Batching { min_size: 2, max_size: 2, max_latency: Duration::from_secs(1) };
/// let scores = server.batch("/score", Verb::Post, batching, |batch: Batch| {
///     for request in batch {
///         let score = request.body().len().to_string();
///         let _ = request.reply(HTTPStatus::OK, &[], score.as_bytes());
///     }
/// })?;
/// let address = server.address(0).unwrap().to_owned();
///
/// let mut client = Client::new(ClientOptions { connections: 2, ..Default::default() })?;
/// client.submit(CallRequest::post(format!("http://{address}/score"), b"four".as_slice()), 0)?;
/// client.submit(CallRequest::post(format!("http://{address}/score"), b"seven..".as_slice()), 1)?;
/// std::thread::scope(|scope| {
///     scope.spawn(|| server.take_calls(0));
///     scope.spawn(|| scores.take_batches());
///     let mut completed: [Completed; 2] = Default::default();
///     let mut answered = 0;
///     while answered < 2 {
///         match client.take_completed(&mut completed, Duration::from_secs(1)) {
///             Ok(done) => answered += done.len(),
///             Err(_) => break,
///         }
///     }
///     server.stop();
/// });
/// let statistics = scores.statistics()?;
/// assert_eq!((statistics.batches, statistics.requests, statistics.filled_batches), (1, 2, 1));
/// # Ok::<(), ucall::Error>(())
/// ```
pub struct BatchEndpoint {
    // The state's reference keeps this server alive.
    server: ucall_server_t,
    raw: ucall_http_batch_endpoint_t,
    state: *mut BatchState,
    drained: AtomicBool,
}

// The handler is `Send + Sync`, and the draining claim keeps the state to one thread at a time.
unsafe impl Send for BatchEndpoint {}
unsafe impl Sync for BatchEndpoint {}

impl BatchEndpoint {
    /// Runs the handler on this thread if a batch is due, waiting up to `timeout` for one; zero
    /// performs one nonblocking round.
    ///
    /// Fails with [`Status::Contended`] while another thread drains the same endpoint.
    pub fn take_batch(&self, timeout: Duration) -> Result<()> {
        let _claim = Claim::take(
            &self.drained,
            "another thread is draining this batch endpoint",
        )?;
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_take_batch_t {
            server: self.server,
            outcome: &mut outcome,
            endpoint: self.raw,
            timeout_microseconds: microseconds(timeout),
        };
        unsafe { ucall_server_take_batch(&mut arguments) };
        check(outcome)
    }

    /// Runs the handler on this thread for every due batch until [`Server::stop`]; requests still
    /// queued then are released without a reply.
    ///
    /// Fails with [`Status::Contended`] while another thread drains the same endpoint.
    pub fn take_batches(&self) -> Result<()> {
        let _claim = Claim::take(
            &self.drained,
            "another thread is draining this batch endpoint",
        )?;
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_take_batches_t {
            server: self.server,
            outcome: &mut outcome,
            endpoint: self.raw,
        };
        unsafe { ucall_server_take_batches(&mut arguments) };
        check(outcome)
    }

    /// A snapshot of the endpoint's counters, readable from any thread while it is drained.
    pub fn statistics(&self) -> Result<BatchEndpointStatistics> {
        let mut statistics = BatchEndpointStatistics::default();
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_batch_endpoint_statistics_t {
            server: self.server,
            outcome: &mut outcome,
            endpoint: self.raw,
            statistics: &mut statistics,
        };
        unsafe { ucall_server_batch_endpoint_statistics(&mut arguments) };
        check(outcome).map(|()| statistics)
    }
}

impl Drop for BatchEndpoint {
    fn drop(&mut self) {
        // Only this endpoint's draining calls run its handler, and none can be in progress.
        drop(unsafe { Box::from_raw(self.state) });
    }
}

/// The requests of one due batch, from every event loop, lent to the handler in arrival order.
///
/// Each request is taken out at most once, by index or by iterating; whatever the handler leaves
/// answers 500 once it returns.
pub struct Batch<'batch> {
    requests: &'batch mut Vec<Option<Request>>,
}

impl<'batch> Batch<'batch> {
    /// Requests in the batch, taken or not.
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Whether the batch has no requests, which a dispatched batch never is.
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Borrows request `index`, unless it was taken.
    pub fn get(&self, index: usize) -> Option<&Request> {
        self.requests.get(index)?.as_ref()
    }

    /// Takes request `index` out of the batch, to reply to it here or on another thread.
    pub fn take(&mut self, index: usize) -> Option<Request> {
        self.requests.get_mut(index)?.take()
    }

    /// Borrows every request not yet taken, in order.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &Request> {
        self.requests.iter().flatten()
    }
}

impl<'batch> IntoIterator for Batch<'batch> {
    type Item = Request;
    type IntoIter = core::iter::Flatten<std::vec::Drain<'batch, Option<Request>>>;

    /// Takes every request not yet taken, in order or, reversed, from the newest.
    fn into_iter(self) -> Self::IntoIter {
        self.requests.drain(..).flatten()
    }
}

/// Which interface a request arrived on, and who sent it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Peer {
    /// The position of its interface in the slice the server was started with.
    pub network_interface_index: usize,
    /// The client's authenticated Noise static key, zeroed on plaintext interfaces.
    pub static_key: NoiseKey,
}

/// One received HTTP request, retained until a reply consumes it.
///
/// It owns its received bytes, so it may move to any thread and be replied to there after its
/// handler returned. Dropping it unreplied answers 500. Reads the library refuses, which happens
/// only on a thread whose CPU cannot run the server's class, read as empty.
///
/// ```
/// use std::sync::mpsc;
/// use ucall::*;
///
/// let (handed, received) = mpsc::channel::<Request>();
/// let mut server = Server::new(&[Interface::new("127.0.0.1:0")])?;
/// server.get("/users/{name}", move |request: Request| handed.send(request).unwrap())?;
/// let address = server.address(0).unwrap().to_owned();
///
/// let mut client = Client::new(ClientOptions { connections: 1, ..Default::default() })?;
/// std::thread::scope(|scope| {
///     scope.spawn(|| server.take_calls(0));
///     scope.spawn(move || {
///         let request = received.recv().unwrap();
///         let name = request.path_parameter("name").unwrap_or_default();
///         let greeting = [b"Hello, ", name].concat();
///         let _ = request.reply(HTTPStatus::OK, &[], &greeting);
///     });
///     let response = client.get(format!("http://{address}/users/ada?verbose=1"));
///     server.stop();
///     assert_eq!(response?.body(), b"Hello, ada");
///     Ok::<(), Error>(())
/// })?;
/// # Ok::<(), ucall::Error>(())
/// ```
pub struct Request {
    server: Arc<ServerCore>,
    raw: ucall_received_http_request_t,
}

// A retained request is used by one thread at a time, and replies may come from any of them.
unsafe impl Send for Request {}

impl Request {
    /// The HTTP method, which tells apart the requests of a [`Verb::Any`] endpoint.
    pub fn verb(&self) -> Verb {
        Verb::from_raw(unsafe { ucall_server_request_verb(self.server.raw, self.raw) })
    }

    /// The request path as sent, still percent-encoded, without the query.
    pub fn path(&self) -> &[u8] {
        let mut path = view(&[]);
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_request_path_t {
            server: self.server.raw,
            outcome: &mut outcome,
            request: self.raw,
            path: &mut path,
        };
        unsafe { ucall_server_request_path(&mut arguments) };
        unsafe { viewed(path) }
    }

    /// Looks a name up through one of the three lookups sharing an argument layout.
    fn named(
        &self,
        lookup: unsafe extern "C" fn(*mut ucall_server_request_path_parameter_t),
        name: &str,
    ) -> Option<&[u8]> {
        let mut value = view(&[]);
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_request_path_parameter_t {
            server: self.server.raw,
            outcome: &mut outcome,
            request: self.raw,
            name: view(name.as_bytes()),
            value: &mut value,
        };
        unsafe { lookup(&mut arguments) };
        check(outcome).ok().map(|()| unsafe { viewed(value) })
    }

    /// The value the endpoint's template captured under `name`, case-sensitive.
    pub fn path_parameter(&self, name: &str) -> Option<&[u8]> {
        self.named(ucall_server_request_path_parameter, name)
    }

    /// The value of query parameter `name`, case-sensitive and still percent-encoded.
    pub fn query(&self, name: &str) -> Option<&[u8]> {
        self.named(ucall_server_request_query_parameter, name)
    }

    /// The value of header `name`, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.named(ucall_server_request_header, name)
    }

    /// The request body, decoded from chunked framing if it arrived that way.
    pub fn body(&self) -> &[u8] {
        let mut body = view(&[]);
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_request_body_t {
            server: self.server.raw,
            outcome: &mut outcome,
            request: self.raw,
            body: &mut body,
        };
        unsafe { ucall_server_request_body(&mut arguments) };
        unsafe { viewed(body) }
    }

    /// The interface the request arrived on and the sender's authenticated static key, readable
    /// after its connection closed.
    pub fn peer(&self) -> Peer {
        let mut peer = Peer {
            network_interface_index: 0,
            static_key: [0; 32],
        };
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_request_peer_t {
            server: self.server.raw,
            outcome: &mut outcome,
            request: self.raw,
            network_interface_index: &mut peer.network_interface_index,
            static_key: &mut peer.static_key,
        };
        unsafe { ucall_server_request_peer(&mut arguments) };
        peer
    }

    /// Path components in order, as sent and still percent-encoded.
    pub fn path_segments_count(&self) -> usize {
        unsafe { ucall_server_request_path_segments_count(self.server.raw, self.raw) }
    }

    /// Path component `index`, counting from zero, or `None` past the last one.
    pub fn path_segment(&self, index: usize) -> Option<&[u8]> {
        let mut segment = view(&[]);
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_request_path_segment_t {
            server: self.server.raw,
            outcome: &mut outcome,
            request: self.raw,
            index,
            segment: &mut segment,
        };
        unsafe { ucall_server_request_path_segment(&mut arguments) };
        check(outcome).ok().map(|()| unsafe { viewed(segment) })
    }

    /// Parts in a `multipart/form-data` body, zero for any other body.
    pub fn parts_count(&self) -> usize {
        unsafe { ucall_server_request_parts_count(self.server.raw, self.raw) }
    }

    /// Part `index` of a `multipart/form-data` body, its payload undecoded.
    ///
    /// Fails with [`Status::InvalidArgument`] past the last part, and with [`Status::Malformed`]
    /// when the body is no well-formed multipart body.
    pub fn part(&self, index: usize) -> Result<RequestPart<'_>> {
        let (mut name, mut content_type, mut data) = (view(&[]), view(&[]), view(&[]));
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_request_part_t {
            server: self.server.raw,
            outcome: &mut outcome,
            request: self.raw,
            index,
            name: &mut name,
            content_type: &mut content_type,
            data: &mut data,
        };
        unsafe { ucall_server_request_part(&mut arguments) };
        check(outcome).map(|()| unsafe {
            RequestPart {
                name: viewed(name),
                content_type: viewed(content_type),
                data: viewed(data),
            }
        })
    }

    /// Hands the request to a thread that may wait, where it gains the replies that may finish
    /// later; the polling thread itself must never wait on them.
    pub fn detach(self) -> DetachedRequest {
        DetachedRequest(self)
    }

    /// Gives the handle up to the reply call that consumed it, without the 500 dropping it answers.
    fn release(self) {
        let consumed = ManuallyDrop::new(self);
        drop(unsafe { ptr::read(&consumed.server) });
    }

    /// Hands the handle to one reply call that is final on return: success and a closed
    /// connection consume it; any other failure leaves it retained, so dropping it answers 500.
    fn finish_final(
        self,
        reply: impl FnOnce(ucall_server_t, ucall_received_http_request_t, *mut ucall_outcome_t),
    ) -> Result<()> {
        let mut outcome = pending_outcome();
        reply(self.server.raw, self.raw, &mut outcome);
        match unsafe { ucall_outcome_status(&mut outcome) } {
            ucall_status_success_k | ucall_status_connection_closed_k => self.release(),
            _ => drop(self),
        }
        check(outcome)
    }

    /// Hands the handle to one reply call that may finish later, answering the outcome while it
    /// is deferred: the refusals that queued nothing leave it retained, so dropping it answers
    /// 500, and every other status consumes it.
    fn finish<'f>(
        self,
        reply: impl FnOnce(ucall_server_t, ucall_received_http_request_t, *mut ucall_outcome_t),
    ) -> Result<Option<Deferred<'f>>> {
        let deferred = Deferred::pending();
        reply(self.server.raw, self.raw, deferred.raw());
        let status = unsafe { ucall_outcome_status(deferred.raw()) };
        match status {
            ucall_status_uninitialized_k
            | ucall_status_invalid_argument_k
            | ucall_status_already_exists_k
            | ucall_status_out_of_memory_k => drop(self),
            _ => self.release(),
        }
        match status {
            ucall_status_deferred_k => Ok(Some(deferred)),
            _ => deferred.wait().map(|()| None),
        }
    }

    /// Replies with `status`, full header lines like "content-type: text/plain", and `body`.
    ///
    /// Content-Length, Date and Server are generated. A closed connection still consumes the
    /// request and reports [`Status::ConnectionClosed`]; any other failure keeps it, and dropping
    /// it then answers 500.
    pub fn reply(self, status: HTTPStatus, headers: &[BytesView<'_>], body: &[u8]) -> Result<()> {
        self.finish_final(|server, request, outcome| {
            let mut arguments = ucall_server_reply_content_t {
                server,
                outcome,
                request,
                headers: BytesView::raw_array(headers),
                headers_count: headers.len(),
                body: view(body),
                http_status: status.0,
            };
            unsafe { ucall_server_reply_content(&mut arguments) }
        })
    }

    /// Replies with an error `status`, 400 or above, and a plain-text `message`.
    pub fn reply_error(self, status: HTTPStatus, message: &str) -> Result<()> {
        self.finish_final(|server, request, outcome| {
            let mut arguments = ucall_server_reply_error_t {
                server,
                outcome,
                request,
                http_status: status.0,
                message: view(message.as_bytes()),
            };
            unsafe { ucall_server_reply_error(&mut arguments) }
        })
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_reply_error_t {
            server: self.server.raw,
            outcome: &mut outcome,
            request: self.raw,
            http_status: HTTPStatus::INTERNAL_ERROR.0,
            message: view(b"The request was dropped without a reply"),
        };
        unsafe { ucall_server_reply_error(&mut arguments) };
    }
}

/// One part of a `multipart/form-data` request body, borrowing the received bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RequestPart<'request> {
    /// The name its `Content-Disposition` gives.
    pub name: &'request [u8],
    /// Its `Content-Type`, empty when absent.
    pub content_type: &'request [u8],
    /// Its payload, undecoded.
    pub data: &'request [u8],
}

/// One part of a reply body, laid out as `ucall_reply_part_t`, so a slice of parts is the C array:
/// bytes and paths borrow for `'b`, copied before the call returns, and descriptors for `'f`,
/// read until the reply is final.
#[derive(Clone, Copy, Debug)]
#[repr(C, i32)]
pub enum ReplyPart<'b, 'f> {
    /// Bytes in memory, copied before the call returns.
    Bytes(BytesView<'b>) = ucall_reply_part_bytes_k,
    /// A range of a regular file opened with `O_DIRECT`, which the event loop reads unbuffered
    /// after the call returns, so it stays open until the reply is final.
    File(FileRange<'f>) = ucall_reply_part_file_k,
    /// A range of a file the event loop opens beneath one of the interface's
    /// [`Interface::reply_directories`], and closes once it is sent.
    Path(PathRange<'b>) = ucall_reply_part_path_k,
}

/// `ucall_file_range_t`: the caller's `O_DIRECT` descriptor, borrowed until the reply is final.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FileRange<'f> {
    /// The open file, borrowed and never closed by UCall.
    pub file: Descriptor<'f>,
    /// The range's first byte.
    pub offset: u64,
    /// The range's byte count; zero sends through the end of the file.
    pub length: u64,
}

/// `ucall_path_range_t`: a file beneath one of the interface's reply directories.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PathRange<'b> {
    /// The position of the directory among the interface's reply directories.
    pub directory: usize,
    /// The file beneath it, relative, copied before the call returns.
    pub path: BytesView<'b>,
    /// The range's first byte.
    pub offset: u64,
    /// The range's byte count; zero sends through the end of the file.
    pub length: u64,
}

const _: () = assert!(
    size_of::<ReplyPart>() == size_of::<ucall_reply_part_t>()
        && align_of::<ReplyPart>() == align_of::<ucall_reply_part_t>()
);

/// A request taken off its polling thread, and the only owner of the verbs that may finish
/// later: [`DetachedRequest::reply_parts`], [`DetachedRequest::reply_stream`] and
/// [`DetachedRequest::body_chunk`].
///
/// It reads like the [`Request`] it came from, moves to any thread, and answers 500 when dropped
/// unreplied. Its replies hand back a [`Deferred`] while a file or path part still sends, and
/// waiting on one belongs off the polling thread, as that thread is the one sending it.
///
/// ```
/// use std::sync::mpsc;
/// use ucall::*;
///
/// let (handed, received) = mpsc::channel::<DetachedRequest>();
/// let mut server = Server::new(&[Interface::new("127.0.0.1:0")])?;
/// server.get("/clip", move |request: Request| handed.send(request.detach()).unwrap())?;
/// let address = server.address(0).unwrap().to_owned();
///
/// let mut client = Client::new(ClientOptions { connections: 1, ..Default::default() })?;
/// std::thread::scope(|scope| {
///     scope.spawn(|| server.take_calls(0));
///     scope.spawn(move || {
///         let detached = received.recv().unwrap();
///         let parts = [ReplyPart::Bytes(b"frame".into())];
///         if let Ok(Some(deferred)) = detached.reply_parts(HTTPStatus::OK, &[], &parts) {
///             let _ = deferred.wait(); // or: deferred.await
///         }
///     });
///     let response = client.get(format!("http://{address}/clip"));
///     server.stop();
///     assert_eq!(response?.body(), b"frame");
///     Ok::<(), Error>(())
/// })?;
/// # Ok::<(), ucall::Error>(())
/// ```
pub struct DetachedRequest(Request);

impl Deref for DetachedRequest {
    type Target = Request;

    /// Reads the request through the verbs [`Request`] has.
    fn deref(&self) -> &Request {
        &self.0
    }
}

impl DetachedRequest {
    /// Replies with `status`, full header lines, and `body`, final on return, as
    /// [`Request::reply`] does.
    pub fn reply(self, status: HTTPStatus, headers: &[BytesView<'_>], body: &[u8]) -> Result<()> {
        self.0.reply(status, headers, body)
    }

    /// Replies with an error `status` and a plain-text `message`, final on return, as
    /// [`Request::reply_error`] does.
    pub fn reply_error(self, status: HTTPStatus, message: &str) -> Result<()> {
        self.0.reply_error(status, message)
    }

    /// Replies with `status`, full header lines, and `parts` concatenated into the body, its
    /// Content-Length measured; `None` once final, and a [`Deferred`] while a file or path part
    /// still sends.
    ///
    /// A part failing before the head left replaces the reply with 404 for a missing, unreadable
    /// or irregular file, 416 for a range past its end, or 500, and the [`Deferred`] reports the
    /// cause. A refusal on return keeps the request, and dropping it then answers 500.
    pub fn reply_parts<'f>(
        self,
        status: HTTPStatus,
        headers: &[BytesView<'_>],
        parts: &[ReplyPart<'_, 'f>],
    ) -> Result<Option<Deferred<'f>>> {
        self.0.finish(|server, request, outcome| {
            let mut arguments = ucall_server_reply_vectored_t {
                server,
                outcome,
                request,
                http_status: status.0,
                headers: BytesView::raw_array(headers),
                headers_count: headers.len(),
                parts: parts.as_ptr().cast(),
                parts_count: parts.len(),
            };
            unsafe { ucall_server_reply_vectored(&mut arguments) }
        })
    }

    /// Sends the status line and header lines, and opens a body appended part by part: chunked,
    /// or of the length a Content-Length header declares.
    ///
    /// A closed connection still consumes the request and reports [`Status::ConnectionClosed`];
    /// any other failure keeps it, and dropping it then answers 500.
    pub fn reply_stream<'f>(
        self,
        status: HTTPStatus,
        headers: &[BytesView<'_>],
    ) -> Result<ReplyStream<'f>> {
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_reply_begin_t {
            server: self.0.server.raw,
            outcome: &mut outcome,
            request: self.0.raw,
            http_status: status.0,
            headers: BytesView::raw_array(headers),
            headers_count: headers.len(),
        };
        unsafe { ucall_server_reply_begin(&mut arguments) };
        let begun = unsafe { ucall_outcome_status(&mut outcome) };
        if begun != ucall_status_success_k && begun != ucall_status_connection_closed_k {
            check(outcome)?;
        }
        let request = ManuallyDrop::new(self.0);
        // A closed connection still takes its end, which dropping the stream sends.
        let stream = ReplyStream {
            server: unsafe { ptr::read(&request.server) },
            raw: request.raw,
            files: PhantomData,
        };
        check(outcome).map(|()| stream)
    }

    /// Pulls the body bytes decoded since the last pull, waiting for them to arrive; empty once
    /// the body ended. On a [`BodyDelivery::Buffered`] endpoint the first pull is the whole body.
    ///
    /// On the polling thread, where nothing can arrive while it runs, a pull finding nothing
    /// fails with [`Status::WouldBlock`] instead. A body cut short fails with
    /// [`Status::ConnectionClosed`], and a malformed one with [`Status::Malformed`].
    pub fn body_chunk(&mut self) -> Result<&[u8]> {
        let mut data = view(&[]);
        let mut outcome = pending_outcome();
        // One pointer each, as the event loop writes them after the call returns.
        let (data_pointer, outcome_pointer) = (ptr::addr_of_mut!(data), ptr::addr_of_mut!(outcome));
        let mut arguments = ucall_server_request_body_chunk_t {
            server: self.0.server.raw,
            outcome: outcome_pointer,
            request: self.0.raw,
            data: data_pointer,
        };
        unsafe {
            ucall_server_request_body_chunk(&mut arguments);
            ucall_outcome_wait(outcome_pointer);
        }
        check(outcome).map(|()| unsafe { viewed(data) })
    }
}

/// A reply whose head left and whose body is appended part by part, from any one thread at a
/// time, until [`ReplyStream::end`]; dropping it ends it, waiting for its file parts to send.
///
/// The descriptors its file parts borrow stay open for `'f`, through the [`Deferred`] its end may
/// hand back.
pub struct ReplyStream<'f> {
    server: Arc<ServerCore>,
    raw: ucall_received_http_request_t,
    files: PhantomData<Descriptor<'f>>,
}

// The stream's handle is used by one thread at a time, and its replies may come from any of them.
unsafe impl Send for ReplyStream<'_> {}

impl<'f> ReplyStream<'f> {
    /// Queues `parts` on the body together, or none of them.
    ///
    /// Fails with [`Status::WouldBlock`], queueing nothing, while the peer lags behind the parts
    /// already queued; retry once it catches up.
    pub fn append(&mut self, parts: &[ReplyPart<'_, 'f>]) -> Result<()> {
        let mut outcome = pending_outcome();
        let mut arguments = ucall_server_reply_append_t {
            server: self.server.raw,
            outcome: &mut outcome,
            request: self.raw,
            parts: parts.as_ptr().cast(),
            parts_count: parts.len(),
        };
        unsafe { ucall_server_reply_append(&mut arguments) };
        check(outcome)
    }

    /// Ends the body, consuming the request whatever the outcome; `None` once final, and a
    /// [`Deferred`] while file or path parts still send.
    ///
    /// A body short of its declared Content-Length fails with [`Status::Malformed`] and closes
    /// the connection after the bytes already sent.
    pub fn end(self) -> Result<Option<Deferred<'f>>> {
        let stream = ManuallyDrop::new(self);
        let ended = stream.end_raw();
        drop(unsafe { ptr::read(&stream.server) });
        ended
    }

    fn end_raw(&self) -> Result<Option<Deferred<'f>>> {
        let deferred = Deferred::pending();
        let mut arguments = ucall_server_reply_end_t {
            server: self.server.raw,
            outcome: deferred.raw(),
            request: self.raw,
        };
        unsafe { ucall_server_reply_end(&mut arguments) };
        match unsafe { ucall_outcome_status(deferred.raw()) } {
            ucall_status_deferred_k => Ok(Some(deferred)),
            _ => deferred.wait().map(|()| None),
        }
    }
}

impl Drop for ReplyStream<'_> {
    fn drop(&mut self) {
        drop(self.end_raw());
    }
}

// region: Tests

#[cfg(test)]
mod tests {
    use core::future::{Future, IntoFuture};
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use std::borrow::Cow;
    use std::io::{Read, Write};
    use std::net::{TcpStream, UdpSocket};
    use std::os::fd::AsFd;
    use std::sync::Mutex;
    use std::time::Instant;

    use super::*;
    use crate::client::{CallRequest, Client, ClientOptions, Completed, RequestOptions};
    use crate::testing::{
        client, detaching, direct_directory, loopback, open_direct, pattern, serving, Stopping,
    };
    use crate::types::{derive_noise_public_key, generate_noise_keypair};

    #[test]
    fn get_reads_path_and_query_parameters() {
        let mut server = Server::new(&[loopback(1)]).unwrap();
        server
            .get("/sum/{unit}", |request: Request| {
                let number = |name| {
                    let text = std::str::from_utf8(request.query(name)?).ok()?;
                    text.parse::<u64>().ok()
                };
                let unit = request.path_parameter("unit").unwrap_or_default().to_vec();
                match (number("a"), number("b")) {
                    (Some(a), Some(b)) => {
                        let mut body = (a + b).to_string().into_bytes();
                        body.push(b' ');
                        body.extend_from_slice(&unit);
                        body.push(b' ');
                        body.extend_from_slice(request.path());
                        let _ = request.reply(
                            HTTPStatus::OK,
                            &["content-type: text/plain".into()],
                            &body,
                        );
                    }
                    _ => {
                        let _ =
                            request.reply_error(HTTPStatus::BAD_REQUEST, "a and b must be numbers");
                    }
                }
            })
            .unwrap();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            let mut client = client(1);
            let response = client
                .get(format!("http://{address}/sum/apples?a=2&b=40"))
                .unwrap();
            assert_eq!(response.status_code(), HTTPStatus::OK);
            assert_eq!(response.header("Content-Type"), Some(&b"text/plain"[..]));
            assert_eq!(response.body(), b"42 apples /sum/apples");
            let refused = client
                .get(format!("http://{address}/sum/apples?a=2"))
                .unwrap();
            assert_eq!(refused.status_code(), HTTPStatus::BAD_REQUEST);
        });
        assert_eq!(server.event_loop_statistics(0).unwrap().requests, 2);
        let past = server.event_loop_statistics(1).unwrap_err();
        assert_eq!(past.status, Status::InvalidArgument);
    }

    #[test]
    fn batches_reply_in_reverse_while_responses_stay_ordered() {
        let mut server = Server::new(&[loopback(1).pipelined_requests(4)]).unwrap();
        let sizes = Arc::new(Mutex::new(Vec::new()));
        let batching = Batching {
            min_size: 4,
            max_size: 4,
            max_latency: Duration::from_secs(5),
        };
        let observed = Arc::clone(&sizes);
        let endpoint = server
            .batch("/score", Verb::Put, batching, move |batch: Batch| {
                observed.lock().unwrap().push(batch.len());
                for request in batch.into_iter().rev() {
                    let body = request.body().to_vec();
                    let _ = request.reply(HTTPStatus::OK, &[], &body);
                }
            })
            .unwrap();
        let address = server.address(0).unwrap().to_owned();
        std::thread::scope(|scope| {
            let draining = scope.spawn(|| endpoint.take_batches());
            serving(&server, || {
                let mut client = Client::new(ClientOptions {
                    connections: 1,
                    pipelined_calls: 4,
                    calls: 4,
                    ..Default::default()
                })
                .unwrap();
                for context in 0..4u64 {
                    // PUT, because a POST never pipelines behind another one.
                    let call = CallRequest {
                        verb: Verb::Put,
                        ..CallRequest::post(
                            format!("http://{address}/score"),
                            vec![b'0' + context as u8],
                        )
                    };
                    client.submit(call, context).unwrap();
                }
                let mut completed: [Completed; 4] = Default::default();
                let mut order = Vec::new();
                while order.len() != 4 {
                    for done in client
                        .take_completed(&mut completed, Duration::from_secs(5))
                        .unwrap()
                    {
                        let response = done.response.as_ref().unwrap();
                        assert_eq!(response.body(), [b'0' + done.context as u8]);
                        order.push(done.context);
                    }
                }
                assert_eq!(order, [0, 1, 2, 3]);
                // The batch was answered, so the draining thread holds the endpoint.
                let contended = endpoint.take_batch(Duration::ZERO).unwrap_err();
                assert_eq!(contended.status, Status::Contended);
            });
            assert_eq!(draining.join().unwrap(), Ok(()));
        });
        assert_eq!(*sizes.lock().unwrap(), [4]);
        let statistics = endpoint.statistics().unwrap();
        let expected = BatchEndpointStatistics {
            batches: 1,
            requests: 4,
            filled_batches: 1,
            ready_batches: 0,
            expired_batches: 0,
        };
        assert_eq!(statistics, expected);
    }

    #[test]
    fn peers_report_their_interface_and_noise_key() {
        let (server_key, _) = generate_noise_keypair().unwrap();
        let (client_key, _) = generate_noise_keypair().unwrap();
        let client_public_key = derive_noise_public_key(&client_key);
        let authorized = Arc::new(Mutex::new(None));
        let recorded = Arc::clone(&authorized);
        let noise = loopback(1)
            .security(Security::NoiseXX, server_key)
            .peer_authorizer(move |key: &NoiseKey| {
                recorded.lock().unwrap().replace(*key).is_none()
            });
        let mut server = Server::new(&[loopback(1), noise]).unwrap();
        server
            .get("/peer", |request: Request| {
                let peer = request.peer();
                let mut body = peer.static_key.to_vec();
                body.push(peer.network_interface_index as u8);
                let _ = request.reply(HTTPStatus::OK, &[], &body);
            })
            .unwrap();
        let plain = server.address(0).unwrap().to_owned();
        let sealed = server.address(1).unwrap().to_owned();
        serving(&server, || {
            let mut client = Client::new(ClientOptions {
                connections: 2,
                private_key: Some(client_key),
                peer_authorizer: Some(Arc::new(|_: &NoiseKey| true)),
                ..Default::default()
            })
            .unwrap();
            let response = client.get(format!("http://{plain}/peer")).unwrap();
            assert_eq!(response.body(), [[0; 32].as_slice(), &[0]].concat());
            let response = client.get(format!("http+noise://{sealed}/peer")).unwrap();
            let key = authorized
                .lock()
                .unwrap()
                .expect("the authorizer saw the client's key");
            assert_eq!(key, client_public_key);
            assert_eq!(response.body(), [key.as_slice(), &[1]].concat());
        });
    }

    #[test]
    fn panics_and_dropped_requests_answer_500() {
        let mut server = Server::new(&[loopback(1)]).unwrap();
        server
            .get("/panic", |_: Request| panic!("the handler failed"))
            .unwrap();
        server.get("/drop", drop).unwrap();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            let mut client = client(1);
            let panicked = client.get(format!("http://{address}/panic")).unwrap();
            assert_eq!(panicked.status_code(), HTTPStatus::INTERNAL_ERROR);
            let dropped = client.get(format!("http://{address}/drop")).unwrap();
            assert_eq!(dropped.status_code(), HTTPStatus::INTERNAL_ERROR);
            assert_eq!(dropped.body(), b"The request was dropped without a reply");
        });
    }

    #[test]
    fn stop_ends_polling_from_another_thread() {
        let mut server = Server::new(&[loopback(1)]).unwrap();
        server
            .get("/ping", |request: Request| {
                let _ = request.reply(HTTPStatus::NO_CONTENT, &[], &[]);
            })
            .unwrap();
        let address = server.address(0).unwrap().to_owned();
        std::thread::scope(|scope| {
            let polling = scope.spawn(|| server.take_calls(0));
            let _stopping = Stopping(&server);
            // An answered call proves the loop is claimed by the polling thread.
            let pinged = client(1).get(format!("http://{address}/ping")).unwrap();
            assert_eq!(pinged.status_code(), HTTPStatus::NO_CONTENT);
            let contended = server.take_call(0, Duration::ZERO).unwrap_err();
            assert_eq!(contended.status, Status::Contended);
            scope.spawn(|| server.stop());
            assert_eq!(polling.join().unwrap(), Ok(()));
        });
    }

    #[test]
    fn reply_parts_concatenates_bytes_and_paths() {
        let directory = direct_directory("reply-parts");
        let clip = pattern(10_000);
        std::fs::write(directory.join("clip.bin"), &clip).unwrap();
        let interface = loopback(1).reply_directories([directory.to_str().unwrap()]);
        let mut server = Server::new(&[interface]).unwrap();
        let (handler, received) = detaching();
        server.get("/clip", handler).unwrap();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            std::thread::scope(|scope| {
                scope.spawn(move || {
                    let parts = [
                        ReplyPart::Bytes(b"<".into()),
                        ReplyPart::Path(PathRange {
                            directory: 0,
                            path: b"clip.bin".into(),
                            offset: 1000,
                            length: 5000,
                        }),
                        ReplyPart::Bytes(b">".into()),
                    ];
                    let detached = received.recv().unwrap();
                    let deferred = detached.reply_parts(HTTPStatus::OK, &[], &parts).unwrap();
                    deferred.expect("a path part defers").wait().unwrap();
                });
                let response = client(1).get(format!("http://{address}/clip")).unwrap();
                let expected = [b"<".as_slice(), &clip[1000..6000], b">"].concat();
                assert_eq!(response.body(), expected.as_slice());
            });
        });
    }

    #[test]
    fn path_part_defers_until_sent() {
        let directory = direct_directory("deferred-paths");
        let interface = loopback(1).reply_directories([directory.to_str().unwrap()]);
        let mut server = Server::new(&[interface]).unwrap();
        let (handler, received) = detaching();
        server.get("/{name}", handler).unwrap();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            std::thread::scope(|scope| {
                scope.spawn(move || {
                    let missing = ReplyPart::Path(PathRange {
                        directory: 0,
                        path: b"missing.bin".into(),
                        offset: 0,
                        length: 0,
                    });
                    let detached = received.recv().unwrap();
                    let deferred = detached
                        .reply_parts(HTTPStatus::OK, &[], &[missing])
                        .unwrap();
                    let mut awaited = pin!(deferred.expect("a path part defers").into_future());
                    let mut context = Context::from_waker(Waker::noop());
                    let ended = loop {
                        match awaited.as_mut().poll(&mut context) {
                            Poll::Ready(ended) => break ended,
                            Poll::Pending => std::thread::yield_now(),
                        }
                    };
                    assert_eq!(ended.unwrap_err().status, Status::NotFound);
                    let detached = received.recv().unwrap();
                    let parts = [ReplyPart::Bytes(b"final".into())];
                    let deferred = detached.reply_parts(HTTPStatus::OK, &[], &parts).unwrap();
                    assert!(deferred.is_none());
                });
                let mut client = client(1);
                let missing = client.get(format!("http://{address}/missing")).unwrap();
                assert_eq!(missing.status_code(), HTTPStatus::NOT_FOUND);
                let bytes = client.get(format!("http://{address}/bytes")).unwrap();
                assert_eq!(bytes.body(), b"final");
            });
        });
    }

    #[test]
    fn detached_request_replies_from_a_worker() {
        let mut server = Server::new(&[loopback(1)]).unwrap();
        let (handler, received) = detaching();
        server.get("/users/{name}", handler).unwrap();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            std::thread::scope(|scope| {
                scope.spawn(move || {
                    let detached = received.recv().unwrap();
                    let greeting = [b"Hello, ", detached.path_parameter("name").unwrap()].concat();
                    let parts = [ReplyPart::Bytes(greeting.as_slice().into())];
                    let deferred = detached.reply_parts(HTTPStatus::OK, &[], &parts).unwrap();
                    assert!(deferred.is_none());
                    drop(received.recv().unwrap());
                });
                let mut client = client(1);
                let replied = client.get(format!("http://{address}/users/ada")).unwrap();
                assert_eq!(replied.body(), b"Hello, ada");
                let dropped = client.get(format!("http://{address}/users/bob")).unwrap();
                assert_eq!(dropped.status_code(), HTTPStatus::INTERNAL_ERROR);
            });
        });
    }

    #[test]
    fn reply_stream_appends_then_ends() {
        let directory = direct_directory("reply-stream");
        let clip = pattern(8192);
        let path = directory.join("clip.bin");
        std::fs::write(&path, &clip).unwrap();
        let file = open_direct(&path);
        let mut server = Server::new(&[loopback(1)]).unwrap();
        let (handler, received) = detaching();
        server.get("/stream", handler).unwrap();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            std::thread::scope(|scope| {
                let file = &file;
                scope.spawn(move || {
                    let detached = received.recv().unwrap();
                    let mut stream = detached.reply_stream(HTTPStatus::OK, &[]).unwrap();
                    stream.append(&[ReplyPart::Bytes(b"<".into())]).unwrap();
                    let range = ReplyPart::File(FileRange {
                        file: file.as_fd(),
                        offset: 4096,
                        length: 4096,
                    });
                    stream
                        .append(&[range, ReplyPart::Bytes(b">".into())])
                        .unwrap();
                    if let Some(deferred) = stream.end().unwrap() {
                        deferred.wait().unwrap();
                    }
                });
                let response = client(1).get(format!("http://{address}/stream")).unwrap();
                let expected = [b"<".as_slice(), &clip[4096..], b">"].concat();
                assert_eq!(response.body(), expected.as_slice());
            });
        });
    }

    #[test]
    fn reply_parts_rejects_overflowing_range() {
        let directory = direct_directory("overflowing-range");
        let interface = loopback(1).reply_directories([directory.to_str().unwrap()]);
        let mut server = Server::new(&[interface]).unwrap();
        let (handler, received) = detaching();
        server.get("/clip", handler).unwrap();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            std::thread::scope(|scope| {
                scope.spawn(move || {
                    let overflowing = ReplyPart::Path(PathRange {
                        directory: 0,
                        path: b"clip.bin".into(),
                        offset: u64::MAX,
                        length: 1,
                    });
                    let detached = received.recv().unwrap();
                    let refused = detached.reply_parts(HTTPStatus::OK, &[], &[overflowing]);
                    assert_eq!(refused.unwrap_err().status, Status::InvalidArgument);
                });
                // The refusal kept the request, so dropping it answered rather than leaving the
                // peer waiting.
                let response = client(1).get(format!("http://{address}/clip")).unwrap();
                assert_eq!(response.status_code(), HTTPStatus::INTERNAL_ERROR);
            });
        });
    }

    #[test]
    fn stream_appends_per_iteration_strings() {
        let mut server = Server::new(&[loopback(1)]).unwrap();
        let (handler, received) = detaching();
        server.get("/rows", handler).unwrap();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            std::thread::scope(|scope| {
                scope.spawn(move || {
                    let detached = received.recv().unwrap();
                    let mut stream = detached.reply_stream(HTTPStatus::OK, &[]).unwrap();
                    for row in 0..3 {
                        let text = format!("row {row}\n");
                        stream
                            .append(&[ReplyPart::Bytes(text.as_bytes().into())])
                            .unwrap();
                    }
                    assert!(stream.end().unwrap().is_none());
                });
                let response = client(1).get(format!("http://{address}/rows")).unwrap();
                assert_eq!(response.body(), b"row 0\nrow 1\nrow 2\n");
            });
        });
    }

    #[test]
    fn streamed_body_pulls_chunks_on_a_worker() {
        let mut server = Server::new(&[loopback(1)]).unwrap();
        let (handler, received) = detaching();
        server
            .route_with("/upload", Verb::Post, BodyDelivery::Streamed, handler)
            .unwrap();
        let address = server.address(0).unwrap().to_owned();
        let body = pattern(4 << 20);
        serving(&server, || {
            std::thread::scope(|scope| {
                scope.spawn(move || {
                    let mut detached = received.recv().unwrap();
                    let mut pulled = Vec::new();
                    loop {
                        let chunk = detached.body_chunk().unwrap();
                        if chunk.is_empty() {
                            break;
                        }
                        pulled.extend_from_slice(chunk);
                    }
                    let parts = [ReplyPart::Bytes(pulled.as_slice().into())];
                    let deferred = detached.reply_parts(HTTPStatus::OK, &[], &parts).unwrap();
                    assert!(deferred.is_none());
                });
                let url = format!("http://{address}/upload");
                let response = client(1).post(url, body.clone()).unwrap();
                assert_eq!(response.body(), body.as_slice());
            });
        });
    }

    #[test]
    fn body_chunk_would_block_on_polling_thread() {
        let mut server = Server::new(&[loopback(1)]).unwrap();
        let streamed = BodyDelivery::Streamed;
        server
            .route_with("/upload", Verb::Post, streamed, |request: Request| {
                let mut detached = request.detach();
                let pulled = detached.body_chunk().map(<[u8]>::len);
                let answer = format!("{:?}", pulled.map_err(|error| error.status));
                let parts = [ReplyPart::Bytes(answer.as_bytes().into())];
                // Bytes alone are final on return, so nothing waits on this thread.
                let _ = detached.reply_parts(HTTPStatus::OK, &[], &parts);
            })
            .unwrap();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            // Only the head is sent, so the body has no byte decoded when the handler pulls.
            let mut connection = TcpStream::connect(&address).unwrap();
            let head = b"POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\n";
            connection.write_all(head).unwrap();
            connection
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut response = Vec::new();
            let mut buffer = [0; 4096];
            while !response.ends_with(b"Err(WouldBlock)") {
                match connection.read(&mut buffer) {
                    Ok(read) if read != 0 => response.extend_from_slice(&buffer[..read]),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    other => panic!(
                        "answered {:?} then {other:?}",
                        String::from_utf8_lossy(&response)
                    ),
                }
            }
            assert!(response.starts_with(b"HTTP/1.1 200"));
        });
    }

    #[test]
    fn multipart_parts_by_index() {
        let mut server = Server::new(&[loopback(1)]).unwrap();
        server
            .post("/form", |request: Request| {
                let count = request.parts_count();
                let mut summary = format!("{count};");
                for index in 0..count {
                    let part = request.part(index).unwrap();
                    for field in [part.name, part.content_type, part.data] {
                        summary.push_str(&String::from_utf8_lossy(field));
                        summary.push('=');
                    }
                    summary.push(';');
                }
                let past = request
                    .part(count)
                    .map(|_| ())
                    .map_err(|error| error.status);
                summary.push_str(&format!("{past:?}"));
                let _ = request.reply(HTTPStatus::OK, &[], summary.as_bytes());
            })
            .unwrap();
        let address = server.address(0).unwrap().to_owned();
        let body = concat!(
            "--zz\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Type: text/plain\r\n\r\n",
            "one\r\n--zz\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\ntwo\r\n--zz--\r\n",
        );
        serving(&server, || {
            let form: Cow<'static, [u8]> =
                b"content-type: multipart/form-data; boundary=zz"[..].into();
            let call = CallRequest {
                headers: vec![form],
                ..CallRequest::post(format!("http://{address}/form"), body.as_bytes())
            };
            let response = client(1).call(call).unwrap();
            let summary = String::from_utf8_lossy(response.body()).into_owned();
            assert_eq!(summary, "2;a=text/plain=one=;b==two=;Err(InvalidArgument)");
        });
    }

    #[test]
    fn path_segments_by_index() {
        let mut server = Server::new(&[loopback(1)]).unwrap();
        server
            .get("/files/{*path}", |request: Request| {
                let count = request.path_segments_count();
                let mut body = count.to_string().into_bytes();
                for index in 0..count {
                    body.push(b'|');
                    body.extend_from_slice(request.path_segment(index).unwrap());
                }
                if request.path_segment(count).is_none() {
                    body.extend_from_slice(b"|end");
                }
                let _ = request.reply(HTTPStatus::OK, &[], &body);
            })
            .unwrap();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            let url = format!("http://{address}/files/a%20b/c?d=e");
            let response = client(1).get(url).unwrap();
            assert_eq!(response.body(), b"3|files|a%20b|c|end");
        });
    }

    #[test]
    fn kk_interface_admits_its_peer_key() {
        let (server_key, server_public_key) = generate_noise_keypair().unwrap();
        let (client_key, client_public_key) = generate_noise_keypair().unwrap();
        let (stranger_key, _) = generate_noise_keypair().unwrap();
        let sealed = loopback(2)
            .security(Security::NoiseKK, server_key)
            .noise_peer_key(client_public_key);
        let mut server = Server::new(&[sealed]).unwrap();
        server
            .get("/peer", |request: Request| {
                let key = request.peer().static_key;
                let _ = request.reply(HTTPStatus::OK, &[], &key);
            })
            .unwrap();
        let address = server.address(0).unwrap().to_owned();
        let call = |key| CallRequest {
            options: RequestOptions {
                security: Security::NoiseKK,
                client_key: Some(key),
                server_key: Some(server_public_key),
                ..Default::default()
            },
            ..CallRequest::get(format!("http://{address}/peer"))
        };
        serving(&server, || {
            let admitted = client(1).call(call(client_key)).unwrap();
            assert_eq!(admitted.body(), client_public_key.as_slice());
            assert!(client(1).call(call(stranger_key)).is_err());
        });
    }

    #[test]
    fn max_request_bytes_answers_413() {
        let mut server = Server::new(&[loopback(2).max_request_bytes(1024)]).unwrap();
        server
            .post("/echo", |request: Request| {
                let body = request.body().to_vec();
                let _ = request.reply(HTTPStatus::OK, &[], &body);
            })
            .unwrap();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            let url = format!("http://{address}/echo");
            let fitting = client(1).post(url.clone(), vec![b'x'; 64]).unwrap();
            assert_eq!(fitting.status_code(), HTTPStatus::OK);
            let oversized = client(1).post(url, vec![b'x'; 4096]).unwrap();
            assert_eq!(oversized.status_code(), HTTPStatus::PAYLOAD_TOO_LARGE);
        });
    }

    #[test]
    fn metrics_datagram_reaches_a_socket() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let metrics = Metrics {
            address: socket.local_addr().unwrap().to_string(),
            prefix: "rusty".into(),
            interval: Duration::from_millis(10),
            ..Default::default()
        };
        let options = ServerOptions {
            metrics: Some(metrics),
            ..Default::default()
        };
        let mut server = Server::with_options(&[loopback(1)], options).unwrap();
        server
            .get("/ping", |request: Request| {
                let _ = request.reply(HTTPStatus::NO_CONTENT, &[], &[]);
            })
            .unwrap();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            let mut client = client(1);
            let mut datagram = [0; 65536];
            // Each call polls the loop, which sends once the interval passed, and a datagram
            // carries only the counters that moved since the last one.
            let counted = (0..100).any(|_| {
                client.get(format!("http://{address}/ping")).unwrap();
                let length = socket.recv(&mut datagram).unwrap_or(0);
                let text = String::from_utf8_lossy(&datagram[..length]);
                text.contains("rusty.requests:")
            });
            assert!(counted, "no datagram counted the requests");
        });
    }

    #[test]
    fn request_options_timeout_overrides_client() {
        let mut server = Server::new(&[loopback(1)]).unwrap();
        // The worker never comes, so held requests stay unanswered until the receiver drops.
        let (handler, held) = detaching();
        server.get("/slow", handler).unwrap();
        let address = server.address(0).unwrap().to_owned();
        serving(&server, || {
            let mut client = Client::new(ClientOptions {
                connections: 1,
                request_timeout: Duration::from_secs(30),
                ..Default::default()
            })
            .unwrap();
            let call = CallRequest {
                options: RequestOptions {
                    timeout: Duration::from_millis(200),
                    ..Default::default()
                },
                ..CallRequest::get(format!("http://{address}/slow"))
            };
            let started = Instant::now();
            let Err(timed_out) = client.call(call) else {
                panic!("the call was answered past its own timeout");
            };
            assert_eq!(timed_out.status, Status::Timeout);
            assert!(started.elapsed() < Duration::from_secs(10));
            drop(held);
        });
    }
}

// endregion: Tests
