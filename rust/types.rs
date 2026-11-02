//! Vocabulary shared by servers and clients: statuses and errors, deferred outcomes, verbs,
//! backends, CPU classes, security modes, Noise keys, log sinks, and the byte views header lines
//! are lent as.
//!
//! File: rust/types.rs
//! Author: Ash Vardanian
//! Date: October 25, 2026

// The C mirror keeps the C spelling of every name.
#![allow(non_camel_case_types, non_upper_case_globals)]

use core::ffi::{c_char, c_int, c_void, CStr};
use core::fmt;
use core::future::{Future, IntoFuture};
use core::marker::PhantomData;
use core::pin::Pin;
use core::ptr::{self, NonNull};
use core::str::FromStr;
use core::task::{Context, Poll};
use core::time::Duration;
use std::os::fd::BorrowedFd;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

// region: Raw Declarations

pub(crate) type ucall_byte_t = u8;
pub(crate) type ucall_noise_key_t = [ucall_byte_t; 32];
pub(crate) type ucall_status_t = u32;
pub(crate) type ucall_http_status_t = u32;
pub(crate) type ucall_io_backend_t = c_int;
pub(crate) type ucall_cpu_class_t = c_int;
pub(crate) type ucall_security_mode_t = c_int;
pub(crate) type ucall_verb_t = c_int;
pub(crate) type ucall_log_level_t = c_int;
pub(crate) type ucall_log_format_t = c_int;
pub(crate) type ucall_body_delivery_t = c_int;

pub(crate) const ucall_status_success_k: ucall_status_t = 0;
pub(crate) const ucall_status_deferred_k: ucall_status_t = 1;
pub(crate) const ucall_status_connection_closed_k: ucall_status_t = 21;
pub(crate) const ucall_status_peer_rejected_k: ucall_status_t = 24;

#[repr(C)]
pub(crate) struct ucall_server_handle_t {
    _opaque: [u8; 0],
}

#[repr(C)]
pub(crate) struct ucall_client_handle_t {
    _opaque: [u8; 0],
}

#[repr(C)]
pub(crate) struct ucall_received_http_request_handle_t {
    _opaque: [u8; 0],
}

#[repr(C)]
pub(crate) struct ucall_http_batch_endpoint_handle_t {
    _opaque: [u8; 0],
}

#[repr(C)]
pub(crate) struct ucall_received_http_response_handle_t {
    _opaque: [u8; 0],
}

pub(crate) type ucall_server_t = *mut ucall_server_handle_t;
pub(crate) type ucall_client_t = *mut ucall_client_handle_t;
pub(crate) type ucall_received_http_request_t = *mut ucall_received_http_request_handle_t;
pub(crate) type ucall_http_batch_endpoint_t = *mut ucall_http_batch_endpoint_handle_t;
pub(crate) type ucall_received_http_response_t = *mut ucall_received_http_response_handle_t;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ucall_bytes_view_t {
    pub(crate) data: *const ucall_byte_t,
    pub(crate) length: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ucall_outcome_t {
    pub(crate) status: ucall_status_t,
    pub(crate) message: *const c_char,
}

pub(crate) type ucall_peer_authorizer_t = Option<
    unsafe extern "C" fn(
        peer_static_key: *const ucall_noise_key_t,
        context: *mut c_void,
    ) -> ucall_status_t,
>;

pub(crate) type ucall_log_callback_t = Option<
    unsafe extern "C" fn(level: ucall_log_level_t, line: ucall_bytes_view_t, context: *mut c_void),
>;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ucall_log_t {
    pub(crate) callback: ucall_log_callback_t,
    pub(crate) context: *mut c_void,
    pub(crate) format: ucall_log_format_t,
    pub(crate) level: ucall_log_level_t,
}

#[repr(C)]
struct ucall_noise_key_generate_t {
    outcome: *mut ucall_outcome_t,
    private_key: *mut ucall_noise_key_t,
    public_key: *mut ucall_noise_key_t,
}

#[repr(C)]
struct ucall_noise_key_derive_t {
    outcome: *mut ucall_outcome_t,
    private_key: *const ucall_noise_key_t,
    public_key: *mut ucall_noise_key_t,
}

extern "C" {
    fn ucall_io_backend_name(backend: ucall_io_backend_t) -> *const c_char;
    fn ucall_cpu_class_name(cpu_class: ucall_cpu_class_t) -> *const c_char;
    fn ucall_io_backend_from_name(name: ucall_bytes_view_t) -> ucall_io_backend_t;
    fn ucall_cpu_class_from_name(name: ucall_bytes_view_t) -> ucall_cpu_class_t;
    fn ucall_status_name(status: ucall_status_t) -> *const c_char;
    fn ucall_version_name() -> *const c_char;
    fn ucall_noise_key_generate(arguments: *mut ucall_noise_key_generate_t);
    fn ucall_noise_key_derive(arguments: *mut ucall_noise_key_derive_t);
    pub(crate) fn ucall_outcome_wait(outcome: *mut ucall_outcome_t) -> ucall_status_t;
    pub(crate) fn ucall_outcome_status(outcome: *mut ucall_outcome_t) -> ucall_status_t;
}

// endregion: Raw Declarations

/// Why a call failed, numbered as the library numbers it; success is the `Ok` of a [`Result`].
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[non_exhaustive]
pub enum Status {
    /// A reply is still sending a file or path part, as [`Deferred::status`] reports it.
    Deferred = 1,
    /// An allocation or reservation could not be satisfied.
    OutOfMemory = 2,
    /// A socket or file could not be opened, read, written, or closed.
    IO = 7,
    /// The peer supplied bytes that cannot be decoded as the expected protocol.
    Malformed = 9,
    /// The library violated its contract, which points at a defect.
    Internal = 10,
    /// The requested size exceeds the representable range.
    Overflow = 11,
    /// The call needs a handle that was never initialized.
    Uninitialized = 12,
    /// The call was refused rather than waited for, like a submission to a full client.
    Contended = 14,
    /// The build, backend, or machine does not implement the requested feature.
    Unsupported = 16,
    /// An argument is missing, out of range, or contradicts another argument.
    InvalidArgument = 17,
    /// The requested endpoint, header, or parameter does not exist.
    NotFound = 18,
    /// An endpoint with the same template and verb is already registered.
    AlreadyExists = 19,
    /// DNS lookup or connection establishment failed.
    ConnectionFailed = 20,
    /// The connection closed before the exchange completed.
    ConnectionClosed = 21,
    /// The operation exceeded its time budget.
    Timeout = 22,
    /// The Noise handshake failed to authenticate or agree on keys.
    HandshakeFailed = 23,
    /// The peer authorizer declined the authenticated static key.
    PeerRejected = 24,
    /// Nothing was ready: a nonblocking poll had no progress to report, a pull on the polling
    /// thread found no body bytes yet, or a stream's peer lags behind its appended parts.
    WouldBlock = 25,
}

impl Status {
    /// Lifts the C status word, reading a value this binding has no name for as `Internal`.
    pub(crate) fn from_raw(value: ucall_status_t) -> core::result::Result<(), Self> {
        if value == ucall_status_success_k {
            return Ok(());
        }
        let status = match value {
            1 => Status::Deferred,
            2 => Status::OutOfMemory,
            7 => Status::IO,
            9 => Status::Malformed,
            11 => Status::Overflow,
            12 => Status::Uninitialized,
            14 => Status::Contended,
            16 => Status::Unsupported,
            17 => Status::InvalidArgument,
            18 => Status::NotFound,
            19 => Status::AlreadyExists,
            20 => Status::ConnectionFailed,
            21 => Status::ConnectionClosed,
            22 => Status::Timeout,
            23 => Status::HandshakeFailed,
            24 => Status::PeerRejected,
            25 => Status::WouldBlock,
            _ => Status::Internal,
        };
        Err(status)
    }
}

impl fmt::Display for Status {
    /// Writes the stable spelling, like "out-of-memory".
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(unsafe { static_string(ucall_status_name(*self as ucall_status_t)) })
    }
}

/// A failure, whether the library reported it or the binding caught it before the call.
///
/// Messages are static storage, so nothing allocates on the failure path.
///
/// ```
/// use ucall::{Client, ClientOptions, Status};
///
/// let refused = Client::new(ClientOptions::default()).err().expect("a client needs connections");
/// assert_eq!(refused.status, Status::InvalidArgument);
/// println!("{refused}"); // "invalid-argument: ..."
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Error {
    /// What went wrong, to branch on.
    pub status: Status,
    /// The detail the status alone cannot carry.
    pub message: &'static str,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.status, self.message)
    }
}

impl std::error::Error for Error {}

/// The result of every fallible call in this crate.
pub type Result<Value> = core::result::Result<Value, Error>;

/// Turns a final outcome into a `Result`.
pub(crate) fn check(outcome: ucall_outcome_t) -> Result<()> {
    Status::from_raw(outcome.status).map_err(|status| Error {
        status,
        message: unsafe { static_string(outcome.message) },
    })
}

/// Reports a failure the binding caught before the call crossed the boundary, under the status
/// the library would have used for the same mistake.
pub(crate) fn fail(status: Status, message: &'static str) -> Error {
    Error { status, message }
}

/// An outcome for the library to overwrite, starting as success.
pub(crate) fn pending_outcome() -> ucall_outcome_t {
    ucall_outcome_t {
        status: ucall_status_success_k,
        message: ptr::null(),
    }
}

/// A reply still sending a file or path part: it owns the outcome the event loop makes final,
/// and the descriptors its parts borrow stay open for `'f`, until it is final.
///
/// [`Deferred::status`] polls without blocking, [`Deferred::wait`] blocks until the reply is
/// final, and `.await` polls it from async code. Dropping one that is not final waits for it, so
/// it belongs off the polling thread, which is the one finishing it.
#[must_use = "dropping a deferred reply waits for it"]
pub struct Deferred<'f> {
    // A raw heap address rather than a `Box`, as the event loop writes it while this moves.
    outcome: NonNull<ucall_outcome_t>,
    files: PhantomData<BorrowedFd<'f>>,
}

// The outcome moves with the `Deferred`, and until it is final only the library writes it.
unsafe impl Send for Deferred<'_> {}

impl Deferred<'_> {
    /// An outcome at a stable heap address, for a verb that may finish after it returns.
    pub(crate) fn pending() -> Self {
        Deferred {
            outcome: NonNull::from(Box::leak(Box::new(pending_outcome()))),
            files: PhantomData,
        }
    }

    /// The outcome to hand the verb.
    pub(crate) fn raw(&self) -> *mut ucall_outcome_t {
        self.outcome.as_ptr()
    }

    /// `Err(Status::Deferred)` until the reply is final, then its final status, read without
    /// blocking through `ucall_outcome_status`.
    pub fn status(&self) -> core::result::Result<(), Status> {
        Status::from_raw(unsafe { ucall_outcome_status(self.raw()) })
    }

    /// Blocks until the reply is final, through `ucall_outcome_wait`, and reports how it ended.
    pub fn wait(self) -> Result<()> {
        unsafe { ucall_outcome_wait(self.raw()) };
        check(unsafe { *self.raw() })
    }
}

impl Drop for Deferred<'_> {
    fn drop(&mut self) {
        // Once final, the library touches the outcome no more, so it is freed here.
        unsafe {
            ucall_outcome_wait(self.raw());
            drop(Box::from_raw(self.raw()));
        }
    }
}

impl fmt::Debug for Deferred<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Deferred({:?})", self.status())
    }
}

impl<'f> IntoFuture for Deferred<'f> {
    type Output = Result<()>;
    type IntoFuture = Wait<'f>;

    fn into_future(self) -> Wait<'f> {
        Wait(Some(self))
    }
}

/// A [`Deferred`] being awaited: every poll reads its status, and one not yet final asks to be
/// polled again.
///
/// The library has no wake-up, so an executor re-polls it while other tasks run, spinning only
/// when nothing else is ready; [`Deferred::wait`] blocks without spinning.
#[must_use = "an awaited reply does nothing unless polled"]
pub struct Wait<'f>(Option<Deferred<'f>>);

impl Future for Wait<'_> {
    type Output = Result<()>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let awaited = &mut self.get_mut().0;
        match awaited.take() {
            None => Poll::Ready(Err(fail(
                Status::InvalidArgument,
                "the reply was already awaited",
            ))),
            Some(deferred) if deferred.status() == Err(Status::Deferred) => {
                *awaited = Some(deferred);
                context.waker().wake_by_ref();
                Poll::Pending
            }
            Some(deferred) => Poll::Ready(deferred.wait()),
        }
    }
}

/// Borrows a static null-terminated string the library owns.
///
/// Every such string is ASCII by construction, so its bytes are read as UTF-8 unchecked.
pub(crate) unsafe fn static_string(raw: *const c_char) -> &'static str {
    if raw.is_null() {
        return "";
    }
    core::str::from_utf8_unchecked(CStr::from_ptr(raw).to_bytes())
}

/// Lends a borrowed slice as the view the library reads.
pub(crate) fn view(bytes: &[u8]) -> ucall_bytes_view_t {
    ucall_bytes_view_t {
        data: bytes.as_ptr(),
        length: bytes.len(),
    }
}

/// Reads a view the library wrote back as a slice living as long as `'owner`.
///
/// # Safety
/// The view must address `length` initialized bytes that stay unchanged for `'owner`.
pub(crate) unsafe fn viewed<'owner>(bytes: ucall_bytes_view_t) -> &'owner [u8] {
    match bytes.data.is_null() {
        true => &[],
        false => core::slice::from_raw_parts(bytes.data, bytes.length),
    }
}

/// Spells a duration as the microseconds every C time budget takes, saturating at the largest.
pub(crate) fn microseconds(duration: Duration) -> usize {
    usize::try_from(duration.as_micros()).unwrap_or(usize::MAX)
}

/// The version of the linked library, like "1.0.0" or "1.0.0-rc.1".
pub fn version() -> &'static str {
    unsafe { static_string(ucall_version_name()) }
}

/// A 32-byte Curve25519 key, private or public, as every Noise handshake takes it.
pub type NoiseKey = [u8; 32];

/// Draws a fresh `(private_key, public_key)` pair from the operating system's entropy.
///
/// Fails with [`Status::IO`] when the operating system refuses entropy.
///
/// ```
/// use ucall::{derive_noise_public_key, generate_noise_keypair};
///
/// let (private_key, public_key) = generate_noise_keypair()?;
/// assert_eq!(derive_noise_public_key(&private_key), public_key);
/// # Ok::<(), ucall::Error>(())
/// ```
pub fn generate_noise_keypair() -> Result<(NoiseKey, NoiseKey)> {
    let mut private_key: NoiseKey = [0; 32];
    let mut public_key: NoiseKey = [0; 32];
    let mut outcome = pending_outcome();
    let mut arguments = ucall_noise_key_generate_t {
        outcome: &mut outcome,
        private_key: &mut private_key,
        public_key: &mut public_key,
    };
    unsafe { ucall_noise_key_generate(&mut arguments) };
    check(outcome).map(|()| (private_key, public_key))
}

/// The public key of `private_key`, as a [`PeerAuthorizer`] on the other side sees it.
pub fn derive_noise_public_key(private_key: &NoiseKey) -> NoiseKey {
    let mut public_key: NoiseKey = [0; 32];
    let mut outcome = pending_outcome();
    let mut arguments = ucall_noise_key_derive_t {
        outcome: &mut outcome,
        private_key,
        public_key: &mut public_key,
    };
    // Derivation fails only on the null pointers references rule out.
    unsafe { ucall_noise_key_derive(&mut arguments) };
    public_key
}

/// A borrowed header line, laid out so a slice of them is lent to the library without copying.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct BytesView<'bytes> {
    raw: ucall_bytes_view_t,
    bytes: PhantomData<&'bytes [u8]>,
}

impl<'bytes> From<&'bytes [u8]> for BytesView<'bytes> {
    fn from(bytes: &'bytes [u8]) -> Self {
        BytesView {
            raw: view(bytes),
            bytes: PhantomData,
        }
    }
}

impl<'bytes> From<&'bytes str> for BytesView<'bytes> {
    fn from(text: &'bytes str) -> Self {
        BytesView::from(text.as_bytes())
    }
}

impl<'bytes, const LENGTH: usize> From<&'bytes [u8; LENGTH]> for BytesView<'bytes> {
    fn from(bytes: &'bytes [u8; LENGTH]) -> Self {
        BytesView::from(bytes.as_slice())
    }
}

impl<'bytes> BytesView<'bytes> {
    /// The bytes this view borrows.
    pub fn as_bytes(&self) -> &'bytes [u8] {
        unsafe { viewed(self.raw) }
    }

    /// Lends a run of views as the counted array the library reads.
    pub(crate) fn raw_array(views: &[BytesView<'_>]) -> *const ucall_bytes_view_t {
        views.as_ptr().cast()
    }
}

impl fmt::Debug for BytesView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_bytes(), formatter)
    }
}

/// An HTTP status code, for replies and received responses alike; codes without a constant here
/// are just as valid.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct HTTPStatus(pub u32);

impl HTTPStatus {
    /// 200, the request succeeded.
    pub const OK: HTTPStatus = HTTPStatus(200);
    /// 201, a resource was created.
    pub const CREATED: HTTPStatus = HTTPStatus(201);
    /// 204, success with an empty body.
    pub const NO_CONTENT: HTTPStatus = HTTPStatus(204);
    /// 206, success with the requested range of the body.
    pub const PARTIAL_CONTENT: HTTPStatus = HTTPStatus(206);
    /// 301, the resource has a new permanent URL.
    pub const MOVED_PERMANENTLY: HTTPStatus = HTTPStatus(301);
    /// 302, the resource is temporarily at a different URL.
    pub const FOUND: HTTPStatus = HTTPStatus(302);
    /// 304, the cached copy is still fresh.
    pub const NOT_MODIFIED: HTTPStatus = HTTPStatus(304);
    /// 400, the request is malformed.
    pub const BAD_REQUEST: HTTPStatus = HTTPStatus(400);
    /// 401, authentication is required or failed.
    pub const UNAUTHORIZED: HTTPStatus = HTTPStatus(401);
    /// 403, authenticated but not permitted.
    pub const FORBIDDEN: HTTPStatus = HTTPStatus(403);
    /// 404, no endpoint matches the path.
    pub const NOT_FOUND: HTTPStatus = HTTPStatus(404);
    /// 405, the endpoint exists, but not for this verb.
    pub const METHOD_NOT_ALLOWED: HTTPStatus = HTTPStatus(405);
    /// 408, the client took too long to send the request.
    pub const TIMEOUT: HTTPStatus = HTTPStatus(408);
    /// 409, the request conflicts with the resource's state.
    pub const CONFLICT: HTTPStatus = HTTPStatus(409);
    /// 412, a request condition does not match the resource.
    pub const PRECONDITION_FAILED: HTTPStatus = HTTPStatus(412);
    /// 413, the request body is too large.
    pub const PAYLOAD_TOO_LARGE: HTTPStatus = HTTPStatus(413);
    /// 429, the rate limit is exceeded.
    pub const TOO_MANY_REQUESTS: HTTPStatus = HTTPStatus(429);
    /// 500, a handler failed or dropped its request unanswered.
    pub const INTERNAL_ERROR: HTTPStatus = HTTPStatus(500);
    /// 501, the verb or feature is not supported.
    pub const NOT_IMPLEMENTED: HTTPStatus = HTTPStatus(501);
    /// 503, the server is overloaded, like a batch endpoint whose queue is full.
    pub const SERVICE_UNAVAILABLE: HTTPStatus = HTTPStatus(503);
    /// 504, an upstream dependency timed out.
    pub const GATEWAY_TIMEOUT: HTTPStatus = HTTPStatus(504);
}

/// An HTTP method, for routing on the server and for calls on the client.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Verb {
    /// Unrecognized; a routed request never carries it.
    Unknown,
    /// GET, reading a resource.
    Get,
    /// POST, creating a resource or calling a procedure.
    Post,
    /// PUT, replacing a resource.
    Put,
    /// DELETE, removing a resource.
    Delete,
    /// PATCH, updating part of a resource.
    Patch,
    /// HEAD, reading only the headers.
    Head,
    /// OPTIONS, asking which methods a resource supports.
    Options,
    /// Matches every method; valid only when registering an endpoint.
    Any,
}

impl Verb {
    pub(crate) fn to_raw(self) -> ucall_verb_t {
        self as ucall_verb_t
    }

    pub(crate) fn from_raw(value: ucall_verb_t) -> Self {
        match value {
            1 => Verb::Get,
            2 => Verb::Post,
            3 => Verb::Put,
            4 => Verb::Delete,
            5 => Verb::Patch,
            6 => Verb::Head,
            7 => Verb::Options,
            8 => Verb::Any,
            _ => Verb::Unknown,
        }
    }
}

/// The I/O implementation a server or client runs on.
///
/// Prints and parses its stable name, like "linux-uring618".
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Default)]
pub enum Backend {
    /// The best native backend this machine and build offer.
    #[default]
    Automatic,
    /// Portable readiness polling on any POSIX system.
    POSIX,
    /// Linux readiness polling over `epoll`, reading files through Linux AIO.
    LinuxEpollAIO,
    /// Linux io_uring as kernel 6.12 offers it.
    LinuxURing612,
    /// Linux io_uring as kernel 6.18 offers it.
    LinuxURing618,
    /// macOS and FreeBSD readiness polling over `kqueue`.
    MacOSKqueue,
    /// Windows I/O completion ports.
    WindowsIOCP,
}

impl Backend {
    pub(crate) fn to_raw(self) -> ucall_io_backend_t {
        self as ucall_io_backend_t
    }

    pub(crate) fn from_raw(value: ucall_io_backend_t) -> Self {
        match value {
            1 => Backend::POSIX,
            2 => Backend::LinuxEpollAIO,
            3 => Backend::LinuxURing612,
            4 => Backend::LinuxURing618,
            5 => Backend::MacOSKqueue,
            6 => Backend::WindowsIOCP,
            _ => Backend::Automatic,
        }
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(unsafe { static_string(ucall_io_backend_name(self.to_raw())) })
    }
}

impl FromStr for Backend {
    type Err = Error;

    /// Reads a stable name back, failing with [`Status::InvalidArgument`] on one no backend has.
    fn from_str(name: &str) -> Result<Self> {
        let backend =
            Backend::from_raw(unsafe { ucall_io_backend_from_name(view(name.as_bytes())) });
        match backend != Backend::Automatic || name == Backend::Automatic.to_string() {
            true => Ok(backend),
            false => Err(fail(
                Status::InvalidArgument,
                "no I/O backend has that name",
            )),
        }
    }
}

/// The CPU kernels a server or client runs, from the portable `Serial` up, where `None` takes what the
/// constructing thread's CPU offers.
///
/// A class is a ceiling: the newest compiled class under it runs, failing with
/// [`Status::Unsupported`] where the CPU does not run it. Every thread that later polls, replies, or
/// reads must run on a CPU supporting the class resolved at construction, and `Serial` is the
/// conservative choice where they differ. Prints and parses its stable name, like "intel-icelake".
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum CPUClass {
    /// Portable kernels that run on any CPU.
    Serial = 1,
    /// x86 cores from Intel Haswell on.
    IntelHaswell = 2,
    /// x86 server cores from Intel Skylake on.
    IntelSkylake = 3,
    /// x86 server cores from Intel Ice Lake on.
    IntelIcelake = 4,
    /// x86 hybrid cores from Intel Alder Lake on.
    IntelAlder = 5,
    /// x86 efficiency cores from Intel Sierra Forest on.
    IntelSierra = 6,
    /// Arm cores from AWS Graviton 2 on.
    AWSG2 = 7,
    /// Arm cores from Apple M2 on.
    AppleM2 = 8,
    /// Arm server cores from AWS Graviton 5 on.
    AWSG5 = 9,
    /// The one class of a monoversioned build, with every capability it compiled.
    Monoversioned = 10,
}

impl CPUClass {
    /// The `ucall_cpu_class_t` of `cpu_class`, zero for `None`.
    pub(crate) fn to_raw(cpu_class: Option<CPUClass>) -> ucall_cpu_class_t {
        cpu_class.map_or(0, |cpu_class| cpu_class as ucall_cpu_class_t)
    }

    pub(crate) fn from_raw(value: ucall_cpu_class_t) -> Option<Self> {
        match value {
            1 => Some(CPUClass::Serial),
            2 => Some(CPUClass::IntelHaswell),
            3 => Some(CPUClass::IntelSkylake),
            4 => Some(CPUClass::IntelIcelake),
            5 => Some(CPUClass::IntelAlder),
            6 => Some(CPUClass::IntelSierra),
            7 => Some(CPUClass::AWSG2),
            8 => Some(CPUClass::AppleM2),
            9 => Some(CPUClass::AWSG5),
            10 => Some(CPUClass::Monoversioned),
            _ => None,
        }
    }
}

impl fmt::Display for CPUClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str(unsafe { static_string(ucall_cpu_class_name(*self as ucall_cpu_class_t)) })
    }
}

impl FromStr for CPUClass {
    type Err = Error;

    /// Reads a stable name back, failing with [`Status::InvalidArgument`] on one no class has.
    fn from_str(name: &str) -> Result<Self> {
        CPUClass::from_raw(unsafe { ucall_cpu_class_from_name(view(name.as_bytes())) })
            .ok_or_else(|| fail(Status::InvalidArgument, "no CPU class has that name"))
    }
}

/// The transport security of a server interface or a client call.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Default)]
pub enum Security {
    /// Plain TCP.
    #[default]
    None,
    /// Noise XX: both parties learn each other's static keys during the handshake.
    NoiseXX,
    /// Noise IK: the client knows the server's static key in advance.
    NoiseIK,
    /// Noise KK: both parties know each other's static keys in advance; client calls only.
    NoiseKK,
}

impl Security {
    pub(crate) fn to_raw(self) -> ucall_security_mode_t {
        self as ucall_security_mode_t
    }
}

/// Decides whether a peer presenting an authenticated static key may proceed past the handshake.
///
/// A server runs it on the polling thread completing the handshake, and a client on its owner
/// thread inside [`Client::take_completed`](crate::Client::take_completed). A panic rejects the
/// peer.
pub type PeerAuthorizer = dyn Fn(&NoiseKey) -> bool + Send + Sync;

/// Lends an optional authorizer as the C callback and the context it is called with.
///
/// The context points at `authorizer` itself, which must stay in place until the handle is freed.
pub(crate) fn lend_authorizer(
    authorizer: &Option<Arc<PeerAuthorizer>>,
) -> (ucall_peer_authorizer_t, *mut c_void) {
    match authorizer {
        Some(authorizer) => (
            Some(authorize_trampoline),
            ptr::from_ref(authorizer).cast_mut().cast(),
        ),
        None => (None, ptr::null_mut()),
    }
}

/// # Safety
/// `context` must address a live `Arc<PeerAuthorizer>`, and `key` a 32-byte key.
unsafe extern "C" fn authorize_trampoline(
    key: *const ucall_noise_key_t,
    context: *mut c_void,
) -> ucall_status_t {
    let authorizer = &*context.cast::<Arc<PeerAuthorizer>>();
    match catch_unwind(AssertUnwindSafe(|| authorizer(&*key))) {
        Ok(true) => ucall_status_success_k,
        _ => ucall_status_peer_rejected_k,
    }
}

/// When an endpoint's handler runs: once the body is buffered, or at headers time, with the body
/// pulled through [`DetachedRequest::body_chunk`](crate::DetachedRequest::body_chunk).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Default)]
pub enum BodyDelivery {
    /// The handler runs once the whole body arrived, read through `body`.
    #[default]
    Buffered,
    /// The handler runs once the headers arrived, and the body is pulled chunk by chunk.
    Streamed,
}

impl BodyDelivery {
    pub(crate) fn to_raw(self) -> ucall_body_delivery_t {
        self as ucall_body_delivery_t
    }
}

/// The severity of a log line, from the most verbose up.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, Default)]
pub enum LogLevel {
    /// Detail for debugging UCall itself.
    #[default]
    Debug,
    /// Routine events.
    Info,
    /// Something recoverable went wrong.
    Warning,
    /// An operation failed.
    Error,
    /// The handle cannot go on.
    Fatal,
}

impl LogLevel {
    fn from_raw(value: ucall_log_level_t) -> Self {
        match value {
            0 => LogLevel::Debug,
            1 => LogLevel::Info,
            2 => LogLevel::Warning,
            3 => LogLevel::Error,
            _ => LogLevel::Fatal,
        }
    }
}

/// The shape of each log line.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Default)]
pub enum LogFormat {
    /// Human-readable lines with normalized units.
    #[default]
    Human,
    /// One JSON document per line.
    JSON,
}

/// Receives one formatted log line, without a trailing newline, on whichever thread produced it,
/// polling threads included; it should return quickly, and a panic drops the line.
pub type LogCallback = dyn Fn(LogLevel, &[u8]) + Send + Sync;

/// The one log sink of a server or a client; without one, the library writes nothing anywhere.
#[derive(Clone)]
pub struct Log {
    /// Receives every line at or above `level`.
    pub callback: Arc<LogCallback>,
    /// The line format.
    pub format: LogFormat,
    /// Lines below this severity are never formatted.
    pub level: LogLevel,
}

/// Lends an optional sink as the C log, whose context points at the callback inside `log`, which
/// must stay in place until the handle is freed.
pub(crate) fn lend_log(log: &Option<Box<Log>>) -> ucall_log_t {
    match log {
        Some(log) => ucall_log_t {
            callback: Some(log_trampoline),
            context: ptr::from_ref(&log.callback).cast_mut().cast(),
            format: log.format as ucall_log_format_t,
            level: log.level as ucall_log_level_t,
        },
        None => ucall_log_t {
            callback: None,
            context: ptr::null_mut(),
            format: 0,
            level: 0,
        },
    }
}

/// # Safety
/// `context` must address a live `Arc<LogCallback>`, and `line` a valid view.
unsafe extern "C" fn log_trampoline(
    level: ucall_log_level_t,
    line: ucall_bytes_view_t,
    context: *mut c_void,
) {
    let callback = &*context.cast::<Arc<LogCallback>>();
    let _ = catch_unwind(AssertUnwindSafe(|| {
        callback(LogLevel::from_raw(level), viewed(line))
    }));
}

// region: Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_come_from_the_library() {
        assert_eq!(Status::OutOfMemory.to_string(), "out-of-memory");
        assert_eq!(Backend::LinuxURing618.to_string(), "linux-uring618");
        assert_eq!(CPUClass::AWSG5.to_string(), "aws-g5");
    }

    #[test]
    fn names_parse_back_and_unknown_ones_fail() {
        assert_eq!(
            "linux-epollaio".parse::<Backend>(),
            Ok(Backend::LinuxEpollAIO)
        );
        assert_eq!("automatic".parse::<Backend>(), Ok(Backend::Automatic));
        assert_eq!("serial".parse::<CPUClass>(), Ok(CPUClass::Serial));
        let unknown = "linux-epol".parse::<Backend>().unwrap_err();
        assert_eq!(unknown.status, Status::InvalidArgument);
        assert!("".parse::<CPUClass>().is_err());
        assert!("automatic".parse::<CPUClass>().is_err());
    }

    #[test]
    fn statuses_round_trip_through_their_numbers() {
        for status in [Status::IO, Status::NotFound, Status::WouldBlock] {
            assert_eq!(Status::from_raw(status as u32), Err(status));
        }
        assert_eq!(Status::from_raw(0), Ok(()));
        assert_eq!(Status::from_raw(3), Err(Status::Internal));
    }

    #[test]
    fn generated_noise_keys_derive_back() {
        let (private_key, public_key) = generate_noise_keypair().unwrap();
        assert_eq!(derive_noise_public_key(&private_key), public_key);
        assert_ne!(generate_noise_keypair().unwrap().0, private_key);
    }
}

// endregion: Tests
