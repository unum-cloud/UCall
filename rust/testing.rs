//! The seed, streams, scratch directories and polling every sibling library's suites share, then
//! UCall's own: loopback servers polled by scoped threads, the clients that call them, and the
//! unbuffered files replies send.
//!
//! File: rust/testing.rs
//! Author: Ash Vardanian
//! Date: October 25, 2026

#![allow(dead_code, reason = "the Shared Testing region is the same in every sibling library, used or not")]

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use crate::client::{Client, ClientOptions};
use crate::server::{DetachedRequest, Interface, Request, Server};

/// The environment variable [`seed`] reads, as in the C, C++ and Python suites.
const SEED_VARIABLE: &str = "UCALL_SEED";

// region Shared Testing
/// Announces a skipped test on stderr, so a run shows what it left out rather than passing in
/// silence.
pub(crate) fn skipped(reason: &str) {
    eprintln!("skipped: {reason}");
}

/// The run's seed, read once from the variable [`SEED_VARIABLE`] names: 42 when unset, drawn afresh
/// for `random` and then printed, so the run can be repeated.
pub(crate) fn seed() -> u64 {
    static SEED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SEED.get_or_init(read_seed)
}

/// Parses [`SEED_VARIABLE`] once for [`seed`].
fn read_seed() -> u64 {
    use std::hash::{BuildHasher, Hasher};

    const EXPECTED: &str = "an unsigned integer or random";
    let text = std::env::var(SEED_VARIABLE).unwrap_or_default();
    if text.is_empty() {
        return 42;
    }
    if text != "random" {
        let Ok(parsed) = text.parse::<u64>() else {
            panic!("{SEED_VARIABLE}=\"{text}\" does not parse, expected {EXPECTED}");
        };
        return parsed;
    }
    let hasher = std::collections::hash_map::RandomState::new().build_hasher();
    let drawn = hasher.finish();
    eprintln!("{SEED_VARIABLE}={drawn}");
    drawn
}

/// SplitMix64's finalizer, a bijection that spreads every input bit over all 64 output bits.
pub(crate) const fn split_mix_bits(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

/// The `index`-th stream of the family `name` under `seed`, identical in C, C++, Python and
/// Mojo.
pub(crate) fn stream_key(seed: u64, name: &str, index: u64) -> u64 {
    let mut hashed = 0xCBF2_9CE4_8422_2325_u64;
    for byte in name.bytes() {
        hashed = (hashed ^ u64::from(byte)).wrapping_mul(0x0100_0000_01B3);
    }
    split_mix_bits(split_mix_bits(seed ^ hashed).wrapping_add(index))
}

/// The `index`-th stream of the running test, keyed by the name libtest gives its thread.
pub(crate) fn case_stream_key(index: u64) -> u64 {
    let thread = std::thread::current();
    let name = thread.name().unwrap_or("main");
    stream_key(seed(), name, index)
}

/// A directory of its own under the system's temporary one, removed when dropped.
pub(crate) struct ScratchDirectory {
    path: std::path::PathBuf,
}

impl ScratchDirectory {
    /// Creates `<temp>/<name>-<pid>-<nanos>`, so parallel tests never share one.
    pub(crate) fn new(name: &str) -> Self {
        let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
        let nanos = since.map_or(0, |elapsed| elapsed.as_nanos());
        let leaf = format!("{name}-{}-{nanos}", std::process::id());
        let path = std::env::temp_dir().join(leaf);
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    /// Where the directory is.
    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for ScratchDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Polls `future` to completion on this thread with a no-op waker.
pub(crate) fn block_on<F: core::future::Future>(future: F) -> F::Output {
    let mut future = core::pin::pin!(future);
    let waker = core::task::Waker::noop();
    let mut context = core::task::Context::from_waker(waker);
    loop {
        if let core::task::Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        std::thread::yield_now();
    }
}
// endregion Shared Testing

/// Stops the server when dropped, so a failed assertion still releases the polling threads.
pub struct Stopping<'server>(pub &'server Server);

impl Drop for Stopping<'_> {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// Runs `calls` on this thread while one scoped thread drives each event loop, then stops the
/// server and checks every loop finished cleanly.
pub fn serving(server: &Server, calls: impl FnOnce()) {
    std::thread::scope(|scope| {
        let polling: Vec<_> =
            (0..server.event_loops()).map(|event_loop| scope.spawn(move || server.take_calls(event_loop))).collect();
        let stopping = Stopping(server);
        calls();
        drop(stopping);
        for polling in polling {
            assert_eq!(polling.join().unwrap(), Ok(()));
        }
    });
}

/// One event loop on a free loopback port, admitting `connections` at once.
pub fn loopback(connections: usize) -> Interface {
    Interface::new("127.0.0.1:0").connections(connections).event_loops(1)
}

/// A plaintext client holding up to `connections` open at once.
pub fn client(connections: usize) -> Client {
    Client::new(ClientOptions { connections, ..Default::default() }).unwrap()
}

/// A handler detaching every request into the returned receiver, for a worker to answer.
pub fn detaching() -> (impl Fn(Request) + Send + Sync + 'static, Receiver<DetachedRequest>) {
    let (handed, received) = mpsc::channel();
    let handler = move |request: Request| handed.send(request.detach()).unwrap();
    (handler, received)
}

/// The next request [`detaching`] handed over, failing the test instead of waiting forever when
/// no call reached the server, since the server's handler keeps the sender alive.
pub fn next_detached(received: &Receiver<DetachedRequest>) -> DetachedRequest {
    received.recv_timeout(Duration::from_secs(30)).expect("no request reached the handler")
}

/// An empty directory for the files replies read unbuffered, removed when dropped: under
/// `UCALL_TEST_DIRECT_DIRECTORY` when set, else beside the test binary, since tmpfs refuses
/// unbuffered reads.
pub fn direct_directory(name: &str) -> ScratchDirectory {
    let base = match std::env::var_os("UCALL_TEST_DIRECT_DIRECTORY") {
        Some(base) if !base.is_empty() => PathBuf::from(base),
        _ => std::env::current_exe().unwrap().parent().unwrap().to_owned(),
    };
    let path = base.join(format!("ucall-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&path).unwrap();
    ScratchDirectory { path }
}

/// Opens `path` for the unbuffered reads a file part requires.
pub fn open_direct(path: &Path) -> File {
    OpenOptions::new().read(true).custom_flags(libc::O_DIRECT).open(path).unwrap()
}

/// `length` bytes cycling through a prime period, so a misplaced range shows.
pub fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}
