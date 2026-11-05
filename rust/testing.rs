//! Loopback servers polled by scoped threads, the clients that call them, and the unbuffered
//! files replies send, for the suites.
//!
//! File: rust/testing.rs
//! Author: Ash Vardanian
//! Date: October 25, 2026

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use crate::client::{Client, ClientOptions};
use crate::server::{DetachedRequest, Interface, Request, Server};

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
        let polling: Vec<_> = (0..server.event_loops())
            .map(|event_loop| scope.spawn(move || server.take_calls(event_loop)))
            .collect();
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
    Interface::new("127.0.0.1:0")
        .connections(connections)
        .event_loops(1)
}

/// A plaintext client holding up to `connections` open at once.
pub fn client(connections: usize) -> Client {
    Client::new(ClientOptions {
        connections,
        ..Default::default()
    })
    .unwrap()
}

/// A handler detaching every request into the returned receiver, for a worker to answer.
pub fn detaching() -> (
    impl Fn(Request) + Send + Sync + 'static,
    Receiver<DetachedRequest>,
) {
    let (handed, received) = mpsc::channel();
    let handler = move |request: Request| handed.send(request.detach()).unwrap();
    (handler, received)
}

/// The next request [`detaching`] handed over, failing the test instead of waiting forever when
/// no call reached the server, since the server's handler keeps the sender alive.
pub fn next_detached(received: &Receiver<DetachedRequest>) -> DetachedRequest {
    received
        .recv_timeout(Duration::from_secs(30))
        .expect("no request reached the handler")
}

/// An empty directory beside the test binary, inside the build tree, since file parts read
/// unbuffered and tmpfs refuses that.
pub fn direct_directory(name: &str) -> PathBuf {
    let directory = std::env::current_exe().unwrap().with_file_name(name);
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// Opens `path` for the unbuffered reads a file part requires.
pub fn open_direct(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECT)
        .open(path)
        .unwrap()
}

/// `length` bytes cycling through a prime period, so a misplaced range shows.
pub fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index % 251) as u8).collect()
}
