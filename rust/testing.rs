//! Loopback servers polled by scoped threads, and the clients that call them, for the suites.

use crate::client::{Client, ClientOptions};
use crate::server::{Interface, Server};

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
