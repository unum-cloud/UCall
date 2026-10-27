//! UCall - HTTP and Noise clients and servers with capability-specialized I/O backends.
//!
//! The crate starts no threads: application threads drive every event loop with
//! [`Server::take_calls`], every batch endpoint with [`BatchEndpoint::take_batches`], and each
//! client on its own thread with [`Client::take_completed`].
//!
//! ```
//! use std::time::Duration;
//! use ucall::*;
//!
//! let interface = Interface::new("127.0.0.1:0").pipelined_requests(16);
//! let mut server = Server::new(&[interface])?;
//! server.post("/sum", |request: Request| {
//!     let sum: u64 = request.body().iter().map(|&byte| u64::from(byte)).sum();
//!     let _ = request.reply(HTTPStatus::OK, &[], sum.to_string().as_bytes());
//! })?;
//! let batching = Batching { min_size: 8, max_size: 64, max_latency: Duration::from_micros(500) };
//! let infer = server.batch("/infer", Verb::Post, batching, |batch: Batch| {
//!     for request in batch {
//!         let _ = request.reply(HTTPStatus::OK, &[], b"scored");
//!     }
//! })?;
//! let address = server.address(0).unwrap().to_owned();
//!
//! let mut client = Client::new(ClientOptions { connections: 4, ..Default::default() })?;
//! std::thread::scope(|scope| {
//!     for event_loop in 0..server.event_loops() {
//!         let server = &server;
//!         scope.spawn(move || server.take_calls(event_loop));
//!     }
//!     scope.spawn(|| infer.take_batches());
//!     let sum = client.post(format!("http://{address}/sum"), vec![1, 2, 3]);
//!     let scored = client.post(format!("http://{address}/infer"), b"pixels".as_slice());
//!     server.stop();
//!     assert_eq!(sum?.body(), b"6");
//!     assert_eq!(scored?.body(), b"scored");
//!     Ok::<(), Error>(())
//! })?;
//! # Ok::<(), ucall::Error>(())
//! ```
//!
//! File: rust/lib.rs
//! Author: Ash Vardanian
//! Date: October 25, 2026

// Acronyms keep their capitals, as in `CPUClass` and `HTTPStatus`.
#![allow(clippy::upper_case_acronyms)]
#![warn(missing_docs)]

mod client;
mod server;
mod types;

#[cfg(test)]
mod testing;

pub use client::{CallRequest, Client, ClientOptions, Completed, Response};
pub use server::{
    Batch, BatchEndpoint, BatchEndpointStatistics, Batching, EventLoopStatistics, Interface, Peer,
    Request, Server,
};
pub use types::{
    derive_noise_public_key, generate_noise_keypair, version, Backend, BytesView, CPUClass, Error,
    HTTPStatus, NoiseKey, PeerAuthorizer, Result, Security, Status, Verb,
};
