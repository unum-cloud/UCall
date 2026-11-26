//! UCall - HTTP and Noise clients and servers with capability-specialized I/O backends.
//!
//! The crate starts no threads: application threads drive every event loop with
//! [`Server::take_calls`], every batch endpoint with [`BatchEndpoint::take_batches`], and each
//! client on its own thread with [`Client::take_completed`].
//!
//! ```
//! use ucall::*;
//!
//! let greet = |request: Request| {
//!     let name = request.path_parameter("name").unwrap_or_default();
//!     let greeting = [b"Hello, ", name].concat();
//!     let _ = request.reply(HTTPStatus::OK, &["content-type: text/plain".into()], &greeting);
//! };
//! let mut server = Server::new(&[Interface::new("127.0.0.1:0")])?;
//! server.get("/hello/{name}", &greet)?;
//! let address = server.address(0).unwrap().to_owned();
//!
//! let mut client = Client::new(ClientOptions { connections: 1, ..Default::default() })?;
//! std::thread::scope(|scope| {
//!     scope.spawn(|| server.take_calls(0));
//!     let response = client.get(format!("http://{address}/hello/world"));
//!     server.stop();
//!     assert_eq!(response?.body()?, b"Hello, world");
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

pub use client::{Client, ClientCall, ClientCallOptions, ClientOptions, Completed, Response, ResponseBodyChunk};
pub use server::{
    Batch, BatchEndpoint, BatchEndpointStatistics, Batching, BodyChunk, DetachedRequest, EventLoopStatistics,
    FileRange, Interface, Metrics, PathRange, Peer, PeerAddress, Polling, ReplyPart, ReplyStream, Request, RequestPart,
    SendPolicy, Server, ServerOptions,
};
#[cfg(windows)]
pub use types::CrtDescriptor;
pub use types::{
    Backend, BodyDelivery, BytesView, CPUClass, Deferred, Descriptor, Error, HTTPStatus, Log, LogFormat, LogLevel,
    NoiseKey, PeerAuthorizer, PercentMode, Result, Security, Status, Verb, decode_percent, derive_noise_public_key,
    generate_noise_keypair, version,
};
