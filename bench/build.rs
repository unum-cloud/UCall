//! Generates the gRPC messages, service and client of `bench.proto` for `tonic_server` and `grpc_client`.
//!
//! File: bench/build.rs
//! Author: Ash Vardanian
//! Date: October 25, 2026

fn main() -> std::io::Result<()> {
    // `Bytes` fields let the echo payload move between calls without copying.
    tonic_prost_build::configure()
        .bytes(".")
        .compile_protos(&["bench.proto"], &["."])
}
