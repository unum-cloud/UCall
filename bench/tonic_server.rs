//! tonic on a multi-threaded Tokio runtime serving the echo and sum workloads over gRPC.
//!
//! File: bench/tonic_server.rs
//! Author: Ash Vardanian
//! Date: October 25, 2026

mod arguments;

use tonic::{Request, Response, Status};

include!(concat!(env!("OUT_DIR"), "/ucall.bench.rs"));

struct Service;

#[tonic::async_trait]
impl bench_server::Bench for Service {
    async fn echo(&self, request: Request<Payload>) -> Result<Response<Payload>, Status> {
        Ok(Response::new(request.into_inner()))
    }

    async fn sum(&self, request: Request<Operands>) -> Result<Response<Total>, Status> {
        let Operands { a, b } = request.into_inner();
        a.checked_add(b)
            .map(|sum| Response::new(Total { sum }))
            .ok_or_else(|| Status::invalid_argument("the sum overflows 64 bits"))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = arguments::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(arguments.threads)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], arguments.port));
        println!(
            "Listening on {address} with {} Tokio workers",
            arguments.threads
        );
        tonic::transport::Server::builder()
            .add_service(bench_server::BenchServer::new(Service))
            .serve(address)
            .await?;
        Ok(())
    })
}
