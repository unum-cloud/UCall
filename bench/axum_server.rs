//! axum on a multi-threaded Tokio runtime serving the echo and sum workloads.
//!
//! File: bench/axum_server.rs
//! Author: Ash Vardanian
//! Date: October 25, 2026

mod arguments;

use axum::{
    body::Bytes,
    extract::Query,
    http::{header, StatusCode},
    routing::{get, post},
    Router,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Operands {
    a: i64,
    b: i64,
}

async fn echo(body: Bytes) -> ([(header::HeaderName, &'static str); 1], Bytes) {
    ([(header::CONTENT_TYPE, "application/octet-stream")], body)
}

async fn sum(Query(Operands { a, b }): Query<Operands>) -> Result<String, StatusCode> {
    a.checked_add(b)
        .map(|sum| sum.to_string())
        .ok_or(StatusCode::BAD_REQUEST)
}

async fn health() -> &'static str {
    "ready\n"
}

fn main() -> std::io::Result<()> {
    let arguments = arguments::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(arguments.threads)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", arguments.port)).await?;
        println!(
            "Listening on 127.0.0.1:{} with {} Tokio workers",
            arguments.port, arguments.threads
        );
        let router = Router::new()
            .route("/echo", post(echo))
            .route("/sum", get(sum))
            .route("/health", get(health));
        axum::serve(listener, router).await
    })
}
