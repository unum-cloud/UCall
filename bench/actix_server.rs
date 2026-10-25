//! actix-web with one worker per thread serving the echo and sum workloads.
//!
//! File: bench/actix_server.rs
//! Author: Ash Vardanian
//! Date: October 25, 2026

mod arguments;

use actix_web::{web, App, HttpResponse, HttpServer};
use serde::Deserialize;

#[derive(Deserialize)]
struct Operands {
    a: i64,
    b: i64,
}

async fn echo(body: web::Bytes) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("application/octet-stream")
        .body(body)
}

async fn sum(operands: web::Query<Operands>) -> HttpResponse {
    match operands.a.checked_add(operands.b) {
        Some(sum) => HttpResponse::Ok()
            .content_type("text/plain")
            .body(sum.to_string()),
        None => HttpResponse::BadRequest().finish(),
    }
}

async fn health() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/plain")
        .body("ready\n")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let arguments = arguments::parse();
    println!(
        "Listening on 127.0.0.1:{} with {} actix workers",
        arguments.port, arguments.threads
    );
    HttpServer::new(|| {
        App::new()
            .route("/echo", web::post().to(echo))
            .route("/sum", web::get().to(sum))
            .route("/health", web::get().to(health))
    })
    .workers(arguments.threads)
    .bind(("127.0.0.1", arguments.port))?
    .run()
    .await
}
