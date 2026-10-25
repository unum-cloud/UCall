//! UCall's Rust bindings serving the echo and sum workloads, one polling thread per event loop.
//!
//! File: bench/ucall_server.rs
//! Author: Ash Vardanian
//! Date: October 25, 2026

mod arguments;

use ucall::{BytesView, HTTPStatus, Interface, Request, Server};

fn query_integer(request: &Request, name: &str) -> Option<i64> {
    std::str::from_utf8(request.query(name)?).ok()?.parse().ok()
}

fn main() -> ucall::Result<()> {
    let arguments = arguments::parse();
    let interface =
        Interface::new(format!("127.0.0.1:{}", arguments.port)).event_loops(arguments.threads);
    let mut server = Server::new(&[interface])?;
    server.post("/echo", |request: Request| {
        // A reply consumes its request, so the body is copied out first.
        let body = request.body().to_vec();
        let headers = [BytesView::from("content-type: application/octet-stream")];
        let _ = request.reply(HTTPStatus::OK, &headers, &body);
    })?;
    server.get("/sum", |request: Request| {
        let a = query_integer(&request, "a");
        let b = query_integer(&request, "b");
        let _ = match a.zip(b).and_then(|(a, b)| a.checked_add(b)) {
            Some(sum) => {
                let headers = [BytesView::from("content-type: text/plain")];
                request.reply(HTTPStatus::OK, &headers, sum.to_string().as_bytes())
            }
            None => request.reply_error(HTTPStatus::BAD_REQUEST, "Expected integers a and b\n"),
        };
    })?;
    server.get("/health", |request: Request| {
        let headers = [BytesView::from("content-type: text/plain")];
        let _ = request.reply(HTTPStatus::OK, &headers, b"ready\n");
    })?;
    println!(
        "Listening on 127.0.0.1:{} with {} event loops",
        arguments.port,
        server.event_loops()
    );
    std::thread::scope(|scope| {
        for event_loop in 0..server.event_loops() {
            let server = &server;
            scope.spawn(move || server.take_calls(event_loop));
        }
    });
    Ok(())
}
