//! The `--port` and `--threads` arguments every Rust server here shares.
//!
//! File: bench/arguments.rs
//! Author: Ash Vardanian
//! Date: October 25, 2026

/// Listening port and worker thread count, read from the command line.
pub struct Arguments {
    pub port: u16,
    pub threads: usize,
}

/// Reads `--port N` and `--threads N`, defaulting to 8545 and 1.
pub fn parse() -> Arguments {
    let mut arguments = Arguments {
        port: 8545,
        threads: 1,
    };
    let mut words = std::env::args().skip(1);
    while let Some(flag) = words.next() {
        let value = words.next().unwrap_or_default();
        match flag.as_str() {
            "--port" => arguments.port = value.parse().expect("--port takes a number"),
            "--threads" => arguments.threads = value.parse().expect("--threads takes a number"),
            _ => panic!("unknown flag {flag}; use --port N and --threads N"),
        }
    }
    arguments
}
