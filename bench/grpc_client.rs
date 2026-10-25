//! A closed-loop gRPC load generator for the echo and sum workloads, the gRPC counterpart of `http.cpp`.
//!
//! Every call is checked: an echo must return its payload, and a sum must return 42.
//!
//! File: bench/grpc_client.rs
//! Author: Ash Vardanian
//! Date: October 25, 2026

use std::time::{Duration, Instant};

use prost::bytes::Bytes;
use tonic::transport::{Channel, Endpoint};

include!(concat!(env!("OUT_DIR"), "/ucall.bench.rs"));

#[derive(Clone, Copy, PartialEq)]
enum Workload {
    Echo,
    Sum,
}

struct Settings {
    address: String,
    workload: Workload,
    bytes: usize,
    connections: usize,
    concurrency: usize,
    threads: usize,
    warmup: Duration,
    time_limit: Duration,
}

/// Reads `ADDRESS` plus `--workload echo|sum`, `--bytes`, `--connections`, `--concurrency`,
/// `--threads`, `--warmup-seconds` and `--time-limit-seconds`.
fn parse() -> Settings {
    let mut settings = Settings {
        address: "127.0.0.1:8545".into(),
        workload: Workload::Echo,
        bytes: 1024,
        connections: 64,
        concurrency: 256,
        threads: 2,
        warmup: Duration::from_secs(1),
        time_limit: Duration::from_secs(8),
    };
    let mut words = std::env::args().skip(1);
    while let Some(word) = words.next() {
        let mut value = || words.next().unwrap_or_default();
        let count = |text: String| text.parse::<usize>().expect("a flag takes a number");
        match word.as_str() {
            "--workload" => {
                settings.workload = match value().as_str() {
                    "echo" => Workload::Echo,
                    "sum" => Workload::Sum,
                    other => panic!("--workload takes echo or sum, not {other}"),
                }
            }
            "--bytes" => settings.bytes = count(value()),
            "--connections" => settings.connections = count(value()).max(1),
            "--concurrency" => settings.concurrency = count(value()).max(1),
            "--threads" => settings.threads = count(value()).max(1),
            "--warmup-seconds" => settings.warmup = Duration::from_secs(count(value()) as u64),
            "--time-limit-seconds" => {
                settings.time_limit = Duration::from_secs(count(value()) as u64)
            }
            address if !address.starts_with("--") => settings.address = address.into(),
            other => panic!("unknown flag {other}"),
        }
    }
    settings
}

/// One call's verdict and duration, or nothing during warmup.
async fn call(
    client: &mut bench_client::BenchClient<Channel>,
    workload: Workload,
    payload: &Bytes,
) -> bool {
    match workload {
        Workload::Echo => client
            .echo(Payload {
                data: payload.clone(),
            })
            .await
            .is_ok_and(|response| response.into_inner().data == *payload),
        Workload::Sum => client
            .sum(Operands { a: 17, b: 25 })
            .await
            .is_ok_and(|response| response.into_inner().sum == 42),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(settings.threads)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let endpoint = Endpoint::from_shared(format!("http://{}", settings.address))?;
        let mut channels = Vec::with_capacity(settings.connections);
        for _ in 0..settings.connections {
            channels.push(endpoint.connect().await?);
        }
        let mut payload = vec![b'x'; settings.bytes];
        if let Some(first) = payload.first_mut() {
            *first = 0;
        }
        let payload = Bytes::from(payload);
        let started = Instant::now();
        let measured_from = started + settings.warmup;
        let finished = measured_from + settings.time_limit;
        let mut tasks = Vec::with_capacity(settings.concurrency);
        for index in 0..settings.concurrency {
            let mut client =
                bench_client::BenchClient::new(channels[index % channels.len()].clone());
            let (workload, payload) = (settings.workload, payload.clone());
            tasks.push(tokio::spawn(async move {
                let (mut latencies, mut failures) = (Vec::<u32>::new(), 0usize);
                loop {
                    let begin = Instant::now();
                    if begin >= finished {
                        break;
                    }
                    let correct = call(&mut client, workload, &payload).await;
                    if begin >= measured_from {
                        latencies.push(begin.elapsed().as_micros().min(u32::MAX as u128) as u32);
                        failures += usize::from(!correct);
                    }
                }
                (latencies, failures)
            }));
        }
        let (mut latencies, mut failures) = (Vec::new(), 0);
        for task in tasks {
            let (task_latencies, task_failures) = task.await?;
            latencies.extend(task_latencies);
            failures += task_failures;
        }
        latencies.sort_unstable();
        let percentile = |fraction: f64| {
            latencies
                .get(
                    ((latencies.len() as f64 * fraction) as usize)
                        .min(latencies.len().saturating_sub(1)),
                )
                .copied()
                .unwrap_or(0)
        };
        println!(
            "Throughput: {:.1} requests/s, p50 {} us, p99 {} us, failed {}",
            latencies.len() as f64 / settings.time_limit.as_secs_f64(),
            percentile(0.50),
            percentile(0.99),
            failures
        );
        Ok(())
    })
}
