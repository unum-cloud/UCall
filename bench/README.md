# Benchmarking UCall

These benchmarks pressure the networking stack itself with two workloads whose handlers do no work of their own.
Application workloads, like the batched inference service and its Python twins, live with the inference example in `examples/inference`.

Every backend answers both from its own server in this folder, and each one takes `--port`, 8545 by default, and `--threads`, 1 by default:

- `POST /echo` returns the request body unchanged as `application/octet-stream`, exercising the raw byte path.
- `GET /sum?a=17&b=25` returns the decimal sum as `text/plain`, exercising query parsing and typed parameters.
- `GET /health` answers `ready\n`.

| Server              | Framework                | Typed sum parameters                     |
| :------------------ | :----------------------- | :--------------------------------------- |
| `ucall_server.cpp`  | UCall native             | `ucall_server_request_query_parameter()` |
| `ucall_server.rs`   | UCall Rust bindings      | `Request::query`                         |
| `ucall_server.py`   | UCall Python bindings    | `def sum(a: int, b: int)`                |
| `axum_server.rs`    | axum on Tokio            | the `Query` extractor                    |
| `actix_server.rs`   | actix-web                | `web::Query`                             |
| `fastapi_server.py` | FastAPI on Uvicorn       | typed query parameters                   |
| `grpc_server.py`    | Python asynchronous gRPC | the `Sum` RPC of `bench.proto`           |
| `tonic_server.rs`   | tonic on Tokio           | the `Sum` RPC of `bench.proto`           |

The native server builds as `ucall_bench_server` and accepts every flag of the native examples, listed under [Server Counters](#server-counters).
The UCall Python bindings bind the typed `a` and `b` in C, before the handler runs.
The Rust servers share `arguments.rs`, the Python ones `arguments.py`, and nothing else; `build.rs` generates the tonic service from `bench.proto`.

`ucall_bench_http` drives the public C interface against a separately running HTTP service.
It owns a fixed ForkUnion worker pool, and `--threads` counts every polling thread, including the calling one.
Each active worker polls its own client over its share of the connections, calls in flight and requests.
The library creates no threads; each client drives many sockets and releases each response after verifying it.
`http.lua` is the matching [wrk](https://github.com/wg/wrk) script, `grpc_client.rs` the matching gRPC load generator on tonic, and `grpc_client.py` a gRPC client that checks replies.

## Setup

Build the native targets and the Rust servers, then install the Python ones into an activated virtual environment:

```sh
cmake -S . -B build_release -DCMAKE_BUILD_TYPE=Release -DUCALL_BUILD_BENCH=ON -DUCALL_BUILD_TOOLS=ON
cmake --build build_release --target ucall_bench_http ucall_bench_server
cargo build --release --manifest-path bench/Cargo.toml
uv venv .venv && source .venv/bin/activate
uv pip install . fastapi 'uvicorn[standard]' grpcio grpcio-tools
```

The gRPC modules generate into `build_proto/`, which Git ignores, following the [gRPC Python toolchain](https://grpc.io/docs/languages/python/quickstart/):

```sh
mkdir -p build_proto
python -m grpc_tools.protoc -Ibench --python_out=build_proto --grpc_python_out=build_proto bench/bench.proto
```

Start a server, then run the driver in another terminal:

```sh
build_release/ucall_bench_server --threads 1 --port 8545
build_release/ucall_bench_http --url http://127.0.0.1:8545/echo --bytes 1024 --verify-echo \
    --threads 2 --connections 64 --in-flight 256 --warmup 1s --time-limit 8s
```

Every result below comes from one Intel Core i9-13950HX with Linux 7.3, GCC 16.2, Rust 1.99, Python 3.14, Release builds, and loopback networking.
The server and the driver run on disjoint cores: the server on the even P-core CPUs 0 and 2, or 0 through 8 for wider runs, and the driver on CPUs 8 and 10 for one-thread runs or on the E-cores 16 through 31 for wider ones.
The CPU governor is powersave.
The machine is a shared desktop with other workloads running, and every point waited for a one-minute load average below 4 before starting, so treat the numbers as indicative.
The baselines are FastAPI 0.162 on Uvicorn 0.54 with uvloop 0.23 and httptools 0.9, grpcio 1.84, axum 0.8.9, actix-web 4.18.1 and tonic 0.14.6 on Tokio 1.54, wrk 4.1, and nginx 1.30.

## Framework Comparison

How many requests per second does each framework serve from the same cores?
Start one server at a time on the server cores:

```sh
taskset -c 0,2 build_release/ucall_bench_server --threads 1 --connections 4096
taskset -c 0,2 bench/target/release/ucall_server --threads 1
taskset -c 0,2 bench/target/release/axum_server --threads 1
taskset -c 0,2 bench/target/release/actix_server --threads 1
taskset -c 0,2 bench/target/release/tonic_server --threads 1
taskset -c 0,2 python bench/ucall_server.py --threads 1
taskset -c 0,2 python bench/fastapi_server.py --threads 1
PYTHONPATH=build_proto taskset -c 0,2,4 python bench/grpc_server.py --threads 1
```

The Python servers stop on `SIGINT`.
The Rust servers keep the default signal actions, so Ctrl+C stops them in a terminal, and scripts that start them in the background stop them with `SIGTERM`.
FastAPI runs on uvloop and httptools without access logs, and its `--threads` counts Uvicorn worker processes.
The gRPC server's `--threads` counts processes too, which share the port through `SO_REUSEPORT`.
For four server threads, pin the server to `0,2,4,6,8` with `--threads 4`, and the driver to `16-31` with `--threads 8 --connections 256 --in-flight 1024`.
The native driver speaks no gRPC, so `grpc_client.rs` drives both gRPC servers, closed-loop at 256 concurrent calls over 64 connections per server thread, verifying every reply.
[ghz](https://ghz.sh/docs/options) saturates its own cores before tonic does, so it stays an independent cross-check rather than the measuring driver.

### Echo

How many 1 KiB echoes per second does each framework serve?
The body is a leading zero byte followed by `x` bytes, and every framework returns it unchanged:

```sh
taskset -c 8,10 build_release/ucall_bench_http --url http://127.0.0.1:8545/echo --bytes 1024 --verify-echo \
    --threads 2 --connections 64 --in-flight 256 --warmup 1s --time-limit 8s --format json
```

The gRPC server carries the same bytes in `ucall.bench.Payload.data`:

```sh
PYTHONPATH=build_proto python - <<'PY'
from pathlib import Path
import bench_pb2
Path('build_proto/payload.pb').write_bytes(bench_pb2.Payload(data=b'\0' + b'x' * 1023).SerializeToString())
PY
taskset -c 16-31 bench/target/release/grpc_client 127.0.0.1:8545 --workload echo --bytes 1024 \
    --threads 8 --connections 64 --concurrency 256 --warmup-seconds 1 --time-limit-seconds 8
PYTHONPATH=build_proto python bench/grpc_client.py 127.0.0.1:8545 --workload echo \
    --requests 100000 --warmup-requests 10000 --connections 64 --concurrency 256 --bytes 1024
taskset -c 16-31 ghz --insecure --proto bench/bench.proto --call ucall.bench.Bench.Echo \
    --binary-file build_proto/payload.pb --connections 64 --concurrency 256 \
    --total 90000 --skipFirst 10000 127.0.0.1:8545
```

One server thread, with every exchange verified and none failed:

| Framework    | Requests/s | p50, µs | p99, µs |
| :----------- | ---------: | ------: | ------: |
| UCall native |    291,060 |     852 |   3,408 |
| UCall Rust   |    278,201 |     852 |   3,801 |
| UCall Python |    267,955 |     885 |   3,801 |
| axum         |    226,963 |   1,180 |   1,245 |
| actix-web    |    247,217 |   1,049 |   2,884 |
| FastAPI      |     20,816 |  12,583 |  13,107 |
| gRPC Python  |     14,785 |  17,150 |  24,801 |
| gRPC Rust    |     82,657 |   3,593 |   5,116 |

The gRPC rows come from `grpc_client.rs`, a different driver, over HTTP/2 with protobuf framing; every measured reply matched.
Four server threads, for the frameworks that scale across threads:

| Framework    | Requests/s | p50, µs | p99, µs |
| :----------- | ---------: | ------: | ------: |
| UCall native |    873,040 |   1,180 |   1,442 |
| UCall Rust   |    792,292 |   1,311 |   1,638 |
| axum         |    621,157 |   1,638 |   2,228 |
| actix-web    |    825,820 |   1,245 |   1,638 |
| gRPC Rust    |    187,511 |   5,092 |  13,469 |

UCall's Python bindings stay within 8% of the native server, because the handler runs on the polling thread with no event loop or coroutine in between.
FastAPI and Python gRPC serve about 13 and 18 times fewer echoes than those bindings on the same core, and tonic about 3.2 times fewer.

### Sum

How many typed calls per second does each framework parse, add and answer?
Every request is `GET /sum?a=17&b=25` without a body, and every reply is the 2-byte `42`:

```sh
taskset -c 8,10 build_release/ucall_bench_http --verb get --bytes 0 --url 'http://127.0.0.1:8545/sum?a=17&b=25' \
    --response-bytes 2 --threads 2 --connections 64 --in-flight 256 --warmup 1s --time-limit 8s --format json
```

The gRPC server answers `ucall.bench.Bench.Sum` with a `Total` message:

```sh
taskset -c 16-31 bench/target/release/grpc_client 127.0.0.1:8545 --workload sum \
    --threads 8 --connections 64 --concurrency 256 --warmup-seconds 1 --time-limit-seconds 8
PYTHONPATH=build_proto python bench/grpc_client.py 127.0.0.1:8545 --workload sum \
    --requests 100000 --warmup-requests 10000 --connections 64 --concurrency 256
taskset -c 16-31 ghz --insecure --proto bench/bench.proto --call ucall.bench.Bench.Sum \
    --data '{"a": 17, "b": 25}' --connections 64 --concurrency 256 \
    --total 90000 --skipFirst 10000 127.0.0.1:8545
```

One server thread:

| Framework    | Requests/s | p50, µs | p99, µs |
| :----------- | ---------: | ------: | ------: |
| UCall native |    439,711 |     590 |     721 |
| UCall Rust   |    403,497 |     655 |     852 |
| UCall Python |    366,810 |     688 |   3,146 |
| axum         |    265,476 |     950 |   1,966 |
| actix-web    |    280,936 |     885 |   1,049 |
| FastAPI      |     13,880 |  18,874 |  20,972 |
| gRPC Python  |     15,040 |  16,833 |  22,078 |
| gRPC Rust    |    107,940 |   2,714 |   3,788 |

Four server threads:

| Framework    | Requests/s | p50, µs | p99, µs |
| :----------- | ---------: | ------: | ------: |
| UCall native |  1,015,842 |   1,016 |   1,311 |
| UCall Rust   |  1,198,058 |     852 |     983 |
| axum         |    726,956 |   1,442 |   1,835 |
| actix-web    |    936,873 |   1,114 |   1,180 |
| gRPC Rust    |    217,100 |   4,396 |  11,752 |

UCall's Python bindings parse and convert both parameters in C before calling the handler, and serve 83% of the native rate and about 26 times FastAPI's.

## Pipelining Depth

How much does pipelining raise the throughput of a few connections, and what does it cost in latency?
The server's `--pipelined-requests` must be at least the driver's `--pipeline-depth`, or the server reads a connection's later requests only as earlier ones finish.
The driver sends PUT, because a client never pipelines behind a POST, which RFC 9112 §9.3.2 forbids replaying.
Restart the server for every point, so its counters cover that point alone:

```sh
for connections in 1 4 64; do
    for depth in 1 4 16 64; do
        taskset -c 0,2,4 build_release/ucall_bench_server --threads 1 --connections 4096 \
            --pipelined-requests $depth --stats json &
        server=$!
        sleep 1
        taskset -c 8 build_release/ucall_bench_http --url http://127.0.0.1:8545/echo --verb put --bytes 1024 --verify-echo \
            --threads 1 --connections $connections --in-flight $((connections * depth)) --pipeline-depth $depth \
            --warmup 1s --time-limit 8s --format json
        kill -INT $server && wait $server
    done
done
```

| Connections | Depth | Requests/s | p50, µs | p99, µs | Server CPU, µs/request |
| ----------: | ----: | ---------: | ------: | ------: | ---------------------: |
|           1 |     1 |    122,282 |       8 |      12 |                    5.1 |
|           1 |     4 |    277,003 |      14 |      23 |                    4.4 |
|           1 |    16 |    307,483 |      53 |      74 |                    4.1 |
|           1 |    64 |    321,304 |     205 |     238 |                    3.9 |
|           4 |     1 |    291,754 |      14 |      18 |                    4.1 |
|           4 |     4 |    339,806 |      47 |      74 |                    3.7 |
|           4 |    16 |    341,152 |     188 |     229 |                    3.7 |
|           4 |    64 |    348,120 |     754 |     819 |                    3.6 |
|          64 |     1 |    337,935 |     180 |     246 |                    3.4 |
|          64 |     4 |    378,116 |     688 |     819 |                    3.3 |
|          64 |    16 |    361,575 |   2,884 |   3,146 |                    3.4 |
|          64 |    64 |    369,662 |  11,534 |  12,583 |                    3.4 |

A depth of 4 lets one connection carry 2.3 times the requests of a depth of 1, while deeper pipelines mostly add latency.
The client composes every call a connection may still carry into one send, and dials another connection only while an origin waits for more calls than its open ones have room for.

## Noise Cost

What does Noise encryption cost per request and per connection?
Generate the keys once, then start the server under each pattern in turn; it prints its public key at startup:

```sh
CLIENT_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
SERVER_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
taskset -c 0,2,4 build_release/ucall_bench_server --threads 1 --connections 4096 --stats json
taskset -c 0,2,4 build_release/ucall_bench_server --threads 1 --connections 4096 --security xx --key $SERVER_KEY \
    --stats json
taskset -c 0,2,4 build_release/ucall_bench_server --threads 1 --connections 4096 --security ik --key $SERVER_KEY \
    --stats json
```

```sh
for bytes in 1024 65536; do
    taskset -c 8,10,12,14 build_release/ucall_bench_http --url http://127.0.0.1:8545/echo \
        --bytes $bytes --verify-echo --threads 2 --connections 64 --in-flight 256 \
        --warmup 1s --time-limit 8s --format json
    taskset -c 8,10,12,14 build_release/ucall_bench_http --url http+noise://127.0.0.1:8545/echo \
        --client-key $CLIENT_KEY --bytes $bytes --verify-echo --threads 2 --connections 64 --in-flight 256 \
        --warmup 1s --time-limit 8s --format json
done
```

Add `--server-key` with the printed public key against the IK server, and `--close` to open a new connection for every request.
`UCALL_BENCH_CLIENT_KEY` and `UCALL_BENCH_SERVER_KEY` keep the keys out of the command line.

| Payload | Security  | Connections | Requests/s | p50, µs | p99, µs | Server CPU, µs/request |
| :------ | :-------- | :---------- | ---------: | ------: | ------: | ---------------------: |
| 1 KiB   | Plaintext | Kept alive  |    366,722 |     688 |   1,049 |                    2.7 |
| 1 KiB   | Plaintext | Closed      |     46,406 |   3,801 |  22,020 |                   14.2 |
| 1 KiB   | Noise XX  | Kept alive  |    290,926 |     885 |   1,114 |                    3.5 |
| 1 KiB   | Noise XX  | Closed      |      4,062 |  65,012 |  67,109 |                  247.7 |
| 1 KiB   | Noise IK  | Kept alive  |    292,451 |     885 |   1,114 |                    3.4 |
| 1 KiB   | Noise IK  | Closed      |      3,396 |  75,497 |  83,886 |                  295.9 |
| 64 KiB  | Plaintext | Kept alive  |     24,884 |  10,486 |  12,059 |                   40.4 |
| 64 KiB  | Plaintext | Closed      |     16,886 |  14,680 |  30,409 |                   55.8 |
| 64 KiB  | Noise XX  | Kept alive  |     11,014 |  23,069 |  30,409 |                   91.1 |
| 64 KiB  | Noise XX  | Closed      |      3,021 |  88,080 |  88,080 |                  332.7 |
| 64 KiB  | Noise IK  | Kept alive  |     12,626 |  20,972 |  23,069 |                   79.6 |
| 64 KiB  | Noise IK  | Closed      |      2,544 | 100,663 | 130,023 |                  393.3 |

On kept-alive connections Noise costs 21% of the 1 KiB throughput and about half of the 64 KiB throughput.
A handshake per request costs about 235 µs of server CPU for XX and 280 µs for IK, which dominates every closed row.

The baseline is TLS 1.3 terminated by nginx in front of the same plaintext server, which is how deployments behind a proxy run.
The native driver speaks no TLS, so [wrk](https://github.com/wg/wrk) drives all three paths closed-loop with the byte-verifying [bench/http.lua](http.lua).
nginx runs one worker on CPU 6 with a self-signed P-256 certificate, and this configuration, its paths shortened:

```nginx
worker_processes 1;
worker_cpu_affinity 0000000001000000;
events { worker_connections 4096; }
http {
    access_log off;
    client_body_buffer_size 128k;
    proxy_buffers 8 64k;
    upstream ucall { server 127.0.0.1:8545; keepalive 64; }
    server {
        listen 127.0.0.1:8080;
        location / { proxy_pass http://ucall; proxy_http_version 1.1; proxy_set_header Connection ""; }
    }
    server {
        listen 127.0.0.1:8443 ssl;
        ssl_certificate cert.pem;
        ssl_certificate_key key.pem;
        ssl_protocols TLSv1.3;
        location / { proxy_pass http://ucall; proxy_http_version 1.1; proxy_set_header Connection ""; }
    }
}
```

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout key.pem -out cert.pem \
    -days 2 -subj /CN=127.0.0.1
for url in http://127.0.0.1:8545/echo http://127.0.0.1:8080/echo https://127.0.0.1:8443/echo; do
    taskset -c 8,10 wrk -t2 -c64 -d8s --latency -s bench/http.lua $url -- 1024
done
```

| Payload | Path                  | Requests/s | p50, µs | p99, µs |
| :------ | :-------------------- | ---------: | ------: | ------: |
| 1 KiB   | UCall directly        |    360,735 |     161 |   1,700 |
| 1 KiB   | nginx plaintext proxy |    141,445 |     443 |     534 |
| 1 KiB   | nginx TLS 1.3 proxy   |    105,547 |     564 |   1,160 |
| 64 KiB  | UCall directly        |     24,904 |   2,440 |   3,800 |
| 64 KiB  | nginx plaintext proxy |     22,900 |   2,660 |   3,920 |
| 64 KiB  | nginx TLS 1.3 proxy   |     16,443 |   4,150 |   5,850 |

The proxy hop alone costs 61% of the 1 KiB throughput, and TLS 1.3 then takes another 25% of what remains.
wrk and the native driver differ, so compare rows within each table.

## Loop Scaling

Does one server scale across event loops and cores?
The server's loops take one even P-core CPU each, and the driver's 8 threads take the E-cores:

```sh
for loops in 1 2 4 8; do
    taskset -c $(seq -s, 0 2 $((loops < 8 ? 2 * loops : 14))) build_release/ucall_bench_server \
        --threads $loops --connections 4096 --stats json &
    server=$!
    sleep 1
    taskset -c 16-31 build_release/ucall_bench_http --url http://127.0.0.1:8545/echo --bytes 1024 --verify-echo \
        --threads 8 --connections $((64 * loops)) --in-flight $((256 * loops)) \
        --warmup 1s --time-limit 8s --format json
    kill -INT $server && wait $server
done
```

| Event loops | Requests/s | Requests/s per loop | p50, µs | p99, µs | Server CPU, µs/request |
| ----------: | ---------: | ------------------: | ------: | ------: | ---------------------: |
|           1 |    302,841 |             302,841 |     852 |   1,180 |                    3.4 |
|           2 |    571,008 |             285,504 |     885 |   1,245 |                    3.5 |
|           4 |    966,160 |             241,540 |   1,114 |   1,311 |                    4.1 |
|           8 |    858,922 |             107,365 |   2,490 |   2,621 |                    5.7 |

Two loops reach 1.9 times one loop and four reach 3.2 times.
At 8 loops the server fills all eight P-cores and serves less than at four, and this run does not separate the server's limit from the driver's.

## Connection Scale

Do admission, memory and tail latency hold at 10,000 connections?
Both runs offer a fixed 20,000 requests/s, so each of the 10,000 connections idles most of the time.
The server's budget is the driver's connections plus 1,024, and its resident memory is read before the driver starts and again under load:

```sh
ulimit -n 65536
taskset -c 0,2,4,6,8 build_release/ucall_bench_server --threads 4 --connections 11024 --stats json &
grep VmRSS /proc/$!/status
taskset -c 16-31 build_release/ucall_bench_http --url http://127.0.0.1:8545/echo --bytes 1024 --verify-echo \
    --threads 4 --connections 10000 --in-flight 10000 --rate 20000 --warmup 2s --time-limit 10s --format json
```

| Connections | Budget | Requests/s | p50, µs | p99, µs | Server CPU, µs/request | Resident at startup | Resident under load |
| ----------: | -----: | ---------: | ------: | ------: | ---------------------: | ------------------: | ------------------: |
|          64 |  1,088 |     20,000 |      98 |     139 |                   14.6 |          25,596 KiB |          25,720 KiB |
|      10,000 | 11,024 |     20,000 |     172 |   1,016 |                   10.2 |         171,256 KiB |         171,496 KiB |

The server preallocates about 15 KiB per budgeted connection, 145,660 KiB across the 9,936 extra connections, and grows by under 250 KiB under load.
To repeat the runs across a real NIC, start the server with `--host 0.0.0.0` and point the driver at its address.

## Driver Flags

`--requests`, `--time-limit`, or both bound the measured phase, which stops issuing at whichever comes first and then drains its outstanding calls.
`--warmup-requests` and `--warmup` bound the unmeasured phase the same way, and it finishes before the measured phase begins.
Durations read like `500ms`, `10s` or `250us`.
Each worker records latencies into its own histogram of 16 linear bins per power of two nanoseconds, merged after timing ends, so a percentile reads at most 1/16 high and recording a completion neither allocates nor sorts.
The report prints the mean, p50, p90, p99, p99.9, p99.99, and maximum in microseconds.
The driver timestamps each batch immediately after its polling call returns.
Latency includes submission, queueing, transport progress, and completion observation by that worker; it is not a kernel completion timestamp.
Throughput covers the measured ForkUnion dispatch through response verification, release, and completion of every worker.
The total row's `driver_cpu_us_per_request` divides the driver's user and system time over the measured phase by its successful requests.
Its `driver_busy_fraction` divides the same time by the elapsed time of every client, so a fraction near 1 means the driver, not the server, bounded the run.
Rejected submissions, failed exchanges, and incorrect echo bytes are counted and produce a nonzero exit status.

`--backend` and `--cpu-class` select the implementation and kernel bundle, and the report prints each active worker's resolved choices.
Explicit unsupported selections fail instead of silently changing the experiment.
`--help` lists every flag; each one also reads its default from a `UCALL_BENCH_` variable named after it, so `UCALL_BENCH_TIME_LIMIT=10s` stands in for `--time-limit 10s` and the command line overrides it.
`--pin` lets the ForkUnion pool pin each worker to its own core where the operating system allows, and the report says whether it did.
`--seed` fixes the request body bytes, drawn from SplitMix64.
`--format json` prints one JSON object per row instead: the configuration, the total, each origin, and each worker.
For the key-value example, seed a value first and use its URL with `--verb get --bytes 0`, omitting `--verify-echo`.
`--response-bytes N` checks only each response body's length, for services whose replies are not echoes, like the 2-byte sum.
`http+noise://` URLs need `--client-key`, the client's 64-digit hexadecimal static private key, and run Noise XX, admitting whatever key the server shows.
Adding `--server-key`, the server's public key in the same spelling, switches them to Noise IK.

`--close` requests connection closure after every response, measuring connection churn separately from keep-alive reuse.
`--pipeline-depth N` lets each connection carry up to `N` calls before their responses arrive, through the client's `max_pipelined_calls`; the default of 1 waits a round trip per call.
Only idempotent calls pipeline: a POST, or a call whose headers close the connection, waits for every call ahead of it.
The server answers pipelined requests in order at any depth, and its interface's `max_pipelined_requests` decides how many of them it dispatches at once.

## Open-Loop Load

By default each in-flight slot sends its next call as soon as the previous one completes, a closed loop that slows down with the server and hides queueing delay.
`--rate N` instead follows one fixed arrival schedule of `N` requests per second, interleaved across workers, so each worker issues at its share of it.
Latency is then measured from each call's __intended__ send time, so a call delayed by a busy slot or a slow server carries that delay, and coordinated omission stays visible in the tail.
A worker without an idle slot keeps its due arrivals queued, and sleeps when it has nothing in flight and the next arrival is in the future.

```sh
build_release/ucall_bench_http --url http://127.0.0.1:8545/echo --bytes 1024 --verify-echo \
    --threads 2 --connections 64 --in-flight 256 --rate 100000 --warmup 1s --time-limit 10s
```

## Server Counters

The driver reads no counters from the server, so it prints where they come from instead.
The native server and every native example print their counters when stopped with `SIGINT` or `SIGTERM`: one line per event loop from `ucall_server_event_loop_statistics()` and one per batch endpoint from `ucall_server_batch_endpoint_statistics()`:

```text
Event loop 0: 41068 polls, 0 empty polls, 41065 kernel enters, 40242 submissions, 80241 completions, 1 cancellations, 79 accepts, 40000 requests, 0 receive re-arms, 44440000 bytes received, 45640000 bytes sent, 85400000 bytes copied, 79 zero-copy sends, 79 zero-copy fallbacks, 39921 copying sends, 0 asynchronous file reads, 0 blocking file reads, 0 bytes read, 0 file window overlaps, 0 linger resets, 120000 ready passes, 40000 replied dequeues, 0 refused requests, 0 handshake failures, 0 authorizer refusals
Batch endpoint 0: 525 batches, 16805 requests, 1 filled, 524 ready, 0 expired
Process CPU: 1.284000 s
```

`--stats json` prints the same counters as one JSON object instead, with `event_loops` and `batch_endpoints` arrays in loop and registration order and the process's `cpu_seconds` last.
At startup the server also prints whether ForkUnion pinned its serving loops to cores, as `Serving loops pinned` or `Serving loops floating`.
A batch endpoint counts its callbacks and the requests they carried, and why each fired: __filled__ on reaching `--batch-max`, __ready__ on reaching `--batch-min` below it, and __expired__ below `--batch-min` once `--batch-latency-us` passed.

The counters cover the server's whole life, warmup included, so divide them by its own `requests` rather than by the driver's measured count:

- __Submissions per request__ counts the operations queued to the kernel for one exchange: io_uring entries, or the requests a readiness backend accepted.
- __Completions per request__ counts the results taken back, so a keep-alive echo on io_uring 7.0 with an armed multishot receive approaches one send submission and two completions.
- __Kernel enters per request__ counts system calls: io_uring enters, or the receives, sends, registrations, and waits of the readiness backends.
- __Empty polls per poll__ shows how often a loop woke without work.
- __Receive re-arms per request__ shows how often io_uring 7.0 had to restart a multishot receive.
- __Bytes copied per request__, compared with the request and response body bytes, shows how many times UCall itself copied each payload byte: receive-buffer appends, reply bodies, Noise records, and parked receives, never the kernel's own copies.
- __Zero-copy and copying sends__ add up to every send: a socket the kernel reported copying sends by copying for the rest of its life, and `zero_copy_fallbacks` counts only the kernel's own reports, so on loopback it stops at about one per connection.
- __File reads per request__ splits a file reply's reads into `file_reads_asynchronous`, which the kernel finished later, and `file_reads_blocking`, which the loop waited on itself, while `bytes_read` counts what they read and `file_window_overlaps` the reads that ran while an earlier window of the stream still sent.
- __Linger resets__ counts closes that reached their linger deadline with the kernel still holding sent bytes, and reset the peer so the kernel released them.
- __Ready passes per request__ counts how often the loop advanced a ready connection for one exchange, and __replied dequeues per request__ how often it took an exchange from its replied queue.
- __Requests per batch__ divides a batch endpoint's `requests` by its `batches`, and its three triggers split those batches by cause.
- __Server CPU per request__ divides the server's `cpu_seconds`, its user and system time since its loops started, by the loops' summed `requests`; `wall_seconds` beside it is the time they served.

The native server and every native example share these flags:

- `--host IP` and `--port N`: the listening address, `127.0.0.1:8545` by default; `0.0.0.0` or `::` accept every NIC.
- `--threads N`: event loops, each polled by its own ForkUnion thread; every registered batch endpoint gets one more thread to drain it.
- `--connections N` and `--pipelined-requests N`: the interface's admission budget and its `max_pipelined_requests`.
- `--security none|xx|ik` and `--key HEX`: Noise on the interface, with the 64-digit server private key; without `--key` the server generates one, and either way it prints its public key at startup.
  XX admits every client key.
- `--batch-min N`, `--batch-max N` and `--batch-latency-us N`: the budgets every batch endpoint of an example registers with.
- `--stats human|json`: the format of the counters printed at exit.
- `--reply-directory PATH`: the directory path parts of replies open files beneath, on a filesystem that takes `O_DIRECT` reads; the native server answers `GET /file/{name}` with the file `name` beneath it.

## Multiple Targets

Repeat `--url` to exercise several logical targets through each active client's connection and call budgets.
Measured and warmup requests are split as evenly as possible across targets and active clients, with a fixed in-flight reservation for each target.
A slow target therefore retains its own outstanding work while the client can continue polling the others.
The report includes per-target issued, completed, successful, failed, and rejected calls, byte checks, response bytes, mean and maximum latency, and first and last completion offsets.

Start two `ucall_bench_server` processes, one with `--port 8545` and one with `--port 8546`, then run:

```sh
build_release/ucall_bench_http \
    --url http://127.0.0.1:8545/echo --url http://127.0.0.1:8546/echo --bytes 1024 --verify-echo \
    --threads 2 --connections 64 --in-flight 256 --requests 100000 --warmup-requests 10000
```

## Retained Replies

For retained replies, use `--reorder` against `ucall_example_echo`, which serves `/echo/reordered`.
The service retains the first tagged request until its partner arrives, then publishes member 1 before member 0, without sleeping or blocking a polling thread.
The driver verifies the echoed body and returned pair and member tags.
It reports observed completion reordering; publication order across sockets does not guarantee TCP arrival or polling order.
This mode requires POST, even measured and warmup counts, and at least two connections and in-flight slots per active target and client.
Each retained member occupies an HTTP/1.1 connection until its partner arrives, so the effective in-flight budget is the smaller of the requested call and connection budgets, rounded to whole pairs.
The report prints that effective capacity; ordinary echo can queue more calls than open connections.
With `--pipeline-depth`, partners may share a connection, so the server must dispatch at least two requests per connection.
The requested ForkUnion worker count remains fixed; workers beyond the available per-target budgets stay idle, and the report shows the active client count.

## Independent Load Generators

Use [wrk2](https://github.com/giltene/wrk2) against any HTTP echo server at the same connection count, byte count, and offered rate.
`bench/http.lua` generates the binary body once per worker and verifies every echoed response.
A 30-second interval covers wrk2's calibration period:

```sh
wrk -t2 -c64 -d30s -R10000 --latency -s bench/http.lua http://127.0.0.1:8545/echo -- 1024
```

The application work matches across drivers, while the wire protocols differ: native HTTP and FastAPI carry an HTTP/1.1 body, and gRPC adds protobuf serialization, gRPC framing, and HTTP/2 multiplexing.
A gRPC connection multiplexes concurrent streams, while a native HTTP/1.1 connection pipelines up to `--pipeline-depth` calls and receives their responses in order.
wrk, ghz, both gRPC clients and the native driver without `--rate` are closed-loop drivers; wrk2 and the native driver with `--rate` schedule an offered rate and charge delayed sends to latency.
Report those load models separately, and inspect saturation and errors before reading their percentiles together.
The Lua driver and `grpc_client.rs` verify response bytes; ghz reports RPC status and decoding only.
