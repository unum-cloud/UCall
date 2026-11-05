# Benchmarking UCall

These benchmarks pressure the networking stack itself with two workloads whose handlers do no work of their own.
Application workloads, like the batched inference service, live with the inference example in `examples/inference`, and its FastAPI and LitServe baselines run under [Inference](#inference).

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
`http.lua` is the matching [wrk](https://github.com/wg/wrk) script, and `grpc_client.rs` the matching gRPC load generator on tonic.

## Setup

Build the native targets and the Rust servers, then install the Python ones into an activated virtual environment:

```sh
cmake -S . -B build_release -DCMAKE_BUILD_TYPE=Release -DUCALL_BUILD_BENCH=ON -DUCALL_BUILD_EXAMPLES=ON
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

Every row names its machine, the server's CPU class, and the date it was measured, on Release builds over loopback networking.
The Intel Core i9-13950HX rows ran Linux 7.3, GCC 16.2, Rust 1.99 and Python 3.14 with the powersave governor on a shared desktop, every point waiting for a one-minute load average below 4, so treat them as indicative; the server took the even P-core CPUs 0 and 2, or 0 through 8 for wider runs, and the driver CPUs 8 and 10, or the E-cores 16 through 31 for wider runs.
The AWS Graviton4 rows ran Linux 7.0, Clang 23.1, Rust 1.99 and Python 3.13 on an otherwise idle box, the server on CPUs 16 and 17, or 16 through 48 for the loop ladder, and the driver on CPUs 48 and 49, or 50 through 95 for the loop ladder, with `--cpu-class apple-m2` on both sides.
That class has since been retired into `aws-g2`, which runs the same kernels apart from the RCpc atomic reference, so the `apple-m2` rows await a re-run under `aws-g2`.
The baselines are FastAPI 0.162 on Uvicorn 0.54 with uvloop 0.23 and httptools 0.9, grpcio 1.84 or 1.85, axum 0.8.9, actix-web 4.18.1 and tonic 0.14 on Tokio 1.54, wrk 4.1, and nginx 1.28 or 1.30.

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
taskset -c 16-31 ghz --insecure --proto bench/bench.proto --call ucall.bench.Bench.Echo \
    --binary-file build_proto/payload.pb --connections 64 --concurrency 256 \
    --total 90000 --skipFirst 10000 127.0.0.1:8545
```

One server thread, with every exchange verified and none failed:

| Machine                                       | Framework    | Requests/s | p50, µs | p99, µs | Date       |
| :-------------------------------------------- | :----------- | ---------: | ------: | ------: | :--------- |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | UCall native |    291,060 |     852 |   3,408 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | UCall Rust   |    278,201 |     852 |   3,801 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | UCall Python |    267,955 |     885 |   3,801 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | axum         |    226,963 |   1,180 |   1,245 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | actix-web    |    247,217 |   1,049 |   2,884 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | FastAPI      |     20,816 |  12,583 |  13,107 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | gRPC Python  |     14,785 |  17,150 |  24,801 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | gRPC Rust    |     82,657 |   3,593 |   5,116 | 2026-10-25 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | UCall native |    198,540 |   1,311 |   1,442 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | UCall Rust   |    190,888 |   1,376 |   1,442 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | UCall Python |    164,662 |   1,573 |   1,769 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | axum         |    150,728 |   1,704 |   1,769 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | actix-web    |    165,570 |   1,573 |   1,573 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | FastAPI      |     16,759 |  15,729 |  15,729 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | gRPC Python  |      9,938 |  25,893 |  26,652 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | gRPC Rust    |     56,360 |   5,680 |   6,017 | 2026-11-02 |

The gRPC rows come from `grpc_client.rs`, a different driver, over HTTP/2 with protobuf framing; every measured reply matched.
Four server threads, for the frameworks that scale across threads:

| Machine                                  | Framework    | Requests/s | p50, µs | p99, µs | Date       |
| :--------------------------------------- | :----------- | ---------: | ------: | ------: | :--------- |
| Intel i9-13950HX, 8P+16E cores, 1 domain | UCall native |    873,040 |   1,180 |   1,442 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain | UCall Rust   |    792,292 |   1,311 |   1,638 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain | axum         |    621,157 |   1,638 |   2,228 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain | actix-web    |    825,820 |   1,245 |   1,638 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain | gRPC Rust    |    187,511 |   5,092 |  13,469 | 2026-10-25 |

UCall's Python bindings stay within 8% of the native server on the Intel machine and 17% on Graviton4, because the handler runs on the polling thread with no event loop or coroutine in between.
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
taskset -c 16-31 ghz --insecure --proto bench/bench.proto --call ucall.bench.Bench.Sum \
    --data '{"a": 17, "b": 25}' --connections 64 --concurrency 256 \
    --total 90000 --skipFirst 10000 127.0.0.1:8545
```

One server thread:

| Machine                                       | Framework    | Requests/s | p50, µs | p99, µs | Date       |
| :-------------------------------------------- | :----------- | ---------: | ------: | ------: | :--------- |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | UCall native |    439,711 |     590 |     721 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | UCall Rust   |    403,497 |     655 |     852 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | UCall Python |    366,810 |     688 |   3,146 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | axum         |    265,476 |     950 |   1,966 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | actix-web    |    280,936 |     885 |   1,049 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | FastAPI      |     13,880 |  18,874 |  20,972 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | gRPC Python  |     15,040 |  16,833 |  22,078 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | gRPC Rust    |    107,940 |   2,714 |   3,788 | 2026-10-25 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | UCall native |    246,738 |   1,049 |   1,180 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | UCall Rust   |    232,030 |   1,114 |   1,180 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | UCall Python |    197,126 |   1,311 |   1,507 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | axum         |    167,745 |   1,573 |   1,573 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | actix-web    |    182,152 |   1,442 |   1,442 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | FastAPI      |     14,831 |  17,826 |  17,826 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | gRPC Python  |     10,142 |  25,340 |  26,053 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | gRPC Rust    |     73,448 |   4,345 |   4,640 | 2026-11-02 |

Four server threads:

| Machine                                  | Framework    | Requests/s | p50, µs | p99, µs | Date       |
| :--------------------------------------- | :----------- | ---------: | ------: | ------: | :--------- |
| Intel i9-13950HX, 8P+16E cores, 1 domain | UCall native |  1,015,842 |   1,016 |   1,311 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain | UCall Rust   |  1,198,058 |     852 |     983 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain | axum         |    726,956 |   1,442 |   1,835 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain | actix-web    |    936,873 |   1,114 |   1,180 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain | gRPC Rust    |    217,100 |   4,396 |  11,752 | 2026-10-25 |

UCall's Python bindings parse and convert both parameters in C before calling the handler, and serve 83% of the native rate and about 26 times FastAPI's.

### Inference

How do Python frameworks serve a compute-heavy application rather than an empty handler?
Three Python services serve the inference example's routes over one NumKong kernel, `examples/inference/model.py`, whose matrix and replies are byte-identical to the native example's for the same seed.

- `examples/inference/server.py` runs on UCall's Python bindings: `/infer` scores on the polling thread, and `/infer/batch` is a batch endpoint polled by its own thread.
- `fastapi_inference.py` runs on FastAPI: `/infer` scores on the event loop, and `/infer/batch` queues requests in an asyncio micro-batcher under the same three budgets, scoring each batch on a worker thread.
- `litserve_inference.py` runs on LitServe, which serves `/infer/batch` alone and batches by `max_batch_size` and `batch_timeout` without a minimum.
  LitServe decodes bodies as JSON, so its middleware first wraps each raw query in a hexadecimal string.

All three take `--rows`, `--dimensions`, `--seed`, `--port`, `--batch-min`, `--batch-max` and `--batch-latency-us`; LitServe ignores `--batch-min`.
The two baselines import the kernel from the example folder:

```sh
uv pip install . numpy numkong fastapi 'uvicorn[standard]' litserve
python examples/inference/server.py --port 8547 \
    --batch-min 8 --batch-max 64 --batch-latency-us 1000
PYTHONPATH=examples/inference python bench/fastapi_inference.py --port 8548 \
    --batch-min 8 --batch-max 64 --batch-latency-us 1000
PYTHONPATH=examples/inference python bench/litserve_inference.py --port 8549 \
    --batch-max 64 --batch-latency-us 1000
```

Drive them with the inference example's commands at ports 8547 through 8549.

## Backend Costs

What does one request cost on each I/O backend, and how do the costs move with connections, body size and pipelining?
One server loop answers 64 or 10,000 connections of 1 KiB or 64 KiB PUT echoes at pipeline depth 1 or 16, each point three times, and the table holds the medians.
The driver takes two threads at 64 connections and four at 10,000:

```sh
for backend in linux-uring612 linux-uring618 linux-epollaio; do
    for connections in 64 10000; do
        for bytes in 1024 65536; do
            for depth in 1 16; do
                taskset -c 16,17 build_release/ucall_bench_server --backend $backend --threads 1 \
                    --connections $((connections + 1024)) --pipelined-requests $depth --stats json &
                server=$!
                sleep 1
                taskset -c 48-51 build_release/ucall_bench_http --url http://127.0.0.1:8545/echo --verb put \
                    --bytes $bytes --verify-echo --backend $backend --threads $((connections > 64 ? 4 : 2)) \
                    --connections $connections --in-flight $((connections * depth)) --pipeline-depth $depth \
                    --warmup 2s --time-limit 8s --format json
                kill -INT $server && wait $server
            done
        done
    done
done
```

Server CPU comes from `perf stat -e task-clock` over the server process, divided by the requests its counters report.
Submissions, completions and kernel enters per request come from the same counters: on io_uring a kernel enter is one `io_uring_enter`, on epoll one `epoll_wait`, and a pass is one walk over the connections the loop found ready.

| Machine                                       | Class      | Backend          | Connections | Body   | Depth | Requests/s |    p50, µs |    p99, µs | Server CPU, µs/request | Submissions/request | Completions/request | Kernel enters/request | Passes/request | Date       |
| :-------------------------------------------- | :--------- | :--------------- | ----------: | :----- | ----: | ---------: | ---------: | ---------: | ---------------------: | ------------------: | ------------------: | --------------------: | -------------: | :--------- |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring618` |          64 | 1 KiB  |     1 |    200,376 |        311 |        426 |                    5.0 |                1.00 |                2.00 |                 0.025 |           2.00 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring618` |          64 | 1 KiB  |    16 |    189,099 |      5,505 |      5,505 |                    5.3 |                1.00 |                1.63 |                 0.016 |           1.88 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring618` |          64 | 64 KiB |     1 |     12,957 |      5,243 |      7,340 |                   77.0 |                1.00 |               18.00 |                 0.038 |          18.00 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring618` |          64 | 64 KiB |    16 |      9,444 |    109,052 |    150,995 |                  106.2 |                1.00 |               17.18 |                 0.017 |          17.56 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring618` |      10,000 | 1 KiB  |     1 |    137,925 |     75,497 |     75,497 |                    7.4 |                1.02 |                2.03 |                 0.028 |           2.02 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring618` |      10,000 | 1 KiB  |    16 |    149,998 |  1,073,742 |  1,140,851 |                    6.8 |                1.13 |                1.52 |                 0.007 |           1.69 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring618` |      10,000 | 64 KiB |     1 |     12,017 |    838,861 |    872,415 |                   87.1 |                3.22 |               20.31 |                 0.095 |          18.29 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring618` |      10,000 | 64 KiB |    16 |      8,084 | 14,495,515 | 21,474,836 |                  119.7 |                2.01 |               18.27 |                 0.035 |          17.84 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring612` |          64 | 1 KiB  |     1 |    200,076 |        328 |        360 |                    5.0 |                2.00 |                2.00 |                 0.031 |           2.00 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring612` |          64 | 1 KiB  |    16 |    194,118 |      5,505 |      5,505 |                    5.1 |                2.00 |                2.00 |                 0.016 |           2.00 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring612` |          64 | 64 KiB |     1 |     12,918 |      4,981 |      5,243 |                   77.4 |               18.00 |               18.00 |                 0.282 |          18.00 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring612` |          64 | 64 KiB |    16 |      8,778 |    117,441 |    121,635 |                  113.7 |               17.21 |               17.22 |                 0.256 |          16.22 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring612` |      10,000 | 1 KiB  |     1 |    115,114 |     75,497 |    100,663 |                    9.4 |                2.03 |                2.13 |                 0.009 |          18.70 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring612` |      10,000 | 1 KiB  |    16 |    111,960 |    973,079 |  9,126,806 |                    9.0 |                1.84 |                2.10 |                 0.013 |           2.08 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring612` |      10,000 | 64 KiB |     1 |      8,921 |    872,415 |  7,516,193 |                  116.2 |               18.29 |               18.45 |                 0.105 |          18.43 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring612` |      10,000 | 64 KiB |    16 |      6,223 | 16,642,998 | 30,064,771 |                  149.5 |               17.46 |               17.70 |                 0.031 |          16.72 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-epollaio` |          64 | 1 KiB  |     1 |    193,593 |        246 |      1,966 |                    5.2 |                2.00 |                2.00 |                 2.161 |           2.00 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-epollaio` |          64 | 1 KiB  |    16 |    190,076 |      5,505 |      5,505 |                    5.8 |                2.05 |                2.05 |                 1.931 |          18.17 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-epollaio` |          64 | 64 KiB |     1 |     13,242 |      4,981 |      6,291 |                   75.6 |               18.00 |               18.00 |                18.974 |          18.00 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-epollaio` |          64 | 64 KiB |    16 |      9,398 |     31,457 |     46,137 |                  106.5 |               17.21 |               17.21 |                17.218 |          16.22 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-epollaio` |      10,000 | 1 KiB  |     1 |    129,068 |     35,127 |     36,438 |                    8.7 |                2.16 |                2.16 |                 2.066 |          17.80 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-epollaio` |      10,000 | 1 KiB  |    16 |    128,874 |  1,275,068 |  1,677,722 |                    8.0 |                2.11 |                2.11 |                 1.892 |           1.88 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-epollaio` |      10,000 | 64 KiB |     1 |      8,855 |  1,275,068 |  2,818,572 |                  119.1 |               18.51 |               18.51 |                19.221 |          18.38 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-epollaio` |      10,000 | 64 KiB |    16 |      6,468 | 14,495,515 | 30,064,771 |                  143.7 |               17.78 |               17.78 |                17.740 |          16.68 | 2026-11-02 |

A 1 KiB echo costs 5 µs of one Graviton core on every backend at 64 connections, 1 submission and 2 completions per request on `linux-uring618` against 2 and 2 on the others, and 0.025 kernel enters per request on the rings against 2 on epoll.
A 64 KiB echo costs 18 completions per request on every backend, one per 4 KiB receive page, which is where its 77 µs go.
At 10,000 connections `linux-uring618` keeps its 2 passes per request and answers 20% more requests per second at 20% less CPU than the other two, which walk 18 passes per request at depth 1.
The 64 KiB rows at 10,000 connections and depth 16 hold 10 GiB in flight and read as queueing, not as cost.

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

| Machine                                       | Class      | Connections | Depth | Requests/s | p50, µs | p99, µs | Server CPU, µs/request | Date       |
| :-------------------------------------------- | :--------- | ----------: | ----: | ---------: | ------: | ------: | ---------------------: | :--------- |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   |           1 |     1 |    122,282 |       8 |      12 |                    5.1 | 2026-10-27 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   |           1 |     4 |    277,003 |      14 |      23 |                    4.4 | 2026-10-27 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   |           1 |    16 |    307,483 |      53 |      74 |                    4.1 | 2026-10-27 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   |           1 |    64 |    321,304 |     205 |     238 |                    3.9 | 2026-10-27 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   |           4 |     1 |    291,754 |      14 |      18 |                    4.1 | 2026-10-27 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   |           4 |     4 |    339,806 |      47 |      74 |                    3.7 | 2026-10-27 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   |           4 |    16 |    341,152 |     188 |     229 |                    3.7 | 2026-10-27 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   |           4 |    64 |    348,120 |     754 |     819 |                    3.6 | 2026-10-27 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   |          64 |     1 |    337,935 |     180 |     246 |                    3.4 | 2026-10-27 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   |          64 |     4 |    378,116 |     688 |     819 |                    3.3 | 2026-10-27 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   |          64 |    16 |    361,575 |   2,884 |   3,146 |                    3.4 | 2026-10-27 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   |          64 |    64 |    369,662 |  11,534 |  12,583 |                    3.4 | 2026-10-27 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |           1 |     1 |     64,598 |      15 |      17 |                    8.1 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |           1 |     4 |    149,076 |      28 |      39 |                    6.4 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |           1 |    16 |    163,436 |      98 |     119 |                    6.1 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |           1 |    64 |    159,097 |     410 |     442 |                    6.3 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |           4 |     1 |    162,359 |      25 |      30 |                    6.0 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |           4 |     4 |    178,458 |      90 |     111 |                    5.6 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |           4 |    16 |    178,362 |     360 |     393 |                    5.6 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |           4 |    64 |    174,921 |   1,507 |   1,507 |                    5.7 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |          64 |     1 |    187,476 |     344 |     442 |                    5.2 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |          64 |     4 |    186,868 |   1,376 |   1,507 |                    5.3 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |          64 |    16 |    184,227 |   5,767 |   5,767 |                    5.4 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |          64 |    64 |    186,530 |  22,020 |  24,117 |                    5.4 | 2026-11-02 |

A depth of 4 lets one connection carry 2.3 times the requests of a depth of 1 on both machines, while deeper pipelines mostly add latency.
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

| Machine                                       | Class      | Payload | Security  | Connections | Requests/s | p50, µs | p99, µs | Server CPU, µs/request | Date       |
| :-------------------------------------------- | :--------- | :------ | :-------- | :---------- | ---------: | ------: | ------: | ---------------------: | :--------- |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 1 KiB   | Plaintext | Kept alive  |    366,722 |     688 |   1,049 |                    2.7 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 1 KiB   | Plaintext | Closed      |     46,406 |   3,801 |  22,020 |                   14.2 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 1 KiB   | Noise XX  | Kept alive  |    290,926 |     885 |   1,114 |                    3.5 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 1 KiB   | Noise XX  | Closed      |      4,062 |  65,012 |  67,109 |                  247.7 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 1 KiB   | Noise IK  | Kept alive  |    292,451 |     885 |   1,114 |                    3.4 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 1 KiB   | Noise IK  | Closed      |      3,396 |  75,497 |  83,886 |                  295.9 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 64 KiB  | Plaintext | Kept alive  |     24,884 |  10,486 |  12,059 |                   40.4 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 64 KiB  | Plaintext | Closed      |     16,886 |  14,680 |  30,409 |                   55.8 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 64 KiB  | Noise XX  | Kept alive  |     11,014 |  23,069 |  30,409 |                   91.1 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 64 KiB  | Noise XX  | Closed      |      3,021 |  88,080 |  88,080 |                  332.7 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 64 KiB  | Noise IK  | Kept alive  |     12,626 |  20,972 |  23,069 |                   79.6 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 64 KiB  | Noise IK  | Closed      |      2,544 | 100,663 | 130,023 |                  393.3 | 2026-10-25 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 1 KiB   | Plaintext | Kept alive  |    194,579 |   1,311 |   1,507 |                    5.1 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 1 KiB   | Plaintext | Closed      |     33,685 |   6,554 |  20,972 |                   20.2 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 64 KiB  | Plaintext | Kept alive  |     12,879 |  20,972 |  23,069 |                   77.6 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 64 KiB  | Plaintext | Closed      |     10,108 |  26,214 |  26,214 |                   98.8 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 1 KiB   | Noise XX  | Kept alive  |    153,654 |   1,638 |   1,901 |                    6.5 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 1 KiB   | Noise XX  | Closed      |      2,855 |  92,275 |  92,275 |                  350.0 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 64 KiB  | Noise XX  | Kept alive  |      7,230 |  35,652 |  39,846 |                  138.4 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 64 KiB  | Noise XX  | Closed      |      2,056 | 125,829 | 130,023 |                  486.4 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 1 KiB   | Noise IK  | Kept alive  |    151,723 |   1,704 |   1,901 |                    6.6 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 1 KiB   | Noise IK  | Closed      |      2,544 | 100,663 | 104,858 |                  392.4 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 64 KiB  | Noise IK  | Kept alive  |      7,317 |  35,652 |  39,846 |                  137.0 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 64 KiB  | Noise IK  | Closed      |      1,885 | 142,606 | 142,606 |                  530.5 | 2026-11-02 |

On kept-alive connections Noise costs 21% of the 1 KiB throughput and about half of the 64 KiB throughput on both machines.
A handshake per request costs about 235 µs of server CPU for XX and 280 µs for IK on the Intel core, and 330 µs and 370 µs on the Graviton core, which dominates every closed row: the three X25519 exchanges of a handshake run the portable constant-time code in `curve25519.hpp`.

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

| Machine                                       | Class      | Payload | Path                  | Requests/s | p50, µs | p99, µs | Date       |
| :-------------------------------------------- | :--------- | :------ | :-------------------- | ---------: | ------: | ------: | :--------- |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 1 KiB   | UCall directly        |    360,735 |     161 |   1,700 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 1 KiB   | nginx plaintext proxy |    141,445 |     443 |     534 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 1 KiB   | nginx TLS 1.3 proxy   |    105,547 |     564 |   1,160 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 64 KiB  | UCall directly        |     24,904 |   2,440 |   3,800 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 64 KiB  | nginx plaintext proxy |     22,900 |   2,660 |   3,920 | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | 64 KiB  | nginx TLS 1.3 proxy   |     16,443 |   4,150 |   5,850 | 2026-10-25 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 1 KiB   | UCall directly        |    192,508 |     313 |     436 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 1 KiB   | nginx plaintext proxy |     79,545 |     799 |     837 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 1 KiB   | nginx TLS 1.3 proxy   |     63,185 |     970 |   1,940 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 64 KiB  | UCall directly        |     12,932 |   5,020 |   8,000 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 64 KiB  | nginx plaintext proxy |     12,756 |   5,050 |   7,170 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | 64 KiB  | nginx TLS 1.3 proxy   |     11,949 |   5,820 |   7,200 | 2026-11-02 |

The proxy hop alone costs about 60% of the 1 KiB throughput, and TLS 1.3 then takes another 20% to 25% of what remains.
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

| Machine                                       | Class      | Event loops | Requests/s | Requests/s per loop | p50, µs | p99, µs | Server CPU, µs/request | Driver busy | Date       |
| :-------------------------------------------- | :--------- | ----------: | ---------: | ------------------: | ------: | ------: | ---------------------: | ----------: | :--------- |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   |           1 |    302,841 |             302,841 |     852 |   1,180 |                    3.4 |             | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   |           2 |    571,008 |             285,504 |     885 |   1,245 |                    3.5 |             | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   |           4 |    966,160 |             241,540 |   1,114 |   1,311 |                    4.1 |             | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   |           8 |    858,922 |             107,365 |   2,490 |   2,621 |                    5.7 |             | 2026-10-25 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |           1 |    201,049 |             201,049 |   1,311 |   1,442 |                    5.0 |        0.61 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |           2 |    391,040 |             195,520 |   1,311 |   1,507 |                    5.1 |        0.62 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |           4 |    764,582 |             191,145 |   1,376 |   1,507 |                    5.2 |        0.61 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |           8 |  1,475,376 |             184,422 |   1,376 |   1,573 |                    5.4 |        0.65 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |          16 |  2,934,689 |             183,418 |   1,442 |   1,573 |                    5.5 |        0.65 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` |          32 |  5,831,297 |             182,228 |   1,442 |   1,573 |                    5.5 |        0.83 | 2026-11-02 |

On the Intel machine two loops reach 1.9 times one loop and four reach 3.2 times; at 8 loops the server fills all eight P-cores and serves less than at four, and that run does not separate the server's limit from the driver's.
On the Graviton 16 loops reach 14.6 times one loop and 32 loops 29 times, at 5.5 µs of server CPU per request throughout.
The driver-busy column divides the driver's CPU time by its elapsed time: at 32 loops its 46 threads run 83% busy, and the same point with 23 driver threads serves 3.8 million requests per second, so the 32-loop row is the driver's limit rather than the server's.

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

| Machine                                       | Class      | Backend          | Connections |  Budget | Requests/s | p50, µs | p99, µs | Server CPU, µs/request | Resident at startup | Resident under load | Date       |
| :-------------------------------------------- | :--------- | :--------------- | ----------: | ------: | ---------: | ------: | ------: | ---------------------: | ------------------: | ------------------: | :--------- |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | automatic        |          64 |   1,088 |     20,000 |      98 |     139 |                   14.6 |          25,596 KiB |          25,720 KiB | 2026-10-25 |
| Intel i9-13950HX, 8P+16E cores, 1 domain      | `serial`   | automatic        |      10,000 |  11,024 |     20,000 |     172 |   1,016 |                   10.2 |         171,256 KiB |         171,496 KiB | 2026-10-25 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring618` |          64 |   1,088 |     20,000 |      70 |      74 |                    8.4 |          50,080 KiB |          50,148 KiB | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring618` |      10,000 |  11,024 |     20,000 |      70 |      74 |                    8.4 |         591,824 KiB |         591,912 KiB | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring618` |      50,000 |  51,024 |     20,000 |      70 |      74 |                    8.5 |         755,296 KiB |         755,364 KiB | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring618` |     100,000 | 101,024 |     20,000 |      70 |      74 |                    8.6 |         956,828 KiB |         956,896 KiB | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring612` |      10,000 |  11,024 |     20,000 |      70 |      74 |                    8.7 |         585,920 KiB |         586,088 KiB | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-uring612` |     100,000 | 101,024 |     20,000 |      70 |      74 |                    8.7 |         917,068 KiB |         917,136 KiB | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-epollaio` |      10,000 |  11,024 |     20,000 |      70 |      78 |                    9.0 |          49,948 KiB |          50,016 KiB | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | `linux-epollaio` |     100,000 | 101,024 |     20,000 |      70 |      82 |                    9.0 |         386,504 KiB |         386,584 KiB | 2026-11-02 |

The Intel server preallocates about 15 KiB per budgeted connection, 145,660 KiB across the 9,936 extra connections, and grows by under 250 KiB under load.
On the Graviton the io_uring engines hold 54 KiB per budgeted connection up to 10,000 and 4 KiB per connection beyond, since each of the four loops registers receive pages for every connection its budget admits, while `linux-epollaio` holds 4 KiB per connection throughout; latency and CPU per request do not move between 64 and 100,000 connections on any backend.
To repeat the runs across a real NIC, start the server with `--host 0.0.0.0` and point the driver at its address.

## File Replies

What does a file reply cost when the server reads it through `O_DIRECT` windows and sends it without a copy?
The server serves `GET /file/{name}` from `--reply-directory`, and 64 connections fetch one file each at pipeline depth 4:

```sh
mkdir -p files
for size in 4096 65536 1048576; do head -c $size /dev/urandom > files/$size.bin; done
taskset -c 16,17 build_release/ucall_bench_server --threads 1 --connections 1088 --reply-directory files --stats json &
server=$!
sleep 1
for size in 4096 65536 1048576; do
    taskset -c 48-51 build_release/ucall_bench_http --url http://127.0.0.1:8545/file/$size.bin --verb get --bytes 0 \
        --response-bytes $size --threads 4 --connections 64 --in-flight 256 --pipeline-depth 4 \
        --warmup 2s --time-limit 8s --format json
done
kill -INT $server && wait $server
```

Reads per request count the asynchronous file reads the server issued, one per 256 KiB window.

| Machine                                       | Class      | Storage               | File   | Requests/s |  Throughput | p50, µs | p99, µs | Server CPU, µs/request | Reads/request | Date       |
| :-------------------------------------------- | :--------- | :-------------------- | :----- | ---------: | ----------: | ------: | ------: | ---------------------: | ------------: | :--------- |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | gp3 root, 16,000 IOPS | 4 KiB  |     16,891 |    66 MiB/s |  16,253 |  19,923 |                   14.1 |          1.00 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | gp3 root, 16,000 IOPS | 64 KiB |      8,587 |   537 MiB/s |  29,360 |  33,554 |                   23.0 |          1.00 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | gp3 root, 16,000 IOPS | 1 MiB  |      1,001 | 1,001 MiB/s | 260,047 | 285,213 |                  210.4 |          4.00 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | instance NVMe         | 4 KiB  |     88,575 |   346 MiB/s |   3,015 |   3,015 |                   11.3 |          1.00 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | instance NVMe         | 64 KiB |     41,329 | 2,583 MiB/s |   6,291 |   6,554 |                   24.2 |          1.00 | 2026-11-02 |
| AWS Graviton4, 96 Neoverse V2 cores, 1 domain | `apple-m2` | instance NVMe         | 1 MiB  |      1,871 | 1,871 MiB/s | 142,606 | 142,606 |                  208.9 |          4.00 | 2026-11-02 |

The storage, not the server, bounds every row: the gp3 root volume rows sit at its 16,000 IOPS and 1,000 MiB/s, and the instance NVMe rows at the drive's read rate, while the server spends 11 µs per 4 KiB reply and stays under 40% of its core at 1 MiB.

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
- `--threads N`: event loops, each polled by its own ForkUnion thread; every registered batch endpoint gets one more thread to poll it.
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
