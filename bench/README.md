# Benchmarking UCall

`build_release/ucall_bench_http` drives the public C interface against a separately running HTTP service.
The application owns a fixed ForkUnion worker pool.
`--threads` counts every application polling thread, including the calling thread, which runs one client instead of adding a spinning coordinator.
Each active worker initializes and polls its own client, with a share of the requested connection, in-flight, and request totals.
The library creates no worker threads; each client drives many sockets, and the driver releases each response after verification.

```sh
cmake -S . -B build_release -DCMAKE_BUILD_TYPE=Release -DUCALL_BUILD_BENCH=ON -DUCALL_BUILD_EXAMPLES=ON
cmake --build build_release --target ucall_bench_http ucall_example_echo
build_release/ucall_example_echo --backend linux-uring612 --cpu-class automatic --threads 1 --port 8545
```

Run the client in another terminal:

```sh
build_release/ucall_bench_http --url http://127.0.0.1:8545/echo \
    --backend linux-uring612 --cpu-class automatic --threads 2 \
    --connections 64 --in-flight 256 --requests 100000 --warmup-requests 10000 --bytes 1024 --verify-echo
```

`--requests` is required and fixes the number of measured attempts.
Warmup finishes before the measured phase begins.
Latency storage and per-worker counters are allocated before warmup; recording a completion does not grow a container or sort samples.
The driver timestamps each batch immediately after its polling call returns.
Latency includes submission, queueing, transport progress, and completion observation by that worker; it is not a kernel completion timestamp.
Throughput covers the measured ForkUnion dispatch through response verification, release, and completion of every worker.
Nearest-rank p50, p95, and p99 selection happens after timing ends.
Rejected submissions, failed exchanges, and incorrect echo bytes are counted and produce a nonzero exit status.

`--backend` and `--cpu-class` select the implementation and kernel bundle; the report prints the application worker count, connection and in-flight budgets, and each active worker's resolved choices and outcomes.
Explicit unsupported selections fail instead of silently changing the experiment.
The same binary can select `linux-uring612` or `linux-uring700`; run the server and client with the intended backend independently.
`--help` lists the other native backends and CPU classes.
For the key-value example, seed a value first and use its URL with `--verb get --bytes 0`, omitting `--verify-echo`.

## Multiple Targets and Retained Replies

Repeat `--url` to exercise several logical targets through each active client's connection and call budgets.
Measured and warmup requests are split as evenly as possible across targets and active clients, with a fixed in-flight reservation for each target.
A slow target therefore retains its own outstanding work while the client can continue polling the others.
The report includes per-target issued, completed, successful, failed, and rejected calls, byte checks, response bytes, mean and maximum latency, and first and last completion offsets.

Start separate echo processes on ports 8545 and 8546, then run:

```sh
build_release/ucall_bench_http \
    --url http://127.0.0.1:8545/echo --url http://127.0.0.1:8546/echo \
    --backend linux-uring612 --cpu-class automatic --threads 2 \
    --connections 64 --in-flight 256 --requests 100000 --warmup-requests 10000 --bytes 1024 --verify-echo
```

For retained replies, use `--reorder` and supply `/echo/reordered` on each echo process.
The service retains the first tagged request until its partner arrives, then publishes member 1 before member 0, without sleeping or blocking a polling thread.
The driver verifies the echoed body and returned pair and member tags.
It reports observed completion reordering; publication order across sockets does not guarantee TCP arrival or polling order.
This mode requires POST, even measured and warmup counts, and at least two connections and in-flight slots per active target and client.
Each retained member occupies an HTTP/1.1 connection until its partner arrives, so the effective in-flight budget is the smaller of the requested call and connection budgets, rounded to whole pairs.
The report prints that effective capacity; ordinary echo can queue more calls than open connections.
Ordinary echo requires one of each.
The requested ForkUnion worker count remains fixed; workers beyond the available per-target budgets stay idle, and the report shows the active client count.

Add `--close` to request connection closure after every response and measure connection churn separately from keep-alive reuse.
The same byte checks, target quotas, and latency boundaries apply to both modes.

## Python Adapters

The semantic workload is an exact binary echo: `N` application bytes, a leading zero followed by `x` bytes, returned unchanged.
Zero-length payloads are also valid.
FastAPI serves raw HTTP bytes at `POST /echo`, matching the native example, and the gRPC adapter carries the same bytes in `ucall.bench.Payload.data`.
Generated protobuf modules stay outside the repository, following the [gRPC Python toolchain](https://grpc.io/docs/languages/python/quickstart/).

For the Linux comparison environment, select the intended installed Python interpreter explicitly and record its version:

```sh
uv venv --python /usr/bin/python3.14 /tmp/ucall-bench-python
uv pip install --python /tmp/ucall-bench-python/bin/python fastapi 'uvicorn[standard]' httpx grpcio grpcio-tools
uv pip freeze --python /tmp/ucall-bench-python/bin/python
mkdir -p /tmp/ucall-bench-proto
/tmp/ucall-bench-python/bin/python -m grpc_tools.protoc -Ibench \
    --python_out=/tmp/ucall-bench-proto --grpc_python_out=/tmp/ucall-bench-proto bench/echo.proto
```

Run the [FastAPI binary response](https://fastapi.tiangolo.com/advanced/custom-response/) service with one application worker, and check its payload before measuring it with the native client:

```sh
/tmp/ucall-bench-python/bin/python -m uvicorn examples.fastapi_server:app \
    --host 127.0.0.1 --port 8545 --workers 1 --loop uvloop --http httptools --no-access-log
/tmp/ucall-bench-python/bin/python examples/fastapi_client.py http://127.0.0.1:8545 --bytes 1024
```

Run the asynchronous Python gRPC service and its fixed-count verifying client in separate terminals:

```sh
PYTHONPATH=/tmp/ucall-bench-proto /tmp/ucall-bench-python/bin/python bench/grpc_server.py 127.0.0.1:8546
PYTHONPATH=/tmp/ucall-bench-proto /tmp/ucall-bench-python/bin/python bench/grpc_client.py 127.0.0.1:8546 \
    --requests 100000 --warmup-requests 10000 --connections 64 --concurrency 256 --bytes 1024
```

The Python client preallocates one latency entry per request and uses asynchronous tasks, with separate counters per task.
Its channel count is explicit; local subchannel pools keep those channels independent.
Protobuf serialization and the Python runtime remain part of the gRPC measurement.

## Independent Load Generators

Use [wrk2](https://github.com/giltene/wrk2) against either native HTTP or FastAPI, with the same connection count, byte count, and offered rate.
`bench/http.lua` generates the binary body once per worker and verifies every echoed response.
The example uses a 30-second interval to cover wrk2's calibration period and an explicit rate of 10,000 requests/s:

```sh
wrk -t2 -c64 -d30s -R10000 --latency -s bench/http.lua http://127.0.0.1:8545/echo -- 1024
```

For [ghz](https://ghz.sh/docs/options), serialize the same application payload once, then load the gRPC method directly from its schema:

```sh
PYTHONPATH=/tmp/ucall-bench-proto /tmp/ucall-bench-python/bin/python - <<'PY'
from pathlib import Path
import echo_pb2
Path('/tmp/ucall-bench-proto/payload.pb').write_bytes(echo_pb2.Payload(data=b'\0' + b'x' * 1023).SerializeToString())
PY
ghz --insecure --proto bench/echo.proto --call ucall.bench.Echo.Exchange \
    --binary-file /tmp/ucall-bench-proto/payload.pb --connections 64 --concurrency 256 \
    --total 110000 --skipFirst 10000 --rps 10000 127.0.0.1:8546
```

The application work matches, while the wire protocols differ: native HTTP and FastAPI use an HTTP/1.1 body; gRPC adds protobuf serialization, gRPC framing, and HTTP/2 multiplexing.
A gRPC connection can carry concurrent streams, while the native HTTP/1.1 client keeps one exchange active per connection and queues the rest.
The native and Python fixed-count clients are closed-loop drivers; wrk2 schedules an offered rate and accounts for delayed sends in its latency distribution.
Report those load models separately, and inspect saturation and errors before interpreting their percentiles together.
The Lua driver verifies response bytes; ghz reports RPC status and decoding, so use the Python gRPC client to check echoed bytes before its independent load run.

Pin server and load-generator processes to disjoint CPU sets on Linux with `taskset`, keeping the chosen physical cores and worker counts fixed across implementations.
Record the full commands, payload size, request count, connection and in-flight counts, CPU classes, backends, package versions, `uname -a`, and `lscpu` with each report.

## Razer Snapshot: October 19, 2026

Ubuntu 26.10, Linux 7.3.0-9-generic, Intel Core i9-13950HX, GCC 16.2.0, glibc 2.44, CMake 4.4.4, and `RelWithDebInfo`; native CPU selection resolved to `intel-alder`.
One server process used one polling thread on logical CPU 0; two caller-inclusive client threads ran on CPUs 8 and 10, on separate physical cores.
Two-target workloads used two server processes, each with one polling thread, on CPUs 0 and 2.
This was a shared desktop with the powersave governor and turbo enabled, without CPU isolation; the throughput ranges expose run-to-run variation.
Earlier results used a different threading model and are superseded here.

### Native Backend Comparisons

Each backend ran three repetitions of 500,000 measured requests after 10,000 warmup requests, with 64 connections, 256 in-flight calls, and a 1,024-byte binary echo over plaintext loopback HTTP.
These sweeps measure per-loop throughput; scaling across multiple loops in one server has not been measured.
Every measured exchange passed byte verification, with zero failures or rejected submissions.
Throughput is the median and min–max across three runs; p50 and p99 are medians of the per-run percentiles, not percentiles pooled across runs.

Varying the server backend with the client fixed to `linux-uring700`:

| Backend       | Median requests/s |  Min–max requests/s | Median p50, µs | Median p99, µs |
| :------------ | ----------------: | ------------------: | -------------: | -------------: |
| POSIX         |         262,883.5 | 261,948.4–263,932.1 |         972.36 |       1,137.88 |
| epoll         |         231,208.4 | 225,956.9–231,290.5 |       1,029.47 |       1,852.29 |
| io_uring 6.12 |         234,935.7 | 234,703.8–236,145.2 |       1,082.81 |       1,208.93 |
| io_uring 7.0  |         221,515.9 | 220,881.6–222,151.4 |       1,121.64 |       1,502.29 |

Varying the client backend with the server fixed to `linux-uring700`:

| Backend       | Median requests/s |  Min–max requests/s | Median p50, µs | Median p99, µs |
| :------------ | ----------------: | ------------------: | -------------: | -------------: |
| POSIX         |         296,614.2 | 237,211.2–298,361.1 |         859.60 |         998.28 |
| epoll         |         275,288.3 | 218,816.6–287,093.5 |         916.34 |       1,113.11 |
| io_uring 6.12 |         249,107.5 | 211,823.9–274,764.6 |       1,010.74 |       1,176.58 |
| io_uring 7.0  |         249,005.7 | 239,780.8–281,626.4 |       1,021.65 |       1,168.73 |

POSIX had the highest median throughput in both sweeps for this workload.
The registered io_uring paths did not outperform it here; the larger client-side ranges also make a single-run ranking unreliable.

### Other Native Workloads

These are individual runs using `linux-uring700` on both sides, with 10,000 warmup requests, the same client topology, and 64 connections.
All calls passed byte verification with zero failures or rejected submissions.

| Workload                         | Measured requests | In-flight calls | Requests/s |   p50, µs |   p99, µs |
| :------------------------------- | ----------------: | --------------: | ---------: | --------: | --------: |
| Two echo targets, 1 KiB          |           100,000 |             256 |  406,084.6 |    445.64 |  1,429.11 |
| Two retained-pair targets, 1 KiB |           100,000 |              64 |  421,037.4 |    143.72 |    211.14 |
| Close after each response, 1 KiB |            10,000 |             256 |  126,191.7 |  1,997.55 |  2,298.85 |
| Echo, 64 KiB                     |            10,000 |             256 |   11,884.9 | 19,922.57 | 67,344.05 |

Each two-target run completed and verified 50,000 calls per target.
The retained-pair run used an effective budget of 64 calls because each held pair needs two live HTTP/1.1 connections.
It observed 46,963 completion-sequence inversions while verifying all 100,000 response tags and bodies; socket arrival order is not guaranteed by reply publication order.
The 64 KiB run returned 0.779 GB/s of response bodies, with a visible 67.34 ms p99 tail; its message buffers grew to hold the complete framed payload.
Registered transmission storage, page-sized sends, and notification retirement still carry costs, and loopback can copy kernel socket buffers.

### Python Services

The services used one application worker, CPython 3.14.8, FastAPI 0.149.0, Uvicorn 0.54.0, uvloop 0.23.0, httptools 0.9.0, and grpcio 1.84.0.
Each individual fixed-count run used 100,000 measured calls, 10,000 warmup calls, 64 connections, 256 outstanding calls, and the same 1,024-byte application payload and CPU placement.
All echoed bytes passed verification.
FastAPI used the native `linux-uring700` HTTP client; gRPC used the asynchronous Python client, including its runtime and protobuf costs.

| Service | Driver      | Requests/s |   p50, µs |   p99, µs |
| :------ | :---------- | ---------: | --------: | --------: |
| FastAPI | Native HTTP |   19,966.6 | 12,792.32 | 13,570.65 |
| gRPC    | Python gRPC |   11,747.8 | 21,681.18 | 23,957.24 |

These are workload-specific end-to-end results with different protocol and client costs; they do not establish a general framework speed multiplier.

### Independent Offered-Rate Runs

wrk2 with LuaJIT 2.1 used two load-generator threads, 64 connections, 30 seconds, and 10,000 scheduled requests/s against each server.
The LuaJIT compatibility spelling was updated from `luaL_reg` to `luaL_Reg`; the byte-verifying workload was unchanged.
All four runs reported zero echo-verification failures.

| Server        | Requests/s | Corrected p50, µs | Corrected p99, µs |
| :------------ | ---------: | ----------------: | ----------------: |
| POSIX         |   9,974.57 |               910 |             1,880 |
| io_uring 6.12 |   9,974.46 |               841 |             1,900 |
| io_uring 7.0  |   9,974.71 |               970 |             2,100 |
| FastAPI       |   9,974.64 |             2,140 |           279,810 |

A separate ghz 0.121.0 run offered 10,000 RPCs/s with 64 connections and concurrency 256, recording 100,000 calls after skipping the first 10,000.
All recorded RPCs were `OK`, with p50 2.15 ms and p99 7.09 ms.
The tool reported 9,089.07 requests/s using an 11-second denominator that includes the skipped interval; it is distinct from the offered rate.

A separate 1,000,000-request run against the `linux-uring700` server was profiled for six seconds at 199 Hz, yielding 614 CPU-clock samples with none lost.
About 12% of self samples fell in buffer append/initialization through `append_text` and `basic_vector::resize`, identifying buffer construction as a follow-up cost.
This small profile supports that qualitative observation, not fine-grained percentage comparisons or a throughput estimate.
