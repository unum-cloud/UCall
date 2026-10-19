# Benchmarking UCall

`build_release/ucall_bench_http` drives the public C interface against a separately running HTTP service.
The application owns a fixed ForkUnion worker pool.
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

## Historical Razer Snapshot

October 19, 2026: Ubuntu 26.10, Linux 7.3.0-9-generic, Intel Core i9-13950HX, GCC 16.2.0, glibc 2.44, CMake 4.4.4, and `RelWithDebInfo`.
The selected CPU class was `intel-alder`.
One server worker ran on logical CPU 0; load generators ran on CPUs 8 and 10, on separate physical cores.
All services echoed the same 1,024-byte binary payload over loopback.
These single-run measurements used the earlier library-owned executor model.
They are historical results, not measurements of the current caller-driven implementation.

The native driver used two executor workers, two clients, 64 total connections, 256 outstanding calls, and queue depth 256.
Each native backend ran on both sides, with 10,000 warmup requests followed by 100,000 measured requests.
All exchanges passed byte verification, with no failed or rejected calls.

| Backend       | Requests/s | p50, µs | p99, µs |
| :------------ | ---------: | ------: | ------: |
| POSIX         |    272,567 |     857 |   1,358 |
| epoll         |    231,304 |   1,038 |   1,530 |
| io_uring 6.12 |    222,941 |   1,076 |   1,363 |
| io_uring 7.0  |    241,194 |   1,025 |   1,210 |

POSIX led throughput for this small loopback exchange; the 7.0 variant improved on 6.12 in this closed-loop run.
This workload includes registered TX copying and notification retirement, so registration alone does not imply a throughput gain.

The Python services each used one application worker, CPython 3.14.8, FastAPI 0.149.0, Uvicorn 0.54.0, uvloop 0.23.0, httptools 0.9.0, and grpcio 1.84.0.
Both fixed-count runs used 64 connections, 256 outstanding calls, 10,000 warmup requests, and 100,000 measured requests, with no failed byte checks.
The HTTP load generator used `linux-uring700`; gRPC used the asynchronous Python client, including its runtime and protobuf costs.

| Service | Driver      | Requests/s | p50, µs | p99, µs |
| :------ | :---------- | ---------: | ------: | ------: |
| FastAPI | Native HTTP |      5,118 |  43,789 | 128,790 |
| gRPC    | Python gRPC |     10,863 |  23,433 |  26,418 |

One initial gRPC run exceeded its 40-second external watchdog; a fresh-server rerun completed in 9.21 seconds.
The cause of that interrupted run remains unconfirmed.

Independent offered-rate runs used wrk2 commit `44a94c17`, LuaJIT 2.1, two load-generator threads, 64 connections, 15 seconds, and 10,000 scheduled requests/s.
The tool's legacy `luaL_reg` spelling was updated to `luaL_Reg` for the newer LuaJIT; the workload script was unchanged.
Both runs reported zero echo-verification failures.

| Server        | Requests/s | Corrected p50, µs | Corrected p99, µs |
| :------------ | ---------: | ----------------: | ----------------: |
| io_uring 6.12 |      9,950 |               841 |             1,920 |
| io_uring 7.0  |      9,946 |             1,620 |             5,040 |

The advanced variant did not improve the offered-rate latency distribution in this pass.
A separate ghz 0.121.0 run used 64 connections, concurrency 256, 22,000 calls with the first 2,000 skipped, and 10,000 offered requests/s.
Its 20,000 recorded RPCs were all `OK`, at 9,087 requests/s, p50 16.76 ms, and p99 25.48 ms.

A separate 15-second software-clock profile of the advanced server used two unpinned workers at 10,000 offered requests/s.
Its 190 samples identified byte-buffer append/initialization and operation-table scans as follow-up costs; the sample count does not support fine-grained percentage comparisons.
