# Inference Example

The inference example is an application, not a framework benchmark: most of its time goes to arithmetic, not to the network.
It shows what batch endpoints buy a compute-heavy service, and that a slow batch endpoint cannot stall the others.
The networking stack itself is measured in the [benchmark guide](../../bench/README.md).

## Native Server

[server.cpp](server.cpp) keeps a resident i8 matrix of `--rows` by `--dimensions` values, 100,000 by 1,024 or about 100 MB by default, filled from ForkUnion's SplitMix64 with `--seed`.
At startup NumKong packs the matrix in slices of 1,024 rows, so one query's scores against a slice fill a 4 KiB stack array.
A query is exactly `--dimensions` request bytes read as i8, and each reply holds the 10 best rows as 80 bytes of little-endian `u32` row and `i32` score pairs, best first.

- `POST /infer` runs NumKong's packed i8 dots for one query over every slice in turn, on the polling thread that received it, with its scores and running top 10 on the stack.
- `POST /infer/batch` is a batch endpoint that copies a batch's queries into one dense matrix, then spreads the slices over a ForkUnion pool of one thread per logical core, each taking every N-th slice, and merges the threads' best rows.
  Its polling thread is the pool's only user, owns the threads' score scratch, and parks the pool between batches.
- `POST /slow/batch` sleeps `--slow-batch-us` microseconds in its callback, 5,000 by default, then answers every request with an empty body.
- `GET /health` answers `ready`.

Besides `--rows`, `--dimensions`, `--seed` and `--slow-batch-us`, it takes the server flags every example shares: `--host`, `--port`, `--threads`, `--connections`, `--pipelined-requests`, `--security`, `--key`, `--batch-min`, `--batch-max`, `--batch-latency-us` and `--stats`.

```sh
cmake -S . -B build_release -DCMAKE_BUILD_TYPE=Release -DUCALL_BUILD_BENCH=ON -DUCALL_BUILD_EXAMPLES=ON
cmake --build build_release --target ucall_bench_http ucall_example_inference
build_release/ucall_example_inference --rows 100000 --dimensions 1024 --threads 1 --connections 2048 \
    --batch-min 8 --batch-max 64 --batch-latency-us 1000 --stats json
```

## Python Server

[server.py](server.py) serves the same routes on UCall's Python bindings over one NumKong kernel, [model.py](model.py), whose matrix and replies are byte-identical to the native example's for the same seed.
`/infer` scores on the polling thread, and `/infer/batch` is a batch endpoint polled by its own thread.
It takes `--rows`, `--dimensions`, `--seed`, `--port`, `--batch-min`, `--batch-max` and `--batch-latency-us`, and its FastAPI and LitServe baselines live with the benchmarks.

```sh
uv venv .venv && source .venv/bin/activate
uv pip install . numpy numkong
python examples/inference/server.py --port 8547 \
    --batch-min 8 --batch-max 64 --batch-latency-us 1000
```

Point the driver commands below at port 8547.

## Batch Amortization

Does batching beat one call per request once the work has a fixed cost per invocation?
The runs use the machine of the [benchmark setup](../../bench/README.md#setup), with the server on CPUs 0-15 so its polling thread stays on a P-core, the drivers on CPUs 16-31, one event loop, and a fresh server for every point.
First the closed-loop ceilings, at 256 connections and 512 calls in flight:

```sh
for route in infer infer/batch; do
    taskset -c 16-31 build_release/ucall_bench_http --url http://127.0.0.1:8545/$route --bytes 1024 --response-bytes 80 \
        --threads 2 --connections 256 --in-flight 512 --warmup 1s --time-limit 8s --format json
done
```

| Route          | Budget       | Requests/s |
| :------------- | :----------- | ---------: |
| `/infer`       | None         |        228 |
| `/infer/batch` | 8/64, 1 ms   |      3,297 |
| `/infer/batch` | 64/256, 5 ms |      4,172 |

A budget reads as the minimum and maximum batch, then the latency budget.
Then sweep the offered rate, restarting the server for every point:

```sh
for rate in 50 100 150 200 250 300; do
    taskset -c 16-31 build_release/ucall_bench_http --url http://127.0.0.1:8545/infer --bytes 1024 --response-bytes 80 \
        --threads 2 --connections 64 --in-flight 256 --rate $rate --warmup 1s --time-limit 10s --format json
done
for route in infer infer/batch; do
    for rate in 500 1000 1500 2000 2500 3000 3500; do
        taskset -c 16-31 build_release/ucall_bench_http --url http://127.0.0.1:8545/$route --bytes 1024 --response-bytes 80 \
            --threads 2 --connections 64 --in-flight 256 --rate $rate --warmup 1s --time-limit 10s --format json
    done
done
```

The `/infer` sweep stops at 300 requests/s, past its ceiling, and the batch sweeps at 3,500 requests/s.
The sweeps ran while other workloads kept the machine at a load average of 20 to 36, so they saturate below the closed-loop ceilings, which ran near 5.
The 64/256 budget runs with `--connections 256 --in-flight 512`, so a full batch fits in flight.

| Route          | Budget       | Offered, requests/s | Served, requests/s |   p50, µs |    p99, µs | Requests per batch | Filled/ready/expired, % | Server CPU, µs/request |
| :------------- | :----------- | ------------------: | -----------------: | --------: | ---------: | -----------------: | :---------------------- | ---------------------: |
| `/infer`       | None         |                  50 |                 50 |     8,389 |     32,506 |                    |                         |                 13,998 |
| `/infer`       | None         |                 100 |                100 |     7,864 |    150,995 |                    |                         |                 11,783 |
| `/infer`       | None         |                 150 |                137 |   167,772 |  2,684,355 |                    |                         |                  9,780 |
| `/infer`       | None         |                 200 |                154 | 1,342,177 |  3,087,008 |                    |                         |                  8,725 |
| `/infer`       | None         |                 250 |                131 | 4,831,838 |  9,126,806 |                    |                         |                  9,087 |
| `/infer`       | None         |                 300 |                130 | 6,710,886 | 13,421,773 |                    |                         |                  8,537 |
| `/infer/batch` | 8/64, 1 ms   |                 500 |                500 |    13,631 |     29,360 |                4.3 | 0/3/97                  |                 18,975 |
| `/infer/batch` | 8/64, 1 ms   |                1000 |                996 |    18,874 |     75,497 |               12.3 | 0/90/10                 |                  9,675 |
| `/infer/batch` | 8/64, 1 ms   |                1500 |              1,480 |   201,327 |    520,094 |               29.4 | 0/99/1                  |                  6,617 |
| `/infer/batch` | 8/64, 1 ms   |                2000 |              1,502 | 1,946,157 |  3,355,443 |               31.8 | 0/100/0                 |                  6,316 |
| `/infer/batch` | 8/64, 1 ms   |                2500 |              1,436 | 3,221,225 |  7,516,193 |               31.9 | 0/100/0                 |                  6,748 |
| `/infer/batch` | 8/64, 1 ms   |                3000 |              1,491 | 5,368,709 | 10,200,547 |               31.9 | 0/100/0                 |                  6,632 |
| `/infer/batch` | 8/64, 1 ms   |                3500 |              1,477 | 6,442,451 | 13,958,644 |               31.9 | 0/100/0                 |                  6,488 |
| `/infer/batch` | 64/256, 5 ms |                 500 |                500 |    14,680 |     32,506 |                4.7 | 0/0/100                 |                 17,100 |
| `/infer/batch` | 64/256, 5 ms |                1000 |                996 |    24,117 |    192,938 |               13.5 | 0/1/99                  |                  8,468 |
| `/infer/batch` | 64/256, 5 ms |                1500 |              1,494 |    29,360 |     71,303 |               28.5 | 0/2/98                  |                  6,695 |
| `/infer/batch` | 64/256, 5 ms |                2000 |              1,994 |    54,526 |    134,218 |               64.0 | 0/48/52                 |                  5,447 |
| `/infer/batch` | 64/256, 5 ms |                2500 |              2,333 |   469,762 |    738,198 |              121.7 | 0/95/5                  |                  4,811 |
| `/infer/batch` | 64/256, 5 ms |                3000 |              2,212 | 1,476,395 |  3,623,879 |              125.0 | 0/98/2                  |                  4,907 |
| `/infer/batch` | 64/256, 5 ms |                3500 |              2,173 | 3,489,661 |  6,174,015 |              126.2 | 0/98/2                  |                  5,017 |

`/infer` streams the whole packed matrix through one core for every query, while `/infer/batch` streams it once per batch across every core, so batching lifts the ceiling about 18 times, from 228 to 4,172 requests/s.
Below saturation batches fire on their latency budget with a few requests each, and they fill toward the maximum as the offered rate grows.
Parked ForkUnion workers take up to 1 ms to wake for each batch, which the example accepts to keep an idle pool off the cores.

## Endpoint Isolation

Does a slow batch endpoint still stall the others?
Each batch endpoint has its own polling thread, so `/infer/batch` should keep its latency while `/slow/batch` sleeps 5 ms in every callback.
The fast route takes a fixed 1,000 requests/s while a second driver offers the slow route 0 to 800 requests/s:

```sh
taskset -c 0-15 build_release/ucall_example_inference --threads 1 --connections 2048 \
    --batch-min 8 --batch-max 64 --batch-latency-us 1000 --slow-batch-us 5000 --stats json
taskset -c 28,30 build_release/ucall_bench_http --url http://127.0.0.1:8545/slow/batch --bytes 16 --response-bytes 0 \
    --threads 1 --connections 64 --in-flight 64 --rate 800 --warmup 1s --time-limit 12s --format json &
taskset -c 16,18 build_release/ucall_bench_http --url http://127.0.0.1:8545/infer/batch --bytes 1024 --response-bytes 80 \
    --threads 2 --connections 64 --in-flight 256 --rate 1000 --warmup 1s --time-limit 10s --format json
wait
```

| Slow offered, requests/s | Fast served, requests/s | Fast p50, µs | Fast p99, µs | Fast requests per batch | Slow batches | Slow requests |
| -----------------------: | ----------------------: | -----------: | -----------: | ----------------------: | -----------: | ------------: |
|                        0 |                     998 |       13,631 |       37,749 |                     8.6 |            0 |             0 |
|                       50 |                     998 |       15,204 |       48,234 |                     9.8 |          650 |           650 |
|                      200 |                   1,000 |       14,680 |       46,137 |                     9.4 |        2,327 |         2,600 |
|                      800 |                     999 |       14,680 |       41,943 |                     9.5 |        2,442 |        10,400 |

The slow and fast counts come from the server's batch counters, warmup included.
A slow batch endpoint does not drag a fast one: the fast route's p99 stays between 38 and 48 ms with no trend as the slow load grows, even when the slow endpoint's polling thread is saturated and packs about 4 requests into each batch.
These runs shared the machine at a load average of 23 to 28.
