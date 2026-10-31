# UCall Example & Benchmark

This folder implements a group of different servers with identical functionality, but using different RPC frameworks, including:

- FastAPI server in Python, compatible with WSGI: `fastapi_server.py`
- UCall server in Python: `ucall_server.py`
- UCall server in C++: `ucall_server.cpp`
- gRPC server in Python: `grpc_server.py`

All of them implement identical endpoints:

- `echo` - return back the payload it received for throughput benchmarks
- `validate_session` - lightweight operation on two integers, returning a boolean, to benchmark the request latency on tiny tasks
- `create_user` - more complex operation on flat dictionary input with strings and integers
- `validate_user_identity` - that validates arguments, raises exceptions, and returns complex nested objects
- `set` & `get` - key-value store operations, similar to Redis
- `resize` - batch-capable image processing operation for Base64-encoded images
- `dot_product` - batch-capable matrix vector-vector multiplication operation


## Reproducing Benchmarks

```sh
cd examples
```

### Debugging FastAPI

To start the server:

```sh
uvicorn fastapi_server:app --port 8000 --reload
```

To run the client tests using HTTPX:

```sh
pytest fastapi_client.py -s -x
pytest fastapi_client.py -s -x -k set_get # for a single test
```

To run HTTPX stress tests and benchmarks:

```sh

```

### FastAPI

```sh
pip install uvicorn fastapi websocket-client requests tqdm fire

# To start the server in the background
uvicorn fastapi_server:app --log-level critical --port 8000 &

# To check if it works as expected
pytest fastapi_client.py


python examples/bench.py "fastapi_client.ClientREST" --progress
python examples/bench.py "fastapi_client.ClientWebSocket" --progress
kill %%
```

Want to dispatch more clients and aggregate statistics?

```sh
python examples/bench.py "fastapi_client.ClientREST" --threads 8
python examples/bench.py "fastapi_client.ClientWebSocket" --threads 8
```

### UCall

UCall can produce both a POSIX compliant old-school server, and a modern `io_uring`-based version for Linux kernel 5.19 and newer.
You would either run `ucall_example_server_posix` or `ucall_example_server_uring`.

```sh
sudo apt-get install cmake g++ build-essential
cmake -DCMAKE_BUILD_TYPE=Release -B build_release
cmake --build build_release --config Release
build_release/build/bin/ucall_example_server_posix &
build_release/build/bin/ucall_example_server_uring &
python examples/bench.py "jsonrpc_client.CaseTCP" --progress
python examples/bench.py "jsonrpc_client.CaseHTTP" --progress
python examples/bench.py "jsonrpc_client.CaseHTTPBatches" --progress
kill %%
```

Want to customize server settings?

```sh
build_release/build/bin/ucall_example_server_uring --nic=127.0.0.1 --port=8545 --threads=16 --silent=false
```

Want to dispatch more clients and aggregate more accurate statistics?

```sh
python examples/bench.py "jsonrpc_client.CaseTCP" --threads 32 --seconds 100
python examples/bench.py "jsonrpc_client.CaseHTTP" --threads 32 --seconds 100
python examples/bench.py "jsonrpc_client.CaseHTTPBatches" --threads 32 --seconds 100
```

A lot has been said about the speed of Python code ~~or the lack of~~.
To get more accurate numbers for mean request latency, you can use wrk for html requests

```sh
wrk -t1 -c32 -d2s http://localhost:8545/ -s json.lua
wrk -t1 -c32 -d2s http://localhost:8545/ -s json16.lua
```

Or the GoLang version for jsonRPC requests:

```sh
go run ./examples/login/jsonrpc_client.go -h
go run ./examples/login/jsonrpc_client.go -b 100
```

Or push it even further dispatching dozens of processes with GNU `parallel` utility:

```sh
sudo apt install parallel
parallel go run ./examples/login/jsonrpc_client.go run ::: {1..32}
```

### gRPC Results

```sh
pip install grpcio grpcio-tools
python ./examples/login/grpc_server.py &
python examples/bench.py "grpc_client.ValidateClient" --progress
python examples/bench.py "grpc_client.ValidateClient" --threads 32
kill %%
```
