# Contributing to UCall

For coding guidelines, refer to [ashvardanian/CONTRIBUTING.md](https://github.com/ashvardanian/ashvardanian/blob/master/CONTRIBUTING.md).
Configuring a source checkout enables the hooks in `.githooks/`.
They check staged additions, Doxygen and docstring structure, imports, naming, and language formatting.

## Compiling C and C++

Building takes CMake 3.28 and a C++20 compiler.
Initialize the sibling submodules before configuring:

```bash
git submodule update --init --recursive
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

The `relwithdebinfo` and `release` presets build the same suites with optimization.
StringZilla, ForkUnion, and SmashTable resolve from their submodules or pinned fetches; `FETCHCONTENT_SOURCE_DIR_STRINGZILLA`, `FETCHCONTENT_SOURCE_DIR_FORKUNION`, and `FETCHCONTENT_SOURCE_DIR_SMASHTABLE` select existing checkouts.
The build exposes one library as `ucall::ucall`.
`UCALL_WITH_POSIX`, `UCALL_WITH_LINUX_EPOLL`, `UCALL_WITH_LINUX_URING`, `UCALL_WITH_KQUEUE`, and `UCALL_WITH_IOCP` control compiled backends; the main project enables those supported by the target operating system.
CPU probes select separate instantiation units and apply their instruction flags without raising the dispatch code's baseline.

`UCALL_BUILD_EXAMPLES=ON` enables `ucall_example_echo`, `ucall_example_ledger`, and `ucall_example_redis`; `UCALL_BUILD_BENCH=ON` enables `ucall_bench_http`.
Executables go directly into the preset's build directory, such as `build_release/ucall_example_echo`.
`UCALL_BUILD_PYTHON=ON` builds the CPython extension that [Python builds](#python-builds) package, and the root `Cargo.toml` builds the Rust crate, as [Rust builds](#rust-builds) describe.

## Running Tests

Native suites live in `test/`, the C caller in `c/test.c`, and benchmark clients in `bench/`.
`UCALL_SEED` selects an unsigned 32-bit seed or `random`, `UCALL_FILTER` selects cases, and `UCALL_MULTIPLIER` scales native sweeps.

```bash
UCALL_FILTER=records UCALL_MULTIPLIER=0.1 ctest --preset debug
```

Python suites sit beside them as `test/serving.py` and `test/calling.py`, and Rust tests sit in each module of `rust/`.

## Python Builds

`pyproject.toml` builds with `scikit-build-core`, which configures the top-level CMake tree with `UCALL_BUILD_PYTHON=ON` and installs the `ucall_python` target, the extension `ucall.lib`, into the `python/ucall/` package.
`python/lib.c` holds the module and the shared argument parsing, while `types.c`, `server.c`, and `client.c` wrap the types, the server, and the client.
The build tree lives in `build_python/<wheel_tag>`, and an editable install recompiles only when the install command runs again.

```sh
uv venv .venv && source .venv/bin/activate
uv pip install scikit-build-core ninja pytest
uv pip install --no-build-isolation -e .
python -X faulthandler -m pytest
```

## Rust Builds

The root `Cargo.toml` builds the crate from `rust/lib.rs`, and `build.rs` compiles the native library through CMake.
`rust/types.rs`, `server.rs`, and `client.rs` mirror the Python sources, each module keeps its tests in `mod tests`, and `rust/testing.rs` holds their shared helpers.

```sh
cargo test
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

## Code Clarity

Use the vocabulary already established by the sibling libraries: variants, CPU classes, capability ladders, and outcomes.
A name identifies the resource or operation it represents; do not introduce another wrapper to rename an existing concept.
Class, alias, and variable templates have bare names, template parameters end in an underscore, concrete types use `_t`, and concrete constants use `_k`.
Declare sibling namespace aliases once and use `st::`, `fu::`, and `sz::` at use sites.
Spell full sibling namespaces only when declaring those aliases.
Each template in `include/` takes its kits and atomic reference as template arguments, and `src/` picks them per CPU class.
No template in `include/` names a CPU class or a capability mask; classes, masks, and the ladder that chooses rungs stay in `src/`.

Every mutable object has one owner and one authoritative state.
Each server loop has one application polling owner; each client is initialized, submitted, polled, and freed by one owner thread.
That owner holds its connections, protocol transitions, deadlines, and backend operation records.
Endpoint callbacks execute synchronously on the polling caller, and batch callbacks on the batch endpoint's draining caller.
Cross-thread retained replies and server shutdown publish state atomically rather than changing the loop's I/O records directly.
Public contracts say when inputs may be reused, when an outcome becomes final, and which owner must outlive which handle.
Cancellation requests work to stop; only retirement permits its storage to be reused.
Represent mutually exclusive phases with scoped enums and independent properties with named enum flags.
Derive state from existing ownership pointers or counters when they already provide the answer; do not mirror it with booleans.
Give owning classes explicit copy and move contracts.
An object referenced by kernel user data or live child pointers stays at a stable address and cannot be copied or moved.

Pass one allocator instance through owning parents, child objects, containers, and buffers, rebinding it for each element type.
Allocators return null on allocation failure, and callers report that failure without throwing.
Deallocation uses the allocator that created the allocation, including responses that outlive their clients.

Keep scalar control in the state machine and bulk byte work in capability-selected StringZilla kernels.
An explicit CPU instantiation exists only when its selected kernels, atomics, or waits differ from its parent.
Use ForkUnion references for cross-thread admission and publication; keep single-owner counters local.
Do not add an abstraction, wrapper, flag, or dedicated file for symmetry or a possible future use.

### Capacities and Bounds

Derive storage from a caller's admission budget, protocol geometry, or an actual operating-system or hardware property.
An I/O transfer limit segments an operation; it does not become a message-size limit.
Exhausted resources apply backpressure or report allocation failure rather than truncating input.
Do not tune constants until one benchmark looks good.

### Comments and Formatting

Public C and C++ contracts use Doxygen tags; Python public functions and modules describe their purpose in docstrings.
A code comment explains a non-obvious reason rather than narrating an operation.
Keep source headers, attribution, and original creation dates consistent with the file's history.

Begin each Markdown sentence on a separate source line and align table columns.
Run `dprint fmt` for Markdown, `clang-format` for C and C++, Ruff for Python, and `cargo +nightly fmt` for Rust.
The staged-file hooks check these conventions and reject template suffixes even with brace initialization.

### Review and Measurements

A commit message explains the resulting behavior, why the change matters, and how it was checked.
Stage a concrete review candidate with a proposed title and body; staging does not authorize committing.
Performance reports name the backend, CPU class, build, placement, workload, admission budgets, and load generator.
Traced timings explain costs and are not throughput measurements.
