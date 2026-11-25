# Contributing to UCall

For coding guidelines, refer to [ashvardanian/CONTRIBUTING.md](https://github.com/ashvardanian/ashvardanian/blob/master/CONTRIBUTING.md).
Configuring a source checkout enables the hooks in `.githooks/`.
They check staged additions, Doxygen and docstring structure, imports, naming, and language formatting.

## Before You Start

Pull the NumKong, StringZilla, ForkUnion and SmashTable submodules before building anything, and put each on the branch `.gitmodules` names, so it tracks that branch instead of sitting on a detached commit:

```sh
git submodule update --init --recursive
git submodule foreach --quiet 'git switch --quiet "$(git config -f "$toplevel/.gitmodules" "submodule.$name.branch")"'
```

Later, bring every submodule to the tip of its branch before bumping the commits this repository records:

```sh
git submodule foreach --quiet 'git pull --ff-only --quiet'
```

`cmake/ucall_siblings.cmake` builds each submodule in place when it is checked out, and otherwise fetches the commit `ucall_sibling` pins for it.
A commit that moves a submodule moves its pin too, and the pre-commit hook refuses one where the two disagree.
Machine specifics such as a compiler path go into a gitignored `CMakeUserPresets.json`, whose presets inherit the ones in `CMakePresets.json`.

## Compiling C and C++

Building takes CMake 3.28 and a C++20 compiler.
Initialize the sibling submodules before configuring:

```bash
git submodule update --init --recursive
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
```

The `relwithdebinfo` and `release` presets build the same suites with optimization, `asan` and `tsan` build them under a sanitizer, and `check` builds every target with Clang and `UCALL_WERROR=ON`.
Tests, examples and benchmarks are off unless a preset or a `-D` switch asks for them.
StringZilla, ForkUnion, SmashTable, and the inference example's NumKong resolve from their submodules or pinned fetches; `FETCHCONTENT_SOURCE_DIR_STRINGZILLA`, `FETCHCONTENT_SOURCE_DIR_FORKUNION`, `FETCHCONTENT_SOURCE_DIR_SMASHTABLE`, and `FETCHCONTENT_SOURCE_DIR_NUMKONG` select existing checkouts.
The build exposes `ucall::static`, which the tests, tools, bindings and the Rust crate link, `ucall::shared`, `ucall::abi`, the C headers alone, and `ucall::cpp`, the C++ SDK linking the C headers and the archive.
`UCALL_WITH_POSIX`, `UCALL_WITH_LINUX_EPOLLAIO`, `UCALL_WITH_BSD_KQUEUE`, `UCALL_WITH_WINDOWS_IOCP`, and `UCALL_WITH_WINDOWS_RIO` take `AUTO`, `ON`, or `OFF`; `AUTO` leaves `c/ucall/types.h` to compile each queue where the target operating system has it, and the header refuses one forced on elsewhere.
`UCALL_WITH_LINUX_URING`, on for Linux, also links liburing, and a library or subproject build serves whichever compiled queue the host admits first.
CPU probes select separate instantiation units, each compiled at the floor like the dispatch code.
Each class unit compiles when StringZilla compiles and ForkUnion enables every capability it uses.
`UCALL_MARCH` raises the floor of UCall's own units to an ISA level, `native` or a CPU name like `graniterapids`, and hands the same value to the siblings.
`UCALL_MULTIVERSIONED`, on by default, compiles every class that exists, `serial` included, and picks among them at run time.
Off, it builds for one machine and compiles only the `monoversioned` class, over every capability the libraries enabled: what the floor implies and what a preset vouches for with `-D <LIBRARY>_TARGET_<CAPABILITY>=1`.
A `cpu_class_ceiling` below that class, or a machine below it, then fails as unsupported rather than running it.
The machine profiles `xeon4`, `xeon6`, `venice`, `grace` and `vera` set both, and CI compiles each of them, beside `android_arm64` over the `linux-epollaio` backend and `msvc2026_x64` with Visual Studio.
`CMAKE_C_COMPILER_LAUNCHER` and `CMAKE_CXX_COMPILER_LAUNCHER` come from the environment, so exporting `ccache` there caches objects in every tree.

`UCALL_BUILD_EXAMPLES=ON` enables `ucall_example_hello`, `ucall_example_echo`, `ucall_example_ledger`, `ucall_example_redis`, and `ucall_example_inference`; `UCALL_BUILD_BENCH=ON` enables `ucall_bench_http` and `ucall_bench_server`.
They share the command-line, polling and shutdown helpers in `tools/`, which every one of them has on its private include path.
`ucall_cli`, the `ucall` command-line client in `tools/`, builds with `UCALL_BUILD_TOOLS` and with any install, and `ucall_test_tools` drives it against an in-process server.
Executables go directly into the preset's build directory, such as `build_release/ucall_example_echo`.
`UCALL_BUILD_PYTHON=ON` builds the CPython extension that [Python builds](#python) package, and the root `Cargo.toml` builds the Rust crate, as [Rust builds](#rust) describe.

`cmake --install` installs `ucall::abi`, `ucall::static`, `ucall::cpp`, the `ucall` command-line client, the C and C++ headers, a CMake package and the license.
`UCALL_BUILD_SHARED=ON`, which the `release` preset sets, adds `ucall_shared` to the default build, and installs it beside the archive with a `ucall.pc`.
The shared library exports the `ucall_*` C interface alone, and the `release` preset remaps the source directory out of every binary.
A C program links either library, as CI's install job does with `examples/hello.c` through `find_package(ucall)` and through `pkg-config`.
CPack packs the `sdk` install component, which holds all of it, stripped, into `ucall-<version>-<platform>-sdk.tar.gz`:

```bash
cmake --preset release
cmake --build --preset release
cpack --config build_release/CPackConfig.cmake
```

### CPU Classes

Each class names one bundle of StringZilla kits, SmashTable row kit, ForkUnion waiter and atomic reference, with the values USearch, UStore and UForm give the same hardware.

| Value | Name            | What it adds                                                                         |
| ----: | --------------- | ------------------------------------------------------------------------------------ |
|     0 | `unknown`       | No ceiling: the newest class this machine runs                                       |
|     1 | `serial`        | Portable kits, standard atomics, yielding waits                                      |
|     2 | `monoversioned` | Whatever the floor and the preset compiled, the one class of a monoversioned build   |
|     3 | `intel-haswell` | AVX2 string kits and row scans, `PAUSE` waits                                        |
|     5 | `intel-skylake` | AVX-512 string kits and row scans over `intel-haswell`                               |
|     6 | `intel-icelake` | Ice Lake's AVX-512 extensions, SHA and its row scans over `intel-skylake`            |
|    11 | `intel-alder`   | SHA over `intel-haswell`, without AVX-512                                            |
|    12 | `aws-g2`        | NEON string kits with AES and SHA, NEON row scans, `YIELD` waits, LSE atomics        |
|    14 | `apple-m4`      | `WFET` timed waits over `aws-g5`; earlier Apple cores dispatch as `aws-g5`           |
|    15 | `aws-g5`        | `WFE` waits and RCpc atomics over `aws-g2`                                           |
|    17 | `alibaba-c930`  | RVV string kits and row scans, `WRS` waits, Zacas atomics                            |
|    18 | `ibm-power10`   | VSX string kits and row scans, `pause_short` waits, ISA 3.0 store atomics            |

`aws-g2` keeps LSE atomics, since every Graviton2 has them and UCall's hot path is atomics.
A compiled class must differ from its parent in a kit, waiter or atomic reference, and a `static_assert` in `make_network` refuses one that does not.
UCall has no GPU classes.

The pick reads StringZilla's and ForkUnion's detected masks, never their enabled ones, since UCall's class units compile their own kits.
A value no class takes fails with `invalid_argument`, as a misspelled name does in `ucall_cpu_class_from_name`.
A `cpu_class_ceiling` intersects the named class's masks with the detected ones, so a class the machine lacks caps the pick rather than refusing it, and `unknown` leaves the detected masks alone.
Construction takes the newest compiled class on the ladder whose masks fit that intersection, and fails with `unsupported` when none does, as a monoversioned build does on an older machine.
Resolved options report the class picked in the same `cpu_class_ceiling` field.

## Threads and Placement

The application's threads call the poll verbs, and UCall starts none of its own.
Each event loop owns one queue, which only the thread polling that loop touches.
Waits happen in the kernel, since a remote peer triggers the events a loop waits on, and a spin would burn a core for nothing.
UCall reports the network interface's memory domain in `ucall_network_interface_t::memory_domain` and places no thread or buffer itself.
The application pins its threads and picks their cores.

### Hardening

`.githooks/pre-commit` holds the rules here that a check on added lines can hold.

- No static, global, shared or thread-local pool, executor, queue set, stream or handle exists, stateless ones included: whoever needs one creates it and frees it.
- A C struct change lands with every binding that lays the struct out by hand, checked field by field in review.
- Tests never restate a struct's layout that the compiler already pins, so no binding asserts a mirror's size or offsets.
- A handler the engine may call from several threads at once is safe to call concurrently in every binding: route handlers, peer authorizers and log handlers.
- Every executor is equal; a handle owns its media, cache and epochs, never an executor, so no engine compares executor addresses to pick a path; the C layer may refuse an arena or plan used on another executor than its own.
- Names say who owns a thing and until when a view is valid; no identifier in any language hands a thing over.
- A fix lands on every residency and vendor that has the bug, or its message names the ones left and why.
- A commit message names only what its diff shows.
- A wave never re-wraps or rewords comments it does not otherwise touch.
- A commit touching `.cu`, `.cuh`, `.hip` or `.metal` names the box that built and ran it, or says none did.

## Code Rules

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
Endpoint callbacks execute synchronously on the polling caller, and batch callbacks on the batch endpoint's polling owner.
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

### Macros

Every all-caps name starts with the full project name, `UCALL_`.
A trailing `_` marks a name as internal: it may change in any release, and nothing outside this repository may define or test it.
A name without it is a public contract, either a switch you may set or a value you may read.

| Family                    | Form                           | Example                 |
| :------------------------ | :----------------------------- | :---------------------- |
| CPU class                 | `UCALL_TARGET_<CLASS>`         | `UCALL_TARGET_SERIAL`   |
| Optional facility         | `UCALL_WITH_[<OS>_]<FACILITY>` | `UCALL_WITH_BSD_KQUEUE` |
| Architecture fact         | `UCALL_ARCH_<ARCH>_`           | `UCALL_ARCH_ARM64_`     |
| Operating-system identity | `UCALL_OS_<OS>_`               | `UCALL_OS_POSIX_`       |

Every name in these families is always defined, as 0 or 1, and tested with `#if`.
`defined(...)` appears only in a `!defined` default and in a guard that an `#error` follows.
A kernel facility, like `UCALL_WITH_WINDOWS_IOCP`, defaults from the identity, while `UCALL_WITH_LINUX_URING` defaults to 0, and the target that links liburing sets it.
Only the Platform Identity region of `c/ucall/types.h` reads operating-system predefines like `__linux__`.
Compiler predefines like `__clang__`, `__GNUC__` and `_MSC_VER` are read raw where they matter.

### Capacities and Bounds

Derive storage from a caller's admission budget, protocol geometry, or an actual operating-system or hardware property.
An I/O transfer limit segments an operation; it does not become a message-size limit.
Exhausted resources apply backpressure or report allocation failure rather than truncating input.
Do not tune constants until one benchmark looks good.

### Statuses

Statuses 0 to 19 keep the same numbers and meanings in every Unum library: success 0, deferred 1, out_of_memory 2, shape_mismatch 3, unsupported_layout 4, unknown_kind 5, read_only 6, io 7, device 8, malformed 9, internal 10, overflow 11, uninitialized 12, config_mismatch 13, contended 14, cancelled 15, unsupported 16, invalid_argument 17, not_found 18, already_exists 19.
A library leaves out the ones it cannot answer but never renumbers the rest, and numbers its own statuses from 20.
Every enum the C interface names, statuses included, has a `ucall_*_name` answering "unrecognized" for a value it does not know and a `ucall_*_from_name(view, &out)` answering `invalid_argument` for a name it does not know, leaving `out` as it was.
CPU and GPU class values are ABI: each class keeps the number USearch gives the same hardware, written explicitly, with unused numbers reserved rather than reused.
`ucall_version_name` answers the full version, pre-release suffix included, in the engine and in the stub alike.

### Notes

A failure's C outcome carries a static message: the static name of what broke, such as a tunnel fault's name, else the status's own `ucall_status_name`.
The SDK in `cpp/` keeps the same `status_t {code, note}` as the other `U*` SDKs, so a status reads alike everywhere: recovery branches on the code, and the note names the broken invariant, step or resource for logs.
A note is 2 to 8 words in sentence case with no closing period, never restates the code, and never carries a value that differs per call, such as a path, an error number, a size or an identifier.

### Refusals

A call the library cannot run answers one status, picked by what is wrong, in this order: `invalid_argument`, `read_only`, `config_mismatch`, `unsupported`, `contended`, `overflow`.
A `NULL` handle the call operates on answers `uninitialized` before any of them.
A malformed argument or list, one that is empty, `NULL` or names a handle twice, answers `invalid_argument`.
A write to a handle opened read-only answers `read_only`.
Handles of another kind, or of a geometry the call cannot join, answer `config_mismatch`.
A well-formed case nothing implements yet, like several event loops on one IOCP interface, answers `unsupported`.
An option the library cannot honour is refused with `unsupported`, never ignored.
A handle another call holds answers `contended` rather than waiting, and a size past its counter answers `overflow`.
A refusal moves nothing: every output and handle reads as it did before the call.
Each header lists a verb's refusals under `@par Statuses` in this order and in these words, and the stub library answers every one of them.

### Query Views

A batched kernel takes its queries as one flat transparent view over a static extent, like a `std::array` of views sized by the batch's extent, never as a span of pointers it chases one query at a time.
A query type that owns packed storage exposes a view of it, and the kernel reads that view.
`.githooks/pre-commit` refuses a `std::span` of pointers to const under `include/`, except a span of C strings, which names things rather than batching queries.

### Compile-Time Choices

Code picks between alternatives at compile time through three gates, each for one kind of choice.

`#if` picks a toolchain or a platform, and nothing else.
A feature the compiler or the operating system lacks is a `#if`; a choice between two algorithms is not.

```cpp
#if defined(_WIN32) // allowed: the platform decides
using file_handle_t = void*;
#else
using file_handle_t = int;
#endif
```

A `requires` clause picks an overload when a whole function differs.
Every constrained overload has an unconstrained fallback beside it, so a type the constraint rejects still finds a function.

```cpp
template <typename index_type_>
status_t run_plan(index_type_& index) noexcept requires is_nvme_index<index_type_> { /* NVMe rounds */ }

template <typename index_type_>
status_t run_plan(index_type_& index) noexcept { /* every other residency */ }
```

`if constexpr` branches on a named concept or a `constexpr bool`, one level deep.
An `else if constexpr` chain is still one level.

```cpp
template <typename query_type_>
concept a_hinted_query = requires(query_type_& query) { query.find_hinted(0u); };

if constexpr (a_hinted_query<query_type_>) seeds = query.find_hinted(shard); // allowed: a named concept
else if constexpr (serial_class_k) seeds = {};                               // allowed: one chain, one level
```

The hook refuses each of these, in the directories its `gated_source_directories` names:

```cpp
if constexpr (requires { query.find_hinted(0u); }) { /* ... */ }   // refused: name the probe as a concept

if constexpr (is_ram_k) {
    if constexpr (is_serial_k) { /* ... */ }                        // refused: a second choice inside the first
}

template <typename value_type_, typename = std::enable_if_t<std::is_integral_v<value_type_>>>
value_type_ clamp(value_type_ value) noexcept;                      // refused: write `requires` on the overload

struct sorted_tag_t {};
void insert(entry_t entry, sorted_tag_t) noexcept;                  // refused: a tag that only picks an overload
```

Control flow nests at most three deep: `if`, `for`, `while`, `switch`, `do`, `try` and `catch` each count, and so does `if constexpr`.
An `else` or `catch` body sits at its `if`'s or `try`'s depth, so an `else if` chain stays flat.
A body without braces counts like a braced one, while a lambda or a plain block adds nothing.
Both sides of a `#if` count from the depth the `#if` began at.

```cpp
for (shard_t& shard : shards)                       // 1
    for (node_t node : shard.nodes)                 // 2
        if (node.live)                              // 3
            while (node.next != end) step(node);    // refused: 4 deep
```

To flatten, return early from failures, extract the inner loop into a function named for what it does, or split an overload per case.

The checks are `check_constexpr_conditions_named`, `check_constexpr_branches_flat`, `check_enable_if_and_tags_absent` and `check_constexpr_nesting`.
They judge only the lines a commit adds, so existing code flattens as it is touched.

### Split String Literals

A string literal split across lines by hand ends every fragment but the last with a trailing `//`.
Without the pin, clang-format joins the fragments or restacks them into a staircase.
This holds in C, C++, CUDA and HIP sources alike.

```cpp
char const help[] =                                 //
    "Usage: probe [options]\n"                      // allowed: every fragment but the last is pinned
    "Runs one probe.\n";

char const help[] = "Usage: probe [options]\n"
                    "Runs one probe.\n";            // refused: the first fragment is unpinned
```

The check is `check_split_string_literal_pinned`.
A comment that explains the line pins it just as well, and a bare `//` on a member line is not taken for a member's documentation.

### Vocabulary

One word names each concept, here and in every Unum project; the right column lists the words it replaces.

| Concept                                                          | Word                                  | Refused                                       |
| :--------------------------------------------------------------- | :------------------------------------ | :-------------------------------------------- |
| a kind of work in a plan, ended by a barrier                     | phase                                 | stage, step, pass                             |
| the same work again, counted                                     | repetition, named for what repeats: round, depth, nesting | phase, pass       |
| an independent unit of one phase, run by any thread in any order | task                                 | step, chunk                                   |
| sequential work                                                  | step                                  | task                                          |
| a per-capability kernel bundle                                   | kit                                   | trait                                         |
| a compiled alternative per class, dtype or residency             | variant                               | arm, cell                                     |
| RAM, VRAM or NVMe                                                | residency                             | home, memory side                             |
| one thread's kernel transport                                    | queue                                 | engine, lane                                  |
| memory a view points into                                        | its owner and the call it stays valid until | lend, lent, borrow, loan, lease         |
| an exported operation and its table entry                        | verb; trampoline                      | …                                             |
| a fixed-shape collection a verb fills                            | outputs                               | landing, lander                               |
| a member of a plan, cursor or walk                               | what it holds and when it holds it    | bits, current, state, data, flags, tmp, scratch |

`.githooks/pre-commit` refuses the hand-over words in identifiers, split on underscores and camelCase, in C, C++ and every binding language, with comments, docstrings and string literals blanked; Rust's `std::borrow` names stay.

### Comments and Formatting

Public C and C++ contracts use Doxygen tags; Python public functions and modules describe their purpose in docstrings.
A closing `@par Statuses:` block lists only the statuses a verb's contract adds, while resource failures, deferral and defects are covered once by the categories in the `ucall_status_t` docblock.
A code comment explains a non-obvious reason rather than narrating an operation.
Keep source headers, attribution, and original creation dates consistent with the file's history.

Begin each Markdown sentence on a separate source line and align table columns.
Run `dprint fmt` for Markdown, `clang-format` for C and C++, Ruff for Python, and `cargo +stable fmt` for Rust.
The staged-file hooks check these conventions and reject template suffixes even with brace initialization.

### Review and Measurements

A commit message explains the resulting behavior, why the change matters, and how it was checked.
Stage a concrete review candidate with a proposed title and body; staging does not authorize committing.
Performance reports name the backend, CPU class, build, placement, workload, admission budgets, and load generator.
Traced timings explain costs and are not throughput measurements.

## Lean State

A type holds only what it cannot recompute, and names each part for what it holds.
These rules are shared by every sibling library, and the pre-commit hook enforces each rule that names a check.

- Members are named for what they hold, never for their type.
  Write `request->call` or `call->kept`, never `call->call` or `file.file`.
  Checked by `check_self_repeat_access`.
- Derived state is a method, not a field.
  A count, mask or capacity that follows from other members is computed when asked, so it can never disagree with them.
- One fact, one constant.
  Every `_k` constant states its derivation in its docblock, or says "measured" and where, and no other constant restates it.
- An owner that never moves holds its parts by value.
  A pointer is for a part that outlives its owner, moves apart from it, or is shared beyond it.
- Empty allocators take no bytes.
  An allocator member is declared `[[no_unique_address]]`, so a container over a stateless allocator is no larger than its own state.
  Checked by `check_empty_member_bytes`.
- No wrapper without its own state or invariant.
  A type that only forwards to one member is a name for that member, so use an alias or a function instead.
- Concepts are `a_`/`an_` noun phrases.
  A concept names what satisfies it, as `an_allocator` or `a_task_callback`: `an_` before a vowel sound, singular, with no `is_` or `has_` prefix and no `_concept` or `_t` suffix.
  Checked by `check_concept_names`.

## Test Suites

### Principles

Tests call the public surface: the C interface and the C++ headers under `include/ucall/`, and each binding its own package; [Private Surface Waivers](#private-surface-waivers) lists the exceptions.
Oracles never compile out: every C and C++ test unit opens with `#undef NDEBUG // ! A test's oracle must stay live in every build`.
The harness owns the output: a case only checks, and the run prints its verdict, every failed check, a `rerun:` line and the summary.
Skips are honest: a case that cannot run says why, `UCALL_NO_SKIPS=1` turns any skip into a failing exit, and a filter that selects nothing fails the run.
Every reason takes one of four forms: `needs <resource>`, `built without <SWITCH>`, `<facility> is refused on this machine` or `no <device>`.
Sweeps are full by default: a case runs on every backend, and one whose subject sits above the I/O backends opts out by name with `any_backend`.
Settings are read once, from `UCALL_<NAME>` variables that a `--name` flag of the same name overrides, and a value that does not parse prints one line and exits 1.
Inputs come from streams that `stream_key` derives from the seed and the case's name, bit for bit alike in C, C++, Rust, Python and Mojo, so a filtered run draws what an unfiltered one did.
The native harness holds one mutable global, `test_run`, the documented exception to owning every mutable object.
Checks fail on worker threads and inside helpers as well as in a case's own body, so the run counts failed checks in one place and `run_test_case` diffs that count around each case, rather than threading a tally through every call.
After a crash, `p test_run` in a core dump names the case in progress and the last failed check, and the signal handlers print the case too.

### Running

Native suites live in `test/`, mirroring `include/ucall/`, the C caller in `c/test.c`, and benchmark clients in `bench/`.
`ucall_test` runs the outcome word, every queue and the network cells, `ucall_test_header_only` the parsers and the tunnel, and `ucall_test_tools` the command-line client; each ctest is named after its executable.
`UCALL_BUILD_STUB=ON` builds `src_stub/`, a stand-in for the C interface that validates every call and serves no network, and `ucall_test_c_stub`, the same `c/test.c` linked against it; the stand-in runs only the serial CPU class.
`ucall_test` sweeps a diagonal of cells: every compiled backend at the best CPU class in plaintext, every class the machine runs on the first backend, and each Noise pattern on the first backend.
`--backend` and `--cpu-class-ceiling` narrow the sweep to one backend or class, and a ceiling above what the host runs skips rather than sweeping the lower class it resolves to.

```bash
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
UCALL_FILTER=ucall_io_backend_linux_uring618_k UCALL_SCALE=0.1 build_debug/ucall_test
```

Each binary prints the build, the machine and its settings, then one verdict per case and a summary:

```text
UCall <version>
- Compiled for: …
- This machine: …
- Seed: 42, scale: 1, filter: none
- <label> ... ok (0.12 s)
- <label> ... skipped: <reason>
- <label> ... FAILED: 1 failed check(s)
  check failed at test/network/exchanges.cpp:120
    expected 200, got 500
  rerun: build_debug/ucall_test --seed 42 --filter '^<label>$'
41 passed, 1 failed, 3 skipped, seed 42
```

Verdicts and the summary go to stdout, failed checks and `rerun:` lines to stderr.
A run exits 1 when a case failed, a check failed outside any case, or nothing ran, 3 when `UCALL_NO_SKIPS` is set and a case skipped, and 0 otherwise.
Under a debugger, `UCALL_TRAP_ON_FAILURE=1` stops at the first failed check; without one, the trap dumps core.

The Python suites, `test/server.py`, `test/client.py` and `test/readme.py`, take their hooks and fixtures from `test/conftest.py` and their settings and backends from `test/base.py`; pytest's header prints the same `- Seed:` line, and pytest's own `-k` and node IDs select cases.
Rust tests sit in each module of `rust/`, and the Mojo suite in `mojo/test.mojo`.

```bash
python -X faulthandler -m pytest -x
python -m pytest -k readme
cargo test
pixi run test
```

### Environment

| Variable                      | Flag                      |        Default | Meaning                                                                                           |
| :---------------------------- | :------------------------ | -------------: | :------------------------------------------------------------------------------------------------ |
| `UCALL_SEED`                  | `--seed`                  |           `42` | Seed of every input stream, any unsigned 64-bit value, or `random` to draw one                    |
| `UCALL_FILTER`                | `--filter`                |          unset | Regex searched in C++ case labels and benchmark rows                                              |
| `UCALL_SCALE`                 | `--scale`                 |            `1` | Positive factor on the iteration counts of native sweeps, like `0.1` for a quick pass             |
| `UCALL_TRAP_ON_FAILURE`       | `--trap-on-failure`       |          unset | Any value but `0` traps into the debugger at the first failed check                               |
| `UCALL_NO_SKIPS`              | `--no-skips`              |          unset | Any value but `0` exits 3 when a case skipped, for runners that must cover every cell             |
| `UCALL_BACKEND`               | `--backend`               |  every backend | One backend to sweep, by its library name, like `linux-uring618`                                  |
| `UCALL_CPU_CLASS_CEILING`     | `--cpu-class-ceiling`     |    every class | One CPU class to sweep, by its library name, like `aws-g2`                                        |
| `UCALL_TEST_DIRECT_DIRECTORY` | `--test-direct-directory` |     build tree | Where cases make the directories their `O_DIRECT` files live in, since `/tmp` is often tmpfs      |

The flags reach the native binaries only.
Python reads `UCALL_SEED`, `UCALL_SCALE` and `UCALL_TEST_DIRECT_DIRECTORY`, falling back to pytest's `tmp_path` for the last; Rust reads `UCALL_SEED` and `UCALL_TEST_DIRECT_DIRECTORY`, falling back to the test binary's directory.

### Writing a Test

A native case is `void test_<behaviour>(args…)`, or `case_result_t test_<behaviour>(args…)` when it may skip, and takes no settings: it reads them from `test_run.settings`.
`main` prints the machine, calls `start_test_run(argc, argv)`, registers each case as `run_test_case("<label>", test_<case>, args…)` and returns `finish_test_run()`.
A label names the code under test and nothing else: a C symbol such as `ucall_server_init`, a qualified C++ name, or the case function's own name, `test_<case>`, and for a runtime choice that function called over the choice's exact constants, as in `test_network_cell(ucall_io_backend_linux_uring618_k, ucall_cpu_class_aws_g2_k, ucall_security_none_k)`.
Checks count a failure at the caller's line without stopping and return whether they held: `expect_true(held)`, `expect_equal(actual, wanted)`, `expect_near(actual, wanted, tolerance)`, `expect_status(status, wanted)`, `expect_equal_bytes(actual, wanted)`, which prints both in hex, and `expect_throws<E>(callable)`.
Context trails as a format string and its arguments, `expect_true(held, "setup: {}", ucall_status_name(status))`, printed under the failing line, and `if (!expect_true(…)) return;` stops a step that would be unsafe.
A case that cannot run returns `case_result_t::skipped(reason)`, its only way to skip.
Inputs come from `split_mix_generator_t generator {case_stream_key()}`, iteration counts from `scaled_iterations(count)` and sweep steps from `sweep_stride(coverage)`, and every wait goes through `spin_until(predicate)`, which `wait_limit_k` bounds.
`c/test.c` registers each case between `start_test_case(label)` and `finish_test_case(skip_reason)`, checks with `expect_(condition)` or `expect_at(held, __FILE__, __LINE__, message)`, and prints the same lines, without a time.

A Python test is `test_<subject>_<behaviour>`, read as a sentence, with a one-line docstring.
A test taking `backend` runs on every backend, and `@pytest.mark.any_backend` runs it once on `Backend.AUTOMATIC` instead, as for argument binding and reply serialization, which sit above the C interface.
`loopback`, `serving`, `direct_directory`, `unraisable`, `seed` and `rng` are the fixtures in `test/conftest.py`; skips happen only in fixtures and collection marks, and `MAX_CASES_PER_TEST` in `test/base.py` caps the cases one test expands to beside its backends.
Rust tests are named as behaviour sentences without a prefix, return `()`, and call `.unwrap()`; `rust/testing.rs` holds the seed, stream and scratch-directory helpers every sibling library shares, then UCall's loopback servers and clients, and a test that cannot run calls `return skipped("…")`.
A Mojo test is a `test_<behaviour>` registered in `main`, and one that cannot run calls `_skipped(reason)`.
The README Quickstarts are tests too: Python's and Mojo's `test_readme_quickstart` run theirs, Rust's runs as the crate's doctest, and the `test_readme_<language>_mirror` tests of `test/readme.py` hold every other README block to its program.

### Benchmarks

`bench/http.cpp` is UCall's load generator, and the `bench/*_server.*` files are the servers it drives, UCall's and other frameworks', as [bench/README.md](bench/README.md) explains.
Each flag of the load generator reads its default from `UCALL_<FLAG>`, so `UCALL_TIME_LIMIT=10s` stands in for `--time-limit 10s`, and the command line overrides it.
It prints the build, the machine and its settings as `- Name: value` lines before its rows, and its timing tables keep their own layout.

### Devices

UCall drives no accelerators: its suites sweep I/O backends and CPU classes, and the hosts below run the classes and platforms the build machine lacks.

#### Arm on an x86 Host

`cmake/toolchain-aarch64-llvm.cmake` cross-compiles with the host's Clang and LLD, and `ctest` runs each suite under `qemu-aarch64 -cpu max`, which enables every feature the Arm CPU classes ask for.
`--cpu-class-ceiling` selects one, and `llvm-objdump -d` on its unit, such as `variants_aws_g2.cpp.o`, shows the instruction every atomic lowered to.
QEMU's user mode has neither io_uring nor Linux AIO, so those cells skip.

```bash
cmake -B build_aarch64 -D CMAKE_TOOLCHAIN_FILE=cmake/toolchain-aarch64-llvm.cmake -D UCALL_BUILD_TEST=ON
cmake --build build_aarch64
ctest --test-dir build_aarch64
qemu-aarch64 -L /usr/aarch64-linux-gnu -cpu max build_aarch64/ucall_test --backend posix --cpu-class-ceiling aws-g2
```

#### RISC-V and Power on an x86 Host

The `linux_riscv64` and `linux_ppc64le` presets cross-compile with GCC, and `ctest` runs each suite under QEMU on a core that admits the `alibaba_c930` or `ibm_power10` class.
RISC-V needs GCC 16, as GCC 15 crashes on StringZilla's RVV kernels, and Power needs GCC 15.

```bash
cmake --preset linux_ppc64le
cmake --build --preset linux_ppc64le
ctest --preset linux_ppc64le
qemu-ppc64le -L /usr/powerpc64le-linux-gnu -cpu power10 build_linux_ppc64le/ucall_test --backend posix --cpu-class-ceiling ibm-power10
```

#### Windows, FreeBSD and macOS on a Linux Host

The IOCP and kqueue backends compile on Linux with the host's Clang through one toolchain file each, which name a sysroot and nothing else; their suites run on the platforms themselves.

```bash
cmake -B build_mingw -D CMAKE_TOOLCHAIN_FILE=cmake/toolchain-x86_64-mingw-llvm.cmake -D UCALL_BUILD_TEST=ON  # needs g++-mingw-w64-x86-64-posix
cmake -B build_freebsd -D CMAKE_TOOLCHAIN_FILE=cmake/toolchain-x86_64-freebsd-llvm.cmake -D UCALL_BUILD_TEST=ON \
    -D UCALL_FREEBSD_SYSROOT=/path/to/unpacked/base.txz
cmake -B build_macos -D CMAKE_TOOLCHAIN_FILE=cmake/toolchain-x86_64-macos-llvm.cmake \
    -D UCALL_MACOS_SDK=/path/to/MacOSX.sdk
cmake --build build_macos --target ucall_static
```

Windows and FreeBSD link their test executables; macOS stops at the static library, since linking needs Apple's linker.

### Private Surface Waivers

These test units include a header the public surface does not cover:

- `test/network.hpp`, `test/network/client.cpp`, `test/network/loops.cpp` and `test/network/resolving.cpp` include `src/variants.hpp` for `io_queues_t` and `network_t`, the queue and network of each CPU class, which the C interface hides behind its handles.
- `test/io/queues.hpp` includes `src/lib.hpp` for `cpu_class_t` and the kits each class picks, which the queue tests instantiate one class at a time.

### Fuzzing

`test/properties.hpp` holds one oracle per parser that reads untrusted bytes, each copying its input into a heap block of exactly its size so AddressSanitizer catches a read past it.
`ucall_test_header_only` drives them from seeded mutations of valid inputs, and the `fuzz` preset builds a libFuzzer harness over each with Clang, AddressSanitizer and UndefinedBehaviorSanitizer:

- `ucall_fuzz_http`: request and response framing, whole against cut into pieces and streamed.
- `ucall_fuzz_multipart`: `multipart/form-data` splitting against a linear reference.
- `ucall_fuzz_routes`: the route trie against a linear matcher with literal, parameter and wildcard precedence.
- `ucall_fuzz_url`: URL parsing round trips, and relative redirects that never leave their origin.
- `ucall_fuzz_dns`: the stub resolver's answer decoder.
- `ucall_fuzz_tunnel`: Noise responders fed hostile first messages, and records whose flipped bytes must never open.

```bash
cmake --preset fuzz
cmake --build --preset fuzz
mkdir -p corpus && build_fuzz/ucall_fuzz_routes -max_total_time=60 corpus
```

CI runs each harness for five minutes with the run number as its seed and keeps what a failing one found.

### Model Checking

`verification/` holds Spin models of the protocols replies cross threads by, each naming its expected verdicts in `@verify` lines, including the mutants that must fail.
`check.sh` runs them through ForkUnion's runner, which also brings `weak_memory.pml`, its model of the C++ memory model for Spin, and runs GenMC clients when `GENMC` names its executable.
It takes ForkUnion from the `forkunion` submodule, or from the checkout `FORKUNION_SOURCE` names.

```bash
git submodule update --init forkunion
./verification/check.sh
./verification/check.sh segment_links.pml
```

## Bindings

Every binding is a thin layer over the C interface, and these rules hold in each of them.
Typed bindings are those whose compiler checks callback signatures, and dynamic bindings are the rest; in UCall the typed ones are Rust and Mojo, and the dynamic ones are Python.

The C library decides what is valid.
A binding forwards its status, turns each status into its language's error in one place, re-checks nothing the library refuses, and keeps no copy of state the library already holds.
Name tables come from the library's `ucall_*_name` and `ucall_*_from_name` pairs, never from a switch written in the binding.

One mechanism reports every outcome: `ucall_outcome_status` reads it without waiting, and `ucall_outcome_wait` parks until it is final.
Nothing in a binding takes a lock, sends a notification or adds synchronization of its own.
The object that submitted a deferred call is the only one that polls its outcome, so no other thread ever waits on it, and whatever a second caller asks, the library answers.
A blocking `wait` calls `ucall_outcome_wait`.
An asynchronous bridge never parks a thread: it reads `ucall_outcome_status` and, while the call is deferred, yields to its runtime.
A runtime that can reschedule a task reads again on its next turn with no sleep, like Python's `loop.call_soon`, a C++ scheduler's `post(poll, state)` and Mojo's runtime, while one that resumes only on a timer pauses with a backoff growing from about 1 µs to 1 ms, like Swift's `Task.sleep`, JavaScript's `setTimeout` and C#'s `Task.Delay`.
A Rust future yields only: `poll` reads the status and, while it is deferred, calls `wake_by_ref` and returns `Poll::Pending`, with no sleep and no timer thread.

A callback never raises into the library.
Its fault never unwinds through C frames and never waits in a latch for the call to end: typed bindings give their callback types no way to throw, like a `noexcept` C++ callback type, while dynamic bindings report the fault through their language's unraisable path, like Python's `sys.unraisablehook` and JavaScript's uncaught-exception handler, and the callback answers cancel.
A Rust callback that panics aborts the process, as Rust does for any unwind reaching an `extern "C"` frame; nothing catches the unwind.
A binding that hands the library no callback of its own has nothing to report.

A view the library hands back lives until the next call on its arena.
The library describes where the memory sits, and the caller checks it; the binding neither copies the view to be safe nor checks its residency on the caller's behalf.

Every array a verb reads shares the call's one count, so mismatched shapes cannot be expressed.
Where a binding's own types hold two lengths, like a slice of keys beside a matrix of values, it checks once that they agree before the call crosses into the library, and nowhere else.

Each verb has one body, which fills the C struct and calls the library with no layers in between.
What it returns is read from the struct's output slot, a trampoline receives the handler itself as its state with no hub around it, and whether a call blocks or defers follows from the type of the receiver it is called on, never from a flag.
Verbs are never shared through a base class; a trait whose default methods hold the one body per verb is fine, like Rust's and Mojo's, since each receiver supplies only its handle, and C++ writes each handle and its receivers as one class template over what the receiver holds, so the handle carries the verbs as Rust's `&Handle` does.

A typed binding takes the scalar as a type parameter of each call, like USearch's `search::<f32>`, rather than letting a handle's type fix one.
A deferred Rust call owns what the library reads until the call is final, since the borrow checker cannot see the library holding it.
A C++ wrapper over the C interface is a full typed binding: it has a deferred receiver, `noexcept` callback types and per-call scalar templates.

A dynamic binding publishes every field of every report the library fills.
A type the binding hands to C by cast, like a slice of parts passed as the C array, is a transparent wrapper over the C struct, like Rust's `#[repr(transparent)]` newtype, so the cast is sound by construction and nothing asserts its size or alignment.
Tests never restate a struct's layout that the compiler already pins: no `offset_of!`, `size_of`, `MemoryLayout` or `Marshal.SizeOf` asserts against the C structs; `offsetof` tables that declare members are declarations, not tests.
Tests of how names print and parse, and of a queue run again through the binding, stay.
A binding test asserts a status, or the exception or error type mapped from it, and never the wording of a message or note, in any language: no pytest `match=`, no comparison of `error.message`, `err.Error()` or a note's text, and no substring search in them, since engines refine their notes over time.

A callback crosses as the C struct it lowers to, built by one generic constructor per handler shape with a trampoline made per handler type, never a trait object, a box or an enum.
A reply that may finish after the handler returns writes into a slot the caller keeps, a `deferred` in C++ and a pinned `Deferred` in Rust, so the polling thread never blocks on it and nothing is boxed.

`.githooks/pre-commit` refuses locks in binding sources, throwing callback types, caught unwinds and kept exceptions.

## Python

`pyproject.toml` builds with `scikit-build-core`, which configures the top-level CMake tree with `UCALL_BUILD_PYTHON=ON` and installs the `ucall_python` target, the extension `ucall.lib`, into the `python/ucall/` package.
`python/lib.c` holds the module and the shared argument parsing, `json.c` turns JSON bodies into Python objects, and `types.c`, `server.c`, and `client.c` wrap the types, the server, and the client.
The build tree lives in `build_python/<wheel_tag>`, and an editable install recompiles only when the install command runs again.

```sh
uv venv .venv && source .venv/bin/activate
uv pip install scikit-build-core ninja pytest
uv pip install --no-build-isolation -e .
python -X faulthandler -m pytest
```

## Rust

The root `Cargo.toml` builds the crate from `rust/lib.rs`, and `build.rs` compiles the native library through CMake.
`UCALL_LIBRARY_DIR`, naming the directory of a `libucall_static.a` CMake already built, links that archive and the system's liburing instead.
`rust/types.rs`, `server.rs`, and `client.rs` mirror the Python sources, each module keeps its tests in `mod tests`, and `rust/testing.rs` holds their shared helpers.

```sh
cargo test
cargo clippy --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
```

## Commits

`.githooks/commit-msg` checks every message:

- The title reads `<Verb>: <Summary>`, where the verb is one of `Add`, `Break`, `Chore`, `Docs`, `Fix`, `Improve` or `Make`.
- The summary opens with a capital letter, unless it opens with a code identifier, which keeps its own case.
- The title runs to at most 80 characters, and a body line to at most 100 columns, unless it holds a URL or is indented code.
- The message includes no AI-assistant attribution, since authorship is the human who committed.
- `Break` marks a change to what the project offers, such as a dropped modality or binding; `Chore` removes or rearranges without changing it.
- The body is prose wrapped near 80 columns and explains the change in primary logic, not renames or formatting.
- One commit per topic, however many files it touches; an intermediate commit may leave the tree unbuildable.

Git's merge, `fixup!` and `squash!` titles are exempt from the title rules.
A `Release: vX.Y.Z` title is exempt too, but its commit must stamp every version site, and no other commit may change `VERSION`.
`.githooks/pre-commit` formats and judges the staged lines, and `.githooks/selftest` runs both hooks against their fixtures.
On a pull request, `.github/scripts/check-commits.sh` replays `commit-msg` over every commit and runs `pre-commit` over the whole range.

## Releases

`.github/scripts/mint-release.sh X.Y.Z` cuts a release from a clean checkout of the branch it ships.
It stamps every version site and commits `Release: vX.Y.Z`.
`.github/scripts/check-release.sh` then checks that commit, even in a clone where `core.hooksPath` is unset, before the script tags it and pushes both.
Then it publishes the GitHub release, marking `X.Y.Z-rc.N` candidates as prereleases.
Publishing starts every `release-<binding>.yml` at once, and each runs `check-release.sh` before it builds anything, so each registry trusts only its own binding's file.
