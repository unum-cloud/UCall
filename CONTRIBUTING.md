# Contributing to UCall

For coding guidelines, refer to [ashvardanian/CONTRIBUTING.md](https://github.com/ashvardanian/ashvardanian/blob/master/CONTRIBUTING.md).
Configuring a source checkout enables the hooks in `.githooks/`.
They check staged additions, Doxygen and docstring structure, imports, naming, and language formatting.

## Compiling C and C++

```bash
cmake --preset host_debug
cmake --build --preset host_debug
ctest --preset host_debug
```

The `host_relwithdebinfo` and `host_release` presets build the same suites with optimization.
StringZilla resolves from its submodule or a pinned fetch; `FETCHCONTENT_SOURCE_DIR_STRINGZILLA` selects an existing checkout.

## Running Tests

Native suites live in `test/`, the C caller in `c/test.c`, and benchmark clients in `bench/`.
`UCALL_SEED` selects an unsigned 32-bit seed or `random`, `UCALL_FILTER` selects cases, and `UCALL_MULTIPLIER` scales native sweeps.

```bash
UCALL_FILTER=records UCALL_MULTIPLIER=0.1 ctest --preset host_debug
```

The Python integration suites in `test/` require the example servers they exercise.
