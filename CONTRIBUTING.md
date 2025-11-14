# Contributing to UCall

Thanks for coming here!
For coding guidelines, please refer to [ashvardanian/CONTRIBUTING.md](https://github.com/ashvardanian/ashvardanian/blob/master/CONTRIBUTING.md).

## Compiling C++ Code

Release build:

```bash
cmake -D CMAKE_BUILD_TYPE=Release -B build_release -D UCALL_BUILD_TESTS=1
cmake --build build_release --config Release --parallel
build_release/ucall_test_posix
```

Debug build for the test suite:

```bash
cmake -D CMAKE_BUILD_TYPE=Debug -B build_debug
cmake --build build_debug --config Debug --target ucall_test_posix
build_debug/ucall_test_posix
```

### Running Tests

Run all tests:

```bash
build_debug/ucall_test_posix
```

Run specific test suites:

```bash
build_debug/ucall_test_posix --gtest_filter="upsert_and_find*"
build_debug/ucall_test_posix --gtest_filter="transaction_*"
build_debug/ucall_test_posix --gtest_filter="*with_threads"
```

Brief output:

```bash
build_debug/ucall_test_posix --gtest_brief=1
```

List available tests:

```bash
build_debug/ucall_test_posix --gtest_list_tests
```

## Compiling Python Bindings

Python bindings are implemented using pure CPython, so you wouldn't need to install SWIG, PyBind11, or any other third-party library.
Still, you need a virtual environment, and it's recommended to use `uv` to create one.

```bash
uv venv --python 3.14t                  # it's recommended to use a recent free-threading version
source .venv/bin/activate               # to activate the virtual environment
uv pip install setuptools wheel         # to pull the latest build tools
uv pip install -e . --force-reinstall   # to build locally from source
```
