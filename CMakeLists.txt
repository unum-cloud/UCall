cmake_minimum_required(VERSION 3.20 FATAL_ERROR)
project(
  ucall
  VERSION 0.5.5
  LANGUAGES C CXX
  DESCRIPTION
  "Up to 100x Faster FastAPI. JSON-RPC with io_uring, SIMD-acceleration, and pure CPython bindings"
  HOMEPAGE_URL "https://github.com/unum-cloud/ucall")

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS NO)

# Detect software capabilities before setting options
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  execute_process(
    COMMAND uname -r
    OUTPUT_VARIABLE UNAME_RESULT
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  message(STATUS "Linux Kernel version: ${UNAME_RESULT}")
  string(REGEX MATCH "([0-9]+)\\.([0-9]+)" _ ${UNAME_RESULT})
  set(LINUX_MAJOR_VERSION ${CMAKE_MATCH_1})
  set(LINUX_MINOR_VERSION ${CMAKE_MATCH_2})

  # Combine major and minor version numbers into one for comparison
  set(LINUX_VERSION "${LINUX_MAJOR_VERSION}.${LINUX_MINOR_VERSION}")
  message(STATUS "Parsed Linux Kernel version: ${LINUX_VERSION}")

  # Check if the Linux kernel version is 5.19 or newer
  if(${LINUX_VERSION} VERSION_GREATER_EQUAL "5.19")
    set(SUPPORTS_IO_URING ON)
  else()
    set(SUPPORTS_IO_URING OFF)
  endif()
endif()

# Set the default values for options based on whether io_uring is supported
option(UCALL_BUILD_LIB_POSIX "Builds the C library for the `posix` backend" ON)
option(UCALL_BUILD_PYTHON_POSIX
  "Builds CPython bindings for the `posix` backend" ON)

# Options depending on SUPPORTS_IO_URING
option(UCALL_BUILD_LIB_URING "Builds the C library for the `uring` backend"
  ${SUPPORTS_IO_URING})
option(UCALL_BUILD_PYTHON_URING
  "Builds CPython bindings for the `uring` backend" ${SUPPORTS_IO_URING})

option(UCALL_BUILD_BENCHMARKS
  "Builds all available backend for the summation server to run benchmarks"
  OFF)
option(UCALL_BUILD_EXAMPLES
  "Builds examples for Redis-like server and PyTorch deployment" OFF)
option(UCALL_BUILD_TESTS "Builds unit tests for the C library" OFF)
option(UCALL_BUILD_ALL "Builds all supported target" OFF)

# Enforce options based on SUPPORTS_IO_URING after its value is known
if(SUPPORTS_IO_URING)
  set(UCALL_BUILD_LIB_URING
    ON
    CACHE BOOL "Force enable UCALL_BUILD_LIB_URING" FORCE)
  set(UCALL_BUILD_PYTHON_URING
    ON
    CACHE BOOL "Force enable UCALL_BUILD_PYTHON_URING" FORCE)
endif()

if(UCALL_BUILD_PYTHON_URING)
  set(UCALL_BUILD_LIB_URING ON)
endif()

if(UCALL_BUILD_ALL)
  set(UCALL_BUILD_BENCHMARKS ON)
  set(UCALL_BUILD_EXAMPLES ON)
  set(UCALL_BUILD_TESTS ON)
endif()

message(STATUS "Supports io_uring: ${SUPPORTS_IO_URING}")
message(STATUS "Building ucall_server_posix: ${UCALL_BUILD_LIB_POSIX}")
message(STATUS "Building ucall_server_uring: ${UCALL_BUILD_LIB_URING}")
message(STATUS "Building py_ucall_posix: ${UCALL_BUILD_PYTHON_POSIX}")
message(STATUS "Building py_ucall_uring: ${UCALL_BUILD_PYTHON_URING}")
message(STATUS "Building benchmarks: ${UCALL_BUILD_BENCHMARKS}")
message(STATUS "Building examples: ${UCALL_BUILD_EXAMPLES}")

# Make Release by default
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CACHEFILE_DIR "${CMAKE_SOURCE_DIR}/build")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
  "${CMAKE_BINARY_DIR}/build/lib"
  CACHE PATH "Path to static libs")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
  "${CMAKE_BINARY_DIR}/build/lib"
  CACHE PATH "Path to shared libs")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/build/bin")

message(STATUS "Library output directory: ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
message(STATUS "Archive output directory: ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}")
message(STATUS "Runtime output directory: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
message(STATUS "Running on OS: ${CMAKE_SYSTEM_NAME}")

if(MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /DEBUG")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2")
  set(CMAKE_CXX_FLAGS_RELWITHDEBINFO
    "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /O2 /DEBUG")
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mavx2")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fmax-errors=1")
endif()

# Check if we are running on Linux
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(LINUX TRUE)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set(CMAKE_OSX_DEPLOYMENT_TARGET "11")
  set(CMAKE_OSX_SYSROOT
    CACHE STRING "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk")
  set(CMAKE_OSX_DEPLOYMENT_TARGET
    "11"
    CACHE STRING "Minimum OS X deployment version")
  set(CMAKE_OSX_ARCHITECTURES
    "x86_64" "universal2" "arm64"
    CACHE STRING "Minimum OS X deployment version")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++ -std=c++17")
endif()

include(FetchContent)
include(ExternalProject)
find_package(Threads REQUIRED)

FetchContent_Declare(
  simdjson
  GIT_REPOSITORY https://github.com/simdjson/simdjson.git
  GIT_TAG v3.9.4
  GIT_SHALLOW 1)
FetchContent_MakeAvailable(simdjson)
include_directories(${simdjson_SOURCE_DIR}/include)

FetchContent_Declare(
  ada
  GIT_REPOSITORY https://github.com/ada-url/ada
  GIT_TAG v2.8.0
  GIT_SHALLOW 1)
FetchContent_MakeAvailable(simdjson)
include_directories(${simdjson_SOURCE_DIR}/include)

# Parsing HTTP headers On MacOS you may need to locate headers here: export
# CPATH=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/
FetchContent_Declare(
  cxxopts
  GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
  GIT_TAG v3.2.0
  GIT_SHALLOW 1)
FetchContent_MakeAvailable(cxxopts)
include_directories(${cxxopts_SOURCE_DIR}/include)

# Parsing HTTP headers On MacOS you may need to locate headers here: export
# CPATH=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/
FetchContent_Declare(
  stringzilla
  GIT_REPOSITORY https://github.com/ashvardanian/stringzilla.git
  GIT_TAG v3.8.4
  GIT_SHALLOW 1)
FetchContent_MakeAvailable(stringzilla)
include_directories(${stringzilla_SOURCE_DIR})

# Base64 decoding
FetchContent_Declare(
  simdutf
  GIT_REPOSITORY https://github.com/simdutf/simdutf
  GIT_TAG v5.2.8
  GIT_SHALLOW 1)
FetchContent_MakeAvailable(simdutf)
include_directories(${simdutf_SOURCE_DIR}/include)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# LibUring
if(UCALL_BUILD_LIB_URING)
  set(URING_DIR ${CMAKE_BINARY_DIR}/_deps/liburing-ep)
  ExternalProject_Add(
    liburing-ep
    GIT_REPOSITORY https://github.com/axboe/liburing.git
    GIT_TAG liburing-2.3
    GIT_SHALLOW 1
    PREFIX ${CMAKE_BINARY_DIR}/_deps/
    SOURCE_DIR ${URING_DIR}
    CONFIGURE_COMMAND
    echo Configuring LibUring && cd ${URING_DIR} && ./configure --nolibc
    --cc=${CMAKE_C_COMPILER} --cxx=${CMAKE_CXX_COMPILER};
    BUILD_COMMAND cd ${URING_DIR} && make;
    INSTALL_COMMAND ""
    UPDATE_COMMAND "")
  add_library(uring_internal STATIC IMPORTED GLOBAL)
  add_dependencies(uring_internal liburing-ep)
  set_property(TARGET uring_internal PROPERTY IMPORTED_LOCATION
    ${URING_DIR}/src/liburing.a)

  include_directories(${URING_DIR}/src/include/)
  set(URING_LIBS uring_internal)
endif()

if(UCALL_BUILD_BENCHMARKS)
  set(BENCHMARK_ENABLE_TESTING OFF)
  set(BENCHMARK_ENABLE_INSTALL OFF)
  set(BENCHMARK_ENABLE_DOXYGEN OFF)
  set(BENCHMARK_INSTALL_DOCS OFF)
  set(BENCHMARK_DOWNLOAD_DEPENDENCIES ON)
  set(BENCHMARK_ENABLE_GTEST_TESTS OFF)
  set(BENCHMARK_USE_BUNDLED_GTEST ON)
  FetchContent_Declare(
    benchmark
    GIT_REPOSITORY https://github.com/google/benchmark
    GIT_TAG v1.7.0
    GIT_SHALLOW 1)
  FetchContent_MakeAvailable(benchmark)
  include_directories(${benchmark_SOURCE_DIR}/include)
endif()

if(UCALL_BUILD_EXAMPLES)
  # CLI
  FetchContent_Declare(
    cxxopts
    GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
    GIT_TAG v3.1.1
    GIT_SHALLOW 1)
  FetchContent_MakeAvailable(cxxopts)
  include_directories(${cxxopts_SOURCE_DIR}/include)
endif()

include_directories(include/ src/)

if(UCALL_BUILD_LIB_POSIX)
  add_library(ucall_server_posix src/engine_posix.cpp)
  target_link_libraries(ucall_server_posix simdjson::simdjson simdutf::simdutf Threads::Threads)
  set(PYTHON_BACKEND ucall_server_posix)
endif()

if(UCALL_BUILD_LIB_URING)
  add_library(ucall_server_uring src/engine_uring.cpp)
  set(PYTHON_BACKEND ucall_server_uring)
  target_link_libraries(ucall_server_uring simdjson::simdjson simdutf::simdutf Threads::Threads
    ${URING_LIBS})
endif()

# Python bindings
find_package(Python3 REQUIRED Development.Module)
include_directories(${Python_INCLUDE_DIRS})

if(UCALL_BUILD_PYTHON_POSIX)
  python3_add_library(py_ucall_posix python/lib.c)
  target_include_directories(py_ucall_posix PUBLIC src/ include/)
  target_link_libraries(py_ucall_posix PRIVATE ucall_server_posix base64)

  # set_target_properties(py_ucall_posix PROPERTIES OUTPUT_NAME posix)
  target_compile_definitions(py_ucall_posix
    PRIVATE UCALL_PYTHON_MODULE_NAME=posix)
  message(
    STATUS
    "Building ucall_server_posix with output in ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}"
  )
endif()

if(UCALL_BUILD_PYTHON_URING)
  python3_add_library(py_ucall_uring python/lib.c)
  target_include_directories(py_ucall_uring PUBLIC src/ include/)
  target_link_libraries(py_ucall_uring PRIVATE ucall_server_uring base64)

  # set_target_properties(py_ucall_uring PROPERTIES OUTPUT_NAME uring)
  target_compile_definitions(py_ucall_uring
    PRIVATE UCALL_PYTHON_MODULE_NAME=uring)
  message(
    STATUS
    "Building py_ucall_uring with output in ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}"
  )
endif()

if(UCALL_BUILD_EXAMPLES)
  add_executable(ucall_example_server_posix examples/ucall_server.cpp)
  target_link_libraries(ucall_example_server_posix ucall_server_posix cxxopts
    fmt::fmt)
  target_compile_options(ucall_example_server_posix
    PUBLIC -DCXXOPTS_NO_EXCEPTIONS=ON)
endif()

if(UCALL_BUILD_EXAMPLES AND UCALL_BUILD_LIB_URING)
  add_executable(ucall_example_server_uring examples/ucall_server.cpp)
  target_link_libraries(ucall_example_server_uring ucall_server_uring cxxopts
    fmt::fmt)
  target_compile_options(ucall_example_server_uring
    PUBLIC -DCXXOPTS_NO_EXCEPTIONS=ON)
endif()
