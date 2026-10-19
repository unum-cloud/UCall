cmake_minimum_required(VERSION 3.28 FATAL_ERROR)
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" UCALL_VERSION_NAME LIMIT_COUNT 1)
project(
    ucall
    VERSION 1.0.0
    LANGUAGES C CXX
    DESCRIPTION "Up to 100x Faster FastAPI. JSON-RPC with io_uring, SIMD-acceleration, and pure CPython bindings"
    HOMEPAGE_URL "https://github.com/unum-cloud/UCall"
)

set(UCALL_IS_MAIN_PROJECT OFF)
if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(UCALL_IS_MAIN_PROJECT ON)
endif ()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS NO)

option(UCALL_BUILD_LIB_POSIX "Builds the legacy POSIX backend pending its C ABI port" OFF)
option(UCALL_BUILD_PYTHON_POSIX "Builds CPython bindings for the `posix` backend" OFF)

option(UCALL_BUILD_LIB_URING "Builds the C library for the `uring` backend" OFF)
option(UCALL_BUILD_PYTHON_URING "Builds CPython bindings for the `uring` backend" OFF)

option(UCALL_BUILD_EXAMPLES "Builds examples for Redis-like server and PyTorch deployment" OFF)
option(UCALL_BUILD_TEST "Builds the C caller and native suites in test/" ${UCALL_IS_MAIN_PROJECT})
option(UCALL_BUILD_ALL "Builds all supported target" OFF)

if (UCALL_BUILD_PYTHON_POSIX)
    set(UCALL_BUILD_LIB_POSIX ON)
endif ()

if (UCALL_BUILD_PYTHON_URING)
    set(UCALL_BUILD_LIB_URING ON)
endif ()

if (UCALL_BUILD_ALL)
    set(UCALL_BUILD_EXAMPLES ON)
    set(UCALL_BUILD_TEST ON)
endif ()

message(STATUS "Building ucall_server_posix: ${UCALL_BUILD_LIB_POSIX}")
message(STATUS "Building ucall_server_uring: ${UCALL_BUILD_LIB_URING}")
message(STATUS "Building py_ucall_posix: ${UCALL_BUILD_PYTHON_POSIX}")
message(STATUS "Building py_ucall_uring: ${UCALL_BUILD_PYTHON_URING}")
message(STATUS "Building examples: ${UCALL_BUILD_EXAMPLES}")
message(STATUS "Building tests: ${UCALL_BUILD_TEST}")

# Make Release by default
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/build/lib"
    CACHE PATH "Path to static libs"
)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/build/lib"
    CACHE PATH "Path to shared libs"
)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/build/bin")

message(STATUS "Library output directory: ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
message(STATUS "Archive output directory: ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}")
message(STATUS "Runtime output directory: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
message(STATUS "Running on OS: ${CMAKE_SYSTEM_NAME}")

if (MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /DEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /O2 /DEBUG")
else ()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
endif ()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fmax-errors=1")
endif ()

# Check if we are running on Linux
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(LINUX TRUE)
endif ()

if (UCALL_IS_MAIN_PROJECT AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
    execute_process(
        COMMAND git config core.hooksPath .githooks
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        OUTPUT_QUIET ERROR_QUIET
    )
endif ()

include(FetchContent)
include(ExternalProject)
find_package(Threads REQUIRED)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if (NOT TARGET stringzilla::static)
    if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/stringzilla/CMakeLists.txt" AND NOT DEFINED
                                                                            FETCHCONTENT_SOURCE_DIR_STRINGZILLA
    )
        add_subdirectory(stringzilla EXCLUDE_FROM_ALL)
    else ()
        FetchContent_Declare(
            stringzilla
            GIT_REPOSITORY https://github.com/ashvardanian/StringZilla
            GIT_TAG a87834b78549d9da1e1b824b14e47e7411684f08
        )
        FetchContent_MakeAvailable(stringzilla)
    endif ()
endif ()

add_library(ucall_core STATIC src/types.cpp src/secure_tunnel.cpp src/crypto_x25519.cpp)
add_library(ucall::core ALIAS ucall_core)
target_include_directories(
    ucall_core
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/c"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
target_compile_features(ucall_core PRIVATE cxx_std_20)
if (NOT MSVC)
    target_compile_options(ucall_core PRIVATE -fno-strict-aliasing)
endif ()
target_compile_definitions(ucall_core PRIVATE UCALL_BUILDING UCALL_VERSION_NAME="${UCALL_VERSION_NAME}")
target_link_libraries(ucall_core PRIVATE stringzilla::static Threads::Threads)
if (WIN32)
    target_link_libraries(ucall_core PRIVATE bcrypt)
    target_compile_definitions(ucall_core PUBLIC UCALL_EXPORT=)
endif ()

if (UCALL_BUILD_LIB_POSIX OR UCALL_BUILD_LIB_URING)
    FetchContent_Declare(
        simdjson
        GIT_REPOSITORY https://github.com/simdjson/simdjson.git
        GIT_TAG v5.0.5
    )
    FetchContent_MakeAvailable(simdjson)
    include_directories(SYSTEM ${simdjson_SOURCE_DIR}/include)
endif ()

if (UCALL_BUILD_LIB_POSIX OR UCALL_BUILD_LIB_URING)
    # Base64 decoding
    set(SIMDUTF_TOOLS
        OFF
        CACHE BOOL "Disable simdutf tools" FORCE
    )
    set(SIMDUTF_TESTS
        OFF
        CACHE BOOL "Disable simdutf tests" FORCE
    )
    FetchContent_Declare(
        simdutf
        GIT_REPOSITORY https://github.com/simdutf/simdutf
        GIT_TAG v9.3.2
        GIT_SHALLOW 1
        SYSTEM
    )
    FetchContent_MakeAvailable(simdutf)
    include_directories(SYSTEM ${simdutf_SOURCE_DIR}/include)

endif ()

# LibUring
if (UCALL_BUILD_LIB_URING)
    set(URING_DIR ${CMAKE_BINARY_DIR}/_deps/liburing-ep)
    ExternalProject_Add(
        liburing-ep
        GIT_REPOSITORY https://github.com/axboe/liburing.git
        GIT_TAG liburing-2.15
        GIT_SHALLOW 1
        PREFIX ${CMAKE_BINARY_DIR}/_deps/
        SOURCE_DIR ${URING_DIR}
        CONFIGURE_COMMAND <SOURCE_DIR>/configure --cc=${CMAKE_C_COMPILER} --cxx=${CMAKE_CXX_COMPILER}
        BUILD_COMMAND make -C <SOURCE_DIR> -s
        BUILD_IN_SOURCE 1
        INSTALL_COMMAND ""
        UPDATE_COMMAND ""
    )
    add_library(uring_internal STATIC IMPORTED GLOBAL)
    add_dependencies(uring_internal liburing-ep)
    set_property(TARGET uring_internal PROPERTY IMPORTED_LOCATION ${URING_DIR}/src/liburing.a)

    include_directories(${URING_DIR}/src/include/)
    set(URING_LIBS uring_internal)
endif ()

if (UCALL_BUILD_TEST OR UCALL_BUILD_EXAMPLES)
    FetchContent_Declare(
        fmt
        GIT_REPOSITORY https://github.com/fmtlib/fmt.git
        GIT_TAG 12.2.0
        FIND_PACKAGE_ARGS 12.2.0
    )
    FetchContent_MakeAvailable(fmt)
endif ()

if (UCALL_BUILD_EXAMPLES)
    FetchContent_Declare(
        cxxopts
        GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
        GIT_TAG v3.3.1
    )
    FetchContent_MakeAvailable(cxxopts)
endif ()

include_directories(c/ src/)

if (UCALL_BUILD_LIB_POSIX)
    add_library(ucall_server_posix src/server_posix.cpp)
    target_link_libraries(ucall_server_posix simdjson::simdjson simdutf::simdutf Threads::Threads ucall_core)
    set(PYTHON_BACKEND ucall_server_posix)
endif ()

if (UCALL_BUILD_LIB_URING)
    add_library(ucall_server_uring src/server_uring.cpp)
    set(PYTHON_BACKEND ucall_server_uring)
    target_link_libraries(
        ucall_server_uring simdjson::simdjson simdutf::simdutf Threads::Threads ${URING_LIBS} ucall_core
    )
endif ()

# Python bindings
if (UCALL_BUILD_PYTHON_POSIX OR UCALL_BUILD_PYTHON_URING)
    find_package(Python3 3.12 REQUIRED Development.Module)
endif ()

if (UCALL_BUILD_PYTHON_POSIX)
    python3_add_library(py_ucall_posix python/lib.c)
    target_include_directories(py_ucall_posix PUBLIC src/ c/)
    target_link_libraries(py_ucall_posix PRIVATE ucall_server_posix base64)

    # set_target_properties(py_ucall_posix PROPERTIES OUTPUT_NAME posix)
    target_compile_definitions(py_ucall_posix PRIVATE UCALL_PYTHON_MODULE_NAME=posix)
    message(STATUS "Building ucall_server_posix with output in ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
endif ()

if (UCALL_BUILD_PYTHON_URING)
    python3_add_library(py_ucall_uring python/lib.c)
    target_include_directories(py_ucall_uring PUBLIC src/ c/)
    target_link_libraries(py_ucall_uring PRIVATE ucall_server_uring base64)

    # set_target_properties(py_ucall_uring PROPERTIES OUTPUT_NAME uring)
    target_compile_definitions(py_ucall_uring PRIVATE UCALL_PYTHON_MODULE_NAME=uring)
    message(STATUS "Building py_ucall_uring with output in ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
endif ()

if (UCALL_BUILD_EXAMPLES)
    add_executable(ucall_example_server_posix examples/ucall_server.cpp)
    target_link_libraries(ucall_example_server_posix ucall_server_posix cxxopts fmt::fmt)
    target_compile_options(ucall_example_server_posix PUBLIC -DCXXOPTS_NO_EXCEPTIONS=ON)
endif ()

if (UCALL_BUILD_EXAMPLES AND UCALL_BUILD_LIB_URING)
    add_executable(ucall_example_server_uring examples/ucall_server.cpp)
    target_link_libraries(ucall_example_server_uring ucall_server_uring cxxopts fmt::fmt)
    target_compile_options(ucall_example_server_uring PUBLIC -DCXXOPTS_NO_EXCEPTIONS=ON)
endif ()

if (UCALL_BUILD_TEST)
    enable_testing()
    add_subdirectory(test)
endif ()
