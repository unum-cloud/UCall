cmake_minimum_required(VERSION 3.28)
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" ucall_version_name_ LIMIT_COUNT 1)
# `project()` takes the numeric core alone, so a candidate's suffix stays in the name.
if (NOT ucall_version_name_ MATCHES "^([0-9]+\\.[0-9]+\\.[0-9]+)")
    message(FATAL_ERROR "VERSION must start with MAJOR.MINOR.PATCH, not '${ucall_version_name_}'")
endif ()
project(
    ucall
    VERSION ${CMAKE_MATCH_1}
    LANGUAGES C CXX
    DESCRIPTION "HTTP and Noise clients and servers with capability-specialized I/O backends"
    HOMEPAGE_URL "https://github.com/unum-cloud/UCall"
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# Each UCall target declares its own language level, so fetched dependencies build at the standard they pick.
set(CMAKE_CXX_EXTENSIONS NO)
# No target uses C++20 modules, and a Clang installed without `clang-scan-deps` would fail every C++ unit.
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

set(ucall_default_posix_ OFF)
set(ucall_default_linux_ OFF)
set(ucall_default_kqueue_ OFF)
set(ucall_default_iocp_ OFF)
if (PROJECT_IS_TOP_LEVEL)
    if (UNIX)
        set(ucall_default_posix_ ON)
    endif ()
    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(ucall_default_linux_ ON)
    elseif (APPLE OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
        set(ucall_default_kqueue_ ON)
    elseif (WIN32)
        set(ucall_default_iocp_ ON)
    endif ()
endif ()

option(UCALL_WITH_POSIX "Include the portable POSIX backend" ${ucall_default_posix_})
option(UCALL_WITH_LINUX_URING "Include Linux io_uring 6.12 and 6.18 backends" ${ucall_default_linux_})
option(UCALL_WITH_LINUX_EPOLLAIO "Include the Linux epoll and AIO backend" ${ucall_default_linux_})
option(UCALL_WITH_KQUEUE "Include the macOS and FreeBSD kqueue backend" ${ucall_default_kqueue_})
option(UCALL_WITH_IOCP "Include the Windows IOCP backend" ${ucall_default_iocp_})
option(UCALL_BUILD_PYTHON "Build the CPython extension; `pyproject.toml` switches it on" OFF)
option(UCALL_BUILD_EXAMPLES "Build the hello, echo, ledger, key-value, and inference examples" OFF)
option(UCALL_BUILD_BENCH "Build HTTP client and server benchmarks" OFF)
option(UCALL_BUILD_TEST "Build C ABI and native correctness tests" OFF)
option(UCALL_BUILD_FUZZ "Build libFuzzer harnesses for the parsers; needs Clang" OFF)
option(UCALL_BUILD_SHARED "Compile ucall_shared in the default build and install both libraries" OFF)
option(UCALL_INSTALL "Install the C headers, libraries and CMake package" ${PROJECT_IS_TOP_LEVEL})
option(UCALL_WERROR "Treat compiler warnings as errors" OFF)
set(UCALL_BUILD_SANITIZERS
    "off"
    CACHE STRING "Sanitizers for UCall's own targets: off, address (with undefined) or thread"
)
set_property(CACHE UCALL_BUILD_SANITIZERS PROPERTY STRINGS off address thread)
# Seeded from the environment at the first configure, so `cargo` and `scikit-build-core` honour `UCALL_MARCH=native`.
set(UCALL_MARCH
    "$ENV{UCALL_MARCH}"
    CACHE STRING "The `-march` floor of the own units and the siblings: empty, an ISA level, native, or a CPU name"
)
option(UCALL_MULTIVERSIONED "Keep every CPU class the toolchain compiles, or only the best ones UCALL_MARCH implies" ON)

include(cmake/ucall_flags.cmake)
include(cmake/ucall_platform.cmake)

# Make Release by default
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
foreach (configuration_ DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${configuration_} "${CMAKE_BINARY_DIR}")
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${configuration_} "${CMAKE_BINARY_DIR}")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${configuration_} "${CMAKE_BINARY_DIR}")
endforeach ()

message(STATUS "Running on OS: ${CMAKE_SYSTEM_NAME}")

if (MSVC)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /DEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /O2 /DEBUG")
else ()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
endif ()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fmax-errors=1")
endif ()

if (PROJECT_IS_TOP_LEVEL AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
    execute_process(
        COMMAND git config core.hooksPath .githooks
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        OUTPUT_QUIET ERROR_QUIET
    )
endif ()

include(FetchContent)
include(GNUInstallDirs)
find_package(Threads REQUIRED)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(cmake/ucall_siblings.cmake)

if (UCALL_WITH_LINUX_URING)
    include(cmake/liburing.cmake)
endif ()

if (UCALL_BUILD_TEST)
    FetchContent_Declare(
        fmt
        GIT_REPOSITORY https://github.com/fmtlib/fmt.git
        GIT_TAG 12.2.0
        SYSTEM FIND_PACKAGE_ARGS 12.2.0
    )
    FetchContent_MakeAvailable(fmt)
endif ()

# Both flavors compile the same units, and their C interface lives in `c/ucall`, which `ucall::header` names alone.
if (NOT UCALL_BUILD_SHARED)
    set(ucall_library_exclusion_ EXCLUDE_FROM_ALL)
endif ()
set(ucall_sources_ src/lib.cpp src/types.cpp src/secure_tunnel.cpp src/crypto_x25519.cpp)
add_library(ucall_static STATIC ${ucall_sources_})
add_library(ucall_shared SHARED ${ucall_library_exclusion_} ${ucall_sources_})
add_library(ucall::static ALIAS ucall_static)
add_library(ucall::shared ALIAS ucall_shared)
add_library(ucall_header INTERFACE)
add_library(ucall::header ALIAS ucall_header)
set_target_properties(ucall_static PROPERTIES EXPORT_NAME static)
set_target_properties(ucall_shared PROPERTIES EXPORT_NAME shared)
set_target_properties(ucall_header PROPERTIES EXPORT_NAME header)
target_include_directories(
    ucall_header INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/c>
                           $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# The archive passes the native interface in `include/` and its siblings on to the tests, tools and bindings built here,
# and an installed archive names only what it links. The shared library passes nothing but the C interface.
function (ucall_setup_library target_ scope_)
    target_include_directories(
        ${target_} ${scope_} "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>" PRIVATE "${PROJECT_SOURCE_DIR}/src"
    )
    target_compile_features(${target_} ${scope_} cxx_std_20)
    target_compile_definitions(${target_} PRIVATE UCALL_BUILDING UCALL_VERSION_NAME="${ucall_version_name_}")
    target_compile_definitions(
        ${target_}
        ${scope_}
        UCALL_WITH_POSIX=$<BOOL:${UCALL_WITH_POSIX}>
        UCALL_WITH_LINUX_EPOLLAIO=$<BOOL:${UCALL_WITH_LINUX_EPOLLAIO}>
        UCALL_WITH_LINUX_URING=$<BOOL:${UCALL_WITH_LINUX_URING}>
        UCALL_WITH_KQUEUE=$<BOOL:${UCALL_WITH_KQUEUE}>
        UCALL_WITH_IOCP=$<BOOL:${UCALL_WITH_IOCP}>
    )
    target_link_libraries(
        ${target_}
        PUBLIC ucall_header
        PRIVATE Threads::Threads $<BUILD_INTERFACE:ucall_sanitizers> $<BUILD_INTERFACE:ucall_warnings>
                $<BUILD_INTERFACE:stringzilla::cpu_capabilities_compiled>
    )
    target_link_libraries(
        ${target_} ${scope_} $<BUILD_INTERFACE:forkunion::header> $<BUILD_INTERFACE:smashtable::header>
        $<BUILD_INTERFACE:stringzilla::header> $<BUILD_INTERFACE:forkunion::cpu_capabilities_compiled>
    )
    # The C ABI is all a binary linking either flavor may export; UCALL_EXPORT marks it.
    set_target_properties(
        ${target_}
        PROPERTIES C_VISIBILITY_PRESET hidden
                   CXX_VISIBILITY_PRESET hidden
                   VISIBILITY_INLINES_HIDDEN ON
    )
    if (NOT MSVC)
        target_compile_options(${target_} ${scope_} $<$<COMPILE_LANGUAGE:CXX>:-fno-strict-aliasing>)
    endif ()
    if (WIN32)
        target_link_libraries(${target_} PRIVATE bcrypt ws2_32 mswsock ntdll)
    endif ()
    if (UCALL_WITH_LINUX_URING)
        target_link_libraries(${target_} ${scope_} uring::uring)
    endif ()
endfunction ()
ucall_setup_library(ucall_static PUBLIC)
ucall_setup_library(ucall_shared PRIVATE)
# A C program links the archive with the C driver, which leaves out the C++ runtime the library needs.
target_link_libraries(ucall_static INTERFACE $<$<LINK_LANGUAGE:C>:${CMAKE_CXX_IMPLICIT_LINK_LIBRARIES}>)
# The archive's consumers call it directly, so on Windows only the shared library exports and its consumers import.
if (WIN32)
    target_compile_definitions(ucall_static PUBLIC UCALL_EXPORT=)
endif ()
# The linker hides what hidden visibility misses: the standard library templates its headers declare visible.
if (APPLE)
    target_link_options(ucall_shared PRIVATE "LINKER:-exported_symbol,_ucall_*")
elseif (CMAKE_SYSTEM_NAME MATCHES "^(Linux|Android|FreeBSD)$")
    file(WRITE "${PROJECT_BINARY_DIR}/ucall_shared.map" "{\n  global: ucall_*;\n  local: *;\n};\n")
    target_link_options(ucall_shared PRIVATE "LINKER:--version-script=${PROJECT_BINARY_DIR}/ucall_shared.map")
endif ()
# `SOVERSION` carries the major alone, the only break the C ABI admits.
set_target_properties(ucall_shared PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})

# One compiled class per distinct native kernel bundle, declared over every StringZilla and ForkUnion capability its
# kits and atomics use, oldest first, `serial` over none. A class exists when each of them is enabled. Its unit takes
# the StringZilla flags of those capabilities in that order, so on Arm the last `-march` holds every extension. A
# multiversioned build keeps every class that exists. A monoversioned one keeps none of them, serial included, and
# compiles the `monoversioned` class instead, over every capability the libraries enabled: what `UCALL_MARCH` implies
# and what a preset vouches for, with the flags of the vouched ones. Every gate is `UCALL_TARGET_<CLASS>` set to 0 or 1.
function (ucall_cpu_variant class_ target_macro_)
    set(kept_ FALSE)
    if (UCALL_MULTIVERSIONED OR class_ STREQUAL "monoversioned")
        set(kept_ TRUE)
    endif ()
    set(flags_)
    foreach (capability_ IN LISTS ARGN)
        if (NOT stringzilla_target_${capability_}_enabled AND NOT forkunion_target_${capability_}_enabled)
            set(kept_ FALSE)
        endif ()
        # MSVC takes one `/arch:`, the newest capability's, and warns when a later one overrides an earlier.
        if (MSVC AND stringzilla_target_${capability_}_flags)
            set(flags_ ${stringzilla_target_${capability_}_flags})
        else ()
            list(APPEND flags_ ${stringzilla_target_${capability_}_flags})
        endif ()
    endforeach ()
    if (kept_)
        target_compile_definitions(ucall_static PRIVATE UCALL_TARGET_${target_macro_}=1)
        target_compile_definitions(ucall_shared PRIVATE UCALL_TARGET_${target_macro_}=1)
        target_sources(ucall_static PRIVATE src/variants_${class_}.cpp)
        target_sources(ucall_shared PRIVATE src/variants_${class_}.cpp)
        set_source_files_properties(src/variants_${class_}.cpp PROPERTIES COMPILE_OPTIONS "${flags_}")
    else ()
        target_compile_definitions(ucall_static PRIVATE UCALL_TARGET_${target_macro_}=0)
        target_compile_definitions(ucall_shared PRIVATE UCALL_TARGET_${target_macro_}=0)
    endif ()
endfunction ()

ucall_cpu_variant(serial SERIAL)
ucall_cpu_variant(intel_haswell INTEL_HASWELL westmere haswell)
ucall_cpu_variant(intel_skylake INTEL_SKYLAKE westmere haswell skylake)
ucall_cpu_variant(
    intel_icelake
    INTEL_ICELAKE
    westmere
    goldmont
    haswell
    skylake
    icelake
)
ucall_cpu_variant(intel_alder INTEL_ALDER westmere goldmont haswell)
ucall_cpu_variant(aws_g2 AWS_G2 neon neonaes neonsha arm64_lse)

if (UCALL_MARCH)
    set(ucall_floor_ "${UCALL_MARCH}")
else ()
    set(ucall_floor_ "the portable floor")
endif ()
if (UCALL_MULTIVERSIONED)
    target_compile_definitions(ucall_static PRIVATE UCALL_TARGET_MONOVERSIONED=0)
    target_compile_definitions(ucall_shared PRIVATE UCALL_TARGET_MONOVERSIONED=0)
    message(STATUS "UCall: multiversioned above ${ucall_floor_}")
else ()
    get_property(ucall_capabilities_enabled_ GLOBAL PROPERTY stringzilla_capabilities_enabled)
    get_property(forkunion_capabilities_enabled_ GLOBAL PROPERTY forkunion_capabilities_enabled)
    list(APPEND ucall_capabilities_enabled_ ${forkunion_capabilities_enabled_})
    # The floor already holds what it implies, and a later `-march` would lower an Arm `-mcpu` floor.
    set(ucall_capabilities_summary_)
    set(ucall_capabilities_vouched_)
    foreach (capability_ IN LISTS ucall_capabilities_enabled_)
        string(APPEND ucall_capabilities_summary_ " ${capability_}")
        if (NOT capability_ STREQUAL "serial"
            AND NOT stringzilla_target_${capability_}_implied
            AND NOT forkunion_target_${capability_}_implied
        )
            list(APPEND ucall_capabilities_vouched_ ${capability_})
        endif ()
    endforeach ()
    message(STATUS "UCall: monoversioned for ${ucall_floor_}:${ucall_capabilities_summary_}")
    ucall_cpu_variant(monoversioned MONOVERSIONED ${ucall_capabilities_vouched_})
endif ()

if (UCALL_BUILD_EXAMPLES)
    foreach (example_ echo ledger redis inference)
        add_executable(ucall_example_${example_} examples/${example_}/server.cpp)
        target_include_directories(ucall_example_${example_} PRIVATE tools)
        target_link_libraries(ucall_example_${example_} PRIVATE ucall_static forkunion::static ucall_warnings)
    endforeach ()
    target_link_libraries(ucall_example_inference PRIVATE numkong::static)
    add_executable(ucall_example_hello examples/hello.c)
    target_link_libraries(ucall_example_hello PRIVATE ucall_static ucall_warnings)
endif ()
# The command-line client builds with the examples and with anything installed, where it joins the SDK.
if (UCALL_BUILD_EXAMPLES OR UCALL_INSTALL)
    add_executable(ucall_cli cli/ucall.cpp)
    set_target_properties(ucall_cli PROPERTIES OUTPUT_NAME ucall)
    target_include_directories(ucall_cli PRIVATE tools)
    target_link_libraries(ucall_cli PRIVATE ucall_static ucall_warnings)
endif ()
if (UCALL_BUILD_BENCH)
    add_executable(ucall_bench_http bench/http.cpp)
    add_executable(ucall_bench_server bench/ucall_server.cpp)
    foreach (bench_ ucall_bench_http ucall_bench_server)
        target_include_directories(${bench_} PRIVATE tools)
        target_link_libraries(${bench_} PRIVATE ucall_static forkunion::static ucall_warnings)
    endforeach ()
endif ()
if (UCALL_BUILD_PYTHON)
    add_subdirectory(python)
endif ()

if (UCALL_BUILD_TEST)
    enable_testing()
    add_subdirectory(test)
endif ()

include(cmake/ucall_install.cmake)
