cmake_minimum_required(VERSION 3.28)
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" ucall_version_name_ LIMIT_COUNT 1)
project(
    ucall
    VERSION 1.0.0
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
option(UCALL_BUILD_TOOLS "Build the echo, ledger, key-value, and inference examples" OFF)
option(UCALL_BUILD_BENCH "Build HTTP client and server benchmarks" OFF)
option(UCALL_BUILD_TEST "Build C ABI and native correctness tests" OFF)
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
include(ExternalProject)
find_package(Threads REQUIRED)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(cmake/ucall_siblings.cmake)

# Prefer a current system liburing; source builds are isolated under the build directory.
if (UCALL_WITH_LINUX_URING)
    find_package(PkgConfig QUIET)
    if (PkgConfig_FOUND)
        pkg_check_modules(UCALL_URING QUIET IMPORTED_TARGET liburing>=2.15)
    endif ()
    if (TARGET PkgConfig::UCALL_URING)
        add_library(uring_internal ALIAS PkgConfig::UCALL_URING)
    else ()
        set(ucall_uring_dir_ ${CMAKE_BINARY_DIR}/_deps/liburing-ep)
        # liburing's own `configure` knows no target, so a cross build names it with the compilers.
        set(ucall_uring_cc_ ${CMAKE_C_COMPILER})
        set(ucall_uring_cxx_ ${CMAKE_CXX_COMPILER})
        if (CMAKE_C_COMPILER_TARGET)
            string(APPEND ucall_uring_cc_ " --target=${CMAKE_C_COMPILER_TARGET}")
            string(APPEND ucall_uring_cxx_ " --target=${CMAKE_CXX_COMPILER_TARGET}")
        endif ()
        ExternalProject_Add(
            liburing-ep
            GIT_REPOSITORY https://github.com/axboe/liburing.git
            GIT_TAG liburing-2.15
            GIT_SHALLOW 1
            PREFIX ${CMAKE_BINARY_DIR}/_deps/
            SOURCE_DIR ${ucall_uring_dir_}
            CONFIGURE_COMMAND <SOURCE_DIR>/configure --cc=${ucall_uring_cc_} --cxx=${ucall_uring_cxx_}
            BUILD_COMMAND make -C <SOURCE_DIR>/src -s
            BUILD_BYPRODUCTS ${ucall_uring_dir_}/src/liburing.a
            BUILD_IN_SOURCE 1
            INSTALL_COMMAND ""
            UPDATE_COMMAND ""
        )
        add_library(uring_internal STATIC IMPORTED GLOBAL)
        add_dependencies(uring_internal liburing-ep)
        set_property(TARGET uring_internal PROPERTY IMPORTED_LOCATION ${ucall_uring_dir_}/src/liburing.a)
        file(MAKE_DIRECTORY ${ucall_uring_dir_}/src/include)
        set_property(TARGET uring_internal PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${ucall_uring_dir_}/src/include)
    endif ()
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

add_library(ucall STATIC src/lib.cpp src/types.cpp src/secure_tunnel.cpp src/crypto_x25519.cpp)
add_library(ucall::ucall ALIAS ucall)
add_library(ucall::header ALIAS ucall)
target_include_directories(
    ucall
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/c" "${CMAKE_CURRENT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
target_compile_features(ucall PUBLIC cxx_std_20)
target_compile_definitions(
    ucall
    PRIVATE UCALL_BUILDING UCALL_VERSION_NAME="${ucall_version_name_}"
    PUBLIC UCALL_WITH_POSIX=$<BOOL:${UCALL_WITH_POSIX}> UCALL_WITH_LINUX_EPOLLAIO=$<BOOL:${UCALL_WITH_LINUX_EPOLLAIO}>
           UCALL_WITH_LINUX_URING=$<BOOL:${UCALL_WITH_LINUX_URING}> UCALL_WITH_KQUEUE=$<BOOL:${UCALL_WITH_KQUEUE}>
           UCALL_WITH_IOCP=$<BOOL:${UCALL_WITH_IOCP}>
)
target_link_libraries(
    ucall
    PUBLIC forkunion::header smashtable::header stringzilla::header
    PRIVATE Threads::Threads ucall_sanitizers ucall_warnings
)
target_link_libraries(
    ucall
    PUBLIC forkunion::cpu_capabilities_compiled
    PRIVATE stringzilla::cpu_capabilities_compiled
)
# The C ABI is all a binary linking the archive may export; UCALL_EXPORT marks it.
set_target_properties(
    ucall
    PROPERTIES C_VISIBILITY_PRESET hidden
               CXX_VISIBILITY_PRESET hidden
               VISIBILITY_INLINES_HIDDEN ON
)
if (NOT MSVC)
    target_compile_options(ucall PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-fno-strict-aliasing>)
endif ()
if (WIN32)
    target_compile_definitions(ucall PUBLIC UCALL_EXPORT=)
    target_link_libraries(ucall PRIVATE bcrypt ws2_32 mswsock ntdll)
endif ()
if (UCALL_WITH_LINUX_URING)
    target_link_libraries(ucall PUBLIC uring_internal)
    if (TARGET liburing-ep)
        add_dependencies(ucall liburing-ep)
    endif ()
endif ()

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
        target_compile_definitions(ucall PRIVATE UCALL_TARGET_${target_macro_}=1)
        target_sources(ucall PRIVATE src/variants_${class_}.cpp)
        set_source_files_properties(src/variants_${class_}.cpp PROPERTIES COMPILE_OPTIONS "${flags_}")
    else ()
        target_compile_definitions(ucall PRIVATE UCALL_TARGET_${target_macro_}=0)
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
ucall_cpu_variant(intel_sierra INTEL_SIERRA westmere goldmont haswell x86_cmpccxadd)
ucall_cpu_variant(aws_g2 AWS_G2 neon neonaes neonsha arm64_lse)
ucall_cpu_variant(
    apple_m2
    APPLE_M2
    neon
    neonaes
    neonsha
    arm64_lse
    arm64_rcpc
)

if (UCALL_MARCH)
    set(ucall_floor_ "${UCALL_MARCH}")
else ()
    set(ucall_floor_ "the portable floor")
endif ()
if (UCALL_MULTIVERSIONED)
    target_compile_definitions(ucall PRIVATE UCALL_TARGET_MONOVERSIONED=0)
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

if (UCALL_BUILD_TOOLS)
    foreach (example_ echo ledger redis inference)
        add_executable(ucall_example_${example_} examples/${example_}/server.cpp)
        target_include_directories(ucall_example_${example_} PRIVATE tools)
        target_link_libraries(ucall_example_${example_} PRIVATE ucall::ucall forkunion::static ucall_warnings)
    endforeach ()
    target_link_libraries(ucall_example_inference PRIVATE numkong::static)
endif ()
if (UCALL_BUILD_BENCH)
    add_executable(ucall_bench_http bench/http.cpp)
    add_executable(ucall_bench_server bench/ucall_server.cpp)
    foreach (bench_ ucall_bench_http ucall_bench_server)
        target_include_directories(${bench_} PRIVATE tools)
        target_link_libraries(${bench_} PRIVATE ucall::ucall forkunion::static ucall_warnings)
    endforeach ()
endif ()
if (UCALL_BUILD_PYTHON)
    add_subdirectory(python)
endif ()

if (UCALL_BUILD_TEST)
    enable_testing()
    add_subdirectory(test)
endif ()
