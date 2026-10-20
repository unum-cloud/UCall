cmake_minimum_required(VERSION 3.28 FATAL_ERROR)
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" UCALL_VERSION_NAME LIMIT_COUNT 1)
project(
    ucall
    VERSION 1.0.0
    LANGUAGES C CXX
    DESCRIPTION "HTTP and Noise clients and servers with capability-specialized I/O backends"
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

set(UCALL_DEFAULT_POSIX OFF)
set(UCALL_DEFAULT_LINUX OFF)
set(UCALL_DEFAULT_KQUEUE OFF)
set(UCALL_DEFAULT_IOCP OFF)
if (UCALL_IS_MAIN_PROJECT)
    if (UNIX)
        set(UCALL_DEFAULT_POSIX ON)
    endif ()
    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(UCALL_DEFAULT_LINUX ON)
    elseif (APPLE OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
        set(UCALL_DEFAULT_KQUEUE ON)
    elseif (WIN32)
        set(UCALL_DEFAULT_IOCP ON)
    endif ()
endif ()

option(UCALL_WITH_POSIX "Include the portable POSIX backend" ${UCALL_DEFAULT_POSIX})
option(UCALL_WITH_LINUX_URING "Include Linux io_uring 6.12 and 7.0 backends" ${UCALL_DEFAULT_LINUX})
option(UCALL_WITH_LINUX_EPOLL "Include the Linux epoll backend" ${UCALL_DEFAULT_LINUX})
option(UCALL_WITH_KQUEUE "Include the macOS and FreeBSD kqueue backend" ${UCALL_DEFAULT_KQUEUE})
option(UCALL_WITH_IOCP "Include the Windows IOCP backend" ${UCALL_DEFAULT_IOCP})
option(UCALL_BUILD_PYTHON_POSIX "Build the POSIX Python SDK" OFF)
option(UCALL_BUILD_PYTHON_URING "Build the io_uring Python SDK" OFF)
option(UCALL_BUILD_EXAMPLES "Build the echo, ledger, and key-value examples" OFF)
option(UCALL_BUILD_BENCH "Build HTTP client and server benchmarks" OFF)
option(UCALL_BUILD_TEST "Build C ABI and native correctness tests" ${UCALL_IS_MAIN_PROJECT})
option(UCALL_BUILD_ALL "Build every target supported on this platform" OFF)
set(UCALL_BUILD_SANITIZERS
    "off"
    CACHE STRING "Sanitizers for UCall's own targets: off, address (with undefined) or thread"
)
set_property(CACHE UCALL_BUILD_SANITIZERS PROPERTY STRINGS off address thread)

# ThreadSanitizer sees no inline assembly, so ForkUnion leaves out its instruction-set atomics and the rungs above them.
if (UCALL_BUILD_SANITIZERS STREQUAL "thread")
    set(FORKUNION_TARGET_ARM64_LSE OFF)
    set(FORKUNION_TARGET_X86_CMPCCXADD OFF)
    set(FORKUNION_TARGET_RISC5_ATOMIC OFF)
endif ()

if (UCALL_BUILD_ALL)
    set(UCALL_BUILD_EXAMPLES ON)
    set(UCALL_BUILD_BENCH ON)
    set(UCALL_BUILD_TEST ON)
endif ()
if (UCALL_BUILD_PYTHON_POSIX OR UCALL_BUILD_PYTHON_URING)
    message(FATAL_ERROR "The Python SDK is awaiting migration to the current C ABI; build the native libraries instead")
endif ()
if (UCALL_WITH_POSIX AND NOT UNIX)
    message(FATAL_ERROR "The POSIX backend requires a POSIX platform")
endif ()
if ((UCALL_WITH_LINUX_URING OR UCALL_WITH_LINUX_EPOLL) AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "The epoll and io_uring backends require Linux")
endif ()
if (UCALL_WITH_KQUEUE AND NOT (APPLE OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD"))
    message(FATAL_ERROR "The kqueue backend requires macOS or FreeBSD")
endif ()
if (UCALL_WITH_IOCP AND NOT WIN32)
    message(FATAL_ERROR "The IOCP backend requires Windows")
endif ()

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

function (ucall_sibling name source_override target url revision)
    if (TARGET ${target})
        return()
    endif ()
    if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${name}/CMakeLists.txt" AND NOT DEFINED
                                                                        FETCHCONTENT_SOURCE_DIR_${source_override}
    )
        add_subdirectory(${name} EXCLUDE_FROM_ALL)
    else ()
        FetchContent_Declare(
            ${name}
            GIT_REPOSITORY ${url}
            GIT_TAG ${revision}
            EXCLUDE_FROM_ALL
        )
        FetchContent_MakeAvailable(${name})
    endif ()
endfunction ()

ucall_sibling(
    stringzilla STRINGZILLA stringzilla::header https://github.com/ashvardanian/StringZilla
    a87834b78549d9da1e1b824b14e47e7411684f08
)
ucall_sibling(
    forkunion FORKUNION forkunion::header https://github.com/ashvardanian/ForkUnion
    c103da31bfc2359ef80315ae0dd52126bb3d3db6
)
ucall_sibling(
    smashtable SMASHTABLE smashtable::header https://github.com/ashvardanian/SmashTable
    7b169145be44f2baa309c2fee4f7f821df9420e4
)

# Prefer a current system liburing; source builds are isolated under the build directory.
if (UCALL_WITH_LINUX_URING)
    find_package(PkgConfig QUIET)
    if (PkgConfig_FOUND)
        pkg_check_modules(UCALL_URING QUIET IMPORTED_TARGET liburing>=2.15)
    endif ()
    if (TARGET PkgConfig::UCALL_URING)
        add_library(uring_internal ALIAS PkgConfig::UCALL_URING)
    else ()
        set(URING_DIR ${CMAKE_BINARY_DIR}/_deps/liburing-ep)
        ExternalProject_Add(
            liburing-ep
            GIT_REPOSITORY https://github.com/axboe/liburing.git
            GIT_TAG liburing-2.15
            GIT_SHALLOW 1
            PREFIX ${CMAKE_BINARY_DIR}/_deps/
            SOURCE_DIR ${URING_DIR}
            CONFIGURE_COMMAND <SOURCE_DIR>/configure --cc=${CMAKE_C_COMPILER} --cxx=${CMAKE_CXX_COMPILER}
            BUILD_COMMAND make -C <SOURCE_DIR>/src -s
            BUILD_BYPRODUCTS ${URING_DIR}/src/liburing.a
            BUILD_IN_SOURCE 1
            INSTALL_COMMAND ""
            UPDATE_COMMAND ""
        )
        add_library(uring_internal STATIC IMPORTED GLOBAL)
        add_dependencies(uring_internal liburing-ep)
        set_property(TARGET uring_internal PROPERTY IMPORTED_LOCATION ${URING_DIR}/src/liburing.a)
        file(MAKE_DIRECTORY ${URING_DIR}/src/include)
        set_property(TARGET uring_internal PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${URING_DIR}/src/include)
    endif ()
endif ()

if (UCALL_BUILD_TEST)
    FetchContent_Declare(
        fmt
        GIT_REPOSITORY https://github.com/fmtlib/fmt.git
        GIT_TAG 12.2.0
        FIND_PACKAGE_ARGS 12.2.0
    )
    FetchContent_MakeAvailable(fmt)
endif ()

# Sanitizers instrument UCall's library and tests, while fetched dependencies keep their own flags.
add_library(ucall_sanitizers INTERFACE)
if (UCALL_BUILD_SANITIZERS STREQUAL "address")
    if (MSVC)
        set(ucall_sanitizer_flags /fsanitize=address)
    else ()
        set(ucall_sanitizer_flags -fsanitize=address,undefined -fno-omit-frame-pointer)
    endif ()
elseif (UCALL_BUILD_SANITIZERS STREQUAL "thread")
    if (MSVC)
        message(FATAL_ERROR "MSVC has no ThreadSanitizer, so UCALL_BUILD_SANITIZERS=thread needs Clang or GCC")
    endif ()
    set(ucall_sanitizer_flags -fsanitize=thread)
elseif (NOT UCALL_BUILD_SANITIZERS STREQUAL "off")
    message(FATAL_ERROR "UCALL_BUILD_SANITIZERS is off, address or thread, not '${UCALL_BUILD_SANITIZERS}'")
endif ()
if (ucall_sanitizer_flags)
    target_compile_options(ucall_sanitizers INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:${ucall_sanitizer_flags}>")
    if (NOT MSVC)
        target_link_options(ucall_sanitizers INTERFACE "$<$<LINK_LANGUAGE:C,CXX>:${ucall_sanitizer_flags}>")
    endif ()
endif ()

# One compiled class per distinct native kernel bundle; flags stay on its instantiation unit.
include(CheckCXXCompilerFlag)

add_library(ucall STATIC src/lib.cpp src/types.cpp src/secure_tunnel.cpp src/crypto_x25519.cpp src/variants_serial.cpp)
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
    PRIVATE UCALL_BUILDING UCALL_VERSION_NAME="${UCALL_VERSION_NAME}"
    PUBLIC UCALL_WITH_POSIX=$<BOOL:${UCALL_WITH_POSIX}> UCALL_WITH_LINUX_EPOLL=$<BOOL:${UCALL_WITH_LINUX_EPOLL}>
           UCALL_WITH_LINUX_URING=$<BOOL:${UCALL_WITH_LINUX_URING}> UCALL_WITH_KQUEUE=$<BOOL:${UCALL_WITH_KQUEUE}>
           UCALL_WITH_IOCP=$<BOOL:${UCALL_WITH_IOCP}>
)
target_link_libraries(
    ucall
    PUBLIC forkunion::header smashtable::header stringzilla::header
    PRIVATE Threads::Threads ucall_sanitizers
)
foreach (capabilities forkunion::cpu_capabilities_compiled stringzilla::cpu_capabilities_compiled)
    if (TARGET ${capabilities})
        target_link_libraries(ucall PUBLIC ${capabilities})
    endif ()
endforeach ()
if (NOT MSVC)
    target_compile_options(ucall PUBLIC $<$<COMPILE_LANGUAGE:CXX>:-fno-strict-aliasing>)
endif ()
if (WIN32)
    target_compile_definitions(ucall PUBLIC UCALL_EXPORT=)
    target_link_libraries(ucall PRIVATE bcrypt ws2_32 mswsock)
endif ()
if (UCALL_WITH_LINUX_URING)
    target_link_libraries(ucall PUBLIC uring_internal)
    if (TARGET liburing-ep)
        add_dependencies(ucall liburing-ep)
    endif ()
endif ()

function (ucall_cpu_variant source target_macro)
    cmake_parse_arguments(PARSE_ARGV 2 argument "" "FLAGS;MSVC_FLAGS" "REQUIRES")
    set(enabled TRUE)
    foreach (requirement IN LISTS argument_REQUIRES)
        if (NOT ${requirement})
            set(enabled FALSE)
        endif ()
    endforeach ()
    if (MSVC)
        set(flags "${argument_MSVC_FLAGS}")
    else ()
        set(flags "${argument_FLAGS}")
    endif ()
    if (enabled)
        check_cxx_compiler_flag("${flags}" ${target_macro})
    else ()
        set(${target_macro} FALSE)
    endif ()
    target_compile_definitions(ucall PUBLIC ${target_macro}=$<BOOL:${${target_macro}}>)
    if (${target_macro})
        target_sources(ucall PRIVATE ${source})
        set_source_files_properties(${source} PROPERTIES COMPILE_FLAGS "${flags}")
    endif ()
endfunction ()

ucall_cpu_variant(
    src/variants_intel_haswell.cpp
    UCALL_TARGET_INTEL_HASWELL
    REQUIRES
    sz_target_haswell_compiles
    sz_target_westmere_compiles
    FLAGS
    "-mavx2 -mfma -mbmi -mbmi2 -mpopcnt -mlzcnt -msse4.2 -maes -mpclmul"
    MSVC_FLAGS
    "/arch:AVX2"
)
ucall_cpu_variant(
    src/variants_intel_skylake.cpp
    UCALL_TARGET_INTEL_SKYLAKE
    REQUIRES
    sz_target_skylake_compiles
    sz_target_westmere_compiles
    FLAGS
    "-mavx2 -mavx512f -mavx512vl -mavx512bw -mavx512dq -mbmi -mbmi2 -mpopcnt -mlzcnt -maes -mpclmul"
    MSVC_FLAGS
    "/arch:AVX512"
)
ucall_cpu_variant(
    src/variants_intel_icelake.cpp
    UCALL_TARGET_INTEL_ICELAKE
    REQUIRES
    sz_target_icelake_compiles
    sz_target_goldmont_compiles
    FLAGS
    "-mavx2 -mavx512f -mavx512vl -mavx512bw -mavx512dq -mavx512vbmi -mavx512vbmi2 -mavx512vnni -mbmi -mbmi2 -mpopcnt -mlzcnt -maes -mvaes -mpclmul -mvpclmulqdq -msha"
    MSVC_FLAGS
    "/arch:AVX512"
)
ucall_cpu_variant(
    src/variants_intel_alder.cpp
    UCALL_TARGET_INTEL_ALDER
    REQUIRES
    sz_target_haswell_compiles
    sz_target_westmere_compiles
    sz_target_goldmont_compiles
    FLAGS
    "-mavx2 -mfma -mbmi -mbmi2 -mpopcnt -mlzcnt -msse4.2 -maes -mpclmul -msha"
    MSVC_FLAGS
    "/arch:AVX2"
)
ucall_cpu_variant(
    src/variants_intel_sierra.cpp
    UCALL_TARGET_INTEL_SIERRA
    REQUIRES
    sz_target_haswell_compiles
    sz_target_westmere_compiles
    sz_target_goldmont_compiles
    fu_target_x86_cmpccxadd_compiles
    FLAGS
    "-mavx2 -mfma -mbmi -mbmi2 -mpopcnt -mlzcnt -msse4.2 -maes -mpclmul -msha"
    MSVC_FLAGS
    "/arch:AVX2"
)
ucall_cpu_variant(
    src/variants_aws_g2.cpp
    UCALL_TARGET_AWS_G2
    REQUIRES
    sz_target_neon_compiles
    sz_target_neonaes_compiles
    sz_target_neonsha_compiles
    fu_target_arm64_lse_compiles
    FLAGS
    "-march=armv8-a+simd+crypto+aes+sha2+lse"
)
ucall_cpu_variant(
    src/variants_apple_m2.cpp
    UCALL_TARGET_APPLE_M2
    REQUIRES
    sz_target_neon_compiles
    sz_target_neonaes_compiles
    sz_target_neonsha_compiles
    fu_target_arm64_lse_compiles
    fu_target_arm64_rcpc_compiles
    FLAGS
    "-march=armv8-a+simd+crypto+aes+sha2+lse+rcpc"
)
ucall_cpu_variant(
    src/variants_aws_g5.cpp
    UCALL_TARGET_AWS_G5
    REQUIRES
    sz_target_sve_compiles
    sz_target_sve2_compiles
    sz_target_sve2aes_compiles
    sz_target_neonsha_compiles
    fu_target_arm64_lse_compiles
    fu_target_arm64_rcpc_compiles
    FLAGS
    "-march=armv8.2-a+sve+sve2+sve2-aes+crypto+lse+rcpc"
)

if (UCALL_BUILD_EXAMPLES)
    foreach (example echo ledger redis)
        add_executable(ucall_example_${example} examples/${example}/server.cpp)
        target_link_libraries(ucall_example_${example} PRIVATE ucall::ucall forkunion::static)
    endforeach ()
endif ()
if (UCALL_BUILD_BENCH)
    add_executable(ucall_bench_http bench/http.cpp)
    target_link_libraries(ucall_bench_http PRIVATE ucall::ucall forkunion::static)
endif ()

if (UCALL_BUILD_TEST)
    enable_testing()
    add_subdirectory(test)
endif ()
