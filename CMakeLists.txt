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

# ThreadSanitizer sees no inline assembly, so ForkUnion leaves out the capabilities it cannot see when told.
set(FORKUNION_BUILD_SANITIZERS ${UCALL_BUILD_SANITIZERS})

if (UCALL_WITH_POSIX AND NOT UNIX)
    message(FATAL_ERROR "The POSIX backend requires a POSIX platform")
endif ()
if ((UCALL_WITH_LINUX_URING OR UCALL_WITH_LINUX_EPOLLAIO) AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "The epoll-AIO and io_uring backends require Linux")
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
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /DEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /O2 /DEBUG")
else ()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions")
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

function (ucall_sibling name_ source_override_ target_ url_ revision_)
    if (TARGET ${target_})
        return()
    endif ()
    if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${name_}/CMakeLists.txt" AND NOT DEFINED
                                                                         FETCHCONTENT_SOURCE_DIR_${source_override_}
    )
        add_subdirectory(${name_} EXCLUDE_FROM_ALL SYSTEM)
    else ()
        FetchContent_Declare(
            ${name_}
            GIT_REPOSITORY ${url_}
            GIT_TAG ${revision_}
            EXCLUDE_FROM_ALL SYSTEM
        )
        FetchContent_MakeAvailable(${name_})
    endif ()
endfunction ()

ucall_sibling(
    stringzilla STRINGZILLA stringzilla::header https://github.com/ashvardanian/StringZilla
    e169620f92db7c5df3a71baf2e035bc43ecf6a39
)
ucall_sibling(
    forkunion FORKUNION forkunion::header https://github.com/ashvardanian/ForkUnion
    0c87b0bb539ccf6d945711a12e73b731530c9fa8
)
ucall_sibling(
    smashtable SMASHTABLE smashtable::header https://github.com/ashvardanian/SmashTable
    07a8cb3800de52a4c0f90e80014b3937b39121dc
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

# Warnings apply to UCall's own targets only, so fetched dependencies build with their own flags. The C interface takes
# named arguments as partially designated structs, leaving the rest zeroed.
add_library(ucall_warnings INTERFACE)
if (MSVC)
    target_compile_options(ucall_warnings INTERFACE /W3)
    if (UCALL_WERROR)
        target_compile_options(ucall_warnings INTERFACE /WX)
    endif ()
else ()
    target_compile_options(
        ucall_warnings
        INTERFACE
            "$<$<COMPILE_LANGUAGE:C,CXX>:-Wall;-Wextra;-Wpedantic;-Wno-unknown-pragmas;-Wno-missing-field-initializers>"
            "$<$<AND:$<COMPILE_LANGUAGE:C,CXX>,$<CXX_COMPILER_ID:Clang,AppleClang>>:-Wdocumentation>"
    )
    if (UCALL_WERROR)
        target_compile_options(ucall_warnings INTERFACE -Werror)
    endif ()
endif ()

# Sanitizers instrument UCall's library and tests, while fetched dependencies keep their own flags.
add_library(ucall_sanitizers INTERFACE)
if (UCALL_BUILD_SANITIZERS STREQUAL "address")
    if (MSVC)
        set(ucall_sanitizer_flags_ /fsanitize=address)
    else ()
        set(ucall_sanitizer_flags_ -fsanitize=address,undefined -fno-omit-frame-pointer)
    endif ()
elseif (UCALL_BUILD_SANITIZERS STREQUAL "thread")
    if (MSVC)
        message(FATAL_ERROR "MSVC has no ThreadSanitizer, so UCALL_BUILD_SANITIZERS=thread needs Clang or GCC")
    endif ()
    set(ucall_sanitizer_flags_ -fsanitize=thread)
elseif (NOT UCALL_BUILD_SANITIZERS STREQUAL "off")
    message(FATAL_ERROR "UCALL_BUILD_SANITIZERS is off, address or thread, not '${UCALL_BUILD_SANITIZERS}'")
endif ()
if (ucall_sanitizer_flags_)
    target_compile_options(ucall_sanitizers INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:${ucall_sanitizer_flags_}>")
    if (NOT MSVC)
        target_link_options(ucall_sanitizers INTERFACE "$<$<LINK_LANGUAGE:C,CXX>:${ucall_sanitizer_flags_}>")
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
foreach (capabilities_ forkunion::cpu_capabilities_compiled stringzilla::cpu_capabilities_compiled)
    if (TARGET ${capabilities_})
        target_link_libraries(ucall PUBLIC ${capabilities_})
    endif ()
endforeach ()
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

function (ucall_cpu_variant class_ target_macro_)
    cmake_parse_arguments(PARSE_ARGV 2 arg "" "FLAGS;MSVC_FLAGS" "REQUIRES")
    set(enabled_ TRUE)
    foreach (requirement_ IN LISTS arg_REQUIRES)
        if (NOT ${requirement_})
            set(enabled_ FALSE)
        endif ()
    endforeach ()
    if (MSVC)
        set(flags_ "${arg_MSVC_FLAGS}")
    else ()
        set(flags_ "${arg_FLAGS}")
    endif ()
    if (enabled_)
        check_cxx_compiler_flag("${flags_}" ucall_class_${class_}_compiles_)
    endif ()
    if (enabled_ AND ucall_class_${class_}_compiles_)
        target_compile_definitions(ucall PUBLIC UCALL_TARGET_${target_macro_}=1)
        target_sources(ucall PRIVATE src/variants_${class_}.cpp)
        set_source_files_properties(src/variants_${class_}.cpp PROPERTIES COMPILE_FLAGS "${flags_}")
    else ()
        target_compile_definitions(ucall PUBLIC UCALL_TARGET_${target_macro_}=0)
    endif ()
endfunction ()

ucall_cpu_variant(
    intel_haswell
    INTEL_HASWELL
    REQUIRES
    stringzilla_target_haswell_compiles
    stringzilla_target_westmere_compiles
    FLAGS
    "-mavx2 -mfma -mbmi -mbmi2 -mpopcnt -mlzcnt -msse4.2 -maes -mpclmul"
    MSVC_FLAGS
    "/arch:AVX2"
)
ucall_cpu_variant(
    intel_skylake
    INTEL_SKYLAKE
    REQUIRES
    stringzilla_target_skylake_compiles
    stringzilla_target_westmere_compiles
    FLAGS
    "-mavx2 -mavx512f -mavx512vl -mavx512bw -mavx512dq -mbmi -mbmi2 -mpopcnt -mlzcnt -maes -mpclmul"
    MSVC_FLAGS
    "/arch:AVX512"
)
ucall_cpu_variant(
    intel_icelake
    INTEL_ICELAKE
    REQUIRES
    stringzilla_target_icelake_compiles
    stringzilla_target_goldmont_compiles
    FLAGS
    "-mavx2 -mavx512f -mavx512vl -mavx512bw -mavx512dq -mavx512vbmi -mavx512vbmi2 -mavx512vnni -mbmi -mbmi2 -mpopcnt -mlzcnt -maes -mvaes -mpclmul -mvpclmulqdq -msha"
    MSVC_FLAGS
    "/arch:AVX512"
)
ucall_cpu_variant(
    intel_alder
    INTEL_ALDER
    REQUIRES
    stringzilla_target_haswell_compiles
    stringzilla_target_westmere_compiles
    stringzilla_target_goldmont_compiles
    FLAGS
    "-mavx2 -mfma -mbmi -mbmi2 -mpopcnt -mlzcnt -msse4.2 -maes -mpclmul -msha"
    MSVC_FLAGS
    "/arch:AVX2"
)
ucall_cpu_variant(
    intel_sierra
    INTEL_SIERRA
    REQUIRES
    stringzilla_target_haswell_compiles
    stringzilla_target_westmere_compiles
    stringzilla_target_goldmont_compiles
    forkunion_target_x86_cmpccxadd_compiles
    FLAGS
    "-mavx2 -mfma -mbmi -mbmi2 -mpopcnt -mlzcnt -msse4.2 -maes -mpclmul -msha"
    MSVC_FLAGS
    "/arch:AVX2"
)
ucall_cpu_variant(
    aws_g2
    AWS_G2
    REQUIRES
    stringzilla_target_neon_compiles
    stringzilla_target_neonaes_compiles
    stringzilla_target_neonsha_compiles
    forkunion_target_arm64_lse_compiles
    FLAGS
    "-march=armv8-a+simd+crypto+aes+sha2+lse"
)
ucall_cpu_variant(
    apple_m2
    APPLE_M2
    REQUIRES
    stringzilla_target_neon_compiles
    stringzilla_target_neonaes_compiles
    stringzilla_target_neonsha_compiles
    forkunion_target_arm64_lse_compiles
    forkunion_target_arm64_rcpc_compiles
    FLAGS
    "-march=armv8-a+simd+crypto+aes+sha2+lse+rcpc"
)
ucall_cpu_variant(
    aws_g5
    AWS_G5
    REQUIRES
    stringzilla_target_sve_compiles
    stringzilla_target_sve2_compiles
    stringzilla_target_sve2aes_compiles
    stringzilla_target_neonsha_compiles
    forkunion_target_arm64_lse_compiles
    forkunion_target_arm64_rcpc_compiles
    FLAGS
    "-march=armv8.2-a+sve+sve2+sve2-aes+crypto+lse+rcpc"
)

if (UCALL_BUILD_TOOLS)
    ucall_sibling(
        numkong NUMKONG numkong::static https://github.com/ashvardanian/NumKong
        49b5140981945527e0ffca4d8037285022b98ad3
    )
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
