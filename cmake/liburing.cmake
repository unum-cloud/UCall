# liburing: https://github.com/axboe/liburing, built here as a static position-independent archive with this build's
# compilers and flags, so neither a build nor an installed package needs a system liburing, which most distributions
# ship only as a shared library and often older than the backends require.

include(FetchContent)
FetchContent_Declare(
    liburing
    GIT_REPOSITORY https://github.com/axboe/liburing.git
    GIT_TAG liburing-2.15
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(liburing)

# `configure` writes `config-host.h` into the root and `compat.h` and `io_uring_version.h` into `src/include/liburing/`.
# It runs once, so a reconfigure leaves those headers untouched. `--use-libc` keeps the freestanding flags of the
# libc-free build away from sanitizers and the bindings, and a cross build names its target through the compilers, since
# `configure` itself knows none.
if (NOT EXISTS "${liburing_SOURCE_DIR}/config-host.h")
    set(ucall_liburing_cc_ "${CMAKE_C_COMPILER}")
    set(ucall_liburing_cxx_ "${CMAKE_CXX_COMPILER}")
    if (CMAKE_C_COMPILER_TARGET)
        string(APPEND ucall_liburing_cc_ " --target=${CMAKE_C_COMPILER_TARGET}")
        string(APPEND ucall_liburing_cxx_ " --target=${CMAKE_CXX_COMPILER_TARGET}")
    endif ()
    execute_process(
        COMMAND sh ./configure --use-libc "--cc=${ucall_liburing_cc_}" "--cxx=${ucall_liburing_cxx_}"
        WORKING_DIRECTORY "${liburing_SOURCE_DIR}"
        RESULT_VARIABLE ucall_liburing_configured_
        OUTPUT_QUIET
    )
    if (NOT ucall_liburing_configured_ EQUAL 0)
        message(FATAL_ERROR "liburing's configure failed, see ${liburing_SOURCE_DIR}/config.log")
    endif ()
endif ()

add_library(
    uring STATIC
    "${liburing_SOURCE_DIR}/src/setup.c" "${liburing_SOURCE_DIR}/src/queue.c" "${liburing_SOURCE_DIR}/src/register.c"
    "${liburing_SOURCE_DIR}/src/syscall.c" "${liburing_SOURCE_DIR}/src/version.c"
)
add_library(uring::uring ALIAS uring)
target_include_directories(uring SYSTEM PUBLIC $<BUILD_INTERFACE:${liburing_SOURCE_DIR}/src/include>)
target_compile_definitions(uring PRIVATE _GNU_SOURCE _LARGEFILE_SOURCE _FILE_OFFSET_BITS=64 LIBURING_INTERNAL)
target_compile_options(uring PRIVATE -include "${liburing_SOURCE_DIR}/config-host.h")
set_target_properties(uring PROPERTIES POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
