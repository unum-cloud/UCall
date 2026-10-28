# The backends each OS supports, and the CPU UCall's own units are tuned for.

if (UCALL_WITH_POSIX AND NOT UNIX)
    message(FATAL_ERROR "The POSIX backend requires a POSIX platform")
endif ()
if (UCALL_WITH_LINUX_URING AND NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "The io_uring backends require Linux")
endif ()
if (UCALL_WITH_LINUX_EPOLLAIO AND NOT CMAKE_SYSTEM_NAME MATCHES "^(Linux|Android)$")
    message(FATAL_ERROR "The epoll-AIO backend requires Linux or Android")
endif ()
if (UCALL_WITH_KQUEUE AND NOT (APPLE OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD"))
    message(FATAL_ERROR "The kqueue backend requires macOS or FreeBSD")
endif ()
if (UCALL_WITH_IOCP AND NOT WIN32)
    message(FATAL_ERROR "The IOCP backend requires Windows")
endif ()

# UCALL_TARGET_ARCH tunes UCall's own units, which all link `ucall_warnings`, for one CPU: `native` for this host, or a
# CPU name like `graniterapids`, also when cross-compiling. Fetched dependencies keep their own flags.
if (UCALL_TARGET_ARCH STREQUAL "native" AND CMAKE_CROSSCOMPILING)
    message(FATAL_ERROR "UCALL_TARGET_ARCH=native needs the host as the target; name a CPU instead")
elseif (
    UCALL_TARGET_ARCH
    AND MSVC
    AND NOT UCALL_TARGET_ARCH STREQUAL "native"
)
    message(FATAL_ERROR "MSVC takes UCALL_TARGET_ARCH=native only; pass an /arch: value such as AVX2 or AVX512 "
                        "through CMAKE_CXX_FLAGS instead of `${UCALL_TARGET_ARCH}`"
    )
elseif (UCALL_TARGET_ARCH AND MSVC)
    # MSVC has no `/arch:native`; each class unit already takes its own `/arch:`, so the toolchain default stays.
elseif (UCALL_TARGET_ARCH AND CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|AARCH64|arm64|ARM64")
    # AArch64 names CPUs through `-mcpu`, like `neoverse-v2`, as `-march` takes only architecture versions.
    target_compile_options(ucall_warnings INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:-mcpu=${UCALL_TARGET_ARCH}>")
elseif (UCALL_TARGET_ARCH)
    target_compile_options(ucall_warnings INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:-march=${UCALL_TARGET_ARCH}>")
endif ()
