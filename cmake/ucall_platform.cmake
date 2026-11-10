# UCALL_MARCH raises the floor of UCall's own units, which all link `ucall_warnings`: an ISA level like `x86-64-v3`,
# `native` for this host, or a CPU name like `graniterapids`, also when cross-compiling. Fetched dependencies keep their
# own flags.
if (UCALL_MARCH STREQUAL "native" AND CMAKE_CROSSCOMPILING)
    message(FATAL_ERROR "UCALL_MARCH=native needs the host as the target; name a CPU instead")
elseif (
    UCALL_MARCH
    AND MSVC
    AND NOT UCALL_MARCH STREQUAL "native"
)
    message(FATAL_ERROR "MSVC takes UCALL_MARCH=native only; pass an /arch: value such as AVX2 or AVX512 "
                        "through CMAKE_CXX_FLAGS instead of `${UCALL_MARCH}`"
    )
elseif (UCALL_MARCH AND MSVC)
    # MSVC has no `/arch:native`; each class unit already takes its own `/arch:`, so the toolchain default stays.
elseif (UCALL_MARCH AND CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|AARCH64|arm64|ARM64")
    # AArch64 names CPUs through `-mcpu`, like `neoverse-v2`, as `-march` takes only architecture versions.
    target_compile_options(ucall_warnings INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:-mcpu=${UCALL_MARCH}>")
elseif (UCALL_MARCH)
    target_compile_options(ucall_warnings INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:-march=${UCALL_MARCH}>")
endif ()
