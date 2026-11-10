# UCALL_MARCH sets the floor of UCall's own units, which all link `ucall_warnings`: empty keeps the architecture's
# floor, whatever a distribution compiler defaults to, an ISA level like `x86-64-v3` raises it, `native` tunes for this
# host, and a CPU name like `graniterapids` for that CPU, also when cross-compiling. It lands after the siblings, so
# MSVC reads which capabilities StringZilla found this host runs.
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
    # MSVC has no `/arch:native`, so it takes the `/arch:` of the widest capability this host runs.
    foreach (capability_ IN ITEMS icelake skylake haswell neon)
        if (stringzilla_target_${capability_}_runs AND NOT ucall_arch_flags_)
            set(ucall_arch_flags_ ${stringzilla_target_${capability_}_flags})
        endif ()
    endforeach ()
    target_compile_options(ucall_warnings INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:${ucall_arch_flags_}>")
elseif (UCALL_MARCH AND CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|AARCH64|arm64|ARM64")
    # AArch64 names CPUs through `-mcpu`, like `neoverse-v2`, as `-march` takes only architecture versions.
    target_compile_options(ucall_warnings INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:-mcpu=${UCALL_MARCH}>")
elseif (UCALL_MARCH)
    target_compile_options(ucall_warnings INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:-march=${UCALL_MARCH}>")
elseif (MSVC OR APPLE)
    # MSVC's defaults are the floor, and on Apple `-arch` pins it per slice of a universal build.
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|AARCH64|arm64|ARM64")
    target_compile_options(ucall_warnings INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:-march=armv8-a>")
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    target_compile_options(ucall_warnings INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:-march=x86-64>")
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "riscv64")
    target_compile_options(ucall_warnings INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:-march=rv64gc>")
endif ()
