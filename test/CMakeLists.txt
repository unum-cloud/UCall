# Adds @p ARGN to @p target_ where the kernel facility the condition names exists.
function (ucall_engine_sources target_ facility_)
    if (facility_ STREQUAL "LINUX" AND CMAKE_SYSTEM_NAME MATCHES "^(Linux|Android)$")
        target_sources(${target_} PRIVATE ${ARGN})
    elseif (facility_ STREQUAL "LINUX_URING" AND UCALL_WITH_LINUX_URING)
        target_sources(${target_} PRIVATE ${ARGN})
    elseif (facility_ STREQUAL "BSD" AND (APPLE OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD"))
        target_sources(${target_} PRIVATE ${ARGN})
    endif ()
endfunction ()

# The library suite: the outcome word, every engine under every admitted CPU class, and the network cells of every
# compiled backend, admitted class and security mode, each passing its class through the C interface's ceiling.
add_executable(
    ucall_test
    main.cpp
    utilities/types.cpp
    io/posix_engine.cpp
    network.cpp
    network/exchanges.cpp
    network/serving.cpp
    network/replies.cpp
    network/client.cpp
    network/resolving.cpp
    network/metrics.cpp
    network/loops.cpp
)
ucall_engine_sources(ucall_test LINUX io/linux_epollaio_engine.cpp)
ucall_engine_sources(ucall_test LINUX_URING io/linux_uring612_engine.cpp io/linux_uring618_engine.cpp)
ucall_engine_sources(ucall_test BSD io/bsd_kqueue_engine.cpp)
target_include_directories(
    ucall_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} "${PROJECT_SOURCE_DIR}/src" "${PROJECT_SOURCE_DIR}/tools"
)
target_link_libraries(ucall_test PRIVATE ucall_static ucall_sanitizers ucall_warnings fmt::fmt)
# Serial needs no capability, so the library compiles it exactly when it keeps every class that exists.
target_compile_definitions(
    ucall_test PRIVATE UCALL_TARGET_SERIAL=$<BOOL:${UCALL_MULTIVERSIONED}>
                       UCALL_TARGET_MONOVERSIONED=$<NOT:$<BOOL:${UCALL_MULTIVERSIONED}>>
)
add_test(NAME ucall_test COMMAND ucall_test)
set_tests_properties(ucall_test PROPERTIES ENVIRONMENT UCALL_TEST_DIRECT_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR})

# The parsers and the tunnel: HTTP messages, routes, percent codec and multipart, DNS messages and configuration, and
# the tunnel's crypto and records.
add_executable(
    ucall_test_header_only
    header_only.cpp
    http/messages.cpp
    http/routes.cpp
    http/percent.cpp
    http/multipart.cpp
    dns/messages.cpp
    dns/configuration.cpp
    tunnel/crypto.cpp
    tunnel/secure_tunnel.cpp
)
target_include_directories(
    ucall_test_header_only PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} "${PROJECT_SOURCE_DIR}/src"
                                   "${PROJECT_SOURCE_DIR}/tools"
)
# The kit rows name what the library compiled, which a unit at baseline flags cannot infer.
target_link_libraries(
    ucall_test_header_only PRIVATE ucall_static ucall_sanitizers ucall_warnings fmt::fmt stringzilla::header
                                   stringzilla::cpu_capabilities_compiled
)
add_test(NAME ucall_test_header_only COMMAND ucall_test_header_only)

if (UNIX AND TARGET ucall_cli)
    add_executable(ucall_test_tools tools.cpp)
    target_include_directories(
        ucall_test_tools PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} "${PROJECT_SOURCE_DIR}/src" "${PROJECT_SOURCE_DIR}/tools"
    )
    target_link_libraries(ucall_test_tools PRIVATE ucall_static ucall_sanitizers ucall_warnings fmt::fmt)
    add_test(NAME ucall_test_tools COMMAND ucall_test_tools $<TARGET_FILE:ucall_cli>)
endif ()

# The kernel ABI mirrors match the kernel's own spelling, checked at compile time against the build's headers.
if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_library(ucall_test_kernel_abi OBJECT kernel_abi.cpp)
    target_link_libraries(ucall_test_kernel_abi PRIVATE ucall_static ucall_warnings)
endif ()

# libFuzzer drives each parser's oracle from `properties.hpp`, under the sanitizers the `fuzz` preset inherits.
if (UCALL_BUILD_FUZZ)
    foreach (harness_ dns http multipart routes tunnel url)
        add_executable(ucall_fuzz_${harness_} fuzz/${harness_}.cpp)
        target_include_directories(
            ucall_fuzz_${harness_} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} "${PROJECT_SOURCE_DIR}/tools"
        )
        target_compile_options(ucall_fuzz_${harness_} PRIVATE -fsanitize=fuzzer)
        target_link_options(ucall_fuzz_${harness_} PRIVATE -fsanitize=fuzzer)
        target_link_libraries(ucall_fuzz_${harness_} PRIVATE ucall_static ucall_sanitizers ucall_warnings fmt::fmt)
    endforeach ()
endif ()
