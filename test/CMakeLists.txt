foreach (suite_ shared routes x25519 noise dns properties)
    add_executable(ucall_test_${suite_} ${suite_}.cpp)
    target_link_libraries(ucall_test_${suite_} PRIVATE ucall_static ucall_sanitizers ucall_warnings fmt::fmt)
    add_test(NAME ${suite_} COMMAND ucall_test_${suite_})
    set_tests_properties(${suite_} PROPERTIES SKIP_RETURN_CODE 77)
endforeach ()

target_link_libraries(ucall_test_noise PRIVATE stringzilla::header)

add_executable(ucall_test_c "${PROJECT_SOURCE_DIR}/c/test.c")
target_link_libraries(ucall_test_c PRIVATE ucall_static ucall_sanitizers ucall_warnings)
target_compile_features(ucall_test_c PRIVATE c_std_11)
add_test(NAME c COMMAND ucall_test_c)

add_executable(
    ucall_test_network network.cpp network/exchanges.cpp network/bodies.cpp network/client.cpp network/files.cpp
)
target_include_directories(ucall_test_network PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ucall_test_network PRIVATE ucall_static ucall_sanitizers ucall_warnings fmt::fmt)
function (ucall_network_case name_ enabled_ backend_)
    if (enabled_)
        add_test(NAME ${name_} COMMAND ucall_test_network --backend ${backend_})
        set_tests_properties(
            ${name_} PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77 ENVIRONMENT
                                UCALL_TEST_DIRECT_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}
        )
    endif ()
endfunction ()
ucall_network_case(parity ON automatic)
set_tests_properties(parity PROPERTIES ENVIRONMENT UCALL_FILTER=test_backend_parity)
ucall_network_case(posix ${UCALL_WITH_POSIX} posix)
ucall_network_case(epollaio ${UCALL_WITH_LINUX_EPOLLAIO} linux-epollaio)
ucall_network_case(uring612 ${UCALL_WITH_LINUX_URING} linux-uring612)
ucall_network_case(uring618 ${UCALL_WITH_LINUX_URING} linux-uring618)
ucall_network_case(kqueue ${UCALL_WITH_KQUEUE} bsd-kqueue)
ucall_network_case(iocp ${UCALL_WITH_IOCP} windows-iocp)

if (UNIX AND TARGET ucall_cli)
    add_executable(ucall_test_cli cli.cpp)
    target_include_directories(ucall_test_cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(ucall_test_cli PRIVATE ucall_static ucall_sanitizers ucall_warnings fmt::fmt)
    add_test(NAME cli COMMAND ucall_test_cli $<TARGET_FILE:ucall_cli>)
    set_tests_properties(cli PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77)
endif ()

add_executable(ucall_test_polling polling.cpp)
target_link_libraries(ucall_test_polling PRIVATE ucall_static ucall_sanitizers ucall_warnings fmt::fmt)
add_test(NAME polling COMMAND ucall_test_polling)
set_tests_properties(
    polling PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77 ENVIRONMENT
                       UCALL_TEST_DIRECT_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}
)

if (UCALL_WITH_LINUX_URING)
    add_executable(ucall_test_uring uring.cpp)
    target_link_libraries(ucall_test_uring PRIVATE ucall_static ucall_sanitizers ucall_warnings uring::uring fmt::fmt)
    add_test(NAME uring COMMAND ucall_test_uring)
    set_tests_properties(
        uring PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77 ENVIRONMENT
                         UCALL_TEST_DIRECT_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}
    )
endif ()

# libFuzzer drives each parser's oracle from `properties.hpp`, under the sanitizers the `fuzz` preset inherits.
if (UCALL_BUILD_FUZZ)
    foreach (harness_ dns http multipart routes tunnel url)
        add_executable(ucall_fuzz_${harness_} fuzz/${harness_}.cpp)
        target_include_directories(ucall_fuzz_${harness_} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        target_compile_options(ucall_fuzz_${harness_} PRIVATE -fsanitize=fuzzer)
        target_link_options(ucall_fuzz_${harness_} PRIVATE -fsanitize=fuzzer)
        target_link_libraries(ucall_fuzz_${harness_} PRIVATE ucall_static ucall_sanitizers ucall_warnings fmt::fmt)
    endforeach ()
endif ()
