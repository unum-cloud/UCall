foreach (suite_ shared routes x25519 noise)
    add_executable(ucall_test_${suite_} ${suite_}.cpp)
    target_link_libraries(ucall_test_${suite_} PRIVATE ucall::ucall ucall_sanitizers ucall_warnings fmt::fmt)
    add_test(NAME ${suite_} COMMAND ucall_test_${suite_})
    set_tests_properties(${suite_} PROPERTIES SKIP_RETURN_CODE 77)
endforeach ()

target_link_libraries(ucall_test_noise PRIVATE stringzilla::header)

add_executable(ucall_test_c "${PROJECT_SOURCE_DIR}/c/test.c")
target_link_libraries(ucall_test_c PRIVATE ucall::ucall ucall_sanitizers ucall_warnings)
target_compile_features(ucall_test_c PRIVATE c_std_11)
add_test(NAME c COMMAND ucall_test_c)

add_executable(ucall_test_network network.cpp)
target_link_libraries(ucall_test_network PRIVATE ucall::ucall ucall_sanitizers ucall_warnings fmt::fmt)
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
ucall_network_case(kqueue ${UCALL_WITH_KQUEUE} macos-kqueue)
ucall_network_case(iocp ${UCALL_WITH_IOCP} windows-iocp)

add_executable(ucall_test_polling polling.cpp)
target_link_libraries(ucall_test_polling PRIVATE ucall::ucall ucall_sanitizers ucall_warnings fmt::fmt)
add_test(NAME polling COMMAND ucall_test_polling)
set_tests_properties(
    polling PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77 ENVIRONMENT
                       UCALL_TEST_DIRECT_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}
)

if (UCALL_WITH_LINUX_URING)
    add_executable(ucall_test_uring uring.cpp)
    target_link_libraries(ucall_test_uring PRIVATE ucall::ucall ucall_sanitizers ucall_warnings uring_internal fmt::fmt)
    add_test(NAME uring COMMAND ucall_test_uring)
    set_tests_properties(
        uring PROPERTIES TIMEOUT 30 SKIP_RETURN_CODE 77 ENVIRONMENT
                         UCALL_TEST_DIRECT_DIRECTORY=${CMAKE_CURRENT_BINARY_DIR}
    )
endif ()
