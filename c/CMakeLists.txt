# The C interface compiled as C11 against the archive, which the C driver links without the C++ runtime it needs.
add_executable(ucall_test_c test.c)
target_link_libraries(ucall_test_c PRIVATE ucall_static ucall_sanitizers ucall_warnings)
target_compile_features(ucall_test_c PRIVATE c_std_11)
add_test(NAME ucall_test_c COMMAND ucall_test_c)

# The same suite against the stand-in in `src_stub/`, so a verb the stand-in answers differently from the headers fails
# here rather than in the binding a bisect points it at.
if (UCALL_BUILD_STUB)
    add_executable(ucall_test_c_stub test.c)
    target_link_libraries(ucall_test_c_stub PRIVATE ucall_shared_stub ucall_sanitizers ucall_warnings)
    target_compile_features(ucall_test_c_stub PRIVATE c_std_11)
    add_test(NAME ucall_test_c_stub COMMAND ucall_test_c_stub)
endif ()
