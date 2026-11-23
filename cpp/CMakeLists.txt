# The header-only C++ SDK over the C interface: `cpp/ucall/*.hpp` include only the C headers `ucall::abi` carries
# and the standard library, which the interface target enforces, so a consumer linking `ucall::cpp` gets the archive
# and sees no engine header.
add_library(ucall_cpp INTERFACE)
add_library(ucall::cpp ALIAS ucall_cpp)
set_target_properties(ucall_cpp PROPERTIES EXPORT_NAME cpp)
target_include_directories(
    ucall_cpp INTERFACE $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/cpp> $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_link_libraries(ucall_cpp INTERFACE ucall::abi ucall::static)
target_compile_features(ucall_cpp INTERFACE cxx_std_20)

# The smoke test against the engine, linked as the C one is, reading the files it replies with from this directory.
if (UCALL_BUILD_TEST)
    add_executable(ucall_test_cpp test.cpp)
    target_link_libraries(ucall_test_cpp PRIVATE ucall::cpp ucall_static ucall_warnings ucall_sanitizers)
    add_test(NAME ucall_test_cpp COMMAND ucall_test_cpp ${CMAKE_CURRENT_SOURCE_DIR})
endif ()

# The same test against the stand-in, which builds without the engine, so an SDK header reaching past `c/` fails to
# compile here. It takes the SDK's headers rather than `ucall::cpp`, which would link the engine's archive.
if (UCALL_BUILD_TEST AND UCALL_BUILD_STUB)
    add_executable(ucall_test_cpp_stub test.cpp)
    target_include_directories(ucall_test_cpp_stub PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_features(ucall_test_cpp_stub PRIVATE cxx_std_20)
    target_link_libraries(ucall_test_cpp_stub PRIVATE ucall::abi ucall_static_stub ucall_warnings ucall_sanitizers)
    add_test(NAME ucall_test_cpp_stub COMMAND ucall_test_cpp_stub ${CMAKE_CURRENT_SOURCE_DIR})
endif ()
