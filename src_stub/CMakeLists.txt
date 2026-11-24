# The stand-in for the C interface: a separate library defining the same symbols without the engine, so any consumer - a
# binding suite, a downstream SDK, a bisect - links in seconds and meets every refusal the headers document. It serves
# no network: initialization validates and returns socketless handles, and polling and calling answer `unsupported`.
#
# It compiles the project's names and serial X25519 kit as they are, and reaches only the header-only siblings: the
# route trie and the serial string kits, ForkUnion's atomic references and SmashTable's containers. No CPU class
# variants, no I/O queues, no liburing, so it skips `ucall_setup_library` and sets by hand the properties consumers
# depend on.
#
# The file names match the engine's, `libucall_shared` and `libucall_static`, in a directory of their own, so a suite
# chooses an implementation with one `-L` and the two can never shadow one another.
set(ucall_stub_sources_ types.cpp server.cpp client.cpp ${PROJECT_SOURCE_DIR}/src/types.cpp
                        ${PROJECT_SOURCE_DIR}/src/crypto_x25519_serial.cpp
)

add_library(ucall_shared_stub SHARED ${ucall_stub_sources_})
add_library(ucall_static_stub STATIC ${ucall_stub_sources_})
add_library(ucall::shared_stub ALIAS ucall_shared_stub)
add_library(ucall::static_stub ALIAS ucall_static_stub)

foreach (target_ ucall_shared_stub ucall_static_stub)
    target_include_directories(${target_} PRIVATE ${PROJECT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR})
    target_compile_features(${target_} PRIVATE cxx_std_20)
    target_compile_definitions(${target_} PRIVATE UCALL_VERSION_NAME="${ucall_version_name_}")
    target_link_libraries(
        ${target_}
        PUBLIC ucall_abi
        PRIVATE $<BUILD_INTERFACE:ucall_sanitizers> $<BUILD_INTERFACE:ucall_warnings>
                $<BUILD_INTERFACE:forkunion::header> $<BUILD_INTERFACE:smashtable::header>
                $<BUILD_INTERFACE:stringzilla::header>
    )
    if (WIN32)
        target_link_libraries(${target_} PRIVATE bcrypt ws2_32)
    endif ()
    set_target_properties(
        ${target_}
        PROPERTIES PREFIX "lib"
                   POSITION_INDEPENDENT_CODE ON
                   C_VISIBILITY_PRESET hidden
                   CXX_VISIBILITY_PRESET hidden
                   VISIBILITY_INLINES_HIDDEN ON
                   LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/stub"
                   ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/stub"
                   RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/stub"
    )
    # A root that pins every configuration's directory outranks the plain ones above.
    foreach (configuration_ DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
        set_target_properties(
            ${target_}
            PROPERTIES LIBRARY_OUTPUT_DIRECTORY_${configuration_} "${CMAKE_BINARY_DIR}/stub"
                       ARCHIVE_OUTPUT_DIRECTORY_${configuration_} "${CMAKE_BINARY_DIR}/stub"
                       RUNTIME_OUTPUT_DIRECTORY_${configuration_} "${CMAKE_BINARY_DIR}/stub"
        )
    endforeach ()
endforeach ()

set_target_properties(ucall_shared_stub PROPERTIES OUTPUT_NAME "ucall_shared")
set_target_properties(ucall_static_stub PROPERTIES OUTPUT_NAME "ucall_static")

# As with the engine, the shared flavor exports and its consumers import on Windows, and a C program linking the archive
# with the C driver needs the C++ runtime named.
target_compile_definitions(
    ucall_shared_stub
    PRIVATE UCALL_EXPORTING=1
    INTERFACE UCALL_SHARED=1
)
target_link_libraries(ucall_static_stub INTERFACE $<$<LINK_LANGUAGE:C>:${CMAKE_CXX_IMPLICIT_LINK_LIBRARIES}>)
if (APPLE)
    target_link_options(ucall_shared_stub PRIVATE "LINKER:-exported_symbol,_ucall_*")
elseif (CMAKE_SYSTEM_NAME MATCHES "^(Linux|Android|FreeBSD)$")
    file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/ucall_shared_stub.map" "{\n  global: ucall_*;\n  local: *;\n};\n")
    target_link_options(
        ucall_shared_stub PRIVATE "LINKER:--version-script=${CMAKE_CURRENT_BINARY_DIR}/ucall_shared_stub.map"
    )
endif ()

# A stand-in is not part of the published package, so it stays out of the export set and installs under a subdirectory
# of its own, where it cannot shadow the engine's library.
if (UCALL_INSTALL)
    install(
        TARGETS ucall_shared_stub ucall_static_stub
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/ucall-stub
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/ucall-stub
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/ucall-stub
    )
endif ()
