# The sibling libraries, and the switches UCall forwards to them.

# ThreadSanitizer sees no inline assembly, so ForkUnion leaves out the capabilities it cannot see when told.
set(FORKUNION_BUILD_SANITIZERS ${UCALL_BUILD_SANITIZERS})

# A sibling builds from its nested checkout, or else from the commit its submodule pins, fetched unless the override
# variable the caller passes, `FETCHCONTENT_SOURCE_DIR_<NAME>`, names a local checkout.
function (ucall_sibling name_ override_ repository_ tag_)
    if (TARGET ${name_}::header)
        return()
    endif ()
    if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${name_}/CMakeLists.txt" AND NOT DEFINED ${override_})
        add_subdirectory(${name_} EXCLUDE_FROM_ALL SYSTEM)
    else ()
        FetchContent_Declare(
            ${name_}
            GIT_REPOSITORY ${repository_}
            GIT_TAG ${tag_}
            EXCLUDE_FROM_ALL SYSTEM
        )
        FetchContent_MakeAvailable(${name_})
    endif ()
endfunction ()

# The siblings compile at the same floor and build kind.
set(FORKUNION_MARCH "${UCALL_MARCH}")
set(STRINGZILLA_MARCH "${UCALL_MARCH}")
set(NUMKONG_MARCH "${UCALL_MARCH}")
set(FORKUNION_MULTIVERSIONED ${UCALL_MULTIVERSIONED})
set(STRINGZILLA_MULTIVERSIONED ${UCALL_MULTIVERSIONED})
set(NUMKONG_MULTIVERSIONED ${UCALL_MULTIVERSIONED})

ucall_sibling(
    stringzilla FETCHCONTENT_SOURCE_DIR_STRINGZILLA https://github.com/ashvardanian/StringZilla
    8b16eea7891d5df9f44706972112d739917b5bf3
)
ucall_sibling(
    forkunion FETCHCONTENT_SOURCE_DIR_FORKUNION https://github.com/ashvardanian/ForkUnion
    9a69946aa5e9a8cbe56b51dab1dfae7f2281537d
)
ucall_sibling(
    smashtable FETCHCONTENT_SOURCE_DIR_SMASHTABLE https://github.com/ashvardanian/SmashTable
    788a94f7baef9eae8923009a444fb6b3dae5f8c4
)

if (UCALL_BUILD_EXAMPLES)
    ucall_sibling(
        numkong FETCHCONTENT_SOURCE_DIR_NUMKONG https://github.com/ashvardanian/NumKong
        0a027dc6ab79fed17f08e20a7cd3bdc94e59f655
    )
endif ()
