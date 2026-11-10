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
    ff22abca2e1f271f37bd8cb10174bc9dd37ed4e7
)
ucall_sibling(
    forkunion FETCHCONTENT_SOURCE_DIR_FORKUNION https://github.com/ashvardanian/ForkUnion
    ce67be6511ce8cfc4b139b3e7266ec0e5edc372c
)
ucall_sibling(
    smashtable FETCHCONTENT_SOURCE_DIR_SMASHTABLE https://github.com/ashvardanian/SmashTable
    30e349dcd1e582896386d959d4a36badce061787
)

if (UCALL_BUILD_EXAMPLES)
    ucall_sibling(
        numkong FETCHCONTENT_SOURCE_DIR_NUMKONG https://github.com/ashvardanian/NumKong
        8870e51d68b11d5a713ce5d647df98d8960f542d
    )
endif ()
