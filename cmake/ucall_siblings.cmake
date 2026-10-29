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
if (UCALL_MARCH)
    set(FORKUNION_MARCH ${UCALL_MARCH})
    set(STRINGZILLA_MARCH ${UCALL_MARCH})
    set(NUMKONG_MARCH ${UCALL_MARCH})
endif ()
set(FORKUNION_MULTIVERSIONED ${UCALL_MULTIVERSIONED})
set(STRINGZILLA_MULTIVERSIONED ${UCALL_MULTIVERSIONED})
set(NUMKONG_MULTIVERSIONED ${UCALL_MULTIVERSIONED})

ucall_sibling(
    stringzilla FETCHCONTENT_SOURCE_DIR_STRINGZILLA https://github.com/ashvardanian/StringZilla
    cff25ca8f55aa223dd6ab437b8665009e928e493
)
ucall_sibling(
    forkunion FETCHCONTENT_SOURCE_DIR_FORKUNION https://github.com/ashvardanian/ForkUnion
    53b2c33f7fd2f06c5c6e36de8104ec7a19a66696
)
ucall_sibling(
    smashtable FETCHCONTENT_SOURCE_DIR_SMASHTABLE https://github.com/ashvardanian/SmashTable
    7bc9e00713929c4273099dce3d1e4e6d61bea4af
)

if (UCALL_BUILD_TOOLS)
    ucall_sibling(
        numkong FETCHCONTENT_SOURCE_DIR_NUMKONG https://github.com/ashvardanian/NumKong
        8b3df749915fdcc01e563df8ff119c3e09c04789
    )
endif ()
