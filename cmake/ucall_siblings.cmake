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

# The siblings tune their own units for the same CPU, and probe what this host runs under `native`.
if (UCALL_TARGET_ARCH)
    set(FORKUNION_TARGET_ARCH ${UCALL_TARGET_ARCH})
    set(STRINGZILLA_TARGET_ARCH ${UCALL_TARGET_ARCH})
    set(NUMKONG_TARGET_ARCH ${UCALL_TARGET_ARCH})
endif ()

ucall_sibling(
    stringzilla FETCHCONTENT_SOURCE_DIR_STRINGZILLA https://github.com/ashvardanian/StringZilla
    53fb6a67b188561ffcab506ee3d03901716b1b49
)
ucall_sibling(
    forkunion FETCHCONTENT_SOURCE_DIR_FORKUNION https://github.com/ashvardanian/ForkUnion
    0b9296ebe0dc3886f4f850f0dc97d6ce382ac909
)
ucall_sibling(
    smashtable FETCHCONTENT_SOURCE_DIR_SMASHTABLE https://github.com/ashvardanian/SmashTable
    e45080c7ea61a5a9c7fc90ac8b9595b49b341574
)

if (UCALL_BUILD_TOOLS)
    ucall_sibling(
        numkong FETCHCONTENT_SOURCE_DIR_NUMKONG https://github.com/ashvardanian/NumKong
        3fecca8d625ccc89ba2605e195e621e48446c795
    )
endif ()
