# The sibling helper, the switches forwarded to the siblings, and the siblings themselves.

include(FetchContent)

# A sibling builds in place from its submodule when a recursive clone checked one out, or else from the commit that
# submodule pins, fetched, so a plain clone or a `FetchContent` of UCall still configures.
# The caller names the sibling's `FETCHCONTENT_SOURCE_DIR_<NAME>`, so nothing derives it.
# A non-empty one points the sibling at a local checkout, as in a workspace keeping the siblings side by side, and
# outranks the submodule.
# A parent project that already added the sibling keeps its copy.
# Every sibling is a system dependency that builds only what UCall's targets link, so its own warnings never fail a
# build under UCALL_WERROR.
function (ucall_sibling name_ override_ repository_ tag_)
    if (TARGET ${name_}::header)
        return()
    endif ()
    if (EXISTS "${PROJECT_SOURCE_DIR}/${name_}/CMakeLists.txt" AND NOT ${override_})
        add_subdirectory("${PROJECT_SOURCE_DIR}/${name_}" "${PROJECT_BINARY_DIR}/${name_}" EXCLUDE_FROM_ALL SYSTEM)
        return()
    endif ()
    message(STATUS "ucall: ${name_} from its local checkout, or else fetched at ${tag_}")
    FetchContent_Declare(
        ${name_}
        GIT_REPOSITORY ${repository_}
        GIT_TAG ${tag_}
        EXCLUDE_FROM_ALL SYSTEM
    )
    FetchContent_MakeAvailable(${name_})
endfunction ()

# The siblings build for the floor, the build kind and the sanitizer UCall builds for, each taking only the
# switches it reads. ThreadSanitizer then sees their barriers, and ForkUnion leaves out the instructions it cannot see.
set(NUMKONG_MARCH "${UCALL_MARCH}")
set(NUMKONG_MULTIVERSIONED "${UCALL_MULTIVERSIONED}")
set(NUMKONG_BUILD_SANITIZERS "${UCALL_BUILD_SANITIZERS}")
set(STRINGZILLA_MARCH "${UCALL_MARCH}")
set(STRINGZILLA_MULTIVERSIONED "${UCALL_MULTIVERSIONED}")
set(STRINGZILLA_BUILD_SANITIZERS "${UCALL_BUILD_SANITIZERS}")
set(FORKUNION_MARCH "${UCALL_MARCH}")
set(FORKUNION_MULTIVERSIONED "${UCALL_MULTIVERSIONED}")
set(FORKUNION_BUILD_SANITIZERS "${UCALL_BUILD_SANITIZERS}")
set(SMASHTABLE_BUILD_SANITIZERS "${UCALL_BUILD_SANITIZERS}")

# Everything below is this project's own: the siblings it builds on, at the commits their submodules pin.

# StringZilla: the find, compare and hash kits each CPU class unit inlines, and the X25519 kits' instruction sets.
# ForkUnion: the thread pools and the ISA-specific waiters and atomics.
# SmashTable: the route tables, connection pools and intrusive lists, header-only.
ucall_sibling(
    stringzilla FETCHCONTENT_SOURCE_DIR_STRINGZILLA https://github.com/ashvardanian/StringZilla
    4ac15c46016516fd8d22bf453126c70d9a88bb81
)
ucall_sibling(
    forkunion FETCHCONTENT_SOURCE_DIR_FORKUNION https://github.com/ashvardanian/ForkUnion
    625811b9446897342126a01674f5d548c6de7110
)
ucall_sibling(
    smashtable FETCHCONTENT_SOURCE_DIR_SMASHTABLE https://github.com/ashvardanian/SmashTable
    30e349dcd1e582896386d959d4a36badce061787
)

# NumKong: the packed dot products only the inference example serves.
if (UCALL_BUILD_EXAMPLES)
    ucall_sibling(
        numkong FETCHCONTENT_SOURCE_DIR_NUMKONG https://github.com/ashvardanian/NumKong
        1febcfe4a62abc70a9b59d303f3632af1c8214ca
    )
endif ()
