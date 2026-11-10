# Warnings and sanitizers, which UCall's own targets take through `ucall_warnings` and `ucall_sanitizers`.

# Warnings apply to UCall's own targets only, so fetched dependencies build with their own flags. The C interface takes
# named arguments as partially designated structs, leaving the rest zeroed.
add_library(ucall_warnings INTERFACE)
if (MSVC)
    # The conformance switches MSVC leaves off by default, which every other supported compiler behaves as.
    target_compile_options(ucall_warnings INTERFACE /W3 /permissive- /Zc:preprocessor /Zc:__cplusplus /utf-8 /bigobj)
    if (UCALL_WERROR)
        target_compile_options(ucall_warnings INTERFACE /WX)
    endif ()
else ()
    target_compile_options(
        ucall_warnings
        INTERFACE
            "$<$<COMPILE_LANGUAGE:C,CXX>:-Wall;-Wextra;-Wpedantic;-Wno-unknown-pragmas;-Wno-missing-field-initializers>"
            "$<$<AND:$<COMPILE_LANGUAGE:C,CXX>,$<CXX_COMPILER_ID:Clang,AppleClang>>:-Wdocumentation>"
    )
    if (UCALL_WERROR)
        target_compile_options(ucall_warnings INTERFACE -Werror)
    endif ()
    target_compile_options(ucall_warnings INTERFACE $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>)
endif ()

# Sanitizers instrument UCall's library and tests, while fetched dependencies keep their own flags.
add_library(ucall_sanitizers INTERFACE)
if (UCALL_BUILD_SANITIZERS STREQUAL "address")
    if (MSVC)
        set(ucall_sanitizer_flags_ /fsanitize=address)
    else ()
        set(ucall_sanitizer_flags_ -fsanitize=address,undefined -fno-omit-frame-pointer)
    endif ()
elseif (UCALL_BUILD_SANITIZERS STREQUAL "thread")
    if (MSVC)
        message(FATAL_ERROR "MSVC has no ThreadSanitizer, so UCALL_BUILD_SANITIZERS=thread needs Clang or GCC")
    endif ()
    set(ucall_sanitizer_flags_ -fsanitize=thread)
elseif (NOT UCALL_BUILD_SANITIZERS STREQUAL "off")
    message(FATAL_ERROR "UCALL_BUILD_SANITIZERS is off, address or thread, not '${UCALL_BUILD_SANITIZERS}'")
endif ()
if (ucall_sanitizer_flags_)
    target_compile_options(ucall_sanitizers INTERFACE "$<$<COMPILE_LANGUAGE:C,CXX>:${ucall_sanitizer_flags_}>")
    if (NOT MSVC)
        target_link_options(ucall_sanitizers INTERFACE "$<$<LINK_LANGUAGE:C,CXX>:${ucall_sanitizer_flags_}>")
    endif ()
endif ()
