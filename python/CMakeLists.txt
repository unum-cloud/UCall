# The CPython extension `ucall.lib`, which `scikit-build-core` drives from `pyproject.toml`.

find_package(Python 3.12 REQUIRED COMPONENTS Interpreter Development.Module)

# Module glue first, then the shared vocabulary, then one file per header of the C interface.
python_add_library(
    ucall_python
    MODULE
    WITH_SOABI
    lib.c
    types.c
    server.c
    client.c
)

# `ucall/__init__.py` imports it as `ucall.lib`, so the file name is part of the interface.
set_target_properties(
    ucall_python
    PROPERTIES OUTPUT_NAME "lib"
               C_STANDARD 11
               C_STANDARD_REQUIRED ON
               C_VISIBILITY_PRESET hidden
               LINKER_LANGUAGE CXX
)
target_include_directories(ucall_python PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ucall_python PRIVATE ucall::ucall)
if (NOT MSVC)
    target_compile_options(ucall_python PRIVATE -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers)
endif ()

# Named, or every dependency's own install rules land in the wheel beside the extension.
install(TARGETS ucall_python LIBRARY DESTINATION ucall COMPONENT ucall_python)
