cmake_minimum_required (VERSION 3.14 FATAL_ERROR)
project (ucall LANGUAGES CXX C)

set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED YES)
set (CMAKE_CXX_EXTENSIONS NO)

set (CMAKE_C_STANDARD 99)
set (CMAKE_C_STANDARD_REQUIRED YES)
set (CMAKE_C_EXTENSIONS NO)

set (UCALL_BACKEND_SUPPORTED_POSIX OFF)
set (UCALL_BACKEND_SUPPORTED_EPOLL OFF)
set (UCALL_BACKEND_SUPPORTED_URING OFF)

set (UCALL_TARGET_NAME_PY_POSIX "py_ucall_posix")
set (UCALL_TARGET_NAME_PY_EPOLL "py_ucall_epoll")
set (UCALL_TARGET_NAME_PY_URING "py_ucall_uring")

set (UCALL_TARGET_NAME_CPP_POSIX "ucall_server_posix")
set (UCALL_TARGET_NAME_CPP_EPOLL "ucall_server_epoll")
set (UCALL_TARGET_NAME_CPP_URING "ucall_server_uring")

# If the user enables `UCALL_BUILD_AUTO=1`, we will auto-detect supported backends. That's the default behaviour.
option (UCALL_BUILD_AUTO "Builds the POSIX server backend" ON)
if (UCALL_BUILD_AUTO)
  set (UCALL_BACKEND_SUPPORTED_POSIX ON)
  if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    set (UCALL_BACKEND_SUPPORTED_EPOLL ON)
    execute_process (
      COMMAND uname -r
      OUTPUT_VARIABLE KERNEL_VERSION
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if (${KERNEL_VERSION} VERSION_GREATER_EQUAL "5.19")
      set (UCALL_BACKEND_SUPPORTED_URING ON)
    endif ()
  endif ()
endif ()

option (UCALL_BUILD_POSIX "Builds the POSIX server backend" ${UCALL_BACKEND_SUPPORTED_POSIX})
option (UCALL_BUILD_EPOLL "Builds the EPOLL server backend" ${UCALL_BACKEND_SUPPORTED_EPOLL})
option (UCALL_BUILD_URING "Builds the I/O URING server backend" ${UCALL_BACKEND_SUPPORTED_URING})

option (UCALL_BUILD_PYTHON "Builds Python bindings for UCall server targets" OFF)
option (UCALL_BUILD_EXAMPLES "Builds examples, that can be used for benchmarking and tutorials" OFF)

# Make Release by default
if (NOT CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Release)
endif ()

# Make Release by default
if (NOT CMAKE_BUILD_TYPE)
  set (
    CMAKE_BUILD_TYPE
    Release
    CACHE STRING "Build type" FORCE
  )
endif ()

# Set binary and library output directories
set (CMAKE_BINARY_DIR "${CMAKE_SOURCE_DIR}/build")
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set (CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

# Set position independent code property
set (CMAKE_POSITION_INDEPENDENT_CODE ON)

# Set compiler flags
if (MSVC)
  add_compile_options (/W3 /O2)
else ()
  add_compile_options (-pedantic -fPIC -fno-exceptions -O3)
endif ()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  add_compile_options (-fmax-errors=1)
endif ()

# Supporting Universal Binaries on MacOS
if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set (
    CMAKE_OSX_DEPLOYMENT_TARGET
    "11"
    CACHE STRING "Minimum OS X deployment version"
  )
  set (
    CMAKE_OSX_ARCHITECTURES
    "x86_64;arm64"
    CACHE STRING "Target architectures"
  )
  add_compile_options (-stdlib=libc++ -std=c++17)
endif ()

include (FetchContent)
include (ExternalProject)

FetchContent_Declare (
  simdjson
  GIT_REPOSITORY https://github.com/simdjson/simdjson.git
  GIT_TAG v3.1.6
  GIT_SHALLOW 1
)
FetchContent_MakeAvailable (simdjson)
include_directories (${simdjson_SOURCE_DIR}/include)

# CLI
FetchContent_Declare (
  cxxopts
  GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
  GIT_TAG v3.1.1
  GIT_SHALLOW 1
)
FetchContent_MakeAvailable (cxxopts)
include_directories (${cxxopts_SOURCE_DIR}/include)

# Parsing HTTP headers On MacOS you may need to locate headers here: export
# CPATH=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/
FetchContent_Declare (
  picohttpparser
  GIT_REPOSITORY https://github.com/unum-cloud/picohttpparser.git
  GIT_SHALLOW 1
)
FetchContent_MakeAvailable (picohttpparser)
include_directories (${picohttpparser_SOURCE_DIR})

# Base64 decoding
FetchContent_Declare (
  tb64
  GIT_REPOSITORY https://github.com/unum-cloud/Turbo-Base64.git
  GIT_SHALLOW 1
)
FetchContent_MakeAvailable (tb64)
include_directories (${tb64_SOURCE_DIR})

# OpenSSL content
FetchContent_Declare (
  OpenSSL
  GIT_REPOSITORY https://github.com/openssl/openssl.git
  GIT_TAG openssl-3.1.3
  GIT_SHALLOW 1
)
FetchContent_MakeAvailable (OpenSSL)
find_package (OpenSSL REQUIRED)

# LibUring
if (UCALL_BUILD_URING)
  set (URING_DIR ${CMAKE_BINARY_DIR}/_deps/liburing-ep)
  ExternalProject_Add (
    liburing-ep
    GIT_REPOSITORY https://github.com/axboe/liburing.git
    GIT_TAG liburing-2.3
    GIT_SHALLOW 1
    PREFIX ${CMAKE_BINARY_DIR}/_deps/
    SOURCE_DIR ${URING_DIR}
    CONFIGURE_COMMAND echo Configuring LibUring && cd ${URING_DIR} && ./configure --nolibc --cc=${CMAKE_C_COMPILER}
                      --cxx=${CMAKE_CXX_COMPILER};
    BUILD_COMMAND cd ${URING_DIR} && make;
    INSTALL_COMMAND ""
    UPDATE_COMMAND ""
  )
  add_library (uring_internal STATIC IMPORTED GLOBAL)
  add_dependencies (uring_internal liburing-ep)
  set_property (TARGET uring_internal PROPERTY IMPORTED_LOCATION ${URING_DIR}/src/liburing.a)

  include_directories (${URING_DIR}/src/include/)
  set (URING_LIBS uring_internal)
endif ()

find_package (Threads REQUIRED)

# `crypto` comes from LibreSSL if it is built, otherwise from system libssl
set (UCALL_DEPS_TLS OpenSSL::SSL OpenSSL::Crypto)
set (UCALL_DEPS_PARSING simdjson::simdjson Threads::Threads)
set (UCALL_DEPS_PYTHON base64)

include_directories (include/ src/headers)

#[[
  Build all requested server backends:
  1. UCALL_TARGET_NAME_CPP_POSIX, which defaults to "ucall_server_posix"
  2. UCALL_TARGET_NAME_CPP_EPOLL, which defaults to "ucall_server_epoll"
  3. UCALL_TARGET_NAME_CPP_URING, which defaults to "ucall_server_uring"
]]
if (UCALL_BUILD_POSIX)
  add_library (${UCALL_TARGET_NAME_CPP_POSIX} src/engine_posix.cpp)
  target_link_libraries (${UCALL_TARGET_NAME_CPP_POSIX} ${UCALL_DEPS_PARSING} ${UCALL_DEPS_TLS})
  set (UCALL_BUILD_SERVER_TARGETS ${UCALL_BUILD_SERVER_TARGETS} ${UCALL_TARGET_NAME_CPP_POSIX})
endif ()

if (UCALL_BUILD_EPOLL)
  add_library (${UCALL_TARGET_NAME_CPP_EPOLL} src/engine_epoll.cpp)
  target_link_libraries (${UCALL_TARGET_NAME_CPP_EPOLL} ${UCALL_DEPS_PARSING} ${UCALL_DEPS_TLS})
  set (UCALL_BUILD_SERVER_TARGETS ${UCALL_BUILD_SERVER_TARGETS} ${UCALL_TARGET_NAME_CPP_EPOLL})
endif ()

if (UCALL_BUILD_URING)
  add_library (${UCALL_TARGET_NAME_CPP_URING} src/engine_uring.cpp)
  target_link_libraries (${UCALL_TARGET_NAME_CPP_URING} ${UCALL_DEPS_PARSING} ${URING_LIBS} ${UCALL_DEPS_TLS})
  set (UCALL_BUILD_SERVER_TARGETS ${UCALL_BUILD_SERVER_TARGETS} ${UCALL_TARGET_NAME_CPP_EPOLL})
endif ()

#[[
  Build Python bindings to every requested backend:
  1. UCALL_TARGET_NAME_PY_POSIX, which defaults to "py_ucall_posix"
  2. UCALL_TARGET_NAME_PY_EPOLL, which defaults to "py_ucall_epoll"
  3. UCALL_TARGET_NAME_PY_URING, which defaults to "py_ucall_uring"
]]
if (UCALL_BUILD_PYTHON)
  find_package (Python3 REQUIRED Development.Module)
  include_directories (${Python_INCLUDE_DIRS})

  if (UCALL_BUILD_POSIX)
    add_library (${UCALL_TARGET_NAME_PY_POSIX} SHARED src/python.c)
    target_include_directories (${UCALL_TARGET_NAME_PY_POSIX} PUBLIC src/ include/)
    target_compile_definitions (${UCALL_TARGET_NAME_PY_POSIX} PRIVATE UCALL_PYTHON_MODULE_NAME=posix)
    target_link_libraries (${UCALL_TARGET_NAME_PY_POSIX} ${UCALL_TARGET_NAME_CPP_POSIX} ${UCALL_DEPS_PYTHON})
    set_target_properties (${UCALL_TARGET_NAME_PY_POSIX} PROPERTIES PREFIX "")
    set_target_properties (${UCALL_TARGET_NAME_PY_POSIX} PROPERTIES OUTPUT_NAME ${UCALL_TARGET_NAME_PY_POSIX})

  endif ()

  if (UCALL_BUILD_EPOLL)
    add_library (${UCALL_TARGET_NAME_PY_EPOLL} SHARED src/python.c)
    target_include_directories (${UCALL_TARGET_NAME_PY_EPOLL} PUBLIC src/ include/)
    target_compile_definitions (${UCALL_TARGET_NAME_PY_POSIX} PRIVATE UCALL_PYTHON_MODULE_NAME=epoll)
    target_link_libraries (${UCALL_TARGET_NAME_PY_EPOLL} ${UCALL_TARGET_NAME_CPP_EPOLL} ${UCALL_DEPS_PYTHON})
    set_target_properties (${UCALL_TARGET_NAME_PY_EPOLL} PROPERTIES PREFIX "")
    set_target_properties (${UCALL_TARGET_NAME_PY_EPOLL} PROPERTIES OUTPUT_NAME ${UCALL_TARGET_NAME_PY_EPOLL})
  endif ()

  if (UCALL_BUILD_URING)
    add_library (${UCALL_TARGET_NAME_PY_URING} SHARED src/python.c)
    target_include_directories (${UCALL_TARGET_NAME_PY_URING} PUBLIC src/ include/)
    target_compile_definitions (${UCALL_TARGET_NAME_PY_POSIX} PRIVATE UCALL_PYTHON_MODULE_NAME=uring)
    target_link_libraries (${UCALL_TARGET_NAME_PY_URING} ${UCALL_TARGET_NAME_CPP_URING} ${UCALL_DEPS_PYTHON})
    set_target_properties (${UCALL_TARGET_NAME_PY_URING} PROPERTIES PREFIX "")
    set_target_properties (${UCALL_TARGET_NAME_PY_URING} PROPERTIES OUTPUT_NAME ${UCALL_TARGET_NAME_PY_URING})
  endif ()
endif ()

#[[
  Build example servers for every one of the requested backends:
  1. ucall_example_login_${backend_name}: a simple login server, that uses JSON-RPC
  2. ucall_example_rest_${backend_name}:
  3. ucall_example_redis_${backend_name}: an hash-table over REST API
]]
if (UCALL_BUILD_EXAMPLES)

  foreach (backend IN LISTS UCALL_BUILD_SERVER_TARGETS)
    string (FIND "${backend}" "_" last_underscore REVERSE)
    math (EXPR substring_length "${last_underscore} + 1")
    string (SUBSTRING "${backend}" ${substring_length} -1 backend_name)

    set (jsonrpc_example_name "ucall_example_login_${backend_name}")
    set (rest_example_name "ucall_example_rest_${backend_name}")
    set (redis_example_name "ucall_example_redis_${backend_name}")

    add_executable (${jsonrpc_example_name} examples/login/ucall_server.cpp)
    target_link_libraries (${jsonrpc_example_name} ${backend} cxxopts)
    target_compile_options (${jsonrpc_example_name} PUBLIC -DCXXOPTS_NO_EXCEPTIONS=ON)

    add_executable (${rest_example_name} examples/login/ucall_server_rest.cpp)
    target_link_libraries (${rest_example_name} ${backend} cxxopts)
    target_compile_options (${rest_example_name} PUBLIC -DCXXOPTS_NO_EXCEPTIONS=ON)

    add_executable (${redis_example_name} examples/redis/ucall_server.cpp)
    target_link_libraries (${redis_example_name} ${backend} cxxopts)
    target_compile_options (${redis_example_name} PUBLIC -DCXXOPTS_NO_EXCEPTIONS=ON)

  endforeach ()

endif ()

get_directory_property (_targets DIRECTORY ${CMAKE_SOURCE_DIR} BUILDSYSTEM_TARGETS)
foreach (_target IN LISTS _targets)
  get_target_property (_target_type ${_target} TYPE)
  if (_target_type STREQUAL "EXECUTABLE"
      OR _target_type STREQUAL "SHARED_LIBRARY"
      OR _target_type STREQUAL "STATIC_LIBRARY"
  )
    add_custom_command (
      TARGET ${_target}
      POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E echo "-+-+ Target $<TARGET_FILE_NAME:${_target}> is at $<TARGET_FILE:${_target}>"
    )
  endif ()
endforeach ()
