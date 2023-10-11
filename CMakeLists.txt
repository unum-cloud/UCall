cmake_minimum_required(VERSION 3.14 FATAL_ERROR)
project(ucall LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS NO)

option(UCALL_BUILD_BENCHMARKS
       "Builds all available backend for the summation server to run benchmarks"
       OFF)
option(UCALL_BUILD_EXAMPLES
       "Builds examples for Redis-like server and PyTorch deployment")
message("CMAKE_SYSTEM_NAME: ${CMAKE_SYSTEM_NAME}")

# Make Release by default
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

if(NOT CMAKE_BINARY_DIR OR ${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  set(CMAKE_BINARY_DIR "${CMAKE_SOURCE_DIR}/build")
endif()
set(CMAKE_CACHEFILE_DIR ${CMAKE_BINARY_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/lib"
    CACHE PATH "Path to static libs")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/lib"
    CACHE PATH "Path to shared libs")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(MSVC)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /DEBUG")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2")
  set(CMAKE_CXX_FLAGS_RELWITHDEBINFO
      "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /O2 /DEBUG")
else()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-exceptions")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fmax-errors=1")
endif()

# Check if we are running on Linux
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(LINUX TRUE)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set(CMAKE_OSX_DEPLOYMENT_TARGET "11")
  set(CMAKE_OSX_SYSROOT
      CACHE STRING "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk")
  set(CMAKE_OSX_DEPLOYMENT_TARGET
      "11"
      CACHE STRING "Minimum OS X deployment version")
  set(CMAKE_OSX_ARCHITECTURES
      "x86_64" "universal2" "arm64"
      CACHE STRING "Minimum OS X deployment version")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++ -std=c++17")
endif()

# Pull the version of Linux kernel, to check if io_uring is available
if(LINUX)
  execute_process(
    COMMAND uname -r
    OUTPUT_VARIABLE UNAME_RESULT
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  message(-- " Linux Kernel version: " ${UNAME_RESULT})
  string(REGEX MATCH "[0-9]+.[0-9]+" LINUX_KERNEL_VERSION ${UNAME_RESULT})
endif()

include_directories(include/ src/headers)

include(FetchContent)
include(ExternalProject)

FetchContent_Declare(
  simdjson
  GIT_REPOSITORY https://github.com/simdjson/simdjson.git
  GIT_TAG v3.1.6
  GIT_SHALLOW 1)
FetchContent_MakeAvailable(simdjson)
include_directories(${simdjson_SOURCE_DIR}/include)

if(${UCALL_BUILD_BENCHMARKS})
  set(BENCHMARK_ENABLE_TESTING OFF)
  set(BENCHMARK_ENABLE_INSTALL OFF)
  set(BENCHMARK_ENABLE_DOXYGEN OFF)
  set(BENCHMARK_INSTALL_DOCS OFF)
  set(BENCHMARK_DOWNLOAD_DEPENDENCIES ON)
  set(BENCHMARK_ENABLE_GTEST_TESTS OFF)
  set(BENCHMARK_USE_BUNDLED_GTEST ON)
  FetchContent_Declare(
    benchmark
    GIT_REPOSITORY https://github.com/google/benchmark
    GIT_TAG v1.7.0
    GIT_SHALLOW 1)
  FetchContent_MakeAvailable(benchmark)
  include_directories(${benchmark_SOURCE_DIR}/include)
endif()

# CLI
FetchContent_Declare(
  cxxopts
  GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
  GIT_TAG v3.1.1
  GIT_SHALLOW 1)
FetchContent_MakeAvailable(cxxopts)
include_directories(${cxxopts_SOURCE_DIR}/include)

# Parsing HTTP headers On MacOS you may need to locate headers here: export
# CPATH=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/
FetchContent_Declare(
  picohttpparser
  GIT_REPOSITORY https://github.com/unum-cloud/picohttpparser.git
  GIT_SHALLOW 1)
FetchContent_MakeAvailable(picohttpparser)
include_directories(${picohttpparser_SOURCE_DIR})

# Base64 decoding
FetchContent_Declare(
  tb64
  GIT_REPOSITORY https://github.com/unum-cloud/Turbo-Base64.git
  GIT_SHALLOW 1)
FetchContent_MakeAvailable(tb64)
include_directories(${tb64_SOURCE_DIR})

if(NOT CMAKE_BUILD_TYPE STREQUAL Debug)
  FetchContent_Declare(
    OpenSSL
    URL https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.7.3.tar.gz
        OVERRIDE_FIND_PACKAGE)

  FetchContent_MakeAvailable(OpenSSL)
  if(IS_DIRECTORY "${LibreSSL_SOURCE_DIR}")
    set_property(DIRECTORY ${LibreSSL_SOURCE_DIR} PROPERTY EXCLUDE_FROM_ALL YES)
  endif()
  set(OPENSSL_INCLUDE_DIR ${LibreSSL_SOURCE_DIR}/include)
  set(OPENSSL_VERSION "1.1.1")
  set(OPENSSL_FOUND true)
  include_directories(${OPENSSL_INCLUDE_DIR})
  list(GET OPENSSL_CRYPTO_LIBRARIES 0 OPENSSL_ONE_LIB_PATH)
  get_filename_component(OPENSSL_LIBDIR "${OPENSSL_ONE_LIB_PATH}" DIRECTORY)
endif()

if(MSVC)
  set(PICOTLS_DIR ${CMAKE_BINARY_DIR}/_deps/picotls-ep)
  set(PICOTLSVS_DIR ${PICOTLS_DIR}/picotlsvs)

  ExternalProject_Add(
    picotls
    GIT_REPOSITORY https://github.com/h2o/picotls.git
    GIT_TAG master
    DEPENDS crypto
    PREFIX ${CMAKE_BINARY_DIR}/_deps/
    SOURCE_DIR ${PICOTLS_DIR}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND
      cd ${PICOTLSVS_DIR} && MSBuild.exe picotlsvs.sln -target:picotls-core
      -target:picotls-openssl -p:OPENSSL64DIR=${LibreSSL_SOURCE_DIR}
      -p:Configuration=Release -p:PlatformToolset=v141
      -p:WindowsTargetPlatformVersion=10.0.17763.0
    INSTALL_COMMAND ""
    UPDATE_COMMAND "")
  add_library(picotls-core STATIC IMPORTED GLOBAL)
  add_dependencies(picotls-core picotls)
  set_property(
    TARGET picotls-core PROPERTY IMPORTED_LOCATION
                                 ${PICOTLSVS_DIR}/x64/Release/picotls-core.lib)
  add_library(picotls-openssl STATIC IMPORTED GLOBAL)
  add_dependencies(picotls-openssl picotls)
  set_property(
    TARGET picotls-openssl
    PROPERTY IMPORTED_LOCATION ${PICOTLSVS_DIR}/x64/Release/picotls-openssl.lib)

  include_directories(${PICOTLS_DIR}/include/ ${PICOTLSVS_DIR}/picotls)
  set(URING_LIBS uring_internal)
else()
  FetchContent_Declare(
    picotls
    GIT_REPOSITORY https://github.com/h2o/picotls.git
    GIT_TAG master)

  FetchContent_MakeAvailable(picotls)
  if(IS_DIRECTORY "${picotls_SOURCE_DIR}")
    set_property(DIRECTORY ${picotls_SOURCE_DIR} PROPERTY EXCLUDE_FROM_ALL YES)
  endif()
  include_directories(${picotls_SOURCE_DIR}/include)
endif()

# `crypto` comes from LibreSSL if it is built, otherwise from system libssl
set(tls_LIBS picotls-core picotls-openssl crypto)

# LibUring
if(LINUX)
  set(URING_DIR ${CMAKE_BINARY_DIR}/_deps/liburing-ep)
  ExternalProject_Add(
    liburing-ep
    GIT_REPOSITORY https://github.com/axboe/liburing.git
    GIT_TAG liburing-2.3
    GIT_SHALLOW 1
    PREFIX ${CMAKE_BINARY_DIR}/_deps/
    SOURCE_DIR ${URING_DIR}
    CONFIGURE_COMMAND
      echo Configuring LibUring && cd ${URING_DIR} && ./configure --nolibc
      --cc=${CMAKE_C_COMPILER} --cxx=${CMAKE_CXX_COMPILER};
    BUILD_COMMAND cd ${URING_DIR} && make;
    INSTALL_COMMAND ""
    UPDATE_COMMAND "")
  add_library(uring_internal STATIC IMPORTED GLOBAL)
  add_dependencies(uring_internal liburing-ep)
  set_property(TARGET uring_internal PROPERTY IMPORTED_LOCATION
                                              ${URING_DIR}/src/liburing.a)

  include_directories(${URING_DIR}/src/include/)
  set(URING_LIBS uring_internal)
endif()

find_package(Threads REQUIRED)

add_library(ucall_server_posix src/engine_posix.cpp)
target_link_libraries(ucall_server_posix simdjson::simdjson Threads::Threads
                      ${tls_LIBS})
set(BACKENDS ucall_server_posix)

if(LINUX)
  add_library(ucall_server_epoll src/engine_epoll.cpp)
  target_link_libraries(ucall_server_epoll simdjson::simdjson Threads::Threads
                        ${tls_LIBS})

  add_library(ucall_server_uring src/engine_uring.cpp)
  target_link_libraries(ucall_server_uring simdjson::simdjson Threads::Threads
                        ${URING_LIBS} ${tls_LIBS})

  set(BACKENDS ${BACKENDS} ucall_server_epoll ucall_server_uring)
endif()

foreach(backend IN LISTS BACKENDS)
  string(FIND "${backend}" "_" last_underscore REVERSE)
  math(EXPR substring_length "${last_underscore} + 1")
  string(SUBSTRING "${backend}" ${substring_length} -1 backend_name)

  set(jsonrpc_example_name "ucall_example_login_${backend_name}")
  set(rest_example_name "ucall_example_rest_${backend_name}")

  add_executable(${jsonrpc_example_name} examples/login/ucall_server.cpp)
  target_link_libraries(${jsonrpc_example_name} ${backend} cxxopts)
  target_compile_options(${jsonrpc_example_name}
                         PUBLIC -DCXXOPTS_NO_EXCEPTIONS=ON)

  add_executable(${rest_example_name} examples/login/ucall_server_rest.cpp)
  target_link_libraries(${rest_example_name} ${backend} cxxopts)
  target_compile_options(${rest_example_name} PUBLIC -DCXXOPTS_NO_EXCEPTIONS=ON)
endforeach()

if(UCALL_BUILD_EXAMPLES)
  add_executable(ucall_example_redis examples/redis/ucall_server.cpp)
  target_link_libraries(ucall_example_redis ucall_server_posix)

  find_package(Torch)
  add_executable(ucall_example_pytorcs examples/pytorch/ucall_server.cpp)
  target_link_libraries(ucall_example_pytorcs ucall_server_posix
                        "${TORCH_LIBRARIES}")
endif()

# Python bindings
find_package(Python3 REQUIRED Development.Module)
include_directories(${Python_INCLUDE_DIRS})

foreach(backend IN LISTS BACKENDS)
  string(FIND "${backend}" "_" last_underscore REVERSE)
  math(EXPR substring_length "${last_underscore} + 1")
  string(SUBSTRING "${backend}" ${substring_length} -1 backend_name)

  set(py_lib_name "py_ucall_${backend_name}")
  python3_add_library(${py_lib_name} src/python.c)
  target_include_directories(${py_lib_name} PUBLIC src/ include/)
  target_link_libraries(${py_lib_name} PRIVATE ${backend} base64)
  set_target_properties(${py_lib_name} PROPERTIES OUTPUT_NAME ${py_lib_name})
  target_compile_definitions(${py_lib_name}
                             PRIVATE UCALL_PYTHON_MODULE_NAME=${backend_name})
endforeach()

get_directory_property(_targets DIRECTORY ${CMAKE_SOURCE_DIR}
                                          BUILDSYSTEM_TARGETS)
foreach(_target IN LISTS _targets)
  get_target_property(_target_type ${_target} TYPE)
  if(_target_type STREQUAL "EXECUTABLE"
     OR _target_type STREQUAL "SHARED_LIBRARY"
     OR _target_type STREQUAL "STATIC_LIBRARY")
    add_custom_command(
      TARGET ${_target}
      POST_BUILD
      COMMAND
        ${CMAKE_COMMAND} -E echo
        "-+-+ Target $<TARGET_FILE_NAME:${_target}> is at $<TARGET_FILE:${_target}>"
    )
  endif()
endforeach()
