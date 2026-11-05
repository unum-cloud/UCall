# AArch64 Linux, cross-compiled with whatever Clang and LLD the host carries, and run under QEMU.
#
# ~~~
#   sudo apt install clang lld crossbuild-essential-arm64 qemu-user
#   cmake -B build_aarch64_llvm -D CMAKE_TOOLCHAIN_FILE=cmake/toolchain-aarch64-llvm.cmake -D UCALL_BUILD_TEST=ON
#   cmake --build build_aarch64_llvm
#   ctest --test-dir build_aarch64_llvm
# ~~~
#
# QEMU's `-cpu max` carries LSE, RCPC and SVE2, so every Arm CPU class the library compiles runs, `aws_g2` and `aws_g5`
# included.
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

find_program(CMAKE_C_COMPILER clang REQUIRED)
find_program(CMAKE_CXX_COMPILER clang++ REQUIRED)

set(CMAKE_C_COMPILER_TARGET aarch64-linux-gnu)
set(CMAKE_CXX_COMPILER_TARGET aarch64-linux-gnu)
set(CMAKE_EXE_LINKER_FLAGS_INIT "-fuse-ld=lld")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-fuse-ld=lld")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "-fuse-ld=lld")

find_program(ucall_qemu_aarch64_ qemu-aarch64)
if (ucall_qemu_aarch64_)
    set(CMAKE_CROSSCOMPILING_EMULATOR "${ucall_qemu_aarch64_};-L;/usr/aarch64-linux-gnu;-cpu;max")
endif ()

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
