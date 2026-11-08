/**
 *  @file test/kernel_abi.cpp
 *  @author Ash Vardanian
 *  @date November 8, 2026
 *  @brief The Linux kernel layouts the library mirrors, checked against the kernel's own headers.
 */
#include <cstddef> // `offsetof`

#include <sys/stat.h> // `struct statx`, `STATX_DIOALIGN`

#if __has_include(<linux/openat2.h>)
#include <linux/openat2.h> // `struct open_how`
#endif

#include "ucall/utilities/sockets.hpp" // `linux_open_how_t`, `linux_statx_t`

namespace ucu = unum::ucall::utilities;

#if __has_include(<linux/openat2.h>)
static_assert(sizeof(ucu::linux_open_how_t) == sizeof(struct open_how),
              "struct open_how is the kernel's; ours must match it");
static_assert(offsetof(ucu::linux_open_how_t, resolve) == offsetof(struct open_how, resolve),
              "struct open_how is the kernel's; ours must match it");
#endif

#if defined(STATX_DIOALIGN)
static_assert(sizeof(ucu::linux_statx_t) == sizeof(struct statx), "struct statx is the kernel's; ours must match it");
static_assert(offsetof(ucu::linux_statx_t, dio_offset_align) == offsetof(struct statx, stx_dio_offset_align),
              "struct statx is the kernel's; ours must match it");
#endif

int main() { return 0; }
