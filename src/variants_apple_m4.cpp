/**
 *  @file src/variants_apple_m4.cpp
 *  @author Ash Vardanian
 *  @date November 16, 2026
 *  @brief Apple M4 network variants for every enabled native I/O engine.
 */
#include "variants.hpp"

namespace unum::ucall {

template void make_network_variant<cpu_class_t::apple_m4_k>(ucall_server_init_t*) noexcept;
template void make_network_variant<cpu_class_t::apple_m4_k>(ucall_client_init_t*) noexcept;

} // namespace unum::ucall
