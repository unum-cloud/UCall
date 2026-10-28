/**
 *  @file src/variants_monoversioned.cpp
 *  @author Ash Vardanian
 *  @date October 28, 2026
 *  @brief Monoversioned network variants for every enabled native I/O engine.
 */
#include "variants.hpp"

namespace unum::ucall {

template void make_network_variant<cpu_class_t::monoversioned_k>(ucall_server_init_t*) noexcept;
template void make_network_variant<cpu_class_t::monoversioned_k>(ucall_client_init_t*) noexcept;

} // namespace unum::ucall
