/**
 *  @file src/variants_ibm_power10.cpp
 *  @author Ash Vardanian
 *  @date November 14, 2026
 *  @brief IBM POWER10 network variants for every enabled native I/O engine.
 */
#include "variants.hpp"

namespace unum::ucall {

template void make_network_variant<cpu_class_t::ibm_power10_k>(ucall_server_init_t*) noexcept;
template void make_network_variant<cpu_class_t::ibm_power10_k>(ucall_client_init_t*) noexcept;

} // namespace unum::ucall
