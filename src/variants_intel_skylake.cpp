/**
 *  @file src/variants_intel_skylake.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Intel skylake network variants for every enabled native I/O engine.
 */
#include "variants.hpp"

namespace unum::ucall {

template void make_network_variant<cpu_class_t::intel_skylake_k>(ucall_server_init_t*) noexcept;
template void make_network_variant<cpu_class_t::intel_skylake_k>(ucall_client_init_t*) noexcept;

} // namespace unum::ucall
