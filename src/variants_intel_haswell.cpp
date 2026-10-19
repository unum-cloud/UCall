/**
 *  @file src/variants_intel_haswell.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Intel haswell network variants for every enabled native I/O engine.
 */
#include "variants.hpp"

namespace unum::ucall {

template void make_network_variant<cpu_class_t::intel_haswell_k>(ucall_server_init_t*) noexcept;
template void make_network_variant<cpu_class_t::intel_haswell_k>(ucall_client_init_t*) noexcept;

} // namespace unum::ucall
