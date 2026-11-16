/**
 *  @file test/network.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The network suite's cell loop: every cell of the diagonal sweep runs every area's cases
 *      on its backend, under its CPU class and in its security mode, as one verdict line.
 */
#include "network.hpp"

namespace unum::ucall::test::network {

std::size_t check_network(settings_t const& settings) {
    std::size_t failures_count = 0;
    for (sweep_cell_t const& cell : diagonal_sweep(settings)) {
        sz::string_t const name = formatted("network {}", name_of(cell));
        if (!settings.filter.selects(name)) continue;
        if (!opens(cell)) {
            failures_count += report(name.c_str(), "this host lacks the engine or the class");
            continue;
        }
        failures_count += report(name.c_str(), keeping_descriptors([&] {
                                     std::size_t failures = check_exchanges(cell, settings);
                                     failures += check_serving(cell, settings);
                                     failures += check_loops(cell, settings);
#if UCALL_OS_POSIX_
                                     failures += check_replies(cell, settings);
                                     failures += check_client(cell, settings);
                                     failures += check_resolving(cell, settings);
                                     failures += check_metrics(cell, settings);
#endif
                                     return failures;
                                 }));
    }
    return failures_count;
}

} // namespace unum::ucall::test::network
