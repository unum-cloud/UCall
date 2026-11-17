/**
 *  @file test/network.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The network suite's cell loop: every cell of the diagonal sweep runs every area's cases
 *      on its backend, under its CPU class and in its security mode, as one verdict line, and each
 *      case that may skip as a verdict line of its own.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build
#include "network.hpp"

namespace unum::ucall::test::network {

/** Why a cell skips when its backend or class does not initialize here. */
static constexpr char const* cell_refused_k = "the backend or the CPU class is refused on this machine";

void run_network_cases() {
    for (sweep_cell_t const& cell : diagonal_sweep()) {
        sz::string_t const label = cell_arguments(cell);
        bool const opened = opens(cell);
        run_test_case(called("test_network_cell", label).c_str(), [&] {
            if (!opened) return case_result_t::skipped(cell_refused_k);
            return keeping_descriptors([&] {
                split_mix_generator_t generator {case_stream_key()};
                test_exchanges_cell(cell, generator);
                test_serving_cell(cell, generator);
                test_loops_cell(cell, generator);
#if UCALL_OS_POSIX_
                test_replies_cell(cell, generator);
                test_client_cell(cell, generator);
                test_resolving_cell(cell);
                test_metrics_cell(cell);
#endif
            });
        });
        if (!opened) continue;
        run_exchanges_cases(cell, label);
        run_serving_cases(cell, label);
        run_loops_cases(cell, label);
#if UCALL_OS_POSIX_
        run_replies_cases(cell, label);
        run_resolving_cases(cell, label);
#endif
    }
}

} // namespace unum::ucall::test::network
