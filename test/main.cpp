/**
 *  @file test/main.cpp
 *  @author Ash Vardanian
 *  @date November 12, 2026
 *  @brief The library suite's entry point: the outcome word, every engine under every admitted CPU
 *      class, and the network cells, rolling every area's failures into the exit code.
 */
#include "network.hpp" // `check_network`

using namespace unum::ucall::test;

int main(int argc, char** argv) {
    install_test_signal_handlers();
    test_settings = read_settings(argc, argv, "ucall_test");
    settings_t const& settings = test_settings;
    print_probe(settings);
    std::size_t failures_count = 0;
    failures_count += utilities::check_utilities(settings);
    failures_count += io::check_io(settings);
    failures_count += network::check_network(settings);
    return report("total", failures_count) ? 1 : 0;
}
