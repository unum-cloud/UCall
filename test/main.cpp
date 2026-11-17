/**
 *  @file test/main.cpp
 *  @author Ash Vardanian
 *  @date November 12, 2026
 *  @brief The library suite's entry point: the outcome word, every engine under every admitted CPU
 *      class, and the network cells.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build

#include "network.hpp" // `run_network_cases`

using namespace unum::ucall::test;

int main(int argc, char** argv) {
    start_test_run(argc, argv);
    utilities::run_utilities_cases();
    io::run_io_cases();
    network::run_network_cases();
    return finish_test_run();
}
