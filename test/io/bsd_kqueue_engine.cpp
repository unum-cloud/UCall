/**
 *  @file test/io/bsd_kqueue_engine.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The kqueue engine under every admitted CPU class.
 */
#include "ucall/io/bsd_kqueue_engine.hpp" // `bsd_kqueue_engine_t`

#include "io/engines.hpp" // `check_engine`, `test_engine_duplex`, `test_accept_batch`, `test_direct_files`

namespace unum::ucall::test::io {

std::size_t check_bsd_kqueue_engine(settings_t const& settings) {
    return check_engine<bsd_kqueue_engine_t>(ucall_io_backend_bsd_kqueue_k, settings,
                                             []<typename engine_type_>(random_generator_t& generator) {
                                                 std::size_t failures = test_engine_duplex<engine_type_>(generator);
                                                 failures += test_accept_batch<engine_type_>();
                                                 failures += test_direct_files<engine_type_>();
                                                 return failures;
                                             });
}

} // namespace unum::ucall::test::io
