/**
 *  @file test/io/bsd_kqueue_engine.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The kqueue engine under every admitted CPU class.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build

#include "ucall/io/bsd_kqueue_engine.hpp" // `bsd_kqueue_engine_t`

#include "io/engines.hpp" // `run_engine_cases`, `test_engine_duplex`, `test_accept_batch`, `test_direct_files`

namespace unum::ucall::test::io {

void run_bsd_kqueue_engine_cases() {
    run_engine_cases<bsd_kqueue_engine_t>(
        ucall_io_backend_bsd_kqueue_k, []<typename engine_type_>(sz::string_t const& label) {
            run_test_case(called("test_engine_cell", label).c_str(), [] {
                return keeping_descriptors([] {
                    split_mix_generator_t generator {case_stream_key()};
                    test_engine_duplex<engine_type_>(generator);
                    test_accept_batch<engine_type_>();
                });
            });
            run_cell_case(label, "test_direct_files", test_direct_files<engine_type_>);
        });
}

} // namespace unum::ucall::test::io
