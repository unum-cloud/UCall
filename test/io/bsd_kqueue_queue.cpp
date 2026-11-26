/**
 *  @file test/io/bsd_kqueue_queue.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The kqueue queue under every admitted CPU class.
 */
#undef NDEBUG // ! A test's oracle must stay live in every build

#include "ucall/io/bsd_kqueue_queue.hpp" // `bsd_kqueue_queue_t`

#include "io/queues.hpp" // `run_queue_cases`, `test_queue_duplex`, `test_accept_batch`, `test_direct_files`

namespace unum::ucall::test::io {

void run_bsd_kqueue_queue_cases() {
    run_queue_cases<bsd_kqueue_queue_t>(ucall_io_backend_bsd_kqueue_k,
                                        []<typename queue_type_>(sz::string_t const& label) {
                                            run_test_case(called("test_queue_cell", label).c_str(), [] {
                                                return keeping_descriptors([] {
                                                    split_mix_generator_t generator {case_stream_key()};
                                                    test_queue_duplex<queue_type_>(generator);
                                                    test_gathered_send<queue_type_>(generator);
                                                    test_accept_batch<queue_type_>();
                                                });
                                            });
                                            run_cell_case(label, "test_direct_files", test_direct_files<queue_type_>);
                                        });
}

} // namespace unum::ucall::test::io
