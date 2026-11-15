/**
 *  @file test/io/posix_engine.cpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief The portable engine under every admitted CPU class, and the composition of every engine's
 *      cells this build compiled.
 */
#include "ucall/io/posix_engine.hpp" // `posix_engine_t`

#include "io/engines.hpp" // `check_engine`, `test_engine_duplex`, `test_accept_batch`, `test_direct_files`

namespace unum::ucall::test::io {

std::size_t check_posix_engine(settings_t const& settings) {
#if UCALL_WITH_POSIX
    return check_engine<posix_engine_t>(ucall_io_backend_posix_k, settings,
                                        []<typename engine_type_>(random_generator_t& generator) {
                                            std::size_t failures = test_engine_duplex<engine_type_>(generator);
                                            failures += test_accept_batch<engine_type_>();
                                            failures += test_direct_files<engine_type_>();
                                            return failures;
                                        });
#else
    return settings.filter.selects("io posix") ? report("io posix", "built without UCALL_WITH_POSIX") : 0;
#endif
}

std::size_t check_io(settings_t const& settings) {
    std::size_t failures_count = check_posix_engine(settings);
#if UCALL_WITH_LINUX_EPOLLAIO
    failures_count += check_linux_epollaio_engine(settings);
#endif
#if UCALL_WITH_LINUX_URING
    failures_count += check_linux_uring612_engine(settings);
    failures_count += check_linux_uring618_engine(settings);
#endif
#if UCALL_WITH_BSD_KQUEUE
    failures_count += check_bsd_kqueue_engine(settings);
#endif
    return failures_count;
}

} // namespace unum::ucall::test::io
