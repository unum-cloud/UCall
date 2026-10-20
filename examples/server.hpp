/**
 *  @file examples/server.hpp
 *  @author Ash Vardanian
 *  @date October 19, 2026
 *  @brief Shared CLI, caller-owned polling, and graceful shutdown for the native service examples.
 */
#pragma once

#include <cstdio>
#include <cstdint>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#else
#include <pthread.h>
#include <signal.h>
#endif // defined(_WIN32)

#include <algorithm>
#include <charconv>
#include <limits>
#include <string_view>
#include <vector>

#include <forkunion.h>

#include "ucall/ucall.h"

namespace examples {

#if defined(_WIN32)
inline HANDLE stop_event {};
inline BOOL WINAPI console_stop(DWORD reason) {
    if (reason != CTRL_C_EVENT && reason != CTRL_BREAK_EVENT && reason != CTRL_CLOSE_EVENT) return FALSE;
    SetEvent(stop_event);
    return TRUE;
}
#endif

struct server_t {
    fu_pool_t pool {};
    fu_generation_t generation {};
    bool running {};
    std::vector<ucall_outcome_t> outcomes;
    ucall_server_t server {};
    ucall_network_interface_t interface {};
    char address[sizeof("127.0.0.1:65535")] {};
#if !defined(_WIN32)
    sigset_t stop_signals {}, original_signals {};
    bool signals_blocked {};
    pthread_t waiter {};
#endif

    static bool succeeded(ucall_outcome_t const& outcome) {
        if (outcome.status == ucall_status_success_k) return true;
        std::fprintf(stderr, "%s%s%s\n", ucall_status_name(outcome.status), outcome.message ? ": " : "",
                     outcome.message ? outcome.message : "");
        return false;
    }
    int init(int argc, char** argv) {
        ucall_server_config_t config {};
        config.cpu_class = ucall_cpu_class_serial_k;
        std::size_t threads = 1;
        std::size_t connections = 1024;
        unsigned port = 8545;
        for (int i = 1; i != argc; ++i) {
            std::string_view flag {argv[i]};
            if (flag == "--help") {
                std::printf("Usage: %s [--backend name] [--cpu-class name] [--threads N] [--port N]\n"
                            "       [--connections N]\n"
                            "Backend defaults to automatic, CPU class to serial, and threads to 1.\n"
                            "The port defaults to 8545; admission defaults to 1024 connections.\n",
                            argv[0]);
                return 1;
            }
            std::string_view value {};
            auto separator = flag.find('=');
            if (separator != flag.npos) {
                value = flag.substr(separator + 1);
                flag = flag.substr(0, separator);
            }
            else if (i + 1 != argc) value = argv[++i];
            auto number = [&](auto& output, bool zero = false) {
                if (value.empty()) return false;
                auto parsed = std::from_chars(value.data(), value.data() + value.size(), output);
                return parsed.ec == std::errc {} && parsed.ptr == value.data() + value.size() && (zero || output);
            };
            bool valid {};
            if (flag == "--port") valid = number(port, true) && port <= std::numeric_limits<std::uint16_t>::max();
            else if (flag == "--threads") valid = number(threads);
            else if (flag == "--connections") valid = number(connections);
            else if (flag == "--backend") {
                for (auto backend :
                     {ucall_io_backend_automatic_k, ucall_io_backend_posix_k, ucall_io_backend_linux_epoll_k,
                      ucall_io_backend_linux_uring612_k, ucall_io_backend_linux_uring700_k,
                      ucall_io_backend_macos_kqueue_k, ucall_io_backend_windows_iocp_k})
                    if (value == ucall_io_backend_name(backend)) {
                        config.backend = backend;
                        valid = true;
                    }
            }
            else if (flag == "--cpu-class") {
                valid = value == "automatic";
                if (valid) config.cpu_class = ucall_cpu_class_unknown_k;
                for (auto cpu :
                     {ucall_cpu_class_serial_k, ucall_cpu_class_intel_haswell_k, ucall_cpu_class_intel_skylake_k,
                      ucall_cpu_class_intel_icelake_k, ucall_cpu_class_intel_alder_k, ucall_cpu_class_intel_sierra_k,
                      ucall_cpu_class_aws_g2_k, ucall_cpu_class_apple_m2_k, ucall_cpu_class_aws_g5_k})
                    if (value == ucall_cpu_class_name(cpu)) {
                        config.cpu_class = cpu;
                        valid = true;
                    }
            }
            if (!valid) {
                std::fprintf(stderr, "Invalid argument: %.*s=%.*s\n", static_cast<int>(flag.size()), flag.data(),
                             static_cast<int>(value.size()), value.data());
                return -1;
            }
        }
#if defined(_WIN32)
        stop_event = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        if (!stop_event || !SetConsoleCtrlHandler(console_stop, TRUE)) return -1;
#else
        sigemptyset(&stop_signals);
        sigaddset(&stop_signals, SIGINT);
        sigaddset(&stop_signals, SIGTERM);
        if (pthread_sigmask(SIG_BLOCK, &stop_signals, &original_signals)) return -1;
        signals_blocked = true;
        waiter = pthread_self();
#endif
        std::snprintf(address, sizeof(address), "127.0.0.1:%u", port);
        interface.address = address;
        interface.max_concurrent_connections = connections;
        interface.event_loops = std::min(threads, connections);
        config.interfaces = &interface;
        config.interfaces_count = 1;
        ucall_outcome_t outcome {};
        ucall_server_config_t resolved {};
        ucall_server_init_t init {&server, &outcome, &config, &resolved};
        ucall_server_init(&init);
        if (!succeeded(outcome)) return -1;
        auto loops = resolved.interfaces[0].event_loops;
        outcomes.resize(loops + 1); // The last thread drains batch endpoints.
        fu_topology_t topology {};
        auto status = fu_topology_new(&topology);
        if (status == fu_success_k) status = fu_pool_new("ucall-example", fu_capabilities_all_k, &pool);
        if (status == fu_success_k) status = fu_pool_spawn(topology, pool, loops + 1, fu_caller_exclusive_k);
        if (topology) fu_topology_delete(topology);
        if (status != fu_success_k) {
            std::fprintf(stderr, "ForkUnion initialization failed: %d\n", static_cast<int>(status));
            return -1;
        }
        std::printf("Listening on %s using %s, %s, %zu application-owned serving loops\n",
                    resolved.interfaces[0].address, ucall_io_backend_name(resolved.backend),
                    ucall_cpu_class_name(resolved.cpu_class), loops);
        return 0;
    }
    static void serve(void* context, std::size_t index, std::size_t) {
        auto& application = *static_cast<server_t*>(context);
        auto& outcome = application.outcomes[index];
        if (index + 1 == application.outcomes.size()) {
            ucall_server_take_batches_t draining {application.server, &outcome};
            ucall_server_take_batches(&draining);
        }
        else {
            ucall_server_take_calls_t serving {application.server, &outcome, index};
            ucall_server_take_calls(&serving);
        }
        if (outcome.status == ucall_status_success_k) return;
        ucall_server_stop(application.server);
#if defined(_WIN32)
        SetEvent(stop_event);
#else
        pthread_kill(application.waiter, SIGTERM);
#endif
    }
    int run() {
        if (fu_pool_unsafe_for_threads(pool, serve, this, &generation) != fu_success_k) return 1;
        running = true;
#if defined(_WIN32)
        auto result = WaitForSingleObject(stop_event, INFINITE) == WAIT_OBJECT_0 ? 0 : 1;
#else
        int signal {};
        auto result = sigwait(&stop_signals, &signal) ? 1 : 0;
#endif
        ucall_server_stop(server);
        fu_pool_unsafe_join(pool, generation);
        running = false;
        for (auto const& outcome : outcomes)
            if (!succeeded(outcome)) result = 1;
        return result;
    }
    ~server_t() {
        ucall_server_stop(server);
        if (running) fu_pool_unsafe_join(pool, generation);
        fu_pool_delete(pool);
        ucall_server_free(server);
#if defined(_WIN32)
        SetConsoleCtrlHandler(console_stop, FALSE);
        if (stop_event) CloseHandle(stop_event);
#else
        if (signals_blocked) pthread_sigmask(SIG_SETMASK, &original_signals, nullptr);
#endif
    }
};

} // namespace examples
