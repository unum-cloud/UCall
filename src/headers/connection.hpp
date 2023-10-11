#pragma once

#include "globals.hpp"

#if defined(UCALL_IS_WINDOWS)
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

#include <chrono>

#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#if defined(UCALL_IS_WINDOWS)
#pragma warning(push)
#pragma warning(disable : 4576)
#endif

#include <picotls.h>
#include <picotls/openssl.h>

#if defined(UCALL_IS_WINDOWS)
#pragma warning(pop)
#endif

#include "containers.hpp"
#include "parse/protocol/protocol.hpp"
#include "shared.hpp"

namespace unum::ucall {

struct connection_t {

    /// @brief Exchange buffers to pipe information in both directions.
    exchange_pipes_t pipes{};

    /// @brief The file descriptor of the stateful connection over TCP.
    descriptor_t descriptor{invalid_descriptor_k};
    /// @brief Current state at which the automata has arrived.
    stage_t stage{};
    protocol_t protocol{};

    struct sockaddr client_address {};
    socklen_t client_address_len{sizeof(struct sockaddr)};

    /// @brief Accumulated duration of sleep cycles.
    std::size_t last_active_ns{};
    std::size_t exchanges{};
    std::size_t empty_transmits{};

    /// @brief TLS related data
    ptls_t* tls_ctx{};
    ptls_buffer_t work_buf{};
    uint8_t ptls_buf[ram_page_size_k];
    ptls_handshake_properties_t hand_props{};

    /// @brief Relative time set for the last wake-up call.
    ssize_t next_wakeup = wakeup_initial_frequency_ns_k;

    void make_tls(ptls_context_t* ssl_ctx) noexcept {
        tls_ctx = ptls_new(ssl_ctx, true);
        ptls_buffer_init(&work_buf, ptls_buf, ram_page_size_k);
    }

    void record_activity() noexcept {
        last_active_ns = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    }

    bool expired() const noexcept {
        return std::chrono::high_resolution_clock::now().time_since_epoch().count() - last_active_ns >
               max_inactive_duration_ns_k;
    }

    bool is_ready() const noexcept { return tls_ctx == nullptr || ptls_handshake_is_complete(tls_ctx); }

    bool must_close() const noexcept {
        auto conn = protocol.get_header("Connection");
        return conn == "Close" || conn == "close";
    }

    bool prepare_step() noexcept {
        if (is_ready())
            return true;

        ssize_t ret = 0;
        work_buf.off = 0;
        const char* in_buf = pipes.input_span().data();
        size_t in_len = pipes.input_span().size();

        ret = ptls_handshake(tls_ctx, &work_buf, in_buf, &in_len, &hand_props);
        pipes.append_outputs({(char*)work_buf.base, work_buf.off});
        if (ret != PTLS_ERROR_IN_PROGRESS && ret != PTLS_ALERT_CLOSE_NOTIFY)
            return false;

        if (ptls_handshake_is_complete(tls_ctx)) {
            pipes.drop_embedded_n(in_len);
            return true;
        }
        return false;
    }

    void encrypt() noexcept {
        if (tls_ctx == nullptr || !ptls_handshake_is_complete(tls_ctx))
            return;

        work_buf.off = 0;
        int res = ptls_send(tls_ctx, &work_buf, pipes.output_span().data(), pipes.output_span().size());
        if (res != -1) {
            pipes.release_outputs();
            pipes.append_outputs({(char*)work_buf.base, work_buf.off});
        }
    }

    void decrypt(size_t received_amount) noexcept {
        if (tls_ctx == nullptr || !ptls_handshake_is_complete(tls_ctx))
            return;

        work_buf.off = 0;
        int res = 0;
        size_t in_len = pipes.input_span().size();
        void const* input = pipes.input_span().data();
        if (received_amount != in_len) {
            input = static_cast<char const*>(input) + (in_len - received_amount);
            in_len = received_amount;
        }
        while (in_len != 0 && res != -1) {
            size_t consumed = in_len;
            res = ptls_receive(tls_ctx, &work_buf, input, &consumed);
            in_len -= consumed;
            input = static_cast<char const*>(input) + consumed;
        }
        if (res != -1 && work_buf.off > 0) {
            printf("WB: %zu\n", work_buf.off);
            pipes.drop_last_input(received_amount);
            std::memcpy(pipes.next_input_address(), work_buf.base, work_buf.off);
            pipes.absorb_input(work_buf.off);
        }
    }

    void reset() noexcept {
        stage = stage_t::unknown_k;
        client_address = {};

        pipes.release_inputs();
        pipes.release_outputs();

        if (tls_ctx) {
            ptls_free(tls_ctx);
            tls_ctx = nullptr;
            ptls_buffer_dispose(&work_buf);
        }

        exchanges = 0;
        empty_transmits = 0;
        next_wakeup = wakeup_initial_frequency_ns_k;
    };
};

struct ssl_context_t {

    constexpr ssl_context_t() noexcept : certs(), sign_certificate(), verify_certificate(), ssl() {
        ssl.random_bytes = ptls_openssl_random_bytes;
        ssl.get_time = &ptls_get_time;
        ssl.key_exchanges = ptls_openssl_key_exchanges;
        ssl.cipher_suites = ptls_openssl_cipher_suites;
        ssl.certificates = {certs, 0};
        ssl.sign_certificate = &sign_certificate.super;
    };

    ssl_context_t(ssl_context_t const& other) = delete;
    ssl_context_t(ssl_context_t&& other) = delete;
    ssl_context_t& operator=(ssl_context_t const&) = delete;
    ssl_context_t& operator=(ssl_context_t&&) = delete;

    int init(const char* pk_path, const char** crts_path, size_t crts_cnt) noexcept {
        FILE* fp;
        X509* cert;

        // Read Certificates
        for (size_t i = 0; i < crts_cnt; ++i) {
            if ((fp = fopen(crts_path[i], "r")) == nullptr)
                return -1;

            while ((cert = PEM_read_X509(fp, nullptr, nullptr, nullptr)) != nullptr) {
                ptls_iovec_t* dst = ssl.certificates.list + ssl.certificates.count++;
                dst->len = i2d_X509(cert, &dst->base);
            }

            fclose(fp);
        }
        if (ptls_openssl_init_verify_certificate(&verify_certificate, nullptr) != 0)
            return -1;

        if (ssl.certificates.count == 0)
            return -1;
        ssl.verify_certificate = &verify_certificate.super;

        if ((fp = fopen(pk_path, "r")) == nullptr)
            return -1;

        EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
        fclose(fp);

        if (pkey == nullptr)
            return -1;

        int rv = ptls_openssl_init_sign_certificate(&sign_certificate, pkey);
        EVP_PKEY_free(pkey);
        if (rv)
            return -1;

        return 0;
    }

    ptls_iovec_t certs[16];
    ptls_openssl_sign_certificate_t sign_certificate;
    ptls_openssl_verify_certificate_t verify_certificate;
    ptls_context_t ssl;
};

struct completed_event_t {
    connection_t* connection_ptr{};
    int result{};
};

} // namespace unum::ucall