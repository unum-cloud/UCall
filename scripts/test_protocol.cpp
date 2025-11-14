/**
 *  @file test_protocol.cpp
 *  @brief Unit tests for protocol state machine and Noise encryption.
 *
 *  This test suite validates protocol-level logic in isolation without real I/O:
 *  - Connection lifecycle and state transitions
 *  - Noise Protocol handshake (XX/IK/KK patterns)
 *  - Transport layer encryption/decryption
 *  - Error handling and edge cases
 *
 *  @note Routing tests are in test_routes.cpp
 *  @note Container tests are in test_shared.cpp
 *
 *  Compilation:
 *  @code{.sh}
 *  g++ -std=c++20 -O2 -I./include -I./src \
 *      -I/opt/homebrew/opt/googletest/include \
 *      -L/opt/homebrew/opt/googletest/lib \
 *      -I/opt/homebrew/opt/noise-c/include \
 *      -L/opt/homebrew/opt/noise-c/lib \
 *      -lgtest -lgtest_main -lnoise -pthread \
 *      scripts/test_protocol.cpp -o test_protocol
 *  ./test_protocol
 *  @endcode
 *
 *  @author Ash Vardanian
 *  @date January 13, 2025
 */

#include <gtest/gtest.h>

#include <cstring>
#include <string_view>

#include "protocol_shared.hpp"

using namespace unum::ucall;

#pragma region Connection State Machine Tests

class ConnectionStateTest : public ::testing::Test {
  protected:
    connection_t connection;
    byte_t input_buffer[4096];
    byte_t output_buffer[4096];

    void SetUp() override {
        connection = {};
        connection.pipes.mount(input_buffer, output_buffer);
        connection.stage = stage_t::unknown_k;
    }

    void TearDown() override { connection.reset(); }
};

TEST_F(ConnectionStateTest, InitialState) {
    EXPECT_EQ(connection.stage, stage_t::unknown_k);
    EXPECT_EQ(connection.descriptor, bad_descriptor_k);
    EXPECT_EQ(connection.exchanges, 0u);
    EXPECT_EQ(connection.empty_transmits, 0u);
}

TEST_F(ConnectionStateTest, ResetClearsState) {
    connection.stage = stage_t::expecting_reception_k;
    connection.exchanges = 10;
    connection.empty_transmits = 5;
    connection.pipes.absorb_input(100);

    connection.reset();

    EXPECT_EQ(connection.stage, stage_t::unknown_k);
    EXPECT_EQ(connection.exchanges, 0u);
    EXPECT_EQ(connection.empty_transmits, 0u);
    EXPECT_EQ(connection.pipes.input_span().size(), 0u);
}

TEST_F(ConnectionStateTest, ActivityTracking) {
    auto before = connection.last_active_ns;
    connection.record_activity();
    auto after = connection.last_active_ns;

    EXPECT_GT(after, before);
}

#pragma endregion Connection State Machine Tests

#pragma region Noise Protocol Tests

class NoiseProtocolTest : public ::testing::Test {
  protected:
    connection_t initiator;
    connection_t responder;
    byte_t initiator_input[4096];
    byte_t initiator_output[4096];
    byte_t responder_input[4096];
    byte_t responder_output[4096];

    void SetUp() override {
        initiator = {};
        responder = {};
        initiator.pipes.mount(initiator_input, initiator_output);
        responder.pipes.mount(responder_input, responder_output);
    }

    void TearDown() override {
        initiator.reset();
        responder.reset();
    }
};

TEST_F(NoiseProtocolTest, InitializeHandshakeXX) {
    // XX pattern: mutual authentication, keys transmitted
    char const *pattern = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

    bool init_ok = initiator.noise_init_handshake(pattern, true);
    EXPECT_TRUE(init_ok) << "Initiator handshake initialization failed";
    EXPECT_NE(initiator.noise_handshake, nullptr);
    EXPECT_FALSE(initiator.noise_handshake_complete);

    bool resp_ok = responder.noise_init_handshake(pattern, false);
    EXPECT_TRUE(resp_ok) << "Responder handshake initialization failed";
    EXPECT_NE(responder.noise_handshake, nullptr);
    EXPECT_FALSE(responder.noise_handshake_complete);
}

TEST_F(NoiseProtocolTest, CleanupNoiseState) {
    char const *pattern = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
    initiator.noise_init_handshake(pattern, true);

    ASSERT_NE(initiator.noise_handshake, nullptr);

    initiator.reset();

    EXPECT_EQ(initiator.noise_handshake, nullptr);
    EXPECT_EQ(initiator.noise_send_cipher, nullptr);
    EXPECT_EQ(initiator.noise_recv_cipher, nullptr);
    EXPECT_FALSE(initiator.noise_handshake_complete);
}

#pragma endregion Noise Protocol Tests

#pragma region Error Handling Tests

TEST(ErrorHandlingTest, NoiseInitFailsWithInvalidPattern) {
    connection_t conn;
    byte_t input[4096];
    byte_t output[4096];
    conn.pipes.mount(input, output);

    // Invalid pattern name
    bool result = conn.noise_init_handshake("InvalidPatternName", true);
    EXPECT_FALSE(result);
    EXPECT_EQ(conn.noise_handshake, nullptr);

    conn.reset();
}

TEST(ErrorHandlingTest, ConnectionResetClearsNoiseState) {
    connection_t conn;
    byte_t input[4096];
    byte_t output[4096];
    conn.pipes.mount(input, output);

    // Initialize handshake
    ASSERT_TRUE(conn.noise_init_handshake("Noise_XX_25519_ChaChaPoly_BLAKE2s", true));
    ASSERT_NE(conn.noise_handshake, nullptr);

    // Reset should clear everything
    conn.reset();
    EXPECT_EQ(conn.noise_handshake, nullptr);
    EXPECT_EQ(conn.noise_send_cipher, nullptr);
    EXPECT_EQ(conn.noise_recv_cipher, nullptr);
    EXPECT_FALSE(conn.noise_handshake_complete);
}

TEST(ErrorHandlingTest, EncryptFailsBeforeHandshakeComplete) {
    connection_t conn;
    byte_t input[4096];
    byte_t output[4096];
    conn.pipes.mount(input, output);

    // Initialize handshake but don't complete it
    ASSERT_TRUE(conn.noise_init_handshake("Noise_XX_25519_ChaChaPoly_BLAKE2s", true));

    // Try to encrypt before handshake complete - should fail
    conn.pipes.append_outputs("test data");
    bool result = conn.noise_encrypt();
    EXPECT_FALSE(result);

    conn.reset();
}

TEST(ErrorHandlingTest, DecryptFailsBeforeHandshakeComplete) {
    connection_t conn;
    byte_t input[4096];
    byte_t output[4096];
    conn.pipes.mount(input, output);

    // Initialize handshake but don't complete it
    ASSERT_TRUE(conn.noise_init_handshake("Noise_XX_25519_ChaChaPoly_BLAKE2s", false));

    // Try to decrypt before handshake complete - should fail
    bool result = conn.noise_decrypt(100);
    EXPECT_FALSE(result);

    conn.reset();
}

#pragma endregion Error Handling Tests

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
