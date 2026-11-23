/**
 *  @file cpp/ucall/ucall.hpp
 *  @author Ash Vardanian
 *  @date November 18, 2026
 *  @brief The UCall C++ interface: shared vocabulary, servers and clients behind one include.
 */
#pragma once

#include "ucall/client.hpp" // `client_t`, `response_t`, `completed_t`
#include "ucall/server.hpp" // `server_t`, `request_t`, `reply_stream_t`, `batch_t`
#include "ucall/types.hpp"  // `status_t`, `expected`, `deferred`, `awaiter`
