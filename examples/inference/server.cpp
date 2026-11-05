/**
 *  @file examples/inference/server.cpp
 *  @author Ash Vardanian
 *  @date October 25, 2026
 *  @brief Top-10 dot-product inference against a resident i8 matrix, per request and per batch.
 *
 *  A query is exactly `--dimensions` request bytes read as i8. Each response holds the 10 best
 *  rows as little-endian pairs of a u32 row index and an i32 score, best first, 80 bytes in all.
 *  NumKong packs the matrix once in fixed-size slices. A single query scores every slice in turn
 *  on its polling thread with stack scratch, while a batch spreads the slices across a ForkUnion
 *  pool, so it streams each packed slice once for all of its queries.
 */
#include <cstddef> // `std::size_t`
#include <cstdint> // `std::int8_t`, `std::uint32_t`, `std::uint64_t`
#include <cstdio>  // `std::printf`, `std::fprintf`
#include <cstring> // `std::memcpy`

#include <algorithm>   // `std::min`
#include <array>       // `std::array`
#include <chrono>      // `std::chrono::microseconds`
#include <limits>      // `std::numeric_limits`
#include <span>        // `std::span`
#include <string_view> // `std::string_view`
#include <thread>      // `std::this_thread::sleep_for`
#include <utility>     // `std::move`

#include <forkunion/forkunion.h>       // `fu_pool_t`, `fu_pool_for_threads`
#include <forkunion/types.hpp>         // `fu::split_mix`
#include <numkong/dots.hpp>            // `nk::dots_packed`
#include <numkong/matrix.hpp>          // `nk::packed_matrix`, `nk::matrix_view`, `nk::matrix_span`
#include <numkong/vector.hpp>          // `nk::vector_view`
#include <smashtable/basic_vector.hpp> // `st::basic_vector`, `st::default_allocator`

#include "server.hpp"

namespace fu = ashvardanian::forkunion;
namespace nk = ashvardanian::numkong;
namespace st = ashvardanian::smashtable;

using query_t = nk::i8_t;
using score_t = query_t::dot_result_t;
using packed_model_t = nk::packed_matrix<query_t, st::default_allocator<char>>;

static constexpr std::size_t results_per_query_k = 10;

/** Rows per packed slice, so one query's scores against a slice fill one 4 KiB page of stack. */
static constexpr std::size_t slice_rows_k = 4096 / sizeof(score_t);

/** How often the parked pool checks for a batch; idle workers would otherwise spin a core each. */
static constexpr std::size_t pool_nap_microseconds_k = 1000;

struct scored_row_t {
    std::uint32_t row {};
    score_t score {score_t::finite_min()};

    /** Whether this row ranks above @p other: a higher score, or an equal one on an earlier row. */
    bool precedes(scored_row_t other) const noexcept {
        return score > other.score || (score == other.score && row < other.row);
    }
};

/** The best rows of one query so far, best first, whatever order they are offered in. */
struct top_rows_t {
    scored_row_t rows[results_per_query_k] {};

    void offer(scored_row_t candidate) noexcept {
        if (!candidate.precedes(rows[results_per_query_k - 1])) return;
        std::size_t position = results_per_query_k - 1;
        for (; position && candidate.precedes(rows[position - 1]); --position) rows[position] = rows[position - 1];
        rows[position] = candidate;
    }
};

/** At most `slice_rows_k` rows of the matrix, packed by NumKong. */
struct model_slice_t {
    packed_model_t packed;
    std::size_t first_row {};
};

/** Offers one query's @p scores against the slice starting at @p first_row. */
static void offer_scores(top_rows_t& top, std::size_t first_row, std::span<score_t const> scores) noexcept {
    for (std::size_t row = 0; row != scores.size(); ++row)
        top.offer({static_cast<std::uint32_t>(first_row + row), scores[row]});
}

/** One pool thread's scratch, grown before each batch by the polling owner. */
struct pool_thread_scratch_t {

    /** A `queries × slice_rows_k` matrix for the slice being scored. */
    st::vector<score_t> scores;

    /** The best rows of each query across this thread's slices. */
    st::vector<top_rows_t> tops;

    /** The latest packing's or batch's outcome on this thread. */
    nk::status_t status {};
};

/** The matrix the pool packs, each thread every N-th slice of it. */
struct packing_call_t {
    std::span<model_slice_t> slices;
    std::span<pool_thread_scratch_t> threads;
    nk::matrix_view<query_t> model;
};

static void pack_slices(void* context, std::size_t thread, std::size_t) {
    packing_call_t& call = *static_cast<packing_call_t*>(context);
    pool_thread_scratch_t& own = call.threads[thread];
    std::size_t const rows = call.model.extent(0);
    for (std::size_t index = thread; index < call.slices.size(); index += call.threads.size()) {
        model_slice_t& slice = call.slices[index];
        slice.first_row = index * slice_rows_k;
        std::size_t const last_row = std::min(slice.first_row + slice_rows_k, rows);
        auto [packed,
              packed_status] = packed_model_t::make(call.model(nk::range(slice.first_row, last_row), nk::slice));
        own.status = packed_status;
        if (nk::failed(own.status)) return;
        slice.packed = std::move(packed);
    }
}

/** One batch's pass over the pool, on the stack of the polling thread that dispatched it. */
struct batch_call_t {
    std::span<model_slice_t const> slices;
    std::span<pool_thread_scratch_t> threads;
    nk::matrix_view<query_t> queries;
};

static void score_slices(void* context, std::size_t thread, std::size_t) {
    batch_call_t& call = *static_cast<batch_call_t*>(context);
    pool_thread_scratch_t& own = call.threads[thread];
    std::size_t const queries_count = call.queries.extent(0);
    for (std::size_t query = 0; query != queries_count; ++query) own.tops[query] = top_rows_t {};
    own.status = nk::status_t::success_k;
    for (std::size_t index = thread; index < call.slices.size(); index += call.threads.size()) {
        model_slice_t const& slice = call.slices[index];
        std::size_t const rows_count = slice.packed.rows();
        own.status = nk::dots_packed<query_t>(call.queries, slice.packed,
                                              nk::matrix_span<score_t> {own.scores.data(), queries_count, rows_count});
        if (nk::failed(own.status)) return;
        std::span<score_t const> const scores {own.scores};
        for (std::size_t query = 0; query != queries_count; ++query)
            offer_scores(own.tops[query], slice.first_row, scores.subspan(query * rows_count, rows_count));
    }
}

/** The scratch the `/infer/batch` drain reuses, grown to the largest batch it has seen. */
struct batch_scratch_t {

    /** The requests whose bodies were valid queries, in batch order. */
    st::vector<ucall_received_http_request_t> requests;

    /** Their queries, one dense `requests × dimensions` matrix for the packed GEMM. */
    st::vector<query_t> queries;

    /** The best rows of each query. */
    st::vector<top_rows_t> tops;
};

struct service_t {
    ucall_server_t server {};
    std::size_t rows = 100'000, dimensions = 1024, seed = 42, slow_batch_microseconds = 5000;
    fu_pool_t pool {}; // Only the `/infer/batch` drain dispatches it, so no call ever finds it busy.
    st::vector<model_slice_t> slices;
    st::vector<pool_thread_scratch_t> pool_scratch;
    batch_scratch_t scratch; // Only the `/infer/batch` drain touches it.

    ~service_t() { fu_pool_delete(pool); }

    /** Fills the matrix from SplitMix64 and packs its slices across the pool. */
    bool load() {
        std::size_t const slices_count = (rows + slice_rows_k - 1) / slice_rows_k;
        fu_topology_t topology {};
        std::size_t cores {};
        fu_status_t status = fu_topology_new(&topology);
        if (status == fu_success_k) status = fu_logical_cores_count(topology, &cores);
        // The pool floats, so the polling thread that dispatches it runs a share unpinned.
        fu_capabilities_t const floating = static_cast<fu_capabilities_t>(
            fu_capabilities_all_k &
            ~(fu_capability_place_threads_by_affinity_k | fu_capability_place_memory_on_domain_k));
        std::size_t const threads = std::min(cores, slices_count);
        if (status == fu_success_k) status = fu_pool_new("ucall-inference", floating, &pool);
        if (status == fu_success_k) status = fu_pool_spawn(topology, pool, threads, fu_caller_inclusive_k);
        if (topology) fu_topology_delete(topology);
        if (status != fu_success_k) {
            std::fprintf(stderr, "ForkUnion initialization failed: %d\n", static_cast<int>(status));
            return false;
        }
        st::vector<query_t> model;
        if (st::failed(model.resize(rows * dimensions)) || st::failed(slices.resize(slices_count)) ||
            st::failed(pool_scratch.resize(threads))) {
            std::fputs("The matrix does not fit in memory\n", stderr);
            return false;
        }
        std::uint64_t const key = fu::split_mix(seed);
        for (std::size_t offset = 0; offset < model.size(); offset += sizeof(std::uint64_t)) {
            std::uint64_t const word = fu::split_mix(key + offset / sizeof(std::uint64_t));
            for (std::size_t byte = 0; byte != sizeof(word) && offset + byte != model.size(); ++byte)
                model[offset + byte] = static_cast<std::int8_t>(static_cast<std::uint8_t>(word >> (8 * byte)));
        }
        packing_call_t packing {slices, pool_scratch, {model.data(), rows, dimensions}};
        if (fu_pool_for_threads(pool, pack_slices, &packing) != fu_success_k) return false;
        fu_pool_sleep(pool, pool_nap_microseconds_k);
        for (pool_thread_scratch_t const& own : pool_scratch)
            if (nk::failed(own.status)) {
                std::fprintf(stderr, "NumKong packing failed: %s\n", nk::status_name(own.status));
                return false;
            }
        return true;
    }

    /** The body as one query, or an empty view after replying 400 to a body of another size. */
    nk::vector_view<query_t> query_of(ucall_received_http_request_t request) const noexcept {
        ucall_outcome_t outcome {};
        ucall_bytes_view_t body {};
        ucall_server_request_body_t extract {server, &outcome, request, &body};
        ucall_server_request_body(&extract);
        std::string_view const bytes = uc::text_view(body);
        if (outcome.status == ucall_status_success_k && bytes.size() == dimensions)
            return {bytes.data(), bytes.size(), sizeof(query_t)};
        uc::tools::reply_error(server, request, ucall_http_status_bad_request_k,
                               "The body must be exactly one i8 query of --dimensions bytes\n");
        return {};
    }

    /** Scores one query against every slice in turn, on the calling thread with stack scratch. */
    bool score_query(nk::vector_view<query_t> query, top_rows_t& top) const noexcept {
        std::array<score_t, slice_rows_k> scores;
        nk::matrix_view<query_t> const queries {query.data(), 1, query.size()};
        for (model_slice_t const& slice : slices) {
            std::span<score_t> const slice_scores = std::span<score_t> {scores}.first(slice.packed.rows());
            nk::matrix_span<score_t> const output {slice_scores.data(), 1, slice_scores.size()};
            if (nk::failed(nk::dots_packed<query_t>(queries, slice.packed, output))) return false;
            offer_scores(top, slice.first_row, slice_scores);
        }
        return true;
    }

    /** Scores a batch's @p queries across the pool, merging each thread's best into @p tops. */
    bool score_batch(nk::matrix_view<query_t> queries, std::span<top_rows_t> tops) noexcept {
        std::size_t const queries_count = queries.extent(0);
        for (pool_thread_scratch_t& own : pool_scratch)
            if ((own.scores.size() < queries_count * slice_rows_k &&
                 st::failed(own.scores.resize(queries_count * slice_rows_k))) ||
                (own.tops.size() < queries_count && st::failed(own.tops.resize(queries_count))))
                return false;
        batch_call_t call {slices, pool_scratch, queries};
        fu_status_t const dispatched = fu_pool_for_threads(pool, score_slices, &call);
        fu_pool_sleep(pool, pool_nap_microseconds_k);
        if (dispatched != fu_success_k) return false;
        for (pool_thread_scratch_t const& own : pool_scratch)
            if (nk::failed(own.status)) return false;
        for (std::size_t query = 0; query != queries_count; ++query) {
            top_rows_t top;
            for (pool_thread_scratch_t const& own : pool_scratch)
                for (scored_row_t const& scored : own.tops[query].rows) top.offer(scored);
            tops[query] = top;
        }
        return true;
    }

    void refuse(ucall_received_http_request_t request) const noexcept {
        uc::tools::reply_error(server, request, ucall_http_status_internal_error_k,
                               "The model failed to score the query\n");
    }

    void reply(ucall_received_http_request_t request, top_rows_t const& top) const noexcept {
        ucall_byte_t bytes[results_per_query_k * sizeof(scored_row_t)] {};
        ucall_byte_t* output = bytes;
        for (scored_row_t const& scored : top.rows)
            for (std::uint32_t const word : {scored.row, static_cast<std::uint32_t>(scored.score.raw())})
                for (std::size_t byte = 0; byte != sizeof(word); ++byte)
                    *output++ = static_cast<ucall_byte_t>(word >> (8 * byte));
        ucall_outcome_t outcome {};
        ucall_server_reply_content_t content {
            server, &outcome, request, ucall_http_status_ok_k, nullptr, 0, {bytes, sizeof(bytes)}};
        ucall_server_reply_content(&content);
    }
};

static void infer(ucall_received_http_request_t request, void* context) {
    service_t const& service = *static_cast<service_t const*>(context);
    nk::vector_view<query_t> const query = service.query_of(request);
    if (query.empty()) return;
    top_rows_t top;
    if (service.score_query(query, top)) service.reply(request, top);
    else service.refuse(request);
}

static void infer_batch(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
    std::span<ucall_received_http_request_t const> const batch {requests, count};
    service_t& service = *static_cast<service_t*>(context);
    batch_scratch_t& scratch = service.scratch;
    std::size_t const dimensions = service.dimensions;
    scratch.requests.clear();
    st::status_t const grown = st::first_failure(scratch.requests.reserve(batch.size()),
                                                 scratch.queries.resize(batch.size() * dimensions));
    if (st::failed(grown)) {
        for (ucall_received_http_request_t const request : batch)
            uc::tools::reply_error(service.server, request, grown);
        return;
    }
    for (ucall_received_http_request_t const request : batch) {
        nk::vector_view<query_t> const query = service.query_of(request);
        if (query.empty()) continue;
        std::memcpy(scratch.queries.data() + scratch.requests.size() * dimensions, query.data(),
                    dimensions * sizeof(query_t));
        [[maybe_unused]] st::status_t const reserved = scratch.requests.push_back(
            st::assume_reserved, ucall_received_http_request_t {request});
    }
    std::size_t const scored = scratch.requests.size();
    if (!scored) return;
    if (st::status_t const resized = scratch.tops.resize(scored); st::failed(resized)) {
        for (ucall_received_http_request_t const request : scratch.requests)
            uc::tools::reply_error(service.server, request, resized);
        return;
    }
    bool const answered = service.score_batch({scratch.queries.data(), scored, dimensions}, scratch.tops);
    for (std::size_t query = 0; query != scored; ++query)
        if (answered) service.reply(scratch.requests[query], scratch.tops[query]);
        else service.refuse(scratch.requests[query]);
}

static void slow_batch(ucall_received_http_request_t const* requests, std::size_t count, void* context) {
    std::span<ucall_received_http_request_t const> const batch {requests, count};
    service_t& service = *static_cast<service_t*>(context);
    std::this_thread::sleep_for(std::chrono::microseconds(service.slow_batch_microseconds));
    for (ucall_received_http_request_t const request : batch) {
        ucall_outcome_t outcome {};
        ucall_server_reply_content_t reply {service.server, &outcome, request, ucall_http_status_ok_k, nullptr, 0, {}};
        ucall_server_reply_content(&reply);
    }
}

int main(int argc, char** argv) {
    service_t service;
    uc::tools::server_t application {};
    int const flagged = application.init(
        argc, argv,
        {{"--rows", "resident matrix rows", service.rows},
         {"--dimensions", "i8 values per row and query bytes", service.dimensions},
         {"--seed", "SplitMix64 seed of the matrix", service.seed},
         {"--slow-batch-us", "sleep of each /slow/batch callback in microseconds", service.slow_batch_microseconds}});
    if (flagged) return flagged < 0 ? 1 : 0;
    if (!service.rows || !service.dimensions || service.rows - 1 > std::numeric_limits<std::uint32_t>::max() ||
        service.rows > std::numeric_limits<std::size_t>::max() / service.dimensions) {
        std::fputs("--rows must fit a u32 index and --rows times --dimensions a size\n", stderr);
        return 1;
    }
    service.server = application.server;
    if (!service.load()) return 1;
    std::printf("Serving a model of %zu rows of %zu i8 dimensions, seed %zu, in %zu packed slices on %zu threads\n",
                service.rows, service.dimensions, service.seed, service.slices.size(), service.pool_scratch.size());
    if (!application.add_endpoint("/infer", ucall_verb_post_k, infer, &service) ||
        !application.add_batch_endpoint("/infer/batch", ucall_verb_post_k, infer_batch, &service) ||
        !application.add_batch_endpoint("/slow/batch", ucall_verb_post_k, slow_batch, &service))
        return 1;
    return application.run();
}
