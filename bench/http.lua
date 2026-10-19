-- bench/http.lua - Binary echo requests and per-worker response verification for wrk2.
-- Ash Vardanian, October 19, 2026.

local threads = {}
failures = 0

function setup(thread)
    threads[#threads + 1] = thread
end

function init(args)
    local bytes = tonumber(args[1] or "1024")
    assert(bytes and bytes >= 0 and bytes == math.floor(bytes), "expected a nonnegative payload size")
    wrk.method = "POST"
    wrk.headers["Content-Type"] = "application/octet-stream"
    wrk.body = bytes == 0 and "" or "\0" .. string.rep("x", bytes - 1)
end

function response(status, headers, body)
    if status ~= 200 or body ~= wrk.body then
        failures = failures + 1
    end
end

function done(summary, latency, requests)
    local total = 0
    for _, thread in ipairs(threads) do
        total = total + thread:get("failures")
    end
    io.write(string.format("Echo verification failures: %d\n", total))
    if total ~= 0 then
        os.exit(1)
    end
end
