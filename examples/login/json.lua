-- examples/login/json.lua: Pipelined session-validation requests for wrk.
-- Ash Vardanian, April 14, 2024.

-- example script demonstrating HTTP pipelining

init = function(args)
   local r = {}
   wrk.headers["Content-Type"] = "application/json"
   --wrk.headers["Connection"] = "Keep-Alive"
   table.insert(r, wrk.format('POST','/', nil, '{"jsonrpc":"2.0","method":"validate_session","params":{"user_id":55,"session_id":21},"id":0}'))
   req = table.concat(r)
end

request = function()
   return req
end
