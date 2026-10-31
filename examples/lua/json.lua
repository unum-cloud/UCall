-- example script demonstrating HTTP pipelining

init = function(args)

   depth = tonumber(args[1]) or 1
   wrk.headers["Content-Type"] = "application/json"

   local r = {}
   for i=1,depth do
      r[i] = wrk.format('POST','/json', nil, '{"jsonrpc":"2.0","method":"validate_session","params":{"user_id":55,"session_id":21},"id":0}')
   end
   req = table.concat(r)

end

request = function()
   return req
end
