# UCall for C

Include `ucall/ucall.h` for the whole interface, or `ucall/types.h`, `ucall/client.h`, and `ucall/server.h` separately.
Every operation that can fail takes its named argument struct and writes a `ucall_outcome_t`.
Getters that cannot fail and handle release functions take their arguments directly.

Byte views carry a pointer and an explicit byte length; zero length means empty.
A client response owns its received bytes until `ucall_received_http_response_free`.
Request views borrow the server's receive storage and remain valid through the endpoint callback.

Deferred client calls publish their outputs before their final outcome status.
Poll through `ucall_outcome_status` or wait through `ucall_outcome_wait` before reading outputs or releasing their storage.

The current build implements the shared status, outcome, and version helpers; client and server declarations await their engine migration.
