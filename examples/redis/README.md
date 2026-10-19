# A Small Key-Value Service

This example combines the UCall C ABI with SmashTable's `locked_store<strict_serializable_hash_map<...>>`.
It provides a small HTTP alternative to a remote key-value service, with binary values and conditional writes.
It uses HTTP rather than the Redis RESP protocol.

| Request                                       | Result                                           |
| :-------------------------------------------- | :----------------------------------------------- |
| `PUT /kv/{key}` with a binary body            | Replace the value; return its revision in `ETag` |
| `GET /kv/{key}`                               | Return the stored bytes and revision, or 404     |
| `DELETE /kv/{key}`                            | Remove the value, or return 404                  |
| `PUT` with `If-None-Match: *`                 | Create only if absent; otherwise return 412      |
| `PUT` or `DELETE` with `If-Match: "revision"` | Change only that revision; otherwise return 412  |

The same methods at `/batch/kv/{key}` use a batched endpoint whose counted-array callback reuses the individual handler.
Each request has its own transaction and response; batching does not combine writes into one transaction.

Keys are the raw, case-sensitive path suffix after `/kv/` or `/batch/kv/`, including any embedded slashes.
Percent escapes remain encoded.
Empty values are valid.
The example accepts a single strong ETag or `*` in `If-Match`; it does not accept ETag lists or weak validators.
`GET` with `If-None-Match: *` returns 304 with the current ETag when the key exists.

```sh
build_release/ucall_example_redis --backend posix --threads 1 --port 8545
curl -i -X PUT http://127.0.0.1:8545/kv/message --data-binary 'hello'
curl -i http://127.0.0.1:8545/kv/message
curl -i -X PUT http://127.0.0.1:8545/kv/message -H 'If-None-Match: *' --data-binary 'overwrite'
```

Every request runs in one strictly serializable transaction.
The read of a revision and its conditional update commit together, preventing a stale writer from silently overwriting a concurrent change.
Revision tokens come from transaction generations, so deleting and recreating a key does not restore an old revision during the process lifetime.
A successful response follows publication of the commit.
Transaction conflicts return 409; allocation failures return 503.

This is one in-memory process, without persistence, replication, eviction, or failover.
Restarting loses both data and revision history.
Its consistency claim covers local committed transactions, not distributed availability or durability.
The example binds loopback by default and supplies no authentication.
