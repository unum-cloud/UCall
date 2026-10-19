# Atomic Account Transfers

This small ledger uses SmashTable's `locked_store<strict_serializable_hash_map<uint64_t, uint64_t>>`.
Accounts 1 and 2 start with 1000 integer units each.

```sh
build_release/ucall_example_ledger --backend posix --threads 1 --port 8545
curl http://127.0.0.1:8545/accounts/1
curl -X POST http://127.0.0.1:8545/transfers/1/2 --data-binary '75'
curl http://127.0.0.1:8545/accounts/2
```

`POST /batch/transfers/{from}/{to}` accepts the same amount body through a batched endpoint.
The callback receives a counted array of requests and runs the same transfer handler for each.
Each transfer commits independently; the batch is not one transaction.

A transfer reads both accounts and stages the debit and credit in one strictly serializable transaction.
Both changes publish together, or neither does.
Insufficient funds, unrepresentable balances, and transaction conflicts return 409.
Malformed numbers return 400, missing accounts return 404, and allocation failures return 503.
Amounts and balances use unsigned 64-bit integer units rather than floating point.

The service is an in-memory transaction example without authentication, persistence, or payment integration.
A timeout after submission leaves the caller uncertain whether a transfer committed; production retry handling would require an idempotency key stored in the same transaction.
