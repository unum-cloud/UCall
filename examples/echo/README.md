# Binary Echo

The smallest UCall service: every route returns what it received, so the transport is all there is to watch.

```sh
build_release/ucall_example_echo --threads 1 --port 8545
curl http://127.0.0.1:8545/health
curl -X POST http://127.0.0.1:8545/echo --data-binary 'hello'
curl -X POST http://127.0.0.1:8545/echo/batch --data-binary 'hello'
```

`POST /echo` answers on the polling thread that parsed the request, with the body unchanged, embedded zero bytes included.
`POST /echo/batch` routes the same work through a batch endpoint, polled by a pool thread of its own.

`POST /echo/reordered` exercises retained replies.
It holds a tagged request until its partner arrives, then answers the second before the first without blocking the polling caller.
The benchmark driver's `--reorder` flag sends such pairs, so socket arrival and completion order stay independently observable.
