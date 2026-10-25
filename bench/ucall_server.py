"""UCall's Python bindings serving the echo and sum workloads, one polling thread per event loop.

Handlers run on the polling thread that received the request, with no event loop or coroutine in between.
The bindings start no threads, so this script starts one per event loop.

File: bench/ucall_server.py
Author: Ash Vardanian
Date: October 25, 2026
"""

import signal
import threading

import arguments

import ucall


def main() -> None:
    """Serve `/echo`, `/sum` and `/health` until SIGINT or SIGTERM."""
    port, threads = arguments.parse(__doc__)
    server = ucall.Server(ucall.Interface(f"127.0.0.1:{port}", event_loops=threads))

    @server.post("/echo")
    def echo(request: ucall.Request) -> None:
        """Return the request body unchanged, including embedded zero bytes."""
        request.reply(request.body, headers=("content-type: application/octet-stream",))

    @server.get("/sum")
    def sum(a: int, b: int) -> str:
        """Add two query parameters, which the bindings parse and bind in C."""
        return str(a + b)

    @server.get("/health")
    def health() -> str:
        """Report readiness."""
        return "ready\n"

    stopping = threading.Event()
    for signal_number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signal_number, lambda *_: stopping.set())
    pollers = [threading.Thread(target=server.take_calls, args=(loop,)) for loop in range(server.event_loops)]
    for poller in pollers:
        poller.start()
    print(f"Listening on {server.addresses[0]} using {server.backend.name}, {server.event_loops} event loops")
    stopping.wait()
    server.stop()
    for poller in pollers:
        poller.join()


if __name__ == "__main__":
    main()
