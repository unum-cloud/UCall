"""FastAPI on Uvicorn serving the echo and sum workloads, one worker process per thread.

File: bench/fastapi_server.py
Author: Ash Vardanian
Date: May 13, 2024
"""

import arguments
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import PlainTextResponse

app = FastAPI()


@app.post("/echo")
async def echo(request: Request) -> Response:
    """Return the request body unchanged, including embedded zero bytes."""
    return Response(await request.body(), media_type="application/octet-stream")


@app.get("/sum")
async def sum(a: int, b: int) -> PlainTextResponse:
    """Add two query parameters, which FastAPI validates as integers."""
    return PlainTextResponse(str(a + b))


@app.get("/health")
async def health() -> PlainTextResponse:
    """Report readiness."""
    return PlainTextResponse("ready\n")


def main() -> None:
    """Serve on uvloop and httptools until SIGINT."""
    port, threads = arguments.parse(__doc__)
    uvicorn.run(
        "fastapi_server:app",
        host="127.0.0.1",
        port=port,
        workers=threads,
        loop="uvloop",
        http="httptools",
        access_log=False,
    )


if __name__ == "__main__":
    main()
