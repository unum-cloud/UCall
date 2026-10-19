"""Binary HTTP echo service for comparison with the native UCall example.

File: examples/fastapi_server.py
Author: Ash Vardanian
Date: May 13, 2024
"""

from fastapi import FastAPI, Request, Response

app = FastAPI()


@app.post("/echo")
async def echo(request: Request) -> Response:
    """Return the request body unchanged, including embedded zero bytes."""
    return Response(await request.body(), media_type="application/octet-stream")


@app.get("/health")
async def health() -> Response:
    """Report that the server is accepting requests."""
    return Response(b"ready\n", media_type="text/plain")
