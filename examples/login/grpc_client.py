"""Client for the gRPC session-validation example."""

#!/usr/bin/env python3
import random

import grpc
import validate_session_pb2 as pb2
import validate_session_pb2_grpc as pb2_grpc


class ValidateClient:
    """Client for gRPC functionality."""

    def __init__(self, uri: str = "127.0.0.1", port: int = 50051) -> None:
        # instantiate a channel
        self.channel = grpc.insecure_channel(f"{uri}:{port}")
        # bind the client and the server
        self.stub = pb2_grpc.LoginServiceStub(self.channel)

    def get_url(self, user_id, session_id):
        """Client function to call the rpc for Validate."""
        result = pb2.ValidateRequest(user_id=user_id, session_id=session_id)
        return self.stub.Validate(result)

    def __call__(self, *, a: int | None = None, b: int | None = None) -> int:
        a = random.randint(1, 1000) if a is None else a
        b = random.randint(1, 1000) if b is None else b
        result = self.get_url(user_id=a, session_id=b)
        c = result.result
        assert ((a ^ b) % 23 == 0) == c, "Wrong Result"
        return c
