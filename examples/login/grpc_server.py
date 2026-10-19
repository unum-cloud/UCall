"""Server for the gRPC session-validation example."""

from concurrent import futures

import grpc
import validate_session_pb2 as pb2
import validate_session_pb2_grpc as pb2_grpc


class ValidateServiceService(pb2_grpc.LoginServiceServicer):
    def __init__(self, *args, **kwargs):
        pass

    def Validate(self, request, context):
        return pb2.ValidateResponse(result=((request.user_id ^ request.session_id) % 23 == 0))


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    pb2_grpc.add_LoginServiceServicer_to_server(ValidateServiceService(), server)
    server.add_insecure_port("[::]:50051")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
