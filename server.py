from concurrent import futures

import argparse
import logging

import grpc

import helloworld_pb2
import helloworld_pb2_grpc

# gRPC
grpc_server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))


class Greeter(helloworld_pb2_grpc.GreeterServicer):
    def SayHello(self, request, context):
        return helloworld_pb2.HelloReply(message="Hello, %s!" % request.name)


def serve(port):
    helloworld_pb2_grpc.add_GreeterServicer_to_server(Greeter(), grpc_server)
    grpc_server.add_insecure_port("[::]:" + port)
    grpc_server.start()
    grpc_server.wait_for_termination()


if __name__ == "__main__":
    logging.basicConfig()
    parser = argparse.ArgumentParser(
        description="A testbench for the Google Cloud C++ Client Library"
    )
    parser.add_argument(
        "--port_grpc", default="8000", help="The listening port for GRPC"
    )
    arguments = parser.parse_args()
    serve(arguments.port_grpc)
