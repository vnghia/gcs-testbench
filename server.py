from concurrent import futures

import argparse
import logging

# gRPC
import grpc

import helloworld_pb2
import helloworld_pb2_grpc

# REST
import flask
from werkzeug import serving
from werkzeug.middleware.dispatcher import DispatcherMiddleware

# gRPC
grpc_server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))


class Greeter(helloworld_pb2_grpc.GreeterServicer):
    def SayHello(self, request, context):
        return helloworld_pb2.HelloReply(message="Hello, %s!" % request.name)


def grpc_serve(port):
    helloworld_pb2_grpc.add_GreeterServicer_to_server(Greeter(), grpc_server)
    grpc_server.add_insecure_port("[::]:" + port)
    grpc_server.start()


# REST
root = flask.Flask(__name__)
root.debug = True

@root.route("/")
def index():
    """Default handler for the test bench."""
    return "OK"

application = DispatcherMiddleware(
    root,
)

def rest_serve(port):
    serving.run_simple(
        "localhost",
        int(port),
        application,
        use_reloader=True,
        use_evalex=True,
    )


if __name__ == "__main__":
    logging.basicConfig()
    parser = argparse.ArgumentParser(
        description="A testbench for the Google Cloud C++ Client Library"
    )
    parser.add_argument(
        "--port_grpc", default="8000", help="The listening port for GRPC"
    )
    parser.add_argument(
        "--port_rest", default="9000", help="The listening port for REST"
    )
    arguments = parser.parse_args()
    grpc_serve(arguments.port_grpc)
    rest_serve(arguments.port_rest)
