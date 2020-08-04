from concurrent import futures

import argparse
import json
import logging

# common
from utils import ToProtoDict, InsertBucket, AllBuckets

# gRPC
import grpc

import storage_pb2 as storage
import storage_pb2_grpc
import storage_resources_pb2 as resources
import storage_resources_pb2_grpc

from google.protobuf.json_format import MessageToDict, ParseDict

# REST
import flask
from werkzeug import serving
from werkzeug.middleware.dispatcher import DispatcherMiddleware

# gRPC
grpc_server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))


class StorageServicer(storage_pb2_grpc.StorageServicer):
    def InsertBucket(self, request, context):
        return resources.Bucket()


def grpc_serve(port):
    storage_pb2_grpc.add_StorageServicer_to_server(StorageServicer(), grpc_server)
    grpc_server.add_insecure_port("[::]:" + port)
    grpc_server.start()


# REST
root = flask.Flask(__name__)
root.debug = True


@root.route("/")
def index():
    """Default handler for the test bench."""
    return "OK"


# Define the WSGI application to handle bucket requests.
GCS_HANDLER_PATH = "/storage/v1"
gcs = flask.Flask(__name__)
gcs.debug = True


@gcs.route("/b", methods=["GET"])
def buckets_list():
    """Implement the 'Buckets: list' API: return the Buckets in a project."""
    result = resources.ListBucketsResponse(next_page_token="", items=[])
    for name, b in AllBuckets():
        result.items.append(b["metadata"])
    return MessageToDict(result)


@gcs.route("/b", methods=["POST"])
def buckets_insert():
    """Implement the 'Buckets: insert' API: create a new Bucket."""
    payload = json.loads(flask.request.data)
    bucket = ParseDict(
        ToProtoDict(payload), resources.Bucket(), ignore_unknown_fields=True
    )
    InsertBucket(bucket)
    return MessageToDict(bucket)


application = DispatcherMiddleware(root, {GCS_HANDLER_PATH: gcs})


def rest_serve(port):
    serving.run_simple(
        "localhost", int(port), application, use_reloader=True, use_evalex=True,
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
