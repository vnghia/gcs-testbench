from concurrent import futures

import argparse
import json
import logging
import os

# common
import utils

# gRPC
import grpc

import storage_pb2 as storage
import storage_pb2_grpc
import storage_resources_pb2 as resources
import storage_resources_pb2_grpc

from google.protobuf.json_format import ParseDict

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


def insert_test_bucket():
    if len(utils.AllBuckets()) == 0:
        bucket_name = os.environ.get(
            "GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", "test-bucket"
        )
        # Enable versioning in the Bucket, the integration tests expect
        # this to be the case, this brings the metageneration number to 4.
        bucket = resources.Bucket(
            name=bucket_name,
            id=bucket_name,
            versioning={"enabled": True},
            metageneration=4,
        )
        utils.InsertBucket(bucket)


@gcs.route("/b", methods=["GET"])
def buckets_list():
    """Implement the 'Buckets: list' API: return the Buckets in a project."""
    insert_test_bucket()
    result = {"next_page_token": "", "items": []}
    for name, b in utils.AllBuckets():
        result["items"].append(utils.ToRestDict(b["metadata"], "storage#bucket"))
    return result


@gcs.route("/b", methods=["POST"])
def buckets_insert():
    """Implement the 'Buckets: insert' API: create a new Bucket."""
    insert_test_bucket()
    print(flask.request.args)
    payload = utils.ToProtoDict(flask.request.data)
    bucket = ParseDict(payload, resources.Bucket(), ignore_unknown_fields=True)
    utils.InsertBucket(bucket)
    return utils.ToRestDict(bucket, "storage#bucket")


@gcs.route("/b/<bucket_name>")
def buckets_get(bucket_name):
    insert_test_bucket()
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    fields = flask.request.args.getlist("fields")
    result = resources.Bucket()
    result.CopyFrom(bucket["metadata"])
    kind = "storage#bucket"
    if len(fields) != 0:
        result = utils.FilterMessage(result, fields)
        if "kind" not in fields:
            kind = None
    return utils.ToRestDict(result, kind)


@gcs.route("/b/<bucket_name>", methods=["PUT"])
def buckets_update(bucket_name):
    insert_test_bucket()
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    payload = utils.ToProtoDict(flask.request.data)
    bucket = bucket["metadata"]
    bucket.Clear()
    bucket = ParseDict(payload, bucket, ignore_unknown_fields=True)
    return utils.ToRestDict(bucket, "storage#bucket")


@gcs.route("/b/<bucket_name>", methods=["PATCH"])
def buckets_patch(bucket_name):
    payload = utils.ToProtoDict(flask.request.data)
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    bucket = bucket["metadata"]
    bucket = ParseDict(payload, bucket, ignore_unknown_fields=True)
    return utils.ToRestDict(bucket, "storage#bucket")


@gcs.route("/b/<bucket_name>", methods=["DELETE"])
def buckets_delete(bucket_name):
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    utils.DeleteBucket(bucket_name)
    return ""


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
