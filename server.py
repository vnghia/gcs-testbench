from concurrent import futures

import argparse
import json
import httpbin
import logging
import os

# common
import utils
import gcs_bucket

# gRPC
import grpc

import storage_pb2 as storage
import storage_pb2_grpc
import storage_resources_pb2 as resources
import storage_resources_pb2_grpc

from google.iam.v1 import policy_pb2
from google.protobuf.json_format import ParseDict, MessageToDict

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
    if len(utils.all_buckets()) == 0:
        bucket_name = os.environ.get(
            "GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", "test-bucket"
        )
        # Enable versioning in the Bucket, the integration tests expect
        # this to be the case, this brings the metageneration number to 4.
        gcs_bucket.Bucket(
            bucket_name, addition={"versioning": {"enabled": True}, "metageneration": 4}
        )


@gcs.route("/b", methods=["GET"])
def buckets_list():
    insert_test_bucket()
    project = flask.request.args.get("project")
    result = {"next_page_token": "", "items": []}
    for name, b in gcs_bucket.Bucket.list(project):
        result["items"].append(b.to_rest(flask.request))
    return result


@gcs.route("/b", methods=["POST"])
def buckets_insert():
    insert_test_bucket()
    bucket = gcs_bucket.Bucket(request=flask.request)
    return bucket.to_rest(flask.request)


@gcs.route("/b/<bucket_name>")
def buckets_get(bucket_name):
    insert_test_bucket()
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    return bucket.to_rest(flask.request)


@gcs.route("/b/<bucket_name>", methods=["PUT"])
def buckets_update(bucket_name):
    insert_test_bucket()
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    projection = bucket.update(flask.request)
    return bucket.to_rest(flask.request, projection)


@gcs.route("/b/<bucket_name>", methods=["PATCH"])
def buckets_patch(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    projection = bucket.update(flask.request, False)
    return bucket.to_rest(flask.request, projection)


@gcs.route("/b/<bucket_name>", methods=["DELETE"])
def buckets_delete(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    bucket.delete()
    return ""


@gcs.route("/b/<bucket_name>/acl")
def bucket_acl_list(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    result = {"items": []}
    for acl in bucket.metadata.acl:
        result["items"].append(gcs_bucket.Bucket.acl_to_rest(acl))
    return result


@gcs.route("/b/<bucket_name>/acl", methods=["POST"])
def bucket_acl_create(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    payload = json.loads(flask.request.data)
    entity = payload["entity"]
    role = payload["role"]
    acl = bucket.insert_acl(entity, role)
    return gcs_bucket.Bucket.acl_to_rest(acl)


@gcs.route("/b/<bucket_name>/acl/<entity>")
def bucket_acl_get(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    acl = bucket.lookup_acl(entity)
    return gcs_bucket.Bucket.acl_to_rest(acl)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["PUT"])
def bucket_acl_update(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    role = json.loads(flask.request.data)["role"]
    acl = bucket.insert_acl(entity, role, update=True, clear=True)
    return gcs_bucket.Bucket.acl_to_rest(acl)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["PATCH"])
def bucket_acl_patch(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    role = json.loads(flask.request.data)["role"]
    acl = bucket.insert_acl(entity, role, update=True, clear=False)
    return gcs_bucket.Bucket.acl_to_rest(acl)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["DELETE"])
def bucket_acl_delete(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    bucket.delete_acl(entity)
    return ""


@gcs.route("/b/<bucket_name>/defaultObjectAcl")
def bucket_default_object_acl_list(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    result = {"items": []}
    for acl in bucket.metadata.default_object_acl:
        result["items"].append(gcs_bucket.Bucket.acl_to_rest(acl, True))
    return result


@gcs.route("/b/<bucket_name>/defaultObjectAcl", methods=["POST"])
def bucket_default_object_acl_create(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    payload = json.loads(flask.request.data)
    entity = payload["entity"]
    role = payload["role"]
    acl = bucket.insert_default_object_acl(entity, role)
    return gcs_bucket.Bucket.acl_to_rest(acl, True)


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["DELETE"])
def bucket_default_object_acl_delete(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    bucket.delete_default_object_acl(entity)
    return ""


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>")
def bucket_default_object_acl_get(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    acl = bucket.lookup_default_object_acl(entity)
    return gcs_bucket.Bucket.acl_to_rest(acl, True)


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["PUT"])
def bucket_default_object_acl_update(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    role = json.loads(flask.request.data)["role"]
    acl = bucket.insert_default_object_acl(entity, role, update=True, clear=True)
    return gcs_bucket.Bucket.acl_to_rest(acl, True)


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["PATCH"])
def bucket_default_object_acl_patch(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    role = json.loads(flask.request.data)["role"]
    acl = bucket.insert_default_object_acl(entity, role, update=True, clear=False)
    return gcs_bucket.Bucket.acl_to_rest(acl, True)


@gcs.route("/b/<bucket_name>/notificationConfigs")
def bucket_notification_list(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    result = {"items": []}
    for notification in bucket.notification:
        result["items"].append(gcs_bucket.Bucket.noti_to_rest(notification))
    return result


@gcs.route("/b/<bucket_name>/notificationConfigs", methods=["POST"])
def bucket_notification_create(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    notification = bucket.insert_noti(flask.request)
    return gcs_bucket.Bucket.noti_to_rest(notification)


@gcs.route("/b/<bucket_name>/notificationConfigs/<notification_id>", methods=["DELETE"])
def bucket_notification_delete(bucket_name, notification_id):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    bucket.delete_noti(notification_id)
    return ""


@gcs.route("/b/<bucket_name>/notificationConfigs/<notification_id>")
def bucket_notification_get(bucket_name, notification_id):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    notification = bucket.lookup_noti(notification_id)
    return gcs_bucket.Bucket.noti_to_rest(notification)


@gcs.route("/b/<bucket_name>/iam")
def bucket_get_iam_policy(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    return gcs_bucket.Bucket.policy_to_rest(bucket.iam_policy)


@gcs.route("/b/<bucket_name>/iam", methods=["PUT"])
def bucket_set_iam_policy(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    bucket.insert_iam_policy(flask.request)
    return gcs_bucket.Bucket.policy_to_rest(bucket.iam_policy)


@gcs.route("/b/<bucket_name>/iam/testPermissions")
def bucket_test_iam_permissions(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    permissions = flask.request.args.getlist("permissions")
    result = {"kind": "storage#testIamPermissionsResponse", "permissions": permissions}
    return result


@gcs.route("/b/<bucket_name>/lockRetentionPolicy", methods=["POST"])
def bucket_lock_retention_policy(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    bucket.metadata.retention_policy.is_locked = True
    return bucket.to_rest(flask.request)


application = DispatcherMiddleware(
    root, {"/httpbin": httpbin.app, GCS_HANDLER_PATH: gcs}
)


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
