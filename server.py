import argparse
import json
import logging
import os
from concurrent import futures

import flask
import grpc
import httpbin
from google.iam.v1 import policy_pb2
from google.protobuf.json_format import MessageToDict, ParseDict
from werkzeug import serving
from werkzeug.middleware.dispatcher import DispatcherMiddleware

import gcs_bucket
import storage_pb2 as storage
import storage_pb2_grpc
import storage_resources_pb2 as resources
import storage_resources_pb2_grpc
import utils

# Constant

KIND_BUCKET_ACL = "storage#bucketAccessControl"
KIND_OBJECT_ACL = "storage#objectAccessControl"
KIND_POLICY = "storage#policy"
KIND_NOTIFICATION = "storage#notification"

# GPRC


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
        bucket_test = gcs_bucket.Bucket(json.dumps({"name": bucket_name}))
        bucket_test.metadata.metageneration = 4
        bucket_test.metadata.versioning.enabled = True


@gcs.route("/b", methods=["GET"])
def buckets_list():
    insert_test_bucket()
    project = flask.request.args.get("project")
    result = resources.ListBucketsResponse(next_page_token="", items=[])
    for name, b in gcs_bucket.Bucket.list(project):
        result.items.append(b.metadata)
    return utils.message_to_rest(
        result,
        "storage#buckets",
        flask.request.args.get("fields", None),
        len(result.items),
    )


@gcs.route("/b", methods=["POST"])
def buckets_insert():
    insert_test_bucket()
    bucket = gcs_bucket.Bucket(flask.request.data)
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
    bucket.update(flask.request.data)
    return bucket.to_rest(flask.request)


@gcs.route("/b/<bucket_name>", methods=["PATCH"])
def buckets_patch(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    bucket.update(flask.request.data)
    return bucket.to_rest(flask.request)


@gcs.route("/b/<bucket_name>", methods=["DELETE"])
def buckets_delete(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    bucket.delete()
    return ""


@gcs.route("/b/<bucket_name>/acl")
def bucket_acl_list(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    result = resources.ListBucketAccessControlsResponse(items=bucket.metadata.acl)
    return utils.message_to_rest(
        result, KIND_BUCKET_ACL + "s", list_size=len(result.items)
    )


@gcs.route("/b/<bucket_name>/acl", methods=["POST"])
def bucket_acl_create(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    acl = bucket.insert_acl(flask.request.data)
    return utils.message_to_rest(acl, KIND_BUCKET_ACL)


@gcs.route("/b/<bucket_name>/acl/<entity>")
def bucket_acl_get(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    acl, _ = bucket.lookup_acl(entity)
    return utils.message_to_rest(acl, KIND_BUCKET_ACL)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["PUT"])
def bucket_acl_update(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    role = json.loads(flask.request.data)["role"]
    data = resources.BucketAccessControl(entity=entity, role=role)
    acl = bucket.insert_acl(data, update=True)
    return utils.message_to_rest(acl, KIND_BUCKET_ACL)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["PATCH"])
def bucket_acl_patch(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    role = json.loads(flask.request.data)["role"]
    data = resources.BucketAccessControl(entity=entity, role=role)
    acl = bucket.insert_acl(data, update=True)
    return utils.message_to_rest(acl, KIND_BUCKET_ACL)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["DELETE"])
def bucket_acl_delete(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    bucket.delete_acl(entity)
    return ""


@gcs.route("/b/<bucket_name>/defaultObjectAcl")
def bucket_default_object_acl_list(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    result = resources.ListObjectAccessControlsResponse(
        items=bucket.metadata.default_object_acl
    )
    return utils.message_to_rest(
        result, KIND_OBJECT_ACL + "s", list_size=len(result.items)
    )


@gcs.route("/b/<bucket_name>/defaultObjectAcl", methods=["POST"])
def bucket_default_object_acl_create(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    acl = bucket.insert_default_object_acl(flask.request.data)
    return utils.message_to_rest(acl, KIND_OBJECT_ACL)


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["DELETE"])
def bucket_default_object_acl_delete(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    bucket.delete_default_object_acl(entity)
    return ""


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>")
def bucket_default_object_acl_get(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    acl, _ = bucket.lookup_default_object_acl(entity)
    return utils.message_to_rest(acl, KIND_OBJECT_ACL)


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["PUT"])
def bucket_default_object_acl_update(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    role = json.loads(flask.request.data)["role"]
    data = resources.ObjectAccessControl(entity=entity, role=role)
    acl = bucket.insert_default_object_acl(data, update=True)
    return utils.message_to_rest(acl, KIND_OBJECT_ACL)


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["PATCH"])
def bucket_default_object_acl_patch(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    role = json.loads(flask.request.data)["role"]
    data = resources.ObjectAccessControl(entity=entity, role=role)
    acl = bucket.insert_default_object_acl(data, update=True)
    return utils.message_to_rest(acl, KIND_OBJECT_ACL)


@gcs.route("/b/<bucket_name>/notificationConfigs")
def bucket_notification_list(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    result = resources.ListNotificationsResponse(items=bucket.notification)
    return utils.message_to_rest(
        result,
        KIND_NOTIFICATION + "s",
        list_size=len(result.items),
        preserving_proto_field_name=True,
    )


@gcs.route("/b/<bucket_name>/notificationConfigs", methods=["POST"])
def bucket_notification_create(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    notification = bucket.insert_notification(flask.request.data)
    return utils.message_to_rest(
        notification, KIND_NOTIFICATION, preserving_proto_field_name=True,
    )


@gcs.route("/b/<bucket_name>/notificationConfigs/<notification_id>", methods=["DELETE"])
def bucket_notification_delete(bucket_name, notification_id):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    bucket.delete_notification(notification_id)
    return ""


@gcs.route("/b/<bucket_name>/notificationConfigs/<notification_id>")
def bucket_notification_get(bucket_name, notification_id):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    notification, _ = bucket.lookup_notification(notification_id)
    return utils.message_to_rest(
        notification, KIND_NOTIFICATION, preserving_proto_field_name=True,
    )


@gcs.route("/b/<bucket_name>/iam")
def bucket_get_iam_policy(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    return utils.message_to_rest(bucket.iam_policy, KIND_POLICY)


@gcs.route("/b/<bucket_name>/iam", methods=["PUT"])
def bucket_set_iam_policy(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request)
    bucket.insert_iam_policy(flask.request.data)
    return utils.message_to_rest(bucket.iam_policy, KIND_POLICY)


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
