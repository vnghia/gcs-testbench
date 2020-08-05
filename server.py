from concurrent import futures

import argparse
import json
import httpbin
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
    project = flask.request.args.get("project")
    if project is None or project.endswith("-"):
        return "Invalid or missing project id in `Buckets: list`", 412
    result = {"next_page_token": "", "items": []}
    for name, b in utils.AllBuckets():
        result["items"].append(utils.ToRestDict(b["metadata"], "storage#bucket"))
    return result


@gcs.route("/b", methods=["POST"])
def buckets_insert():
    """Implement the 'Buckets: insert' API: create a new Bucket."""
    insert_test_bucket()
    if not utils.ValidateBucketName(json.loads(flask.request.data)["name"]):
        return "Bucket name %s is invalid" % json.loads(flask.request.data)["name"], 412
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


@gcs.route("/b/<bucket_name>/acl")
def bucket_acl_list(bucket_name):
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    result = {"items": []}
    for item in bucket["metadata"].acl:
        result["items"].append(utils.ToRestDict(item, "storage#bucketAccessControl"))
    return result


@gcs.route("/b/<bucket_name>/acl", methods=["POST"])
def bucket_acl_create(bucket_name):
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    payload = utils.ToProtoDict(flask.request.data)
    acl = ParseDict(
        payload, resources.BucketAccessControl(), ignore_unknown_fields=True
    )
    bucket["metadata"].acl.append(acl)
    return utils.ToRestDict(acl, "storage#bucketAccessControl")


@gcs.route("/b/<bucket_name>/acl/<entity>")
def bucket_acl_get(bucket_name, entity):
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    for item in bucket["metadata"].acl:
        if item.entity == entity:
            return utils.ToRestDict(item, "storage#bucketAccessControl")
    return "ACL does not exist", 404


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["PUT"])
def bucket_acl_update(bucket_name, entity):
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    for i in range(len(bucket["metadata"].acl)):
        if bucket["metadata"].acl[i].entity == entity:
            payload = utils.ToProtoDict(flask.request.data)
            bucket["metadata"].acl[i].Clear()
            ParseDict(payload, bucket["metadata"].acl[i], ignore_unknown_fields=True)
            return utils.ToRestDict(
                bucket["metadata"].acl[i], "storage#bucketAccessControl"
            )
    return "ACL does not exist", 404


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["PATCH"])
def bucket_acl_patch(bucket_name, entity):
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    for i in range(len(bucket["metadata"].acl)):
        if bucket["metadata"].acl[i].entity == entity:
            payload = utils.ToProtoDict(flask.request.data)
            ParseDict(payload, bucket["metadata"].acl[i], ignore_unknown_fields=True)
            return utils.ToRestDict(
                bucket["metadata"].acl[i], "storage#bucketAccessControl"
            )
    return "ACL does not exist", 404


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["DELETE"])
def bucket_acl_delete(bucket_name, entity):
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    for i in range(len(bucket["metadata"].acl)):
        if bucket["metadata"].acl[i].entity == entity:
            del bucket["metadata"].acl[i]
            return ""
    return "ACL does not exist", 404


@gcs.route("/b/<bucket_name>/defaultObjectAcl")
def bucket_default_object_acl_list(bucket_name):
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    result = {"items": []}
    for item in bucket["metadata"].default_object_acl:
        result["items"].append(utils.ToRestDict(item, "storage#objectAccessControl"))
    return result


@gcs.route("/b/<bucket_name>/defaultObjectAcl", methods=["POST"])
def bucket_default_object_acl_create(bucket_name):
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    payload = utils.ToProtoDict(flask.request.data)
    acl = ParseDict(
        payload, resources.ObjectAccessControl(), ignore_unknown_fields=True
    )
    bucket["metadata"].default_object_acl.append(acl)
    return utils.ToRestDict(acl, "storage#objectAccessControl")


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["DELETE"])
def bucket_default_object_acl_delete(bucket_name, entity):
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    for i in range(len(bucket["metadata"].default_object_acl)):
        if bucket["metadata"].default_object_acl[i].entity == entity:
            del bucket["metadata"].default_object_acl[i]
            return ""
    return "ACL does not exist", 404


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>")
def bucket_default_object_acl_get(bucket_name, entity):
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    for item in bucket["metadata"].default_object_acl:
        if item.entity == entity:
            return utils.ToRestDict(item, "storage#objectAccessControl")
    return "ACL does not exist", 404


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["PUT"])
def bucket_default_object_acl_update(bucket_name, entity):
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    for i in range(len(bucket["metadata"].default_object_acl)):
        if bucket["metadata"].default_object_acl[i].entity == entity:
            payload = utils.ToProtoDict(flask.request.data)
            bucket["metadata"].default_object_acl[i].Clear()
            ParseDict(
                payload,
                bucket["metadata"].default_object_acl[i],
                ignore_unknown_fields=True,
            )
            return utils.ToRestDict(
                bucket["metadata"].default_object_acl[i], "storage#objectAccessControl"
            )
    return "ACL does not exist", 404


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["PATCH"])
def bucket_default_object_acl_patch(bucket_name, entity):
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    for i in range(len(bucket["metadata"].default_object_acl)):
        if bucket["metadata"].default_object_acl[i].entity == entity:
            payload = utils.ToProtoDict(flask.request.data)
            ParseDict(
                payload,
                bucket["metadata"].default_object_acl[i],
                ignore_unknown_fields=True,
            )
            return utils.ToRestDict(
                bucket["metadata"].default_object_acl[i], "storage#objectAccessControl"
            )
    return "ACL does not exist", 404


@gcs.route("/b/<bucket_name>/notificationConfigs")
def bucket_notification_list(bucket_name):
    raw_list, code = utils.ListNotification(bucket_name)
    if code != 200:
        return raw_list, code
    result = {"items": []}
    for noti in raw_list:
        result["items"].append(utils.ToRestDict(noti, "storage#notification"))
    return result


@gcs.route("/b/<bucket_name>/notificationConfigs", methods=["POST"])
def bucket_notification_create(bucket_name):
    payload = utils.ToProtoDict(flask.request.data)
    noti = ParseDict(payload, resources.Notification(), ignore_unknown_fields=True)
    result, code = utils.InsertNotification(bucket_name, noti)
    if code != 200:
        return result, code
    result = MessageToDict(result, preserving_proto_field_name=True)
    result["kind"] = "storage#notification"
    return result


@gcs.route("/b/<bucket_name>/notificationConfigs/<notification_id>", methods=["DELETE"])
def bucket_notification_delete(bucket_name, notification_id):
    raw_list, code = utils.ListNotification(bucket_name)
    if code != 200:
        return raw_list, code
    for i in range(len(raw_list)):
        if raw_list[i].id == notification_id:
            del raw_list[i]
            return ""
    return "Notification %s does not exist" % notification_id, 404


@gcs.route("/b/<bucket_name>/notificationConfigs/<notification_id>")
def bucket_notification_get(bucket_name, notification_id):
    raw_list, code = utils.ListNotification(bucket_name)
    if code != 200:
        return raw_list, code
    for noti in raw_list:
        if noti.id == notification_id:
            result = MessageToDict(noti, preserving_proto_field_name=True)
            result["kind"] = "storage#notification"
            return result
    return "Notification %s does not exist" % notification_id, 404


@gcs.route("/b/<bucket_name>/iam")
def bucket_get_iam_policy(bucket_name):
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    result, code = utils.GetBucketIamPolicy(bucket_name)
    if code != 200:
        return result, code
    return utils.ToRestDict(result, "storage#policy")


@gcs.route("/b/<bucket_name>/iam", methods=["PUT"])
def bucket_set_iam_policy(bucket_name):
    payload = utils.ToProtoDict(flask.request.data)
    policy = ParseDict(payload, policy_pb2.Policy(), ignore_unknown_fields=True)
    result, code = utils.SetBucketIamPolicy(bucket_name, policy)
    if code != 200:
        return result, code
    return utils.ToRestDict(result, "storage#policy")


@gcs.route("/b/<bucket_name>/iam/testPermissions")
def bucket_test_iam_permissions(bucket_name):
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    permissions = flask.request.args.getlist("permissions")
    result = {"kind": "storage#testIamPermissionsResponse", "permissions": permissions}
    return result


@gcs.route("/b/<bucket_name>/lockRetentionPolicy", methods=["POST"])
def bucket_lock_retention_policy(bucket_name):
    bucket, status_code = utils.CheckBucketPrecondition(bucket_name, flask.request)
    if status_code != 200:
        return bucket, status_code
    bucket["metadata"].retention_policy.is_locked = True
    return utils.ToRestDict(bucket["metadata"], "storage#bucket")


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
