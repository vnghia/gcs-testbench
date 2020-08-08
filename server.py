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
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request.args)
    return bucket.to_rest(flask.request)


@gcs.route("/b/<bucket_name>", methods=["PUT"])
def buckets_update(bucket_name):
    insert_test_bucket()
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request.args)
    bucket.update(flask.request.data)
    return bucket.to_rest(flask.request)


@gcs.route("/b/<bucket_name>", methods=["PATCH"])
def buckets_patch(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request.args)
    bucket.update(flask.request.data)
    return bucket.to_rest(flask.request)


@gcs.route("/b/<bucket_name>", methods=["DELETE"])
def buckets_delete(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name, flask.request.args)
    bucket.delete()
    return ""


@gcs.route("/b/<bucket_name>/acl")
def bucket_acl_list(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    result = resources.ListBucketAccessControlsResponse(items=bucket.metadata.acl)
    return utils.message_to_rest(
        result, KIND_BUCKET_ACL + "s", list_size=len(result.items)
    )


@gcs.route("/b/<bucket_name>/acl", methods=["POST"])
def bucket_acl_create(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    acl = bucket.insert_acl(flask.request.data)
    return utils.message_to_rest(acl, KIND_BUCKET_ACL)


@gcs.route("/b/<bucket_name>/acl/<entity>")
def bucket_acl_get(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    acl, _ = bucket.lookup_acl(entity)
    return utils.message_to_rest(acl, KIND_BUCKET_ACL)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["PUT"])
def bucket_acl_update(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    role = json.loads(flask.request.data)["role"]
    data = resources.BucketAccessControl(entity=entity, role=role)
    acl = bucket.insert_acl(data, update=True)
    return utils.message_to_rest(acl, KIND_BUCKET_ACL)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["PATCH"])
def bucket_acl_patch(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    role = json.loads(flask.request.data)["role"]
    data = resources.BucketAccessControl(entity=entity, role=role)
    acl = bucket.insert_acl(data, update=True)
    return utils.message_to_rest(acl, KIND_BUCKET_ACL)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["DELETE"])
def bucket_acl_delete(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    bucket.delete_acl(entity)
    return ""


@gcs.route("/b/<bucket_name>/defaultObjectAcl")
def bucket_default_object_acl_list(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    result = resources.ListObjectAccessControlsResponse(
        items=bucket.metadata.default_object_acl
    )
    return utils.message_to_rest(
        result, KIND_OBJECT_ACL + "s", list_size=len(result.items)
    )


@gcs.route("/b/<bucket_name>/defaultObjectAcl", methods=["POST"])
def bucket_default_object_acl_create(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    acl = bucket.insert_default_object_acl(flask.request.data)
    return utils.message_to_rest(acl, KIND_OBJECT_ACL)


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["DELETE"])
def bucket_default_object_acl_delete(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    bucket.delete_default_object_acl(entity)
    return ""


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>")
def bucket_default_object_acl_get(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    acl, _ = bucket.lookup_default_object_acl(entity)
    return utils.message_to_rest(acl, KIND_OBJECT_ACL)


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["PUT"])
def bucket_default_object_acl_update(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    role = json.loads(flask.request.data)["role"]
    data = resources.ObjectAccessControl(entity=entity, role=role)
    acl = bucket.insert_default_object_acl(data, update=True)
    return utils.message_to_rest(acl, KIND_OBJECT_ACL)


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["PATCH"])
def bucket_default_object_acl_patch(bucket_name, entity):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    role = json.loads(flask.request.data)["role"]
    data = resources.ObjectAccessControl(entity=entity, role=role)
    acl = bucket.insert_default_object_acl(data, update=True)
    return utils.message_to_rest(acl, KIND_OBJECT_ACL)


@gcs.route("/b/<bucket_name>/notificationConfigs")
def bucket_notification_list(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    result = resources.ListNotificationsResponse(items=bucket.notification)
    return utils.message_to_rest(
        result,
        KIND_NOTIFICATION + "s",
        list_size=len(result.items),
        preserving_proto_field_name=True,
    )


@gcs.route("/b/<bucket_name>/notificationConfigs", methods=["POST"])
def bucket_notification_create(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    notification = bucket.insert_notification(flask.request.data)
    return utils.message_to_rest(
        notification, KIND_NOTIFICATION, preserving_proto_field_name=True,
    )


@gcs.route("/b/<bucket_name>/notificationConfigs/<notification_id>", methods=["DELETE"])
def bucket_notification_delete(bucket_name, notification_id):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    bucket.delete_notification(notification_id)
    return ""


@gcs.route("/b/<bucket_name>/notificationConfigs/<notification_id>")
def bucket_notification_get(bucket_name, notification_id):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    notification, _ = bucket.lookup_notification(notification_id)
    return utils.message_to_rest(
        notification, KIND_NOTIFICATION, preserving_proto_field_name=True,
    )


@gcs.route("/b/<bucket_name>/iam")
def bucket_get_iam_policy(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    return utils.message_to_rest(bucket.iam_policy, KIND_POLICY)


@gcs.route("/b/<bucket_name>/iam", methods=["PUT"])
def bucket_set_iam_policy(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    bucket.insert_iam_policy(flask.request.data)
    return utils.message_to_rest(bucket.iam_policy, KIND_POLICY)


@gcs.route("/b/<bucket_name>/iam/testPermissions")
def bucket_test_iam_permissions(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    permissions = flask.request.args.getlist("permissions")
    result = {"kind": "storage#testIamPermissionsResponse", "permissions": permissions}
    return result


@gcs.route("/b/<bucket_name>/lockRetentionPolicy", methods=["POST"])
def bucket_lock_retention_policy(bucket_name):
    bucket = gcs_bucket.Bucket.lookup(bucket_name)
    bucket.metadata.retention_policy.is_locked = True
    return bucket.to_rest(flask.request)


@gcs.route("/b/<bucket_name>/o")
def objects_list(bucket_name):
    insert_test_bucket()
    objs, prefixes = gcs_object.Object.list(bucket_name)
    result = {"items": [], "prefixes": prefixes, "nextPageToken": ""}
    versions = flask.request.args.get("versions", False)
    for obj in objs:
        result["items"].append(obj.to_rest(flask.request, None))
        if versions:
            result["items"].extend(obj.old_metadatas_to_rest(flask.request, None))
    return result


@gcs.route("/b/<bucket_name>/o/<path:object_name>", methods=["PUT"])
def objects_update(bucket_name, object_name):
    obj = gcs_object.Object.lookup(bucket_name, object_name, flask.request)
    projection = obj.update(flask.request)
    return obj.to_rest(flask.request, projection=projection)


@gcs.route("/b/<bucket_name>/o/<path:object_name>", methods=["PATCH"])
def objects_patch(bucket_name, object_name):
    obj = gcs_object.Object.lookup(bucket_name, object_name, flask.request)
    projection = obj.update(flask.request)
    return obj.to_rest(flask.request, projection=projection)


@gcs.route("/b/<bucket_name>/o/<path:object_name>", methods=["DELETE"])
def objects_delete(bucket_name, object_name):
    obj = gcs_object.Object.lookup(bucket_name, object_name, flask.request)
    obj.delete()
    return ""


# Define the WSGI application to handle bucket requests.
UPLOAD_HANDLER_PATH = "/upload/storage/v1"
upload = flask.Flask(__name__)
upload.debug = True


@upload.route("/b/<bucket_name>/o", methods=["POST"])
def objects_insert(bucket_name):
    obj = gcs_object.Object(bucket_name, request=flask.request)
    return obj.to_rest(flask.request)


# Define the WSGI application to handle bucket requests.
DOWNLOAD_HANDLER_PATH = "/download/storage/v1"
download = flask.Flask(__name__)
download.debug = True


@gcs.route("/b/<bucket_name>/o/<path:object_name>")
@download.route("/b/<bucket_name>/o/<path:object_name>")
def objects_get(bucket_name, object_name):
    obj = gcs_object.Object.lookup(bucket_name, object_name, flask.request)
    alt = flask.request.args.get("alt", "json")
    if alt == "json":
        return obj.get_generation(flask.request)
    else:
        return obj.content


application = DispatcherMiddleware(
    root,
    {
        "/httpbin": httpbin.app,
        GCS_HANDLER_PATH: gcs,
        UPLOAD_HANDLER_PATH: upload,
        DOWNLOAD_HANDLER_PATH: download,
    },
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
