# Copyright 2020 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import json

import flask
import httpbin
from werkzeug import serving
from werkzeug.middleware.dispatcher import DispatcherMiddleware

import storage_resources_pb2 as resources
from common import (
    constant,
    gcs_bucket,
    gcs_object,
    gcs_project,
    gcs_rewrite,
    gcs_upload,
    process,
    error,
    data_utils,
)

db = None

# Default handler for the test bench.
root = flask.Flask(__name__)
root.debug = True


@root.route("/")
def index():
    return "OK"


# Define the WSGI application to handle bucket requests.
GCS_HANDLER_PATH = "/storage/v1"
gcs = flask.Flask(__name__)
gcs.debug = True


@gcs.route("/b", methods=["GET"])
def buckets_list():
    db.insert_test_bucket()
    project = flask.request.args.get("project")
    result = resources.ListBucketsResponse(next_page_token="", items=[])
    for name, b in db.list_bucket(project, None):
        result.items.append(b.metadata)
    return process.message_to_rest(
        result,
        "storage#buckets",
        flask.request.args.get("fields", None),
        len(result.items),
    )


@gcs.route("/b", methods=["POST"])
def buckets_insert():
    db.insert_test_bucket()
    bucket = gcs_bucket.Bucket.init(flask.request, None)
    db.insert_bucket(bucket)
    return bucket.to_rest(flask.request)


@gcs.route("/b/<bucket_name>")
def buckets_get(bucket_name):
    db.insert_test_bucket()
    bucket = db.get_bucket(bucket_name, flask.request, None)
    return bucket.to_rest(flask.request)


@gcs.route("/b/<bucket_name>", methods=["PUT"])
def buckets_update(bucket_name):
    db.insert_test_bucket()
    bucket = db.get_bucket(bucket_name, flask.request, None)
    bucket.update(flask.request, None)
    return bucket.to_rest(flask.request)


@gcs.route("/b/<bucket_name>", methods=["PATCH"])
def buckets_patch(bucket_name):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    bucket.patch(flask.request, None)
    return bucket.to_rest(flask.request)


@gcs.route("/b/<bucket_name>", methods=["DELETE"])
def buckets_delete(bucket_name):
    db.delete_bucket(bucket_name, flask.request, None)
    return ""


@gcs.route("/b/<bucket_name>/acl")
def bucket_acl_list(bucket_name):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    result = resources.ListBucketAccessControlsResponse(items=bucket.metadata.acl)
    return process.message_to_rest(
        result, constant.KIND_BUCKET_ACL + "s", list_size=len(result.items)
    )


@gcs.route("/b/<bucket_name>/acl", methods=["POST"])
def bucket_acl_create(bucket_name):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    acl = bucket.insert_acl(flask.request, None)
    return process.message_to_rest(acl, constant.KIND_BUCKET_ACL)


@gcs.route("/b/<bucket_name>/acl/<entity>")
def bucket_acl_get(bucket_name, entity):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    acl = bucket.get_acl(entity, None)
    return process.message_to_rest(acl, constant.KIND_BUCKET_ACL)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["PUT"])
def bucket_acl_update(bucket_name, entity):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    acl = bucket.update_acl(entity, flask.request, None)
    return process.message_to_rest(acl, constant.KIND_BUCKET_ACL)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["PATCH"])
def bucket_acl_patch(bucket_name, entity):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    acl = bucket.patch_acl(entity, flask.request, None)
    return process.message_to_rest(acl, constant.KIND_BUCKET_ACL)


@gcs.route("/b/<bucket_name>/acl/<entity>", methods=["DELETE"])
def bucket_acl_delete(bucket_name, entity):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    bucket.delete_acl(entity, None)
    return ""


@gcs.route("/b/<bucket_name>/defaultObjectAcl")
def bucket_default_object_acl_list(bucket_name):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    result = resources.ListObjectAccessControlsResponse(
        items=bucket.metadata.default_object_acl
    )
    return process.message_to_rest(
        result, constant.KIND_OBJECT_ACL + "s", list_size=len(result.items)
    )


@gcs.route("/b/<bucket_name>/defaultObjectAcl", methods=["POST"])
def bucket_default_object_acl_create(bucket_name):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    acl = bucket.insert_doacl(flask.request, None)
    return process.message_to_rest(acl, constant.KIND_OBJECT_ACL)


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>")
def bucket_default_object_acl_get(bucket_name, entity):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    acl = bucket.get_doacl(entity, None)
    return process.message_to_rest(acl, constant.KIND_OBJECT_ACL)


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["PUT"])
def bucket_default_object_acl_update(bucket_name, entity):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    acl = bucket.update_doacl(entity, flask.request, None)
    return process.message_to_rest(acl, constant.KIND_OBJECT_ACL)


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["PATCH"])
def bucket_default_object_acl_patch(bucket_name, entity):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    acl = bucket.patch_doacl(entity, flask.request, None)
    return process.message_to_rest(acl, constant.KIND_OBJECT_ACL)


@gcs.route("/b/<bucket_name>/defaultObjectAcl/<entity>", methods=["DELETE"])
def bucket_default_object_acl_delete(bucket_name, entity):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    bucket.delete_doacl(entity, None)
    return ""


@gcs.route("/b/<bucket_name>/notificationConfigs")
def bucket_notification_list(bucket_name):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    result = resources.ListNotificationsResponse(items=bucket.notifications)
    return process.message_to_rest(
        result,
        constant.KIND_NOTIFICATION + "s",
        list_size=len(result.items),
        preserving_proto_field_name=True,
    )


@gcs.route("/b/<bucket_name>/notificationConfigs", methods=["POST"])
def bucket_notification_create(bucket_name):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    notification = bucket.insert_notification(flask.request, None)
    return process.message_to_rest(
        notification,
        constant.KIND_NOTIFICATION,
        preserving_proto_field_name=True,
    )


@gcs.route("/b/<bucket_name>/notificationConfigs/<notification_id>")
def bucket_notification_get(bucket_name, notification_id):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    notification = bucket.get_notification(notification_id, None)
    return process.message_to_rest(
        notification,
        constant.KIND_NOTIFICATION,
        preserving_proto_field_name=True,
    )


@gcs.route("/b/<bucket_name>/notificationConfigs/<notification_id>", methods=["DELETE"])
def bucket_notification_delete(bucket_name, notification_id):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    bucket.delete_notification(notification_id, None)
    return ""


@gcs.route("/b/<bucket_name>/iam")
def bucket_get_iam_policy(bucket_name):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    return process.message_to_rest(bucket.iam_policy, constant.KIND_POLICY)


@gcs.route("/b/<bucket_name>/iam", methods=["PUT"])
def bucket_set_iam_policy(bucket_name):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    bucket.set_iam_policy(flask.request, None)
    return process.message_to_rest(bucket.iam_policy, constant.KIND_POLICY)


@gcs.route("/b/<bucket_name>/iam/testPermissions")
def bucket_test_iam_permissions(bucket_name):
    db.get_bucket(bucket_name, flask.request, None)
    permissions = flask.request.args.getlist("permissions")
    result = {
        "kind": "storage#testIamPermissionsResponse",
        "permissions": permissions,
    }
    return result


@gcs.route("/b/<bucket_name>/lockRetentionPolicy", methods=["POST"])
def bucket_lock_retention_policy(bucket_name):
    bucket = db.get_bucket(bucket_name, flask.request, None)
    bucket.metadata.retention_policy.is_locked = True
    return bucket.to_rest(flask.request)


# ---OBJECT--- #


@gcs.route("/b/<bucket_name>/o")
def objects_list(bucket_name):
    db.insert_test_bucket()
    items, prefixes = db.list_object(bucket_name, flask.request, None)
    result = resources.ListObjectsResponse(items=items, prefixes=prefixes)
    return process.message_to_rest(
        result,
        "storage#objects",
        flask.request.args.get("fields", None),
        len(result.items),
    )


@gcs.route("/b/<bucket_name>/o/<path:object_name>", methods=["PUT"])
def objects_update(bucket_name, object_name):
    obj = db.get_object(bucket_name, object_name, flask.request, False, None)
    obj.update(flask.request, None)
    return obj.to_rest(flask.request)


@gcs.route("/b/<bucket_name>/o/<path:object_name>", methods=["PATCH"])
def objects_patch(bucket_name, object_name):
    obj = db.get_object(bucket_name, object_name, flask.request, False, None)
    obj.patch(flask.request, None)
    return obj.to_rest(flask.request)


@gcs.route("/b/<bucket_name>/o/<path:object_name>", methods=["DELETE"])
def objects_delete(bucket_name, object_name):
    db.delete_object(bucket_name, object_name, flask.request, None)
    return ""


# === OBJECT SPECIAL OPERATIONS === #


@gcs.route("/b/<bucket_name>/o/<path:object_name>/compose", methods=["POST"])
def objects_compose(bucket_name, object_name):
    payload = process.process_data(flask.request.data)
    source_objects = payload["sourceObjects"]
    if source_objects is None:
        error.abort(400, "You must provide at least one source component.", None)
    if len(source_objects) > 32:
        error.abort(
            400,
            "The number of source components provided"
            " (%d) exceeds the maximum (32)" % len(source_objects),
            None,
        )
    composed_media = b""
    for source_object in source_objects:
        source_object_name = source_object.get("name")
        if source_object_name is None:
            error.abort(400, "Required.", None)
        generation = source_object.get("generation")
        if_generation_match = (
            source_object.get("objectPreconditions").get("ifGenerationMatch")
            if source_object.get("objectPreconditions") is not None
            else None
        )
        obj = gcs_object.Object.lookup(
            bucket_name,
            source_object_name,
            {
                "generation": generation,
                "ifGenerationMatch": if_generation_match,
            },
        )
        composed_media += obj.media
    metadata = {"name": object_name, "bucket": bucket_name}
    metadata.update(payload.get("destination", {}))
    composed_object = gcs_object.Object(
        metadata,
        composed_media,
        flask.request.args,
        flask.request.headers,
    )
    return composed_object.to_rest(flask.request)


@gcs.route(
    "/b/<source_bucket>/o/<path:source_object>/copyTo/b/<destination_bucket>/o/<path:destination_object>",
    methods=["POST"],
)
def objects_copy(source_bucket, source_object, destination_bucket, destination_object):
    source_obj = gcs_object.Object.lookup(
        source_bucket, source_object, flask.request.args, True
    )
    db.check_object_generation(
        destination_bucket, destination_object, flask.request, False, None
    )
    destination_metadata = source_obj.metadata
    destination_metadata.bucket = destination_bucket
    destination_metadata.name = destination_object
    destination_obj = gcs_object.Object(
        destination_metadata,
        source_obj.media,
        flask.request.args,
        flask.request.headers,
    )
    destination_obj.update(flask.request.data)
    return destination_obj.to_rest(flask.request)


@gcs.route(
    "/b/<source_bucket>/o/<path:source_object>/rewriteTo/b/<destination_bucket>/o/<path:destination_object>",
    methods=["POST"],
)
def objects_rewrite(
    source_bucket, source_object, destination_bucket, destination_object
):
    db.insert_test_bucket()
    args = dict(flask.request.args)
    args["sourceBucket"] = source_bucket
    args["sourceObject"] = source_object
    args["destinationBucket"] = destination_bucket
    args["destinationObject"] = destination_object
    flask.request.args = args
    return gcs_rewrite.Rewrite.process_request(flask.request, context=None)


# === OBJECT ACCESS CONTROL === #


@gcs.route("/b/<bucket_name>/o/<path:object_name>/acl")
def objects_acl_list(bucket_name, object_name):
    obj = db.get_object(bucket_name, object_name, flask.request, False, None)
    result = resources.ListObjectAccessControlsResponse(items=obj.metadata.acl)
    return process.message_to_rest(
        result,
        constant.KIND_OBJECT_ACL + "s",
        flask.request.args.get("fields", None),
        len(result.items),
    )


@gcs.route("/b/<bucket_name>/o/<path:object_name>/acl", methods=["POST"])
def objects_acl_create(bucket_name, object_name):
    obj = db.get_object(bucket_name, object_name, flask.request, False, None)
    acl = obj.insert_acl(flask.request, None)
    return process.message_to_rest(acl, constant.KIND_OBJECT_ACL)


@gcs.route("/b/<bucket_name>/o/<path:object_name>/acl/<entity>")
def objects_acl_get(bucket_name, object_name, entity):
    obj = db.get_object(bucket_name, object_name, flask.request, False, None)
    acl = obj.get_acl(entity, None)
    return process.message_to_rest(acl, constant.KIND_OBJECT_ACL)


@gcs.route("/b/<bucket_name>/o/<path:object_name>/acl/<entity>", methods=["PUT"])
def objects_acl_update(bucket_name, object_name, entity):
    obj = db.get_object(bucket_name, object_name, flask.request, False, None)
    acl = obj.update_acl(entity, flask.request, None)
    return process.message_to_rest(acl, constant.KIND_OBJECT_ACL)


@gcs.route("/b/<bucket_name>/o/<path:object_name>/acl/<entity>", methods=["PATCH"])
def objects_acl_patch(bucket_name, object_name, entity):
    obj = db.get_object(bucket_name, object_name, flask.request, False, None)
    acl = obj.patch_acl(entity, flask.request, None)
    return process.message_to_rest(acl, constant.KIND_OBJECT_ACL)


@gcs.route("/b/<bucket_name>/o/<path:object_name>/acl/<entity>", methods=["DELETE"])
def objects_acl_delete(bucket_name, object_name, entity):
    obj = db.get_object(bucket_name, object_name, flask.request, False, None)
    obj.delete_acl(entity, None)
    return ""


# Define the WSGI application to handle bucket requests.
UPLOAD_HANDLER_PATH = "/upload/storage/v1"
upload = flask.Flask(__name__)
upload.debug = True


@upload.route("/b/<bucket_name>/o", methods=["POST"])
def objects_insert(bucket_name):
    db.insert_test_bucket()
    db.check_bucket_exist(bucket_name, None)
    upload_type = flask.request.args.get("uploadType")
    if upload_type is None:
        error.abort(400, "uploadType not set in Objects: insert", None)
    if upload_type not in {"multipart", "media", "resumable"}:
        error.abort(400, "testbench does not support %s uploadType" % upload_type, None)
    obj = None
    if upload_type == "resumable":
        upload = gcs_upload.Upload.init(bucket_name, flask.request, None)
        db.insert_upload(upload)
        return upload.to_rest()
    elif upload_type == "media":
        obj = gcs_object.Object.init_media(bucket_name, flask.request)
    elif upload_type == "multipart":
        obj = gcs_object.Object.init_multipart(bucket_name, flask.request)
    db.insert_object(bucket_name, obj, flask.request, None)
    return obj.to_rest(flask.request)


@upload.route("/b/<bucket_name>/o", methods=["PUT"])
def resumable_upload_chunk(bucket_name):
    request = flask.request
    upload_id = request.args.get("upload_id")
    if upload_id is None:
        error.abort(400, "Missing upload_id in resumable_upload_chunk", None)
    upload = db.get_upload(upload_id, None)
    content_length = int(request.headers.get("content-length", 0))
    if content_length != len(request.data):
        error.abort(412, "content-length header is not invaild.", None)
    content_range = request.headers.get("content-range")
    if content_range is not None:
        items = list(constant.content_range_split.match(content_range).groups())
        if len(items) != 2 or (items[0] == items[1] and items[0] != "*"):
            error.abort(400, "Invalid Content-Range in upload %s" % content_range)
        if items[1] != "*":
            x_upload_content_length = upload.request.headers.get(
                "x-upload-content-length", 0
            )
            if x_upload_content_length != 0 and x_upload_content_length != int(
                items[1]
            ):
                error.abort(
                    400,
                    "X-Upload-Content-Length"
                    "validation failed. Expected=%d, got %d."
                    % (int(x_upload_content_length), int(items[1])),
                    None,
                )
            upload.complete = int(items[1]) == len(upload.media)
            if upload.complete:
                obj = gcs_object.Object.init(
                    upload.metadata, upload.media, upload.request, None
                )
                obj.metadata.metadata["x_testbench_upload"] = "resumable"
                db.insert_object(bucket_name, obj, upload.request, None)
                return obj.to_rest(upload.request)
        if items[0] == "*":
            if upload.complete:
                return db.get_object(
                    bucket_name, upload.metadata.name, request, False, None
                ).to_rest(upload.request)
            else:
                return upload.status_rest()
        upload.media += request.data
        upload.complete = (
            len(upload.media) == int(items[1]) if items[1] != "*" else False
        )
        if upload.complete:
            obj = gcs_object.Object.init(
                upload.metadata, upload.media, upload.request, None
            )
            obj.metadata.metadata["x_testbench_upload"] = "resumable"
            db.insert_object(bucket_name, obj, upload.request, None)
            return obj.to_rest(upload.request)
    if upload.complete:
        return db.get_object(
            bucket_name, upload.metadata.name, upload.request, False, None
        ).to_rest(upload.request)
    else:
        return upload.status_rest()


@upload.route("/b/<bucket_name>/o", methods=["DELETE"])
def delete_resumable_upload(bucket_name):
    upload_id = flask.request.args.get("upload_id")
    if upload_id is None:
        error.abort(400, "Missing upload_id in delete_resumable_upload", None)
    db.delete_upload(upload_id, None)
    return flask.make_response("", 499, {"content-length": 0})


# Define the WSGI application to handle bucket requests.
DOWNLOAD_HANDLER_PATH = "/download/storage/v1"
download = flask.Flask(__name__)
download.debug = True


@gcs.route("/b/<bucket_name>/o/<path:object_name>")
@download.route("/b/<bucket_name>/o/<path:object_name>")
def objects_get(bucket_name, object_name):
    obj = db.get_object(bucket_name, object_name, flask.request, False, None)
    alt = flask.request.args.get("alt", "json")
    if alt == "json":
        return obj.to_rest(flask.request)
    else:
        return obj.media_rest(flask.request)


IAM_HANDLER_PATH = "/iamapi"
iam = flask.Flask(__name__)
iam.debug = True


@iam.route("/projects/-/serviceAccounts/<service_account>:signBlob", methods=["POST"])
def sign_blob(service_account):
    """Implement the `projects.serviceAccounts.signBlob` API."""
    payload = json.loads(flask.request.data)
    if payload.get("payload") is None:
        error.abort(400, "Missing payload in the payload", None)
    try:
        blob = base64.b64decode(payload.get("payload"))
    except TypeError:
        error.abort(400, "payload must be base64-encoded", None)
    blob = b"signed: " + blob
    response = {
        "keyId": "fake-key-id-123",
        "signedBlob": base64.b64encode(blob).decode("utf-8"),
    }
    return response


# Define the WSGI application to handle (a few) requests in the XML API.
XMLAPI_HANDLER_PATH = "/xmlapi"
xmlapi = flask.Flask(__name__)
xmlapi.debug = True


@xmlapi.route("/<bucket_name>/<object_name>")
def xmlapi_get_object(bucket_name, object_name):
    if flask.request.args.get("acl") is not None:
        error.abort(500, "ACL query not supported in XML API", None)
    if flask.request.args.get("encryption") is not None:
        error.abort(500, "Encryption query not supported in XML API", None)
    obj = db.get_object(bucket_name, object_name, flask.request, False, None)
    return obj.media_rest(flask.request)


@xmlapi.route("/<bucket_name>/<object_name>", methods=["PUT"])
def xmlapi_put_object(bucket_name, object_name):
    db.insert_test_bucket()
    obj, request = gcs_object.Object.init_xml(bucket_name, object_name, flask.request)
    db.insert_object(bucket_name, obj, flask.request, None)
    return ""


# Define the WSGI application to handle HMAC key requests
(PROJECTS_HANDLER_PATH, projects_app) = gcs_project.get_projects_app()


server = DispatcherMiddleware(
    root,
    {
        "/httpbin": httpbin.app,
        GCS_HANDLER_PATH: gcs,
        UPLOAD_HANDLER_PATH: upload,
        DOWNLOAD_HANDLER_PATH: download,
        IAM_HANDLER_PATH: iam,
        XMLAPI_HANDLER_PATH: xmlapi,
        PROJECTS_HANDLER_PATH: projects_app,
    },
)


def run(port, database):
    global db
    db = database
    serving.run_simple(
        "localhost",
        int(port),
        server,
        use_reloader=False,
        threaded=True,
    )
