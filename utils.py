import base64
import json
import re
import struct
from datetime import timezone
from random import random

import flask
from crc32c import crc32
from dateutil.parser import parse
from flatdict import FlatterDict
from google.protobuf.json_format import MessageToDict, ParseDict
from google.protobuf.message import Message

import storage_resources_pb2 as resources

# regex
remove_index = re.compile(r":[0-9]+|^[0-9]+")
split_fields = re.compile(r"[a-zA-Z0-9]*\(.*\)|[a-zA-Z0-9]+")


# etag hash


def compute_etag(content):
    return base64.b64encode(bytearray(content, "utf-8"))


def random_etag(content=""):
    return compute_etag(content + str(random()))


def compute_crc32c(content):
    return base64.b64encode(struct.pack(">I", crc32(content))).decode("utf-8")


def encode_crc32c(value):
    if not isinstance(value, int):
        return value
    return base64.b64encode(struct.pack(">I", value)).decode("utf-8")


# protobuf <-> rest


def to_dict(source):
    if not isinstance(source, dict):
        return source
    destination_dict = dict()
    destination_list = list()
    for key, value in source.items():
        if key.isdecimal():
            destination_list.append(to_dict(value))
        else:
            destination_dict[key] = to_dict(value)
    if len(destination_list) != 0:
        return destination_list
    else:
        return destination_dict


def process_data(data):
    flat = None
    if isinstance(data, bytes) or isinstance(data, str):
        flat = FlatterDict(json.loads(data))
    elif isinstance(data, dict):
        flat = FlatterDict(data)
    else:
        abort(500, "Data must be dict or bytes")
    delete_keys = []
    for key in flat.keys():
        if key.endswith("createdBefore"):
            flat[key] = parse(flat[key]).replace(tzinfo=timezone.utc).isoformat()
        if "bucketPolicyOnly" in key:
            new_key = key.replace("bucketPolicyOnly", "uniformBucketLevelAccess", 1)
            if flat.get(new_key) is None:
                flat[new_key] = flat[key]
            delete_keys.append(key)
        if flat[key] is None:
            if key.endswith("updated"):
                delete_keys.append(key)
        if key == "kind":
            delete_keys.append(key)
    for key in delete_keys:
        del flat[key]
    return to_dict(flat.as_dict())


def fields_to_list(fields):
    if fields is None or not isinstance(fields, str):
        return []
    fields = fields.replace(" ", "")

    def field_to_dict(field):
        if "(" not in field and ")" not in field:
            return [field]
        items = re.split(r",|\(|\)", field)
        result = []
        for item in items[1:-1]:
            result.append(items[0] + ":" + item.replace("/", ":"))
        return result

    result = list()
    for field in split_fields.findall(fields):
        result += field_to_dict(field)
    return result


def message_to_rest(
    message, kind, fields=None, list_size=0, preserving_proto_field_name=False,
):
    flat = FlatterDict(
        MessageToDict(message, preserving_proto_field_name=preserving_proto_field_name)
    )
    keep = fields_to_list(fields)
    for i in range(list_size):
        flat.setdefault("items:%d:kind" % i, kind[:-1])
    flat["kind"] = kind
    delete_key = []
    for key in flat.keys():
        if key.endswith("createdBefore"):
            flat[key] = parse(flat[key]).strftime("%Y-%m-%d")
        if key.endswith("crc32c"):
            flat[key] = encode_crc32c(flat[key])
        if len(keep) > 0:
            re_key = remove_index.sub("", key)
            if re_key not in keep:
                delete_key.append(key)
    for key in delete_key:
        del flat[key]
    return to_dict(flat.as_dict())


# rest


def extract_media(request):
    """Extract the media from a flask Request.

    To avoid race conditions when using greenlets we cannot perform I/O in the
    constructor of GcsObjectVersion, or in any of the operations that modify
    the state of the service.  Because sometimes the media is uploaded with
    chunked encoding, we need to do I/O before finishing the GcsObjectVersion
    creation. If we do this I/O after the GcsObjectVersion creation started,
    the the state of the application may change due to other I/O.

    :param request:flask.Request the HTTP request.
    :return: the full media of the request.
    :rtype: str
    """
    if request.environ.get("HTTP_TRANSFER_ENCODING", "") == "chunked":
        return request.environ.get("wsgi.input").read()
    return request.data


# error


def abort(code, message):
    flask.abort(flask.make_response(flask.jsonify(message), code))


def check_generation(generation, match, not_match, is_meta):
    generation = int(generation) if generation is not None else None
    match = int(match) if match is not None else None
    not_match = int(not_match) if not_match is not None else None
    message = "generation" if not is_meta else "metageneration"
    if generation is not None and not_match is not None and not_match == generation:
        abort(
            412,
            "Precondition Failed (%s = %s vs %s_not_match = %s)"
            % (message, generation, message, not_match),
        )
    if generation is not None and match is not None and match != generation:
        abort(
            412,
            "Precondition Failed (%s = %s vs %s_match = %s)"
            % (message, generation, message, match),
        )
    return True


def corrupt_media(media):
    """Return a randomly modified version of a string.

    :param media:bytes a string (typically some object media) to be modified.
    :return: a string that is slightly different than media.
    :rtype: str
    """
    # Deal with the boundary condition.
    if not media:
        return bytearray(random.sample("abcdefghijklmnopqrstuvwxyz", 1), "utf-8")
    return b"B" + media[1:] if media[0:1] == b"A" else b"A" + media[1:]


# buckets


GCS_BUCKETS = dict()
GCS_OBJECTS = dict()
GCS_UPLOADS = dict()


def insert_bucket(bucket):
    GCS_BUCKETS[bucket.metadata.name] = bucket
    GCS_OBJECTS[bucket.metadata.name] = dict()


def lookup_bucket(bucket_name):
    return GCS_BUCKETS.get(bucket_name, None)


def all_buckets():
    return GCS_BUCKETS.items()


def delete_bucket(bucket_name):
    del GCS_BUCKETS[bucket_name]
    del GCS_OBJECTS[bucket_name]
    delete_upload = [
        upload_id
        for upload_id, upload in GCS_UPLOADS.items()
        if upload.metadata.bucket == bucket_name
    ]
    for upload_id in delete_upload:
        del GCS_UPLOADS[upload_id]


def all_objects(bucket_name, versions):
    bucket = GCS_OBJECTS.get(bucket_name)
    if bucket is None:
        abort(404, "Bucket %s does not exist" % bucket_name)
    return [
        obj
        for object_key, obj in bucket.items()
        if versions or (not versions and object_key == obj.metadata.name)
    ]


def lookup_object(bucket_name, object_name):
    bucket = GCS_OBJECTS.get(bucket_name)
    if bucket is None:
        abort(404, "Bucket %s does not exist" % bucket_name)
    return bucket.get(object_name)


def delete_object(bucket_name, object_name):
    # TODO(vnvo2409): updated and deleted time
    bucket = GCS_BUCKETS.get(bucket_name)
    if bucket is None:
        abort(404, "Bucket %s does not exist" % bucket_name)
    obj = GCS_OBJECTS[bucket_name].get(object_name)
    if obj is not None and bucket.metadata.versioning.enabled:
        GCS_OBJECTS[bucket_name][
            obj.metadata.name + "#" + str(obj.metadata.generation)
        ] = obj
    return GCS_OBJECTS[bucket_name].pop(object_name, None)


def insert_object(bucket_name, obj):
    bucket = GCS_OBJECTS.get(bucket_name)
    if bucket is None:
        abort(404, "Bucket %s does not exist" % bucket_name)
    delete_object(bucket_name, obj.metadata.name)
    GCS_OBJECTS[bucket_name][obj.metadata.name] = obj


def check_object_generation(bucket_name, object_name, args):
    obj = lookup_object(bucket_name, object_name)
    generation = obj.metadata.generation if obj is not None else 0
    generation_match = None
    generation_not_match = None
    if isinstance(args, Message):
        generation_match = (
            str(args.if_generation_match.value)
            if args.HasField("if_generation_match")
            else None
        )
        generation_not_match = (
            str(args.if_generation_not_match.value)
            if args.HasField("if_generation_not_match")
            else None
        )
    elif args is not None:
        generation_match = args.get("ifGenerationMatch", None)
        generation_not_match = args.get("ifGenerationNotMatch", None)
    check_generation(generation, generation_match, generation_not_match, False)
    metageneration = obj.metadata.metageneration if obj is not None else None
    metageneration_match = None
    metageneration_not_match = None
    if isinstance(args, Message):
        metageneration_match = (
            str(args.if_metageneration_match.value)
            if args.HasField("if_metageneration_match")
            else None
        )
        metageneration_not_match = (
            str(args.if_metageneration_not_match.value)
            if args.HasField("if_metageneration_not_match")
            else None
        )
    elif args is not None:
        metageneration_match = args.get("ifMetagenerationMatch", None)
        metageneration_not_match = args.get("ifMetagenerationNotMatch", None)
    check_generation(
        metageneration, metageneration_match, metageneration_not_match, True
    )
    return obj


def lookup_upload(upload_id):
    return GCS_UPLOADS.get(upload_id)


def delete_upload(upload_id):
    GCS_UPLOADS.pop(upload_id, None)


def insert_upload(upload):
    GCS_UPLOADS[upload.upload_id] = upload
