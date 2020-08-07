import base64
import json
import re
from datetime import timezone
from random import random

import flask
from dateutil.parser import parse
from flatdict import FlatterDict
from google.protobuf.json_format import MessageToDict, ParseDict

import storage_resources_pb2 as resources


# regex
remove_index = re.compile(r":[0-9]+|^[0-9]+")
split_fields = re.compile(r"[a-zA-Z0-9]*\(.*\)|[a-zA-Z0-9]+")

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
    flat = FlatterDict(json.loads(data))
    delete_keys = []
    for key in flat.keys():
        if key.endswith("createdBefore"):
            flat[key] = parse(flat[key]).replace(tzinfo=timezone.utc).isoformat()
        if "bucketPolicyOnly" in key:
            new_key = key.replace("bucketPolicyOnly", "uniformBucketLevelAccess", 1)
            if flat.get(new_key) is None:
                flat[new_key] = flat[key]
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
    message, kind, fields=None, list_size=0, preserving_proto_field_name=False
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
        if len(keep) > 0:
            re_key = remove_index.sub("", key)
            if re_key not in keep:
                delete_key.append(key)
    for key in delete_key:
        del flat[key]
    return to_dict(flat.as_dict())


# etag


def compute_etag(content):
    return base64.b64encode(bytearray(content, "utf-8"))


def random_etag(content=""):
    return compute_etag(content + str(random()))


# error


def abort(code, message):
    flask.abort(flask.make_response(flask.jsonify(message), code))


# buckets


GCS_BUCKETS = dict()


def insert_bucket(bucket):
    GCS_BUCKETS[bucket.metadata.name] = bucket


def lookup_bucket(bucket_name):
    return GCS_BUCKETS.get(bucket_name, None)


def all_buckets():
    return GCS_BUCKETS.items()


def delete_bucket(bucket_name):
    del GCS_BUCKETS[bucket_name]
