import base64
import json
import re
import flask

import storage_resources_pb2 as resources

from flatdict import FlatterDict
from google.protobuf.json_format import MessageToDict, ParseDict

snake_case = re.compile(r"(?<!^)(?=[A-Z])")


def ToSnakeCase(source):
    return snake_case.sub("_", source).lower()


def ToSnakeCaseFlat(source):
    destination = FlatterDict()
    source = FlatterDict(source)
    for key in source:
        destination[ToSnakeCase(key)] = source[key]
    return destination


def ToBuiltinDict(source):
    if not isinstance(source, dict):
        return source
    destination_dict = dict()
    destination_list = list()
    for key, value in source.items():
        if key.isdecimal():
            destination_list.append(ToBuiltinDict(value))
        else:
            destination_dict[key] = ToBuiltinDict(value)
    if len(destination_list) != 0:
        return destination_list
    else:
        return destination_dict


def ToProtoDict(payload):
    payload = json.loads(payload)
    flat = ToSnakeCaseFlat(payload)
    created_before = flat.get("lifecycle:rule:0:condition:created_before")
    if created_before is not None:
        created_before += "T00:00:00+00:00"
        flat["lifecycle:rule:0:condition:created_before"] = created_before
    flat.pop("iam_configuration:bucket_policy_only:enabled", None)
    flat.pop("kind", None)
    return ToBuiltinDict(flat.as_dict())


def ToRestDict(payload, kind=None):
    payload = MessageToDict(payload)
    flat = FlatterDict(payload)
    if kind is not None:
        flat["kind"] = kind
    created_before = flat.get("lifecycle:rule:0:condition:createdBefore")
    if created_before is not None:
        flat["lifecycle:rule:0:condition:createdBefore"] = created_before.replace(
            "T00:00:00Z", ""
        )
    return ToBuiltinDict(flat.as_dict())


GCS_BUCKETS = dict()


def insert_bucket(bucket):
    GCS_BUCKETS[bucket.metadata.name] = bucket


def lookup_bucket(bucket_name):
    return GCS_BUCKETS.get(bucket_name, None)


def all_buckets():
    return GCS_BUCKETS.items()


def delete_bucket(bucket_name):
    del GCS_BUCKETS[bucket_name]


def compute_etag(content):
    return base64.b64encode(bytearray(content, "utf-8"))


def abort(code, message):
    flask.abort(flask.make_response(flask.jsonify(message), code))
