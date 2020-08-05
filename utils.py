import json
import re

import storage_resources_pb2 as resources

from flatdict import FlatterDict
from google.protobuf.json_format import MessageToDict, ParseDict

snake_case = re.compile(r"(?<!^)(?=[A-Z])")


def ToSnakeCase(source):
    return snake_case.sub("_", source).lower()


# def ToCamelCase(source):
#     components = source.split("_")
#     return components[0] + "".join(x.title() for x in components[1:])


# def ToProtoDict(source):
#     destination = {}
#     for key in source:
#         if isinstance(source[key], list):
#             for x in range(len(source[key])):
#                 if isinstance(source[key][x], dict):
#                     source[key][x] = ToProtoDict(source[key][x])
#             destination[ToSnakeCase(key)] = source[key]
#         elif isinstance(source[key], dict):
#             result = ToProtoDict(source[key])
#             destination[ToSnakeCase(key)] = result
#         else:
#             destination[ToSnakeCase(key)] = source[key]
#     return destination


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


def FilterMessage(message, fields):
    dump = MessageToDict(message, preserving_proto_field_name=True)
    payload = dict()
    for key in fields:
        payload[ToSnakeCase(key)] = dump.get(ToSnakeCase(key))
    message.Clear()
    return ParseDict(payload, message, ignore_unknown_fields=True)


GCS_BUCKETS = dict()


def InsertBucketACL(bucket, entity, role):
    bucket.acl.append(
        resources.BucketAccessControl(bucket=bucket.name, role=role, entity=entity)
    )


def make_bucket(metadata):
    InsertBucketACL(metadata, "project-owners-123456789", "OWNER")
    InsertBucketACL(metadata, "project-editors-123456789", "OWNER")
    InsertBucketACL(metadata, "project-viewers-123456789", "READER")
    InsertBucketACL(metadata, "project-owners-123456789", "OWNER")
    InsertBucketACL(metadata, "project-editors-123456789", "OWNER")
    InsertBucketACL(metadata, "project-viewers-123456789", "READER")
    return {"metadata": metadata}


def InsertBucket(bucket):
    GCS_BUCKETS[bucket.name] = make_bucket(bucket)


def AllBuckets():
    return GCS_BUCKETS.items()


def LookupBucket(bucket_name):
    bucket = GCS_BUCKETS.get(bucket_name)
    return bucket


def DeleteBucket(bucket_name):
    del GCS_BUCKETS[bucket_name]


def CheckBucketPrecondition(bucket_name, request):
    bucket = LookupBucket(bucket_name)
    if bucket is None:
        return "Bucket %s does not exist" % bucket_name, 404
    metageneration = str(bucket["metadata"].metageneration)
    metageneration_match = request.args.get("ifMetagenerationMatch")
    metageneration_not_match = request.args.get("ifMetagenerationNotMatch")
    if (
        metageneration_not_match is not None
        and metageneration_not_match == metageneration
    ):
        return (
            "Precondition Failed (metageneration = %s vs metageneration_not_match = %s)"
            % (metageneration, metageneration_not_match),
            412,
        )
    if metageneration_match is not None and metageneration_match != metageneration:
        return (
            "Precondition Failed (metageneration = %s vs metageneration_match = %s)"
            % (metageneration, metageneration_match),
            412,
        )
    return bucket, 200


def UpdateBucketFromRequest(bucket, request):
    pass
