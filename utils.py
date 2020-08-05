import base64
import json
import re

import storage_resources_pb2 as resources

from flatdict import FlatterDict
from google.iam.v1 import policy_pb2
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


def ValidateBucketName(bucket_name):
    valid = True
    if "." in bucket_name:
        valid &= len(bucket_name) <= 222
        valid &= all([len(part) <= 63 for part in bucket_name.split(".")])
    else:
        valid &= len(bucket_name) <= 63
    valid &= re.match("^[a-z0-9][a-z0-9._\\-]+[a-z0-9]$", bucket_name) is not None
    valid &= not bucket_name.startswith("goog")
    valid &= re.search("g[0o][0o]g[1l][e3]", bucket_name) is None
    valid &= (
        re.match("^[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}$", bucket_name)
        is None
    )
    return valid


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


def InsertObjectDefaultACL(bucket, entity, role):
    bucket.default_object_acl.append(
        resources.ObjectAccessControl(bucket=bucket.name, role=role, entity=entity)
    )


def InsertBucketIamPolicy(bucket, bindings):
    role_mapping = {
        "READER": "roles/storage.legacyBucketReader",
        "WRITER": "roles/storage.legacyBucketWriter",
        "OWNER": "roles/storage.legacyBucketOwner",
    }
    copy_of_bindings = bindings.copy()
    for entry in bucket.acl:
        legacy_role = entry.role
        if legacy_role is None or entry.entity is None:
            return "Invalid ACL entry", 500
        role = role_mapping.get(legacy_role)
        if role is None:
            return "Invalid legacy role %s" % legacy_role, 500
        found = False
        members = [entry.entity]
        for binding in copy_of_bindings:
            if binding.role == role and not binding.condition:
                found = True
                for member in members:
                    binding.members.append(member)
                break
        if not found:
            copy_of_bindings.append(policy_pb2.Binding(role=role, members=members))
    return (
        policy_pb2.Policy(
            version=1,
            bindings=copy_of_bindings,
            etag=base64.b64encode(bytearray("etag-0", "utf-8")),
        ),
        200,
    )


def make_bucket(metadata):
    InsertBucketACL(metadata, "project-owners-123456789", "OWNER")
    InsertBucketACL(metadata, "project-editors-123456789", "OWNER")
    InsertBucketACL(metadata, "project-viewers-123456789", "READER")
    InsertObjectDefaultACL(metadata, "project-owners-123456789", "OWNER")
    InsertObjectDefaultACL(metadata, "project-editors-123456789", "OWNER")
    InsertObjectDefaultACL(metadata, "project-viewers-123456789", "READER")
    return {"metadata": metadata, "notification": [], "iam_policy": None}


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


def InsertNotification(bucket_name, notification):
    InsertNotification.counter += 1
    bucket = LookupBucket(bucket_name)
    if bucket is None:
        return "Bucket %s does not exist" % bucket_name, 404
    nofication_id = "notification-%s" % str(InsertNotification.counter)
    notification.id = nofication_id
    bucket["notification"].append(notification)
    return notification, 200


InsertNotification.counter = 0


def ListNotification(bucket_name):
    bucket = LookupBucket(bucket_name)
    if bucket is None:
        return "Bucket %s does not exist" % bucket_name, 404
    return bucket["notification"], 200


def GetBucketIamPolicy(bucket_name):
    bucket = LookupBucket(bucket_name)
    if bucket is None:
        return "Bucket %s does not exist" % bucket_name, 404
    if bucket["iam_policy"] is None:
        result, code = InsertBucketIamPolicy(bucket["metadata"], [])
        if code != 200:
            return result, code
        bucket["iam_policy"] = result
    return bucket["iam_policy"], 200


def SetBucketIamPolicy(bucket_name, policy):
    SetBucketIamPolicy.counter += 1
    bucket = LookupBucket(bucket_name)
    if bucket is None:
        return "Bucket %s does not exist" % bucket_name, 404
    if bucket["iam_policy"] is None:
        bucket["iam_policy"] = policy
    else:
        bucket["iam_policy"].CopyFrom(policy)
    bucket["iam_policy"].etag = base64.b64encode(
        bytearray("etag-%d" % SetBucketIamPolicy.counter, "utf-8")
    )
    return bucket["iam_policy"], 200


SetBucketIamPolicy.counter = 0
