import re

from flatdict import FlatterDict

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
    flat = ToSnakeCaseFlat(payload)
    created_before = flat.get("lifecycle:rule:0:condition:created_before")
    if created_before is not None:
        created_before += "T00:00:00+00:00"
        flat["lifecycle:rule:0:condition:created_before"] = created_before
    return ToBuiltinDict(flat.as_dict())


def ToRestDict(payload):
    flat = FlatterDict(payload)
    created_before = flat.get("lifecycle:rule:0:condition:createdBefore")
    if created_before is not None:
        flat["lifecycle:rule:0:condition:createdBefore"] = created_before.replace(
            "T00:00:00Z", ""
        )
    return ToBuiltinDict(flat.as_dict())


# def ToRestDict(source):
#     destination = {}
#     for key in source:
#         if isinstance(source[key], dict):
#             result = ToProtoDict(source[key])
#             destination[ToCamelCase(key)] = result
#         else:
#             destination[ToCamelCase(key)] = source[key]
#     return destination


GCS_BUCKETS = dict()


def make_bucket(metadata):
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
