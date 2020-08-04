import re

snake_case = re.compile(r"(?<!^)(?=[A-Z])")


def ToSnakeCase(source):
    return snake_case.sub("_", source).lower()


# def ToCamelCase(source):
#     components = source.split("_")
#     return components[0] + "".join(x.title() for x in components[1:])


def ToProtoDict(source):
    destination = {}
    for key in source:
        if isinstance(source[key], dict):
            result = ToProtoDict(source[key])
            destination[ToSnakeCase(key)] = result
        else:
            destination[ToSnakeCase(key)] = source[key]
    return destination


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
