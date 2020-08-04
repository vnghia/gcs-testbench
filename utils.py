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
        if isinstance(source[key], list):
            for x in range(len(source[key])):
                if isinstance(source[key][x], dict):
                    source[key][x] = ToProtoDict(source[key][x])
            destination[ToSnakeCase(key)] = source[key]
        elif isinstance(source[key], dict):
            result = ToProtoDict(source[key])
            destination[ToSnakeCase(key)] = result
        else:
            destination[ToSnakeCase(key)] = source[key]
    return destination


def FixParseTime(payload):
    if payload.get("lifecycle") is not None:
        if payload.get("lifecycle").get("rule") is not None:
            if payload.get("lifecycle").get("rule")[0].get("condition") is not None:
                if (
                    payload.get("lifecycle")
                    .get("rule")[0]
                    .get("condition")
                    .get("createdBefore")
                    is not None
                ):
                    payload.get("lifecycle").get("rule")[0].get("condition")[
                        "createdBefore"
                    ] += "T00:00:00+00:00"


def RemoveFixParseTime(payload):
    if payload.get("lifecycle") is not None:
        if payload.get("lifecycle").get("rule") is not None:
            if payload.get("lifecycle").get("rule")[0].get("condition") is not None:
                if (
                    payload.get("lifecycle")
                    .get("rule")[0]
                    .get("condition")
                    .get("createdBefore")
                    is not None
                ):
                    payload.get("lifecycle").get("rule")[0].get("condition")[
                        "createdBefore"
                    ] = (
                        payload.get("lifecycle")
                        .get("rule")[0]
                        .get("condition")["createdBefore"]
                        .replace("T00:00:00Z", "")
                    )
    return payload


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
