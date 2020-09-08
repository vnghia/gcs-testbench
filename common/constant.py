import re

content_range_split = re.compile(r"bytes (\*|[0-9]+-[0-9]+)\/(\*|[0-9]+)")

KIND_BUCKET_ACL = "storage#bucketAccessControl"
KIND_OBJECT_ACL = "storage#objectAccessControl"
KIND_POLICY = "storage#policy"
KIND_NOTIFICATION = "storage#notification"
