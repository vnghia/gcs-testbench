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

import os

import storage_resources_pb2 as resources
from common import error

PROJECT_ID = os.getenv("GOOGLE_CLOUD_CPP_STORAGE_TEST_PROJECT_ID", "123456789")


# Extract


def extract_predefined_acl(request, is_destination, context):
    if context is not None:
        extract_field = (
            "predefined_acl" if not is_destination else "destination_predefined_acl"
        )
        return getattr(request, extract_field, None)
    else:
        extract_field = (
            "predefinedAcl" if not is_destination else "destinationPredefinedAcl"
        )
        return request.args.get(extract_field, "")


def extract_predefined_doacl(request, context):
    return (
        request.args.get("predefinedDefaultObjectAcl", "")
        if context is None
        else request.predefined_default_object_acl
    )


# Entity


def project_entity(team):
    return "project-%s-%s" % (team, PROJECT_ID)


def object_entity(team):
    return "object-%s-%s" % (team, PROJECT_ID)


# ID


def entity_id(entity):
    return "%s-id-%s" % (entity, PROJECT_ID)


# Email


def entity_email(entity):
    if entity.startswith("user-"):
        return entity[len("user-") :]
    else:
        return "%s.%s@google.com" % (entity, PROJECT_ID)


# BucketAccessControl


def bucket_acl(bucket, role, context):
    return bucket_entity_acl(bucket, None, role, context)


def bucket_entity_acl(bucket, entity, role, context):
    acl = resources.BucketAccessControl()
    if role == "OWNER":
        acl.entity = project_entity("owners") if entity is None else entity
        acl.project_team.team = "owners"
    elif role == "WRITER":
        acl.entity = project_entity("editors") if entity is None else entity
        acl.project_team.team = "editors"
    elif role == "READER":
        acl.entity = project_entity("editors") if entity is None else entity
        acl.project_team.team = "viewers"
    else:
        error.abort(412, "Role %s is invalid." % role, context)
    acl.role = role
    acl.bucket = bucket
    acl.entity_id = entity_id(acl.entity)
    acl.email = entity_email(acl.entity)
    acl.id = "%s/acl/%s" % (acl.bucket, acl.entity_id)
    acl.etag = acl.id
    acl.project_team.project_number = PROJECT_ID
    return acl


def bucket_predefined_acls(bucket, predefined_acl, context):
    acls = []
    if predefined_acl == "authenticatedRead" or predefined_acl == 1:
        acls.append(bucket_acl(bucket, "OWNER", context))
        acls.append(
            bucket_entity_acl(bucket, "allAuthenticatedUsers", "READER", context)
        )
    elif predefined_acl == "private" or predefined_acl == 2:
        acls.append(bucket_acl(bucket, "OWNER", context))
    elif predefined_acl == "projectPrivate" or predefined_acl == 3:
        acls.append(bucket_acl(bucket, "OWNER", context))
        acls.append(bucket_acl(bucket, "READER", context))
        acls.append(bucket_acl(bucket, "WRITER", context))
    elif predefined_acl == "publicRead" or predefined_acl == 4:
        acls.append(bucket_acl(bucket, "OWNER", context))
        acls.append(bucket_entity_acl(bucket, "allUsers", "READER", context))
    elif predefined_acl == "publicReadWrite" or predefined_acl == 5:
        acls.append(bucket_acl(bucket, "OWNER", context))
        acls.append(bucket_entity_acl(bucket, "allUsers", "WRITER", context))
    return acls


def bucket_project_doacl(bucket, role, context):
    return bucket_entity_doacl(bucket, None, role, context)


def bucket_object_doacl(bucket, role, context):
    team = ""
    if role == "OWNER":
        team = "owners"
    elif role == "READER":
        team = "viewers"
    elif role == "WRITER":
        team = "editors"
    else:
        error.abort(412, 412, "Role %s is invalid." % role, context)
    return bucket_entity_doacl(bucket, object_entity(team), role, context)


def bucket_entity_doacl(bucket, entity, role, context):
    acl = resources.ObjectAccessControl()
    if role == "OWNER":
        acl.entity = project_entity("owners") if entity is None else entity
        acl.project_team.team = "owners"
    elif role == "READER":
        acl.entity = project_entity("viewers") if entity is None else entity
        acl.project_team.team = "viewers"
    else:
        error.abort(412, "Role %s is invalid." % role, context)
    acl.role = role
    acl.entity_id = entity_id(acl.entity)
    acl.email = entity_email(acl.entity)
    acl.etag = "%s/acl/%s" % (bucket, acl.entity_id)
    acl.project_team.project_number = PROJECT_ID
    return acl


def bucket_predefined_doacls(bucket, predefined_doacl, context):
    acls = []
    if predefined_doacl == "authenticatedRead" or predefined_doacl == 1:
        acls.append(bucket_object_doacl(bucket, "OWNER", context))
        acls.append(
            bucket_entity_doacl(bucket, "allAuthenticatedUsers", "READER", context)
        )
    elif predefined_doacl == "bucketOwnerFullControl" or predefined_doacl == 2:
        acls.append(bucket_object_doacl(bucket, "OWNER", context))
        acls.append(bucket_project_doacl(bucket, "OWNER", context))
    elif predefined_doacl == "bucketOwnerRead" or predefined_doacl == 3:
        acls.append(bucket_object_doacl(bucket, "OWNER", context))
        acls.append(
            bucket_entity_doacl(bucket, project_entity("owners"), "READER", context)
        )
    elif predefined_doacl == "private" or predefined_doacl == 4:
        acls.append(bucket_object_doacl(bucket, "OWNER", context))
    elif predefined_doacl == "projectPrivate" or predefined_doacl == 5:
        acls.append(bucket_object_doacl(bucket, "OWNER", context))
        acls.append(bucket_project_doacl(bucket, "OWNER", context))
        acls.append(bucket_project_doacl(bucket, "READER", context))
    elif predefined_doacl == "publicRead" or predefined_doacl == 6:
        acls.append(bucket_object_doacl(bucket, "OWNER", context))
        acls.append(bucket_entity_doacl(bucket, "allUsers", "READER", context))
    return acls
