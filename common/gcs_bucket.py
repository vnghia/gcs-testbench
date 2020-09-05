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

import json
import re

from google.iam.v1 import policy_pb2
from google.protobuf.json_format import ParseDict

import storage_resources_pb2 as resources
from common import error, gcs_acl, hash_utils, process


class Bucket:
    def __init__(self, request, context):
        self.metadata = (
            request.bucket
            if context is not None
            else ParseDict(process.process_data(request.data), resources.Bucket())
        )
        self.__validate_bucket_name(context)
        self.metadata.id = self.metadata.name
        self.metadata.owner.entity = gcs_acl.project_entity("owners")
        self.metadata.owner.entity_id = gcs_acl.entity_id(self.metadata.owner.entity)
        self.__update_predefined_acl_and_doacl(request, context)
        self.__init_iam_policy(context)
        self.notifications = []

    # Utils

    def __validate_bucket_name(self, context):
        valid = True
        bucket_name = self.metadata.name
        if "." in bucket_name:
            valid &= len(bucket_name) <= 222
            valid &= all([len(part) <= 63 for part in bucket_name.split(".")])
        else:
            valid &= len(bucket_name) <= 63
            valid &= (
                re.match("^[a-z0-9][a-z0-9._\\-]+[a-z0-9]$", bucket_name) is not None
            )
            valid &= not bucket_name.startswith("goog")
            valid &= re.search("g[0o][0o]g[1l][e3]", bucket_name) is None
            valid &= (
                re.match(
                    "^[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}$", bucket_name
                )
                is None
            )
        if not valid:
            error.abort(412, "Bucket name %s is invalid" % bucket_name, context)

    def __update_predefined_acl_and_doacl(self, request, context):
        predefined_acl = gcs_acl.extract_predefined_acl(request, context)
        predefined_default_object_acl = gcs_acl.extract_predefined_default_object_acl(
            request, context
        )
        self.__update_predefined_acl(predefined_acl, context)
        self.__update_predefined_default_object_acl(
            predefined_default_object_acl, context
        )

    # Bucket operations

    def __update(self, request, update_mask, context):
        metadata = (
            request.metadata
            if context is not None
            else ParseDict(process.process_data(request.data), self.metadata)
        )
        if context is not None:
            if update_mask is not None:
                update_mask.MergeMessage(metadata, self.metadata)
            else:
                self.metadata.MergeFrom(metadata)
        self.__update_predefined_acl_and_doacl(request, context)
        if self.metadata.versioning.enabled:
            self.metadata.metageneration += 1

    def patch(self, request, context):
        update_mask = None
        if context is not None:
            update_mask = (
                request.update_mask if request.HasField("update_mask") else None
            )
        self.__update(request, update_mask, context)

    def update(self, request, context):
        self.__update(request, None, context)

    # ACL

    def __update_predefined_acl(self, predefined_acl, context):
        protobuf2rest = [
            "",
            "authenticatedRead",
            "private",
            "projectPrivate",
            "publicRead",
            "publicReadWrite",
        ]
        if context is not None:
            predefined_acl = protobuf2rest[predefined_acl]
        if predefined_acl != "":
            if self.metadata.iam_configuration.uniform_bucket_level_access.enabled:
                error.abort(
                    400, "Bad Requests: Predefined ACL is not allowed.", context
                )
            if len(self.metadata.acl) != 0:
                return
        bucket = self.metadata.name
        acls = gcs_acl.bucket_predefined_acls(bucket, predefined_acl, context)
        self.metadata.acl.extend(acls)

    def __search_acl(self, entity):
        for i in range(len(self.metadata.acl)):
            if self.metadata.acl[i].entity == entity:
                return i

    def __get_index_acl(self, entity, context):
        index = self.__search_acl(entity)
        if index is None:
            error.abort(404, "Acl %s does not exist" % entity, context)
        return index

    def get_acl(self, entity, context):
        index = self.__get_index_acl(entity, context)
        return self.metadata.acl[index]

    def insert_acl(self, request, context):
        if self.metadata.iam_configuration.uniform_bucket_level_access.enabled:
            error.abort(400, "Bad Requests: Insert ACL is not allowed.", context)
        acl = None
        if context is None:
            payload = json.loads(request.data)
            acl = gcs_acl.bucket_entity_acl(
                self.metadata.name, payload["entity"], payload["role"], context
            )
        else:
            acl = request.bucket_access_control
            acl = gcs_acl.bucket_entity_acl(
                self.metadata.name,
                request.bucket_access_control.entity,
                request.bucket_access_control.role,
                context,
            )
        self.metadata.acl.append(acl)
        return acl

    def __update_acl(self, entity, request, update_mask, context):
        if self.metadata.iam_configuration.uniform_bucket_level_access.enabled:
            error.abort(400, "Bad Requests: Update/Patch ACL is not allowed.", context)
        index = self.__get_index_acl(entity, context)
        acl = (
            request.bucket_access_control
            if context is not None
            else ParseDict(process.process_data(request.data), self.metadata.acl[index])
        )
        if context is not None:
            if update_mask is not None:
                update_mask.MergeMessage(acl, self.metadata.acl[index])
            else:
                self.metadata.acl[index].MergeFrom(acl)
        return self.metadata.acl[index]

    def update_acl(self, entity, request, context):
        return self.__update_acl(entity, request, None, context)

    def patch_acl(self, entity, request, context):
        update_mask = None
        if context is not None:
            update_mask = (
                request.update_mask if request.HasField("update_mask") else None
            )
        return self.__update_acl(entity, request, update_mask, context)

    def delete_acl(self, entity, context):
        index = self.__search_acl(entity)
        if index is None:
            error.abort(404, "Acl %s does not exist" % entity, context)
        del self.metadata.acl[index]

    # Default Object ACL

    def __update_predefined_default_object_acl(
        self, predefined_default_object_acl, context
    ):
        protobuf2rest = [
            "",
            "authenticatedRead",
            "bucketOwnerFullControl",
            "bucketOwnerRead",
            "private",
            "projectPrivate",
            "publicRead",
        ]
        if context is not None:
            predefined_default_object_acl = protobuf2rest[predefined_default_object_acl]
        if predefined_default_object_acl != "":
            if self.metadata.iam_configuration.uniform_bucket_level_access.enabled:
                error.abort(
                    400,
                    "Bad Requests: Predefined Default Object ACL is not allowed.",
                    context,
                )
            if len(self.metadata.default_object_acl) != 0:
                return
        bucket = self.metadata.name
        acls = gcs_acl.bucket_predefined_default_object_acls(
            bucket, predefined_default_object_acl, context
        )
        self.metadata.default_object_acl.extend(acls)

    def __search_default_object_acl(self, entity):
        for i in range(len(self.metadata.default_object_acl)):
            if self.metadata.default_object_acl[i].entity == entity:
                return i

    def __get_index_default_object_acl(self, entity, context):
        index = self.__search_default_object_acl(entity)
        if index is None:
            error.abort(404, "Default Object Acl %s does not exist" % entity, context)
        return index

    def get_default_object_acl(self, entity, context):
        index = self.__get_index_default_object_acl(entity, context)
        return self.metadata.default_object_acl[index]

    def insert_default_object_acl(self, request, context):
        if self.metadata.iam_configuration.uniform_bucket_level_access.enabled:
            error.abort(
                400, "Bad Requests: Insert Default Object ACL is not allowed.", context
            )
        acl = None
        if context is None:
            payload = json.loads(request.data)
            acl = gcs_acl.bucket_entity_default_object_acl(
                self.metadata.name, payload["entity"], payload["role"], context
            )
        else:
            acl = gcs_acl.bucket_entity_default_object_acl(
                self.metadata.name,
                request.object_access_control.entity,
                request.object_access_control.role,
                context,
            )
        self.metadata.default_object_acl.append(acl)
        return acl

    def __update_default_object_acl(self, entity, request, update_mask, context):
        if self.metadata.iam_configuration.uniform_bucket_level_access.enabled:
            error.abort(
                400,
                "Bad Requests: Update/Patch Default Object ACL is not allowed.",
                context,
            )
        index = self.__get_index_default_object_acl(entity, context)
        acl = (
            request.object_access_control
            if context is not None
            else ParseDict(
                process.process_data(request.data),
                self.metadata.default_object_acl[index],
            )
        )
        if context is not None:
            if update_mask is not None:
                update_mask.MergeMessage(acl, self.metadata.default_object_acl[index])
            else:
                self.metadata.default_object_acl[index].MergeFrom(acl)
        return self.metadata.default_object_acl[index]

    def update_default_object_acl(self, entity, request, context):
        return self.__update_default_object_acl(entity, request, None, context)

    def patch_default_object_acl(self, entity, request, context):
        update_mask = None
        if context is not None:
            update_mask = (
                request.update_mask if request.HasField("update_mask") else None
            )
        return self.__update_default_object_acl(entity, request, update_mask, context)

    def delete_default_object_acl(self, entity, context):
        index = self.__search_default_object_acl(entity)
        if index is None:
            error.abort(404, "Default Object Acl %s does not exist" % entity, context)
        del self.metadata.default_object_acl[index]

    # Notification

    def __get_notification(self, notification_id):
        for i in range(len(self.notifications)):
            if self.notifications[i].id == notification_id:
                return i

    def __get_index_notification(self, notification_id, context):
        index = self.__get_notification(notification_id)
        if index is None:
            error.abort(
                404, "Notification %s does not exist" % notification_id, context
            )
        return index

    def insert_notification(self, request, context):
        notification = (
            request.notification
            if context is not None
            else ParseDict(process.process_data(request.data), resources.Notification())
        )
        notification.id = hash_utils.random_str("notification-")
        self.notifications.append(notification)
        return notification

    def get_notification(self, notification_id, context):
        index = self.__get_index_notification(notification_id, context)
        return self.notifications[index]

    def delete_notification(self, notification_id, context):
        index = self.__get_index_notification(notification_id, context)
        del self.notifications[index]

    # IAM Policy

    def __init_iam_policy(self, context):
        role_mapping = {
            "READER": "roles/storage.legacyBucketReader",
            "WRITER": "roles/storage.legacyBucketWriter",
            "OWNER": "roles/storage.legacyBucketOwner",
        }
        bindings = []
        for entry in self.metadata.acl:
            legacy_role = entry.role
            if legacy_role is None or entry.entity is None:
                error.abort(500, "Invalid ACL entry", context)
            role = role_mapping.get(legacy_role)
            if role is None:
                error.abort(500, "Invalid legacy role %s" % legacy_role, context)
            bindings.append(policy_pb2.Binding(role=role, members=[entry.entity]))
        self.iam_policy = policy_pb2.Policy(
            version=1,
            bindings=bindings,
            etag=hash_utils.random_bytes("iam_policy"),
        )

    def set_iam_policy(self, request, context):
        policy = (
            request.iam_request.policy
            if context is not None
            else ParseDict(process.process_data(request.data), policy_pb2.Policy())
        )
        self.iam_policy = policy
        self.iam_policy.etag = hash_utils.random_bytes("iam_policy")
        return self.iam_policy

    # Reponse

    def to_rest(self, request):
        projection = "noAcl"
        if b"acl" in request.data or b"defaultObjectAcl" in request.data:
            projection = "full"
        projection = request.args.get("projection", projection)
        result = process.message_to_rest(
            self.metadata, "storage#bucket", request.args.get("fields", None)
        )
        if projection == "noAcl":
            result.pop("acl", None)
            result.pop("defaultObjectAcl", None)
            result.pop("owner", None)
        return result
