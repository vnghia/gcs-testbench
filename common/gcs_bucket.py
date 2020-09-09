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

import datetime
import json
import re

from google.iam.v1 import policy_pb2
from google.protobuf.field_mask_pb2 import FieldMask
from google.protobuf.json_format import ParseDict

import scalpl
import storage_resources_pb2 as resources
from common import error, gcs_acl, hash_utils, process


class Bucket:
    def __init__(self, metadata, notifications, iam_policy):
        self.metadata = metadata
        self.notifications = notifications
        self.iam_policy = iam_policy

    # === BUCKET === #

    @classmethod
    def __validate_bucket_name(cls, bucket_name, context):
        valid = True
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

    @classmethod
    def __upsert_predefined_acl_and_doacl(cls, request, metadata, set_default, context):
        predefined_acl = gcs_acl.extract_predefined_acl(request, False, context)
        if predefined_acl == "" or predefined_acl == 0:
            if set_default:
                predefined_acl = "private"
        elif metadata.iam_configuration.uniform_bucket_level_access.enabled:
            error.abort(400, "Bad Requests: Predefined ACL is not allowed.", context)
        acls = gcs_acl.bucket_predefined_acls(metadata.name, predefined_acl, context)
        for acl in acls:
            cls.__upsert_acl(metadata, acl, None, False, context)

        predefined_doacl = gcs_acl.extract_predefined_doacl(request, context)
        if predefined_doacl == "" or predefined_doacl == 0:
            if set_default:
                predefined_doacl = "private"
        elif metadata.iam_configuration.uniform_bucket_level_access.enabled:
            error.abort(
                400,
                "Bad Requests: Predefined Default Object ACL is not allowed.",
                context,
            )
        doacls = gcs_acl.bucket_predefined_doacls(
            metadata.name, predefined_doacl, context
        )
        for doacl in doacls:
            cls.__upsert_doacl(metadata, doacl, None, False, context)

    @classmethod
    def __preprocess_metadata(cls, data):
        proxy = scalpl.Cut(data)
        keys = process.nested_key(data)
        proxy.pop("iamConfiguration.bucketPolicyOnly", None)
        for key in keys:
            if key.endswith("createdBefore"):
                proxy[key] = proxy[key] + "T00:00:00Z"
        return proxy.data

    @classmethod
    def __update_metadata(cls, source, destination, update_mask):
        update_mask.MergeMessage(source, destination, True, True)
        if destination.versioning.enabled:
            destination.metageneration += 1
        destination.updated.FromDatetime(datetime.datetime.now())

    @classmethod
    def init(cls, request, context):
        metadata = (
            request.bucket
            if context is not None
            else ParseDict(
                cls.__preprocess_metadata(json.loads(request.data)), resources.Bucket()
            )
        )
        cls.__validate_bucket_name(metadata.name, context)
        time_created = datetime.datetime.now()
        metadata.time_created.FromDatetime(time_created)
        metadata.updated.FromDatetime(time_created)
        metadata.id = metadata.name
        metadata.owner.entity = gcs_acl.project_entity("owners")
        metadata.owner.entity_id = gcs_acl.entity_id(metadata.owner.entity)
        cls.__upsert_predefined_acl_and_doacl(request, metadata, True, context)
        iam_policy = cls.__compute_iam_policy(metadata, context)
        return Bucket(metadata, [], iam_policy)

    def patch(self, request, context):
        update_mask = FieldMask()
        metadata = None
        if context is not None:
            metadata = request.metadata
            if not request.HasField("update_mask"):
                error.abort(412, "PatchBucketRequest does not have field update_mask.")
            paths = [field[0].name for field in metadata.ListFields()]
            if paths != request.update_mask.paths:
                error.abort(412, "PatchBucketRequest does not match update_mask.")
            update_mask = request.update_mask
        else:
            data = json.loads(request.data)
            if "labels" in data:
                if data["labels"] is None:
                    self.metadata.labels.clear()
                else:
                    for key, value in data["labels"].items():
                        if value is None:
                            self.metadata.labels.pop(key, None)
                        else:
                            self.metadata.labels[key] = value
            data.pop("labels", None)
            data = self.__preprocess_metadata(data)
            metadata = ParseDict(data, resources.Bucket())
            paths = ",".join(data.keys())
            update_mask.FromJsonString(paths)
        self.__update_metadata(metadata, self.metadata, update_mask)
        self.__upsert_predefined_acl_and_doacl(request, self.metadata, False, context)

    def update(self, request, context):
        metadata = (
            request.metadata
            if context is not None
            else ParseDict(
                self.__preprocess_metadata(json.loads(request.data)),
                resources.Bucket(),
            )
        )
        update_mask = FieldMask(
            paths=[
                "acl",
                "default_object_acl",
                "lifecycle",
                "cors",
                "storage_class",
                "default_event_based_hold",
                "labels",
                "website",
                "versioning",
                "logging",
                "encryption",
                "billing",
                "retention_policy",
                "location_type",
                "iam_configuration",
            ]
        )
        self.__update_metadata(metadata, self.metadata, update_mask)
        self.__upsert_predefined_acl_and_doacl(request, self.metadata, False, context)

    # === ACL === #

    @classmethod
    def __search_acl(cls, metadata, entity):
        for i in range(len(metadata.acl)):
            if metadata.acl[i].entity == entity:
                return i

    @classmethod
    def __upsert_acl(cls, metadata, acl, update_mask, update_only, context):
        index = cls.__search_acl(metadata, acl.entity)
        if index is not None:
            if update_mask is None:
                update_mask = FieldMask(
                    paths=resources.BucketAccessControl.DESCRIPTOR.fields_by_name.keys()
                )
            update_mask.MergeMessage(acl, metadata.acl[index])
            return metadata.acl[index]
        elif update_only:
            error.abort(404, "ACL %s does not exist" % acl.entity, context)
        else:
            metadata.acl.append(acl)
            return acl

    def __get_acl(self, entity, context):
        index = self.__search_acl(self.metadata, entity)
        if index is None:
            error.abort(404, "ACL %s does not exist" % entity, context)
        return index

    def get_acl(self, entity, context):
        index = self.__get_acl(entity, context)
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
        return self.__upsert_acl(self.metadata, acl, None, False, context)

    def update_acl(self, entity, request, context):
        if self.metadata.iam_configuration.uniform_bucket_level_access.enabled:
            error.abort(400, "Bad Requests: Update ACL is not allowed.", context)
        acl = (
            request.bucket_access_control
            if context is not None
            else ParseDict(json.loads(request.data), resources.BucketAccessControl())
        )
        acl.entity = entity
        return self.__upsert_acl(self.metadata, acl, None, True, context)

    def patch_acl(self, entity, request, context):
        if self.metadata.iam_configuration.uniform_bucket_level_access.enabled:
            error.abort(400, "Bad Requests: Patch ACL is not allowed.", context)
        update_mask = FieldMask()
        acl = None
        if context is not None:
            acl = request.bucket_access_control
            update_mask = request.update_mask
        else:
            data = json.loads(request.data)
            acl = ParseDict(data, resources.BucketAccessControl())
            paths = ",".join(data.keys())
            update_mask.FromJsonString(paths)
        acl.entity = entity
        return self.__upsert_acl(self.metadata, acl, update_mask, True, context)

    def delete_acl(self, entity, context):
        index = self.__get_acl(entity, context)
        del self.metadata.acl[index]

    # === DEFAULT OBJECT ACL === #

    @classmethod
    def __search_doacl(cls, metadata, entity):
        for i in range(len(metadata.default_object_acl)):
            if metadata.default_object_acl[i].entity == entity:
                return i

    @classmethod
    def __upsert_doacl(cls, metadata, doacl, update_mask, update_only, context):
        index = cls.__search_doacl(metadata, doacl.entity)
        if index is not None:
            if update_mask is None:
                update_mask = FieldMask(
                    paths=resources.ObjectAccessControl.DESCRIPTOR.fields_by_name.keys()
                )
            update_mask.MergeMessage(doacl, metadata.default_object_acl[index])
            return metadata.default_object_acl[index]
        elif update_only:
            error.abort(
                404, "Default Object ACL %s does not exist" % doacl.entity, context
            )
        else:
            metadata.default_object_acl.append(doacl)
            return doacl

    def __get_doacl(self, entity, context):
        index = self.__search_doacl(self.metadata, entity)
        if index is None:
            error.abort(404, "Default Object ACL %s does not exist" % entity, context)
        return index

    def get_doacl(self, entity, context):
        index = self.__get_doacl(entity, context)
        return self.metadata.default_object_acl[index]

    def insert_doacl(self, request, context):
        if self.metadata.iam_configuration.uniform_bucket_level_access.enabled:
            error.abort(
                400, "Bad Requests: Insert Default Object ACL is not allowed.", context
            )
        doacl = None
        if context is None:
            payload = json.loads(request.data)
            doacl = gcs_acl.bucket_entity_doacl(
                self.metadata.name, payload["entity"], payload["role"], context
            )
        else:
            doacl = gcs_acl.bucket_entity_doacl(
                self.metadata.name,
                request.object_access_control.entity,
                request.object_access_control.role,
                context,
            )
        return self.__upsert_doacl(self.metadata, doacl, None, False, context)

    def update_doacl(self, entity, request, context):
        if self.metadata.iam_configuration.uniform_bucket_level_access.enabled:
            error.abort(
                400,
                "Bad Requests: Update Default Object ACL is not allowed.",
                context,
            )
        doacl = (
            request.object_access_control
            if context is not None
            else ParseDict(
                json.loads(request.data),
                resources.ObjectAccessControl(),
            )
        )
        doacl.entity = entity
        return self.__upsert_doacl(self.metadata, doacl, None, True, context)

    def patch_doacl(self, entity, request, context):
        if self.metadata.iam_configuration.uniform_bucket_level_access.enabled:
            error.abort(
                400,
                "Bad Requests: Patch Default Object ACL is not allowed.",
                context,
            )
        update_mask = FieldMask()
        doacl = None
        if context is not None:
            doacl = request.bucket_access_control
            update_mask = request.update_mask
        else:
            data = json.loads(request.data)
            doacl = ParseDict(data, resources.ObjectAccessControl())
            paths = ",".join(data.keys())
            update_mask.FromJsonString(paths)
        doacl.entity = entity
        return self.__upsert_doacl(self.metadata, doacl, update_mask, True, context)

    def delete_doacl(self, entity, context):
        index = self.__get_doacl(entity, context)
        del self.metadata.default_object_acl[index]

    # === NOTIFICATIONS === #

    def __get_notification(self, notification_id, context):
        for i in range(len(self.notifications)):
            if self.notifications[i].id == notification_id:
                return i
        error.abort(404, "Notification %s does not exist" % notification_id, context)

    def insert_notification(self, request, context):
        notification = (
            request.notification
            if context is not None
            else ParseDict(json.loads(request.data), resources.Notification())
        )
        notification.id = hash_utils.random_str("notification-")
        self.notifications.append(notification)
        return notification

    def get_notification(self, notification_id, context):
        index = self.__get_notification(notification_id, context)
        return self.notifications[index]

    def delete_notification(self, notification_id, context):
        index = self.__get_notification(notification_id, context)
        del self.notifications[index]

    # === IAM POLICY === #

    @classmethod
    def __compute_iam_policy(cls, metadata, context):
        role_mapping = {
            "READER": "roles/storage.legacyBucketReader",
            "WRITER": "roles/storage.legacyBucketWriter",
            "OWNER": "roles/storage.legacyBucketOwner",
        }
        bindings = []
        for entry in metadata.acl:
            legacy_role = entry.role
            if legacy_role is None or entry.entity is None:
                error.abort(500, "Invalid ACL entry", context)
            role = role_mapping.get(legacy_role)
            if role is None:
                error.abort(500, "Invalid legacy role %s" % legacy_role, context)
            bindings.append(policy_pb2.Binding(role=role, members=[entry.entity]))
        return policy_pb2.Policy(
            version=1,
            bindings=bindings,
            etag=hash_utils.random_bytes("iam_policy"),
        )

    def set_iam_policy(self, request, context):
        policy = None
        if context is None:
            data = json.loads(request.data)
            data.pop("kind", None)
            policy = ParseDict(data, policy_pb2.Policy())
        else:
            policy = request.iam_request.policy
        self.iam_policy = policy
        self.iam_policy.etag = hash_utils.random_bytes("iam_policy")
        return self.iam_policy

    # === RESPONSE UTILS === #

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
