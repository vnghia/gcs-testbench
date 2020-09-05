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

import random
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
        self.iam_policy = None
        self.notification = []
        self.__init_iam_policy(context)

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

    def __init_iam_policy(self, context=None):
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
            etag=hash_utils.random_bytes("__init_iam_policy"),
        )

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

    def insert_acl(self, data, update=False):
        acl = (
            data
            if isinstance(data, resources.BucketAccessControl)
            else ParseDict(process.process_data(data), resources.BucketAccessControl())
        )
        acl.etag = hash_utils.random_bytes(acl.entity + acl.role)
        acl.id = self.metadata.name + "/" + acl.entity
        acl.bucket = self.metadata.name
        if update:
            _, index = self.lookup_acl(acl.entity)
            self.metadata.acl[index].MergeFrom(acl)
            return self.metadata.acl[index]
        else:
            self.metadata.acl.append(acl)
            return acl

    def lookup_acl(self, entity):
        for i in range(len(self.metadata.acl)):
            if self.metadata.acl[i].entity == entity:
                return self.metadata.acl[i], i
        error.abort(404, "Acl %s does not exist" % entity)

    def delete_acl(self, entity):
        _, index = self.lookup_acl(entity)
        del self.metadata.acl[index]

    def insert_default_object_acl(self, data, update=False):
        acl = (
            data
            if isinstance(data, resources.ObjectAccessControl)
            else ParseDict(process.process_data(data), resources.ObjectAccessControl())
        )
        acl.etag = hash_utils.random_bytes(acl.entity + acl.role)
        acl.id = self.metadata.name + "/" + acl.entity
        acl.bucket = self.metadata.name
        if update:
            _, index = self.lookup_default_object_acl(acl.entity)
            self.metadata.default_object_acl[index].MergeFrom(acl)
            return self.metadata.default_object_acl[index]
        else:
            self.metadata.default_object_acl.append(acl)
            return acl

    def lookup_default_object_acl(self, entity):
        for i in range(len(self.metadata.default_object_acl)):
            if self.metadata.default_object_acl[i].entity == entity:
                return self.metadata.default_object_acl[i], i
        error.abort(404, "Acl %s does not exist" % entity)

    def delete_default_object_acl(self, entity):
        _, index = self.lookup_default_object_acl(entity)
        del self.metadata.default_object_acl[index]

    def insert_notification(self, data):
        noti = (
            data
            if isinstance(data, resources.Notification)
            else ParseDict(process.process_data(data), resources.Notification())
        )
        noti.id = "notification-%s" % str(random.random())
        self.notification.append(noti)
        return noti

    def delete_notification(self, notification_id):
        _, index = self.lookup_notification(notification_id)
        del self.notification[index]

    def lookup_notification(self, notification_id):
        for i in range(len(self.notification)):
            if self.notification[i].id == notification_id:
                return self.notification[i], i
        error.abort(404, "Notification %s does not exist" % notification_id)

    def insert_iam_policy(self, data):
        policy = (
            data
            if isinstance(data, policy_pb2.Policy)
            else ParseDict(process.process_data(data), policy_pb2.Policy())
        )
        self.iam_policy.CopyFrom(policy)
        self.iam_policy.etag = hash_utils.random_bytes("iam_policy")
        return self.iam_policy
