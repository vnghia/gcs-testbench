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
import random
import re
import os

from google.iam.v1 import policy_pb2
from google.protobuf.json_format import ParseDict
from google.protobuf.message import Message

import storage_resources_pb2 as resources
import utils


class Bucket:
    def __init__(self, metadata, args={}, context=None):
        if isinstance(metadata, resources.Bucket):
            self.metadata = metadata
        else:
            metadata = utils.process_data(metadata)
            if not self.__validate_bucket_name(metadata["name"]):
                utils.abort(
                    412, "Bucket name %s is invalid" % metadata["name"], context
                )
            self.metadata = ParseDict(metadata, resources.Bucket())
        self.metadata.id = self.metadata.name
        self.metadata.owner.entity = "project-owners-123456789"
        self.metadata.owner.entity_id = (
            self.metadata.name + "/" + "project-owners-123456789"
        )
        self.notification = []
        self.iam_policy = None
        self.__init_acl()
        self.__init_iam_policy(context)
        utils.insert_bucket(self)

    @classmethod
    def list(cls, project, context=None):
        if project is None or project.endswith("-"):
            utils.abort(
                412, "Invalid or missing project id in `Buckets: list`", context
            )
        return utils.all_buckets()

    @classmethod
    def __validate_bucket_name(cls, bucket_name):
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
        return valid

    @classmethod
    def lookup(cls, bucket_name, args=None, context=None):
        bucket = utils.lookup_bucket(bucket_name)
        if bucket is None:
            utils.abort(404, "Bucket %s does not exist" % bucket_name, context)
        metageneration = str(bucket.metadata.metageneration)
        metageneration_match = None
        metageneration_not_match = None
        if isinstance(args, Message):
            metageneration_match = (
                str(args.if_metageneration_match.value)
                if args.HasField("if_metageneration_match")
                else None
            )
            metageneration_not_match = (
                str(args.if_metageneration_not_match.value)
                if args.HasField("if_metageneration_not_match")
                else None
            )
        elif args is not None:
            metageneration_match = args.get("ifMetagenerationMatch", None)
            metageneration_not_match = args.get("ifMetagenerationNotMatch", None)
        if (
            metageneration_not_match is not None
            and metageneration_not_match == metageneration
        ):
            utils.abort(
                412,
                "Precondition Failed (metageneration = %s vs metageneration_not_match = %s)"
                % (metageneration, metageneration_not_match),
                context,
            )
        if metageneration_match is not None and metageneration_match != metageneration:
            utils.abort(
                412,
                "Precondition Failed (metageneration = %s vs metageneration_match = %s)"
                % (metageneration, metageneration_match),
                context,
            )
        return bucket

    def __init_acl(self):
        # TODO(vnvo2409): Check for predefinedAcl
        def make_acl_proto(entity, role):
            return resources.BucketAccessControl(entity=entity, role=role)

        self.insert_acl(make_acl_proto("project-owners-123456789", "OWNER"))
        self.insert_acl(make_acl_proto("project-editors-123456789", "OWNER"))
        self.insert_acl(make_acl_proto("project-viewers-123456789", "READER"))

        # TODO(vnvo2409): Check for predefinedDefaultObjectAcl
        self.insert_default_object_acl(
            utils.make_object_acl_proto(
                self.metadata.name, "project-owners-123456789", "OWNER"
            )
        )
        self.insert_default_object_acl(
            utils.make_object_acl_proto(
                self.metadata.name, "project-editors-123456789", "OWNER"
            )
        )
        self.insert_default_object_acl(
            utils.make_object_acl_proto(
                self.metadata.name, "project-viewers-123456789", "READER"
            )
        )

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
                utils.abort(500, "Invalid ACL entry", context)
            role = role_mapping.get(legacy_role)
            if role is None:
                utils.abort(500, "Invalid legacy role %s" % legacy_role, context)
            bindings.append(policy_pb2.Binding(role=role, members=[entry.entity]))
        self.iam_policy = policy_pb2.Policy(
            version=1,
            bindings=bindings,
            etag=utils.compute_etag("__init_iam_policy"),
        )

    def to_rest(self, request):
        projection = "noAcl"
        if b"acl" in request.data or b"defaultObjectAcl" in request.data:
            projection = "full"
        projection = request.args.get("projection", projection)
        result = utils.message_to_rest(
            self.metadata, "storage#bucket", request.args.get("fields", None)
        )
        if projection == "noAcl":
            result.pop("acl", None)
            result.pop("defaultObjectAcl", None)
            result.pop("owner", None)
        return result

    def update(self, data):
        metageneration = self.metadata.metageneration
        if isinstance(data, resources.Bucket):
            self.metadata.MergeFrom(data)
        else:
            self.metadata = ParseDict(utils.process_data(data), self.metadata)
        if self.metadata.versioning.enabled:
            self.metadata.metageneration = metageneration + 1

    def delete(self):
        utils.delete_bucket(self.metadata.name)

    def insert_acl(self, data, update=False):
        acl = (
            data
            if isinstance(data, resources.BucketAccessControl)
            else ParseDict(utils.process_data(data), resources.BucketAccessControl())
        )
        acl.etag = utils.random_etag(acl.entity + acl.role)
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
        utils.abort(404, "Acl %s does not exist" % entity)

    def delete_acl(self, entity):
        _, index = self.lookup_acl(entity)
        del self.metadata.acl[index]

    def insert_default_object_acl(self, data, update=False):
        acl = (
            data
            if isinstance(data, resources.ObjectAccessControl)
            else ParseDict(utils.process_data(data), resources.ObjectAccessControl())
        )
        acl.etag = utils.random_etag(acl.entity + acl.role)
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
        utils.abort(404, "Acl %s does not exist" % entity)

    def delete_default_object_acl(self, entity):
        _, index = self.lookup_default_object_acl(entity)
        del self.metadata.default_object_acl[index]

    def insert_notification(self, data):
        noti = (
            data
            if isinstance(data, resources.Notification)
            else ParseDict(utils.process_data(data), resources.Notification())
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
        utils.abort(404, "Notification %s does not exist" % notification_id)

    def insert_iam_policy(self, data):
        policy = (
            data
            if isinstance(data, policy_pb2.Policy)
            else ParseDict(utils.process_data(data), policy_pb2.Policy())
        )
        self.iam_policy.CopyFrom(policy)
        self.iam_policy.etag = utils.random_etag("iam_policy")
        return self.iam_policy

    @classmethod
    def insert_test_bucket(cls):
        bucket_name = os.environ.get(
            "GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", "test-bucket"
        )
        if utils.lookup_bucket(bucket_name) is None:
            bucket_test = Bucket(json.dumps({"name": bucket_name}))
            bucket_test.metadata.metageneration = 4
            bucket_test.metadata.versioning.enabled = True
