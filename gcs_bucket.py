import storage_resources_pb2 as resources
import utils
import json
import re
import random

from google.iam.v1 import policy_pb2
from google.protobuf.json_format import ParseDict, MessageToDict


class Bucket:
    def __init__(self, bucket_name="", request=None, addition=None):
        payload = dict()
        if request is not None:
            payload = utils.ToProtoDict(request.data)
        else:
            payload["name"] = bucket_name
        payload["id"] = payload["name"]
        if not self.__validate_bucket_name(payload["name"]):
            utils.abort(412, "Bucket name %s is invalid" % payload["name"])
        if isinstance(addition, dict):
            payload.update(addition)
        self.metadata = ParseDict(payload, resources.Bucket())
        self.notification = []
        self.iam_policy = None
        self.__init_acl()
        self.__init_iam_policy()
        utils.insert_bucket(self)

    @classmethod
    def lookup(cls, bucket_name, request=None):
        bucket = utils.lookup_bucket(bucket_name)
        if bucket is None:
            utils.abort(404, "Bucket %s does not exist" % bucket_name)
        if request is not None:
            metageneration = str(bucket.metadata.metageneration)
            metageneration_match = request.args.get("ifMetagenerationMatch")
            metageneration_not_match = request.args.get("ifMetagenerationNotMatch")
            if (
                metageneration_not_match is not None
                and metageneration_not_match == metageneration
            ):
                utils.abort(
                    412,
                    "Precondition Failed (metageneration = %s vs metageneration_not_match = %s)"
                    % (metageneration, metageneration_not_match),
                )
            if (
                metageneration_match is not None
                and metageneration_match != metageneration
            ):
                utils.abort(
                    412,
                    "Precondition Failed (metageneration = %s vs metageneration_match = %s)"
                    % (metageneration, metageneration_match),
                )
        return bucket

    @classmethod
    def list(cls, project):
        if project is None or project.endswith("-"):
            utils.abort(412, "Invalid or missing project id in `Buckets: list`")
        return utils.all_buckets()

    @classmethod
    def acl_to_rest(cls, acl, object=False):
        if object:
            return utils.ToRestDict(acl, "storage#objectAccessControl")
        return utils.ToRestDict(acl, "storage#bucketAccessControl")

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

    def to_rest(self, request=None, projection=None):
        result = utils.ToRestDict(self.metadata, "storage#bucket")
        if request is not None:
            projection = request.args.get("projection", projection)
            fields = request.args.getlist("fields")
            if len(fields) != 0:
                deletes = [key for key in result if key not in fields]
                for field in deletes:
                    del result[field]
            if projection is None or projection == "noAcl":
                result.pop("acl", None)
                result.pop("defaultObjectAcl", None)
                result.pop("owner", None)
        return result

    def update(self, request, clear=True):
        payload = utils.ToProtoDict(request.data)
        projection = "noAcl"
        if "acl" in payload:
            projection = "full"
        if clear:
            self.metadata.Clear()
        self.metadata = ParseDict(payload, self.metadata)
        return projection

    def delete(self):
        utils.delete_bucket(self.metadata.name)

    def __init_acl(self):
        # TODO(vnvo2409): Check for predefinedAcl
        self.insert_acl("project-owners-123456789", "OWNER")
        self.insert_acl("project-editors-123456789", "OWNER")
        self.insert_acl("project-viewers-123456789", "READER")

        # TODO(vnvo2409): Check for predefinedDefaultObjectAcl
        self.insert_default_object_acl("project-owners-123456789", "OWNER")
        self.insert_default_object_acl("project-editors-123456789", "OWNER")
        self.insert_default_object_acl("project-viewers-123456789", "READER")

    def __init_iam_policy(self):
        role_mapping = {
            "READER": "roles/storage.legacyBucketReader",
            "WRITER": "roles/storage.legacyBucketWriter",
            "OWNER": "roles/storage.legacyBucketOwner",
        }
        bindings = []
        for entry in self.metadata.acl:
            legacy_role = entry.role
            if legacy_role is None or entry.entity is None:
                utils.abort(500, "Invalid ACL entry")
            role = role_mapping.get(legacy_role)
            if role is None:
                utils.abort(500, "Invalid legacy role %s" % legacy_role)
            bindings.append(policy_pb2.Binding(role=role, members=[entry.entity]))
        self.iam_policy = policy_pb2.Policy(
            version=1, bindings=bindings, etag=utils.compute_etag("__init_iam_policy"),
        )

    def insert_acl(self, entity, role, update=False, clear=True):
        acl = resources.BucketAccessControl(
            role=role,
            etag=utils.compute_etag(entity + role),
            id=self.metadata.name + "/" + entity,
            bucket=self.metadata.name,
            entity=entity,
        )
        if update:
            for i in range(len(self.metadata.acl)):
                if acl.entity == self.metadata.acl[i].entity:
                    if clear:
                        self.metadata.acl[i].CopyFrom(acl)
                    else:
                        self.metadata.acl[i].MergeFrom(acl)
                    return self.metadata.acl[i]
        else:
            self.metadata.acl.append(acl)
            return acl
        utils.abort(404, "Acl %s does not exist" % acl.entity)

    def lookup_acl(self, entity):
        for acl in self.metadata.acl:
            if acl.entity == entity:
                return acl
        utils.abort(404, "Acl %s does not exist" % entity)

    def delete_acl(self, entity):
        for i in range(len(self.metadata.acl)):
            if self.metadata.acl[i].entity == entity:
                del self.metadata.acl[i]
                return
        utils.abort(404, "Acl %s does not exist" % entity)

    def insert_default_object_acl(self, entity, role, update=False, clear=True):
        acl = resources.ObjectAccessControl(
            role=role,
            etag=utils.compute_etag(entity + role),
            id=self.metadata.name + "/" + entity,
            bucket=self.metadata.name,
            entity=entity,
        )
        if update:
            for i in range(len(self.metadata.default_object_acl)):
                if acl.entity == self.metadata.default_object_acl[i].entity:
                    if clear:
                        self.metadata.default_object_acl[i].CopyFrom(acl)
                    else:
                        self.metadata.default_object_acl[i].MergeFrom(acl)
                    return self.metadata.default_object_acl[i]
        else:
            self.metadata.default_object_acl.append(acl)
            return acl
        utils.abort(404, "Acl %s does not exist" % acl.entity)

    def lookup_default_object_acl(self, entity):
        for acl in self.metadata.default_object_acl:
            if acl.entity == entity:
                return acl
        utils.abort(404, "Acl %s does not exist" % entity)

    def delete_default_object_acl(self, entity):
        for i in range(len(self.metadata.default_object_acl)):
            if self.metadata.default_object_acl[i].entity == entity:
                del self.metadata.default_object_acl[i]
                return
        utils.abort(404, "Acl %s does not exist" % entity)

    def insert_noti(self, request):
        noti = ParseDict(utils.ToProtoDict(request.data), resources.Notification())
        noti.id = "notification-%s" % str(random.random())
        self.notification.append(noti)
        return noti

    def delete_noti(self, notification_id):
        for i in range(len(self.notification)):
            if self.notification[i].id == notification_id:
                del self.notification[i]
                return
        utils.abort(404, "Notification %s does not exist" % notification_id)

    def lookup_noti(self, notification_id):
        for i in range(len(self.notification)):
            if self.notification[i].id == notification_id:
                return self.notification[i]
        utils.abort(404, "Notification %s does not exist" % notification_id)

    @classmethod
    def noti_to_rest(cls, notification):
        result = MessageToDict(notification, preserving_proto_field_name=True)
        result["kind"] = "storage#notification"
        return result

    @classmethod
    def policy_to_rest(cls, policy):
        return utils.ToRestDict(policy, "storage#policy")

    def insert_iam_policy(self, request):
        policy = ParseDict(utils.ToProtoDict(request.data), policy_pb2.Policy())
        self.iam_policy.CopyFrom(policy)
        self.iam_policy.etag = utils.compute_etag(
            "iam_policy_%s" % str(random.random())
        )
        return self.iam_policy
