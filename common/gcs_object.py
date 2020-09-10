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
import datetime
import time

import flask
import crc32c
from google.protobuf.json_format import ParseDict

import storage_resources_pb2 as resources
import utils
from common import data_utils, error, gcs_acl, hash_utils, process, rest_utils
from google.protobuf.field_mask_pb2 import FieldMask


class Object:
    def __init__(self, metadata, media):
        self.metadata = metadata
        self.media = media

    # === OBJECT === #

    @classmethod
    def __update_predefined_acl(
        cls, request, metadata, set_default, is_destination, context
    ):
        predefined_acl = gcs_acl.extract_predefined_acl(
            request, is_destination, context
        )
        if predefined_acl == "" or predefined_acl == 0:
            if set_default:
                predefined_acl = "private"
        acls = gcs_acl.object_predefined_acls(
            metadata.bucket, metadata.name, metadata.generation, predefined_acl, context
        )
        for acl in acls:
            cls.__upsert_acl(metadata, acl, None, False, context)

    @classmethod
    def init(cls, metadata, media, request, is_destination, context):
        if (
            context is None
            and request.headers.get("x-goog-testbench-instructions")
            == "inject-upload-data-error"
        ):
            media = data_utils.corrupt_media(media)
        timestamp = datetime.datetime.now(datetime.timezone.utc)
        metadata.generation = hash_utils.random_bigint()
        metadata.metageneration = 1
        metadata.id = "%s/o/%s#%d" % (
            metadata.bucket,
            metadata.name,
            metadata.generation,
        )
        metadata.size = len(media)
        actual_md5Hash = hash_utils.base64_md5(media)
        if metadata.md5_hash != "" and actual_md5Hash != metadata.md5_hash:
            error.abort(
                412,
                "Object checksum md5 does not match. Expected %s Actual %s"
                % (metadata.md5_hash, actual_md5Hash),
                context,
            )
        actual_crc32c = crc32c.crc32(media)
        if metadata.HasField("crc32c") and actual_crc32c != metadata.crc32c.value:
            error.abort(
                400,
                "Object checksum crc32c does not match. Expected %s Actual %s"
                % (metadata.crc32c, actual_crc32c),
                context,
            )
        metadata.md5_hash = actual_md5Hash
        metadata.crc32c.value = actual_crc32c
        metadata.time_created.FromDatetime(timestamp)
        metadata.updated.FromDatetime(timestamp)
        metadata.owner.entity = gcs_acl.object_entity("owners")
        metadata.owner.entity_id = gcs_acl.entity_id(metadata.owner.entity)
        cls.__update_predefined_acl(request, metadata, True, is_destination, context)
        return Object(metadata, media)

    @classmethod
    def init_dict(cls, metadata_dict, media, is_destination, request):
        metadata = ParseDict(metadata_dict, resources.Object())
        return cls.init(metadata, media, request, is_destination, None)

    @classmethod
    def init_multipart(cls, bucket_name, request):
        metadata, media_headers, media = rest_utils.parse_multipart(request)
        metadata["name"] = request.args.get("name", metadata.get("name", None))
        if metadata["name"] is None:
            error.abort(412, "name not set in Objects: insert", None)
        if (
            metadata.get("contentType") is not None
            and media_headers.get("content-type") is not None
            and metadata.get("contentType") != media_headers.get("content-type")
        ):
            error.abort(
                400,
                (
                    "Content-Type specified in the upload (%s) does not match"
                    + "contentType specified in the metadata (%s)."
                )
                % (media_headers.get("content-type"), metadata.get("contentType")),
                None,
            )
        metadata["bucket"] = bucket_name
        if "contentType" not in metadata:
            metadata["contentType"] = media_headers.get("content-type")
        metadata["metadata"] = (
            {} if "metadata" not in metadata else metadata["metadata"]
        )
        metadata["metadata"]["x_testbench_upload"] = "multipart"
        if "md5Hash" in metadata:
            metadata["metadata"]["x_testbench_md5"] = metadata["md5Hash"]
            metadata["md5Hash"] = metadata["md5Hash"]
        if "crc32c" in metadata:
            metadata["metadata"]["x_testbench_crc32c"] = metadata["crc32c"]
            metadata["crc32c"] = hash_utils.debase64_crc32c(metadata["crc32c"])
        metadata.update(utils.extract_encryption(request))
        return cls.init_dict(metadata, media, False, request)

    @classmethod
    def init_media(cls, bucket_name, request):
        object_name = request.args.get("name", None)
        media = request.data
        if object_name is None:
            error.abort(412, "name not set in Objects: insert", None)
        metadata = {
            "bucket": bucket_name,
            "name": object_name,
            "metadata": {"x_testbench_upload": "simple"},
        }
        return cls.init_dict(metadata, media, False, request)

    @classmethod
    def init_xml(cls, bucket_name, object_name, request):
        media = request.data
        metadata = {
            "bucket": bucket_name,
            "name": object_name,
            "metadata": {"x_testbench_upload": "xml"},
        }
        if "content-type" in request.headers:
            metadata["contentType"] = request.headers["content-type"]
        fake_request = rest_utils.FakeRequest(args=request.args.to_dict())
        fake_request.headers = {
            key.lower(): value
            for key, value in request.headers.items()
            if key.lower().startswith("x-goog-")
        }
        rest_utils.xml_headers_to_json_args(fake_request.headers, fake_request.args)
        x_goog_hash = fake_request.headers.get("x-goog-hash")
        if x_goog_hash is not None:
            for checksum in x_goog_hash.split(","):
                if checksum.startswith("md5="):
                    md5Hash = checksum[4:]
                    metadata["md5Hash"] = md5Hash
                if checksum.startswith("crc32c="):
                    crc32c_value = checksum[7:]
                    metadata["crc32c"] = hash_utils.debase64_crc32c(crc32c_value)
        return cls.init_dict(metadata, media, False, fake_request), fake_request

    @classmethod
    def __update_metadata(cls, source, destination, update_mask):
        update_mask.MergeMessage(source, destination, True, True)
        destination.metageneration += 1
        destination.updated.FromDatetime(datetime.datetime.now(datetime.timezone.utc))

    def patch(self, request, context):
        update_mask = FieldMask()
        metadata = None
        if context is not None:
            metadata = request.metadata
            if not request.HasField("update_mask"):
                error.abort(412, "PatchObjectRequest does not have field update_mask.")
            paths = [field[0].name for field in metadata.ListFields()]
            if paths != request.update_mask.paths:
                error.abort(412, "PatchObjectRequest does not match update_mask.")
            update_mask = request.update_mask
        else:
            data = json.loads(request.data)
            if "metadata" in data:
                if data["metadata"] is None:
                    self.metadata.metadata.clear()
                else:
                    for key, value in data["metadata"].items():
                        if value is None:
                            self.metadata.metadata.pop(key, None)
                        else:
                            self.metadata.metadata[key] = value
            data.pop("metadata", None)
            paths = ",".join(data.keys())
            update_mask.FromJsonString(paths)
            metadata = ParseDict(data, resources.Object())
        self.__update_metadata(metadata, self.metadata, update_mask)
        self.__update_predefined_acl(request, self.metadata, False, False, context)

    def update(self, request, context):
        metadata = (
            request.metadata
            if context is not None
            else ParseDict(
                json.loads(request.data),
                resources.Object(),
            )
        )
        update_mask = FieldMask(
            paths=[
                "content_encoding",
                "content_disposition",
                "cache_control",
                "acl",
                "content_language",
                "content_type",
                "storage_class",
                "kms_key_name",
                "temporary_hold",
                "retention_expiration_time",
                "metadata",
                "event_based_hold",
                "customer_encryption",
            ]
        )
        self.__update_metadata(metadata, self.metadata, update_mask)
        self.__update_predefined_acl(request, self.metadata, False, False, context)

    # === OBJECT ACL === #

    @classmethod
    def __search_acl(cls, metadata, entity):
        entity = gcs_acl.canonical_entity(entity)
        for i in range(len(metadata.acl)):
            if metadata.acl[i].entity == entity:
                return i

    @classmethod
    def __upsert_acl(cls, metadata, acl, update_mask, update_only, context):
        index = cls.__search_acl(metadata, acl.entity)
        if index is not None:
            if update_mask is None:
                update_mask = FieldMask(
                    paths=resources.ObjectAccessControl.DESCRIPTOR.fields_by_name.keys()
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
        acl = None
        if context is None:
            payload = json.loads(request.data)
            acl = gcs_acl.object_entity_acl(
                self.metadata.bucket,
                self.metadata.name,
                self.metadata.generation,
                payload["entity"],
                payload["role"],
                context,
            )
        else:
            acl = request.object_access_control
            acl = gcs_acl.object_entity_acl(
                self.metadata.bucket,
                self.metadata.name,
                self.metadata.generation,
                request.object_access_control.entity,
                request.object_access_control.role,
                context,
            )
        return self.__upsert_acl(self.metadata, acl, None, False, context)

    def update_acl(self, entity, request, context):
        acl = (
            request.object_access_control
            if context is not None
            else ParseDict(json.loads(request.data), resources.ObjectAccessControl())
        )
        acl.entity = entity
        return self.__upsert_acl(self.metadata, acl, None, True, context)

    def patch_acl(self, entity, request, context):
        update_mask = FieldMask()
        acl = None
        if context is not None:
            acl = request.object_access_control
            update_mask = request.update_mask
        else:
            data = json.loads(request.data)
            acl = ParseDict(data, resources.ObjectAccessControl())
            paths = ",".join(data.keys())
            update_mask.FromJsonString(paths)
        acl.entity = entity
        return self.__upsert_acl(self.metadata, acl, update_mask, True, context)

    def delete_acl(self, entity, context):
        index = self.__get_acl(entity, context)
        del self.metadata.acl[index]

    # === RESPONSE === #

    def to_rest(self, request, fields=None):
        projection = "noAcl"
        if b"acl" in request.data:
            projection = "full"
        projection = request.args.get("projection", projection)
        result = process.message_to_rest(
            self.metadata,
            "storage#object",
            request.args.get("fields", fields),
        )
        if projection == "noAcl":
            result.pop("acl", None)
            result.pop("owner", None)
        return result

    def media_rest(self, request):
        instructions = request.headers.get("x-goog-testbench-instructions")
        begin = 0
        end = len(self.media)
        if request.range is not None:
            begin = (
                request.range.ranges[0][0]
                if request.range.ranges[0][0] is not None
                else begin
            )
            end = (
                request.range.ranges[0][1]
                if request.range.ranges[0][1] is not None
                else end
            )
        length = len(self.media)
        response_stream = None
        content_range = "bytes %d-%d/%d" % (begin, end - 1, length)

        def streamer():
            return self.media[begin:end]

        response_stream = streamer

        if instructions == "return-corrupted-data":
            media = data_utils.corrupt_media(self.media[begin:end])

            def streamer():
                return media

            response_stream = streamer

        if instructions is not None and instructions.startswith(u"stall-always"):

            def streamer():
                chunk_size = 16 * 1024
                for r in range(begin, end, chunk_size):
                    chunk_end = min(r + chunk_size, end)
                    if r == begin:
                        time.sleep(10)
                    yield self.media[r:chunk_end]

            response_stream = streamer

        if instructions == "stall-at-256KiB" and begin == 0:

            def streamer():
                chunk_size = 16 * 1024
                for r in range(begin, end, chunk_size):
                    chunk_end = min(r + chunk_size, end)
                    if r == 256 * 1024:
                        time.sleep(10)
                    yield self.media[r:chunk_end]

            response_stream = streamer

        headers = {
            "Content-Range": content_range,
            "x-goog-hash": self.x_goog_hash_header(),
            "x-goog-generation": self.metadata.generation,
        }
        return flask.Response(response_stream(), status=200, headers=headers)

    def x_goog_hash_header(self):
        header = ""
        if "x_testbench_crc32c" in self.metadata.metadata:
            header += "crc32c=" + self.metadata.metadata["x_testbench_crc32c"]
        if "x_testbench_md5" in self.metadata.metadata:
            if header != "":
                header += ","
            header += "md5=" + self.metadata.metadata["x_testbench_md5"]
        return header if header != "" else None
