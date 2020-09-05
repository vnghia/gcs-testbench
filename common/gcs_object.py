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
import time
from datetime import datetime, timezone

import flask
import gcs_upload
from crc32c import crc32
from google.protobuf.json_format import ParseDict
from google.protobuf.message import Message

import storage_pb2 as storage
import storage_resources_pb2 as resources
import utils


class Object:
    def __init__(self, metadata, media, args={}, headers={}, context=None):
        timestamp = datetime.now(timezone.utc)
        if isinstance(metadata, resources.Object):
            self.metadata = metadata
        else:
            metadata = utils.process_data(metadata)
            self.metadata = ParseDict(metadata, resources.Object())
        self.metadata.generation = self.__random_generation()
        self.metadata.metageneration = 1
        self.metadata.id = (
            self.metadata.bucket
            + "/"
            + self.metadata.name
            + "#"
            + str(self.metadata.generation)
        )
        self.media = media
        self.metadata.size = len(self.media)
        actual_md5Hash = utils.compute_md5(media)
        if self.metadata.md5_hash != "" and actual_md5Hash != self.metadata.md5_hash:
            utils.abort(
                412,
                "Object checksum md5 does not match. Expected %s Actual %s"
                % (actual_md5Hash, self.metadata.md5_hash),
                context,
            )
        self.metadata.md5_hash = actual_md5Hash
        self.metadata.crc32c.value = crc32(self.media)
        self.metadata.time_created.FromDatetime(timestamp)
        self.metadata.updated.FromDatetime(timestamp)
        self.__update_acl(args, headers)
        utils.insert_object(self.metadata.bucket, self)

    @classmethod
    def __random_generation(cls):
        return random.getrandbits(63)

    @classmethod
    def list(cls, bucket_name, args):
        is_proto = isinstance(args, storage.ListObjectsRequest)
        versions = args.versions if is_proto else args.get("versions", False)
        prefix = args.prefix if is_proto else args.get("prefix", "")
        delimiter = args.delimiter if is_proto else args.get("delimiter", "")
        start_offset = args.get("startOffset", "")
        end_offset = args.get("endOffset", "")
        items = []
        prefixes = set()
        for obj in utils.all_objects(bucket_name, versions):
            name = obj.metadata.name
            if name.find(prefix) != 0:
                continue
            if name < start_offset:
                continue
            if end_offset != "" and name >= end_offset:
                continue
            delimiter_index = name.find(delimiter, len(prefix))
            if delimiter != "" and delimiter_index > 0:
                prefixes.add(name[: delimiter_index + 1])
                continue
            items.append(obj.metadata)
        return items, list(prefixes)

    @classmethod
    def __parse_multipart_rest_request(cls, request):
        content_type = request.headers.get("content-type")
        if content_type is None or not content_type.startswith("multipart/related"):
            utils.abort(
                412, "Missing or invalid content-type header in multipart upload"
            )
        _, _, boundary = content_type.partition("boundary=")
        if boundary is None:
            utils.abort(
                412, "Missing boundary in content-type header in multipart upload"
            )

        def parse_part(part):
            result = part.split(b"\r\n")
            if result[0] != b"" and result[-1] != b"":
                utils.abort(412, "Could not parse %s" % str(part))
            result = list(filter(None, result))
            headers = dict()
            if len(result) < 2:
                result.append(b"")
            for header in result[:-1]:
                key, value = header.split(b": ")
                headers[key.decode("utf-8")] = value.decode("utf-8")
            return headers, result[-1]

        boundary = bytearray(boundary, "utf-8")
        parts = request.data.split(b"--" + boundary)
        if parts[-1] != b"--\r\n":
            utils.abort(412, "Missing end marker (--%s--) in media body" % boundary)
        _, resource = parse_part(parts[1])
        metadata = json.loads(resource)
        media_headers, media = parse_part(parts[2])
        return metadata, media_headers, media

    @classmethod
    def __insert_rest_multipart(cls, bucket_name, request):
        metadata, media_headers, media = cls.__parse_multipart_rest_request(request)
        instructions = request.headers.get("x-goog-testbench-instructions")
        if instructions == "inject-upload-data-error":
            media = utils.corrupt_media(media)
        metadata["name"] = request.args.get("name", metadata.get("name", None))
        if metadata["name"] is None:
            utils.abort(412, "name not set in Objects: insert")
        if (
            metadata.get("contentType") is not None
            and media_headers.get("content-type") is not None
            and metadata.get("contentType") != media_headers.get("content-type")
        ):
            utils.abort(
                400,
                (
                    "Content-Type specified in the upload (%s) does not match"
                    + "contentType specified in the metadata (%s)."
                )
                % (media_headers.get("content-type"), metadata.get("contentType")),
            )
        utils.check_object_generation(bucket_name, metadata["name"], request.args)
        metadata["bucket"] = bucket_name
        if "contentType" not in metadata:
            metadata["contentType"] = media_headers.get("content-type")
        metadata["metadata"] = (
            dict() if "metadata" not in metadata else metadata["metadata"]
        )
        metadata["metadata"]["x_testbench_upload"] = "multipart"
        if "md5Hash" in metadata:
            metadata["metadata"]["x_testbench_md5"] = metadata["md5Hash"]
            actual_md5Hash = utils.compute_md5(media)
            if actual_md5Hash != metadata["md5Hash"]:
                utils.abort(
                    412,
                    "Object checksum md5 does not match. Expected %s Actual %s"
                    % (actual_md5Hash, metadata["md5Hash"]),
                )
            del metadata["md5Hash"]
        if "crc32c" in metadata:
            metadata["metadata"]["x_testbench_crc32c"] = metadata["crc32c"]
            actual_crc32c = utils.compute_crc32c(media)
            if actual_crc32c != metadata["crc32c"]:
                utils.abort(
                    400,
                    "Object checksum crc32c does not match. Expected %s Actual %s"
                    % (actual_crc32c, metadata["crc32c"]),
                )
            del metadata["crc32c"]
        metadata.update(utils.extract_encryption(request))
        obj = Object(metadata, media, request.args, request.headers)
        return obj

    @classmethod
    def __insert_rest_xml(cls, bucket_name, object_name, request):
        media = utils.extract_media(request)
        instructions = request.headers.get("x-goog-testbench-instructions")
        if instructions == "inject-upload-data-error":
            media = utils.corrupt_media(media)
        metadata = dict()
        metadata["bucket"] = bucket_name
        metadata["name"] = object_name
        if "content-type" in request.headers:
            metadata["contentType"] = request.headers["content-type"]
        args = dict()
        if "x-goog-if-generation-match" in request.headers:
            args["ifGenerationMatch"] = request.headers["x-goog-if-generation-match"]
        if "x-goog-if-meta-generation-match" in request.headers:
            args["ifMetagenerationMatch"] = request.headers[
                "x-goog-if-meta-generation-match"
            ]
        goog_hash = request.headers.get("x-goog-hash")
        if goog_hash is not None:
            for hash in goog_hash.split(","):
                if hash.startswith("md5="):
                    md5Hash = hash[4:]
                    actual_md5Hash = utils.compute_md5(media)
                    if actual_md5Hash != md5Hash:
                        utils.abort(
                            412,
                            "Object checksum md5 does not match. Expected %s Actual %s"
                            % (actual_md5Hash, md5Hash),
                        )
                if hash.startswith("crc32c="):
                    crc32c = hash[7:]
                    actual_crc32c = utils.compute_crc32c(media)
                    if actual_crc32c != crc32c:
                        utils.abort(
                            400,
                            "Object checksum crc32c does not match. Expected %s Actual %s"
                            % (actual_crc32c, crc32c),
                        )
        utils.check_object_generation(bucket_name, object_name, args)
        obj = Object(metadata, media, request.args, request.headers)
        obj.metadata.metadata["x_testbench_upload"] = "xml"
        return obj

    @classmethod
    def __insert_rest(cls, bucket_name, request, xml_object_name=None):
        if xml_object_name is not None:
            return cls.__insert_rest_xml(bucket_name, xml_object_name, request)
        upload_type = request.args.get("uploadType")
        if upload_type is None:
            utils.abort(400, "uploadType not set in Objects: insert")
        if upload_type not in {"multipart", "media", "resumable"}:
            utils.abort(400, "testbench does not support %s uploadType" % upload_type)
        if upload_type == "resumable":
            return gcs_upload.Upload(bucket_name, request).to_rest()
        if upload_type == "media":
            object_name = request.args.get("name", None)
            instructions = request.headers.get("x-goog-testbench-instructions")
            media = utils.extract_media(request)
            if instructions == "inject-upload-data-error":
                media = utils.corrupt_media(media)
            if object_name is None:
                utils.abort(412, "name not set in Objects: insert")
            utils.check_object_generation(bucket_name, object_name, request.args)
            obj = Object(
                {"bucket": bucket_name, "name": object_name},
                media,
                request.args,
                request.headers,
            )
            obj.metadata.metadata["x_testbench_upload"] = "simple"
            return obj
        if upload_type == "multipart":
            return cls.__insert_rest_multipart(bucket_name, request)

    @classmethod
    def __insert_grpc(cls, bucket_name, request):
        pass

    @classmethod
    def insert(cls, bucket_name, request, xml_object_name=None, context=None):
        bucket = utils.lookup_bucket(bucket_name)
        if bucket is None:
            utils.abort(404, "Bucket %s does not exist", context)
        if isinstance(request, storage.InsertObjectRequest):
            return cls.__insert_grpc(bucket_name, request)
        else:
            return cls.__insert_rest(bucket_name, request, xml_object_name)

    @classmethod
    def lookup(cls, bucket_name, object_name, args=None, source=False, context=None):
        generation_field = "generation" if not source else "sourceGeneration"
        if isinstance(args, Message):
            current_generation = str(args.generation) if args.generation != 0 else ""
        else:
            current_generation = (
                str(args.get(generation_field))
                if args is not None and args.get(generation_field) is not None
                else ""
            )
        obj = utils.check_object_generation(
            bucket_name, object_name, args, current_generation, source, context=context
        )
        if obj is None:
            utils.abort(404, "Object %s does not exist" % object_name, context)
        return obj

    def lookup_acl(self, entity):
        for i in range(len(self.metadata.acl)):
            if self.metadata.acl[i].entity == entity:
                return self.metadata.acl[i], i
        utils.abort(404, "Acl %s does not exist" % entity)

    def insert_acl(self, data, update=False):
        acl = (
            data
            if isinstance(data, resources.ObjectAccessControl)
            else ParseDict(utils.process_data(data), resources.ObjectAccessControl())
        )
        acl.etag = utils.random_etag(acl.entity + acl.role)
        acl.id = self.metadata.name + "/" + acl.entity
        acl.bucket = self.metadata.bucket
        if update:
            _, index = self.lookup_acl(acl.entity)
            self.metadata.acl[index].MergeFrom(acl)
            return self.metadata.acl[index]
        else:
            self.metadata.acl.append(acl)
            return acl

    def delete_acl(self, entity):
        _, index = self.lookup_acl(entity)
        del self.metadata.acl[index]

    def __update_acl(self, args, headers):
        predefined_acl = None
        if headers.get("x-goog-acl") is not None:
            acl2json_mapping = {
                "authenticated-read": "authenticatedRead",
                "bucket-owner-full-control": "bucketOwnerFullControl",
                "bucket-owner-read": "bucketOwnerRead",
                "private": "private",
                "project-private": "projectPrivate",
                "public-read": "publicRead",
            }
            acl = headers.get("x-goog-acl")
            predefined_acl = acl2json_mapping.get(acl)
            if predefined_acl is None:
                utils.abort(400, "Invalid predefinedAcl value %s" % acl)
        else:
            predefined_acl = args.get(
                "predefinedAcl", args.get("destinationPredefinedAcl")
            )
        if predefined_acl is None:
            predefined_acl = "projectPrivate"
        owner_entity = "project-owners-123456789"
        self.metadata.acl.append(
            utils.make_object_acl_proto(
                self.metadata.bucket,
                owner_entity,
                "OWNER",
                self.metadata.name,
            )
        )
        self.metadata.owner.entity = "project-owners-123456789"
        self.metadata.owner.entity_id = (
            self.metadata.bucket
            + "/"
            + self.metadata.name
            + "/"
            + "project-owners-123456789"
        )
        acl = None
        if predefined_acl == "authenticatedRead":
            acl = [
                utils.make_object_acl_proto(
                    self.metadata.bucket,
                    "allAuthenticatedUsers",
                    "READER",
                    self.metadata.name,
                )
            ]
        elif predefined_acl == "bucketOwnerFullControl":
            acl = [
                utils.make_object_acl_proto(
                    self.metadata.bucket,
                    owner_entity,
                    "OWNER",
                    self.metadata.name,
                )
            ]
        elif predefined_acl == "bucketOwnerRead":
            acl = [
                utils.make_object_acl_proto(
                    self.metadata.bucket,
                    owner_entity,
                    "READER",
                    self.metadata.name,
                )
            ]
        elif predefined_acl == "private":
            acl = [
                utils.make_object_acl_proto(
                    self.metadata.bucket,
                    "project-owners",
                    "OWNER",
                    self.metadata.name,
                )
            ]
        elif predefined_acl == "publicRead":
            acl = [
                utils.make_object_acl_proto(
                    self.metadata.bucket,
                    "allUsers",
                    "READER",
                    self.metadata.name,
                )
            ]
        elif predefined_acl == "projectPrivate":
            acl = [
                utils.make_object_acl_proto(
                    self.metadata.bucket,
                    "project-editors-123456789",
                    "OWNER",
                    self.metadata.name,
                ),
                utils.make_object_acl_proto(
                    self.metadata.bucket,
                    "project-viewers-123456789",
                    "READER",
                    self.metadata.name,
                ),
            ]
        else:
            utils.abort(400, "Invalid predefinedAcl value")
        for item in acl:
            self.insert_acl(item)
        pass

    def to_rest(self, request, fields=None):
        projection = "noAcl"
        if b"acl" in request.data:
            projection = "full"
        projection = request.args.get("projection", projection)
        result = utils.message_to_rest(
            self.metadata,
            "storage#object",
            request.args.get("fields", fields),
        )
        if projection == "noAcl":
            result.pop("acl", None)
            result.pop("owner", None)
        return result

    def update(self, data):
        metageneration = self.metadata.metageneration
        x_testbench_metadata = {
            key: value
            for key, value in self.metadata.metadata.items()
            if key.startswith("x_testbench_")
        }
        versioning = utils.lookup_bucket(
            self.metadata.bucket
        ).metadata.versioning.enabled
        if isinstance(data, resources.Object):
            self.metadata.MergeFrom(data)
        else:
            self.metadata = ParseDict(utils.process_data(data), self.metadata)
        self.metadata.metadata.update(x_testbench_metadata)
        if versioning:
            self.metadata.metageneration = metageneration + 1

    def delete(self):
        utils.delete_object(self.metadata.bucket, self.metadata.name)

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
            media = utils.corrupt_media(self.media[begin:end])

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
            "x-goog-hash": self.__x_goog_hash_header(),
            "x-goog-generation": self.metadata.generation,
        }
        return flask.Response(response_stream(), status=200, headers=headers)

    def __x_goog_hash_header(self):
        header = ""
        if "x_testbench_crc32c" in self.metadata.metadata:
            header += "crc32c=" + utils.encode_crc32c(self.metadata.crc32c.value)
        if "x_testbench_md5" in self.metadata.metadata:
            header += ",md5=" + str(self.metadata.md5_hash)
        return header if header != "" else None

    def rewrite(self):
        pass
