import json
import random
import re
from datetime import datetime, timezone
from hashlib import md5

import flask
from crc32c import crc32
from google.iam.v1 import policy_pb2
from google.protobuf.json_format import MessageToDict, Parse, ParseDict
from google.protobuf.message import Message

import gcs_upload
import storage_pb2 as storage
import storage_resources_pb2 as resources
import utils


class Object:
    def __init__(self, metadata, media, args={}):
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
        self.metadata.md5_hash = md5(self.media).hexdigest()
        self.metadata.crc32c.value = crc32(self.media)
        self.metadata.time_created.FromDatetime(timestamp)
        self.metadata.updated.FromDatetime(timestamp)
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
                utils.abort(412, "Could not parse %s" % str(part))
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
            media = testbench_utils.corrupt_media(media)
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
                % (media_headers.get("content-type"), resource.get("contentType")),
            )
        utils.check_object_generation(bucket_name, metadata["name"], request.args)
        metadata["bucket"] = bucket_name
        if "contentType" not in metadata:
            metadata["contentType"] = media_headers.get("content-type")
        metadata["metadata"] = dict()
        metadata["metadata"]["x_testbench_upload"] = "multipart"
        if "md5Hash" in metadata:
            metadata["metadata"]["x_testbench_md5"] = metadata["md5Hash"]
            actual_md5Hash = md5(media).hexdigit()
            if actual_md5Hash != metadata["md5Hash"]:
                utils.abort(
                    412,
                    "Object checksum does not match. Expected %s Actual %s"
                    % (actual_md5Hash, metadata["md5Hash"]),
                )
            del metadata["md5Hash"]
        if "crc32c" in metadata:
            metadata["metadata"]["x_testbench_crc32c"] = metadata["crc32c"]
            actual_crc32c = utils.compute_crc32c(media)
            if actual_crc32c != metadata["crc32c"]:
                utils.abort(
                    400,
                    "Object checksum does not match. Expected %s Actual %s"
                    % (actual_crc32c, metadata["crc32c"]),
                )
            del metadata["crc32c"]
        obj = Object(metadata, media)
        return obj

    @classmethod
    def __insert_rest_xml(cls, bucket_name, object_name, request):
        media = utils.extract_media(request)
        instructions = request.headers.get("x-goog-testbench-instructions")
        if instructions == "inject-upload-data-error":
            media = testbench_utils.corrupt_media(media)
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
        md5hash = None
        crc32c = None
        if goog_hash is not None:
            for hash in goog_hash.split(","):
                if hash.startswith("md5="):
                    md5hash = hash[4:]
                    actual_md5Hash = md5(media).hexdigit()
                    if actual_md5Hash != md5Hash:
                        utils.abort(
                            412,
                            "Object checksum does not match. Expected %s Actual %s"
                            % (actual_md5Hash, md5Hash),
                        )
                if hash.startswith("crc32c="):
                    crc32c = hash[7:]
                    actual_crc32c = utils.compute_crc32c(media)
                    if actual_crc32c != crc32c:
                        utils.abort(
                            400,
                            "Object checksum does not match. Expected %s Actual %s"
                            % (actual_crc32c, crc32c),
                        )
        utils.check_object_generation(bucket_name, object_name, args)
        obj = Object(metadata, media)
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
                media = testbench_utils.corrupt_media(media)
            if object_name is None:
                utils.abort(412, "name not set in Objects: insert")
            utils.check_object_generation(bucket_name, object_name, request.args)
            obj = Object({"bucket": bucket_name, "name": object_name}, media,)
            obj.metadata.metadata["x_testbench_upload"] = "simple"
            return obj
        if upload_type == "multipart":
            return cls.__insert_rest_multipart(bucket_name, request)

    @classmethod
    def __insert_grpc(cls, bucket_name, request):
        pass

    @classmethod
    def insert(cls, bucket_name, request, xml_object_name=None):
        if isinstance(request, storage.InsertObjectRequest):
            return cls.__insert_grpc(bucket_name, request)
        else:
            return cls.__insert_rest(bucket_name, request, xml_object_name)

    @classmethod
    def lookup(cls, bucket_name, object_name, args=None):
        obj = utils.check_object_generation(bucket_name, object_name, args)
        if obj is None:
            utils.abort(404, "Bucket %s does not exist" % bucket_name)
        return obj

    def to_rest(self, request):
        projection = "noAcl"
        if b"acl" in request.data:
            projection = "full"
        projection = request.args.get("projection", projection)
        result = utils.message_to_rest(
            self.metadata, "storage#object", request.args.get("fields", None),
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
        media = self.media
        if instructions == "return-corrupted-data":
            media = utils.corrupt_media(media)
        response = flask.make_response(media)
        response.headers["x-goog-hash"] = ""
        if "x_testbench_crc32c" in self.metadata.metadata:
            response.headers["x-goog-hash"] += "crc32c=" + utils.encode_crc32c(
                self.metadata.crc32c.value
            )
        if "x_testbench_md5" in self.metadata.metadata:
            response.headers["x-goog-hash"] += ",md5Hash=" + str(self.metadata.md5)
        if response.headers["x-goog-hash"] == "":
            del response.headers["x-goog-hash"]
        return response
