import storage_resources_pb2 as resources
import utils
import json
import re
import random

from crc32c import crc32
from hashlib import md5
from google.iam.v1 import policy_pb2
from google.protobuf.json_format import ParseDict, MessageToDict, Parse


class Object:
    def __init__(self, bucket_name, object_name="", request=None, addition=None):
        payload = dict()
        payload["bucket"] = bucket_name
        self.content = bytes()
        self.testbench = dict()
        if request is not None:
            upload_type = request.args.get("uploadType")
            if upload_type == "multipart":
                payload, content = self.__init__multipart(payload, request)
                self.content = content
            elif upload_type == "media":
                payload["name"] = request.args.get("name", object_name)
                self.content = request.data
        else:
            payload["name"] = object_name
        if isinstance(addition, dict):
            payload.update(addition)
        self.metadata = ParseDict(payload, resources.Object())
        self.old_metadatas = {str(self.metadata.generation): self.metadata}
        utils.insert_object(self)

    @classmethod
    def insert(cls, bucket_name, object_name="", request=None, addition=None):
        upload_type = request.args.get("uploadType")
        if upload_type == "resumable":
            x_upload_content_type = request.headers.get(
                "x-upload-content-type", "application/octet-stream"
            )
            x_upload_content_length = request.headers.get("x-upload-content-length")
            expected_bytes = None
            if x_upload_content_length:
                expected_bytes = int(x_upload_content_length)

            if request.args.get("name") is not None and len(request.data):
                utils.abort(
                    400, "The name argument is only supported for empty payloads"
                )
            metadata = None
            if len(request.data):
                metadata = json.loads(request.data)
            else:
                metadata = {"name": request.args.get("name")}
            if metadata.get("name") is None:
                utils.abort(400, "Missing object name argument")
            metadata.setdefault("contentType", x_upload_content_type)

        name = request.args.get("name", object_name)
        obj = utils.all_objects(bucket_name).get(name)
        if obj is None:
            return Object(bucket_name, object_name, request, addition)
        if upload_type == "multipart":
            payload = utils.ToRestDict(obj.metadata)
            payload, content = obj.__init__multipart(payload, request)
            obj.content = content
            obj.metadata = ParseDict(payload, obj.metadata)
            return obj
        elif upload_type == "media":
            obj.content = request.data
            obj.metadata.generation += 1
            return obj

    def __init__multipart(self, payload, request):
        metadata, media_headers, media = self.__parse_multipart_request(request)
        payload["name"] = request.args.get("name", metadata.get("name", None))
        if payload["name"] is None:
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
        payload["content_type"] = media_headers.get("content-type")
        payload["size"] = len(media)
        payload["crc32c"] = crc32(media)
        payload["md5_hash"] = md5(media).hexdigest()
        self.testbench["x_testbench_upload"] = "multipart"
        if "md5Hash" in metadata:
            self.testbench["x_testbench_md5"] = metadata["md5Hash"]
        if "crc32c" in metadata:
            self.testbench["x_testbench_crc32c"] = metadata["crc32c"]
        return payload, media

    @classmethod
    def __parse_multipart_request(cls, request):
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
    def __to_rest(cls, metadata, request=None, projection=None, testbench=None):
        result = utils.ToRestDict(metadata, "storage#object")
        if request is not None:
            projection = request.args.get("projection", projection)
            fields = request.args.getlist("fields")
            if len(fields) != 0:
                deletes = [key for key in result if key not in fields]
                for field in deletes:
                    del result[field]
            if projection is None or projection == "noAcl":
                result.pop("acl", None)
                result.pop("owner", None)
            if isinstance(testbench, dict):
                result.update(testbench)
        return result

    def to_rest(self, request=None, projection=None, use_testbench=True):
        testbench = None
        if use_testbench:
            testbench = self.testbench
        return self.__to_rest(self.metadata, request, projection, testbench)

    def old_metadatas_to_rest(self, request=None, projection=None, use_testbench=True):
        testbench = None
        if use_testbench:
            testbench = self.testbench
        return [
            self.__to_rest(metadata, request, projection, testbench)
            for metadata in self.old_metadatas.values()
        ]

    @classmethod
    def list(cls, bucket_name, request=None):
        prefix = ""
        delimiter = ""
        start_offset = ""
        end_offset = ""
        if request is not None:
            prefix = request.args.get("prefix", prefix)
            delimiter = request.args.get("delimiter", delimiter)
            start_offset = request.args.get("startOffset", start_offset)
            end_offset = request.args.get("endOffset", end_offset)
        items = []
        prefixes = set()
        for name, obj in utils.all_objects(bucket_name).items():
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
            items.append(obj)
        return items, list(prefixes)

    @classmethod
    def lookup(
        cls,
        bucket_name,
        object_name,
        request,
        if_generation_match="ifGenerationMatch",
        if_generation_not_match="ifGenerationNotMatch",
        if_metageneration_match="ifMetagenerationMatch",
        if_metageneration_not_match="ifMetagenerationNotMatch",
    ):
        obj = utils.all_objects(bucket_name).get(object_name)
        if obj is None:
            utils.abort(404, "Object %s does not exist" % object_name)

        generation_match = request.args.get(if_generation_match)
        generation_not_match = request.args.get(if_generation_not_match)
        metageneration_match = request.args.get(if_metageneration_match)
        metageneration_not_match = request.args.get(if_metageneration_not_match)
        generation = obj.metadata.generation
        if generation_match is not None and generation_match != generation:
            utils.abort(412, "Precondition Failed")
        if generation_not_match is not None and generation_not_match == generation:
            utils.abort(412, "Precondition Failed")
        metageneration = obj.metadata.metageneration
        if (
            metageneration_not_match is not None
            and metageneration_not_match == metageneration
        ):
            utils.abort(412, "Precondition Failed")
        if metageneration_match is not None and metageneration_match != metageneration:
            utils.abort(412, "Precondition Failed")

        return obj

    def get_generation(self, request, to_rest=True):
        generation = request.args.get("generation")
        if generation is None:
            generation = request.args.get("sourceGeneration")
        if generation is None:
            if to_rest:
                return self.__to_rest(self.metadata, request, testbench=self.testbench)
            else:
                return self.metadata
        if self.old_metadatas.get(generation) is None:
            utils.abort(404, "Generation %s does not exist" % generation)
        if to_rest:
            return self.__to_rest(
                self.old_metadatas[generation], request, testbench=self.testbench
            )
        else:
            return self.old_metadatas[generation]

    def update(self, request):
        payload = utils.ToProtoDict(request.data)
        projection = "noAcl"
        if "acl" in payload:
            projection = "full"
        self.metadata = ParseDict(payload, self.metadata)
        return projection

    def delete(self):
        print(self.to_rest())
        print(self.metadata.bucket, " ", self.metadata.name)
        utils.delete_object(self.metadata.bucket, self.metadata.name)
