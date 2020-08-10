import re

import flask
from google.protobuf.json_format import MessageToDict, Parse, ParseDict

import storage_pb2 as storage
import storage_resources_pb2 as resources
import utils

content_range_split = re.compile(r"bytes (\*|[0-9]+-[0-9]+)\/(\*|[0-9]+)")


class Upload:
    def __init__(self, bucket_name, request, resumable=True, context=None):
        host_url = ""
        self.inject_upload_data_error = False
        if isinstance(request, storage.InsertObjectSpec):
            utils.check_object_generation(
                request.resource.bucket, request.resource.name, request, context=context
            )
            self.metadata = request.resource
        else:
            self.inject_upload_data_error = (
                request.headers.get("x-goog-testbench-instructions")
                == "inject-upload-data-error"
            )
            metadata = dict()
            metadata["bucket"] = bucket_name
            metadata["contentType"] = request.headers.get(
                "x-upload-content-type", "application/octet-stream"
            )
            if "x-upload-content-length" in request.headers:
                metadata["size"] = int(request.headers.get("x-upload-content-length"))
            if request.args.get("name") is not None and len(request.data):
                utils.abort(
                    400, "The name argument is only supported for empty payloads",
                )
            if len(request.data):
                metadata.update(json.loads(request.data))
            else:
                metadata["name"] = request.args.get("name")
            if metadata.get("name") is None:
                utils.abort(400, "Missing object name argument")
            utils.check_object_generation(bucket_name, metadata["name"], request.args)
            self.metadata = ParseDict(utils.process_data(metadata), resources.Object())
            host_url = request.host_url
        self.upload_id = utils.compute_etag(
            self.metadata.bucket + "/o/" + self.metadata.name
        ).decode("utf-8")
        self.location = (
            host_url
            + "upload/storage/v1/b/%s/o?uploadType=resumable&upload_id=%s"
            % (self.metadata.bucket, self.upload_id)
        )
        self.media = b""
        self.committed_size = len(self.media)
        self.complete = False
        if resumable:
            utils.insert_upload(self)

    @classmethod
    def lookup(cls, upload_id, context=None):
        upload = utils.lookup_upload(upload_id)
        if upload is None:
            utils.abort(404, "Upload %s does not exist" % upload_id, context)
        return upload

    def to_rest(self):
        response = flask.make_response("")
        response.headers["Location"] = self.location
        return response

    def status_rest(self):
        response = flask.make_response()
        if self.committed_size > 1 and not self.complete:
            response.headers["Range"] = "bytes=0-%d" % (self.committed_size - 1)
        response.data = "" if not self.complete else self.media
        response.status_code = 308 if not self.complete else 200
        return response

    def __process_request_grpc(self, request):
        pass

    def __process_request_rest(self, request):
        content_range = request.headers.get("content-range")
        content_length = request.headers.get("content-length")
        if content_range is not None:
            items = list(content_range_split.match(content_range).groups())
            if len(items) != 2 or (items[0] == items[1] and items[0] != "*"):
                utils.abort(400, "Invalid Content-Range in upload %s" % content_range)
            if items[1] != "*":
                if self.metadata.size != 0 and self.metadata.size != int(items[1]):
                    utils.abort(
                        400,
                        "X-Upload-Content-Length"
                        "validation failed. Expected=%d, got %d."
                        % (self.metadata.size, int(items[1])),
                    )
                if self.committed_size == int(items[1]):
                    self.complete = True
                    return
            if items[0] == "*":
                return self.status_rest()
            else:
                self.media += utils.extract_media(request)
                self.committed_size = len(self.media)
                self.complete = (
                    self.committed_size == int(items[1]) if items[1] != "*" else False
                )
                if self.complete and self.inject_upload_data_error:
                    self.media = utils.corrupt_media(self.media)

    def process_request(self, request):
        if isinstance(request, storage.InsertObjectRequest):
            self.__process_request_grpc(request)
        else:
            self.__process_request_rest(request)
