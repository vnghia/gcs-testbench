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

import hashlib
import json
import re

import flask
from google.protobuf.json_format import ParseDict
import storage_resources_pb2 as resources

from common import error, process, rest_utils

content_range_split = re.compile(r"bytes (\*|[0-9]+-[0-9]+)\/(\*|[0-9]+)")


class Upload:
    def __init__(self, metadata, upload_id, location, media, complete, request):
        self.metadata = metadata
        self.upload_id = upload_id
        self.location = location
        self.media = media
        self.complete = complete
        self.request = request

    @classmethod
    def init(cls, bucket_name, request, context):
        # TODO(vnvo2409): Construct request for both gRPC and REST
        metadata, location = None, ""
        if context is not None:
            metadata = request.resource
        else:
            name = request.args.get("name", "")
            if len(request.data) > 0:
                if name != "":
                    error.abort(
                        400,
                        "The name argument is only supported for empty payloads",
                        context,
                    )
                data = json.loads(request.data)
                metadata = ParseDict(process.process_data(data), resources.Object())
            else:
                metadata = resources.Object()
                metadata.name = name
            if metadata.content_type == "":
                metadata.content_type = request.headers.get(
                    "x-upload-content-type", "application/octet-stream"
                )
            location = (
                request.host_url
                + "upload/storage/v1/b/test-bucket/o?uploadType=resumable"
            )
            headers = {
                key.lower(): value
                for key, value in request.headers.items()
                if key.lower().startswith("x-")
            }
            request = rest_utils.FakeRequest(
                args=request.args.to_dict(), headers=headers, data=b""
            )
        if metadata.name == "":
            error.abort(400, "Missing object name argument", context)
        metadata.bucket = bucket_name
        upload_id = hashlib.sha256(
            ("%s/o/%s" % (bucket_name, metadata.name)).encode("utf-8")
        ).hexdigest()
        location = "%s&upload_id=%s" % (location, upload_id)
        return Upload(metadata, upload_id, location, b"", False, request)

    # === UTILS === #

    def to_rest(self):
        response = flask.make_response("")
        response.headers["Location"] = self.location
        return response

    def status_rest(self):
        response = flask.make_response()
        if len(self.media) > 1 and not self.complete:
            response.headers["Range"] = "bytes=0-%d" % (len(self.media) - 1)
        response.data = "" if not self.complete else self.media
        response.status_code = 308 if not self.complete else 200
        return response
