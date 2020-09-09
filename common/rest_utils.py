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

from common import error
import json


class FakeRequest:
    def __init__(self, args, headers, data):
        self.args = args
        self.headers = headers
        self.data = data


def parse_multipart(request):
    content_type = request.headers.get("content-type")
    if content_type is None or not content_type.startswith("multipart/related"):
        error.abort(
            412, "Missing or invalid content-type header in multipart upload", None
        )
    _, _, boundary = content_type.partition("boundary=")
    if boundary is None:
        error.abort(
            412, "Missing boundary in content-type header in multipart upload", None
        )

    def parse_part(part):
        result = part.split(b"\r\n")
        if result[0] != b"" and result[-1] != b"":
            error.abort(412, "Could not parse %s" % str(part))
        result = list(filter(None, result))
        headers = {}
        if len(result) < 2:
            result.append(b"")
        for header in result[:-1]:
            key, value = header.split(b": ")
            headers[key.decode("utf-8")] = value.decode("utf-8")
        return headers, result[-1]

    boundary = bytearray(boundary, "utf-8")
    parts = request.data.split(b"--" + boundary)
    if parts[-1] != b"--\r\n":
        error.abort(412, "Missing end marker (--%s--) in media body" % boundary, None)
    _, resource = parse_part(parts[1])
    metadata = json.loads(resource)
    media_headers, media = parse_part(parts[2])
    return metadata, media_headers, media
