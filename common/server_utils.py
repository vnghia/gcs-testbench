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

from common import error, gcs_key
import json
from types import SimpleNamespace

protobuf_wrapper2args = {
    "if_generation_match": "ifGenerationMatch",
    "if_generation_not_match": "ifGenerationNotMatch",
    "if_metageneration_match": "ifMetagenerationMatch",
    "if_metageneration_not_match": "ifMetagenerationNotMatch",
    "if_source_generation_match": "ifSourceGenerationMatch",
    "if_source_generation_not_match": "ifSourceGenerationNotMatch",
    "if_source_metageneration_match": "ifSourceMetagenerationMatch",
    "if_source_metageneration_not_match": "ifSourceMetagenerationNotMatch",
}

protobuf_scalar2args = {
    "predefined_acl": "predefinedAcl",
    "destination_predefined_acl": "destinationPredefinedAcl",
    "generation": "generation",
    "source_generation": "sourceGeneration",
}


class FakeRequest(SimpleNamespace):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def HasField(self, field):
        return hasattr(self, field) and getattr(self, field) is not None

    @classmethod
    def init_protobuf(cls, request, context):
        fake_request = FakeRequest(args={}, headers={})
        fake_request.update_protobuf(request, context)
        return fake_request

    def update_protobuf(self, request, context):
        for proto_field, args_field in protobuf_wrapper2args.items():
            if hasattr(request, proto_field) and request.HasField(proto_field):
                self.args[args_field] = getattr(request, proto_field).value
                setattr(self, proto_field, getattr(request, proto_field))
        csek_field = "common_object_request_params"
        if hasattr(request, csek_field):
            algorithm, key_b64, key_sha256_b64 = gcs_key.extract_csek(
                request, False, context
            )
            self.headers["x-goog-encryption-algorithm"] = algorithm
            self.headers["x-goog-encryption-key"] = key_b64
            self.headers["x-goog-encryption-key-sha256"] = key_sha256_b64
            setattr(self, csek_field, getattr(request, csek_field))
        elif not hasattr(self, csek_field):
            setattr(
                self,
                csek_field,
                SimpleNamespace(
                    encryption_algorithm="", encryption_key="", encryption_key_sha256=""
                ),
            )


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


def xml_headers_to_json_args(headers, args):
    field_map = {
        "x-goog-if-generation-match": "ifGenerationMatch",
        "x-goog-if-meta-generation-match": "ifMetagenerationMatch",
        "x-goog-acl": "predefinedAcl",
    }
    for field_xml, field_json in field_map.items():
        if field_xml in headers:
            args[field_json] = headers[field_xml]
