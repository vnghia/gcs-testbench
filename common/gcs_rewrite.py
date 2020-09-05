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

from google.protobuf.json_format import ParseDict

import storage_pb2 as storage
import utils
from common import gcs_object


class Rewrite:
    def __init__(
        self,
        request,
        context,
    ):
        if isinstance(request, storage.RewriteObjectRequest):
            self.request = request
        else:
            self.request = ParseDict(request.args, storage.RewriteObjectRequest())
        self.status = storage.RewriteResponse(
            rewrite_token=utils.compute_md5(
                (
                    self.request.source_bucket
                    + "/"
                    + self.request.source_object
                    + "to"
                    + self.request.destination_bucket
                    + "/"
                    + self.request.destination_object
                ).encode("utf-8")
            )
        )
        self.media = b""
        utils.insert_rewrite(self)

    def to_rest(self, request, fields=None):
        return utils.message_to_rest(
            self.status,
            "storage#rewriteResponse",
            request.args.get("fields", fields),
        )

    @classmethod
    def process_request(cls, request, context):
        token = request.args.get("rewriteToken")
        rewrite = (
            utils.lookup_rewrite(token) if token is not None else Rewrite(request, None)
        )
        source = gcs_object.Object.lookup(
            rewrite.request.source_bucket,
            rewrite.request.source_object,
            request.args,
            True,
            context,
        )
        total_bytes_rewritten = rewrite.status.total_bytes_rewritten
        total_bytes_rewritten += (
            1024 * 1024
            if 1024 * 1024 <= len(source.media) - total_bytes_rewritten
            else len(source.media) - total_bytes_rewritten
        )
        rewrite.status.object_size = len(source.media)
        rewrite.media += source.media[
            (rewrite.status.total_bytes_rewritten) : total_bytes_rewritten
        ]
        rewrite.status.total_bytes_rewritten = len(rewrite.media)
        if total_bytes_rewritten == len(source.media):
            utils.check_object_generation(
                rewrite.request.destination_bucket,
                rewrite.request.destination_object,
                request.args,
            )
            destination_metadata = source.metadata
            destination_metadata.bucket = rewrite.request.destination_bucket
            destination_metadata.name = rewrite.request.destination_object
            destination_obj = gcs_object.Object(
                destination_metadata,
                source.media,
                request.args,
                request.headers,
            )
            destination_obj.update(request.data)
            rewrite.status.object_size = rewrite.status.total_bytes_rewritten
            rewrite.status.done = True
            rewrite.status.rewrite_token = ""
            rewrite.status.resource.MergeFrom(destination_obj.metadata)
        result = rewrite.to_rest(request)
        return result
