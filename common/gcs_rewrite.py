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
from common import gcs_object, hash_utils, process, rest_utils


class Rewrite:
    def __init__(
        self,
        src_bucket_name,
        src_object_name,
        dst_bucket_name,
        dst_object_name,
        rewrite_token,
        media,
        max_bytes_rewritten_per_call,
        request,
    ):
        self.src_bucket_name = src_bucket_name
        self.src_object_name = src_object_name
        self.dst_bucket_name = dst_bucket_name
        self.dst_object_name = dst_object_name
        self.rewrite_token = rewrite_token
        self.media = media
        self.max_bytes_rewritten_per_call = max_bytes_rewritten_per_call
        self.request = request

    def to_rest(self, request, fields=None):
        return process.message_to_rest(
            self.status,
            "storage#rewriteResponse",
            request.args.get("fields", fields),
        )

    @classmethod
    def init(
        cls,
        src_bucket_name,
        src_object_name,
        dst_bucket_name,
        dst_object_name,
        request,
        context,
    ):
        fake_request, max_bytes_rewritten_per_call = None, 1024 * 1024
        if context is not None:
            pass
        else:
            fake_request = rest_utils.FakeRequest(
                args=request.args.to_dict(), headers={}, data=request.data
            )
            max_bytes_rewritten_per_call = min(
                int(fake_request.args.get("maxBytesRewrittenPerCall", 1024 * 1024)),
                1024 * 1024,
            )
        rewrite_token = hash_utils.base64_md5(
            (
                "%s/o/%s/rewriteTo/b/%s/o/%s"
                % (
                    src_bucket_name,
                    src_object_name,
                    dst_bucket_name,
                    dst_object_name,
                )
            ).encode("utf-8")
        )
        return Rewrite(
            src_bucket_name,
            src_object_name,
            dst_bucket_name,
            dst_object_name,
            rewrite_token,
            b"",
            max_bytes_rewritten_per_call,
            fake_request,
        )
