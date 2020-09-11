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
import hashlib
import json
import base64


def extract_csek(request, is_source, context):
    algorithm, key_b64, key_sha256_b64 = "", "", ""
    if context is None:
        algorithm_field = (
            "x-goog-encryption-algorithm"
            if not is_source
            else "x-goog-copy-source-encryption-algorithm"
        )
        key_field = (
            "x-goog-encryption-key"
            if not is_source
            else "x-goog-copy-source-encryption-key"
        )
        key_sha256_field = (
            "x-goog-encryption-key-sha256"
            if not is_source
            else "x-goog-copy-source-encryption-key-sha256"
        )
        algorithm = request.headers.get(algorithm_field, "")
        key_b64 = request.headers.get(key_field, "")
        key_sha256_b64 = request.headers.get(key_sha256_field, "")
    else:
        algorithm = request.common_object_request_params.encryption_algorithm
        key_b64 = request.common_object_request_params.encryption_key
        key_sha256_b64 = request.common_object_request_params.encryption_key_sha256
    return algorithm, key_b64, key_sha256_b64


def abort_csek_error(code, context):
    msg = "Missing a SHA256 hash of the encryption key, or it is not"
    msg += " base64 encoded, or it does not match the encryption key."
    link = "https://cloud.google.com/storage/docs/encryption#customer-supplied_encryption_keys"
    error_msg = {
        "error": {
            "errors": [
                {
                    "domain": "global",
                    "reason": "customerEncryptionKeySha256IsInvalid",
                    "message": msg,
                    "extendedHelp": link,
                }
            ],
            "code": code,
            "message": msg,
        }
    }
    error.abort(code, json.dumps(error_msg), context)


def check_csek(algorithm, key_b64, key_sha256_b64, context):
    if algorithm != "AES256":
        error.abort(400, "Invalid or missing algorithm %s for CSEK" % algorithm)
    key = base64.standard_b64decode(key_b64)
    if len(key) != 256 / 8:
        abort_csek_error(400, context)
    expected_sha256 = base64.standard_b64decode(key_sha256_b64)
    actual_sha256 = hashlib.sha256(key).digest()
    if expected_sha256 != actual_sha256:
        abort_csek_error(400, context)
    return actual_sha256
