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

import crc32c
import base64
import random
import struct
import hashlib


def random_str(prefix):
    return prefix + str(random.getrandbits(32))


def random_bytes(prefix):
    return random_str(prefix).encode("utf-8")


def base64_int(value):
    return base64.b64encode(struct.pack(">I", value)).decode("utf-8")


def base64_crc32c(value):
    return base64_int(crc32c.crc32(value))


def debase64_crc32c(value):
    return struct.unpack(">I", base64.b64decode(value.encode("utf-8")))[0]


def debase64_md5(value):
    return base64.b64decode(value.encode("utf-8")).hex()


def debase64_str(value):
    return base64.b64decode(value.encode("utf-8")).hex()


def random_bigint(size=63):
    return random.getrandbits(size)


def base64_bytes(content):
    return base64.b64encode(content).decode("utf-8")


def base64_md5(content):
    return base64_bytes(hashlib.md5(content).digest())
