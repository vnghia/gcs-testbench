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

import base64
import random
import struct


def random_str(prefix):
    return prefix + str(random.getrandbits(32))


def random_bytes(prefix):
    return random_str(prefix).encode("utf-8")


def base64_crc32c(value):
    return base64.b64encode(struct.pack(">I", value)).decode("utf-8")
