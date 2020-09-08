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

import json
import re
from datetime import timezone

import dateutil
from flatdict import FlatterDict
from google.protobuf.json_format import MessageToDict

from common import error, hash_utils

remove_index = re.compile(r":[0-9]+|^[0-9]+")
split_fields = re.compile(r"[a-zA-Z0-9]*\(.*\)|[a-zA-Z0-9]+")


def nested_key(data):
    if isinstance(data, list):
        keys = []
        for i in range(len(data)):
            result = nested_key(data[i])
            if isinstance(result, list):
                if isinstance(data[i], dict):
                    keys.extend(["[%d].%s" % (i, item) for item in result])
                elif isinstance(data[i], list):
                    keys.extend(["[%d]%s" % (i, item) for item in result])
            elif result == "":
                keys.append("[%d]" % i)
        return keys
    elif isinstance(data, dict):
        keys = []
        for key, value in data.items():
            result = nested_key(value)
            if isinstance(result, list):
                if isinstance(value, dict):
                    keys.extend(["%s.%s" % (key, item) for item in result])
                elif isinstance(value, list):
                    keys.extend(["%s%s" % (key, item) for item in result])
            elif result == "":
                keys.append("%s" % key)
        return keys
    else:
        return ""


def to_dict(source):
    if not isinstance(source, dict):
        return source
    destination_dict = {}
    destination_list = []
    for key, value in source.items():
        if key.isdecimal():
            destination_list.append(to_dict(value))
        else:
            destination_dict[key] = to_dict(value)
    if len(destination_list) != 0:
        return destination_list
    else:
        return destination_dict


def process_data(data):
    flat = None
    if isinstance(data, bytes) or isinstance(data, str):
        flat = FlatterDict(json.loads(data))
    elif isinstance(data, dict):
        flat = FlatterDict(data)
    else:
        error.abort(500, "Data must be dict or bytes")
    delete_keys = []
    for key in flat.keys():
        if key.endswith("createdBefore"):
            flat[key] = (
                dateutil.parser.parse(flat[key])
                .replace(tzinfo=timezone.utc)
                .isoformat()
            )
        if "bucketPolicyOnly" in key:
            new_key = key.replace("bucketPolicyOnly", "uniformBucketLevelAccess", 1)
            if flat.get(new_key) is None:
                flat[new_key] = flat[key]
            delete_keys.append(key)
        if flat[key] is None:
            if key.endswith("updated"):
                delete_keys.append(key)
        if key == "kind":
            delete_keys.append(key)
    for key in delete_keys:
        del flat[key]
    return to_dict(flat.as_dict())


def fields_to_list(fields):
    if fields is None or not isinstance(fields, str):
        return []
    fields = fields.replace(" ", "")

    def field_to_dict(field):
        if "(" not in field and ")" not in field:
            return [field]
        items = re.split(r",|\(|\)", field)
        result = []
        for item in items[1:-1]:
            result.append(items[0] + ":" + item.replace("/", ":"))
        return result

    result = []
    for field in split_fields.findall(fields):
        result += field_to_dict(field)
    return result


def message_to_rest(
    message,
    kind,
    fields=None,
    list_size=0,
    preserving_proto_field_name=False,
):
    flat = FlatterDict(
        MessageToDict(message, preserving_proto_field_name=preserving_proto_field_name)
    )
    keep = fields_to_list(fields)
    for i in range(list_size):
        flat.setdefault("items:%d:kind" % i, kind[:-1])
    flat["kind"] = kind
    delete_key = []
    for key in flat.keys():
        if key.endswith("createdBefore"):
            flat[key] = dateutil.parser.parse(flat[key]).strftime("%Y-%m-%d")
        if key.endswith("crc32c"):
            flat[key] = hash_utils.base64_crc32c(flat[key])
        if fields is not None:
            re_key = remove_index.sub("", key)
            if re_key not in keep:
                delete_key.append(key)
    for key in delete_key:
        del flat[key]
    return to_dict(flat.as_dict())
