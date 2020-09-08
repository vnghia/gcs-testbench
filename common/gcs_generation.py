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

# === COMMON === #


def extract_generation_condition_grpc(request, is_meta, is_source):
    match_field = ""
    not_match_field = ""
    if is_meta:
        match_field = (
            "if_metageneration_match"
            if not is_source
            else "if_source_metageneration_match"
        )
        not_match_field = (
            "if_metageneration_not_match"
            if not is_source
            else "if_source_metageneration_not_match"
        )
    else:
        match_field = (
            "if_generation_match" if not is_source else "if_source_generation_match"
        )
        not_match_field = (
            "if_generation_not_match"
            if not is_source
            else "if_source_generation_not_match"
        )
    match = (
        getattr(request, match_field, None).value
        if request.HasField(match_field)
        else None
    )
    not_match = (
        getattr(request, not_match_field, None).value
        if request.HasField(not_match_field)
        else None
    )
    return match, not_match


def extract_generation_condition_rest(request, is_meta, is_source):
    match_field = ""
    not_match_field = ""
    if is_meta:
        match_field = (
            "ifMetagenerationMatch" if not is_source else "ifSourceMetagenerationMatch"
        )
        not_match_field = (
            "ifMetagenerationNotMatch"
            if not is_source
            else "ifSourceMetagenerationNotMatch"
        )
    else:
        match_field = (
            "ifGenerationMatch" if not is_source else "ifSourceGenerationMatch"
        )
        not_match_field = (
            "ifGenerationNotMatch" if not is_source else "ifSourceGenerationNotMatch"
        )
    match = int(request.args.get(match_field)) if match_field in request.args else None
    not_match = (
        int(request.args.get(not_match_field))
        if not_match_field in request.args
        else None
    )
    return match, not_match


def extract_generation_condition(request, is_meta, is_source, context):
    match = None
    not_match = None
    if context is not None:
        match, not_match = extract_generation_condition_grpc(
            request, is_meta, is_source
        )
    else:
        match, not_match = extract_generation_condition_rest(
            request, is_meta, is_source
        )
    return match, not_match


def check_generic_generation(generation, match, not_match, is_meta, context):
    message = "generation" if not is_meta else "metageneration"
    if generation is not None and not_match is not None and not_match == generation:
        error.abort(
            412,
            "Precondition Failed (%s = %s vs %s_not_match = %s)"
            % (message, generation, message, not_match),
            context,
        )
    if generation is not None and match is not None and match != generation:
        error.abort(
            412,
            "Precondition Failed (%s = %s vs %s_match = %s)"
            % (message, generation, message, match),
            context,
        )


# === OBJECT === #


def extract_object_generation(request, is_source, context):
    if context is not None:
        extract_field = "generation" if not is_source else "source_generation"
        return getattr(request, extract_field, 0)
    else:
        extract_field = "generation" if not is_source else "sourceGeneration"
        return int(request.args.get(extract_field, 0))
