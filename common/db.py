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

import os

from common import gcs_bucket, error, gcs_generation

import storage_pb2 as storage


class Database:
    def __init__(self, buckets, objects, live_generations, uploads, rewrites):
        self.buckets = buckets
        self.objects = objects
        self.live_generations = live_generations
        self.uploads = uploads
        self.rewrites = rewrites

    @classmethod
    def init(cls):
        return Database({}, {}, {}, {}, {})

    # === BUCKET === #

    @classmethod
    def __check_bucket_metageneration(cls, bucket, request, context):
        generation = bucket.metadata.metageneration
        match, not_match = gcs_generation.extract_generation_condition(
            request, True, False, context
        )
        gcs_generation.check_generic_generation(
            generation, match, not_match, True, context
        )

    def list_bucket(self, project, context):
        if project is None or project.endswith("-"):
            error.abort(
                412, "Invalid or missing project id in `Buckets: list`", context
            )
        return self.buckets.items()

    def get_bucket(self, bucket_name, request, context):
        bucket = self.buckets.get(bucket_name)
        if bucket is None:
            error.abort(404, "Bucket %s does not exist." % bucket_name, context)
        self.__check_bucket_metageneration(bucket, request, context)
        return bucket

    def insert_test_bucket(self):
        bucket_name = os.environ.get(
            "GOOGLE_CLOUD_CPP_STORAGE_TEST_BUCKET_NAME", "test-bucket"
        )
        if self.buckets.get(bucket_name) is None:
            request = storage.InsertBucketRequest(bucket={"name": bucket_name})
            bucket_test = gcs_bucket.Bucket.init(request, "")
            bucket_test.metadata.metageneration = 4
            bucket_test.metadata.versioning.enabled = True
            self.insert_bucket(bucket_test)

    def insert_bucket(self, bucket):
        self.buckets[bucket.metadata.name] = bucket
        self.objects[bucket.metadata.name] = {}
        self.live_generations[bucket.metadata.name] = {}

    def delete_bucket(self, bucket_name, request, context):
        self.get_bucket(bucket_name, request, context)
        del self.buckets[bucket_name]
        del self.objects[bucket_name]
        del self.live_generations[bucket_name]
        delete_upload = [
            upload_id
            for upload_id, upload in self.uploads.items()
            if upload.metadata.bucket == bucket_name
        ]
        for upload_id in delete_upload:
            del self.uploads[upload_id]

    # === OBJECT === #

    def __get_bucket_object(self, bucket_name, context):
        bucket = self.objects.get(bucket_name)
        if bucket is None:
            error.abort(404, "Bucket %s does not exist." % bucket_name, context)
        return bucket

    def check_bucket_exist(self, bucket_name, context):
        self.__get_bucket_object(bucket_name, context)

    @classmethod
    def __extract_list_object_request(cls, request, context):
        delimiter, prefix, versions = "", "", False
        start_offset, end_offset = "", None
        if context is not None:
            delimiter = request.delimiter
            prefix = request.prefix
            versions = request.versions
        else:
            delimiter = request.args.get("delimiter", "")
            prefix = request.args.get("prefix", "")
            versions = request.args.get("versions", False, type=bool)
            start_offset = request.args.get("startOffset", "")
            end_offset = request.args.get("endOffset")
        return delimiter, prefix, versions, start_offset, end_offset

    def list_object(self, bucket_name, request, context):
        bucket = self.__get_bucket_object(bucket_name, context)
        (
            delimiter,
            prefix,
            versions,
            start_offset,
            end_offset,
        ) = self.__extract_list_object_request(request, context)
        items = []
        prefixes = set()
        for obj in bucket.values():
            generation = obj.metadata.generation
            name = obj.metadata.name
            if not versions and generation != self.live_generations[bucket_name].get(
                name
            ):
                continue
            if name.find(prefix) != 0:
                continue
            if name < start_offset:
                continue
            if end_offset is not None and name >= end_offset:
                continue
            delimiter_index = name.find(delimiter, len(prefix))
            if delimiter != "" and delimiter_index > 0:
                prefixes.add(name[: delimiter_index + 1])
                continue
            items.append(obj.metadata)
        return items, list(prefixes)

    def check_object_generation(
        self, bucket_name, object_name, request, is_source, context
    ):
        bucket = self.__get_bucket_object(bucket_name, context)
        generation = gcs_generation.extract_object_generation(
            request, is_source, context
        )
        if generation == 0:
            generation = self.live_generations[bucket_name].get(object_name, 0)
        match, not_match = gcs_generation.extract_generation_condition(
            request, False, is_source, context
        )
        gcs_generation.check_generic_generation(
            generation, match, not_match, False, context
        )
        obj = bucket.get("%s#%d" % (object_name, generation))
        metageneration = obj.metadata.metageneration if obj is not None else None
        match, not_match = gcs_generation.extract_generation_condition(
            request, True, is_source, context
        )
        gcs_generation.check_generic_generation(
            metageneration, match, not_match, True, context
        )
        return obj, generation

    def get_object(self, bucket_name, object_name, request, is_source, context):
        obj, generation = self.check_object_generation(
            bucket_name, object_name, request, is_source, context
        )
        if obj is None:
            if generation == 0:
                error.abort(
                    404,
                    "Object %s does not have any live version." % object_name,
                    context,
                )
            else:
                error.abort(
                    404,
                    "Object %s does not have any version with generation %d."
                    % (object_name, generation),
                    context,
                )
        return obj

    def insert_object(self, bucket_name, obj, request, context):
        self.check_object_generation(
            bucket_name, obj.metadata.name, request, False, context
        )
        bucket = self.__get_bucket_object(bucket_name, context)
        name = obj.metadata.name
        generation = obj.metadata.generation
        bucket["%s#%d" % (name, generation)] = obj
        self.live_generations[bucket_name][name] = generation

    def delete_object(self, bucket_name, object_name, request, context):
        obj = self.get_object(bucket_name, object_name, request, False, context)
        generation = obj.metadata.generation
        live_generation = self.live_generations[bucket_name][object_name]
        if generation == live_generation:
            del self.live_generations[bucket_name][object_name]
        del self.objects[bucket_name]["%s#%d" % (object_name, generation)]

    # === UPLOAD === #

    def get_upload(self, upload_id, context):
        upload = self.uploads.get(upload_id)
        if upload is None:
            error.abort(404, "Upload %s does not exist." % upload_id, context)
        return upload

    def insert_upload(self, upload):
        self.uploads[upload.upload_id] = upload

    def delete_upload(self, upload_id, context):
        self.get_upload(upload_id, context)
        del self.uploads[upload_id]

    # === REWRITE === #

    def get_rewrite(self, token, context):
        rewrite = self.rewrites.get(token)
        if rewrite is None:
            error.abort(404, "Rewrite %s does not exist." % token, context)
        return rewrite

    def insert_rewrite(self, rewrite):
        self.rewrites[rewrite.rewrite_token] = rewrite

    def delete_rewrite(self, token, context):
        self.get_rewrite(token, context)
        del self.uploads[token]
