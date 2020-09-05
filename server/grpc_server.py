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

from concurrent import futures

import grpc
from google.protobuf.empty_pb2 import Empty

import storage_pb2 as storage
import storage_pb2_grpc
import storage_resources_pb2 as resources
import utils
from common import gcs_bucket, gcs_object, gcs_upload

server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))


class StorageServicer(storage_pb2_grpc.StorageServicer):
    def InsertBucket(self, request, context):
        gcs_bucket.Bucket.insert_test_bucket()
        bucket = gcs_bucket.Bucket(request.bucket, context=context)
        return bucket.metadata

    def ListBuckets(self, request, context):
        gcs_bucket.Bucket.insert_test_bucket()
        result = resources.ListBucketsResponse(next_page_token="", items=[])
        for name, b in gcs_bucket.Bucket.list(request.project, context=context):
            result.items.append(b.metadata)
        return result

    def GetBucket(self, request, context):
        bucket_name = request.bucket
        bucket = gcs_bucket.Bucket.lookup(bucket_name, request, context=context)
        return bucket.metadata

    def DeleteBucket(self, request, context):
        bucket_name = request.bucket
        bucket = gcs_bucket.Bucket.lookup(bucket_name, request, context=context)
        bucket.delete()
        return Empty()

    def InsertObject(self, request_iterator, context):
        gcs_bucket.Bucket.insert_test_bucket()
        upload = None
        for request in request_iterator:
            first_message = request.WhichOneof("first_message")
            if first_message == "upload_id":
                upload = gcs_upload.Upload.lookup(request.upload_id, context=context)
            elif first_message == "insert_object_spec":
                insert_object_spec = request.insert_object_spec
                upload = gcs_upload.Upload(
                    insert_object_spec.resource.bucket,
                    insert_object_spec,
                    resumable=False,
                    context=context,
                )
            upload.media += request.checksummed_data.content
            upload.committed_size = len(upload.media)
            if request.finish_write:
                upload.complete = True
                break
        if not upload.complete:
            utils.abort(400, "Request does not set finish_write", context=context)
        obj = gcs_object.Object(upload.metadata, upload.media)
        return obj.metadata

    def GetObjectMedia(self, request, context):
        obj = gcs_object.Object.lookup(request.bucket, request.object, request)
        yield storage.GetObjectMediaResponse(
            checksummed_data={"content": obj.media}, metadata=obj.metadata
        )

    def DeleteObject(self, request, context):
        obj = gcs_object.Object.lookup(request.bucket, request.object, request)
        obj.delete()
        return Empty()

    def StartResumableWrite(self, request, context):
        insert_object_spec = request.insert_object_spec
        upload = gcs_upload.Upload(
            insert_object_spec.resource.bucket, insert_object_spec, context=context
        )
        upload.metadata.metadata["x_testbench_upload"] = "resumable"
        return storage.StartResumableWriteResponse(upload_id=upload.upload_id)

    def QueryWriteStatus(self, request, context):
        upload = gcs_upload.Upload.lookup(request.upload_id, context=context)
        return storage.QueryWriteStatusResponse(
            committed_size=upload.committed_size, complete=upload.complete
        )


def run(port):
    storage_pb2_grpc.add_StorageServicer_to_server(StorageServicer(), server)
    server.add_insecure_port("[::]:" + port)
    server.start()
