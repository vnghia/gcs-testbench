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

import crc32c
import grpc
from google.protobuf.empty_pb2 import Empty

import storage_pb2 as storage
import storage_pb2_grpc
import storage_resources_pb2 as resources
from common import gcs_bucket, gcs_object, gcs_upload, error

server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
db = None


class StorageServicer(storage_pb2_grpc.StorageServicer):
    # === BUCKET ===#
    def InsertBucket(self, request, context):
        db.insert_test_bucket()
        bucket = gcs_bucket.Bucket.init(request, context)
        db.insert_bucket(bucket)
        return bucket.metadata

    def ListBuckets(self, request, context):
        db.insert_test_bucket()
        result = resources.ListBucketsResponse(next_page_token="", items=[])
        for name, b in db.list_bucket(request.project, context):
            result.items.append(b.metadata)
        return result

    def GetBucket(self, request, context):
        bucket_name = request.bucket
        bucket = db.get_bucket(bucket_name, request, context)
        return bucket.metadata

    def DeleteBucket(self, request, context):
        bucket_name = request.bucket
        db.delete_bucket(bucket_name, request, context)
        return Empty()

    # === OBJECT === #
    def InsertObject(self, request_iterator, context):
        db.insert_test_bucket()
        upload, is_resumable = None, False
        for request in request_iterator:
            first_message = request.WhichOneof("first_message")
            if first_message == "upload_id":
                upload = db.get_upload(request.upload_id, context)
                if upload.complete:
                    error.abort(
                        400,
                        "Upload %s is already completed." % upload.upload_id,
                        context,
                    )
                is_resumable = True
            elif first_message == "insert_object_spec":
                insert_object_spec = request.insert_object_spec
                upload = gcs_upload.Upload.init(
                    insert_object_spec.resource.bucket, insert_object_spec, context
                )
            data = request.WhichOneof("data")
            checksummed_data = None
            if data == "checksummed_data":
                checksummed_data = request.checksummed_data
            elif data == "reference":
                checksummed_data = self.GetObjectMedia(
                    data.reference, context
                ).checksummed_data
            else:
                continue
            content = checksummed_data.content
            crc32c_hash = (
                checksummed_data.crc32c.value
                if checksummed_data.HasField("crc32c")
                else None
            )
            if crc32c_hash is not None and crc32c.crc32(content) != crc32c_hash:
                error.abort(412, "Mismatch crc32c in checksummed data.", context)
            upload.media += checksummed_data.content
            if request.finish_write:
                upload.complete = True
                break
        if not upload.complete:
            if not is_resumable:
                error.abort(400, "Request does not set finish_write", context)
            else:
                return
        obj = gcs_object.Object.init(
            upload.metadata, upload.media, upload.request, False, context
        )
        db.insert_object(obj.metadata.bucket, obj, upload.request, context)
        return obj.metadata

    def GetObjectMedia(self, request, context):
        obj = db.get_object(request.bucket, request.object, request, False, context)
        yield storage.GetObjectMediaResponse(
            checksummed_data={
                "content": obj.media,
                "crc32c": {"value": crc32c.crc32(obj.media)},
            },
            metadata=obj.metadata,
        )

    def DeleteObject(self, request, context):
        db.delete_object(request.bucket, request.object, request, context)
        return Empty()

    def StartResumableWrite(self, request, context):
        insert_object_spec = request.insert_object_spec
        upload = gcs_upload.Upload.init(
            insert_object_spec.resource.bucket, insert_object_spec, context
        )
        upload.metadata.metadata["x_testbench_upload"] = "resumable"
        db.insert_upload(upload)
        return storage.StartResumableWriteResponse(upload_id=upload.upload_id)

    def QueryWriteStatus(self, request, context):
        upload = db.get_upload(request.upload_id, context)
        return storage.QueryWriteStatusResponse(
            committed_size=len(upload.media), complete=upload.complete
        )


def run(port, database):
    global db
    db = database
    storage_pb2_grpc.add_StorageServicer_to_server(StorageServicer(), server)
    server.add_insecure_port("[::]:" + port)
    server.start()
