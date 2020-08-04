import logging

import grpc

import storage_pb2 as storage
import storage_pb2_grpc
import storage_resources_pb2 as resources
import storage_resources_pb2_grpc


def run():
    with grpc.insecure_channel("localhost:8000") as channel:
        stub = storage_pb2_grpc.StorageStub(channel)
        bucket = resources.Bucket(name="name")
        response = stub.InsertBucket(storage.InsertBucketRequest(bucket=bucket))
    print(response)


if __name__ == "__main__":
    logging.basicConfig()
    run()
