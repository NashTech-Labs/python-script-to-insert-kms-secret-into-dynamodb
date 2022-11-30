import boto3
import os
import base64
import datetime

def insert_dynamo_secret(hash, value):
    kms = boto3.client("kms")
    encrypted = kms.encrypt(KeyId=os.environ["KEY_ARN"], Plaintext=value.encode("utf-8"))
    encoded = base64.b64encode(encrypted["CiphertextBlob"]).decode("utf-8")

    dynamo = boto3.client("dynamodb")
    response = dynamo.put_item(
        TableName=os.environ["DYNAMO_NAME"],
        Item = {
            "EntryHash": {
                "S": hash
            },
            "Value": {
                "S": encoded
            },
            "LastTouched": {
                "S": datetime.datetime.utcnow().isoformat()
            }
        }
    )

def retrieve_dynamo_secret(hash):
    kms = boto3.client("kms")
    dynamo = boto3.client("dynamodb")

    response = dynamo.get_item(
        TableName=os.environ["DYNAMO_NAME"],
        Key={
            "EntryHash": {
                "S": hash
            }
        }
    )

    decrypted = kms.decrypt(KeyId=os.environ["KEY_ARN"],
                            CiphertextBlob=base64.b64decode(response["Item"]["Value"]["S"].encode("utf-8")))
    return decrypted["Plaintext"].decode("utf-8")