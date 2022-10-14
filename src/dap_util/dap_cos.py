#!/usr/bin/env python3

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

from ssl import ALERT_DESCRIPTION_BAD_CERTIFICATE_STATUS_RESPONSE
from ibm_botocore.client import Config, ClientError
from pprint import pprint
import os, ibm_boto3, time, argparse
import dap_crypto, ibmcloud, dap_consts

BACKUP_BUCKET_NAME = 'dap-backup'
if "DAP_BACKUP_BUCKET" in os.environ:
    BACKUP_BUCKET_NAME = os.environ["DAP_BACKUP_BUCKET"]

def create_bucket(bucket_name, cos):
    print("Creating new bucket: {0}".format(bucket_name))
    try:
        cos.Bucket(bucket_name).create(
            CreateBucketConfiguration={
                "LocationConstraint": 'us-south-standard'
            }
        )
        print("Bucket: {0} created!".format(bucket_name))
    except ClientError as be:
        print("CLIENT ERROR: {0}".format(be))
    except Exception as e:
        print("Unable to create bucket: {0}".format(e))

def get_buckets(cos):
    print("Retrieving list of buckets")
    try:
        buckets = cos.buckets.all()
        for bucket in buckets:
            print("Bucket Name: {0}".format(bucket.name))
    except ClientError as be:
        print("CLIENT ERROR: {0}\n".format(be))
    except Exception as e:
        print("Unable to retrieve list buckets: {0}".format(e))

def put_item(bucket_name, item_name, item, cos):
    print("Creating new item: {0}".format(item_name))
    try:
        cos.Object(bucket_name, item_name).put(
            Body=item
        )
        print("Item: {0} created!".format(item_name))
    except ClientError as be:
        print("CLIENT ERROR: {0}\n".format(be))
    except Exception as e:
        print("Unable to create text file: {0}".format(e))

def get_item(bucket_name, item_name, cos):
    print("Retrieving item from bucket: {0}, key: {1}".format(bucket_name, item_name))
    try:
        file = cos.Object(bucket_name, item_name).get()
        item = file["Body"].read().decode('utf-8')
        print("File Contents: {0}".format(item))
        return item
    except ClientError as be:
        print("CLIENT ERROR: {0}\n".format(be))
    except Exception as e:
        print("Unable to retrieve file contents: {0}".format(e))

def delete_item(bucket_name, item_name, cos):
    print("Deleting item: {0}".format(item_name))
    try:
        cos.Object(bucket_name, item_name).delete()
        print("Item: {0} deleted!".format(item_name))
    except ClientError as be:
        print("CLIENT ERROR: {0}\n".format(be))
    except Exception as e:
        print("Unable to delete item: {0}".format(e))

def create_cos_client(name):
    cos_apikey = None
    cos_id = None

    if 'COS_API_KEY' in os.environ:
        cos_apikey = os.environ['COS_API_KEY']
    if 'COS_ID' in os.environ:
        cos_id = os.environ['COS_ID']

    if cos_apikey == None or cos_id == None:
        if 'DAP_ROOT_DIR' not in os.environ:
            raise Exception('DAP_ROOT_DIR environment variable is not set')
        if 'ENC_COS_API_KEY' not in os.environ:
            raise Exception('ENC_COS_API_KEY environment variable is not set')
        if 'ENC_COS_ID' not in os.environ:
            raise Exception('ENC_COS_ID environment variable is not set')

        dap_dir = os.environ['DAP_ROOT_DIR']

        # Decrypt COS API key and COS ID
        cos_apikey = dap_crypto.rsa_decrypt(dap_dir + '/build-time-keys/private.pem', os.environ['ENC_COS_API_KEY'])
        cos_id = dap_crypto.rsa_decrypt(dap_dir + '/build-time-keys/private.pem', os.environ['ENC_COS_ID'])

    print('cos_apikey: {}'.format(cos_apikey))
    print('cos_id: {}'.format(cos_id))

    endpoint_url = 'https://s3.us-south.cloud-object-storage.appdomain.cloud'
    if 'COS_ENDPOINT' in os.environ:
        endpoint_url = os.environ['COS_ENDPOINT']

    return ibm_boto3.resource(
        's3',
        ibm_api_key_id=cos_apikey,
        ibm_service_instance_id=cos_id,
        ibm_auth_endpoint='https://iam.cloud.ibm.com/identity/token',
        config=Config(signature_version="oauth"),
        endpoint_url=endpoint_url
    )

    # Create COS credentials
    '''
    cos_token = ibmcloud.get_token(cos_apikey)['access_token']
    cos_credentials = ibmcloud.create_credentials(name + '-cos-credentials', cos_id, cos_token)['credentials']
    print('cos-token: {}'.format(cos_token))
    pprint(cos_credentials)

    # Create COS client
    return ibm_boto3.resource(
        's3',
        ibm_api_key_id=cos_credentials['apikey'],
        ibm_service_instance_id=cos_credentials['resource_instance_id'],
        ibm_auth_endpoint='https://iam.cloud.ibm.com/identity/token',
        config=Config(signature_version="oauth"),
        endpoint_url='https://s3.us-south.cloud-object-storage.appdomain.cloud'
    )
    '''

def create_backup_bucket(cos_client, bucket_name=BACKUP_BUCKET_NAME):
    create_bucket(bucket_name, cos_client)

def backup_to_cos(name, record, cos_client, bucket_name=BACKUP_BUCKET_NAME):
    put_item(bucket_name, name, record, cos_client)

def encrypt_and_backup_to_cos(name, record, key1, key2, cos_client, bucket_name=BACKUP_BUCKET_NAME):
    encrypted_record = dap_crypto.hmac_and_encrypt_with_common_keys(record, key1, key2)
    backup_to_cos(name, encrypted_record, cos_client, bucket_name=bucket_name)

def get_backup_from_cos(name, cos_client, bucket_name=BACKUP_BUCKET_NAME):
    return get_item(bucket_name, name, cos_client)

def get_and_decrypt_backup_from_cos(name, key1, key2, cos_client, max_tries=dap_consts.COMMON_SECRETS_MAX_RETRIES, bucket_name=BACKUP_BUCKET_NAME):
    num_tries = 0
    while True:
        try:
            encrypted_backup = get_backup_from_cos(name, cos_client, bucket_name=bucket_name)
            return dap_crypto.decrypt_and_hmac_with_common_keys(encrypted_backup, key1, key2)
        except Exception as e:
            num_tries+=1
            if num_tries < max_tries:
                print('{}-th retry for common-secret decryption of {} after 5-sec sleeping'.format(num_tries, name))
                time.sleep(5)
            else:
                raise e

def encrypt_and_backup_to_cos_(args, key1, key2, cos_client):
    return encrypt_and_backup_to_cos(args.name, args.record, key1, key2, cos_client)

def get_and_decrypt_backup_from_cos_(args, key1, key2, cos_client):
    record = get_and_decrypt_backup_from_cos(args.name, key1, key2, cos_client)
    print(record)
    return record

def delete_(args, key1, key2, cos_client, bucket_name=BACKUP_BUCKET_NAME):
    delete_item(bucket_name, args.name, cos_client)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='commands')

    encrypt_backup_parser = subparsers.add_parser('encrypt_backup', help='Backup a record to COS with encryption')
    encrypt_backup_parser.add_argument('name')
    encrypt_backup_parser.add_argument('record')
    encrypt_backup_parser.set_defaults(func=encrypt_and_backup_to_cos_)

    get_decrypt_parser = subparsers.add_parser('get_decrypt', help='Get and recrypt a COS record')
    get_decrypt_parser.add_argument('name')
    get_decrypt_parser.set_defaults(func=get_and_decrypt_backup_from_cos_)

    delete_parser = subparsers.add_parser('delete', help='Delete a COS record')
    delete_parser.add_argument('name')
    delete_parser.set_defaults(func=delete_)

    key1, key2 = dap_crypto.derive_common_keys()
    cos_client = create_cos_client("CLI")

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args, key1, key2, cos_client)
    else:
        parser.parse_args('-h')
