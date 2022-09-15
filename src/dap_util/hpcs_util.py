# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import time, json, asn1, os, yaml
import grpc, server_pb2 as pb
from subprocess import check_output

def to_big_bytes(value, length=8):
    if type(value) is bool:
        return pb.AttributeValue(AttributeTF=value)
    if type(value) is bytes:
        return pb.AttributeValue(AttributeB=value)
    if type(value) is str:
        return pb.AttributeValue(AttributeB=value.encode('utf-8'))
    return pb.AttributeValue(AttributeI=value)

def ep11attributes(kv_pairs):
    attributes = {}
    for k in kv_pairs.keys():
        attributes[k] = to_big_bytes(kv_pairs[k])
    return attributes

# GetPubkeyBytesFromSPKI extracts a coordinate bit array from the public key in SPKI format
def GetPubkeyBytesFromSPKI(spki):
    decoder = asn1.Decoder()
    try:
        decoder.start(spki)
        decoder.enter()
        decoder.read() # read the initial sequence
        tag, pubkey = decoder.read()
        pubkey_bytearray = bytearray(pubkey)
        pubkey = bytes(pubkey_bytearray[1:]) # drop the first byte
        return pubkey
    except Exception as e:
        print(e)
        return None

class Channel:

    def __init__(self, credentials):
        credentials['API_KEY'] = os.environ['HPCS_API_KEY'] if os.environ.get('HPCS_API_KEY') is not None else credentials['API_KEY']
        credentials['ENDPOINT'] = os.environ['HPCS_ENDPOINT'] if os.environ.get('HPCS_ENDPOINT') is not None else credentials['ENDPOINT']
        credentials['GUID'] = os.environ['HPCS_GUID'] if os.environ.get('HPCS_GUID') is not None else credentials['GUID'] 
        self._authPlugin = self.AuthPlugin(credentials)
        self._clientKey = os.environ['HPCS_CLIENT_KEY'] if os.environ.get('HPCS_CLIENT_KEY') is not None else credentials['CLIENT_KEY']
        self._clientCert = os.environ['HPCS_CLIENT_CERT'] if os.environ.get('HPCS_CLIENT_CERT') is not None else credentials['CLIENT_CERT']

    def get_channel(self, address):
        if self._clientKey is not None and self._clientCert is not None:
            print('Using HPCS_CLIENT_KEY and HPCS_CLIENT_CERT')
            address = os.environ['HPCS_ADDRESS'] if os.environ.get('HPCS_ADDRESS') is not None else address
            private_key = self._clientKey.encode('utf-8')
            certificate_chain = self._clientCert.encode('utf-8')
            channel_credential = grpc.ssl_channel_credentials(
                                    private_key=private_key,
                                    certificate_chain=certificate_chain)
            call_credentials = grpc.metadata_call_credentials(self._authPlugin)
            composite_credentials = grpc.composite_channel_credentials(channel_credential, call_credentials)
            channel = grpc.secure_channel(address, composite_credentials)
            return channel
        if 'ZHSM_CREDENTIAL' in os.environ and os.environ['ZHSM_CREDENTIAL']:
            print('Using ZHSM_CREDENTIAL')
            with open(os.environ['ZHSM_CREDENTIAL']) as file:
                credential_file = yaml.safe_load(file)
                address = credential_file['url']
                root_certificates = open(credential_file['cacert_path'], 'rb').read()
                private_key = open(credential_file['key_path'], 'rb').read()
                certificate_chain = open(credential_file['cert_path'], 'rb').read()
                channel_credential = grpc.ssl_channel_credentials(
                                        root_certificates=root_certificates,
                                        private_key=private_key,
                                        certificate_chain=certificate_chain)
                channel = grpc.secure_channel(address, channel_credential)
                return channel
        if 'ZHSM' in os.environ and os.environ['ZHSM']:
            print('Using ZHSM')
            return grpc.insecure_channel(os.environ['ZHSM'])
        print('Using HPCS_ADDRESS')
        address = os.environ['HPCS_ADDRESS'] if os.environ.get('HPCS_ADDRESS') is not None else address
        call_credentials = grpc.metadata_call_credentials(self._authPlugin)
        channel_credential = grpc.ssl_channel_credentials()
        composite_credentials = grpc.composite_channel_credentials(channel_credential, call_credentials)
        channel = grpc.secure_channel(address, composite_credentials)
        return channel
        
    class AuthPlugin(grpc.AuthMetadataPlugin):
        
        def __init__(self, credentials):
            self._credentials = credentials
            self._access_token = ''
            self._expiration = int(time.time())
    
        def __call__(self, context, callback):
            #print('__call__ context=' + str(context))
            current = int(time.time())
            expiration = int(self._expiration) - 60 # set the expiration 60 sec before the actual one
            if expiration < current:
                self.get_access_token()

            metadata = (('authorization', 'Bearer {}'.format(self._access_token)),('bluemix-instance', '{}'.format(self._credentials['GUID'])),)
            callback(metadata, None)

        def get_access_token(self):
            apikey = self._credentials['API_KEY']
            endpoint = self._credentials['ENDPOINT']
            cmd = 'curl -sS -k -X POST --header "Content-Type: application/x-www-form-urlencoded" --header "Accept: application/json" --data-urlencode "grant_type=urn:ibm:params:oauth:grant-type:apikey" --data-urlencode "apikey=' + apikey + '" "' + endpoint + '/identity/token"'

            try:
                resp_str = check_output(cmd, shell=True).rstrip().decode('utf8')
            except Exception as e:
                print('an unexpected response from IAM_ENDPOINT=' + endpoint)
                print(e)
                import traceback
                traceback.print_exc()
                return None

            try:
                resp = json.loads(resp_str)
                self._expiration = resp['expiration']
                self._access_token = resp['access_token']
                return self._access_token
        
            except Exception as e:
                print('an unexpected response from IAM_ENDPOINT=' + self._endpoint)
                print('response=' + str(resp_str))
                print(e)
                import traceback
                traceback.print_exc()
                return None
        
    
