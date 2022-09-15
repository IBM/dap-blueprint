#!/usr/bin/env python3

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import hpcs_util as util

import uuid, grpc, hashlib, asn1, os, argparse
import server_pb2 as pb, server_pb2_grpc
import grep11consts as ep11
import dap_crypto, hpcs_util
# import grep11consts as ep11
# import dap_crypto

# The following IBM Cloud items need to be changed prior to running the sample program
hpcs_address_template = "<grep11_server_address>:<port>"

hpcs_credentials_template = {
    'API_KEY':   "<ibm_cloud_apikey>",
    'ENDPOINT': "<https://<iam_ibm_cloud_endpoint>",
    'GUID': "<hpcs_guid>",
    'CLIENT_KEY': None,
    'CLIENT_CERT': None
}

def create_credentials_and_address():
    hpcs_credentials = {
        'API_KEY': None,
        'ENDPOINT': None,
        'GUID': None,
        'CLIENT_KEY': None,
        'CLIENT_CERT': None
    }
    hpcs_address = None

    if 'DAP_ROOT_DIR' not in os.environ:
        raise Exception('DAP_ROOT_DIR environment variable is not set')
    dap_dir = os.environ['DAP_ROOT_DIR']

    if (   'ENC_HPCS_API_KEY' in os.environ and os.environ['ENC_HPCS_API_KEY']
        and 'ENC_HPCS_ENDPOINT' in os.environ and os.environ['ENC_HPCS_ENDPOINT']
        and 'ENC_HPCS_GUID' in os.environ and os.environ['ENC_HPCS_GUID']
        and 'ENC_HPCS_ADDRESS' in os.environ and os.environ['ENC_HPCS_ADDRESS']):
        # Decrypt HPCS credentials
        hpcs_credentials['API_KEY'] = dap_crypto.rsa_decrypt(dap_dir + '/build-time-keys/private.pem', os.environ['ENC_HPCS_API_KEY'])
        hpcs_credentials['ENDPOINT'] = dap_crypto.rsa_decrypt(dap_dir + '/build-time-keys/private.pem', os.environ['ENC_HPCS_ENDPOINT'])
        hpcs_credentials['GUID'] = dap_crypto.rsa_decrypt(dap_dir + '/build-time-keys/private.pem', os.environ['ENC_HPCS_GUID'])
        hpcs_address = dap_crypto.rsa_decrypt(dap_dir + '/build-time-keys/private.pem', os.environ['ENC_HPCS_ADDRESS'])

    if (    'ENC_HPCS_CLIENT_KEY_AES_ENC_KEY' in os.environ and os.environ['ENC_HPCS_CLIENT_KEY_AES_ENC_KEY']
        and 'ENC_HPCS_CLIENT_KEY1' in os.environ and os.environ['ENC_HPCS_CLIENT_KEY1']
        and 'ENC_HPCS_CLIENT_KEY2' in os.environ and os.environ['ENC_HPCS_CLIENT_KEY2']
        and 'ENC_HPCS_CLIENT_CERT_AES_ENC_KEY' in os.environ and os.environ['ENC_HPCS_CLIENT_CERT_AES_ENC_KEY']
        and 'ENC_HPCS_CLIENT_CERT' in os.environ and os.environ['ENC_HPCS_CLIENT_CERT']):
        hpcs_credentials['CLIENT_KEY'] = dap_crypto.rsa_decrypt_long(dap_dir + '/build-time-keys/private.pem', os.environ['ENC_HPCS_CLIENT_KEY1'] + os.environ['ENC_HPCS_CLIENT_KEY2'], os.environ['ENC_HPCS_CLIENT_KEY_AES_ENC_KEY'])
        hpcs_credentials['CLIENT_CERT'] = dap_crypto.rsa_decrypt_long(dap_dir + '/build-time-keys/private.pem', os.environ['ENC_HPCS_CLIENT_CERT'], os.environ['ENC_HPCS_CLIENT_CERT_AES_ENC_KEY'])

    if (    'ENC_GREP11_HOST' in os.environ and os.environ['ENC_GREP11_HOST']
        and 'ENC_GREP11_CERT' in os.environ and os.environ['ENC_GREP11_CERT']
        and 'ENC_GREP11_CERT_AES_ENC_KEY' in os.environ and os.environ['ENC_GREP11_CERT_AES_ENC_KEY']
        and 'ENC_GREP11_KEY' in os.environ and os.environ['ENC_GREP11_KEY']
        and 'ENC_GREP11_KEY_AES_ENC_KEY' in os.environ and os.environ['ENC_GREP11_KEY_AES_ENC_KEY']
        and 'ENC_GREP11_CACERT' in os.environ and os.environ['ENC_GREP11_CACERT']
        and 'ENC_GREP11_CACERT_AES_ENC_KEY' in os.environ and os.environ['ENC_GREP11_CACERT_AES_ENC_KEY']):
        dir = '/grep11_credentials'
        os.mkdir(dir)
        grep11_cert = dap_crypto.rsa_decrypt_long(dap_dir + '/build-time-keys/private.pem', os.environ['ENC_GREP11_CERT'], os.environ['ENC_GREP11_CERT_AES_ENC_KEY'])
        with open(dir + '/client.pem') as file:
            file.write('-----BEGIN CERTIFICATE-----')
            file.write(grep11_cert)
            file.write('-----END CERTIFICATE-----')
            file.close()
        grep11_key = dap_crypto.rsa_decrypt_long(dap_dir + '/build-time-keys/private.pem', os.environ['ENC_GREP11_KEY'], os.environ['ENC_GREP11_KEY_AES_ENC_KEY'])
        with open(dir + '/client-key.pem') as file:
            file.write('-----BEGIN RSA PRIVATE KEY-----')
            file.write(grep11_key)
            file.write('-----END RSA PRIVATE KEY-----')
            file.close()
        grep11_cacert = dap_crypto.rsa_decrypt_long(dap_dir + '/build-time-keys/private.pem', os.environ['ENC_GREP11_CACERT'], os.environ['ENC_GREP11_CACERT_AES_ENC_KEY'])
        with open(dir + '/ca.pem') as file:
            file.write('-----BEGIN CERTIFICATE-----')
            file.write(grep11_cacert)
            file.write('-----END CERTIFICATE-----')
            file.close()
        grep11_host = dap_crypto.rsa_decrypt(dap_dir + '/build-time-keys/private.pem', os.environ['ENC_GREP11_HOST']),
        with open(dir + '/grep11_credential.yaml') as file:
            file.write('url: \"' + grep11_host + '\"')
            file.write('cert_path: \"' + dir + '/client.pem\"')
            file.write('key_path: \"' + dir + '/client-key.pem\"')
            file.write('cacert_path: \"' + dir + '/cap.pem\"')
            file.close()

    print('hpcs_credentials={}'.format(hpcs_credentials))
    print('hpcs_address={}'.format(hpcs_address))

    return hpcs_credentials, hpcs_address

def get_pubkey_bytes_from_spki(spki):
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

def convert_to_bytes(doc):
    if type(doc) is str:
        return doc.encode('utf-8')
    elif type(doc) is bytes:
        return doc
    else:
        raise Exception('Cannot convert to bytes ' + str(type(doc)))

def gen_key_pair(hpcs_credentials=hpcs_credentials_template, hpcs_address=hpcs_address_template):
    with util.Channel(hpcs_credentials).get_channel(hpcs_address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)
        
	        # Generate RSA key pairs
            publicExponent = b'\x11'
            publicKeyTemplate=util.ep11attributes({
                ep11.CKA_ENCRYPT: True,
                ep11.CKA_VERIFY: True, # to verify a signature
                ep11.CKA_MODULUS_BITS: 2048,
                ep11.CKA_PUBLIC_EXPONENT: publicExponent,
                ep11.CKA_EXTRACTABLE: False
            })
            privateKeyTemplate=util.ep11attributes({
                ep11.CKA_PRIVATE: True,
                ep11.CKA_SENSITIVE: True,
                ep11.CKA_DECRYPT: True,
                ep11.CKA_SIGN: True, # to generate a signature
                ep11.CKA_EXTRACTABLE: False
            })
            generateKeypairRequest = pb.GenerateKeyPairRequest(
                Mech=pb.Mechanism(Mechanism=ep11.CKM_RSA_PKCS_KEY_PAIR_GEN),
                PubKeyTemplate=publicKeyTemplate,
                PrivKeyTemplate=privateKeyTemplate,
                #PrivKeyId=str(uuid.uuid4()),
                #PubKeyId=str(uuid.uuid4())
            )
            generateKeyPairStatus = cryptoClient.GenerateKeyPair(generateKeypairRequest)
        
            print('Generated RSA PKCS key pair')
            # print('privkey=' + str(generateKeyPairStatus.PrivKeyBytes))
            # print('pubkey=' + str(generateKeyPairStatus.PubKeyBytes))

            return generateKeyPairStatus.PrivKeyBytes, generateKeyPairStatus.PubKeyBytes
        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)

def sign(privkey, doc, hpcs_credentials=hpcs_credentials_template, hpcs_address=hpcs_address_template):
    with util.Channel(hpcs_credentials).get_channel(hpcs_address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)
        
            signInitRequest = pb.SignInitRequest(
                Mech=pb.Mechanism(Mechanism=ep11.CKM_SHA1_RSA_PKCS),
                PrivKey=privkey
            )
            signInitResponse = cryptoClient.SignInit(signInitRequest)

            signData = hashlib.sha256(convert_to_bytes(doc)).digest()
            signRequest = pb.SignRequest(
                State=signInitResponse.State,
                Data=signData
            )
            SignResponse = cryptoClient.Sign(signRequest)

            print("Data signed")

            return SignResponse.Signature
        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)

def verify(pubkey, doc, signature, hpcs_credentials=hpcs_credentials_template, hpcs_address=hpcs_address_template):
    with util.Channel(hpcs_credentials).get_channel(hpcs_address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)

            verifyInitRequest = pb.VerifyInitRequest(
                Mech=pb.Mechanism(Mechanism=ep11.CKM_SHA1_RSA_PKCS),
                PubKey=pubkey
            )
            verifyInitResponse = cryptoClient.VerifyInit(verifyInitRequest)

            signData = hashlib.sha256(convert_to_bytes(doc)).digest()
            verifyRequest = pb.VerifyRequest(
                State=verifyInitResponse.State,
                Data=signData,
                Signature=signature
            )
            VerifyResponse = cryptoClient.Verify(verifyRequest)

            print("Verified")

            if VerifyResponse:
                return True
            else:
                return False
        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)

def bip32_create_master_seed(hpcs_credentials=hpcs_credentials_template, hpcs_address=hpcs_address_template):
    with util.Channel(hpcs_credentials).get_channel(hpcs_address) as channel:
        try:
            keyLen = 128
            cryptoClient = server_pb2_grpc.CryptoStub(channel)

            generateKeyRequest = pb.GenerateKeyRequest(
		        Mech = pb.Mechanism(Mechanism=ep11.CKM_GENERIC_SECRET_KEY_GEN),
		        Template = util.ep11attributes({
				    ep11.CKA_KEY_TYPE:        ep11.CKK_GENERIC_SECRET,
				    ep11.CKA_CLASS:           ep11.CKO_SECRET_KEY,
				    ep11.CKA_VALUE_LEN:       int(keyLen / 8),
				    ep11.CKA_WRAP:            False,
				    ep11.CKA_UNWRAP:          False,
				    ep11.CKA_SIGN:            True,
				    ep11.CKA_VERIFY:          True,
				    ep11.CKA_EXTRACTABLE:     False,
				    ep11.CKA_DERIVE:          True,
				    ep11.CKA_IBM_USE_AS_DATA: True
                })
            )
            generateKeyResponse = cryptoClient.GenerateKey(generateKeyRequest)

            print("Generated Generic Secret Key")

            return generateKeyResponse.KeyBytes
        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)

def bip32_derive_key(master_seed, path, hpcs_credentials=hpcs_credentials_template, hpcs_address=hpcs_address_template):
    print('master_seed: {}'.format(master_seed.hex()))
    with util.Channel(hpcs_credentials).get_channel(hpcs_address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)

            key, chaincode = _bip32_derive_key_core(
		        cryptoClient,
		        pb.BTCDeriveParm.CkBIP0032MASTERK,
		        0,
		        master_seed,
		        b""
	        )
            
            last_index = path[-1]
            for child_index in path[:-1]:
                key, chaincode = _bip32_derive_key_core(cryptoClient, pb.BTCDeriveParm.CkBIP0032PRV2PRV, child_index, key, chaincode)
            return _bip32_derive_key_core(cryptoClient, pb.BTCDeriveParm.CkBIP0032PRV2PUB, last_index, key, chaincode)

        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)

def bip32_sign(master_seed, path, sign_data, hpcs_credentials=hpcs_credentials_template, hpcs_address=hpcs_address_template):
    with util.Channel(hpcs_credentials).get_channel(hpcs_address) as channel:
        try:
            print('master_seed={}'.format(master_seed.hex()))
            cryptoClient = server_pb2_grpc.CryptoStub(channel)

            key, chaincode = _bip32_derive_key_core(
		        cryptoClient,
		        pb.BTCDeriveParm.CkBIP0032MASTERK,
		        0,
		        master_seed,
		        b""
	        )
            
            last_index = path[-1]
            for child_index in path[:-1]:
                key, chaincode = _bip32_derive_key_core(cryptoClient, pb.BTCDeriveParm.CkBIP0032PRV2PRV, child_index, key, chaincode)
            key, chaincode = _bip32_derive_key_core(cryptoClient, pb.BTCDeriveParm.CkBIP0032PRV2PRV, last_index, key, chaincode)

            # signData = hashlib.sha256(convert_to_bytes(doc)).digest()
            sign_data = convert_to_bytes(sign_data)
            signSingleRequest = pb.SignSingleRequest(
                Mech = pb.Mechanism(Mechanism = ep11.CKM_ECDSA),
                PrivKey = key,
                Data = sign_data
            )
            signSingleResponse = cryptoClient.SignSingle(signSingleRequest)

            print("Data signed")

            return signSingleResponse.Signature
        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)

def _bip32_derive_key_core(cryptoClient, deriveType, childKeyIndex, baseKey, chainCode):

    try:
        print('_bip32_derive_key_core')
        print('deriveType={} childKeyIndex={}'.format(pb.BTCDeriveParm.BTCDeriveType.Name(deriveType), childKeyIndex))
        print('baseKey={}'.format(baseKey.hex()))
        deriveKeyRequest = pb.DeriveKeyRequest(
            Mech = pb.Mechanism(
                Mechanism = ep11.CKM_IBM_BTC_DERIVE,
                BTCDeriveParameter = pb.BTCDeriveParm(
                    Type = deriveType,
                    ChildKeyIndex = childKeyIndex,
                    ChainCode = chainCode,
                    Version = 1
                )
            ),
            Template = util.ep11attributes({
                ep11.CKA_VERIFY:          True,
                ep11.CKA_EXTRACTABLE:     False,
                ep11.CKA_DERIVE:          True,
                ep11.CKA_KEY_TYPE:        ep11.CKK_ECDSA,
                ep11.CKA_VALUE_LEN:       0,
                ep11.CKA_IBM_USE_AS_DATA: True
            }),
            BaseKey = baseKey
        )

        deriveKeyResponse = cryptoClient.DeriveKey(deriveKeyRequest)

        if deriveType == pb.BTCDeriveParm.CkBIP0032PRV2PUB:
            print('pubkey={}'.format(hpcs_util.GetPubkeyBytesFromSPKI(deriveKeyResponse.NewKeyBytes).hex()))
        else:
            print('key={}'.format(deriveKeyResponse.NewKeyBytes.hex()))
        print()

        return deriveKeyResponse.NewKeyBytes, deriveKeyResponse.CheckSum

    except grpc.RpcError as rpc_error:
        print('grpc error details=' + str(rpc_error.details()))
        raise Exception(rpc_error)
    
    except Exception as e:
        print(e)
        import traceback
        traceback.print_exc()
        raise Exception(e)

def rsa_encrypt(pubkey, msg, hpcs_credentials=hpcs_credentials_template, hpcs_address=hpcs_address_template):
    with util.Channel(hpcs_credentials).get_channel(hpcs_address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)
        
            encryptRequest = pb.EncryptSingleRequest(
                Key=pubkey,
                Mech=pb.Mechanism(Mechanism=ep11.CKM_RSA_PKCS),
                Plain=msg
            )
            encryptResponse = cryptoClient.EncryptSingle(encryptRequest)

            print("Data encrypted")

            return encryptResponse.Ciphered

        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)

def rsa_decrypt(privkey, cipher_text, hpcs_credentials=hpcs_credentials_template, hpcs_address=hpcs_address_template):
    with util.Channel(hpcs_credentials).get_channel(hpcs_address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)

            decryptRequest = pb.DecryptSingleRequest(
                Key=privkey,
                Mech=pb.Mechanism(Mechanism=ep11.CKM_RSA_PKCS),
                Ciphered=cipher_text
            )
            decryptResponse = cryptoClient.DecryptSingle(decryptRequest)

            return decryptResponse.Plain

        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)

def aes_gen_key(hpcs_credentials=hpcs_credentials_template, hpcs_address=hpcs_address_template):
    with util.Channel(hpcs_credentials).get_channel(hpcs_address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)
        
            keyLen = 128
            template = util.ep11attributes({
                ep11.CKA_VALUE_LEN:   int(keyLen/8),
                ep11.CKA_WRAP:        False,
                ep11.CKA_UNWRAP:      False,
                ep11.CKA_ENCRYPT:     True,
                ep11.CKA_DECRYPT:     True,
                ep11.CKA_EXTRACTABLE: False, # set to false!
                ep11.CKA_TOKEN:       False # ignored by EP11
            })

            r = pb.GenerateKeyRequest(
                Mech=pb.Mechanism(Mechanism=ep11.CKM_AES_KEY_GEN),
                Template=template,
                # KeyId=str(uuid.uuid4()) # optional
            )

            generateKeyStatus = cryptoClient.GenerateKey(r)

            print("Generated AES Key")

            rngTemplate = pb.GenerateRandomRequest(
                Len=(ep11.AES_BLOCK_SIZE)
	        )
        
            rng = cryptoClient.GenerateRandom(rngTemplate)

            iv = rng.Rnd[:ep11.AES_BLOCK_SIZE]

            print("Generated IV")

            return generateKeyStatus.KeyBytes, iv

        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)

def aes_encrypt(key, iv, msg, hpcs_credentials=hpcs_credentials_template, hpcs_address=hpcs_address_template):
    with util.Channel(hpcs_credentials).get_channel(hpcs_address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)
        
            encryptRequest = pb.EncryptSingleRequest(
                Key=key,
                Mech=pb.Mechanism(Mechanism=ep11.CKM_AES_CBC_PAD, ParameterB=iv),
                Plain=msg
            )
            encryptResponse = cryptoClient.EncryptSingle(encryptRequest)

            print("Data encrypted")

            return encryptResponse.Ciphered

        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)

def aes_decrypt(key, iv, cipher_text, hpcs_credentials=hpcs_credentials_template, hpcs_address=hpcs_address_template):
    with util.Channel(hpcs_credentials).get_channel(hpcs_address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)

            decryptRequest = pb.DecryptSingleRequest(
                Key=key,
                Mech=pb.Mechanism(Mechanism=ep11.CKM_AES_CBC_PAD, ParameterB=iv),
                Ciphered=cipher_text
            )
            decryptResponse = cryptoClient.DecryptSingle(decryptRequest)

            return decryptResponse.Plain

        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)
    
        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)

def gen_key_pair_(args):
    privkey, pubkey = gen_key_pair()
    print('privkey={}'.format(privkey.hex()))
    print('pubkey={}'.format(pubkey.hex()))
    return privkey.hex(), pubkey.hex()

def rsa_encrypt_(args):
    cipher_text = rsa_encrypt(bytes.fromhex(args.pubkey), args.msg.encode())
    print('cipher_text={}'.format(cipher_text.hex()))
    return cipher_text.hex()

def rsa_decrypt_(args):
    msg = rsa_decrypt(bytes.fromhex(args.privkey), bytes.fromhex(args.cipher_text))
    print('msg={}'.format(msg.decode('utf-8')))
    return msg.decode('utf-8')

def aes_gen_key_(args):
    key, iv = aes_gen_key()
    print('key={}'.format(key.hex()))
    print('iv={}'.format(iv.hex()))
    return key.hex(), iv.hex()

def aes_encrypt_(args):
    cipher_text = aes_encrypt(bytes.fromhex(args.key), bytes.fromhex(args.iv), args.msg.encode())
    print('cipher_text={}'.format(cipher_text.hex()))
    return cipher_text.hex()

def aes_decrypt_(args):
    msg = aes_decrypt(bytes.fromhex(args.key), bytes.fromhex(args.iv), bytes.fromhex(args.cipher_text))
    print('msg={}'.format(msg.decode('utf-8')))
    return msg.decode('utf-8')

def create_master_seed_(args):
    seed = bip32_create_master_seed().hex()
    print('seed={}'.format(seed))
    return seed

def __convert_bip32path(bip32path):
    if not bip32path.startswith('m/'):
        raise Exception('bip32path ({}) does not start with \'m/\''.format(bip32path))
    bip32path = bip32path.lstrip('m/')
    path_as_list = []
    for x in bip32path.split('/'):
        is_hardened = False
        if x.endswith("'"):
            is_hardened = True
            x = x.rstrip("'")
        if not x.isdigit():
            raise Exception('bip32path ({}) includes non-integer string except for / and \''.format(bip32path))
        x = int(x)
        if is_hardened:
            x = x | 0x80000000
        path_as_list.append(x)
    print('bip32path {} is converted into ['.format(bip32path), end='')
    for x in path_as_list:
        print('{}, '.format(hex(x)), end='')
    print(']')
    return path_as_list

def derive_pubkey_(args):
    pubkey, _ = bip32_derive_key(bytes.fromhex(args.seed), __convert_bip32path(args.path))
    print('pubkey={}'.format(pubkey.hex()))
    return pubkey.hex()

def ecdh(hpcs_credentials=hpcs_credentials_template, hpcs_address=hpcs_address_template):
    with util.Channel(hpcs_credentials).get_channel(hpcs_address) as channel:
        try:
            cryptoClient = server_pb2_grpc.CryptoStub(channel)

	        # Generate ECDH key pairs for Alice and Bob
            encoder = asn1.Encoder()
            encoder.start()
            # encoder.write('1.2.840.10045.3.1.7', asn1.Numbers.ObjectIdentifier)
            # secp256k1
            encoder.write('1.3.132.0.10', asn1.Numbers.ObjectIdentifier)
            ecParameters = encoder.output()

            if not ecParameters:
                raise Exception("Unable to encode parameter OID")

            publicKeyECTemplate = util.ep11attributes({
                ep11.CKA_EC_PARAMS: ecParameters,
                ep11.CKA_EXTRACTABLE: False
            })
            privateKeyECTemplate = util.ep11attributes({
                ep11.CKA_DERIVE: True,
                ep11.CKA_EXTRACTABLE: False
            })
            generateECKeypairRequest = pb.GenerateKeyPairRequest(
                Mech=pb.Mechanism(Mechanism=ep11.CKM_EC_KEY_PAIR_GEN),
                PubKeyTemplate=publicKeyECTemplate,
                PrivKeyTemplate=privateKeyECTemplate
            )
            aliceECKeypairResponse = cryptoClient.GenerateKeyPair(generateECKeypairRequest)

            print("Generated Alice EC key pair")

            bobECKeypairResponse = cryptoClient.GenerateKeyPair(generateECKeypairRequest)

            print("Generated Bob EC key pair")

	        # Derive AES key for Alice
            '''
            deriveKeyTemplate = util.ep11attributes({
                ep11.CKA_CLASS: ep11.CKO_SECRET_KEY,
                ep11.CKA_KEY_TYPE: ep11.CKK_AES,
                ep11.CKA_VALUE_LEN: int(128/8),
                ep11.CKA_ENCRYPT: True,
                ep11.CKA_DECRYPT: True,
            })
            '''
            combinedCoordinates = util.GetPubkeyBytesFromSPKI(bobECKeypairResponse.PubKeyBytes)
            if not combinedCoordinates:
                raise Exception("Bob's EC key cannot obtain coordinates")
            # Derive EC key
            deriveKeyTemplate = util.ep11attributes({
                ep11.CKA_CLASS: ep11.CKO_PRIVATE_KEY,
                ep11.CKA_KEY_TYPE: ep11.CKK_EC,
                ep11.CKA_EC_PARAMS: ecParameters,
                ep11.CKA_VALUE: aliceECKeypairResponse.PrivKeyBytes
            })
            aliceDerivekeyRequest = pb.DeriveKeyRequest(
                Mech=pb.Mechanism(Mechanism=ep11.CKM_ECDH1_DERIVE, ParameterB=combinedCoordinates),
                Template=deriveKeyTemplate,
                BaseKey=aliceECKeypairResponse.PrivKeyBytes
            )
            aliceDerivekeyResponse = cryptoClient.DeriveKey(aliceDerivekeyRequest)

            # Derive AES key for Bob
            combinedCoordinates = util.GetPubkeyBytesFromSPKI(aliceECKeypairResponse.PubKeyBytes)
            if not combinedCoordinates:
                raise Exception("Alice's EC key cannot obtain coordinates")
            bobDerivekeyRequest = pb.DeriveKeyRequest(
                Mech=pb.Mechanism(Mechanism=ep11.CKM_ECDH1_DERIVE, ParameterB=combinedCoordinates),
                Template=deriveKeyTemplate,
                BaseKey=bobECKeypairResponse.PrivKeyBytes
            )
            bobDerivekeyResponse = cryptoClient.DeriveKey(bobDerivekeyRequest)

	        # Encrypt with Alice's key and decrypt with Bob's key
            '''
            msg = b'hello world!'
            rngTemplate = pb.GenerateRandomRequest(
                Len=int(ep11.AES_BLOCK_SIZE)
            )
            rng = cryptoClient.GenerateRandom(rngTemplate)

            iv = rng.Rnd[:ep11.AES_BLOCK_SIZE]

            encryptRequest = pb.EncryptSingleRequest(
                Key=aliceDerivekeyResponse.NewKeyBytes,
                Mech=pb.Mechanism(Mechanism=ep11.CKM_AES_CBC_PAD, ParameterB=iv),
                Plain=msg
            )
            encryptResponse = cryptoClient.EncryptSingle(encryptRequest)

            decryptRequest = pb.DecryptSingleRequest(
                Key=bobDerivekeyResponse.NewKeyBytes,
                Mech=pb.Mechanism(Mechanism=ep11.CKM_AES_CBC_PAD, ParameterB=iv),
                Ciphered=encryptResponse.Ciphered
            )
            decryptResponse = cryptoClient.DecryptSingle(decryptRequest)

            if decryptResponse.Plain != msg:
                raise Exception("Decrypted message{} is different from the original message: {}".format(decryptResponse.Plain, msg))
            else:
                print("Alice and Bob get the same derived key")
            '''

        except grpc.RpcError as rpc_error:
            print('grpc error details=' + str(rpc_error.details()))
            raise Exception(rpc_error)

        except Exception as e:
            print(e)
            import traceback
            traceback.print_exc()
            raise Exception(e)

def ecdh_(args):
    ecdh()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='commands')

    rsa_gen_key_pair_parser = subparsers.add_parser('gen_key_pair', help='Generate a RSA key pair')
    rsa_gen_key_pair_parser.set_defaults(func=gen_key_pair_)

    rsa_encrypt_parser = subparsers.add_parser('rsa_encrypt', help='Encrypt a message with a RSA public key')
    rsa_encrypt_parser.add_argument('msg')
    rsa_encrypt_parser.add_argument('pubkey')
    rsa_encrypt_parser.set_defaults(func=rsa_encrypt_)

    rsa_decrypt_parser = subparsers.add_parser('rsa_decrypt', help='Decrypt a cipher text with a RSA private key')
    rsa_decrypt_parser.add_argument('cipher_text')
    rsa_decrypt_parser.add_argument('privkey')
    rsa_decrypt_parser.set_defaults(func=rsa_decrypt_)

    aes_gen_key_parser = subparsers.add_parser('aes_gen_key', help='Generate a AES key')
    aes_gen_key_parser.set_defaults(func=aes_gen_key_)

    aes_encrypt_parser = subparsers.add_parser('aes_encrypt', help='Encrypt a message with a AES key')
    aes_encrypt_parser.add_argument('msg')
    aes_encrypt_parser.add_argument('key')
    aes_encrypt_parser.add_argument('iv')
    aes_encrypt_parser.set_defaults(func=aes_encrypt_)

    aes_decrypt_parser = subparsers.add_parser('aes_decrypt', help='Decrypt a cipher text with a AES key')
    aes_decrypt_parser.add_argument('cipher_text')
    aes_decrypt_parser.add_argument('key')
    aes_decrypt_parser.add_argument('iv')
    aes_decrypt_parser.set_defaults(func=aes_decrypt_)

    ecdh_parser = subparsers.add_parser('ecdh', help='ECDH operation')
    ecdh_parser.set_defaults(func=ecdh_)

    create_master_seed_parser = subparsers.add_parser('create_master_seed', help='Create a master seed')
    create_master_seed_parser.set_defaults(func=create_master_seed_)

    derive_pubkey_parser = subparsers.add_parser('derive_pubkey', help='Derive a public key')
    derive_pubkey_parser.add_argument('seed')
    derive_pubkey_parser.add_argument('path')
    derive_pubkey_parser.set_defaults(func=derive_pubkey_)

    args = parser.parse_args()
    if hasattr(args, 'func'):
        res = args.func(args)
    else:
        parser.parse_args(['-h'])

