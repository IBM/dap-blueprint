#!/usr/bin/env python3

import argparse, json, os, argon2, hmac, hashlib
from posix import environ
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from dns.rdataclass import NONE

def gen_rsa_keypair(path):
    privkey = RSA.generate(2048, e=11)
    with open(path + '/private.pem', 'w') as f:
        f.write(privkey.export_key().decode('utf-8'))
    pubkey = privkey.publickey()
    with open(path + '/public.pem', 'w') as f:
        f.write(pubkey.export_key().decode('utf-8'))

def rsa_encrypt(pubkey_file, message):
    with open(pubkey_file, 'rb') as f:
        pem = f.read()
        key = RSA.import_key(pem)
        cipher = PKCS1_OAEP.new(key)
        if type(message) is str:
            message = message.encode()
        return cipher.encrypt(message).hex()

def rsa_decrypt(privkey_file, cipher_text, to_string=True):
    with open(privkey_file, 'rb') as f:
        pem = f.read()
        key = RSA.import_key(pem)
        decipher = PKCS1_OAEP.new(key)
        message = decipher.decrypt(bytes.fromhex(cipher_text))
        if to_string:
            return message.decode("utf-8")
        else:
            return message

def rsa_sign_(privkey, message):
    h = SHA256.new(message.encode())
    return pkcs1_15.new(privkey).sign(h)

def rsa_sign(privkey_file, message):
    with open(privkey_file, 'rb') as f:
        pem = f.read()
        key = RSA.import_key(pem)
        return rsa_sign_(key, message).hex()

def rsa_verify_(pubkey, message, signature):
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(pubkey).verify(h, bytes.fromhex(signature))
        verified = True
    except ValueError:
        verified = False
    return verified

def rsa_verify(pubkey_file, message, signature):
    with open(pubkey_file, 'rb') as f:
        pem = f.read()
        key = RSA.import_key(pem)
        return rsa_verify_(key, message, signature)

def _iv():
    return b'0123456789012345'

def aes_encrypt(key, message):
    cipher = AES.new(key, AES.MODE_EAX, _iv())
    return cipher.encrypt(message.encode()).hex()
    
def rsa_encrypt_long(pubkey_file, message):
    aes_key = get_random_bytes(32)
    cipher_text = aes_encrypt(aes_key, message)
    index = int(len(cipher_text) / 2)
    cipher_text1 = cipher_text[:index]
    cipher_text2 = cipher_text[index:]
    return {
        'cipher_text': aes_encrypt(aes_key, message),
        'cipher_text1': cipher_text1,
        'cipher_text2': cipher_text2,
        'aes_encrypted_key': rsa_encrypt(pubkey_file, aes_key)
    }

def aes_decrypt(key, cipher_text, to_string=True):
    decipher = AES.new(key, AES.MODE_EAX, _iv())
    message = decipher.decrypt(bytes.fromhex(cipher_text))
    if to_string:
        return message.decode('utf-8')
    else:
        return message

def rsa_decrypt_long(privkey_file, cipher_text, aes_encrypted_key, to_string=True):
    aes_key = rsa_decrypt(privkey_file, aes_encrypted_key, to_string=False)
    return aes_decrypt(aes_key, cipher_text)

def derive_common_keys(old=False):
    build_time_secret = None
    deploy_time_secret = None
    if old:
        if 'OLD_BUILD_TIME_SECRET' in os.environ:
            build_time_secret = os.environ['OLD_BUILD_TIME_SECRET']
        if 'OLD_DEPLOY_TIME_SECRET' in os.environ:
            deploy_time_secret = os.environ['OLD_DEPLOY_TIME_SECRET']
        if not build_time_secret and not deploy_time_secret:
            # We have no old secrets.
            return None, None
        print('Using old secrets')
    
    if not build_time_secret and 'BUILD_TIME_SECRET' in os.environ:
        build_time_secret = os.environ['BUILD_TIME_SECRET']
    if not build_time_secret:
        raise Exception('BUILD_TIME_SECRET environment variable is not set')
    
    if not deploy_time_secret and 'DEPLOY_TIME_SECRET' in os.environ:
        deploy_time_secret = os.environ['DEPLOY_TIME_SECRET']
    if not deploy_time_secret:
        raise Exception('DEPLOY_TIME_SECRET environment variable is not set')

    salt = None
    if 'ARGON2_SALT' in os.environ:
        salt = os.environ['ARGON2_SALT']
    if not salt:
        raise Exception('ARGON2_SALT environment variable is not set')

    print('Deriving common keys')
    print('  build_time_secret={}'.format(build_time_secret))
    print('  deploy_time_secret={}'.format(deploy_time_secret))

    # Deterministically derive two keys that are shared among polict and signing services
    secret = build_time_secret + deploy_time_secret
    hash = argon2.argon2_hash(secret, salt)
    assert len(hash) == 128, 'Argon2 hash length should be 128'
    common_key1 = hash[:96]
    common_key2 = hash[96:128]
    print('common-key1: {}'.format(common_key1))
    print('common-key2: {}'.format(common_key2))
    return common_key1, common_key2

def gen_hmac(message, key):
    return hmac.new(key, message.encode(), hashlib.md5).hexdigest()

def hmac_and_encrypt_with_common_keys(message, common_key1, common_key2):
    _hmac = gen_hmac(message, common_key1)
    hmac_message = {
        'message': message,
        'hmac': _hmac
    }
    return aes_encrypt(common_key2, json.dumps(hmac_message))

def verify_hmac(message, hmac1, key):
    hmac2 = hmac.new(key, message.encode(), hashlib.md5).hexdigest()
    if hmac1 == hmac2:
        return True
    else:
        return False

def decrypt_and_hmac_with_common_keys(cipher_text, common_key1, common_key2):
    hmac_message = json.loads(aes_decrypt(common_key2, cipher_text))
    message = hmac_message['message']
    hmac1 = hmac_message['hmac']
    if not verify_hmac(message, hmac1, common_key1):
        raise Exception('HMAC verification failure')
    return message

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='commands')

    gen_rsa_keypair_parser = subparsers.add_parser('gen_rsa_keypair', help='Generate a RSA key pair')
    gen_rsa_keypair_parser.add_argument('path')
    gen_rsa_keypair_parser.set_defaults(func=gen_rsa_keypair)

    rsa_encrypt_parser = subparsers.add_parser('rsa_encrypt', help='Encrypt a message with a RSA public key')
    rsa_encrypt_parser.add_argument('pubkey_file')
    rsa_encrypt_parser.add_argument('message')
    rsa_encrypt_parser.set_defaults(func=rsa_encrypt)

    rsa_decrypt_parser = subparsers.add_parser('rsa_decrypt', help='Decrypt a cipher text with a RSA private key')
    rsa_decrypt_parser.add_argument('privkey_file')
    rsa_decrypt_parser.add_argument('cipher_text')
    rsa_decrypt_parser.set_defaults(func=rsa_decrypt)

    rsa_encrypt_long_parser = subparsers.add_parser('rsa_encrypt_long', help='Encrypt a long message with a RSA public key')
    rsa_encrypt_long_parser.add_argument('pubkey_file')
    rsa_encrypt_long_parser.add_argument('message')
    rsa_encrypt_long_parser.set_defaults(func=rsa_encrypt_long)

    rsa_decrypt_long_parser = subparsers.add_parser('rsa_decrypt_long', help='Decrypt a long cipher text with a RSA private key')
    rsa_decrypt_long_parser.add_argument('privkey_file')
    rsa_decrypt_long_parser.add_argument('cipher_text')
    rsa_decrypt_long_parser.add_argument('aes_encrypted_key')
    rsa_decrypt_long_parser.set_defaults(func=rsa_decrypt_long)

    derive_common_keys_parser = subparsers.add_parser('derive_common_keys', help='Derive two common keys from secrets')
    derive_common_keys_parser.set_defaults(func=derive_common_keys)

    rsa_sign_parser = subparsers.add_parser('rsa_sign', help='Sign a message with a RSA private key')
    rsa_sign_parser.add_argument('privkey_file')
    rsa_sign_parser.add_argument('message')
    rsa_sign_parser.set_defaults(func=rsa_sign)

    rsa_verify_parser = subparsers.add_parser('rsa_verify', help='Verify a signature with a RSA public key')
    rsa_verify_parser.add_argument('pubkey_file')
    rsa_verify_parser.add_argument('message')
    rsa_verify_parser.add_argument('signature')
    rsa_verify_parser.set_defaults(func=rsa_verify)

    hmac_and_encrypt = subparsers.add_parser('hmac_and_encrypt', help='Calculate HMAC and encrypt a message with common keys')
    hmac_and_encrypt.add_argument('message')
    hmac_and_encrypt.add_argument('key1')
    hmac_and_encrypt.add_argument('key2')
    hmac_and_encrypt.set_defaults(func=hmac_and_encrypt_with_common_keys)

    decrypt_and_hmac = subparsers.add_parser('decrypt_and_hmac', help='Decrypt a cipher text and verify HMAC with common keys')
    decrypt_and_hmac.add_argument('cipher_text')
    decrypt_and_hmac.add_argument('key1')
    decrypt_and_hmac.add_argument('key2')
    decrypt_and_hmac.set_defaults(func=decrypt_and_hmac_with_common_keys)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        if args.func is gen_rsa_keypair:
            gen_rsa_keypair(args.path)
        elif args.func is rsa_encrypt:
            cipher_text = rsa_encrypt(args.pubkey_file, args.message)
            print(cipher_text)
        elif args.func is rsa_decrypt:
            message = rsa_decrypt(args.privkey_file, args.cipher_text)
            print(message)
        elif args.func is rsa_encrypt_long:
            res = rsa_encrypt_long(args.pubkey_file, args.message)
            print(json.dumps(res))
        elif args.func is rsa_decrypt_long:
            message = rsa_decrypt_long(args.privkey_file, args.cipher_text, args.aes_encrypted_key)
            print(message)
        elif args.func is rsa_sign:
            signature = rsa_sign(args.privkey_file, args.message)
            print(signature)
        elif args.func is rsa_verify:
            verified = rsa_verify(args.pubkey_file, args.message, args.signature)
            print(verified)
        elif args.func is derive_common_keys:
            key1, key2 = derive_common_keys()
            print('key1={}'.format(key1.hex()))
            print('key2={}'.format(key2.hex()))
        elif args.func is hmac_and_encrypt_with_common_keys:
            cipher_text = hmac_and_encrypt_with_common_keys(args.message, bytes.fromhex(args.key1), bytes.fromhex(args.key2))
            print(cipher_text)
        elif args.func is decrypt_and_hmac_with_common_keys:
            message = decrypt_and_hmac_with_common_keys(args.cipher_text, bytes.fromhex(args.key1), bytes.fromhex(args.key2))
            print(message)
        else:
            raise Exception('Unknown command ' + str(args.func))
    else:
        parser.parse_args(['-h'])