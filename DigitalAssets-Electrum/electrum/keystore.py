#!/usr/bin/env python2
# -*- mode: python -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2016  The Electrum developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from unicodedata import normalize
import hashlib
import re
from typing import Tuple, TYPE_CHECKING, Union, Sequence, Optional, Dict, List, NamedTuple

from . import bitcoin, ecc, constants, bip32
from .bitcoin import deserialize_privkey, serialize_privkey
from .bip32 import (convert_bip32_path_to_list_of_uint32, BIP32_PRIME,
                    is_xpub, is_xprv, BIP32Node, normalize_bip32_derivation,
                    convert_bip32_intpath_to_strpath)
from .ecc import string_to_number, number_to_string
from .crypto import (pw_decode, pw_encode, sha256, sha256d, PW_HASH_VERSION_LATEST,
                     SUPPORTED_PW_HASH_VERSIONS, UnsupportedPasswordHashVersion, hash_160)
from .util import (InvalidPassword, WalletFileException,
                   BitcoinException, bh2u, bfh, inv_dict)
from .mnemonic import Mnemonic, load_wordlist, seed_type, is_seed
from .plugin import run_hook
from .logging import Logger

import hpcs_util as hpcsutil, grpc, server_pb2_grpc, server_pb2 as pb, grep11consts as ep11
import dap_client

import json

if TYPE_CHECKING:
    from .gui.qt.util import TaskThread
    from .transaction import Transaction, PartialTransaction, PartialTxInput, PartialTxOutput
    from .plugins.hw_wallet import HW_PluginBase, HardwareClientBase


class KeyStore(Logger):
    type: str

    def __init__(self):
        Logger.__init__(self)
        self.is_requesting_to_be_rewritten_to_wallet_file = False  # type: bool

    def to_json(self):
        return {}

    def has_seed(self) -> bool:
        return False

    def is_watching_only(self) -> bool:
        return False

    def can_import(self) -> bool:
        return False

    def get_type_text(self) -> str:
        return f'{self.type}'

    def may_have_password(self):
        """Returns whether the keystore can be encrypted with a password."""
        raise NotImplementedError()

    def get_tx_derivations(self, tx: 'PartialTransaction') -> Dict[str, Union[Sequence[int], str]]:
        print('keystore:KeyStore:get_tx_derivation tx={} inputs={}'.format(tx, tx.inputs()))
        keypairs = {}
        for txin in tx.inputs():
            print('keystore:KeyStore:get_tx_derivation txin={}'.format(txin))
            if txin.is_complete():
                print('keystore:KeyStore:get_tx_derivation txin.is_complete=True')
                continue
            for pubkey in txin.pubkeys:
                if pubkey in txin.part_sigs:
                    # this pubkey already signed
                    print('keystore:KeyStore:get_tx_derivation already signed')
                    continue
                derivation = self.get_pubkey_derivation(pubkey, txin)
                print('keystore:KeyStore:get_tx_derivation derivation={}'.format(derivation))
                if not derivation:
                    continue
                keypairs[pubkey.hex()] = derivation
        print('get_tx_derivation: keypairs={}'.format(keypairs))
        return keypairs

    def can_sign(self, tx) -> bool:
        print('keystore:KeyStore:can_sign')
        if self.is_watching_only():
            print('keystore:KeyStore:can_sign False')
            return False
        resp = bool(self.get_tx_derivations(tx))
        print('keystore:KeyStore:can_sign resp={}'.format(resp))
        return bool(resp)

    def ready_to_sign(self) -> bool:
        print('keystore:KeyStore:need_to_sign')
        return not self.is_watching_only()

    def dump(self) -> dict:
        raise NotImplementedError()  # implemented by subclasses

    def is_deterministic(self) -> bool:
        raise NotImplementedError()  # implemented by subclasses

    def sign_message(self, sequence, message, password) -> bytes:
        raise NotImplementedError()  # implemented by subclasses

    def decrypt_message(self, sequence, message, password) -> bytes:
        raise NotImplementedError()  # implemented by subclasses

    def sign_transaction(self, tx: 'PartialTransaction', password, sync=True) -> None:
        raise NotImplementedError()  # implemented by subclasses

    def get_signed_transaction(self, tx: 'PartialTransaction', password) -> None:
        raise NotImplementedError()  # implemented by subclasses

    def get_pubkey_derivation(self, pubkey: bytes,
                              txinout: Union['PartialTxInput', 'PartialTxOutput'],
                              *, only_der_suffix=True) \
            -> Union[Sequence[int], str, None]:
        """Returns either a derivation int-list if the pubkey can be HD derived from this keystore,
        the pubkey itself (hex) if the pubkey belongs to the keystore but not HD derived,
        or None if the pubkey is unrelated.
        """
        def test_der_suffix_against_pubkey(der_suffix: Sequence[int], pubkey: bytes) -> bool:
            if len(der_suffix) != 2:
                return False
            if pubkey.hex() != self.derive_pubkey(*der_suffix):
                return False
            return True

        print('KeyStore:get_pubkey_derivation pubkey={} txinout={}'.format(pubkey.hex(), txinout.to_json()))
        if hasattr(self, 'get_root_fingerprint'):
            if pubkey not in txinout.bip32_paths:
                return None
            fp_found, path_found = txinout.bip32_paths[pubkey]
            der_suffix = None
            full_path = None
            # try fp against our root
            my_root_fingerprint_hex = self.get_root_fingerprint()
            my_der_prefix_str = self.get_derivation_prefix()
            ks_der_prefix = convert_bip32_path_to_list_of_uint32(my_der_prefix_str) if my_der_prefix_str else None
            if (my_root_fingerprint_hex is not None and ks_der_prefix is not None and
                    fp_found.hex() == my_root_fingerprint_hex):
                if path_found[:len(ks_der_prefix)] == ks_der_prefix:
                    der_suffix = path_found[len(ks_der_prefix):]
                    if not test_der_suffix_against_pubkey(der_suffix, pubkey):
                        der_suffix = None
            # try fp against our intermediate fingerprint
            if (der_suffix is None and hasattr(self, 'xpub') and
                    fp_found == BIP32Node.from_xkey(self.xpub).calc_fingerprint_of_this_node()):
                der_suffix = path_found
                if not test_der_suffix_against_pubkey(der_suffix, pubkey):
                    der_suffix = None
            if der_suffix is None:
                return None
            if ks_der_prefix is not None:
                full_path = ks_der_prefix + list(der_suffix)
            print('KeyStore:get_pubkey_derivation der_suffix={} full_path={}'.format('/'.join([str(p) for p in der_suffix]), '/'.join([str(p) for p in full_path])))
            return der_suffix if only_der_suffix else full_path
        return None

    def find_my_pubkey_in_txinout(
            self, txinout: Union['PartialTxInput', 'PartialTxOutput'],
            *, only_der_suffix: bool = False
    ) -> Tuple[Optional[bytes], Optional[List[int]]]:
        # note: we assume that this cosigner only has one pubkey in this txin/txout
        print('KeyStore:find_my_pubkey_in_txinout txinout={}'.format(txinout))
        for pubkey in txinout.bip32_paths:
            path = self.get_pubkey_derivation(pubkey, txinout, only_der_suffix=only_der_suffix)
            if path and not isinstance(path, (str, bytes)):
                return pubkey, list(path)
        return None, None


class Software_KeyStore(KeyStore):

    def __init__(self, d):
        KeyStore.__init__(self)
        self.pw_hash_version = d.get('pw_hash_version', 1)
        if self.pw_hash_version not in SUPPORTED_PW_HASH_VERSIONS:
            raise UnsupportedPasswordHashVersion(self.pw_hash_version)

    def may_have_password(self):
        return not self.is_watching_only()

    def sign_message(self, sequence, message, password) -> bytes:
        privkey, compressed = self.get_private_key(sequence, password)
        key = ecc.ECPrivkey(privkey)
        return key.sign_message(message, compressed)

    def decrypt_message(self, sequence, message, password) -> bytes:
        privkey, compressed = self.get_private_key(sequence, password)
        ec = ecc.ECPrivkey(privkey)
        decrypted = ec.decrypt_message(message)
        return decrypted

    def sign_transaction(self, tx, password, sync=True):
        print('keystore:Software_KeySore:sign_transaction tx={}'.format(tx.to_json()))
        if self.is_watching_only():
            return
        # Raise if password is not correct.
        self.check_password(password)
        # Add private keys
        keypairs = self.get_tx_derivations(tx)
        print('keystore:Software_KeySore:sign_transaction keypairs={}'.format(keypairs))
        for k, v in keypairs.items():
            keypairs[k] = self.get_private_key(v, password)
        # Sign
        if keypairs:
            tx.sign(keypairs, sync)

    def get_signed_transaction(self, tx, password):
        print('keystore:Software_KeySore:get_signed_transaction tx={}'.format(tx.to_json()))
        if self.is_watching_only():
            return
        # Raise if password is not correct.
        self.check_password(password)
        # Add private keys
        keypairs = self.get_tx_derivations(tx)
        print('keystore:Software_KeySore:get_signed_transaction keypairs={}'.format(keypairs))
        for k, v in keypairs.items():
            keypairs[k] = self.get_private_key(v, password)
        # Sign
        if keypairs:
            return tx.get_signed_transaction(keypairs)
        return False

    def update_password(self, old_password, new_password):
        raise NotImplementedError()  # implemented by subclasses

    def check_password(self, password):
        raise NotImplementedError()  # implemented by subclasses

    def get_private_key(self, *args, **kwargs) -> Tuple[bytes, bool]:
        raise NotImplementedError()  # implemented by subclasses


class Imported_KeyStore(Software_KeyStore):
    # keystore for imported private keys

    type = 'imported'

    def __init__(self, d):
        Software_KeyStore.__init__(self, d)
        self.keypairs = d.get('keypairs', {})

    def is_deterministic(self):
        return False

    def get_master_public_key(self):
        return None

    def dump(self):
        return {
            'type': self.type,
            'keypairs': self.keypairs,
            'pw_hash_version': self.pw_hash_version,
        }

    def can_import(self):
        return True

    def check_password(self, password):
        pubkey = list(self.keypairs.keys())[0]
        self.get_private_key(pubkey, password)

    def import_privkey(self, sec, password):
        txin_type, privkey, compressed = deserialize_privkey(sec)
        pubkey = ecc.ECPrivkey(privkey).get_public_key_hex(compressed=compressed)
        # re-serialize the key so the internal storage format is consistent
        serialized_privkey = serialize_privkey(
            privkey, compressed, txin_type, internal_use=True)
        # NOTE: if the same pubkey is reused for multiple addresses (script types),
        # there will only be one pubkey-privkey pair for it in self.keypairs,
        # and the privkey will encode a txin_type but that txin_type cannot be trusted.
        # Removing keys complicates this further.
        self.keypairs[pubkey] = pw_encode(serialized_privkey, password, version=self.pw_hash_version)
        return txin_type, pubkey

    def delete_imported_key(self, key):
        self.keypairs.pop(key)

    def get_private_key(self, pubkey, password):
        sec = pw_decode(self.keypairs[pubkey], password, version=self.pw_hash_version)
        txin_type, privkey, compressed = deserialize_privkey(sec)
        # this checks the password
        if pubkey != ecc.ECPrivkey(privkey).get_public_key_hex(compressed=compressed):
            raise InvalidPassword()
        return privkey, compressed

    def get_pubkey_derivation(self, pubkey, txin, *, only_der_suffix=True):
        if pubkey.hex() in self.keypairs:
            return pubkey.hex()
        return None

    def update_password(self, old_password, new_password):
        self.check_password(old_password)
        if new_password == '':
            new_password = None
        for k, v in self.keypairs.items():
            b = pw_decode(v, old_password, version=self.pw_hash_version)
            c = pw_encode(b, new_password, version=PW_HASH_VERSION_LATEST)
            self.keypairs[k] = c
        self.pw_hash_version = PW_HASH_VERSION_LATEST


import requests
class HsmGenerated_KeyStore(Imported_KeyStore):
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # keystore for hsm generated private keys
    type = 'hsmgenerated'
    headers = {'content-type': 'application/json'}

    # pass policy server url and approverparams while init
    def __init__(self, d):
        Imported_KeyStore.__init__(self, d)
        #self.type = type
        self.policy_server_url = d.get('policy_server_url', '')
        self.approver_email = d.get('approver_email', '')
        self.policy_crt_key_path = d.get('policy_crt_key_path', '')
        self.pw_hash_version = d.get('pw_hash_version', 1)

    def is_deterministic(self):
        return False

    def dump(self):
        d = {
            'type': self.type,
            'pw_hash_version': self.pw_hash_version,
            'keypairs': self.keypairs,
        }
        return d

    def import_keyrecord(self, keyrecord):
        pubkey = keyrecord['pubKey']
        info = keyrecord['info']
        print('keystore.import_keyrecord: info=' + json.dumps(info, indent=4))
        self.keypairs[pubkey] = [info, False]

    def get_private_key(self, pubkey, password):
        return self.keypairs[pubkey]
    
    def create_approver_id(self):
        print('create approver id %s ' % self.policy_server_url)
        resp = requests.put(self.policy_server_url + '/v1/approvers/', params={'email': self.approver_email}, cert=self.policy_crt_key_path, verify=False, headers=self.headers)
        print('resp value - %s ' % resp.text)
        approverItem = resp.json()
        #catch error
        if 'err_code' in approverItem and approverItem['err_code'] != -1:
            raise Exception("Email address of approver is not exist in pre-approval list")
        else:
            approverID = approverItem['approver_id']
            approver_pubKey = approverItem['approver_public_key']

        #self.set_approver_id(approverID, approver_pubKey)    
        return approverID, approver_pubKey

    #set approver id into db
    def set_approver_id(self, app_id, app_pubkey):
        if app_id and app_pubkey:
            self.keypairs = {
                app_pubkey: {
                    'approver_id': app_id, 
                }
            }
    
    #sign message with :
    # policy_server_url
    # approver_id 
    # email 
    # digest
    def sign_message(self, sequence, message, password, approverID) -> bytes:
        #get approver id from keystore 
        #approver_id = get_approver_id(self, sequence)

        #sign message
        resp = requests.get(self.policy_server_url + '/v1/approvers/' + approverID +'/signature', params={'email': self.email, 'digest': message}, cert=self.policy_crt_key_path, verify=False, headers=self.headers)
        if resp.text != -1:
            return resp.json()['sig']
        else: 
            raise Exception("Signature failed")

    #get approver's public key by email & approverID
    def get_approver_pubkey(self, approverID):
        resp = requests.get(self.policy_server_url + '/v1/approvers/' + approverID, params={'email': self.email}, cert=self.policy_crt_key_path, verify=False, headers=self.headers)
        if resp.text != -1:
            return resp.json()['approver_public_keys']
        else:
            raise Exception('Failed to get public key of current approver')

    #delete approver by email and ID
    def del_approver(self, approverID):
        resp = requests.delete(self.policy_server_url + '/v1/approvers/' + approverID, params={'email': self.email}, cert=self.policy_crt_key_path, verify=False, headers=self.headers)
        if resp.text == -1:
            raise Exception('Failed to delete current approver')
        else:
            #get public key of the deleted approver
            del_pubKey = get_approver_pubkey(self, approverID)
            self.keypairs.pop(del_pubKey)

    #rollout 
    def rollout_approver(self, approverID):
        resp = requests.put(self.policy_server_url + '/v1/approvers/' + approverID, params={'email': self.email}, cert=self.policy_crt_key_path, verify=False, headers=self.headers)
        if resp.text != -1:
            item = resp.json()
            rollout_pubKey = item['approver_public_key']
            rollout_sig = item['signature']
        else:
            raise Exception('Failed to rollout current approver')
    
    #get approver id by pubkey
    # def get_approver_id(self, pubkey):
    #     keypair_enti = self.keypairs[pubkey]
    #     approver_id = keypair_enti['approver_id']
    #     return approver_id

class Deterministic_KeyStore(Software_KeyStore):

    def __init__(self, d):
        Software_KeyStore.__init__(self, d)
        self.seed = d.get('seed', '')
        self.passphrase = d.get('passphrase', '')

    def is_deterministic(self):
        print('keystore:Deterministic_KeySore:is_deterministic')
        return True

    def dump(self):
        d = {
            'type': self.type,
            'pw_hash_version': self.pw_hash_version,
        }
        if self.seed:
            d['seed'] = self.seed
        if self.passphrase:
            d['passphrase'] = self.passphrase
        return d

    def has_seed(self):
        print('keystore:Deterministic_KeySore:has_seed seed={}'.format(self.seed))
        return bool(self.seed)

    def is_watching_only(self):
        return not self.has_seed()

    def add_seed(self, seed):
        print('Deterministic_KeyStore:add_seed seed={}'.format(seed))
        if self.seed:
            raise Exception("a seed exists")
        self.seed = self.format_seed(seed)

    def get_seed(self, password):
        print('Deterministic_KeyStore:get_seed')
        if not self.has_seed():
            raise Exception("This wallet has no seed words")
        return pw_decode(self.seed, password, version=self.pw_hash_version)

    def get_passphrase(self, password):
        if self.passphrase:
            return pw_decode(self.passphrase, password, version=self.pw_hash_version)
        else:
            return ''


class Xpub:

    def __init__(self, *, derivation_prefix: str = None, root_fingerprint: str = None):
        print('keystore:Xpub:__init__')
        self.xpub = None
        self.xpub_receive = None
        self.xpub_change = None

        # "key origin" info (subclass should persist these):
        self._derivation_prefix = derivation_prefix  # type: Optional[str]
        self._root_fingerprint = root_fingerprint  # type: Optional[str]

    def to_json(self):
        node = BIP32Node.from_xkey(self.xpub)
        d = {
            'xpub': self.xpub,
            'root_fingerprint': self.get_root_fingerprint(),
            'derivation_prefix': self.get_derivation_prefix(),
            'pubkey': node.eckey.get_public_key_bytes().hex(),
            'fingerprint': node.calc_fingerprint_of_this_node().hex(),
            'der_prefix_ints':  convert_bip32_path_to_list_of_uint32('m'),
        }
        return d
    def get_master_public_key(self):
        print('Xpub:get_master_public_key')
        return self.xpub

    def get_derivation_prefix(self) -> Optional[str]:
        """Returns to bip32 path from some root node to self.xpub
        Note that the return value might be None; if it is unknown.
        """
        print('Xpub:get_derivation_prefix prefix={}'.format(self._derivation_prefix))
        return self._derivation_prefix

    def get_root_fingerprint(self) -> Optional[str]:
        """Returns the bip32 fingerprint of the top level node.
        This top level node is the node at the beginning of the derivation prefix,
        i.e. applying the derivation prefix to it will result self.xpub
        Note that the return value might be None; if it is unknown.
        """
        print('Xpub:get_root_fingerprint fingerprintt={}'.format(self._root_fingerprint))
        return self._root_fingerprint

    def get_fp_and_derivation_to_be_used_in_partial_tx(self, der_suffix: Sequence[int], *,
                                                       only_der_suffix: bool = True) -> Tuple[bytes, Sequence[int]]:
        """Returns fingerprint and derivation path corresponding to a derivation suffix.
        The fingerprint is either the root fp or the intermediate fp, depending on what is available
        and 'only_der_suffix', and the derivation path is adjusted accordingly.
        """
        print('keystore:Xpub:get_fp_and_derivation_to_be_used_in_partial_tx der_suffix={}'.format(der_suffix))
        fingerprint_hex = self.get_root_fingerprint()
        der_prefix_str = self.get_derivation_prefix()
        if not only_der_suffix and fingerprint_hex is not None and der_prefix_str is not None:
            # use root fp, and true full path
            print('keystore:Xpub:get_fp_and_derivation_to_be_used_in_partial_tx: use ROOT fp!!!!!!!!!!!!!')
            pubkey = "ROOT"
            fingerprint_bytes = bfh(fingerprint_hex)
            der_prefix_ints = convert_bip32_path_to_list_of_uint32(der_prefix_str)
        else:
            # use intermediate fp, and claim der suffix is the full path
            #fingerprint_bytes = BIP32Node.from_xkey(self.xpub).calc_fingerprint_of_this_node()
            # self.xpub corresponds to m/0' node
            node = BIP32Node.from_xkey(self.xpub)
            print('keystore:Xpub:get_fp_and_derivation_to_be_used_in_partial_tx: use intermediate fp node={} pubkey={}'.format(node, node.eckey.get_public_key_bytes().hex()))
            pubkey = node.eckey.get_public_key_bytes().hex()
            fingerprint_bytes = node.calc_fingerprint_of_this_node()
            der_prefix_ints = convert_bip32_path_to_list_of_uint32('m')
        der_full = der_prefix_ints + list(der_suffix)
        print('***keystore:Xpub:get_fp_and_derivation_to_be_used_in_partial_tx fingerprint={} der_full={} pubkey={}'.format(fingerprint_bytes.hex(), der_full, pubkey))
        return fingerprint_bytes, der_full

    def get_xpub_to_be_used_in_partial_tx(self, *, only_der_suffix: bool) -> str:
        assert self.xpub
        print('keystore:Xpub:get_xpub_to_be_used_in_partial_tx')
        fp_bytes, der_full = self.get_fp_and_derivation_to_be_used_in_partial_tx(der_suffix=[],
                                                                                 only_der_suffix=only_der_suffix)
        bip32node = BIP32Node.from_xkey(self.xpub)
        depth = len(der_full)
        child_number_int = der_full[-1] if len(der_full) >= 1 else 0
        child_number_bytes = child_number_int.to_bytes(length=4, byteorder="big")
        fingerprint = bytes(4) if depth == 0 else bip32node.fingerprint
        bip32node = bip32node._replace(depth=depth,
                                       fingerprint=fingerprint,
                                       child_number=child_number_bytes)
        return bip32node.to_xpub()

    def add_key_origin_from_root_node(self, *, derivation_prefix: str, root_node: BIP32Node):
        assert self.xpub
        # try to derive ourselves from what we were given
        print('keystore:Xpub:add_key_origin_from_root_node root_node={}'.format(root_node))
        child_node1 = root_node.subkey_at_private_derivation(derivation_prefix)
        child_pubkey_bytes1 = child_node1.eckey.get_public_key_bytes(compressed=True)
        child_node2 = BIP32Node.from_xkey(self.xpub)
        child_pubkey_bytes2 = child_node2.eckey.get_public_key_bytes(compressed=True)
        if child_pubkey_bytes1 != child_pubkey_bytes2:
            raise Exception("(xpub, derivation_prefix, root_node) inconsistency")
        self.add_key_origin(derivation_prefix=derivation_prefix,
                            root_fingerprint=root_node.calc_fingerprint_of_this_node().hex().lower())

    def add_key_origin(self, *, derivation_prefix: Optional[str], root_fingerprint: Optional[str]):
        print('keystore:Xpub:add_key_origin derivation_prefix={} root_fingerprint={}'.format(derivation_prefix, root_fingerprint))
        assert self.xpub
        self._root_fingerprint = root_fingerprint
        self._derivation_prefix = normalize_bip32_derivation(derivation_prefix)

    def derive_pubkey(self, for_change, n) -> str:
        for_change = int(for_change)
        assert for_change in (0, 1)
        xpub = self.xpub_change if for_change else self.xpub_receive
        if xpub is None:
            rootnode = BIP32Node.from_xkey(self.xpub)
            xpub = rootnode.subkey_at_public_derivation((for_change,)).to_xpub()
            if for_change:
                self.xpub_change = xpub
            else:
                self.xpub_receive = xpub
        pubkey = self.get_pubkey_from_xpub(xpub, (n,))
        print('keystore:Xpub:derive_pubkey: pubkey={} for_change={} n={} xpub={} self={}'.format(pubkey, for_change, n, BIP32Node.from_xkey(xpub), self.to_json()))
        return pubkey

    @classmethod
    def get_pubkey_from_xpub(self, xpub, sequence):
        node = BIP32Node.from_xkey(xpub).subkey_at_public_derivation(sequence)
        print('keystore:Xpub:get_pubkey_from_xpub: xpub={} sequence={} node={}'.format(xpub, sequence, node))
        return node.eckey.get_public_key_hex(compressed=True)


class BIP32_KeyStore(Deterministic_KeyStore, Xpub):

    type = 'bip32'

    def __init__(self, d):
        print('keystore:BIP32_KeyStore:__init__ d={}'.format(d))
        Xpub.__init__(self, derivation_prefix=d.get('derivation'), root_fingerprint=d.get('root_fingerprint'))
        Deterministic_KeyStore.__init__(self, d)
        self.xpub = d.get('xpub')
        self.xprv = d.get('xprv')
        print('keystore:BIP32_KeyStore:__init__ {}'.format(self.dump()))

    def format_seed(self, seed):
        return ' '.join(seed.split())

    def dump(self):
        d = Deterministic_KeyStore.dump(self)
        d['xpub'] = self.xpub
        d['xprv'] = self.xprv
        d['derivation'] = self.get_derivation_prefix()
        d['root_fingerprint'] = self.get_root_fingerprint()
        return d

    def short_dump(self):
        d = Deterministic_KeyStore.dump(self)
        d['xpub'] = self.xpub
        d['xprv'] = self.xprv
        d['derivation'] = self.get_derivation_prefix()
        d['root_fingerprint'] = self.get_root_fingerprint()
        return d

    def get_master_private_key(self, password):
        print('keystore:BIP32_KeyStore:get_master_private_key')
        return pw_decode(self.xprv, password, version=self.pw_hash_version)

    def check_password(self, password):
        xprv = pw_decode(self.xprv, password, version=self.pw_hash_version)
        if BIP32Node.from_xkey(xprv).chaincode != BIP32Node.from_xkey(self.xpub).chaincode:
            raise InvalidPassword()

    def update_password(self, old_password, new_password):
        self.check_password(old_password)
        if new_password == '':
            new_password = None
        if self.has_seed():
            decoded = self.get_seed(old_password)
            self.seed = pw_encode(decoded, new_password, version=PW_HASH_VERSION_LATEST)
        if self.passphrase:
            decoded = self.get_passphrase(old_password)
            self.passphrase = pw_encode(decoded, new_password, version=PW_HASH_VERSION_LATEST)
        if self.xprv is not None:
            b = pw_decode(self.xprv, old_password, version=self.pw_hash_version)
            self.xprv = pw_encode(b, new_password, version=PW_HASH_VERSION_LATEST)
        self.pw_hash_version = PW_HASH_VERSION_LATEST

    def is_watching_only(self):
        return self.xprv is None

    def add_xpub(self, xpub):
        print('keystore:BIP32_KeyStore:add_xpub xpub={}'.format(xpub))
        assert is_xpub(xpub)
        self.xpub = xpub
        root_fingerprint, derivation_prefix = bip32.root_fp_and_der_prefix_from_xkey(xpub)
        self.add_key_origin(derivation_prefix=derivation_prefix, root_fingerprint=root_fingerprint)

    def add_xprv(self, xprv):
        print('keystore:BIP32_KeyStore:add_xprv xprv={}'.format(xprv))
        assert is_xprv(xprv)
        self.xprv = xprv
        self.add_xpub(bip32.xpub_from_xprv(xprv))

    def add_xprv_from_seed(self, bip32_seed, xtype, derivation):
        print('keystore:BIP32_KeyStore:add_xprv_from_seed bip32_seed={} xtype={} derivation={}'.format(bip32_seed.hex(), xtype, derivation))
        rootnode = BIP32Node.from_rootseed(bip32_seed, xtype=xtype)
        node = rootnode.subkey_at_private_derivation(derivation)
        print('keystore:BIP32_KeyStore:add_xprv_from_seed rootnode={} node={}'.format(rootnode, node))
        self.add_xprv(node.to_xprv())
        self.add_key_origin_from_root_node(derivation_prefix=derivation, root_node=rootnode)

    def get_private_key(self, sequence, password):
        print('keystore:BIP32_KeyStore:get_private_key sequence={}'.format(sequence))
        xprv = self.get_master_private_key(password)
        node = BIP32Node.from_xkey(xprv).subkey_at_private_derivation(sequence)
        pk = node.eckey.get_secret_bytes()
        return pk, True

    def get_keypair(self, sequence, password):
        print('keystore:BIP32_KeyStore:get_keypair sequence={}'.format(sequence))
        k, _ = self.get_private_key(sequence, password)
        cK = ecc.ECPrivkey(k).get_public_key_bytes()
        return cK, k

class Bip32Hsm_KeyStore(Software_KeyStore):
    #sys.path.extend(['../ep11', '../util'])
    #import grep11consts as ep11
    #import server_pb2 as pb, server_pb2_grpc, grpc
    import hashlib, hpcs_util as hpcsutil

    type = 'bip32hsm'

    # wallet_type is 'standard' or 'segwit'
    def __init__(self, d, wallet_type=None):
        Software_KeyStore.__init__(self, d)
        self.xtype = 'p2wpkh' if wallet_type == 'segwit' else 'p2pkh' # 'standard'
        print('Bip32Hsm_KeyStore:__init__:wallet_type={} xtype={} d={}'.format(wallet_type, self.xtype, json.dumps(d, indent=4)))
        self.root_receive = None
        self.root_change = None
        self.derived_nodes = {}
        if 'master_seed' in d:
            self.master_seed = d['master_seed']
            self.xtype = d['xtype']
        else:
            self.master_seed = self._generate_master_seed()
        if 'derived_nodes' in d:
            self.derived_nodes = d['derived_nodes']
        if 'root_receive' in d:
            self.root_receive = d['root_receive']
        if 'root_change' in d:
            self.root_change = d['root_change']
        if 'pw_hash_version' in d:
            self.pw_hash_version = d['pw_hash_version']
        if 'derivation' in d:
            self._derivation_prefix = d['derivation']
        else:
            # FIXME: here we support only the standard wallet type. The segqit type uses a different prefix.
            self._derivation_prefix = normalize_bip32_derivation("m/")
        #self.master_node = None
        #self.xtype = None

        print('Bip32Hsm_KeyStore:__init__:self={}'.format(json.dumps(self.short_dump(), indent=4)))

    def _generate_master_seed(self):
        print('Bip32Hsm_KeyStore:generate_master_seed')

        #    bip32_seed='f063e669b4e50c7e96dca632f91f68cde91e1ec9ab91266faad101fdcfd23656c7817160847b63e99b5f749fcbd58047c62952168abea646fd4dfbb4edcf8e0d'
        #    return bip32_seed

        with hpcsutil.Channel().get_channel() as channel:
            try:
                keyLen = 128
                cryptoClient = server_pb2_grpc.CryptoStub(channel)
                generateKeyRequest = pb.GenerateKeyRequest(
		            Mech = pb.Mechanism(Mechanism=ep11.CKM_GENERIC_SECRET_KEY_GEN),
		            Template = hpcsutil.ep11attributes({
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
                print('Bip32Hsm_KeyStore:generate_master_seed {}'.format(generateKeyResponse.KeyBytes))
                return generateKeyResponse.KeyBytes.hex()
            except grpc.RpcError as rpc_error:
                print('grpc error details=' + str(rpc_error.details()))
                raise Exception(rpc_error)
    
            except Exception as e:
                print(e)
                import traceback
                traceback.print_exc()
                raise Exception(e)

    def _bip32_deriveKey(self, deriveType, childKeyIndex, baseKey, chainCode):
        print('Bip32Hsm_KeyStore:bip32_deriveKey')
        with hpcsutil.Channel().get_channel() as channel:
            try:
                cryptoClient = server_pb2_grpc.CryptoStub(channel)
                deriveKeyRequest = pb.DeriveKeyRequest(
                    Mech = pb.Mechanism(
                        Mechanism = ep11.CKM_IBM_BTC_DERIVE,
                        BTCDeriveParameter = pb.BTCDeriveParm(
                            Type = deriveType,
                            ChildKeyIndex = childKeyIndex,
                            ChainCode = bytes.fromhex(chainCode),
                            Version = 1
                        )
                    ),
                    Template = hpcsutil.ep11attributes({
                        ep11.CKA_VERIFY:          True,
                        ep11.CKA_EXTRACTABLE:     False,
                        ep11.CKA_DERIVE:          True,
                        ep11.CKA_KEY_TYPE:        ep11.CKK_ECDSA,
                        ep11.CKA_VALUE_LEN:       0,
                        ep11.CKA_IBM_USE_AS_DATA: True
                    }),
                    BaseKey = bytes.fromhex(baseKey)
                )
                deriveKeyResponse = cryptoClient.DeriveKey(deriveKeyRequest)

                print("Derived Key type={} index={}".format(pb.BTCDeriveParm.BTCDeriveType.Name(deriveType), childKeyIndex))

                return deriveKeyResponse.NewKeyBytes.hex(), deriveKeyResponse.CheckSum.hex()

            except grpc.RpcError as rpc_error:
                print('grpc error details=' + str(rpc_error.details()))
                raise Exception(rpc_error)
    
            except Exception as e:
                print(e)
                import traceback
                traceback.print_exc()
                raise Exception(e)

    def sign(self, privateKey_bytes, publicKey_bytes, signData):
        privateKey = bytes.fromhex(privateKey_bytes)
        publicKey = bytes.fromhex(publicKey_bytes)
        with hpcsutil.Channel().get_channel() as channel:
            try:
                cryptoClient = server_pb2_grpc.CryptoStub(channel)

                signSingleRequest = pb.SignSingleRequest(
                    Mech = pb.Mechanism(Mechanism = ep11.CKM_ECDSA),
                    PrivKey = privateKey,
                    Data = signData
                )
                signSingleResponse = cryptoClient.SignSingle(signSingleRequest)

                print("Data signed")

                verifySingleRequest = pb.VerifySingleRequest(
                    Mech = pb.Mechanism(Mechanism = ep11.CKM_ECDSA),
                    PubKey = publicKey,
                    Data = signData,
                    Signature = signSingleResponse.Signature
                )

                cryptoClient.VerifySingle(verifySingleRequest)

                print("Signature verified")

                return signSingleResponse.Signature

            except grpc.RpcError as rpc_error:
                print('grpc error details=' + str(rpc_error.details()))
                raise Exception(rpc_error)

            except Exception as e:
                print(e)
                import traceback
                traceback.print_exc()
                raise Exception(e)

    def _generate_root_node(self, master_seed):
        # master = "m/"
        masterSecretKey, masterChainCode = self._bip32_deriveKey(
            pb.BTCDeriveParm.CkBIP0032MASTERK,
		    0,
            master_seed,
		    b"".hex()
	    )
        path = 'm/'
        if self.xtype is 'p2wpkh':
            # master = "m/0'/"
            masterSecretKey, masterChainCode = self._bip32_deriveKey(
                pb.BTCDeriveParm.CkBIP0032PRV2PRV,
		        2147483648, # 0x80000000
                masterSecretKey,
                masterChainCode
	        )
            path = 'm/2147483648'
        node = {'privkey': {'key': masterSecretKey, 'chaincode': masterChainCode},
                'path': path}
        print('_generate_root_node: {}'.format(json.dumps(node, indent=4)))
        return node

    def _public_derived_node(self, relative_path, node):
        print('Bip32Hsm_KeyStore:public_derived_node {} {}'.format(relative_path, node))
        last_index = relative_path[-1]
        key = node['privkey']['key']
        chaincode = node['privkey']['chaincode']
        path = node['path']
        print('last_index={} {} {}'.format(last_index, relative_path[:-1], path))
        for child_index in relative_path[:-1]:
            key, chaincode = self._bip32_deriveKey(pb.BTCDeriveParm.CkBIP0032PRV2PRV, child_index, key, chaincode)
            path = path + '/' + str(child_index)
        privkey, privchaincode = self._bip32_deriveKey(pb.BTCDeriveParm.CkBIP0032PRV2PRV, last_index, key, chaincode)
        pubkey, pubchaincode = self._bip32_deriveKey(pb.BTCDeriveParm.CkBIP0032PRV2PUB, last_index, key, chaincode)
        path = path + '/' + str(last_index)

        node = {'pubkey': {'key': pubkey, 'chaincode': pubchaincode},
                'privkey': {'key': privkey, 'chaincode': privchaincode},
                'path': path}
    
        print('Bip32Hsm_KeyStore:public_derived_node node={}'.format(json.dumps(node, indent=4)))

        pubkeyBytesHex = hpcsutil.GetPubkeyBytesFromSPKI(bytes.fromhex(pubkey)).hex()

        address = bitcoin.pubkey_to_address(self.xtype, pubkeyBytesHex)

        print('Bip32Hsm_KeyStore:public_derived_node node={} address={}'.format(json.dumps(node, indent=4), address))

        self.add_derived_node(node, address)

        return node

    def add_derived_node(self, node, address):
        self.derived_nodes[address] = node
        print('add_derived_node: {}'.format(json.dumps(self.derived_nodes, indent=4)))

    def get_derivation_prefix(self) -> Optional[str]:
        print('Bip32Hsm_KeyStore:get_derivation_prefix prefix={}'.format(self._derivation_prefix))
        return self._derivation_prefix

    def is_deterministic(self):
        return True

    def dump(self):
        print('Bip32Hsm_KeyStore:dump')
        # d = Deterministic_KeyStore.dump(self)
        d = {
            'type': self.type,
            'xtype': self.xtype,
            'pw_hash_version': self.pw_hash_version,
            'derivation': self.get_derivation_prefix(),
            'master_seed': self.master_seed,
            #'root_fingerprint': self.get_root_fingerprint(),
            #'derived_nodes': json.dumps(self.derived_nodes, indent=4)
        }
        d['root_receive'] = self.root_receive
        d['root_change'] = self.root_change
        d['derived_nodes'] = self.derived_nodes
        #if self.seed:
        #    d['seed'] = self.seed
        #if self.passphrase:
        #    d['passphrase'] = self.passphrase
        # d['xpub'] = self.xpub
        # d['xprv'] = self.xprv
        #d['root_fingerprint'] = self.get_root_fingerprint()
        print('Bip32Hsm_KeyStore:dump {}'.format(json.dumps(self.derived_nodes, indent=4)))
        print('Bip32Hsm_KeyStore:dump {}'.format(json.dumps(d, indent=4)))
        return d

    def short_dump(self):
        print('Bip32Hsm_KeyStore:short_dump')
        d = {
            'type': self.type,
            'xtype': self.xtype,
            'pw_hash_version': self.pw_hash_version,
            'derivation': self.get_derivation_prefix(),
            'master_seed': self.master_seed,
        }
        d['root_receive'] = self.root_receive
        d['root_change'] = self.root_change
        d['num_derived_nodes'] = len(self.derived_nodes)
        return d

    def get_public_key(self, address):
        if address not in self.derived_nodes:
            print('keystore:Bip32Hsm_Keystore:get_public_key NOT FOUND address={} derived_nodes={}'.format(address, json.dumps(self.derived_nodes, indent=4)))
            raise Exception(_('Address not found.'))
        print('keystore:Bip32Hsm_Keystore:get_public_key FOUND {}'.format(json.dumps(self.derived_nodes[address], indent=4)))
        pubkey = self.derived_nodes[address]['pubkey']['key']
        pubkeyBytes = hpcsutil.GetPubkeyBytesFromSPKI(bytes.fromhex(pubkey))
        return pubkeyBytes.hex()

    def get_private_key(self, address, password):
        if address not in self.derived_nodes:
            print('keystore:Bip32Hsm_Keystore:get_private_key NOT FOUND address={} derived_nodes={}'.format(address, json.dumps(self.derived_nodes, indent=4)))
            raise Exception(_('Address not found.'))
        print('keystore:Bip32Hsm_Keystore:get_private_key FOUND {}'.format(json.dumps(self.derived_nodes[address], indent=4)))
        privkeyHex = self.derived_nodes[address]['privkey']['key']
        return bytes.fromhex(privkeyHex), True

    def get_pubkey_derivation(self, pubkey, txin, *, only_der_suffix=True):
        for address in self.derived_nodes.keys():
            pubkeyBlobHex = self.derived_nodes[address]['pubkey']['key']
            if hpcsutil.GetPubkeyBytesFromSPKI(bytes.fromhex(pubkeyBlobHex)) == pubkey:
                print('keystore:Bip32Hsm_Keystore:get_pubkey_derivation FOUND {}'.format(json.dumps(self.derived_nodes[address], indent=4)))
                return address
        print('keystore:Bip32Hsm_Keystore:get_pubkey_derivation NOT FOUND pubkey={} derived_nodes={}'.format(pubkey.hex(), json.dumps(self.derived_nodes, indent=4)))
        raise Exception(('Pubkey not found.'))
        #return None

    def derive_pubkey(self, for_change, n) -> str:
        print('Bip32Hsm_KeyStore:derive_pubkey')
        for_change = int(for_change)
        assert for_change in (0, 1)
        # xpub = self.xpub_change if for_change else self.xpub_receive
        root = self.root_change if for_change else self.root_receive
        print('keystore:Bip32Hsm_KeyStore:derive_pubkey: root={} for_change={} n={}'.format(root, for_change, n))
        if root is None:
            #rootnode = BIP32Node.from_xkey(self.xpub)
            # generate the master node
            common_root = self._generate_root_node(self.master_seed)
            #xpub = rootnode.subkey_at_public_derivation((for_change,)).to_xpub()
            # generate a root node (m/0 for root_receive, m/1 for root_change)
            root = self._public_derived_node((for_change,), common_root)
            if for_change:
                self.root_change = root
            else:
                self.root_receive = root
        return self.get_pubkey_from_root(root, (n,))

    def get_pubkey_from_root(self, root, sequence):
        node = self._public_derived_node(sequence, root)
        #BIP32Node.from_xkey(xpub).subkey_at_public_derivation(sequence)
        print('keystore:Bip32Hsm_KeyStore:get_pubkey_from_root: root={} sequence={} node={}'.format(root, sequence, node))
        pubkeyBytes = hpcsutil.GetPubkeyBytesFromSPKI(bytes.fromhex(node['pubkey']['key'])) # node.eckey.get_public_key_hex(compressed=True)
        print('keystore:Bip32Hsm_KeyStore:get_pubkey_from_root: pubkeyBytes={}'.format(pubkeyBytes.hex()))
        return pubkeyBytes.hex()

    def _get_private_key(self, sequence, password):
        print('keystore:BIP32Hsm_KeyStore:get_private_key sequence={}'.format(sequence))
        master_node = self._generate_root_node(self.master_seed)

        node = self._public_derived_node(sequence, master_node)

        print('@@@keystore:BIP32Hsm_KeyStore:get_private_key node={}'.format(json.dumps(node, indent=4)))
        print('@@@keystore:BIP32Hsm_KeyStore:get_private_key pubkey={}'.format(hpcsutil.GetPubkeyBytesFromSPKI(bytes.fromhex(node['pubkey']['key'])).hex()))

        #key = master_node['privkey']['key']
        #chaincode = master_node['privkey']['chaincode']
        #for child_index in sequence:
        #    key, chaincode = self._bip32_deriveKey(pb.BTCDeriveParm.CkBIP0032PRV2PRV, child_index, key, chaincode)

        key = node['privkey']['key']
        chaincode = node['privkey']['chaincode']
        print('@@@keystore:BIP32Hsm_KeyStore:get_private_key privateky={} chaincode={}'.format(key, chaincode))
        return bytes.fromhex(key), True

    def get_fp_and_derivation_to_be_used_in_partial_tx(self, der_suffix: Sequence[int], *,
                                                       only_der_suffix: bool = True) -> Tuple[bytes, Sequence[int]]:
        """Returns fingerprint and derivation path corresponding to a derivation suffix.
        The fingerprint is either the root fp or the intermediate fp, depending on what is available
        and 'only_der_suffix', and the derivation path is adjusted accordingly.
        """
        print('keystore:Bip32Hsm_KeyStore:get_fp_and_derivation_to_be_used_in_partial_tx der_suffix={} only_der_suffix={}'.format(der_suffix, only_der_suffix))
        fingerprint_hex = self.get_root_fingerprint()
        der_prefix_str = self.get_derivation_prefix()
        if not only_der_suffix and fingerprint_hex is not None and der_prefix_str is not None:
            # use root fp, and true full path
            print('keystore:Bip32Hsm_KeyStore:get_fp_and_derivation_to_be_used_in_partial_tx: use ROOT fp!!!!!!!!!!!!!')
            fingerprint_bytes = bfh(fingerprint_hex)
            print('keystore:Bip32Hsm_KeyStore:get_fp_and_derivation_to_be_used_in_partial_tx: fingerprint_bytes={}'.format(fingerprint_bytes))
            print('keystore:Bip32Hsm_KeyStore:get_fp_and_derivation_to_be_used_in_partial_tx: der_prefix_str={}'.format(der_prefix_str))
            der_prefix_ints = convert_bip32_path_to_list_of_uint32(der_prefix_str)
            print('keystore:Bip32Hsm_KeyStore:get_fp_and_derivation_to_be_used_in_partial_tx: der_prefix_ints={}'.format(der_prefix_ints))
        else:
            # use intermediate fp, and claim der suffix is the full path
            # FIXME: this temporary
            print('keystore:Bip32Hsm_KeyStore:get_fp_and_derivation_to_be_used_in_partial_tx: use intermediate fp root_receive pubkey={}'.format(self.root_receive['pubkey']['key']))
            pubkey_bytes = bytes.fromhex(self.root_receive['pubkey']['key'])
            #fingerprint_bytes = bfh(fingerprint_hex) #BIP32Node.from_xkey(self.xpub).calc_fingerprint_of_this_node()
            fingerprint_bytes = hash_160(pubkey_bytes)[0:4]
            der_prefix_ints = convert_bip32_path_to_list_of_uint32('m')
        der_full = der_prefix_ints + list(der_suffix)
        print('keystore:Bip32Hsm_KeyStore:get_fp_and_derivation_to_be_used_in_partial_tx fingerprint_bytes={} der_full={}'.format(fingerprint_bytes, der_full))
        return fingerprint_bytes, der_full

    def get_root_fingerprint(self) -> Optional[str]:
        """Returns the bip32 fingerprint of the top level node.
        This top level node is the node at the beginning of the derivation prefix,
        i.e. applying the derivation prefix to it will result self.xpub
        Note that the return value might be None; if it is unknown.
        """
        master_node = self._generate_root_node(self.master_seed)
        root = self._public_derived_node((0,), master_node)
        pubkeyBytes = hpcsutil.GetPubkeyBytesFromSPKI(bytes.fromhex(root['pubkey']['key']))
        self._root_fingerprint = hash_160(pubkeyBytes)[0:4].hex()
        print('keystore:Bip32Hsm_KeyStore:get_root_fingerprint fingerprintt={}'.format(self._root_fingerprint))
        return self._root_fingerprint

    def check_password(self, password):
        print('check_password: TODO')
        return

    def sign_message(self, sequence, message, password) -> bytes:
        raise NotImplementedError()  # not supported

    def decrypt_message(self, sequence, message, password) -> bytes:
        raise NotImplementedError()  # not supported

class HyperProtectServiceException(Exception):
    def __init__(self, errors: dict):
        self.errors = errors

import os, dap_consts, txqueue
from dap_resource import DAPDBaaSResource

class DAP_KeyStore(Software_KeyStore):
    #sys.path.extend(['../ep11', '../util'])
    #import grep11consts as ep11
    #import server_pb2 as pb, server_pb2_grpc, grpc
    import hashlib, hpcs_util as hpcsutil

    type = 'dap'

    dap_resource = None

    def __init__(self, d, wallet_type=None):
        Software_KeyStore.__init__(self, d)
        if 'xtype' in d:
            self.xtype = d['xtype']
        else:
            self.xtype = 'p2wpkh' if wallet_type == 'segwit' else 'p2pkh' # 'standard'
        if 'watch_only' not in d:
            self.watch_only = False
        else:
            self.watch_only = d['watch_only']
        print('DAP_KeyStore:__init__:wallet_type={} watch_only={} xtype={} d={}'.format(wallet_type, self.watch_only, self.xtype, json.dumps(d, indent=4)))
        if 'userid' not in d or 'password' not in d:
            raise Exception('DAP_KeyStore requires userid and password')
        self.userid = d['userid']
        self.password = d['password']
        if 'host' not in d or 'port' not in d:
            raise Exception('DAP_KeyStore requires host and port for transaction proposer')
        self.host = d['host']
        self.port = str(d['port'])
        if 'seedid' in d:
            self.seedid = d['seedid']
        else:
            self.seedid = self._generate_master_seed()
        self.root_receive = None
        self.root_change = None
        self.derived_nodes = {}
        if 'derived_nodes' in d:
            self.derived_nodes = d['derived_nodes']
        if 'root_receive' in d:
            self.root_receive = d['root_receive']
        if 'root_change' in d:
            self.root_change = d['root_change']
        if 'pw_hash_version' in d:
            self.pw_hash_version = d['pw_hash_version']
        if 'derivation' in d:
            self._derivation_prefix = d['derivation']
        else:
            # FIXME: here we support only the standard wallet type. The segqit type uses a different prefix.
            self._derivation_prefix = normalize_bip32_derivation("m/")

        print('DAP_KeyStore:__init__:self={}'.format(json.dumps(self.short_dump(), indent=4)))

    def is_watching_only(self) -> bool:
        if self.watch_only:
            return True
        return super().is_watching_only()

    def __send_request_to_txqueue(self, func, args):
        if func != dap_client.derive_pubkey:
            raise Exception('Cannot send any request to txqueue except for derive_pubkey')

        if not DAP_KeyStore.dap_resource:
            if 'DAP_SERVICE' not in os.environ:
                raise Exception('DAP_SERVICE not specified')
            DAP_KeyStore.dap_resource = DAPDBaaSResource(serviceid=dap_consts.SERVICE_NAME_MAP[os.environ['DAP_SERVICE']])

        res = {
            'status': None,
            'pubkey': None,
            'chaincode': None,
        }

        doc = txqueue.create_request_document(
                type=dap_consts.INTERNAL_OPERATION,
                method=dap_consts.DERIVE_PUBKEY_METHOD,
                params={'userid': self.userid,
                        'seedid': args[0],
                        'bip32path': args[1]}
        )
        # Skip policy services
        for serviceid in dap_consts.POLICY_SERVICES:
            doc[serviceid] = 'dummy'
        query = txqueue.create_response_query(type=dap_consts.INTERNAL_OPERATION, id=doc['request']['id'])
        doc, code, res['status'] = txqueue.send_request(DAP_KeyStore.dap_resource.txqueue_client, doc, query)

        if code == 500:
            raise Exception('Failed to derive a public key')

        res['pubkey'] = doc['result']['pubkey']
        res['chaincode'] = doc['result']['chaincode']
        return res

    def __send_request(self, func, args=None):
        if self.watch_only:
            return self.__send_request_to_txqueue(func, args)

        if args is not None:
            res = func(self.host, self.port, self.userid, *args)
        else:
            res = func(self.host, self.port, self.userid)
        if type(res) is dict:
            return res

        # Token can be expired. Try again after login.
        dap_client.login(self.host, self.port, self.userid, self.password)
        if args is not None:
            return func(self.host, self.port, self.userid, *args)
        else:
            return func(self.host, self.port, self.userid)

    def _generate_master_seed(self):
        print('DAP_KeyStore:generate_master_seed')
        res = self.__send_request(dap_client.create_seed)
        if res is None:
            raise Exception('Failed to create a seed')
        print('seedid={}'.format(res['seedid']))
        return res['seedid']

    def get_derivation_prefix(self) -> Optional[str]:
        print('DAP_KeyStore:get_derivation_prefix prefix={}'.format(self._derivation_prefix))
        return self._derivation_prefix

    def is_deterministic(self):
        return True

    def dump(self):
        print('DAP_KeyStore:dump')
        # d = Deterministic_KeyStore.dump(self)
        d = {
            'type': self.type,
            'xtype': self.xtype,
            'pw_hash_version': self.pw_hash_version,
            'derivation': self.get_derivation_prefix(),
            'seedid': self.seedid,
            'userid': self.userid,
            'password': self.password,
            'host': self.host,
            'port': self.port,
            'watch_only': self.watch_only,
        }
        d['root_receive'] = self.root_receive
        d['root_change'] = self.root_change
        d['derived_nodes'] = self.derived_nodes
        #if self.seed:
        #    d['seed'] = self.seed
        #if self.passphrase:
        #    d['passphrase'] = self.passphrase
        # d['xpub'] = self.xpub
        # d['xprv'] = self.xprv
        #d['root_fingerprint'] = self.get_root_fingerprint()
        print('DAP_KeyStore:dump {}'.format(json.dumps(self.derived_nodes, indent=4)))
        print('DAP_KeyStore:dump {}'.format(json.dumps(d, indent=4)))
        return d

    def short_dump(self):
        print('DAP_KeyStore:short_dump')
        d = {
            'type': self.type,
            'xtype': self.xtype,
            'pw_hash_version': self.pw_hash_version,
            'derivation': self.get_derivation_prefix(),
            'seedid': self.seedid,
        }
        d['root_receive'] = self.root_receive
        d['root_change'] = self.root_change
        d['num_derived_nodes'] = len(self.derived_nodes)
        return d

    def _generate_master_node(self):
        path = 'm/'
        if self.xtype == 'p2wpkh':
            path = 'm/2147483648'
        node = {'path': path}
        print('_generate_master_node: {}'.format(json.dumps(node, indent=4)))
        return node

    def _add_derived_node(self, node, address):
        self.derived_nodes[address] = node
        print('add_derived_node: {}'.format(json.dumps(self.derived_nodes, indent=4)))

    def _public_derived_node(self, relative_path, node):
        print('DAP_KeyStore:public_derived_node_1 {} {}'.format(relative_path, node))
        if 'pubkey' not in node:
            # Create root_receive or root_change
            if len(relative_path) != 1:
                raise Exception('Length of relative path should be 1 for root_receive and root_change. relative_path={}'.format(relative_path))
            if relative_path[0] != 0 and relative_path[0] != 1:
                raise Exception('Relative path for root_receive and and root_change should be 0 and 1 respectively. relative_path={}'.format(relative_path))
            absolute_path = relative_path
            if self.xtype == 'p2wpkh':
                absolute_path = [2147483648] + list(relative_path)
            absolute_path_str = bip32.convert_bip32_intpath_to_strpath(absolute_path)
            print('DAP_KeyStore:public_derived_node_2 xtype={} absolute_path={} absolute_path_str={}'.format(self.xtype, absolute_path, absolute_path_str))
            res = self.__send_request(dap_client.derive_pubkey, [self.seedid, absolute_path_str])
            path = node['path'] + '/' + str(relative_path[0])
            node = {'pubkey': {'key': res['pubkey'], 'chaincode': res['chaincode']},
                    'path': path}
        else:
            ### Disable local derivation because bip32.CKD_pub and HPCS return different public keys
            localPubkeyBytes = hpcsutil.GetPubkeyBytesFromSPKI(bytes.fromhex(node['pubkey']['key']))
            compressedPubkeyBytes = ecc.ECPubkey(localPubkeyBytes).get_public_key_bytes(compressed=True)
            chaincodeBytes = bytes.fromhex(node['pubkey']['chaincode'])

            path = node['path']
            for child_index in relative_path:
                compressedPubkeyBytes, chaincodeBytes = bip32.CKD_pub(compressedPubkeyBytes, chaincodeBytes, child_index)
                path = path + '/' + str(child_index)
            if self.xtype == 'p2wpkh':
                localPubkeyBytes = ecc.ECPubkey(compressedPubkeyBytes).get_public_key_bytes(compressed=True)
            else:
                localPubkeyBytes = ecc.ECPubkey(compressedPubkeyBytes).get_public_key_bytes(compressed=False)
            localSPKI = hpcsutil.GetSPKIFromPubkeyBytes(localPubkeyBytes)
            node = {'pubkey': {'key': localSPKI.hex(), 'chaincode': chaincodeBytes.hex()},
                    'path': path}

            '''
            remotePubkeyBytes = hpcsutil.GetPubkeyBytesFromSPKI(doc['pubkey'])
            print('LocalPubkey ={}'.format(localPubkeyBytes.hex()))
            print('RemotePubkey={}'.format(remotePubkeyBytes.hex()))

            remoteSPKI = hpcsutil.GetSPKIFromPubkeyBytes(remotePubkeyBytes)
            print('LocalSPKI ={}'.format(localSPKI.hex()))
            print('RemoteSPKI={}'.format(remoteSPKI.hex()))
            '''

        print('DAP_KeyStore:public_derived_node_3 node={}'.format(json.dumps(node, indent=4)))

        pubkeyBytesHex = hpcsutil.GetPubkeyBytesFromSPKI(bytes.fromhex(node['pubkey']['key'])).hex()

        address = bitcoin.pubkey_to_address(self.xtype, pubkeyBytesHex)

        print('DAP_KeyStore:public_derived_node_4 node={} address={}'.format(json.dumps(node, indent=4), address))

        self._add_derived_node(node, address)

        return node

    def get_public_key(self, address):
        if address not in self.derived_nodes:
            print('keystore:DAP_Keystore:get_public_key NOT FOUND address={} derived_nodes={}'.format(address, json.dumps(self.derived_nodes, indent=4)))
            # raise Exception(('Address not found.'))
            # Occassionally, public keys and address are not stored in a wallet file.
            # In this case, we fall back to the original key derivation in Bip32Hsm_Wallet.get_public_key.
            # Fix by Nakaike
            return None
        print('keystore:DAP_Keystore:get_public_key FOUND {}'.format(json.dumps(self.derived_nodes[address], indent=4)))
        pubkey = self.derived_nodes[address]['pubkey']['key']
        pubkeyBytes = hpcsutil.GetPubkeyBytesFromSPKI(bytes.fromhex(pubkey))
        return pubkeyBytes.hex()

    def get_private_key(self, address, password):
        if address not in self.derived_nodes:
            print('keystore:DAP_Keystore:get_private_key NOT FOUND address={} derived_nodes={}'.format(address, json.dumps(self.derived_nodes, indent=4)))
            raise Exception(('Address not found.'))
        print('keystore:DAP_Keystore:get_private_key FOUND {}'.format(json.dumps(self.derived_nodes[address], indent=4)))
        path = self.derived_nodes[address]['path']
        dap_privkey = {
            'keystore': self,
            'path': path
        }
        return dap_privkey, True

    def sign_on_signing_service(self, payload, sync=True):
        if sync == True:
            return self.__send_request(dap_client.sign, [self.seedid, payload])
        else:
            return self.__send_request(dap_client.sign_request, [self.seedid, payload])

    def get_signs_from_signing_service(self, payload, sync=True):
        return self.__send_request(dap_client.sign_result, [self.seedid, payload])

    def get_pubkey_derivation(self, pubkey, txin, *, only_der_suffix=True):
        for address in self.derived_nodes.keys():
            pubkeyBlobHex = self.derived_nodes[address]['pubkey']['key']
            if hpcsutil.GetPubkeyBytesFromSPKI(bytes.fromhex(pubkeyBlobHex)) == pubkey:
                print('keystore:DAP_Keystore:get_pubkey_derivation FOUND {}'.format(json.dumps(self.derived_nodes[address], indent=4)))
                return address
        print('keystore:DAP_Keystore:get_pubkey_derivation NOT FOUND pubkey={} derived_nodes={}'.format(pubkey.hex(), json.dumps(self.derived_nodes, indent=4)))
        raise Exception(('Pubkey not found.'))
        #return None

    def derive_pubkey(self, for_change, n) -> str:
        print('DAP_KeyStore:derive_pubkey: for_change={} n={}'.format(for_change, n))
        for_change = int(for_change)
        assert for_change in (0, 1)

        root = self.root_change if for_change else self.root_receive
        print('keystore:DAP_KeyStore:derive_pubkey: for_change={} n={}'.format(for_change, n))
        if root is None:
            path = [for_change]
            master_node = self._generate_master_node()
            root = self._public_derived_node(path, master_node)
            if for_change:
                self.root_change = root
            else:
                self.root_receive = root
        return self.get_pubkey_from_root(root, (n,))

    def get_pubkey_from_root(self, root, sequence):
        print('keystore:DAP_KeyStore:get_pubkey_from_root: sequence={} root={}'.format(sequence, json.dumps(root, indent=4)))
        node = self._public_derived_node(sequence, root)
        pubkeyBytes = hpcsutil.GetPubkeyBytesFromSPKI(bytes.fromhex(node['pubkey']['key']))
        return pubkeyBytes.hex()

    def get_fp_and_derivation_to_be_used_in_partial_tx(self, der_suffix: Sequence[int], *,
                                                       only_der_suffix: bool = True) -> Tuple[bytes, Sequence[int]]:
        """Returns fingerprint and derivation path corresponding to a derivation suffix.
        The fingerprint is either the root fp or the intermediate fp, depending on what is available
        and 'only_der_suffix', and the derivation path is adjusted accordingly.
        """
        print('keystore:DAP_KeyStore:get_fp_and_derivation_to_be_used_in_partial_tx der_suffix={} only_der_suffix={}'.format(der_suffix, only_der_suffix))
        fingerprint_hex = self.get_root_fingerprint()
        der_prefix_str = self.get_derivation_prefix()
        if not only_der_suffix and fingerprint_hex is not None and der_prefix_str is not None:
            # use root fp, and true full path
            print('keystore:DAP_KeyStore:get_fp_and_derivation_to_be_used_in_partial_tx: use ROOT fp!!!!!!!!!!!!!')
            fingerprint_bytes = bfh(fingerprint_hex)
            print('keystore:DAP_KeyStore:get_fp_and_derivation_to_be_used_in_partial_tx: fingerprint_bytes={}'.format(fingerprint_bytes))
            print('keystore:DAP_KeyStore:get_fp_and_derivation_to_be_used_in_partial_tx: der_prefix_str={}'.format(der_prefix_str))
            der_prefix_ints = convert_bip32_path_to_list_of_uint32(der_prefix_str)
            print('keystore:DAP_KeyStore:get_fp_and_derivation_to_be_used_in_partial_tx: der_prefix_ints={}'.format(der_prefix_ints))
        else:
            # use intermediate fp, and claim der suffix is the full path
            # FIXME: this temporary
            print('keystore:DAP_KeyStore:get_fp_and_derivation_to_be_used_in_partial_tx: use intermediate fp root_receive pubkey={}'.format(self.root_receive['pubkey']['key']))
            pubkey_bytes = bytes.fromhex(self.root_receive['pubkey']['key'])
            #fingerprint_bytes = bfh(fingerprint_hex) #BIP32Node.from_xkey(self.xpub).calc_fingerprint_of_this_node()
            fingerprint_bytes = hash_160(pubkey_bytes)[0:4]
            der_prefix_ints = convert_bip32_path_to_list_of_uint32('m')
        der_full = der_prefix_ints + list(der_suffix)
        print('keystore:DAP_KeyStore:get_fp_and_derivation_to_be_used_in_partial_tx fingerprint_bytes={} der_full={}'.format(fingerprint_bytes, der_full))
        return fingerprint_bytes, der_full

    def get_root_fingerprint(self) -> Optional[str]:
        """Returns the bip32 fingerprint of the top level node.
        This top level node is the node at the beginning of the derivation prefix,
        i.e. applying the derivation prefix to it will result self.xpub
        Note that the return value might be None; if it is unknown.
        """
        master_node = self._generate_master_node()
        if self.root_receive:
            root = self.root_receive
        else:
            root = self._public_derived_node((0,), master_node)
        pubkeyBytes = hpcsutil.GetPubkeyBytesFromSPKI(bytes.fromhex(root['pubkey']['key']))
        self._root_fingerprint = hash_160(pubkeyBytes)[0:4].hex()
        print('keystore:DAP_KeyStore:get_root_fingerprint fingerprintt={}'.format(self._root_fingerprint))
        return self._root_fingerprint

    def check_password(self, password):
        print('check_password: TODO')
        return

    def sign_message(self, sequence, message, password) -> bytes:
        raise NotImplementedError()  # not supported

    def decrypt_message(self, sequence, message, password) -> bytes:
        raise NotImplementedError()  # not supported

class Old_KeyStore(Deterministic_KeyStore):

    type = 'old'

    def __init__(self, d):
        Deterministic_KeyStore.__init__(self, d)
        self.mpk = d.get('mpk')
        self._root_fingerprint = None

    def get_hex_seed(self, password):
        return pw_decode(self.seed, password, version=self.pw_hash_version).encode('utf8')

    def dump(self):
        d = Deterministic_KeyStore.dump(self)
        d['mpk'] = self.mpk
        return d

    def add_seed(self, seedphrase):
        Deterministic_KeyStore.add_seed(self, seedphrase)
        s = self.get_hex_seed(None)
        self.mpk = self.mpk_from_seed(s)

    def add_master_public_key(self, mpk):
        self.mpk = mpk

    def format_seed(self, seed):
        from . import old_mnemonic, mnemonic
        seed = mnemonic.normalize_text(seed)
        # see if seed was entered as hex
        if seed:
            try:
                bfh(seed)
                return str(seed)
            except Exception:
                pass
        words = seed.split()
        seed = old_mnemonic.mn_decode(words)
        if not seed:
            raise Exception("Invalid seed")
        return seed

    def get_seed(self, password):
        from . import old_mnemonic
        s = self.get_hex_seed(password)
        return ' '.join(old_mnemonic.mn_encode(s))

    @classmethod
    def mpk_from_seed(klass, seed):
        secexp = klass.stretch_key(seed)
        privkey = ecc.ECPrivkey.from_secret_scalar(secexp)
        return privkey.get_public_key_hex(compressed=False)[2:]

    @classmethod
    def stretch_key(self, seed):
        x = seed
        for i in range(100000):
            x = hashlib.sha256(x + seed).digest()
        return string_to_number(x)

    @classmethod
    def get_sequence(self, mpk, for_change, n):
        return string_to_number(sha256d(("%d:%d:"%(n, for_change)).encode('ascii') + bfh(mpk)))

    @classmethod
    def get_pubkey_from_mpk(self, mpk, for_change, n):
        z = self.get_sequence(mpk, for_change, n)
        master_public_key = ecc.ECPubkey(bfh('04'+mpk))
        public_key = master_public_key + z*ecc.generator()
        return public_key.get_public_key_hex(compressed=False)

    def derive_pubkey(self, for_change, n) -> str:
        print('keystore:old_keystore:derive_pubkey: for_change={} n={}'.format(for_change, n))
        return self.get_pubkey_from_mpk(self.mpk, for_change, n)

    def get_private_key_from_stretched_exponent(self, for_change, n, secexp):
        secexp = (secexp + self.get_sequence(self.mpk, for_change, n)) % ecc.CURVE_ORDER
        pk = number_to_string(secexp, ecc.CURVE_ORDER)
        return pk

    def get_private_key(self, sequence, password):
        seed = self.get_hex_seed(password)
        secexp = self.stretch_key(seed)
        self.check_seed(seed, secexp=secexp)
        for_change, n = sequence
        pk = self.get_private_key_from_stretched_exponent(for_change, n, secexp)
        return pk, False

    def check_seed(self, seed, *, secexp=None):
        if secexp is None:
            secexp = self.stretch_key(seed)
        master_private_key = ecc.ECPrivkey.from_secret_scalar(secexp)
        master_public_key = master_private_key.get_public_key_bytes(compressed=False)[1:]
        if master_public_key != bfh(self.mpk):
            raise InvalidPassword()

    def check_password(self, password):
        seed = self.get_hex_seed(password)
        self.check_seed(seed)

    def get_master_public_key(self):
        return self.mpk

    def get_derivation_prefix(self) -> str:
        return 'm'

    def get_root_fingerprint(self) -> str:
        if self._root_fingerprint is None:
            master_public_key = ecc.ECPubkey(bfh('04'+self.mpk))
            xfp = hash_160(master_public_key.get_public_key_bytes(compressed=True))[0:4]
            self._root_fingerprint = xfp.hex().lower()
        return self._root_fingerprint

    # TODO Old_KeyStore and Xpub could share a common baseclass?
    def get_fp_and_derivation_to_be_used_in_partial_tx(self, der_suffix: Sequence[int], *,
                                                       only_der_suffix: bool = True) -> Tuple[bytes, Sequence[int]]:
        fingerprint_hex = self.get_root_fingerprint()
        der_prefix_str = self.get_derivation_prefix()
        fingerprint_bytes = bfh(fingerprint_hex)
        der_prefix_ints = convert_bip32_path_to_list_of_uint32(der_prefix_str)
        der_full = der_prefix_ints + list(der_suffix)
        return fingerprint_bytes, der_full

    def update_password(self, old_password, new_password):
        self.check_password(old_password)
        if new_password == '':
            new_password = None
        if self.has_seed():
            decoded = pw_decode(self.seed, old_password, version=self.pw_hash_version)
            self.seed = pw_encode(decoded, new_password, version=PW_HASH_VERSION_LATEST)
        self.pw_hash_version = PW_HASH_VERSION_LATEST


class Hardware_KeyStore(KeyStore, Xpub):
    hw_type: str
    device: str
    plugin: 'HW_PluginBase'
    thread: Optional['TaskThread'] = None

    type = 'hardware'

    def __init__(self, d):
        Xpub.__init__(self, derivation_prefix=d.get('derivation'), root_fingerprint=d.get('root_fingerprint'))
        KeyStore.__init__(self)
        # Errors and other user interaction is done through the wallet's
        # handler.  The handler is per-window and preserved across
        # device reconnects
        self.xpub = d.get('xpub')
        self.label = d.get('label')
        self.handler = None
        run_hook('init_keystore', self)

    def set_label(self, label):
        self.label = label

    def may_have_password(self):
        return False

    def is_deterministic(self):
        return True

    def get_type_text(self) -> str:
        return f'hw[{self.hw_type}]'

    def dump(self):
        return {
            'type': self.type,
            'hw_type': self.hw_type,
            'xpub': self.xpub,
            'derivation': self.get_derivation_prefix(),
            'root_fingerprint': self.get_root_fingerprint(),
            'label':self.label,
        }

    def unpaired(self):
        '''A device paired with the wallet was disconnected.  This can be
        called in any thread context.'''
        self.logger.info("unpaired")

    def paired(self):
        '''A device paired with the wallet was (re-)connected.  This can be
        called in any thread context.'''
        self.logger.info("paired")

    def can_export(self):
        return False

    def is_watching_only(self):
        '''The wallet is not watching-only; the user will be prompted for
        pin and passphrase as appropriate when needed.'''
        assert not self.has_seed()
        return False

    def get_password_for_storage_encryption(self) -> str:
        from .storage import get_derivation_used_for_hw_device_encryption
        client = self.plugin.get_client(self)
        derivation = get_derivation_used_for_hw_device_encryption()
        xpub = client.get_xpub(derivation, "standard")
        password = self.get_pubkey_from_xpub(xpub, ())
        return password

    def has_usable_connection_with_device(self) -> bool:
        if not hasattr(self, 'plugin'):
            return False
        client = self.plugin.get_client(self, force_pair=False)
        if client is None:
            return False
        return client.has_usable_connection_with_device()

    def ready_to_sign(self):
        return super().ready_to_sign() and self.has_usable_connection_with_device()

    def opportunistically_fill_in_missing_info_from_device(self, client: 'HardwareClientBase'):
        assert client is not None
        if self._root_fingerprint is None:
            self._root_fingerprint = client.request_root_fingerprint_from_device()
            self.is_requesting_to_be_rewritten_to_wallet_file = True
        if self.label != client.label():
            self.label = client.label()
            self.is_requesting_to_be_rewritten_to_wallet_file = True


def bip39_normalize_passphrase(passphrase):
    return normalize('NFKD', passphrase or '')

def bip39_to_seed(mnemonic, passphrase):
    import hashlib, hmac
    PBKDF2_ROUNDS = 2048
    mnemonic = normalize('NFKD', ' '.join(mnemonic.split()))
    passphrase = bip39_normalize_passphrase(passphrase)
    return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'),
        b'mnemonic' + passphrase.encode('utf-8'), iterations = PBKDF2_ROUNDS)


def bip39_is_checksum_valid(mnemonic: str) -> Tuple[bool, bool]:
    """Test checksum of bip39 mnemonic assuming English wordlist.
    Returns tuple (is_checksum_valid, is_wordlist_valid)
    """
    words = [ normalize('NFKD', word) for word in mnemonic.split() ]
    words_len = len(words)
    wordlist = load_wordlist("english.txt")
    n = len(wordlist)
    i = 0
    words.reverse()
    while words:
        w = words.pop()
        try:
            k = wordlist.index(w)
        except ValueError:
            return False, False
        i = i*n + k
    if words_len not in [12, 15, 18, 21, 24]:
        return False, True
    checksum_length = 11 * words_len // 33  # num bits
    entropy_length = 32 * checksum_length  # num bits
    entropy = i >> checksum_length
    checksum = i % 2**checksum_length
    entropy_bytes = int.to_bytes(entropy, length=entropy_length//8, byteorder="big")
    hashed = int.from_bytes(sha256(entropy_bytes), byteorder="big")
    calculated_checksum = hashed >> (256 - checksum_length)
    return checksum == calculated_checksum, True


def from_bip39_seed(seed, passphrase, derivation, xtype=None):
    k = BIP32_KeyStore({})
    bip32_seed = bip39_to_seed(seed, passphrase)
    if xtype is None:
        xtype = xtype_from_derivation(derivation)
    k.add_xprv_from_seed(bip32_seed, xtype, derivation)
    return k


PURPOSE48_SCRIPT_TYPES = {
    'p2wsh-p2sh': 1,  # specifically multisig
    'p2wsh': 2,       # specifically multisig
}
PURPOSE48_SCRIPT_TYPES_INV = inv_dict(PURPOSE48_SCRIPT_TYPES)


def xtype_from_derivation(derivation: str) -> str:
    """Returns the script type to be used for this derivation."""
    bip32_indices = convert_bip32_path_to_list_of_uint32(derivation)
    print('xtype_from_derivation derivation={} bip32_indicies={}'.format(derivation, bip32_indices))
    if len(bip32_indices) >= 1:
        if bip32_indices[0] == 84 + BIP32_PRIME:
            print('xtype_from_derivation p2wpkh')
            return 'p2wpkh'
        elif bip32_indices[0] == 49 + BIP32_PRIME:
            print('xtype_from_derivation p2wpkh-p2sh')
            return 'p2wpkh-p2sh'
        elif bip32_indices[0] == 44 + BIP32_PRIME:
            print('xtype_from_derivation standard')
            return 'standard'
        elif bip32_indices[0] == 45 + BIP32_PRIME:
            print('xtype_from_derivation standard')
            return 'standard'

    if len(bip32_indices) >= 4:
        if bip32_indices[0] == 48 + BIP32_PRIME:
            # m / purpose' / coin_type' / account' / script_type' / change / address_index
            script_type_int = bip32_indices[3] - BIP32_PRIME
            script_type = PURPOSE48_SCRIPT_TYPES_INV.get(script_type_int)
            if script_type is not None:
                print('xtype_from_derivation script_type={}'.format(script_type))
                return script_type
    print('xtype_from_derivation standard (others)')
    return 'standard'


hw_keystores = {}

def register_keystore(hw_type, constructor):
    hw_keystores[hw_type] = constructor

def hardware_keystore(d) -> Hardware_KeyStore:
    hw_type = d['hw_type']
    if hw_type in hw_keystores:
        constructor = hw_keystores[hw_type]
        return constructor(d)
    raise WalletFileException(f'unknown hardware type: {hw_type}. '
                              f'hw_keystores: {list(hw_keystores)}')

def load_keystore(storage, name) -> KeyStore:
    d = storage.get(name, {})
    print('keystore:load_keystore name={} d={}'.format(name, json.dumps(d, indent=4)))
    t = d.get('type')
    if not t:
        raise WalletFileException(
            'Wallet format requires update.\n'
            'Cannot find keystore for name {}'.format(name))
    keystore_constructors = {ks.type: ks for ks in [Old_KeyStore, HsmGenerated_KeyStore, Imported_KeyStore, BIP32_KeyStore, Bip32Hsm_KeyStore, DAP_KeyStore]}
    keystore_constructors['hardware'] = hardware_keystore
    try:
        ks_constructor = keystore_constructors[t]
    except KeyError:
        raise WalletFileException(f'Unknown type {t} for keystore named {name}')
    k = ks_constructor(d)
    return k


def is_old_mpk(mpk: str) -> bool:
    try:
        int(mpk, 16)  # test if hex string
    except:
        return False
    if len(mpk) != 128:
        return False
    try:
        ecc.ECPubkey(bfh('04' + mpk))
    except:
        return False
    return True


def is_address_list(text):
    parts = text.split()
    return bool(parts) and all(bitcoin.is_address(x) for x in parts)


def get_private_keys(text, *, allow_spaces_inside_key=True, raise_on_error=False):
    if allow_spaces_inside_key:  # see #1612
        parts = text.split('\n')
        parts = map(lambda x: ''.join(x.split()), parts)
        parts = list(filter(bool, parts))
    else:
        parts = text.split()
    if bool(parts) and all(bitcoin.is_private_key(x, raise_on_error=raise_on_error) for x in parts):
        return parts


def is_private_key_list(text, *, allow_spaces_inside_key=True, raise_on_error=False):
    return bool(get_private_keys(text,
                                 allow_spaces_inside_key=allow_spaces_inside_key,
                                 raise_on_error=raise_on_error))


def is_master_key(x):
    return is_old_mpk(x) or is_bip32_key(x)


def is_bip32_key(x):
    return is_xprv(x) or is_xpub(x)


def bip44_derivation(account_id, bip43_purpose=44):
    coin = constants.net.BIP44_COIN_TYPE
    der = "m/%d'/%d'/%d'" % (bip43_purpose, coin, int(account_id))
    return normalize_bip32_derivation(der)


def purpose48_derivation(account_id: int, xtype: str) -> str:
    # m / purpose' / coin_type' / account' / script_type' / change / address_index
    bip43_purpose = 48
    coin = constants.net.BIP44_COIN_TYPE
    account_id = int(account_id)
    script_type_int = PURPOSE48_SCRIPT_TYPES.get(xtype)
    if script_type_int is None:
        raise Exception('unknown xtype: {}'.format(xtype))
    der = "m/%d'/%d'/%d'/%d'" % (bip43_purpose, coin, account_id, script_type_int)
    return normalize_bip32_derivation(der)


def from_seed(seed, passphrase, is_p2sh=False):
    t = seed_type(seed)
    print('keystore: seed_type={} seed={} is_p2sh={}'.format(t, seed, is_p2sh))
    if t == 'old':
        keystore = Old_KeyStore({})
        keystore.add_seed(seed)
    elif t in ['standard', 'segwit']:
        keystore = BIP32_KeyStore({})
        keystore.add_seed(seed)
        keystore.passphrase = passphrase
        bip32_seed = Mnemonic.mnemonic_to_seed(seed, passphrase)
        if t == 'standard':
            der = "m/"
            xtype = 'standard'
        else:
            der = "m/1'/" if is_p2sh else "m/0'/"
            xtype = 'p2wsh' if is_p2sh else 'p2wpkh'
        print('from_seed: bip32_seed={} der={} xtype={}'.format(bip32_seed.hex(), der, xtype))
        keystore.add_xprv_from_seed(bip32_seed, xtype, der)
    else:
        raise BitcoinException('Unexpected seed type {}'.format(repr(t)))
    print('keystore:from_seed returning keystore={}'.format(keystore.dump()))
    return keystore

def from_private_key_list(text):
    keystore = Imported_KeyStore({})
    for x in get_private_keys(text):
        keystore.import_privkey(x, None)
    return keystore

def from_old_mpk(mpk):
    keystore = Old_KeyStore({})
    keystore.add_master_public_key(mpk)
    return keystore

def from_xpub(xpub):
    k = BIP32_KeyStore({})
    k.add_xpub(xpub)
    return k

def from_xprv(xprv):
    k = BIP32_KeyStore({})
    k.add_xprv(xprv)
    return k

def from_master_key(text):
    if is_xprv(text):
        k = from_xprv(text)
    elif is_old_mpk(text):
        k = from_old_mpk(text)
    elif is_xpub(text):
        k = from_xpub(text)
    else:
        raise BitcoinException('Invalid master key')
    return k
