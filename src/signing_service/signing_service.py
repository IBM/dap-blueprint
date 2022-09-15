#!/usr/bin/env python3

import json, uuid, time, os
from polling_service import PollingService
import dbaas, dap_hpcs, dap_crypto, dap_cos, dap_consts, hpcs_util

WALLET_BACKUP_BUCKET_NAME = 'wallet-backup'
if "WALLET_BACKUP_BUCKET" in os.environ:
    WALLET_BACKUP_BUCKET_NAME = os.environ["WALLET_BACKUP_BUCKET"]

HARDENED_BIT = 0x80000000

class SigningService(PollingService):

    def __init__(self, reboot=False):
        query = {'$or': [{'request.type': {'$eq': x}} for x in dap_consts.REQUEST_TYPES + [dap_consts.INTERNAL_OPERATION]],
                 dap_consts.SIGNING_SERVICE: {'$eq': None}}
        for serviceid in dap_consts.POLICY_SERVICES:
            query[serviceid] = {'$ne': None}
        super().__init__(
            serviceid=dap_consts.SIGNING_SERVICE,
            query=query,
            response=dap_consts.SIGNING_SERVICE,
            reboot=reboot
        )

        dap_cos.create_backup_bucket(self.resource.cos_client, bucket_name=WALLET_BACKUP_BUCKET_NAME)

        self.__wait_for_dbaas_to_be_ready(self.resource.walletdb_client)
        self.__wait_for_dbaas_to_be_ready(self.resource.txqueue_client)

        self._post_ready_status(with_pubkey=False)

        self.__skip_hpcs_verify = False
        if 'SKIP_HPCS_VERIFY' in os.environ and os.environ['SKIP_HPCS_VERIFY']:
            self.__skip_hpcs_verify = True
        self.__hpcs_interval = 0
        if 'HPCS_INTERVAL' in os.environ and os.environ['HPCS_INTERVAL']:
            self.__hpcs_interval = int(os.environ['HPCS_INTERVAL'])

        # Check if we can access a HPCS instance
        privkey, pubkey = dap_hpcs.gen_key_pair(hpcs_credentials=self.resource.hpcs_credentials, hpcs_address=self.resource.hpcs_address)
        print('privkey={}'.format(privkey.hex()))
        print('pubkey={}'.format(pubkey.hex()))

    def __wait_for_dbaas_to_be_ready(self, client):
        print('Waiting for a DBaaS instance to be ready ...')
        while True:
            try:
                dbaas.enqueue(client, 'test', {'serviceid': self.serviceid})
                dbaas.dequeue(client, 'test', {'serviceid': {'$eq': self.serviceid}})
                print('Done')
                return
            except Exception as e:
                print(e)
                time.sleep(5)

    def __verify_pubkey_hmac(self, serviceid, params):
        if 'pubkeys' not in params:
            raise Exception('No any public key')
        if serviceid in params['pubkeys']:
            pubkey = params['pubkeys'][serviceid]
        else:
            raise Exception('No pubkey for ' + serviceid)

        if 'hmacs' not in params:
            raise Exception('No any hmac for public keys')
        if serviceid in params['hmacs']:
            pubkey_hmac = params['hmacs'][serviceid]
        else:
            raise Exception('No hmac for ' + serviceid)
        if not dap_crypto.verify_hmac(pubkey, pubkey_hmac, self.resource.common_key1):
            raise Exception('Public key verification failure for ' + serviceid)
        return pubkey

    def __get_pubkeys(self, seedid):
        wallet = dbaas.get(self.resource.walletdb_client, 'wallets', {'seedid': seedid})
        if wallet is None:
            return None
        return wallet['pubkeys']

    def verify(self, doc):
        # Skip any verification
        if self._get_type(doc) == dap_consts.INTERNAL_OPERATION:
            return dap_consts.DAP_VERIFICATION_SUCCEED, 'ok', doc
        method = self._get_method(doc)
        if method and method == dap_consts.UPDATE_DBAAS_PASSWORD_METHOD:
            # Skip verification
            return dap_consts.DAP_VERIFICATION_SUCCEED, 'ok', doc
        params = self._get_params(doc)
        if params is None:
            raise Exception('No request parameters')
        if 'seedid' in params:
            pubkeys = self.__get_pubkeys(params['seedid'])
            if pubkeys is None:
                return dap_consts.DAP_VERIFICATION_FAIL, 'Your seed does not exist (verification failure in ' + self.serviceid + ' because no public keys are provided)', doc
            print('pubkeys are retrieved from a wallet')
        elif 'pubkeys' in params:
            pubkeys = {}
            for serviceid in dap_consts.POLICY_SERVICES:
                pubkey = self.__verify_pubkey_hmac(serviceid, params)
                pubkeys[serviceid] = pubkey
            print('pubkeys are retrieved from params')
        elif self._get_type(doc) == dap_consts.ADMIN_OPERATION:
            pubkeys = {}
            for serviceid in dap_consts.POLICY_SERVICES:
                pubkeys[serviceid] = dap_cos.get_and_decrypt_backup_from_cos(dap_consts.PUBKEY_BACKUP_NAMES[serviceid],
                                                                             self.resource.common_key1,
                                                                             self.resource.common_key2,
                                                                             self.resource.cos_client)
            print('pubkeys are retrieved from cos')
        else:
            raise Exception('No public keys found in signing service')

        if not self.__skip_hpcs_verify:
            for serviceid in dap_consts.POLICY_SERVICES:
                verified = dap_hpcs.verify(bytes.fromhex(pubkeys[serviceid]),
                                        json.dumps(self._get_request(doc)), bytes.fromhex(doc[serviceid]),
                                        hpcs_credentials=self.resource.hpcs_credentials,
                                        hpcs_address=self.resource.hpcs_address)
                if not verified:
                    return dap_consts.DAP_VERIFICATION_FAIL, 'Verification faulure for ' + serviceid, doc
        return dap_consts.DAP_VERIFICATION_SUCCEED, 'ok', doc

    def execute(self, doc):
        if self.__hpcs_interval > 0:
            time.sleep(self.__hpcs_interval)

        method = self._get_method(doc)
        params = self._get_params(doc)
        if method == dap_consts.CREATE_SEED_METHOD:
            doc['result'] = self.__create_seed(params)
        elif method == dap_consts.QUERY_SEED_METHOD:
            doc['result'] = self.__query_seed(params)
        elif method == dap_consts.DELETE_SEED_METHOD:
            doc['result'] = self.__delete_seed(params)
        elif method == dap_consts.DERIVE_PUBKEY_METHOD:
            doc['result'] = self.__derive_pubkey(params)
        elif method == dap_consts.SIGN_METHOD:
            doc['result'] = self.__sign(params)
        elif method == dap_consts.UPDATE_SS_KEYS_METHOD:
            doc['result'] = self.__update_ss_keys(params)
        elif method == dap_consts.GENERATE_PS_KEYS_METHOD:
            doc['result'] = self.__generate_ps_keys(params)
        elif method == dap_consts.UPDATE_DBAAS_PASSWORD_METHOD:
            doc['result'] = self.__update_dbaas_password(params)
        elif method == dap_consts.ADMIN_CREATE_SEED:
            doc['result'] = self.__admin_create_seed(params)
        else:
            raise Exception('Unknown method ' + method)
        assert doc['result'] is not None, 'result must be filled'
        doc['status'] = 'ok'
        doc[self.response] = 'done'

    def __get_wallet(self, seedid, userid):
        wallet = dbaas.get(self.resource.walletdb_client, 'wallets', {'seedid': seedid, 'userid': userid})
        if wallet is None:
            return None, 'Your seed does not exist (seedid={} userid={})'.format(seedid, userid)
        if 'seed' not in wallet:
            None, 'Seed does not exist in your wallet (seedid={} userid={})'.format(seedid, userid)
        return wallet, None

    def __wallet_backup_name(self, seedid, userid):
        return seedid + '___' + userid

    def __create_seed(self, params):
        seed = dap_hpcs.bip32_create_master_seed(hpcs_credentials=self.resource.hpcs_credentials,
                                                 hpcs_address=self.resource.hpcs_address)
        encrypted_seed = dap_hpcs.aes_encrypt(self.resource.aes_key, 
                                              self.resource.aes_iv, 
                                              seed,
                                              hpcs_credentials=self.resource.hpcs_credentials,
                                              hpcs_address=self.resource.hpcs_address).hex()
        seedid = str(uuid.uuid4())
        if 'userid' not in params:
            raise Exception('No userid sepcified')
        userid = params['userid']
        wallet = {
            'seedid': seedid,
            'userid': userid,
            'seed': encrypted_seed,
            'pubkeys': {}
        }
        for serviceid in dap_consts.POLICY_SERVICES:
            pubkey = self.__verify_pubkey_hmac(serviceid, params)
            wallet['pubkeys'][serviceid] = pubkey
        dbaas.store(self.resource.walletdb_client, 'wallets', {'seedid': seedid, 'userid': userid}, wallet)

        dap_cos.encrypt_and_backup_to_cos(self.__wallet_backup_name(seedid, userid), 
                                          json.dumps(wallet),
                                          self.resource.common_key1,
                                          self.resource.common_key2,
                                          self.resource.cos_client,
                                          bucket_name=WALLET_BACKUP_BUCKET_NAME)

        return seedid

    def __query_seed(self, params):
        if 'seedid' not in params:
            raise Exception('No seedid sepcified')
        if 'userid' not in params:
            raise Exception('No userid sepcified')
        _, err = self.__get_wallet(params['seedid'], params['userid'])
        if err:
            return err
        return 'Your seed for ' + params['seedid'] + ' and ' + params['userid'] + ' exists'

    def __delete_seed(self, params):
        if 'seedid' not in params:
            raise Exception('No seedid sepcified')
        if 'userid' not in params:
            raise Exception('No userid sepcified')
        wallet = dbaas.delete(self.resource.walletdb_client, 'wallets', {'seedid': params['seedid'], 'userid': params['userid']})
        if wallet is not None:
            return 'Your seed ' + params['seedid'] + ' and ' + params['userid'] + ' was deleted'
        else:
            return 'Your seed ' + params['seedid'] + ' and ' + params['userid'] + ' was already deleted'

    def __decrypt_seed(self, wallet):
        return dap_hpcs.aes_decrypt(self.resource.aes_key, 
                                    self.resource.aes_iv, 
                                    bytes.fromhex(wallet['seed']),
                                    hpcs_credentials=self.resource.hpcs_credentials,
                                    hpcs_address=self.resource.hpcs_address)

    def __convert_bip32path(self, bip32path):
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
                x = x | HARDENED_BIT
            path_as_list.append(x)
        print('bip32path {} is converted into ['.format(bip32path), end='')
        for x in path_as_list:
            print('{}, '.format(hex(x)), end='')
        print(']')
        return path_as_list

    def __derive_pubkey(self, params):
        if 'seedid' not in params:
            raise Exception('No seedid sepcified')
        if 'userid' not in params:
            raise Exception('No userid sepcified')
        if 'bip32path' not in params:
            raise Exception('No bip32path sepcified')
        wallet, err = self.__get_wallet(params['seedid'], params['userid'])
        if err:
            return err
        seed = self.__decrypt_seed(wallet)
        path = self.__convert_bip32path(params['bip32path'])
        pubkey, chaincode = dap_hpcs.bip32_derive_key(seed, 
                                                      path,
                                                      hpcs_credentials=self.resource.hpcs_credentials,
                                                      hpcs_address=self.resource.hpcs_address)
        raw_pubkey = hpcs_util.GetPubkeyBytesFromSPKI(pubkey)
        return {'pubkey': pubkey.hex(), 'chaincode': chaincode.hex(), 'raw_pubkey': raw_pubkey.hex()}

    def __sign(self, params):
        if 'seedid' not in params:
            raise Exception('No seedid provided')
        if 'userid' not in params:
            raise Exception('No userid sepcified')
        if 'inputs' not in params:
            raise Exception('No inputs provided')
        wallet, err = self.__get_wallet(params['seedid'], params['userid'])
        if err:
            return wallet
        seed = self.__decrypt_seed(wallet)
        inputs = params['inputs']
        signs = []
        for i, input in enumerate(inputs):
            if 'hash' not in input:
                return 'hash is not provided for {}-th input'.format(i)
            if 'bip32path' not in input:
                return 'bip32path is not provided for {}-th input'.format(i)
            sig = dap_hpcs.bip32_sign(seed, 
                                      self.__convert_bip32path(input['bip32path']), 
                                      bytes.fromhex(input['hash']),
                                      hpcs_credentials=self.resource.hpcs_credentials,
                                      hpcs_address=self.resource.hpcs_address)
            signs.append(sig.hex())
        return signs

    def __update_ss_keys(self, params):
        old_aes_key, old_aes_iv = self.resource.update_aes_keys()
        if old_aes_key is None or old_aes_iv is None:
            raise Exception('AES key does not exist')
        wallets_col = dbaas.get_col(self.resource.walletdb_client, 'wallets')
        num_wallets = 0
        for wallet in wallets_col.find({}):
            seed = dap_hpcs.aes_decrypt(old_aes_key,
                                        old_aes_iv,
                                        bytes.fromhex(wallet['seed']),
                                        hpcs_credentials=self.resource.hpcs_credentials,
                                        hpcs_address=self.resource.hpcs_address)
            encrypted_seed = dap_hpcs.aes_encrypt(self.resource.aes_key,
                                                  self.resource.aes_iv,
                                                  seed,
                                                  hpcs_credentials=self.resource.hpcs_credentials,
                                                  hpcs_address=self.resource.hpcs_address).hex()
            result = wallets_col.update_one({'_id': wallet['_id']}, {'$set': {'seed': encrypted_seed}})
            if result.modified_count == 0:
                print('Warning: Failed to update an ecrypted seed in a wallet ' + wallet['seedid'])
            else:
                num_wallets+=1

                # Update backup
                wallet.pop('_id')
                wallet['seed'] = encrypted_seed
                dap_cos.encrypt_and_backup_to_cos(wallet['seedid'], 
                                                json.dumps(wallet),
                                                self.resource.common_key1,
                                                self.resource.common_key2,
                                                self.resource.cos_client,
                                                bucket_name=WALLET_BACKUP_BUCKET_NAME)

        print('Re-encrypted seeds in {} wallets'.format(num_wallets))
        return 'Re-encrypted seeds in {} wallets'.format(num_wallets)

    def __generate_ps_keys(self, params):
        if 'serviceid' not in params:
            raise Exception('serviceid is not provided')
        serviceid = params['serviceid']
        _, pubkey = self.resource.generate_rsa_keys(serviceid)
        wallets_col = dbaas.get_col(self.resource.walletdb_client, 'wallets')
        num_wallets = 0
        for wallet in wallets_col.find({}):
            query = {
                '_id': wallet['_id'],
                'pubkeys.' + serviceid: {'$ne': None}
            }
            result = wallets_col.update_one(query, {'$set': {'pubkeys.' + serviceid: pubkey.hex()}})
            if result.modified_count == 0:
                print('No public key for {} in a wallet {}'.format(serviceid, wallet['seedid']))
            else:
                num_wallets+=1

                # Update backup
                wallet.pop('_id')
                wallet['pubkeys'][serviceid] = pubkey.hex()
                dap_cos.encrypt_and_backup_to_cos(self.__wallet_backup_name(wallet['seedid'], wallet['userid']),
                                                  json.dumps(wallet),
                                                  self.resource.common_key1,
                                                  self.resource.common_key2,
                                                  self.resource.cos_client,
                                                  bucket_name=WALLET_BACKUP_BUCKET_NAME)

        print('Update a public key for {} in {} wallets'.format(serviceid, num_wallets))
        return 'Update a public key for {} in {} wallets'.format(serviceid, num_wallets)

    def __update_dbaas_password(self, params):
        if 'backup_name' not in params:
            raise Exception('backup_name is not provided')
        self.resource.update_dbaas_password(params['backup_name'])
        return 'ok'

    def __admin_create_seed(self, params):
        if 'seed' not in params:
            raise Exception('No seed specified')
        seed = bytes.fromhex(params['seed'])
        encrypted_seed = dap_hpcs.aes_encrypt(self.resource.aes_key, 
                                              self.resource.aes_iv, 
                                              seed,
                                              hpcs_credentials=self.resource.hpcs_credentials,
                                              hpcs_address=self.resource.hpcs_address).hex()
        seedid = str(uuid.uuid1())
        if 'userid' not in params:
            raise Exception('No userid sepcified')
        userid = params['userid']
        wallet = {
            'seedid': seedid,
            'userid': userid,
            'seed': encrypted_seed,
            'pubkeys': {}
        }
        for serviceid in dap_consts.POLICY_SERVICES:
            wallet['pubkeys'][serviceid] = dap_cos.get_and_decrypt_backup_from_cos(dap_consts.PUBKEY_BACKUP_NAMES[serviceid],
                                                                                   self.resource.common_key1,
                                                                                   self.resource.common_key2,
                                                                                   self.resource.cos_client)
        dbaas.store(self.resource.walletdb_client, 'wallets', {'seedid': seedid, 'userid': userid}, wallet)

        dap_cos.encrypt_and_backup_to_cos(self.__wallet_backup_name(seedid, userid), 
                                          json.dumps(wallet),
                                          self.resource.common_key1,
                                          self.resource.common_key2,
                                          self.resource.cos_client,
                                          bucket_name=WALLET_BACKUP_BUCKET_NAME)

        return seedid

def run(reboot=False):
    SigningService(reboot=reboot).run()
