# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import os, json, secrets, string, time
from pprint import pprint
import dbaas, dap_crypto, dap_cos, dap_consts, dap_hpcs, dbaas_api

class DAPDBaaSResource:
    def __init__(self, serviceid):
        self.serviceid = serviceid
        self.common_key1, self.common_key2 = dap_crypto.derive_common_keys()
        self.cos_client = dap_cos.create_cos_client(self.serviceid)
        self.update_txqueue_client()
        self.queue_name = 'txqueue'

    def update_txqueue_client(self):
        print('Updating txqueue client ...')
        dbaas_info = dbaas.get_info(dap_consts.BACKUP_TXQUEUE_INFO)
        self.txqueue_client = dbaas.get_client_from_info(dbaas_info)

class DAPCommonResource(DAPDBaaSResource):

    def __init__(self, reboot, serviceid):
        super().__init__(serviceid)

        self.hpcs_credentials, self.hpcs_address = dap_hpcs.create_credentials_and_address()
        if not reboot: # First boot
            self.privkey, self.pubkey = self.generate_rsa_keys(self.serviceid)
        else: # Reboot
            old_common_key1, old_common_key2 = dap_crypto.derive_common_keys(old=True)
            if old_common_key1 and old_common_key2:
                self._reencrypt_rsa_keys_backup(old_common_key1, old_common_key2, self.serviceid)
            
            self.privkey, self.pubkey = self._get_rsa_keys_backup(self.serviceid)

    def _backup_rsa_keys_to_cos(self, privkey, pubkey, serviceid):
        dap_cos.encrypt_and_backup_to_cos(dap_consts.PRIVKEY_BACKUP_NAMES[serviceid], 
                                          privkey.hex(),
                                          self.common_key1,
                                          self.common_key2,
                                          self.cos_client)
        dap_cos.encrypt_and_backup_to_cos(dap_consts.PUBKEY_BACKUP_NAMES[serviceid], 
                                          pubkey.hex(),
                                          self.common_key1,
                                          self.common_key2,
                                          self.cos_client)

    def _get_rsa_keys_backup(self, serviceid):
        privkey = bytes.fromhex(dap_cos.get_and_decrypt_backup_from_cos(dap_consts.PRIVKEY_BACKUP_NAMES[serviceid],
                                                                        self.common_key1,
                                                                        self.common_key2,
                                                                        self.cos_client))
        pubkey = bytes.fromhex(dap_cos.get_and_decrypt_backup_from_cos(dap_consts.PUBKEY_BACKUP_NAMES[serviceid],
                                                                       self.common_key1,
                                                                       self.common_key2,
                                                                       self.cos_client))
        return privkey, pubkey

    def _reencrypt_rsa_keys_backup(self, old_common_key1, old_common_key2, serviceid):
        print('Re-encrypting a backup of RSA keys for {}'.format(self.serviceid))
        try:
            privkey = bytes.fromhex(dap_cos.get_and_decrypt_backup_from_cos(dap_consts.PRIVKEY_BACKUP_NAMES[serviceid],
                                                                        old_common_key1,
                                                                        old_common_key2,
                                                                        self.cos_client,
                                                                        max_tries=1))
            pubkey = bytes.fromhex(dap_cos.get_and_decrypt_backup_from_cos(dap_consts.PUBKEY_BACKUP_NAMES[serviceid],
                                                                    old_common_key1,
                                                                    old_common_key2,
                                                                    self.cos_client,
                                                                    max_tries=1))
            self._backup_rsa_keys_to_cos(privkey, pubkey, serviceid)
        except Exception as e:
            print(str(e))
            print('Failed to re-encrypt a backup of RSA keys for {} (a common key can be already updated)'.format(serviceid))

    def generate_rsa_keys(self, serviceid):
        # Derive RSA key pairs
        print('Generating a RSA key pair for {}'.format(serviceid))
        privkey, pubkey = dap_hpcs.gen_key_pair(hpcs_credentials=self.hpcs_credentials, hpcs_address=self.hpcs_address)
        print('  privkey: {}'.format(privkey.hex()))
        print('  pubkey: {}'.format(pubkey.hex()))
        self._backup_rsa_keys_to_cos(privkey, pubkey, serviceid)
        return privkey, pubkey

    def update_rsa_keys(self, serviceid):
        print('Updating RSA keys for {}'.format(serviceid))
        self.privkey, self.pubkey = self._get_rsa_keys_backup(serviceid)

class DAPSSResource(DAPCommonResource):

    def __init__(self, reboot, serviceid=dap_consts.SIGNING_SERVICE):
        super().__init__(reboot, serviceid)

        dap_cos.create_backup_bucket(self.cos_client)

        dap_dir = os.environ['DAP_ROOT_DIR']

        deploy_time_secret_backup = dap_crypto.rsa_encrypt(dap_dir + '/build-time-keys/public.pem', os.environ['DEPLOY_TIME_SECRET'])
        dap_cos.backup_to_cos('deploy-time-secret', deploy_time_secret_backup, self.cos_client)

        if not reboot: # First boot
            self.update_aes_keys()
        else: # Reboot
            old_common_key1, old_common_key2 = dap_crypto.derive_common_keys(old=True)
            if old_common_key1 and old_common_key2:
                self.__reencrypt_aes_keys_backup(old_common_key1, old_common_key2)
            
            self.aes_key, self.aes_iv = self.__get_aes_keys_backup()

        self.update_txqueue_client()
        self.update_walletdb_client()

    def update_dbaas_password(self, backup_name):
        new_password = dap_crypto.gen_password()
        dbaas_info = dbaas.get_info(backup_name)
        dbaas_info['PASSWORD'] = new_password

        print('Updating password for ' + backup_name)
        pprint(dbaas_info)
        
        if backup_name == dap_consts.BACKUP_TXQUEUE_INFO:
            dbaas.update_password(self.txqueue_client, 'admin', dbaas_info['USER'], new_password)
            self.__backup_dbaas_info_to_cos(dbaas_info, backup_name)
            self.update_txqueue_client()
            dbaas.kill_all_sessions(self.txqueue_client)
        elif backup_name == dap_consts.BACKUP_WALLETDB_INFO:
            dbaas.update_password(self.walletdb_client, 'admin', dbaas_info['USER'], new_password)
            self.__backup_dbaas_info_to_cos(dbaas_info, backup_name)
            self.update_walletdb_client()
            dbaas.kill_all_sessions(self.walletdb_client)
        else:
            raise Exception('Unknown backup name ' + backup_name)

    def update_aes_keys(self):
        # Derive AES key
        print('Updating a AES key for {}'.format(self.serviceid))
        
        old_aes_key = self.aes_key if hasattr(self, 'aes_key') else None
        old_aes_iv = self.aes_iv if hasattr(self, 'aes_iv') else None
        self.aes_key, self.aes_iv = dap_hpcs.aes_gen_key(hpcs_credentials=self.hpcs_credentials, hpcs_address=self.hpcs_address)

        if old_aes_key is not None:
            print('  from {}'.format(old_aes_key.hex()))
        print('  to {}'.format(self.aes_key.hex()))

        self.__backup_aes_keys_to_cos(self.aes_key, self.aes_iv)
        
        return old_aes_key, old_aes_iv

    def __backup_aes_keys_to_cos(self, aes_key, aes_iv):
        dap_cos.encrypt_and_backup_to_cos(dap_consts.BACKUP_SIGNING_SERVICE_AES_KEY,
                                          aes_key.hex(),
                                          self.common_key1,
                                          self.common_key2,
                                          self.cos_client)
        dap_cos.encrypt_and_backup_to_cos(dap_consts.BACKUP_SIGNING_SERVICE_AES_IV,
                                          aes_iv.hex(),
                                          self.common_key1,
                                          self.common_key2,
                                          self.cos_client)

    def __get_aes_keys_backup(self):
        aes_key = bytes.fromhex(dap_cos.get_and_decrypt_backup_from_cos(dap_consts.BACKUP_SIGNING_SERVICE_AES_KEY,
                                                                        self.common_key1,
                                                                        self.common_key2,
                                                                        self.cos_client))
        aes_iv = bytes.fromhex(dap_cos.get_and_decrypt_backup_from_cos(dap_consts.BACKUP_SIGNING_SERVICE_AES_IV,
                                                                       self.common_key1,
                                                                       self.common_key2,
                                                                       self.cos_client))
        return aes_key, aes_iv

    def __reencrypt_aes_keys_backup(self, old_common_key1, old_common_key2):
        print('Re-encrypting a backup of AES keys')
        try:
            aes_key = bytes.fromhex(dap_cos.get_and_decrypt_backup_from_cos(dap_consts.BACKUP_SIGNING_SERVICE_AES_KEY,
                                                                            old_common_key1,
                                                                            old_common_key2,
                                                                            self.cos_client,
                                                                            max_tries=1))
            aes_iv = bytes.fromhex(dap_cos.get_and_decrypt_backup_from_cos(dap_consts.BACKUP_SIGNING_SERVICE_AES_IV,
                                                                           old_common_key1,
                                                                           old_common_key2,
                                                                           self.cos_client,
                                                                           max_tries=1))
            self.__backup_aes_keys_to_cos(aes_key, aes_iv)
        except Exception as e:
            print(str(e))
            print('Failed to re-encrypt a backup of AES keys (a common key can be already updated)')

    def update_walletdb_client(self):
        print('Updating walletdb client ...')
        dbaas_info = dbaas.get_info(dap_consts.BACKUP_WALLETDB_INFO)
        self.walletdb_client = dbaas.get_client_from_info(dbaas_info)
