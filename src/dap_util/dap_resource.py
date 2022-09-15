# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import os, json, secrets, string, time
from pprint import pprint
import dbaas, dap_crypto, dap_cos, dap_consts, dap_hpcs, dbaas_api

def gen_password(size=16):
   chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
   password = ''.join(secrets.choice(chars) for x in range(size - 3))
   password = password + secrets.choice(string.ascii_uppercase)
   password = password + secrets.choice(string.ascii_lowercase)
   password = password + secrets.choice(string.digits)
   return password

class DAPDBaaSResource:
    def __init__(self, reboot, serviceid, dbaas_created=True, ca_file=None):
        self.serviceid = serviceid
        self.common_key1, self.common_key2 = dap_crypto.derive_common_keys()
        self.cos_client = dap_cos.create_cos_client(self.serviceid)
        if dbaas_created == True:
            self.update_txqueue_client(ca_file)
        else:
            # Signing service creates the client after it sets up DBaaS.
            self.txqueue_client = None

        self.queue_name = 'txqueue'

    def _get_dbaas_info(self, backup_name, ca_file=None):
        dbaas_info = json.loads(dap_cos.get_and_decrypt_backup_from_cos(backup_name,
                                                                        self.common_key1,
                                                                        self.common_key2, 
                                                                        self.cos_client))

        if ca_file is not None:
            dbaas_info['CA_FILE'] = ca_file
        print('dbaas_info for ' + backup_name)
        pprint(dbaas_info)
        return dbaas_info

    def update_txqueue_client(self, ca_file=None):
        print('Updating txqueue client ...')
        self.txqueue_client = dbaas.get_client_from_info(self._get_dbaas_info(dap_consts.BACKUP_TXQUEUE_INFO, ca_file))

class DAPCommonResource(DAPDBaaSResource):

    def __init__(self, reboot, serviceid, dbaas_created=True):
        super().__init__(reboot, serviceid, dbaas_created)

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

    def __init__(self, reboot, serviceid=dap_consts.SIGNING_SERVICE, dbaas_created=False):
        super().__init__(reboot, serviceid, dbaas_created)

        dbaas_envs = ['ENC_DBAAS_USER_ID', 'ENC_DBAAS_TOKEN_AES_ENC_KEY', 'ENC_DBAAS_TOKEN', 'DBAAS_CA_FILE']
        if not all (v in os.environ for v in dbaas_envs):
            raise Exception('Environment variables ' + str(dbaas_envs) + ' must be set')
        if 'DAP_ROOT_DIR' not in os.environ:
            raise Exception('DAP_ROOT_DIR environment variable is not set')

        dap_cos.create_backup_bucket(self.cos_client)

        dap_dir = os.environ['DAP_ROOT_DIR']

        # How to decrypt this backup? Private key exists only in an image.
        deploy_time_secret_backup = dap_crypto.rsa_encrypt(dap_dir + '/build-time-keys/public.pem', os.environ['DEPLOY_TIME_SECRET'])
        dap_cos.backup_to_cos('deploy-time-secret', deploy_time_secret_backup, self.cos_client)

        if not reboot: # First boot
            self.update_aes_keys()

            # Decrypt DBaaS token
            dbaas_userid = dap_crypto.rsa_decrypt(
                privkey_file=dap_dir + '/build-time-keys/private.pem', 
                cipher_text=os.environ['ENC_DBAAS_USER_ID'])
            dbaas_token = dap_crypto.rsa_decrypt_long(
                privkey_file=dap_dir + '/build-time-keys/private.pem',
                cipher_text=os.environ['ENC_DBAAS_TOKEN'],
                aes_encrypted_key=os.environ['ENC_DBAAS_TOKEN_AES_ENC_KEY'])
            print('dbaas_userid: {}'.format(dbaas_userid))

            # Create WalletDB
            instance_name = 'walletdb'
            if 'WALLETDB_NAME' in os.environ:
                instance_name = os.environ['WALLETDB_NAME']
            walletdb_password = gen_password()
            walletdb_clusterid = dbaas_api.create_instance(instance_name, walletdb_password, dbaas_userid, dbaas_token)['cluster_id']
            walletdb_endpoint = ''
            while not walletdb_endpoint:
                time.sleep(5)
                walletdb_endpoint = dbaas_api.get_cluster(walletdb_clusterid, dbaas_userid, dbaas_token)['public_endpoint']
            walletdb_info = {
                'HOSTS': walletdb_endpoint,
                'CA_FILE': os.environ['DBAAS_CA_FILE'],
                'REPLICA_SET': instance_name,
                'USER': 'admin',
                'PASSWORD': walletdb_password
            }
            print('walletdb-info')
            pprint(walletdb_info)

            # Tentatively, we use a dedicated instance for debugging
            # walletdb_info = {
            #     'HOSTS': os.environ['WALLETDB_HOSTS'],
            #     'CA_FILE': os.environ['DBAAS_CA_FILE'],
            #     'REPLICA_SET': 'walletdb',
            #     'USER': 'admin',
            #     'PASSWORD': os.environ['WALLETDB_PASSWORD']
            # }

            # Create TxQueue
            instance_name = 'txqueue'
            if 'TXQUEUE_NAME' in os.environ:
                instance_name = os.environ['TXQUEUE_NAME']
            txqueue_password = gen_password()
            txqueue_clusterid = dbaas_api.create_instance(instance_name, txqueue_password, dbaas_userid, dbaas_token)['cluster_id']
            txqueue_endpoint = ''
            while not txqueue_endpoint:
                time.sleep(5)
                txqueue_endpoint = dbaas_api.get_cluster(txqueue_clusterid, dbaas_userid, dbaas_token)['public_endpoint']
            txqueue_info = {
                'HOSTS': txqueue_endpoint,
                'CA_FILE': os.environ['DBAAS_CA_FILE'],
                'REPLICA_SET': instance_name,
                'USER': 'admin',
                'PASSWORD': txqueue_password
            }
            print('txqueue-info')
            pprint(txqueue_info)

            # Tentatively, we use a dedicated instance for debugging
            # txqueue_info = {
            #     'HOSTS': os.environ['TXQUEUE_HOSTS'],
            #     'CA_FILE': os.environ['DBAAS_CA_FILE'],
            #     'REPLICA_SET': 'txqueue',
            #     'USER': 'admin',
            #     'PASSWORD': os.environ['TXQUEUE_PASSWORD']
            # }

            self.__backup_dbaas_info_to_cos(txqueue_info, dap_consts.BACKUP_TXQUEUE_INFO)
            self.__backup_dbaas_info_to_cos(walletdb_info, dap_consts.BACKUP_WALLETDB_INFO)
        else: # Reboot
            old_common_key1, old_common_key2 = dap_crypto.derive_common_keys(old=True)
            if old_common_key1 and old_common_key2:
                self.__reencrypt_aes_keys_backup(old_common_key1, old_common_key2)
                self.__reencrypt_dbaas_info(old_common_key1, old_common_key2, dap_consts.BACKUP_TXQUEUE_INFO)
                self.__reencrypt_dbaas_info(old_common_key1, old_common_key2, dap_consts.BACKUP_WALLETDB_INFO)
            
            self.aes_key, self.aes_iv = self.__get_aes_keys_backup()

        self.update_txqueue_client()
        self.update_walletdb_client()

    def update_dbaas_password(self, backup_name):
        new_password = gen_password()
        dbaas_info = self._get_dbaas_info(backup_name)
        dbaas_info['PASSWORD'] = new_password
        
        print('Updating password for ' + backup_name)
        pprint(dbaas_info)
        
        if backup_name == dap_consts.BACKUP_TXQUEUE_INFO:
            dbaas.update_password(self.txqueue_client, 'admin', dbaas_info['USER'], new_password)
            self.__backup_dbaas_info_to_cos(dbaas_info, backup_name)
            # self.update_txqueue_client()
            # dbaas.kill_all_sessions(self.txqueue_client)
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

    def __backup_dbaas_info_to_cos(self, dbaas_info, backup_name):
        dap_cos.encrypt_and_backup_to_cos(backup_name, 
                                          json.dumps(dbaas_info),
                                          self.common_key1,
                                          self.common_key2,
                                          self.cos_client)

    def __reencrypt_dbaas_info(self, old_common_key1, old_common_key2, backup_name):
        print('Re-encrypting a backup of DBaaS info {}'.format(backup_name))
        try:
            dbaas_info = json.loads(dap_cos.get_and_decrypt_backup_from_cos(backup_name,
                                                                            old_common_key1,
                                                                            old_common_key2,
                                                                            self.cos_client,
                                                                            max_tries=1))
            self.__backup_dbaas_info_to_cos(dbaas_info, backup_name)
        except Exception as e:
            print(str(e))
            print('Failed to re-encrypt a backup of DBaaS info {} (a common key can be already updated)'.format(backup_name))

    def update_walletdb_client(self):
        self.walletdb_client = dbaas.get_client_from_info(self._get_dbaas_info(dap_consts.BACKUP_WALLETDB_INFO))
