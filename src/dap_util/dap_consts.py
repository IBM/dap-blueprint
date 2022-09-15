# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

service = None
reboot = False
flask_root_path = None

# This is the maximum number of retries to decrypt a COS backup record, which is encrypted by a common secret, 
# because decryption can fail until another service updates the backup record with a new common secret.
COMMON_SECRETS_MAX_RETRIES = 5

SIGNING_SERVICE             = 'signing_service'
SIGNING_SERVICE_SHORT_NAME  = 'SS'

AUTHORIZATION_POLICY_SERVICE        = 'authorization_policy_service'
FRAUD_DETECTION_POLICY_SERVICE      = 'fraud_detection_policy_service'
TRANSACTION_APPROVAL_POLICY_SERVICE = 'transaction_approval_policy_service'
AUTHORIZATION_POLICY_SERVICE_SHORT_NAME         = 'AP'
FRAUD_DETECTION_POLICY_SERVICE_SHORT_NAME       = 'FDP'
TRANSACTION_APPROVAL_POLICY_SERVICE_SHORT_NAME  = 'TAP'

TRANSACTION_PROPOSER            = 'transaction_proposer'
TRANSACTION_PROPOSER_SHORT_NAME = 'TP'

AUTHORIZATION_POLICY_APPROVAL_SERVER            = 'authorization_policy_approval_server'
AUTHORIZATION_POLICY_APPROVAL_SERVER_SHORT_NAME = 'APAS'

POLICY_SERVICES = [
    AUTHORIZATION_POLICY_SERVICE,
    FRAUD_DETECTION_POLICY_SERVICE,
    TRANSACTION_APPROVAL_POLICY_SERVICE,
]

SERVICE_NAME_MAP = {
    SIGNING_SERVICE_SHORT_NAME:                     SIGNING_SERVICE,
    AUTHORIZATION_POLICY_SERVICE_SHORT_NAME:        AUTHORIZATION_POLICY_SERVICE,
    FRAUD_DETECTION_POLICY_SERVICE_SHORT_NAME:      FRAUD_DETECTION_POLICY_SERVICE,
    TRANSACTION_APPROVAL_POLICY_SERVICE_SHORT_NAME: TRANSACTION_APPROVAL_POLICY_SERVICE,
    TRANSACTION_PROPOSER_SHORT_NAME:                TRANSACTION_PROPOSER,
    AUTHORIZATION_POLICY_SERVICE_SHORT_NAME:        AUTHORIZATION_POLICY_APPROVAL_SERVER
}

BACKUP_WALLETDB_INFO                                = 'walletdb'
BACKUP_TXQUEUE_INFO                                 = 'txqueue'

BACKUP_SIGNING_SERVICE_AES_KEY                      = SIGNING_SERVICE + '-hex-aes-key'
BACKUP_SIGNING_SERVICE_AES_IV                       = SIGNING_SERVICE + '-hex-aes-iv'

BACKUP_SIGNING_SERVICE_PRIVKEY                      = SIGNING_SERVICE + '-hex-privkey'
BACKUP_SIGNING_SERVICE_PUBKEY                       = SIGNING_SERVICE + '-hex-pubkey'
BACUP_AUTHORIZATION_POLICY_SERVICE_PRIVKEY          = AUTHORIZATION_POLICY_SERVICE + '-hex-privkey'
BACUP_AUTHORIZATION_POLICY_SERVICE_PUBKEY           = AUTHORIZATION_POLICY_SERVICE + '-hex-pubkey'
BACUP_FRAUD_DETECTION_POLICY_SERVICE_PRIVKEY        = FRAUD_DETECTION_POLICY_SERVICE + '-hex-privkey'
BACUP_FRAUD_DETECTION_POLICY_SERVICE_PUBKEY         = FRAUD_DETECTION_POLICY_SERVICE + '-hex-pubkey'
BACUP_TRANSACTION_APPROVAL_POLICY_SERVICE_PRIVKEY   = TRANSACTION_APPROVAL_POLICY_SERVICE + '-hex-privkey'
BACUP_TRANSACTION_APPROVAL_POLICY_SERVICE_PUBKEY    = TRANSACTION_APPROVAL_POLICY_SERVICE + '-hex-pubkey'
BACKUP_TRANSACTION_PROPOSER_PRIVKEY                 = TRANSACTION_PROPOSER + '-hex-privkey'
BACKUP_TRANSACTION_PROPOSER_PUBKEY                  = TRANSACTION_PROPOSER + '-hex-pubkey'

PRIVKEY_BACKUP_NAMES = {
    SIGNING_SERVICE:                        BACKUP_SIGNING_SERVICE_PRIVKEY,
    AUTHORIZATION_POLICY_SERVICE:           BACUP_AUTHORIZATION_POLICY_SERVICE_PRIVKEY,
    FRAUD_DETECTION_POLICY_SERVICE:         BACUP_FRAUD_DETECTION_POLICY_SERVICE_PRIVKEY,
    TRANSACTION_APPROVAL_POLICY_SERVICE:    BACUP_TRANSACTION_APPROVAL_POLICY_SERVICE_PRIVKEY,
    TRANSACTION_PROPOSER:                   BACKUP_TRANSACTION_PROPOSER_PRIVKEY,
}

PUBKEY_BACKUP_NAMES = {
    SIGNING_SERVICE:                        BACKUP_SIGNING_SERVICE_PUBKEY,
    AUTHORIZATION_POLICY_SERVICE:           BACUP_AUTHORIZATION_POLICY_SERVICE_PUBKEY,
    FRAUD_DETECTION_POLICY_SERVICE:         BACUP_FRAUD_DETECTION_POLICY_SERVICE_PUBKEY,
    TRANSACTION_APPROVAL_POLICY_SERVICE:    BACUP_TRANSACTION_APPROVAL_POLICY_SERVICE_PUBKEY,
    TRANSACTION_PROPOSER:                   BACKUP_TRANSACTION_PROPOSER_PUBKEY,
}

BACKUP_NAMES = [
    BACKUP_WALLETDB_INFO,
    BACKUP_TXQUEUE_INFO,
    BACKUP_SIGNING_SERVICE_AES_KEY,
    BACKUP_SIGNING_SERVICE_AES_IV
] + list(PRIVKEY_BACKUP_NAMES.values()) + list(PUBKEY_BACKUP_NAMES.values())

SERVICE_STATUS          = 'ServiceStatus'
ADMIN_OPERATION         = 'AdminOperation'
SEED_OPERATION          = 'SeedOperation'
TRANSACTION_OPERATION   = 'TransactionOperation'
INTERNAL_OPERATION      = 'InternalOperation'
APPROVAL_RESULT         = 'ApprovalResult'

REQUEST_TYPES = [
    SERVICE_STATUS,
    ADMIN_OPERATION,
    SEED_OPERATION,
    TRANSACTION_OPERATION,
    APPROVAL_RESULT,
]

### SEED_OPERATION ###
CREATE_SEED_METHOD      = 'create_seed'
QUERY_SEED_METHOD       = 'query_seed'
DELETE_SEED_METHOD      = 'delete_seed'
DERIVE_PUBKEY_METHOD    = 'derive_pubkey'

SEED_METHODS = [
    CREATE_SEED_METHOD,
    QUERY_SEED_METHOD,
    DELETE_SEED_METHOD,
    DERIVE_PUBKEY_METHOD,
]

### TRANSACTION_OPERATION ###
SIGN_METHOD             = 'sign'

TRANSACTION_METHODS = [
    SIGN_METHOD,
]

### ADMIN_OPERATION ###
UPDATE_SS_KEYS_METHOD           = 'update_ss_keys'
GENERATE_PS_KEYS_METHOD         = 'generate_ps_keys'
UPDATE_PS_KEYS_METHOD           = 'update_ps_keys'
UPDATE_DBAAS_PASSWORD_METHOD    = 'update_dbaas_password'
ADMIN_CREATE_SEED               = 'admin_create_seed'

ADMIN_METHODS = [
    UPDATE_SS_KEYS_METHOD,
    GENERATE_PS_KEYS_METHOD,
    UPDATE_PS_KEYS_METHOD,
    UPDATE_DBAAS_PASSWORD_METHOD,
    ADMIN_CREATE_SEED,
]

### INTERNAL_OPERATION ###
INTERNAL_METHODS = [
    DERIVE_PUBKEY_METHOD
]

### Verification status for policy and signing services ###
DAP_VERIFICATION_SUCCEED = 0
DAP_VERIFICATION_FAIL    = 1
DAP_VERIFICATION_WAIT    = 2 # Take long time for human verification