# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

locals {
  auths = {
    (var.REGISTRY_URL) : {
      "username": var.REGISTRY_USERNAME,
      "password": var.REGISTRY_PASSWORD
    }
  }
  images = {
    "dct" : {
      (var.DAP_IMAGE) : {
        "notary": var.NOTARY_URL,
        "publicKey": var.DCT_PUBKEY
      }
    }
  }
  env = {
    "type" : "env",
    "logging" : {
      "logDNA" : {
          "ingestionKey" : var.LOGDNA_INGESTION_KEY,
          "hostname" : var.LOGDNA_SYSLOG_INGESTION_HOSTNAME,
      }
    },
    "env" : {
      "ZHSM": var.ZHSM,
      "ZHSM_CREDENTIAL": var.ZHSM_CREDENTIAL,
      "SSH_PUBKEY": var.SSH_PUBKEY,
      "ARGON2_SALT": var.ARGON2_SALT,
      "DEPLOY_TIME_SECRET": var.DEPLOY_TIME_SECRET,
      "OLD_DEPLOY_TIME_SECRET": var.OLD_DEPLOY_TIME_SECRET,
      "DAP_REBOOT": var.DAP_REBOOT,
      "ENC_DBAAS_USER_ID": var.ENC_DBAAS_USER_ID,
      "ENC_DBAAS_TOKEN_AES_ENC_KEY": var.ENC_DBAAS_TOKEN_AES_ENC_KEY,
      "ENC_DBAAS_TOKEN": var.ENC_DBAAS_TOKEN,
      "ENC_COS_API_KEY": var.ENC_COS_API_KEY,
      "ENC_COS_ID": var.ENC_COS_ID,
      "ENC_HPCS_API_KEY": var.ENC_HPCS_API_KEY,
      "ENC_HPCS_ENDPOINT": var.ENC_HPCS_ENDPOINT,
      "ENC_HPCS_GUID": var.ENC_HPCS_GUID,
      "ENC_HPCS_ADDRESS": var.ENC_HPCS_ADDRESS,
      "ENC_HPCS_CLIENT_KEY_AES_ENC_KEY": var.ENC_HPCS_CLIENT_KEY_AES_ENC_KEY,
      "ENC_HPCS_CLIENT_KEY1": var.ENC_HPCS_CLIENT_KEY1,
      "ENC_HPCS_CLIENT_KEY2": var.ENC_HPCS_CLIENT_KEY2,
      "ENC_HPCS_CLIENT_CERT_AES_ENC_KEY": var.ENC_HPCS_CLIENT_CERT_AES_ENC_KEY,
      "ENC_HPCS_CLIENT_CERT": var.ENC_HPCS_CLIENT_CERT,
      "DAP_BACKUP_BUCKET": var.DAP_BACKUP_BUCKET,
      "WALLET_BACKUP_BUCKET": var.WALLET_BACKUP_BUCKET,
      "SKIP_HPCS_VERIFY": var.SKIP_HPCS_VERIFY,
      "HPCS_INTERVAL": var.HPCS_INTERVAL,
      "RHSSO_HOST": var.RHSSO_HOST,
      "DAP_HOST": var.DAP_HOST,
      "LOGDNA_INGESTION_KEY": var.LOGDNA_INGESTION_KEY,
      "LOGDNA_INGESTION_HOSTNAME": var.LOGDNA_INGESTION_HOSTNAME,
      "LOGDNA_API_HOSTNAME": var.LOGDNA_API_HOSTNAME,
      "TRANSACTION_PROPOSER_PORT": var.TRANSACTION_PROPOSER_PORT,
      "APPROVAL_SERVER_PORT": var.APPROVAL_SERVER_PORT,
      "RHSSO_SSH_PORT": var.RHSSO_SSH_PORT,
      "TRANSACTION_PROPOSER_SSH_PORT": var.TRANSACTION_PROPOSER_SSH_PORT,
      "AUTHORIZATION_POLICY_SERVICE_SSH_PORT": var.AUTHORIZATION_POLICY_SERVICE_SSH_PORT,
      "FRAUD_DETECTION_POLICY_SERVICE_SSH_PORT": var.FRAUD_DETECTION_POLICY_SERVICE_SSH_PORT,
      "TRANSACTION_APPROVAL_POLICY_SERVICE_SSH_PORT": var.TRANSACTION_APPROVAL_POLICY_SERVICE_SSH_PORT,
      "SIGNING_SERVICE_SSH_PORT": var.SIGNING_SERVICE_SSH_PORT,
      "TXQUEUE_NAME": var.TXQUEUE_NAME,
      "WALLETDB_NAME": var.WALLETDB_NAME,
      "MAIL_USERNAME": var.MAIL_USERNAME,
      "MAIL_PASSWORD": var.MAIL_PASSWORD,
      "DBAAS_RESOURCE_GROUP": var.DBAAS_RESOURCE_GROUP,
      "RHSSO_ADMIN_PASSWORD": var.RHSSO_ADMIN_PASSWORD,
      "RHPAM_ADMIN_PASSWORD": var.RHPAM_ADMIN_PASSWORD,
      "RHPAM_USER_PASSWORD": var.RHPAM_USER_PASSWORD,
      "RHPAM_APPROVER_PASSWORD": var.RHPAM_APPROVER_PASSWORD
    }
  }
  workload_template = {
    "type" : "workload",
    "auths": local.auths,
    "images": "${var.DCT_PUBKEY != "" ? local.images : {}}"
  }
}
