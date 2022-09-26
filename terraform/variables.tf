# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

# variable "ibmcloud_api_key" {
#   description = "Enter your IBM Cloud API Key, you can get your IBM Cloud API key using: https://cloud.ibm.com/iam#/apikeys"
# }

variable REGISTRY_URL {
  type        = string
  description = "Registry URL to pull an image."
}

variable REGISTRY_USERNAME {
  type        = string
  description = "Username to access your registry."
}

variable REGISTRY_PASSWORD {
  type        = string
  description = "Password to access your registry"
}

variable NOTARY_URL {
  type        = string
  description = "URL of your notary server"
  default     = ""
}

variable DCT_PUBKEY {
  type        = string
  description = "Public key for docker content trust."
  default     = ""
}

variable DAP_IMAGE {
  type        = string
  description = "DAP image name."
}

variable "REGION" {
  type        = string
  description = "Region to deploy to, e.g. eu-gb."
}

variable "ZONE" {
  type        = string
  description = "Zone to deploy to, e.g. 2."
}

variable "LOGDNA_INGESTION_KEY" {
  type        = string
  description = "Ingestion key for logDNA."
  sensitive   = true
}

variable "LOGDNA_INGESTION_HOSTNAME" {
  type        = string
  description = "Ingestion hostname (just the name not the port)."
}

variable "LOGDNA_SYSLOG_INGESTION_HOSTNAME" {
  type        = string
  description = "Ingestion hostname for syslog (just the name not the port)."
}

variable "LOGDNA_API_HOSTNAME" {
  type        = string
  description = "API hostname for LogDNA (just the name not the port)."
}

variable "PREFIX" {
  type        = string
  description = "Prefix for all generated resources. Make sure to have a custom image with that name."
  default     = "hpcr-dap"
}

variable "PROFILE" {
  type        = string
  description = "Profile used for the VSI, this has to be a secure execution profile in the format Xz2e-YxZ, e.g. bz2e-1x4."
  default     = "bz2e-1x4"
}

variable "ZHSM" {
  type        = string
  description = "IP address and port (xxx.xxx.xxx.xxx:nnnn) for an on-prem HPCS instance."
  default     = ""
}

variable "ZHSM_CREDENTIAL" {
  type        = string
  description = "Path to a credential yaml file (should be /git/dap-blueprint/demo/grep11_credentials/grep11_credential.yaml) for an on-prem HPCS instance."
  default     = ""
}

variable "SSH_PUBKEY" {
  type        = string
  description = "SSH public key to access DAP containers (should be used only for debugging)."
  default     = ""
}

variable "ARGON2_SALT" {
  type        = string
  description = "A salt value to calculate a ARGON2 hash value."
}

variable "DEPLOY_TIME_SECRET" {
  type        = string
  description = "Deploy-time secret."
} 

variable "OLD_DEPLOY_TIME_SECRET" {
  type        = string
  description = "Old deploy-time secret (used only for rotating a key)."
  default     = ""
}

variable "DAP_REBOOT" {
  type        = string
  description = "If True, DAP is rebooted. Otherwise, DAP is booted from scratch."
  default     = "True"
}

variable "ENC_DBAAS_USER_ID" {
  type        = string
  description = "Encrypted user id to create Hyper Protect DBaaS instances."
}

variable "ENC_DBAAS_TOKEN_AES_ENC_KEY" {
  type        = string
  description = "Encrypted AES key for an encrypted token to create Hyper Protect DBaaS instances."
}

variable "ENC_DBAAS_TOKEN" {
  type        = string
  description = "Encryped token to create Hyper Protect DBaaS instances."
}

variable "ENC_COS_API_KEY" {
  type        = string
  description = "Encryped API key to access a cloud-object storage (COS) instance."
}

variable "ENC_COS_ID" {
  type        = string
  description = "Encryped cloud-object storage id."
}

variable "ENC_HPCS_API_KEY" {
  type        = string
  description = "Encryped API key to access a Hyper Protect Crypto Service instance."
  default     = ""
}

variable "ENC_HPCS_ENDPOINT" {
  type        = string
  description = "Encryped endpoint of a Hyper Protect Crypto Service instance."
  default     = ""
}

variable "ENC_HPCS_GUID" {
  type        = string
  description = "Encrypted id of a Hyper Protect Crypto Service instance."
  default     = ""
}

variable "ENC_HPCS_ADDRESS" {
  type        = string
  description = "Encryped IP address of Hyper Protect Crypto Service instance."
  default     = ""
}

variable "ENC_HPCS_CLIENT_KEY_AES_ENC_KEY" {
  type        = string
  description = "Encryped AES key to decrypt an encrypted client key used for mTLS authentication of Hyper Protect Crypto Service."
  default     = ""
}

variable "ENC_HPCS_CLIENT_KEY1" {
  type        = string
  description = "First half of an encryped client key used for mTLS authentication of Hyper Protect Crypto Service."
  default     = ""
}

variable "ENC_HPCS_CLIENT_KEY2" {
  type        = string
  description = "Second half of an encrypted client key used for mTLS authentication of Hyper Protect Crypto Service."
  default     = ""
}

variable "ENC_HPCS_CLIENT_CERT_AES_ENC_KEY" {
  type        = string
  description = "Encryped AES key to decrypt an encrypted client certificate used for mTLS authentication of Hyper Protect Crypto Service."
  default     = ""
}

variable "ENC_HPCS_CLIENT_CERT" {
  type        = string
  description = "Encryped client certificate for mTLS authentication of Hyper Protect Crypto Service."
  default     = ""
}

variable "DAP_BACKUP_BUCKET" {
  type        = string
  description = "Bucket name to backup the DAP information in a cloud-object storage instance."
}

variable "WALLET_BACKUP_BUCKET" {
  type        = string
  description = "Bucket name to backup the wallet information in a cloud-object storage instance."
}

variable "SKIP_HPCS_VERIFY" {
  type        = string
  description = "If True, signature verification is disabled (only for debugging purpose)."
  default     = "False"
}

variable "HPCS_INTERVAL" {
  type        = string
  description = "Interval in seconds to access a Hyper Protect Crypto Service instance."
  default     = "0"
}

variable "RHSSO_HOST" {
  type        = string
  description = "IP address of Red Hat Single Sign-On server."
  default     = ""
}

variable "DAP_HOST" {
  type        = string
  description = "IP address of transaction proposer."
  default     = ""
}

variable "TRANSACTION_PROPOSER_PORT" {
  type        = string
  description = "Transaction proposer port"
  default     = "5000"
}

variable "APPROVAL_SERVER_PORT" {
  type        = string
  description = "Approval server port"
  default     = "5001"
}

variable "RHSSO_SSH_PORT" {
  type        = string
  description = "SSH port for rhsso (only for debugging)"
  default     = "6000"
}

variable "TRANSACTION_PROPOSER_SSH_PORT" {
  type        = string
  description = "SH port for transaction proposer (only for debugging)"
  default     = "6001"
}

variable "AUTHORIZATION_POLICY_SERVICE_SSH_PORT" {
  type        = string
  description = "SH port for authorization policy service (only for debugging)"
  default     = "6002"
}

variable "FRAUD_DETECTION_POLICY_SERVICE_SSH_PORT" {
  type        = string
  description = "SH port for fraud-detection policy service (only for debugging)"
  default     = "6003"
}

variable "TRANSACTION_APPROVAL_POLICY_SERVICE_SSH_PORT" {
  type        = string
  description = "SH port for transaction-approval policy service (only for debugging)"
  default     = "6004"
}

variable "SIGNING_SERVICE_SSH_PORT" {
  type        = string
  description = "SH port for signing service (only for debugging)"
  default     = "6005"
}

variable "TXQUEUE_NAME" {
  type        = string
  description = "Instance name of txqueue."
  default     = "txqueue"
}

variable "WALLETDB_NAME" {
  type        = string
  description = "Instance name of walletdb."
  default     = "walletdb"
}

variable "MAIL_USERNAME" {
  type        = string
  description = "User name of your SMTP server (e.g., mailtrap smtp server)."
}

variable "MAIL_PASSWORD" {
  type        = string
  description = "Password of your SMTP server (e.g., mailtrap smtp server)."
}

variable "DBAAS_RESOURCE_GROUP" {
  type        = string
  description = "Resource group to create a Hyper Protect DBaaS instance in your IBM Cloud account."
}

variable "RHSSO_ADMIN_PASSWORD" {
  type        = string
  description = "Admin password for Red Hat Single Sign-On."
}

variable "RHPAM_ADMIN_PASSWORD" {
  type        = string
  description = "Admin password for Red Hat Process Automation Manager."
}

variable "RHPAM_USER_PASSWORD" {
  type        = string
  description = "User password (alice, bob, charlie)."
}

variable "RHPAM_APPROVER_PASSWORD" {
  type        = string
  description = "Approver password (aimee, jon, katy)."
}
