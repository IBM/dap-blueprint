#!/bin/bash

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

source ../.env
export $(cat .env.tf | grep -v ^#)
SSH_PUBKEY=`cat ${SSH_PUBKEY_PATH}`
export TF_VAR_SSH_PUBKEY="${SSH_PUBKEY}"

./gen_compose.sh

RHSSO_TARGETS="-target local_file.rhsso_contract -target local_file.rhsso_contract_encrypted"
TP_TARGETS="-target local_file.transaction_proposer_contract -target local_file.transaction_proposer_contract_encrypted"
AP_TARGETS="-target local_file.authorization_policy_service_contract -target local_file.authorization_policy_service_contract_encrypted"
FDP_TARGETS="-target local_file.fraud_detection_policy_service_contract -target local_file.fraud_detection_policy_service_contract_encrypted"
TAP_TARGETS="-target local_file.transaction_approval_policy_service_contract -target local_file.transaction_approval_policy_service_contract_encrypted"
SS_TARGETS="-target local_file.signing_service_contract -target local_file.signing_service_contract_encrypted"

TARGETS="${RHSSO_TARGETS} ${TP_TARGETS} ${AP_TARGETS} ${FDP_TARGETS} ${TAP_TARGETS} ${SS_TARGETS}"

touch rhsso.yml
touch tp.yml
touch ap.yml
touch fdp.yml
touch tap.yml
touch ss.yml

echo Destroying ${TARGETS}
terraform destroy ${TARGETS}

touch rhsso.yml
touch tp.yml
touch ap.yml
touch fdp.yml
touch tap.yml
touch ss.yml

echo Deploying ${TARGETS}
terraform apply ${TARGETS}
