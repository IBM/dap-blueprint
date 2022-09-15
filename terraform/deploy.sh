#!/bin/bash

SERVICE=${1:-all}
DESTROY=${2:-true}
DEPLOY=${3:-true}

source ../.env
export $(cat .env.tf | grep -v ^#)
SSH_PUBKEY=`cat ${SSH_PUBKEY_PATH}`
export TF_VAR_SSH_PUBKEY="${SSH_PUBKEY}"

./gen_compose.sh

RHSSO_TARGETS="-target ibm_is_instance.rhsso_vsi -target ibm_is_floating_ip.rhsso_floating_ip -target local_file.rhsso_contract"
TP_TARGETS="-target ibm_is_instance.transaction_proposer_vsi -target ibm_is_floating_ip.transaction_proposer_floating_ip -target local_file.transaction_proposer_contract"
AP_TARGETS="-target ibm_is_instance.authorization_policy_service_vsi -target ibm_is_floating_ip.authorization_policy_service_floating_ip -target local_file.authorization_policy_service_contract"
FDP_TARGETS="-target ibm_is_instance.fraud_detection_policy_service_vsi -target ibm_is_floating_ip.fraud_detection_policy_service_floating_ip -target local_file.fraud_detection_policy_service_contract"
TAP_TARGETS="-target ibm_is_instance.transaction_approval_policy_service_vsi -target ibm_is_floating_ip.transaction_approval_policy_service_floating_ip -target local_file.transaction_approval_policy_service_contract"
SS_TARGETS="-target ibm_is_instance.signing_service_vsi -target ibm_is_floating_ip.signing_service_floating_ip -target local_file.signing_service_contract"

unset TARGETS
if [[ ${SERVICE} == RHSSO ]]; then
    TARGETS="${TARGETS} ${RHSSO_TARGETS}"
elif [[ ${SERVICE} == TP ]]; then
    TARGETS="${TARGETS} ${TP_TARGETS}"
elif [[ ${SERVICE} == AP ]]; then
    TARGETS="${TARGETS} ${AP_TARGETS}"
elif [[ ${SERVICE} == FDP ]]; then
    TARGETS="${TARGETS} ${FDP_TARGETS}"
elif [[ ${SERVICE} == TAP ]]; then
    TARGETS="${TARGETS} ${TAP_TARGETS}"
elif [[ ${SERVICE} == SS ]]; then
    TARGETS="${TARGETS} ${SS_TARGETS}"
else
    TARGETS="${TARGETS} ${TP_TARGETS} ${AP_TARGETS} ${FDP_TARGETS} ${TAP_TARGETS} ${SS_TARGETS}"
fi


if [[ ${DESTROY} == true ]]; then
    echo Destroying ${TARGETS}
    terraform destroy ${TARGETS}
fi

TARGETS="${TARGETS} -target ibm_is_security_group_rule.dap_outbound -target ibm_is_security_group_rule.dap_inbound"
if [[ ${DEPLOY} == true ]]; then
    echo Deploying ${TARGETS}
    terraform apply ${TARGETS}
fi
