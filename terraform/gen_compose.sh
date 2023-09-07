#!/bin/bash

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

. .env.tf

WORKLOADS="rhsso signing_service transaction_proposer authorization_policy_service fraud_detection_policy_service transaction_approval_policy_service txqueue walletdb"

unset DELETE_LINES
if [[ ${DOCKER_NETWORK_EXTERNAL} == true ]]; then
    DELETE_LINES="-e /driver/d -e /ipam/d -e /config/d -e /subnet/d"
fi

for WORKLOAD in ${WORKLOADS}
do
    rm -rf ${WORKLOAD}
    mkdir -p ${WORKLOAD}
    sed ${DELETE_LINES} -e "s/DAP_IMAGE/${TF_VAR_DAP_IMAGE//\//\\/}/g" -e "s/DOCKER_NETWORK_EXTERNAL/${DOCKER_NETWORK_EXTERNAL}/g" ./compose_templates/${WORKLOAD}.yml > ./${WORKLOAD}/docker-compose.yml
    sed ${DELETE_LINES} -e "s/MONGO_IMAGE/${TF_VAR_MONGO_IMAGE//\//\\/}/g" -e "s/DOCKER_NETWORK_EXTERNAL/${DOCKER_NETWORK_EXTERNAL}/g" ./compose_templates/${WORKLOAD}.yml > ./${WORKLOAD}/docker-compose.yml
done
