#!/bin/bash

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

SERVICE=${1:-all}
DAP_REBOOT=${2:-True}
DOCKER_BUILD_LOG=${3:-docker-build.log}

./create-tf-env.sh ${DAP_REBOOT} true ${DOCKER_BUILD_LOG}

ENV_FILE=.env.local

rm -rf ${ENV_FILE}
touch ${ENV_FILE}
while read line
do
    echo ${line#*TF_VAR_} >> ${ENV_FILE}
done < ./terraform/.env.tf

export $(cat .env | grep -v ^#)
SSH_PUBKEY=`cat ${SSH_PUBKEY_PATH}`
echo "SSH_PUBKEY=${SSH_PUBKEY}" >> ${ENV_FILE}

pushd terraform > /dev/null
./gen_compose.sh
popd > /dev/null

if [ ${SERVICE} == RHSSO ]; then
    cp .env.local terraform/rhsso/.env
    pushd terraform/rhsso > /dev/null
    docker-compose down
    docker-compose up -d
    popd > /dev/null
elif [ ${SERVICE} == TP ]; then
    cp .env.local terraform/transaction_proposer/.env
    pushd terraform/transaction_proposer > /dev/null
    docker-compose down
    docker-compose up -d
    popd > /dev/null
elif [ ${SERVICE} == AP ]; then
    cp .env.local terraform/authorization_policy_service/.env
    pushd terraform/authorization_policy_service > /dev/null
    docker-compose down
    docker-compose up -d
    popd > /dev/null
elif [ ${SERVICE} == FDP ]; then
    cp .env.local terraform/fraud_detection_policy_service/.env
    pushd terraform/fraud_detection_policy_service > /dev/null
    docker-compose down
    docker-compose up -d
    popd > /dev/null
elif [ ${SERVICE} == TAP ]; then
    cp .env.local terraform/transaction_approval_policy_service/.env
    pushd terraform/transaction_approval_policy_service > /dev/null
    docker-compose down
    docker-compose up -d
    popd > /dev/null
elif [ ${SERVICE} == SS ]; then
    cp .env.local terraform/signing_service/.env
    pushd terraform/signing_service > /dev/null
    docker-compose down
    docker-compose up -d
    popd > /dev/null
else
    WORKLOADS="signing_service authorization_policy_service fraud_detection_policy_service transaction_approval_policy_service"
    for WORKLOAD in ${WORKLOADS}
    do
        cp .env.local terraform/${WORKLOAD}/.env
        pushd terraform/${WORKLOAD} > /dev/null
        docker-compose up -d
        popd
    done
fi
