#!/bin/bash

SERVICE=${1:-all}

if [ ${SERVICE} == RHSSO ]; then
    pushd terraform/rhsso > /dev/null
    docker-compose down
    popd > /dev/null
elif [ ${SERVICE} == TP ]; then
    pushd terraform/transaction_proposer > /dev/null
    docker-compose down
    popd > /dev/null
elif [ ${SERVICE} == AP ]; then
    pushd terraform/authorization_policy_service > /dev/null
    docker-compose down
    popd > /dev/null
elif [ ${SERVICE} == FDP ]; then
    pushd terraform/fraud_detection_policy_service > /dev/null
    docker-compose down
    popd > /dev/null
elif [ ${SERVICE} == TAP ]; then
    pushd terraform/transaction_approval_policy_service > /dev/null
    docker-compose down
    popd > /dev/null
elif [ ${SERVICE} == SS ]; then
    pushd terraform/signing_service > /dev/null
    docker-compose down
    popd > /dev/null
else
    WORKLOADS="signing_service transaction_proposer authorization_policy_service fraud_detection_policy_service transaction_approval_policy_service"
    for WORKLOAD in ${WORKLOADS}
    do
        pushd terraform/${WORKLOAD} > /dev/null
        docker-compose down
        popd
    done
fi
