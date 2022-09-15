#!/bin/bash

WORKLOADS="signing_service transaction_proposer authorization_policy_service fraud_detection_policy_service transaction_approval_policy_service"

cd terraform
for WORKLOAD in ${WORKLOADS}
do
    pushd ${WORKLOAD} > /dev/null
    docker-compose down
    popd > /dev/null
done

