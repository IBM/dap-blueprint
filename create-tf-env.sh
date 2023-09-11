#!/bin/bash

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

DAP_REBOOT=${1}
DOCKER_NETWORK_EXTERNAL=${2}
DOCKER_BUILD_LOG=${3}

export $(cat .env.build | grep -v ^#)
export $(cat .env | grep -v ^#)

./collect-build-time-keys.py ${DOCKER_BUILD_LOG}
./setup-credentials.sh ./build-time-keys/public.pem

ENV_FILE=terraform/.env.tf

rm -rf ${ENV_FILE}
touch ${ENV_FILE}
while read line
do
    if [[ -n ${line} ]] && [[ ${line} != \#* ]]; then
        if [[ ${line} != SSH_PUBKEY* ]]; then
            echo "TF_VAR_${line}" >> ${ENV_FILE}
        fi
        if [[ ${line} == IC_API_KEY* ]] || [[ ${line} == IAAS_CLASSIC_USERNAME* ]] || [[ ${line} == IAAS_CLASSIC_API_KEY* ]]; then
            echo "${line}" >> ${ENV_FILE}
        fi
    fi
done < .env
echo "TF_VAR_DAP_REBOOT=${DAP_REBOOT}" >> ${ENV_FILE}
echo "DOCKER_NETWORK_EXTERNAL=${DOCKER_NETWORK_EXTERNAL}" >> ${ENV_FILE}
while read line
do
    if [[ -n ${line} ]] && [[ ${line} != \#* ]]; then
        echo "TF_VAR_${line}" >> ${ENV_FILE}
    fi
done < credentials.env
while read line
do
    if [[ -n ${line} ]] && [[ ${line} != \#* ]]; then
        if [[ ${line} == REGISTRY* ]]; then
            echo "TF_VAR_${line}" >> ${ENV_FILE}
        fi
    fi
done < .env.build
