#!/bin/bash

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

DAP_REBOOT=${1:-True}
DOCKER_BUILD_LOG=${2:-docker-build.log}

./create-tf-env.sh ${DAP_REBOOT} false ${DOCKER_BUILD_LOG}

cd terraform
./create_contract.sh
