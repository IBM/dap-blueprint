#!/bin/bash

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

SERVICE=${1:-all}
DAP_REBOOT=${2:-True}
DOCKER_BUILD_LOG=${3:-docker-build.log}

./create-tf-env.sh ${DAP_REBOOT} false ${DOCKER_BUILD_LOG}

cd terraform
./deploy.sh ${SERVICE}
