#!/bin/bash

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

export $(cat .env.build | grep -v ^#)

unset ARGS
ARGS="${ARGS} --build-arg BUILD_TIME_SECRET=""${BUILD_TIME_SECRET}"
ARGS="${ARGS} --build-arg OLD_BUILD_TIME_SECRET=""${OLD_BUILD_TIME_SECRET}"
ARGS="${ARGS} --build-arg REDHAT_EMAIL=""${REDHAT_EMAIL}"
ARGS="${ARGS} --build-arg REDHAT_TOKEN=""${REDHAT_TOKEN}"

docker build --progress=plain -t dap-base ${ARGS} -f Dockerfile . 2>&1 | tee docker-build.log
docker tag dap-base ${REGISTRY_URL}/${REGISTRY_NAMESPACE}/dap-base

docker build --progress=plain -t dap-mongo ${ARGS} -f Dockerfile.mongo . 2>&1 | tee mongo-build.log
docker tag dap-mongo ${REGISTRY_URL}/${REGISTRY_NAMESPACE}/dap-mongo
