#!/bin/bash

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

SERVICE=${1:-all}

cd terraform
./deploy.sh ${SERVICE} true false
