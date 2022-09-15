#!/bin/bash

SERVICE=${1:-all}

cd terraform
./deploy.sh ${SERVICE} true false
