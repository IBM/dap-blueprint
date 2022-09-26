#!/bin/bash

export $(cat .env | grep -v ^#)

PORT=7777
NAME=electrum

mkdir -p electrum-data/wallets

docker stop ${NAME}
docker rm ${NAME}
docker run -v `pwd`/electrum-data:/data -v `pwd`/.dap.tmp:/git/dap-blueprint/DigitalAssets-Electrum/.dap.tmp -e DAP_HOST=${DAP_HOST} -e RHSSO_HOST=${RHSSO_HOST} -e DAP_SERVICE=ELECTRUM -p ${PORT}:7777 --network dap-network --name ${NAME} -d dap-base
