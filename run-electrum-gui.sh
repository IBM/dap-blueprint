#!/bin/bash

export $(cat .env | grep -v ^#)

if [ "$#" -ne 2 ]; then
    echo "Usage: run-electrum-gui.sh <port> <vnc-password>"
    exit 1
fi

VNC_PORT=$1
VNC_PASSWORD=$2
NAME=electrumgui-${VNC_PORT}

mkdir -p electrum-data/wallets

docker stop ${NAME}
docker rm ${NAME}
docker run -v `pwd`/electrum-data:/data -v `pwd`/.dap.tmp:/git/dap-blueprint/DigitalAssets-Electrum/.dap.tmp -e DAP_HOST=${DAP_HOST} -e RHSSO_HOST=${RHSSO_HOST} -e DAP_SERVICE=ELECTRUMGUI -p ${VNC_PORT}:${VNC_PORT} -e VNC_PASSWORD=${VNC_PASSWORD} -e VNC_PORT=${VNC_PORT} --network dap-network --name ${NAME} -d dap-base
