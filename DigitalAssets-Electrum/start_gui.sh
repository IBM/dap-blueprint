#!/bin/bash

NETWORK=--testnet
VERBOSE="-V INFO"

echo Using ${ELECTRUM_DATA} path

mkdir -p /root/.vnc
x11vnc -storepasswd ${VNC_PASSWORD} ~/.vnc/passwd
Xvfb :1 -screen 0 1280x1024x16 &
sleep 2
x11vnc -forever -usepw -create -rfbport ${VNC_PORT} -display :1.0 &
sleep 2

export DISPLAY=:1.0
./run_electrum ${NETWORK} ${VERBOSE} -D ${ELECTRUM_DATA}
