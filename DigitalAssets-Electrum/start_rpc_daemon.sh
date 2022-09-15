#!/bin/bash

NETWORK=--testnet
VERBOSE="-V INFO"

echo Using ${ELECTRUM_DATA} path

./run_electrum ${NETWORK} ${VERBOSE} -D ${ELECTRUM_DATA} -o setconfig rpcuser ${ELECTRUM_USER}
./run_electrum ${NETWORK} ${VERBOSE} -D ${ELECTRUM_DATA} -o setconfig rpcpassword ${ELECTRUM_PASSWORD}
./run_electrum ${NETWORK} ${VERBOSE} -D ${ELECTRUM_DATA} -o setconfig rpchost 0.0.0.0
./run_electrum ${NETWORK} ${VERBOSE} -D ${ELECTRUM_DATA} -o setconfig rpcport 7777

./run_electrum ${NETWORK} ${VERBOSE} -D ${ELECTRUM_DATA} daemon
