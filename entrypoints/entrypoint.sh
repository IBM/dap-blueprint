#!/bin/bash

SUPERVISORD_CONF=/usr/local/etc/supervisord.conf

# This code should run only for HPVS deployment since RHSSO_HOST is not set for local deployment.
if [ ${DAP_SERVICE} != RHSSO ] && [ -n "${RHSSO_HOST}" ]; then
    echo "Setting rhsso-host to /etc/hosts"
    RHSSO_IP=`host ${RHSSO_HOST}`
    RHSSO_IP=${RHSSO_IP##* }
    echo "${RHSSO_IP} rhsso-host" >> /etc/hosts
fi

# This code should run only for HPVS deployment since RHSSO_HOST is not set for local deployment.
if [ ${DAP_SERVICE} != TP] && [ -n "${DAP_HOST}" ]; then
    echo "Setting dap-host to /etc/hosts"
    DAP_IP=`host ${DAP_HOST}`
    DAP_IP=${DAP_IP##* }
    echo "${DAP_IP} dap-host" >> /etc/hosts
fi

mkdir /dap-logs
if [ ! -d /data ]; then
    mkdir /data
fi

if [ ${DAP_SERVICE} == ELECTRUMGUI ]; then
    cd /git/dap-blueprint/DigitalAssets-Electrum
    sh -c './start_gui.sh'
    exit 0
fi

if [ ${DAP_SERVICE} == ELECTRUM ]; then
    cp supervisord-${DAP_SERVICE,,}.conf ${SUPERVISORD_CONF}
    /usr/local/bin/supervisord
fi

mkdir -p /root/.ssh/
echo ${SSH_PUBKEY} > /root/.ssh/authorized_keys
chmod 700 /root/.ssh
chmod 600 /root/.ssh/authorized_keys

if [ ! -f supervisord-${DAP_SERVICE,,}.conf ]; then
    echo Unknown service ${DAP_SERVICE}
else
    cp supervisord-${DAP_SERVICE,,}.conf ${SUPERVISORD_CONF}
    if [ ${DAP_SERVICE} == RHSSO ]; then
        /usr/local/bin/supervisord
        cd /rhsso-7.4/bin
        ./initialize-rhsso.sh > /dap-logs/rhsso-init.out 2> /dap-logs/rhsso-init.err
        tail -f /dev/null
    else
        /usr/local/bin/supervisord
    fi
fi
