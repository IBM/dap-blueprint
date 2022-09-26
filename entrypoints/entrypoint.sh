#!/bin/bash

SUPERVISORD_CONF=/usr/local/etc/supervisord.conf

if [ ${DAP_SERVICE} != RHSSO ]; then
    echo "${RHSSO_HOST} rhsso-host" >> /etc/hosts
fi

if [ -n "${DAP_HOST}" ]; then
    echo "${DAP_HOST} dap-host" >> /etc/hosts
fi

mkdir /dap-logs
if [ ! -d /data ]; then
    mkdir /data
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
