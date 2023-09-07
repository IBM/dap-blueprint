#!/bin/bash

if [ ${DAP_SERVICE} = TXQUEUE ]; then
    HOST=${TXQUEUE_HOST}
    PORT=${TXQUEUE_PORT}
    CERT_DIR=${TXQUEUE_CERT_DIR}
elif [ ${DAP_SERVICE} = WALLETDB ]; then
    HOST=${WALLETDB_HOST}
    PORT=${WALLETDB_PORT}
    CERT_DIR=${WALLETDB_CERT_DIR}
fi
SIZE=2048

rm -rf cert
mkdir cert

# Generating a CA key and a self-signed CA certificate
openssl genrsa -out cert/ca-key.pem ${SIZE}
openssl req -new -x509 -key cert/ca-key.pem -out cert/root-ca.pem -subj "/CN=CA"

# Generating a server key and a server certificate
openssl genrsa -out cert/server-key.pem ${SIZE}
openssl req -new -key cert/server-key.pem -out cert/server.csr -subj "/CN=${HOST}" -addext "subjectAltName = DNS:${HOST}"
openssl x509 -req -in cert/server.csr -CA cert/root-ca.pem -CAkey cert/ca-key.pem -CAcreateserial -out cert/server-cert.pem -extfile <(printf "subjectAltName=DNS:${HOST}")
cat cert/server-key.pem cert/server-cert.pem > cert/mongod.pem

# Generating a client key and a client certificate
openssl genrsa -out cert/client-key.pem ${SIZE}
openssl req -new -key cert/client-key.pem -out cert/client.csr -subj "/CN=${HOST}" -addext "subjectAltName = DNS:${HOST}"
openssl x509 -req -in cert/client.csr -CA cert/root-ca.pem -CAkey cert/ca-key.pem -CAcreateserial -out cert/client-cert.pem -extfile <(printf "subjectAltName=DNS:${HOST}")
cat cert/client-key.pem cert/client-cert.pem > cert/mongo-client.pem

# Generating a security key
openssl rand -base64 756 > /etc/mongo-key.txt
chmod 400 /etc/mongo-key.txt
chown 999:999 /etc/mongo-key.txt

rm -rf ${CERT_DIR}
mv cert ${CERT_DIR}

MONGO_PASSWORD=`/git/dap-blueprint/src/dap_util/dap_crypto.py gen_password`
echo "Password for ${DAP_SERVICE}: ${MONGO_PASSWORD}"

echo "Storing DBaaS info"
/git/dap-blueprint/src/dap_util/dbaas.py --password ${MONGO_PASSWORD} --name ${DAP_SERVICE,,} backup_dbaas_info

rm -rf /data/configdb
rm -rf /data/db
mkdir -p /data/configdb
mkdir -p /data/db

chown 999:999 /dap-logs

cp mongod.conf /etc/mongod.conf

export MONGO_INITDB_ROOT_USERNAME=admin
export MONGO_INITDB_ROOT_PASSWORD=${MONGO_PASSWORD}

mongo-entrypoint.sh --config /etc/mongod.conf --logpath /dap-logs/mongod.log

mongo --host ${HOST} --port ${PORT} -u admin -p ${MONGO_PASSWORD} --authenticationDatabase admin --tls --tlsCAFile /mongo-cert/root-ca.pem --tlsCertificateKeyFile /mongo-cert/mongo-client.pem admin --eval 'rs.initiate()'
