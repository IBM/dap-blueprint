#!/bin/bash

HOST=${1}
PASSWORD=${2}

mongo --host ${HOST} -u admin -p ${PASSWORD} --authenticationDatabase admin --tls --tlsCAFile /mongo-cert/root-ca.pem --tlsCertificateKeyFile /mongo-cert/mongo-client.pem admin
