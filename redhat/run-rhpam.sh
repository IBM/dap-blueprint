#!/bin/bash

./get-kie-secrets.py > ./kie-secrets.json
KIE_SECRET=`cat ./kie-secrets.json | jq -r .kie_secret`
KIE_EXECUTION_SERVER_SECRET=`cat ./kie-secrets.json | jq -r .kie_execution_server_secret`

echo KIE_SECRET=${KIE_SECRET}
echo KIE_EXECUTION_SERVER_SECRET=${KIE_EXECUTION_SERVER_SECRET}

sed -e "s/admin-password/${RHPAM_ADMIN_PASSWORD}/g" -e "s/mail-username/${MAIL_USERNAME}/g" -e "s/mail-password/${MAIL_PASSWORD}/g" -e "s/kie-secret/${KIE_SECRET}/g" -e "s/kie-execution-server-secret/${KIE_EXECUTION_SERVER_SECRET}/g" standalone-full.xml.org > ../standalone/configuration/standalone-full.xml

./jboss-cli.sh --file=adapter-elytron-install-offline.cli -Dserver.config=standalone-full.xml

./standalone.sh -c standalone-full.xml
