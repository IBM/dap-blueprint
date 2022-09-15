#!/bin/bash

sed -e "s/mail-username/${MAIL_USERNAME}/g" -e "s/mail-password/${MAIL_PASSWORD}/g" standalone.xml.org > ../standalone/configuration/standalone.xml

./add-user-keycloak.sh -r master -u admin -p ${RHSSO_ADMIN_PASSWORD}

./standalone.sh
