#/bin/bash

sleep 60

KIE_CLIENT_ID=e0fa3224-9fd9-47b9-9494-fa489ab99b64
KIE_EXECUTION_SERVER_CLIENT_ID=2d919e0d-df18-45c8-baf2-9c843eb2f277

### Authenticate
i=1
while :
do
    echo ${i}th try for authentication
    RHSSO_OUT=`./kcadm.sh config credentials --server http://localhost:8180/auth --realm master --user admin --password ${RHSSO_ADMIN_PASSWORD} 2>&1`
    echo RHSSO_OUT=${RHSSO_OUT}
    if [ ! "`echo $RHSSO_OUT | grep 'Failed'`" ]; then
        break
    fi
    sleep 10

    i=$((i++))
done

### Create a realm
# AUTHORIZATION_POLICY_SERVICE_HOST=localhost:8080
# sed -e "s/localhost:8080/${AUTHORIZATION_POLICY_SERVICE_HOST}/g" ./realm-export.json.org > ./realm-export.json
cp realm-export.json.org realm-export.json
./kcadm.sh create realms -f realm-export.json -s enabled=true

### Create credentials
./kcadm.sh create clients/${KIE_CLIENT_ID}/client-secret -r rhpam
./kcadm.sh create clients/${KIE_EXECUTION_SERVER_CLIENT_ID}/client-secret -r rhpam
KIE_SECRET=`./kcadm.sh get clients/${KIE_CLIENT_ID}/client-secret -r rhpam | jq -r '.value'`
KIE_EXECUTION_SERVER_SECRET=`./kcadm.sh get clients/${KIE_EXECUTION_SERVER_CLIENT_ID}/client-secret -r rhpam | jq -r '.value'`
echo KIE_SECRET=${KIE_SECRET}
echo KIE_EXECUTION_SERVER_SECRET=${KIE_EXECUTION_SERVER_SECRET}
echo -n ${KIE_SECRET} > /tmp/kie-secret.txt
echo -n ${KIE_EXECUTION_SERVER_SECRET} > /tmp/kie-execution-server-secret.txt
echo "Storing KIE_SECRET and KIE_EXECUTION_SERVER_SECRET in COS"
/git/dap-blueprint/src/dap_util/dap_cos.py encrypt_backup rhsso-kie-secret ${KIE_SECRET}
/git/dap-blueprint/src/dap_util/dap_cos.py encrypt_backup rhsso-kie-execution-server-secret ${KIE_EXECUTION_SERVER_SECRET}

### Create an approver role
./kcadm.sh create roles -r rhpam -s name=end-user

### Create end-users
# admin
./kcadm.sh create users -r rhpam -s username=admin -s enabled=true
./kcadm.sh set-password -r rhpam --username admin --new-password ${RHPAM_ADMIN_PASSWORD}
./kcadm.sh add-roles --uusername admin --rolename admin -r rhpam
./kcadm.sh add-roles --uusername admin --rolename kie-server -r rhpam
./kcadm.sh add-roles --uusername admin --rolename rest-all -r rhpam
# controlleruser
./kcadm.sh create users -r rhpam -s username=controlleruser -s enabled=true
./kcadm.sh set-password -r rhpam --username controlleruser --new-password ${RHPAM_ADMIN_PASSWORD}
./kcadm.sh add-roles --uusername controlleruser --rolename kie-server -r rhpam
./kcadm.sh add-roles --uusername controlleruser --rolename rest-all -r rhpam
# alice
./kcadm.sh create users -r rhpam -s username=alice -s enabled=true -s email=alice@ibm.com
./kcadm.sh set-password -r rhpam --username alice --new-password ${RHPAM_USER_PASSWORD}
./kcadm.sh add-roles --uusername alice --rolename end-user -r rhpam
# bob
./kcadm.sh create users -r rhpam -s username=bob -s enabled=true -s email=bob@ibm.com
./kcadm.sh set-password -r rhpam --username bob --new-password ${RHPAM_USER_PASSWORD}
./kcadm.sh add-roles --uusername bob --rolename end-user -r rhpam
# charlie
./kcadm.sh create users -r rhpam -s username=charlie -s enabled=true -s email=charlie@ibm.com
./kcadm.sh set-password -r rhpam --username charlie --new-password ${RHPAM_USER_PASSWORD}
./kcadm.sh add-roles --uusername charlie --rolename end-user -r rhpam
# eve
./kcadm.sh create users -r rhpam -s username=eve -s enabled=true -s email=eve@ibm.com
./kcadm.sh set-password -r rhpam --username eve --new-password ${RHPAM_USER_PASSWORD}
./kcadm.sh add-roles --uusername eve --rolename end-user -r rhpam
# mallory
./kcadm.sh create users -r rhpam -s username=mallory -s enabled=true -s email=mallory@ibm.com
./kcadm.sh set-password -r rhpam --username mallory --new-password ${RHPAM_USER_PASSWORD}
./kcadm.sh add-roles --uusername mallory --rolename end-user -r rhpam
# aimee
./kcadm.sh create users -r rhpam -s username=aimee -s enabled=true -s email=aimee@ibm.com
./kcadm.sh set-password -r rhpam --username aimee --new-password ${RHPAM_APPROVER_PASSWORD}
./kcadm.sh add-roles --uusername aimee --rolename user -r rhpam
# jon
./kcadm.sh create users -r rhpam -s username=jon -s enabled=true -s email=jon@ibm.com
./kcadm.sh set-password -r rhpam --username jon --new-password ${RHPAM_APPROVER_PASSWORD}
./kcadm.sh add-roles --uusername jon --rolename user -r rhpam
# katy
./kcadm.sh create users -r rhpam -s username=katy -s enabled=true -s email=katy@ibm.com
./kcadm.sh set-password -r rhpam --username katy --new-password ${RHPAM_APPROVER_PASSWORD}
./kcadm.sh add-roles --uusername katy --rolename user -r rhpam

### Create an OIDC client
./kcadm.sh add-roles -r rhpam --uusername admin --cclientid realm-management --rolename manage-clients
./kcreg.sh config credentials --server http://localhost:8180/auth --realm rhpam --user admin --password ${RHPAM_ADMIN_PASSWORD} --client admin-cli
./kcreg.sh create -s clientId=flask -s 'redirectUris=["https://localhost:5000/*","https://localhost:5001/*","https://dap-host:5000/*","https://approval-host:5001/*"]'
./kcreg.sh update kie -s 'redirectUris=["https://localhost:8443/business-central/*","https://rhpam-host:8443/business-central/*"]'
./kcreg.sh update kie-execution-server -s 'redirectUris=["https://localhost:8443/kie-server/*"]'
OIDC_SECRET=`./kcreg.sh get flask | jq -r '.secret'`
echo OIDC_SECRET=${OIDC_SECRET}
echo -n ${OIDC_SECRET} > /tmp/oidc-secret.txt

echo "Storing OIDC_SECRET in COS"
/git/dap-blueprint/src/dap_util/dap_cos.py encrypt_backup rhsso-oidc-secret ${OIDC_SECRET}

FRONTEND_HOST=rhsso-host
# FRONTEND_URL=http://${FRONTEND_HOST}:8180/auth
FRONTEND_URL=https://${FRONTEND_HOST}:8543/auth
echo FRONTEND_URL=${FRONTEND_URL}
./kcadm.sh update realms/rhpam -s "attributes.frontendUrl=${FRONTEND_URL}"

# ./kcadm.sh update realms/rhpam -s 'sslRequired=all'
