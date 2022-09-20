#!/bin/bash

# sleep 30

GIT_PROJECT_NAME=Authorization_Policy.git
PROJECT_NAME=Authorization_Policy

echo GIT_PROJECT_NAME=${GIT_PROJECT_NAME}
echo PROJECT_NAME=${PROJECT_NAME}

PORT=8443
# PORT=8080

# cd ../dap_client
cd /git/dap-blueprint/src/dap_client

./dap_client.py --port $PORT wait_rhpam
./dap_client.py --port $PORT login_rhpam admin ${RHPAM_PASSWORD}
./dap_client.py --port $PORT create_space_rhpam admin --space MySpace
sleep 10
./dap_client.py --port $PORT git_clone_rhpam admin ${PROJECT_NAME} "file:///git/${GIT_PROJECT_NAME}" --space MySpace
sleep 10

./dap_client.py --port $PORT build_project_rhpam admin ${PROJECT_NAME}
sleep 10
./dap_client.py --port $PORT deploy_project_rhpam admin ${PROJECT_NAME}
sleep 10
./dap_client.py --port $PORT containers_rhpam admin
./dap_client.py --port $PORT start_container_rhpam admin ${PROJECT_NAME}
