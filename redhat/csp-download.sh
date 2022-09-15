#!/bin/bash

CSP_USERNAME=${1}
CSP_TOKEN=${2}

ansible-playbook -vvvv tests/test.yml -e csp_url='https://access.redhat.com/jbossnetwork/restricted/softwareDownload.html?softwareId=80791&product=' -e csp_download_dest='/redhat-packages/rh-sso-7.4.0.zip' -e csp_username=${CSP_USERNAME} -e csp_password=${CSP_TOKEN}
ansible-playbook -vvvv tests/test.yml -e csp_url='https://access.redhat.com/jbossnetwork/restricted/softwareDownload.html?softwareId=80771&product=' -e csp_download_dest='/redhat-packages/rh-sso-7.4.0-eap7-adapter.zip' -e csp_username=${CSP_USERNAME} -e csp_password=${CSP_TOKEN}
ansible-playbook -vvvv tests/test.yml -e csp_url='https://access.redhat.com/jbossnetwork/restricted/softwareDownload.html?softwareId=80101&product=' -e csp_download_dest='/redhat-packages/jboss-eap-7.3.0.zip' -e csp_username=${CSP_USERNAME} -e csp_password=${CSP_TOKEN}
ansible-playbook -vvvv tests/test.yml -e csp_url='https://access.redhat.com/jbossnetwork/restricted/softwareDownload.html?softwareId=98751&product=' -e csp_download_dest='/redhat-packages/rhpam-7.11.0-business-central-eap7-deployable.zip' -e csp_username=${CSP_USERNAME} -e csp_password=${CSP_TOKEN}
ansible-playbook -vvvv tests/test.yml -e csp_url='https://access.redhat.com/jbossnetwork/restricted/softwareDownload.html?softwareId=98761&product=' -e csp_download_dest='/redhat-packages/rhpam-7.11.0-kie-server-ee8.zip' -e csp_username=${CSP_USERNAME} -e csp_password=${CSP_TOKEN}
