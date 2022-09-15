#!/bin/bash

# This script is assumed to be run by a workload provider. A public
# key is assumed to be stored in keys/public.pem which is generated to
# build an image before running this script.

PUBKEY_FILE=${1}

CRYPTO=./src/dap_util/dap_crypto.py

# user_id and token are stored in .dbaas.tmp/dbaas.token in the JSON
# format.
./src/dap_util/dbaas_api.py get_token ${DBAAS_API_KEY}
DBAAS_USER_ID=`cat .dbaas.tmp/dbaas.token | jq -r .user_id`
DBAAS_TOKEN=`cat .dbaas.tmp/dbaas.token | jq -r .access_token`
ENC_DBAAS_USER_ID=`${CRYPTO} rsa_encrypt ${PUBKEY_FILE} ${DBAAS_USER_ID}`
TMP=`${CRYPTO} rsa_encrypt_long ${PUBKEY_FILE} ${DBAAS_TOKEN}`
ENC_DBAAS_TOKEN_AES_ENC_KEY=`echo ${TMP} | jq -r .aes_encrypted_key`
ENC_DBAAS_TOKEN=`echo ${TMP} | jq -r .cipher_text`

ENC_COS_API_KEY=`${CRYPTO} rsa_encrypt ${PUBKEY_FILE} ${COS_API_KEY}`
ENC_COS_ID=`${CRYPTO} rsa_encrypt ${PUBKEY_FILE} ${COS_ID}`

if [[ -n "${HPCS_ADDRESS}" ]]; then
    ENC_HPCS_ADDRESS=`${CRYPTO} rsa_encrypt ${PUBKEY_FILE} ${HPCS_ADDRESS}`
fi

if [[ -n "${HPCS_ENDPOINT}" ]] && [[ -n "${HPCS_API_KEY}" ]] && [[ -n "${HPCS_GUID}" ]]; then
    ENC_HPCS_ENDPOINT=`${CRYPTO} rsa_encrypt ${PUBKEY_FILE} ${HPCS_ENDPOINT}`
    ENC_HPCS_API_KEY=`${CRYPTO} rsa_encrypt ${PUBKEY_FILE} ${HPCS_API_KEY}`
    ENC_HPCS_GUID=`${CRYPTO} rsa_encrypt ${PUBKEY_FILE} ${HPCS_GUID}`
fi

if [[ -n "${HPCS_CLIENT_KEY}" ]] && [[ -n "${HPCS_CLIENT_CERT}" ]]; then
    TMP=`${CRYPTO} rsa_encrypt_long ${PUBKEY_FILE} "${HPCS_CLIENT_KEY}"`
    ENC_HPCS_CLIENT_KEY_AES_ENC_KEY=`echo ${TMP} | jq -r .aes_encrypted_key`
    ENC_HPCS_CLIENT_KEY1=`echo ${TMP} | jq -r .cipher_text1`
    ENC_HPCS_CLIENT_KEY2=`echo ${TMP} | jq -r .cipher_text2`

    TMP=`${CRYPTO} rsa_encrypt_long ${PUBKEY_FILE} "${HPCS_CLIENT_CERT}"`
    ENC_HPCS_CLIENT_CERT_AES_ENC_KEY=`echo ${TMP} | jq -r .aes_encrypted_key`
    ENC_HPCS_CLIENT_CERT=`echo ${TMP} | jq -r .cipher_text`
fi

if [[ -n "${GREP11_HOST}" ]] && [[ -n "${GREP11_CERT}" ]] && [[ -n "${GREP11_KEY}" ]] && [[ -n "${GREP11_CACERT}" ]]; then
    ENC_GREP11_HOST=`${CRYPTO} rsa_encrypt ${PUBKEY_FILE} ${GREP11_HOST}`

    TMP=`${CRYPTO} rsa_encrypt_long ${PUBKEY_FILE} "${GREP11_CERT}"`
    ENC_GREP11_CERT_AES_ENC_KEY=`echo ${TMP} | jq -r .aes_encrypted_key`
    ENC_GREP11_CERT=`echo ${TMP} | jq -r .cipher_text`

    TMP=`${CRYPTO} rsa_encrypt_long ${PUBKEY_FILE} "${GREP11_KEY}"`
    ENC_GREP11_KEY_AES_ENC_KEY=`echo ${TMP} | jq -r .aes_encrypted_key`
    ENC_GREP11_KEY=`echo ${TMP} | jq -r .cipher_text`

    TMP=`${CRYPTO} rsa_encrypt_long ${PUBKEY_FILE} "${GREP11_CACERT}"`
    ENC_GREP11_CACERT_AES_ENC_KEY=`echo ${TMP} | jq -r .aes_encrypted_key`
    ENC_GREP11_CACERT=`echo ${TMP} | jq -r .cipher_text`
fi

FILE=credentials.env

echo "# This is a set of encrypted credentials provided from a workload provider" > ${FILE}

echo "ENC_DBAAS_USER_ID=${ENC_DBAAS_USER_ID}" >> ${FILE}
echo "ENC_DBAAS_TOKEN_AES_ENC_KEY=${ENC_DBAAS_TOKEN_AES_ENC_KEY}" >> ${FILE}
echo "ENC_DBAAS_TOKEN=${ENC_DBAAS_TOKEN}" >> ${FILE}

echo "ENC_COS_API_KEY=${ENC_COS_API_KEY}" >> ${FILE}
echo "ENC_COS_ID=${ENC_COS_ID}" >> ${FILE}

if [[ -n "${ENC_HPCS_ADDRESS}" ]]; then
    echo "ENC_HPCS_ADDRESS=${ENC_HPCS_ADDRESS}" >> ${FILE}
fi

if [[ -n "${ENC_HPCS_ENDPOINT}" ]] && [[ -n "${ENC_HPCS_API_KEY}" ]] && [[ -n "${ENC_HPCS_GUID}" ]]; then
    echo "ENC_HPCS_API_KEY=${ENC_HPCS_API_KEY}" >> ${FILE}
    echo "ENC_HPCS_ENDPOINT=${ENC_HPCS_ENDPOINT}" >> ${FILE}
    echo "ENC_HPCS_GUID=${ENC_HPCS_GUID}" >> ${FILE}
fi

if [[ -n "${ENC_HPCS_CLIENT_KEY1}" ]] && [[ -n "${ENC_HPCS_CLIENT_KEY2}" ]] && [[ -n "${ENC_HPCS_CLIENT_CERT}" ]]; then
    echo "ENC_HPCS_CLIENT_KEY_AES_ENC_KEY=${ENC_HPCS_CLIENT_KEY_AES_ENC_KEY}" >> ${FILE}    
    echo "ENC_HPCS_CLIENT_KEY1=${ENC_HPCS_CLIENT_KEY1}" >> ${FILE}
    echo "ENC_HPCS_CLIENT_KEY2=${ENC_HPCS_CLIENT_KEY2}" >> ${FILE}
    echo "ENC_HPCS_CLIENT_CERT_AES_ENC_KEY=${ENC_HPCS_CLIENT_CERT_AES_ENC_KEY}" >> ${FILE}
    echo "ENC_HPCS_CLIENT_CERT=${ENC_HPCS_CLIENT_CERT}" >> ${FILE}
fi

if [[ -n "${ENC_GREP11_HOST}" ]] && [[ -n "${ENC_GREP11_CERT}" ]] && [[ -n "${ENC_GREP11_KEY}" ]] && [[ -n "${ENC_GREP11_CACERT}" ]]; then
    echo "ENC_GREP11_HOST=${ENC_GREP11_HOST}" >> ${FILE}
    echo "ENC_GREP11_CERT_AES_ENC_KEY=${ENC_GREP11_CERT_AES_ENC_KEY}" >> ${FILE}
    echo "ENC_GREP11_CERT=${ENC_GREP11_HOST}" >> ${FILE}
    echo "ENC_GREP11_KEY_AES_ENC_KEY=${ENC_GREP11_KEY_AES_ENC_KEY}" >> ${FILE}
    echo "ENC_GREP11_KEY=${ENC_GREP11_KEY}" >> ${FILE}
    echo "ENC_GREP11_CACERT_AES_ENC_KEY=${ENC_GREP11_CACERT_AES_ENC_KEY}" >> ${FILE}
    echo "ENC_GREP11_CACERT=${ENC_GREP11_CACERT}" >> ${FILE}
fi
