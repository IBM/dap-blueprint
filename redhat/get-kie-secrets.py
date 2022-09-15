#!/usr/bin/env python3

import dap_crypto, dap_cos, time, json

key1, key2 = dap_crypto.derive_common_keys()
cos_client = dap_cos.create_cos_client('CLI')
kie_secret = None
kie_execution_server_secret = None
while True:
    try:
        kie_secret = dap_cos.get_and_decrypt_backup_from_cos('rhsso-kie-secret', key1, key2, cos_client)
        kie_execution_server_secret = dap_cos.get_and_decrypt_backup_from_cos('rhsso-kie-execution-server-secret', key1, key2, cos_client)
        break
    except Exception as e:
        print('Failed to get KIE secrets')
        print('Try after 10-sec sleeping')
        time.sleep(10)
json_data = {
    'kie_secret': kie_secret,
    'kie_execution_server_secret': kie_execution_server_secret
}

with open('./kie-secrets.json', 'w') as f:
    json.dump(json_data, f)
