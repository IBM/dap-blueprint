#!/usr/bin/env python3

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import argparse, os
import dap_consts

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('service', choices=[
        dap_consts.TRANSACTION_PROPOSER_SHORT_NAME,
        dap_consts.AUTHORIZATION_POLICY_SERVICE_SHORT_NAME,
        dap_consts.FRAUD_DETECTION_POLICY_SERVICE_SHORT_NAME,
        dap_consts.TRANSACTION_APPROVAL_POLICY_SERVICE_SHORT_NAME,
        dap_consts.SIGNING_SERVICE_SHORT_NAME,
        dap_consts.AUTHORIZATION_POLICY_APPROVAL_SERVER_SHORT_NAME])
    parser.add_argument('--dump', default=False)

    reboot = False
    if 'DAP_REBOOT' in os.environ and os.environ['DAP_REBOOT'] == 'True':
        reboot = True

    args = parser.parse_args()

    if not reboot:
        print('Booting ' + args.service)
    else:
        print('Re-booting ' + args.service)
    dap_consts.reboot = reboot
    if 'DAP_ROOT_DIR' not in os.environ:
        raise Exception('DAP_ROOT_DIR environment variable is not set')

    if args.service == dap_consts.TRANSACTION_PROPOSER_SHORT_NAME:    
        dap_consts.service = dap_consts.TRANSACTION_PROPOSER
        dap_consts.flask_root_path = os.environ['DAP_ROOT_DIR'] + '/transaction_proposer'
        from transaction_proposer import transaction_proposer
        transaction_proposer.run(args.dump)
    elif args.service == dap_consts.AUTHORIZATION_POLICY_APPROVAL_SERVER_SHORT_NAME:
        dap_consts.service = dap_consts.AUTHORIZATION_POLICY_APPROVAL_SERVER
        dap_consts.flask_root_path = os.environ['DAP_ROOT_DIR'] + '/policy_service/approval_server'
        from policy_service.approval_server import approval_server
        approval_server.run(args.dump)
    elif args.service == dap_consts.AUTHORIZATION_POLICY_SERVICE_SHORT_NAME:
        from policy_service import authorization_policy_service
        authorization_policy_service.run(reboot)
    elif args.service == dap_consts.FRAUD_DETECTION_POLICY_SERVICE_SHORT_NAME:
        from policy_service import fraud_detection_policy_service
        fraud_detection_policy_service.run(reboot)
    elif args.service == dap_consts.TRANSACTION_APPROVAL_POLICY_SERVICE_SHORT_NAME:
        from policy_service import transaction_approval_policy_service
        transaction_approval_policy_service.run(reboot)
    elif args.service == dap_consts.SIGNING_SERVICE_SHORT_NAME:
        from signing_service import signing_service
        signing_service.run(reboot)
    else:
        print('Unknown service ' + args.service)
