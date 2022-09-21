#!/usr/bin/env python3

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import os
from polling_service import PollingService
import dap_consts, electrum_client, dap_client
from .approval_server import approval_table

class AuthorizationPolicyService(PollingService):

    def __init__(self, reboot = False):
        super().__init__(
            serviceid=dap_consts.AUTHORIZATION_POLICY_SERVICE,
            query={
                '$or': [{'request.type': {'$eq': x}} for x in dap_consts.REQUEST_TYPES],
                dap_consts.AUTHORIZATION_POLICY_SERVICE: {'$eq': None}
            },
            response=dap_consts.AUTHORIZATION_POLICY_SERVICE,
            reboot=reboot
        )

        self.btc_amount_threshold = 0.0001
        if 'BTC_AMOUNT_THRESHOLD' in os.environ:
            self.btc_amount_threshold = int(os.environ['BTC_AMOUNT_THRESHOLD'])

        self.btc_daily_amount_threshold = 0.001
        if 'BTC_DAILY_AMOUNT_THRESHOLD' in os .environ:
            self.btc_daily_amount_threshold = int(os.environ['BTC_DAILY_AMOUNT_THRESHOLD'])

        self._post_ready_status(with_pubkey=True)

    def __send_request(self, func, args=None):
        if args is not None:
            res = func('localhost', 5001, 'admin', *args)
        else:
            res = func('localhost', 5001, 'admin')
        if type(res) is dict:
            return res

        # Retry when a token is expired.
        dap_client.login(host='localhost', port=5001, userid='admin', password=os.environ['RHPAM_ADMIN_PASSWORD'])
        if args is not None:
            return func('localhost', 5001, 'admin', *args)
        else:
            return func('localhost', 5001, 'admin')

    def update_txqueue_client(self):
        super().update_txqueue_client()
        self.__send_request(dap_client.update_db_password, ['txqueue'])
        electrum_client.update_txqueue_client()

    def verify(self, doc):
        if self.skip_verification:
            return dap_consts.DAP_VERIFICATION_SUCCEED, 'success', doc

        type = self._get_type(doc)
        method = self._get_method(doc)
        if type == dap_consts.APPROVAL_RESULT:
            if doc['result']:
                # Approved!!!
                print('Transaction approved by approvers!!!')
                return dap_consts.DAP_VERIFICATION_SUCCEED, 'success', doc['doc']
            else:
                # Rejected!!!
                print('Transaction rejected by approvers!!!')
                return dap_consts.DAP_VERIFICATION_FAIL, 'Rejected by approvers in {}'.format(self.serviceid), doc['doc']
        elif method == dap_consts.SIGN_METHOD:
            params = self._get_params(doc)
            if 'invoice' in params:
                # TODO: Lightning support
                return dap_consts.DAP_VERIFICATION_SUCCEED, 'success', doc

            userid  = params['userid']
            seedid  = params['seedid']
            tx      = params['transaction']
            inputs  = params['inputs']

            loaded = electrum_client.load_or_create_dap(userid=userid, seedid=seedid, tx=tx)
            if not loaded:
                raise Exception('Failed to load a wallet for {}'.format(userid))
            
            print('Validating a transaction')
            validated = electrum_client.validatetx(tx, userid, inputs)
            if not validated['result']:
                raise Exception('Transaction validation failure')

            try:
                amount = float(electrum_client.getamount(tx, userid)['result'])
            except Exception as e:
                print(str(e))
                raise Exception('Failed to retrieve a total amount to be sent')
            print('amount={}'.format(amount))

            try:
                daily_amount = float(electrum_client.getdailyamount(tx, userid)['result'])
            except Exception as e:
                print(str(e))
                raise Exception('Failed to retrieve a daily amount sent and to be sent')
            print('daily_amount={}'.format(daily_amount))

            print('Waiting for responses from approvers ...')
            res = self.__send_request(dap_client.create_approval, [
                userid,
                seedid,
                tx,
                amount,
                daily_amount,
                doc
            ])
            if not res:
                return dap_consts.DAP_VERIFICATION_FAIL, 'Failed to create approval requests', doc
            return dap_consts.DAP_VERIFICATION_WAIT, 'wait', doc

            # rules = []
            # if amount > self.btc_amount_threshold:
            #     rules.append(approval_table.RULE3['id'])
            # if daily_amount > self.btc_daily_amount_threshold:
            #     rules.append(approval_table.RULE4['id'])
            # if rules:
            #     print('Waiting for responses from approvers ...')
            #     res = self.__send_request(dap_client.create_approval, [
            #         userid,
            #         seedid,
            #         tx,
            #         amount,
            #         daily_amount,
            #         rules,
            #         doc
            #     ])
            #     if not res:
            #         return dap_consts.DAP_VERIFICATION_FAIL, 'Failed to create approval requests', doc
            #     return dap_consts.DAP_VERIFICATION_WAIT, 'wait', doc

        return dap_consts.DAP_VERIFICATION_SUCCEED, 'success', doc

def run(reboot=False):
    AuthorizationPolicyService(reboot=reboot).run()
