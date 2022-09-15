# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import os
from polling_service import PollingService
import dap_consts, electrum_client

class FraudDetectionPolicyService(PollingService):

    def __init__(self, reboot = False):
        super().__init__(
            serviceid=dap_consts.FRAUD_DETECTION_POLICY_SERVICE,
            query={
                '$or': [{'request.type': {'$eq': x}} for x in dap_consts.REQUEST_TYPES],
                dap_consts.FRAUD_DETECTION_POLICY_SERVICE: {'$eq': None}
            },
            response=dap_consts.FRAUD_DETECTION_POLICY_SERVICE,
            reboot=reboot
        )

        self.btc_daily_txs_threshold = 3
        if 'BTC_DAILY_TXS_THRESHOLD' in os.environ:
            self.btc_daily_txs_threshold = int(os.environ['BTC_DAILY_TXS_THRESHOLD'])

        self.used_addresses = []

        self._post_ready_status(with_pubkey=True)

    def verify(self, doc):
        return dap_consts.DAP_VERIFICATION_SUCCEED, 'success', doc

    def verify(self, doc):
        if self.skip_verification:
            return dap_consts.DAP_VERIFICATION_SUCCEED, 'success', doc

        method = self._get_method(doc)
        '''
        if method == dap_consts.SIGN_METHOD:
            params = self._get_params(doc)
            if 'invoice' in params:
                # TODO: Lightning support
                return dap_consts.DAP_VERIFICATION_SUCCEED, 'success', doc

            userid  = params['userid']
            seedid  = params['seedid']
            tx      = params['transaction']

            loaded = electrum_client.load_or_create_dap(userid=userid, seedid=seedid, tx=tx)
            if not loaded:
                raise Exception('Failed to load a wallet for {}'.format(userid))

            num_daily_txs = len(electrum_client.gettransactions(24, userid)['result'])
            if num_daily_txs > self.btc_daily_txs_threshold:
                return dap_consts.DAP_VERIFICATION_FAIL, 'Number of daily transactions {} exceeds a threshold in {}'.format(num_daily_txs, self.serviceid), doc
            print('Number of daily transactions {} is less than a threshold'.format(num_daily_txs))

            psbt = electrum_client.desrialize(tx)['result']
            for output in psbt['outputs']:
                address = output['address']
                if address in self.used_addresses:
                    return dap_consts.DAP_VERIFICATION_FAIL, 'Your request is rejected in {}. You cannot send bitcoins to the same address {} multiple times. Please use a different address.'.format(self.serviceid, address), doc
                self.used_addresses.append(address)
        '''
        return dap_consts.DAP_VERIFICATION_SUCCEED, 'success', doc

def run(reboot=False):
    FraudDetectionPolicyService(reboot=reboot).run()
