from concurrent.futures import process
from curses.ascii import isdigit
import time, dap_client, os
from dap_util import electrum_client

table = {}

kie_host = 'localhost'
kie_port = '8443'

class TransactionRecord:

    def __init__(self, userid, seedid, amount, daily_amount, psbt, doc):
        self.userid = userid
        self.seedid = seedid
        self.amount = amount
        self.daily_amount = daily_amount
        self.psbt = psbt
        self.doc = doc
        self.process_instance_id = self.__send_request(dap_client.create_ap_instance_rhpam, [userid, amount, daily_amount, psbt])

        # Check if this process instance has completed without any approval
        process_instance = self.__send_request(dap_client.get_ap_instance_rhpam, [self.process_instance_id])
        print(process_instance)
        amount_approved = False
        daily_amount_approved = False
        for item in process_instance['variable-instance']:
            if item['name'] == 'amount_approved':
                if item['value'] == 'true':
                    amount_approved = True
                else:
                    break
            elif item['name'] == 'daily_amount_approved':
                if item['value'] == 'true':
                    daily_amount_approved = True
                else:
                    break
        self.processed = amount_approved and daily_amount_approved

    def __send_request(self, func, args=None):
        if args is not None:
            res = func(kie_host, kie_port, 'admin', *args)
        else:
            res = func(kie_host, kie_port, 'admin')
        if (type(res) is str and res.isdigit()) or type(res) is dict:
            return res

        # Retry when a token is expired.
        dap_client.login_kie(host=kie_host, port=kie_port, userid='admin', password=os.environ['RHPAM_ADMIN_PASSWORD'])
        if args is not None:
            return func(kie_host, kie_port, 'admin', *args)
        else:
            return func(kie_host, kie_port, 'admin')

def create_transaction_record(psbt, userid, seedid, amount, daily_amount, doc):
    record = TransactionRecord(userid, seedid, amount, daily_amount, psbt, doc)
    table[record.process_instance_id] = record
    print('Created an approval process for process_instance_id={} processed={}'.format(record.process_instance_id, record.processed))
    return record

def get_record(process_instance_id):
    if process_instance_id not in table:
        return None
    return table[process_instance_id]

def get_user_transactions(userid, hours):
    psbts = []
    seedid = None
    tx = None
    for process_instance_id, record in table.items():
        if record.userid == userid:
            psbts.append(record.psbt)
            seedid = record.seedid
            tx = record.psbt
    if seedid and tx:
        electrum_client.load_or_create_dap(userid=userid, seedid=seedid, tx=tx)
        return psbts, electrum_client.gettransactions(hours, userid)['result']
    return psbts, []

