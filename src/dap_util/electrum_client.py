#!/usr/bin/env python3

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import os, argparse, json, sys
from pprint import pprint
from urllib import request
from urllib.error import HTTPError
import warnings

from dap_client import update_db_password

warnings.filterwarnings("ignore", category=UserWarning, module='urllib')

if 'ELECTRUM_USER' not in os.environ or 'ELECTRUM_PASSWORD' not in os.environ or 'ELECTRUM_DATA' not in os.environ:
    raise Exception('Environment variable ELECTRUM_USER, ELECTRUM_PASSWORD, and ELECTRUM_DATA should be set')

ELECTRUM_USER = os.environ['ELECTRUM_USER']
ELECTRUM_PASSWORD = os.environ['ELECTRUM_PASSWORD']
ELECTRUM_DATA = os.environ['ELECTRUM_DATA']
URL = 'http://127.0.0.1:7777'
HEADERS = {
    'Content-Type': 'application/json'
}

WALLETS_DIR = ELECTRUM_DATA + '/wallets'
if not os.path.exists(WALLETS_DIR):
    os.mkdir(WALLETS_DIR)

password_mgr = request.HTTPPasswordMgrWithDefaultRealm()
password_mgr.add_password(None, URL, ELECTRUM_USER, ELECTRUM_PASSWORD)
handler = request.HTTPBasicAuthHandler(password_mgr)
opener = request.build_opener(handler)
request.install_opener(opener)

def _print_request(req):
    print('-----------------------------')
    print('Sending the following request')
    print('URL={}'.format(req.get_full_url()))
    print('Method={}'.format(req.get_method()))
    print('Header')
    pprint(req.headers)
    print('Body')
    pprint(req.data.decode('utf-8'))
    print()

def _send_request(payload):
    req = request.Request(URL, json.dumps(payload).encode(), HEADERS)
    _print_request(req)
    with request.urlopen(req) as res:
        json_data = json.load(res)
        print('-----------------------------')
        print('Getting the following response')
        pprint(json_data)
        print()
        return json_data

    return None

def _create_command(method, params):
    return {
        'jsonrpc': '2.0',
        'id': 'curltext',
        'method': method,
        'params': params
    }

def create_dap(userid, password, seedid, watch_only, host, port, seed_type, otp):
    params = {
        'userid': userid,
        'password': password,
        'wallet_path': WALLETS_DIR + '/' + userid,
        'seedid': seedid,
        'watch_only': watch_only,
        'host': host,
        'port': port,
        'seed_type': seed_type,
        'otp': otp
    }
    return _send_request(_create_command('create_dap', params))

def create_dap_(args):
    return create_dap(args.userid, args.password, args.seedid, args.watch_only, args.host, args.port, args.seed_type, args.otp)

def create_bip32hsm(args):
    params = {
        'password': args.password,
        'wallet_path': WALLETS_DIR + '/' + args.userid
    }
    return _send_request(_create_command('create_bip32hsm', params))

def load_wallet(userid, otp):
    params = {
        'wallet_path': WALLETS_DIR + '/' + userid,
        'otp': otp
    }
    return _send_request(_create_command('load_wallet', params))

def load_wallet_(args):
    return load_wallet(args.userid, args.otp)

def getbalance(args):
    params = {
        'wallet': WALLETS_DIR + '/' + args.userid
    }
    return _send_request(_create_command('getbalance', params))

def getunusedaddress(args):
    params = {
        'wallet': WALLETS_DIR + '/' + args.userid
    }
    return _send_request(_create_command('getunusedaddress', params))

def payto(args):
    params = {
        'destination': args.destination,
        'amount': args.amount,
        'wallet': WALLETS_DIR + '/' + args.userid,
        'unsigned': args.unsigned,
        'sync': args.sync,
        'psbthex': True
    }

    json_data = _send_request(_create_command('payto', params))
    result = json_data['result']
    if args.broadcast == True and args.sync == True and args.unsigned == False and result['status'] == 'success':
        print('Broadcasting')
        broadcast_params = {
            'tx': result['transactionid']
        }
        return _send_request(_create_command('broadcast', broadcast_params))
    else:
        print('No broadcasting')
        return json_data

def getsignedtx(args):
    params = {
        'tx': args.tx,
        'wallet': WALLETS_DIR + '/' + args.userid,
    }

    json_data = _send_request(_create_command('getsignedtx', params))
    result = json_data['result']
    if args.broadcast == True and result['status'] == 'success':
        print('Broadcasting')
        broadcast_params = {
            'tx': result['transactionid']
        }
        return _send_request(_create_command('broadcast', broadcast_params))
    else:
        print('No broadcasting')
        return json_data

def broadcast(args):
    params = {
        'tx': args.tx,
    }

    return _send_request(_create_command('broadcast', params))

def validatetx(tx, userid, inputs):
    params = {
        'tx': tx,
        'wallet': WALLETS_DIR + '/' + userid,
        'inputs': inputs,
    }

    return _send_request(_create_command('validatetx', params))

def validatetx_(args):
    with open(args.inputs, mode='rt', encoding='utf-8') as file:
        inputs = json.load(file)
        pprint(inputs)
        return validatetx(args.tx, args.userid, inputs)

def is_segwit(tx):
    params = {
        'tx': tx
    }

    return _send_request(_create_command('is_segwit', params))

def is_segwit_(args):
    return is_segwit(args.tx)

def getamount(tx, userid):
    params = {
        'tx': tx,
        'wallet': WALLETS_DIR + '/' + userid,
    }

    return _send_request(_create_command('getamount', params))

def getamount_(args):
    return getamount(args.tx, args.userid)

def getdailyamount(tx, userid):
    params = {
        'tx': tx,
        'wallet': WALLETS_DIR + '/' + userid,
    }

    return _send_request(_create_command('getdailyamount', params))

def getdailyamount_(args):
    return getdailyamount(args.tx, args.userid)

def gettransactions(hours, userid):
    params = {
        'hours': hours,
        'wallet': WALLETS_DIR + '/' + userid,
    }

    return _send_request(_create_command('gettransactions', params))

def gettransactions_(args):
    return gettransactions(args.hours, args.userid)

def desrialize(tx):
    params = {
        'tx': tx
    }

    return _send_request(_create_command('deserialize', params))

def deserialize_(args):
    return desrialize(args.tx)

def load_or_create_dap(userid, seedid, tx):
    loaded = load_wallet(userid=userid)
    if not loaded['result']:
        print('Creating a wallet for {}'.format(userid))
        seed_type = 'standard'
        if is_segwit(tx)['result']:
            seed_type = 'segwit'
        create_dap(userid=userid, password=None, seedid=seedid, watch_only=True, host='localhost', port=5000, seed_type=seed_type, otp=None)
        loaded = load_wallet(userid=userid, otp=None)
        if not loaded['result']:
            return False
    return True

def update_txqueue_client():
    return _send_request(_create_command('update_txqueue_client', {}))

def update_txqueue_client_():
    return update_txqueue_client()

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='commands')

    create_dap_parser = subparsers.add_parser('create_dap', help='Create a DAP wallet')
    create_dap_parser.add_argument('userid')
    create_dap_parser.add_argument('password')
    create_dap_parser.add_argument('--seedid', default=None)
    create_dap_parser.add_argument('--watch_only', action='store_true')
    create_dap_parser.add_argument('--host', default='localhost')
    create_dap_parser.add_argument('--port', default=5000)
    create_dap_parser.add_argument('--seed_type', default='standard')
    create_dap_parser.add_argument('--otp', default=None)
    create_dap_parser.set_defaults(func=create_dap_)

    create_bip32hsm_parser = subparsers.add_parser('create_bip32hsm', help='Create a bip32hsm wallet')
    create_bip32hsm_parser.add_argument('userid')
    create_bip32hsm_parser.add_argument('password')
    create_bip32hsm_parser.set_defaults(func=create_bip32hsm)

    load_wallet_parser = subparsers.add_parser('load_wallet', help='Load a wallet')
    load_wallet_parser.add_argument('userid')
    load_wallet_parser.add_argument('--otp', default=None)
    load_wallet_parser.set_defaults(func=load_wallet_)

    getbalance_parser = subparsers.add_parser('getbalance', help='Get balance')
    getbalance_parser.add_argument('userid')
    getbalance_parser.set_defaults(func=getbalance)

    getunusedaddress_parser = subparsers.add_parser('getunusedaddress', help='Get a un-used address')
    getunusedaddress_parser.add_argument('userid')
    getunusedaddress_parser.set_defaults(func=getunusedaddress)

    payto_parser = subparsers.add_parser('payto', help='Send an amount of bitconins to a destination address')
    payto_parser.add_argument('userid')
    payto_parser.add_argument('destination')
    payto_parser.add_argument('amount')
    payto_parser.add_argument('--unsigned', action='store_true')
    payto_parser.add_argument('--broadcast', action='store_true')
    payto_parser.add_argument('--sync', action='store_true')
    payto_parser.set_defaults(func=payto)

    add_sign_parser = subparsers.add_parser('getsignedtx', help='Get a signed transaction')
    add_sign_parser.add_argument('userid')
    add_sign_parser.add_argument('tx')
    add_sign_parser.add_argument('--broadcast', action='store_true')
    add_sign_parser.set_defaults(func=getsignedtx)

    broadcast_parser = subparsers.add_parser('broadcast', help='Broadcast a transaction')
    broadcast_parser.add_argument('userid')
    broadcast_parser.add_argument('tx')
    broadcast_parser.set_defaults(func=broadcast)

    validate_tx_parser = subparsers.add_parser('validatetx', help='Validate a PSBT transaction with hash values to be signed')
    validate_tx_parser.add_argument('userid')
    validate_tx_parser.add_argument('tx')
    validate_tx_parser.add_argument('inputs')
    validate_tx_parser.set_defaults(func=validatetx_)

    is_segwit_parser = subparsers.add_parser('is_segwit', help='Return True if this transaction is initiated from a segwit wallet')
    is_segwit_parser.add_argument('tx')
    is_segwit_parser.set_defaults(func=is_segwit_)

    get_amount_parser = subparsers.add_parser('getamount', help='Get the total amount to be sent from a PSBT transaction')
    get_amount_parser.add_argument('userid')
    get_amount_parser.add_argument('tx')
    get_amount_parser.set_defaults(func=getamount_)

    get_daily_amount_parser = subparsers.add_parser('getdailyamount', help='Get the total amount within a day including an amount in a given PSBT transaction')
    get_daily_amount_parser.add_argument('userid')
    get_daily_amount_parser.add_argument('tx')
    get_daily_amount_parser.set_defaults(func=getdailyamount_)

    get_transactions_parser = subparsers.add_parser('gettransactions', help='Get transactions within the specified hours')
    get_transactions_parser.add_argument('userid')
    get_transactions_parser.add_argument('hours')
    get_transactions_parser.set_defaults(func=gettransactions_)

    deserialize_parser = subparsers.add_parser('deserialize', help='Get transactions within the specified hours')
    deserialize_parser.add_argument('userid')
    deserialize_parser.add_argument('tx')
    deserialize_parser.set_defaults(func=deserialize_)

    update_txqueue_client_parser = subparsers.add_parser('update_txqueue_client', help='Update a txqueue client')
    update_txqueue_client_parser.add_argument('userid')
    update_txqueue_client_parser.set_defaults(func=update_txqueue_client_)

    args = parser.parse_args()
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.parse_args(['-h'])
