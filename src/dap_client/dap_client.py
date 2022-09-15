#!/usr/bin/env python3

# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

import os, argparse, json, ssl, copy, logging, sys, lxml.html, time
from filters import JsonFilter, StringFilter
from urllib.parse import quote
from pprint import pprint
from urllib import request
from urllib.error import HTTPError, URLError

URL = 'https://localhost:5000'
if 'DAP_URL' in os.environ:
    URL = os.environ['DAP_URL']

HEADERS = {
    'Content-Type': 'application/json'
}

SSL_CONTEXT = ssl.SSLContext()

logger = logging.getLogger(__name__)
logger.addFilter(JsonFilter(['password']))

def _print_request(req):
    logger.info(' -----------------------------')
    logger.info(' Sending the following request')
    logger.info(' URL: {}'.format(req.get_full_url()))
    logger.info(' Method: {}'.format(req.get_method()))
    logger.info(' Header')
    logger.info(' {}'.format(json.dumps(req.headers, indent=4)))
    logger.info(' Body')
    logger.info(' {}'.format(json.dumps(json.loads(req.data.decode('utf-8')), indent=4)))

def _send_request(host, port, path, payload, token=None, method='POST', isJSON=True):
    url = 'https://' + host + ':' + str(port) + path
    headers = HEADERS
    if token is not None:
        headers = copy.deepcopy(HEADERS)
        if 'access_token' in token:
            headers['Authorization'] = 'Bearer ' + token['access_token']
        if 'session' in token and 'oidc_id_token' in token:
            headers['Cookie'] = 'session=' + token['session'] + '; oidc_id_token=' + token['oidc_id_token']
        if 'JSESSIONID' in token and 'OAuth_Token_Request_State' in token:
            headers['Cookie'] = 'JSESSIONID=' + token['JSESSIONID'] + '; OAuth_Token_Request_State=' + token['OAuth_Token_Request_State']
    req = request.Request(url, json.dumps(payload).encode(), headers, method=method)
    _print_request(req)
    try:
        with request.urlopen(req, context=SSL_CONTEXT) as res:
            if isJSON:
                json_data = json.load(res)
                logger.info(' -----------------------------')
                logger.info(' Getting the following response')
                logger.info(' {}'.format(json.dumps(json_data, indent=4)))
                return json_data
            else:
                data = res.read().decode()
                print(data)
                return data
    except HTTPError as e:
        err = e.read().decode('utf-8')
        print('HTTP error: {}'.format(e.code))
        print(err)
        return err
    except URLError as e:
        print(str(e))
        return str(e)
    return None

TMPDIR = '.dap.tmp'

def _tmp_file_name(userid, type):
    if not os.path.isdir(TMPDIR):
        os.mkdir(TMPDIR)

    if type == 'token':
        return TMPDIR + '/' + userid + '.token.json'
    elif type == 'walletid':
        return TMPDIR + '/' + userid + '.walletid'
    elif type == 'pubkey':
        return TMPDIR + '/' + userid + '.pubkey'
    return None

def _store_tmp_data(userid, tmp_data, type):
    file = _tmp_file_name(userid, type)
    if file is None:
        return
    with open(file, mode='w') as f:
        f.write(tmp_data)
        f.close()

def _remove_tmp_data(userid, type):
    file = _tmp_file_name(userid, type)
    if file is None:
        return
    if os.path.exists(file):
        os.remove(file)

def _read_tmp_data(userid, type):
    file = _tmp_file_name(userid, type)
    if file is None:
        return None
    try:
        with open(file) as f:
            if type == 'token':
                data = json.load(f)
            else:
                data = f.read()
            f.close()
            return data
    except Exception as e:
        print(e)
    return None

def _get_token(userid):
    token = _read_tmp_data(userid, 'token')
    return token

def _get_seedid(userid, seedid):
    if seedid is not None:
        return seedid
    seedid = _read_tmp_data(userid, 'seedid')
    if seedid is None:
        raise Exception('Cannot find seedid for ' + userid)
    return seedid

def _get_pubkey(serviceid):
    data = _read_tmp_data(serviceid, 'pubkey')
    if data is None:
        return None, None
    json_data = json.loads(data)
    return json_data['pubkey'], json_data['pubkey_hmac']

def _get_pubkeys():
    ap_pubkey, ap_hmac = _get_pubkey('authorization_policy_service')
    fdp_pubkey, fdp_hmac = _get_pubkey('fraud_detection_policy_service')
    tap_pubkey, tap_hmac = _get_pubkey('transaction_approval_policy_service')
    return {
        'pubkeys': {
            'authorization_policy_service': ap_pubkey,
            'fraud_detection_policy_service': fdp_pubkey,
            'transaction_approval_policy_service': tap_pubkey
        },
        'hmacs': {
            'authorization_policy_service': ap_hmac,
            'fraud_detection_policy_service': fdp_hmac,
            'transaction_approval_policy_service': tap_hmac
        }
    }

def service_status(host, port, userid, serviceid):
    res = _send_request(host=host,
                        port=port,
                        path='/admin/service/' + serviceid, 
                        payload={},
                        token=_get_token(userid),
                        method='GET')
    if type(res) is dict:
        _store_tmp_data(serviceid, json.dumps(res), 'pubkey')
    return res

def service_status_(args):
    return service_status(args.host, args.port, args.userid, args.serviceid)

def service_statues(host, port, userid):
    for serviceid in ['authorization_policy_service', 'fraud_detection_policy_service', 'transaction_approval_policy_service']:
        res = _send_request(host=host,
                            port=port,
                            path='/admin/service/' + serviceid, 
                            payload={},
                            token=_get_token(userid),
                            method='GET')
        if type(res) is dict:
            print('Storing {} public key'.format(serviceid))
            _store_tmp_data(serviceid, json.dumps(res), 'pubkey')
        else:
            print('{} is not ready yet or the status is already retrieved.'.format(serviceid))
    return 'ok'

def service_statuses_(args):
    return service_statues(args.host, args.port, args.userid)

def create_seed(host, port, userid):
    res = _send_request(host=host,
                        port=port,
                        path='/seeds/create', 
                        payload=_get_pubkeys(),
                        token=_get_token(userid),
                        method='POST')
    if type(res) is dict:
        _store_tmp_data(userid, res['seedid'], 'seedid')
    return res

def create_seed_(args):
    return create_seed(args.host, args.port, args.userid)

def query_seed(host, port, userid, seedid):
    res = _send_request(host=host,
                        port=port,
                        path='/seeds/' + seedid, 
                        payload={},
                        token=_get_token(userid),
                        method='GET')
    return res

def query_seed_(args):
    return query_seed(args.host, args.port, args.userid, args.seedid)

def delete_seed(host, port, userid, seedid):
    return _send_request(host=host,
                         port=port,
                         path='/seeds/' + seedid, 
                         payload={}, 
                         token = _get_token(userid), 
                         method='DELETE')

def delete_seed_(args):
    return delete_seed(args.host, args.port, args.userid, args.seedid)

def derive_pubkey(host, port, userid, seedid, bip32path):
    bip32path = quote(bip32path, safe='')
    return _send_request(host=host,
                         port=port,
                         path='/seeds/' + seedid + '/pubkeys/' + bip32path,
                         payload={},
                         token = _get_token(userid),
                         method='POST')

def derive_pubkey_(args):
    return derive_pubkey(args.host, args.port, args.userid, args.seedid, args.bip32path)

def sign(host, port, userid, seedid, payload):
    return _send_request(host=host,
                         port=port,
                         path='/seeds/' + seedid + '/sign',
                         payload=payload,
                         token = _get_token(userid),
                         method='POST')

def sign_(args):
    with open(args.json_file, mode='rt', encoding='utf-8') as file:
        payload = json.load(file)
        return sign(args.host, args.port, args.userid, args.seedid, payload)

def sign_request(host, port, userid, seedid, payload):
    return _send_request(host=host,
                         port=port,
                         path='/seeds/' + seedid + '/sign/request',
                         payload=payload,
                         token = _get_token(userid),
                         method='POST')

def sign_request_(args):
    with open(args.json_file, mode='rt', encoding='utf-8') as file:
        payload = json.load(file)
        return sign_request(args.host, args.port, args.userid, args.seedid, payload)

def sign_result(host, port, userid, seedid, payload):
    return _send_request(host=host,
                         port=port,
                         path='/seeds/' + seedid + '/sign/result',
                         payload=payload,
                         token = _get_token(userid),
                         method='POST')

def sign_result_(args):
    with open(args.json_file, mode='rt', encoding='utf-8') as file:
        payload = json.load(file)
        return sign_result(args.host, args.port, args.userid, args.seedid, payload)

def update_ss_keys(host, port, userid):
    return _send_request(host=host,
                         port=port,
                         path='/admin/updatesskeys',
                         payload={},
                         token = _get_token(userid),
                         method='POST')

def update_ss_keys_(args):
    return update_ss_keys(args.host, args.port, args.userid)

def update_ps_keys(host, port, userid, serviceid):
    return _send_request(host=host,
                         port=port,
                         path='/admin/updatepskeys/' + serviceid,
                         payload={},
                         token = _get_token(userid),
                         method='POST')

def update_ps_keys_(args):
    return update_ps_keys(args.host, args.port, args.userid, args.serviceid)

def update_db_password(host, port, userid, db):
     return _send_request(host=host,
                         port=port,
                         path='/admin/dbs/' + db,
                         payload={},
                         token = _get_token(userid),
                         method='POST')

def update_db_password_(args):
    return update_db_password(args.host, args.port, args.userid, args.db)

def create_approval(host, port, userid, sender, seedid, psbt, amount, daily_amount, doc):
    payload = {
        'userid': sender,
        'seedid': seedid,
        'psbt': psbt,
        'amount': amount,
        'daily_amount': daily_amount,
        'doc': doc
    }
    return _send_request(host=host,
                         port=port,
                         path='/admin/approval',
                         payload=payload,
                         token = _get_token(userid),
                         method='POST')

def create_approval_(args):
    print(args.doc)
    return create_approval(args.host, args.port, args.userid, args.sender, args.seedid, args.psbt, args.amount, args.daily_amount, args.doc)

def transactions(host, port, userid):
    return _send_request(host=host,
                         port=port,
                         path='/transactions',
                         payload={},
                         token = _get_token(userid),
                         method='GET')

def transactions_(args):
    return transactions(args.host, args.port, args.userid)

def transaction_details(host, port, userid, tx):
    return _send_request(host=host,
                         port=port,
                         path='/transactions/' + tx,
                         payload={},
                         token = _get_token(userid),
                         method='GET')

def transaction_details_(args):
    return transaction_details(args.host, args.port, args.userid, args.tx)

def approve(host, port, userid, tx, ruleid, approval):
    payload = {
        'ruleid': ruleid,
        'approval': approval
    }
    return _send_request(host=host,
                         port=port,
                         path='/transactions/' + tx,
                         payload=payload,
                         token = _get_token(userid),
                         method='PATCH')

def approve_(args):
    return approve(args.host, args.port, args.userid, args.tx, args.ruleid, True)

def reject_(args):
    return approve(args.host, args.port, args.userid, args.tx, args.ruleid, False)

def user_transactions(host, port, userid, sender, hours):
    return _send_request(host=host,
                         port=port,
                         path='/users/' + sender + '/transactions/hours/' + hours,
                         payload={},
                         token = _get_token(userid),
                         method='GET')

def user_transactions_(args):
    return user_transactions(args.host, args.port, args.userid, args.sender, args.hours)

def admin_create_seed(host, port, userid, seed, owner):
    res = _send_request(host=host,
                        port=port,
                        path='/admin/createseed', 
                        payload={'seed': seed, 'userid': owner},
                        token=_get_token(userid),
                        method='POST')
    if type(res) is dict:
        _store_tmp_data(userid, res['seedid'], 'seedid')
    return res

def admin_create_seed_(args):
    return admin_create_seed(args.host, args.port, args.userid, args.seed, args.owner)

def cleanup_txqueue(host, port, userid):
    res = _send_request(host=host,
                        port=port,
                        path='/admin/dbs/txqueue/cleanup',
                        payload={},
                        token=_get_token(userid),
                        method='POST')
    return res

def cleanup_txqueue_(args):
    return cleanup_txqueue(args.host, args.port, args.userid)

import requests, webbrowser, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def login(host, port, userid, password):
    url = 'https://' + host + ':' + str(port) + '/auth/login'
    session = requests.session()
    r = session.get(url, verify=False)
    root = lxml.html.fromstring(r.text)
    post_url = root.xpath('//form[@method="post"]')[0].action
    print('POST_URL=' + post_url)
    data = {'username': userid, 'password': password}
    try:
        r = session.post(post_url, data=data)
    except Exception as e:
        print(e)
        return
    _store_tmp_data(userid, r.text, 'token')
    json_data = json.loads(r.text)
    pprint(json_data)
    return json_data

def login_(args):
    return login(args.host, args.port, args.userid, args.password)

def login_2fa(host, port, userid, password, otp):
    url = 'https://' + host + ':' + str(port) + '/auth/login'
    session = requests.session()
    r = session.get(url, verify=False)
    root = lxml.html.fromstring(r.text)
    auth_url = root.xpath('//form[@method="post"]')[0].action
    print('AUTH_URL=' + auth_url)
    data = {'username': userid, 'password': password}
    try:
        r = session.post(auth_url, data=data)
    except Exception as e:
        print(e)
        return
    root = lxml.html.fromstring(r.text)
    otp_url = root.xpath('//form[@method="post"]')[0].action
    print('OTP_URL=' + otp_url)
    data = {'otp': otp}
    try:
        r = session.post(otp_url, data=data)
    except Exception as e:
        print(e)
        return
    print(r.text)
    _store_tmp_data(userid, r.text, 'token')
    json_data = json.loads(r.text)
    pprint(json_data)
    return json_data

def login_2fa_(args):
    return login_2fa(args.host, args.port, args.userid, args.password, args.otp)

def logout(host, port, userid):
    # url = 'https://' + host + ':' + str(port) + '/auth/logout'
    # webbrowser.open(url=url)
    res = _send_request(host=host,
                    port=port,
                    path='/auth/logout',
                    payload={},
                    token=_get_token(userid),
                    method='GET')
    return ""

def logout_(args):
    return logout(args.host, args.port, args.userid)

def user(host, port, userid):
    res = _send_request(host=host,
                        port=port,
                        path='/auth/user',
                        payload={},
                        token=_get_token(userid),
                        method='POST')
    return res

def user_(args):
    return user(args.host, args.port, args.userid)

def approver(host, port, userid):
    res = _send_request(host=host,
                        port=port,
                        path='/auth/approver',
                        payload={},
                        token=_get_token(userid),
                        method='POST')
    return res

def approver_(args):
    return approver(args.host, args.port, args.userid)

def login_rhpam(host, port, userid, password):
    url = 'https://' + host + ':' + str(port) + '/business-central'
    session = requests.session()
    r = session.get(url, verify=False)
    root = lxml.html.fromstring(r.text)
    post_url = root.xpath('//form[@method="post"]')[0].action
    print('POST_URL=' + post_url)
    data = {'username': userid, 'password': password}
    r = session.post(post_url, data=data)
    cookie = r.request.headers['Cookie']
    cookie = cookie.split('; ')
    token = {}
    token['JSESSIONID'] = cookie[0].strip('JSESSIONID=')
    token['OAuth_Token_Request_State'] = cookie[1].strip('OAuth_Token_Request_State=')
    _store_tmp_data(userid, json.dumps(token), 'token')
    pprint(token)
    return json.dumps(token)

def login_rhpam_(args):
    return login_rhpam(args.host, args.port, args.userid, args.password)

def wait_rhpam(host, port):
    url = 'https://' + host + ':' + port + '/business-central'
    res = None
    while True:
        print('Checking if RHPAM server launched')
        session = requests.session()
        try:
            res = session.get(url, verify=False)
        except Exception as e:
            print('RHPAM server has not launched yet')
            print(e)
            time.sleep(10)
            continue
        break
    return res

def wait_rhpam_(args):
    return wait_rhpam(args.host, args.port)

def spaces_rhpam(host, port, userid):
    res = _send_request(host=host,
                        port=port,
                        path='/business-central/rest/spaces',
                        payload={},
                        token=_get_token(userid),
                        method="GET")
    return res

def spaces_rhpam_(args):
    return spaces_rhpam(args.host, args.port, args.userid)

def create_space_rhpam(host, port, userid, space):
    payload = {
        'name': space,
        'owner': userid,
        'defaultGroupId': 'com.myspace'
    }
    res = _send_request(host=host,
                        port=port,
                        path='/business-central/rest/spaces',
                        payload=payload,
                        token=_get_token(userid),
                        method="POST")
    return res

def create_space_rhpam_(args):
    return create_space_rhpam(args.host, args.port, args.userid, args.space)

def projects_rhpam(host, port, userid, space):
    res = _send_request(host=host,
                        port=port,
                        path='/business-central/rest/spaces/' + space + '/projects', 
                        payload={},
                        token=_get_token(userid),
                        method="GET")
    return res

def projects_rhpam_(args):
    return projects_rhpam(args.host, args.port, args.userid, args.space)

def create_project_rhpam(host, port, userid, space, project):
    payload = {
        'name': project,
        'groupId': 'com.myspace',
        'version': '1.0.0-SNAPSHOT',
        'description': project
    }
    res = _send_request(host=host,
                        port=port,
                        path='/business-central/rest/spaces/' + space + '/projects',
                        payload=payload,
                        token=_get_token(userid),
                        method="POST")
    return res

def create_project_rhpam_(args):
    return create_project_rhpam(args.host, args.port, args.userid, args.space, args.project)

def git_clone_rhpam(host, port, userid, space, project, url):
    payload = {
        'name': project,
        'gitURL': url
    }
    res = _send_request(host=host,
                        port=port,
                        path='/business-central/rest/spaces/' + space + '/git/clone', 
                        payload=payload,
                        token=_get_token(userid),
                        method="POST")
    return res

def git_clone_rhpam_(args):
    return git_clone_rhpam(args.host, args.port, args.userid, args.space, args.project, args.url)

def build_project_rhpam(host, port, userid, space, project):
    res = _send_request(host=host,
                    port=port,
                    path='/business-central/rest/spaces/' + space + '/projects/' + project + '/maven/compile',
                    payload={},
                    token=_get_token(userid),
                    method="POST")

    res = _send_request(host=host,
                    port=port,
                    path='/business-central/rest/spaces/' + space + '/projects/' + project + '/maven/deploy',
                    payload={},
                    token=_get_token(userid),
                    method="POST")
    return res

def build_project_rhpam_(args):
    return build_project_rhpam(args.host, args.port, args.userid, args.space, args.project)

def deploy_project_rhpam(host, port, userid, project, group, version):
    payload = {
        "container-id" : project,
        "container-name" : project,
        "release-id" : {
            "group-id" : group,
            "artifact-id" : project,
            "version" : version
        },
        "configuration" : {
            "RULE" : {
            "org.kie.server.controller.api.model.spec.RuleConfig" : {
                "pollInterval" : "",
                "scannerStatus" : "STOPPED"
            }
            },
            "PROCESS" : {
            "org.kie.server.controller.api.model.spec.ProcessConfig" : {
                "runtimeStrategy" : "SINGLETON",
                "kbase" : "",
                "ksession" : "",
                "mergeMode" : "MERGE_COLLECTIONS"
            }
            }
        }
    }
    res = _send_request(host=host,
                        port=port,
                        path='/business-central/rest/controller/management/servers/default-kieserver/containers/' + project,
                        payload=payload,
                        token=_get_token(userid),
                        method="PUT",
                        isJSON=False)
    return res

def deploy_project_rhpam_(args):
    return deploy_project_rhpam(args.host, args.port, args.userid, args.project, args.group, args.version)

def containers_rhpam(host, port, userid):
    res = _send_request(host=host,
                        port=port,
                        path='/business-central/rest/controller/management/servers/default-kieserver/containers/',
                        payload={},
                        token=_get_token(userid),
                        method="GET")
    return res

def containers_rhpam_(args):
    return containers_rhpam(args.host, args.port, args.userid)

def start_container_rhpam(host, port, userid, container):
    res = _send_request(host=host,
                        port=port,
                        path='/business-central/rest/controller/management/servers/default-kieserver/containers/' + container + '/status/started',
                        payload={},
                        token=_get_token(userid),
                        method="POST",
                        isJSON=False)
    return res

def start_container_rhpam_(args):
    return start_container_rhpam(args.host, args.port, args.userid, args.container)

def login_kie(host, port, userid, password):
    url = 'https://' + host + ':' + str(port) + '/kie-server/services/rest/server'
    session = requests.session()
    r = session.get(url, verify=False)
    root = lxml.html.fromstring(r.text)
    post_url = root.xpath('//form[@method="post"]')[0].action
    data = {'username': userid, 'password': password}
    r = session.post(post_url, data=data)
    cookie = r.request.headers['Cookie']
    cookie = cookie.split('; ')
    token = {}
    token['JSESSIONID'] = cookie[0].strip('JSESSIONID=')
    token['OAuth_Token_Request_State'] = cookie[1].strip('OAuth_Token_Request_State=')
    _store_tmp_data(userid, json.dumps(token), 'token')
    print(post_url)
    pprint(token)
    return json.dumps(token)

def login_kie_(args):
    return login_kie(args.host, args.port, args.userid, args.password)
    
def create_ap_instance_rhpam(host, port, userid, payer, amount, dailyamount, psbt):
    payload = {
        "btctx": {
            "com.myspace.authorization_policy.BTCTransaction": {
                "payer": payer,
                "amount": amount,
                "dailyamount": dailyamount,
                "psbt": psbt
            }
        }
    }
    res = _send_request(host=host,
                        port=port,
                        path='/kie-server/services/rest/server/containers/Authorization_Policy/processes/Authorization_Policy.BTCTransactionApprovalProcess/instances',
                        payload=payload,
                        token=_get_token(userid),
                        method="POST",
                        isJSON=False)
    return res

def create_ap_instance_rhpam_(args):
    return create_ap_instance_rhpam(args.host, args.port, args.userid, args.payer, args.amount, args.dailyamount, args.psbt)

def get_ap_instances_rhpam(host, port, userid):
    res = _send_request(host=host,
                        port=port,
                        path='/kie-server/services/rest/server/containers/Authorization_Policy/processes/instances',
                        payload={},
                        token=_get_token(userid),
                        method="GET")
    return res

def get_ap_instances_rhpam_(args):
    return get_ap_instances_rhpam(args.host, args.port, args.userid)

def get_ap_instance_rhpam(host, port, userid, id):
    res = _send_request(host=host,
                        port=port,
                        path='/kie-server/services/rest/server/containers/Authorization_Policy/processes/instances/' + str(id) + '/variables/instances',
                        payload={},
                        token=_get_token(userid),
                        method="GET")
    return res

def get_ap_instance_rhpam_(args):
    return get_ap_instance_rhpam(args.host, args.port, args.userid, args.id)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='localhost')
    parser.add_argument('--port', default='5000')
    parser.add_argument('--log', default='INFO')

    subparsers = parser.add_subparsers(title='commands')

    login_parser = subparsers.add_parser('login', help='Obtain an API token')
    login_parser.add_argument('userid')
    login_parser.add_argument('password')
    login_parser.set_defaults(func=login_)

    login_2fa_parser = subparsers.add_parser('login_2fa', help='Obtain an API token though 2-factor authentication')
    login_2fa_parser.add_argument('userid')
    login_2fa_parser.add_argument('password')
    login_2fa_parser.add_argument('otp')
    login_2fa_parser.set_defaults(func=login_2fa_)

    logout_parser = subparsers.add_parser('logout', help='login')
    logout_parser.add_argument('userid')
    logout_parser.set_defaults(func=logout_)

    service_status_parser = subparsers.add_parser('service_status', help='Qeury service status')
    service_status_parser.add_argument('userid')
    service_status_parser.add_argument('serviceid')
    service_status_parser.set_defaults(func=service_status_)

    service_statuses_parser = subparsers.add_parser('service_statuses', help='Query service statuses')
    service_statuses_parser.add_argument('userid')
    service_statuses_parser.set_defaults(func=service_statuses_)

    create_seed_parser = subparsers.add_parser('create_seed', help='Create a seed')
    create_seed_parser.add_argument('userid')
    create_seed_parser.set_defaults(func=create_seed_)

    query_seed_parser = subparsers.add_parser('query_seed', help='Query if a seedid exists')
    query_seed_parser.add_argument('userid')
    query_seed_parser.add_argument('seedid')
    query_seed_parser.set_defaults(func=query_seed_)

    delete_seed_parser = subparsers.add_parser('delete_seed', help='Delete a seed')
    delete_seed_parser.add_argument('userid')
    delete_seed_parser.add_argument('seedid')
    delete_seed_parser.set_defaults(func=delete_seed_)

    derive_pubkey_parser = subparsers.add_parser('derive_pubkey', help='Derivbe a public key along with a bip32 derivation path')
    derive_pubkey_parser.add_argument('userid')
    derive_pubkey_parser.add_argument('seedid')
    derive_pubkey_parser.add_argument('bip32path')
    derive_pubkey_parser.set_defaults(func=derive_pubkey_)

    sign_parser = subparsers.add_parser('sign', help='Sign inputs in a transaction')
    sign_parser.add_argument('userid')
    sign_parser.add_argument('seedid')
    sign_parser.add_argument('json_file')
    sign_parser.set_defaults(func=sign_)

    sign_request_parser = subparsers.add_parser('sign_request', help='Send a request for signing a transaction')
    sign_request_parser.add_argument('userid')
    sign_request_parser.add_argument('seedid')
    sign_request_parser.add_argument('json_file')
    sign_request_parser.set_defaults(func=sign_request_)

    sign_result_parser = subparsers.add_parser('sign_result', help='Retrieve a signing result')
    sign_result_parser.add_argument('userid')
    sign_result_parser.add_argument('seedid')
    sign_result_parser.add_argument('json_file')
    sign_result_parser.set_defaults(func=sign_result_)

    update_ss_keys_parser = subparsers.add_parser('update_ss_keys', help='Update encryption keys on signing service')
    update_ss_keys_parser.add_argument('userid')
    update_ss_keys_parser.set_defaults(func=update_ss_keys_)

    update_ps_keys_parser = subparsers.add_parser('update_ps_keys', help='Update signing keys on policy service')
    update_ps_keys_parser.add_argument('userid')
    update_ps_keys_parser.add_argument('serviceid')
    update_ps_keys_parser.set_defaults(func=update_ps_keys_)

    update_db_password_parser = subparsers.add_parser('update_db_password', help='Update a password of a DBaaS instance')
    update_db_password_parser.add_argument('userid')
    update_db_password_parser.add_argument('db')
    update_db_password_parser.set_defaults(func=update_db_password_)

    create_approval_parser = subparsers.add_parser('create_approval', help='Create an approval request')
    create_approval_parser.add_argument('userid')
    create_approval_parser.add_argument('sender')
    create_approval_parser.add_argument('seedid')
    create_approval_parser.add_argument('psbt')
    create_approval_parser.add_argument('amount')
    create_approval_parser.add_argument('daily_amount')
    create_approval_parser.add_argument('doc')
    create_approval_parser.set_defaults(func=create_approval_)

    transactions_parser = subparsers.add_parser('list_txs', help='List transactions')
    transactions_parser.add_argument('userid')
    transactions_parser.set_defaults(func=transactions_)

    transaction_details_parser = subparsers.add_parser('tx_details', help='Retrieve transaction details')
    transaction_details_parser.add_argument('userid')
    transaction_details_parser.add_argument('tx')
    transaction_details_parser.set_defaults(func=transaction_details_)

    approve_parser = subparsers.add_parser('approve', help='Approve a transaction for a rule')
    approve_parser.add_argument('userid')
    approve_parser.add_argument('tx')
    approve_parser.add_argument('ruleid')
    approve_parser.set_defaults(func=approve_)

    reject_parser = subparsers.add_parser('reject', help='Reject a transaction for a rule')
    reject_parser.add_argument('userid')
    reject_parser.add_argument('tx')
    reject_parser.add_argument('ruleid')
    reject_parser.set_defaults(func=reject_)

    user_transactions_parser = subparsers.add_parser('user_txs', help='Get transactions for a user within the specified hours')
    user_transactions_parser.add_argument('userid')
    user_transactions_parser.add_argument('sender')
    user_transactions_parser.add_argument('hours', default=24)
    user_transactions_parser.set_defaults(func=user_transactions_)

    admin_create_seed_parser = subparsers.add_parser('admin_create_seed', help='Create a seed (only for testing)')
    admin_create_seed_parser.add_argument('userid')
    admin_create_seed_parser.add_argument('owner')
    admin_create_seed_parser.add_argument('seed')
    admin_create_seed_parser.set_defaults(func=admin_create_seed_)

    cleanup_txqueue_parser = subparsers.add_parser('cleanup_txqueue', help='Cleanup txqueue')
    cleanup_txqueue_parser.add_argument('userid')
    cleanup_txqueue_parser.set_defaults(func=cleanup_txqueue_)

    user_parser = subparsers.add_parser('user', help='user')
    user_parser.add_argument('userid')
    user_parser.set_defaults(func=user_)

    approver_parser = subparsers.add_parser('approver', help='approver')
    approver_parser.add_argument('userid')
    approver_parser.set_defaults(func=approver_)

    login_rhpam_parser = subparsers.add_parser('login_rhpam', help='Obtain an API token to access RHPAM')
    login_rhpam_parser.add_argument('userid')
    login_rhpam_parser.add_argument('password')
    login_rhpam_parser.set_defaults(func=login_rhpam_)

    wait_rhpam_parser = subparsers.add_parser('wait_rhpam', help='Wait for RHPAM to be launched')
    wait_rhpam_parser.set_defaults(func=wait_rhpam_)

    spaces_rhpam_parser = subparsers.add_parser('spaces_rhpam', help='List RHPAM spaces')
    spaces_rhpam_parser.add_argument('userid')
    spaces_rhpam_parser.set_defaults(func=spaces_rhpam_)

    create_space_rhpam_parser = subparsers.add_parser('create_space_rhpam', help='Create a RHPAM space')
    create_space_rhpam_parser.add_argument('userid')
    create_space_rhpam_parser.add_argument('--space', default='MySpace')
    create_space_rhpam_parser.set_defaults(func=create_space_rhpam_)

    projects_rhpam_parser = subparsers.add_parser('projects_rhpam', help='List RHPAM projects')
    projects_rhpam_parser.add_argument('userid')
    projects_rhpam_parser.add_argument('--space', default='MySpace')
    projects_rhpam_parser.set_defaults(func=projects_rhpam_)

    create_project_rhpam_parser = subparsers.add_parser('create_project_rhpam', help='Create a RHPAM project')
    create_project_rhpam_parser.add_argument('userid')
    create_project_rhpam_parser.add_argument('project')
    create_project_rhpam_parser.add_argument('--space', default='MySpace')
    create_project_rhpam_parser.set_defaults(func=create_project_rhpam_)

    git_clone_rhpam_parser = subparsers.add_parser('git_clone_rhpam', help='Clone a RHPAM rule repository')
    git_clone_rhpam_parser.add_argument('userid')
    git_clone_rhpam_parser.add_argument('project')
    git_clone_rhpam_parser.add_argument('url')
    git_clone_rhpam_parser.add_argument('--space', default='MySpace')
    git_clone_rhpam_parser.set_defaults(func=git_clone_rhpam_)

    build_project_rhpam_parser = subparsers.add_parser('build_project_rhpam', help='Build a RHPAM project')
    build_project_rhpam_parser.add_argument('userid')
    build_project_rhpam_parser.add_argument('project')
    build_project_rhpam_parser.add_argument('--space', default='MySpace')
    build_project_rhpam_parser.set_defaults(func=build_project_rhpam_)

    deploy_project_rhpam_parser = subparsers.add_parser('deploy_project_rhpam', help='Deploy a RHPAM project')
    deploy_project_rhpam_parser.add_argument('userid')
    deploy_project_rhpam_parser.add_argument('project')
    deploy_project_rhpam_parser.add_argument('--group', default='com.myspace')
    deploy_project_rhpam_parser.add_argument('--version', default='1.0.0-SNAPSHOT')
    deploy_project_rhpam_parser.set_defaults(func=deploy_project_rhpam_)

    containers_rhpam_parser = subparsers.add_parser('containers_rhpam', help='List a RHPAM containers')
    containers_rhpam_parser.add_argument('userid')
    containers_rhpam_parser.set_defaults(func=containers_rhpam_)

    start_container_rhpam_parser = subparsers.add_parser('start_container_rhpam', help='Start a RHPAM container')
    start_container_rhpam_parser.add_argument('userid')
    start_container_rhpam_parser.add_argument('container')
    start_container_rhpam_parser.set_defaults(func=start_container_rhpam_)

    login_kie_parser = subparsers.add_parser('login_kie', help='Obtain an API token to access a kie server')
    login_kie_parser.add_argument('userid')
    login_kie_parser.add_argument('password')
    login_kie_parser.set_defaults(func=login_kie_)

    create_ap_instance_rhpam_parser = subparsers.add_parser('create_ap_instance_rhpam', help='Create an authorization policy instance')
    create_ap_instance_rhpam_parser.add_argument('userid')
    create_ap_instance_rhpam_parser.add_argument('payer')
    create_ap_instance_rhpam_parser.add_argument('amount')
    create_ap_instance_rhpam_parser.add_argument('dailyamount')
    create_ap_instance_rhpam_parser.add_argument('psbt')
    create_ap_instance_rhpam_parser.set_defaults(func=create_ap_instance_rhpam_)

    get_ap_instances_rhpam_parser = subparsers.add_parser('get_ap_instances_rhpam', help='Get authorization policy instances')
    get_ap_instances_rhpam_parser.add_argument('userid')
    get_ap_instances_rhpam_parser.set_defaults(func=get_ap_instances_rhpam_)

    get_ap_instance_rhpam_parser = subparsers.add_parser('get_ap_instance_rhpam', help='Get an authorization policy instance')
    get_ap_instance_rhpam_parser.add_argument('userid')
    get_ap_instance_rhpam_parser.add_argument('id')
    get_ap_instance_rhpam_parser.set_defaults(func=get_ap_instance_rhpam_)

    args = parser.parse_args()

    numeric_level = getattr(logging, args.log.upper(), None)
    logging.basicConfig(level=numeric_level, stream=sys.stdout)

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.parse_args(['-h'])
