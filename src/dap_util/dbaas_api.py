#!/usr/bin/env python3

import os, argparse, json, copy
from pprint import pprint
from urllib import request
from urllib.error import HTTPError, URLError

if 'DBAAS_CA_FILE' not in os.environ:
    raise Exception('Please set an environment variable DBAAS_CA_FILE')

CA_FILE = os.environ['DBAAS_CA_FILE']

HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

def _print_request(req):
    print('-----------------------------')
    print('Sending the following request')
    print('URL={}'.format(req.get_full_url()))
    print('Method={}'.format(req.get_method()))
    print('Header')
    pprint(req.headers)
    print('Body')
    if req.data is not None:
        pprint(req.data.decode('utf-8'))
    print()

def __send_request(url, data, headers, method):
    req = request.Request(url, data, headers, method=method)
    _print_request(req)
    try:
        with request.urlopen(req, cafile=CA_FILE) as res:
            print('-----------------------------')
            print('Getting the following response')
            print('HTTP status code: ' + str(res.code))
            json_data = '{}'
            try:
                json_data = json.load(res)
            except Exception:
                pass
            pprint(json_data)
            print()
            return json_data
    except HTTPError as e:
        err = e.read().decode('utf-8')
        print('HTTP error: {}'.format(e.code))
        print(err)
        return err
    except URLError as e:
        print(str(e))
        return str(e)
    return None

def _send_request(path, method, additional_headers={}, payload=None, apikey=None, token=None):
    if path.endswith('token'):
        if apikey is None:
            raise Exception('API key is not provided. It is needed to get an access token.')
    elif token is None:
        raise Exception('Access token is not provided. It is needed to access Hyper Protect DBaaS APIs.')

    url = 'https://dbaas904.hyperp-dbaas.cloud.ibm.com:20000/api/v3' + path
    
    headers = HEADERS
    headers = copy.deepcopy(HEADERS)
    if apikey:
        headers['api_key'] = apikey
    else:
        headers['x-auth-token'] = token
    headers.update(additional_headers)

    data = json.dumps(payload).encode() if payload else None

    return __send_request(url, data, headers, method)

TMP_TOKEN_FILE = '.dbaas.tmp/dbaas.token'

def _store_token(token):
    if not os.path.exists('.dbaas.tmp'):
        os.mkdir('.dbaas.tmp')
    with open(TMP_TOKEN_FILE, mode='w') as f:
        f.write(token)
    return None

def _get_userid_and_token():
    if not os.path.exists(TMP_TOKEN_FILE):
        return None, None
    with open(TMP_TOKEN_FILE) as f:
        json_data = json.load(f)
        return json_data['user_id'], json_data['access_token']
    return None, None

def get_token(apikey):
    path = '/auth/token'
    res = _send_request(path=path, method='GET', apikey=apikey)
    _store_token(json.dumps(res))
    return res

def create_instance(name, password, userid, token):
    path = '/' + str(userid) + '/services'
    additional_headers = {
        'accept-license-agreement': 'yes'
    }
    resource_group = "Default"
    if "DBAAS_RESOURCE_GROUP" in os.environ:
        resource_group = os.environ["DBAAS_RESOURCE_GROUP"]
    plan = 'mongodb-free'
    if 'DBAAS_PLAN' in os.environ:
        plan = os.environ['DBAAS_PLAN']
    cpu = 2
    memory = '1GiB'
    storage = '2GiB'
    if plan == 'mongodb-flexible':
        cpu = 1
        memory = '2GiB'
        storage = '5GiB'
    payload = {
        'name': name,
        'catalog': 'hyperp-dbaas-mongodb',
        'resource_group': resource_group,
        'plan': plan,
        'admin_name': 'admin',
        'password': password,
        'cpu': cpu,
        'memory': memory,
        'storage': storage
    }
    if 'DBAAS_TAG' in os.environ and os.environ['DBAAS_TAG']:
        payload['tags'] = [os.environ['DBAAS_TAG']]
    return _send_request(path=path, method='POST', additional_headers=additional_headers, payload=payload, token=token)

def get_instances(userid, token):
    path = '/' + str(userid) + '/services'
    return _send_request(path=path, method='GET', token=token)

def get_instance(guid, userid, token):
    path = '/' + str(userid) + '/services/' + str(guid)
    return _send_request(path=path, method='GET', token=token)

def delete_instance(guid, token):
    url = 'https://resource-controller.cloud.ibm.com/v2/resource_instances/' + str(guid)
    headers = {
        'Authorization': 'Bearer ' + str(token)
    }
    return __send_request(url=url, data=None, headers=headers, method='DELETE')

def get_cluster(clusterid, userid, token):
    path = '/' + str(userid) + '/clusters/' + str(clusterid)
    return _send_request(path=path, method='GET', token=token)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--userid')
    parser.add_argument('--token')
    subparsers = parser.add_subparsers(title='commands')

    get_token_parser = subparsers.add_parser('get_token', help='Get an access token')
    get_token_parser.add_argument('apikey')
    get_token_parser.set_defaults(func=get_token)

    create_parser = subparsers.add_parser('create_instance', help='Create an instance')
    create_parser.add_argument('name')
    create_parser.add_argument('password')
    create_parser.set_defaults(func=create_instance)

    get_instances_parser = subparsers.add_parser('get_instances', help='Get instances')
    get_instances_parser.set_defaults(func=get_instances)

    get_instance_parser = subparsers.add_parser('get_instance', help='Get details of an instance')
    get_instance_parser.add_argument('guid')
    get_instance_parser.set_defaults(func=get_instance)

    delete_instance_parser = subparsers.add_parser('delete_instance', help='Delete an instance')
    delete_instance_parser.add_argument('guid')
    delete_instance_parser.set_defaults(func=delete_instance)

    get_cluster_parser = subparsers.add_parser('get_cluster', help='Get details of a cluster')
    get_cluster_parser.add_argument('clusterid')
    get_cluster_parser.set_defaults(func=get_cluster)

    args = parser.parse_args()

    userid, token = _get_userid_and_token()
    if args.userid is not None:
        userid = args.userid
    if args.token is not None:
        token = args.token

    if hasattr(args, 'func'):
        res = None
        if args.func is get_token:
            res = get_token(args.apikey)
        elif args.func is create_instance:
            res = create_instance(args.name, args.password, userid, token)
        elif args.func is get_instances:
            res = get_instances(userid, token)
        elif args.func is get_instance:
            res = get_instance(args.guid, userid, token)
        elif args.func is delete_instance:
            res = delete_instance(args.guid, token)
        elif args.func is get_cluster:
            res = get_cluster(args.clusterid, userid, token)
        else:
            raise Exception('Unknown command ' + str(args.func))
        pprint(res)
    else:
        parser.parse_args(['-h'])