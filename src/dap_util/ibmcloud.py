#!/usr/bin/env python3

import argparse, json
from pprint import pprint
from urllib import request

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

def _send_request(url, data, headers, method):
    req = request.Request(url, data, headers, method=method)
    _print_request(req)
    with request.urlopen(req) as res:
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
    return None

def get_token(apikey):
    url = 'https://iam.cloud.ibm.com/identity/token'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
    }
    data = 'grant_type=urn:ibm:params:oauth:grant-type:apikey&apikey=' + apikey
    return _send_request(url, data.encode(), headers, method='POST')

def create_credentials(name, guid, token):
  url = 'https://resource-controller.cloud.ibm.com/v2/resource_keys'
  headers = {
      'Authorization': 'Bearer ' + token,
      'Cotent-Type': 'application/json'
  }
  data = {
      'name': name,
      'source': guid,
      'role': 'Writer'
  }
  return _send_request(url, json.dumps(data).encode(), headers, method='POST')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='commands')

    get_token_parser = subparsers.add_parser('get_token', help='Get an access token')
    get_token_parser.add_argument('apikey')
    get_token_parser.set_defaults(func=get_token)

    create_credentials_parser = subparsers.add_parser('create_credentials', help='Create credentials')
    create_credentials_parser.add_argument('name')
    create_credentials_parser.add_argument('guid')
    create_credentials_parser.add_argument('token')
    create_credentials_parser.set_defaults(func=create_credentials)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        res = None
        if args.func is get_token:
            res = get_token(args.apikey)
        elif args.func is create_credentials:
            res = create_credentials(args.name, args.guid, args.token)
        else:
            raise Exception('Unknown command ' + str(args.func))
        pprint(res)
    else:
        parser.parse_args(['-h'])