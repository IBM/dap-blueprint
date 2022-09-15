#!/usr/bin/env python3

import argparse, os, sys, re

def _create_key_file(is_secure_build, is_pubkey):
    dir = 'build-time-keys'

    if not os.path.exists(dir):
        os.mkdir(dir)
    if is_pubkey:
        return open(dir + '/public.pem', mode='w')
    else:
        return open(dir + '/private.pem', mode='w')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('logfile')

    args = parser.parse_args()
    
    if not os.path.exists(args.logfile):
        print('No log file specified')
        sys.exit()

    logfile = open(args.logfile)
    is_secure_build = False
    pubkey_file = None
    privkey_file = None
    for line in logfile.readlines():
        if line.startswith('INFO'):
            is_secure_build = True
            line = line[line.find('run: ')+5:]
        else:
            m = re.match(r'#[0-9]+ [0-9.]+ (.+)', line)
            if m:
                line = m.groups()[0] + '\n'
        
        if line == '-----BEGIN PUBLIC KEY-----\n':
            pubkey_file = _create_key_file(is_secure_build, True)

        if line == '-----BEGIN RSA PRIVATE KEY-----\n':
            privkey_file = _create_key_file(is_secure_build, False)

        if pubkey_file:
            pubkey_file.write(line)
            if line == '-----END PUBLIC KEY-----\n':
                pubkey_file.close()
                pubkey_file = None
            
        if privkey_file:
            privkey_file.write(line)
            if line == '-----END RSA PRIVATE KEY-----\n':
                privkey_file.close()
                privkey_file = None
