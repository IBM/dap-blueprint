#
# Licensed Materials - Property of IBM
#
# 5737-I09
#
# Copyright IBM Corp. 2019 All Rights Reserved.
# US Government Users Restricted Rights - Use, duplication or
# disclosure restricted by GSA ADP Schedule Contract with IBM Corp
#
import logging, re


class JsonFilter(logging.Filter):

    def __init__(self, json_keys):
        super(JsonFilter, self).__init__()
        self._json_keys = json_keys

    def filter(self, record):
        record.msg = self.redact(record.msg)
        if isinstance(record.args, dict):
            for k in record.args.keys():
                record.args[k] = self.redact(record.args[k])
        else:
            record.args = tuple(self.redact(arg) for arg in record.args)
        return True

    def redact(self, msg):
        if not isinstance(msg, str):
            msg = str(msg)
        for key in self._json_keys:
            pattern = '"' + key + '":\s*"[^"]+"'
            output = '"' + key + '": "<' + key + '>"'
            msg = re.sub(pattern, output, msg)

            pattern = '"' + key + '":\s*""'
            output = '"' + key + '": "<null>"'
            msg = re.sub(pattern, output, msg)

            pattern = '"' + key + '=[^"]+"'
            output = '"' + key + '=<' + key + '>"'
            msg = re.sub(pattern, output, msg)

            pattern = '"' + key + '="'
            output = '"' + key + '=<null>"'
            msg = re.sub(pattern, output, msg)

            pattern = '"' + key.lower() + '":\s*"[^"]+"'
            output = '"' + key.lower() + '": "<' + key.lower() + '>"'
            msg = re.sub(pattern, output, msg)

            pattern = '"' + key.lower() + '":\s*""'
            output = '"' + key.lower() + '": "<null>"'
            msg = re.sub(pattern, output, msg)

            pattern = '"' + key.lower() + '=[^"]+"'
            output = '"' + key.lower() + '=<' + key.lower() + '>"'
            msg = re.sub(pattern, output, msg)

            pattern = '"' + key.lower() + '="'
            output = '"' + key.lower() + '=<null>"'
            msg = re.sub(pattern, output, msg)
        return msg


class TokenFilter(logging.Filter):

    def __init__(self):
        super(TokenFilter, self).__init__()

    def filter(self, record):
        record.msg = self.redact(record.msg)
        if isinstance(record.args, dict):
            for k in record.args.keys():
                record.args[k] = self.redact(record.args[k])
        else:
            record.args = tuple(self.redact(arg) for arg in record.args)
        return True

    def redact(self, msg):
        if not isinstance(msg, str):
            msg = str(msg)
        pattern = 'authorization: Bearer [\S]+'
        output = 'authorization: Bearer <TOKEN>'
        msg = re.sub(pattern, output, msg)
        return msg


class StringFilter(logging.Filter):

    def __init__(self, stringstobefiltered):
        super(StringFilter, self).__init__()
        self._stringstobefiltered = stringstobefiltered

    def filter(self, record):
        record.msg = self.redact(record.msg)
        if isinstance(record.args, dict):
            for k in record.args.keys():
                record.args[k] = self.redact(record.args[k])
        else:
            record.args = tuple(self.redact(arg) for arg in record.args)
        return True

    def redact(self, msg):
        for key in self._stringstobefiltered:
            msg = re.sub(re.escape(key), "*******", msg)
        return msg
