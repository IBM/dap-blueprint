# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

from setuptools import setup
from setuptools import find_packages


def _requires_from_file(filename):
    return open(filename).read().splitlines()

setup(
    name='dap_client',
    version='0.0.1',
    license='TBD',
    description='CLI for dap blueprint',
    author='nakaike@jp.ibm.com  ',
    url='https://github.ibm.com/ZaaS/dap-blueprint/tree/mvp2/demo/dap_client',
    packages=find_packages('.'),
    package_dir={'': '.'}
)
