# Copyright IBM Corp. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0

from setuptools import setup, find_packages

setup(
    name='dap_util',
    version='0.1.0',
    description='Utility for dap blueprint',
    author='Takuya Nakaike',
    author_email='nakaike@jp.ibm.com',
    packages=find_packages(where='.'),
    package_dir={'': '.'},
)
