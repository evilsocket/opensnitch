from setuptools import setup

import os
import sys

path = os.path.abspath(os.path.dirname(__file__))
sys.path.append(path)

import version

setup(name='opensnitch-ui',
      version=version.version,
      description='Prompt service and UI for the opensnitch application firewall.',
      url='https://github.com/evilsocket/opensnitch',
      author='Simone "evilsocket" Margaritelli',
      author_email='evilsocket@protonmail.com',
      license='GPL',
      scripts = [ 'bin/opensnitch-ui' ],
      zip_safe=False)
