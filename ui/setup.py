from setuptools import setup, find_packages

import os
import sys

path = os.path.abspath(os.path.dirname(__file__))
sys.path.append(path)

from opensnitch.version import version
        
setup(name='opensnitch-ui',
      version=version,
      description='Prompt service and UI for the opensnitch application firewall.',
      url='https://github.com/evilsocket/opensnitch',
      author='Simone "evilsocket" Margaritelli',
      author_email='evilsocket@protonmail.com',
      license='GPL',
      packages=find_packages(),
      include_package_data = True,
      package_data={'': '*.*'},
      scripts = [ 'bin/opensnitch-ui' ],
      zip_safe=False)
