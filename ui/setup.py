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
      package_data={'': ['*.*']},
      data_files=[('/usr/share/applications', ['opensnitch_ui.desktop']),
               ('/usr/share/kservices5', ['kcm_opensnitch.desktop'])],
      scripts=[ 'bin/opensnitch-ui' ],
      install_requires=[
          'grpcio==1.0.0',
          'grpcio-tools==1.10.1',
          'pyinotify==0.9.6',
          'unicode_slugify==0.1.3',
          'pyqt5==5.10.1',
          'configparser==3.5.0',
      ],
      zip_safe=False)
