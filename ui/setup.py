from setuptools import setup, find_packages

import os
import sys

path = os.path.abspath(os.path.dirname(__file__))
sys.path.append(path)

from opensnitch.version import version

def get_data_files():
    data = []
    
    for f in ('dialogs', 'res'):
        for folder, subdirs, files in os.walk( 'opensnitch/%s/' % f ):
            for fname in files:
                if fname[0] != '.':
                    data.append( os.path.join( folder, fname ) )

    return data
        
setup(name='opensnitch-ui',
      version=version,
      description='Prompt service and UI for the opensnitch application firewall.',
      url='https://github.com/evilsocket/opensnitch',
      author='Simone "evilsocket" Margaritelli',
      author_email='evilsocket@protonmail.com',
      license='GPL',
      packages=find_packages(),
      include_package_data = True,
      package_data={'': '*.*'},#get_data_files()},
      scripts = [ 'bin/opensnitch-ui' ],
      zip_safe=False)
