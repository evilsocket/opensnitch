from setuptools import setup, find_packages

import os
import sys

path = os.path.abspath(os.path.dirname(__file__))
sys.path.append(path)

from opensnitch.version import version

setup(name='opensnitch-ui',
      version=version,
      description='Prompt service and UI for the opensnitch interactive firewall application.',
      long_description='GUI for the opensnitch interactive firewall application\n\
opensnitch-ui is a GUI for opensnitch written in Python.\n\
It allows the user to view live outgoing connections, as well as search\n\
to make connections.\n\
.\n\
The user can decide if block the outgoing connection based on properties of\n\
the connection: by port, by uid, by dst ip, by program or a combination\n\
of them.\n\
.\n\
These rules can last forever, until the app restart or just one time.',
      url='https://github.com/evilsocket/opensnitch',
      author='Simone "evilsocket" Margaritelli',
      author_email='evilsocket@protonmail.com',
      license='GPL-3.0',
      packages=find_packages(),
      include_package_data = True,
      package_data={'': ['*.*']},
      data_files=[('/usr/share/applications', ['resources/opensnitch_ui.desktop']),
               ('/usr/share/kservices5', ['resources/kcm_opensnitch.desktop']),
               ('/usr/share/icons/hicolor/scalable/apps', ['resources/icons/opensnitch-ui.svg']),
               ('/usr/share/icons/hicolor/48x48/apps', ['resources/icons/48x48/opensnitch-ui.png']),
               ('/usr/share/icons/hicolor/64x64/apps', ['resources/icons/64x64/opensnitch-ui.png']),
               ('/usr/share/metainfo', ['resources/io.github.evilsocket.opensnitch.appdata.xml'])],
      scripts = [ 'bin/opensnitch-ui' ],
      zip_safe=False)
