# This file is part of OpenSnitch.
#
# Copyright(c) 2017 Simone Margaritelli
# evilsocket@gmail.com
# http://www.evilsocket.net
#
# This file may be licensed under the terms of of the
# GNU General Public License Version 2 (the ``GPL'').
#
# Software distributed under the License is distributed
# on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
# express or implied. See the GPL for the specific language
# governing rights and limitations.
#
# You should have received a copy of the GPL along with this
# program. If not, go to http://www.gnu.org/licenses/gpl.html
# or write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
from setuptools import setup, find_packages
from opensnitch.version import VERSION
import sys


if sys.version_info[0] != 3:
    raise RuntimeError('Unsupported python version "{0}"'.format(
      sys.version_info[0]))

try:
    with open('README.md') as f:
        long_description = f.read()
except:
    long_description = 'OpenSnitch - An application level firewall for GNU/Linux.'  # noqa


setup(name='opensnitch',
      version=VERSION,
      description=long_description,
      long_description=long_description,
      author='Simone Margaritelli',
      author_email='evilsocket@gmail.com',
      url='http://www.github.com/evilsocket/opensnitch',
      packages=find_packages(),
      scripts=['bin/opensnitchd', 'bin/opensnitch-qt'],
      package_data={'': ['*.ui']},
      license='GPL',
      zip_safe=False,
      install_requires=[
          'scapy-python3',
          'dpkt',
          'NetfilterQueue',
          'psutil',
          'pyinotify',
          'python-iptables',
          'python-prctl',
          'pygobject',
      ])
