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
import easygui as g
import nfqueue

# TODO: Implement a better UI.
# TODO: Implement tray icon and menu.
# TODO: Implement rules editor.
class UI:
    @staticmethod
    def prompt_user( c ):
        title = 'OpenSnitch'
        msg = "%s (%s) wants to connect to %s on %s port %s%s" % ( \
                c.app.name,
                c.app_path,
                c.hostname,
                c.proto.upper(),
                c.dst_port,
                " (%s)" % c.service if c.service is not None else '' )
        choices = [ 'Allow Once',
                    'Allow All',
                    'Deny Once',
                    'Deny All' ]

        idx = g.indexbox(msg, title, choices)

        results = [ \
            ( nfqueue.NF_ACCEPT, False ),
            ( nfqueue.NF_ACCEPT, True ),
            ( nfqueue.NF_DROP, False ),
            ( nfqueue.NF_DROP, True )
        ]
       
        return results[idx]

