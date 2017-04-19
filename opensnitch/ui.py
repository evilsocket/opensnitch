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

from opensnitch.rule import Rule

# TODO: Implement a better UI.
# TODO: Implement tray icon and menu.
# TODO: Implement rules editor.
class UI:
    CHOICES = [ 'Allow Once',
                'Allow Forever',
                'Whitelist App',
                'Deny Once',
                'Deny Forever',
                'Block App' ]

    RESULTS = [ \
      # save | verdict    | all
      ( False, Rule.ACCEPT, False ),
      ( True,  Rule.ACCEPT, False ),
      ( True,  Rule.ACCEPT, True  ),
      ( False, Rule.DROP,   False ),
      ( True,  Rule.DROP,   False ),
      ( True,  Rule.DROP,   True  )
    ]

    @staticmethod
    def prompt_user( c ):
        title = 'OpenSnitch'
        msg = "%s (%s, pid=%s) wants to connect to %s on %s port %s%s" % ( \
                c.app.name,
                c.app_path,
                c.app.pid,
                c.hostname,
                c.proto.upper(),
                c.dst_port,
                " (%s)" % c.service if c.service is not None else '' )

        idx = g.indexbox( msg, title, UI.CHOICES )
        return UI.RESULTS[idx]

