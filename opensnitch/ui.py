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
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
from opensnitch.rule import Rule

# TODO: Implement a better UI.
# TODO: Implement tray icon and menu.
# TODO: Implement rules editor.
class UI:
    CHOICES = [ 'Allow Once',
                'Allow All',
                'Deny Once',
                'Deny All' ]

    RESULTS = [ \
      # save | verdict    | all
      ( False, Rule.ACCEPT, False ),
      ( True,  Rule.ACCEPT, True ),
      ( False, Rule.DROP,   False ),
      ( True,  Rule.DROP,   True )
    ]

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

        dialog = Gtk.MessageDialog(None, Gtk.DialogFlags.MODAL, Gtk.MessageType.QUESTION, Gtk.ButtonsType.NONE, "OpenSnitch")
        dialog.format_secondary_text(msg)
        dialog.add_button("Allow Once", 0)
        dialog.add_button("Allow Always", 1)
        dialog.add_button("Deny Once", 2)
        dialog.add_button("Deny Always", 3)
        response = dialog.run()
        if response == -4:
            UI.RESULTS[2]
        return UI.RESULTS[response]
