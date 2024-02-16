
from opensnitch.nodes import Nodes
from opensnitch.database import Database
from opensnitch.database.enums import ConnFields
from opensnitch.utils import Utils
from opensnitch.utils.infowindow import InfoWindow
from PyQt5.QtCore import QCoreApplication as QC

class ConnDetails(InfoWindow):
    """Display a small dialog with the details of a connection
    """

    def __init__(self, parent):
        super().__init__(parent)

        self._db = Database.instance()
        self._nodes = Nodes.instance()

    def showByField(self, field, value):
        records = self._db.get_connection_by_field(field, value)
        if not records.next():
            return

        node = records.value(ConnFields.Node)
        uid = records.value(ConnFields.UID)
        if self._nodes.is_local(node):
            uid = Utils.get_user_id(uid)

        conn_text = QC.translate("stats", """
<b>{0}</b><br><br>
<b>Time:</b> {1}<br><br>
<b>Process:</b><br>{2}<br>
<b>Cmdline:</b><br>{3}<br>
<b>CWD:</b><br>{4}<br><br>
<b>UID:</b> {5} <b>PID:</b> {6}<br>
<br>
<b>Node:</b> {7}<br><br>
<b>{8}</b> {9}:{10} -> {11} ({12}):{13}
<br><br>
<b>Rule:</b><br>
{14}
""".format(
                    records.value(ConnFields.Action).upper(),
                    records.value(ConnFields.Time),
                    records.value(ConnFields.Process),
                    records.value(ConnFields.Cmdline),
                    records.value(ConnFields.CWD),
                    uid,
                    records.value(ConnFields.PID),
                    node,
                    records.value(ConnFields.Protocol).upper(),
                    records.value(ConnFields.SrcPort),
                    records.value(ConnFields.SrcIP),
                    records.value(ConnFields.DstIP),
                    records.value(ConnFields.DstHost),
                    records.value(ConnFields.DstPort),
                    records.value(ConnFields.Rule)
                ))

        self.showText(conn_text)
