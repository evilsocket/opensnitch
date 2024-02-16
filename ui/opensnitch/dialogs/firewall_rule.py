import sys
import os
import os.path
import ipaddress

from PyQt5 import QtCore, QtGui, uic, QtWidgets
from PyQt5.QtCore import QCoreApplication as QC

from opensnitch.config import Config
from opensnitch.nodes import Nodes
from opensnitch.utils import NetworkServices, NetworkInterfaces, QuickHelp, Icons, Utils
from opensnitch import ui_pb2
import opensnitch.firewall as Fw
from opensnitch.firewall.utils import Utils as FwUtils


DIALOG_UI_PATH = "%s/../res/firewall_rule.ui" % os.path.dirname(sys.modules[__name__].__file__)
class FwRuleDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):
    LOG_TAG = "[fw rule dialog]"
    ACTION_IDX_DENY = 0
    ACTION_IDX_ALLOW = 1

    IN = 0
    OUT = 1
    FORWARD = 2
    PREROUTING = 3
    POSTROUTING = 4

    OP_NEW = 0
    OP_SAVE = 1
    OP_DELETE = 2

    FORM_TYPE_SIMPLE = 0
    FORM_TYPE_EXCLUDE_SERVICE = 1
    FORM_TYPE_ALLOW_IN_SERVICE = 2
    FORM_TYPE = FORM_TYPE_SIMPLE

    STATM_DPORT = 0
    STATM_SPORT = 1
    STATM_DEST_IP = 2
    STATM_SOURCE_IP = 3
    STATM_IIFNAME = 4
    STATM_OIFNAME = 5
    STATM_CT_SET = 6
    STATM_CT_MARK = 7
    STATM_CT_STATE = 8
    STATM_META_SET_MARK = 9
    STATM_META = 10
    STATM_ICMP = 11
    STATM_ICMPv6 = 12
    STATM_LOG = 13
    STATM_QUOTA = 14
    STATM_COUNTER = 15
    STATM_LIMIT = 16

    _notification_callback = QtCore.pyqtSignal(ui_pb2.NotificationReply)

    def __init__(self, parent=None, appicon=None):
        QtWidgets.QDialog.__init__(self, parent)
        self.setupUi(self)
        self.setWindowIcon(appicon)

        self._fw = Fw.Firewall.instance()
        self._nodes = Nodes.instance()
        self.net_srv = NetworkServices()
        self.statements = {}
        self.st_num = 0

        self.STATM_LIST = [
            "",
            QC.translate("firewall", "Dest Port"),
            QC.translate("firewall", "Source Port"),
            QC.translate("firewall", "Dest IP"),
            QC.translate("firewall", "Source IP"),
            QC.translate("firewall", "Input interface"),
            QC.translate("firewall", "Output interface"),
            QC.translate("firewall", "Set conntrack mark"),
            QC.translate("firewall", "Match conntrack mark"),
            QC.translate("firewall", "Match conntrack state(s)"),
            QC.translate("firewall", "Set mark on packet"),
            QC.translate("firewall", "Match packet information"),
            #"TCP",
            #"UDP",
            "ICMP",
            "ICMPv6",
            "LOG",
            QC.translate("firewall", "Bandwidth quotas"),
            "COUNTER",
            QC.translate("firewall", "Rate limit connections"),
        ]

        self.STATM_CONF = {
            self.STATM_DPORT: {
                'name': Fw.Statements.TCP.value, # tcp, udp, dccp, sctp
                'tooltip': QC.translate("firewall", """
Supported formats:

 - Simple: 23
 - Ranges: 80-1024
 - Multiple ports: 80,443,8080
"""),
                'keys': [
                    {'key': Fw.Statements.DPORT.value, 'values': self.net_srv.to_array()}
                ]
            },
            self.STATM_SPORT: {
                'name': Fw.Statements.TCP.value,
                'tooltip': QC.translate("firewall", """
Supported formats:

 - Simple: 23
 - Ranges: 80-1024
 - Multiple ports: 80,443,8080
"""),
                'keys': [
                    {'key': Fw.Statements.SPORT.value, 'values': self.net_srv.to_array()}
                ]
            },
            self.STATM_DEST_IP: {
                'name': Fw.Statements.IP.value, # ip or ip6
                'tooltip': QC.translate("firewall", """
Supported formats:

 - Simple: 1.2.3.4
 - IP ranges: 1.2.3.100-1.2.3.200
 - Network ranges: 1.2.3.4/24
"""),
                'keys': [
                    {'key': Fw.Statements.DADDR.value, 'values': []}
                ]
            },
            self.STATM_SOURCE_IP: {
                'name': Fw.Statements.IP.value,
                'tooltip': QC.translate("firewall", """
Supported formats:

 - Simple: 1.2.3.4
 - IP ranges: 1.2.3.100-1.2.3.200
 - Network ranges: 1.2.3.4/24
"""),
                'keys': [
                    {'key': Fw.Statements.SADDR.value, 'values': []}
                ]
            },
            self.STATM_IIFNAME: {
                'name': Fw.Statements.IIFNAME.value,
                'tooltip': QC.translate("firewall", """Match input interface. Regular expressions not allowed.
Use * to match multiple interfaces."""),
                'keys': [
                    {'key': "", 'values': []}
                ]
            },
            self.STATM_OIFNAME: {
                'name': Fw.Statements.OIFNAME.value,
                'tooltip': QC.translate("firewall", """Match output interface. Regular expressions not allowed.
Use * to match multiple interfaces."""),
                'keys': [
                    {'key': "", 'values': []}
                ]
            },
            self.STATM_CT_SET: {
                'name': Fw.Statements.CT.value,
                'tooltip': QC.translate("firewall", "Set a conntrack mark on the connection, in decimal format."),
                'keys': [
                    # we need 2 keys for this expr: key: set, value: <empty>, key: mark, value: xxx
                    {'key': Fw.ExprCt.SET.value, 'values': None}, # must be empty
                    {'key': Fw.ExprCt.MARK.value, 'values': []}
                ]
            },
            # match mark
            self.STATM_CT_MARK: {
                'name': Fw.Statements.CT.value,
                'tooltip': QC.translate("firewall", "Match a conntrack mark of the connection, in decimal format."),
                'keys': [
                    {'key': Fw.ExprCt.MARK.value, 'values': []}
                ]
            },
            self.STATM_CT_STATE: {
                'name': Fw.Statements.CT.value,
                'tooltip': QC.translate("firewall", """Match conntrack states.

Supported formats:
 - Simple: new
 - Multiple states separated by commas: related,new
"""),
                'keys': [
                    {
                        'key': Fw.ExprCt.STATE.value,
                        'values': [Fw.ExprCt.NEW.value, Fw.ExprCt.ESTABLISHED.value, Fw.ExprCt.RELATED.value, Fw.ExprCt.INVALID.value]
                    }
                ]
            },
            self.STATM_META: {
                'name': Fw.Statements.META.value,
                'tooltip': QC.translate("firewall", """
Match packet's metainformation.

Value must be in decimal format, except for the "l4proto" option.
For l4proto it can be a lower case string, for example:
 tcp
 udp
 icmp,
 etc

If the value is decimal for protocol or lproto, it'll use it as the code of
that protocol.
"""),
                'keys': [
                    {'key': Fw.ExprMeta.MARK.value, 'values': []},
                    {'key': Fw.ExprMeta.L4PROTO.value, 'values': Fw.Protocols.values()}
                ]
            },
            self.STATM_META_SET_MARK: {
                'name': Fw.Statements.META.value,
                'tooltip': QC.translate("firewall", "Set a mark on the packet matching the specified conditions. The value is in decimal format."),
                'keys': [
                    {'key': Fw.ExprMeta.SET.value, 'values': None},
                    {'key': Fw.ExprMeta.MARK.value, 'values': []}
                ]
            },
            self.STATM_ICMP: {
                'name': Fw.Statements.ICMP.value,
                'tooltip': QC.translate("firewall", """
Match ICMP codes.

Supported formats:
 - Simple: echo-request
 - Multiple separated by commas: echo-request,echo-reply
"""),
                'keys':  [
                    {'key': "type", 'values': Fw.ExprICMP.values()}
                ]
            },
            self.STATM_ICMPv6: {
                'name': Fw.Statements.ICMPv6.value,
                'tooltip': QC.translate("firewall", """
Match ICMPv6 codes.

Supported formats:
 - Simple: echo-request
 - Multiple separated by commas: echo-request,echo-reply
"""),
                'keys':  [
                    {'key': "type", 'values': Fw.ExprICMP.values()}
                ]
            },
            self.STATM_LOG: {
                'name': Fw.Statements.LOG.value,
                'tooltip': QC.translate("firewall", "Print a message when this rule matches a packet."),
                'keys':  [
                    {'key': Fw.ExprLog.PREFIX.value, 'values': []}
                ]
            },
            self.STATM_QUOTA: {
                'name': Fw.ExprQuota.QUOTA.value,
                'tooltip': QC.translate("firewall", """
Apply quotas on connections.

For example when:
 - "quota over 10/mbytes" -> apply the Action defined (DROP)
 - "quota until 10/mbytes" -> apply the Action defined (ACCEPT)

The value must be in the format: VALUE/UNITS, for example:
 - 10mbytes, 1/gbytes, etc
"""),
                'keys':  [
                    {'key': Fw.ExprQuota.OVER.value, 'values': []},
                    {'key': Fw.ExprQuota.UNIT.value, 'values': [
                        "1/{0}".format(Fw.RateUnits.BYTES.value),
                        "1/{0}".format(Fw.RateUnits.KBYTES.value),
                        "1/{0}".format(Fw.RateUnits.MBYTES.value),
                        "1/{0}".format(Fw.RateUnits.GBYTES.value),
                    ]}
                ]
            },
            self.STATM_COUNTER: {
                'name': Fw.ExprCounter.COUNTER.value,
                'tooltip': QC.translate("firewall", ""),
                # packets, bytes
                'keys':  [
                    {'key': Fw.ExprCounter.PACKETS.value, 'values': None},
                    {'key': Fw.ExprCounter.NAME.value, 'values': []}
                ]
            },
            # TODO: https://github.com/evilsocket/opensnitch/wiki/System-rules#rules-expressions
            self.STATM_LIMIT: {
                'name': Fw.ExprLimit.LIMIT.value,
                'tooltip': QC.translate("firewall", """
Apply limits on connections.

For example when:
 - "limit over 10/mbytes/minute" -> apply the Action defined (DROP, ACCEPT, etc)
    (When there're more than 10MB per minute, apply an Action)

 - "limit until 10/mbytes/hour" -> apply the Action defined (ACCEPT)

The value must be in the format: VALUE/UNITS/TIME, for example:
 - 10/mbytes/minute, 1/gbytes/hour, etc
"""),

                'keys':  [
                    {'key': Fw.ExprLimit.OVER.value, 'values': []},
                    {'key': Fw.ExprLimit.UNITS.value, 'values': [
                        "1/{0}/{1}".format(Fw.RateUnits.BYTES.value, Fw.TimeUnits.SECOND.value),
                        "1/{0}/{1}".format(Fw.RateUnits.KBYTES.value, Fw.TimeUnits.MINUTE.value),
                        "1/{0}/{1}".format(Fw.RateUnits.MBYTES.value, Fw.TimeUnits.HOUR.value),
                        "1/{0}/{1}".format(Fw.RateUnits.GBYTES.value, Fw.TimeUnits.DAY.value),
                    ]}
                ]
            },
            #self.STATM_TCP: {
            #    'name': Fw.Statements.TCP.value, # ['dport', 'sport' ... ]
            #    'key':  Fw.Statements.DADDR.value,
            #    'values': []
            #},
            #self.STATM_UDP: {
            #    'name': Fw.Statements.UDP.value,
            #    'key':  Fw.Statements.DADDR.value, # ['dport', 'sport' ... ]
            #    'values': []
            #},
        }

        self._notification_callback.connect(self._cb_notification_callback)
        self._notifications_sent = {}

        self.uuid = ""
        self.simple_port_idx = None

        self._nodes.nodesUpdated.connect(self._cb_nodes_updated)
        self.cmdClose.clicked.connect(self._cb_close_clicked)
        self.cmdReset.clicked.connect(self._cb_reset_clicked)
        self.cmdAdd.clicked.connect(self._cb_add_clicked)
        self.cmdSave.clicked.connect(self._cb_save_clicked)
        self.cmdDelete.clicked.connect(self._cb_delete_clicked)
        self.helpButton.clicked.connect(self._cb_help_button_clicked)
        self.comboVerdict.currentIndexChanged.connect(self._cb_verdict_changed)
        self.lineVerdictParms.textChanged.connect(self._cb_verdict_parms_changed)
        self.checkEnable.toggled.connect(self._cb_check_enable_toggled)
        self.lineDescription.textChanged.connect(self._cb_description_changed)

        self.cmdAddStatement.clicked.connect(self._cb_add_new_statement)
        self.cmdDelStatement.clicked.connect(self._cb_del_statement)
        # remove default page
        self.toolBoxSimple.removeItem(0)
        self.add_new_statement("", self.toolBoxSimple)
        self.hboxAdvanced.setVisible(False)
        # setTabVisible not available on <= 5.14
        #self.tabWidget.setTabVisible(0, True)

        if QtGui.QIcon.hasThemeIcon("emblem-default"):
            return

        # -----------------------------------------------------------

        saveIcon = Icons.new(self, "document-save")
        closeIcon = Icons.new(self, "window-close")
        delIcon = Icons.new(self, "edit-delete")
        addIcon = Icons.new(self, "list-add")
        remIcon = Icons.new(self, "list-remove")
        helpIcon = Icons.new(self, "help-browser")
        self.cmdSave.setIcon(saveIcon)
        self.cmdDelete.setIcon(delIcon)
        self.cmdClose.setIcon(closeIcon)
        self.cmdAdd.setIcon(addIcon)
        self.helpButton.setIcon(helpIcon)
        self.cmdAddStatement.setIcon(addIcon)
        self.cmdDelStatement.setIcon(remIcon)

    def show(self):
        super(FwRuleDialog, self).show()
        self._reset_fields()

        if FwUtils.isProtobufSupported() == False:
            self._disable_controls()
            self._disable_buttons()
            self._set_status_error(
                QC.translate(
                    "firewall",
                    "Your protobuf version is incompatible, you need to install protobuf 3.8.0 or superior\n(pip3 install --ignore-installed protobuf==3.8.0)"
                )
            )
            return False

        self._load_nodes()
        self.comboDirection.currentIndexChanged.connect(self._cb_direction_changed)
        return True

    def _close(self):
        self.comboDirection.currentIndexChanged.disconnect(self._cb_direction_changed)
        self.hide()

    @QtCore.pyqtSlot(ui_pb2.NotificationReply)
    def _cb_notification_callback(self, reply):
        self._enable_buttons()

        try:
            if reply.id not in self._notifications_sent:
                return

            rep = self._notifications_sent[reply.id]
            if reply.code == ui_pb2.OK:
                if 'operation' in rep and rep['operation'] == self.OP_DELETE:
                    self.tabWidget.setDisabled(True)
                    self._set_status_successful(QC.translate("firewall", "Rule deleted"))
                    self._disable_controls()
                    del self._notifications_sent[reply.id]
                    return

                if 'operation' in rep and rep['operation'] == self.OP_SAVE:
                    self._set_status_successful(QC.translate("firewall", "Rule saved"))
                else:
                    self._set_status_successful(QC.translate("firewall", "Rule added"))

            else:
                # XXX: The errors returned by the nftables lib are not really descriptive.
                # "invalid argument", "no such file or directory", without context
                # 1st one: invalid combination of table/chain/priorities?
                # 2nd one: does the table/chain exist?
                errormsg = QC.translate("firewall", "Error adding rules:\n{0}".format(reply.data))
                if 'operation' in rep and rep['operation'] == self.OP_SAVE:
                    if 'uuid' in rep and rep['uuid'] in reply.data:
                        errormsg = QC.translate("firewall", "Error saving rule")
                    else:
                        self._set_status_message(QC.translate("firewall", "Rule saved, but there're other rules with errors (REVIEW):\n{0}".format(reply.data)))
                        return
                self._set_status_error(errormsg)

        except Exception as e:
            print("[fw rule dialog exception] notif error:", e)
        finally:
            if reply.id in self._notifications_sent:
                del self._notifications_sent[reply.id]

    @QtCore.pyqtSlot(int)
    def _cb_nodes_updated(self, total):
        self.tabWidget.setDisabled(True if total == 0 else False)

    def closeEvent(self, e):
        self._close()


    def _cb_check_enable_toggled(self, status):
        self._enable_save()

    def _cb_description_changed(self, text):
        self._enable_save()

    def _cb_help_button_clicked(self):
        QuickHelp.show(
            QC.translate("firewall",
                         "You can use ',' or '-' to specify multiple ports/IPs or ranges/values:<br><br>" \
                         "ports: 22 or 22,443 or 50000-60000<br>" \
                         "IPs: 192.168.1.1 or 192.168.1.30-192.168.1.130<br>" \
                         "Values: echo-reply,echo-request<br>" \
                         "Values: new,established,related"
                         )
        )


    def _cb_close_clicked(self):
        self._close()

    def _cb_delete_clicked(self):
        node_addr, node, chain, err = self.form_to_protobuf()
        if err != None:
            self._set_status_error(QC.translate("firewall", "Invalid rule: {0}".format(err)))
            return

        self._set_status_message(QC.translate("firewall", "Deleting rule, wait"))
        ok, fw_config = self._fw.delete_rule(node_addr, self.uuid)
        if not ok:
            self._set_status_error(QC.translate("firewall", "Error updating rule"))
            return

        if self.comboNodes.currentIndex() == 0:
            self.send_notifications(node['firewall'], self.OP_DELETE)
        else:
            self.send_notification(node_addr, node['firewall'], self.OP_DELETE)

    def _cb_save_clicked(self):
        if len(self.statements) == 0:
            self._set_status_message(QC.translate("firewall", "Add at least one statement."))
            return
        node_addr, node, chain, err = self.form_to_protobuf()
        if err != None:
            self._set_status_error(QC.translate("firewall", "Invalid rule: {0}".format(err)))
            return

        self._set_status_message(QC.translate("firewall", "Adding rule, wait"))
        ok, err = self._fw.update_rule(node_addr, self.uuid, chain)
        if not ok:
            self._set_status_error(QC.translate("firewall", "Error updating rule ({0}): {1}".format(node_addr, err)))
            return

        self._enable_buttons(False)
        if self.comboNodes.currentIndex() == 0:
            self.send_notification(node_addr, node['firewall'], self.OP_SAVE, self.uuid)
        else:
            self.send_notifications(node['firewall'], self.OP_SAVE)

    def _cb_reset_clicked(self):
        self._reset_widgets("", self.toolBoxSimple)
        self.add_new_statement(QC.translate("firewall", "<select a statement>"), self.toolBoxSimple)

    def _cb_add_clicked(self):
        if len(self.statements) == 0:
            self._set_status_message(QC.translate("firewall", "Add at least one statement."))
            return
        node_addr, node, chain, err = self.form_to_protobuf()
        if err != None:
            self._set_status_error(QC.translate("firewall", "Invalid rule: {0}".format(err)))
            return

        ok, err = self._fw.insert_rule(node_addr, chain)
        if not ok:
            self._set_status_error(QC.translate("firewall", "Error adding rule: {0}".format(err)))
            return
        self._set_status_message(QC.translate("firewall", "Adding rule, wait"))
        self._enable_buttons(False)

        if self.comboNodes.currentIndex() == 0:
            self.send_notification(node_addr, node['firewall'], self.OP_NEW, chain.Rules[0].UUID)
        else:
            self.send_notifications(node['firewall'], self.OP_NEW)

    def _cb_add_new_statement(self):
        self._enable_save()
        self.add_new_statement(QC.translate("firewall", "<select a statement>"), self.toolBoxSimple)

    def _cb_del_statement(self):
        self._enable_save()

        idx = self.toolBoxSimple.currentIndex()
        if idx < 0:
            return

        if idx in self.statements:
            del self.statements[idx]

        w = self.toolBoxSimple.widget(idx)
        if w != None:
            w.setParent(None)

        self._reorder_toolbox_pages()

    def _cb_statem_combo_changed(self, idx):
        self._enable_save()

        st_idx = self.toolBoxSimple.currentIndex()
        self._configure_statem_value_opts(st_idx)
        w = self.statements[st_idx]
        tidx = 0 if idx == 0 else idx-1
        w['value'].setToolTip(self.STATM_CONF[tidx]['tooltip'])
        self._set_statement_title(st_idx, w['value'].currentText())

    def _cb_statem_value_changed(self, val):
        self._enable_save()

        st_idx = self.toolBoxSimple.currentIndex()
        self._set_statement_title(st_idx)

    def _cb_statem_value_index_changed(self, idx):
        self._enable_save()

        st_idx = self.toolBoxSimple.currentIndex()
        w = self.statements[st_idx]
        idx = w['what'].currentIndex()-1 # first item is blank
        val = w['value'].currentText().lower()
        if idx != -1 and (idx == self.STATM_SPORT or idx == self.STATM_DPORT):
            # automagically choose the protocol for the selected port:
            # echo/7 (tcp) -> tcp
            if Fw.PortProtocols.TCP.value in val:
                w['opts'].setCurrentIndex(
                    Fw.PortProtocols.values().index(Fw.PortProtocols.TCP.value)
                )
            elif Fw.PortProtocols.UDP.value in val:
                w['opts'].setCurrentIndex(
                    Fw.PortProtocols.values().index(Fw.PortProtocols.UDP.value)
                )
        self._set_statement_title(st_idx)

    def _cb_statem_op_changed(self, idx):
        self._enable_save()

        st_idx = self.toolBoxSimple.currentIndex()
        self._set_statement_title(st_idx)

    def _cb_statem_opts_changed(self, idx):
        self._enable_save()

        st_idx = self.toolBoxSimple.currentIndex()
        self._set_statement_title(st_idx)

    def _cb_direction_changed(self, idx):
        self._enable_save()

        self._is_valid_rule()

    def _cb_verdict_changed(self, idx):
        self._enable_save()

        showVerdictParms = self._has_verdict_parms(idx)
        self.lineVerdictParms.setVisible(showVerdictParms)
        self.comboVerdictParms.setVisible(showVerdictParms)
        self._configure_verdict_parms(idx)


    def _cb_verdict_parms_changed(self, idx):
        self._enable_save()

    def _is_valid_rule(self):
        if (self.comboVerdict.currentText().lower() == Config.ACTION_REDIRECT or \
            self.comboVerdict.currentText().lower() == Config.ACTION_TPROXY or \
            self.comboVerdict.currentText().lower() == Config.ACTION_DNAT) and \
             (self.comboDirection.currentIndex() == self.IN or self.comboDirection.currentIndex() == self.POSTROUTING):
            self._set_status_message(
                QC.translate(
                    "firewall",
                    "{0} cannot be used with IN or POSTROUTING directions.".format(self.comboVerdict.currentText().upper())
                )
            )
            return False
        elif self.comboVerdict.currentText().lower() == Config.ACTION_SNAT and \
             self.comboDirection.currentIndex() != self.POSTROUTING:
            self._set_status_message(
                QC.translate(
                    "firewall",
                    "{0} can only be used with POSTROUTING.".format(self.comboVerdict.currentText().upper())
                )
            )
            self.comboDirection.setCurrentIndex(self.POSTROUTING)
            return False

        self._set_status_message("")
        return True

    def _has_verdict_parms(self, idx):
        # TODO:
        # Fw.Verdicts.values()[idx+1] == Config.ACTION_REJECT or \
        # Fw.Verdicts.values()[idx+1] == Config.ACTION_JUMP or \
        return Fw.Verdicts.values()[idx+1] == Config.ACTION_QUEUE or \
            Fw.Verdicts.values()[idx+1] == Config.ACTION_REDIRECT or \
            Fw.Verdicts.values()[idx+1] == Config.ACTION_TPROXY or \
            Fw.Verdicts.values()[idx+1] == Config.ACTION_DNAT or \
            Fw.Verdicts.values()[idx+1] == Config.ACTION_SNAT or \
            Fw.Verdicts.values()[idx+1] == Config.ACTION_MASQUERADE

    def _configure_verdict_parms(self, idx):
        self.comboVerdictParms.clear()

        verdict = Fw.Verdicts.values()[idx+1]
        if verdict == Config.ACTION_QUEUE:
            self.comboVerdictParms.addItem(QC.translate("firewall", "num"), "num")

        elif verdict == Config.ACTION_JUMP:
            self.comboVerdictParms.setVisible(False)

        elif verdict == Config.ACTION_REDIRECT or \
            verdict == Config.ACTION_TPROXY or \
            verdict == Config.ACTION_SNAT or \
            verdict == Config.ACTION_DNAT:
            self.comboVerdictParms.addItem(QC.translate("firewall", "to"), "to")

        elif verdict == Config.ACTION_MASQUERADE:
            # for persistent,fully-random,etc, options
            self.comboVerdictParms.addItem("")
            self.comboVerdictParms.addItem(QC.translate("firewall", "to"), "to")

        # https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT)#Redirect
        if (verdict == Config.ACTION_REDIRECT or verdict == Config.ACTION_DNAT) and \
                (self.comboDirection.currentIndex() != self.OUT and self.comboDirection.currentIndex() != self.PREROUTING):
            self.comboDirection.setCurrentIndex(self.OUT)

        elif self.comboVerdict.currentText().lower() == Config.ACTION_SNAT and \
             self.comboDirection.currentIndex() != self.POSTROUTING:
            self.comboDirection.setCurrentIndex(self.POSTROUTING)

    def _reorder_toolbox_pages(self):
        tmp = {}
        for i,k in enumerate(self.statements):
            tmp[i] = self.statements[k]
        self.statements = tmp

    def _reset_widgets(self, title, topWidget):
        for i in range(topWidget.count()):
            topWidget.removeItem(i)
            w = topWidget.widget(i)
            if w is not None:
                w.setParent(None)

        self.statements = {}
        self.st_num = 0

        # if we don't do this, toolbox's subwidgets are not deleted (removed
        # from the GUI, but not deleted), so sometimes after loading/closing several rules,
        # you may end up with rules mixed on the same layout/form.
        self.toolBoxSimple.setParent(None)
        self.toolBoxSimple = QtWidgets.QToolBox()
        self.tabWidget.widget(0).layout().addWidget(self.toolBoxSimple)
        #self.toolBoxSimple.currentChanged.connect(self._cb_toolbox_page_changed)

    def _set_statement_title(self, st_idx, value=None):
        """Transform the widgets to nftables rule text format
        """
        self._reset_status_message()
        self.toolBoxSimple.setItemText(st_idx, "")
        w = self.statements[st_idx]
        idx = w['what'].currentIndex()-1 # first item is blank
        if idx == -1:
            return

        st = self.STATM_CONF[idx]['name']
        st_opts = w['opts'].currentText()
        if idx == self.STATM_DEST_IP or idx == self.STATM_SOURCE_IP:
            st = st_opts
        if idx == self.STATM_DPORT or idx == self.STATM_SPORT:
            st = st_opts

        title = st
        for keys in self.STATM_CONF[idx]['keys']:
            title += " " + keys['key']
        st_op = Fw.Operator.values()[w['op'].currentIndex()]
        st_val = w['value'].currentText()
        if value != None:
            st_val = value

        # override previous setup for some statements
        if idx == self.STATM_META:
            title = "{0} {1} {2} {3}".format(st, st_opts, st_op, st_val)
        elif idx == self.STATM_QUOTA:
            title = "{0} {1} {2}".format(st, st_opts, st_val)
        elif idx == self.STATM_LIMIT:
            title = "{0} {1} {2}".format(st, st_opts, st_val)
        else:
            title = "{0} {1} {2}".format(title, st_op, st_val)

        self.toolBoxSimple.setItemText(st_idx, title)

    def _configure_statem_value_opts(self, st_idx):
        w = self.statements[st_idx]
        idx = w['what'].currentIndex()-1 # first item is blank
        if idx == -1:
            return

        w['value'].blockSignals(True);
        w['opts'].blockSignals(True);

        oldValue = w['value'].currentText()
        w['value'].clear()
        for k in self.STATM_CONF[idx]['keys']:
            if k['values'] == None:
                continue
            w['value'].addItems(k['values'])
        w['value'].setCurrentText(oldValue)

        w['opts'].clear()
        if idx == self.STATM_DPORT or \
            idx == self.STATM_SPORT:
            w['op'].setVisible(True)
            w['opts'].setVisible(True)
            w['opts'].addItems(Fw.PortProtocols.values())

        elif idx == self.STATM_DEST_IP or \
            idx == self.STATM_SOURCE_IP:
            w['op'].setVisible(True)
            w['opts'].setVisible(True)
            w['opts'].addItems(Fw.Family.values())
            w['opts'].removeItem(0) # remove 'inet' item

        elif idx == self.STATM_IIFNAME or idx == self.STATM_OIFNAME:
            w['op'].setVisible(True)
            w['opts'].setVisible(False)
            if self._nodes.is_local(self.comboNodes.currentText()):
                w['value'].addItems(NetworkInterfaces.list().keys())
                w['value'].setCurrentText("")

        elif idx == self.STATM_META:
            w['op'].setVisible(True)
            w['opts'].setVisible(True)
            # exclude first item of the list
            w['opts'].addItems(Fw.ExprMeta.values()[1:])

        elif idx == self.STATM_ICMP or idx == self.STATM_ICMPv6 or \
            idx == self.STATM_CT_STATE or idx == self.STATM_CT_MARK:
            w['op'].setVisible(True)
            w['opts'].setVisible(False)

        elif idx == self.STATM_LOG:
            w['op'].setVisible(False)
            w['opts'].setVisible(True)
            w['opts'].addItems(Fw.ExprLogLevels.values())
            w['opts'].setCurrentIndex(
                # nftables default log level is warn
                Fw.ExprLogLevels.values().index(Fw.ExprLogLevels.WARN.value)
            )
        elif idx == self.STATM_QUOTA or idx == self.STATM_LIMIT:
            w['op'].setVisible(False)
            w['opts'].setVisible(True)
            w['opts'].addItems([Fw.ExprQuota.OVER.value, Fw.ExprQuota.UNTIL.value])
        else:
            w['op'].setVisible(False)
            w['opts'].setVisible(False)

        w['opts'].blockSignals(False);
        w['value'].blockSignals(False);

    def add_new_statement(self, title="", topWidget=None):
        """Creates dynamically the widgets to define firewall rules:
            statement (dst port, dst ip, log), protocol, operator (==, !=,...)
            and value (443, 1.1.1.1, etc)
            Some expressions may have different options (protocol, family, options, etc)
        """
        w = QtWidgets.QWidget()
        w.setParent(topWidget)
        l = QtWidgets.QVBoxLayout(w)

        boxH1 = QtWidgets.QHBoxLayout()
        boxH2 = QtWidgets.QHBoxLayout()
        l.addLayout(boxH1)
        l.addLayout(boxH2)

        # row 1: | statement | protocol |
        stWidget = QtWidgets.QComboBox(w)
        stWidget.addItems(self.STATM_LIST)

        prots = ["TCP", "UDP", "ICMP"]
        stOptsWidget = QtWidgets.QComboBox(w)
        stOptsWidget.setSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Fixed)
        stOptsWidget.addItems(prots)

        # row 2: | operator | value |
        ops = [
            QC.translate("firewall", "Equal"),
            QC.translate("firewall", "Not equal"),
            QC.translate("firewall", "Greater or equal than"),
            QC.translate("firewall", "Greater than"),
            QC.translate("firewall", "Less or equal than"),
            QC.translate("firewall", "Less than")
        ]
        stOpWidget = QtWidgets.QComboBox(w)
        stOpWidget.setSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Fixed)
        stOpWidget.addItems(ops)

        stValueWidget = QtWidgets.QComboBox(w)
        stValueWidget.setEditable(True)
        stValueWidget.setSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        stValueWidget.setCurrentText("")

        # add statement, proto/opts, operator and value
        boxH1.addWidget(stWidget)
        boxH1.addWidget(stOptsWidget)
        boxH2.addWidget(stOpWidget)
        boxH2.addWidget(stValueWidget)
        w.setLayout(l)

        # insert page after current index
        curIdx = self.toolBoxSimple.currentIndex()
        topWidget.insertItem(curIdx+1, w, title)
        topWidget.setCurrentIndex(curIdx+1)

        # if current index is not the last one, reorder statements
        if curIdx+1 != self.st_num:
            for i in range(curIdx+1, self.st_num):
                if i in self.statements:
                    self.statements[i+1] = self.statements[i]

        self.statements[curIdx+1] = {
            'what': stWidget,
            'opts': stOptsWidget,
            'op': stOpWidget,
            'value': stValueWidget
        }

        stWidget.currentIndexChanged.connect(self._cb_statem_combo_changed)
        stOpWidget.currentIndexChanged.connect(self._cb_statem_op_changed)
        stOptsWidget.currentIndexChanged.connect(self._cb_statem_opts_changed)
        stValueWidget.currentIndexChanged.connect(self._cb_statem_value_index_changed)
        stValueWidget.currentTextChanged.connect(self._cb_statem_value_changed)

        self.st_num += 1

    def _load_nodes(self):
        self.comboNodes.clear()
        self._node_list = self._nodes.get()
        #self.comboNodes.addItem(QC.translate("firewall", "All"))
        for addr in self._node_list:
            self.comboNodes.addItem(addr)

        if len(self._node_list) == 0:
            self.tabWidget.setDisabled(True)

    def _load_meta_statement(self, exp, idx):
        try:
            isMultiProto = False
            isSetMark = False
            newStatm = self.STATM_SPORT
            newValue = ""
            optsValue = ""
            for v in exp.Statement.Values:
                if v.Key ==  Fw.ExprMeta.SET.value:
                    isSetMark = True
                    continue
                if isSetMark and v.Key == Fw.ExprMeta.MARK.value:
                    newStatm = self.STATM_META_SET_MARK
                    if self._is_valid_int_value(v.Value):
                        newValue = v.Value
                    else:
                        self._set_status_error(
                            QC.translate(
                                "firewall",
                                "Invalid mark ({0})".format(v.Value)
                            )
                        )
                    break

                if v.Key ==  Fw.ExprMeta.L4PROTO.value:
                    optsValue = v.Value
                if v.Key == Fw.Statements.SPORT.value:
                    isMultiProto = True
                    newValue = v.Value
                    break
                elif v.Key == Fw.Statements.DPORT.value:
                    newStatm = self.STATM_DPORT
                    isMultiProto = True
                    newValue = v.Value
                    break

            if isSetMark:
                self.statements[idx]['what'].setCurrentIndex(newStatm+1)
                self.statements[idx]['value'].setCurrentText(newValue)

            elif isMultiProto:
                self.statements[idx]['what'].setCurrentIndex(newStatm+1)
                self.statements[idx]['opts'].setCurrentIndex(
                    Fw.PortProtocols.values().index(optsValue)
                )
                try:
                    self.statements[idx]['value'].setCurrentIndex(
                        self.net_srv.index_by_port(newValue)
                    )
                except:
                    self.statements[idx]['value'].setCurrentText(newValue)

            else:
                self.statements[idx]['what'].setCurrentIndex(self.STATM_META+1)
                self.statements[idx]['opts'].setCurrentIndex(
                    # first item of the list is "set", not present in the combobox
                    Fw.ExprMeta.values().index(exp.Statement.Values[0].Key)-1
                )
                self.statements[idx]['value'].setCurrentText(exp.Statement.Values[0].Value)

        except Exception as e:
            print("_load_meta_statement() exception:", e)
            self._set_status_message(e)

    def _load_limit_statement(self, exp, idx):
        try:
            self.statements[idx]['what'].setCurrentIndex(self.STATM_LIMIT+1)
            self.statements[idx]['opts'].setCurrentIndex(1)
            lval = ""
            for v in exp.Statement.Values:
                if v.Key == Fw.ExprLimit.OVER.value:
                    self.statements[idx]['opts'].setCurrentIndex(0)
                elif v.Key == Fw.ExprLimit.UNITS.value:
                    lval = v.Value
                elif v.Key == Fw.ExprLimit.RATE_UNITS.value:
                    lval = "%s/%s" % (lval, v.Value)
                elif v.Key == Fw.ExprLimit.TIME_UNITS.value:
                    lval = "%s/%s" % (lval, v.Value)

            self.statements[idx]['value'].setCurrentText(lval)
        except Exception as e:
            print("_load_limit_statement() exception:", e)
            self._set_status_message(e)

    def _load_ct_statement(self, exp, idx):
        """load CT statements, for example:
            Name: ct, Key: set, Key: mark, Value: 123
            Name: ct, Key: mark, Value: 123
            Name: ct, Key: state, value: new,established
        """
        try:
            if exp.Statement.Values[0].Key == Fw.ExprCt.STATE.value:
                self.statements[idx]['what'].setCurrentIndex(self.STATM_CT_STATE+1)
                self.statements[idx]['value'].setCurrentText(exp.Statement.Values[0].Value)
                for v in exp.Statement.Values:
                    curText = self.statements[idx]['value'].currentText()
                    if v.Value not in curText:
                        self.statements[idx]['value'].setCurrentText(
                            "{0},{1}".format(
                                curText,
                                v.Value
                            )
                        )

            elif exp.Statement.Values[0].Key == Fw.ExprCt.SET.value:
                self.statements[idx]['what'].setCurrentIndex(self.STATM_CT_SET+1)
                markVal = ""
                for v in exp.Statement.Values:
                    if v.Key == Fw.ExprCt.MARK.value:
                        markVal = v.Value
                        break

                self.statements[idx]['value'].setCurrentText(markVal)
                if markVal == "":
                    raise ValueError(
                        QC.translate("firewall", "Warning: ct set mark value is empty, malformed rule?")
                    )

            elif exp.Statement.Values[0].Key == Fw.ExprCt.MARK.value:
                self.statements[idx]['what'].setCurrentIndex(self.STATM_CT_MARK+1)
                self.statements[idx]['value'].setCurrentText(exp.Statement.Values[0].Value)

        except Exception as e:
            print("_load_ct_statement() exception:", e)
            self._set_status_message(e)

    def load(self, addr, uuid):
        if not self.show():
            return

        self.FORM_TYPE = self.FORM_TYPE_SIMPLE
        self.setWindowTitle(QC.translate("firewall", "Firewall rule"))
        self.cmdDelete.setVisible(True)
        self.cmdSave.setVisible(True)
        self.cmdAdd.setVisible(False)
        self.checkEnable.setVisible(True)
        self.checkEnable.setEnabled(True)
        self.checkEnable.setChecked(True)
        self.frameDirection.setVisible(True)
        self.comboNodes.setCurrentText(addr)

        self._enable_buttons()

        self.uuid = uuid

        node, rule = self._fw.get_rule_by_uuid(uuid)
        if rule == None or \
                (rule.Hook.lower() != Fw.Hooks.INPUT.value and \
                 rule.Hook.lower() != Fw.Hooks.FORWARD.value and \
                 rule.Hook.lower() != Fw.Hooks.PREROUTING.value and \
                 rule.Hook.lower() != Fw.Hooks.POSTROUTING.value and \
                 rule.Hook.lower() != Fw.Hooks.OUTPUT.value):
            hook = "invalid" if rule == None else rule.Hook
            self._set_status_error(QC.translate("firewall", "Rule hook ({0}) not supported yet".format(hook)))
            self._disable_controls()
            return

        self.checkEnable.setChecked(rule.Rules[0].Enabled)
        self.lineDescription.setText(rule.Rules[0].Description)

        self.tabWidget.blockSignals(True);
        self.hboxAdvanced.setVisible(True)
        self._reset_widgets("", self.toolBoxSimple)
        self.tabWidget.setCurrentIndex(0)

        if len(rule.Rules[0].Expressions) <= 1:
            self.tabWidget.setTabText(0, QC.translate("firewall", "Simple"))
            self.add_new_statement("", self.toolBoxSimple)
        else:
            for i in enumerate(rule.Rules[0].Expressions):
                self.add_new_statement("", self.toolBoxSimple)
            self.tabWidget.setTabText(0, QC.translate("firewall", "Advanced"))

        self.tabWidget.blockSignals(False);

        isNotSupported = False
        idx = 0
        for exp in rule.Rules[0].Expressions:
            #print(idx, "|", exp)

            # set current page, so the title and opts of each statement is
            # configured properly.
            self.toolBoxSimple.setCurrentIndex(idx)

            if Fw.Utils.isExprPort(exp.Statement.Name):
                if exp.Statement.Values[0].Key == Fw.Statements.DPORT.value:
                    self.statements[idx]['what'].setCurrentIndex(self.STATM_DPORT+1)
                elif exp.Statement.Values[0].Key == Fw.Statements.SPORT.value:
                    self.statements[idx]['what'].setCurrentIndex(self.STATM_SPORT+1)

                try:
                    self.statements[idx]['value'].setCurrentIndex(
                        self.net_srv.index_by_port(exp.Statement.Values[0].Value)
                    )
                except:
                    self.statements[idx]['value'].setCurrentText(exp.Statement.Values[0].Value)

                st_name = exp.Statement.Name
                self.statements[idx]['opts'].setCurrentIndex(
                    Fw.PortProtocols.values().index(st_name.lower())
                )

            elif exp.Statement.Name == Fw.Statements.IP.value or exp.Statement.Name == Fw.Statements.IP6.value:
                if exp.Statement.Values[0].Key == Fw.Statements.DADDR.value:
                    self.statements[idx]['what'].setCurrentIndex(self.STATM_DEST_IP+1)
                elif exp.Statement.Values[0].Key == Fw.Statements.SADDR.value:
                    self.statements[idx]['what'].setCurrentIndex(self.STATM_SOURCE_IP+1)

                self.statements[idx]['value'].setCurrentText(exp.Statement.Values[0].Value)

                st_name = exp.Statement.Name
                self.statements[idx]['opts'].setCurrentIndex(
                    Fw.Family.values().index(st_name.lower())-1 # first item does not apply
                )

            elif exp.Statement.Name == Fw.Statements.IIFNAME.value:
                self.statements[idx]['what'].setCurrentIndex(self.STATM_IIFNAME+1)
                self.statements[idx]['value'].setCurrentText(exp.Statement.Values[0].Key)

            elif exp.Statement.Name == Fw.Statements.OIFNAME.value:
                self.statements[idx]['what'].setCurrentIndex(self.STATM_OIFNAME+1)
                self.statements[idx]['value'].setCurrentText(exp.Statement.Values[0].Key)

            elif exp.Statement.Name == Fw.Statements.CT.value:
                self._load_ct_statement(exp, idx)

            elif exp.Statement.Name == Fw.Statements.META.value:
                self._load_meta_statement(exp, idx)

            elif exp.Statement.Name == Fw.Statements.ICMP.value or exp.Statement.Name == Fw.Statements.ICMPv6.value:
                if exp.Statement.Name == Fw.Statements.ICMP.value:
                    self.statements[idx]['what'].setCurrentIndex(self.STATM_ICMP+1)
                else:
                    self.statements[idx]['what'].setCurrentIndex(self.STATM_ICMPv6+1)

                self.statements[idx]['value'].setCurrentText(exp.Statement.Values[0].Value)
                for v in exp.Statement.Values:
                    curText = self.statements[idx]['value'].currentText()
                    if v.Value not in curText:
                        self.statements[idx]['value'].setCurrentText(
                            "{0},{1}".format(
                                curText,
                                v.Value
                            )
                        )

            elif exp.Statement.Name == Fw.Statements.LOG.value:
                self.statements[idx]['what'].setCurrentIndex(self.STATM_LOG+1)

                for v in exp.Statement.Values:
                    if v.Key == Fw.ExprLog.PREFIX.value:
                        self.statements[idx]['value'].setCurrentText(v.Value)
                    elif v.Key == Fw.ExprLog.LEVEL.value:
                        try:
                            lvl = Fw.ExprLogLevels.values().index(v.Value)
                        except:
                            lvl = Fw.ExprLogLevels.values().index(Fw.ExprLogLevels.WARN.value)
                        self.statements[idx]['opts'].setCurrentIndex(lvl)

            elif exp.Statement.Name == Fw.Statements.QUOTA.value:
                self.statements[idx]['what'].setCurrentIndex(self.STATM_QUOTA+1)
                self.statements[idx]['opts'].setCurrentIndex(1)
                for v in exp.Statement.Values:
                    if v.Key == Fw.ExprQuota.OVER.value:
                        self.statements[idx]['opts'].setCurrentIndex(0)
                    else:
                        self.statements[idx]['value'].setCurrentText(
                            "{0}/{1}".format(v.Value, v.Key)
                        )

            elif exp.Statement.Name == Fw.Statements.LIMIT.value:
                self._load_limit_statement(exp, idx)

            elif exp.Statement.Name == Fw.Statements.COUNTER.value:
                self.statements[idx]['what'].setCurrentIndex(self.STATM_COUNTER+1)
                for v in exp.Statement.Values:
                    if v.Key == Fw.ExprCounter.NAME.value:
                        self.statements[idx]['value'].setCurrentText(v.Value)

            else:
                isNotSupported = True
                break

            # a statement may not have an operator. It's assumed that it's the
            # equal operator.
            op = Fw.Operator.EQUAL.value if exp.Statement.Op == "" else exp.Statement.Op
            self.statements[idx]['op'].setCurrentIndex(
                Fw.Operator.values().index(op)
            )

            idx+=1

        if isNotSupported:
            self._set_status_error(QC.translate("firewall", "This rule is not supported yet."))
            self._disable_controls()
            return

        if rule.Hook.lower() == Fw.Hooks.INPUT.value:
            self.comboDirection.setCurrentIndex(self.IN)
        elif rule.Hook.lower() == Fw.Hooks.OUTPUT.value:
            self.comboDirection.setCurrentIndex(self.OUT)
        elif rule.Hook.lower() == Fw.Hooks.FORWARD.value:
            self.comboDirection.setCurrentIndex(self.FORWARD)
        elif rule.Hook.lower() == Fw.Hooks.PREROUTING.value:
            self.comboDirection.setCurrentIndex(self.PREROUTING)
        elif rule.Hook.lower() == Fw.Hooks.POSTROUTING.value:
            self.comboDirection.setCurrentIndex(self.POSTROUTING)
        # TODO: changing the direction of an existed rule needs work, it causes
        # some nasty effects. Disabled for now.
        self.comboDirection.setEnabled(False)

        try:
            self.comboVerdict.setCurrentIndex(
                Fw.Verdicts.values().index(
                    rule.Rules[0].Target.lower()
                )-1
            )
            if self._has_verdict_parms(self.comboVerdict.currentIndex()):
                tparms = rule.Rules[0].TargetParameters.lower()
                parts = tparms.split(" ")
                self.lineVerdictParms.setText(parts[1])
                if parts[1] == "":
                    print("Firewall Rule: verdict parms error:", parts)
        except:
            self._set_status_error(QC.translate("firewall", "Rule target ({0}) not supported yet".format(rule.Rules[0].Target.lower())))
            self._disable_controls()

        self._enable_save(False)

    def new(self):
        if not self.show():
            return

        self._reset_widgets("", self.toolBoxSimple)
        self.FORM_TYPE = self.FORM_TYPE_SIMPLE
        self.setWindowTitle(QC.translate("firewall", "Firewall rule"))
        self.cmdDelete.setVisible(False)
        self.cmdSave.setVisible(False)
        self.cmdAdd.setVisible(True)
        self.checkEnable.setVisible(True)
        self.checkEnable.setEnabled(True)
        self.checkEnable.setChecked(True)
        self.frameDirection.setVisible(True)

        self.cmdSave.setVisible(False)
        self.cmdDelete.setVisible(False)
        self.cmdAdd.setVisible(True)

        self.hboxAdvanced.setVisible(True)
        self.tabWidget.setTabText(0, "")
        self.tabWidget.setCurrentIndex(0)
        self.add_new_statement("", self.toolBoxSimple)

    def exclude_service(self, direction):
        if not self.show():
            return

        self._reset_widgets("", self.toolBoxSimple)
        self.setWindowTitle(QC.translate("firewall", "Exclude service"))
        self.cmdDelete.setVisible(False)
        self.cmdSave.setVisible(False)
        self.cmdReset.setVisible(False)
        self.cmdAdd.setVisible(True)
        self.checkEnable.setVisible(False)
        self.checkEnable.setEnabled(True)
        self.tabWidget.setTabText(0, "")
        self.hboxAdvanced.setVisible(False)

        dirPort = self.STATM_DPORT+1
        self.FORM_TYPE = self.FORM_TYPE_ALLOW_IN_SERVICE
        self.lblExcludeTip.setText(QC.translate("firewall", "Allow inbound connections to the selected port."))
        if direction == self.OUT:
            self.lblExcludeTip.setText(QC.translate("firewall", "Allow outbound connections to the selected port."))
            self.FORM_TYPE = self.FORM_TYPE_EXCLUDE_SERVICE
            dirPort = self.STATM_DPORT+1

        self.add_new_statement("", self.toolBoxSimple)
        self.statements[0]['what'].setCurrentIndex(dirPort)
        self.statements[0]['what'].setVisible(False)
        self.statements[0]['op'].setVisible(False)
        self.statements[0]['value'].setCurrentText("")

        self.frameDirection.setVisible(False)
        self.lblExcludeTip.setVisible(True)

        self.checkEnable.setChecked(True)

    def form_to_protobuf(self):
        """Transform form widgets to protobuf struct
        """
        chain = Fw.ChainFilter.input()
        # XXX: tproxy does not work with destnat+output
        if self.comboDirection.currentIndex() == self.OUT and \
            (self.comboVerdict.currentIndex()+1 == Fw.Verdicts.values().index(Config.ACTION_TPROXY) or \
                self.comboVerdict.currentIndex()+1 == Fw.Verdicts.values().index(Config.ACTION_DNAT) or \
                self.comboVerdict.currentIndex()+1 == Fw.Verdicts.values().index(Config.ACTION_REDIRECT)
            ):
            chain = Fw.ChainDstNAT.output()
        elif self.comboDirection.currentIndex() == self.FORWARD:
            chain = Fw.ChainMangle.forward()
        elif self.comboDirection.currentIndex() == self.PREROUTING:
            chain = Fw.ChainDstNAT.prerouting()
        elif self.comboDirection.currentIndex() == self.POSTROUTING:
            chain = Fw.ChainDstNAT.postrouting()

        elif self.comboDirection.currentIndex() == self.OUT or self.FORM_TYPE == self.FORM_TYPE_EXCLUDE_SERVICE:
            chain = Fw.ChainMangle.output()
        elif self.comboDirection.currentIndex() == self.IN or self.FORM_TYPE == self.FORM_TYPE_ALLOW_IN_SERVICE:
            chain = Fw.ChainFilter.input()

        verdict_idx = self.comboVerdict.currentIndex()
        verdict = Fw.Verdicts.values()[verdict_idx+1] # index 0 is ""
        _target_parms = ""
        if self._has_verdict_parms(verdict_idx):
            if self.lineVerdictParms.text() == "":
                return None, None, None, QC.translate("firewall", "Verdict ({0}) parameters cannot be empty.".format(verdict))

            # these verdicts parameters need ":" to specify a port or ip:port
            if (self.comboVerdict.currentText().lower() == Config.ACTION_REDIRECT or \
                self.comboVerdict.currentText().lower() == Config.ACTION_TPROXY or \
                self.comboVerdict.currentText().lower() == Config.ACTION_SNAT or \
                self.comboVerdict.currentText().lower() == Config.ACTION_DNAT) and \
                    ":" not in self.lineVerdictParms.text():
                return None, None, None, QC.translate("firewall", "Verdict ({0}) parameters format is: <IP>:port.".format(verdict))

            if self.comboVerdict.currentText().lower() == Config.ACTION_QUEUE:
                try:
                    t = int(self.lineVerdictParms.text())
                except:
                    return None, None, None, QC.translate("firewall", "Verdict ({0}) parameters format must be a number".format(verdict))

            vidx = self.comboVerdictParms.currentIndex()
            _target_parms = "{0} {1}".format(
                self.comboVerdictParms.itemData(vidx),
                self.lineVerdictParms.text().replace(" ", "")
            )

        rule = Fw.Rules.new(
            enabled=self.checkEnable.isChecked(),
            _uuid=self.uuid,
            description=self.lineDescription.text(),
            target=verdict,
            target_parms=_target_parms
        )

        for k in self.statements:
            st_idx = self.statements[k]['what'].currentIndex()-1
            if st_idx == -1:
                return None, None, None, QC.translate("firewall", "select a statement.")

            statement = self.STATM_CONF[st_idx]['name']
            statem_keys = self.STATM_CONF[st_idx]['keys']
            statem_op = Fw.Operator.values()[self.statements[k]['op'].currentIndex()]
            statem_opts = self.statements[k]['opts'].currentText().lower()

            key_values = []
            for sk in statem_keys:
                if sk['values'] == None:
                    key_values.append((sk['key'], ""))
                else:
                    statem_value = self.statements[k]['value'].currentText()
                    val_idx = self.statements[k]['value'].currentIndex()

                    if statem_value == "" or (statem_value == "0" and st_idx != self.STATM_META):
                        return None, None, None, QC.translate("firewall", "value cannot be 0 or empty.")

                    if st_idx == self.STATM_QUOTA:
                        if sk['key'] == Fw.ExprQuota.OVER.value:
                            if self.statements[k]['opts'].currentIndex() == 0:
                                key_values.append((sk['key'], ""))
                            continue
                        elif sk['key'] == Fw.ExprQuota.UNIT.value or sk['key'] in Fw.RateUnits.values():
                            units = statem_value.split("/")
                            if len(units) != 2: # we expect the format key/value
                                return None, None, None, QC.translate("firewall", "the value format is 1024/kbytes (or bytes, mbytes, gbytes)")
                            if units[1] not in Fw.RateUnits.values():
                                return None, None, None, QC.translate("firewall", "the value format is 1024/kbytes (or bytes, mbytes, gbytes)")

                            sk['key'] = units[1]
                            statem_value = units[0]
                            if not self._is_valid_int_value(statem_value):
                                raise ValueError("quota value is invalid ({0}). It must be value/unit (1/kbytes)".format(statem_value))

                    elif st_idx == self.STATM_LIMIT:
                        if sk['key'] == Fw.ExprLimit.OVER.value:
                            if self.statements[k]['opts'].currentIndex() == 0:
                                key_values.append((sk['key'], ""))
                        elif sk['key'] == Fw.ExprLimit.UNITS.value:
                            units = statem_value.split("/")
                            if len(units) != 3: # we expect the format key/value
                                return None, None, None, QC.translate("firewall", "the value format is 1024/kbytes/second (or bytes, mbytes, gbytes)")

                            if units[1] not in Fw.RateUnits.values():
                                return None, None, None, QC.translate("firewall", "rate-limit not valid, use: bytes, kbytes, mbytes or gbytes.")
                            if units[2] not in Fw.TimeUnits.values():
                                return None, None, None, QC.translate("firewall", "time-limit not valid, use: second, minute, hour or day")
                            key_values.append((Fw.ExprLimit.UNITS.value, units[0]))
                            key_values.append((Fw.ExprLimit.RATE_UNITS.value, units[1]))
                            key_values.append((Fw.ExprLimit.TIME_UNITS.value, units[2]))

                        continue

                    elif st_idx == self.STATM_LOG:
                        key_values.append((Fw.ExprLog.LEVEL.value, statem_opts))

                    elif st_idx == self.STATM_META:
                        sk['key'] = self.statements[k]['opts'].currentText()

                    elif st_idx == self.STATM_IIFNAME or st_idx == self.STATM_OIFNAME:
                        # for these statements, the values is set in the Key
                        # field instead of Value. Value must be empty
                        sk['key'] = statem_value
                        statem_value = ""

                    elif st_idx == self.STATM_DEST_IP or st_idx == self.STATM_SOURCE_IP:
                        statement = statem_opts
                        # convert network u.x.y.z/nn to 1.2.3.4-1.255.255.255
                        # format.
                        # FIXME: This should be supported by the daemon,
                        # instead of converting it here.
                        # TODO: validate IP ranges.
                        if "/" in statem_value:
                            try:
                                net = ipaddress.ip_network(statem_value)
                                hosts = list(net)
                                statem_value = "{0}-{1}".format(str(hosts[0]), str(hosts[-1]))
                            except Exception as e:
                                return None, None, None, QC.translate("firewall", "IP network format error, {0}".format(e))
                        elif not "-" in statem_value:
                            try:
                                ipaddress.ip_address(statem_value)
                            except Exception as e:
                                return None, None, None, QC.translate("firewall", "{0}".format(e))

                    elif st_idx == self.STATM_DPORT or st_idx == self.STATM_SPORT:
                        # if it's a tcp+udp port, we need to add a meta+l4proto
                        # statement, with the protos + ports as values.
                        optsIdx = self.statements[k]['opts'].currentIndex()
                        isMultiProto = optsIdx == 0
                        if isMultiProto:
                            meta = self.STATM_CONF[self.STATM_META]['keys'][1]
                            statement = self.STATM_CONF[self.STATM_META]['name']
                            # key: l4proto
                            key_values.append((meta['key'], statem_opts))

                        else:
                            statement = statem_opts

                        # 1. if the value is one of the /etc/services return
                        # the port
                        # 2. if the value contains , or - just use the written
                        # value, to allow multiple ports and ranges.
                        # 3. otherwise validate that the entered value is an
                        # int
                        try:
                            if "," in statem_value or "-" in statem_value:
                                raise ValueError("port entered is multiport or a port range")
                            service_idx = self.net_srv.service_by_name(statem_value)
                            statem_value = self.net_srv.port_by_index(service_idx)
                        except:
                            if "," not in statem_value and "-" not in statem_value:
                                if not self._is_valid_int_value(statem_value):
                                    return None, None, None, QC.translate("firewall", "port not valid.")

                    elif st_idx == self.STATM_CT_SET or st_idx == self.STATM_CT_MARK or st_idx == self.STATM_META_SET_MARK:
                        if not self._is_valid_int_value(statem_value):
                            return None, None, None, QC.translate("firewall", "Invalid value {0}, number expected.".format(statem_value))

                    elif st_idx == self.STATM_ICMP or st_idx == self.STATM_ICMPv6:
                        values = statem_value.split(",")
                        for val in values:
                            if val not in Fw.ExprICMP.values():
                                return None, None, None, QC.translate("firewall", "Invalid ICMP type \"{0}\".".format(val))

                    keyVal = (sk['key'], statem_value.replace(" ", ""))
                    if keyVal not in key_values:
                        key_values.append(keyVal)
                    else:
                        print("[REVIEW] statement values duplicated (there shouldn't be):", keyVal)

            exprs = Fw.Expr.new(
                statem_op,
                statement,
                key_values,
            )
            rule.Expressions.extend([exprs])
        chain.Rules.extend([rule])

        node_addr = self.comboNodes.currentText()
        node = self._nodes.get_node(node_addr)
        return node_addr, node, chain, None

    def _is_valid_int_value(self, value):
        try:
            int(value)
        except:
            return False

        return True

    def send_notification(self, node_addr, fw_config, op, uuid):
        nid, notif = self._nodes.reload_fw(node_addr, fw_config, self._notification_callback)
        self._notifications_sent[nid] = {'addr': node_addr, 'operation': op, 'notif': notif, 'uuid': uuid}

    def send_notifications(self, fw_config, op):
        for addr in self._nodes.get_nodes():
            nid, notif = self._nodes.reload_fw(addr, fw_config, self._notification_callback)
            self._notifications_sent[nid] = {'addr': addr, 'operation': op, 'notif': notif}

    def _set_status_error(self, msg):
        self.statusLabel.show()
        self.statusLabel.setStyleSheet('color: red')
        self.statusLabel.setText(msg)

    def _set_status_successful(self, msg):
        self.statusLabel.show()
        self.statusLabel.setStyleSheet('color: green')
        self.statusLabel.setText(msg)

    def _set_status_message(self, msg):
        self.statusLabel.show()
        self.statusLabel.setStyleSheet('color: darkorange')
        self.statusLabel.setText(msg)

    def _reset_status_message(self):
        self.statusLabel.setText("")
        self.statusLabel.hide()

    def _reset_fields(self):
        self.FORM_TYPE = self.FORM_TYPE_SIMPLE
        self.setWindowTitle(QC.translate("firewall", "Firewall rule"))

        self.cmdDelete.setVisible(False)
        self.cmdSave.setVisible(False)
        self.cmdAdd.setVisible(True)

        self.checkEnable.setVisible(True)
        self.checkEnable.setEnabled(True)
        self.checkEnable.setChecked(True)
        self.frameDirection.setVisible(True)
        self.lblExcludeTip.setVisible(False)
        self.lblExcludeTip.setText("")

        self._reset_status_message()
        self._enable_buttons()
        self.tabWidget.setDisabled(False)
        self.lineDescription.setText("")
        self.comboDirection.setCurrentIndex(self.IN)
        self.comboDirection.setEnabled(True)

        self.comboVerdict.blockSignals(True);
        self.comboVerdict.setCurrentIndex(0)
        self.comboVerdict.blockSignals(False);
        self.lineVerdictParms.setVisible(False)
        self.comboVerdictParms.setVisible(False)
        self.lineVerdictParms.setText("")

        self.uuid = ""

    def _enable_save(self, enable=True):
        """Enable Save buton whenever some detail of a route changes.
        The button may or not be hidden. If we're editing a rule it'll be shown
        but disabled/enabled.
        """
        self.cmdSave.setEnabled(enable)

    def _enable_buttons(self, enable=True):
        """Disable add/save buttons until a response is received from the daemon.
        """
        self.cmdSave.setEnabled(enable)
        self.cmdAdd.setEnabled(enable)
        self.cmdDelete.setEnabled(enable)

    def _disable_buttons(self, disabled=True):
        self.cmdSave.setDisabled(disabled)
        self.cmdAdd.setDisabled(disabled)
        self.cmdDelete.setDisabled(disabled)

    def _disable_controls(self):
        self._disable_buttons()
        self.tabWidget.setDisabled(True)
