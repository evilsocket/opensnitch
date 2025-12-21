import sys
import os
import os.path
import ipaddress

from PyQt6 import QtCore, uic, QtWidgets
from PyQt6.QtCore import QCoreApplication as QC

from opensnitch.config import Config
from opensnitch.nodes import Nodes
from opensnitch.utils import (
    Message,
    NetworkServices,
    QuickHelp,
    Icons,
    logger
)
import opensnitch.firewall as Fw
from opensnitch.firewall.utils import Utils as FwUtils

import opensnitch.proto as proto
ui_pb2, ui_pb2_grpc = proto.import_()

from . import (
    constants,
    notifications,
    rules,
    statements,
    utils
)

DIALOG_UI_PATH = "%s/../../res/firewall_rule.ui" % os.path.dirname(sys.modules[__name__].__file__)
class FwRuleDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):

    _notification_callback = QtCore.pyqtSignal(str, ui_pb2.NotificationReply)

    def __init__(self, parent=None, appicon=None):
        QtWidgets.QDialog.__init__(self, parent)
        self.setupUi(self)
        self.setWindowIcon(appicon)

        self.nodes = Nodes.instance()
        self.net_srv = NetworkServices()
        self.logger = logger.get(__name__)
        statements.statem_list = {}
        statements.st_num = 0
        self.FORM_TYPE = constants.FORM_TYPE_SIMPLE

        self._notification_callback.connect(self.cb_notification_callback)
        self._notifications_sent = {}

        self.uuid = ""
        self.addr = ""
        self.simple_port_idx = None

        self.nodes.nodesUpdated.connect(self.cb_nodes_updated)
        self.comboNodes.currentIndexChanged.connect(self.cb_combo_nodes_changed)
        self.cmdClose.clicked.connect(self.cb_close_clicked)
        self.cmdReset.clicked.connect(self.cb_reset_clicked)
        self.cmdAdd.clicked.connect(self.cb_add_clicked)
        self.cmdSave.clicked.connect(self.cb_save_clicked)
        self.cmdDelete.clicked.connect(self.cb_delete_clicked)
        self.helpButton.clicked.connect(self.cb_help_button_clicked)
        self.comboVerdict.currentIndexChanged.connect(self.cb_verdict_changed)
        self.lineVerdictParms.textChanged.connect(self.cb_verdict_parms_changed)
        self.checkEnable.toggled.connect(self.cb_check_enable_toggled)
        self.lineDescription.textChanged.connect(self.cb_description_changed)

        self.cmdAddStatement.clicked.connect(self.cb_add_new_statement)
        self.cmdDelStatement.clicked.connect(self.cb_del_statement)
        # remove default page
        self.toolBoxSimple.removeItem(0)
        self.add_new_statement("", self.toolBoxSimple)
        self.hboxAdvanced.setVisible(False)
        # setTabVisible not available on <= 5.14
        #self.tabWidget.setTabVisible(0, True)

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
        return self.init()

    def init(self):
        statements.statem_list = {}
        statements.st_num = 0
        self.uuid = ""
        self.addr = ""
        self.FORM_TYPE = constants.FORM_TYPE_SIMPLE
        self._notifications_sent = {}
        utils.reset_fields(self)

        if FwUtils.isProtobufSupported() is False:
            utils.disable_controls(self)
            utils.disable_buttons(self)
            utils.set_status_error(
                self,
                QC.translate(
                    "firewall",
                    "Your protobuf version is incompatible, you need to install protobuf 3.8.0 or superior\n(pip3 install --ignore-installed protobuf==3.8.0)"
                )
            )
            return False

        utils.load_nodes(self)
        self.comboDirection.currentIndexChanged.connect(self.cb_direction_changed)
        return True

    def _close(self):
        del statements.statem_list
        self.comboDirection.currentIndexChanged.disconnect(self.cb_direction_changed)
        self.hide()

    @QtCore.pyqtSlot(str, ui_pb2.NotificationReply)
    def cb_notification_callback(self, addr, reply):
        utils.enable_buttons(self)
        notifications.handle(self, addr, reply)

    @QtCore.pyqtSlot(int)
    def cb_nodes_updated(self, total):
        self.tabWidget.setDisabled(True if total == 0 else False)

    def cb_combo_nodes_changed(self, idx):
        naddr = self.comboNodes.itemData(idx)
        add = naddr != self.addr
        self.cmdSave.setVisible(not add)
        self.cmdAdd.setVisible(add)

    def closeEvent(self, e):
        self._close()

    def cb_check_enable_toggled(self, status):
        utils.enable_save(self)

    def cb_description_changed(self, text):
        utils.enable_save(self)

    def cb_help_button_clicked(self):
        QuickHelp.show(
            QC.translate(
                "firewall",
                "You can use ',' or '-' to specify multiple ports/IPs or ranges/values:<br><br>" \
                "ports: 22 or 22,443 or 50000-60000<br>" \
                "IPs: 192.168.1.1 or 192.168.1.30-192.168.1.130<br>" \
                "Values: echo-reply,echo-request<br>" \
                "Values: new,established,related"
            )
        )

    def cb_close_clicked(self):
        self._close()

    def cb_delete_clicked(self):
        self.delete()

    def cb_save_clicked(self):
        self.save()

    def cb_add_clicked(self):
        nIdx = self.comboNodes.currentIndex()
        if nIdx == 0:
            ret = Message.yes_no(
                QC.translate("stats", "This rule will be applied to all nodes"),
                QC.translate("stats", "Are you sure?"),
                QtWidgets.QMessageBox.Icon.Warning)
            if ret == QtWidgets.QMessageBox.StandardButton.Cancel:
                return

        rules.add(self, nIdx)

    def cb_reset_clicked(self):
        utils.reset_widgets(self, "", self.toolBoxSimple)
        self.add_new_statement(QC.translate("firewall", "<select a statement>"), self.toolBoxSimple)

    def cb_add_new_statement(self):
        utils.enable_save(self)
        self.add_new_statement(QC.translate("firewall", "<select a statement>"), self.toolBoxSimple)

    def cb_del_statement(self):
        self.del_statement()

    def del_statement(self):
        utils.enable_save(self)

        idx = self.toolBoxSimple.currentIndex()
        if idx < 0:
            return

        if idx in statements.statem_list:
            del statements.statem_list[idx]

        w = self.toolBoxSimple.widget(idx)
        if w is not None:
            w.setParent(None)

        self.reorder_toolbox_pages()

    def cb_statem_combo_changed(self, idx):
        utils.enable_save(self)

        st_idx = self.toolBoxSimple.currentIndex()
        statements.configure_value_opts(self, st_idx)
        w = statements.statem_list[st_idx]
        tidx = 0 if idx == 0 else idx-1
        w['value'].setToolTip(statements.CONF[tidx]['tooltip'])
        statements.set_title(self, st_idx, w['value'].currentText())

    def cb_statem_value_changed(self, val):
        utils.enable_save(self)

        st_idx = self.toolBoxSimple.currentIndex()
        statements.set_title(self, st_idx)

    def cb_statem_value_index_changed(self, idx):
        utils.enable_save(self)

        st_idx = self.toolBoxSimple.currentIndex()
        w = statements.statem_list[st_idx]
        idx = w['what'].currentIndex()-1 # first item is blank
        val = w['value'].currentText().lower()
        if idx != -1 and (idx == statements.SPORT or idx == statements.DPORT):
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
        statements.set_title(self, st_idx)

    def cb_statem_op_changed(self, idx):
        utils.enable_save(self)

        st_idx = self.toolBoxSimple.currentIndex()
        statements.set_title(self, st_idx)

    def cb_statem_opts_changed(self, idx):
        utils.enable_save(self)

        st_idx = self.toolBoxSimple.currentIndex()
        statements.set_title(self, st_idx)

    def cb_direction_changed(self, idx):
        utils.enable_save(self)
        rules.is_valid(self)

    def cb_verdict_changed(self, idx):
        utils.enable_save(self)

        showVerdictParms = rules.has_verdict_parms(self, idx)
        self.lineVerdictParms.setVisible(showVerdictParms)
        self.comboVerdictParms.setVisible(showVerdictParms)
        rules.configure_verdict_parms(self, idx)

    def cb_verdict_parms_changed(self, idx):
        utils.enable_save(self)

    def reorder_toolbox_pages(self):
        tmp = {}
        for i,k in enumerate(statements.statem_list):
            tmp[i] = statements.statem_list[k]
        statements.statem_list = tmp

    def add_new_statement(self, title="", topWidget=None):
        statements.add_new(self, title, topWidget)
        statements.st_num += 1

    def load(self, addr, uuid):
        if not self.show():
            return
        rules.load(self, addr, uuid)

    def new(self):
        if not self.show():
            return
        rules.new(self)

    def exclude_service(self, direction):
        if not self.show():
            return
        rules.exclude_service(self, direction)

    def save(self):
        if len(statements.statem_list) == 0:
            utils.set_status_message(self, QC.translate("firewall", "Add at least one statement."))
            return
        chain, err = self.form_to_protobuf()
        if err is not None:
            utils.set_status_error(self, QC.translate("firewall", "Invalid rule: {0}".format(err)))
            return

        nIdx = self.comboNodes.currentIndex()
        node_addr = self.comboNodes.itemData(nIdx)
        node = self.nodes.get_node(node_addr)
        self.logger.debug("saving rule to: %s", node_addr)

        utils.set_status_message(self, QC.translate("firewall", "Saving rule, wait"))
        if nIdx == 0:
            for addr in self.nodes.get_nodes():
                self.logger.debug("saving rule to all nodes: %s", addr)
                node = self.nodes.get_node(addr)
                err = rules.save(self, addr, node, chain, self.uuid)
                if not None:
                    utils.set_status_error(self, err)
                else:
                    node = self.nodes.get_node(addr)
                    notifications.send(self, addr, node['firewall'], constants.OP_SAVE, self.uuid)
        else:
            self.logger.debug("saving rule to 1 node: %s", node_addr)
            rules.save(self, node_addr, node, chain, self.uuid)
            if err is not None:
                utils.set_status_error(self, err)
                return
            utils.enable_buttons(self, False)

    def delete(self):
        chain, err = self.form_to_protobuf()
        if err is not None:
            utils.set_status_error(self, QC.translate("firewall", "Invalid rule: {0}".format(err)))
            return

        nIdx = self.comboNodes.currentIndex()
        node_addr = self.comboNodes.itemData(nIdx)
        node = self.nodes.get_node(node_addr)

        utils.set_status_message(self, QC.translate("firewall", "Deleting rule, wait"))
        if nIdx == 0:
            for addr in self.nodes.get_nodes():
                node = self.nodes.get_node(addr)
                err = rules.delete(self, addr, node, self.uuid)
                if err is not None:
                    utils.set_status_error(self, err)
        else:
            err = rules.delete(self, node_addr, node, self.uuid)
            if err is not None:
                utils.set_status_error(self, err)

    def form_to_protobuf(self):
        """Transform form widgets to protobuf struct
        """
        chain = Fw.ChainFilter.input()
        # XXX: tproxy does not work with destnat+output
        if self.comboDirection.currentIndex() == constants.OUT and \
            (self.comboVerdict.currentIndex()+1 == Fw.Verdicts.values().index(Config.ACTION_TPROXY) or \
                self.comboVerdict.currentIndex()+1 == Fw.Verdicts.values().index(Config.ACTION_DNAT) or \
                self.comboVerdict.currentIndex()+1 == Fw.Verdicts.values().index(Config.ACTION_REDIRECT)
            ):
            chain = Fw.ChainDstNAT.output()
        elif self.comboDirection.currentIndex() == constants.FORWARD:
            chain = Fw.ChainMangle.forward()
        elif self.comboDirection.currentIndex() == constants.PREROUTING:
            chain = Fw.ChainDstNAT.prerouting()
        elif self.comboDirection.currentIndex() == constants.POSTROUTING:
            chain = Fw.ChainDstNAT.postrouting()

        elif self.comboDirection.currentIndex() == constants.OUT or self.FORM_TYPE == constants.FORM_TYPE_EXCLUDE_SERVICE:
            chain = Fw.ChainMangle.output()
        elif self.comboDirection.currentIndex() == constants.IN or self.FORM_TYPE == constants.FORM_TYPE_ALLOW_IN_SERVICE:
            chain = Fw.ChainFilter.input()

        verdict_idx = self.comboVerdict.currentIndex()
        verdict = Fw.Verdicts.values()[verdict_idx+1] # index 0 is ""
        _target_parms = ""
        if rules.has_verdict_parms(self, verdict_idx):
            if self.lineVerdictParms.text() == "":
                return None, QC.translate("firewall", "Verdict ({0}) parameters cannot be empty.".format(verdict))

            # these verdicts parameters need ":" to specify a port or ip:port
            if (self.comboVerdict.currentText().lower() == Config.ACTION_REDIRECT or \
                self.comboVerdict.currentText().lower() == Config.ACTION_TPROXY or \
                self.comboVerdict.currentText().lower() == Config.ACTION_SNAT or \
                self.comboVerdict.currentText().lower() == Config.ACTION_DNAT) and \
                    ":" not in self.lineVerdictParms.text():
                return None, QC.translate("firewall", "Verdict ({0}) parameters format is: <IP>:port.".format(verdict))

            if self.comboVerdict.currentText().lower() == Config.ACTION_QUEUE:
                try:
                    t = int(self.lineVerdictParms.text())
                except:
                    return None, QC.translate("firewall", "Verdict ({0}) parameters format must be a number".format(verdict))

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

        for k in statements.statem_list:
            st_idx = statements.statem_list[k]['what'].currentIndex()-1
            if st_idx == -1:
                return None, QC.translate("firewall", "select a statement.")

            statement = statements.CONF[st_idx]['name']
            statem_keys = statements.CONF[st_idx]['keys']
            statem_op = Fw.Operator.values()[statements.statem_list[k]['op'].currentIndex()]
            statem_opts = statements.statem_list[k]['opts'].currentText().lower()

            key_values = []
            for sk in statem_keys:
                if sk['values'] is None:
                    key_values.append((sk['key'], ""))
                else:
                    statem_value = statements.statem_list[k]['value'].currentText()
                    val_idx = statements.statem_list[k]['value'].currentIndex()

                    if statem_value == "" or (statem_value == "0" and st_idx != statements.META):
                        return None, QC.translate("firewall", "value cannot be 0 or empty.")

                    if st_idx == statements.QUOTA:
                        if sk['key'] == Fw.ExprQuota.OVER.value:
                            if statements.statem_list[k]['opts'].currentIndex() == 0:
                                key_values.append((sk['key'], ""))
                            continue
                        elif sk['key'] == Fw.ExprQuota.UNIT.value or sk['key'] in Fw.RateUnits.values():
                            units = statem_value.split("/")
                            if len(units) != 2: # we expect the format key/value
                                return None, QC.translate("firewall", "the value format is 1024/kbytes (or bytes, mbytes, gbytes)")
                            if units[1] not in Fw.RateUnits.values():
                                return None, QC.translate("firewall", "the value format is 1024/kbytes (or bytes, mbytes, gbytes)")

                            sk['key'] = units[1]
                            statem_value = units[0]
                            if not utils.is_valid_int_value(statem_value):
                                raise ValueError("quota value is invalid ({0}). It must be value/unit (1/kbytes)".format(statem_value))

                    elif st_idx == statements.LIMIT:
                        if sk['key'] == Fw.ExprLimit.OVER.value:
                            if statements.statem_list[k]['opts'].currentIndex() == 0:
                                key_values.append((sk['key'], ""))
                        elif sk['key'] == Fw.ExprLimit.UNITS.value:
                            units = statem_value.split("/")
                            if len(units) != 3: # we expect the format key/value
                                return None, QC.translate("firewall", "the value format is 1024/kbytes/second (or bytes, mbytes, gbytes)")

                            if units[1] not in Fw.RateUnits.values():
                                return None, QC.translate("firewall", "rate-limit not valid, use: bytes, kbytes, mbytes or gbytes.")
                            if units[2] not in Fw.TimeUnits.values():
                                return None, QC.translate("firewall", "time-limit not valid, use: second, minute, hour or day")
                            key_values.append((Fw.ExprLimit.UNITS.value, units[0]))
                            key_values.append((Fw.ExprLimit.RATE_UNITS.value, units[1]))
                            key_values.append((Fw.ExprLimit.TIME_UNITS.value, units[2]))

                        continue

                    elif st_idx == statements.LOG:
                        key_values.append((Fw.ExprLog.LEVEL.value, statem_opts))

                    elif st_idx == statements.META:
                        sk['key'] = statements.statem_list[k]['opts'].currentText()

                    elif st_idx == statements.IIFNAME or st_idx == statements.OIFNAME:
                        # for these statements, the values is set in the Key
                        # field instead of Value. Value must be empty
                        sk['key'] = statem_value
                        statem_value = ""

                    elif st_idx == statements.DEST_IP or st_idx == statements.SOURCE_IP:
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
                                return None, QC.translate("firewall", "IP network format error, {0}".format(e))
                        elif not "-" in statem_value:
                            try:
                                ipaddress.ip_address(statem_value)
                            except Exception as e:
                                return None, QC.translate("firewall", "{0}".format(e))

                    elif st_idx == statements.DPORT or st_idx == statements.SPORT:
                        # if it's a tcp+udp port, we need to add a meta+l4proto
                        # statement, with the protos + ports as values.
                        optsIdx = statements.statem_list[k]['opts'].currentIndex()
                        isMultiProto = optsIdx == 0
                        if isMultiProto:
                            meta = statements.CONF[statements.META]['keys'][1]
                            statement = statements.CONF[statements.META]['name']
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
                            service_idx = self.net_srv.service_by_name(statem_value)
                            if service_idx >= 0:
                                if self.lineDescription.text() == "":
                                    self.lineDescription.setText(statem_value)
                                    #rule.Rules[0].Description = statem_value
                                statem_value = self.net_srv.port_by_index(service_idx)
                                if "," in statem_value or "-" in statem_value:
                                    raise ValueError("port entered is multiport or a port range")
                            else:
                                raise ValueError("port not found by name")
                        except:
                            if "," not in statem_value and "-" not in statem_value:
                                if not utils.is_valid_int_value(statem_value):
                                    return None, QC.translate("firewall", "port not valid.")

                    elif st_idx == statements.CT_SET or st_idx == statements.CT_MARK or st_idx == statements.META_SET_MARK:
                        if not utils.is_valid_int_value(statem_value):
                            return None, QC.translate("firewall", "Invalid value {0}, number expected.".format(statem_value))

                    elif st_idx == statements.ICMP or st_idx == statements.ICMPv6:
                        values = statem_value.split(",")
                        for val in values:
                            if val not in Fw.ExprICMP.values():
                                return None, QC.translate("firewall", "Invalid ICMP type \"{0}\".".format(val))

                    keyVal = (sk['key'], statem_value.replace(" ", ""))
                    if keyVal not in key_values:
                        key_values.append(keyVal)
                    else:
                        self.logger.warning("[REVIEW] statement values duplicated (there shouldn't be): %s", keyVal)

            exprs = Fw.Expr.new(
                statem_op,
                statement,
                key_values,
            )
            rule.Expressions.extend([exprs])
        chain.Rules.extend([rule])

        return chain, None

