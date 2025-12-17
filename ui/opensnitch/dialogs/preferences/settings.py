import json
import time
from PyQt6.QtCore import QCoreApplication as QC

import opensnitch.proto as proto
ui_pb2, ui_pb2_grpc = proto.import_()

from opensnitch.config import Config
from opensnitch.utils import languages
from opensnitch.database import Database
from opensnitch.dialogs.preferences import (
    utils,
)
from opensnitch.dialogs.preferences.sections import (
    db as section_db,
    ui as section_ui,
    nodes as section_nodes
)
from opensnitch.rules import DefaultRulesPath

def save(win):
    utils.reset_status_message(win)
    nodes_saved = save_nodes_config(win)
    ui_saved = save_ui_config(win)
    db_saved = section_db.save_config(win)

    win.saved.emit()
    if win.settings_changed or win.changes_needs_restart is not None or (ui_saved and db_saved and nodes_saved):
        utils.set_status_successful(win, QC.translate("preferences", "Configuration applied."))
    win.settingsSaved = True
    utils.needs_restart(win)

def load(win):
    """load the settings from the configuration file"""
    win.default_action = win.cfgMgr.getInt(win.cfgMgr.DEFAULT_ACTION_KEY)
    win.default_target = win.cfgMgr.getInt(win.cfgMgr.DEFAULT_TARGET_KEY, 0)
    win.default_timeout = win.cfgMgr.getInt(win.cfgMgr.DEFAULT_TIMEOUT_KEY, Config.DEFAULT_TIMEOUT)
    win.disable_popups = win.cfgMgr.getBool(win.cfgMgr.DEFAULT_DISABLE_POPUPS)

    if win.cfgMgr.hasKey(win.cfgMgr.DEFAULT_DURATION_KEY):
        win.default_duration = win.cfgMgr.getInt(win.cfgMgr.DEFAULT_DURATION_KEY)
    else:
        win.default_duration = win.cfgMgr.DEFAULT_DURATION_IDX

    win.comboUIDuration.setCurrentIndex(win.default_duration)
    win.comboUIDialogPos.setCurrentIndex(win.cfgMgr.getInt(win.cfgMgr.DEFAULT_POPUP_POSITION))
    win.comboUIAction.setCurrentIndex(win.default_action)
    win.comboUITarget.setCurrentIndex(win.default_target)
    win.spinUITimeout.setValue(win.default_timeout)
    win.spinUITimeout.setEnabled(not win.disable_popups)
    win.popupsCheck.setChecked(win.disable_popups)

    win.showAdvancedCheck.setChecked(win.cfgMgr.getBool(win.cfgMgr.DEFAULT_POPUP_ADVANCED))
    win.dstIPCheck.setChecked(win.cfgMgr.getBool(win.cfgMgr.DEFAULT_POPUP_ADVANCED_DSTIP))
    win.dstPortCheck.setChecked(win.cfgMgr.getBool(win.cfgMgr.DEFAULT_POPUP_ADVANCED_DSTPORT))
    win.uidCheck.setChecked(win.cfgMgr.getBool(win.cfgMgr.DEFAULT_POPUP_ADVANCED_UID))
    win.checkSum.setChecked(win.cfgMgr.getBool(win.cfgMgr.DEFAULT_POPUP_ADVANCED_CHECKSUM))

    win.comboUIRules.blockSignals(True)
    win.comboUIRules.setCurrentIndex(win.cfgMgr.getInt(win.cfgMgr.DEFAULT_IGNORE_TEMPORARY_RULES))
    win.checkUIRules.setChecked(win.cfgMgr.getBool(win.cfgMgr.DEFAULT_IGNORE_RULES))
    win.comboUIRules.setEnabled(win.cfgMgr.getBool(win.cfgMgr.DEFAULT_IGNORE_RULES))

    #win._set_rules_duration_filter()

    win.cfgMgr.setRulesDurationFilter(
        win.cfgMgr.getBool(win.cfgMgr.DEFAULT_IGNORE_RULES),
        win.cfgMgr.getInt(win.cfgMgr.DEFAULT_IGNORE_TEMPORARY_RULES)
    )
    win.comboUIRules.blockSignals(False)

        # by default, if no configuration exists, enable notifications.
    win.groupNotifs.setChecked(win.cfgMgr.getBool(Config.NOTIFICATIONS_ENABLED, True))
    win.radioSysNotifs.setChecked(
        True if win.cfgMgr.getInt(Config.NOTIFICATIONS_TYPE) == Config.NOTIFICATION_TYPE_SYSTEM and win.desktop_notifications.is_available() == True else False
    )
    win.radioQtNotifs.setChecked(
        True if win.cfgMgr.getInt(Config.NOTIFICATIONS_TYPE) == Config.NOTIFICATION_TYPE_QT or win.desktop_notifications.is_available() == False else False
    )

    ## db
    win.dbType = win.cfgMgr.getInt(win.cfgMgr.DEFAULT_DB_TYPE_KEY)
    win.comboDBType.setCurrentIndex(win.dbType)
    if win.comboDBType.currentIndex() != Database.DB_TYPE_MEMORY:
        win.dbFileButton.setVisible(True)
        win.dbLabel.setVisible(True)
        win.dbLabel.setText(win.cfgMgr.getSettings(win.cfgMgr.DEFAULT_DB_FILE_KEY))
    dbMaxDays = win.cfgMgr.getInt(win.cfgMgr.DEFAULT_DB_MAX_DAYS, 1)
    dbJrnlWal = win.cfgMgr.getBool(win.cfgMgr.DEFAULT_DB_JRNL_WAL)
    dbPurgeInterval = win.cfgMgr.getInt(win.cfgMgr.DEFAULT_DB_PURGE_INTERVAL, 5)
    section_db.enable_db_cleaner_options(win, win.cfgMgr.getBool(Config.DEFAULT_DB_PURGE_OLDEST), dbMaxDays)
    section_db.enable_db_jrnl_wal(win, win.cfgMgr.getBool(Config.DEFAULT_DB_PURGE_OLDEST), dbJrnlWal)
    win.spinDBMaxDays.setValue(dbMaxDays)
    win.spinDBPurgeInterval.setValue(dbPurgeInterval)

    section_ui.load_themes(win)
    section_nodes.load_node_settings(win)
    section_ui.load_ui_settings(win)

def save_ui_config(win):
    try:
        save_ui_columns_config(win)

        maxmsgsize = win.comboGrpcMsgSize.currentText()
        mmsize_saved = win.cfgMgr.getSettings(Config.DEFAULT_SERVER_MAX_MESSAGE_LENGTH)
        if maxmsgsize != "" and mmsize_saved != maxmsgsize:
            win.cfgMgr.setSettings(Config.DEFAULT_SERVER_MAX_MESSAGE_LENGTH, maxmsgsize.replace(" ", ""))
            win.changes_needs_restart = QC.translate("preferences", "Server options changed")

        savedauthtype = win.cfgMgr.getSettings(Config.AUTH_TYPE)
        authtype = win.comboAuthType.itemData(win.comboAuthType.currentIndex())
        cacert = win.cfgMgr.getSettings(Config.AUTH_CA_CERT)
        cert = win.cfgMgr.getSettings(Config.AUTH_CERT)
        certkey = win.cfgMgr.getSettings(Config.AUTH_CERTKEY)
        if not utils.validate_certs(win):
            return False

        server_addr = win.cfgMgr.getSettings(Config.DEFAULT_SERVER_ADDR)
        if win.comboServerAddr.currentText() != server_addr:
            win.cfgMgr.setSettings(Config.DEFAULT_SERVER_ADDR, win.comboServerAddr.currentText())
            win.changes_needs_restart = QC.translate("preferences", "Server address changed")

        old_workers = win.cfgMgr.getInt(Config.DEFAULT_SERVER_MAX_WORKERS, 20)
        max_workers = win.spinGrpcMaxWorkers.value()
        if old_workers != max_workers:
            win.cfgMgr.setSettings(Config.DEFAULT_SERVER_MAX_WORKERS, int(win.spinGrpcMaxWorkers.value()))
            win.changes_needs_restart = QC.translate("preferences", "Server max workers changed")

        old_clients = win.cfgMgr.getInt(Config.DEFAULT_SERVER_MAX_CLIENTS, 0)
        max_clients = win.spinGrpcMaxClients.value()
        if old_clients != max_clients:
            win.cfgMgr.setSettings(Config.DEFAULT_SERVER_MAX_CLIENTS, int(win.spinGrpcMaxClients.value()))
            win.changes_needs_restart = QC.translate("preferences", "Server max clients changed")

        if savedauthtype != authtype or win.lineCertFile.text() != cert or \
                win.lineCertKeyFile.text() != certkey or win.lineCACertFile.text() != cacert:
            win.changes_needs_restart = QC.translate("preferences", "Certificates changed")
        win.cfgMgr.setSettings(Config.AUTH_TYPE, authtype)
        win.cfgMgr.setSettings(Config.AUTH_CA_CERT, win.lineCACertFile.text())
        win.cfgMgr.setSettings(Config.AUTH_CERT, win.lineCertFile.text())
        win.cfgMgr.setSettings(Config.AUTH_CERTKEY, win.lineCertKeyFile.text())

        selected_lang = win.comboUILang.itemData(win.comboUILang.currentIndex())
        saved_lang = win.cfgMgr.getSettings(Config.DEFAULT_LANGUAGE)
        saved_lang = "" if saved_lang is None else saved_lang
        if saved_lang != selected_lang:
            languages.save(win.cfgMgr, selected_lang)
            win.changes_needs_restart = QC.translate("preferences", "Language changed")

        win.cfgMgr.setSettings(win.cfgMgr.DEFAULT_IGNORE_TEMPORARY_RULES, int(win.comboUIRules.currentIndex()))
        win.cfgMgr.setSettings(win.cfgMgr.DEFAULT_IGNORE_RULES, bool(win.checkUIRules.isChecked()))
        #win._set_rules_duration_filter()
        win.cfgMgr.setRulesDurationFilter(
            bool(win.checkUIRules.isChecked()),
            int(win.comboUIRules.currentIndex())
        )
        if win.checkUIRules.isChecked():
            win.nodes.delete_rule_by_field(Config.DURATION_FIELD, Config.RULES_DURATION_FILTER)

        win.cfgMgr.setSettings(win.cfgMgr.STATS_REFRESH_INTERVAL, int(win.spinUIRefresh.value()))
        win.cfgMgr.setSettings(win.cfgMgr.DEFAULT_ACTION_KEY, win.comboUIAction.currentIndex())
        win.cfgMgr.setSettings(win.cfgMgr.DEFAULT_DURATION_KEY, int(win.comboUIDuration.currentIndex()))
        win.cfgMgr.setSettings(win.cfgMgr.DEFAULT_TARGET_KEY, win.comboUITarget.currentIndex())
        win.cfgMgr.setSettings(win.cfgMgr.DEFAULT_TIMEOUT_KEY, win.spinUITimeout.value())
        win.cfgMgr.setSettings(win.cfgMgr.DEFAULT_DISABLE_POPUPS, bool(win.popupsCheck.isChecked()))
        win.cfgMgr.setSettings(win.cfgMgr.DEFAULT_POPUP_POSITION, int(win.comboUIDialogPos.currentIndex()))

        win.cfgMgr.setSettings(win.cfgMgr.DEFAULT_POPUP_ADVANCED, bool(win.showAdvancedCheck.isChecked()))
        win.cfgMgr.setSettings(win.cfgMgr.DEFAULT_POPUP_ADVANCED_DSTIP, bool(win.dstIPCheck.isChecked()))
        win.cfgMgr.setSettings(win.cfgMgr.DEFAULT_POPUP_ADVANCED_DSTPORT, bool(win.dstPortCheck.isChecked()))
        win.cfgMgr.setSettings(win.cfgMgr.DEFAULT_POPUP_ADVANCED_UID, bool(win.uidCheck.isChecked()))
        win.cfgMgr.setSettings(win.cfgMgr.DEFAULT_POPUP_ADVANCED_CHECKSUM, bool(win.checkSum.isChecked()))

        win.cfgMgr.setSettings(win.cfgMgr.NOTIFICATIONS_ENABLED, bool(win.groupNotifs.isChecked()))
        win.cfgMgr.setSettings(win.cfgMgr.NOTIFICATIONS_TYPE,
                            int(Config.NOTIFICATION_TYPE_SYSTEM if win.radioSysNotifs.isChecked() else Config.NOTIFICATION_TYPE_QT))

        thm_name = section_ui.get_theme_name(win)
        win.themes.save_theme(win.comboUITheme.currentIndex(), thm_name, str(win.spinUIDensity.value()))

        qt_platform = win.cfgMgr.getSettings(Config.QT_PLATFORM_PLUGIN)
        if qt_platform != win.comboUIQtPlatform.currentText():
            win.changes_needs_restart = QC.translate("preferences", "Qt platform plugin changed")
        win.cfgMgr.setSettings(Config.QT_PLATFORM_PLUGIN, win.comboUIQtPlatform.currentText())
        win.cfgMgr.setSettings(Config.QT_AUTO_SCREEN_SCALE_FACTOR, bool(win.checkUIAutoScreen.isChecked()))
        win.cfgMgr.setSettings(Config.QT_SCREEN_SCALE_FACTOR, win.lineUIScreenFactor.text())

        current_theme = win.comboUITheme.currentText()
        if win.themes.available() and current_theme.endswith(win.saved_theme) is False:
            win.changes_needs_restart = QC.translate("preferences", "UI theme changed")

        # this is a workaround for not display pop-ups.
        # see #79 for more information.
        if win.popupsCheck.isChecked():
            win.cfgMgr.setSettings(win.cfgMgr.DEFAULT_TIMEOUT_KEY, 0)

        win._autostart.enable(win.checkAutostart.isChecked())

        win.settings_changed = True
        return True

    except Exception as e:
        utils.set_status_error(win, str(e))
        return False

def save_ui_columns_config(win):
    cols=list()
    if win.checkHideTime.isChecked():
        cols.append("0")
    if win.checkHideNode.isChecked():
        cols.append("1")
    if win.checkHideAction.isChecked():
        cols.append("2")
    if win.checkHideSrcPort.isChecked():
        cols.append("3")
    if win.checkHideSrcIP.isChecked():
        cols.append("4")
    if win.checkHideDstIP.isChecked():
        cols.append("5")
    if win.checkHideDstHost.isChecked():
        cols.append("6")
    if win.checkHideDstPort.isChecked():
        cols.append("7")
    if win.checkHideProto.isChecked():
        cols.append("8")
    if win.checkHideUID.isChecked():
        cols.append("9")
    if win.checkHidePID.isChecked():
        cols.append("10")
    if win.checkHideProc.isChecked():
        cols.append("11")
    if win.checkHideCmdline.isChecked():
        cols.append("12")
    if win.checkHideRule.isChecked():
        cols.append("13")

    win.cfgMgr.setSettings(Config.STATS_SHOW_COLUMNS, cols)

def save_nodes_config(win):
    addr = section_nodes.get_node_addr(win)
    if win.node_needs_update is False:
        return False
    if addr is None:
        utils.set_status_message(win, QC.translate("preferences", "There're no nodes connected"))
        return False

    utils.set_status_message(win, QC.translate("preferences", "Saving configuration..."))
    try:
        notif = ui_pb2.Notification(
                id=int(str(time.time()).replace(".", "")),
                type=ui_pb2.CHANGE_CONFIG,
                data="",
                rules=[])
        if win.checkApplyToNodes.isChecked():
            for addr in win.nodes.get_nodes():
                error = save_node_config(win, notif, addr)
                if error is not None:
                    utils.set_status_error(win, error)
                    return False
        else:
            error = save_node_config(win, notif, addr)
            if error is not None:
                utils.set_status_error(win, error)
                return False
    except Exception as e:
        win.logger.warning("exception saving config: %s", repr(e))
        utils.set_status_error(win, QC.translate("preferences", "Exception saving config: {0}").format(str(e)))
        return False

    win.node_needs_update = False
    return True

def save_node_config(win, notifObject, addr):
    try:
        if win.nodes.count() == 0:
            win.logger.debug("save_node_config() no nodes connected")
            return
        if not win.nodes.is_connected(addr):
            win.logger.debug("save_node_config() %s not connected", addr)
            return
        utils.set_status_message(win, QC.translate("preferences", "Applying configuration on {0} ...").format(addr))
        notifObject.data, error = build_node_config(win, addr)
        if error is not None:
            win.logger.debug("save_node_config() -> build_node_config error: %s", error)
            return error

        # exclude this message if there're more than one node connected
        # XXX: unix:/local is a special name for the node, when the gRPC
        # does not return the correct address of the node.
        current_node = section_nodes.get_node_addr(win)
        node_address = win.comboNodeAddress.currentText()
        server_addr = win.comboServerAddr.currentText()
        win.logger.debug("save_node_config() nodes: %s active node: %s node_address: %s server_addr: %s", win.nodes.count(), current_node, node_address, server_addr)
        if server_addr.startswith("unix:") and (current_node != node_address or \
                server_addr != node_address):
            #win.logger.debug("save_node_config() nodes: %s active node: %s node_address: %s server_addr: %s", win.nodes.count(), current_node, node_address, server_addr)
            win.changes_needs_restart = QC.translate("preferences", "Node address changed (update GUI address if needed)")
        if node_address.startswith("unix:") and server_addr.startswith("unix:") is False:
            win.changes_needs_restart = QC.translate("preferences", "Node address changed (update GUI address if needed)")

        win.nodes.save_node_config(addr, notifObject.data)
        nid = win.nodes.send_notification(addr, notifObject, win._notification_callback)
        win._notifications_sent[nid] = notifObject

    except Exception as e:
        win.logger.warning("exception saving node config on %s: %s", addr, repr(e))
        utils.set_status_error(
            win,
            QC.translate("preferences", "Exception saving node config {0}: {1}").format(
                addr, str(e)
            )
        )
        return addr + ": " + str(e)

    return None

def save_node_auth_config(win, config):
    try:
        auth = config.get('Authentication')
        if auth is None:
            auth = {}

        auth['Type'] = win.NODE_AUTH[win.comboNodeAuthType.currentIndex()]
        tls = auth.get('TLSOptions')
        if tls is None:
            tls = {}

        tls['CACert'] = win.lineNodeCACertFile.text()
        tls['ServerCert'] = win.lineNodeServerCertFile.text()
        tls['ClientCert'] = win.lineNodeCertFile.text()
        tls['ClientKey'] = win.lineNodeCertKeyFile.text()
        tls['SkipVerify'] = win.checkNodeAuthSkipVerify.isChecked()
        tls['ClientAuthType'] = win.NODE_AUTH_VERIFY[win.comboNodeAuthVerifyType.currentIndex()]
        auth['TLSOptions'] = tls
        config['Authentication'] = auth

        return config
    except Exception as e:
        win.logger.warning("node auth options exception: %s", repr(e))
        utils.set_status_error(win, str(e))
        return None

def build_node_config(win, addr):
    """load the config of a node before sending it back to the node"""
    try:
        if win.comboNodeAddress.currentText() == "":
            return None, QC.translate("preferences", "Server address can not be empty")

        node_action = Config.ACTION_DENY
        if win.comboNodeAction.currentIndex() == Config.ACTION_ALLOW_IDX:
            node_action = Config.ACTION_ALLOW
        elif win.comboNodeAction.currentIndex() == Config.ACTION_REJECT_IDX:
            node_action = Config.ACTION_REJECT

        node_duration = Config.DURATION_ONCE

        node_conf = win.nodes.get_node_config(addr)
        if node_conf is None:
            return None, " "
        node_config = json.loads(node_conf)
        node_config['DefaultAction'] = node_action
        node_config['DefaultDuration'] = node_duration
        node_config['ProcMonitorMethod'] = win.comboNodeMonitorMethod.currentText()
        node_config['LogLevel'] = win.comboNodeLogLevel.currentIndex()
        node_config['LogUTC'] = win.checkNodeLogUTC.isChecked()
        node_config['LogMicro'] = win.checkNodeLogMicro.isChecked()
        node_config['InterceptUnknown'] = win.checkInterceptUnknown.isChecked()

        if node_config.get('Server') is not None:
            # skip setting Server Address if we're applying the config to all nodes
            node_config['Server']['Address'] = win.comboNodeAddress.currentText()
            node_config['Server']['LogFile'] = win.comboNodeLogFile.currentText()

            cfg = save_node_auth_config(win, node_config['Server'])
            if cfg is not None:
                node_config['Server'] = cfg
        else:
            win.logger.debug("build_node_config() %s doesn't have Server item. You need to update the configuration of this node", addr)

        rules = node_config.get('Rules')
        if rules is None:
            rules = {}
        if rules.get('EnableChecksums') is None:
            rules['EnableChecksums'] = False
            win.enableChecksums.setChecked(False)
        if rules.get('Path') is None or rules.get('Path') == "":
            rules['Path'] = DefaultRulesPath
            win.lineNodeRulesPath.setText(DefaultRulesPath)

        rules['EnableChecksums'] = win.enableChecksums.isChecked()
        rules['Path'] = win.lineNodeRulesPath.text()
        node_config['Rules'] = rules

        internal = node_config.get('Internal')
        if internal is None:
            internal = {}
        if internal.get('FlushConnsOnStart') is None:
            internal['FlushConnsOnStart'] = False
            win.checkNodeFlushConns.setChecked(False)
        if internal.get('GCPercent') is None:
            internal['GCPercent'] = 100
            win.spinNodeGC.setValue(100)

        internal['FlushConnsOnStart'] = win.checkNodeFlushConns.isChecked()
        internal['GCPercent'] = win.spinNodeGC.value()
        node_config['Internal'] = internal

        fwOptions = node_config.get('FwOptions')
        if fwOptions is None:
            fwOptions = {}
        if fwOptions.get('MonitorInterval') is None:
            fwOptions['MonitorInterval'] = "15s"
        if fwOptions.get('QueueBypass') is None:
            fwOptions['QueueBypass'] = True
        node_config['FwOptions'] = fwOptions

        fwOptions['QueueBypass'] = not win.checkNodeBypassQueue.isChecked()
        fwOptions['MonitorInterval'] = win.lineNodeFwMonInterval.text() + "s"

        stats = node_config.get('Stats')
        if stats is None:
            stats = {}
        if stats.get('MaxEvents') is None:
            stats['MaxEvents'] = 250
            win.lineNodeMaxEvents.setText("250")
        if stats.get('MaxStats') is None:
            stats['MaxStats'] = 50
            win.lineNodeMaxStats.setText("50")

        stats['MaxEvents'] = int(win.lineNodeMaxEvents.text())
        stats['MaxStats'] = int(win.lineNodeMaxStats.text())
        node_config['Stats'] = stats

        return json.dumps(node_config, indent="    "), None
    except Exception as e:
        win.logger.warning("exception loading node config on %s: %s" % addr, repr(e))
        utils.set_status_error(win, QC.translate("preferences", "Error loading node config: {0}".format(e)))

    return None, QC.translate("preferences", "Error loading {0} configuration").format(addr)

