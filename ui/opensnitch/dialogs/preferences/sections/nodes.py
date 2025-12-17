import json

from PyQt6.QtCore import QCoreApplication as QC
from opensnitch.dialogs.preferences import utils

def load(win):
    win.node_list = win.nodes.get()
    for addr in win.node_list:
        hostname = win.nodes.get_node_hostname(addr)
        win.comboNodes.addItem(f"{addr} - {hostname}", addr)

    if len(win.node_list) == 0:
        win.reset_node_settings(win)
        utils.set_status_message(win, QC.translate("preferences", "There're no nodes connected"))

    showNodes = len(win.node_list) > 1
    win.comboNodes.setVisible(showNodes)
    win.checkApplyToNodes.setVisible(showNodes)

def get_node_addr(win):
    nIdx = win.comboNodes.currentIndex()
    addr = win.comboNodes.itemData(nIdx)
    return addr

def config_auth_type(win, idx):
    curtype = win.comboNodeAuthType.itemData(win.comboNodeAuthType.currentIndex())
    #savedtype = win.cfgMgr.getSettings(Config.AUTH_TYPE)
    #if curtype != savedtype:
    #    win.changes_needs_restart = QC.translate("preferences", "Auth type changed")

    win.lineNodeCACertFile.setEnabled(idx == win.AUTH_TLS_MUTUAL)
    win.lineNodeServerCertFile.setEnabled(idx >= win.AUTH_TLS_SIMPLE)
    win.lineNodeCertFile.setEnabled(idx >= win.AUTH_TLS_SIMPLE)
    win.lineNodeCertKeyFile.setEnabled(idx >= win.AUTH_TLS_SIMPLE)
    win.checkNodeAuthSkipVerify.setEnabled(idx >= win.AUTH_TLS_SIMPLE)
    win.comboNodeAuthVerifyType.setEnabled(idx >= win.AUTH_TLS_SIMPLE)

    win.node_needs_update = True

def reset_node_settings(win):
    win.comboNodeAction.setCurrentIndex(0)
    #win.comboNodeDuration.setCurrentIndex(0)
    win.comboNodeMonitorMethod.setCurrentIndex(0)
    win.checkInterceptUnknown.setChecked(False)
    win.comboNodeLogLevel.setCurrentIndex(0)
    win.checkNodeLogUTC.setChecked(True)
    win.checkNodeLogMicro.setChecked(False)
    win.labelNodeName.setText("")
    win.labelNodeVersion.setText("")
    win.comboNodeAuthType.blockSignals(True)
    win.comboNodeAuthType.setCurrentIndex(win.AUTH_SIMPLE)
    win.comboNodeAuthType.blockSignals(False)
    win.lineNodeCACertFile.setText("")
    win.lineNodeServerCertFile.setText("")
    win.lineNodeCertFile.setText("")
    win.lineNodeCertKeyFile.setText("")
    win.checkNodeAuthSkipVerify.setChecked(False)
    win.comboNodeAuthVerifyType.setCurrentIndex(0)
    win.cb_combo_node_auth_type_changed(0)

def load_node_settings(win):
    addr = get_node_addr(win)
    if addr is None:
        return

    try:
        node_data = win.node_list[addr]['data']
        win.labelNodeVersion.setText(node_data.version)
        win.labelNodeName.setText(node_data.name)
        win.comboNodeLogLevel.setCurrentIndex(node_data.logLevel)

        node_config = json.loads(node_data.config)
        win.comboNodeAction.setCurrentText(node_config['DefaultAction'])
        #win.comboNodeDuration.setCurrentText(node_config['DefaultDuration'])
        win.comboNodeMonitorMethod.setCurrentText(node_config['ProcMonitorMethod'])
        win.checkInterceptUnknown.setChecked(node_config['InterceptUnknown'])
        win.comboNodeLogLevel.setCurrentIndex(int(node_config['LogLevel']))

        if node_config.get('LogUTC') is None:
            node_config['LogUTC'] = False
        win.checkNodeLogUTC.setChecked(node_config['LogUTC'])
        if node_config.get('LogMicro') is None:
            node_config['LogMicro'] = False
        win.checkNodeLogMicro.setChecked(node_config['LogMicro'])

        if node_config.get('Server') != None:
            win.comboNodeAddress.setEnabled(True)
            win.comboNodeLogFile.setEnabled(True)

            win.comboNodeAddress.setCurrentText(node_config['Server']['Address'])
            win.comboNodeLogFile.setCurrentText(node_config['Server']['LogFile'])

            load_node_auth_settings(win, node_config['Server'])
        else:
            win.comboNodeAddress.setEnabled(False)
            win.comboNodeLogFile.setEnabled(False)

        rules = node_config.get('Rules')
        if rules is None:
            rules = {}
        if rules.get('EnableChecksums') is None:
            rules['EnableChecksums'] = False
        if rules.get('Path') is None or rules.get('Path') == "":
            rules['Path'] = DefaultRulesPath
        node_config['Rules'] = rules

        win.enableChecksums.setChecked(rules.get('EnableChecksums'))
        win.lineNodeRulesPath.setText(rules.get('Path'))

        internal = node_config.get('Internal')
        if internal is None:
            internal = {}
        if internal.get('FlushConnsOnStart') is None:
            internal['FlushConnsOnStart'] = False
        if internal.get('GCPercent') is None:
            internal['GCPercent'] = 100
        node_config['Internal'] = internal

        win.checkNodeFlushConns.setChecked(internal.get('FlushConnsOnStart'))
        win.spinNodeGC.setValue(internal.get('GCPercent'))

        fwOptions = node_config.get('FwOptions')
        if fwOptions is None:
            fwOptions = {}
        if fwOptions.get('MonitorInterval') is None or fwOptions.get('MonitorInterval') == "":
            fwOptions['MonitorInterval'] = "15s"
        if fwOptions.get('QueueBypass') is None:
            fwOptions['QueueBypass'] = True
        node_config['FwOptions'] = fwOptions

        monInterval = fwOptions['MonitorInterval'][:-1]
        win.lineNodeFwMonInterval.setText(monInterval)
        win.checkNodeBypassQueue.setChecked(not fwOptions.get('QueueBypass'))

        stats = node_config.get('Stats')
        if stats is None:
            stats = {}
        if stats.get('MaxEvents') is None:
            stats['MaxEvents'] = 250
        if stats.get('MaxStats') is None:
            stats['MaxStats'] = 50
        node_config['Stats'] = stats

        win.lineNodeMaxEvents.setText(str(node_config['Stats']['MaxEvents']))
        win.lineNodeMaxStats.setText(str(node_config['Stats']['MaxStats']))

        win.node_list[addr]['data'].config = json.dumps(node_config, indent="    ")

    except Exception as e:
        win.logger.warning("exception loading config: %s", repr(e))
        utils.set_status_error(win, QC.translate("preferences", "Error loading config {0}: {1}".format(addr, e)))

def load_node_auth_settings(win, config):
    try:
        if config is None:
            return

        auth = config.get('Authentication')
        authtype_idx = 0
        if auth != None:
            if auth.get('Type') != None:
                authtype_idx = win.comboNodeAuthType.findData(auth['Type'])
        else:
            config['Authentication'] = {}
            auth = config.get('Authentication')

        win.lineNodeCACertFile.blockSignals(True)
        win.lineNodeServerCertFile.blockSignals(True)
        win.lineNodeCertFile.blockSignals(True)
        win.lineNodeCertKeyFile.blockSignals(True)

        win.lineNodeCACertFile.setEnabled(authtype_idx >= 0)
        win.lineNodeServerCertFile.setEnabled(authtype_idx >= 0)
        win.lineNodeCertFile.setEnabled(authtype_idx >= 0)
        win.lineNodeCertKeyFile.setEnabled(authtype_idx >= 0)

        tls = auth.get('TLSOptions')
        if tls != None and authtype_idx >= 0:
            if tls.get('CACert') != None:
                win.lineNodeCACertFile.setText(tls['CACert'])
            if tls.get('ServerCert') != None:
                win.lineNodeServerCertFile.setText(tls['ServerCert'])
            if tls.get('ClientCert') != None:
                win.lineNodeCertFile.setText(tls['ClientCert'])
            if tls.get('ClientKey') != None:
                win.lineNodeCertKeyFile.setText(tls['ClientKey'])
            if tls.get('SkipVerify') != None:
                win.checkNodeAuthSkipVerify.setChecked(tls['SkipVerify'])

            if tls.get('ClientAuthType') != None:
                clienttype_idx = win.comboNodeAuthVerifyType.findData(tls['ClientAuthType'])
                if clienttype_idx >= 0:
                    win.comboNodeAuthVerifyType.setCurrentIndex(clienttype_idx)

        win.comboNodeAuthType.blockSignals(True)
        win.comboNodeAuthType.setCurrentIndex(authtype_idx)
        win.comboNodeAuthType.blockSignals(False)
        # signals are connected after this method is called
        win.cb_combo_node_auth_type_changed(authtype_idx)
    except Exception as e:
        win.logger.warning("[prefs] load node auth options exception: %s", repr(e))
        utils.set_status_error(win, QC.translate("preferences", "Error loading node auth config: {0}".format(e)))

    finally:
        win.lineNodeCACertFile.blockSignals(False)
        win.lineNodeServerCertFile.blockSignals(False)
        win.lineNodeCertFile.blockSignals(False)
        win.lineNodeCertKeyFile.blockSignals(False)

