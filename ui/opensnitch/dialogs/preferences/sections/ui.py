import os

from PyQt6.QtCore import QCoreApplication as QC
from opensnitch.utils import languages
from opensnitch.config import Config

def load_langs(win):
    try:
        win.comboUILang.clear()
        win.comboUILang.blockSignals(True)
        win.comboUILang.addItem(QC.translate("preferences", "System default"), "")
        langs, langNames = languages.get_all()
        for idx, lang in enumerate(langs):
            win.comboUILang.addItem(langNames[idx].capitalize(), langs[idx])
        win.comboUILang.blockSignals(False)
    except Exception as e:
        win.logger.warning("exception loading languages: %s", repr(e))


def load_themes(win):
    win.comboUITheme.blockSignals(True)
    theme_idx, win.saved_theme, theme_density = win.themes.get_saved_theme()
    if win.saved_theme == "":
        win.saved_theme = "System"

    win.labelThemeError.setVisible(False)
    win.labelThemeError.setText("")
    win.comboUITheme.clear()
    win.comboUITheme.addItem(QC.translate("preferences", "System"), "System")
    if win.themes.available():
        themes = win.themes.list_themes()
        for t in themes:
            win.comboUITheme.addItem(os.path.basename(t), t)
    else:
        win.labelThemeError.setStyleSheet('color: red')
        win.labelThemeError.setVisible(True)
        win.labelThemeError.setText(QC.translate("preferences", "Themes not available. Install qt-material: pip3 install qt-material"))

    win.comboUITheme.setCurrentIndex(theme_idx)
    show_ui_density_widgets(win, theme_idx)
    try:
        win.spinUIDensity.setValue(int(theme_density))
    except Exception as e:
        win.logger.warning("load_theme() invalid theme density scale: %s, %s", theme_density, repr(e))

    win.comboUITheme.blockSignals(False)

def get_theme_name(win):
    thm_idx = win.comboUITheme.currentIndex()
    return win.comboUITheme.itemData(thm_idx)

def change_theme(win):
    extra_opts = {
        'density_scale': str(win.spinUIDensity.value())
    }
    thm_name = get_theme_name(win)
    win.themes.change_theme(win, thm_name, extra_opts)

def show_ui_density_widgets(win, idx):
    """show ui density widget only for qt-material themes:
        https://github.com/UN-GCPDS/qt-material?tab=readme-ov-file#density-scale
    """
    hidden = idx == 0
    win.labelUIDensity.setHidden(hidden)
    win.spinUIDensity.setHidden(hidden)
    win.cmdUIDensityUp.setHidden(hidden)
    win.cmdUIDensityDown.setHidden(hidden)

def show_ui_scalefactor_widgets(win, show=False):
    win.labelUIScreenFactor.setHidden(show)
    win.lineUIScreenFactor.setHidden(show)

def load_ui_settings(win):
    win.ui_refresh_interval = win.cfgMgr.getInt(win.cfgMgr.STATS_REFRESH_INTERVAL, 0)
    win.spinUIRefresh.setValue(win.ui_refresh_interval)

    saved_lang = win.cfgMgr.getSettings(Config.DEFAULT_LANGUAGE)
    if saved_lang:
        saved_langname = win.cfgMgr.getSettings(Config.DEFAULT_LANGNAME)
        win.comboUILang.blockSignals(True)
        win.comboUILang.setCurrentText(saved_langname)
        win.comboUILang.blockSignals(False)

    auto_scale = win.cfgMgr.getBool(Config.QT_AUTO_SCREEN_SCALE_FACTOR, default_value=True)
    screen_factor = win.cfgMgr.getSettings(Config.QT_SCREEN_SCALE_FACTOR)
    if screen_factor is None or screen_factor == "":
        screen_factor = "1"
    win.lineUIScreenFactor.setText(screen_factor)
    win.checkUIAutoScreen.blockSignals(True)
    win.checkUIAutoScreen.setChecked(auto_scale)
    win.checkUIAutoScreen.blockSignals(False)
    show_ui_scalefactor_widgets(win, auto_scale)

    qt_platform = win.cfgMgr.getSettings(Config.QT_PLATFORM_PLUGIN)
    if qt_platform is not None and qt_platform != "":
        win.comboUIQtPlatform.setCurrentText(qt_platform)

    win.checkAutostart.setChecked(win._autostart.isEnabled())

    maxmsgsize = win.cfgMgr.getSettings(Config.DEFAULT_SERVER_MAX_MESSAGE_LENGTH)
    if maxmsgsize:
        win.comboGrpcMsgSize.setCurrentText(maxmsgsize)
    else:
        win.comboGrpcMsgSize.setCurrentIndex(0)

    server_addr = win.cfgMgr.getSettings(Config.DEFAULT_SERVER_ADDR)
    if server_addr == "" or server_addr is None:
        server_addr = win.comboServerAddr.itemText(0)
    win.comboServerAddr.setCurrentText(server_addr)

    max_workers = win.cfgMgr.getInt(Config.DEFAULT_SERVER_MAX_WORKERS, 20)
    win.spinGrpcMaxWorkers.setValue(max_workers)
    max_clients = win.cfgMgr.getInt(Config.DEFAULT_SERVER_MAX_CLIENTS, 0)
    win.spinGrpcMaxClients.setValue(max_clients)
    keepalive = win.cfgMgr.getInt(Config.DEFAULT_SERVER_KEEPALIVE, 5000)
    win.spinGrpcKeepalive.setValue(keepalive)
    keepalive_timeout = win.cfgMgr.getInt(Config.DEFAULT_SERVER_KEEPALIVE_TIMEOUT, 20000)
    win.spinGrpcKeepaliveTimeout.setValue(keepalive_timeout)

    win.lineCACertFile.setText(win.cfgMgr.getSettings(Config.AUTH_CA_CERT))
    win.lineCertFile.setText(win.cfgMgr.getSettings(Config.AUTH_CERT))
    win.lineCertKeyFile.setText(win.cfgMgr.getSettings(Config.AUTH_CERTKEY))
    authtype_idx = win.comboAuthType.findData(win.cfgMgr.getSettings(Config.AUTH_TYPE))
    if authtype_idx <= 0:
        authtype_idx = 0
        win.lineCACertFile.setEnabled(False)
        win.lineCertFile.setEnabled(False)
        win.lineCertKeyFile.setEnabled(False)
    win.comboAuthType.setCurrentIndex(authtype_idx)

    load_ui_columns_config(win)

def load_ui_columns_config(win):
    cols = win.cfgMgr.getSettings(Config.STATS_SHOW_COLUMNS)
    if cols is None:
        return

    for c in range(13):
        checked = str(c) in cols

        if c == 0:
            win.checkHideTime.setChecked(checked)
        elif c == 1:
            win.checkHideNode.setChecked(checked)
        elif c == 2:
            win.checkHideAction.setChecked(checked)
        elif c == 3:
            win.checkHideSrcPort.setChecked(checked)
        elif c == 4:
            win.checkHideSrcIP.setChecked(checked)
        elif c == 5:
            win.checkHideDstIP.setChecked(checked)
        elif c == 6:
            win.checkHideDstHost.setChecked(checked)
        elif c == 7:
            win.checkHideDstPort.setChecked(checked)
        elif c == 8:
            win.checkHideProto.setChecked(checked)
        elif c == 9:
            win.checkHideUID.setChecked(checked)
        elif c == 10:
            win.checkHidePID.setChecked(checked)
        elif c == 11:
            win.checkHideProc.setChecked(checked)
        elif c == 12:
            win.checkHideCmdline.setChecked(checked)
        elif c == 13:
            win.checkHideRule.setChecked(checked)

