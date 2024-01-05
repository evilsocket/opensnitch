import os
import sys
import json

from PyQt5 import QtCore, QtGui, uic, QtWidgets

from opensnitch import ui_pb2
from opensnitch.nodes import Nodes
from opensnitch.desktop_parser import LinuxDesktopParser
from opensnitch.utils import Message, Icons
from opensnitch.config import Config

DIALOG_UI_PATH = "%s/../res/process_details.ui" % os.path.dirname(sys.modules[__name__].__file__)
class ProcessDetailsDialog(QtWidgets.QDialog, uic.loadUiType(DIALOG_UI_PATH)[0]):

    LOG_TAG = "[ProcessDetails]: "

    _notification_callback = QtCore.pyqtSignal(ui_pb2.NotificationReply)

    TAB_STATUS          = 0
    TAB_DESCRIPTORS     = 1
    TAB_IOSTATS         = 2
    TAB_MAPS            = 3
    TAB_STACK           = 4
    TAB_ENVS            = 5

    TABS = {
            TAB_STATUS: {
                "text": None,
                "scrollPos": 0
                },
            TAB_DESCRIPTORS: {
                "text": None,
                "scrollPos": 0
                },
            TAB_IOSTATS: {
                "text": None,
                "scrollPos": 0
                },
            TAB_MAPS: {
                "text": None,
                "scrollPos": 0
                },
            TAB_STACK: {
                "text": None,
                "scrollPos": 0
                },
            TAB_ENVS: {
                "text": None,
                "scrollPos": 0
                }
            }

    def __init__(self, parent=None, appicon=None):
        super(ProcessDetailsDialog, self).__init__(parent)
        QtWidgets.QDialog.__init__(self, parent, QtCore.Qt.WindowStaysOnTopHint)
        self.setWindowFlags(QtCore.Qt.Window)
        self.setupUi(self)
        self.setWindowIcon(appicon)

        self._app_name = None
        self._app_icon = None
        self._apps_parser = LinuxDesktopParser()
        self._nodes = Nodes.instance()
        self._notification_callback.connect(self._cb_notification_callback)

        self._nid = None
        self._pid = ""
        self._notifications_sent = {}

        self.cmdClose.clicked.connect(self._cb_close_clicked)
        self.cmdAction.clicked.connect(self._cb_action_clicked)
        self.comboPids.currentIndexChanged.connect(self._cb_combo_pids_changed)

        self.TABS[self.TAB_STATUS]['text'] = self.textStatus
        self.TABS[self.TAB_DESCRIPTORS]['text'] = self.textOpenedFiles
        self.TABS[self.TAB_IOSTATS]['text'] = self.textIOStats
        self.TABS[self.TAB_MAPS]['text'] = self.textMappedFiles
        self.TABS[self.TAB_STACK]['text'] = self.textStack
        self.TABS[self.TAB_ENVS]['text'] = self.textEnv

        self.TABS[self.TAB_DESCRIPTORS]['text'].setFont(QtGui.QFont("monospace"))

        self.iconStart = QtGui.QIcon.fromTheme("media-playback-start")
        self.iconPause = QtGui.QIcon.fromTheme("media-playback-pause")

        if QtGui.QIcon.hasThemeIcon("window-close"):
            return

        closeIcon = Icons.new(self, "window-close")
        self.cmdClose.setIcon(closeIcon)
        self.iconStart = Icons.new(self, "media-playback-start")
        self.iconPause = Icons.new(self, "media-playback-pause")

    @QtCore.pyqtSlot(ui_pb2.NotificationReply)
    def _cb_notification_callback(self, reply):
        if reply.id not in self._notifications_sent:
            print("[stats] unknown notification received: ", reply.id)
        else:
            noti = self._notifications_sent[reply.id]

            if reply.code == ui_pb2.ERROR:
                self._show_message(
                    QtCore.QCoreApplication.translate(
                        "proc_details",
                        "<b>Error loading process information:</b> <br><br>\n\n") + reply.data
                )
                self._pid = ""
                self._set_button_running(False)

                # if we haven't loaded any data yet, just close the window
                if self._data_loaded == False:
                    # but if there're more than 1 pid keep the window open.
                    # we may have one pid already closed and one alive.
                    if self.comboPids.count() <= 1:
                        self._close()

                self._delete_notification(reply.id)
                return

            if noti.type == ui_pb2.MONITOR_PROCESS and reply.data != "":
                self._load_data(reply.data)

            elif noti.type == ui_pb2.STOP_MONITOR_PROCESS:
                if reply.data != "":
                    self._show_message(
                        QtCore.QCoreApplication.translate(
                            "proc_details",
                            "<b>Error stopping monitoring process:</b><br><br>") + reply.data
                    )
                    self._set_button_running(False)

                self._delete_notification(reply.id)

    def closeEvent(self, e):
        self._close()

    def _cb_close_clicked(self):
        self._close()

    def _cb_combo_pids_changed(self, idx):
        if idx == -1:
            return
        # TODO: this event causes to send to 2 Start notifications
        #if self._pid != "" and self._pid != self.comboPids.currentText():
        #    self._stop_monitoring()
        #    self._pid = self.comboPids.currentText()
        #    self._start_monitoring()

    def _cb_action_clicked(self):
        if not self.cmdAction.isChecked():
            self._stop_monitoring()
        else:
            self._start_monitoring()

    def _show_message(self, text):
        Message.ok(text, "", QtWidgets.QMessageBox.Warning)

    def _delete_notification(self, nid):
        if nid in self._notifications_sent:
            del self._notifications_sent[nid]

    def _reset(self):
        self._app_name = None
        self._app_icon = None
        self.comboPids.clear()
        self.labelProcName.setText(QtCore.QCoreApplication.translate("proc_details", "loading..."))
        self.labelProcArgs.setText(QtCore.QCoreApplication.translate("proc_details", "loading..."))
        self.labelProcPath.setText(QtCore.QCoreApplication.translate("proc_details", "loading..."))
        self.labelProcIcon.clear()
        self.labelStatm.setText("")
        self.labelCwd.setText("")
        self.labelChecksums.setText("")
        self.labelParent.setText("")
        for tidx in range(0, len(self.TABS)):
            self.TABS[tidx]['text'].setPlainText("")

    def _set_button_running(self, yes):
        if yes:
            self.cmdAction.setChecked(True)
            self.cmdAction.setIcon(self.iconPause)
        else:
            self.cmdAction.setChecked(False)
            self.cmdAction.setIcon(self.iconStart)

    def _close(self):
        self._stop_monitoring()
        self.comboPids.clear()
        self._pid = ""
        self.hide()

    def monitor(self, pids):
        if self._pid != "":
            self._stop_monitoring()

        self._data_loaded = False
        self._pids = pids
        self._reset()
        for pid in pids:
            if pid != None:
                self.comboPids.addItem(pid)

        self.show()
        self._start_monitoring()

    def _set_tab_text(self, tab_idx, text):
        self.TABS[tab_idx]['scrollPos'] = self.TABS[tab_idx]['text'].verticalScrollBar().value()
        self.TABS[tab_idx]['text'].setPlainText(text)
        self.TABS[tab_idx]['text'].verticalScrollBar().setValue(self.TABS[tab_idx]['scrollPos'])

    def _start_monitoring(self):
        try:
            # avoid to send notifications without a pid
            if self._pid != "":
                return

            self._pid = self.comboPids.currentText()
            if self._pid == "":
                return

            self._set_button_running(True)
            noti = ui_pb2.Notification(clientName="", serverName="", type=ui_pb2.MONITOR_PROCESS, data=self._pid, rules=[])
            self._nid = self._nodes.send_notification(self._pids[self._pid], noti, self._notification_callback)
            self._notifications_sent[self._nid] = noti
        except Exception as e:
            print(self.LOG_TAG + "exception starting monitoring: ", e)

    def _stop_monitoring(self):
        if self._pid == "":
            return

        self._set_button_running(False)
        noti = ui_pb2.Notification(clientName="", serverName="", type=ui_pb2.STOP_MONITOR_PROCESS, data=str(self._pid), rules=[])
        self._nid = self._nodes.send_notification(self._pids[self._pid], noti, self._notification_callback)
        self._notifications_sent[self._nid] = noti
        self._pid = ""
        self._app_icon = None

    def _load_data(self, data):
        """Load the process information received via notifications.
        """
        tab_idx = self.tabWidget.currentIndex()

        try:
            proc = json.loads(data)
            self._load_app_icon(proc['Path'])
            if self._app_name != None:
                self.labelProcName.setText("<b>" + self._app_name + "</b>")
                self.labelProcName.setToolTip("<b>" + self._app_name + "</b>")

            if 'Tree' in proc:
                proc['Tree'].reverse()
                self.labelParent.setText(
                    "<b>Parent(s): </b>" + " 🡆 ".join(
                        path['key'] for path in proc['Tree']
                    )
                )
            else:
                self.labelParent.setText("<could not obtain hash>")

            if proc['Path'] not in proc['Args']:
                self.labelProcPath.setVisible(True)
                self.labelProcPath.setText("({0})".format(proc['Path']))
            else:
                self.labelProcPath.setVisible(False)

            if 'Checksums' in proc:
                checksums = proc['Checksums']
                hashes = ""
                if Config.OPERAND_PROCESS_HASH_MD5 in checksums:
                    hashes = "<b>md5:</b> {0}".format(checksums[Config.OPERAND_PROCESS_HASH_MD5])
                if Config.OPERAND_PROCESS_HASH_SHA1 in checksums:
                    hashes = "<b>sha1:</b> {0}".format(checksums[Config.OPERAND_PROCESS_HASH_SHA1])

                self.labelChecksums.setText(hashes)


            self.labelProcArgs.setFixedHeight(30)
            self.labelProcArgs.setText(" ".join(proc['Args']))
            self.labelProcArgs.setToolTip(" ".join(proc['Args']))
            self.labelCwd.setText("<b>CWD: </b>" + proc['CWD'])
            self.labelCwd.setToolTip("<b>CWD: </b>" + proc['CWD'])
            self._load_mem_data(proc['Statm'])

            if tab_idx == self.TAB_STATUS:
                self._set_tab_text(tab_idx, proc['Status'])

            elif tab_idx == self.TAB_DESCRIPTORS:
                self._load_descriptors(proc['Descriptors'])

            elif tab_idx == self.TAB_IOSTATS:
                self._load_iostats(proc['IOStats'])

            elif tab_idx == self.TAB_MAPS:
                self._set_tab_text(tab_idx, proc['Maps'])

            elif tab_idx == self.TAB_STACK:
                self._set_tab_text(tab_idx, proc['Stack'])

            elif tab_idx == self.TAB_ENVS:
                self._load_env_vars(proc['Env'])

            self._data_loaded = True

        except Exception as e:
            print(self.LOG_TAG + "exception loading data: ", e)

    def _load_app_icon(self, proc_path):
        if self._app_icon != None:
            return

        self._app_name, self._app_icon, _, _ = self._apps_parser.get_info_by_path(proc_path, "terminal")
        pixmap = Icons.get_by_appname(self._app_icon)
        self.labelProcIcon.setPixmap(pixmap)

        if self._app_name == None:
            self._app_name = proc_path

    def _load_iostats(self, iostats):
        ioText = "%-16s %dMB<br>%-16s %dMB<br>%-16s %d<br>%-16s %d<br>%-16s %dMB<br>%-16s %dMB<br>" % (
                "<b>Chars read:</b>",
                ((iostats['RChar'] / 1024) / 1024),
                "<b>Chars written:</b>",
                ((iostats['WChar'] / 1024) / 1024),
                "<b>Syscalls read:</b>",
                (iostats['SyscallRead']),
                "<b>Syscalls write:</b>",
                (iostats['SyscallWrite']),
                "<b>KB read:</b>",
                ((iostats['ReadBytes'] / 1024) / 1024),
                "<b>KB written: </b>",
                ((iostats['WriteBytes'] / 1024) / 1024)
                )

        self.textIOStats.setPlainText("")
        self.textIOStats.appendHtml(ioText)

    def _load_mem_data(self, mem):
        # assuming page size == 4096
        pagesize = 4096
        memText = "<b>VIRT:</b> %dMB, <b>RSS:</b> %dMB, <b>Libs:</b> %dMB, <b>Data:</b> %dMB, <b>Text:</b> %dMB" % (
                ((mem['Size'] * pagesize) / 1024) / 1024,
                ((mem['Resident'] * pagesize) / 1024) / 1024,
                ((mem['Lib'] * pagesize) / 1024) / 1024,
                ((mem['Data'] * pagesize) / 1024) / 1024,
                ((mem['Text'] * pagesize) / 1024) / 1024
                )
        self.labelStatm.setText(memText)

    def _load_descriptors(self, descriptors):
        text = "%-12s%-40s%-8s -> %s\n\n" % ("Size", "Time", "Name", "Symlink")
        for d in descriptors:
            text += "{:<12}{:<40}{:<8} -> {}\n".format(str(d['Size']), d['ModTime'], d['Name'], d['SymLink'])

        self._set_tab_text(self.TAB_DESCRIPTORS, text)

    def _load_env_vars(self, envs):
        if envs == {}:
            self._set_tab_text(self.TAB_ENVS, "<no environment variables>")
            return

        text = "%-15s\t%s\n\n" % ("Name", "Value")
        for env_name in envs:
            text += "%-15s:\t%s\n" % (env_name, envs[env_name])

        self._set_tab_text(self.TAB_ENVS, text)


