import json

from PyQt6 import QtCore, QtGui, uic, QtWidgets
from PyQt6.QtCore import QCoreApplication as QC

import opensnitch.proto as proto
ui_pb2, ui_pb2_grpc = proto.import_()

from .. import (
    constants
)

TASK_NAME = "node-monitor"

class Nodemon:
    def __init__(self, win):
        self.win = win

    def reset_node_info(self, status=""):
        # value 0 is continuous progress
        self.win.nodeRAMProgress.setMaximum(1)
        self.win.nodeRAMProgress.setValue(0)
        self.win.labelNodeProcs.setText("")
        self.win.labelNodeLoadAvg.setText("")
        self.win.labelNodeUptime.setText("")
        self.win.labelNodeSwap.setText("")
        self.win.labelNodeRAM.setText(status)


    def monitor_selected_node(self, node_addr, col_uptime, col_hostname, col_version, col_kernel):
        # TODO:
        #  - create a tasks package, to centralize/normalize tasks' names and
        #  config
        if not self.win._nodes.is_connected(node_addr):
            self.reset_node_info(QC.translate("stats", "node not connected"))
        else:
            noti = ui_pb2.Notification(
                clientName="",
                serverName="",
                type=ui_pb2.TASK_START,
                data='{"name": "%s", "data": {"node": "%s", "interval": "5s"}}' % (TASK_NAME, node_addr),
                rules=[])
            nid = self.win.send_notification(
                node_addr, noti, self.win._notification_callback
            )
            if nid is not None:
                self.save_ntf(nid, noti)

            self.win.nodeRAMProgress.setMaximum(0)
            self.win.nodeSwapProgress.setMaximum(0)
            self.win.labelNodeName.setText(QC.translate("stats", "loading node information..."))
            self.win.labelNodeName.setText("<h3>{0}</h3>".format(col_hostname))
            self.win.labelNodeDetails.setText(
                QC.translate(
                    "stats",
                    "<p><strong>daemon uptime:</strong> {0}</p>".format(col_uptime) + \
                    "<p><strong>Version:</strong> {0}</p>".format(col_version) + \
                    "<p><strong>Kernel:</strong> {0}</p>".format(col_kernel)
                )
            )

    def unmonitor_deselected_node(self, last_addr):
        if not self.win._nodes.is_connected(last_addr):
            self.reset_node_info(QC.translate("stats", "node not connected"))
        else:
            noti = ui_pb2.Notification(
                clientName="",
                serverName="",
                type=ui_pb2.TASK_STOP,
                data='{"name": "%s", "data": {"node": "%s", "interval": "5s"}}' % (TASK_NAME, last_addr),
                rules=[])
            nid = self.win.send_notification(
                last_addr, noti, self.win._notification_callback
            )
            if nid is not None:
                self.save_ntf(nid, noti)
            self.win.labelNodeDetails.setText("")

            # XXX: would be useful to leave latest data?
            #self.reset_node_info()

# create plugins and actions before dialogs

    def update_node_info(self, data):
        try:
            # TODO: move to .utils
            def formatUptime(uptime):
                hours = uptime / 3600
                minutes = uptime % 3600 / 60
                #seconds = uptime % 60
                days = (uptime / 1440) / 60
                months = 0
                years = 0
                if days > 0:
                    hours = hours % 24
                    minutes = (uptime % 3600) / 60

                if days > 0:
                    uptime = "{0:.0f} days {1:.0f}h {2:.0f}m".format(days, hours, minutes)
                else:
                    uptime = "{0:.0f}h {1:.0f}m".format(hours, minutes)

                return QC.translate(
                    "stats",
                    "<strong>System uptime:</strong> %s" % uptime
                )

            # TODO: move to .utils
            def bytes2units(value):
                units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
                idx = 0
                while value / 1024 > 0:
                    value = value / 1024
                    idx+=1
                    if value < 1024:
                        break

                return "{0:.0f} {1}".format(value, units [idx])

            node_data = json.loads(data)
            load1 = node_data['Loads'][0] / 100000
            totalRam = node_data['Totalram']
            totalSwap = node_data['Totalswap']
            freeRam = totalRam - node_data['Freeram']
            freeSwap = totalSwap - node_data['Freeswap']
            self.win.nodeRAMProgress.setMaximum(int(totalRam/1000))
            self.win.nodeRAMProgress.setValue(int(freeRam/1000))
            self.win.nodeRAMProgress.setFormat("%p%")
            self.win.nodeSwapProgress.setMaximum(int(totalSwap/1000))
            self.win.nodeSwapProgress.setFormat("%p%")
            self.win.nodeSwapProgress.setValue(int(freeSwap/1000))

            # if any of these values is 0, set max progressbar value to 1, to
            # avoid the "busy" effect:
            # https://doc.qt.io/qtforpython-5/PySide2/QtWidgets/QProgressBar.html#detailed-description
            if self.win.nodeRAMProgress.value() == 0:
                self.win.nodeRAMProgress.setMaximum(1)
            if self.win.nodeSwapProgress.value() == 0:
                self.win.nodeSwapProgress.setMaximum(1)

            ram = bytes2units(totalRam)
            free = bytes2units(node_data['Freeram'])
            swap = bytes2units(totalSwap)
            freeSwap = bytes2units(node_data['Freeswap'])

            self.win.labelNodeRAM.setText("<strong>RAM:</strong> {0} <strong>Free:</strong> {1}".format(ram, free))
            self.win.labelNodeSwap.setText("<strong>Swap:</strong> {0} <strong>Free:</strong> {1}".format(swap, freeSwap))
            self.win.labelNodeProcs.setText(
                QC.translate("stats", "<strong>Processes:</strong> {0}".format(node_data['Procs']))
            )
            self.win.nodeRAMProgress.setFormat("%p%")
            self.win.nodeSwapProgress.setFormat("%p%")
            self.win.labelNodeLoadAvg.setText(
                QC.translate(
                    "stats",
                    "<strong>Load avg:</strong> {0:.2f}, {1:.2f}, {2:.2f}".format(
                        node_data['Loads'][0] / 100000,
                        node_data['Loads'][1] / 100000,
                        node_data['Loads'][2] / 100000
                    )
                )

            )
            self.win.labelNodeUptime.setText(formatUptime(node_data['Uptime']))
        except Exception as e:
            print("exception parsing taskStart data:", e, data)
        # TODO: update nodes tab

