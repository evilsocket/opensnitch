from PyQt5 import QtWidgets, QtGui

import sys
import os
import time
import signal
import argparse

path = os.path.abspath(os.path.dirname(__file__))
sys.path.append(path)
sys.path.append(path + "/../proto/")

import grpc
from concurrent import futures
import ui_pb2
import ui_pb2_grpc

from service import UIService
from stats_dialog import StatsDialog
from version import version

def on_exit():
    # print "Closing UI"
    app.quit()
    server.stop(0)
    sys.exit(0)

def on_stats():
    stats_dialog.show()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OpenSnitch UI service.')
    parser.add_argument("--socket", dest="socket", default="opensnitch-ui.sock", help="Path of the unix socket for the gRPC service.", metavar="FILE")

    args = parser.parse_args()
    app = QtWidgets.QApplication(sys.argv)

    white_image = QtGui.QPixmap(os.path.join(path, "res/icon-white.png"))
    white_icon = QtGui.QIcon()
    white_icon.addPixmap(white_image, QtGui.QIcon.Normal, QtGui.QIcon.Off)

    app.setWindowIcon(white_icon)

    red_image = QtGui.QPixmap(os.path.join(path, "res/icon-red.png"))
    red_icon = QtGui.QIcon()
    red_icon.addPixmap(red_image, QtGui.QIcon.Normal, QtGui.QIcon.Off)

    menu = QtWidgets.QMenu()
    stats_dialog = StatsDialog()

    statsAction = menu.addAction("Statistics")
    statsAction.triggered.connect(on_stats)
    exitAction = menu.addAction("Close")
    exitAction.triggered.connect(on_exit)

    tray = QtWidgets.QSystemTrayIcon(white_icon)
    tray.setContextMenu(menu)
    tray.show()

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))

    ui_pb2_grpc.add_UIServicer_to_server(UIService(stats_dialog), server)
    
    socket = os.path.abspath(args.socket)
    server.add_insecure_port("unix:%s" % socket)

    # https://stackoverflow.com/questions/5160577/ctrl-c-doesnt-work-with-pyqt
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    try:
        # print "OpenSnitch UI service running on %s ..." % socket
        server.start()
        app.exec_()
    except KeyboardInterrupt:
        on_exit()

