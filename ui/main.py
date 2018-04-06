from PyQt5 import QtWidgets, QtGui

import sys
import os
import time
import signal
import argparse
from concurrent import futures

path = os.path.abspath(os.path.dirname(__file__))
sys.path.append(path)
sys.path.append(path + "/../proto/")

import grpc
import ui_pb2
import ui_pb2_grpc

from service import UIService
from version import version

def on_exit():
    app.quit()
    server.stop(0)
    sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OpenSnitch UI service.')
    parser.add_argument("--socket", dest="socket", default="opensnitch-ui.sock", help="Path of the unix socket for the gRPC service.", metavar="FILE")

    args = parser.parse_args()
    app = QtWidgets.QApplication(sys.argv)

    service = UIService(app, on_exit)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))

    ui_pb2_grpc.add_UIServicer_to_server(service, server)
    
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

