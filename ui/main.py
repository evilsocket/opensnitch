from PyQt5 import QtWidgets
import sys
import os
import time
import signal
import argparse

path = os.path.abspath(os.path.dirname(__file__))
sys.path.append(path)
sys.path.append(path + "/../ui.proto/")

import grpc
from concurrent import futures
import ui_pb2
import ui_pb2_grpc

from dialog import Dialog

class UIServicer(ui_pb2_grpc.UIServicer):
    def __init__(self):
        self.dialog = Dialog()

    def Ping(self, request, context):
	return ui_pb2.PingReply(id=request.id)

    def AskRule(self, request, context):
        rule = self.dialog.promptUser(request)
        print "%s -> %s" % ( request, rule )
        return rule

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OpenSnitch UI service.')
    parser.add_argument("--socket", dest="socket", default="opensnitch-ui.sock", help="Path of the unix socket for the gRPC service.", metavar="FILE")

    args = parser.parse_args()

    app = QtWidgets.QApplication(sys.argv)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))

    ui_pb2_grpc.add_UIServicer_to_server(UIServicer(), server)
    
    socket = os.path.abspath(args.socket)
    server.add_insecure_port("unix:%s" % socket)

    # https://stackoverflow.com/questions/5160577/ctrl-c-doesnt-work-with-pyqt
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    try:
        print "OpenSnitch UI service running on %s ..." % socket

        server.start()
        app.exec_()
    except KeyboardInterrupt:
        app.quit()
        server.stop(0)

