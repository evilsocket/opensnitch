from PyQt5 import QtWidgets
import sys
import os
import time
import signal

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
        # print "Got ping 0x%x" % request.id
	return ui_pb2.PingReply(id=request.id)

    def AskRule(self, request, context):
        print "%s" % request
        self.dialog.promptUser(request)
	return ui_pb2.RuleReply(
		name="user.choice",
		action="allow",
                duration="always",
		what="process.path",
		value=request.process_path)

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))

    ui_pb2_grpc.add_UIServicer_to_server(UIServicer(), server)
    
    server.add_insecure_port("unix:./opensnitch-ui.sock")

    # https://stackoverflow.com/questions/5160577/ctrl-c-doesnt-work-with-pyqt
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    try:
        server.start()
        app.exec_()
    except KeyboardInterrupt:
        app.quit()
        server.stop(0)

