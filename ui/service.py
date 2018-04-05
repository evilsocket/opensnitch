import ui_pb2
import ui_pb2_grpc

from dialog import Dialog

class UIService(ui_pb2_grpc.UIServicer):
    def __init__(self, stats_dialog):
        self.stats_dialog = stats_dialog
        self.dialog = Dialog()
        
    def Ping(self, request, context):
        self.stats_dialog.update(request.stats)
	return ui_pb2.PingReply(id=request.id)

    def AskRule(self, request, context):
        rule = self.dialog.promptUser(request)
        # print "%s -> %s" % ( request, rule )
        return rule
