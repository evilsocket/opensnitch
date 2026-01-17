from PyQt6.QtCore import QCoreApplication as QC

import opensnitch.proto as proto
ui_pb2, ui_pb2_grpc = proto.import_()

from . import (
    constants,
    utils
)

def send(win, node_addr, fw_config, op, uuid):
    nid, notif = win.nodes.reload_fw(node_addr, fw_config, win._notification_callback)
    win._notifications_sent[nid] = {'addr': node_addr, 'operation': op, 'notif': notif, 'uuid': uuid}

def send_all(win, fw_config, op):
    for addr in win.nodes.get_nodes():
        nid, notif = win.nodes.reload_fw(addr, fw_config, win._notification_callback)
        win._notifications_sent[nid] = {'addr': addr, 'operation': op, 'notif': notif}

def handle(win, addr, reply):
    try:
        if reply.id not in win._notifications_sent:
            return

        rep = win._notifications_sent[reply.id]
        if reply.code == ui_pb2.OK:
            if 'operation' in rep and rep['operation'] == constants.OP_DELETE:
                win.tabWidget.setDisabled(True)
                utils.set_status_successful(win, QC.translate("firewall", "Rule deleted"))
                utils.disable_controls(win)
                del win._notifications_sent[reply.id]
                return

            opSave = 'operation' in rep and rep['operation'] == constants.OP_SAVE
            if opSave:
                utils.set_status_successful(win, QC.translate("firewall", "Rule saved"))
            else:
                win.cmdAdd.setVisible(opSave)
                win.cmdSave.setVisible(not opSave)
                utils.set_status_successful(win, QC.translate("firewall", "Rule added"))

        else:
            # XXX: The errors returned by the nftables lib are not really descriptive.
            # "invalid argument", "no such file or directory", without context
            # 1st one: invalid combination of table/chain/priorities?
            # 2nd one: does the table/chain exist?
            errormsg = QC.translate("firewall", "Error adding rules:\n{0}".format(reply.data))
            if 'operation' in rep and rep['operation'] == constants.OP_SAVE:
                if 'uuid' in rep and rep['uuid'] in reply.data:
                    errormsg = QC.translate("firewall", "Error saving rule")
                else:
                    utils.set_status_message(
                        win,
                        QC.translate(
                            "firewall",
                            "Rule saved, but there're other rules with errors (REVIEW):\n{0}".format(reply.data)
                        )
                    )
                    return
            utils.set_status_error(win, errormsg)

    except Exception as e:
        win.logger.debug("[fw rule dialog exception] notif error: %s", repr(e))
    finally:
        if reply.id in win._notifications_sent:
            del win._notifications_sent[reply.id]

