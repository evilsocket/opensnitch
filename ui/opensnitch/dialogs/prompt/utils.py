from slugify import slugify

from PyQt5 import QtGui
from PyQt5.QtCore import QCoreApplication as QC

from opensnitch.config import Config
from opensnitch.dialogs.prompt import constants

def set_elide_text(widget, text, max_size=132):
    if len(text) > max_size:
        text = text[:max_size] + "..."

    widget.setText(text)

def get_rule_name(rule, is_list):
    rule_temp_name = slugify("%s %s" % (rule.action, rule.duration))
    if is_list:
        rule_temp_name = "%s-list" % rule_temp_name
    else:
        rule_temp_name = "%s-simple" % rule_temp_name
    rule_temp_name = slugify("%s %s" % (rule_temp_name, rule.operator.data))

    return rule_temp_name[:128]

def get_popup_message(is_local, node, app_name, con):
    """
    _get_popup_message helps constructing the message that is displayed on
    the pop-up dialog. Example:
        curl is connecting to www.opensnitch.io on TCP port 443
    """
    message = "<b>%s</b>" % app_name
    if not is_local:
        message = QC.translate("popups", "<b>Remote</b> process %s running on <b>%s</b>") % ( \
            message,
            node.split(':')[1])

    msg_action = QC.translate("popups", "is connecting to <b>%s</b> on %s port %d") % ( \
        con.dst_host or con.dst_ip,
        con.protocol.upper(),
        con.dst_port )

    # icmp port is 0 (i.e.: no port)
    if con.dst_port == 0:
        msg_action = QC.translate("popups", "is connecting to <b>%s</b>, %s") % ( \
            con.dst_host or con.dst_ip,
            con.protocol.upper() )

    if con.dst_port == 53 and con.dst_ip != con.dst_host and con.dst_host != "":
        msg_action = QC.translate("popups", "is attempting to resolve <b>%s</b> via %s, %s port %d") % ( \
            con.dst_host,
            con.dst_ip,
            con.protocol.upper(),
            con.dst_port)

    return "%s %s" % (message, msg_action)

def set_app_path(appPathLabel, app_name, app_args, con):
    # show the binary path if it's not part of the cmdline args:
    # cmdline: telnet 1.1.1.1 (path: /usr/bin/telnet.netkit)
    # cmdline: /usr/bin/telnet.netkit 1.1.1.1 (the binary path is part of the cmdline args, no need to display it)
    if con.process_path != "" and len(con.process_args) >= 1 and con.process_path not in con.process_args:
        appPathLabel.setToolTip("Process path: %s" % con.process_path)
        if app_name.lower() == app_args:
            set_elide_text(appPathLabel, "%s" % con.process_path)
        else:
            set_elide_text(appPathLabel, "(%s)" % con.process_path)
        appPathLabel.setVisible(True)
    elif con.process_path != "" and len(con.process_args) == 0:
        set_elide_text(appPathLabel, "%s" % con.process_path)
        appPathLabel.setVisible(True)
    else:
        appPathLabel.setVisible(False)
        appPathLabel.setText("")

def set_app_args(argsLabel, app_name, app_args):
    # if the app name and the args are the same, there's no need to display
    # the args label (amule for example)
    if app_name.lower() != app_args:
        argsLabel.setVisible(True)
        set_elide_text(argsLabel, app_args)
        argsLabel.setToolTip(app_args)
    else:
        argsLabel.setVisible(False)
        argsLabel.setText("")

def set_app_description(appDescriptionLabel, description):
    if description != None and description != "":
        appDescriptionLabel.setVisible(True)
        appDescriptionLabel.setFixedHeight(50)
        appDescriptionLabel.setToolTip(description)
        set_elide_text(appDescriptionLabel, "%s" % description)
    else:
        appDescriptionLabel.setVisible(False)
        appDescriptionLabel.setFixedHeight(0)
        appDescriptionLabel.setText("")

def get_duration(duration_idx):
    if duration_idx == 0:
        return Config.DURATION_ONCE
    elif duration_idx == 1:
        return constants.DURATION_30s
    elif duration_idx == 2:
        return constants.DURATION_5m
    elif duration_idx == 3:
        return constants.DURATION_15m
    elif duration_idx == 4:
        return constants.DURATION_30m
    elif duration_idx == 5:
        return constants.DURATION_1h
    elif duration_idx == 6:
        return Config.DURATION_UNTIL_RESTART
    else:
        return Config.DURATION_ALWAYS

def set_default_duration(cfg, durationCombo):
    if cfg.hasKey(Config.DEFAULT_DURATION_KEY):
        cur_idx = cfg.getInt(Config.DEFAULT_DURATION_KEY)
        durationCombo.setCurrentIndex(cur_idx)
    else:
        durationCombo.setCurrentIndex(Config.DEFAULT_DURATION_IDX)

def render_details(node, detailsWidget, con):
    tree = ""
    space = "&nbsp;"
    spaces = "&nbsp;"
    indicator = ""

    try:
        # reverse() doesn't exist on old protobuf libs.
        con.process_tree.reverse()
    except:
        pass
    for path in con.process_tree:
        tree = "{0}<p>│{1}\t{2}{3}{4}</p>".format(tree, path.value, spaces, indicator, path.key)
        spaces += "&nbsp;" * 4
        indicator = "\\_ "

    # XXX: table element doesn't work?
    details = """<b>{0}</b> {1}:{2} -> {3}:{4}
<br><br>
<b>Path:</b>{5}{6}<br>
<b>Cmdline:</b>&nbsp;{7}<br>
<b>CWD:</b>{8}{9}<br>
<b>MD5:</b>{10}{11}<br>
<b>UID:</b>{12}{13}<br>
<b>PID:</b>{14}{15}<br>
<br>
<b>Process tree:</b><br>
{16}
<br>
<p><b>Environment variables:<b></p>
{17}
""".format(
con.protocol.upper(),
con.src_port, con.src_ip, con.dst_ip, con.dst_port,
space * 6, con.process_path,
" ".join(con.process_args),
space * 6, con.process_cwd,
space * 7, con.process_checksums[Config.OPERAND_PROCESS_HASH_MD5],
space * 9, con.user_id,
space * 9, con.process_id,
tree,
"".join('<p>{}={}</p>'.format(key, value) for key, value in con.process_env.items())
)

    detailsWidget.document().clear()
    detailsWidget.document().setHtml(details)
    detailsWidget.moveCursor(QtGui.QTextCursor.Start)
