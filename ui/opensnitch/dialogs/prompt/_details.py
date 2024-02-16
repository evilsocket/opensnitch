from PyQt5 import QtGui
from opensnitch.config import Config

def render(node, detailsWidget, con):
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
