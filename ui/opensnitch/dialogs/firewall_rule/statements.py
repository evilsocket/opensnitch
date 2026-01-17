from PyQt6 import QtWidgets
from PyQt6.QtCore import QCoreApplication as QC
import opensnitch.firewall as Fw
from opensnitch.utils import (
    NetworkServices,
    NetworkInterfaces
)
from . import (
    utils
)

net_srv = NetworkServices()
# list of widgets representing a rule.
statem_list = {}
st_num = 0

DPORT = 0
SPORT = 1
DEST_IP = 2
SOURCE_IP = 3
IIFNAME = 4
OIFNAME = 5
CT_SET = 6
CT_MARK = 7
CT_STATE = 8
META_SET_MARK = 9
META = 10
ICMP = 11
ICMPv6 = 12
LOG = 13
QUOTA = 14
COUNTER = 15
LIMIT = 16

LIST = [
    "",
    QC.translate("firewall", "Dest Port"),
    QC.translate("firewall", "Source Port"),
    QC.translate("firewall", "Dest IP"),
    QC.translate("firewall", "Source IP"),
    QC.translate("firewall", "Input interface"),
    QC.translate("firewall", "Output interface"),
    QC.translate("firewall", "Set conntrack mark"),
    QC.translate("firewall", "Match conntrack mark"),
    QC.translate("firewall", "Match conntrack state(s)"),
    QC.translate("firewall", "Set mark on packet"),
    QC.translate("firewall", "Match packet information"),
    #"TCP",
    #"UDP",
    "ICMP",
    "ICMPv6",
    "LOG",
    QC.translate("firewall", "Bandwidth quotas"),
    "COUNTER",
    QC.translate("firewall", "Rate limit connections"),
]

# definitions of all possible firewall rules statements
CONF = {
    DPORT: {
        'name': Fw.Statements.TCP.value, # tcp, udp, dccp, sctp
        'tooltip': QC.translate("firewall", """
Supported formats:

- Simple: 23
- Ranges: 80-1024
- Multiple ports: 80,443,8080
"""),
        'keys': [
            {'key': Fw.Statements.DPORT.value, 'values': net_srv.to_array()}
        ]
    },
    SPORT: {
        'name': Fw.Statements.TCP.value,
        'tooltip': QC.translate("firewall", """
Supported formats:

- Simple: 23
- Ranges: 80-1024
- Multiple ports: 80,443,8080
"""),
        'keys': [
            {'key': Fw.Statements.SPORT.value, 'values': net_srv.to_array()}
        ]
    },
    DEST_IP: {
        'name': Fw.Statements.IP.value, # ip or ip6
        'tooltip': QC.translate("firewall", """
Supported formats:

- Simple: 1.2.3.4
- IP ranges: 1.2.3.100-1.2.3.200
- Network ranges: 1.2.3.4/24
"""),
        'keys': [
            {'key': Fw.Statements.DADDR.value, 'values': []}
        ]
    },
    SOURCE_IP: {
        'name': Fw.Statements.IP.value,
        'tooltip': QC.translate("firewall", """
Supported formats:

- Simple: 1.2.3.4
- IP ranges: 1.2.3.100-1.2.3.200
- Network ranges: 1.2.3.4/24
"""),
        'keys': [
            {'key': Fw.Statements.SADDR.value, 'values': []}
        ]
    },
    IIFNAME: {
        'name': Fw.Statements.IIFNAME.value,
        'tooltip': QC.translate("firewall", """Match input interface. Regular expressions not allowed.
Use * to match multiple interfaces."""),
        'keys': [
            {'key': "", 'values': []}
        ]
    },
    OIFNAME: {
        'name': Fw.Statements.OIFNAME.value,
        'tooltip': QC.translate("firewall", """Match output interface. Regular expressions not allowed.
Use * to match multiple interfaces."""),
        'keys': [
            {'key': "", 'values': []}
        ]
    },
    CT_SET: {
        'name': Fw.Statements.CT.value,
        'tooltip': QC.translate("firewall", "Set a conntrack mark on the connection, in decimal format."),
        'keys': [
            # we need 2 keys for this expr: key: set, value: <empty>, key: mark, value: xxx
            {'key': Fw.ExprCt.SET.value, 'values': None}, # must be empty
            {'key': Fw.ExprCt.MARK.value, 'values': []}
        ]
    },
    # match mark
    CT_MARK: {
        'name': Fw.Statements.CT.value,
        'tooltip': QC.translate("firewall", "Match a conntrack mark of the connection, in decimal format."),
        'keys': [
            {'key': Fw.ExprCt.MARK.value, 'values': []}
        ]
    },
    CT_STATE: {
        'name': Fw.Statements.CT.value,
        'tooltip': QC.translate("firewall", """Match conntrack states.

Supported formats:
- Simple: new
- Multiple states separated by commas: related,new
"""),
        'keys': [
            {
                'key': Fw.ExprCt.STATE.value,
                'values': [
                    Fw.ExprCt.NEW.value,
                    Fw.ExprCt.ESTABLISHED.value,
                    Fw.ExprCt.RELATED.value,
                    Fw.ExprCt.INVALID.value
                ]
            }
        ]
    },
    META: {
        'name': Fw.Statements.META.value,
        'tooltip': QC.translate("firewall", """
Match packet's metainformation.

Value must be in decimal format, except for the "l4proto" option.
For l4proto it can be a lower case string, for example:
tcp
udp
icmp,
etc

If the value is decimal for protocol or lproto, it'll use it as the code of
that protocol.
"""),
        'keys': [
            {'key': Fw.ExprMeta.MARK.value, 'values': []},
            {'key': Fw.ExprMeta.L4PROTO.value, 'values': Fw.Protocols.values()}
        ]
    },
    META_SET_MARK: {
        'name': Fw.Statements.META.value,
        'tooltip': QC.translate("firewall", "Set a mark on the packet matching the specified conditions. The value is in decimal format."),
        'keys': [
            {'key': Fw.ExprMeta.SET.value, 'values': None},
            {'key': Fw.ExprMeta.MARK.value, 'values': []}
        ]
    },
    ICMP: {
        'name': Fw.Statements.ICMP.value,
        'tooltip': QC.translate("firewall", """
Match ICMP codes.

Supported formats:
- Simple: echo-request
- Multiple separated by commas: echo-request,echo-reply
"""),
        'keys':  [
            {'key': "type", 'values': Fw.ExprICMP.values()}
        ]
    },
    ICMPv6: {
        'name': Fw.Statements.ICMPv6.value,
        'tooltip': QC.translate("firewall", """
Match ICMPv6 codes.

Supported formats:
- Simple: echo-request
- Multiple separated by commas: echo-request,echo-reply
"""),
        'keys':  [
            {'key': "type", 'values': Fw.ExprICMP.values()}
        ]
    },
    LOG: {
        'name': Fw.Statements.LOG.value,
        'tooltip': QC.translate("firewall", "Print a message when this rule matches a packet."),
        'keys':  [
            {'key': Fw.ExprLog.PREFIX.value, 'values': []}
        ]
    },
    QUOTA: {
        'name': Fw.ExprQuota.QUOTA.value,
        'tooltip': QC.translate("firewall", """
Apply quotas on connections.

For example when:
- "quota over 10/mbytes" -> apply the Action defined (DROP)
- "quota until 10/mbytes" -> apply the Action defined (ACCEPT)

The value must be in the format: VALUE/UNITS, for example:
- 10/mbytes, 1/gbytes, etc
"""),
        'keys':  [
            {'key': Fw.ExprQuota.OVER.value, 'values': []},
            {'key': Fw.ExprQuota.UNIT.value, 'values': [
                "1/{0}".format(Fw.RateUnits.BYTES.value),
                "1/{0}".format(Fw.RateUnits.KBYTES.value),
                "1/{0}".format(Fw.RateUnits.MBYTES.value),
                "1/{0}".format(Fw.RateUnits.GBYTES.value),
            ]}
        ]
    },
    COUNTER: {
        'name': Fw.ExprCounter.COUNTER.value,
        'tooltip': QC.translate("firewall", ""),
        # packets, bytes
        'keys':  [
            {'key': Fw.ExprCounter.PACKETS.value, 'values': None},
            {'key': Fw.ExprCounter.NAME.value, 'values': []}
        ]
    },
    # TODO: https://github.com/evilsocket/opensnitch/wiki/System-rules#rules-expressions
    LIMIT: {
        'name': Fw.ExprLimit.LIMIT.value,
        'tooltip': QC.translate("firewall", """
Apply limits on connections.

For example when:
 - "limit over 10/mbytes/minute" -> apply the Action defined (DROP, ACCEPT, etc)
    (When there're more than 10MB per minute, apply an Action)

 - "limit until 10/mbytes/hour" -> apply the Action defined (ACCEPT)

The value must be in the format: VALUE/UNITS/TIME, for example:
 - 10/mbytes/minute, 1/gbytes/hour, etc
"""),
    'keys':  [
            {'key': Fw.ExprLimit.OVER.value, 'values': []},
            {'key': Fw.ExprLimit.UNITS.value, 'values': [
                "1/{0}/{1}".format(Fw.RateUnits.BYTES.value, Fw.TimeUnits.SECOND.value),
                "1/{0}/{1}".format(Fw.RateUnits.KBYTES.value, Fw.TimeUnits.MINUTE.value),
                "1/{0}/{1}".format(Fw.RateUnits.MBYTES.value, Fw.TimeUnits.HOUR.value),
                "1/{0}/{1}".format(Fw.RateUnits.GBYTES.value, Fw.TimeUnits.DAY.value),
            ]}
        ]
    },
    #TCP: {
    #    'name': Fw.Statements.TCP.value, # ['dport', 'sport' ... ]
    #    'key':  Fw.Statements.DADDR.value,
    #    'values': []
    #},
    #UDP: {
    #    'name': Fw.Statements.UDP.value,
    #    'key':  Fw.Statements.DADDR.value, # ['dport', 'sport' ... ]
    #    'values': []
    #},
}

def add_new(win, title="", topWidget=None):
    """Creates dynamically the widgets to define firewall rules:
        statement (dst port, dst ip, log), protocol, operator (==, !=,...)
        and value (443, 1.1.1.1, etc)
        Some expressions may have different options (protocol, family, options, etc)
    """
    w = QtWidgets.QWidget()
    w.setParent(topWidget)
    l = QtWidgets.QVBoxLayout(w)

    boxH1 = QtWidgets.QHBoxLayout()
    boxH2 = QtWidgets.QHBoxLayout()
    l.addLayout(boxH1)
    l.addLayout(boxH2)

    # row 1: | statement | protocol |
    stWidget = QtWidgets.QComboBox(w)
    stWidget.addItems(LIST)

    prots = ["TCP", "UDP", "ICMP"]
    stOptsWidget = QtWidgets.QComboBox(w)
    stOptsWidget.setSizePolicy(QtWidgets.QSizePolicy.Policy.Maximum, QtWidgets.QSizePolicy.Policy.Fixed)
    stOptsWidget.addItems(prots)

    # row 2: | operator | value |
    ops = [
        QC.translate("firewall", "Equal"),
        QC.translate("firewall", "Not equal"),
        QC.translate("firewall", "Greater or equal than"),
        QC.translate("firewall", "Greater than"),
        QC.translate("firewall", "Less or equal than"),
        QC.translate("firewall", "Less than")
    ]
    stOpWidget = QtWidgets.QComboBox(w)
    stOpWidget.setSizePolicy(QtWidgets.QSizePolicy.Policy.Maximum, QtWidgets.QSizePolicy.Policy.Fixed)
    stOpWidget.addItems(ops)

    stValueWidget = QtWidgets.QComboBox(w)
    stValueWidget.setEditable(True)
    stValueWidget.setSizePolicy(QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Fixed)
    stValueWidget.setCurrentText("")

    # add statement, proto/opts, operator and value
    boxH1.addWidget(stWidget)
    boxH1.addWidget(stOptsWidget)
    boxH2.addWidget(stOpWidget)
    boxH2.addWidget(stValueWidget)
    w.setLayout(l)

    # insert page after current index
    curIdx = win.toolBoxSimple.currentIndex()
    topWidget.insertItem(curIdx+1, w, title)
    topWidget.setCurrentIndex(curIdx+1)

    # if current index is not the last one, reorder statements
    if curIdx+1 != st_num:
        for i in range(curIdx+1, st_num):
            if i in statem_list:
                statem_list[i+1] = statem_list[i]

    statem_list[curIdx+1] = {
        'what': stWidget,
        'opts': stOptsWidget,
        'op': stOpWidget,
        'value': stValueWidget
    }

    stWidget.currentIndexChanged.connect(win.cb_statem_combo_changed)
    stOpWidget.currentIndexChanged.connect(win.cb_statem_op_changed)
    stOptsWidget.currentIndexChanged.connect(win.cb_statem_opts_changed)
    stValueWidget.currentIndexChanged.connect(win.cb_statem_value_index_changed)
    stValueWidget.currentTextChanged.connect(win.cb_statem_value_changed)

def configure_value_opts(win, st_idx):
    w = statem_list[st_idx]
    idx = w['what'].currentIndex()-1 # first item is blank
    if idx == -1:
        return

    w['value'].blockSignals(True)
    w['opts'].blockSignals(True)

    oldValue = w['value'].currentText()
    w['value'].clear()
    for k in CONF[idx]['keys']:
        if k['values'] is None:
            continue
        w['value'].addItems(k['values'])
    w['value'].setCurrentText(oldValue)

    w['opts'].clear()
    if idx == DPORT or \
        idx == SPORT:
        w['op'].setVisible(True)
        w['opts'].setVisible(True)
        w['opts'].addItems(Fw.PortProtocols.values())

    elif idx == DEST_IP or \
        idx == SOURCE_IP:
        w['op'].setVisible(True)
        w['opts'].setVisible(True)
        w['opts'].addItems(Fw.Family.values())
        w['opts'].removeItem(0) # remove 'inet' item

    elif idx == IIFNAME or idx == OIFNAME:
        w['op'].setVisible(True)
        w['opts'].setVisible(False)
        if win.nodes.is_local(win.comboNodes.currentText()):
            w['value'].addItems(NetworkInterfaces.list().keys())
            w['value'].setCurrentText("")

    elif idx == META:
        w['op'].setVisible(True)
        w['opts'].setVisible(True)
        # exclude first item of the list
        w['opts'].addItems(Fw.ExprMeta.values()[1:])

    elif idx == ICMP or idx == ICMPv6 or \
        idx == CT_STATE or idx == CT_MARK:
        w['op'].setVisible(True)
        w['opts'].setVisible(False)

    elif idx == LOG:
        w['op'].setVisible(False)
        w['opts'].setVisible(True)
        w['opts'].addItems(Fw.ExprLogLevels.values())
        w['opts'].setCurrentIndex(
            # nftables default log level is warn
            Fw.ExprLogLevels.values().index(Fw.ExprLogLevels.WARN.value)
        )
    elif idx == QUOTA or idx == LIMIT:
        w['op'].setVisible(False)
        w['opts'].setVisible(True)
        w['opts'].addItems([Fw.ExprQuota.OVER.value, Fw.ExprQuota.UNTIL.value])
    else:
        w['op'].setVisible(False)
        w['opts'].setVisible(False)

    w['opts'].blockSignals(False)
    w['value'].blockSignals(False)

def load_meta(win, exp, idx):
    try:
        isMultiProto = False
        isSetMark = False
        newStatm = SPORT
        newValue = ""
        optsValue = ""
        for v in exp.Statement.Values:
            if v.Key ==  Fw.ExprMeta.SET.value:
                isSetMark = True
                continue
            if isSetMark and v.Key == Fw.ExprMeta.MARK.value:
                newStatm = META_SET_MARK
                if utils.is_valid_int_value(v.Value):
                    newValue = v.Value
                else:
                    utils.set_status_error(
                        win,
                        QC.translate(
                            "firewall",
                            "Invalid mark ({0})".format(v.Value)
                        )
                    )
                break

            if v.Key ==  Fw.ExprMeta.L4PROTO.value:
                optsValue = v.Value
            if v.Key == Fw.Statements.SPORT.value:
                isMultiProto = True
                newValue = v.Value
                break
            elif v.Key == Fw.Statements.DPORT.value:
                newStatm = DPORT
                isMultiProto = True
                newValue = v.Value
                break

        if isSetMark:
            statem_list[idx]['what'].setCurrentIndex(newStatm+1)
            statem_list[idx]['value'].setCurrentText(newValue)

        elif isMultiProto:
            statem_list[idx]['what'].setCurrentIndex(newStatm+1)
            statem_list[idx]['opts'].setCurrentIndex(
                Fw.PortProtocols.values().index(optsValue)
            )
            pidx = win.net_srv.index_by_port(newValue)
            if pidx >= 0:
                statem_list[idx]['value'].setCurrentIndex(pidx)
            else:
                statem_list[idx]['value'].setCurrentText(newValue)

        else:
            statem_list[idx]['what'].setCurrentIndex(META+1)
            statem_list[idx]['opts'].setCurrentIndex(
                # first item of the list is "set", not present in the combobox
                Fw.ExprMeta.values().index(exp.Statement.Values[0].Key)-1
            )
            statem_list[idx]['value'].setCurrentText(exp.Statement.Values[0].Value)

    except Exception as e:
        win.logger.warning("load_meta_statement() exception: %s", repr(e))
        utils.set_status_message(win, e)

def load_limit(win, exp, idx):
    try:
        statem_list[idx]['what'].setCurrentIndex(LIMIT+1)
        statem_list[idx]['opts'].setCurrentIndex(1)
        lval = ""
        for v in exp.Statement.Values:
            if v.Key == Fw.ExprLimit.OVER.value:
                statem_list[idx]['opts'].setCurrentIndex(0)
            elif v.Key == Fw.ExprLimit.UNITS.value:
                lval = v.Value
            elif v.Key == Fw.ExprLimit.RATE_UNITS.value:
                lval = "%s/%s" % (lval, v.Value)
            elif v.Key == Fw.ExprLimit.TIME_UNITS.value:
                lval = "%s/%s" % (lval, v.Value)

        statem_list[idx]['value'].setCurrentText(lval)
    except Exception as e:
        win.logger.warning("load_limit_statement() exception: %s", repr(e))
        utils.set_status_message(win, e)

def load_ct(win, exp, idx):
    """load CT statements, for example:
        Name: ct, Key: set, Key: mark, Value: 123
        Name: ct, Key: mark, Value: 123
        Name: ct, Key: state, value: new,established
    """
    try:
        if exp.Statement.Values[0].Key == Fw.ExprCt.STATE.value:
            statem_list[idx]['what'].setCurrentIndex(CT_STATE+1)
            statem_list[idx]['value'].setCurrentText(exp.Statement.Values[0].Value)
            for v in exp.Statement.Values:
                curText = statem_list[idx]['value'].currentText()
                if v.Value not in curText:
                    statem_list[idx]['value'].setCurrentText(
                        "{0},{1}".format(
                            curText,
                            v.Value
                        )
                    )

        elif exp.Statement.Values[0].Key == Fw.ExprCt.SET.value:
            statem_list[idx]['what'].setCurrentIndex(CT_SET+1)
            markVal = ""
            for v in exp.Statement.Values:
                if v.Key == Fw.ExprCt.MARK.value:
                    markVal = v.Value
                    break

            statem_list[idx]['value'].setCurrentText(markVal)
            if markVal == "":
                raise ValueError(
                    QC.translate("firewall", "Warning: ct set mark value is empty, malformed rule?")
                )

        elif exp.Statement.Values[0].Key == Fw.ExprCt.MARK.value:
            statem_list[idx]['what'].setCurrentIndex(CT_MARK+1)
            statem_list[idx]['value'].setCurrentText(exp.Statement.Values[0].Value)

    except Exception as e:
        win.logger.warning("load_ct_statement() exception: %s", repr(e))
        utils.set_status_message(win, e)


def set_title(win, st_idx, value=None):
    """Transform the widgets to nftables rule text format
    """
    utils.reset_status_message(win)
    win.toolBoxSimple.setItemText(st_idx, "")
    w = statem_list[st_idx]
    idx = w['what'].currentIndex()-1 # first item is blank
    if idx == -1:
        return

    st = CONF[idx]['name']
    st_opts = w['opts'].currentText()
    if idx == DEST_IP or idx == SOURCE_IP:
        st = st_opts
    if idx == DPORT or idx == SPORT:
        st = st_opts

    title = st
    for keys in CONF[idx]['keys']:
        title += " " + keys['key']
    st_op = Fw.Operator.values()[w['op'].currentIndex()]
    st_val = w['value'].currentText()
    if value is not None:
        st_val = value

    # override previous setup for some statements
    if idx == META:
        title = "{0} {1} {2} {3}".format(st, st_opts, st_op, st_val)
    elif idx == QUOTA:
        title = "{0} {1} {2}".format(st, st_opts, st_val)
    elif idx == LIMIT:
        title = "{0} {1} {2}".format(st, st_opts, st_val)
    else:
        title = "{0} {1} {2}".format(title, st_op, st_val)

    win.toolBoxSimple.setItemText(st_idx, title)


