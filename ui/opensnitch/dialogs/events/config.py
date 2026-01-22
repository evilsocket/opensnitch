from PyQt6.QtCore import QCoreApplication as QC

from . import (
    constants
)

class ConfigManager:
    def __init__(self, parent):
        super(ConfigManager, self).__init__(parent)

        self.COL_STR_RULES = QC.translate("stats", "Rules", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_CONNECTIONS = QC.translate("stats", "Connections", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_DROPPED = QC.translate("stats", "Dropped", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_VERSION = QC.translate("stats", "Version", "This is a word, without spaces and symbols.").replace(" ", "")

        # columns names. Must be added as members of this instance in order to names be translated.
        self.COL_STR_NAME = QC.translate("stats", "Name", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_ADDR = QC.translate("stats", "Address", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_STATUS = QC.translate("stats", "Status", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_HOSTNAME = QC.translate("stats", "Hostname", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_UPTIME = QC.translate("stats", "Uptime", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_VERSION = QC.translate("stats", "Version", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_RULES_NUM = QC.translate("stats", "Rules", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_TIME = QC.translate("stats", "Time", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_CREATED = QC.translate("stats", "Created", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_ACTION = QC.translate("stats", "Action", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_DURATION = QC.translate("stats", "Duration", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_NOLOG = QC.translate("stats", "Log", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_OP_TYPE = QC.translate("stats", "Type", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_OP_OPERAND = QC.translate("stats", "Operand", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_OP_DATA = QC.translate("stats", "Data", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_DESCRIPTION = QC.translate("stats", "Description", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_NODE = QC.translate("stats", "Node", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_ENABLED = QC.translate("stats", "Enabled", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_PRECEDENCE = QC.translate("stats", "Precedence", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_HITS = QC.translate("stats", "Hits", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_PROTOCOL = QC.translate("stats", "Protocol", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_PROCESS = QC.translate("stats", "Process", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_PROC_CMDLINE = QC.translate("stats", "Cmdline", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_DESTINATION = QC.translate("stats", "Destination", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_SRC_PORT = QC.translate("stats", "SrcPort", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_SRC_IP = QC.translate("stats", "SrcIP", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_DST_IP = QC.translate("stats", "DstIP", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_DST_HOST = QC.translate("stats", "DstHost", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_DST_PORT = QC.translate("stats", "DstPort", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_RULE = QC.translate("stats", "Rule", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_UID = QC.translate("stats", "UserID", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_PID = QC.translate("stats", "PID", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_LAST_CONNECTION = QC.translate("stats", "LastConnection", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_TYPE = QC.translate("stats", "Type", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_WHAT = QC.translate("stats", "What", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_PRIORITY = QC.translate("stats", "Priority", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_FAMILY = QC.translate("stats", "Family", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_IFACE = QC.translate("stats", "Iface", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_METADATA = QC.translate("stats", "Metadata", "This is a word, without spaces and symbols.").replace(" ", "")
        self.COL_STR_STATE = QC.translate("stats", "State", "This is a word, without spaces and symbols.").replace(" ", "")

        self.FIREWALL_STOPPED  = QC.translate("stats", "Not running")
        self.FIREWALL_DISABLED = QC.translate("stats", "Disabled")
        self.FIREWALL_RUNNING  = QC.translate("stats", "Running")

        # detail views queries (when you double click on an item).
        # basically a SELECT * FROM connections WHERE what = 'x' GROUP BY ...

        # TODO: use prepared statements:
        # - replace %DATA% by ?
        # -
        nodes_query = "SELECT " \
                f"MAX(c.time) as {self.COL_STR_TIME}, " \
                f"c.action as {self.COL_STR_ACTION}, " \
                f"count(c.process) as {self.COL_STR_HITS}, " \
                f"c.uid as {self.COL_STR_UID}, " \
                f"c.protocol as {self.COL_STR_PROTOCOL}, " \
                f"c.src_port as {self.COL_STR_SRC_PORT}, " \
                f"c.src_ip as {self.COL_STR_SRC_IP}, " \
                f"c.dst_ip as {self.COL_STR_DST_IP}, " \
                f"c.dst_host as {self.COL_STR_DST_HOST}, " \
                f"c.dst_port as {self.COL_STR_DST_PORT}, " \
                f"c.pid as {self.COL_STR_PID}, " \
                f"c.process as {self.COL_STR_PROCESS}, " \
                f"c.process_args as {self.COL_STR_PROC_CMDLINE}, " \
                f"c.process_cwd as CWD, " \
                f"c.rule as {self.COL_STR_RULE} " \
            "FROM connections as c " \
            "WHERE c.node = '%DATA%'"

        rules_query = "SELECT " \
                f"MAX(c.time) as {self.COL_STR_TIME}, " \
                f"c.node as {self.COL_STR_NODE}, " \
                f"count(c.process) as {self.COL_STR_HITS}, " \
                f"c.uid as {self.COL_STR_UID}, " \
                f"c.protocol as {self.COL_STR_PROTOCOL}, " \
                f"c.src_port as {self.COL_STR_SRC_PORT}, " \
                f"c.src_ip as {self.COL_STR_SRC_IP}, " \
                f"c.dst_ip as {self.COL_STR_DST_IP}, " \
                f"c.dst_host as {self.COL_STR_DST_HOST}, " \
                f"c.dst_port as {self.COL_STR_DST_PORT}, " \
                f"c.pid as {self.COL_STR_PID}, " \
                f"c.process as {self.COL_STR_PROCESS}, " \
                f"c.process_args as {self.COL_STR_PROC_CMDLINE}, " \
                f"c.process_cwd as CWD " \
            "FROM connections as c"

        hosts_query = "SELECT " \
                f"MAX(c.time) as {self.COL_STR_TIME}, " \
                f"c.node as {self.COL_STR_NODE}, " \
                f"count(c.process) as {self.COL_STR_HITS}, " \
                f"c.action as {self.COL_STR_ACTION}, " \
                f"c.uid as {self.COL_STR_UID}, " \
                f"c.protocol as {self.COL_STR_PROTOCOL}, " \
                f"c.src_port as {self.COL_STR_SRC_PORT}, " \
                f"c.src_ip as {self.COL_STR_SRC_IP}, " \
                f"c.dst_ip as {self.COL_STR_DST_IP}, " \
                f"c.dst_port as {self.COL_STR_DST_PORT}, " \
                f"c.pid as {self.COL_STR_PID}, " \
                f"c.process as {self.COL_STR_PROCESS}, " \
                f"c.process_args as {self.COL_STR_PROC_CMDLINE}, " \
                f"c.process_cwd as CWD, " \
                f"c.rule as {self.COL_STR_RULE} " \
            "FROM connections as c " \
            "WHERE c.dst_host = '%DATA%'"

        procs_query = "SELECT " \
                f"MAX(c.time) as {self.COL_STR_TIME}, " \
                f"c.node as {self.COL_STR_NODE}, " \
                f"count(c.dst_ip) as {self.COL_STR_HITS}, " \
                f"c.action as {self.COL_STR_ACTION}, " \
                f"c.uid as {self.COL_STR_UID}, " \
                f"c.protocol as {self.COL_STR_PROTOCOL}, " \
                f"c.src_port as {self.COL_STR_SRC_PORT}, " \
                f"c.src_ip as {self.COL_STR_SRC_IP}, " \
                f"c.dst_ip as {self.COL_STR_DST_IP}, " \
                f"c.dst_host as {self.COL_STR_DST_HOST}, " \
                f"c.dst_port as {self.COL_STR_DST_PORT}, " \
                f"c.pid as {self.COL_STR_PID}, " \
                f"c.process_args as {self.COL_STR_PROC_CMDLINE}, " \
                f"c.process_cwd as CWD, " \
                f"c.rule as {self.COL_STR_RULE} " \
            "FROM connections as c " \
            "WHERE c.process = '%DATA%'"

        addrs_query = "SELECT " \
                f"MAX(c.time) as {self.COL_STR_TIME}, " \
                f"c.node as {self.COL_STR_NODE}, " \
                f"count(c.dst_ip) as {self.COL_STR_HITS}, " \
                f"c.action as {self.COL_STR_ACTION}, " \
                f"c.uid as {self.COL_STR_UID}, " \
                f"c.protocol as {self.COL_STR_PROTOCOL}, " \
                f"c.src_port as {self.COL_STR_SRC_PORT}, " \
                f"c.src_ip as {self.COL_STR_SRC_IP}, " \
                f"c.dst_host as {self.COL_STR_DST_HOST}, " \
                f"c.dst_port as {self.COL_STR_DST_PORT}, " \
                f"c.pid as {self.COL_STR_PID}, " \
                f"c.process as {self.COL_STR_PROCESS}, " \
                f"c.process_args as {self.COL_STR_PROC_CMDLINE}, " \
                f"c.process_cwd as CWD, " \
                f"c.rule as {self.COL_STR_RULE} " \
            "FROM connections as c " \
            "WHERE c.dst_ip = '%DATA%'"

        ports_query = "SELECT " \
                f"MAX(c.time) as {self.COL_STR_TIME}, " \
                f"c.node as {self.COL_STR_NODE}, " \
                f"count(c.dst_ip) as {self.COL_STR_HITS}, " \
                f"c.action as {self.COL_STR_ACTION}, " \
                f"c.uid as {self.COL_STR_UID}, " \
                f"c.protocol as {self.COL_STR_PROTOCOL}, " \
                f"c.src_port as {self.COL_STR_SRC_PORT}, " \
                f"c.src_ip as {self.COL_STR_SRC_IP}, " \
                f"c.dst_ip as {self.COL_STR_DST_IP}, " \
                f"c.dst_host as {self.COL_STR_DST_HOST}, " \
                f"c.pid as {self.COL_STR_PID}, " \
                f"c.process as {self.COL_STR_PROCESS}, " \
                f"c.process_args as {self.COL_STR_PROC_CMDLINE}, " \
                f"c.process_cwd as CWD, " \
                f"c.rule as {self.COL_STR_RULE} " \
            "FROM connections as c " \
            "WHERE c.dst_port = '%DATA%'"

        users_query = "SELECT " \
                f"MAX(c.time) as {self.COL_STR_TIME}, " \
                f"c.node as {self.COL_STR_NODE}, " \
                f"count(c.dst_ip) as {self.COL_STR_HITS}, " \
                f"c.action as {self.COL_STR_ACTION}, " \
                f"c.protocol as {self.COL_STR_PROTOCOL}, " \
                f"c.src_port as {self.COL_STR_SRC_PORT}, " \
                f"c.src_ip as {self.COL_STR_SRC_IP}, " \
                f"c.dst_ip as {self.COL_STR_DST_IP}, " \
                f"c.dst_host as {self.COL_STR_DST_HOST}, " \
                f"c.dst_port as {self.COL_STR_DST_PORT}, " \
                f"c.pid as {self.COL_STR_PID}, " \
                f"c.process as {self.COL_STR_PROCESS}, " \
                f"c.process_args as {self.COL_STR_PROC_CMDLINE}, " \
                f"c.process_cwd as CWD, " \
                f"c.rule as {self.COL_STR_RULE} " \
            "FROM connections as c " \
            "WHERE c.uid = '%DATA%'"

        stats_headers = [
            self.COL_STR_WHAT,
            self.COL_STR_HITS
        ]

        # in order to let users create dynamic views, we'd have to:
        # - add a new item to this configuration
        # - add a new tab
        # - add a container layout (top horizontal layout + cmd Back + label +
        # central layout)
        # - add a tableView
        # - call views.view_setup(), with the configuration and the table view
        # - connect the widget signals
        # XXX:
        # - on double click, the new view should enter into a more detailed view

        # Notes:
        # - The delegate config defines how the view is stylized.
        # - last_order_by order queries by fields.
        # - last_order_to defines the ORDER parameter
        self.views_config = {
            constants.TAB_MAIN: {
                "enabled": True,
                "name": "connections",
                "label": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": "commonDelegateConfig",
                "display_fields": "time as Time, " \
                        "node, " \
                        "action, " \
                        "src_port, " \
                        "src_ip, " \
                        "dst_ip, " \
                        "dst_host, " \
                        "dst_port, " \
                        "protocol, " \
                        "uid, " \
                        "pid, " \
                        "process, " \
                        "process_args, " \
                        "rule",
                "query": "",
                "header_labels": [
                    self.COL_STR_TIME,
                    self.COL_STR_NODE,
                    self.COL_STR_ACTION,
                    self.COL_STR_SRC_PORT,
                    self.COL_STR_SRC_IP,
                    self.COL_STR_DST_IP,
                    self.COL_STR_DST_HOST,
                    self.COL_STR_DST_PORT,
                    self.COL_STR_PROTOCOL,
                    self.COL_STR_UID,
                    self.COL_STR_PID,
                    self.COL_STR_PROCESS,
                    self.COL_STR_PROC_CMDLINE,
                    self.COL_STR_RULE,
                ],
                "context_menu": None,
                "group_by": constants.LAST_GROUP_BY,
                "last_order_by": "1",
                "last_order_to": 1,
                "tracking_column": constants.COL_TIME
            },
            constants.TAB_NODES: {
                "enabled": True,
                "name": "nodes",
                "label": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": "commonDelegateConfig",
                "display_fields": f"last_connection as {self.COL_STR_LAST_CONNECTION}, "\
                        f"addr as {self.COL_STR_ADDR}, " \
                        f"status as {self.COL_STR_STATUS}, " \
                        f"hostname as {self.COL_STR_HOSTNAME}, " \
                        f"daemon_version as {self.COL_STR_VERSION}, " \
                        f"daemon_uptime as {self.COL_STR_UPTIME}, " \
                        f"daemon_rules as {self.COL_STR_RULES}," \
                        f"cons as {self.COL_STR_CONNECTIONS}," \
                        f"cons_dropped as {self.COL_STR_DROPPED}," \
                        f"version as {self.COL_STR_VERSION}",
                "query": nodes_query,
                "header_labels": [
                    self.COL_STR_LAST_CONNECTION,
                    self.COL_STR_ADDR,
                    self.COL_STR_STATUS,
                    self.COL_STR_HOSTNAME,
                    self.COL_STR_VERSION,
                    self.COL_STR_UPTIME,
                    self.COL_STR_RULES,
                    self.COL_STR_CONNECTIONS,
                    self.COL_STR_DROPPED,
                    self.COL_STR_VERSION
                ],
                "context_menu": None,
                "last_order_by": "3,2",
                "last_order_to": 1,
                "tracking_column": constants.COL_NODE
            },
            constants.TAB_RULES: {
                "enabled": True,
                "name": "rules",
                "label": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": "defaultRulesDelegateConfig",
                "display_fields": f"time as {self.COL_STR_TIME}," \
                        f"node as {self.COL_STR_NODE}," \
                        f"name as {self.COL_STR_NAME}," \
                        f"enabled as {self.COL_STR_ENABLED}," \
                        f"precedence as {self.COL_STR_PRECEDENCE}," \
                        f"action as {self.COL_STR_ACTION}," \
                        f"duration as {self.COL_STR_DURATION}," \
                        f"description as {self.COL_STR_DESCRIPTION}, " \
                        f"nolog as {self.COL_STR_NOLOG}, " \
                        f"operator_type as {self.COL_STR_OP_TYPE}, " \
                        f"operator_operand as {self.COL_STR_OP_OPERAND}, " \
                        f"operator_data as {self.COL_STR_OP_DATA}, " \
                        f"created as {self.COL_STR_CREATED}",
                "query": rules_query,
                "header_labels": [
                    self.COL_STR_TIME,
                    self.COL_STR_NODE,
                    self.COL_STR_NAME,
                    self.COL_STR_ENABLED,
                    self.COL_STR_PRECEDENCE,
                    self.COL_STR_ACTION,
                    self.COL_STR_DURATION,
                    self.COL_STR_DESCRIPTION,
                    self.COL_STR_NOLOG,
                    self.COL_STR_OP_TYPE,
                    self.COL_STR_OP_OPERAND,
                    self.COL_STR_OP_DATA,
                    self.COL_STR_CREATED
                ],
                "context_menu": None,
                "last_order_by": "2",
                "last_order_to": 0,
                "tracking_column": constants.COL_R_NAME
            },
            constants.TAB_HOSTS: {
                "enabled": True,
                "name": "hosts",
                "label": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": "commonDelegateConfig",
                "display_fields": "*",
                "query": hosts_query,
                "header_labels": stats_headers,
                "context_menu": None,
                "last_order_by": "2",
                "last_order_to": 1,
                "tracking_column": constants.COL_TIME
            },
            constants.TAB_PROCS: {
                "enabled": True,
                "name": "procs",
                "label": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": "commonDelegateConfig",
                "display_fields": "*",
                "query": procs_query,
                "header_labels": stats_headers,
                "context_menu": None,
                "last_order_by": "2",
                "last_order_to": 1,
                "tracking_column": constants.COL_TIME
            },
            constants.TAB_ADDRS: {
                "enabled": True,
                "name": "addrs",
                "label": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": "commonDelegateConfig",
                "display_fields": "*",
                "query": addrs_query,
                "header_labels": stats_headers,
                "context_menu": None,
                "last_order_by": "2",
                "last_order_to": 1,
                "tracking_column": constants.COL_TIME
            },
            constants.TAB_PORTS: {
                "enabled": True,
                "name": "ports",
                "label": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": "commonDelegateConfig",
                "display_fields": "*",
                "query": ports_query,
                "header_labels": stats_headers,
                "context_menu": None,
                "last_order_by": "2",
                "last_order_to": 1,
                "tracking_column": constants.COL_TIME
            },
            constants.TAB_USERS: {
                "enabled": True,
                "name": "users",
                "label": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": "commonDelegateConfig",
                "display_fields": "*",
                "query": users_query,
                "header_labels": stats_headers,
                "context_menu": None,
                "last_order_by": "2",
                "last_order_to": 1,
                "tracking_column": constants.COL_TIME
            },
            constants.TAB_NETSTAT: {
                "enabled": True,
                "name": "sockets",
                "label": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": "netstatDelegateConfig",
                "display_fields": "proc_comm as Comm," \
                    f"proc_path as {self.COL_STR_PROCESS}, " \
                    f"state as {self.COL_STR_STATE}, " \
                    f"src_port as {self.COL_STR_SRC_PORT}, " \
                    f"src_ip as {self.COL_STR_SRC_IP}, " \
                    f"dst_ip as {self.COL_STR_DST_IP}, " \
                    f"dst_port as {self.COL_STR_DST_PORT}, " \
                    f"proto as {self.COL_STR_PROTOCOL}, " \
                    "uid as UID, " \
                    "proc_pid as PID, " \
                    f"family as {self.COL_STR_FAMILY}, " \
                    f"iface as {self.COL_STR_IFACE}, " \
                    f"'inode: ' || inode || ', cookies: '|| cookies || ', rqueue: ' || rqueue || ', wqueue: ' || wqueue || ', expires: ' || expires || ', retrans: ' || retrans || ', timer: ' || timer as {self.COL_STR_METADATA} ",
                "query": "",
                "header_labels": [
                    "Comm",
                    self.COL_STR_PROCESS,
                    self.COL_STR_STATE,
                    self.COL_STR_SRC_PORT,
                    self.COL_STR_SRC_IP,
                    self.COL_STR_DST_IP,
                    self.COL_STR_DST_PORT,
                    self.COL_STR_PROTOCOL,
                    self.COL_STR_UID,
                    self.COL_STR_PID,
                    self.COL_STR_FAMILY,
                    self.COL_STR_IFACE,
                    self.COL_STR_METADATA
                ],
                "context_menu": None,
                "last_order_by": "2",
                "last_order_to": 1,
                "tracking_column": constants.COL_NET_METADATA
            },
            constants.TAB_FIREWALL: {
                "enabled": True,
                "name": "firewall",
                "label": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": "defaultFWDelegateConfig",
                "display_fields": "*",
                "query": "",
                "header_labels": [],
                "last_order_by": "2",
                "last_order_to": 0,
                "tracking_column": constants.COL_TIME
            },
            constants.TAB_ALERTS: {
                "enabled": True,
                "name": "alerts",
                "label": None,
                "cmd": None,
                "cmdCleanStats": None,
                "view": None,
                "filterLine": None,
                "model": None,
                "delegate": "defaultRulesDelegateConfig",
                "display_fields": f"time as {self.COL_STR_TIME}, " \
                    f"node as {self.COL_STR_NODE}, " \
                    f"type as {self.COL_STR_TYPE}, " \
                    f"substr(what, 0, 64) as {self.COL_STR_WHAT}, " \
                    f"substr(body, 0, 64) as {self.COL_STR_DESCRIPTION} ",
                "query": "",
                "header_labels": [
                    self.COL_STR_TIME,
                    self.COL_STR_NODE,
                    self.COL_STR_TYPE,
                    self.COL_STR_WHAT,
                    self.COL_STR_DESCRIPTION,
                    self.COL_STR_PRIORITY
                ],
                "context_menu": None,
                "last_order_by": "1",
                "last_order_to": 0,
                "tracking_column": constants.COL_TIME
            }
        }

    def default_views_config(self):
        return self.views_config
