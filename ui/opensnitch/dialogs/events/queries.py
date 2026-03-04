import re

from PyQt6 import QtCore

from . import (
    constants
)
from opensnitch.config import Config
from opensnitch.customwidgets.completer import Completer
from opensnitch.proto.enums import (
    ConnFields,
    NodeFields,
    RuleFields
)

OP_NOT_EQUAL = "!="
OP_NOT_EQUAL2 = "<>"
OP_EQUAL = "="
# LIKE
OP_CONTAINS = "~"
# NOT LIKE
OP_NO_CONTAINS = "!~"
# LIKE 'what%'
OP_STARTS_WITH = ">~"
# LIKE '%what'
OP_ENDS_WITH = "<~"
OP_GT=">"
OP_GT_EQ=">="
OP_LT="<"
OP_LT_EQ="<="

class Queries:
    def __init__(self, win):
        self.win = win
        self.options = [
            ConnFields.Time.value,
            ConnFields.DstHost.value,
            ConnFields.DstPort.value,
            ConnFields.SrcPort.value,
            ConnFields.DstIP.value,
            ConnFields.SrcIP.value,
            ConnFields.PID.value,
            ConnFields.UID.value,
            ConnFields.Rule.value,
            ConnFields.ProcCWD.value,
            ConnFields.Process.value,
            ConnFields.Cmdline.value,
            ConnFields.Proto.value,
            ConnFields.Action.value,
            ConnFields.Node.value,
            NodeFields.Addr.value,
            RuleFields.Action.value,
            RuleFields.Name.value
        ]
        self.opt_map = {
            self.options[0]: "c.time",
            self.options[1]: "c.dst_host",
            self.options[2]: "c.dst_port",
            self.options[3]: "c.src_port",
            self.options[4]: "c.dst_ip",
            self.options[5]: "c.src_ip",
            self.options[6]: "c.pid",
            self.options[7]: "c.uid",
            self.options[8]: "c.rule",
            self.options[9]: "c.process_cwd",
            self.options[10]: "c.process",
            self.options[11]: "c.process_args",
            self.options[12]: "c.protocol",
            self.options[13]: "c.action",
            self.options[14]: "c.node",
            self.options[15]: "c.node",
            self.options[16]: "c.action",
            self.options[17]: "c.rule"
        }
        self.rules_opts = [
            RuleFields.Time.value,
            RuleFields.Created.value,
            RuleFields.Name.value,
            RuleFields.Description.value,
            RuleFields.Node.value,
            RuleFields.Enabled.value,
            RuleFields.Action.value,
            RuleFields.Nolog.value,
            RuleFields.Priority.value,
            RuleFields.Duration.value,
            RuleFields.OpType.value,
            RuleFields.OpOperand.value,
            RuleFields.OpData.value
        ]
        self.rules_opt_map = {
            self.rules_opts[0]: "rules.time",
            self.rules_opts[1]: "rules.created",
            self.rules_opts[2]: "rules.name",
            self.rules_opts[3]: "rules.description",
            self.rules_opts[4]: "rules.node",
            self.rules_opts[5]: "rules.enabled",
            self.rules_opts[6]: "rules.action",
            self.rules_opts[7]: "rules.nolog",
            self.rules_opts[8]: "rules.priority",
            self.rules_opts[9]: "rules.duration",
            self.rules_opts[10]: "rules.operator_type",
            self.rules_opts[11]: "rules.operator_operand",
            self.rules_opts[12]: "rules.operator_data"
        }
        self.reOperators = "=|!=|<>|~|!~|>~|<~|>=|>|<=|<"
        self.reValues=r'[0-9a-zA-Z\.\-_\/:]+'

    def get_completer(self, idx):
        opts = self.options
        if idx == constants.TAB_RULES and self.win.in_detail_view(idx) is False:
            opts = self.rules_opts

        reKeys = '|'.join(opts)
        reKeys = reKeys.replace('.', r'\.')
        self.adv_search=re.compile(
            # the 3rd group should contain all the characters allowed in a
            # filesystem, in order to match paths.
            r'(({0})({1})({2}))+'.format(reKeys, self.reOperators, self.reValues)
        )

        completer = Completer(opts)
        completer.setFilterMode(QtCore.Qt.MatchFlag.MatchContains)
        return completer

    def get_query(self, table, fields):
        return f"SELECT {fields} FROM {table}"

    def get_view_query(self, model, idx, where_clause=None):
        """builds the query of a view"""
        qstr = self.get_query(
            self.win.TABLES[idx]['name'],
            self.win.TABLES[idx]['display_fields']
        )
        if where_clause is not None:
            qstr += where_clause
        qstr += self.win.get_view_order()
        qstr += self.win.get_view_limit()
        return qstr

    # TODO:
    # we assume that the filter fields are of the Connections table,
    # but for example the rules or the netstat views have a different table name.
    # This search should be more generic, not tied to a view, to allow filters
    # of any table.
    def advanced_search(self, text):
        """build advanced search.
        Replace connection properties with database fields to construct advanced
        filters.
        For example:
            conn.dstport>123 AND conn.dstport<1024

        translates to:
            c.dst_port > 123 AND c.dst_port < 1024
        """
        has_filter = False
        groups=self.adv_search.findall(text)
        if groups is None:
            return None

        for opt in groups:
            # group = conn.dstport=53
            # k = conn.dstport
            # op = =, != , >, ...
            # v = 53
            #group = opt[0]
            k = opt[1]
            op = opt[2]
            v = opt[3]
            nk = None
            cur_idx = self.win.get_current_view_idx()
            if cur_idx == constants.TAB_RULES and self.win.in_detail_view(cur_idx) is False:
                nk = self.rules_opt_map.get(k)
            else:
                nk = self.opt_map.get(k)

            if nk is not None:
                has_filter = True
                if op == OP_NOT_EQUAL:
                    text = text.replace(opt[0], nk+"!=\""+v+"\"")
                elif op == OP_EQUAL:
                    text = text.replace(opt[0], nk+"=\""+v+"\"")
                elif op == OP_CONTAINS:
                    text = text.replace(opt[0], nk+" LIKE \"%"+v+"%\"")
                elif op == OP_NO_CONTAINS:
                    text = text.replace(opt[0], nk+" NOT LIKE \"%"+v+"%\"")
                elif op == OP_ENDS_WITH:
                    text = text.replace(opt[0], nk+" LIKE \"%"+v+"\"")
                elif op == OP_STARTS_WITH:
                    text = text.replace(opt[0], nk+" LIKE \""+v+"%\"")
                elif op in (OP_GT, OP_GT_EQ, OP_LT, OP_LT_EQ):
                    # FIXME: we're comparing strings as integers here.
                    try:
                        int(v)
                    except:
                        continue
                    text = text.replace(opt[0], nk+op+v)

        if not has_filter:
            text = None
        return text

    def get_filter_line(self, idx, text, adv_search=None):
        if text == "":
            return ""

        if idx == constants.TAB_RULES and self.win.rulesTable.isVisible():
            if adv_search is not None:
                return f" WHERE {adv_search}"
            return f" WHERE rules.name LIKE '%{text}%' OR" \
                f" rules.node LIKE '%{text}%' OR" \
                f" rules.enabled LIKE '%{text}%' OR" \
                f" rules.action LIKE '%{text}%' OR" \
                f" rules.duration LIKE '%{text}%' OR" \
                f" rules.description LIKE '%{text}%' OR" \
                f" rules.nolog LIKE '%{text}%' OR" \
                f" rules.precedence LIKE '%{text}%' OR" \
                f" rules.operator_type LIKE '%{text}%' OR" \
                f" rules.operator_operand LIKE '%{text}%' OR" \
                f" rules.operator_data LIKE '%{text}%'"
        elif idx == constants.TAB_HOSTS or \
            idx == constants.TAB_PROCS or \
            idx == constants.TAB_ADDRS or \
            idx == constants.TAB_PORTS or \
            idx == constants.TAB_USERS:
            return f" WHERE what LIKE '%{text}%' ".format(text)
        elif idx == constants.TAB_NETSTAT:
            if adv_search is not None:
                return f" WHERE {adv_search}"
            return f" WHERE proc_comm LIKE '%{text}%' OR" \
                f" proc_path LIKE '%{text}%' OR" \
                f" state LIKE '%{text}%' OR" \
                f" src_port LIKE '%{text}%' OR" \
                f" src_ip LIKE '%{text}%' OR" \
                f" dst_ip LIKE '%{text}%' OR" \
                f" dst_port LIKE '%{text}%' OR" \
                f" proto LIKE '%{text}%' OR" \
                f" uid LIKE '%{text}%' OR" \
                f" proc_pid LIKE '%{text}%' OR" \
                f" family LIKE '%{text}%' OR" \
                f" iface LIKE '%{text}%' OR" \
                f" inode LIKE '%{text}%'"

        return ""

    def get_indetail_filter(self, indetail_view, lastQuery, text, advanced_filter):
        """builds the query when a tab is in the detail view."""
        try:
            cur_idx = self.win.get_current_view_idx()
            base_query = lastQuery.split("GROUP BY")
            qstr = base_query[0]
            where = qstr.split("WHERE")[1]  # get SELECT ... WHERE (*)
            ands = where.split("AND")[0] # get WHERE (*) AND (...)
            qstr = qstr.split("WHERE")[0]  # get * WHERE ...

            if advanced_filter is not None:
                andd = where.split("AND")[0]
                qstr += "WHERE " + andd.strip() + " AND " + advanced_filter
                return

            # if there's no text to filter, strip the filter "AND ()", and
            # return the original query.
            if text == "":
                andd = where.split("AND")[0]
                qstr += f"WHERE {ands}"
                print("IN DETAIL VIEW FILTER, text empty: ", qstr)
                return

            qstr += "WHERE %s" % ands.lstrip()
            qstr += f"AND (c.time LIKE '%{text}%' OR " \
                f"c.action LIKE '%{text}%' OR " \
                f"c.pid LIKE '%{text}%' OR " \
                f"c.protocol LIKE '%{text}%' OR " \
                f"c.src_port LIKE '%{text}%' OR " \
                f"c.src_ip LIKE '%{text}%' OR " \
                f"c.process_cwd LIKE '%{text}%' OR " \
                f"c.rule LIKE '%{text}%' OR "

            # exclude from query the field of the view we're filtering by
            if indetail_view != constants.TAB_PORTS:
                qstr += f"c.dst_port LIKE '%{text}%' OR ".format(text)
            if indetail_view != constants.TAB_ADDRS:
                qstr += f"c.dst_ip LIKE '%{text}%' OR ".format(text)
            if indetail_view != constants.TAB_HOSTS:
                qstr += f"c.dst_host LIKE '%{text}%' OR ".format(text)
            if indetail_view != constants.TAB_PROCS:
                qstr += f"c.process LIKE '%{text}%' OR ".format(text)
            if indetail_view != constants.TAB_USERS:
                qstr += f"c.uid LIKE '%{text}%' OR ".format(text)

            qstr += f"c.process_args LIKE '%{text}%')".format(text)

        except Exception as e:
            print("get_indetail_filter() exception:", e)

        finally:
            if len(base_query) > 1:
                qstr += " GROUP BY" + base_query[1]
            return qstr

    def get_nodes_filter(self, indetail_view, lastQuery, text, advanced_filter):
        # in normal view, there's no GROUP BY
        base_query = lastQuery.split("GROUP BY")
        if not indetail_view:
            base_query = lastQuery.split("ORDER BY")

        qstr = base_query[0]
        # if there's any previous search, remove it
        if "AND" in qstr:
            os = qstr.split('AND')
            qstr = os[0]

        if text == "":
            # if there's no search text, restore the query
            # the GROUP and ORDER clausules are other later.
            qstr = base_query[0]

        else:

            if indetail_view:
                if advanced_filter is not None:
                    qstr += f"AND {advanced_filter}"
                else:
                    qstr += f"AND (c.time LIKE '%{text}%' OR " \
                        f"c.action LIKE '%{text}%' OR " \
                        f"c.uid LIKE '%{text}%' OR " \
                        f"c.pid LIKE '%{text}%' OR " \
                        f"c.protocol LIKE '%{text}%' OR " \
                        f"c.src_port LIKE '%{text}%' OR " \
                        f"c.dst_port LIKE '%{text}%' OR " \
                        f"c.src_ip LIKE '%{text}%' OR " \
                        f"c.dst_ip LIKE '%{text}%' OR " \
                        f"c.dst_host LIKE '%{text}%' OR " \
                        f"c.process LIKE '%{text}%' OR " \
                        f"c.process_cwd LIKE '%{text}%' OR " \
                        f"c.process_args LIKE '%{text}%')"
            else:
                if "WHERE" in qstr:
                    w = qstr.split('WHERE')
                    qstr = w[0]

                qstr += "WHERE (" \
                    f"last_connection LIKE '%{text}%' OR " \
                    f"addr LIKE '%{text}%' OR " \
                    f"status LIKE '%{text}%' OR " \
                    f"hostname LIKE '%{text}%' OR " \
                    f"version LIKE '%{text}%'" \
                    ")"

        if indetail_view:
            qstr += " GROUP BY" + base_query[1]
        else:
            qstr += " ORDER BY" + base_query[1]

        return qstr

    def get_events_generic_filter(self, action, filter_text):
        return f" WHERE {action} (" \
                    f" process LIKE '%{filter_text}%'" \
                    f" OR process_args LIKE '%{filter_text}%'" \
                    f" OR process_cwd LIKE '%{filter_text}%'" \
                    f" OR src_port LIKE '%{filter_text}%'" \
                    f" OR src_ip LIKE '%{filter_text}%'" \
                    f" OR dst_ip LIKE '%{filter_text}%'" \
                    f" OR dst_host LIKE '%{filter_text}%'" \
                    f" OR dst_port LIKE '%{filter_text}%'" \
                    f" OR rule LIKE '%{filter_text}%'" \
                    f" OR node LIKE '%{filter_text}%'" \
                    f" OR time LIKE '%{filter_text}%'" \
                    f" OR uid LIKE '%{filter_text}%'" \
                    f" OR pid LIKE '%{filter_text}%'" \
                    f" OR protocol LIKE '%{filter_text}%')"

    def set_rules_filter(self, parent_row=constants.NO_PARENT, item_row=0, what="", what1="", what2=""):
        section = constants.FILTER_TREE_APPS
        filter_text = self.win.get_search_text()

        model = self.win.get_active_table().model()
        if parent_row == constants.NO_PARENT:

            if item_row == constants.RULES_TREE_NODES:
                section=constants.FILTER_TREE_NODES
                what=""
            elif item_row == constants.RULES_TREE_ALERTS:
                section=constants.FILTER_TREE_NODES
                what=""
                alerts_query = "SELECT {0} FROM {1} {2} {3}".format(
                    self.win.TABLES[constants.TAB_ALERTS]['display_fields'],
                    self.win.TABLES[constants.TAB_ALERTS]['name'],
                    self.win.get_view_order(),
                    self.win.get_view_limit()
                )
                self.setQuery(model, alerts_query, limit=self.win.get_query_limit(), offset=0)
                return
            elif item_row == constants.RULES_TREE_FIREWALL:
                self.set_fw_rules_filter(parent_row, item_row, what, what1, what2)
                return
            else:
                section=constants.FILTER_TREE_APPS
                what=""

        elif parent_row == constants.RULES_TREE_APPS:
            if item_row == constants.RULES_TREE_PERMANENT:
                section=constants.FILTER_TREE_APPS
                what=constants.RULES_TYPE_PERMANENT
            elif item_row == constants.RULES_TREE_TEMPORARY:
                section=constants.FILTER_TREE_APPS
                what=constants.RULES_TYPE_TEMPORARY

        elif parent_row == constants.RULES_TREE_NODES:
            section=constants.FILTER_TREE_NODES

        elif parent_row == constants.RULES_TREE_FIREWALL:
            self.set_fw_rules_filter(parent_row, item_row, what, what1, what2)
            return

        if section == constants.FILTER_TREE_APPS:
            if what == constants.RULES_TYPE_TEMPORARY:
                what = "WHERE r.duration != '{0}'".format(Config.DURATION_ALWAYS)
            elif what == constants.RULES_TYPE_PERMANENT:
                what = "WHERE r.duration = '{0}'".format(Config.DURATION_ALWAYS)
        elif section == constants.FILTER_TREE_NODES and what != "":
            what = f"WHERE r.node = '{what}'"

        if filter_text != "":
            if what == "":
                what = "WHERE"
            else:
                what = what + " AND"
            what = what + f" r.name LIKE '%{filter_text}%'"
        q = "SELECT {0} FROM rules as r {1} {2} {3}".format(
            self.win.TABLES[constants.TAB_RULES]['display_fields'],
            what,
            self.win.get_view_order(),
            self.win.get_view_limit()
        )
        self.setQuery(model, q, limit=self.win.get_query_limit(), offset=0)

    def set_fw_rules_filter(self, parent_row=constants.NO_PARENT, item_row=0, what="", what1="", what2=""):
        section = constants.FILTER_TREE_APPS
        filter_text = self.win.get_search_text()

        if parent_row == constants.NO_PARENT:
            if item_row == constants.RULES_TREE_FIREWALL:
                self.win.TABLES[constants.TAB_FIREWALL]['view'].model().filterAll()

        if item_row == constants.FILTER_TREE_FW_NODE:
            self.win.TABLES[constants.TAB_FIREWALL]['view'].filterByNode(what)

        elif item_row == constants.FILTER_TREE_FW_TABLE:
            parm = what.split("-")
            if len(parm) < 2:
                return
            self.win.TABLES[constants.TAB_FIREWALL]['view'].filterByTable(what1, parm[0], parm[1])

        elif item_row == constants.FILTER_TREE_FW_CHAIN: # + table
            # 1. addr, 2. hook, 3. chainname
            try:
                parm = what.split("#")
                tbl = what1.split("-")
                self.win.TABLES[constants.TAB_FIREWALL]['view'].filterByChain(
                    what2,
                    tbl[0],
                    tbl[1],
                    parm[2],
                    parm[1]
                )
            except Exception as e:
                print("Exception loading firewall chains:", what, ",", what1, "-", e)
                return

        # TODO: add a parameter to every filter*() method, to accept text filters.
        if filter_text != "":
            self.win.TABLES[constants.TAB_FIREWALL]['view'].filterByQuery(filter_text)
        # TODO: allow users configure the columns to display
        #self.win.show_view_columns(constants.TAB_FIREWALL)

    def set_events_query(self, advanced_filter=None):
        if self.win.get_current_view_idx() != constants.TAB_MAIN:
            return

        model = self.win.TABLES[constants.TAB_MAIN]['view'].model()
        qstr = self.get_query(
            self.win.TABLES[constants.TAB_MAIN]['name'],
            self.win.TABLES[constants.TAB_MAIN]['display_fields']
        )

        filter_text = self.win.get_search_text()
        action = ""
        if self.win.comboAction.currentIndex() == 1:
            action = f"action = \"{Config.ACTION_ALLOW}\""
        elif self.win.comboAction.currentIndex() == 2:
            action = f"action = \"{Config.ACTION_DENY}\""
        elif self.win.comboAction.currentIndex() == 3:
            action = f"action = \"{Config.ACTION_REJECT}\""

        # FIXME: use prepared statements
        if advanced_filter is not None:
            qstr += " as c WHERE " + advanced_filter
        elif filter_text == "":
            if action != "":
                qstr += " WHERE " + action
        else:
            if action != "":
                action += " AND "
            qstr += self.get_events_generic_filter(action, filter_text)

        qstr += self.win.get_view_order() + self.win.get_view_limit()
        self.setQuery(model, qstr, limit=self.win.get_query_limit())

    def set_nodes_query(self, data):
        model = self.win.get_active_table().model()
        query = self.win.TABLES[constants.TAB_NODES]['query'].replace("%DATA%", data)
        qtail = "GROUP BY {0}, c.process_args, c.uid, c.src_ip, c.dst_ip, c.dst_host, c.dst_port, c.protocol {1}".format(
            self.win.COL_STR_PROCESS,
            self.win.get_view_order() + self.win.get_view_limit()
        )
        self.setQuery(model, f"{query} {qtail}", limit=self.win.get_query_limit(), offset=0)

    def set_rules_query(self, rule_name="", node=""):
        if node != "":
            node = f"c.node = '{node}'"
        if rule_name != "":
            rule_name = f"c.rule = '{rule_name}'"

        condition = "%s AND %s" % (rule_name, node) if rule_name != "" and node != "" else ""

        model = self.win.get_active_table().model()
        qtail = "WHERE {0} GROUP BY c.process, c.process_args, c.uid, c.dst_ip, c.dst_host, c.dst_port {1}".format(
            condition,
            self.win.get_view_order() + self.win.get_view_limit()
        )
        self.setQuery(
            model,
            "{0} {1}".format(
                self.win.TABLES[constants.TAB_RULES]['query'],
                qtail
            ),
            limit=self.win.get_query_limit()
        )

    def set_hosts_query(self, data):
        model = self.win.get_active_table().model()
        query = self.win.TABLES[constants.TAB_HOSTS]['query'].replace("%DATA%", data)
        qtail = "GROUP BY c.pid, {0}, c.process_args, c.src_ip, c.dst_ip, c.dst_port, c.protocol, c.action, c.node {1}".format(
            self.win.COL_STR_PROCESS,
            self.win.get_view_order(constants.SORT_DESC) + self.win.get_view_limit()
        )
        self.setQuery(model, f"{query} {qtail}", limit=self.win.get_query_limit(), offset=0)

    def set_process_query(self, data):
        model = self.win.get_active_table().model()
        query = self.win.TABLES[constants.TAB_PROCS]['query'].replace("%DATA%", data)
        qtail = "GROUP BY c.src_ip, c.dst_ip, c.dst_host, c.dst_port, c.uid, c.action, c.node, c.pid, c.process_args {0}".format(
            self.win.get_view_order(constants.SORT_DESC) + self.win.get_view_limit()
        )
        self.setQuery(model, f"{query} {qtail}", limit=self.win.get_query_limit(), offset=0)

        return self.win.get_active_table().model().rowCount()

    def set_addrs_query(self, data):
        model = self.win.get_active_table().model()
        query = self.win.TABLES[constants.TAB_ADDRS]['query'].replace("%DATA%", data)
        qtail = "GROUP BY c.pid, {0}, c.process_args, c.src_ip, c.dst_port, {1}, c.protocol, c.action, c.uid, c.node {2}".format(
            self.win.COL_STR_PROCESS,
            self.win.COL_STR_DST_HOST,
            self.win.get_view_order(constants.SORT_DESC) + self.win.get_view_limit()
        )
        self.setQuery(model, f"{query} {qtail}", limit=self.win.get_query_limit(), offset=0)

    def set_ports_query(self, data):
        model = self.win.get_active_table().model()
        query = self.win.TABLES[constants.TAB_PORTS]['query'].replace("%DATA%", data)
        qtail = "GROUP BY c.pid, {0}, c.process_args, {1}, c.src_ip, c.dst_ip, c.protocol, c.action, c.uid, c.node {2}".format(
            self.win.COL_STR_PROCESS,
            self.win.COL_STR_DST_HOST,
            self.win.get_view_order(constants.SORT_DESC) + self.win.get_view_limit()
        )
        #self.setQuery(model, f"{query} {qtail}", ((0, data),))
        self.setQuery(model, f"{query} {qtail}", limit=self.win.get_query_limit(), offset=0)

    def set_users_query(self, data):
        uid = data.split(" ")
        if len(uid) == 2:
            uid = uid[1].strip("()")
        else:
            uid = uid[0]
        model = self.win.get_active_table().model()
        query = self.win.TABLES[constants.TAB_USERS]['query'].replace("%DATA%", uid)
        qtail = "GROUP BY c.pid, {0}, c.process_args, c.src_ip, c.dst_ip, c.dst_host, c.dst_port, c.protocol, c.action, c.node {1}".format(
            self.win.COL_STR_PROCESS,
            self.win.get_view_order(constants.SORT_DESC) + self.win.get_view_limit()
        )
        self.setQuery(model, f"{query} {qtail}", limit=self.win.get_query_limit(), offset=0)

    def setQuery(self, model, q, binds=None, limit=0, offset=None):
        if self.win.is_context_menu_active() or self.win.is_scrollbar_active():
            return
        with self.win._lock:
            try:
                model.query().clear()
                model.setQuery(
                    q,
                    self.win._db_sqlite,
                    binds,
                    limit=limit,
                    offset=offset
                )
                if model.lastError().isValid():
                    print("setQuery() error: ", model.lastError().text())

                if self.win.get_current_view_idx() != constants.TAB_MAIN:
                    self.win.labelRowsCount.setText("{0}".format(model.totalRowCount))
                else:
                    self.win.labelRowsCount.setText("")
            except Exception as e:
                print(self.win._address, "setQuery() exception: ", e)

