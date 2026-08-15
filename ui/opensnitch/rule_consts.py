#   Copyright (C) 2026 The OpenSnitch Authors
#
#   This file is part of OpenSnitch.
#
#   OpenSnitch is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   OpenSnitch is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with OpenSnitch.  If not, see <http://www.gnu.org/licenses/>.

class RuleConsts:
    """Rule operands, types, actions and durations, as understood by the daemon.

    These constants have no Qt dependency, so they can be used by components
    that run without a graphical environment (opensnitch-cli). Config inherits
    from this class, so Config.OPERAND_* and friends keep working as before.

    The daemon side counterpart is daemon/rule/operator.go and daemon/rule/rule.go
    """

    OPERAND_PROCESS_ID = "process.id"
    OPERAND_PROCESS_PATH = "process.path"
    OPERAND_PROCESS_COMMAND = "process.command"
    OPERAND_PROCESS_ENV = "process.env."
    OPERAND_PROCESS_HASH_MD5 = "process.hash.md5"
    OPERAND_PROCESS_HASH_SHA1 = "process.hash.sha1"
    OPERAND_USER_ID = "user.id"
    OPERAND_IFACE_OUT = "iface.out"
    OPERAND_IFACE_IN = "iface.in"
    OPERAND_SOURCE_IP = "source.ip"
    OPERAND_SOURCE_PORT = "source.port"
    OPERAND_DEST_IP = "dest.ip"
    OPERAND_DEST_HOST = "dest.host"
    OPERAND_DEST_PORT = "dest.port"
    OPERAND_DEST_NETWORK = "dest.network"
    OPERAND_SOURCE_NETWORK = "source.network"
    OPERAND_PROTOCOL = "protocol"
    OPERAND_LIST_DOMAINS = "lists.domains"
    OPERAND_LIST_DOMAINS_REGEXP = "lists.domains_regexp"
    OPERAND_LIST_IPS = "lists.ips"
    OPERAND_LIST_NETS = "lists.nets"

    RULE_TYPE_LIST = "list"
    RULE_TYPE_LISTS = "lists"
    RULE_TYPE_SIMPLE = "simple"
    RULE_TYPE_REGEXP = "regexp"
    RULE_TYPE_NETWORK = "network"
    RULE_TYPE_RANGE = "range"
    RulesTypes = (RULE_TYPE_LIST, RULE_TYPE_LISTS, RULE_TYPE_SIMPLE, RULE_TYPE_REGEXP, RULE_TYPE_NETWORK, RULE_TYPE_RANGE)

    # don't translate
    ACTION_ALLOW = "allow"
    ACTION_DENY = "deny"
    ACTION_REJECT = "reject"
    ACTION_ACCEPT = "accept"
    ACTION_DROP = "drop"
    ACTION_JUMP = "jump"
    ACTION_REDIRECT = "redirect"
    ACTION_RETURN = "return"
    ACTION_TPROXY = "tproxy"
    ACTION_SNAT = "snat"
    ACTION_DNAT = "dnat"
    ACTION_MASQUERADE = "masquerade"
    ACTION_QUEUE = "queue"
    ACTION_LOG = "log"
    ACTION_STOP = "stop"

    DURATION_FIELD = "duration"
    DURATION_UNTIL_RESTART = "until restart"
    DURATION_ALWAYS = "always"
    DURATION_ONCE = "once"
    DURATION_12h = "12h"
    DURATION_1h = "1h"
    DURATION_30m = "30m"
    DURATION_15m = "15m"
    DURATION_5m = "5m"
    DURATION_30s = "30s"

    RULES_TEMPORARY_LIST = [
        DURATION_ONCE, DURATION_30s, DURATION_5m,
        DURATION_15m, DURATION_30m, DURATION_1h,
        DURATION_12h,
        DURATION_UNTIL_RESTART]
