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

"""Whether a rule covers a connection, decided on our side.

The daemon is the authority on matching (daemon/rule/operator.go); this mirrors
just enough of it to answer "would the daemon still ask about this connection
if that rule were installed?". Review uses it to close queue entries a freshly
approved rule already covers, and the service uses it to answer a daemon asking
about a connection whose decision is still waiting in the outbox.

The two possible mistakes cost very different amounts. Missing a match only
means one extra question. Claiming a match the daemon would not see silently
throws away the chance to review a connection, so everything this module does
not fully understand — an operand the CLI cannot produce, a pattern Go might
compile differently — is answered with None ("can't tell"), never guessed at.
"""

import ipaddress
import re

from opensnitch.rule_consts import RuleConsts

# operand -> how to read the value it is compared against off a Connection.
# The daemon side is the operand dispatch in operator.go Match().
_SIMPLE_VALUES = {
    RuleConsts.OPERAND_PROCESS_PATH: lambda con: con.process_path,
    RuleConsts.OPERAND_PROCESS_COMMAND: lambda con: " ".join(con.process_args),
    RuleConsts.OPERAND_PROCESS_ID: lambda con: str(con.process_id),
    RuleConsts.OPERAND_USER_ID: lambda con: str(con.user_id),
    RuleConsts.OPERAND_DEST_HOST: lambda con: con.dst_host,
    RuleConsts.OPERAND_DEST_IP: lambda con: con.dst_ip,
    RuleConsts.OPERAND_DEST_PORT: lambda con: str(con.dst_port),
    RuleConsts.OPERAND_PROTOCOL: lambda con: con.protocol,
}

_HASH_OPERANDS = (RuleConsts.OPERAND_PROCESS_HASH_MD5,
                  RuleConsts.OPERAND_PROCESS_HASH_SHA1)


def _connection_value(operand, con):
    getter = _SIMPLE_VALUES.get(operand)
    if getter is None:
        return None
    return getter(con)


def _simple(op, con):
    if op.operand in _HASH_OPERANDS:
        # the daemon compares against every checksum it computed. When it has
        # none, or checksums are disabled, it fakes a match — we can't know
        # which from here, so only an actual equality is an answer.
        if op.data != "" and op.data in dict(con.process_checksums).values():
            return True
        return None

    value = _connection_value(op.operand, con)
    if value is None:
        return None
    if op.sensitive:
        return value == op.data
    # simpleCmp uses strings.EqualFold by default
    return value.lower() == op.data.lower()


def _regexp(op, con):
    value = _connection_value(op.operand, con)
    if value is None:
        return None
    pattern = op.data
    if not op.sensitive:
        # the daemon lowercases both sides (operator.go Compile / reCmp)
        pattern = pattern.lower()
        value = value.lower()
    try:
        # Go's MatchString is a search, not a full match
        return re.search(pattern, value) is not None
    except re.error:
        return None


def _network(op, con):
    if op.operand != RuleConsts.OPERAND_DEST_NETWORK:
        return None
    try:
        # a network alias instead of a CIDR only resolves on the daemon
        return ipaddress.ip_address(con.dst_ip) in ipaddress.ip_network(op.data)
    except ValueError:
        return None


def operator_matches(op, con):
    """True or False when the daemon's verdict is knowable, None when it isn't."""
    if op.operand == "true":
        return True

    if op.type == RuleConsts.RULE_TYPE_LIST:
        # every operand of a list rule has to match (operator.go listMatch)
        verdicts = [operator_matches(child, con) for child in op.list]
        if False in verdicts:
            return False
        if None in verdicts or len(verdicts) == 0:
            return None
        return True

    if op.type == RuleConsts.RULE_TYPE_SIMPLE:
        return _simple(op, con)
    if op.type == RuleConsts.RULE_TYPE_REGEXP:
        return _regexp(op, con)
    if op.type == RuleConsts.RULE_TYPE_NETWORK:
        return _network(op, con)

    # lists, range, and whatever the future adds: the daemon knows, we don't
    return None


def rule_matches(rule, con):
    """True or False when the daemon's verdict is knowable, None when it isn't."""
    if not rule.enabled:
        return False
    return operator_matches(rule.operator, con)
